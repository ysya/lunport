import { deepStrictEqual, match, strictEqual, throws } from "node:assert/strict";
import { execFileSync, spawnSync } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { after, describe, it } from "node:test";
import { fileURLToPath } from "node:url";

import {
  applyUpdate,
  compareVersions,
  describeWranglerChanges,
  listFiles,
  planSync,
  prBody,
  readRelayVersion,
  readWorkerName,
  withWorkerName,
  workflowOutdated,
} from "./update-relay.mjs";

const SCRIPT = fileURLToPath(new URL("./update-relay.mjs", import.meta.url));
// The relay's own wrangler.jsonc: relay/ here, the repository root in a deployed copy.
const REAL_WRANGLER = readFileSync(new URL("../../wrangler.jsonc", import.meta.url), "utf8");

const UPSTREAM_WRANGLER = `{
  "$schema": "node_modules/wrangler/config-schema.json",
  // a comment with "name": "decoy" inside, before the real name
  "name": "sshelter-relay",
  "main": "src/index.ts",
  "compatibility_date": "2026-08-20",
  "durable_objects": {
    "bindings": [
      { "name": "CHAIN", "class_name": "ChainStore" },
      { "name": "IP_LIMIT", "class_name": "IpLimiter" }
    ]
  },
  "migrations": [{ "tag": "v1", "new_sqlite_classes": ["ChainStore", "IpLimiter"] }]
}
`;

const SHA = "a".repeat(40);
const temporary = [];

after(() => {
  for (const dir of temporary) rmSync(dir, { recursive: true, force: true });
});

function tempDir() {
  const dir = mkdtempSync(join(tmpdir(), "update-relay-"));
  temporary.push(dir);
  return dir;
}

function tree(files) {
  const root = tempDir();
  for (const [path, content] of Object.entries(files)) {
    mkdirSync(dirname(join(root, path)), { recursive: true });
    writeFileSync(join(root, path), content);
  }
  return root;
}

const pkg = (version) => `${JSON.stringify({ name: "sshelter-relay", version }, null, 2)}\n`;

/** A minimal relay at `version`, with `code` as its source and the owner's Worker name. */
const relay = (version, code, name = "sshelter-relay") => ({
  "package.json": pkg(version),
  "wrangler.jsonc": withWorkerName(UPSTREAM_WRANGLER, name),
  "src/index.ts": code,
});

/** Every file under `dir` (as listFiles sees them) with its contents. */
const snapshot = (dir) => Object.fromEntries(listFiles(dir).map((path) => [path, readFileSync(join(dir, path), "utf8")]));

const summaryOf = (overrides = {}) => ({
  workerName: "my-relay",
  fromVersion: "0.2.0",
  toVersion: "0.3.0",
  direction: "upgrade",
  removed: [],
  workflowOutdated: false,
  scriptChanged: false,
  durableObjectsChanged: false,
  newMigrationTags: [],
  ...overrides,
});

describe("the Worker name", () => {
  it("reads the top-level name, not a binding's or a comment's", () => {
    strictEqual(readWorkerName(UPSTREAM_WRANGLER), "sshelter-relay");
  });

  it("keeps the Worker name and changes nothing else", () => {
    const renamed = withWorkerName(UPSTREAM_WRANGLER, "my-relay");
    strictEqual(readWorkerName(renamed), "my-relay");
    strictEqual(renamed.replace('"name": "my-relay"', '"name": "sshelter-relay"'), UPSTREAM_WRANGLER);
  });

  it("refuses to guess when the first name key is not the Worker name", () => {
    const noTopLevel = UPSTREAM_WRANGLER.replace('  "name": "sshelter-relay",\n', "");
    throws(() => withWorkerName(noTopLevel, "my-relay"), /no top-level Worker name/);
    // Move the top-level name to the end: the first "name" outside a comment is now a binding's, so the check refuses.
    const nameLast = noTopLevel.replace(/\n}\n$/, ',\n  "name": "sshelter-relay"\n}\n');
    strictEqual(readWorkerName(nameLast), "sshelter-relay");
    throws(() => withWorkerName(nameLast, "my-relay"), /not the Worker name/);
  });

  it("refuses even when the new name equals the old one, if a binding's name key comes first", () => {
    // The top-level name would come out right, so only the check for collateral changes catches the renamed binding.
    const text = `{ "durable_objects": { "bindings": [{ "name": "CHAIN", "class_name": "C" }] }, "name": "sshelter-relay" }`;
    throws(() => withWorkerName(text, "sshelter-relay"), /not the Worker name/);
  });

  it("skips a decoy name inside a block comment that closes after it", () => {
    const oneLine = `{\n  /* "name": "decoy" */\n  "name": "sshelter-relay"\n}\n`;
    strictEqual(withWorkerName(oneLine, "my-relay"), `{\n  /* "name": "decoy" */\n  "name": "my-relay"\n}\n`);
    const multiLine = `{\n  /*\n    "name": "decoy",\n  */\n  "name": "sshelter-relay"\n}\n`;
    strictEqual(withWorkerName(multiLine, "my-relay"), multiLine.replace('"name": "sshelter-relay"', '"name": "my-relay"'));
  });

  it("still refuses a file whose block comment never closes", () => {
    throws(() => withWorkerName(`{\n  "name": "sshelter-relay"\n  /* never closed\n}\n`, "my-relay"), /unterminated block comment/);
  });

  it("round-trips the relay's real wrangler.jsonc", () => {
    const name = readWorkerName(REAL_WRANGLER);
    const renamed = withWorkerName(REAL_WRANGLER, "renamed-relay");
    strictEqual(readWorkerName(renamed), "renamed-relay");
    strictEqual(withWorkerName(renamed, name), REAL_WRANGLER);
  });
});

describe("versions", () => {
  it("compares the numeric X.Y.Z core", () => {
    strictEqual(compareVersions("0.2.0", "0.3.0"), -1);
    strictEqual(compareVersions("0.3.0", "0.3.0"), 0);
    strictEqual(compareVersions("0.3.0", "0.2.9"), 1);
    strictEqual(compareVersions("0.10.0", "0.9.0"), 1);
    strictEqual(compareVersions("1.0.0", "0.99.99"), 1);
  });

  it("ignores a pre-release or build suffix", () => {
    strictEqual(compareVersions("1.0.0-beta.1", "1.0.0"), 0);
    strictEqual(compareVersions("1.0.0", "1.0.0-rc.2+build.7"), 0);
    strictEqual(compareVersions("0.3.0+build.5", "0.3.1-beta.1"), -1);
  });

  it("names a version without an X.Y.Z core", () => {
    throws(() => compareVersions("1.2", "1.2.0"), /"1\.2" has no X\.Y\.Z core/);
    throws(() => compareVersions("0.3.0", "0.3.0.1"), /"0\.3\.0\.1" has no X\.Y\.Z core/);
    throws(() => compareVersions("0.3.0", "latest"), /"latest"/);
  });

  it("reads the relay version from package.json and says when it cannot", () => {
    strictEqual(readRelayVersion(tree({ "package.json": pkg("0.4.1") })), "0.4.1");
    throws(() => readRelayVersion(tree({ "src/index.ts": "" })), /package\.json is missing/);
    throws(() => readRelayVersion(tree({ "package.json": "{}" })), /package\.json has no version/);
  });
});

describe("planSync", () => {
  it("copies upstream files and removes files upstream dropped", () => {
    const plan = planSync(["src/index.ts", "package.json"], ["src/index.ts", "src/old.ts", "package.json"]);
    deepStrictEqual(plan, { copy: ["src/index.ts", "package.json"], remove: ["src/old.ts"] });
  });

  it("never touches the owner's other GitHub files but keeps its own up to date", () => {
    const plan = planSync(
      [".github/workflows/update-relay.yml", ".github/scripts/update-relay.mjs", "src/index.ts"],
      [".github/workflows/update-relay.yml", ".github/workflows/mine.yml", ".github/scripts/update-relay.mjs", "src/index.ts"],
    );
    deepStrictEqual(plan.copy, [".github/scripts/update-relay.mjs", "src/index.ts"]);
    deepStrictEqual(plan.remove, []);
  });

  it("never deletes .github files that an older upstream release lacks", () => {
    const plan = planSync(["src/index.ts"], [".github/scripts/update-relay.mjs", ".github/workflows/update-relay.yml", "src/index.ts"]);
    deepStrictEqual(plan.remove, []);
  });
});

describe("describeWranglerChanges", () => {
  it("reports new migration tags and binding changes", () => {
    const next = UPSTREAM_WRANGLER.replace(
      '[{ "tag": "v1", "new_sqlite_classes": ["ChainStore", "IpLimiter"] }]',
      '[{ "tag": "v1", "new_sqlite_classes": ["ChainStore", "IpLimiter"] }, { "tag": "v2", "new_sqlite_classes": ["Extra"] }]',
    ).replace('{ "name": "IP_LIMIT", "class_name": "IpLimiter" }', '{ "name": "IP_LIMIT", "class_name": "IpLimiter" }, { "name": "EXTRA", "class_name": "Extra" }');
    deepStrictEqual(describeWranglerChanges(UPSTREAM_WRANGLER, next), { durableObjectsChanged: true, newMigrationTags: ["v2"] });
    deepStrictEqual(describeWranglerChanges(UPSTREAM_WRANGLER, UPSTREAM_WRANGLER), { durableObjectsChanged: false, newMigrationTags: [] });
  });
});

describe("prBody", () => {
  it("names both versions, the source, the kept Worker name, removed files and migrations", () => {
    const body = prBody(summaryOf({ removed: ["src/old.ts"], newMigrationTags: ["v2"] }), "ysya/sshelter", "v0.3.0", SHA);
    const lines = body.split("\n");
    strictEqual(lines[0], `Updates this relay from **0.2.0** to **0.3.0** — **v0.3.0** of [ysya/sshelter](https://github.com/ysya/sshelter) (commit \`${SHA}\`).`);
    for (const part of [
      "The Worker name `my-relay` is kept",
      "- Files removed: `src/old.ts`",
      "- Migrations: **new tags** `v2` — they run on deploy and cannot be undone",
      "- Durable Object bindings: unchanged",
      "- Update workflow: unchanged",
    ]) {
      strictEqual(body.includes(part), true, part);
    }
    strictEqual(body.includes("downgrade"), false);
    strictEqual(body.includes("Update script"), false);
  });

  it("warns about a downgrade", () => {
    const body = prBody(summaryOf({ fromVersion: "0.3.0", toVersion: "0.2.0", direction: "downgrade" }), "ysya/sshelter", "v0.2.0", SHA);
    strictEqual(body.startsWith("Updates this relay from **0.3.0** to **0.2.0** — **v0.2.0**"), true);
    strictEqual(body.includes("**This is a downgrade.** Features newer than 0.2.0 go away when you merge it."), true);
  });

  it("escapes a ref and a migration tag that would open an HTML comment and hide the lines after them", () => {
    const body = prBody(summaryOf({ newMigrationTags: ["x`\n<!--", "v4"], scriptChanged: true }), "ysya/sshelter", "v1<!--", SHA);
    const lines = body.split("\n");
    // Outside code spans no "<!--" is left; inside one it is shown as typed and cannot start a comment.
    strictEqual(body.replace(/`[^`\n]*`/g, "").includes("<!--"), false);
    strictEqual(lines[0].includes("**v1&lt;!--** of [ysya/sshelter]"), true);
    strictEqual(lines.includes("- Migrations: **new tags** `x<!--`, `v4` — they run on deploy and cannot be undone"), true);
    strictEqual(
      lines.includes("- Update script: **changed** — it runs with write access on the next update; review `.github/scripts/update-relay.mjs`."),
      true,
    );
  });

  it("keeps every upstream value on its own line and inside its own code span", () => {
    const summary = summaryOf({
      workerName: "my`relay",
      fromVersion: "0.3.0\r\n<b>",
      toVersion: "0.2.0>",
      direction: "downgrade",
      removed: ["a`b.ts", "c\nd.ts"],
    });
    const body = prBody(summary, "some<one/fork", "main\nmore", SHA);
    const lines = body.split("\n");
    strictEqual(
      lines[0],
      `Updates this relay from **0.3.0 &lt;b&gt;** to **0.2.0&gt;** — **main more** of [some&lt;one/fork](https://github.com/some<one/fork) (commit \`${SHA}\`).`,
    );
    strictEqual(lines.includes("**This is a downgrade.** Features newer than 0.2.0&gt; go away when you merge it."), true);
    strictEqual(body.includes("The Worker name `myrelay` is kept"), true);
    strictEqual(lines.includes("- Files removed: `ab.ts`, `cd.ts`"), true);
  });

  it("links the upstream workflow to copy by hand and flags a changed update script", () => {
    const body = prBody(summaryOf({ workflowOutdated: true, scriptChanged: true }), "someone/fork", "main", SHA);
    strictEqual(
      body.includes(`copy [\`relay/.github/workflows/update-relay.yml\`](https://github.com/someone/fork/blob/${SHA}/relay/.github/workflows/update-relay.yml) into \`.github/workflows/\` by hand`),
      true,
    );
    strictEqual(
      body.includes("- Update script: **changed** — it runs with write access on the next update; review `.github/scripts/update-relay.mjs`."),
      true,
    );
  });
});

describe("workflowOutdated", () => {
  it("returns false when upstream has no workflow file", () => {
    const upstream = tree({ "src/index.ts": "code" });
    const repo = tree({ ".github/workflows/update-relay.yml": "v1" });
    strictEqual(workflowOutdated(upstream, repo), false);
  });

  it("returns true when the repo lacks the workflow file", () => {
    const upstream = tree({ ".github/workflows/update-relay.yml": "v2" });
    const repo = tree({ "src/index.ts": "code" });
    strictEqual(workflowOutdated(upstream, repo), true);
  });

  it("returns true when contents differ", () => {
    const upstream = tree({ ".github/workflows/update-relay.yml": "v2" });
    const repo = tree({ ".github/workflows/update-relay.yml": "v1" });
    strictEqual(workflowOutdated(upstream, repo), true);
  });

  it("returns false when identical", () => {
    const content = "v1";
    const upstream = tree({ ".github/workflows/update-relay.yml": content });
    const repo = tree({ ".github/workflows/update-relay.yml": content });
    strictEqual(workflowOutdated(upstream, repo), false);
  });
});

describe("applyUpdate", () => {
  it("syncs the files, keeps the Worker name and the owner's files, and reports what changed", () => {
    const upstream = tree({
      ...relay("0.3.0", "new"),
      ".github/workflows/update-relay.yml": "workflow v2",
      ".gitignore": "node_modules/\n",
    });
    const repo = tree({
      ...relay("0.2.0", "old", "my-relay"),
      "src/removed.ts": "gone upstream",
      ".github/workflows/update-relay.yml": "workflow v1",
      ".github/workflows/mine.yml": "mine",
      "node_modules/x/index.js": "dependency",
    });
    const summary = applyUpdate(upstream, repo);
    deepStrictEqual(summary, summaryOf({ removed: ["src/removed.ts"], workflowOutdated: true }));
    strictEqual(readFileSync(join(repo, "src/index.ts"), "utf8"), "new");
    strictEqual(readFileSync(join(repo, "package.json"), "utf8"), pkg("0.3.0"));
    strictEqual(existsSync(join(repo, "src/removed.ts")), false);
    strictEqual(readFileSync(join(repo, ".github/workflows/update-relay.yml"), "utf8"), "workflow v1");
    strictEqual(readFileSync(join(repo, ".github/workflows/mine.yml"), "utf8"), "mine");
    strictEqual(existsSync(join(repo, "node_modules/x/index.js")), true);
    strictEqual(readWorkerName(readFileSync(join(repo, "wrangler.jsonc"), "utf8")), "my-relay");
    deepStrictEqual(listFiles(repo).includes(".gitignore"), true);
  });

  it("never lists, copies or removes anything named .git", () => {
    // A .git directory, or a .git file pointing at one (worktrees, submodules), at any depth.
    const upstream = tree({ ...relay("0.3.0", "new"), ".git": "gitdir: /elsewhere\n", "src/.git": "gitdir: ../planted\n" });
    const repo = tree({ ...relay("0.3.0", "old"), ".git/HEAD": "ref: refs/heads/main\n", "selfhost/.git": "gitdir: /owned\n" });
    const isGit = (path) => path.split("/").includes(".git");
    strictEqual(listFiles(upstream).some(isGit), false);
    strictEqual(listFiles(repo).some(isGit), false);
    applyUpdate(upstream, repo);
    strictEqual(readFileSync(join(repo, ".git/HEAD"), "utf8"), "ref: refs/heads/main\n");
    strictEqual(existsSync(join(repo, "src/.git")), false);
    strictEqual(readFileSync(join(repo, "selfhost/.git"), "utf8"), "gitdir: /owned\n");
    strictEqual(readFileSync(join(repo, "src/index.ts"), "utf8"), "new");
  });

  it("changes nothing when upstream is older, and says why", () => {
    const upstream = tree(relay("0.2.0", "older"));
    const repo = tree({ ...relay("0.3.0", "newer", "my-relay"), "src/extra.ts": "only here" });
    const before = snapshot(repo);
    deepStrictEqual(applyUpdate(upstream, repo), {
      skipped: "downgrade",
      fromVersion: "0.3.0",
      toVersion: "0.2.0",
      direction: "downgrade",
      message: "This relay (0.3.0) is newer than the upstream release (0.2.0); nothing to do. Run the workflow with an explicit ref to downgrade.",
    });
    deepStrictEqual(snapshot(repo), before);
  });

  it("downgrades when asked to", () => {
    const upstream = tree(relay("0.2.0", "older"));
    const repo = tree({ ...relay("0.3.0", "newer", "my-relay"), "src/extra.ts": "only here" });
    const summary = applyUpdate(upstream, repo, { allowDowngrade: true });
    deepStrictEqual(summary, summaryOf({ fromVersion: "0.3.0", toVersion: "0.2.0", direction: "downgrade", removed: ["src/extra.ts"] }));
    strictEqual(readFileSync(join(repo, "src/index.ts"), "utf8"), "older");
    strictEqual(readWorkerName(readFileSync(join(repo, "wrangler.jsonc"), "utf8")), "my-relay");
  });

  it("applies the same version, and compares pre-releases by their core", () => {
    const same = tree(relay("0.3.0", "old"));
    strictEqual(applyUpdate(tree(relay("0.3.0", "rebuilt")), same).direction, "same");
    strictEqual(readFileSync(join(same, "src/index.ts"), "utf8"), "rebuilt");
    // 0.4.0-beta.1 has the core 0.4.0: newer than 0.3.0, the same as 0.4.0 (so not a refused downgrade).
    strictEqual(applyUpdate(tree(relay("0.4.0-beta.1", "beta")), tree(relay("0.3.0", "old"))).direction, "upgrade");
    const released = tree(relay("0.4.0", "release"));
    strictEqual(applyUpdate(tree(relay("0.4.0-beta.1", "beta")), released).direction, "same");
    strictEqual(readFileSync(join(released, "src/index.ts"), "utf8"), "beta");
  });

  it("leaves the repository untouched when it cannot keep the Worker name", () => {
    // Upstream's first "name" key outside a comment belongs to a binding: the update refuses before any file changes.
    const nameLast = UPSTREAM_WRANGLER.replace('  "name": "sshelter-relay",\n', "").replace(/\n}\n$/, ',\n  "name": "sshelter-relay"\n}\n');
    const upstream = tree({ ...relay("0.3.0", "new"), "wrangler.jsonc": nameLast });
    const repo = tree({ ...relay("0.2.0", "old", "my-relay"), "src/removed.ts": "gone upstream" });
    const before = snapshot(repo);
    throws(() => applyUpdate(upstream, repo), /not the Worker name/);
    deepStrictEqual(snapshot(repo), before);
  });

  it("reports whether the update script changes", () => {
    const script = ".github/scripts/update-relay.mjs";
    const changed = (upstreamScript, repoScript) => {
      const upstream = tree({ ...relay("0.3.0", "new"), ...(upstreamScript === undefined ? {} : { [script]: upstreamScript }) });
      const repo = tree({ ...relay("0.2.0", "old"), ...(repoScript === undefined ? {} : { [script]: repoScript }) });
      return applyUpdate(upstream, repo).scriptChanged;
    };
    strictEqual(changed("script v2", "script v1"), true);
    strictEqual(changed("script v2", undefined), true);
    strictEqual(changed("script v1", "script v1"), false);
    strictEqual(changed(undefined, "script v1"), false);
  });
});

describe("the command line", () => {
  const run = (script, ...args) => execFileSync(process.execPath, [script, ...args], { encoding: "utf8" });

  it("applies an update and prints the summary, then the pull request body", () => {
    const upstream = tree({ "package.json": pkg("0.3.0"), "wrangler.jsonc": REAL_WRANGLER, "src/a.ts": "new" });
    const repo = tree({ "package.json": pkg("0.2.0"), "wrangler.jsonc": withWorkerName(REAL_WRANGLER, "my-relay"), "src/a.ts": "old" });
    const summary = JSON.parse(run(SCRIPT, "apply", upstream, repo));
    deepStrictEqual(summary, summaryOf());
    strictEqual(readFileSync(join(repo, "src/a.ts"), "utf8"), "new");
    const summaryFile = join(tempDir(), "summary.json");
    writeFileSync(summaryFile, JSON.stringify(summary));
    const body = run(SCRIPT, "pr-body", summaryFile, "ysya/sshelter", "v0.3.0", SHA);
    strictEqual(body, `${prBody(summary, "ysya/sshelter", "v0.3.0", SHA)}\n`);
  });

  it("downgrades only with --allow-downgrade", () => {
    const upstream = tree(relay("0.2.0", "older"));
    const repo = tree(relay("0.3.0", "newer"));
    strictEqual(JSON.parse(run(SCRIPT, "apply", upstream, repo)).skipped, "downgrade");
    strictEqual(readFileSync(join(repo, "src/index.ts"), "utf8"), "newer");
    strictEqual(JSON.parse(run(SCRIPT, "apply", upstream, repo, "--allow-downgrade")).direction, "downgrade");
    strictEqual(readFileSync(join(repo, "src/index.ts"), "utf8"), "older");
  });

  it("runs through a symlinked path", () => {
    const link = join(tempDir(), "update-relay.mjs");
    symlinkSync(SCRIPT, link);
    const repo = tree(relay("0.3.0", "old"));
    strictEqual(JSON.parse(run(link, "apply", tree(relay("0.3.0", "new")), repo)).direction, "same");
    strictEqual(readFileSync(join(repo, "src/index.ts"), "utf8"), "new");
  });

  it("rejects unknown arguments with the usage", () => {
    const result = spawnSync(process.execPath, [SCRIPT, "apply", tempDir(), tempDir(), "--force"], { encoding: "utf8" });
    strictEqual(result.status, 2);
    match(result.stderr, /usage: update-relay\.mjs apply <upstream-relay-dir> <repo-dir> \[--allow-downgrade\]/);
  });
});
