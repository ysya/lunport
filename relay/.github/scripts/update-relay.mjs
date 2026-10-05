// Updates a relay deployed with the "Deploy to Cloudflare" button to an upstream SSHelter release.
// Used by .github/workflows/update-relay.yml. Node >= 20, no dependencies.
//   node update-relay.mjs apply <upstream-relay-dir> <repo-dir> [--allow-downgrade]  -> prints a JSON summary
//   node update-relay.mjs pr-body <summary.json> <upstream> <ref> <sha>              -> prints the pull request body
// An upstream relay older than this one changes nothing unless --allow-downgrade is given: the summary then has
// `skipped` and `message` instead.
import { copyFileSync, existsSync, mkdirSync, readFileSync, readdirSync, realpathSync, rmSync, statSync, writeFileSync } from "node:fs";
import { dirname, join, relative, sep } from "node:path";
import { pathToFileURL } from "node:url";

// The relay's own helper scripts under .github/; everything else there is the owner's. The update workflow itself is
// only compared: GitHub does not let a workflow push changes to .github/workflows/.
const SCRIPT_FILE = ".github/scripts/update-relay.mjs";
const MANAGED_GITHUB_FILES = new Set([SCRIPT_FILE, ".github/scripts/update-relay.test.mjs"]);
const WORKFLOW_FILE = ".github/workflows/update-relay.yml";
const SKIPPED_DIRS = new Set(["node_modules", ".wrangler"]);

/** Drop `//` and `/* *\/` comments outside strings, so JSON.parse can read a .jsonc file. */
export function stripJsonComments(text) {
  let out = "";
  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    if (c === '"') {
      const start = i;
      for (i++; i < text.length && text[i] !== '"'; i++) if (text[i] === "\\") i++;
      out += text.slice(start, i + 1);
    } else if (c === "/" && text[i + 1] === "/") {
      while (i < text.length && text[i] !== "\n") i++;
      out += "\n";
    } else if (c === "/" && text[i + 1] === "*") {
      i = text.indexOf("*/", i + 2) + 1;
      if (i === 0) throw new Error("unterminated block comment in wrangler.jsonc");
    } else {
      out += c;
    }
  }
  return out;
}

const parseJsonc = (text) => JSON.parse(stripJsonComments(text));

/** The `version` in `<dir>/package.json`. */
export function readRelayVersion(dir) {
  const file = join(dir, "package.json");
  if (!existsSync(file)) throw new Error(`${file} is missing, so the relay version is unknown`);
  const { version } = JSON.parse(readFileSync(file, "utf8"));
  if (typeof version !== "string" || version === "") throw new Error(`${file} has no version`);
  return version;
}

/** The numeric X.Y.Z core of a version. */
function versionCore(version) {
  const match = /^(\d+)\.(\d+)\.(\d+)(?:[-+].*)?$/.exec(String(version));
  if (!match) throw new Error(`relay version ${JSON.stringify(version)} has no X.Y.Z core`);
  return match.slice(1).map(Number);
}

/**
 * -1, 0 or 1 as `a` is older than, the same as or newer than `b`. Only the X.Y.Z core counts: a `-prerelease` or
 * `+build` suffix is ignored, so a future pre-release upstream never blocks an older deployed copy of this script.
 */
export function compareVersions(a, b) {
  const x = versionCore(a);
  const y = versionCore(b);
  for (let i = 0; i < 3; i++) {
    if (x[i] !== y[i]) return x[i] < y[i] ? -1 : 1;
  }
  return 0;
}

export function readWorkerName(wranglerText) {
  const name = parseJsonc(wranglerText).name;
  if (typeof name !== "string" || name === "") throw new Error("wrangler.jsonc has no Worker name");
  return name;
}

/** True when `match`, which ends `prefix`, sits inside a comment. */
function endsInComment(prefix, match) {
  try {
    return !stripJsonComments(prefix).endsWith(match);
  } catch {
    // Only an unterminated block comment throws. The whole file parsed, so this one closes after the match.
    return true;
  }
}

/** Put `name` back as the Worker name. Refuses rather than guess when the first "name" key is not the top-level one. */
export function withWorkerName(wranglerText, name) {
  const before = parseJsonc(wranglerText);
  if (typeof before.name !== "string") throw new Error("wrangler.jsonc has no top-level Worker name");
  // The first `"name": "..."` outside a comment. A match inside a comment disappears when the text up to its end
  // is stripped, so the stripped prefix no longer ends with it.
  const pattern = /"name"\s*:\s*"[^"]*"/g;
  let index = -1;
  let length = 0;
  for (let m = pattern.exec(wranglerText); m; m = pattern.exec(wranglerText)) {
    if (!endsInComment(wranglerText.slice(0, m.index + m[0].length), m[0])) {
      index = m.index;
      length = m[0].length;
      break;
    }
  }
  if (index < 0) throw new Error("wrangler.jsonc has no top-level Worker name");
  const next = `${wranglerText.slice(0, index)}"name": ${JSON.stringify(name)}${wranglerText.slice(index + length)}`;
  const after = parseJsonc(next);
  if (after.name !== name || JSON.stringify({ ...after, name: before.name }) !== JSON.stringify(before)) {
    throw new Error("wrangler.jsonc: the first \"name\" key is not the Worker name; keep your Worker name by hand");
  }
  return next;
}

export function planSync(upstreamFiles, repoFiles) {
  const managed = (path) => !path.startsWith(".github/") || MANAGED_GITHUB_FILES.has(path);
  const upstream = new Set(upstreamFiles);
  return {
    copy: upstreamFiles.filter(managed),
    // Never delete anything under .github/: an older upstream release may predate the scripts the owner already has.
    remove: repoFiles.filter((path) => !path.startsWith(".github/") && !upstream.has(path)),
  };
}

/** True when upstream has `path` and this repository lacks it or has different contents. */
function differsUpstream(upstreamDir, repoDir, path) {
  const upstream = join(upstreamDir, path);
  if (!existsSync(upstream)) return false;
  const local = join(repoDir, path);
  return !existsSync(local) || readFileSync(upstream, "utf8") !== readFileSync(local, "utf8");
}

/** True when the upstream release ships a different update workflow than this repository has. */
export function workflowOutdated(upstreamDir, repoDir) {
  return differsUpstream(upstreamDir, repoDir, WORKFLOW_FILE);
}

export function describeWranglerChanges(oldText, newText) {
  const before = parseJsonc(oldText);
  const after = parseJsonc(newText);
  const tags = (config) => (config.migrations ?? []).map((m) => m.tag);
  const known = new Set(tags(before));
  return {
    durableObjectsChanged: JSON.stringify(before.durable_objects ?? null) !== JSON.stringify(after.durable_objects ?? null),
    newMigrationTags: tags(after).filter((tag) => !known.has(tag)),
  };
}

// Upstream decides the ref, the versions, the removed files and the migration tags. Unescaped, a value such as
// `v1<!--` or a tag with a line break could open an HTML comment and hide the warnings after it in the pull request.

/** A Markdown code span; backticks and line breaks are dropped so the value can neither close it nor start a new line. */
const code = (value) => `\`${String(value).replace(/[`\r\n]/g, "")}\``;

/** Plain Markdown text on one line, with `<` and `>` escaped so the value cannot open an HTML tag or comment. */
const text = (value) => String(value).replace(/\r\n?|\n/g, " ").replace(/</g, "&lt;").replace(/>/g, "&gt;");

export function prBody(summary, upstream, ref, sha) {
  const removed = summary.removed.length ? summary.removed.map(code).join(", ") : "none";
  const workflowUrl = `https://github.com/${upstream}/blob/${sha}/relay/${WORKFLOW_FILE}`;
  return [
    `Updates this relay from **${text(summary.fromVersion)}** to **${text(summary.toVersion)}** — **${text(ref)}** of [${text(upstream)}](https://github.com/${upstream}) (commit ${code(sha)}).`,
    ...(summary.direction === "downgrade"
      ? ["", `**This is a downgrade.** Features newer than ${text(summary.toVersion)} go away when you merge it.`]
      : []),
    "",
    `Merging deploys it through Cloudflare Workers Builds. The Worker name ${code(summary.workerName)} is kept, so the relay URL and its stored data stay the same.`,
    "",
    `- Files removed: ${removed}`,
    `- Durable Object bindings: ${summary.durableObjectsChanged ? "**changed** — review `wrangler.jsonc` before merging" : "unchanged"}`,
    `- Migrations: ${summary.newMigrationTags.length ? `**new tags** ${summary.newMigrationTags.map(code).join(", ")} — they run on deploy and cannot be undone` : "none new"}`,
    `- Update workflow: ${summary.workflowOutdated ? `**changed upstream** — GitHub does not let this workflow edit workflow files, so copy [\`relay/${WORKFLOW_FILE}\`](${workflowUrl}) into \`.github/workflows/\` by hand` : "unchanged"}`,
    ...(summary.scriptChanged
      ? ["- Update script: **changed** — it runs with write access on the next update; review `.github/scripts/update-relay.mjs`."]
      : []),
  ].join("\n");
}

/**
 * Every file under `dir` as a POSIX path relative to it, skipping node_modules and .wrangler directories and every
 * entry named .git: a directory, or a file pointing at one (worktrees, submodules). What is not listed is never copied
 * from upstream and never removed from the repository.
 */
export function listFiles(dir) {
  const out = [];
  const walk = (current) => {
    for (const entry of readdirSync(current, { withFileTypes: true })) {
      if (entry.name === ".git") continue;
      if (entry.isDirectory()) {
        if (!SKIPPED_DIRS.has(entry.name)) walk(join(current, entry.name));
      } else if (entry.isFile()) {
        out.push(relative(dir, join(current, entry.name)).split(sep).join("/"));
      }
    }
  };
  walk(dir);
  return out.sort();
}

/**
 * Brings the relay in `repoDir` to the one in `upstreamDir`. An older upstream changes nothing unless
 * `allowDowngrade`; every check runs before the first file changes, so a refusal leaves the repository as it was.
 */
export function applyUpdate(upstreamDir, repoDir, { allowDowngrade = false } = {}) {
  const fromVersion = readRelayVersion(repoDir);
  const toVersion = readRelayVersion(upstreamDir);
  const order = compareVersions(fromVersion, toVersion);
  const direction = order < 0 ? "upgrade" : order === 0 ? "same" : "downgrade";
  if (direction === "downgrade" && !allowDowngrade) {
    return {
      skipped: "downgrade",
      fromVersion,
      toVersion,
      direction,
      message: `This relay (${fromVersion}) is newer than the upstream release (${toVersion}); nothing to do. Run the workflow with an explicit ref to downgrade.`,
    };
  }
  const oldWrangler = readFileSync(join(repoDir, "wrangler.jsonc"), "utf8");
  const workerName = readWorkerName(oldWrangler);
  const newWrangler = withWorkerName(readFileSync(join(upstreamDir, "wrangler.jsonc"), "utf8"), workerName);
  // Compared before the copy below replaces the repository's script.
  const scriptChanged = differsUpstream(upstreamDir, repoDir, SCRIPT_FILE);
  const plan = planSync(listFiles(upstreamDir), listFiles(repoDir));
  for (const path of plan.copy) {
    mkdirSync(dirname(join(repoDir, path)), { recursive: true });
    copyFileSync(join(upstreamDir, path), join(repoDir, path));
  }
  for (const path of plan.remove) rmSync(join(repoDir, path));
  writeFileSync(join(repoDir, "wrangler.jsonc"), newWrangler);
  return {
    workerName,
    fromVersion,
    toVersion,
    direction,
    removed: plan.remove,
    workflowOutdated: workflowOutdated(upstreamDir, repoDir),
    scriptChanged,
    ...describeWranglerChanges(oldWrangler, newWrangler),
  };
}

/** True when node was started with this file, also through a symlinked path. */
function invokedDirectly() {
  if (!process.argv[1]) return false;
  try {
    return import.meta.url === pathToFileURL(realpathSync(process.argv[1])).href;
  } catch {
    return false;
  }
}

if (invokedDirectly()) {
  const [command, ...args] = process.argv.slice(2);
  const allowDowngrade = args[2] === "--allow-downgrade";
  if (command === "apply" && args.length === (allowDowngrade ? 3 : 2) && statSync(args[0]).isDirectory()) {
    console.log(JSON.stringify(applyUpdate(args[0], args[1], { allowDowngrade })));
  } else if (command === "pr-body" && args.length === 4) {
    console.log(prBody(JSON.parse(readFileSync(args[0], "utf8")), args[1], args[2], args[3]));
  } else {
    console.error(
      "usage: update-relay.mjs apply <upstream-relay-dir> <repo-dir> [--allow-downgrade] | pr-body <summary.json> <upstream> <ref> <sha>",
    );
    process.exit(2);
  }
}
