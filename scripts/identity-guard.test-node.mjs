import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { ALLOWLIST, formatFindings, scanForLegacyNames } from "./identity-guard.mjs";

// The repository tests below scan this file like any other, so the old names the fixtures need are assembled here, not written out.
const OLD_APP_ID = ["org", "home" + "lab", "ss" + "helter"].join(".");
const OLD_NAME = "SS" + "Helter";
const OLD_VENDOR = "home" + "lab";
const FROZEN = "frozen-identity:";

// Writes `files` (path to text or bytes) into a fresh directory that is removed when the test ends, and returns it.
function fixture(t, files) {
  const root = mkdtempSync(join(tmpdir(), "identity-guard-"));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  for (const [path, content] of Object.entries(files)) {
    mkdirSync(dirname(join(root, path)), { recursive: true });
    writeFileSync(join(root, path), content);
  }
  return root;
}

// Scans every file of a fixture holding `files`.
const scan = (t, files) => scanForLegacyNames({ root: fixture(t, files), files: Object.keys(files) });

test("flags an old name outside the allowlist", t => {
  // Indented and with Windows line endings: the finding's text is the line without either.
  const findings = scan(t, {
    "src/lib/store.ts": `const KEY = "lunport-ui";\r\n  const OLD = "${OLD_APP_ID}";\r\n`,
    "src/lib/clean.ts": 'export const NAME = "Lunport";\n',
  });
  assert.deepEqual(findings, [{ file: "src/lib/store.ts", line: 2, text: `const OLD = "${OLD_APP_ID}";` }]);
});

test("matches every old name in any case and reports a line once", t => {
  const text = [OLD_NAME, OLD_NAME.toUpperCase(), `Org.${OLD_VENDOR}`, OLD_VENDOR.toUpperCase(), `${OLD_APP_ID} ${OLD_NAME}`, "Lunport"].join("\n");
  assert.deepEqual(scan(t, { "docs/notes.md": text }).map(finding => finding.line), [1, 2, 3, 4, 5]);
});

test("accepts frozen-marked lines and allowlisted files", t => {
  const allowed = [
    "CHANGELOG.md",
    "src-tauri/src/legacy_identity.rs",
    "src/lib/legacy-identity.ts",
    "src/lib/legacy-identity.test.ts",
    "src-tauri/installers/legacy.nsh",
    "src-tauri/installers/legacy.wxi",
    "src-tauri/src/identity_migration/tests.rs",
    "src-tauri/signing/legacy/credential-helper-v1.c",
    "src-tauri/signing/legacy/credential-helper-v1.json",
    "src-tauri/signing/legacy/credential-helper-v1.bin",
    "src-tauri/signing/legacy/bridge/main.c",
    "relay/wrangler.jsonc",
    "relay/wrangler.private-core.example.jsonc",
  ];
  const files = Object.fromEntries(allowed.map(path => [path, `${OLD_APP_ID}\n`]));
  files["src-tauri/src/sync/crypto.rs"] = [
    `// ${FROZEN} the key-derivation input of data that is already stored`,
    `const INFO: &[u8] = b"${OLD_NAME}/v1";`,
    `const SALT: &[u8] = b"${OLD_NAME}"; // ${FROZEN} the salt of stored keys`,
  ].join("\n");
  assert.deepEqual(scan(t, files), []);
});

test("a marker covers its own line and the line below it, nothing further", t => {
  const text = [
    `// ${FROZEN} reason`,
    `const A: &str = "${OLD_NAME}";`,
    `const B: &str = "${OLD_NAME}";`,
    `const C: &str = "${OLD_NAME}"; // ${FROZEN} reason`,
    "const D: u8 = 0;",
  ].join("\n");
  assert.deepEqual(scan(t, { "src/a.rs": text }).map(finding => finding.line), [3]);
});

test("an allowlist entry covers what it names and no look-alike", t => {
  const covered = ["src-tauri/signing/legacy/deep/nested/case.c", "src-tauri/signing/legacy/bridge/main.c"];
  const lookAlikes = [
    // The migration's production code takes old names from legacy_identity like everything else; only its tests are allowlisted.
    "src-tauri/src/identity_migration/mod.rs",
    "src-tauri/src/identity_migration/tests.rs.orig",
    "src-tauri/signing/legacy-extra/main.c",
    // Helper v1 lives in legacy/; a copy beside helper v2 would be a stray old name.
    "src-tauri/signing/credential-helper-v1.c",
    "src-tauri/signing/credential-helper-v1.json",
    "docs/CHANGELOG.md",
    "relay/wrangler.jsonc.bak",
  ];
  const files = Object.fromEntries([...covered, ...lookAlikes].map(path => [path, OLD_APP_ID]));
  assert.deepEqual(scan(t, files).map(finding => finding.file), lookAlikes);
});

test("skips binary files and files that git lists but that are gone", t => {
  const files = { "assets/icon.bin": Buffer.concat([Buffer.from("\0PNG\0"), Buffer.from(OLD_APP_ID)]) };
  const root = fixture(t, files);
  assert.deepEqual(scanForLegacyNames({ root, files: [...Object.keys(files), "src/deleted-but-not-staged.rs"] }), []);
});

test("the failure message says where an old name belongs", () => {
  const message = formatFindings([
    { file: "src/a.ts", line: 3, text: 'const KEY = "x";' },
    { file: "src/a.ts", line: 9, text: "more" },
    { file: "src-tauri/b.rs", line: 1, text: "less" },
  ]);
  assert.match(message, /^3 lines in 2 files /);
  assert.match(message, /^ {2}src\/a\.ts:3: const KEY = "x";$/m);
  for (const place of ["legacy_identity", "legacy-identity", FROZEN, "scripts/identity-guard.mjs"]) assert.ok(message.includes(place), place);
});

test("a long line is cut down around the old name", () => {
  const text = `${"a".repeat(300)} ${OLD_NAME} ${"b".repeat(300)}`;
  const shown = formatFindings([{ file: "docs/usage.md", line: 7, text }]).split("\n").find(line => line.includes("docs/usage.md:7:"));
  assert.ok(shown.includes(OLD_NAME), shown);
  assert.ok(shown.length < 260, `${shown.length} characters`);
});

test("every allowlist entry gives a one-line reason", () => {
  assert.ok(ALLOWLIST.length > 0);
  for (const { glob, reason } of ALLOWLIST) assert.match(reason, /^\S[^\n]*$/, glob);
});

const REPOSITORY = fileURLToPath(new URL("..", import.meta.url));

// Git with none of the variables a hook or another git command may have set, so that it works on the repository at `root` alone.
function git(root, ...args) {
  const env = Object.fromEntries(Object.entries(process.env).filter(([name]) => !name.startsWith("GIT_")));
  return execFileSync("git", args, { cwd: root, env, encoding: "utf8" });
}

// The files git lists in the checkout at `root`: what the scan reads.
const listed = root => git(root, "ls-files", "-z").split("\0").filter(Boolean);

// Scans every file git lists in the checkout at `root`, and fails with each finding; a checkout where git lists nothing fails too, so
// that a scan that read no file cannot pass. Returns the files it scanned.
function assertNoOldNames(root) {
  const files = listed(root);
  assert.ok(files.length > 0, `git lists no files in ${root}`);
  const findings = scanForLegacyNames({ root, files });
  // assert.ok shows only the message; deepEqual would append a diff of every finding.
  assert.ok(findings.length === 0, formatFindings(findings));
  return files;
}

// Fails the build whenever an old name turns up outside the places that may hold one.
test("the repository has no unexpected old names", () => {
  assertNoOldNames(REPOSITORY);
});

test("the repository scan reads the files git lists and fails on an old name among them", t => {
  // The test above reads this checkout's files, the guard and this test among them, so it passes because it found nothing, not because
  // it read nothing.
  const files = listed(REPOSITORY);
  for (const file of ["scripts/identity-guard.mjs", "scripts/identity-guard.test-node.mjs", "src-tauri/src/identity.rs"]) {
    assert.ok(files.includes(file), `the scan does not read ${file}`);
  }
  // A checkout with an old name planted in a file git tracks fails with that line. A file git does not track is not read.
  const root = fixture(t, {
    "src/clean.ts": 'export const NAME = "Lunport";\n',
    "src/planted.ts": `export const NAME = "Lunport";\nconst OLD = "${OLD_APP_ID}";\n`,
    "notes/untracked.md": `${OLD_NAME}\n`,
  });
  git(root, "-c", "init.defaultBranch=main", "init", "--quiet");
  assert.throws(() => assertNoOldNames(root), /git lists no files in /);
  git(root, "add", "src");
  assert.throws(() => assertNoOldNames(root), error => {
    assert.match(error.message, /^1 line in 1 file use a name /);
    assert.ok(error.message.includes(`  src/planted.ts:2: const OLD = "${OLD_APP_ID}";`), error.message);
    assert.ok(!error.message.includes("untracked"), error.message);
    return true;
  });
  // Once the old name is gone, the same checkout passes.
  writeFileSync(join(root, "src/planted.ts"), 'export const NAME = "Lunport";\n');
  assert.deepEqual(assertNoOldNames(root), ["src/clean.ts", "src/planted.ts"]);
});
