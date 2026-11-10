import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { ALLOWLIST, formatFindings, scanForNoteCitations } from "./note-citation-guard.mjs";

// The repository tests below scan this file like any other, so each citation the fixtures need is written with a `~` inside it, which
// keeps the text here from matching, and `cite` takes it out.
const cite = text => text.replaceAll("~", "");

// Writes `files` (path to text or bytes) into a fresh directory that is removed when the test ends, and returns it.
function fixture(t, files) {
  const root = mkdtempSync(join(tmpdir(), "note-citation-guard-"));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  for (const [path, content] of Object.entries(files)) {
    mkdirSync(dirname(join(root, path)), { recursive: true });
    writeFileSync(join(root, path), content);
  }
  return root;
}

// Scans every file of a fixture holding `files`.
const scan = (t, files) => scanForNoteCitations({ root: fixture(t, files), files: Object.keys(files) });

test("flags each form a citation takes, and a line with several once", t => {
  const cases = [
    ["// The layout follows docs/superpower~s/specs/sync.md.", "the folder planning notes were once kept in"],
    ["/// Spec ~§7.3: the shell's status reaches the client.", "a section of a spec, plan or design"],
    ["// As in design ~2026-10-26, AI edits.", "a design by its date"],
    ["/// The CLI's loop (plan ~1b).", "a plan by its number"],
    ["// Task ~3: what the console reads.", "a task of a plan"],
    ["// The hop is connected first (amended R~8).", "a requirement by its number"],
    ["// Review Focus ~4: no directory is no accounts.", "an item of a review's focus list"],
    ["// Fix round ~1 moved the retry.", "a round of review fixes"],
    ["// Kept for the final wav~e.", "a wave of reviews"],
    ["// Invisible to SP~1 clients.", "a sub-project by its number"],
    ["// 計畫 ~1 的範圍。", "a plan or a phase of one by its number"],
    ["//! 第 ~0 期從舊模組搬過來。", "a plan or a phase of one by its number"],
    ["// Plan ~1b R~17 and Task ~2 in one line.", "a plan by its number"],
  ].map(([line, names]) => [cite(line), names]);
  const findings = scan(t, { "src/a.rs": cases.map(([line]) => line).join("\n") });
  assert.deepEqual(
    findings.map(({ line, names }) => [line, names]),
    cases.map(([, names], index) => [index + 1, names]),
  );
});

test("a finding's text is its line without the indent or a Windows line ending", t => {
  const findings = scan(t, { "src/b.ts": cite("const a = 1;\r\n    // Task ~3: the console.\r\n") });
  assert.deepEqual(findings, [{ file: "src/b.ts", line: 2, text: cite("// Task ~3: the console."), names: "a task of a plan" }]);
});

test("leaves alone text that only looks like a citation", t => {
  const text = [
    "// RFC 4254 §6.10: the exit status of the remote command.",
    'StrCpy $R0 "$INSTDIR"',
    "IntCmp $R1 0 done",
    "// Keep the archive in Cloudflare R2.",
    "b3BlbnNzaC1rZXktdjEAAAAA+R1/bm9uZQAAAARub25lAAAAAAAAAAEAAAAz=R3",
    "// Phase 1 reads the file and phase 2 writes it.",
    "// AES-GCM as NIST SP800-38D describes it.",
    "// It planned 2 hosts, needs design 2.0 and ends the second fix round.",
    "// The Task list holds task 3 of the queue.",
  ].join("\n");
  assert.deepEqual(scan(t, { "src/c.rs": text }), []);
});

test("an allowlisted file is not read, and no look-alike of one is allowlisted", t => {
  const citation = cite("* Spec ~§7.3 is met.\n");
  const findings = scan(t, { "CHANGELOG.md": citation, "docs/CHANGELOG.md": citation, "CHANGELOG.md.orig": citation });
  assert.deepEqual(findings.map(finding => finding.file), ["docs/CHANGELOG.md", "CHANGELOG.md.orig"]);
});

test("skips binary files and files that git lists but that are gone", t => {
  const files = { "assets/icon.bin": Buffer.concat([Buffer.from("\0PNG\0"), Buffer.from(cite("Task ~3"))]) };
  const root = fixture(t, files);
  assert.deepEqual(scanForNoteCitations({ root, files: [...Object.keys(files), "src/deleted-but-not-staged.rs"] }), []);
});

test("the failure message names each line and what to write instead", () => {
  const message = formatFindings([
    { file: "src/a.rs", line: 3, text: cite("// Task ~3: the console."), names: "a task of a plan" },
    { file: "src/a.rs", line: 9, text: cite("// (R~17)"), names: "a requirement by its number" },
    { file: "docs/b.md", line: 1, text: cite("Spec ~§2"), names: "a section of a spec, plan or design" },
  ]);
  assert.match(message, /^3 lines in 2 files cite planning documents /);
  assert.ok(message.includes(cite("\n  src/a.rs:3: // Task ~3: the console. (a task of a plan)\n")), message);
  for (const part of ["AGENTS.md", "scripts/note-citation-guard.mjs"]) assert.ok(message.includes(part), part);
  assert.match(formatFindings([{ file: "a.rs", line: 1, text: "x", names: "y" }]), /^1 line in 1 file cites /);
});

test("a long line is cut down around the citation", () => {
  const text = `${"a ".repeat(150)}${cite("Task ~3")} ${"b ".repeat(150)}`;
  const shown = formatFindings([{ file: "docs/usage.md", line: 7, text, names: "a task of a plan" }])
    .split("\n")
    .find(line => line.includes("docs/usage.md:7:"));
  assert.ok(shown.includes(cite("Task ~3")), shown);
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

// Scans every file git lists in the checkout at `root` and fails with each finding; a checkout where git lists nothing fails too, so
// that a scan that read no file cannot pass. Returns the files it scanned.
function assertNoCitations(root) {
  const files = listed(root);
  assert.ok(files.length > 0, `git lists no files in ${root}`);
  const findings = scanForNoteCitations({ root, files });
  // assert.ok shows only the message; deepEqual would append a diff of every finding.
  assert.ok(findings.length === 0, formatFindings(findings));
  return files;
}

// Fails the build whenever a tracked file cites a planning document again.
test("the repository cites no planning document", () => {
  assertNoCitations(REPOSITORY);
});

test("the repository scan reads the files git lists and fails on a citation among them", t => {
  // The test above reads this checkout's files, the guard and this test among them, so it passes because it found nothing, not because
  // it read nothing.
  const files = listed(REPOSITORY);
  for (const file of ["scripts/note-citation-guard.mjs", "scripts/note-citation-guard.test-node.mjs", "AGENTS.md"]) {
    assert.ok(files.includes(file), `the scan does not read ${file}`);
  }
  // A checkout with a citation planted in a file git tracks fails with that line. A file git does not track is not read.
  const root = fixture(t, {
    "src/clean.ts": "export const NAME = \"Lunport\";\n",
    "src/planted.ts": cite("export const NAME = \"Lunport\";\n// Review Focus ~2: the name.\n"),
    "notes/untracked.md": cite("Task ~1\n"),
  });
  git(root, "-c", "init.defaultBranch=main", "init", "--quiet");
  assert.throws(() => assertNoCitations(root), /git lists no files in /);
  git(root, "add", "src");
  assert.throws(() => assertNoCitations(root), error => {
    assert.match(error.message, /^1 line in 1 file cites planning documents /);
    assert.ok(error.message.includes(cite("  src/planted.ts:2: // Review Focus ~2: the name.")), error.message);
    assert.ok(!error.message.includes("untracked"), error.message);
    return true;
  });
  // Once the citation is gone, the same checkout passes.
  writeFileSync(join(root, "src/planted.ts"), "export const NAME = \"Lunport\";\n");
  assert.deepEqual(assertNoCitations(root), ["src/clean.ts", "src/planted.ts"]);
});
