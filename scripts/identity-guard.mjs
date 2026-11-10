// Finds names the app had before it became Lunport where only the current names belong. An old name is written once, in `legacy_identity`
// (Rust) or `legacy-identity` (TypeScript); the few other places that may hold one are listed in ALLOWLIST, each with its reason.
import { readFileSync } from "node:fs";
import { join } from "node:path";

// A bracketed letter in each name keeps this file from matching its own pattern, so it needs no allowlist entry of its own.
const OLD_NAME = /ssh[e]lter|org\.hom[e]lab|hom[e]lab/i;

// A frozen protocol constant (a key-derivation input, a hash domain, a file name already on disk or on a server) cannot be renamed
// without breaking what exists. It stays where it is, with this marker in a comment on its line or on the line above.
const MARKER = "frozen-identity:";

// Paths from the repository root, as `git ls-files` prints them. Only `**` is a wildcard (any text, slashes included), as in `dir/**`.
export const ALLOWLIST = [
  { glob: "CHANGELOG.md", reason: "release history keeps the name each release shipped under" },
  { glob: "src-tauri/src/legacy_identity.rs", reason: "the Rust module that holds every old name" },
  { glob: "src/lib/legacy-identity.ts", reason: "the TypeScript module that holds every old name" },
  { glob: "src/lib/legacy-identity.test.ts", reason: "the tests of that TypeScript module" },
  { glob: "src-tauri/installers/legacy.nsh", reason: "NSIS include that finds and removes the old Windows install" },
  { glob: "src-tauri/installers/legacy.wxi", reason: "WiX include that finds and removes the old Windows install" },
  { glob: "scripts/legacy-identity.json", reason: "old values the upgrade validators need" },
  { glob: "src-tauri/src/identity_migration/tests.rs", reason: "the data migration's tests, whose fixtures are the old data folders" },
  { glob: "src-tauri/src/identity_migration/credentials_tests.rs", reason: "the credential migration's tests, whose fixtures are items saved under the old credential services" },
  { glob: "src-tauri/src/identity_migration/credentials_runs_tests.rs", reason: "the credential step's tests in the migration's runs, whose fixtures are the old data folder and old credential services" },
  { glob: "src-tauri/src/identity_migration/credentials_windows_tests.rs", reason: "the Windows credential migration's tests, whose fixtures are entries named after the old services" },
  { glob: "src-tauri/src/identity_migration/credentials_linux_tests.rs", reason: "the Secret Service migration's tests, whose fixtures are items of the old services" },
  { glob: "src-tauri/src/identity_migration/login_item_tests.rs", reason: "migration tests and fixtures" },
  { glob: "src-tauri/src/identity_migration/mcp_configs_tests.rs", reason: "migration tests and fixtures" },
  { glob: "src-tauri/signing/legacy/**", reason: "frozen helper v1 (source, manifest, signed binary), the bridge to it and the certificate both were signed with" },
  { glob: "relay/wrangler.jsonc", reason: "the Worker name is a frozen server identity" },
  { glob: "relay/wrangler.private-core.example.jsonc", reason: "the same Worker name, in the example configuration" },
];

function globToRegExp(glob) {
  const source = glob.split("**").map(part => part.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")).join(".*");
  return new RegExp(`^${source}$`);
}

const allowed = ALLOWLIST.map(({ glob }) => globToRegExp(glob));

// The text of a file, or undefined for a binary file (it holds a NUL byte, which is also how git tells) and for a path that git still
// lists but that is gone from the working tree.
function readText(path) {
  let bytes;
  try {
    bytes = readFileSync(path);
  } catch (error) {
    if (error.code === "ENOENT") return undefined;
    throw error;
  }
  return bytes.includes(0) ? undefined : bytes.toString("utf8");
}

// The lines of `files` (paths from `root`) that hold an old name, as { file, line, text } with `line` counted from 1. Allowlisted
// files, binary files and lines marked frozen are left out, and a line with several names is one finding.
export function scanForLegacyNames({ root, files }) {
  const findings = [];
  for (const file of files) {
    if (allowed.some(pattern => pattern.test(file))) continue;
    const text = readText(join(root, file));
    if (text === undefined) continue;
    const lines = text.split("\n");
    lines.forEach((line, index) => {
      if (!OLD_NAME.test(line) || line.includes(MARKER) || lines[index - 1]?.includes(MARKER)) return;
      findings.push({ file, line: index + 1, text: line.trim() });
    });
  }
  return findings;
}

const plural = (count, noun) => `${count} ${noun}${count === 1 ? "" : "s"}`;

// A finding's text for the failure message: a long line is cut down to a window that keeps the old name in view.
function shown(text, width = 160) {
  if (text.length <= width) return text;
  const start = Math.max(0, text.search(OLD_NAME) - 40);
  const end = start + width;
  return `${start > 0 ? "..." : ""}${text.slice(start, end)}${end < text.length ? "..." : ""}`;
}

// The failure message: every finding as `file:line: text`, then where old names belong.
export function formatFindings(findings) {
  const files = new Set(findings.map(finding => finding.file)).size;
  return [
    `${plural(findings.length, "line")} in ${plural(files, "file")} use a name the app had before it became Lunport:`,
    ...findings.map(({ file, line, text }) => `  ${file}:${line}: ${shown(text)}`),
    "",
    "An old name is written once per language, and everything else uses the current names:",
    "  Rust        the `legacy_identity` module (src-tauri/src/legacy_identity.rs)",
    "  TypeScript  the `legacy-identity` module (src/lib/legacy-identity.ts)",
    `  A protocol constant that can never change stays where it is, with \`${MARKER} <why>\` in a comment on its line or the line above.`,
    "The other places that may hold an old name, and why, are listed in ALLOWLIST in scripts/identity-guard.mjs.",
  ].join("\n");
}
