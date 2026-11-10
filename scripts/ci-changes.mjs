// One path policy for PR checks. Dispatch runs everything; release-only version
// edits get consistency checks without recompiling the unchanged application.
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { appendFileSync, readFileSync, realpathSync } from "node:fs";
import { pathToFileURL } from "node:url";
import { cratePackageName } from "./identity.mjs";
import { setCargoPackageVersion } from "./set-app-version.mjs";

// The application crate's package name: the root package of its Cargo.lock.
const APPLICATION_PACKAGE = cratePackageName(readFileSync(new URL("../src-tauri/Cargo.toml", import.meta.url), "utf8"));
const escaped = text => text.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

export function cargoLockVersion(text, replacement) {
  const match = new RegExp(`\\[\\[package\\]\\]\\r?\\nname = "${escaped(APPLICATION_PACKAGE)}"\\r?\\nversion = "([^"]+)"`).exec(text);
  assert.ok(match, "Cargo.lock must contain the application package");
  return replacement === undefined ? match[1] : text.replace(match[0], match[0].replace(`version = "${match[1]}"`, `version = "${replacement}"`));
}

export function withoutVersion(path, text) {
  if (path === "package.json" || path === "src-tauri/tauri.conf.json") {
    const data = JSON.parse(text);
    assert.equal(typeof data.version, "string");
    delete data.version;
    return JSON.stringify(data);
  }
  if (path === "src-tauri/Cargo.toml") return setCargoPackageVersion(text, "0.0.0");
  if (path === "src-tauri/Cargo.lock") return cargoLockVersion(text, "0.0.0");
  return undefined;
}

export function selectChecks(files, readRevision, force = false) {
  const checks = { frontend: force, native: force, profiles: force, packages: force, credentials: force, windows: force };
  for (const path of files) {
    // CI policy edits exercise all routes once. Other workflow edits belong to
    // their own checks, rather than recompiling the app for a release label.
    if (/^scripts\/ci-changes(?:\.test-node)?\.mjs$/.test(path) || /^\.github\/workflows\/test-(engine|windows)\.yml$/.test(path)) {
      checks.frontend = checks.native = checks.profiles = checks.credentials = true;
    }
    if (/\.md$/.test(path)) continue;
    let versionOnly = false;
    if (["package.json", "src-tauri/tauri.conf.json", "src-tauri/Cargo.toml", "src-tauri/Cargo.lock"].includes(path)) {
      try {
        versionOnly = withoutVersion(path, readRevision("base", path)) === withoutVersion(path, readRevision("head", path));
      } catch {
        // Added, deleted or malformed files must not silently skip a build.
      }
    }
    if (versionOnly) continue;
    if (/^(src\/|public\/|tests\/browser\/|patches\/|index\.html$|package\.json$|pnpm-(lock|workspace)\.yaml$|vite\.config\.|tsconfig)/.test(path)) checks.frontend = true;
    // The release-profile test links the app library and checks profile selection,
    // identity, guarded writes and central sync. Other Rust changes use the full
    // platform debug suites without rebuilding both release profiles.
    if (/^src-tauri\/(?:Cargo\.(?:toml|lock)|build\.rs|tauri(?:\.dev)?\.conf\.json|tests\/app_profile_build\.rs|src\/(?:app_profile|identity|legacy_identity|write_policy|lib)\.rs)$/.test(path) || path.startsWith("src-tauri/src/sync/central/") || path.startsWith("vendor/tauri-runtime-wry/")) checks.profiles = true;
    // The Rust tests compare legacy_identity with scripts/legacy-identity.json; the Linux upgrade check reads it and scripts/identity.mjs.
    if (path.startsWith("src-tauri/") || path.startsWith("vendor/tauri-runtime-wry/") || /^scripts\/(validate-group-order-compat\.sh|compat\/|validate-windows-startup\.ps1|legacy-identity\.json$)/.test(path)) checks.native = true;
    if (/^src-tauri\/(tauri.*\.json$|icons\/|installers\/)/.test(path) || /^scripts\/(validate-linux-rebrand\.py|identity\.mjs|legacy-identity\.json)$/.test(path) || path === ".github/workflows/rebrand-package-check.yml") checks.packages = true;
    // The macOS credential checks also read the values the app pins the frozen helpers to (identity.rs, legacy_identity.rs), the app
    // identifier their production-signed test clients are signed with (tauri.conf.json), and the identity values their scripts read
    // (scripts/identity.mjs, which reads those files, and scripts/legacy-identity.json).
    if (/^src-tauri\/(Cargo\.(toml|lock)$|build\.rs$|tauri\.conf\.json$|signing\/|src\/(macos_credential|secrets\.rs|(legacy_)?identity\.rs$))/.test(path) || /^scripts\/(.*macos|identity\.mjs$|legacy-identity\.json$)/.test(path) || /^\.github\/workflows\/(macos-keychain-check|release|beta)\.yml$/.test(path)) checks.credentials = true;
    // The Windows suite, which native changes run anyway, builds the console helper with the Windows builds' script.
    if (/^scripts\/(windows-console-helper|identity)\.mjs$/.test(path)) checks.windows = true;
  }
  return checks;
}

export function validateVersions(read = path => readFileSync(path, "utf8")) {
  const version = JSON.parse(read("package.json")).version;
  assert.match(version, /^\d+\.\d+\.\d+(?:-\d+)?$/);
  assert.equal(JSON.parse(read("src-tauri/tauri.conf.json")).version, version, "Tauri version differs");
  const cargo = read("src-tauri/Cargo.toml").split(/^\[package\]\s*$/m)[1]?.split(/^\[/m)[0];
  assert.equal(cargo?.match(/^version\s*=\s*"([^"]+)"/m)?.[1], version, "Cargo version differs");
  assert.equal(cargoLockVersion(read("src-tauri/Cargo.lock")), version, "Cargo.lock version differs");
  assert.equal(JSON.parse(read(".release-please-manifest.json"))["."], version, "release-please version differs");
  return version;
}

function main() {
  const version = validateVersions();
  const force = process.env.GITHUB_EVENT_NAME === "workflow_dispatch";
  const refs = { base: process.env.BASE_SHA, head: process.env.HEAD_SHA };
  if (!force) for (const ref of Object.values(refs)) assert.match(ref ?? "", /^[a-f0-9]{40}$/);
  const git = args => execFileSync("git", args, { encoding: "utf8", maxBuffer: 16 * 1024 * 1024 });
  // No rename detection: moving a file must check both its old and new area.
  const files = force ? [] : git(["diff", "--name-only", "--no-renames", "-z", refs.base, refs.head]).split("\0").filter(Boolean);
  const checks = selectChecks(files, (revision, path) => git(["show", `${refs[revision]}:${path}`]), force);
  if (process.env.GITHUB_OUTPUT) appendFileSync(process.env.GITHUB_OUTPUT, Object.entries(checks).map(([key, value]) => `${key}=${value}\n`).join(""));
  console.log(JSON.stringify({ version, checks }, null, 2));
}

if (process.argv[1] && import.meta.url === pathToFileURL(realpathSync(process.argv[1])).href) main();
