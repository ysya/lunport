// One path policy for PR checks. Dispatch runs everything; release-only version
// edits get consistency checks without recompiling the unchanged application.
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { appendFileSync, readFileSync, realpathSync } from "node:fs";
import { pathToFileURL } from "node:url";
import { setCargoPackageVersion } from "./set-app-version.mjs";

export function cargoLockVersion(text, replacement) {
  const match = /\[\[package\]\]\r?\nname = "sshelter"\r?\nversion = "([^"]+)"/.exec(text);
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
  const checks = { frontend: force, native: force, packages: force, credentials: force };
  for (const path of files) {
    // CI policy edits exercise all routes once. Other workflow edits belong to
    // their own checks, rather than recompiling the app for a release label.
    if (/^scripts\/ci-changes(?:\.test-node)?\.mjs$/.test(path) || /^\.github\/workflows\/test-(engine|windows)\.yml$/.test(path)) {
      checks.frontend = checks.native = checks.credentials = true;
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
    if (/^(src\/|public\/|index\.html$|package\.json$|pnpm-lock\.yaml$|vite\.config\.|tsconfig)/.test(path)) checks.frontend = true;
    if (path.startsWith("src-tauri/") || /^scripts\/(validate-group-order-compat\.sh|compat\/|validate-windows-startup\.ps1)/.test(path)) checks.native = true;
    if (/^src-tauri\/(tauri.*\.json$|icons\/|installers\/)/.test(path) || path === "scripts/validate-linux-rebrand.py" || path === ".github/workflows/rebrand-package-check.yml") checks.packages = true;
    if (/^src-tauri\/(Cargo\.(toml|lock)$|build\.rs$|signing\/|src\/(macos_credential|secrets\.rs))/.test(path) || /^scripts\/.*macos/.test(path) || /^\.github\/workflows\/(macos-keychain-check|release|beta)\.yml$/.test(path)) checks.credentials = true;
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
