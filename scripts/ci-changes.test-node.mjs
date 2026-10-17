import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import { cargoLockVersion, selectChecks, validateVersions, withoutVersion } from "./ci-changes.mjs";
import { setCargoPackageVersion } from "./set-app-version.mjs";

const unchanged = { frontend: false, native: false, packages: false, credentials: false };
const noRead = () => { throw new Error("not a version-only change"); };

test("UI changes do not run three native suites; Rust changes do not rebuild UI", () => {
  assert.deepEqual(selectChecks(["src/components/HostCard.tsx"], noRead), { ...unchanged, frontend: true });
  assert.deepEqual(selectChecks(["src-tauri/src/ssh/engine.rs"], noRead), { ...unchanged, native: true });
  assert.deepEqual(selectChecks(["src/bindings/Host.ts", "src-tauri/src/model.rs"], noRead), { ...unchanged, frontend: true, native: true });
});

test("version-only release edits skip compilation, dependency and config edits do not", () => {
  const files = ["package.json", "src-tauri/tauri.conf.json", "src-tauri/Cargo.toml", "src-tauri/Cargo.lock"];
  const read = (revision, path) => {
    const text = readFileSync(path, "utf8");
    if (revision === "head") return text;
    if (path.endsWith("Cargo.toml")) return setCargoPackageVersion(text, "0.0.0");
    if (path.endsWith("Cargo.lock")) return cargoLockVersion(text, "0.0.0");
    return JSON.stringify({ ...JSON.parse(text), version: "0.0.0" });
  };
  assert.deepEqual(selectChecks(files, read), unchanged);
  assert.equal(selectChecks(["package.json"], (revision) => JSON.stringify({ version: "1.5.0", dependencies: { react: revision === "head" ? "20" : "19" } })).frontend, true);
  assert.deepEqual(selectChecks(["src-tauri/tauri.conf.json"], revision => JSON.stringify({ version: "1.5.0", bundle: { active: revision === "head" } })), { ...unchanged, native: true, packages: true });
  assert.notEqual(withoutVersion("src-tauri/Cargo.toml", '[package]\nversion = "1"\n[dependencies]\nx = "1"'), withoutVersion("src-tauri/Cargo.toml", '[package]\nversion = "2"\n[dependencies]\nx = "2"'));
  assert.notEqual(withoutVersion("src-tauri/Cargo.lock", '[[package]]\nname = "sshelter"\nversion = "1"\n[[package]]\nname = "other"\nversion = "1"'), withoutVersion("src-tauri/Cargo.lock", '[[package]]\nname = "sshelter"\nversion = "2"\n[[package]]\nname = "other"\nversion = "2"'));
});

test("missing version files run checks, docs skip builds, manual runs force all routes", () => {
  assert.deepEqual(selectChecks(["src-tauri/tauri.conf.json"], noRead), { ...unchanged, native: true, packages: true });
  assert.deepEqual(selectChecks(["README.md", "src-tauri/signing/README.md"], noRead), unchanged);
  assert.deepEqual(selectChecks([], noRead, true), { frontend: true, native: true, packages: true, credentials: true });
  assert.deepEqual(selectChecks(["scripts/ci-changes.mjs"], noRead), { ...unchanged, frontend: true, native: true, credentials: true });
  assert.equal(selectChecks(["scripts/validate-windows-startup.ps1"], noRead).native, true);
  assert.equal(selectChecks(["src-tauri/Cargo.lock"], noRead).credentials, true);
  assert.equal(selectChecks(["scripts/build-macos-release.sh"], noRead).credentials, true);
});

test("a stale lock or release manifest fails the cheap version gate", () => {
  const read = path => readFileSync(path, "utf8");
  assert.equal(validateVersions(read), JSON.parse(read("package.json")).version);
  assert.throws(() => validateVersions(path => path === "src-tauri/Cargo.lock" ? read(path).replace(/(name = "sshelter"\nversion = ")[^"]+/, '$10.0.0') : read(path)));
  assert.throws(() => validateVersions(path => path === ".release-please-manifest.json" ? '{".":"0.0.0"}' : read(path)));
});
