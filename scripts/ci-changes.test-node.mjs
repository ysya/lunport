import assert from "node:assert/strict";
import { readFileSync, readdirSync } from "node:fs";
import test from "node:test";
import { cargoLockVersion, selectChecks, validateVersions, withoutVersion } from "./ci-changes.mjs";
import { cratePackageName } from "./identity.mjs";
import { setCargoPackageVersion } from "./set-app-version.mjs";

const unchanged = { frontend: false, native: false, packages: false, credentials: false, windows: false };
// The application crate's package name, which ci-changes.mjs finds in Cargo.lock.
const PACKAGE = cratePackageName(readFileSync("src-tauri/Cargo.toml", "utf8"));
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
  assert.deepEqual(selectChecks(["src-tauri/tauri.conf.json"], revision => JSON.stringify({ version: "1.5.0", bundle: { active: revision === "head" } })), { ...unchanged, native: true, packages: true, credentials: true });
  assert.notEqual(withoutVersion("src-tauri/Cargo.toml", '[package]\nversion = "1"\n[dependencies]\nx = "1"'), withoutVersion("src-tauri/Cargo.toml", '[package]\nversion = "2"\n[dependencies]\nx = "2"'));
  const lock = version => `[[package]]\nname = "${PACKAGE}"\nversion = "${version}"\n[[package]]\nname = "other"\nversion = "${version}"`;
  assert.notEqual(withoutVersion("src-tauri/Cargo.lock", lock("1")), withoutVersion("src-tauri/Cargo.lock", lock("2")));
});

test("missing version files run checks, docs skip builds, manual runs force all routes", () => {
  assert.deepEqual(selectChecks(["src-tauri/tauri.conf.json"], noRead), { ...unchanged, native: true, packages: true, credentials: true });
  assert.deepEqual(selectChecks(["README.md", "src-tauri/signing/README.md"], noRead), unchanged);
  assert.deepEqual(selectChecks([], noRead, true), { frontend: true, native: true, packages: true, credentials: true, windows: true });
  assert.deepEqual(selectChecks(["scripts/ci-changes.mjs"], noRead), { ...unchanged, frontend: true, native: true, credentials: true });
  assert.equal(selectChecks(["scripts/validate-windows-startup.ps1"], noRead).native, true);
  assert.equal(selectChecks(["src-tauri/Cargo.lock"], noRead).credentials, true);
  assert.equal(selectChecks(["scripts/build-macos-release.sh"], noRead).credentials, true);
});

// The Linux upgrade check, the Windows suite and the macOS credential scripts read scripts/identity.mjs; the Linux and macOS checks and
// the Rust tests read scripts/legacy-identity.json.
test("identity data and the console helper step run the checks that read them", () => {
  assert.deepEqual(selectChecks(["scripts/identity.mjs"], noRead), { ...unchanged, packages: true, credentials: true, windows: true });
  assert.deepEqual(selectChecks(["scripts/windows-console-helper.mjs"], noRead), { ...unchanged, windows: true });
  assert.deepEqual(selectChecks(["scripts/windows-console-helper.test-node.mjs", "scripts/identity.test-node.mjs"], noRead), unchanged);
  assert.deepEqual(selectChecks(["scripts/legacy-identity.json"], noRead), { ...unchanged, native: true, packages: true, credentials: true });
  assert.deepEqual(selectChecks(["scripts/validate-linux-rebrand.py"], noRead), { ...unchanged, packages: true });
  // Look-alikes of the identity data are none of it.
  for (const path of ["scripts/identity.mjs.orig", "scripts/legacy-identity.test-node.mjs", "scripts/identity-guard.mjs"]) {
    assert.equal(selectChecks([path], noRead).credentials, false, path);
  }
});

// The macOS credential checks read the frozen helpers and their sources, the values the app pins them to (identity.rs and
// legacy_identity.rs), the app identifier the production-signed test clients are signed with (tauri.conf.json) and their own scripts.
test("the frozen helpers, their pins and the app identifier run the macOS credential checks", () => {
  for (const path of [
    "src-tauri/signing/credential-helper-v2.c",
    "src-tauri/signing/credential-helper-v2.json",
    "src-tauri/signing/legacy/credential-helper-v1.bin",
    "src-tauri/signing/legacy/credential-bridge.c",
    "src-tauri/signing/macos-project.pem",
    "src-tauri/src/identity.rs",
    "src-tauri/src/legacy_identity.rs",
    "src-tauri/src/macos_credential_helper.rs",
    "scripts/validate-macos-bridge.sh",
    "scripts/macos-bridge-client.c",
    "scripts/macos-helper-client.c",
    "scripts/validate-macos-frozen-helper.sh",
    ".github/workflows/macos-keychain-check.yml",
  ]) {
    assert.equal(selectChecks([path], noRead).credentials, true, path);
  }
  assert.deepEqual(selectChecks(["src-tauri/src/identity.rs"], noRead), { ...unchanged, native: true, credentials: true });
  // Look-alikes and other Rust code stay with the native suites.
  for (const path of ["src-tauri/src/identity_migration/mod.rs", "src-tauri/src/identity_migration/credentials_macos.rs", "src-tauri/src/identity.rs.orig", "src-tauri/tauri.dev.conf.json"]) {
    assert.equal(selectChecks([path], noRead).credentials, false, path);
  }
});

// A job whose condition reads a selection output that does not exist reads an empty string and is skipped, and a skipped required job
// reports as passing: a typo in an output's name, in the step output it passes on or in a condition would silently drop a check.
test("workflows pass each selection on under its own name, and their conditions read only those outputs", () => {
  const selections = Object.keys(selectChecks([], noRead, true));
  const workflows = readdirSync(".github/workflows").filter(name => name.endsWith(".yml"));
  const selecting = workflows.filter(name => readFileSync(`.github/workflows/${name}`, "utf8").includes("run: node scripts/ci-changes.mjs"));
  assert.deepEqual(selecting.sort(), ["macos-keychain-check.yml", "rebrand-package-check.yml", "test-engine.yml", "test-windows.yml"]);
  for (const name of workflows) {
    const text = readFileSync(`.github/workflows/${name}`, "utf8");
    const outputs = [...text.matchAll(/^ {6}([\w-]+): \$\{\{ steps\.select\.outputs\.([\w-]+) \}\}$/gm)].map(([, output, step]) => {
      assert.equal(output, step, `${name} passes the selection ${step} on as ${output}`);
      assert.ok(selections.includes(step), `${name} passes on ${step}, which scripts/ci-changes.mjs does not select`);
      return output;
    });
    assert.equal(outputs.length > 0, selecting.includes(name), `${name}: selection outputs without the selection step, or the reverse`);
    for (const [, output, comparison] of text.matchAll(/needs\.changes\.outputs\.([\w-]+)( == 'true')?/g)) {
      assert.ok(outputs.includes(output), `${name} reads needs.changes.outputs.${output}, which its selection job does not declare`);
      // Outputs are strings: a comparison with true, or none, never matches.
      assert.ok(comparison, `${name} reads needs.changes.outputs.${output} without comparing it with 'true'`);
    }
  }
  // The required Windows job runs for native changes and for the scripts its console helper step shares with the Windows builds.
  const windows = readFileSync(".github/workflows/test-windows.yml", "utf8");
  assert.deepEqual([...windows.matchAll(/^ {6}([\w-]+): \$\{\{ steps\.select\.outputs\.[\w-]+ \}\}$/gm)].map(match => match[1]), ["native", "windows"]);
  const slots = windows.split(/^(?= {2}[\w-]+:$)/m).find(job => /^ {2}slots:\r?$/m.test(job));
  assert.ok(slots, "test-windows.yml has no slots job");
  assert.match(slots, /^ {4}name: Rust, SSH and native smoke \(Windows\)$/m);
  assert.deepEqual(
    [...slots.matchAll(/^ {4}if: (.*)$/gm)].map(match => match[1]),
    ["needs.changes.outputs.native == 'true' || needs.changes.outputs.windows == 'true'"],
  );
  assert.equal(selectChecks(["scripts/windows-console-helper.mjs"], noRead).windows, true);
});

test("a stale lock or release manifest fails the cheap version gate", () => {
  const read = path => readFileSync(path, "utf8");
  assert.equal(validateVersions(read), JSON.parse(read("package.json")).version);
  assert.throws(() => validateVersions(path => path === "src-tauri/Cargo.lock" ? read(path).replace(new RegExp(`(name = "${PACKAGE}"\\nversion = ")[^"]+`), "$10.0.0") : read(path)));
  assert.throws(() => validateVersions(path => path === ".release-please-manifest.json" ? '{".":"0.0.0"}' : read(path)));
});

test("terminal patches, workspace configuration and browser regressions run frontend checks", () => {
  for (const path of ["patches/@wterm__dom@0.5.4.patch", "pnpm-workspace.yaml", "tests/browser/terminal-qa.mjs", "tests/browser/terminal-harness.ts", "tests/browser/terminal.html", "tests/browser/fixtures/ubuntu-vim-startup.json"]) {
    assert.deepEqual(selectChecks([path], noRead), { ...unchanged, frontend: true }, path);
  }
});
