import assert from "node:assert/strict";
import { execFileSync, spawnSync } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import {
  CONFIGURATIONS,
  CONSOLE_HELPER_CRATE,
  IDENTITY_SOURCE,
  MANIFESTS,
  PENDING_MANIFESTS,
  REPOSITORY,
  SOURCE_FIELDS,
  consoleHelper,
  cratePackageName,
  parseIdentitySource,
  readIdentity,
  readIdentitySource,
  readManifests,
  readProfiles,
  toEnv,
} from "./identity.mjs";

const SCRIPT = fileURLToPath(new URL("./identity.mjs", import.meta.url));
const json = path => JSON.parse(readFileSync(join(REPOSITORY, path), "utf8"));

// A checkout holding `files` (path to text, or to an object written as JSON), removed when the test ends.
function checkout(t, files) {
  const root = mkdtempSync(join(tmpdir(), "identity-"));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  for (const [path, content] of Object.entries(files)) {
    mkdirSync(dirname(join(root, path)), { recursive: true });
    writeFileSync(join(root, path), typeof content === "string" ? content : JSON.stringify(content));
  }
  return root;
}

const HELPER_CRATE = '[package]\nname = "acme-cli"\nversion = "0.1.0"\n\n[workspace]\n\n[[test]]\nname = "relay"\n';
const BASE = { identifier: "com.example.acme", productName: "Acme", mainBinaryName: "acme", bundle: { publisher: "example", active: true } };
// An identity.rs in the form the real module writes it, with the shared values as constants and a test that repeats a block.
const SOURCE = [
  "//! The one place this app's own identity values are written down.",
  'const PUBLISHER: &str = "example";',
  "",
  "pub const PRODUCTION: Identity = Identity {",
  '    app_id: "com.example.acme",',
  '    product_name: "Acme",',
  '    credential_service: "Acme",',
  '    login_item: "Acme",',
  '    installer_identity: "Acme",',
  "    publisher: PUBLISHER,",
  "};",
  "",
  "/// The Development profile runs beside Production.",
  "pub const DEVELOPMENT: Identity = Identity {",
  '    app_id: "com.example.acme.dev",',
  '    product_name: "Acme Dev",',
  '    credential_service: "Acme Development",',
  '    login_item: "Acme Dev",',
  '    installer_identity: "Acme Dev",',
  "    publisher: PUBLISHER,",
  "};",
  "",
  "/// The code-signing identifier of the macOS credential helper, protocol version 2.",
  'pub const HELPER_V2_IDENTIFIER: &str = "com.example.acme.helper-v2";',
  "",
  "#[cfg(test)]",
  "mod tests {",
  "    #[test]",
  "    fn production_values() {",
  "        assert_eq!(",
  "            PRODUCTION,",
  "            Identity {",
  '                credential_service: "Other",',
  '                login_item: "Other",',
  '                installer_identity: "Other",',
  "            }",
  "        );",
  "    }",
  "}",
  "",
].join("\n");
const SOURCE_VALUES = {
  production: { credentialService: "Acme", loginItem: "Acme", installerIdentity: "Acme" },
  development: { credentialService: "Acme Development", loginItem: "Acme Dev", installerIdentity: "Acme Dev" },
};

test("each profile's values come from its Tauri configuration, the console helper's from its crate, the rest from identity.rs", () => {
  const profiles = readProfiles();
  const source = readIdentitySource();
  assert.deepEqual(Object.keys(profiles), ["production", "development"]);
  for (const [profile, path] of Object.entries(CONFIGURATIONS)) {
    const config = json(path);
    assert.deepEqual(profiles[profile], {
      appId: config.identifier,
      productName: config.productName,
      publisher: config.bundle.publisher,
      mainBinary: config.mainBinaryName,
      consoleHelper: cratePackageName(readFileSync(join(REPOSITORY, CONSOLE_HELPER_CRATE), "utf8")),
      credentialService: source[profile].credentialService,
      loginItem: source[profile].loginItem,
      installerIdentity: source[profile].installerIdentity,
    }, profile);
  }
  assert.equal(profiles.production.appId, "dev.ysya.lunport");
  assert.equal(profiles.development.appId, "dev.ysya.lunport.dev");
});

// The macOS validators keep their items under the Development credential service, which no Tauri configuration holds and which is not
// the Development product name. The login items and installer identities are printed beside it, though no script reads them yet.
test("identity.rs gives each profile its credential service, login item and installer identity, and helper v2 its identifier", () => {
  const source = readIdentitySource();
  assert.deepEqual(Object.keys(source), ["production", "development", "helperV2Identifier"]);
  for (const profile of Object.keys(CONFIGURATIONS)) assert.deepEqual(Object.keys(source[profile]), Object.keys(SOURCE_FIELDS), profile);
  assert.deepEqual(source.production, { credentialService: "Lunport", loginItem: "Lunport", installerIdentity: "Lunport" });
  assert.deepEqual(source.development, { credentialService: "Lunport Development", loginItem: "Lunport Dev", installerIdentity: "Lunport Dev" });
  assert.notEqual(source.development.credentialService, readProfiles().development.productName);
  assert.equal(source.helperV2Identifier, "dev.ysya.lunport.credential-helper.v2");
  // The blocks read are the module's own constants, whatever its tests repeat: each holds the application id of its configuration.
  const text = readFileSync(join(REPOSITORY, IDENTITY_SOURCE), "utf8").replace(/\r\n/g, "\n");
  for (const [profile, name] of [["production", "PRODUCTION"], ["development", "DEVELOPMENT"]]) {
    const block = text.split(`\npub const ${name}: Identity = Identity {\n`)[1]?.split("\n};\n")[0];
    assert.ok(block?.includes(`    app_id: "${readProfiles()[profile].appId}",\n`), `${name} in ${IDENTITY_SOURCE}`);
  }
});

test("identity.rs is read in the form it writes its values, and any other form is refused with the line expected", () => {
  assert.deepEqual(parseIdentitySource(SOURCE), { ...SOURCE_VALUES, helperV2Identifier: "com.example.acme.helper-v2" });
  assert.deepEqual(parseIdentitySource(SOURCE.replace(/\n/g, "\r\n")), parseIdentitySource(SOURCE), "a Windows checkout");
  const cases = [
    // A field of one block is never taken from the other, nor from the tests.
    [SOURCE.replace('    credential_service: "Acme",\n', ""), /the PRODUCTION identity in src-tauri\/src\/identity\.rs has no `credential_service: "…",` line/],
    [SOURCE.replace('    login_item: "Acme Dev",\n', ""), /the DEVELOPMENT identity in src-tauri\/src\/identity\.rs has no `login_item: "…",` line/],
    [SOURCE.replace('installer_identity: "Acme Dev",', "installer_identity: INSTALLER_IDENTITY,"), /DEVELOPMENT identity .* no `installer_identity: "…",` line/],
    [SOURCE.replace('login_item: "Acme",', 'login_item: "Acme \\"Mobile\\"",'), /PRODUCTION identity .* no `login_item: "…",` line/],
    [SOURCE.replace("pub const DEVELOPMENT: Identity = Identity {", "pub const DEV: Identity = Identity {"), /has no `pub const DEVELOPMENT: Identity = Identity \{ … \};` block/],
    // A block that does not end where it should would run into the next one.
    [SOURCE.replace("    publisher: PUBLISHER,\n};\n\n/// The Development", "    publisher: PUBLISHER,\n\n/// The Development"), /the PRODUCTION identity in src-tauri\/src\/identity\.rs has more than one `app_id:` line/],
    [SOURCE.replace(/^pub const HELPER_V2_IDENTIFIER.*$/m, "pub const HELPER_V2_IDENTIFIER: &str = HELPER_V2;"), /has no `pub const HELPER_V2_IDENTIFIER: &str = "…";` line/],
    [SOURCE.replace('credential_service: "Acme Development",', 'credential_service: "",'), /credential_service of the DEVELOPMENT identity in src-tauri\/src\/identity\.rs must be a non-empty single-line string/],
  ];
  for (const [text, message] of cases) assert.throws(() => parseIdentitySource(text), message);
});

// windows-bundle-check.yml and scripts/validate-windows-rebrand.ps1 find the helper by that name.
test("the console helper is the main binary's name with -cli in both profiles", () => {
  for (const values of Object.values(readProfiles())) assert.equal(values.consoleHelper, `${values.mainBinary}-cli`);
});

test("Development is merged over Production, as tauri:dev merges it", t => {
  const root = checkout(t, {
    [CONFIGURATIONS.production]: BASE,
    [CONFIGURATIONS.development]: { identifier: "com.example.acme.dev", productName: "Acme Dev", bundle: { active: false } },
    [CONSOLE_HELPER_CRATE]: HELPER_CRATE,
    [IDENTITY_SOURCE]: SOURCE,
  });
  assert.deepEqual(readProfiles(root), {
    production: { appId: "com.example.acme", productName: "Acme", publisher: "example", mainBinary: "acme", consoleHelper: "acme-cli", ...SOURCE_VALUES.production },
    development: { appId: "com.example.acme.dev", productName: "Acme Dev", publisher: "example", mainBinary: "acme", consoleHelper: "acme-cli", ...SOURCE_VALUES.development },
  });
});

test("a missing, empty or multi-line value is refused with the file it belongs in", t => {
  const cases = [
    [{ ...BASE, mainBinaryName: undefined }, {}, /mainBinaryName in src-tauri\/tauri\.conf\.json/],
    [BASE, { productName: "" }, /productName in src-tauri\/tauri\.dev\.conf\.json/],
    [BASE, { bundle: { publisher: null } }, /bundle\.publisher in src-tauri\/tauri\.dev\.conf\.json/],
    [{ ...BASE, identifier: "com.example\nacme" }, {}, /identifier in src-tauri\/tauri\.conf\.json/],
  ];
  for (const [production, development, message] of cases) {
    const root = checkout(t, {
      [CONFIGURATIONS.production]: production,
      [CONFIGURATIONS.development]: development,
      [CONSOLE_HELPER_CRATE]: HELPER_CRATE,
      [IDENTITY_SOURCE]: SOURCE,
    });
    assert.throws(() => readProfiles(root), message);
  }
  const withoutSource = checkout(t, { [CONFIGURATIONS.production]: BASE, [CONFIGURATIONS.development]: {}, [CONSOLE_HELPER_CRATE]: HELPER_CRATE });
  assert.throws(() => readProfiles(withoutSource), /cannot read src-tauri\/src\/identity\.rs/);
});

test("a file that is not JSON is refused with its path", t => {
  const files = { [CONFIGURATIONS.production]: BASE, [CONFIGURATIONS.development]: {}, [CONSOLE_HELPER_CRATE]: HELPER_CRATE, [IDENTITY_SOURCE]: SOURCE };
  assert.throws(() => readProfiles(checkout(t, { ...files, [CONFIGURATIONS.development]: "{ productName: " })), /cannot parse src-tauri\/tauri\.dev\.conf\.json: /);
  assert.throws(() => readProfiles(checkout(t, { ...files, [CONFIGURATIONS.production]: "" })), /cannot parse src-tauri\/tauri\.conf\.json: /);
  const manifest = Object.values(MANIFESTS)[0];
  assert.throws(() => readManifests(checkout(t, { [manifest]: "not json" })), new RegExp(`cannot parse ${manifest.replace(/[.]/g, "\\.")}: `));
});

test("a crate's package name is read from its [package] table only", t => {
  assert.equal(cratePackageName(readFileSync(join(REPOSITORY, CONSOLE_HELPER_CRATE), "utf8")), readProfiles().production.consoleHelper);
  assert.equal(cratePackageName('[dependencies]\nname = "other"\n\n[package]\nversion = "1.0.0"\nname = "acme-cli"\n[[bin]]\nname = "x"\n'), "acme-cli");
  assert.equal(cratePackageName('[package]\r\nname = "acme-cli"\r\n'), "acme-cli");
  assert.throws(() => cratePackageName('[workspace]\nname = "acme-cli"\n'), /no \[package\] name/);
  // A checkout from before the helper was renamed has the earlier name, which is what a build of that checkout must use.
  assert.equal(consoleHelper(checkout(t, { [CONSOLE_HELPER_CRATE]: '[package]\nname = "earlier-cli"\n' })), "earlier-cli");
  assert.throws(() => consoleHelper(checkout(t, {})), /cannot read src-tauri\/cli-helper\/Cargo\.toml/);
});

test("each frozen executable's manifest is printed as it is, under its key", t => {
  assert.ok(Object.keys(MANIFESTS).length > 0);
  const manifests = readManifests();
  for (const [key, path] of Object.entries(MANIFESTS)) {
    if (existsSync(join(REPOSITORY, path))) assert.deepEqual(manifests[key], json(path), key);
    else assert.ok(PENDING_MANIFESTS.has(key) && !Object.hasOwn(manifests, key), `${key}: ${path} is missing`);
  }
  // Helper v2's entry is its manifest, or the identifier identity.rs gives it while that manifest is pending and missing.
  const helperV2 = manifests.helperV2 ?? { identifier: readIdentitySource().helperV2Identifier };
  assert.deepEqual(readIdentity(), { ...readProfiles(), ...manifests, helperV2 });
  const root = checkout(t, { [CONFIGURATIONS.production]: BASE, [CONFIGURATIONS.development]: {}, [CONSOLE_HELPER_CRATE]: HELPER_CRATE, [IDENTITY_SOURCE]: SOURCE });
  assert.throws(() => readIdentity(root), new RegExp(`cannot read ${MANIFESTS.helperV1.replace(/[.]/g, "\\.")}`));
});

// build-macos-credential-helper.sh signs a helper v2 candidate under this identifier before any manifest exists, and
// verify-macos-credential-helper.py holds every candidate's manifest to it.
test("helper v2's manifest must name identity.rs's identifier, which its entry holds alone while the manifest is pending", t => {
  // Nothing is pending now; this marks helper v2's manifest pending as it was until it was frozen, so that the fallback stays covered.
  PENDING_MANIFESTS.add("helperV2");
  t.after(() => PENDING_MANIFESTS.delete("helperV2"));
  const files = { [CONFIGURATIONS.production]: BASE, [CONFIGURATIONS.development]: {}, [CONSOLE_HELPER_CRATE]: HELPER_CRATE, [IDENTITY_SOURCE]: SOURCE };
  const v1 = { protocol: 1, identifier: "com.example.acme.helper-v1" };
  const bridge = { protocol: 1, identifier: "com.example.acme" };
  const identifierLines = identity => toEnv(identity).split("\n").filter(line => line.startsWith("HELPER_V2_IDENTIFIER="));
  const pending = readIdentity(checkout(t, { ...files, [MANIFESTS.helperV1]: v1, [MANIFESTS.bridge]: bridge }));
  assert.deepEqual(Object.keys(pending), ["production", "development", "helperV1", "helperV2", "bridge"]);
  assert.deepEqual(pending.helperV2, { identifier: "com.example.acme.helper-v2" });
  assert.deepEqual(identifierLines(pending), ["HELPER_V2_IDENTIFIER=com.example.acme.helper-v2"]);
  const v2 = { protocol: 2, identifier: "com.example.acme.helper-v2", cdhashes: { arm64: "ab", x86_64: "cd" } };
  const frozen = readIdentity(checkout(t, { ...files, [MANIFESTS.helperV1]: v1, [MANIFESTS.helperV2]: v2, [MANIFESTS.bridge]: bridge }));
  assert.deepEqual(frozen.helperV2, v2);
  assert.deepEqual(identifierLines(frozen), ["HELPER_V2_IDENTIFIER=com.example.acme.helper-v2"]);
  const other = checkout(t, { ...files, [MANIFESTS.helperV1]: v1, [MANIFESTS.helperV2]: { ...v2, identifier: "com.example.other" }, [MANIFESTS.bridge]: bridge });
  assert.throws(
    () => readIdentity(other),
    /src-tauri\/signing\/credential-helper-v2\.json names "com\.example\.other", but HELPER_V2_IDENTIFIER in src-tauri\/src\/identity\.rs is "com\.example\.acme\.helper-v2"/,
  );
});

// Helper v1, helper v2 and the bridge are all frozen and committed, so no manifest is pending and none may be missing.
test("the frozen macOS executables: helper v1, helper v2 and the bridge, all committed and required", t => {
  assert.deepEqual(MANIFESTS, {
    helperV1: "src-tauri/signing/legacy/credential-helper-v1.json",
    helperV2: "src-tauri/signing/credential-helper-v2.json",
    bridge: "src-tauri/signing/legacy/credential-bridge.json",
  });
  assert.deepEqual([...PENDING_MANIFESTS], []);
  assert.equal(readManifests().helperV1.identifier, json(MANIFESTS.helperV1).identifier);
  assert.equal(readManifests().helperV2.artifact_sha256, json(MANIFESTS.helperV2).artifact_sha256);
  assert.equal(readManifests().bridge.artifact_sha256, json(MANIFESTS.bridge).artifact_sha256);
  const without = checkout(t, { [MANIFESTS.helperV1]: {}, [MANIFESTS.bridge]: {} });
  assert.throws(() => readManifests(without), /cannot read src-tauri\/signing\/credential-helper-v2\.json/);
});

// Nothing is pending now; the mechanism stays for the next executable to be frozen, so this marks helper v2's manifest as it was until then.
test("a pending manifest is left out until it is committed, then printed like the others", t => {
  PENDING_MANIFESTS.add("helperV2");
  t.after(() => PENDING_MANIFESTS.delete("helperV2"));
  const manifest = (identifier, protocol) => ({ protocol, identifier, artifact_sha256: "ab", cdhashes: { arm64: "cd", x86_64: "ef" } });
  const v1 = manifest("com.example.acme.helper-v1", 1);
  const v2 = manifest("com.example.acme.helper-v2", 2);
  const bridge = manifest("com.example.acme", 1);
  const frozen = checkout(t, { [MANIFESTS.helperV1]: v1, [MANIFESTS.bridge]: bridge });
  assert.deepEqual(readManifests(frozen), { helperV1: v1, bridge });
  const all = checkout(t, { [MANIFESTS.helperV1]: v1, [MANIFESTS.helperV2]: v2, [MANIFESTS.bridge]: bridge });
  assert.deepEqual(readManifests(all), { helperV1: v1, helperV2: v2, bridge });
  // A pending manifest that is there is read like any other: one that is not JSON is refused.
  const broken = checkout(t, { [MANIFESTS.helperV1]: v1, [MANIFESTS.helperV2]: "{", [MANIFESTS.bridge]: bridge });
  assert.throws(() => readManifests(broken), /cannot parse src-tauri\/signing\/credential-helper-v2\.json: /);
  // Helper v1's and the bridge's manifests are never optional.
  assert.throws(() => readManifests(checkout(t, { [MANIFESTS.helperV2]: v2, [MANIFESTS.bridge]: bridge })), /cannot read src-tauri\/signing\/legacy\/credential-helper-v1\.json/);
  assert.throws(() => readManifests(checkout(t, { [MANIFESTS.helperV1]: v1 })), /cannot read src-tauri\/signing\/legacy\/credential-bridge\.json/);
  const identity = { production: { appId: "com.example.acme" }, development: { appId: "com.example.acme.dev" }, ...readManifests(all) };
  const env = toEnv(identity);
  for (const line of ["HELPER_V1_PROTOCOL=1", "HELPER_V2_PROTOCOL=2", "HELPER_V2_IDENTIFIER=com.example.acme.helper-v2", "BRIDGE_IDENTIFIER=com.example.acme", "BRIDGE_CDHASHES_X86_64=ef"]) {
    assert.ok(env.split("\n").includes(line), line);
  }
});

test("env lines hold one profile's values, then each manifest's under its key", () => {
  const identity = {
    production: { appId: "com.example.acme", productName: "Acme" },
    development: { appId: "com.example.acme.dev", productName: "Acme Dev" },
    helperV1: { protocol: 1, artifact_sha256: "ab", cdhashes: { arm64: "cd", x86_64: "ef" } },
  };
  const manifest = "HELPER_V1_PROTOCOL=1\nHELPER_V1_ARTIFACT_SHA256=ab\nHELPER_V1_CDHASHES_ARM64=cd\nHELPER_V1_CDHASHES_X86_64=ef\n";
  assert.equal(toEnv(identity), `APP_ID=com.example.acme\nPRODUCT_NAME=Acme\n${manifest}`);
  assert.equal(toEnv(identity, "development"), `APP_ID=com.example.acme.dev\nPRODUCT_NAME=Acme Dev\n${manifest}`);
  assert.throws(() => toEnv(identity, "staging"), /unknown profile "staging"/);
  assert.throws(() => toEnv({ ...identity, helperV1: { note: "two\nlines" } }), /HELPER_V1_NOTE must be a non-empty single-line string/);
});

test("the command prints both profiles' values and the frozen executables' as JSON, or one profile's as env lines", t => {
  const run = (...args) => execFileSync(process.execPath, [SCRIPT, ...args], { encoding: "utf8" });
  assert.deepEqual(JSON.parse(run()), readIdentity());
  assert.equal(run("--format", "env"), toEnv(readIdentity()));
  assert.equal(run("--format", "env", "--profile", "development"), toEnv(readIdentity(), "development"));
  const root = checkout(t, {
    [CONFIGURATIONS.production]: BASE,
    [CONFIGURATIONS.development]: {},
    [CONSOLE_HELPER_CRATE]: HELPER_CRATE,
    [IDENTITY_SOURCE]: SOURCE,
    [MANIFESTS.helperV1]: { identifier: "com.example.acme.helper-v1" },
    [MANIFESTS.helperV2]: { identifier: "com.example.acme.helper-v2" },
    [MANIFESTS.bridge]: { identifier: "com.example.acme" },
  });
  assert.deepEqual(JSON.parse(run("--root", root)), readIdentity(root));
  for (const [args, message] of [
    [["--format", "yaml"], /unknown format "yaml"/],
    [["--profile", "staging"], /unknown profile "staging"/],
    [["--verbose"], /Unknown option '--verbose'/],
  ]) {
    const result = spawnSync(process.execPath, [SCRIPT, ...args], { encoding: "utf8" });
    assert.equal(result.status, 1, args.join(" "));
    assert.match(result.stderr, message);
  }
});
