// The identity installs had before 2.0 is written three times: in the NSIS include, in the WiX include, and in
// scripts/legacy-identity.json for the scripts that upgrade and check those installs. These tests keep the copies equal for both
// profiles, each keyed on the profile's current identifier from the Tauri configurations.
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

const read = path => readFileSync(new URL(`../${path}`, import.meta.url), "utf8");
const json = JSON.parse(read("scripts/legacy-identity.json"));
const identifiers = {
  production: JSON.parse(read("src-tauri/tauri.conf.json")).identifier,
  development: JSON.parse(read("src-tauri/tauri.dev.conf.json")).identifier,
};

// The installer identity each current identifier maps to, from a table of `if`/`elseif` branches that define it.
function table(lines, branch, define) {
  const map = {};
  let current;
  for (const line of lines) {
    const opened = line.match(branch);
    if (opened) current = opened[1];
    else if (/^\s*(!else|<\?else\?>)\s*$/.test(line) || /^\s*(!endif|<\?endif\?>)/.test(line)) current = undefined;
    const defined = line.match(define);
    if (defined && current !== undefined) map[current] = defined[1];
  }
  return map;
}

function nsis() {
  const text = read("src-tauri/installers/legacy.nsh");
  const defines = Object.fromEntries([...text.matchAll(/^!define (LEGACY_\w+) "([^"]*)"$/gm)].map(match => [match[1], match[2]]));
  const identities = table(
    text.split("\n"),
    /^\s*!(?:else )?if "\$\{BUNDLEID\}" == "([^"]+)"/,
    /^\s*!define LEGACY_INSTALLER_IDENTITY "([^"]*)"/,
  );
  return { defines, identities };
}

function wix() {
  const text = read("src-tauri/installers/legacy.wxi");
  const defines = Object.fromEntries([...text.matchAll(/<\?define (\w+) = "([^"]*)" \?>/g)].map(match => [match[1], match[2]]));
  const identities = table(
    text.split("\n"),
    /<\?(?:else)?if \$\(var\.BundleIdentifier\) = "([^"]+)" \?>/,
    /<\?define LegacyInstallerIdentity = "([^"]*)" \?>/,
  );
  return { defines, identities };
}

test("both includes map exactly the two current identifiers", () => {
  const expected = Object.values(identifiers).sort();
  assert.deepEqual(Object.keys(nsis().identities).sort(), expected);
  assert.deepEqual(Object.keys(wix().identities).sort(), expected);
});

for (const profile of Object.keys(identifiers)) {
  test(`the ${profile} profile has one earlier installer identity everywhere`, () => {
    const id = identifiers[profile];
    const values = json[profile];
    assert.ok(values?.installerIdentity, `scripts/legacy-identity.json has no ${profile} installerIdentity`);
    assert.equal(nsis().identities[id], values.installerIdentity, "legacy.nsh");
    assert.equal(wix().identities[id], values.installerIdentity, "legacy.wxi");
    // The NSIS uninstaller removes the earlier login entry under the installer identity.
    assert.equal(values.loginItem, values.installerIdentity, "loginItem");
  });

  test(`the ${profile} profile has the same earlier manufacturer and executables everywhere`, () => {
    const values = json[profile];
    const { defines } = nsis();
    assert.equal(defines.LEGACY_MANUFACTURER, values.manufacturer, "legacy.nsh manufacturer");
    assert.equal(wix().defines.LegacyManufacturer, values.manufacturer, "legacy.wxi manufacturer");
    assert.equal(defines.LEGACY_BINARY, values.mainBinary, "legacy.nsh main binary");
    assert.equal(defines.LEGACY_CONSOLE_HELPER, values.consoleHelper, "legacy.nsh console helper");
  });
}

test("the WiX registry key and shortcut name are built from the identity, not written again", () => {
  const { defines } = wix();
  assert.equal(defines.LegacyProductKey, "Software\\$(var.LegacyManufacturer)\\$(var.LegacyInstallerIdentity)");
  assert.equal(defines.LegacyShortcutName, "$(var.LegacyInstallerIdentity)");
});
