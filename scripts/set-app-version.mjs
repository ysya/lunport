#!/usr/bin/env node
// Stamps a beta version (X.Y.Z-N) into the three files that carry it, in the CI workspace only —
// beta builds never commit this back (release-please keeps owning the version on main):
//
//   node scripts/set-app-version.mjs 0.16.1-1
import { readFileSync, realpathSync, writeFileSync } from "node:fs";
import { pathToFileURL } from "node:url";

import { BETA_VERSION_RE, workflowCommandMessage } from "./beta-channel.mjs";

/** Replace the `version` key of the `[package]` table only; dependency tables keep theirs. */
export function setCargoPackageVersion(toml, version) {
  let table = "";
  let found = false;
  let replaced = false;
  const lines = toml.split("\n").map((line) => {
    const header = /^\s*\[([^\]]+)\]\s*$/.exec(line);
    if (header) {
      table = header[1].trim();
      return line;
    }
    if (!found && table === "package" && /^\s*version\s*=/.test(line)) {
      found = true;
      const quoted = /=\s*"[^"]*"/;
      if (quoted.test(line)) {
        replaced = true;
        // A replacer function, so `$&`, `$1` and friends in the version are written literally.
        return line.replace(quoted, () => `= "${version}"`);
      }
    }
    return line;
  });
  if (!found) throw new Error("Cargo.toml has no [package] version");
  if (!replaced) throw new Error("Cargo.toml's [package] version is not a double-quoted string");
  return lines.join("\n");
}

/** Replace the top-level `version` of a JSON document. */
export function setJsonVersion(text, version) {
  const data = JSON.parse(text);
  if (typeof data.version !== "string") throw new Error("the JSON document has no top-level version");
  data.version = version;
  return `${JSON.stringify(data, null, 2)}\n`;
}

function main(version) {
  if (!version) throw new Error("usage: set-app-version.mjs <version>");
  if (!BETA_VERSION_RE.test(version)) throw new Error(`invalid version "${version}" (expected X.Y.Z-N)`);
  for (const file of ["package.json", "src-tauri/tauri.conf.json"]) {
    writeFileSync(file, setJsonVersion(readFileSync(file, "utf8"), version));
  }
  const cargo = "src-tauri/Cargo.toml";
  writeFileSync(cargo, setCargoPackageVersion(readFileSync(cargo, "utf8"), version));
  console.log(`app version set to ${version}`);
}

if (process.argv[1] && import.meta.url === pathToFileURL(realpathSync(process.argv[1])).href) {
  try {
    main(process.argv[2]);
  } catch (error) {
    console.error(`::error::${workflowCommandMessage(error.message)}`);
    process.exit(1);
  }
}
