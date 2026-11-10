#!/usr/bin/env node
// Lunport's identity values for scripts and workflows, read from the files the build itself reads, so that no script writes one again:
//
//   node scripts/identity.mjs                                          both profiles' values, then the frozen executables', as JSON
//   node scripts/identity.mjs --format env [--profile development]     KEY=value lines: one profile's values (Production's by
//                                                                      default), then the frozen executables'
//   --root <dir>                                                       reads another checkout than this script's
//
// A profile's values are its application id, product name, publisher, main binary, console helper, credential service, login item and
// installer identity. The first four come from its Tauri configuration (Development's merged over Production's, as `pnpm tauri:dev`
// merges it). The console helper's name comes from its crate, which cargo names the executable after: Windows builds bundle the helper
// through `tauri build --config`, so no configuration holds it. The last three, which no configuration holds either, come from
// src-tauri/src/identity.rs (IDENTITY_SOURCE), where the app reads all of these values; its tests compare the ones the configurations
// and the crate repeat. The frozen macOS executables' values come from the manifests written when each was frozen (MANIFESTS);
// helper v2's must name the identifier identity.rs gives it. The pipe and thread prefixes, which only the app uses, are not
// printed. The names installs had before 2.0 are in scripts/legacy-identity.json.
//
// The env lines suit $GITHUB_ENV and $GITHUB_OUTPUT. A value may hold spaces ("Lunport Dev"), so bash reads them with
// `while IFS='=' read -r key value`, not eval.
import { existsSync, readFileSync, realpathSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { parseArgs } from "node:util";

/** The checkout this script belongs to. */
export const REPOSITORY = join(dirname(fileURLToPath(import.meta.url)), "..");

/** The Tauri configuration of each build profile; Development's is merged over Production's. */
export const CONFIGURATIONS = {
  production: "src-tauri/tauri.conf.json",
  development: "src-tauri/tauri.dev.conf.json",
};

/** The crate of the console helper Windows installs next to the main executable. */
export const CONSOLE_HELPER_CRATE = "src-tauri/cli-helper/Cargo.toml";

/**
 * The Rust module that holds the identity values no Tauri configuration holds. Node cannot run it, so its text is read: each profile's
 * `pub const PRODUCTION: Identity = Identity { … };` (or DEVELOPMENT) block with one `field: "value",` line per value, and the
 * `pub const HELPER_V2_IDENTIFIER: &str = "…";` line.
 */
export const IDENTITY_SOURCE = "src-tauri/src/identity.rs";

/** The values each profile takes from IDENTITY_SOURCE, by the name of their field in its `Identity { … }` block. */
export const SOURCE_FIELDS = {
  credentialService: "credential_service",
  loginItem: "login_item",
  installerIdentity: "installer_identity",
};

/**
 * The manifests of the frozen macOS executables, each printed as it is under its key: credential helper v1, which versions before 2.0
 * used and the credential migration still reaches, helper v2, which keeps this version's credentials, and the bridge from this app to
 * helper v1.
 */
export const MANIFESTS = {
  helperV1: "src-tauri/signing/legacy/credential-helper-v1.json",
  helperV2: "src-tauri/signing/credential-helper-v2.json",
  bridge: "src-tauri/signing/legacy/credential-bridge.json",
};

/**
 * The manifests of MANIFESTS that a checkout may not hold yet, and that are left out while it does not. None is pending: helper v2 is
 * frozen and committed, so every manifest must be there.
 */
export const PENDING_MANIFESTS = new Set();

const read = (root, path) => {
  try {
    return readFileSync(join(root, path), "utf8");
  } catch (error) {
    throw new Error(`cannot read ${path}: ${error.message}`);
  }
};

const readJson = (root, path) => {
  const text = read(root, path);
  try {
    return JSON.parse(text);
  } catch (error) {
    throw new Error(`cannot parse ${path}: ${error.message}`);
  }
};

// RFC 7396, as Tauri merges a configuration given with --config over the default one: objects merge key by key, anything else replaces.
function merge(base, patch) {
  if (patch === null || typeof patch !== "object" || Array.isArray(patch)) return patch;
  const merged = base !== null && typeof base === "object" && !Array.isArray(base) ? { ...base } : {};
  for (const [key, value] of Object.entries(patch)) {
    if (value === null) delete merged[key];
    else merged[key] = merge(merged[key], value);
  }
  return merged;
}

// A value one line of `KEY=value` can carry: a non-empty string without control characters.
function checked(value, where) {
  if (typeof value !== "string" || value === "" || /[\u0000-\u001f\u007f]/.test(value)) {
    throw new Error(`${where} must be a non-empty single-line string, not ${JSON.stringify(value)}`);
  }
  return value;
}

/** The `[package]` name of a Cargo manifest. */
export function cratePackageName(toml) {
  const table = toml.split(/^\s*\[package\]\s*$/m)[1]?.split(/^\s*\[/m)[0];
  const name = table?.match(/^\s*name\s*=\s*"([^"]*)"\s*$/m)?.[1];
  if (name === undefined) throw new Error("the manifest has no [package] name");
  return name;
}

/** The console helper's name, without the `.exe` Windows adds: its crate's package name in the checkout at `root`. */
export function consoleHelper(root = REPOSITORY) {
  return checked(cratePackageName(read(root, CONSOLE_HELPER_CRATE)), `the package name in ${CONSOLE_HELPER_CRATE}`);
}

// The name of each profile's `Identity { … }` block in IDENTITY_SOURCE.
const SOURCE_BLOCKS = { production: "PRODUCTION", development: "DEVELOPMENT" };

// A `field: "value",` line of such a block: a plain string literal, without escapes. A Windows checkout may end lines with "\r\n".
const LITERAL_FIELD = /^[ \t]*(\w+): "([^"\\\r\n]*)",[ \t]*\r?$/gm;

/**
 * The values IDENTITY_SOURCE's text holds for scripts: `{ production, development }`, each with the values of SOURCE_FIELDS, and
 * `helperV2Identifier`. A value written in any other form (a constant, an escape) or missing, a block under another name and a block
 * that runs into the next one are refused, with the line this function expects, so that a change to the module's format fails here
 * instead of printing a stale value.
 */
export function parseIdentitySource(text) {
  const values = {};
  for (const [profile, name] of Object.entries(SOURCE_BLOCKS)) {
    const block = new RegExp(`^pub const ${name}: Identity = Identity \\{[ \\t]*\\r?\\n([\\s\\S]*?)^\\};`, "m").exec(text)?.[1];
    if (block === undefined) throw new Error(`${IDENTITY_SOURCE} has no \`pub const ${name}: Identity = Identity { … };\` block`);
    const literals = {};
    for (const [, field, value] of block.matchAll(LITERAL_FIELD)) {
      if (Object.hasOwn(literals, field)) throw new Error(`the ${name} identity in ${IDENTITY_SOURCE} has more than one \`${field}:\` line`);
      literals[field] = value;
    }
    values[profile] = {};
    for (const [key, field] of Object.entries(SOURCE_FIELDS)) {
      if (!Object.hasOwn(literals, field)) throw new Error(`the ${name} identity in ${IDENTITY_SOURCE} has no \`${field}: "…",\` line`);
      values[profile][key] = checked(literals[field], `${field} of the ${name} identity in ${IDENTITY_SOURCE}`);
    }
  }
  const helperV2 = /^pub const HELPER_V2_IDENTIFIER: &str = "([^"\\\r\n]*)";[ \t]*\r?$/m.exec(text)?.[1];
  if (helperV2 === undefined) throw new Error(`${IDENTITY_SOURCE} has no \`pub const HELPER_V2_IDENTIFIER: &str = "…";\` line`);
  values.helperV2Identifier = checked(helperV2, `HELPER_V2_IDENTIFIER in ${IDENTITY_SOURCE}`);
  return values;
}

/** The values IDENTITY_SOURCE holds for scripts in the checkout at `root` (parseIdentitySource). */
export function readIdentitySource(root = REPOSITORY) {
  return parseIdentitySource(read(root, IDENTITY_SOURCE));
}

/**
 * Both profiles' values in the checkout at `root`: `{ production, development }`, each `{ appId, productName, publisher, mainBinary,
 * consoleHelper, credentialService, loginItem, installerIdentity }`.
 */
export function readProfiles(root = REPOSITORY) {
  const base = readJson(root, CONFIGURATIONS.production);
  const helper = consoleHelper(root);
  const source = readIdentitySource(root);
  const profiles = {};
  for (const [profile, path] of Object.entries(CONFIGURATIONS)) {
    const config = profile === "production" ? base : merge(base, readJson(root, path));
    profiles[profile] = {
      appId: checked(config.identifier, `identifier in ${path}`),
      productName: checked(config.productName, `productName in ${path}`),
      publisher: checked(config.bundle?.publisher, `bundle.publisher in ${path}`),
      mainBinary: checked(config.mainBinaryName, `mainBinaryName in ${path}`),
      consoleHelper: helper,
      ...source[profile],
    };
  }
  return profiles;
}

/** Every manifest of MANIFESTS in the checkout at `root`, by its key; a pending manifest the checkout does not hold yet is left out. */
export function readManifests(root = REPOSITORY) {
  return Object.fromEntries(
    Object.entries(MANIFESTS)
      .filter(([key, path]) => !PENDING_MANIFESTS.has(key) || existsSync(join(root, path)))
      .map(([key, path]) => [key, readJson(root, path)]),
  );
}

/**
 * What the command prints for the checkout at `root`: both profiles' values, then each manifest under its key. Helper v2's manifest must
 * name the identifier identity.rs gives it; while that manifest is pending (PENDING_MANIFESTS) and missing, the entry holds the
 * identifier alone.
 */
export function readIdentity(root = REPOSITORY) {
  const identity = readProfiles(root);
  const manifests = readManifests(root);
  const { helperV2Identifier } = readIdentitySource(root);
  for (const key of Object.keys(MANIFESTS)) {
    if (key === "helperV2") {
      const manifest = manifests.helperV2;
      if (manifest !== undefined && manifest.identifier !== helperV2Identifier) {
        throw new Error(
          `${MANIFESTS.helperV2} names ${JSON.stringify(manifest.identifier)}, but HELPER_V2_IDENTIFIER in ${IDENTITY_SOURCE} is ${JSON.stringify(helperV2Identifier)}`,
        );
      }
      identity.helperV2 = manifest ?? { identifier: helperV2Identifier };
    } else if (Object.hasOwn(manifests, key)) {
      identity[key] = manifests[key];
    }
  }
  return identity;
}

// `appId` → `APP_ID`, `helperV1` → `HELPER_V1`, `artifact_sha256` → `ARTIFACT_SHA256`.
const envName = key => key.replace(/([a-z0-9])([A-Z])/g, "$1_$2").toUpperCase();

function flatten(value, prefix, lines) {
  if (value !== null && typeof value === "object" && !Array.isArray(value)) {
    for (const [key, inner] of Object.entries(value)) flatten(inner, prefix ? `${prefix}_${envName(key)}` : envName(key), lines);
  } else {
    lines.push(`${prefix}=${checked(String(value), prefix)}`);
  }
}

/** `identity`'s values as `KEY=value` lines: `profile`'s without a prefix, then each manifest's under its key. */
export function toEnv(identity, profile = "production") {
  if (!Object.hasOwn(CONFIGURATIONS, profile)) throw new Error(`unknown profile "${profile}" (production or development)`);
  const lines = [];
  flatten(identity[profile], "", lines);
  for (const key of Object.keys(identity)) if (!Object.hasOwn(CONFIGURATIONS, key)) flatten(identity[key], envName(key), lines);
  return `${lines.join("\n")}\n`;
}

function main(argv) {
  const { values } = parseArgs({
    args: argv,
    options: { root: { type: "string" }, format: { type: "string", default: "json" }, profile: { type: "string", default: "production" } },
  });
  if (!Object.hasOwn(CONFIGURATIONS, values.profile)) throw new Error(`unknown profile "${values.profile}" (production or development)`);
  const identity = readIdentity(values.root ?? REPOSITORY);
  if (values.format === "json") process.stdout.write(`${JSON.stringify(identity, null, 2)}\n`);
  else if (values.format === "env") process.stdout.write(toEnv(identity, values.profile));
  else throw new Error(`unknown format "${values.format}" (json or env)`);
}

if (process.argv[1] && import.meta.url === pathToFileURL(realpathSync(process.argv[1])).href) {
  try {
    main(process.argv.slice(2));
  } catch (error) {
    console.error(`identity.mjs: ${error.message}`);
    process.exit(1);
  }
}
