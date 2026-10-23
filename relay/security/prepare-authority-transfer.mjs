/** Read-only plan generation for an existing public relay. Never calls Cloudflare or deploys. */
import { readFileSync, writeFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { createHash } from "node:crypto";
import { stripJsonComments } from "./json-comments.mjs";
const central = {
  ACCOUNT: "AccountStore",
  VAULT: "VaultStore",
  PASSKEY: "PasskeyStore",
  LEGACY_RETIREMENT: "LegacyRetirementStore",
  SECURITY_FLOOR: "SecurityFloorStore",
};
const known = new Set(["ChainStore", "IpLimiter", ...Object.values(central)]);
const fail = () => {
  throw new Error(
    "Live namespace inventory or existing migration history is incomplete or incompatible. Preserve the original deployment and do not substitute fresh namespaces.",
  );
};
export function prepareAuthorityTransfer(
  source,
  live,
  { installation, privateCore },
) {
  if (
    !/^[0-9a-f]{32}$/.test(installation ?? "") ||
    !/^[a-z0-9][a-z0-9-]{0,62}$/.test(privateCore ?? "") ||
    privateCore === source.name ||
    live?.version !== 1 ||
    !/^[0-9a-f]{32}$/.test(live.account_id ?? "") ||
    (source.account_id && source.account_id !== live.account_id) ||
    live.script_name !== source.name ||
    live.private_script_absent !== true ||
    !Array.isArray(live.namespaces) ||
    source.main !== "src/index.ts" ||
    source.vars?.CENTRAL_PRIVATE_CORE === "1"
  )
    fail();
  try {
    if (
      new URL(live.origin).origin !== live.origin ||
      !live.origin.startsWith("https://")
    )
      fail();
  } catch {
    fail();
  }
  const names = new Map();
  const ids = new Set();
  for (const ns of live.namespaces) {
    if (
      !known.has(ns.class_name) ||
      names.has(ns.class_name) ||
      ns.storage !== "sqlite" ||
      !/^[0-9a-f]{32}$/.test(ns.id ?? "") ||
      ids.has(ns.id)
    )
      fail();
    names.set(ns.class_name, ns.id);
    ids.add(ns.id);
  }
  if (!names.has("ChainStore") || !names.has("IpLimiter")) fail();
  if (!Array.isArray(source.migrations)) fail();
  const index = source.migrations.findIndex(
    (m) => m.tag === live.migration_tag,
  );
  if (
    index < 0 ||
    source.migrations.filter((m) => m.tag === live.migration_tag).length !== 1
  )
    fail();
  const history = structuredClone(source.migrations.slice(0, index + 1)),
    classes = new Set();
  for (const step of history) {
    if (
      step.new_classes?.length ||
      step.renamed_classes?.length ||
      step.transferred_classes?.length
    )
      fail();
    for (const name of step.new_sqlite_classes ?? []) {
      if (classes.has(name) || !known.has(name)) fail();
      classes.add(name);
    }
    for (const name of step.deleted_classes ?? []) classes.delete(name);
  }
  if (
    classes.size !== names.size ||
    [...classes].some((name) => !names.has(name))
  )
    fail();
  const bindings = source.durable_objects?.bindings;
  if (
    !Array.isArray(bindings) ||
    new Set(bindings.map((b) => b.name)).size !== bindings.length
  )
    fail();
  for (const [binding, cls] of Object.entries({
    CHAIN: "ChainStore",
    IP_LIMIT: "IpLimiter",
    ...central,
  })) {
    if (!names.has(cls)) continue;
    const item = bindings.find((b) => b.name === binding);
    if (
      item?.class_name !== cls ||
      (item.script_name && item.script_name !== source.name)
    )
      fail();
  }
  const closed = {
    account_id: live.account_id,
    compatibility_date: source.compatibility_date,
    workers_dev: false,
    preview_urls: false,
    routes: [],
  };
  const coreVars = { ...source.vars };
  for (const key of [
    "CENTRAL_ENABLED", "PASSKEY_ENABLED", "CENTRAL_ORIGIN",
    "OIDC_ISSUER", "OIDC_JWKS_URL", "OIDC_API_AUDIENCE",
    "OIDC_NATIVE_CLIENT_ID", "OIDC_SYNC_SCOPE",
  ]) delete coreVars[key];
  const core = {
    ...closed,
    name: privateCore,
    main: "src/index.ts",
    build: { command: "node scripts/build-passkey-page.mjs" },
    durable_objects: {
      bindings: [
        { name: "CHAIN", class_name: "ChainStore" },
        { name: "IP_LIMIT", class_name: "IpLimiter" },
      ],
    },
    migrations: [
      {
        tag: "independent-authority-core-v1",
        new_sqlite_classes: ["IpLimiter"],
        transferred_classes: [
          { from: "ChainStore", from_script: source.name, to: "ChainStore" },
        ],
      },
    ],
    vars: {
      ...coreVars,
      CENTRAL_PRIVATE_CORE: "1",
    },
  };
  const security = {
    ...structuredClone(source),
    ...closed,
    main: "src/security/gateway.ts",
    build: { command: "node scripts/build-passkey-page.mjs" },
    durable_objects: {
      bindings: [
        { name: "IP_LIMIT", class_name: "IpLimiter" },
        ...Object.entries(central).map(([name, class_name]) => ({
          name,
          class_name,
        })),
      ],
    },
    migrations: history,
    vars: {
      ...source.vars,
      CENTRAL_ORIGIN: live.origin,
      SECURITY_INSTALLATION: installation,
      CENTRAL_ENABLED: "0",
      PASSKEY_ENABLED: source.vars?.PASSKEY_ENABLED ?? "1",
    },
  };
  const missing = Object.values(central).filter((cls) => !names.has(cls));
  if (missing.length) {
    if (history.some((m) => m.tag === "independent-authority-security-v1"))
      fail();
    security.migrations.push({
      tag: "independent-authority-security-v1",
      new_sqlite_classes: missing,
    });
  }
  return {
    coreBootstrap: core,
    security,
    core: structuredClone(core),
    plan: {
      version: 1,
      installation,
      origin: live.origin,
      public_script: source.name,
      private_core: privateCore,
      expected_preserved_security_namespaces: Object.fromEntries(
        [...names].filter(([cls]) => cls !== "ChainStore"),
      ),
      expected_private_chain_namespace: names.get("ChainStore"),
      new_security_classes: missing,
      public_activation:
        "blocked until namespace identities, independent floor/authority pin and routing/IAM/build-pipeline checks pass",
      original_public_routes: {
        workers_dev: source.workers_dev ?? "verify-live",
        routes: source.routes ?? "verify-live",
      },
    },
  };
}
function main() {
  const [
    sourcePath,
    inventoryPath,
    expected,
    installation,
    privateCore,
    prefix = "authority-handoff",
  ] = process.argv.slice(2);
  if (
    !sourcePath ||
    !inventoryPath ||
    !/^[0-9a-f]{64}$/.test(expected ?? "") ||
    !/^[a-z0-9-]{1,48}$/.test(prefix)
  )
    fail();
  const inventory = readFileSync(inventoryPath);
  if (createHash("sha256").update(inventory).digest("hex") !== expected) fail();
  const source = JSON.parse(
      stripJsonComments(readFileSync(sourcePath, "utf8")),
    ),
    live = JSON.parse(inventory);
  const result = prepareAuthorityTransfer(source, live, {
      installation,
      privateCore,
    }),
    root = dirname(resolve(sourcePath));
  for (const [kind, value] of Object.entries(result)) {
    const name = resolve(
        root,
        `${prefix}.${kind}.${kind === "plan" ? "json" : "jsonc"}`,
      ),
      bytes = JSON.stringify(value, null, 2) + "\n";
    try {
      writeFileSync(name, bytes, { flag: "wx", mode: 0o600 });
    } catch (error) {
      if (error.code !== "EEXIST" || readFileSync(name, "utf8") !== bytes)
        throw error;
    }
  }
  console.log(
    "Prepared closed handoff configurations beside the source config. No deployment or activation occurred.",
  );
}
if (
  process.argv[1] &&
  import.meta.url === pathToFileURL(resolve(process.argv[1])).href
) {
  try {
    main();
  } catch {
    console.error(
      "Authority handoff preparation refused. Verify the pinned live inventory and original configuration; no deployment occurred.",
    );
    process.exitCode = 1;
  }
}
