// Read-only checks for the unrouted deployment examples; no network or deployment.
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { stripJsonComments } from "../.github/scripts/update-relay.mjs";
const here = dirname(fileURLToPath(import.meta.url));
const binding = (config, name) =>
  config.durable_objects?.bindings?.find((item) => item.name === name);
export function validateSecurityDeployment(core, security, bootstrap) {
  const problems = [];
  for (const [name, config] of [
    ["core", core],
    ["security", security],
    ["bootstrap", bootstrap],
  ]) {
    if (
      config.workers_dev !== false ||
      config.preview_urls !== false ||
      !Array.isArray(config.routes) ||
      config.routes.length
    )
      problems.push(
        `${name}: examples must remain unrouted, with workers.dev and previews disabled`,
      );
    if (config.compatibility_date !== "2026-08-20")
      problems.push(`${name}: review compatibility-date changes explicitly`);
  }
  if (
    core.main !== "src/index.ts" ||
    core.vars?.CENTRAL_PRIVATE_CORE !== "1" ||
    core.vars?.CENTRAL_ENABLED !== "0"
  )
    problems.push(
      "core: require private mode and generic OIDC disabled in examples",
    );
  if (
    security.main !== "src/security/gateway.ts" ||
    bootstrap.main !== security.main ||
    bootstrap.name !== security.name
  )
    problems.push(
      "security: bootstrap and final gateway must have the same owner and entrypoint",
    );
  const service = security.services?.find((item) => item.binding === "CORE");
  if (
    service?.service !== core.name ||
    service?.entrypoint !== "CentralSyncBackend" ||
    bootstrap.services?.length
  )
    problems.push(
      "security: require only the checked named core RPC; bootstrap has no core service",
    );
  for (const name of [
    "LEGACY_RETIREMENT",
    "SECURITY_FLOOR",
    "IP_LIMIT",
    "ACCOUNT",
    "VAULT",
    "PASSKEY",
  ]) {
    const expected = {
      LEGACY_RETIREMENT: "LegacyRetirementStore",
      SECURITY_FLOOR: "SecurityFloorStore",
      IP_LIMIT: "IpLimiter",
      ACCOUNT: "AccountStore",
      VAULT: "VaultStore",
      PASSKEY: "PasskeyStore",
    }[name];
    for (const config of [security, bootstrap]) {
      const item = binding(config, name);
      if (item?.class_name !== expected || item.script_name)
        problems.push(
          `${name}: security state must remain owned by the security Worker`,
        );
    }
  }
  if (
    binding(core, "LEGACY_RETIREMENT")?.script_name !== security.name ||
    binding(core, "LEGACY_RETIREMENT")?.class_name !== "LegacyRetirementStore"
  )
    problems.push("core: registry binding must point to the security owner");
  if (
    binding(security, "CHAIN")?.script_name !== core.name ||
    binding(bootstrap, "CHAIN")
  )
    problems.push(
      "security: legacy chain access must target the core; bootstrap waits for that owner",
    );
  for (const [name, cls] of [
    ["ACCOUNT", "AccountStore"],
    ["VAULT", "VaultStore"],
    ["PASSKEY", "PasskeyStore"],
  ]) {
    if (
      binding(core, name)?.class_name !== cls ||
      binding(core, name)?.script_name !== security.name
    )
      problems.push(
        `core: ${name} must reference the independent security authority`,
      );
  }
  const origin = security.vars?.CENTRAL_ORIGIN;
  try {
    if (new URL(origin).origin !== origin || !origin.startsWith("https://"))
      throw new Error();
  } catch {
    problems.push("security: require a canonical HTTPS origin");
  }
  if (
    core.vars?.CENTRAL_ORIGIN !== origin ||
    bootstrap.vars?.CENTRAL_ORIGIN !== origin ||
    !/^[0-9a-f]{32}$/.test(security.vars?.SECURITY_INSTALLATION ?? "") ||
    bootstrap.vars?.SECURITY_INSTALLATION !==
      security.vars.SECURITY_INSTALLATION
  )
    problems.push(
      "security: origin and stable installation must match across examples",
    );
  const migrations = (config) => JSON.stringify(config.migrations);
  if (migrations(security) !== migrations(bootstrap))
    problems.push("security: bootstrap/final migration history differs");
  for (const name of ["CHAIN", "IP_LIMIT"])
    if (binding(core, name)?.script_name || !binding(core, name))
      problems.push(`core: preserve local ${name} ownership`);
  for (const config of [core, security, bootstrap]) {
    const names = config.durable_objects?.bindings?.map((v) => v.name) ?? [];
    if (new Set(names).size !== names.length)
      problems.push("duplicate durable binding names");
  }
  const created = (cfg) =>
    cfg.migrations?.flatMap((m) => m.new_sqlite_classes ?? []) ?? [];
  for (const cls of ["AccountStore", "VaultStore", "PasskeyStore"])
    if (created(core).includes(cls) || !created(security).includes(cls))
      problems.push(
        `${cls}: fresh central namespaces must be created only in the independent security owner`,
      );
  return problems;
}
export function checkExamples(root = resolve(here, "..")) {
  const read = (name) =>
    JSON.parse(
      stripJsonComments(
        readFileSync(resolve(root, `wrangler.${name}.example.jsonc`), "utf8"),
      ),
    );
  return validateSecurityDeployment(
    read("private-core"),
    read("security"),
    read("security-bootstrap"),
  );
}
if (
  process.argv[1] &&
  import.meta.url === pathToFileURL(resolve(process.argv[1])).href
) {
  const problems = checkExamples();
  if (problems.length) {
    for (const problem of problems) console.error(problem);
    process.exitCode = 1;
  } else
    console.log(
      "Unrouted security examples pass source checks; live routing, permissions, namespaces and provisioning remain unaudited.",
    );
}
