import { verifyAuthorityImport } from "./authority-check";
/** Local one-shot operator command. This module has no fetch handler or public socket. */
import { REGISTRY_WITNESS, type FloorEnv } from "../../src/security/floor";
type ControlEnv = FloorEnv & {
  SECURITY_INSTALLATION: string;
  SELFHOST_CONTROL_MODE: string;
  SELFHOST_EXPECTED_REGISTRY?: string;
  SELFHOST_CONFIRM_NEW_INSTALLATION?: string;
  SELFHOST_MINIMUM_FLOOR?: string;
  SELFHOST_EXPECTED_AUTHORITY?: string;
  SELFHOST_AUTHORITY_RECEIPT?: string;
  SELFHOST_AUTHORITY_IMPORT?: string;
  AUTHORITY_READ?: Fetcher;
};
export default {
  async test(_controller: unknown, env: ControlEnv) {
    if (!/^[0-9a-f]{32}$/.test(env.SECURITY_INSTALLATION ?? ""))
      throw new Error("A stable installation ID is required.");
    const floor = env.SECURITY_FLOOR.getByName(
      "floor:" + env.SECURITY_INSTALLATION,
    );
    const registry =
      env.LEGACY_RETIREMENT.idFromName(REGISTRY_WITNESS).toString();
    const current = await floor.inspect(env.SECURITY_INSTALLATION);
    if (env.SELFHOST_CONTROL_MODE === "inspect") {
      console.log(
        JSON.stringify({
          installation: env.SECURITY_INSTALLATION,
          registry,
          status: current.status,
          minimum: current.minimum,
          present: current.present,
          authority: current.authority,
          pinned: current.pinned,
        }),
      );
      return;
    }
    if (
      !/^[0-9a-f]{64}$/.test(env.SELFHOST_EXPECTED_REGISTRY ?? "") ||
      env.SELFHOST_EXPECTED_REGISTRY !== registry
    )
      throw new Error(
        "Inspect and confirm the expected registry identity first.",
      );
    const minimum = Number(env.SELFHOST_MINIMUM_FLOOR ?? "2");
    if (!Number.isSafeInteger(minimum) || minimum < 1 || minimum > 65535)
      throw new Error("Invalid minimum backend floor.");
    if (env.SELFHOST_CONTROL_MODE === "bind-authority") {
      if (
        !current.present ||
        current.authority !== env.SELFHOST_EXPECTED_AUTHORITY
      )
        throw new Error(
          "Inspect and confirm the independent authoritative namespace identities first.",
        );
      if (!env.AUTHORITY_READ || !env.SELFHOST_AUTHORITY_IMPORT)
        throw new Error(
          "Verified stopped-runtime import evidence is required.",
        );
      await verifyAuthorityImport(
        env.SECURITY_INSTALLATION,
        env.SELFHOST_AUTHORITY_RECEIPT ?? "",
        env.SELFHOST_AUTHORITY_IMPORT,
        env.AUTHORITY_READ,
      );
      const bound = await floor.bindAuthority(
        env.SECURITY_INSTALLATION,
        minimum,
        registry,
        env.SELFHOST_EXPECTED_AUTHORITY ?? "",
        env.SELFHOST_AUTHORITY_RECEIPT ?? "",
      );
      if (bound.status !== 200)
        throw new Error(
          "Authority handoff rejected; retain all original storage and import evidence.",
        );
      console.log(
        JSON.stringify({ installation: env.SECURITY_INSTALLATION, ...bound }),
      );
      return;
    }
    if (env.SELFHOST_CONTROL_MODE === "provision-new") {
      if (
        env.SELFHOST_CONFIRM_NEW_INSTALLATION !== env.SECURITY_INSTALLATION ||
        current.present
      )
        throw new Error(
          "Explicit fresh-install confirmation is required; existing installations use raise-floor.",
        );
    } else if (env.SELFHOST_CONTROL_MODE === "raise-floor") {
      if (current.status !== 200 || minimum < current.minimum!)
        throw new Error("An existing floor may only increase.");
    } else throw new Error("Unknown private operator action.");
    const result = await floor.provision(
      env.SECURITY_INSTALLATION,
      minimum,
      registry,
    );
    if (result.status !== 200)
      throw new Error(
        "Provisioning rejected; preserve all security storage and inspect the restore state.",
      );
    console.log(
      JSON.stringify({
        installation: env.SECURITY_INSTALLATION,
        registry,
        status: result.status,
        minimum: result.minimum,
      }),
    );
  },
};
