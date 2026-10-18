import { DurableObject } from "cloudflare:workers";

const HEX32 = /^[0-9a-f]{32}$/,
  HEX64 = /^[0-9a-f]{64}$/;
export const REGISTRY_WITNESS = "lunport-legacy-registry-v1";
export const MINIMUM_BACKEND_FLOOR = 1;
export type FloorEnv = {
  LEGACY_RETIREMENT: Env["LEGACY_RETIREMENT"];
  SECURITY_FLOOR: DurableObjectNamespace<SecurityFloorStore>;
};
type Floor = {
  version: 1;
  installation: string;
  minimum: number;
  registry: string;
};
export type FloorResult =
  { status: 200; minimum: number; registry: string } | { status: 409 | 503 };
const validMinimum = (value: number) =>
  Number.isSafeInteger(value) && value >= 1 && value <= 65535;
function validFloor(value: unknown): value is Floor {
  if (!value || typeof value !== "object") return false;
  const floor = value as Floor;
  return (
    Object.keys(floor).sort().join() ===
      "installation,minimum,registry,version" &&
    floor.version === 1 &&
    typeof floor.installation === "string" &&
    HEX32.test(floor.installation) &&
    typeof floor.registry === "string" &&
    HEX64.test(floor.registry) &&
    validMinimum(floor.minimum)
  );
}
/** Separate security deployment: explicit provisioning only; no traffic-created default. */
export class SecurityFloorStore extends DurableObject<FloorEnv> {
  private identity(installation: string): string | null {
    try {
      if (
        typeof installation !== "string" ||
        !HEX32.test(installation) ||
        !this.env.SECURITY_FLOOR.idFromName("floor:" + installation).equals(
          this.ctx.id,
        )
      )
        return null;
      return this.env.LEGACY_RETIREMENT.idFromName(REGISTRY_WITNESS).toString();
    } catch {
      return null;
    }
  }
  /** Private deployment RPC. Operator must preserve/import prior security metadata first. */
  async provision(
    installation: string,
    minimum: number,
    expectedRegistry: string,
  ): Promise<FloorResult> {
    const registry = this.identity(installation);
    if (!registry || registry !== expectedRegistry || !validMinimum(minimum))
      return { status: 503 };
    return this.ctx.blockConcurrencyWhile(async () => {
      const value: unknown = await this.ctx.storage.get("floor");
      if (value !== undefined && !validFloor(value)) return { status: 503 };
      if (
        value &&
        (value.installation !== installation ||
          value.registry !== registry ||
          minimum < value.minimum)
      )
        return { status: 409 };
      const floor: Floor = { version: 1, installation, minimum, registry };
      await this.ctx.storage.put("floor", floor);
      return { status: 200, minimum, registry };
    });
  }
  async authorize(
    installation: string,
    compiledMinimum = MINIMUM_BACKEND_FLOOR,
  ): Promise<FloorResult> {
    const registry = this.identity(installation);
    if (!registry || !validMinimum(compiledMinimum)) return { status: 503 };
    return this.ctx.blockConcurrencyWhile(async () => {
      const value: unknown = await this.ctx.storage.get("floor");
      if (
        !validFloor(value) ||
        value.installation !== installation ||
        value.registry !== registry
      )
        return { status: 503 };
      const minimum = Math.max(value.minimum, compiledMinimum);
      if (minimum !== value.minimum)
        await this.ctx.storage.put("floor", { ...value, minimum });
      return { status: 200, minimum, registry };
    });
  }
}
