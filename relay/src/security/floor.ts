import { DurableObject } from "cloudflare:workers";
import {
  authorityWitness,
  validAuthority,
  type AuthorityEnv,
} from "./authority";

const HEX32 = /^[0-9a-f]{32}$/,
  HEX64 = /^[0-9a-f]{64}$/;
export const REGISTRY_WITNESS = "lunport-legacy-registry-v1";
export const MINIMUM_BACKEND_FLOOR = 2;
export type FloorEnv = AuthorityEnv & {
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
  | { status: 200; minimum: number; registry: string; authority: string }
  | { status: 409 | 503 };
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
type Authority = {
  version: 1;
  installation: string;
  registry: string;
  authority: string;
  receipt: string;
};
function validPin(value: unknown): value is Authority {
  if (!value || typeof value !== "object") return false;
  const pin = value as Authority;
  return (
    Object.keys(pin).sort().join() ===
      "authority,installation,receipt,registry,version" &&
    pin.version === 1 &&
    typeof pin.installation === "string" &&
    HEX32.test(pin.installation) &&
    typeof pin.registry === "string" &&
    HEX64.test(pin.registry) &&
    validAuthority(pin.authority) &&
    (pin.receipt === "fresh" ||
      (typeof pin.receipt === "string" && HEX64.test(pin.receipt)))
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
  private authority(): string | null {
    try {
      const value = authorityWitness(this.env);
      return validAuthority(value) ? value : null;
    } catch {
      return null;
    }
  }
  private async pinned(
    installation: string,
    registry: string,
    authority: string,
  ): Promise<boolean> {
    const value: unknown = await this.ctx.storage.get("authority");
    return (
      validPin(value) &&
      value.installation === installation &&
      value.registry === registry &&
      value.authority === authority
    );
  }
  /** Read-only operator inspection; absence, corruption and old unbound floors stay unavailable. */
  async inspect(installation: string) {
    const registry = this.identity(installation),
      authority = this.authority();
    const value: unknown = await this.ctx.storage.get("floor");
    const valid =
      !!registry &&
      validFloor(value) &&
      value.installation === installation &&
      value.registry === registry;
    const pinned = !!(
      valid &&
      authority &&
      (await this.pinned(installation, registry!, authority))
    );
    return {
      present: value !== undefined,
      status: valid && pinned ? 200 : 503,
      minimum: valid ? value.minimum : null,
      registry,
      authority,
      pinned,
    };
  }
  /** Explicit private operator handoff after exact namespace/data migration readback. */
  async bindAuthority(
    installation: string,
    minimum: number,
    registry: string,
    authority: string,
    receipt: string,
  ): Promise<FloorResult> {
    if (
      registry !== this.identity(installation) ||
      authority !== this.authority() ||
      !HEX64.test(receipt) ||
      !validMinimum(minimum) ||
      minimum < MINIMUM_BACKEND_FLOOR
    )
      return { status: 503 };
    return this.ctx.blockConcurrencyWhile(async () => {
      const value: unknown = await this.ctx.storage.get("floor");
      if (
        !validFloor(value) ||
        value.installation !== installation ||
        value.registry !== registry
      )
        return { status: 503 };
      const old: unknown = await this.ctx.storage.get("authority");
      const pin: Authority = {
        version: 1,
        installation,
        registry,
        authority,
        receipt,
      };
      if (
        old !== undefined &&
        (!validPin(old) ||
          old.installation !== installation ||
          old.registry !== registry ||
          old.authority !== authority ||
          old.receipt !== receipt)
      )
        return { status: 409 };
      const next = Math.max(value.minimum, minimum);
      await this.ctx.storage.transaction(async (storage) => {
        await storage.put("authority", pin);
        await storage.put("floor", { ...value, minimum: next });
      });
      return { status: 200, minimum: next, registry, authority };
    });
  }
  /** Private deployment RPC. Operator must preserve/import prior security metadata first. */
  async provision(
    installation: string,
    minimum: number,
    expectedRegistry: string,
  ): Promise<FloorResult> {
    const registry = this.identity(installation),
      authority = this.authority();
    if (
      !registry ||
      !authority ||
      registry !== expectedRegistry ||
      !validMinimum(minimum) ||
      minimum < MINIMUM_BACKEND_FLOOR
    )
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
      if (value && !(await this.pinned(installation, registry, authority)))
        return { status: 409 };
      const floor: Floor = { version: 1, installation, minimum, registry };
      await this.ctx.storage.transaction(async (storage) => {
        if (!value) {
          if ((await storage.get("authority")) !== undefined)
            throw new Error("Unowned security pin");
          await storage.put("authority", {
            version: 1,
            installation,
            registry,
            authority,
            receipt: "fresh",
          } satisfies Authority);
        }
        await storage.put("floor", floor);
      });
      return { status: 200, minimum, registry, authority };
    });
  }
  async authorize(
    installation: string,
    compiledMinimum = MINIMUM_BACKEND_FLOOR,
  ): Promise<FloorResult> {
    const registry = this.identity(installation),
      authority = this.authority();
    if (!registry || !authority || !validMinimum(compiledMinimum))
      return { status: 503 };
    return this.ctx.blockConcurrencyWhile(async () => {
      const value: unknown = await this.ctx.storage.get("floor");
      if (
        !validFloor(value) ||
        value.installation !== installation ||
        value.registry !== registry ||
        !(await this.pinned(installation, registry, authority))
      )
        return { status: 503 };
      const minimum = Math.max(
        value.minimum,
        compiledMinimum,
        MINIMUM_BACKEND_FLOOR,
      );
      if (minimum !== value.minimum)
        await this.ctx.storage.put("floor", { ...value, minimum });
      return { status: 200, minimum, registry, authority };
    });
  }
}
