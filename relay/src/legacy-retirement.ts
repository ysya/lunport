import { DurableObject } from "cloudflare:workers";

const HEX64 = /^[0-9a-f]{64}$/;
const HEX32 = /^[0-9a-f]{32}$/;

/** Public bindings only; an old bearer never authenticates the target account. */
export interface LegacyMigrationScope {
  operation: string;
  origin: string;
  account: string;
  genesis: string;
  vault: string;
}
export interface LegacySnapshot {
  latestSeq: number;
  count: number;
  digest: string;
}
interface Fence {
  version: 1;
  phase: "frozen" | "retired";
  tokenHash: string;
  scope: LegacyMigrationScope;
  snapshot: LegacySnapshot;
}
export type LegacyGate = 200 | 404 | 409 | 410 | 503;

export function validScope(value: unknown): value is LegacyMigrationScope {
  if (!value || typeof value !== "object") return false;
  const scope = value as LegacyMigrationScope;
  if (
    Object.keys(scope).sort().join() !==
    "account,genesis,operation,origin,vault"
  )
    return false;
  if (
    !HEX32.test(scope.operation) ||
    ![scope.account, scope.genesis, scope.vault].every(
      (v) => typeof v === "string" && HEX64.test(v),
    )
  )
    return false;
  if (typeof scope.operation !== "string" || typeof scope.origin !== "string")
    return false;
  try {
    const url = new URL(scope.origin);
    return scope.origin === url.origin && url.protocol === "https:";
  } catch {
    return false;
  }
}
export function validSnapshot(value: unknown): value is LegacySnapshot {
  if (!value || typeof value !== "object") return false;
  const snapshot = value as LegacySnapshot;
  return (
    Object.keys(snapshot).sort().join() === "count,digest,latestSeq" &&
    Number.isSafeInteger(snapshot.latestSeq) &&
    snapshot.latestSeq >= 0 &&
    Number.isSafeInteger(snapshot.count) &&
    snapshot.count >= 0 &&
    snapshot.count <= 4096 &&
    snapshot.count <= snapshot.latestSeq &&
    typeof snapshot.digest === "string" &&
    HEX64.test(snapshot.digest)
  );
}
function validFence(value: unknown): value is Fence {
  if (!value || typeof value !== "object") return false;
  const fence = value as Fence;
  return (
    Object.keys(fence).sort().join() ===
      "phase,scope,snapshot,tokenHash,version" &&
    fence.version === 1 &&
    (fence.phase === "frozen" || fence.phase === "retired") &&
    typeof fence.tokenHash === "string" &&
    HEX64.test(fence.tokenHash) &&
    validScope(fence.scope) &&
    validSnapshot(fence.snapshot)
  );
}
export function sameMigration(
  a: LegacyMigrationScope,
  b: LegacyMigrationScope,
): boolean {
  return (
    a.operation === b.operation &&
    a.origin === b.origin &&
    a.account === b.account &&
    a.genesis === b.genesis &&
    a.vault === b.vault
  );
}
export function sameSnapshot(a: LegacySnapshot, b: LegacySnapshot): boolean {
  return (
    a.latestSeq === b.latestSeq && a.count === b.count && a.digest === b.digest
  );
}

/** Separate namespace: no alarm, TTL, deletion, reset or public HTTP endpoint. */
export class LegacyRetirementStore extends DurableObject<Env> {
  private matches(chain: string): boolean {
    return (
      typeof chain === "string" &&
      HEX64.test(chain) &&
      this.env.LEGACY_RETIREMENT.idFromName(chain).equals(this.ctx.id)
    );
  }
  async check(
    chain: string,
    tokenHash: string,
    write: boolean,
  ): Promise<LegacyGate> {
    if (!this.matches(chain) || !HEX64.test(tokenHash)) return 503;
    const value: unknown = await this.ctx.storage.get("fence");
    if (value === undefined) return 200;
    if (!validFence(value)) return 503;
    if (value.tokenHash !== tokenHash) return 404;
    if (value.phase === "retired") return 410;
    return write ? 409 : 200;
  }
  /** Called only after ChainStore has durably fenced and snapshotted its source. */
  async freeze(
    chain: string,
    tokenHash: string,
    scope: LegacyMigrationScope,
    snapshot: LegacySnapshot,
  ): Promise<LegacyGate> {
    if (
      !this.matches(chain) ||
      !HEX64.test(tokenHash) ||
      !validScope(scope) ||
      !validSnapshot(snapshot)
    )
      return 503;
    return this.ctx.blockConcurrencyWhile(async () => {
      const value: unknown = await this.ctx.storage.get("fence");
      if (value !== undefined) {
        if (!validFence(value)) return 503;
        if (value.tokenHash !== tokenHash) return 404;
        if (
          !sameMigration(value.scope, scope) ||
          !sameSnapshot(value.snapshot, snapshot)
        )
          return 409;
        return value.phase === "retired" ? 410 : 200;
      }
      await this.ctx.storage.put("fence", {
        version: 1,
        phase: "frozen",
        tokenHash,
        scope,
        snapshot,
      } satisfies Fence);
      return 200;
    });
  }
  // A retire transition is deliberately absent until the central migration
  // coordinator can prove the target commit. Caller-supplied hashes are insufficient.
}
