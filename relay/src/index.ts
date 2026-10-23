import { DurableObject, WorkerEntrypoint } from "cloudflare:workers";
export { IpLimiter } from "./ip-limit";
export { LegacyRetirementStore } from "./legacy-retirement";
export { AccountStore } from "./v2/account";
export { PasskeyStore } from "./v2/passkeys/store";
export { VaultStore } from "./v2/store";
export { SecurityFloorStore } from "./security/floor";

/** Preserve the historical Durable Object class and stored data during upgrades. */
export class ChainStore extends DurableObject<Env> {
  async alarm(): Promise<void> {}
}

/** Preserve the old private entrypoint name while refusing all chain traffic. */
export class CentralSyncBackend extends WorkerEntrypoint<Env> {
  async forward(_requiredFloor: number, _registry: string, _request: Request): Promise<Response> {
    return new Response(null, { status: 404 });
  }
}

export default {
  fetch(): Response {
    return new Response(null, { status: 404 });
  },
} satisfies ExportedHandler<Env>;
