import { DurableObject } from "cloudflare:workers";
import {
  verifyRecoveryRead,
  type RecoveryReadProof,
  type RecoveryReadGrant,
} from "./recovery";
import { validConfirmation, type PairingConfirmation } from "./pairing";
import type { DeviceProof, Identity, Principal, SessionProof } from "./auth";
import {
  applyMembership,
  enrollmentCanonical,
  genesisCanonical,
  trustGenesis,
  validKeys,
  verifyEnrollment,
  type Device,
  type Enrollment,
  type Genesis,
  type SignedMembership,
  type TrustedMembership,
} from "./membership";
import {
  base64,
  exactObject,
  canonical,
  hash,
  hex,
  safeNumber,
  validOrigin,
  type WrappedKeys,
} from "./protocol";
import {
  metadataJson,
  rpcResponse,
  rpcCall,
  completeWraps,
  type ControlProof,
  type Install,
  type Result,
} from "./store";

type Registration = {
  device: Device;
  credential: string;
  name: string;
  created: number;
  request: Enrollment | null;
  confirmation: PairingConfirmation | null;
};
type Vault = { epoch: number; rekey: boolean };
type Barrier = {
  id: string;
  targets: string[];
  acknowledged: string[];
  wraps: Record<string, WrappedKeys[]>;
  freeze: boolean;
};
type Account = {
  locator: string;
  origin: string;
  id: string;
  version: number;
  epoch: number;
  registrations: Record<string, Registration>;
  denied: string[];
  vaults: Record<string, Vault>;
  proof: ControlProof | null;
  trusted: TrustedMembership | null;
  pending: Barrier | null;
  lastControl: string | null;
};
type Session = {
  id: string;
  secret_hash: string;
  device: string;
  epoch: number;
  expires: number;
  revoked: number;
};
const SESSION_MS = 5 * 60 * 1000;
const SCHEMA = `CREATE TABLE IF NOT EXISTS account_state (id INTEGER PRIMARY KEY CHECK(id=1), value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS sessions (id TEXT PRIMARY KEY, secret_hash TEXT NOT NULL, device TEXT NOT NULL, epoch INTEGER NOT NULL, expires INTEGER NOT NULL, revoked INTEGER NOT NULL DEFAULT 0);
CREATE INDEX IF NOT EXISTS sessions_device ON sessions(device);`;
function randomId(bytes: number): string {
  return Array.from(crypto.getRandomValues(new Uint8Array(bytes)), (v) =>
    v.toString(16).padStart(2, "0"),
  ).join("");
}
function sameDevice(a: Device, b: Device): boolean {
  return (
    a.id === b.id &&
    a.keys.signing === b.keys.signing &&
    a.keys.encryption === b.keys.encryption
  );
}
function requestId(request: Enrollment): string {
  return base64(enrollmentCanonical(request)) + "." + request.signature;
}
/** Permanent account/security metadata has no idle-TTL deletion. OIDC is verified before RPC. */
export class AccountStore extends DurableObject<Env> {
  register(
    identity: Identity,
    origin: string,
    proof: DeviceProof,
    device: Device,
    name: string,
    now = Date.now(),
  ): Promise<Response> {
    return rpcCall(() =>
      this.registerResult(identity, origin, proof, device, name, now),
    );
  }
  overview(actor: Principal): Promise<Response> {
    return rpcCall(() => this.overviewResult(actor));
  }
  logout(actor: Principal): Promise<Response> {
    return rpcCall(() => this.logoutResult(actor));
  }
  async enrollment(
    actor: Principal,
    request: Enrollment,
    now = Date.now(),
  ): Promise<Response> {
    return rpcCall(() => this.enrollmentResult(actor, request, now));
  }
  async bootstrap(
    actor: Principal,
    genesis: Genesis,
    vault: string,
    wraps: WrappedKeys[],
  ): Promise<Response> {
    return rpcCall(() => this.bootstrapResult(actor, genesis, vault, wraps));
  }
  async control(
    actor: Principal,
    node: SignedMembership,
    wraps: Record<string, WrappedKeys[]>,
    confirmation: PairingConfirmation | null = null,
    now = Date.now(),
  ): Promise<Response> {
    return rpcCall(() =>
      this.controlResult(actor, node, wraps, confirmation, now),
    );
  }
  async createVault(
    actor: Principal,
    vault: string,
    wraps: WrappedKeys[],
  ): Promise<Response> {
    return rpcCall(() => this.createVaultResult(actor, vault, wraps));
  }
  async revokeAccess(
    identity: Identity,
    device: string,
    now = Date.now(),
  ): Promise<Response> {
    return rpcCall(() => this.revokeAccessResult(identity, device, now));
  }
  async resume(actor: Principal): Promise<Response> {
    return rpcCall(() => this.resumeResult(actor));
  }
  private load(): Account | null {
    if (
      !this.ctx.storage.sql
        .exec(
          "SELECT name FROM sqlite_master WHERE type='table' AND name='account_state'",
        )
        .toArray().length
    )
      return null;
    const row = this.ctx.storage.sql
      .exec<{ value: string }>("SELECT value FROM account_state WHERE id=1")
      .toArray()[0];
    return row ? (JSON.parse(row.value) as Account) : null;
  }
  private save(state: Account): void {
    const encoded = metadataJson(state);
    this.ctx.storage.sql.exec(SCHEMA);
    this.ctx.storage.sql.exec(
      "INSERT INTO account_state VALUES(1,?) ON CONFLICT(id) DO UPDATE SET value=excluded.value",
      encoded,
    );
  }
  private allowed(
    state: Account | null,
    actor: Principal,
    pending = false,
  ): state is Account {
    return (
      !!state &&
      actor.locator === state.locator &&
      actor.account === state.id &&
      actor.epoch === state.epoch &&
      actor.expires > Date.now() &&
      !!state.registrations[actor.device] &&
      !state.denied.includes(actor.device) &&
      (pending || !!state.trusted?.devices[actor.device])
    );
  }
  private registerResult(
    identity: Identity,
    origin: string,
    proof: DeviceProof,
    device: Device,
    name: string,
    now = Date.now(),
  ): Result {
    if (
      !hex(identity.locator, 64) ||
      !validOrigin(origin) ||
      !exactObject(device, ["id", "keys"]) ||
      !hex(device?.id, 32) ||
      !validKeys(device.keys) ||
      proof.id !== device.id ||
      !hex(proof.credential, 64) ||
      !hex(proof.session.id, 32) ||
      !hex(proof.session.hash, 64) ||
      typeof name !== "string" ||
      name.length > 80 ||
      /[\x00-\x1f\x7f]/.test(name)
    )
      return { status: 400 };
    return this.ctx.storage.transactionSync(() => {
      const state =
        this.load() ??
        ({
          locator: identity.locator,
          origin,
          id: randomId(32),
          version: 0,
          epoch: 1,
          registrations: {},
          denied: [],
          vaults: {},
          proof: null,
          trusted: null,
          pending: null,
          lastControl: null,
        } satisfies Account);
      if (
        state.locator !== identity.locator ||
        state.origin !== origin ||
        state.denied.includes(device.id)
      )
        return { status: 403 };
      const prior = state.registrations[device.id];
      if (
        prior &&
        (!sameDevice(prior.device, device) ||
          prior.credential !== proof.credential)
      )
        return { status: 403 };
      if (
        state.trusted?.seen_devices[device.id] &&
        !state.trusted.devices[device.id]
      )
        return { status: 403 };
      if (!prior) {
        // Pending identities expire; approved/revoked identities remain in signed history and cannot be reused.
        for (const [id, registration] of Object.entries(state.registrations)) {
          if (
            !state.trusted?.seen_devices[id] &&
            now - registration.created > 15 * 60 * 1000
          )
            delete state.registrations[id];
        }
        if (
          Object.keys(state.registrations).length >= 128 ||
          Object.values(state.registrations).some(
            (r) =>
              r.device.keys.signing === device.keys.signing ||
              r.device.keys.encryption === device.keys.encryption,
          )
        )
          return { status: 413 };
        state.registrations[device.id] = {
          device: structuredClone(device),
          credential: proof.credential,
          name,
          created: now,
          request: null,
          confirmation: null,
        };
        state.version += 1;
        this.save(state);
      }
      const session = this.ctx.storage.sql
        .exec<Session>("SELECT * FROM sessions WHERE id=?", proof.session.id)
        .toArray()[0];
      if (
        session &&
        (session.device !== device.id ||
          session.secret_hash !== proof.session.hash)
      )
        return { status: 409 };
      this.ctx.storage.sql.exec("DELETE FROM sessions WHERE expires<=?", now);
      const count = this.ctx.storage.sql
        .exec<{ count: number }>(
          "SELECT COUNT(*) AS count FROM sessions WHERE device=?",
          device.id,
        )
        .one().count;
      if (!session && count >= 8) return { status: 429 };
      // Session IDs never slide expiry. A response-loss retry gets the same expiry, not a fresh bearer lifetime.
      const expires = session?.expires ?? now + SESSION_MS;
      if (
        session &&
        (session.expires <= now ||
          session.revoked !== 0 ||
          session.epoch !== state.epoch)
      )
        return { status: 401 };
      if (!session)
        this.ctx.storage.sql.exec(
          "INSERT INTO sessions(id,secret_hash,device,epoch,expires) VALUES(?,?,?,?,?)",
          proof.session.id,
          proof.session.hash,
          device.id,
          state.epoch,
          expires,
        );
      return {
        status: 200,
        body: {
          account_id: state.id,
          account_locator: state.locator,
          device_state: state.trusted?.devices[device.id]
            ? "active"
            : "pending",
          auth_epoch: state.epoch,
          expires_at_ms: expires,
        },
      };
    });
  }
  authorize(
    proof: SessionProof,
    data: boolean,
    now = Date.now(),
  ): Principal | null {
    const state = this.load();
    if (!state) return null;
    const session = this.ctx.storage.sql
      .exec<Session>("SELECT * FROM sessions WHERE id=?", proof.id)
      .toArray()[0];
    if (
      !session ||
      session.secret_hash !== proof.hash ||
      session.expires <= now ||
      session.revoked !== 0 ||
      session.epoch !== state.epoch ||
      state.denied.includes(session.device) ||
      !state.registrations[session.device] ||
      (data &&
        (!state.trusted?.devices[session.device] || state.pending !== null))
    )
      return null;
    return {
      locator: state.locator,
      account: state.id,
      device: session.device,
      epoch: state.epoch,
      session: session.id,
      expires: session.expires,
    };
  }
  private overviewResult(actor: Principal): Result {
    const state = this.load();
    if (!this.allowed(state, actor, true)) return { status: 403 };
    const active = !!state.trusted?.devices[actor.device];
    return {
      status: 200,
      body: {
        account_id: state.id,
        auth_epoch: state.epoch,
        device_state: active ? "active" : "pending",
        phase: state.pending ? "revocation_pending" : "ready",
        proof: state.proof,
        genesis_hash: state.trusted?.anchor.genesis_hash ?? null,
        pairing_confirmation:
          state.registrations[actor.device].confirmation ?? null,
        ...(active
          ? {
              vaults: state.vaults,
              denied: state.denied,
              devices: Object.values(state.registrations).map((r) => ({
                device: r.device,
                name: r.name,
                state:
                  state.denied.includes(r.device.id) ||
                  (state.trusted?.seen_devices[r.device.id] &&
                    !state.trusted.devices[r.device.id])
                    ? "revoked"
                    : state.trusted?.devices[r.device.id]
                      ? "active"
                      : "pending",
                request: r.request,
              })),
              barrier: state.pending
                ? {
                    id: state.pending.id,
                    acknowledged: state.pending.acknowledged.length,
                    total: state.pending.targets.length,
                  }
                : null,
            }
          : {}),
      },
    };
  }
  private logoutResult(actor: Principal): Result {
    const state = this.load();
    if (!this.allowed(state, actor, true)) return { status: 403 };
    this.ctx.storage.sql.exec(
      "UPDATE sessions SET revoked=1 WHERE id=?",
      actor.session,
    );
    return { status: 204 };
  }
  private async enrollmentResult(
    actor: Principal,
    request: Enrollment,
    now = Date.now(),
  ): Promise<Result> {
    const observed = this.load();
    if (
      !this.allowed(observed, actor, true) ||
      !observed.trusted ||
      observed.trusted.devices[actor.device]
    )
      return { status: 403 };
    if (
      !(await verifyEnrollment(request, now)) ||
      request.origin !== observed.origin ||
      request.account_id !== observed.id ||
      request.genesis_hash !== observed.trusted.anchor.genesis_hash ||
      !sameDevice(request.device, observed.registrations[actor.device].device)
    )
      return { status: 400 };
    return this.ctx.storage.transactionSync(() => {
      const state = this.load();
      if (
        !this.allowed(state, actor, true) ||
        state.version !== observed.version
      )
        return { status: 409 };
      state.registrations[actor.device].request = request;
      state.version += 1;
      this.save(state);
      return { status: 204 };
    });
  }
  private async bootstrapResult(
    actor: Principal,
    genesis: Genesis,
    vault: string,
    wraps: WrappedKeys[],
  ): Promise<Result> {
    const observed = this.load();
    if (!this.allowed(observed, actor, true)) return { status: 403 };
    if (observed.proof) return { status: 409 };
    if (
      !genesis ||
      !hex(vault, 64) ||
      genesis.origin !== observed.origin ||
      genesis.account_id !== observed.id ||
      !genesis.first ||
      !validKeys(genesis.first.keys) ||
      !sameDevice(genesis.first, observed.registrations[actor.device].device)
    )
      return { status: 400 };
    let trusted: TrustedMembership | null;
    try {
      trusted = await trustGenesis(genesis, {
        origin: observed.origin,
        account_id: observed.id,
        genesis_hash: await hash(genesisCanonical(genesis)),
      });
    } catch {
      return { status: 400 };
    }
    if (
      !trusted ||
      !(await completeWraps(trusted, vault, 1, wraps, actor.device))
    )
      return { status: 400 };
    const result = this.ctx.storage.transactionSync(() => {
      const state = this.load();
      if (
        !this.allowed(state, actor, true) ||
        state.version !== observed.version ||
        state.proof
      )
        return { status: 409 };
      state.proof = { genesis, nodes: [] };
      state.trusted = trusted;
      state.epoch += 1;
      state.version += 1;
      state.vaults[vault] = { epoch: 1, rekey: false };
      state.pending = {
        id: trusted!.head,
        targets: [vault],
        acknowledged: [],
        wraps: { [vault]: wraps },
        freeze: false,
      };
      state.lastControl = trusted!.head;
      this.save(state);
      return { status: 202 };
    });
    return result.status === 202 ? this.resumeBarrier() : result;
  }
  private async controlResult(
    actor: Principal,
    node: SignedMembership,
    wraps: Record<string, WrappedKeys[]>,
    confirmation: PairingConfirmation | null = null,
    now = Date.now(),
  ): Promise<Result> {
    const observed = this.load();
    if (!this.allowed(observed, actor) || !observed.trusted || !observed.proof)
      return { status: 403 };
    if (
      node?.body &&
      node.signature === observed.proof.nodes.at(-1)?.signature
    ) {
      try {
        if (
          (await hash(
            (await import("./membership")).membershipCanonical(node.body),
          )) === observed.trusted.head
        )
          return observed.pending
            ? this.resumeBarrier()
            : {
                status: 200,
                body: {
                  access_revoked: true,
                  rekey_pending: Object.values(observed.vaults).some(
                    (v) => v.rekey,
                  ),
                },
              };
      } catch {
        return { status: 400 };
      }
    }
    if (observed.pending) return { status: 423 };
    if (
      observed.proof.nodes.length >= 1024 ||
      node?.body?.author !== actor.device ||
      node.body.action === "recover"
    )
      return { status: 400 };
    const next = await applyMembership(observed.trusted, node);
    if (
      !next ||
      Math.abs(safeNumber(node.body.issued_at_ms, false) - now) > 300000 ||
      Object.keys(next.devices).some((id) => observed.denied.includes(id))
    )
      return { status: 400 };
    const freeze = node.body.action !== "add";
    if (node.body.action === "add") {
      if (Object.values(observed.vaults).some((v) => v.rekey))
        return { status: 423 };
      const request = node.body.enrollment!,
        registered = observed.registrations[request.device.id];
      if (
        !validConfirmation(confirmation, request.request_id, next.head) ||
        !registered?.request ||
        requestId(registered.request) !== requestId(request) ||
        !(await verifyEnrollment(request, now))
      )
        return { status: 400 };
    } else if (confirmation !== null) return { status: 400 };
    // A new recovery authority must be able to open retained data even if this device is
    // lost before content rekey completes. Install next-head bridge wraps at the old epoch.
    if (node.body.action === "add" || node.body.action === "recovery") {
      if (
        !wraps ||
        Object.keys(wraps).length !== Object.keys(observed.vaults).length
      )
        return { status: 400 };
      for (const [id, vault] of Object.entries(observed.vaults))
        if (
          !(await completeWraps(next, id, vault.epoch, wraps[id], actor.device))
        )
          return { status: 400 };
    } else if (!wraps || Object.keys(wraps).length) return { status: 400 };
    const result = this.publishMembership(
      observed,
      actor,
      node,
      next,
      wraps,
      freeze,
      confirmation,
    );
    return result.status === 202 ? this.resumeBarrier() : result;
  }
  private publishMembership(
    observed: Account,
    actor: Principal,
    node: SignedMembership,
    next: TrustedMembership,
    wraps: Record<string, WrappedKeys[]>,
    freeze: boolean,
    confirmation: PairingConfirmation | null,
    pendingActor = false,
  ): Result {
    return this.ctx.storage.transactionSync(() => {
      const state = this.load();
      if (
        !this.allowed(state, actor, pendingActor) ||
        state.version !== observed.version ||
        state.pending
      )
        return { status: 409 };
      if (node.body.enrollment)
        state.registrations[node.body.enrollment.device.id].confirmation =
          confirmation;
      state.proof!.nodes.push(node);
      state.trusted = next;
      state.epoch += 1;
      state.version += 1;
      for (const id of Object.keys(observed.trusted!.devices))
        if (!next.devices[id] && !state.denied.includes(id))
          state.denied.push(id);
      if (freeze)
        for (const vault of Object.values(state.vaults)) vault.rekey = true;
      state.pending = {
        id: next.head,
        targets: Object.keys(state.vaults),
        acknowledged: [],
        wraps,
        freeze,
      };
      state.lastControl = next.head;
      this.save(state);
      return { status: 202 };
    });
  }
  async recoveryWraps(
    actor: Principal,
    proof: RecoveryReadProof,
  ): Promise<Response> {
    return rpcCall(() => this.recoveryWrapsResult(actor, proof));
  }
  private async recoveryWrapsResult(
    actor: Principal,
    proof: RecoveryReadProof,
    now = Date.now(),
  ): Promise<Result> {
    const observed = this.load();
    if (
      !this.allowed(observed, actor, true) ||
      !observed.trusted ||
      !observed.proof ||
      observed.trusted.devices[actor.device]
    )
      return { status: 403 };
    const request = observed.registrations[actor.device].request;
    if (
      !request ||
      !(await verifyRecoveryRead(
        observed.trusted,
        request,
        proof,
        observed.epoch,
        now,
      ))
    )
      return { status: 403 };
    if (this.load()?.version !== observed.version) return { status: 409 };
    // A newly backed-up kit must also recover a device lost while the prior barrier was
    // interrupted. Prove current kit authority first, then finish the already-signed barrier.
    if (observed.pending) {
      const result = await this.resumeBarrier();
      if (result.status !== 200) return result;
      return this.recoveryWrapsResult(actor, proof, now);
    }
    const grant: RecoveryReadGrant = {
      kind: "recovery_read",
      locator: observed.locator,
      account: observed.id,
      device: actor.device,
      epoch: observed.epoch,
      head: observed.trusted.head,
      expires: Math.min(
        actor.expires,
        safeNumber(request.expires_at_ms, false),
        now + 300000,
      ),
    };
    const results: unknown[] = [];
    for (const id of Object.keys(observed.vaults)) {
      const result = await this.env.VAULT.getByName(
        observed.id + ":" + id,
      ).recoveryForGrant(grant);
      if (result.status !== 200) {
        await result.body?.cancel();
        return { status: 409, body: { error: "recovery_checkpoint_changed" } };
      }
      results.push(await result.json());
    }
    if (this.load()?.version !== observed.version) return { status: 409 };
    return {
      status: 200,
      body: {
        membership_head: observed.trusted.head,
        auth_epoch: observed.epoch,
        results,
      },
    };
  }
  async recover(
    actor: Principal,
    node: SignedMembership,
    wraps: Record<string, WrappedKeys[]>,
    now = Date.now(),
  ): Promise<Response> {
    return rpcCall(() => this.recoverResult(actor, node, wraps, now));
  }
  private async recoverResult(
    actor: Principal,
    node: SignedMembership,
    wraps: Record<string, WrappedKeys[]>,
    now: number,
  ): Promise<Result> {
    const observed = this.load();
    if (
      !this.allowed(observed, actor, true) ||
      !observed.trusted ||
      !observed.proof
    )
      return { status: 403 };
    if (
      node?.body?.enrollment?.device?.id === actor.device &&
      node.signature === observed.proof.nodes.at(-1)?.signature
    ) {
      try {
        if (
          (await hash(
            (await import("./membership")).membershipCanonical(node.body),
          )) === observed.trusted.head
        )
          return this.resumeBarrier();
      } catch {
        return { status: 400 };
      }
    }
    if (observed.pending) return { status: 423 };
    if (
      observed.proof.nodes.length >= 1024 ||
      observed.trusted.devices[actor.device] ||
      observed.trusted.seen_devices[actor.device] ||
      node?.body?.action !== "recover" ||
      node.body.author !== "recovery"
    )
      return { status: 403 };
    const request = observed.registrations[actor.device].request;
    if (
      !request ||
      !node.body.enrollment ||
      requestId(request) !== requestId(node.body.enrollment) ||
      !(await verifyEnrollment(request, now))
    )
      return { status: 400 };
    const next = await applyMembership(observed.trusted, node);
    if (
      !next ||
      Math.abs(safeNumber(node.body.issued_at_ms, false) - now) > 300000 ||
      next.recovery.signing === observed.trusted.recovery.signing ||
      next.recovery.encryption === observed.trusted.recovery.encryption ||
      Object.keys(next.devices).some((id) => observed.denied.includes(id))
    )
      return { status: 400 };
    if (
      !wraps ||
      Object.keys(wraps).length !== Object.keys(observed.vaults).length
    )
      return { status: 400 };
    for (const [id, vault] of Object.entries(observed.vaults))
      if (
        !(await completeWraps(next, id, vault.epoch, wraps[id], actor.device))
      )
        return { status: 400 };
    const result = this.publishMembership(
      observed,
      actor,
      node,
      next,
      wraps,
      true,
      null,
      true,
    );
    return result.status === 202 ? this.resumeBarrier() : result;
  }
  deviceAccess(identity: Identity): Response {
    const state = this.load();
    if (!state || identity.locator !== state.locator)
      return rpcResponse({ status: 404 });
    return rpcResponse({
      status: 200,
      body: {
        account_locator: state.locator,
        auth_epoch: state.epoch,
        barrier_pending: state.pending !== null,
        devices: Object.values(state.registrations).map((r) => ({
          id: r.device.id,
          name: r.name,
          created_at_ms: r.created,
          state:
            state.denied.includes(r.device.id) ||
            (state.trusted?.seen_devices[r.device.id] &&
              !state.trusted.devices[r.device.id])
              ? "revoked"
              : state.trusted?.devices[r.device.id]
                ? "active"
                : "pending",
        })),
      },
    });
  }
  private async createVaultResult(
    actor: Principal,
    vault: string,
    wraps: WrappedKeys[],
  ): Promise<Result> {
    const observed = this.load();
    if (!this.allowed(observed, actor) || !observed.trusted)
      return { status: 403 };
    if (observed.pending || Object.values(observed.vaults).some((v) => v.rekey))
      return { status: 423 };
    if (
      !hex(vault, 64) ||
      observed.vaults[vault] ||
      Object.keys(observed.vaults).length >= 64 ||
      !(await completeWraps(observed.trusted, vault, 1, wraps, actor.device))
    )
      return { status: 400 };
    const result = this.ctx.storage.transactionSync(() => {
      const state = this.load();
      if (
        !this.allowed(state, actor) ||
        state.version !== observed.version ||
        state.pending
      )
        return { status: 409 };
      state.vaults[vault] = { epoch: 1, rekey: false };
      state.version += 1;
      state.pending = {
        id: state.trusted!.head + ":" + vault,
        targets: [vault],
        acknowledged: [],
        wraps: { [vault]: wraps },
        freeze: false,
      };
      this.save(state);
      return { status: 202 };
    });
    return result.status === 202 ? this.resumeBarrier() : result;
  }
  private async revokeAccessResult(
    identity: Identity,
    device: string,
    now = Date.now(),
  ): Promise<Result> {
    const observed = this.load();
    if (
      !observed ||
      identity.locator !== observed.locator ||
      identity.authenticatedAt === null ||
      now - identity.authenticatedAt > 300000 ||
      identity.authenticatedAt > now + 5000
    )
      return { status: 403 };
    if (!hex(device, 32) || !observed.registrations[device])
      return { status: 404 };
    if (observed.pending)
      return observed.denied.includes(device)
        ? this.resumeBarrier()
        : { status: 423 };
    if (observed.denied.includes(device))
      return {
        status: 200,
        body: {
          access_revoked: true,
          rekey_pending: Object.values(observed.vaults).some((v) => v.rekey),
        },
      };
    observed.denied.push(device);
    observed.epoch += 1;
    observed.version += 1;
    for (const vault of Object.values(observed.vaults)) vault.rekey = true;
    observed.pending = {
      id: randomId(16),
      targets: Object.keys(observed.vaults),
      acknowledged: [],
      wraps: {},
      freeze: true,
    };
    this.save(observed);
    return this.resumeBarrier();
  }
  private async resumeResult(actor: Principal): Promise<Result> {
    const state = this.load();
    if (!this.allowed(state, actor)) return { status: 403 };
    return this.resumeBarrier();
  }
  private async resumeBarrier(): Promise<Result> {
    let state = this.load();
    if (!state?.pending)
      return {
        status: 200,
        body: {
          access_revoked: true,
          rekey_pending: Object.values(state?.vaults ?? {}).some(
            (v) => v.rekey,
          ),
        },
      };
    const pendingId = state.pending.id;
    for (const vault of state.pending.targets) {
      state = this.load();
      if (!state?.pending || state.pending.id !== pendingId) break;
      if (state.pending.acknowledged.includes(vault)) continue;
      const input: Install = {
        locator: state.locator,
        account: state.id,
        vault,
        epoch: state.epoch,
        proof: state.proof!,
        wraps: state.pending.wraps[vault] ?? [],
        freeze: state.pending.freeze,
        denied: state.denied,
      };
      let status: number;
      try {
        status = await this.env.VAULT.getByName(state.id + ":" + vault).install(
          input,
        );
      } catch {
        status = 503;
      }
      if (status !== 200)
        return {
          status: 202,
          body: {
            access_revoked: false,
            barrier_pending: true,
            retry_after_seconds: 5,
          },
        };
      state = this.load();
      if (!state?.pending || state.pending.id !== pendingId) break;
      if (!state.pending.acknowledged.includes(vault)) {
        state.pending.acknowledged.push(vault);
        state.version += 1;
        this.save(state);
      }
    }
    state = this.load();
    if (!state?.pending || state.pending.id !== pendingId)
      return { status: 409 };
    if (state.pending.acknowledged.length !== state.pending.targets.length)
      return { status: 202 };
    state.pending = null;
    state.version += 1;
    this.save(state);
    return {
      status: 200,
      body: {
        access_revoked: true,
        rekey_pending: Object.values(state.vaults).some((v) => v.rekey),
      },
    };
  }
}
