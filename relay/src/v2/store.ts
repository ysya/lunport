import { DurableObject } from "cloudflare:workers";
import type { RecoveryReadGrant } from "./recovery";
import type { Principal } from "./auth";
import {
  applyMembership,
  trustGenesis,
  verifyCurrentWrap,
  verifyCurrentWrite,
  type Genesis,
  type SignedMembership,
  type TrustedMembership,
} from "./membership";
import {
  canonical,
  hash,
  hex,
  recordCanonical,
  safeNumber,
  type RecordEnvelope,
  type WrappedKeys,
} from "./protocol";

export type Result<T = unknown> = { status: number; body?: T };
/** Standard Response is an RPC-supported value; arbitrary unknown DTOs are not. */
export function rpcResponse(result: Result): Response {
  const headers = {
    "cache-control": "no-store",
    "x-content-type-options": "nosniff",
    ...(result.status === 429 || result.status === 202 || result.status === 503
      ? { "retry-after": "5" }
      : {}),
  };
  return result.body === undefined
    ? new Response(null, { status: result.status, headers })
    : Response.json(result.body, { status: result.status, headers });
}
class MetadataCapacity extends Error {}
export function metadataJson(value: unknown): string {
  const encoded = JSON.stringify(value);
  if (new TextEncoder().encode(encoded).byteLength > 1048576)
    throw new MetadataCapacity();
  return encoded;
}
export async function rpcCall(
  action: () => Result | Promise<Result>,
): Promise<Response> {
  try {
    return rpcResponse(await action());
  } catch (error) {
    if (error instanceof MetadataCapacity)
      return rpcResponse({ status: 413, body: { error: "metadata_capacity" } });
    throw error;
  }
}
export type ControlProof = { genesis: Genesis; nodes: SignedMembership[] };
export type Install = {
  locator: string;
  account: string;
  vault: string;
  epoch: number;
  proof: ControlProof;
  wraps: WrappedKeys[];
  freeze: boolean;
  denied: string[];
};
export type Receipt = {
  operation_id: string;
  record_id: string;
  revision: string;
  sequence: string;
  digest: string;
  history_hash: string;
};
type Version = {
  record_id: string;
  revision: number;
  seq: number;
  envelope: string;
  digest: string;
  history_hash: string;
};
type VaultState = {
  locator: string;
  account: string;
  vault: string;
  epoch: number;
  keyEpoch: number;
  trusted: TrustedMembership;
  phase: "ready" | "rekey_pending";
  wraps: WrappedKeys[];
  version: number;
  sequence: number;
  historyHash: string;
  denied: string[];
};
const ZERO = "0".repeat(64);
const MAX_HISTORY_BYTES = 32 * 1024 * 1024;
const MAX_HISTORY = 16384;
const MAX_RECEIPTS = 32768;
const SCHEMA = `CREATE TABLE IF NOT EXISTS vault_state (id INTEGER PRIMARY KEY CHECK(id=1), value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS versions (seq INTEGER PRIMARY KEY, record_id TEXT NOT NULL, revision INTEGER NOT NULL, envelope TEXT NOT NULL, digest TEXT NOT NULL, history_hash TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS versions_record ON versions(record_id, revision);
CREATE TABLE IF NOT EXISTS current_records (record_id TEXT PRIMARY KEY, revision INTEGER NOT NULL, seq INTEGER NOT NULL, envelope TEXT NOT NULL, digest TEXT NOT NULL, history_hash TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS operations (operation_id TEXT PRIMARY KEY, digest TEXT NOT NULL, receipt TEXT NOT NULL);`;
export async function verifyControl(
  proof: ControlProof,
): Promise<TrustedMembership | null> {
  try {
    if (!proof || !Array.isArray(proof.nodes) || proof.nodes.length > 1024)
      return null;
    const { genesisCanonical } = await import("./membership");
    const anchor = {
      origin: proof.genesis.origin,
      account_id: proof.genesis.account_id,
      genesis_hash: await hash(genesisCanonical(proof.genesis)),
    };
    let trusted = await trustGenesis(proof.genesis, anchor);
    for (const node of proof.nodes) {
      if (!trusted) return null;
      trusted = await applyMembership(trusted, node);
    }
    return trusted;
  } catch {
    return null;
  }
}
export async function completeWraps(
  trusted: TrustedMembership,
  vault: string,
  epoch: number,
  wraps: WrappedKeys[],
  author?: string,
): Promise<boolean> {
  if (
    !Array.isArray(wraps) ||
    wraps.length !== Object.keys(trusted.devices).length + 1 ||
    wraps.length > 65
  )
    return false;
  const recipients = new Set<string>();
  for (const wrapped of wraps) {
    if (
      !wrapped?.header ||
      recipients.has(wrapped.header.recipient) ||
      (author && wrapped.header.author !== author) ||
      !(await verifyCurrentWrap(trusted, wrapped, vault, epoch))
    )
      return false;
    recipients.add(wrapped.header.recipient);
  }
  return (
    recipients.has("recovery") &&
    Object.keys(trusted.devices).every((id) => recipients.has(id))
  );
}
export async function envelopeDigest(
  envelope: RecordEnvelope,
): Promise<string> {
  return hash(
    canonical([
      "lunport-operation-v2",
      new TextDecoder().decode(recordCanonical(envelope.header)),
      envelope.nonce,
      envelope.ciphertext,
      envelope.signature,
    ]),
  );
}
function versionBody(row: Version) {
  return {
    revision: String(row.revision),
    sequence: String(row.seq),
    envelope: JSON.parse(row.envelope) as RecordEnvelope,
    digest: row.digest,
    history_hash: row.history_hash,
  };
}
/** Each operation rechecks installed authorization at the final synchronous SQL transaction. */
export class VaultStore extends DurableObject<Env> {
  metadata(actor: Principal): Promise<Response> {
    return rpcCall(() => this.metadataResult(actor));
  }
  wrap(actor: Principal): Promise<Response> {
    return rpcCall(() => this.wrapResult(actor));
  }
  pull(actor: Principal, since: number): Promise<Response> {
    return rpcCall(() => this.pullResult(actor, since));
  }
  async push(actor: Principal, records: RecordEnvelope[]): Promise<Response> {
    return rpcCall(() => this.pushResult(actor, records));
  }
  recoveryForGrant(grant: RecoveryReadGrant): Response {
    const state = this.load();
    if (
      !state ||
      grant.kind !== "recovery_read" ||
      grant.locator !== state.locator ||
      grant.account !== state.account ||
      grant.epoch !== state.epoch ||
      grant.head !== state.trusted.head ||
      grant.expires <= Date.now() ||
      state.denied.includes(grant.device)
    )
      return rpcResponse({ status: 403 });
    const wrap = state.wraps.find((w) => w.header.recipient === "recovery");
    return wrap
      ? rpcResponse({
          status: 200,
          body: { vault: state.vault, epoch: state.keyEpoch, wrap },
        })
      : rpcResponse({ status: 423 });
  }
  private load(): VaultState | null {
    if (
      !this.ctx.storage.sql
        .exec(
          "SELECT name FROM sqlite_master WHERE type='table' AND name='vault_state'",
        )
        .toArray().length
    )
      return null;
    const row = this.ctx.storage.sql
      .exec<{ value: string }>("SELECT value FROM vault_state WHERE id=1")
      .toArray()[0];
    return row ? (JSON.parse(row.value) as VaultState) : null;
  }
  private save(state: VaultState): void {
    const encoded = metadataJson(state);
    this.ctx.storage.sql.exec(SCHEMA);
    this.ctx.storage.sql.exec(
      "INSERT INTO vault_state VALUES(1,?) ON CONFLICT(id) DO UPDATE SET value=excluded.value",
      encoded,
    );
  }
  private allowed(
    state: VaultState | null,
    actor: Principal,
  ): state is VaultState {
    return (
      !!state &&
      actor.locator === state.locator &&
      actor.account === state.account &&
      actor.epoch === state.epoch &&
      actor.expires > Date.now() &&
      !!state.trusted.devices[actor.device] &&
      !state.denied.includes(actor.device)
    );
  }
  async install(input: Install): Promise<number> {
    if (
      !hex(input.locator, 64) ||
      !hex(input.account, 64) ||
      !hex(input.vault, 64) ||
      !Number.isSafeInteger(input.epoch) ||
      input.epoch < 1
    )
      return 400;
    const observed = this.load();
    const trusted = await verifyControl(input.proof);
    if (!trusted || trusted.anchor.account_id !== input.account) return 400;
    if (
      observed &&
      (observed.locator !== input.locator ||
        observed.account !== input.account ||
        observed.vault !== input.vault ||
        trusted.anchor.genesis_hash !== observed.trusted.anchor.genesis_hash ||
        trusted.anchor.origin !== observed.trusted.anchor.origin)
    )
      return 403;
    if (
      observed &&
      trusted.head === observed.trusted.head &&
      observed.epoch === input.epoch
    )
      return 200;
    if (
      observed &&
      ((trusted.head !== observed.trusted.head &&
        trusted.revision !== observed.trusted.revision + 1) ||
        input.epoch <= observed.epoch)
    )
      return 409;
    if (
      !Array.isArray(input.denied) ||
      input.denied.length > 1024 ||
      input.denied.some((id) => !hex(id, 32))
    )
      return 400;
    const keyEpoch = observed?.keyEpoch ?? 1;
    if (!Array.isArray(input.wraps)) return 400;
    const recoveryChanged =
      !!observed &&
      (trusted.recovery.signing !== observed.trusted.recovery.signing ||
        trusted.recovery.encryption !== observed.trusted.recovery.encryption);
    const newRecipient =
      !!observed &&
      Object.keys(trusted.devices).some((id) => !observed.trusted.devices[id]);
    if (
      (!input.freeze ||
        !observed ||
        recoveryChanged ||
        newRecipient ||
        input.wraps.length > 0) &&
      !(await completeWraps(trusted, input.vault, keyEpoch, input.wraps))
    )
      return 400;
    return this.ctx.storage.transactionSync(() => {
      const current = this.load();
      if ((current?.version ?? -1) !== (observed?.version ?? -1)) return 409;
      this.save({
        locator: input.locator,
        account: input.account,
        vault: input.vault,
        epoch: input.epoch,
        keyEpoch,
        trusted,
        phase: input.freeze ? "rekey_pending" : "ready",
        wraps: input.wraps.length ? input.wraps : (current?.wraps ?? []),
        version: (current?.version ?? 0) + 1,
        sequence: current?.sequence ?? 0,
        historyHash: current?.historyHash ?? ZERO,
        denied: input.denied,
      });
      return 200;
    });
  }
  private metadataResult(actor: Principal): Result {
    const state = this.load();
    if (!this.allowed(state, actor)) return { status: 403 };
    return {
      status: 200,
      body: {
        vault: state.vault,
        epoch: state.keyEpoch,
        membership_head: state.trusted.head,
        phase: state.phase,
        sequence: String(state.sequence),
        history_hash: state.historyHash,
      },
    };
  }
  private wrapResult(actor: Principal): Result {
    const state = this.load();
    if (!this.allowed(state, actor)) return { status: 403 };
    const wrap = state.wraps.find((w) => w.header.recipient === actor.device);
    return wrap
      ? { status: 200, body: wrap }
      : { status: 423, body: { error: "rekey_pending" } };
  }
  private pullResult(actor: Principal, since: number): Result {
    const state = this.load();
    if (!this.allowed(state, actor)) return { status: 403 };
    if (!Number.isSafeInteger(since) || since < 0 || since > state.sequence)
      return { status: 400 };
    const rows = this.ctx.storage.sql
      .exec<Version>(
        "SELECT * FROM versions WHERE seq>? ORDER BY seq LIMIT 32",
        since,
      )
      .toArray();
    const records = [];
    let bytes = 0;
    for (const row of rows) {
      if (records.length && bytes + row.envelope.length > 1048576) break;
      records.push(versionBody(row));
      bytes += row.envelope.length;
    }
    return {
      status: 200,
      body: {
        records,
        sequence: String(state.sequence),
        history_hash: state.historyHash,
        membership_head: state.trusted.head,
        epoch: state.keyEpoch,
        phase: state.phase,
      },
    };
  }
  private async pushResult(
    actor: Principal,
    envelopes: RecordEnvelope[],
  ): Promise<Result> {
    const observed = this.load();
    if (!this.allowed(observed, actor)) return { status: 403 };
    if (observed.phase !== "ready")
      return { status: 423, body: { error: "rekey_pending" } };
    if (
      !Array.isArray(envelopes) ||
      envelopes.length < 1 ||
      envelopes.length > 32
    )
      return { status: 400 };
    const ids = new Set<string>(),
      ops = new Set<string>();
    const accepted: {
        envelope: RecordEnvelope;
        encoded: string;
        receipt: Receipt;
      }[] = [],
      receipts: Receipt[] = [];
    const conflicts: unknown[] = [];
    let sequence = observed.sequence,
      historyHash = observed.historyHash;
    for (const envelope of envelopes) {
      if (
        !(await verifyCurrentWrite(
          observed.trusted,
          envelope,
          observed.vault,
          observed.keyEpoch,
          actor.device,
        ))
      )
        return { status: 403 };
      const { record_id, operation_id, expected_revision } = envelope.header;
      if (ids.has(record_id) || ops.has(operation_id)) return { status: 400 };
      ids.add(record_id);
      ops.add(operation_id);
      const digest = await envelopeDigest(envelope);
      const prior = this.ctx.storage.sql
        .exec<{ digest: string; receipt: string }>(
          "SELECT digest,receipt FROM operations WHERE operation_id=?",
          operation_id,
        )
        .toArray()[0];
      if (prior) {
        if (prior.digest !== digest)
          return { status: 409, body: { error: "operation_reused" } };
        receipts.push(JSON.parse(prior.receipt));
        continue;
      }
      const current = this.ctx.storage.sql
        .exec<Version>(
          "SELECT * FROM current_records WHERE record_id=?",
          record_id,
        )
        .toArray()[0];
      if (safeNumber(expected_revision, true) !== (current?.revision ?? 0)) {
        conflicts.push({
          record_id,
          current: current ? versionBody(current) : null,
        });
        continue;
      }
      sequence += 1;
      if (!Number.isSafeInteger(sequence)) return { status: 413 };
      historyHash = await hash(
        canonical([
          "lunport-history-v2",
          historyHash,
          String(sequence),
          digest,
        ]),
      );
      const receipt: Receipt = {
        operation_id,
        record_id,
        revision: String((current?.revision ?? 0) + 1),
        sequence: String(sequence),
        digest,
        history_hash: historyHash,
      };
      accepted.push({ envelope, encoded: JSON.stringify(envelope), receipt });
      receipts.push(receipt);
    }
    // Async signature/hash checks may yield to an install/revocation; final ACL is authoritative.
    return this.ctx.storage.transactionSync(() => {
      const current = this.load();
      if (!this.allowed(current, actor)) return { status: 403 };
      if (current.phase !== "ready")
        return { status: 423, body: { error: "rekey_pending" } };
      if (current.version !== observed.version)
        return { status: 409, body: { error: "retry" } };
      if (conflicts.length)
        return { status: 409, body: { error: "revision_conflict", conflicts } };
      const usage = this.ctx.storage.sql
        .exec<{ count: number; bytes: number }>(
          "SELECT COUNT(*) AS count, COALESCE(SUM(LENGTH(envelope)),0) AS bytes FROM versions",
        )
        .one();
      const count = this.ctx.storage.sql
        .exec<{ count: number }>(
          "SELECT COUNT(*) AS count FROM current_records",
        )
        .one().count;
      const operations = this.ctx.storage.sql
        .exec<{ count: number }>("SELECT COUNT(*) AS count FROM operations")
        .one().count;
      const additional = accepted.filter(
        (a) => a.receipt.revision === "1",
      ).length;
      if (
        usage.count + accepted.length > MAX_HISTORY ||
        usage.bytes + accepted.reduce((sum, a) => sum + a.encoded.length, 0) >
          MAX_HISTORY_BYTES ||
        count + additional > 4096 ||
        operations + accepted.length > MAX_RECEIPTS
      )
        return { status: 413, body: { error: "vault_capacity" } };
      for (const { envelope, encoded, receipt } of accepted) {
        const args = [
          receipt.record_id,
          Number(receipt.revision),
          Number(receipt.sequence),
          encoded,
          receipt.digest,
          receipt.history_hash,
        ];
        this.ctx.storage.sql.exec(
          "INSERT INTO versions(record_id,revision,seq,envelope,digest,history_hash) VALUES(?,?,?,?,?,?)",
          ...args,
        );
        this.ctx.storage.sql.exec(
          "INSERT INTO current_records VALUES(?,?,?,?,?,?) ON CONFLICT(record_id) DO UPDATE SET revision=excluded.revision,seq=excluded.seq,envelope=excluded.envelope,digest=excluded.digest,history_hash=excluded.history_hash",
          ...args,
        );
        this.ctx.storage.sql.exec(
          "INSERT INTO operations VALUES(?,?,?)",
          envelope.header.operation_id,
          receipt.digest,
          JSON.stringify(receipt),
        );
      }
      if (accepted.length)
        this.save({
          ...current,
          version: current.version + 1,
          sequence,
          historyHash,
        });
      return {
        status: 200,
        body: {
          receipts,
          sequence: String(sequence),
          history_hash: historyHash,
        },
      };
    });
  }
}
