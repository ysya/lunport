import { DurableObject } from "cloudflare:workers";
import { verifyRekey, wrapsDigest, type SignedRekey } from "./rekey";
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
  exactObject,
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
type RekeyJournal = {
  manifest: SignedRekey;
  wraps: WrappedKeys[];
  staged: number;
  historyHash: string;
};
type StagedVersion = {
  revision: string;
  sequence: string;
  envelope: RecordEnvelope;
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
  rekey?: RekeyJournal | null;
  abortedRekeys?: string[];
};
const ZERO = "0".repeat(64);
const MAX_HISTORY_BYTES = 32 * 1024 * 1024;
const MAX_HISTORY = 16384;
const MAX_RECEIPTS = 32768;
const SCHEMA = `CREATE TABLE IF NOT EXISTS vault_state (id INTEGER PRIMARY KEY CHECK(id=1), value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS versions (seq INTEGER PRIMARY KEY, record_id TEXT NOT NULL, revision INTEGER NOT NULL, envelope TEXT NOT NULL, digest TEXT NOT NULL, history_hash TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS versions_record ON versions(record_id, revision);
CREATE TABLE IF NOT EXISTS current_records (record_id TEXT PRIMARY KEY, revision INTEGER NOT NULL, seq INTEGER NOT NULL, envelope TEXT NOT NULL, digest TEXT NOT NULL, history_hash TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS operations (operation_id TEXT PRIMARY KEY, digest TEXT NOT NULL, receipt TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS rekey_versions (seq INTEGER PRIMARY KEY,record_id TEXT NOT NULL,revision INTEGER NOT NULL,envelope TEXT NOT NULL,digest TEXT NOT NULL,history_hash TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS rekey_commits (epoch INTEGER PRIMARY KEY,rotation_id TEXT UNIQUE NOT NULL,manifest TEXT NOT NULL,wraps TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS rekey_source_digests (epoch INTEGER NOT NULL,seq INTEGER NOT NULL,digest TEXT NOT NULL,PRIMARY KEY(epoch,seq));`;
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
  private recoveryAllowed(
    state: VaultState | null,
    grant: RecoveryReadGrant,
  ): state is VaultState {
    return (
      !!state &&
      grant.kind === "recovery_read" &&
      grant.locator === state.locator &&
      grant.account === state.account &&
      grant.epoch === state.epoch &&
      grant.head === state.trusted.head &&
      grant.expires > Date.now() &&
      !state.denied.includes(grant.device)
    );
  }
  recoveryForGrant(grant: RecoveryReadGrant): Response {
    const state = this.load();
    if (!this.recoveryAllowed(state, grant))
      return rpcResponse({ status: 403 });
    const wrap = state.wraps.find((w) => w.header.recipient === "recovery");
    if (!wrap) return rpcResponse({ status: 423 });
    const committed =
      state.keyEpoch === 1 ? null : this.committedBundle(state.keyEpoch);
    if (state.keyEpoch > 1 && !committed)
      return rpcResponse({
        status: 409,
        body: { error: "recovery_commit_unavailable" },
      });
    return rpcResponse({
      status: 200,
      body: {
        vault: state.vault,
        epoch: state.keyEpoch,
        phase: state.phase,
        wrap,
        committed,
        sequence: String(state.sequence),
        history_hash: state.historyHash,
        commits: this.ctx.storage.sql
          .exec<{ manifest: string }>(
            "SELECT manifest FROM rekey_commits ORDER BY epoch",
          )
          .toArray()
          .map((row) => JSON.parse(row.manifest)),
      },
    });
  }
  recoveryHistoryForGrant(grant: RecoveryReadGrant, since: number): Response {
    const state = this.load();
    if (!this.recoveryAllowed(state, grant))
      return rpcResponse({ status: 403 });
    return rpcResponse(this.historyResult(state, since));
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
      // A newly removed device may already know any staged key. Supersede the staging
      // journal on every new ACL/head installation and require fresh content keys.
      if (current?.rekey)
        this.ctx.storage.sql.exec("DELETE FROM rekey_versions");
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
        rekey: null,
        abortedRekeys: [],
      });
      return 200;
    });
  }
  beginRekey(
    actor: Principal,
    manifest: SignedRekey,
    wraps: WrappedKeys[],
  ): Promise<Response> {
    return rpcCall(() => this.beginRekeyResult(actor, manifest, wraps));
  }
  private async beginRekeyResult(
    actor: Principal,
    manifest: SignedRekey,
    wraps: WrappedKeys[],
  ): Promise<Result> {
    const observed = this.load();
    if (!this.allowed(observed, actor)) return { status: 403 };
    if (
      observed.phase !== "rekey_pending" ||
      Object.keys(observed.trusted.devices).some((id) =>
        observed.denied.includes(id),
      )
    )
      return { status: 423 };
    if (
      !(await verifyRekey(
        observed.trusted,
        manifest,
        {
          vault: observed.vault,
          authEpoch: observed.epoch,
          keyEpoch: observed.keyEpoch,
          sequence: observed.sequence,
          historyHash: observed.historyHash,
        },
        actor.device,
      )) ||
      !(await completeWraps(
        observed.trusted,
        observed.vault,
        observed.keyEpoch + 1,
        wraps,
        actor.device,
      )) ||
      (await wrapsDigest(wraps)) !== manifest.body.wraps_digest
    )
      return { status: 403 };
    return this.ctx.storage.transactionSync(() => {
      const state = this.load();
      if (!this.allowed(state, actor)) return { status: 403 };
      if (state.version !== observed.version) return { status: 409 };
      if (state.abortedRekeys?.includes(manifest.body.rotation_id))
        return { status: 409, body: { error: "rotation_aborted" } };
      if ((state.abortedRekeys?.length ?? 0) >= 128)
        return { status: 413, body: { error: "rotation_capacity" } };
      if (state.rekey)
        return state.rekey.manifest.signature === manifest.signature &&
          state.rekey.manifest.body.rotation_id === manifest.body.rotation_id
          ? {
              status: 200,
              body: {
                staged: String(state.rekey.staged),
                history_hash: state.rekey.historyHash,
              },
            }
          : { status: 409, body: { error: "rekey_in_progress" } };
      const count = this.ctx.storage.sql
        .exec<{ count: number }>("SELECT COUNT(*) AS count FROM rekey_commits")
        .one().count;
      const proofs = this.ctx.storage.sql
        .exec<{ count: number }>(
          "SELECT COUNT(*) AS count FROM rekey_source_digests",
        )
        .one().count;
      if (count >= 64 || proofs + state.sequence > 1048576)
        return { status: 413, body: { error: "checkpoint_capacity" } };
      this.ctx.storage.sql.exec("DELETE FROM rekey_versions");
      this.save({
        ...state,
        version: state.version + 1,
        rekey: { manifest, wraps, staged: 0, historyHash: ZERO },
      });
      return { status: 200, body: { staged: "0", history_hash: ZERO } };
    });
  }
  stageRekey(
    actor: Principal,
    id: string,
    after: string,
    rows: StagedVersion[],
  ): Promise<Response> {
    return rpcCall(() => this.stageRekeyResult(actor, id, after, rows));
  }
  private async stageRekeyResult(
    actor: Principal,
    id: string,
    afterRaw: string,
    rows: StagedVersion[],
  ): Promise<Result> {
    const observed = this.load();
    if (!this.allowed(observed, actor)) return { status: 403 };
    const journal = observed.rekey;
    if (
      observed.phase !== "rekey_pending" ||
      !journal ||
      journal.manifest.body.rotation_id !== id
    )
      return { status: 409 };
    if (journal.manifest.body.author !== actor.device) return { status: 403 };
    let after: number;
    try {
      after = safeNumber(afterRaw, true);
    } catch {
      return { status: 400 };
    }
    if (
      !Array.isArray(rows) ||
      rows.length < 1 ||
      rows.length > 32 ||
      after + rows.length > observed.sequence ||
      after > journal.staged ||
      (after < journal.staged && after + rows.length > journal.staged)
    )
      return { status: 409 };
    let historyHash =
      after === 0
        ? ZERO
        : this.ctx.storage.sql
            .exec<{ history_hash: string }>(
              "SELECT history_hash FROM rekey_versions WHERE seq=?",
              after,
            )
            .toArray()[0]?.history_hash;
    if (!historyHash) return { status: 409 };
    const staged: { row: StagedVersion; encoded: string }[] = [];
    for (let index = 0; index < rows.length; index++) {
      const row = rows[index],
        seq = after + index + 1;
      if (
        !exactObject(row, [
          "revision",
          "sequence",
          "envelope",
          "digest",
          "history_hash",
        ]) ||
        row.sequence !== String(seq)
      )
        return { status: 400 };
      const original = this.ctx.storage.sql
        .exec<Version>("SELECT * FROM versions WHERE seq=?", seq)
        .toArray()[0];
      if (!original || row.revision !== String(original.revision))
        return { status: 400 };
      const old = JSON.parse(original.envelope) as RecordEnvelope,
        h = row.envelope?.header;
      if (
        !h ||
        h.record_id !== old.header.record_id ||
        h.kind !== old.header.kind ||
        h.deleted !== old.header.deleted ||
        h.expected_revision !== old.header.expected_revision ||
        h.operation_id !== old.header.operation_id ||
        !(await verifyCurrentWrite(
          observed.trusted,
          row.envelope,
          observed.vault,
          observed.keyEpoch + 1,
          actor.device,
        ))
      )
        return { status: 403 };
      const digest = await envelopeDigest(row.envelope);
      historyHash = await hash(
        canonical(["lunport-history-v2", historyHash, String(seq), digest]),
      );
      if (row.digest !== digest || row.history_hash !== historyHash)
        return { status: 400 };
      if (after < journal.staged) {
        const saved = this.ctx.storage.sql
          .exec<Version>("SELECT * FROM rekey_versions WHERE seq=?", seq)
          .toArray()[0];
        if (
          !saved ||
          saved.digest !== digest ||
          saved.history_hash !== historyHash
        )
          return { status: 409 };
      }
      staged.push({ row, encoded: JSON.stringify(row.envelope) });
    }
    return this.ctx.storage.transactionSync(() => {
      const state = this.load();
      if (!this.allowed(state, actor)) return { status: 403 };
      if (
        state.version !== observed.version ||
        !state.rekey ||
        state.rekey.manifest.body.rotation_id !== id ||
        state.phase !== "rekey_pending"
      )
        return { status: 409 };
      if (after < journal.staged)
        return {
          status: 200,
          body: {
            staged: String(journal.staged),
            history_hash: journal.historyHash,
          },
        };
      const count = after + rows.length;
      if (
        count === state.sequence &&
        historyHash !== journal.manifest.body.target_history_hash
      )
        return { status: 409, body: { error: "target_digest_mismatch" } };
      const usage = this.ctx.storage.sql
        .exec<{ bytes: number }>(
          "SELECT COALESCE(SUM(LENGTH(envelope)),0) AS bytes FROM rekey_versions",
        )
        .one().bytes;
      if (
        usage + staged.reduce((sum, r) => sum + r.encoded.length, 0) >
        MAX_HISTORY_BYTES
      )
        return { status: 413 };
      for (const { row, encoded } of staged)
        this.ctx.storage.sql.exec(
          "INSERT INTO rekey_versions VALUES(?,?,?,?,?,?)",
          Number(row.sequence),
          row.envelope.header.record_id,
          Number(row.revision),
          encoded,
          row.digest,
          row.history_hash,
        );
      this.save({
        ...state,
        version: state.version + 1,
        rekey: { ...journal, staged: count, historyHash },
      });
      return {
        status: 200,
        body: { staged: String(count), history_hash: historyHash },
      };
    });
  }
  commitRekey(actor: Principal, id: string): Response {
    return rpcResponse(
      this.ctx.storage.transactionSync(() => {
        const state = this.load();
        if (!this.allowed(state, actor)) return { status: 403 };
        const previous = this.ctx.storage.sql
          .exec<{ manifest: string }>(
            "SELECT manifest FROM rekey_commits WHERE rotation_id=?",
            id,
          )
          .toArray()[0];
        if (previous)
          return {
            status: 200,
            body: { manifest: JSON.parse(previous.manifest) },
          };
        const journal = state.rekey;
        if (
          state.phase !== "rekey_pending" ||
          !journal ||
          journal.manifest.body.rotation_id !== id
        )
          return { status: 409 };
        if (journal.manifest.body.author !== actor.device)
          return { status: 403 };
        if (
          journal.staged !== state.sequence ||
          journal.historyHash !== journal.manifest.body.target_history_hash
        )
          return { status: 409, body: { error: "staging_incomplete" } };
        const count = this.ctx.storage.sql
          .exec<{ count: number }>(
            "SELECT COUNT(*) AS count FROM rekey_versions",
          )
          .one().count;
        if (count !== state.sequence) return { status: 409 };
        const epoch = state.keyEpoch + 1;
        // Digests prove to offline clients that their known source prefix extends to the signed
        // source checkpoint. Old ciphertext is not retained; original operation receipts are.
        this.ctx.storage.sql.exec(
          "INSERT INTO rekey_source_digests SELECT ?,seq,digest FROM versions",
          epoch,
        );
        this.ctx.storage.sql.exec("DELETE FROM versions");
        this.ctx.storage.sql.exec("DELETE FROM current_records");
        this.ctx.storage.sql.exec(
          "INSERT INTO versions SELECT seq,record_id,revision,envelope,digest,history_hash FROM rekey_versions",
        );
        this.ctx.storage.sql.exec(
          "INSERT INTO current_records SELECT v.record_id,v.revision,v.seq,v.envelope,v.digest,v.history_hash FROM versions v JOIN (SELECT record_id,MAX(revision) AS revision FROM versions GROUP BY record_id) c ON c.record_id=v.record_id AND c.revision=v.revision",
        );
        this.ctx.storage.sql.exec(
          "INSERT INTO rekey_commits VALUES(?,?,?,?)",
          epoch,
          id,
          JSON.stringify(journal.manifest),
          JSON.stringify(journal.wraps),
        );
        this.ctx.storage.sql.exec("DELETE FROM rekey_versions");
        this.save({
          ...state,
          keyEpoch: epoch,
          phase: "ready",
          wraps: journal.wraps,
          version: state.version + 1,
          historyHash: journal.historyHash,
          rekey: null,
          abortedRekeys: [],
        });
        return { status: 200, body: { manifest: journal.manifest } };
      }),
    );
  }
  abortRekey(actor: Principal, id: string): Response {
    const state = this.load();
    if (!this.allowed(state, actor)) return rpcResponse({ status: 403 });
    if (!state.rekey || state.rekey.manifest.body.rotation_id !== id)
      return rpcResponse({ status: 409 });
    this.ctx.storage.transactionSync(() => {
      this.ctx.storage.sql.exec("DELETE FROM rekey_versions");
      this.save({
        ...state,
        version: state.version + 1,
        rekey: null,
        abortedRekeys: [...(state.abortedRekeys ?? []), id],
      });
    });
    return rpcResponse({ status: 204 });
  }
  rekeyStatus(actor: Principal): Response {
    const state = this.load();
    if (!this.allowed(state, actor)) return rpcResponse({ status: 403 });
    return rpcResponse({
      status: 200,
      body: {
        phase: state.phase,
        epoch: state.keyEpoch,
        sequence: String(state.sequence),
        history_hash: state.historyHash,
        journal: state.rekey
          ? {
              manifest: state.rekey.manifest,
              staged: String(state.rekey.staged),
              history_hash: state.rekey.historyHash,
            }
          : null,
        commits: this.ctx.storage.sql
          .exec<{ manifest: string }>(
            "SELECT manifest FROM rekey_commits ORDER BY epoch",
          )
          .toArray()
          .map((r) => JSON.parse(r.manifest)),
      },
    });
  }
  committedWraps(actor: Principal, epoch: number): Response {
    const state = this.load();
    if (!this.allowed(state, actor)) return rpcResponse({ status: 403 });
    if (!Number.isSafeInteger(epoch) || epoch < 2 || epoch > 65)
      return rpcResponse({ status: 400 });
    const bundle = this.committedBundle(epoch);
    return rpcResponse(
      bundle ? { status: 200, body: bundle } : { status: 404 },
    );
  }
  private committedBundle(
    epoch: number,
  ): { manifest: SignedRekey; wraps: WrappedKeys[] } | null {
    const commit = this.ctx.storage.sql
      .exec<{ manifest: string; wraps: string }>(
        "SELECT manifest,wraps FROM rekey_commits WHERE epoch=?",
        epoch,
      )
      .toArray()[0];
    return commit
      ? {
          manifest: JSON.parse(commit.manifest),
          wraps: JSON.parse(commit.wraps),
        }
      : null;
  }
  sourceProof(actor: Principal, epoch: number, after: number): Response {
    const state = this.load();
    if (!this.allowed(state, actor)) return rpcResponse({ status: 403 });
    return rpcResponse(this.sourceResult(epoch, after));
  }
  recoverySourceForGrant(
    grant: RecoveryReadGrant,
    epoch: number,
    after: number,
  ): Response {
    if (!this.recoveryAllowed(this.load(), grant))
      return rpcResponse({ status: 403 });
    return rpcResponse(this.sourceResult(epoch, after));
  }
  private sourceResult(epoch: number, after: number): Result {
    if (
      !Number.isSafeInteger(epoch) ||
      epoch < 2 ||
      epoch > 65 ||
      !Number.isSafeInteger(after) ||
      after < 0 ||
      after > 16384
    )
      return { status: 400 };
    const commit = this.ctx.storage.sql
      .exec<{ manifest: string }>(
        "SELECT manifest FROM rekey_commits WHERE epoch=?",
        epoch,
      )
      .toArray()[0];
    if (!commit) return { status: 404 };
    const manifest = JSON.parse(commit.manifest) as SignedRekey;
    if (after > safeNumber(manifest.body.source_sequence, true))
      return { status: 400 };
    return {
      status: 200,
      body: {
        manifest,
        digests: this.ctx.storage.sql
          .exec<{ seq: number; digest: string }>(
            "SELECT seq,digest FROM rekey_source_digests WHERE epoch=? AND seq>? ORDER BY seq LIMIT 256",
            epoch,
            after,
          )
          .toArray()
          .map((r) => ({ sequence: String(r.seq), digest: r.digest })),
      },
    };
  }
  operationReceipt(actor: Principal, id: string): Response {
    const state = this.load();
    if (!this.allowed(state, actor)) return rpcResponse({ status: 403 });
    if (!hex(id, 32)) return rpcResponse({ status: 400 });
    const row = this.ctx.storage.sql
      .exec<{ receipt: string }>(
        "SELECT receipt FROM operations WHERE operation_id=?",
        id,
      )
      .toArray()[0];
    return row
      ? rpcResponse({ status: 200, body: JSON.parse(row.receipt) })
      : rpcResponse({ status: 404 });
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
        authorization_epoch: String(state.epoch),
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
    return this.historyResult(state, since);
  }
  /** Same bounded ciphertext read for members and kit-authorized pending devices. */
  private historyResult(state: VaultState, since: number): Result {
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
          MAX_HISTORY_BYTES - 256 * 1024 ||
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
