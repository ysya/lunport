import { DurableObject } from "cloudflare:workers";
import {
  freezeCanonical,
  freezeDigest,
  sourceOrder,
  canExtendFreeze,
  verifyFreeze,
  frozenManifestMatches,
  type SignedFreeze,
  type FreezeJournal,
} from "./migration-freeze";
import { validSnapshot } from "../legacy-retirement";
import {
  migrationCanonical,
  migrationDigest,
  migrationScope,
  migrationSnapshot,
  verifyMigration,
  type SignedMigration,
  type MigrationJournal,
} from "./migration";
import {
  sameMigration,
  sameSnapshot,
  type LegacyMigrationScope,
  type LegacySnapshot,
} from "../legacy-retirement";
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
  verify,
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
CREATE TABLE IF NOT EXISTS rekey_source_digests (epoch INTEGER NOT NULL,seq INTEGER NOT NULL,digest TEXT NOT NULL,PRIMARY KEY(epoch,seq));
CREATE TABLE IF NOT EXISTS migration_journal (id INTEGER PRIMARY KEY CHECK(id=1),value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS migration_versions (seq INTEGER PRIMARY KEY,record_id TEXT NOT NULL,revision INTEGER NOT NULL,operation_id TEXT UNIQUE NOT NULL,envelope TEXT NOT NULL,digest TEXT NOT NULL,history_hash TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS migration_versions_record ON migration_versions(record_id,seq);
CREATE TABLE IF NOT EXISTS migration_freeze (id INTEGER PRIMARY KEY CHECK(id=1),value TEXT NOT NULL);`;
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
  private migrationJournal(): MigrationJournal | null {
    if (
      !this.ctx.storage.sql
        .exec(
          "SELECT name FROM sqlite_master WHERE type='table' AND name='migration_journal'",
        )
        .toArray().length
    )
      return null;
    const row = this.ctx.storage.sql
      .exec<{ value: string }>("SELECT value FROM migration_journal WHERE id=1")
      .toArray()[0];
    if (!row) return null;
    const journal = JSON.parse(row.value) as MigrationJournal;
    migrationCanonical(journal.manifest.body);
    if (
      !exactObject(journal, [
        "manifest",
        "digest",
        "phase",
        "staged",
        "historyHash",
        "retired",
      ]) ||
      !exactObject(journal.manifest, ["body", "signature"]) ||
      !hex(journal.digest, 64) ||
      !hex(journal.historyHash, 64) ||
      !["staging", "committed", "retired"].includes(journal.phase) ||
      !Number.isSafeInteger(journal.staged) ||
      journal.staged < 0 ||
      journal.staged >
        safeNumber(journal.manifest.body.target_sequence, false) ||
      !Number.isSafeInteger(journal.retired) ||
      journal.retired < 0 ||
      journal.retired > journal.manifest.body.sources.length ||
      (journal.phase === "staging" && journal.retired !== 0) ||
      (journal.phase !== "staging" &&
        (journal.staged !==
          safeNumber(journal.manifest.body.target_sequence, false) ||
          journal.historyHash !== journal.manifest.body.target_history_hash)) ||
      (journal.phase === "retired" &&
        journal.retired !== journal.manifest.body.sources.length)
    )
      throw new Error("Invalid migration journal.");
    return journal;
  }
  private migrationPending(): boolean {
    const migration = this.migrationJournal();
    return migration
      ? migration.phase === "staging"
      : this.freezeJournal() !== null;
  }
  private saveMigration(journal: MigrationJournal): void {
    this.ctx.storage.sql.exec(
      "INSERT INTO migration_journal VALUES(1,?) ON CONFLICT(id) DO UPDATE SET value=excluded.value",
      metadataJson(journal),
    );
  }
  private migrationObject(state: VaultState): boolean {
    return this.env.VAULT.idFromName(state.account + ":" + state.vault).equals(
      this.ctx.id,
    );
  }
  private migrationCurrent(
    state: VaultState,
    journal: MigrationJournal,
    actor: Principal,
  ): boolean {
    const body = journal.manifest.body;
    return (
      this.allowed(state, actor) &&
      this.migrationObject(state) &&
      state.phase === "ready" &&
      !state.rekey &&
      state.trusted.head === body.membership_head &&
      state.epoch === safeNumber(body.authorization_epoch, false) &&
      state.keyEpoch === safeNumber(body.key_epoch, false) &&
      state.trusted.anchor.origin === body.origin &&
      state.trusted.anchor.genesis_hash === body.genesis_hash &&
      state.account === body.account_id &&
      state.vault === body.vault_id
    );
  }
  private async migrationSources(manifest: SignedMigration): Promise<boolean> {
    try {
      for (const source of manifest.body.sources) {
        if (
          !(await this.env.LEGACY_RETIREMENT.getByName(
            source.chain_id,
          ).confirmFrozen(
            source.chain_id,
            migrationScope(manifest.body),
            migrationSnapshot(source),
          ))
        )
          return false;
      }
      return true;
    } catch {
      return false;
    }
  }
  private freezeJournal(): FreezeJournal | null {
    if (
      !this.ctx.storage.sql
        .exec(
          "SELECT name FROM sqlite_master WHERE type='table' AND name='migration_freeze'",
        )
        .toArray().length
    )
      return null;
    const row = this.ctx.storage.sql
      .exec<{ value: string }>("SELECT value FROM migration_freeze WHERE id=1")
      .toArray()[0];
    if (!row) return null;
    const journal = JSON.parse(row.value) as FreezeJournal;
    if (
      !exactObject(journal, ["version", "proof", "sources"]) ||
      journal.version !== 1 ||
      !Array.isArray(journal.proof) ||
      !journal.proof.length ||
      journal.proof.length > 65 ||
      !Array.isArray(journal.sources) ||
      journal.sources.length > 65
    )
      throw new Error("Invalid source freeze journal.");
    for (let index = 0; index < journal.proof.length; index++) {
      const step = journal.proof[index];
      if (
        !exactObject(step, ["intent", "digest"]) ||
        !exactObject(step.intent, ["body", "signature"]) ||
        !hex(step.digest, 64)
      )
        throw new Error("Invalid source freeze proof.");
      freezeCanonical(step.intent.body);
      if (
        step.intent.body.revision !== String(index + 1) ||
        (index &&
          !canExtendFreeze(
            journal.proof[index - 1].intent,
            journal.proof[index - 1].digest,
            step.intent,
          ))
      )
        throw new Error("Invalid source freeze extension.");
    }
    const body = journal.proof.at(-1)!.intent.body;
    let previous = "";
    for (const source of journal.sources) {
      if (
        !exactObject(source, [
          "chain_id",
          "sequence",
          "count",
          "ciphertext_digest",
        ]) ||
        source.chain_id <= previous ||
        !body.chains.includes(source.chain_id) ||
        !validSnapshot(migrationSnapshot(source))
      )
        throw new Error("Invalid frozen source checkpoint.");
      previous = source.chain_id;
    }
    return journal;
  }
  private saveFreeze(journal: FreezeJournal): void {
    this.ctx.storage.sql.exec(
      "INSERT INTO migration_freeze VALUES(1,?) ON CONFLICT(id) DO UPDATE SET value=excluded.value",
      metadataJson(journal),
    );
  }
  private async verifyFreezeJournal(
    journal: FreezeJournal,
    state: VaultState,
  ): Promise<boolean> {
    for (const step of journal.proof) {
      const body = step.intent.body,
        author = state.trusted.seen_devices[body.author];
      if (
        !author ||
        body.origin !== state.trusted.anchor.origin ||
        body.account_id !== state.account ||
        body.genesis_hash !== state.trusted.anchor.genesis_hash ||
        body.vault_id !== state.vault ||
        (await freezeDigest(step.intent)) !== step.digest ||
        !(await verify(
          author.signing,
          freezeCanonical(body),
          step.intent.signature,
        ))
      )
        return false;
    }
    return true;
  }
  private freezeStatusResult(actor: Principal): Result {
    const state = this.load();
    if (!this.allowed(state, actor) || !this.migrationObject(state))
      return { status: 403 };
    const journal = this.freezeJournal();
    if (!journal) return { status: 404 };
    const latest = journal.proof.at(-1)!,
      done = new Set(journal.sources.map((source) => source.chain_id));
    const next = sourceOrder(latest.intent.body)
      .filter((chain) => !done.has(chain))
      .slice(0, 8);
    return {
      status: 200,
      body: {
        proof: journal.proof,
        sources: journal.sources,
        phase:
          done.size === latest.intent.body.chains.length
            ? "frozen"
            : "freezing",
        next,
      },
    };
  }
  freezeStatus(actor: Principal): Promise<Response> {
    return rpcCall(async () => {
      const state = this.load(),
        journal = this.freezeJournal();
      if (!this.allowed(state, actor) || !this.migrationObject(state))
        return { status: 403 };
      if (!journal) return { status: 404 };
      if (!(await this.verifyFreezeJournal(journal, state)))
        return { status: 503 };
      const current = this.load();
      if (!this.allowed(current, actor)) return { status: 403 };
      return current.version === state.version
        ? this.freezeStatusResult(actor)
        : { status: 409 };
    });
  }
  /** Ephemeral old bearers authenticate only their legacy chains, never the central account. */
  freezeSources(
    actor: Principal,
    intent: SignedFreeze,
    credentials: { chain: string; token: string }[],
  ): Promise<Response> {
    return rpcCall(async () => {
      const observed = this.load();
      if (!this.allowed(observed, actor) || !this.migrationObject(observed))
        return { status: 403 };
      if (
        !(await verifyFreeze(
          observed.trusted,
          intent,
          observed.epoch,
          observed.keyEpoch,
          observed.vault,
          actor.device,
        ))
      )
        return { status: 403 };
      if (
        !Array.isArray(credentials) ||
        credentials.length > 8 ||
        credentials.some(
          (value) =>
            !exactObject(value, ["chain", "token"]) ||
            !hex(value.chain, 64) ||
            !hex(value.token, 64),
        )
      )
        return { status: 400 };
      const digest = await freezeDigest(intent),
        prior = this.freezeJournal();
      if (prior && !(await this.verifyFreezeJournal(prior, observed)))
        return { status: 503 };
      if (
        this.migrationJournal() ||
        observed.sequence !== 0 ||
        observed.historyHash !== ZERO ||
        observed.phase !== "ready" ||
        observed.rekey
      )
        return { status: 409 };
      if (
        prior
          ? digest !== prior.proof.at(-1)!.digest &&
            !canExtendFreeze(
              prior.proof.at(-1)!.intent,
              prior.proof.at(-1)!.digest,
              intent,
            )
          : intent.body.revision !== "1"
      )
        return { status: 409 };
      const order = sourceOrder(intent.body),
        witnessed = new Set(
          prior?.sources.map((source) => source.chain_id) ?? [],
        );
      let last = -1;
      for (const value of credentials) {
        const index = order.indexOf(value.chain);
        if (
          index <= last ||
          index < 0 ||
          order.slice(0, index).some((chain) => !witnessed.has(chain))
        )
          return { status: 400 };
        witnessed.add(value.chain);
        last = index;
      }
      const prepared = this.ctx.storage.transactionSync(() => {
        const current = this.load(),
          latest = this.freezeJournal();
        if (!this.allowed(current, actor)) return 403;
        if (
          current.version !== observed.version ||
          latest?.proof.at(-1)?.digest !== prior?.proof.at(-1)?.digest ||
          this.migrationJournal()
        )
          return 409;
        if (latest?.proof.at(-1)?.digest !== digest) {
          this.ctx.storage.sql.exec(SCHEMA);
          this.saveFreeze({
            version: 1,
            proof: [...(latest?.proof ?? []), { intent, digest }],
            sources: latest?.sources ?? [],
          });
          this.save({ ...current, version: current.version + 1 });
        }
        return 200;
      });
      if (prepared !== 200) return { status: prepared };
      for (const credential of credentials) {
        const state = this.load(),
          journal = this.freezeJournal();
        if (!this.allowed(state, actor)) return { status: 403 };
        if (
          !journal ||
          journal.proof.at(-1)!.digest !== digest ||
          this.migrationJournal()
        )
          return { status: 409 };
        if (
          journal.sources.some((source) => source.chain_id === credential.chain)
        )
          continue;
        const tokenHash = await hash(
          new TextEncoder().encode(credential.token),
        );
        const checked = this.load();
        if (!this.allowed(checked, actor)) return { status: 403 };
        let response: { status: number; snapshot?: LegacySnapshot };
        try {
          response = await this.env.CHAIN.getByName(
            credential.chain,
          ).freezeForMigration(
            credential.chain,
            tokenHash,
            migrationScope(intent.body),
          );
        } catch {
          return { status: 503 };
        }
        if (
          response.status !== 200 ||
          !response.snapshot ||
          !validSnapshot(response.snapshot)
        )
          return { status: response.status === 200 ? 503 : response.status };
        if (!this.allowed(this.load(), actor)) return { status: 403 };
        let frozen: number;
        try {
          frozen = await this.env.LEGACY_RETIREMENT.getByName(
            credential.chain,
          ).freeze(
            credential.chain,
            tokenHash,
            migrationScope(intent.body),
            response.snapshot,
          );
        } catch {
          return { status: 503 };
        }
        if (frozen !== 200) return { status: frozen };
        const source = {
          chain_id: credential.chain,
          sequence: String(response.snapshot.latestSeq),
          count: String(response.snapshot.count),
          ciphertext_digest: response.snapshot.digest,
        };
        const result = this.ctx.storage.transactionSync(() => {
          const current = this.load(),
            latest = this.freezeJournal();
          if (!this.allowed(current, actor)) return 403;
          if (
            !latest ||
            latest.proof.at(-1)!.digest !== digest ||
            this.migrationJournal()
          )
            return 409;
          const known = latest.sources.find(
            (value) => value.chain_id === credential.chain,
          );
          if (known)
            return sameSnapshot(migrationSnapshot(known), response.snapshot!)
              ? 200
              : 409;
          this.saveFreeze({
            ...latest,
            sources: [...latest.sources, source].sort((a, b) =>
              a.chain_id < b.chain_id ? -1 : a.chain_id > b.chain_id ? 1 : 0,
            ),
          });
          this.save({ ...current, version: current.version + 1 });
          return 200;
        });
        if (result !== 200) return { status: result };
      }
      return this.freezeStatusResult(actor);
    });
  }
  /** Transport admission is private-ingress only; native cutover is separately guarded. */
  beginMigration(
    actor: Principal,
    manifest: SignedMigration,
    freshWraps?: WrappedKeys[],
    requireFreeze = false,
  ): Promise<Response> {
    return rpcCall(async () => {
      const observed = this.load();
      if (!this.allowed(observed, actor) || !this.migrationObject(observed))
        return { status: 403 };
      if (
        !(await verifyMigration(
          observed.trusted,
          manifest,
          observed.epoch,
          observed.keyEpoch,
          observed.vault,
          actor.device,
        ))
      )
        return { status: 403 };
      const frozen = this.freezeJournal();
      if (requireFreeze && !frozen) return { status: 409 };
      if (
        frozen &&
        (!(await this.verifyFreezeJournal(frozen, observed)) ||
          !frozenManifestMatches(frozen, manifest))
      )
        return { status: 409 };
      const wraps = freshWraps ?? observed.wraps;
      if (
        freshWraps &&
        !(await completeWraps(
          observed.trusted,
          observed.vault,
          observed.keyEpoch,
          freshWraps,
          actor.device,
        ))
      )
        return { status: 403 };
      if (manifest.body.wraps_digest !== (await wrapsDigest(wraps)))
        return { status: 409 };
      const digest = await migrationDigest(manifest),
        prior = this.migrationJournal();
      if (prior)
        return prior.digest === digest
          ? this.migrationStatusResult(actor)
          : { status: 409 };
      if (
        observed.sequence !== 0 ||
        observed.historyHash !== ZERO ||
        observed.phase !== "ready" ||
        observed.rekey
      )
        return { status: 409 };
      if (!(await this.migrationSources(manifest))) return { status: 503 };
      return this.ctx.storage.transactionSync(() => {
        const current = this.load();
        if (!this.allowed(current, actor)) return { status: 403 };
        if (current.version !== observed.version || this.migrationJournal())
          return { status: 409 };
        this.ctx.storage.sql.exec(SCHEMA);
        if (freshWraps)
          this.save({
            ...current,
            wraps: freshWraps,
            version: current.version + 1,
          });
        this.saveMigration({
          manifest,
          digest,
          phase: "staging",
          staged: 0,
          historyHash: ZERO,
          retired: 0,
        });
        return this.migrationStatusResult(actor);
      });
    });
  }
  migrationStatus(actor: Principal): Response {
    return rpcResponse(this.migrationStatusResult(actor));
  }
  private migrationStatusResult(actor: Principal): Result {
    const state = this.load();
    if (!this.allowed(state, actor) || !this.migrationObject(state))
      return { status: 403 };
    const journal = this.migrationJournal();
    return journal
      ? {
          status: 200,
          body: {
            manifest: journal.manifest,
            manifest_digest: journal.digest,
            phase: journal.phase,
            staged: String(journal.staged),
            history_hash: journal.historyHash,
            retired: String(journal.retired),
          },
        }
      : { status: 404 };
  }
  stageMigration(
    actor: Principal,
    id: string,
    afterText: string,
    envelopes: RecordEnvelope[],
  ): Promise<Response> {
    return rpcCall(async () => {
      const observed = this.load(),
        journal = this.migrationJournal();
      if (!this.allowed(observed, actor)) return { status: 403 };
      if (
        !journal ||
        journal.phase !== "staging" ||
        journal.manifest.body.migration_id !== id ||
        !this.migrationCurrent(observed, journal, actor)
      )
        return { status: 409 };
      let after: number;
      try {
        after = safeNumber(afterText, true);
      } catch {
        return { status: 400 };
      }
      if (
        !Array.isArray(envelopes) ||
        envelopes.length < 1 ||
        envelopes.length > 32
      )
        return { status: 400 };
      if (
        after > journal.staged ||
        after + envelopes.length >
          safeNumber(journal.manifest.body.target_sequence, false) ||
        (after < journal.staged && after + envelopes.length > journal.staged)
      )
        return { status: 409 };
      let historyHash =
        after === 0
          ? ZERO
          : this.ctx.storage.sql
              .exec<{ history_hash: string }>(
                "SELECT history_hash FROM migration_versions WHERE seq=?",
                after,
              )
              .toArray()[0]?.history_hash;
      if (!historyHash) return { status: 409 };
      const rows: {
        envelope: RecordEnvelope;
        encoded: string;
        digest: string;
        historyHash: string;
        sequence: number;
        revision: number;
      }[] = [];
      const revisions = new Map<string, number>(),
        ops = new Set<string>();
      for (const envelope of envelopes) {
        if (
          !(await verifyCurrentWrite(
            observed.trusted,
            envelope,
            observed.vault,
            observed.keyEpoch,
            actor.device,
          )) ||
          envelope.header.author !== journal.manifest.body.author
        )
          return { status: 403 };
        const { record_id, operation_id } = envelope.header;
        if (ops.has(operation_id)) return { status: 400 };
        ops.add(operation_id);
        const previous =
          revisions.get(record_id) ??
          this.ctx.storage.sql
            .exec<{ revision: number }>(
              "SELECT revision FROM migration_versions WHERE record_id=? AND seq<=? ORDER BY seq DESC LIMIT 1",
              record_id,
              after,
            )
            .toArray()[0]?.revision ??
          0;
        if (safeNumber(envelope.header.expected_revision, true) !== previous)
          return { status: 409 };
        const revision = previous + 1;
        revisions.set(record_id, revision);
        const digest = await envelopeDigest(envelope),
          sequence = after + rows.length + 1;
        historyHash = await hash(
          canonical([
            "lunport-history-v2",
            historyHash,
            String(sequence),
            digest,
          ]),
        );
        if (after < journal.staged) {
          const prior = this.ctx.storage.sql
            .exec<{ digest: string }>(
              "SELECT digest FROM migration_versions WHERE seq=?",
              sequence,
            )
            .toArray()[0];
          if (prior?.digest !== digest) return { status: 409 };
        } else if (
          this.ctx.storage.sql
            .exec(
              "SELECT seq FROM migration_versions WHERE operation_id=?",
              operation_id,
            )
            .toArray().length
        )
          return { status: 409 };
        rows.push({
          envelope,
          encoded: JSON.stringify(envelope),
          digest,
          historyHash,
          sequence,
          revision,
        });
      }
      return this.ctx.storage.transactionSync(() => {
        const current = this.load(),
          latest = this.migrationJournal();
        if (!this.allowed(current, actor)) return { status: 403 };
        if (
          !latest ||
          latest.digest !== journal.digest ||
          latest.phase !== "staging" ||
          latest.staged !== journal.staged ||
          current.version !== observed.version ||
          !this.migrationCurrent(current, latest, actor)
        )
          return { status: 409 };
        if (after < latest.staged) return this.migrationStatusResult(actor);
        const bytes = this.ctx.storage.sql
          .exec<{ bytes: number }>(
            "SELECT COALESCE(SUM(LENGTH(envelope)),0) AS bytes FROM migration_versions",
          )
          .one().bytes;
        if (
          bytes + rows.reduce((sum, row) => sum + row.encoded.length, 0) >
          MAX_HISTORY_BYTES - 256 * 1024
        )
          return { status: 413 };
        const ids = new Set(
          this.ctx.storage.sql
            .exec<{ record_id: string }>(
              "SELECT DISTINCT record_id FROM migration_versions",
            )
            .toArray()
            .map((row) => row.record_id),
        );
        for (const row of rows) ids.add(row.envelope.header.record_id);
        if (ids.size > 4096) return { status: 413 };
        for (const row of rows)
          this.ctx.storage.sql.exec(
            "INSERT INTO migration_versions VALUES(?,?,?,?,?,?,?)",
            row.sequence,
            row.envelope.header.record_id,
            row.revision,
            row.envelope.header.operation_id,
            row.encoded,
            row.digest,
            row.historyHash,
          );
        this.saveMigration({
          ...latest,
          staged: after + rows.length,
          historyHash,
        });
        return this.migrationStatusResult(actor);
      });
    });
  }
  commitMigration(actor: Principal, id: string): Promise<Response> {
    return rpcCall(async () => {
      const observed = this.load(),
        journal = this.migrationJournal();
      if (!this.allowed(observed, actor) || !this.migrationObject(observed))
        return { status: 403 };
      if (!journal || journal.manifest.body.migration_id !== id)
        return { status: 409 };
      if (journal.phase !== "staging") return this.migrationStatusResult(actor);
      if (
        !this.migrationCurrent(observed, journal, actor) ||
        journal.staged !==
          safeNumber(journal.manifest.body.target_sequence, false) ||
        journal.historyHash !== journal.manifest.body.target_history_hash ||
        observed.sequence !== 0 ||
        observed.historyHash !== ZERO
      )
        return { status: 409 };
      if (
        journal.manifest.body.wraps_digest !==
          (await wrapsDigest(observed.wraps)) ||
        !(await this.migrationSources(journal.manifest))
      )
        return { status: 503 };
      return this.ctx.storage.transactionSync(() => {
        const current = this.load(),
          latest = this.migrationJournal();
        if (!this.allowed(current, actor)) return { status: 403 };
        if (
          !latest ||
          latest.digest !== journal.digest ||
          latest.phase !== "staging" ||
          latest.staged !== journal.staged ||
          current.version !== observed.version ||
          !this.migrationCurrent(current, latest, actor)
        )
          return { status: 409 };
        const rows = this.ctx.storage.sql
          .exec<{
            seq: number;
            record_id: string;
            revision: number;
            operation_id: string;
            envelope: string;
            digest: string;
            history_hash: string;
          }>("SELECT * FROM migration_versions ORDER BY seq")
          .toArray();
        if (
          rows.length !== journal.staged ||
          rows.at(-1)?.history_hash !== journal.historyHash ||
          this.ctx.storage.sql
            .exec("SELECT seq FROM versions LIMIT 1")
            .toArray().length ||
          this.ctx.storage.sql
            .exec("SELECT record_id FROM current_records LIMIT 1")
            .toArray().length ||
          this.ctx.storage.sql
            .exec("SELECT operation_id FROM operations LIMIT 1")
            .toArray().length
        )
          return { status: 409 };
        for (const row of rows) {
          this.ctx.storage.sql.exec(
            "INSERT INTO versions VALUES(?,?,?,?,?,?)",
            row.seq,
            row.record_id,
            row.revision,
            row.envelope,
            row.digest,
            row.history_hash,
          );
          this.ctx.storage.sql.exec(
            "INSERT INTO current_records VALUES(?,?,?,?,?,?) ON CONFLICT(record_id) DO UPDATE SET revision=excluded.revision,seq=excluded.seq,envelope=excluded.envelope,digest=excluded.digest,history_hash=excluded.history_hash",
            row.record_id,
            row.revision,
            row.seq,
            row.envelope,
            row.digest,
            row.history_hash,
          );
          const receipt: Receipt = {
            operation_id: row.operation_id,
            record_id: row.record_id,
            revision: String(row.revision),
            sequence: String(row.seq),
            digest: row.digest,
            history_hash: row.history_hash,
          };
          this.ctx.storage.sql.exec(
            "INSERT INTO operations VALUES(?,?,?)",
            row.operation_id,
            row.digest,
            JSON.stringify(receipt),
          );
        }
        this.save({
          ...current,
          version: current.version + 1,
          sequence: journal.staged,
          historyHash: journal.historyHash,
        });
        this.saveMigration({
          ...latest,
          phase: latest.manifest.body.sources.length ? "committed" : "retired",
        });
        this.ctx.storage.sql.exec("DELETE FROM migration_versions");
        return this.migrationStatusResult(actor);
      });
    });
  }
  /** Internal callback: registry accepts a durable target commit, never a claimed hash. */
  migrationCommitWitness(
    actor: Principal,
    scope: LegacyMigrationScope,
    chain: string,
    snapshot: LegacySnapshot,
  ): number {
    const state = this.load(),
      journal = this.migrationJournal();
    if (!this.allowed(state, actor) || !this.migrationObject(state)) return 403;
    if (
      !journal ||
      journal.phase === "staging" ||
      !sameMigration(migrationScope(journal.manifest.body), scope)
    )
      return 409;
    const source = journal.manifest.body.sources.find(
      (s) => s.chain_id === chain,
    );
    return source &&
      sameSnapshot(migrationSnapshot(source), snapshot) &&
      state.trusted.anchor.origin === scope.origin &&
      state.trusted.anchor.genesis_hash === scope.genesis
      ? 204
      : 409;
  }
  retireMigration(actor: Principal, id: string): Promise<Response> {
    return rpcCall(async () => {
      const observed = this.load(),
        journal = this.migrationJournal();
      if (!this.allowed(observed, actor) || !this.migrationObject(observed))
        return { status: 403 };
      if (
        !journal ||
        journal.manifest.body.migration_id !== id ||
        journal.phase === "staging"
      )
        return { status: 409 };
      if (journal.phase === "retired") return this.migrationStatusResult(actor);
      for (const source of journal.manifest.body.sources.slice(
        journal.retired,
        journal.retired + 8,
      )) {
        let code: number;
        try {
          code = await this.env.LEGACY_RETIREMENT.getByName(
            source.chain_id,
          ).retireForMigration(
            source.chain_id,
            migrationScope(journal.manifest.body),
            migrationSnapshot(source),
            actor,
          );
        } catch {
          return { status: 503 };
        }
        if (code !== 200) return { status: code };
        const current = this.load(),
          latest = this.migrationJournal();
        if (!this.allowed(current, actor)) return { status: 403 };
        if (
          !latest ||
          latest.digest !== journal.digest ||
          latest.phase === "staging"
        )
          return { status: 409 };
        const index = latest.manifest.body.sources.findIndex(
          (s) => s.chain_id === source.chain_id,
        );
        // A lost acknowledgement retries the same irreversible registry transition.
        if (latest.retired < index) return { status: 409 };
        if (latest.retired === index)
          this.saveMigration({
            ...latest,
            retired: index + 1,
            phase:
              index + 1 === latest.manifest.body.sources.length
                ? "retired"
                : "committed",
          });
      }
      return this.migrationStatusResult(actor);
    });
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
    if (this.migrationPending()) return rpcResponse({ status: 423 });
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
    if (this.migrationPending())
      return { status: 423, body: { error: "migration_pending" } };
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
    if (this.migrationPending())
      return { status: 423, body: { error: "migration_pending" } };
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
    if (this.migrationPending())
      return { status: 423, body: { error: "migration_pending" } };
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
    if (this.migrationPending())
      return { status: 423, body: { error: "migration_pending" } };
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
      if (this.migrationPending())
        return { status: 423, body: { error: "migration_pending" } };
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
