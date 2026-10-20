/** Signed initial-library commit. Contains public ciphertext commitments only. */
import {
  canonical,
  decode,
  exactObject,
  hash,
  hex,
  safeNumber,
  validOrigin,
  verify,
} from "./protocol";
import type { TrustedMembership } from "./membership";
import type {
  LegacyMigrationScope,
  LegacySnapshot,
} from "../legacy-retirement";
export type MigrationSource = {
  chain_id: string;
  sequence: string;
  count: string;
  ciphertext_digest: string;
};
export type MigrationBody = {
  origin: string;
  account_id: string;
  genesis_hash: string;
  vault_id: string;
  migration_id: string;
  authorization_epoch: string;
  key_epoch: string;
  membership_head: string;
  author: string;
  inventory_digest: string;
  target_sequence: string;
  target_history_hash: string;
  wraps_digest: string;
  sources: MigrationSource[];
};
export type SignedMigration = { body: MigrationBody; signature: string };
export type MigrationJournal = {
  manifest: SignedMigration;
  digest: string;
  phase: "staging" | "committed" | "retired";
  staged: number;
  historyHash: string;
  retired: number;
};
const fields = [
  "origin",
  "account_id",
  "genesis_hash",
  "vault_id",
  "migration_id",
  "authorization_epoch",
  "key_epoch",
  "membership_head",
  "author",
  "inventory_digest",
  "target_sequence",
  "target_history_hash",
  "wraps_digest",
] as const;
export function migrationCanonical(body: MigrationBody): Uint8Array {
  if (
    !exactObject(body, [...fields, "sources"]) ||
    fields.some((f) => typeof body[f] !== "string") ||
    !validOrigin(body.origin) ||
    ![
      body.account_id,
      body.genesis_hash,
      body.vault_id,
      body.membership_head,
      body.inventory_digest,
      body.target_history_hash,
      body.wraps_digest,
    ].every((v) => hex(v, 64)) ||
    !hex(body.migration_id, 32) ||
    !hex(body.author, 32) ||
    !Array.isArray(body.sources) ||
    body.sources.length > 65
  )
    throw new Error("Invalid migration manifest.");
  safeNumber(body.authorization_epoch, false);
  safeNumber(body.key_epoch, false);
  if (safeNumber(body.target_sequence, false) > 16384)
    throw new Error("Invalid migration capacity.");
  let previous = "";
  const sources = body.sources.map((source) => {
    if (
      !exactObject(source, [
        "chain_id",
        "sequence",
        "count",
        "ciphertext_digest",
      ]) ||
      !hex(source.chain_id, 64) ||
      !hex(source.ciphertext_digest, 64) ||
      source.chain_id <= previous
    )
      throw new Error("Invalid migration sources.");
    previous = source.chain_id;
    const count = safeNumber(source.count, true),
      sequence = safeNumber(source.sequence, true);
    if (count > 4096 || count > sequence)
      throw new Error("Invalid migration checkpoint.");
    return new TextDecoder().decode(
      canonical([
        "lunport-migration-source-v2",
        source.chain_id,
        source.sequence,
        source.count,
        source.ciphertext_digest,
      ]),
    );
  });
  return canonical([
    "lunport-migration-v2",
    ...fields.map((f) => body[f]),
    String(sources.length),
    ...sources,
  ]);
}
export function migrationScope(
  body: Pick<
    MigrationBody,
    "origin" | "account_id" | "genesis_hash" | "vault_id" | "migration_id"
  >,
): LegacyMigrationScope {
  return {
    operation: body.migration_id,
    origin: body.origin,
    account: body.account_id,
    genesis: body.genesis_hash,
    vault: body.vault_id,
  };
}
export function migrationSnapshot(source: MigrationSource): LegacySnapshot {
  return {
    latestSeq: safeNumber(source.sequence, true),
    count: safeNumber(source.count, true),
    digest: source.ciphertext_digest,
  };
}
export async function migrationDigest(
  manifest: SignedMigration,
): Promise<string> {
  if (!exactObject(manifest, ["body", "signature"]))
    throw new Error("Invalid migration manifest.");
  decode(manifest.signature, 64, 64);
  return hash(
    canonical([
      "lunport-migration-commit-v2",
      new TextDecoder().decode(migrationCanonical(manifest.body)),
      manifest.signature,
    ]),
  );
}
export async function verifyMigration(
  member: TrustedMembership,
  manifest: SignedMigration,
  authEpoch: number,
  keyEpoch: number,
  vault: string,
  actor: string,
): Promise<boolean> {
  try {
    if (!exactObject(manifest, ["body", "signature"])) return false;
    const body = manifest.body,
      bytes = migrationCanonical(body),
      author = member.devices[actor];
    return (
      !!author &&
      body.origin === member.anchor.origin &&
      body.account_id === member.anchor.account_id &&
      body.genesis_hash === member.anchor.genesis_hash &&
      body.vault_id === vault &&
      body.author === actor &&
      body.membership_head === member.head &&
      safeNumber(body.authorization_epoch, false) === authEpoch &&
      safeNumber(body.key_epoch, false) === keyEpoch &&
      (await verify(author.signing, bytes, manifest.signature))
    );
  } catch {
    return false;
  }
}
