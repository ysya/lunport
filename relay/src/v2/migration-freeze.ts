/** Signed, monotonic complete-source intent. Bearers never belong to this journal. */
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
import type { MigrationSource, SignedMigration } from "./migration";
export type FreezeBody = {
  origin: string;
  account_id: string;
  genesis_hash: string;
  vault_id: string;
  migration_id: string;
  authorization_epoch: string;
  key_epoch: string;
  membership_head: string;
  author: string;
  /** Opaque commitment to a randomized encrypted preview, never a plaintext inventory hash. */
  preview_digest: string;
  parent_chain: string;
  revision: string;
  previous_digest: string;
  chains: string[];
};
export type SignedFreeze = { body: FreezeBody; signature: string };
export type FreezeJournal = {
  version: 1;
  proof: { intent: SignedFreeze; digest: string }[];
  sources: MigrationSource[];
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
  "preview_digest",
  "parent_chain",
  "revision",
  "previous_digest",
] as const;
export function freezeCanonical(body: FreezeBody): Uint8Array {
  if (
    !exactObject(body, [...fields, "chains"]) ||
    fields.some((f) => typeof body[f] !== "string") ||
    !validOrigin(body.origin) ||
    ![
      body.account_id,
      body.genesis_hash,
      body.vault_id,
      body.membership_head,
      body.preview_digest,
    ].every((v) => hex(v, 64)) ||
    !hex(body.migration_id, 32) ||
    !hex(body.author, 32) ||
    !Array.isArray(body.chains) ||
    body.chains.length > 65
  )
    throw new Error("Invalid source freeze intent.");
  safeNumber(body.authorization_epoch, false);
  safeNumber(body.key_epoch, false);
  const revision = safeNumber(body.revision, false);
  if (
    revision > 65 ||
    (revision === 1
      ? body.previous_digest !== ""
      : !hex(body.previous_digest, 64))
  )
    throw new Error("Invalid source freeze revision.");
  let previous = "";
  for (const chain of body.chains) {
    if (!hex(chain, 64) || chain <= previous)
      throw new Error("Invalid source freeze chains.");
    previous = chain;
  }
  if (
    body.parent_chain !== "" &&
    (!hex(body.parent_chain, 64) || !body.chains.includes(body.parent_chain))
  )
    throw new Error("Invalid source freeze parent.");
  return canonical([
    "lunport-migration-freeze-v2",
    ...fields.map((f) => body[f]),
    String(body.chains.length),
    ...body.chains,
  ]);
}
export async function freezeDigest(intent: SignedFreeze): Promise<string> {
  if (!exactObject(intent, ["body", "signature"]))
    throw new Error("Invalid source freeze intent.");
  decode(intent.signature, 64, 64);
  return hash(
    canonical([
      "lunport-migration-freeze-proof-v2",
      new TextDecoder().decode(freezeCanonical(intent.body)),
      intent.signature,
    ]),
  );
}
export function sourceOrder(body: FreezeBody): string[] {
  return body.parent_chain
    ? [
        body.parent_chain,
        ...body.chains.filter((chain) => chain !== body.parent_chain),
      ]
    : [...body.chains];
}
export function canExtendFreeze(
  before: SignedFreeze,
  beforeDigest: string,
  after: SignedFreeze,
): boolean {
  try {
    freezeCanonical(before.body);
    freezeCanonical(after.body);
    const a = before.body,
      b = after.body;
    return (
      [
        "origin",
        "account_id",
        "genesis_hash",
        "vault_id",
        "migration_id",
        "parent_chain",
        "preview_digest",
      ].every(
        (field) =>
          a[field as keyof FreezeBody] === b[field as keyof FreezeBody],
      ) &&
      b.previous_digest === beforeDigest &&
      safeNumber(b.revision, false) === safeNumber(a.revision, false) + 1 &&
      safeNumber(b.authorization_epoch, false) >=
        safeNumber(a.authorization_epoch, false) &&
      safeNumber(b.key_epoch, false) >= safeNumber(a.key_epoch, false) &&
      a.chains.every((chain) => b.chains.includes(chain))
    );
  } catch {
    return false;
  }
}
export async function verifyFreeze(
  member: TrustedMembership,
  intent: SignedFreeze,
  authEpoch: number,
  keyEpoch: number,
  vault: string,
  actor: string,
): Promise<boolean> {
  try {
    if (!exactObject(intent, ["body", "signature"])) return false;
    const b = intent.body,
      author = member.devices[actor],
      bytes = freezeCanonical(b);
    return (
      !!author &&
      b.origin === member.anchor.origin &&
      b.account_id === member.anchor.account_id &&
      b.genesis_hash === member.anchor.genesis_hash &&
      b.vault_id === vault &&
      b.author === actor &&
      b.membership_head === member.head &&
      safeNumber(b.authorization_epoch, false) === authEpoch &&
      safeNumber(b.key_epoch, false) === keyEpoch &&
      (await verify(author.signing, bytes, intent.signature))
    );
  } catch {
    return false;
  }
}
export function frozenManifestMatches(
  journal: FreezeJournal,
  manifest: SignedMigration,
): boolean {
  const body = journal.proof.at(-1)!.intent.body,
    target = manifest.body;
  return (
    [
      "origin",
      "account_id",
      "genesis_hash",
      "vault_id",
      "migration_id",
      "authorization_epoch",
      "key_epoch",
      "membership_head",
      "author",
    ].every(
      (field) =>
        body[field as keyof FreezeBody] ===
        target[field as keyof typeof target],
    ) &&
    body.chains.length === journal.sources.length &&
    journal.sources.length === target.sources.length &&
    journal.sources.every((source, index) => {
      const actual = target.sources[index];
      return (
        actual.chain_id === source.chain_id &&
        actual.sequence === source.sequence &&
        actual.count === source.count &&
        actual.ciphertext_digest === source.ciphertext_digest
      );
    })
  );
}
