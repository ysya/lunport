/** Signed old-to-new content checkpoint. The service never receives content/index keys. */
import {
  base64,
  canonical,
  decode,
  exactObject,
  hash,
  hex,
  safeNumber,
  validOrigin,
  wrapCanonical,
  verify,
  type WrappedKeys,
} from "./protocol";
import type { TrustedMembership } from "./membership";
export type RekeyBody = {
  origin: string;
  account_id: string;
  genesis_hash: string;
  vault_id: string;
  rotation_id: string;
  authorization_epoch: string;
  from_epoch: string;
  to_epoch: string;
  membership_head: string;
  author: string;
  source_sequence: string;
  source_history_hash: string;
  target_history_hash: string;
  wraps_digest: string;
};
export type SignedRekey = { body: RekeyBody; signature: string };
export type FrozenCheckpoint = {
  vault: string;
  authEpoch: number;
  keyEpoch: number;
  sequence: number;
  historyHash: string;
};
const fields = [
  "origin",
  "account_id",
  "genesis_hash",
  "vault_id",
  "rotation_id",
  "authorization_epoch",
  "from_epoch",
  "to_epoch",
  "membership_head",
  "author",
  "source_sequence",
  "source_history_hash",
  "target_history_hash",
  "wraps_digest",
] as const;
export function rekeyCanonical(body: RekeyBody): Uint8Array {
  if (
    !exactObject(body, fields) ||
    fields.some((f) => typeof body[f] !== "string") ||
    !validOrigin(body.origin) ||
    ![
      body.account_id,
      body.genesis_hash,
      body.vault_id,
      body.membership_head,
      body.source_history_hash,
      body.target_history_hash,
      body.wraps_digest,
    ].every((v) => hex(v, 64)) ||
    !hex(body.rotation_id, 32) ||
    !hex(body.author, 32)
  )
    throw new Error("Invalid rekey manifest.");
  safeNumber(body.authorization_epoch, false);
  const from = safeNumber(body.from_epoch, false),
    to = safeNumber(body.to_epoch, false),
    count = safeNumber(body.source_sequence, true);
  if (
    to !== from + 1 ||
    !Number.isSafeInteger(from + 1) ||
    count > 16384 ||
    (count === 0 &&
      [body.source_history_hash, body.target_history_hash].some(
        (v) => v !== "0".repeat(64),
      ))
  )
    throw new Error("Invalid rekey checkpoint.");
  return canonical(["lunport-rekey-v2", ...fields.map((f) => body[f])]);
}
export async function wrapsDigest(wraps: WrappedKeys[]): Promise<string> {
  if (!Array.isArray(wraps) || wraps.length < 1 || wraps.length > 65)
    throw new Error("Invalid rekey recipients.");
  const sorted = [...wraps].sort((a, b) =>
    a.header.recipient < b.header.recipient
      ? -1
      : a.header.recipient > b.header.recipient
        ? 1
        : 0,
  );
  if (new Set(sorted.map((w) => w.header.recipient)).size !== sorted.length)
    throw new Error("Duplicate rekey recipient.");
  const entries = sorted.map((w) => {
    const header = wrapCanonical(w.header);
    decode(w.encapsulated_key, 32, 32);
    decode(w.ciphertext, 80, 80);
    decode(w.signature, 64, 64);
    return [base64(header), w.encapsulated_key, w.ciphertext, w.signature];
  });
  return hash(
    new TextEncoder().encode(
      JSON.stringify(["lunport-rekey-wraps-v2", entries]),
    ),
  );
}
export async function verifyRekey(
  state: TrustedMembership,
  manifest: SignedRekey,
  checkpoint: FrozenCheckpoint,
  actor: string,
): Promise<boolean> {
  try {
    if (!exactObject(manifest, ["body", "signature"])) return false;
    const b = manifest.body,
      bytes = rekeyCanonical(b),
      author = state.devices[actor];
    return (
      !!author &&
      b.origin === state.anchor.origin &&
      b.account_id === state.anchor.account_id &&
      b.genesis_hash === state.anchor.genesis_hash &&
      b.vault_id === checkpoint.vault &&
      b.author === actor &&
      b.membership_head === state.head &&
      safeNumber(b.authorization_epoch, false) === checkpoint.authEpoch &&
      safeNumber(b.from_epoch, false) === checkpoint.keyEpoch &&
      safeNumber(b.source_sequence, true) === checkpoint.sequence &&
      b.source_history_hash === checkpoint.historyHash &&
      (await verify(author.signing, bytes, manifest.signature))
    );
  } catch {
    return false;
  }
}
