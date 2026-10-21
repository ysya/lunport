/** Signed account-unlock ciphertext. No password, PRF output or plaintext recovery kit. */
import { base64, canonical, decode, exactObject, hash, hex, safeNumber, validOrigin, verify } from "./protocol";
import { validKeys, type PublicKeys, type TrustAnchor, type TrustedMembership } from "./membership";
export type UnlockBinding = { kind: "password" } | { kind: "native_prf"; credential_hash: string };
export type UnlockEnvelope = {
  header: { version: 1; anchor: TrustAnchor; generation: string; binding: UnlockBinding; salt: string };
  nonce: string;
  ciphertext: string;
};
export type UnlockBody = {
  version: 1;
  anchor: TrustAnchor;
  revision: string;
  previous_digest: string;
  membership_head: string;
  authorization_epoch: string;
  author: string;
  recovery: PublicKeys;
  slots: UnlockEnvelope[];
};
export type SignedUnlock = { body: UnlockBody; signature: string };
function invalid(): never { throw new Error("Invalid account unlock data."); }
function anchorValid(value: unknown): value is TrustAnchor {
  return exactObject(value, ["origin", "account_id", "genesis_hash"]) &&
    validOrigin(value.origin) && (value.origin as string).startsWith("https:") &&
    hex(value.account_id, 64) && hex(value.genesis_hash, 64);
}
function sameAnchor(a: TrustAnchor, b: TrustAnchor): boolean {
  return a.origin === b.origin && a.account_id === b.account_id && a.genesis_hash === b.genesis_hash;
}
export function slotId(envelope: UnlockEnvelope): string {
  const binding = envelope.header.binding;
  if (exactObject(binding, ["kind"]) && binding.kind === "password") return "password";
  if (exactObject(binding, ["kind", "credential_hash"]) && binding.kind === "native_prf" && hex(binding.credential_hash, 64))
    return "native_prf:" + binding.credential_hash;
  return invalid();
}
export function envelopeCanonical(envelope: UnlockEnvelope): Uint8Array {
  if (!exactObject(envelope, ["header", "nonce", "ciphertext"]) ||
      !exactObject(envelope.header, ["version", "anchor", "generation", "binding", "salt"])) invalid();
  const h = envelope.header;
  if (h.version !== 1 || !anchorValid(h.anchor)) invalid();
  safeNumber(h.generation, false);
  decode(h.salt, 32, 32);
  decode(envelope.nonce, 24, 24);
  decode(envelope.ciphertext, 17, 4112);
  const id = slotId(envelope);
  return canonical(["lunport-account-unlock-envelope-v1", h.anchor.origin, h.anchor.account_id,
    h.anchor.genesis_hash, h.generation, id, h.salt, envelope.nonce, envelope.ciphertext]);
}
export function unlockCanonical(body: UnlockBody): Uint8Array {
  if (!exactObject(body, ["version", "anchor", "revision", "previous_digest", "membership_head",
      "authorization_epoch", "author", "recovery", "slots"]) || body.version !== 1 ||
      !anchorValid(body.anchor) || !hex(body.membership_head, 64) || !hex(body.author, 32) ||
      !validKeys(body.recovery) || !Array.isArray(body.slots) || body.slots.length < 1 || body.slots.length > 8) invalid();
  const revision = safeNumber(body.revision, false);
  safeNumber(body.authorization_epoch, false);
  if (revision === 1 ? body.previous_digest !== "" : !hex(body.previous_digest, 64)) invalid();
  const slots: string[] = [];
  let previous = "";
  for (const envelope of body.slots) {
    const encoded = base64(envelopeCanonical(envelope)), id = slotId(envelope);
    if (id <= previous || !sameAnchor(envelope.header.anchor, body.anchor) ||
        safeNumber(envelope.header.generation, false) > revision) invalid();
    previous = id;
    slots.push(encoded);
  }
  return canonical(["lunport-account-unlock-registry-v1", "1", body.anchor.origin, body.anchor.account_id,
    body.anchor.genesis_hash, body.revision, body.previous_digest, body.membership_head,
    body.authorization_epoch, body.author, body.recovery.signing, body.recovery.encryption,
    String(slots.length), ...slots]);
}
export async function unlockDigest(value: SignedUnlock): Promise<string> {
  if (!exactObject(value, ["body", "signature"])) invalid();
  decode(value.signature, 64, 64);
  return hash(canonical(["lunport-account-unlock-proof-v1", base64(unlockCanonical(value.body)), value.signature]));
}
/** CAS revision protects concurrent updates; unchanged slots need no old passkey secret to keep. */
export async function verifyUnlockUpdate(
  member: TrustedMembership, before: SignedUnlock | null, after: SignedUnlock, epoch: number, actor: string,
): Promise<boolean> {
  try {
    if (!exactObject(after, ["body", "signature"])) return false;
    const b = after.body, bytes = unlockCanonical(b), author = member.devices[actor];
    if (!author || !sameAnchor(b.anchor, member.anchor) || b.membership_head !== member.head || b.author !== actor ||
        safeNumber(b.authorization_epoch, false) !== epoch || b.recovery.signing !== member.recovery.signing ||
        b.recovery.encryption !== member.recovery.encryption ||
        safeNumber(b.revision, false) !== (before ? safeNumber(before.body.revision, false) : 0) + 1 ||
        b.previous_digest !== (before ? await unlockDigest(before) : "")) return false;
    const sameAuthority = before?.body.recovery.signing === b.recovery.signing && before?.body.recovery.encryption === b.recovery.encryption;
    for (const envelope of b.slots) {
      if (envelope.header.generation === b.revision) continue;
      const old = sameAuthority && before?.body.slots.find((slot) => slotId(slot) === slotId(envelope));
      if (!old || base64(envelopeCanonical(old)) !== base64(envelopeCanonical(envelope))) return false;
    }
    return verify(author.signing, bytes, after.signature);
  } catch { return false; }
}
