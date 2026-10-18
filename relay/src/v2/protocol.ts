import { ed25519 } from "@noble/curves/ed25519.js";
/** Fixed protocol encodings shared with Rust. Keys here must come from verified membership,
 * never a public key supplied alongside the record being verified. No content decryption. */
const encoder = new TextEncoder();
const MAX_RECORD = 64 * 1024;
export type RecordHeader = {
  origin: string;
  account_id: string;
  genesis_hash: string;
  vault_id: string;
  record_id: string;
  key_epoch: string;
  membership_head: string;
  author: string;
  operation_id: string;
  expected_revision: string;
  kind: string;
  deleted: boolean;
};
export type WrapHeader = {
  origin: string;
  account_id: string;
  genesis_hash: string;
  vault_id: string;
  key_epoch: string;
  membership_head: string;
  recipient: string;
  recipient_key: string;
  author: string;
};
export type RecordEnvelope = {
  header: RecordHeader;
  nonce: string;
  ciphertext: string;
  signature: string;
};
export type WrappedKeys = {
  header: WrapHeader;
  encapsulated_key: string;
  ciphertext: string;
  signature: string;
};
const recordFields = [
  "origin",
  "account_id",
  "genesis_hash",
  "vault_id",
  "record_id",
  "key_epoch",
  "membership_head",
  "author",
  "operation_id",
  "expected_revision",
  "kind",
  "deleted",
] as const;
const wrapFields = [
  "origin",
  "account_id",
  "genesis_hash",
  "vault_id",
  "key_epoch",
  "membership_head",
  "recipient",
  "recipient_key",
  "author",
] as const;
function invalid(): never {
  throw new Error("Invalid central sync protocol data.");
}
export function exactObject(
  value: unknown,
  fields: readonly string[],
): value is Record<string, unknown> {
  return (
    value !== null &&
    typeof value === "object" &&
    !Array.isArray(value) &&
    Object.keys(value).length === fields.length &&
    Object.keys(value).every((field) => fields.includes(field))
  );
}
export function hex(value: unknown, length: number): value is string {
  return (
    typeof value === "string" &&
    value.length === length &&
    /^[0-9a-f]+$/.test(value)
  );
}
export function safeNumber(value: unknown, zero: boolean): number {
  if (typeof value !== "string" || !/^(0|[1-9][0-9]{0,15})$/.test(value))
    invalid();
  const n = Number(value);
  if (!Number.isSafeInteger(n) || (!zero && n === 0)) invalid();
  return n;
}
export function validOrigin(
  value: unknown,
  allowLoopback = false,
): value is string {
  if (typeof value !== "string") return false;
  try {
    const url = new URL(value);
    return (
      url.origin === value &&
      !url.username &&
      !url.password &&
      (url.protocol === "https:" ||
        (allowLoopback &&
          url.protocol === "http:" &&
          ["127.0.0.1", "[::1]", "localhost"].includes(url.hostname)))
    );
  } catch {
    return false;
  }
}
export function base64(bytes: Uint8Array): string {
  let binary = "";
  for (let i = 0; i < bytes.length; i += 8192)
    binary += String.fromCharCode(...bytes.subarray(i, i + 8192));
  return btoa(binary);
}
export function decode(
  value: unknown,
  minimum: number,
  maximum: number,
): Uint8Array {
  if (typeof value !== "string" || value.length > Math.ceil(maximum / 3) * 4)
    invalid();
  let bytes: Uint8Array;
  try {
    bytes = Uint8Array.from(atob(value), (c) => c.charCodeAt(0));
  } catch {
    return invalid();
  }
  if (
    bytes.length < minimum ||
    bytes.length > maximum ||
    base64(bytes) !== value
  )
    invalid();
  return bytes;
}
export function canonical(fields: readonly string[]): Uint8Array {
  return encoder.encode(JSON.stringify(fields));
}
export function recordCanonical(
  header: RecordHeader,
  allowLoopback = false,
): Uint8Array {
  if (
    !exactObject(header, recordFields) ||
    recordFields.some(
      (f) => f !== "deleted" && typeof header[f] !== "string",
    ) ||
    typeof header.deleted !== "boolean" ||
    !validOrigin(header.origin, allowLoopback) ||
    ![
      header.account_id,
      header.genesis_hash,
      header.vault_id,
      header.record_id,
      header.membership_head,
    ].every((value) => hex(value, 64)) ||
    !hex(header.author, 32) ||
    !hex(header.operation_id, 32) ||
    !["host", "group", "keyslot", "key", "meta"].includes(header.kind)
  )
    invalid();
  safeNumber(header.key_epoch, false);
  safeNumber(header.expected_revision, true);
  return canonical([
    "lunport-record-v2",
    header.origin,
    header.account_id,
    header.genesis_hash,
    header.vault_id,
    header.record_id,
    header.key_epoch,
    header.membership_head,
    header.author,
    header.operation_id,
    header.expected_revision,
    header.kind,
    header.deleted ? "1" : "0",
  ]);
}
export function wrapCanonical(
  header: WrapHeader,
  allowLoopback = false,
): Uint8Array {
  if (
    !exactObject(header, wrapFields) ||
    wrapFields.some((f) => typeof header[f] !== "string") ||
    !validOrigin(header.origin, allowLoopback) ||
    ![
      header.account_id,
      header.genesis_hash,
      header.vault_id,
      header.membership_head,
    ].every((value) => hex(value, 64)) ||
    (header.recipient !== "recovery" && !hex(header.recipient, 32)) ||
    !hex(header.author, 32)
  )
    invalid();
  safeNumber(header.key_epoch, false);
  decode(header.recipient_key, 32, 32);
  return canonical([
    "lunport-vault-wrap-v2",
    header.origin,
    header.account_id,
    header.genesis_hash,
    header.vault_id,
    header.key_epoch,
    header.membership_head,
    header.recipient,
    header.recipient_key,
    header.author,
  ]);
}
export async function hash(bytes: Uint8Array): Promise<string> {
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", bytes));
  return Array.from(digest, (b) => b.toString(16).padStart(2, "0")).join("");
}
export async function authorBytes(
  domain: string,
  header: Uint8Array,
  nonce: string,
  ciphertext: Uint8Array,
): Promise<Uint8Array> {
  return canonical([domain, base64(header), nonce, await hash(ciphertext)]);
}
export async function verify(
  trustedPublicKey: string,
  bytes: Uint8Array,
  signature: string,
): Promise<boolean> {
  try {
    const publicKey = decode(trustedPublicKey, 32, 32);
    const sig = decode(signature, 64, 64);
    // Match dalek verify_strict, including weak public keys and small-order R.
    // workerd native verification accepts the weak-key compatibility vector.
    if (
      ed25519.Point.fromBytes(publicKey).isSmallOrder() ||
      ed25519.Point.fromBytes(sig.subarray(0, 32)).isSmallOrder()
    )
      return false;
    return ed25519.verify(sig, bytes, publicKey, { zip215: false });
  } catch {
    return false;
  }
}
export async function verifyRecord(
  envelope: RecordEnvelope,
  trustedAuthor: string,
  allowLoopback = false,
): Promise<boolean> {
  try {
    if (!exactObject(envelope, ["header", "nonce", "ciphertext", "signature"]))
      return false;
    const header = recordCanonical(envelope.header, allowLoopback);
    decode(envelope.nonce, 24, 24);
    const ciphertext = decode(envelope.ciphertext, 16, MAX_RECORD + 16);
    return verify(
      trustedAuthor,
      await authorBytes(
        "lunport-record-author-v2",
        header,
        envelope.nonce,
        ciphertext,
      ),
      envelope.signature,
    );
  } catch {
    return false;
  }
}
export async function verifyWrap(
  wrapped: WrappedKeys,
  trustedAuthor: string,
  allowLoopback = false,
): Promise<boolean> {
  try {
    if (
      !exactObject(wrapped, [
        "header",
        "encapsulated_key",
        "ciphertext",
        "signature",
      ])
    )
      return false;
    const header = wrapCanonical(wrapped.header, allowLoopback);
    decode(wrapped.encapsulated_key, 32, 32);
    const ciphertext = decode(wrapped.ciphertext, 80, 80);
    return verify(
      trustedAuthor,
      await authorBytes(
        "lunport-wrap-author-v2",
        header,
        wrapped.encapsulated_key,
        ciphertext,
      ),
      wrapped.signature,
    );
  } catch {
    return false;
  }
}
