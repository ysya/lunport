/** Control history is public but signed. Only the locally anchored genesis establishes trust. */
import { ed25519 } from "@noble/curves/ed25519.js";
import {
  base64,
  canonical,
  decode,
  exactObject,
  hash,
  hex,
  safeNumber,
  validOrigin,
  verify,
  verifyRecord,
  verifyWrap,
  type RecordEnvelope,
  type WrappedKeys,
} from "./protocol";
export type PublicKeys = { signing: string; encryption: string };
export type Device = { id: string; keys: PublicKeys };
export type TrustAnchor = {
  origin: string;
  account_id: string;
  genesis_hash: string;
};
export type Genesis = {
  origin: string;
  account_id: string;
  nonce: string;
  first: Device;
  recovery: PublicKeys;
  device_signature: string;
  recovery_signature: string;
};
export type Enrollment = {
  origin: string;
  account_id: string;
  genesis_hash: string;
  request_id: string;
  device: Device;
  nonce: string;
  created_at_ms: string;
  expires_at_ms: string;
  signature: string;
};
export type Action = "add" | "unlock" | "revoke" | "recover" | "recovery";
export type MembershipBody = {
  origin: string;
  account_id: string;
  genesis_hash: string;
  revision: string;
  previous_head: string;
  author: string;
  action: Action;
  issued_at_ms: string;
  enrollment: Enrollment | null;
  devices: Record<string, PublicKeys>;
  recovery: PublicKeys;
};
export type SignedMembership = { body: MembershipBody; signature: string };
export type TrustedMembership = {
  anchor: TrustAnchor;
  revision: number;
  head: string;
  devices: Record<string, PublicKeys>;
  recovery: PublicKeys;
  seen_devices: Record<string, PublicKeys>;
  seen_recovery: PublicKeys[];
};
const encoder = new TextEncoder();
function invalid(): never {
  throw new Error("Invalid central membership data.");
}
export function validKeys(value: unknown): value is PublicKeys {
  try {
    if (!exactObject(value, ["signing", "encryption"])) return false;
    const key = decode(value.signing, 32, 32);
    if (ed25519.Point.fromBytes(key).isSmallOrder()) return false;
    return decode(value.encryption, 32, 32).some((b) => b !== 0);
  } catch {
    return false;
  }
}
function validDevice(value: unknown): value is Device {
  return (
    exactObject(value, ["id", "keys"]) &&
    hex(value.id, 32) &&
    validKeys(value.keys)
  );
}
const sameKeys = (a: PublicKeys, b: PublicKeys) =>
  a.signing === b.signing && a.encryption === b.encryption;
const overlaps = (a: PublicKeys, b: PublicKeys) =>
  a.signing === b.signing || a.encryption === b.encryption;
export function genesisCanonical(
  genesis: Genesis,
  allowLoopback = false,
): Uint8Array {
  if (
    !exactObject(genesis, [
      "origin",
      "account_id",
      "nonce",
      "first",
      "recovery",
      "device_signature",
      "recovery_signature",
    ]) ||
    !validOrigin(genesis.origin, allowLoopback) ||
    !hex(genesis.account_id, 64) ||
    !hex(genesis.nonce, 64) ||
    !validDevice(genesis.first) ||
    !validKeys(genesis.recovery) ||
    overlaps(genesis.first.keys, genesis.recovery)
  )
    invalid();
  return canonical([
    "lunport-genesis-v2",
    genesis.origin,
    genesis.account_id,
    genesis.nonce,
    genesis.first.id,
    genesis.first.keys.signing,
    genesis.first.keys.encryption,
    genesis.recovery.signing,
    genesis.recovery.encryption,
  ]);
}
export async function trustGenesis(
  genesis: Genesis,
  anchor: TrustAnchor,
  allowLoopback = false,
): Promise<TrustedMembership | null> {
  try {
    const bytes = genesisCanonical(genesis, allowLoopback);
    if (
      genesis.origin !== anchor.origin ||
      genesis.account_id !== anchor.account_id ||
      (await hash(bytes)) !== anchor.genesis_hash ||
      !(await verify(
        genesis.first.keys.signing,
        bytes,
        genesis.device_signature,
      )) ||
      !(await verify(
        genesis.recovery.signing,
        bytes,
        genesis.recovery_signature,
      ))
    )
      return null;
    const devices = { [genesis.first.id]: structuredClone(genesis.first.keys) };
    return {
      anchor: structuredClone(anchor),
      revision: 0,
      head: anchor.genesis_hash,
      devices,
      recovery: structuredClone(genesis.recovery),
      seen_devices: structuredClone(devices),
      seen_recovery: [structuredClone(genesis.recovery)],
    };
  } catch {
    return null;
  }
}
export function enrollmentCanonical(
  request: Enrollment,
  allowLoopback = false,
): Uint8Array {
  if (
    !exactObject(request, [
      "origin",
      "account_id",
      "genesis_hash",
      "request_id",
      "device",
      "nonce",
      "created_at_ms",
      "expires_at_ms",
      "signature",
    ]) ||
    !validOrigin(request.origin, allowLoopback) ||
    ![request.account_id, request.genesis_hash, request.nonce].every((v) =>
      hex(v, 64),
    ) ||
    !hex(request.request_id, 32) ||
    !validDevice(request.device)
  )
    invalid();
  const created = safeNumber(request.created_at_ms, false),
    expires = safeNumber(request.expires_at_ms, false);
  if (expires <= created || expires - created > 15 * 60 * 1000) invalid();
  return canonical([
    "lunport-enrollment-v2",
    request.origin,
    request.account_id,
    request.genesis_hash,
    request.request_id,
    request.device.id,
    request.device.keys.signing,
    request.device.keys.encryption,
    request.nonce,
    request.created_at_ms,
    request.expires_at_ms,
  ]);
}
export async function verifyEnrollment(
  request: Enrollment,
  now: number | null = null,
  allowLoopback = false,
): Promise<boolean> {
  try {
    const bytes = enrollmentCanonical(request, allowLoopback);
    if (
      now !== null &&
      (now > safeNumber(request.expires_at_ms, false) ||
        safeNumber(request.created_at_ms, false) > now + 5 * 60 * 1000)
    )
      return false;
    return verify(request.device.keys.signing, bytes, request.signature);
  } catch {
    return false;
  }
}
export function membershipCanonical(
  body: MembershipBody,
  allowLoopback = false,
): Uint8Array {
  if (
    !exactObject(body, [
      "origin",
      "account_id",
      "genesis_hash",
      "revision",
      "previous_head",
      "author",
      "action",
      "issued_at_ms",
      "enrollment",
      "devices",
      "recovery",
    ]) ||
    !validOrigin(body.origin, allowLoopback) ||
    ![body.account_id, body.genesis_hash, body.previous_head].every((v) =>
      hex(v, 64),
    ) ||
    (body.author !== "recovery" && !hex(body.author, 32)) ||
    !["add", "unlock", "revoke", "recover", "recovery"].includes(body.action) ||
    !validKeys(body.recovery) ||
    body.devices === null ||
    typeof body.devices !== "object" ||
    Array.isArray(body.devices) ||
    Object.keys(body.devices).length > 64
  )
    invalid();
  safeNumber(body.revision, false);
  safeNumber(body.issued_at_ms, false);
  const members = Object.keys(body.devices)
    .sort()
    .map((id) => {
      const keys = body.devices[id];
      if (!hex(id, 32) || !validKeys(keys)) invalid();
      return [id, keys.signing, keys.encryption];
    });
  const request =
    body.enrollment === null
      ? ""
      : base64(enrollmentCanonical(body.enrollment, allowLoopback));
  const requestSignature =
    body.enrollment === null ? "" : body.enrollment.signature;
  return encoder.encode(
    JSON.stringify([
      "lunport-membership-v2",
      body.origin,
      body.account_id,
      body.genesis_hash,
      body.revision,
      body.previous_head,
      body.author,
      body.action,
      body.issued_at_ms,
      request,
      requestSignature,
      members,
      body.recovery.signing,
      body.recovery.encryption,
    ]),
  );
}
export async function applyMembership(
  previous: TrustedMembership,
  next: SignedMembership,
  allowLoopback = false,
): Promise<TrustedMembership | null> {
  try {
    if (!exactObject(next, ["body", "signature"])) return null;
    const body = next.body,
      bytes = membershipCanonical(body, allowLoopback);
    if (
      body.origin !== previous.anchor.origin ||
      body.account_id !== previous.anchor.account_id ||
      body.genesis_hash !== previous.anchor.genesis_hash ||
      body.previous_head !== previous.head ||
      safeNumber(body.revision, false) !== previous.revision + 1
    )
      return null;
    const author =
      (body.action === "recover" || body.action === "unlock")
        ? body.author === "recovery"
          ? previous.recovery
          : null
        : previous.devices[body.author];
    if (!author || !(await verify(author.signing, bytes, next.signature)))
      return null;
    const retained = Object.entries(body.devices).every(
      ([id, keys]) =>
        previous.devices[id] && sameKeys(previous.devices[id], keys),
    );
    if (["add", "unlock", "recover"].includes(body.action)) {
      const request = body.enrollment;
      if (!request || !(await verifyEnrollment(request, null, allowLoopback)))
        return null;
      const issued = safeNumber(body.issued_at_ms, false);
      if (
        request.origin !== previous.anchor.origin ||
        request.account_id !== previous.anchor.account_id ||
        request.genesis_hash !== previous.anchor.genesis_hash ||
        issued < safeNumber(request.created_at_ms, false) ||
        issued > safeNumber(request.expires_at_ms, false) ||
        !body.devices[request.device.id] ||
        !sameKeys(body.devices[request.device.id], request.device.keys) ||
        previous.seen_devices[request.device.id] ||
        [
          ...Object.values(previous.seen_devices),
          ...previous.seen_recovery,
        ].some((keys) => overlaps(keys, request.device.keys))
      )
        return null;
      if (body.action === "add" || body.action === "unlock") {
        if (
          !sameKeys(body.recovery, previous.recovery) ||
          Object.keys(body.devices).length !==
            Object.keys(previous.devices).length + 1 ||
          Object.entries(previous.devices).some(
            ([id, keys]) =>
              !body.devices[id] || !sameKeys(body.devices[id], keys),
          )
        )
          return null;
      } else if (Object.keys(body.devices).length !== 1) return null;
    } else if (body.action === "revoke") {
      if (
        body.enrollment !== null ||
        !sameKeys(body.recovery, previous.recovery) ||
        !retained ||
        Object.keys(body.devices).length >= Object.keys(previous.devices).length
      )
        return null;
    } else if (
      body.enrollment !== null ||
      !sameKeysMap(body.devices, previous.devices) ||
      sameKeys(body.recovery, previous.recovery)
    )
      return null;
    const seenDevices = structuredClone(previous.seen_devices);
    if (body.enrollment)
      seenDevices[body.enrollment.device.id] = structuredClone(
        body.enrollment.device.keys,
      );
    const seenRecovery = structuredClone(previous.seen_recovery);
    if (!sameKeys(body.recovery, previous.recovery)) {
      if (
        [...Object.values(seenDevices), ...seenRecovery].some((keys) =>
          overlaps(keys, body.recovery),
        )
      )
        return null;
      seenRecovery.push(structuredClone(body.recovery));
    }
    return {
      anchor: structuredClone(previous.anchor),
      revision: previous.revision + 1,
      head: await hash(bytes),
      devices: structuredClone(body.devices),
      recovery: structuredClone(body.recovery),
      seen_devices: seenDevices,
      seen_recovery: seenRecovery,
    };
  } catch {
    return null;
  }
}
function sameKeysMap(
  a: Record<string, PublicKeys>,
  b: Record<string, PublicKeys>,
): boolean {
  return (
    Object.keys(a).length === Object.keys(b).length &&
    Object.entries(a).every(([id, keys]) => b[id] && sameKeys(keys, b[id]))
  );
}

/** Vault/epoch/actor come from the routed resource and authenticated device session. */
export async function verifyCurrentWrite(
  state: TrustedMembership,
  envelope: RecordEnvelope,
  vaultId: string,
  keyEpoch: number,
  actor: string,
  allowLoopback = false,
): Promise<boolean> {
  try {
    const h = envelope.header,
      author = state.devices[actor];
    return (
      !!author &&
      h.origin === state.anchor.origin &&
      h.account_id === state.anchor.account_id &&
      h.genesis_hash === state.anchor.genesis_hash &&
      h.vault_id === vaultId &&
      safeNumber(h.key_epoch, false) === keyEpoch &&
      h.membership_head === state.head &&
      h.author === actor &&
      (await verifyRecord(envelope, author.signing, allowLoopback))
    );
  } catch {
    return false;
  }
}
export async function verifyCurrentWrap(
  state: TrustedMembership,
  wrapped: WrappedKeys,
  vaultId: string,
  keyEpoch: number,
  allowLoopback = false,
): Promise<boolean> {
  try {
    const h = wrapped.header,
      author = state.devices[h.author],
      recipient =
        h.recipient === "recovery"
          ? state.recovery
          : state.devices[h.recipient];
    return (
      !!author &&
      !!recipient &&
      h.origin === state.anchor.origin &&
      h.account_id === state.anchor.account_id &&
      h.genesis_hash === state.anchor.genesis_hash &&
      h.vault_id === vaultId &&
      safeNumber(h.key_epoch, false) === keyEpoch &&
      h.membership_head === state.head &&
      h.recipient_key === recipient.encryption &&
      (await verifyWrap(wrapped, author.signing, allowLoopback))
    );
  } catch {
    return false;
  }
}
