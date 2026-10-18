/** Opaque root/data confirmation tag. Only paired clients possess its secret and can verify it. */
import { decode, exactObject, hex, safeNumber } from "./protocol";
export type VaultMinimum = {
  vault: string;
  creation_head: string;
  creation_authorization_epoch: string;
  key_epoch: string;
  sequence: string;
  history_hash: string;
};
export type PairingConfirmation = {
  request_id: string;
  approved_head: string;
  personal_vault: string;
  minimums: VaultMinimum[];
  mac: string;
};
function validMinimum(value: unknown): value is VaultMinimum {
  const fields = [
    "vault",
    "creation_head",
    "creation_authorization_epoch",
    "key_epoch",
    "sequence",
    "history_hash",
  ];
  if (
    !exactObject(value, fields) ||
    fields.some((f) => typeof value[f] !== "string") ||
    !hex(value.vault, 64) ||
    !hex(value.creation_head, 64) ||
    !hex(value.history_hash, 64)
  )
    return false;
  return (
    safeNumber(value.creation_authorization_epoch, false) > 0 &&
    safeNumber(value.key_epoch, false) <= 65 &&
    safeNumber(value.sequence, true) <= 16384 &&
    (value.sequence !== "0" || value.history_hash === "0".repeat(64))
  );
}
export function validConfirmation(
  value: unknown,
  request: string,
  head: string,
  vaults: Record<string, { epoch: number }>,
  authorizationEpoch: number,
): value is PairingConfirmation {
  try {
    if (
      !exactObject(value, [
        "request_id",
        "approved_head",
        "personal_vault",
        "minimums",
        "mac",
      ]) ||
      value.request_id !== request ||
      !hex(value.request_id, 32) ||
      value.approved_head !== head ||
      !hex(value.approved_head, 64) ||
      !hex(value.personal_vault, 64) ||
      !Array.isArray(value.minimums) ||
      value.minimums.length < 1 ||
      value.minimums.length > 64 ||
      decode(value.mac, 32, 32).length !== 32
    )
      return false;
    const seen = new Set<string>();
    for (const minimum of value.minimums) {
      if (
        !validMinimum(minimum) ||
        seen.has(minimum.vault) ||
        !vaults[minimum.vault] ||
        safeNumber(minimum.key_epoch, false) !== vaults[minimum.vault].epoch ||
        safeNumber(minimum.creation_authorization_epoch, false) >
          authorizationEpoch
      )
        return false;
      seen.add(minimum.vault);
    }
    return (
      seen.has(value.personal_vault) && seen.size === Object.keys(vaults).length
    );
  } catch {
    return false;
  }
}
