/** Opaque root confirmation tag. Only paired clients possess its secret and can verify it. */
import { decode, exactObject, hex } from "./protocol";
export type PairingConfirmation = {
  request_id: string;
  approved_head: string;
  mac: string;
};
export function validConfirmation(
  value: unknown,
  request: string,
  head: string,
): value is PairingConfirmation {
  try {
    return (
      exactObject(value, ["request_id", "approved_head", "mac"]) &&
      value.request_id === request &&
      hex(value.request_id, 32) &&
      value.approved_head === head &&
      hex(value.approved_head, 64) &&
      decode(value.mac, 32, 32).length === 32
    );
  } catch {
    return false;
  }
}
