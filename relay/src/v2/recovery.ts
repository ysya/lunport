/** A kit-authenticated, read-only bridge grant. This is internal RPC data, never a caller principal. */
import {
  enrollmentCanonical,
  verifyEnrollment,
  type Enrollment,
  type TrustedMembership,
} from "./membership";
import { base64, canonical, exactObject, safeNumber, verify } from "./protocol";
export type RecoveryReadProof = {
  request_id: string;
  membership_head: string;
  auth_epoch: string;
  signature: string;
};
export type RecoveryReadGrant = {
  kind: "recovery_read";
  locator: string;
  account: string;
  device: string;
  epoch: number;
  head: string;
  expires: number;
};
export async function verifyRecoveryRead(
  state: TrustedMembership,
  request: Enrollment,
  proof: RecoveryReadProof,
  epoch: number,
  now: number,
): Promise<boolean> {
  try {
    if (
      !exactObject(proof, [
        "request_id",
        "membership_head",
        "auth_epoch",
        "signature",
      ]) ||
      proof.request_id !== request.request_id ||
      proof.membership_head !== state.head ||
      safeNumber(proof.auth_epoch, false) !== epoch ||
      request.origin !== state.anchor.origin ||
      request.account_id !== state.anchor.account_id ||
      request.genesis_hash !== state.anchor.genesis_hash ||
      !(await verifyEnrollment(request, now))
    )
      return false;
    const bytes = canonical([
      "lunport-recovery-read-v2",
      state.anchor.origin,
      state.anchor.account_id,
      state.anchor.genesis_hash,
      state.head,
      String(epoch),
      base64(enrollmentCanonical(request)),
      request.signature,
    ]);
    return verify(state.recovery.signing, bytes, proof.signature);
  } catch {
    return false;
  }
}
