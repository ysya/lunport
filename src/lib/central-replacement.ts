import { tauriInvoke } from "@/lib/ipc";
import type { CentralStatus } from "./central-sync";
export type ReplacementRoute = "trusted_device" | "recovery_kit";
/** Public concurrency metadata; it never authorizes decryption or a device switch by itself. */
export type ReplacementInvocation = {
  generation: string;
  scope: string;
  route: ReplacementRoute;
  operation: string | null;
};
export type ReplacementProgress = {
  phase:
    | "idle"
    | "paused"
    | "awaiting_approval"
    | "recovering"
    | "backup_required"
    | "submitted"
    | "cleanup_required"
    | "verification_required"
    | "reading"
    | "complete";
  operation: string | null;
  route: ReplacementRoute | null;
  verified: number;
  total: number;
  root_fingerprint: string | null;
  backup_confirmed: boolean;
  unresolved_archives: number;
};
export const replacementScope = (status: CentralStatus) =>
  JSON.stringify([
    status.service,
    status.account_id,
    status.device_id,
    status.root_fingerprint,
  ]);
export const replacementKey = (status: CentralStatus) =>
  ["central-replacement", replacementScope(status)] as const;
export const replacementStatus = () =>
  tauriInvoke<ReplacementProgress>("central_replacement_status");
// Only metadata reservations enter this queue. A previous component's delayed reservation must
// finish before a newer component reserves; secret input/reveal promises never enter this queue.
let reservations: Promise<void> = Promise.resolve();
export const reserveReplacement = (route: ReplacementRoute) => {
  const next = reservations.then(() =>
    tauriInvoke<ReplacementInvocation>("central_replacement_reserve", {
      route,
    }),
  );
  reservations = next.then(
    () => undefined,
    () => undefined,
  );
  return next;
};
export const startReplacement = (
  invocation: ReplacementInvocation,
  kit: string | null,
) =>
  tauriInvoke<ReplacementProgress>("central_replacement_start", {
    invocation,
    kit,
  });
export const continueReplacement = (
  invocation: ReplacementInvocation,
  operation: string,
) =>
  tauriInvoke<ReplacementProgress>("central_replacement_continue", {
    invocation,
    operation,
  });
export const revalidateReplacement = (
  invocation: ReplacementInvocation,
  operation: string,
  kit: string | null,
) =>
  tauriInvoke<ReplacementProgress>("central_replacement_revalidate", {
    invocation,
    operation,
    kit,
  });
export const cancelReplacement = (invocation: ReplacementInvocation) =>
  tauriInvoke<ReplacementProgress>("central_replacement_cancel", {
    invocation,
  });
// Dedicated reveals stay in ephemeral component state, never query/mutation caches.
export const revealReplacementPairing = (
  invocation: ReplacementInvocation,
  operation: string,
) =>
  tauriInvoke<{ code: string; expires_at_ms: string }>(
    "central_replacement_reveal_pairing",
    { invocation, operation },
  );
export const revealReplacementKit = (
  invocation: ReplacementInvocation,
  operation: string,
) =>
  tauriInvoke<{ root: string; kit: string }>("central_replacement_reveal_kit", {
    invocation,
    operation,
  });
export const confirmReplacement = (
  invocation: ReplacementInvocation,
  operation: string,
) =>
  tauriInvoke<ReplacementProgress>("central_replacement_confirm", {
    invocation,
    operation,
  });
