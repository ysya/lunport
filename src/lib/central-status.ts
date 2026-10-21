import type { CentralStatus } from "./central-sync";

/** One public summary for Sync, Keys and the workspace status bar. */
export function syncSummary(s: CentralStatus | undefined) {
  if (!s) return { text: "Checking sync status…", action: "Open sync", ready: false };
  if (!s.available || !s.configured) return { text: "Local library · Sync is optional", action: "Set up sync", ready: false };
  if (s.login_pending) return { text: "Waiting for browser sign-in…", action: "Open sync", ready: false };
  if (s.phase === "revoked") return { text: "This device’s access was revoked", action: "Review device access", ready: false };
  if (s.replacement_pending) return { text: "Device replacement needs attention", action: "Review recovery", ready: false };
  if (s.needs_recovery) return { text: "Reconnect this device to unlock sync", action: "Review recovery", ready: false };
  if (s.needs_reconciliation) return { text: "Restored history needs review", action: "Review history", ready: false };
  if (!s.has_session || s.phase === "signed_out") return { text: "Sign in to resume sync", action: "Sign in", ready: false };
  if (s.phase === "rekey") return { text: "Finishing encryption key rotation…", action: "Review sync", ready: false };
  if (s.connecting) return { text: "Unlocking and connecting this device…", action: "Open sync", ready: false };
  if (s.phase === "setup" || s.phase === "backup_required") return { text: "Create your sync password", action: "Set password", ready: false };
  if (s.phase === "awaiting_approval") return { text: "Unlock your library to sync", action: "Unlock", ready: false };
  if (s.conflicts) return { text: `${s.conflicts} sync ${s.conflicts === 1 ? "conflict needs" : "conflicts need"} review`, action: "Review conflicts", ready: false };
  if (s.cooldown_seconds) return { text: "Sync paused by server · Changes saved locally", action: "View waiting time", ready: false };
  if (s.error) return { text: "Sync interrupted · Changes saved locally", action: "Review sync", ready: false };
  if (s.syncing || s.phase === "enrolled") return { text: "Syncing encrypted library…", action: "Open sync", ready: false };
  if (s.pending) return { text: `${s.pending} changes saved, waiting to sync`, action: "Sync now", ready: s.can_sync };
  return { text: s.automatic_sync ? "Automatic encrypted sync" : "Encrypted library connected", action: "Sync now", ready: s.can_sync };
}

export function syncProblem(message: string) {
  const value = message.toLowerCase();
  if (value.includes("cooldown") || value.includes("429")) return "The server has paused requests. Your changes are saved locally; sync will resume after the waiting period.";
  if (value.includes("account changed") || value.includes("different account") || value.includes("account mismatch")) return "The account selection changed. Refresh the account or sign in with this library’s account. Use a separate library for a different account.";
  if (value.includes("password") && (value.includes("incorrect") || value.includes("invalid") || value.includes("unlock"))) return "Could not unlock the library. Check the sync password created on your first device.";
  if (value.includes("sign in") || value.includes("sign-in") || value.includes("unauthorized") || value.includes("expired")) return "Sign in again to renew access. Local changes are retained.";
  if (value.includes("protocol") || value.includes("unsupported") || value.includes("incompatible")) return "The app could not verify the server’s sync data. Check that the app and server are up to date, then refresh the account.";
  return "Could not complete sync. Your local library is retained. Check the connection and server, then retry.";
}

/** Native observations are ordered within one process; no timestamp or persistent authority. */
export function newerCentralStatus(previous: CentralStatus | undefined, incoming: CentralStatus): CentralStatus {
  if (previous?.observation && incoming.observation && BigInt(previous.observation) > BigInt(incoming.observation)) return previous;
  return incoming;
}
