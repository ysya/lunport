import { tauriInvoke } from "@/lib/ipc";
export type CentralStatus = {
  available: boolean;
  configured: boolean;
  phase:
    | "setup"
    | "awaiting_approval"
    | "backup_required"
    | "enrolled"
    | "active"
    | "rekey"
    | "revoked"
    | "signed_out";
  service: string | null;
  account_id: string | null;
  device_id: string | null;
  root_fingerprint: string | null;
  membership_head: string | null;
  authorization_epoch: string | null;
  has_session: boolean;
  login_pending: boolean;
  needs_recovery: boolean;
  can_sync: boolean;
  pending: number;
  conflicts: number;
  error: string | null;
};
export const centralStatusKey = ["central-account-status"] as const;
export const centralStatus = () => tauriInvoke<CentralStatus>("central_status");
export const centralSignIn = (service: string) =>
  tauriInvoke<CentralStatus>("central_sign_in", { service });
export const centralCancelSignIn = () =>
  tauriInvoke<void>("central_cancel_sign_in");
export const centralRefresh = () =>
  tauriInvoke<CentralStatus>("central_refresh");
export const centralSignOut = () =>
  tauriInvoke<CentralStatus>("central_sign_out");
export const centralPrepareVault = () =>
  tauriInvoke<CentralStatus>("central_prepare_vault");
// A dedicated reveal result stays in component memory, never React Query or a mutation cache.
export const centralRevealRecovery = () =>
  tauriInvoke<{ root: string; kit: string }>("central_reveal_recovery");
export const centralConfirmRecovery = (root: string) =>
  tauriInvoke<CentralStatus>("central_confirm_recovery", { root });

export type CentralDevice = {
  id: string;
  name: string;
  state: "approved" | "pending" | "revoked" | "access_blocked";
  fingerprint: string;
  current: boolean;
};
export type CentralDeviceRegistry = {
  membership_head: string;
  authorization_epoch: string;
  devices: CentralDevice[];
};
export const centralDevicesKey = (status: CentralStatus) =>
  [
    "central-devices",
    status.account_id,
    status.device_id,
    status.membership_head,
    status.authorization_epoch,
  ] as const;
export const centralDevices = () =>
  tauriInvoke<CentralDeviceRegistry>("central_devices");
export const centralPairingCode = () =>
  tauriInvoke<{ code: string; expires_at_ms: string }>("central_pairing_code");
export const centralApproveDevice = (code: string) =>
  tauriInvoke<CentralStatus>("central_approve_device", { code });
