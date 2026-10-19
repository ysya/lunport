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
  replacement_pending: boolean;
  can_sync: boolean;
  pending: number;
  conflicts: number;
  error: string | null;
};
export const centralStatusKey = ["central-account-status"] as const;
export const centralStatus = () => tauriInvoke<CentralStatus>("central_status");
export const centralSignIn = (service: string, method?: "passkey" | "oidc") =>
  tauriInvoke<CentralStatus>("central_sign_in", {
    service,
    ...(method ? { method } : {}),
  });
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

export type CentralRevokeResult = {
  status: CentralStatus;
  access_revoked: boolean;
  rekey_pending: boolean;
  barrier_pending: boolean;
};
export const centralRevokeDevice = (
  device: CentralDevice,
  registry: CentralDeviceRegistry,
) =>
  tauriInvoke<CentralRevokeResult>("central_revoke_device", {
    device: device.id,
    membershipHead: registry.membership_head,
    authorizationEpoch: registry.authorization_epoch,
    fingerprint: device.fingerprint,
  });

export type CentralAccountDevice = {
  id: string;
  name: string;
  created_at_ms: string;
  state: "active" | "pending" | "revoked";
  current: boolean;
};
export type CentralAccountAccess = {
  authorization_epoch: string;
  barrier_pending: boolean;
  devices: CentralAccountDevice[];
};
export const centralAccountAccessKey = (status: CentralStatus) =>
  [
    "central-account-access",
    status.service,
    status.account_id,
    status.device_id,
    status.root_fingerprint,
    status.authorization_epoch,
    status.phase,
  ] as const;
export const centralAccountAccess = () =>
  tauriInvoke<CentralAccountAccess>("central_account_access");
export const centralRevokeAccountDevice = (selection: {
  device: string;
  authorization_epoch: string;
  created_at_ms: string;
}) =>
  tauriInvoke<CentralRevokeResult>("central_revoke_account_device", {
    selection,
  });

export type CentralRecoveryProgress = {
  phase:
    | "idle"
    | "reading"
    | "backup_required"
    | "submitted"
    | "cleanup_required"
    | "complete";
  operation: string | null;
  backup_confirmed: boolean;
  verified: number;
  total: number;
  root_fingerprint: string | null;
};
export const centralRecoveryKey = (status: CentralStatus) =>
  [
    "central-recovery",
    status.service,
    status.account_id,
    status.device_id,
    status.root_fingerprint,
    status.authorization_epoch,
    status.phase,
  ] as const;
export const centralRecoveryStatus = () =>
  tauriInvoke<CentralRecoveryProgress>("central_recovery_status");
// Kit inputs and reveal responses are passed directly; neither belongs in a query/mutation cache.
export const centralBeginAccountRecovery = (kit: string) =>
  tauriInvoke<CentralRecoveryProgress>("central_begin_account_recovery", {
    kit,
  });
export const centralRevalidateAccountRecovery = (kit: string | null) =>
  tauriInvoke<CentralRecoveryProgress>("central_revalidate_account_recovery", {
    kit,
  });
export const centralAdvanceAccountRecovery = () =>
  tauriInvoke<CentralRecoveryProgress>("central_advance_account_recovery");
export const centralCancelAccountRecovery = () =>
  tauriInvoke<void>("central_cancel_account_recovery");
export const centralRevealNewRecovery = () =>
  tauriInvoke<{ root: string; kit: string }>("central_reveal_new_recovery");
export const centralConfirmAccountRecovery = (operation: string) =>
  tauriInvoke<CentralRecoveryProgress>("central_confirm_account_recovery", {
    operation,
  });
