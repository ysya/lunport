import { tauriInvoke } from "@/lib/ipc";
import type { HostTransport } from "@/bindings/HostTransport";
import type { TunnelRule } from "@/bindings/TunnelRule";
import type { HostScope } from "@/lib/records";
export type CentralStatus = {
  observation?: string;
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
  account_authenticated?: boolean;
  login_pending: boolean;
  needs_recovery: boolean;
  reconnect_available?: boolean;
  replacement_pending: boolean;
  needs_reconciliation: boolean;
  can_sync: boolean;
  pending: number;
  conflicts: number;
  error: string | null;
  cooldown_seconds?: number;
  syncing?: boolean;
  connecting?: boolean;
  automatic_sync?: boolean;
};
export const centralServerCapabilities = (service: string) =>
  tauriInvoke<{ passkey: boolean; oidc: boolean }>("central_server_capabilities", { service });
export const centralStatusKey = ["central-account-status"] as const;
export const centralStatus = () => tauriInvoke<CentralStatus>("central_status");
export const centralSignIn = (service: string, method?: "passkey" | "oidc") =>
  tauriInvoke<CentralStatus>("central_sign_in", {
    service,
    ...(method ? { method } : {}),
  });
export const centralChangeServer = (service: string) =>
  tauriInvoke<void>("central_change_server", { service });
export const centralCancelSignIn = () =>
  tauriInvoke<void>("central_cancel_sign_in");
export const centralRefresh = () =>
  tauriInvoke<CentralStatus>("central_refresh");
export const centralSignOut = () =>
  tauriInvoke<CentralStatus>("central_sign_out");
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

export type AutomaticSyncProgress = {
  phase: "signed_out" | "sign_in_required" | "password_setup" | "password_unlock" | "password_recovery" | "connecting" | "syncing" | "ready" | "needs_attention";
  status: CentralStatus;
};
export const automaticSyncKey = ["central-automatic-sync"] as const;
export const centralAutomaticStatus = () => tauriInvoke<AutomaticSyncProgress>("central_automatic_status");
export const centralAutomaticStart = () => tauriInvoke<AutomaticSyncProgress>("central_automatic_start");
export const centralAutomaticStep = () => tauriInvoke<AutomaticSyncProgress>("central_automatic_step");
// Password stays in the form/call only; never put it in a Query or mutation cache.
export const centralUnlockPassword = (password: string) => tauriInvoke<AutomaticSyncProgress>("central_unlock_password", { password });

/** An item of the shared Catalog that this device and another changed differently (design 2026-10-27); `null` where that side removed it or never had it. */
export type CatalogCollision =
  | { kind: "tunnel"; id: string; local: TunnelRule | null; remote: TunnelRule | null }
  | { kind: "route"; host_id: string; local: HostTransport | null; remote: HostTransport | null }
  | { kind: "collection"; id: string; local: string | null; remote: string | null }
  | { kind: "group_order"; scope: HostScope; local: string[] | null; remote: string[] | null }
  | { kind: "pam_scope"; id: string; local: import("@/bindings/PamScope").PamScope | null; remote: import("@/bindings/PamScope").PamScope | null };
/** The Catalog's review: its colliding items, which choice fits, and why none does (`over`). Without items the merge waits for the next sync. */
export type CatalogReview = { items: CatalogCollision[]; over: string | null; can_local: boolean; can_remote: boolean };
export type CentralConflict = { id: string; token: string; kind: string; name: string; local: Record<string, unknown> | null; remote: Record<string, unknown> | null; local_deleted: boolean; remote_deleted: boolean; remote_revision: string; can_resolve: boolean; can_remote: boolean; can_copy: boolean; catalog: CatalogReview | null };
export const centralConflicts = () => tauriInvoke<CentralConflict[]>("central_conflicts");
export const centralResolveConflict = (row: CentralConflict, choice: "local" | "remote" | "copy_remote", copyAlias?: string) =>
  tauriInvoke<CentralStatus>("central_conflict_resolve", { id: row.id, token: row.token, choice, copyAlias: copyAlias ?? null });
