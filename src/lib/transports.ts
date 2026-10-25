import { tauriInvoke } from "./ipc";
import type { RecordOverview } from "./records";
import type { HostTransport } from "@/bindings/HostTransport";
import type { TransportKind } from "@/bindings/TransportKind";
import type { PamCheck } from "@/bindings/PamCheck";
import type { OsLoginProfileView } from "@/bindings/OsLoginProfileView";
export type { HostTransport, TransportKind, PamCheck, OsLoginProfileView };

/** A placeholder for the PAM entitlements field, never a default: Lunport is a public product. */
export const pamPlaceholder = "prod-operate, prod-admin";

export const saveTransport = (transport: HostTransport, expected: HostTransport | null) =>
  tauriInvoke<RecordOverview>("transports_save", { transport, expected });
export const deleteTransport = (expected: HostTransport) => tauriInvoke<RecordOverview>("transports_delete", { expected });
export const fetchOsLoginProfile = (account: string | null, project: string, keyId: string | null) =>
  tauriInvoke<OsLoginProfileView>("transports_oslogin_profile", { account, project, keyId });

export function newIapTransport(hostId: string): HostTransport {
  return { host_id: hostId, kind: { type: "gcp_iap", project: "", zone: "", instance: "", interface: "nic0", account: null, os_login: true, pam: null } };
}

export function transportFor(overview: RecordOverview, hostId: string | null): HostTransport | null {
  if (!hostId) return null;
  return overview.transports?.find((transport) => transport.host_id === hostId) ?? null;
}

export function transportLabel(transport: HostTransport): string {
  const kind = transport.kind;
  return `Google Cloud IAP · ${kind.project} / ${kind.zone} / ${kind.instance}`;
}

const resourceName = /^[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?$/;
const isResourceName = (value: string) => resourceName.test(value) && !value.endsWith("-");
const isProject = (value: string) =>
  /^[0-9]{6,20}$/.test(value) || (value.length >= 6 && value.length <= 30 && /^[a-z][a-z0-9-]*[a-z0-9]$/.test(value));
const isEmail = (value: string) =>
  value.length <= 254 && /^[^\s@\u0000-\u001f\u007f]+@[^\s@.\u0000-\u001f\u007f][^\s@\u0000-\u001f\u007f]*\.[^\s@\u0000-\u001f\u007f]+$/.test(value);

/** The same rules and sentences as the backend's `HostTransport::validate`, so the Save button and the backend agree. */
export function transportProblem(transport: HostTransport): string | null {
  const kind = transport.kind;
  if (!isProject(kind.project)) return "Enter the Google Cloud project id.";
  if (!isResourceName(kind.zone)) return "Enter the zone of the instance.";
  if (!isResourceName(kind.instance)) return "Enter the instance name.";
  if (!/^nic[0-7]$/.test(kind.interface)) return "Enter a network interface such as nic0.";
  if (kind.account !== null && !isEmail(kind.account)) return "Enter the Google account as an email address.";
  if (kind.pam) {
    if (kind.pam.entitlements.length === 0) return "Enter at least one PAM entitlement.";
    if (kind.pam.entitlements.length > 8) return "Enter at most 8 PAM entitlements.";
    if (!kind.pam.entitlements.every(isResourceName)) return "Enter PAM entitlement ids such as prod-operate.";
    if (!isResourceName(kind.pam.location)) return "Enter the PAM location, such as global.";
  }
  return null;
}
