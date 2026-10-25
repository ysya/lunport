import { tauriInvoke } from "./ipc";
import type { HostPayload, RecordHostView, RecordOverview } from "./records";
import type { HostTransport } from "@/bindings/HostTransport";
import type { TransportKind } from "@/bindings/TransportKind";
import type { PamCheck } from "@/bindings/PamCheck";
import type { OsLoginProfileView } from "@/bindings/OsLoginProfileView";
import type { PamStatusView } from "@/bindings/PamStatusView";
export type { HostTransport, TransportKind, PamCheck, OsLoginProfileView, PamStatusView };

/** A placeholder for the PAM entitlements field, never a default: Lunport is a public product. */
export const pamPlaceholder = "prod-operate, prod-admin";

export const saveTransport = (transport: HostTransport, expected: HostTransport | null) =>
  tauriInvoke<RecordOverview>("transports_save", { transport, expected });
export const deleteTransport = (expected: HostTransport) => tauriInvoke<RecordOverview>("transports_delete", { expected });
export const fetchOsLoginProfile = (account: string | null, project: string, keyId: string | null) =>
  tauriInvoke<OsLoginProfileView>("transports_oslogin_profile", { account, project, keyId });
export const fetchPamStatus = (hostId: string) => tauriInvoke<PamStatusView>("transports_pam_status", { hostId });
export const requestPamGrant = (hostId: string, justification: string, durationSecs: number) =>
  tauriInvoke<PamStatusView>("transports_pam_request", { hostId, justification, durationSecs });

const hhmm = (ms: number) => {
  const at = new Date(ms);
  return `${String(at.getHours()).padStart(2, "0")}:${String(at.getMinutes()).padStart(2, "0")}`;
};

/** One line about a transport's PAM grant (design 2026-10-25): which entitlement holds it and until when, on this computer's clock, or why there is none. */
export function pamStatusLine(view: PamStatusView): string {
  switch (view.state) {
    case "active":
      return `${view.entitlement ?? "grant"} · active${view.active_until_ms === null ? "" : ` until ${hhmm(view.active_until_ms)}`}`;
    case "activating":
      return `${view.entitlement ?? "grant"} · activating…`;
    case "error":
      return view.message ?? "The grant could not be checked.";
    default:
      return "no active grant";
  }
}

export function newIapTransport(hostId: string): HostTransport {
  return { host_id: hostId, kind: { type: "gcp_iap", project: "", zone: "", instance: "", interface: "nic0", account: null, os_login: true, pam: null } };
}

export function transportFor(overview: RecordOverview, hostId: string | null): HostTransport | null {
  if (!hostId) return null;
  return overview.transports?.find((transport) => transport.host_id === hostId) ?? null;
}

/** What the Use OS Login username button does with the profile it fetched: the username to save, a note about the key, or why not. */
export function osLoginOutcome(view: OsLoginProfileView): { username: string | null; note: string | null; error: string | null } {
  if (!view.username)
    return { username: null, note: null, error: `OS Login has no POSIX account for ${view.account} in this project; the project may not have OS Login enabled.` };
  return {
    username: view.username,
    note: view.key_registered === false ? "This key is not registered with OS Login yet; it is registered at the first connection." : null,
    error: null,
  };
}

/**
 * What the Use OS Login username button writes into `host` for the profile it fetched: the payload to save (`null` when the connection
 * already uses that username, or when nothing may be written), the note to show, or why not. The comparison is with the username the
 * connection uses (the effective payload); a host that inherits its username from its Group is left alone, since its own field is not
 * what the connection uses.
 */
export function osLoginUsernameUpdate(host: RecordHostView, view: OsLoginProfileView): { payload: HostPayload | null; note: string | null; error: string | null } {
  const outcome = osLoginOutcome(view);
  if (!outcome.username) return { payload: null, note: null, error: outcome.error };
  if (host.payload.inherit?.includes("user"))
    return { payload: null, note: null, error: "This host takes its username from its Group; change it there, or stop inheriting it in the host editor." };
  const note = [`Username: ${outcome.username}.`, outcome.note].filter(Boolean).join(" ");
  if (host.effective_payload.user === outcome.username) return { payload: null, note, error: null };
  return { payload: { ...host.payload, user: outcome.username, host_key: null }, note, error: null };
}

export function transportLabel(transport: HostTransport): string {
  const kind = transport.kind;
  return `Google Cloud IAP · ${kind.project} / ${kind.zone} / ${kind.instance}`;
}

const resourceName = /^[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?$/;
const isResourceName = (value: string) => resourceName.test(value) && !value.endsWith("-");
const isProject = (value: string) =>
  /^[0-9]{6,20}$/.test(value) || (value.length >= 6 && value.length <= 30 && /^[a-z][a-z0-9-]*[a-z0-9]$/.test(value));
/** The backend's rule: the account names a directory under gcloud's config, so only the characters an address and a directory name share. */
const isEmail = (value: string) => {
  const at = value.indexOf("@");
  if (at <= 0 || value.length > 254) return false;
  const labels = value.slice(at + 1).split(".");
  return /^[A-Za-z0-9._%+'-]+$/.test(value.slice(0, at)) && labels.length >= 2 && labels.every((label) => /^[A-Za-z0-9-]+$/.test(label));
};

/** The entitlements field as typed, split on commas; the text itself stays in the field so a comma can be typed. */
export const parseEntitlements = (text: string): string[] => text.split(",").map((entry) => entry.trim()).filter(Boolean);

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
    const { duration_secs: duration, justification } = kind.pam;
    if (duration < 60 || duration > 480 * 60 || duration % 60 !== 0) return "Enter a grant duration between 1 and 480 minutes.";
    if (justification !== null && ([...justification].length > 512 || /[\u0000-\u001f\u007f]/.test(justification)))
      return "Keep the justification under 512 characters on one line.";
  }
  return null;
}

/** A PAM check as the checkbox starts it: no entitlement yet, the global location, a 30-minute grant, nothing to say yet. */
export const newPamCheck = (): PamCheck => ({ entitlements: [], location: "global", duration_secs: 30 * 60, justification: null });
