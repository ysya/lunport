import { queryOptions } from "@tanstack/react-query";
import { tauriInvoke } from "./ipc";
import type { RecordOverview } from "./records";
import type { HostTransport } from "@/bindings/HostTransport";
import type { TransportKind } from "@/bindings/TransportKind";
import type { PamCheck } from "@/bindings/PamCheck";
import type { OsLoginProfileView } from "@/bindings/OsLoginProfileView";
import type { PamStatusView } from "@/bindings/PamStatusView";
import type { GcloudAccountsView } from "@/bindings/GcloudAccountsView";
import type { GrantMemoryView } from "@/bindings/GrantMemoryView";
import type { IapProbeView } from "@/bindings/IapProbeView";
import type { PamGrantView } from "@/bindings/PamGrantView";
export type { HostTransport, TransportKind, PamCheck, OsLoginProfileView, PamStatusView, GcloudAccountsView, GrantMemoryView, IapProbeView, PamGrantView };

/** A placeholder for the PAM entitlements field, never a default: Lunport is a public product. */
export const pamPlaceholder = "prod-operate, prod-admin";

export const fetchOsLoginProfile = (account: string | null, project: string, keyId: string | null) =>
  tauriInvoke<OsLoginProfileView>("transports_oslogin_profile", { account, project, keyId });
export const fetchPamStatus = (hostId: string) => tauriInvoke<PamStatusView>("transports_pam_status", { hostId });
/**
 * A host's Access grant as the details pane keeps it: read when the pane opens and again every minute while it stays open. A window
 * gaining focus does not read it again, since every read is a Google call. Not retried (the next minute reads it again), and read even
 * when the webview thinks it is offline, since the answer comes from this app's backend, which says in its own sentence when Google
 * cannot be reached.
 */
export const pamStatusQuery = (hostId: string) =>
  queryOptions({
    queryKey: ["gcp", "pam-status", hostId],
    queryFn: () => fetchPamStatus(hostId),
    refetchInterval: 60_000,
    refetchOnWindowFocus: false,
    retry: false,
    networkMode: "always",
  });
/** Requests a grant for the host's route and waits for it: on `entitlement`, which the route must list, else on the first it lists. */
export const requestPamGrant = (hostId: string, justification: string, durationSecs: number, entitlement?: string) =>
  tauriInvoke<PamStatusView>("transports_pam_request", {
    hostId,
    justification,
    durationSecs,
    ...(entitlement === undefined ? {} : { entitlement }),
  });
/** The Google accounts gcloud holds credentials for on this computer and whether each sign-in works. */
export const listGcloudAccounts = () => tauriInvoke<GcloudAccountsView>("gcp_accounts");
/** The query key of `listGcloudAccounts`, shared by every view of gcloud's accounts. */
export const gcloudAccountsKey = ["gcp", "accounts"] as const;
/**
 * `listGcloudAccounts` as the host editor's account picker and the Google Cloud page read it, from one cache entry. Each read checks
 * every sign-in with Google, so a minute-old answer is reused across mounts, switches and window focus. Not retried, and read even when
 * the webview thinks it is offline (a VPN or Wi-Fi switch), since the answer comes from this app's backend, which says in its own
 * sentence when Google cannot be reached: otherwise a computer with no cached answer would wait for the network and never show that
 * the sign-ins could not be checked.
 */
export const gcloudAccountsQuery = queryOptions({
  queryKey: gcloudAccountsKey,
  queryFn: listGcloudAccounts,
  retry: false,
  staleTime: 60_000,
  networkMode: "always",
});
/** One row per entitlement the saved routes require, with the state of the grant on it, read now. */
export const listPamGrants = () => tauriInvoke<PamGrantView[]>("gcp_pam_grants");
/** The query key of `listPamGrants`, for the Google Cloud page's Access grants. */
export const pamGrantsKey = ["gcp", "pam-grants"] as const;
/**
 * The Google Cloud page's Access grants: read when the section shows and again every minute while it stays open. As with
 * `pamStatusQuery`, a window gaining focus does not read it again (every read is a Google call for each entitlement), it is not retried
 * (the next minute reads it again), and it is read even when the webview thinks it is offline, since the answer comes from this app's
 * backend, which says in its own sentence when Google cannot be reached. The page turns it on only while a listed route requires a grant.
 */
export const pamGrantsQuery = queryOptions({
  queryKey: pamGrantsKey,
  queryFn: listPamGrants,
  refetchInterval: 60_000,
  refetchOnWindowFocus: false,
  retry: false,
  networkMode: "always",
});
/** Check through IAP: whether this computer reaches the host's instance through its route. It attempts no SSH. */
export const probeIap = (hostId: string) => tauriInvoke<IapProbeView>("transports_iap_probe", { hostId });

const hhmm = (ms: number) => {
  const at = new Date(ms);
  return `${String(at.getHours()).padStart(2, "0")}:${String(at.getMinutes()).padStart(2, "0")}`;
};

/** What a grant that could not be checked says in place of its state: the API's own sentence. */
const grantProblem = (grant: { message: string | null }) => grant.message ?? "The grant could not be checked.";

/** One line about a transport's PAM grant (design 2026-10-25): which entitlement holds it and until when, on this computer's clock, or why there is none. */
export function pamStatusLine(view: PamStatusView): string {
  switch (view.state) {
    case "active":
      return `${view.entitlement ?? "grant"} · active${view.active_until_ms === null ? "" : ` until ${hhmm(view.active_until_ms)}`}`;
    case "activating":
      return `${view.entitlement ?? "grant"} · activating…`;
    case "error":
      return grantProblem(view);
    default:
      return "no active grant";
  }
}

/** One line about a grant, as a row of the Google Cloud page or a host's details shows it. A grant in the `error` state shows its `message` instead; this line reads "No active grant" for it (see `grantStateOrMessage`). */
export function grantStateLine(grant: { state: string; active_until_ms: number | null }): string {
  switch (grant.state) {
    case "active":
      return grant.active_until_ms === null ? "Active" : `Active until ${hhmm(grant.active_until_ms)}`;
    case "activating":
      return "Activating…";
    default:
      return "No active grant";
  }
}

/**
 * What a row of the Google Cloud page and the details pane say of a grant they read: `grantStateLine`, except for a grant in the
 * `error` state, which has the API's own sentence (its `message`) instead of "No active grant", since it could not be checked.
 */
export function grantStateOrMessage(grant: { state: string; active_until_ms: number | null; message: string | null }): string {
  return grant.state === "error" ? grantProblem(grant) : grantStateLine(grant);
}

/** What a host's Access grant says of the grant it read: the entitlement holding it and its state, or why it could not be checked. */
export function grantLine(status: PamStatusView): string {
  const line = grantStateOrMessage(status);
  return status.state === "error" || !status.entitlement ? line : `${status.entitlement} · ${line}`;
}

/**
 * What a tunnel's row says of the grant its first hop needs (design 2026-10-26, Tunnels through a host that needs a grant): a grant
 * active or activating as the host's Access grant says it, the API's sentence when it could not be checked, and otherwise the
 * entitlements of the route's PAM check, any of which can hold one.
 */
export function tunnelGrantLine(status: PamStatusView, pam: PamCheck): string {
  return status.state === "active" || status.state === "activating" || status.state === "error"
    ? grantLine(status)
    : `Needs a grant: ${pam.entitlements.join(", ")}`;
}

export function newIapTransport(hostId: string): HostTransport {
  return { host_id: hostId, kind: { type: "gcp_iap", project: "", zone: "", instance: "", interface: "nic0", account: null, os_login: true, pam: null } };
}

export function transportFor(overview: RecordOverview, hostId: string | null): HostTransport | null {
  if (!hostId) return null;
  return overview.transports?.find((transport) => transport.host_id === hostId) ?? null;
}

/**
 * Whether the route of `hostId` syncs wherever the host does, or stays on this computer. A route says so itself (`transport_sync`); for a
 * host with no route yet, a new host included, it is whether a route saved now would sync, which is where the library uses central sync.
 */
export function routeSynced(overview: RecordOverview, hostId: string | null): boolean {
  const own = overview.transport_sync?.find((entry) => entry.host_id === hostId);
  return own ? own.synced : overview.central_mode === true && Boolean(overview.account);
}

/** What this computer remembers of the host's last grant request, to offer again; `null` when it made none. */
export function grantMemoryFor(overview: RecordOverview, hostId: string | null): GrantMemoryView | null {
  if (!hostId) return null;
  return overview.grant_memory?.find((memory) => memory.host_id === hostId) ?? null;
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

/** Where a route goes, as a card and the details pane name it: `project / instance`. */
export const iapTarget = (kind: TransportKind): string => `${kind.project} / ${kind.instance}`;

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
