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
import type { TransportLocalReason } from "@/bindings/TransportLocalReason";
import type { AccountAction } from "@/bindings/AccountAction";
import type { AccountActionView } from "@/bindings/AccountActionView";
import type { GcloudCliView } from "@/bindings/GcloudCliView";
import type { PamOverview } from "@/bindings/PamOverview";
import type { PamEntitlementView } from "@/bindings/PamEntitlementView";
import type { PamScopeView } from "@/bindings/PamScopeView";
import type { PamRoleView } from "@/bindings/PamRoleView";
import type { PamScope } from "@/bindings/PamScope";
import type { GrantRequestMemory } from "@/bindings/GrantRequestMemory";
export type {
  HostTransport,
  TransportKind,
  PamCheck,
  OsLoginProfileView,
  PamStatusView,
  GcloudAccountsView,
  GrantMemoryView,
  IapProbeView,
  TransportLocalReason,
  AccountAction,
  AccountActionView,
  GcloudCliView,
  PamOverview,
  PamEntitlementView,
  PamScopeView,
  PamRoleView,
  PamScope,
  GrantRequestMemory,
};

/** A placeholder for the PAM entitlements field, never a default: Lunport is a public product. */
export const pamPlaceholder = "prod-operate, prod-admin";

export const fetchOsLoginProfile = (account: string | null, project: string, keyId: string | null) =>
  tauriInvoke<OsLoginProfileView>("transports_oslogin_profile", { account, project, keyId });
export const fetchPamStatus = (hostId: string) => tauriInvoke<PamStatusView>("transports_pam_status", { hostId });
/**
 * A host's Access grant as the details pane keeps it: read when the pane opens, every minute while it stays open, and when the window
 * becomes visible again after background polling stopped. Not retried (the next minute reads it again), and read even
 * when the webview thinks it is offline, since the answer comes from this app's backend, which says in its own sentence when Google
 * cannot be reached.
 */
export const pamStatusQuery = (hostId: string) =>
  queryOptions({
    queryKey: ["gcp", "pam-status", hostId],
    queryFn: () => fetchPamStatus(hostId),
    refetchInterval: 60_000,
    refetchOnWindowFocus: true,
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
/** Where gcloud is on this computer, found once for the app's run (design 2026-10-27, Finding gcloud). */
export const gcloudCliKey = ["gcp", "cli"] as const;
export const gcloudCliQuery = queryOptions({
  queryKey: gcloudCliKey,
  queryFn: () => tauriInvoke<GcloudCliView>("gcp_cli_status"),
  retry: false,
  staleTime: Infinity,
  networkMode: "always",
});
/** Looks for gcloud again: the Accounts tab's Check again. */
export const locateGcloudAgain = () => tauriInvoke<GcloudCliView>("gcp_cli_locate_again");
/** Runs one account action with gcloud, once the person confirmed it (design 2026-10-27, The Accounts tab). */
export const runAccountAction = (action: AccountAction) => tauriInvoke<AccountActionView>("gcp_account_action", { action });
/** Stops the account action that is running, if one is. */
export const cancelAccountAction = () => tauriInvoke<void>("gcp_account_cancel");
/** The event that carries the sign-in page's address while gcloud waits for the browser. */
export const SIGN_IN_URL_EVENT = "gcp://sign-in-url";

/** The Access tab's overview: the places Lunport looks and every entitlement it found or a route names, read now. */
export const listPamOverview = () => tauriInvoke<PamOverview>("gcp_pam_overview");
export const pamOverviewKey = ["gcp", "pam-overview"] as const;
/**
 * The Access tab's overview: read when the tab shows, every minute while it stays open, and when the window becomes visible again.
 * As with `pamStatusQuery`, it is not retried (the next minute reads it again), and it is read even when the webview thinks it is
 * offline, since the backend says in its own sentence when Google cannot be reached.
 */
export const pamOverviewQuery = queryOptions({
  queryKey: pamOverviewKey,
  queryFn: listPamOverview,
  refetchInterval: 60_000,
  refetchOnWindowFocus: true,
  retry: false,
  networkMode: "always",
});
/** Requests a grant on the entitlement `name` as `account` (none: gcloud's active account) and waits for it, or for its approver. */
export const requestEntitlementGrant = (account: string | null, name: string, justification: string, durationSecs: number) =>
  tauriInvoke<PamStatusView>("gcp_pam_request", { account, name, justification, durationSecs });
/** Adds a search scope; the answer is the overview with it. */
export const savePamScope = (parent: string, location: string, account: string | null) =>
  tauriInvoke<RecordOverview>("gcp_pam_scope_save", { parent, location, account });
/** Removes a search scope; the answer is the overview without it. */
export const removePamScope = (id: string) => tauriInvoke<RecordOverview>("gcp_pam_scope_remove", { id });
/** The entitlement ids the account may request in the project's location, for the host editor's suggestions. */
export const pamSuggestionsQuery = (account: string | null, project: string, location: string) =>
  queryOptions({
    queryKey: ["gcp", "pam-suggestions", account, project, location],
    queryFn: () => tauriInvoke<string[]>("gcp_pam_suggestions", { account, project, location }),
    staleTime: 5 * 60_000,
    retry: false,
    refetchOnWindowFocus: false,
    networkMode: "always",
  });

/** The kinds of place a search scope names, as the Add scope dialog offers them. */
export type ScopeKind = "projects" | "folders" | "organizations";
/** A scope's parent from what the dialog was given, or the backend's sentence why not. */
export function scopeParent(kind: ScopeKind, id: string): { parent: string } | { problem: string } {
  const trimmed = id.trim();
  const ok = kind === "projects" ? isScopeProject(trimmed) : /^\d{1,20}$/.test(trimmed);
  return ok ? { parent: `${kind}/${trimmed}` } : { problem: "Enter a project ID, or a folder or organization number." };
}
const isScopeProject = (value: string) => {
  const colon = value.lastIndexOf(":");
  const id = colon < 0 ? value : value.slice(colon + 1);
  if (colon >= 0 && !/^[a-z0-9-]+(\.[a-z0-9-]+)*$/.test(value.slice(0, colon))) return false;
  return isProject(id);
};
/** A scope or an entitlement's parent as the page names it: `project acme-dev-654321`, `folder 123456789012`, `organization 987…`. */
export function parentLabel(parent: string): string {
  const [kind, id] = parent.split("/", 2);
  const word = kind === "projects" ? "project" : kind === "folders" ? "folder" : kind === "organizations" ? "organization" : kind;
  return id === undefined ? parent : `${word} ${id}`;
}
/** How long a grant may last, in words: `Up to 1 hour`, `Up to 45 minutes`. */
export function upTo(seconds: number): string {
  const minutes = Math.floor(seconds / 60);
  if (minutes >= 60 && minutes % 60 === 0) {
    const hours = minutes / 60;
    return `Up to ${hours} hour${hours === 1 ? "" : "s"}`;
  }
  return `Up to ${minutes} minute${minutes === 1 ? "" : "s"}`;
}

/** Check through IAP: whether this computer reaches the host's instance through its route. It attempts no SSH. */
export const probeIap = (hostId: string) => tauriInvoke<IapProbeView>("transports_iap_probe", { hostId });

const hhmm = (ms: number) => {
  const at = new Date(ms);
  return `${String(at.getHours()).padStart(2, "0")}:${String(at.getMinutes()).padStart(2, "0")}`;
};

/** What a grant that could not be checked says in place of its state: the API's own sentence. */
const grantProblem = (grant: { message: string | null }) => grant.message ?? "The grant could not be checked.";

/** The API's active state can outlive a cached grant's deadline while a refresh is pending or paused. */
const grantExpired = (grant: { state: string; active_until_ms?: number | null }, now: number) =>
  grant.state === "active" && grant.active_until_ms != null && grant.active_until_ms <= now;

/** One line about a transport's PAM grant (design 2026-10-25): which entitlement holds it and until when, on this computer's clock, or why there is none. */
export function pamStatusLine(view: PamStatusView, now = Date.now()): string {
  if (grantExpired(view, now)) return `${view.entitlement ?? "grant"} · expired`;
  switch (view.state) {
    case "active":
      return `${view.entitlement ?? "grant"} · active${view.active_until_ms === null ? "" : ` until ${hhmm(view.active_until_ms)}`}`;
    case "activating":
      return `${view.entitlement ?? "grant"} · activating…`;
    case "approval_awaited":
      return `${view.entitlement ?? "grant"} · awaiting approval`;
    case "error":
      return grantProblem(view);
    default:
      return "no active grant";
  }
}

/** One line about a grant, as a row of the Google Cloud page or a host's details shows it. A grant in the `error` state shows its `message` instead; this line reads "No active grant" for it (see `grantStateOrMessage`). */
export function grantStateLine(grant: { state: string; active_until_ms: number | null }, now = Date.now()): string {
  if (grantExpired(grant, now)) return "Expired";
  switch (grant.state) {
    case "active":
      return grant.active_until_ms === null ? "Active" : `Active until ${hhmm(grant.active_until_ms)}`;
    case "activating":
      return "Activating…";
    case "approval_awaited":
      return "Awaiting approval";
    default:
      return "No active grant";
  }
}

/**
 * What a row of the Google Cloud page and the details pane say of a grant they read: `grantStateLine`, except for a grant in the
 * `error` state, which has the API's own sentence (its `message`) instead of "No active grant", since it could not be checked.
 */
export function grantStateOrMessage(grant: { state: string; active_until_ms: number | null; message: string | null }, now = Date.now()): string {
  return grant.state === "error" ? grantProblem(grant) : grantStateLine(grant, now);
}

/**
 * Whether a grant that was read is held: active before its known deadline, or activating (a request already in flight, R54). Request
 * grant is off for both, and a held grant is shown as held. A grant not read yet, or whose read failed, is not.
 */
export function grantHeld(grant: { state: string; active_until_ms?: number | null } | null, now = Date.now()): boolean {
  return grant?.state === "activating" || (grant?.state === "active" && !grantExpired(grant, now));
}

/**
 * Whether Request grant is off for a grant that was read: held, or waiting for an approver (design 2026-10-27), since PAM refuses another
 * request on the entitlement while one waits.
 */
export function grantBusy(grant: { state: string; active_until_ms?: number | null } | null, now = Date.now()): boolean {
  return grantHeld(grant, now) || grant?.state === "approval_awaited";
}

/** What a host's Access grant says of the grant it read: the entitlement holding it and its state, or why it could not be checked. */
export function grantLine(status: PamStatusView, now = Date.now()): string {
  const line = grantStateOrMessage(status, now);
  return status.state === "error" || !status.entitlement ? line : `${status.entitlement} · ${line}`;
}

/**
 * What a tunnel's row says of the grant its first hop needs (design 2026-10-26, Tunnels through a host that needs a grant): a held
 * grant as the host's Access grant says it, the API's sentence when it could not be checked, and otherwise the entitlements of the
 * route's PAM check, any of which can hold one.
 */
export function tunnelGrantLine(status: PamStatusView, pam: PamCheck, now = Date.now()): string {
  return grantBusy(status, now) || status.state === "error" ? grantLine(status, now) : `Needs a grant: ${pam.entitlements.join(", ")}`;
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

/**
 * Why the route of `hostId` stays on this computer, when that can be said: only that the library has no room for it (`no_room`). A route
 * that syncs, or one waiting for anything else (the library's latest changes not read yet, a conflict, paused writes), gives none.
 */
export function routeLocalReason(overview: RecordOverview, hostId: string): TransportLocalReason | null {
  return overview.transport_sync?.find((entry) => entry.host_id === hostId)?.reason ?? null;
}

/** An entitlement of a route by its full name, as PAM names it and the library's grant memory is kept. */
export const entitlementName = (project: string, location: string, id: string) => `projects/${project}/locations/${location}/entitlements/${id}`;

/**
 * What a request for the host's route starts from (design 2026-10-27): the library's memory of the entitlement it requests (`entitlement`,
 * else the route's first), else what this computer remembered for the host as an earlier release kept it; `null` when there is neither.
 */
export function grantMemoryFor(overview: RecordOverview, hostId: string | null, entitlement?: string): GrantMemoryView | null {
  if (!hostId) return null;
  const pam = transportFor(overview, hostId)?.kind;
  const id = entitlement ?? pam?.pam?.entitlements[0];
  if (pam?.pam && id) {
    const name = entitlementName(pam.project, pam.pam.location, id);
    const synced = overview.pam_requests?.find((memory) => memory.name === name);
    if (synced) return { host_id: hostId, justification: synced.justification, duration_secs: synced.duration_secs };
  }
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
/** Whether `value` reads as a project id or number, as the route editor and the backend check it. */
export const isProjectId = (value: string) => isProject(value);
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
