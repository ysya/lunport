import { afterEach, describe, expect, it, vi } from "vitest";
import { QueryClient } from "@tanstack/react-query";
import { stubBackend } from "./test-ipc";
import type { RecordOverview } from "./records";
import { recordOverview } from "@/components/records/fixtures";
import {
  fetchOsLoginProfile,
  gcloudAccountsKey,
  gcloudAccountsQuery,
  grantHeld,
  grantMemoryFor,
  grantStateLine,
  grantStateOrMessage,
  iapTarget,
  listGcloudAccounts,
  listPamOverview,
  parentLabel,
  pamOverviewKey,
  pamOverviewQuery,
  requestEntitlementGrant,
  runAccountAction,
  savePamScope,
  scopeParent,
  upTo,
  grantBusy,
  newIapTransport,
  osLoginOutcome,
  pamPlaceholder,
  pamStatusLine,
  pamStatusQuery,
  parseEntitlements,
  probeIap,
  requestPamGrant,
  routeLocalReason,
  routeSynced,
  transportFor,
  transportProblem,
  type GcloudAccountsView,
  type HostTransport,
  type IapProbeView,
  type PamEntitlementView,
  type PamOverview,
  type PamStatusView,
  type TransportKind,
} from "./transports";

afterEach(() => vi.unstubAllGlobals());

const HOST = "0000000000000001";
const iap = (hostId = HOST): HostTransport => ({
  host_id: hostId,
  kind: {
    type: "gcp_iap",
    project: "acme-dev-654321",
    zone: "asia-east1-b",
    instance: "jumpbox",
    interface: "nic0",
    account: "frank@example.com",
    os_login: true,
    pam: null,
  },
});
const withKind = (patch: Partial<TransportKind>): HostTransport => ({ ...iap(), kind: { ...iap().kind, ...patch } });
const OPERATE = "projects/acme-prod-123456/locations/global/entitlements/prod-operate";
const entitlementRow = (patch: Partial<PamEntitlementView> = {}): PamEntitlementView => ({
  account: "frank@example.com",
  name: OPERATE,
  parent: "projects/acme-prod-123456",
  location: "global",
  entitlement: "prod-operate",
  max_duration_secs: 3600,
  needs_approval: false,
  roles: [],
  state: "none",
  active_until_ms: null,
  message: null,
  host_ids: [HOST],
  memory: null,
  default_duration_secs: 1800,
  ...patch,
});

describe("transports", () => {
  it("finds the host's transport or null", () => {
    const overview = recordOverview({ transports: [iap()] });
    expect(transportFor(overview, HOST)).toEqual(iap());
    expect(transportFor(overview, "0000000000000002")).toBeNull();
    expect(transportFor(overview, null)).toBeNull();
    expect(transportFor(recordOverview(), HOST)).toBeNull();
  });

  it("starts a new route with the defaults", () => {
    expect(newIapTransport(HOST)).toEqual({
      host_id: HOST,
      kind: { type: "gcp_iap", project: "", zone: "", instance: "", interface: "nic0", account: null, os_login: true, pam: null },
    });
    expect(pamPlaceholder).toBe("prod-operate, prod-admin");
  });

  it("validates like the backend, one sentence for the first bad field", () => {
    expect(transportProblem(iap())).toBeNull();
    expect(transportProblem(newIapTransport(HOST))).toBe("Enter the Google Cloud project id.");
    expect(transportProblem(withKind({ project: "Eng" }))).toBe("Enter the Google Cloud project id.");
    expect(transportProblem(withKind({ project: "123456789012" }))).toBeNull();
    expect(transportProblem(withKind({ zone: "asia east1" }))).toBe("Enter the zone of the instance.");
    expect(transportProblem(withKind({ instance: "" }))).toBe("Enter the instance name.");
    expect(transportProblem(withKind({ interface: "eth0" }))).toBe("Enter a network interface such as nic0.");
    expect(transportProblem(withKind({ account: "frank" }))).toBe("Enter the Google account as an email address.");
    // The account names a directory under gcloud's config: no path characters, in either validator.
    for (const traversal of ["../../tmp/x@example.com", "/etc/x@example.com", "a\\b@example.com", "a:b@example.com", "a@b/c.example.com"])
      expect(transportProblem(withKind({ account: traversal }))).toBe("Enter the Google account as an email address.");
    expect(transportProblem(withKind({ account: "first.last+tag@sub.example.com" }))).toBeNull();
    expect(transportProblem(withKind({ account: null }))).toBeNull();
    expect(transportProblem(withKind({ pam: { entitlements: [], location: "global", duration_secs: 1800, justification: null } }))).toBe("Enter at least one PAM entitlement.");
    expect(transportProblem(withKind({ pam: { entitlements: ["Prod"], location: "global", duration_secs: 1800, justification: null } }))).toBe("Enter PAM entitlement ids such as prod-operate.");
    expect(transportProblem(withKind({ pam: { entitlements: ["prod-operate"], location: "Global", duration_secs: 1800, justification: null } }))).toBe("Enter the PAM location, such as global.");
    expect(transportProblem(withKind({ pam: { entitlements: ["a", "b", "c", "d", "e", "f", "g", "h", "i"], location: "global", duration_secs: 1800, justification: null } }))).toBe("Enter at most 8 PAM entitlements.");
    expect(transportProblem(withKind({ pam: { entitlements: ["prod-operate", "prod-admin"], location: "global", duration_secs: 1800, justification: null } }))).toBeNull();
    // The grant request's defaults (design 2026-10-25, PAM grant requests), with the backend's sentences.
    expect(transportProblem(withKind({ pam: { entitlements: ["prod-operate"], location: "global", duration_secs: 30, justification: null } }))).toBe("Enter a grant duration between 1 and 480 minutes.");
    expect(transportProblem(withKind({ pam: { entitlements: ["prod-operate"], location: "global", duration_secs: 28_860, justification: null } }))).toBe("Enter a grant duration between 1 and 480 minutes.");
    expect(transportProblem(withKind({ pam: { entitlements: ["prod-operate"], location: "global", duration_secs: 1800, justification: "x".repeat(513) } }))).toBe("Keep the justification under 512 characters on one line.");
    expect(transportProblem(withKind({ pam: { entitlements: ["prod-operate"], location: "global", duration_secs: 1800, justification: "restart\napp-api" } }))).toBe("Keep the justification under 512 characters on one line.");
    expect(transportProblem(withKind({ pam: { entitlements: ["prod-operate"], location: "global", duration_secs: 3600, justification: "restart app-api" } }))).toBeNull();
  });

  it("asks the backend for the OS Login profile", async () => {
    const calls = stubBackend(async () => ({ account: "frank@example.com", username: "frank_example_com", key_registered: false }));
    const view = await fetchOsLoginProfile("frank@example.com", "acme-dev-654321", null);
    expect(view.username).toBe("frank_example_com");
    expect(calls).toEqual([["transports_oslogin_profile", { account: "frank@example.com", project: "acme-dev-654321", keyId: null }]]);
  });

  it("asks the backend for the gcloud accounts, the Access overview, and a check through IAP", async () => {
    const accounts: GcloudAccountsView = { config_found: true, active: "frank@example.com", accounts: [{ account: "frank@example.com", state: "signed_in", message: null }] };
    const overview: PamOverview = { scopes: [], entitlements: [entitlementRow()] };
    const probe: IapProbeView = { status: "reachable", latency_ms: 120, elapsed_ms: 340, checked_at_ms: 1_700_000_000_000, message: null };
    const replies: Record<string, unknown> = { gcp_accounts: accounts, gcp_pam_overview: overview, transports_iap_probe: probe };
    const calls = stubBackend(async (cmd) => replies[cmd]);
    expect(await listGcloudAccounts()).toBe(accounts);
    expect(await listPamOverview()).toBe(overview);
    expect(await probeIap(HOST)).toBe(probe);
    expect(calls).toEqual([
      ["gcp_accounts", {}],
      ["gcp_pam_overview", {}],
      ["transports_iap_probe", { hostId: HOST }],
    ]);
  });

  it("sends the account actions, the requests by entitlement and the scope edits with the backend's argument names", async () => {
    const calls = stubBackend(async () => null);
    await runAccountAction({ kind: "remove", account: "frank@example.com" });
    await requestEntitlementGrant(null, OPERATE, "restart app-api", 1800);
    await savePamScope("folders/123456789012", "global", "ops@example.com");
    expect(calls).toEqual([
      ["gcp_account_action", { action: { kind: "remove", account: "frank@example.com" } }],
      ["gcp_pam_request", { account: null, name: OPERATE, justification: "restart app-api", durationSecs: 1800 }],
      ["gcp_pam_scope_save", { parent: "folders/123456789012", location: "global", account: "ops@example.com" }],
    ]);
  });

  it("reads a scope's parent from the dialog as the backend checks it, and names parents and lengths in words", () => {
    expect(scopeParent("projects", " acme-dev-654321 ")).toEqual({ parent: "projects/acme-dev-654321" });
    expect(scopeParent("projects", "example.com:acme-dev-654321")).toEqual({ parent: "projects/example.com:acme-dev-654321" });
    expect(scopeParent("folders", "123456789012")).toEqual({ parent: "folders/123456789012" });
    expect(scopeParent("organizations", "987654321098")).toEqual({ parent: "organizations/987654321098" });
    for (const [kind, id] of [["projects", "acme"], ["folders", "abc"], ["organizations", ""], ["projects", "Acme-Dev-654321"]] as const)
      expect("problem" in scopeParent(kind, id), `${kind} ${id}`).toBe(true);
    expect(parentLabel("projects/acme-dev-654321")).toBe("project acme-dev-654321");
    expect(parentLabel("folders/123456789012")).toBe("folder 123456789012");
    expect(parentLabel("organizations/987654321098")).toBe("organization 987654321098");
    expect([upTo(3600), upTo(7200), upTo(2700), upTo(60)]).toEqual(["Up to 1 hour", "Up to 2 hours", "Up to 45 minutes", "Up to 1 minute"]);
  });

  it("requests a grant on the route's first entitlement, or on the one named", async () => {
    const view: PamStatusView = { entitlement: "prod-admin", state: "activating", active_until_ms: null, message: null };
    const calls = stubBackend(async () => view);
    expect(await requestPamGrant(HOST, "restart app-api", 1800)).toBe(view);
    await requestPamGrant(HOST, "restart app-api", 3600, "prod-admin");
    expect(calls).toEqual([
      ["transports_pam_request", { hostId: HOST, justification: "restart app-api", durationSecs: 1800 }],
      ["transports_pam_request", { hostId: HOST, justification: "restart app-api", durationSecs: 3600, entitlement: "prod-admin" }],
    ]);
    // Without an entitlement the argument is left out, not sent as undefined or null: the backend then asks for the first one.
    expect(Object.keys(calls[0][1] as object)).toEqual(["hostId", "justification", "durationSecs"]);
  });

  it("reads a host's grant through the backend, apart for each host, when the pane opens and every minute, but not on window focus", async () => {
    const view: PamStatusView = { entitlement: "prod-operate", state: "active", active_until_ms: 1_700_000_000_000, message: null };
    const calls = stubBackend(async () => view);
    expect(await new QueryClient().fetchQuery(pamStatusQuery(HOST))).toEqual(view);
    expect(calls).toEqual([["transports_pam_status", { hostId: HOST }]]);
    expect(pamStatusQuery(HOST).queryKey).not.toEqual(pamStatusQuery("0000000000000002").queryKey);
    expect(pamStatusQuery(HOST).refetchInterval).toBe(60_000);
    // A window gaining focus would cost a Google call the design does not ask for.
    expect(pamStatusQuery(HOST).refetchOnWindowFocus).toBe(false);
  });

  it("names a route's target as project / instance", () => {
    expect(iapTarget(iap().kind)).toBe("acme-dev-654321 / jumpbox");
  });

  it("says what a grant is up to in one line, on this computer's clock", () => {
    const at = new Date(2026, 9, 26, 9, 5).getTime();
    expect(grantStateLine({ state: "active", active_until_ms: at })).toBe("Active until 09:05");
    expect(grantStateLine({ state: "active", active_until_ms: null })).toBe("Active");
    expect(grantStateLine({ state: "activating", active_until_ms: null })).toBe("Activating…");
    expect(grantStateLine({ state: "none", active_until_ms: null })).toBe("No active grant");
    // A grant that could not be checked reads like none here, which is why rows show `grantStateOrMessage` instead.
    expect(grantStateLine({ state: "error", active_until_ms: null })).toBe("No active grant");
    expect(grantStateLine({ state: "approval_awaited", active_until_ms: null })).toBe("Awaiting approval");
    // A row the Access tab shows, or a PamStatusView, needs no conversion.
    expect(grantStateLine(entitlementRow({ state: "activating" }))).toBe("Activating…");
  });

  it("tells whether a route syncs: its own flag, else whether a route saved now would", () => {
    const account = { chain_id: "a".repeat(64), device_name: "Synthetic" };
    const route = (synced: boolean, patch: Partial<RecordOverview> = {}) =>
      recordOverview({ transports: [iap()], transport_sync: [{ host_id: HOST, synced, reason: null }], ...patch });
    expect(routeSynced(route(true), HOST)).toBe(true);
    expect(routeSynced(route(false), HOST)).toBe(false);
    // The route's own flag decides, even in a library that uses central sync: a route kept on this computer says so.
    expect(routeSynced(route(false, { central_mode: true, account }), HOST)).toBe(false);
    // Other hosts' flags are theirs.
    expect(routeSynced(route(true), "0000000000000002")).toBe(false);
    // A host with no route yet (a new one too) syncs one saved now exactly where the library uses central sync.
    expect(routeSynced(recordOverview(), HOST)).toBe(false);
    expect(routeSynced(recordOverview({ account }), HOST)).toBe(false);
    expect(routeSynced(recordOverview({ central_mode: true }), HOST)).toBe(false);
    expect(routeSynced(recordOverview({ central_mode: true, account }), HOST)).toBe(true);
    expect(routeSynced(recordOverview({ central_mode: true, account }), null)).toBe(true);
  });

  it("tells why a route stays on this computer only when the library has no room for it", () => {
    const overview = (reason: "no_room" | null) => recordOverview({ transports: [iap()], transport_sync: [{ host_id: HOST, synced: false, reason }] });
    expect(routeLocalReason(overview("no_room"), HOST)).toBe("no_room");
    expect(routeLocalReason(overview(null), HOST)).toBeNull();
    expect(routeLocalReason(overview("no_room"), "0000000000000002")).toBeNull(); // another host's reason is its own
    expect(routeLocalReason(recordOverview(), HOST)).toBeNull();
  });

  it("holds a grant that is active or activating, and nothing else", () => {
    expect(grantHeld({ state: "active" })).toBe(true);
    // Activating is a request already in flight: held too, so Request grant stays off.
    expect(grantHeld({ state: "activating" })).toBe(true);
    for (const state of ["none", "error", "scheduled", ""]) expect(grantHeld({ state }), state).toBe(false);
    // No answer yet, or a read that failed.
    expect(grantHeld(null)).toBe(false);
    // A row of the Access tab fits as a host's status does.
    expect(grantHeld(entitlementRow({ state: "activating" }))).toBe(true);
    // A grant waiting for an approver is not held, but Request grant stays off for it: PAM refuses a second request meanwhile.
    expect(grantHeld({ state: "approval_awaited" })).toBe(false);
    expect([grantBusy({ state: "approval_awaited" }), grantBusy({ state: "active" }), grantBusy({ state: "none" }), grantBusy(null)]).toEqual([true, true, false, false]);
  });

  it("says what a grant that was read says for itself: its state, or the API's sentence when it could not be checked", () => {
    const at = new Date(2026, 9, 26, 9, 5).getTime();
    expect(grantStateOrMessage({ state: "active", active_until_ms: at, message: null })).toBe("Active until 09:05");
    expect(grantStateOrMessage({ state: "activating", active_until_ms: null, message: null })).toBe("Activating…");
    expect(grantStateOrMessage({ state: "none", active_until_ms: null, message: null })).toBe("No active grant");
    const refused = "Privileged Access Manager refused the request: quota exceeded.";
    expect(grantStateOrMessage({ state: "error", active_until_ms: null, message: refused })).toBe(refused);
    // An error that carries no sentence still says it could not be checked, never "No active grant".
    expect(grantStateOrMessage({ state: "error", active_until_ms: null, message: null })).toBe("The grant could not be checked.");
    // A row of the page and a status of the details pane both fit.
    expect(grantStateOrMessage(entitlementRow({ state: "error", message: refused }))).toBe(refused);
  });

  it("reads gcloud's accounts through one cache entry the editor and the page share, and reuses a minute-old answer", async () => {
    const accounts: GcloudAccountsView = { config_found: true, active: null, accounts: [] };
    const calls = stubBackend(async () => accounts);
    expect(await new QueryClient().fetchQuery(gcloudAccountsQuery)).toEqual(accounts);
    expect(calls).toEqual([["gcp_accounts", {}]]);
    expect(gcloudAccountsQuery.queryKey).toEqual(gcloudAccountsKey);
    // Each read checks every sign-in with Google.
    expect(gcloudAccountsQuery.staleTime).toBe(60_000);
    expect(gcloudAccountsQuery.retry).toBe(false);
    // The answer comes from this app's backend, which words a Google outage itself: a webview that thinks it is offline (a VPN or a
    // Wi-Fi switch) must still ask, or a computer with no cached answer would never show that the sign-ins could not be checked.
    expect(gcloudAccountsQuery.networkMode).toBe("always");
  });

  it("reads the Access overview through the backend, when the tab shows and every minute, but not on window focus", async () => {
    const overview: PamOverview = { scopes: [], entitlements: [entitlementRow()] };
    const calls = stubBackend(async () => overview);
    expect(await new QueryClient().fetchQuery(pamOverviewQuery)).toEqual(overview);
    expect(calls).toEqual([["gcp_pam_overview", {}]]);
    expect(pamOverviewQuery.queryKey).toEqual(pamOverviewKey);
    expect(pamOverviewQuery.refetchInterval).toBe(60_000);
    // A window gaining focus would cost a Google call for each scope and entitlement that nothing asked for; a failed read waits.
    expect(pamOverviewQuery.refetchOnWindowFocus).toBe(false);
    expect(pamOverviewQuery.retry).toBe(false);
    expect(pamOverviewQuery.networkMode).toBe("always");
  });

  it("words a grant request's result in one line", () => {
    const at = new Date(2026, 9, 25, 11, 7).getTime();
    expect(pamStatusLine({ entitlement: "prod-admin", state: "active", active_until_ms: at, message: null })).toBe("prod-admin · active until 11:07");
    expect(pamStatusLine({ entitlement: "prod-admin", state: "approval_awaited", active_until_ms: null, message: null })).toBe("prod-admin · awaiting approval");
    expect(pamStatusLine({ entitlement: "prod-operate", state: "activating", active_until_ms: null, message: null })).toBe("prod-operate · activating…");
    expect(pamStatusLine({ entitlement: null, state: "none", active_until_ms: null, message: null })).toBe("no active grant");
    expect(pamStatusLine({ entitlement: null, state: "error", active_until_ms: null, message: "Privileged Access Manager refused the request: quota exceeded." })).toBe(
      "Privileged Access Manager refused the request: quota exceeded.",
    );
    expect(pamStatusLine({ entitlement: null, state: "error", active_until_ms: null, message: null })).toBe("The grant could not be checked.");
  });

  it("turns an OS Login profile into the username to save and a note about the key", () => {
    expect(osLoginOutcome({ account: "ops@example.com", username: "ops_example_com", key_registered: false })).toEqual({
      username: "ops_example_com",
      note: "This key is not registered with OS Login yet; it is registered at the first connection.",
      error: null,
    });
    expect(osLoginOutcome({ account: "ops@example.com", username: "ops_example_com", key_registered: true }).note).toBeNull();
    expect(osLoginOutcome({ account: "ops@example.com", username: null, key_registered: null })).toEqual({
      username: null,
      note: null,
      error: "OS Login has no POSIX account for ops@example.com in this project; the project may not have OS Login enabled.",
    });
  });

  it("lets the entitlements be typed with commas: the field keeps its text and the list is parsed from it", () => {
    // A controlled input rebuilt from the parsed list would eat the comma as it is typed; the field keeps the text and parses it.
    expect(parseEntitlements("prod-operate,")).toEqual(["prod-operate"]);
    expect(parseEntitlements("prod-operate, prod-admin")).toEqual(["prod-operate", "prod-admin"]);
    expect(parseEntitlements(" , prod-admin,,")).toEqual(["prod-admin"]);
    expect(parseEntitlements("")).toEqual([]);
  });

  it("finds the library's memory of the entitlement a host's request asks for, else what this computer remembered for the host", () => {
    const memory = { host_id: HOST, justification: "restart app-api", duration_secs: 1800 };
    const overview = recordOverview({ grant_memory: [memory] });
    expect(grantMemoryFor(overview, HOST)).toEqual(memory);
    const pam = { entitlements: ["prod-operate", "prod-admin"], location: "global", duration_secs: 1800, justification: null };
    const routed = recordOverview({
      transports: [withKind({ project: "acme-prod-123456", pam })],
      grant_memory: [memory],
      pam_requests: [{ name: OPERATE, justification: "deploy hotfix", duration_secs: 3600 }],
    });
    expect(grantMemoryFor(routed, HOST)).toEqual({ host_id: HOST, justification: "deploy hotfix", duration_secs: 3600 });
    // Another entitlement has no memory of its own: the host's.
    expect(grantMemoryFor(routed, HOST, "prod-admin")).toEqual(memory);
    expect(grantMemoryFor(overview, "0000000000000002")).toBeNull();
    expect(grantMemoryFor(overview, null)).toBeNull();
    expect(grantMemoryFor(recordOverview(), HOST)).toBeNull();
  });
});
