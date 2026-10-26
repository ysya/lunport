import { afterEach, describe, expect, it, vi } from "vitest";
import { stubBackend } from "./test-ipc";
import type { RecordOverview } from "./records";
import { recordOverview } from "@/components/records/fixtures";
import {
  deleteTransport,
  fetchOsLoginProfile,
  grantMemoryFor,
  grantStateLine,
  iapTarget,
  listGcloudAccounts,
  listPamGrants,
  newIapTransport,
  pamPlaceholder,
  probeIap,
  requestPamGrant,
  routeSynced,
  saveTransport,
  transportFor,
  transportLabel,
  transportProblem,
  type GcloudAccountsView,
  type HostTransport,
  type IapProbeView,
  type PamGrantView,
  type PamStatusView,
  type TransportKind,
} from "./transports";

afterEach(() => vi.unstubAllGlobals());

const HOST = "0000000000000001";
const iap = (hostId = HOST): HostTransport => ({
  host_id: hostId,
  kind: {
    type: "gcp_iap",
    project: "eng-dev-396409",
    zone: "asia-east1-b",
    instance: "jumpbox",
    interface: "nic0",
    account: "frank@retower.io",
    os_login: true,
    pam: null,
  },
});
const withKind = (patch: Partial<TransportKind>): HostTransport => ({ ...iap(), kind: { ...iap().kind, ...patch } });

describe("transports", () => {
  it("finds the host's transport or null", () => {
    const overview = recordOverview({ transports: [iap()] });
    expect(transportFor(overview, HOST)).toEqual(iap());
    expect(transportFor(overview, "0000000000000002")).toBeNull();
    expect(transportFor(overview, null)).toBeNull();
    expect(transportFor(recordOverview(), HOST)).toBeNull();
  });

  it("labels a transport and starts a new one with the defaults", () => {
    expect(transportLabel(iap())).toBe("Google Cloud IAP · eng-dev-396409 / asia-east1-b / jumpbox");
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
    expect(transportProblem(withKind({ project: "834470760514" }))).toBeNull();
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

  it("saves and deletes through the backend with the displayed value", async () => {
    const overview = recordOverview();
    const calls = stubBackend(async () => overview);
    expect(await saveTransport(iap(), null)).toBe(overview);
    await deleteTransport(iap());
    expect(calls).toEqual([
      ["transports_save", { transport: iap(), expected: null }],
      ["transports_delete", { expected: iap() }],
    ]);
  });

  it("asks the backend for the OS Login profile", async () => {
    const calls = stubBackend(async () => ({ account: "frank@retower.io", username: "frank_retower_io", key_registered: false }));
    const view = await fetchOsLoginProfile("frank@retower.io", "eng-dev-396409", null);
    expect(view.username).toBe("frank_retower_io");
    expect(calls).toEqual([["transports_oslogin_profile", { account: "frank@retower.io", project: "eng-dev-396409", keyId: null }]]);
  });

  it("asks the backend for the gcloud accounts, the grants the routes need, and a check through IAP", async () => {
    const accounts: GcloudAccountsView = { config_found: true, active: "frank@retower.io", accounts: [{ account: "frank@retower.io", state: "signed_in", message: null }] };
    const grants: PamGrantView[] = [
      { account: "frank@retower.io", project: "eng-dev-396409", location: "global", entitlement: "prod-operate", state: "none", active_until_ms: null, message: null, host_ids: [HOST] },
    ];
    const probe: IapProbeView = { status: "reachable", latency_ms: 120, elapsed_ms: 340, checked_at_ms: 1_700_000_000_000, message: null };
    const replies: Record<string, unknown> = { gcp_accounts: accounts, gcp_pam_grants: grants, transports_iap_probe: probe };
    const calls = stubBackend(async (cmd) => replies[cmd]);
    expect(await listGcloudAccounts()).toBe(accounts);
    expect(await listPamGrants()).toBe(grants);
    expect(await probeIap(HOST)).toBe(probe);
    expect(calls).toEqual([
      ["gcp_accounts", {}],
      ["gcp_pam_grants", {}],
      ["transports_iap_probe", { hostId: HOST }],
    ]);
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

  it("names a route's target as project / instance", () => {
    expect(iapTarget(iap().kind)).toBe("eng-dev-396409 / jumpbox");
  });

  it("says what a grant is up to in one line, on this computer's clock", () => {
    const at = new Date(2026, 9, 26, 9, 5).getTime();
    expect(grantStateLine({ state: "active", active_until_ms: at })).toBe("Active until 09:05");
    expect(grantStateLine({ state: "active", active_until_ms: null })).toBe("Active");
    expect(grantStateLine({ state: "activating", active_until_ms: null })).toBe("Activating…");
    expect(grantStateLine({ state: "none", active_until_ms: null })).toBe("No active grant");
    // A row the page shows from PamGrantView or PamStatusView needs no conversion.
    const row: PamGrantView = { account: null, project: "p", location: "global", entitlement: "prod-operate", state: "activating", active_until_ms: null, message: null, host_ids: [] };
    expect(grantStateLine(row)).toBe("Activating…");
  });

  it("tells whether a route syncs: its own flag, else whether a route saved now would", () => {
    const account = { chain_id: "a".repeat(64), device_name: "Synthetic" };
    const route = (synced: boolean, patch: Partial<RecordOverview> = {}) =>
      recordOverview({ transports: [iap()], transport_sync: [{ host_id: HOST, synced }], ...patch });
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

  it("finds what this computer remembers of the host's last grant request", () => {
    const memory = { host_id: HOST, justification: "restart app-api", duration_secs: 1800 };
    const overview = recordOverview({ grant_memory: [memory] });
    expect(grantMemoryFor(overview, HOST)).toEqual(memory);
    expect(grantMemoryFor(overview, "0000000000000002")).toBeNull();
    expect(grantMemoryFor(overview, null)).toBeNull();
    expect(grantMemoryFor(recordOverview(), HOST)).toBeNull();
  });
});
