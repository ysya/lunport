import { afterEach, describe, expect, it, vi } from "vitest";
import { stubBackend } from "./test-ipc";
import { recordOverview } from "@/components/records/fixtures";
import {
  deleteTransport,
  fetchOsLoginProfile,
  newIapTransport,
  pamPlaceholder,
  saveTransport,
  transportFor,
  transportLabel,
  transportProblem,
  type HostTransport,
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
});
