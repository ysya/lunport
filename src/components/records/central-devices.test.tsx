import { renderToStaticMarkup } from "react-dom/server";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { describe, it, expect, vi } from "vitest";
import { CentralDevices, CentralDeviceList } from "./CentralDevices";
import { centralDevicesKey, type CentralStatus } from "@/lib/central-sync";
import { buttonTag, DISABLED, text } from "@/components/keychain/test-markup";
const status: CentralStatus = {
  available: true,
  configured: true,
  phase: "enrolled",
  service: "https://sync.example.com",
  account_id: "a",
  device_id: "b",
  root_fingerprint: "c",
  membership_head: "d",
  authorization_epoch: "3",
  has_session: true,
  login_pending: false,
  needs_recovery: false,
  can_sync: false,
  pending: 0,
  conflicts: 0,
  error: null,
};
describe("trusted device management", () => {
  it("shows the current device and keeps untrusted labels escaped", () => {
    const html = renderToStaticMarkup(
      <CentralDeviceList
        registry={{
          membership_head: "d",
          authorization_epoch: "3",
          devices: [
            {
              id: "b",
              name: "<script>device</script>",
              state: "approved",
              fingerprint: "fingerprint",
              current: true,
            },
          ],
        }}
      />,
    );
    expect(text(html)).toContain("This device");
    expect(text(html)).toContain("Approved");
    expect(html).not.toContain("<script>");
  });
  it("offers revocation for another approved or blocked device and never for this device", () => {
    const devices = [
      {
        id: "own",
        name: "Own device",
        state: "approved" as const,
        fingerprint: "own",
        current: true,
      },
      {
        id: "other",
        name: "Other device",
        state: "approved" as const,
        fingerprint: "other",
        current: false,
      },
      {
        id: "blocked",
        name: "Blocked device",
        state: "access_blocked" as const,
        fingerprint: "blocked",
        current: false,
      },
      {
        id: "pending",
        name: "Pending device",
        state: "pending" as const,
        fingerprint: "pending",
        current: false,
      },
    ];
    const html = renderToStaticMarkup(
      <CentralDeviceList
        registry={{ membership_head: "d", authorization_epoch: "3", devices }}
        onRevoke={vi.fn()}
        disabled
      />,
    );
    expect((html.match(/Revoke device…/g) ?? []).length).toBe(1);
    expect((html.match(/Finish revocation…/g) ?? []).length).toBe(1);
    expect(buttonTag(html, "Revoke device…")).toContain(DISABLED);
    expect(buttonTag(html, "Finish revocation…")).toContain(DISABLED);
    expect(text(html)).toContain("Revocation requested");
  });
  it("requires a pairing code and explains that approval unlocks the library", () => {
    const client = new QueryClient();
    client.setQueryData(centralDevicesKey(status), {
      membership_head: "d",
      authorization_epoch: "3",
      devices: [],
    });
    const html = renderToStaticMarkup(
      <QueryClientProvider client={client}>
        <CentralDevices
          status={status}
          disabled={false}
          onBusyChange={vi.fn()}
          update={vi.fn()}
        />
      </QueryClientProvider>,
    );
    expect(buttonTag(html, "Approve device")).toContain(DISABLED);
    expect(text(html)).toContain("Approval unlocks your encrypted library");
    expect(html).not.toContain("LPPAIR2:");
  });
  it("uses separate public list cache entries after a membership or access barrier", () => {
    expect(centralDevicesKey({ ...status, membership_head: "e" })).not.toEqual(
      centralDevicesKey(status),
    );
    expect(
      centralDevicesKey({ ...status, authorization_epoch: "4" }),
    ).not.toEqual(centralDevicesKey(status));
  });
});
