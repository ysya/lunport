import { renderToStaticMarkup } from "react-dom/server";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { describe, it, expect, vi } from "vitest";
import {
  CentralAccountAccess,
  CentralAccountAccessList,
} from "./CentralAccountAccess";
import {
  centralAccountAccessKey,
  type CentralAccountAccess as Registry,
  type CentralStatus,
} from "@/lib/central-sync";
import { buttonTag, DISABLED, text } from "@/components/keychain/test-markup";
const status: CentralStatus = {
  available: true,
  configured: true,
  phase: "revoked",
  service: "https://sync.example.com",
  account_id: "a",
  device_id: "b",
  root_fingerprint: "c",
  membership_head: "d",
  authorization_epoch: "3",
  has_session: false,
  login_pending: false,
  needs_recovery: true,
  replacement_pending: false,
  can_sync: false,
  pending: 1,
  conflicts: 0,
  error: null,
};
const registry: Registry = {
  authorization_epoch: "3",
  barrier_pending: false,
  devices: [
    {
      id: "b",
      name: "<script>own</script>",
      created_at_ms: "1700000000000",
      state: "active",
      current: true,
    },
    {
      id: "e",
      name: "Lost device",
      created_at_ms: "1700000000000",
      state: "revoked",
      current: false,
    },
  ],
};
describe("account access without Vault credentials", () => {
  it("offers account revocation for this device and escapes service labels", () => {
    const html = renderToStaticMarkup(
      <CentralAccountAccessList registry={registry} onRevoke={vi.fn()} />,
    );
    expect(text(html)).toContain("This device");
    expect((html.match(/Revoke device…/g) ?? []).length).toBe(1);
    expect(html).not.toContain("<script>");
  });
  it("keeps revoked devices pending until the service barrier is complete", () => {
    const html = renderToStaticMarkup(
      <CentralAccountAccessList
        registry={{ ...registry, barrier_pending: true }}
        onRevoke={vi.fn()}
        disabled
      />,
    );
    expect(text(html)).toContain("Revocation pending");
    expect(buttonTag(html, "Finish revocation…")).toContain(DISABLED);
  });
  it("keeps account access separate from encrypted library unlock", () => {
    const client = new QueryClient();
    client.setQueryData(centralAccountAccessKey(status), registry);
    const html = renderToStaticMarkup(
      <QueryClientProvider client={client}>
        <CentralAccountAccess
          status={status}
          disabled={false}
          update={vi.fn()}
          onBusyChange={vi.fn()}
        />
      </QueryClientProvider>,
    );
    expect(text(html)).toContain(
      "Unlocking the encrypted library still requires a trusted device or your offline recovery kit",
    );
    expect(text(html)).toContain("authenticating again in your browser");
    expect(html).not.toContain('type="password"');
  });
  it("isolates metadata caches by account scope and authorization epoch", () => {
    expect(
      centralAccountAccessKey({
        ...status,
        service: "https://another.example",
      }),
    ).not.toEqual(centralAccountAccessKey(status));
    expect(
      centralAccountAccessKey({ ...status, root_fingerprint: "changed" }),
    ).not.toEqual(centralAccountAccessKey(status));
    expect(
      centralAccountAccessKey({ ...status, authorization_epoch: "4" }),
    ).not.toEqual(centralAccountAccessKey(status));
  });
});
