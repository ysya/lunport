import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { renderToStaticMarkup } from "react-dom/server";
import type { ReactNode } from "react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { osLoginOutcome, type HostTransport } from "@/lib/transports";
import { hostPayload, hostView, recordOverview } from "./fixtures";
import { RecordHostEditor } from "./HostEditor";
import { HostPreview } from "./HostPreview";
import { TransportFields } from "./TransportFields";
import { TransportsPanel } from "./TransportsPanel";

afterEach(() => vi.unstubAllGlobals());

const HOST = "0000000000000001";
const iap: HostTransport = {
  host_id: HOST,
  kind: { type: "gcp_iap", project: "eng-dev-396409", zone: "asia-east1-b", instance: "jumpbox", interface: "nic0", account: "frank@retower.io", os_login: true, pam: null },
};
const render = (node: ReactNode) => renderToStaticMarkup(<QueryClientProvider client={new QueryClient()}>{node}</QueryClientProvider>);

describe("Google Cloud IAP transports", () => {
  it("lists the hosts that use a tunnel in their own panel, with New transport for the rest", () => {
    const host = hostView({ id: HOST, payload: hostPayload({ alias: "jumpbox-dev", user: "frank_retower_io" }) });
    const other = hostView({ id: "0000000000000002", payload: hostPayload({ alias: "web" }) });
    const html = render(<TransportsPanel overview={recordOverview({ hosts: [host, other], transports: [iap] })} accept={(overview) => overview} />);
    expect(html).toContain("Google Cloud");
    expect(html).toContain("jumpbox-dev");
    expect(html).toContain("Google Cloud IAP · eng-dev-396409 / asia-east1-b / jumpbox");
    expect(html).toContain("frank@retower.io");
    expect(html).toContain("OS Login");
    expect(html).toContain("New transport");
    expect(html).toContain('id="new-transport-button"');
    expect(html).not.toContain("web</");
  });

  it("explains itself when no host uses a tunnel, and asks for a host first", () => {
    const html = render(<TransportsPanel overview={recordOverview({ transports: [] })} accept={(overview) => overview} />);
    expect(html).toContain("No host uses a Google Cloud IAP tunnel yet");
    const noHosts = render(<TransportsPanel overview={recordOverview({ hosts: [], transports: [] })} accept={(overview) => overview} />);
    expect(noHosts).toContain("Add an SSH host first");
    expect(noHosts).toMatch(/<button[^>]*id="new-transport-button"[^>]*disabled=""/);
  });

  it("shows the IAP fields, and the PAM fields only when a grant is required", () => {
    const html = render(<TransportFields kind={iap.kind} onChange={() => {}} disabled={false} />);
    expect(html).toContain("Network interface");
    expect(html).toContain('value="nic0"');
    expect(html).toContain('value="frank@retower.io"');
    expect(html).toContain("OS Login");
    expect(html).not.toContain("Entitlements");
    const withPam = render(<TransportFields kind={{ ...iap.kind, pam: { entitlements: [], location: "global" } }} onChange={() => {}} disabled={false} />);
    expect(withPam).toContain("Entitlements");
    expect(withPam).toContain("prod-operate, prod-admin");
    expect(withPam).toContain("Enter at least one PAM entitlement.");
  });

  it("turns an OS Login profile into the username to save and a note about the key", () => {
    expect(osLoginOutcome({ account: "frank@retower.io", username: "frank_retower_io", key_registered: false })).toEqual({
      username: "frank_retower_io",
      note: "This key is not registered with OS Login yet; it is registered at the first connection.",
      error: null,
    });
    expect(osLoginOutcome({ account: "frank@retower.io", username: "frank_retower_io", key_registered: true }).note).toBeNull();
    expect(osLoginOutcome({ account: "frank@retower.io", username: null, key_registered: null })).toEqual({
      username: null,
      note: null,
      error: "OS Login has no POSIX account for frank@retower.io in this project; the project may not have OS Login enabled.",
    });
  });

  it("keeps the host editor free of transport settings and shows the transport in the host preview", () => {
    const host = hostView({ id: HOST });
    const overview = recordOverview({ hosts: [host], transports: [iap] });
    const editor = render(
      <RecordHostEditor host={host} hostId={HOST} overview={overview} terminalId={null} newTab={false} accept={(o) => o} onSaved={() => {}} onDeleted={() => {}} onDirty={() => {}} />,
    );
    expect(editor).not.toContain("Connect through");
    const preview = render(<HostPreview host={host} overview={overview} connect={() => {}} edit={() => {}} close={() => {}} busy={false} />);
    expect(preview).toContain("Connect through");
    expect(preview).toContain("Google Cloud IAP · eng-dev-396409 / asia-east1-b / jumpbox");
    const direct = render(<HostPreview host={host} overview={recordOverview({ hosts: [host] })} connect={() => {}} edit={() => {}} close={() => {}} busy={false} />);
    expect(direct).not.toContain("Google Cloud IAP");
  });
});
