import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { renderToStaticMarkup } from "react-dom/server";
import type { ReactNode } from "react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { stubBackend } from "@/lib/test-ipc";
import type { HostTransport } from "@/lib/transports";
import { hostPayload, hostView, recordOverview } from "./fixtures";
import { RecordHostEditor } from "./HostEditor";
import { HostPreview } from "./HostPreview";
import { TransportSection } from "./TransportSection";
import { applyOsLoginProfile, beginEditor, saveTransportDraft } from "./editor";

afterEach(() => vi.unstubAllGlobals());

const HOST = "0000000000000001";
const iap: HostTransport = {
  host_id: HOST,
  kind: { type: "gcp_iap", project: "eng-dev-396409", zone: "asia-east1-b", instance: "jumpbox", interface: "nic0", account: "frank@retower.io", os_login: true, pam: null },
};
const render = (node: ReactNode) => renderToStaticMarkup(<QueryClientProvider client={new QueryClient()}>{node}</QueryClientProvider>);

describe("Google Cloud IAP transports in the host editor", () => {
  it("shows the IAP fields, the OS Login hint and the username button for a host with a transport", () => {
    const host = hostView({ id: HOST, payload: hostPayload({ user: "frank_retower_io" }) });
    const html = render(
      <RecordHostEditor
        host={host}
        hostId={HOST}
        overview={recordOverview({ hosts: [host], transports: [iap] })}
        terminalId={null}
        newTab={false}
        accept={(overview) => overview}
        onSaved={() => {}}
        onDeleted={() => {}}
        onDirty={() => {}}
      />,
    );
    expect(html).toContain("Connect through");
    expect(html).toContain('value="eng-dev-396409"');
    expect(html).toContain("Use OS Login username");
    expect(html).toContain("OS Login decides the username");
    expect(html).toContain('value="frank_retower_io"');
  });

  it("offers Direct for a host without a transport and shows the IAP fields only for one", () => {
    const direct = render(<TransportSection hostId={HOST} value={null} onChange={() => {}} disabled={false} />);
    expect(direct).toContain("Connect through");
    expect(direct).toContain("Direct (TCP)");
    expect(direct).not.toContain("Network interface");
    const withIap = render(<TransportSection hostId={HOST} value={iap} onChange={() => {}} disabled={false} />);
    expect(withIap).toContain("Network interface");
    expect(withIap).toContain('value="nic0"');
    expect(withIap).toContain('value="frank@retower.io"');
    expect(withIap).not.toContain("Entitlements");
    const withPam = render(
      <TransportSection hostId={HOST} value={{ ...iap, kind: { ...iap.kind, pam: { entitlements: [], location: "global" } } }} onChange={() => {}} disabled={false} />,
    );
    expect(withPam).toContain("Entitlements");
    expect(withPam).toContain("prod-operate, prod-admin");
    expect(withPam).toContain("Enter at least one PAM entitlement.");
  });

  it("saves the transport after the host with the displayed value as expected", async () => {
    const overview = recordOverview();
    let calls = stubBackend(async () => overview);
    expect(await saveTransportDraft(HOST, iap, recordOverview({ transports: [] }))).toBe(overview);
    expect(calls).toEqual([["transports_save", { transport: iap, expected: null }]]);
    const changed: HostTransport = { ...iap, kind: { ...iap.kind, zone: "asia-east1-c" } };
    calls = stubBackend(async () => overview);
    await saveTransportDraft(HOST, changed, recordOverview({ transports: [iap] }));
    expect(calls).toEqual([["transports_save", { transport: changed, expected: iap }]]);
    calls = stubBackend(async () => overview);
    expect(await saveTransportDraft(HOST, undefined, recordOverview({ transports: [iap] }))).toBeNull();
    expect(calls).toEqual([]);
    calls = stubBackend(async () => overview);
    await saveTransportDraft("0000000000000009", { ...iap, host_id: "" }, recordOverview());
    expect(calls).toEqual([["transports_save", { transport: { ...iap, host_id: "0000000000000009" }, expected: null }]]);
  });

  it("deletes the transport when Direct is chosen", async () => {
    const overview = recordOverview();
    let calls = stubBackend(async () => overview);
    expect(await saveTransportDraft(HOST, null, recordOverview({ transports: [iap] }))).toBe(overview);
    expect(calls).toEqual([["transports_delete", { expected: iap }]]);
    calls = stubBackend(async () => overview);
    expect(await saveTransportDraft(HOST, null, recordOverview())).toBeNull();
    expect(calls).toEqual([]);
  });

  it("fetches the OS Login username into the Username field", () => {
    const state = beginEditor(hostView({ id: HOST, payload: hostPayload({ user: "frank" }) }));
    const fetched = applyOsLoginProfile(state, { account: "frank@retower.io", username: "frank_retower_io", key_registered: false });
    expect(fetched.state.payload.user).toBe("frank_retower_io");
    expect(fetched.state.dirty).toBe(true);
    expect(fetched.note).toBe("This key is not registered with OS Login yet; it is registered at the first connection.");
    const registered = applyOsLoginProfile(state, { account: "frank@retower.io", username: "frank_retower_io", key_registered: true });
    expect(registered.note).toBeNull();
    const missing = applyOsLoginProfile(state, { account: "frank@retower.io", username: null, key_registered: null });
    expect(missing.state.payload.user).toBe("frank");
    expect(missing.state.dirty).toBe(false);
    expect(missing.state.error).toBe("OS Login has no POSIX account for frank@retower.io in this project; the project may not have OS Login enabled.");
  });

  it("shows the transport in the host preview", () => {
    const host = hostView({ id: HOST });
    const html = render(
      <HostPreview host={host} overview={recordOverview({ hosts: [host], transports: [iap] })} connect={() => {}} edit={() => {}} close={() => {}} busy={false} />,
    );
    expect(html).toContain("Connect through");
    expect(html).toContain("Google Cloud IAP · eng-dev-396409 / asia-east1-b / jumpbox");
    const direct = render(<HostPreview host={host} overview={recordOverview({ hosts: [host] })} connect={() => {}} edit={() => {}} close={() => {}} busy={false} />);
    expect(direct).not.toContain("Google Cloud IAP");
  });
});
