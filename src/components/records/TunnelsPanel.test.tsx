import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it, vi } from "vitest";
import { TunnelsPanel } from "./TunnelsPanel";
import { recordOverview } from "./fixtures";
import { tunnelsKey, newTunnel, tunnelRoute, startTunnel, type TunnelView } from "@/lib/tunnels";
vi.mock("@/lib/ipc", () => ({ tauriInvoke: vi.fn() }));
vi.mock("@/lib/tunnels", async (original) => ({ ...await original<typeof import("@/lib/tunnels")>(), startTunnel: vi.fn() }));
function row(patch: Partial<TunnelView> = {}): TunnelView {
  return { rule: { ...newTunnel("0000000000000001"), id: "0000000000000002", name: "Database" }, live: { phase: "stopped", forwarding: { running: false, port: 0, connections: 0, error: null } }, synced: true, blocked: false, changed: false, removed: false, ...patch };
}
function render(rows?: TunnelView[], hosts = true) {
  const client = new QueryClient();
  if (rows) client.setQueryData(tunnelsKey, rows);
  return renderToStaticMarkup(<QueryClientProvider client={client}><TunnelsPanel overview={recordOverview(hosts ? {} : { hosts: [] })} /></QueryClientProvider>);
}
describe("Tunnels", () => {
  it("loading saved definitions never starts a connection", () => {
    const html = render([row()]);
    expect(html).toContain("Synced rule"); expect(html).toContain("Stopped");
    expect(html).toContain("Start"); expect(startTunnel).not.toHaveBeenCalled();
  });
  it("keeps Stop available after remote deletion and makes pending changes visible", () => {
    const active = row({ live: { phase: "running", forwarding: { running: true, port: 15432, connections: 1, error: null } }, removed: true, blocked: true });
    expect(render([active])).toContain("Stop to remove here");
    expect(render([{ ...active, removed: false, changed: true }])).toContain("Restart to apply changes");
    expect(render([active])).toContain(">Stop</button>");
  });
  it("missing hosts disable Start while keeping rules visible", () => {
    const html = render([row()], false);
    expect(html).toContain("Host unavailable");
    expect(html).toMatch(/<button[^>]*disabled=""[^>]*>[\s\S]*?>Start<\/button>/);
  });
  it("offers a useful empty state and a loading state", () => {
    expect(render([])).toContain("Create a local, remote or SOCKS5 tunnel");
    expect(render([], false)).toContain("Add an SSH host first");
    expect(render()).toContain("Loading tunnels");
  });
  it("renders IPv6 endpoints and the actual assigned port", () => {
    const rule = row().rule; rule.forward.bind_address = "::1"; rule.forward.port = 0;
    expect(tunnelRoute(rule)).toBe("[::1]:auto → 127.0.0.1:5432");
    expect(tunnelRoute(rule, 49152)).toBe("[::1]:49152 → 127.0.0.1:5432");
    rule.forward.kind = "dynamic";
    expect(tunnelRoute(rule, 49152)).toBe("[::1]:49152 → SOCKS5");
  });
});
