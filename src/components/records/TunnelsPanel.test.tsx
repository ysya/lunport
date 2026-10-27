import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it, vi } from "vitest";
import { TunnelsPanel } from "./TunnelsPanel";
import { hostPayload, hostTransport, hostView, recordOverview } from "./fixtures";
import { text } from "@/components/keychain/test-markup";
import { tauriInvoke } from "@/lib/ipc";
import type { RecordHostView, RecordOverview } from "@/lib/records";
import { tunnelGrantLine, type PamStatusView } from "@/lib/transports";
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

/*
 * Design 2026-10-26, Tunnels through a host that needs a grant. The rows read the grant through the backend, which a server render
 * never does: `renderTunnels` draws the panel once, which makes the grant queries its rows hold, runs those queries through the real
 * fetcher against the mocked command, and draws the panel again with what they found.
 */
describe("the grant a tunnel's first hop needs", () => {
  const AT = new Date(2026, 9, 27, 10, 0).getTime(); // 10:00 on this computer's clock
  const pam = { entitlements: ["prod-operate", "prod-admin"], location: "global", duration_secs: 1800, justification: null };
  const host = (n: number, alias: string): RecordHostView => hostView({ id: String(n).padStart(16, "0"), payload: hostPayload({ alias, hostname: `10.0.0.${n}` }) });
  /** `base` reached through the saved hosts `jump`, in this order. */
  const withJumps = (base: RecordHostView, jump: string[]): RecordHostView => hostView({ id: base.id, payload: hostPayload({ ...base.payload, jump }) });
  const pamHost = host(1, "db-1");
  const plainHost = host(2, "web-1");
  const pamJump = host(3, "jump-1");
  const internalHost = host(4, "internal-1");
  const routedHost = host(5, "api-1");
  const routes = [
    hostTransport({ instance: "db-1", pam }, pamHost.id),
    hostTransport({ instance: "jump-1", pam }, pamJump.id),
    hostTransport({ instance: "api-1" }, routedHost.id), // a route without a PAM check
  ];
  const active: PamStatusView = { entitlement: "prod-operate", state: "active", active_until_ms: AT, message: null };
  const activating: PamStatusView = { entitlement: "prod-admin", state: "activating", active_until_ms: null, message: null };
  const none: PamStatusView = { entitlement: null, state: "none", active_until_ms: null, message: null };
  const refused = "Privileged Access Manager refused the request: quota exceeded.";
  const unchecked: PamStatusView = { entitlement: null, state: "error", active_until_ms: null, message: refused };

  type Library = { overview: RecordOverview; tunnels: TunnelView[] };
  const tunnelTo = (target: RecordHostView, id = "0000000000000020"): TunnelView => row({ rule: { ...row().rule, id, host_id: target.id } });
  /** The hosts given, then every host above that is not among them, with the routes above; and these tunnels. */
  const libraryOf = (hosts: RecordHostView[], tunnels: TunnelView[]): Library => {
    const others = [pamHost, plainHost, pamJump, internalHost, routedHost].filter((plain) => !hosts.some((given) => given.id === plain.id));
    return { overview: recordOverview({ hosts: [...hosts, ...others], transports: routes }), tunnels };
  };
  const overviewWithTunnelThrough = (target: RecordHostView): Library => libraryOf([target], [tunnelTo(target)]);
  /** A tunnel to `target`, reached through `jump`. */
  const overviewWithTunnelBehind = (target: RecordHostView, jump: RecordHostView): Library => {
    const behind = withJumps(target, [jump.id]);
    return libraryOf([behind], [tunnelTo(behind)]);
  };

  const invoke = vi.mocked(tauriInvoke);
  const lastInvoke = (command: string) => invoke.mock.calls.filter(([name]) => name === command).slice(-1)[0]?.[1] as Record<string, unknown>;
  const grantQueries = (client: QueryClient) => client.getQueryCache().findAll({ queryKey: ["gcp", "pam-status"] });

  /** The panel once the grants its rows read are answered: `pamStatus` (else an active prod-operate grant until 10:00), or that error. */
  async function renderTunnels({ overview, tunnels }: Library, answers: { pamStatus?: PamStatusView | Error } = {}) {
    invoke.mockReset();
    invoke.mockImplementation(async (command: string) => {
      if (command !== "transports_pam_status") throw new Error(`unexpected command ${command}`);
      const answer = answers.pamStatus ?? active;
      if (answer instanceof Error) throw answer;
      return answer;
    });
    // A mounting row reads again whatever the last read found; this one draws what that read left, even a failure.
    const client = new QueryClient({ defaultOptions: { queries: { retryOnMount: false } } });
    client.setQueryData(tunnelsKey, tunnels);
    const draw = () => renderToStaticMarkup(<QueryClientProvider client={client}><TunnelsPanel overview={overview} /></QueryClientProvider>);
    draw();
    await Promise.all(grantQueries(client).map((query) => query.fetch().catch(() => undefined)));
    return { client, text: text(draw()) };
  }
  const renderTunnelsText = async (library: Library, answers: { pamStatus?: PamStatusView | Error } = {}) => (await renderTunnels(library, answers)).text;
  /** The panel shows no grant line for the tunnels of `library`, holds no grant query and reads nothing. */
  async function expectNoGrantLine(library: Library) {
    const { client, text: shown } = await renderTunnels(library);
    expect(shown).not.toContain("grant");
    expect(grantQueries(client)).toHaveLength(0);
    expect(invoke).not.toHaveBeenCalled();
  }

  it("shows the grant a tunnel's first hop needs", async () => {
    const shown = await renderTunnelsText(overviewWithTunnelThrough(pamHost)); // transports_pam_status: prod-operate active until 10:00
    expect(shown).toContain("prod-operate · Active until 10:00");
    expect(lastInvoke("transports_pam_status").hostId).toBe(pamHost.id);
  });
  it("shows an activating grant as the details pane does", async () => {
    expect(await renderTunnelsText(overviewWithTunnelThrough(pamHost), { pamStatus: activating })).toContain("prod-admin · Activating…");
  });
  it("says a grant is needed when none is active", async () => {
    expect(await renderTunnelsText(overviewWithTunnelThrough(pamHost), { pamStatus: none })).toContain("Needs a grant: prod-operate, prod-admin");
  });
  it("says why the grant could not be checked instead of saying one is needed", async () => {
    const answered = await renderTunnelsText(overviewWithTunnelThrough(pamHost), { pamStatus: unchecked });
    expect(answered).toContain(refused);
    expect(answered).not.toContain("Needs a grant");
    // The command itself failing reads the same way.
    const failed = await renderTunnelsText(overviewWithTunnelThrough(pamHost), { pamStatus: new Error("Google did not answer.") });
    expect(failed).toContain("Google did not answer.");
    expect(failed).not.toContain("Needs a grant");
  });
  it("reads the grant of the first jump host", async () => {
    await renderTunnelsText(overviewWithTunnelBehind(internalHost, pamJump));
    expect(lastInvoke("transports_pam_status").hostId).toBe(pamJump.id);
  });
  it("follows the first jump host's own first jump host, as the backend chains them", async () => {
    // internal-1 is reached through web-1, which is reached through jump-1: jump-1 is dialed first.
    const middle = withJumps(plainHost, [pamJump.id]);
    const behind = withJumps(internalHost, [middle.id]);
    expect(await renderTunnelsText(libraryOf([middle, behind], [tunnelTo(behind)]))).toContain("prod-operate · Active until 10:00");
    expect(lastInvoke("transports_pam_status").hostId).toBe(pamJump.id);
  });
  it("shows no grant line for a tunnel whose first hop needs none", async () => {
    await expectNoGrantLine(overviewWithTunnelThrough(plainHost));
    await expectNoGrantLine(overviewWithTunnelThrough(routedHost));
    // Behind a jump host that needs none, a host's own PAM check is not the tunnel's: the jump host is dialed first.
    await expectNoGrantLine(overviewWithTunnelBehind(pamHost, plainHost));
  });
  it("shows no grant line when the first hop cannot be found", async () => {
    // A jump host this computer has not got, though a route with a PAM check names it.
    const gone = host(99, "gone-1");
    const missing = overviewWithTunnelBehind(internalHost, gone);
    await expectNoGrantLine({ ...missing, overview: { ...missing.overview, transports: [...routes, hostTransport({ instance: "gone-1", pam }, gone.id)] } });
    // Jump hosts that go round in a circle, through a host whose route has a PAM check: a tunnel to either has no first hop.
    const loop = withJumps(pamJump, [internalHost.id]);
    const looped = withJumps(internalHost, [loop.id]);
    await expectNoGrantLine(libraryOf([loop, looped], [tunnelTo(loop, "0000000000000021"), tunnelTo(looped, "0000000000000022")]));
  });
  it("reads a first hop's grant once for every tunnel through it", async () => {
    const { client, text: shown } = await renderTunnels(libraryOf([], [tunnelTo(pamHost, "0000000000000021"), tunnelTo(pamHost, "0000000000000022")]));
    expect(grantQueries(client)).toHaveLength(1);
    expect(invoke.mock.calls.filter(([name]) => name === "transports_pam_status")).toHaveLength(1);
    expect(shown.match(/prod-operate · Active until 10:00/g)).toHaveLength(2);
  });
  it("words the row's line from the grant read and the route's entitlements", () => {
    expect(tunnelGrantLine(active, pam)).toBe("prod-operate · Active until 10:00");
    expect(tunnelGrantLine({ ...active, active_until_ms: null }, pam)).toBe("prod-operate · Active");
    expect(tunnelGrantLine(activating, pam)).toBe("prod-admin · Activating…");
    // A grant waiting for its approver is said as such, not as a missing one (design 2026-10-27).
    expect(tunnelGrantLine({ ...activating, state: "approval_awaited" }, pam)).toBe("prod-admin · Awaiting approval");
    expect(tunnelGrantLine(none, pam)).toBe("Needs a grant: prod-operate, prod-admin");
    expect(tunnelGrantLine(none, { ...pam, entitlements: ["prod-deploy"] })).toBe("Needs a grant: prod-deploy");
    expect(tunnelGrantLine(unchecked, pam)).toBe(refused);
    expect(tunnelGrantLine({ ...unchecked, message: null }, pam)).toBe("The grant could not be checked.");
  });
});
