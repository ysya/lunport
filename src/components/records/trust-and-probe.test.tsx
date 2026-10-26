import { afterEach, describe, expect, it, vi } from "vitest";
import type { ReactElement, ReactNode } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { renderHook, stubBackend } from "@/lib/test-ipc";
import { buttonsIn, buttonTag, DISABLED, elementsOf, text, textIn } from "@/components/keychain/test-markup";
import { Dialog } from "@/components/ui/dialog";
import { hostPayload, hostTransport, hostView } from "./fixtures";
import { TrustedHostRow } from "./KnownHostsManager";
import {
  checkTarget,
  ConnectionCheck,
  ConnectionCheckView,
  iapProbeLabel,
  probeLabel,
  runCheck,
  type CheckOutcome,
  type ConnectionCheckViewProps,
} from "./ConnectionCheck";
import { GrantRequestCardView, GrantRequestDialog, grantRequestDefaults, requestGrant, type GrantRequestCardViewProps } from "./GrantRequestDialog";
import { forgetRecordHostKey, probeRecordHost, setRecordGroupOrder, type ConnectionProbe, type RecordHostView } from "@/lib/records";
import type { HostTransport, IapProbeView, PamStatusView } from "@/lib/transports";
import { KnownHostsFilePanel } from "@/components/KnownHostsDialog";
import { queryKeys } from "@/lib/queries";
afterEach(() => vi.unstubAllGlobals());
/**
 * The element tree a component with hooks draws on its first render. A server render keeps no state update and runs no effect, so
 * what the tree's callbacks start (a request to the backend) is real, and what they would then show is not drawn.
 */
const firstRender = (draw: () => ReactNode): ReactNode => renderHook(new QueryClient(), draw);

describe("host trust and reachability", () => {
  it("renders the populated OpenSSH tab without requiring a Legacy tooltip provider", () => {
    const client = new QueryClient();
    client.setQueryData(queryKeys.knownHosts,[{line_index:0,line_hash:"a".repeat(64),hosts:"fixture.test",key_type:"ssh-ed25519",fingerprint_sha256:"SHA256:fixture",hashed:false,marker:null}]);
    const html = renderToStaticMarkup(<QueryClientProvider client={client}><KnownHostsFilePanel /></QueryClientProvider>);
    expect(html).toContain("fixture.test");
    expect(html).toContain("SHA256:fixture");
  });
  it("passes the exact displayed identity and large revision tokens when forgetting trust", async () => {
    const host=hostView();
    host.payload.host_key={algorithm:"ssh-ed25519",public_key:"public-blob",fingerprint:"SHA256:fixture",pinned_at_ms:1,pinned_by_device_id:"d".repeat(32)};
    const calls=stubBackend(async () => null);
    await forgetRecordHostKey(host);
    await probeRecordHost(host.id);
    const order={ids:["b"],revision:host.revision,blocked:false,sync_enabled:true};
    await setRecordGroupOrder(order,["a","b"]);
    expect(calls).toEqual([
      ["records_host_forget_key",{id:host.id,revision:host.revision,hostname:host.effective_payload.hostname,port:host.effective_payload.port,expectedPin:host.payload.host_key}],
      ["records_host_probe",{hostId:host.id}],
      ["records_group_order",{expectedIds:["b"],revision:host.revision,ids:["a","b"]}],
    ]);
  });
  it("identifies the saved fingerprint and its source without exposing key material", () => {
    const host=hostView();
    host.payload.host_key={algorithm:"ssh-ed25519",public_key:"public-blob",fingerprint:"SHA256:fixture",pinned_at_ms:1,pinned_by_device_id:"d".repeat(32)};
    const html=renderToStaticMarkup(<TrustedHostRow host={host} disabled={false} verifying={false} verify={()=>{}} forget={()=>{}} />);
    expect(html).toContain("SHA256:fixture");
    expect(html).toContain("Local host");
    expect(html).toContain("Forget identity");
    expect(html).not.toContain("public-blob");
  });
  it("labels a TCP result separately from SSH login or host online status", () => {
    const result:ConnectionProbe={host_id:"a",hostname:"fixture",port:22,status:"reachable",latency_ms:7,elapsed_ms:10,checked_at_ms:1};
    expect(probeLabel(result)).toBe("Port reachable · 7 ms");
    expect(probeLabel({...result,status:"timed_out"})).toBe("Connection timed out");
    expect(probeLabel({...result,status:"requires_jump"})).toBe("Uses a jump host");
    expect(probeLabel({...result,status:"settings_changed"})).toContain("check again");
  });
});

describe("checking a host through its IAP route", () => {
  const host = hostView({ payload: hostPayload({ alias: "web-1" }) });
  const route = hostTransport();
  const probe = (patch: Partial<IapProbeView> = {}): IapProbeView => ({
    status: "reachable",
    latency_ms: 182,
    elapsed_ms: 240,
    checked_at_ms: 1,
    message: null,
    ...patch,
  });
  const idle = (on: HostTransport | null): ConnectionCheckViewProps => ({ route: on, groupError: false, busy: false, outcome: null, error: null, onCheck: () => {} });
  const pane = (props: Partial<ConnectionCheckViewProps> & { route: HostTransport | null }) =>
    renderToStaticMarkup(<ConnectionCheckView {...idle(props.route)} {...props} />);
  /** The pane as a press on its button leaves it: the check ran against the stubbed backend and the pane shows what it found. */
  async function clickCheck(checked: RecordHostView, on: HostTransport | null): Promise<string> {
    let running: Promise<CheckOutcome> | undefined;
    const before = { ...idle(on), onCheck: () => { running = runCheck(checked, on); } };
    const button = buttonsIn(ConnectionCheckView(before)).find((candidate) => textIn(candidate).startsWith("Check "));
    button!.props.onClick!();
    return text(renderToStaticMarkup(<ConnectionCheckView {...before} outcome={await running!} />));
  }
  const answering = (reply: unknown) => stubBackend(async () => reply);

  it("words what IAP found, and says why it did not reach the instance", () => {
    expect(iapProbeLabel(probe())).toBe("Reachable through IAP · 182 ms");
    expect(iapProbeLabel(probe({ latency_ms: null }))).toBe("Reachable through IAP");
    expect(iapProbeLabel(probe({ status: "denied", message: "IAP refused this Google account." }))).toBe("IAP refused this Google account.");
    expect(iapProbeLabel(probe({ status: "unreachable", message: "IAP did not answer in time." }))).toBe("IAP did not answer in time.");
    // A check that carries no sentence still says what happened, and a status this release does not know reads as unreachable.
    expect(iapProbeLabel(probe({ status: "denied", message: null }))).toBe("IAP refused this Google account.");
    expect(iapProbeLabel(probe({ status: "unreachable", message: null }))).toBe("Could not reach the instance's port through IAP.");
    expect(iapProbeLabel(probe({ status: "something-new", message: null }))).toBe("Could not reach the instance's port through IAP.");
  });

  it("checks an IAP host through IAP", async () => {
    const calls = answering(probe()); // transports_iap_probe answers reachable, 182 ms
    const shown = await clickCheck(host, route);
    expect(calls).toEqual([["transports_iap_probe", { hostId: host.id }]]);
    expect(shown).toContain("Reachable through IAP · 182 ms");
    expect(shown).toContain("240 ms total");
  });

  it("shows the sentence IAP gave when it refused or did not answer", async () => {
    answering(probe({ status: "denied", latency_ms: null, message: "IAP refused this Google account. Request a grant first." }));
    expect(await clickCheck(host, route)).toContain("IAP refused this Google account. Request a grant first.");
    answering(probe({ status: "unreachable", latency_ms: null, message: "IAP did not answer in time." }));
    const shown = await clickCheck(host, route);
    expect(shown).toContain("IAP did not answer in time.");
    expect(shown).not.toContain("Reachable");
  });

  it("keeps checking an address host at its saved port", async () => {
    const calls = answering({ host_id: host.id, hostname: "fixture.invalid", port: 22, status: "reachable", latency_ms: 7, elapsed_ms: 10, checked_at_ms: 1 });
    const shown = await clickCheck(host, null);
    expect(calls).toEqual([["records_host_probe", { hostId: host.id }]]);
    expect(shown).toContain("Port reachable · 7 ms");
    expect(shown).toContain("Check port");
    // The jump route's pointer belongs to the port check.
    answering({ host_id: host.id, hostname: "fixture.invalid", port: 22, status: "requires_jump", latency_ms: null, elapsed_ms: 1, checked_at_ms: 1 });
    expect(await clickCheck(host, null)).toContain("Verify fingerprint");
    answering(probe());
    expect(await clickCheck(host, route)).not.toContain("Verify fingerprint");
  });

  it("words the pane for the route, and keeps its button off while a check runs or the Group needs review", () => {
    const iapPane = pane({ route });
    expect(text(iapPane)).toContain("Check whether this computer reaches the instance's port through IAP with its Google sign-in. Login and server identity are verified separately.");
    expect(buttonTag(iapPane, "Check through IAP")).not.toContain(DISABLED);
    expect(buttonTag(pane({ route, busy: true }), "Checking…")).toContain(DISABLED);
    expect(buttonTag(pane({ route, groupError: true }), "Check through IAP")).toContain(DISABLED);
    const portPane = pane({ route: null });
    expect(text(portPane)).toContain("Check whether the saved TCP port can be reached from this computer.");
    expect(buttonTag(portPane, "Check port")).not.toContain(DISABLED);
    expect(text(portPane)).not.toContain("through IAP");
    expect(pane({ route, error: "Invalid host identity." })).toContain('role="alert"');
  });

  it("runs the check the pane is worded for when its button is pressed", async () => {
    const press = async (on: HostTransport | null) => {
      const pane = firstRender(() => ConnectionCheck({ host, transport: on })) as ReactElement<ConnectionCheckViewProps>;
      pane.props.onCheck();
      await new Promise((resolve) => setTimeout(resolve, 0));
    };
    const calls = answering(probe());
    await press(route);
    expect(calls.map(([command]) => command)).toEqual(["transports_iap_probe"]);
    await press(null);
    expect(calls.map(([command]) => command)).toEqual(["transports_iap_probe", "records_host_probe"]);
    // A caller that passes no route gets the port check.
    const bare = firstRender(() => ConnectionCheck({ host })) as ReactElement<ConnectionCheckViewProps>;
    expect(bare.props.route).toBeNull();
  });

  it("starts over when the route or the port changes, since the IAP answer names no host", () => {
    const base = checkTarget(host, route);
    // The same host and route read again from a refreshed overview are the same check.
    expect(checkTarget(structuredClone(host), structuredClone(route))).toBe(base);
    expect(checkTarget(host, hostTransport({ zone: "asia-east1-c" }))).not.toBe(base);
    expect(checkTarget(host, hostTransport({ account: "ops@example.com" }))).not.toBe(base);
    expect(checkTarget(host, null)).not.toBe(base);
    expect(checkTarget(host, undefined)).toBe(checkTarget(host, null));
    expect(checkTarget(hostView({ payload: hostPayload({ alias: "web-1", port: 2222 }) }), route)).not.toBe(base);
    expect(checkTarget(hostView({ payload: hostPayload({ alias: "web-1", hostname: "other.invalid" }) }), route)).not.toBe(base);
    // A rename changes nothing the check depends on.
    expect(checkTarget(hostView({ payload: hostPayload({ alias: "renamed" }) }), route)).toBe(base);
  });
});

describe("requesting a grant for a host's route", () => {
  const host = hostView();
  const pamRoute = (seconds = 1800) =>
    hostTransport({ pam: { entitlements: ["prod-operate", "prod-admin"], location: "global", duration_secs: seconds, justification: null } });

  it("prefills a request from this computer's memory, else the route's default length", () => {
    expect(grantRequestDefaults(pamRoute(1800), { host_id: host.id, justification: "Deploy hotfix", duration_secs: 2700 })).toEqual({
      justification: "Deploy hotfix",
      minutes: "45",
    });
    expect(grantRequestDefaults(pamRoute(1800), null)).toEqual({ justification: "", minutes: "30" });
    expect(grantRequestDefaults(pamRoute(5400), null)).toEqual({ justification: "", minutes: "90" });
    // A justification an earlier release saved in the route is not offered; only this computer's own memory is.
    const old = hostTransport({ pam: { entitlements: ["prod-operate"], location: "global", duration_secs: 1800, justification: "restart app-api" } });
    expect(grantRequestDefaults(old, null).justification).toBe("");
    expect(grantRequestDefaults(hostTransport(), null)).toEqual({ justification: "", minutes: "30" });
  });

  it("asks for the entitlement it is given, else leaves the first to the backend", async () => {
    const calls = stubBackend(async () => ({ entitlement: "prod-admin", state: "activating", active_until_ms: null, message: null }));
    await requestGrant(pamRoute(), "prod-admin", "  Deploy hotfix  ", "45");
    await requestGrant(pamRoute(), undefined, "Deploy hotfix", "30");
    expect(calls).toEqual([
      ["transports_pam_request", { hostId: host.id, justification: "Deploy hotfix", durationSecs: 2700, entitlement: "prod-admin" }],
      ["transports_pam_request", { hostId: host.id, justification: "Deploy hotfix", durationSecs: 1800 }],
    ]);
  });

  it("starts the dialog from this computer's memory and requests the entitlement it was given", async () => {
    const granted: PamStatusView = { entitlement: "prod-admin", state: "activating", active_until_ms: null, message: null };
    const calls = stubBackend(async () => granted);
    const onRequested = vi.fn();
    const dialog = (props: Partial<Parameters<typeof GrantRequestDialog>[0]>) =>
      elementsOf(
        firstRender(() => GrantRequestDialog({ transport: pamRoute(), alias: "web-1", onClose: () => {}, onRequested, ...props })),
        GrantRequestCardView,
      )[0].props as unknown as GrantRequestCardViewProps;
    const card = dialog({ entitlement: "prod-admin", memory: { host_id: host.id, justification: "Deploy hotfix", duration_secs: 2700 } });
    expect(card).toMatchObject({ entitlement: "prod-admin", justification: "Deploy hotfix", minutes: "45", busy: false });
    card.onRequest();
    await vi.waitFor(() => expect(onRequested).toHaveBeenCalledWith(granted));
    expect(calls).toEqual([["transports_pam_request", { hostId: host.id, justification: "Deploy hotfix", durationSecs: 2700, entitlement: "prod-admin" }]]);
    // A caller that names no entitlement and passes no memory gets the route's first entitlement and its default length.
    expect(dialog({ transport: pamRoute(5400) })).toMatchObject({ entitlement: undefined, justification: "", minutes: "90" });
  });

  it("names the entitlement being requested", () => {
    const view = (entitlement?: string) =>
      text(
        renderToStaticMarkup(
          <Dialog open>
            <GrantRequestCardView transport={pamRoute()} entitlement={entitlement} alias="web-1" justification="" minutes="30" busy={false} result={null} error={null}
              onJustification={() => {}} onMinutes={() => {}} onRequest={() => {}} onClose={() => {}} />
          </Dialog>,
        ),
      );
    expect(view()).toContain("grant on prod-operate for web-1");
    expect(view("prod-admin")).toContain("grant on prod-admin for web-1");
    expect(view("prod-admin")).not.toContain("prod-operate");
  });
});
