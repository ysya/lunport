import { describe, expect, it } from "vitest";
import { newIapTransport, type HostTransport, type PamCheck, type TransportKind } from "@/lib/transports";
import { hostPayload } from "./fixtures";
import { beginRoute, draftRoute, routeChange, routeEdited, routeProblem, withRouteHostname } from "./route";

const iap = (hostId: string): HostTransport => ({
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
const pam = (): PamCheck => ({ entitlements: ["prod-operate"], location: "global", duration_secs: 1800, justification: null });
const blank = () => newIapTransport("").kind;
const HOST = "0000000000000001";

describe("route drafts", () => {
  it("starts from the saved route and remembers IAP fields across switches", () => {
    const draft = beginRoute(null, "iap");
    const typed = { ...draft, iap: { ...draft.iap, instance: "jumpbox" } };
    expect(draftRoute({ ...typed, via: "address" })).toBeNull();
    expect(draftRoute({ ...typed, via: "iap" })?.instance).toBe("jumpbox");
  });

  it("begins on a copy of the saved route, else on Address or the IAP defaults", () => {
    const saved = iap(HOST).kind;
    const draft = beginRoute(saved);
    expect(draft).toEqual({ via: "iap", iap: saved });
    expect(draft.iap).not.toBe(saved);
    expect(beginRoute(null)).toEqual({ via: "address", iap: blank() });
    expect(beginRoute(null, "iap")).toEqual({ via: "iap", iap: blank() });
    // A saved route is where the draft starts, whatever the caller asked for.
    expect(beginRoute(saved, "address").via).toBe("iap");
  });

  it("reports a problem for an IAP route only", () => {
    expect(routeProblem(beginRoute(iap(HOST).kind))).toBeNull();
    expect(routeProblem({ via: "iap", iap: { ...iap(HOST).kind, zone: "asia east1" } })).toBe("Enter the zone of the instance.");
    // What was typed for IAP is not Address's problem.
    expect(routeProblem({ via: "address", iap: blank() })).toBeNull();
    expect(routeProblem(beginRoute(null, "address"))).toBeNull();
  });

  it("does not flag an untouched new IAP route", () => {
    expect(routeEdited(beginRoute(null, "iap"), null)).toBe(false);
    expect(routeProblem(beginRoute(null, "iap"))).toBe("Enter the Google Cloud project id.");
  });

  it("flags a new route once something is typed, and not when it is typed away again", () => {
    const fresh = beginRoute(null, "iap");
    const typed = { ...fresh, iap: { ...fresh.iap, instance: "jumpbox" } };
    expect(routeEdited(typed, null)).toBe(true);
    expect(routeEdited({ ...typed, iap: { ...typed.iap, instance: "" } }, null)).toBe(false);
    // The route that would be saved is none, as for a host that never had one.
    expect(routeEdited({ ...typed, via: "address" }, null)).toBe(false);
    expect(routeEdited(beginRoute(null, "address"), null)).toBe(false);
  });

  it("flags a saved route that would save differently or be removed", () => {
    const saved: TransportKind = { ...iap(HOST).kind, pam: pam() };
    const draft = beginRoute(saved);
    expect(routeEdited(draft, saved)).toBe(false);
    expect(routeEdited({ ...draft, iap: { ...draft.iap, zone: "asia-east1-c" } }, saved)).toBe(true);
    expect(routeEdited({ ...draft, iap: { ...draft.iap, pam: { ...pam(), entitlements: ["prod-admin"] } } }, saved)).toBe(true);
    expect(routeEdited({ ...draft, iap: { ...draft.iap, pam: null } }, saved)).toBe(true);
    expect(routeEdited({ ...draft, via: "address" }, saved)).toBe(true);
    // Switching away and back keeps the fields, so it is no edit.
    expect(routeEdited({ ...draft, via: "iap" }, saved)).toBe(false);
  });

  it("reports no change, a save or a removal", () => {
    const saved = iap(HOST);
    expect(routeChange(beginRoute(saved.kind), saved)).toBeUndefined();
    expect(routeChange({ ...beginRoute(saved.kind), via: "address" }, saved)).toEqual({ expected: saved, kind: null });
    expect(routeChange(beginRoute(null, "address"), null)).toBeUndefined();
  });

  it("saves a new route against none and an edited one against the route as displayed", () => {
    const saved = iap(HOST);
    expect(routeChange({ via: "iap", iap: saved.kind }, null)).toEqual({ expected: null, kind: saved.kind });
    const edited = { ...saved.kind, instance: "jumpbox-2", pam: pam() };
    expect(routeChange({ via: "iap", iap: edited }, saved)).toEqual({ expected: saved, kind: edited });
    // IAP fields typed and then given up for Address leave a host without a route as it was.
    expect(routeChange({ via: "address", iap: edited }, null)).toBeUndefined();
  });

  it("sends exactly the two keys the backend accepts", () => {
    const saved = iap(HOST);
    const removal = routeChange({ ...beginRoute(saved.kind), via: "address" }, saved);
    const creation = routeChange({ via: "iap", iap: saved.kind }, null);
    expect(Object.keys(removal ?? {}).sort()).toEqual(["expected", "kind"]);
    expect(Object.keys(creation ?? {}).sort()).toEqual(["expected", "kind"]);
  });

  it("compares routes by value, whatever the order the fields were built in", () => {
    const saved: HostTransport = { ...iap(HOST), kind: { ...iap(HOST).kind, pam: pam() } };
    const reordered: TransportKind = {
      pam: { justification: null, duration_secs: 1800, location: "global", entitlements: ["prod-operate"] },
      os_login: true,
      account: "frank@retower.io",
      interface: "nic0",
      instance: "jumpbox",
      zone: "asia-east1-b",
      project: "eng-dev-396409",
      type: "gcp_iap",
    };
    expect(routeChange({ via: "iap", iap: reordered }, saved)).toBeUndefined();
    expect(routeEdited({ via: "iap", iap: reordered }, saved.kind)).toBe(false);
  });

  it("gives a new IAP host the instance name as its hostname", () => {
    const draft = { ...beginRoute(null, "iap"), iap: { ...newIapTransport("").kind, instance: "jumpbox" } };
    expect(withRouteHostname(hostPayload({ hostname: "" }), draft).hostname).toBe("jumpbox");
    expect(withRouteHostname(hostPayload({ hostname: "10.0.0.8" }), draft).hostname).toBe("10.0.0.8");
  });

  it("leaves the hostname empty with Address or without an instance, and never edits the payload it is given", () => {
    const typed = { ...beginRoute(null, "iap"), iap: { ...blank(), instance: "jumpbox" } };
    const empty = hostPayload({ hostname: "" });
    expect(withRouteHostname(empty, { ...typed, via: "address" }).hostname).toBe("");
    expect(withRouteHostname(empty, beginRoute(null, "iap")).hostname).toBe("");
    withRouteHostname(empty, typed);
    expect(empty.hostname).toBe("");
  });
});
