import type { RouteChange } from "@/bindings/RouteChange";
import type { HostPayload } from "@/lib/records";
import { newIapTransport, transportProblem, type HostTransport, type TransportKind } from "@/lib/transports";

/** How the host editor's Connect via reaches the host: at its address, or through a Google Cloud IAP route. */
export type Via = "address" | "iap";

/**
 * The route half of the host editor's draft: the choice, and the IAP fields as last typed. They stay while Address is chosen, so
 * switching back finds them; only the choice decides what is saved.
 */
export type RouteDraft = { via: Via; iap: TransportKind };

/**
 * Structural equality of plain data, whatever order the keys were built in: the backend compares routes field by field, and a route
 * read from it and one built in the editor need not list their fields alike.
 */
function sameValue(a: unknown, b: unknown): boolean {
  if (a === b) return true;
  if (typeof a !== "object" || typeof b !== "object" || a === null || b === null) return false;
  if (Array.isArray(a) || Array.isArray(b))
    return Array.isArray(a) && Array.isArray(b) && a.length === b.length && a.every((value, index) => sameValue(value, b[index]));
  const left = a as Record<string, unknown>;
  const right = b as Record<string, unknown>;
  const keys = Object.keys(left);
  return keys.length === Object.keys(right).length && keys.every((key) => key in right && sameValue(left[key], right[key]));
}

/** What a new route starts as: the IAP defaults, nothing typed. */
const blankRoute = (): TransportKind => newIapTransport("").kind;

/**
 * The draft the editor starts from: a copy of the host's saved route, else Address, or IAP for a host created from the Google Cloud
 * page's New IAP host (`initialVia`). A saved route is where the draft starts, whatever `initialVia` asks for.
 */
export function beginRoute(saved: TransportKind | null, initialVia: Via = "address"): RouteDraft {
  return saved ? { via: "iap", iap: structuredClone(saved) } : { via: initialVia, iap: blankRoute() };
}

/** The route the draft would save: none for Address. */
export const draftRoute = (draft: RouteDraft): TransportKind | null => (draft.via === "iap" ? draft.iap : null);

/** The sentence for the first bad IAP field, as `transportProblem` words it; Address has no route to be wrong. */
export function routeProblem(draft: RouteDraft): string | null {
  return draft.via === "iap" ? transportProblem({ host_id: "", kind: draft.iap }) : null;
}

/**
 * Whether the draft differs from the saved route, for the editor's unsaved-changes state and for when to show `routeProblem`. A new
 * IAP route with nothing typed in it is not an edit yet (a new host's empty fields are not either), though it is not yet saveable.
 */
export function routeEdited(draft: RouteDraft, saved: TransportKind | null): boolean {
  const route = draftRoute(draft);
  if (saved === null) return route !== null && !sameValue(route, blankRoute());
  return !sameValue(route, saved);
}

/**
 * The route half of the save command: the route as the editor displayed it (`expected`) and the route to save (`kind`, none to remove
 * it); `undefined` when the draft leaves the route as it is, so the host is saved without touching it, as the backend does for a
 * change that is none.
 */
export function routeChange(draft: RouteDraft, saved: HostTransport | null): RouteChange | undefined {
  const kind = draftRoute(draft);
  return sameValue(kind, saved?.kind ?? null) ? undefined : { expected: saved, kind };
}

/**
 * The payload to save with the draft: the host record still needs a hostname, which the editor does not show for an IAP route, so a
 * new host with none takes the instance name. A hostname the host has keeps.
 */
export function withRouteHostname(payload: HostPayload, draft: RouteDraft): HostPayload {
  return draft.via === "iap" && payload.hostname === "" ? { ...payload, hostname: draft.iap.instance } : payload;
}
