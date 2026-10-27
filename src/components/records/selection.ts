export type HostSelection =
  | { kind: "none" }
  | {
      kind: "new";
      nonce: number;
      groupId?: string;
      scope?: import("@/lib/records").HostScope;
      duplicateSource?: import("@/lib/records").RecordHostView;
      /** How the new host is reached at first: Google Cloud IAP for the Google Cloud page's New IAP host. */
      via?: "iap";
    }
  | {
      kind: "new_group";
      nonce: number;
      parentId?: string;
      scope?: import("@/lib/records").HostScope;
    }
  | { kind: "group"; id: string }
  | { kind: "host"; id: string };

export function decideHostSelection(
  current: HostSelection,
  next: HostSelection,
  dirty: boolean,
  busy: boolean,
): "keep" | "confirm" | "select" {
  if (busy) return "keep";
  if (
    (current.kind === "host" || current.kind === "group") &&
    current.kind === next.kind &&
    "id" in next &&
    current.id === next.id
  )
    return "keep";
  return dirty ? "confirm" : "select";
}
