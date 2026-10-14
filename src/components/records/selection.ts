export type HostSelection =
  | { kind: "none" }
  | { kind: "new"; nonce: number }
  | { kind: "host"; id: string };

export function decideHostSelection(
  current: HostSelection,
  next: HostSelection,
  dirty: boolean,
  busy: boolean,
): "keep" | "confirm" | "select" {
  if (busy) return "keep";
  if (current.kind === "host" && next.kind === "host" && current.id === next.id)
    return "keep";
  return dirty ? "confirm" : "select";
}
