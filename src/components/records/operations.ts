import { connectRecordHost, type RecordOverview } from "@/lib/records";
import { selectHost } from "./editor";
import { useSettingsStore } from "@/stores/settings";
import { recentHostKey } from "./library-view";
export async function connectSavedHost(
  overview: RecordOverview,
  hostId: string,
  terminalId: string | null,
  newTab: boolean,
): Promise<void> {
  const host = selectHost(overview.hosts, hostId);
  if (!host)
    throw new Error(
      "The host is missing or its ID is ambiguous. Refresh the workspace.",
    );
  if (host.readiness.kind !== "ready" || host.group_error)
    throw new Error("Resolve this host's key or settings before connecting.");
  await connectRecordHost(hostId, terminalId, newTab);
  try {
    useSettingsStore.getState().recordConnection(recentHostKey(hostId));
  } catch {
    // A local history write must not turn a successful terminal launch into an error.
  }
}
export function scopeLabel(
  overview: RecordOverview,
  scope: RecordOverview["hosts"][number]["scope"],
): string {
  void overview;
  void scope;
  return "Library";
}
