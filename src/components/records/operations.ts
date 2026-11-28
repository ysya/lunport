import { connectRecordHost, type RecordOverview } from "@/lib/records";
import { selectHost } from "./editor";
import { useSettingsStore } from "@/stores/settings";
import { recentHostKey } from "./library-view";
import { IN_APP_TERMINAL } from "@/lib/settings-logic";
import type { TmuxWorkspaceLocation } from "@/lib/tmux-workspace-state";
import { useTerminalStore } from "@/stores/terminals";
export async function connectSavedHost(
  overview: RecordOverview,
  hostId: string,
  terminalId: string | null,
  newTab: boolean,
  tmux?: { resume?: TmuxWorkspaceLocation },
  placement?: "dock",
): Promise<void> {
  const host = selectHost(overview.hosts, hostId);
  if (!host)
    throw new Error(
      "The host is missing or its ID is ambiguous. Refresh the workspace.",
    );
  if (host.readiness.kind !== "ready" || host.group_error)
    throw new Error("Resolve this host's key or settings before connecting.");
  const sessions = useTerminalStore.getState();
  if (placement === "dock" && !tmux) {
    const existing = sessions.tabs.find((tab) => tab.kind === "terminal" && !tab.mode && "id" in tab.host && tab.host.id === hostId && (tab.state === "open" || tab.state === "connecting"));
    if (existing) {
      sessions.showDock(existing.id);
      return;
    }
  }
  if (placement === "dock" || tmux || terminalId === IN_APP_TERMINAL) {
    const payload = host.effective_payload;
    sessions.open({
      kind: "terminal",
      host: { id: hostId },
      name: payload.alias,
      address: `${payload.user}@${payload.hostname}:${payload.port}`,
      historyKey: recentHostKey(hostId),
      ...(tmux && { mode: "tmux", tmuxResume: tmux.resume }),
    }, placement);
    return;
  }
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
