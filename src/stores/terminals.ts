import { create } from "zustand";
import type { TerminalHost, TmuxSessionInfo } from "@/lib/embedded-terminal";
import { sameTmuxSession, type SessionIdentity, type TmuxWorkspaceLocation } from "@/lib/tmux-workspace-state";
import type { DatabaseEnvironment } from "@/bindings/DatabaseEnvironment";
import type { ReadOnlyMode } from "@/bindings/ReadOnlyMode";

export type TerminalState = "connecting" | "open" | "ended" | "error";
export type TerminalTab = {
  kind: "terminal";
  id: string;
  host: TerminalHost;
  name: string;
  address: string;
  historyKey: string;
  mode?: "tmux";
  tmuxResume?: TmuxWorkspaceLocation;
  tmuxSession?: TmuxSessionInfo;
  state: TerminalState;
};
type DatabaseTabOptions = {
  kind: "database";
  databaseId: string;
  name: string;
  address: string;
} & (
  | { environment: DatabaseEnvironment; readOnly: Exclude<ReadOnlyMode, "standard">; postgresRevision?: never }
  | { environment: null; readOnly: "standard"; postgresRevision: string }
);
export type DatabaseTab = DatabaseTabOptions & { id: string; state: TerminalState };
export type SessionTab = TerminalTab | DatabaseTab;
type TerminalStore = {
  tabs: SessionTab[];
  activeId: string | null;
  dockedId: string | null;
  dockMaximized: boolean;
  open: (tab: Omit<TerminalTab, "id" | "state" | "tmuxSession"> | DatabaseTabOptions, placement?: "dock") => string;
  showDock: (id: string) => void;
  hideDock: () => void;
  setDockMaximized: (maximized: boolean) => void;
  setReadOnly: (id: string, readOnly: Exclude<ReadOnlyMode, "standard">) => void;
  activate: (id: string | null) => void;
  updateState: (id: string, state: TerminalState) => void;
  claimTmuxSession: (id: string, session?: TmuxSessionInfo) => boolean;
  close: (id: string) => void;
  reset: () => void;
};
function attachedTmux(tabs: SessionTab[], historyKey: string, session: SessionIdentity, except?: string) {
  return tabs.find((tab): tab is TerminalTab => tab.kind === "terminal" && tab.id !== except && tab.historyKey === historyKey &&
    (tab.state === "open" || tab.state === "connecting") && !!tab.tmuxSession && sameTmuxSession(tab.tmuxSession, session),
  );
}
/** Session metadata only. Terminal bytes, credentials and live handles are never persisted. */
export const useTerminalStore = create<TerminalStore>((set, get) => ({
  tabs: [], activeId: null, dockedId: null, dockMaximized: false,
  open: (input, placement) => {
    const current = get();
    const dock = placement === "dock" && input.kind === "terminal" && current.tabs.some((tab) => tab.id === current.activeId && tab.kind === "database");
    if (input.kind === "terminal" && input.mode === "tmux" && input.tmuxResume) {
      const existing = attachedTmux(current.tabs, input.historyKey, input.tmuxResume.session);
      if (existing) {
        if (dock) current.showDock(existing.id);
        else current.activate(existing.id);
        return existing.id;
      }
    }
    const id = crypto.randomUUID();
    set((current) => {
      if (current.tabs.length >= 8) throw new Error("Close a tab before opening another (maximum 8).");
      let name = input.name;
      let ordinal = 2;
      while (current.tabs.some((tab) => tab.name === name)) name = `${input.name} (${ordinal++})`;
      return {
        tabs: [...current.tabs, { ...input, name, id, state: "connecting" }],
        ...(dock ? { dockedId: id } : { activeId: id, dockMaximized: false }),
      };
    });
    return id;
  },
  showDock: (id) => set((current) => current.tabs.some((tab) => tab.id === id && tab.kind === "terminal") ? { dockedId: id } : {}),
  hideDock: () => set({ dockedId: null, dockMaximized: false }),
  setDockMaximized: (dockMaximized) => set((current) => current.dockedId ? { dockMaximized } : {}),
  setReadOnly: (id, readOnly) => set((current) => ({ tabs: current.tabs.map((tab) => tab.id === id && tab.kind === "database" && tab.environment !== null && tab.readOnly !== readOnly ? { ...tab, readOnly } : tab) })),
  activate: (id) => set((current) => id === null || current.tabs.some((tab) => tab.id === id) ? { activeId: id, dockMaximized: false } : {}),
  updateState: (id, state) => set((current) => ({ tabs: current.tabs.map((tab) => tab.id === id && tab.state !== state ? { ...tab, state } : tab) })),
  claimTmuxSession: (id, session) => {
    const current = get();
    const tab = current.tabs.find((entry) => entry.id === id);
    if (tab?.kind !== "terminal" || tab.mode !== "tmux") return false;
    const existing = session && attachedTmux(current.tabs, tab.historyKey, session, id);
    if (existing) {
      set({
        tabs: current.tabs.filter((entry) => entry.id !== id),
        activeId: current.activeId === id ? existing.id : current.activeId,
        dockedId: current.dockedId === id ? existing.id : current.dockedId,
      });
      return false;
    }
    set({ tabs: current.tabs.map((entry) => entry === tab ? { ...tab, tmuxSession: session } : entry) });
    return true;
  },
  close: (id) => set((current) => {
    const index = current.tabs.findIndex((tab) => tab.id === id);
    const tabs = current.tabs.filter((tab) => tab.id !== id);
    return {
      tabs,
      ...(current.activeId === id ? { activeId: tabs[Math.max(0, index - 1)]?.id ?? null, dockMaximized: false } : {}),
      ...(current.dockedId === id ? { dockedId: null, dockMaximized: false } : {}),
    };
  }),
  reset: () => set({ tabs: [], activeId: null, dockedId: null, dockMaximized: false }),
}));
