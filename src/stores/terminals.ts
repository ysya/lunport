import { create } from "zustand";
import type { TerminalHost, TmuxSessionInfo } from "@/lib/embedded-terminal";
import { sameTmuxSession, type SessionIdentity, type TmuxWorkspaceLocation } from "@/lib/tmux-workspace-state";

export type TerminalState = "connecting" | "open" | "ended" | "error";
export type TerminalTab = {
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
type TerminalStore = {
  tabs: TerminalTab[];
  activeId: string | null;
  open: (tab: Omit<TerminalTab, "id" | "state" | "tmuxSession">) => string;
  activate: (id: string | null) => void;
  updateState: (id: string, state: TerminalState) => void;
  claimTmuxSession: (id: string, session?: TmuxSessionInfo) => boolean;
  close: (id: string) => void;
  reset: () => void;
};
function attachedTmux(tabs: TerminalTab[], historyKey: string, session: SessionIdentity, except?: string) {
  return tabs.find((tab) => tab.id !== except && tab.historyKey === historyKey &&
    (tab.state === "open" || tab.state === "connecting") && tab.tmuxSession && sameTmuxSession(tab.tmuxSession, session),
  );
}
/** Session metadata only. Terminal bytes, credentials and live handles are never persisted. */
export const useTerminalStore = create<TerminalStore>((set, get) => ({
  tabs: [], activeId: null,
  open: (input) => {
    if (input.mode === "tmux" && input.tmuxResume) {
      const existing = attachedTmux(get().tabs, input.historyKey, input.tmuxResume.session);
      if (existing) {
        set({ activeId: existing.id });
        return existing.id;
      }
    }
    const id = crypto.randomUUID();
    set((current) => {
      if (current.tabs.length >= 8) throw new Error("Close a terminal before opening another (maximum 8).");
      let name = input.name;
      let ordinal = 2;
      while (current.tabs.some((tab) => tab.name === name)) name = `${input.name} (${ordinal++})`;
      return { tabs: [...current.tabs, { ...input, name, id, state: "connecting" }], activeId: id };
    });
    return id;
  },
  activate: (id) => set((current) => id === null || current.tabs.some((tab) => tab.id === id) ? { activeId: id } : {}),
  updateState: (id, state) => set((current) => ({ tabs: current.tabs.map((tab) => tab.id === id && tab.state !== state ? { ...tab, state } : tab) })),
  claimTmuxSession: (id, session) => {
    const current = get();
    const tab = current.tabs.find((entry) => entry.id === id);
    if (tab?.mode !== "tmux") return false;
    const existing = session && attachedTmux(current.tabs, tab.historyKey, session, id);
    if (existing) {
      set({ tabs: current.tabs.filter((entry) => entry.id !== id), activeId: current.activeId === id ? existing.id : current.activeId });
      return false;
    }
    set({ tabs: current.tabs.map((entry) => entry === tab ? { ...tab, tmuxSession: session } : entry) });
    return true;
  },
  close: (id) => set((current) => {
    const index = current.tabs.findIndex((tab) => tab.id === id);
    const tabs = current.tabs.filter((tab) => tab.id !== id);
    return { tabs, activeId: current.activeId === id ? tabs[Math.max(0, index - 1)]?.id ?? null : current.activeId };
  }),
  reset: () => set({ tabs: [], activeId: null }),
}));
