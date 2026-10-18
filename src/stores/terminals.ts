import { create } from "zustand";
import type { TerminalHost } from "@/lib/embedded-terminal";

export type TerminalState = "connecting" | "open" | "ended" | "error";
export type TerminalTab = {
  id: string;
  host: TerminalHost;
  name: string;
  address: string;
  historyKey: string;
  state: TerminalState;
};
type TerminalStore = {
  tabs: TerminalTab[];
  activeId: string | null;
  open: (tab: Omit<TerminalTab, "id" | "state">) => string;
  activate: (id: string | null) => void;
  updateState: (id: string, state: TerminalState) => void;
  close: (id: string) => void;
  reset: () => void;
};
/** Session metadata only. Terminal bytes, credentials and live handles are never persisted. */
export const useTerminalStore = create<TerminalStore>((set) => ({
  tabs: [], activeId: null,
  open: (input) => {
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
  close: (id) => set((current) => {
    const index = current.tabs.findIndex((tab) => tab.id === id);
    const tabs = current.tabs.filter((tab) => tab.id !== id);
    return { tabs, activeId: current.activeId === id ? tabs[Math.max(0, index - 1)]?.id ?? null : current.activeId };
  }),
  reset: () => set({ tabs: [], activeId: null }),
}));
