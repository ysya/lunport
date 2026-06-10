import { create } from "zustand";

interface UiState {
  /** Currently selected host alias in the master-detail layout (null = nothing selected). */
  selectedAlias: string | null;
  setSelectedAlias: (alias: string | null) => void;
  /** Free-text host-list filter. */
  search: string;
  setSearch: (search: string) => void;
  /** Full source_file paths of collapsed sidebar groups (in-memory only). */
  collapsedGroups: string[];
  toggleGroup: (file: string) => void;
  /** Whether the "New host" dialog is open (driven by the command palette + toolbar). */
  addHostOpen: boolean;
  setAddHostOpen: (open: boolean) => void;
  /** Whether the Settings window is open (driven by ⌘, , the toolbar gear, and the palette). */
  settingsOpen: boolean;
  setSettingsOpen: (open: boolean) => void;
}

/**
 * 只放「會話內」UI 狀態，永不鏡像後端資料（後端資料由 TanStack Query 持有）。
 * 持久化偏好（theme、terminal、connection/lint/discovery 等)一律住在
 * `useSettingsStore`（zustand persist）。
 */
export const useUiStore = create<UiState>((set) => ({
  selectedAlias: null,
  setSelectedAlias: (selectedAlias) => set({ selectedAlias }),
  search: "",
  setSearch: (search) => set({ search }),
  collapsedGroups: [],
  toggleGroup: (file) =>
    set((s) => ({
      collapsedGroups: s.collapsedGroups.includes(file)
        ? s.collapsedGroups.filter((f) => f !== file)
        : [...s.collapsedGroups, file],
    })),
  addHostOpen: false,
  setAddHostOpen: (addHostOpen) => set({ addHostOpen }),
  settingsOpen: false,
  setSettingsOpen: (settingsOpen) => set({ settingsOpen }),
}));
