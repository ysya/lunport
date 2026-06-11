import { create } from "zustand";
import { persist } from "zustand/middleware";

/** localStorage key for persisted sidebar NAVIGATION state (scope + collapsed groups). */
export const UI_STORAGE_KEY = "sshelter-ui";

interface UiState {
  /** Currently selected host alias in the master-detail layout (null = nothing selected). */
  selectedAlias: string | null;
  setSelectedAlias: (alias: string | null) => void;
  /** Free-text host-list filter. */
  search: string;
  setSearch: (search: string) => void;
  /** Full source_file paths of collapsed sidebar groups (persisted). */
  collapsedGroups: string[];
  toggleGroup: (file: string) => void;
  /**
   * Sidebar file-scope filter: a full source_file path to show ONLY that file's
   * hosts, or null for the grouped "All files" view (persisted).
   */
  fileScope: string | null;
  setFileScope: (file: string | null) => void;
  /** Whether the "New host" dialog is open (driven by the command palette + toolbar). */
  addHostOpen: boolean;
  setAddHostOpen: (open: boolean) => void;
  /** Whether the Settings window is open (driven by ⌘, , the toolbar gear, and the palette). */
  settingsOpen: boolean;
  setSettingsOpen: (open: boolean) => void;
  /** Whether the ⌘K command palette is open (also driven by the global quick-connect hotkey). */
  paletteOpen: boolean;
  setPaletteOpen: (open: boolean) => void;
}

/**
 * 只放「會話內」UI 狀態，永不鏡像後端資料（後端資料由 TanStack Query 持有）。
 * 持久化偏好（theme、terminal、connection/lint/discovery 等)一律住在
 * `useSettingsStore`（zustand persist）。
 *
 * 例外：`collapsedGroups` 與 `fileScope` 是「導覽狀態」（不是偏好設定），透過
 * `partialize` 單獨持久化到 `sshelter-ui`，其餘欄位維持 session-only。
 */
export const useUiStore = create<UiState>()(
  persist(
    (set) => ({
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
      fileScope: null,
      setFileScope: (fileScope) => set({ fileScope }),
      addHostOpen: false,
      setAddHostOpen: (addHostOpen) => set({ addHostOpen }),
      settingsOpen: false,
      setSettingsOpen: (settingsOpen) => set({ settingsOpen }),
      paletteOpen: false,
      setPaletteOpen: (paletteOpen) => set({ paletteOpen }),
    }),
    {
      name: UI_STORAGE_KEY,
      // ONLY navigation state survives restarts; everything else is session-only.
      partialize: (s) => ({ collapsedGroups: s.collapsedGroups, fileScope: s.fileScope }),
    },
  ),
);
