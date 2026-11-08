import { create } from "zustand";
import { persist } from "zustand/middleware";

import { DEFAULT_HOST_PREVIEW_WIDTH, clampHostPreviewWidth } from "@/lib/host-preview-width";

/** localStorage key for persisted sidebar NAVIGATION state (the Library sidebar, collapsed Groups, the details width). */
export const UI_STORAGE_KEY = "sshelter-ui";

export type SettingsCategory =
  | "general"
  | "updates"
  | "about"
  | "appearance"
  | "connection"
  | "files"
  | "ai"
  | "sync"
  | "advanced";

interface UiState {
  /** Free-text host-list filter. */
  search: string;
  setSearch: (search: string) => void;
  /** Library navigation (persisted). */
  librarySidebarCollapsed: boolean;
  toggleLibrarySidebar: () => void;
  collapsedRecordGroups: string[];
  toggleRecordGroup: (id: string) => void;
  /** Preferred Connection details width in CSS pixels; viewport limits never overwrite it. */
  hostPreviewWidth: number;
  setHostPreviewWidth: (width: number) => void;
  /** Whether the Settings page is open (driven by ⌘, , the toolbar gear, and the palette). */
  settingsOpen: boolean;
  setSettingsOpen: (open: boolean) => void;
  /** Settings category selected by toolbar shortcuts; session-only. */
  settingsCategory: SettingsCategory;
  setSettingsCategory: (category: SettingsCategory) => void;
  /** Whether the ⌘K command palette is open (also driven by the global quick-connect hotkey). */
  paletteOpen: boolean;
  setPaletteOpen: (open: boolean) => void;
}

/**
 * 只放「會話內」UI 狀態,永不鏡像後端資料(後端資料由 TanStack Query 持有)。持久化偏好一律住在
 * `useSettingsStore`(zustand persist)。例外:`librarySidebarCollapsed`、`collapsedRecordGroups` 與
 * `hostPreviewWidth` 是側邊欄的導覽/版面狀態,透過 `partialize` 單獨持久化到 `sshelter-ui`。
 */
export const useUiStore = create<UiState>()(
  persist(
    (set) => ({
      search: "",
      setSearch: (search) => set({ search }),
      librarySidebarCollapsed: false,
      toggleLibrarySidebar: () => set((s) => ({ librarySidebarCollapsed: !s.librarySidebarCollapsed })),
      collapsedRecordGroups: [],
      toggleRecordGroup: (id) =>
        set((s) => ({
          collapsedRecordGroups: s.collapsedRecordGroups.includes(id)
            ? s.collapsedRecordGroups.filter((value) => value !== id)
            : [...s.collapsedRecordGroups, id],
        })),
      hostPreviewWidth: DEFAULT_HOST_PREVIEW_WIDTH,
      setHostPreviewWidth: (width) => set({ hostPreviewWidth: clampHostPreviewWidth(width) }),
      settingsOpen: false,
      setSettingsOpen: (settingsOpen) => set({ settingsOpen }),
      settingsCategory: "general",
      setSettingsCategory: (settingsCategory) => set({ settingsCategory }),
      paletteOpen: false,
      setPaletteOpen: (paletteOpen) => set({ paletteOpen }),
    }),
    {
      name: UI_STORAGE_KEY,
      // Only the sidebar's navigation and layout state survives restarts; everything else is session-only.
      partialize: (s) => ({
        librarySidebarCollapsed: s.librarySidebarCollapsed,
        collapsedRecordGroups: s.collapsedRecordGroups,
        hostPreviewWidth: s.hostPreviewWidth,
      }),
    },
  ),
);
