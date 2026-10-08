import { create } from "zustand";
import { persist } from "zustand/middleware";

import type { MoveFailure } from "@/bindings/MoveFailure";
import type { KeySetupRequest } from "@/lib/key-slots";
import type { KeychainSelection } from "@/lib/keychain";
import { DEFAULT_SIDEBAR_WIDTH, clampSidebarWidth } from "@/lib/sidebar-width";

/** What the New-config-file dialog should do after the file exists. */
export type NewFileIntent =
  | { kind: "scope" }
  | { kind: "addHost" }
  | { kind: "move"; aliases: string[] };

/**
 * localStorage key for persisted sidebar NAVIGATION state (scope + collapsed groups, width, Hosts | Keychain view) and the
 * dismissed Keychain launch hint (`launchHintDismissed`).
 */
export const UI_STORAGE_KEY = "sshelter-ui";

export type SettingsCategory =
  | "general"
  | "appearance"
  | "connection"
  | "files"
  | "ai"
  | "sync"
  | "advanced";

/** What the sidebar shows (key vault spec §7.1). */
export type SidebarView = "hosts" | "keychain";

interface UiState {
  /** Currently selected host alias in the master-detail layout (null = nothing selected). */
  selectedAlias: string | null;
  /**
   * The file of the row that was clicked. It matters only for an alias with several copies,
   * where the rows are told apart by alias AND file; null when the selection did not come from
   * a row (the command palette, a lint issue, a host just added or renamed).
   */
  selectedFile: string | null;
  /** Selects by alias alone: forgets the file. */
  setSelectedAlias: (alias: string | null) => void;
  /** Selects one row: its alias and the file it is in. */
  selectHost: (alias: string, file: string) => void;
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
  /** Sidebar grouping dimension: by source file or by tag (persisted). */
  groupMode: "file" | "tag";
  setGroupMode: (mode: "file" | "tag") => void;
  /** Sidebar width in rem, set by dragging its edge (persisted; see lib/sidebar-width). */
  sidebarWidth: number;
  setSidebarWidth: (width: number) => void;
  /** The sidebar's Hosts | Keychain switch (persisted, like its width). */
  sidebarView: SidebarView;
  setSidebarView: (view: SidebarView) => void;
  /** The key the Keychain's detail pane shows (null = none). Session-only. */
  keychainSelection: KeychainSelection | null;
  selectKey: (selection: KeychainSelection | null) => void;
  /** Switch the sidebar to the Keychain; with `selection`, show that key (Settings → Sync's Pick…). */
  openKeychain: (selection?: KeychainSelection) => void;
  /** The Keychain's launch-at-login hint was dismissed (persisted; key vault spec §5.7). */
  launchHintDismissed: boolean;
  dismissLaunchHint: () => void;
  /** The keys the last Move couldn't move, with why (key vault spec §8). Session-only. */
  moveFailures: MoveFailure[];
  setMoveFailures: (failures: MoveFailure[]) => void;
  /** Whether the "New host" dialog is open (driven by the command palette + toolbar). */
  addHostOpen: boolean;
  setAddHostOpen: (open: boolean) => void;
  /**
   * The file the right-click "New host in this file" wants the Add-host dialog
   * to preselect (null = none; the dialog falls back to fileScope). Session-only.
   */
  addHostTargetFile: string | null;
  setAddHostTargetFile: (file: string | null) => void;
  /** Host targeted by the "Deploy key" dialog (null = closed). Session-only. */
  deployKeyAlias: string | null;
  setDeployKeyAlias: (alias: string | null) => void;
  /**
   * Public key the deploy dialog should preselect: handed over by the Keychain's Export to host, which also makes the deploy
   * point the host at it (key vault spec §7.3.1). Null = derive from the host's IdentityFile. Session-only.
   */
  deployKeyInitialPub: string | null;
  setDeployKeyInitialPub: (path: string | null) => void;
  /** The handed-over key's name (a slot's name), for the deploy dialog's picker and its attach text. Session-only. */
  deployKeyInitialName: string | null;
  setDeployKeyInitialName: (name: string | null) => void;
  /** New-config-file dialog: open while non-null; says how to continue after. */
  newFileIntent: NewFileIntent | null;
  setNewFileIntent: (intent: NewFileIntent | null) => void;
  /** Whether the Settings window is open (driven by ⌘, , the toolbar gear, and the palette). */
  settingsOpen: boolean;
  setSettingsOpen: (open: boolean) => void;
  /** Settings category selected by toolbar shortcuts; session-only. */
  settingsCategory: SettingsCategory;
  setSettingsCategory: (category: SettingsCategory) => void;
  /** Whether the ⌘K command palette is open (also driven by the global quick-connect hotkey). */
  paletteOpen: boolean;
  setPaletteOpen: (open: boolean) => void;
  /**
   * The "Move hosts into a space" wizard: open while non-null; `spaceId` is the
   * space it should move hosts into (null = let the wizard pick). Session-only.
   */
  syncMigration: { spaceId: string | null } | null;
  setSyncMigration: (value: { spaceId: string | null } | null) => void;
  /** Whether the review of synced hosts waiting for approval is open (approval toast, Settings → Sync). Session-only. */
  syncApprovalsOpen: boolean;
  setSyncApprovalsOpen: (open: boolean) => void;
  /** "Keys used by synced hosts" (SP3 spec §7.1): open while non-null. Session-only. */
  keySetup: KeySetupRequest | null;
  setKeySetup: (request: KeySetupRequest | null) => void;
}

/**
 * 只放「會話內」UI 狀態，永不鏡像後端資料（後端資料由 TanStack Query 持有）。
 * 持久化偏好（theme、terminal、connection/lint/discovery 等)一律住在
 * `useSettingsStore`（zustand persist）。
 *
 * 例外：`collapsedGroups`、`fileScope`、`groupMode`、`sidebarWidth` 與 `sidebarView` 是側邊欄的「導覽／版面狀態」
 * （不是偏好設定），`launchHintDismissed` 記得 Keychain 的提示已經按掉；它們透過 `partialize` 單獨持久化到 `sshelter-ui`，其餘欄位維持 session-only。
 */
export const useUiStore = create<UiState>()(
  persist(
    (set) => ({
      selectedAlias: null,
      selectedFile: null,
      setSelectedAlias: (selectedAlias) => set({ selectedAlias, selectedFile: null }),
      selectHost: (selectedAlias, selectedFile) => set({ selectedAlias, selectedFile }),
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
      groupMode: "file",
      setGroupMode: (groupMode) => set({ groupMode }),
      sidebarWidth: DEFAULT_SIDEBAR_WIDTH,
      setSidebarWidth: (width) => set({ sidebarWidth: clampSidebarWidth(width) }),
      sidebarView: "hosts",
      setSidebarView: (sidebarView) => set({ sidebarView }),
      keychainSelection: null,
      selectKey: (keychainSelection) => set({ keychainSelection }),
      openKeychain: (selection) => set((s) => ({ sidebarView: "keychain", keychainSelection: selection ?? s.keychainSelection })),
      launchHintDismissed: false,
      dismissLaunchHint: () => set({ launchHintDismissed: true }),
      moveFailures: [],
      setMoveFailures: (moveFailures) => set({ moveFailures }),
      addHostOpen: false,
      setAddHostOpen: (addHostOpen) => set({ addHostOpen }),
      addHostTargetFile: null,
      setAddHostTargetFile: (addHostTargetFile) => set({ addHostTargetFile }),
      deployKeyAlias: null,
      setDeployKeyAlias: (deployKeyAlias) => set({ deployKeyAlias }),
      deployKeyInitialPub: null,
      setDeployKeyInitialPub: (deployKeyInitialPub) => set({ deployKeyInitialPub }),
      deployKeyInitialName: null,
      setDeployKeyInitialName: (deployKeyInitialName) => set({ deployKeyInitialName }),
      newFileIntent: null,
      setNewFileIntent: (newFileIntent) => set({ newFileIntent }),
      settingsOpen: false,
      setSettingsOpen: (settingsOpen) => set({ settingsOpen }),
      settingsCategory: "general",
      setSettingsCategory: (settingsCategory) => set({ settingsCategory }),
      paletteOpen: false,
      setPaletteOpen: (paletteOpen) => set({ paletteOpen }),
      syncMigration: null,
      setSyncMigration: (syncMigration) => set({ syncMigration }),
      syncApprovalsOpen: false,
      setSyncApprovalsOpen: (syncApprovalsOpen) => set({ syncApprovalsOpen }),
      keySetup: null,
      setKeySetup: (keySetup) => set({ keySetup }),
    }),
    {
      name: UI_STORAGE_KEY,
      // ONLY sidebar navigation/layout state and the dismissed launch hint (`launchHintDismissed`) survive restarts; everything
      // else is session-only.
      partialize: (s) => ({
        collapsedGroups: s.collapsedGroups,
        fileScope: s.fileScope,
        groupMode: s.groupMode,
        sidebarWidth: s.sidebarWidth,
        sidebarView: s.sidebarView,
        launchHintDismissed: s.launchHintDismissed,
      }),
    },
  ),
);
