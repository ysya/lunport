import { create } from "zustand";
import { persist } from "zustand/middleware";

import {
  clampFontSize,
  DEFAULT_FONT_SIZE,
  defaultLintRules,
  resolveTheme,
  systemPrefersDark,
  type ThemePref,
} from "@/lib/settings-logic";

/** localStorage key for ALL persisted preferences (zustand persist envelope). */
export const SETTINGS_STORAGE_KEY = "sshelter-settings";

/** Pre-settings-store keys, read ONCE as migration seeds (never written again). */
const LEGACY_THEME_KEY = "sshelter-theme";
const LEGACY_TERMINAL_KEY = "sshelter-terminal";

/**
 * One-time migration seed: if the old standalone theme key holds an explicit
 * choice, start from it; otherwise default to following the OS. The persist
 * middleware merges `sshelter-settings` (when present) OVER these seeds, so the
 * legacy keys only matter on the very first launch after the upgrade.
 */
function legacyTheme(): ThemePref {
  if (typeof window === "undefined") return "system";
  try {
    const stored = window.localStorage.getItem(LEGACY_THEME_KEY);
    if (stored === "light" || stored === "dark") return stored;
  } catch {
    // localStorage unavailable — fall through.
  }
  return "system";
}

/** One-time migration seed for the preferred-terminal id (see {@link legacyTheme}). */
function legacyTerminalId(): string | null {
  if (typeof window === "undefined") return null;
  try {
    const stored = window.localStorage.getItem(LEGACY_TERMINAL_KEY);
    return stored && stored.length > 0 ? stored : null;
  } catch {
    return null;
  }
}

interface SettingsState {
  /** Theme preference; "system" follows the OS (resolved in `useApplyTheme`). */
  theme: ThemePref;
  setTheme: (theme: ThemePref) => void;
  /** Palette action: cycle light↔dark based on the currently RESOLVED theme. */
  toggleTheme: () => void;
  /**
   * Preferred terminal id to launch connections into (null = system default /
   * first detected). Passed as `terminalOverride` to `connect_launch`.
   */
  terminalId: string | null;
  setTerminalId: (id: string | null) => void;
  /**
   * Per-host terminal overrides (host alias → terminal id). A host's override
   * wins over the global `terminalId`; no entry = use the global preference.
   * Resolve with `resolveTerminal` from `@/lib/settings-logic`.
   */
  hostTerminals: Record<string, string>;
  /** Set or clear (null deletes the entry) the terminal override for a host. */
  setHostTerminal: (alias: string, id: string | null) => void;
  /** Root font-size in px (the whole UI is rem-based and scales with it). */
  fontSize: number;
  setFontSize: (px: number) => void;
  /** Check GitHub Releases for a newer build shortly after launch. */
  autoCheckUpdates: boolean;
  setAutoCheckUpdates: (enabled: boolean) => void;
  /** Show the menu-bar (tray) icon. Mirrored to the backend via `tray_set_visible`. */
  trayVisible: boolean;
  setTrayVisible: (visible: boolean) => void;
  /** Keep running in the menu bar when the window closes (`app_set_close_to_tray`). */
  closeToTray: boolean;
  setCloseToTray: (enabled: boolean) => void;
  /**
   * Global quick-connect hotkey (⌥⌘K / Ctrl+Alt+K): show + focus the window
   * and open the ⌘K palette from anywhere. Registration is synced by
   * `useGlobalHotkey`; this flag is only the persisted preference.
   */
  globalHotkey: boolean;
  setGlobalHotkey: (enabled: boolean) => void;
  /** Prefer opening connections in a new TAB (only honored by capable terminals). */
  newTabConnect: boolean;
  setNewTabConnect: (enabled: boolean) => void;
  /** SSH config file to load (null = `~/.ssh/config`). */
  configPath: string | null;
  setConfigPath: (path: string | null) => void;
  /** How many backups to keep (null = unlimited). Mirrored via `config_set_backup_retention`. */
  backupRetention: number | null;
  setBackupRetention: (limit: number | null) => void;
  /** Discovery sources for the Discover dialog. */
  discoverKnownHosts: boolean;
  setDiscoverKnownHosts: (enabled: boolean) => void;
  discoverTailscale: boolean;
  setDiscoverTailscale: (enabled: boolean) => void;
  /** Poll for on-disk drift automatically (in addition to focus checks). */
  driftAutoCheck: boolean;
  setDriftAutoCheck: (enabled: boolean) => void;
  driftIntervalSec: number;
  setDriftIntervalSec: (sec: number) => void;
  /** Per-rule lint toggles, keyed by the backend's stable rule ids. */
  lintRules: Record<string, boolean>;
  setLintRule: (rule: string, enabled: boolean) => void;
  /**
   * User display aliases for source config files (full path → label), shown
   * by sidebar group headers, the file-scope picker, and the Add-host target
   * picker via `labelsFor`. No entry = the automatic `shortLabels` heuristic.
   */
  fileAliases: Record<string, string>;
  /**
   * Set or clear the display alias for a file. The label is trimmed; null or
   * a blank string DELETES the entry, restoring the automatic label.
   */
  setFileAlias: (path: string, label: string | null) => void;
}

/**
 * All persistent *preferences* (the Settings window's backing store). Pure UI
 * state (selection, search, open dialogs) stays in `useUiStore`; backend data
 * stays in TanStack Query.
 */
export const useSettingsStore = create<SettingsState>()(
  persist(
    (set) => ({
      theme: legacyTheme(),
      setTheme: (theme) => set({ theme }),
      toggleTheme: () =>
        set((s) => ({
          theme: resolveTheme(s.theme, systemPrefersDark()) === "dark" ? "light" : "dark",
        })),
      terminalId: legacyTerminalId(),
      setTerminalId: (terminalId) => set({ terminalId }),
      hostTerminals: {},
      setHostTerminal: (alias, id) =>
        set((s) => {
          if (id === null) {
            if (!(alias in s.hostTerminals)) return {};
            const next = { ...s.hostTerminals };
            delete next[alias];
            return { hostTerminals: next };
          }
          return { hostTerminals: { ...s.hostTerminals, [alias]: id } };
        }),
      fontSize: DEFAULT_FONT_SIZE,
      setFontSize: (fontSize) => set({ fontSize: clampFontSize(fontSize) }),
      autoCheckUpdates: true,
      setAutoCheckUpdates: (autoCheckUpdates) => set({ autoCheckUpdates }),
      trayVisible: true,
      setTrayVisible: (trayVisible) => set({ trayVisible }),
      closeToTray: false,
      setCloseToTray: (closeToTray) => set({ closeToTray }),
      globalHotkey: false,
      setGlobalHotkey: (globalHotkey) => set({ globalHotkey }),
      newTabConnect: false,
      setNewTabConnect: (newTabConnect) => set({ newTabConnect }),
      configPath: null,
      setConfigPath: (configPath) => set({ configPath }),
      backupRetention: 20,
      setBackupRetention: (backupRetention) => set({ backupRetention }),
      discoverKnownHosts: true,
      setDiscoverKnownHosts: (discoverKnownHosts) => set({ discoverKnownHosts }),
      discoverTailscale: true,
      setDiscoverTailscale: (discoverTailscale) => set({ discoverTailscale }),
      driftAutoCheck: false,
      setDriftAutoCheck: (driftAutoCheck) => set({ driftAutoCheck }),
      driftIntervalSec: 30,
      setDriftIntervalSec: (driftIntervalSec) => set({ driftIntervalSec }),
      lintRules: defaultLintRules(),
      setLintRule: (rule, enabled) =>
        set((s) => ({ lintRules: { ...s.lintRules, [rule]: enabled } })),
      fileAliases: {},
      setFileAlias: (path, label) =>
        set((s) => {
          const trimmed = label?.trim() ?? "";
          if (trimmed === "") {
            if (!(path in s.fileAliases)) return {};
            const next = { ...s.fileAliases };
            delete next[path];
            return { fileAliases: next };
          }
          return { fileAliases: { ...s.fileAliases, [path]: trimmed } };
        }),
    }),
    { name: SETTINGS_STORAGE_KEY },
  ),
);
