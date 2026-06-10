import { create } from "zustand";
import { persist } from "zustand/middleware";

import {
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
  /** Check GitHub Releases for a newer build shortly after launch. */
  autoCheckUpdates: boolean;
  setAutoCheckUpdates: (enabled: boolean) => void;
  /** Show the menu-bar (tray) icon. Mirrored to the backend via `tray_set_visible`. */
  trayVisible: boolean;
  setTrayVisible: (visible: boolean) => void;
  /** Keep running in the menu bar when the window closes (`app_set_close_to_tray`). */
  closeToTray: boolean;
  setCloseToTray: (enabled: boolean) => void;
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
      autoCheckUpdates: true,
      setAutoCheckUpdates: (autoCheckUpdates) => set({ autoCheckUpdates }),
      trayVisible: true,
      setTrayVisible: (trayVisible) => set({ trayVisible }),
      closeToTray: false,
      setCloseToTray: (closeToTray) => set({ closeToTray }),
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
    }),
    { name: SETTINGS_STORAGE_KEY },
  ),
);
