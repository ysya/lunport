import { create } from "zustand";
import { persist } from "zustand/middleware";
import { getColorTheme, type ColorThemeId } from "@/lib/color-themes";

import {
  clampFontSize,
  DEFAULT_FONT_SIZE,
  IN_APP_TERMINAL,
  clampTerminalFontSize,
  DEFAULT_TERMINAL_FONT_SIZE,
  resolveTheme,
  systemPrefersDark,
  type ThemePref,
  type UpdateChannel,
} from "@/lib/settings-logic";

/** localStorage key for ALL persisted preferences (zustand persist envelope). */
export const SETTINGS_STORAGE_KEY = "sshelter-settings";

/** The pre-settings-store theme key, read ONCE as a migration seed (never written again). */
const LEGACY_THEME_KEY = "sshelter-theme";

/**
 * The persisted envelope's version. 1 (2026-10-25): Lunport's own terminal becomes everyone's preferred terminal once, whatever an
 * older build had saved; a terminal chosen after that is kept, as before.
 */
export const SETTINGS_VERSION = 1;

/** Brings preferences saved by an older build up to `SETTINGS_VERSION`. */
export function migrateSettings(persisted: unknown, version: number): Partial<SettingsState> {
  const state = (persisted ?? {}) as Partial<SettingsState>;
  return version < 1 ? { ...state, terminalId: IN_APP_TERMINAL } : state;
}

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

interface SettingsState {
  /** Theme preference; "system" follows the OS (resolved in `useApplyTheme`). */
  theme: ThemePref;
  setTheme: (theme: ThemePref) => void;
  colorTheme: ColorThemeId;
  setColorTheme: (theme: ColorThemeId) => void;
  /** Palette action: cycle light↔dark based on the currently RESOLVED mode. */
  toggleTheme: () => void;
  /**
   * "lunport" opens an in-app session; null uses the system default / first
   * detected external terminal. Lunport's own terminal is the default for
   * everyone (settings version 1 reset older choices once); a choice made
   * since then survives upgrades.
   */
  terminalId: string | null;
  setTerminalId: (id: string | null) => void;
  terminalFontSize: number;
  setTerminalFontSize: (size: number) => void;
  terminalCursorBlink: boolean;
  setTerminalCursorBlink: (enabled: boolean) => void;
  /** Root font-size in px (the whole UI is rem-based and scales with it). */
  fontSize: number;
  setFontSize: (px: number) => void;
  motion: "system" | "reduced";
  setMotion: (motion: "system" | "reduced") => void;
  /** Show tag chips on sidebar host rows (file grouping only). */
  showHostTags: boolean;
  setShowHostTags: (enabled: boolean) => void;
  /** Legacy alias or records:<stable host ID> → last accepted connection launch (epoch ms). */
  recentConnections: Record<string, number>;
  recordConnection: (alias: string) => void;
  /** Check GitHub Releases for a newer build shortly after launch. */
  autoCheckUpdates: boolean;
  setAutoCheckUpdates: (enabled: boolean) => void;
  /** Update channel (Settings → Updates): Stable (default) or Beta (prereleases). Read it through `normalizeUpdateChannel`. */
  updateChannel: UpdateChannel;
  setUpdateChannel: (channel: UpdateChannel) => void;
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
}

/**
 * All persistent *preferences* (the Settings window's backing store). Pure UI
 * state (search, open dialogs) stays in `useUiStore`; backend data stays in
 * TanStack Query. Preferences of the retired Legacy workspace (config path,
 * backups, discovery, drift, lint rules, file aliases) are dropped on read.
 */
export const useSettingsStore = create<SettingsState>()(
  persist(
    (set) => ({
      theme: legacyTheme(),
      setTheme: (theme) => set({ theme }),
      colorTheme: "lunport",
      setColorTheme: (colorTheme) => set({ colorTheme: getColorTheme(colorTheme).id }),
      toggleTheme: () =>
        set((s) => ({
          theme: resolveTheme(s.theme, systemPrefersDark()) === "dark" ? "light" : "dark",
        })),
      terminalId: IN_APP_TERMINAL,
      setTerminalId: (terminalId) => set({ terminalId }),
      terminalFontSize: DEFAULT_TERMINAL_FONT_SIZE,
      setTerminalFontSize: (size) => set({ terminalFontSize: clampTerminalFontSize(size) }),
      terminalCursorBlink: true,
      setTerminalCursorBlink: (terminalCursorBlink) => set({ terminalCursorBlink }),
      fontSize: DEFAULT_FONT_SIZE,
      setFontSize: (fontSize) => set({ fontSize: clampFontSize(fontSize) }),
      motion: "system",
      setMotion: (motion) => set({ motion }),
      showHostTags: true,
      setShowHostTags: (showHostTags) => set({ showHostTags }),
      recentConnections: {},
      recordConnection: (alias) =>
        set((s) => {
          const next = { ...s.recentConnections, [alias]: Date.now() };
          // Keep the map bounded: only the 20 most recent survive.
          const keep = Object.entries(next)
            .sort(([, a], [, b]) => b - a)
            .slice(0, 20);
          return { recentConnections: Object.fromEntries(keep) };
        }),
      autoCheckUpdates: true,
      setAutoCheckUpdates: (autoCheckUpdates) => set({ autoCheckUpdates }),
      updateChannel: "stable",
      setUpdateChannel: (updateChannel) => set({ updateChannel }),
      trayVisible: true,
      setTrayVisible: (trayVisible) => set({ trayVisible }),
      closeToTray: false,
      setCloseToTray: (closeToTray) => set({ closeToTray }),
      globalHotkey: false,
      setGlobalHotkey: (globalHotkey) => set({ globalHotkey }),
      newTabConnect: false,
      setNewTabConnect: (newTabConnect) => set({ newTabConnect }),
    }),
    { name: SETTINGS_STORAGE_KEY, version: SETTINGS_VERSION, migrate: migrateSettings },
  ),
);
