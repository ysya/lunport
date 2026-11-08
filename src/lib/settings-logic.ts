import type { TerminalInfo } from "@/bindings/TerminalInfo";

export const IN_APP_TERMINAL = "lunport";
export const DEFAULT_TERMINAL_FONT_SIZE = 14;
export function clampTerminalFontSize(value: unknown): number {
  return typeof value === "number" && Number.isInteger(value) && value >= 10 && value <= 24 ? value : DEFAULT_TERMINAL_FONT_SIZE;
}

/** The persisted theme preference: explicit, or follow the OS. */
export type ThemePref = "system" | "light" | "dark";
/** What actually gets applied to the document. */
export type ResolvedTheme = "light" | "dark";

/** Resolve a theme preference to a concrete light/dark value. Pure — testable. */
export function resolveTheme(pref: ThemePref, systemDark: boolean): ResolvedTheme {
  if (pref === "system") return systemDark ? "dark" : "light";
  return pref;
}

/**
 * Whether the OS currently prefers dark. Defaults to dark when `matchMedia` is
 * unavailable (matches the app's historical default).
 */
export function systemPrefersDark(): boolean {
  if (typeof window === "undefined" || typeof window.matchMedia !== "function") {
    return true;
  }
  return window.matchMedia("(prefers-color-scheme: dark)").matches;
}

/**
 * UI text-size choices (the root `font-size`; the whole UI is rem-based so it
 * scales proportionally). 15 is the shipped default.
 */
export const FONT_SIZE_OPTIONS = [
  { value: 13, label: "Small" },
  { value: 14, label: "Compact" },
  { value: 15, label: "Default" },
  { value: 16, label: "Large" },
  { value: 17, label: "Larger" },
] as const;

export const DEFAULT_FONT_SIZE = 15;

/** Clamp a persisted font size to a valid option (bad/legacy values → default). */
export function clampFontSize(value: unknown): number {
  return FONT_SIZE_OPTIONS.some((o) => o.value === value)
    ? (value as number)
    : DEFAULT_FONT_SIZE;
}

export function quickConnectShortcut(platform: string | undefined): string {
  return platform === "macos" ? "Alt+Super+K" : "Ctrl+Alt+K";
}

/** Human-readable label for {@link quickConnectShortcut} (shown in Settings). */
export function quickConnectLabel(platform: string | undefined): string {
  return platform === "macos" ? "⌥⌘K" : "Ctrl+Alt+K";
}

/**
 * Whether the selected terminal can open the connection in a new TAB.
 * `null` (= system default / first detected) counts as unsupported because we
 * cannot know which terminal the backend will pick.
 */
export function terminalSupportsNewTab(
  terminalId: string | null,
  terminals: TerminalInfo[],
): boolean {
  if (terminalId === null) return false;
  return terminals.find((t) => t.id === terminalId)?.supports_new_tab ?? false;
}

/**
 * The terminal id to launch a connection to `alias` into: the host's override
 * (from the settings store's `hostTerminals`) wins; otherwise the global
 * preference; otherwise `null` = system default / first detected. Pass the
 * result BOTH as `terminalOverride` and into `effectiveNewTab` — new-tab
 * gating must follow the terminal that will actually launch.
 */
export function effectiveNewTab(
  newTabConnect: boolean,
  terminalId: string | null,
  terminals: TerminalInfo[],
): boolean {
  return newTabConnect && terminalSupportsNewTab(terminalId, terminals);
}

/** Update channels (Settings → Updates). */
export type UpdateChannel = "stable" | "beta";

/**
 * The channel to check, from a persisted or imported value. Anything other
 * than "beta" — missing, misspelled, written by a newer build — means Stable,
 * the code path every install used before channels existed.
 */
export function normalizeUpdateChannel(value: unknown): UpdateChannel {
  return value === "beta" ? "beta" : "stable";
}
