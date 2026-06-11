import type { TerminalInfo } from "@/bindings/TerminalInfo";
import type { LintIssue } from "@/bindings/LintIssue";

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

/**
 * The lint rules the backend emits, with stable kebab-case ids (mirrors
 * `LintIssue.rule`) and human-readable labels for the Settings switches.
 */
export const LINT_RULES = [
  { id: "duplicate-directive", label: "Duplicate directives" },
  { id: "shadowed-host", label: "Shadowed host aliases" },
  { id: "missing-identity-file", label: "Missing identity files" },
  { id: "insecure-strict-host-key-checking", label: "Insecure StrictHostKeyChecking" },
  { id: "undefined-proxy-jump", label: "Undefined ProxyJump hops" },
] as const;

/** All known lint rules enabled — the store default. */
export function defaultLintRules(): Record<string, boolean> {
  return Object.fromEntries(LINT_RULES.map((r) => [r.id, true]));
}

/**
 * Keep only issues whose rule is enabled. Unknown rule ids stay visible (fail
 * open) so issues from rules the backend adds later are never silently hidden.
 */
export function filterLintIssues<T extends Pick<LintIssue, "rule">>(
  issues: T[],
  rules: Record<string, boolean>,
): T[] {
  return issues.filter((issue) => rules[issue.rule] !== false);
}

/**
 * The terminal id to launch a connection to `alias` into: the host's override
 * (from the settings store's `hostTerminals`) wins; otherwise the global
 * preference; otherwise `null` = system default / first detected. Pass the
 * result BOTH as `terminalOverride` and into `effectiveNewTab` — new-tab
 * gating must follow the terminal that will actually launch.
 */
export function resolveTerminal(
  alias: string,
  hostTerminals: Record<string, string>,
  globalTerminalId: string | null,
): string | null {
  const override = hostTerminals[alias];
  if (override !== undefined && override !== "") return override;
  return globalTerminalId ?? null;
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
 * The `newTab` value to actually send to `connect_launch`: the user's
 * preference, gated on the resolved terminal supporting tabs at all.
 */
export function effectiveNewTab(
  newTabConnect: boolean,
  terminalId: string | null,
  terminals: TerminalInfo[],
): boolean {
  return newTabConnect && terminalSupportsNewTab(terminalId, terminals);
}
