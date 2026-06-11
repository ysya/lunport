import { afterEach, describe, expect, it, vi } from "vitest";

import type { TerminalInfo } from "@/bindings/TerminalInfo";
import {
  clampFontSize,
  DEFAULT_FONT_SIZE,
  defaultLintRules,
  effectiveNewTab,
  filterLintIssues,
  LINT_RULES,
  resolveTheme,
  systemPrefersDark,
  terminalSupportsNewTab,
} from "./settings-logic";

describe("resolveTheme", () => {
  it("passes explicit preferences through regardless of the OS", () => {
    expect(resolveTheme("light", true)).toBe("light");
    expect(resolveTheme("light", false)).toBe("light");
    expect(resolveTheme("dark", true)).toBe("dark");
    expect(resolveTheme("dark", false)).toBe("dark");
  });

  it('resolves "system" from the OS preference', () => {
    expect(resolveTheme("system", true)).toBe("dark");
    expect(resolveTheme("system", false)).toBe("light");
  });
});

describe("systemPrefersDark", () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("defaults to dark when window/matchMedia is unavailable", () => {
    // Node test environment: no `window` at all.
    expect(systemPrefersDark()).toBe(true);
    // A window without matchMedia (very old engines) also falls back to dark.
    vi.stubGlobal("window", {});
    expect(systemPrefersDark()).toBe(true);
  });

  it("reads the prefers-color-scheme media query when available", () => {
    const matchMedia = vi.fn((query: string) => ({
      matches: query === "(prefers-color-scheme: dark)",
    }));
    vi.stubGlobal("window", { matchMedia });
    expect(systemPrefersDark()).toBe(true);
    expect(matchMedia).toHaveBeenCalledWith("(prefers-color-scheme: dark)");

    vi.stubGlobal("window", { matchMedia: () => ({ matches: false }) });
    expect(systemPrefersDark()).toBe(false);
  });
});

describe("lint rule filtering", () => {
  const issue = (rule: string) => ({ rule });

  it("defaults all known rules to enabled", () => {
    const defaults = defaultLintRules();
    for (const r of LINT_RULES) expect(defaults[r.id]).toBe(true);
    expect(Object.keys(defaults)).toHaveLength(LINT_RULES.length);
  });

  it("keeps only issues whose rule is enabled", () => {
    const issues = [
      issue("duplicate-directive"),
      issue("shadowed-host"),
      issue("missing-identity-file"),
    ];
    const rules = { ...defaultLintRules(), "shadowed-host": false };
    expect(filterLintIssues(issues, rules).map((i) => i.rule)).toEqual([
      "duplicate-directive",
      "missing-identity-file",
    ]);
  });

  it("fails open for rule ids the store does not know about", () => {
    const issues = [issue("brand-new-backend-rule")];
    expect(filterLintIssues(issues, defaultLintRules())).toHaveLength(1);
  });

  it("returns everything when all rules are enabled and nothing when all are off", () => {
    const issues = LINT_RULES.map((r) => issue(r.id));
    expect(filterLintIssues(issues, defaultLintRules())).toHaveLength(issues.length);
    const allOff = Object.fromEntries(LINT_RULES.map((r) => [r.id, false]));
    expect(filterLintIssues(issues, allOff)).toHaveLength(0);
  });
});

describe("new-tab connect gating", () => {
  const TERMINALS: TerminalInfo[] = [
    { id: "iterm2", label: "iTerm2", supports_new_tab: true },
    { id: "terminal", label: "Terminal", supports_new_tab: false },
  ];

  it("treats the system default (null) as unsupported", () => {
    expect(terminalSupportsNewTab(null, TERMINALS)).toBe(false);
  });

  it("reads supports_new_tab off the matching terminal", () => {
    expect(terminalSupportsNewTab("iterm2", TERMINALS)).toBe(true);
    expect(terminalSupportsNewTab("terminal", TERMINALS)).toBe(false);
  });

  it("treats unknown terminal ids (and an empty list) as unsupported", () => {
    expect(terminalSupportsNewTab("kitty", TERMINALS)).toBe(false);
    expect(terminalSupportsNewTab("iterm2", [])).toBe(false);
  });

  it("only sends newTab=true when both the preference AND support hold", () => {
    expect(effectiveNewTab(true, "iterm2", TERMINALS)).toBe(true);
    expect(effectiveNewTab(false, "iterm2", TERMINALS)).toBe(false);
    expect(effectiveNewTab(true, "terminal", TERMINALS)).toBe(false);
    expect(effectiveNewTab(true, null, TERMINALS)).toBe(false);
  });
});

describe("clampFontSize", () => {
  it("passes valid options through", () => {
    expect(clampFontSize(13)).toBe(13);
    expect(clampFontSize(17)).toBe(17);
  });

  it("falls back to the default for invalid/legacy values", () => {
    expect(clampFontSize(9)).toBe(DEFAULT_FONT_SIZE);
    expect(clampFontSize(40)).toBe(DEFAULT_FONT_SIZE);
    expect(clampFontSize("15")).toBe(DEFAULT_FONT_SIZE);
    expect(clampFontSize(undefined)).toBe(DEFAULT_FONT_SIZE);
  });
});
