import { describe, expect, it } from "vitest";
import { COLOR_THEMES } from "./color-themes";
import { terminalColors } from "./terminal-theme";
import { clampTerminalFontSize, DEFAULT_TERMINAL_FONT_SIZE } from "./settings-logic";
describe("terminal appearance", () => {
  it("uses each app theme's light and dark colors with a complete 24-bit ANSI palette", () => {
    for (const theme of COLOR_THEMES) for (const mode of ["light", "dark"] as const) {
      const colors = terminalColors(theme.id, mode);
      expect(colors.background).toBe(parseInt(theme[mode]["--background"].slice(1), 16));
      expect(colors.foreground).toBe(parseInt(theme[mode]["--foreground"].slice(1), 16));
      expect(colors.foreground).not.toBe(colors.background);
      expect(colors.palette).toHaveLength(16);
      for (const color of [colors.foreground, colors.background, colors.cursor, ...colors.palette]) {
        expect(Number.isInteger(color) && color >= 0 && color <= 0xffffff).toBe(true);
      }
    }
    expect(terminalColors("unknown", "light")).toEqual(terminalColors("lunport", "light"));
  });
  it("bounds imported font preferences without silently accepting invalid values", () => {
    for (const value of [null, "14", 9, 25, 14.5, Infinity]) expect(clampTerminalFontSize(value)).toBe(DEFAULT_TERMINAL_FONT_SIZE);
    for (const value of [10, 14, 24]) expect(clampTerminalFontSize(value)).toBe(value);
  });
});
