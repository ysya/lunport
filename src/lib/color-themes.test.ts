import { describe, expect, it } from "vitest";
import { applyColorTheme, COLOR_THEMES, getColorTheme } from "./color-themes";

function contrast(a: string, b: string) {
  const luminance = (hex: string) => {
    const rgb = hex.slice(1).match(/../g)!.map((part) => {
      const value = parseInt(part, 16) / 255;
      return value <= 0.04045 ? value / 12.92 : ((value + 0.055) / 1.055) ** 2.4;
    });
    return rgb[0] * 0.2126 + rgb[1] * 0.7152 + rgb[2] * 0.0722;
  };
  const values = [luminance(a), luminance(b)].sort((x, y) => y - x);
  return (values[0] + 0.05) / (values[1] + 0.05);
}

describe("app color themes", () => {
  for (const theme of COLOR_THEMES) for (const mode of ["light", "dark"] as const) {
    it(`${theme.name} ${mode} keeps small text and primary actions readable`, () => {
      const palette = theme[mode];
      for (const surface of ["--background", "--card", "--popover", "--sidebar"] as const) {
        for (const text of ["--foreground", "--muted-foreground", "--primary", "--success", "--destructive", "--warning"] as const) {
          expect(contrast(palette[text], palette[surface]), `${text} on ${surface}`).toBeGreaterThanOrEqual(4.5);
        }
      }
      expect(contrast(palette["--primary-foreground"], palette["--primary"])).toBeGreaterThanOrEqual(4.5);
      expect(contrast(palette["--warning-foreground"], palette["--warning"])).toBeGreaterThanOrEqual(4.5);
    });
  }

  it("accepts older or unknown imported preferences and removes all preset overrides when returning to Lunport", () => {
    const values = new Map<string, string>();
    const root = { dataset: {}, style: {
      setProperty: (key: string, value: string) => values.set(key, value),
      removeProperty: (key: string) => values.delete(key),
    } } as unknown as HTMLElement;
    applyColorTheme(root, "nord", "dark");
    expect(values.get("--background")).toBe("#2e3440");
    applyColorTheme(root, "nord", "light");
    expect(values.get("--background")).toBe("#eceff4");
    for (const value of [undefined, null, "unknown-theme", {}, "lunport"]) {
      applyColorTheme(root, value, "dark");
      expect(root.dataset.colorTheme).toBe("lunport");
      expect(values.size).toBe(0);
      expect(getColorTheme(value).id).toBe("lunport");
    }
  });
});
