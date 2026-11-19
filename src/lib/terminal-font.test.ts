import { existsSync, readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { describe, expect, it } from "vitest";
// The patched renderer is not part of the package's public entry points.
import { glyphCellClass } from "../../node_modules/@wterm/dom/dist/renderer.js";

const cssPath = "src/components/records/terminal.css";
const css = readFileSync(cssPath, "utf8");
const SYMBOLS = "Symbols Nerd Font Mono";

function symbolsFace(): string {
  const face = (css.match(/@font-face\s*\{[^}]*\}/g) ?? []).find((rule) => rule.includes(`"${SYMBOLS}"`));
  if (!face) throw new Error(`terminal.css has no @font-face for ${SYMBOLS}`);
  return face;
}

function covers(face: string, codepoint: number): boolean {
  const ranges = face.match(/unicode-range:\s*([^;}]+)/)?.[1].split(",") ?? [];
  return ranges.some((range) => {
    const [start, end = start] = range.trim().replace(/^U\+/i, "").split("-").map((value) => parseInt(value, 16));
    return codepoint >= start && codepoint <= end;
  });
}

describe("terminal symbol font", () => {
  it("falls back to the bundled symbols font after the text font", () => {
    const stack = css.match(/--term-font-family:\s*([^;]+);/)?.[1].split(",").map((family) => family.trim().replace(/"/g, ""));
    expect(stack).toEqual(["Geist Mono Variable", SYMBOLS, "monospace"]);
  });

  it("ships the font file its @font-face names", () => {
    const url = symbolsFace().match(/url\("([^"]+)"\)/)?.[1];
    expect(url).toBeDefined();
    expect(existsSync(resolve(dirname(cssPath), url!))).toBe(true);
  });

  it("covers prompt glyphs without taking over ordinary text", () => {
    const face = symbolsFace();
    // Powerline separator, Font Awesome clock, Material Design icon, power symbol.
    for (const codepoint of [0xe0b0, 0xe0b2, 0xf017, 0xf0001, 0x23fb]) expect(covers(face, codepoint)).toBe(true);
    // Latin, box drawing, CJK and symbols the system fonts already draw.
    for (const codepoint of [0x41, 0x2500, 0x4e2d, 0x2665, 0x26a1]) expect(covers(face, codepoint)).toBe(false);
  });
});

describe("terminal glyph cells", () => {
  it("marks geometric Powerline separators for drawing", () => {
    expect(glyphCellClass(0xe0b0)).toBe("term-powerline term-powerline-e0b0");
    expect(glyphCellClass(0xe0bf)).toBe("term-powerline term-powerline-e0bf");
  });

  it("marks other private-use glyphs as symbols", () => {
    // Branch, flame separator, Font Awesome clock, Material Design icon.
    for (const codepoint of [0xe0a0, 0xe0c0, 0xf017, 0xf0001, 0xffffd]) expect(glyphCellClass(codepoint)).toBe("term-symbol");
  });

  it("has a style for every class the renderer emits", () => {
    expect(css).toMatch(/\.term-symbol\s*\{[^}]*font-family:\s*"Symbols Nerd Font Mono"/);
    for (let codepoint = 0xe0b0; codepoint <= 0xe0bf; codepoint++) {
      const [, shape] = glyphCellClass(codepoint).split(" ");
      expect(css, shape).toMatch(new RegExp(`\\.${shape}::before`));
    }
  });

  it("leaves ordinary text alone", () => {
    for (const codepoint of [0x41, 0x2500, 0x2714, 0x4e2d, 0xdfff, 0xf900, 0x1f600, 0xffffe]) expect(glyphCellClass(codepoint)).toBe("");
  });
});
