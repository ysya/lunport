import { describe, expect, it } from "vitest";

import { revealHidden } from "./reveal-hidden";

/*
 * Characters that make ssh read something other than what the screen shows. `revealHidden` must show every one of them as a code
 * wherever Lunport displays connection text it did not vet itself (the authentication window, AI access lists): a character
 * shown as it is, but read differently, is how a `ProxyCommand` could hide what it runs (U+303F was).
 *
 * The classes are the ones the retired Legacy sync refused in synced host text (`is_invisible` in `sync/hosts_file.rs` until
 * 2026-11-08), kept here as data: `std` knows neither General_Category=Cf nor Default_Ignorable_Code_Point, so they were
 * hand-written code point ranges, and this test still checks every code point of every range, the tag characters
 * (U+E0000–U+E0FFF, 4096 code points) included.
 *
 * Not covered here: the combining marks without a base, which are not a fixed set of code points; `revealHidden` shows them by
 * position (see reveal-hidden.test.ts).
 */

const span = (first: number, last: number): number[] => Array.from({ length: last - first + 1 }, (_, i) => first + i);
const points = (ranges: [number, number][]): number[] => ranges.flatMap(([first, last]) => span(first, last));

/** Every General_Category=Cf character: 21 ranges, 170 code points. */
const FORMAT_CHARACTERS: [number, number][] = [[0xad, 0xad], [0x600, 0x605], [0x61c, 0x61c], [0x6dd, 0x6dd], [0x70f, 0x70f], [0x890, 0x891], [0x8e2, 0x8e2], [0x180e, 0x180e], [0x200b, 0x200f], [0x202a, 0x202e], [0x2060, 0x2064], [0x2066, 0x206f], [0xfeff, 0xfeff], [0xfff9, 0xfffb], [0x110bd, 0x110bd], [0x110cd, 0x110cd], [0x13430, 0x1343f], [0x1bca0, 0x1bca3], [0x1d173, 0x1d17a], [0xe0001, 0xe0001], [0xe0020, 0xe007f]];
/** Unicode's Default_Ignorable_Code_Point: what fonts and layout engines do not draw. */
const DEFAULT_IGNORABLE: [number, number][] = [[0xad, 0xad], [0x34f, 0x34f], [0x61c, 0x61c], [0x115f, 0x1160], [0x17b4, 0x17b5], [0x180b, 0x180f], [0x200b, 0x200f], [0x202a, 0x202e], [0x2060, 0x206f], [0x3164, 0x3164], [0xfe00, 0xfe0f], [0xfeff, 0xfeff], [0xffa0, 0xffa0], [0xfff0, 0xfff8], [0x1bca0, 0x1bca3], [0x1d173, 0x1d17a], [0xe0000, 0xe0fff]];
/** Blank by design but not default-ignorable: braille blank, musical null notehead, hieroglyph spaces, ideographic half fill space. */
const BLANK_BY_DESIGN: [number, number][] = [[0x2800, 0x2800], [0x1d159, 0x1d159], [0x13441, 0x13441], [0x13442, 0x13442], [0x303f, 0x303f]];

/** What Rust's `char::is_whitespace` tests: the White_Space property. */
const WHITE_SPACE = /^\p{White_Space}$/u;

/** The non-ASCII White_Space characters, which a parser reads as blank and OpenSSH does not, and the byte order mark. */
function confusableSpacePoints(): number[] {
  const found: number[] = [];
  for (let cp = 0x80; cp <= 0x10ffff; cp++) {
    if (cp === 0xfeff || WHITE_SPACE.test(String.fromCodePoint(cp))) found.push(cp);
  }
  return found;
}

/** General_Category=Cc: C0 (U+0000–U+001F), DEL and C1 (U+007F–U+009F), except tab. */
const controlPoints = (): number[] => [...span(0x00, 0x1f), ...span(0x7f, 0x9f)].filter((cp) => cp !== 0x09);

interface HiddenClass {
  label: string;
  /** Code points the class certainly holds. */
  sentinels: number[];
  points: () => number[];
}

const CLASSES: HiddenClass[] = [
  {
    label: "non-ASCII space or byte order mark",
    sentinels: [0x85, 0xa0, 0x1680, 0x2003, 0x2028, 0x3000, 0xfeff],
    points: confusableSpacePoints,
  },
  {
    label: "format character (General_Category=Cf)",
    sentinels: [0xad, 0x600, 0x61c, 0x6dd, 0x70f, 0x890, 0x8e2, 0x180e, 0x200b, 0x202e, 0x2066, 0xfff9, 0x110bd, 0x110cd, 0x13430, 0x1d173, 0xe0001, 0xe007f],
    points: () => points(FORMAT_CHARACTERS),
  },
  {
    label: "default-ignorable code point",
    sentinels: [0x34f, 0x115f, 0x180b, 0x3164, 0xfe0f, 0xffa0, 0xe0000, 0xe0100, 0xe0fff],
    points: () => points(DEFAULT_IGNORABLE),
  },
  {
    label: "blank-by-design character",
    sentinels: [0x2800, 0x1d159, 0x13441, 0x13442, 0x303f],
    points: () => points(BLANK_BY_DESIGN),
  },
  {
    label: "control character other than tab (C0, DEL, C1)",
    sentinels: [0x00, 0x1b, 0x1f, 0x7f, 0x80, 0x85, 0x9f],
    points: controlPoints,
  },
];

const hex = (cp: number) => `U+${cp.toString(16).toUpperCase().padStart(4, "0")}`;

describe("hidden characters: every class is revealed as a code", () => {
  it.each(CLASSES)("reveals every $label", ({ points: classPoints, sentinels }) => {
    const found = classPoints();
    expect(sentinels.filter((cp) => !found.includes(cp)).map(hex), "code points the class should hold").toEqual([]);
    // A letter on both sides: a combining mark would be revealed there only if it is always shown, not because it has no base.
    const shown = (cp: number) => `a\u27E8${hex(cp)}\u27E9b`;
    const plain = found.filter((cp) => revealHidden(`a${String.fromCodePoint(cp)}b`) !== shown(cp));
    expect(plain.map(hex), "code points shown as they are").toEqual([]);
  });
});
