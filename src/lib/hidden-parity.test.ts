import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";

import { revealHidden } from "./sync-approvals";

/*
 * The backend refuses a synced host whose text holds a character that makes ssh read
 * something other than what the screen shows (`is_invisible` in hosts_file.rs), except
 * inside an ssh_config comment. The approval dialog has to show every one of those
 * characters as a code (`revealHidden`): it also shows text the backend never vetted
 * (this computer's own version of a host, comments), and a character that is refused
 * but not revealed is how a `ProxyCommand` could hide what it runs (U+303F was).
 *
 * The backend's classes are hand-written code point ranges, because `std` knows neither
 * General_Category=Cf nor Default_Ignorable_Code_Point. This test reads those
 * declarations from the Rust source and checks every code point of every range, the
 * tag characters (U+E0000–U+E0FFF, 4096 code points) included. The reader is
 * deliberately narrow: when a declaration changes shape it throws and says what to
 * update, instead of passing on a list it no longer understands.
 *
 * Not covered here: `StrayCharacter`, the combining marks without a base that the
 * backend refuses in the five lines ssh hands to a shell. Those are not a fixed set of
 * code points; `revealHidden` shows them by position (see sync-approvals.test.ts).
 */

const RUST_FILE = "src-tauri/src/sync/hosts_file.rs";
const THIS_FILE = "src/lib/hidden-parity.test.ts";

let source: string | undefined;
const rust = (): string => (source ??= readFileSync(RUST_FILE, "utf8"));

const shapeMessage = (what: string) => `${RUST_FILE}: ${what}. The backend's refusal rules changed shape; update ${THIS_FILE} to match.`;
const changed = (what: string) => new Error(shapeMessage(what));

/** The text between the braces of the top-level `fn name(c: char) -> bool { … }`; its closing brace is the first `}` that starts a line. */
function functionBody(name: string): string {
  const parts = rust().split(`\nfn ${name}(c: char) -> bool {\n`);
  if (parts.length !== 2) throw changed(`expected exactly one top-level \`fn ${name}(c: char) -> bool {\`, found ${parts.length - 1}`);
  const end = parts[1].indexOf("\n}\n");
  if (end < 0) throw changed(`\`fn ${name}\` has no closing brace at the start of a line`);
  return parts[1].slice(0, end);
}

const span = (first: number, last: number): number[] => Array.from({ length: last - first + 1 }, (_, i) => first + i);

/** One alternative of a `matches!`: `'\u{00ad}'` or `'\u{200b}'..='\u{200f}'`. */
const ALTERNATIVE = /^'\\u\{([0-9a-f]{1,6})\}'(?:\s*\.\.=\s*'\\u\{([0-9a-f]{1,6})\}')?$/i;

/** Every code point of `fn name(c: char) -> bool { matches!(c, '\u{…}' | '\u{…}'..='\u{…}' | …) }`. */
function rangePoints(name: string): number[] {
  const matched = /^\s*matches!\(\s*c,([\s\S]*?),?\s*\)\s*$/.exec(functionBody(name));
  if (!matched) throw changed(`\`fn ${name}\` is not a single \`matches!(c, …)\``);
  return matched[1].split("|").flatMap((alternative) => {
    const text = alternative.trim();
    const range = ALTERNATIVE.exec(text);
    if (!range) throw changed(`cannot read \`${text}\` in \`fn ${name}\` (expected '\\u{…}' or '\\u{…}'..='\\u{…}')`);
    const first = parseInt(range[1], 16);
    const last = range[2] === undefined ? first : parseInt(range[2], 16);
    if (first > last || last > 0x10ffff) throw changed(`\`fn ${name}\` has an empty or out-of-range \`${text}\``);
    return span(first, last);
  });
}

/** What Rust's `char::is_whitespace` tests: the White_Space property. */
const WHITE_SPACE = /^\p{White_Space}$/u;

/** `is_confusable_space`: the non-ASCII White_Space characters, and the byte order mark. */
function confusableSpacePoints(): number[] {
  const rule = "(!c.is_ascii() && c.is_whitespace()) || c == '\\u{feff}'";
  if (functionBody("is_confusable_space").trim() !== rule) throw changed(`\`fn is_confusable_space\` is no longer \`${rule}\``);
  const points: number[] = [];
  for (let cp = 0x80; cp <= 0x10ffff; cp++) {
    if (cp === 0xfeff || WHITE_SPACE.test(String.fromCodePoint(cp))) points.push(cp);
  }
  return points;
}

/** `c.is_control() && c != '\t'`: General_Category=Cc, which is C0 (U+0000–U+001F), DEL and C1 (U+007F–U+009F), except tab. */
const controlPoints = (): number[] => [...span(0x00, 0x1f), ...span(0x7f, 0x9f)].filter((cp) => cp !== 0x09);

interface RefusalClass {
  /** The term of `is_invisible`'s `||` chain that refuses it, as written in Rust. */
  term: string;
  label: string;
  /** Code points the class certainly holds: a reader that finds less must fail. */
  sentinels: number[];
  /** Every code point of the class, read from the Rust declarations. */
  points: () => number[];
}

const CLASSES: RefusalClass[] = [
  {
    term: "is_confusable_space(c)",
    label: "non-ASCII space or byte order mark",
    sentinels: [0x85, 0xa0, 0x1680, 0x2003, 0x2028, 0x3000, 0xfeff],
    points: confusableSpacePoints,
  },
  {
    term: "is_format_character(c)",
    label: "format character (General_Category=Cf)",
    sentinels: [0xad, 0x600, 0x61c, 0x6dd, 0x70f, 0x890, 0x8e2, 0x180e, 0x200b, 0x202e, 0x2066, 0xfff9, 0x110bd, 0x110cd, 0x13430, 0x1d173, 0xe0001, 0xe007f],
    points: () => rangePoints("is_format_character"),
  },
  {
    term: "is_default_ignorable(c)",
    label: "default-ignorable code point",
    sentinels: [0x34f, 0x115f, 0x180b, 0x3164, 0xfe0f, 0xffa0, 0xe0000, 0xe0100, 0xe0fff],
    points: () => rangePoints("is_default_ignorable"),
  },
  {
    term: "is_blank_by_design(c)",
    label: "blank-by-design character",
    sentinels: [0x2800, 0x1d159, 0x13441, 0x13442, 0x303f],
    points: () => rangePoints("is_blank_by_design"),
  },
  {
    term: "(c.is_control() && c != '\\t')",
    label: "control character other than tab (C0, DEL, C1)",
    sentinels: [0x00, 0x1b, 0x1f, 0x7f, 0x80, 0x85, 0x9f],
    points: controlPoints,
  },
];

const hex = (cp: number) => `U+${cp.toString(16).toUpperCase().padStart(4, "0")}`;

describe("hidden characters: what the dialog reveals against what the backend refuses", () => {
  it("is_invisible is made of exactly the classes checked below", () => {
    const terms = functionBody("is_invisible")
      .split("||")
      .map((term) => term.trim());
    const known = CLASSES.map((c) => c.term);
    const message = shapeMessage("`is_invisible` refuses other classes than the ones checked here (`unknown`), or no longer refuses one (`missing`)");
    expect({ unknown: terms.filter((t) => !known.includes(t)), missing: known.filter((t) => !terms.includes(t)) }, message).toEqual({ unknown: [], missing: [] });
  });

  it.each(CLASSES)("reveals every $label the backend refuses", ({ points, sentinels }) => {
    const found = points();
    expect(sentinels.filter((cp) => !found.includes(cp)).map(hex), "code points the reader should have found").toEqual([]);
    // A letter on both sides: a combining mark would be revealed there only if it is always shown, not because it has no base.
    const shown = (cp: number) => `a\u27E8${hex(cp)}\u27E9b`;
    const plain = found.filter((cp) => revealHidden(`a${String.fromCodePoint(cp)}b`) !== shown(cp));
    expect(plain.map(hex), "code points the backend refuses but the dialog shows as they are").toEqual([]);
  });
});
