/**
 * Characters that are shown as a code wherever they are: bidi controls (which
 * reorder text on screen), zero-width and other format characters, controls,
 * non-ASCII spaces, and the letters and marks that draw nothing (the default
 * ignorables: Hangul fillers, variation selectors, the combining grapheme
 * joiner). U+2800 (the blank Braille cell), U+1D159 (the null notehead),
 * U+13441 / U+13442 (the blank hieroglyphs) and U+303F (the ideographic half fill
 * space) are blank by design but not default ignorable, so they are listed.
 * reveal-hidden-classes.test.ts checks every code point of the hidden classes
 * the retired Legacy sync refused.
 */
const ALWAYS_SHOWN = /[\p{Cf}\p{Cc}\p{Zs}\p{Zl}\p{Zp}\p{Default_Ignorable_Code_Point}\u{2800}\u{1D159}\u{13441}\u{13442}\u{303F}]/u;
const COMBINING_MARK = /\p{M}/u;
/** What a combining mark can sit on and be seen: a letter or a digit. */
const MARK_BASE = /[\p{L}\p{N}]/u;

/**
 * Text as ssh reads it, shown so the screen cannot lie about it: every
 * `ALWAYS_SHOWN` character, and every combining mark that has no letter, digit or
 * mark to sit on (after a space, `=`, `;`, at a line start, after a character that
 * was just shown), becomes a visible `⟨U+202E⟩`. A mark with a base is an accent
 * and stays. The backend refuses most of these in synced hosts, but a gated value
 * can still carry some: where a shell comment starts depends on what precedes the
 * `#`, and an invisible letter or an orphan mark after a space makes the `#` part
 * of a word while the screen shows a comment.
 */
export function revealHidden(text: string): string {
  let out = "";
  let onBase = false; // whether the previous character can carry a combining mark: a letter or digit, or a mark already on one
  for (const ch of text) {
    if (ch !== "\t" && ch !== " " && (ALWAYS_SHOWN.test(ch) || (COMBINING_MARK.test(ch) && !onBase))) {
      out += `⟨U+${ch.codePointAt(0)!.toString(16).toUpperCase().padStart(4, "0")}⟩`;
      onBase = false;
    } else {
      out += ch;
      onBase = MARK_BASE.test(ch) || COMBINING_MARK.test(ch);
    }
  }
  return out;
}
