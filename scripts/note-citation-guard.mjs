// Finds citations of planning documents that are not part of this repository: a section, task, requirement or review-round number of a
// spec, plan or design, or a design named by its date. Those documents stay outside the repository (AGENTS.md), so such a pointer leads
// a reader nowhere; a comment, test name or document says what it means without one. The few files that may hold such text are listed
// in ALLOWLIST, each with its reason.
import { join } from "node:path";
import { globToRegExp, readText } from "./tracked-files.mjs";

// Each form a citation takes, with what it names in the failure message. None of the patterns matches this file's own text: an escape,
// a bracketed letter or a lookaround stands where a citation has a space, a letter or a digit.
export const FORMS = [
  { pattern: /docs\/superpower[s]/i, names: "the folder planning notes were once kept in" },
  { pattern: /\b(?:spec|plan|design)\s*§/i, names: "a section of a spec, plan or design" },
  { pattern: /\bdesign\s+20\d\d-\d\d-\d\d/i, names: "a design by its date" },
  { pattern: /\bplan\s+\d+[a-z]?\b/i, names: "a plan by its number" },
  { pattern: /\bTask\s+\d+\b/, names: "a task of a plan" },
  // Not an NSIS register such as `$R0`, a run of base64, or R2, Cloudflare's object storage.
  { pattern: /(?<![$\w+\/=])R(?!2\b)\d{1,2}\b(?![+\/=])/, names: "a requirement by its number" },
  { pattern: /\bReview Focus\s+\d/i, names: "an item of a review's focus list" },
  { pattern: /\bfix round\s+\d/i, names: "a round of review fixes" },
  { pattern: /\bfinal wav[e]\b/i, names: "a wave of reviews" },
  { pattern: /\bSP\d\b/, names: "a sub-project by its number" },
  { pattern: /計畫\s*\d|第\s*\d+\s*期/, names: "a plan or a phase of one by its number" },
];

// Paths from the repository root, as `git ls-files` prints them. Only `**` is a wildcard (any text, slashes included), as in `dir/**`.
export const ALLOWLIST = [
  { glob: "CHANGELOG.md", reason: "release history keeps the notes each release shipped with" },
];

const allowed = ALLOWLIST.map(({ glob }) => globToRegExp(glob));

// The lines of `files` (paths from `root`) that cite a planning document, as { file, line, text, names } with `line` counted from 1 and
// `names` saying what the first form found on the line refers to. Allowlisted and binary files are left out, and a line is one finding
// however many citations it holds.
export function scanForNoteCitations({ root, files }) {
  const findings = [];
  for (const file of files) {
    if (allowed.some(pattern => pattern.test(file))) continue;
    const text = readText(join(root, file));
    if (text === undefined) continue;
    text.split("\n").forEach((line, index) => {
      const form = FORMS.find(({ pattern }) => pattern.test(line));
      if (form) findings.push({ file, line: index + 1, text: line.trim(), names: form.names });
    });
  }
  return findings;
}

const plural = (count, noun) => `${count} ${noun}${count === 1 ? "" : "s"}`;

// A finding's text for the failure message: a long line is cut down to a window that keeps the first citation in view.
function shown(text, width = 160) {
  if (text.length <= width) return text;
  const found = FORMS.map(({ pattern }) => text.search(pattern)).filter(index => index >= 0);
  const start = Math.max(0, Math.min(...found) - 40);
  const end = start + width;
  return `${start > 0 ? "..." : ""}${text.slice(start, end)}${end < text.length ? "..." : ""}`;
}

// The failure message: every finding as `file:line: text (what it cites)`, then what to write instead.
export function formatFindings(findings) {
  const files = new Set(findings.map(finding => finding.file)).size;
  return [
    `${plural(findings.length, "line")} in ${plural(files, "file")} ${findings.length === 1 ? "cites" : "cite"} planning documents that are not in this repository:`,
    ...findings.map(({ file, line, text, names }) => `  ${file}:${line}: ${shown(text)} (${names})`),
    "",
    "Planning documents stay outside the repository (AGENTS.md), so a pointer to one leads a reader nowhere. Say in the comment, test name",
    "or document what the cited part says, and leave the pointer out.",
    "The files that may hold such text, and why, are listed in ALLOWLIST in scripts/note-citation-guard.mjs.",
  ].join("\n");
}
