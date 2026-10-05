import type { ApprovalNotice } from "@/bindings/ApprovalNotice";
import type { GatedDirective } from "@/bindings/GatedDirective";
import type { HostSummary } from "@/bindings/HostSummary";
import type { PendingApprovalView } from "@/bindings/PendingApprovalView";
import type { ReviewOutcome } from "@/bindings/ReviewOutcome";
import type { ReviewedVersion } from "@/bindings/ReviewedVersion";
import type { SyncSpaceView } from "@/bindings/SyncSpaceView";
import { listNames, plural } from "@/lib/format";
import type { SyncMessage } from "@/lib/sync-events";

/**
 * Settings a synced host may only bring in after this computer approves them
 * (spec §7.4 and the B2 review): they run local programs, share this computer's
 * credentials, environment or network with the other side, run commands on the
 * server, turn off the host-key checks that keep a redirect safe, or open
 * forwarded ports to the local network. The backend's `approval::GATED_KEYWORDS`
 * decides; this copy (documented spelling, same order) only labels and
 * highlights. A test keeps them equal.
 */
export const GATED_KEYWORDS = [
  "ProxyCommand",
  "LocalCommand",
  "PermitLocalCommand",
  "KnownHostsCommand",
  "PKCS11Provider",
  "SecurityKeyProvider",
  "ForwardAgent",
  "ForwardX11",
  "ForwardX11Trusted",
  "RemoteForward",
  "SmartcardDevice",
  "XAuthLocation",
  "RemoteCommand",
  "StrictHostKeyChecking",
  "NoHostAuthenticationForProxyCommand",
  "VerifyHostKeyDNS",
  "UserKnownHostsFile",
  "GlobalKnownHostsFile",
  "SendEnv",
  "GSSAPIDelegateCredentials",
  "IdentityAgent",
  "PermitRemoteOpen",
  "NoHostAuthenticationForLocalhost",
  "GatewayPorts",
] as const;

/**
 * Gated unless written in the plain port-only form (`approval::gated_forward`):
 * a signature can hold them although they are not in `GATED_KEYWORDS`.
 */
const SOMETIMES_GATED = ["LocalForward", "DynamicForward"] as const;

const ALWAYS_GATED = new Set<string>(GATED_KEYWORDS.map((k) => k.toLowerCase()));
const LABELS = new Map<string, string>([...GATED_KEYWORDS, ...SOMETIMES_GATED].map((k) => [k.toLowerCase(), k]));

/** A lowercase keyword in its usual spelling (`proxycommand` → `ProxyCommand`). */
export function keywordLabel(keyword: string): string {
  return LABELS.get(keyword) ?? keyword;
}

/**
 * Characters that are shown as a code wherever they are: bidi controls (which
 * reorder text on screen), zero-width and other format characters, controls,
 * non-ASCII spaces, and the letters and marks that draw nothing (the default
 * ignorables: Hangul fillers, variation selectors, the combining grapheme
 * joiner). U+2800 (the blank Braille cell), U+1D159 (the null notehead),
 * U+13441 / U+13442 (the blank hieroglyphs) and U+303F (the ideographic half fill
 * space) are blank by design but not default ignorable, so they are listed.
 * Everything the backend refuses outside a comment must be shown here:
 * hidden-parity.test.ts reads the backend's ranges and checks it.
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

/** A block's lines for display: hidden characters revealed. */
export function displayLines(text: string): string[] {
  return splitLines(text).map(revealHidden);
}

/** A keyword as ssh_config spells one: a letter, then letters and digits. */
const KEYWORD = "[A-Za-z][A-Za-z0-9]*";
/** A line that starts with a keyword, followed by `=`, white space or the end: captures it. */
const LINE_KEYWORD = new RegExp(`^\\s*(${KEYWORD})\\s*(?:=|\\s|$)`);
/** What comes before a directive's value: its keyword and the `=` or white space after it. */
const KEYWORD_PREFIX = new RegExp(`^\\s*${KEYWORD}\\s*=?`);

/** The keyword of a config line, lowercased (`Keyword value` or `Keyword=value`); null for blanks and comments. */
export function lineKeyword(line: string): string | null {
  const match = LINE_KEYWORD.exec(line);
  return match ? match[1].toLowerCase() : null;
}

/** A block's lines: one trailing newline dropped, and one CR per line (CRLF files). */
function splitLines(text: string): string[] {
  return text
    .replace(/\r?\n$/, "")
    .split("\n")
    .map((line) => line.replace(/\r$/, ""));
}

export interface BlockLine {
  text: string;
  /** A gated setting: highlighted in the review. */
  gated: boolean;
  /**
   * The Host line of a host this computer has that now applies to different names,
   * or of a host it does not have yet that names more than one host.
   */
  scope: boolean;
}

/**
 * Trims what Rust's `trim` trims (the Unicode White_Space class: U+0085 yes, U+FEFF
 * no), which is how the backend cuts a signature's text. JavaScript's own `trim`
 * differs on exactly those two, so a line that ends in one of them would not
 * match its signature.
 */
function trimWhiteSpace(text: string): string {
  return text.replace(/^\p{White_Space}+|\p{White_Space}+$/gu, "");
}

/** The part of a directive line after its keyword (and `=`), trimmed: what a signature holds as `value`. */
function restOfLine(line: string): string {
  return trimWhiteSpace(line.replace(KEYWORD_PREFIX, ""));
}

/**
 * The names a `Host` line applies to: its words up to the first one that starts a
 * comment (OpenSSH reads `#` as a comment only at the start of a word).
 */
function hostPatterns(hostText: string): string[] {
  const names: string[] = [];
  for (const word of hostText.split(/[ \t]+/)) {
    if (word === "") continue;
    if (word.startsWith("#")) break;
    names.push(word);
  }
  return names;
}

/**
 * A host that is not in its space's file yet whose `Host` line names more than one
 * host (or a pattern): it reaches names the one the change list leads with does not.
 */
function widerThanOneName(view: PendingApprovalView): boolean {
  if (view.current_text !== null) return false;
  const names = hostPatterns(view.incoming.host);
  return names.length > 1 || names.some((name) => /[*?!]/.test(name));
}

/**
 * The incoming block, line by line, for the review dialog (display only — the
 * backend's parser decides). A line is marked when its keyword is always gated,
 * or when the incoming signature holds it (a forward with a bind address).
 */
export function blockLines(view: PendingApprovalView): BlockLine[] {
  const scopeChanged = (view.current_text !== null && view.applied.host !== view.incoming.host) || widerThanOneName(view);
  return splitLines(view.text).map((line) => {
    const keyword = lineKeyword(line);
    const signed = keyword !== null && view.incoming.gated.some((g) => g.keyword === keyword && g.value === restOfLine(line));
    return {
      text: revealHidden(line),
      gated: keyword !== null && (ALWAYS_GATED.has(keyword) || signed),
      scope: scopeChanged && keyword === "host",
    };
  });
}

/** Which of two blocks for one name ssh reads first (it takes the first value of each keyword). */
export type Rank =
  /** The existing host is in a file that is not a space's: synced files are Included first, so the held host's block is read first. */
  | { kind: "synced_first" }
  /**
   * The existing host is another block of the held host's own space file. `appended`: the held host is not in the file
   * yet, so its block is added after every block there (the existing one comes first); otherwise it is replaced in place
   * and only the order of the two blocks in that file decides.
   */
  | { kind: "own_file"; appended: boolean }
  /** The existing host is in another space's file; `before`: that file comes before the held host's in the Include list. */
  | { kind: "space"; space: string; before: boolean }
  /** The spaces are not known (yet), or the held host's space is not among them. */
  | { kind: "unknown" };

export type ApprovalChange =
  | { kind: "not_in_space"; space: string; host: string }
  | { kind: "new_block"; space: string; host: string }
  | { kind: "takeover"; name: string; file: string; heldSpace: string; rank: Rank; gated: string[] }
  | { kind: "scope"; from: string; to: string }
  | { kind: "added"; keyword: string; value: string }
  | { kind: "removed"; keyword: string; value: string }
  | { kind: "changed"; keyword: string; from: string; to: string }
  | { kind: "moved"; keyword: string; value: string };

const sameDirective = (a: GatedDirective, b: GatedDirective) => a.keyword === b.keyword && a.value === b.value;

/**
 * How the gated settings differ, in order (the approval signature compares them
 * in order: the first value of a keyword is the one ssh uses). An LCS diff keeps
 * the untouched ones out; within each run of edits a removal and an addition of
 * the same keyword read as one change, and the same setting removed in one place
 * and added in another reads as a reorder.
 */
function gatedChanges(applied: GatedDirective[], incoming: GatedDirective[]): ApprovalChange[] {
  const n = applied.length;
  const m = incoming.length;
  const lcs = Array.from({ length: n + 1 }, () => new Array<number>(m + 1).fill(0));
  for (let i = n - 1; i >= 0; i--) {
    for (let j = m - 1; j >= 0; j--) {
      lcs[i][j] = sameDirective(applied[i], incoming[j]) ? lcs[i + 1][j + 1] + 1 : Math.max(lcs[i + 1][j], lcs[i][j + 1]);
    }
  }

  const out: ApprovalChange[] = [];
  let removed: GatedDirective[] = [];
  let added: GatedDirective[] = [];
  const flush = () => {
    for (const add of added) {
      const k = removed.findIndex((r) => r.keyword === add.keyword);
      if (k >= 0) {
        out.push({ kind: "changed", keyword: add.keyword, from: removed[k].value, to: add.value });
        removed.splice(k, 1);
      } else {
        out.push({ kind: "added", ...add });
      }
    }
    for (const r of removed) out.push({ kind: "removed", ...r });
    removed = [];
    added = [];
  };

  let i = 0;
  let j = 0;
  while (i < n || j < m) {
    if (i < n && j < m && sameDirective(applied[i], incoming[j])) {
      flush();
      i += 1;
      j += 1;
    } else if (j < m && (i === n || lcs[i][j + 1] >= lcs[i + 1][j])) {
      added.push(incoming[j]);
      j += 1;
    } else {
      removed.push(applied[i]);
      i += 1;
    }
  }
  flush();

  // The same setting removed in one run and added in another moved.
  const result: ApprovalChange[] = [];
  const merged = new Set<number>();
  out.forEach((change, index) => {
    if (merged.has(index)) return;
    if (change.kind === "added" || change.kind === "removed") {
      const twin = out.findIndex(
        (other, k) =>
          k > index &&
          !merged.has(k) &&
          (other.kind === "added" || other.kind === "removed") &&
          other.kind !== change.kind &&
          other.keyword === change.keyword &&
          other.value === change.value,
      );
      if (twin >= 0) {
        merged.add(twin);
        result.push({ kind: "moved", keyword: change.keyword, value: change.value });
        return;
      }
    }
    result.push(change);
  });
  return result;
}

/** A host of the loaded config, as far as the review needs it: the names it applies to and the file it is in. */
export type ConfigHost = Pick<HostSummary, "patterns" | "source_file">;

/** A name the held host would also apply to, which the loaded config already has in `file`. */
export interface Takeover {
  name: string;
  file: string;
}

/**
 * A space of the sync account as far as the review needs it: its name and its file
 * (null when this computer does not sync it). `SyncOverview.spaces` lists them in
 * the order of the Include list (spec §4.3), which is the order ssh reads their files in.
 */
export type ReviewSpace = Pick<SyncSpaceView, "id" | "name" | "file_path">;

/**
 * Hosts of the loaded config (the main config, a file it includes, a space's file)
 * that a held host's names would sit in front of: the names it applies to from now
 * on that it did not apply to before. For a host that is not in its space's file yet
 * that is every name on its Host line; for a host it already has, the names a widened
 * scope adds. ("Not in the space's file" does not mean "new on this computer".) A name
 * matches when it is one of the existing host's patterns.
 */
export function existingHosts(view: PendingApprovalView, hosts: readonly ConfigHost[]): Takeover[] {
  const already = new Set(view.current_text === null ? [] : hostPatterns(view.applied.host));
  const found: Takeover[] = [];
  for (const name of new Set([view.alias, ...hostPatterns(view.incoming.host)])) {
    if (already.has(name)) continue;
    for (const host of hosts) {
      if (host.patterns.includes(name) && !found.some((f) => f.name === name && f.file === host.source_file)) {
        found.push({ name, file: host.source_file });
      }
    }
  }
  return found;
}

/**
 * Which block ssh reads first, the approved one or the existing host's in `file`.
 * The main config starts with the Include of the space files, in the order of
 * `spaces`, so a file that is not a space's comes after all of them; another space's
 * file wins or loses by its place in that list; and a host's own space file gets the
 * approved block added after what it already holds.
 */
function takeoverRank(view: PendingApprovalView, file: string, spaces: readonly ReviewSpace[] | undefined): Rank {
  if (spaces === undefined) return { kind: "unknown" };
  const files = spaces.filter((s) => s.file_path !== null);
  const own = files.findIndex((s) => s.id === view.space_id);
  if (own < 0) return { kind: "unknown" };
  const at = files.findIndex((s) => s.file_path === file);
  if (at < 0) return { kind: "synced_first" };
  if (at === own) return { kind: "own_file", appended: view.current_text === null };
  return { kind: "space", space: files[at].name, before: at < own };
}

/**
 * What approving would change on this computer (spec §7.4 signature differences).
 * `hosts` is the loaded config and `spaces` the sync account's spaces in Include
 * order: together they say which existing hosts the held host would take over, and
 * which of the two blocks ssh would read first.
 */
export function approvalChanges(view: PendingApprovalView, hosts: readonly ConfigHost[] = [], spaces?: readonly ReviewSpace[]): ApprovalChange[] {
  // Every gated setting of the block that would be approved, once each: what applies to the names it reaches.
  const gated = [...new Set(view.incoming.gated.map((g) => g.keyword))];
  const takeovers = existingHosts(view, hosts).map(
    (t): ApprovalChange => ({ kind: "takeover", ...t, heldSpace: view.space_name, rank: takeoverRank(view, t.file, spaces), gated }),
  );
  // A name that another block of the host's own space file already carries: the host is not "new" there, so say how it is added.
  const inOwnFile = takeovers.some((t) => t.kind === "takeover" && t.rank.kind === "own_file");
  const head: ApprovalChange[] =
    view.current_text === null
      ? [{ kind: inOwnFile ? "new_block" : "not_in_space", space: view.space_name, host: view.incoming.host }]
      : view.applied.host !== view.incoming.host
        ? [{ kind: "scope", from: view.applied.host, to: view.incoming.host }]
        : [];
  return [...head, ...takeovers, ...gatedChanges(view.applied.gated, view.incoming.gated)];
}

/**
 * Gated settings that add up when a name has two blocks instead of the first value winning like every other
 * setting (`ssh -G`, OpenSSH 10.3): every forward, every `SendEnv`. Lowercase, as a signature holds them.
 */
const ADDS_UP = new Set(["localforward", "remoteforward", "dynamicforward", "sendenv"]);

/**
 * What the held block's gated settings do next to another block of the same name that ssh may read first (spec
 * §4.3). ssh applies both and takes each setting from the first block that sets it, so the held block's settings
 * still apply unless an earlier block sets the same one — and forwards and `SendEnv` apply either way. "Its values
 * are kept" would read as if the held block's `ProxyCommand` were ignored; this names the settings that are not.
 * `otherFirst`: the other block is known to be read first (otherwise it may be, or not). Null when the block has
 * no gated setting.
 */
function stillApplies(gated: readonly string[], otherFirst: boolean): string | null {
  const names = (keywords: readonly string[]) => listNames(keywords.map(keywordLabel));
  const wins = gated.filter((keyword) => !ADDS_UP.has(keyword));
  const adds = gated.filter((keyword) => ADDS_UP.has(keyword));
  const sentences: string[] = [];
  if (wins.length > 0) {
    const [apply, them] = wins.length === 1 ? ["applies", "it"] : ["apply", "them"];
    sentences.push(
      otherFirst
        ? `${names(wins)} from this block still ${apply} unless that block sets ${them} too`
        : `${names(wins)} from this block ${apply} unless the other block is read first and sets ${them} too`,
    );
  }
  if (adds.length > 0) {
    const [apply, add] = adds.length === 1 ? ["applies", "it adds"] : ["apply", "they add"];
    sentences.push(`${names(adds)} from this block ${apply} either way, because ${add} up across blocks`);
  }
  return sentences.length > 0 ? `${sentences.join(". ")}.` : null;
}

/** A takeover note followed by what the held block's gated settings still do (nothing more when it has none). */
function withApplies(note: string, gated: readonly string[], otherFirst: boolean): string {
  const applies = stillApplies(gated, otherFirst);
  return applies === null ? note : `${note}. ${applies}`;
}

/** One change for the review, with hidden characters revealed (`revealHidden`). */
export function changeText(change: ApprovalChange): string {
  const v = revealHidden;
  switch (change.kind) {
    case "not_in_space":
      return `Not in ${v(change.space)} on this computer yet: Host ${v(change.host)}`;
    case "new_block":
      return `A new block in ${v(change.space)}: Host ${v(change.host)}`;
    case "takeover": {
      const { name, file, heldSpace, rank, gated } = change;
      switch (rank.kind) {
        case "synced_first":
          return `Takes over ${v(name)} in ${v(file)} (synced files are read first)`;
        case "own_file":
          return rank.appended
            ? withApplies(`${v(name)} is also a name of another block in ${v(file)}: that block comes first and its values win wherever it sets one`, gated, true)
            : withApplies(`${v(name)} is also a name of another block in ${v(file)}: whichever of the two blocks comes first there wins wherever it sets a value`, gated, false);
        case "space":
          return rank.before
            ? withApplies(`${v(name)} is also in ${v(file)} (space ${v(rank.space)}), which is read before ${v(heldSpace)}: its values win wherever it sets one`, gated, true)
            : `Takes over ${v(name)} in ${v(file)} (space ${v(rank.space)}, read after ${v(heldSpace)})`;
        case "unknown":
          return withApplies(`${v(name)} is also in ${v(file)}: ssh reads synced files first, and between two of them the Include order decides`, gated, false);
      }
    }
    case "scope":
      return `Applies to: ${v(change.from)} → ${v(change.to)}`;
    case "added":
      return `Adds ${keywordLabel(change.keyword)} ${v(change.value)}`;
    case "removed":
      return `Removes ${keywordLabel(change.keyword)} ${v(change.value)}`;
    case "changed":
      return `${keywordLabel(change.keyword)}: ${v(change.from)} → ${v(change.to)}`;
    case "moved":
      return `Order changed: ${keywordLabel(change.keyword)} ${v(change.value)}`;
  }
}

export interface ApprovalGroup {
  spaceId: string;
  spaceName: string;
  views: PendingApprovalView[];
}

/** Pending hosts per space, in the order the backend listed them (`sync_approve` takes one space at a time). */
export function approvalGroups(views: readonly PendingApprovalView[]): ApprovalGroup[] {
  const groups = new Map<string, ApprovalGroup>();
  for (const view of views) {
    const group = groups.get(view.space_id);
    if (group) group.views.push(view);
    else groups.set(view.space_id, { spaceId: view.space_id, spaceName: view.space_name, views: [view] });
  }
  return [...groups.values()];
}

/** What a decision sends back for the versions the review showed (`sync_approve` / `sync_reject`). */
export function reviewedVersions(views: readonly PendingApprovalView[]): ReviewedVersion[] {
  return views.map((v) => ({ alias: v.alias, digest: v.digest }));
}

/**
 * Whether two lists hold the same versions, in any order. A version is its space,
 * alias and content digest: new content for a host comes with a new digest, while
 * the same version pulled again later keeps its digest.
 */
export function sameVersions(a: readonly PendingApprovalView[], b: readonly PendingApprovalView[]): boolean {
  const key = (v: PendingApprovalView) => JSON.stringify([v.space_id, v.alias, v.digest]);
  const shown = new Set(a.map(key));
  return a.length === b.length && shown.size === a.length && b.every((v) => shown.has(key(v)));
}

/** One call's batch of versions and what the backend answered. */
export interface ReviewResult {
  batch: ApprovalGroup;
  outcome: ReviewOutcome;
}

/**
 * A decision: one call per space with exactly the versions of its batch
 * (`reviewedVersions`), in order. Stops at the first failure (the mutation shows
 * why); what already went through stays done and is returned.
 */
export async function runDecision(
  batches: readonly ApprovalGroup[],
  call: (spaceId: string, approvals: ReviewedVersion[]) => Promise<ReviewOutcome>,
): Promise<ReviewResult[]> {
  const results: ReviewResult[] = [];
  for (const batch of batches) {
    try {
      results.push({ batch, outcome: await call(batch.spaceId, reviewedVersions(batch.views)) });
    } catch {
      break;
    }
  }
  return results;
}

/** A host named in a notice, with its space: the same alias can wait in two spaces. */
export interface HostRef {
  spaceId: string;
  spaceName: string;
  alias: string;
}

/** What identifies a held host: its space and alias (one version waits per host). */
export function hostKey(spaceId: string, alias: string): string {
  return JSON.stringify([spaceId, alias]);
}

/**
 * The outcomes of one decision (one call per space) as one: how many hosts the
 * backend processed, which of the versions sent it processed (all but the hosts it
 * skipped), and the hosts it skipped because the waiting version was no longer the one sent.
 */
export function combineOutcomes(results: readonly ReviewResult[]): { applied: number; decided: PendingApprovalView[]; changed: HostRef[] } {
  return {
    applied: results.reduce((n, r) => n + r.outcome.applied, 0),
    decided: results.flatMap((r) => r.batch.views.filter((v) => !r.outcome.changed.includes(v.alias))),
    changed: results.flatMap((r) => r.outcome.changed.map((alias) => ({ spaceId: r.batch.spaceId, spaceName: r.batch.spaceName, alias }))),
  };
}

/** How a card differs from what the user saw: its content changed, or the host was not there. */
export type VersionMark = "changed" | "new";

/** What a card says about its mark. */
export function markText(mark: VersionMark): string {
  return mark === "changed" ? "Changed since you opened this — review it again" : "New since you opened this";
}

export interface Adoption {
  /** The marks after the newest list replaces the one on screen, by `hostKey`. */
  marks: Map<string, VersionMark>;
  /** Hosts whose waiting version is not the one that was on screen. */
  changed: HostRef[];
  /** Hosts that were not on screen. */
  added: HostRef[];
}

/**
 * Puts the newest list on screen without letting a host change unseen. Compared with
 * the list that was shown, a host with another digest is marked "changed" and a host
 * that was not there "new" (so is a host the user just decided on that comes back with
 * other content). A mark stays until the user decides on that host: neither the notice
 * going away nor "Show them" takes it off. Hosts that left the list lose theirs.
 * `decided` is what the backend processed in the decision that just ran.
 */
export function adoptNewest(
  shown: readonly PendingApprovalView[],
  fresh: readonly PendingApprovalView[],
  marks: ReadonlyMap<string, VersionMark>,
  decided: readonly PendingApprovalView[],
): Adoption {
  const seen = new Map(shown.map((v): [string, PendingApprovalView] => [hostKey(v.space_id, v.alias), v]));
  const done = new Map(decided.map((v): [string, PendingApprovalView] => [hostKey(v.space_id, v.alias), v]));
  const next = new Map<string, VersionMark>();
  const changed: HostRef[] = [];
  const added: HostRef[] = [];
  for (const view of fresh) {
    const key = hostKey(view.space_id, view.alias);
    const ref = { spaceId: view.space_id, spaceName: view.space_name, alias: view.alias };
    const decidedVersion = done.get(key);
    const before = decidedVersion ?? seen.get(key);
    if (before === undefined) {
      next.set(key, "new");
      added.push(ref);
    } else if (before.digest !== view.digest) {
      // A decided host that is back has a version the user never saw; a host still being reviewed changed under them.
      next.set(key, decidedVersion ? "new" : "changed");
      (decidedVersion ? added : changed).push(ref);
    } else if (!decidedVersion && marks.has(key)) {
      next.set(key, marks.get(key)!);
    }
  }
  return { marks: next, changed, added };
}

/**
 * What the review says when hosts differ from what was on screen: the ones that
 * changed (their newer version waits) and the ones that are new, each with its space
 * (hidden characters revealed); null when there are none. A host named in both is listed once, as changed.
 */
export function changedNotice(changed: readonly HostRef[], added: readonly HostRef[] = []): string | null {
  const key = (h: HostRef) => hostKey(h.spaceId, h.alias);
  const once = (hosts: readonly HostRef[]) => [...new Map(hosts.map((h): [string, HostRef] => [key(h), h])).values()];
  const changedHosts = once(changed);
  const changedKeys = new Set(changedHosts.map(key));
  const addedHosts = once(added).filter((h) => !changedKeys.has(key(h)));
  const names = (hosts: readonly HostRef[]) => hosts.map((h) => `${revealHidden(h.alias)} in ${revealHidden(h.spaceName)}`).join(", ");
  const sentences: string[] = [];
  if (changedHosts.length > 0) {
    sentences.push(`${names(changedHosts)} changed since you opened this — review ${changedHosts.length === 1 ? "it" : "them"} again.`);
  }
  if (addedHosts.length > 0) {
    sentences.push(`${names(addedHosts)} ${addedHosts.length === 1 ? "is" : "are"} new since you opened this — review ${addedHosts.length === 1 ? "it" : "them"}.`);
  }
  return sentences.length > 0 ? sentences.join(" ") : null;
}

/**
 * What "Approve all" / "Reject all" says once it ran, counting only what went through
 * (`done` of the `asked` hosts): a success only when everything did, otherwise a
 * warning with the count; null when nothing did (an error toast or the notice says why).
 */
export function decisionSummary(
  decision: "approve" | "reject",
  done: number,
  asked: number,
): { level: "success" | "warning"; text: string } | null {
  if (done <= 0) return null;
  const what = decision === "approve" ? "Applied" : "Kept this computer's version of";
  return done >= asked
    ? { level: "success", text: `${what} ${plural(done, "host")}` }
    : { level: "warning", text: `${what} ${done} of ${plural(asked, "host")}` };
}

/**
 * Whether a fetched list is ready to review: nothing is refreshing it and the last
 * fetch worked. A re-opened dialog first sees the list cached from an earlier
 * review while the refetch runs, and that list can be out of date (even empty).
 */
export function isSettled(query: { isSuccess: boolean; isFetching: boolean }): boolean {
  return query.isSuccess && !query.isFetching;
}

/**
 * Whether the newest list can replace the one on screen without asking: nothing was
 * on screen, so there is no version to keep in place. Hosts that arrive then are shown
 * at once (marked new) instead of behind "Newer versions arrived".
 */
export function adoptAtOnce(shown: readonly PendingApprovalView[], newest: readonly PendingApprovalView[]): boolean {
  return shown.length === 0 && newest.length > 0;
}

/** What sits above the review's list: each one pushes the list down or up where it appears or goes away. */
export interface AboveList {
  /** The paragraph that says approvals are off (`structureLock`), or null. */
  lock: string | null;
  /** The paragraph that names hosts that changed or are new, or null. */
  notice: string | null;
  /** The "Newer versions arrived" banner is on screen. */
  newer: boolean;
}

/**
 * Whether the list (and the buttons in it) moved on screen because of what sits above it. The dialog is
 * centred, so when a paragraph appears, goes away or says something else (a longer text wraps onto more
 * lines) the list shifts while the pointer has not: a click aimed at one host's button lands on another's.
 * The review keeps the decision buttons off for a moment whenever this is true, as it does when the list
 * itself was replaced.
 */
export function listMoved(before: AboveList, after: AboveList): boolean {
  return before.lock !== after.lock || before.notice !== after.notice || before.newer !== after.newer;
}

/**
 * What makes a synced host wait for approval, as one phrase: the toast, the Review row in Settings → Sync and the
 * review dialog all say it, so they say the same (`GATED_KEYWORDS`: programs run here, on the server, credentials,
 * environment or network shared, host-key checks relaxed).
 */
export const GATED_SETTINGS =
  "settings that run programs (on this computer or on the server), share your credentials, environment or network, or relax host-key checks";

/** The review dialog's introduction. */
export const REVIEW_INTRO = `These hosts came from your other computers with ${GATED_SETTINGS}. Nothing is applied until you approve it. Rejecting keeps this computer's version and sends nothing back.`;

/** The Review row's description in Settings → Sync: what held hosts bring, and why Review is off when `lock` says so (`structureLock`). */
export function approvalsRowNote(lock: string | null): string {
  return `They bring ${GATED_SETTINGS}. Nothing changes until you approve them.${lock ? ` ${lock}` : ""}`;
}

/** `sync://approval`: hosts newly held back this round. */
export function approvalMessage(notices: readonly ApprovalNotice[]): SyncMessage | null {
  const aliases = notices.flatMap((n) => n.aliases);
  if (aliases.length === 0) return null;
  const one = aliases.length === 1;
  return {
    title: one ? `${revealHidden(aliases[0])} needs your approval` : `${aliases.length} synced hosts need your approval`,
    description: `${one ? "It came" : "They came"} from another computer with ${GATED_SETTINGS}. Nothing changes until you approve ${one ? "it" : "them"}.`,
  };
}
