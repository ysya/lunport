import type { HostSummary } from "@/bindings/HostSummary";
import type { MigrationFailure } from "@/bindings/MigrationFailure";
import type { MigrationReport } from "@/bindings/MigrationReport";
import type { NewSpaceGroup } from "@/bindings/NewSpaceGroup";
import type { SyncSpaceView } from "@/bindings/SyncSpaceView";
import { plural } from "@/lib/format";
import { revealHidden } from "@/lib/sync-approvals";
import { MAX_SPACE_NAME, spaceNameError } from "@/lib/sync-spaces";
import { basename } from "@/lib/utils";

/**
 * Same rule as the backend's `hosts_file::is_syncable_block`: every pattern must be
 * a plain name. `Host web *.internal` or `Host web !prod` is a wildcard rule, not a
 * host — the sidebar's `isWildcardOnly` (all patterns wildcard, `!` ignored) is the
 * wrong predicate for sync.
 */
export function isSyncableHost(h: HostSummary): boolean {
  return h.patterns.length > 0 && h.patterns.every((p) => p !== "" && !/[*?!]/.test(p));
}

/**
 * Tidy a pasted sync code before the backend validates it: one line,
 * single spaces, lowercase, no list numbering or stray punctuation.
 */
export function cleanWordsInput(raw: string): string {
  return raw
    .split(/\r?\n/)
    .map((line) => line.replace(/^\s*\d+\s*[.)\-:]?\s*/, ""))
    .join(" ")
    .toLowerCase()
    .replace(/[^a-z\s\u3000]/g, " ")
    .replace(/[\s\u3000]+/g, " ")
    .trim();
}

/** How many words a sync code has: the Join and Enter buttons wait for exactly this many. */
export const SYNC_CODE_WORDS = 24;

/** Words in a pasted sync code after `cleanWordsInput`. */
export function wordCount(raw: string): number {
  const cleaned = cleanWordsInput(raw);
  return cleaned === "" ? 0 : cleaned.split(" ").length;
}

export interface MigrationGroup {
  file: string;
  hosts: HostSummary[];
}

/**
 * Hosts that can still move into a space, grouped by their current file
 * (`spaceFiles` = the files of the spaces this computer syncs). A local host that
 * shares any name with a host in any space is left out: in the same space the
 * backend refuses it, and in another space it would make a second copy of the name
 * (ssh applies both and takes each setting from the first one that sets it, and
 * SSHelter then edits that name by neither copy) — and right after joining these are
 * exactly the local copies of hosts the account already has (the duplicates list
 * offers to rename or remove them). Hosts the
 * backend can never move (`unmovable`, from `sync_unmovable_hosts`: an `Include`,
 * a value ssh would pass to a shell, …) are listed separately, each with its reason.
 */
export function groupHostsForMigration(
  hosts: readonly HostSummary[],
  spaceFiles: readonly string[],
  unmovable: ReadonlySet<string>,
): MigrationGroup[] {
  const inSpace = new Set(spaceFiles);
  const syncedNames = new Set(hosts.filter((h) => inSpace.has(h.source_file)).flatMap((h) => h.patterns));
  const byFile = new Map<string, HostSummary[]>();
  for (const h of hosts) {
    if (inSpace.has(h.source_file) || !isSyncableHost(h) || unmovable.has(h.alias)) continue;
    if (h.patterns.some((p) => syncedNames.has(p))) continue;
    const bucket = byFile.get(h.source_file);
    if (bucket) bucket.push(h);
    else byFile.set(h.source_file, [h]);
  }
  return [...byFile.entries()].map(([file, hosts]) => ({ file, hosts }));
}

/**
 * The selection limited to hosts the wizard still lists. A selected host can
 * drop out of the list — e.g. a same-name local host once the first sync brings
 * in its synced twin — and must then neither count toward "Move N hosts" nor be
 * submitted. Returns `selected` itself when nothing was dropped, so a state
 * update with the result is a no-op.
 */
export function keepVisible(selected: Set<string>, groups: { hosts: { alias: string }[] }[]): Set<string> {
  const visible = new Set(groups.flatMap((g) => g.hosts.map((h) => h.alias)));
  const kept = new Set([...selected].filter((alias) => visible.has(alias)));
  return kept.size === selected.size ? selected : kept;
}

/** The wizard's target value for "one new space per source file". */
export const PER_FILE = "__per_file__";

/**
 * The backend's `migrate::tag_for_file`: the file name without `.config` / `.conf`
 * (case-sensitive), lowercased, every run of characters outside `[a-z0-9_-]`
 * turned into one `-`, with `-` trimmed from both ends.
 */
export function tagForFile(path: string): string {
  const name = basename(path);
  const stem = (name.endsWith(".config") ? name.slice(0, -7) : name.endsWith(".conf") ? name.slice(0, -5) : name).toLowerCase();
  let out = "";
  for (const ch of stem) {
    if (/^[a-z0-9_-]$/.test(ch)) out += ch;
    else if (!out.endsWith("-")) out += "-";
  }
  return out.replace(/^-+|-+$/g, "");
}

function truncate(name: string, max: number): string {
  return [...name].slice(0, max).join("").trimEnd();
}

/**
 * The sidebar label the user gave a file, when it can name a space: the backend refuses a space name
 * with a control character, and the whole group of hosts with it, so such a label is not used (the
 * file's tag is). A label that is too long is shortened by `uniqueSpaceName`.
 */
function usableAlias(alias: string | undefined): string | null {
  const trimmed = alias?.trim() ?? "";
  return trimmed !== "" && spaceNameError(truncate(trimmed, MAX_SPACE_NAME), []) === null ? trimmed : null;
}

/** `base`, or `base 2`, `base 3`… — the first one no name in `taken` matches, ignoring case (like the backend). */
export function uniqueSpaceName(base: string, taken: Iterable<string>): string {
  const used = new Set([...taken].map((n) => n.toLowerCase()));
  const first = truncate(base, MAX_SPACE_NAME);
  if (!used.has(first.toLowerCase())) return first;
  for (let n = 2; ; n += 1) {
    const suffix = ` ${n}`;
    const name = truncate(base, MAX_SPACE_NAME - suffix.length) + suffix;
    if (!used.has(name.toLowerCase())) return name;
  }
}

/**
 * "One new space per source file" (spec §7.2): each file's space is named after
 * the file — the sidebar label the user gave it, else its tag (`tagForFile`) —
 * and made unique against the account's spaces and the other new ones, so no
 * group fails on a taken name. Computed for every listed file so the names stay
 * put while the user changes the selection.
 */
export function plannedSpaceNames(
  groups: readonly MigrationGroup[],
  fileAliases: Record<string, string>,
  existing: readonly string[],
): Map<string, string> {
  const taken = [...existing];
  const names = new Map<string, string>();
  for (const g of groups) {
    const base = usableAlias(fileAliases[g.file]) ?? (tagForFile(g.file) || "Space");
    const name = uniqueSpaceName(base, taken);
    taken.push(name);
    names.set(g.file, name);
  }
  return names;
}

/**
 * What `sync_move_files_to_new_spaces` gets: one group per file that has selected
 * hosts, each host once. The backend moves a name only for the first group that
 * lists it — as an alias, or as another name of a host that group moves
 * (`Host db database`) — and fails it as "listed in more than one group" after
 * that, so a host defined in two files goes with the file listed first.
 */
export function newSpaceGroups(groups: readonly MigrationGroup[], selected: ReadonlySet<string>, names: ReadonlyMap<string, string>): NewSpaceGroup[] {
  const sent = new Set<string>();
  return groups.flatMap((g) => {
    const aliases: string[] = [];
    for (const h of g.hosts) {
      if (!selected.has(h.alias) || sent.has(h.alias)) continue;
      aliases.push(h.alias);
      for (const name of [h.alias, ...h.patterns]) sent.add(name);
    }
    const name = names.get(g.file);
    return aliases.length > 0 && name ? [{ name, aliases }] : [];
  });
}

/**
 * Whether `id` is a target the wizard can move hosts into: one new space per file, or a space this
 * computer syncs whose data is not missing on the relay (a move into it succeeds, and then the space
 * stays paused until it is rebuilt).
 */
export function isValidTarget(spaces: readonly SyncSpaceView[], id: string | null): boolean {
  return id === PER_FILE || spaces.some((s) => s.id === id && s.selected && !s.missing);
}

/**
 * Where the wizard moves hosts: the space it was opened for, while this computer
 * syncs it and it is not missing; else the first synced space past its first sync
 * (else any synced one that is not missing); else one new space per file.
 */
export function migrationTarget(spaces: readonly SyncSpaceView[], requested: string | null): string {
  if (requested && isValidTarget(spaces, requested)) return requested;
  const usable = spaces.filter((s) => s.selected && !s.missing);
  return (usable.find((s) => !s.first_sync_pending) ?? usable[0])?.id ?? PER_FILE;
}

/** What decides whether "Move N hosts" can be pressed. */
export interface MoveState {
  /** How many of the selected hosts the wizard still lists. */
  selected: number;
  pending: boolean;
  /** The target space was just turned on and its first sync is not done. */
  waitingForFirstSync: boolean;
  /** `PER_FILE` or a space id. */
  target: string;
  /** The space `target` names, when it names one this computer syncs. */
  targetSpace: Pick<SyncSpaceView, "missing"> | null;
}

/** Hosts are selected, nothing runs, the target is ready for them: not waiting for its first sync, and not a space whose data is missing. */
export function canMove(state: MoveState): boolean {
  if (state.selected === 0 || state.pending || state.waitingForFirstSync) return false;
  return state.target === PER_FILE || (state.targetSpace !== null && !state.targetSpace.missing);
}

/** Where the toast says the hosts went: the space's name (another computer chose it, so hidden characters are revealed). */
export function intoSpace(name: string): string {
  return `into ${revealHidden(name)}`;
}

/** What the wizard says while a space that was just turned on has not finished its first sync. */
export function firstSyncWait(name: string): string {
  return `Waiting for the first sync of ${revealHidden(name)} to finish…`;
}

/** A synced space's entry in the target list: its name, and what keeps it from taking hosts yet. */
export function targetLabel(s: Pick<SyncSpaceView, "name" | "missing" | "first_sync_pending">): string {
  return `${revealHidden(s.name)}${s.missing ? " (needs rebuild)" : s.first_sync_pending ? " (first sync…)" : ""}`;
}

/**
 * What the backend writes in `failed` for a host that did move but whose tag could not be saved
 * (`migrate::migrate_hosts`): the host is in the space, and only listed as a problem.
 */
export const TAG_FAILED_PREFIX = "moved, but its tag could not be saved";

/**
 * The toast after a move: the hosts that moved — a host whose tag failed moved too — and how many have a
 * problem. A warning when any has one, whether or not anything moved.
 */
export function moveSummary(report: MigrationReport, into: string): { level: "success" | "warning"; text: string } {
  const moved = report.moved.length + report.failed.filter((f) => f.error.startsWith(TAG_FAILED_PREFIX)).length;
  const problems = report.failed.length;
  const head = moved === 0 ? `No host moved ${into}` : `Moved ${plural(moved, "host")} ${into}`;
  return { level: problems > 0 ? "warning" : "success", text: `${head}${problems > 0 ? `, ${plural(problems, "host")} with a problem` : ""}` };
}

/** Hosts that share one reason, in the order the reasons first appear: the relay's rate limit, say, is one line however many hosts it stopped. */
export function groupByReason(failures: readonly MigrationFailure[]): { error: string; aliases: string[] }[] {
  const groups = new Map<string, string[]>();
  for (const failure of failures) {
    const aliases = groups.get(failure.error);
    if (aliases) aliases.push(failure.alias);
    else groups.set(failure.error, [failure.alias]);
  }
  return [...groups].map(([error, aliases]) => ({ error, aliases }));
}

/**
 * Preselect every listed host only for a fresh account — every synced space empty
 * and past its first sync (right after "Create") — otherwise the user picks.
 */
export function preselectAll(spaces: readonly SyncSpaceView[]): boolean {
  const synced = spaces.filter((s) => s.selected);
  return synced.length > 0 && synced.every((s) => !s.first_sync_pending && s.hosts === 0);
}
