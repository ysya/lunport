import type { DuplicateAlias } from "@/bindings/DuplicateAlias";
import type { HostSummary } from "@/bindings/HostSummary";
import type { SyncSpaceView } from "@/bindings/SyncSpaceView";
import { listNames } from "@/lib/format";
import { revealHidden } from "@/lib/sync-approvals";
import { spaceProblem } from "@/lib/sync-spaces";

/**
 * The files of the spaces this computer syncs, each labeled with its space's
 * name (spec §8: the sidebar shows one group per synced space). Insertion order
 * is the backend's, which is the order of the Include line. The labels are for
 * display — headers, menus, toasts, confirms — and another computer chose the
 * names, so bidi and zero-width characters in them are revealed (`revealHidden`).
 */
export function spaceFileLabels(spaces: readonly SyncSpaceView[]): Map<string, string> {
  return new Map(spaces.flatMap((s) => (s.selected && s.file_path ? [[s.file_path, revealHidden(s.name)] as [string, string]] : [])));
}

/**
 * The problem of each synced space, keyed like `spaceFileLabels` (by file): the group header
 * in the sidebar shows it as a warning marker, so a paused or missing space is visible
 * where its hosts are, not only in Settings → Sync.
 */
export function spaceFileProblems(spaces: readonly SyncSpaceView[]): Map<string, string> {
  return new Map(
    spaces.flatMap((s) => {
      const problem = s.selected && s.file_path ? spaceProblem(s) : null;
      return problem && s.file_path ? [[s.file_path, problem.text] as [string, string]] : [];
    }),
  );
}

/** Identifies one copy of an alias: the same alias can sit in several files. */
export function shadowKey(file: string, alias: string): string {
  return JSON.stringify([file, alias]);
}

/**
 * The copies ssh reads second (spec §4.3: the space file that comes first in the
 * Include line is read first, and where it sets a value that value wins), keyed by
 * `shadowKey`, each mapped to the space file whose copy is read first — the row
 * marker names it. `spaceFiles` is in Include order (`spaceFileLabels(...).keys()`).
 */
export function shadowedCopies(
  duplicates: readonly DuplicateAlias[],
  hosts: readonly HostSummary[],
  spaceFiles: readonly string[],
): Map<string, string> {
  const out = new Map<string, string>();
  for (const d of duplicates) {
    const winner = spaceFiles.find((file) => file !== d.local_file && hosts.some((h) => h.source_file === file && h.alias === d.alias));
    if (winner) out.set(shadowKey(d.local_file, d.alias), winner);
  }
  return out;
}

/**
 * What ssh does with two blocks for one name (spec §4.3): it applies every matching block and takes each
 * setting from the first one that sets it, so what only a later copy sets still applies — a `ProxyCommand`
 * included — and options that can repeat add up. Every text about duplicate hosts says this; none may say
 * that the later copy is ignored.
 */
export const SSH_COMBINES =
  "ssh applies every copy and takes each setting from the first one that sets it, so a setting only a later copy has still applies, and options that can repeat (IdentityFile, LocalForward, RemoteForward, DynamicForward, SendEnv) add up";

/**
 * The tooltip of the amber marker on a copy ssh reads second. `winner` labels the copy it reads first;
 * `inSpace`: this copy is in another space's file (otherwise in your own config, where synced files come first).
 */
export function shadowTooltip(alias: string, winner: string, inSpace: boolean): string {
  const why = inSpace ? `${winner} comes first in the Include line` : "synced files are read before the rest of your config";
  return `${alias} is also in ${winner}, which ssh reads first (${why}). ${SSH_COMBINES}.`;
}

/** The row menu's label for removing the copy ssh reads second: the other copy stays. */
export function removeCopyLabel(winner: string): string {
  return `Remove this copy (the one in ${winner} stays)`;
}

/** One place a name is defined: its file, and the space's name when that file is a synced space's. */
export interface NameCopy {
  file: string;
  space: string | null;
  /**
   * The name is the block's first pattern (`Host web`, `Host web db`; not `Host db web`): the only blocks the
   * backend lists as duplicates and the sidebar's file-addressed fixes can find (`migrate::duplicate_aliases`).
   */
  first: boolean;
}

/**
 * The names that more than one block defines while at least one of those blocks sits in a synced
 * space's file, each with its copies: the space files in Include order (the Include line is at the top
 * of the main config, so ssh reads those first, in that order), then the other files as they are loaded —
 * which is NOT the order ssh reads them in (an `Include` above a block is read before it). A name counts
 * when ANY pattern of a block carries it, which is how the backend finds a host by alias
 * (`find_host_file_index`): for such a name an edit, removal or move by alias lands on the first block in
 * load order, which may not be the copy the user selected. Duplicates entirely outside space files are not
 * listed: they keep working as they always did. `spaceFiles` is `spaceFileLabels(...)`: file → space name,
 * in Include order; an empty map means no space is synced. `undefined` means it is not known yet (the sync
 * overview is loading or failed): the check fails closed — every name with several copies counts, none of
 * them called synced, in load order — so nothing is edited by name on a guess.
 */
export function ambiguousNames(
  hosts: readonly Pick<HostSummary, "patterns" | "source_file">[],
  spaceFiles: ReadonlyMap<string, string> | undefined,
): Map<string, NameCopy[]> {
  const out = new Map<string, NameCopy[]>();
  if (spaceFiles?.size === 0) return out;
  const defined = new Map<string, { file: string; first: boolean }[]>(); // name → the blocks that carry it, in load order
  for (const host of hosts) {
    for (const name of new Set(host.patterns)) {
      const copy = { file: host.source_file, first: host.patterns[0] === name };
      const copies = defined.get(name);
      if (copies) copies.push(copy);
      else defined.set(name, [copy]);
    }
  }
  if (spaceFiles === undefined) {
    for (const [name, copies] of defined) {
      if (copies.length >= 2) out.set(name, copies.map((copy) => ({ ...copy, space: null })));
    }
    return out;
  }
  const includeOrder = [...spaceFiles.keys()];
  for (const [name, copies] of defined) {
    if (copies.length < 2 || !copies.some((copy) => spaceFiles.has(copy.file))) continue;
    const inSpaces = copies.filter((copy) => spaceFiles.has(copy.file)).sort((a, b) => includeOrder.indexOf(a.file) - includeOrder.indexOf(b.file));
    const elsewhere = copies.filter((copy) => !spaceFiles.has(copy.file));
    out.set(
      name,
      [...inSpaces, ...elsewhere].map((copy) => ({ ...copy, space: spaceFiles.get(copy.file) ?? null })),
    );
  }
  return out;
}

/**
 * Whether a row is the selected one. Rows are selected by alias AND file when the alias has several
 * copies, so clicking one never highlights the other; an alias with a single copy is selected by
 * alias alone, as before.
 */
export function isSelectedRow(
  host: Pick<HostSummary, "alias" | "source_file">,
  selected: { alias: string | null; file: string | null },
  ambiguous: boolean,
): boolean {
  if (host.alias !== selected.alias) return false;
  return !ambiguous || host.source_file === selected.file;
}

/** The distinct files' labels, for a sentence. */
function placesOf(copies: readonly NameCopy[], labelOf: (file: string) => string): string {
  return listNames([...new Set(copies.map((copy) => labelOf(copy.file)))]);
}

/**
 * Why the actions that find a host by its name (edit, rename, move, remove, drag) are off on every
 * row of an alias with several copies: SSHelter cannot tell which copy they would change.
 */
export function ambiguityReason(alias: string, copies: readonly NameCopy[], labelOf: (file: string) => string): string {
  return `${alias} is defined in ${placesOf(copies, labelOf)}, so SSHelter can't tell which copy this would change. Select the host to see how to fix that.`;
}

/** One copy in the editor pane's explanation. */
export interface CopyLine {
  label: string;
  file: string;
  /** `synced space` or `not synced`; null while it is not known which are synced. */
  detail: string | null;
  /** What can be done about this copy: the sidebar's fixes where it has them, else editing its file by hand; null while nothing is known. */
  how: string | null;
}

/** Copies the explanation lists together: the synced spaces (whose order is known), or the other files (whose order is not). */
export interface CopiesGroup {
  heading: string;
  /** Numbered: the copies are in the order ssh reads them. Only the synced spaces can say so. */
  ordered: boolean;
  copies: CopyLine[];
}

export interface CopiesNote {
  title: string;
  /** Why no copy is placed: the sync state is not known (yet). Null otherwise. */
  unknown: string | null;
  groups: CopiesGroup[];
  /** How ssh combines them (`SSH_COMBINES`). */
  combine: string;
  /** What SSHelter does not do, and when the name can be edited again. */
  fix: string;
}

/**
 * What the editor pane says in place of the editor for an alias with several copies. `copies` is as
 * `ambiguousNames` lists them (the synced ones in Include order). `shadows` is `shadowedCopies(...)`:
 * the copies the sidebar has file-addressed fixes for. The backend lists only a copy that starts with the
 * name and sits in another file than the one ssh reads first, so a name that is a later pattern of a block
 * (`Host a web`), and a second block in the same file, have none: those say what does work — edit the file.
 * `spacesKnown` false: the sync overview has not been read, so which copy is synced, and which one ssh reads
 * first, is not known — the note says so and leaves every copy alone, claiming nothing about any of them.
 */
export function copiesNote(
  alias: string,
  copies: readonly NameCopy[],
  labelOf: (file: string) => string,
  shadows: ReadonlyMap<string, string> = new Map(),
  spacesKnown = true,
): CopiesNote {
  const title = `${alias} is defined in more than one place`;
  const combine = `${SSH_COMBINES}.`;
  if (!spacesKnown) {
    return {
      title,
      unknown:
        "SSHelter has not read which spaces this computer syncs, so it can't tell whether one of these copies is synced, or which one ssh reads first.",
      groups: [{ heading: "The copies:", ordered: false, copies: copies.map((copy) => ({ label: labelOf(copy.file), file: copy.file, detail: null, how: null })) }],
      combine,
      fix: "Until it can, SSHelter leaves all of them alone. If this stays, Settings → Sync shows why.",
    };
  }
  const line = (copy: NameCopy): CopyLine => ({
    label: labelOf(copy.file),
    file: copy.file,
    detail: copy.space !== null ? "synced space" : "not synced",
    how:
      copy.first && shadows.has(shadowKey(copy.file, alias))
        ? `In the sidebar, open this copy's menu (the ⋯ button or a right-click) and choose “Keep this copy as ${alias}-local” or “Remove this copy”.`
        : "The sidebar has no action for this copy. To rename or remove it, edit this file in a text editor, then choose Reload from disk.",
  });
  const synced = copies.filter((copy) => copy.space !== null).map(line);
  const others = copies.filter((copy) => copy.space === null).map(line);
  const groups: CopiesGroup[] = [];
  if (synced.length > 0) {
    groups.push(
      synced.length === 1
        ? { heading: "In a synced space, which ssh reads first:", ordered: false, copies: synced }
        : { heading: "In synced spaces, which ssh reads first, in this order:", ordered: true, copies: synced },
    );
  }
  if (others.length > 0) {
    groups.push({
      heading: "In other files, which ssh reads after the synced spaces (their order among themselves isn't shown):",
      ordered: false,
      copies: others,
    });
  }
  return {
    title,
    unknown: null,
    groups,
    combine,
    fix: `SSHelter edits, renames, moves and removes a host by its name, so it can't tell which copy you mean and leaves all of them alone. Once only one copy is left, ${alias} can be edited again.`,
  };
}

/** What the deploy result says instead of writing `IdentityFile` into the first copy of a host that has several. */
export function identityFileNote(alias: string, value: string): string {
  return `${alias} is defined in more than one place, so SSHelter did not edit it. Once only one copy is left, add “IdentityFile ${value}” to it so that ssh offers this key.`;
}

/** One fix of a copy that ssh reads second (the sidebar's row menu and the wizard's list), addressed by file. */
export interface ShadowFix {
  alias: string;
  action: "rename" | "remove";
  /** The shadowed copy's file, which the backend finds the host in. */
  file: string;
  fileLabel: string;
  /** The space this file belongs to, or null when it is one of the user's own files. */
  space: string | null;
  /** The label of the copy ssh reads first, which the fix never touches. */
  winner: string;
}

/**
 * What the confirm says about a fix, and the toast after it. A copy in a synced space is a change that
 * every computer syncing that space receives (a remote deletion applies without asking); a copy in the
 * user's own file changes this computer only. Never "ssh uses X": the other copy stays, and ssh still
 * combines both until one is gone.
 */
export function shadowFixText(fix: ShadowFix): { title: string; description: string; confirm: string; done: string } {
  const { alias, action, fileLabel, space, winner } = fix;
  const local = `${alias}-local`;
  const untouched = `The copy in ${winner} is not touched.`;
  const backup = "A backup is written first, so it can be restored from Backup history.";
  if (action === "remove") {
    return {
      title: `Remove the copy of ${alias} in ${fileLabel}?`,
      description:
        space !== null
          ? `${alias} is in the synced space “${space}”, so this also removes it on every computer that syncs ${space}. ${untouched} ${backup}`
          : `Only this computer changes: the copy is deleted from ${fileLabel}. ${untouched} ${backup}`,
      confirm: "Remove this copy",
      done: `Removed the copy of ${alias} in ${fileLabel}`,
    };
  }
  return {
    title: `Keep the copy of ${alias} in ${fileLabel} as ${local}?`,
    description:
      space !== null
        ? `The copy is renamed to ${local} in the synced space “${space}”, so every computer that syncs ${space} gets ${local} and loses its copy of ${alias}. ${untouched} ${backup}`
        : `Only this computer changes: the copy in ${fileLabel} is renamed to ${local}. ${untouched} ${backup}`,
    confirm: `Keep as ${local}`,
    done: `Renamed the copy of ${alias} in ${fileLabel} to ${local}`,
  };
}

/**
 * For a removal of hosts that live in `files`: what the confirm adds when some of them are in a
 * synced space — the deletion reaches every computer that syncs it. Null when none is, so the
 * confirm stays as it was. `spaceLabels` is `spaceFileLabels(...)`.
 */
export function removalSyncNote(files: readonly string[], spaceLabels: ReadonlyMap<string, string>): string | null {
  const names = files.flatMap((file) => spaceLabels.get(file) ?? []);
  if (names.length === 0) return null;
  const spaces = [...new Set(names)];
  const where = `${spaces.length === 1 ? "the synced space" : "the synced spaces"} ${listNames(spaces.map((name) => `“${name}”`))}`;
  const everywhere = `on every computer that syncs ${spaces.length === 1 ? "that space" : "those spaces"}`;
  if (files.length === 1) return `This host is in ${where}: removing it here removes it ${everywhere}.`;
  const who = names.length === files.length ? "These hosts are" : names.length === 1 ? "One of these hosts is" : `${names.length} of these hosts are`;
  const them = names.length === 1 ? "it" : "them";
  return `${who} in ${where}: removing ${them} here removes ${them} ${everywhere}.`;
}
