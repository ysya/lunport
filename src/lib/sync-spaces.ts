import type { SyncOverview } from "@/bindings/SyncOverview";
import type { SyncSpaceView } from "@/bindings/SyncSpaceView";
import { listNames, plural } from "@/lib/format";
import { revealHidden } from "@/lib/sync-approvals";
import type { Tone } from "@/lib/sync-overview";

/** The backend's limit (`spaces::clean_space_name`), in characters. */
export const MAX_SPACE_NAME = 64;

/** `On MacBook-A and MacBook-B`, or that no computer syncs the space: the Spaces list and the chooser say it the same way. */
export function syncedOnText(syncedOn: readonly string[]): string {
  return syncedOn.length > 0 ? `On ${listNames(syncedOn)}` : "Not synced on any computer";
}

export interface SpaceRow {
  id: string;
  /** The name as it is (a rename starts from it). */
  name: string;
  /**
   * The name as the UI shows it: another computer chose it, so bidi and zero-width characters in it are
   * revealed (`revealHidden`) instead of reordering or hiding part of the sentence around it.
   */
  label: string;
  selected: boolean;
  fileName: string | null;
  /** `work-3fa2c1d9.config · 3 hosts`, or "Not on this computer". */
  detail: string;
  syncedOn: string;
  status: { tone: Tone; text: string } | null;
  /** The relay lost the space's data: offer "Rebuild" and "Delete" (spec §9). */
  missing: boolean;
  pendingUploads: number;
}

/**
 * What stops a space from syncing: its data is gone from the relay (spec §9), or an error paused it (a
 * refused file, a failed write). Null for a healthy space. The most urgent state of a space, and the one
 * the status row, the Spaces list and the sidebar's group header all report.
 */
export function spaceProblem(s: SyncSpaceView): { tone: "error"; text: string } | null {
  if (s.missing) return { tone: "error", text: "Its data is missing on the relay. Rebuild it from this computer, or delete the space." };
  if (s.last_error) return { tone: "error", text: s.last_error };
  return null;
}

function spaceStatus(s: SyncSpaceView): SpaceRow["status"] {
  const problem = spaceProblem(s);
  if (problem) return problem;
  if (s.first_sync_pending) return { tone: "busy", text: "Syncing for the first time…" };
  if (s.approvals > 0) return { tone: "warning", text: `${plural(s.approvals, "host")} waiting for your approval` };
  if (s.pending_uploads > 0) return { tone: "ok", text: `${plural(s.pending_uploads, "change")} waiting to upload` };
  return null;
}

/** The Spaces list (spec §8), in the backend's order (the order of the Include line). */
export function spaceRows(o: SyncOverview): SpaceRow[] {
  return o.spaces.map((s) => ({
    id: s.id,
    name: s.name,
    label: revealHidden(s.name),
    selected: s.selected,
    fileName: s.file_name,
    detail: s.selected && s.file_name ? [s.file_name, s.hosts === null ? null : plural(s.hosts, "host")].filter(Boolean).join(" · ") : "Not on this computer",
    syncedOn: syncedOnText(s.synced_on),
    status: spaceStatus(s),
    missing: s.missing,
    pendingUploads: s.pending_uploads,
  }));
}

/** The title of the confirm before turning a space off on this computer. */
export const stopSyncingTitle = (row: Pick<SpaceRow, "label">): string => `Stop syncing “${row.label}” on this computer?`;

/** The title of the confirm before deleting a space everywhere. */
export const deleteSpaceTitle = (row: Pick<SpaceRow, "label">): string => `Delete “${row.label}” everywhere?`;

/** The toast after a space was deleted. */
export const deletedSpaceToast = (row: Pick<SpaceRow, "label">): string => `Deleted “${row.label}”`;

/** The title of the rename dialog. */
export const renameSpaceTitle = (row: Pick<SpaceRow, "label">): string => `Rename “${row.label}”`;

/** The toasts after a space was created or renamed: the name the user typed, as it will be shown everywhere. */
export const createdSpaceToast = (name: string): string => `Created “${revealHidden(name)}”`;
export const renamedSpaceToast = (name: string): string => `Renamed to “${revealHidden(name)}”`;

/** The states in which the account takes no structural change and no decision on a held host. */
export type AccountBlock = "upgrading" | "not_joined" | "frozen" | "rotating" | "read_only";

/**
 * Which of those states the account is in, if any, in the order the backend checks them
 * (`account::account_ready`; an unfinished v1 upgrade shows as not joined). The one ladder
 * `structureLock` and `changeCodeBlocker` both read.
 */
export function accountBlock(o: SyncOverview): AccountBlock | null {
  if (o.upgrading) return "upgrading";
  if (!o.joined) return "not_joined";
  if (o.frozen) return "frozen";
  if (o.rotation) return "rotating";
  if (o.read_only) return "read_only";
  return null;
}

/**
 * Why spaces cannot be created, renamed, deleted, turned on or off, and why held hosts cannot be
 * approved or rejected, right now — the same states the backend refuses (`account::account_ready`) —
 * or null. While the sync code is being changed the way out is to wait or, until the old data is
 * frozen, to cancel (`ROTATING_MESSAGE`: "finish or cancel changing the sync code first").
 */
export function structureLock(o: SyncOverview): string | null {
  switch (accountBlock(o)) {
    case null:
      return null;
    case "upgrading":
      return "Wait until this computer has finished upgrading its sync.";
    case "not_joined":
      return "Join or create a sync account first.";
    case "frozen":
      return "Enter the new sync code first.";
    case "rotating":
      return o.rotation?.cancellable
        ? "Wait for the new sync code to be in place, or cancel the change first."
        : "Wait for the new sync code to be in place first.";
    case "read_only":
      return "Update SSHelter first: this sync account uses a newer format.";
  }
}

/**
 * The backend's rules for a space name (`spaces::clean_space_name` and the
 * case-insensitive uniqueness check), so the dialog can say what is wrong before
 * sending. `exceptId` is the space being renamed.
 */
export function spaceNameError(name: string, spaces: readonly SyncSpaceView[], exceptId?: string): string | null {
  const trimmed = name.trim();
  if (trimmed === "") return "Enter a name.";
  if (/\p{Cc}/u.test(trimmed)) return "A name can't contain control characters.";
  if ([...trimmed].length > MAX_SPACE_NAME) return `Use at most ${MAX_SPACE_NAME} characters.`;
  const lower = trimmed.toLowerCase();
  if (spaces.some((s) => s.id !== exceptId && s.name.toLowerCase() === lower)) return `A space named “${trimmed}” already exists.`;
  return null;
}

/**
 * What the confirm says after the file's name when a space is turned off on this computer. Turning
 * a space off backs its file up and removes it here and leaves the space everywhere else — except
 * that a space whose data is missing on the relay may exist nowhere but in this file, so "turn it
 * back on any time" would promise what cannot be done.
 */
export function unselectNote(row: Pick<SpaceRow, "missing" | "pendingUploads">): string {
  if (row.missing) {
    return "is backed up and removed from this computer, and ssh stops reading it. The space's data is missing on the relay, so this file may be the only copy of its hosts: the backup keeps it, but turning the space on again finds nothing to sync from. Rebuild the space first to keep syncing it.";
  }
  const unsent =
    row.pendingUploads > 0 ? ` ${plural(row.pendingUploads, "change")} made here and not uploaded yet won't reach them — the backup keeps them.` : "";
  return `is backed up and removed from this computer, and ssh stops reading it. The space stays in your sync account and on your other computers; turn it back on any time.${unsent}`;
}

/**
 * The one summary after "Choose spaces" turned several spaces on: those that could not be turned on, by name,
 * with the backend's reason in which a space's id (`space <64 hex> is not in this sync account`) is replaced by its
 * name (hidden characters revealed: another computer chose it). Null when every space was turned on.
 */
export function chooseFailures(failed: readonly { id: string; name: string; message: string }[]): { title: string; description: string } | null {
  if (failed.length === 0) return null;
  const named = failed.map((f) => {
    const name = revealHidden(f.name);
    return { name, message: f.message.split(f.id).join(`“${name}”`) };
  });
  if (named.length === 1) return { title: `Could not turn on “${named[0].name}”`, description: named[0].message };
  return {
    title: `Could not turn on ${named.length} spaces`,
    description: named.map((f) => `“${f.name}”: ${f.message}`).join("; "),
  };
}
