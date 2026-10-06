import type { RotationStep } from "@/bindings/RotationStep";
import type { SyncFrozenView } from "@/bindings/SyncFrozenView";
import type { SyncNotice } from "@/bindings/SyncNotice";
import type { SyncOverview } from "@/bindings/SyncOverview";
import type { SyncRelayView } from "@/bindings/SyncRelayView";
import { listNames, plural, relativeTime } from "@/lib/format";
import { revealHidden } from "@/lib/sync-approvals";
import { noticeMessage } from "@/lib/sync-events";
import { accountBlock, spaceProblem } from "@/lib/sync-spaces";

/** How a status reads: ok = all good, busy = working on it, warning = needs the user, error = failed. */
export type Tone = "ok" | "busy" | "warning" | "error";

// Defined in `format.ts` (see there); the sync UI imports it from here.
export { plural };

const PLATFORMS: Record<string, string> = { macos: "macOS", linux: "Linux", windows: "Windows" };

export function platformLabel(platform: string): string {
  return PLATFORMS[platform] ?? platform;
}

const ROTATION_LABELS: Record<RotationStep, string> = {
  prepared: "Sending this computer's changes",
  local_changes_sent: "Freezing the old sync data",
  freezing: "Freezing the old sync data",
  copying: "Copying your spaces",
  deleting: "Removing the old copies",
  switching: "Switching to the new sync code",
};

/** What changing the sync code is doing now (spec §7.5 steps 2–7). */
export function rotationLabel(step: RotationStep): string {
  return ROTATION_LABELS[step];
}

export interface StatusLine {
  badge: string;
  tone: Tone;
  text: string;
}

/**
 * Backend texts the pane tells apart (`rotation::SWAP_PENDING_MESSAGE` and
 * `rotation::NEXT_CODE_GONE_AFTER_FREEZE_MESSAGE`; a test reads them from the Rust
 * source). Every other error is shown as it comes.
 */
export const SWAP_PENDING_MESSAGE =
  "the keychain did not accept the new sync code yet; SSHelter keeps the new code and retries, and syncing continues meanwhile";
export const CHANGE_CANNOT_FINISH_MESSAGE =
  "the new sync code is missing from the keychain, so this sync code change can never finish and the old sync account can no longer be joined — leave the sync account on this computer, then create a new sync account on one computer; the other computers leave the old account and join the new one";

/** The Sync pane's status row. States that stop syncing come first; then errors, a space's too; then progress. */
export function statusLine(o: SyncOverview, now: number): StatusLine {
  if (o.upgrading) {
    return { badge: "Upgrading", tone: o.last_error ? "error" : "busy", text: o.last_error ?? "Moving this computer to the new sync format…" };
  }
  if (o.frozen) return { badge: "Paused", tone: "warning", text: "The sync code was changed on another computer" };
  if (o.rotation) {
    // The backend retries every step by itself (the relay's limits, a locked keychain…),
    // so its error is status, not a task — except a change that can never finish: that
    // text tells the user to leave and start a new sync account.
    const step = rotationLabel(o.rotation.step);
    if (!o.last_error) return { badge: "Changing code", tone: "busy", text: step };
    return { badge: "Changing code", tone: o.last_error === CHANGE_CANNOT_FINISH_MESSAGE ? "error" : "busy", text: `${step} — ${o.last_error}` };
  }
  if (o.read_only) {
    return { badge: "Read-only", tone: "warning", text: "This sync account uses a newer format — update SSHelter to keep syncing" };
  }
  // The new sync code is in use; only saving it to the keychain is still being retried.
  if (o.last_error === SWAP_PENDING_MESSAGE) return { badge: "Saving code", tone: "busy", text: o.last_error };
  if (o.last_error) return { badge: "Error", tone: "error", text: o.last_error };
  // A paused or missing space stops syncing both ways while the account itself is fine: say so here, not only on its row.
  const problems = o.spaces.flatMap((s) => {
    const problem = s.selected ? spaceProblem(s) : null;
    return problem ? [{ name: revealHidden(s.name), ...problem }] : [];
  });
  if (problems.length === 1) return { badge: "Error", tone: problems[0].tone, text: `${problems[0].name}: ${problems[0].text}` };
  if (problems.length > 1) return { badge: "Error", tone: "error", text: `${problems.length} spaces need attention — see Spaces` };
  if (o.last_sync_ms === null) return { badge: "Waiting", tone: "busy", text: "Waiting for the first sync" };
  const last = `last sync ${relativeTime(o.last_sync_ms, now)}`;
  if (o.pending_uploads > 0) return { badge: "Synced", tone: "ok", text: `${plural(o.pending_uploads, "change")} waiting to upload · ${last}` };
  return { badge: "Synced", tone: "ok", text: `Up to date · ${last}` };
}

export interface RelayDetails {
  version: string;
  /** Set when the relay lacks a feature this app can use: show it with the "Updating your relay" link. */
  updateHint: string | null;
}

/** The relay's version and what an update would bring (spec §6.4: no `pull-batch` or no `freeze`). */
export function relayDetails(relay: SyncRelayView | null): RelayDetails {
  if (!relay) return { version: "Not checked yet", updateHint: null };
  const missing: string[] = [];
  if (!relay.batch_pull) missing.push("it checks one space at a time, which uses more of its request limit");
  if (!relay.freeze) missing.push("it can't change the sync code");
  return {
    version: relay.version ? `Relay ${relay.version}` : "Older relay (no version reported)",
    updateHint: missing.length > 0 ? `This relay can be updated: ${missing.join(", and ")}.` : null,
  };
}

/**
 * Why "Change sync code" is unavailable, or null when it can start. Before the
 * relay was checked the backend checks it itself, so an unknown relay does not block.
 */
export function changeCodeBlocker(o: SyncOverview): { reason: string; updateRelay: boolean } | null {
  const block = (reason: string, updateRelay = false) => ({ reason, updateRelay });
  switch (accountBlock(o)) {
    case "upgrading":
    case "not_joined":
      return block("Join or create a sync account first.");
    case "frozen":
      return block("The sync code was already changed on another computer — enter the new one first.");
    case "rotating":
      return block("The sync code is being changed.");
    case "read_only":
      return block("Update SSHelter first: this sync account uses a newer format.");
    case null:
      return o.relay && !o.relay.freeze ? block("Your relay can't change the sync code yet — update the relay first.", true) : null;
  }
}

/**
 * What the "Sync code" row says (the frozen state has its own row). During a change
 * `sync_show_words` still gives the old code: say when it stops working.
 */
export function syncCodeNote(o: SyncOverview): string {
  if (o.rotation) {
    return "While the sync code is being changed, Show gives the old code: it stops working once the old data is frozen, and the new code is shown when the change finishes.";
  }
  return changeCodeBlocker(o)?.reason ?? "Needed to add another computer. Shown only on request.";
}

/** The frozen banner (spec §7.5 "other computers"): who changed the sync code, and that nothing unsent is lost. */
export function frozenMessage(frozen: SyncFrozenView): string {
  const kept = "Enter the new sync code to keep syncing; changes this computer has not uploaded yet are kept and sent afterwards.";
  const by = frozen.by_devices;
  if (by.length === 0) {
    return `The relay no longer accepts this computer's changes: the sync code was probably changed on another computer. ${kept}`;
  }
  if (by.length === 1) return `The sync code was changed on ${by[0]}. ${kept}`;
  return `${listNames(by)} changed the sync code at the same time. ${kept.replace("the new sync code", "either new sync code")}`;
}

export interface DeviceRow {
  id: string;
  name: string;
  isThis: boolean;
  detail: string;
}

/** The Devices list: platform, last contact (other computers only) and the spaces each one syncs. */
export function deviceRows(o: SyncOverview, now: number): DeviceRow[] {
  const names = new Map(o.spaces.map((s) => [s.id, revealHidden(s.name)]));
  return o.devices.map((d) => {
    const spaces = d.spaces.flatMap((id) => names.get(id) ?? []);
    const parts = [platformLabel(d.platform)];
    if (!d.is_this) parts.push(`last seen ${relativeTime(d.last_seen_ms, now)}`);
    parts.push(spaces.length > 0 ? listNames(spaces) : "no spaces");
    return { id: d.id, name: d.is_this ? `${d.name} (this computer)` : d.name, isThis: d.is_this, detail: parts.join(" · ") };
  });
}

/** Leaving may also delete the account from the relay only when no other computer is listed (spec §7.3). */
export function isLastDevice(o: SyncOverview): boolean {
  return o.devices.length > 0 && o.devices.every((d) => d.is_this);
}

/**
 * Why leaving does not offer to delete the sync account from the relay, or null
 * when it does: only the last listed computer may delete it (spec §7.3), and never
 * after the sync code changed elsewhere — the old account then tells the computers
 * still on the old code about the change (the backend refuses that delete too) —
 * nor while a sync code change is past the freeze (leaving is refused then, or goes
 * through without touching the relay).
 */
export function deleteAccountNote(o: SyncOverview): string | null {
  if (o.frozen) {
    return "The sync code was changed on another computer, so leaving removes only this computer: the old sync account stays on the relay for the computers that still use the old code.";
  }
  if (o.rotation && !o.rotation.cancellable) {
    return "The sync code change in progress can no longer be cancelled, so leaving now never deletes the sync account from the relay.";
  }
  if (!isLastDevice(o)) return "Your other computers keep syncing. To delete the sync account from the relay, leave on the last computer.";
  return null;
}

/**
 * What leaving does to a sync code change in progress, or null when none runs
 * (spec §7.5). Leave stays available: the overview can't tell whether the staged
 * new code still exists, so the backend decides — before the freeze it cancels the
 * change; after it, it refuses (its text is shown as it comes) unless the change
 * can never finish, and then this computer leaves.
 */
export function leaveRotationNote(o: SyncOverview): string | null {
  if (!o.rotation) return null;
  return o.rotation.cancellable
    ? "A sync code change is in progress. Leaving cancels it first: nothing on the relay is frozen yet."
    : "A sync code change is in progress and can no longer be cancelled, so SSHelter lets this computer leave only if the change can never finish (its new sync code is gone from the keychain). Otherwise, let it finish first.";
}

/**
 * What `sync_leave_account` is asked: also delete the account from the relay only when leaving may
 * offer that at all (`deleteAccountNote` is null: the last computer, nothing changed elsewhere, no
 * change past its freeze) and the user ticked it. A box that was ticked and then went away — a second
 * computer joined, the sync code was changed — must not delete anything.
 */
export function leaveRequest(o: SyncOverview, wantsDelete: boolean): { deleteRemote: boolean } {
  return { deleteRemote: deleteAccountNote(o) === null && wantsDelete };
}

/**
 * What leaving does to the changes this computer made and has not uploaded yet (the same warning turning a
 * space off gives): they never reach the other computers, and the files this computer keeps still have them.
 * Only the changes to hosts in the spaces this computer syncs are counted: the overview's own
 * `pending_uploads` also counts the sync account's records (a device, a space), which no file holds, so the
 * claim about the files would be false for those. Null when no such change is waiting to upload.
 */
export function leaveUnsentNote(o: SyncOverview): string | null {
  const n = o.spaces.reduce((sum, s) => sum + (s.selected ? s.pending_uploads : 0), 0);
  if (n <= 0) return null;
  return `${plural(n, "change")} made here and not uploaded yet won't reach your other computers — the files this computer keeps still have ${n === 1 ? "it" : "them"}.`;
}

export interface NoticeRow {
  index: number;
  title: string;
  description: string;
  /** The `new_sync_code` notice: its button shows the new code, and saving it dismisses the notice. */
  showsNewCode: boolean;
}

/** Where the `new_sync_code` notice is in the overview right now, or null: the dismiss index shifts when another notice goes, so it is looked up when it is needed. */
export function newSyncCodeNoticeIndex(o: SyncOverview): number | null {
  const index = o.notices.findIndex((notice) => notice.kind === "new_sync_code");
  return index < 0 ? null : index;
}

/**
 * What the dialog that shows the sync code says while the sync code is being changed, or null when it
 * says what it always says ("enter these words on another computer"): until the old data is frozen
 * the code still works but is about to stop; after it, it is the old code and no other computer can use it.
 */
export function shownCodeNote(o: SyncOverview): string | null {
  if (!o.rotation) return null;
  return o.rotation.cancellable
    ? "A sync code change is in progress. This is still the current sync code, but it stops working once the old data is frozen; the new sync code is shown when the change finishes."
    : "This is the old sync code, and it no longer works: the old sync data is frozen. The new sync code is shown when the change finishes.";
}

/** The "Files SSHelter doesn't use" row: one file or several, in the right grammar. */
export function strayFilesNote(files: readonly string[]): string {
  const one = files.length === 1;
  return `ssh doesn't read ${files.join(", ")} in ~/.ssh/sshelter: ${one ? "it is" : "they are"} not in SSHelter's Include line. SSHelter leaves ${one ? "it" : "them"} alone — copy any host you still need into your SSH config before deleting ${one ? "it" : "them"}.`;
}

/** Notices that stay true after this computer left the account: where its files went, and what was deleted elsewhere. */
const TRUE_AFTER_LEAVING = new Set<SyncNotice["kind"]>(["left_account", "space_deleted"]);

/**
 * Notices for the pane, with the index `sync_dismiss_notice` needs. The upgrade and the keys notice have their own
 * dialogs (the slots that need a key have their own row).
 * The backend keeps notices when this computer leaves, but most of them are about the account it
 * left: "SSHelter renames the space's file on the next sync" and "Show the new sync code" are not
 * true any more. Without an account only the notices that stay true read as they were; the others
 * keep their title and say what they were about, and the pane lets the user dismiss them.
 */
export function noticeRows(o: SyncOverview): NoticeRow[] {
  return o.notices.flatMap((notice, index) => {
    if (notice.kind === "upgraded" || notice.kind === "keys_needed") return [];
    if (!o.joined && !TRUE_AFTER_LEAVING.has(notice.kind)) {
      return [{ index, title: noticeMessage(notice).title, description: "This was about the sync account this computer has since left.", showsNewCode: false }];
    }
    return [{ index, ...noticeMessage(notice), showsNewCode: notice.kind === "new_sync_code" }];
  });
}
