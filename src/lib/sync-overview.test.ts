import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";

import type { SyncNotice } from "@/bindings/SyncNotice";
import { plural as formatPlural } from "./format";
import { noticeMessage } from "./sync-events";
import { MINUTE, NOW, SPOOFED_NAME, SPOOFED_NAME_SHOWN, device, overview, space } from "./sync-fixtures";
import {
  CHANGE_CANNOT_FINISH_MESSAGE,
  SWAP_PENDING_MESSAGE,
  changeCodeBlocker,
  deleteAccountNote,
  deviceRows,
  frozenMessage,
  isLastDevice,
  leaveRequest,
  leaveRotationNote,
  leaveUnsentNote,
  newSyncCodeNoticeIndex,
  noticeRows,
  plural,
  relayDetails,
  rotationLabel,
  shownCodeNote,
  statusLine,
  strayFilesNote,
  syncCodeNote,
} from "./sync-overview";

describe("plural", () => {
  it("counts", () => {
    expect(plural(1, "host")).toBe("1 host");
    expect(plural(0, "host")).toBe("0 hosts");
    expect(plural(2, "change")).toBe("2 changes");
  });

  it("is the function of format.ts that the approvals review uses too, not a copy of it", () => {
    expect(plural).toBe(formatPlural);
  });
});

describe("statusLine", () => {
  it("is up to date with the time of the last sync", () => {
    expect(statusLine(overview(), NOW)).toEqual({ badge: "Synced", tone: "ok", text: "Up to date · last sync 2m ago" });
  });

  it("counts changes waiting to upload", () => {
    expect(statusLine(overview({ pending_uploads: 3 }), NOW).text).toBe("3 changes waiting to upload · last sync 2m ago");
  });

  it("waits for the first sync", () => {
    expect(statusLine(overview({ last_sync_ms: null }), NOW)).toEqual({ badge: "Waiting", tone: "busy", text: "Waiting for the first sync" });
  });

  it("shows the engine's error", () => {
    expect(statusLine(overview({ last_error: "the relay had trouble answering" }), NOW)).toEqual({
      badge: "Error",
      tone: "error",
      text: "the relay had trouble answering",
    });
  });

  it("puts the states that stop syncing before an error", () => {
    const broken = { last_error: "boom" };
    expect(statusLine(overview({ ...broken, read_only: true }), NOW).badge).toBe("Read-only");
    expect(statusLine(overview({ ...broken, rotation: { step: "copying", cancellable: false, paused_until_ms: null } }), NOW)).toEqual({
      badge: "Changing code",
      tone: "busy",
      text: "Copying your spaces — boom",
    });
    expect(statusLine(overview({ ...broken, frozen: { detected_at_ms: NOW, by_devices: ["MacBook-B"] } }), NOW)).toEqual({
      badge: "Paused",
      tone: "warning",
      text: "The sync code was changed on another computer",
    });
  });

  it("shows a sync code change's error with its step: the backend retries it, unless the change can never finish", () => {
    const copying = { step: "copying" as const, cancellable: false, paused_until_ms: null };
    const limited = "the relay is limiting requests from this network; sync retries automatically in a few minutes";
    expect(statusLine(overview({ rotation: copying }), NOW)).toEqual({ badge: "Changing code", tone: "busy", text: "Copying your spaces" });
    expect(statusLine(overview({ rotation: copying, last_error: limited }), NOW)).toEqual({
      badge: "Changing code",
      tone: "busy",
      text: `Copying your spaces — ${limited}`,
    });
    expect(statusLine(overview({ rotation: copying, last_error: CHANGE_CANNOT_FINISH_MESSAGE }), NOW)).toEqual({
      badge: "Changing code",
      tone: "error",
      text: `Copying your spaces — ${CHANGE_CANNOT_FINISH_MESSAGE}`,
    });
  });

  it("says the new sync code is still being saved to the keychain without calling it an error", () => {
    expect(statusLine(overview({ last_error: SWAP_PENDING_MESSAGE }), NOW)).toEqual({ badge: "Saving code", tone: "busy", text: SWAP_PENDING_MESSAGE });
  });

  it("says what a space's error is, with its name: the account is fine, but that space stopped syncing", () => {
    const work = (overrides: Parameters<typeof space>[0]) => space({ id: "b".repeat(64), name: "Work", ...overrides });
    expect(statusLine(overview({ spaces: [space(), work({ last_error: "its file has a block with an Include" })] }), NOW)).toEqual({
      badge: "Error",
      tone: "error",
      text: "Work: its file has a block with an Include",
    });
    // Missing on the relay: the same words the Spaces list uses, with the name in front.
    expect(statusLine(overview({ spaces: [work({ missing: true, last_error: "this space's data is missing on the relay" })] }), NOW)).toEqual({
      badge: "Error",
      tone: "error",
      text: "Work: Its data is missing on the relay. Rebuild it from this computer, or delete the space.",
    });
  });

  it("counts the spaces that need attention when there are several, and points to the list", () => {
    const spaces = [
      space({ last_error: "duplicate Host web" }),
      space({ id: "b".repeat(64), name: "Work", missing: true }),
      space({ id: "c".repeat(64), name: "Lab" }),
      space({ id: "d".repeat(64), name: "Old", selected: false, file_name: null, file_path: null, hosts: null, last_error: "stale" }),
    ];
    expect(statusLine(overview({ spaces }), NOW)).toEqual({ badge: "Error", tone: "error", text: "2 spaces need attention — see Spaces" });
  });

  it("puts a space's problem after the account-level states and before the first-sync wait and the synced states", () => {
    const broken = [space({ last_error: "duplicate Host web" })];
    // The account's own states win: frozen, a sync code change, read-only, an account error.
    expect(statusLine(overview({ spaces: broken, frozen: { detected_at_ms: NOW, by_devices: [] } }), NOW).badge).toBe("Paused");
    expect(statusLine(overview({ spaces: broken, rotation: { step: "copying", cancellable: false, paused_until_ms: null } }), NOW).badge).toBe("Changing code");
    expect(statusLine(overview({ spaces: broken, read_only: true }), NOW).badge).toBe("Read-only");
    expect(statusLine(overview({ spaces: broken, last_error: SWAP_PENDING_MESSAGE }), NOW).badge).toBe("Saving code");
    expect(statusLine(overview({ spaces: broken, last_error: "the relay had trouble answering" }), NOW).text).toBe("the relay had trouble answering");
    // Then the space, before "Waiting…", "N changes waiting" and "Up to date".
    expect(statusLine(overview({ spaces: broken, last_sync_ms: null }), NOW).text).toBe("Personal: duplicate Host web");
    expect(statusLine(overview({ spaces: broken, pending_uploads: 3 }), NOW).text).toBe("Personal: duplicate Host web");
    expect(statusLine(overview({ spaces: broken }), NOW).badge).toBe("Error");
    // A space this computer does not sync has nothing to report.
    expect(statusLine(overview({ spaces: [space({ selected: false, last_error: "stale" })] }), NOW).badge).toBe("Synced");
  });

  it("shows an unfinished v1 upgrade and why it is stuck", () => {
    expect(statusLine(overview({ joined: false, upgrading: true }), NOW)).toEqual({
      badge: "Upgrading",
      tone: "busy",
      text: "Moving this computer to the new sync format…",
    });
    expect(statusLine(overview({ joined: false, upgrading: true, last_error: "keychain locked" }), NOW).tone).toBe("error");
  });
});

describe("the backend texts the pane tells apart", () => {
  it("are rotation.rs's SWAP_PENDING_MESSAGE and NEXT_CODE_GONE_AFTER_FREEZE_MESSAGE", () => {
    const rust = readFileSync("src-tauri/src/sync/rotation.rs", "utf8");
    const quoted = (name: string) => new RegExp(`${name}: &str =\\s*"([^"]*)"`).exec(rust)?.[1];
    expect(quoted("SWAP_PENDING_MESSAGE")).toBe(SWAP_PENDING_MESSAGE);
    expect(quoted("NEXT_CODE_GONE_AFTER_FREEZE_MESSAGE")).toBe(CHANGE_CANNOT_FINISH_MESSAGE);
  });
});

describe("rotationLabel", () => {
  it("names what is happening at each step", () => {
    expect(rotationLabel("prepared")).toBe("Sending this computer's changes");
    expect(rotationLabel("local_changes_sent")).toBe("Freezing the old sync data");
    expect(rotationLabel("freezing")).toBe("Freezing the old sync data");
    expect(rotationLabel("copying")).toBe("Copying your spaces");
    expect(rotationLabel("deleting")).toBe("Removing the old copies");
    expect(rotationLabel("switching")).toBe("Switching to the new sync code");
  });
});

describe("relayDetails", () => {
  it("shows the version of an up-to-date relay without a hint", () => {
    expect(relayDetails(overview().relay)).toEqual({ version: "Relay 0.2.0", updateHint: null });
  });

  it("says an older relay can be updated, and what it is missing", () => {
    expect(relayDetails({ url: "u", version: null, batch_pull: false, freeze: false })).toEqual({
      version: "Older relay (no version reported)",
      updateHint:
        "This relay can be updated: it checks one space at a time, which uses more of its request limit, and it can't change the sync code.",
    });
    expect(relayDetails({ url: "u", version: "0.1.0", batch_pull: false, freeze: true }).updateHint).toBe(
      "This relay can be updated: it checks one space at a time, which uses more of its request limit.",
    );
  });

  it("has nothing to say before the relay was checked", () => {
    expect(relayDetails(null)).toEqual({ version: "Not checked yet", updateHint: null });
  });
});

describe("changeCodeBlocker", () => {
  it("lets a healthy account change its sync code, also before the relay was checked", () => {
    expect(changeCodeBlocker(overview())).toBeNull();
    expect(changeCodeBlocker(overview({ relay: null }))).toBeNull();
  });

  it("needs a relay that can freeze, with a pointer to the update guide", () => {
    expect(changeCodeBlocker(overview({ relay: { url: "u", version: null, batch_pull: true, freeze: false } }))).toEqual({
      reason: "Your relay can't change the sync code yet — update the relay first.",
      updateRelay: true,
    });
  });

  it("explains every other state that blocks it", () => {
    expect(changeCodeBlocker(overview({ frozen: { detected_at_ms: NOW, by_devices: [] } }))?.reason).toBe(
      "The sync code was already changed on another computer — enter the new one first.",
    );
    expect(changeCodeBlocker(overview({ rotation: { step: "prepared", cancellable: true, paused_until_ms: null } }))?.reason).toBe(
      "The sync code is being changed.",
    );
    expect(changeCodeBlocker(overview({ read_only: true }))?.reason).toBe("Update SSHelter first: this sync account uses a newer format.");
    expect(changeCodeBlocker(overview({ joined: false }))?.reason).toBe("Join or create a sync account first.");
  });
});

describe("syncCodeNote", () => {
  it("says what Show gives during a sync code change, and otherwise why Change… is unavailable", () => {
    expect(syncCodeNote(overview())).toBe("Needed to add another computer. Shown only on request.");
    expect(syncCodeNote(overview({ rotation: { step: "copying", cancellable: false, paused_until_ms: null } }))).toBe(
      "While the sync code is being changed, Show gives the old code: it stops working once the old data is frozen, and the new code is shown when the change finishes.",
    );
    expect(syncCodeNote(overview({ read_only: true }))).toBe("Update SSHelter first: this sync account uses a newer format.");
  });
});

describe("frozenMessage", () => {
  it("names who changed the sync code and promises the unsent changes", () => {
    expect(frozenMessage({ detected_at_ms: NOW, by_devices: ["MacBook-B"] })).toBe(
      "The sync code was changed on MacBook-B. Enter the new sync code to keep syncing; changes this computer has not uploaded yet are kept and sent afterwards.",
    );
  });

  it("covers a rejected upload before the marker is known, and two computers at once", () => {
    expect(frozenMessage({ detected_at_ms: NOW, by_devices: [] })).toBe(
      "The relay no longer accepts this computer's changes: the sync code was probably changed on another computer. Enter the new sync code to keep syncing; changes this computer has not uploaded yet are kept and sent afterwards.",
    );
    expect(frozenMessage({ detected_at_ms: NOW, by_devices: ["MacBook-B", "Mac-mini"] })).toBe(
      "MacBook-B and Mac-mini changed the sync code at the same time. Enter either new sync code to keep syncing; changes this computer has not uploaded yet are kept and sent afterwards.",
    );
  });
});

describe("deviceRows", () => {
  const work = space({ id: "b".repeat(64), name: "Work" });
  const o = overview({
    spaces: [space(), work],
    devices: [
      device({ spaces: [space().id] }),
      device({ id: "device-b", name: "MacBook-B", platform: "linux", is_this: false, last_seen_ms: NOW - 3 * 60 * MINUTE, spaces: [space().id, work.id, "gone".repeat(16)] }),
      device({ id: "device-c", name: "Old PC", platform: "windows", is_this: false, last_seen_ms: NOW - 40 * 86_400_000, spaces: [] }),
    ],
  });

  it("names the platform, the last contact and the spaces each computer syncs", () => {
    expect(deviceRows(o, NOW)).toEqual([
      { id: "device-a", name: "MacBook-A (this computer)", isThis: true, detail: "macOS · Personal" },
      { id: "device-b", name: "MacBook-B", isThis: false, detail: "Linux · last seen 3h ago · Personal and Work" },
      { id: "device-c", name: "Old PC", isThis: false, detail: "Windows · last seen 1mo ago · no spaces" },
    ]);
  });

  it("offers deleting the account only on the last listed computer", () => {
    expect(isLastDevice(o)).toBe(false);
    expect(isLastDevice(overview())).toBe(true);
    expect(isLastDevice(overview({ devices: [] }))).toBe(false);
  });
});

describe("deleteAccountNote", () => {
  it("offers deleting the account only on the last listed computer, never after the sync code changed elsewhere or past a change's freeze", () => {
    expect(deleteAccountNote(overview())).toBeNull();
    expect(deleteAccountNote(overview({ devices: [device(), device({ id: "device-b", name: "MacBook-B", is_this: false })] }))).toBe(
      "Your other computers keep syncing. To delete the sync account from the relay, leave on the last computer.",
    );
    expect(deleteAccountNote(overview({ frozen: { detected_at_ms: NOW, by_devices: ["MacBook-B"] } }))).toBe(
      "The sync code was changed on another computer, so leaving removes only this computer: the old sync account stays on the relay for the computers that still use the old code.",
    );
    expect(deleteAccountNote(overview({ rotation: { step: "copying", cancellable: false, paused_until_ms: null } }))).toBe(
      "The sync code change in progress can no longer be cancelled, so leaving now never deletes the sync account from the relay.",
    );
    expect(deleteAccountNote(overview({ rotation: { step: "prepared", cancellable: true, paused_until_ms: null } }))).toBeNull();
  });
});

describe("leaveRotationNote", () => {
  it("says what leaving does to a sync code change: it cancels one that can still be cancelled; past the freeze it is refused unless the change can never finish", () => {
    expect(leaveRotationNote(overview())).toBeNull();
    expect(leaveRotationNote(overview({ rotation: { step: "local_changes_sent", cancellable: true, paused_until_ms: null } }))).toBe(
      "A sync code change is in progress. Leaving cancels it first: nothing on the relay is frozen yet.",
    );
    expect(leaveRotationNote(overview({ rotation: { step: "copying", cancellable: false, paused_until_ms: null } }))).toBe(
      "A sync code change is in progress and can no longer be cancelled, so SSHelter lets this computer leave only if the change can never finish (its new sync code is gone from the keychain). Otherwise, let it finish first.",
    );
  });
});

describe("leaveRequest", () => {
  const other = [device(), device({ id: "device-b", name: "MacBook-B", is_this: false })];

  it("deletes the account from the relay only when leaving offers it and the user asked", () => {
    expect(leaveRequest(overview(), true)).toEqual({ deleteRemote: true });
    expect(leaveRequest(overview(), false)).toEqual({ deleteRemote: false });
  });

  it("never deletes when leaving no longer offers it, whatever was ticked: another computer is listed, the sync code changed elsewhere, a change is past its freeze", () => {
    expect(leaveRequest(overview({ devices: other }), true)).toEqual({ deleteRemote: false });
    expect(leaveRequest(overview({ frozen: { detected_at_ms: NOW, by_devices: [] } }), true)).toEqual({ deleteRemote: false });
    expect(leaveRequest(overview({ rotation: { step: "copying", cancellable: false, paused_until_ms: null } }), true)).toEqual({ deleteRemote: false });
    // A change that can still be cancelled does not stop it: leaving cancels the change first.
    expect(leaveRequest(overview({ rotation: { step: "prepared", cancellable: true, paused_until_ms: null } }), true)).toEqual({ deleteRemote: true });
  });
});

describe("newSyncCodeNoticeIndex", () => {
  it("finds the notice where it is now, so a dismissal never hits another one after the list shifted", () => {
    const code: SyncNotice = { kind: "new_sync_code" };
    const deleted: SyncNotice = { kind: "space_deleted", name: "Work", by_device: "MacBook-B" };
    expect(newSyncCodeNoticeIndex(overview({ notices: [deleted, code] }))).toBe(1);
    expect(newSyncCodeNoticeIndex(overview({ notices: [code] }))).toBe(0); // the one before it was dismissed meanwhile
    expect(newSyncCodeNoticeIndex(overview({ notices: [deleted] }))).toBeNull();
    expect(newSyncCodeNoticeIndex(overview())).toBeNull();
  });
});

describe("shownCodeNote", () => {
  it("says nothing special while no sync code change runs", () => {
    expect(shownCodeNote(overview())).toBeNull();
  });

  it("says the code stops working at the freeze, and after the freeze that it is the old code and no use on another computer", () => {
    expect(shownCodeNote(overview({ rotation: { step: "prepared", cancellable: true, paused_until_ms: null } }))).toBe(
      "A sync code change is in progress. This is still the current sync code, but it stops working once the old data is frozen; the new sync code is shown when the change finishes.",
    );
    const frozen = shownCodeNote(overview({ rotation: { step: "copying", cancellable: false, paused_until_ms: null } }));
    expect(frozen).toBe("This is the old sync code, and it no longer works: the old sync data is frozen. The new sync code is shown when the change finishes.");
    expect(frozen).not.toContain("Enter these words");
  });
});

describe("strayFilesNote", () => {
  it("speaks of one file in the singular", () => {
    expect(strayFilesNote(["hosts.config"])).toBe(
      "ssh doesn't read hosts.config in ~/.ssh/sshelter: it is not in SSHelter's Include line. SSHelter leaves it alone — copy any host you still need into your SSH config before deleting it.",
    );
  });

  it("and of several in the plural", () => {
    expect(strayFilesNote(["a.config", "b.config"])).toBe(
      "ssh doesn't read a.config, b.config in ~/.ssh/sshelter: they are not in SSHelter's Include line. SSHelter leaves them alone — copy any host you still need into your SSH config before deleting them.",
    );
  });
});

describe("a space's name, which another computer chose", () => {
  it("is shown with its hidden characters revealed in the status row", () => {
    const line = statusLine(overview({ spaces: [space({ name: SPOOFED_NAME, last_error: "duplicate Host web" })] }), NOW);
    expect(line.text).toBe(`${SPOOFED_NAME_SHOWN}: duplicate Host web`);
    expect(line.text).not.toMatch(/[\u202E\u200B]/);
  });

  it("is shown with its hidden characters revealed in the list of computers and the spaces each one syncs", () => {
    const o = overview({
      spaces: [space({ name: SPOOFED_NAME })],
      devices: [device({ spaces: [space().id] }), device({ id: "device-b", name: "MacBook-B", is_this: false, spaces: [space().id] })],
    });
    expect(deviceRows(o, NOW).map((row) => row.detail)).toEqual([`macOS · ${SPOOFED_NAME_SHOWN}`, `macOS · last seen 5m ago · ${SPOOFED_NAME_SHOWN}`]);
  });
});

describe("leaveUnsentNote", () => {
  it("says that changes not uploaded yet never reach the other computers, and where they stay", () => {
    expect(leaveUnsentNote(overview())).toBeNull();
    expect(leaveUnsentNote(overview({ pending_uploads: 1, spaces: [space({ pending_uploads: 1 })] }))).toBe(
      "1 change made here and not uploaded yet won't reach your other computers — the files this computer keeps still have it.",
    );
    expect(leaveUnsentNote(overview({ pending_uploads: 3, spaces: [space({ pending_uploads: 2 }), space({ id: "b".repeat(64), name: "Work", pending_uploads: 1 })] }))).toBe(
      "3 changes made here and not uploaded yet won't reach your other computers — the files this computer keeps still have them.",
    );
  });

  it("counts only what the files keep: the changes to hosts in the spaces this computer syncs, not the sync account's own records", () => {
    // `pending_uploads` of the overview also counts the account's records (a device, a space), which no file holds.
    const withAccountRecords = overview({ pending_uploads: 5, spaces: [space({ pending_uploads: 1 })] });
    expect(leaveUnsentNote(withAccountRecords)).toBe(
      "1 change made here and not uploaded yet won't reach your other computers — the files this computer keeps still have it.",
    );
    // Nothing but account records waiting: no file has anything to keep, so the note says nothing.
    expect(leaveUnsentNote(overview({ pending_uploads: 2, spaces: [space()] }))).toBeNull();
    // A space this computer does not sync has no file here.
    expect(leaveUnsentNote(overview({ pending_uploads: 4, spaces: [space({ selected: false, file_name: null, file_path: null, hosts: null, pending_uploads: 4 })] }))).toBeNull();
  });
});

describe("noticeRows", () => {
  it("lists the notices with their index, leaving the upgrade to its dialog", () => {
    const o = overview({
      notices: [
        { kind: "upgraded", kept_file: null, kept_hosts: [], moved_files: [] },
        { kind: "new_sync_code" },
        { kind: "space_deleted", name: "Work", by_device: "MacBook-B" },
      ],
    });
    expect(noticeRows(o)).toEqual([
      {
        index: 1,
        title: "The sync code was changed",
        description: "Show the new sync code, save it, and enter it on each of your other computers.",
        showsNewCode: true,
      },
      { index: 2, title: "“Work” was deleted on MacBook-B", description: "Its file was backed up and removed from this computer.", showsNewCode: false },
    ]);
  });

  it("keeps saying what is still true after leaving, and says of the rest what they were about, instead of what they can't do any more", () => {
    const left = { kind: "left_account" as const, kept_files: ["/home/f/.ssh/sshelter-local/personal-3fa2c1d9.config"] };
    const deleted = { kind: "space_deleted" as const, name: "Work", by_device: "MacBook-B" };
    const notices: SyncNotice[] = [
      { kind: "rename_blocked", space_id: "a", name: "Work", file_name: "work-3fa2c1d9.config" },
      { kind: "upgraded", kept_file: null, kept_hosts: [], moved_files: [] },
      { kind: "new_sync_code" },
      { kind: "other_rotation", devices: ["MacBook-B"] },
      deleted,
      left,
    ];
    const about = "This was about the sync account this computer has since left.";
    expect(noticeRows(overview({ joined: false, devices: [], spaces: [], notices }))).toEqual([
      { index: 0, title: "The file of “Work” keeps its old name", description: about, showsNewCode: false },
      { index: 2, title: "The sync code was changed", description: about, showsNewCode: false },
      { index: 3, title: "MacBook-B also changed the sync code", description: about, showsNewCode: false },
      { index: 4, ...noticeMessage(deleted), showsNewCode: false },
      { index: 5, ...noticeMessage(left), showsNewCode: false },
    ]);
    // Joined, every notice keeps its own words and the new-code one its button.
    const joined = noticeRows(overview({ notices }));
    expect(joined.map((row) => row.index)).toEqual([0, 2, 3, 4, 5]);
    expect(joined[0].description).toContain("SSHelter renames the space's file on the next sync");
    expect(joined.map((row) => row.showsNewCode)).toEqual([false, true, false, false, false]);
  });

  it("lists them on a computer that left, too, so it can tell where its files went", () => {
    const left = { kind: "left_account" as const, kept_files: ["/home/f/.ssh/sshelter-local/personal-3fa2c1d9.config"] };
    expect(noticeRows(overview({ joined: false, devices: [], spaces: [], notices: [left] }))).toEqual([
      { index: 0, title: "Your synced files are now local files", description: noticeMessage(left).description, showsNewCode: false },
    ]);
  });
});
