import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";

import { NOW, SPOOFED_NAME, SPOOFED_NAME_SHOWN, overview, space } from "./sync-fixtures";
import {
  MAX_SPACE_NAME,
  accountBlock,
  chooseFailures,
  createdSpaceToast,
  deleteSpaceTitle,
  deletedSpaceToast,
  renameSpaceTitle,
  renamedSpaceToast,
  spaceNameError,
  spaceProblem,
  spaceRows,
  stopSyncingTitle,
  structureLock,
  syncedOnText,
  unselectNote,
} from "./sync-spaces";

const WORK_ID = "b".repeat(64);

describe("spaceRows", () => {
  it("shows a synced space's file, host count and the computers that sync it", () => {
    expect(spaceRows(overview({ spaces: [space({ synced_on: ["MacBook-A", "Mac-mini"] })] }))).toEqual([
      {
        id: space().id,
        name: "Personal",
        label: "Personal",
        selected: true,
        fileName: "personal-3fa2c1d9.config",
        detail: "personal-3fa2c1d9.config · 3 hosts",
        syncedOn: "On MacBook-A and Mac-mini",
        status: null,
        missing: false,
        pendingUploads: 0,
      },
    ]);
  });

  it("knows nothing about the hosts of a space this computer does not sync", () => {
    const [row] = spaceRows(
      overview({ spaces: [space({ id: WORK_ID, name: "Work", selected: false, file_name: null, file_path: null, hosts: null, synced_on: [] })] }),
    );
    expect(row).toEqual(
      expect.objectContaining({ selected: false, fileName: null, detail: "Not on this computer", syncedOn: "Not synced on any computer" }),
    );
  });

  it("puts the most urgent state of a space first", () => {
    const status = (overrides: Parameters<typeof space>[0]) => spaceRows(overview({ spaces: [space(overrides)] }))[0].status;
    expect(status({ missing: true, last_error: "this space's data is missing on the relay", approvals: 2 })).toEqual({
      tone: "error",
      text: "Its data is missing on the relay. Rebuild it from this computer, or delete the space.",
    });
    expect(status({ last_error: "duplicate Host web", first_sync_pending: true })).toEqual({ tone: "error", text: "duplicate Host web" });
    expect(status({ first_sync_pending: true, approvals: 1 })).toEqual({ tone: "busy", text: "Syncing for the first time…" });
    expect(status({ approvals: 2, pending_uploads: 1 })).toEqual({ tone: "warning", text: "2 hosts waiting for your approval" });
    expect(status({ pending_uploads: 1 })).toEqual({ tone: "ok", text: "1 change waiting to upload" });
  });
});

describe("a space's name, which another computer chose", () => {
  const [row] = spaceRows(overview({ spaces: [space({ name: SPOOFED_NAME })] }));
  const hidden = /[\u202E\u200B]/;

  it("keeps the name as it is for a rename to start from, and shows it with its hidden characters revealed", () => {
    expect(row.name).toBe(SPOOFED_NAME);
    expect(row.label).toBe(SPOOFED_NAME_SHOWN);
  });

  it("is revealed in the titles of the confirms, the toasts and the rename dialog", () => {
    expect(stopSyncingTitle(row)).toBe(`Stop syncing “${SPOOFED_NAME_SHOWN}” on this computer?`);
    expect(deleteSpaceTitle(row)).toBe(`Delete “${SPOOFED_NAME_SHOWN}” everywhere?`);
    expect(deletedSpaceToast(row)).toBe(`Deleted “${SPOOFED_NAME_SHOWN}”`);
    expect(renameSpaceTitle(row)).toBe(`Rename “${SPOOFED_NAME_SHOWN}”`);
    for (const text of [stopSyncingTitle(row), deleteSpaceTitle(row), deletedSpaceToast(row), renameSpaceTitle(row)]) expect(text).not.toMatch(hidden);
  });

  it("reads as it always did for an ordinary name", () => {
    const [plain] = spaceRows(overview({ spaces: [space({ name: "Work" })] }));
    expect(stopSyncingTitle(plain)).toBe("Stop syncing “Work” on this computer?");
    expect(deleteSpaceTitle(plain)).toBe("Delete “Work” everywhere?");
    expect(deletedSpaceToast(plain)).toBe("Deleted “Work”");
    expect(renameSpaceTitle(plain)).toBe("Rename “Work”");
  });

  it("is revealed in the toasts that repeat the name the user typed", () => {
    expect(createdSpaceToast(SPOOFED_NAME)).toBe(`Created “${SPOOFED_NAME_SHOWN}”`);
    expect(renamedSpaceToast(SPOOFED_NAME)).toBe(`Renamed to “${SPOOFED_NAME_SHOWN}”`);
    expect(createdSpaceToast("Work")).toBe("Created “Work”");
    expect(renamedSpaceToast("Work")).toBe("Renamed to “Work”");
  });
});

describe("spaceProblem", () => {
  it("is what stops a space from syncing: its data gone from the relay first, then the error that paused it", () => {
    expect(spaceProblem(space())).toBeNull();
    expect(spaceProblem(space({ first_sync_pending: true, approvals: 2, pending_uploads: 4 }))).toBeNull(); // progress, not a problem
    expect(spaceProblem(space({ last_error: "duplicate Host web" }))).toEqual({ tone: "error", text: "duplicate Host web" });
    expect(spaceProblem(space({ missing: true, last_error: "this space's data is missing on the relay" }))).toEqual({
      tone: "error",
      text: "Its data is missing on the relay. Rebuild it from this computer, or delete the space.",
    });
  });
});

describe("accountBlock", () => {
  const rotating = { step: "copying" as const, cancellable: false, paused_until_ms: null };
  const frozen = { detected_at_ms: NOW, by_devices: [] };

  it("is null for a healthy account", () => {
    expect(accountBlock(overview())).toBeNull();
  });

  it("names the state, in the order the backend checks them: upgrading, not joined, frozen, rotating, read-only", () => {
    expect(accountBlock(overview({ joined: false, upgrading: true }))).toBe("upgrading");
    expect(accountBlock(overview({ joined: false }))).toBe("not_joined");
    expect(accountBlock(overview({ frozen }))).toBe("frozen");
    expect(accountBlock(overview({ rotation: rotating }))).toBe("rotating");
    expect(accountBlock(overview({ read_only: true }))).toBe("read_only");
    // Several at once: the earlier one wins.
    expect(accountBlock(overview({ joined: false, upgrading: true, read_only: true }))).toBe("upgrading");
    expect(accountBlock(overview({ joined: false, read_only: true }))).toBe("not_joined");
    expect(accountBlock(overview({ frozen, rotation: rotating, read_only: true }))).toBe("frozen");
    expect(accountBlock(overview({ rotation: rotating, read_only: true }))).toBe("rotating");
  });
});

describe("structureLock", () => {
  const rotating = (cancellable: boolean) => ({ step: "copying" as const, cancellable, paused_until_ms: null });

  it("lets a healthy account change its spaces and decide on held hosts", () => {
    expect(structureLock(overview())).toBeNull();
  });

  it("says why neither works right now, in words that fit both", () => {
    expect(structureLock(overview({ frozen: { detected_at_ms: NOW, by_devices: [] } }))).toBe("Enter the new sync code first.");
    expect(structureLock(overview({ read_only: true }))).toBe("Update SSHelter first: this sync account uses a newer format.");
    expect(structureLock(overview({ joined: false }))).toBe("Join or create a sync account first.");
    expect(structureLock(overview({ joined: false, upgrading: true }))).toBe("Wait until this computer has finished upgrading its sync.");
  });

  it("offers the cancel route while a sync code change can still be cancelled (the backend: 'finish or cancel')", () => {
    expect(structureLock(overview({ rotation: rotating(true) }))).toBe("Wait for the new sync code to be in place, or cancel the change first.");
    expect(structureLock(overview({ rotation: rotating(false) }))).toBe("Wait for the new sync code to be in place first.");
  });

  it("follows the backend's order when several states hold: frozen before a change in progress before read-only", () => {
    const frozen = { detected_at_ms: NOW, by_devices: [] };
    expect(structureLock(overview({ frozen, rotation: rotating(false) }))).toBe("Enter the new sync code first.");
    expect(structureLock(overview({ rotation: rotating(false), read_only: true }))).toBe("Wait for the new sync code to be in place first.");
    expect(structureLock(overview({ joined: false, read_only: true }))).toBe("Join or create a sync account first.");
  });
});

describe("spaceNameError", () => {
  const spaces = [space(), space({ id: WORK_ID, name: "Work" })];

  it("accepts a new name, and a space's own name when renaming it", () => {
    expect(spaceNameError("Homelab", spaces)).toBeNull();
    expect(spaceNameError("  work  ", spaces, WORK_ID)).toBeNull();
  });

  it("applies the backend's rules: not empty, no control characters, at most 64 characters, unique ignoring case", () => {
    expect(spaceNameError("   ", spaces)).toBe("Enter a name.");
    expect(spaceNameError("Lab\u0007", spaces)).toBe("A name can't contain control characters.");
    expect(spaceNameError("x".repeat(MAX_SPACE_NAME), spaces)).toBeNull();
    expect(spaceNameError("x".repeat(MAX_SPACE_NAME + 1), spaces)).toBe("Use at most 64 characters.");
    expect(spaceNameError("é".repeat(MAX_SPACE_NAME), spaces)).toBeNull(); // characters, not bytes
    expect(spaceNameError(" WORK ", spaces)).toBe("A space named “WORK” already exists.");
  });

  it("counts characters, not UTF-16 units: 64 astral characters fit, 65 do not", () => {
    // U+1F600 is two UTF-16 units, so `.length` would call 64 of them 128.
    expect(spaceNameError("\u{1F600}".repeat(MAX_SPACE_NAME), spaces)).toBeNull();
    expect(spaceNameError("\u{1F600}".repeat(MAX_SPACE_NAME + 1), spaces)).toBe("Use at most 64 characters.");
  });

  it("uses the backend's limit (spaces.rs MAX_SPACE_NAME)", () => {
    const rust = readFileSync("src-tauri/src/sync/spaces.rs", "utf8");
    expect(Number(/const MAX_SPACE_NAME: usize = (\d+);/.exec(rust)?.[1])).toBe(MAX_SPACE_NAME);
  });
});

describe("syncedOnText", () => {
  it("names the computers that sync a space, or says that none does", () => {
    expect(syncedOnText([])).toBe("Not synced on any computer");
    expect(syncedOnText(["MacBook-A"])).toBe("On MacBook-A");
    expect(syncedOnText(["MacBook-A", "Mac-mini", "Old PC"])).toBe("On MacBook-A, Mac-mini and Old PC");
  });
});

describe("unselectNote", () => {
  it("says the space stays everywhere else and can be turned back on, and what happens to changes not uploaded yet", () => {
    expect(unselectNote({ missing: false, pendingUploads: 0 })).toBe(
      "is backed up and removed from this computer, and ssh stops reading it. The space stays in your sync account and on your other computers; turn it back on any time.",
    );
    expect(unselectNote({ missing: false, pendingUploads: 2 })).toBe(
      "is backed up and removed from this computer, and ssh stops reading it. The space stays in your sync account and on your other computers; turn it back on any time. 2 changes made here and not uploaded yet won't reach them — the backup keeps them.",
    );
  });

  it("does not promise a missing space can be turned back on: this computer may hold the only copy", () => {
    const note = unselectNote({ missing: true, pendingUploads: 3 });
    expect(note).toBe(
      "is backed up and removed from this computer, and ssh stops reading it. The space's data is missing on the relay, so this file may be the only copy of its hosts: the backup keeps it, but turning the space on again finds nothing to sync from. Rebuild the space first to keep syncing it.",
    );
    expect(note).not.toContain("turn it back on any time");
    expect(note).not.toContain("on your other computers");
  });
});

describe("chooseFailures", () => {
  const work = { id: WORK_ID, name: "Work" };

  it("is null when every space was turned on", () => {
    expect(chooseFailures([])).toBeNull();
  });

  it("names one space that could not be turned on, with its name instead of its id in the backend's reason", () => {
    expect(chooseFailures([{ ...work, message: `space ${WORK_ID} is not in this sync account` }])).toEqual({
      title: "Could not turn on “Work”",
      description: "space “Work” is not in this sync account",
    });
  });

  it("shows the hidden characters in the names it prints", () => {
    const one = chooseFailures([{ id: WORK_ID, name: SPOOFED_NAME, message: `space ${WORK_ID} is not in this sync account` }]);
    expect(one).toEqual({
      title: `Could not turn on “${SPOOFED_NAME_SHOWN}”`,
      description: `space “${SPOOFED_NAME_SHOWN}” is not in this sync account`,
    });
    const several = chooseFailures([
      { id: WORK_ID, name: SPOOFED_NAME, message: "boom" },
      { id: "c".repeat(64), name: "Lab", message: "bang" },
    ]);
    expect(several?.description).toBe(`“${SPOOFED_NAME_SHOWN}”: boom; “Lab”: bang`);
    expect(JSON.stringify([one, several])).not.toMatch(/[\u202E\u200B]/);
  });

  it("gives one summary for several, each with its reason", () => {
    expect(
      chooseFailures([
        { ...work, message: `space ${WORK_ID} is not in this sync account` },
        { id: "c".repeat(64), name: "Lab", message: "the relay is rate-limiting this device; try again later" },
      ]),
    ).toEqual({
      title: "Could not turn on 2 spaces",
      description: "“Work”: space “Work” is not in this sync account; “Lab”: the relay is rate-limiting this device; try again later",
    });
  });
});
