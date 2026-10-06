import { afterEach, describe, expect, it, vi } from "vitest";

import { keyCandidate, keySlot, overview, SPOOFED_NAME, SPOOFED_NAME_SHOWN } from "@/lib/sync-fixtures";
import {
  choiceFor,
  deviceLine,
  finishedKeysNeededNotice,
  hostsLine,
  hostsMissingKey,
  identityFileChanged,
  isValidSlotName,
  keySetupAskedBefore,
  keysNeededNoticeIndex,
  keptNote,
  keysToAsk,
  lockedNote,
  needsKeyLabel,
  notSetUpLabel,
  passphraseNote,
  rememberKeySetupAsked,
  reuseChoices,
  rewrittenLines,
  slotActions,
  slotStatusText,
  slotsNeedingKey,
  syncConfirmText,
  syncedKeysNote,
  usesLine,
} from "./key-slots";

afterEach(() => vi.unstubAllGlobals());

const two = keyCandidate({
  hosts: [
    { alias: "web", space_name: "Personal", value: "~/.ssh/id_mac", locked: null },
    { alias: "db", space_name: "Work", value: "\"/home/f/.ssh/id_mac\"", locked: null },
  ],
});
const LOCK = "This host has more than one copy; SSHelter changes it once only one copy is left.";

describe("which keys the dialog asks about", () => {
  it("asks about keys without a slot that would rewrite at least one of the given hosts", () => {
    const reused = keyCandidate({ path: "/home/f/.ssh/old", existing_slot: "a".repeat(32) });
    const lockedOnly = keyCandidate({ path: "/home/f/.ssh/locked", hosts: [{ alias: "api", space_name: "Personal", value: "~/.ssh/locked", locked: LOCK }] });
    const all = { keys: [two, reused, lockedOnly], unsupported: [] };
    expect(keysToAsk(all, null)).toEqual([two]);
    expect(keysToAsk(all, ["db"])).toEqual([two]);
    expect(keysToAsk(all, ["other"])).toEqual([]);
    expect(keysToAsk(undefined, null)).toEqual([]);
    // `reused` is used by `web` (the builder's default host): reused for web, left alone for a host that doesn't use it.
    expect(reuseChoices(all, null)).toEqual([{ path: "/home/f/.ssh/old", decision: { kind: "reuse", slot_id: "a".repeat(32) } }]);
    expect(reuseChoices(all, ["web"])).toEqual([{ path: "/home/f/.ssh/old", decision: { kind: "reuse", slot_id: "a".repeat(32) } }]);
    expect(reuseChoices(all, ["db"])).toEqual([]);
  });

  it("describes a key, its passphrase and the lines it rewrites", () => {
    expect(usesLine(keyCandidate(), "id_mac")).toBe("web uses id_mac.");
    expect(usesLine(two, "personal")).toBe("web and db use personal.");
    expect(passphraseNote(keyCandidate())).toBe("No passphrase — your sync code and every joined computer can use this key once it syncs.");
    expect(passphraseNote(keyCandidate({ has_passphrase: true }))).toBe("Has a passphrase — it stays on each computer.");
    expect(passphraseNote(keyCandidate({ has_passphrase: null }))).toBeNull();
    expect(rewrittenLines(two, "personal")).toEqual([
      "web: IdentityFile ~/.ssh/id_mac → ~/.ssh/sshelter/keys/personal-…",
      "db: IdentityFile \"/home/f/.ssh/id_mac\" → ~/.ssh/sshelter/keys/personal-…",
    ]);
    const mixed = keyCandidate({ hosts: [...two.hosts, { alias: "api", space_name: "Personal", value: "~/.ssh/id_mac", locked: LOCK }] });
    expect(rewrittenLines(mixed, "k")).toHaveLength(2);
    expect(lockedNote(mixed)).toBe(`Not changed: api — ${LOCK}`);
    expect(lockedNote(two)).toBeNull();
    expect(choiceFor(keyCandidate(), true, "id_mac")).toEqual({ path: "/home/f/.ssh/id_mac", decision: { kind: "sync", name: "id_mac" } });
    expect(choiceFor(keyCandidate(), false, "k")).toEqual({ path: "/home/f/.ssh/id_mac", decision: { kind: "keep", name: "k" } });
  });

  it("accepts the slot names the backend accepts", () => {
    for (const ok of ["id_ed25519", "work", "a", "Key.2026_v-1", "k".repeat(64)]) expect(isValidSlotName(ok)).toBe(true);
    for (const bad of ["", "-x", ".x", "a b", "a/b", "id.pub", "ID.PUB", "k".repeat(65), "鍵"]) expect(isValidSlotName(bad)).toBe(false);
  });

  it("notices an IdentityFile change in a host save, whatever its spelling", () => {
    expect(identityFileChanged([{ keyword: "identityfile", value: "~/.ssh/k", remove: false }])).toBe(true);
    expect(identityFileChanged([{ keyword: "HostName", value: "x", remove: false }])).toBe(false);
  });
});

describe("a key slot kept from the previous sync account", () => {
  const FILE = "mac-3fa2c1d9";
  const host = (alias: string, value: string, locked: string | null = null) => ({ alias, space_name: "Personal", value, locked });
  const kept = (synced_copy: boolean, hosts = [host("web", `~/.ssh/sshelter/keys/${FILE}`)]) =>
    keyCandidate({ default_name: "mac", kept_slot: { id: `3fa2c1d9${"0".repeat(24)}`, file_name: FILE, synced_copy }, hosts });

  it("says where the key came from and that its hosts keep their slot path", () => {
    expect(keptNote(kept(false))).toBe("From your previous sync account. Its hosts keep using ~/.ssh/sshelter/keys/mac-3fa2c1d9.");
    expect(keptNote(kept(true))).toBe(
      "This computer's copy, synced to it in your previous sync account. Its hosts keep using ~/.ssh/sshelter/keys/mac-3fa2c1d9.",
    );
    expect(keptNote(keyCandidate())).toBeNull();
  });

  it("rewrites only the hosts that don't use the slot yet, to its full file name", () => {
    const k = kept(false, [
      host("web", `~/.ssh/sshelter/keys/${FILE}`),
      host("quoted", ` "~/.ssh/sshelter/keys/${FILE}" `),
      host("percent", `%d/.ssh/sshelter/keys/${FILE}`),
      host("db", "~/.ssh/id_mac"),
      host("api", "~/.ssh/sshelter/keys/id_mac-0123abcd"),
      host("deeper", `~/.ssh/sshelter/keys/${FILE}/x`),
      host("locked", "~/.ssh/id_mac", LOCK),
    ]);
    expect(rewrittenLines(k, "mac")).toEqual([
      `db: IdentityFile ~/.ssh/id_mac → ~/.ssh/sshelter/keys/${FILE}`,
      `api: IdentityFile ~/.ssh/sshelter/keys/id_mac-0123abcd → ~/.ssh/sshelter/keys/${FILE}`,
      `deeper: IdentityFile ~/.ssh/sshelter/keys/${FILE}/x → ~/.ssh/sshelter/keys/${FILE}`,
    ]);
    expect(rewrittenLines(kept(true), "mac")).toEqual([]);
    // Other keys: unchanged, the name the user gives plus "…".
    expect(rewrittenLines(keyCandidate(), "id_mac")).toEqual(["web: IdentityFile ~/.ssh/id_mac → ~/.ssh/sshelter/keys/id_mac-…"]);
  });
});

describe("Settings → Sync rows", () => {
  it("count keys to set up and slots that need a key here", () => {
    expect(notSetUpLabel(1)).toBe("1 key used by synced hosts isn't set up");
    expect(notSetUpLabel(2)).toBe("2 keys used by synced hosts aren't set up");
    expect(needsKeyLabel(1)).toBe("1 key slot needs a key on this computer");
    expect(needsKeyLabel(3)).toBe("3 key slots need a key on this computer");
    const o = overview({
      key_slots: [
        keySlot(),
        keySlot({ id: "b".repeat(32), status: { kind: "needs_key", waiting_for_sync: false } }),
        keySlot({ id: "c".repeat(32), status: { kind: "needs_key", waiting_for_sync: true } }),
      ],
    });
    expect(slotsNeedingKey(o).map((s) => s.id)).toEqual(["b".repeat(32)]);
  });

  it("reminds about synced keys after a sync code change", () => {
    expect(syncedKeysNote(overview({ key_slots: [keySlot(), keySlot({ id: "b".repeat(32), name: SPOOFED_NAME, mode: "own" })] }))).toBe(
      "If a computer was lost, also replace these synced keys on your servers: id_mac.",
    );
    expect(syncedKeysNote(overview({ key_slots: [keySlot({ mode: "own" })] }))).toBeNull();
  });
});

describe("a slot row", () => {
  it("says the status in words and tone", () => {
    expect(slotStatusText({ kind: "ready", file: "/f", synced_copy: false, fingerprint: null })).toEqual({ text: "Ready", tone: "ok" });
    expect(slotStatusText({ kind: "needs_key", waiting_for_sync: false })).toEqual({ text: "Needs a key on this computer", tone: "warning" });
    expect(slotStatusText({ kind: "needs_key", waiting_for_sync: true })).toEqual({ text: "Waiting for the synced key", tone: "busy" });
    expect(slotStatusText({ kind: "not_in_use", file: "/f" })).toEqual({ text: "Not in use", tone: "ok" });
    expect(slotStatusText({ kind: "not_used_here" })).toEqual({ text: "Not used on this computer", tone: "ok" });
    expect(slotStatusText({ kind: "synced_available", file: "/f" })).toEqual({ text: "A synced key is available", tone: "warning" });
    expect(slotStatusText({ kind: "source_changed", file: "/f" }).text).toBe(
      "This computer's key changed — your other computers still have the previous one",
    );
    expect(slotStatusText({ kind: "error", message: "boom" })).toEqual({ text: "boom", tone: "error" });
  });

  it("offers the actions that fit", () => {
    const none = { syncThis: false, stopSyncing: false, pick: null, useSynced: false, syncNew: false, deleteCopy: false };
    expect(slotActions(keySlot())).toEqual({ ...none, stopSyncing: true, pick: "change" });
    expect(slotActions(keySlot({ mode: "own", fingerprint: null }))).toEqual({ ...none, syncThis: true, pick: "change" });
    expect(slotActions(keySlot({ mode: "own", status: { kind: "needs_key", waiting_for_sync: false } }))).toEqual({ ...none, pick: "pick" });
    expect(slotActions(keySlot({ status: { kind: "synced_available", file: "/f" } }))).toEqual({ ...none, stopSyncing: true, pick: "change", useSynced: true });
    expect(slotActions(keySlot({ status: { kind: "source_changed", file: "/f" } }))).toEqual({ ...none, stopSyncing: true, syncNew: true, pick: "change" });
    expect(slotActions(keySlot({ mode: "own", status: { kind: "not_in_use", file: "/f" } }))).toEqual({ ...none, deleteCopy: true });
    // A slot in error always has a way forward: pick a key here (the backend says why when picking can't help).
    expect(slotActions(keySlot({ mode: "own", status: { kind: "error", message: "The key this slot points to is gone: /home/f/.ssh/id_mac." } }))).toEqual({ ...none, pick: "pick" });
    expect(slotActions(keySlot({ status: { kind: "error", message: "The synced key didn't match and was not written." } }))).toEqual({ ...none, stopSyncing: true, pick: "pick" });
  });

  it("offers nothing but deleting an unused copy for a slot the account no longer has", () => {
    const none = { syncThis: false, stopSyncing: false, pick: null, useSynced: false, syncNew: false, deleteCopy: false };
    // Kept for hosts outside the spaces (left the account, joined another): there is nothing to sync or pick it for.
    expect(slotActions(keySlot({ in_account: false }))).toEqual(none);
    expect(slotActions(keySlot({ in_account: false, mode: "own", fingerprint: null }))).toEqual(none);
    expect(slotActions(keySlot({ in_account: false, status: { kind: "error", message: "The key this slot points to is gone: /f." } }))).toEqual(none);
    // A deleted slot's copy nobody uses can still be deleted.
    expect(slotActions(keySlot({ in_account: false, status: { kind: "not_in_use", file: "/f" } }))).toEqual({ ...none, deleteCopy: true });
  });

  it("asks before a key is uploaded, saying whether a passphrase still protects the key that goes", () => {
    const own = keySlot({ mode: "own", fingerprint: null, has_passphrase: null });
    expect(syncConfirmText({ ...own, local_has_passphrase: true })).toEqual({
      title: "Sync id_mac to your other computers?",
      description: "Has a passphrase — it stays on each computer.",
    });
    expect(syncConfirmText({ ...own, local_has_passphrase: false }).description).toBe(
      "No passphrase — your sync code and every joined computer can use this key once it syncs.",
    );
    expect(syncConfirmText({ ...own, local_has_passphrase: null }).description).toBeNull();
    // "Sync the new key": the note is about this computer's new key, not the synced one it replaces.
    const changed = keySlot({ status: { kind: "source_changed", file: "/f" }, has_passphrase: true, local_has_passphrase: false });
    expect(syncConfirmText(changed).description).toBe("No passphrase — your sync code and every joined computer can use this key once it syncs.");
    expect(syncConfirmText(keySlot({ name: SPOOFED_NAME })).title).toBe(`Sync ${SPOOFED_NAME_SHOWN} to your other computers?`);
  });

  it("lists hosts and other computers, revealing hidden characters in their names", () => {
    expect(hostsLine(keySlot({ hosts: ["web", "db"] }))).toBe("Used by web and db");
    expect(hostsLine(keySlot({ hosts: [] }))).toBeNull();
    expect(
      deviceLine(keySlot({ devices: [{ name: SPOOFED_NAME, fingerprint: null, synced_copy: true }, { name: "FRANK-DESKTOP", fingerprint: "SHA256:x", synced_copy: false }] })),
    ).toBe(`${SPOOFED_NAME_SHOWN}: synced copy · FRANK-DESKTOP: its own key`);
    expect(deviceLine(keySlot())).toBeNull();
  });

  it("marks the sidebar hosts whose key is missing here, but not while the synced key is on its way", () => {
    const o = overview({
      key_slots: [
        keySlot(),
        keySlot({ id: "b".repeat(32), hosts: ["db"], status: { kind: "needs_key", waiting_for_sync: false } }),
        keySlot({ id: "c".repeat(32), hosts: ["api"], status: { kind: "error", message: "x" } }),
        keySlot({ id: "d".repeat(32), hosts: ["ci"], status: { kind: "needs_key", waiting_for_sync: true } }),
      ],
    });
    expect([...hostsMissingKey(o)].sort()).toEqual(["api", "db"]);
    expect(hostsMissingKey(undefined).size).toBe(0);
  });
});

describe("the Keys for this computer notice", () => {
  it("is found by its kind", () => {
    expect(keysNeededNoticeIndex(overview({ notices: [{ kind: "new_sync_code" }, { kind: "keys_needed", names: ["id_mac"] }] }))).toBe(1);
    expect(keysNeededNoticeIndex(overview())).toBeNull();
  });

  it("is finished once no slot needs a key picked here", () => {
    const notices = [{ kind: "keys_needed" as const, names: ["id_mac"] }];
    const needing = keySlot({ mode: "own", fingerprint: null, status: { kind: "needs_key", waiting_for_sync: false } });
    expect(finishedKeysNeededNotice(overview({ notices, key_slots: [needing] }))).toBeNull();
    // Picked here or in Keys, or the origin started syncing it: nothing left to ask.
    expect(finishedKeysNeededNotice(overview({ notices, key_slots: [keySlot()] }))).toBe(0);
    expect(finishedKeysNeededNotice(overview({ notices, key_slots: [keySlot({ status: { kind: "needs_key", waiting_for_sync: true } })] }))).toBe(0);
    expect(finishedKeysNeededNotice(overview({ key_slots: [keySlot()] }))).toBeNull();
  });

  it("waits while there are no slots at all: the overview has none while the account keys are unavailable (a locked keychain)", () => {
    const notices = [{ kind: "keys_needed" as const, names: ["id_mac"] }];
    expect(finishedKeysNeededNotice(overview({ notices, key_slots: [] }))).toBeNull();
    // As soon as the slots are there again, the notice is judged by them.
    expect(finishedKeysNeededNotice(overview({ notices, key_slots: [keySlot()] }))).toBe(0);
  });
});

describe("the once-per-computer setup prompt", () => {
  it("remembers that it asked, and survives a missing or broken localStorage", () => {
    expect(keySetupAskedBefore()).toBe(false); // node: no localStorage
    expect(() => rememberKeySetupAsked()).not.toThrow();
    const store = new Map<string, string>();
    vi.stubGlobal("localStorage", { getItem: (k: string) => store.get(k) ?? null, setItem: (k: string, v: string) => store.set(k, v) });
    expect(keySetupAskedBefore()).toBe(false);
    rememberKeySetupAsked();
    expect(keySetupAskedBefore()).toBe(true);
    // What is stored is on users' disks once a beta ships: renaming it would ask everyone again. Named like `sshelter-settings`.
    expect([...store]).toEqual([["sshelter-key-setup-asked", "1"]]);
    vi.stubGlobal("localStorage", { getItem: () => { throw new Error("denied"); }, setItem: () => { throw new Error("denied"); } });
    expect(keySetupAskedBefore()).toBe(false);
    expect(() => rememberKeySetupAsked()).not.toThrow();
  });
});
