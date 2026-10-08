import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";

import type { KeyInfo } from "@/bindings/KeyInfo";
import type { MoveFailure } from "@/bindings/MoveFailure";
import type { SlotStatusView } from "@/bindings/SlotStatusView";
import type { SyncKeySlotView } from "@/bindings/SyncKeySlotView";
import type { KeychainSelection } from "@/lib/keychain";
import { queryKeys } from "@/lib/queries";
import { syncOverviewKey } from "@/lib/sync";
import { keySlot, overview, SLOT_FINGERPRINT, SPOOFED_NAME, SPOOFED_NAME_SHOWN } from "@/lib/sync-fixtures";
import { FileKeyDetailView, KeyDetailFor, SlotKeyDetailView, type KeyAction } from "./KeyDetail";
import { buttonTag, buttonsIn, DISABLED, HIDDEN_CHARS, text, textIn } from "./test-markup";

function keyFile(overrides: Partial<KeyInfo> = {}): KeyInfo {
  return {
    name: "id_ed25519",
    private_path: "/home/f/.ssh/id_ed25519",
    public_path: "/home/f/.ssh/id_ed25519.pub",
    key_type: "ED25519",
    bits: 256,
    fingerprint_sha256: "SHA256:abc",
    comment: "frank@laptop",
    in_agent: true,
    hosts: ["web"],
    ...overrides,
  };
}

type SlotProps = { busy?: boolean; keyHere?: boolean; moveFailure?: string | null };
const slotTree = (slot: SyncKeySlotView, onAction: (a: KeyAction) => void = () => {}, onHost: (alias: string) => void = () => {}, p: SlotProps = {}) =>
  SlotKeyDetailView({ slot, busy: p.busy ?? false, keyHere: p.keyHere ?? true, moveFailure: p.moveFailure ?? null, onAction, onHost });
const slotDetail = (slot: SyncKeySlotView, p: SlotProps = {}) => renderToStaticMarkup(slotTree(slot, undefined, undefined, p));

/** What each action button of a slot's detail asks for, by its label (the host buttons ask for none). */
function pressEach(slot: SyncKeySlotView): Record<string, KeyAction> {
  const asked: KeyAction[] = [];
  const pressed: Record<string, KeyAction> = {};
  for (const button of buttonsIn(slotTree(slot, (a) => asked.push(a)))) {
    asked.length = 0;
    button.props.onClick!();
    if (asked.length > 0) pressed[textIn(button)] = asked[0];
  }
  return pressed;
}

const COPY_EXPORT = { "Copy public key": "copy", "Export to host…": "exportHost" } as const;

describe("a key slot's detail", () => {
  it("shows its name, badges, type, fingerprint, where it is kept, its hosts and the other computers", () => {
    const html = slotDetail(
      keySlot({ in_vault: true, hosts: ["web", "db"], devices: [{ name: "FRANK-DESKTOP", fingerprint: null, synced_copy: true, in_vault: true }] }),
    );
    for (const part of ["id_mac", "Synced", "ssh-ed25519", SLOT_FINGERPRINT, "Ready", "In SSHelter — programs ask before they use it", "web", "db", "FRANK-DESKTOP: in SSHelter"]) {
      expect(text(html)).toContain(part);
    }
  });

  it("offers Export private key only for a key in SSHelter, and Move only for a file for now", () => {
    expect(pressEach(keySlot({ in_vault: true }))).toEqual({
      ...COPY_EXPORT,
      "Export private key…": "exportPrivate",
      "Change…": "pick",
      "Stop syncing": "stop",
    });
    expect(pressEach(keySlot({ file_for_now: true }))).toEqual({
      ...COPY_EXPORT,
      "Move into SSHelter": "move",
      "Change…": "pick",
      "Stop syncing": "stop",
    });
  });

  it("offers what each state needs", () => {
    const own = { mode: "own" as const, fingerprint: null };
    expect(pressEach(keySlot({ ...own, status: { kind: "needs_key", waiting_for_sync: false } }))).toEqual({
      ...COPY_EXPORT,
      "Pick a key on this computer…": "pick",
    });
    expect(pressEach(keySlot({ ...own, in_vault: true }))).toEqual({
      ...COPY_EXPORT,
      "Export private key…": "exportPrivate",
      "Sync to your computers": "sync",
      "Change…": "pick",
    });
    expect(pressEach(keySlot({ status: { kind: "synced_available", file: "/f" } }))).toEqual({
      ...COPY_EXPORT,
      "Use the synced key": "useSynced",
      "Change…": "pick",
      "Stop syncing": "stop",
    });
    expect(pressEach(keySlot({ status: { kind: "source_changed", file: "/f" } }))).toEqual({
      ...COPY_EXPORT,
      "Sync the new key": "syncNew",
      "Change…": "pick",
      "Stop syncing": "stop",
    });
    expect(pressEach(keySlot({ ...own, in_account: false, status: { kind: "not_in_use", file: "/f" } }))).toEqual({
      ...COPY_EXPORT,
      "Delete copy": "delete",
    });
  });

  it("shows a key only on this computer with a backup note, its day and its passphrase, and offers Delete key while no host uses it", () => {
    const local = keySlot({ local_only: true, in_account: false, mode: "own", in_vault: true, vault_has_passphrase: true, hosts: [] });
    const t = text(slotDetail(local));
    for (const part of ["This computer only", "Only this computer has this key. Export a copy to keep a backup.", "Created", "2023-11-15", "Passphrase", "Yes"]) {
      expect(t).toContain(part);
    }
    expect(pressEach(local)).toEqual({ ...COPY_EXPORT, "Export private key…": "exportPrivate", "Delete key…": "deleteKey" });
    expect(pressEach({ ...local, hosts: ["web"] })).toEqual({ ...COPY_EXPORT, "Export private key…": "exportPrivate" });
  });

  it("turns the actions off while one runs, and Copy and Export to host off without a key here", () => {
    const slot = keySlot({ status: { kind: "synced_available", file: "/f" } });
    for (const label of ["Use the synced key", "Change…", "Stop syncing", "Copy public key", "Export to host…"]) {
      expect(buttonTag(slotDetail(slot, { busy: true }), label)).toContain(DISABLED);
      expect(buttonTag(slotDetail(slot), label)).not.toContain(DISABLED);
    }
    const none = slotDetail(keySlot({ status: { kind: "needs_key", waiting_for_sync: false } }), { keyHere: false });
    expect(buttonTag(none, "Copy public key")).toContain(DISABLED);
    expect(buttonTag(none, "Export to host…")).toContain(DISABLED);
    expect(buttonTag(none, "Pick a key on this computer…")).not.toContain(DISABLED);
  });

  it("says where a file for now is, and why the last Move couldn't move it", () => {
    const html = slotDetail(keySlot({ file_for_now: true }), { moveFailure: "The key this slot points to is gone: /home/f/.ssh/id_mac." });
    expect(text(html)).toContain("File for now — any program can use it without asking");
    expect(text(html)).toContain("/home/f/.ssh/id_mac");
    expect(text(html)).toContain("Couldn't move into SSHelter: The key this slot points to is gone: /home/f/.ssh/id_mac.");
  });

  it("says why a file stays a file", () => {
    const reason = "SSHelter's agent can't use this kind of key (for example a security key or a DSA key), so it stays as a file.";
    expect(text(slotDetail(keySlot({ stays_file: reason })))).toContain(`It stays a file: ${reason}`);
  });

  it("shows a host in Hosts when it is pressed, and says when no host uses the key", () => {
    const shown: string[] = [];
    const tree = slotTree(keySlot({ hosts: ["web", "db"] }), undefined, (alias) => shown.push(alias));
    for (const b of buttonsIn(tree).filter((b) => ["web", "db"].includes(textIn(b)))) b.props.onClick!();
    expect(shown).toEqual(["web", "db"]);
    expect(text(slotDetail(keySlot({ hosts: [] })))).toContain("No hosts use it.");
  });

  it("reveals hidden characters in the name, the key type, the hosts and the other computers' names, which come from elsewhere", () => {
    const html = slotDetail(
      keySlot({
        name: SPOOFED_NAME,
        key_type: SPOOFED_NAME,
        hosts: [SPOOFED_NAME],
        devices: [{ name: SPOOFED_NAME, fingerprint: null, synced_copy: false, in_vault: false }],
      }),
    );
    expect(html).not.toMatch(HIDDEN_CHARS);
    expect(text(html).split(SPOOFED_NAME_SHOWN).length - 1).toBe(4);
  });

  it("shows the file a key is kept in, unless the key is in SSHelter", () => {
    const FILE = "/home/f/.ssh/id_work";
    const named: SlotStatusView[] = [
      { kind: "ready", file: FILE, synced_copy: false, fingerprint: SLOT_FINGERPRINT },
      { kind: "not_in_use", file: FILE },
      { kind: "synced_available", file: FILE },
      { kind: "source_changed", file: FILE },
    ];
    for (const status of named) {
      // A key SSHelter's agent can never hold stays a file without being a "file for now".
      expect(text(slotDetail(keySlot({ status, in_vault: false, file_for_now: false }))), status.kind).toContain(FILE);
      // A key in SSHelter has no file here: its slot path holds only the .pub.
      expect(text(slotDetail(keySlot({ status, in_vault: true }))), status.kind).not.toContain(FILE);
    }
  });

  it("reveals hidden characters in the reason a Move gave", () => {
    const html = slotDetail(keySlot({ file_for_now: true }), { moveFailure: `The key ${SPOOFED_NAME} is gone.` });
    expect(html).not.toMatch(HIDDEN_CHARS);
    expect(text(html)).toContain(`Couldn't move into SSHelter: The key ${SPOOFED_NAME_SHOWN} is gone.`);
  });
});

describe("a key file's detail", () => {
  const fileDetail = (file: KeyInfo) => renderToStaticMarkup(FileKeyDetailView({ file, onAction: () => {}, onHost: () => {} }));

  it("shows its type, fingerprint, comment, paths, ssh-agent and hosts, and that SSHelter doesn't manage it", () => {
    const t = text(fileDetail(keyFile()));
    for (const part of [
      "id_ed25519",
      "ED25519 256",
      "in ssh-agent",
      "SHA256:abc",
      "frank@laptop",
      "/home/f/.ssh/id_ed25519.pub",
      "web",
      "SSHelter doesn't manage this file: any program can use it without asking.",
    ]) {
      expect(t).toContain(part);
    }
    expect(text(fileDetail(keyFile({ in_agent: false })))).not.toContain("in ssh-agent");
  });

  it("copies and exports only with a .pub next to it", () => {
    const asked: string[] = [];
    const tree = FileKeyDetailView({ file: keyFile(), onAction: (a) => asked.push(a), onHost: () => {} });
    buttonsIn(tree)
      .filter((b) => textIn(b) !== "web")
      .forEach((b) => b.props.onClick!());
    expect(asked).toEqual(["copy", "exportHost"]);
    const none = fileDetail(keyFile({ public_path: null }));
    expect(buttonTag(none, "Copy public key")).toContain(DISABLED);
    expect(buttonTag(none, "Export to host…")).toContain(DISABLED);
    expect(text(none)).toContain("No .pub file next to it.");
  });

  it("reveals hidden characters in its name, its comment and the hosts that use it", () => {
    const html = fileDetail(keyFile({ name: SPOOFED_NAME, comment: SPOOFED_NAME, hosts: [SPOOFED_NAME] }));
    expect(html).not.toMatch(HIDDEN_CHARS);
    expect(text(html).split(SPOOFED_NAME_SHOWN).length - 1).toBe(3);
  });
});

describe("the detail pane", () => {
  // A server render reads a zustand store's initial state, so the selection is handed in (`KeyDetailFor`), not set in the store.
  const pane = (
    selection: KeychainSelection | null,
    slots: SyncKeySlotView[],
    keys: KeyInfo[],
    moveFailures: MoveFailure[] = [],
    joined = true,
  ) => {
    const queryClient = new QueryClient();
    const account = joined ? {} : { joined: false, account_short: null, devices: [], spaces: [] };
    queryClient.setQueryData(syncOverviewKey, overview({ ...account, key_slots: slots }));
    queryClient.setQueryData(queryKeys.keys, keys);
    return text(
      renderToStaticMarkup(
        <QueryClientProvider client={queryClient}>
          <KeyDetailFor selection={selection} moveFailures={moveFailures} onShowHost={() => {}} />
        </QueryClientProvider>,
      ),
    );
  };

  it("asks for a key while none is selected, or the selected one is gone", () => {
    expect(pane(null, [keySlot()], [])).toContain("No key selected");
    expect(pane({ kind: "slot", id: "f".repeat(32) }, [keySlot()], [])).toContain("Choose a key from the list.");
  });

  it("shows the selected slot, with the reason the last Move gave for it", () => {
    const slot = keySlot({ file_for_now: true });
    const t = pane({ kind: "slot", id: slot.id }, [slot], [], [{ slot_id: slot.id, name: "id_mac", message: "boom" }]);
    expect(t).toContain("id_mac");
    expect(t).toContain("Couldn't move into SSHelter: boom");
  });

  it("shows the selected slot without a sync account, with what it can still do here", () => {
    const slot = keySlot({ in_account: false, in_vault: true });
    const t = pane({ kind: "slot", id: slot.id }, [slot], [], [], false);
    expect(t).toContain("id_mac");
    expect(t).toContain("Export private key…");
    expect(t).not.toContain("Choose a key from the list.");
  });

  it("shows the selected key file", () => {
    expect(pane({ kind: "file", path: "/home/f/.ssh/id_ed25519" }, [], [keyFile()])).toContain("SSHelter doesn't manage this file");
  });
});
