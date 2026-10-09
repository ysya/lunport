import { renderToStaticMarkup } from "react-dom/server";
import type { ComponentProps, ReactElement, ReactNode } from "react";
import { describe, expect, it } from "vitest";

import type { KeyInfo } from "@/bindings/KeyInfo";
import type { SyncKeySlotView } from "@/bindings/SyncKeySlotView";
import { AlertDialog, AlertDialogAction, AlertDialogCancel, AlertDialogDescription, AlertDialogTitle } from "@/components/ui/alert-dialog";
import { DialogDescription, DialogTitle } from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { keySlot, SPOOFED_NAME, SPOOFED_NAME_SHOWN } from "@/lib/sync-fixtures";
import { DeleteCopyConfirm, DeleteKeyConfirm, ExportPrivateKeyForm, KeyChoices, MoveKeyConfirm, replacedKeyNote, SyncKeyConfirm } from "./dialogs";
import { buttonsIn, DISABLED, elementsOf, HIDDEN_CHARS, text, textIn } from "./test-markup";

describe("the keys to pick from", () => {
  const key = (name: string, fingerprint: string | null): KeyInfo => ({
    name,
    private_path: `/home/f/.ssh/${name}`,
    public_path: `/home/f/.ssh/${name}.pub`,
    key_type: "ED25519",
    bits: 256,
    fingerprint_sha256: fingerprint,
    comment: null,
    in_agent: false,
    hosts: [],
  });
  const choices = (props: Partial<ComponentProps<typeof KeyChoices>> = {}) =>
    renderToStaticMarkup(<KeyChoices keys={[key("id_mac", "SHA256:abc")]} loading={false} busy={false} onChoose={() => {}} {...props} />);

  it("says the keys are being scanned, instead of showing an empty box", () => {
    const html = choices({ keys: undefined, loading: true });
    expect(text(html)).toContain("Scanning keys…");
    expect(html).not.toContain("<button");
    expect(html).not.toContain("settings-group");
  });

  it("says there are none, and where else to look, once the scan found no private key", () => {
    for (const keys of [undefined, []]) {
      const html = choices({ keys });
      expect(text(html)).toContain("No private keys in ~/.ssh. Choose one with Browse…");
      expect(html).not.toContain("<button");
      expect(html).not.toContain("settings-group");
    }
  });

  it("lists a button per key, with its fingerprint or else its path, and turns them off while one is being set", () => {
    const html = choices({ keys: [key("id_mac", "SHA256:abc"), key("old_rsa", null)] });
    expect(text(html)).toContain("id_mac SHA256:abc");
    expect(text(html)).toContain("old_rsa /home/f/.ssh/old_rsa");
    expect(text(html)).not.toContain("Scanning keys");
    expect(html.match(/<button/g)).toHaveLength(2);
    expect(html).not.toContain(DISABLED);
    expect(choices({ busy: true }).match(/disabled=""/g)).toHaveLength(1);
  });

  it("asks for the path of the key that was pressed", () => {
    const chosen: string[] = [];
    // The list has no hooks: calling it gives its element tree, whose buttons can be pressed.
    const tree = KeyChoices({ keys: [key("id_mac", "SHA256:abc"), key("old_rsa", null)], loading: false, busy: false, onChoose: (path) => chosen.push(path) });
    for (const button of buttonsIn(tree)) button.props.onClick!();
    expect(chosen).toEqual(["/home/f/.ssh/id_mac", "/home/f/.ssh/old_rsa"]);
  });
});

describe("the confirm before a key is uploaded", () => {
  const confirm = (slot: SyncKeySlotView, onConfirm = () => {}) => SyncKeyConfirm({ slot, open: true, onCancel: () => {}, onConfirm });
  const title = (tree: ReactNode) => textIn(elementsOf(tree, AlertDialogTitle));
  const description = (tree: ReactNode) => elementsOf(tree, AlertDialogDescription).map(textIn);

  it("names the key and says a passphrase still protects it", () => {
    const tree = confirm(keySlot({ mode: "own", fingerprint: null, has_passphrase: null, local_has_passphrase: true }));
    expect(title(tree)).toBe("Sync id_mac to your other computers?");
    expect(description(tree)).toEqual(["Has a passphrase — it stays on each computer."]);
  });

  it("says who can use a key without a passphrase — the new key's, for Sync the new key", () => {
    const tree = confirm(keySlot({ status: { kind: "source_changed", file: "/f" }, has_passphrase: true, local_has_passphrase: false }));
    expect(title(tree)).toBe("Sync id_mac to your other computers?");
    expect(description(tree)).toEqual(["No passphrase — your sync code and every joined computer can use this key once it syncs."]);
  });

  it("leaves the passphrase out when it isn't known", () => {
    expect(description(confirm(keySlot({ mode: "own", fingerprint: null, has_passphrase: null, local_has_passphrase: null })))).toEqual([]);
  });

  it("reveals hidden characters in a name another computer chose", () => {
    expect(title(confirm(keySlot({ name: SPOOFED_NAME })))).toBe(`Sync ${SPOOFED_NAME_SHOWN} to your other computers?`);
  });

  it("can be cancelled, and syncs only when Sync key is pressed", () => {
    let confirmed = 0;
    const tree = confirm(keySlot(), () => confirmed++);
    expect(elementsOf(tree, AlertDialogCancel).map(textIn)).toEqual(["Cancel"]);
    const [action] = elementsOf(tree, AlertDialogAction);
    expect(textIn(action)).toBe("Sync key");
    expect(confirmed).toBe(0);
    action.props.onClick!();
    expect(confirmed).toBe(1);
  });
});

describe("the confirm before a copy is deleted", () => {
  it("says this computer's copy goes and other computers keep theirs, and claims nothing about the original key", () => {
    let deleted = 0;
    const tree = DeleteCopyConfirm({ slot: keySlot({ name: SPOOFED_NAME }), open: true, onCancel: () => {}, onConfirm: () => deleted++ });
    expect(textIn(elementsOf(tree, AlertDialogTitle))).toBe("Delete this copy?");
    expect(elementsOf(tree, AlertDialogDescription).map(textIn)).toEqual([
      `The copy of ${SPOOFED_NAME_SHOWN} on this computer is deleted. Other computers aren't affected.`,
    ]);
    const [action] = elementsOf(tree, AlertDialogAction);
    expect(textIn(action)).toBe("Delete copy");
    action.props.onClick!();
    expect(deleted).toBe(1);
  });
});

describe("deleting a key in SSHelter", () => {
  it("warns that deleting a vault key may delete the only copy", () => {
    const tree = DeleteCopyConfirm({ slot: keySlot({ in_vault: true, status: { kind: "not_in_use", file: "/f" } }), open: true, onCancel: () => {}, onConfirm: () => {} });
    expect(elementsOf(tree, AlertDialogDescription).map(textIn)).toEqual([
      "The key id_mac kept in SSHelter on this computer is deleted. If it is your only copy, it is gone. Other computers aren't affected.",
    ]);
  });

  it("reveals hidden characters in the name of the vault key it deletes", () => {
    const slot = keySlot({ in_vault: true, name: SPOOFED_NAME, status: { kind: "not_in_use", file: "/f" } });
    const tree = DeleteCopyConfirm({ slot, open: true, onCancel: () => {}, onConfirm: () => {} });
    expect(elementsOf(tree, AlertDialogDescription).map(textIn)).toEqual([
      `The key ${SPOOFED_NAME_SHOWN} kept in SSHelter on this computer is deleted. If it is your only copy, it is gone. Other computers aren't affected.`,
    ]);
  });
});

describe("deleting a key only on this computer", () => {
  it("says it may be the only copy, and deletes on Delete", () => {
    let deleted = 0;
    const tree = DeleteKeyConfirm({ slot: keySlot({ name: SPOOFED_NAME, local_only: true }), open: true, onCancel: () => {}, onConfirm: () => deleted++ });
    expect(textIn(elementsOf(tree, AlertDialogTitle))).toBe(`Delete ${SPOOFED_NAME_SHOWN}?`);
    expect(elementsOf(tree, AlertDialogDescription).map(textIn)).toEqual([
      "SSHelter removes this key from this computer. It's the only copy unless you exported one.",
    ]);
    const [action] = elementsOf(tree, AlertDialogAction);
    expect(textIn(action)).toBe("Delete");
    action.props.onClick!();
    expect(deleted).toBe(1);
  });
});

describe("the confirm before a Move removes a key file", () => {
  const PATH = "/home/f/.ssh/id_work";
  const confirm = (path: string | null = PATH, on: { onCancel?: () => void; onConfirm?: () => void; open?: boolean } = {}) =>
    MoveKeyConfirm({ path, open: true, onCancel: () => {}, onConfirm: () => {}, ...on });
  /** The dialog's own `onOpenChange`: what Cancel, Escape and a click outside end in. */
  const closeDialog = (tree: ReactNode) => (elementsOf(tree, AlertDialog)[0] as unknown as ReactElement<{ onOpenChange: (open: boolean) => void }>).props.onOpenChange(false);

  it("names the file, and says the vault keeps the only copy while the file goes", () => {
    const tree = confirm();
    expect(textIn(elementsOf(tree, AlertDialogTitle))).toBe("Move id_work into SSHelter?");
    expect(elementsOf(tree, AlertDialogDescription).map(textIn)).toEqual([
      "SSHelter keeps the only copy of this key on this computer and removes /home/f/.ssh/id_work. Export private key… gets a file back.",
    ]);
  });

  it("names a Windows file by its last part", () => {
    expect(textIn(elementsOf(confirm("C:\\Users\\f\\.ssh\\id_work"), AlertDialogTitle))).toBe("Move id_work into SSHelter?");
  });

  it("lets a long file name and path wrap anywhere, as other paths do: neither has a space to break at", () => {
    const name = "k".repeat(70);
    const path = `/home/f/${"a-folder-with-a-long-name/".repeat(4)}${name}`;
    const tree = confirm(path);
    const breaksAnywhere = elementsOf(tree, "span").filter((span) => String((span.props as { className?: string }).className).includes("break-all"));
    expect(breaksAnywhere.map(textIn)).toEqual([name, path]);
    // The sentences around them still wrap between words.
    expect(textIn(elementsOf(tree, AlertDialogTitle))).toBe(`Move ${name} into SSHelter?`);
    expect(elementsOf(tree, AlertDialogDescription).map(textIn)).toEqual([
      `SSHelter keeps the only copy of this key on this computer and removes ${path}. Export private key… gets a file back.`,
    ]);
  });

  it("reveals hidden characters in the file's name and path: they come from the disk", () => {
    const tree = confirm(`/home/f/Downloads/${SPOOFED_NAME}`);
    expect(textIn(elementsOf(tree, AlertDialogTitle))).toBe(`Move ${SPOOFED_NAME_SHOWN} into SSHelter?`);
    expect(elementsOf(tree, AlertDialogDescription).map(textIn)).toEqual([
      `SSHelter keeps the only copy of this key on this computer and removes /home/f/Downloads/${SPOOFED_NAME_SHOWN}. Export private key… gets a file back.`,
    ]);
    expect(textIn(tree)).not.toMatch(HIDDEN_CHARS);
  });

  it("moves only when Move into SSHelter is pressed; Cancel, Escape and a click outside leave everything as it is", () => {
    let moved = 0;
    let cancelled = 0;
    const tree = confirm(PATH, { onConfirm: () => moved++, onCancel: () => cancelled++ });
    expect(elementsOf(tree, AlertDialogCancel).map(textIn)).toEqual(["Cancel"]);
    const [action] = elementsOf(tree, AlertDialogAction);
    expect(textIn(action)).toBe("Move into SSHelter");
    expect([moved, cancelled]).toEqual([0, 0]);
    closeDialog(tree);
    expect([moved, cancelled]).toEqual([0, 1]);
    action.props.onClick!();
    expect([moved, cancelled]).toEqual([1, 1]);
  });

  it("is open only when asked to be", () => {
    const opened = (tree: ReactNode) => (elementsOf(tree, AlertDialog)[0] as unknown as ReactElement<{ open: boolean }>).props.open;
    expect(opened(confirm())).toBe(true);
    expect(opened(confirm(PATH, { open: false }))).toBe(false);
  });
});

describe("what happens to the key a pick replaces", () => {
  it("stays in SSHelter for a key in SSHelter, and becomes a .previous file for a synced copy", () => {
    expect(replacedKeyNote(keySlot({ in_vault: true }))).toBe("SSHelter keeps the key it replaces.");
    expect(replacedKeyNote(keySlot({ status: { kind: "ready", file: "/f", synced_copy: true, fingerprint: null } }))).toBe(
      "The synced copy on this computer is kept as a .previous file.",
    );
    expect(replacedKeyNote(keySlot())).toBeNull();
  });
});

describe("Export private key", () => {
  const form = (props: Partial<ComponentProps<typeof ExportPrivateKeyForm>> = {}) =>
    ExportPrivateKeyForm({
      name: "id_mac",
      hasPassphrase: false,
      passphrase: "",
      repeat: "",
      busy: false,
      onPassphrase: () => {},
      onRepeat: () => {},
      onExport: () => {},
      onCancel: () => {},
      ...props,
    });
  const exportButton = (tree: ReactNode) => buttonsIn(tree).find((b) => textIn(b) === "Export…")!;

  it("names the key and says what an exported file means, revealing hidden characters", () => {
    const tree = form({ name: SPOOFED_NAME });
    expect(textIn(elementsOf(tree, DialogTitle))).toBe(`Export ${SPOOFED_NAME_SHOWN}?`);
    expect(textIn(elementsOf(tree, DialogDescription))).toBe(
      "Any program can use the exported file without asking, and SSHelter won't keep track of it.",
    );
  });

  it("offers a passphrase only for a key without one, and asks for it twice", () => {
    expect(elementsOf(form(), Input)).toHaveLength(1);
    expect(textIn(form())).toContain("Add a passphrase (optional)");
    expect(elementsOf(form({ passphrase: "x" }), Input)).toHaveLength(2);
    expect(textIn(form({ passphrase: "x" }))).toContain("Repeat the passphrase");
    const protectedKey = form({ hasPassphrase: true });
    expect(elementsOf(protectedKey, Input)).toHaveLength(0);
    expect(textIn(protectedKey)).toContain("It stays protected by its passphrase.");
  });

  it("exports once the passphrase is the same twice, and never while an export runs", () => {
    expect(exportButton(form()).props.disabled).toBe(false);
    expect(exportButton(form({ passphrase: "x", repeat: "" })).props.disabled).toBe(true);
    expect(exportButton(form({ passphrase: "x", repeat: "y" })).props.disabled).toBe(true);
    expect(exportButton(form({ passphrase: "x", repeat: "x" })).props.disabled).toBe(false);
    // No passphrase is a valid choice: a repeat left over from one that was emptied must not block the export.
    expect(exportButton(form({ passphrase: "", repeat: "x" })).props.disabled).toBe(false);
    expect(exportButton(form({ busy: true })).props.disabled).toBe(true);
    let exported = 0;
    exportButton(form({ onExport: () => exported++ })).props.onClick!();
    expect(exported).toBe(1);
  });
});
