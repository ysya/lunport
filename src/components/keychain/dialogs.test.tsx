import { renderToStaticMarkup } from "react-dom/server";
import type { ComponentProps, ReactNode } from "react";
import { describe, expect, it } from "vitest";

import type { KeyInfo } from "@/bindings/KeyInfo";
import type { SyncKeySlotView } from "@/bindings/SyncKeySlotView";
import { AlertDialogAction, AlertDialogCancel, AlertDialogDescription, AlertDialogTitle } from "@/components/ui/alert-dialog";
import { DialogDescription, DialogTitle } from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { keySlot, SPOOFED_NAME, SPOOFED_NAME_SHOWN } from "@/lib/sync-fixtures";
import { DeleteCopyConfirm, ExportPrivateKeyForm, KeyChoices, replacedKeyNote, SyncKeyConfirm } from "./dialogs";
import { buttonsIn, DISABLED, elementsOf, text, textIn } from "./test-markup";

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
    expect(exportButton(form({ busy: true })).props.disabled).toBe(true);
    let exported = 0;
    exportButton(form({ onExport: () => exported++ })).props.onClick!();
    expect(exported).toBe(1);
  });
});
