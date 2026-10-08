import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { isValidElement, type ComponentProps, type ReactElement, type ReactNode } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";

import type { KeyInfo } from "@/bindings/KeyInfo";
import type { SlotStatusView } from "@/bindings/SlotStatusView";
import type { SyncKeySlotView } from "@/bindings/SyncKeySlotView";
import { agentProblemKey } from "@/lib/agent";
import { syncOverviewKey } from "@/lib/sync";
import { keySlot, overview, SLOT_FINGERPRINT, SPOOFED_NAME, SPOOFED_NAME_SHOWN } from "@/lib/sync-fixtures";
import { AlertDialogAction, AlertDialogCancel, AlertDialogDescription, AlertDialogTitle } from "@/components/ui/alert-dialog";
import { AgentProblemLine, DeleteCopyConfirm, KeepFileConfirm, KeyChoices, KeySlotRow, KeySlotsSection, SyncKeyConfirm, type SlotAction } from "./KeySlotsSection";

/** A slot's row in the Keys dialog, rendered on the server: its words and the actions it offers. */
const row = (slot = keySlot(), busy = false) => renderToStaticMarkup(<KeySlotRow slot={slot} busy={busy} onAction={() => {}} />);
/** The words of some markup, with the apostrophes React escapes put back. */
const text = (html: string) => html.replace(/<[^>]*>/g, " ").replace(/&#x27;/g, "'").replace(/\s+/g, " ");
/** The lines of text of a row (its paragraphs), top to bottom, with the apostrophes React escapes put back. */
const lines = (html: string) => [...html.matchAll(/<p [^>]*>(.*?)<\/p>/g)].map((m) => m[1].replace(/&#x27;/g, "'"));
/** The opening tag of the button labelled `label`, without its closing ">". */
const buttonTag = (html: string, label: string) => {
  const at = html.indexOf(`>${label}<`);
  if (at < 0) throw new Error(`no ${label} button`);
  return html.slice(html.lastIndexOf("<button", at), at);
};
// The shared Button's class names carry `disabled:` variants, so only the attribute itself says a button is off.
const DISABLED = 'disabled=""';

describe("a key slot in the Keys dialog", () => {
  it("shows how the key is shared, its state here, its hosts and the other computers", () => {
    const t = text(row(keySlot({ hosts: ["web", "db"], devices: [{ name: "FRANK-DESKTOP", fingerprint: null, synced_copy: true, in_vault: false }] })));
    expect(t).toContain("id_mac");
    expect(t).toContain("Synced to your computers");
    expect(t).toContain("SHA256:9Q3QMhBJBcoUNE88XYEQbCPlcFByPPyVPJ6enJtQ+ew");
    expect(t).toContain("Ready");
    expect(t).toContain("Used by web and db");
    expect(t).toContain("FRANK-DESKTOP: a synced file");
    expect(row()).toContain(">Stop syncing<");
    expect(row()).toContain(">Change…<");
  });

  it("offers the action each state needs", () => {
    expect(row(keySlot({ mode: "own", fingerprint: null, status: { kind: "needs_key", waiting_for_sync: false } }))).toContain(">Pick a key on this computer…<");
    expect(text(row(keySlot({ mode: "own", fingerprint: null })))).toContain("Each computer uses its own key");
    expect(row(keySlot({ mode: "own", fingerprint: null }))).toContain(">Sync this key<");
    expect(row(keySlot({ status: { kind: "synced_available", file: "/f" } }))).toContain(">Use the synced key<");
    expect(row(keySlot({ status: { kind: "source_changed", file: "/f" } }))).toContain(">Sync the new key<");
    expect(row(keySlot({ mode: "own", status: { kind: "not_in_use", file: "/f" } }))).toContain(">Delete copy<");
  });

  it("reveals hidden characters in a name another computer chose", () => {
    expect(text(row(keySlot({ name: SPOOFED_NAME })))).toContain(SPOOFED_NAME_SHOWN);
  });

  it("shows a slot the account no longer has, which hosts here still use, without buttons", () => {
    const html = row(keySlot({ in_account: false, hosts: ["web"] }));
    expect(text(html)).toContain("Ready");
    expect(text(html)).toContain("Used by web");
    expect(html).not.toContain("<button");
  });

  it("says why a slot failed, and still offers a key to pick", () => {
    const message = "The key this slot points to is gone: /home/f/.ssh/id_mac.";
    const html = row(keySlot({ mode: "own", fingerprint: null, hosts: [], status: { kind: "error", message } }));
    expect(text(html)).toContain(message);
    expect(html).toContain(">Pick a key on this computer…<");
    expect(text(html)).not.toContain("Used by");
  });

  it("turns every button off while an action is running", () => {
    const slot = keySlot({ status: { kind: "synced_available", file: "/f" } });
    const labels = ["Use the synced key", "Change…", "Stop syncing"];
    for (const label of labels) {
      expect(buttonTag(row(slot, true), label)).toContain(DISABLED);
      expect(buttonTag(row(slot, false), label)).not.toContain(DISABLED);
    }
  });
});

describe("the file a slot uses", () => {
  const FILE = "/home/f/.ssh/id_work";
  const named: SlotStatusView[] = [
    { kind: "ready", file: FILE, synced_copy: false, fingerprint: SLOT_FINGERPRINT },
    { kind: "not_in_use", file: FILE },
    { kind: "synced_available", file: FILE },
    { kind: "source_changed", file: FILE },
  ];
  const unnamed: SlotStatusView[] = [{ kind: "needs_key", waiting_for_sync: false }, { kind: "not_used_here" }, { kind: "error", message: "boom" }];

  it("is the line under the state, for the states that name one", () => {
    for (const status of named) {
      // The lines: the name, how the key is shared, the state, the file, the hosts.
      expect(lines(row(keySlot({ status }))).slice(3), status.kind).toEqual([FILE, "Used by web"]);
    }
  });

  it("is in the muted monospace font and may break anywhere, as a path is long", () => {
    const html = row(keySlot({ status: named[0] }));
    const at = html.indexOf(`>${FILE}</p>`);
    const opening = html.slice(html.lastIndexOf("<p ", at), at);
    for (const cls of ["font-mono", "break-all", "text-muted-foreground"]) expect(opening).toContain(cls);
  });

  it("is not there for the states that name none", () => {
    for (const status of unnamed) {
      expect(lines(row(keySlot({ status }))).slice(3), status.kind).toEqual(["Used by web"]);
    }
  });

  it("is left out for a key only in SSHelter: its slot path holds only the .pub, and the line above says where the key is", () => {
    for (const status of named) {
      const html = row(keySlot({ in_vault: true, status }));
      expect(lines(html).slice(3), status.kind).toEqual(["Only in SSHelter on this computer — programs ask before they use it", "Used by web"]);
      expect(html, status.kind).not.toContain(FILE);
    }
  });
});

/** The buttons of an element tree: its elements that have an `onClick`, in the order they are drawn. */
function buttonsIn(node: ReactNode, found: ReactElement<{ onClick?: () => void; children?: ReactNode; disabled?: boolean }>[] = []) {
  if (Array.isArray(node)) node.forEach((child) => buttonsIn(child, found));
  else if (isValidElement<{ onClick?: () => void; children?: ReactNode; disabled?: boolean }>(node)) {
    if (typeof node.props.onClick === "function") found.push(node);
    buttonsIn(node.props.children, found);
  }
  return found;
}

/** What each button of a row asks for when it is pressed, by its label (the row has no hooks: calling it gives its element tree). */
function pressEach(slot: SyncKeySlotView): Record<string, SlotAction> {
  const asked: SlotAction[] = [];
  const pressed: Record<string, SlotAction> = {};
  for (const button of buttonsIn(KeySlotRow({ slot, busy: false, onAction: (action) => asked.push(action) }))) {
    asked.length = 0;
    button.props.onClick!();
    pressed[String(button.props.children)] = asked[0];
  }
  return pressed;
}

describe("the buttons of a key slot", () => {
  it("each ask for their own action", () => {
    expect(pressEach(keySlot({ mode: "own", fingerprint: null }))).toEqual({ "Sync this key": "sync", "Change…": "pick", "Only in SSHelter": "vault" });
    expect(pressEach(keySlot({ status: { kind: "synced_available", file: "/f" } }))).toEqual({
      "Use the synced key": "useSynced",
      "Change…": "pick",
      "Stop syncing": "stop",
    });
    expect(pressEach(keySlot({ status: { kind: "source_changed", file: "/f" } }))).toEqual({
      "Sync the new key": "syncNew",
      "Change…": "pick",
      "Stop syncing": "stop",
    });
    expect(pressEach(keySlot({ mode: "own", fingerprint: null, status: { kind: "needs_key", waiting_for_sync: false } }))).toEqual({
      "Pick a key on this computer…": "pick",
    });
    expect(pressEach(keySlot({ mode: "own", status: { kind: "not_in_use", file: "/f" } }))).toEqual({ "Delete copy": "delete" });
    // A vault key offers Change… too (the key it replaces stays in SSHelter), and still a way back to a file until Task 12.
    expect(pressEach(keySlot({ in_vault: true }))).toEqual({ "Change…": "pick", "Keep a file": "file", "Stop syncing": "stop" });
  });
});

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

/** The text of an element tree, in drawing order (a component without hooks can be called to get its tree). */
function textIn(node: ReactNode): string {
  if (typeof node === "string" || typeof node === "number") return String(node);
  if (Array.isArray(node)) return node.map(textIn).join("");
  if (isValidElement<{ children?: ReactNode }>(node)) return textIn(node.props.children);
  return "";
}

/** The elements of a tree made by `type` (a component), in drawing order. */
function elementsOf(node: ReactNode, type: unknown, found: ReactElement<{ onClick?: () => void; children?: ReactNode }>[] = []) {
  if (Array.isArray(node)) node.forEach((child) => elementsOf(child, type, found));
  else if (isValidElement<{ onClick?: () => void; children?: ReactNode }>(node)) {
    if (node.type === type) found.push(node);
    elementsOf(node.props.children, type, found);
  }
  return found;
}

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

describe("the slots section of the Keys dialog", () => {
  const section = (o = overview()) => {
    const queryClient = new QueryClient();
    queryClient.setQueryData(syncOverviewKey, o);
    return renderToStaticMarkup(
      <QueryClientProvider client={queryClient}>
        <KeySlotsSection />
      </QueryClientProvider>,
    );
  };

  it("lists the slots under its title", () => {
    const html = section(overview({ key_slots: [keySlot(), keySlot({ id: "b".repeat(32), name: "work", hosts: ["db"] })] }));
    expect(text(html)).toContain("Keys used by synced hosts");
    expect(text(html)).toContain("id_mac");
    expect(text(html)).toContain("work");
  });

  it("shows nothing while there are no slots, or this computer is not in a sync account", () => {
    expect(section(overview())).toBe("");
    expect(section(overview({ joined: false, key_slots: [keySlot()] }))).toBe("");
  });
});

describe("keeping a slot's key only in SSHelter", () => {
  it("offers the move each way", () => {
    expect(row(keySlot())).toContain(">Only in SSHelter<");
    const vault = row(keySlot({ in_vault: true }));
    expect(vault).toContain(">Keep a file<");
    expect(vault).not.toContain(">Only in SSHelter<");
    expect(lines(vault)).toContain("Only in SSHelter on this computer — programs ask before they use it");
  });

  it("asks before the key becomes a file any program can use", () => {
    let kept = 0;
    const tree = KeepFileConfirm({ slot: keySlot({ name: SPOOFED_NAME }), open: true, onCancel: () => {}, onConfirm: () => kept++ });
    expect(textIn(elementsOf(tree, AlertDialogTitle))).toBe(`Keep ${SPOOFED_NAME_SHOWN} as a file?`);
    expect(elementsOf(tree, AlertDialogDescription).map(textIn)).toEqual(["Any program on this computer can use the file without asking."]);
    expect(elementsOf(tree, AlertDialogCancel).map(textIn)).toEqual(["Cancel"]);
    const [action] = elementsOf(tree, AlertDialogAction);
    expect(textIn(action)).toBe("Keep a file");
    action.props.onClick!();
    expect(kept).toBe(1);
  });

  it("shows why the agent can't be reached, with Fix for a removed Include", () => {
    const missing = renderToStaticMarkup(<AgentProblemLine problem={{ kind: "include_missing" }} busy={false} onFix={() => {}} />);
    expect(text(missing)).toContain("Hosts that use keys in SSHelter can't reach its agent.");
    expect(missing).toContain(">Fix<");
    const failed = renderToStaticMarkup(<AgentProblemLine problem={{ kind: "not_running", reason: "path too long" }} busy={false} onFix={() => {}} />);
    expect(text(failed)).toContain("SSHelter's agent isn't running: path too long");
    expect(failed).not.toContain(">Fix<");
  });

  it("turns Fix off while something is running, and presses it through onFix", () => {
    const problem = { kind: "include_missing" } as const;
    // The line has no hooks: calling it gives its element tree, whose button can be read and pressed.
    const fixButton = (busy: boolean, onFix = () => {}) => buttonsIn(AgentProblemLine({ problem, busy, onFix }))[0];
    expect(fixButton(true).props.disabled).toBe(true);
    expect(fixButton(false).props.disabled).toBe(false);
    let fixed = 0;
    const fix = fixButton(false, () => fixed++);
    expect(textIn(fix)).toBe("Fix");
    fix.props.onClick!();
    expect(fixed).toBe(1);
  });

  it("lets a long reason wrap instead of pushing Fix out of the dialog", () => {
    const reason = `socket path is too long: /home/${"x".repeat(200)}/.ssh/sshelter/agent/sock`;
    const html = renderToStaticMarkup(<AgentProblemLine problem={{ kind: "not_running", reason }} busy={false} onFix={() => {}} />);
    const opening = html.slice(html.indexOf("<p "), html.indexOf(">", html.indexOf("<p ")));
    for (const cls of ["min-w-0", "break-words"]) expect(opening).toContain(cls);
  });

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

  it("shows the problem above the rows only while a key is in the vault", () => {
    const render = (slot: SyncKeySlotView) => {
      const queryClient = new QueryClient();
      queryClient.setQueryData(syncOverviewKey, overview({ key_slots: [slot] }));
      queryClient.setQueryData(agentProblemKey, { kind: "include_missing" });
      return renderToStaticMarkup(
        <QueryClientProvider client={queryClient}>
          <KeySlotsSection />
        </QueryClientProvider>,
      );
    };
    expect(text(render(keySlot({ in_vault: true })))).toContain("can't reach its agent");
    expect(text(render(keySlot()))).not.toContain("can't reach its agent");
  });
});
