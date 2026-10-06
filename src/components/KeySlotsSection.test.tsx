import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { isValidElement, type ComponentProps, type ReactElement, type ReactNode } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";

import type { KeyInfo } from "@/bindings/KeyInfo";
import type { SlotStatusView } from "@/bindings/SlotStatusView";
import type { SyncKeySlotView } from "@/bindings/SyncKeySlotView";
import { syncOverviewKey } from "@/lib/sync";
import { keySlot, overview, SLOT_FINGERPRINT, SPOOFED_NAME, SPOOFED_NAME_SHOWN } from "@/lib/sync-fixtures";
import { KeyChoices, KeySlotRow, KeySlotsSection, type SlotAction } from "./KeySlotsSection";

/** A slot's row in the Keys dialog, rendered on the server: its words and the actions it offers. */
const row = (slot = keySlot(), busy = false) => renderToStaticMarkup(<KeySlotRow slot={slot} busy={busy} onAction={() => {}} />);
const text = (html: string) => html.replace(/<[^>]*>/g, " ").replace(/\s+/g, " ");
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
    const t = text(row(keySlot({ hosts: ["web", "db"], devices: [{ name: "FRANK-DESKTOP", fingerprint: null, synced_copy: true }] })));
    expect(t).toContain("id_mac");
    expect(t).toContain("Synced to your computers");
    expect(t).toContain("SHA256:9Q3QMhBJBcoUNE88XYEQbCPlcFByPPyVPJ6enJtQ+ew");
    expect(t).toContain("Ready");
    expect(t).toContain("Used by web and db");
    expect(t).toContain("FRANK-DESKTOP: synced copy");
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
});

/** The buttons of an element tree: its elements that have an `onClick`, in the order they are drawn. */
function buttonsIn(node: ReactNode, found: ReactElement<{ onClick?: () => void; children?: ReactNode }>[] = []) {
  if (Array.isArray(node)) node.forEach((child) => buttonsIn(child, found));
  else if (isValidElement<{ onClick?: () => void; children?: ReactNode }>(node)) {
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
    expect(pressEach(keySlot({ mode: "own", fingerprint: null }))).toEqual({ "Sync this key": "sync", "Change…": "pick" });
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
