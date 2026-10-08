import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { renderToStaticMarkup } from "react-dom/server";
import type { ComponentProps } from "react";
import { describe, expect, it } from "vitest";

import type { KeyInfo } from "@/bindings/KeyInfo";
import type { SyncKeySlotView } from "@/bindings/SyncKeySlotView";
import type { KeychainSelection } from "@/lib/keychain";
import { queryKeys } from "@/lib/queries";
import { syncOverviewKey } from "@/lib/sync";
import { keySlot, overview, SPOOFED_NAME, SPOOFED_NAME_SHOWN } from "@/lib/sync-fixtures";
import { KeychainList, KeychainListView } from "./KeychainList";
import { buttonsIn, HIDDEN_CHARS, text, textIn } from "./test-markup";

function keyFile(name: string, overrides: Partial<KeyInfo> = {}): KeyInfo {
  return {
    name,
    private_path: `/home/f/.ssh/${name}`,
    public_path: `/home/f/.ssh/${name}.pub`,
    key_type: "ED25519",
    bits: 256,
    fingerprint_sha256: null,
    comment: null,
    in_agent: false,
    hosts: [],
    ...overrides,
  };
}

type Props = ComponentProps<typeof KeychainListView>;
const props = (overrides: Partial<Props> = {}): Props => ({
  slots: [keySlot()],
  files: [keyFile("id_ed25519")],
  filesOpen: false,
  selection: null,
  moveFailures: [],
  query: "",
  onQuery: () => {},
  onSelect: () => {},
  onToggleFiles: () => {},
  onNew: () => {},
  ...overrides,
});
const list = (overrides: Partial<Props> = {}) => renderToStaticMarkup(KeychainListView(props(overrides)));

describe("the Keychain's list", () => {
  it("lists the keys in SSHelter with their badges, and the other key files once they are opened", () => {
    const t = text(list());
    for (const part of ["In SSHelter", "id_mac", "Synced", "ssh-ed25519", "Other key files in ~/.ssh"]) expect(t).toContain(part);
    expect(t).not.toContain("id_ed25519");
    expect(text(list({ filesOpen: true }))).toContain("id_ed25519");
  });

  it("shows the other key files while searching, even when they are closed", () => {
    expect(text(list({ query: "id" }))).toContain("id_ed25519");
  });

  it("marks a key file loaded into ssh-agent", () => {
    expect(text(list({ filesOpen: true, files: [keyFile("id_ed25519", { in_agent: true })] }))).toContain("in ssh-agent");
    expect(text(list({ filesOpen: true }))).not.toContain("in ssh-agent");
  });

  it("says where keys come from while there are none, and when nothing matches a search", () => {
    const empty = text(list({ slots: [] }));
    expect(empty).toContain("No keys in SSHelter yet");
    expect(empty).toContain("Add one with New key or Generate key. Keys used by synced hosts appear here too.");
    expect(text(list({ slots: [], files: [], query: "zzz" }))).toContain("No keys match.");
  });

  it("says when there are no other key files, and when none matches a search", () => {
    expect(text(list({ filesOpen: true, files: [] }))).toContain("No other key files.");
    expect(text(list({ files: [], query: "zzz" }))).toContain("No key files match.");
  });

  it("selects the key that is pressed, and marks the selected one", () => {
    const selected: KeychainSelection[] = [];
    const tree = KeychainListView(props({ filesOpen: true, onSelect: (s) => selected.push(s) }));
    buttonsIn(tree)
      .filter((b) => ["id_mac", "id_ed25519"].some((name) => textIn(b).startsWith(name)))
      .forEach((b) => b.props.onClick!());
    expect(selected).toEqual([
      { kind: "slot", id: keySlot().id },
      { kind: "file", path: "/home/f/.ssh/id_ed25519" },
    ]);
    expect(list({ selection: { kind: "slot", id: keySlot().id } })).toContain('aria-current="true"');
    expect(list()).not.toContain('aria-current="true"');
  });

  it("opens the other key files", () => {
    let toggled = 0;
    const tree = KeychainListView(props({ onToggleFiles: () => toggled++ }));
    buttonsIn(tree).find((b) => textIn(b).includes("Other key files"))!.props.onClick!();
    expect(toggled).toBe(1);
  });

  it("starts New key and Generate key, and no longer offers a key file", () => {
    const asked: string[] = [];
    for (const b of buttonsIn(KeychainListView(props({ onNew: (mode) => asked.push(mode) })))) {
      if (textIn(b) === "New key" || textIn(b) === "Generate key") b.props.onClick!();
    }
    expect(asked).toEqual(["import", "generate"]);
    expect(text(list())).not.toContain("Generate a key file…");
    expect(text(list({ slots: [] }))).toContain("Add one with New key or Generate key. Keys used by synced hosts appear here too.");
  });

  it("offers New key and Generate key as buttons whether keys are listed, none are, or a search matches none", () => {
    for (const overrides of [{}, { slots: [] }, { query: "zzz", slots: [] }]) {
      const labels = buttonsIn(KeychainListView(props(overrides))).map(textIn);
      expect(labels, JSON.stringify(overrides)).toEqual(expect.arrayContaining(["New key", "Generate key"]));
    }
  });

  it("says on a row why the last Move couldn't move its key", () => {
    const slot = keySlot({ file_for_now: true });
    expect(list({ slots: [slot], moveFailures: [{ slot_id: slot.id, name: "id_mac", message: "boom" }] })).toContain(
      'title="Couldn&#x27;t move into SSHelter: boom"',
    );
  });

  it("reveals hidden characters in names", () => {
    const html = list({ slots: [keySlot({ name: SPOOFED_NAME })], filesOpen: true, files: [keyFile(SPOOFED_NAME)] });
    expect(html).not.toMatch(HIDDEN_CHARS);
    expect(text(html).split(SPOOFED_NAME_SHOWN).length - 1).toBe(2);
  });

  it("reveals hidden characters in a key type and in the reason a Move gave, which come from other computers", () => {
    const slot = keySlot({ name: "id_mac", key_type: SPOOFED_NAME, file_for_now: true });
    const html = list({ slots: [slot], moveFailures: [{ slot_id: slot.id, name: "id_mac", message: `The key ${SPOOFED_NAME} is gone.` }] });
    expect(html).not.toMatch(HIDDEN_CHARS);
    // The key type is shown in the row (the markup's text); the reason is in the row's tooltip (an attribute).
    expect(text(html)).toContain(SPOOFED_NAME_SHOWN);
    expect(html).toContain(`title="Couldn&#x27;t move into SSHelter: The key ${SPOOFED_NAME_SHOWN} is gone."`);
  });
});

describe("the Keychain without a sync account", () => {
  // A server render reads a zustand store's initial state (no selection, no Move failures): only the queries are filled in.
  const render = (slots: SyncKeySlotView[]) => {
    const queryClient = new QueryClient();
    queryClient.setQueryData(syncOverviewKey, overview({ joined: false, account_short: null, devices: [], spaces: [], key_slots: slots }));
    queryClient.setQueryData(queryKeys.keys, []);
    return text(
      renderToStaticMarkup(
        <QueryClientProvider client={queryClient}>
          <KeychainList />
        </QueryClientProvider>,
      ),
    );
  };

  it("still lists the keys this computer keeps in SSHelter, for example after leaving the account", () => {
    const t = render([keySlot({ in_account: false, in_vault: true })]);
    expect(t).toContain("id_mac");
    expect(t).toContain("Not in your sync account");
    expect(t).not.toContain("No keys in SSHelter yet");
  });
});
