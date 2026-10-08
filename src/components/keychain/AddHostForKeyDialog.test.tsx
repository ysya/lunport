import { QueryClient } from "@tanstack/react-query";
import { renderToStaticMarkup } from "react-dom/server";
import { toast } from "sonner";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { Dialog } from "@/components/ui/dialog";
import { SelectItem } from "@/components/ui/select";
import { queryKeys } from "@/lib/queries";
import { syncOverviewKey } from "@/lib/sync";
import { overview, SPOOFED_NAME, SPOOFED_NAME_SHOWN } from "@/lib/sync-fixtures";
import { useUiStore } from "@/stores/ui";
import { AddHostForKeyView, afterHostAdded, newHostFields, type AddHostForKeyState } from "./AddHostForKeyDialog";
import { buttonTag, buttonsIn, DISABLED, elementsOf, HIDDEN_CHARS, text, textIn } from "./test-markup";

const target = { name: "laptop", value: "~/.ssh/sshelter/keys/laptop-3fa2c1d9" };
const FILE = "/home/f/.ssh/config";
const state = (overrides: Partial<AddHostForKeyState> = {}): AddHostForKeyState => ({ alias: "", hostName: "", user: "", file: FILE, ...overrides });
const props = (s: AddHostForKeyState, over: Partial<Parameters<typeof AddHostForKeyView>[0]> = {}): Parameters<typeof AddHostForKeyView>[0] => ({
  target,
  state: s,
  files: [FILE],
  labels: new Map([[FILE, "config"]]),
  existing: new Set(["web"]),
  busy: false,
  onChange: () => {},
  onAdd: () => {},
  onCancel: () => {},
  ...over,
});
// The title and the description need a Dialog around them; a server render draws it without its portal, so the form shows in place.
const view = (s: AddHostForKeyState, name = target.name, over: Partial<Parameters<typeof AddHostForKeyView>[0]> = {}) =>
  renderToStaticMarkup(<Dialog open>{AddHostForKeyView(props(s, { target: { ...target, name }, ...over }))}</Dialog>);

describe("Add a host for this key", () => {
  it("says the host will use the key, and adds only a free alias", () => {
    const t = text(view(state()));
    expect(t).toContain("Add a host for laptop");
    expect(t).toContain("The new host uses this key: IdentityFile ~/.ssh/sshelter/keys/laptop-3fa2c1d9");
    expect(buttonTag(view(state()), "Add host")).toContain(DISABLED);
    expect(text(view(state({ alias: "web" })))).toContain("web already exists.");
    expect(buttonTag(view(state({ alias: "github.com", user: "git" })), "Add host")).not.toContain(DISABLED);
  });

  it("reveals hidden characters in the key's name", () => {
    const html = view(state(), SPOOFED_NAME);
    expect(html).not.toMatch(HIDDEN_CHARS);
    expect(text(html)).toContain(`Add a host for ${SPOOFED_NAME_SHOWN}`);
  });

  it("asks for a host alias with a reason, and says nothing while the alias is empty", () => {
    expect(text(view(state()))).not.toContain("Enter a host alias.");
    expect(text(view(state({ alias: "  " })))).toContain("Enter a host alias.");
    expect(text(view(state({ alias: "my host" })))).toContain("A host alias can't contain spaces.");
    expect(buttonTag(view(state({ alias: "my host" })), "Add host")).toContain(DISABLED);
    const free = text(view(state({ alias: "github.com" })));
    for (const message of ["Enter a host alias.", "A host alias can't contain spaces.", "already exists."]) expect(free).not.toContain(message);
  });

  it("waits for a config file to be chosen", () => {
    expect(buttonTag(view(state({ alias: "github.com", file: "" })), "Add host")).toContain(DISABLED);
    expect(text(view(state({ alias: "github.com", file: "" })))).toContain("Select a config file");
  });

  it("turns the form and both buttons off while the host is written", () => {
    const html = view(state({ alias: "github.com" }), target.name, { busy: true });
    expect(buttonTag(html, "Cancel")).toContain(DISABLED);
    expect(buttonTag(html, "Add host")).toContain(DISABLED);
    expect(html.match(/<input\b[^>]*>/g)!.every((input) => input.includes(DISABLED))).toBe(true);
    expect(html.match(/<button\b[^>]*role="combobox"[^>]*>/)![0]).toContain(DISABLED);
  });

  it("adds or cancels when the buttons are pressed", () => {
    const asked: string[] = [];
    const tree = AddHostForKeyView(props(state({ alias: "github.com" }), { onAdd: () => asked.push("add"), onCancel: () => asked.push("cancel") }));
    for (const button of buttonsIn(tree)) button.props.onClick!();
    expect(buttonsIn(tree).map(textIn)).toEqual(["Cancel", "Add host"]);
    expect(asked).toEqual(["cancel", "add"]);
  });

  it("reveals hidden characters in the key's value, in the file labels and in the alias that exists", () => {
    const html = view(state(), target.name, { target: { ...target, value: `~/.ssh/${SPOOFED_NAME}` } });
    expect(html).not.toMatch(HIDDEN_CHARS);
    expect(text(html)).toContain(`IdentityFile ~/.ssh/${SPOOFED_NAME_SHOWN}`);
    // What is typed stays as typed, in its box; the message that names it does not.
    const typed = view(state({ alias: SPOOFED_NAME }), target.name, { existing: new Set([SPOOFED_NAME]) });
    const message = typed.match(/<p class="text-xs text-destructive">([^<]*)<\/p>/)![1];
    expect(message).toBe(`${SPOOFED_NAME_SHOWN} already exists.`);
    expect(message).not.toMatch(HIDDEN_CHARS);
    // The file list is in the select's popup, which a server render leaves out: read it from the tree.
    const items = elementsOf(AddHostForKeyView(props(state(), { labels: new Map([[FILE, SPOOFED_NAME]]) })), SelectItem);
    expect(items.map(textIn)).toEqual([SPOOFED_NAME_SHOWN]);
  });
});

describe("the host Add a host for this key writes", () => {
  it("is the key as its IdentityFile, with HostName and User when they were typed", () => {
    expect(newHostFields(state({ alias: "github.com" }), target.value)).toEqual([{ keyword: "IdentityFile", value: target.value, remove: false }]);
    expect(newHostFields(state({ alias: "github.com", hostName: " ssh.github.com ", user: " git " }), "~/.ssh/id_work")).toEqual([
      { keyword: "HostName", value: "ssh.github.com", remove: false },
      { keyword: "User", value: "git", remove: false },
      { keyword: "IdentityFile", value: "~/.ssh/id_work", remove: false },
    ]);
  });

  it("puts a key path with a space in double quotes, as ssh reads one argument only then", () => {
    const identityFile = (value: string) => newHostFields(state({ alias: "github.com" }), value)[0].value;
    expect(identityFile("~/.ssh/id work")).toBe('"~/.ssh/id work"');
    expect(identityFile("~/.ssh/id\twork")).toBe('"~/.ssh/id\twork"');
    // Nothing to quote, or quoted already: as it is.
    expect(identityFile("~/.ssh/sshelter/keys/laptop-3fa2c1d9")).toBe("~/.ssh/sshelter/keys/laptop-3fa2c1d9");
    expect(identityFile('"~/.ssh/id work"')).toBe('"~/.ssh/id work"');
  });
});

describe("after the host was added", () => {
  /** What the toasts on screen say (`getToasts` also lists the ones being dismissed, which say nothing). */
  const toasts = () => toast.getToasts().flatMap((t) => ("title" in t ? [{ title: t.title, description: t.description }] : []));

  beforeEach(() => {
    // sonner's `toast.dismiss` schedules through requestAnimationFrame, which Node lacks.
    vi.stubGlobal("requestAnimationFrame", (cb: FrameRequestCallback) => {
      cb(0);
      return 0;
    });
  });
  afterEach(() => {
    for (const t of toast.getToasts()) toast.dismiss(t.id);
    vi.unstubAllGlobals();
    useUiStore.setState({ keySetup: null });
  });

  it("refreshes the hosts the keys list, asks the Sync key dialog about the new host, and says it was added", () => {
    const queryClient = new QueryClient();
    queryClient.setQueryData(queryKeys.keys, []);
    queryClient.setQueryData(syncOverviewKey, overview());
    afterHostAdded(queryClient, "github.com");
    expect(queryClient.getQueryState(queryKeys.keys)?.isInvalidated).toBe(true);
    expect(queryClient.getQueryState(syncOverviewKey)?.isInvalidated).toBe(true);
    expect(useUiStore.getState().keySetup).toEqual({ aliases: ["github.com"], reason: "saved" });
    expect(toasts()).toEqual([{ title: "Added github.com", description: undefined }]);
  });

  it("reveals hidden characters in the alias it names", () => {
    afterHostAdded(new QueryClient(), SPOOFED_NAME);
    expect(toasts()).toEqual([{ title: `Added ${SPOOFED_NAME_SHOWN}`, description: undefined }]);
    // The Sync key dialog gets the alias itself: it finds the host by it.
    expect(useUiStore.getState().keySetup).toEqual({ aliases: [SPOOFED_NAME], reason: "saved" });
  });
});
