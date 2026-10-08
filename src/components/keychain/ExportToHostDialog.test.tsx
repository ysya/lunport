import { describe, expect, it } from "vitest";

import type { HostSummary } from "@/bindings/HostSummary";
import { CommandItem } from "@/components/ui/command";
import { DialogDescription, DialogTitle } from "@/components/ui/dialog";
import { SPOOFED_NAME, SPOOFED_NAME_SHOWN } from "@/lib/sync-fixtures";
import { ExportToHostView, type ExportMode } from "./ExportToHostDialog";
import { buttonsIn, elementsOf, textIn } from "./test-markup";

const host = (alias: string): HostSummary => ({ alias, patterns: [alias], source_file: "/home/f/.ssh/config", tags: [], hostname: "10.0.0.1", user: null });

/** The picker's tree: it has no hooks, so calling it gives its elements. */
function view(props: Partial<Parameters<typeof ExportToHostView>[0]> = {}) {
  return ExportToHostView({
    name: "id_mac",
    hosts: [host("web"), host("db")],
    mode: "app",
    terminal: true,
    busy: false,
    onMode: () => {},
    onPick: () => {},
    ...props,
  });
}

describe("Export to host", () => {
  it("names the key and says what happens, revealing hidden characters", () => {
    const tree = view({ name: SPOOFED_NAME });
    expect(textIn(elementsOf(tree, DialogTitle))).toBe(`Export ${SPOOFED_NAME_SHOWN} to a host`);
    expect(textIn(elementsOf(tree, DialogDescription))).toBe(
      "Adds the public key to the host's authorized_keys, then sets the host to use this key.",
    );
  });

  it("offers the app and the Terminal way, and says the Terminal way leaves the host's settings alone", () => {
    const modes: ExportMode[] = [];
    const buttons = buttonsIn(view({ onMode: (m) => modes.push(m) }));
    expect(buttons.map(textIn)).toEqual(["In the app", "In Terminal (ssh-copy-id)"]);
    buttons.forEach((b) => b.props.onClick!());
    expect(modes).toEqual(["app", "terminal"]);
    expect(textIn(view({ mode: "terminal" }))).toContain("The terminal deploy doesn't change the host's settings.");
    expect(textIn(view({ mode: "app" }))).not.toContain("terminal deploy");
  });

  it("offers only the app way where ssh-copy-id can't run", () => {
    const tree = view({ terminal: false, mode: "terminal" });
    expect(buttonsIn(tree)).toEqual([]);
    expect(textIn(tree)).not.toContain("terminal deploy");
  });

  it("exports to the host that is picked, and to none while a deploy is starting", () => {
    const picked: string[] = [];
    elementsOf(view({ onPick: (alias) => picked.push(alias) }), CommandItem).forEach((item) => item.props.onSelect!());
    expect(picked).toEqual(["web", "db"]);
    expect(elementsOf(view({ busy: true }), CommandItem).map((item) => item.props.disabled)).toEqual([true, true]);
  });

  it("shows host names with their hidden characters revealed", () => {
    expect(textIn(view({ hosts: [host(SPOOFED_NAME)] }))).toContain(SPOOFED_NAME_SHOWN);
  });
});
