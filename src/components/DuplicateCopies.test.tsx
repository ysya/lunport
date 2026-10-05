import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";

import type { HostSummary } from "@/bindings/HostSummary";
import { queryKeys } from "@/lib/queries";
import { syncDuplicatesKey, syncOverviewKey } from "@/lib/sync";
import { overview, space } from "@/lib/sync-fixtures";
import { SSH_COMBINES, copiesNote, shadowKey, type NameCopy } from "@/lib/sync-sidebar";
import { CopiesPanel, DuplicateCopies } from "./DuplicateCopies";

const PERSONAL = "/home/f/.ssh/sshelter/personal-3fa2c1d9.config";
const WORK = "/home/f/.ssh/sshelter/work-8b01e4aa.config";
const MAIN = "/home/f/.ssh/config";
const LAB = "/home/f/.ssh/config.d/homelab.config";
const labelOf = (file: string) => ({ [PERSONAL]: "Personal", [WORK]: "Work", [MAIN]: "config", [LAB]: "homelab.config" })[file] ?? file;

const personal: NameCopy = { file: PERSONAL, space: "Personal", first: true };
const work: NameCopy = { file: WORK, space: "Work", first: true };
const main: NameCopy = { file: MAIN, space: null, first: true };
const lab: NameCopy = { file: LAB, space: null, first: true };

function panel(copies: NameCopy[], shadows: ReadonlyMap<string, string> = new Map()): string {
  return renderToStaticMarkup(<CopiesPanel note={copiesNote("web", copies, labelOf, shadows)} />);
}

/** The file path an item shows (the main config's path is a prefix of the other files', so `includes` would not tell them apart). */
function pathOf(item: string): string | undefined {
  return /<div class="font-mono[^"]*">([^<]*)<\/div>/.exec(item)?.[1];
}

/** The inside of every list, in order, with the tag it is (`ol` or `ul`). */
function lists(html: string): { tag: string; items: string[] }[] {
  return [...html.matchAll(/<(ol|ul)\b[^>]*>([\s\S]*?)<\/\1>/g)].map((m) => ({
    tag: m[1],
    items: [...m[2].matchAll(/<li\b[^>]*>([\s\S]*?)<\/li>/g)].map((li) => li[1]),
  }));
}

describe("the explanation shown in place of the editor", () => {
  it("numbers only the synced spaces, in the order ssh reads them, and lists the other files without an order", () => {
    const html = panel([personal, work, main, lab]);
    expect(html).toContain("web is defined in more than one place");
    expect(html).toContain("In synced spaces, which ssh reads first, in this order:");
    expect(html).toContain("In other files, which ssh reads after the synced spaces (their order among themselves isn&#x27;t shown):");
    const [synced, others] = lists(html);
    expect(synced.tag).toBe("ol");
    expect(synced.items.map((item) => item.includes(PERSONAL))).toEqual([true, false]);
    expect(synced.items.map((item) => item.includes(WORK))).toEqual([false, true]);
    expect(synced.items.every((item) => item.includes("synced space"))).toBe(true);
    expect(others.tag).toBe("ul");
    expect(others.items).toHaveLength(2);
    expect(others.items.every((item) => item.includes("not synced"))).toBe(true);
    // Nothing says all the copies come in one order.
    expect(html).not.toContain("reads the copies in this order");
    expect(html).toContain(`${SSH_COMBINES}.`);
  });

  it("does not number a single synced copy", () => {
    const html = panel([work, main]);
    expect(html).toContain("In a synced space, which ssh reads first:");
    expect(html).not.toContain("<ol");
    expect(lists(html).map((list) => list.tag)).toEqual(["ul", "ul"]);
  });

  it("gives each copy its file, and points to the sidebar only for a copy that has the actions there", () => {
    // The backend lists Work's and the main config's copies (Personal's is the one ssh reads first); main's is `Host a web`.
    const shadows = new Map([[shadowKey(WORK, "web"), PERSONAL]]);
    const html = panel([personal, work, { ...main, first: false }], shadows);
    const [synced, others] = lists(html);
    const [personalItem, workItem] = synced.items;
    const [mainItem] = others.items;
    expect(workItem).toContain(WORK);
    expect(workItem).toContain("In the sidebar, open this copy&#x27;s menu");
    expect(workItem).toContain("Keep this copy as web-local");
    expect(workItem).toContain("Remove this copy");
    for (const [item, file] of [
      [personalItem, PERSONAL],
      [mainItem, MAIN],
    ]) {
      expect(item).toContain(file);
      expect(item).toContain("The sidebar has no action for this copy.");
      expect(item).toContain("edit this file in a text editor");
      expect(item).toContain("Reload from disk");
      expect(item).not.toContain("Keep this copy as");
    }
  });

  it("sends every copy to its file when the sidebar has no action for any of them", () => {
    const html = panel([work, { ...main, first: false }]);
    expect(html).not.toContain("Keep this copy as");
    expect(html).not.toContain("In the sidebar, open");
    expect([...html.matchAll(/edit this file in a text editor/g)]).toHaveLength(2);
  });

  it("edits nothing: no form, no field, no button", () => {
    expect(panel([work, main])).not.toMatch(/<(form|input|textarea|select|button)\b/);
  });

  it("says it has not read the sync state, and lists the copies without placing any, while the spaces are not known", () => {
    const html = renderToStaticMarkup(<CopiesPanel note={copiesNote("web", [main, lab], labelOf, new Map(), false)} />);
    expect(html).toContain("SSHelter has not read which spaces this computer syncs");
    expect(html).toContain("Until it can, SSHelter leaves all of them alone.");
    const [only, ...rest] = lists(html);
    expect(rest).toEqual([]);
    expect(only.tag).toBe("ul");
    expect(only.items.map(pathOf)).toEqual([MAIN, LAB]);
    expect(html).not.toContain("synced space");
    expect(html).not.toContain("not synced");
    expect(html).not.toContain("Keep this copy as");
    expect(html).not.toContain("text editor");
  });
});

describe("the pane for a name with several copies, wired to the queries", () => {
  const hosts: HostSummary[] = [work, main].map((copy) => ({
    alias: "web",
    patterns: ["web"],
    source_file: copy.file,
    tags: [],
    hostname: null,
    user: null,
  }));

  function pane(options: { overviewKnown?: boolean; duplicates?: { alias: string; local_file: string }[] } = {}): string {
    const queryClient = new QueryClient();
    queryClient.setQueryData(queryKeys.hosts, { files: [MAIN, WORK], hosts });
    if (options.overviewKnown !== false) {
      queryClient.setQueryData(syncOverviewKey, overview({ spaces: [space({ id: "a".repeat(64), name: "Work", file_path: WORK })] }));
    }
    queryClient.setQueryData(syncDuplicatesKey, options.duplicates ?? []);
    return renderToStaticMarkup(
      <QueryClientProvider client={queryClient}>
        <DuplicateCopies alias="web" copies={[work, main]} />
      </QueryClientProvider>,
    );
  }

  it("points to the sidebar for exactly the copies the backend lists, and to the file for the rest", () => {
    // Work's copy is the one ssh reads first; the backend lists the main config's.
    const [synced, others] = lists(pane({ duplicates: [{ alias: "web", local_file: MAIN }] }));
    expect(synced.items[0]).toContain("edit this file in a text editor");
    expect(others.items[0]).toContain("Keep this copy as web-local");
    expect(others.items[0]).not.toContain("text editor");
    // Not listed (a `Host a web` block, say): the file.
    const none = lists(pane());
    expect([...none[0].items, ...none[1].items].every((item) => item.includes("edit this file in a text editor"))).toBe(true);
  });

  it("claims nothing about the copies until the sync overview is read", () => {
    const html = pane({ overviewKnown: false });
    expect(html).toContain("SSHelter has not read which spaces this computer syncs");
    expect(html).not.toContain("synced space");
    expect(html).not.toContain("Keep this copy as");
  });
});
