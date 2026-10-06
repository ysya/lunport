import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";

import type { HostSummary } from "@/bindings/HostSummary";
import type { SyncKeySlotView } from "@/bindings/SyncKeySlotView";
import { queryKeys } from "@/lib/queries";
import { syncDuplicatesKey, syncOverviewKey } from "@/lib/sync";
import { SPOOFED_NAME, SPOOFED_NAME_SHOWN, keySlot, overview, space } from "@/lib/sync-fixtures";
import { HostList } from "./HostList";

/*
 * The sidebar rendered on the server (no DOM in these tests), with the query cache filled in: what a row offers when
 * its name has several copies, the markers on a shadowed copy and on a space's header. The menus are closed in a
 * server render and the selection comes from the store's initial state, so those are covered by the pure helpers
 * (`isSelectedRow`, `ambiguityReason`, …) in sync-sidebar.test.ts.
 */

const MAIN = "/home/f/.ssh/config";
const LAB = "/home/f/.ssh/config.d/homelab.config";
const WORK = "/home/f/.ssh/sshelter/work-aaaaaaaa.config";

function host(alias: string, file: string, patterns: string[] = [alias]): HostSummary {
  return { alias, patterns, source_file: file, tags: [], hostname: "10.0.0.1", user: null };
}

function render(
  hosts: HostSummary[],
  options: {
    spaceError?: string;
    spaceName?: string;
    shadowed?: { alias: string; local_file: string }[];
    overviewKnown?: boolean;
    keySlots?: SyncKeySlotView[];
  } = {},
): string {
  const queryClient = new QueryClient();
  queryClient.setQueryData(queryKeys.hosts, { files: [MAIN, LAB, WORK], hosts });
  // Left out of the cache, the overview is "loading" in a server render (nothing fetches it): not known yet.
  if (options.overviewKnown !== false) {
    queryClient.setQueryData(
      syncOverviewKey,
      overview({
        spaces: [space({ id: "a".repeat(64), name: options.spaceName ?? "Work", file_path: WORK, last_error: options.spaceError ?? null })],
        key_slots: options.keySlots ?? [],
      }),
    );
  }
  queryClient.setQueryData(syncDuplicatesKey, options.shadowed ?? []);
  return renderToStaticMarkup(
    <QueryClientProvider client={queryClient}>
      <HostList hosts={hosts} />
    </QueryClientProvider>,
  );
}

/**
 * Whether each row can be dragged, keyed `alias#n`: the n-th row of that alias in the order the rows are listed
 * (the main config's first, then the other files').
 */
function draggable(html: string): Record<string, boolean> {
  const out: Record<string, boolean> = {};
  const seen: Record<string, number> = {};
  for (const row of html.split('<li class="animate-row-enter').slice(1)) {
    const alias = /<span class="min-w-0 flex-1 truncate[^"]*">([^<]*)<\/span>/.exec(row)?.[1] ?? "?";
    const button = /<button type="button"[^>]*>/.exec(row)?.[0] ?? "";
    out[`${alias}#${seen[alias] ?? 0}`] = button.includes('draggable="true"');
    seen[alias] = (seen[alias] ?? 0) + 1;
  }
  return out;
}

describe("a row whose name has several copies, one in a synced space", () => {
  const hosts = [host("web", MAIN), host("db", MAIN), host("web", WORK)];

  it("cannot be dragged, on any copy: a drop would move the first copy by name; other rows still can", () => {
    expect(draggable(render(hosts))).toEqual({ "web#0": false, "db#0": true, "web#1": false });
  });

  it("is also found by a later pattern of a block (`Host a web`), as the backend's lookup by alias does", () => {
    expect(draggable(render([host("a", MAIN, ["a", "web"]), host("web", WORK)]))).toEqual({ "a#0": true, "web#0": false });
  });

  it("keeps every row draggable where the copies are all outside the synced spaces, as before", () => {
    expect(draggable(render([host("web", MAIN), host("web", LAB), host("db", MAIN)]))).toEqual({ "web#0": true, "db#0": true, "web#1": true });
  });
});

describe("before the sync overview is known (loading, or failed)", () => {
  it("treats every name with several copies as ambiguous, wherever it is defined: nothing is dragged by name on a guess", () => {
    const hosts = [host("web", MAIN), host("web", LAB), host("db", MAIN)];
    expect(draggable(render(hosts, { overviewKnown: false }))).toEqual({ "web#0": false, "db#0": true, "web#1": false });
  });

  it("lets those rows be dragged again once the spaces are known and none of the copies is in one", () => {
    const hosts = [host("web", MAIN), host("web", LAB), host("db", MAIN)];
    expect(draggable(render(hosts, { overviewKnown: true }))).toEqual({ "web#0": true, "db#0": true, "web#1": true });
  });
});

describe("the marker on a copy that ssh reads second", () => {
  it("explains that ssh applies both copies, first value wins, in a tooltip", () => {
    const html = render([host("web", MAIN), host("web", WORK)], { shadowed: [{ alias: "web", local_file: MAIN }] });
    expect(html).toContain(
      'title="web is also in Work, which ssh reads first (synced files are read before the rest of your config). ssh applies every copy and takes each setting from the first one that sets it, so a setting only a later copy has still applies, and options that can repeat (IdentityFile, LocalForward, RemoteForward, DynamicForward, SendEnv) add up."',
    );
    expect(html).toContain('aria-label="Also in Work, which ssh reads first"');
    expect(html).not.toContain("ssh uses");
  });

  it("is not there when nothing is shadowed", () => {
    expect(render([host("web", MAIN), host("db", WORK)])).not.toContain("which ssh reads first");
  });
});

describe("a synced space's name, which another computer chose", () => {
  it("is shown with its hidden characters revealed on the group header, in its tooltip and in the markers", () => {
    const html = render([host("web", WORK), host("web", MAIN)], { spaceName: SPOOFED_NAME, spaceError: "boom", shadowed: [{ alias: "web", local_file: MAIN }] });
    expect(html).toContain(SPOOFED_NAME_SHOWN);
    expect(html).toContain(`title="Synced space “${SPOOFED_NAME_SHOWN}” — ${WORK} (rename it in Settings → Sync)"`);
    expect(html).toContain(`aria-label="Problem with ${SPOOFED_NAME_SHOWN}: boom"`);
    // The copy in the main config is shadowed by the space's copy: its marker names the space.
    expect(html).toContain(`aria-label="Also in ${SPOOFED_NAME_SHOWN}, which ssh reads first"`);
    expect(html).not.toMatch(/[\u202E\u200B]/);
  });
});

describe("the marker on a host whose key isn't on this computer", () => {
  // React writes the apostrophes of an attribute as `&#x27;`.
  const TITLE = 'title="This host&#x27;s key isn&#x27;t on this computer — pick one in Keys."';
  const needsKey = { kind: "needs_key" as const, waiting_for_sync: false };

  it("points to Keys, once, on the row of the host that uses the slot", () => {
    const html = render([host("web", WORK)], { keySlots: [keySlot({ hosts: ["web"], status: needsKey })] });
    expect(html.split(TITLE).length - 1).toBe(1);
    expect(html).toContain('aria-label="This host&#x27;s key isn&#x27;t on this computer"');
  });

  it("is only on the hosts that use the slot, and not on the other rows", () => {
    const html = render([host("web", WORK), host("db", WORK)], { keySlots: [keySlot({ hosts: ["web"], status: needsKey })] });
    expect(html.split(TITLE).length - 1).toBe(1);
    const rows = html.split('<li class="animate-row-enter').slice(1);
    expect(rows.map((row) => row.includes(TITLE))).toEqual([true, false]);
  });

  it("is also there when the slot failed, but not while the synced key is on its way or the key is ready", () => {
    expect(render([host("web", WORK)], { keySlots: [keySlot({ hosts: ["web"], status: { kind: "error", message: "boom" } })] })).toContain(TITLE);
    expect(render([host("web", WORK)], { keySlots: [keySlot({ hosts: ["web"], status: { kind: "needs_key", waiting_for_sync: true } })] })).not.toContain(TITLE);
    expect(render([host("web", WORK)], { keySlots: [keySlot({ hosts: ["web"] })] })).not.toContain(TITLE);
    expect(render([host("web", WORK)])).not.toContain(TITLE);
  });
});

describe("a synced space's group header", () => {
  it("carries a warning marker with the space's error when the space is paused", () => {
    const html = render([host("web", WORK)], { spaceError: "duplicate Host web" });
    expect(html).toContain('title="duplicate Host web"');
    expect(html).toContain('aria-label="Problem with Work: duplicate Host web"');
  });

  it("has none while the space is healthy", () => {
    expect(render([host("web", WORK)])).not.toContain("Problem with");
  });
});
