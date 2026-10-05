import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";

import type { DuplicateAlias } from "@/bindings/DuplicateAlias";
import type { HostSummary } from "@/bindings/HostSummary";
import { SPOOFED_NAME, SPOOFED_NAME_SHOWN, space } from "./sync-fixtures";
import {
  SSH_COMBINES,
  ambiguityReason,
  ambiguousNames,
  copiesNote,
  identityFileNote,
  isSelectedRow,
  removalSyncNote,
  removeCopyLabel,
  shadowFixText,
  shadowKey,
  shadowTooltip,
  shadowedCopies,
  spaceFileLabels,
  spaceFileProblems,
} from "./sync-sidebar";

const MAIN = "/home/f/.ssh/config";
const LAB = "/home/f/.ssh/config.d/homelab.config";
const PERSONAL = "/home/f/.ssh/sshelter/personal-3fa2c1d9.config";
const WORK = "/home/f/.ssh/sshelter/work-8b01e4aa.config";

function host(alias: string, file: string, patterns: string[] = [alias]): HostSummary {
  return { alias, patterns, source_file: file, tags: [], hostname: null, user: null };
}

/**
 * What the backend lists for the sidebar's file-addressed fixes (`migrate::duplicate_aliases`), as a model of
 * the Rust: a block counts by its FIRST pattern only; a name's winner is the first space file (Include order)
 * with a block that starts with it; every block that starts with the name in another file is listed. Two blocks
 * in the winner's own file, and a name that is only a later pattern of a block, are never listed.
 */
function backendDuplicates(hosts: readonly HostSummary[], spaceFiles: readonly string[]): DuplicateAlias[] {
  const winners = new Map<string, string>();
  for (const file of spaceFiles) {
    for (const h of hosts) if (h.source_file === file && !winners.has(h.patterns[0])) winners.set(h.patterns[0], file);
  }
  return hosts.flatMap((h) => {
    const winner = winners.get(h.patterns[0]);
    return winner !== undefined && winner !== h.source_file ? [{ alias: h.patterns[0], local_file: h.source_file }] : [];
  });
}

/** The source of one Rust function: from its `fn` line to the closing brace at the start of a line. */
function rustFunction(source: string, name: string): string {
  const start = source.indexOf(`fn ${name}(`);
  if (start < 0) throw new Error(`no fn ${name}`);
  return source.slice(start, source.indexOf("\n}\n", start));
}

describe("spaceFileLabels", () => {
  it("labels each synced space's file with the space name, in Include order", () => {
    const labels = spaceFileLabels([
      space({ file_path: PERSONAL }),
      space({ id: "c".repeat(64), name: "Old", selected: false, file_name: null, file_path: null, hosts: null }),
      space({ id: "b".repeat(64), name: "Work", file_path: WORK }),
    ]);
    expect([...labels.entries()]).toEqual([
      [PERSONAL, "Personal"],
      [WORK, "Work"],
    ]);
  });
});

describe("a space's name, which another computer chose", () => {
  const labels = spaceFileLabels([space({ name: SPOOFED_NAME, file_path: WORK }), space({ id: "c".repeat(64), name: "Personal", file_path: PERSONAL })]);

  it("is revealed in the label of its file: the sidebar's header, its menus and every sentence built from the label", () => {
    expect(labels.get(WORK)).toBe(SPOOFED_NAME_SHOWN);
    expect(labels.get(PERSONAL)).toBe("Personal");
  });

  it("is revealed in the removal note and the confirms that name the space", () => {
    expect(removalSyncNote([WORK], labels)).toBe(
      `This host is in the synced space “${SPOOFED_NAME_SHOWN}”: removing it here removes it on every computer that syncs that space.`,
    );
    const fix = shadowFixText({ alias: "web", action: "remove", file: WORK, fileLabel: labels.get(WORK)!, space: labels.get(WORK)!, winner: labels.get(PERSONAL)! });
    expect(fix.title).toBe(`Remove the copy of web in ${SPOOFED_NAME_SHOWN}?`);
    expect(fix.description).toContain(`the synced space “${SPOOFED_NAME_SHOWN}”, so this also removes it on every computer that syncs ${SPOOFED_NAME_SHOWN}.`);
    expect(fix.done).toBe(`Removed the copy of web in ${SPOOFED_NAME_SHOWN}`);
    for (const text of [removalSyncNote([WORK], labels)!, fix.title, fix.description, fix.done]) expect(text).not.toMatch(/[\u202E\u200B]/);
  });

  it("is revealed in the places the pane and the reasons name", () => {
    const places = ambiguousNames([host("web", WORK), host("web", MAIN)], labels).get("web")!;
    const labelOf = (file: string) => labels.get(file) ?? "config";
    expect(ambiguityReason("web", places, labelOf)).toBe(
      `web is defined in ${SPOOFED_NAME_SHOWN} and config, so SSHelter can't tell which copy this would change. Select the host to see how to fix that.`,
    );
    expect(copiesNote("web", places, labelOf).groups[0].copies[0].label).toBe(SPOOFED_NAME_SHOWN);
  });
});

describe("spaceFileProblems", () => {
  it("keys each synced space's problem by its file, for the warning marker on the group header", () => {
    const problems = spaceFileProblems([
      space({ file_path: PERSONAL, last_error: "duplicate Host web" }),
      space({ id: "b".repeat(64), name: "Work", file_path: WORK }), // healthy: no marker
      space({ id: "c".repeat(64), name: "Lab", file_path: "/home/f/.ssh/sshelter/lab-cccccccc.config", missing: true }),
      space({ id: "d".repeat(64), name: "Old", selected: false, file_name: null, file_path: null, hosts: null, last_error: "stale" }),
    ]);
    expect([...problems.entries()]).toEqual([
      [PERSONAL, "duplicate Host web"],
      ["/home/f/.ssh/sshelter/lab-cccccccc.config", "Its data is missing on the relay. Rebuild it from this computer, or delete the space."],
    ]);
  });
});

describe("shadowedCopies", () => {
  const hosts = [host("web", PERSONAL), host("web", WORK), host("web", MAIN), host("db", MAIN)];

  it("maps each shadowed copy to the space file ssh reads instead (the first in Include order)", () => {
    const copies = shadowedCopies(
      [
        { alias: "web", local_file: MAIN },
        { alias: "web", local_file: WORK },
      ],
      hosts,
      [PERSONAL, WORK],
    );
    expect(copies).toEqual(
      new Map([
        [shadowKey(MAIN, "web"), PERSONAL],
        [shadowKey(WORK, "web"), PERSONAL],
      ]),
    );
  });

  it("follows the Include line, not the order the hosts were loaded in", () => {
    // Personal's copy is loaded first, but the Include line lists Work first: ssh reads Work's copy first.
    const loaded = [host("web", PERSONAL), host("web", WORK), host("web", MAIN)];
    const copies = shadowedCopies(
      [
        { alias: "web", local_file: PERSONAL },
        { alias: "web", local_file: MAIN },
      ],
      loaded,
      [WORK, PERSONAL],
    );
    expect(copies).toEqual(
      new Map([
        [shadowKey(PERSONAL, "web"), WORK],
        [shadowKey(MAIN, "web"), WORK],
      ]),
    );
  });

  it("skips a copy whose winner is not in the loaded hosts yet", () => {
    expect(shadowedCopies([{ alias: "db", local_file: MAIN }], hosts, [PERSONAL, WORK]).size).toBe(0);
  });

  it("keys by file and alias, so the same alias in two files never collides", () => {
    expect(shadowKey(MAIN, "web")).not.toBe(shadowKey(WORK, "web"));
    expect(shadowKey("/a b", "c")).not.toBe(shadowKey("/a", "b c"));
  });
});

describe("what the sidebar says about a copy ssh reads second", () => {
  it("never says the copy is ignored: ssh applies both, the first value of each setting wins, repeatable options add up", () => {
    expect(SSH_COMBINES).toContain("applies every copy");
    expect(SSH_COMBINES).toContain("first one that sets it");
    expect(SSH_COMBINES).toContain("only a later copy has still applies");
    for (const keyword of ["IdentityFile", "LocalForward", "RemoteForward", "DynamicForward", "SendEnv"]) expect(SSH_COMBINES).toContain(keyword);
    expect(SSH_COMBINES.toLowerCase()).not.toContain("ignored");
  });

  it("explains the marker by what is read first, in a space file and in the main config alike", () => {
    expect(shadowTooltip("web", "Work", true)).toBe(
      `web is also in Work, which ssh reads first (Work comes first in the Include line). ${SSH_COMBINES}.`,
    );
    expect(shadowTooltip("web", "Work", false)).toBe(
      `web is also in Work, which ssh reads first (synced files are read before the rest of your config). ${SSH_COMBINES}.`,
    );
  });

  it("labels the removal by what stays, not by what ssh 'uses'", () => {
    expect(removeCopyLabel("Work")).toBe("Remove this copy (the one in Work stays)");
    expect(removeCopyLabel("Work")).not.toContain("ssh uses");
  });
});

describe("ambiguousNames", () => {
  // The space files in Include order: Personal before Work.
  const spaceFiles = new Map([
    [PERSONAL, "Personal"],
    [WORK, "Work"],
  ]);

  it("lists a name defined in a space file and elsewhere, with its copies in the order ssh reads them", () => {
    // The main config is loaded first, but ssh reads the Include line at its top first.
    const hosts = [host("web", MAIN), host("db", MAIN), host("web", WORK), host("web", PERSONAL), host("nas", LAB)];
    const found = ambiguousNames(hosts, spaceFiles);
    expect([...found.keys()]).toEqual(["web"]);
    expect(found.get("web")).toEqual([
      { file: PERSONAL, space: "Personal", first: true },
      { file: WORK, space: "Work", first: true },
      { file: MAIN, space: null, first: true },
    ]);
  });

  it("orders the space copies by the Include line, not by the order the hosts were loaded in", () => {
    const found = ambiguousNames([host("web", WORK), host("web", PERSONAL)], spaceFiles);
    expect(found.get("web")?.map((copy) => copy.space)).toEqual(["Personal", "Work"]);
  });

  it("keeps duplicates that have no copy in a space file as they were, and lists no name that is defined once", () => {
    expect(ambiguousNames([host("web", MAIN), host("web", LAB)], spaceFiles).size).toBe(0);
    expect(ambiguousNames([host("web", WORK), host("db", PERSONAL)], spaceFiles).size).toBe(0);
    // Not syncing any space: nothing to be careful about.
    expect(ambiguousNames([host("web", MAIN), host("web", LAB)], new Map()).size).toBe(0);
    expect(ambiguousNames([host("web", WORK), host("web", MAIN)], new Map()).size).toBe(0);
  });

  it("finds a copy by any pattern of its block, as the backend's lookup by alias does", () => {
    // `Host a web` in the main config answers to `web` too: an edit of `web` by alias would land there, not in Work.
    const found = ambiguousNames([host("a", MAIN, ["a", "web"]), host("web", WORK)], spaceFiles);
    expect([...found.keys()]).toEqual(["web"]);
    expect(found.get("web")?.map((copy) => copy.file)).toEqual([WORK, MAIN]);
    // A name that repeats within one block is one copy.
    expect(ambiguousNames([host("web", WORK, ["web", "web"])], spaceFiles).size).toBe(0);
  });

  it("lists a name once per block when a file holds it twice next to a space copy", () => {
    const found = ambiguousNames([host("web", MAIN), host("web", MAIN), host("web", WORK)], spaceFiles);
    expect(found.get("web")?.map((copy) => copy.file)).toEqual([WORK, MAIN, MAIN]);
  });

  it("marks a copy whose block starts with the name, the only kind the sidebar's fixes can find", () => {
    const found = ambiguousNames([host("a", MAIN, ["a", "web"]), host("web", MAIN, ["web", "db"]), host("web", WORK)], spaceFiles);
    expect(found.get("web")).toEqual([
      { file: WORK, space: "Work", first: true },
      { file: MAIN, space: null, first: false },
      { file: MAIN, space: null, first: true },
    ]);
  });

  describe("while the spaces this computer syncs are not known (the overview is loading or failed)", () => {
    const hosts = [host("web", MAIN), host("web", LAB), host("db", MAIN), host("a", MAIN, ["a", "nas"]), host("nas", LAB)];

    it("fails closed: every name with several copies counts, wherever it is defined", () => {
      const found = ambiguousNames(hosts, undefined);
      expect([...found.keys()].sort()).toEqual(["nas", "web"]);
      // As loaded, none called synced: nothing is known about the Include line.
      expect(found.get("web")).toEqual([
        { file: MAIN, space: null, first: true },
        { file: LAB, space: null, first: true },
      ]);
      expect(found.get("nas")).toEqual([
        { file: MAIN, space: null, first: false },
        { file: LAB, space: null, first: true },
      ]);
    });

    it("still leaves a name that is defined once alone, and a name that repeats within one block", () => {
      expect(ambiguousNames([host("db", MAIN), host("web", LAB, ["web", "web"])], undefined).size).toBe(0);
    });

    it("is not the same as knowing that no space is synced: then nothing is ambiguous", () => {
      expect(ambiguousNames(hosts, new Map()).size).toBe(0);
      expect(ambiguousNames(hosts, undefined).size).toBe(2);
    });
  });
});

describe("isSelectedRow", () => {
  const web = { alias: "web", source_file: WORK };
  const sameNameElsewhere = { alias: "web", source_file: MAIN };

  it("selects a name with several copies by alias and file, so clicking one never highlights the other", () => {
    const selected = { alias: "web", file: WORK };
    expect(isSelectedRow(web, selected, true)).toBe(true);
    expect(isSelectedRow(sameNameElsewhere, selected, true)).toBe(false);
    // Selected from somewhere that does not know the file (the command palette): no copy is picked for the user.
    expect(isSelectedRow(web, { alias: "web", file: null }, true)).toBe(false);
    expect(isSelectedRow(sameNameElsewhere, { alias: "web", file: null }, true)).toBe(false);
  });

  it("keeps selecting by alias alone where nothing is ambiguous", () => {
    expect(isSelectedRow(web, { alias: "web", file: WORK }, false)).toBe(true);
    expect(isSelectedRow(sameNameElsewhere, { alias: "web", file: WORK }, false)).toBe(true);
    expect(isSelectedRow(web, { alias: "web", file: null }, false)).toBe(true);
    expect(isSelectedRow(web, { alias: "db", file: WORK }, false)).toBe(false);
    expect(isSelectedRow(web, { alias: null, file: null }, true)).toBe(false);
  });
});

describe("what is said about a name that has several copies", () => {
  const spaceFiles = new Map([
    [PERSONAL, "Personal"],
    [WORK, "Work"],
  ]);
  const labelOf = (file: string) => ({ [WORK]: "Work", [PERSONAL]: "Personal", [MAIN]: "config", [LAB]: "homelab.config" })[file] ?? file;
  const copies = [
    { file: WORK, space: "Work", first: true },
    { file: MAIN, space: null, first: true },
  ];
  /** The pane's note for `web`: the copies `ambiguousNames` finds, and the fixes the backend's list gives the sidebar. */
  function noteFor(hosts: HostSummary[]) {
    const files = [...spaceFiles.keys()];
    const found = ambiguousNames(hosts, spaceFiles).get("web") ?? [];
    return copiesNote("web", found, labelOf, shadowedCopies(backendDuplicates(hosts, files), hosts, files));
  }
  const lines = (note: ReturnType<typeof noteFor>) => note.groups.flatMap((group) => group.copies);
  const SIDEBAR_FIX =
    "In the sidebar, open this copy's menu (the ⋯ button or a right-click) and choose “Keep this copy as web-local” or “Remove this copy”.";
  const FILE_FIX = "The sidebar has no action for this copy. To rename or remove it, edit this file in a text editor, then choose Reload from disk.";

  it("names the places in the reason the alias-addressed actions are off", () => {
    expect(ambiguityReason("web", copies, labelOf)).toBe(
      "web is defined in Work and config, so SSHelter can't tell which copy this would change. Select the host to see how to fix that.",
    );
    // A file that holds the name twice is named once.
    expect(ambiguityReason("web", [...copies, copies[1]], labelOf)).toContain("defined in Work and config, so");
  });

  it("explains how ssh combines the copies, and what SSHelter does not do until one copy is left", () => {
    const note = noteFor([host("web", PERSONAL), host("web", WORK)]);
    expect(note.title).toBe("web is defined in more than one place");
    expect(note.combine).toBe(`${SSH_COMBINES}.`);
    expect(note.fix).toBe(
      "SSHelter edits, renames, moves and removes a host by its name, so it can't tell which copy you mean and leaves all of them alone. Once only one copy is left, web can be edited again.",
    );
  });

  it("claims an order only where it is known: the synced spaces, in Include order — never the other files' order", () => {
    // Loaded: Lab, config, Work, Personal. ssh reads Personal, then Work, then the rest in an order that is not known here.
    const note = noteFor([host("web", LAB), host("web", MAIN), host("web", WORK), host("web", PERSONAL)]);
    expect(note.groups).toEqual([
      {
        heading: "In synced spaces, which ssh reads first, in this order:",
        ordered: true,
        copies: [
          { label: "Personal", file: PERSONAL, detail: "synced space", how: FILE_FIX },
          { label: "Work", file: WORK, detail: "synced space", how: SIDEBAR_FIX },
        ],
      },
      {
        heading: "In other files, which ssh reads after the synced spaces (their order among themselves isn't shown):",
        ordered: false,
        copies: [
          { label: "homelab.config", file: LAB, detail: "not synced", how: SIDEBAR_FIX },
          { label: "config", file: MAIN, detail: "not synced", how: SIDEBAR_FIX },
        ],
      },
    ]);
    // Nothing numbers the other files, and no text says the copies come in one order.
    const text = JSON.stringify(note);
    expect(text).not.toContain("reads the copies in this order");
    expect(note.groups[1].heading).not.toContain("in this order");
  });

  it("speaks of one synced copy without an order", () => {
    const [synced] = noteFor([host("web", WORK), host("web", MAIN)]).groups;
    expect(synced.heading).toBe("In a synced space, which ssh reads first:");
    expect(synced.ordered).toBe(false);
  });

  describe("a copy the sidebar has no action for", () => {
    // The backend lists only copies that START with the name and sit in another file than the winner's.
    const shapes: [string, HostSummary[]][] = [
      ["the name is a later pattern of a block: `Host a web` next to `Host web`", [host("a", MAIN, ["a", "web"]), host("web", WORK)]],
      ["the name is a later pattern of a space's block: `Host db web` next to `Host web`", [host("db", WORK, ["db", "web"]), host("web", MAIN)]],
      ["two blocks of one space file", [host("web", WORK), host("web", WORK)]],
    ];

    it.each(shapes)("says to edit the file in a text editor and Reload from disk, and never points to a sidebar action: %s", (_shape, hosts) => {
      // The premise: the backend lists none of these copies, so the sidebar offers no fix on any of them.
      expect(backendDuplicates(hosts, [PERSONAL, WORK])).toEqual([]);
      const note = noteFor(hosts);
      expect(lines(note).length).toBeGreaterThanOrEqual(2);
      for (const line of lines(note)) {
        expect(line.how).toBe(FILE_FIX);
        // Which file, by name and path, is on the line: the label, and the path beside it.
        expect(line.label).not.toBe("");
        expect([MAIN, WORK]).toContain(line.file);
      }
      const everything = JSON.stringify(note);
      expect(everything).not.toContain("Keep this copy as");
      expect(everything).not.toContain("In the sidebar, open");
    });

    it("keeps the sidebar's advice for the copy that has the actions, and sends the others to their file", () => {
      // Personal's copy is read first: the backend lists only Work's.
      const note = noteFor([host("web", PERSONAL), host("web", WORK)]);
      expect(lines(note).map((line) => [line.label, line.how])).toEqual([
        ["Personal", FILE_FIX],
        ["Work", SIDEBAR_FIX],
      ]);
    });

    it("tells apart two blocks of one file: only the one that starts with the name has the actions", () => {
      // main has `Host web` (listed: Work's copy is read first) and `Host a web` (not listed: a later pattern).
      const note = noteFor([host("web", WORK), host("web", MAIN), host("a", MAIN, ["a", "web"])]);
      expect(lines(note).map((line) => [line.file, line.how])).toEqual([
        [WORK, FILE_FIX],
        [MAIN, SIDEBAR_FIX],
        [MAIN, FILE_FIX],
      ]);
    });

    it("rests on the backend listing a copy by its first pattern only (migrate.rs)", () => {
      const rust = readFileSync("src-tauri/src/sync/migrate.rs", "utf8");
      expect(rustFunction(rust, "duplicate_aliases")).toContain("filter_map(first_alias)");
      expect(rustFunction(rust, "winners")).toContain("filter_map(first_alias)");
      expect(rustFunction(rust, "resolve_shadowed")).toContain("first_alias(i) == Some(alias)");
    });
  });

  describe("while the spaces this computer syncs are not known", () => {
    const unknownCopies = [
      { file: MAIN, space: null, first: true },
      { file: LAB, space: null, first: true },
    ];
    const note = copiesNote("web", unknownCopies, labelOf, new Map(), false);

    it("says so, and places no copy: not synced, not read first, not in any order", () => {
      expect(note.unknown).toBe(
        "SSHelter has not read which spaces this computer syncs, so it can't tell whether one of these copies is synced, or which one ssh reads first.",
      );
      expect(note.groups).toEqual([
        {
          heading: "The copies:",
          ordered: false,
          copies: [
            { label: "config", file: MAIN, detail: null, how: null },
            { label: "homelab.config", file: LAB, detail: null, how: null },
          ],
        },
      ]);
      // The copies and what is said about them claim nothing (the first sentence says what is not known).
      const text = JSON.stringify([note.groups, note.fix]);
      for (const claim of ["synced space", "not synced", "reads first", "in this order", "Keep this copy as", "text editor"]) {
        expect(text, claim).not.toContain(claim);
      }
    });

    it("leaves every copy alone until it knows, and says where to look if that lasts", () => {
      expect(note.title).toBe("web is defined in more than one place");
      expect(note.combine).toBe(`${SSH_COMBINES}.`);
      expect(note.fix).toBe("Until it can, SSHelter leaves all of them alone. If this stays, Settings → Sync shows why.");
    });

    it("is not said once the spaces are known", () => {
      expect(copiesNote("web", copies, labelOf).unknown).toBeNull();
    });
  });

  it("says why the deployed key was not written into the host", () => {
    expect(identityFileNote("web", "~/.ssh/id_ed25519")).toBe(
      "web is defined in more than one place, so SSHelter did not edit it. Once only one copy is left, add “IdentityFile ~/.ssh/id_ed25519” to it so that ssh offers this key.",
    );
  });
});

describe("what a fix of a copy says before it runs", () => {
  const base = { alias: "web", file: WORK, fileLabel: "Work", winner: "Personal" };

  it("says a removal in a synced space reaches every computer that syncs it, and that the other copy is not touched", () => {
    const text = shadowFixText({ ...base, action: "remove", space: "Work" });
    expect(text.title).toBe("Remove the copy of web in Work?");
    expect(text.description).toBe(
      "web is in the synced space “Work”, so this also removes it on every computer that syncs Work. The copy in Personal is not touched. A backup is written first, so it can be restored from Backup history.",
    );
    expect(text.confirm).toBe("Remove this copy");
    expect(text.done).toBe("Removed the copy of web in Work");
  });

  it("says a rename in a synced space reaches every computer that syncs it", () => {
    const text = shadowFixText({ ...base, action: "rename", space: "Work" });
    expect(text.title).toBe("Keep the copy of web in Work as web-local?");
    expect(text.description).toBe(
      "The copy is renamed to web-local in the synced space “Work”, so every computer that syncs Work gets web-local and loses its copy of web. The copy in Personal is not touched. A backup is written first, so it can be restored from Backup history.",
    );
    expect(text.confirm).toBe("Keep as web-local");
    expect(text.done).toBe("Renamed the copy of web in Work to web-local");
  });

  it("says a copy in the user's own file changes this computer only, and never claims anything syncs", () => {
    const own = { ...base, file: MAIN, fileLabel: "config", space: null };
    const removal = shadowFixText({ ...own, action: "remove" });
    expect(removal.description).toBe(
      "Only this computer changes: the copy is deleted from config. The copy in Personal is not touched. A backup is written first, so it can be restored from Backup history.",
    );
    const rename = shadowFixText({ ...own, action: "rename" });
    expect(rename.description).toBe(
      "Only this computer changes: the copy in config is renamed to web-local. The copy in Personal is not touched. A backup is written first, so it can be restored from Backup history.",
    );
    for (const text of [removal, rename]) expect(text.description).not.toContain("every computer");
  });
});

describe("removalSyncNote", () => {
  const spaces = new Map([
    [PERSONAL, "Personal"],
    [WORK, "Work"],
  ]);

  it("says the deletion of a host in a synced space reaches every computer that syncs that space", () => {
    expect(removalSyncNote([WORK], spaces)).toBe("This host is in the synced space “Work”: removing it here removes it on every computer that syncs that space.");
  });

  it("says nothing for a host in one of the user's own files, so its confirm stays as it was", () => {
    expect(removalSyncNote([MAIN], spaces)).toBeNull();
    expect(removalSyncNote([], spaces)).toBeNull();
    expect(removalSyncNote([WORK], new Map())).toBeNull();
  });

  it("counts the hosts in synced spaces when several are removed, and names each space once", () => {
    expect(removalSyncNote([WORK, MAIN, WORK], spaces)).toBe(
      "2 of these hosts are in the synced space “Work”: removing them here removes them on every computer that syncs that space.",
    );
    expect(removalSyncNote([MAIN, PERSONAL], spaces)).toBe(
      "One of these hosts is in the synced space “Personal”: removing it here removes it on every computer that syncs that space.",
    );
    expect(removalSyncNote([PERSONAL, WORK], spaces)).toBe(
      "These hosts are in the synced spaces “Personal” and “Work”: removing them here removes them on every computer that syncs those spaces.",
    );
  });
});
