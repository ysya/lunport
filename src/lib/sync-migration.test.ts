import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import type { HostSummary } from "@/bindings/HostSummary";
import { SPOOFED_NAME, SPOOFED_NAME_SHOWN, space } from "./sync-fixtures";
import {
  PER_FILE,
  SYNC_CODE_WORDS,
  TAG_FAILED_PREFIX,
  canMove,
  cleanWordsInput,
  firstSyncWait,
  groupByReason,
  groupHostsForMigration,
  intoSpace,
  isSyncableHost,
  isValidTarget,
  keepVisible,
  migrationTarget,
  moveSummary,
  newSpaceGroups,
  plannedSpaceNames,
  preselectAll,
  tagForFile,
  targetLabel,
  uniqueSpaceName,
  wordCount,
} from "./sync-migration";

function host(alias: string, file: string, patterns: string[] = [alias]): HostSummary {
  return { alias, patterns, source_file: file, tags: [], hostname: null, user: null };
}

const MAIN = "/home/f/.ssh/config";
const LAB = "/home/f/.ssh/config.d/homelab.config";
const PERSONAL = "/home/f/.ssh/sshelter/personal-3fa2c1d9.config";
const WORK = "/home/f/.ssh/sshelter/work-8b01e4aa.config";
const NONE = new Set<string>();

describe("isSyncableHost", () => {
  it("requires every pattern to be a plain name (same rule as the backend)", () => {
    expect(isSyncableHost(host("web", "/f"))).toBe(true);
    expect(isSyncableHost(host("web", "/f", ["web", "web.example.com"]))).toBe(true);
    expect(isSyncableHost(host("*", "/f", ["*"]))).toBe(false);
    expect(isSyncableHost(host("web", "/f", ["web", "*.internal"]))).toBe(false);
    expect(isSyncableHost(host("web", "/f", ["web", "!prod"]))).toBe(false);
    expect(isSyncableHost(host("web?", "/f", ["web?"]))).toBe(false);
    expect(isSyncableHost(host("w", "/f", []))).toBe(false);
  });
});

describe("cleanWordsInput", () => {
  it("joins lines, strips numbering and punctuation, lowercases", () => {
    const raw = "1. Abandon\n2) abandon,\n3 - ABANDON\n\n  about ";
    expect(cleanWordsInput(raw)).toBe("abandon abandon abandon about");
  });

  it("collapses whitespace including full-width spaces", () => {
    expect(cleanWordsInput("a\u3000b   c")).toBe("a b c");
  });
});

describe("wordCount", () => {
  it("counts the words of a sync code the way the Join and Enter buttons read it: tidied first", () => {
    expect(SYNC_CODE_WORDS).toBe(24);
    expect(wordCount("")).toBe(0);
    expect(wordCount("  \n ")).toBe(0);
    expect(wordCount("abandon ability able")).toBe(3);
    // Numbered lines, capitals, full-width spaces and stray punctuation do not count as words.
    expect(wordCount("1. Abandon\n2) ability,\n3 - ABLE\u3000about")).toBe(4);
    const code = Array.from({ length: SYNC_CODE_WORDS }, () => "abandon").join(" ");
    expect(wordCount(code)).toBe(SYNC_CODE_WORDS);
    expect(wordCount(`${code} art`)).toBe(SYNC_CODE_WORDS + 1);
  });
});

describe("groupHostsForMigration", () => {
  it("groups real hosts by source file and skips wildcards and hosts already in a space", () => {
    const hosts = [
      host("web", MAIN),
      host("*", MAIN, ["*"]),
      host("mixed", MAIN, ["mixed", "*.internal"]),
      host("db", LAB),
      host("synced", PERSONAL),
      host("other", WORK),
    ];
    const groups = groupHostsForMigration(hosts, [PERSONAL, WORK], NONE);
    expect(groups.map((g) => g.file)).toEqual([MAIN, LAB]);
    expect(groups[0].hosts.map((h) => h.alias)).toEqual(["web"]);
    expect(groups[1].hosts.map((h) => h.alias)).toEqual(["db"]);
  });

  it("returns no groups when nothing is left to move", () => {
    expect(groupHostsForMigration([host("synced", PERSONAL)], [PERSONAL], NONE)).toEqual([]);
  });

  it("leaves out local hosts that share any name with a host in any space", () => {
    const hosts = [
      host("web", PERSONAL),
      host("app-1", WORK, ["app-1", "app"]),
      host("web", MAIN), // same alias as a synced host
      host("web-prod", MAIN, ["web-prod", "web"]), // a later pattern is synced
      host("app", LAB), // matches a synced host's later pattern, in another space
      host("db", MAIN),
      host("app-2", LAB), // similar, but no shared name
    ];
    const groups = groupHostsForMigration(hosts, [PERSONAL, WORK], NONE);
    expect(groups.map((g) => [g.file, g.hosts.map((h) => h.alias)])).toEqual([
      [MAIN, ["db"]],
      [LAB, ["app-2"]],
    ]);
  });

  it("leaves out hosts the backend can never move (it lists them with the reason)", () => {
    const groups = groupHostsForMigration([host("jump", MAIN), host("db", MAIN)], [PERSONAL], new Set(["jump"]));
    expect(groups[0].hosts.map((h) => h.alias)).toEqual(["db"]);
  });
});

describe("keepVisible", () => {
  it("drops selected hosts the wizard no longer lists", () => {
    const before = groupHostsForMigration([host("web", MAIN), host("db", MAIN)], [PERSONAL], NONE);
    const selected = new Set(["web", "db"]);
    expect(keepVisible(selected, before)).toBe(selected);
    // The first sync of the space brings a synced `web`: the local `web` leaves the list and the selection.
    const after = groupHostsForMigration([host("web", PERSONAL), host("web", MAIN), host("db", MAIN)], [PERSONAL], NONE);
    expect([...keepVisible(selected, after)]).toEqual(["db"]);
  });

  it("keeps the same set when every selected host is still listed", () => {
    const groups = groupHostsForMigration([host("a", "/f"), host("b", "/f"), host("c", "/g")], [PERSONAL], NONE);
    const selected = new Set(["a", "c"]);
    expect(keepVisible(selected, groups)).toBe(selected);
    const none = new Set<string>();
    expect(keepVisible(none, groups)).toBe(none);
  });

  it("drops everything when nothing is listed", () => {
    expect(keepVisible(new Set(["a"]), []).size).toBe(0);
  });
});

describe("tagForFile", () => {
  it("is the backend's tag_for_file: the file name without .config/.conf, lowercase, [a-z0-9_-] only", () => {
    expect(tagForFile(LAB)).toBe("homelab");
    expect(tagForFile("/home/f/.ssh/config.d/web.conf")).toBe("web");
    expect(tagForFile(MAIN)).toBe("config");
    expect(tagForFile("/x/My Servers (old).config")).toBe("my-servers-old");
    expect(tagForFile("/x/Lab.CONFIG")).toBe("lab-config"); // the suffix check is case-sensitive, like the backend
    expect(tagForFile("C:\\Users\\f\\.ssh\\work_vm.conf")).toBe("work_vm");
  });
});

describe("uniqueSpaceName", () => {
  it("adds a number when the name is taken, ignoring case", () => {
    expect(uniqueSpaceName("homelab", ["Personal"])).toBe("homelab");
    expect(uniqueSpaceName("homelab", ["HomeLab"])).toBe("homelab 2");
    expect(uniqueSpaceName("homelab", ["homelab", "homelab 2"])).toBe("homelab 3");
  });

  it("stays within 64 characters", () => {
    const name = uniqueSpaceName("x".repeat(64), ["x".repeat(64)]);
    expect(name).toBe(`${"x".repeat(62)} 2`);
  });

  it("keeps within 64 characters once the number has two digits, too", () => {
    // " 2" … " 9" take two characters, " 10" three: the base gives one more character up.
    const taken = ["x".repeat(64), ...Array.from({ length: 8 }, (_, i) => `${"x".repeat(62)} ${i + 2}`)];
    const name = uniqueSpaceName("x".repeat(64), taken);
    expect(name).toBe(`${"x".repeat(61)} 10`);
    expect([...name]).toHaveLength(64);
    expect(uniqueSpaceName("homelab", ["homelab", ...Array.from({ length: 8 }, (_, i) => `homelab ${i + 2}`)])).toBe("homelab 10");
  });

  it("does not leave a space at the end of a name it had to cut", () => {
    // Cut at 64 characters the base would end in a space: that space goes.
    const base = `${"a".repeat(63)} b`;
    expect(uniqueSpaceName(base, [])).toBe("a".repeat(63));
  });
});

describe("one space per file", () => {
  const groups = groupHostsForMigration([host("web", MAIN), host("db", LAB), host("nas", "/home/f/.orbstack/ssh/config")], [PERSONAL], NONE);

  it("names each new space after its file: the sidebar alias first, else the file's tag, never a taken name", () => {
    const names = plannedSpaceNames(groups, { [LAB]: "Home lab" }, ["Personal", "config"]);
    expect([...names.entries()]).toEqual([
      [MAIN, "config 2"],
      [LAB, "Home lab"],
      ["/home/f/.orbstack/ssh/config", "config 3"],
    ]);
  });

  it("trims the label the user gave a file, and falls back to the file's tag when it is blank", () => {
    const names = plannedSpaceNames(groups, { [LAB]: "  Home lab  ", [MAIN]: "   " }, []);
    expect(names.get(LAB)).toBe("Home lab");
    expect(names.get(MAIN)).toBe("config");
  });

  it("names a file whose tag is empty \"Space\", and numbers the next one", () => {
    const odd = groupHostsForMigration([host("a", "/home/f/.ssh/.config"), host("b", "/home/f/.ssh/-.conf")], [PERSONAL], NONE);
    expect(odd).toHaveLength(2);
    expect([...plannedSpaceNames(odd, {}, []).values()]).toEqual(["Space", "Space 2"]);
  });

  it("does not use a label the backend would refuse (a control character): the whole group would fail", () => {
    const names = plannedSpaceNames(groups, { [LAB]: "Lab\u0007" }, []);
    expect(names.get(LAB)).toBe("homelab");
    // A label that is merely too long is cut, not dropped.
    expect([...(plannedSpaceNames(groups, { [LAB]: "L".repeat(80) }, []).get(LAB) ?? "")]).toHaveLength(64);
  });

  it("sends only the files with selected hosts", () => {
    const names = plannedSpaceNames(groups, {}, []);
    expect(newSpaceGroups(groups, new Set(["db", "nas"]), names)).toEqual([
      { name: "homelab", aliases: ["db"] },
      { name: "config 2", aliases: ["nas"] },
    ]);
  });

  it("sends each host once: a name an earlier file already sends, as an alias or as another name of its host, stays out", () => {
    const twice = groupHostsForMigration(
      [host("web", MAIN), host("db", MAIN, ["db", "database"]), host("web", LAB), host("database", LAB), host("nas", LAB)],
      [PERSONAL],
      NONE,
    );
    expect(newSpaceGroups(twice, new Set(["web", "db", "database", "nas"]), plannedSpaceNames(twice, {}, []))).toEqual([
      { name: "config", aliases: ["web", "db"] },
      { name: "homelab", aliases: ["nas"] },
    ]);
  });
});

describe("migrationTarget", () => {
  const personal = space();
  const work = space({ id: "b".repeat(64), name: "Work", first_sync_pending: true });
  const off = space({ id: "c".repeat(64), name: "Old", selected: false, file_name: null, file_path: null, hosts: null });

  it("keeps the space the wizard was opened for while this computer syncs it", () => {
    expect(migrationTarget([personal, work], work.id)).toBe(work.id);
  });

  it("otherwise picks the first synced space that finished its first sync", () => {
    expect(migrationTarget([work, personal], null)).toBe(personal.id);
    expect(migrationTarget([work], off.id)).toBe(work.id);
  });

  it("falls back to one new space per file when this computer syncs no space", () => {
    expect(migrationTarget([off], null)).toBe(PER_FILE);
    expect(migrationTarget([], null)).toBe(PER_FILE);
  });

  it("never picks a space whose data is missing on the relay while another one is ready, whatever the order or the request", () => {
    const missing = space({ id: "d".repeat(64), name: "Gone", missing: true });
    expect(migrationTarget([missing, personal], null)).toBe(personal.id);
    expect(migrationTarget([missing, personal], missing.id)).toBe(personal.id);
    // Nothing else is ready: a space that is only waiting for its first sync is still better than one that cannot take hosts.
    expect(migrationTarget([missing, work], null)).toBe(work.id);
  });
});

describe("isValidTarget", () => {
  const ready = space();
  const missing = space({ id: "d".repeat(64), name: "Gone", missing: true });
  const off = space({ id: "c".repeat(64), name: "Old", selected: false, file_name: null, file_path: null, hosts: null });

  it("accepts one new space per file and a synced space that can take hosts, nothing else", () => {
    expect(isValidTarget([ready], PER_FILE)).toBe(true);
    expect(isValidTarget([ready], ready.id)).toBe(true);
    expect(isValidTarget([ready], null)).toBe(false);
    expect(isValidTarget([ready, missing, off], missing.id)).toBe(false); // missing on the relay
    expect(isValidTarget([ready, missing, off], off.id)).toBe(false); // not synced here
    expect(isValidTarget([ready], "e".repeat(64))).toBe(false); // gone from the account
  });
});

describe("canMove", () => {
  const ready = { missing: false };
  const state = { selected: 2, pending: false, waitingForFirstSync: false, target: "a".repeat(64), targetSpace: ready };

  it("is true when hosts are selected, nothing runs and the target can take them", () => {
    expect(canMove(state)).toBe(true);
    expect(canMove({ ...state, target: PER_FILE, targetSpace: null })).toBe(true);
  });

  it("is false with nothing selected, while a move runs, or while the target waits for its first sync", () => {
    expect(canMove({ ...state, selected: 0 })).toBe(false);
    expect(canMove({ ...state, pending: true })).toBe(false);
    expect(canMove({ ...state, waitingForFirstSync: true })).toBe(false);
  });

  it("is false when the target is not a space this computer syncs, or its data is missing on the relay", () => {
    expect(canMove({ ...state, targetSpace: null })).toBe(false);
    expect(canMove({ ...state, targetSpace: { missing: true } })).toBe(false);
  });
});

describe("moveSummary", () => {
  const fail = (alias: string, error: string) => ({ alias, error });
  const report = (moved: string[], failed: { alias: string; error: string }[]) => ({ moved, failed, tagged: 0 });

  it("is a success when everything moved", () => {
    expect(moveSummary(report(["a", "b"], []), "into Work")).toEqual({ level: "success", text: "Moved 2 hosts into Work" });
    expect(moveSummary(report(["a"], []), "into Work").text).toBe("Moved 1 host into Work");
  });

  it("is a warning when some hosts had a problem, and says how many", () => {
    expect(moveSummary(report(["a"], [fail("b", "'b' is already in that space")]), "into Work")).toEqual({
      level: "warning",
      text: "Moved 1 host into Work, 1 host with a problem",
    });
  });

  it("is a warning, and does not say 'Moved 0', when nothing moved", () => {
    const failed = ["a", "b", "c", "d", "e"].map((alias) => fail(alias, "wildcard"));
    expect(moveSummary(report([], failed), "into new spaces")).toEqual({ level: "warning", text: "No host moved into new spaces, 5 hosts with a problem" });
  });

  it("counts a host that moved but whose tag could not be saved as moved: the backend lists it under failed only", () => {
    const tagFailed = fail("a", `${TAG_FAILED_PREFIX}: disk is full`);
    expect(moveSummary(report([], [tagFailed]), "into Work")).toEqual({ level: "warning", text: "Moved 1 host into Work, 1 host with a problem" });
    expect(moveSummary(report(["b"], [tagFailed, fail("c", "not attempted: an earlier move failed")]), "into Work").text).toBe(
      "Moved 2 hosts into Work, 2 hosts with a problem",
    );
  });

  it("tells a moved host with a failed tag by the backend's own text (migrate.rs)", () => {
    const rust = readFileSync("src-tauri/src/sync/migrate.rs", "utf8");
    expect(rust).toContain(`format!("${TAG_FAILED_PREFIX}: {e}")`);
  });
});

describe("a space's name, which another computer chose, in the wizard", () => {
  it("is shown with its hidden characters revealed in the toast after a move and while the first sync runs", () => {
    expect(intoSpace(SPOOFED_NAME)).toBe(`into ${SPOOFED_NAME_SHOWN}`);
    expect(firstSyncWait(SPOOFED_NAME)).toBe(`Waiting for the first sync of ${SPOOFED_NAME_SHOWN} to finish…`);
    expect(moveSummary({ moved: ["web"], failed: [], tagged: 0 }, intoSpace(SPOOFED_NAME)).text).toBe(`Moved 1 host into ${SPOOFED_NAME_SHOWN}`);
  });

  it("is shown with its hidden characters revealed in the list of target spaces, with what keeps a space from taking hosts yet", () => {
    expect(targetLabel(space({ name: SPOOFED_NAME }))).toBe(SPOOFED_NAME_SHOWN);
    expect(targetLabel(space({ name: SPOOFED_NAME, missing: true }))).toBe(`${SPOOFED_NAME_SHOWN} (needs rebuild)`);
    expect(targetLabel(space({ name: SPOOFED_NAME, first_sync_pending: true }))).toBe(`${SPOOFED_NAME_SHOWN} (first sync…)`);
  });

  it("reads as it always did for an ordinary name", () => {
    expect(intoSpace("Work")).toBe("into Work");
    expect(firstSyncWait("Work")).toBe("Waiting for the first sync of Work to finish…");
    expect(targetLabel(space({ name: "Work" }))).toBe("Work");
    expect(targetLabel(space({ name: "Work", missing: true, first_sync_pending: true }))).toBe("Work (needs rebuild)");
  });
});

describe("groupByReason", () => {
  it("lists the hosts that share a reason once, in the order the reasons first appear", () => {
    const limited = "the relay is rate-limiting new spaces from this network, so no more are created now; try again in about an hour";
    expect(
      groupByReason([
        { alias: "a", error: "'a' is already in that space" },
        { alias: "b", error: limited },
        { alias: "c", error: limited },
        { alias: "d", error: "'d' is already in that space" },
        { alias: "e", error: limited },
      ]),
    ).toEqual([
      { error: "'a' is already in that space", aliases: ["a"] },
      { error: limited, aliases: ["b", "c", "e"] },
      { error: "'d' is already in that space", aliases: ["d"] },
    ]);
    expect(groupByReason([])).toEqual([]);
  });
});

describe("preselectAll", () => {
  it("selects every host only while all synced spaces are empty and done with their first sync", () => {
    expect(preselectAll([space({ hosts: 0 })])).toBe(true); // right after "Create"
    expect(preselectAll([space({ hosts: 0 }), space({ id: "b".repeat(64), hosts: 2 })])).toBe(false);
    expect(preselectAll([space({ hosts: 0, first_sync_pending: true })])).toBe(false);
    expect(preselectAll([])).toBe(false);
  });
});
