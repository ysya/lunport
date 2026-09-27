import { describe, expect, it } from "vitest";
import type { HostSummary } from "@/bindings/HostSummary";
import { cleanWordsInput, groupHostsForMigration, isSyncableHost, keepVisible } from "./sync-migration";

function host(alias: string, file: string, patterns: string[] = [alias]): HostSummary {
  return { alias, patterns, source_file: file, tags: [], hostname: null, user: null };
}

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
    expect(cleanWordsInput("a　b   c")).toBe("a b c");
  });
});

describe("groupHostsForMigration", () => {
  const managed = "/home/f/.ssh/sshelter/hosts.config";

  it("groups real hosts by source file and skips wildcards and already-synced hosts", () => {
    const hosts = [
      host("web", "/home/f/.ssh/config"),
      host("*", "/home/f/.ssh/config", ["*"]),
      host("mixed", "/home/f/.ssh/config", ["mixed", "*.internal"]),
      host("db", "/home/f/.ssh/config.d/homelab.config"),
      host("synced", managed),
    ];
    const groups = groupHostsForMigration(hosts, managed);
    expect(groups.map((g) => g.file)).toEqual(["/home/f/.ssh/config", "/home/f/.ssh/config.d/homelab.config"]);
    expect(groups[0].hosts.map((h) => h.alias)).toEqual(["web"]);
    expect(groups[1].hosts.map((h) => h.alias)).toEqual(["db"]);
  });

  it("returns no groups when nothing is left to migrate", () => {
    expect(groupHostsForMigration([host("synced", managed)], managed)).toEqual([]);
  });

  it("leaves out local hosts that share any name with a synced host", () => {
    const hosts = [
      host("web", managed),
      host("app-1", managed, ["app-1", "app"]),
      host("web", "/home/f/.ssh/config"), // same alias as a synced host
      host("web-prod", "/home/f/.ssh/config", ["web-prod", "web"]), // a later pattern is synced
      host("app", "/home/f/.ssh/config.d/homelab.config"), // matches a synced host's later pattern
      host("db", "/home/f/.ssh/config"),
      host("app-2", "/home/f/.ssh/config.d/homelab.config"), // similar, but no shared name
    ];
    const groups = groupHostsForMigration(hosts, managed);
    expect(groups.map((g) => g.file)).toEqual(["/home/f/.ssh/config", "/home/f/.ssh/config.d/homelab.config"]);
    expect(groups[0].hosts.map((h) => h.alias)).toEqual(["db"]);
    expect(groups[1].hosts.map((h) => h.alias)).toEqual(["app-2"]);
  });

  it("drops a file group whose every host is already synced", () => {
    const hosts = [host("web", managed), host("web", "/home/f/.ssh/config"), host("db", "/home/f/.ssh/config.d/x.config")];
    expect(groupHostsForMigration(hosts, managed).map((g) => g.file)).toEqual(["/home/f/.ssh/config.d/x.config"]);
  });
});

describe("keepVisible", () => {
  const managed = "/home/f/.ssh/sshelter/hosts.config";

  it("drops selected hosts the wizard no longer lists", () => {
    const before = groupHostsForMigration([host("web", "/home/f/.ssh/config"), host("db", "/home/f/.ssh/config")], managed);
    const selected = new Set(["web", "db"]);
    expect(keepVisible(selected, before)).toBe(selected);
    // The first sync brings a synced `web`: the local `web` leaves the list and the selection.
    const after = groupHostsForMigration(
      [host("web", managed), host("web", "/home/f/.ssh/config"), host("db", "/home/f/.ssh/config")],
      managed,
    );
    expect([...keepVisible(selected, after)]).toEqual(["db"]);
  });

  it("keeps the same set when every selected host is still listed", () => {
    const groups = groupHostsForMigration([host("a", "/f"), host("b", "/f"), host("c", "/g")], managed);
    const selected = new Set(["a", "c"]);
    expect(keepVisible(selected, groups)).toBe(selected);
    const none = new Set<string>();
    expect(keepVisible(none, groups)).toBe(none);
  });

  it("drops everything when nothing is listed", () => {
    expect(keepVisible(new Set(["a"]), []).size).toBe(0);
  });
});
