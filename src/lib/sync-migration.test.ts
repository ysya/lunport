import { describe, expect, it } from "vitest";
import type { HostSummary } from "@/bindings/HostSummary";
import { cleanWordsInput, groupHostsForMigration, isSyncableHost } from "./sync-migration";

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
});
