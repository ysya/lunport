import { describe, it, expect } from "vitest";
import type { BackupInfo } from "@/bindings/BackupInfo";
import { relativeTime, sortBackupsByNewest } from "@/lib/format";

const NOW = 1_700_000_000_000; // fixed reference for deterministic tests

describe("relativeTime", () => {
  it("reports 'just now' under a minute (and for future timestamps)", () => {
    expect(relativeTime(NOW - 5_000, NOW)).toBe("just now");
    expect(relativeTime(NOW + 10_000, NOW)).toBe("just now");
  });

  it("reports minutes, hours, and days", () => {
    expect(relativeTime(NOW - 5 * 60_000, NOW)).toBe("5m ago");
    expect(relativeTime(NOW - 3 * 3_600_000, NOW)).toBe("3h ago");
    expect(relativeTime(NOW - 2 * 86_400_000, NOW)).toBe("2d ago");
  });

  it("reports coarse months and years", () => {
    expect(relativeTime(NOW - 45 * 86_400_000, NOW)).toBe("1mo ago");
    expect(relativeTime(NOW - 400 * 86_400_000, NOW)).toBe("1y ago");
  });
});

describe("sortBackupsByNewest", () => {
  const mk = (ms: number): BackupInfo => ({
    path: `/b.${ms}.bak`,
    file: "/b",
    timestamp_ms: ms,
  });

  it("sorts newest-first by timestamp", () => {
    const sorted = sortBackupsByNewest([mk(100), mk(300), mk(200)]);
    expect(sorted.map((b) => b.timestamp_ms)).toEqual([300, 200, 100]);
  });

  it("does not mutate the input array", () => {
    const input = [mk(100), mk(300)];
    sortBackupsByNewest(input);
    expect(input.map((b) => b.timestamp_ms)).toEqual([100, 300]);
  });
});
