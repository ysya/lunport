import { describe, expect, it } from "vitest";
import { auditRows } from "./mcp-audit-rows";
describe("persistent audit view identity", () => {
  it("renders repeated historical IDs and identical timestamps as distinct rows", () => {
    const event = { id: "mcp-session-1", completed_at_ms: 1, command: "uptime" };
    const rows = auditRows([event, { ...event }, { ...event, command: "hostname" }]);
    expect(new Set(rows.map((row) => row.key)).size).toBe(3);
    expect(rows.map((row) => row.entry.command)).toEqual(["uptime", "uptime", "hostname"]);
  });
  it("keeps every entry and existing keys when an entry is prepended", () => {
    const events = Array.from({ length: 1200 }, (_, n) => ({ id: "mcp-session-1", command: String(n) }));
    const before = auditRows(events);
    const after = auditRows([{ id: "mcp-session-1", command: "new" }, ...events]);
    expect(before).toHaveLength(1200);
    expect(after).toHaveLength(1201);
    before.forEach((row, i) => expect(after[i + 1].key).toBe(row.key));
    expect(after[0].key).not.toBe(before[0].key);
  });
});
