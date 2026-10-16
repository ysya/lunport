import { describe, expect, it } from "vitest";
import { auditRows } from "./mcp-audit-rows";
describe("persistent audit view identity", () => {
  it("renders repeated historical IDs and identical timestamps as distinct rows", () => {
    const event = { id: "mcp-session-1", completed_at_ms: 1, command: "uptime" };
    const rows = auditRows([event, { ...event }, { ...event, command: "hostname" }]);
    expect(new Set(rows.map((row) => row.key)).size).toBe(3);
    expect(rows.map((row) => row.entry.command)).toEqual(["uptime", "uptime", "hostname"]);
  });
  it("keeps existing event identity when a different event is prepended and caps at ten", () => {
    const events = Array.from({ length: 12 }, (_, n) => ({ id: "mcp-session-1", command: String(n) }));
    const before = auditRows(events);
    const after = auditRows([{ id: "mcp-session-1", command: "new" }, ...events]);
    expect(before).toHaveLength(10);
    expect(after).toHaveLength(10);
    expect(after[1].key).toBe(before[0].key);
    expect(after[0].key).not.toBe(before[0].key);
  });
});
