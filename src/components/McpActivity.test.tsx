import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";
import type { McpAuditEntry } from "@/bindings/McpAuditEntry";
import { McpActivity } from "./McpActivity";

const entry: McpAuditEntry = {
  id: "request-1", client: "mcp", host_id: "f393a89a00e4fe7d", alias: "leg-gitlabconnect",
  command: "git status", mode: "ask", requested_by: [], requester_id: null,
  client_info: { name: null, title: null, version: null },
  at_ms: Date.parse("2026-10-23T03:12:12Z"), completed_at_ms: Date.parse("2026-10-23T03:12:12Z"),
  outcome: "canceled", ended: "canceled", exit_code: null, signal: null, detail: null,
};
const render = (patch: Partial<McpAuditEntry> = {}) => renderToStaticMarkup(<McpActivity entries={[{ ...entry, ...patch }]} />);

describe("AI activity results", () => {
  it("puts the host, command and readable result first and keeps diagnostics collapsed", () => {
    const html = render();
    const summary = html.slice(0, html.indexOf("<details"));
    expect(summary).toContain("leg-gitlabconnect");
    expect(summary).toContain("git status");
    expect(summary).toContain("Canceled");
    expect(summary).toContain("Ask mode");
    expect(summary).not.toContain(entry.host_id);
    expect(summary).not.toContain("Unknown");
    expect(summary).not.toContain("Exit code");
    expect(summary).not.toContain("Observed requester");
    expect(html).not.toContain("<details open");
    expect(html).toContain(entry.host_id);
    expect(html).toContain("request-1");
    expect(html).toContain("Observed requester");
  });

  it.each([
    [{ outcome: "allowed", ended: "exited", exit_code: 0 }, "Succeeded"],
    [{ outcome: "allowed", ended: "exited", exit_code: 2 }, "Failed · exit 2"],
    [{ outcome: "allowed", ended: "exited", exit_code: null }, "Result unavailable"],
    [{ outcome: "allowed", ended: null, exit_code: null }, "Result unavailable"],
    [{ outcome: "allowed", ended: "disconnected", exit_code: 0 }, "Connection lost"],
    [{ outcome: "allowed", ended: "truncated", exit_code: 0 }, "Output limit reached"],
    [{ outcome: "allowed", ended: "timed_out", exit_code: 0 }, "Timed out"],
    [{ outcome: "allowed", ended: "signaled", signal: "TERM", exit_code: 0 }, "Stopped by signal"],
    [{ outcome: "denied", ended: null, exit_code: 0 }, "Denied"],
    [{ outcome: "canceled", ended: "exited", exit_code: 0 }, "Canceled"],
    [{ outcome: "failed" }, "Failed"],
    [{ outcome: "a_future_outcome" }, "Result unavailable"],
  ] satisfies [Partial<McpAuditEntry>, string][]) ("uses the recorded result for %j", (patch, label) => {
    const summary = render(patch).split("<details")[0];
    expect(summary).toContain(label);
    if (label !== "Succeeded") expect(summary).not.toContain("Succeeded");
  });

  it.each([
    ["host_created", "Host created"], ["host_key_not_verified", "Fingerprint not verified"],
    ["transport_set", "Route saved"], ["transport_not_removed", "Route not removed"],
  ])("shows connection management without invented command execution for %s", (outcome, label) => {
    const html = render({ outcome, command: "", ended: null });
    expect(html).toContain(label);
    expect(html).toContain("No remote command");
    expect(html).not.toContain("Exit code");
  });

  it("keeps client self-reports separate from observed attribution and preserves recorded notes", () => {
    const html = render({ client_info: { name: "Claimed AI", title: null, version: "1" }, detail: "Client disconnected" });
    expect(html).toContain("Observed requester: Unknown");
    expect(html).toContain("Self-reported client: Claimed AI");
    expect(html).toContain("Client disconnected");
    expect(html.split("<details")[0]).not.toContain("Claimed AI");
  });
});
