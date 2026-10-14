import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it, vi } from "vitest";
import { SettingsCategoryPane } from "./SettingsDialog";
import { recordOverview, hostView, hostPayload, groupView } from "./records/fixtures";
import { mcpStatusKey } from "@/lib/mcp";
import type { McpStatus } from "@/bindings/McpStatus";

vi.mock("@/lib/queries", async load => ({
  ...await load<typeof import("@/lib/queries")>(), usePlatform: () => ({ data: "macos" }),
}));
const status: McpStatus = {
  enabled: true, bridge_active: true, approval_mode: "ask",
  noninteractive_credentials_supported: false,
  noninteractive_credentials_notice: "Stored credentials require Ask on macOS.",
  audit_error: "Audit file unavailable", allowed_hosts: ["0000000000000001"], pending: [],
  recent: [{
    id: "a", client: "mcp", host_id: "0000000000000001", alias: "web", command: "sleep 4", mode: "ask",
    requested_by: ["observed-process"], requester_id: "42", client_info: { name: "claimed-client", title: null, version: "1" },
    at_ms: 1, completed_at_ms: 2, outcome: "allowed", ended: "disconnected", exit_code: null, signal: null, detail: null,
  }],
  executable: "/fixture/sshelter", last_client_at_ms: null,
};
function render(overview = recordOverview(), data: McpStatus = status) {
  const client = new QueryClient();
  client.setQueryData(mcpStatusKey, data);
  return renderToStaticMarkup(
    <QueryClientProvider client={client}><SettingsCategoryPane category="ai" recordOverview={overview} /></QueryClientProvider>,
  );
}

describe("Records AI Access", () => {
  it("offers Ask and Auto-log and shows the actual platform credential capability", () => {
    const html = render();
    expect(html).toContain("Auto-log");
    expect(html).toContain(status.noninteractive_credentials_notice);
  });

  it("shows public audit failure and authorization separately from a missing exit", () => {
    const html = render();
    expect(html).toContain(status.audit_error!);
    expect(html).toContain("disconnected");
    expect(html).toContain("Exit: unknown");
    expect(html).toContain("observed-process");
    expect(html).toContain("Self-reported client");
    expect(html).toContain("claimed-client");
  });

  it("shows effective endpoint and nested Group path without a Group grant control", () => {
    const parent = groupView({ id: "group-1", payload: { schema: 1, name: "Operations", parent_id: null, defaults: {} } });
    const child = groupView({ id: "group-2", payload: { schema: 1, name: "Fleet", parent_id: "group-1", defaults: {} } });
    const html = render(recordOverview({
      groups: [parent, child],
      hosts: [hostView({ payload: hostPayload({ user: "fallback", group_id: "group-2" }), effective_payload: hostPayload({ user: "ops", port: 2222 }) })],
    }));
    expect(html).toContain("ops@fixture.invalid:2222");
    expect(html).toContain("Group: Operations / Fleet");
    expect(html).not.toContain("fallback@");
    expect((html.match(/role="switch"/g) ?? []).length).toBe(2);
  });

  it("renders only the latest ten real endings without inferring success", () => {
    const recent = Array.from({ length: 11 }, (_, i) => ({
      ...status.recent[0], id: `audit-${i}`, alias: `entry-${i}`,
      ended: i === 0 ? "timed_out" : i === 1 ? "truncated" : "canceled", exit_code: null,
    }));
    const html = render(recordOverview(), { ...status, recent });
    expect(html).toContain("entry-9");
    expect(html).not.toContain("entry-10");
    expect(html).toContain("timed_out");
    expect(html).toContain("truncated");
    expect(html).toContain("canceled");
    expect(html).not.toContain("Exit: 0");
  });

  it("shows the individually allowed stable ID rather than only the alias", () => {
    expect(render()).toContain("ID: 0000000000000001");
  });
});
