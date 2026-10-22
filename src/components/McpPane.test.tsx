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
  audit_error: "Audit file unavailable", allowed_hosts: ["0000000000000001"], allowed_groups: [], pending: [],
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

  it("shows request and completion dates with seconds and the local time zone", () => {
    const requested = new Date("2026-10-21T23:59:58.000Z");
    const completed = new Date("2026-10-22T00:00:02.000Z");
    const html = render(recordOverview(), { ...status, recent: [{
      ...status.recent[0], at_ms: requested.getTime(), completed_at_ms: completed.getTime(),
    }] });
    const times = [...html.matchAll(/<time dateTime="([^"]+)">([^<]+)<\/time>/g)];
    expect(times.map(match => match[1])).toEqual([requested.toISOString(), completed.toISOString()]);
    expect(html).toContain("Requested:");
    expect(html).toContain("Completed:");
    [requested, completed].forEach((date, index) => {
      expect(times[index][2]).toContain(date.toLocaleDateString(undefined, { dateStyle: "medium" }));
      expect(times[index][2]).toContain(date.toLocaleTimeString(undefined, { timeStyle: "long" }));
    });
  });

  it("shows only the known time for older entries and avoids invented or invalid dates", () => {
    const entry = { ...status.recent[0], at_ms: 0, completed_at_ms: Date.parse("2026-10-22T00:00:02.000Z") };
    const html = render(recordOverview(), { ...status, recent: [entry] });
    expect(html).not.toContain("Requested:");
    expect(html).toContain('dateTime="2026-10-22T00:00:02.000Z"');
    expect(html).toContain("Completed:");
    const missing = render(recordOverview(), { ...status, recent: [{ ...entry, completed_at_ms: Number.MAX_SAFE_INTEGER }] });
    expect(missing).toContain("Time unavailable");
    expect(missing).not.toContain("<time");
    expect(missing).not.toContain("1970");
    expect(missing).not.toContain("Invalid Date");
  });

  it("offers nested Group rules and a separate Hosts tab without misleading switches", () => {
    const parent = groupView({ id: "group-1", payload: { schema: 1, name: "Operations", parent_id: null, defaults: {} } });
    const child = groupView({ id: "group-2", payload: { schema: 1, name: "Fleet", parent_id: "group-1", defaults: {} } });
    const html = render(recordOverview({
      groups: [parent, child],
      hosts: [hostView({ payload: hostPayload({ user: "fallback", group_id: "group-2" }), effective_payload: hostPayload({ user: "ops", port: 2222 }) })],
    }));
    expect(html).toContain("Access by Group or host");
    expect(html).toContain("Operations / Fleet");
    expect(html).not.toContain("fallback@");
    expect((html.match(/role="switch"/g) ?? []).length).toBe(1);
    expect(html).toContain("Allow Group Operations / Fleet");
    expect(html).toContain("Group access includes subgroups and future members");
  });

  it("shows inherited Group access as allowed and directs changes to its parent", () => {
    const parent = groupView({ id: "group-1", payload: { schema: 1, name: "Operations", parent_id: null, defaults: {} } });
    const child = groupView({ id: "group-2", payload: { schema: 1, name: "Fleet", parent_id: "group-1", defaults: {} } });
    const overview = recordOverview({ groups: [parent, child], hosts: [hostView({ payload: hostPayload({ group_id: "group-2" }) })] });
    const policy = { ...status, allowed_hosts: [], allowed_groups: ["local/group-1"] };
    expect(render(overview, policy)).toContain("1 of 1 hosts allowed");
    expect(render(overview, policy)).toContain("Via Operations");
    expect(render(overview, policy)).toContain("Manage inherited access for Operations / Fleet");
    expect(render(overview, policy)).toContain("Remove grant for Group Operations");
    expect(render(overview, policy)).not.toContain("Allow Group Operations / Fleet");
    expect(render({ ...overview, groups: [child] }, policy)).toContain("0 of 1 hosts allowed");
    expect(render({ ...overview, hosts: [hostView()] }, policy)).toContain("0 of 1 hosts allowed");
    const partial = render(overview, { ...status, allowed_groups: [] });
    expect(partial).toContain("Partial");
    expect(partial).toContain("Individual or subgroup grants");
    expect(partial).not.toContain("Remove grant for Group Operations");
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

  it("shows the host destination and direct action while keeping technical IDs out of the access list", () => {
    const html = render();
    const access = html.slice(html.indexOf('id="settings-allowed-hosts"'), html.indexOf('id="settings-recent-activity"'));
    expect(access).toContain("deploy@fixture.invalid:22");
    expect(access).toContain("Individual grant");
    expect(access).toContain("Remove individual grant for web");
    expect(access).not.toContain("0000000000000001");
  });
});
