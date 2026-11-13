import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it, vi } from "vitest";
import { SettingsCategoryPane } from "./SettingsPage";
import { recordOverview, hostView, hostPayload, groupView } from "./records/fixtures";
import { mcpStatusKey } from "@/lib/mcp";
import type { McpAuditEntry } from "@/bindings/McpAuditEntry";
import type { McpStatus } from "@/bindings/McpStatus";

vi.mock("@/lib/queries", async load => ({
  ...await load<typeof import("@/lib/queries")>(), usePlatform: () => ({ data: "macos" }),
}));
const status: McpStatus = {
  enabled: true, bridge_active: true, approval_mode: "ask",
  max_transfer_mib: 1024,
  noninteractive_credentials_supported: false,
  noninteractive_credentials_notice: "Stored credentials require Ask on macOS.",
  audit_error: "Audit file unavailable", allowed_hosts: ["0000000000000001"], allowed_groups: [], allowed_databases: [], pending: [],
  recent: [{
    id: "a", client: "mcp", host_id: "0000000000000001", alias: "web", command: "sleep 4", mode: "ask",
    requested_by: ["observed-process"], requester_id: "42", client_info: { name: "claimed-client", title: null, version: "1" },
    at_ms: 1, completed_at_ms: 2, outcome: "allowed", ended: "disconnected", exit_code: null, signal: null, detail: null,
    review: null, stop: null, tunnel: null,
  }],
  executable: "/fixture/lunport", last_client_at_ms: null,
};
function render(overview = recordOverview(), data: McpStatus = status, onOpenActivity?: () => void) {
  const client = new QueryClient();
  client.setQueryData(mcpStatusKey, data);
  return renderToStaticMarkup(
    <QueryClientProvider client={client}><SettingsCategoryPane category="ai" recordOverview={overview} onOpenActivity={onOpenActivity} /></QueryClientProvider>,
  );
}
/** The text a person reads: no tags, entities decoded. */
const text = (html: string) => html.replace(/<[^>]*>/g, "").replace(/&quot;/g, "\"").replace(/&#x27;/g, "'").replace(/&lt;/g, "<").replace(/&gt;/g, ">").replace(/&amp;/g, "&");

describe("Records AI Access", () => {
  it("shows the current file transfer limit as an editable MiB setting", () => {
    const html = render();
    expect(html).toContain("Single-file transfer limit");
    expect(html).toMatch(/type="number"[^>]*value="1024"/);
    expect(html).toContain("Save limit");
  });
  it("offers Ask and Auto-log and shows the actual platform credential capability", () => {
    const html = render();
    expect(html).toContain("Auto-log");
    expect(html).toContain(status.noninteractive_credentials_notice);
  });
  it("says that Auto-log starts tunnels and databases without the approval window", () => {
    expect(text(render())).toContain(
      "Auto-log skips ordinary SSH command and file transfer review, and starts tunnels and databases without an approval window.",
    );
  });

  it("shows the audit persistence error above the activity summary", () => {
    const html = render();
    expect(html).toContain(`Audit persistence error: ${status.audit_error}`);
    expect(html.indexOf(status.audit_error!)).toBeLessThan(html.indexOf("Last:"));
  });

  it("summarizes the latest AI entry and opens the page", () => {
    const completed = new Date();
    completed.setHours(14, 20, 0, 0);
    const latest: McpAuditEntry = {
      ...status.recent[0], alias: "web-1", command: "uptime", outcome: "allowed", ended: "exited", exit_code: 0,
      review: "approved", at_ms: completed.getTime() - 800, completed_at_ms: completed.getTime(),
    };
    const html = render(recordOverview(), { ...status, recent: [latest] }, () => {});
    expect(html).toMatch(/<h2[^>]*>Activity<\/h2>/);
    expect(html).toContain("What AI clients did, with each result, is on its own page.");
    const clock = completed.toLocaleTimeString(undefined, { hour: "2-digit", minute: "2-digit" });
    expect(text(html)).toContain(`Last: today ${clock} · Ran a command on web-1 · Succeeded`);
    expect(html).toContain("Open AI activity");
    expect(render(recordOverview(), { ...status, recent: [latest] })).not.toContain("Open AI activity");
    const timeless = text(render(recordOverview(), { ...status, recent: [{ ...latest, at_ms: 0, completed_at_ms: Number.MAX_SAFE_INTEGER }] }));
    expect(timeless).toContain("Last: Ran a command on web-1 · Succeeded");
    expect(timeless).not.toContain("Invalid Date");
  });

  it("says when there is no AI activity yet", () => {
    const html = render(recordOverview(), { ...status, recent: [] }, () => {});
    expect(html).toContain("No AI activity yet");
    expect(html).not.toContain("Last:");
    expect(html).toContain("Open AI activity");
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

  it("shows the host destination and direct action while keeping technical IDs out of the access list", () => {
    const html = render();
    const access = html.slice(html.indexOf('id="settings-allowed-hosts"'), html.indexOf('id="settings-activity"'));
    expect(access).toContain("deploy@fixture.invalid:22");
    expect(access).toContain("Individual grant");
    expect(access).toContain("Remove individual grant for web");
    expect(access).not.toContain("0000000000000001");
  });
});
