import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";
import type { McpAuditEntry } from "@/bindings/McpAuditEntry";
import { NO_FILTERS } from "@/lib/mcp-activity";
import { auditRows } from "@/lib/mcp-audit-rows";
import { AiActivityView } from "./AiActivityPanel";
import { hostPayload, hostView, recordOverview } from "./fixtures";

const NOW = new Date(2026, 10, 10, 15).getTime();
const today = (hour: number, minute: number) => new Date(2026, 10, 10, hour, minute).getTime();
const yesterday = (hour: number, minute: number) => new Date(2026, 10, 9, hour, minute).getTime();
const noop = () => {};

function entry(patch: Partial<McpAuditEntry> = {}): McpAuditEntry {
  return {
    id: "request-1", client: "mcp", host_id: "0000000000000001", alias: "web-1", command: "uptime", mode: "auto_log",
    requested_by: ["Terminal", "claude"], requester_id: "42", client_info: { name: "claimed-client", title: null, version: "1" },
    at_ms: today(14, 20) - 800, completed_at_ms: today(14, 20),
    outcome: "allowed", ended: "exited", exit_code: 0, signal: null, detail: null,
    review: "auto_log", stop: null, tunnel: null,
    ...patch,
  };
}

const overview = recordOverview({
  hosts: [
    hostView({ payload: hostPayload({ alias: "web-1" }) }),
    hostView({ id: "0000000000000002", payload: hostPayload({ alias: "db-replica" }) }),
  ],
});

type ViewProps = Parameters<typeof AiActivityView>[0];
function render(entries: McpAuditEntry[], props: Partial<ViewProps> = {}) {
  return renderToStaticMarkup(<AiActivityView
    data={{ revision: 1, entries, audit_error: null }} pending={false} error={null} retry={noop}
    overview={overview} now={NOW} filters={NO_FILTERS} setFilters={noop}
    shown={100} showMore={noop} expanded={new Set()} toggle={noop} showHost={noop} openAiSettings={noop}
    {...props}
  />);
}
/** The text a person reads: no tags, entities decoded. */
const text = (html: string) => html.replace(/<[^>]*>/g, "").replace(/&quot;/g, "\"").replace(/&#x27;/g, "'").replace(/&lt;/g, "<").replace(/&gt;/g, ">").replace(/&amp;/g, "&");
/** The opening tag of the button whose text starts with `label`. */
const buttonBefore = (html: string, label: string) => {
  const before = html.slice(0, html.indexOf(`${label}</button>`));
  return before.slice(before.lastIndexOf("<button"));
};
const expandedAll = (entries: McpAuditEntry[]) => new Set(auditRows(entries).map(row => row.key));

describe("AI activity page", () => {
  const timeline = [
    entry({ id: "a" }),
    entry({ id: "b", command: "df -h", exit_code: 1, at_ms: today(14, 0) - 3000, completed_at_ms: today(14, 0) }),
    entry({
      id: "c", command: "rm -rf /tmp/cache", mode: "ask", review: "refused", outcome: "denied", ended: null, exit_code: null,
      stop: { kind: "refused", window: "approval", reason: "MCP request was denied" },
      at_ms: yesterday(18, 0) - 5000, completed_at_ms: yesterday(18, 0),
    }),
  ];

  it("shows a day-grouped timeline with titles, results and the meta line", () => {
    const html = render(timeline);
    expect(html).toMatch(/<h2[^>]*>Today<\/h2>/);
    expect(html).toMatch(/<h2[^>]*>Yesterday<\/h2>/);
    const page = text(html);
    expect(page).toContain("Ran a command on web-1");
    expect(page).toContain("Asked to run a command on web-1");
    expect(page).toContain("Failed · exit 1");
    expect(page).toContain("Refused by you");
    const clock = new Date(today(14, 20)).toLocaleTimeString(undefined, { hour: "2-digit", minute: "2-digit", second: "2-digit" });
    expect(page).toContain(`Terminal → claude · Auto-log · ${clock} · took 0.8 s`);
    for (const chip of ["All 3", "Succeeded 1", "Failed 1", "Not run 1", "Error 0"]) expect(page).toContain(chip);
    expect(html).toContain('aria-pressed="true"');
    expect(page).toContain("MCP request was denied");
  });

  it("keeps the self-reported client out of the card and shows it expanded", () => {
    const disconnected = [entry({ ended: "disconnected", exit_code: null })];
    const collapsed = render(disconnected);
    expect(collapsed).not.toContain("Self-reported client");
    expect(collapsed).toContain('aria-expanded="false"');
    const html = render(disconnected, { expanded: expandedAll(disconnected) });
    expect(html).toContain('aria-expanded="true"');
    expect(html).toContain("Self-reported client");
    expect(html).toContain("claimed-client");
    expect(html).toContain("Requested");
    expect(html).toContain("Completed");
    for (const ms of [disconnected[0].at_ms, disconnected[0].completed_at_ms]) {
      const date = new Date(ms);
      expect(html).toContain(`dateTime="${date.toISOString()}"`);
      expect(html).toContain(date.toLocaleDateString(undefined, { dateStyle: "medium" }));
      expect(html).toContain(date.toLocaleTimeString(undefined, { timeStyle: "long" }));
    }
    expect(html).toContain("Exit code</dt>");
    expect(html).toContain("Not reported");
    expect(text(html)).toContain("Ran, then the connection was lost.");
    expect(text(html)).toContain("Auto-log: ran without per-command review.");
    expect(html).toContain("Copy command");
  });

  it("shows 100 entries, then 100 more", () => {
    const many = Array.from({ length: 150 }, (_, n) => entry({ id: `request-${n}`, command: `echo ${n}` }));
    const first = render(many);
    expect(first.match(/<li/g)).toHaveLength(100);
    expect(first).toContain("Show 100 more");
    expect(first).toContain("Lunport keeps the latest 1,000 AI entries on this computer.");
    const all = render(many, { shown: 200 });
    expect(all.match(/<li/g)).toHaveLength(150);
    expect(all).not.toContain("Show 100 more");
  });

  it("empty, no-match and load-failure states", () => {
    const empty = text(render([]));
    expect(empty).toContain("No AI activity yet");
    expect(empty).toContain("Commands, tunnels, host and route changes and server key checks that AI clients ask Lunport for appear here with their results.");
    expect(empty).not.toContain("each request");
    expect(empty).toContain("Set up AI access");
    const none = text(render(timeline, { filters: { ...NO_FILTERS, kind: "error" } }));
    expect(none).toContain("No activity matches these filters");
    expect(none).toContain("Try another client, host or result.");
    expect(none).toContain("Clear filters");
    const failed = renderToStaticMarkup(<AiActivityView
      data={undefined} pending={false} error={new Error("bridge down")} retry={noop}
      overview={overview} now={NOW} filters={NO_FILTERS} setFilters={noop}
      shown={100} showMore={noop} expanded={new Set()} toggle={noop} showHost={noop} openAiSettings={noop}
    />);
    expect(failed).toContain("AI activity could not be loaded.");
    expect(failed).toContain("Retry");
  });

  it("a deleted host keeps its recorded name and disables Show host", () => {
    const gone = [entry({ host_id: "0000000000000009", alias: "old-web" })];
    const html = render(gone, { expanded: expandedAll(gone) });
    expect(text(html)).toContain("Ran a command on old-web");
    expect(html).not.toMatch(/<button[^>]*>old-web<\/button>/);
    expect(buttonBefore(html, "Show host")).toContain('disabled=""');
    expect(html).toContain("This host is no longer in your library.");

    const renamed = [entry({ alias: "web-old" })];
    const current = render(renamed, { expanded: expandedAll(renamed) });
    expect(current).toMatch(/<option value="0000000000000001"[^>]*>web-1<\/option>/);
    expect(current).toMatch(/<button[^>]*>web-old<\/button>/);
    expect(buttonBefore(current, "Show host")).not.toContain('disabled=""');
  });

  it("reveals hidden characters in every recorded string", () => {
    const hidden = "‮";
    const entries = [
      entry({
        id: "a", alias: `web${hidden}-1`, command: `echo ${hidden}ok`, requested_by: [`Term${hidden}inal`], requester_id: `4${hidden}2`,
        outcome: "error", ended: null, exit_code: null, review: "auto_log", stop: { kind: "error", window: null, reason: `failed ${hidden} here` },
      }),
      entry({ id: "b", outcome: "tunnel_started", command: "", tunnel: `Data${hidden}base`, review: "auto_log" }),
    ];
    const html = render(entries, { expanded: expandedAll(entries) });
    expect(html).not.toContain(hidden);
    for (const revealed of [`web⟨U+202E⟩-1`, `echo ⟨U+202E⟩ok`, `Term⟨U+202E⟩inal`, `failed ⟨U+202E⟩ here`, `Data⟨U+202E⟩base`]) {
      expect(html).toContain(revealed);
    }
  });

  it("shows the audit error", () => {
    const html = renderToStaticMarkup(<AiActivityView
      data={{ revision: 1, entries: [entry()], audit_error: "Audit file unavailable" }} pending={false} error={null} retry={noop}
      overview={overview} now={NOW} filters={NO_FILTERS} setFilters={noop}
      shown={100} showMore={noop} expanded={new Set()} toggle={noop} showHost={noop} openAiSettings={noop}
    />);
    expect(html).toMatch(/role="alert"/);
    expect(text(html)).toContain("Audit persistence error: Audit file unavailable. Completed commands are not retried.");
  });

  it("impossible times read Time unavailable", () => {
    const impossible = [entry({ at_ms: 0, completed_at_ms: Number.MAX_SAFE_INTEGER })];
    const html = render(impossible, { expanded: expandedAll(impossible) });
    expect(html).toContain("Time unavailable");
    expect(html).not.toContain("Invalid Date");
    expect(html).not.toContain("1970");
    expect(html).not.toContain("<time");
  });
});
