import { QueryClient } from "@tanstack/react-query";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { McpActivityLog } from "@/bindings/McpActivityLog";
import type { McpAuditEntry } from "@/bindings/McpAuditEntry";
import type { McpStop } from "@/bindings/McpStop";
import type { McpStopKind } from "@/bindings/McpStopKind";
import type { McpWindow } from "@/bindings/McpWindow";
import {
  actionKind, activityResult, activityTitle, dayLabel, durationLabel, groupByDay, hostKey, kindCounts, matchesFilters, NO_FILTERS,
  observedClient, resultSentence, reviewLabel, reviewSentence, titleText,
  type ActivityFilters, type ActivityKind,
} from "./mcp-activity";
import { fetchMcpActivity, mcpActivityKey, mergeActivity, type McpActivityData } from "./mcp";
import { stubBackend } from "./test-ipc";

const NOW = new Date(2026, 10, 10, 15).getTime();
const CLAUDE = ["Terminal", "claude"];
const CODEX = ["Code Helper", "codex"];

function entry(patch: Partial<McpAuditEntry> = {}): McpAuditEntry {
  return {
    id: "request-1", client: "mcp", host_id: "0000000000000001", alias: "web-1", command: "uptime", mode: "ask",
    requested_by: CLAUDE, requester_id: "42", client_info: { name: null, title: null, version: null },
    at_ms: NOW - 60_000, completed_at_ms: NOW - 59_000,
    outcome: "allowed", ended: "exited", exit_code: 0, signal: null, detail: null,
    review: "approved", stop: null, tunnel: null,
    ...patch,
  };
}
const stop = (kind: McpStopKind, window: McpWindow | null = null): McpStop => ({ kind, window, reason: "fixture reason" });
/** An entry written before review and stop were recorded. */
const older = (patch: Partial<McpAuditEntry>) => entry({ review: null, stop: null, ended: null, exit_code: null, ...patch });

beforeEach(() => {
  vi.spyOn(Date, "now").mockReturnValue(NOW);
});
afterEach(() => {
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});

describe("AI activity results", () => {
  it.each([
    [{ stop: stop("refused", "approval") }, "not_run", "Refused by you"],
    [{ stop: stop("no_answer", "server_key") }, "not_run", "No answer"],
    [{ stop: stop("canceled") }, "not_run", "Canceled"],
    [{ stop: stop("not_allowed") }, "not_run", "Not allowed"],
    [{ stop: stop("error"), outcome: "error", ended: null, exit_code: null }, "error", "Error"],
    [{ stop: stop("refused", "approval"), outcome: "host_creation_not_completed", command: "" }, "not_run", "Refused by you"],
    [{ outcome: "host_created", command: "" }, "succeeded", "Host created"],
    [{ outcome: "host_updated", command: "" }, "succeeded", "Host updated"],
    [{ outcome: "host_key_verified", command: "" }, "succeeded", "Fingerprint verified"],
    [{ outcome: "transport_set", command: "" }, "succeeded", "Route saved"],
    [{ outcome: "transport_removed", command: "" }, "succeeded", "Route removed"],
    [{ outcome: "tunnel_created", command: "" }, "succeeded", "Tunnel created"],
    [{ outcome: "tunnel_updated", command: "" }, "succeeded", "Tunnel updated"],
    [{ outcome: "tunnel_deleted", command: "" }, "succeeded", "Tunnel deleted"],
    [{ outcome: "tunnel_started", command: "" }, "succeeded", "Tunnel started"],
    [{ outcome: "tunnel_stopped", command: "" }, "succeeded", "Tunnel stopped"],
    ...[
      "host_creation_not_completed", "host_update_not_completed", "host_key_not_verified", "transport_not_set", "transport_not_removed",
      "tunnel_not_created", "tunnel_not_updated", "tunnel_not_deleted", "tunnel_not_started",
    ].map(outcome => [older({ outcome, command: "" }), "not_run", "Not completed"] as const),
    [{ ended: "canceled", exit_code: null }, "failed", "Canceled while running"],
    [{ outcome: "canceled", ended: "canceled", exit_code: null }, "failed", "Canceled while running"],
    [{ ended: "timed_out", exit_code: null }, "failed", "Timed out"],
    [{ ended: "truncated", exit_code: 0 }, "failed", "Output limit reached"],
    [{ ended: "disconnected", exit_code: null }, "failed", "Connection lost"],
    [{ ended: "signaled", signal: "TERM", exit_code: null }, "failed", "Stopped by signal"],
    [{ ended: "exited", signal: "KILL", exit_code: null }, "failed", "Stopped by signal"],
    [{ exit_code: 2 }, "failed", "Failed · exit 2"],
    [{}, "succeeded", "Succeeded"],
    [{ exit_code: null }, "unknown", "Result unavailable"],
    [{ ended: null, exit_code: null }, "unknown", "Result unavailable"],
    [older({ outcome: "canceled", ended: "exited", exit_code: 0 }), "not_run", "Canceled"],
    [older({ outcome: "denied" }), "not_run", "Denied"],
    [older({ outcome: "timed_out" }), "not_run", "Timed out"],
    [older({ outcome: "error" }), "error", "Error"],
    [older({ outcome: "failed" }), "failed", "Failed"],
    [{ outcome: "a_future_outcome" }, "unknown", "Result unavailable"],
  ] satisfies (readonly [Partial<McpAuditEntry>, ActivityKind, string])[])("maps every recorded result to its kind and label: %j", (patch, kind, label) => {
    expect(activityResult(entry(patch))).toEqual({ kind, label });
  });

  it.each([
    ["allowed", "command"], ["error", "command"], ["a_future_outcome", "command"],
    ["tunnel_started", "tunnel"], ["tunnel_not_deleted", "tunnel"], ["tunnel_stopped", "tunnel"],
    ["host_key_verified", "server_key"], ["host_key_not_verified", "server_key"],
    ["host_created", "change"], ["host_creation_not_completed", "change"], ["host_updated", "change"], ["host_update_not_completed", "change"],
    ["transport_set", "change"], ["transport_not_removed", "change"],
  ])("files %s under %s", (outcome, kind) => {
    expect(actionKind(entry({ outcome }))).toBe(kind);
  });
});

describe("AI activity titles", () => {
  it("titles name the action, the host and the tunnel", () => {
    const command = entry();
    expect(activityTitle(command, "succeeded")).toEqual({ before: "Ran a command on ", host: "web-1", after: "" });
    expect(activityTitle(command, "failed").before).toBe("Ran a command on ");
    expect(activityTitle(command, "unknown").before).toBe("Ran a command on ");
    expect(activityTitle(command, "not_run").before).toBe("Asked to run a command on ");
    expect(activityTitle(command, "error").before).toBe("Could not run a command on ");
    const started = entry({ outcome: "tunnel_started", command: "", tunnel: "Database" });
    expect(activityTitle(started, "succeeded")).toEqual({ before: "Started tunnel Database through ", host: "web-1", after: "" });
    const beforeTunnelNames = entry({ outcome: "tunnel_started", command: "", alias: "web-1 · Database", tunnel: null });
    expect(activityTitle(beforeTunnelNames, "succeeded")).toEqual({ before: "Started tunnel ", host: "web-1 · Database", after: "" });
    const proposed = entry({ outcome: "host_creation_not_completed", alias: "db-replica", command: "", review: null, stop: stop("refused", "approval") });
    const title = activityTitle(proposed, activityResult(proposed).kind);
    expect(title).toEqual({ before: "Proposed a new host ", host: "db-replica", after: "" });
    expect(titleText(title)).toBe("Proposed a new host db-replica");
  });

  it.each([
    ["host_created", "Created host web-1", "Proposed a new host web-1", "Could not create host web-1"],
    ["host_update_not_completed", "Updated host web-1", "Proposed changes to host web-1", "Could not update host web-1"],
    ["transport_set", "Saved the route of web-1", "Proposed a route for web-1", "Could not save the route of web-1"],
    ["transport_not_removed", "Removed the route of web-1", "Proposed removing the route of web-1", "Could not remove the route of web-1"],
    ["tunnel_not_created", "Created tunnel Database through web-1", "Proposed tunnel Database through web-1", "Could not create tunnel Database through web-1"],
    ["tunnel_updated", "Updated tunnel Database through web-1", "Proposed changes to tunnel Database through web-1", "Could not update tunnel Database through web-1"],
    ["tunnel_deleted", "Deleted tunnel Database through web-1", "Proposed deleting tunnel Database through web-1", "Could not delete tunnel Database through web-1"],
    ["tunnel_not_started", "Started tunnel Database through web-1", "Asked to start tunnel Database through web-1", "Could not start tunnel Database through web-1"],
    ["tunnel_stopped", "Stopped tunnel Database through web-1", "Stopped tunnel Database through web-1", "Stopped tunnel Database through web-1"],
    ["host_key_not_verified", "Verified the server key of web-1", "Asked to verify the server key of web-1", "Could not verify the server key of web-1"],
  ])("titles %s by its result", (outcome, done, notRun, error) => {
    const row = entry({ outcome, command: "", tunnel: outcome.startsWith("tunnel_") ? "Database" : null });
    expect(titleText(activityTitle(row, "succeeded"))).toBe(done);
    expect(titleText(activityTitle(row, "not_run"))).toBe(notRun);
    expect(titleText(activityTitle(row, "error"))).toBe(error);
  });
});

describe("AI activity review and result sentences", () => {
  it("review labels follow the review, and older entries show their mode", () => {
    expect(reviewLabel(entry({ review: "approved" }))).toBe("Approved by you");
    expect(reviewLabel(entry({ review: "refused" }))).toBe("Refused by you");
    expect(reviewLabel(entry({ review: "no_answer" }))).toBe("No answer");
    expect(reviewLabel(entry({ review: "auto_log", mode: "auto_log" }))).toBe("Auto-log");
    expect(reviewLabel(entry({ review: "not_asked" }))).toBeNull();
    expect(reviewLabel(older({ mode: "auto_log" }))).toBe("Auto-log mode");
    expect(reviewLabel(older({ mode: "ask" }))).toBe("Ask mode");
    expect(reviewLabel(entry({ review: null, stop: stop("canceled", "approval") }))).toBeNull();
  });

  it("review sentences say who decided, and when nobody did", () => {
    expect(reviewSentence(entry({ review: "approved" }))).toBe("You approved it in Lunport’s window.");
    expect(reviewSentence(entry({ review: "refused" }))).toBe("You refused it in Lunport’s window.");
    expect(reviewSentence(entry({ review: "no_answer" }))).toBe("Lunport’s window got no answer.");
    expect(reviewSentence(entry({ review: "auto_log", mode: "auto_log" }))).toBe("Auto-log: ran without per-command review.");
    expect(reviewSentence(entry({ review: "auto_log", mode: "auto_log", outcome: "tunnel_started", tunnel: "Database" }))).toBe("Auto-log: started without per-tunnel review.");
    expect(reviewSentence(entry({ review: "not_asked", outcome: "tunnel_stopped" }))).toBe("This action has no approval step.");
    expect(reviewSentence(entry({ review: null, stop: stop("canceled", "approval") }))).toBe("It stopped before its review.");
    expect(reviewSentence(older({ mode: "ask" }))).toBe("Recorded in Ask mode.");
    expect(reviewSentence(older({ mode: "auto_log" }))).toBe("Recorded in Auto-log mode.");
  });

  it.each([
    [{}, "Ran and exited with code 0."],
    [{ exit_code: 2 }, "Ran and exited with code 2."],
    [{ ended: "signaled", signal: "TERM", exit_code: null }, "Ran and was stopped by signal TERM."],
    [{ ended: "signaled", signal: null, exit_code: null }, "Ran and was stopped by a signal."],
    [{ ended: "timed_out", exit_code: null }, "Ran until its time limit and was stopped."],
    [{ ended: "truncated", exit_code: 0 }, "Ran until the output limit and was stopped."],
    [{ ended: "disconnected", exit_code: null }, "Ran, then the connection was lost."],
    [{ outcome: "canceled", ended: "canceled", exit_code: null }, "Ran, then the request was canceled."],
    [{ exit_code: null }, "No exit status was recorded."],
    [{ stop: stop("not_allowed"), review: null }, "This host is not allowed for AI access."],
    [{ stop: stop("refused", "approval") }, "Refused by you in the approval window."],
    [{ stop: stop("no_answer", "server_key") }, "No answer in the server key window."],
    [{ stop: stop("refused", "credentials") }, "Refused by you in the credentials window."],
    [{ stop: stop("no_answer", "grant") }, "No answer in the Request a grant window."],
    [{ stop: stop("canceled") }, "Canceled."],
    [{ stop: stop("error") }, "Error."],
    [{ outcome: "tunnel_started", command: "", tunnel: "Database" }, "Tunnel started."],
    [older({ outcome: "tunnel_not_started", command: "" }), "Not completed."],
    [older({ outcome: "denied" }), "Denied."],
  ] satisfies [Partial<McpAuditEntry>, string][])("result sentence for %j", (patch, sentence) => {
    const row = entry(patch);
    expect(resultSentence(row, activityResult(row))).toBe(sentence);
  });
});

describe("AI activity times", () => {
  it("durations need two times in order", () => {
    const took = (at_ms: number, completed_at_ms: number) => durationLabel(entry({ at_ms, completed_at_ms }));
    expect(took(0, 5000)).toBeNull();
    expect(took(5000, 5000)).toBeNull();
    expect(took(5000, 4000)).toBeNull();
    expect(took(NOW, NOW + 800)).toBe("took 0.8 s");
    expect(took(NOW, NOW + 12_400)).toBe("took 12 s");
    expect(took(NOW, NOW + 125_000)).toBe("took 2 min 5 s");
    expect(took(NOW, NOW + 50)).toBe("took under 0.1 s");
  });

  it("days read Today, Yesterday, then the date, and never invent a time", () => {
    expect(dayLabel(new Date(2026, 10, 10, 0, 5).getTime(), NOW)).toBe("Today");
    expect(dayLabel(new Date(2026, 10, 9, 23, 59).getTime(), NOW)).toBe("Yesterday");
    const earlier = new Date(2026, 10, 7, 12).getTime();
    expect(dayLabel(earlier, NOW)).toBe(new Date(earlier).toLocaleDateString(undefined, { weekday: "short", month: "short", day: "numeric" }));
    const lastYear = new Date(2025, 10, 7, 12).getTime();
    expect(dayLabel(lastYear, NOW)).toBe(new Date(lastYear).toLocaleDateString(undefined, { weekday: "short", month: "short", day: "numeric", year: "numeric" }));
    expect(dayLabel(0, NOW)).toBe("Time unavailable");
    expect(dayLabel(Number.MAX_SAFE_INTEGER, NOW)).toBe("Time unavailable");
  });

  it("groups consecutive rows by their day, newest first", () => {
    const at = [new Date(2026, 10, 10, 14).getTime(), new Date(2026, 10, 10, 9).getTime(), new Date(2026, 10, 9, 20).getTime(), 0];
    const groups = groupByDay(at, ms => ms, NOW);
    expect(groups.map(group => [group.label, group.rows.length])).toEqual([["Today", 2], ["Yesterday", 1], ["Time unavailable", 1]]);
  });
});

describe("AI activity filters", () => {
  const rows = [
    entry({ id: "a", command: "uptime" }),
    entry({ id: "b", command: "df -h", exit_code: 1 }),
    entry({ id: "c", outcome: "tunnel_not_started", command: "", tunnel: "Database", stop: stop("refused", "approval"), review: "refused" }),
    entry({ id: "d", host_id: "0000000000000002", alias: "db-replica", requested_by: CODEX, command: "systemctl status nginx", outcome: "error", ended: null, exit_code: null, stop: stop("error") }),
    entry({ id: "e", host_id: "0000000000000002", alias: "db-replica", requested_by: CODEX, outcome: "host_key_verified", command: "", review: "not_asked" }),
    entry({ id: "f", host_id: "0000000000000002", alias: "db-replica", outcome: "host_updated", command: "" }),
  ];
  const ids = (filters: Partial<ActivityFilters>) => rows.filter(row => matchesFilters(row, { ...NO_FILTERS, ...filters })).map(row => row.id);

  it("filters combine and chip counts ignore only the result", () => {
    expect(ids({})).toEqual(["a", "b", "c", "d", "e", "f"]);
    expect(ids({ client: "Code Helper → codex" })).toEqual(["d", "e"]);
    expect(ids({ host: "0000000000000002" })).toEqual(["d", "e", "f"]);
    expect(ids({ action: "command" })).toEqual(["a", "b", "d"]);
    expect(ids({ action: "tunnel" })).toEqual(["c"]);
    expect(ids({ action: "change" })).toEqual(["f"]);
    expect(ids({ action: "server_key" })).toEqual(["e"]);
    expect(ids({ kind: "succeeded" })).toEqual(["a", "e", "f"]);
    expect(ids({ kind: "failed" })).toEqual(["b"]);
    expect(ids({ kind: "not_run" })).toEqual(["c"]);
    expect(ids({ kind: "error" })).toEqual(["d"]);
    expect(ids({ host: "0000000000000002", kind: "succeeded" })).toEqual(["e", "f"]);
    expect(ids({ client: "Terminal → claude", action: "command" })).toEqual(["a", "b"]);
    expect(ids({ search: "  DF " })).toEqual(["b"]);
    expect(ids({ search: "database" })).toEqual(["c"]);
    expect(ids({ search: "codex" })).toEqual(["d", "e"]);
    expect(ids({ search: "verified the server key" })).toEqual(["e"]);
    expect(ids({ search: "db-replica", kind: "error" })).toEqual(["d"]);
    expect(kindCounts(rows, { ...NO_FILTERS, host: "0000000000000002", kind: "failed" }))
      .toEqual({ all: 3, succeeded: 2, failed: 0, not_run: 0, error: 1, unknown: 0 });
  });

  it("names the client as Lunport observed it and the host by its id", () => {
    expect(observedClient(entry({ requested_by: ["Terminal", "Unknown", "claude"] }))).toBe("Terminal → claude");
    expect(observedClient(entry({ requested_by: ["Unknown"] }))).toBe("An unidentified AI client");
    expect(observedClient(entry({ requested_by: [] }))).toBe("An unidentified AI client");
    expect(hostKey(entry())).toBe("0000000000000001");
    expect(hostKey(entry({ host_id: null, alias: "web-1" }))).toBe("alias:web-1");
  });
});

describe("AI activity query", () => {
  const data = (patch: Partial<McpActivityData> = {}): McpActivityData => ({ revision: 4, entries: [entry()], audit_error: null, ...patch });

  it("merging an unchanged answer keeps the same object", () => {
    const previous = data();
    expect(mergeActivity(previous, { revision: 4, entries: null, audit_error: null })).toBe(previous);
    const failing = mergeActivity(previous, { revision: 4, entries: null, audit_error: "Audit file unavailable" });
    expect(failing).not.toBe(previous);
    expect(failing).toEqual({ revision: 4, entries: previous.entries, audit_error: "Audit file unavailable" });
    const next = [entry({ id: "request-2" }), entry()];
    expect(mergeActivity(previous, { revision: 5, entries: next, audit_error: null })).toEqual({ revision: 5, entries: next, audit_error: null });
    expect(mergeActivity(undefined, { revision: 2, entries: null, audit_error: "Audit file unavailable" }))
      .toEqual({ revision: 2, entries: [], audit_error: "Audit file unavailable" });
  });

  it("asks only for what changed since the revision it holds", async () => {
    const answers: McpActivityLog[] = [
      { revision: 4, entries: [entry()], audit_error: null },
      { revision: 4, entries: null, audit_error: null },
    ];
    const calls = stubBackend(async () => answers.shift());
    const client = new QueryClient();
    const first = await fetchMcpActivity(client);
    client.setQueryData(mcpActivityKey, first);
    const second = await fetchMcpActivity(client);
    expect(calls).toEqual([["mcp_activity", { since: null }], ["mcp_activity", { since: 4 }]]);
    expect(second).toBe(first);
  });
});
