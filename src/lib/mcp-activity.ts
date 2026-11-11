import type { McpAuditEntry } from "@/bindings/McpAuditEntry";
import type { McpReview } from "@/bindings/McpReview";
import type { McpStopKind } from "@/bindings/McpStopKind";
import type { McpWindow } from "@/bindings/McpWindow";

/** What became of an AI request, as the AI activity page sorts it; "unknown" is counted under All only. */
export type ActivityKind = "succeeded" | "failed" | "not_run" | "error" | "unknown";
/** The kinds of action the page filters by. */
export type ActionKind = "command" | "transfer" | "tunnel" | "database" | "change" | "server_key";

export interface ActivityResult { kind: ActivityKind; label: string }
/** A row's title, the host apart from the words around it. */
export interface ActivityTitle { before: string; host: string; after: string }
export interface ActivityFilters {
  search: string;
  client: string | null;
  host: string | null;
  action: ActionKind | null;
  kind: ActivityKind | "all";
}

export const NO_FILTERS: ActivityFilters = { search: "", client: null, host: null, action: null, kind: "all" };

const SUCCEEDED: ActivityResult = { kind: "succeeded", label: "Succeeded" };
const UNKNOWN: ActivityResult = { kind: "unknown", label: "Result unavailable" };
/** A tunnel or a database still connecting when its start answered: how it went is not recorded, and the page that lists them shows it. */
const STARTING = new Map([["tunnel_starting", "Tunnels"], ["database_starting", "Databases"]]);
const STILL_CONNECTING: ActivityResult = { kind: "unknown", label: "Still connecting" };
const NO_EXIT = "No exit status was recorded.";

const STOPS: Record<McpStopKind, ActivityResult> = {
  refused: { kind: "not_run", label: "Refused by you" },
  no_answer: { kind: "not_run", label: "No answer" },
  canceled: { kind: "not_run", label: "Canceled" },
  not_allowed: { kind: "not_run", label: "Not allowed" },
  error: { kind: "error", label: "Error" },
};

/** The connection management outcomes that succeeded, by their label. */
const DONE = new Map([
  ["scp_uploaded", "Uploaded"], ["scp_downloaded", "Downloaded"],
  ["host_created", "Host created"], ["host_updated", "Host updated"], ["host_key_verified", "Fingerprint verified"],
  ["transport_set", "Route saved"], ["transport_removed", "Route removed"],
  ["tunnel_created", "Tunnel created"], ["tunnel_updated", "Tunnel updated"], ["tunnel_deleted", "Tunnel deleted"],
  ["tunnel_started", "Tunnel started"], ["tunnel_stopped", "Tunnel stopped"],
  ["database_created", "Database created"], ["database_updated", "Database updated"], ["database_deleted", "Database deleted"],
  ["database_started", "Database started"], ["database_stopped", "Database stopped"],
]);
/** The connection management outcomes that did not complete. */
const NOT_DONE = new Set([
  "scp_not_uploaded", "scp_not_downloaded",
  "host_creation_not_completed", "host_update_not_completed", "host_key_not_verified", "transport_not_set", "transport_not_removed",
  "tunnel_not_created", "tunnel_not_updated", "tunnel_not_deleted", "tunnel_not_started",
  "database_not_created", "database_not_updated", "database_not_deleted", "database_not_started",
]);
/** What an entry from before review and stop were recorded says when nothing ran; a command's own end is recorded as `allowed`. */
const OLDER = new Map<string, ActivityResult>([
  ["canceled", { kind: "not_run", label: "Canceled" }],
  ["denied", { kind: "not_run", label: "Denied" }],
  ["timed_out", { kind: "not_run", label: "Timed out" }],
  ["error", { kind: "error", label: "Error" }],
  ["failed", { kind: "failed", label: "Failed" }],
]);
const CHANGES = new Set(["host_created", "host_creation_not_completed", "host_updated", "host_update_not_completed"]);

/** Whether the entry is of a command that ran: its end is what it records. A request canceled once its command was sent records how
 * the command ended (`canceled`, or its own end when the cancel came after it), and only then. */
function ranCommand(entry: McpAuditEntry): boolean {
  return entry.outcome === "allowed" || (entry.outcome === "canceled" && entry.ended != null);
}

/** How a command that ran ended, and the sentence that says so. */
function ending(entry: McpAuditEntry): { result: ActivityResult; sentence: string } {
  const failed = (label: string, sentence: string) => ({ result: { kind: "failed" as const, label }, sentence });
  if (entry.ended === "canceled") return failed("Canceled while running", "Ran, then the request was canceled.");
  if (entry.ended === "timed_out") return failed("Timed out", "Ran until its time limit and was stopped.");
  if (entry.ended === "truncated") return failed("Output limit reached", "Ran until the output limit and was stopped.");
  if (entry.ended === "disconnected") return failed("Connection lost", "Ran, then the connection was lost.");
  if (entry.ended === "signaled" || entry.signal) {
    return failed("Stopped by signal", entry.signal ? `Ran and was stopped by signal ${entry.signal}.` : "Ran and was stopped by a signal.");
  }
  if (entry.exit_code != null && entry.exit_code !== 0) return failed(`Failed · exit ${entry.exit_code}`, `Ran and exited with code ${entry.exit_code}.`);
  if (entry.ended === "exited" && entry.exit_code === 0) return { result: SUCCEEDED, sentence: "Ran and exited with code 0." };
  return { result: UNKNOWN, sentence: NO_EXIT };
}

/** What became of the request: what stopped it, else what it recorded. Nothing is inferred from a missing exit status. */
export function activityResult(entry: McpAuditEntry): ActivityResult {
  if (entry.stop) return STOPS[entry.stop.kind] ?? UNKNOWN;
  if (STARTING.has(entry.outcome)) return STILL_CONNECTING;
  const done = DONE.get(entry.outcome);
  if (done) return { kind: "succeeded", label: done };
  if (NOT_DONE.has(entry.outcome)) return { kind: "not_run", label: "Not completed" };
  if (ranCommand(entry)) return ending(entry).result;
  return OLDER.get(entry.outcome) ?? UNKNOWN;
}

export function actionKind(entry: McpAuditEntry): ActionKind {
  if (entry.outcome.startsWith("scp_")) return "transfer";
  if (entry.outcome.startsWith("tunnel_")) return "tunnel";
  if (entry.outcome.startsWith("database_")) return "database";
  if (entry.outcome.startsWith("host_key_")) return "server_key";
  if (entry.outcome.startsWith("transport_") || CHANGES.has(entry.outcome)) return "change";
  return "command";
}

/** Title words before the host: when it was done (succeeded, failed or unknown), when it did not run, and when it was an error. */
type Columns = readonly [string, string, string];
const both = (done: string, notDone: string, columns: Columns): [string, Columns][] => [[done, columns], [notDone, columns]];
const HOST_TITLES = new Map<string, Columns>([
  ...both("host_created", "host_creation_not_completed", ["Created host ", "Proposed a new host ", "Could not create host "]),
  ...both("host_updated", "host_update_not_completed", ["Updated host ", "Proposed changes to host ", "Could not update host "]),
  ...both("transport_set", "transport_not_set", ["Saved the route of ", "Proposed a route for ", "Could not save the route of "]),
  ...both("transport_removed", "transport_not_removed", ["Removed the route of ", "Proposed removing the route of ", "Could not remove the route of "]),
  ...both("host_key_verified", "host_key_not_verified", ["Verified the server key of ", "Asked to verify the server key of ", "Could not verify the server key of "]),
]);
/** The verb before "tunnel" or "database", by the same columns. */
const NAMED_VERBS = new Map<string, Columns>([
  ...both("tunnel_created", "tunnel_not_created", ["Created", "Proposed", "Could not create"]),
  ...both("tunnel_updated", "tunnel_not_updated", ["Updated", "Proposed changes to", "Could not update"]),
  ...both("tunnel_deleted", "tunnel_not_deleted", ["Deleted", "Proposed deleting", "Could not delete"]),
  ...both("tunnel_started", "tunnel_not_started", ["Started", "Asked to start", "Could not start"]),
  ["tunnel_starting", ["Starting", "Asked to start", "Could not start"]],
  ["tunnel_stopped", ["Stopped", "Stopped", "Stopped"]],
  ...both("database_created", "database_not_created", ["Created", "Proposed", "Could not create"]),
  ...both("database_updated", "database_not_updated", ["Updated", "Proposed changes to", "Could not update"]),
  ...both("database_deleted", "database_not_deleted", ["Deleted", "Proposed deleting", "Could not delete"]),
  ...both("database_started", "database_not_started", ["Started", "Asked to start", "Could not start"]),
  ["database_starting", ["Starting", "Asked to start", "Could not start"]],
  ["database_stopped", ["Stopped", "Stopped", "Stopped"]],
]);
const COMMAND_TITLES: Columns = ["Ran a command on ", "Asked to run a command on ", "Could not run a command on "];
const UPLOAD_TITLES: Columns = ["Uploaded a file to ", "Asked to upload a file to ", "Could not upload a file to "];
const DOWNLOAD_TITLES: Columns = ["Downloaded a file from ", "Asked to download a file from ", "Could not download a file from "];

/** What the request was, by what became of it (`kind`). An entry from before tunnels were named apart has the tunnel in its alias; a
 * database on its public IP is reached through no host, so its title ends with its name. */
export function activityTitle(entry: McpAuditEntry, kind: ActivityKind): ActivityTitle {
  const column = kind === "not_run" ? 1 : kind === "error" ? 2 : 0;
  const verbs = NAMED_VERBS.get(entry.outcome);
  if (verbs && actionKind(entry) === "database") {
    const named = `${verbs[column]} database${entry.database ? ` ${entry.database}` : ""}`;
    return entry.host_id ? { before: `${named} through `, host: entry.alias, after: "" } : { before: named, host: "", after: "" };
  }
  if (verbs) {
    const before = entry.tunnel ? `${verbs[column]} tunnel ${entry.tunnel} through ` : `${verbs[column]} tunnel `;
    return { before, host: entry.alias, after: "" };
  }
  if (entry.outcome === "scp_uploaded" || entry.outcome === "scp_not_uploaded") {
    return { before: UPLOAD_TITLES[column], host: entry.alias, after: "" };
  }
  if (entry.outcome === "scp_downloaded" || entry.outcome === "scp_not_downloaded") {
    return { before: DOWNLOAD_TITLES[column], host: entry.alias, after: "" };
  }
  return { before: (HOST_TITLES.get(entry.outcome) ?? COMMAND_TITLES)[column], host: entry.alias, after: "" };
}

export function titleText(title: ActivityTitle): string {
  return `${title.before}${title.host}${title.after}`;
}

const REVIEW_LABELS: Record<McpReview, string | null> = {
  approved: "Approved by you", refused: "Refused by you", no_answer: "No answer", auto_log: "Auto-log", not_asked: null,
};

/** How the request was reviewed, for its row; an entry from before reviews were recorded shows its mode. */
export function reviewLabel(entry: McpAuditEntry): string | null {
  if (entry.review) return REVIEW_LABELS[entry.review] ?? null;
  if (entry.stop) return null;
  return entry.mode === "auto_log" ? "Auto-log mode" : "Ask mode";
}

export function reviewSentence(entry: McpAuditEntry): string {
  switch (entry.review) {
    case "approved": return "You approved it in Lunport’s window.";
    case "refused": return "You refused it in Lunport’s window.";
    case "no_answer": return "Lunport’s window got no answer.";
    case "auto_log":
      return actionKind(entry) === "tunnel" ? "Auto-log: started without per-tunnel review."
        : actionKind(entry) === "database" ? "Auto-log: started without per-database review."
        : actionKind(entry) === "transfer" ? "Auto-log: transferred without per-transfer review."
        : "Auto-log: ran without per-command review.";
    case "not_asked": return "This action has no approval step.";
  }
  if (entry.stop) return "It stopped before its review.";
  return entry.mode === "auto_log" ? "Recorded in Auto-log mode." : "Recorded in Ask mode.";
}

const WINDOWS: Record<McpWindow, string> = {
  approval: "the approval window",
  server_key: "the server key window",
  credentials: "the credentials window",
  sudo: "the sudo authorization window",
  grant: "the Request a grant window",
};

/** What happened, in a sentence: how a command that ran ended, or what stopped the request and in which of Lunport's windows. */
export function resultSentence(entry: McpAuditEntry, result: ActivityResult): string {
  if (entry.stop) {
    if (entry.stop.kind === "not_allowed") return "This host is not allowed for AI access.";
    const where = entry.stop.window ? WINDOWS[entry.stop.window] : undefined;
    return where ? `${result.label} in ${where}.` : `${result.label}.`;
  }
  const page = STARTING.get(entry.outcome);
  if (page) return `Still connecting when Lunport answered; the ${page} page shows how it went.`;
  if (ranCommand(entry)) return ending(entry).sentence;
  if (result.kind === "unknown") return NO_EXIT;
  return `${result.label}.`;
}

/** How long the request took, from its request to its completion; `null` unless both times are known, can be dates and are in order. */
export function durationLabel(entry: McpAuditEntry): string | null {
  const { at_ms: at, completed_at_ms: completed } = entry;
  if (!(at > 0) || !(completed > at) || !Number.isFinite(new Date(completed).getTime())) return null;
  const ms = completed - at;
  if (ms < 100) return "took under 0.1 s";
  if (ms < 10_000) return `took ${(ms / 1000).toFixed(1)} s`;
  const seconds = Math.round(ms / 1000);
  return seconds < 60 ? `took ${seconds} s` : `took ${Math.floor(seconds / 60)} min ${seconds % 60} s`;
}

/** The AI client as Lunport observed it (the requester chain), never what the client says of itself. */
export function observedClient(entry: McpAuditEntry): string {
  const observed = entry.requested_by.filter(name => name !== "Unknown");
  return observed.length > 0 ? observed.join(" → ") : "An unidentified AI client";
}

/** What the host filter tells hosts apart by: the host's id, or the alias of an entry that recorded none. */
export function hostKey(entry: McpAuditEntry): string {
  return entry.host_id ?? `alias:${entry.alias}`;
}

/** Whether the entry names a host, by its id or only by its alias. A database on its public IP is reached through none: its entry
 * records no host id and an empty alias, so there is no host to filter by, show or give an id for. */
export function namesHost(entry: McpAuditEntry): boolean {
  return entry.host_id != null || entry.alias !== "";
}

const sameDay = (a: Date, b: Date) => a.getFullYear() === b.getFullYear() && a.getMonth() === b.getMonth() && a.getDate() === b.getDate();

/** The local day of `ms` as a heading: Today, Yesterday, else the date (with its year when it is another year's). */
export function dayLabel(ms: number, now: number): string {
  const date = new Date(ms);
  if (!(ms > 0) || !Number.isFinite(date.getTime())) return "Time unavailable";
  const today = new Date(now);
  if (sameDay(date, today)) return "Today";
  if (sameDay(date, new Date(today.getFullYear(), today.getMonth(), today.getDate() - 1))) return "Yesterday";
  const year = date.getFullYear() === today.getFullYear() ? {} : { year: "numeric" as const };
  return date.toLocaleDateString(undefined, { weekday: "short", month: "short", day: "numeric", ...year });
}

/** Consecutive rows of the same day (`at`) under that day's heading; the rows are newest first already. */
export function groupByDay<T>(rows: readonly T[], at: (row: T) => number, now: number): { label: string; rows: T[] }[] {
  const groups: { label: string; rows: T[] }[] = [];
  for (const row of rows) {
    const label = dayLabel(at(row), now);
    const last = groups[groups.length - 1];
    if (last?.label === label) last.rows.push(row);
    else groups.push({ label, rows: [row] });
  }
  return groups;
}

/** Whether the entry passes every filter (the result chip too, unless `ignoreKind`). */
export function matchesFilters(entry: McpAuditEntry, filters: ActivityFilters, ignoreKind = false): boolean {
  if (filters.client !== null && observedClient(entry) !== filters.client) return false;
  if (filters.host !== null && hostKey(entry) !== filters.host) return false;
  if (filters.action !== null && actionKind(entry) !== filters.action) return false;
  const { kind } = activityResult(entry);
  if (!ignoreKind && filters.kind !== "all" && kind !== filters.kind) return false;
  const search = filters.search.trim().toLowerCase();
  if (!search) return true;
  const fields = [entry.command, entry.alias, entry.tunnel ?? "", entry.database ?? "", observedClient(entry), titleText(activityTitle(entry, kind))];
  return fields.some(field => field.toLowerCase().includes(search));
}

/** The number of entries under each result chip, with every other filter applied. */
export function kindCounts(entries: readonly McpAuditEntry[], filters: ActivityFilters): Record<ActivityKind | "all", number> {
  const counts: Record<ActivityKind | "all", number> = { all: 0, succeeded: 0, failed: 0, not_run: 0, error: 0, unknown: 0 };
  for (const entry of entries) {
    if (!matchesFilters(entry, filters, true)) continue;
    counts.all += 1;
    counts[activityResult(entry).kind] += 1;
  }
  return counts;
}
