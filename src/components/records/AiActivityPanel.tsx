import "./ai-activity.css";
import { useMemo, useState } from "react";
import { Bot, Search } from "lucide-react";
import type { McpAuditEntry } from "@/bindings/McpAuditEntry";
import { useMcpActivity, type McpActivityData } from "@/lib/mcp";
import { auditRows } from "@/lib/mcp-audit-rows";
import {
  groupByDay, hostKey, kindCounts, matchesFilters, NO_FILTERS, observedClient,
  type ActionKind, type ActivityFilters, type ActivityKind,
} from "@/lib/mcp-activity";
import type { RecordOverview } from "@/lib/records";
import { revealHidden } from "@/lib/reveal-hidden";
import { useNow } from "@/lib/use-now";
import { cn, errorMessage } from "@/lib/utils";
import { PageHeader } from "@/components/app/PageHeader";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { selectClass } from "./form";
import { ActivityEntry, entryTime } from "./ActivityEntry";

/** How many entries the page shows at first, and how many more each time it is asked. */
const PAGE = 100;
const NO_ENTRIES: McpAuditEntry[] = [];

const CHIPS: { kind: ActivityKind | "all"; label: string }[] = [
  { kind: "all", label: "All" },
  { kind: "succeeded", label: "Succeeded" },
  { kind: "failed", label: "Failed" },
  { kind: "not_run", label: "Not run" },
  { kind: "error", label: "Error" },
];

const ACTIONS: { action: ActionKind; label: string }[] = [
  { action: "command", label: "Commands" },
  { action: "tunnel", label: "Tunnels" },
  { action: "change", label: "Host and route changes" },
  { action: "server_key", label: "Server keys" },
];

// Recorded names can hold hidden characters; an option's value carries them encoded so that none reaches the page as it is.
const optionValue = (key: string) => encodeURIComponent(key);
const fromOption = (value: string) => (value ? decodeURIComponent(value) : null);

type Option = { key: string; label: string };
const byLabel = (a: Option, b: Option) => a.label.localeCompare(b.label);

/** The AI activity page, as its state and the latest answer of `mcp_activity` make it. */
export function AiActivityView({
  data, pending, error, retry, overview, now, filters, setFilters, shown, showMore, expanded, toggle, showHost, openAiSettings,
}: {
  data: McpActivityData | undefined;
  pending: boolean;
  error: unknown;
  retry: () => void;
  overview: RecordOverview;
  now: number;
  filters: ActivityFilters;
  setFilters: (filters: ActivityFilters) => void;
  shown: number;
  showMore: () => void;
  expanded: ReadonlySet<string>;
  toggle: (key: string) => void;
  showHost: (hostId: string) => void;
  openAiSettings: () => void;
}) {
  const entries = data?.entries ?? NO_ENTRIES;
  const rows = useMemo(() => auditRows(entries), [entries]);
  const hosts = useMemo(() => new Map(overview.hosts.map((host) => [host.id, host])), [overview.hosts]);
  const visible = useMemo(() => rows.filter((row) => matchesFilters(row.entry, filters)), [rows, filters]);
  const counts = useMemo(() => kindCounts(entries, filters), [entries, filters]);
  // The clients and hosts the entries name, and the one chosen even after its last entry is gone.
  const clients = useMemo(() => {
    const names = new Set(entries.map(observedClient));
    if (filters.client !== null) names.add(filters.client);
    return [...names].map((name) => ({ key: name, label: name })).sort(byLabel);
  }, [entries, filters.client]);
  const hostOptions = useMemo(() => {
    const options = new Map<string, Option>();
    const add = (key: string, recorded: string) => {
      if (options.has(key)) return;
      options.set(key, { key, label: hosts.get(key)?.payload.alias ?? recorded });
    };
    for (const entry of entries) add(hostKey(entry), entry.alias);
    if (filters.host !== null) add(filters.host, filters.host.replace(/^alias:/, ""));
    return [...options.values()].sort(byLabel);
  }, [entries, hosts, filters.host]);
  const groups = groupByDay(visible.slice(0, shown), (row) => entryTime(row.entry), now);

  return <div className="ai-activity-panel space-y-5">
    <PageHeader title="AI activity" count={data ? entries.length : undefined}
      description="What AI clients did through Lunport, newest first. Output and authentication answers are never recorded." />
    {data?.audit_error && <p role="alert" className="rounded-lg border border-destructive/30 p-3 text-sm text-destructive">
      Audit persistence error: {revealHidden(data.audit_error)}. Completed commands are not retried.
    </p>}
    {error !== null && error !== undefined && <div role="alert" className="flex flex-wrap items-center gap-2 rounded-lg border border-destructive/30 p-3 text-sm text-destructive">
      <span className="min-w-0 flex-1 break-words">AI activity could not be loaded. {revealHidden(errorMessage(error))}</span>
      <Button variant="ghost" size="sm" onClick={retry}>Retry</Button>
    </div>}
    {!data ? pending && <p role="status" className="py-12 text-center text-sm text-muted-foreground">Loading AI activity…</p>
      : entries.length === 0 ? <div className="flex flex-col items-center gap-3 rounded-xl border border-dashed px-6 py-14 text-center">
        <Bot className="size-7 text-muted-foreground" aria-hidden="true" />
        <h2 className="font-medium">No AI activity yet</h2>
        <p className="max-w-sm text-sm text-muted-foreground">Commands, tunnels, host and route changes and server key checks that AI clients ask Lunport for appear here with their results.</p>
        <Button variant="outline" onClick={openAiSettings}>Set up AI access</Button>
      </div>
      : <>
        <div className="space-y-3">
          <div className="flex flex-wrap items-center gap-3">
            <div className="relative min-w-48 flex-1">
              <Search className="pointer-events-none absolute left-3 top-2.5 size-4 text-muted-foreground" />
              <Input id="activity-search" aria-label="Search AI activity" placeholder="Search commands, hosts or clients…" className="pl-9"
                value={filters.search} onChange={(event) => setFilters({ ...filters, search: event.target.value })} />
            </div>
            <select aria-label="AI client" className={cn(selectClass, "sm:w-44")} value={filters.client === null ? "" : optionValue(filters.client)}
              onChange={(event) => setFilters({ ...filters, client: fromOption(event.target.value) })}>
              <option value="">All clients</option>
              {clients.map((client) => <option key={client.key} value={optionValue(client.key)}>{revealHidden(client.label)}</option>)}
            </select>
            <select aria-label="Host" className={cn(selectClass, "sm:w-44")} value={filters.host === null ? "" : optionValue(filters.host)}
              onChange={(event) => setFilters({ ...filters, host: fromOption(event.target.value) })}>
              <option value="">All hosts</option>
              {hostOptions.map((host) => <option key={host.key} value={optionValue(host.key)}>{revealHidden(host.label)}</option>)}
            </select>
            <select aria-label="Action" className={cn(selectClass, "sm:w-44")} value={filters.action ?? ""}
              onChange={(event) => setFilters({ ...filters, action: (event.target.value || null) as ActionKind | null })}>
              <option value="">All actions</option>
              {ACTIONS.map(({ action, label }) => <option key={action} value={action}>{label}</option>)}
            </select>
          </div>
          <div role="group" aria-label="Result" className="flex flex-wrap gap-2">
            {CHIPS.map(({ kind, label }) => <button key={kind} type="button" aria-pressed={filters.kind === kind}
              className={cn(
                "inline-flex h-7 items-center gap-1.5 rounded-full border px-3 text-xs font-medium transition-colors focus-visible:outline-2 focus-visible:outline-ring",
                filters.kind === kind ? "border-primary bg-primary text-primary-foreground" : "text-muted-foreground hover:bg-muted hover:text-foreground",
              )}
              onClick={() => setFilters({ ...filters, kind })}>
              {label}{" "}<span className="tabular-nums opacity-80">{counts[kind]}</span>
            </button>)}
          </div>
        </div>
        {visible.length === 0 ? <div className="flex flex-col items-center gap-3 rounded-xl border border-dashed px-6 py-14 text-center">
          <Search className="size-7 text-muted-foreground" aria-hidden="true" />
          <h2 className="font-medium">No activity matches these filters</h2>
          <p className="max-w-sm text-sm text-muted-foreground">Try another client, host or result.</p>
          <Button variant="outline" onClick={() => setFilters(NO_FILTERS)}>Clear filters</Button>
        </div>
          : <div className="space-y-5">
            {groups.map((group, index) => <section key={`${index}:${group.label}`} className="space-y-2">
              <h2 className="text-xs font-medium uppercase tracking-wide text-muted-foreground">{group.label}</h2>
              <ol className="space-y-2">
                {group.rows.map((row) => <ActivityEntry key={row.key} entry={row.entry}
                  host={row.entry.host_id ? hosts.get(row.entry.host_id) ?? null : null}
                  expanded={expanded.has(row.key)} onToggle={() => toggle(row.key)} showHost={showHost} />)}
              </ol>
            </section>)}
            {visible.length > shown && <div className="flex justify-center">
              <Button variant="outline" onClick={showMore}>Show 100 more</Button>
            </div>}
          </div>}
        <p className="text-center text-xs text-muted-foreground">Lunport keeps the latest 1,000 AI entries on this computer.</p>
      </>}
  </div>;
}

/** The AI activity page in the Library: every AI request Lunport recorded, with what became of it. */
export function AiActivityPanel({ overview, showHost, openAiSettings }: {
  overview: RecordOverview;
  showHost: (hostId: string) => void;
  openAiSettings: () => void;
}) {
  const query = useMcpActivity();
  const now = useNow();
  const [filters, setFilterState] = useState<ActivityFilters>(NO_FILTERS);
  const [shown, setShown] = useState(PAGE);
  const [expanded, setExpanded] = useState<ReadonlySet<string>>(() => new Set());
  // A new filter starts the list again from its first page.
  const setFilters = (next: ActivityFilters) => {
    setFilterState(next);
    setShown(PAGE);
  };
  const toggle = (key: string) => setExpanded((previous) => {
    const next = new Set(previous);
    if (!next.delete(key)) next.add(key);
    return next;
  });
  return <AiActivityView
    data={query.data} pending={query.isPending} error={query.error} retry={() => void query.refetch()}
    overview={overview} now={now} filters={filters} setFilters={setFilters}
    shown={shown} showMore={() => setShown((count) => count + PAGE)} expanded={expanded} toggle={toggle}
    showHost={showHost} openAiSettings={openAiSettings}
  />;
}
