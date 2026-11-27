import { useEffect, useRef, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { Database } from "lucide-react";
import type { McpStatus } from "@/bindings/McpStatus";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Switch } from "@/components/ui/switch";
import { EnvironmentBadge } from "@/components/records/DatabaseBadges";
import { databasesQuery, routeHost, type DatabaseView } from "@/lib/databases";
import { mcpGroupKey, mcpHostGroups, useSetMcpDatabaseAllowed } from "@/lib/mcp";
import type { RecordOverview } from "@/lib/records";
import { revealHidden } from "@/lib/reveal-hidden";
import { settingsSectionId } from "@/lib/settings-navigation";

export function McpDatabaseAccessSummary({ row, overview, status }: {
  row: Pick<DatabaseView, "database" | "blocked">;
  overview: RecordOverview;
  status?: McpStatus;
}) {
  const { database } = row;
  const hostId = routeHost(database);
  const host = hostId ? overview.hosts.find((entry) => entry.id === hostId) : undefined;
  const privateRoute = database.network === "private";
  const directHost = host && status?.allowed_hosts.includes(host.id);
  const group = host && status && mcpHostGroups(overview, host)
    .find((entry) => status.allowed_groups.includes(mcpGroupKey(entry.scope, entry.id)));
  const routeAllowed = !privateRoute || directHost || group;
  const sqlGrant = status?.allowed_databases?.includes(database.id);
  const blocked = !status ? "Status unavailable" : !status.enabled ? "Paused"
    : privateRoute && !host ? "Route unavailable" : !routeAllowed ? "Blocked by route" : null;
  const sql = !status ? "Status unavailable" : !sqlGrant ? "Not granted" : blocked ?? "Allowed";
  const port = database.local_port === null ? "No port configured"
    : blocked ?? (row.blocked ? "Needs sync review to start" : "Allowed");
  const source = directHost ? "Host grant" : group ? "Group " + revealHidden(group.payload.name) : "Host access required";

  return <div className="space-y-1.5 text-xs">
    <dl className="flex flex-wrap gap-x-5 gap-y-1">
      <div><dt className="text-muted-foreground">Direct SQL</dt><dd className="font-medium">{sql}</dd></div>
      <div><dt className="text-muted-foreground">Local port</dt><dd className="font-medium">{port}</dd></div>
    </dl>
    <p className="break-words text-muted-foreground">{host
      ? "Via " + revealHidden(host.payload.alias) + (status ? " · " + source : "")
      : privateRoute ? "Route host unavailable" : "Public IP"}</p>
  </div>;
}

export function McpDatabaseAccess({ overview, status, databaseId }: {
  overview: RecordOverview;
  status?: McpStatus;
  databaseId: string | null;
}) {
  const query = useQuery(databasesQuery);
  const change = useSetMcpDatabaseAllowed();
  const [search, setSearch] = useState("");
  const searchRef = useRef<HTMLInputElement>(null);
  const selectedRef = useRef<HTMLLIElement>(null);
  const databases = (query.data ?? []).filter((row) => !row.removed);
  const targetExists = databases.some(({ database }) => database.id === databaseId);
  const needle = search.trim().toLowerCase();
  const visible = databases.filter(({ database }) => (database.name + " " + database.project + " " + database.instance).toLowerCase().includes(needle))
    .sort((a, b) => a.database.name.localeCompare(b.database.name));

  useEffect(() => {
    if (!databaseId || query.isPending) return;
    const frame = requestAnimationFrame(() => {
      const target = selectedRef.current ?? searchRef.current;
      target?.scrollIntoView({ block: "nearest" });
      target?.focus({ preventScroll: true });
    });
    return () => cancelAnimationFrame(frame);
  }, [databaseId, query.isPending, targetExists]);

  return <div id={settingsSectionId("Cloud SQL access")} tabIndex={-1} className="space-y-3">
    <div className="space-y-2 px-4 pt-3">
      <p className="text-xs text-muted-foreground">Direct SQL grants allow reads and requests for writes. Every write requires approval. Local port management follows the database route.</p>
      <Input ref={searchRef} aria-label="Search Cloud SQL access" placeholder="Search databases, instances or projects…" value={search} onChange={(event) => setSearch(event.target.value)} />
    </div>
    {query.isError ? <div className="flex items-center gap-2 px-4 pb-3" role="alert">
      <p className="text-sm text-destructive">Could not load Cloud SQL databases.</p>
      <Button size="sm" variant="outline" onClick={() => void query.refetch()}>Retry</Button>
    </div> : query.isPending ? <p role="status" className="px-4 pb-3 text-sm text-muted-foreground">Loading databases…</p>
      : visible.length === 0 ? <p className="px-4 pb-3 text-sm text-muted-foreground">{needle ? "No databases match this search." : "No saved Cloud SQL databases."}</p>
        : <ul aria-label="Cloud SQL access" className="divide-y border-t">
          {visible.map((row) => {
            const { database } = row;
            const name = revealHidden(database.name);
            const selected = database.id === databaseId;
            return <li
              key={database.id}
              ref={selected ? selectedRef : undefined}
              tabIndex={selected ? -1 : undefined}
              className="flex flex-wrap items-start justify-between gap-3 px-4 py-3 focus-visible:outline-2 focus-visible:-outline-offset-2 focus-visible:outline-ring data-[target=true]:bg-primary/5"
              data-target={selected || undefined}
            >
              <div className="min-w-44 flex-1 space-y-1.5">
                <h3 className="flex flex-wrap items-center gap-2 break-words text-sm font-medium">
                  <Database className="size-4 shrink-0 text-muted-foreground" aria-hidden="true" />{name}
                  <EnvironmentBadge environment={database.environment} />
                </h3>
                <p className="break-words text-xs text-muted-foreground">{revealHidden(database.instance + " · " + database.project)}</p>
                <McpDatabaseAccessSummary row={row} overview={overview} status={status} />
              </div>
              <label className="flex items-center gap-2 text-xs">
                Direct SQL grant
                <Switch
                  aria-label={"Allow direct AI SQL on " + name}
                  disabled={!status || change.isPending}
                  checked={status?.allowed_databases?.includes(database.id) ?? false}
                  onCheckedChange={(allowed) => change.mutate({ id: database.id, allowed })}
                />
              </label>
            </li>;
          })}
        </ul>}
  </div>;
}
