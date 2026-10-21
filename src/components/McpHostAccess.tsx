import { useEffect, useRef, useState } from "react";
import { Check, ChevronDown, ChevronRight, Folder, Search, Server, ShieldCheck, X } from "lucide-react";
import type { McpStatus } from "@/bindings/McpStatus";
import type { HostScope } from "@/lib/records";
import { useSetMcpGroupAllowed, useSetMcpHostAllowed } from "@/lib/mcp";
import { cn } from "@/lib/utils";
import { Section } from "@/components/settings-primitives";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuSeparator, DropdownMenuTrigger } from "@/components/ui/dropdown-menu";

export type McpAccessHost = {
  id: string; alias: string; hostname: string | null; user: string | null;
  port?: number; groupPath?: string; groupKeys?: string[];
};
export type McpAccessGroup = {
  id: string; scope: HostScope; key: string; name: string; path: string;
  error: string | null; ancestorKeys?: string[];
};
type Filter = "all" | "allowed" | "blocked";

/** Display the effective permission and its source separately from the grant being edited. */
export function McpHostAccess({ hosts, groups, generation, records, status, unavailable }: {
  hosts: McpAccessHost[]; groups: McpAccessGroup[]; generation?: string;
  records: boolean; status?: McpStatus; unavailable: boolean;
}) {
  const hostMutation = useSetMcpHostAllowed();
  const groupMutation = useSetMcpGroupAllowed();
  const [view, setView] = useState(records && groups.length ? "groups" : "hosts");
  const [search, setSearch] = useState("");
  const [filter, setFilter] = useState<Filter>("all");
  const [within, setWithin] = useState<string | null>(null);
  const [notice, setNotice] = useState("");
  const groupsTab = useRef<HTMLButtonElement>(null);
  const hostsTab = useRef<HTMLButtonElement>(null);
  const focusAfterMenu = useRef<"groups" | "hosts" | null>(null);
  const byKey = new Map(groups.map((group) => [group.key, group]));
  useEffect(() => {
    if (within && !groups.some((group) => group.key === within)) setWithin(null);
  }, [groups, within]);
  const direct = new Set(status?.allowed_hosts ?? []);
  const grants = new Set(status?.allowed_groups ?? []);
  const groupSources = (keys: string[] = []) => keys.flatMap((key) => {
    const group = byKey.get(key);
    return group && !group.error && grants.has(key) ? [group] : [];
  });
  const hostSources = (host: McpAccessHost) => groupSources(host.groupKeys);
  const hostAllowed = (host: McpAccessHost) => direct.has(host.id) || hostSources(host).length > 0;
  const groupAllowed = (group: McpAccessGroup) => !group.error && (grants.has(group.key) || groupSources(group.ancestorKeys).length > 0);
  const allowedCount = hosts.filter(hostAllowed).length;
  const busy = hostMutation.isPending || groupMutation.isPending;
  const unknown = !status || unavailable;
  const disabled = unknown || busy;
  const needle = search.trim().toLowerCase();
  const hostText = (host: McpAccessHost) => `${host.alias} ${host.hostname ?? ""} ${host.user ?? ""} ${host.id} ${host.groupPath ?? ""}`.toLowerCase();
  const matchesFilter = (allowed: boolean) => filter === "all" || (filter === "allowed" ? allowed : !allowed);
  const memberIndex = new Map<string, McpAccessHost[]>();
  for (const host of hosts) for (const key of host.groupKeys ?? []) {
    if (!memberIndex.has(key)) memberIndex.set(key, []);
    memberIndex.get(key)!.push(host);
  }
  const members = (group: McpAccessGroup) => memberIndex.get(group.key) ?? [];
  const visibleHosts = hosts.filter((host) => (!within || host.groupKeys?.includes(within)) && hostText(host).includes(needle) && matchesFilter(hostAllowed(host)));
  // Keep the existing hierarchy, including parents when a child matches a search or filter.
  const matchingGroups = groups.filter((group) => matchesFilter(groupAllowed(group) || members(group).some(hostAllowed))
    && (`${group.path} ${group.id}`.toLowerCase().includes(needle) || members(group).some((host) => hostText(host).includes(needle))));
  const visibleKeys = new Set(matchingGroups.flatMap((group) => [group.key, ...(group.ancestorKeys ?? [])]));
  const children = new Map<string, McpAccessGroup[]>();
  for (const group of groups) {
    const parent = group.ancestorKeys?.[0];
    if (parent && !group.error) {
      if (!children.has(parent)) children.set(parent, []);
      children.get(parent)!.push(group);
    }
  }
  const rank = new Map(groups.map((group, index) => [group.key, index]));
  const ordered: McpAccessGroup[] = [];
  const remaining = new Set(groups.map((group) => group.key));
  const sort = (a: McpAccessGroup, b: McpAccessGroup) => rank.get(a.key)! - rank.get(b.key)!;
  const visit = (group: McpAccessGroup) => {
    if (!remaining.delete(group.key)) return;
    if (visibleKeys.has(group.key)) ordered.push(group);
    (children.get(group.key) ?? []).sort(sort).forEach(visit);
  };
  groups.filter((group) => group.error || !group.ancestorKeys?.length || !byKey.has(group.ancestorKeys[0])).sort(sort).forEach(visit);
  groups.filter((group) => remaining.has(group.key)).sort(sort).forEach(visit);

  const resetNotice = () => { setNotice(""); hostMutation.reset(); groupMutation.reset(); };
  const updateGroup = async (group: McpAccessGroup, allowed: boolean) => {
    if (!generation) return;
    resetNotice();
    try {
      await groupMutation.mutateAsync({ groupId: group.id, scope: group.scope, generation, allowed });
      setNotice(allowed ? `Allowed ${group.name}, including its subgroups.` : `Removed the direct grant for ${group.name}. Other grants still apply.`);
    } catch { /* The hook shows the native error; keep the current policy visible. */ }
  };
  const updateHost = async (host: McpAccessHost, allowed: boolean) => {
    resetNotice();
    try {
      await hostMutation.mutateAsync({ alias: host.id, allowed });
      setNotice(allowed ? `Allowed ${host.alias}.` : `Removed the individual grant for ${host.alias}. Other grants still apply.`);
    } catch { /* The hook shows the native error; keep the current policy visible. */ }
  };
  const showHosts = (group: McpAccessGroup) => {
    setWithin(group.key); setSearch(""); setFilter("all"); setView("hosts"); hostsTab.current?.focus();
  };
  const manageSource = (group: McpAccessGroup) => {
    setWithin(null); setSearch(group.path); setFilter("all"); setView("groups"); groupsTab.current?.focus();
  };
  const inheritedActions = (label: string, source: McpAccessGroup, allowSeparately: () => void, cannotGrant: boolean) => <DropdownMenu>
    <DropdownMenuTrigger asChild><Button variant="ghost" size="sm" aria-label={`Manage inherited access for ${label}`}>Manage access<ChevronDown className="size-3" /></Button></DropdownMenuTrigger>
    <DropdownMenuContent align="end" onCloseAutoFocus={(event) => {
      const target = focusAfterMenu.current;
      focusAfterMenu.current = null;
      if (target) {
        event.preventDefault();
        requestAnimationFrame(() => (target === "groups" ? groupsTab : hostsTab).current?.focus());
      }
    }}>
      <DropdownMenuItem onSelect={() => { focusAfterMenu.current = "groups"; manageSource(source); }}>Manage {source.path}</DropdownMenuItem>
      <DropdownMenuSeparator />
      <DropdownMenuItem disabled={cannotGrant} onSelect={() => { focusAfterMenu.current = view === "groups" ? "groups" : "hosts"; allowSeparately(); }}><div><p>Allow separately</p><p className="text-xs text-muted-foreground">Keep access if the inherited grant is removed.</p></div></DropdownMenuItem>
    </DropdownMenuContent>
  </DropdownMenu>;
  const accessBadge = (allowed: boolean, error?: string | null, partial = false) => <Badge variant="outline" className={cn("gap-1", error ? "border-warning/30 text-warning" : !unknown && allowed ? "border-success/25 bg-success/10 text-success" : partial && !unknown && "border-primary/25 bg-primary/10 text-primary")}>
    {error ? "Needs review" : unknown ? "Unavailable" : partial ? "Partial" : <>{allowed && <Check aria-hidden="true" className="size-3" />}{allowed ? "Allowed" : "Not allowed"}</>}
  </Badge>;
  const empty = (text: string) => <p className="px-4 py-8 text-center text-sm text-muted-foreground">{text}</p>;

  return <Section title="Allowed hosts" description={records ? "Choose Groups or individual hosts. Group access includes subgroups and future members." : "Choose the host aliases your AI tools may use."}>
    <div className="overflow-hidden rounded-xl border bg-card/30">
      <div className="flex flex-wrap items-center justify-between gap-3 border-b bg-muted/20 px-4 py-3">
        <div className="flex min-w-0 items-center gap-2.5">
          <ShieldCheck aria-hidden="true" className="size-5 shrink-0 text-primary" />
          <p role="status" className="text-sm font-medium">{unknown ? (unavailable ? "Permissions unavailable" : "Loading permissions…") : `${allowedCount} of ${hosts.length} hosts allowed`}</p>
        </div>
        <span className="text-xs text-muted-foreground">{!unknown && !status.enabled ? "AI access is off · Rules are saved" : "On this device"}</span>
      </div>
      <Tabs value={view} onValueChange={(value) => { setView(value); }} className="flex-col gap-0">
        <div className="flex flex-wrap items-center justify-between gap-3 px-4 pt-3">
          <TabsList aria-label="Access by Group or host" className="h-8">
            {records && <TabsTrigger ref={groupsTab} value="groups" className="h-7 flex-none gap-2 px-3 data-[state=active]:bg-background data-[state=active]:text-foreground data-[state=active]:shadow-sm"><Folder className="size-3.5" />Groups <span className="text-xs opacity-60">{groups.length}</span></TabsTrigger>}
            <TabsTrigger ref={hostsTab} value="hosts" className="h-7 flex-none gap-2 px-3 data-[state=active]:bg-background data-[state=active]:text-foreground data-[state=active]:shadow-sm"><Server className="size-3.5" />Hosts <span className="text-xs opacity-60">{hosts.length}</span></TabsTrigger>
          </TabsList>
          <Select value={filter} onValueChange={(value) => setFilter(value as Filter)}>
            <SelectTrigger aria-label="Filter access" className="h-8 w-36"><SelectValue /></SelectTrigger>
            <SelectContent><SelectItem value="all">All access</SelectItem><SelectItem value="allowed">Allowed</SelectItem><SelectItem value="blocked">Not allowed</SelectItem></SelectContent>
          </Select>
        </div>
        <div className="px-4 py-3">
          <div className="relative">
            <Search aria-hidden="true" className="pointer-events-none absolute left-2.5 top-2.5 size-3.5 text-muted-foreground" />
            <Input aria-label="Search AI permissions" placeholder={view === "groups" ? "Search Groups or member hosts…" : "Search hosts, destinations or Groups…"} value={search} onChange={(event) => setSearch(event.target.value)} className="h-9 pl-8 pr-9" />
            {search && <Button variant="ghost" size="icon-xs" className="absolute right-1.5 top-1.5" aria-label="Clear permission search" onClick={() => setSearch("")}><X /></Button>}
          </div>
          {view === "hosts" && within && <div className="mt-2 flex items-center gap-1 text-xs text-muted-foreground"><Folder aria-hidden="true" className="size-3.5 shrink-0" /><span className="min-w-0 truncate">In {byKey.get(within)?.path ?? "Group"} and subgroups</span><Button variant="ghost" size="icon-xs" aria-label="Show all hosts" onClick={() => setWithin(null)}><X /></Button></div>}
        </div>
        <TabsContent value="groups" className="m-0 border-t">
          {!groups.length ? <div className="px-4 py-6 text-center"><p className="mb-3 text-sm text-muted-foreground">No Groups yet. Allow individual hosts instead.</p><Button variant="outline" size="sm" onClick={() => { setView("hosts"); hostsTab.current?.focus(); }}>Choose hosts</Button></div> : !ordered.length ? empty("No Groups match this search and filter.") : <ul aria-label="Group access" className="divide-y">
            {ordered.map((group) => {
              const own = grants.has(group.key);
              const source = groupSources(group.ancestorKeys)[0];
              const count = members(group).length;
              const memberAllowedCount = members(group).filter(hostAllowed).length;
              const partial = !groupAllowed(group) && memberAllowedCount > 0;
              return <li key={group.key} className="px-4 py-3" style={{ paddingLeft: 16 + Math.min(group.ancestorKeys?.length ?? 0, 4) * 16 }}>
                <div className="flex flex-wrap items-center gap-x-3 gap-y-2">
                  <Folder aria-hidden="true" className={cn("size-4 shrink-0", groupAllowed(group) ? "text-primary" : "text-muted-foreground")} />
                  <div className="min-w-28 flex-1">
                    <p className="break-words text-sm font-medium" title={group.path}>{group.name}</p>
                    <div className="mt-1 flex flex-wrap items-center gap-x-2 gap-y-1 text-xs text-muted-foreground">
                      <button type="button" className="inline-flex items-center gap-0.5 rounded hover:text-foreground hover:underline focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring" aria-label={`View hosts in ${group.path}`} onClick={() => showHosts(group)}>{partial && !unknown ? `${memberAllowedCount} of ` : ""}{count} {count === 1 ? "host" : "hosts"}<ChevronRight aria-hidden="true" className="size-3" /></button>
                      <span>· {group.scope.kind === "local" ? "Local" : "Synced"}</span>
                      <span className="min-w-0 max-w-full break-words">· {own ? source ? `Direct grant + via ${source.name}` : "Direct Group grant" : source ? `Via ${source.name}` : partial ? "Individual or subgroup grants" : "Includes subgroups"}</span>
                    </div>
                  </div>
                  <div className="ml-auto flex flex-wrap items-center gap-2">
                    {accessBadge(groupAllowed(group), group.error, partial)}
                    {own ? <Button variant="ghost" size="sm" disabled={disabled || !generation} aria-label={`Remove grant for Group ${group.path}`} onClick={() => void updateGroup(group, false)}>{groupMutation.isPending && groupMutation.variables?.groupId === group.id ? "Saving…" : "Remove grant"}</Button>
                      : source ? inheritedActions(group.path, source, () => void updateGroup(group, true), disabled || !generation || !!group.error)
                      : <Button variant="outline" size="sm" disabled={disabled || !generation || !!group.error} aria-label={`Allow Group ${group.path}`} onClick={() => void updateGroup(group, true)}>{groupMutation.isPending && groupMutation.variables?.groupId === group.id ? "Saving…" : "Allow Group"}</Button>}
                  </div>
                </div>
                {group.error && <p className="mt-2 break-words text-xs text-warning">Review this Group’s hierarchy before granting access.</p>}
              </li>;
            })}
          </ul>}
        </TabsContent>
        <TabsContent value="hosts" className="m-0 border-t">
          {!hosts.length ? empty("No SSH hosts in this library.") : !visibleHosts.length ? empty("No hosts match this search and filter.") : <ul aria-label="Host access" className="divide-y">
            {visibleHosts.map((host) => {
              const own = direct.has(host.id);
              const source = hostSources(host)[0];
              return <li key={host.id} className="px-4 py-3">
                <div className="flex flex-wrap items-center gap-x-3 gap-y-2">
                  <Server aria-hidden="true" className="size-4 shrink-0 text-muted-foreground" />
                  <div className="min-w-28 flex-1">
                    <p className="break-words text-sm font-medium">{host.alias}</p>
                    <p className="mt-0.5 break-all font-mono text-xs text-muted-foreground">{host.user ? `${host.user}@` : ""}{host.hostname ?? host.alias}{host.port ? `:${host.port}` : ""}</p>
                    <p className="mt-1 break-words text-xs text-muted-foreground">{own ? source ? `Individual grant + via ${source.name}` : "Individual grant" : source ? `Via ${source.name}` : host.groupPath || "Ungrouped"}</p>
                  </div>
                  <div className="ml-auto flex flex-wrap items-center gap-2">
                    {accessBadge(hostAllowed(host))}
                    {own ? <Button variant="ghost" size="sm" disabled={disabled} aria-label={`Remove individual grant for ${host.alias}`} onClick={() => void updateHost(host, false)}>{hostMutation.isPending && hostMutation.variables?.alias === host.id ? "Saving…" : "Remove direct grant"}</Button>
                      : source ? inheritedActions(host.alias, source, () => void updateHost(host, true), disabled)
                      : <Button variant="outline" size="sm" disabled={disabled} aria-label={`Allow host ${host.alias}`} onClick={() => void updateHost(host, true)}>{hostMutation.isPending && hostMutation.variables?.alias === host.id ? "Saving…" : "Allow host"}</Button>}
                  </div>
                </div>
              </li>;
            })}
          </ul>}
        </TabsContent>
      </Tabs>
      <div className="border-t bg-muted/10 px-4 py-2.5 text-xs text-muted-foreground">
        {view === "groups" ? "Group grants apply to current and future members, including synced hosts." : records ? "Removing a direct grant keeps any access provided by a Group." : "Only allowed aliases are available to local AI tools."}
      </div>
    </div>
    {notice && <p role="status" className="mt-2 flex items-start gap-1.5 text-xs text-success"><Check aria-hidden="true" className="mt-0.5 size-3.5 shrink-0" />{notice}</p>}
    {(hostMutation.isError || groupMutation.isError) && <p role="alert" className="mt-2 text-xs text-destructive">Could not update access. Refresh the library and try again.</p>}
  </Section>;
}
