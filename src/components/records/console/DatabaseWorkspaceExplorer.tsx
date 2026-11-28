import "./database-console.css";
import { useCallback, useEffect, useMemo, useState, useSyncExternalStore } from "react";
import { useQuery } from "@tanstack/react-query";
import { ChevronDown, ChevronRight, Cloud, Database, ListCollapse, LoaderCircle, RotateCw, Search, SquareTerminal } from "lucide-react";
import { HOST_UNAVAILABLE, databasesQuery, type DatabaseEnvironment } from "@/lib/databases";
import { standardPostgresQuery } from "@/lib/standard-postgres";
import type { ConsoleSession } from "@/lib/database-console-session";
import { revealHidden } from "@/lib/reveal-hidden";
import { errorMessage } from "@/lib/utils";
import { useTerminalStore, type DatabaseTab } from "@/stores/terminals";
import { openDatabaseConsole, openStandardPostgresConsole } from "../DatabasesPanel";
import { filterSchemaTree, SchemaTreeBranches, TRUNCATED } from "./SchemaTree";

export const DATABASE_EXPLORER_ID = "database-workspace-explorer";

type ExplorerProps = {
  activeId: string | null;
  hidden?: boolean;
  sources: ReadonlyMap<string, ConsoleSession>;
  onBrowse: (sessionId: string, schema: string, relation: string) => void;
  onOpenQuery: (sessionId: string) => void;
};

type Source = {
  key: string;
  name: string;
  environment: DatabaseEnvironment | null;
  connect?: () => string | undefined;
  routeUnavailable?: boolean;
};

function sourceKey(databaseId: string, environment: DatabaseEnvironment | null): string {
  return `${environment === null ? "postgres" : "cloud"}:${databaseId}`;
}

function useConsoleState(session?: ConsoleSession) {
  const subscribe = useCallback((listener: () => void) => session?.subscribe(listener) ?? (() => {}), [session]);
  const snapshot = useCallback(() => session?.state ?? null, [session]);
  return useSyncExternalStore(subscribe, snapshot, snapshot);
}

function sourceType(source: Source): string {
  return source.environment === null ? "PostgreSQL" : "Cloud SQL";
}

function sourceSearchText(source: Source): string {
  return `${source.name} ${sourceType(source)} ${source.environment ?? ""}`;
}

function searchTerms(filter: string): string[] {
  const trimmed = filter.trim().toLowerCase();
  return trimmed ? trimmed.split(/\s+/) : [];
}

function matches(terms: string[], ...path: string[]): boolean {
  const haystack = path.join(" ").toLowerCase();
  return terms.every((term) => haystack.includes(term));
}

function SourceBranch({ source, tab, session, active, hidden, open, collapsedMatch, terms, onToggle, onBrowse, onOpenQuery }:
  Pick<ExplorerProps, "onBrowse" | "onOpenQuery"> & {
    source: Source;
    tab?: DatabaseTab;
    session?: ConsoleSession;
    active: boolean;
    hidden?: boolean;
    open: boolean;
    collapsedMatch: boolean;
    terms: string[];
    onToggle: (expanded: boolean) => void;
  }) {
  const state = useConsoleState(session);
  const tree = state?.schema ?? null;
  const type = sourceType(source);
  const searchContext = sourceSearchText(source);
  const matching = useMemo(() => terms.length
    ? filterSchemaTree(tree, (schema, object) => matches(terms, searchContext, `${schema}.${object}`))
    : undefined, [tree, terms, searchContext]);
  const visible = !matching || matching.length > 0 || matches(terms, searchContext);
  const expanded = !!tab && (matching ? !collapsedMatch : open);
  const showContents = visible && expanded;
  const name = revealHidden(source.name);
  const unavailable = !tab && source.routeUnavailable;
  const Chevron = expanded ? ChevronDown : ChevronRight;
  const DatabaseIcon = source.environment === null ? Database : Cloud;
  const connecting = !!tab && (!state || state.status === "opening");
  const openQuery = () => { if (tab) onOpenQuery(tab.id); };
  const connectionError = state?.status !== "open" ? state?.message : null;

  return <li hidden={!visible}>
    <button type="button" className="console-tree-toggle database-workspace-source" aria-expanded={expanded}
      data-active={active} data-environment={source.environment ?? undefined} disabled={unavailable}
      aria-description={unavailable ? HOST_UNAVAILABLE : undefined} title={`${name} · ${type}${unavailable ? ` · ${HOST_UNAVAILABLE}` : ""}`}
      onClick={() => onToggle(expanded)}>
      <Chevron className="size-3 shrink-0" aria-hidden="true" />
      {connecting ? <LoaderCircle className="size-3.5 shrink-0 motion-safe:animate-spin" aria-hidden="true" />
        : <DatabaseIcon className="size-3.5 shrink-0" aria-hidden="true" />}
      <span className="console-tree-name">{name}</span>
      {source.environment && <span className="console-status-environment">{source.environment.toUpperCase()}</span>}
    </button>
    <div className="database-workspace-source-content" hidden={!showContents}>
      {tab && <div className="database-workspace-source-actions">
        <button type="button" className="console-tree-toggle" aria-label={`Open SQL console for ${name}`} onClick={openQuery}>
          <SquareTerminal className="size-3.5 shrink-0" aria-hidden="true" /> SQL Console
        </button>
        <button type="button" className="console-icon-button" aria-label={`Refresh schema for ${name}`} title="Refresh schema"
          disabled={state?.status !== "open"} onClick={() => void session?.refreshSchema()}>
          <RotateCw className="size-3.5" aria-hidden="true" />
        </button>
      </div>}
      {connecting && <p className="console-schema-note" role="status">Connecting…</p>}
      {state?.status === "password_required" && <p className="console-schema-note">Open the SQL console to enter the database password.</p>}
      {connectionError && <p className="console-schema-note" role="alert">{revealHidden(connectionError)}</p>}
      {state?.schemaError && <p className="console-schema-note" role="alert">{revealHidden(state.schemaError)}</p>}
      {tree?.truncated && <p className="console-schema-note">{TRUNCATED}</p>}
      {state?.status === "open" && !state.schemaError && (tree
        ? tree.schemas.length === 0 && <p className="console-schema-note">No schemas found.</p>
        : <p className="console-schema-note" role="status">Loading schema…</p>)}
      <SchemaTreeBranches key={tab?.id} tree={tree} matching={matching} hidden={hidden || !showContents}
        canBrowse={state?.status === "open" && !state.running} preview={active ? state?.preview ?? null : null} browseOnClick
        onBrowse={(schema, relation) => { if (tab) onBrowse(tab.id, schema, relation); }} />
    </div>
  </li>;
}

/** One database explorer across the open consoles, with saved sources available to connect on expansion. */
export function DatabaseWorkspaceExplorer({ activeId, hidden, sources, onBrowse, onOpenQuery }: ExplorerProps) {
  const cloud = useQuery(databasesQuery);
  const postgres = useQuery(standardPostgresQuery);
  const tabs = useTerminalStore((state) => state.tabs);
  const activeTab = tabs.find((tab) => tab.id === activeId);
  const activeSource = activeTab?.kind === "database" ? sourceKey(activeTab.databaseId, activeTab.environment) : null;
  const active = useConsoleState(activeId ? sources.get(activeId) : undefined);
  const previewSchema = active?.preview?.schema;
  const previewRelation = active?.preview?.relation;
  const [preferred, setPreferred] = useState<Record<string, string>>({});
  const [expanded, setExpanded] = useState(() => new Set(activeSource ? [activeSource] : []));
  const [filter, setFilter] = useState("");
  const [collapsedMatches, setCollapsedMatches] = useState(new Set<string>());
  const terms = useMemo(() => searchTerms(filter), [filter]);

  const roots = new Map<string, Source>();
  const tabBySource = new Map<string, DatabaseTab>();
  for (const row of cloud.data ?? []) {
    if (row.removed) continue;
    const key = sourceKey(row.database.id, row.environment);
    roots.set(key, { key, name: row.database.name, environment: row.environment, connect: () => openDatabaseConsole(row) });
  }
  for (const profile of postgres.data ?? []) {
    const key = sourceKey(profile.id, null);
    roots.set(key, { key, name: profile.name, environment: null, routeUnavailable: profile.route_unavailable, connect: () => openStandardPostgresConsole(profile) });
  }
  for (const tab of tabs) {
    if (tab.kind !== "database") continue;
    const key = sourceKey(tab.databaseId, tab.environment);
    const selected = tabBySource.get(key);
    const preferredId = key === activeSource ? activeId : preferred[key];
    if (!selected || selected.id !== preferredId) tabBySource.set(key, tab);
    if (!roots.has(key)) roots.set(key, { key, name: tab.name, environment: tab.environment });
  }

  const activeRoot = activeSource === null ? undefined : roots.get(activeSource);
  const activeSearch = activeRoot ? sourceSearchText(activeRoot) : null;
  useEffect(() => {
    if (activeSource === null || activeId === null) return;
    setPreferred((current) => current[activeSource] === activeId ? current : { ...current, [activeSource]: activeId });
    setExpanded((current) => current.has(activeSource) ? current : new Set(current).add(activeSource));
    if (previewSchema !== undefined && previewRelation !== undefined && activeSearch !== null) {
      const relationPath = `${previewSchema}.${previewRelation}`;
      setFilter((current) => matches(searchTerms(current), activeSearch, relationPath) ? current : "");
    }
    setCollapsedMatches((current) => {
      if (!current.has(activeSource)) return current;
      const next = new Set(current);
      next.delete(activeSource);
      return next;
    });
  }, [activeSource, activeId, activeSearch, previewSchema, previewRelation]);

  const changeFilter = (value: string) => {
    setFilter(value);
    setCollapsedMatches(new Set());
  };

  const toggle = (source: Source, tab: DatabaseTab | undefined, open: boolean) => {
    if (tab && terms.length) {
      const next = new Set(collapsedMatches);
      if (open) next.add(source.key);
      else next.delete(source.key);
      setCollapsedMatches(next);
      return;
    }
    if (!open && !tab && !source.connect?.()) return;
    const next = new Set(expanded);
    if (open) next.delete(source.key);
    else next.add(source.key);
    setExpanded(next);
  };

  const loading = cloud.isPending || postgres.isPending;
  return <aside id={DATABASE_EXPLORER_ID} className="database-workspace-explorer" hidden={hidden} aria-label="Database explorer">
    <div className="database-workspace-explorer-tools">
      <div className="database-workspace-explorer-heading">
        <h2>Databases</h2>
        <button type="button" className="console-icon-button" aria-label="Collapse all databases" title="Collapse all"
          onClick={() => { changeFilter(""); setExpanded(new Set()); }}>
          <ListCollapse className="size-3.5" aria-hidden="true" />
        </button>
      </div>
      <div className="console-schema-filter">
        <Search className="size-3.5" aria-hidden="true" />
        <input type="search" aria-label="Filter databases and objects" placeholder="Filter…" autoComplete="off" value={filter}
          onChange={(event) => changeFilter(event.target.value)} />
      </div>
    </div>
    <div className="database-workspace-tree">
      {cloud.isError && <p className="console-schema-note" role="alert">{revealHidden(errorMessage(cloud.error))}</p>}
      {postgres.isError && <p className="console-schema-note" role="alert">{revealHidden(errorMessage(postgres.error))}</p>}
      {loading && roots.size === 0 && <p className="console-schema-note" role="status">Loading databases…</p>}
      {!loading && !cloud.isError && !postgres.isError && roots.size === 0 && <p className="console-schema-note">No databases saved.</p>}
      <ul className="console-tree database-workspace-sources">
        {[...roots.values()].map((source) => {
          const tab = tabBySource.get(source.key);
          return <SourceBranch key={source.key} source={source} tab={tab} session={tab ? sources.get(tab.id) : undefined}
            active={!!tab && tab.id === activeId} hidden={hidden} open={expanded.has(source.key)} collapsedMatch={collapsedMatches.has(source.key)}
            terms={terms} onToggle={(open) => toggle(source, tab, open)} onBrowse={onBrowse} onOpenQuery={onOpenQuery} />;
        })}
      </ul>
      {!loading && roots.size > 0 && terms.length > 0 && <p className="console-schema-note database-workspace-no-matches" role="status">No matching objects.</p>}
    </div>
  </aside>;
}
