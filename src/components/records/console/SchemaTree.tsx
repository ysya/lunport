import { useMemo, useState } from "react";
import { ChevronDown, ChevronRight, Folder, LoaderCircle, RotateCw, Search, Table2 } from "lucide-react";
import type { RelationNode } from "@/bindings/RelationNode";
import type { SchemaNode } from "@/bindings/SchemaNode";
import type { SchemaTree as Tree } from "@/bindings/SchemaTree";
import type { TablePreview } from "@/lib/database-console-session";
import { revealHidden } from "@/lib/reveal-hidden";

export const TRUNCATED = "Lunport shows the first 5,000 tables and views.";

type Group = "tables" | "views" | "functions";
const GROUP_NAMES: Record<Group, string> = { tables: "Tables", views: "Views", functions: "Functions" };
const groupOf = (relation: RelationNode): Group => (relation.kind === "view" || relation.kind === "materialized_view" ? "views" : "tables");

const schemaKey = (schema: string) => `schema:${schema}`;
const groupKey = (schema: string, group: Group) => JSON.stringify([schema, group]);
const relationKey = (schema: string, relation: string) => JSON.stringify([schema, "relation", relation]);
const NO_INITIAL_RELATIONS: string[] = [];

/** What shows open at first: the `public` schema (or the first one) with its tables, and each `schema.relation` of `initialOpen`. */
function firstOpen(tree: Tree | null, initialOpen: string[]): Set<string> {
  const open = new Set<string>();
  const first = tree?.schemas.find((schema) => schema.name === "public") ?? tree?.schemas[0];
  if (first) open.add(schemaKey(first.name)).add(groupKey(first.name, "tables"));
  for (const name of initialOpen) {
    const dot = name.indexOf(".");
    const schema = tree?.schemas.find((candidate) => candidate.name === name.slice(0, dot));
    const relation = schema?.relations.find((candidate) => candidate.name === name.slice(dot + 1));
    if (!schema || !relation) continue;
    open.add(schemaKey(schema.name)).add(groupKey(schema.name, groupOf(relation))).add(relationKey(schema.name, relation.name));
  }
  return open;
}

export function filterSchemaTree(tree: Tree | null, matches: (schema: string, object: string) => boolean): SchemaNode[] {
  return (tree?.schemas ?? []).map((schema) => ({
    ...schema,
    relations: schema.relations.filter((relation) => matches(schema.name, relation.name)),
    functions: schema.functions.filter((fn) => matches(schema.name, fn.name)),
  })).filter((schema) => schema.relations.length > 0 || schema.functions.length > 0 || matches(schema.name, ""));
}

function revealWorkspaceRelation(row: HTMLButtonElement | null) {
  const scroll = row?.closest(".database-workspace-tree");
  if (!row || !scroll) return;
  const viewport = scroll.getBoundingClientRect();
  const relation = row.getBoundingClientRect();
  if (relation.top < viewport.top) scroll.scrollTop += relation.top - viewport.top;
  else if (relation.bottom > viewport.bottom) scroll.scrollTop += relation.bottom - viewport.bottom;
}

function Toggle({ open, onToggle, label, count, icon }: { open: boolean; onToggle: () => void; label: string; count?: number; icon?: boolean }) {
  const Chevron = open ? ChevronDown : ChevronRight;
  return <button type="button" className="console-tree-toggle" aria-expanded={open} onClick={onToggle}>
    <Chevron className="size-3 shrink-0" aria-hidden="true" />
    {icon && <Folder className="size-3.5 shrink-0" aria-hidden="true" />}
    <span className="console-tree-name" title={label}>{label}</span>
    {count !== undefined && <span className="console-tree-count">{count.toLocaleString("en-US")}</span>}
  </button>;
}

/** The branches of one connection, with optional filtering supplied by its sidebar. */
export function SchemaTreeBranches({ tree, matching, hidden, canBrowse, onBrowse, preview, browseOnClick, initialOpen = NO_INITIAL_RELATIONS }: {
  tree: Tree | null;
  matching?: SchemaNode[];
  hidden?: boolean;
  canBrowse: boolean;
  onBrowse: (schema: string, relation: string) => void;
  preview: TablePreview | null;
  browseOnClick?: boolean;
  initialOpen?: string[];
}) {
  const activeSchema = browseOnClick ? preview?.schema : undefined;
  const activeRelation = activeSchema === undefined ? undefined : tree?.schemas.find((schema) => schema.name === activeSchema)
    ?.relations.find((relation) => relation.name === preview?.relation);
  const activeGroup = activeRelation ? groupOf(activeRelation) : undefined;
  const [open, setOpen] = useState<Set<string> | null>(null);
  const [lastReveal, setLastReveal] = useState<string | null>(null);
  const [filterCollapsed, setFilterCollapsed] = useState<{ matching: SchemaNode[]; keys: Set<string> } | null>(null);
  const revealKey = activeSchema !== undefined && activeRelation ? relationKey(activeSchema, activeRelation.name) : null;
  if (lastReveal !== revealKey) {
    setLastReveal(revealKey);
    if (activeSchema !== undefined && activeGroup) {
      const schema = schemaKey(activeSchema);
      const group = groupKey(activeSchema, activeGroup);
      setOpen(new Set(open ?? firstOpen(tree, initialOpen)).add(schema).add(group));
      if (filterCollapsed) {
        const keys = new Set(filterCollapsed.keys);
        keys.delete(schema);
        keys.delete(group);
        setFilterCollapsed({ matching: filterCollapsed.matching, keys });
      }
    }
  }
  const shown = open ?? firstOpen(tree, initialOpen);
  const filteredKeys = filterCollapsed?.matching === matching ? filterCollapsed?.keys : undefined;
  const toggle = (key: string) => {
    const next = new Set(shown);
    if (!next.delete(key)) next.add(key);
    setOpen(next);
  };
  const toggleBranch = (key: string) => {
    if (!matching || !browseOnClick) return toggle(key);
    const keys = new Set(filteredKeys);
    if (!keys.delete(key)) keys.add(key);
    setFilterCollapsed({ matching, keys });
  };
  const isBranchOpen = (key: string) => matching ? !filteredKeys?.has(key) : shown.has(key);
  const schemas = matching ?? tree?.schemas ?? [];
  if (hidden) return null;

  return <ul className="console-tree">
      {schemas.map((schema) => {
        const groups: Record<Group, number> = {
          tables: schema.relations.filter((relation) => groupOf(relation) === "tables").length,
          views: schema.relations.filter((relation) => groupOf(relation) === "views").length,
          functions: schema.functions.length,
        };
        return <li key={schema.name}>
          <Toggle open={isBranchOpen(schemaKey(schema.name))} onToggle={() => toggleBranch(schemaKey(schema.name))} label={revealHidden(schema.name)} icon />
          {isBranchOpen(schemaKey(schema.name)) && <ul>
            {(Object.keys(groups) as Group[]).filter((group) => groups[group] > 0).map((group) => {
              const key = groupKey(schema.name, group);
              return <li key={group}>
                <Toggle open={isBranchOpen(key)} onToggle={() => toggleBranch(key)} label={GROUP_NAMES[group]} count={groups[group]} />
                {isBranchOpen(key) && <ul>
                  {group === "functions"
                    ? schema.functions.map((fn, index) => <li key={`${fn.name}(${fn.arguments})#${index}`} className="console-tree-leaf">
                      <span className="console-tree-name" title={revealHidden(`${fn.name}(${fn.arguments})`)}>{revealHidden(fn.name)}<span className="console-tree-type">({revealHidden(fn.arguments)})</span></span>
                    </li>)
                    : schema.relations.filter((relation) => groupOf(relation) === group).map((relation) => {
                      const key = relationKey(schema.name, relation.name);
                      const expanded = shown.has(key);
                      const active = preview?.schema === schema.name && preview.relation === relation.name;
                      const name = revealHidden(relation.name);
                      const qualifiedName = revealHidden(`${schema.name}.${relation.name}`);
                      const Chevron = expanded ? ChevronDown : ChevronRight;
                      const browse = () => onBrowse(schema.name, relation.name);
                      return <li key={relation.name}>
                        <div className="console-tree-relation" data-active={active}>
                          <button type="button" className="console-icon-button" aria-label={`${expanded ? "Collapse" : "Expand"} columns for ${name}`} aria-expanded={expanded} onClick={() => toggle(key)}>
                            <Chevron className="size-3" aria-hidden="true" />
                          </button>
                          <button
                            type="button"
                            className="console-tree-name"
                            title={qualifiedName}
                            aria-current={active ? "true" : undefined}
                            disabled={!canBrowse}
                            ref={browseOnClick && active ? revealWorkspaceRelation : undefined}
                            onClick={(event) => {
                              if (browseOnClick || event.detail === 0) browse();
                              else event.currentTarget.focus();
                            }}
                            onDoubleClick={browseOnClick ? undefined : browse}
                          >{browseOnClick ? <>
                            <Table2 className="size-3.5 shrink-0" aria-hidden="true" />
                            <span className="console-tree-name">{name}</span>
                          </> : name}</button>
                          {!browseOnClick && <button type="button" className="console-icon-button console-tree-browse" title="Browse data" aria-label={`Browse data in ${qualifiedName}`} disabled={!canBrowse} tabIndex={-1} onClick={browse}>
                            <Table2 className="size-3.5" aria-hidden="true" />
                          </button>}
                        </div>
                        {expanded && <ul className="console-tree-columns">
                          {relation.columns.map((column) => <li key={column.name} className="console-tree-leaf">
                            <span className="console-tree-name" title={revealHidden(column.name)}>{revealHidden(column.name)}</span>
                            <span className="console-tree-type">{revealHidden(column.type_name)}{column.primary_key ? " · PK" : ""}</span>
                          </li>)}
                        </ul>}
                      </li>;
                    })}
                </ul>}
              </li>;
            })}
          </ul>}
        </li>;
      })}
    </ul>;
}

/** The schema sidebar for a standalone database console. */
export function SchemaTree({ id, hidden, tree, error, canRefresh, onRefresh, canBrowse, onBrowse, preview, initialOpen }: {
  id?: string;
  hidden?: boolean;
  tree: Tree | null;
  error: string | null;
  canRefresh: boolean;
  onRefresh: () => void;
  canBrowse: boolean;
  onBrowse: (schema: string, relation: string) => void;
  preview: TablePreview | null;
  /** `schema.relation` names drawn open at first. */
  initialOpen?: string[];
}) {
  const [filter, setFilter] = useState("");
  const needle = filter.trim().toLowerCase();
  const matching = useMemo(() => needle ? filterSchemaTree(tree, (_schema, name) => name.toLowerCase().includes(needle)) : undefined, [tree, needle]);
  return <aside id={id} hidden={hidden} className="console-schema" aria-label="Schema">
    <div className="console-schema-tools">
      <div className="console-schema-filter">
        <Search className="size-3.5" aria-hidden="true" />
        <input type="search" aria-label="Filter tables" placeholder="Filter tables…" value={filter} onChange={(event) => setFilter(event.target.value)} />
      </div>
      <button type="button" className="console-icon-button" aria-label="Refresh schema" title="Refresh schema" disabled={!canRefresh} onClick={onRefresh}>
        <RotateCw className="size-3.5" aria-hidden="true" />
      </button>
    </div>
    {error && <p className="console-schema-note" role="alert">{revealHidden(error)}</p>}
    {tree?.truncated && <p className="console-schema-note">{TRUNCATED}</p>}
    {!tree && !error && <LoaderCircle className="console-schema-loading size-4 motion-safe:animate-spin" aria-label="Loading schema" />}
    <SchemaTreeBranches tree={tree} matching={matching} canBrowse={canBrowse} onBrowse={onBrowse} preview={preview} initialOpen={initialOpen} />
  </aside>;
}
