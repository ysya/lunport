import { useEffect, useId, useState, type ReactNode } from "react";
import {
  Clock3, Folder, FolderOpen, Hash, KeyRound, Plus,
  AlertCircle, Server, ChevronRight,
} from "lucide-react";
import type { RecordOverview } from "@/lib/records";
import { cn } from "@/lib/utils";
import { revealHidden } from "@/lib/sync-approvals";
import { useUiStore } from "@/stores/ui";
import { Disclosure } from "@/components/app/Disclosure";
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from "@/components/ui/tooltip";
import { buildRecordTree, affectedRecords, scopeKey, type GroupNode } from "./group-tree";
import { libraryHosts, type LibraryFilter } from "./library-view";

export type WorkspacePanel = "hosts" | "keys" | "account" | "import";
export const LIBRARY_NAVIGATION_ID = "library-navigation";

function NavigationItem({ label, icon, active, action, count, collapsed = false }: {
  label: string; icon: ReactNode; active: boolean; action: () => void;
  count?: number; collapsed?: boolean;
}) {
  const [tooltipOpen, setTooltipOpen] = useState(false);
  useEffect(() => { if (!collapsed) setTooltipOpen(false); }, [collapsed]);
  return (
    <Tooltip open={collapsed && tooltipOpen} onOpenChange={setTooltipOpen}>
      <TooltipTrigger asChild>
        <button
          type="button"
          className={cn("library-nav-item", active && "is-active")}

          aria-current={active ? "page" : undefined}
          onClick={action}

          aria-label={count === undefined ? label : `${label} (${count})`}
          title={collapsed ? undefined : label}
        >
          {icon}
          <span className="library-nav-label">
            {label}
          </span>
          {count !== undefined && <span className="library-nav-count">
            {count}
          </span>}
          {collapsed && !!count && label === "Needs attention" && <span className="library-nav-attention" aria-hidden="true" />}
        </button>
      </TooltipTrigger>
      <TooltipContent side="right" sideOffset={8}>
        {label}
        {count !== undefined ? ` (${count})` : ""}
      </TooltipContent>
    </Tooltip>
  );
}

function GroupNavigationItem({ node, overview, filter, activePanel, choose }: {
  node: GroupNode; overview: RecordOverview; filter: LibraryFilter;
  activePanel: WorkspacePanel; choose: (filter: LibraryFilter) => void;
}) {
  const controls = useId();
  const key = `${scopeKey(node.group.scope)}:${node.group.id}`;
  const closed = useUiStore((s) => s.collapsedRecordGroups.includes(key));
  const toggle = useUiStore((s) => s.toggleRecordGroup);
  const label = revealHidden(node.group.payload.name);
  return (
    <div className="library-group-node">
      <div className="library-group-navigation-row">
        {node.children.length ? (
          <button
            type="button"
            className="library-group-disclosure"
            aria-label={`${closed ? "Expand" : "Collapse"} ${label}`}

            aria-expanded={!closed}
            aria-controls={controls}
            onClick={() => toggle(key)}
          >
            <ChevronRight className="size-3" data-expanded={!closed} />
          </button>
        ) : <span className="library-group-disclosure-spacer" />}
        <NavigationItem
          label={label}
          icon={<Folder className="size-4" />}

          active={activePanel === "hosts" && filter.kind === "group" && filter.id === node.group.id}

          action={() => choose({ kind: "group", id: node.group.id })}
          count={affectedRecords(overview, node.group).hosts}
        />
      </div>
      {!!node.children.length && (
        <Disclosure open={!closed} id={controls}>
          <div className="library-group-children">
            {node.children.map((child) => <GroupNavigationItem
              key={child.group.id}
              node={child}
              overview={overview}
              filter={filter}
              activePanel={activePanel}
              choose={choose}
            />)}
          </div>
        </Disclosure>
      )}
    </div>
  );
}

export function LibraryNavigation({ overview, panel, filter, navigate, changeFilter, createGroup }: {
  overview: RecordOverview; panel: WorkspacePanel; filter: LibraryFilter;
  navigate: (panel: WorkspacePanel) => void; changeFilter: (filter: LibraryFilter) => void;
  createGroup: () => void;
}) {
  const collapsed = useUiStore((s) => s.librarySidebarCollapsed);
  const choose = (next: LibraryFilter) => { changeFilter(next); navigate("hosts"); };
  const groups = buildRecordTree(overview).flatMap((root) => root.groups)
    .sort((a, b) => a.group.payload.name.localeCompare(b.group.payload.name));
  const tags = [...new Set(overview.hosts.flatMap((h) => h.payload.tags))].sort();
  const attention = libraryHosts(overview, { kind: "attention" }, "", {}).length;
  const row = (label: string, icon: ReactNode, active: boolean, action: () => void, count?: number) => (
    <NavigationItem
      label={label}
      icon={icon}
      active={active}
      action={action}
      count={count}
      collapsed={collapsed}
    />
  );
  return (
    <TooltipProvider delayDuration={300}>
      <aside
        id={LIBRARY_NAVIGATION_ID}
        className="library-navigation"
        aria-label="Library navigation"
        data-collapsed={collapsed}
      >
        <div className="library-nav-heading library-workspace-label" aria-hidden={collapsed}>Library</div>
        <nav aria-label="Workspace sections" className="space-y-1">
          {row("All hosts", <Server className="size-4" />, panel === "hosts" && (filter.kind === "all" || collapsed && ["group", "tag", "ungrouped"].includes(filter.kind)), () => choose({ kind: "all" }), overview.hosts.length)}
          {row("Recent", <Clock3 className="size-4" />, panel === "hosts" && filter.kind === "recent", () => choose({ kind: "recent" }))}
          {row("Needs attention", <AlertCircle className="size-4" />, panel === "hosts" && filter.kind === "attention", () => choose({ kind: "attention" }), attention || undefined)}
          {row("Keys", <KeyRound className="size-4" />, panel === "keys", () => navigate("keys"), overview.keys.length)}
        </nav>
        <div
          className="library-nav-collections min-h-0 flex-1 overflow-y-auto"
          inert={collapsed}
          aria-hidden={collapsed}
        >
          <div className="library-nav-heading">
            <span>Groups</span>
            <button type="button" aria-label="New group" title="New group" onClick={createGroup}>
              <Plus className="size-3.5" />
            </button>
          </div>
          <nav aria-label="Groups" className="space-y-0.5">
            {groups.map((node) => <GroupNavigationItem
              key={`${scopeKey(node.group.scope)}:${node.group.id}`}
              node={node}
              overview={overview}
              filter={filter}
              activePanel={panel}
              choose={choose}
            />)}
            <NavigationItem
              label="Ungrouped"
              icon={<FolderOpen className="size-4" />}
              active={panel === "hosts" && filter.kind === "ungrouped"}
              action={() => choose({ kind: "ungrouped" })}
            />
          </nav>
          {!!tags.length && <>
            <div className="library-nav-heading mt-5">Tags</div>
            <nav aria-label="Tags" className="space-y-0.5">
              {tags.map((tag) => <NavigationItem
                key={tag}
                label={revealHidden(tag)}
                icon={<Hash className="size-3.5" />}
                active={panel === "hosts" && filter.kind === "tag" && filter.id === tag}
                action={() => choose({ kind: "tag", id: tag })}
              />)}
            </nav>
          </>}
        </div>
      </aside>
    </TooltipProvider>
  );
}
