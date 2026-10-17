import { useEffect, useId, useRef, useState, type ReactNode, type PointerEvent } from "react";
import {
  Clock3, Folder, FolderOpen, Hash, KeyRound, Plus,
  AlertCircle, Server, ChevronRight, ArrowUp, ArrowDown, ArrowDownAZ, MoreHorizontal,
} from "lucide-react";
import type { RecordOverview } from "@/lib/records";
import { cn } from "@/lib/utils";
import { revealHidden } from "@/lib/sync-approvals";
import { useUiStore } from "@/stores/ui";
import { Disclosure } from "@/components/app/Disclosure";
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from "@/components/ui/tooltip";
import { buildRecordTree, affectedRecords, scopeKey, type GroupNode } from "./group-tree";
import { libraryHosts, type LibraryFilter } from "./library-view";
import { groupComparator, moveGroup } from "./group-order";
import { DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuLabel, DropdownMenuTrigger } from "@/components/ui/dropdown-menu";

type GroupOrdering = {
  enabled: boolean;
  dragged: string | null;
  drop: {id:string; side:"before" | "after"} | null;
  start: (event: PointerEvent<HTMLDivElement>, id:string, siblings:string[]) => void;
  suppressClick: () => boolean;
  move: (siblings: string[], id: string, target: string, side: "before" | "after") => void;
};

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
          onClick={(event) => { event.currentTarget.focus(); action(); }}

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

function GroupNavigationItem({ node, overview, filter, activePanel, choose, ordering, siblings }: {
  node: GroupNode; overview: RecordOverview; filter: LibraryFilter;
  activePanel: WorkspacePanel; choose: (filter: LibraryFilter) => void;
  ordering: GroupOrdering; siblings: string[];
}) {
  const controls = useId();
  const key = `${scopeKey(node.group.scope)}:${node.group.id}`;
  const closed = useUiStore((s) => s.collapsedRecordGroups.includes(key));
  const toggle = useUiStore((s) => s.toggleRecordGroup);
  const label = revealHidden(node.group.payload.name);
  const dropSide = ordering.drop?.id === node.group.id ? ordering.drop.side : null;
  const index = siblings.indexOf(node.group.id);
  const move = (offset: -1 | 1) => {
    const target = siblings[index + offset];
    if (ordering.enabled && target) ordering.move(siblings, node.group.id, target, offset < 0 ? "before" : "after");
  };
  return (
    <div className="library-group-node">
      <div className={cn("library-group-navigation-row", dropSide && `group-drop-${dropSide}`, ordering.dragged === node.group.id && "is-dragging")}
        data-group-row={node.group.id}
        data-reorderable={ordering.enabled}
        onPointerDown={(event) => ordering.start(event, node.group.id, siblings)}
        onClickCapture={(event) => { if (ordering.suppressClick()) { event.preventDefault(); event.stopPropagation(); } }}
        onKeyDown={(event) => {
          if (event.altKey && !event.ctrlKey && !event.metaKey && ["ArrowUp", "ArrowDown"].includes(event.key)) {
            event.preventDefault(); event.stopPropagation(); move(event.key === "ArrowUp" ? -1 : 1);
          }
        }}
      >
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
        <DropdownMenu>
          <DropdownMenuTrigger asChild>
            <button type="button" className="library-group-actions" aria-label={`Group order for ${label}`} disabled={!ordering.enabled}>
              <MoreHorizontal className="size-3.5" />
            </button>
          </DropdownMenuTrigger>
          <DropdownMenuContent align="start">
            <DropdownMenuLabel>Group order</DropdownMenuLabel>
            <DropdownMenuItem disabled={!ordering.enabled || index <= 0} onSelect={() => move(-1)}><ArrowUp />Move up</DropdownMenuItem>
            <DropdownMenuItem disabled={!ordering.enabled || index >= siblings.length - 1} onSelect={() => move(1)}><ArrowDown />Move down</DropdownMenuItem>
          </DropdownMenuContent>
        </DropdownMenu>
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
              ordering={ordering}
              siblings={node.children.map((g) => g.group.id)}
            />)}
          </div>
        </Disclosure>
      )}
    </div>
  );
}

export function LibraryNavigation({ overview, panel, filter, navigate, changeFilter, createGroup, reorder, reordering = false }: {
  overview: RecordOverview; panel: WorkspacePanel; filter: LibraryFilter;
  navigate: (panel: WorkspacePanel) => void; changeFilter: (filter: LibraryFilter) => void;
  createGroup: () => void;
  reorder?: (ids: string[]) => void;
  reordering?: boolean;
}) {
  const collapsed = useUiStore((s) => s.librarySidebarCollapsed);
  const choose = (next: LibraryFilter) => { changeFilter(next); navigate("hosts"); };
  const compareGroups = groupComparator(overview.group_order?.ids ?? []);
  const groups = buildRecordTree(overview).flatMap((root) => root.groups)
    .sort((a, b) => compareGroups(a.group, b.group));
  const [dragged, setDragged] = useState<string | null>(null);
  const [drop, setDrop] = useState<GroupOrdering["drop"]>(null);
  const cleanupDrag = useRef<(() => void) | null>(null);
  const suppressClick = useRef(false);
  useEffect(() => () => cleanupDrag.current?.(), []);
  const ordering: GroupOrdering = {
    enabled: !!reorder && !reordering && !overview.group_order?.blocked,
    dragged, drop,
    suppressClick: () => suppressClick.current,
    start: (event, id, siblings) => {
      // Pointer gestures work alongside Tauri's native Windows file-drop handling.
      if (!ordering.enabled || event.button !== 0 || !(event.target instanceof Element) || !event.target.closest(".library-nav-item")) return;
      cleanupDrag.current?.();
      const origin = {x:event.clientX, y:event.clientY};
      const pointer = event.pointerId;
      let active = false;
      let hit: GroupOrdering["drop"] = null;
      const move = (e: globalThis.PointerEvent) => {
        if (e.pointerId !== pointer) return;
        if (!active && Math.hypot(e.clientX-origin.x, e.clientY-origin.y) < 5) return;
        if (!active) { active = true; setDragged(id); }
        e.preventDefault();
        const row = document.elementFromPoint(e.clientX,e.clientY)?.closest<HTMLElement>("[data-group-row]");
        const target = row?.dataset.groupRow;
        hit = row && target && target !== id && siblings.includes(target)
          ? {id:target, side:e.clientY < row.getBoundingClientRect().top + row.getBoundingClientRect().height/2 ? "before" : "after"} : null;
        setDrop(hit);
      };
      const cleanup = () => {
        window.removeEventListener("pointermove",move);
        window.removeEventListener("pointerup",finish);
        window.removeEventListener("pointercancel",cancel);
        window.removeEventListener("blur",cancel);
        window.removeEventListener("keydown",key);
        cleanupDrag.current = null;
        setDragged(null); setDrop(null);
        if (active) { suppressClick.current = true; window.setTimeout(() => {suppressClick.current=false;},0); }
      };
      const finish = (e:globalThis.PointerEvent) => {
        if (e.pointerId !== pointer) return;
        cleanup();
        if (active && hit) ordering.move(siblings,id,hit.id,hit.side);
      };
      const cancel = () => cleanup();
      const key = (e:KeyboardEvent) => { if (e.key === "Escape") { e.preventDefault(); cleanup(); } };
      cleanupDrag.current = cleanup;
      window.addEventListener("pointermove",move,{passive:false});
      window.addEventListener("pointerup",finish);
      window.addEventListener("pointercancel",cancel);
      window.addEventListener("blur",cancel);
      window.addEventListener("keydown",key);
    },
    move: (siblings, id, target, side) => {
      const ids = moveGroup(overview.group_order?.ids ?? [], siblings, id, target, side);
      if (ids) reorder?.(ids);
    },
  };
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
            <div className="ml-auto flex items-center gap-1"><DropdownMenu>
              <DropdownMenuTrigger asChild><button type="button" aria-label="Group sorting" title="Group sorting"><MoreHorizontal className="size-3.5" /></button></DropdownMenuTrigger>
              <DropdownMenuContent align="start">
                <DropdownMenuLabel>{overview.group_order?.sync_enabled ? "Order syncs to your computers" : "Order saved on this computer"}</DropdownMenuLabel>
                <DropdownMenuItem disabled={!ordering.enabled || !overview.group_order?.ids.length} onSelect={() => reorder?.([])}><ArrowDownAZ />Sort groups by name</DropdownMenuItem>
              </DropdownMenuContent>
            </DropdownMenu>
            <button type="button" aria-label="New group" title="New group" onClick={createGroup}>
              <Plus className="size-3.5" />
            </button>
            </div>
          </div>
          <nav aria-label="Groups" className="space-y-0.5">
            {groups.map((node) => <GroupNavigationItem
              key={`${scopeKey(node.group.scope)}:${node.group.id}`}
              node={node}
              overview={overview}
              filter={filter}
              activePanel={panel}
              choose={choose}
              ordering={ordering}
              siblings={groups.map((g) => g.group.id)}
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
