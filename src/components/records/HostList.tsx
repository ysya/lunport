import { Fragment, useEffect, useRef, useState, type PointerEvent, type ReactElement } from "react";
import {
  AlertCircle,
  Check,
  ChevronRight,
  Clock3,
  Cloud,
  Download,
  Folder,
  FolderPlus,
  FolderOpen,
  Hash,
  ArrowDownAZ,
  LoaderCircle,
  MoreHorizontal,
  Pencil,
  Plus,
  Search,
  Server,
  SlidersHorizontal,
  TriangleAlert,
  Upload,
  X,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { PageHeader } from "@/components/app/PageHeader";
import { Input } from "@/components/ui/input";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { isImeKey } from "@/lib/ime";
import { SEARCH_INPUT_ID } from "@/lib/app-shortcuts";
import { useSettingsStore } from "@/stores/settings";
import type { HostScope, RecordHostView, RecordOverview } from "@/lib/records";
import { revealHidden } from "@/lib/reveal-hidden";
import { iapTarget, transportFor } from "@/lib/transports";
import { cn } from "@/lib/utils";
import { CollectionActions } from "./CollectionActions";
import { HostContextMenu } from "./HostContextMenu";
import {
  buildRecordTree,
  groupAncestors,
  groupPath,
  type GroupNode,
  type ScopeRoot,
  selectGroup as uniqueGroup,
} from "./group-tree";
import { libraryHosts, type LibraryFilter } from "./library-view";
import { groupComparator, moveGroup } from "./group-order";

export const readinessLabel = {
  ready: "Ready",
  needs_key: "Needs key",
  key_conflict: "Key conflict",
  needs_review: "Needs review",
};
export function browseGroupNodes(roots: ScopeRoot[], search: string): GroupNode[] {
  const nodes = roots.flatMap((root) => root.groups);
  const needle = search.trim().toLocaleLowerCase();
  if (!needle) return nodes;
  const matches: GroupNode[] = [];
  const visit = (node: GroupNode) => {
    if (node.group.payload.name.toLocaleLowerCase().includes(needle)) matches.push(node);
    node.children.forEach(visit);
  };
  nodes.forEach(visit);
  return matches;
}
export function RecordHostList({
  overview,
  selectedId,
  select,
  inspect,
  dismiss,
  selectGroup,
  edit,
  duplicate,
  create,
  createGroup,
  reorder,
  reordering = false,
  disabled = false,
  organizeDisabled = false,
  accept,
  onBusy,
  expand,
  connect,
  connectingId,
  filter = { kind: "all" },
  changeFilter,
  importHosts,
  exportHosts,
  searchShortcut = "Ctrl F",
}: {
  overview: RecordOverview;
  selectedId: string | null;
  selectedGroupId?: string | null;
  select: (id: string) => void;
  inspect?: (id: string) => void;
  dismiss?: () => void;
  edit?: (id: string) => void;
  duplicate?: (id: string) => void;
  selectGroup?: (id: string) => void;
  selectScope?: (scope: HostScope) => void;
  create?: () => void;
  createGroup?: (parentId?: string | null) => void;
  reorder?: (ids: string[]) => void;
  reordering?: boolean;
  disabled?: boolean;
  organizeDisabled?: boolean;
  accept?: (overview: RecordOverview) => unknown;
  onBusy?: (busy: boolean) => void;
  expand?: () => void;
  connect?: (id: string) => void;
  connectingId?: string | null;
  filter?: LibraryFilter;
  changeFilter?: (filter: LibraryFilter) => void;
  importHosts?: () => void;
  exportHosts?: (previousWorkspace: boolean) => void;
  searchShortcut?: string;
}) {
  const recent = useSettingsStore((state) => state.recentConnections);
  const [search, setSearch] = useState("");
  const [collectionSearch, setCollectionSearch] = useState("");
  const [collectionsOpen, setCollectionsOpen] = useState(false);
  const [groupsOpen, setGroupsOpen] = useState(true);
  const [tagsOpen, setTagsOpen] = useState(true);
  const [draggedGroup, setDraggedGroup] = useState<string | null>(null);
  const [groupDrop, setGroupDrop] = useState<{ id: string; side: "before" | "after" } | null>(null);
  const [expandedGroups, setExpandedGroups] = useState<Set<string>>(new Set());
  const cleanupGroupDrag = useRef<(() => void) | null>(null);
  const suppressGroupClick = useRef(false);
  useEffect(() => () => cleanupGroupDrag.current?.(), []);
  const list = useRef<HTMLElement>(null);
  const [selecting, setSelecting] = useState(false);
  const [checked, setChecked] = useState<Set<string>>(new Set());
  const hosts = libraryHosts(overview, filter, search, recent);
  const groupIndex = filter.kind === "groups";
  const tagIndex = filter.kind === "tags";
  const browseIndex = groupIndex || tagIndex;
  const attention = libraryHosts(overview, { kind: "attention" }, "", {}).length;
  const roots = buildRecordTree(overview);
  const compareGroups = groupComparator(overview.group_order?.ids ?? []);
  const rootGroups = browseGroupNodes(roots, collectionSearch)
    .sort((a, b) => compareGroups(a.group, b.group));
  const tagCounts = new Map<string, number>();
  for (const host of overview.hosts)
    for (const tag of new Set(host.payload.tags)) tagCounts.set(tag, (tagCounts.get(tag) ?? 0) + 1);
  const allTags = [...tagCounts.keys()].sort((a, b) => a.localeCompare(b));
  const visibleTags = allTags.filter((tag) => tag.toLocaleLowerCase().includes(collectionSearch.trim().toLocaleLowerCase()));
  const showUngrouped = !collectionSearch.trim() || "ungrouped".includes(collectionSearch.trim().toLocaleLowerCase());
  const currentGroup =
    filter.kind === "group" ? uniqueGroup(overview.groups, filter.id) : null;
  const groupAncestry = currentGroup
    ? groupAncestors(overview, currentGroup.id, currentGroup.scope)
    : null;
  useEffect(() => {
    if (filter.kind !== "group") return;
    setGroupsOpen(true);
    setExpandedGroups((current) => {
      const next = new Set(current);
      for (const ancestor of groupAncestry?.groups.slice(1) ?? []) next.add(ancestor.id);
      return next;
    });
  }, [filter.kind, filter.kind === "group" ? filter.id : null, currentGroup?.payload.parent_id]);
  useEffect(() => {
    if (filter.kind === "tag") setTagsOpen(true);
  }, [filter.kind, filter.kind === "tag" ? filter.id : null]);
  const title =
    filter.kind === "group"
      ? (currentGroup?.payload.name ?? "Unavailable group")
      : filter.kind === "tag"
        ? "# " + filter.id
        : (
            {
              all: "All hosts",
              recent: "Recent",
              attention: "Needs attention",
              ungrouped: "Ungrouped",
              groups: "Groups",
              tags: "Tags",
            } as const
          )[filter.kind];
  const counts = new Map<string, number>();
  for (const host of overview.hosts)
    counts.set(host.id, (counts.get(host.id) ?? 0) + 1);
  const toggle = (id: string) =>
    setChecked((current) => {
      const next = new Set(current);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  const openHost = (host: RecordHostView) => {
    if (selecting) toggle(host.id);
    else select(host.id);
  };
  const connectHost = (host: RecordHostView) => {
    if (!connect || disabled || selecting || connectingId || (counts.get(host.id) ?? 0) > 1)
      return;
    if (host.readiness.kind !== "ready" || host.group_error) (edit ?? select)(host.id);
    else connect(host.id);
  };
  const canOrganize = (host: RecordHostView) =>
    !disabled &&
    !organizeDisabled &&
    !host.group_error &&
    counts.get(host.id) === 1;
  const browse = (next: LibraryFilter) => {
    setSearch("");
    setCollectionSearch("");
    setSelecting(false);
    setChecked(new Set());
    setCollectionsOpen(false);
    changeFilter?.(next);
  };
  const orderEnabled = !!reorder && !reordering && !overview.group_order?.blocked && !collectionSearch.trim();
  const startGroupDrag = (event: PointerEvent<HTMLDivElement>, id: string, siblings: string[]) => {
    // Pointer gestures work alongside Tauri's native Windows file-drop handling.
    if (!orderEnabled || event.button !== 0 || !(event.target instanceof Element) ||
      !event.target.closest(".library-group-card > button:first-child")) return;
    cleanupGroupDrag.current?.();
    const origin = { x: event.clientX, y: event.clientY };
    const pointer = event.pointerId;
    let active = false;
    let hit: { id: string; side: "before" | "after" } | null = null;
    const move = (next: globalThis.PointerEvent) => {
      if (next.pointerId !== pointer) return;
      if (!active && Math.hypot(next.clientX - origin.x, next.clientY - origin.y) < 5) return;
      if (!active) { active = true; setDraggedGroup(id); }
      next.preventDefault();
      const card = document.elementFromPoint(next.clientX, next.clientY)?.closest<HTMLElement>("[data-group-row]");
      const target = card?.dataset.groupRow;
      hit = card && target && target !== id && siblings.includes(target)
        ? { id: target, side: next.clientY < card.getBoundingClientRect().top + card.getBoundingClientRect().height / 2 ? "before" : "after" }
        : null;
      setGroupDrop(hit);
    };
    const cleanup = () => {
      window.removeEventListener("pointermove", move);
      window.removeEventListener("pointerup", finish);
      window.removeEventListener("pointercancel", cancel);
      window.removeEventListener("blur", cancel);
      window.removeEventListener("keydown", key);
      cleanupGroupDrag.current = null;
      setDraggedGroup(null); setGroupDrop(null);
      if (active) { suppressGroupClick.current = true; window.setTimeout(() => { suppressGroupClick.current = false; }, 0); }
    };
    const finish = (next: globalThis.PointerEvent) => {
      if (next.pointerId !== pointer) return;
      cleanup();
      if (active && hit) {
        const ids = moveGroup(overview.group_order?.ids ?? [], siblings, id, hit.id, hit.side);
        if (ids) reorder?.(ids);
      }
    };
    const cancel = () => cleanup();
    const key = (next: KeyboardEvent) => { if (next.key === "Escape") { next.preventDefault(); cleanup(); } };
    cleanupGroupDrag.current = cleanup;
    window.addEventListener("pointermove", move, { passive: false });
    window.addEventListener("pointerup", finish);
    window.addEventListener("pointercancel", cancel);
    window.addEventListener("blur", cancel);
    window.addEventListener("keydown", key);
  };
  const groupCards = (nodes: GroupNode[], tree = false): ReactElement => {
    const siblings = nodes.map((node) => node.group.id);
    const move = (id: string, index: number, offset: -1 | 1) => {
      const target = siblings[index + offset];
      if (!orderEnabled || !target) return;
      const next = moveGroup(overview.group_order?.ids ?? [], siblings, id, target, offset < 0 ? "before" : "after");
      if (next) reorder?.(next);
    };
    return <div className={cn("library-group-grid", tree && "library-group-tree")}>
      {nodes.map((node, index) => {
        const name = revealHidden(node.group.payload.name);
        const expanded = expandedGroups.has(node.group.id);
        const card = <div key={node.group.id}
          className={cn("library-group-card", filter.kind === "group" && filter.id === node.group.id && "is-selected", draggedGroup === node.group.id && "is-dragging", groupDrop?.id === node.group.id && `group-drop-${groupDrop.side}`)}
          data-group-row={node.group.id} data-reorderable={orderEnabled}
          onPointerDown={(event) => startGroupDrag(event, node.group.id, siblings)}
          onClickCapture={(event) => { if (suppressGroupClick.current) { event.preventDefault(); event.stopPropagation(); } }}
          onKeyDown={(event) => {
            if (event.altKey && !event.ctrlKey && !event.metaKey && (event.key === "ArrowUp" || event.key === "ArrowDown")) {
              event.preventDefault();
              move(node.group.id, index, event.key === "ArrowUp" ? -1 : 1);
            }
          }}>
          <button type="button" aria-label={`Open group ${name}`}
            aria-current={filter.kind === "group" && filter.id === node.group.id ? "page" : undefined}
            disabled={disabled || !changeFilter}
            onClick={() => browse({ kind: "group", id: node.group.id })}>
            <span className="library-folder-icon"><Folder className="size-5" /></span>
            <span className="min-w-0"><strong className="block truncate">{name}</strong>
              <span>{node.hosts.length} {node.hosts.length === 1 ? "host" : "hosts"}</span>
              {!!collectionSearch.trim() && !!node.group.payload.parent_id &&
                <span className="library-group-path">{revealHidden(groupPath(overview, node.group.id, node.group.scope))}</span>}
            </span>
          </button>
          {tree && node.children.length > 0 && <button type="button" className="library-group-edit library-group-toggle"
            aria-label={`${expanded ? "Collapse" : "Expand"} group ${name}`} aria-expanded={expanded}
            onClick={() => setExpandedGroups((current) => {
              const next = new Set(current);
              if (next.has(node.group.id)) next.delete(node.group.id);
              else next.add(node.group.id);
              return next;
            })}><ChevronRight className={cn("size-4", expanded && "rotate-90")} /></button>}
          {selectGroup && <button type="button" className="library-group-edit" aria-label={`Edit group ${name}`}
            disabled={disabled} onClick={() => selectGroup(node.group.id)}><MoreHorizontal className="size-4" /></button>}
        </div>;
        return tree ? <div key={node.group.id} className="library-group-branch">
          {card}
          {expanded && node.children.length > 0 && groupCards(node.children, true)}
        </div> : card;
      })}
    </div>;
  };
  return (
    <div className="library-catalog flex h-full min-h-0">
      {changeFilter && <aside id="host-collections" className="library-collections" aria-label="Host collections" data-open={collectionsOpen}>
        <div className="library-collections-heading">
          <strong>Browse</strong>
          <button type="button" aria-label="Close collections" onClick={() => setCollectionsOpen(false)}><X className="size-4" /></button>
        </div>
        <div className="library-collections-search">
          <Search className="size-3.5" aria-hidden="true" />
          <Input id={browseIndex ? SEARCH_INPUT_ID : undefined} aria-label="Find groups or tags" placeholder="Find groups or tags…" value={collectionSearch}
            onChange={(event) => setCollectionSearch(event.target.value)} />
        </div>
        <nav aria-label="Host collection filters" className="library-collection-list">
          {([
            { kind: "all", label: "All hosts", icon: <Server className="size-4" />, count: overview.hosts.length },
            { kind: "recent", label: "Recent", icon: <Clock3 className="size-4" /> },
            { kind: "attention", label: "Needs attention", icon: <AlertCircle className="size-4" />, count: attention },
          ] as const).map((item) => <button key={item.kind} type="button" className="library-collection-item"
            aria-current={filter.kind === item.kind ? "page" : undefined} onClick={() => browse({ kind: item.kind })}>
            {item.icon}<span>{item.label}</span>{"count" in item && <small>{item.count}</small>}
          </button>)}
          <div className="library-collection-section">
            <div className="library-collection-heading-row">
              <button type="button" className="library-collection-heading" aria-expanded={groupsOpen}
                onClick={() => setGroupsOpen((open) => !open)}><ChevronRight className={cn("size-4", groupsOpen && "rotate-90")} />Groups</button>
              {createGroup && <button type="button" aria-label="New root group" title="New group" disabled={disabled}
                onClick={() => createGroup(null)}><Plus className="size-3.5" /></button>}
              {reorder && <DropdownMenu>
                <DropdownMenuTrigger asChild><button type="button" aria-label="Group sorting" disabled={!orderEnabled}><MoreHorizontal className="size-4" /></button></DropdownMenuTrigger>
                <DropdownMenuContent align="end">
                  <DropdownMenuItem disabled={!orderEnabled || !overview.group_order?.ids.length} onSelect={() => reorder([])}><ArrowDownAZ />Sort groups by name</DropdownMenuItem>
                </DropdownMenuContent>
              </DropdownMenu>}
            </div>
            {groupsOpen && <>
              {groupCards(rootGroups, !collectionSearch.trim())}
              {showUngrouped && <button type="button" className="library-collection-item library-collection-ungrouped"
                aria-current={filter.kind === "ungrouped" ? "page" : undefined} onClick={() => browse({ kind: "ungrouped" })}>
                <FolderOpen className="size-4" /><span>Ungrouped</span><small>{libraryHosts(overview, { kind: "ungrouped" }, "", {}).length}</small>
              </button>}
              {!rootGroups.length && !showUngrouped && <p className="library-collection-empty">No matching groups</p>}
            </>}
          </div>
          <div className="library-collection-section">
            <button type="button" className="library-collection-heading" aria-expanded={tagsOpen}
              onClick={() => setTagsOpen((open) => !open)}><ChevronRight className={cn("size-4", tagsOpen && "rotate-90")} />Tags</button>
            {tagsOpen && <>
              {visibleTags.map((tag) => <button key={tag} type="button" className="library-collection-item library-collection-tag"
                aria-current={filter.kind === "tag" && filter.id === tag ? "page" : undefined}
                onClick={() => browse({ kind: "tag", id: tag })}>
                <Hash className="size-4" /><span>{revealHidden(tag)}</span><small>{tagCounts.get(tag)}</small>
              </button>)}
              {!visibleTags.length && <p className="library-collection-empty">{collectionSearch ? "No matching tags" : "No tags yet"}</p>}
            </>}
          </div>
        </nav>
      </aside>}
      {collectionsOpen && changeFilter && <button type="button" className="library-collections-backdrop"
        aria-label="Close collections" onClick={() => setCollectionsOpen(false)} />}
      <div className="library-catalog-content flex min-h-0 min-w-0 flex-1 flex-col">
      <PageHeader className="library-page-header" title={revealHidden(title)} count={browseIndex ? undefined : hosts.length}
        breadcrumb={filter.kind === "group" || filter.kind === "tag" ? <div className="library-breadcrumb">
            <button
              type="button"
              onClick={() => browse({ kind: "all" })}
            >
              Hosts
            </button>
            <span>/</span>
            {filter.kind === "group" ? <>
              <button type="button" onClick={() => { browse({ kind: "groups" }); setGroupsOpen(true); setCollectionsOpen(true); }}>Groups</button>
              {[...(groupAncestry?.groups ?? [])].reverse().map((group) => <Fragment key={group.id}>
                <span>/</span>
                {group.id === filter.id
                  ? <span aria-current="location">{revealHidden(group.payload.name)}</span>
                  : <button type="button" aria-label={`Go to group ${revealHidden(group.payload.name)}`}
                    onClick={() => browse({ kind: "group", id: group.id })}>{revealHidden(group.payload.name)}</button>}
              </Fragment>)}
            </> : <span>Tags</span>}
          </div> : undefined}
        description={filter.kind === "attention" ? "Review connection settings and keys before connecting." : groupAncestry?.error ? revealHidden(`Needs review: ${groupAncestry.error}`) : currentGroup ? "Hosts directly in this group." : undefined}
        actions={<>
          {changeFilter && <Button variant="outline" size="sm" className="library-collections-toggle"
            aria-controls="host-collections" aria-expanded={collectionsOpen} onClick={() => setCollectionsOpen((open) => !open)}>
            <Folder className="size-4" />Browse
          </Button>}
          {currentGroup && selectGroup && (
            <Button
              variant="outline"
              size="sm"
              onClick={() => selectGroup(currentGroup.id)}
              disabled={disabled}
            >
              <SlidersHorizontal className="size-3.5" />
              Group settings
            </Button>
          )}
          {currentGroup && createGroup && (
            <Button variant="outline" size="sm" onClick={() => createGroup(currentGroup.id)} disabled={disabled}>
              <Plus className="size-4" />New subgroup
            </Button>
          )}
          {create && !browseIndex && (
            <Button
              className="library-create"
              onClick={create}
              disabled={disabled}
            >
              <Plus className="size-4" />
              New host
            </Button>
          )}
          {(createGroup || importHosts || exportHosts) && (
            <DropdownMenu>
              <DropdownMenuTrigger asChild>
                <Button
                  variant="outline"
                  size="icon"
                  aria-label="More library actions"
                >
                  <MoreHorizontal className="size-4" />
                </Button>
              </DropdownMenuTrigger>
              <DropdownMenuContent align="end">
                {importHosts && (
                  <DropdownMenuItem disabled={disabled} onSelect={importHosts}>
                    <Upload />
                    Import hosts and Groups
                  </DropdownMenuItem>
                )}
                {exportHosts && <>
                  <DropdownMenuItem disabled={disabled} onSelect={() => exportHosts(false)}>
                    <Download />Export hosts and Groups…
                  </DropdownMenuItem>
                  <DropdownMenuItem disabled={disabled} onSelect={() => exportHosts(true)}>
                    <Download />Choose a saved workspace…
                  </DropdownMenuItem>
                </>}
                {createGroup && (
                  <DropdownMenuItem disabled={disabled} onSelect={() => createGroup(null)}>
                    <FolderPlus />
                    New group
                  </DropdownMenuItem>
                )}
              </DropdownMenuContent>
            </DropdownMenu>
          )}
        </>}
      />
      {!browseIndex && <div className="library-catalog-toolbar">
        <div className="library-search">
          <Search className="size-4" />
          <Input
            id={SEARCH_INPUT_ID}
            aria-label="Search hosts"
            placeholder="Search name, address, username or tag…"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            onKeyDown={(e) => {
              if (isImeKey(e)) return;
              if (e.key === "Enter" && !selecting && hosts[0]) {
                e.preventDefault();
                connectHost(hosts[0]);
              }
            }}
          />
          {search ? (
            <button
              type="button"
              aria-label="Clear search"
              onClick={() => setSearch("")}
            >
              <X className="size-3.5" />
            </button>
          ) : (
            <kbd>{searchShortcut}</kbd>
          )}
        </div>
        {accept && (
          <Button
            variant={selecting ? "secondary" : "ghost"}
            size="sm"
            aria-pressed={selecting}
            disabled={
              disabled ||
              (!selecting && (organizeDisabled || !overview.hosts.length))
            }
            title={
              organizeDisabled
                ? "Save or discard your draft before organizing hosts"
                : "Select multiple hosts"
            }
            onClick={() => {
              setSelecting(!selecting);
              setChecked(new Set());
              if (!selecting) expand?.();
            }}
          >
            {selecting ? "Done" : "Select"}
          </Button>
        )}
      </div>}
      <div className="library-catalog-scroll min-h-0 flex-1 overflow-y-auto"
        onClick={(event) => {
          if (!(event.target instanceof Element) || event.target.closest('button, input, select, textarea, a, [role="menu"], [role="dialog"], .library-host-card, .library-group-card')) return;
          dismiss?.();
        }}>
        {selecting && (
          <div className="library-selection-bar">
            <span>{checked.size} selected</span>
            <button
              type="button"
              onClick={() =>
                setChecked(new Set(hosts.filter(canOrganize).map((h) => h.id)))
              }
            >
              Select visible
            </button>
            <button type="button" onClick={() => setChecked(new Set())}>
              Clear
            </button>
          </div>
        )}
        {browseIndex && <section className="library-browse-prompt">
          <Folder className="size-6" aria-hidden="true" />
          <p>Choose a {groupIndex ? "group" : "tag"} from Browse.</p>
        </section>}
        {!browseIndex && <section ref={list} tabIndex={-1} aria-label="Saved hosts" className="library-host-section" data-selecting={selecting}>
          <div className="library-host-grid">
            {hosts.map((host, index) => {
              const ambiguous = (counts.get(host.id) ?? 0) > 1;
              const blocked =
                host.readiness.kind !== "ready" ||
                !!host.group_error ||
                ambiguous;
              const active = selecting
                ? checked.has(host.id)
                : selectedId === host.id && !ambiguous;
              const name = revealHidden(host.payload.alias);
              const showPath = filter.kind !== "group" && filter.kind !== "ungrouped";
              const pathLabel = revealHidden(groupPath(overview, host.payload.group_id, host.scope) || "Ungrouped");
              const target = revealHidden(host.effective_payload.hostname);
              const user = revealHidden(host.effective_payload.user);
              const endpointHost = target.includes(":") && !target.startsWith("[")
                ? `[${target}]`
                : target;
              const port = host.effective_payload.port;
              const route = transportFor(overview, host.id);
              const connection = `${route ? "IAP" : "SSH"}${user ? ` · ${user}` : ""}`;
              const connectionTitle = route
                ? `Google Cloud IAP · ${revealHidden(iapTarget(route.kind))}`
                : `${connection}${user ? "" : " · OS username"} · ${endpointHost}:${port}`;
              const warningLabel = ambiguous
                ? "Conflicting host ID"
                : host.group_error
                  ? "Needs review"
                  : readinessLabel[host.readiness.kind];
              return (
                <HostContextMenu
                  key={host.id + ":" + index}
                  host={host}
                  overview={overview}
                  disabled={disabled || ambiguous || selecting}
                  organizeDisabled={!canOrganize(host)}
                  connectDisabled={blocked || !!connectingId}
                  connect={connect ? () => connectHost(host) : undefined}
                  edit={edit ? () => edit(host.id) : undefined}
                  duplicate={duplicate ? () => duplicate(host.id) : undefined}
                  inspect={inspect ? () => inspect(host.id) : undefined}
                  accept={accept}
                  onBusy={onBusy}
                  returnFocus={() => {
                    const next = list.current?.querySelector<HTMLElement>(
                      '[data-slot="context-menu-trigger"]:not([data-disabled])',
                    );
                    (next ?? list.current)?.focus();
                  }}
                >
                  <article
                    tabIndex={0}
                    aria-label={"Host actions for " + name}
                    className={cn(
                      "library-host-card",
                      showPath && "has-path",
                      active && "is-selected",
                      blocked && "needs-attention",
                    )}
                  >
                    <button
                      type="button"
                      data-host-id={host.id}
                      className="library-host-summary"
                      aria-pressed={active}
                      disabled={
                        disabled ||
                        ambiguous ||
                        (selecting && !canOrganize(host))
                      }
                      onClick={() => openHost(host)}
                      onDoubleClick={() => connectHost(host)}
                      onKeyDown={(e) => {
                        if (isImeKey(e)) return;
                        if (e.key === "Enter" && !selecting && connect) {
                          e.preventDefault();
                          connectHost(host);
                        }
                      }}
                    >
                      {selecting && (
                        <span className="library-host-checkbox" aria-hidden="true">
                          {checked.has(host.id) ? (
                            <Check className="size-4" />
                          ) : (
                            <span className="size-4 rounded border border-current" />
                          )}
                        </span>
                      )}
                      <span className="library-host-identity">
                        <strong title={name}>{name}</strong>
                        {showPath && <span className="library-host-path" title={pathLabel}>{pathLabel}</span>}
                      </span>
                      <span className="library-host-secondary">
                        <span className="library-host-connection" title={connectionTitle}>
                          {route && <Cloud className="mr-1 inline size-3 align-[-1px]" aria-hidden="true" />}
                          {connection}
                        </span>
                        {blocked && (
                          <span className="library-host-warning" title={warningLabel} aria-label={warningLabel}>
                            <TriangleAlert className="size-3 shrink-0" aria-hidden="true" />
                            {ambiguous ? "ID conflict" : warningLabel}
                          </span>
                        )}
                      </span>
                    </button>
                    <div className="library-host-actions">
                      {!selecting && edit && (
                        <Button
                          variant="ghost"
                          size="icon-sm"
                          className="library-host-edit"
                          aria-label={"Edit " + name}
                          aria-busy={connectingId === host.id}
                          title={
                            connectingId === host.id
                              ? "Opening…"
                              : "Edit " + name
                          }
                          disabled={disabled || !!connectingId || ambiguous}
                          onClick={(e) => {
                            e.stopPropagation();
                            edit(host.id);
                          }}
                          onDoubleClick={(event) => event.stopPropagation()}
                        >
                          {connectingId === host.id ? (
                            <LoaderCircle className="size-3.5 animate-spin motion-reduce:animate-none" />
                          ) : (
                            <Pencil className="size-3.5" />
                          )}
                        </Button>
                      )}
                    </div>
                  </article>
                </HostContextMenu>
              );
            })}
          </div>
          {!hosts.length && (
            <div className="library-empty">
              <div>
                <Server className="size-7" />
              </div>
              <h2>
                {search.trim()
                  ? "No matching hosts"
                  : filter.kind === "recent"
                    ? "Your next connection starts here"
                    : filter.kind === "attention"
                      ? "All hosts are ready"
                      : filter.kind === "group"
                        ? "No hosts directly in this group"
                      : "No hosts here yet"}
              </h2>
              <p>
                {search.trim()
                  ? "Try another name, address, username or tag."
                  : filter.kind === "recent"
                    ? "Open a connection and it will appear here for quick access."
                    : filter.kind === "attention"
                      ? "There are no connection settings or keys to review."
                      : filter.kind === "group"
                        ? "Subgroups are in Browse. Add a host directly to this group."
                      : "Add a server or bring your connections from an SSH config."}
              </p>
              {search.trim() ? (
                <Button variant="outline" onClick={() => setSearch("")}>
                  Clear search
                </Button>
              ) : filter.kind === "recent" || filter.kind === "attention" ? (
                <Button
                  variant="outline"
                  onClick={() => browse({ kind: "all" })}
                >
                  Browse all hosts
                </Button>
              ) : (
                <div className="flex gap-2">
                  {create && (
                    <Button onClick={create}>
                      <Plus className="size-4" />
                      New host
                    </Button>
                  )}
                  {importHosts && (
                    <Button variant="outline" onClick={importHosts}>
                      Import hosts and Groups
                    </Button>
                  )}
                </div>
              )}
            </div>
          )}
        </section>}
        {filter.kind === "all" &&
          roots.some((root) => root.diagnostics.length) && (
            <section className="mt-6">
              <div className="library-section-label">Groups to review</div>
              {roots
                .flatMap((root) => root.diagnostics)
                .map(({ group, error }, at) => (
                  <button
                    key={group.id + ":" + at}
                    className="mb-2 block w-full rounded-lg border p-3 text-left text-sm"
                    disabled={
                      disabled ||
                      !selectGroup ||
                      !uniqueGroup(overview.groups, group.id)
                    }
                    onClick={() => selectGroup?.(group.id)}
                  >
                    <strong>{revealHidden(group.payload.name)}</strong>
                    <span className="mt-1 block text-xs text-destructive">
                      {revealHidden(error)}
                    </span>
                  </button>
                ))}
            </section>
          )}
      </div>
      {accept && selecting && (
        <CollectionActions
          overview={overview}
          ids={[...checked]}
          disabled={disabled || organizeDisabled}
          accept={accept}
          onBusy={onBusy}
          clear={() => setChecked(new Set())}
          onCompleted={(ids) =>
            setChecked(
              (current) =>
                new Set([...current].filter((id) => !ids.includes(id))),
            )
          }
        />
      )}
      </div>
    </div>
  );
}
