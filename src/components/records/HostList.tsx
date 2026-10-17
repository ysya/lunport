import { useRef, useState } from "react";
import {
  ArrowUpRight,
  Check,
  ChevronDown,
  Folder,
  FolderPlus,
  LayoutGrid,
  List,
  MoreHorizontal,
  Pencil,
  Plus,
  Search,
  Server,
  SlidersHorizontal,
  Upload,
  X,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { PageHeader } from "@/components/app/PageHeader";
import { useUiStore } from "@/stores/ui";
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
import { revealHidden } from "@/lib/sync-approvals";
import { cn } from "@/lib/utils";
import { CollectionActions } from "./CollectionActions";
import { HostContextMenu } from "./HostContextMenu";
import {
  buildRecordTree,
  affectedRecords,
  groupPath,
  selectGroup as uniqueGroup,
} from "./group-tree";
import { libraryHosts, type LibraryFilter } from "./library-view";

export const readinessLabel = {
  ready: "Ready",
  needs_key: "Needs key",
  key_conflict: "Key conflict",
  needs_review: "Needs review",
};
export function RecordHostList({
  overview,
  selectedId,
  select,
  selectGroup,
  edit,
  create,
  createGroup,
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
  searchShortcut = "Ctrl F",
}: {
  overview: RecordOverview;
  selectedId: string | null;
  selectedGroupId?: string | null;
  select: (id: string) => void;
  edit?: (id: string) => void;
  selectGroup?: (id: string) => void;
  selectScope?: (scope: HostScope) => void;
  create?: () => void;
  createGroup?: () => void;
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
  searchShortcut?: string;
}) {
  const showTags = useSettingsStore((state) => state.showHostTags);
  const recent = useSettingsStore((state) => state.recentConnections);
  const [search, setSearch] = useState("");
  const list = useRef<HTMLElement>(null);
  const layout = useUiStore((s) => s.hostLayout);
  const setLayout = useUiStore((s) => s.setHostLayout);
  const [selecting, setSelecting] = useState(false);
  const [checked, setChecked] = useState<Set<string>>(new Set());
  const hosts = libraryHosts(overview, filter, search, recent);
  const roots = buildRecordTree(overview);
  const allNodes = roots.flatMap((root) => root.groups);
  const findNode = (
    nodes: typeof allNodes,
  ): (typeof allNodes)[number] | undefined => {
    for (const node of nodes) {
      if (filter.kind === "group" && node.group.id === filter.id) return node;
      const child = findNode(node.children);
      if (child) return child;
    }
  };
  const browsableGroups =
    filter.kind === "group"
        ? (findNode(allNodes)?.children ?? [])
        : [];
  const currentGroup =
    filter.kind === "group" ? uniqueGroup(overview.groups, filter.id) : null;
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
    if (!connect || disabled || connectingId || (counts.get(host.id) ?? 0) > 1)
      return;
    if (host.readiness.kind !== "ready" || host.group_error) select(host.id);
    else connect(host.id);
  };
  const canOrganize = (host: RecordHostView) =>
    !disabled &&
    !organizeDisabled &&
    !host.group_error &&
    counts.get(host.id) === 1;
  return (
    <div className="library-catalog flex h-full min-h-0 flex-col">
      <PageHeader className="library-page-header" title={revealHidden(title)} count={hosts.length}
        breadcrumb={filter.kind === "group" || filter.kind === "tag" ? <div className="library-breadcrumb">
            <button
              type="button"
              onClick={() => changeFilter?.({ kind: "all" })}
            >
              Library
            </button>
            <span>/</span>
            <span>Hosts</span>
          </div> : undefined}
        description={filter.kind === "attention" ? "Review connection settings and keys before connecting." : currentGroup ? revealHidden(groupPath(overview, currentGroup.id, currentGroup.scope)) : undefined}
        actions={<>
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
          {importHosts && (
            <Button variant="outline" size="sm" onClick={importHosts} disabled={disabled}>
              <Upload className="size-3.5" />
              Import hosts
            </Button>
          )}
          {create && (
            <Button
              className="library-create"
              onClick={create}
              disabled={disabled}
            >
              <Plus className="size-4" />
              New host
            </Button>
          )}
          {createGroup && (
            <DropdownMenu>
              <DropdownMenuTrigger asChild>
                <Button
                  variant="outline"
                  size="icon"
                  aria-label="More library actions"
                >
                  <ChevronDown className="size-4" />
                </Button>
              </DropdownMenuTrigger>
              <DropdownMenuContent align="end">
                {createGroup && (
                  <DropdownMenuItem disabled={disabled} onSelect={createGroup}>
                    <FolderPlus />
                    New group
                  </DropdownMenuItem>
                )}
              </DropdownMenuContent>
            </DropdownMenu>
          )}
        </>}
      />
      <div className="library-catalog-toolbar">
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
        <div className="library-view-toggle" aria-label="Host view">
          <button
            type="button"
            aria-label="Grid view"
            aria-pressed={layout === "grid"}
            onClick={() => setLayout("grid")}
          >
            <LayoutGrid className="size-4" />
          </button>
          <button
            type="button"
            aria-label="List view"
            aria-pressed={layout === "list"}
            onClick={() => setLayout("list")}
          >
            <List className="size-4" />
          </button>
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
      </div>
      <div className="library-catalog-scroll min-h-0 flex-1 overflow-y-auto">
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
        {!search.trim() && !!browsableGroups.length && (
          <section className="library-group-section" aria-label="Browse groups">
            <div className="library-section-label">
              Groups <span>{browsableGroups.length}</span>
            </div>
            <div className="library-group-grid">
              {browsableGroups.map((node) => (
                <div key={node.group.id} className="library-group-card">
                  <button
                    type="button"
                    disabled={disabled || !changeFilter}
                    onClick={() =>
                      changeFilter?.({ kind: "group", id: node.group.id })
                    }
                  >
                    <span className="library-folder-icon">
                      <Folder className="size-5" />
                    </span>
                    <span className="min-w-0">
                      <strong className="block truncate">
                        {revealHidden(node.group.payload.name)}
                      </strong>
                      <span>
                        {affectedRecords(overview, node.group).hosts} hosts
                      </span>
                    </span>
                  </button>
                  {selectGroup && (
                    <button
                      type="button"
                      className="library-group-edit"
                      aria-label={
                        "Edit group " + revealHidden(node.group.payload.name)
                      }
                      disabled={disabled}
                      onClick={() => selectGroup(node.group.id)}
                    >
                      <MoreHorizontal className="size-4" />
                    </button>
                  )}
                </div>
              ))}
            </div>
          </section>
        )}
        <section ref={list} tabIndex={-1} aria-label="Saved hosts">
          <div className="library-section-label">
            {search.trim() ? "Search results" : "Hosts"}
            <span>{hosts.length}</span>
            {search.trim() && connect && (
              <small>Enter to connect · Click for details</small>
            )}
          </div>
          {layout === "list" && !!hosts.length && (
            <div className="library-list-head">
              <span>Name</span>
              <span>Address</span>
              <span>Connection</span>
            </div>
          )}
          <div className="library-host-grid" data-layout={layout}>
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
              const target = revealHidden(host.effective_payload.hostname);
              const user = revealHidden(host.effective_payload.user);
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
                      onKeyDown={(e) => {
                        if (isImeKey(e)) return;
                        if (e.key === "Enter" && !selecting && connect) {
                          e.preventDefault();
                          connectHost(host);
                        }
                      }}
                    >
                      <span className="library-server-icon">
                        {selecting ? (
                          checked.has(host.id) ? (
                            <Check className="size-5" />
                          ) : (
                            <span className="size-4 rounded border border-current" />
                          )
                        ) : (
                          <Server className="size-5" />
                        )}
                      </span>
                      <span className="library-host-identity">
                        <strong title={name}>{name}</strong>
                        <span className="library-host-address" title={target}>
                          {target}
                        </span>
                      </span>
                      <span className="library-host-meta">
                        <span className="library-host-user">
                          {user || "Default user"}
                          <span>:{host.effective_payload.port}</span>
                        </span>
                        {showTags && !!host.payload.tags.length && (
                          <span className="library-host-tags">
                            {host.payload.tags.slice(0, 3).map((tag) => (
                              <span key={tag}>{revealHidden(tag)}</span>
                            ))}
                          </span>
                        )}
                      </span>
                      {blocked && (
                        <span className="library-host-warning">
                          {ambiguous
                            ? "Conflicting host ID"
                            : host.group_error
                              ? "Needs review"
                              : readinessLabel[host.readiness.kind]}
                        </span>
                      )}
                    </button>
                    {!selecting && (
                      <div className="library-host-actions">
                        <span className="library-protocol">SSH</span>
                        {connect && (
                          <Button
                            variant="ghost"
                            size="sm"
                            aria-label={"Connect to " + name}
                            disabled={disabled || !!connectingId || blocked}
                            onClick={(e) => {
                              e.stopPropagation();
                              connectHost(host);
                            }}
                          >
                            {connectingId === host.id ? "Opening…" : "Connect"}
                            <ArrowUpRight className="size-3.5" />
                          </Button>
                        )}
                        {edit && (
                          <Button
                            variant="ghost"
                            size="icon-sm"
                            aria-label={"Edit " + name}
                            disabled={disabled || ambiguous}
                            onClick={(e) => {
                              e.stopPropagation();
                              edit(host.id);
                            }}
                          >
                            <Pencil className="size-3.5" />
                          </Button>
                        )}
                      </div>
                    )}
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
                      : "No hosts here yet"}
              </h2>
              <p>
                {search.trim()
                  ? "Try another name, address, username or tag."
                  : filter.kind === "recent"
                    ? "Open a connection and it will appear here for quick access."
                    : filter.kind === "attention"
                      ? "There are no connection settings or keys to review."
                      : "Add a server or bring your connections from an SSH config."}
              </p>
              {search.trim() ? (
                <Button variant="outline" onClick={() => setSearch("")}>
                  Clear search
                </Button>
              ) : filter.kind === "recent" || filter.kind === "attention" ? (
                <Button
                  variant="outline"
                  onClick={() => changeFilter?.({ kind: "all" })}
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
                      Import hosts
                    </Button>
                  )}
                </div>
              )}
            </div>
          )}
        </section>
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
  );
}
