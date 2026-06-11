import { useEffect, useMemo, useRef, useState } from "react";
import {
  Search,
  ServerOff,
  Server,
  Globe,
  ChevronRight,
  Play,
  SlidersHorizontal,
} from "lucide-react";

import type { HostSummary } from "@/bindings/HostSummary";
import { useUiStore } from "@/stores/ui";
import { useConnect, useHostsQuery, useTerminals } from "@/lib/queries";
import { useSettingsStore } from "@/stores/settings";
import { effectiveNewTab } from "@/lib/settings-logic";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { AddHostDialog } from "@/components/AddHostDialog";
import { cn, basename } from "@/lib/utils";
import { isWildcardOnly, labelsFor, secondaryLine, shortLabels } from "@/lib/host-display";

/** Sentinel Select value for the "All files" scope (Radix items can't be empty). */
const ALL_FILES = "__all__";

/**
 * How long a single click on a group header waits before toggling collapse —
 * just past the double-click window, so a rename double-click never toggles.
 */
const COLLAPSE_CLICK_DELAY_MS = 250;

/** Dotted-quad IPv4 (e.g. 10.0.0.5) — these are servers, not "web" hosts. */
const IPV4_RE = /^\d{1,3}(\.\d{1,3}){3}$/;
/** A hostname that ends in a DNS-style label, e.g. example.com / corp.internal. */
const DOMAIN_RE = /\.[a-z]{2,}$/i;

/**
 * Pick a leading anchor glyph for a row: a globe for hosts that resolve to a
 * DNS domain (alias or hostname like `github.com` / `corp.internal`), a server
 * for IPs and bare names. Monochrome + muted — a left anchor so the list isn't
 * a wall of text.
 */
function HostGlyph({ host }: { host: HostSummary }) {
  const target = (host.hostname?.trim() || host.alias).trim();
  const isDomain = !IPV4_RE.test(target) && DOMAIN_RE.test(target);
  const Icon = isDomain ? Globe : Server;
  return (
    <Icon
      className="size-3.5 shrink-0 text-muted-foreground/70 group-aria-[current=true]:text-primary/80"
      aria-hidden
    />
  );
}

/** True if the host matches the (lowercased) search term across its searchable fields. */
function matches(host: HostSummary, q: string): boolean {
  if (!q) return true;
  const hay = [
    host.alias,
    ...host.patterns,
    ...host.tags,
    host.source_file,
  ]
    .join(" ")
    .toLowerCase();
  return hay.includes(q);
}

interface HostRowProps {
  host: HostSummary;
  active: boolean;
  /** Staggered enter-animation delay, e.g. "44ms". */
  delay: string;
  /** Wildcard-defaults rows are de-emphasized and not connectable. */
  variant: "host" | "defaults";
  onSelect: () => void;
  /** Omitted for defaults rows — connecting to `Host *` is meaningless. */
  onConnect?: () => void;
}

/**
 * Compact single-line row (~28px): glyph + alias + right-aligned mono
 * secondary (`user@hostname`). Selection stays the ONE quiet cue — an inset
 * accent-tinted pill. Tags are no longer shown per-row (still searchable and
 * visible in the editor).
 */
function HostRow({ host, active, delay, variant, onSelect, onConnect }: HostRowProps) {
  const secondary = secondaryLine(host);
  const isDefaults = variant === "defaults";
  return (
    <li
      className="animate-row-enter group/row relative"
      style={{ animationDelay: delay }}
    >
      <button
        type="button"
        onClick={onSelect}
        aria-current={active ? "true" : undefined}
        className={cn(
          "group flex h-7 w-full items-center gap-2 rounded-[6px] pr-2 pl-2 text-left select-none",
          "transition-[background-color,padding] duration-100",
          "hover:bg-muted/70 focus-visible:bg-muted/70 focus-visible:ring-2 focus-visible:ring-ring/50 focus-visible:outline-none",
          // Reserve room for the overlay Play button while it's visible so the
          // right-aligned secondary slides clear instead of colliding with it.
          onConnect && "group-hover/row:pr-8 [&:has(+button:focus-visible)]:pr-8",
          active && "bg-primary/12 hover:bg-primary/15",
        )}
      >
        {isDefaults ? (
          <SlidersHorizontal
            className="size-3.5 shrink-0 text-muted-foreground/60 group-aria-[current=true]:text-primary/80"
            aria-hidden
          />
        ) : (
          <HostGlyph host={host} />
        )}
        <span
          className={cn(
            "min-w-0 flex-1 truncate text-[0.8125rem] leading-7",
            isDefaults
              ? "font-normal text-muted-foreground"
              : cn("font-medium", active ? "text-foreground" : "text-foreground/90"),
          )}
        >
          {host.alias}
        </span>
        {secondary && (
          <span
            className={cn(
              "max-w-[55%] truncate text-right font-mono text-[0.6875rem]",
              isDefaults ? "text-muted-foreground/60" : "text-muted-foreground",
            )}
          >
            {secondary}
          </span>
        )}
      </button>
      {/*
       * Connect affordance — overlays the row's right edge, hidden until the
       * row is hovered/focused (or the button itself is focused for keyboard
       * users). Stops propagation so it never also selects the row.
       */}
      {onConnect && (
        <Button
          type="button"
          variant="ghost"
          size="icon"
          aria-label={`Connect to ${host.alias}`}
          title={`Connect to ${host.alias}`}
          onClick={(e) => {
            e.stopPropagation();
            onConnect();
          }}
          className="absolute top-1/2 right-1 size-6 -translate-y-1/2 text-muted-foreground opacity-0 transition-opacity hover:text-foreground focus-visible:opacity-100 group-hover/row:opacity-100"
        >
          <Play className="size-3.5" />
        </Button>
      )}
    </li>
  );
}

/** Tiny muted subheader for the wildcard-defaults footer (smaller than group headers). */
function DefaultsLabel() {
  return (
    <div className="px-2 pt-2 pb-0.5 text-[0.625rem] font-medium tracking-[0.1em] text-muted-foreground/60 uppercase select-none">
      Defaults
    </div>
  );
}

export interface HostListProps {
  hosts: HostSummary[];
  isLoading?: boolean;
}

export function HostList({ hosts, isLoading }: HostListProps) {
  const search = useUiStore((s) => s.search);
  const setSearch = useUiStore((s) => s.setSearch);
  const selectedAlias = useUiStore((s) => s.selectedAlias);
  const setSelectedAlias = useUiStore((s) => s.setSelectedAlias);
  const collapsedGroups = useUiStore((s) => s.collapsedGroups);
  const toggleGroup = useUiStore((s) => s.toggleGroup);
  const fileScope = useUiStore((s) => s.fileScope);
  const setFileScope = useUiStore((s) => s.setFileScope);
  const terminalId = useSettingsStore((s) => s.terminalId);
  const newTabConnect = useSettingsStore((s) => s.newTabConnect);
  const fileAliases = useSettingsStore((s) => s.fileAliases);
  const setFileAlias = useSettingsStore((s) => s.setFileAlias);
  const terminals = useTerminals();
  const connect = useConnect();

  // ALL loaded source files (same cache entry App reads) — drives the scope
  // Select even for files that currently have zero hosts.
  const { data } = useHostsQuery();
  const files = useMemo(() => data?.files ?? [], [data]);
  // Auto heuristic over the FULL file set (the "clear back to this" baseline)…
  const autoLabels = useMemo(() => shortLabels(files), [files]);
  // …overlaid with the user's per-file display aliases (an override wins).
  const labels = useMemo(() => labelsFor(files, fileAliases), [files, fileAliases]);

  // Inline group-label rename (double-click a header) — transient local state.
  const [editingFile, setEditingFile] = useState<string | null>(null);
  const [draft, setDraft] = useState("");
  // Pending single-click collapse toggle, deferred past the double-click
  // window so a rename double-click never toggles the group.
  const collapseTimer = useRef<number | null>(null);
  useEffect(
    () => () => {
      if (collapseTimer.current !== null) window.clearTimeout(collapseTimer.current);
    },
    [],
  );

  const cancelPendingCollapse = () => {
    if (collapseTimer.current !== null) {
      window.clearTimeout(collapseTimer.current);
      collapseTimer.current = null;
    }
  };

  /** Header click: keyboard activation toggles at once; mouse clicks wait out a possible double-click. */
  const headerClick = (file: string, detail: number) => {
    if (detail > 1) return; // second click of a double-click — rename handles it
    if (detail === 0) {
      // Keyboard (Enter/Space) — can't become a double-click, toggle now.
      toggleGroup(file);
      return;
    }
    cancelPendingCollapse();
    collapseTimer.current = window.setTimeout(() => {
      collapseTimer.current = null;
      toggleGroup(file);
    }, COLLAPSE_CLICK_DELAY_MS);
  };

  const beginEdit = (file: string) => {
    cancelPendingCollapse();
    setDraft(labels.get(file) ?? basename(file));
    setEditingFile(file);
  };

  /** Enter: trimmed value saves; empty — or identical to the AUTO label — clears the override. */
  const commitEdit = (file: string) => {
    const trimmed = draft.trim();
    const auto = autoLabels.get(file) ?? basename(file);
    setFileAlias(file, trimmed === "" || trimmed === auto ? null : trimmed);
    setEditingFile(null);
  };

  // If the scoped file vanished after a reload, fall back to All gracefully.
  useEffect(() => {
    if (data && fileScope && !data.files.includes(fileScope)) setFileScope(null);
  }, [data, fileScope, setFileScope]);
  const scope = fileScope && files.includes(fileScope) ? fileScope : null;

  const sections = useMemo(() => {
    const q = search.trim().toLowerCase();
    const scoped = scope ? hosts.filter((h) => h.source_file === scope) : hosts;
    const filtered = scoped.filter((h) => matches(h, q));

    // Group by source_file, preserving first-appearance order. A single-file
    // scope yields ONE headerless section (flat list).
    const byFile = new Map<string, HostSummary[]>();
    for (const h of filtered) {
      const bucket = byFile.get(h.source_file);
      if (bucket) bucket.push(h);
      else byFile.set(h.source_file, [h]);
    }
    if (scope && !byFile.has(scope)) byFile.set(scope, []);

    return [...byFile.entries()].map(([file, fileHosts]) => ({
      file,
      // null name = flat list without a group header (single-file scope).
      name: scope ? null : (labels.get(file) ?? basename(file)),
      hosts: fileHosts.filter((h) => !isWildcardOnly(h)),
      // Wildcard-only blocks (`*`, `*.web`) are config DEFAULTS, not hosts —
      // demoted to a footer and excluded from every user-facing count.
      defaults: fileHosts.filter((h) => isWildcardOnly(h)),
    }));
  }, [hosts, search, scope, labels]);

  // "N hosts" reflects the scoped + filtered CONNECTABLE count (no wildcards).
  const hostCount = sections.reduce((n, s) => n + s.hosts.length, 0);
  const visibleRows = sections.reduce((n, s) => n + s.hosts.length + s.defaults.length, 0);
  // When a search is active, force-expand all groups so results are never hidden.
  const searchActive = search.trim().length > 0;

  const connectTo = (alias: string) =>
    connect.mutate({
      alias,
      terminalOverride: terminalId,
      newTab: effectiveNewTab(newTabConnect, terminalId, terminals.data ?? []),
    });

  // A running index across all rows so the staggered enter animation reads as a
  // single cascade rather than restarting per group.
  let rowIndex = -1;
  const nextDelay = () => {
    rowIndex += 1;
    return `${Math.min(rowIndex, 16) * 22}ms`;
  };

  return (
    <div className="flex h-full min-h-0 flex-col">
      <div className="shrink-0 space-y-1.5 border-b p-2">
        <div className="relative">
          <Search className="pointer-events-none absolute top-1/2 left-2.5 size-3.5 -translate-y-1/2 text-muted-foreground" />
          <Input
            type="search"
            placeholder="Search hosts…"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            aria-label="Search hosts"
            className="h-7 pl-8 text-sm"
          />
        </div>
        {/* File-scope switcher: All files, or exactly one loaded config file. */}
        <div className="flex items-center gap-1.5">
          <Select
            value={scope ?? ALL_FILES}
            onValueChange={(v) => setFileScope(v === ALL_FILES ? null : v)}
          >
            <SelectTrigger
              size="sm"
              aria-label="File scope"
              title={scope ?? "All files"}
              className="h-6 min-w-0 flex-1 border-none bg-transparent px-1.5 text-xs text-muted-foreground shadow-none hover:bg-muted/60 hover:text-foreground dark:bg-transparent dark:hover:bg-muted/60"
            >
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value={ALL_FILES} className="text-xs">
                All files
              </SelectItem>
              {files.map((f) => (
                <SelectItem key={f} value={f} title={f} className="font-mono text-xs">
                  {labels.get(f) ?? basename(f)}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
          <span className="shrink-0 pr-1 font-mono text-[0.6875rem] text-muted-foreground/70 tabular-nums">
            {isLoading ? "…" : `${hostCount} ${hostCount === 1 ? "host" : "hosts"}`}
          </span>
        </div>
      </div>

      {/*
       * Plain overflow scroller (NOT Radix ScrollArea): its viewport wraps
       * children in a `display: table` div that breaks `position: sticky`,
       * which the group headers rely on. macOS overlay scrollbars keep this
       * visually identical.
       */}
      <div className="min-h-0 flex-1 overflow-y-auto">
        <div className="p-1.5 pt-0">
          {isLoading ? (
            <HostListSkeleton />
          ) : visibleRows === 0 ? (
            hosts.length === 0 ? (
              <EmptyHosts />
            ) : searchActive ? (
              <p className="px-2 py-10 text-center text-sm text-muted-foreground">
                No hosts match{" "}
                <span className="font-mono text-foreground">“{search.trim()}”</span>.
              </p>
            ) : (
              <p className="px-2 py-10 text-center text-sm text-muted-foreground">
                No hosts in{" "}
                <span className="font-mono text-foreground">
                  {scope ? (labels.get(scope) ?? basename(scope)) : "this file"}
                </span>
                .
              </p>
            )
          ) : (
            sections.map((section) => {
              const isCollapsed =
                section.name !== null &&
                !searchActive &&
                collapsedGroups.includes(section.file);
              const alias = fileAliases[section.file];
              const isEditing = editingFile === section.file;
              return (
                <div key={section.file} className="mb-3 last:mb-0">
                  {section.name !== null &&
                    (isEditing ? (
                      /*
                       * Inline rename: the header's label swaps for a tiny mono
                       * input pre-filled with the CURRENT display label. Enter
                       * saves (empty or auto-identical clears the override),
                       * Esc/blur cancels. A div, not the collapse button —
                       * collapse is suspended while editing.
                       */
                      <div className="sidebar-sticky-header sticky top-0 z-10 flex w-full items-center justify-between rounded-sm px-2 py-1 select-none">
                        <span className="flex min-w-0 flex-1 items-center gap-1">
                          <ChevronRight
                            className={cn(
                              "size-3 shrink-0 text-muted-foreground/60 transition-transform duration-150",
                              !isCollapsed && "rotate-90",
                            )}
                            aria-hidden
                          />
                          <Input
                            autoFocus
                            value={draft}
                            onChange={(e) => setDraft(e.target.value)}
                            onFocus={(e) => e.currentTarget.select()}
                            onBlur={() => setEditingFile(null)}
                            onKeyDown={(e) => {
                              if (e.key === "Enter") {
                                e.preventDefault();
                                commitEdit(section.file);
                              } else if (e.key === "Escape") {
                                e.stopPropagation();
                                setEditingFile(null);
                              }
                            }}
                            aria-label={`Display name for ${section.file} — press Enter to save, or clear the field to restore the automatic label`}
                            title="Enter saves · Esc cancels · empty restores the automatic label"
                            className="h-5 min-w-0 flex-1 rounded-sm px-1 text-[0.6875rem] font-mono md:text-[0.6875rem]"
                          />
                        </span>
                        <span className="pl-2 font-mono text-[0.6875rem] text-muted-foreground/70 tabular-nums">
                          {section.hosts.length}
                        </span>
                      </div>
                    ) : (
                      <button
                        type="button"
                        onClick={(e) => headerClick(section.file, e.detail)}
                        onDoubleClick={(e) => {
                          e.preventDefault();
                          e.stopPropagation();
                          beginEdit(section.file);
                        }}
                        className="sidebar-sticky-header sticky top-0 z-10 flex w-full items-center justify-between rounded-sm px-2 py-1.5 select-none hover:bg-muted/50 focus-visible:ring-2 focus-visible:ring-ring/50 focus-visible:outline-none cursor-default"
                        title={
                          alias
                            ? `${alias} — ${section.file} (double-click to rename)`
                            : `${section.file} (double-click to rename)`
                        }
                        aria-expanded={!isCollapsed}
                      >
                        <span className="flex min-w-0 items-center gap-1">
                          <ChevronRight
                            className={cn(
                              "size-3 shrink-0 text-muted-foreground/60 transition-transform duration-150",
                              !isCollapsed && "rotate-90",
                            )}
                            aria-hidden
                          />
                          <span className="truncate text-[0.6875rem] font-semibold tracking-[0.08em] text-muted-foreground uppercase">
                            {section.name}
                          </span>
                        </span>
                        <span className="font-mono text-[0.6875rem] text-muted-foreground/70 tabular-nums">
                          {section.hosts.length}
                        </span>
                      </button>
                    ))}
                  {!isCollapsed && (
                    <>
                      {section.hosts.length > 0 && (
                        <ul className="space-y-px">
                          {section.hosts.map((host) => (
                            <HostRow
                              key={`${host.source_file}::${host.alias}`}
                              host={host}
                              active={host.alias === selectedAlias}
                              delay={nextDelay()}
                              variant="host"
                              onSelect={() => setSelectedAlias(host.alias)}
                              onConnect={() => connectTo(host.alias)}
                            />
                          ))}
                        </ul>
                      )}
                      {section.defaults.length > 0 && (
                        <>
                          <DefaultsLabel />
                          <ul className="space-y-px">
                            {section.defaults.map((host) => (
                              <HostRow
                                key={`${host.source_file}::${host.alias}`}
                                host={host}
                                active={host.alias === selectedAlias}
                                delay={nextDelay()}
                                variant="defaults"
                                onSelect={() => setSelectedAlias(host.alias)}
                              />
                            ))}
                          </ul>
                        </>
                      )}
                    </>
                  )}
                </div>
              );
            })
          )}
        </div>
      </div>
    </div>
  );
}

/** Skeleton placeholder rows while the host list loads. */
function HostListSkeleton() {
  return (
    <div className="space-y-4 pt-1.5" aria-hidden>
      {[0, 1].map((g) => (
        <div key={g}>
          <Skeleton className="mx-2 mb-2 h-3 w-20" />
          <div className="space-y-px">
            {[0, 1, 2].map((r) => (
              <div key={r} className="flex h-7 items-center gap-2 px-2">
                <Skeleton className="size-3.5 shrink-0 rounded" />
                <Skeleton className="h-3 w-2/5" />
                <Skeleton className="ml-auto h-2.5 w-1/3" />
              </div>
            ))}
          </div>
        </div>
      ))}
    </div>
  );
}

/** Friendly empty state when no hosts exist at all. */
function EmptyHosts() {
  return (
    <div className="flex flex-col items-center gap-3 px-4 py-12 text-center select-none">
      <div className="flex size-10 items-center justify-center rounded-lg bg-muted text-muted-foreground ring-1 ring-border">
        <ServerOff className="size-5" />
      </div>
      <div className="space-y-0.5">
        <p className="text-sm font-medium">No hosts yet</p>
        <p className="text-xs text-muted-foreground">
          Add your first SSH host to get started.
        </p>
      </div>
      <AddHostDialog variant="labeled" />
    </div>
  );
}

export default HostList;
