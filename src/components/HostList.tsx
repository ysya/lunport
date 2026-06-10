import { useMemo } from "react";
import { Search, ServerOff, Server, Globe, ChevronRight, Play } from "lucide-react";

import type { HostSummary } from "@/bindings/HostSummary";
import { useUiStore } from "@/stores/ui";
import { useConnect } from "@/lib/queries";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Skeleton } from "@/components/ui/skeleton";
import { AddHostDialog } from "@/components/AddHostDialog";
import { cn, basename } from "@/lib/utils";
import { secondaryLine, shortLabels } from "@/lib/host-display";

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
  const terminalId = useUiStore((s) => s.terminalId);
  const connect = useConnect();

  const grouped = useMemo(() => {
    const q = search.trim().toLowerCase();
    const filtered = hosts.filter((h) => matches(h, q));

    // Group by source_file, preserving first-appearance order.
    const byFile = new Map<string, HostSummary[]>();
    for (const h of filtered) {
      const bucket = byFile.get(h.source_file);
      if (bucket) bucket.push(h);
      else byFile.set(h.source_file, [h]);
    }

    // Compute distinct shortest-unique labels across all loaded source files
    // (first-appearance order, de-duplicated). NOTE: we label over the full
    // unfiltered set so labels stay stable while searching.
    const allFiles = [...new Map(hosts.map((h) => [h.source_file, true])).keys()];
    const labels = shortLabels(allFiles);

    return [...byFile.entries()].map(([file, fileHosts]) => ({
      file,
      name: labels.get(file) ?? basename(file),
      hosts: fileHosts,
    }));
  }, [hosts, search]);

  const totalShown = grouped.reduce((n, g) => n + g.hosts.length, 0);
  // When a search is active, force-expand all groups so results are never hidden.
  const searchActive = search.trim().length > 0;

  // A running index across all rows so the staggered enter animation reads as a
  // single cascade rather than restarting per group.
  let rowIndex = -1;

  return (
    <div className="flex h-full min-h-0 flex-col">
      <div className="shrink-0 border-b p-2">
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
      </div>

      <ScrollArea className="min-h-0 flex-1">
        <div className="p-1.5">
          {isLoading ? (
            <HostListSkeleton />
          ) : totalShown === 0 ? (
            hosts.length === 0 ? (
              <EmptyHosts />
            ) : (
              <p className="px-2 py-10 text-center text-sm text-muted-foreground">
                No hosts match{" "}
                <span className="font-mono text-foreground">“{search.trim()}”</span>.
              </p>
            )
          ) : (
            grouped.map((group) => {
              const isCollapsed = !searchActive && collapsedGroups.includes(group.file);
              return (
              <div key={group.file} className="mb-3">
                <button
                  type="button"
                  onClick={() => toggleGroup(group.file)}
                  className="flex w-full items-center justify-between px-2 py-1 select-none rounded-sm hover:bg-muted/50 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring/50 cursor-default"
                  title={group.file}
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
                    <span
                      className="truncate text-[0.6875rem] font-semibold tracking-[0.08em] text-muted-foreground uppercase"
                    >
                      {group.name}
                    </span>
                  </span>
                  <span className="font-mono text-[0.6875rem] text-muted-foreground/70 tabular-nums">
                    {group.hosts.length}
                  </span>
                </button>
                {!isCollapsed && (
                <ul className="space-y-px">
                  {group.hosts.map((host) => {
                    const active = host.alias === selectedAlias;
                    rowIndex += 1;
                    const delay = `${Math.min(rowIndex, 16) * 22}ms`;
                    const secondary = secondaryLine(host);
                    return (
                      <li
                        key={`${host.source_file}::${host.alias}`}
                        className="animate-row-enter group/row relative"
                        style={{ animationDelay: delay }}
                      >
                        {/*
                         * Source-list row: leading monochrome glyph anchor +
                         * dense content. Selection is ONE quiet cue — an inset
                         * accent-tinted pill (radius 6) with slightly stronger
                         * text. No left bar, no border, no colored alias.
                         */}
                        <button
                          type="button"
                          onClick={() => setSelectedAlias(host.alias)}
                          aria-current={active ? "true" : undefined}
                          className={cn(
                            "group flex w-full items-start gap-2 rounded-[6px] py-1.5 pr-9 pl-2 text-left transition-colors duration-100 select-none",
                            "hover:bg-muted/70 focus-visible:bg-muted/70 focus-visible:ring-2 focus-visible:ring-ring/50 focus-visible:outline-none",
                            active && "bg-primary/12 hover:bg-primary/15",
                          )}
                        >
                          <span className="flex h-[18px] items-center">
                            <HostGlyph host={host} />
                          </span>
                          <span className="flex min-w-0 flex-1 flex-col gap-0.5">
                            <span
                              className={cn(
                                "truncate text-[0.8125rem] leading-[18px] font-medium",
                                active ? "text-foreground" : "text-foreground/90",
                              )}
                            >
                              {host.alias}
                            </span>
                            {secondary && (
                              <span className="truncate font-mono text-xs leading-tight text-muted-foreground">
                                {secondary}
                              </span>
                            )}
                            {host.tags.length > 0 && (
                              <span className="flex flex-wrap gap-1 pt-0.5">
                                {host.tags.map((tag) => (
                                  <Badge
                                    key={tag}
                                    variant="outline"
                                    className="border-border/70 font-mono text-[0.65rem] font-normal text-muted-foreground"
                                  >
                                    {tag}
                                  </Badge>
                                ))}
                              </span>
                            )}
                          </span>
                        </button>
                        {/*
                         * Connect affordance — overlays the row's right edge,
                         * hidden until the row is hovered/focused (or the button
                         * itself is focused for keyboard users). Stops propagation
                         * so it never also selects the row.
                         */}
                        <Button
                          type="button"
                          variant="ghost"
                          size="icon"
                          aria-label={`Connect to ${host.alias}`}
                          title={`Connect to ${host.alias}`}
                          onClick={(e) => {
                            e.stopPropagation();
                            connect.mutate({ alias: host.alias, terminalOverride: terminalId });
                          }}
                          className="absolute top-1/2 right-1.5 size-6 -translate-y-1/2 text-muted-foreground opacity-0 transition-opacity hover:text-foreground focus-visible:opacity-100 group-hover/row:opacity-100"
                        >
                          <Play className="size-3.5" />
                        </Button>
                      </li>
                    );
                  })}
                </ul>
                )}
              </div>
              );
            })
          )}
        </div>
      </ScrollArea>
    </div>
  );
}

/** Skeleton placeholder rows while the host list loads. */
function HostListSkeleton() {
  return (
    <div className="space-y-4" aria-hidden>
      {[0, 1].map((g) => (
        <div key={g}>
          <Skeleton className="mx-2 mb-2 h-3 w-20" />
          <div className="space-y-px">
            {[0, 1, 2].map((r) => (
              <div key={r} className="flex items-start gap-2 px-2 py-1.5">
                <Skeleton className="mt-0.5 size-3.5 shrink-0 rounded" />
                <div className="flex-1 space-y-1.5">
                  <Skeleton className="h-3 w-2/3" />
                  <Skeleton className="h-2.5 w-1/2" />
                </div>
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
