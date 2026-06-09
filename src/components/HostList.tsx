import { useMemo } from "react";
import { Search, ServerOff } from "lucide-react";

import type { HostSummary } from "@/bindings/HostSummary";
import { useUiStore } from "@/stores/ui";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Skeleton } from "@/components/ui/skeleton";
import { AddHostDialog } from "@/components/AddHostDialog";
import { cn, basename } from "@/lib/utils";

/**
 * Derive a short, DISTINCT secondary line for a host row from its resolved
 * connection target — `user@hostname`, or whichever is present. Falls back to
 * extra (wildcard) patterns, and finally to `null` so we render NO second line
 * rather than duplicating the alias.
 */
function secondaryLine(host: HostSummary): string | null {
  const hostname = host.hostname?.trim() ?? "";
  const user = host.user?.trim() ?? "";
  if (user && hostname) return `${user}@${hostname}`;
  if (hostname) return hostname;
  if (user) return user;
  const extra = host.patterns.filter((p) => p !== host.alias);
  if (extra.length > 0) return extra.join(", ");
  return null;
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

    return [...byFile.entries()].map(([file, fileHosts]) => ({
      file,
      name: basename(file),
      hosts: fileHosts,
    }));
  }, [hosts, search]);

  const totalShown = grouped.reduce((n, g) => n + g.hosts.length, 0);

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
            className="h-7 pl-8 font-mono text-sm placeholder:font-sans"
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
            grouped.map((group) => (
              <div key={group.file} className="mb-3">
                <div className="flex items-center justify-between px-2 py-1">
                  <span
                    className="text-[0.65rem] font-semibold tracking-[0.12em] text-muted-foreground uppercase"
                    title={group.file}
                  >
                    {group.name}
                  </span>
                  <span className="font-mono text-[0.65rem] text-muted-foreground/70 tabular-nums">
                    {group.hosts.length}
                  </span>
                </div>
                <ul className="space-y-0.5">
                  {group.hosts.map((host) => {
                    const active = host.alias === selectedAlias;
                    rowIndex += 1;
                    const delay = `${Math.min(rowIndex, 16) * 22}ms`;
                    const secondary = secondaryLine(host);
                    return (
                      <li
                        key={`${host.source_file}::${host.alias}`}
                        className="animate-row-enter"
                        style={{ animationDelay: delay }}
                      >
                        <button
                          type="button"
                          onClick={() => setSelectedAlias(host.alias)}
                          aria-current={active ? "true" : undefined}
                          className={cn(
                            "group relative flex w-full flex-col gap-0.5 rounded-md border border-transparent py-1.5 pr-2 pl-2.5 text-left transition-colors",
                            "hover:bg-muted/70 focus-visible:bg-muted/70 focus-visible:ring-2 focus-visible:ring-ring/60 focus-visible:outline-none",
                            active && "border-primary/20 bg-primary/10 hover:bg-primary/15",
                          )}
                        >
                          <span
                            aria-hidden
                            className={cn(
                              "absolute top-1.5 bottom-1.5 left-0 w-0.5 rounded-full bg-primary transition-opacity",
                              active ? "opacity-100" : "opacity-0",
                            )}
                          />
                          <div className="flex items-center justify-between gap-2">
                            <span
                              className={cn(
                                "truncate font-mono text-sm font-medium",
                                active && "text-primary",
                              )}
                            >
                              {host.alias}
                            </span>
                          </div>
                          {secondary && (
                            <span className="truncate font-mono text-xs text-muted-foreground">
                              {secondary}
                            </span>
                          )}
                          {host.tags.length > 0 && (
                            <div className="flex flex-wrap gap-1 pt-0.5">
                              {host.tags.map((tag) => (
                                <Badge
                                  key={tag}
                                  variant="outline"
                                  className="border-border/70 font-mono text-[0.65rem] font-normal text-muted-foreground"
                                >
                                  {tag}
                                </Badge>
                              ))}
                            </div>
                          )}
                        </button>
                      </li>
                    );
                  })}
                </ul>
              </div>
            ))
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
          <div className="space-y-1.5">
            {[0, 1, 2].map((r) => (
              <div key={r} className="space-y-1.5 px-3 py-2">
                <Skeleton className="h-3.5 w-2/3" />
                <Skeleton className="h-3 w-1/2" />
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
    <div className="flex flex-col items-center gap-3 px-4 py-12 text-center">
      <div className="flex size-10 items-center justify-center rounded-lg bg-muted/60 text-muted-foreground ring-1 ring-border">
        <ServerOff className="size-5" />
      </div>
      <div className="space-y-0.5">
        <p className="text-sm font-medium">No hosts yet</p>
        <p className="text-xs text-muted-foreground">
          Add your first SSH host to get started.
        </p>
      </div>
      <AddHostDialog />
    </div>
  );
}

export default HostList;
