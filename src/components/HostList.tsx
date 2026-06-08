import { useMemo } from "react";
import type { HostSummary } from "@/bindings/HostSummary";
import { useUiStore } from "@/stores/ui";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import { ScrollArea } from "@/components/ui/scroll-area";
import { cn } from "@/lib/utils";

const UNGROUPED = "Ungrouped";

/** Last path segment of a (possibly `/`- or `\`-separated) file path. */
function basename(p: string): string {
  const norm = p.replace(/\\/g, "/");
  const parts = norm.split("/");
  return parts[parts.length - 1] || p;
}

/** True if the host matches the (lowercased) search term across its searchable fields. */
function matches(host: HostSummary, q: string): boolean {
  if (!q) return true;
  const hay = [
    host.alias,
    ...host.patterns,
    host.group ?? "",
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

    const byGroup = new Map<string, HostSummary[]>();
    for (const h of filtered) {
      const g = h.group && h.group.trim() !== "" ? h.group : UNGROUPED;
      const bucket = byGroup.get(g);
      if (bucket) bucket.push(h);
      else byGroup.set(g, [h]);
    }

    // Stable, alphabetical group order with "Ungrouped" last.
    const names = [...byGroup.keys()].sort((a, b) => {
      if (a === UNGROUPED) return 1;
      if (b === UNGROUPED) return -1;
      return a.localeCompare(b);
    });

    return names.map((name) => ({ name, hosts: byGroup.get(name)! }));
  }, [hosts, search]);

  const totalShown = grouped.reduce((n, g) => n + g.hosts.length, 0);

  return (
    <div className="flex h-full flex-col">
      <div className="border-b p-3">
        <Input
          type="search"
          placeholder="Search hosts…"
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          aria-label="Search hosts"
        />
      </div>

      <ScrollArea className="flex-1">
        <div className="p-2">
          {isLoading ? (
            <p className="px-2 py-8 text-center text-sm text-muted-foreground">
              Loading hosts…
            </p>
          ) : totalShown === 0 ? (
            <p className="px-2 py-8 text-center text-sm text-muted-foreground">
              {hosts.length === 0 ? "No hosts found." : "No hosts match your search."}
            </p>
          ) : (
            grouped.map((group) => (
              <div key={group.name} className="mb-3">
                <div className="px-2 py-1 text-xs font-medium tracking-wide text-muted-foreground uppercase">
                  {group.name}
                </div>
                <ul className="space-y-0.5">
                  {group.hosts.map((host) => {
                    const active = host.alias === selectedAlias;
                    return (
                      <li key={`${host.source_file}::${host.alias}`}>
                        <button
                          type="button"
                          onClick={() => setSelectedAlias(host.alias)}
                          aria-current={active ? "true" : undefined}
                          className={cn(
                            "flex w-full flex-col gap-1 rounded-md px-2 py-1.5 text-left text-sm transition-colors",
                            "hover:bg-muted focus-visible:bg-muted focus-visible:outline-none",
                            active && "bg-muted",
                          )}
                        >
                          <div className="flex items-center justify-between gap-2">
                            <span className="truncate font-medium">{host.alias}</span>
                            <Badge
                              variant="secondary"
                              className="shrink-0 font-normal"
                              title={host.source_file}
                            >
                              {basename(host.source_file)}
                            </Badge>
                          </div>
                          {host.tags.length > 0 && (
                            <div className="flex flex-wrap gap-1">
                              {host.tags.map((tag) => (
                                <Badge
                                  key={tag}
                                  variant="outline"
                                  className="font-normal text-muted-foreground"
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

export default HostList;
