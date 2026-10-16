import type { RecordHostView, RecordOverview } from "@/lib/records";
import { groupAncestors, recordHostSearchText } from "./group-tree";

export type LibraryFilter =
  | { kind: "all" | "recent" | "attention" | "ungrouped" }
  | { kind: "group" | "tag"; id: string };

export const recentHostKey = (id: string) => `records:${id}`;

export function hostNeedsAttention(host: RecordHostView): boolean {
  return host.readiness.kind !== "ready" || !!host.group_error;
}

export function libraryHosts(
  overview: RecordOverview,
  filter: LibraryFilter,
  search: string,
  recent: Record<string, number>,
): RecordHostView[] {
  const words = search.toLocaleLowerCase().trim().split(/\s+/).filter(Boolean);
  const counts = new Map<string, number>();
  for (const host of overview.hosts)
    counts.set(host.id, (counts.get(host.id) ?? 0) + 1);
  return overview.hosts
    .filter((host) => {
      if (filter.kind === "recent" && !recent[recentHostKey(host.id)])
        return false;
      if (
        filter.kind === "attention" &&
        !hostNeedsAttention(host) &&
        counts.get(host.id) === 1
      )
        return false;
      if (filter.kind === "ungrouped" && host.payload.group_id) return false;
      if (filter.kind === "tag" && !host.payload.tags.includes(filter.id))
        return false;
      if (
        filter.kind === "group" &&
        !groupAncestors(
          overview,
          host.payload.group_id,
          host.scope,
        ).groups.some((g) => g.id === filter.id)
      )
        return false;
      const text = recordHostSearchText(overview, host).toLocaleLowerCase();
      return words.every((word) => text.includes(word));
    })
    .sort((a, b) =>
      filter.kind === "recent"
        ? recent[recentHostKey(b.id)] - recent[recentHostKey(a.id)] ||
          a.payload.alias.localeCompare(b.payload.alias)
        : a.payload.alias.localeCompare(b.payload.alias) ||
          a.id.localeCompare(b.id),
    );
}
