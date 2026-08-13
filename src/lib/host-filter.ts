import type { HostSummary } from "@/bindings/HostSummary";

/**
 * Sidebar search grammar: whitespace-separated terms, ANDed together.
 * `#x` filters by tag, `@x` by user, anything else is free text across the
 * host's searchable fields. A bare `#` or `@` is mid-typing, not a filter.
 */
export interface ParsedQuery {
  tags: string[];
  users: string[];
  texts: string[];
}

export function parseQuery(q: string): ParsedQuery {
  const parsed: ParsedQuery = { tags: [], users: [], texts: [] };
  for (const raw of q.trim().toLowerCase().split(/\s+/)) {
    if (raw === "" || raw === "#" || raw === "@") continue;
    if (raw.startsWith("#")) parsed.tags.push(raw.slice(1));
    else if (raw.startsWith("@")) parsed.users.push(raw.slice(1));
    else parsed.texts.push(raw);
  }
  return parsed;
}

export function hostMatches(host: HostSummary, q: ParsedQuery): boolean {
  if (q.tags.length > 0) {
    const tags = host.tags.map((t) => t.toLowerCase());
    if (!q.tags.every((t) => tags.some((tag) => tag.includes(t)))) return false;
  }

  if (q.users.length > 0) {
    const user = host.user?.toLowerCase();
    if (!user || !q.users.every((u) => user.includes(u))) return false;
  }

  if (q.texts.length > 0) {
    const hay = [
      host.alias,
      ...host.patterns,
      ...host.tags,
      host.source_file,
      host.hostname ?? "",
      host.user ?? "",
    ]
      .join(" ")
      .toLowerCase();
    if (!q.texts.every((t) => hay.includes(t))) return false;
  }

  return true;
}
