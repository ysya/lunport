import type { HostSummary } from "@/bindings/HostSummary";

/**
 * Derive a short, DISTINCT secondary line for a host row from its resolved
 * connection target — `user@hostname`, or whichever is present. Falls back to
 * extra (wildcard) patterns, and finally to `null` so callers render NO second
 * line rather than duplicating the alias.
 */
export function secondaryLine(host: HostSummary): string | null {
  const hostname = host.hostname?.trim() ?? "";
  const user = host.user?.trim() ?? "";
  if (user && hostname) return `${user}@${hostname}`;
  if (hostname) return hostname;
  if (user) return user;
  const extra = host.patterns.filter((p) => p !== host.alias);
  if (extra.length > 0) return extra.join(", ");
  return null;
}

/**
 * Map each source-file path to the shortest trailing path-segment label unique
 * among `files`. The first file to claim a basename keeps it; later collisions
 * extend by prepending one more path segment. Comparison is case-insensitive.
 */
export function shortLabels(files: string[]): Map<string, string> {
  const used = new Set<string>();
  const map = new Map<string, string>();
  for (const f of files) {
    const segs = f.split("/").filter(Boolean);
    let n = 1;
    let label = segs[segs.length - 1] ?? f;
    while (used.has(label.toLowerCase()) && n < segs.length) {
      n += 1;
      label = segs.slice(segs.length - n).join("/");
    }
    used.add(label.toLowerCase());
    map.set(f, label);
  }
  return map;
}
