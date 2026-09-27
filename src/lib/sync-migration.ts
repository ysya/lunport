import type { HostSummary } from "@/bindings/HostSummary";

/**
 * Same rule as the backend's `hosts_file::is_syncable_block`: every pattern must be
 * a plain name. `Host web *.internal` or `Host web !prod` is a wildcard rule, not a
 * host — the sidebar's `isWildcardOnly` (all patterns wildcard, `!` ignored) is the
 * wrong predicate for sync.
 */
export function isSyncableHost(h: HostSummary): boolean {
  return h.patterns.length > 0 && h.patterns.every((p) => p !== "" && !/[*?!]/.test(p));
}

/**
 * Tidy a pasted recovery phrase before the backend validates it: one line,
 * single spaces, lowercase, no list numbering or stray punctuation.
 */
export function cleanWordsInput(raw: string): string {
  return raw
    .split(/\r?\n/)
    .map((line) => line.replace(/^\s*\d+\s*[.)\-:]?\s*/, ""))
    .join(" ")
    .toLowerCase()
    .replace(/[^a-z\s　]/g, " ")
    .replace(/[\s　]+/g, " ")
    .trim();
}

/**
 * Hosts that can still be moved into the synced file, grouped by their current file.
 * A local host that shares any name with a synced host is left out: a second block
 * for a synced name would make the synced file define it twice (the backend refuses
 * such moves), and right after Join these are exactly the local copies of hosts the
 * chain already has.
 */
export function groupHostsForMigration(
  hosts: HostSummary[],
  managedFile: string,
): { file: string; hosts: HostSummary[] }[] {
  const syncedNames = new Set(hosts.filter((h) => h.source_file === managedFile).flatMap((h) => h.patterns));
  const byFile = new Map<string, HostSummary[]>();
  for (const h of hosts) {
    if (h.source_file === managedFile || !isSyncableHost(h)) continue;
    if (h.patterns.some((p) => syncedNames.has(p))) continue;
    const bucket = byFile.get(h.source_file);
    if (bucket) bucket.push(h);
    else byFile.set(h.source_file, [h]);
  }
  return [...byFile.entries()].map(([file, hosts]) => ({ file, hosts }));
}

/**
 * The selection limited to hosts the wizard still lists. A selected host can
 * drop out of the list — e.g. a same-name local host once the first sync brings
 * in its synced twin — and must then neither count toward "Move N hosts" nor be
 * submitted. Returns `selected` itself when nothing was dropped, so a state
 * update with the result is a no-op.
 */
export function keepVisible(selected: Set<string>, groups: { hosts: { alias: string }[] }[]): Set<string> {
  const visible = new Set(groups.flatMap((g) => g.hosts.map((h) => h.alias)));
  const kept = new Set([...selected].filter((alias) => visible.has(alias)));
  return kept.size === selected.size ? selected : kept;
}
