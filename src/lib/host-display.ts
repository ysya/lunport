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
 * Path segments that carry no identity on their own — extending a colliding
 * label with one of these (e.g. `ssh/config` for OrbStack's
 * `~/.orbstack/ssh/config`) reads as noise, so the disambiguator skips past
 * them to the first DISTINCTIVE ancestor instead.
 */
const GENERIC_SEGMENTS = new Set(["ssh", ".ssh", "etc", "config.d", "conf.d", "ssh_config.d"]);

/** A segment rendered as a label: leading dots stripped (`.orbstack` → `orbstack`). */
function displaySegment(seg: string): string {
  const stripped = seg.replace(/^\.+/, "");
  return stripped.length > 0 ? stripped : seg;
}

/**
 * Map each source-file path to a short label unique among `files`. The first
 * file to claim a basename keeps it; later collisions are labeled by their
 * nearest DISTINCTIVE ancestor directory (skipping generic segments like
 * `ssh`/`config.d`), so `~/.orbstack/ssh/config` shows as `orbstack` rather
 * than `ssh/config`. Falls back to progressively longer trailing paths when no
 * distinctive ancestor exists. Comparison is case-insensitive.
 */
export function shortLabels(files: string[]): Map<string, string> {
  const used = new Set<string>();
  const map = new Map<string, string>();
  const claim = (label: string): boolean => {
    if (used.has(label.toLowerCase())) return false;
    used.add(label.toLowerCase());
    return true;
  };

  for (const f of files) {
    const segs = f.split("/").filter(Boolean);
    const basename = segs[segs.length - 1] ?? f;
    if (claim(basename)) {
      map.set(f, basename);
      continue;
    }

    // Collision: prefer the nearest non-generic ancestor as the identity.
    const anchor = [...segs.slice(0, -1)]
      .reverse()
      .find((s) => !GENERIC_SEGMENTS.has(s.toLowerCase()));
    if (anchor) {
      const label = displaySegment(anchor);
      if (claim(label)) {
        map.set(f, label);
        continue;
      }
    }

    // Fall back: extend with progressively longer trailing paths.
    let n = 1;
    let label = basename;
    while (used.has(label.toLowerCase()) && n < segs.length) {
      n += 1;
      label = segs.slice(segs.length - n).join("/");
    }
    used.add(label.toLowerCase());
    map.set(f, label);
  }
  return map;
}

/**
 * True when EVERY pattern of the host block is a wildcard (contains `*` or
 * `?`), e.g. `Host *` or `Host *.web`. These blocks supply config DEFAULTS —
 * they are not connectable hosts, so the sidebar demotes them to a "Defaults"
 * footer and excludes them from host counts.
 */
export function isWildcardOnly(host: HostSummary): boolean {
  return (
    host.patterns.length > 0 && host.patterns.every((p) => p.includes("*") || p.includes("?"))
  );
}
