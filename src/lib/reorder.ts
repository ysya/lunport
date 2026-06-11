import { isWildcardOnly } from "@/lib/host-display";

/**
 * The minimal host shape the reorder math needs. Structurally satisfied by
 * `HostSummary` — kept narrow so tests can build fixtures without the full type.
 */
export interface ReorderableHost {
  /** First pattern token — the identity `config_reorder_hosts` matches on. */
  alias: string;
  patterns: string[];
}

/**
 * Build the COMPLETE alias order for `config_reorder_hosts` after dragging one
 * concrete host within a file.
 *
 * Backend contract (`edit::reorder_hosts`): aliases named in `order` are placed
 * FIRST (in the given sequence) and any host block NOT named is pushed AFTER
 * all named ones. The order must therefore be exhaustive — omitting the
 * wildcard-only DEFAULTS blocks (`Host *`) would shove them to the end of the
 * file and change config semantics. This helper keeps them pinned: wildcard
 * blocks retain their absolute slot among the file's host blocks, and only the
 * CONCRETE hosts are permuted around them.
 *
 * @param fileHosts ALL host blocks of ONE file, in document order — including
 *   wildcard-only blocks.
 * @param fromIdx Index of the dragged host within the CONCRETE (non-wildcard)
 *   subsequence of `fileHosts`.
 * @param toIdx Insertion gap within that same concrete subsequence, measured
 *   BEFORE removal of the dragged item: `0` = before the first concrete host,
 *   `n` = after the last. `toIdx === fromIdx` and `toIdx === fromIdx + 1` are
 *   no-ops.
 * @returns The full alias order for every host block in the file. If `fromIdx`
 *   is out of range the current order is returned unchanged.
 */
export function buildNewOrder(
  fileHosts: readonly ReorderableHost[],
  fromIdx: number,
  toIdx: number,
): string[] {
  // Aliases of the concrete (draggable) subsequence, in document order.
  const concrete = fileHosts.filter((h) => !isWildcardOnly(h)).map((h) => h.alias);

  if (fromIdx < 0 || fromIdx >= concrete.length) {
    return fileHosts.map((h) => h.alias);
  }

  // Move within the concrete subsequence. The gap index was measured against
  // the list BEFORE removal, so gaps past the source shift down by one.
  const gap = Math.max(0, Math.min(toIdx, concrete.length));
  const [moved] = concrete.splice(fromIdx, 1);
  concrete.splice(gap > fromIdx ? gap - 1 : gap, 0, moved!);

  // Rebuild the full order: wildcard blocks keep their absolute slots, the
  // remaining slots take the reordered concrete sequence.
  let c = 0;
  return fileHosts.map((h) => (isWildcardOnly(h) ? h.alias : concrete[c++]!));
}

/**
 * Apply a `config_reorder_hosts` order to the cached global host list —
 * the optimistic mirror of the backend edit. Only hosts of `file` move; their
 * positions WITHIN the global array are kept and refilled in the new order
 * (other files' hosts are untouched).
 *
 * Mirrors the backend's matching semantics exactly: each alias in `order`
 * consumes the first unused block matching ANY of its patterns; blocks not
 * named keep their relative order AFTER the named ones.
 */
export function applyOrderToHosts<
  H extends ReorderableHost & { source_file: string },
>(hosts: readonly H[], file: string, order: readonly string[]): H[] {
  const slots: number[] = [];
  const fileHosts: H[] = [];
  hosts.forEach((h, i) => {
    if (h.source_file === file) {
      slots.push(i);
      fileHosts.push(h);
    }
  });

  const used = new Array<boolean>(fileHosts.length).fill(false);
  const reordered: H[] = [];
  for (const alias of order) {
    const i = fileHosts.findIndex((h, idx) => !used[idx] && h.patterns.includes(alias));
    if (i !== -1) {
      used[i] = true;
      reordered.push(fileHosts[i]!);
    }
  }
  fileHosts.forEach((h, i) => {
    if (!used[i]) reordered.push(h);
  });

  const out = [...hosts];
  slots.forEach((slot, i) => {
    out[slot] = reordered[i]!;
  });
  return out;
}
