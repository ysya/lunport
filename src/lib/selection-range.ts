/**
 * Shift-click range for the sidebar's multi-select: every alias between the
 * anchor (last plain/⌘ click) and the target, in visible order, inclusive.
 * A missing anchor degrades to just the target; a missing target to nothing.
 */
export function rangeBetween(
  visible: string[],
  anchor: string | null,
  target: string,
): string[] {
  const targetAt = visible.indexOf(target);
  if (targetAt === -1) return [];
  const anchorAt = anchor === null ? -1 : visible.indexOf(anchor);
  if (anchorAt === -1) return [target];
  const [lo, hi] =
    anchorAt <= targetAt ? [anchorAt, targetAt] : [targetAt, anchorAt];
  return visible.slice(lo, hi + 1);
}
