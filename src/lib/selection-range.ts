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

/** What a click on a sidebar row does to the multi-selection. */
export type RowClick =
  /** ⌘/Ctrl-click: check or uncheck the row. */
  | "toggle"
  /** Shift-click: check every row from the anchor to this one. */
  | "range"
  /** ⌘/Ctrl- or Shift-click on a row that cannot be checked: select it, leave the checked rows as they are. */
  | "keep"
  /** A plain click: select the row, clear the checked rows. */
  | "select";

/**
 * Which of those a click is. `checkable` false: the row cannot join the multi-selection (a name with several
 * copies, which the batch actions would resolve by name), so a modified click neither adds it nor — as a
 * plain click does — clears the rows the user already checked.
 */
export function rowClickKind(
  keys: { metaKey: boolean; ctrlKey: boolean; shiftKey: boolean },
  checkable: boolean,
): RowClick {
  const toggle = keys.metaKey || keys.ctrlKey;
  if (!toggle && !keys.shiftKey) return "select";
  if (!checkable) return "keep";
  return toggle ? "toggle" : "range";
}
