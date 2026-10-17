import type { RecordGroupView } from "@/lib/records";

export function groupComparator(ids: readonly string[]) {
  const rank = new Map(ids.map((id, index) => [id, index]));
  return (a: RecordGroupView, b: RecordGroupView) =>
    (rank.get(a.id) ?? Number.MAX_SAFE_INTEGER) - (rank.get(b.id) ?? Number.MAX_SAFE_INTEGER)
    || a.payload.name.localeCompare(b.payload.name) || a.id.localeCompare(b.id);
}

/** Replace sibling positions while retaining ranks for collapsed/unselected groups. */
export function moveGroup(
  ids: readonly string[], siblings: readonly string[], moving: string, target: string,
  side: "before" | "after",
): string[] | null {
  if (moving === target || !siblings.includes(moving) || !siblings.includes(target)) return null;
  const reordered = siblings.filter((id) => id !== moving);
  reordered.splice(reordered.indexOf(target) + (side === "after" ? 1 : 0), 0, moving);
  const base = [...ids, ...siblings.filter((id) => !ids.includes(id))];
  const members = new Set(siblings);
  let index = 0;
  const result = base.map((id) => members.has(id) ? reordered[index++] : id);
  return result.every((id, i) => id === ids[i]) && result.length === ids.length ? null : result;
}
