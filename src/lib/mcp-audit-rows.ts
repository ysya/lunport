/** Request IDs are process-local. Historical events can even have identical timestamps.
 * These rows are stateless: identical events use occurrence order within the current view.
 */
export function auditRows<T extends { id: string }>(entries: readonly T[]) {
  const occurrences = new Map<string, number>();
  return entries.slice(0, 10).map((entry) => {
    const identity = JSON.stringify(entry);
    const occurrence = occurrences.get(identity) ?? 0;
    occurrences.set(identity, occurrence + 1);
    return { entry, key: JSON.stringify([identity, occurrence]) };
  });
}
