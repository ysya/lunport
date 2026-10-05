import { useEffect, useState } from "react";

/**
 * The current time, refreshed every `intervalMs`. Relative times ("last sync 2m ago") are worked out
 * from it, so they keep moving while nothing else re-renders: a query that did not change does not.
 */
export function useNow(intervalMs = 30_000): number {
  const [now, setNow] = useState(() => Date.now());
  useEffect(() => {
    const id = window.setInterval(() => setNow(Date.now()), intervalMs);
    return () => window.clearInterval(id);
  }, [intervalMs]);
  return now;
}
