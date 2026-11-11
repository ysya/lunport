import { useEffect, useState } from "react";

/**
 * `value` once it has stopped changing for `delayMs`. The first value shows at once, and a later one shows only when no other has
 * followed it within the delay, so that text typed one character at a time is read as the text it ends up as, not as every start of it:
 * a project id typed by hand is a project id at a dozen lengths, and Google need not be asked about each. For values that compare by
 * `Object.is` (text, numbers, `null`).
 */
export function useDebounced<T>(value: T, delayMs: number): T {
  const [settled, setSettled] = useState(value);
  useEffect(() => {
    if (Object.is(value, settled)) return;
    const timer = setTimeout(() => setSettled(value), delayMs);
    return () => clearTimeout(timer);
    // `settled` is not a dependency: it changes only when this timer sets it, and then there is nothing left to wait for.
  }, [value, delayMs]);
  return settled;
}
