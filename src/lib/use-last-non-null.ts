import { useRef } from "react";

/**
 * The latest value that was not null. A dialog opened for a row (or a request) is closed by setting that
 * row to null, but it takes a moment to animate out; reading what it showed from here keeps its title and
 * text from going empty (`Stop syncing “”…`) during that moment.
 */
export function useLastNonNull<T>(value: T | null): T | null {
  const last = useRef<T | null>(value);
  if (value !== null) last.current = value;
  return last.current;
}
