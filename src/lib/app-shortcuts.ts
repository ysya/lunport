/** DOM id of the host-search input (HostList), the ⌘F focus target. */
export const SEARCH_INPUT_ID = "host-search-input";

/**
 * True when the event originates from a text-editing context (input, textarea,
 * contenteditable), where app-level single-purpose shortcuts must stay out of
 * the way. Pure, testable.
 */
export function isTypingContext(target: EventTarget | null): boolean {
  if (!(target instanceof HTMLElement)) return false;
  if (target instanceof HTMLInputElement || target instanceof HTMLTextAreaElement) {
    return true;
  }
  return target.isContentEditable;
}
