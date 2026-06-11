import { useEffect } from "react";

import { useUiStore } from "@/stores/ui";

/** DOM id of the host-search input (HostList) — the ⌘F focus target. */
export const SEARCH_INPUT_ID = "host-search-input";

/**
 * True when the event originates from a text-editing context (input, textarea,
 * contenteditable) — where app-level single-purpose shortcuts must stay out of
 * the way. Pure — testable.
 */
export function isTypingContext(target: EventTarget | null): boolean {
  if (!(target instanceof HTMLElement)) return false;
  if (target instanceof HTMLInputElement || target instanceof HTMLTextAreaElement) {
    return true;
  }
  return target.isContentEditable;
}

/**
 * App-wide single-key-plus-modifier shortcuts (mounted once in App):
 *   - ⌘F / Ctrl+F → focus the host-search input (and suppress the WebView's
 *     native find). Ignored while typing elsewhere; pressing it IN the search
 *     input just re-selects the query.
 *   - ⌘N / Ctrl+N → open the Add-host dialog. Same typing-context guard.
 *
 * ⌘K (palette) and ⌘, (settings) live with their components; this hook only
 * owns shortcuts that have no natural component home.
 */
export function useAppShortcuts(): void {
  const setAddHostOpen = useUiStore((s) => s.setAddHostOpen);

  useEffect(() => {
    const onKeyDown = (e: KeyboardEvent) => {
      if (!(e.metaKey || e.ctrlKey) || e.altKey || e.shiftKey) return;
      const key = e.key.toLowerCase();

      if (key === "f") {
        const search = document.getElementById(SEARCH_INPUT_ID);
        const inSearch = e.target === search;
        if (isTypingContext(e.target) && !inSearch) return;
        // Suppress the WebView's built-in find UI in all handled cases.
        e.preventDefault();
        if (search instanceof HTMLInputElement) {
          search.focus();
          search.select();
        }
      } else if (key === "n") {
        if (isTypingContext(e.target)) return;
        e.preventDefault();
        setAddHostOpen(true);
      }
    };
    window.addEventListener("keydown", onKeyDown);
    return () => window.removeEventListener("keydown", onKeyDown);
  }, [setAddHostOpen]);
}
