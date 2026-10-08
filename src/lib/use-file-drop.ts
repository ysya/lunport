import { useEffect, useRef } from "react";
import { getCurrentWebview } from "@tauri-apps/api/webview";

/** The one path of a single-file drop, or null (several files, no files, or not a drop). Exported for the tests. */
export function droppedPath(event: { type: string; paths?: string[] }): string | null {
  return event.type === "drop" && event.paths?.length === 1 ? event.paths[0] : null;
}

/**
 * Calls `onPath` with a key file dropped onto the window while `enabled`. Tauri delivers file drops as its own event (with
 * `dragDropEnabled` at its default the webview gets no DOM file drops); it carries absolute paths, and the backend reads the file.
 */
export function useFileDrop(enabled: boolean, onPath: (path: string) => void): void {
  const latest = useRef(onPath);
  useEffect(() => {
    latest.current = onPath;
  });
  useEffect(() => {
    if (!enabled) return;
    let unlisten: (() => void) | null = null;
    let gone = false;
    void getCurrentWebview()
      .onDragDropEvent((event) => {
        const path = droppedPath(event.payload);
        if (path !== null) latest.current(path);
      })
      .then(
        (stop) => {
          if (gone) stop();
          else unlisten = stop;
        },
        // Without the listener a drop does nothing; "Choose a file…" still works, so this stays quiet (as `useCheckUnknownRelay` does).
        () => undefined,
      );
    return () => {
      gone = true;
      unlisten?.();
    };
  }, [enabled]);
}
