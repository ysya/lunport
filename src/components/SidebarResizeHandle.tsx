import { useRef, useState, type KeyboardEvent, type PointerEvent, type RefObject } from "react";

import {
  DEFAULT_SIDEBAR_WIDTH,
  MAX_SIDEBAR_WIDTH,
  MIN_SIDEBAR_WIDTH,
  clampSidebarWidth,
  widthAfterDrag,
  widthAfterKey,
} from "@/lib/sidebar-width";
import { cn } from "@/lib/utils";
import { useUiStore } from "@/stores/ui";

/**
 * The drag handle on the sidebar's right edge. While dragging it sizes the sidebar element directly
 * (no re-render per pointer move) and stores the final width on release. Double-click restores the
 * default width; with focus, the arrow keys, Home and End resize it.
 */
export function SidebarResizeHandle({ sidebarRef }: { sidebarRef: RefObject<HTMLElement | null> }) {
  const width = clampSidebarWidth(useUiStore((s) => s.sidebarWidth));
  const setWidth = useUiStore((s) => s.setSidebarWidth);
  const drag = useRef<{ startX: number; startPx: number; remPx: number; width: number } | null>(null);
  const [dragging, setDragging] = useState(false);

  const onPointerDown = (e: PointerEvent<HTMLDivElement>) => {
    const sidebar = sidebarRef.current;
    if (e.button !== 0 || !sidebar) return;
    e.preventDefault();
    e.currentTarget.setPointerCapture(e.pointerId);
    drag.current = {
      startX: e.clientX,
      // The rendered width: it can be below the stored one when the window caps it.
      startPx: sidebar.getBoundingClientRect().width,
      remPx: Number.parseFloat(getComputedStyle(document.documentElement).fontSize) || 16,
      width,
    };
    document.documentElement.classList.add("sidebar-resizing");
    setDragging(true);
  };

  const onPointerMove = (e: PointerEvent<HTMLDivElement>) => {
    const d = drag.current;
    const sidebar = sidebarRef.current;
    if (!d || !sidebar) return;
    d.width = widthAfterDrag(d.startPx, e.clientX - d.startX, d.remPx);
    sidebar.style.width = `${d.width}rem`;
  };

  const endDrag = (e: PointerEvent<HTMLDivElement>) => {
    const d = drag.current;
    if (!d) return;
    drag.current = null;
    if (e.currentTarget.hasPointerCapture(e.pointerId)) e.currentTarget.releasePointerCapture(e.pointerId);
    document.documentElement.classList.remove("sidebar-resizing");
    setDragging(false);
    setWidth(d.width);
  };

  const onKeyDown = (e: KeyboardEvent<HTMLDivElement>) => {
    const next = widthAfterKey(width, e.key);
    if (next === null) return;
    e.preventDefault();
    setWidth(next);
  };

  return (
    <div
      role="separator"
      aria-orientation="vertical"
      aria-label="Resize sidebar"
      aria-valuemin={MIN_SIDEBAR_WIDTH}
      aria-valuemax={MAX_SIDEBAR_WIDTH}
      aria-valuenow={width}
      tabIndex={0}
      title="Drag to resize · double-click to reset"
      data-dragging={dragging || undefined}
      className={cn(
        // Zero net width: 8px of hit area centered on the sidebar's border, above both panes.
        "relative z-10 -mx-1 w-2 shrink-0 cursor-col-resize touch-none outline-none",
        "after:absolute after:inset-y-0 after:left-1/2 after:w-0.5 after:-translate-x-1/2 after:transition-colors",
        "hover:after:bg-ring/60 focus-visible:after:bg-ring data-dragging:after:bg-ring",
      )}
      onPointerDown={onPointerDown}
      onPointerMove={onPointerMove}
      onPointerUp={endDrag}
      onPointerCancel={endDrag}
      onDoubleClick={() => setWidth(DEFAULT_SIDEBAR_WIDTH)}
      onKeyDown={onKeyDown}
    />
  );
}
