/**
 * Sidebar width, in rem: it follows Settings → Appearance → Text size like the rest of the UI
 * (the text size sets the root font size). 16rem is the former fixed `w-64`.
 */
export const DEFAULT_SIDEBAR_WIDTH = 16;
export const MIN_SIDEBAR_WIDTH = 12;
export const MAX_SIDEBAR_WIDTH = 32;
/** How far one arrow-key press on the resize handle moves it (rem). */
const KEY_STEP = 1;

/** A persisted or dragged width, clamped to the allowed range; bad or legacy values → the default. */
export function clampSidebarWidth(value: unknown): number {
  if (typeof value !== "number" || !Number.isFinite(value)) return DEFAULT_SIDEBAR_WIDTH;
  const wholePixels = Math.round(value * 16) / 16;
  return Math.min(MAX_SIDEBAR_WIDTH, Math.max(MIN_SIDEBAR_WIDTH, wholePixels));
}

/** The width after dragging the handle `deltaPx` from a sidebar `startPx` wide, at `remPx` per rem. */
export function widthAfterDrag(startPx: number, deltaPx: number, remPx: number): number {
  return clampSidebarWidth((startPx + deltaPx) / remPx);
}

/** The width after a key press on the resize handle, or null for keys that do not resize. */
export function widthAfterKey(width: number, key: string): number | null {
  switch (key) {
    case "ArrowLeft":
      return clampSidebarWidth(width - KEY_STEP);
    case "ArrowRight":
      return clampSidebarWidth(width + KEY_STEP);
    case "Home":
      return MIN_SIDEBAR_WIDTH;
    case "End":
      return MAX_SIDEBAR_WIDTH;
    default:
      return null;
  }
}
