export const DEFAULT_HOST_PREVIEW_WIDTH = 400;
export const MIN_HOST_PREVIEW_WIDTH = 320;
export const MAX_HOST_PREVIEW_WIDTH = 640;

export function clampHostPreviewWidth(value: unknown): number {
  if (typeof value !== "number" || !Number.isFinite(value))
    return DEFAULT_HOST_PREVIEW_WIDTH;
  return Math.min(
    MAX_HOST_PREVIEW_WIDTH,
    Math.max(MIN_HOST_PREVIEW_WIDTH, Math.round(value)),
  );
}

/** Large fonts or navigation can exhaust the content area above the window breakpoint. */
export function hostPreviewNeedsCompact(available: number): boolean {
  return Number.isFinite(available) && available < 2 * MIN_HOST_PREVIEW_WIDTH;
}

/** Reserve list space without modifying the user's saved preferred width. */
export function hostPreviewLimit(available: number): number {
  if (!Number.isFinite(available)) return MAX_HOST_PREVIEW_WIDTH;
  return clampHostPreviewWidth(Math.floor(available - 320));
}

export function hostPreviewWidthAfterDrag(
  start: number,
  delta: number,
  limit: number,
): number {
  const next =
    clampHostPreviewWidth(start) - (Number.isFinite(delta) ? delta : 0);
  return Math.min(clampHostPreviewWidth(limit), clampHostPreviewWidth(next));
}

export function hostPreviewWidthAfterKey(
  width: number,
  key: string,
  limit: number,
): number | null {
  let next: number;
  switch (key) {
    case "ArrowLeft":
      next = hostPreviewWidthAfterDrag(width, -16, limit);
      break;
    case "ArrowRight":
      next = hostPreviewWidthAfterDrag(width, 16, limit);
      break;
    case "Home":
      next = MIN_HOST_PREVIEW_WIDTH;
      break;
    case "End":
      next = clampHostPreviewWidth(limit);
      break;
    default:
      return null;
  }
  // A no-op at a viewport cap must not replace a larger saved preference.
  return next === clampHostPreviewWidth(width) ? null : next;
}
