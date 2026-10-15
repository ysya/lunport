import { useEffect, useRef, useState, type RefObject } from "react";
import {
  DEFAULT_HOST_PREVIEW_WIDTH,
  MIN_HOST_PREVIEW_WIDTH,
  hostPreviewWidthAfterDrag,
  hostPreviewWidthAfterKey,
} from "@/lib/host-preview-width";

export function HostPreviewResizeHandle({
  pane,
  width,
  limit,
  controls,
  setWidth,
}: {
  pane: RefObject<HTMLElement | null>;
  width: number;
  limit: number;
  controls: string;
  setWidth: (width: number) => void;
}) {
  const drag = useRef<{
    pointerId: number;
    startX: number;
    startWidth: number;
    width: number;
  } | null>(null);
  const [liveWidth, setLiveWidth] = useState<number | null>(null);
  const paint = (value: number) =>
    pane.current?.style.setProperty("--host-preview-width", `${value}px`);
  const finish = (
    handle: HTMLDivElement,
    pointerId?: number,
    cancelled = false,
  ) => {
    const current = drag.current;
    if (
      !current ||
      (pointerId !== undefined && pointerId !== current.pointerId)
    )
      return;
    drag.current = null;
    if (handle.hasPointerCapture(current.pointerId))
      handle.releasePointerCapture(current.pointerId);
    document.documentElement.classList.remove("host-preview-resizing");
    setLiveWidth(null);
    if (
      cancelled ||
      Math.round(current.width) === Math.round(current.startWidth)
    )
      paint(width);
    else setWidth(current.width);
  };
  useEffect(
    () => () => {
      document.documentElement.classList.remove("host-preview-resizing");
    },
    [],
  );
  return (
    <div
      role="separator"
      aria-label="Resize connection details"
      aria-orientation="vertical"
      aria-controls={controls}
      aria-valuemin={MIN_HOST_PREVIEW_WIDTH}
      aria-valuemax={limit}
      aria-valuenow={liveWidth ?? width}
      aria-valuetext={`${liveWidth ?? width} pixels`}
      tabIndex={0}
      title="Drag to resize · double-click to reset · arrow keys to adjust"
      className="library-preview-resize"
      data-dragging={liveWidth !== null || undefined}
      onPointerDown={(event) => {
        if (event.button !== 0 || !pane.current || drag.current) return;
        event.preventDefault();
        event.currentTarget.focus();
        event.currentTarget.setPointerCapture(event.pointerId);
        const startWidth = pane.current.getBoundingClientRect().width;
        drag.current = {
          pointerId: event.pointerId,
          startX: event.clientX,
          startWidth,
          width: startWidth,
        };
        document.documentElement.classList.add("host-preview-resizing");
        setLiveWidth(startWidth);
      }}
      onPointerMove={(event) => {
        if (!drag.current || event.pointerId !== drag.current.pointerId) return;
        drag.current.width = hostPreviewWidthAfterDrag(
          drag.current.startWidth,
          event.clientX - drag.current.startX,
          limit,
        );
        paint(drag.current.width);
        setLiveWidth(drag.current.width);
      }}
      onPointerUp={(event) => finish(event.currentTarget, event.pointerId)}
      onPointerCancel={(event) =>
        finish(event.currentTarget, event.pointerId, true)
      }
      onLostPointerCapture={(event) =>
        finish(event.currentTarget, undefined, true)
      }
      onDoubleClick={() => setWidth(DEFAULT_HOST_PREVIEW_WIDTH)}
      onKeyDown={(event) => {
        if (event.key === "Escape" && drag.current) {
          event.preventDefault();
          event.stopPropagation();
          finish(event.currentTarget, undefined, true);
          return;
        }
        const next = hostPreviewWidthAfterKey(width, event.key, limit);
        if (next === null) return;
        event.preventDefault();
        setWidth(next);
      }}
    />
  );
}
