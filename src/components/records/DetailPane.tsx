import { useEffect, useId, useRef, useState, type CSSProperties, type ReactNode } from "react";
import { X, ArrowLeft } from "lucide-react";
import { Button } from "@/components/ui/button";
import { useDetailMotion } from "@/components/app/DetailPresence";
import { clampHostPreviewWidth, hostPreviewLimit, hostPreviewNeedsCompact } from "@/lib/host-preview-width";
import { useUiStore } from "@/stores/ui";
import { HostPreviewResizeHandle } from "./HostPreviewResizeHandle";

export function DetailPane({ itemId, title, label, close, children }: {
  itemId: string; title: string; label: string; close: () => void; children: ReactNode;
}) {
  const { open, finish } = useDetailMotion();
  const closeButton = useRef<HTMLButtonElement>(null);
  const pane = useRef<HTMLElement>(null);
  const paneId = useId();
  const preferredWidth = clampHostPreviewWidth(useUiStore((s) => s.hostPreviewWidth));
  const setWidth = useUiStore((s) => s.setHostPreviewWidth);
  const [available, setAvailable] = useState(Infinity);
  const compact = hostPreviewNeedsCompact(available);
  const limit = hostPreviewLimit(available);
  const width = Math.min(preferredWidth, limit);
  const previous = useRef({ itemId: "", compact: false });
  const closeRef = useRef(close);
  closeRef.current = close;
  useEffect(() => {
    if (!open) return;
    const escape = (event: KeyboardEvent) => {
      if (event.key !== "Escape" || event.defaultPrevented) return;
      if (event.target instanceof Element && event.target.closest('[role="dialog"], [role="alertdialog"]')) return;
      event.preventDefault();
      closeRef.current();
    };
    window.addEventListener("keydown", escape);
    return () => window.removeEventListener("keydown", escape);
  }, [open]);
  useEffect(() => {
    const parent = pane.current?.parentElement;
    if (!parent) return;
    const measure = () => setAvailable(parent.getBoundingClientRect().width);
    measure();
    const observer = new ResizeObserver(measure);
    observer.observe(parent);
    return () => observer.disconnect();
  }, []);
  useEffect(() => {
    const singlePane = compact || window.matchMedia("(max-width: 820px)").matches;
    if (open && (previous.current.itemId !== itemId || (singlePane && !previous.current.compact))) closeButton.current?.focus();
    previous.current = { itemId, compact: singlePane };
  }, [itemId, compact, available, open]);
  useEffect(() => {
    const main = pane.current?.parentElement?.querySelector<HTMLElement>(":scope > .library-main");
    if (!main) return;
    const media = window.matchMedia("(max-width: 820px)");
    const update = () => { main.inert = open && (compact || media.matches || width >= available); };
    update();
    media.addEventListener("change", update);
    return () => { main.inert = false; media.removeEventListener("change", update); };
  }, [compact, open, width, available]);
  return (
    <aside
      ref={pane}
      id={paneId}
      className="library-host-preview app-detail-enter"
      aria-label={label}
      aria-hidden={!open}
      inert={!open}
      data-state={open ? "open" : "closed"}
      onAnimationEnd={(event) => { if (!open && event.target === event.currentTarget) finish(); }}
      data-compact={compact || undefined}
      style={{ "--host-preview-width": `${width}px` } as CSSProperties}
    >
      <HostPreviewResizeHandle
        pane={pane}
        width={width}
        limit={limit}
        controls={paneId}
        setWidth={setWidth}
        label={`Resize ${title.toLowerCase()}`}
      />
      <header>
        <span>
          {title}
        </span>
        <Button variant="ghost" size="icon-sm" aria-label="Close details" ref={closeButton} onClick={close}>
          <ArrowLeft className="library-detail-back size-4" />
          <X className="library-detail-close size-4" />
        </Button>
      </header>
      <div className="library-preview-scroll">
        {children}
      </div>
    </aside>
  );
}
