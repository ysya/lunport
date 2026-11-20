import { useEffect, useLayoutEffect, useRef, useState, type CSSProperties } from "react";
import { WTerm } from "@wterm/dom";
import { GhosttyCore } from "@wterm/ghostty";
import ghosttyWasm from "@wterm/ghostty/ghostty-vt.wasm?url";
import "@wterm/dom/css";
import { toast } from "sonner";
import { Button } from "@/components/ui/button";
import { terminalColors } from "@/lib/terminal-theme";
import type { TmuxPane as PaneGeometry, TmuxPaneCapture } from "@/lib/tmux-control";

export type RegisterTmuxPane = (id: string, view: {
  terminal: WTerm;
  write: (bytes: Uint8Array) => void;
  restore: (capture: TmuxPaneCapture, replace: boolean) => void;
  fail: (error: unknown) => void;
}) => () => void;

export function TmuxDivider({ pane, axis, max, onResize }: {
  pane: PaneGeometry;
  axis: "cols" | "rows";
  max: number;
  onResize: (size: number) => void;
}) {
  const vertical = axis === "cols";
  const stopDrag = useRef<(() => void) | null>(null);
  const [offset, setOffset] = useState<number | null>(null);
  const size = vertical ? pane.width : pane.height;
  const latest = useRef({ size, max, onResize });
  latest.current = { size, max, onResize };

  useEffect(() => () => stopDrag.current?.(), []);

  return <div className="tmux-divider" role="separator" tabIndex={0}
    aria-label={vertical ? "Resize side-by-side panes" : "Resize top-and-bottom panes"}
    aria-orientation={vertical ? "vertical" : "horizontal"} aria-valuenow={size} aria-valuemin={1} aria-valuemax={max}
    data-axis={axis} data-dragging={offset !== null} style={{
      "--divider-left": pane.left + (vertical ? pane.width : 0),
      "--divider-top": pane.top + (vertical ? 0 : pane.height),
      "--divider-width": vertical ? 1 : pane.width,
      "--divider-height": vertical ? pane.height : 1,
      "--divider-offset": offset ?? 0,
    } as CSSProperties}
    onKeyDown={(event) => {
      const increase = vertical ? "ArrowRight" : "ArrowDown";
      const decrease = vertical ? "ArrowLeft" : "ArrowUp";
      if (event.key !== increase && event.key !== decrease) return;
      event.preventDefault();
      const next = size + (event.key === increase ? 1 : -1);
      if (next > 0 && next <= max) onResize(next);
    }}
    onPointerDown={(event) => {
      if (event.button !== 0 || stopDrag.current) return;
      const handle = event.currentTarget;
      const bounds = handle.getBoundingClientRect();
      const cell = vertical ? bounds.width : bounds.height;
      const owner = handle.ownerDocument.defaultView;
      if (!cell || !owner) return;
      event.preventDefault();
      const pointer = event.pointerId;
      const start = vertical ? event.clientX : event.clientY;
      const distance = (next: PointerEvent) => {
        const { size, max } = latest.current;
        const end = vertical ? next.clientX : next.clientY;
        return Math.max(1 - size, Math.min(max - size, Math.round((end - start) / cell)));
      };
      const move = (next: PointerEvent) => { if (next.pointerId === pointer) setOffset(distance(next)); };
      const cancel = () => { stopDrag.current?.(); setOffset(null); };
      const pointerCancel = (next: PointerEvent) => { if (next.pointerId === pointer) cancel(); };
      const end = (next: PointerEvent) => {
        if (next.pointerId !== pointer) return;
        const delta = distance(next);
        cancel();
        if (delta) latest.current.onResize(latest.current.size + delta);
      };
      // Follow the pointer even when the browser delivers movement to an adjacent pane.
      owner.addEventListener("pointermove", move, true);
      owner.addEventListener("pointerup", end, true);
      owner.addEventListener("pointercancel", pointerCancel, true);
      owner.addEventListener("blur", cancel);
      stopDrag.current = () => {
        owner.removeEventListener("pointermove", move, true);
        owner.removeEventListener("pointerup", end, true);
        owner.removeEventListener("pointercancel", pointerCancel, true);
        owner.removeEventListener("blur", cancel);
        stopDrag.current = null;
        if (handle.hasPointerCapture(pointer)) handle.releasePointerCapture(pointer);
      };
      setOffset(0);
      handle.setPointerCapture(pointer);
    }}
  />;
}

export function TmuxPane({ pane, selected, active, cursorBlink, register, onFocus, onInput }: {
  pane: PaneGeometry;
  selected: boolean;
  active: boolean;
  cursorBlink: boolean;
  register: RegisterTmuxPane;
  onFocus: (id: string) => void;
  onInput: (id: string, data: string | Uint8Array) => void;
}) {
  const host = useRef<HTMLDivElement>(null);
  const terminal = useRef<WTerm | null>(null);
  const latest = useRef({ pane, active, onInput });
  latest.current = { pane, active, onInput };
  const [attempt, setAttempt] = useState(0);
  const [ready, setReady] = useState(false);
  const [error, setError] = useState(false);

  useEffect(() => {
    let cancelled = false;
    let writing = false;
    let bracketedPasteKnown = false;
    let core: GhosttyCore | undefined;
    let view: WTerm | undefined;
    let unregister: (() => void) | undefined;
    let appearance: MutationObserver | undefined;
    const element = host.current!;
    const fail = () => { if (!cancelled) { setReady(false); setError(true); } };
    const send = (data: string | Uint8Array) => {
      // tmux handles terminal queries from the process running inside the pane.
      if (!cancelled && !writing && latest.current.active) latest.current.onInput(pane.id, data);
    };
    const write = (data: string | Uint8Array) => {
      writing = true;
      try { view?.write(data); }
      finally { writing = false; }
    };
    const guardPaste = (event: ClipboardEvent) => {
      if (bracketedPasteKnown || core?.bracketedPaste()) return;
      const text = event.clipboardData?.getData("text");
      if (text && !/[\r\n]/.test(text)) return;
      event.preventDefault();
      event.stopPropagation();
      toast.error("Paste one line at a time when the pane’s paste mode is unknown.");
    };
    element.addEventListener("paste", guardPaste, true);

    void (async () => {
      core = await GhosttyCore.load({ wasmPath: ghosttyWasm, scrollbackLimit: 1024 * 1024, imageStorageLimit: 0 });
      if (cancelled) { core.dispose(); return; }
      const { width, height } = latest.current.pane;
      // The element is inert until capture completes because WTerm.init focuses its textarea.
      view = new WTerm(element, {
        core, cols: width, rows: height, autoResize: false, cursorBlink: true,
        renderingPaused: !latest.current.active, onData: send, onBinary: send,
      });
      await view.init();
      if (cancelled) return;
      terminal.current = view;
      const current = latest.current.pane;
      if (view.cols !== current.width || view.rows !== current.height) view.resize(current.width, current.height);
      view.setRenderingPaused(!latest.current.active);
      const applyAppearance = () => {
        const root = document.documentElement;
        view?.setThemeColors(terminalColors(root.dataset.colorTheme, root.classList.contains("dark") ? "dark" : "light"));
      };
      applyAppearance();
      appearance = new MutationObserver(applyAppearance);
      appearance.observe(document.documentElement, { attributes: true, attributeFilter: ["class", "style", "data-color-theme"] });
      unregister = register(pane.id, {
        terminal: view,
        write,
        restore: (capture, replace) => {
          if (cancelled) return;
          bracketedPasteKnown = capture.bracketedPasteKnown;
          if (replace) {
            view?.clearSelection();
            // Captured rows include tmux's recent history and a new cursor position.
            write("\x1bc\x1b[3J");
          }
          write(capture.bytes);
          setError(false);
          setReady(true);
        },
        fail,
      });
    })().catch(fail);

    return () => {
      cancelled = true;
      unregister?.();
      element.removeEventListener("paste", guardPaste, true);
      appearance?.disconnect();
      view?.destroy();
      core?.dispose();
      terminal.current = null;
    };
  }, [attempt, pane.id, register]);

  useLayoutEffect(() => {
    const view = terminal.current;
    if (view && (view.cols !== pane.width || view.rows !== pane.height)) view.resize(pane.width, pane.height);
  }, [pane.width, pane.height]);

  useEffect(() => { terminal.current?.setRenderingPaused(!active); }, [active]);

  return <div className="tmux-pane" role="group" aria-label={`tmux pane ${pane.id}`} data-selected={selected} style={{
    "--pane-left": pane.left, "--pane-top": pane.top, "--pane-width": pane.width, "--pane-height": pane.height,
  } as CSSProperties}>
    <div ref={host} className="embedded-terminal tmux-terminal" data-cursor-blink={cursorBlink} inert={!ready} onFocus={() => onFocus(pane.id)} />
    {error && <div className="tmux-pane-recovery">
      <p role="alert">Could not load this pane.</p>
      <Button size="xs" variant="outline" onClick={() => { setReady(false); setError(false); setAttempt((current) => current + 1); }}>Reload pane</Button>
    </div>}
  </div>;
}
