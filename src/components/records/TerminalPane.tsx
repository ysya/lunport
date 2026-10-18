import { useEffect, useRef, useState } from "react";
import { WTerm } from "@wterm/dom";
import { GhosttyCore } from "@wterm/ghostty";
import ghosttyWasm from "@wterm/ghostty/ghostty-vt.wasm?url";
import "@wterm/dom/css";
import "./terminal.css";
import { Copy, Minus, Plus, RotateCw, Unplug } from "lucide-react";
import { writeText } from "@tauri-apps/plugin-clipboard-manager";
import { Button } from "@/components/ui/button";
import { EmbeddedTerminal } from "@/lib/embedded-terminal";
import { toast } from "sonner";
import { useSettingsStore } from "@/stores/settings";
import { recentHostKey } from "./library-view";

export type TerminalTab = { id: string; hostId: string; name: string; address: string };

export function TerminalPane({ tab, active }: { tab: TerminalTab; active: boolean }) {
  const element = useRef<HTMLDivElement>(null);
  const terminal = useRef<WTerm | null>(null);
  const connection = useRef<EmbeddedTerminal | null>(null);
  const [attempt, setAttempt] = useState(0);
  const [fontSize, setFontSize] = useState(13);
  const [connectionState, setConnectionState] = useState<{ kind: "connecting" | "open" | "ended" | "error"; text: string }>({ kind: "connecting", text: "Loading terminal…" });
  const { kind: state, text: status } = connectionState;
  const [size, setSize] = useState({ cols: 80, rows: 24 });
  const activeRef = useRef(active);
  activeRef.current = active;

  useEffect(() => {
    let cancelled = false;
    let core: GhosttyCore | undefined;
    let wt: WTerm | undefined;
    let session: EmbeddedTerminal | undefined;
    let appearance: MutationObserver | undefined;
    setConnectionState({ kind: "connecting", text: "Connecting…" });
    void (async () => {
      core = await GhosttyCore.load({ wasmPath: ghosttyWasm, scrollbackLimit: 8 * 1024 * 1024, imageStorageLimit: 0 });
      if (cancelled) { core.dispose(); return; }
      const encoder = new TextEncoder();
      session = new EmbeddedTerminal((bytes) => wt?.write(bytes), (event) => {
        if (cancelled) return;
        if (event.type === "opened") {
          setConnectionState({ kind: "open", text: "Connected" });
          try { useSettingsStore.getState().recordConnection(recentHostKey(tab.hostId)); } catch { /* History is optional. */ }
          wt?.fit();
          if (activeRef.current) wt?.focus();
        } else if (event.type === "bridge_error") {
          setConnectionState({ kind: "error", text: event.text });
        } else if (event.type === "exited") {
          setConnectionState((previous) => previous.kind === "error" ? previous : { kind: "ended", text: event.signal ? `Ended (${event.signal})` : event.code === null ? "Disconnected" : `Shell exited (${event.code})` });
        } else if (event.type === "closed") {
          setConnectionState((previous) => previous.kind === "error" || previous.kind === "ended" ? previous : { kind: "ended", text: "Disconnected" });
        } else if (event.type === "event" && (event.event === "error" || event.event === "disconnected")) {
          setConnectionState({ kind: "error", text: event.text ?? event.reason ?? "Connection failed" });
        } else if (event.type === "question") setConnectionState({ kind: "connecting", text: event.text });
      });
      connection.current = session;
      wt = new WTerm(element.current!, {
        core, cols: 80, rows: 24, autoResize: true, cursorBlink: true,
        renderingPaused: !activeRef.current,
        onData: (data) => session?.input(encoder.encode(data)),
        onBinary: (data) => session?.input(data),
        onResize: (cols, rows) => { if (!cancelled) { setSize({ cols, rows }); session?.resize(cols, rows); } },
        // OSC 52 clipboard writes from the remote host are intentionally not enabled.
      });
      terminal.current = wt;
      await wt.init();
      if (cancelled) return;
      const applyAppearance = () => {
        if (cancelled || !element.current) return;
        const style = getComputedStyle(element.current);
        const color = (name: string, fallback: number) => {
          const value = style.getPropertyValue(name).trim();
          return /^#[0-9a-f]{6}$/i.test(value) ? parseInt(value.slice(1), 16) : fallback;
        };
        const dark = document.documentElement.classList.contains("dark");
        const palette = dark
          ? [0x323742, 0xe06c75, 0x98c379, 0xe5c07b, 0x61afef, 0xc678dd, 0x56b6c2, 0xabb2bf, 0x5c6370, 0xf28b94, 0xb3d796, 0xf5d79b, 0x8bc6f7, 0xdda0f1, 0x83d0d8, 0xf8fafc]
          : [0x24292f, 0xb42332, 0x246b35, 0x806000, 0x1458b0, 0x8249a5, 0x146c73, 0x57606a, 0x6e7781, 0xcf2438, 0x2d7c40, 0x936b00, 0x2671ce, 0x9c55be, 0x1c7d86, 0x8c959f];
        wt?.setThemeColors({ foreground: color("--foreground", 0xeef0f4), background: color("--background", 0x111214), cursor: color("--primary", 0x82b1ff), palette });
      };
      applyAppearance();
      appearance = new MutationObserver(applyAppearance);
      appearance.observe(document.documentElement, { attributes: true, attributeFilter: ["class", "style"] });
      wt.fit();
      await session.start(tab.hostId, core.getCols(), core.getRows());
    })().catch((error) => {
      if (!cancelled) { setConnectionState({ kind: "error", text: String(error) }); session?.close(); }
    });
    return () => {
      cancelled = true;
      appearance?.disconnect(); session?.close(); wt?.destroy(); core?.dispose();
      connection.current = null; terminal.current = null;
    };
  }, [tab.hostId, attempt]);
  useEffect(() => {
    terminal.current?.setRenderingPaused(!active);
    if (active) { terminal.current?.fit(); terminal.current?.focus(); }
  }, [active]);
  useEffect(() => { terminal.current?.fit(); }, [fontSize]);

  const copy = async () => {
    const text = terminal.current?.getSelectionText();
    if (!text) { toast("Select terminal text to copy"); return; }
    try { await writeText(text); } catch { toast.error("Could not copy terminal selection"); }
  };
  return <section className="embedded-pane" hidden={!active} aria-label={`SSH terminal: ${tab.name}`}>
    <div className="embedded-toolbar">
      <div className="embedded-endpoint"><span className="embedded-state" data-state={state} /><strong>{tab.name}</strong><span>{tab.address}</span></div>
      <div className="embedded-actions">
        <Button size="icon-sm" variant="ghost" aria-label="Decrease terminal font size" disabled={fontSize <= 10} onClick={() => setFontSize((size) => size - 1)}><Minus /></Button>
        <span className="embedded-font-size">{fontSize}</span>
        <Button size="icon-sm" variant="ghost" aria-label="Increase terminal font size" disabled={fontSize >= 24} onClick={() => setFontSize((size) => size + 1)}><Plus /></Button>
        <Button size="icon-sm" variant="ghost" aria-label="Copy terminal selection" onClick={() => void copy()}><Copy /></Button>
        {state === "open" || state === "connecting"
          ? <Button size="sm" variant="ghost" onClick={() => { connection.current?.close(); setConnectionState({ kind: "ended", text: "Disconnected" }); }}><Unplug />Disconnect</Button>
          : <Button size="sm" variant="ghost" onClick={() => setAttempt((attempt) => attempt + 1)}><RotateCw />Reconnect</Button>}
      </div>
    </div>
    <div ref={element} className="embedded-terminal" style={{ fontSize, "--term-font-size": `${fontSize}px`, "--term-row-height": `${fontSize * 1.4}px` } as React.CSSProperties} />
    <footer className="embedded-statusbar"><span role="status">{status}</span><span>SSH · {size.cols} × {size.rows} · wterm / Ghostty</span></footer>
  </section>;
}
