import { useCallback, useEffect, useRef, useState } from "react";
import { WTerm } from "@wterm/dom";
import { GhosttyCore } from "@wterm/ghostty";
import ghosttyWasm from "@wterm/ghostty/ghostty-vt.wasm?url";
import "@wterm/dom/css";
import "./terminal.css";
import { ArrowDown, ArrowUp, Check, CircleAlert, Copy, LoaderCircle, Minus, MoreHorizontal, Plus, RotateCw, Search, Type, Unplug, X } from "lucide-react";
import { writeText } from "@tauri-apps/plugin-clipboard-manager";
import { Button } from "@/components/ui/button";
import { TerminalSession, type TerminalStatus } from "@/lib/terminal-session";
import { RECONNECT_TERMINAL_OUTPUT } from "@/lib/terminal-reconnect";
import { toast } from "sonner";
import { useSettingsStore } from "@/stores/settings";
import { useTerminalStore, type TerminalTab } from "@/stores/terminals";
import { clampTerminalFontSize, DEFAULT_TERMINAL_FONT_SIZE } from "@/lib/settings-logic";
import { terminalColors } from "@/lib/terminal-theme";
import { Input } from "@/components/ui/input";
import { isImeKey } from "@/lib/ime";
import { DropdownMenu, DropdownMenuCheckboxItem, DropdownMenuContent, DropdownMenuItem, DropdownMenuLabel, DropdownMenuSeparator, DropdownMenuShortcut, DropdownMenuSub, DropdownMenuSubContent, DropdownMenuSubTrigger, DropdownMenuTrigger } from "@/components/ui/dropdown-menu";
import { Dialog, DialogContent, DialogTitle, DialogDescription, DialogFooter } from "@/components/ui/dialog";

export function TerminalPane({ tab, active }: { tab: TerminalTab; active: boolean }) {
  const element = useRef<HTMLDivElement>(null);
  const terminal = useRef<WTerm | null>(null);
  const connection = useRef<TerminalSession | null>(null);
  const [attempt, setAttempt] = useState(0);
  const [confirmReconnect, setConfirmReconnect] = useState(false);
  const reconnectKeyHeld = useRef(false);
  const fontSize = useSettingsStore((state) => clampTerminalFontSize(state.terminalFontSize));
  const setFontSize = useSettingsStore((state) => state.setTerminalFontSize);
  const cursorBlink = useSettingsStore((state) => state.terminalCursorBlink !== false);
  const [searchOpen, setSearchOpen] = useState(false);
  const [query, setQuery] = useState("");
  const queryRef = useRef(query);
  queryRef.current = query;
  const searchInput = useRef<HTMLInputElement>(null);
  const [searchStatus, setSearchStatus] = useState({ count: 0, activeIndex: -1, searching: false, limited: false });
  const [connectionState, setConnectionState] = useState<TerminalStatus>({ kind: "connecting", text: "Loading terminal…", autoReconnect: true });
  const { kind: state, text: status, retry } = connectionState;
  const [size, setSize] = useState({ cols: 80, rows: 24 });
  const activeRef = useRef(active);
  activeRef.current = active;
  const modifierLabel = typeof navigator !== "undefined" && /Mac/.test(navigator.platform) ? "⌘" : "Ctrl+";
  const statusLabel = state === "error" ? "Connection failed" : connectionState.question ? "Authentication required" : status;
  const restoreFocus = useCallback(() => {
    if (!activeRef.current || document.querySelector('[role="dialog"], [role="alertdialog"], [role="menu"]')) return;
    if (searchInput.current) searchInput.current.focus();
    else terminal.current?.focus();
  }, []);
  const closeSearch = () => { setSearchOpen(false); requestAnimationFrame(restoreFocus); };
  const reconnect = useCallback(() => {
    setConfirmReconnect(false);
    if (connection.current) void connection.current.reconnect();
    else setAttempt((attempt) => attempt + 1);
  }, []);
  const requestReconnect = () => { if (state === "open") setConfirmReconnect(true); else reconnect(); };

  useEffect(() => {
    let cancelled = false;
    let core: GhosttyCore | undefined;
    let wt: WTerm | undefined;
    let session: TerminalSession | undefined;
    let appearance: MutationObserver | undefined;
    setConnectionState({ kind: "connecting", text: "Loading terminal…", autoReconnect: true });
    void (async () => {
      core = await GhosttyCore.load({ wasmPath: ghosttyWasm, scrollbackLimit: 8 * 1024 * 1024, imageStorageLimit: 0 });
      if (cancelled) { core.dispose(); return; }
      const encoder = new TextEncoder();
      let previousState: TerminalStatus["kind"] = "connecting";
      session = new TerminalSession(tab.host, (bytes) => wt?.write(bytes), (next) => {
        if (cancelled) return;
        setConnectionState(next);
        if (next.kind === "open" && previousState !== "open") {
          try { useSettingsStore.getState().recordConnection(tab.historyKey); } catch { /* History is optional. */ }
          wt?.fit();
          restoreFocus();
        }
        previousState = next.kind;
      }, () => { wt?.clearSelection(); wt?.write(RECONNECT_TERMINAL_OUTPUT); });
      wt = new WTerm(element.current!, {
        core, cols: 80, rows: 24, autoResize: true, cursorBlink: true,
        renderingPaused: !activeRef.current,
        onData: (data) => session?.input(encoder.encode(data)),
        onBinary: (data) => session?.input(data),
        onResize: (cols, rows) => { if (!cancelled) { setSize({ cols, rows }); session?.resize(cols, rows); } },
        // OSC 52 clipboard writes from the remote host are intentionally not enabled.
      });
      wt.onSearchChange = (state) => { if (!cancelled) setSearchStatus(state); };
      terminal.current = wt;
      await wt.init();
      if (cancelled) return;
      connection.current = session;
      const applyAppearance = () => {
        if (cancelled || !element.current) return;
        const dark = document.documentElement.classList.contains("dark");
        wt?.setThemeColors(terminalColors(document.documentElement.dataset.colorTheme, dark ? "dark" : "light"));
      };
      applyAppearance();
      appearance = new MutationObserver(applyAppearance);
      appearance.observe(document.documentElement, { attributes: true, attributeFilter: ["class", "style"] });
      wt.fit();
      if (queryRef.current) wt.search(queryRef.current);
      await session.start(core.getCols(), core.getRows());
    })().catch((error) => {
      if (!cancelled) { setConnectionState({ kind: "error", text: String(error), autoReconnect: true }); session?.dispose(); connection.current = null; }
    });
    return () => {
      cancelled = true;
      appearance?.disconnect(); session?.dispose(); wt?.destroy(); core?.dispose();
      connection.current = null; terminal.current = null;
    };
  }, [tab.id, attempt, restoreFocus]);
  useEffect(() => {
    const online = () => connection.current?.networkRestored();
    window.addEventListener("online", online);
    return () => window.removeEventListener("online", online);
  }, []);
  useEffect(() => { useTerminalStore.getState().updateState(tab.id, state); }, [tab.id, state]);
  useEffect(() => {
    terminal.current?.setRenderingPaused(!active);
    if (active) { terminal.current?.fit(); restoreFocus(); }
  }, [active, restoreFocus]);
  useEffect(() => { terminal.current?.fit(); }, [fontSize]);
  useEffect(() => {
    terminal.current?.search(searchOpen ? query : "");
  }, [query, searchOpen]);
  useEffect(() => {
    if (!searchOpen || !active) return;
    searchInput.current?.focus();
    searchInput.current?.select();
  }, [searchOpen, active]);
  useEffect(() => {
    if (!active) return;
    const keydown = (event: KeyboardEvent) => {
      if (isImeKey({ nativeEvent: event, keyCode: event.keyCode }) || event.defaultPrevented) return;
      if (event.target instanceof Element && (event.target.closest('[role="dialog"], [role="alertdialog"], [role="menu"]') || !element.current?.parentElement?.contains(event.target) && event.target.closest('input, textarea, [contenteditable="true"]'))) return;
      if (event.key === "Enter" && event.target instanceof Node && element.current?.contains(event.target)) {
        if (reconnectKeyHeld.current) { event.preventDefault(); event.stopPropagation(); return; }
        if ((state === "ended" || state === "error" || retry) && !event.repeat && !event.metaKey && !event.ctrlKey && !event.altKey && !event.shiftKey) {
          event.preventDefault(); event.stopPropagation(); reconnectKeyHeld.current = true; reconnect(); return;
        }
      }
      const modifier = /Mac/.test(navigator.platform) ? event.metaKey && !event.ctrlKey : event.ctrlKey && !event.metaKey;
      if (!modifier || event.altKey) return;
      const key = event.key.toLowerCase();
      if (key === "f") {
        event.preventDefault(); event.stopPropagation();
        setSearchOpen(true); searchInput.current?.focus(); searchInput.current?.select();
      } else if (["=", "+", "-", "0"].includes(key)) {
        event.preventDefault(); event.stopPropagation();
        const current = clampTerminalFontSize(useSettingsStore.getState().terminalFontSize);
        setFontSize(key === "0" ? DEFAULT_TERMINAL_FONT_SIZE : Math.max(10, Math.min(24, current + (key === "-" ? -1 : 1))));
      }
    };
    const keyup = (event: KeyboardEvent) => { if (isImeKey({ nativeEvent: event, keyCode: event.keyCode })) return; if (event.key === "Enter") reconnectKeyHeld.current = false; };
    window.addEventListener("keydown", keydown, true);
    window.addEventListener("keyup", keyup, true);
    return () => { window.removeEventListener("keydown", keydown, true); window.removeEventListener("keyup", keyup, true); };
  }, [active, setFontSize, state, retry, reconnect]);
  useEffect(() => { if (!active) reconnectKeyHeld.current = false; }, [active]);

  const copy = async () => {
    const text = terminal.current?.getSelectionText();
    if (!text) { toast("Select terminal text to copy"); return; }
    try { await writeText(text); } catch { toast.error("Could not copy terminal selection"); }
  };
  return <section id={`terminal-panel-${tab.id}`} role="tabpanel" aria-labelledby={`terminal-tab-${tab.id}`} className="embedded-pane" hidden={!active}>
    {searchOpen && <div className="embedded-search" role="search" aria-label="Terminal search">
      <Input ref={searchInput} value={query} placeholder="Find in terminal…" aria-label="Find in terminal" onChange={(event) => setQuery(event.target.value)} onKeyDown={(event) => {
        if (isImeKey(event)) return;
        if (event.key === "Enter") { event.preventDefault(); if (event.shiftKey) terminal.current?.findPrevious(); else terminal.current?.findNext(); }
        else if (event.key === "Escape") { event.preventDefault(); event.stopPropagation(); closeSearch(); }
      }} />
      <span role="status">{searchStatus.searching ? "Searching…" : query ? `${searchStatus.activeIndex + 1} / ${searchStatus.count}${searchStatus.limited ? "+" : ""}` : ""}</span>
      <Button size="icon-sm" variant="ghost" aria-label="Previous match" disabled={!searchStatus.count} onClick={() => terminal.current?.findPrevious()}><ArrowUp /></Button>
      <Button size="icon-sm" variant="ghost" aria-label="Next match" disabled={!searchStatus.count} onClick={() => terminal.current?.findNext()}><ArrowDown /></Button>
      <Button size="icon-sm" variant="ghost" aria-label="Close terminal search" onClick={closeSearch}><X /></Button>
    </div>}
    <div ref={element} className="embedded-terminal" data-cursor-blink={cursorBlink} style={{ fontSize, "--term-font-size": `${fontSize}px`, "--term-row-height": `${fontSize * 1.4}px` } as React.CSSProperties} />
    {(state === "ended" || state === "error" || retry) && <div className="embedded-recovery" role="region" aria-label="Terminal reconnection">
      {retry ? <LoaderCircle className="size-4 motion-safe:animate-spin" /> : <Unplug className="size-4" />}
      <div><strong>{retry ? "Reconnecting automatically" : "Session ended"}</strong><p>{retry ? `Attempt ${retry} of 5 · Enter to retry now` : status}</p><p>Previous output stays here. Reconnect opens a new shell.</p></div>
      <div className="embedded-recovery-actions"><Button size="sm" onClick={reconnect}><RotateCw />{retry ? "Retry now" : "Reconnect"}</Button>{retry && <Button size="sm" variant="outline" onClick={() => connection.current?.disconnect()}>Stop retrying</Button>}</div>
    </div>}
    <footer className="embedded-statusbar">
      <div className="embedded-connection">
        <span className="embedded-address" title={tab.address}>{tab.address}</span>
        <span className="embedded-connection-status" role="status" data-state={state} title={status}>
          {state === "connecting" ? <LoaderCircle className="size-3 motion-safe:animate-spin" /> : state === "error" ? <CircleAlert className="size-3" /> : state === "open" ? <Check className="size-3" /> : <Unplug className="size-3" />}
          <span>{statusLabel}</span>
        </span>
      </div>
      <div className="embedded-actions">
        {state === "open" && <Button size="icon-xs" variant="ghost" aria-label="Reconnect terminal" title="Reconnect terminal" onClick={requestReconnect}><RotateCw /></Button>}
        <Button size="icon-xs" variant="ghost" aria-label="Search terminal" title={`Find in terminal (${modifierLabel}F)`} aria-expanded={searchOpen} onClick={() => { if (searchOpen) closeSearch(); else setSearchOpen(true); }}><Search /></Button>
        <DropdownMenu>
          <DropdownMenuTrigger asChild><Button size="icon-xs" variant="ghost" aria-label="Terminal options" title="Terminal options"><MoreHorizontal /></Button></DropdownMenuTrigger>
          <DropdownMenuContent align="end" onCloseAutoFocus={(event) => { event.preventDefault(); requestAnimationFrame(restoreFocus); }}>
            <DropdownMenuLabel className="embedded-session-details"><strong>{tab.name}</strong><span>{tab.address}</span><span>{status}</span><span>SSH · {size.cols} × {size.rows}</span></DropdownMenuLabel>
            <DropdownMenuSeparator />
            <DropdownMenuItem onSelect={() => setSearchOpen(true)}><Search />Find in terminal<DropdownMenuShortcut>{modifierLabel}F</DropdownMenuShortcut></DropdownMenuItem>
            <DropdownMenuItem onSelect={() => void copy()}><Copy />Copy selection</DropdownMenuItem>
            <DropdownMenuSub>
              <DropdownMenuSubTrigger><Type />Text size<DropdownMenuShortcut>{fontSize} px</DropdownMenuShortcut></DropdownMenuSubTrigger>
              <DropdownMenuSubContent>
                <DropdownMenuItem disabled={fontSize >= 24} onSelect={() => setFontSize(fontSize + 1)}><Plus />Increase<DropdownMenuShortcut>{modifierLabel}+</DropdownMenuShortcut></DropdownMenuItem>
                <DropdownMenuItem disabled={fontSize <= 10} onSelect={() => setFontSize(fontSize - 1)}><Minus />Decrease<DropdownMenuShortcut>{modifierLabel}−</DropdownMenuShortcut></DropdownMenuItem>
                <DropdownMenuItem onSelect={() => setFontSize(DEFAULT_TERMINAL_FONT_SIZE)}>Reset to default<DropdownMenuShortcut>{modifierLabel}0</DropdownMenuShortcut></DropdownMenuItem>
              </DropdownMenuSubContent>
            </DropdownMenuSub>
            <DropdownMenuSeparator />
            <DropdownMenuCheckboxItem checked={connectionState.autoReconnect} onCheckedChange={(enabled) => connection.current?.setAutoReconnect(enabled)}>Automatically reconnect</DropdownMenuCheckboxItem>
            <DropdownMenuItem disabled={state === "connecting" && !retry} onSelect={requestReconnect}><RotateCw />Reconnect</DropdownMenuItem>
            {(state === "open" || state === "connecting") && <DropdownMenuItem variant="destructive" onSelect={() => connection.current?.disconnect()}><Unplug />{retry ? "Stop retrying" : "Disconnect session"}</DropdownMenuItem>}
          </DropdownMenuContent>
        </DropdownMenu>
      </div>
    </footer>
    <Dialog open={confirmReconnect} onOpenChange={setConfirmReconnect}>
      <DialogContent onCloseAutoFocus={(event) => { event.preventDefault(); requestAnimationFrame(restoreFocus); }}>
        <DialogTitle>Reconnect terminal?</DialogTitle>
        <DialogDescription>This ends the current SSH session and opens a new shell. Running commands may stop. Previous output stays in this tab.</DialogDescription>
        <DialogFooter><Button variant="outline" onClick={() => setConfirmReconnect(false)}>Cancel</Button><Button onClick={reconnect}><RotateCw />Reconnect</Button></DialogFooter>
      </DialogContent>
    </Dialog>
  </section>;
}
