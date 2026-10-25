import { lazy, Suspense, useEffect, useRef, useState, type ReactNode, type RefObject } from "react";
import { CircleAlert, Library, LoaderCircle, Plus, Terminal, Unplug, X } from "lucide-react";
import { useTerminalStore, type TerminalTab } from "@/stores/terminals";
import { useUiStore } from "@/stores/ui";
import { Button } from "@/components/ui/button";
import { Dialog, DialogContent, DialogTitle, DialogDescription, DialogFooter } from "@/components/ui/dialog";
import { isImeKey } from "@/lib/ime";
import "./terminal.css";
const TerminalPane = lazy(() => import("./TerminalPane").then((module) => ({ default: module.TerminalPane })));

/**
 * The session tabs the title bar shows. The strip, and the room between and around the tabs, drag the window: Tauri starts a drag
 * only from an element that carries `data-tauri-drag-region` itself, so the containers carry it and the tabs' buttons stay buttons.
 */
export function SessionTabBar({ tabs, activeId, activate, requestClose, strip }: {
  tabs: TerminalTab[];
  activeId: string | null;
  activate: (id: string | null) => void;
  requestClose: (id: string) => void;
  strip: RefObject<HTMLElement | null>;
}) {
  return <div className="embedded-tabbar" data-tauri-drag-region>
    <nav ref={strip} className="embedded-tabs" data-tauri-drag-region role="tablist" aria-label="Workspace sessions" onKeyDown={(event) => {
      if (isImeKey(event) || !(event.target instanceof Element) || event.target.getAttribute("role") !== "tab") return;
      const buttons = Array.from(event.currentTarget.querySelectorAll<HTMLButtonElement>('[role="tab"]'));
      const index = buttons.indexOf(event.target as HTMLButtonElement);
      const next = event.key === "ArrowRight" ? (index + 1) % buttons.length : event.key === "ArrowLeft" ? (index + buttons.length - 1) % buttons.length : event.key === "Home" ? 0 : event.key === "End" ? buttons.length - 1 : null;
      if (next === null) return;
      event.preventDefault(); event.stopPropagation(); buttons[next]?.focus();
    }}>
      <div className="embedded-tab" data-tauri-drag-region data-active={!activeId} role="presentation">
        <button type="button" id="terminal-tab-library" role="tab" aria-selected={!activeId} aria-controls="terminal-library" tabIndex={!activeId ? 0 : -1} onClick={() => activate(null)}><Library className="size-3.5" /><span>Library</span></button>
      </div>
      {tabs.map((tab) => {
        const ordinal = tab.name.match(/ \(\d+\)$/)?.[0] ?? "";
        return <div key={tab.id} className="embedded-tab" data-tauri-drag-region data-active={activeId === tab.id} data-state={tab.state} role="presentation">
        <button type="button" id={`terminal-tab-${tab.id}`} role="tab" title={`${tab.name}\n${tab.address}\n${tab.state}`} aria-label={`${tab.name}, ${tab.state}`} aria-selected={activeId === tab.id} aria-controls={`terminal-panel-${tab.id}`} tabIndex={activeId === tab.id ? 0 : -1} onClick={() => activate(tab.id)}>
          {tab.state === "connecting" ? <LoaderCircle className="size-3.5 motion-safe:animate-spin" /> : tab.state === "error" ? <CircleAlert className="size-3.5 text-destructive" /> : tab.state === "ended" ? <Unplug className="size-3.5" /> : <Terminal className="size-3.5" />}<span>{ordinal ? tab.name.slice(0, -ordinal.length) : tab.name}</span>{ordinal && <span className="embedded-tab-ordinal">{ordinal.trim()}</span>}
        </button>
        <button type="button" className="embedded-tab-close" tabIndex={activeId === tab.id ? 0 : -1} aria-label={`Close terminal ${tab.name}`} onClick={() => requestClose(tab.id)}><X className="size-3" /></button>
      </div>;
      })}
    </nav>
    <button type="button" className="embedded-new-tab" aria-label="New connection" title="New connection · Quick connect" onClick={() => useUiStore.getState().setPaletteOpen(true)}><Plus className="size-4" /></button>
  </div>;
}

export function TerminalWorkspace({ children, renderHeader, openKeys }: { children: ReactNode; renderHeader?: (tabs: ReactNode) => ReactNode; openKeys?: () => void }) {
  const tabs = useTerminalStore((state) => state.tabs);
  const activeId = useTerminalStore((state) => state.activeId);
  const activate = useTerminalStore((state) => state.activate);
  const [closing, setClosing] = useState<string | null>(null);
  const strip = useRef<HTMLElement>(null);
  const requestClose = (id: string) => {
    const tab = useTerminalStore.getState().tabs.find((tab) => tab.id === id);
    if (tab?.state === "open" || tab?.state === "connecting") setClosing(id);
    else useTerminalStore.getState().close(id);
  };
  useEffect(() => () => useTerminalStore.getState().reset(), []);
  useEffect(() => { strip.current?.querySelector<HTMLElement>('[data-active="true"]')?.scrollIntoView({ block: "nearest", inline: "nearest" }); }, [activeId, tabs.length]);
  useEffect(() => {
    const keydown = (event: KeyboardEvent) => {
      if (event.isComposing || event.defaultPrevented || event.target instanceof Element && event.target.closest('[role="dialog"], [role="alertdialog"], [role="menu"]')) return;
      const current = useTerminalStore.getState();
      if (!current.tabs.length) return;
      const mac = /Mac/.test(navigator.platform);
      if (current.activeId && (mac ? event.metaKey && !event.ctrlKey : event.ctrlKey && event.shiftKey) && event.key.toLowerCase() === "w") {
        event.preventDefault(); event.stopPropagation(); requestClose(current.activeId);
      } else if (event.ctrlKey && !event.metaKey && event.key === "Tab") {
        event.preventDefault(); event.stopPropagation();
        const ids = [null, ...current.tabs.map((tab) => tab.id)];
        const index = ids.indexOf(current.activeId);
        current.activate(ids[(index + (event.shiftKey ? ids.length - 1 : 1)) % ids.length]);
      }
    };
    window.addEventListener("keydown", keydown, true);
    return () => window.removeEventListener("keydown", keydown, true);
  }, []);
  const tabBar = tabs.length > 0 ? <SessionTabBar tabs={tabs} activeId={activeId} activate={activate} requestClose={requestClose} strip={strip} /> : null;
  return <div className="terminal-workspace">
    {renderHeader ? renderHeader(tabBar) : tabBar}
    <div id="terminal-library" className="terminal-library" role={tabs.length ? "tabpanel" : undefined} aria-labelledby={tabs.length ? "terminal-tab-library" : undefined} hidden={!!activeId}>{children}</div>
    <Suspense fallback={activeId ? <div className="flex flex-1 items-center justify-center text-muted-foreground">Loading terminal…</div> : null}>
      {tabs.map((tab) => <TerminalPane key={tab.id} tab={tab} active={activeId === tab.id} openKeys={openKeys} />)}
    </Suspense>
    <Dialog open={closing !== null} onOpenChange={(open) => { if (!open) setClosing(null); }}>
      <DialogContent onCloseAutoFocus={(event) => {
        event.preventDefault();
        requestAnimationFrame(() => {
          const id = useTerminalStore.getState().activeId;
          const panel = document.getElementById(id ? `terminal-panel-${id}` : "terminal-library");
          const input = panel?.querySelector<HTMLElement>("input, textarea");
          const tab = document.getElementById(id ? `terminal-tab-${id}` : "terminal-tab-library");
          (input ?? tab)?.focus();
        });
      }}>
        <DialogTitle>Close terminal?</DialogTitle>
        <DialogDescription>This ends this SSH session. Running commands may stop. Reconnecting opens a new shell.</DialogDescription>
        <DialogFooter>
          <Button variant="outline" onClick={() => setClosing(null)}>Cancel</Button>
          <Button variant="destructive" onClick={() => { if (closing) useTerminalStore.getState().close(closing); setClosing(null); }}>Close terminal</Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  </div>;
}
