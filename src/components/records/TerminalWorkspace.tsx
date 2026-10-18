import { lazy, Suspense, useEffect, useRef, useState, type ReactNode } from "react";
import { Library, Plus, Terminal, X } from "lucide-react";
import { useTerminalStore } from "@/stores/terminals";
import { useUiStore } from "@/stores/ui";
import { Button } from "@/components/ui/button";
import { Dialog, DialogContent, DialogTitle, DialogDescription, DialogFooter } from "@/components/ui/dialog";
import "./terminal.css";
const TerminalPane = lazy(() => import("./TerminalPane").then((module) => ({ default: module.TerminalPane })));

export function TerminalWorkspace({ children }: { children: ReactNode }) {
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
      if (event.isComposing || event.defaultPrevented || event.target instanceof Element && event.target.closest('[role="dialog"], [role="alertdialog"]')) return;
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
  return <div className="terminal-workspace">
    {tabs.length > 0 && <nav ref={strip} className="embedded-tabs" aria-label="Workspace sessions">
      <div className="embedded-tab" data-active={!activeId}>
        <button type="button" aria-current={!activeId ? "page" : undefined} onClick={() => activate(null)}><Library className="size-3.5" /><span>Library</span></button>
      </div>
      {tabs.map((tab) => <div key={tab.id} className="embedded-tab" data-active={activeId === tab.id}>
        <button type="button" title={`${tab.name} · ${tab.state}`} aria-current={activeId === tab.id ? "page" : undefined} onClick={() => activate(tab.id)}>
          <span className="embedded-state" data-state={tab.state} /><Terminal className="size-3.5" /><span>{tab.name}</span>
        </button>
        <button type="button" aria-label={`Close terminal ${tab.name}`} onClick={() => requestClose(tab.id)}><X className="size-3" /></button>
      </div>)}
      <button type="button" className="embedded-new-tab" aria-label="New connection" title="Quick connect" onClick={() => useUiStore.getState().setPaletteOpen(true)}><Plus className="size-4" /></button>
    </nav>}
    <div className="terminal-library" hidden={!!activeId}>{children}</div>
    <Suspense fallback={activeId ? <div className="flex flex-1 items-center justify-center text-muted-foreground">Loading terminal…</div> : null}>
      {tabs.map((tab) => <TerminalPane key={tab.id} tab={tab} active={activeId === tab.id} />)}
    </Suspense>
    <Dialog open={closing !== null} onOpenChange={(open) => { if (!open) setClosing(null); }}>
      <DialogContent>
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
