import { lazy, Suspense, useEffect, useRef, useState, type ReactNode, type RefObject } from "react";
import { CircleAlert, Database, Library, LoaderCircle, Maximize2, Minus, PanelBottom, PanelLeftClose, PanelLeftOpen, Plus, Search, SquareTerminal, Table2, Terminal, Unplug, X } from "lucide-react";
import { useTerminalStore, type SessionTab } from "@/stores/terminals";
import { useSettingsStore } from "@/stores/settings";
import { useUiStore } from "@/stores/ui";
import { Button } from "@/components/ui/button";
import { Checkbox } from "@/components/ui/checkbox";
import { Dialog, DialogContent, DialogTitle, DialogDescription, DialogFooter } from "@/components/ui/dialog";
import { isImeKey } from "@/lib/ime";
import { revealHidden } from "@/lib/reveal-hidden";
import { DATABASE_EXPLORER_ID, DatabaseWorkspaceExplorer } from "./console/DatabaseWorkspaceExplorer";
import { useDatabaseWorkspace, type RelationDocument } from "./console/use-database-workspace";
import "./terminal.css";
const TerminalPane = lazy(() => import("./TerminalPane").then((module) => ({ default: module.TerminalPane })));
const TmuxWorkspace = lazy(() => import("./TmuxWorkspace").then((module) => ({ default: module.TmuxWorkspace })));
const DatabaseConsolePane = lazy(() => import("./console/DatabaseConsolePane"));

export function requestTerminalClose(id: string, onConfirm: (id: string) => void) {
  const tab = useTerminalStore.getState().tabs.find((item) => item.id === id);
  const confirm = tab?.kind === "terminal" && tab.mode === "tmux"
    ? tab.tmuxSession?.destroyUnattached
    : useSettingsStore.getState().confirmTerminalClose !== false;
  if (confirm && (tab?.state === "open" || tab?.state === "connecting")) onConfirm(id);
  else useTerminalStore.getState().close(id);
}

export function completeTerminalClose(id: string, doNotAskAgain: boolean) {
  if (doNotAskAgain) useSettingsStore.getState().setConfirmTerminalClose(false);
  useTerminalStore.getState().close(id);
}

/**
 * The session tabs the title bar shows. The strip, and the room between and around the tabs, drag the window: Tauri starts a drag
 * only from an element that carries `data-tauri-drag-region` itself, so the containers carry it and the tabs' buttons stay buttons.
 */
type WorkspaceTab = SessionTab & { document?: RelationDocument; sourceName?: string };

export function SessionTabBar({ tabs, activeId, activate, requestClose, strip, leading }: {
  tabs: WorkspaceTab[];
  activeId: string | null;
  activate: (id: string | null) => void;
  requestClose: (id: string) => void;
  strip: RefObject<HTMLElement | null>;
  leading?: ReactNode;
}) {
  return <div className="embedded-tabbar" data-tauri-drag-region>
    {leading}
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
        const database = tab.kind === "database";
        const tmux = !database && tab.mode === "tmux";
        const session = database ? undefined : tab.tmuxSession;
        const table = tab.document;
        const name = table ? revealHidden(table.relation) : session ? `${tab.name} / ${revealHidden(session.name)}` : tab.name;
        const ordinal = session || table ? "" : name.match(/ \(\d+\)$/)?.[0] ?? "";
        const label = table ? `${revealHidden(table.schema)}.${name} · ${tab.sourceName}` : `${name}${tmux ? " · tmux" : ""}`;
        return <div key={tab.id} className="embedded-tab" data-tauri-drag-region data-active={activeId === tab.id} data-state={tab.state} data-environment={database ? tab.environment : undefined} role="presentation">
        <button type="button" id={`terminal-tab-${tab.id}`} role="tab" title={`${label}\n${tab.address}\n${tab.state}`} aria-label={`${table ? label : name + (tmux ? ", tmux" : "")}, ${tab.state}`} aria-selected={activeId === tab.id} aria-controls={`terminal-panel-${table?.sessionId ?? tab.id}`} tabIndex={activeId === tab.id ? 0 : -1} onClick={() => activate(tab.id)}>
          {tab.state === "connecting" ? <LoaderCircle className="size-3.5 motion-safe:animate-spin" /> : tab.state === "error" ? <CircleAlert className="size-3.5 text-destructive" /> : tab.state === "ended" ? <Unplug className="size-3.5" /> : table ? <Table2 className="size-3.5" /> : database ? <Database className="size-3.5" /> : tmux ? <SquareTerminal className="size-3.5" /> : <Terminal className="size-3.5" />}
          {table ? <span className="embedded-tab-document"><span>{name}</span><span>{tab.sourceName}</span></span> : <span>{ordinal ? name.slice(0, -ordinal.length) : name}</span>}
          {ordinal && <span className="embedded-tab-ordinal">{ordinal.trim()}</span>}
        </button>
        <button type="button" className="embedded-tab-close" tabIndex={activeId === tab.id ? 0 : -1} aria-label={table ? `Close table ${label}` : `Close ${database ? "console" : tmux ? "tmux workspace" : "terminal"} ${name}`} onClick={() => requestClose(tab.id)}><X className="size-3" /></button>
      </div>;
      })}
    </nav>
    <button type="button" className="embedded-new-tab" aria-label="New connection" title="New connection · Quick connect" onClick={() => useUiStore.getState().setPaletteOpen(true)}><Plus className="size-4" /></button>
  </div>;
}

export function TerminalWorkspace({ children, renderHeader, openKeys }: { children: ReactNode; renderHeader?: (tabs: ReactNode) => ReactNode; openKeys?: () => void }) {
  const tabs = useTerminalStore((state) => state.tabs);
  const activeId = useTerminalStore((state) => state.activeId);
  const dockedId = useTerminalStore((state) => state.dockedId);
  const dockMaximized = useTerminalStore((state) => state.dockMaximized);
  const setDockMaximized = useTerminalStore((state) => state.setDockMaximized);
  const hideDock = useTerminalStore((state) => state.hideDock);
  const databaseActive = tabs.some((tab) => tab.id === activeId && tab.kind === "database");
  const dockVisible = !!dockedId && databaseActive;
  const settingsOpen = useUiStore((state) => state.settingsOpen);
  const database = useDatabaseWorkspace(tabs);
  const viewId = activeId ? database.selected[activeId] ?? activeId : null;
  const explorerVisible = databaseActive && !database.collapsed && !(dockVisible && dockMaximized);
  const workTabs = tabs.flatMap<WorkspaceTab>((tab) => tab.kind === "database"
    ? [tab, ...database.relations.filter((doc) => doc.sessionId === tab.id).map((doc) => ({
        ...tab, id: doc.id, document: doc, sourceName: revealHidden(tab.name),
      }))]
    : [tab]);
  const [closing, setClosing] = useState<string | null>(null);
  const closingKind = useTerminalStore((state) => state.tabs.find((tab) => tab.id === closing)?.kind);
  const consoleClose = closingKind === "database";
  const [doNotAskAgain, setDoNotAskAgain] = useState(false);
  const closingTab = tabs.find((tab) => tab.id === closing);
  const closingTmux = closingTab?.kind === "terminal" && closingTab.mode === "tmux";
  const closingSession = closingTab?.kind === "terminal" ? closingTab.tmuxSession : undefined;
  const strip = useRef<HTMLElement>(null);
  const closeOrigin = useRef<HTMLElement | null>(null);
  const requestClose = (id: string) => {
    closeOrigin.current = document.activeElement instanceof HTMLElement ? document.activeElement : null;
    setDoNotAskAgain(false);
    requestTerminalClose(id, setClosing);
  };
  const closeView = (id: string) => {
    const doc = database.findView(id);
    if (!doc) {
      requestClose(id);
      return;
    }
    database.closeView(doc);
    if (viewId === id || strip.current?.contains(document.activeElement)) {
      requestAnimationFrame(() => document.getElementById(`terminal-tab-${doc.sessionId}`)?.focus());
    }
  };
  const findDatabaseObject = () => {
    setDockMaximized(false);
    database.setCollapsed(false);
    requestAnimationFrame(() => document.getElementById(DATABASE_EXPLORER_ID)?.querySelector("input")?.focus());
  };
  const shortcuts = useRef({ viewId, workTabs, activate: database.activateView, closeView, databaseActive, findDatabaseObject });
  shortcuts.current = { viewId, workTabs, activate: database.activateView, closeView, databaseActive, findDatabaseObject };
  useEffect(() => () => useTerminalStore.getState().reset(), []);
  useEffect(() => { strip.current?.querySelector<HTMLElement>('[data-active="true"]')?.scrollIntoView({ block: "nearest", inline: "nearest" }); }, [viewId, workTabs.length]);
  useEffect(() => {
    const keydown = (event: KeyboardEvent) => {
      if (useUiStore.getState().settingsOpen || event.isComposing || event.defaultPrevented || event.target instanceof Element && event.target.closest('[role="dialog"], [role="alertdialog"], [role="menu"]')) return;
      const current = useTerminalStore.getState();
      const views = shortcuts.current;
      if (!current.tabs.length) return;
      const mac = /Mac/.test(navigator.platform);
      if (views.databaseActive && (mac ? event.metaKey && !event.ctrlKey : event.ctrlKey && !event.metaKey) &&
          !event.altKey && !event.shiftKey && event.key.toLowerCase() === "p" &&
          !(event.target instanceof Element && event.target.closest("[data-terminal-dock]"))) {
        event.preventDefault(); event.stopPropagation(); views.findDatabaseObject();
      } else if (current.activeId && (mac ? event.metaKey && !event.ctrlKey : event.ctrlKey && event.shiftKey) && event.key.toLowerCase() === "w") {
        const dockFocused = event.target instanceof Element && event.target.closest("[data-terminal-dock]");
        const closeId = (current.dockMaximized || dockFocused) && current.dockedId ? current.dockedId : views.viewId ?? current.activeId;
        event.preventDefault(); event.stopPropagation(); views.closeView(closeId);
      } else if (event.ctrlKey && !event.metaKey && event.key === "Tab") {
        event.preventDefault(); event.stopPropagation();
        const ids = [null, ...views.workTabs.map((tab) => tab.id)];
        const index = ids.indexOf(views.viewId);
        views.activate(ids[(index + (event.shiftKey ? ids.length - 1 : 1)) % ids.length]);
      }
    };
    window.addEventListener("keydown", keydown, true);
    return () => window.removeEventListener("keydown", keydown, true);
  }, []);
  const toggleExplorer = databaseActive && <><Button type="button" variant="ghost" size="icon" className="database-explorer-toggle shrink-0"
    aria-label={explorerVisible ? "Hide database explorer" : "Show database explorer"}
    aria-expanded={explorerVisible} aria-controls={DATABASE_EXPLORER_ID}
    onClick={() => {
      if (dockMaximized) { setDockMaximized(false); database.setCollapsed(false); }
      else database.setCollapsed((collapsed) => !collapsed);
    }}>
    {explorerVisible ? <PanelLeftClose className="size-4" /> : <PanelLeftOpen className="size-4" />}
  </Button>
    <Button type="button" variant="ghost" size="icon-sm" className="database-explorer-toggle shrink-0"
      aria-label="Find database objects" aria-controls={DATABASE_EXPLORER_ID} onClick={findDatabaseObject}>
      <Search className="size-4" />
    </Button></>;
  const tabBar = tabs.length > 0 ? <SessionTabBar tabs={workTabs} activeId={viewId} activate={database.activateView} requestClose={closeView} strip={strip} leading={toggleExplorer} /> : null;
  return <div className="terminal-workspace">
    {renderHeader ? renderHeader(tabBar) : tabBar}
    <div className="terminal-workspace-body" data-dock-open={dockVisible && !dockMaximized} data-database-explorer={explorerVisible}>
      {tabs.some((tab) => tab.kind === "database") && <DatabaseWorkspaceExplorer activeId={activeId} sources={database.sources}
        hidden={!explorerVisible} onBrowse={database.browse} onOpenQuery={database.openQuery} />}
      <div id="terminal-library" className="terminal-library" role={tabs.length ? "tabpanel" : undefined} aria-labelledby={tabs.length ? "terminal-tab-library" : undefined} hidden={!!activeId}>{children}</div>
      {tabs.map((tab) => {
        const docked = dockVisible && dockedId === tab.id;
        const active = !settingsOpen && (docked || (activeId === tab.id && !(dockVisible && dockMaximized)));
        if (tab.kind === "database") return <div key={tab.id} id={`terminal-panel-${tab.id}`} className="embedded-pane" data-database-pane role="tabpanel" aria-labelledby={`terminal-tab-${database.selected[tab.id] ?? tab.id}`} hidden={!active}>
          <Suspense fallback={<div className="flex flex-1 items-center justify-center text-muted-foreground">Loading console…</div>}>
            <DatabaseConsolePane tab={tab} active={active} workspace={{
              document: database.findView(database.selected[tab.id] ?? null),
              openQuery: () => database.openQuery(tab.id),
              register: database.register,
            }} />
          </Suspense>
        </div>;
        return <div key={tab.id} className="embedded-terminal-slot" hidden={!active} data-terminal-dock={docked ? (dockMaximized ? "maximized" : "docked") : undefined}>
          {docked && <header className="terminal-dock-header">
            <div className="terminal-dock-title">
              {tab.mode === "tmux" ? <SquareTerminal aria-hidden="true" /> : <Terminal aria-hidden="true" />}
              <span title={tab.address}>{tab.name}{tab.tmuxSession ? ` / ${revealHidden(tab.tmuxSession.name)}` : ""}</span>
            </div>
            <div className="terminal-dock-actions">
              <Button size="sm" variant="ghost" onClick={() => setDockMaximized(!dockMaximized)}>
                {dockMaximized ? <PanelBottom /> : <Maximize2 />}{dockMaximized ? "Dock" : "Maximize"}
              </Button>
              <Button size="sm" variant="ghost" onClick={() => {
                hideDock();
                document.getElementById(`terminal-tab-${viewId}`)?.focus();
              }}><Minus />Hide</Button>
              <Button size="sm" variant="ghost" onClick={() => requestClose(tab.id)}>{tab.mode === "tmux" ? "Detach" : "Disconnect"}</Button>
            </div>
          </header>}
          <Suspense fallback={active ? <div className="flex flex-1 items-center justify-center text-muted-foreground">Loading terminal…</div> : null}>
            {tab.mode === "tmux"
              ? <TmuxWorkspace tab={tab} active={active} docked={docked && !dockMaximized} />
              : <TerminalPane tab={tab} active={active} docked={docked && !dockMaximized} openKeys={openKeys} />}
          </Suspense>
        </div>;
      })}
    </div>
    <Dialog open={closing !== null} onOpenChange={(open) => { if (!open) { setClosing(null); setDoNotAskAgain(false); } }}>
      <DialogContent onCloseAutoFocus={(event) => {
        event.preventDefault();
        requestAnimationFrame(() => {
          const origin = closeOrigin.current;
          if (origin?.isConnected && !origin.closest("[hidden]")) {
            origin.focus();
            return;
          }
          const id = useTerminalStore.getState().activeId;
          const panel = document.getElementById(id ? `terminal-panel-${id}` : "terminal-library");
          const input = panel?.querySelector<HTMLElement>("input, textarea");
          const tab = document.getElementById(id ? `terminal-tab-${id}` : "terminal-tab-library");
          (input ?? tab)?.focus();
        });
      }}>
        <DialogTitle>{consoleClose ? "Close console?" : closingTmux ? (closingSession ? `Detach from ${revealHidden(closingSession.name)}?` : "Detach from tmux?") : "Close terminal?"}</DialogTitle>
        <DialogDescription>{consoleClose ? "This ends this database session, closes its table tabs, and cancels any query still running." : closingTmux ? "The remote tmux configuration may end this session when its last client detaches." : "This ends this SSH session. Running commands may stop. Reconnecting opens a new shell."}</DialogDescription>
        {!closingTmux && <label className="flex items-center gap-2 text-sm text-muted-foreground">
          <Checkbox checked={doNotAskAgain} onCheckedChange={(checked) => setDoNotAskAgain(checked === true)} />
          Don't ask again
        </label>}
        <DialogFooter>
          <Button variant="outline" onClick={() => { setClosing(null); setDoNotAskAgain(false); }}>Cancel</Button>
          <Button variant="destructive" onClick={() => { if (closing) completeTerminalClose(closing, !closingTmux && doNotAskAgain); setClosing(null); setDoNotAskAgain(false); }}>{consoleClose ? "Close console" : closingTmux ? "Detach" : "Close terminal"}</Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  </div>;
}
