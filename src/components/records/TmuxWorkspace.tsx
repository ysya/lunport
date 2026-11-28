import { useCallback, useEffect, useRef, useState, type CSSProperties } from "react";
import { ArrowDown, ArrowUp, Columns2, Copy, LoaderCircle, MoreHorizontal, Plus, RotateCw, Rows2, Search, Unplug, X } from "lucide-react";
import type { WTerm } from "@wterm/dom";
import { writeText } from "@tauri-apps/plugin-clipboard-manager";
import { toast } from "sonner";
import { AlertDialog, AlertDialogAction, AlertDialogCancel, AlertDialogContent, AlertDialogDescription, AlertDialogFooter, AlertDialogTitle } from "@/components/ui/alert-dialog";
import { Button } from "@/components/ui/button";
import { DropdownMenu, DropdownMenuCheckboxItem, DropdownMenuContent, DropdownMenuItem, DropdownMenuSeparator, DropdownMenuTrigger } from "@/components/ui/dropdown-menu";
import { Input } from "@/components/ui/input";
import type { TmuxSelection, TmuxSessionInfo } from "@/lib/embedded-terminal";
import { isImeKey } from "@/lib/ime";
import { revealHidden } from "@/lib/reveal-hidden";
import { clampTerminalFontSize, DEFAULT_TERMINAL_FONT_SIZE } from "@/lib/settings-logic";
import { TerminalSession, type TerminalStatus } from "@/lib/terminal-session";
import { TmuxControl, type TmuxSnapshot } from "@/lib/tmux-control";
import { useSettingsStore } from "@/stores/settings";
import { useTerminalStore, type TerminalTab } from "@/stores/terminals";
import { TmuxDivider, TmuxPane, type RegisterTmuxPane } from "./TmuxPane";
import { forgetTmuxWorkspace, readTmuxWorkspace, rememberTmuxWorkspace, sameTmuxSession, workspaceWindow, type TmuxWorkspaceLocation } from "@/lib/tmux-workspace-state";
import "./terminal.css";
import "./tmux-workspace.css";

const initialStatus: TerminalStatus = { kind: "connecting", text: "Connecting…", autoReconnect: true };
const emptySearch = { count: 0, activeIndex: -1, searching: false, limited: false };
const dialogSelector = '[role="dialog"], [role="alertdialog"], [role="menu"]';

type Confirmation = { kind: "detach" }
  | { kind: "session"; session: TmuxSessionInfo }
  | { kind: "window"; session: TmuxSessionInfo; id: string; name: string };

type WorkspaceActions = {
  choose: (target: TmuxSelection, session?: TmuxSessionInfo, location?: TmuxWorkspaceLocation) => void;
  command: (run: (control: TmuxControl) => Promise<void>) => void;
  openWindow: (id?: string) => void;
  register: RegisterTmuxPane;
  input: (id: string, data: string | Uint8Array) => void;
  focus: (id: string) => void;
  terminal: (id: string | undefined) => WTerm | undefined;
  selection: () => string | undefined;
  activate: () => void;
  resize: (cols: number, rows: number) => void;
  reconnect: (chooseAgain?: boolean) => void;
  terminate: (confirmation: Exclude<Confirmation, { kind: "detach" }>) => void;
  disconnect: () => void;
  setAutoReconnect: (enabled: boolean) => void;
};

function TmuxSessionPicker({ inputId, sessions, remembered, onChoose }: {
  inputId: string;
  sessions: TmuxSessionInfo[];
  remembered: TmuxWorkspaceLocation | null;
  onChoose: WorkspaceActions["choose"];
}) {
  const [name, setName] = useState("");
  const [nameError, setNameError] = useState("");
  const previous = remembered && sessions.find((session) => sameTmuxSession(remembered.session, session));
  const attach = (session: TmuxSessionInfo, location?: TmuxWorkspaceLocation) => {
    onChoose({ kind: "attach", id: session.id, created: session.created, server: session.server }, session, location);
  };

  return <div className="tmux-picker">
    <h2>Choose a tmux session</h2>
    {previous && remembered && <Button className="tmux-resume" variant="secondary" onClick={() => attach(previous, remembered)}>
      <RotateCw />Resume {revealHidden(previous.name)}
    </Button>}
    {remembered && !previous && <p role="status">Your last tmux session is no longer available.</p>}
    {sessions.length ? <ul aria-label="Available tmux sessions">
      {sessions.map((session) => <li key={session.id}>
        <div><span>{revealHidden(session.name)}</span>
          {session.destroyUnattached && <small>May end when the last client detaches</small>}
        </div>
        <Button size="sm" variant="outline" aria-label={`Attach to ${revealHidden(session.name)}`} onClick={() => attach(session)}>Attach</Button>
      </li>)}
    </ul> : <p>No running tmux sessions on this host.</p>}
    <form className="tmux-create" onSubmit={(event) => {
      event.preventDefault();
      if (name !== name.trim() || /[\\\p{Cc}]/u.test(name) || name.endsWith(";") || new TextEncoder().encode(name).length > 128) {
        setNameError("Use up to 128 UTF-8 bytes with no leading or trailing spaces, backslashes, control characters or trailing semicolon.");
        return;
      }
      onChoose({ kind: "create", name });
    }}>
      <label htmlFor={inputId}>New session name</label>
      <div>
        <Input id={inputId} value={name} autoComplete="off" required maxLength={128} aria-invalid={!!nameError}
          aria-describedby={nameError ? `${inputId}-error` : undefined}
          onChange={(event) => { setName(event.target.value); setNameError(""); }} />
        <Button type="submit"><Plus />Create session</Button>
      </div>
      {nameError && <p id={`${inputId}-error`} role="alert">{nameError}</p>}
    </form>
  </div>;
}

export function TmuxWorkspace({ tab, active, docked }: { tab: TerminalTab; active: boolean; docked?: boolean }) {
  const [status, setStatus] = useState(initialStatus);
  const [sessions, setSessions] = useState<TmuxSessionInfo[] | null>(null);
  const [remembered, setRemembered] = useState<TmuxWorkspaceLocation | null>(() => readTmuxWorkspace(tab.historyKey));
  const [snapshot, setSnapshot] = useState<TmuxSnapshot | null>(null);
  const [connectionCount, setConnectionCount] = useState(0);
  const [rendererCount, setRendererCount] = useState(0);
  const [viewedWindow, setViewedWindow] = useState<string | null>(null);
  const [focusedPane, setFocusedPane] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [confirmation, setConfirmation] = useState<Confirmation | null>(null);
  const [searchOpen, setSearchOpen] = useState(false);
  const [query, setQuery] = useState("");
  const [searchStatus, setSearchStatus] = useState(emptySearch);
  const workspace = useRef<HTMLElement>(null);
  const viewport = useRef<HTMLDivElement>(null);
  const probe = useRef<HTMLSpanElement>(null);
  const actions = useRef<WorkspaceActions | null>(null);
  const copyButton = useRef<HTMLButtonElement>(null);
  const copySelection = useRef<string | undefined>(undefined);
  const searchInput = useRef<HTMLInputElement>(null);
  const searchOpenRef = useRef(searchOpen);
  searchOpenRef.current = searchOpen;
  const activeRef = useRef(active);
  activeRef.current = active;
  const fontSize = useSettingsStore((state) => clampTerminalFontSize(state.terminalFontSize));
  const setFontSize = useSettingsStore((state) => state.setTerminalFontSize);
  const cursorBlink = useSettingsStore((state) => state.terminalCursorBlink !== false);
  const currentWindow = workspaceWindow(snapshot, viewedWindow);
  const visiblePanes = currentWindow?.panes.filter((pane) => pane.visible);
  const selectedPane = visiblePanes?.find((pane) => pane.id === focusedPane) ?? visiblePanes?.find((pane) => pane.id === currentWindow?.activePaneId) ?? visiblePanes?.[0];
  const selectedPaneId = selectedPane?.id;

  useEffect(() => {
    type PaneView = Parameters<RegisterTmuxPane>[1] & { loaded: boolean; capture: number; receiving: boolean };
    const panes = new Map<string, PaneView>();
    let control: TmuxControl | null = null;
    let layout: TmuxSnapshot | null = null;
    let target: TmuxSessionInfo | null = null;
    let restore: TmuxWorkspaceLocation | null = null;
    let location: TmuxWorkspaceLocation | null = tab.tmuxResume ?? null;
    let localWindow: string | null = null;
    let localPane: string | null = null;
    let wantFocus = false;
    let restoringFocus = false;
    let cancelled = false;
    let sentSize = "";
    let selecting = false;
    let endedReason = "";

    const remember = () => {
      const window = workspaceWindow(layout, localWindow);
      if (!target || !window) return;
      const pane = window.panes.find((candidate) => candidate.id === localPane && candidate.visible)
        ?? window.panes.find((candidate) => candidate.id === window.activePaneId);
      if (!pane) return;
      location = { session: target, windowId: window.id, paneId: pane.id };
      if (activeRef.current) rememberTmuxWorkspace(tab.historyKey, location);
    };
    const restorePaneFocus = () => {
      if (!wantFocus || !activeRef.current || searchOpenRef.current) return;
      const currentWindow = workspaceWindow(layout, localWindow);
      const id = currentWindow?.panes.find((pane) => pane.id === localPane && pane.visible)?.id ?? currentWindow?.activePaneId;
      const view = id && panes.get(id);
      if (!view || !view.loaded) return;
      wantFocus = false;
      requestAnimationFrame(() => {
        const focused = document.activeElement;
        if (!activeRef.current || searchOpenRef.current || panes.get(id) !== view || document.querySelector(dialogSelector)) return;
        if (focused !== document.body && focused?.id !== `terminal-tab-${tab.id}` && !focused?.closest('[role="tabpanel"][hidden]')) return;
        restoringFocus = true;
        try { view.terminal.focus(); }
        finally { restoringFocus = false; }
      });
    };
    const capturePane = (id: string, view: PaneView) => {
      const current = control;
      if (!current) return;
      const revision = ++view.capture;
      view.receiving = false;
      const currentCapture = () => control === current && panes.get(id) === view && view.capture === revision;
      // The capture marker is delivered inline with output frames. Earlier
      // frames already belong to the captured screen and are dropped.
      void current.capturePane(id, (capture) => {
        if (!currentCapture()) return;
        const first = !view.loaded;
        view.restore(capture, revision > 1);
        view.loaded = true;
        view.receiving = true;
        if (first) setRendererCount((count) => count + 1);
        restorePaneFocus();
      }).catch((cause: unknown) => {
        if (!currentCapture()) return;
        view.loaded = false;
        view.fail(cause);
      });
    };
    const syncPaneGeometry = (pane: { id: string; width: number; height: number }, view: PaneView) => {
      if (view.terminal.cols === pane.width && view.terminal.rows === pane.height) return;
      view.terminal.resize(pane.width, pane.height);
      // Resizing tmux can trigger a TUI redraw before the layout snapshot arrives.
      // Capture at the new dimensions to replace bytes parsed at the old width.
      capturePane(pane.id, view);
    };
    const resetView = () => {
      const previous = control;
      control = null;
      previous?.dispose();
      layout = null;
      localWindow = null;
      localPane = null;
      panes.clear();
      sentSize = "";
      setSnapshot(null);
      setViewedWindow(null);
      setFocusedPane(null);
    };
    const fail = (cause: unknown) => {
      if (!cancelled) setError(revealHidden(cause instanceof Error ? cause.message : String(cause)));
    };
    const choose: WorkspaceActions["choose"] = (selection, known, previous) => {
      if (cancelled || selecting) return;
      if (known && !useTerminalStore.getState().claimTmuxSession(tab.id, known)) return;
      selecting = true;
      restore = previous ?? null;
      target = known ?? null;
      location = previous ?? null;
      endedReason = "";
      wantFocus = activeRef.current;
      setError(null);
      setSessions(null);
      setStatus((current) => ({ ...current, text: "Attaching to tmux…" }));
      void connection.selectTmux(selection).catch((cause: unknown) => {
        if (cancelled || !selecting) return;
        selecting = false;
        target = null;
        restore = null;
        useTerminalStore.getState().claimTmuxSession(tab.id);
        connection.disconnect();
        fail(cause);
      });
    };
    const discovered = (available: TmuxSessionInfo[]) => {
      if (cancelled) return;
      selecting = false;
      const requested = target ?? location?.session;
      if (requested) {
        const matching = available.find((session) => sameTmuxSession(requested, session));
        if (matching) {
          choose({ kind: "attach", id: matching.id, created: matching.created, server: matching.server }, matching, location ?? undefined);
          return;
        }
        setError("The tmux session you were using is no longer available.");
        forgetTmuxWorkspace(tab.historyKey, requested);
        target = null;
        restore = null;
        location = null;
        useTerminalStore.getState().claimTmuxSession(tab.id);
      }
      setRemembered(readTmuxWorkspace(tab.historyKey));
      setSessions(available);
    };
    const connectControl = () => {
      let recorded = false;
      let refreshing = false;
      let refreshAgain = false;
      const refresh = async () => {
        if (control !== next) return;
        if (refreshing) { refreshAgain = true; return; }
        refreshing = true;
        try {
          do {
            refreshAgain = false;
            const model = await next.snapshot();
            if (control !== next) return;
            const canonical = { id: model.sessionId, name: model.sessionName, created: model.sessionCreated, server: model.server, destroyUnattached: model.destroyUnattached };
            if (target && !sameTmuxSession(target, canonical)) {
              target = null;
              useTerminalStore.getState().claimTmuxSession(tab.id);
              connection.disconnect();
              fail("The selected tmux session changed before it could be opened.");
              return;
            }
            if (!target || target.name !== canonical.name || target.destroyUnattached !== canonical.destroyUnattached) {
              if (!useTerminalStore.getState().claimTmuxSession(tab.id, canonical)) return;
            }
            target = canonical;

            const previous = restore;
            restore = null;
            const window = workspaceWindow(model, previous?.windowId ?? localWindow);
            if (window?.id !== localWindow) localPane = null;
            if (previous && sameTmuxSession(previous.session, canonical)) {
              localPane = window?.panes.find((pane) => pane.id === previous.paneId && pane.visible)?.id ?? null;
            }
            localWindow = window?.id ?? null;
            layout = model;
            for (const pane of window?.panes ?? []) {
              const view = panes.get(pane.id);
              if (pane.visible && view) syncPaneGeometry(pane, view);
            }
            if (!recorded) {
              recorded = true;
              try { useSettingsStore.getState().recordConnection(tab.historyKey); } catch { /* History is optional. */ }
            }
            remember();
            setViewedWindow(localWindow);
            setFocusedPane(localPane);
            setSnapshot(model);
          } while (refreshAgain);
        } catch (cause) {
          if (control === next) fail(cause);
        } finally {
          refreshing = false;
        }
      };
      const next = new TmuxControl({
        write: (bytes) => connection.input(bytes),
        onTopologyChanged: () => { void refresh(); },
        onOutput: (id, bytes) => {
          const view = panes.get(id);
          if (control === next && view?.receiving) view.write(bytes);
        },
        onExit: (reason, source) => {
          if (control !== next) return;
          endedReason = reason || "tmux exited";
          resetView();
          if (source === "protocol") connection.disconnect();
          if (reason) fail(reason);
        },
      });
      control = next;
      setConnectionCount((count) => count + 1);
      void refresh();
      return refresh;
    };

    let refreshLayout: (() => Promise<void>) | undefined;
    const connection = new TerminalSession(tab.host, (bytes) => control?.feed(bytes), (next) => {
      if (cancelled) return;
      if (next.kind === "open") {
        if (!control && !endedReason) {
          selecting = false;
          refreshLayout = connectControl();
        }
      } else {
        resetView();
        if (next.kind === "error" || next.kind === "ended") {
          selecting = false;
          setSessions(null);
        }
      }
      setStatus(next);
    }, () => {
      resetView();
      endedReason = "";
      selecting = false;
      setSessions(null);
    }, { tmuxSessions: discovered });

    actions.current = {
      choose,
      command: (run) => {
        const current = control;
        if (!current) return;
        void run(current).then(() => { if (control === current) void refreshLayout?.(); })
          .catch((cause: unknown) => { if (control === current) fail(cause); });
      },
      openWindow: (id) => {
        const current = control;
        if (!current) return;
        const opened = id ? current.selectWindow(id).then(() => id) : current.newWindow();
        void opened.then((windowId) => {
          if (control !== current) return;
          if (localWindow !== windowId) localPane = null;
          localWindow = windowId;
          void refreshLayout?.();
        }).catch((cause: unknown) => { if (control === current) fail(cause); });
      },
      register: (id, pane) => {
        if (!control) return () => {};
        const view = { ...pane, loaded: false, capture: 0, receiving: false };
        panes.set(id, view);
        const geometry = workspaceWindow(layout, localWindow)?.panes.find((candidate) => candidate.id === id);
        if (geometry && (view.terminal.cols !== geometry.width || view.terminal.rows !== geometry.height)) {
          view.terminal.resize(geometry.width, geometry.height);
        }
        capturePane(id, view);
        return () => { if (panes.get(id) === view) panes.delete(id); };
      },
      input: (id, bytes) => {
        const current = control;
        if (!current || !panes.get(id)?.loaded) return;
        void current.sendInput(id, bytes).catch((cause: unknown) => { if (control === current) fail(cause); });
      },
      focus: (id) => {
        const current = control;
        const window = workspaceWindow(layout, localWindow);
        if (!current || !window?.panes.some((pane) => pane.id === id && pane.visible)) return;
        if (localPane !== id) {
          localPane = id;
          setFocusedPane(id);
          remember();
        }
        if (!restoringFocus && window.activePaneId !== id) {
          void current.selectPane(id).catch((cause: unknown) => { if (control === current) fail(cause); });
        }
      },
      terminal: (id) => {
        const view = id ? panes.get(id) : undefined;
        return view?.loaded ? view.terminal : undefined;
      },
      selection: () => {
        for (const view of panes.values()) {
          const text = view.terminal.getSelectionText();
          if (text) return text;
        }
      },
      activate: () => {
        remember();
        if (layout) wantFocus = true;
        restorePaneFocus();
      },
      resize: (cols, rows) => {
        const current = control;
        const key = `${cols}x${rows}`;
        if (!current || key === sentSize) return;
        sentSize = key;
        void current.resize(cols, rows).then(() => {
          if (control === current && sentSize === key) void refreshLayout?.();
        }).catch((cause: unknown) => {
          if (control !== current || sentSize !== key) return;
          sentSize = "";
          fail(cause);
        });
      },
      reconnect: (chooseAgain) => {
        setError(null);
        setSessions(null);
        if (chooseAgain) {
          target = null;
          location = null;
          restore = null;
          useTerminalStore.getState().claimTmuxSession(tab.id);
        }
        void connection.reconnect();
      },
      terminate: (confirmed) => {
        const current = control;
        if (!current || !target || !sameTmuxSession(confirmed.session, target)) return;
        const terminate = confirmed.kind === "session" ? current.killSession() : current.killWindow(confirmed.id);
        void terminate.then(() => {
          if (cancelled) return;
          if (confirmed.kind === "session") useTerminalStore.getState().close(tab.id);
          else if (control === current) void refreshLayout?.();
        }).catch((cause: unknown) => { if (control === current) fail(cause); });
      },
      disconnect: () => connection.disconnect(),
      setAutoReconnect: (enabled) => connection.setAutoReconnect(enabled),
    };
    const online = () => connection.networkRestored();
    window.addEventListener("online", online);
    void connection.start(80, 24);
    return () => {
      cancelled = true;
      actions.current = null;
      control?.dispose();
      connection.dispose();
      window.removeEventListener("online", online);
    };
  }, [tab.id, tab.host, tab.historyKey, tab.tmuxResume]);

  const register = useCallback<RegisterTmuxPane>((id, pane) => actions.current?.register(id, pane) ?? (() => {}), []);
  const onPaneFocus = useCallback((id: string) => actions.current?.focus(id), []);
  const onPaneInput = useCallback((id: string, data: string | Uint8Array) => actions.current?.input(id, data), []);
  const focusPane = useCallback(() => {
    if (activeRef.current && !document.querySelector(dialogSelector)) actions.current?.terminal(selectedPaneId)?.focus();
  }, [selectedPaneId]);
  const closeSearch = useCallback(() => {
    setSearchOpen(false);
    requestAnimationFrame(focusPane);
  }, [focusPane]);

  useEffect(() => { useTerminalStore.getState().updateState(tab.id, status.kind); }, [tab.id, status.kind]);
  const hasLayout = snapshot !== null;
  useEffect(() => {
    const surface = viewport.current;
    const cell = probe.current;
    if (!active || !hasLayout || !surface || !cell) return;
    const resize = () => {
      const metric = cell.getBoundingClientRect();
      if (!metric.width || !metric.height || !surface.clientWidth || !surface.clientHeight) return;
      surface.style.setProperty("--tmux-cell-width", `${metric.width}px`);
      surface.style.setProperty("--tmux-cell-height", `${metric.height}px`);
      actions.current?.resize(
        Math.max(1, Math.min(1000, Math.floor(surface.clientWidth / metric.width))),
        Math.max(1, Math.min(1000, Math.floor(surface.clientHeight / metric.height))),
      );
    };
    const observer = new ResizeObserver(resize);
    observer.observe(surface);
    observer.observe(cell);
    resize();
    return () => observer.disconnect();
  }, [active, hasLayout, connectionCount]);

  useEffect(() => {
    setSearchStatus(emptySearch);
    if (!searchOpen) return;
    const terminal = actions.current?.terminal(selectedPaneId);
    if (!terminal) return;
    terminal.onSearchChange = setSearchStatus;
    terminal.search(query);
    return () => { terminal.onSearchChange = null; terminal.clearSearch(); };
  }, [query, searchOpen, selectedPaneId, connectionCount, rendererCount]);

  useEffect(() => {
    if (active) actions.current?.activate();
  }, [active]);

  useEffect(() => {
    if (searchOpen && active) { searchInput.current?.focus(); searchInput.current?.select(); }
  }, [searchOpen, active]);

  useEffect(() => {
    if (!active) return;
    const rememberSelection = (event: PointerEvent) => {
      // WTerm clears its custom selection during the following document capture phase.
      copySelection.current = event.button === 0 && copyButton.current && event.composedPath().includes(copyButton.current)
        ? actions.current?.selection() : undefined;
    };
    const clearSelection = () => { copySelection.current = undefined; };
    window.addEventListener("pointerdown", rememberSelection, true);
    window.addEventListener("pointercancel", clearSelection, true);
    return () => {
      window.removeEventListener("pointerdown", rememberSelection, true);
      window.removeEventListener("pointercancel", clearSelection, true);
      clearSelection();
    };
  }, [active]);

  useEffect(() => {
    if (!active || !hasLayout) return;
    const keydown = (event: KeyboardEvent) => {
      if (isImeKey({ nativeEvent: event, keyCode: event.keyCode }) || event.defaultPrevented || document.querySelector(dialogSelector)) return;
      const target = event.target instanceof Element ? event.target : null;
      if ((!target || !workspace.current?.contains(target)) && (docked || target?.closest('input, textarea, [contenteditable="true"]'))) return;
      const modifier = /Mac/.test(navigator.platform) ? event.metaKey && !event.ctrlKey : event.ctrlKey && !event.metaKey;
      if (!modifier || event.altKey) return;
      const key = event.key.toLowerCase();
      if (!["f", "=", "+", "-", "0"].includes(key)) return;
      event.preventDefault();
      event.stopPropagation();
      if (key === "f") {
        setSearchOpen(true);
        searchInput.current?.focus();
        searchInput.current?.select();
      } else {
        const size = clampTerminalFontSize(useSettingsStore.getState().terminalFontSize);
        setFontSize(key === "0" ? DEFAULT_TERMINAL_FONT_SIZE : clampTerminalFontSize(size + (key === "-" ? -1 : 1)));
      }
    };
    window.addEventListener("keydown", keydown, true);
    return () => window.removeEventListener("keydown", keydown, true);
  }, [active, docked, hasLayout, setFontSize]);

  const closeTab = () => useTerminalStore.getState().close(tab.id);
  const detach = () => snapshot?.destroyUnattached ? setConfirmation({ kind: "detach" }) : closeTab();
  const attached = snapshot && { id: snapshot.sessionId, name: snapshot.sessionName, created: snapshot.sessionCreated, server: snapshot.server, destroyUnattached: snapshot.destroyUnattached };
  const copy = async (pointerClick: boolean) => {
    const text = (pointerClick ? copySelection.current : undefined) ?? actions.current?.selection();
    copySelection.current = undefined;
    if (!text) { toast("Select terminal text to copy"); return; }
    try { await writeText(text); } catch { toast.error("Could not copy terminal selection"); }
  };
  const find = (previous: boolean) => {
    const terminal = actions.current?.terminal(selectedPaneId);
    if (previous) terminal?.findPrevious();
    else terminal?.findNext();
  };

  return <section ref={workspace} id={`terminal-panel-${tab.id}`} role="tabpanel" aria-labelledby={`terminal-tab-${tab.id}`} className="embedded-pane tmux-workspace" hidden={!active}>
    {snapshot && currentWindow && <>
      <div className="tmux-toolbar">
        <nav className="tmux-window-tabs" aria-label="tmux windows">
          {snapshot.windows.map((window) => <Button key={window.id} size="sm" variant="ghost" title={revealHidden(window.name)} aria-pressed={window.id === currentWindow.id}
            onClick={() => actions.current?.openWindow(window.id)}>
            <span className="tmux-window-index">{window.index}</span><span className="tmux-window-name">{revealHidden(window.name)}</span>
          </Button>)}
        </nav>
        <Button size="icon-sm" variant="ghost" aria-label="New window" title="New window" onClick={() => actions.current?.openWindow()}><Plus /></Button>
        <div className="tmux-pane-actions">
          <Button size="icon-sm" variant="ghost" disabled={!selectedPaneId} aria-label="Split pane side by side" title="Split pane side by side"
            onClick={() => actions.current?.command((control) => control.splitPane(selectedPaneId!, "horizontal"))}><Columns2 /></Button>
          <Button size="icon-sm" variant="ghost" disabled={!selectedPaneId} aria-label="Split pane top and bottom" title="Split pane top and bottom"
            onClick={() => actions.current?.command((control) => control.splitPane(selectedPaneId!, "vertical"))}><Rows2 /></Button>
          <Button ref={copyButton} size="icon-sm" variant="ghost" aria-label="Copy selection" title="Copy selection"
            onPointerDown={(event) => { if (event.button === 0) event.preventDefault(); }} onClick={(event) => void copy(event.detail > 0)}><Copy /></Button>
          <Button size="icon-sm" variant="ghost" aria-label="Find in pane" title="Find in pane" aria-expanded={searchOpen}
            onClick={() => { if (searchOpen) closeSearch(); else setSearchOpen(true); }}><Search /></Button>
        </div>
      </div>
      {searchOpen && <div className="embedded-search tmux-search" role="search" aria-label="Search tmux pane">
        <Input ref={searchInput} value={query} placeholder="Find in pane…" aria-label="Find in pane" onChange={(event) => setQuery(event.target.value)} onKeyDown={(event) => {
          if (isImeKey(event)) return;
          if (event.key === "Enter") { event.preventDefault(); find(event.shiftKey); }
          else if (event.key === "Escape") { event.preventDefault(); event.stopPropagation(); closeSearch(); }
        }} />
        <span role="status">{searchStatus.searching ? "Searching…" : query ? `${searchStatus.activeIndex + 1} / ${searchStatus.count}${searchStatus.limited ? "+" : ""}` : ""}</span>
        <Button size="icon-sm" variant="ghost" aria-label="Previous match" disabled={!searchStatus.count} onClick={() => find(true)}><ArrowUp /></Button>
        <Button size="icon-sm" variant="ghost" aria-label="Next match" disabled={!searchStatus.count} onClick={() => find(false)}><ArrowDown /></Button>
        <Button size="icon-sm" variant="ghost" aria-label="Close pane search" onClick={closeSearch}><X /></Button>
      </div>}
      <div ref={viewport} className="tmux-viewport" style={{ "--term-font-size": `${fontSize}px`, "--tmux-row-height": `${fontSize * 1.4}px` } as CSSProperties}>
        <span className="tmux-cell-probe" ref={probe} aria-hidden="true">W</span>
        <div key={`${connectionCount}:${currentWindow.id}`} className="tmux-layout" style={{ "--tmux-cols": currentWindow.width, "--tmux-rows": currentWindow.height } as CSSProperties}>
          {visiblePanes?.map((pane) => <TmuxPane key={pane.id} pane={pane} selected={pane.id === selectedPaneId} active={active}
            cursorBlink={cursorBlink} register={register} onFocus={onPaneFocus} onInput={onPaneInput} />)}
          {visiblePanes?.map((pane) => <div key={`dividers-${pane.id}`}>
            {pane.left + pane.width < currentWindow.width - 1 && <TmuxDivider pane={pane} axis="cols" max={currentWindow.width - pane.left - 2}
              onResize={(cols) => actions.current?.command((control) => control.resizePane(pane.id, { cols }))} />}
            {pane.top + pane.height < currentWindow.height - 1 && <TmuxDivider pane={pane} axis="rows" max={currentWindow.height - pane.top - 2}
              onResize={(rows) => actions.current?.command((control) => control.resizePane(pane.id, { rows }))} />}
          </div>)}
        </div>
      </div>
    </>}
    {sessions && !snapshot && <TmuxSessionPicker inputId={`tmux-new-name-${tab.id}`} sessions={sessions} remembered={remembered} onChoose={(selection, known, previous) => actions.current?.choose(selection, known, previous)} />}
    {!sessions && !snapshot && <div className="tmux-connection-message">
      {status.kind === "connecting" && <LoaderCircle className="size-5 motion-safe:animate-spin" />}
      <strong role="status">{status.question ? "Authentication required" : status.kind === "open" ? "Loading tmux workspace…" : revealHidden(status.text)}</strong>
      {(status.kind === "ended" || status.kind === "error" || status.retry || error) && <div>
        <Button size="sm" onClick={() => actions.current?.reconnect()}><RotateCw />{status.retry ? "Retry now" : "Reconnect"}</Button>
        {(status.kind === "ended" || status.kind === "error" || error) && <Button size="sm" variant="outline" onClick={() => actions.current?.reconnect(true)}>Choose a session</Button>}
        {status.retry && <Button size="sm" variant="outline" onClick={() => actions.current?.disconnect()}>Stop retrying</Button>}
      </div>}
    </div>}
    {error && <div className="tmux-error" role="alert"><span>{error}</span><Button size="icon-xs" variant="ghost" aria-label="Dismiss error" onClick={() => setError(null)}><X /></Button></div>}
    <footer className="embedded-statusbar tmux-statusbar">
      <div className="embedded-connection">
        <span className="embedded-address" title={tab.address}>{tab.address}</span>
        {snapshot && <span className="tmux-session-name" title={revealHidden(snapshot.sessionName)}>{revealHidden(snapshot.sessionName)}</span>}
      </div>
      {snapshot?.destroyUnattached && <span className="tmux-detach-warning">May end when the last client detaches</span>}
      <div className="embedded-actions">
        <Button size="xs" variant="outline" onClick={detach}><Unplug />{snapshot ? "Detach" : "Close"}</Button>
        {attached && currentWindow && <DropdownMenu>
          <DropdownMenuTrigger asChild><Button size="icon-xs" variant="ghost" aria-label="tmux options"><MoreHorizontal /></Button></DropdownMenuTrigger>
          <DropdownMenuContent align="end">
            <DropdownMenuCheckboxItem checked={status.autoReconnect} onCheckedChange={(enabled) => actions.current?.setAutoReconnect(enabled)}>Automatically reconnect</DropdownMenuCheckboxItem>
            <DropdownMenuSeparator />
            <DropdownMenuItem variant="destructive" onSelect={() => setConfirmation({
              kind: "window", session: attached, id: currentWindow.id, name: currentWindow.name,
            })}>Terminate window…</DropdownMenuItem>
            <DropdownMenuItem variant="destructive" onSelect={() => setConfirmation({ kind: "session", session: attached })}>Terminate session…</DropdownMenuItem>
          </DropdownMenuContent>
        </DropdownMenu>}
      </div>
    </footer>
    <AlertDialog open={active && confirmation !== null} onOpenChange={(open) => { if (!open) setConfirmation(null); }}>
      <AlertDialogContent>
        <AlertDialogTitle>{confirmation?.kind === "detach" ? "Detach from this tmux session?" : confirmation?.kind === "window" ? "Terminate tmux window?" : "Terminate tmux session?"}</AlertDialogTitle>
        <AlertDialogDescription>{confirmation?.kind === "detach"
          ? `“${revealHidden(snapshot?.sessionName ?? "")}” may end when its last client detaches, depending on the server settings.`
          : confirmation?.kind === "window"
          ? `This closes “${revealHidden(confirmation.name)}” in every linked session and stops its processes. Any session left without windows also ends.`
          : confirmation ? `This ends “${revealHidden(confirmation.session.name)}” on the host and stops processes in windows it does not share with other sessions.` : ""}</AlertDialogDescription>
        <AlertDialogFooter>
          <AlertDialogCancel>Cancel</AlertDialogCancel>
          <AlertDialogAction variant="destructive" onClick={() => {
            if (confirmation?.kind === "detach") closeTab();
            else if (confirmation) actions.current?.terminate(confirmation);
          }}>{confirmation?.kind === "detach" ? "Detach" : confirmation?.kind === "window" ? "Terminate window" : "Terminate session"}</AlertDialogAction>
        </AlertDialogFooter>
      </AlertDialogContent>
    </AlertDialog>
  </section>;
}
