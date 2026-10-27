import "./library.css";
import { UpdateIndicator } from "@/components/UpdatesPane";
import { BrandMark } from "@/components/app/BrandMark";
import { useCallback, useEffect, useRef, useState } from "react";
import { useQueryClient } from "@tanstack/react-query";
import {
  ArrowUpRight,
  Bot,
  ChevronDown,
  Cloud,
  MoreHorizontal,
  PanelLeftClose,
  PanelLeftOpen,
  RotateCw,
  Search,
  Settings,
  SunMoon,
  Terminal,
} from "lucide-react";
import { toast } from "sonner";
import { SettingsDialog } from "@/components/SettingsDialog";
import { useUiStore } from "@/stores/ui";
import { useGlobalHotkey } from "@/lib/global-hotkey";
import { isTypingContext, SEARCH_INPUT_ID } from "@/lib/app-shortcuts";
import { RecordsCommandPalette } from "./CommandPalette";
import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogTitle,
  DialogDescription,
  DialogFooter,
} from "@/components/ui/dialog";
import {
  DropdownMenu,
  DropdownMenuCheckboxItem,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuRadioGroup,
  DropdownMenuRadioItem,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import {
  applyRecordOverview,
  exportRecordHosts,
  recordsStatusKey,
  setRecordGroupOrder,
  type RecordOverview,
  type HostScope,
  type RecordsStatus,
} from "@/lib/records";
import { usePlatform, useTerminals } from "@/lib/queries";
import { effectiveNewTab, IN_APP_TERMINAL, terminalSupportsNewTab } from "@/lib/settings-logic";
import { useSettingsStore } from "@/stores/settings";
import { cn } from "@/lib/utils";
import { revealHidden } from "@/lib/sync-approvals";
import { useLastNonNull } from "@/lib/use-last-non-null";
import { RecordHostList } from "./HostList";
import { RecordHostEditor } from "./HostEditor";
import { RecordGroupEditor } from "./GroupEditor";
import { selectGroup } from "./group-tree";
import { selectHost } from "./editor";
import { RecordsKeysPanel, KEYS_SEARCH_INPUT_ID, GENERATE_KEY_BUTTON_ID } from "./KeysPanel";
import { RecordsAccountPanel } from "./AccountPanel";
import { RecordsImportPanel } from "./ImportPanel";
import { useCentralStatus } from "@/lib/use-central-status";
import { syncSummary } from "@/lib/central-status";
import { centralAutomaticStep, centralStatusKey } from "@/lib/central-sync";
import { WorkspaceTransfer } from "./WorkspaceTransfer";
import { decideHostSelection, type HostSelection } from "./selection";
import { LibraryNavigation, LIBRARY_NAVIGATION_ID, type WorkspacePanel } from "./LibraryNavigation";
import type { LibraryFilter } from "./library-view";
import { HostPreview } from "./HostPreview";
import { DetailPresence } from "@/components/app/DetailPresence";
import { connectSavedHost } from "./operations";
import { TerminalWorkspace } from "./TerminalWorkspace";
import { useTerminalStore } from "@/stores/terminals";
import { TunnelsPanel } from "./TunnelsPanel";
import { GoogleCloudPanel } from "./GoogleCloudPanel";

export function RecordsWorkspace({
  overview,
  reload,
}: {
  overview: RecordOverview;
  reload: () => void;
}) {
  const central = useCentralStatus();
  const summary = syncSummary(central.data);
  const [transferOpen, setTransferOpen] = useState(false);
  useGlobalHotkey();
  const setSettingsOpen = useUiStore((state) => state.setSettingsOpen);
  const setSettingsCategory = useUiStore((state) => state.setSettingsCategory);
  const setPaletteOpen = useUiStore((state) => state.setPaletteOpen);
  const sidebarCollapsed = useUiStore((state) => state.librarySidebarCollapsed);
  const toggleSidebar = useUiStore((state) => state.toggleLibrarySidebar);
  const openSettings = (category: "general" | "ai") => {
    setSettingsCategory(category);
    setSettingsOpen(true);
  };
  const client = useQueryClient();
  const [panel, setPanel] = useState<WorkspacePanel>("hosts");
  const activeTerminal = useTerminalStore((state) => state.activeId);
  const setActiveTerminal = useTerminalStore((state) => state.activate);
  const [filter, setFilter] = useState<LibraryFilter>({ kind: "all" });
  const [inspectedId, setInspectedId] = useState<string | null>(null);
  const [selectedHostId, setSelectedHostId] = useState<string | null>(null);
  const [selection, setSelection] = useState<HostSelection>({ kind: "none" });
  const editorKind = useLastNonNull(selection.kind === "none" ? null : selection.kind);
  const [pendingSelection, setPendingSelection] =
    useState<HostSelection | null>(null);
  const [dirty, setDirty] = useState(false);
  const [editorBusy, setEditorBusy] = useState(false);
  const editorRef = useRef<HTMLDivElement>(null);
  const editorOrigin = useRef<HTMLElement | null>(null);
  const isGroupEditor =
    selection.kind === "group" || selection.kind === "new_group";
  const [syncing, setSyncing] = useState(false);
  const [accountBusy, setAccountBusy] = useState(false);
  const [reordering, setReordering] = useState(false);
  const syncActive = syncing || accountBusy || !!overview.syncing;
  const [connectingId, setConnectingId] = useState<string | null>(null);
  const connectInFlight = useRef(false);
  const syncInFlight = useRef(false);
  const exportInFlight = useRef(false);
  const exportHosts = async (previousWorkspace: boolean) => {
    if (exportInFlight.current) return;
    exportInFlight.current = true;
    setEditorBusy(true);
    try {
      const receipt = await exportRecordHosts(previousWorkspace);
      if (receipt) toast.success(`Exported ${receipt.hosts} hosts and ${receipt.groups} Groups`, {
        description: "Passwords, SSH private keys and account credentials are excluded. Import this file on your other device, then assign SSH keys.",
      });
    } catch (failure) {
      toast.error("Could not export host settings", { description: revealHidden(String(failure)) });
    } finally {
      exportInFlight.current = false;
      setEditorBusy(false);
    }
  };
  const nonce = useRef(0);
  const platform = usePlatform();
  const terminals = useTerminals();
  const terminalId = useSettingsStore((state) => state.terminalId);
  const setTerminalId = useSettingsStore((state) => state.setTerminalId);
  const preferNewTab = useSettingsStore((state) => state.newTabConnect);
  const setNewTab = useSettingsStore((state) => state.setNewTabConnect);
  const toggleTheme = useSettingsStore((state) => state.toggleTheme);
  const newTab = effectiveNewTab(
    preferNewTab,
    terminalId,
    terminals.data ?? [],
  );
  const onDirty = useCallback((value: boolean) => setDirty(value), []);
  const accept = useCallback(
    (incoming: RecordOverview) => {
      applyRecordOverview(client, incoming);
      return (
        client.getQueryData<RecordsStatus>(recordsStatusKey)?.overview ??
        incoming
      );
    },
    [client],
  );
  const requestSelection = (next: HostSelection) => {
    if (editorBusy) return;
    const decision = decideHostSelection(selection, next, dirty, editorBusy);
    if (decision === "confirm") setPendingSelection(next);
    if (decision === "select") {
      if (selection.kind === "none" && next.kind !== "none") editorOrigin.current = document.activeElement as HTMLElement | null;
      setSelection(next);
      setDirty(false);
    }
  };
  const changeFilter = (next: LibraryFilter) => {
    setFilter(next);
    setInspectedId(null);
    setSelectedHostId(null);
  };
  const groupContext =
    panel === "hosts" && filter.kind === "group"
      ? selectGroup(overview.groups, filter.id)
      : null;
  const creationScope: HostScope = groupContext?.scope ??
    overview.library_scope ?? { kind: "local" };
  const newHost = (via?: "iap"): HostSelection => ({
    kind: "new",
    nonce: ++nonce.current,
    groupId: groupContext?.id,
    scope: creationScope,
    via,
  });
  const createHost = () => requestSelection(newHost());
  // The editor is a dialog over any panel, so the Google Cloud page's New IAP host needs no panel switch.
  const createIapHost = () => requestSelection(newHost("iap"));
  const createGroup = () =>
    requestSelection({
      kind: "new_group",
      nonce: ++nonce.current,
      parentId: groupContext?.id,
      scope: creationScope,
    });
  const editHost = (id: string) => {
    setPanel("hosts");
    setSelectedHostId(id);
    setInspectedId(null);
    requestSelection({ kind: "host", id });
  };
  const duplicateHost = (id: string) => {
    const source = selectHost(overview.hosts, id);
    if (!source || (source.scope.kind === "space" && overview.shared_writes_blocked)) return;
    setPanel("hosts");
    setSelectedHostId(id);
    setInspectedId(null);
    requestSelection({ kind: "new", nonce: ++nonce.current, duplicateSource: structuredClone(source) });
  };
  const connect = async (id: string) => {
    if (connectInFlight.current || editorBusy) return;
    connectInFlight.current = true;
    setConnectingId(id);
    try {
      await connectSavedHost(overview, id, terminalId, newTab);
    } catch (error) {
      toast.error("Could not open connection", {
        description: revealHidden(String(error)),
      });
    } finally {
      connectInFlight.current = false;
      setConnectingId(null);
    }
  };
  useEffect(() => {
    const keydown = (event: KeyboardEvent) => {
      if (activeTerminal) return;
      if (!(event.metaKey || event.ctrlKey) || event.altKey || event.shiftKey)
        return;
      if (event.target instanceof Element && event.target.closest('[role="dialog"], [role="alertdialog"]')) return;
      if (
        isTypingContext(event.target) &&
        ![SEARCH_INPUT_ID, KEYS_SEARCH_INPUT_ID, "tunnels-search"].includes((event.target as HTMLElement).id)
      )
        return;
      if (event.key.toLowerCase() === "n") {
        event.preventDefault();
        if (panel === "tunnels") document.getElementById("new-tunnel-button")?.click();
        else if (panel === "transports") createIapHost();
        else if (panel === "keys") document.getElementById(GENERATE_KEY_BUTTON_ID)?.click();
        else createHost();
      } else if (event.key.toLowerCase() === "f") {
        event.preventDefault();
        const searchId = panel === "tunnels" ? "tunnels-search" : panel === "keys" ? KEYS_SEARCH_INPUT_ID : SEARCH_INPUT_ID;
        if (panel !== "keys" && panel !== "tunnels") setPanel("hosts");
        window.requestAnimationFrame(() => {
          const input = document.getElementById(searchId);
          if (input instanceof HTMLInputElement) {
            input.focus();
            input.select();
          }
        });
      }
    };
    window.addEventListener("keydown", keydown);
    return () => window.removeEventListener("keydown", keydown);
  }, [requestSelection, panel, activeTerminal]);
  const onSaved = useCallback((id: string | null) => {
    setPanel("hosts");
    setSelection({ kind: "none" });
    setSelectedHostId(id);
    setInspectedId(null);
    setDirty(false);
  }, []);
  const onGroupSaved = useCallback((id: string | null) => {
    setPanel("hosts");
    setSelection({ kind: "none" });
    if (id) setFilter({ kind: "group", id });
    setDirty(false);
  }, []);
  const onDeleted = useCallback(() => {
    setSelection({ kind: "none" });
    setInspectedId(null);
    setSelectedHostId(null);
    setDirty(false);
  }, []);
  const sync = async () => {
    if (syncInFlight.current) return;
    syncInFlight.current = true;
    setSyncing(true);
    try {
      const progress = await centralAutomaticStep();
      client.setQueryData(centralStatusKey, progress.status);
      reload();
    } catch (failure) {
      toast.error("Could not start sync", { description: revealHidden(String(failure)) });
    } finally {
      syncInFlight.current = false;
      setSyncing(false);
    }
  };
  const selectedId = selection.kind === "host" ? selection.id : null;
  const selected = selectedId ? selectHost(overview.hosts, selectedId) : null;
  const selectedGroupId = selection.kind === "group" ? selection.id : null;
  const selectedGroup = selectedGroupId
    ? selectGroup(overview.groups, selectedGroupId)
    : null;
  const inspected = inspectedId
    ? selectHost(overview.hosts, inspectedId)
    : null;
  const terminalName = terminalId === IN_APP_TERMINAL ? "Lunport" :
    terminals.data?.find((terminal) => terminal.id === terminalId)?.label ?? "System default terminal";
  const shortcut = platform.data === "macos" ? "⌘ K" : activeTerminal ? "Ctrl Shift K" : "Ctrl K";
  return (
    <div className={cn("app-shell library-shell flex h-screen overflow-hidden", platform.data === "macos" && "is-macos")}
      data-sidebar-collapsed={sidebarCollapsed}>
      <div className="library-sidebar">
        <header className="library-sidebar-header" data-tauri-drag-region>
          <span className="library-app-name">
            <BrandMark className="size-5" />
            <span>Lunport</span>
          </span>
        </header>
        <LibraryNavigation
          overview={overview}
          panel={panel}
          filter={filter}
          navigate={(next) => { setActiveTerminal(null); setPanel(next); }}
          changeFilter={(next) => { setActiveTerminal(null); changeFilter(next); }}
          createGroup={createGroup}
          reordering={reordering}
          reorder={(ids) => {
            if (reordering) return;
            setReordering(true);
            const origin = document.activeElement instanceof HTMLElement ? document.activeElement : null;
            const order = overview.group_order ?? { ids: [], revision: null, blocked: false, sync_enabled: false };
            void setRecordGroupOrder(order, ids).then((incoming) => {
              accept(incoming);
              requestAnimationFrame(() => {
                if (origin?.isConnected && document.activeElement === document.body) origin.focus({preventScroll:true});
              });
            }).catch((error: unknown) => {
              toast.error("Could not reorder groups", { description: error instanceof Error ? error.message : String(error) });
              reload();
            }).finally(() => setReordering(false));
          }}
        />
      </div>
      <div className="library-workspace-column flex min-h-0 min-w-0 flex-1 flex-col">
        <TerminalWorkspace openKeys={() => {
          setActiveTerminal(null);
          setPanel("keys");
          requestAnimationFrame(() => document.getElementById(KEYS_SEARCH_INPUT_ID)?.focus());
        }} renderHeader={(tabs) => (
        <header
          data-tauri-drag-region
          className="library-titlebar"
          data-has-sessions={!!tabs}
        >
          <Button type="button" variant="ghost" size="icon" aria-label={sidebarCollapsed ? "Expand sidebar" : "Collapse sidebar"}
            aria-expanded={!sidebarCollapsed} aria-controls={LIBRARY_NAVIGATION_ID} onClick={toggleSidebar}>
            {sidebarCollapsed ? <PanelLeftOpen className="size-4" /> : <PanelLeftClose className="size-4" />}
          </Button>
          {tabs ?? <button
            type="button"
            className="library-quick-connect"
            onClick={() => setPaletteOpen(true)}
          >
            <Search className="size-3.5" />
            <span>Quick connect</span>
            <kbd>{shortcut}</kbd>
          </button>}
          <div className="library-titlebar-actions">
            <UpdateIndicator />
            <Button type="button" variant="ghost" size="sm" title="Sync settings"
              aria-label="Sync settings" aria-current={panel === "account" ? "page" : undefined} onClick={() => { setActiveTerminal(null); setPanel("account"); }}>
              <Cloud className="size-4" />
              <span className="library-sync-label">Sync</span>
            </Button>
            <Button type="button" variant="ghost" size="icon-sm" title="Settings"
              aria-label="Settings" onClick={() => openSettings("general")}>
              <Settings className="size-4" />
            </Button>
            <DropdownMenu>
              <DropdownMenuTrigger asChild>
                <Button variant="ghost" size="icon-sm" aria-label="Workspace menu">
                  <MoreHorizontal className="size-4" />
                </Button>
              </DropdownMenuTrigger>
              <DropdownMenuContent align="end">
                <DropdownMenuItem onSelect={reload}>
                  <RotateCw />
                  Refresh workspace
                </DropdownMenuItem>
                <DropdownMenuItem onSelect={toggleTheme}>
                  <SunMoon />
                  Toggle theme
                </DropdownMenuItem>
                <DropdownMenuSeparator />
                <DropdownMenuItem onSelect={() => openSettings("ai")}>
                  <Bot />
                  AI access (MCP)
                </DropdownMenuItem>
              </DropdownMenuContent>
            </DropdownMenu>
          </div>
        </header>
        )}>
        {overview.shared_writes_blocked && (
          <p role="status" className="library-notice">
            {syncActive
              ? "Setting up sync… Your saved records are kept while this finishes."
              : overview.pending_account
                ? "Sync setup is incomplete. Resume setup to continue."
                : "Shared changes are paused. Review sync settings to continue."}
            <Button
              variant="ghost"
              size="sm"
              onClick={() => setPanel("account")}
            >
              Review sync
              <ArrowUpRight className="size-3.5" />
            </Button>
          </p>
        )}
        {!syncActive &&
          !overview.central_mode && overview.account &&
          (!overview.library_enabled ||
            [...overview.hosts, ...overview.groups].some(
              (row) => row.scope.kind === "local",
            )) && (
            <div role="status" className="library-notice">
              <span>
                {overview.library_enabled
                  ? "Some records need review before they can sync."
                  : "Include your existing hosts and Groups in library sync."}
              </span>
              <Button
                variant="ghost"
                size="sm"
                onClick={() => setPanel("account")}
              >
                Review setup
                <ArrowUpRight className="size-3.5" />
              </Button>
            </div>
          )}
        <div
          className="library-detail-layout flex min-h-0 flex-1"
          hidden={!!activeTerminal}
          data-inspecting={panel === "hosts" && !!inspected}
        >
          <main
            hidden={panel !== "hosts"}
            className="library-main min-h-0 min-w-0 flex-1"
            aria-label="Hosts workspace"
          >
            <RecordHostList
              overview={overview}
              selectedId={selectedHostId}
              select={(id) => {
                setSelectedHostId(id);
                setInspectedId(null);
              }}
              inspect={(id) => {
                setSelectedHostId(id);
                setInspectedId(id);
              }}
              dismiss={() => {
                setSelectedHostId(null);
                setInspectedId(null);
              }}
              edit={editHost}
              duplicate={duplicateHost}
              selectGroup={(id) => requestSelection({ kind: "group", id })}
              create={createHost}
              createGroup={createGroup}
              disabled={editorBusy}
              organizeDisabled={dirty || editorBusy}
              accept={accept}
              onBusy={setEditorBusy}
              expand={() => setInspectedId(null)}
              connect={(id) => void connect(id)}
              connectingId={connectingId}
              filter={filter}
              changeFilter={changeFilter}
              searchShortcut={platform.data === "macos" ? "⌘ F" : "Ctrl F"}
              importHosts={() => setPanel("import")}
              exportHosts={(previous) => previous ? setTransferOpen(true) : void exportHosts(false)}
            />
          </main>
          {panel === "hosts" && <DetailPresence>{inspected ? (
            <HostPreview
              host={inspected}
              overview={overview}
              connect={() => void connect(inspected.id)}
              edit={() => editHost(inspected.id)}
              close={() => {
                const previousId = inspectedId;
                setInspectedId(null);
                requestAnimationFrame(() => {
                  const target = document.querySelector<HTMLElement>(`[data-host-id="${CSS.escape(previousId ?? "")}"]`);
                  (target ?? document.getElementById(SEARCH_INPUT_ID))?.focus();
                });
              }}
              busy={editorBusy || !!connectingId}
            />
          ) : null}</DetailPresence>}
          {panel !== "hosts" && (
            <main
              key={panel}
              className={cn("library-tools-main app-main min-h-0 min-w-0 flex-1", panel === "keys" ? "flex flex-col overflow-hidden" : "overflow-y-auto")}
              aria-label="Workspace content"
            >
              {panel === "keys" && <RecordsKeysPanel overview={overview} syncStatus={central.data} openSync={() => setPanel("account")} />}
              {panel === "tunnels" && <TunnelsPanel overview={overview} />}
              {panel === "transports" && <GoogleCloudPanel overview={overview} accept={accept} createIapHost={createIapHost} editHost={editHost} />}
              {panel === "account" && (
                <RecordsAccountPanel
                  onOpenImport={() => setPanel("import")}
                  overview={overview}
                  onBusyChange={setAccountBusy}
                />
              )}
              {panel === "import" && <RecordsImportPanel />}
            </main>
          )}
        </div>
        <footer className="library-statusbar" hidden={!!activeTerminal}>
          <button
            type="button"
            className="library-sync-link"
            aria-label="Sync status and settings"
            onClick={() => setPanel("account")}
          >
            <Cloud className="size-3.5" />
            <span role="status">{central.isError ? "Sync status unavailable · Open to retry" : summary.text}</span>
          </button>
          <Button
            variant="ghost"
            size="sm"
            className="library-sync-now"
            disabled={syncActive || !!central.data?.syncing}
            onClick={summary.ready ? sync : () => setPanel("account")}
          >
            {syncActive
              ? "Syncing…"
              : summary.action}
          </Button>
          <DropdownMenu>
            <DropdownMenuTrigger asChild>
              <button
                type="button"
                className="library-terminal-options"
                aria-label="Connection options"
              >
                <Terminal className="size-3.5" />
                <span>{terminalName}</span>
                <ChevronDown className="size-3" />
              </button>
            </DropdownMenuTrigger>
            <DropdownMenuContent align="end" className="w-64">
              <DropdownMenuLabel>Open connections in</DropdownMenuLabel>
              <DropdownMenuRadioGroup
                value={terminalId ?? ""}
                onValueChange={(value) => setTerminalId(value || null)}
              >
                <DropdownMenuRadioItem value={IN_APP_TERMINAL}>Lunport (in app)</DropdownMenuRadioItem>
                <DropdownMenuRadioItem value="">
                  System default terminal
                </DropdownMenuRadioItem>
                {terminals.data?.map((terminal) => (
                  <DropdownMenuRadioItem
                    key={terminal.id}
                    value={terminal.id}
                  >
                    {terminal.label}
                  </DropdownMenuRadioItem>
                ))}
              </DropdownMenuRadioGroup>
              <DropdownMenuSeparator />
              <DropdownMenuCheckboxItem
                checked={terminalId === IN_APP_TERMINAL || preferNewTab}
                disabled={
                  !terminalSupportsNewTab(terminalId, terminals.data ?? [])
                }
                onCheckedChange={setNewTab}
              >
                Open in a new tab
              </DropdownMenuCheckboxItem>
            </DropdownMenuContent>
          </DropdownMenu>
        </footer>
        </TerminalWorkspace>
      </div>
      <Dialog
        open={selection.kind !== "none"}
        onOpenChange={(open) => {
          if (!open) requestSelection({ kind: "none" });
        }}
      >
        <DialogContent
          ref={editorRef}
          showCloseButton={false}
          className={cn(
            "library-editor-dialog",
            isGroupEditor ? "library-group-dialog sm:max-w-xl" : "library-host-dialog sm:max-w-2xl",
            editorKind === "host" && "library-editor-drawer",
          )}
          onOpenAutoFocus={(event) => {
            const name =
              editorRef.current?.querySelector<HTMLInputElement>(
                isGroupEditor ? "[data-group-name]" : "[data-host-alias]",
              );
            if (name && !name.matches(":disabled")) {
              event.preventDefault();
              name.focus();
            }
          }}
          onCloseAutoFocus={(event) => {
            event.preventDefault();
            const origin = editorOrigin.current;
            const detailClose = document.querySelector<HTMLElement>('.library-host-preview[data-state="open"] button[aria-label="Close details"]');
            (detailClose ?? (origin?.isConnected ? origin : document.getElementById(SEARCH_INPUT_ID)))?.focus();
          }}
        >
          {!isGroupEditor && (
            <>
              <DialogTitle className="sr-only">
                {selection.kind === "new" ? selection.duplicateSource ? "Duplicate host" : "New host" : "Edit host"}
              </DialogTitle>
              <DialogDescription className="sr-only">
                Update connection settings, then save your changes.
              </DialogDescription>
            </>
          )}
          <div
            className={
              isGroupEditor
                ? "library-group-editor-container"
                : "library-host-editor-container"
            }
          >
            {selection.kind === "group" || selection.kind === "new_group" ? (
              <RecordGroupEditor
                key={
                  selection.kind === "group"
                    ? "group:" + selection.id
                    : "new-group:" + selection.nonce
                }
                group={selectedGroup}
                groupId={selectedGroupId}
                initialScope={
                  selection.kind === "new_group" ? selection.scope : undefined
                }
                initialParentId={
                  selection.kind === "new_group"
                    ? selection.parentId
                    : undefined
                }
                overview={overview}
                accept={accept}
                onSaved={onGroupSaved}
                onDeleted={onDeleted}
                onDirty={onDirty}
                onBusy={setEditorBusy}
                onCancel={() => requestSelection({ kind: "none" })}
              />
            ) : (
              selection.kind !== "none" && (
                <RecordHostEditor
              connectHost={async (id) => { await connectSavedHost(overview, id, terminalId, newTab); setSelection({ kind: "none" }); }}
                  key={
                    selection.kind === "host"
                      ? selection.id
                      : "new:" + selection.nonce
                  }
                  initialScope={
                    selection.kind === "new" ? selection.scope : undefined
                  }
                  initialGroupId={
                    selection.kind === "new" ? selection.groupId : undefined
                  }
                  initialVia={selection.kind === "new" ? selection.via : undefined}
                  duplicateSource={selection.kind === "new" ? selection.duplicateSource : undefined}
                  onDuplicate={selectedId ? () => duplicateHost(selectedId) : undefined}
                  host={selected}
                  hostId={selectedId}
                  overview={overview}
                  terminalId={terminalId}
                  newTab={newTab}
                  accept={accept}
                  onSaved={onSaved}
                  onDeleted={onDeleted}
                  onDirty={onDirty}
                  onBusy={setEditorBusy}
                  onCancel={() => requestSelection({ kind: "none" })}
                />
              )
            )}
          </div>
        </DialogContent>
      </Dialog>
      <Dialog
        open={pendingSelection !== null}
        onOpenChange={(open) => {
          if (!open) setPendingSelection(null);
        }}
      >
        <DialogContent onCloseAutoFocus={(event) => {
          event.preventDefault();
          const name = editorRef.current?.querySelector<HTMLElement>("[data-group-name], [data-host-alias]");
          const origin = editorOrigin.current;
          (name ?? (origin?.isConnected ? origin : document.getElementById(SEARCH_INPUT_ID)))?.focus();
        }}>
          <DialogTitle>Unsaved changes</DialogTitle>
          <DialogDescription>
            Discard your unsaved changes before leaving this editor?
          </DialogDescription>
          <DialogFooter>
            <Button
              variant="outline"
              autoFocus
              onClick={() => setPendingSelection(null)}
            >
              Keep editing
            </Button>
            <Button
              variant="destructive"
              disabled={editorBusy}
              onClick={() => {
                if (!pendingSelection || editorBusy) return;
                setSelection(pendingSelection);
                setPendingSelection(null);
                setDirty(false);
              }}
            >
              Discard changes
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
      <RecordsCommandPalette
        overview={overview}
        terminalId={terminalId}
        newTab={newTab}
        editorBusy={editorBusy}
        edit={editHost}
        create={createHost}
      />
      <WorkspaceTransfer open={transferOpen} onOpenChange={setTransferOpen} onImport={() => { setTransferOpen(false); setPanel("import"); }} />
      <SettingsDialog
        recordOverview={overview}
        onOpenDataTools={() => { setSettingsOpen(false); setTransferOpen(true); }}
        onOpenImport={() => {
          setSettingsOpen(false);
          setActiveTerminal(null);
          setPanel("import");
        }}
        onOpenSync={() => {
          setSettingsOpen(false);
          setActiveTerminal(null);
          setPanel("account");
        }}
      />
    </div>
  );
}
