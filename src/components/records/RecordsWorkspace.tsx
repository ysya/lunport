import "./library.css";
import { UpdateIndicator } from "@/components/UpdatesPane";
import { useCallback, useEffect, useRef, useState } from "react";
import { useQueryClient } from "@tanstack/react-query";
import {
  ArrowUpRight,
  Bot,
  ChevronDown,
  Cloud,
  MoreHorizontal,
  RotateCw,
  Search,
  Settings,
  SunMoon,
  Terminal,
} from "lucide-react";
import { toast } from "sonner";
import { SettingsDialog } from "@/components/SettingsDialog";
import { useUiStore } from "@/stores/ui";
import { useSyncBackendSettings } from "@/lib/backend-settings";
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
  recordsStatusKey,
  syncRecordsNow,
  type RecordOverview,
  type HostScope,
  type RecordsStatus,
} from "@/lib/records";
import { usePlatform, useTerminals } from "@/lib/queries";
import { effectiveNewTab, terminalSupportsNewTab } from "@/lib/settings-logic";
import { useSettingsStore } from "@/stores/settings";
import { cn } from "@/lib/utils";
import { revealHidden } from "@/lib/sync-approvals";
import { RecordHostList } from "./HostList";
import { RecordHostEditor } from "./HostEditor";
import { RecordGroupEditor } from "./GroupEditor";
import { selectGroup } from "./group-tree";
import { selectHost } from "./editor";
import { RecordsKeysPanel } from "./KeysPanel";
import { RecordsAccountPanel } from "./AccountPanel";
import { RecordsImportPanel } from "./ImportPanel";
import { RecordSyncStatus } from "./SyncStatus";
import { decideHostSelection, type HostSelection } from "./selection";
import { LibraryNavigation, type WorkspacePanel } from "./LibraryNavigation";
import type { LibraryFilter } from "./library-view";
import { HostPreview } from "./HostPreview";
import { connectSavedHost } from "./operations";

export function RecordsWorkspace({
  overview,
  reload,
}: {
  overview: RecordOverview;
  reload: () => void;
}) {
  useSyncBackendSettings();
  useGlobalHotkey();
  const setSettingsOpen = useUiStore((state) => state.setSettingsOpen);
  const setSettingsCategory = useUiStore((state) => state.setSettingsCategory);
  const setPaletteOpen = useUiStore((state) => state.setPaletteOpen);
  const openSettings = (category: "general" | "ai") => {
    setSettingsCategory(category);
    setSettingsOpen(true);
  };
  const client = useQueryClient();
  const [panel, setPanel] = useState<WorkspacePanel>("hosts");
  const [filter, setFilter] = useState<LibraryFilter>({ kind: "all" });
  const [inspectedId, setInspectedId] = useState<string | null>(null);
  const [selection, setSelection] = useState<HostSelection>({ kind: "none" });
  const [pendingSelection, setPendingSelection] =
    useState<HostSelection | null>(null);
  const [dirty, setDirty] = useState(false);
  const [editorBusy, setEditorBusy] = useState(false);
  const editorRef = useRef<HTMLDivElement>(null);
  const isGroupEditor =
    selection.kind === "group" || selection.kind === "new_group";
  const [syncing, setSyncing] = useState(false);
  const [accountBusy, setAccountBusy] = useState(false);
  const syncActive = syncing || accountBusy || !!overview.syncing;
  const [error, setError] = useState<string | null>(null);
  const [connectingId, setConnectingId] = useState<string | null>(null);
  const connectInFlight = useRef(false);
  const syncInFlight = useRef(false);
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
      setSelection(next);
      setDirty(false);
    }
  };
  const changeFilter = (next: LibraryFilter) => {
    setFilter(next);
    setInspectedId(null);
  };
  const groupContext =
    panel === "hosts" && filter.kind === "group"
      ? selectGroup(overview.groups, filter.id)
      : null;
  const creationScope: HostScope = groupContext?.scope ??
    overview.library_scope ?? { kind: "local" };
  const createHost = () =>
    requestSelection({
      kind: "new",
      nonce: ++nonce.current,
      groupId: groupContext?.id,
      scope: creationScope,
    });
  const createGroup = () =>
    requestSelection({
      kind: "new_group",
      nonce: ++nonce.current,
      parentId: groupContext?.id,
      scope: creationScope,
    });
  const editHost = (id: string) => {
    setPanel("hosts");
    requestSelection({ kind: "host", id });
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
      if (!(event.metaKey || event.ctrlKey) || event.altKey || event.shiftKey)
        return;
      if (
        isTypingContext(event.target) &&
        (event.target as HTMLElement).id !== SEARCH_INPUT_ID
      )
        return;
      if (event.key.toLowerCase() === "n") {
        event.preventDefault();
        createHost();
      } else if (event.key.toLowerCase() === "f") {
        event.preventDefault();
        setPanel("hosts");
        window.requestAnimationFrame(() => {
          const input = document.getElementById(SEARCH_INPUT_ID);
          if (input instanceof HTMLInputElement) {
            input.focus();
            input.select();
          }
        });
      }
    };
    window.addEventListener("keydown", keydown);
    return () => window.removeEventListener("keydown", keydown);
  }, [requestSelection]);
  const onSaved = useCallback((id: string | null) => {
    setPanel("hosts");
    setSelection({ kind: "none" });
    setInspectedId(id);
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
    setDirty(false);
  }, []);
  const sync = async () => {
    if (syncInFlight.current) return;
    syncInFlight.current = true;
    setSyncing(true);
    setError(null);
    try {
      await syncRecordsNow();
      reload();
    } catch {
      setError("Sync could not be started. Refresh and retry.");
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
  const terminalName =
    terminals.data?.find((terminal) => terminal.id === terminalId)?.label ??
    "System default terminal";
  const shortcut = platform.data === "macos" ? "⌘ K" : "Ctrl K";
  return (
    <div className="app-shell library-shell flex h-screen flex-col overflow-hidden">
      <header
        data-tauri-drag-region
        className={cn(
          "library-titlebar",
          platform.data === "macos" && "is-macos",
        )}
      >
        <span className="library-app-name">
          <Terminal className="size-4" />
          SSHelter
        </span>
        <button
          type="button"
          className="library-quick-connect"
          onClick={() => setPaletteOpen(true)}
        >
          <Search className="size-3.5" />
          <span>Quick connect</span>
          <kbd>{shortcut}</kbd>
        </button>
        <UpdateIndicator />
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
            <DropdownMenuItem onSelect={() => openSettings("general")}>
              <Settings />
              Settings
            </DropdownMenuItem>
          </DropdownMenuContent>
        </DropdownMenu>
      </header>
      <div className="flex min-h-0 flex-1">
        <LibraryNavigation
          overview={overview}
          panel={panel}
          filter={filter}
          navigate={setPanel}
          changeFilter={changeFilter}
          createGroup={createGroup}
          settings={() => openSettings("general")}
        />
        <div className="flex min-h-0 min-w-0 flex-1 flex-col">
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
            overview.account &&
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
            className="flex min-h-0 flex-1"
            data-inspecting={panel === "hosts" && !!inspected}
          >
            <main
              hidden={panel !== "hosts"}
              className="library-main min-h-0 min-w-0 flex-1"
              aria-label="Hosts workspace"
            >
              <RecordHostList
                overview={overview}
                selectedId={inspectedId}
                select={setInspectedId}
                edit={editHost}
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
              />
            </main>
            {panel === "hosts" && inspected && (
              <HostPreview
                host={inspected}
                overview={overview}
                connect={() => void connect(inspected.id)}
                edit={() => editHost(inspected.id)}
                close={() => setInspectedId(null)}
                busy={editorBusy || !!connectingId}
              />
            )}
            {panel !== "hosts" && (
              <main
                key={panel}
                className="library-tools-main app-main min-h-0 min-w-0 flex-1 overflow-y-auto"
                aria-label="Workspace content"
              >
                {panel === "keys" && <RecordsKeysPanel overview={overview} />}
                {panel === "account" && (
                  <RecordsAccountPanel
                    overview={overview}
                    onBusyChange={setAccountBusy}
                  />
                )}
                {panel === "import" && <RecordsImportPanel />}
              </main>
            )}
          </div>
          <footer className="library-statusbar">
            <button
              type="button"
              className="library-sync-link"
              aria-label="Sync status and settings"
              onClick={() => setPanel("account")}
            >
              <Cloud className="size-3.5" />
              <RecordSyncStatus
                connected={!!overview.account && overview.library_enabled}
                pending={!!overview.pending_account}
                pendingChanges={overview.pending_changes}
                lastSyncMs={overview.last_sync_ms}
                error={error ?? overview.last_error}
                syncing={syncActive}
              />
            </button>
            <Button
              variant="ghost"
              size="sm"
              className="library-sync-now"
              disabled={syncActive}
              onClick={
                overview.library_enabled ? sync : () => setPanel("account")
              }
            >
              {syncActive
                ? "Syncing…"
                : overview.library_enabled
                  ? "Sync now"
                  : "Set up sync"}
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
                  checked={preferNewTab}
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
        </div>
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
        >
          {!isGroupEditor && (
            <>
              <DialogTitle className="sr-only">
                {selection.kind === "new" ? "New host" : "Edit host"}
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
        <DialogContent>
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
      <SettingsDialog
        recordOverview={overview}
        onOpenImport={() => {
          setSettingsOpen(false);
          setPanel("import");
        }}
        onOpenSync={() => {
          setSettingsOpen(false);
          setPanel("account");
        }}
      />
    </div>
  );
}
