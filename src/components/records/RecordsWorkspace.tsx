import { useCallback, useEffect, useRef, useState } from "react";
import { useQueryClient } from "@tanstack/react-query";
import {
  Bot,
  RotateCw,
  Settings,
  Terminal,
  SunMoon,
  Plus,
  FolderPlus,
  PanelLeftClose,
  PanelLeftOpen,
} from "lucide-react";
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
import { SidebarResizeHandle } from "@/components/SidebarResizeHandle";
import { clampSidebarWidth } from "@/lib/sidebar-width";
import { RecordHostList } from "./HostList";
import { RecordHostEditor } from "./HostEditor";
import { RecordGroupEditor } from "./GroupEditor";
import { selectGroup } from "./group-tree";
import { selectHost } from "./editor";
import { RecordsKeysPanel } from "./KeysPanel";
import { RecordsAccountPanel } from "./AccountPanel";
import { RecordsImportPanel } from "./ImportPanel";
import { selectClass } from "./form";
import { RecordSyncStatus } from "./SyncStatus";
import { decideHostSelection, type HostSelection } from "./selection";
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
  const openSettings = (category: "general" | "ai") => {
    setSettingsCategory(category);
    setSettingsOpen(true);
  };
  const client = useQueryClient();
  const [panel, setPanel] = useState<"hosts" | "keys" | "account" | "import">(
    "hosts",
  );
  const [selection, setSelection] = useState<HostSelection>({ kind: "none" });
  const [pendingSelection, setPendingSelection] =
    useState<HostSelection | null>(null);
  const creationScope: HostScope = overview.library_scope ?? { kind: "local" };
  const [dirty, setDirty] = useState(false);
  const [editorBusy, setEditorBusy] = useState(false);
  const [syncing, setSyncing] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const nonce = useRef(0);
  const collectionRef = useRef<HTMLElement>(null);
  const collectionWidth = clampSidebarWidth(
    useUiStore((state) => state.sidebarWidth),
  );
  const [listExpanded, setListExpanded] = useState(false);
  const showDetail = selection.kind !== "none" && !listExpanded;
  const syncInFlight = useRef(false);
  const platform = usePlatform();
  const terminals = useTerminals();
  const terminalId = useSettingsStore((state) => state.terminalId);
  const setTerminalId = useSettingsStore((state) => state.setTerminalId);
  const preferNewTab = useSettingsStore((state) => state.newTabConnect);
  const setNewTab = useSettingsStore((state) => state.setNewTabConnect);
  const toggleTheme = useSettingsStore((state) => state.toggleTheme);
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
    setPanel("hosts");
    setListExpanded(false);
    const decision = decideHostSelection(selection, next, dirty, editorBusy);
    if (decision === "confirm") setPendingSelection(next);
    if (decision === "select") {
      setSelection(next);
      setDirty(false);
    }
  };
  const groupContext =
    selection.kind === "group"
      ? selectGroup(overview.groups, selection.id)
      : selection.kind === "host"
        ? (() => {
            const host = selectHost(overview.hosts, selection.id);
            return host?.payload.group_id
              ? selectGroup(overview.groups, host.payload.group_id)
              : null;
          })()
        : null;
  const createHost = () =>
    requestSelection({
      kind: "new",
      nonce: ++nonce.current,
      groupId: groupContext?.id,
      scope: groupContext?.scope ?? creationScope,
    });
  const createGroup = () =>
    requestSelection({
      kind: "new_group",
      nonce: ++nonce.current,
      parentId: groupContext?.id,
      scope: groupContext?.scope ?? creationScope,
    });
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
    setSelection(id ? { kind: "host", id } : { kind: "none" });
    setDirty(false);
  }, []);
  const onGroupSaved = useCallback((id: string | null) => {
    setSelection(id ? { kind: "group", id } : { kind: "none" });
    setDirty(false);
  }, []);
  const onDeleted = useCallback(() => {
    setSelection({ kind: "none" });
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
  return (
    <div className="app-shell flex h-screen flex-col overflow-hidden">
      <header
        data-tauri-drag-region
        className={cn(
          "app-toolbar flex h-11 shrink-0 items-center gap-2 border-b pr-3",
          platform.data === "macos" ? "pl-[78px]" : "pl-3",
        )}
      >
        <div className="pointer-events-none flex items-center gap-2">
          <Terminal className="size-4 text-muted-foreground" />
          <span className="text-sm font-semibold">SSHelter</span>
          <span className="text-xs text-muted-foreground">
            {overview.hosts.length} hosts
          </span>
        </div>
        <div className="ml-auto flex items-center gap-1">
          <Button
            variant="ghost"
            size="icon"
            aria-label="AI access (MCP)"
            onClick={() => openSettings("ai")}
          >
            <Bot className="size-4" />
          </Button>
          <Button
            variant="ghost"
            size="icon"
            aria-label="Settings"
            onClick={() => openSettings("general")}
          >
            <Settings className="size-4" />
          </Button>
          <Button
            variant="ghost"
            size="icon"
            aria-label="Refresh workspace"
            onClick={reload}
          >
            <RotateCw className="size-4" />
          </Button>
          <Button
            variant="ghost"
            size="icon"
            aria-label="Toggle theme"
            onClick={toggleTheme}
          >
            <SunMoon className="size-4" />
          </Button>
          <Button
            variant="outline"
            size="sm"
            disabled={syncing}
            onClick={
              overview.library_enabled ? sync : () => setPanel("account")
            }
          >
            {syncing
              ? "Starting sync…"
              : overview.library_enabled
                ? "Sync now"
                : "Set up sync"}
          </Button>
        </div>
      </header>
      <nav
        aria-label="Workspace sections"
        className="app-toolbar flex shrink-0 flex-wrap items-center gap-1 border-b px-3 py-2"
      >
        {(["hosts", "keys", "account", "import"] as const).map((value) => (
          <Button
            key={value}
            size="sm"
            variant={panel === value ? "secondary" : "ghost"}
            aria-pressed={panel === value}
            onClick={() => setPanel(value)}
          >
            {value === "account"
              ? "Sync"
              : value[0].toUpperCase() + value.slice(1)}
            {value === "hosts" && dirty && (
              <span
                aria-label="Unsaved record changes"
                className="size-1.5 rounded-full bg-primary"
              />
            )}
          </Button>
        ))}
        {panel === "hosts" && (
          <div className="ml-auto flex flex-wrap items-center gap-2">
            {selection.kind !== "none" && (
              <Button
                size="sm"
                variant="ghost"
                aria-expanded={showDetail}
                aria-controls="record-details"
                onClick={() => setListExpanded(!listExpanded)}
              >
                {showDetail ? (
                  <PanelLeftClose className="size-4" />
                ) : (
                  <PanelLeftOpen className="size-4" />
                )}
                {showDetail ? "Expand list" : "Show details"}
              </Button>
            )}
            <Button
              size="sm"
              variant="outline"
              disabled={editorBusy}
              onClick={createGroup}
            >
              <FolderPlus className="size-4" /> New group
            </Button>
            <Button size="sm" disabled={editorBusy} onClick={createHost}>
              <Plus className="size-4" /> New host
            </Button>
          </div>
        )}
      </nav>
      <Dialog
        open={pendingSelection !== null}
        onOpenChange={(open) => {
          if (!open) setPendingSelection(null);
        }}
      >
        <DialogContent>
          <DialogTitle>Unsaved changes</DialogTitle>
          <DialogDescription>
            Discard the unsaved changes before opening another host or Group?
          </DialogDescription>
          <DialogFooter>
            <Button
              size="sm"
              variant="outline"
              autoFocus
              onClick={() => setPendingSelection(null)}
            >
              Keep editing
            </Button>
            <Button
              size="sm"
              variant="destructive"
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
      {overview.shared_writes_blocked && (
        <p
          role="status"
          className="shrink-0 border-b p-3 text-xs text-destructive"
        >
          Shared changes are paused. Review account status before syncing
          changes.
        </p>
      )}
      {overview.account &&
        (!overview.library_enabled ||
          [...overview.hosts, ...overview.groups].some(
            (row) => row.scope.kind === "local",
          )) && (
          <div
            role="status"
            className="flex shrink-0 items-center justify-between gap-3 border-b bg-muted/40 px-4 py-2 text-sm"
          >
            <span>
              {overview.library_enabled
                ? "Some records need review before they can sync."
                : "Finish library sync setup to include all existing hosts and Groups."}
            </span>
            <Button
              size="sm"
              variant="outline"
              onClick={() => setPanel("account")}
            >
              Review sync setup
            </Button>
          </div>
        )}
      <div className="flex min-h-0 flex-1">
        <section
          hidden={panel !== "hosts"}
          className="records-host-workspace flex min-h-0 min-w-0 flex-1"
          data-detail={showDetail}
          aria-label="Hosts workspace"
        >
          <section
            ref={collectionRef}
            className="records-collection flex min-h-0 min-w-0 shrink-0 flex-col overflow-hidden"
            aria-label="Host collection"
            style={
              showDetail
                ? { width: `${collectionWidth}rem`, maxWidth: "45%" }
                : { width: "100%" }
            }
          >
            <RecordHostList
              overview={overview}
              selectedId={selectedId}
              selectedGroupId={selectedGroupId}
              selectGroup={(id) => requestSelection({ kind: "group", id })}
              select={(id) => requestSelection({ kind: "host", id })}
              disabled={editorBusy}
              organizeDisabled={dirty || editorBusy}
              accept={accept}
              onBusy={setEditorBusy}
              expand={() => setListExpanded(true)}
            />
          </section>
          {showDetail && <SidebarResizeHandle sidebarRef={collectionRef} />}
          <main
            id="record-details"
            hidden={!showDetail}
            className="app-main min-h-0 min-w-0 flex-1 overflow-hidden border-l"
            aria-label="Record details"
          >
            <section
              hidden={panel !== "hosts"}
              className="h-full overflow-y-auto"
            >
              {selection.kind === "none" ? (
                <div className="flex min-h-80 flex-col items-center justify-center gap-3 p-6 text-center">
                  <h1 className="font-medium">
                    {overview.hosts.length
                      ? "Select a host to connect"
                      : "Add your first host"}
                  </h1>
                  <p className="text-sm text-muted-foreground">
                    Select a host, add a new one, or import an SSH
                    configuration.
                  </p>
                </div>
              ) : selection.kind === "group" ||
                selection.kind === "new_group" ? (
                <RecordGroupEditor
                  key={
                    selection.kind === "group"
                      ? `group:${selection.id}`
                      : `new-group:${selection.nonce}`
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
                  onCancel={onDeleted}
                />
              ) : (
                <RecordHostEditor
                  key={
                    selection.kind === "host"
                      ? selection.id
                      : `new:${selection.nonce}`
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
                  newTab={effectiveNewTab(
                    preferNewTab,
                    terminalId,
                    terminals.data ?? [],
                  )}
                  accept={accept}
                  onSaved={onSaved}
                  onDeleted={onDeleted}
                  onDirty={onDirty}
                  onBusy={setEditorBusy}
                  onCancel={onDeleted}
                />
              )}
            </section>
          </main>
        </section>
        {panel !== "hosts" && (
          <main
            key={panel}
            className="app-main min-h-0 min-w-0 flex-1 overflow-y-auto"
            aria-label="Workspace content"
          >
            {panel === "keys" && <RecordsKeysPanel overview={overview} />}
            {panel === "account" && <RecordsAccountPanel overview={overview} />}
            {panel === "import" && <RecordsImportPanel />}
          </main>
        )}
      </div>
      <footer className="app-toolbar flex shrink-0 flex-wrap items-center gap-3 border-t px-3 py-2">
        <select
          aria-label="Terminal"
          className={cn(selectClass, "h-7 w-auto max-w-44 text-xs")}
          value={terminalId ?? ""}
          onChange={(event) => setTerminalId(event.target.value || null)}
        >
          <option value="">System default terminal</option>
          {terminals.data?.map((terminal) => (
            <option key={terminal.id} value={terminal.id}>
              {terminal.label}
            </option>
          ))}
        </select>
        <label className="flex items-center gap-1.5 text-xs">
          <input
            type="checkbox"
            checked={preferNewTab}
            disabled={!terminalSupportsNewTab(terminalId, terminals.data ?? [])}
            onChange={(event) => setNewTab(event.target.checked)}
          />
          New tab
        </label>
        <div className="ml-auto max-w-md text-right">
          <RecordSyncStatus
            connected={!!overview.account && overview.library_enabled}
            pending={!!overview.pending_account}
            pendingChanges={overview.pending_changes}
            lastSyncMs={overview.last_sync_ms}
            error={error ?? overview.last_error}
          />
        </div>
      </footer>
      <RecordsCommandPalette
        overview={overview}
        terminalId={terminalId}
        newTab={effectiveNewTab(preferNewTab, terminalId, terminals.data ?? [])}
        editorBusy={editorBusy}
        edit={(id) => requestSelection({ kind: "host", id })}
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
