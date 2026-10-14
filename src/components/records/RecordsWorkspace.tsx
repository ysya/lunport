import { useCallback, useEffect, useRef, useState } from "react";
import { useQueryClient } from "@tanstack/react-query";
import { Bot, RotateCw, Settings, Terminal, SunMoon } from "lucide-react";
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
  type RecordsStatus,
} from "@/lib/records";
import { usePlatform, useTerminals } from "@/lib/queries";
import { effectiveNewTab, terminalSupportsNewTab } from "@/lib/settings-logic";
import { useSettingsStore } from "@/stores/settings";
import { cn } from "@/lib/utils";
import { RecordHostList } from "./HostList";
import { RecordHostEditor } from "./HostEditor";
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
  const [dirty, setDirty] = useState(false);
  const [editorBusy, setEditorBusy] = useState(false);
  const [syncing, setSyncing] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const nonce = useRef(0);
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
    const decision = decideHostSelection(selection, next, dirty, editorBusy);
    if (decision === "confirm") setPendingSelection(next);
    if (decision === "select") {
      setSelection(next);
      setDirty(false);
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
        requestSelection({ kind: "new", nonce: ++nonce.current });
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
            onClick={overview.account ? sync : () => setPanel("account")}
          >
            {syncing
              ? "Starting sync…"
              : overview.account
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
                aria-label="Unsaved host changes"
                className="size-1.5 rounded-full bg-primary"
              />
            )}
          </Button>
        ))}
      </nav>
      <Dialog
        open={pendingSelection !== null}
        onOpenChange={(open) => {
          if (!open) setPendingSelection(null);
        }}
      >
        <DialogContent>
          <DialogTitle>Unsaved host changes</DialogTitle>
          <DialogDescription>
            Discard the unsaved host changes before opening another host?
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
      <div className="flex min-h-0 flex-1">
        <aside
          hidden={panel !== "hosts"}
          className="app-sidebar min-h-0 w-60 shrink-0 border-r"
        >
          <RecordHostList
            overview={overview}
            selectedId={selectedId}
            select={(id) => requestSelection({ kind: "host", id })}
            create={() =>
              requestSelection({ kind: "new", nonce: ++nonce.current })
            }
            disabled={editorBusy}
          />
        </aside>
        <main className="app-main min-h-0 min-w-0 flex-1 overflow-hidden">
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
                  Select a host, add a new one, or import an SSH configuration.
                </p>
              </div>
            ) : (
              <RecordHostEditor
                key={
                  selection.kind === "host"
                    ? selection.id
                    : `new:${selection.nonce}`
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
          {panel !== "hosts" && (
            <div key={panel} className="h-full overflow-y-auto">
              {panel === "keys" && <RecordsKeysPanel overview={overview} />}
              {panel === "account" && (
                <RecordsAccountPanel overview={overview} />
              )}
              {panel === "import" && <RecordsImportPanel />}
            </div>
          )}
        </main>
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
            connected={!!overview.account}
            pending={!!overview.pending_account}
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
        create={() => requestSelection({ kind: "new", nonce: ++nonce.current })}
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
