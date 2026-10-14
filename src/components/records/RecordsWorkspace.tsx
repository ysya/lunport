import { useCallback, useRef, useState } from "react";
import { useQueryClient } from "@tanstack/react-query";
import { Plus, RotateCw, Terminal, SunMoon } from "lucide-react";
import { Button } from "@/components/ui/button";
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
import { revealHidden } from "@/lib/sync-approvals";
import { cn } from "@/lib/utils";
import { RecordHostList } from "./HostList";
import { RecordHostEditor } from "./HostEditor";
import { selectHost } from "./editor";
import { RecordsKeysPanel } from "./KeysPanel";
import { RecordsAccountPanel } from "./AccountPanel";
import { RecordsImportPanel } from "./ImportPanel";
import { selectClass } from "./form";
type Selection =
  | { kind: "none" }
  | { kind: "new"; nonce: number }
  | { kind: "host"; id: string };
export function RecordsWorkspace({
  overview,
  reload,
}: {
  overview: RecordOverview;
  reload: () => void;
}) {
  const client = useQueryClient();
  const [panel, setPanel] = useState<"hosts" | "keys" | "account" | "import">(
    "hosts",
  );
  const [selection, setSelection] = useState<Selection>({ kind: "none" });
  const [pendingSelection, setPendingSelection] = useState<Selection | null>(
    null,
  );
  const [dirty, setDirty] = useState(false);
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
  const requestSelection = (next: Selection) => {
    setPanel("hosts");
    if (
      next.kind === "host" &&
      selection.kind === "host" &&
      next.id === selection.id
    )
      return;
    if (dirty) setPendingSelection(next);
    else {
      setSelection(next);
      setDirty(false);
    }
  };
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
            disabled={syncing || !overview.account}
            onClick={sync}
          >
            {syncing ? "Starting sync…" : "Sync now"}
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
              ? "Sync account"
              : value[0].toUpperCase() + value.slice(1)}
          </Button>
        ))}
        <Button
          className="ml-auto"
          size="sm"
          onClick={() =>
            requestSelection({ kind: "new", nonce: ++nonce.current })
          }
        >
          <Plus className="size-4" />
          New host
        </Button>
      </nav>
      {pendingSelection && (
        <div
          role="alertdialog"
          aria-label="Unsaved host changes"
          className="flex shrink-0 flex-wrap items-center gap-3 border-b bg-muted p-3"
        >
          <p className="text-sm">Discard the unsaved host changes?</p>
          <Button
            size="sm"
            variant="destructive"
            onClick={() => {
              setSelection(pendingSelection);
              setPendingSelection(null);
              setDirty(false);
            }}
          >
            Discard changes
          </Button>
          <Button
            size="sm"
            variant="outline"
            onClick={() => setPendingSelection(null)}
          >
            Keep editing
          </Button>
        </div>
      )}
      {(error || overview.last_error) && (
        <p
          role="status"
          className="shrink-0 border-b p-3 text-xs text-destructive whitespace-pre-wrap"
        >
          {revealHidden(error ?? overview.last_error ?? "")}
        </p>
      )}
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
        <aside className="app-sidebar w-64 shrink-0 overflow-y-auto border-r">
          <RecordHostList
            overview={overview}
            selectedId={selectedId}
            select={(id) => requestSelection({ kind: "host", id })}
          />
        </aside>
        <main className="app-main min-w-0 flex-1 overflow-y-auto">
          <section hidden={panel !== "hosts"}>
            {selection.kind === "none" ? (
              <div className="flex min-h-80 flex-col items-center justify-center gap-3 p-6 text-center">
                <h1 className="font-medium">No host selected</h1>
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
              />
            )}
          </section>
          {panel === "keys" && <RecordsKeysPanel overview={overview} />}
          {panel === "account" && <RecordsAccountPanel overview={overview} />}
          {panel === "import" && <RecordsImportPanel />}
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
        <p className="ml-auto text-xs text-muted-foreground">
          AI access and key deployment are unavailable in this workspace.
        </p>
      </footer>
    </div>
  );
}
