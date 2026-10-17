import { Dialog, DialogTitle } from "@/components/ui/dialog";
import { TaskDialogContent } from "@/components/app/TaskDialog";
import { useRef, useState } from "react";
import { useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import { Bot, KeyRound, RotateCw, Settings, ServerCog } from "lucide-react";
import { BrandMark } from "@/components/app/BrandMark";

import { useRecordsStatus, recordsStatusKey, useLegacyWorkspace } from "@/lib/records";
import { WorkspaceGate } from "@/components/records/WorkspaceGate";
import { RecordsWorkspace } from "@/components/records/RecordsWorkspace";
import { RecordsMigrationPanel } from "@/components/records/MigrationPanel";
import { LegacyMigrationLanding } from "@/components/records/LegacyMigrationLanding";
import { LegacyPauseReview } from "@/components/records/LegacyPauseReview";
import { pauseLegacyForMigration } from "@/components/records/migration-actions";

import { useHostsQuery, usePlatform, useLoadConfig } from "@/lib/queries";
import { useUiStore } from "@/stores/ui";
import { useApplyTheme } from "@/lib/theme";
import { useSyncBackendSettings } from "@/lib/backend-settings";
import { useGlobalHotkey } from "@/lib/global-hotkey";
import { useAppShortcuts } from "@/lib/app-shortcuts";
import { useSyncEvents } from "@/lib/sync-events";
import { useAmbiguousNames } from "@/lib/sync-labels";
import { clampSidebarWidth } from "@/lib/sidebar-width";
import { HostList } from "@/components/HostList";
import { HostEditor } from "@/components/HostEditor";
import { DuplicateCopies } from "@/components/DuplicateCopies";
import { AddHostDialog } from "@/components/AddHostDialog";
import { LintDialog } from "@/components/LintDialog";
import { DiscoverDialog } from "@/components/DiscoverDialog";
import { BackupHistoryDialog } from "@/components/BackupHistoryDialog";
import { KeyDetailPane } from "@/components/keychain/KeyDetail";
import { MainPaneContent } from "@/components/MainPane";
import { KeychainList } from "@/components/keychain/KeychainList";
import { SidebarSwitch } from "@/components/keychain/SidebarSwitch";
import { KnownHostsDialog } from "@/components/KnownHostsDialog";
import { DeployKeyDialog } from "@/components/DeployKeyDialog";
import { NewConfigFileDialog } from "@/components/NewConfigFileDialog";
import { SyncMigrationDialog } from "@/components/SyncMigrationDialog";
import { SyncUpgradeDialog } from "@/components/SyncUpgradeDialog";
import { SyncApprovalDialog } from "@/components/SyncApprovalDialog";
import { SyncKeyDialog } from "@/components/SyncKeyDialog";
import { KeysNeededDialog } from "@/components/KeysNeededDialog";
import { UpdateIndicator } from "@/components/UpdatesPane";
import { SettingsDialog } from "@/components/SettingsDialog";
import { CommandPalette } from "@/components/CommandPalette";
import { DriftBanner } from "@/components/DriftBanner";
import { McpApprovalDialog } from "@/components/McpApprovalDialog";
import { SidebarResizeHandle } from "@/components/SidebarResizeHandle";
import { Toaster } from "@/components/ui/sonner";
import { Button } from "@/components/ui/button";
import { cn } from "@/lib/utils";
import { isWildcardOnly } from "@/lib/host-display";
import { useMcpStatus } from "@/lib/mcp";
import {
  Tooltip,
  TooltipContent,
  TooltipProvider,
  TooltipTrigger,
} from "@/components/ui/tooltip";

/**
 * App shell: master-detail layout. The sidebar shows the host list or the
 * Keychain (key vault spec §7.1); the main pane shows the selected host's
 * editor or the selected key's detail.
 *
 * Config is loaded on mount via `useHostsQuery` (a single `config_load` that
 * yields files + hosts). Errors are surfaced as a toast.
 */
function LegacyApp({ requestMigrationPause }: { requestMigrationPause: () => void }) {
  // Re-send persisted tray/close-to-tray/retention prefs (backend resets each launch).
  useSyncBackendSettings();
  // OS-level quick-connect hotkey (⌥⌘K / Ctrl+Alt+K) — registered when enabled.
  useGlobalHotkey();
  // In-app ⌘F (focus host search) and ⌘N (new host).
  useAppShortcuts();
  // Sync engine → UI (status, applied changes, conflicts, approvals, notices). The backend
  // syncs on window focus by itself and holds that while the relay asks it to back off; a
  // `sync_now` here would skip the backoff, so only the "Sync now" button calls it.
  useSyncEvents();

  const { data, isLoading, isError, error } = useHostsQuery();
  const platform = usePlatform();
  const isMac = platform.data === "macos";
  const selectedAlias = useUiStore((s) => s.selectedAlias);
  const sidebarView = useUiStore((s) => s.sidebarView);
  const setSidebarView = useUiStore((s) => s.setSidebarView);
  const openKeychain = useUiStore((s) => s.openKeychain);
  const sidebarWidth = clampSidebarWidth(useUiStore((s) => s.sidebarWidth));
  const sidebarRef = useRef<HTMLElement>(null);
  const reload = useLoadConfig();
  const queryClient = useQueryClient();

  const handleReload = () =>
    reload.mutate(undefined, {
      onSuccess: () => {
        // Re-read everything from disk (in case the file was edited outside Lunport).
        queryClient.invalidateQueries({ queryKey: ["config"] });
        toast.success("Reloaded from disk");
      },
    });
  const setSettingsOpen = useUiStore((s) => s.setSettingsOpen);
  const setSettingsCategory = useUiStore((s) => s.setSettingsCategory);
  const mcpStatus = useMcpStatus(2_000);
  const pendingMcp = mcpStatus.data?.pending.length ?? 0;

  const hosts = data?.hosts ?? [];
  // Wildcard-only blocks (`Host *`) are config defaults, not hosts — keep them
  // out of every user-facing count.
  const hostCount = hosts.filter((h) => !isWildcardOnly(h)).length;
  // A name with several copies, one in a synced space (any name with several copies until the sync
  // overview is known): the editor would act on the first copy by name, not on the one the user
  // clicked, so the pane explains the copies instead (read-only).
  const ambiguous = useAmbiguousNames(hosts);
  const copies = selectedAlias ? ambiguous.get(selectedAlias) : undefined;

  return (
    <TooltipProvider delayDuration={300}>
      {/* Root: the ONLY fixed-height container; never scrolls. */}
      <div className="app-shell flex h-screen flex-col overflow-hidden" style={{ "--legacy-sidebar-width": `${sidebarWidth}rem` } as React.CSSProperties}>
        {/*
         * Native toolbar = window drag region. On macOS the content sits under
         * the Overlay title bar, so pad the left so the wordmark clears the
         * traffic lights. Interactive children opt OUT of dragging so clicks
         * still register.
         */}
        <header
          data-tauri-drag-region
          className={cn(
            "app-toolbar relative z-20 flex min-h-[3.2rem] shrink-0 items-center gap-3 border-b pr-2.5",
            isMac ? "pl-[78px]" : "pl-3",
          )}
        >
          <div className="pointer-events-none flex items-center gap-2">
            <BrandMark className="size-5 text-primary" />
            <div className="flex items-baseline gap-1.5">
              <h1 className="text-[0.8125rem] font-semibold tracking-tight">Lunport</h1>
              <span className="font-mono text-[0.6875rem] text-muted-foreground/80 tabular-nums">
                {isLoading ? "loading…" : `${hostCount} ${hostCount === 1 ? "host" : "hosts"}`}
              </span>
            </div>
          </div>

          <div className="ml-auto flex items-center gap-1">
            <UpdateIndicator />
            <Tooltip>
              <TooltipTrigger asChild>
                <Button
                  type="button"
                  variant="ghost"
                  size="icon"
                  className="size-7"
                  aria-label="Reload from disk"
                  onClick={handleReload}
                  disabled={reload.isPending}
                >
                  <RotateCw className={cn("size-4", reload.isPending && "animate-spin")} />
                </Button>
              </TooltipTrigger>
              <TooltipContent>Reload from disk</TooltipContent>
            </Tooltip>

            <LintDialog />
            <DiscoverDialog />
            <Tooltip>
              <TooltipTrigger asChild>
                <Button
                  type="button"
                  variant="ghost"
                  size="icon"
                  className="size-7"
                  aria-label="Keychain"
                  aria-pressed={sidebarView === "keychain"}
                  onClick={() => (sidebarView === "keychain" ? setSidebarView("hosts") : openKeychain())}
                >
                  <KeyRound className="size-4" />
                </Button>
              </TooltipTrigger>
              <TooltipContent>Keychain</TooltipContent>
            </Tooltip>
            <KnownHostsDialog />
            <BackupHistoryDialog />

            <Tooltip>
              <TooltipTrigger asChild>
                <Button
                  type="button"
                  variant="ghost"
                  size="icon"
                  className="relative size-7"
                  aria-label="AI access"
                  onClick={() => {
                    setSettingsCategory("ai");
                    setSettingsOpen(true);
                  }}
                >
                  <Bot
                    className={cn(
                      "size-4",
                      mcpStatus.data?.enabled && "text-success",
                    )}
                  />
                  {pendingMcp > 0 && (
                    <span className="absolute right-0 top-0 size-2 rounded-full bg-warning ring-2 ring-background" />
                  )}
                </Button>
              </TooltipTrigger>
              <TooltipContent>
                {pendingMcp > 0 ? `${pendingMcp} AI request pending` : "AI access"}
              </TooltipContent>
            </Tooltip>

            <Tooltip>
              <TooltipTrigger asChild>
                <Button
                  type="button"
                  variant="ghost"
                  size="icon"
                  className="size-7"
                  aria-label="Settings"
                  onClick={() => {
                    setSettingsCategory("general");
                    setSettingsOpen(true);
                  }}
                >
                  <Settings className="size-4" />
                </Button>
              </TooltipTrigger>
              <TooltipContent>Settings (⌘,)</TooltipContent>
            </Tooltip>

            <AddHostDialog />
          </div>
        </header>

        {/* Content row: flex-1 + min-h-0 so children get a bounded height. */}
        <div className="flex min-h-0 flex-1">
          {/* Resizable by its edge (SidebarResizeHandle); half the window at most, so the editor keeps room. */}
          <aside
            ref={sidebarRef}
            className="app-sidebar flex min-h-0 shrink-0 flex-col overflow-hidden border-r"
            style={{ width: `${sidebarWidth}rem`, maxWidth: "50vw" }}
          >
            <SidebarSwitch />
            {sidebarView === "keychain" ? (
              <KeychainList />
            ) : (
              // HostList fills its parent (`h-full`): this wrapper is the room left under the switch.
              <div className="flex min-h-0 flex-1 flex-col">
                {isError ? <div role="alert" className="m-3 space-y-3 rounded-lg border border-destructive/30 p-3 text-sm">
                  <p className="font-medium">Could not load SSH config</p>
                  <p className="break-words text-xs text-muted-foreground">{String(error)}</p>
                  <Button size="sm" variant="outline" disabled={reload.isPending} onClick={handleReload}>Retry</Button>
                  <Button size="sm" variant="ghost" onClick={() => { setSettingsCategory("files"); setSettingsOpen(true); }}>Config settings</Button>
                </div> : <HostList hosts={hosts} isLoading={isLoading} />}
              </div>
            )}
            <div className="shrink-0 space-y-2 border-t p-3"><p className="text-xs text-muted-foreground">OpenSSH files · Legacy workspace</p><Button variant="outline" size="sm" className="w-full" onClick={requestMigrationPause}>Pause for migration</Button></div>
          </aside>
          <SidebarResizeHandle sidebarRef={sidebarRef} />

          {/*
           * Editor pane: its OWN bounded scroll region, independent of sidebar.
           * The editor lays itself out as a responsive two-pane block (form +
           * sticky ssh_config inspector) that fills wide panes and stacks when
           * narrow. We give it a generous cap (~1100px) and keep it LEFT-aligned
           * so it reads full at ~1600px without stretching absurdly ultra-wide.
           */}
          <main className="app-main min-h-0 min-w-0 flex-1 overflow-y-auto">
            {/* Hosts stays mounted (hidden) while the Keychain shows: the editor keeps its unsaved edits. */}
            <MainPaneContent
              keychain={sidebarView === "keychain"}
              hosts={
                selectedAlias ? (
                  <div className="app-legacy-editor space-y-5 pb-24">
                    <DriftBanner />
                    {copies ? <DuplicateCopies alias={selectedAlias} copies={copies} /> : <HostEditor alias={selectedAlias} />}
                  </div>
                ) : (
                  <EmptySelection />
                )
              }
              keyDetail={<KeyDetailPane />}
            />
          </main>
        </div>

        <CommandPalette />
        <SettingsDialog />
        <DeployKeyDialog />
        <NewConfigFileDialog />
        <SyncMigrationDialog />
        <SyncUpgradeDialog />
        <SyncApprovalDialog />
        <SyncKeyDialog />
        <KeysNeededDialog />
        <McpApprovalDialog />
      </div>
    </TooltipProvider>
  );
}

/** Centered, characterful empty state shown when no host is selected. */
function EmptySelection() {
  return (
    <div className="flex h-full flex-col items-center justify-center gap-4 px-6 text-center select-none">
      <div className="flex size-12 items-center justify-center rounded-xl bg-muted text-muted-foreground ring-1 ring-border">
        <ServerCog className="size-6" />
      </div>
      <div className="space-y-1">
        <p className="text-sm font-medium">No host selected</p>
        <p className="text-sm text-muted-foreground">
          Select a host from the sidebar to edit, or add a new one.
        </p>
      </div>
    </div>
  );
}

function App() {
  useApplyTheme();
  const status = useRecordsStatus();
  const client = useQueryClient();
  const [resuming, setResuming] = useState(false);
  const [migrationOpen, setMigrationOpen] = useState(false);
  const [pauseOpen, setPauseOpen] = useState(false);
  const [savedEdits, setSavedEdits] = useState(false);
  const [pausing, setPausing] = useState(false);
  const [pauseError, setPauseError] = useState<string | null>(null);
  const pauseInFlight = useRef(false);
  const resumeInFlight = useRef(false);
  const chooseLegacy = async () => {
    if (resumeInFlight.current) return;
    resumeInFlight.current = true;
    setResuming(true);
    try {
      await useLegacyWorkspace();
      await client.cancelQueries({ queryKey: recordsStatusKey });
      await client.invalidateQueries({ queryKey: recordsStatusKey });
    } catch {
      toast.error(
        "Could not open the existing workspace. Retry when workspace status is available.",
      );
    } finally {
      resumeInFlight.current = false;
      setResuming(false);
    }
  };
  const pauseForMigration = async () => {
    if (pauseInFlight.current || !savedEdits) return;
    pauseInFlight.current = true;
    setPausing(true);
    setPauseError(null);
    try {
      if (await pauseLegacyForMigration(client, savedEdits)) {
        setPauseOpen(false);
        setSavedEdits(false);
      }
    } catch {
      setPauseError(
        "Could not pause the workspace. Save your edits and retry.",
      );
    } finally {
      pauseInFlight.current = false;
      setPausing(false);
    }
  };
  return (
    <>
      <WorkspaceGate
        status={status.data}
        resuming={resuming}
        error={status.isError}
        retry={() => void status.refetch()}
        useLegacy={() => void chooseLegacy()}
        legacy={() => (
          <LegacyApp
            requestMigrationPause={() => {
              setPauseError(null);
              setSavedEdits(false);
              setPauseOpen(true);
            }}
          />
        )}
        pausedLegacy={() => (
          <LegacyMigrationLanding
            busy={resuming}
            useLegacy={() => void chooseLegacy()}
            retry={() => void status.refetch()}
            previewMigration={() => setMigrationOpen(true)}
          />
        )}
        records={() => (
          <>
            <RecordsWorkspace
              overview={status.data!.overview!}
              reload={() => void status.refetch()}
            />
            <McpApprovalDialog />
          </>
        )}
      />
      <Dialog open={pauseOpen} onOpenChange={(open) => { if (!pausing) { setPauseOpen(open); if (!open) setSavedEdits(false); } }}>
        <TaskDialogContent role="alertdialog" className="sm:max-w-xl" aria-describedby={undefined} showCloseButton={!pausing} onEscapeKeyDown={(event) => { if (pausing) event.preventDefault(); }}>
          <DialogTitle className="sr-only">Pause for migration</DialogTitle>
          <LegacyPauseReview saved={savedEdits} busy={pausing} setSaved={setSavedEdits} error={pauseError} confirm={() => void pauseForMigration()} cancel={() => { setPauseOpen(false); setSavedEdits(false); }} />
        </TaskDialogContent>
      </Dialog>
      {migrationOpen && (
        <div className="app-shell fixed inset-0 z-50 overflow-y-auto pt-11">
          <RecordsMigrationPanel onClose={() => setMigrationOpen(false)} />
        </div>
      )}
      <Toaster />
    </>
  );
}

export default App;
