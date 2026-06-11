import { useEffect } from "react";
import { useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import { RotateCw, Settings, Terminal, ServerCog } from "lucide-react";

import { useHostsQuery, usePlatform, useLoadConfig } from "@/lib/queries";
import { useUiStore } from "@/stores/ui";
import { useApplyTheme } from "@/lib/theme";
import { useSyncBackendSettings } from "@/lib/backend-settings";
import { HostList } from "@/components/HostList";
import { HostEditor } from "@/components/HostEditor";
import { AddHostDialog } from "@/components/AddHostDialog";
import { LintDialog } from "@/components/LintDialog";
import { DiscoverDialog } from "@/components/DiscoverDialog";
import { BackupHistoryDialog } from "@/components/BackupHistoryDialog";
import { KeysDialog } from "@/components/KeysDialog";
import { SettingsDialog } from "@/components/SettingsDialog";
import { CommandPalette } from "@/components/CommandPalette";
import { DriftBanner } from "@/components/DriftBanner";
import { Toaster } from "@/components/ui/sonner";
import { Button } from "@/components/ui/button";
import { cn } from "@/lib/utils";
import { isWildcardOnly } from "@/lib/host-display";
import {
  Tooltip,
  TooltipContent,
  TooltipProvider,
  TooltipTrigger,
} from "@/components/ui/tooltip";

/**
 * App shell: master-detail layout. The left pane is the host list; the right
 * pane is the host editor for the selected alias.
 *
 * Config is loaded on mount via `useHostsQuery` (a single `config_load` that
 * yields files + hosts). Errors are surfaced as a toast.
 */
function App() {
  useApplyTheme();
  // Re-send persisted tray/close-to-tray/retention prefs (backend resets each launch).
  useSyncBackendSettings();

  const { data, isLoading, isError, error } = useHostsQuery();
  const platform = usePlatform();
  const isMac = platform.data === "macos";
  const selectedAlias = useUiStore((s) => s.selectedAlias);
  const reload = useLoadConfig();
  const queryClient = useQueryClient();

  const handleReload = () =>
    reload.mutate(undefined, {
      onSuccess: () => {
        // Re-read everything from disk (in case the file was edited outside SSHelter).
        queryClient.invalidateQueries({ queryKey: ["config"] });
        toast.success("Reloaded from disk");
      },
    });
  const setSettingsOpen = useUiStore((s) => s.setSettingsOpen);

  useEffect(() => {
    if (isError) {
      toast.error("Failed to load SSH config", {
        description: typeof error === "string" ? error : String(error),
      });
    }
  }, [isError, error]);

  const hosts = data?.hosts ?? [];
  // Wildcard-only blocks (`Host *`) are config defaults, not hosts — keep them
  // out of every user-facing count.
  const hostCount = hosts.filter((h) => !isWildcardOnly(h)).length;

  return (
    <TooltipProvider delayDuration={300}>
      {/* Root: the ONLY fixed-height container; never scrolls. */}
      <div className="app-shell flex h-screen flex-col overflow-hidden">
        {/*
         * Native toolbar = window drag region. On macOS the content sits under
         * the Overlay title bar, so pad the left so the wordmark clears the
         * traffic lights. Interactive children opt OUT of dragging so clicks
         * still register.
         */}
        <header
          data-tauri-drag-region
          className={cn(
            "app-toolbar relative z-20 flex h-11 shrink-0 items-center gap-3 border-b pr-2.5",
            isMac ? "pl-[78px]" : "pl-3",
          )}
        >
          <div className="pointer-events-none flex items-center gap-2">
            <Terminal className="size-4 text-muted-foreground" />
            <div className="flex items-baseline gap-1.5">
              <h1 className="text-[0.8125rem] font-semibold tracking-tight">SSHelter</h1>
              <span className="font-mono text-[0.6875rem] text-muted-foreground/80 tabular-nums">
                {isLoading ? "loading…" : `${hostCount} ${hostCount === 1 ? "host" : "hosts"}`}
              </span>
            </div>
          </div>

          <div className="ml-auto flex items-center gap-1">
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
            <KeysDialog />
            <BackupHistoryDialog />

            <Tooltip>
              <TooltipTrigger asChild>
                <Button
                  type="button"
                  variant="ghost"
                  size="icon"
                  className="size-7"
                  aria-label="Settings"
                  onClick={() => setSettingsOpen(true)}
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
          <aside className="app-sidebar flex w-64 min-h-0 shrink-0 flex-col overflow-hidden border-r">
            <HostList hosts={hosts} isLoading={isLoading} />
          </aside>

          {/*
           * Editor pane: its OWN bounded scroll region, independent of sidebar.
           * The editor lays itself out as a responsive two-pane block (form +
           * sticky ssh_config inspector) that fills wide panes and stacks when
           * narrow. We give it a generous cap (~1100px) and keep it LEFT-aligned
           * so it reads full at ~1600px without stretching absurdly ultra-wide.
           */}
          <main className="app-main min-h-0 min-w-0 flex-1 overflow-y-auto">
            {selectedAlias ? (
              <div className="mx-auto max-w-[720px] space-y-5 px-6 py-5 pb-24">
                <DriftBanner />
                <HostEditor alias={selectedAlias} />
              </div>
            ) : (
              <EmptySelection />
            )}
          </main>
        </div>

        <CommandPalette />
        <SettingsDialog />
        <Toaster />
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

export default App;
