import { useEffect } from "react";
import { toast } from "sonner";
import { Moon, Sun, TerminalSquare, ServerCog } from "lucide-react";

import { useHostsQuery } from "@/lib/queries";
import { useUiStore } from "@/stores/ui";
import { useApplyTheme } from "@/lib/theme";
import { HostList } from "@/components/HostList";
import { HostEditor } from "@/components/HostEditor";
import { AddHostDialog } from "@/components/AddHostDialog";
import { DriftBanner } from "@/components/DriftBanner";
import { Toaster } from "@/components/ui/sonner";
import { Button } from "@/components/ui/button";
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

  const { data, isLoading, isError, error } = useHostsQuery();
  const selectedAlias = useUiStore((s) => s.selectedAlias);
  const theme = useUiStore((s) => s.theme);
  const toggleTheme = useUiStore((s) => s.toggleTheme);

  useEffect(() => {
    if (isError) {
      toast.error("Failed to load SSH config", {
        description: typeof error === "string" ? error : String(error),
      });
    }
  }, [isError, error]);

  const hosts = data?.hosts ?? [];

  return (
    <TooltipProvider delayDuration={300}>
      <div className="app-atmosphere flex h-screen flex-col overflow-hidden">
        <header className="relative z-10 flex shrink-0 items-center gap-3 border-b bg-background/70 px-4 py-2.5 backdrop-blur-sm">
          <div className="flex items-center gap-2">
            <span className="flex size-7 items-center justify-center rounded-md bg-primary/15 text-primary ring-1 ring-primary/25">
              <TerminalSquare className="size-4" />
            </span>
            <div className="flex items-baseline gap-2">
              <h1 className="text-sm font-semibold tracking-tight">SSHelter</h1>
              <span className="font-mono text-xs text-muted-foreground tabular-nums">
                {isLoading ? "loading…" : `${hosts.length} ${hosts.length === 1 ? "host" : "hosts"}`}
              </span>
            </div>
          </div>

          <div className="ml-auto flex items-center gap-1.5">
            <Tooltip>
              <TooltipTrigger asChild>
                <Button
                  type="button"
                  variant="ghost"
                  size="icon"
                  aria-label="Toggle theme"
                  onClick={toggleTheme}
                >
                  {theme === "dark" ? (
                    <Sun className="size-4" />
                  ) : (
                    <Moon className="size-4" />
                  )}
                </Button>
              </TooltipTrigger>
              <TooltipContent>
                {theme === "dark" ? "Light mode" : "Dark mode"}
              </TooltipContent>
            </Tooltip>
            <AddHostDialog />
          </div>
        </header>

        <div className="relative z-10 flex min-h-0 flex-1">
          <aside className="w-72 shrink-0 border-r bg-sidebar/40">
            <HostList hosts={hosts} isLoading={isLoading} />
          </aside>

          <main className="min-w-0 flex-1 overflow-auto">
            {selectedAlias ? (
              <div className="mx-auto max-w-2xl space-y-4 p-6 pb-28">
                <DriftBanner />
                <HostEditor alias={selectedAlias} />
              </div>
            ) : (
              <EmptySelection />
            )}
          </main>
        </div>

        <Toaster />
      </div>
    </TooltipProvider>
  );
}

/** Centered, characterful empty state shown when no host is selected. */
function EmptySelection() {
  return (
    <div className="flex h-full flex-col items-center justify-center gap-4 px-6 text-center">
      <div className="flex size-14 items-center justify-center rounded-xl bg-muted/60 text-muted-foreground ring-1 ring-border">
        <ServerCog className="size-7" />
      </div>
      <div className="space-y-1">
        <p className="text-sm font-medium">No host selected</p>
        <p className="text-sm text-muted-foreground">
          Select a host to edit, or{" "}
          <kbd className="rounded border bg-muted px-1.5 py-0.5 font-mono text-[0.7rem] text-foreground">
            New host
          </kbd>{" "}
          to create one.
        </p>
      </div>
    </div>
  );
}

export default App;
