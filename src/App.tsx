import { useEffect } from "react";
import { toast } from "sonner";
import { useHostsQuery } from "@/lib/queries";
import { useUiStore } from "@/stores/ui";
import { HostList } from "@/components/HostList";
import { HostEditor } from "@/components/HostEditor";
import { AddHostDialog } from "@/components/AddHostDialog";
import { DriftBanner } from "@/components/DriftBanner";
import { Toaster } from "@/components/ui/sonner";

/**
 * App shell: master-detail layout. The left pane is the host list; the right
 * pane is the host editor for the selected alias.
 *
 * Config is loaded on mount via `useHostsQuery` (a single `config_load` that
 * yields files + hosts). Errors are surfaced as a toast.
 */
function App() {
  const { data, isLoading, isError, error } = useHostsQuery();
  const selectedAlias = useUiStore((s) => s.selectedAlias);

  useEffect(() => {
    if (isError) {
      toast.error("Failed to load SSH config", {
        description: typeof error === "string" ? error : String(error),
      });
    }
  }, [isError, error]);

  const hosts = data?.hosts ?? [];

  return (
    <div className="flex h-screen flex-col overflow-hidden">
      <header className="flex shrink-0 items-center gap-3 border-b px-4 py-2">
        <h1 className="text-sm font-semibold">SSHelter</h1>
        <span className="text-xs text-muted-foreground">
          {isLoading ? "loading…" : `${hosts.length} hosts`}
        </span>
        <div className="ml-auto">
          <AddHostDialog />
        </div>
      </header>

      <div className="flex min-h-0 flex-1">
        <aside className="w-72 shrink-0 border-r">
          <HostList hosts={hosts} isLoading={isLoading} />
        </aside>

        <main className="min-w-0 flex-1 overflow-auto p-6">
          {selectedAlias ? (
            <div className="mx-auto max-w-2xl space-y-4">
              <DriftBanner />
              <HostEditor alias={selectedAlias} />
            </div>
          ) : (
            <div className="flex h-full items-center justify-center text-sm text-muted-foreground">
              Select a host
            </div>
          )}
        </main>
      </div>

      <Toaster />
    </div>
  );
}

export default App;
