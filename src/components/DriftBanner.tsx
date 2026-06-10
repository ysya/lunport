import { useEffect } from "react";
import { useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import { RefreshCw, TriangleAlert } from "lucide-react";

import { useDrift, useLoadConfig, queryKeys } from "@/lib/queries";
import { useSettingsStore } from "@/stores/settings";
import { Button } from "@/components/ui/button";
import { basename } from "@/lib/utils";

/**
 * Detects on-disk drift (files changed since load) and offers a one-click
 * reload. The drift query is enabled here and re-checked whenever the window
 * regains focus. Renders nothing when no file has drifted.
 */
export function DriftBanner() {
  const queryClient = useQueryClient();
  const driftAutoCheck = useSettingsStore((s) => s.driftAutoCheck);
  const driftIntervalSec = useSettingsStore((s) => s.driftIntervalSec);
  const { data } = useDrift({
    enabled: true,
    // Opt-in polling on top of the always-on focus re-check below.
    refetchInterval: driftAutoCheck ? driftIntervalSec * 1000 : undefined,
  });
  const loadConfig = useLoadConfig();

  // Re-check drift when the window regains focus.
  useEffect(() => {
    const onFocus = () => {
      queryClient.invalidateQueries({ queryKey: queryKeys.drift });
    };
    window.addEventListener("focus", onFocus);
    return () => window.removeEventListener("focus", onFocus);
  }, [queryClient]);

  const changed = (data ?? []).filter((d) => d.changed);
  if (changed.length === 0) return null;

  const names = changed.map((d) => basename(d.path)).join(", ");

  return (
    <div className="flex items-center justify-between gap-3 rounded-lg border border-warning/40 bg-warning/10 px-3.5 py-2.5 text-sm">
      <div className="flex min-w-0 items-center gap-2.5">
        <TriangleAlert className="size-4 shrink-0 text-warning" />
        <span className="min-w-0 text-foreground select-none">
          Changed on disk:{" "}
          <span className="font-mono font-medium break-all select-text">{names}</span>
        </span>
      </div>
      <Button
        type="button"
        size="sm"
        variant="outline"
        className="shrink-0"
        disabled={loadConfig.isPending}
        onClick={() =>
          loadConfig.mutate(undefined, {
            onSuccess: () => {
              toast.success("Config reloaded from disk");
              queryClient.invalidateQueries({ queryKey: queryKeys.drift });
            },
          })
        }
      >
        <RefreshCw className={loadConfig.isPending ? "size-4 animate-spin" : "size-4"} /> Reload
      </Button>
    </div>
  );
}

export default DriftBanner;
