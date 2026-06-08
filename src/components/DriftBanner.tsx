import { useEffect } from "react";
import { useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import { RefreshCw } from "lucide-react";

import { useDrift, useLoadConfig, queryKeys } from "@/lib/queries";
import { Button } from "@/components/ui/button";

/** Last path segment of a (possibly `/`- or `\`-separated) file path. */
function basename(p: string): string {
  const norm = p.replace(/\\/g, "/");
  const parts = norm.split("/");
  return parts[parts.length - 1] || p;
}

/**
 * Detects on-disk drift (files changed since load) and offers a one-click
 * reload. The drift query is enabled here and re-checked whenever the window
 * regains focus. Renders nothing when no file has drifted.
 */
export function DriftBanner() {
  const queryClient = useQueryClient();
  const { data } = useDrift({ enabled: true });
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
    <div className="flex items-center justify-between gap-3 rounded-md border border-amber-500/50 bg-amber-500/10 px-3 py-2 text-sm">
      <span className="text-amber-700 dark:text-amber-400">
        Changed on disk: <span className="font-medium">{names}</span>
      </span>
      <Button
        type="button"
        size="sm"
        variant="outline"
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
        <RefreshCw className="size-4" /> Reload
      </Button>
    </div>
  );
}

export default DriftBanner;
