import { useMemo, useState } from "react";
import { Telescope, FileKey, Network } from "lucide-react";

import type { Suggestion } from "@/bindings/Suggestion";
import { useDiscoverHosts } from "@/lib/queries";
import { useSettingsStore } from "@/stores/settings";
import { cn } from "@/lib/utils";

import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from "@/components/ui/dialog";
import {
  Tooltip,
  TooltipContent,
  TooltipTrigger,
} from "@/components/ui/tooltip";

const SOURCE_LABEL: Record<string, string> = {
  known_hosts: "known_hosts",
  tailscale: "Tailscale",
};

/** Toolbar button + a dialog listing discovered host candidates by source. */
export function DiscoverDialog() {
  const [open, setOpen] = useState(false);
  // Lazy: only shell out to discover when the dialog is open.
  const { data, isLoading, isFetching } = useDiscoverHosts({ enabled: open });
  const discoverKnownHosts = useSettingsStore((s) => s.discoverKnownHosts);
  const discoverTailscale = useSettingsStore((s) => s.discoverTailscale);
  const allSourcesOff = !discoverKnownHosts && !discoverTailscale;
  // Hide suggestions from disabled sources; unknown sources stay visible.
  const suggestions = (data ?? []).filter((s) =>
    s.source === "known_hosts"
      ? discoverKnownHosts
      : s.source === "tailscale"
        ? discoverTailscale
        : true,
  );

  const grouped = useMemo(() => {
    const map = new Map<string, Suggestion[]>();
    for (const s of suggestions) {
      const arr = map.get(s.source) ?? [];
      arr.push(s);
      map.set(s.source, arr);
    }
    return map;
  }, [suggestions]);

  return (
    <Dialog open={open} onOpenChange={setOpen}>
      <Tooltip>
        <TooltipTrigger asChild>
          <DialogTrigger asChild>
            <Button
              type="button"
              variant="ghost"
              size="icon"
              className="size-7"
              aria-label="Discover hosts"
            >
              <Telescope className="size-4" />
            </Button>
          </DialogTrigger>
        </TooltipTrigger>
        <TooltipContent>Discover hosts</TooltipContent>
      </Tooltip>

      <DialogContent className="sm:max-w-md">
        <DialogHeader>
          <DialogTitle>Discover hosts</DialogTitle>
          <DialogDescription>
            Candidates found in your <span className="font-mono">known_hosts</span> and
            Tailscale network.
          </DialogDescription>
        </DialogHeader>

        {allSourcesOff ? (
          <p className="py-6 text-center text-sm text-muted-foreground select-none">
            All discovery sources are disabled. Enable them in Settings → Advanced.
          </p>
        ) : isLoading || isFetching ? (
          <p className="py-6 text-center text-sm text-muted-foreground select-none">
            Scanning…
          </p>
        ) : suggestions.length === 0 ? (
          <p className="py-6 text-center text-sm text-muted-foreground select-none">
            No candidates found.
          </p>
        ) : (
          <div className="-mx-1 max-h-[60vh] space-y-4 overflow-y-auto px-1">
            {[...grouped.entries()].map(([source, list]) => (
              <div key={source}>
                <span className="section-label flex items-center gap-1.5">
                  {source === "tailscale" ? (
                    <Network className="size-3" />
                  ) : (
                    <FileKey className="size-3" />
                  )}
                  {SOURCE_LABEL[source] ?? source}
                </span>
                <div className="settings-group">
                  {list.map((s, i) => (
                    <DiscoverRow key={`${source}-${s.name}-${i}`} suggestion={s} />
                  ))}
                </div>
              </div>
            ))}
          </div>
        )}
      </DialogContent>
    </Dialog>
  );
}

function DiscoverRow({ suggestion }: { suggestion: Suggestion }) {
  const { name, host_name, port, online } = suggestion;
  return (
    <div className="flex min-h-9 items-center justify-between gap-3 px-3 py-2">
      <div className="flex min-w-0 items-center gap-2">
        {online !== null && (
          <span
            className={cn(
              "size-1.5 shrink-0 rounded-full",
              online ? "bg-emerald-500" : "bg-muted-foreground/40",
            )}
            title={online ? "Online" : "Offline"}
            aria-hidden
          />
        )}
        <span className="truncate font-mono text-sm">{name}</span>
      </div>
      <span className="shrink-0 truncate font-mono text-xs text-muted-foreground">
        {host_name}
        {port !== null ? `:${port}` : ""}
      </span>
    </div>
  );
}

export default DiscoverDialog;
