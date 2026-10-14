import { useState } from "react";
import { Plus } from "lucide-react";
import { Button } from "@/components/ui/button";
import { SEARCH_INPUT_ID } from "@/lib/app-shortcuts";
import { useSettingsStore } from "@/stores/settings";
import { Input } from "@/components/ui/input";
import type { RecordOverview } from "@/lib/records";
import { revealHidden } from "@/lib/sync-approvals";
import { cn } from "@/lib/utils";
import { scopeLabel } from "./operations";
export const readinessLabel = {
  ready: "Ready",
  needs_key: "Needs key",
  key_conflict: "Key conflict",
  needs_review: "Needs review",
};
export function RecordHostList({
  overview,
  selectedId,
  select,
  create,
  disabled = false,
}: {
  overview: RecordOverview;
  selectedId: string | null;
  select: (id: string) => void;
  create?: () => void;
  disabled?: boolean;
}) {
  const showTags = useSettingsStore((state) => state.showHostTags);
  const [search, setSearch] = useState("");
  const hosts = overview.hosts.filter((host) =>
    `${host.payload.alias} ${host.payload.hostname} ${host.payload.tags.join(" ")}`
      .toLowerCase()
      .includes(search.toLowerCase()),
  );
  const counts = new Map<string, number>();
  for (const host of overview.hosts)
    counts.set(host.id, (counts.get(host.id) ?? 0) + 1);
  return (
    <div className="flex h-full min-h-0 flex-col">
      <div className="shrink-0 space-y-3 border-b p-3">
        <div className="flex items-center justify-between">
          <h2 className="text-sm font-semibold">Hosts</h2>
          {create && (
            <Button
              size="sm"
              variant="ghost"
              disabled={disabled}
              onClick={create}
            >
              <Plus className="size-3.5" /> New host
            </Button>
          )}
        </div>
        <Input
          id={SEARCH_INPUT_ID}
          aria-label="Search hosts"
          placeholder="Search hosts…"
          value={search}
          onChange={(event) => setSearch(event.target.value)}
        />
      </div>
      <div className="min-h-0 flex-1 space-y-1 overflow-y-auto p-2">
        {hosts.length === 0 && (
          <p className="p-3 text-sm text-muted-foreground">
            {search
              ? "No matching hosts"
              : "No hosts yet. Add a host or import a configuration."}
          </p>
        )}
        {hosts.map((host, index) => (
          <button
            key={`${host.id}:${host.scope.kind === "local" ? "local" : host.scope.space_id}:${index}`}
            type="button"
            className={cn(
              "w-full rounded-md px-3 py-2 text-left hover:bg-accent",
              selectedId === host.id && "bg-accent",
            )}
            aria-pressed={selectedId === host.id}
            disabled={disabled}
            onClick={() => select(host.id)}
          >
            <span className="block truncate text-sm font-medium">
              {revealHidden(host.payload.alias)}
            </span>
            {showTags && host.payload.tags.length > 0 && (
              <span className="block truncate text-xs text-muted-foreground">
                {revealHidden(host.payload.tags.join(" · "))}
              </span>
            )}
            <span className="block truncate text-xs text-muted-foreground">
              {revealHidden(host.payload.hostname)} ·{" "}
              {revealHidden(scopeLabel(overview, host.scope))}
            </span>
            <span className="text-xs text-muted-foreground">
              {(counts.get(host.id) ?? 0) > 1
                ? "Conflicting host ID"
                : readinessLabel[host.readiness.kind]}
            </span>
          </button>
        ))}
      </div>
    </div>
  );
}
