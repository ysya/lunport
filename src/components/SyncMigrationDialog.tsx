import { useEffect, useMemo, useRef, useState } from "react";
import { Loader2 } from "lucide-react";
import { toast } from "sonner";

import { useHostsQuery } from "@/lib/queries";
import { labelsFor } from "@/lib/host-display";
import { groupHostsForMigration } from "@/lib/sync-migration";
import { useDuplicateAliases, useMigrateHosts, useResolveShadowed, useSyncStatus } from "@/lib/sync";
import { useSettingsStore } from "@/stores/settings";
import { useUiStore } from "@/stores/ui";
import { basename } from "@/lib/utils";
import { Button } from "@/components/ui/button";
import { Checkbox } from "@/components/ui/checkbox";
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog";

/**
 * "Move hosts into sync": pick existing hosts (grouped by file) to move into the
 * synced file, optionally tagging them with their old file's name; then resolve
 * aliases that the synced file now shadows — addressed by file, never by
 * first-match, so the synced copy is never touched.
 */
export function SyncMigrationDialog() {
  const open = useUiStore((s) => s.syncMigrationOpen);
  const setOpen = useUiStore((s) => s.setSyncMigrationOpen);
  return (
    <Dialog open={open} onOpenChange={setOpen}>
      <DialogContent className="sm:max-w-lg">{open && <MigrationFlow onClose={() => setOpen(false)} />}</DialogContent>
    </Dialog>
  );
}

function MigrationFlow({ onClose }: { onClose: () => void }) {
  const status = useSyncStatus();
  const hostsQuery = useHostsQuery();
  const fileAliases = useSettingsStore((s) => s.fileAliases);
  const migrate = useMigrateHosts();
  const duplicates = useDuplicateAliases(true);
  const resolve = useResolveShadowed();
  const [tagByFile, setTagByFile] = useState(true);
  const [selected, setSelected] = useState<Set<string>>(new Set());
  // Guards the default-selection effect below so it only ever fires once per
  // dialog opening (this component unmounts when the dialog closes, so the ref
  // is fresh again next time it opens).
  const didDefaultSelect = useRef(false);

  const managed = status.data?.managed_file ?? "";
  const files = useMemo(() => hostsQuery.data?.files ?? [], [hostsQuery.data]);
  const labels = useMemo(() => labelsFor(files, fileAliases), [files, fileAliases]);
  // Only group once BOTH queries are loaded. Before `status` loads, `managed`
  // falls back to "", which would fail to exclude synced hosts from the
  // synced file — they would be listed (and pre-selected) as if still local.
  const groups = useMemo(
    () => (status.data && hostsQuery.data ? groupHostsForMigration(hostsQuery.data.hosts, status.data.managed_file) : []),
    [status.data, hostsQuery.data],
  );

  // Default to everything selected, but only the FIRST time the list is known
  // for this dialog opening. Re-running this whenever `groups` changes while
  // the selection is empty would silently re-select hosts the user had
  // deselected — for example right after a successful partial move clears it.
  useEffect(() => {
    if (!didDefaultSelect.current && groups.length > 0) {
      didDefaultSelect.current = true;
      setSelected(new Set(groups.flatMap((g) => g.hosts.map((h) => h.alias))));
    }
  }, [groups]);

  const toggle = (alias: string, on: boolean) =>
    setSelected((prev) => {
      const next = new Set(prev);
      if (on) next.add(alias);
      else next.delete(alias);
      return next;
    });

  const run = () =>
    migrate.mutate(
      { aliases: [...selected], tagByFile },
      {
        onSuccess: (report) => {
          const failed = report.failed.length;
          toast.success(`Moved ${report.moved.length} host${report.moved.length === 1 ? "" : "s"} into sync${failed ? `, ${failed} failed` : ""}`);
          setSelected(new Set());
        },
      },
    );

  const dups = duplicates.data ?? [];

  return (
    <>
      <DialogHeader>
        <DialogTitle>Move hosts into sync</DialogTitle>
        <DialogDescription>
          Selected hosts move into <span className="font-mono">{basename(managed)}</span> (a backup is written first) and appear on every device in the chain. Wildcard blocks stay where they are.
        </DialogDescription>
      </DialogHeader>

      {groups.length === 0 ? (
        <p className="text-sm text-muted-foreground">Every host is already in the synced file.</p>
      ) : (
        <div className="max-h-[40vh] space-y-3 overflow-y-auto pr-1">
          {groups.map((g) => (
            <div key={g.file} className="space-y-1">
              <p className="text-xs font-semibold tracking-wide text-muted-foreground uppercase">{labels.get(g.file) ?? basename(g.file)}</p>
              {g.hosts.map((h) => (
                <label key={h.alias} className="flex items-center gap-2 text-sm">
                  <Checkbox checked={selected.has(h.alias)} onCheckedChange={(v) => toggle(h.alias, v === true)} />
                  <span className="font-mono">{h.alias}</span>
                  {h.hostname && <span className="truncate text-xs text-muted-foreground">{h.user ? `${h.user}@` : ""}{h.hostname}</span>}
                </label>
              ))}
            </div>
          ))}
        </div>
      )}

      {groups.length > 0 && (
        <label className="flex items-center gap-2 text-sm">
          <Checkbox checked={tagByFile} onCheckedChange={(v) => setTagByFile(v === true)} />
          Tag each host with its current file name (keeps your grouping in tag view)
        </label>
      )}

      {dups.length > 0 && (
        <div className="space-y-1.5 rounded-md border border-amber-500/40 bg-amber-500/10 p-3 text-xs">
          <p className="font-medium text-amber-700 dark:text-amber-400">Synced hosts shadow local definitions</p>
          <p className="text-muted-foreground">The synced file is included first, so its options win — but ssh still takes any option the synced block does not set from these local blocks, and IdentityFile entries add up. Keep the local one under a new name, or remove it (its extra options go away) and use only the synced version:</p>
          {dups.map((d) => (
            <div key={`${d.alias}-${d.local_file}`} className="flex items-center justify-between gap-2">
              <span className="font-mono">{d.alias} <span className="text-muted-foreground">in {basename(d.local_file)}</span></span>
              <div className="flex gap-1">
                <Button type="button" variant="outline" size="sm" className="h-6 px-2 text-xs" disabled={resolve.isPending} onClick={() => resolve.mutate({ alias: d.alias, file: d.local_file, action: "rename" })}>
                  Keep as {d.alias}-local
                </Button>
                <Button type="button" variant="outline" size="sm" className="h-6 px-2 text-xs text-destructive" disabled={resolve.isPending} onClick={() => resolve.mutate({ alias: d.alias, file: d.local_file, action: "remove" })}>
                  Remove local
                </Button>
              </div>
            </div>
          ))}
        </div>
      )}

      <DialogFooter>
        <Button type="button" variant="outline" onClick={onClose}>Close</Button>
        {groups.length > 0 && (
          <Button type="button" disabled={selected.size === 0 || migrate.isPending} onClick={run}>
            {migrate.isPending && <Loader2 className="size-4 animate-spin" />} Move {selected.size} host{selected.size === 1 ? "" : "s"}
          </Button>
        )}
      </DialogFooter>
    </>
  );
}
