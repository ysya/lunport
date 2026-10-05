import { useEffect, useMemo, useRef, useState } from "react";
import { Loader2 } from "lucide-react";
import { toast } from "sonner";

import type { MigrationFailure } from "@/bindings/MigrationFailure";
import type { MigrationReport } from "@/bindings/MigrationReport";
import { useHostsQuery } from "@/lib/queries";
import {
  PER_FILE,
  canMove,
  firstSyncWait,
  groupByReason,
  groupHostsForMigration,
  intoSpace,
  isValidTarget,
  keepVisible,
  migrationTarget,
  moveSummary,
  newSpaceGroups,
  plannedSpaceNames,
  preselectAll,
  targetLabel,
} from "@/lib/sync-migration";
import { useFileLabels, useSpaceFileLabels } from "@/lib/sync-labels";
import { SSH_COMBINES, shadowKey, shadowedCopies, type ShadowFix } from "@/lib/sync-sidebar";
import { plural } from "@/lib/sync-overview";
import { errorMessage, useDuplicateAliases, useMoveFilesToNewSpaces, useMoveHostsToSpace, useSyncOverview, useUnmovableHosts } from "@/lib/sync";
import { useLastNonNull } from "@/lib/use-last-non-null";
import { useSettingsStore } from "@/stores/settings";
import { useUiStore } from "@/stores/ui";
import { basename } from "@/lib/utils";
import { Button } from "@/components/ui/button";
import { Checkbox } from "@/components/ui/checkbox";
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Select, SelectContent, SelectItem, SelectSeparator, SelectTrigger, SelectValue } from "@/components/ui/select";
import { ShadowFixDialog } from "@/components/ShadowFixDialog";

/**
 * "Move hosts into a space" (spec §7.2, §8): pick existing hosts (grouped by
 * file) and move them into one space this computer syncs — or into one new space
 * per source file — optionally tagging those from included files with their old
 * file's name (never the main config's "config"). Lists the hosts that can never
 * be synced and why, and resolves aliases a space now shadows — addressed by
 * file, never by first match, so the copy ssh reads first is never touched.
 */
export function SyncMigrationDialog() {
  const request = useUiStore((s) => s.syncMigration);
  const setRequest = useUiStore((s) => s.setSyncMigration);
  // Owned here, not by the flow: this is where a dismissal (Esc, a click outside, the close button) is refused
  // while a move runs — closing then would lose the toast and the list of hosts that had a problem.
  const [busy, setBusy] = useState(false);
  // Kept while the dialog animates out, so it does not go empty.
  const shown = useLastNonNull(request);
  return (
    <Dialog
      open={request !== null}
      onOpenChange={(open) => {
        if (!open && !busy) setRequest(null);
      }}
    >
      <DialogContent className="sm:max-w-lg" showCloseButton={!busy}>
        {shown && <MigrationFlow requested={shown.spaceId} setBusy={setBusy} onClose={() => setRequest(null)} />}
      </DialogContent>
    </Dialog>
  );
}

/**
 * The hosts that were refused or failed, one line per reason: the relay's rate limit, which stops every
 * remaining host, is one line however many it stopped. A long list scrolls instead of growing the dialog.
 * Exported for the markup tests.
 */
export function ReasonList({ failures }: { failures: readonly MigrationFailure[] }) {
  return (
    <div className="max-h-40 space-y-1.5 overflow-y-auto pr-1">
      {groupByReason(failures).map((g) => (
        <div key={g.error} className="space-y-0.5">
          <span className="font-mono break-all">{g.aliases.join(", ")}</span>
          <p className="text-muted-foreground">{g.error}</p>
        </div>
      ))}
    </div>
  );
}

function MigrationFlow({ requested, setBusy, onClose }: { requested: string | null; setBusy: (busy: boolean) => void; onClose: () => void }) {
  const overview = useSyncOverview();
  const hostsQuery = useHostsQuery();
  const fileAliases = useSettingsStore((s) => s.fileAliases);
  const moveToSpace = useMoveHostsToSpace();
  const moveToNewSpaces = useMoveFilesToNewSpaces();
  const duplicates = useDuplicateAliases(true);
  const unmovable = useUnmovableHosts(true);
  // The fix of a copy a space shadows that waits for its confirm.
  const [fix, setFix] = useState<ShadowFix | null>(null);
  const [tagByFile, setTagByFile] = useState(true);
  const [selected, setSelected] = useState<Set<string>>(new Set());
  // null = follow `migrationTarget` (the requested space, else a sensible default).
  const [chosenTarget, setChosenTarget] = useState<string | null>(null);
  // The previous Move's failures (if any), kept on screen until the next Move
  // replaces them or the dialog closes (this component unmounts then).
  const [failedMoves, setFailedMoves] = useState<MigrationFailure[]>([]);
  // Guards the default-selection effect below so it only ever settles once per
  // dialog opening (this component unmounts when the dialog closes).
  const didDefaultSelect = useRef(false);

  const spaces = useMemo(() => overview.data?.spaces ?? [], [overview.data]);
  const synced = spaces.filter((s) => s.selected);
  const spaceLabels = useSpaceFileLabels();
  const spaceFiles = useMemo(() => [...spaceLabels.keys()], [spaceLabels]);
  // The user's pick while it is still valid (a space can be turned off, or lose its data on the relay, meanwhile).
  const targetId = chosenTarget !== null && isValidTarget(spaces, chosenTarget) ? chosenTarget : migrationTarget(spaces, requested);
  const targetSpace = synced.find((s) => s.id === targetId) ?? null;
  const unmovableAliases = useMemo(() => new Set((unmovable.data ?? []).map((f) => f.alias)), [unmovable.data]);
  const loaded = Boolean(overview.data && hostsQuery.data && unmovable.data);
  // A query that failed never turns into data: say why instead of "Loading hosts…" forever, or beside a list that is out of date.
  const loadError = [overview, hostsQuery, unmovable].find((query) => query.isError);
  // Only group once everything is loaded: before the overview arrives, no file
  // counts as a space file, and synced hosts would be listed (and preselected)
  // as if they were local.
  const groups = useMemo(
    () => (overview.data && hostsQuery.data && unmovable.data ? groupHostsForMigration(hostsQuery.data.hosts, spaceFiles, unmovableAliases) : []),
    [overview.data, hostsQuery.data, unmovable.data, spaceFiles, unmovableAliases],
  );
  const files = useMemo(() => hostsQuery.data?.files ?? [], [hostsQuery.data]);
  const labels = useFileLabels(files);
  const newNames = useMemo(() => plannedSpaceNames(groups, fileAliases, spaces.map((s) => s.name)), [groups, fileAliases, spaces]);
  // The target space was just turned on and its first (baseline) sync has not
  // finished: hosts moved now would race it, and the backend refuses them anyway.
  const waitingForFirstSync = targetSpace?.first_sync_pending === true;

  // The default selection is decided once per dialog opening, and only after no
  // synced space is waiting for its first sync. Everything is preselected only
  // for a fresh account (all synced spaces empty, e.g. right after Create);
  // otherwise the user picks. A manual toggle settles it too.
  useEffect(() => {
    if (didDefaultSelect.current || !overview.data || groups.length === 0) return;
    if (spaces.some((s) => s.selected && s.first_sync_pending)) return;
    didDefaultSelect.current = true;
    if (preselectAll(spaces)) setSelected(new Set(groups.flatMap((g) => g.hosts.map((h) => h.alias))));
  }, [groups, overview.data, spaces]);

  // Whenever the list changes, drop selected hosts it no longer shows — e.g. a
  // same-name local host once a first sync brings in its synced twin. The effect
  // runs after render, so the count and the submitted aliases also go through
  // `keepVisible` for the render in between.
  useEffect(() => {
    setSelected((prev) => keepVisible(prev, groups));
  }, [groups]);
  const visibleSelected = useMemo(() => keepVisible(selected, groups), [selected, groups]);

  const toggle = (alias: string, on: boolean) => {
    didDefaultSelect.current = true;
    setSelected((prev) => {
      const next = new Set(prev);
      if (on) next.add(alias);
      else next.delete(alias);
      return next;
    });
  };

  const done = (report: MigrationReport, into: string) => {
    // `failed` also lists a host that moved but whose tag could not be saved: it counts as moved, and as a problem.
    const summary = moveSummary(report, into);
    toast[summary.level](summary.text);
    setSelected(new Set());
    // A failed write stops the batch, so entries after it are "not attempted" —
    // surfaced below, not just as a count.
    setFailedMoves(report.failed);
  };

  const run = () => {
    const aliases = [...visibleSelected];
    if (targetId === PER_FILE) {
      const newGroups = newSpaceGroups(groups, visibleSelected, newNames);
      // A group none of whose hosts can move creates no space, so the toast does not count spaces.
      moveToNewSpaces.mutate({ groups: newGroups, tagByFile }, { onSuccess: (report) => done(report, "into new spaces") });
    } else if (targetSpace) {
      moveToSpace.mutate({ aliases, spaceId: targetSpace.id, tagByFile }, { onSuccess: (report) => done(report, intoSpace(targetSpace.name)) });
    }
  };

  const pending = moveToSpace.isPending || moveToNewSpaces.isPending;
  useEffect(() => {
    setBusy(pending);
  }, [pending, setBusy]);
  useEffect(() => () => setBusy(false), [setBusy]);
  const dups = duplicates.data ?? [];
  // For each shadowed copy, the copy ssh reads first (the confirm says it is not touched).
  const winners = useMemo(() => shadowedCopies(dups, hostsQuery.data?.hosts ?? [], spaceFiles), [dups, hostsQuery.data, spaceFiles]);
  const cannotMove = unmovable.data ?? [];

  return (
    <>
      <DialogHeader>
        <DialogTitle>Move hosts into a space</DialogTitle>
        <DialogDescription>
          Selected hosts move into the space's file in ~/.ssh/sshelter (a backup is written first) and appear on every computer that syncs that space.
          Wildcard blocks stay where they are. Space files are read before your main config, so moved hosts' own options now take precedence over wildcard
          blocks (like <span className="font-mono">Host *</span>) earlier in that file.
        </DialogDescription>
      </DialogHeader>

      <div className="flex items-center gap-2 text-sm">
        <span className="shrink-0 text-muted-foreground">Move into</span>
        <Select value={targetId} onValueChange={setChosenTarget}>
          <SelectTrigger className="h-7 min-w-0 flex-1 text-sm" aria-label="Target space">
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            {synced.map((s) => (
              <SelectItem key={s.id} value={s.id} disabled={s.missing}>
                {targetLabel(s)}
              </SelectItem>
            ))}
            {synced.length > 0 && <SelectSeparator />}
            <SelectItem value={PER_FILE}>One new space per file</SelectItem>
          </SelectContent>
        </Select>
      </div>

      {loadError && (
        <p className="text-sm text-destructive">
          {loaded ? "Could not refresh the hosts" : "Could not load the hosts"}: {errorMessage(loadError.error)}
        </p>
      )}
      {!loaded ? (
        loadError ? null : <p className="text-sm text-muted-foreground">Loading hosts…</p>
      ) : groups.length === 0 ? (
        <p className="text-sm text-muted-foreground">Every host that can be synced is already in a space.</p>
      ) : (
        <div className="max-h-[40vh] space-y-3 overflow-y-auto pr-1">
          {groups.map((g) => (
            <div key={g.file} className="space-y-1">
              <p className="text-xs font-semibold tracking-wide text-muted-foreground uppercase">
                {labels.get(g.file) ?? basename(g.file)}
                {targetId === PER_FILE && <span className="font-normal normal-case tracking-normal"> → new space “{newNames.get(g.file)}”</span>}
              </p>
              {g.hosts.map((h) => (
                <label key={h.alias} className="flex items-center gap-2 text-sm">
                  <Checkbox checked={selected.has(h.alias)} onCheckedChange={(v) => toggle(h.alias, v === true)} />
                  <span className="font-mono">{h.alias}</span>
                  {h.hostname && (
                    <span className="truncate text-xs text-muted-foreground">
                      {h.user ? `${h.user}@` : ""}
                      {h.hostname}
                    </span>
                  )}
                </label>
              ))}
            </div>
          ))}
        </div>
      )}

      {groups.length > 0 && (
        <label className="flex items-center gap-2 text-sm">
          <Checkbox checked={tagByFile} onCheckedChange={(v) => setTagByFile(v === true)} />
          Tag hosts from included files with their file name (keeps your grouping in tag view)
        </label>
      )}

      {groups.length > 0 && waitingForFirstSync && targetSpace && (
        <p className="text-sm text-muted-foreground">{firstSyncWait(targetSpace.name)}</p>
      )}

      {cannotMove.length > 0 && (
        <div className="space-y-1.5 rounded-md border p-3 text-xs">
          <p className="font-medium">Can't be synced</p>
          <ReasonList failures={cannotMove} />
        </div>
      )}

      {failedMoves.length > 0 && (
        <div className="space-y-1.5 rounded-md border border-destructive/40 bg-destructive/10 p-3 text-xs">
          <p className="font-medium text-destructive">Problems with {plural(failedMoves.length, "host")}</p>
          <ReasonList failures={failedMoves} />
        </div>
      )}

      {duplicates.isError && (
        <p className="text-xs text-destructive">Could not look for hosts defined in more than one file: {errorMessage(duplicates.error)}</p>
      )}
      {dups.length > 0 && (
        <div className="space-y-1.5 rounded-md border border-amber-500/40 bg-amber-500/10 p-3 text-xs">
          <p className="font-medium text-amber-700 dark:text-amber-400">Hosts defined in more than one file</p>
          <p className="text-muted-foreground">
            {SSH_COMBINES}. Keep this copy under a new name, or remove it so that only the other copy is left:
          </p>
          <div className="max-h-40 space-y-1.5 overflow-y-auto pr-1">
            {dups.map((d) => {
              const winner = winners.get(shadowKey(d.local_file, d.alias));
              const confirmFix = (action: ShadowFix["action"]) =>
                setFix({
                  alias: d.alias,
                  action,
                  file: d.local_file,
                  fileLabel: labels.get(d.local_file) ?? basename(d.local_file),
                  space: spaceLabels.get(d.local_file) ?? null,
                  winner: winner ? (labels.get(winner) ?? basename(winner)) : "the space listed first",
                });
              return (
                <div key={`${d.alias}-${d.local_file}`} className="flex items-center justify-between gap-2">
                  <span className="font-mono">
                    {d.alias} <span className="text-muted-foreground">in {labels.get(d.local_file) ?? basename(d.local_file)}</span>
                  </span>
                  <div className="flex gap-1">
                    <Button type="button" variant="outline" size="sm" className="h-6 px-2 text-xs" onClick={() => confirmFix("rename")}>
                      Keep as {d.alias}-local
                    </Button>
                    <Button type="button" variant="outline" size="sm" className="h-6 px-2 text-xs text-destructive" onClick={() => confirmFix("remove")}>
                      Remove this copy
                    </Button>
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      )}

      <ShadowFixDialog fix={fix} onClose={() => setFix(null)} />

      <DialogFooter>
        <Button type="button" variant="outline" disabled={pending} onClick={onClose}>
          Close
        </Button>
        {groups.length > 0 && (
          <Button
            type="button"
            disabled={!canMove({ selected: visibleSelected.size, pending, waitingForFirstSync, target: targetId, targetSpace })}
            onClick={run}
          >
            {pending && <Loader2 className="size-4 animate-spin" />} Move {plural(visibleSelected.size, "host")}
          </Button>
        )}
      </DialogFooter>
    </>
  );
}
