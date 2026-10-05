import { useEffect, useLayoutEffect, useRef, useState } from "react";
import { Loader2, ShieldAlert } from "lucide-react";
import { toast } from "sonner";

import type { PendingApprovalView } from "@/bindings/PendingApprovalView";
import { useHostsQuery } from "@/lib/queries";
import { errorMessage, useApproveHosts, usePendingApprovals, useRejectHosts, useSyncOverview } from "@/lib/sync";
import {
  adoptAtOnce,
  adoptNewest,
  approvalChanges,
  approvalGroups,
  blockLines,
  changeText,
  changedNotice,
  combineOutcomes,
  decisionSummary,
  displayLines,
  hostKey,
  REVIEW_INTRO,
  isSettled,
  listMoved,
  markText,
  revealHidden,
  runDecision,
  sameVersions,
  type AboveList,
  type ApprovalGroup,
  type ConfigHost,
  type HostRef,
  type ReviewSpace,
  type VersionMark,
} from "@/lib/sync-approvals";
import { relativeTime } from "@/lib/format";
import { structureLock } from "@/lib/sync-spaces";
import { useUiStore } from "@/stores/ui";
import { cn } from "@/lib/utils";
import { Button } from "@/components/ui/button";
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog";

/**
 * Shown in logical order, left to right, whatever the characters are: right-to-left
 * text cannot make a line look different from what ssh reads. Text from other
 * computers also goes through `revealHidden`, which makes bidi and zero-width
 * characters visible.
 */
const LOGICAL_ORDER = "[direction:ltr] [unicode-bidi:bidi-override]";

/**
 * How long the decision buttons stay off after the list on screen was replaced, or moved because a paragraph
 * above it appeared, went away or changed (`listMoved`). The dialog is centred, so when the list appears or
 * changes it grows or shifts while the pointer has not moved: a click aimed at what was there would land on a
 * button of a host nobody has read. Long enough to see the change, too short to notice.
 */
export const CLICK_GUARD_MS = 600;

/**
 * Review of synced hosts held back because they bring settings that run
 * programs, share credentials or relax host-key checks (spec §7.4,
 * `GATED_KEYWORDS`). Each host shows the full incoming
 * block with the gated lines marked and what approving changes; approve or reject
 * one host, or everything at once — always exactly the versions on screen.
 * A host whose version changes while the review is open is marked on its own card
 * and named in a notice, never swapped in silently. The dialog cannot be dismissed
 * while a decision runs, and it offers no decision while the account cannot take one
 * (the sync code changed elsewhere or is being changed, a newer format, an unfinished
 * upgrade): the backend refuses them then, so the buttons are off and the reason is shown.
 * Opened from the approval toast and from Settings → Sync.
 */
export function SyncApprovalDialog() {
  const open = useUiStore((s) => s.syncApprovalsOpen);
  const setOpen = useUiStore((s) => s.setSyncApprovalsOpen);
  // Owned here, not by the review: this is where a dismissal (Esc, a click outside, the
  // close button) is refused. A decision is one call per space; closing in the middle
  // would leave it half done and its result unreported.
  const [running, setRunning] = useState<Running | null>(null);
  return (
    <Dialog
      open={open}
      onOpenChange={(next) => {
        if (next || running === null) setOpen(next);
      }}
    >
      <DialogContent className="sm:max-w-2xl" showCloseButton={running === null}>
        {open && <ApprovalReview running={running} setRunning={setRunning} onClose={() => setOpen(false)} />}
      </DialogContent>
    </Dialog>
  );
}

/** The decision under way: which one, for everything (`"all"`) or for one host (its `hostKey`). */
interface Running {
  decision: "approve" | "reject";
  target: string;
}

function ApprovalReview({
  running,
  setRunning,
  onClose,
}: {
  running: Running | null;
  setRunning: (running: Running | null) => void;
  onClose: () => void;
}) {
  const pending = usePendingApprovals(true);
  const config = useHostsQuery();
  // The spaces in the order of the Include list: which space's file ssh reads first.
  const overview = useSyncOverview();
  const approve = useApproveHosts();
  const reject = useRejectHosts();
  // The versions on screen. They stay put until the user decides or asks for the
  // newest ones, so a version that arrives meanwhile never takes the place of the
  // one being approved; the backend checks each digest too and reports what changed.
  const [shown, setShown] = useState<PendingApprovalView[] | null>(null);
  // Hosts whose version is not the one the user first saw, by `hostKey`: each stays marked until it is decided.
  const [marks, setMarks] = useState<ReadonlyMap<string, VersionMark>>(new Map());
  const [notice, setNotice] = useState<string | null>(null);
  const busy = running !== null;
  // The decision buttons are off for a moment after the list on screen was replaced (`CLICK_GUARD_MS`).
  const [guarded, setGuarded] = useState(false);
  const guardTimer = useRef<number | null>(null);
  const guard = () => {
    setGuarded(true);
    if (guardTimer.current !== null) window.clearTimeout(guardTimer.current);
    guardTimer.current = window.setTimeout(() => {
      guardTimer.current = null;
      setGuarded(false);
    }, CLICK_GUARD_MS);
  };
  useEffect(
    () => () => {
      if (guardTimer.current !== null) window.clearTimeout(guardTimer.current);
    },
    [],
  );

  // Only a list that nothing is refreshing: a re-opened dialog first has the list cached
  // from an earlier review, which can be out of date (even empty) while the refetch runs.
  useEffect(() => {
    if (shown === null && pending.data !== undefined && isSettled(pending)) {
      setShown(pending.data);
      guard();
    }
  }, [shown, pending.data, pending.isSuccess, pending.isFetching]);

  const views = shown ?? [];
  const groups = approvalGroups(views);
  const hosts: ConfigHost[] = config.data?.hosts ?? [];
  const spaces: ReviewSpace[] | undefined = overview.data?.spaces;
  // Why no decision is possible right now, if so (`structureLock`: the backend refuses approvals then).
  const lock = overview.data ? structureLock(overview.data) : null;
  // With nothing on screen there is no list to keep still: the banner is for a list the user is reading.
  const newer = shown !== null && shown.length > 0 && pending.data !== undefined && !sameVersions(shown, pending.data);
  // The list itself rather than an error or nothing in its place: what "Approve all" and "Reject all" act on.
  const listing = !pending.isError && shown !== null && views.length > 0;
  const runningAll = running?.target === "all" ? running.decision : null;
  const only = (view: PendingApprovalView): ApprovalGroup[] => [{ spaceId: view.space_id, spaceName: view.space_name, views: [view] }];

  // What sits above the list, rendered from this one object. The buttons are off for a moment whenever any of it
  // appears, goes away or says something else, too: the lock paragraph clearing is the render that re-enables them
  // AND moves the list. Before the browser paints, so that render is never on screen with its buttons on.
  const above: AboveList = { lock, notice, newer: newer && !busy };
  const aboveBefore = useRef(above);
  useLayoutEffect(() => {
    if (listMoved(aboveBefore.current, above)) guard();
    aboveBefore.current = above;
  }, [above.lock, above.notice, above.newer]);

  /**
   * Puts a newer list on screen. Whatever differs from what was shown (a changed
   * version, a new host) is marked on its own card and named in the notice, together
   * with the hosts the backend skipped, so nothing changes unseen.
   */
  const adopt = (fresh: PendingApprovalView[], decided: PendingApprovalView[], skipped: HostRef[] = []) => {
    const adoption = adoptNewest(views, fresh, marks, decided);
    setShown(fresh);
    guard();
    setMarks(adoption.marks);
    setNotice(changedNotice([...skipped, ...adoption.changed], adoption.added));
  };

  // Hosts that arrive while nothing is on screen (the review opened with nothing waiting, or the last host was just
  // decided): there is no version to keep in place, so show them at once, marked new, rather than "Nothing is waiting"
  // beside "Newer versions arrived".
  useEffect(() => {
    if (shown !== null && pending.data !== undefined && isSettled(pending) && adoptAtOnce(shown, pending.data)) adopt(pending.data, []);
  }, [shown, pending.data, pending.isSuccess, pending.isFetching]);

  /**
   * One call per space with the versions on screen, then the newest list. Hosts
   * that changed while the review was open are left alone: say so, show their
   * newer version, marked. Stops at the first failure (the mutation toasts it).
   */
  const decide = async (decision: "approve" | "reject", batches: ApprovalGroup[], target: string) => {
    setRunning({ decision, target });
    setNotice(null);
    try {
      const results = await runDecision(batches, (spaceId, approvals) => (decision === "approve" ? approve : reject).mutateAsync({ spaceId, approvals }));
      const { applied, decided, changed } = combineOutcomes(results);
      const fresh = await pending.refetch();
      if (fresh.isSuccess) adopt(fresh.data, decided, changed);
      else setNotice(changedNotice(changed));
      if (target === "all") {
        const summary = decisionSummary(decision, applied, batches.reduce((n, b) => n + b.views.length, 0));
        if (summary) toast[summary.level](summary.text);
      }
    } finally {
      setRunning(null);
    }
  };

  return (
    <>
      <DialogHeader>
        <DialogTitle>Review synced hosts</DialogTitle>
        <DialogDescription>{REVIEW_INTRO}</DialogDescription>
      </DialogHeader>

      {above.lock && (
        <p className="rounded-md border border-amber-500/40 bg-amber-500/10 p-2 text-xs text-amber-800 dark:text-amber-300">
          Approving and rejecting are off right now. {above.lock}
        </p>
      )}
      {above.notice && (
        <p className="rounded-md border border-amber-500/40 bg-amber-500/10 p-2 text-xs text-amber-800 dark:text-amber-300">{above.notice}</p>
      )}
      {above.newer && (
        <div className="flex items-center justify-between gap-2 rounded-md border p-2 text-xs">
          <span>Newer versions arrived while this was open.</span>
          <Button
            type="button"
            variant="outline"
            size="sm"
            className="h-7"
            onClick={() => adopt(pending.data ?? [], [])}
          >
            Show them
          </Button>
        </div>
      )}

      {pending.isError ? (
        <p className="text-sm text-destructive">Could not load the hosts: {errorMessage(pending.error)}</p>
      ) : shown === null ? (
        <p className="text-sm text-muted-foreground">Loading…</p>
      ) : views.length === 0 ? (
        <p className="text-sm text-muted-foreground">Nothing is waiting for your approval.</p>
      ) : (
        <div className="max-h-[55vh] space-y-4 overflow-y-auto pr-1">
          {groups.map((g) => (
            <section key={g.spaceId} className="space-y-2">
              <p className="text-xs font-semibold tracking-wide text-muted-foreground uppercase">{revealHidden(g.spaceName)}</p>
              {g.views.map((view) => {
                const key = hostKey(view.space_id, view.alias);
                return (
                  <PendingHost
                    key={view.alias}
                    view={view}
                    hosts={hosts}
                    spaces={spaces}
                    mark={marks.get(key)}
                    running={running?.target === key ? running.decision : null}
                    busy={busy}
                    locked={lock !== null}
                    guarded={guarded}
                    onApprove={() => void decide("approve", only(view), key)}
                    onReject={() => void decide("reject", only(view), key)}
                  />
                );
              })}
            </section>
          ))}
        </div>
      )}

      <ReviewFooter
        count={listing ? views.length : 0}
        busy={busy}
        locked={lock !== null}
        guarded={guarded}
        runningAll={runningAll}
        onClose={onClose}
        onRejectAll={() => void decide("reject", groups, "all")}
        onApproveAll={() => void decide("approve", groups, "all")}
      />
    </>
  );
}

/**
 * "Reject all" and "Approve all" while more than one host is listed, then Close, which
 * stays at the right edge: hosts that arrive change what sits beside it, never what is
 * under a click aimed at it (that click would approve hosts nobody has read).
 * Exported for the markup tests.
 */
export function ReviewFooter({
  count,
  busy,
  locked,
  guarded,
  runningAll,
  onClose,
  onRejectAll,
  onApproveAll,
}: {
  /** How many hosts the all-hosts buttons would act on; 0 while no list is shown (loading, an error, nothing waiting). */
  count: number;
  busy: boolean;
  /** The account cannot take a decision now (`structureLock`): both all-hosts buttons are off. Close stays. */
  locked: boolean;
  /** The list was just replaced (`CLICK_GUARD_MS`): both all-hosts buttons are off for a moment. Close stays. */
  guarded: boolean;
  /** Which of the all-hosts buttons is running its decision (null: neither). */
  runningAll: "approve" | "reject" | null;
  onClose: () => void;
  onRejectAll: () => void;
  onApproveAll: () => void;
}) {
  return (
    <DialogFooter>
      {count > 1 && (
        <>
          <Button type="button" variant="outline" disabled={busy || locked || guarded} onClick={onRejectAll}>
            {runningAll === "reject" && <Loader2 className="size-4 animate-spin" />} Reject all
          </Button>
          <Button type="button" disabled={busy || locked || guarded} onClick={onApproveAll}>
            {runningAll === "approve" && <Loader2 className="size-4 animate-spin" />} Approve all ({count})
          </Button>
        </>
      )}
      <Button type="button" variant="outline" disabled={busy} onClick={onClose}>
        Close
      </Button>
    </DialogFooter>
  );
}

/**
 * One held host: where it came from, what approving changes (and which existing
 * hosts it would take over), the incoming block with the gated lines marked, and
 * the buttons. Exported for the markup tests.
 */
export function PendingHost({
  view,
  hosts,
  spaces,
  mark,
  running,
  busy,
  locked,
  guarded,
  onApprove,
  onReject,
}: {
  view: PendingApprovalView;
  /** The loaded config: which existing hosts approving would take over. */
  hosts: readonly ConfigHost[];
  /** The sync account's spaces in Include order (undefined while not loaded): which block ssh reads first. */
  spaces: readonly ReviewSpace[] | undefined;
  /** Set when this version is not the one the user first saw; stays until they decide on the host. */
  mark: VersionMark | undefined;
  /** Which of the two buttons is running its decision (null: neither). */
  running: "approve" | "reject" | null;
  busy: boolean;
  /** The account cannot take a decision now (`structureLock`): both buttons are off. */
  locked: boolean;
  /** The list was just replaced (`CLICK_GUARD_MS`): both buttons are off for a moment. */
  guarded: boolean;
  onApprove: () => void;
  onReject: () => void;
}) {
  return (
    <div className={cn("space-y-2 rounded-md border p-3", mark && "border-amber-500/60")}>
      <div className="flex items-start justify-between gap-3">
        <div className="min-w-0">
          <p className="flex items-center gap-1.5 font-mono text-sm">
            <ShieldAlert className="size-3.5 shrink-0 text-amber-600 dark:text-amber-400" aria-hidden />
            <span className={LOGICAL_ORDER}>{revealHidden(view.alias)}</span>
          </p>
          <p className={cn("text-xs text-muted-foreground", LOGICAL_ORDER)}>
            From {revealHidden(view.from_device)} · {relativeTime(view.updated_at_ms)}
          </p>
        </div>
        <div className="flex shrink-0 gap-1.5">
          <Button type="button" variant="outline" size="sm" className="h-7" disabled={busy || locked || guarded} onClick={onReject}>
            {running === "reject" && <Loader2 className="size-3.5 animate-spin" />} Reject
          </Button>
          <Button type="button" size="sm" className="h-7" disabled={busy || locked || guarded} onClick={onApprove}>
            {running === "approve" && <Loader2 className="size-3.5 animate-spin" />} Approve
          </Button>
        </div>
      </div>
      {mark && (
        <p className="rounded-md border border-amber-500/40 bg-amber-500/10 px-2 py-1 text-xs font-medium text-amber-800 dark:text-amber-300">
          {markText(mark)}
        </p>
      )}
      <ul className="list-disc space-y-0.5 pl-5 text-xs">
        {approvalChanges(view, hosts, spaces).map((change, i) => (
          <li key={i} className={cn("break-all whitespace-pre-wrap font-mono", LOGICAL_ORDER)}>
            {changeText(change)}
          </li>
        ))}
      </ul>
      <pre className="overflow-x-auto rounded-md bg-muted/40 p-2 font-mono text-xs leading-5" aria-label={`Incoming block for ${revealHidden(view.alias)}`}>
        {blockLines(view).map((line, i) => (
          <div key={i} className={cn(LOGICAL_ORDER, (line.gated || line.scope) && "-mx-1 rounded-sm bg-amber-500/15 px-1 text-amber-800 dark:text-amber-300")}>
            {line.text || " "}
          </div>
        ))}
      </pre>
      {view.current_text !== null && (
        <details className="text-xs">
          <summary className="cursor-default text-muted-foreground select-none">This computer's current version</summary>
          <pre className="mt-1 overflow-x-auto rounded-md bg-muted/40 p-2 font-mono leading-5">
            {displayLines(view.current_text).map((line, i) => (
              <div key={i} className={LOGICAL_ORDER}>
                {line || " "}
              </div>
            ))}
          </pre>
        </details>
      )}
    </div>
  );
}
