import { useId, useRef, useState, type KeyboardEvent } from "react";
import { Dialog, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { TaskDialogBody, TaskDialogContent } from "@/components/app/TaskDialog";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { revealHidden } from "@/lib/sync-approvals";
import { useNow } from "@/lib/use-now";
import { justificationAcceptable } from "@/lib/mcp-flow";
import {
  parentLabel,
  pamStatusLine,
  requestEntitlementGrant,
  requestPamGrant,
  type GrantMemoryView,
  type HostTransport,
  type PamEntitlementView,
  type PamStatusView,
} from "@/lib/transports";

const MAX_MINUTES = 480;
const MAX_JUSTIFICATION = 512;

/**
 * What the form starts with: what this computer remembers of its last request for the host, its justification and its length in minutes;
 * for a host this computer never asked a grant for, no justification and the route's default length (the route no longer carries a
 * justification, so one an earlier release saved there is not offered).
 */
export function grantRequestDefaults(transport: HostTransport, memory: GrantMemoryView | null): { justification: string; minutes: string } {
  if (memory) return { justification: memory.justification, minutes: String(Math.round(memory.duration_secs / 60)) };
  return { justification: "", minutes: String(Math.round((transport.kind.pam?.duration_secs ?? 1800) / 60)) };
}

/** Whether Request may go: whole minutes from 1 to `max` (480 at most) and a justification the backend accepts (one line, no control characters). */
export function grantRequestReady(justification: string, minutes: string, max = MAX_MINUTES): boolean {
  const whole = /^\d+$/.test(minutes.trim()) ? Number(minutes.trim()) : NaN;
  return justificationAcceptable(justification) && whole >= 1 && whole <= Math.min(max, MAX_MINUTES);
}

/** The most minutes a request on an entitlement may ask for: its own maximum when the search said, within Lunport's 480. */
export const maxMinutesOf = (row: Pick<PamEntitlementView, "max_duration_secs">) =>
  row.max_duration_secs === null ? MAX_MINUTES : Math.max(1, Math.min(MAX_MINUTES, Math.floor(row.max_duration_secs / 60)));

/** What a request on an entitlement starts from: the library's memory of its last request, else its default length (design 2026-10-27). */
export function entitlementRequestDefaults(row: PamEntitlementView): { justification: string; minutes: string } {
  const max = maxMinutesOf(row);
  if (row.memory) return { justification: row.memory.justification, minutes: String(Math.min(max, Math.round(row.memory.duration_secs / 60))) };
  return { justification: "", minutes: String(Math.min(max, Math.round(row.default_duration_secs / 60))) };
}

/** What the dialog says once a request waits for an approver. */
export const AWAITING_APPROVER = "Requested. The grant becomes active once an approver approves it.";

/**
 * What Request sends: the grant on `entitlement` (the route's first when none is named, which the backend picks) for the minutes typed,
 * with the justification trimmed.
 */
export function requestGrant(transport: HostTransport, entitlement: string | undefined, justification: string, minutes: string): Promise<PamStatusView> {
  return requestPamGrant(transport.host_id, justification.trim(), Number(minutes.trim()) * 60, entitlement);
}

export type GrantRequestCardViewProps = {
  /** The host's route the request goes through (a host's details); left out for a request on an entitlement (the Access tab). */
  transport?: HostTransport;
  /** The entitlement the request is for; the route's first when left out. */
  entitlement?: string;
  /** The host's alias, with `transport`. */
  alias?: string;
  /** What a request on an entitlement is for, in place of the host: where the entitlement lives and the account requesting it. */
  subject?: { parent: string; account: string | null };
  /** The most minutes the form takes: the entitlement's own maximum when known, else 480. */
  maxMinutes?: number;
  justification: string;
  minutes: string;
  busy: boolean;
  result: PamStatusView | null;
  error: string | null;
  onJustification: (value: string) => void;
  onMinutes: (value: string) => void;
  onRequest: () => void;
  onClose: () => void;
};

/** The dialog's content, apart from its state: rendered inside a `Dialog` (the tests render it in one without the portal). */
export function GrantRequestCardView({ transport, entitlement: named, alias, subject, maxMinutes = MAX_MINUTES, justification, minutes, busy, result, error, onJustification, onMinutes, onRequest, onClose }: GrantRequestCardViewProps) {
  const now = useNow(1000);
  const justificationId = useId();
  const minutesId = useId();
  const ready = !busy && result === null && grantRequestReady(justification, minutes, maxMinutes);
  const entitlement = named ?? transport?.kind.pam?.entitlements[0] ?? "";
  const account = (subject ? subject.account : transport?.kind.account) ?? "gcloud's active account";
  const what = subject ? `${entitlement} (${parentLabel(subject.parent)})` : `${entitlement} for ${revealHidden(alias ?? "")}`;
  const requestOnEnter = (event: KeyboardEvent<HTMLInputElement>) => {
    if (event.key !== "Enter") return;
    event.preventDefault();
    if (!event.nativeEvent.isComposing && ready) onRequest();
  };
  return (
    <>
      <DialogHeader>
        <DialogTitle>Request a grant</DialogTitle>
        <DialogDescription>
          A Privileged Access Manager grant on {what}, requested as {account}. Lunport waits until it is active, or until it waits for an approver; the entitlement's own maximum applies.
        </DialogDescription>
      </DialogHeader>
      <TaskDialogBody>
        <div className="space-y-3 text-sm">
          <div className="space-y-1">
            <Label htmlFor={justificationId}>Justification</Label>
            <Input
              id={justificationId}
              autoFocus
              value={justification}
              maxLength={MAX_JUSTIFICATION}
              autoComplete="off"
              disabled={busy || result !== null}
              onChange={(event) => onJustification(event.target.value)}
              onKeyDown={requestOnEnter}
            />
          </div>
          <div className="space-y-1">
            <Label htmlFor={minutesId}>Duration (minutes)</Label>
            <Input
              id={minutesId}
              type="number"
              inputMode="numeric"
              min={1}
              max={maxMinutes}
              step={1}
              className="w-28"
              value={minutes}
              disabled={busy || result !== null}
              onChange={(event) => onMinutes(event.target.value)}
              onKeyDown={requestOnEnter}
            />
          </div>
          {busy && <p role="status" className="text-xs text-muted-foreground">Requesting the grant and waiting for it to become active…</p>}
          {result && <p role="status" className="text-xs">{result.state === "approval_awaited" ? AWAITING_APPROVER : pamStatusLine(result, now)}</p>}
          {error && <p role="alert" className="text-xs text-destructive">{error}</p>}
        </div>
      </TaskDialogBody>
      <DialogFooter>
        <Button variant="outline" disabled={busy} onClick={onClose}>
          {result ? "Close" : "Cancel"}
        </Button>
        {result === null && (
          <Button disabled={!ready} onClick={onRequest}>
            {busy ? "Requesting…" : "Request"}
          </Button>
        )}
      </DialogFooter>
    </>
  );
}

/**
 * The Request-a-grant dialog (design 2026-10-25, PAM grant requests; 2026-10-26, Commands): a justification and a duration, prefilled
 * from what this computer remembers of its last request for the host (`memory`), else the route's default length; requested on
 * `entitlement`, else the route's first as the connect would; the grant's state, or the refusal, shows inside once Lunport has waited
 * for it. Mount it for one request at a time, keyed by what the request is for, so another starts afresh: the details pane keys the
 * section that holds it by the host, the Google Cloud page keys the dialog by the row (account, project, location and entitlement).
 */
export function GrantRequestDialog({ transport, entitlement, memory, alias, onClose, onRequested }: {
  transport: HostTransport;
  /** The entitlement to request, one the route lists; the route's first when left out. */
  entitlement?: string;
  /** This computer's memory of its last request for the host; `null` when it made none. */
  memory: GrantMemoryView | null;
  alias: string;
  onClose: () => void;
  onRequested: (view: PamStatusView) => void;
}) {
  const defaults = grantRequestDefaults(transport, memory);
  const [justification, setJustification] = useState(defaults.justification);
  const [minutes, setMinutes] = useState(defaults.minutes);
  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState<PamStatusView | null>(null);
  const [error, setError] = useState<string | null>(null);
  const flight = useRef(false);

  const request = async () => {
    if (busy || result !== null || !grantRequestReady(justification, minutes) || flight.current) return;
    flight.current = true;
    setBusy(true);
    setError(null);
    try {
      const view = await requestGrant(transport, entitlement, justification, minutes);
      setResult(view);
      onRequested(view);
    } catch (failure) {
      setError(revealHidden(failure instanceof Error ? failure.message : String(failure)));
    } finally {
      flight.current = false;
      setBusy(false);
    }
  };

  return (
    <Dialog open onOpenChange={(open) => { if (!open && !busy) onClose(); }}>
      <TaskDialogContent className="sm:max-w-lg">
        <GrantRequestCardView
          transport={transport}
          entitlement={entitlement}
          alias={alias}
          justification={justification}
          minutes={minutes}
          busy={busy}
          result={result}
          error={error}
          onJustification={setJustification}
          onMinutes={setMinutes}
          onRequest={() => void request()}
          onClose={onClose}
        />
      </TaskDialogContent>
    </Dialog>
  );
}

/**
 * The Request-a-grant dialog of the Access tab (design 2026-10-27): a request on the entitlement of `row`, as its account, prefilled from
 * the library's memory of its last request, else its default length, and capped by its own maximum. Mount it for one request at a time,
 * keyed by the row, so another starts afresh.
 */
export function EntitlementGrantDialog({ row, onClose, onRequested }: { row: PamEntitlementView; onClose: () => void; onRequested: (view: PamStatusView) => void }) {
  const defaults = entitlementRequestDefaults(row);
  const maxMinutes = maxMinutesOf(row);
  const [justification, setJustification] = useState(defaults.justification);
  const [minutes, setMinutes] = useState(defaults.minutes);
  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState<PamStatusView | null>(null);
  const [error, setError] = useState<string | null>(null);
  const flight = useRef(false);

  const request = async () => {
    if (busy || result !== null || !grantRequestReady(justification, minutes, maxMinutes) || flight.current) return;
    flight.current = true;
    setBusy(true);
    setError(null);
    try {
      const view = await requestEntitlementGrant(row.account, row.name, justification.trim(), Number(minutes.trim()) * 60);
      setResult(view);
      onRequested(view);
    } catch (failure) {
      setError(revealHidden(failure instanceof Error ? failure.message : String(failure)));
    } finally {
      flight.current = false;
      setBusy(false);
    }
  };

  return (
    <Dialog open onOpenChange={(open) => { if (!open && !busy) onClose(); }}>
      <TaskDialogContent className="sm:max-w-lg">
        <GrantRequestCardView
          entitlement={row.entitlement}
          subject={{ parent: row.parent, account: row.account }}
          maxMinutes={maxMinutes}
          justification={justification}
          minutes={minutes}
          busy={busy}
          result={result}
          error={error}
          onJustification={setJustification}
          onMinutes={setMinutes}
          onRequest={() => void request()}
          onClose={onClose}
        />
      </TaskDialogContent>
    </Dialog>
  );
}
