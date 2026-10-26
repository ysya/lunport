import { useId, useRef, useState, type KeyboardEvent } from "react";
import { Dialog, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { TaskDialogBody, TaskDialogContent } from "@/components/app/TaskDialog";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { revealHidden } from "@/lib/sync-approvals";
import { justificationAcceptable } from "@/lib/mcp-flow";
import { pamStatusLine, requestPamGrant, type GrantMemoryView, type HostTransport, type PamStatusView } from "@/lib/transports";

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

/** Whether Request may go: whole minutes from 1 to 480 and a justification the backend accepts (one line, no control characters). */
export function grantRequestReady(justification: string, minutes: string): boolean {
  const whole = /^\d+$/.test(minutes.trim()) ? Number(minutes.trim()) : NaN;
  return justificationAcceptable(justification) && whole >= 1 && whole <= MAX_MINUTES;
}

/**
 * What Request sends: the grant on `entitlement` (the route's first when none is named, which the backend picks) for the minutes typed,
 * with the justification trimmed.
 */
export function requestGrant(transport: HostTransport, entitlement: string | undefined, justification: string, minutes: string): Promise<PamStatusView> {
  return requestPamGrant(transport.host_id, justification.trim(), Number(minutes.trim()) * 60, entitlement);
}

export type GrantRequestCardViewProps = {
  transport: HostTransport;
  /** The entitlement the request is for; the route's first when left out. */
  entitlement?: string;
  alias: string;
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
export function GrantRequestCardView({ transport, entitlement: named, alias, justification, minutes, busy, result, error, onJustification, onMinutes, onRequest, onClose }: GrantRequestCardViewProps) {
  const justificationId = useId();
  const minutesId = useId();
  const ready = !busy && result === null && grantRequestReady(justification, minutes);
  const entitlement = named ?? transport.kind.pam?.entitlements[0] ?? "";
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
          A Privileged Access Manager grant on {entitlement} for {revealHidden(alias)}, requested as {transport.kind.account ?? "gcloud's active account"}. Lunport waits until it is active; the entitlement's own maximum applies.
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
              max={MAX_MINUTES}
              step={1}
              className="w-28"
              value={minutes}
              disabled={busy || result !== null}
              onChange={(event) => onMinutes(event.target.value)}
              onKeyDown={requestOnEnter}
            />
          </div>
          {busy && <p role="status" className="text-xs text-muted-foreground">Requesting the grant and waiting for it to become active…</p>}
          {result && <p role="status" className="text-xs">{pamStatusLine(result)}</p>}
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
 * for it. Mount it for one transport at a time (key it by the host).
 */
export function GrantRequestDialog({ transport, entitlement, memory = null, alias, onClose, onRequested }: {
  transport: HostTransport;
  /** The entitlement to request, one the route lists; the route's first when left out. */
  entitlement?: string;
  /** This computer's memory of its last request for the host, if it made one. */
  memory?: GrantMemoryView | null;
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
