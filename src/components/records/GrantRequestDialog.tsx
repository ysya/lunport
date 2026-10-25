import { useId, useRef, useState, type KeyboardEvent } from "react";
import { Dialog, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { TaskDialogBody, TaskDialogContent } from "@/components/app/TaskDialog";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { revealHidden } from "@/lib/sync-approvals";
import { pamStatusLine, requestPamGrant, type HostTransport, type PamStatusView } from "@/lib/transports";

const MAX_MINUTES = 480;
const MAX_JUSTIFICATION = 512;

/** What the form starts with: the transport's last justification and its default duration, in minutes. */
export function grantRequestDefaults(transport: HostTransport): { justification: string; minutes: string } {
  const pam = transport.kind.pam;
  return { justification: pam?.justification ?? "", minutes: String(Math.round((pam?.duration_secs ?? 1800) / 60)) };
}

/** Whether Request may go: whole minutes from 1 to 480 and a justification with something in it, as the backend checks too. */
export function grantRequestReady(justification: string, minutes: string): boolean {
  const whole = /^\d+$/.test(minutes.trim()) ? Number(minutes.trim()) : NaN;
  const words = justification.trim().length;
  return words > 0 && words <= MAX_JUSTIFICATION && whole >= 1 && whole <= MAX_MINUTES;
}

export type GrantRequestCardViewProps = {
  transport: HostTransport;
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
export function GrantRequestCardView({ transport, alias, justification, minutes, busy, result, error, onJustification, onMinutes, onRequest, onClose }: GrantRequestCardViewProps) {
  const justificationId = useId();
  const minutesId = useId();
  const ready = !busy && result === null && grantRequestReady(justification, minutes);
  const entitlement = transport.kind.pam?.entitlements[0] ?? "";
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
 * The Google Cloud panel's Request-a-grant dialog (design 2026-10-25, PAM grant requests): a justification and a duration, prefilled
 * from the transport's defaults, requested on the transport's first entitlement as the connect would; the grant's state, or the refusal,
 * shows inside once Lunport has waited for it. Mount it for one transport at a time (key it by the host).
 */
export function GrantRequestDialog({ transport, alias, onClose, onRequested }: {
  transport: HostTransport;
  alias: string;
  onClose: () => void;
  onRequested: (view: PamStatusView) => void;
}) {
  const defaults = grantRequestDefaults(transport);
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
      const view = await requestPamGrant(transport.host_id, justification.trim(), Number(minutes.trim()) * 60);
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
