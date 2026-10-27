import { useEffect, useRef, useState } from "react";
import { Activity, LoaderCircle } from "lucide-react";
import { Button } from "@/components/ui/button";
import { probeRecordHost, type RecordHostView, type ConnectionProbe } from "@/lib/records";
import { errorMessage } from "@/lib/sync";
import { revealHidden } from "@/lib/sync-approvals";
import { probeIap, type HostTransport, type IapProbeView } from "@/lib/transports";

export function probeLabel(result: ConnectionProbe): string {
  switch (result.status) {
    case "reachable": return `Port reachable${result.latency_ms === null ? "" : ` · ${result.latency_ms} ms`}`;
    case "refused": return "Connection refused";
    case "timed_out": return "Connection timed out";
    case "dns_failed": return "Could not resolve this address";
    case "requires_jump": return "Uses a jump host";
    case "settings_changed": return "Connection settings changed — check again";
    default: return "Could not reach this port";
  }
}

/** What Check through IAP found: the sentence the backend gave when IAP refused the account or the instance did not answer, else the time it took. */
export function iapProbeLabel(result: IapProbeView): string {
  switch (result.status) {
    case "reachable": return `Reachable through IAP${result.latency_ms === null ? "" : ` · ${result.latency_ms} ms`}`;
    case "denied": return revealHidden(result.message ?? "IAP refused this Google account.");
    default: return revealHidden(result.message ?? "Could not reach the instance's port through IAP.");
  }
}

/** What a check found, as the pane words it. */
export type CheckOutcome = { label: string; reachable: boolean; checkedAtMs: number; elapsedMs: number; viaJump: boolean };

/** Runs the check a host's button starts: through IAP when the host has a route, else at its saved TCP port. */
export async function runCheck(host: RecordHostView, route: HostTransport | null): Promise<CheckOutcome> {
  if (route) {
    const found = await probeIap(host.id);
    return { label: iapProbeLabel(found), reachable: found.status === "reachable", checkedAtMs: found.checked_at_ms, elapsedMs: found.elapsed_ms, viaJump: false };
  }
  const found = await probeRecordHost(host.id);
  return { label: probeLabel(found), reachable: found.status === "reachable", checkedAtMs: found.checked_at_ms, elapsedMs: found.elapsed_ms, viaJump: found.status === "requires_jump" };
}

/**
 * What a check's result is about; the result goes when this changes. The port check answers with the address it tried, but the IAP
 * check's answer names no host, so the host and its route are part of it, as the hostname and port are.
 */
export function checkTarget(host: RecordHostView, route: HostTransport | null | undefined): string {
  const { hostname, port, jump } = host.effective_payload;
  return JSON.stringify([host.id, hostname, port, jump, route?.kind ?? null]);
}

export type ConnectionCheckViewProps = {
  /** The host's route: the check goes through IAP when it has one, else to the saved TCP port. */
  route: HostTransport | null;
  groupError: boolean;
  busy: boolean;
  outcome: CheckOutcome | null;
  error: string | null;
  onCheck: () => void;
};

/** The Connection check section, apart from its state. */
export function ConnectionCheckView({ route, groupError, busy, outcome, error, onCheck }: ConnectionCheckViewProps) {
  return <div className="library-preview-section">
    <h3><Activity className="size-3.5" />Connection check</h3>
    <p className="text-xs text-muted-foreground">
      {route
        ? "Check whether this computer reaches the instance's port through IAP with its Google sign-in. Login and server identity are verified separately."
        : "Check whether the saved TCP port can be reached from this computer. Login and server identity are verified separately."}
    </p>
    <Button variant="outline" size="sm" className="mt-3" disabled={busy || groupError} onClick={onCheck}>
      {busy && <LoaderCircle className="size-3.5 animate-spin" />}{busy ? "Checking…" : route ? "Check through IAP" : "Check port"}
    </Button>
    {outcome && <div role="status" className="mt-3 space-y-1 text-xs">
      <p className={outcome.reachable ? "text-primary" : "text-muted-foreground"}>{outcome.label}</p>
      <p className="text-muted-foreground">Checked {new Date(outcome.checkedAtMs).toLocaleTimeString()} · {outcome.elapsedMs} ms total</p>
      {outcome.viaJump && <p className="text-muted-foreground">Use “Verify fingerprint” in server identity management to check through the configured jump route.</p>}
    </div>}
    {error && <p role="alert" className="mt-3 text-xs text-destructive break-words">{error}</p>}
  </div>;
}

export function ConnectionCheck({host, transport}: {host: RecordHostView; transport?: HostTransport | null}) {
  const route = transport ?? null;
  const target = checkTarget(host, route);
  const [outcome, setOutcome] = useState<CheckOutcome | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const request = useRef(0);
  useEffect(() => {
    request.current++; setOutcome(null); setError(null); setBusy(false);
    return () => { request.current++; };
  }, [target]);
  const check = async () => {
    if (busy) return;
    const id = ++request.current;
    setBusy(true); setError(null);
    try {
      const checked = await runCheck(host, route);
      if (id === request.current) setOutcome(checked);
    } catch (e) {
      if (id === request.current) setError(revealHidden(errorMessage(e)));
    } finally {
      if (id === request.current) setBusy(false);
    }
  };
  return <ConnectionCheckView route={route} groupError={!!host.group_error} busy={busy} outcome={outcome} error={error} onCheck={() => void check()} />;
}
