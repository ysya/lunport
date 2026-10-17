import { useEffect, useRef, useState } from "react";
import { Activity, LoaderCircle } from "lucide-react";
import { Button } from "@/components/ui/button";
import { probeRecordHost, type RecordHostView, type ConnectionProbe } from "@/lib/records";
import { errorMessage } from "@/lib/sync";
import { revealHidden } from "@/lib/sync-approvals";

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

export function ConnectionCheck({host}: {host: RecordHostView}) {
  const target = JSON.stringify([host.id, host.effective_payload.hostname, host.effective_payload.port, host.effective_payload.jump]);
  const [result, setResult] = useState<ConnectionProbe | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const request = useRef(0);
  useEffect(() => {
    request.current++; setResult(null); setError(null); setBusy(false);
    return () => { request.current++; };
  }, [target]);
  const check = async () => {
    if (busy) return;
    const id = ++request.current;
    setBusy(true); setError(null);
    try {
      const checked = await probeRecordHost(host.id);
      if (id === request.current) setResult(checked);
    } catch (e) {
      if (id === request.current) setError(revealHidden(errorMessage(e)));
    } finally {
      if (id === request.current) setBusy(false);
    }
  };
  return <div className="library-preview-section">
    <h3><Activity className="size-3.5" />Connection check</h3>
    <p className="text-xs text-muted-foreground">Check whether the saved TCP port can be reached from this computer. Login and server identity are verified separately.</p>
    <Button variant="outline" size="sm" className="mt-3" disabled={busy || !!host.group_error} onClick={() => void check()}>
      {busy && <LoaderCircle className="size-3.5 animate-spin" />}{busy ? "Checking…" : "Check port"}
    </Button>
    {result && <div role="status" className="mt-3 space-y-1 text-xs">
      <p className={result.status === "reachable" ? "text-primary" : "text-muted-foreground"}>{probeLabel(result)}</p>
      <p className="text-muted-foreground">Checked {new Date(result.checked_at_ms).toLocaleTimeString()} · {result.elapsed_ms} ms total</p>
      {result.status === "requires_jump" && <p className="text-muted-foreground">Use “Verify fingerprint” in server identity management to check through the configured jump route.</p>}
    </div>}
    {error && <p role="alert" className="mt-3 text-xs text-destructive break-words">{error}</p>}
  </div>;
}
