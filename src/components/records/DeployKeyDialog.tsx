import { useEffect, useRef, useState } from "react";
import { Button } from "@/components/ui/button";
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { cancelRecordDeploy, confirmRecordDeploy, previewRecordDeploy, type RecordDeployPreview, type RecordDeployResult, type RecordOverview } from "@/lib/records";
import { deploymentMessage } from "@/lib/records-deploy";
import { revealHidden } from "@/lib/sync-approvals";
import { RecordField, selectClass } from "./form";

export function RecordsDeployKeyDialog({ overview, keyId, onClose }: {
  overview: RecordOverview; keyId: string; onClose: () => void;
}) {
  const [hostId, setHostId] = useState("");
  const [preview, setPreview] = useState<RecordDeployPreview | null>(null);
  const [authorized, setAuthorized] = useState(false);
  const [phase, setPhase] = useState<"idle" | "previewing" | "running" | "canceling">("idle");
  const [result, setResult] = useState<RecordDeployResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const current = useRef<string | null>(null);
  const revision = useRef(0);
  const inFlight = useRef(false);
  useEffect(() => () => {
    revision.current++;
    if (current.current) void cancelRecordDeploy(current.current).catch(() => {});
  }, []);
  const discard = () => {
    revision.current++;
    if (current.current) void cancelRecordDeploy(current.current).catch(() => {});
    current.current = null;
    setPreview(null); setAuthorized(false); setResult(null); setError(null);
  };
  const refresh = async () => {
    if (inFlight.current || !hostId) return;
    discard();
    const rev = revision.current;
    inFlight.current = true; setPhase("previewing");
    try {
      const next = await previewRecordDeploy(hostId, keyId);
      if (rev !== revision.current) { await cancelRecordDeploy(next.id); return; }
      current.current = next.id; setPreview(next);
    } catch {
      if (rev === revision.current) setError("A public preview is unavailable. Refresh the workspace and check the saved host and key.");
    } finally {
      inFlight.current = false;
      if (rev === revision.current) setPhase("idle");
    }
  };
  const deploy = async () => {
    if (inFlight.current || !preview || !authorized) return;
    inFlight.current = true; setPhase("running"); setError(null); setResult(null);
    try { setResult(await confirmRecordDeploy(preview.id, true)); }
    catch { setError("The deployment result could not be received. Installation may have started; inspect the remote account before trying again."); }
    finally { inFlight.current = false; current.current = null; setPhase("idle"); setAuthorized(false); }
  };
  const cancel = async () => {
    if (!current.current || phase === "canceling") return;
    setPhase("canceling");
    try { await cancelRecordDeploy(current.current); }
    catch { setError("Cancellation could not be sent. Keep this window open until the operation ends."); setPhase("running"); }
  };
  const busy = phase !== "idle";
  return <Dialog open onOpenChange={(open) => { if (!open && !busy) onClose(); }}>
    <DialogContent className="sm:max-w-xl overflow-hidden" showCloseButton={!busy}
      onEscapeKeyDown={(event) => { if (busy) event.preventDefault(); }}
      onInteractOutside={(event) => event.preventDefault()}>
      <RecordsDeployContent overview={overview} hostId={hostId} preview={preview} authorized={authorized} phase={phase} result={result} error={error}
        onHostChange={(id) => { discard(); setHostId(id); }} onRefresh={refresh} onAuthorize={setAuthorized} onDeploy={deploy} onCancel={cancel} onClose={onClose} />
    </DialogContent>
  </Dialog>;
}

export function RecordsDeployContent({ overview, hostId, preview, authorized, phase, result, error, onHostChange, onRefresh, onAuthorize, onDeploy, onCancel, onClose }: {
  overview: RecordOverview; hostId: string; preview: RecordDeployPreview | null;
  authorized: boolean; phase: "idle" | "previewing" | "running" | "canceling";
  result: RecordDeployResult | null; error: string | null;
  onHostChange: (id: string) => void; onRefresh: () => void; onAuthorize: (value: boolean) => void;
  onDeploy: () => void; onCancel: () => void; onClose: () => void;
}) {
  const running = phase === "running" || phase === "canceling";
  const busy = phase !== "idle";
  return <div className="flex min-h-0 max-h-[calc(100dvh-4rem)] flex-col gap-4 overflow-hidden">
      <DialogHeader className="shrink-0">
        <DialogTitle>Deploy public key</DialogTitle>
        <DialogDescription>Install a public key in a saved host's remote account. The account must have a POSIX shell and standard POSIX utilities. Remote Windows installation is unsupported; Windows clients can deploy to POSIX hosts.</DialogDescription>
      </DialogHeader>
      <section aria-label="Deployment details" className="min-h-0 flex-1 space-y-4 overflow-y-auto pr-1">
      <RecordField label="Saved target">
        <select className={selectClass} value={hostId} disabled={busy} onChange={(event) => onHostChange(event.target.value)}>
          <option value="">Choose a saved host</option>
          {overview.hosts.map((host) => <option key={host.id} value={host.id} disabled={!!host.group_error || host.readiness.kind !== "ready"}>
            {revealHidden(host.payload.alias)} — {revealHidden(host.effective_payload.hostname)}
          </option>)}
        </select>
      </RecordField>
      <Button variant="outline" disabled={!hostId || busy} onClick={onRefresh}>{phase === "previewing" ? "Loading preview…" : preview ? "Refresh preview" : "Preview deployment"}</Button>
      {preview && <section className="min-w-0 space-y-3 rounded-md border p-3" aria-label="Reviewed deployment">
        <div><p className="text-xs text-muted-foreground">Effective destination</p><p className="break-all font-mono text-sm">{revealHidden(preview.user)}@{revealHidden(preview.hostname)}:{preview.port}</p></div>
        <div><p className="text-xs text-muted-foreground">{revealHidden(preview.key_name)} · Public-key fingerprint</p><p className="break-all font-mono text-xs">{preview.fingerprint}</p></div>
        <div><p className="text-xs text-muted-foreground">Connection route</p><ol className="list-decimal space-y-1 pl-5 text-xs">{preview.route.map((hop, i) => <li className="break-all" key={i}>{revealHidden(hop)}</li>)}</ol></div>
        <p className="text-xs text-muted-foreground">Writes only this public key to ~/.ssh/authorized_keys. Existing entries and key restrictions are preserved. Saved host authentication settings and AI Access permissions remain unchanged.</p>
      </section>}
      </section>
      <footer aria-label="Deployment actions" className="shrink-0 space-y-3 border-t pt-3">
      {preview && !result && !error && <label className="flex items-start gap-2 text-sm">
        <input type="checkbox" className="mt-1" checked={authorized} disabled={busy} onChange={(event) => onAuthorize(event.target.checked)} />
        <span>I am authorized to install this public key on the account and destination shown above.</span>
      </label>}
      {running && <p role="status" className="text-sm">{phase === "canceling" ? "Canceling the connection and remote operation…" : "Connecting and installing… Authentication or server identity questions may open in a separate window."}</p>}
      {result && <p role="status" className={`text-sm ${["added", "already_present"].includes(result.outcome) && !result.audit_error ? "" : "text-amber-600 dark:text-amber-400"}`}>{deploymentMessage(result)}</p>}
      {error && <p role="alert" className="text-sm text-destructive">{error}</p>}
      <div className="flex flex-wrap justify-end gap-2">
        {running ? <Button variant="outline" disabled={phase === "canceling"} onClick={onCancel}>{phase === "canceling" ? "Canceling…" : "Cancel deployment"}</Button>
        : <><Button variant="outline" disabled={busy} onClick={onClose}>Close</Button><Button disabled={busy || !preview || !authorized || !!result || !!error} onClick={onDeploy}>Confirm deployment</Button></>}
      </div>
      </footer>
  </div>;
}
