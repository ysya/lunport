import { useState, type ReactNode } from "react";
import { useQueryClient } from "@tanstack/react-query";
import { Copy, ShieldCheck, Trash2 } from "lucide-react";
import { toast } from "sonner";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import { Dialog, DialogTrigger, DialogHeader, DialogTitle, DialogDescription, DialogFooter, DialogClose } from "@/components/ui/dialog";
import { TaskDialogContent, TaskDialogBody } from "@/components/app/TaskDialog";
import { AlertDialog, AlertDialogTrigger, AlertDialogContent, AlertDialogHeader, AlertDialogTitle, AlertDialogDescription, AlertDialogFooter, AlertDialogCancel, AlertDialogAction } from "@/components/ui/alert-dialog";
import { Tabs, TabsList, TabsTrigger, TabsContent } from "@/components/ui/tabs";
import { KnownHostsFilePanel } from "@/components/KnownHostsDialog";
import { applyRecordOverview, forgetRecordHostKey, verifyRecordHostKey, recordsStatusKey, type RecordOverview, type RecordHostView } from "@/lib/records";
import { revealHidden } from "@/lib/sync-approvals";
import { errorMessage } from "@/lib/sync";
import { copyText } from "@/lib/clipboard";
import { pinnedOn } from "@/lib/hostkey";

export function KnownHostsManager({ overview, hostId, trigger }: {
  overview: RecordOverview; hostId?: string; trigger?: ReactNode;
}) {
  const [open, setOpen] = useState(false);
  return <Dialog open={open} onOpenChange={setOpen}>
    <DialogTrigger asChild>{trigger ?? <Button variant="outline" size="sm"><ShieldCheck className="size-3.5" />Manage known hosts…</Button>}</DialogTrigger>
    <TaskDialogContent className="sm:max-w-2xl">
      <DialogHeader><DialogTitle>Known hosts</DialogTitle><DialogDescription>Review the server identities you have trusted in Lunport and OpenSSH.</DialogDescription></DialogHeader>
      <TaskDialogBody>{open && <KnownHostsContent overview={overview} hostId={hostId} />}</TaskDialogBody>
      <DialogFooter><DialogClose asChild><Button variant="outline">Close</Button></DialogClose></DialogFooter>
    </TaskDialogContent>
  </Dialog>;
}

function KnownHostsContent({ overview, hostId }: {overview:RecordOverview; hostId?:string}) {
  const client = useQueryClient();
  const [query, setQuery] = useState("");
  const [onlyHost, setOnlyHost] = useState(!!hostId);
  const [busy, setBusy] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const q = query.trim().toLowerCase();
  const hosts = overview.hosts.filter((host) => {
    if (onlyHost && host.id !== hostId) return false;
    if (!host.payload.host_key && host.id !== hostId) return false;
    const pin = host.payload.host_key;
    return !q || `${host.payload.alias} ${host.effective_payload.hostname} ${host.effective_payload.port} ${pin?.algorithm ?? ""} ${pin?.fingerprint ?? ""}`.toLowerCase().includes(q);
  }).sort((a,b) => a.payload.alias.localeCompare(b.payload.alias));
  async function run(host: RecordHostView, action: () => Promise<RecordOverview>) {
    if (busy) return;
    setBusy(host.id); setError(null);
    try { applyRecordOverview(client, await action()); }
    catch (e) { setError(revealHidden(errorMessage(e))); void client.invalidateQueries({queryKey:recordsStatusKey}); }
    finally { setBusy(null); }
  }
  return <Tabs defaultValue="lunport" className="min-w-0 space-y-4">
    <TabsList><TabsTrigger value="lunport">Lunport identities</TabsTrigger><TabsTrigger value="openssh">OpenSSH known_hosts</TabsTrigger></TabsList>
    <TabsContent value="lunport" className="space-y-4">
      <p className="text-xs text-muted-foreground">Saved server fingerprints used by Lunport’s SSH client. Identities for shared hosts sync to your computers; local hosts stay on this computer.</p>
      <div className="flex items-center gap-2"><Input value={query} onChange={(e) => setQuery(e.target.value)} placeholder="Search host, fingerprint or key type…" aria-label="Search Lunport known hosts" spellCheck={false} />
        {onlyHost && <Button variant="outline" size="sm" onClick={() => setOnlyHost(false)}>Show all</Button>}</div>
      {error && <p role="alert" className="text-sm text-destructive break-words">{error}</p>}
      {!hosts.length ? <p className="app-task-state">{q ? "No matching identities." : "No saved server identities."}</p>
        : <div className="settings-group">{hosts.map((host) => <TrustedHostRow key={host.id} host={host}
            disabled={!!busy || host.scope.kind === "space" && overview.shared_writes_blocked}
            verifying={busy === host.id}
            forget={() => void run(host, () => forgetRecordHostKey(host))}
            verify={() => void run(host, async () => (await verifyRecordHostKey(host.id)).overview)} />)}</div>}
    </TabsContent>
    <TabsContent value="openssh" className="space-y-4"><KnownHostsFilePanel /></TabsContent>
  </Tabs>;
}

export function TrustedHostRow({host, disabled, verifying, forget, verify}: {
  host:RecordHostView; disabled:boolean; verifying:boolean; forget:()=>void; verify:()=>void;
}) {
  const pin = host.payload.host_key;
  const label = revealHidden(host.payload.alias);
  const address = host.effective_payload.hostname.includes(":") ? `[${host.effective_payload.hostname}]` : host.effective_payload.hostname;
  return <div className="space-y-3 px-4 py-3">
    <div className="flex min-w-0 items-start justify-between gap-3">
      <div className="min-w-0"><p className="font-medium break-all">{label}</p><p className="font-mono text-xs text-muted-foreground break-all">{revealHidden(address)}:{host.effective_payload.port}</p></div>
      <Badge variant="outline" className="shrink-0">{host.scope.kind === "space" ? "Synced host" : "Local host"}</Badge>
    </div>
    {pin ? <>
      <p className="font-mono text-xs text-muted-foreground">{revealHidden(pin.algorithm)}</p>
      <p className="font-mono text-xs break-all select-text">{revealHidden(pin.fingerprint)}</p>
      <p className="text-xs text-muted-foreground">Verified {pinnedOn(pin.pinned_at_ms)} · Device <span title={revealHidden(pin.pinned_by_device_id)}>{revealHidden(pin.pinned_by_device_id.slice(0,8))}</span></p>
    </> : <p className="text-xs text-muted-foreground">No server key has been verified yet.</p>}
    <div className="flex flex-wrap items-center gap-2">
      <Button variant="outline" size="sm" disabled={disabled || !!host.group_error} onClick={verify}>{verifying ? "Working…" : "Verify fingerprint"}</Button>
      {pin && <>
        <Button variant="ghost" size="sm" onClick={() => void copyText(pin.fingerprint).then(() => toast.success("Fingerprint copied")).catch(() => toast.error("Could not copy fingerprint"))}><Copy className="size-3.5" />Copy</Button>
        <AlertDialog><AlertDialogTrigger asChild><Button variant="ghost" size="sm" disabled={disabled} className="text-destructive"><Trash2 className="size-3.5" />Forget identity…</Button></AlertDialogTrigger>
          <AlertDialogContent><AlertDialogHeader><AlertDialogTitle>Forget {label}’s server identity?</AlertDialogTitle><AlertDialogDescription>
            Lunport will ask you to verify the fingerprint on the next connection. {host.scope.kind === "space" ? "This change syncs to your computers. " : ""}The saved host and its login keys are kept.
            <span className="mt-3 block font-mono break-all">{revealHidden(pin.fingerprint)}</span>
          </AlertDialogDescription></AlertDialogHeader><AlertDialogFooter><AlertDialogCancel>Cancel</AlertDialogCancel><AlertDialogAction onClick={forget}>Forget identity</AlertDialogAction></AlertDialogFooter></AlertDialogContent>
        </AlertDialog>
      </>}
    </div>
  </div>;
}
