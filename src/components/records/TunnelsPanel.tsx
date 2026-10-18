import "./tunnels.css";
import { useRef, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { AlertCircle, ArrowLeftRight, LoaderCircle, PencilLine, Play, Plus, Search, Square, Trash2 } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { PageHeader } from "@/components/app/PageHeader";
import { Dialog, DialogHeader, DialogTitle, DialogDescription, DialogFooter } from "@/components/ui/dialog";
import { TaskDialogContent, TaskDialogBody } from "@/components/app/TaskDialog";
import { AlertDialog, AlertDialogContent, AlertDialogHeader, AlertDialogTitle, AlertDialogDescription, AlertDialogFooter, AlertDialogAction, AlertDialogCancel } from "@/components/ui/alert-dialog";
import { RecordField, selectClass } from "./form";
import { revealHidden } from "@/lib/sync-approvals";
import type { RecordOverview } from "@/lib/records";
import { listTunnels, saveTunnel, deleteTunnel, startTunnel, stopTunnel, tunnelsKey, tunnelKinds, tunnelBusy, tunnelRoute, newTunnel, type TunnelRule, type TunnelView, type ForwardKind } from "@/lib/tunnels";

const phases = { stopped: "Stopped", connecting: "Connecting", running: "Running", stopping: "Stopping", error: "Failed" };
export function TunnelsPanel({ overview }: { overview: RecordOverview }) {
  const query = useQuery({ queryKey: tunnelsKey, queryFn: listTunnels, refetchInterval: 1500 });
  const [search, setSearch] = useState("");
  const [draft, setDraft] = useState<TunnelRule | null>(null);
  const [original, setOriginal] = useState<TunnelRule | null>(null);
  const [busy, setBusy] = useState(false);
  const flight = useRef(false);
  const [error, setError] = useState<string | null>(null);
  const [editorError, setEditorError] = useState<string | null>(null);
  const [discarding, setDiscarding] = useState(false);
  const [deleting, setDeleting] = useState<TunnelView | null>(null);
  const baseline = useRef("");
  const rows = query.data ?? [];
  const visible = rows.filter((r) => `${r.rule.name} ${overview.hosts.find((h) => h.id === r.rule.host_id)?.payload.alias ?? ""} ${tunnelRoute(r.rule)}`.toLowerCase().includes(search.trim().toLowerCase()));
  const edit = (rule: TunnelRule | null) => {
    const value = rule ? structuredClone(rule) : newTunnel(overview.hosts[0]?.id);
    setOriginal(rule); setDraft(value); baseline.current = JSON.stringify(value); setEditorError(null);
  };
  const close = () => {
    if (flight.current) return;
    if (draft && JSON.stringify(draft) !== baseline.current) setDiscarding(true);
    else setDraft(null);
  };
  const action = async (run: () => Promise<void>, inEditor = false) => {
    if (flight.current) return;
    flight.current = true; setBusy(true); setError(null); setEditorError(null);
    try { await run(); if (inEditor) setDraft(null); setDeleting(null); }
    catch (error) { (inEditor ? setEditorError : setError)(revealHidden(String(error))); }
    finally { await query.refetch(); flight.current = false; setBusy(false); }
  };
  const patch = (value: Partial<TunnelRule>) => setDraft((d) => d && ({ ...d, ...value }));
  const forward = (value: Partial<TunnelRule["forward"]>) => setDraft((d) => d && ({ ...d, forward: { ...d.forward, ...value } }));
  return <div className="tunnels-panel space-y-5">
    <PageHeader title="Tunnels" count={rows.length} description="Forward ports through your saved SSH hosts."
      actions={<Button id="new-tunnel-button" onClick={() => edit(null)} disabled={busy || !overview.hosts.length || !!overview.account && overview.shared_writes_blocked}><Plus className="size-4" />New tunnel</Button>} />
    <div className="flex flex-wrap items-center gap-3">
      <div className="relative min-w-48 flex-1"><Search className="pointer-events-none absolute left-3 top-2.5 size-4 text-muted-foreground" /><Input id="tunnels-search" aria-label="Search tunnels" placeholder="Search tunnels or hosts…" className="pl-9" value={search} onChange={(e) => setSearch(e.target.value)} /></div>
      <span className="text-xs text-muted-foreground">{overview.account ? "Rules sync · Start separately on each device" : "Rules sync when you connect an account"}</span>
    </div>
    {(error || query.error) && <p role="alert" className="rounded-lg border border-destructive/30 p-3 text-sm text-destructive">{error ?? revealHidden(String(query.error))}<Button variant="ghost" size="sm" onClick={() => void query.refetch()}>Refresh</Button></p>}
    {query.isPending ? <p role="status" className="py-12 text-center text-sm text-muted-foreground">Loading tunnels…</p> : rows.length === 0 ?
      <div className="flex flex-col items-center gap-3 rounded-xl border border-dashed px-6 py-14 text-center">
        <ArrowLeftRight className="size-7 text-muted-foreground" /><h2 className="font-medium">Your private services, within reach</h2>
        <p className="max-w-sm text-sm text-muted-foreground">Create a local, remote or SOCKS5 tunnel. It can keep running when you close a terminal tab.</p>
        {!overview.hosts.length && <p className="text-sm text-muted-foreground">Add an SSH host first to create a tunnel.</p>}
      </div> : <div className="overflow-x-auto rounded-lg border">
      <table className="w-full text-left text-sm"><thead className="border-b bg-muted/30 text-xs text-muted-foreground"><tr><th className="px-4 py-3 font-medium">Tunnel</th><th className="tunnel-route-column px-4 py-3 font-medium">Route</th><th className="px-4 py-3 font-medium">Status</th><th className="px-4 py-3"><span className="sr-only">Actions</span></th></tr></thead>
        <tbody>{visible.map((row) => {
          const host = overview.hosts.find((h) => h.id === row.rule.host_id);
          const active = tunnelBusy(row);
          const route = tunnelRoute(row.rule, active ? row.live.forwarding.port || row.rule.forward.port : row.rule.forward.port);
          const changing = row.live.phase === "connecting" || row.live.phase === "stopping";
          const warning = row.removed ? "Deleted on another device. Stop this running tunnel to remove it here." : row.changed ? "The rule changed on another device. Stop and start again to apply it." : row.live.forwarding.error;
          return <tr key={row.rule.id} className="border-b last:border-0 hover:bg-muted/20">
            <td className="max-w-60 px-4 py-3"><button className="block max-w-full truncate text-left font-medium hover:text-primary disabled:cursor-default" disabled={active || row.blocked || busy} onClick={() => edit(row.rule)}>{revealHidden(row.rule.name)}</button><span className="mt-1 block truncate text-xs text-muted-foreground">{tunnelKinds[row.rule.forward.kind]} · {host ? revealHidden(host.payload.alias) : "Host unavailable"}</span><span className="tunnel-route-compact mt-1 max-w-56 truncate font-mono text-xs text-muted-foreground" title={route}>{route}</span></td>
            <td className="tunnel-route-column max-w-80 px-4 py-3"><span className="block truncate font-mono text-xs" title={route}>{route}</span><span className="mt-1 block text-xs text-muted-foreground">{row.removed ? "Removed elsewhere" : row.synced ? "Synced rule" : "On this computer"}</span></td>
            <td className="whitespace-nowrap px-4 py-3"><span className="inline-flex items-center gap-1.5" title={warning ? revealHidden(warning) : undefined}>
              {changing ? <LoaderCircle className="size-3 animate-spin" /> : <span className={`size-1.5 rounded-full ${row.live.phase === "running" ? "bg-success" : row.live.phase === "error" ? "bg-destructive" : "bg-muted-foreground/50"}`} />}
              {phases[row.live.phase]}{warning && <><AlertCircle className="size-3 text-warning" /><span className="sr-only">{revealHidden(warning)}</span></>}
              </span><span className="mt-1 block text-xs text-muted-foreground">{row.removed ? "Stop to remove here" : row.changed ? "Restart to apply changes" : row.live.phase === "running" ? `${row.live.forwarding.connections} active connection${row.live.forwarding.connections === 1 ? "" : "s"}` : row.blocked ? "Sync review needed" : "\u00a0"}</span></td>
            <td className="px-3 py-3"><div className="flex items-center justify-end gap-1"><Button size="sm" variant={active ? "outline" : "secondary"} disabled={busy || row.live.phase === "stopping" || !active && (!host || row.blocked)} onClick={() => void action(() => active ? stopTunnel(row.rule.id) : startTunnel(row.rule))}>{active ? <Square className="size-3" /> : <Play className="size-3" />}{active ? row.live.phase === "connecting" ? "Cancel" : "Stop" : row.live.phase === "error" ? "Retry" : "Start"}</Button>
              <Button size="icon-sm" variant="ghost" aria-label={`Edit ${row.rule.name}`} disabled={active || busy || row.blocked} onClick={() => edit(row.rule)}><PencilLine className="size-3.5" /></Button>
              <Button size="icon-sm" variant="ghost" aria-label={`Delete ${row.rule.name}`} disabled={active || busy || row.blocked} onClick={() => setDeleting(row)}><Trash2 className="size-3.5" /></Button></div></td>
          </tr>;
        })}</tbody></table>
        {!visible.length && <p className="p-8 text-center text-sm text-muted-foreground">No tunnels match this search.</p>}
      </div>}
    <Dialog open={!!draft} onOpenChange={(open) => { if (!open) close(); }}><TaskDialogContent className="sm:max-w-xl">
      <DialogHeader><DialogTitle>{original ? "Edit tunnel" : "New tunnel"}</DialogTitle><DialogDescription>Save the rule, then start it on this computer when needed.</DialogDescription></DialogHeader>
      {draft && <form id="tunnel-editor" onSubmit={(e) => { e.preventDefault(); const rule = { ...draft, name: draft.name.trim(), forward: { ...draft.forward, bind_address: draft.forward.bind_address.trim(), target_host: draft.forward.target_host.trim(), ...(draft.forward.kind === "dynamic" ? { target_host: "", target_port: 0 } : {}) } }; void action(() => saveTunnel(rule, original), true); }} className="contents">
        <TaskDialogBody><fieldset disabled={busy} className="space-y-4">
          {editorError && <p role="alert" className="text-sm text-destructive">{editorError}</p>}
          <RecordField label="Name"><Input value={draft.name} maxLength={128} required placeholder="Production database" onChange={(e) => patch({ name: e.target.value })} autoFocus /></RecordField>
          <RecordField label="SSH host"><select className={selectClass} value={draft.host_id} required onChange={(e) => patch({ host_id: e.target.value })}><option value="" disabled>Choose a host</option>{overview.hosts.map((h) => <option key={h.id} value={h.id}>{revealHidden(h.payload.alias)}</option>)}</select></RecordField>
          <RecordField label="Type"><select className={selectClass} value={draft.forward.kind} onChange={(e) => forward({ kind: e.target.value as ForwardKind })}><option value="local">Local — access a remote service</option><option value="remote">Remote — access a service on this computer</option><option value="dynamic">SOCKS5 — proxy through the SSH host</option></select></RecordField>
          <div className="grid grid-cols-[minmax(0,1fr)_7rem] gap-3"><RecordField label={draft.forward.kind === "remote" ? "Listen address on SSH host" : "Listen address on this computer"}><Input value={draft.forward.bind_address} required onChange={(e) => forward({ bind_address: e.target.value })} /></RecordField><RecordField label="Listen port"><Input type="number" min={0} max={65535} required value={draft.forward.port} onChange={(e) => forward({ port: Number(e.target.value) })} /></RecordField></div>
          <p className="text-xs text-muted-foreground">127.0.0.1 listens on loopback. Port 0 chooses an available port.{draft.forward.kind === "remote" && " The SSH server must permit remote forwarding."}</p>
          {draft.forward.kind !== "dynamic" ? <div className="grid grid-cols-[minmax(0,1fr)_7rem] gap-3"><RecordField label={draft.forward.kind === "remote" ? "Destination from this computer" : "Destination from SSH host"}><Input value={draft.forward.target_host} required onChange={(e) => forward({ target_host: e.target.value })} /></RecordField><RecordField label="Destination port"><Input type="number" min={1} max={65535} required value={draft.forward.target_port} onChange={(e) => forward({ target_port: Number(e.target.value) })} /></RecordField></div> : <p className="rounded-lg bg-muted/50 p-3 text-sm text-muted-foreground">Set your browser or tool to use this SOCKS5 address. Destination names are resolved through the SSH host.</p>}
        </fieldset></TaskDialogBody>
      </form>}
      <DialogFooter><Button variant="outline" disabled={busy} onClick={close}>Cancel</Button><Button type="submit" form="tunnel-editor" disabled={busy}>{busy && <LoaderCircle className="size-3 animate-spin" />}Save tunnel</Button></DialogFooter>
    </TaskDialogContent></Dialog>
    <AlertDialog open={discarding} onOpenChange={setDiscarding}><AlertDialogContent><AlertDialogHeader><AlertDialogTitle>Discard tunnel changes?</AlertDialogTitle><AlertDialogDescription>Your unsaved changes will be lost.</AlertDialogDescription></AlertDialogHeader><AlertDialogFooter><AlertDialogCancel>Keep editing</AlertDialogCancel><AlertDialogAction onClick={() => { setDiscarding(false); setDraft(null); }}>Discard</AlertDialogAction></AlertDialogFooter></AlertDialogContent></AlertDialog>
    <AlertDialog open={!!deleting} onOpenChange={(open) => { if (!open && !busy) setDeleting(null); }}><AlertDialogContent><AlertDialogHeader><AlertDialogTitle>Delete {deleting?.rule.name}?</AlertDialogTitle><AlertDialogDescription>{deleting?.synced ? "This removes the saved rule from your synced devices. Already-running tunnels there can be stopped separately." : "This removes the saved tunnel rule."}</AlertDialogDescription></AlertDialogHeader><p role="alert" className="text-sm text-destructive">{error}</p><AlertDialogFooter><AlertDialogCancel disabled={busy}>Cancel</AlertDialogCancel><Button variant="destructive" disabled={busy} onClick={() => { if (deleting) void action(() => deleteTunnel(deleting.rule)); }}>Delete tunnel</Button></AlertDialogFooter></AlertDialogContent></AlertDialog>
  </div>;
}
