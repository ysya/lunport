import { useEffect, useRef, useState } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogDescription, DialogFooter } from "@/components/ui/dialog";
import { centralConflicts, centralResolveConflict, type CentralConflict, type CentralStatus } from "@/lib/central-sync";
import type { RecordOverview } from "@/lib/records";
import { revealHidden } from "@/lib/sync-approvals";
import { CATALOG_CHOICE_NOTE, CATALOG_TITLE, CatalogConflictView, catalogChoiceTitle } from "./CatalogConflict";

type Option = "local" | "remote" | "copy_remote";

/** One record in conflict: the Catalog as its colliding items (design 2026-10-27), any other record as its two versions. */
export function ConflictRow({row, overview, disabled, busy, pick}: {row:CentralConflict; overview?:RecordOverview; disabled:boolean; busy:boolean; pick:(row:CentralConflict, option:Option)=>void}) {
  const pending=!row.can_resolve&&<p className="text-sm text-muted-foreground">Sync must verify the pending write receipt before this conflict can be resolved.</p>;
  if(row.catalog) return <div className="space-y-2 rounded-md border p-3">
    <h4 className="text-sm font-medium">{CATALOG_TITLE}</h4>
    {pending}
    <CatalogConflictView review={row.catalog} overview={overview} disabled={disabled||busy||!row.can_resolve} choose={option=>pick(row,option)} />
  </div>;
  return <div className="space-y-2 rounded-md border p-3">
    <h4 className="text-sm font-medium break-all">{revealHidden(row.name)} · {row.kind === "password" ? "SSH password" : row.kind}</h4>
    {row.local_deleted&&<p className="text-sm">Deleted on this device</p>}{row.remote_deleted&&<p className="text-sm">Deleted on another device</p>}
    <ConflictComparison row={row} overview={overview} />
    {pending}
    {!row.can_remote&&row.can_resolve&&<p className="text-sm text-muted-foreground">This record contains key material or library structure. You can retain this device’s version; previous encrypted versions remain in history. Private keys are never displayed here.</p>}
    <div className="flex flex-wrap gap-2">{(["local","remote","copy_remote"] as const).filter(option=>option==="local"||option==="remote"?option==="local"||row.can_remote:row.can_copy).map(option=><Button key={option} size="sm" variant="outline" disabled={disabled||busy||!row.can_resolve} onClick={()=>pick(row,option)}>{option==="local"?"Keep this device’s version…":option==="remote"?"Use synced version…":"Keep both hosts…"}</Button>)}</div>
  </div>;
}

export function CentralConflicts({status, disabled, update, onBusyChange, overview}: {overview?:RecordOverview; status:CentralStatus; disabled:boolean; update:(status:CentralStatus)=>void; onBusyChange:(busy:boolean)=>void}) {
  const client=useQueryClient();
  const key=["central-conflicts",status.service,status.account_id,status.device_id,status.membership_head,status.authorization_epoch];
  const query=useQuery({queryKey:key,queryFn:centralConflicts,retry:false,refetchOnWindowFocus:false});
  const [selection,setSelection]=useState<CentralConflict|null>(null),[choice,setChoice]=useState<"local"|"remote"|"copy_remote">("local");
  const [alias,setAlias]=useState(""),[busy,setBusy]=useState(false),[error,setError]=useState<string|null>(null);
  const inFlight=useRef(false), mounted=useRef(false);
  useEffect(()=>{mounted.current=true;return()=>{mounted.current=false;};},[]);
  useEffect(()=>{onBusyChange(busy);return()=>onBusyChange(false);},[busy,onBusyChange]);
  const resolve=async()=>{
    if(!selection||disabled||inFlight.current)return;
    inFlight.current=true;setBusy(true);setError(null);
    try{const result=await centralResolveConflict(selection,choice,alias);if(mounted.current){update(result);setSelection(null);void client.invalidateQueries({queryKey:["records"]});}}
    catch(value){if(mounted.current)setError(String(value));}
    finally{inFlight.current=false;if(mounted.current){setBusy(false);void query.refetch();}}
  };
  return <section className="space-y-3 rounded-lg border p-3" aria-label="Sync conflicts">
    <h3 className="font-medium">Review sync conflicts</h3><p className="text-sm text-muted-foreground">Choose the version to use, or keep a host copy. Before applying your choice, Lunport keeps an encrypted local recovery snapshot. Unrelated records continue syncing.</p>
    {query.isPending&&<p role="status">Loading verified versions…</p>}
    {query.isError&&<p role="alert" className="app-error">Could not load conflict review. Refresh the account or retry loading.</p>}
    {query.data?.map(row=><ConflictRow key={row.id} row={row} overview={overview} disabled={disabled} busy={busy} pick={(row,option)=>{setChoice(option);setSelection(row);setAlias(`${row.name}-copy`);setError(null);}} />)}
    <Button variant="ghost" size="sm" disabled={disabled||busy||query.isFetching} onClick={()=>void query.refetch()}>Refresh conflicts</Button>
    <Dialog open={!!selection} onOpenChange={open=>{if(!open&&!busy)setSelection(null);}}><DialogContent className="max-h-[85vh] overflow-y-auto sm:max-w-xl">{selection?.catalog&&choice!=="copy_remote"?<DialogHeader><DialogTitle>{catalogChoiceTitle(choice)}</DialogTitle><DialogDescription>{CATALOG_CHOICE_NOTE}</DialogDescription></DialogHeader>:<DialogHeader><DialogTitle>{choice==="copy_remote"?"Keep both host versions?":"Use this version?"}</DialogTitle><DialogDescription>{choice==="local"?"Your current device’s version will replace the synced version for this record.":choice==="remote"?"The reviewed synced version will replace this device’s current record.":"Keep this device’s host and create a separate host using the synced settings. Assign and verify its authentication before connecting."} Previous versions are kept in an encrypted local recovery snapshot on this device.</DialogDescription></DialogHeader>}
      <p className="text-sm break-all">{selection&&(selection.catalog?CATALOG_TITLE:revealHidden(selection.name))}</p>
      {choice==="copy_remote"&&<label className="text-sm">New host name<Input value={alias} onChange={event=>setAlias(event.target.value)} disabled={busy} maxLength={128}/></label>}
      {error&&<div className="space-y-2"><p role="alert" className="app-error whitespace-pre-wrap">{revealHidden(error)}</p><Button variant="outline" disabled={busy} onClick={() => void query.refetch().then(result => { const current=result.data?.find(row=>row.id===selection?.id); if(current){setSelection(current);setError(null);}else if(result.data){setSelection(null);} })}>Refresh review</Button></div>}
      <DialogFooter><Button variant="outline" disabled={busy} onClick={()=>setSelection(null)}>Cancel</Button><Button disabled={disabled||busy||(choice==="copy_remote"&&!alias.trim())} onClick={()=>void resolve()}>Confirm version</Button></DialogFooter>
    </DialogContent></Dialog>
  </section>;
}

const labels: Record<string, string> = {
  alias: "Host name", hostname: "Address", port: "Port", user: "User", auth: "Authentication", key_id: "SSH key",
  jump: "Jump hosts", group_id: "Group", parent_id: "Parent Group", name: "Name", tags: "Tags", notes: "Notes",
  fingerprint: "Fingerprint", type: "Key type", keepalive_secs: "Keepalive interval", keepalive_max_missed: "Missed keepalives", connect_timeout_secs: "Connection timeout",
};
function entries(value: Record<string, unknown> | null): Record<string, unknown> {
  if (!value) return {};
  const { schema: _schema, host_key: _pin, imported: _imported, defaults, ...rest } = value;
  if (defaults && typeof defaults === "object") {
    for (const [field, item] of Object.entries(defaults)) {
      if (field === "authentication" && item && typeof item === "object") Object.assign(rest, item);
      else rest[field] = item;
    }
  }
  return rest;
}
export function ConflictComparison({ row, overview }: { row: CentralConflict; overview?: RecordOverview }) {
  const left = entries(row.local), right = entries(row.remote);
  const fields = [...new Set([...Object.keys(left), ...Object.keys(right)])].filter(field => JSON.stringify(left[field]) !== JSON.stringify(right[field]));
  const display = (field: string, value: unknown): string => {
    if (value === undefined || value === null || value === "") return "—";
    if (field === "key_id" && typeof value === "string") value = overview?.keys.find(key => key.id === value)?.public?.name ?? value;
    if ((field === "group_id" || field === "parent_id") && typeof value === "string") value = overview?.groups.find(group => group.id === value)?.payload.name ?? value;
    if (field === "jump" && Array.isArray(value)) value = value.map(id => overview?.hosts.find(host => host.id === id)?.payload.alias ?? id);
    if (Array.isArray(value) && value.every(item => typeof item === "string")) return value.map(item => revealHidden(item)).join(", ") || "—";
    return typeof value === "object" ? JSON.stringify(value, (_, item) => typeof item === "string" ? revealHidden(item) : item) : revealHidden(String(value));
  };
  if (!fields.length) return <p className="text-sm text-muted-foreground">{row.kind === "password" ? "Saved SSH passwords differ. Choose which version to keep; passwords are never displayed." : row.kind === "key" ? "Private key material differs. It stays inside Lunport and is never displayed." : "The saved versions differ in protected metadata. Review the choice before continuing."}</p>;
  return <div className="max-h-72 overflow-auto rounded-md border"><table className="w-full table-fixed text-left text-xs" aria-label="Version differences"><thead><tr className="border-b bg-muted"><th className="w-1/4 p-2">Setting</th><th className="p-2">This device</th><th className="p-2">Synced version</th></tr></thead><tbody>{fields.map(field => <tr key={field} className="border-b last:border-0"><th className="p-2 align-top font-medium break-words">{labels[field] ?? field.replace(/_/g, " ")}</th><td className="p-2 align-top whitespace-pre-wrap break-all">{row.local_deleted ? "Deleted" : display(field, left[field])}</td><td className="p-2 align-top whitespace-pre-wrap break-all">{row.remote_deleted ? "Deleted" : display(field, right[field])}</td></tr>)}</tbody></table></div>;
}
