import { useState, useRef } from "react";
import { useQuery } from "@tanstack/react-query";
import { toast } from "sonner";
import { Button } from "@/components/ui/button";
import { Dialog, DialogHeader, DialogTitle, DialogDescription } from "@/components/ui/dialog";
import { TaskDialogContent, TaskDialogBody } from "@/components/app/TaskDialog";
import { exportRecordHosts, savedWorkspaces } from "@/lib/records";
import { revealHidden } from "@/lib/sync-approvals";

export function WorkspaceTransfer({ open, onOpenChange, onImport }: { open: boolean; onOpenChange: (open: boolean) => void; onImport?: () => void }) {
  const query = useQuery({ queryKey: ["saved-workspaces"], queryFn: savedWorkspaces, enabled: open, retry: false, staleTime: 0 });
  const [busy, setBusy] = useState(false), [error, setError] = useState<string | null>(null);
  const inFlight = useRef(false);
  const exportSource = async (id?: string) => {
    if (inFlight.current) return;
    inFlight.current = true; setBusy(true); setError(null);
    try {
      const result = await exportRecordHosts(false, id);
      if (result) toast.success(`Exported ${result.hosts} hosts and ${result.groups} Groups`, { description: "Import this file into your local library. Assign SSH keys afterward." });
    } catch (value) { setError(String(value)); }
    finally { inFlight.current = false; setBusy(false); }
  };
  return <Dialog open={open} onOpenChange={(next) => { if (!busy) onOpenChange(next); }}>
    <TaskDialogContent className="sm:max-w-2xl">
      <DialogHeader><DialogTitle>Host and Group settings</DialogTitle><DialogDescription>Export connection settings from this library or a retained workspace. Private keys, passwords and account credentials are excluded. Source files stay in place.</DialogDescription></DialogHeader>
      <TaskDialogBody className="space-y-5">
        <div className="flex flex-wrap gap-2"><Button disabled={busy} onClick={() => void exportSource()}>Export current library…</Button>{onImport && <Button variant="outline" disabled={busy} onClick={onImport}>Import settings…</Button>}</div>
        <div className="space-y-3"><h3 className="font-medium">Saved workspaces</h3>
          <p className="text-sm text-muted-foreground">Choose a source, export it, then open Import settings to preview hosts and Groups before adding them to this library.</p>
          {query.isPending && <p role="status">Looking for saved workspaces…</p>}
          {query.isError && <p role="alert" className="app-error">Could not list saved workspaces. Existing files are retained.</p>}
          {query.data?.length === 0 && <p>No saved workspaces found.</p>}
          {query.data?.map((row) => <section className="rounded-lg border p-3 space-y-2" key={row.id}>
            <h4 className="text-sm font-medium">{row.active ? "Current library" : row.id === "original" ? "Original workspace" : "Saved server workspace"}</h4>
            <p className="break-all text-xs text-muted-foreground">{revealHidden(row.service ?? "Local / older sync")}</p>
            <code className="block break-all text-xs text-muted-foreground">{row.id}</code>
            {row.modified_ms && <p className="text-xs text-muted-foreground">Saved {new Date(row.modified_ms).toLocaleString()}</p>}
            {row.error ? <p className="text-sm text-destructive">{row.error}</p> : <p className="text-sm">{row.hosts} hosts · {row.groups} Groups</p>}
            <Button size="sm" variant="outline" disabled={busy || !!row.error || (!row.hosts && !row.groups)} onClick={() => void exportSource(row.id)}>Export settings…</Button>
          </section>)}
          <Button variant="ghost" size="sm" disabled={busy || query.isFetching} onClick={() => void query.refetch()}>Refresh saved workspaces</Button>
        </div>
        {error && <p role="alert" className="app-error whitespace-pre-wrap">{revealHidden(error)}</p>}
      </TaskDialogBody>
    </TaskDialogContent>
  </Dialog>;
}
