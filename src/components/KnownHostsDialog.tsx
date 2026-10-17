import { TaskDialogContent as DialogContent, TaskDialogBody } from "@/components/app/TaskDialog";
import { useMemo, useState } from "react";
import { ShieldEllipsis, Trash2, Copy } from "lucide-react";
import { toast } from "sonner";

import type { KnownHostEntry } from "@/bindings/KnownHostEntry";
import { useKnownHosts, useRemoveKnownHosts } from "@/lib/queries";
import { cn } from "@/lib/utils";
import { copyText } from "@/lib/clipboard";
import { revealHidden } from "@/lib/sync-approvals";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import {
  Dialog,
  DialogClose,
  DialogFooter,
  DialogDescription,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from "@/components/ui/dialog";
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
  AlertDialogTrigger,
} from "@/components/ui/alert-dialog";
import {
  Tooltip,
  TooltipContent,
  TooltipTrigger,
  TooltipProvider,
} from "@/components/ui/tooltip";

/** Legacy toolbar entry; the file panel is shared with the Library trust manager. */
export function KnownHostsDialog() {
  const [open, setOpen] = useState(false);
  return (
    <Dialog open={open} onOpenChange={setOpen}>
      <Tooltip>
        <TooltipTrigger asChild><DialogTrigger asChild>
          <Button type="button" variant="ghost" size="icon" className="size-7" aria-label="Known hosts"><ShieldEllipsis className="size-4" /></Button>
        </DialogTrigger></TooltipTrigger>
        <TooltipContent>Known hosts</TooltipContent>
      </Tooltip>
      <DialogContent className="sm:max-w-xl">
        <DialogHeader>
          <DialogTitle>Known hosts</DialogTitle>
          <DialogDescription>Manage server identities saved in OpenSSH on this computer.</DialogDescription>
        </DialogHeader>
        <TaskDialogBody>{open && <KnownHostsFilePanel />}</TaskDialogBody>
        <DialogFooter><DialogClose asChild><Button variant="outline">Close</Button></DialogClose></DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

/** Reads only when its containing dialog/tab is mounted. */
export function KnownHostsFilePanel() {
  const [query, setQuery] = useState("");
  const { data, isLoading, isError, refetch, isFetching } = useKnownHosts({ enabled: true });
  const remove = useRemoveKnownHosts();
  const entries = data ?? [];
  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase();
    return q ? entries.filter((e) => `${e.hosts} ${e.key_type} ${e.fingerprint_sha256 ?? ""}`.toLowerCase().includes(q)) : entries;
  }, [entries, query]);
  return <TooltipProvider delayDuration={300}>
    <p className="text-xs text-muted-foreground">Entries in <span className="font-mono">~/.ssh/known_hosts</span> on this computer. Removing an entry creates a backup first. Hashed hostnames remain hidden.</p>
    <div className="flex items-center gap-2">
      <Input value={query} onChange={(e) => setQuery(e.target.value)} placeholder="Search host, fingerprint or key type…" aria-label="Search OpenSSH known hosts" spellCheck={false} autoCorrect="off" autoCapitalize="off" />
      <Button variant="outline" size="sm" disabled={isFetching || remove.isPending} onClick={() => void refetch()}>Reload</Button>
    </div>
    {isLoading ? <p className="app-task-state">Reading known_hosts…</p>
      : isError ? <div className="app-task-state" role="alert"><p>Could not read known hosts.</p><Button variant="outline" size="sm" onClick={() => void refetch()}>Retry</Button></div>
      : !entries.length ? <p className="app-task-state">No entries — known_hosts is empty or missing.</p>
      : !filtered.length ? <p className="app-task-state">No matching entries.</p>
      : <div className="settings-group">{filtered.map((entry) => <KnownHostRow key={entry.line_index} entry={entry} removing={remove.isPending} onRemove={() => remove.mutate({
          lineIndices:[entry.line_index], expectedHosts:[entry.hosts], expectedLineHashes:[entry.line_hash],
        }, {onSuccess: () => toast.success("OpenSSH host key removed")})} />)}</div>}
  </TooltipProvider>;
}

function KnownHostRow({
  entry,
  removing,
  onRemove,
}: {
  entry: KnownHostEntry;
  removing: boolean;
  onRemove: () => void;
}) {
  const revoked = entry.marker === "@revoked";
  const label = entry.hashed ? "a hashed entry" : revealHidden(entry.hosts);

  return (
    <div className="group flex min-h-9 items-center gap-3 px-3 py-2">
      <div className="min-w-0 flex-1 space-y-0.5">
        <div className="flex items-center gap-2">
          <span
            className={cn(
              "truncate font-mono text-sm",
              entry.hashed && "text-muted-foreground",
            )}
            title={revealHidden(entry.hosts)}
          >
            {revealHidden(entry.hosts)}
          </span>
          {entry.hashed && (
            <Badge
              variant="outline"
              className="h-4 shrink-0 px-1.5 text-[0.625rem] text-muted-foreground"
            >
              hashed
            </Badge>
          )}
          <Badge
            variant="secondary"
            className="h-4 shrink-0 px-1.5 font-mono text-[0.625rem]"
          >
            {revealHidden(entry.key_type)}
          </Badge>
          {entry.marker && (
            <Badge
              variant={revoked ? "destructive" : "secondary"}
              className="h-4 shrink-0 px-1.5 font-mono text-[0.625rem]"
            >
              {revealHidden(entry.marker)}
            </Badge>
          )}
        </div>
        {entry.fingerprint_sha256 && (
          <span
            className="block truncate font-mono text-xs text-muted-foreground"
            title={entry.fingerprint_sha256}
          >
            {entry.fingerprint_sha256}
          </span>
        )}
      </div>

      <div className="flex shrink-0 items-center opacity-0 transition-opacity group-hover:opacity-100 focus-within:opacity-100">
        {entry.fingerprint_sha256 && <Button type="button" variant="ghost" size="icon" className="size-7" aria-label={`Copy fingerprint for ${label}`} onClick={() => void copyText(entry.fingerprint_sha256!).then(() => toast.success("Fingerprint copied")).catch(() => toast.error("Could not copy fingerprint"))}><Copy className="size-3.5" /></Button>}
        <AlertDialog>
          <Tooltip>
            <TooltipTrigger asChild>
              <AlertDialogTrigger asChild>
                <Button
                  type="button"
                  variant="ghost"
                  size="icon"
                  className="size-6 text-muted-foreground hover:text-destructive"
                  aria-label={`Remove known host ${label}`}
                  disabled={removing}
                >
                  <Trash2 className="size-3.5" />
                </Button>
              </AlertDialogTrigger>
            </TooltipTrigger>
            <TooltipContent>Remove entry</TooltipContent>
          </Tooltip>
          <AlertDialogContent>
            <AlertDialogHeader>
              <AlertDialogTitle>
                Remove{" "}
                <span className="font-mono break-all">
                  {entry.hashed ? "hashed entry" : revealHidden(entry.hosts)}
                </span>
                ?
              </AlertDialogTitle>
              <AlertDialogDescription>
                This removes the host key from{" "}
                <span className="font-mono">known_hosts</span> (a backup is taken first).
                You will re-verify the server&apos;s key on the next connect.
                <span className="mt-3 block font-mono break-all">{revealHidden(entry.key_type)} · {entry.fingerprint_sha256 ?? "Fingerprint unavailable"}</span>
                {revoked && <span className="mt-2 block">This entry marks a revoked key. Removing it also removes that revocation rule.</span>}
              </AlertDialogDescription>
            </AlertDialogHeader>
            <AlertDialogFooter>
              <AlertDialogCancel>Cancel</AlertDialogCancel>
              <AlertDialogAction onClick={onRemove}>Remove</AlertDialogAction>
            </AlertDialogFooter>
          </AlertDialogContent>
        </AlertDialog>
      </div>
    </div>
  );
}

export default KnownHostsDialog;
