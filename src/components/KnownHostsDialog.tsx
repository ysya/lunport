import { useMemo, useState } from "react";
import { ShieldEllipsis, Trash2 } from "lucide-react";
import { toast } from "sonner";

import type { KnownHostEntry } from "@/bindings/KnownHostEntry";
import { useKnownHosts, useRemoveKnownHosts } from "@/lib/queries";
import { cn } from "@/lib/utils";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import {
  Dialog,
  DialogContent,
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
} from "@/components/ui/tooltip";

/**
 * Toolbar button + a dialog viewing ~/.ssh/known_hosts: search, inspect, and delete entries —
 * the "host key changed after reinstall" cleanup (ssh-keygen -R without the terminal).
 * Removal is line-exact and backed up by the backend; the entry's first field is sent along as
 * a stale-view guard (a Conflict refetches instead of deleting the wrong line).
 */
export function KnownHostsDialog() {
  const [open, setOpen] = useState(false);
  const [query, setQuery] = useState("");
  // Lazy: only read known_hosts while the dialog is open.
  const { data, isLoading, isFetching } = useKnownHosts({ enabled: open });
  const remove = useRemoveKnownHosts();

  const entries = data ?? [];
  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase();
    if (!q) return entries;
    return entries.filter(
      (e) =>
        e.hosts.toLowerCase().includes(q) || e.key_type.toLowerCase().includes(q),
    );
  }, [entries, query]);

  const handleOpenChange = (next: boolean) => {
    setOpen(next);
    if (!next) setQuery("");
  };

  function handleRemove(entry: KnownHostEntry) {
    remove.mutate(
      { lineIndices: [entry.line_index], expectedHosts: [entry.hosts] },
      {
        onSuccess: () => {
          toast.success("Host key removed", {
            description: entry.hashed ? "1 hashed entry" : entry.hosts,
          });
        },
      },
    );
  }

  return (
    <Dialog open={open} onOpenChange={handleOpenChange}>
      <Tooltip>
        <TooltipTrigger asChild>
          <DialogTrigger asChild>
            <Button
              type="button"
              variant="ghost"
              size="icon"
              className="size-7"
              aria-label="Known hosts"
            >
              <ShieldEllipsis className="size-4" />
            </Button>
          </DialogTrigger>
        </TooltipTrigger>
        <TooltipContent>Known hosts</TooltipContent>
      </Tooltip>

      <DialogContent className="sm:max-w-lg">
        <DialogHeader>
          <DialogTitle>Known hosts</DialogTitle>
          <DialogDescription>
            Host keys in <span className="font-mono">~/.ssh/known_hosts</span>. Remove an
            entry when a server was reinstalled and its key changed.
          </DialogDescription>
        </DialogHeader>

        <Input
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          placeholder="Search hosts or key type…"
          aria-label="Search known hosts"
          spellCheck={false}
          autoCorrect="off"
          autoCapitalize="off"
          className="h-8 font-mono text-sm"
        />

        {isLoading || isFetching ? (
          <p className="py-6 text-center text-sm text-muted-foreground select-none">
            Reading known_hosts…
          </p>
        ) : entries.length === 0 ? (
          <p className="py-6 text-center text-sm text-muted-foreground select-none">
            No entries — <span className="font-mono">known_hosts</span> is empty or missing.
          </p>
        ) : filtered.length === 0 ? (
          <p className="py-6 text-center text-sm text-muted-foreground select-none">
            No entries match “{query}”.
          </p>
        ) : (
          <div className="-mx-1 max-h-[52vh] overflow-y-auto px-1">
            <div className="settings-group">
              {filtered.map((e) => (
                <KnownHostRow
                  key={e.line_index}
                  entry={e}
                  removing={remove.isPending}
                  onRemove={() => handleRemove(e)}
                />
              ))}
            </div>
          </div>
        )}
      </DialogContent>
    </Dialog>
  );
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
  const label = entry.hashed ? "a hashed entry" : entry.hosts;

  return (
    <div className="group flex min-h-9 items-center gap-3 px-3 py-2">
      <div className="min-w-0 flex-1 space-y-0.5">
        <div className="flex items-center gap-2">
          <span
            className={cn(
              "truncate font-mono text-sm",
              entry.hashed && "text-muted-foreground",
            )}
            title={entry.hosts}
          >
            {entry.hosts}
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
            {entry.key_type}
          </Badge>
          {entry.marker && (
            <Badge
              variant={revoked ? "destructive" : "secondary"}
              className="h-4 shrink-0 px-1.5 font-mono text-[0.625rem]"
            >
              {entry.marker}
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
                  {entry.hashed ? "hashed entry" : entry.hosts}
                </span>
                ?
              </AlertDialogTitle>
              <AlertDialogDescription>
                This removes the host key from{" "}
                <span className="font-mono">known_hosts</span> (a backup is taken first).
                You will re-verify the server&apos;s key on the next connect.
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
