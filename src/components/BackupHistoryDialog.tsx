import { useMemo, useState } from "react";
import { History } from "lucide-react";
import { toast } from "sonner";

import type { BackupInfo } from "@/bindings/BackupInfo";
import { useBackups, useRestoreBackup } from "@/lib/queries";
import { basename } from "@/lib/utils";

import { Button } from "@/components/ui/button";
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

/** Format a unix-millis timestamp as a coarse relative string ("2h ago"). */
function relativeTime(ms: number): string {
  const diff = Date.now() - ms;
  if (diff < 0) return "just now";
  const sec = Math.floor(diff / 1000);
  if (sec < 60) return "just now";
  const min = Math.floor(sec / 60);
  if (min < 60) return `${min}m ago`;
  const hr = Math.floor(min / 60);
  if (hr < 24) return `${hr}h ago`;
  const day = Math.floor(hr / 24);
  if (day < 30) return `${day}d ago`;
  const month = Math.floor(day / 30);
  if (month < 12) return `${month}mo ago`;
  return `${Math.floor(month / 12)}y ago`;
}

/** Toolbar button + a dialog listing config backups, newest-first, with restore. */
export function BackupHistoryDialog() {
  const [open, setOpen] = useState(false);
  // Lazy: only list backups once the dialog is open.
  const { data, isLoading, isFetching } = useBackups({ enabled: open });
  const restore = useRestoreBackup();

  const backups = useMemo(
    () => [...(data ?? [])].sort((a, b) => b.timestamp_ms - a.timestamp_ms),
    [data],
  );

  function handleRestore(b: BackupInfo) {
    restore.mutate(
      { backupPath: b.path },
      {
        onSuccess: () => {
          toast.success(`Restored ${basename(b.file)}`);
          setOpen(false);
        },
      },
    );
  }

  return (
    <Dialog open={open} onOpenChange={setOpen}>
      <Tooltip>
        <TooltipTrigger asChild>
          <DialogTrigger asChild>
            <Button
              type="button"
              variant="ghost"
              size="icon"
              className="size-7"
              aria-label="Backup history"
            >
              <History className="size-4" />
            </Button>
          </DialogTrigger>
        </TooltipTrigger>
        <TooltipContent>Backup history</TooltipContent>
      </Tooltip>

      <DialogContent className="sm:max-w-md">
        <DialogHeader>
          <DialogTitle>Backup history</DialogTitle>
          <DialogDescription>
            Snapshots taken before edits. Restoring overwrites the live file.
          </DialogDescription>
        </DialogHeader>

        {isLoading || isFetching ? (
          <p className="py-6 text-center text-sm text-muted-foreground select-none">
            Loading backups…
          </p>
        ) : backups.length === 0 ? (
          <p className="py-6 text-center text-sm text-muted-foreground select-none">
            No backups yet.
          </p>
        ) : (
          <div className="-mx-1 max-h-[60vh] overflow-y-auto px-1">
            <div className="settings-group">
              {backups.map((b, i) => (
                <BackupRow
                  key={`${b.path}-${i}`}
                  backup={b}
                  restoring={restore.isPending}
                  onRestore={() => handleRestore(b)}
                />
              ))}
            </div>
          </div>
        )}
      </DialogContent>
    </Dialog>
  );
}

function BackupRow({
  backup,
  restoring,
  onRestore,
}: {
  backup: BackupInfo;
  restoring: boolean;
  onRestore: () => void;
}) {
  const absolute = useMemo(
    () => new Date(backup.timestamp_ms).toLocaleString(),
    [backup.timestamp_ms],
  );

  return (
    <div className="flex min-h-9 items-center justify-between gap-3 px-3 py-2">
      <div className="min-w-0 space-y-0.5">
        <span className="block truncate font-mono text-sm" title={backup.file}>
          {basename(backup.file)}
        </span>
        <span className="block text-xs text-muted-foreground" title={absolute}>
          {relativeTime(backup.timestamp_ms)}
        </span>
      </div>

      <AlertDialog>
        <AlertDialogTrigger asChild>
          <Button
            type="button"
            variant="secondary"
            size="sm"
            className="h-7 shrink-0"
            disabled={restoring}
          >
            Restore
          </Button>
        </AlertDialogTrigger>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>
              Restore “<span className="font-mono">{basename(backup.file)}</span>”?
            </AlertDialogTitle>
            <AlertDialogDescription>
              This overwrites the live{" "}
              <span className="font-mono">{basename(backup.file)}</span> with the
              snapshot from <span className="font-mono">{absolute}</span>. This
              cannot be undone.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>Cancel</AlertDialogCancel>
            <AlertDialogAction onClick={onRestore}>Restore</AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </div>
  );
}

export default BackupHistoryDialog;
