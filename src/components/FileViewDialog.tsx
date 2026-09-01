import { useState } from "react";
import { Check, Copy } from "lucide-react";
import { toast } from "sonner";

import { useFileText } from "@/lib/queries";
import { copyText } from "@/lib/clipboard";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";

export interface FileViewDialogProps {
  /** Full path of the loaded managed config file to show; null = closed. */
  path: string | null;
  /** Sidebar display label for the file (falls back to the path's basename). */
  label?: string;
  onOpenChange: (open: boolean) => void;
}

/**
 * Read-only raw view of ONE loaded config file — the exact on-disk bytes, mono,
 * scrollable, with a Copy action. The text is fetched lazily when the dialog
 * opens (mount this component only while open so each open re-reads the file).
 * No syntax highlighting in v1 — a future nicety.
 */
export function FileViewDialog({ path, label, onOpenChange }: FileViewDialogProps) {
  const { data, isLoading, isError } = useFileText(path);
  const [copied, setCopied] = useState(false);

  const onCopy = async () => {
    if (data === undefined) return;
    try {
      await copyText(data);
      setCopied(true);
      toast("Copied");
      window.setTimeout(() => setCopied(false), 1400);
    } catch {
      toast.error("Couldn't copy to clipboard");
    }
  };

  return (
    <Dialog open={path !== null} onOpenChange={onOpenChange}>
      <DialogContent className="sm:max-w-2xl">
        <DialogHeader>
          <div className="flex items-center justify-between gap-3 pr-6">
            <DialogTitle className="truncate">{label ?? "Config file"}</DialogTitle>
            <Button
              type="button"
              variant="ghost"
              size="xs"
              className="h-6 shrink-0 gap-1.5 text-muted-foreground"
              onClick={onCopy}
              disabled={data === undefined}
              aria-label="Copy file contents"
            >
              {copied ? <Check className="size-3.5" /> : <Copy className="size-3.5" />}
              {copied ? "Copied" : "Copy"}
            </Button>
          </div>
          <DialogDescription className="truncate font-mono text-xs" title={path ?? undefined}>
            {path}
          </DialogDescription>
        </DialogHeader>

        <div className="settings-group">
          {isLoading ? (
            <div className="space-y-2 px-3.5 py-3" aria-hidden>
              <Skeleton className="h-3 w-2/3" />
              <Skeleton className="h-3 w-1/2" />
              <Skeleton className="h-3 w-3/5" />
            </div>
          ) : isError ? (
            <p className="px-3.5 py-3 text-sm text-muted-foreground">
              Could not read this file.
            </p>
          ) : (
            <pre className="max-h-[60vh] overflow-auto px-3.5 py-3 font-mono text-xs leading-relaxed whitespace-pre text-muted-foreground select-text">
              {data}
            </pre>
          )}
        </div>
      </DialogContent>
    </Dialog>
  );
}

export default FileViewDialog;
