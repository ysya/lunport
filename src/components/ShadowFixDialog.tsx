import { Loader2 } from "lucide-react";
import { toast } from "sonner";

import { useResolveShadowed } from "@/lib/sync";
import { shadowFixText, type ShadowFix } from "@/lib/sync-sidebar";
import { useLastNonNull } from "@/lib/use-last-non-null";
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from "@/components/ui/alert-dialog";

/**
 * The confirm before "Keep this copy as …-local" or "Remove this copy" (the sidebar's row menu and the
 * Move hosts wizard): a copy in a synced space is changed on every computer that syncs that space, and
 * the dialog says so before anything is written. The fix is addressed by file (`sync_resolve_shadowed`),
 * so it can only reach the copy ssh reads second. A toast says what was done.
 */
export function ShadowFixDialog({ fix, onClose }: { fix: ShadowFix | null; onClose: () => void }) {
  const resolve = useResolveShadowed();
  // Keep the text while the dialog animates out.
  const shown = useLastNonNull(fix);
  const text = shown ? shadowFixText(shown) : null;

  return (
    <AlertDialog
      open={fix !== null}
      onOpenChange={(open) => {
        if (!open && !resolve.isPending) onClose();
      }}
    >
      <AlertDialogContent>
        <AlertDialogHeader>
          <AlertDialogTitle>{text?.title}</AlertDialogTitle>
          <AlertDialogDescription>{text?.description}</AlertDialogDescription>
        </AlertDialogHeader>
        <AlertDialogFooter>
          <AlertDialogCancel disabled={resolve.isPending}>Cancel</AlertDialogCancel>
          <AlertDialogAction
            variant={shown?.action === "remove" ? "destructive" : "default"}
            disabled={resolve.isPending}
            onClick={(e) => {
              // Keep the dialog open until the request settles.
              e.preventDefault();
              if (!shown || !text) return;
              resolve.mutate(
                { alias: shown.alias, file: shown.file, action: shown.action },
                {
                  onSuccess: () => {
                    toast.success(text.done);
                    onClose();
                  },
                },
              );
            }}
          >
            {resolve.isPending && <Loader2 className="size-3.5 animate-spin" />} {text?.confirm}
          </AlertDialogAction>
        </AlertDialogFooter>
      </AlertDialogContent>
    </AlertDialog>
  );
}
