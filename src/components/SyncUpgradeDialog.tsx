import { useState } from "react";

import { useDismissNotice, useSyncOverview } from "@/lib/sync";
import { upgradeExplanation, upgradeNotice } from "@/lib/sync-events";
import { Button } from "@/components/ui/button";
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog";

/**
 * The one-time explanation after this computer moved from v1 sync to spaces
 * (spec §8). The backend keeps the `upgraded` notice — across restarts — until it is
 * dismissed, so closing sends the dismiss; but the dialog closes first and never
 * waits for the answer. When the backend refuses (a second SSHelter process never
 * saves state), the error toast says so, the app stays usable, and the dialog
 * comes back on the next launch.
 */
export function SyncUpgradeDialog() {
  const overview = useSyncOverview();
  const dismiss = useDismissNotice();
  const [closed, setClosed] = useState(false);
  const found = overview.data ? upgradeNotice(overview.data.notices) : null;
  if (!found || closed) return null;

  const close = () => {
    setClosed(true);
    dismiss.mutate({ index: found.index });
  };

  return (
    <Dialog open onOpenChange={(open) => !open && close()}>
      <DialogContent className="sm:max-w-md">
        <DialogHeader>
          <DialogTitle>Sync was upgraded</DialogTitle>
          <DialogDescription>Sync now keeps hosts in spaces: groups of hosts that each computer chooses whether to sync.</DialogDescription>
        </DialogHeader>
        <ul className="list-disc space-y-1.5 pl-5 text-sm">
          {upgradeExplanation(found.notice).map((line) => (
            <li key={line}>{line}</li>
          ))}
        </ul>
        <DialogFooter>
          <Button type="button" onClick={close}>
            Got it
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
