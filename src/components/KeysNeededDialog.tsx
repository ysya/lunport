import { useEffect, useRef, useState } from "react";

import type { SyncKeySlotView } from "@/bindings/SyncKeySlotView";
import { PickKeyDialog } from "@/components/keychain/dialogs";
import { Button } from "@/components/ui/button";
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { finishedKeysNeededNotice, hostsLine, keysNeededNoticeIndex, slotsNeedingKey } from "@/lib/key-slots";
import { useDismissNotice, useSyncOverview } from "@/lib/sync";
import { revealHidden } from "@/lib/sync-approvals";

/**
 * "Keys for this computer" (SP3 spec §6.7, plan ruling 5): opens on the backend's `keys_needed` notice, which comes the
 * first time a synced host here needs a key that stays on another computer — for example right after joining. "Done"
 * dismisses the notice; the Settings row and the Keys dialog stay until each slot has a key. Once nothing is left to
 * pick, the notice is dismissed by itself.
 */
export function KeysNeededDialog() {
  const overview = useSyncOverview();
  const dismiss = useDismissNotice();
  const [picking, setPicking] = useState<SyncKeySlotView | null>(null);
  const o = overview.data;
  const index = o ? keysNeededNoticeIndex(o) : null;
  const slots = o ? slotsNeedingKey(o) : [];
  // The backend dismisses by index and doesn't check which notice it is: a second request while the first is still on its
  // way (Escape pressed twice, Done and then a click outside) would remove whichever notice has moved into that index.
  const done = () => {
    if (index !== null && !dismiss.isPending) dismiss.mutate({ index });
  };
  // One try per notice: a failed dismiss shows its error once instead of retrying on every render.
  const finished = o ? finishedKeysNeededNotice(o) : null;
  const dismissNotice = dismiss.mutate;
  const tried = useRef<number | null>(null);
  useEffect(() => {
    if (finished === null) {
      tried.current = null;
      return;
    }
    if (tried.current === finished) return;
    tried.current = finished;
    dismissNotice({ index: finished });
  }, [finished, dismissNotice]);
  return (
    <>
      <Dialog open={index !== null && slots.length > 0 && picking === null} onOpenChange={(next) => !next && done()}>
        <DialogContent className="sm:max-w-md">
          <DialogHeader>
            <DialogTitle>Keys for this computer</DialogTitle>
            <DialogDescription>
              Synced hosts on this computer use keys that stay on your other computers. Pick a key on this computer for each, or do it later in Keys.
            </DialogDescription>
          </DialogHeader>
          <div className="settings-group max-h-[40vh] overflow-y-auto">
            {slots.map((slot) => (
              <div key={slot.id} className="flex items-center justify-between gap-3 px-3 py-2">
                <div className="min-w-0">
                  <p className="truncate font-mono text-sm">{revealHidden(slot.name)}</p>
                  <p className="text-xs text-muted-foreground">{hostsLine(slot)}</p>
                </div>
                <Button type="button" size="sm" className="h-7" onClick={() => setPicking(slot)}>
                  Pick…
                </Button>
              </div>
            ))}
          </div>
          <DialogFooter>
            <Button type="button" disabled={dismiss.isPending} onClick={done}>
              Done
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
      <PickKeyDialog slot={picking} onClose={() => setPicking(null)} />
    </>
  );
}
