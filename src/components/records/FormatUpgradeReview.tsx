import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogTitle,
  DialogDescription,
  DialogFooter,
} from "@/components/ui/dialog";
export function FormatUpgradeReview({
  open,
  busy,
  confirm,
  cancel,
}: {
  open: boolean;
  busy: boolean;
  confirm: () => void;
  cancel: () => void;
}) {
  return (
    <Dialog
      open={open}
      onOpenChange={(value) => {
        if (!value && !busy) cancel();
      }}
    >
      <DialogContent>
        <DialogTitle>Enable Groups and inheritance</DialogTitle>
        <DialogDescription>
          This upgrades the saved format and creates a local backup. Other
          devices must use a compatible version before shared changes sync.
          Confirm all other clients are updated or stopped.
        </DialogDescription>
        <DialogFooter>
          <Button autoFocus variant="outline" disabled={busy} onClick={cancel}>
            Keep editing
          </Button>
          <Button disabled={busy} onClick={confirm}>
            Clients updated — save
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
