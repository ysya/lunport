import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogDescription, DialogFooter } from "@/components/ui/dialog";
import type { LibrarySyncPreview, LibraryRename } from "@/lib/records";
import { revealHidden } from "@/lib/sync-approvals";
import { RecordField } from "./form";

export function LibrarySyncReview({ preview, renames, setRenames, busy, error, confirm, refresh, cancel }: {
  preview: LibrarySyncPreview;
  renames: LibraryRename[];
  setRenames: (renames: LibraryRename[]) => void;
  busy: boolean;
  error: string | null;
  confirm: () => void;
  refresh: () => void;
  cancel: () => void;
}) {
  return (
    <Dialog open onOpenChange={(open) => { if (!open && !busy) cancel(); }}>
      <DialogContent className="library-sync-review sm:max-w-xl" showCloseButton={false}>
        <DialogHeader>
          <DialogTitle>Review library sync</DialogTitle>
          <DialogDescription>
            {preview.conflicts.length
              ? "Some local names are already used in the synced library. Keep both records by choosing new names for these local copies."
              : "The latest library has no name conflicts. You can include the records now."}
          </DialogDescription>
        </DialogHeader>
        <div className="library-sync-review-body">
          <p className="text-sm text-muted-foreground">
            {preview.local_hosts} hosts · {preview.local_groups} Groups to include.
            Synced records stay unchanged. Host aliases are also used by CLI Connect.
            No records or private keys will be merged or deleted.
          </p>
          <fieldset disabled={busy} className="space-y-4">
            {preview.conflicts.map((conflict, index) => (
              <RecordField key={`${conflict.kind}:${conflict.id}`} label={`${conflict.kind === "host" ? "Host alias" : "Group name"}: ${revealHidden(conflict.current_name)}`}>
                <Input
                  aria-label={`New ${conflict.kind === "host" ? "alias" : "Group name"} for ${revealHidden(conflict.current_name)}`}
                  value={renames[index]?.name ?? ""}
                  onChange={(event) => setRenames(renames.map((r, at) => at === index ? { ...r, name: event.target.value } : r))}
                />
              </RecordField>
            ))}
          </fieldset>
          {error && <p role="alert" className="text-sm text-destructive">{error}</p>}
        </div>
        <DialogFooter>
          {error && <Button variant="outline" disabled={busy} onClick={refresh}>Refresh review</Button>}
          <Button variant="outline" disabled={busy} onClick={cancel}>Cancel</Button>
          <Button disabled={busy || renames.some((r) => !r.name.trim())} onClick={confirm}>
            {busy ? "Including…" : preview.conflicts.length ? "Rename and include library" : "Include library"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
