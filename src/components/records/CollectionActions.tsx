import { useRef, useState } from "react";
import type { RecordOverview } from "@/lib/records";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import {
  Dialog,
  DialogContent,
  DialogTitle,
  DialogDescription,
  DialogFooter,
} from "@/components/ui/dialog";
import { applyCollectionAction } from "./collection-actions";
import { selectClass } from "./form";
import { revealHidden } from "@/lib/sync-approvals";

export function CollectionActions({
  overview,
  ids,
  disabled,
  accept,
  onBusy,
  onCompleted,
  clear,
}: {
  overview: RecordOverview;
  ids: string[];
  disabled: boolean;
  accept: (overview: RecordOverview) => unknown;
  onBusy?: (busy: boolean) => void;
  onCompleted: (ids: string[]) => void;
  clear: () => void;
}) {
  const [dialog, setDialog] = useState<"move" | "tag" | null>(null);
  const [tag, setTag] = useState("");
  const [destination, setDestination] = useState("none");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const inFlight = useRef(false);
  const reviewed = useRef<{ overview: RecordOverview; ids: string[] } | null>(
    null,
  );
  const open = (kind: "move" | "tag") => {
    reviewed.current = { overview, ids: [...ids] };
    setError(null);
    setDialog(kind);
  };
  const run = async () => {
    if (inFlight.current || !dialog || !reviewed.current) return;
    inFlight.current = true;
    setBusy(true);
    onBusy?.(true);
    setError(null);
    try {
      const result = await applyCollectionAction(
        reviewed.current.overview,
        reviewed.current.ids,
        dialog === "move"
          ? {
              kind: "group",
              groupId: destination === "none" ? null : destination,
            }
          : { kind: "tag", tag },
        accept,
      );
      onCompleted(result.completed);
      // A failure requires reopening with a fresh reviewed snapshot; never replay successes.
      setDialog(null);
      setError(result.error);
    } catch {
      setError(
        "The selected hosts changed or are unavailable. Refresh and review the selection.",
      );
      setDialog(null);
    } finally {
      inFlight.current = false;
      setBusy(false);
      onBusy?.(false);
    }
  };
  return (
    <>
      <div
        className="shrink-0 space-y-2 border-t bg-muted/40 px-4 py-3"
        aria-label="Selected host actions"
      >
        <div className="flex flex-wrap items-center gap-2">
          <span className="mr-auto text-sm font-medium">
            {ids.length} selected
          </span>
          <Button
            size="sm"
            variant="outline"
            disabled={disabled || busy || !ids.length}
            onClick={() => open("move")}
          >
            Move to group…
          </Button>
          <Button
            size="sm"
            variant="outline"
            disabled={disabled || busy || !ids.length}
            onClick={() => open("tag")}
          >
            Add tag…
          </Button>
          <Button size="sm" variant="ghost" disabled={busy} onClick={clear}>
            Clear
          </Button>
        </div>
        {error && (
          <p role="alert" className="text-xs text-destructive">
            {error}
          </p>
        )}
      </div>
      <Dialog
        open={dialog !== null}
        onOpenChange={(value) => {
          if (!value && !busy) setDialog(null);
        }}
      >
        <DialogContent showCloseButton={!busy}>
          <DialogTitle>
            {dialog === "move"
              ? "Move selected hosts to a Group"
              : "Add a tag to selected hosts"}
          </DialogTitle>
          <DialogDescription>
            Apply to {reviewed.current?.ids.length ?? ids.length} hosts. Changes
            apply one host at a time. If a host changed elsewhere, the operation
            stops so you can review it. Grouping keeps current connection
            settings as host overrides.
          </DialogDescription>
          {dialog === "move" ? (
            <label className="space-y-2 text-sm">
              Group
              <select
                aria-label="Destination Group"
                value={destination}
                onChange={(event) => setDestination(event.target.value)}
                disabled={busy}
                className={selectClass}
              >
                <option value="none">Ungrouped</option>
                {overview.groups
                  .filter((group) => !group.group_error)
                  .map((group) => (
                    <option key={group.id} value={group.id}>
                      {revealHidden(group.payload.name)}
                    </option>
                  ))}
              </select>
            </label>
          ) : (
            <Input
              aria-label="Tag to add"
              autoFocus
              value={tag}
              disabled={busy}
              onChange={(event) => setTag(event.target.value)}
            />
          )}
          <DialogFooter>
            <Button
              variant="outline"
              disabled={busy}
              onClick={() => setDialog(null)}
            >
              Cancel
            </Button>
            <Button
              disabled={busy || (dialog === "tag" && !tag.trim())}
              onClick={() => void run()}
            >
              {busy ? "Applying…" : "Apply"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </>
  );
}
