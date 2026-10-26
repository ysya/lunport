import { useRef, useState, type ReactElement } from "react";
import {
  ArrowUpRight,
  Copy,
  CopyPlus,
  FolderInput,
  Pencil,
  Info,
  Tag,
  Trash2,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import {
  ContextMenu,
  ContextMenuTrigger,
  ContextMenuContent,
  ContextMenuItem,
  ContextMenuSeparator,
} from "@/components/ui/context-menu";
import {
  Dialog,
  DialogContent,
  DialogTitle,
  DialogDescription,
  DialogFooter,
} from "@/components/ui/dialog";
import { copyText } from "@/lib/clipboard";
import type { RecordHostView, RecordOverview } from "@/lib/records";
import { revealHidden } from "@/lib/sync-approvals";
import { transportFor } from "@/lib/transports";
import { applyCollectionAction } from "./collection-actions";
import { selectGroup } from "./group-tree";
import { deleteReviewedHost, reviewedHostIsCurrent } from "./host-actions";
import { selectClass } from "./form";

type Action = "group" | "tag" | "delete";
export function HostContextMenu({
  children,
  host,
  overview,
  disabled,
  organizeDisabled,
  connectDisabled,
  connect,
  edit,
  duplicate,
  inspect,
  accept,
  onBusy,
  returnFocus,
}: {
  children: ReactElement;
  host: RecordHostView;
  overview: RecordOverview;
  disabled: boolean;
  organizeDisabled: boolean;
  connectDisabled: boolean;
  connect?: () => void;
  edit?: () => void;
  duplicate?: () => void;
  inspect?: () => void;
  accept?: (next: RecordOverview) => unknown;
  onBusy?: (busy: boolean) => void;
  returnFocus: () => void;
}) {
  const [review, setReview] = useState<{
    action: Action;
    host: RecordHostView;
    overview: RecordOverview;
  } | null>(null);
  const [group, setGroup] = useState("none");
  const [tag, setTag] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const inFlight = useRef(false);
  const openingDialog = useRef(false);
  const cancel = useRef<HTMLButtonElement>(null);
  const trigger = useRef<HTMLElement | null>(null);
  const stale = !!review && !reviewedHostIsCurrent(review.host, overview);
  const open = (action: Action) => {
    if (disabled || organizeDisabled || !accept) return;
    openingDialog.current = true;
    setReview({ action, host, overview });
    setGroup(host.payload.group_id ?? "none");
    setTag("");
    setError(null);
  };
  const apply = async () => {
    if (
      inFlight.current ||
      !review ||
      !accept ||
      disabled ||
      organizeDisabled ||
      stale
    )
      return;
    inFlight.current = true;
    setBusy(true);
    onBusy?.(true);
    setError(null);
    try {
      if (review.action === "delete") {
        await deleteReviewedHost(review.host, overview, accept);
      } else {
        const result = await applyCollectionAction(
          review.overview,
          [review.host.id],
          review.action === "group"
            ? { kind: "group", groupId: group === "none" ? null : group }
            : { kind: "tag", tag },
          accept,
        );
        if (result.error) throw new Error(result.error);
      }
      setReview(null);
    } catch {
      // Close the reviewed action before another attempt can be made. Never replay a write.
      setReview(null);
      setError(
        "Could not change this host. Refresh and reopen its menu to review the latest saved version.",
      );
    } finally {
      inFlight.current = false;
      setBusy(false);
      onBusy?.(false);
    }
  };
  return (
    <>
      <ContextMenu>
        <ContextMenuTrigger
          ref={(node) => {
            trigger.current = node;
          }}
          asChild
          disabled={disabled}
          aria-haspopup="menu"
          onKeyDown={(event) => {
            if (
              !disabled &&
              (event.key === "ContextMenu" ||
                (event.key === "F10" && event.shiftKey))
            ) {
              event.preventDefault();
              const bounds = event.currentTarget.getBoundingClientRect();
              event.currentTarget.dispatchEvent(
                new MouseEvent("contextmenu", {
                  bubbles: true,
                  cancelable: true,
                  clientX: bounds.left + 16,
                  clientY: bounds.top + 16,
                }),
              );
            }
          }}
        >
          {children}
        </ContextMenuTrigger>
        <ContextMenuContent
          onCloseAutoFocus={(event) => {
            if (openingDialog.current) {
              event.preventDefault();
              openingDialog.current = false;
            }
          }}
        >
          <ContextMenuItem
            disabled={disabled || connectDisabled || !connect}
            onSelect={connect}
          >
            <ArrowUpRight />
            Connect
          </ContextMenuItem>
          <ContextMenuItem
            disabled={disabled || !edit}
            onSelect={() => {
              openingDialog.current = true;
              edit?.();
            }}
          >
            <Pencil />
            Edit host…
          </ContextMenuItem>
          {duplicate && (
            <ContextMenuItem
              disabled={disabled || (host.scope.kind === "space" && overview.shared_writes_blocked)}
              onSelect={() => {
                openingDialog.current = true;
                duplicate();
              }}
            >
              <CopyPlus />
              Duplicate host…
            </ContextMenuItem>
          )}
          {inspect && (
            <ContextMenuItem disabled={disabled} onSelect={() => {
              openingDialog.current = true;
              inspect();
            }}>
              <Info />
              Connection details
            </ContextMenuItem>
          )}
          {/* A host with a route is reached through it, so its saved hostname is never dialed and there is no address to copy. */}
          {!transportFor(overview, host.id) && (
            <ContextMenuItem
              disabled={disabled}
              onSelect={() => {
                void copyText(host.effective_payload.hostname).catch(() =>
                  setError("Could not copy the address. Please retry."),
                );
              }}
            >
              <Copy />
              Copy address
            </ContextMenuItem>
          )}
          <ContextMenuSeparator />
          <ContextMenuItem
            disabled={disabled || organizeDisabled || !accept}
            onSelect={() => open("group")}
          >
            <FolderInput />
            Move to group…
          </ContextMenuItem>
          <ContextMenuItem
            disabled={disabled || organizeDisabled || !accept}
            onSelect={() => open("tag")}
          >
            <Tag />
            Add tag…
          </ContextMenuItem>
          <ContextMenuSeparator />
          <ContextMenuItem
            variant="destructive"
            disabled={disabled || organizeDisabled || !accept}
            onSelect={() => open("delete")}
          >
            <Trash2 />
            Delete host…
          </ContextMenuItem>
        </ContextMenuContent>
      </ContextMenu>
      {error && (
        <p role="alert" className="text-xs text-destructive">
          {error}
        </p>
      )}
      <Dialog
        open={!!review}
        onOpenChange={(open) => {
          if (!open && !busy) setReview(null);
        }}
      >
        <DialogContent
          showCloseButton={!busy}
          onOpenAutoFocus={(event) => {
            event.preventDefault();
            cancel.current?.focus();
          }}
          onCloseAutoFocus={(event) => {
            event.preventDefault();
            if (trigger.current?.isConnected) trigger.current.focus();
            else returnFocus();
          }}
          onEscapeKeyDown={(event) => {
            if (busy) event.preventDefault();
          }}
          onInteractOutside={(event) => {
            if (busy) event.preventDefault();
          }}
        >
          <DialogTitle>
            {review?.action === "delete"
              ? "Delete host?"
              : review?.action === "group"
                ? "Move host to a Group"
                : "Add a tag"}
          </DialogTitle>
          <DialogDescription>
            <strong>{revealHidden(review?.host.payload.alias ?? "")}</strong>
            {review?.action === "delete"
              ? " will be removed from your library. This also syncs to your other devices when library sync is enabled. The server and saved keys are kept."
              : " — changes apply to this saved host. Grouping keeps current connection settings as host overrides."}
          </DialogDescription>
          {review?.action === "group" && (
            <label className="space-y-2 text-sm">
              Group
              <select
                aria-label="Destination Group"
                className={selectClass}
                value={group}
                onChange={(e) => setGroup(e.target.value)}
                disabled={busy || stale}
              >
                <option value="none">Ungrouped</option>
                {overview.groups
                  .filter(
                    (g) => !g.group_error && selectGroup(overview.groups, g.id),
                  )
                  .map((g) => (
                    <option key={g.id} value={g.id}>
                      {revealHidden(g.payload.name)}
                    </option>
                  ))}
              </select>
            </label>
          )}
          {review?.action === "tag" && (
            <Input
              aria-label="Tag to add"
              value={tag}
              onChange={(e) => setTag(e.target.value)}
              disabled={busy || stale}
            />
          )}
          {stale && (
            <p role="status" className="text-sm text-muted-foreground">
              This host changed. Close this dialog and reopen its menu to review
              the latest saved version.
            </p>
          )}
          <DialogFooter>
            <Button
              ref={cancel}
              variant="outline"
              disabled={busy}
              onClick={() => setReview(null)}
            >
              Cancel
            </Button>
            <Button
              variant={review?.action === "delete" ? "destructive" : "default"}
              disabled={
                busy ||
                disabled ||
                organizeDisabled ||
                stale ||
                (review?.action === "tag" && !tag.trim())
              }
              onClick={() => void apply()}
            >
              {busy
                ? "Applying…"
                : review?.action === "delete"
                  ? "Delete host"
                  : "Apply"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </>
  );
}
