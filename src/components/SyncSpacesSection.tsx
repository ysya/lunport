import { useState, type ReactNode } from "react";
import { FolderInput, Loader2, MoreHorizontal, Pencil, Plus, Trash2 } from "lucide-react";
import { toast } from "sonner";

import type { SyncOverview } from "@/bindings/SyncOverview";
import type { SyncSpaceView } from "@/bindings/SyncSpaceView";
import { isImeKey } from "@/lib/ime";
import { errorMessage, useCreateSpace, useDeleteSpace, useRebuildSpace, useRenameSpace, useSelectSpace, useUnselectSpace } from "@/lib/sync";
import { revealHidden } from "@/lib/sync-approvals";
import { plural } from "@/lib/sync-overview";
import {
  chooseFailures,
  createdSpaceToast,
  deleteSpaceTitle,
  deletedSpaceToast,
  renameSpaceTitle,
  renamedSpaceToast,
  spaceNameError,
  spaceRows,
  stopSyncingTitle,
  structureLock,
  syncedOnText,
  unselectNote,
  type SpaceRow,
} from "@/lib/sync-spaces";
import { useLastNonNull } from "@/lib/use-last-non-null";
import { useUiStore } from "@/stores/ui";
import { cn } from "@/lib/utils";
import { Section, SettingsGroup, SettingsRow } from "@/components/settings-primitives";
import { TONE_TEXT } from "@/components/sync-primitives";
import { Button } from "@/components/ui/button";
import { Checkbox } from "@/components/ui/checkbox";
import { Input } from "@/components/ui/input";
import { Switch } from "@/components/ui/switch";
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuSeparator, DropdownMenuTrigger } from "@/components/ui/dropdown-menu";
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

type Naming = { mode: "create" } | { mode: "rename"; row: SpaceRow };

/**
 * Settings → Sync → Spaces (spec §8): each space with its file, host count and
 * the computers that sync it; a switch turns it on or off for THIS computer;
 * rename, delete (everywhere) and "New space". Unselecting and deleting are
 * confirmed first, with copy that says exactly which computers lose what.
 */
export function SpacesSection({ overview: o }: { overview: SyncOverview }) {
  const select = useSelectSpace();
  const rebuild = useRebuildSpace();
  const openMigration = useUiStore((s) => s.setSyncMigration);
  const [naming, setNaming] = useState<Naming | null>(null);
  const [unselecting, setUnselecting] = useState<SpaceRow | null>(null);
  const [deleting, setDeleting] = useState<SpaceRow | null>(null);
  const lock = structureLock(o);
  const rows = spaceRows(o);

  return (
    <Section
      title="Spaces"
      description="Each space is a group of hosts with its own file in ~/.ssh/sshelter. Turn a space on to sync it on this computer; turning it off removes only this computer's file."
    >
      <SettingsGroup>
        {rows.length === 0 && (
          <p className="px-3 py-3 text-sm text-muted-foreground">This sync account has no spaces yet. Create one to start syncing hosts.</p>
        )}
        {rows.map((row) => (
          <div key={row.id} className="flex items-start justify-between gap-4 px-3 py-2">
            <div className="min-w-0 space-y-0.5 select-none">
              <p className="truncate text-sm">{row.label}</p>
              <p className="truncate text-xs text-muted-foreground" title={`${row.detail} · ${row.syncedOn}`}>
                {row.detail} · {row.syncedOn}
              </p>
              {row.status && <p className={cn("text-xs", TONE_TEXT[row.status.tone])}>{row.status.text}</p>}
              {row.missing && (
                <div className="flex gap-1.5 pt-1">
                  <Button type="button" variant="outline" size="sm" className="h-7" disabled={lock !== null || rebuild.isPending} onClick={() => rebuild.mutate({ spaceId: row.id })}>
                    {rebuild.isPending && rebuild.variables?.spaceId === row.id && <Loader2 className="size-3.5 animate-spin" />} Rebuild from this computer
                  </Button>
                  <Button type="button" variant="outline" size="sm" className="h-7 text-destructive hover:text-destructive" disabled={lock !== null} onClick={() => setDeleting(row)}>
                    Delete space…
                  </Button>
                </div>
              )}
            </div>
            <div className="flex shrink-0 items-center gap-1 pt-0.5">
              <Switch
                checked={row.selected}
                disabled={lock !== null || select.isPending}
                aria-label={`Sync ${row.label} on this computer`}
                onCheckedChange={(on) => (on ? select.mutate({ spaceId: row.id }) : setUnselecting(row))}
              />
              <DropdownMenu>
                <DropdownMenuTrigger asChild>
                  <Button type="button" variant="ghost" size="icon" className="size-7 text-muted-foreground" aria-label={`Actions for ${row.label}`} disabled={lock !== null}>
                    <MoreHorizontal className="size-3.5" />
                  </Button>
                </DropdownMenuTrigger>
                <DropdownMenuContent align="end">
                  <DropdownMenuItem onSelect={() => setNaming({ mode: "rename", row })}>
                    <Pencil className="size-3.5" /> Rename…
                  </DropdownMenuItem>
                  {row.selected && !row.missing && (
                    <DropdownMenuItem onSelect={() => openMigration({ spaceId: row.id })}>
                      <FolderInput className="size-3.5" /> Move hosts here…
                    </DropdownMenuItem>
                  )}
                  <DropdownMenuSeparator />
                  <DropdownMenuItem variant="destructive" onSelect={() => setDeleting(row)}>
                    <Trash2 className="size-3.5" /> Delete…
                  </DropdownMenuItem>
                </DropdownMenuContent>
              </DropdownMenu>
            </div>
          </div>
        ))}
        <SettingsRow label="New space" description={lock ?? "Starts empty and syncs on this computer."}>
          <Button type="button" variant="outline" size="sm" className="h-7" disabled={lock !== null} onClick={() => setNaming({ mode: "create" })}>
            <Plus className="size-3.5" /> New space…
          </Button>
        </SettingsRow>
        <SettingsRow label="Move hosts into a space" description={lock ?? "Choose which of this computer's hosts should follow you to your other computers."}>
          <Button type="button" variant="outline" size="sm" className="h-7" disabled={lock !== null} onClick={() => openMigration({ spaceId: null })}>
            Choose hosts…
          </Button>
        </SettingsRow>
      </SettingsGroup>

      <NamingDialog naming={naming} spaces={o.spaces} onClose={() => setNaming(null)} />
      <UnselectDialog row={unselecting} onClose={() => setUnselecting(null)} />
      <DeleteDialog row={deleting} onClose={() => setDeleting(null)} />
    </Section>
  );
}

/**
 * New space / Rename. The dialog owns the request, not the form: this is where a dismissal (Esc, a click
 * outside, the close button, Cancel) is refused while it runs — closing then would lose the toast, and
 * opening "New space…" again with the same name would meet the space that is being created.
 */
function NamingDialog({ naming, spaces, onClose }: { naming: Naming | null; spaces: SyncSpaceView[]; onClose: () => void }) {
  const create = useCreateSpace();
  const rename = useRenameSpace();
  const busy = create.isPending || rename.isPending;
  // Kept while the dialog animates out, so it does not go empty.
  const shown = useLastNonNull(naming);

  const submit = (name: string) => {
    if (!shown) return;
    if (shown.mode === "create") {
      create.mutate(
        { name },
        {
          onSuccess: () => {
            toast.success(createdSpaceToast(name));
            onClose();
          },
        },
      );
    } else {
      rename.mutate(
        { spaceId: shown.row.id, name },
        {
          onSuccess: () => {
            toast.success(renamedSpaceToast(name));
            onClose();
          },
        },
      );
    }
  };

  return (
    <Dialog
      open={naming !== null}
      onOpenChange={(open) => {
        if (!open && !busy) onClose();
      }}
    >
      <DialogContent className="sm:max-w-sm" showCloseButton={!busy}>
        {shown && (
          <SpaceNameForm key={shown.mode === "rename" ? shown.row.id : "new"} naming={shown} spaces={spaces} busy={busy} onSubmit={submit} onCancel={onClose} />
        )}
      </DialogContent>
    </Dialog>
  );
}

function SpaceNameForm({
  naming,
  spaces,
  busy,
  onSubmit,
  onCancel,
}: {
  naming: Naming;
  spaces: SyncSpaceView[];
  busy: boolean;
  onSubmit: (name: string) => void;
  onCancel: () => void;
}) {
  const current = naming.mode === "rename" ? naming.row.name : "";
  const [name, setName] = useState(current);
  const error = spaceNameError(name, spaces, naming.mode === "rename" ? naming.row.id : undefined);
  const disabled = error !== null || name.trim() === current || busy;

  const submit = () => {
    if (!disabled) onSubmit(name.trim());
  };

  return (
    <>
      <DialogHeader>
        <DialogTitle>{naming.mode === "create" ? "New space" : renameSpaceTitle(naming.row)}</DialogTitle>
        <DialogDescription>
          {naming.mode === "create"
            ? "The space starts empty and syncs on this computer. Its file in ~/.ssh/sshelter is named after it."
            : "Every computer that syncs this space renames its file to match."}
        </DialogDescription>
      </DialogHeader>
      <Input
        autoFocus
        value={name}
        onChange={(e) => setName(e.target.value)}
        onKeyDown={(e) => {
          // The Enter that commits a Chinese, Japanese or Korean composition is part of the typing, not a submit.
          if (e.key === "Enter" && !isImeKey(e)) submit();
        }}
        aria-label="Space name"
        placeholder="Work"
        className="h-8"
      />
      {name.trim() !== "" && error && <p className="text-xs text-destructive">{error}</p>}
      <DialogFooter>
        <Button type="button" variant="outline" disabled={busy} onClick={onCancel}>
          Cancel
        </Button>
        <Button type="button" disabled={disabled} onClick={submit}>
          {busy && <Loader2 className="size-4 animate-spin" />} {naming.mode === "create" ? "Create" : "Rename"}
        </Button>
      </DialogFooter>
    </>
  );
}

/**
 * The confirm shared by turning a space off and deleting it: it cannot be dismissed while the request
 * runs, stays open until the answer comes, and keeps the row it was opened for while it animates out
 * (a null row would print "Stop syncing “”…").
 */
function SpaceConfirmDialog({
  row,
  onClose,
  pending,
  title,
  description,
  confirm,
  destructive = false,
  run,
}: {
  row: SpaceRow | null;
  onClose: () => void;
  pending: boolean;
  title: (row: SpaceRow) => string;
  description: (row: SpaceRow) => ReactNode;
  confirm: string;
  destructive?: boolean;
  /** Starts the request; `done` closes the dialog once it succeeded. */
  run: (row: SpaceRow, done: () => void) => void;
}) {
  const shown = useLastNonNull(row);
  return (
    <AlertDialog
      open={row !== null}
      onOpenChange={(open) => {
        if (!open && !pending) onClose();
      }}
    >
      <AlertDialogContent>
        <AlertDialogHeader>
          <AlertDialogTitle>{shown && title(shown)}</AlertDialogTitle>
          <AlertDialogDescription>{shown && description(shown)}</AlertDialogDescription>
        </AlertDialogHeader>
        <AlertDialogFooter>
          <AlertDialogCancel disabled={pending}>Cancel</AlertDialogCancel>
          <AlertDialogAction
            variant={destructive ? "destructive" : "default"}
            disabled={pending}
            onClick={(e) => {
              // Keep the dialog open until the request settles.
              e.preventDefault();
              if (shown) run(shown, onClose);
            }}
          >
            {pending && <Loader2 className="size-3.5 animate-spin" />} {confirm}
          </AlertDialogAction>
        </AlertDialogFooter>
      </AlertDialogContent>
    </AlertDialog>
  );
}

/** Turning a space off removes only this computer's file (backed up first); the space stays everywhere else. */
function UnselectDialog({ row, onClose }: { row: SpaceRow | null; onClose: () => void }) {
  const unselect = useUnselectSpace();
  return (
    <SpaceConfirmDialog
      row={row}
      onClose={onClose}
      pending={unselect.isPending}
      title={stopSyncingTitle}
      description={(r) => (
        <>
          <span className="font-mono">{r.fileName}</span> {unselectNote(r)}
        </>
      )}
      confirm="Remove from this computer"
      run={(r, done) => unselect.mutate({ spaceId: r.id }, { onSuccess: done })}
    />
  );
}

/** Deleting removes the space on every computer and on the relay. */
function DeleteDialog({ row, onClose }: { row: SpaceRow | null; onClose: () => void }) {
  const del = useDeleteSpace();
  return (
    <SpaceConfirmDialog
      row={row}
      onClose={onClose}
      pending={del.isPending}
      title={deleteSpaceTitle}
      description={() =>
        "The space and its hosts are removed from every computer that syncs it — each one backs up its file first — and from the relay. This can't be undone. To stop syncing it only on this computer, turn it off instead."
      }
      confirm="Delete space"
      destructive
      run={(r, done) =>
        del.mutate(
          { spaceId: r.id },
          {
            onSuccess: () => {
              toast.success(deletedSpaceToast(r));
              done();
            },
          },
        )
      }
    />
  );
}

/**
 * Right after joining (which selects no space): pick the spaces to sync here.
 * Every space starts checked; each one chosen gets its file and a first sync.
 * `onClose` is called once per opening, with the ids that were turned on (none
 * when the user leaves without choosing). While the spaces are being turned on
 * the dialog cannot be dismissed (Esc, a click outside, the close button): it
 * would close before the result is known, and `onClose` would be called a second
 * time when the last space is done.
 */
export function ChooseSpacesDialog({ open, overview, onClose }: { open: boolean; overview: SyncOverview | undefined; onClose: (selected: string[]) => void }) {
  // Owned here, not by the form: this is where a dismissal is refused.
  const [busy, setBusy] = useState(false);
  return (
    <Dialog
      open={open}
      onOpenChange={(next) => {
        if (!next && !busy) onClose([]);
      }}
    >
      <DialogContent className="sm:max-w-md" showCloseButton={!busy}>
        {/* Not tied to `open`: Radix unmounts the content once the exit animation is done, so the form stays on screen while it fades and starts afresh at the next opening. */}
        {overview && <ChooseSpacesForm overview={overview} busy={busy} setBusy={setBusy} onClose={onClose} />}
      </DialogContent>
    </Dialog>
  );
}

function ChooseSpacesForm({
  overview,
  busy,
  setBusy,
  onClose,
}: {
  overview: SyncOverview;
  busy: boolean;
  setBusy: (busy: boolean) => void;
  onClose: (selected: string[]) => void;
}) {
  // Quiet: the failures are reported once, after the loop, not one toast each.
  const select = useSelectSpace(true);
  // Fixed when the dialog opens: each space drops out of `overview` as soon as it is turned on.
  const [candidates] = useState(() => overview.spaces.filter((s) => !s.selected));
  const [chosen, setChosen] = useState(() => new Set(candidates.map((s) => s.id)));
  // Every call would be refused while the account cannot change its spaces (a newer format right after joining, say).
  const lock = structureLock(overview);

  const toggle = (id: string, on: boolean) =>
    setChosen((prev) => {
      const next = new Set(prev);
      if (on) next.add(id);
      else next.delete(id);
      return next;
    });

  const run = async () => {
    setBusy(true);
    const done: string[] = [];
    const failed: { id: string; name: string; message: string }[] = [];
    for (const s of candidates.filter((c) => chosen.has(c.id))) {
      try {
        await select.mutateAsync({ spaceId: s.id });
        done.push(s.id);
      } catch (error) {
        failed.push({ id: s.id, name: s.name, message: errorMessage(error) });
      }
    }
    setBusy(false);
    const summary = chooseFailures(failed);
    if (summary) toast.error(summary.title, { description: summary.description });
    onClose(done);
  };

  return (
    <>
      <DialogHeader>
        <DialogTitle>Choose spaces for this computer</DialogTitle>
        <DialogDescription>
          Each space you choose gets its own file in ~/.ssh/sshelter and syncs from now on. You can change this any time under Settings → Sync → Spaces.
        </DialogDescription>
      </DialogHeader>
      {candidates.length === 0 ? (
        <p className="text-sm text-muted-foreground">This sync account has no spaces yet. Create one under Spaces.</p>
      ) : (
        <div className="max-h-[40vh] space-y-2 overflow-y-auto pr-1">
          {candidates.map((s) => (
            <label key={s.id} className="flex items-start gap-2 text-sm">
              <Checkbox className="mt-0.5" checked={chosen.has(s.id)} disabled={busy} onCheckedChange={(v) => toggle(s.id, v === true)} />
              <span className="min-w-0">
                <span className="block truncate">{revealHidden(s.name)}</span>
                <span className="block truncate text-xs text-muted-foreground">{syncedOnText(s.synced_on)}</span>
              </span>
            </label>
          ))}
        </div>
      )}
      {lock && <p className={cn("text-sm", TONE_TEXT.warning)}>{lock}</p>}
      <DialogFooter>
        <Button type="button" variant="outline" disabled={busy} onClick={() => onClose([])}>
          Not now
        </Button>
        {candidates.length > 0 && (
          <Button type="button" disabled={busy || lock !== null || chosen.size === 0} onClick={() => void run()}>
            {busy && <Loader2 className="size-4 animate-spin" />} Sync {plural(chosen.size, "space")}
          </Button>
        )}
      </DialogFooter>
    </>
  );
}
