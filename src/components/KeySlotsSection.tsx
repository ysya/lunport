import { useState } from "react";
import { open as openFileDialog } from "@tauri-apps/plugin-dialog";
import { toast } from "sonner";

import type { AgentProblem } from "@/bindings/AgentProblem";
import type { KeyInfo } from "@/bindings/KeyInfo";
import type { SyncKeySlotView } from "@/bindings/SyncKeySlotView";
import { TONE_TEXT } from "@/components/sync-primitives";
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
import { Button } from "@/components/ui/button";
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { agentProblemText, useAgentProblem, useFixAgentInclude } from "@/lib/agent";
import { deliveryAction, deliveryLine, deviceLine, hostsLine, slotActions, slotStatusText, syncConfirmText } from "@/lib/key-slots";
import { useKeys } from "@/lib/queries";
import { useKeyDeleteCopy, useKeyPick, useKeySetDelivery, useKeySetMode, useKeyUseSynced, useSyncOverview } from "@/lib/sync";
import { revealHidden } from "@/lib/sync-approvals";
import { useLastNonNull } from "@/lib/use-last-non-null";
import { cn } from "@/lib/utils";

export type SlotAction = "sync" | "stop" | "pick" | "useSynced" | "syncNew" | "delete" | "vault" | "file";

/** One slot in the Keys dialog. Exported for the markup tests. */
export function KeySlotRow({ slot, busy, onAction }: { slot: SyncKeySlotView; busy: boolean; onAction: (action: SlotAction) => void }) {
  const status = slotStatusText(slot.status);
  // The file this computer uses, for the states that name one (spec §7.2: "the file this computer uses and its state").
  const file = "file" in slot.status ? slot.status.file : null;
  const actions = slotActions(slot);
  const delivery = deliveryAction(slot);
  const kept = deliveryLine(slot);
  const hosts = hostsLine(slot);
  const devices = deviceLine(slot);
  const button = (action: SlotAction, label: string, variant: "outline" | "ghost" = "outline", extra = "") => (
    <Button type="button" size="sm" variant={variant} className={cn("h-7", extra)} disabled={busy} onClick={() => onAction(action)}>
      {label}
    </Button>
  );
  return (
    <div className="flex items-start justify-between gap-3 px-3 py-2">
      <div className="min-w-0 space-y-0.5">
        <p className="truncate font-mono text-sm">{revealHidden(slot.name)}</p>
        <p className="text-xs break-all text-muted-foreground">
          {slot.mode === "synced" ? "Synced to your computers" : "Each computer uses its own key"}
          {slot.fingerprint ? ` · ${slot.fingerprint}` : ""}
        </p>
        <p className={cn("text-xs", TONE_TEXT[status.tone])}>{status.text}</p>
        {kept && <p className="text-xs text-muted-foreground">{kept}</p>}
        {file && <p className="font-mono text-xs break-all text-muted-foreground">{file}</p>}
        {hosts && <p className="text-xs text-muted-foreground">{hosts}</p>}
        {devices && <p className="text-xs text-muted-foreground">{devices}</p>}
      </div>
      <div className="flex shrink-0 flex-wrap justify-end gap-1">
        {actions.syncThis && button("sync", "Sync this key")}
        {actions.syncNew && button("syncNew", "Sync the new key")}
        {actions.useSynced && button("useSynced", "Use the synced key")}
        {actions.pick && button("pick", actions.pick === "pick" ? "Pick a key on this computer…" : "Change…")}
        {delivery === "vault" && button("vault", "Only in SSHelter")}
        {delivery === "file" && button("file", "Keep a file")}
        {actions.stopSyncing && button("stop", "Stop syncing", "ghost")}
        {actions.deleteCopy && button("delete", "Delete copy", "ghost", "text-destructive hover:text-destructive")}
      </div>
    </div>
  );
}

/**
 * The keys of this computer to pick from: a note while they are scanned and when there are none (the likely case on a
 * computer that just joined), otherwise one button per key. Exported for the markup tests.
 */
export function KeyChoices({
  keys,
  loading,
  busy,
  onChoose,
}: {
  keys: KeyInfo[] | undefined;
  loading: boolean;
  busy: boolean;
  onChoose: (path: string) => void;
}) {
  if (loading || !keys || keys.length === 0) {
    return (
      <p className="py-6 text-center text-sm text-muted-foreground select-none">
        {loading ? "Scanning keys…" : "No private keys in ~/.ssh. Choose one with Browse…"}
      </p>
    );
  }
  return (
    <div className="settings-group max-h-[40vh] overflow-y-auto">
      {keys.map((k) => (
        <button
          key={k.private_path}
          type="button"
          disabled={busy}
          className="flex w-full flex-col items-start px-3 py-2 text-left hover:bg-muted/60"
          onClick={() => onChoose(k.private_path)}
        >
          <span className="font-mono text-sm">{k.name}</span>
          <span className="text-xs break-all text-muted-foreground">{k.fingerprint_sha256 ?? k.private_path}</span>
        </button>
      ))}
    </div>
  );
}

/** Pick one of this computer's keys for a slot (only this computer changes). */
export function PickKeyDialog({ slot, onClose }: { slot: SyncKeySlotView | null; onClose: () => void }) {
  const keys = useKeys({ enabled: slot !== null });
  const pick = useKeyPick();
  const name = slot ? revealHidden(slot.name) : "";
  const choose = (path: string) => {
    if (!slot) return;
    const file = path.split(/[\\/]/).pop() ?? path;
    pick.mutate({ slotId: slot.id, path }, { onSuccess: () => { toast.success(`${name} uses ${file} on this computer`); onClose(); } });
  };
  const browse = async () => {
    const picked = await openFileDialog({ multiple: false, directory: false, title: "Choose a private key" });
    if (typeof picked === "string") choose(picked);
  };
  const replacesCopy = slot?.status.kind === "ready" && slot.status.synced_copy;
  return (
    <Dialog open={slot !== null} onOpenChange={(next) => !next && !pick.isPending && onClose()}>
      <DialogContent className="sm:max-w-md" showCloseButton={!pick.isPending}>
        <DialogHeader>
          <DialogTitle>Pick a key on this computer</DialogTitle>
          <DialogDescription>Hosts that use {name} will use the key you pick, on this computer only.</DialogDescription>
        </DialogHeader>
        {replacesCopy && <p className="text-sm text-muted-foreground">The synced copy on this computer is kept as a .previous file.</p>}
        <KeyChoices keys={keys.data} loading={keys.isLoading} busy={pick.isPending} onChoose={choose} />
        <DialogFooter>
          <Button type="button" variant="outline" disabled={pick.isPending} onClick={() => void browse()}>
            Browse…
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

/**
 * The confirm before "Sync this key" / "Sync the new key" upload this computer's key to the account: once it syncs it
 * can't be taken back (stopping never deletes the copies), so say which key and whether a passphrase still protects it.
 * `slot` is what to show (it stays set while the dialog closes); `open` whether it shows. No hooks: exported for the tests.
 */
export function SyncKeyConfirm({
  slot,
  open,
  onCancel,
  onConfirm,
}: {
  slot: SyncKeySlotView | null;
  open: boolean;
  onCancel: () => void;
  onConfirm: () => void;
}) {
  const text = slot ? syncConfirmText(slot) : null;
  return (
    <AlertDialog open={open} onOpenChange={(next) => !next && onCancel()}>
      {/* Without a passphrase note nothing describes the dialog: say so, or Radix warns that the description is missing. */}
      <AlertDialogContent {...(text?.description ? {} : { "aria-describedby": undefined })}>
        <AlertDialogHeader>
          <AlertDialogTitle>{text?.title}</AlertDialogTitle>
          {text?.description && <AlertDialogDescription>{text.description}</AlertDialogDescription>}
        </AlertDialogHeader>
        <AlertDialogFooter>
          <AlertDialogCancel>Cancel</AlertDialogCancel>
          <AlertDialogAction onClick={onConfirm}>Sync key</AlertDialogAction>
        </AlertDialogFooter>
      </AlertDialogContent>
    </AlertDialog>
  );
}

/**
 * The confirm before this computer's copy of a key is deleted. It says nothing about the original key: for a copy whose
 * original was replaced or removed, this copy may be the last one. A key kept only in SSHelter says that the vault entry
 * is what goes, and that it may be the last copy. No hooks: exported for the tests.
 */
export function DeleteCopyConfirm({
  slot,
  open,
  onCancel,
  onConfirm,
}: {
  slot: SyncKeySlotView | null;
  open: boolean;
  onCancel: () => void;
  onConfirm: () => void;
}) {
  return (
    <AlertDialog open={open} onOpenChange={(next) => !next && onCancel()}>
      <AlertDialogContent>
        <AlertDialogHeader>
          <AlertDialogTitle>Delete this copy?</AlertDialogTitle>
          <AlertDialogDescription>
            {slot?.in_vault
              ? `The key ${revealHidden(slot.name)} kept in SSHelter on this computer is deleted. If it is your only copy, it is gone. Other computers aren't affected.`
              : `The copy of ${slot ? revealHidden(slot.name) : ""} on this computer is deleted. Other computers aren't affected.`}
          </AlertDialogDescription>
        </AlertDialogHeader>
        <AlertDialogFooter>
          <AlertDialogCancel>Cancel</AlertDialogCancel>
          <AlertDialogAction variant="destructive" onClick={onConfirm}>
            Delete copy
          </AlertDialogAction>
        </AlertDialogFooter>
      </AlertDialogContent>
    </AlertDialog>
  );
}

/** The confirm before a vault key becomes a file again: any program can use a file without asking. No hooks: exported for the tests. */
export function KeepFileConfirm({
  slot,
  open,
  onCancel,
  onConfirm,
}: {
  slot: SyncKeySlotView | null;
  open: boolean;
  onCancel: () => void;
  onConfirm: () => void;
}) {
  return (
    <AlertDialog open={open} onOpenChange={(next) => !next && onCancel()}>
      <AlertDialogContent>
        <AlertDialogHeader>
          <AlertDialogTitle>Keep {slot ? revealHidden(slot.name) : ""} as a file?</AlertDialogTitle>
          <AlertDialogDescription>Any program on this computer can use the file without asking.</AlertDialogDescription>
        </AlertDialogHeader>
        <AlertDialogFooter>
          <AlertDialogCancel>Cancel</AlertDialogCancel>
          <AlertDialogAction onClick={onConfirm}>Keep a file</AlertDialogAction>
        </AlertDialogFooter>
      </AlertDialogContent>
    </AlertDialog>
  );
}

/** Why ssh can't reach SSHelter's agent (key vault spec §6, §11), with Fix when the Include line was removed. Exported for the tests. */
export function AgentProblemLine({ problem, busy, onFix }: { problem: AgentProblem; busy: boolean; onFix: () => void }) {
  return (
    <div className="flex items-center justify-between gap-3 px-1">
      <p className={cn("text-xs", TONE_TEXT.error)}>{agentProblemText(problem)}</p>
      {problem.kind === "include_missing" && (
        <Button type="button" size="sm" variant="outline" className="h-7 shrink-0" disabled={busy} onClick={onFix}>
          Fix
        </Button>
      )}
    </div>
  );
}

/** "Keys used by synced hosts" in the Keys dialog (SP3 spec §7.2). Nothing while there are no slots. */
export function KeySlotsSection() {
  const overview = useSyncOverview();
  const setMode = useKeySetMode();
  const switchToSynced = useKeyUseSynced();
  const deleteCopy = useKeyDeleteCopy();
  const delivery = useKeySetDelivery();
  const fix = useFixAgentInclude();
  const [picking, setPicking] = useState<SyncKeySlotView | null>(null);
  const [syncing, setSyncing] = useState<SyncKeySlotView | null>(null);
  const [deleting, setDeleting] = useState<SyncKeySlotView | null>(null);
  const [keeping, setKeeping] = useState<SyncKeySlotView | null>(null);
  // What the confirms show while they animate out (their slot state is already null by then).
  const shownSyncing = useLastNonNull(syncing);
  const shownDeleting = useLastNonNull(deleting);
  const shownKeeping = useLastNonNull(keeping);
  const slots = overview.data?.joined ? overview.data.key_slots : [];
  const anyInVault = slots.some((s) => s.in_vault);
  // Asked only while a key is in the vault; a hook, so it comes before the early return below.
  const problemQuery = useAgentProblem(anyInVault);
  const problem = anyInVault ? (problemQuery.data ?? null) : null;
  if (slots.length === 0) return null;
  const busy = setMode.isPending || switchToSynced.isPending || deleteCopy.isPending || delivery.isPending || fix.isPending;
  const act = (slot: SyncKeySlotView, action: SlotAction) => {
    const name = revealHidden(slot.name);
    switch (action) {
      case "sync":
      case "syncNew":
        // Uploading a private key can't be taken back: ask first (`SyncKeyConfirm`).
        setSyncing(slot);
        break;
      case "stop":
        setMode.mutate({ slotId: slot.id, mode: "own" }, { onSuccess: () => toast.success(`${name} no longer syncs; computers that have it keep their copy`) });
        break;
      case "pick":
        setPicking(slot);
        break;
      case "useSynced":
        switchToSynced.mutate({ slotId: slot.id }, { onSuccess: () => toast.success(`${name} uses the synced key on this computer`) });
        break;
      case "delete":
        setDeleting(slot);
        break;
      case "vault":
        delivery.mutate(
          { slotId: slot.id, vault: true },
          {
            onSuccess: () =>
              toast.success(
                `${name} is now only in SSHelter on this computer`,
                anyInVault
                  ? undefined
                  : {
                      description:
                        "Hosts that use it connect only while SSHelter is open. In Settings, turn on Launch at login and Keep running in menu bar when window closes.",
                    },
              ),
          },
        );
        break;
      case "file":
        // A file can be used by any program without asking: confirm first (`KeepFileConfirm`).
        setKeeping(slot);
        break;
    }
  };
  return (
    <section className="space-y-1.5">
      <h3 className="px-1 text-xs font-medium text-muted-foreground select-none">Keys used by synced hosts</h3>
      {problem && <AgentProblemLine problem={problem} busy={busy} onFix={() => fix.mutate()} />}
      {/* Capped like the key list above it, so a long list scrolls here instead of pushing the dialog off the window. */}
      <div className="-mx-1 max-h-[30vh] overflow-y-auto px-1">
        <div className="settings-group">
          {slots.map((slot) => (
            <KeySlotRow key={slot.id} slot={slot} busy={busy} onAction={(action) => act(slot, action)} />
          ))}
        </div>
      </div>
      <PickKeyDialog slot={picking} onClose={() => setPicking(null)} />
      <SyncKeyConfirm
        slot={shownSyncing}
        open={syncing !== null}
        onCancel={() => setSyncing(null)}
        onConfirm={() => {
          if (syncing) {
            const name = revealHidden(syncing.name);
            setMode.mutate({ slotId: syncing.id, mode: "synced" }, { onSuccess: () => toast.success(`${name} syncs to your other computers`) });
          }
          setSyncing(null);
        }}
      />
      <DeleteCopyConfirm
        slot={shownDeleting}
        open={deleting !== null}
        onCancel={() => setDeleting(null)}
        onConfirm={() => {
          if (deleting) deleteCopy.mutate({ slotId: deleting.id });
          setDeleting(null);
        }}
      />
      <KeepFileConfirm
        slot={shownKeeping}
        open={keeping !== null}
        onCancel={() => setKeeping(null)}
        onConfirm={() => {
          if (keeping) {
            const name = revealHidden(keeping.name);
            delivery.mutate({ slotId: keeping.id, vault: false }, { onSuccess: () => toast.success(`${name} is kept as a file on this computer`) });
          }
          setKeeping(null);
        }}
      />
    </section>
  );
}
