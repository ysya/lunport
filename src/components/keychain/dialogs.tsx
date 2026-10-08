import { useState } from "react";
import { open as openFileDialog } from "@tauri-apps/plugin-dialog";
import { toast } from "sonner";

import type { KeyInfo } from "@/bindings/KeyInfo";
import type { SyncKeySlotView } from "@/bindings/SyncKeySlotView";
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
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { syncConfirmText } from "@/lib/key-slots";
import { useGenerateKey, useGenerateKeyInTerminal, useKeys } from "@/lib/queries";
import { errorMessage, exportPrivateKey, useKeyPick } from "@/lib/sync";
import { revealHidden } from "@/lib/sync-approvals";
import { useSettingsStore } from "@/stores/settings";
import { useUiStore } from "@/stores/ui";

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
  const note = slot ? replacedKeyNote(slot) : null;
  return (
    <Dialog open={slot !== null} onOpenChange={(next) => !next && !pick.isPending && onClose()}>
      <DialogContent className="sm:max-w-md" showCloseButton={!pick.isPending}>
        <DialogHeader>
          <DialogTitle>Pick a key on this computer</DialogTitle>
          <DialogDescription>
            Hosts that use {name} will use the key you pick, on this computer only. SSHelter keeps a copy of it; your file stays where it is.
          </DialogDescription>
        </DialogHeader>
        {note && <p className="text-sm text-muted-foreground">{note}</p>}
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
 * The confirm before the detail's "Sync to your computers" / "Sync the new key" upload this computer's key to the account: once it
 * syncs it can't be taken back (stopping never deletes the copies), so say which key and whether a passphrase still protects it.
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

/** What happens to the key a pick replaces on this computer (key vault spec §4.3); null when there is none to keep. */
export function replacedKeyNote(slot: SyncKeySlotView): string | null {
  if (slot.in_vault) return "SSHelter keeps the key it replaces.";
  return slot.status.kind === "ready" && slot.status.synced_copy ? "The synced copy on this computer is kept as a .previous file." : null;
}

/**
 * Export private key (key vault spec §7.3.2): what an exported file means, and, for a key without a passphrase, an optional one
 * typed twice (a typo would lock the file for good). No hooks: exported for the tests.
 */
export function ExportPrivateKeyForm({
  name,
  hasPassphrase,
  passphrase,
  repeat,
  busy,
  onPassphrase,
  onRepeat,
  onExport,
  onCancel,
}: {
  name: string;
  /** The key in SSHelter has a passphrase (`SyncKeySlotView.vault_has_passphrase`). */
  hasPassphrase: boolean | null;
  passphrase: string;
  repeat: string;
  busy: boolean;
  onPassphrase: (value: string) => void;
  onRepeat: (value: string) => void;
  onExport: () => void;
  onCancel: () => void;
}) {
  return (
    <>
      <DialogHeader>
        <DialogTitle>Export {revealHidden(name)}?</DialogTitle>
        <DialogDescription>{"Any program can use the exported file without asking, and SSHelter won't keep track of it."}</DialogDescription>
      </DialogHeader>
      {hasPassphrase === true && <p className="text-sm text-muted-foreground">It stays protected by its passphrase.</p>}
      {hasPassphrase === false && (
        <div className="space-y-3">
          <div className="space-y-1.5">
            <Label htmlFor="export-passphrase">Add a passphrase (optional)</Label>
            <Input id="export-passphrase" type="password" autoComplete="new-password" value={passphrase} onChange={(e) => onPassphrase(e.target.value)} />
          </div>
          {passphrase !== "" && (
            <div className="space-y-1.5">
              <Label htmlFor="export-passphrase-repeat">Repeat the passphrase</Label>
              <Input id="export-passphrase-repeat" type="password" autoComplete="new-password" value={repeat} onChange={(e) => onRepeat(e.target.value)} />
            </div>
          )}
        </div>
      )}
      <DialogFooter>
        <Button type="button" variant="outline" disabled={busy} onClick={onCancel}>
          Cancel
        </Button>
        <Button type="button" disabled={busy || (passphrase !== "" && passphrase !== repeat)} onClick={onExport}>
          Export…
        </Button>
      </DialogFooter>
    </>
  );
}

/**
 * Export private key: the backend opens the save dialog and writes the file. The form is mounted only while the dialog is open,
 * keyed by slot, so a typed passphrase goes when the dialog does. A cancelled save dialog leaves this one open.
 */
export function ExportPrivateKeyDialog({ slot, onClose }: { slot: SyncKeySlotView | null; onClose: () => void }) {
  return (
    <Dialog open={slot !== null} onOpenChange={(next) => !next && onClose()}>
      <DialogContent className="sm:max-w-md">{slot && <ExportPrivateKeyFlow key={slot.id} slot={slot} onClose={onClose} />}</DialogContent>
    </Dialog>
  );
}

function ExportPrivateKeyFlow({ slot, onClose }: { slot: SyncKeySlotView; onClose: () => void }) {
  const [passphrase, setPassphrase] = useState("");
  const [repeat, setRepeat] = useState("");
  const [busy, setBusy] = useState(false);
  const changePassphrase = (value: string) => {
    setPassphrase(value);
    // The repeat goes with an empty passphrase: a copy typed for an earlier one must not come back with the next.
    if (value === "") setRepeat("");
  };
  const run = async () => {
    setBusy(true);
    try {
      const path = await exportPrivateKey(slot.id, passphrase === "" ? null : passphrase);
      if (path !== null) {
        toast.success(`Exported ${revealHidden(slot.name)}`, { description: path });
        onClose();
      }
    } catch (error) {
      toast.error("Could not export the key", { description: revealHidden(errorMessage(error)) });
    } finally {
      setBusy(false);
    }
  };
  return (
    <ExportPrivateKeyForm
      name={slot.name}
      hasPassphrase={slot.vault_has_passphrase}
      passphrase={passphrase}
      repeat={repeat}
      busy={busy}
      onPassphrase={changePassphrase}
      onRepeat={setRepeat}
      onExport={() => void run()}
      onCancel={onClose}
    />
  );
}

/** New-key name rule — mirrors the backend gate (`^[A-Za-z0-9][A-Za-z0-9._-]*$`, no `.pub`). */
const KEY_NAME_RE = /^[A-Za-z0-9][A-Za-z0-9._-]*$/;

/**
 * "Generate a key file…" (key vault spec §7.2): a new ed25519 key file in ~/.ssh, at once without a passphrase or in Terminal with
 * one. SSHelter doesn't manage the file. Plan 2b generates keys straight into SSHelter and removes this.
 */
export function GenerateKeyFileDialog({
  open,
  onOpenChange,
  existingNames,
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  existingNames: string[];
}) {
  const [name, setName] = useState("");
  const [comment, setComment] = useState("");
  const generate = useGenerateKey();
  const generateInTerminal = useGenerateKeyInTerminal();
  const terminalId = useSettingsStore((s) => s.terminalId);
  const selectKey = useUiStore((s) => s.selectKey);
  const trimmed = name.trim();
  const validName = KEY_NAME_RE.test(trimmed) && !trimmed.endsWith(".pub");
  const taken = existingNames.includes(trimmed);
  const canSubmit = validName && !taken && !generate.isPending;
  const close = () => {
    setName("");
    setComment("");
    onOpenChange(false);
  };
  const handleGenerate = () => {
    generate.mutate(
      { name: trimmed, comment: comment.trim() || null },
      {
        onSuccess: (key) => {
          toast.success(`Generated ${key.name}`, { description: key.fingerprint_sha256 ?? undefined });
          selectKey({ kind: "file", path: key.private_path });
          close();
        },
      },
    );
  };
  const handleGenerateInTerminal = () => {
    generateInTerminal.mutate(
      { name: trimmed, comment: comment.trim() || null, terminalOverride: terminalId },
      {
        onSuccess: () => {
          toast.success("Opening terminal…", { description: "ssh-keygen will ask for a passphrase there." });
          close();
        },
      },
    );
  };
  return (
    <Dialog open={open} onOpenChange={(next) => (next ? onOpenChange(true) : close())}>
      <DialogContent className="sm:max-w-md">
        <DialogHeader>
          <DialogTitle>Generate a key file</DialogTitle>
          <DialogDescription>{"A new ed25519 key in ~/.ssh. SSHelter doesn't manage it: any program can use it without asking."}</DialogDescription>
        </DialogHeader>
        <div className="flex gap-2">
          <Input
            value={name}
            onChange={(e) => setName(e.target.value)}
            placeholder="id_ed25519_work"
            aria-label="New key name"
            spellCheck={false}
            autoCorrect="off"
            autoCapitalize="off"
            className="h-7 flex-1 font-mono text-sm"
          />
          <Input value={comment} onChange={(e) => setComment(e.target.value)} placeholder="Comment (optional)" aria-label="New key comment" className="h-7 flex-1 text-sm" />
        </div>
        {taken && (
          <p className="text-xs text-amber-600 dark:text-amber-500">
            <span className="font-mono">{trimmed}</span> already exists.
          </p>
        )}
        <p className="text-xs text-muted-foreground">
          “Generate” sets no passphrase — anyone with the file can use it. Use “Generate in Terminal…” to protect the key with a passphrase.
        </p>
        <DialogFooter>
          <Button type="button" variant="secondary" size="sm" className="h-7" disabled={!canSubmit || generateInTerminal.isPending} onClick={handleGenerateInTerminal}>
            Generate in Terminal…
          </Button>
          <Button type="button" size="sm" className="h-7" disabled={!canSubmit} onClick={handleGenerate}>
            Generate
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
