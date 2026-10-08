import { useState, type ReactNode } from "react";
import { KeyRound } from "lucide-react";
import { toast } from "sonner";

import type { KeyInfo } from "@/bindings/KeyInfo";
import type { MoveFailure } from "@/bindings/MoveFailure";
import type { SyncKeySlotView } from "@/bindings/SyncKeySlotView";
import { DeleteCopyConfirm, ExportPrivateKeyDialog, PickKeyDialog, SyncKeyConfirm } from "@/components/keychain/dialogs";
import { ExportToHostDialog, type ExportTarget } from "@/components/keychain/ExportToHostDialog";
import { TONE_TEXT } from "@/components/sync-primitives";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { copyText } from "@/lib/clipboard";
import { deviceLine, slotActions, slotStatusText, whereLine } from "@/lib/key-slots";
import { hasKeyHere, slotBadges, slotFingerprint, slotPublicPath, type KeyBadge, type KeychainSelection } from "@/lib/keychain";
import { useHomeDir, useKeys, useReadPublicKey } from "@/lib/queries";
import { useKeyDeleteCopy, useKeySetDelivery, useKeySetMode, useKeyUseSynced, useSyncOverview } from "@/lib/sync";
import { revealHidden } from "@/lib/sync-approvals";
import { useLastNonNull } from "@/lib/use-last-non-null";
import { cn } from "@/lib/utils";
import { useUiStore } from "@/stores/ui";

/** What a key's detail asks for. */
export type KeyAction = "copy" | "exportHost" | "exportPrivate" | "move" | "sync" | "syncNew" | "useSynced" | "pick" | "stop" | "delete";

export const BADGE_CLASS: Record<KeyBadge["tone"], string> = {
  plain: "",
  warning: "border-amber-500/40 text-amber-700 dark:text-amber-400",
  error: "border-destructive/40 text-destructive",
};

/** A labelled line of a key's detail. */
function Fact({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div className="grid grid-cols-[8rem_1fr] gap-3 px-3 py-2 text-sm">
      <span className="text-muted-foreground">{label}</span>
      <div className="min-w-0 space-y-0.5">{children}</div>
    </div>
  );
}

/** The hosts that use a key; pressing one shows it in Hosts. A plain function, so a test sees the buttons in the tree. */
function hostLinks(hosts: readonly string[], onHost: (alias: string) => void): ReactNode {
  if (hosts.length === 0) return <p className="text-xs text-muted-foreground">No hosts use it.</p>;
  return (
    <div className="flex flex-wrap gap-1">
      {hosts.map((alias) => (
        <Button key={alias} type="button" size="sm" variant="ghost" className="h-6 px-1.5 font-mono text-xs" onClick={() => onHost(alias)}>
          {revealHidden(alias)}
        </Button>
      ))}
    </div>
  );
}

/**
 * A key slot's detail (key vault spec §7.3). `keyHere` = this computer has the key and its .pub is known (Copy public key and
 * Export to host); `moveFailure` = why the last Move couldn't move it. No hooks: exported for the tests.
 */
export function SlotKeyDetailView({
  slot,
  busy,
  keyHere,
  moveFailure,
  onAction,
  onHost,
}: {
  slot: SyncKeySlotView;
  busy: boolean;
  keyHere: boolean;
  moveFailure: string | null;
  onAction: (action: KeyAction) => void;
  onHost: (alias: string) => void;
}) {
  const status = slotStatusText(slot.status);
  const actions = slotActions(slot);
  const where = whereLine(slot);
  // The file this computer uses, for the states that name one. A key in SSHelter has none (its slot path holds only the .pub):
  // the line above says where the key is. A key SSHelter's agent can never hold stays a file without being a "file for now".
  const file = !slot.in_vault && "file" in slot.status ? slot.status.file : null;
  const devices = deviceLine(slot);
  const button = (action: KeyAction, label: string, extra: { ghost?: boolean; destructive?: boolean; off?: boolean } = {}) => (
    <Button
      key={action}
      type="button"
      size="sm"
      variant={extra.ghost ? "ghost" : "outline"}
      className={cn("h-7", extra.destructive && "text-destructive hover:text-destructive")}
      disabled={busy || extra.off}
      onClick={() => onAction(action)}
    >
      {label}
    </Button>
  );
  const slotButtons = [
    actions.syncThis && button("sync", "Sync to your computers"),
    actions.syncNew && button("syncNew", "Sync the new key"),
    actions.useSynced && button("useSynced", "Use the synced key"),
    actions.pick && button("pick", actions.pick === "pick" ? "Pick a key on this computer…" : "Change…"),
    actions.stopSyncing && button("stop", "Stop syncing", { ghost: true }),
    actions.deleteCopy && button("delete", "Delete copy", { ghost: true, destructive: true }),
  ].filter(Boolean);
  return (
    <div className="space-y-5">
      <header className="space-y-2">
        <h2 className="truncate font-mono text-lg font-semibold">{revealHidden(slot.name)}</h2>
        <div className="flex flex-wrap items-center gap-1.5">
          {slotBadges(slot).map((b) => (
            <Badge key={b.label} variant="outline" className={BADGE_CLASS[b.tone]}>
              {b.label}
            </Badge>
          ))}
          {slot.key_type && <span className="font-mono text-xs text-muted-foreground">{revealHidden(slot.key_type)}</span>}
        </div>
      </header>
      <div className="flex flex-wrap gap-1.5">
        {button("copy", "Copy public key", { off: !keyHere })}
        {button("exportHost", "Export to host…", { off: !keyHere })}
        {slot.in_vault && button("exportPrivate", "Export private key…")}
        {slot.file_for_now && button("move", "Move into SSHelter")}
      </div>
      <div className="settings-group">
        <Fact label="Fingerprint">
          <p className="font-mono text-xs break-all">{slotFingerprint(slot) ?? "No key on this computer yet"}</p>
        </Fact>
        <Fact label="On this computer">
          <p className={cn("text-sm", TONE_TEXT[status.tone])}>{status.text}</p>
          {where && <p className="text-xs text-muted-foreground">{where}</p>}
          {file && <p className="font-mono text-xs break-all text-muted-foreground">{file}</p>}
          {moveFailure && <p className={cn("text-xs", TONE_TEXT.error)}>{`Couldn't move into SSHelter: ${revealHidden(moveFailure)}`}</p>}
        </Fact>
        <Fact label="Hosts">{hostLinks(slot.hosts, onHost)}</Fact>
        {devices && (
          <Fact label="Other computers">
            <p className="text-xs text-muted-foreground">{devices}</p>
          </Fact>
        )}
      </div>
      {slotButtons.length > 0 && <div className="flex flex-wrap gap-1.5">{slotButtons}</div>}
    </div>
  );
}

/** A key file in ~/.ssh (key vault spec §7.3): SSHelter doesn't manage it, and never deletes it (§7.6). No hooks: exported for the tests. */
export function FileKeyDetailView({ file, onAction, onHost }: { file: KeyInfo; onAction: (action: "copy" | "exportHost") => void; onHost: (alias: string) => void }) {
  const hasPub = file.public_path !== null;
  return (
    <div className="space-y-5">
      <header className="space-y-2">
        <h2 className="truncate font-mono text-lg font-semibold">{revealHidden(file.name)}</h2>
        <div className="flex flex-wrap items-center gap-1.5">
          <Badge variant="outline">
            {file.key_type}
            {file.bits !== null ? ` ${file.bits}` : ""}
          </Badge>
          {file.in_agent && <Badge variant="outline">in ssh-agent</Badge>}
        </div>
        <p className="text-xs text-muted-foreground">{"SSHelter doesn't manage this file: any program can use it without asking."}</p>
      </header>
      <div className="flex flex-wrap gap-1.5">
        <Button type="button" size="sm" variant="outline" className="h-7" disabled={!hasPub} onClick={() => onAction("copy")}>
          Copy public key
        </Button>
        <Button type="button" size="sm" variant="outline" className="h-7" disabled={!hasPub} onClick={() => onAction("exportHost")}>
          Export to host…
        </Button>
      </div>
      <div className="settings-group">
        <Fact label="Fingerprint">
          <p className="font-mono text-xs break-all">{file.fingerprint_sha256 ?? "Unknown"}</p>
        </Fact>
        {file.comment && (
          <Fact label="Comment">
            <p className="text-xs break-all">{revealHidden(file.comment)}</p>
          </Fact>
        )}
        <Fact label="Path">
          <p className="font-mono text-xs break-all">{file.private_path}</p>
        </Fact>
        <Fact label="Public key">
          <p className="font-mono text-xs break-all">{file.public_path ?? "No .pub file next to it."}</p>
        </Fact>
        <Fact label="Hosts">{hostLinks(file.hosts, onHost)}</Fact>
      </div>
    </div>
  );
}

function NoKeySelected() {
  return (
    <div className="flex h-full flex-col items-center justify-center gap-4 px-6 text-center select-none">
      <div className="flex size-12 items-center justify-center rounded-xl bg-muted text-muted-foreground ring-1 ring-border">
        <KeyRound className="size-6" />
      </div>
      <div className="space-y-1">
        <p className="text-sm font-medium">No key selected</p>
        <p className="text-sm text-muted-foreground">Choose a key from the list.</p>
      </div>
    </div>
  );
}

/** The Keychain's main pane: the selected key's detail and its dialogs, or a prompt to choose one. */
export function KeyDetailPane() {
  const selection = useUiStore((s) => s.keychainSelection);
  const moveFailures = useUiStore((s) => s.moveFailures);
  const setSidebarView = useUiStore((s) => s.setSidebarView);
  const setSelectedAlias = useUiStore((s) => s.setSelectedAlias);
  const showHost = (alias: string) => {
    setSidebarView("hosts");
    setSelectedAlias(alias);
  };
  return <KeyDetailFor selection={selection} moveFailures={moveFailures} onShowHost={showHost} />;
}

/**
 * The detail of `selection`, with the data and the actions it needs. The ui store's part is in `KeyDetailPane`: a server render
 * (the tests) reads a zustand store's initial state, so the tests hand these in. Exported for the tests.
 */
export function KeyDetailFor({
  selection,
  moveFailures,
  onShowHost,
}: {
  selection: KeychainSelection | null;
  moveFailures: MoveFailure[];
  onShowHost: (alias: string) => void;
}) {
  const overview = useSyncOverview();
  const keys = useKeys({ enabled: true });
  const home = useHomeDir().data ?? null;
  const readPublic = useReadPublicKey();
  const setMode = useKeySetMode();
  const switchToSynced = useKeyUseSynced();
  const deleteCopy = useKeyDeleteCopy();
  const delivery = useKeySetDelivery();
  const [picking, setPicking] = useState<SyncKeySlotView | null>(null);
  const [syncing, setSyncing] = useState<SyncKeySlotView | null>(null);
  const [deleting, setDeleting] = useState<SyncKeySlotView | null>(null);
  const [exporting, setExporting] = useState<SyncKeySlotView | null>(null);
  const [exportTarget, setExportTarget] = useState<ExportTarget | null>(null);
  // What the confirms show while they animate out (their slot state is already null by then).
  const shownSyncing = useLastNonNull(syncing);
  const shownDeleting = useLastNonNull(deleting);
  const slots = overview.data?.joined ? overview.data.key_slots : [];
  const slot = selection?.kind === "slot" ? (slots.find((s) => s.id === selection.id) ?? null) : null;
  const file = selection?.kind === "file" ? ((keys.data ?? []).find((k) => k.private_path === selection.path) ?? null) : null;
  const busy = setMode.isPending || switchToSynced.isPending || deleteCopy.isPending || delivery.isPending;

  const copyPublicKey = (path: string | null, name: string) => {
    if (!path) return;
    readPublic.mutate(
      { path },
      {
        onSuccess: async (publicKey) => {
          try {
            await copyText(publicKey);
            toast.success(`Copied the public key of ${revealHidden(name)}`);
          } catch {
            toast.error("Clipboard unavailable");
          }
        },
      },
    );
  };
  const actOnSlot = (s: SyncKeySlotView, action: KeyAction) => {
    const name = revealHidden(s.name);
    const publicPath = slotPublicPath(s, home);
    switch (action) {
      case "copy":
        copyPublicKey(publicPath, s.name);
        break;
      case "exportHost":
        if (publicPath) setExportTarget({ name: s.name, publicPath, inSSHelter: s.in_vault });
        break;
      case "exportPrivate":
        setExporting(s);
        break;
      case "move":
        delivery.mutate({ slotId: s.id, vault: true }, { onSuccess: () => toast.success(`${name} is now in SSHelter on this computer`) });
        break;
      case "sync":
      case "syncNew":
        // Uploading a private key can't be taken back: ask first (`SyncKeyConfirm`).
        setSyncing(s);
        break;
      case "stop":
        setMode.mutate({ slotId: s.id, mode: "own" }, { onSuccess: () => toast.success(`${name} no longer syncs; computers that have it keep their copy`) });
        break;
      case "useSynced":
        switchToSynced.mutate({ slotId: s.id }, { onSuccess: () => toast.success(`${name} uses the synced key on this computer`) });
        break;
      case "pick":
        setPicking(s);
        break;
      case "delete":
        setDeleting(s);
        break;
    }
  };

  return (
    <>
      {slot ? (
        <div className="mx-auto max-w-[720px] space-y-5 px-6 py-5 pb-24">
          <SlotKeyDetailView
            slot={slot}
            busy={busy}
            keyHere={hasKeyHere(slot) && slotPublicPath(slot, home) !== null}
            moveFailure={slot.file_for_now ? (moveFailures.find((f) => f.slot_id === slot.id)?.message ?? null) : null}
            onAction={(action) => actOnSlot(slot, action)}
            onHost={onShowHost}
          />
        </div>
      ) : file ? (
        <div className="mx-auto max-w-[720px] space-y-5 px-6 py-5 pb-24">
          <FileKeyDetailView
            file={file}
            onAction={(action) => {
              if (action === "copy") copyPublicKey(file.public_path, file.name);
              else if (file.public_path) setExportTarget({ name: file.name, publicPath: file.public_path, inSSHelter: false });
            }}
            onHost={onShowHost}
          />
        </div>
      ) : (
        <NoKeySelected />
      )}
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
      <ExportPrivateKeyDialog slot={exporting} onClose={() => setExporting(null)} />
      <ExportToHostDialog target={exportTarget} onClose={() => setExportTarget(null)} />
    </>
  );
}
