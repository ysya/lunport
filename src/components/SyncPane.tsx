import { useState } from "react";
import { useQueryClient } from "@tanstack/react-query";
import { Copy, Eye, Loader2, RefreshCw, UserMinus } from "lucide-react";
import { toast } from "sonner";

import type { SyncStatus } from "@/bindings/SyncStatus";
import { cleanWordsInput } from "@/lib/sync-migration";
import {
  createChain,
  errorMessage,
  joinChain,
  refreshSyncViews,
  showWords,
  useForgetDevice,
  useLeaveChain,
  useSetDeviceName,
  useSetRelayUrl,
  useSyncNow,
  useSyncStatus,
} from "@/lib/sync";
import { copyText } from "@/lib/clipboard";
import { useSettingsStore } from "@/stores/settings";
import { useUiStore } from "@/stores/ui";
import { Section, SettingsGroup, SettingsRow } from "@/components/settings-primitives";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Checkbox } from "@/components/ui/checkbox";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
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
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog";

/**
 * Settings → Sync. The recovery-phrase dialogs live HERE, above the joined /
 * not-joined split: creating a chain flips `joined` immediately, and a dialog
 * owned by NotJoinedPane would unmount before the user confirmed the words.
 * The words only ever live in component state — never in a query cache.
 */
export function SyncPane() {
  const status = useSyncStatus(5_000);
  const setMigrationOpen = useUiStore((s) => s.setSyncMigrationOpen);
  const [freshWords, setFreshWords] = useState<string | null>(null); // just created; must be confirmed
  const [shownWords, setShownWords] = useState<string | null>(null); // re-shown on request
  const [saved, setSaved] = useState(false);

  if (!status.data) {
    // A failed status query never turns into data: show why instead of loading forever.
    return status.isError ? (
      <p className="px-3 py-3 text-sm text-destructive">Could not load sync status: {errorMessage(status.error)}</p>
    ) : (
      <p className="px-3 py-3 text-sm text-muted-foreground">Loading sync status…</p>
    );
  }

  const finishOnboarding = () => {
    setFreshWords(null);
    setSaved(false);
    setMigrationOpen(true);
  };

  return (
    <>
      {status.data.joined ? (
        <JoinedPane status={status.data} onShowWords={setShownWords} />
      ) : (
        <NotJoinedPane status={status.data} onCreated={setFreshWords} />
      )}

      <Dialog open={freshWords !== null} onOpenChange={(open) => { if (!open && saved) finishOnboarding(); }}>
        <DialogContent className="sm:max-w-lg" showCloseButton={false} onEscapeKeyDown={(e) => { if (!saved) e.preventDefault(); }} onPointerDownOutside={(e) => { if (!saved) e.preventDefault(); }}>
          <DialogHeader>
            <DialogTitle>Your recovery phrase</DialogTitle>
            <DialogDescription>
              Enter these 24 words on every other device. Anyone with them can read your synced hosts, so keep them in a password manager — SSHelter can show them again from a device that is already in the chain.
            </DialogDescription>
          </DialogHeader>
          <WordGrid words={freshWords ?? ""} />
          <label className="flex items-center gap-2 text-sm">
            <Checkbox checked={saved} onCheckedChange={(v) => setSaved(v === true)} />
            I have saved these words somewhere safe
          </label>
          <DialogFooter>
            <Button type="button" disabled={!saved} onClick={finishOnboarding}>
              Continue
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      <Dialog open={shownWords !== null} onOpenChange={(open) => { if (!open) setShownWords(null); }}>
        <DialogContent className="sm:max-w-lg">
          <DialogHeader>
            <DialogTitle>Recovery phrase</DialogTitle>
            <DialogDescription>Enter these words on the new device under Settings → Sync → Join.</DialogDescription>
          </DialogHeader>
          <WordGrid words={shownWords ?? ""} />
        </DialogContent>
      </Dialog>
    </>
  );
}

/** Advanced row shared by both panes: the relay must be reachable BEFORE create/join. */
function RelayUrlRow({ current }: { current: string }) {
  const setRelayUrl = useSetRelayUrl();
  const [draft, setDraft] = useState(current);
  return (
    <SettingsRow id="sync-relay" label="Relay URL" description="https:// only (plain http is allowed for localhost). Self-host from the repository's relay/ folder.">
      <div className="flex items-center gap-1.5">
        <Input id="sync-relay" value={draft} onChange={(e) => setDraft(e.target.value)} placeholder="https://relay.example.com" className="h-7 w-64 font-mono text-xs" />
        <Button type="button" variant="secondary" size="sm" className="h-7" disabled={draft.trim() === current || setRelayUrl.isPending} onClick={() => setRelayUrl.mutate({ url: draft })}>
          Save
        </Button>
      </div>
    </SettingsRow>
  );
}

/** Create or join. Errors keep the form as it was so the user can fix a typo. */
function NotJoinedPane({ status, onCreated }: { status: SyncStatus; onCreated: (words: string) => void }) {
  const queryClient = useQueryClient();
  const [deviceName, setDeviceName] = useState(status.device_name);
  const [words, setWords] = useState("");
  const [busy, setBusy] = useState<"create" | "join" | null>(null);
  const leave = useLeaveChain();
  const setFileAlias = useSettingsStore((s) => s.setFileAlias);
  const fileAliases = useSettingsStore((s) => s.fileAliases);
  const setMigrationOpen = useUiStore((s) => s.setSyncMigrationOpen);

  const labelManagedFile = () => {
    if (status.managed_file && !fileAliases[status.managed_file]) setFileAlias(status.managed_file, "Synced");
  };

  const onCreate = async () => {
    setBusy("create");
    try {
      const phrase = await createChain(deviceName);
      labelManagedFile();
      onCreated(phrase);
      refreshSyncViews(queryClient);
    } catch (error) {
      toast.error("Could not create sync chain", { description: errorMessage(error) });
    } finally {
      setBusy(null);
    }
  };

  const onJoin = async () => {
    setBusy("join");
    try {
      await joinChain(cleanWordsInput(words), deviceName);
      labelManagedFile();
      setWords("");
      toast.success("Joined the sync chain");
      refreshSyncViews(queryClient);
      setMigrationOpen(true);
    } catch (error) {
      // Keep the pasted words so a typo can be fixed.
      toast.error("Could not join sync chain", { description: errorMessage(error) });
    } finally {
      setBusy(null);
    }
  };

  const cleaned = cleanWordsInput(words);
  const wordCount = cleaned === "" ? 0 : cleaned.split(" ").length;
  // Release builds made without a built-in relay start with an empty relay URL:
  // the user must enter one before creating or joining (the backend refuses too).
  const relayMissing = status.relay_url.trim() === "";

  return (
    <>
      {/* Errors that happen while not joined — a state file set aside at startup,
          an I/O error that needs a restart, sync running in another SSHelter
          process — have nowhere else to show. */}
      {status.last_error && (
        <Section title="Sync error">
          <SettingsGroup>
            <SettingsRow label="Status" description={status.last_error}>
              <Badge variant="destructive">Error</Badge>
            </SettingsRow>
          </SettingsGroup>
        </Section>
      )}

      {status.phrase_cleanup_pending && (
        <Section title="Cleanup needed" description="You left the chain, but the recovery phrase is still in the keychain.">
          <SettingsGroup>
            <SettingsRow label="Recovery phrase" description="Retry removing it from the OS keychain.">
              <Button type="button" variant="outline" size="sm" className="h-7" disabled={leave.isPending} onClick={() => leave.mutate({ deleteRemote: false })}>
                Remove phrase
              </Button>
            </SettingsRow>
          </SettingsGroup>
        </Section>
      )}

      {relayMissing && (
        <Section
          title="Relay"
          description="This build has no built-in relay. Enter the URL of the relay to sync through (self-host one from the repository's relay/ folder), then create or join a chain."
        >
          <SettingsGroup>
            <RelayUrlRow current={status.relay_url} />
          </SettingsGroup>
        </Section>
      )}

      <Section
        title="Sync chain"
        description="Sync is in beta. Keep hosts in sync across your computers without an account. A 24-word recovery phrase is the only secret; the relay only ever stores encrypted records."
      >
        <SettingsGroup>
          <SettingsRow id="sync-device-name" label="This device" description="Shown to your other devices.">
            <Input id="sync-device-name" value={deviceName} onChange={(e) => setDeviceName(e.target.value)} className="h-7 w-48 text-sm" />
          </SettingsRow>
          <SettingsRow
            label="Start a new chain"
            description={relayMissing ? "Enter a relay URL above first." : "Creates the recovery phrase you will enter on other devices."}
          >
            <Button type="button" size="sm" className="h-7" disabled={busy !== null || deviceName.trim() === "" || relayMissing} onClick={() => void onCreate()}>
              {busy === "create" && <Loader2 className="size-3.5 animate-spin" />} Create
            </Button>
          </SettingsRow>
        </SettingsGroup>
      </Section>

      <Section title="Join an existing chain" description="Paste the 24 words from another device. Nothing is sent until you press Join.">
        <div className="space-y-2">
          <Textarea
            value={words}
            onChange={(e) => setWords(e.target.value)}
            placeholder="abandon ability able …"
            rows={3}
            className="font-mono text-sm"
            aria-label="Recovery phrase"
            autoCorrect="off"
            autoCapitalize="off"
            spellCheck={false}
          />
          <Button type="button" size="sm" className="h-7" disabled={busy !== null || wordCount !== 24 || deviceName.trim() === "" || relayMissing} onClick={() => void onJoin()}>
            {busy === "join" && <Loader2 className="size-3.5 animate-spin" />} Join
          </Button>
        </div>
      </Section>

      {!relayMissing && (
        <Section title="Advanced" description="Change this before creating or joining if you self-host the relay or the default one is unreachable.">
          <SettingsGroup>
            <RelayUrlRow current={status.relay_url} />
          </SettingsGroup>
        </Section>
      )}
    </>
  );
}

function WordGrid({ words }: { words: string }) {
  const list = words.split(" ");
  const copy = async () => {
    try {
      await copyText(words);
      toast.success("Recovery phrase copied — clear your clipboard when done");
    } catch (error) {
      toast.error("Clipboard unavailable", { description: errorMessage(error) });
    }
  };
  return (
    <div className="space-y-2">
      <ol className="grid grid-cols-3 gap-x-4 gap-y-1 rounded-md border bg-muted/40 p-3 font-mono text-sm select-text">
        {list.map((w, i) => (
          <li key={`${i}-${w}`} className="flex gap-2">
            <span className="w-5 text-right text-muted-foreground tabular-nums">{i + 1}</span>
            {w}
          </li>
        ))}
      </ol>
      <Button type="button" variant="outline" size="sm" className="h-7" onClick={() => void copy()}>
        <Copy className="size-3.5" /> Copy
      </Button>
    </div>
  );
}

function JoinedPane({ status: s, onShowWords }: { status: SyncStatus; onShowWords: (words: string) => void }) {
  const syncNow = useSyncNow();
  const leave = useLeaveChain();
  const forget = useForgetDevice();
  const setDeviceName = useSetDeviceName();
  const setMigrationOpen = useUiStore((st) => st.setSyncMigrationOpen);
  const [revealing, setRevealing] = useState(false);
  const [leaveOpen, setLeaveOpen] = useState(false);
  const [deleteRemote, setDeleteRemote] = useState(false);
  const [nameDraft, setNameDraft] = useState(s.device_name);

  const lastSync = s.last_sync_ms ? new Date(s.last_sync_ms).toLocaleString() : "never";

  const reveal = async () => {
    setRevealing(true);
    try {
      onShowWords(await showWords());
    } catch (error) {
      toast.error("Could not read recovery phrase", { description: errorMessage(error) });
    } finally {
      setRevealing(false);
    }
  };

  return (
    <>
      <Section title="Sync chain" description={`Sync is in beta · Chain ${s.chain_short ?? ""} · ${s.hosts_in_sync} hosts in sync · last sync ${lastSync}`}>
        <SettingsGroup>
          <SettingsRow label="Status" description={s.last_error ?? (s.pending > 0 ? `${s.pending} change${s.pending === 1 ? "" : "s"} waiting to upload` : "Up to date")}>
            <div className="flex items-center gap-1.5">
              <Badge variant={s.last_error ? "destructive" : s.read_only ? "outline" : "secondary"}>
                {s.read_only ? "Read-only" : s.last_error ? "Error" : "Synced"}
              </Badge>
              <Button type="button" variant="ghost" size="icon" className="size-7" aria-label="Sync now" disabled={syncNow.isPending} onClick={() => syncNow.mutate()}>
                <RefreshCw className="size-3.5" />
              </Button>
            </div>
          </SettingsRow>
          <SettingsRow id="sync-name" label="This device">
            <div className="flex items-center gap-1.5">
              <Input id="sync-name" value={nameDraft} onChange={(e) => setNameDraft(e.target.value)} className="h-7 w-40 text-sm" />
              <Button type="button" variant="secondary" size="sm" className="h-7" disabled={nameDraft.trim() === "" || nameDraft === s.device_name || setDeviceName.isPending} onClick={() => setDeviceName.mutate({ name: nameDraft })}>
                Rename
              </Button>
            </div>
          </SettingsRow>
          <SettingsRow label="Move hosts into sync" description="Choose which existing hosts should follow you to other devices.">
            <Button type="button" variant="outline" size="sm" className="h-7" onClick={() => setMigrationOpen(true)}>
              Choose hosts…
            </Button>
          </SettingsRow>
          <SettingsRow label="Recovery phrase" description="Needed to add another device. Shown only on request.">
            <Button type="button" variant="outline" size="sm" className="h-7" disabled={revealing} onClick={() => void reveal()}>
              <Eye className="size-3.5" /> Show
            </Button>
          </SettingsRow>
        </SettingsGroup>
      </Section>

      <Section
        title="Devices"
        description="Every device that joined this chain. Forget only removes a device from this list — a device that still has the recovery phrase keeps syncing. If a device was lost, leave this chain, start a new one on the devices you keep, and rotate the keys it could see."
      >
        <SettingsGroup>
          {s.devices.map((d) => (
            <SettingsRow key={d.id} label={d.name + (d.is_this ? " (this device)" : "")} description={`${d.platform} · last seen ${new Date(d.last_seen_ms).toLocaleString()}`}>
              {!d.is_this && (
                <Button type="button" variant="ghost" size="sm" className="h-7 text-muted-foreground" aria-label={`Forget ${d.name}`} disabled={forget.isPending} onClick={() => forget.mutate({ deviceId: d.id })}>
                  <UserMinus className="size-3.5" /> Forget
                </Button>
              )}
            </SettingsRow>
          ))}
        </SettingsGroup>
      </Section>

      <Section title="Advanced" description="The relay only stores encrypted records.">
        <SettingsGroup>
          {/* Read-only while joined: the cursor and every record's seq belong to this relay (spec §6). */}
          <SettingsRow label="Relay URL" description="Leave the chain to switch relays, then create or join on the new one.">
            <span className="max-w-64 truncate font-mono text-xs text-muted-foreground" title={s.relay_url}>
              {s.relay_url}
            </span>
          </SettingsRow>
          <SettingsRow label="Leave chain" description="This device keeps every file it has; it just stops syncing.">
            <Button type="button" variant="outline" size="sm" className="h-7 text-destructive hover:text-destructive" onClick={() => setLeaveOpen(true)}>
              Leave…
            </Button>
          </SettingsRow>
        </SettingsGroup>
      </Section>

      <AlertDialog open={leaveOpen} onOpenChange={(open) => { if (!leave.isPending) setLeaveOpen(open); }}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Leave the sync chain?</AlertDialogTitle>
            <AlertDialogDescription>
              Your hosts stay in <span className="font-mono">{s.managed_file}</span> and keep working. Rejoining later needs the recovery phrase.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <label className="flex items-center gap-2 text-sm">
            <Checkbox checked={deleteRemote} onCheckedChange={(v) => setDeleteRemote(v === true)} />
            Also delete the chain from the relay (other devices will stop syncing)
          </label>
          <AlertDialogFooter>
            <AlertDialogCancel disabled={leave.isPending}>Cancel</AlertDialogCancel>
            <AlertDialogAction
              disabled={leave.isPending}
              onClick={(e) => {
                // Keep the dialog open until the request settles: Radix's Close
                // (which Action composes) skips its auto-close when the click
                // handler calls preventDefault first.
                e.preventDefault();
                leave.mutate({ deleteRemote }, { onSuccess: () => { setLeaveOpen(false); toast.success("Left the sync chain"); } });
              }}
            >
              {leave.isPending && <Loader2 className="size-3.5 animate-spin" />} Leave
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </>
  );
}
