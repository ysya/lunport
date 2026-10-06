import { useEffect, useState } from "react";
import { useQueryClient } from "@tanstack/react-query";
import { ExternalLink, Eye, KeyRound, Loader2, RefreshCw, ShieldAlert, UserMinus } from "lucide-react";
import { toast } from "sonner";

import type { SyncFrozenView } from "@/bindings/SyncFrozenView";
import type { SyncOverview } from "@/bindings/SyncOverview";
import type { SyncRotationView } from "@/bindings/SyncRotationView";
import { listNames } from "@/lib/format";
import { keysToAsk, needsKeyLabel, notSetUpLabel, slotsNeedingKey, syncedKeysNote } from "@/lib/key-slots";
import { approvalsRowNote, revealHidden } from "@/lib/sync-approvals";
import { SYNC_CODE_WORDS, cleanWordsInput, wordCount } from "@/lib/sync-migration";
import {
  createAccount,
  errorMessage,
  joinAccount,
  openRelayDeploy,
  openRelayUpdateGuide,
  refreshSyncViews,
  rejoinAccount,
  showWords,
  syncOverviewKey,
  useCancelSyncCodeChange,
  useChangeSyncCode,
  useCheckRelay,
  useCheckUnknownRelay,
  useDismissNotice,
  useForgetDevice,
  useKeyCandidates,
  useLeaveAccount,
  useSetDeviceName,
  useSetRelayUrl,
  useSyncNow,
  useSyncOverview,
} from "@/lib/sync";
import {
  changeCodeBlocker,
  deleteAccountNote,
  deviceRows,
  frozenMessage,
  leaveRequest,
  leaveRotationNote,
  leaveUnsentNote,
  newSyncCodeNoticeIndex,
  noticeRows,
  plural,
  relayDetails,
  rotationLabel,
  shownCodeNote,
  statusLine,
  strayFilesNote,
  syncCodeNote,
} from "@/lib/sync-overview";
import { structureLock } from "@/lib/sync-spaces";
import { useNow } from "@/lib/use-now";
import { useUiStore } from "@/stores/ui";
import { cn } from "@/lib/utils";
import { Section, SettingsGroup, SettingsRow } from "@/components/settings-primitives";
import { SyncCodeDialog, TONE_TEXT } from "@/components/sync-primitives";
import { ChooseSpacesDialog, SpacesSection } from "@/components/SyncSpacesSection";
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

/** What "Stop syncing" does to an upgrade that is stuck: the row says it, and so does the confirm. */
const STOP_UPGRADE_NOTE =
  "Gives up the upgrade on this computer. The files in ~/.ssh/sshelter that your SSH config includes — its synced hosts among them — move to ~/.ssh/sshelter-local/, where ssh keeps reading them.";

/**
 * Settings → Sync. The sync-code dialogs live HERE, above the joined / not-joined
 * split: creating an account flips `joined` immediately, and a dialog owned by
 * NotJoinedPane would unmount before the user confirmed the words. The words only
 * ever live in component state — never in a query cache, a store, a log or a toast.
 */
export function SyncPane() {
  const overview = useSyncOverview(5_000);
  const openMigration = useUiStore((s) => s.setSyncMigration);
  const dismiss = useDismissNotice();
  const [createdWords, setCreatedWords] = useState<string | null>(null); // just created; must be confirmed
  const [shownWords, setShownWords] = useState<string | null>(null); // shown on request
  const [newCode, setNewCode] = useState<string | null>(null); // after changing it
  const [choosingSpaces, setChoosingSpaces] = useState(false); // right after joining, which selects no space

  const o = overview.data;
  if (!o) {
    // A failed overview query never turns into data: show why instead of loading forever.
    return overview.isError ? (
      <p className="px-3 py-3 text-sm text-destructive">Could not load sync status: {errorMessage(overview.error)}</p>
    ) : (
      <p className="px-3 py-3 text-sm text-muted-foreground">Loading sync status…</p>
    );
  }

  return (
    <>
      {/* While upgrading, `joined` is false: NotJoinedPane checks `upgrading` before it offers create or join. */}
      {o.joined ? (
        <JoinedPane overview={o} onShowWords={setShownWords} onShowNewCode={setNewCode} />
      ) : (
        <NotJoinedPane overview={o} onCreated={setCreatedWords} onJoined={() => setChoosingSpaces(true)} />
      )}

      <ChooseSpacesDialog
        open={choosingSpaces}
        overview={o}
        onClose={(selected) => {
          setChoosingSpaces(false);
          // As after creating: offer to move this computer's hosts into a space next.
          if (selected.length > 0) openMigration({ spaceId: selected[0] });
        }}
      />

      <SyncCodeDialog
        mode="created"
        words={createdWords}
        onDone={() => {
          setCreatedWords(null);
          openMigration({ spaceId: null });
        }}
      />
      {/* While the sync code is being changed this is still the old code: the dialog says when it stops working. */}
      <SyncCodeDialog mode="shown" words={shownWords} description={shownCodeNote(o) ?? undefined} onDone={() => setShownWords(null)} />
      <SyncCodeDialog
        mode="changed"
        words={newCode}
        note={syncedKeysNote(o) ?? undefined}
        onDone={() => {
          // Saved: the "new sync code" notice has done its job. Its place in the list is looked up now, not when
          // the dialog opened: another notice may have gone since, and the index is what the backend dismisses by.
          const index = newSyncCodeNoticeIndex(o);
          if (index !== null) dismiss.mutate({ index });
          setNewCode(null);
        }}
      />
    </>
  );
}

/** The relay must be reachable BEFORE create/join; joined computers cannot switch relays. */
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
function NotJoinedPane({
  overview: o,
  onCreated,
  onJoined,
}: {
  overview: SyncOverview;
  onCreated: (words: string) => void;
  onJoined: () => void;
}) {
  const queryClient = useQueryClient();
  const [deviceName, setDeviceName] = useState(o.device_name);
  const [words, setWords] = useState("");
  const [busy, setBusy] = useState<"create" | "join" | null>(null);
  const leave = useLeaveAccount();
  const dismiss = useDismissNotice();
  const [confirmStop, setConfirmStop] = useState(false);
  // After leaving, `left_account` says where this computer's files went.
  const notices = noticeRows(o);
  // The upgrade's status line (its error, or that it is moving this computer to the new format).
  const upgrade = statusLine(o, Date.now());

  const onCreate = async () => {
    setBusy("create");
    try {
      onCreated(await createAccount(deviceName));
      refreshSyncViews(queryClient);
    } catch (error) {
      toast.error("Could not create the sync account", { description: errorMessage(error) });
    } finally {
      setBusy(null);
    }
  };

  const onJoin = async () => {
    setBusy("join");
    try {
      const joined = await joinAccount(cleanWordsInput(words), deviceName);
      setWords("");
      queryClient.setQueryData(syncOverviewKey, joined);
      refreshSyncViews(queryClient);
      toast.success("Joined the sync account");
      onJoined();
    } catch (error) {
      // Keep the pasted words so a typo can be fixed.
      toast.error("Could not join the sync account", { description: errorMessage(error) });
    } finally {
      setBusy(null);
    }
  };

  // Release builds made without a built-in relay start with an empty relay URL:
  // the user must enter one before creating or joining (the backend refuses too).
  const relayMissing = o.relay_url.trim() === "";
  const blocked = busy !== null || deviceName.trim() === "" || relayMissing;

  return (
    <>
      {/* Errors while not joined — a state file set aside at startup, an I/O error that
          needs a restart, sync running in another SSHelter process — show here. */}
      {o.last_error && !o.upgrading && (
        <Section title="Sync error">
          <SettingsGroup>
            <SettingsRow label="Status" description={o.last_error}>
              <Badge variant="destructive">Error</Badge>
            </SettingsRow>
          </SettingsGroup>
        </Section>
      )}

      {o.phrase_cleanup_pending && (
        <Section title="Cleanup needed" description="You left the sync account, but the sync code is still in the keychain.">
          <SettingsGroup>
            <SettingsRow label="Sync code" description="Retry removing it from the OS keychain.">
              <Button type="button" variant="outline" size="sm" className="h-7" disabled={leave.isPending} onClick={() => leave.mutate({ deleteRemote: false })}>
                Remove sync code
              </Button>
            </SettingsRow>
          </SettingsGroup>
        </Section>
      )}

      {notices.length > 0 && (
        <Section title="Notices">
          <SettingsGroup>
            {notices.map((n) => (
              <SettingsRow key={`${n.index}-${n.title}`} label={n.title} description={n.description}>
                <Button type="button" variant="ghost" size="sm" className="h-7 text-muted-foreground" disabled={dismiss.isPending} onClick={() => dismiss.mutate({ index: n.index })}>
                  Dismiss
                </Button>
              </SettingsRow>
            ))}
          </SettingsGroup>
        </Section>
      )}

      {o.upgrading ? (
        <Section title="Upgrading sync" description="This computer synced with an earlier SSHelter. Its hosts move into a space named “Synced”; nothing needs to be entered again.">
          <SettingsGroup>
            <SettingsRow label="Status" description={upgrade.text}>
              {upgrade.tone === "error" ? <Badge variant="destructive">Error</Badge> : <Loader2 className="size-4 animate-spin text-muted-foreground" />}
            </SettingsRow>
            {o.last_error && (
              <SettingsRow label="Stop syncing" description={STOP_UPGRADE_NOTE}>
                <Button type="button" variant="outline" size="sm" className="h-7" disabled={leave.isPending} onClick={() => setConfirmStop(true)}>
                  Stop syncing
                </Button>
              </SettingsRow>
            )}
          </SettingsGroup>
        </Section>
      ) : (
        <>
          {relayMissing && (
            <Section
              title="Relay"
              description="This build has no built-in relay. Deploy your own, enter its URL, then create or join a sync account. Use the same relay URL on every computer."
            >
              <SettingsGroup>
                <SettingsRow
                  label="Deploy a relay"
                  description="Opens Cloudflare in your browser: it copies the relay into a new repository on your GitHub or GitLab account and deploys it (the free plan is enough). Paste the workers.dev URL it gives you below."
                >
                  <Button type="button" variant="outline" size="sm" className="h-7" onClick={() => void openRelayDeploy()}>
                    <ExternalLink className="size-3.5" /> Deploy to Cloudflare
                  </Button>
                </SettingsRow>
                <RelayUrlRow current={o.relay_url} />
              </SettingsGroup>
            </Section>
          )}

          <Section
            title="Sync account"
            description="Sync is in beta. Keep hosts in sync across your computers without signing up anywhere: a 24-word sync code is the only secret, and the relay only ever stores encrypted data."
          >
            <SettingsGroup>
              <SettingsRow id="sync-device-name" label="This computer" description="Shown to your other computers.">
                <Input id="sync-device-name" value={deviceName} onChange={(e) => setDeviceName(e.target.value)} className="h-7 w-48 text-sm" />
              </SettingsRow>
              <SettingsRow
                label="Create a sync account"
                description={relayMissing ? "Enter a relay URL above first." : "Starts with one space, “Personal”, and shows the sync code to enter on your other computers."}
              >
                <Button type="button" size="sm" className="h-7" disabled={blocked} onClick={() => void onCreate()}>
                  {busy === "create" && <Loader2 className="size-3.5 animate-spin" />} Create
                </Button>
              </SettingsRow>
            </SettingsGroup>
          </Section>

          <Section title="Join with a sync code" description="Paste the 24 words from a computer that already syncs. Nothing is sent until you press Join.">
            <div className="space-y-2">
              <Textarea
                value={words}
                onChange={(e) => setWords(e.target.value)}
                placeholder="abandon ability able …"
                rows={3}
                className="font-mono text-sm"
                aria-label="Sync code"
                autoCorrect="off"
                autoCapitalize="off"
                spellCheck={false}
              />
              <Button type="button" size="sm" className="h-7" disabled={blocked || wordCount(words) !== SYNC_CODE_WORDS} onClick={() => void onJoin()}>
                {busy === "join" && <Loader2 className="size-3.5 animate-spin" />} Join
              </Button>
            </div>
          </Section>

          {!relayMissing && (
            <Section title="Advanced" description="Change this before creating or joining if you self-host the relay or the default one is unreachable.">
              <SettingsGroup>
                <RelayUrlRow current={o.relay_url} />
              </SettingsGroup>
            </Section>
          )}
        </>
      )}

      <AlertDialog
        open={confirmStop}
        onOpenChange={(open) => {
          if (!leave.isPending) setConfirmStop(open);
        }}
      >
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Stop syncing on this computer?</AlertDialogTitle>
            <AlertDialogDescription>
              {STOP_UPGRADE_NOTE} Afterwards you can create or join a sync account.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel disabled={leave.isPending}>Cancel</AlertDialogCancel>
            <AlertDialogAction
              disabled={leave.isPending}
              onClick={(e) => {
                // Keep the dialog open until the request settles (see the change-code dialog).
                e.preventDefault();
                leave.mutate({ deleteRemote: false }, { onSuccess: () => setConfirmStop(false) });
              }}
            >
              {leave.isPending && <Loader2 className="size-3.5 animate-spin" />} Stop syncing
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </>
  );
}

/** Frozen (spec §7.5): the sync code changed elsewhere. The new words stay in this component's state only. */
function RejoinRow({ frozen }: { frozen: SyncFrozenView }) {
  const queryClient = useQueryClient();
  const [words, setWords] = useState("");
  const [busy, setBusy] = useState(false);

  const onRejoin = async () => {
    setBusy(true);
    try {
      queryClient.setQueryData(syncOverviewKey, await rejoinAccount(cleanWordsInput(words)));
      setWords("");
      refreshSyncViews(queryClient);
      // Spaces the new account does not continue became local files: a `left_account` notice lists them.
      toast.success("Syncing again with the new sync code");
    } catch (error) {
      // Every refusal changes nothing (the old code, another account's code, files that can't
      // be kept local…): show it as it comes and keep the words for another try.
      toast.error("Could not use the new sync code", { description: errorMessage(error) });
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="space-y-2 px-3 py-2">
      <p className="text-sm font-medium">Enter the new sync code</p>
      <p className="text-xs text-muted-foreground">{frozenMessage(frozen)}</p>
      <Textarea
        value={words}
        onChange={(e) => setWords(e.target.value)}
        placeholder="abandon ability able …"
        rows={3}
        className="font-mono text-sm"
        aria-label="New sync code"
        autoCorrect="off"
        autoCapitalize="off"
        spellCheck={false}
      />
      <Button type="button" size="sm" className="h-7" disabled={busy || wordCount(words) !== SYNC_CODE_WORDS} onClick={() => void onRejoin()}>
        {busy && <Loader2 className="size-3.5 animate-spin" />} Use the new sync code
      </Button>
    </div>
  );
}

/** Changing the sync code is running: where it is, a relay pause, and Cancel until the old data is frozen. Its errors show in the status row. */
function RotationRow({ rotation }: { rotation: SyncRotationView }) {
  const cancel = useCancelSyncCodeChange();
  const paused = rotation.paused_until_ms
    ? ` Paused by the relay's hourly limit on new spaces; continues at ${new Date(rotation.paused_until_ms).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })}.`
    : "";
  return (
    <SettingsRow
      label="Changing the sync code"
      description={`${rotationLabel(rotation.step)}…${paused} ${rotation.cancellable ? "You can still cancel." : "It can no longer be cancelled: your other computers are already stopped."}`}
    >
      {rotation.cancellable ? (
        <Button type="button" variant="outline" size="sm" className="h-7" disabled={cancel.isPending} onClick={() => cancel.mutate()}>
          Cancel
        </Button>
      ) : (
        <Loader2 className="size-4 animate-spin text-muted-foreground" />
      )}
    </SettingsRow>
  );
}

function JoinedPane({
  overview: o,
  onShowWords,
  onShowNewCode,
}: {
  overview: SyncOverview;
  onShowWords: (words: string) => void;
  onShowNewCode: (words: string) => void;
}) {
  const syncNow = useSyncNow();
  const dismiss = useDismissNotice();
  const openApprovals = useUiStore((s) => s.setSyncApprovalsOpen);
  const candidates = useKeyCandidates(o.joined);
  const notSetUp = keysToAsk(candidates.data, null).length;
  const needing = slotsNeedingKey(o);
  const setKeySetup = useUiStore((s) => s.setKeySetup);
  const setKeysOpen = useUiStore((s) => s.setKeysOpen);
  // Relative times ("last sync 2m ago") keep moving while the overview itself does not change.
  const now = useNow();
  const status = statusLine(o, now);
  // Held hosts can't be approved or rejected while the sync code changed elsewhere or is being changed, or the account is read-only.
  const lock = structureLock(o);
  const [reading, setReading] = useState<number | "code" | null>(null);

  /** Reads the sync code from the keychain into the caller's dialog state. */
  const readWords = async (key: number | "code", show: (words: string) => void) => {
    setReading(key);
    try {
      show(await showWords());
    } catch (error) {
      toast.error("Could not read the sync code", { description: errorMessage(error) });
    } finally {
      setReading(null);
    }
  };

  return (
    <>
      <Section title="Sync" description={`Sync is in beta · account ${o.account_short ?? ""}`}>
        <SettingsGroup>
          <SettingsRow label="Status" description={status.text}>
            <div className="flex items-center gap-1.5">
              <Badge variant={status.tone === "error" ? "destructive" : status.tone === "ok" ? "secondary" : "outline"} className={cn(status.tone === "warning" && TONE_TEXT.warning)}>
                {status.badge}
              </Badge>
              <Button type="button" variant="ghost" size="icon" className="size-7" aria-label="Sync now" disabled={syncNow.isPending} onClick={() => syncNow.mutate()}>
                <RefreshCw className="size-3.5" />
              </Button>
            </div>
          </SettingsRow>
          {o.frozen && <RejoinRow frozen={o.frozen} />}
          {o.rotation && <RotationRow rotation={o.rotation} />}
          {o.approvals_waiting > 0 && (
            <SettingsRow
              label={`${plural(o.approvals_waiting, "host")} waiting for your approval`}
              description={approvalsRowNote(lock)}
            >
              <Button type="button" size="sm" className="h-7" disabled={lock !== null} onClick={() => openApprovals(true)}>
                <ShieldAlert className="size-3.5" /> Review…
              </Button>
            </SettingsRow>
          )}
          {notSetUp > 0 && (
            <SettingsRow label={notSetUpLabel(notSetUp)} description="Choose whether each key goes to your other computers.">
              <Button type="button" size="sm" className="h-7" onClick={() => setKeySetup({ aliases: null, reason: "settings" })}>
                Set up…
              </Button>
            </SettingsRow>
          )}
          {needing.length > 0 && (
            <SettingsRow
              label={needsKeyLabel(needing.length)}
              description={`Synced hosts use ${listNames(needing.map((s) => revealHidden(s.name)))}, which stay on your other computers.`}
            >
              <Button type="button" size="sm" className="h-7" onClick={() => setKeysOpen(true)}>
                Pick…
              </Button>
            </SettingsRow>
          )}
          {noticeRows(o).map((n) => (
            <SettingsRow key={`${n.index}-${n.title}`} label={n.title} description={n.description}>
              <div className="flex items-center gap-1.5">
                {n.showsNewCode && (
                  <Button type="button" size="sm" className="h-7" disabled={reading !== null} onClick={() => void readWords(n.index, onShowNewCode)}>
                    <KeyRound className="size-3.5" /> Show new sync code
                  </Button>
                )}
                {!n.showsNewCode && (
                  <Button type="button" variant="ghost" size="sm" className="h-7 text-muted-foreground" disabled={dismiss.isPending} onClick={() => dismiss.mutate({ index: n.index })}>
                    Dismiss
                  </Button>
                )}
              </div>
            </SettingsRow>
          ))}
          {o.stray_files.length > 0 && (
            <SettingsRow
              label="Files SSHelter doesn't use"
              description={strayFilesNote(o.stray_files)}
            >
              <span />
            </SettingsRow>
          )}
        </SettingsGroup>
      </Section>

      <SpacesSection overview={o} />
      <AccountSection overview={o} reading={reading === "code"} onShowCode={() => void readWords("code", onShowWords)} />
      <DevicesSection overview={o} now={now} />
      <LeaveSection overview={o} />
    </>
  );
}

function AccountSection({ overview: o, reading, onShowCode }: { overview: SyncOverview; reading: boolean; onShowCode: () => void }) {
  const setDeviceName = useSetDeviceName();
  const checkRelay = useCheckRelay();
  const changeCode = useChangeSyncCode();
  const [nameDraft, setNameDraft] = useState(o.device_name);
  const [confirmChange, setConfirmChange] = useState(false);
  const relay = relayDetails(o.relay);
  const blocker = changeCodeBlocker(o);
  // Null = the relay was not asked yet, never "no freeze": ask it once.
  useCheckUnknownRelay(o.relay === null);
  // A change that starts (here or on another computer), a frozen account, a newer format: the question is moot, so close it.
  const blocked = blocker !== null;
  useEffect(() => {
    if (blocked) setConfirmChange(false);
  }, [blocked]);

  return (
    <Section title="Account">
      <SettingsGroup>
        <SettingsRow id="sync-name" label="This computer">
          <div className="flex items-center gap-1.5">
            <Input id="sync-name" value={nameDraft} onChange={(e) => setNameDraft(e.target.value)} className="h-7 w-40 text-sm" />
            <Button
              type="button"
              variant="secondary"
              size="sm"
              className="h-7"
              disabled={nameDraft.trim() === "" || nameDraft === o.device_name || setDeviceName.isPending}
              onClick={() => setDeviceName.mutate({ name: nameDraft })}
            >
              Rename
            </Button>
          </div>
        </SettingsRow>
        {o.frozen ? (
          <SettingsRow label="Sync code" description="The sync code was changed on another computer: enter the new one above.">
            <span />
          </SettingsRow>
        ) : (
          <SettingsRow label="Sync code" description={syncCodeNote(o)}>
            <div className="flex items-center gap-1.5">
              {blocker?.updateRelay && (
                <Button type="button" variant="ghost" size="sm" className="h-7" onClick={() => void openRelayUpdateGuide()}>
                  <ExternalLink className="size-3.5" /> How to update
                </Button>
              )}
              {/* During a change this is still the old code; the row says when it stops working. */}
              <Button type="button" variant="outline" size="sm" className="h-7" disabled={reading} onClick={onShowCode}>
                <Eye className="size-3.5" /> Show
              </Button>
              <Button type="button" variant="outline" size="sm" className="h-7" disabled={blocker !== null || changeCode.isPending} onClick={() => setConfirmChange(true)}>
                Change…
              </Button>
            </div>
          </SettingsRow>
        )}
        {/* Read-only while joined: the cursors and every record's seq belong to this relay (spec §7.3). */}
        <SettingsRow label="Relay" description={`${o.relay_url} · ${relay.version}${relay.updateHint ? ` · ${relay.updateHint}` : ""}`}>
          <div className="flex items-center gap-1.5">
            {relay.updateHint && (
              <Button type="button" variant="ghost" size="sm" className="h-7" onClick={() => void openRelayUpdateGuide()}>
                <ExternalLink className="size-3.5" /> How to update
              </Button>
            )}
            <Button type="button" variant="outline" size="sm" className="h-7" disabled={checkRelay.isPending} onClick={() => checkRelay.mutate()}>
              {checkRelay.isPending && <Loader2 className="size-3.5 animate-spin" />} Check again
            </Button>
          </div>
        </SettingsRow>
      </SettingsGroup>

      <AlertDialog
        open={confirmChange}
        onOpenChange={(open) => {
          if (!changeCode.isPending) setConfirmChange(open);
        }}
      >
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Change the sync code?</AlertDialogTitle>
            <AlertDialogDescription>
              Use this when a computer with the sync code was lost or stolen. SSHelter creates a new sync code, freezes the old data on the relay so
              nothing more can be written to it, and copies every space to new locations. A computer that only has the old code keeps what it had but
              can't read or write anything new.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <ul className="list-disc space-y-1 pl-5 text-sm text-muted-foreground">
            <li>Every other computer stops syncing until you enter the new sync code on it. Changes it hasn't uploaded yet are kept and sent afterwards.</li>
            <li>Your relay must support freezing data; SSHelter checks that before it starts.</li>
            <li>You can cancel only until the old data is frozen.</li>
            {o.key_slots.some((s) => s.mode === "synced") && (
              <li>Keys you synced stay on every computer that has them. If a computer was lost, replace those keys on your servers.</li>
            )}
          </ul>
          <AlertDialogFooter>
            <AlertDialogCancel disabled={changeCode.isPending}>Cancel</AlertDialogCancel>
            <AlertDialogAction
              disabled={changeCode.isPending}
              onClick={(e) => {
                // Keep the dialog open until the request settles: Radix's Close
                // (which Action composes) skips its auto-close when the click
                // handler calls preventDefault first.
                e.preventDefault();
                changeCode.mutate(undefined, { onSuccess: () => setConfirmChange(false) });
              }}
            >
              {changeCode.isPending && <Loader2 className="size-3.5 animate-spin" />} Change sync code
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </Section>
  );
}

function DevicesSection({ overview: o, now }: { overview: SyncOverview; now: number }) {
  const forget = useForgetDevice();
  return (
    <Section
      title="Devices"
      description="Every computer in this sync account. Forget only removes a computer from this list — it does not lock it out: a computer that still has the sync code keeps syncing. To lock out a lost computer, change the sync code."
    >
      <SettingsGroup>
        {deviceRows(o, now).map((d) => (
          <SettingsRow key={d.id} label={d.name} description={d.detail}>
            {!d.isThis && (
              <Button type="button" variant="ghost" size="sm" className="h-7 text-muted-foreground" aria-label={`Forget ${d.name}`} disabled={forget.isPending} onClick={() => forget.mutate({ deviceId: d.id })}>
                <UserMinus className="size-3.5" /> Forget
              </Button>
            )}
          </SettingsRow>
        ))}
      </SettingsGroup>
    </Section>
  );
}

function LeaveSection({ overview: o }: { overview: SyncOverview }) {
  const leave = useLeaveAccount();
  const [open, setOpen] = useState(false);
  const [deleteRemote, setDeleteRemote] = useState(false);
  // null = this computer may also delete the account from the relay.
  const deleteNote = deleteAccountNote(o);
  // Leave stays available during a sync code change; the dialog says what leaving does to it.
  const rotationNote = leaveRotationNote(o);
  // Changes made here and not uploaded yet never reach the other computers.
  const unsentNote = leaveUnsentNote(o);

  return (
    <Section title="Advanced" description="The relay only stores encrypted records.">
      <SettingsGroup>
        <SettingsRow label="Leave sync account" description="This computer stops syncing; its space files become local files that ssh keeps reading.">
          <Button
            type="button"
            variant="outline"
            size="sm"
            className="h-7 text-destructive hover:text-destructive"
            onClick={() => {
              setDeleteRemote(false);
              setOpen(true);
            }}
          >
            Leave…
          </Button>
        </SettingsRow>
      </SettingsGroup>

      <AlertDialog
        open={open}
        onOpenChange={(next) => {
          if (!leave.isPending) setOpen(next);
        }}
      >
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Leave the sync account?</AlertDialogTitle>
            <AlertDialogDescription>
              This computer stops syncing. Its space files move to ~/.ssh/sshelter-local/ and keep working as local files: ssh still reads
              them, and you can later move their hosts into another sync account. Joining again needs the sync code.
            </AlertDialogDescription>
          </AlertDialogHeader>
          {o.key_slots.length > 0 && <p className="text-sm text-muted-foreground">Keys in ~/.ssh/sshelter/keys stay on this computer.</p>}
          {unsentNote && <p className={cn("text-sm", TONE_TEXT.warning)}>{unsentNote}</p>}
          {rotationNote && <p className={cn("text-sm", TONE_TEXT.warning)}>{rotationNote}</p>}
          {deleteNote === null ? (
            <label className="flex items-start gap-2 text-sm">
              <Checkbox className="mt-0.5" checked={deleteRemote} onCheckedChange={(v) => setDeleteRemote(v === true)} />
              <span>
                Also delete the sync account and every space from the relay. No other computer is listed; without this, the relay deletes them after
                180 days unused.
              </span>
            </label>
          ) : (
            <p className="text-sm text-muted-foreground">{deleteNote}</p>
          )}
          <AlertDialogFooter>
            <AlertDialogCancel disabled={leave.isPending}>Cancel</AlertDialogCancel>
            <AlertDialogAction
              disabled={leave.isPending}
              onClick={(e) => {
                // Keep the dialog open until the request settles (see the change-code dialog).
                e.preventDefault();
                leave.mutate(
                  leaveRequest(o, deleteRemote),
                  {
                    onSuccess: () => {
                      setOpen(false);
                      toast.success("Left the sync account");
                    },
                  },
                );
              }}
            >
              {leave.isPending && <Loader2 className="size-3.5 animate-spin" />} Leave
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </Section>
  );
}
