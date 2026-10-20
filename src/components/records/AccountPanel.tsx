import { useEffect, useRef, useState } from "react";
import { useQueryClient } from "@tanstack/react-query";
import { Button } from "@/components/ui/button";
import { PageHeader } from "@/components/app/PageHeader";
import { ActionBar, FormSection, WorkflowSteps } from "@/components/app/Workflow";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import {
  applyRecordOverview,
  enableLibrarySync,
  previewLibrarySync,
  recordAccountWords,
  resumeRecordAccount,
  setRecordRelayUrl,
  type RecordOverview,
  type LibrarySyncPreview,
  type LibraryRename,
} from "@/lib/records";
import { revealHidden } from "@/lib/sync-approvals";
import { clearAccountDraft, submitAccountDraft } from "./panel-actions";
import { RecordField } from "./form";
import { RecordsMigrationPanel } from "./MigrationPanel";
import { RecordsAccountLifecyclePanel } from "./AccountLifecyclePanel";
import { RecordConflictPanel } from "./ConflictPanel";
import { LibrarySyncReview } from "./LibrarySyncReview";
import { CentralAccountSection } from "./CentralAccountPanel";
import { librarySyncError, suggestedLibraryRenames } from "./library-sync";

export function RecordsAccountPanel({
  overview,
  onBusyChange,
}: {
  overview: RecordOverview;
  onBusyChange?: (busy: boolean) => void;
}) {
  const client = useQueryClient();
  const [migrationOpen, setMigrationOpen] = useState(false);
  const [recoveryVersion, setRecoveryVersion] = useState(0);
  const [mode, setMode] = useState<"create" | "join" | null>(null);
  const [draft, setDraft] = useState(clearAccountDraft);
  const deviceNameInput = useRef<HTMLInputElement>(null);
  const createTrigger = useRef<HTMLButtonElement>(null);
  const joinTrigger = useRef<HTMLButtonElement>(null);
  const codeRegion = useRef<HTMLElement>(null);
  const connectedRegion = useRef<HTMLDivElement>(null);
  const libraryHeading = useRef<HTMLHeadingElement>(null);
  const libraryTrigger = useRef<HTMLButtonElement>(null);
  const [focusLibrary, setFocusLibrary] = useState(false);
  const previousMode = useRef(mode);
  const hadCode = useRef(false);
  useEffect(() => {
    if (mode && mode !== previousMode.current) deviceNameInput.current?.focus();
    else if (!mode && previousMode.current && !overview.account) (previousMode.current === "create" ? createTrigger.current : joinTrigger.current)?.focus();
    else if (!mode && previousMode.current && overview.account && !draft.createdWords) connectedRegion.current?.focus();
    previousMode.current = mode;
  }, [mode, overview.account, draft.createdWords]);
  useEffect(() => {
    if (draft.createdWords) codeRegion.current?.focus();
    else if (hadCode.current) connectedRegion.current?.focus();
    hadCode.current = !!draft.createdWords;
  }, [draft.createdWords, overview.account?.chain_id]);
  useEffect(() => {
    if (focusLibrary && libraryHeading.current) {
      libraryHeading.current.focus();
      setFocusLibrary(false);
    }
  });
  const [upgradeConfirmed, setUpgradeConfirmed] = useState(false);
  const [libraryReview, setLibraryReview] = useState<LibrarySyncPreview | null>(null);
  const [libraryRenames, setLibraryRenames] = useState<LibraryRename[]>([]);
  const pendingRecords = [...overview.hosts, ...overview.groups].filter(
    (row) => row.scope.kind === "local",
  ).length;
  const needsUpgrade =
    (!overview.account || overview.shared_format_upgrade_required) &&
    (overview.groups.some((g) => g.scope.kind === "local") ||
      overview.hosts.some(
        (h) => h.scope.kind === "local" && h.payload.schema === 3,
      ));
  const [relay, setRelay] = useState(overview.relay_url);
  const [relayDirty, setRelayDirty] = useState(false);
  const [settingsBusy, setBusy] = useState(false);
  const [lifecycleBusy, setLifecycleBusy] = useState(false);
  const [conflictBusy, setConflictBusy] = useState(false);
  const [centralBusy, setCentralBusy] = useState(false);
  const busy = settingsBusy || lifecycleBusy || conflictBusy || centralBusy;
  const active = busy || draft.busy || !!overview.syncing;
  useEffect(() => {
    onBusyChange?.(busy || draft.busy);
    return () => onBusyChange?.(false);
  }, [busy, draft.busy, onBusyChange]);
  const [error, setError] = useState<string | null>(null);
  const inFlight = useRef(false);
  useEffect(() => {
    if (!relayDirty) setRelay(overview.relay_url);
  }, [overview.relay_url, relayDirty]);
  const update = (patch: Partial<typeof draft>) =>
    setDraft((current) => ({ ...current, ...patch }));
  const reset = () => {
    setDraft(clearAccountDraft());
    setMode(null);
  };
  const submit = async () => {
    if (inFlight.current || lifecycleBusy) return;
    inFlight.current = true;
    try {
      if (
        await submitAccountDraft(
          client,
          draft,
          update,
          mode === "create",
          needsUpgrade ? upgradeConfirmed : undefined,
        )
      )
        setMode(null);
    } finally {
      inFlight.current = false;
    }
  };
  const run = async (
    operation: () => Promise<void>,
    failureMessage?: string | ((error: unknown) => string),
  ) => {
    if (inFlight.current || lifecycleBusy) return;
    inFlight.current = true;
    setBusy(true);
    setError(null);
    try {
      await operation();
    } catch (error) {
      setError(
        (typeof failureMessage === "function" ? failureMessage(error) : failureMessage) ??
          "Could not update sync settings. Refresh and retry the pending setup if one is listed.",
      );
    } finally {
      inFlight.current = false;
      setBusy(false);
    }
  };
  const prepareLibrary = (refreshOnly = false) => run(async () => {
    const preview = await previewLibrarySync();
    if (preview.conflicts.length || refreshOnly) {
      setLibraryReview(preview);
      setLibraryRenames(suggestedLibraryRenames(preview));
      return;
    }
    applyRecordOverview(client, await enableLibrarySync(upgradeConfirmed, { token: preview.token, renames: [] }));
    setFocusLibrary(true);
  }, librarySyncError);
  const includeReviewedLibrary = () => run(async () => {
    if (!libraryReview) return;
    applyRecordOverview(client, await enableLibrarySync(upgradeConfirmed, { token: libraryReview.token, renames: libraryRenames }));
    setLibraryReview(null);
  }, librarySyncError);
  const resume = () =>
    run(async () => {
      const result = await resumeRecordAccount(draft.words || undefined);
      update({ words: "", error: null });
      applyRecordOverview(client, result);
      setRecoveryVersion((current) => current + 1);
      if (!result.pending_account) setFocusLibrary(true);
    });
  const showCode = () =>
    run(async () => {
      // Codes are held in this component only, never in query data or mutation variables.
      const words = await recordAccountWords();
      update({ createdWords: words, words: "" });
    });
  const pending = overview.pending_account;
  const relayLocked = !!overview.account || !!pending;
  let validRelay = false;
  try {
    const url = new URL(relay);
    validRelay =
      url.protocol === "https:" ||
      (url.protocol === "http:" &&
        ["localhost", "127.0.0.1", "[::1]"].includes(url.hostname));
  } catch {
    /* Native validation remains authoritative. */
  }

  if (migrationOpen)
    return (
      <RecordsMigrationPanel
        initialWords={draft.words}
        onWordsCleared={() => update({ words: "", migrationOffered: false })}
        onClose={() => setMigrationOpen(false)}
      />
    );

  return (
    <div className="app-workflow-page space-y-6">
      {libraryReview && <LibrarySyncReview preview={libraryReview} renames={libraryRenames} setRenames={setLibraryRenames} busy={busy} error={error} confirm={includeReviewedLibrary} refresh={() => prepareLibrary(true)} cancel={() => { setLibraryReview(null); setError(null); }} restoreFocus={() => (libraryTrigger.current ?? libraryHeading.current)?.focus()} />}
      <PageHeader title="Sync" description="Sign in with a Passkey to sync your hosts, keys, Groups and tunnel rules with end-to-end encryption." />
      <CentralAccountSection disabled={settingsBusy || lifecycleBusy || conflictBusy || draft.busy || !!overview.syncing} onBusyChange={setCentralBusy} />
      <details open={!!overview.pending_account} className="space-y-4">
        <summary className="cursor-pointer text-sm font-medium">Older sync-code libraries</summary>
      <WorkflowSteps steps={["Relay", "Device", "Library sync"]} current={pending ? 1 : overview.account ? 2 : overview.relay_url ? 1 : 0} complete={!!overview.account && overview.library_enabled && !pending && !overview.shared_writes_blocked && !draft.createdWords} />
      <RecordConflictPanel conflicts={overview.conflicts ?? []} disabled={active || !!overview.pending_account} onBusyChange={setConflictBusy} />
      {draft.createdWords && (
        <section ref={codeRegion} tabIndex={-1} aria-label="Save your sync code" className="app-notice space-y-3 outline-none">
          <h2 className="font-medium">Save your sync code</h2>
          <p className="text-sm text-muted-foreground">
            Keep this code private. It lets another computer join your sync
            chain and unlock synced keys.
          </p>
          <Textarea
            aria-label="New sync code"
            value={draft.createdWords}
            readOnly
            autoComplete="off"
            className="font-mono"
          />
          <ActionBar label="Sync code actions"><Button onClick={reset}>I saved the code</Button></ActionBar>
        </section>
      )}
      {draft.error && (
        <p
          role="alert"
          className="app-task-error whitespace-pre-wrap"
        >
          {revealHidden(draft.error)}
        </p>
      )}
      {pending && (
        <section className="app-notice space-y-3" aria-busy={active}>
          <h2 className="font-medium">
            {active ? "Setting up sync…" : "Finish sync setup"}
          </h2>
          <p className="text-sm text-muted-foreground">
            {active
              ? "Please wait while this step finishes. Your saved records are kept."
              : "The previous setup did not finish. Resume it to continue using the same sync chain."}
          </p>
          <details className="text-xs text-muted-foreground">
            <summary>Setup details</summary>
            <p>
              {pending.kind.replace(/_/g, " ")} · {revealHidden(pending.phase)}
            </p>
            <p className="break-all font-mono">{pending.id}</p>
          </details>
          {!active &&
            pending.kind !== "create_space" &&
            pending.kind !== "leave_account" && (
              <RecordField label="Sync code for recovery (optional)">
                <Textarea
                  autoComplete="off"
                  value={draft.words}
                  disabled={busy || draft.busy}
                  onChange={(event) => update({ words: event.target.value })}
                />
                <p className="text-xs text-muted-foreground">
                  Supply the code if this device no longer has the staged
                  account key.
                </p>
              </RecordField>
            )}
          <ActionBar label="Sync recovery actions">
          {!active &&
            pending.kind !== "create_space" &&
            pending.kind !== "leave_account" && (
              <Button
                variant="outline"
                disabled={busy || draft.busy || !draft.words}
                onClick={() => update({ words: "" })}
              >
                Clear recovery code
              </Button>
            )}
          <Button disabled={active} onClick={resume}>
            {active ? "Working…" : "Resume sync setup"}
          </Button>
          </ActionBar>
        </section>
      )}
      <FormSection title="Relay connection" description="The relay carries encrypted changes between your devices.">
        <RecordField label="Relay URL">
          <Input
            type="url"
            value={relay}
            disabled={relayLocked || busy || draft.busy}
            placeholder="https://your-relay.example"
            className="font-mono"
            onChange={(event) => {
              setRelay(event.target.value);
              setRelayDirty(true);
            }}
          />
        </RecordField>
        {relayLocked ? (
          <p className="text-xs text-muted-foreground">
            The relay is fixed while joined to a sync chain or while setup is
            pending.
          </p>
        ) : (
          <>
            <p className="text-xs text-muted-foreground">
              Enter and save your HTTPS relay URL before creating or joining a
              sync chain.
            </p>
            <ActionBar label="Relay actions"><Button
              variant="outline"
              disabled={busy || draft.busy || !relayDirty || !validRelay}
              onClick={() =>
                run(async () => {
                  applyRecordOverview(client, await setRecordRelayUrl(relay));
                  setRelayDirty(false);
                })
              }
            >
              Save relay URL
            </Button></ActionBar>
          </>
        )}
      </FormSection>
      {overview.account ? (
        <FormSection title="Connected device">
          <div ref={connectedRegion} tabIndex={-1} aria-label="Connected device details" className="space-y-2 outline-none">
          <p className="text-sm font-medium">
            {revealHidden(overview.account.device_name)}
          </p>
          <p className="break-all font-mono text-xs text-muted-foreground">
            Chain {overview.account.chain_id}
          </p>
          </div>
          <div><Button
            variant="outline"
            disabled={busy || draft.busy || !!pending}
            onClick={showCode}
          >
            Show sync code
          </Button></div>
        </FormSection>
      ) : !mode ? (
        <FormSection title="Set up this device" description="Create a private sync chain or join one you already use.">
          <p className="text-sm text-muted-foreground">
            Your library works offline. Creating or joining sync includes all
            existing hosts and Groups on this device. Changes made offline are
            saved and sync when the connection returns.
          </p>
          <div className="app-page-actions">
            <Button
              ref={createTrigger}
              disabled={
                busy ||
                overview.shared_writes_blocked ||
                !!pending ||
                !overview.relay_url
              }
              onClick={() => {
                reset();
                setMode("create");
              }}
            >
              Create sync chain
            </Button>
            <Button
              ref={joinTrigger}
              variant="outline"
              disabled={
                busy ||
                overview.shared_writes_blocked ||
                !!pending ||
                !overview.relay_url
              }
              onClick={() => {
                reset();
                setMode("join");
              }}
            >
              Join with sync code
            </Button>
          </div>
        </FormSection>
      ) : (
        <FormSection title={mode === "create" ? "Create sync chain" : "Join with sync code"} description={mode === "create" ? "Name this device. You will receive a private code to connect your other computers." : "Name this device and enter the private code from a computer already in your chain."}>
          <fieldset
            disabled={draft.busy || overview.shared_writes_blocked || !!pending}
            className="space-y-4"
          >
            <RecordField label="Device name">
              <Input
                ref={deviceNameInput}
                value={draft.deviceName}
                onChange={(event) => update({ deviceName: event.target.value })}
              />
            </RecordField>
            {mode === "join" && (
              <RecordField label="Sync code">
                <Textarea
                  value={draft.words}
                  autoComplete="off"
                  onChange={(event) => update({ words: event.target.value })}
                />
              </RecordField>
            )}
            {mode === "join" && draft.migrationOffered && (
              <div className="space-y-2">
                <p className="text-sm text-muted-foreground">
                  If this account uses an older format, preview its migration
                  with the code above.
                </p>
                <Button
                  variant="outline"
                  disabled={draft.busy}
                  onClick={() => setMigrationOpen(true)}
                >
                  Preview older account migration
                </Button>
              </div>
            )}
            {needsUpgrade && (
              <label className="flex items-start gap-2 text-sm">
                <input
                  type="checkbox"
                  checked={upgradeConfirmed}
                  onChange={(event) =>
                    setUpgradeConfirmed(event.target.checked)
                  }
                />
                I have updated or stopped older clients. Include Groups and
                inherited settings using the current sync format.
              </label>
            )}
            <ActionBar label="Device setup actions">
              <Button variant="outline" onClick={reset}>
                Cancel
              </Button>
              <Button
                disabled={
                  (needsUpgrade && !upgradeConfirmed) ||
                  !draft.deviceName.trim() ||
                  (mode === "join" && !draft.words.trim())
                }
                onClick={submit}
              >
                {draft.busy
                  ? "Working…"
                  : mode === "create"
                    ? "Create chain"
                    : "Join chain"}
              </Button>
            </ActionBar>
          </fieldset>
        </FormSection>
      )}
      {overview.shared_writes_blocked && (
        <p role="status" className="text-sm text-muted-foreground">
          {active
            ? "Setting up sync… Shared changes will continue when this step finishes."
            : pending
              ? "Resume the pending setup to continue syncing changes."
              : "Sync changes are paused. Review account settings to continue."}
        </p>
      )}
      {error && !libraryReview && (
        <p role="alert" className="app-task-error">
          {error}
        </p>
      )}
      {overview.account && (
        <FormSection title="Library sync" headingRef={libraryHeading}>
          <p className="text-sm text-muted-foreground">
            {overview.library_enabled && !pendingRecords
              ? "All hosts and Groups are included. Offline changes sync automatically when connected."
              : `Include your entire library in sync. ${pendingRecords} existing hosts and Groups on this device will be included together.`}
          </p>
          {(!overview.library_enabled || pendingRecords > 0) && (
            <>
              {needsUpgrade && (
                <label className="flex items-start gap-2 text-sm">
                  <input
                    type="checkbox"
                    checked={upgradeConfirmed}
                    onChange={(event) =>
                      setUpgradeConfirmed(event.target.checked)
                    }
                  />
                  I have updated or stopped older clients. Include Groups and
                  inherited settings using the current sync format.
                </label>
              )}
              <ActionBar label="Library sync actions"><Button
                ref={libraryTrigger}
                disabled={
                  busy ||
                  draft.busy ||
                  !!pending ||
                  overview.shared_writes_blocked ||
                  (needsUpgrade && !upgradeConfirmed)
                }
                onClick={() => prepareLibrary()}
              >
                {overview.library_enabled
                  ? "Include remaining records"
                  : "Enable library sync"}
              </Button></ActionBar>
            </>
          )}
        </FormSection>
      )}
      <RecordsAccountLifecyclePanel
        overview={overview}
        disabled={settingsBusy || draft.busy || !!draft.createdWords}
        onBusyChange={setLifecycleBusy}
        recoveryVersion={recoveryVersion}
      />
      </details>
    </div>
  );
}
