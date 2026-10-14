import { useEffect, useRef, useState } from "react";
import { useQueryClient } from "@tanstack/react-query";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import { Checkbox } from "@/components/ui/checkbox";
import { Label } from "@/components/ui/label";
import {
  applyRecordOverview,
  createRecordSpace,
  selectRecordSpace,
  recordAccountWords,
  resumeRecordAccount,
  setRecordRelayUrl,
  type RecordOverview,
} from "@/lib/records";
import { revealHidden } from "@/lib/sync-approvals";
import { clearAccountDraft, submitAccountDraft } from "./panel-actions";
import { RecordField } from "./form";
import { RecordsMigrationPanel } from "./MigrationPanel";
import { RecordsAccountLifecyclePanel } from "./AccountLifecyclePanel";

export function RecordsAccountPanel({
  overview,
}: {
  overview: RecordOverview;
}) {
  const client = useQueryClient();
  const [migrationOpen, setMigrationOpen] = useState(false);
  const [recoveryVersion, setRecoveryVersion] = useState(0);
  const [mode, setMode] = useState<"create" | "join" | null>(null);
  const [draft, setDraft] = useState(clearAccountDraft);
  const [name, setName] = useState("");
  const [relay, setRelay] = useState(overview.relay_url);
  const [relayDirty, setRelayDirty] = useState(false);
  const [settingsBusy, setBusy] = useState(false);
  const [lifecycleBusy, setLifecycleBusy] = useState(false);
  const busy = settingsBusy || lifecycleBusy;
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
      if (await submitAccountDraft(client, draft, update, mode === "create"))
        setMode(null);
    } finally {
      inFlight.current = false;
    }
  };
  const run = async (operation: () => Promise<void>) => {
    if (inFlight.current || lifecycleBusy) return;
    inFlight.current = true;
    setBusy(true);
    setError(null);
    try {
      await operation();
    } catch {
      setError(
        "Could not update sync settings. Refresh and retry the pending setup if one is listed.",
      );
    } finally {
      inFlight.current = false;
      setBusy(false);
    }
  };
  const resume = () =>
    run(async () => {
      const result = await resumeRecordAccount(draft.words || undefined);
      update({ words: "", error: null });
      applyRecordOverview(client, result);
      setRecoveryVersion((current) => current + 1);
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
    <div className="mx-auto max-w-3xl space-y-6 p-6">
      <header className="space-y-2">
        <h1 className="text-lg font-semibold">Sync</h1>
        <p className="text-sm text-muted-foreground">
          Sync across your devices with a private code. No login is required.
          The relay stores encrypted data; you choose which hosts and keys to
          share.
        </p>
      </header>
      {draft.createdWords && (
        <section className="space-y-3 rounded-md border p-4">
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
          <Button onClick={reset}>I saved the code</Button>
        </section>
      )}
      {draft.error && (
        <p
          role="alert"
          className="text-sm text-destructive whitespace-pre-wrap"
        >
          {revealHidden(draft.error)}
        </p>
      )}
      {pending && (
        <section className="space-y-3 rounded-md border p-4">
          <h2 className="font-medium">Sync operation is pending</h2>
          <p className="text-sm text-muted-foreground">
            {pending.kind.replace(/_/g, " ")} · {revealHidden(pending.phase)}
          </p>
          <p className="break-all font-mono text-xs text-muted-foreground">
            {pending.id}
          </p>
          {pending.kind !== "create_space" &&
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
          <Button disabled={busy || draft.busy} onClick={resume}>
            Retry sync setup
          </Button>
          {pending.kind !== "create_space" &&
            pending.kind !== "leave_account" && (
              <Button
                variant="outline"
                disabled={busy || draft.busy || !draft.words}
                onClick={() => update({ words: "" })}
              >
                Clear recovery code
              </Button>
            )}
        </section>
      )}
      <section className="space-y-3 border-t pt-4">
        <RecordField label="Relay URL">
          <Input
            type="url"
            value={relay}
            disabled={relayLocked || busy || draft.busy}
            placeholder="https://your-relay.example"
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
            <Button
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
            </Button>
          </>
        )}
      </section>
      {overview.account ? (
        <section className="space-y-3 rounded-md border p-4">
          <h2 className="font-medium">
            {revealHidden(overview.account.device_name)}
          </h2>
          <p className="break-all font-mono text-xs text-muted-foreground">
            Chain {overview.account.chain_id}
          </p>
          <Button
            variant="outline"
            disabled={busy || draft.busy || !!pending}
            onClick={showCode}
          >
            Show sync code
          </Button>
        </section>
      ) : !mode ? (
        <section className="space-y-3">
          <p className="text-sm text-muted-foreground">
            Hosts and keys stay on this device until you create or join a sync
            chain and choose what to sync.
          </p>
          <div className="flex gap-2">
            <Button
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
        </section>
      ) : (
        <section className="space-y-4 rounded-md border p-4">
          <h2 className="font-medium">
            {mode === "create" ? "Create sync chain" : "Join with sync code"}
          </h2>
          <fieldset
            disabled={draft.busy || overview.shared_writes_blocked || !!pending}
            className="space-y-4"
          >
            <RecordField label="Device name">
              <Input
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
            <div className="flex gap-2">
              <Button
                disabled={
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
              <Button variant="outline" onClick={reset}>
                Cancel
              </Button>
            </div>
          </fieldset>
        </section>
      )}
      {overview.shared_writes_blocked && (
        <p role="status" className="text-sm text-destructive">
          Shared changes are paused while account data is reviewed. Local hosts
          remain editable.
        </p>
      )}
      {error && (
        <p role="alert" className="text-sm text-destructive">
          {error}
        </p>
      )}
      {overview.account && (
        <section className="space-y-4 border-t pt-4">
          <h2 className="font-medium">Spaces</h2>
          <p className="text-sm text-muted-foreground">
            Select a space to show its hosts. Move hosts into a selected space
            to sync them.
          </p>
          {overview.spaces.map((space) => (
            <Label key={space.id} className="flex items-center gap-2">
              <Checkbox
                checked={space.selected}
                disabled={
                  busy ||
                  draft.busy ||
                  space.missing ||
                  overview.shared_writes_blocked ||
                  !!pending
                }
                onCheckedChange={(checked) =>
                  run(async () => {
                    applyRecordOverview(
                      client,
                      await selectRecordSpace(space.id, checked === true),
                    );
                  })
                }
              />
              {revealHidden(space.name)}
              {space.missing && (
                <span className="text-muted-foreground">Missing space</span>
              )}
            </Label>
          ))}
          <div className="flex items-center gap-2">
            <Input
              aria-label="New space name"
              placeholder="New space name"
              value={name}
              disabled={
                busy ||
                draft.busy ||
                overview.shared_writes_blocked ||
                !!pending
              }
              onChange={(event) => setName(event.target.value)}
            />
            <Button
              disabled={
                busy ||
                draft.busy ||
                overview.shared_writes_blocked ||
                !!pending ||
                !name.trim()
              }
              onClick={() =>
                run(async () => {
                  applyRecordOverview(client, await createRecordSpace(name));
                  setName("");
                })
              }
            >
              Create space
            </Button>
          </div>
        </section>
      )}
      <RecordsAccountLifecyclePanel
        overview={overview}
        disabled={settingsBusy || draft.busy || !!draft.createdWords}
        onBusyChange={setLifecycleBusy}
        recoveryVersion={recoveryVersion}
      />
    </div>
  );
}
