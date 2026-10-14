import { useRef, useState } from "react";
import { useQueryClient } from "@tanstack/react-query";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import {
  applyRecordOverview,
  downloadRecordKey,
  setRecordKeySync,
  type RecordOverview,
} from "@/lib/records";
import { revealHidden } from "@/lib/sync-approvals";
import { copyText } from "@/lib/clipboard";
import { isValidSlotName } from "@/lib/key-slots";
import { clearKeyDraft, submitKeyDraft } from "./panel-actions";
import { RecordField } from "./form";
export function RecordsKeysPanel({ overview }: { overview: RecordOverview }) {
  const client = useQueryClient();
  const [mode, setMode] = useState<"import" | "generate" | null>(null);
  const [draft, setDraft] = useState(clearKeyDraft);
  const [confirming, setConfirming] = useState<{
    id: string;
    enabled: boolean;
  } | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const inFlight = useRef(false);
  const update = (patch: Partial<typeof draft>) =>
    setDraft((current) => ({ ...current, ...patch }));
  const reset = () => {
    setDraft(clearKeyDraft());
    setMode(null);
  };
  const submit = async () => {
    if (inFlight.current) return;
    inFlight.current = true;
    try {
      if (await submitKeyDraft(client, draft, update, mode === "generate"))
        reset();
    } finally {
      inFlight.current = false;
    }
  };
  const publicAction = async (action: () => Promise<void>) => {
    if (inFlight.current) return;
    inFlight.current = true;
    setBusy(true);
    setError(null);
    try {
      await action();
    } catch {
      setError(
        "The key action could not be completed. Refresh the workspace and retry.",
      );
    } finally {
      inFlight.current = false;
      setBusy(false);
    }
  };
  return (
    <div className="mx-auto max-w-3xl space-y-6 p-6">
      <header className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h1 className="text-lg font-semibold">Keys</h1>
          <p className="text-sm text-muted-foreground">
            New keys are local until you choose to sync them. Sync changes may
            be waiting for the relay.
          </p>
        </div>
        {!mode && (
          <div className="flex gap-2">
            <Button
              variant="outline"
              disabled={busy}
              onClick={() => {
                reset();
                setMode("import");
              }}
            >
              Import private key
            </Button>
            <Button
              disabled={busy}
              onClick={() => {
                reset();
                setMode("generate");
              }}
            >
              Generate key
            </Button>
          </div>
        )}
      </header>
      {error && (
        <p role="alert" className="text-sm text-destructive">
          {error}
        </p>
      )}
      {mode && (
        <section className="space-y-4 rounded-md border p-4">
          <h2 className="text-sm font-semibold">
            {mode === "import" ? "Import private key" : "Generate Ed25519 key"}
          </h2>
          <fieldset disabled={draft.busy} className="space-y-4">
            <RecordField label="Key name">
              <Input
                value={draft.name}
                placeholder="work_key"
                onChange={(e) => update({ name: e.target.value })}
              />
            </RecordField>
            {mode === "import" && (
              <RecordField label="Private key">
                <Textarea
                  value={draft.privateText}
                  autoComplete="off"
                  className="min-h-40 font-mono text-xs"
                  onChange={(e) => update({ privateText: e.target.value })}
                />
                <p className="text-xs text-muted-foreground">
                  The key is copied into SSHelter's vault. This form does not
                  remove the source key.
                </p>
              </RecordField>
            )}
            {mode === "generate" && (
              <p className="text-sm text-muted-foreground">
                Creates an Ed25519 key in this device's vault.
              </p>
            )}
            {draft.error && (
              <p role="alert" className="text-sm text-destructive">
                {draft.error}
              </p>
            )}
            <div className="flex gap-2">
              <Button
                disabled={
                  !isValidSlotName(draft.name) ||
                  (mode === "import" && !draft.privateText.trim())
                }
                onClick={submit}
              >
                {draft.busy
                  ? "Working…"
                  : mode === "import"
                    ? "Import key"
                    : "Generate"}
              </Button>
              <Button variant="outline" onClick={reset}>
                Cancel
              </Button>
            </div>
          </fieldset>
        </section>
      )}
      {overview.keys.length === 0 && (
        <p className="text-sm text-muted-foreground">No key references yet.</p>
      )}
      {overview.keys.map((key) => (
        <section key={key.id} className="space-y-3 rounded-md border p-4">
          <div className="flex flex-wrap justify-between gap-2">
            <div>
              <h2 className="font-medium">
                {revealHidden(key.public?.name ?? key.id)}
              </h2>
              <p className="text-xs text-muted-foreground">
                {key.authority === "account" ? "Account key" : "Local key"} ·{" "}
                {key.status.replace(/_/g, " ")} ·{" "}
                {typeof key.synced !== "boolean"
                  ? "Sync state unavailable"
                  : key.synced
                    ? "Sync enabled"
                    : "Sync disabled"}
              </p>
            </div>
            <div className="flex flex-wrap gap-2">
              {key.public && (
                <Button
                  size="sm"
                  variant="outline"
                  disabled={busy || draft.busy}
                  onClick={() =>
                    publicAction(() => copyText(key.public!.public_key))
                  }
                >
                  Copy public key
                </Button>
              )}
              {key.status === "needs_material" &&
                key.authority === "account" && (
                  <Button
                    size="sm"
                    disabled={
                      busy || draft.busy || overview.shared_writes_blocked
                    }
                    onClick={() =>
                      publicAction(async () => {
                        applyRecordOverview(
                          client,
                          await downloadRecordKey(key.id),
                        );
                      })
                    }
                  >
                    Download synced key
                  </Button>
                )}
              {key.status === "available" && overview.account && (
                <Button
                  size="sm"
                  variant="outline"
                  disabled={
                    busy ||
                    draft.busy ||
                    overview.shared_writes_blocked ||
                    typeof key.synced !== "boolean"
                  }
                  onClick={() => {
                    if (typeof key.synced === "boolean")
                      setConfirming({ id: key.id, enabled: !key.synced });
                  }}
                >
                  {typeof key.synced !== "boolean"
                    ? "Sync state unavailable"
                    : key.synced
                      ? "Stop syncing"
                      : "Sync key"}
                </Button>
              )}
            </div>
          </div>
          {key.public && (
            <>
              <p className="break-all font-mono text-xs">
                {revealHidden(key.public.fingerprint)}
              </p>
              <p className="break-all font-mono text-xs text-muted-foreground">
                {revealHidden(key.public.public_key)}
              </p>
            </>
          )}
          {key.status === "available" && (
            <p className="text-xs text-muted-foreground">
              Private key availability is checked when connecting.
            </p>
          )}
          {key.status === "conflict" && (
            <p className="text-sm text-destructive">
              Local and account key metadata conflict. Connecting and
              downloading are blocked until the conflict is reviewed.
            </p>
          )}
          {key.status === "deleted" && (
            <p className="text-sm text-muted-foreground">
              This account key was deleted. A local copy cannot replace its
              account identity.
            </p>
          )}
          {confirming?.id === key.id && (
            <div className="space-y-3 border-t pt-3">
              <p className="text-sm">
                {confirming.enabled
                  ? "Sync this key to your other computers? The encrypted private key will be uploaded to your account."
                  : "Stop syncing this key? Copies already downloaded on other computers remain there."}
              </p>
              <div className="flex gap-2">
                <Button
                  disabled={
                    busy ||
                    draft.busy ||
                    overview.shared_writes_blocked ||
                    typeof key.synced !== "boolean" ||
                    key.status !== "available" ||
                    confirming.enabled === key.synced
                  }
                  onClick={() =>
                    publicAction(async () => {
                      if (
                        typeof key.synced !== "boolean" ||
                        key.status !== "available" ||
                        confirming.enabled === key.synced
                      )
                        return;
                      applyRecordOverview(
                        client,
                        await setRecordKeySync(key.id, confirming.enabled),
                      );
                      setConfirming(null);
                    })
                  }
                >
                  {confirming.enabled ? "Confirm sync" : "Confirm stop"}
                </Button>
                <Button
                  variant="outline"
                  disabled={busy || draft.busy}
                  onClick={() => setConfirming(null)}
                >
                  Cancel
                </Button>
              </div>
            </div>
          )}
        </section>
      ))}
    </div>
  );
}
