import { useEffect, useRef, useState } from "react";
import { useQueryClient } from "@tanstack/react-query";
import { Button } from "@/components/ui/button";
import { Textarea } from "@/components/ui/textarea";
import { Checkbox } from "@/components/ui/checkbox";
import { Label } from "@/components/ui/label";
import { PageHeader } from "@/components/app/PageHeader";
import { ActionBar, FormSection, WorkflowSteps } from "@/components/app/Workflow";
import {
  recordsPendingMigrationsKey,
  usePendingRecordMigrations,
  type MigrationPreviewResult,
  type MigrationReceipt,
} from "@/lib/records";
import { revealHidden } from "@/lib/sync-approvals";
import {
  clearMigrationDraft,
  discardMigrationPreview,
  previewMigrationDraft,
  confirmMigrationDraft,
  resumeMigrationDraft,
  type MigrationDraft,
} from "./migration-actions";
import { RecordField } from "./form";
export function MigrationReview({
  preview,
  consent,
  busy,
  consumed,
  setConsent,
  confirm,
  cancel,
}: {
  preview: MigrationPreviewResult;
  consent: boolean;
  busy: boolean;
  consumed: boolean;
  setConsent: (value: boolean) => void;
  confirm: () => void;
  cancel?: () => void;
}) {
  const data = preview.preview;
  return (
    <FormSection title="Migration preview">
      <p className="text-sm">
        {data.host_count} hosts · {data.key_count} keys ·{" "}
        {data.selected_space_ids.length} selected spaces
      </p>
      <p className="text-xs text-muted-foreground">
        Saved source: {revealHidden(data.source_kind)} · Account format{" "}
        {data.account_schema}
      </p>
      {data.diagnostics.length > 0 && (
        <section className="space-y-2">
          <h3 className="text-sm font-medium">Preview notes</h3>
          {data.diagnostics.map((note, index) => (
            <p key={index} className="break-all text-xs text-muted-foreground">
              {revealHidden(note.code).replace(/_/g, " ")}
              {note.host_id && ` · Host ${note.host_id}`}
              {note.space_id && ` · Space ${note.space_id}`}
            </p>
          ))}
        </section>
      )}
      {!data.can_confirm && (
        <p role="status" className="text-sm text-destructive">
          This preview cannot be confirmed. Resolve the listed issues and
          preview again.
        </p>
      )}
      <p className="text-sm text-muted-foreground">
        Migration uses saved settings. Save any edits before confirming.
        Existing sources are retained for recovery.
      </p>
      <Label className="flex items-start gap-2">
        <Checkbox
          checked={consent}
          disabled={busy || consumed || !data.can_confirm}
          onCheckedChange={(checked) => setConsent(checked === true)}
        />
        <span>
          I have saved my edits. The old apps are stopped or all participating
          devices use a compatible version.
        </span>
      </Label>
      <details className="text-xs text-muted-foreground">
        <summary className="cursor-pointer">Reviewed source details</summary>
        <p className="mt-2 break-all font-mono">Digest {data.source_digest}</p>
        {data.selected_space_ids.map((id) => (
          <p key={id} className="break-all font-mono">
            Space {id}
          </p>
        ))}
      </details>
      <ActionBar label="Migration actions" hint={consumed ? "This preview was submitted. Resume an existing migration below, or prepare a new preview." : undefined}>
        {cancel && <Button variant="outline" disabled={busy} onClick={cancel}>{consumed ? "Preview again" : "Cancel preview"}</Button>}
        <Button disabled={busy || consumed || !data.can_confirm || !consent} onClick={confirm}>Confirm migration</Button>
      </ActionBar>
    </FormSection>
  );
}
export function MigrationOutcome({
  receipt,
  busy,
  resume,
}: {
  receipt: MigrationReceipt;
  busy: boolean;
  resume: () => void;
}) {
  return (
    <section className="app-notice space-y-3" role="status">
      <h2 className="font-medium">
        {receipt.complete ? "Migration completed" : "Migration pending"}
      </h2>
      <p className="break-all text-xs text-muted-foreground">
        {revealHidden(receipt.phase)} · {receipt.migration_id}
      </p>
      {!receipt.complete && (
        <>
          <p className="text-sm text-muted-foreground">
            Migration progress is retained when this panel closes. Resume this
            operation to continue; closing does not undo completed steps.
          </p>
          <Button disabled={busy} onClick={resume}>
            Resume migration
          </Button>
        </>
      )}
    </section>
  );
}
export function RecordsMigrationPanel({
  initialWords = "",
  onWordsCleared,
  onClose,
}: {
  initialWords?: string;
  onWordsCleared?: () => void;
  onClose?: () => void;
}) {
  const client = useQueryClient();
  const pending = usePendingRecordMigrations();
  const [state, setState] = useState(() => clearMigrationDraft(initialWords));
  const inFlight = useRef(false);
  const token = useRef<string | null>(null);
  const mounted = useRef(true);
  const discardToken = () => {
    const current = token.current;
    token.current = null;
    if (current) void discardMigrationPreview(current);
  };
  const update = (patch: Partial<MigrationDraft>) => {
    if (!mounted.current) {
      if (patch.preview) void discardMigrationPreview(patch.preview.token);
      return;
    }
    if (Object.prototype.hasOwnProperty.call(patch, "preview"))
      token.current = patch.preview?.token ?? null;
    setState((current) => ({ ...current, ...patch }));
  };
  useEffect(() => {
    mounted.current = true;
    return () => {
      mounted.current = false;
      discardToken();
      onWordsCleared?.();
    };
  }, []);
  const reset = () => {
    discardToken();
    setState(clearMigrationDraft());
    onWordsCleared?.();
  };
  const close = () => {
    reset();
    onClose?.();
  };
  const preview = async () => {
    if (inFlight.current) return;
    inFlight.current = true;
    discardToken();
    try {
      if (await previewMigrationDraft(state, update)) onWordsCleared?.();
    } finally {
      inFlight.current = false;
    }
  };
  const confirm = async () => {
    if (inFlight.current) return;
    inFlight.current = true;
    try {
      await confirmMigrationDraft(client, state, update);
    } finally {
      inFlight.current = false;
      await client.invalidateQueries({ queryKey: recordsPendingMigrationsKey });
    }
  };
  const resume = async (id: string) => {
    if (inFlight.current) return;
    inFlight.current = true;
    try {
      if (await resumeMigrationDraft(client, id, update, state.words))
        onWordsCleared?.();
    } finally {
      inFlight.current = false;
      await client.invalidateQueries({ queryKey: recordsPendingMigrationsKey });
    }
  };
  return (
    <div className="app-workflow-page space-y-6" aria-busy={state.busy}>
      <PageHeader title="Move to the records workspace" description="Preview the saved workspace and review its hosts and keys before starting migration. The preview is read-only." actions={onClose && (
          <Button variant="outline" disabled={state.busy} onClick={close}>
            Close migration
          </Button>
      )} />
      <WorkflowSteps steps={["Saved workspace", "Review", "Finish"]} current={state.receipt ? 2 : state.preview ? 1 : 0} complete={state.receipt?.complete} />
      {state.error && (
        <p role="alert" className="app-task-error">
          {state.error}
        </p>
      )}
      {state.receipt && (
        <MigrationOutcome
          receipt={state.receipt}
          busy={state.busy}
          resume={() => void resume(state.receipt!.migration_id)}
        />
      )}
      {!state.preview && !state.receipt && (
        <FormSection title="Saved workspace">
          <RecordField label="Sync code (optional)">
            <Textarea
              autoComplete="off"
              value={state.words}
              disabled={state.busy}
              onChange={(event) => update({ words: event.target.value })}
            />
            <p className="text-xs text-muted-foreground">
              Leave this blank to preview the stored account. Supply a code for
              an older account or if the stored code is unavailable.
            </p>
          </RecordField>
          <ActionBar label="Migration source actions">
            <Button variant="outline" disabled={state.busy} onClick={reset}>
              Clear code
            </Button>
            <Button disabled={state.busy} onClick={preview}>
              {state.busy ? "Preparing preview…" : "Preview migration"}
            </Button>
          </ActionBar>
        </FormSection>
      )}
      {state.preview && (
        <>
          <MigrationReview
            preview={state.preview}
            consent={state.consent}
            busy={state.busy}
            consumed={state.consumed}
            setConsent={(value) => update({ consent: value })}
            confirm={() => void confirm()}
            cancel={reset}
          />
        </>
      )}
      {((state.receipt && !state.receipt.complete) ||
        (pending.data ?? []).length > 0) && (
        <RecordField label="Migration recovery code (optional)">
          <Textarea
            value={state.words}
            autoComplete="off"
            disabled={state.busy}
            onChange={(event) => update({ words: event.target.value })}
          />
          <p className="text-xs text-muted-foreground">
            Supply the original sync code if this device no longer has the
            staged account key. It is used only for the selected resume
            operation.
          </p>
          <Button
            variant="outline"
            disabled={state.busy || !state.words}
            onClick={() => {
              update({ words: "" });
              onWordsCleared?.();
            }}
          >
            Clear recovery code
          </Button>
        </RecordField>
      )}
      <FormSection title="Pending migrations" actions={
          <Button
            variant="outline"
            size="sm"
            disabled={state.busy || pending.isFetching}
            onClick={() => void pending.refetch()}
          >
            Refresh pending migrations
          </Button>
      }>
        {pending.isPending ? <p role="status" className="text-sm text-muted-foreground">Loading pending migrations…</p> : pending.isError ? (
          <p role="alert" className="app-task-error">
            Pending migrations could not be read.
          </p>
        ) : (pending.data ?? []).length === 0 ? (
          <p className="text-sm text-muted-foreground">
            No pending migrations.
          </p>
        ) : (
          pending.data?.map((entry) => (
            <div
              key={entry.migration_id}
              className="app-review-row"
            >
              <div>
                <p className="break-all font-mono text-xs">
                  {entry.migration_id}
                </p>
                <p className="text-xs text-muted-foreground">
                  {revealHidden(entry.phase)} · {entry.host_count} hosts ·{" "}
                  {entry.key_count} keys
                </p>
              </div>
              <Button
                variant="outline"
                disabled={state.busy}
                onClick={() => void resume(entry.migration_id)}
              >
                Resume migration
              </Button>
            </div>
          ))
        )}
      </FormSection>
    </div>
  );
}
