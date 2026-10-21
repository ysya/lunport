import { useEffect, useRef, useState } from "react";
import { useQueryClient } from "@tanstack/react-query";
import { open } from "@tauri-apps/plugin-dialog";
import { Button } from "@/components/ui/button";
import { PageHeader } from "@/components/app/PageHeader";
import { ActionBar, FormSection, WorkflowSteps } from "@/components/app/Workflow";
import { Input } from "@/components/ui/input";
import { Checkbox } from "@/components/ui/checkbox";
import { Label } from "@/components/ui/label";
import {
  cancelRecordImport,
  previewRecordImport,
  recordsPendingImportsKey,
  usePendingRecordImports,
  type ImportPreviewResult,
  type ImportResult,
} from "@/lib/records";
import { revealHidden } from "@/lib/sync-approvals";
import { submitImportConsent, resumeImport } from "./panel-actions";
import { RecordField } from "./form";
export function ImportReview({
  preview,
  copies,
  setCopies,
  busy,
}: {
  preview: ImportPreviewResult;
  copies: string[];
  setCopies: (ids: string[]) => void;
  busy: boolean;
}) {
  const groups = preview.preview.groups ?? [];
  const groupNames = new Map(groups.map((group) => [group.id, group.payload.name]));
  const refs = [
    ...new Map(
      preview.preview.key_references.map((reference) => [
        reference.key_id,
        reference,
      ]),
    ).values(),
  ];
  return (
    <div className="space-y-4">
      {groups.length > 0 && (
        <FormSection title={`Groups to import (${groups.length})`} description="Groups, their hierarchy and connection defaults are saved to the local library.">
          <div className="app-review-list">
            {groups.map((group) => (
              <div key={group.id} className="app-review-row">
                <div className="min-w-0">
                  <p className="text-sm font-medium">{revealHidden(group.payload.name)}</p>
                  {group.payload.parent_id && <p className="text-xs text-muted-foreground">Parent: {revealHidden(groupNames.get(group.payload.parent_id) ?? group.payload.parent_id)}</p>}
                </div>
              </div>
            ))}
          </div>
        </FormSection>
      )}
      <FormSection title={`Hosts to import (${preview.preview.candidates.length})`} description="Hosts are saved to the local library. Review any connection warnings before continuing.">
        <div className="app-review-list">
        {preview.preview.candidates.map((candidate) => (
          <div key={candidate.id} className="app-review-row">
            <div className="min-w-0">
            <p className="text-sm font-medium">
              {revealHidden(candidate.payload.alias)}
            </p>
            <p className="break-all font-mono text-xs text-muted-foreground">
              {revealHidden(candidate.payload.hostname)}:
              {candidate.payload.port} · Local
            </p>
            {candidate.payload.group_id && <p className="text-xs text-muted-foreground">Group: {revealHidden(groupNames.get(candidate.payload.group_id) ?? candidate.payload.group_id)}</p>}
            </div>
            {candidate.payload.imported?.unsupported.some(
              (setting) => setting.requires_review,
            ) && (
              <p className="text-xs text-destructive">
                Needs review before connecting
              </p>
            )}
          </div>
        ))}
        </div>
      </FormSection>
      {preview.preview.warnings.length > 0 && (
        <FormSection title="Import notes">
          {preview.preview.warnings.map((warning, index) => (
            <p key={index} className="text-xs whitespace-pre-wrap">
              <span
                className={
                  warning.blocks_connection
                    ? "text-destructive"
                    : "text-muted-foreground"
                }
              >
                {revealHidden(
                  `${warning.location.path}:${warning.location.line} · ${warning.keyword}: ${warning.reason}`,
                )}
              </span>
            </p>
          ))}
        </FormSection>
      )}
      {refs.length > 0 && (
        <FormSection title="Optional key copies" description="Choose each private key to copy into Lunport. Source files remain in place. Hosts with missing keys can be saved and completed later.">
          {refs.map((reference) => (
            <div key={reference.key_id} className="space-y-1">
              <Label className="flex items-center gap-2">
                <Checkbox
                  checked={copies.includes(reference.key_id)}
                  disabled={busy || reference.resolved_path === null}
                  onCheckedChange={(checked) =>
                    setCopies(
                      checked === true
                        ? [...new Set([...copies, reference.key_id])]
                        : copies.filter((id) => id !== reference.key_id),
                    )
                  }
                />
                Copy {revealHidden(reference.value)}
              </Label>
              <p className="ml-6 break-all text-xs text-muted-foreground">
                {revealHidden(reference.resolved_path ?? "Unresolved key path")}
                {reference.fingerprint &&
                  ` · ${revealHidden(reference.fingerprint)}`}
              </p>
            </div>
          ))}
        </FormSection>
      )}
      <details className="text-xs text-muted-foreground">
        <summary className="cursor-pointer">
          Reviewed source files ({preview.preview.provenance.length})
        </summary>
        <ul className="mt-2 space-y-2">
          {preview.preview.provenance.map((source) => (
            <li key={source.canonical_path} className="break-all">
              {revealHidden(source.path)} · {source.bytes} bytes
              <br />
              SHA256 {source.digest}
            </li>
          ))}
        </ul>
      </details>
    </div>
  );
}
export function RecordsImportPanel() {
  const client = useQueryClient();
  const pending = usePendingRecordImports();
  const [source, setSource] = useState("");
  const [preview, setPreview] = useState<ImportPreviewResult | null>(null);
  const [copies, setCopies] = useState<string[]>([]);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [consumed, setConsumed] = useState(false);
  const [receipt, setReceipt] = useState<ImportResult["receipt"] | null>(null);
  const inFlight = useRef(false);
  const token = useRef<string | null>(null);
  const mounted = useRef(true);
  const reviewRegion = useRef<HTMLDivElement>(null);
  const resultRegion = useRef<HTMLElement>(null);
  const sourceInput = useRef<HTMLInputElement>(null);
  useEffect(() => {
    if (preview) reviewRegion.current?.focus();
    else if (receipt) resultRegion.current?.focus();
  }, [preview, receipt]);
  useEffect(() => {
    mounted.current = true;
    return () => {
      mounted.current = false;
      if (token.current) void cancelRecordImport(token.current).catch(() => {});
    };
  }, []);
  const cancel = () => {
    if (token.current) void cancelRecordImport(token.current).catch(() => {});
    token.current = null;
    setPreview(null);
    setCopies([]);
    setConsumed(false);
    setError(null);
  };
  const run = async (operation: () => Promise<void>) => {
    if (inFlight.current) return;
    inFlight.current = true;
    setBusy(true);
    setError(null);
    try {
      await operation();
    } catch (failure) {
      if (mounted.current)
        setError(
          revealHidden(
            failure instanceof Error ? failure.message : String(failure),
          ),
        );
    } finally {
      inFlight.current = false;
      if (mounted.current) setBusy(false);
    }
  };
  const requestPreview = () =>
    run(async () => {
      cancel();
      const result = await previewRecordImport(source);
      if (!mounted.current) {
        await cancelRecordImport(result.token);
        return;
      }
      token.current = result.token;
      setPreview(result);
      setCopies([]);
      setReceipt(null);
    });
  const confirm = () =>
    run(async () => {
      if (!preview || consumed) return;
      setConsumed(true);
      token.current = null;
      try {
        const result = await submitImportConsent(client, preview, copies);
        if (mounted.current) {
          setReceipt(result.receipt);
          setPreview(null);
          setCopies([]);
        }
      } finally {
        await client.invalidateQueries({ queryKey: recordsPendingImportsKey });
      }
    });
  const resume = (importId: string) =>
    run(async () => {
      const result = await resumeImport(client, importId);
      if (mounted.current) setReceipt(result.receipt);
      await client.invalidateQueries({ queryKey: recordsPendingImportsKey });
    });
  const chooseFile = () =>
    run(async () => {
      const path = await open({
        multiple: false,
        directory: false,
        title: "Choose SSH configuration or Lunport hosts",
      });
      if (typeof path === "string" && mounted.current) {
        cancel();
        setSource(path);
      }
    });
  return (
    <div className="app-workflow-page space-y-6" aria-busy={busy}>
      <PageHeader title="Import hosts" description="Review an SSH configuration, a Lunport host export, or an old Lunport sync-state.json. Saved-workspace imports restore hosts and Groups; assign new SSH keys afterward. Source files stay in place." />
      <WorkflowSteps steps={["Choose source", "Review", "Finish"]} current={preview ? 1 : receipt ? 2 : 0} complete={!!receipt && !preview} />
      {error && (
        <p
          role="alert"
          className="app-task-error whitespace-pre-wrap"
        >
          {error}
        </p>
      )}
      {receipt && (
        <section ref={resultRegion} tabIndex={-1} role="status" className="app-notice space-y-2 outline-none">
          <h2>Import completed</h2>
          <p>
          Import completed: {receipt.host_ids.length} hosts,{" "}
          {(receipt.group_ids ?? []).length} Groups,{" "}
          {receipt.copied_key_ids.length} copied keys.
          </p>
        </section>
      )}
      {!preview && (
        <FormSection title={receipt ? "Import another file" : "Source file"} description="Choose an SSH configuration or a saved sync-state.json, then review the hosts before importing.">
          <RecordField label="Source file">
            <Input
              ref={sourceInput}
              value={source}
              disabled={busy}
              placeholder="/path/to/ssh/config or lunport-hosts.json"
              className="font-mono"
              onChange={(event) => setSource(event.target.value)}
            />
          </RecordField>
          <ActionBar label="Source actions">
            <Button variant="outline" disabled={busy} onClick={chooseFile}>
              Choose file
            </Button>
            <Button disabled={busy || !source.trim()} onClick={requestPreview}>
              {busy ? "Working…" : "Preview import"}
            </Button>
          </ActionBar>
        </FormSection>
      )}
      {preview && (
        <div ref={reviewRegion} role="region" aria-label="Import review" tabIndex={-1} className="space-y-6 outline-none">
          <p className="break-all font-mono text-xs text-muted-foreground">{revealHidden(source)}</p>
          <ImportReview
            preview={preview}
            copies={copies}
            setCopies={setCopies}
            busy={busy || consumed}
          />
          <ActionBar label="Import actions" hint={consumed ? "This preview was already submitted. Resume a pending import below, or preview the file again." : `${copies.length} private key ${copies.length === 1 ? "copy" : "copies"} selected.`}>
            <Button variant="outline" disabled={busy} onClick={() => { cancel(); requestAnimationFrame(() => sourceInput.current?.focus()); }}>
              {consumed ? "Preview again" : "Cancel import"}
            </Button>
            <Button
              disabled={
                busy || consumed || (preview.preview.candidates.length === 0 && (preview.preview.groups ?? []).length === 0)
              }
              onClick={confirm}
            >
              {busy
                ? "Working…"
                : `Import ${preview.preview.candidates.length} hosts${(preview.preview.groups ?? []).length > 0 ? ` and ${preview.preview.groups!.length} Groups` : ""}`}
            </Button>
          </ActionBar>
        </div>
      )}
      <FormSection title="Pending imports" description="Continue imports whose saved progress still needs to finish." actions={
          <Button
            variant="outline"
            size="sm"
            disabled={busy || pending.isFetching}
            onClick={() => void pending.refetch()}
          >
            Refresh pending imports
          </Button>
      }>
        {pending.isPending ? <p role="status" className="text-sm text-muted-foreground">Loading pending imports…</p> : pending.isError ? (
          <p role="alert" className="app-task-error">
            Pending imports could not be read.
          </p>
        ) : (pending.data ?? []).length === 0 ? (
          <p className="text-sm text-muted-foreground">No pending imports.</p>
        ) : (
          pending.data?.map((entry) => (
            <div
              key={entry.import_id}
              className="app-review-row"
            >
              <div>
                <p className="font-mono text-xs">{entry.import_id}</p>
                <p className="text-xs text-muted-foreground">
                  {revealHidden(entry.phase)} · {entry.host_count} hosts ·{" "}
                  {entry.group_count ?? 0} Groups · {entry.key_count} keys
                </p>
              </div>
              <Button
                variant="outline"
                disabled={busy}
                onClick={() => resume(entry.import_id)}
              >
                Retry import
              </Button>
            </div>
          ))
        )}
      </FormSection>
    </div>
  );
}
