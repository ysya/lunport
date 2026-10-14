import { useEffect, useRef, useState } from "react";
import { useQueryClient } from "@tanstack/react-query";
import { open } from "@tauri-apps/plugin-dialog";
import { Button } from "@/components/ui/button";
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
      <section className="space-y-2">
        <h2 className="font-medium">
          Hosts to import ({preview.preview.candidates.length})
        </h2>
        {preview.preview.candidates.map((candidate) => (
          <div key={candidate.id} className="rounded-md border p-3">
            <p className="text-sm font-medium">
              {revealHidden(candidate.payload.alias)}
            </p>
            <p className="text-xs text-muted-foreground">
              {revealHidden(candidate.payload.hostname)}:
              {candidate.payload.port} · Local
            </p>
            {candidate.payload.imported?.unsupported.some(
              (setting) => setting.requires_review,
            ) && (
              <p className="text-xs text-destructive">
                Needs review before connecting
              </p>
            )}
          </div>
        ))}
      </section>
      {preview.preview.warnings.length > 0 && (
        <section className="space-y-2">
          <h2 className="font-medium">Import notes</h2>
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
        </section>
      )}
      {refs.length > 0 && (
        <section className="space-y-3 rounded-md border p-4">
          <h2 className="font-medium">Optional key copies</h2>
          <p className="text-sm text-muted-foreground">
            Choose each private key to copy into SSHelter. Source files remain
            in place. Hosts with missing keys can be saved and completed later.
          </p>
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
        </section>
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
        title: "Choose SSH configuration to import",
      });
      if (typeof path === "string" && mounted.current) {
        cancel();
        setSource(path);
      }
    });
  return (
    <div className="mx-auto max-w-3xl space-y-6 p-6">
      <h1 className="text-lg font-semibold">Import SSH configuration</h1>
      <p className="text-sm text-muted-foreground">
        Review an existing file before importing hosts into the local workspace.
        The source configuration stays in place.
      </p>
      {error && (
        <p
          role="alert"
          className="text-sm text-destructive whitespace-pre-wrap"
        >
          {error}
        </p>
      )}
      {receipt && (
        <p role="status" className="rounded-md border p-3 text-sm">
          Import completed: {receipt.host_ids.length} hosts,{" "}
          {receipt.copied_key_ids.length} copied keys.
        </p>
      )}
      {!preview && (
        <section className="space-y-3">
          <RecordField label="Configuration file">
            <Input
              value={source}
              disabled={busy}
              placeholder="/path/to/ssh/config"
              onChange={(event) => setSource(event.target.value)}
            />
          </RecordField>
          <div className="flex gap-2">
            <Button variant="outline" disabled={busy} onClick={chooseFile}>
              Choose file
            </Button>
            <Button disabled={busy || !source.trim()} onClick={requestPreview}>
              {busy ? "Working…" : "Preview import"}
            </Button>
          </div>
        </section>
      )}
      {preview && (
        <>
          <ImportReview
            preview={preview}
            copies={copies}
            setCopies={setCopies}
            busy={busy || consumed}
          />
          <div className="flex flex-wrap gap-2">
            <Button
              disabled={
                busy || consumed || preview.preview.candidates.length === 0
              }
              onClick={confirm}
            >
              {busy
                ? "Working…"
                : `Import ${preview.preview.candidates.length} hosts`}
            </Button>
            <Button variant="outline" disabled={busy} onClick={cancel}>
              {consumed ? "Preview again" : "Cancel import"}
            </Button>
          </div>
          {consumed && (
            <p className="text-sm text-muted-foreground">
              This preview was already submitted. Resume a pending import below,
              or preview the file again.
            </p>
          )}
        </>
      )}
      <section className="space-y-3 border-t pt-4">
        <div className="flex items-center justify-between">
          <h2 className="font-medium">Pending imports</h2>
          <Button
            variant="outline"
            size="sm"
            disabled={busy || pending.isFetching}
            onClick={() => void pending.refetch()}
          >
            Refresh pending imports
          </Button>
        </div>
        {pending.isError ? (
          <p className="text-sm text-destructive">
            Pending imports could not be read.
          </p>
        ) : (pending.data ?? []).length === 0 ? (
          <p className="text-sm text-muted-foreground">No pending imports.</p>
        ) : (
          pending.data?.map((entry) => (
            <div
              key={entry.import_id}
              className="flex flex-wrap items-center justify-between gap-3 rounded-md border p-3"
            >
              <div>
                <p className="font-mono text-xs">{entry.import_id}</p>
                <p className="text-xs text-muted-foreground">
                  {revealHidden(entry.phase)} · {entry.host_count} hosts ·{" "}
                  {entry.key_count} keys
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
      </section>
    </div>
  );
}
