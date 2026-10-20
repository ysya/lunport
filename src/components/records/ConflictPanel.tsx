import { useState } from "react";
import { useQueryClient } from "@tanstack/react-query";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import {
  applyRecordOverview,
  resolveRecordConflict,
  type RecordConflict,
  type ConflictVersion,
} from "@/lib/records";
import { revealHidden } from "@/lib/sync-approvals";

const labels: Record<string, string> = {
  alias: "Name", hostname: "Hostname", port: "Port", user: "User",
  auth: "Authentication", key_id: "Key", jump: "Jump hosts", tags: "Tags",
  notes: "Notes", name: "Name", group_id: "Group", parent_id: "Parent Group",
  defaults: "Defaults", inherit: "Inherited settings", host_key: "Server identity",
  public_key: "Public key", fingerprint: "Fingerprint", key_type: "Key type",
  has_passphrase: "Passphrase protected", keepalive_secs: "Keepalive interval",
  keepalive_max_missed: "Missed keepalives", connect_timeout_secs: "Connection timeout",
  ids: "Group order",
};
const hidden = new Set(["schema", "schema_version", "imported", "origin_device_id", "created_by_app_version"]);
function displayValue(value: unknown): string {
  if (value === null || value === undefined) return "—";
  if (typeof value === "boolean") return value ? "Yes" : "No";
  if (Array.isArray(value)) return value.map(displayValue).join(", ") || "—";
  if (typeof value === "object") {
    if ("fingerprint" in value) return String(value.fingerprint);
    return Object.entries(value).filter(([key]) => !hidden.has(key))
      .map(([key, field]) => `${labels[key] ?? key.replace(/_/g, " ")}: ${displayValue(field)}`).join("; ");
  }
  return String(value) || "—";
}
function Version({ title, version }: { title: string; version: ConflictVersion | null }) {
  const payload = version?.record?.payload;
  const fields = payload && typeof payload === "object"
    ? Object.entries(payload).filter(([key]) => !hidden.has(key)) : [];
  return (
    <section className="min-w-0 space-y-2 rounded-md border p-3" aria-label={title}>
      <h4 className="text-sm font-medium">{title}</h4>
      {!version ? (
        <p className="text-xs text-muted-foreground">The common base is unavailable for this earlier edit.</p>
      ) : (
        <>
          {version.deleted && <p className="text-sm">Deleted</p>}
          {version.record ? (
            <dl className="max-h-64 space-y-2 overflow-auto text-xs">
              {fields.map(([key, value]) => (
                <div key={key}>
                  <dt className="text-muted-foreground">{labels[key] ?? key.replace(/_/g, " ")}</dt>
                  <dd className="whitespace-pre-wrap break-words">{revealHidden(displayValue(value))}</dd>
                </div>
              ))}
            </dl>
          ) : (
            <p className="text-xs text-muted-foreground">Encrypted credentials stay inside the app. Their contents are hidden here.</p>
          )}
        </>
      )}
    </section>
  );
}
function Conflict({ conflict, disabled, onBusyChange }: {
  conflict: RecordConflict;
  disabled: boolean;
  onBusyChange: (busy: boolean) => void;
}) {
  const client = useQueryClient();
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [copyAlias, setCopyAlias] = useState(`${conflict.label}-copy`);
  const remote = conflict.remote[conflict.remote.length - 1] ?? null;
  async function resolve(choice: "local" | "remote" | "copy_remote") {
    if (busy || disabled) return;
    setBusy(true);
    onBusyChange(true);
    setError(null);
    try {
      applyRecordOverview(client, await resolveRecordConflict(conflict, choice, copyAlias));
    } catch (cause) {
      setError(String(cause));
    } finally {
      setBusy(false);
      onBusyChange(false);
    }
  }
  return (
    <article className="space-y-3 rounded-lg border p-4" aria-label={`Conflict: ${revealHidden(conflict.label)}`}>
      <h3 className="font-medium break-words">{revealHidden(conflict.label)}</h3>
      <div className="grid gap-3 lg:grid-cols-2">
        <Version title="Local" version={conflict.local} />
        <Version title="Latest remote" version={remote} />
      </div>
      <details>
        <summary className="cursor-pointer text-sm">Common base and earlier remote versions</summary>
        <div className="mt-3 space-y-3">
          <Version title="Common base" version={conflict.base} />
          {conflict.remote.slice(0, -1).map((version) => (
            <Version key={version.seq} title={`Earlier remote version ${version.seq}`} version={version} />
          ))}
        </div>
      </details>
      <p className="text-xs text-muted-foreground">Both versions are saved on this device until you choose. Resolving replaces this record; other edits stay queued.</p>
      {error && <p role="alert" className="text-sm text-destructive whitespace-pre-wrap">{revealHidden(error)}</p>}
      <div className="flex flex-wrap gap-2">
        <Button disabled={busy || disabled} onClick={() => void resolve("local")}>Keep local</Button>
        <Button variant="outline" disabled={busy || disabled} onClick={() => void resolve("remote")}>Keep latest remote</Button>
      </div>
      {conflict.can_copy_remote && (
        <div className="flex flex-wrap items-center gap-2">
          <Input className="max-w-xs" aria-label="Copied host name" value={copyAlias}
            onChange={(event) => setCopyAlias(event.target.value)} disabled={busy || disabled} />
          <Button variant="outline" disabled={busy || disabled || !copyAlias.trim()}
            onClick={() => void resolve("copy_remote")}>Keep local and copy remote host</Button>
        </div>
      )}
    </article>
  );
}
export function RecordConflictPanel({ conflicts, disabled = false, onBusyChange = () => {} }: {
  conflicts: RecordConflict[];
  disabled?: boolean;
  onBusyChange?: (busy: boolean) => void;
}) {
  if (conflicts.length === 0) return null;
  return (
    <section className="space-y-4" aria-label="Saved sync conflicts">
      <h2 className="text-lg font-medium">Saved sync conflicts</h2>
      <p className="text-sm text-muted-foreground">Concurrent changes need your review. These records pause uploading while other records can sync.</p>
      {conflicts.map((conflict) => (
        <Conflict key={`${conflict.space_id ?? "account"}:${conflict.key}:${conflict.token}`}
          conflict={conflict} disabled={disabled} onBusyChange={onBusyChange} />
      ))}
    </section>
  );
}
