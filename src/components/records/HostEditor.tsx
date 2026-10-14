import { useEffect, useRef, useState } from "react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { Checkbox } from "@/components/ui/checkbox";
import {
  deleteRecordHost,
  moveRecordHost,
  type HostPayload,
  type HostScope,
  type RecordHostView,
  type RecordOverview,
} from "@/lib/records";
import { revealHidden } from "@/lib/sync-approvals";
import {
  beginEditor,
  changeEditor,
  editorProblem,
  refreshEditor,
  submitEditor,
  selectHost,
} from "./editor";
import { connectSavedHost, scopeLabel } from "./operations";
import { readinessLabel } from "./HostList";
import { RecordField, selectClass } from "./form";
export function RecordHostEditor({
  host,
  hostId,
  overview,
  terminalId,
  newTab,
  accept,
  onSaved,
  onDeleted,
  onDirty,
  onBusy,
  onCancel,
}: {
  host: RecordHostView | null;
  hostId: string | null;
  overview: RecordOverview;
  terminalId: string | null;
  newTab: boolean;
  accept: (overview: RecordOverview) => RecordOverview;
  onSaved: (id: string | null) => void;
  onDeleted: () => void;
  onDirty: (dirty: boolean) => void;
  onBusy?: (busy: boolean) => void;
  onCancel?: () => void;
}) {
  const [state, setState] = useState(() =>
    hostId && !host
      ? {
          ...beginEditor(null),
          id: hostId,
          unavailable: true,
          changedOnServer: true,
        }
      : beginEditor(host),
  );
  const [busy, setBusy] = useState(false);
  const [askingDelete, setAskingDelete] = useState(false);
  const [destination, setDestination] = useState("local");
  const inFlight = useRef(false);
  useEffect(() => {
    setState((current) => refreshEditor(current, host));
  }, [host]);
  useEffect(() => {
    onDirty(state.dirty);
  }, [state.dirty, onDirty]);
  const patch = (values: Partial<HostPayload>) =>
    setState((current) => changeEditor(current, values));
  const sharedBlocked =
    overview.shared_writes_blocked && state.scope.kind === "space";
  const run = async (operation: () => Promise<void>) => {
    if (inFlight.current) return;
    inFlight.current = true;
    setBusy(true);
    onBusy?.(true);
    setState((current) => ({ ...current, error: null }));
    try {
      await operation();
    } catch (error) {
      setState((current) => ({
        ...current,
        error: revealHidden(
          error instanceof Error ? error.message : String(error),
        ),
      }));
    } finally {
      inFlight.current = false;
      setBusy(false);
      onBusy?.(false);
    }
  };
  const save = () =>
    run(async () => {
      const result = await submitEditor(state);
      const accepted = accept(result);
      const oldIds = new Set(overview.hosts.map((value) => value.id));
      const created = result.hosts.filter(
        (value) =>
          !oldIds.has(value.id) &&
          value.payload.alias === state.payload.alias &&
          JSON.stringify(value.scope) === JSON.stringify(state.scope),
      );
      const id = state.id ?? (created.length === 1 ? created[0].id : null);
      const saved = id ? selectHost(accepted.hosts, id) : null;
      if (saved) setState(beginEditor(saved));
      onSaved(id);
    });
  const remove = () =>
    run(async () => {
      if (
        !askingDelete ||
        !state.id ||
        !state.revision ||
        state.unavailable ||
        sharedBlocked
      )
        return;
      accept(await deleteRecordHost(state.id, state.revision));
      setAskingDelete(false);
      onDeleted();
    });
  const move = () =>
    run(async () => {
      if (!state.id || !state.revision || state.dirty || state.unavailable)
        return;
      const scope: HostScope =
        destination === "local"
          ? { kind: "local" }
          : { kind: "space", space_id: destination };
      const result = await moveRecordHost(state.id, state.revision, scope);
      const accepted = accept(result);
      const saved = selectHost(accepted.hosts, state.id);
      if (saved) setState(beginEditor(saved));
    });
  const blocking =
    state.payload.imported?.unsupported.filter(
      (value) => value.requires_review,
    ) ?? [];
  return (
    <div className="mx-auto max-w-3xl space-y-5 px-6 pb-6">
      <header className="sticky top-0 z-10 flex flex-wrap items-center justify-between gap-3 border-b bg-background py-4">
        <div className="min-w-0 flex-1">
          <h1 className="truncate text-lg font-semibold">
            {state.id ? revealHidden(state.payload.alias) : "New host"}
          </h1>
          <p className="text-xs text-muted-foreground">
            {revealHidden(scopeLabel(overview, state.scope))}
            {" · "}
            {!state.id
              ? "Not saved yet"
              : state.dirty
                ? "Unsaved changes"
                : "Saved"}
          </p>
        </div>
        <div className="flex items-center gap-2">
          {state.dirty && state.id && (
            <Button
              variant="ghost"
              disabled={busy || !host}
              onClick={() => setState(beginEditor(host))}
            >
              Discard changes
            </Button>
          )}
          {!state.id && onCancel && (
            <Button variant="ghost" disabled={busy} onClick={onCancel}>
              Cancel
            </Button>
          )}
          <Button
            disabled={
              busy ||
              sharedBlocked ||
              (!state.dirty && state.id !== null) ||
              editorProblem(state) !== null
            }
            onClick={save}
          >
            {busy ? "Working…" : state.id ? "Save changes" : "Create host"}
          </Button>
          <Button
            variant="outline"
            disabled={
              busy ||
              state.dirty ||
              state.unavailable ||
              !host ||
              host.readiness.kind !== "ready"
            }
            onClick={() =>
              run(() =>
                connectSavedHost(overview, state.id!, terminalId, newTab),
              )
            }
          >
            Connect
          </Button>
        </div>
      </header>
      {state.dirty && editorProblem(state) && (
        <p role="status" className="text-sm text-muted-foreground">
          {editorProblem(state)}
        </p>
      )}
      {host && host.readiness.kind !== "ready" && (
        <p role="status" className="rounded-md border p-3 text-sm">
          {readinessLabel[host.readiness.kind]}. Review the key reference and
          jump hosts before connecting.
        </p>
      )}
      {state.changedOnServer && (
        <div role="status" className="rounded-md border p-3 text-sm">
          This host changed or became unavailable. Your draft and saved revision
          are retained.
          <Button
            variant="outline"
            size="sm"
            className="ml-3"
            disabled={busy || !host}
            onClick={() => setState(beginEditor(host))}
          >
            Reload saved settings
          </Button>
        </div>
      )}
      {sharedBlocked && (
        <p role="status" className="text-sm text-destructive">
          Shared changes are paused. Local hosts remain editable.
        </p>
      )}
      {state.error && (
        <p
          role="alert"
          className="text-sm text-destructive whitespace-pre-wrap"
        >
          {state.error}
        </p>
      )}
      {!state.id && (
        <RecordField label="Save in">
          <select
            className={selectClass}
            disabled={busy}
            value={
              state.scope.kind === "local" ? "local" : state.scope.space_id
            }
            onChange={(e) =>
              setState((current) => ({
                ...current,
                scope:
                  e.target.value === "local"
                    ? { kind: "local" }
                    : { kind: "space", space_id: e.target.value },
                dirty: true,
              }))
            }
          >
            <option value="local">Local</option>
            {overview.spaces
              .filter((space) => space.selected && !space.missing)
              .map((space) => (
                <option
                  key={space.id}
                  disabled={overview.shared_writes_blocked}
                  value={space.id}
                >
                  {revealHidden(space.name)}
                </option>
              ))}
          </select>
        </RecordField>
      )}
      <fieldset
        disabled={busy || state.unavailable || sharedBlocked}
        className="space-y-4 disabled:opacity-60"
      >
        <div className="grid gap-4 sm:grid-cols-2">
          <RecordField label="Alias">
            <Input
              value={state.payload.alias}
              onChange={(e) => patch({ alias: e.target.value })}
            />
          </RecordField>
          <RecordField label="Hostname or IP">
            <Input
              value={state.payload.hostname}
              onChange={(e) => patch({ hostname: e.target.value })}
            />
          </RecordField>
          <RecordField label="Port">
            <Input
              type="number"
              min={1}
              max={65535}
              value={state.payload.port}
              onChange={(e) => patch({ port: Number(e.target.value) })}
            />
          </RecordField>
          <RecordField label="Username">
            <Input
              value={state.payload.user}
              onChange={(e) => patch({ user: e.target.value })}
            />
          </RecordField>
        </div>
        <RecordField label="Authentication">
          <select
            className={selectClass}
            value={state.payload.auth}
            onChange={(e) =>
              patch({
                auth: e.target.value as HostPayload["auth"],
                key_id: e.target.value === "key" ? state.payload.key_id : null,
              })
            }
          >
            <option value="password">Password</option>
            <option value="key">SSH key</option>
            <option value="interactive">Keyboard interactive</option>
          </select>
        </RecordField>
        {state.payload.auth === "key" && (
          <RecordField label="Key reference">
            <select
              className={selectClass}
              value={state.payload.key_id ?? ""}
              onChange={(e) => patch({ key_id: e.target.value || null })}
            >
              <option value="">Choose a key…</option>
              {state.payload.key_id &&
                !overview.keys.some(
                  (key) => key.id === state.payload.key_id,
                ) && (
                  <option value={state.payload.key_id}>
                    Missing key ({state.payload.key_id})
                  </option>
                )}
              {overview.keys.map((key) => (
                <option key={key.id} value={key.id}>
                  {revealHidden(key.public?.name ?? key.id)} ·{" "}
                  {key.status.replace(/_/g, " ")}
                </option>
              ))}
            </select>
            <p className="text-xs text-muted-foreground">
              Key availability is verified again when connecting.
            </p>
          </RecordField>
        )}
        {state.payload.auth === "password" && (
          <p className="text-xs text-muted-foreground">
            Passwords are requested in the terminal when needed and stay on
            this device.
          </p>
        )}
        <details
          className="rounded-lg border p-4"
          open={state.payload.jump.length > 0 || undefined}
        >
          <summary className="text-sm font-medium">
            Advanced SSH settings
          </summary>
          <div className="mt-4 space-y-4">
            <RecordField label="Jump hosts (in order)">
              {state.payload.jump.map((id, index) => (
                <div key={`${id}:${index}`} className="flex items-center gap-2">
                  <span className="min-w-0 flex-1 truncate text-sm">
                    {index + 1}.{" "}
                    {revealHidden(
                      selectHost(overview.hosts, id)?.payload.alias ??
                        `Missing or conflicting host (${id})`,
                    )}
                  </span>
                  <Button
                    type="button"
                    variant="outline"
                    size="sm"
                    onClick={() =>
                      patch({
                        jump: state.payload.jump.filter(
                          (_, at) => at !== index,
                        ),
                      })
                    }
                  >
                    Remove
                  </Button>
                </div>
              ))}
              <select
                aria-label="Add jump host"
                className={selectClass}
                value=""
                disabled={state.payload.jump.length >= 5}
                onChange={(e) => {
                  if (e.target.value)
                    patch({ jump: [...state.payload.jump, e.target.value] });
                }}
              >
                <option value="">Add jump host…</option>
                {overview.hosts
                  .filter(
                    (value) =>
                      value.id !== state.id &&
                      !state.payload.jump.includes(value.id) &&
                      selectHost(overview.hosts, value.id),
                  )
                  .map((value) => (
                    <option key={value.id} value={value.id}>
                      {revealHidden(value.payload.alias)} ·{" "}
                      {revealHidden(scopeLabel(overview, value.scope))}
                    </option>
                  ))}
              </select>
            </RecordField>
            <div className="grid gap-4 sm:grid-cols-3">
              {(
                [
                  ["Keepalive interval (seconds)", "keepalive_secs", 0],
                  ["Missed keepalives", "keepalive_max_missed", 0],
                  ["Connect timeout (seconds)", "connect_timeout_secs", 1],
                ] as const
              ).map(([label, name, min]) => (
                <RecordField key={name} label={label}>
                  <Input
                    type="number"
                    min={min}
                    max={4294967295}
                    value={state.payload[name]}
                    onChange={(e) => patch({ [name]: Number(e.target.value) })}
                  />
                </RecordField>
              ))}
            </div>
          </div>
        </details>
        <RecordField label="Tags">
          <Input
            value={state.payload.tags.join(", ")}
            onChange={(e) =>
              patch({
                tags: e.target.value
                  .split(",")
                  .map((value) => value.trim())
                  .filter(Boolean),
              })
            }
          />
        </RecordField>
        <RecordField label="Notes">
          <Textarea
            value={state.payload.notes}
            onChange={(e) => patch({ notes: e.target.value })}
          />
        </RecordField>
        {blocking.length > 0 && (
          <div className="space-y-3 rounded-md border p-3">
            <p className="text-sm">
              Review these imported settings and adapt the host fields above:
            </p>
            <ul className="space-y-1 text-xs">
              {blocking.map((value, index) => (
                <li key={index} className="font-mono whitespace-pre-wrap">
                  {revealHidden(`${value.keyword} ${value.value}`)}
                </li>
              ))}
            </ul>
            <Label className="flex items-center gap-2">
              <Checkbox
                checked={state.reviewed}
                onCheckedChange={(checked) =>
                  setState((current) => ({
                    ...current,
                    reviewed: checked === true,
                    dirty: true,
                  }))
                }
              />
              Reviewed settings
            </Label>
          </div>
        )}
      </fieldset>
      {state.payload.host_key && (
        <div className="space-y-1 rounded-md border p-3 text-xs">
          <p className="font-medium">Pinned host key</p>
          <p className="break-all font-mono">
            {revealHidden(state.payload.host_key.fingerprint)}
          </p>
          <p className="text-muted-foreground">
            Changing the hostname or port clears this pin. A new fingerprint
            must be verified when connecting.
          </p>
        </div>
      )}
      {state.id && (
        <details className="rounded-lg border p-4">
          <summary className="text-sm font-medium">Manage host</summary>
          <section className="mt-4 space-y-3">
            <p className="text-xs text-muted-foreground">
              Move this host to a synced space to share it with your other
              devices, or keep it Local.
            </p>
            <div className="flex items-center gap-2">
              <select
                aria-label="Move destination"
                className={selectClass}
                value={destination}
                disabled={
                  busy || state.dirty || state.unavailable || sharedBlocked
                }
                onChange={(e) => setDestination(e.target.value)}
              >
                <option value="local">Local</option>
                {overview.spaces
                  .filter((space) => space.selected && !space.missing)
                  .map((space) => (
                    <option
                      key={space.id}
                      disabled={overview.shared_writes_blocked}
                      value={space.id}
                    >
                      {revealHidden(space.name)}
                    </option>
                  ))}
              </select>
              <Button
                variant="outline"
                disabled={
                  busy ||
                  state.dirty ||
                  state.unavailable ||
                  sharedBlocked ||
                  (state.scope.kind === "local"
                    ? destination === "local"
                    : destination === state.scope.space_id) ||
                  (destination !== "local" && overview.shared_writes_blocked)
                }
                onClick={move}
              >
                Move host
              </Button>
            </div>
            {askingDelete ? (
              <div className="flex items-center gap-3">
                <p className="text-sm">
                  Delete this saved host and discard its draft?
                </p>
                <Button
                  variant="destructive"
                  disabled={busy || state.unavailable || sharedBlocked}
                  onClick={remove}
                >
                  Confirm delete
                </Button>
                <Button
                  variant="outline"
                  disabled={busy}
                  onClick={() => setAskingDelete(false)}
                >
                  Cancel
                </Button>
              </div>
            ) : (
              <Button
                variant="outline"
                disabled={busy || state.unavailable || sharedBlocked}
                onClick={() => setAskingDelete(true)}
              >
                Delete host
              </Button>
            )}
          </section>
          <p className="mt-4 break-all font-mono text-xs text-muted-foreground">
            Host ID: {state.id}
          </p>
        </details>
      )}
    </div>
  );
}
