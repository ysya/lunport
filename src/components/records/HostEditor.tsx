import { useEffect, useRef, useState } from "react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { Checkbox } from "@/components/ui/checkbox";
import {
  deleteRecordHost,
  type HostPayload,
  type InheritedField,
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
import {
  groupPath,
  requiresFormatUpgrade,
  scopeKey,
  selectGroup,
} from "./group-tree";
import {
  inheritedFields,
  toggleInheritance,
  previewHostDraft,
} from "./inheritance";
import { FormatUpgradeReview } from "./FormatUpgradeReview";
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
  initialScope = { kind: "local" },
  initialGroupId = null,
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
  initialScope?: HostScope;
  initialGroupId?: string | null;
}) {
  const [state, setState] = useState(() =>
    hostId && !host
      ? {
          ...beginEditor(null),
          id: hostId,
          unavailable: true,
          changedOnServer: true,
        }
      : host
        ? beginEditor(host)
        : {
            ...beginEditor(null),
            scope: structuredClone(initialScope),
            payload: { ...beginEditor(null).payload, group_id: initialGroupId },
          },
  );
  const [busy, setBusy] = useState(false);
  const [askingUpgrade, setAskingUpgrade] = useState(false);
  const [askingDelete, setAskingDelete] = useState(false);
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
  const save = (confirmed?: boolean) => {
    if (
      (state.payload.group_id || state.payload.inherit?.length) &&
      requiresFormatUpgrade(overview, state.scope) &&
      confirmed !== true
    ) {
      setAskingUpgrade(true);
      return;
    }
    return run(async () => {
      const result = await submitEditor(state, confirmed);
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
      setAskingUpgrade(false);
      onSaved(id);
    });
  };
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
  const preview = previewHostDraft(overview, state.scope, state.payload, host);
  const inherits = (field: InheritedField) =>
    state.payload.inherit?.includes(field) ?? false;
  const visible = { ...state.payload };
  for (const field of state.payload.inherit ?? []) {
    if (field === "authentication") {
      visible.auth = preview.payload.auth;
      visible.key_id = preview.payload.key_id;
    } else Object.assign(visible, { [field]: preview.payload[field] });
  }
  const inheritedControl = (field: InheritedField) => (
    <div className="space-y-1">
      <label className="flex items-center gap-2 text-xs">
        <input
          type="checkbox"
          aria-label={`${inheritedFields.find(([name]) => name === field)?.[1]}: Use ${state.payload.group_id ? "group" : "app"} default`}
          checked={inherits(field)}
          onChange={(e) =>
            patch(toggleInheritance(state.payload, field, e.target.checked))
          }
        />
        Use {state.payload.group_id ? "group" : "app"} default
      </label>
      {inherits(field) && (
        <p className="break-words text-xs text-muted-foreground">
          {preview.error
            ? "Effective value unavailable"
            : `Source: ${preview.sources[field] === "default" ? "App default" : revealHidden(overview.groups.find((g) => g.id === preview.sources[field])?.payload.name ?? "Group")}`}
        </p>
      )}
    </div>
  );
  const groupChoices = overview.groups.filter(
    (g) =>
      (overview.library_enabled ||
        scopeKey(g.scope) === scopeKey(state.scope)) &&
      selectGroup(overview.groups, g.id),
  );
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
        <div className="flex flex-wrap items-center gap-2">
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
            onClick={() => save()}
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
              host.readiness.kind !== "ready" ||
              !!host.group_error ||
              !!preview.error
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
      {host?.group_error && (
        <p
          role="status"
          className="rounded-md border p-3 text-sm text-destructive"
        >
          {revealHidden(host.group_error)}. Connection is blocked until the
          Group settings are resolved.
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
          Sync changes are paused while account data is reviewed.
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
      {preview.error && (
        <p role="status" className="text-sm text-destructive">
          {revealHidden(preview.error)}. Effective settings are unavailable.
        </p>
      )}
      <fieldset
        disabled={busy || state.unavailable || sharedBlocked}
        className="space-y-4 disabled:opacity-60"
      >
        <RecordField label="Group">
          <select
            className={selectClass}
            value={state.payload.group_id ?? ""}
            onChange={(e) => {
              const group = selectGroup(overview.groups, e.target.value);
              setState((current) => ({
                ...changeEditor(current, { group_id: e.target.value || null }),
                scope: structuredClone(group?.scope ?? current.scope),
              }));
            }}
          >
            <option value="">Ungrouped</option>
            {state.payload.group_id &&
              !groupChoices.some((g) => g.id === state.payload.group_id) && (
                <option value={state.payload.group_id}>
                  Unavailable Group ({state.payload.group_id})
                </option>
              )}
            {groupChoices.map((g) => (
              <option key={g.id} value={g.id}>
                {revealHidden(groupPath(overview, g.id, g.scope))}
              </option>
            ))}
          </select>
        </RecordField>
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
              disabled={inherits("port")}
              value={inherits("port") && preview.error ? "" : visible.port}
              onChange={(e) => patch({ port: Number(e.target.value) })}
            />
            {inheritedControl("port")}
          </RecordField>
          <RecordField label="Username">
            <Input
              disabled={inherits("user")}
              placeholder={
                inherits("user") && preview.error
                  ? "Unavailable"
                  : "OS username"
              }
              value={inherits("user") && preview.error ? "" : visible.user}
              onChange={(e) => patch({ user: e.target.value })}
            />
            {inheritedControl("user")}
          </RecordField>
        </div>
        <RecordField label="Authentication">
          <select
            className={selectClass}
            disabled={inherits("authentication")}
            value={
              inherits("authentication") && preview.error ? "" : visible.auth
            }
            onChange={(e) =>
              patch({
                auth: e.target.value as HostPayload["auth"],
                key_id: e.target.value === "key" ? state.payload.key_id : null,
              })
            }
          >
            {inherits("authentication") && preview.error && (
              <option value="">Unavailable</option>
            )}
            <option value="password">Password</option>
            <option value="key">SSH key</option>
            <option value="interactive">Keyboard interactive</option>
          </select>
          {inheritedControl("authentication")}
        </RecordField>
        {visible.auth === "key" &&
          !(inherits("authentication") && preview.error) && (
            <RecordField label="Key reference">
              <select
                className={selectClass}
                disabled={inherits("authentication")}
                value={visible.key_id ?? ""}
                onChange={(e) => patch({ key_id: e.target.value || null })}
              >
                <option value="">Choose a key…</option>
                {visible.key_id &&
                  !overview.keys.some((key) => key.id === visible.key_id) && (
                    <option value={visible.key_id}>
                      Missing key ({visible.key_id})
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
        {visible.auth === "password" && (
          <p className="text-xs text-muted-foreground">
            Passwords are requested in the terminal when needed and stay on this
            device.
          </p>
        )}
        <details
          className="rounded-lg border p-4"
          open={
            visible.jump.length > 0 ||
            state.payload.inherit?.some((f) =>
              [
                "jump",
                "keepalive_secs",
                "keepalive_max_missed",
                "connect_timeout_secs",
              ].includes(f),
            ) ||
            undefined
          }
        >
          <summary className="text-sm font-medium">
            Advanced SSH settings
          </summary>
          <div className="mt-4 space-y-4">
            <RecordField label="Jump hosts (in order)">
              {inheritedControl("jump")}
              {(inherits("jump") && preview.error ? [] : visible.jump).map(
                (id, index) => (
                  <div
                    key={`${id}:${index}`}
                    className="flex items-center gap-2"
                  >
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
                      disabled={inherits("jump")}
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
                ),
              )}
              <select
                aria-label="Add jump host"
                className={selectClass}
                value=""
                disabled={inherits("jump") || state.payload.jump.length >= 5}
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
                    disabled={inherits(name)}
                    value={inherits(name) && preview.error ? "" : visible[name]}
                    onChange={(e) => patch({ [name]: Number(e.target.value) })}
                  />
                  {inheritedControl(name)}
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
      <FormatUpgradeReview
        open={askingUpgrade}
        busy={busy}
        confirm={() => save(true)}
        cancel={() => setAskingUpgrade(false)}
      />
    </div>
  );
}
