import { useEffect, useRef, useState } from "react";
import { CopyPlus, Server, X } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { Checkbox } from "@/components/ui/checkbox";
import { ActionBar, EditorHeader, FormSection } from "@/components/app/Workflow";
import {
  deleteRecordHost,
  verifyRecordHostKey,
  type HostPayload,
  type InheritedField,
  type HostScope,
  type RecordHostView,
  type RecordOverview,
} from "@/lib/records";
import { revealHidden } from "@/lib/sync-approvals";
import {
  beginEditor,
  beginDuplicateEditor,
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
import { HostPasswordField, saveHostPassword, type PasswordChange } from "./HostPasswordField";
import { TransportSection } from "./TransportSection";
import { applyOsLoginProfile, saveTransportDraft } from "./editor";
import { fetchOsLoginProfile, transportFor, transportProblem, type HostTransport } from "@/lib/transports";
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
  connectHost,
  initialScope = { kind: "local" },
  initialGroupId = null,
  duplicateSource,
  onDuplicate,
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
  connectHost?: (id: string) => Promise<void>;
  initialScope?: HostScope;
  initialGroupId?: string | null;
  duplicateSource?: RecordHostView;
  onDuplicate?: () => void;
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
        : duplicateSource
          ? beginDuplicateEditor(duplicateSource, overview.hosts)
        : {
            ...beginEditor(null),
            scope: structuredClone(initialScope),
            payload: { ...beginEditor(null).payload, group_id: initialGroupId },
          },
  );
  const [busy, setBusy] = useState(false);
  const [passwordChange, setPasswordChange] = useState<PasswordChange>(null);
  // `undefined`: the Connect through section was not touched; `null`: Direct was chosen; a value: the IAP transport as edited.
  const [transportDraft, setTransportDraft] = useState<HostTransport | null | undefined>(undefined);
  const [osLoginNote, setOsLoginNote] = useState<string | null>(null);
  const dirty = state.dirty || passwordChange !== null || transportDraft !== undefined;
  const savedTransport = transportFor(overview, state.id);
  const shownTransport = transportDraft === undefined ? savedTransport : transportDraft;
  const currentHost = state.id ? selectHost(overview.hosts, state.id) : host;
  const [askingUpgrade, setAskingUpgrade] = useState(false);
  const [askingDelete, setAskingDelete] = useState(false);
  const inFlight = useRef(false);
  useEffect(() => {
    setState((current) => {
      const refreshed = refreshEditor(current, currentHost);
      // A record refresh after creation must not erase a credential-store failure.
      return passwordChange && current.error ? { ...refreshed, error: current.error } : refreshed;
    });
  }, [currentHost]);
  useEffect(() => {
    onDirty(dirty);
  }, [dirty, onDirty]);
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
      (state.dirty || state.id === null) &&
      (state.payload.group_id || state.payload.inherit?.length) &&
      requiresFormatUpgrade(overview, state.scope) &&
      confirmed !== true
    ) {
      setAskingUpgrade(true);
      return;
    }
    return run(async () => {
      const result = state.id && !state.dirty ? overview : await submitEditor(state, confirmed);
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
      if (passwordChange) {
        if (!id || !saved) {
          setState(current => ({ ...current, unavailable: true }));
          throw new Error("The host was saved, but its identity is unavailable. Reopen the host to save its password.");
        }
        await saveHostPassword(saved, passwordChange, accepted);
        setPasswordChange(null);
      }
      if (transportDraft !== undefined) {
        if (!id) {
          setState(current => ({ ...current, unavailable: true }));
          throw new Error("The host was saved, but its identity is unavailable. Reopen the host to save how it connects.");
        }
        const result = await saveTransportDraft(id, transportDraft, accepted);
        if (result) accept(result);
        setTransportDraft(undefined);
      }
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
  const preview = previewHostDraft(overview, state.scope, state.payload, currentHost);
  useEffect(() => { setPasswordChange(null); }, [preview.payload.auth]);
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
    <div className="host-editor">
      <EditorHeader
        icon={<Server className="size-5" />}
        title={
          <h1 className="truncate">
            {state.id ? revealHidden(state.payload.alias) : duplicateSource ? "Duplicate host" : "New host"}
          </h1>
        }
        description={
          <p className="text-xs text-muted-foreground">
            {revealHidden(scopeLabel(overview, state.scope))}
            {" · "}
            {!state.id
              ? "Not saved yet"
              : dirty
                ? "Unsaved changes"
                : "Saved"}
          </p>
        }
        close={onCancel && (
          <Button
            variant="ghost"
            size="icon-sm"
            aria-label="Close editor"
            disabled={busy}
            onClick={onCancel}
          >
            <X className="size-4" />
          </Button>
        )}
      />
      <div className="app-editor-body">
        {duplicateSource && !state.id && (
          <p className="text-xs text-muted-foreground">
            Copied settings from {revealHidden(duplicateSource.payload.alias)}.
            {preview.payload.auth === "password" && " Enter a password again when connecting or save one below."}
          </p>
        )}
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
              onClick={() => { setState(beginEditor(currentHost)); setPasswordChange(null); setTransportDraft(undefined); setOsLoginNote(null); }}
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
        {preview.error && (
          <p role="status" className="text-sm text-destructive">
            {revealHidden(preview.error)}. Effective settings are unavailable.
          </p>
        )}
        <fieldset
          disabled={busy || state.unavailable || sharedBlocked}
          className="host-editor-fields disabled:opacity-60"
        >
          <FormSection title="Connection" description="Name this host and set its address. Inherited values follow the selected group.">
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
                  data-host-alias
                  autoFocus={!!duplicateSource}
                  autoComplete="off"
                  placeholder="e.g. production-web"
                  value={state.payload.alias}
                  onChange={(e) => patch({ alias: e.target.value })}
                />
              </RecordField>
              <RecordField label="Hostname or IP">
                <Input
                  autoComplete="off"
                  placeholder="e.g. server.example.com"
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
                {shownTransport?.kind.os_login && (
                  <div className="space-y-1">
                    <Button
                      type="button"
                      variant="outline"
                      size="sm"
                      disabled={busy || inherits("user") || !shownTransport.kind.project}
                      onClick={() =>
                        run(async () => {
                          const view = await fetchOsLoginProfile(shownTransport.kind.account, shownTransport.kind.project, state.payload.key_id);
                          const applied = applyOsLoginProfile(state, view);
                          setState(applied.state);
                          setOsLoginNote(applied.note);
                        })
                      }
                    >
                      Use OS Login username
                    </Button>
                    <p className="text-xs text-muted-foreground">OS Login decides the username; fetch it with Use OS Login username.</p>
                    {osLoginNote && <p className="text-xs text-muted-foreground">{osLoginNote}</p>}
                  </div>
                )}
              </RecordField>
            </div>
          </FormSection>
          <FormSection title="Authentication" description="Choose how this device signs in to the server.">
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
              <HostPasswordField hostId={state.id} generation={overview.generation} syncEnabled={overview.central_mode} change={passwordChange} onChange={change => {
                setPasswordChange(change);
                setState(current => ({ ...current, error: null }));
              }} />
            )}
          </FormSection>
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
          <TransportSection
            hostId={state.id}
            value={shownTransport}
            onChange={(next) => setTransportDraft(next)}
            disabled={busy || sharedBlocked || state.unavailable}
          />
          <FormSection title="Organization" description="Add searchable tags and notes for this host.">
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
          </FormSection>
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
        {state.id && (
          <section className="space-y-2 rounded-lg border p-4 text-xs" aria-label="Server identity">
            <p className="font-medium">Server identity</p>
            {state.payload.host_key ? (
              <p className="select-text break-all font-mono">{revealHidden(state.payload.host_key.fingerprint)}</p>
            ) : <p className="text-muted-foreground">No server key has been verified yet.</p>}
            <p className="text-muted-foreground">Compare the server fingerprint in Lunport before login. No remote command is run. Changing the hostname or port clears the saved pin.</p>
            <Button size="sm" variant="outline" disabled={busy || state.dirty || state.unavailable || sharedBlocked || !!preview.error} onClick={() => run(async () => {
              const result = await verifyRecordHostKey(state.id!);
              accept(result.overview);
            })}>Verify server fingerprint</Button>
          </section>
        )}
        {state.id && (
          <details className="rounded-lg border p-4">
            <summary className="text-sm font-medium">Manage host</summary>
            <section className="mt-4 flex flex-col items-start gap-3">
              {onDuplicate && (
                <Button
                  variant="outline"
                  disabled={busy || dirty || state.unavailable || sharedBlocked}
                  title={dirty ? "Save or discard changes before duplicating this host." : undefined}
                  onClick={onDuplicate}
                >
                  <CopyPlus className="size-4" />
                  Duplicate host…
                </Button>
              )}
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
      {state.error && <p role="alert" className="mx-5 mb-3 shrink-0 text-xs text-destructive whitespace-pre-wrap">{state.error}</p>}
      <ActionBar className="app-editor-action-bar" label="Host editor actions" hint={
        <span role="status">
          {dirty
            ? "Unsaved changes"
            : state.id
              ? "Saved to your library"
              : "Save this host before connecting."}
        </span>
      }>
          {dirty && state.id && (
            <Button
              variant="ghost"
              disabled={busy || !currentHost}
              onClick={() => { setState(beginEditor(currentHost)); setPasswordChange(null); setTransportDraft(undefined); setOsLoginNote(null); }}
            >
              Discard changes
            </Button>
          )}
          {onCancel && (
            <Button variant="ghost" disabled={busy} onClick={onCancel}>
              Cancel
            </Button>
          )}
          <Button
            disabled={
              busy ||
              sharedBlocked ||
              (!dirty && state.id !== null) ||
              (passwordChange?.kind === "set" && passwordChange.value.length === 0) ||
              (transportDraft != null && transportProblem(transportDraft) !== null) ||
              editorProblem(state) !== null
            }
            onClick={() => save()}
          >
            {busy ? "Working…" : state.id ? "Save changes" : "Create host"}
          </Button>
          {state.id && (
            <Button
              variant="outline"
              disabled={
                busy ||
                dirty ||
                state.unavailable ||
                !currentHost ||
                currentHost.readiness.kind !== "ready" ||
                !!currentHost.group_error ||
                !!preview.error
              }
              onClick={() =>
                run(() =>
                  connectHost ? connectHost(state.id!) : connectSavedHost(overview, state.id!, terminalId, newTab),
                )
              }
            >
              Connect
            </Button>
          )}
      </ActionBar>
      <FormatUpgradeReview
        open={askingUpgrade}
        busy={busy}
        confirm={() => save(true)}
        cancel={() => setAskingUpgrade(false)}
      />
    </div>
  );
}
