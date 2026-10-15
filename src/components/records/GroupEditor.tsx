import { useEffect, useId, useRef, useState, type ReactNode } from "react";
import { ChevronDown, Folder, SlidersHorizontal, X } from "lucide-react";
import { isImeKey } from "@/lib/ime";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import {
  Dialog,
  DialogContent,
  DialogTitle,
  DialogDescription,
  DialogFooter,
} from "@/components/ui/dialog";
import {
  fetchRecordsStatus,
  type GroupDefaults,
  type GroupPayload,
  type HostScope,
  type RecordGroupView,
  type RecordOverview,
} from "@/lib/records";
import { revealHidden } from "@/lib/sync-approvals";
import {
  beginGroupEditor,
  beginGroupDeletion,
  submitGroupDeletion,
  type GroupDeletionCandidate,
  changeGroupEditor,
  refreshGroupEditor,
  groupEditorProblem,
  groupConnectionSettingsChanged,
  submitGroupEditor,
} from "./group-editor";
import {
  affectedRecords,
  groupAncestors,
  groupPath,
  requiresFormatUpgrade,
  scopeKey,
  selectGroup,
} from "./group-tree";
import { scopeLabel } from "./operations";
import { RecordField, selectClass } from "./form";
import { FormatUpgradeReview } from "./FormatUpgradeReview";
import {
  inheritedFields,
  previewInheritance,
  effectiveField,
} from "./inheritance";
import { emptyHostPayload, selectHost } from "./editor";
export function RecordGroupEditor({
  group,
  groupId,
  overview,
  initialScope = { kind: "local" },
  initialParentId = null,
  accept,
  onSaved,
  onDeleted,
  onDirty,
  onBusy,
  onCancel,
}: {
  group: RecordGroupView | null;
  groupId: string | null;
  overview: RecordOverview;
  initialScope?: HostScope;
  initialParentId?: string | null;
  accept: (overview: RecordOverview) => RecordOverview;
  onSaved: (id: string | null) => void;
  onDeleted: () => void;
  onDirty: (dirty: boolean) => void;
  onBusy?: (busy: boolean) => void;
  onCancel?: () => void;
}) {
  const [deletionError, setDeletionError] = useState<string | null>(null);
  const [state, setState] = useState(() =>
    groupId && !group
      ? {
          ...beginGroupEditor(null),
          id: groupId,
          unavailable: true,
          changedOnServer: true,
        }
      : beginGroupEditor(group, initialScope, initialParentId),
  );
  const [busy, setBusy] = useState(false),
    [upgrade, setUpgrade] = useState(false),
    [deleting, setDeleting] = useState<GroupDeletionCandidate | null>(null);
  const inFlight = useRef(false);
  useEffect(() => {
    setState((current) => refreshGroupEditor(current, group));
  }, [group]);
  useEffect(() => {
    onDirty(state.dirty);
  }, [state.dirty, onDirty]);
  const blocked =
    overview.shared_writes_blocked && state.scope.kind === "space";
  const patch = (values: Partial<GroupPayload>) =>
    setState((current) => changeGroupEditor(current, values));
  const defaultPatch = (values: Partial<GroupDefaults>) =>
    patch({ defaults: { ...state.payload.defaults, ...values } });
  const affected = state.id
    ? affectedRecords(overview, {
        ...group!,
        id: state.id,
        scope: state.scope,
        payload: state.payload,
      })
    : { groups: 0, hosts: 0 };
  const previewOverview = {
    ...overview,
    groups: [
      ...overview.groups.filter((g) => g.id !== state.id),
      {
        id: state.id ?? "draft-group",
        scope: state.scope,
        payload: state.payload,
        revision: state.revision ?? {
          version: "0",
          updated_at_ms: "0",
          device_id: "",
        },
        group_error: null,
      },
    ],
  };
  const preview = previewInheritance(previewOverview, state.scope, {
    ...emptyHostPayload(),
    group_id: state.id ?? "draft-group",
    inherit: inheritedFields.map(([field]) => field),
  });
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
  const save = (confirmed = false) => {
    if (
      busy ||
      blocked ||
      state.unavailable ||
      groupEditorProblem(state, overview)
    )
      return;
    if (
      !state.id &&
      requiresFormatUpgrade(overview, state.scope) &&
      !confirmed
    ) {
      setUpgrade(true);
      return;
    }
    void run(async () => {
      const result = await submitGroupEditor(state, overview, confirmed);
      const accepted = accept(result);
      const oldIds = new Set(overview.groups.map((g) => g.id));
      const created = result.groups.filter(
        (g) =>
          !oldIds.has(g.id) &&
          g.payload.name === state.payload.name.trim() &&
          scopeKey(g.scope) === scopeKey(state.scope),
      );
      const id = state.id ?? (created.length === 1 ? created[0].id : null);
      const saved = id ? selectGroup(accepted.groups, id) : null;
      if (saved) setState(beginGroupEditor(saved));
      setUpgrade(false);
      onSaved(id);
    });
  };
  const parentChoices = overview.groups.filter(
    (g) =>
      ((!state.id && overview.library_enabled) ||
        scopeKey(g.scope) === scopeKey(state.scope)) &&
      g.id !== state.id &&
      selectGroup(overview.groups, g.id) &&
      !groupAncestors(overview, g.id, g.scope).groups.some(
        (a) => a.id === state.id,
      ),
  );
  const problem = groupEditorProblem(state, overview);
  const defaults = state.payload.defaults;
  const connectionCount = [
    defaults.port,
    defaults.user,
    defaults.authentication,
  ].filter((value) => value != null).length;
  const advancedCount = [
    defaults.jump,
    defaults.keepalive_secs,
    defaults.keepalive_max_missed,
    defaults.connect_timeout_secs,
  ].filter((value) => value != null).length;
  const settingsChanged = groupConnectionSettingsChanged(group, state);
  const showImpact =
    settingsChanged && (affected.hosts > 0 || affected.groups > 0);
  const portMayChange =
    group &&
    ((defaults.port ?? null) !== (group.payload.defaults.port ?? null) ||
      state.payload.parent_id !== group.payload.parent_id);
  const parentPreview = previewInheritance(overview, state.scope, {
    ...emptyHostPayload(),
    group_id: state.payload.parent_id,
    inherit: inheritedFields.map(([field]) => field),
  });
  const canSave = !busy && !blocked && !problem && (!state.id || state.dirty);
  return (
    <div className="group-editor">
      <header className="group-editor-header">
        <span className="group-editor-symbol">
          <Folder aria-hidden="true" className="size-5" />
        </span>
        <div>
          <DialogTitle>{state.id ? "Edit group" : "New group"}</DialogTitle>
          <DialogDescription>
            {state.id
              ? `${affected.hosts} host${affected.hosts === 1 ? "" : "s"} · ${revealHidden(scopeLabel(overview, state.scope))}`
              : "Keep related hosts together in your library."}
          </DialogDescription>
        </div>
        {onCancel && (
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
      </header>
      <div className="group-editor-body">
        {state.changedOnServer && (
          <div role="status" className="group-editor-notice">
            This group changed or became unavailable. Your draft is kept.
            <Button
              className="mt-2"
              size="sm"
              variant="outline"
              disabled={busy || !group}
              onClick={() => setState(beginGroupEditor(group))}
            >
              Reload saved settings
            </Button>
          </div>
        )}
        {group?.group_error && (
          <p role="status" className="text-sm text-destructive">
            {revealHidden(group.group_error)}
          </p>
        )}
        {blocked && (
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
        <fieldset
          disabled={busy || blocked || state.unavailable}
          className="group-editor-fields disabled:opacity-60"
        >
          <div className="group-editor-basics">
            <RecordField label="Group name">
              <Input
                data-group-name
                autoComplete="off"
                placeholder="e.g. Production"
                value={state.payload.name}
                maxLength={128}
                onChange={(e) => patch({ name: e.target.value })}
                onKeyDown={(e) => {
                  if (isImeKey(e)) return;
                  if (e.key === "Enter") {
                    e.preventDefault();
                    if (canSave) save();
                  }
                }}
              />
            </RecordField>
            <RecordField label="Parent group">
              <select
                className={selectClass}
                value={state.payload.parent_id ?? ""}
                onChange={(e) => {
                  const parent = selectGroup(overview.groups, e.target.value);
                  setState((current) => ({
                    ...changeGroupEditor(current, {
                      parent_id: e.target.value || null,
                    }),
                    scope:
                      !current.id && parent
                        ? structuredClone(parent.scope)
                        : current.scope,
                  }));
                }}
              >
                <option value="">Library root</option>
                {state.payload.parent_id &&
                  !parentChoices.some(
                    (g) => g.id === state.payload.parent_id,
                  ) && (
                    <option value={state.payload.parent_id}>
                      Unavailable parent ({state.payload.parent_id})
                    </option>
                  )}
                {parentChoices.map((g) => (
                  <option key={g.id} value={g.id}>
                    {revealHidden(groupPath(overview, g.id, g.scope))}
                  </option>
                ))}
              </select>
              <p className="group-field-hint">
                Choose where this group belongs.
              </p>
            </RecordField>
          </div>
          <div className="group-editor-options">
            <GroupSettingsSection
              title="Connection defaults"
              description="Username, port and authentication"
              count={connectionCount}
              initialOpen={!!state.id && connectionCount > 0}
            >
              <p className="group-field-hint">
                Optional. Leave fields empty to use parent or app defaults.
                Hosts use these values only for fields set to inherit.
              </p>
              <div className="group-connection-grid">
                <RecordField label="Username">
                  <Input
                    placeholder={
                      defaults.user === ""
                        ? "OS username"
                        : parentPreview.payload.user || "Use OS username"
                    }
                    value={defaults.user ?? ""}
                    disabled={defaults.user === ""}
                    onChange={(e) =>
                      defaultPatch({ user: e.target.value || null })
                    }
                  />
                  <label className="group-os-user">
                    <input
                      type="checkbox"
                      checked={defaults.user === ""}
                      onChange={(e) =>
                        defaultPatch({ user: e.target.checked ? "" : null })
                      }
                    />
                    Use OS username
                  </label>
                </RecordField>
                <RecordField label="Port">
                  <Input
                    type="number"
                    min={1}
                    max={65535}
                    placeholder={String(parentPreview.payload.port)}
                    value={defaults.port ?? ""}
                    onChange={(e) =>
                      defaultPatch({
                        port:
                          e.target.value === "" ? null : Number(e.target.value),
                      })
                    }
                  />
                </RecordField>
              </div>
              <RecordField label="Authentication">
                <select
                  className={selectClass}
                  value={state.payload.defaults.authentication?.auth ?? ""}
                  onChange={(e) =>
                    defaultPatch({
                      authentication: e.target.value
                        ? {
                            auth: e.target.value as
                              "key" | "password" | "interactive",
                            key_id:
                              e.target.value === "key"
                                ? (state.payload.defaults.authentication
                                    ?.key_id ?? null)
                                : null,
                          }
                        : null,
                    })
                  }
                >
                  <option value="">Use parent/app default</option>
                  <option value="password">Password</option>
                  <option value="interactive">Keyboard interactive</option>
                  <option value="key">SSH key</option>
                </select>
              </RecordField>
              {state.payload.defaults.authentication?.auth === "key" && (
                <RecordField label="SSH key">
                  <select
                    className={selectClass}
                    value={state.payload.defaults.authentication.key_id ?? ""}
                    onChange={(e) =>
                      defaultPatch({
                        authentication: {
                          auth: "key",
                          key_id: e.target.value || null,
                        },
                      })
                    }
                  >
                    <option value="">Choose a key…</option>
                    {state.payload.defaults.authentication.key_id &&
                      !overview.keys.some(
                        (k) =>
                          k.id ===
                          state.payload.defaults.authentication?.key_id,
                      ) && (
                        <option
                          value={state.payload.defaults.authentication.key_id}
                        >
                          Missing key (
                          {state.payload.defaults.authentication.key_id})
                        </option>
                      )}
                    {overview.keys.map((k) => (
                      <option key={k.id} value={k.id}>
                        {revealHidden(k.public?.name ?? k.id)} ·{" "}
                        {k.status.replace(/_/g, " ")}
                      </option>
                    ))}
                  </select>
                </RecordField>
              )}
            </GroupSettingsSection>
            <GroupSettingsSection
              title="Advanced SSH options"
              description="Jump hosts, keepalive and timeout"
              count={advancedCount}
              initialOpen={!!state.id && advancedCount > 0}
            >
              <RecordField label="Jump hosts">
                <select
                  className={selectClass}
                  value={
                    state.payload.defaults.jump == null ? "inherit" : "explicit"
                  }
                  onChange={(e) =>
                    defaultPatch({
                      jump: e.target.value === "inherit" ? null : [],
                    })
                  }
                >
                  <option value="inherit">Use parent/app default</option>
                  <option value="explicit">
                    Custom route (empty connects directly)
                  </option>
                </select>
                {state.payload.defaults.jump != null && (
                  <div className="space-y-2">
                    {state.payload.defaults.jump.map((id, index) => (
                      <div
                        className="flex items-center gap-2"
                        key={`${id}:${index}`}
                      >
                        <span className="min-w-0 flex-1 truncate text-sm">
                          {index + 1}.{" "}
                          {revealHidden(
                            selectHost(overview.hosts, id)?.payload.alias ??
                              `Missing or conflicting host (${id})`,
                          )}
                        </span>
                        <Button
                          size="sm"
                          variant="outline"
                          onClick={() =>
                            defaultPatch({
                              jump: state.payload.defaults.jump!.filter(
                                (_, i) => i !== index,
                              ),
                            })
                          }
                        >
                          Remove
                        </Button>
                      </div>
                    ))}
                    <select
                      aria-label="Add default jump host"
                      className={selectClass}
                      value=""
                      disabled={state.payload.defaults.jump.length >= 5}
                      onChange={(e) => {
                        if (e.target.value)
                          defaultPatch({
                            jump: [
                              ...state.payload.defaults.jump!,
                              e.target.value,
                            ],
                          });
                      }}
                    >
                      <option value="">Add jump host…</option>
                      {overview.hosts
                        .filter(
                          (h) =>
                            selectHost(overview.hosts, h.id) &&
                            !state.payload.defaults.jump!.includes(h.id),
                        )
                        .map((h) => (
                          <option key={h.id} value={h.id}>
                            {revealHidden(h.payload.alias)} ·{" "}
                            {revealHidden(scopeLabel(overview, h.scope))}
                          </option>
                        ))}
                    </select>
                  </div>
                )}
              </RecordField>

              <div className="group-connection-grid">
                {(
                  [
                    ["Keepalive interval (seconds)", "keepalive_secs", 0],
                    ["Missed keepalives", "keepalive_max_missed", 0],
                    ["Connect timeout (seconds)", "connect_timeout_secs", 1],
                  ] as const
                ).map(([label, field, min]) => (
                  <RecordField key={field} label={label}>
                    <Input
                      type="number"
                      min={min}
                      max={4294967295}
                      placeholder={String(parentPreview.payload[field])}
                      value={defaults[field] ?? ""}
                      onChange={(e) =>
                        defaultPatch({
                          [field]:
                            e.target.value === ""
                              ? null
                              : Number(e.target.value),
                        })
                      }
                    />
                  </RecordField>
                ))}
              </div>
            </GroupSettingsSection>
          </div>
        </fieldset>
        {showImpact && (
          <div role="status" className="group-editor-notice">
            These settings may affect {affected.hosts} host
            {affected.hosts === 1 ? "" : "s"}
            {affected.groups > 0 && (
              <>
                {" "}
                and {affected.groups} subgroup{affected.groups === 1 ? "" : "s"}
              </>
            )}
            . Only inherited fields will change.
            {portMayChange && affected.hosts > 0 && (
              <p className="group-field-hint mt-1">
                If a host’s inherited port changes, its saved host-key pin will
                be cleared.
              </p>
            )}
          </div>
        )}
        <details className="group-defaults-preview">
          <summary>
            View effective defaults{" "}
            <ChevronDown aria-hidden="true" className="size-3.5" />
          </summary>
          {preview.error ? (
            <p role="status" className="text-sm text-destructive">
              {revealHidden(preview.error)}
            </p>
          ) : (
            <dl>
              {inheritedFields.map(([field, label]) => (
                <div key={field}>
                  <dt>{label}</dt>
                  <dd>
                    {revealHidden(effectiveField(preview.payload, field))}
                    <small>
                      {preview.sources[field] === "default"
                        ? "App default"
                        : revealHidden(
                            previewOverview.groups.find(
                              (g) => g.id === preview.sources[field],
                            )?.payload.name ?? "Group",
                          )}
                    </small>
                  </dd>
                </div>
              ))}
            </dl>
          )}
        </details>
        {state.id && (
          <details className="group-management">
            <summary>
              Manage group{" "}
              <ChevronDown aria-hidden="true" className="size-3.5" />
            </summary>
            <div className="space-y-3">
              <h3 className="text-sm font-medium">
                Delete group and subgroups
              </h3>
              <p className="text-xs text-muted-foreground">
                Includes {affected.groups} descendant Group
                {affected.groups === 1 ? "" : "s"}.
              </p>
              {deletionError && (
                <p
                  role="alert"
                  className="break-words text-xs text-destructive"
                >
                  {deletionError}
                </p>
              )}
              {!overview.group_deletion_token && (
                <p role="alert" className="text-xs text-destructive">
                  Refresh the records to prepare a new deletion review.
                </p>
              )}
              <p className="text-xs text-muted-foreground">
                All {affected.hosts} hosts are preserved with their current
                effective settings, IDs and credential references. Membership
                and inheritance are removed.
              </p>
              <Button
                variant="outline"
                disabled={
                  busy ||
                  blocked ||
                  state.unavailable ||
                  !overview.group_deletion_token
                }
                onClick={() => {
                  setDeletionError(null);
                  setDeleting(
                    beginGroupDeletion(
                      state,
                      affected,
                      overview.group_deletion_token,
                    ),
                  );
                }}
              >
                Delete group…
              </Button>
              <p className="break-all font-mono text-xs text-muted-foreground">
                Group ID: {state.id}
              </p>
            </div>
          </details>
        )}
      </div>
      <footer className="group-editor-footer">
        <div className="group-editor-save-state">
          <span
            role="status"
            className={state.dirty && problem ? "text-destructive" : undefined}
          >
            {state.unavailable
              ? "Group unavailable"
              : state.dirty && problem
                ? problem
                : state.id
                  ? state.dirty
                    ? "Unsaved changes"
                    : "All changes saved"
                  : "Only a name is required"}
          </span>
          {state.id && state.dirty && (
            <Button
              size="sm"
              variant="ghost"
              disabled={busy || !group}
              onClick={() => setState(beginGroupEditor(group))}
            >
              Reset
            </Button>
          )}
        </div>
        <div className="group-editor-actions">
          {onCancel && (
            <Button variant="outline" disabled={busy} onClick={onCancel}>
              Cancel
            </Button>
          )}
          <Button disabled={!canSave} onClick={() => save()}>
            {busy ? "Saving…" : state.id ? "Save changes" : "Create group"}
          </Button>
        </div>
      </footer>
      <FormatUpgradeReview
        open={upgrade}
        busy={busy}
        confirm={() => save(true)}
        cancel={() => setUpgrade(false)}
      />
      <Dialog
        open={deleting !== null}
        onOpenChange={(value) => {
          if (!busy && !value) setDeleting(null);
        }}
      >
        <DialogContent>
          <DialogTitle>Delete Group subtree?</DialogTitle>
          <DialogDescription>
            Delete this Group and {deleting?.counts.groups ?? 0} descendant
            Groups. Keep all {deleting?.counts.hosts ?? 0} hosts with their
            effective settings. Unsaved Group edits will be discarded.
          </DialogDescription>
          <DialogFooter>
            <Button
              autoFocus
              variant="outline"
              disabled={busy}
              onClick={() => setDeleting(null)}
            >
              Keep editing
            </Button>
            <Button
              variant="destructive"
              disabled={busy || blocked || state.unavailable}
              onClick={() =>
                void run(async () => {
                  if (!state.id || !state.revision || !deleting) return;
                  try {
                    accept(await submitGroupDeletion(deleting, state));
                  } catch (error) {
                    // Retire the failed review. Refresh for an explicit new confirmation;
                    // never silently replace the frozen candidate and retry deletion.
                    setDeleting(null);
                    try {
                      const fresh = await fetchRecordsStatus();
                      if (fresh.overview) accept(fresh.overview);
                    } catch {
                      // Keep the recovery guidance visible if the refresh also fails.
                    }
                    const message = `${error instanceof Error ? error.message : String(error)} Refresh the records and review the deletion again.`;
                    setDeletionError(revealHidden(message));
                    return;
                  }
                  setDeleting(null);
                  onDeleted();
                })
              }
            >
              Confirm delete
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}

function GroupSettingsSection({
  title,
  description,
  count,
  initialOpen,
  children,
}: {
  title: string;
  description: string;
  count: number;
  initialOpen: boolean;
  children: ReactNode;
}) {
  const [open, setOpen] = useState(initialOpen);
  const id = useId();
  return (
    <section className="group-settings-section" data-open={open}>
      <button
        type="button"
        className="group-settings-toggle"
        aria-expanded={open}
        aria-controls={id}
        onClick={() => setOpen(!open)}
      >
        <SlidersHorizontal aria-hidden="true" className="size-4" />
        <span>
          <strong>{title}</strong>
          <small>{description}</small>
        </span>
        <span className="group-settings-count">
          {count ? `${count} set` : "Optional"}
        </span>
        <ChevronDown
          aria-hidden="true"
          className="group-settings-chevron size-4"
        />
      </button>
      <div id={id} className="group-settings-content" hidden={!open}>
        {children}
      </div>
    </section>
  );
}
