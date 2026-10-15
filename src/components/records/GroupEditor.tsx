import { useEffect, useRef, useState } from "react";
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
    if (blocked || state.unavailable) return;
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
  return (
    <div className="mx-auto max-w-3xl space-y-5 px-6 pb-6">
      <header className="sticky top-0 z-10 flex flex-wrap items-center justify-between gap-3 border-b bg-background py-4">
        <div className="min-w-0 flex-1">
          <h1 className="truncate text-lg font-semibold">
            {state.id ? revealHidden(state.payload.name) : "New group"}
          </h1>
          <p className="text-xs text-muted-foreground">
            {revealHidden(scopeLabel(overview, state.scope))} ·{" "}
            {state.dirty
              ? "Unsaved changes"
              : state.id
                ? "Saved"
                : "Not saved yet"}
          </p>
        </div>
        <div className="flex flex-wrap gap-2">
          {state.id && state.dirty && (
            <Button
              variant="ghost"
              disabled={busy || !group}
              onClick={() => setState(beginGroupEditor(group))}
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
              busy || blocked || !!problem || (!!state.id && !state.dirty)
            }
            onClick={() => save()}
          >
            {busy ? "Working…" : state.id ? "Save group" : "Create group"}
          </Button>
        </div>
      </header>
      {state.changedOnServer && (
        <div role="status" className="rounded-md border p-3 text-sm">
          This Group changed or became unavailable. Your draft and saved
          revision are retained.{" "}
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
      {state.dirty && problem && (
        <p role="status" className="text-sm text-muted-foreground">
          {problem}
        </p>
      )}
      <p className="rounded-md border p-3 text-sm">
        Changes can affect {affected.groups} descendant Group
        {affected.groups === 1 ? "" : "s"} and {affected.hosts} host
        {affected.hosts === 1 ? "" : "s"}. Inherited port changes clear affected
        host-key pins.
      </p>
      <fieldset
        disabled={busy || blocked || state.unavailable}
        className="space-y-4 disabled:opacity-60"
      >
        <RecordField label="Group name">
          <Input
            value={state.payload.name}
            maxLength={128}
            onChange={(e) => patch({ name: e.target.value })}
          />
        </RecordField>
        <RecordField label="Parent Group">
          <select
            className={selectClass}
            value={state.payload.parent_id ?? ""}
            onChange={(e) => {
              const group = selectGroup(overview.groups, e.target.value);
              setState((current) => ({
                ...changeGroupEditor(current, {
                  parent_id: e.target.value || null,
                }),
                scope:
                  !current.id && group
                    ? structuredClone(group.scope)
                    : current.scope,
              }));
            }}
          >
            <option value="">Library root</option>
            {state.payload.parent_id &&
              !parentChoices.some((g) => g.id === state.payload.parent_id) && (
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
        </RecordField>
        <h2 className="text-sm font-semibold">Connection defaults</h2>
        <p className="text-xs text-muted-foreground">
          Unset values use the nearest parent default, then the app default.
          Hosts inherit only fields they explicitly select.
        </p>
        <div className="grid gap-4 sm:grid-cols-2">
          {(
            [
              ["Port", "port", 1],
              ["Keepalive interval (seconds)", "keepalive_secs", 0],
              ["Missed keepalives", "keepalive_max_missed", 0],
              ["Connect timeout (seconds)", "connect_timeout_secs", 1],
            ] as const
          ).map(([label, field, min]) => (
            <RecordField key={field} label={label}>
              <Input
                type="number"
                min={min}
                placeholder="Use parent/app default"
                value={state.payload.defaults[field] ?? ""}
                onChange={(e) =>
                  defaultPatch({
                    [field]:
                      e.target.value === "" ? null : Number(e.target.value),
                  })
                }
              />
            </RecordField>
          ))}
        </div>
        <RecordField label="Username default">
          <Input
            placeholder="Use parent/app default"
            value={state.payload.defaults.user ?? ""}
            onChange={(e) => defaultPatch({ user: e.target.value || null })}
          />
          <label className="flex items-center gap-2 text-xs">
            <input
              type="checkbox"
              checked={state.payload.defaults.user === ""}
              onChange={(e) =>
                defaultPatch({ user: e.target.checked ? "" : null })
              }
            />
            Use OS username explicitly
          </label>
        </RecordField>
        <RecordField label="Authentication default">
          <select
            className={selectClass}
            value={state.payload.defaults.authentication?.auth ?? ""}
            onChange={(e) =>
              defaultPatch({
                authentication: e.target.value
                  ? {
                      auth: e.target.value as
                        | "key"
                        | "password"
                        | "interactive",
                      key_id:
                        e.target.value === "key"
                          ? (state.payload.defaults.authentication?.key_id ??
                            null)
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
          <RecordField label="Default key reference">
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
                  (k) => k.id === state.payload.defaults.authentication?.key_id,
                ) && (
                  <option value={state.payload.defaults.authentication.key_id}>
                    Missing key ({state.payload.defaults.authentication.key_id})
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
        <RecordField label="Jump defaults">
          <select
            className={selectClass}
            value={state.payload.defaults.jump == null ? "inherit" : "explicit"}
            onChange={(e) =>
              defaultPatch({ jump: e.target.value === "inherit" ? null : [] })
            }
          >
            <option value="inherit">Use parent/app default</option>
            <option value="explicit">
              Explicit route (empty means direct)
            </option>
          </select>
          {state.payload.defaults.jump != null && (
            <div className="space-y-2">
              {state.payload.defaults.jump.map((id, index) => (
                <div className="flex items-center gap-2" key={`${id}:${index}`}>
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
                      jump: [...state.payload.defaults.jump!, e.target.value],
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
      </fieldset>
      <section className="space-y-2 rounded-lg border p-4">
        <h2 className="text-sm font-semibold">Effective defaults preview</h2>
        {preview.error ? (
          <p role="status" className="text-sm text-destructive">
            {revealHidden(preview.error)}
          </p>
        ) : (
          inheritedFields.map(([field, label]) => (
            <p key={field} className="break-words text-xs">
              <span className="font-medium">{label}: </span>
              {revealHidden(effectiveField(preview.payload, field))} ·{" "}
              {preview.sources[field] === "default"
                ? "App default"
                : revealHidden(
                    previewOverview.groups.find(
                      (g) => g.id === preview.sources[field],
                    )?.payload.name ?? "Group",
                  )}
            </p>
          ))
        )}
      </section>
      {state.id && (
        <section className="space-y-3 rounded-lg border p-4">
          <h2 className="text-sm font-semibold">Delete Group subtree</h2>
          {deletionError && (
            <p role="alert" className="break-words text-xs text-destructive">
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
            effective settings, IDs and credential references. Membership and
            inheritance are removed.
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
        </section>
      )}
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
