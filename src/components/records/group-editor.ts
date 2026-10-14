import {
  createRecordGroup,
  deleteRecordGroup,
  updateRecordGroup,
  type GroupPayload,
  type HostScope,
  type RecordGroupView,
  type RecordOverview,
  type RecordRevision,
} from "@/lib/records";
import { groupAncestors, requiresFormatUpgrade, scopeKey } from "./group-tree";
export type GroupEditorState = {
  id: string | null;
  scope: HostScope;
  payload: GroupPayload;
  revision: RecordRevision | null;
  dirty: boolean;
  changedOnServer: boolean;
  unavailable: boolean;
  error: string | null;
};
export function beginGroupEditor(
  group: RecordGroupView | null,
  scope: HostScope = { kind: "local" },
  parentId: string | null = null,
): GroupEditorState {
  return {
    id: group?.id ?? null,
    scope: structuredClone(group?.scope ?? scope),
    payload: structuredClone(
      group?.payload ?? {
        schema: 1,
        name: "",
        parent_id: parentId,
        defaults: {},
      },
    ),
    revision: group ? structuredClone(group.revision) : null,
    dirty: false,
    changedOnServer: false,
    unavailable: false,
    error: null,
  };
}
export function changeGroupEditor(
  state: GroupEditorState,
  patch: Partial<GroupPayload>,
): GroupEditorState {
  return {
    ...state,
    payload: { ...state.payload, ...structuredClone(patch) },
    dirty: true,
    error: null,
  };
}
export function refreshGroupEditor(
  state: GroupEditorState,
  group: RecordGroupView | null,
): GroupEditorState {
  if (!state.id) return state;
  if (!group || group.id !== state.id)
    return { ...state, unavailable: true, changedOnServer: true };
  if (!state.dirty) return beginGroupEditor(group);
  return {
    ...state,
    unavailable: false,
    changedOnServer:
      JSON.stringify(state.revision) !== JSON.stringify(group.revision) ||
      scopeKey(state.scope) !== scopeKey(group.scope),
  };
}
export function groupEditorProblem(
  state: GroupEditorState,
  overview: RecordOverview,
): string | null {
  if (state.unavailable)
    return "This Group is unavailable in the current snapshot.";
  const name = state.payload.name.trim();
  if (!name || name.length > 128 || /[\u0000-\u001f\u007f]/.test(name))
    return "Enter a Group name of 1–128 characters without controls.";
  if (state.payload.parent_id === state.id && state.id)
    return "A Group cannot parent itself.";
  const chain = groupAncestors(overview, state.payload.parent_id, state.scope);
  if (chain.error) return chain.error;
  if (chain.groups.some((g) => g.id === state.id))
    return "A Group cannot move into its own subtree.";
  if (chain.groups.length >= 32) return "Group ancestry exceeds 32 levels.";
  if (
    overview.groups.some(
      (g) =>
        g.id !== state.id &&
        scopeKey(g.scope) === scopeKey(state.scope) &&
        g.payload.parent_id === state.payload.parent_id &&
        g.payload.name === name,
    )
  )
    return "A Group with this name already exists under this parent.";
  const d = state.payload.defaults;
  for (const [field, min, max] of [
    ["port", 1, 65535],
    ["keepalive_secs", 0, 4294967295],
    ["keepalive_max_missed", 0, 4294967295],
    ["connect_timeout_secs", 1, 4294967295],
  ] as const)
    if (
      d[field] != null &&
      (!Number.isInteger(d[field]) || d[field]! < min || d[field]! > max)
    )
      return `${field} is out of range.`;
  if (d.user != null && /[\s\u0000-\u001f\u007f]/.test(d.user))
    return "Username cannot contain spaces or controls.";
  if (
    d.authentication?.auth === "key" &&
    !/^[a-f0-9]{32}$/.test(d.authentication.key_id ?? "")
  )
    return "Choose a valid key reference.";
  if (
    d.authentication &&
    d.authentication.auth !== "key" &&
    d.authentication.key_id !== null
  )
    return "Password and interactive defaults cannot reference a key.";
  if (
    d.jump &&
    (d.jump.length > 5 ||
      new Set(d.jump).size !== d.jump.length ||
      d.jump.some((id) => !/^[a-f0-9]{16}$/.test(id)))
  )
    return "Choose up to five distinct jump hosts.";
  return null;
}
export async function submitGroupEditor(
  state: GroupEditorState,
  overview: RecordOverview,
  upgradeConfirmed = false,
): Promise<RecordOverview> {
  const problem = groupEditorProblem(state, overview);
  if (problem) throw new Error(problem);
  if (
    !state.id &&
    requiresFormatUpgrade(overview, state.scope) &&
    !upgradeConfirmed
  )
    throw new Error(
      "Confirm other clients are updated before enabling Groups.",
    );
  const payload = structuredClone({
    ...state.payload,
    name: state.payload.name.trim(),
  });
  if (!state.id)
    return createRecordGroup(state.scope, payload, upgradeConfirmed);
  if (!state.revision) throw new Error("The saved revision is unavailable.");
  return updateRecordGroup(state.id, state.revision, payload);
}

export type GroupDeletionCandidate = Readonly<{
  id: string;
  revision: Readonly<RecordRevision>;
  counts: Readonly<{ groups: number; hosts: number }>;
}>;
export function beginGroupDeletion(
  state: GroupEditorState,
  counts: { groups: number; hosts: number },
): GroupDeletionCandidate {
  if (!state.id || !state.revision || state.unavailable)
    throw new Error("The saved Group is unavailable.");
  return Object.freeze({
    id: state.id,
    revision: Object.freeze(structuredClone(state.revision)),
    counts: Object.freeze({ ...counts }),
  });
}
export async function submitGroupDeletion(
  candidate: GroupDeletionCandidate,
  current: GroupEditorState,
): Promise<RecordOverview> {
  if (current.unavailable || current.id !== candidate.id || !current.revision)
    throw new Error("The reviewed Group is unavailable.");
  return deleteRecordGroup(candidate.id, candidate.revision);
}
