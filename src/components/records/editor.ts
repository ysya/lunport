import {
  createRecordHost,
  updateRecordHost,
  type HostPayload,
  type HostScope,
  type RecordHostView,
  type RecordRevision,
  type RecordOverview,
  type ImportPreviewResult,
} from "@/lib/records";
import { deleteTransport, saveTransport, transportFor, type HostTransport, type OsLoginProfileView } from "@/lib/transports";
export type EditorState = {
  originalScope?: HostScope;
  id: string | null;
  scope: HostScope;
  payload: HostPayload;
  revision: RecordRevision | null;
  dirty: boolean;
  reviewed: boolean;
  changedOnServer: boolean;
  unavailable: boolean;
  error: string | null;
};
export function emptyHostPayload(): HostPayload {
  return {
    schema: 2,
    alias: "",
    hostname: "",
    port: 22,
    user: "",
    auth: "password",
    key_id: null,
    jump: [],
    keepalive_secs: 30,
    keepalive_max_missed: 3,
    connect_timeout_secs: 15,
    host_key: null,
    tags: [],
    notes: "",
    imported: null,
  };
}
export function beginEditor(host: RecordHostView | null): EditorState {
  return {
    id: host?.id ?? null,
    scope: structuredClone(host?.scope ?? { kind: "local" }),
    originalScope: host ? structuredClone(host.scope) : undefined,
    payload: structuredClone({
      ...(host?.payload ?? emptyHostPayload()),
      group_id: host?.payload.group_id ?? null,
      inherit: host?.payload.inherit ?? [],
    }),
    revision: host ? structuredClone(host.revision) : null,
    dirty: false,
    reviewed: false,
    changedOnServer: false,
    unavailable: false,
    error: null,
  };
}
export function beginDuplicateEditor(
  host: RecordHostView,
  hosts: RecordHostView[],
): EditorState {
  const aliases = new Set(hosts.map((value) => value.payload.alias));
  const base = `${host.payload.alias}-copy`;
  let alias = base;
  for (let suffix = 2; aliases.has(alias); suffix++) alias = `${base}-${suffix}`;
  return {
    ...beginEditor(null),
    scope: structuredClone(host.scope),
    payload: structuredClone({ ...host.payload, alias, host_key: null }),
    dirty: true,
  };
}
export function changeEditor(
  state: EditorState,
  patch: Partial<HostPayload>,
): EditorState {
  return {
    ...state,
    payload: { ...state.payload, ...structuredClone(patch) },
    dirty: true,
    error: null,
  };
}
export function refreshEditor(
  state: EditorState,
  host: RecordHostView | null,
): EditorState {
  if (state.id === null) return state;
  if (host === null || host.id !== state.id)
    return { ...state, changedOnServer: true, unavailable: true };
  if (!state.dirty) return beginEditor(host);
  const changed =
    state.revision?.version !== host.revision.version ||
    state.revision.updated_at_ms !== host.revision.updated_at_ms ||
    state.revision.device_id !== host.revision.device_id ||
    JSON.stringify(state.originalScope ?? state.scope) !==
      JSON.stringify(host.scope);
  return { ...state, changedOnServer: changed, unavailable: false };
}
export function buildEditorPayload(state: EditorState): HostPayload {
  const payload = structuredClone(state.payload);
  payload.host_key = null;
  if (payload.group_id || payload.inherit?.length) payload.schema = 3;
  else {
    delete payload.group_id;
    delete payload.inherit;
    payload.schema = 2;
  }
  if (state.reviewed && payload.imported)
    payload.imported.unsupported = payload.imported.unsupported.filter(
      (setting) => !setting.requires_review,
    );
  return payload;
}
export function editorProblem(state: EditorState): string | null {
  const p = state.payload;
  if (state.unavailable)
    return "This host is unavailable in the current snapshot.";
  if (
    !p.alias ||
    p.alias.startsWith("-") ||
    !/^[A-Za-z0-9._@%\-]+$/.test(p.alias)
  )
    return "Enter a valid alias without spaces.";
  if (!p.hostname || /[\s\u0000-\u001f\u007f]/.test(p.hostname))
    return "Enter a hostname or IP address without spaces.";
  if (!Number.isInteger(p.port) || p.port < 1 || p.port > 65535)
    return "Port must be between 1 and 65535.";
  if (/[\s\u0000-\u001f\u007f]/.test(p.user))
    return "Username cannot contain spaces or control characters.";
  if (p.auth === "key" && !p.key_id) return "Choose a key reference.";
  if (p.key_id !== null && !/^[a-f0-9]{32}$/.test(p.key_id))
    return "Choose a valid key reference.";
  if (
    p.jump.length > 5 ||
    new Set(p.jump).size !== p.jump.length ||
    p.jump.some((id) => !/^[a-f0-9]{16}$/.test(id) || id === state.id)
  )
    return "Choose up to five distinct jump hosts.";
  for (const [label, value, minimum] of [
    ["Keepalive interval", p.keepalive_secs, 0],
    ["Missed keepalives", p.keepalive_max_missed, 0],
    ["Connect timeout", p.connect_timeout_secs, 1],
  ] as const)
    if (!Number.isInteger(value) || value < minimum || value > 4294967295)
      return `${label} is out of range.`;
  return null;
}
export async function submitEditor(
  state: EditorState,
  upgradeConfirmed?: boolean,
): Promise<RecordOverview> {
  const problem = editorProblem(state);
  if (problem) throw new Error(problem);
  const payload = buildEditorPayload(state);
  if (state.id === null)
    return createRecordHost(state.scope, payload, upgradeConfirmed);
  if (!state.revision) throw new Error("The saved revision is unavailable.");
  return updateRecordHost(state.id, state.revision, payload, upgradeConfirmed);
}
/**
 * The transport step of a save, after the host is saved and its id known: `undefined` means the section was not touched, `null` that
 * Direct was chosen (the saved transport goes), a value that it is saved against the one displayed. The overview the backend answers,
 * or `null` when nothing was sent.
 */
export async function saveTransportDraft(
  id: string,
  draft: HostTransport | null | undefined,
  overview: RecordOverview,
): Promise<RecordOverview | null> {
  if (draft === undefined) return null;
  const saved = transportFor(overview, id);
  if (draft === null) return saved ? deleteTransport(saved) : null;
  return saveTransport({ ...draft, host_id: id }, saved);
}

/** What the Use OS Login username button does with the profile it fetched: the username goes into the draft; the note is about the key. */
export function applyOsLoginProfile(
  state: EditorState,
  view: OsLoginProfileView,
): { state: EditorState; note: string | null } {
  if (!view.username)
    return {
      state: { ...state, error: `OS Login has no POSIX account for ${view.account} in this project; the project may not have OS Login enabled.` },
      note: null,
    };
  const next = view.username === state.payload.user ? { ...state, error: null } : changeEditor(state, { user: view.username });
  return {
    state: next,
    note: view.key_registered === false ? "This key is not registered with OS Login yet; it is registered at the first connection." : null,
  };
}

export function selectHost(
  hosts: RecordHostView[],
  id: string,
): RecordHostView | null {
  const matching = hosts.filter((host) => host.id === id);
  return matching.length === 1 ? matching[0] : null;
}
export function confirmedCopyIds(
  preview: ImportPreviewResult,
  selected: string[],
): string[] {
  const allowed = new Set(
    preview.preview.key_references
      .filter((reference) => reference.resolved_path !== null)
      .map((reference) => reference.key_id),
  );
  return [...new Set(selected)].filter((id) => allowed.has(id));
}
