import { tauriInvoke } from "@/lib/ipc";
import {
  useQuery,
  useQueryClient,
  type QueryClient,
} from "@tanstack/react-query";
export type HostScope = { kind: "local" } | { kind: "space"; space_id: string };
export type RecordRevision = {
  version: string;
  updated_at_ms: string;
  device_id: string;
};
export type StoredHostKey = {
  algorithm: string;
  public_key: string;
  fingerprint: string;
  pinned_at_ms: number;
  pinned_by_device_id: string;
};
export type ImportedSettings = {
  source: string;
  at_ms: number;
  unsupported: Array<{
    keyword: string;
    value: string;
    requires_review: boolean;
  }>;
};
export type InheritedField =
  | "port"
  | "user"
  | "authentication"
  | "jump"
  | "keepalive_secs"
  | "keepalive_max_missed"
  | "connect_timeout_secs";
export type GroupAuthentication = {
  auth: "key" | "password" | "interactive";
  key_id: string | null;
};
export type GroupDefaults = {
  port?: number | null;
  user?: string | null;
  authentication?: GroupAuthentication | null;
  jump?: string[] | null;
  keepalive_secs?: number | null;
  keepalive_max_missed?: number | null;
  connect_timeout_secs?: number | null;
};
export type GroupPayload = {
  schema: 1;
  name: string;
  parent_id: string | null;
  defaults: GroupDefaults;
};
export type RecordGroupView = {
  id: string;
  scope: HostScope;
  payload: GroupPayload;
  revision: RecordRevision;
  group_error: string | null;
};
export type HostPayload = {
  group_id?: string | null;
  inherit?: InheritedField[];
  schema: number;
  alias: string;
  hostname: string;
  port: number;
  user: string;
  auth: "key" | "password" | "interactive";
  key_id: string | null;
  jump: string[];
  keepalive_secs: number;
  keepalive_max_missed: number;
  connect_timeout_secs: number;
  host_key: StoredHostKey | null;
  tags: string[];
  notes: string;
  imported: ImportedSettings | null;
};
export type RecordHostView = {
  id: string;
  scope: HostScope;
  payload: HostPayload;
  revision: RecordRevision;
  effective_payload: HostPayload;
  inherited_from: Partial<Record<InheritedField, string>>;
  group_error: string | null;
  readiness: {
    kind: "ready" | "needs_key" | "key_conflict" | "needs_review";
    key_id?: string;
  };
};
export type KeySlotPayload = {
  schema: number;
  name: string;
  public_key: string;
  fingerprint: string;
  key_type: string;
  has_passphrase: boolean;
  created_at_ms: number;
  origin_device_id: string;
};
export type RecordKeyView = {
  id: string;
  authority: "local" | "account";
  synced: boolean | null;
  public: KeySlotPayload | null;
  status: "available" | "needs_material" | "conflict" | "deleted";
};
export type RecordOverview = {
  generation: string;
  groups: RecordGroupView[];
  format_upgrade_required: boolean;
  shared_format_upgrade_required: boolean;
  hosts: RecordHostView[];
  keys: RecordKeyView[];
  spaces: Array<{
    id: string;
    name: string;
    selected: boolean;
    missing: boolean;
  }>;
  account: { chain_id: string; device_name: string } | null;
  shared_writes_blocked: boolean;
  relay_url: string;
  pending_account: {
    id: string;
    kind:
      | "create_account"
      | "join_account"
      | "create_space"
      | "leave_account"
      | "rotate_account";
    phase: string;
  } | null;
  last_sync_ms: number | null;
  last_error: string | null;
};
export type RecordsStatus = {
  format: "records" | "legacy" | "blocked";
  legacy_paused: boolean;
  blocked_reason: string | null;
  overview: RecordOverview | null;
};
export type ImportPreview = {
  candidates: Array<{ id: string; scope: HostScope; payload: HostPayload }>;
  warnings: Array<{
    location: { path: string; line: number };
    keyword: string;
    reason: string;
    blocks_connection: boolean;
    alias: string | null;
  }>;
  provenance: Array<{
    path: string;
    canonical_path: string;
    digest: string;
    bytes: number;
  }>;
  key_references: Array<{
    host_id: string;
    key_id: string;
    value: string;
    resolved_path: string | null;
    fingerprint: string | null;
    will_copy: boolean;
  }>;
  host_ids: Record<string, string>;
  source_digest: string;
};
export type ImportPreviewResult = { token: string; preview: ImportPreview };
export type ImportResult = {
  receipt: { import_id: string; host_ids: string[]; copied_key_ids: string[] };
  overview: RecordOverview;
};
export const recordsStatusKey = ["records", "status"] as const;
export async function fetchRecordsStatus(): Promise<RecordsStatus> {
  return tauriInvoke<RecordsStatus>("records_status");
}
export function useRecordsStatus() {
  const client = useQueryClient();
  return useQuery({
    queryKey: recordsStatusKey,
    queryFn: async () => {
      const incoming = await fetchRecordsStatus();
      return acceptStatus(client.getQueryData(recordsStatusKey), incoming);
    },
    refetchInterval: 2000,
    retry: false,
  });
}
export function acceptStatus(
  current: RecordsStatus | undefined,
  incoming: RecordsStatus,
): RecordsStatus {
  if (
    current?.format === "records" &&
    incoming.format === "records" &&
    current.overview &&
    incoming.overview &&
    BigInt(current.overview.generation) > BigInt(incoming.overview.generation)
  )
    return current;
  return incoming;
}
export function applyRecordOverview(
  client: QueryClient,
  overview: RecordOverview,
): void {
  client.setQueryData<RecordsStatus>(recordsStatusKey, (current) => {
    if (!current || current.format !== "records") return current;
    return acceptStatus(current, { ...current, overview });
  });
}
export async function createRecordHost(
  scope: HostScope,
  payload: HostPayload,
  upgradeConfirmed?: boolean,
): Promise<RecordOverview> {
  return tauriInvoke("records_host_create", {
    scope,
    payload,
    ...(upgradeConfirmed === undefined ? {} : { upgradeConfirmed }),
  });
}
export async function updateRecordHost(
  id: string,
  revision: RecordRevision,
  payload: HostPayload,
  upgradeConfirmed?: boolean,
): Promise<RecordOverview> {
  return tauriInvoke("records_host_update", {
    id,
    revision,
    payload,
    ...(upgradeConfirmed === undefined ? {} : { upgradeConfirmed }),
  });
}
export async function deleteRecordHost(
  id: string,
  revision: RecordRevision,
): Promise<RecordOverview> {
  return tauriInvoke("records_host_delete", { id, revision });
}
export async function moveRecordHost(
  id: string,
  revision: RecordRevision,
  destination: HostScope,
): Promise<RecordOverview> {
  return tauriInvoke("records_host_move", { id, revision, destination });
}
export async function connectRecordHost(
  hostId: string,
  terminalId: string | null,
  newTab = false,
): Promise<void> {
  return tauriInvoke("records_connect", { hostId, terminalId, newTab });
}
export async function useLegacyWorkspace(): Promise<void> {
  return tauriInvoke("records_use_legacy");
}
export async function previewRecordImport(
  source: string,
): Promise<ImportPreviewResult> {
  return tauriInvoke("records_import_preview", { source });
}
export async function confirmRecordImport(
  token: string,
  copyKeyIds: string[],
): Promise<ImportResult> {
  return tauriInvoke("records_import_confirm", { token, copyKeyIds });
}
export async function resumeRecordImport(
  importId: string,
): Promise<ImportResult> {
  return tauriInvoke("records_import_resume", { importId });
}
export async function importRecordKey(
  name: string,
  privateText: string,
): Promise<RecordOverview> {
  return tauriInvoke("records_key_import", { name, privateText });
}
export async function generateRecordKey(name: string): Promise<RecordOverview> {
  return tauriInvoke("records_key_generate", { name });
}
export async function createRecordAccount(
  deviceName: string,
): Promise<AccountSetupResult> {
  return tauriInvoke("records_account_create", { deviceName });
}
export async function joinRecordAccount(
  words: string,
  deviceName: string,
): Promise<RecordOverview> {
  return tauriInvoke("records_account_join", { words, deviceName });
}
export async function createRecordSpace(name: string): Promise<RecordOverview> {
  return tauriInvoke("records_space_create", { name });
}
export async function selectRecordSpace(
  spaceId: string,
  selected: boolean,
): Promise<RecordOverview> {
  return tauriInvoke("records_space_select", { spaceId, selected });
}
export async function setRecordKeySync(
  keyId: string,
  enabled: boolean,
): Promise<RecordOverview> {
  return tauriInvoke("records_key_sync", { keyId, enabled });
}
export async function syncRecordsNow(): Promise<void> {
  return tauriInvoke("records_sync_now");
}

export type PendingRecordImport = {
  import_id: string;
  phase: string;
  host_count: number;
  key_count: number;
};
export const recordsPendingImportsKey = [
  "records",
  "imports",
  "pending",
] as const;
export async function cancelRecordImport(token: string): Promise<void> {
  return tauriInvoke("records_import_cancel", { token });
}
export async function pendingRecordImports(): Promise<PendingRecordImport[]> {
  return tauriInvoke("records_import_pending");
}
export function usePendingRecordImports() {
  return useQuery({
    queryKey: recordsPendingImportsKey,
    queryFn: pendingRecordImports,
    retry: false,
  });
}
export async function downloadRecordKey(
  keyId: string,
): Promise<RecordOverview> {
  return tauriInvoke("records_key_download", { keyId });
}

export type AccountSetupResult = {
  words: string;
  overview: RecordOverview;
  complete: boolean;
  pending_error: string | null;
  operation_id: string;
};
export async function resumeRecordAccount(
  words?: string,
): Promise<RecordOverview> {
  return tauriInvoke("records_account_resume", { words: words ?? null });
}
export async function recordAccountWords(): Promise<string> {
  return tauriInvoke("records_account_words");
}
export async function setRecordRelayUrl(url: string): Promise<RecordOverview> {
  return tauriInvoke("records_set_relay_url", { url });
}

export type MigrationPreview = {
  source_digest: string;
  source_kind: string;
  account_schema: number;
  selected_space_ids: string[];
  host_count: number;
  key_count: number;
  diagnostics: Array<{
    code: string;
    host_id?: string | null;
    space_id?: string | null;
  }>;
  can_confirm: boolean;
};
export type MigrationPreviewResult = {
  token: string;
  preview: MigrationPreview;
};
export type MigrationReceipt = {
  migration_id: string;
  phase: string;
  complete: boolean;
};
export type MigrationResult = {
  receipt: MigrationReceipt;
  status: RecordsStatus;
};
export type PendingRecordMigration = {
  migration_id: string;
  phase: string;
  host_count: number;
  key_count: number;
};
export const recordsPendingMigrationsKey = [
  "records",
  "migrations",
  "pending",
] as const;
export async function previewRecordMigration(
  words?: string,
): Promise<MigrationPreviewResult> {
  return tauriInvoke("records_migration_preview", { words: words ?? null });
}
export async function confirmRecordMigration(
  token: string,
  oldClientsStoppedOrCompatible: boolean,
): Promise<MigrationResult> {
  return tauriInvoke("records_migration_confirm", {
    token,
    oldClientsStoppedOrCompatible,
  });
}
export async function resumeRecordMigration(
  migrationId: string,
  words?: string,
): Promise<MigrationResult> {
  return tauriInvoke("records_migration_resume", {
    migrationId,
    words: words ?? null,
  });
}
export async function pendingRecordMigrations(): Promise<
  PendingRecordMigration[]
> {
  return tauriInvoke("records_migration_pending");
}
export async function cancelRecordMigration(token: string): Promise<void> {
  return tauriInvoke("records_migration_cancel", { token });
}

export function usePendingRecordMigrations() {
  return useQuery({
    queryKey: recordsPendingMigrationsKey,
    queryFn: pendingRecordMigrations,
    retry: false,
  });
}

export async function pauseLegacyWorkspace(): Promise<RecordsStatus> {
  return tauriInvoke("records_pause_legacy");
}

export type AccountLeaveReceipt = {
  operation_id: string;
  complete: boolean;
  copied_hosts: number;
  mappings: Array<{
    source_space_id: string;
    source_host_id: string;
    local_host_id: string;
    alias: string;
  }>;
  pending_error: string | null;
};
export type AccountLeaveResult = {
  receipt: AccountLeaveReceipt;
  overview: RecordOverview;
};
export async function leaveRecordAccount(): Promise<AccountLeaveResult> {
  return tauriInvoke("records_account_leave");
}
export async function rotateRecordAccount(
  deviceName: string,
): Promise<AccountSetupResult> {
  return tauriInvoke("records_account_rotate", { deviceName });
}

export async function createRecordGroup(
  scope: HostScope,
  payload: GroupPayload,
  upgradeConfirmed: boolean,
): Promise<RecordOverview> {
  return tauriInvoke("records_group_create", {
    scope,
    payload,
    upgradeConfirmed,
  });
}
export async function updateRecordGroup(
  id: string,
  revision: RecordRevision,
  payload: GroupPayload,
): Promise<RecordOverview> {
  return tauriInvoke("records_group_update", { id, revision, payload });
}
export async function deleteRecordGroup(
  id: string,
  revision: RecordRevision,
): Promise<RecordOverview> {
  return tauriInvoke("records_group_delete", { id, revision });
}
