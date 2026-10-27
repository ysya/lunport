import type {
  HostPayload,
  ImportPreviewResult,
  RecordHostView,
  RecordGroupView,
  RecordOverview,
  RecordsStatus,
} from "@/lib/records";
import type { HostTransport, TransportKind } from "@/lib/transports";
export const hostPayload = (p: Partial<HostPayload> = {}): HostPayload => ({
  schema: 2,
  alias: "web",
  hostname: "fixture.invalid",
  port: 22,
  user: "deploy",
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
  ...p,
});
export const hostView = (p: Partial<RecordHostView> = {}): RecordHostView => ({
  id: "0000000000000001",
  scope: { kind: "local" },
  payload: hostPayload(),
  revision: {
    version: "9007199254740993",
    updated_at_ms: "18446744073709551614",
    device_id: "d".repeat(32),
  },
  effective_payload: p.payload ?? hostPayload(),
  inherited_from: {},
  group_error: null,
  readiness: { kind: "ready" },
  ...p,
});
/** A host's Google Cloud IAP route, with synthetic names and no account or grant check; `kind` overrides its fields. */
export const hostTransport = (
  kind: Partial<TransportKind> = {},
  hostId: string = hostView().id,
): HostTransport => ({
  host_id: hostId,
  kind: {
    type: "gcp_iap",
    project: "acme-prod-123456",
    zone: "asia-east1-b",
    instance: "web-1",
    interface: "nic0",
    account: null,
    os_login: true,
    pam: null,
    ...kind,
  },
});
export const recordOverview = (
  p: Partial<RecordOverview> = {},
): RecordOverview => ({
  library_enabled: false,
  library_scope: { kind: "local" },
  pending_changes: 0,
  generation: "9007199254740993",
  group_deletion_token: "fixture-reviewed-snapshot",
  hosts: [hostView()],
  groups: [],
  transports: [],
  format_upgrade_required: false,
  shared_format_upgrade_required: false,
  keys: [],
  spaces: [],
  account: null,
  shared_writes_blocked: false,
  relay_url: "https://relay.fixture.invalid",
  pending_account: null,
  last_sync_ms: null,
  last_error: null,
  ...p,
});
export const recordsStatus = (
  p: Partial<RecordsStatus> = {},
): RecordsStatus => ({
  format: "records",
  legacy_paused: false,
  blocked_reason: null,
  overview: recordOverview(),
  ...p,
});
export const importPreview = (
  p: Partial<ImportPreviewResult["preview"]> = {},
): ImportPreviewResult => ({
  token: "preview-token",
  preview: {
    candidates: [
      {
        id: "0000000000000002",
        scope: { kind: "local" },
        payload: hostPayload({ alias: "imported" }),
      },
    ],
    warnings: [],
    provenance: [
      {
        path: "/fixture/config",
        canonical_path: "/fixture/config",
        digest: "a".repeat(64),
        bytes: 50,
      },
    ],
    key_references: [
      {
        host_id: "0000000000000002",
        key_id: "a".repeat(32),
        value: "id_work",
        resolved_path: "/fixture/id_work",
        fingerprint: "SHA256:fixture",
        will_copy: false,
      },
    ],
    host_ids: {},
    source_digest: "b".repeat(64),
    ...p,
  },
});

export const migrationPreview =
  (): import("@/lib/records").MigrationPreviewResult => ({
    token: "migration-fixture-token",
    preview: {
      source_digest: "a".repeat(64),
      source_kind: "v2",
      account_schema: 2,
      selected_space_ids: ["b".repeat(64)],
      host_count: 2,
      key_count: 1,
      diagnostics: [],
      can_confirm: true,
    },
  });

export const groupView = (
  p: Partial<RecordGroupView> = {},
): RecordGroupView => ({
  id: "0000000000000010",
  scope: { kind: "local" },
  payload: { schema: 1, name: "Operations", parent_id: null, defaults: {} },
  revision: hostView().revision,
  group_error: null,
  ...p,
});
