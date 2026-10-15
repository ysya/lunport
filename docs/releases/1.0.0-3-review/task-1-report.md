# Task 1 implementation report

Status: DONE; awaiting task-scoped controller review.

Commit: `2b8ef00f69938c1e902a768d0865bb21c514e2bf` — `feat(records): add nested groups and inherited settings`. Review base: `bd36d41d69ae55f343c7c70de9d42d5e240e3dd9`.

## Changes

- Added strict Group payload/defaults/authentication and inherited-field types, Group record codec, Local group map, encrypted `group` kind, and authenticated opaque Group identity shadows.
- Retained state version 3 and host schema 2 compatibility. Group-capable state uses version 4; grouped/inherited hosts use schema 3. Future state versions remain rejected. Empty membership/inheritance extensions are omitted on serialization.
- Pure resolution traverses at most 32 same-scope ancestors; nearest defaults win only for explicitly inherited fields. Raw host settings remain separate. Missing/deleted/opaque ancestors and cycles fail closed, with inspectable diagnostics and Needs review readiness.
- Repository/Records directory route, auth/key readiness, effective endpoint and pin CAS use effective settings. Group port changes clear descendant pins atomically; persisted remote changes also clear changed endpoint pins. Conflicted account key identity cannot fall back to same-ID Local material.
- Added pure Group CRUD with stable IDs, optimistic revisions, same-parent name checks, parent/scope validation and effective-route validation. Subtree deletion materializes host values and preserves host IDs/key references before tombstoning Groups. Cross-scope host moves materialize schema-2 values and remove membership.
- Added native Group commands and overview DTOs. Local/shared upgrades require explicit confirmation. Runtime writes a SHA-256-named source backup with mode 0600 before publishing version 4. Account schemas 3 and 4 are compatible; shared Groups/schema-3 hosts require a monotonic metadata promotion to schema 4 and a clean acknowledged gate before child pushes.
- Leave journals add optional Group mappings while remaining backward compatible. Leave remaps parent/member/jump IDs and preserves nested effective values and password namespaces; unreadable selected Group sources stop detach. Rotation copies Group live/tombstone rows and preserves schema-4 metadata.
- Updated existing future-format fixtures from schema/state 4 to 5, preserving their original future-client checks. Legacy migration/import producers continue emitting ungrouped schema-2 hosts.

## Controller-approved API addition

The controller explicitly requested optional `upgrade_confirmed` on native host create/update, so ungrouped hosts can use app-default inheritance without first creating a Group. The optional argument defaults to false. This uses the same pure promotion, source backup and account gate as Group creation. Existing schema-2 calls are unaffected.

## Exact native JSON contracts for frontend

```ts
type HostScope = { kind: 'local' } | { kind: 'space'; space_id: string };
type RevisionToken = { version: string; updated_at_ms: string; device_id: string };
type InheritedField =
  | 'port' | 'user' | 'authentication' | 'jump'
  | 'keepalive_secs' | 'keepalive_max_missed' | 'connect_timeout_secs';
type GroupAuthentication = { auth: 'key' | 'password' | 'interactive'; key_id: string | null };
type GroupDefaults = {
  port?: number | null;
  user?: string | null;
  authentication?: GroupAuthentication | null;
  jump?: string[] | null;
  keepalive_secs?: number | null;
  keepalive_max_missed?: number | null;
  connect_timeout_secs?: number | null;
};
type GroupPayload = {
  schema: 1;
  name: string;
  parent_id: string | null;
  defaults: GroupDefaults;
};
type GroupView = {
  id: string;
  scope: HostScope;
  payload: GroupPayload;
  revision: RevisionToken;
  group_error: string | null;
};
// Added to existing HostPayload (schema is now 2 | 3):
// group_id?: string | null;
// inherit?: InheritedField[];
// Added to existing native HostView:
// effective_payload: HostPayload;
// inherited_from: Partial<Record<InheritedField, string>>;
// group_error: string | null;
// Added to RecordOverview:
// groups: GroupView[];
// format_upgrade_required: boolean;
// shared_format_upgrade_required: boolean;
```

- HostView `payload` remains raw and must be used for editing; use `effective_payload` for previews only. If `group_error` is non-null, do not interpret the effective field as a usable connection fallback; readiness is `needs_review` and directory execution refuses it.
- `inherited_from` contains only selected inherited fields, with a Group ID or literal `default`. Empty effective `user` means the existing OS-username sentinel; RecordDirectory substitutes the OS username at connection time. This keeps repository resolution pure and allows tests to supply the username.
- Missing `group_id` / `inherit` must be normalized to null / `[]` in the UI. Group default fields with no value are omitted by serialization; passing null is also accepted.
- Authentication is atomic. For `key`, `key_id` must be a valid 32-hex ID; for `password`/`interactive`, Group `key_id` must be null.
- Existing Group scope is immutable; update accepts no scope argument.
- Show format confirmation for Local when `format_upgrade_required`; for a Space when either flag is true. Shared flag is false when no account exists.
- All commands return the complete `RecordOverview` after persisted mutation:

```ts
invoke('records_group_create', { scope, payload, upgradeConfirmed: boolean });
invoke('records_group_update', { id, revision, payload });
invoke('records_group_delete', { id, revision });
invoke('records_host_create', { scope, payload, upgradeConfirmed?: boolean });
invoke('records_host_update', { id, revision, payload, upgradeConfirmed?: boolean });
```

The Tauri argument names use camelCase; payload and returned DTO fields remain snake_case. Revision numbers remain decimal strings. Group creation trims the supplied name; decoded persisted Group names must already be trimmed. IDs are 16 lowercase hex characters. The pure repo GroupView is `{ group: GroupRecord, revision: RecordRevision, group_error }`; the native view above is deliberately flattened like HostView.

## TDD evidence and verification

1. Initial RED: `cargo test --offline --locked --lib group` from `src-tauri`; `/private/tmp/sshelter-task1-red.log`. Expected E0425 missing `resolve_effective` and E0609 missing Local `groups` (6 feature-boundary errors). No unrelated compiler error used as RED evidence.
2. Initial GREEN: same group filter, 13 passed, 0 failed, including nested literal `ops / 2222 / keepalive 10`, provenance and missing/cyclic/cross-scope cases. `/private/tmp/sshelter-task1-green3.log`.
3. Lifecycle RED: Group filter reached 21 passed / 1 failed. New rotation regression exposed the temporary rotation validator's state version 3 and its empty schema-4 destination gate restriction. `/private/tmp/sshelter-task1-lifecycle-red.log` and `/private/tmp/sshelter-task1-rotation-debug.log`. Fixed the validator to accept Group-capable state and the empty destination gate to accept the supported maximum, preserving source account schema.
4. Group GREEN: 26 passed / 0 failed. `/private/tmp/sshelter-task1-groups-ready.log`. Covers nested effective values/provenance, raw overrides, defaults/auth atomicity, key conflict no fallback, missing/cyclic/scope/opaque failures, stale revisions, duplicate names, invalid inherited routes, parent port 22→2222 pin invalidation/CAS, directory effective endpoint, deletion materialization, schema-2 move, backup mode/bytes, old/new/future formats, failed schema gate zero child pushes, independent second-device decryption, leave mappings, unreadable leave refusal, rotation live/tombstone preservation.
5. Complete safe suite before the controller's optional-host API follow-up:
   `cargo test --offline --locked --manifest-path src-tauri/Cargo.toml --lib -- --skip secrets::tests::round_trip_set_get_delete --skip askpass::tests::env_secret_takes_priority_over_keychain --skip askpass::tests::missing_account_and_no_env_yields_none`
   **2468 passed, 0 failed, 3 filtered**, 125.76 seconds. `/private/tmp/sshelter-task1-full-safe.log`. Used escalation only to allow disposable loopback SSH fixtures; no real hosts or credentials were operated.
6. Optional-host API RED: `cargo test --offline --locked --manifest-path src-tauri/Cargo.toml --lib ungrouped_host_app_defaults`; expected E0425 for missing `promote_for_host`. `/private/tmp/sshelter-task1-host-upgrade-red.log`.
7. Optional-host API GREEN: same filter **1 passed / 0 failed**; proves unconfirmed rejection leaves state unchanged, confirmed promotion resolves all seven literal app defaults and preserves the exact original source backup. `/private/tmp/sshelter-task1-host-upgrade-green.log`.
8. Final focused Records/lifecycle/directory regression after optional API addition and formatting: `cargo test --offline --locked --manifest-path src-tauri/Cargo.toml --lib record_` with disposable-loopback escalation: **331 passed, 0 failed, 2141 filtered**, 16.75 seconds. `/private/tmp/sshelter-task1-record-final.log`. The controller will rerun the whole integration suite, as explicitly instructed, rather than repeating all 2468 tests for this small follow-up.
9. `git diff --check` passed.

Initial broad sandboxed `record_` attempt had 323 pass / 4 fail: two toy SSH listeners were denied by sandbox, one existing schema99 error-kind expectation required restoring the decoder's schema probe, and the rotation regression above. These were addressed; no failed sandbox result is represented as a passing runtime check.

Formatting cleanup was restricted to Task 1 files. A partial-format attempt damaged two existing condition delimiters/module declarations; they were restored from the exact original functions with only the intended schema-maximum substitution, then compiled and covered by the final Records regression. An optional post-format `cargo check --tests` rebuilt separate metadata dependencies and was canceled; it is not claimed as validation.

## Self-review and boundaries

- Reviewed legacy admission: `sync/merge.rs` still admits only host records into legacy space handling and its explicit account-kind whitelist excludes Group; adding the enum kind does not expose Group payloads to legacy writers. Unsupported account-kind envelopes remain sealed.
- Reviewed promotion ordering and shared retries: dirty schema-4 metadata remains public/retryable; a failed account push cannot release Group/schema-3 child rows. The marker does not claim to recall an older client's already-in-flight request; UI confirmation remains required.
- Reviewed materialization: Group delete and cross-scope move return schema 2; leave preserves Group structure with schema-3 members under state 4. ID and credential references are preserved or explicitly remapped; no passwords/private key data enter Group/default DTOs or journals.
- Reviewed pin invalidation and opaque authority checks for direct, ancestor, remote and CAS paths. Subtree deletion conservatively refuses any unreadable live Group envelope in the target scope.
- Existing three compile warnings remain: unused `PreparedImport::deselect_key_copy`, `FreshAccountProof::observed_schema`, and `config::edit::set_host_enabled`. No new dependencies, frontend product code, MCP code, relay deployment or release workflow changes.
- This task does not claim frontend rendering, production data migration, real-device credentials, remote-host operation or Beta publication. Those remain controller/integration work.

## Files changed

- `src-tauri/src/lib.rs`
- `src-tauri/src/session/record_directory.rs`
- `src-tauri/src/session/record_directory_tests.rs`
- `src-tauri/src/sync/mod.rs`
- `src-tauri/src/sync/record.rs`
- `src-tauri/src/sync/record_account.rs`
- `src-tauri/src/sync/record_account_tests.rs`
- `src-tauri/src/sync/record_commands.rs`
- `src-tauri/src/sync/record_leave.rs`
- `src-tauri/src/sync/record_leave_tests.rs`
- `src-tauri/src/sync/record_merge.rs`
- `src-tauri/src/sync/record_merge_tests.rs`
- `src-tauri/src/sync/record_migration_tests.rs`
- `src-tauri/src/sync/record_repository.rs`
- `src-tauri/src/sync/record_repository_tests/mod.rs`
- `src-tauri/src/sync/record_rotation.rs`
- `src-tauri/src/sync/record_rotation_tests.rs`
- `src-tauri/src/sync/record_round.rs`
- `src-tauri/src/sync/record_round_tests.rs`
- `src-tauri/src/sync/record_runtime.rs`
- `src-tauri/src/sync/record_runtime_tests/active.rs`
- `src-tauri/src/sync/record_runtime_tests/mod.rs`
- `src-tauri/src/sync/records_v3/importer/resolve.rs`
- `src-tauri/src/sync/records_v3/state.rs`
- `src-tauri/src/sync/records_v3/tests.rs`
- `src-tauri/src/sync/records_v3/types.rs`
- `src-tauri/src/sync/records_v3/validate.rs`
- `src-tauri/src/sync/state_v2.rs`
- `src-tauri/src/sync/record_groups.rs`
- `src-tauri/src/sync/record_groups_tests.rs`

## Task 1 review fix round 1 — Important I1

基準：`2b8ef00f69938c1e902a768d0865bb21c514e2bf`。本輪只處理 review 的同步 effective-route 問題；M1 三個既存 warning 保留。

### 根因與修正

`record_merge::merge_space` 原本從單一 Space 擷取 raw HostPayload，呼叫 `validate_hosts` 判斷關係。這會把被 inheritance 覆蓋的 raw missing jump 當成衝突，也無法發現只有 effective route 才出現的 missing/cycle；同時缺乏其它 scope 的合法 jump target。

- merge 層繼續保留可解碼的關係衝突資料，僅負責傳輸／shape／opaque gate；移除已無正確語意的內部 `TypedMergeOutcome.review_required` 及 `DiagnosticCode::RelationConflict`。
- `record_round::run` 在把 merged section 放入 `latest` 的 candidate state 後，直接呼叫既有 `record_repository::snapshot`，共用 Group resolver 與 effective route readiness。沒有新增繼承或路由算法。
- snapshot 包含 Local 及所有 selected、非 missing Space；只將目前正在同步 Space 的 NeedsReview host 計入該 Space 的 upload gate，保留跨 scope target 上下文。格式 gate 不相容時沿用原本的安全停止流程。
- 正常資料可以送出；effective missing/cycle 則保留已拉回的資料與本地 dirty rows，回傳 `RecordRoundReport.review_required` 並跳過該 Space 上傳，供後續修復。
- 前端/native API DTO 完全不變；只有未序列化的 Rust merge 內部 outcome 移除欄位。原報告的 commands 與 DTO shapes 仍適用。

### RED / GREEN 證據

1. RED（修改測試後、修改實作前）：
   `cargo test --offline --locked --manifest-path src-tauri/Cargo.toml --lib record_round::tests:: -- --nocapture`
   **22 passed / 3 failed / 2449 filtered**。三個失敗分別是 inherited empty route 仍被判 review、effective missing route 未被判 review，以及其它 Space 的 target 被誤判缺失。Log：`/private/tmp/sshelter-task1-fix-round1-red.log`。
2. 初次 GREEN：
   `cargo test --offline --locked --manifest-path src-tauri/Cargo.toml --lib record_round::tests::`
   **25 passed / 0 failed / 2449 filtered**。Log：`/private/tmp/sshelter-task1-fix-round1-green.log`。
3. 完成 rustfmt 後的最終 focused regression：
   - `cargo test --offline --locked --manifest-path src-tauri/Cargo.toml --lib record_merge::tests::` → **31 passed / 0 failed / 2443 filtered**，0.01s；log `/private/tmp/sshelter-task1-fix-round1-merge.log`。
   - `cargo test --offline --locked --manifest-path src-tauri/Cargo.toml --lib record_round::tests::` → **25 passed / 0 failed / 2449 filtered**，0.98s；log `/private/tmp/sshelter-task1-fix-round1-round.log`。
   - 合計 **56 passed / 0 failed**；`git diff --check` 通過。

新增／擴充回歸包含：raw missing jump + nested Group inherited empty jump 成功上傳，第二裝置獨立 join/decrypt 後 raw 值仍保留、effective jump 為空且 Ready；raw 空路由但 inherited missing target 與兩節點 cycle 均 NeedsReview、dirty rows 不上傳；同 snapshot 的另一個 Space 提供 jump target 時兩邊均成功上傳。原有 account-before-child schema gate 失敗／重試斷言仍保留。

### 自審與範圍

本輪 diff 僅四個 owned Rust 檔案：`record_merge.rs`、`record_merge_tests.rs`、`record_round.rs`、`record_round_tests.rs`。已核對 relation validator 呼叫點、outcome 使用者、scope 過濾與錯誤處理；復用完整 snapshot，沒有自行重新實作 inheritance。merge 單元測試的契約調整為保留資料且格式 gate Compatible，實際 review／停止上傳改由 round 回歸驗證。

所有 fixtures 都是 TestDevice、FakeRelay、記憶體 Keychain 與暫存目錄；未使用真實 hosts、credentials、relay。無新依賴、frontend、MCP、release 或 state promotion/backup 變更。依 controller 指示未重跑全 suite；最後整合仍由 controller 驗證。更正：round 1 的實際輸出是四個 warnings，包括新增的 unused `TypedRecord` 與三個既存 warnings（`deselect_key_copy`、`observed_schema`、`set_host_enabled`）；原本誤寫為僅三個。後續 re-review 發現的 R1 同步阻擋退化與 R2 warning 於下方 round 2 處理。

Fix commit：`bcfd05d94d1a7e54e25e8a6466709894c1b08126` — `fix(sync): validate effective routes before space uploads`。提交時持有 `/private/tmp/sshelter-index.lock`，確認 index 原本為空，僅 stage 上列四個路徑。

## Task 1 review fix round 2 — R1 / R2

基準：`bcfd05d94d1a7e54e25e8a6466709894c1b08126`。已逐項讀取正式 `task-1-rereview-round1.md`；本輪只修 R1 的 connection-review 誤作同步 gate，以及 R2 unused import／錯誤 warning 紀錄。

### 修正與自審

新增 `record_repository::scope_requires_relationship_review(state, scope)`，從完整 repository snapshot 取得已解析的 effective payload，再以既有 `group_error`、`ensure_host_authority`、`alias_conflict`、`route_indices` 判斷目前 scope 是否有 Group／authority／關係錯誤。同步 round 使用這個具明確用途的 helper，不再使用彙總 `HostReadiness::NeedsReview`。Group inheritance 與 effective route 演算法仍各自只有原本的中央實作；包含其它 selected scope 的完整 snapshot 仍被保留。

匯入註記本身與 missing key material 都不是這個同步 gate 的條件；有真實 missing/cycle 的路由仍被阻擋，即使它同時帶有匯入註記。連線 readiness 與 directory 檢查完全未修改。helper 依目前 Space 篩選待判定主機，但解析 routes 時看完整 hosts；資料無法建立 snapshot 時仍安全回傳錯誤。未新增序列化欄位或修改 native／frontend DTO。

R2 已移除 `record_merge.rs` 的 `TypedRecord` import。已直接核對原 round1 merge/round logs 的 **4 warnings**，並更正上一節錯誤陳述；本輪最終三個 focused logs 逐一顯示 **3 warnings**，僅剩既存 `deselect_key_copy`、`observed_schema`、`set_host_enabled`，不宣稱 warning-free。

### RED / GREEN 與涵蓋測試

RED（測試新增後、實作修正前）：
`cargo test --offline --locked --manifest-path src-tauri/Cargo.toml --lib import_warning_allows_valid_peer_upload`
→ **0 passed / 2 failed / 2474 filtered**。兩者都在 `assert!(!report.review_required)` 失敗，證明 dirty 與 clean warning row 都會阻擋 peer 更新。Log：`/private/tmp/sshelter-task1-fix-round2-red.log`。

同命令 GREEN → **2 passed / 0 failed / 2474 filtered**。Log：`/private/tmp/sshelter-task1-fix-round2-green.log`。新增測試：

- `dirty_import_warning_allows_valid_peer_upload_but_still_blocks_connection`
- `clean_import_warning_allows_valid_peer_upload_but_still_blocks_connection`

兩者使用 fake-relay encrypted rows，預先放入正常 peer，再透過 repository 更新該 peer；驗證 warning row 的 dirty／clean 前置狀態、dirty rows 收到同步 receipt、Space 無 review gate、warning host 的 effective jump 為空但仍 NeedsReview，並實際呼叫 `RecordDirectory::resolve` 確認回傳 Unsupported 且未進入 material／username／pin callbacks。

最終 focused regression（全部在本輪最終 Rust 改動之後）：

| 命令（共同前綴 `cargo test --offline --locked --manifest-path src-tauri/Cargo.toml --lib`） | 結果 | Log |
| --- | --- | --- |
| `record_round::tests::` | **27 passed / 0 failed / 2449 filtered**，1.00s | `/private/tmp/sshelter-task1-fix-round2-round.log` |
| `record_repository::tests::` | **47 passed / 0 failed / 2429 filtered**，0.00s | `/private/tmp/sshelter-task1-fix-round2-repository.log` |
| `record_merge::tests::` | **31 passed / 0 failed / 2445 filtered**，0.00s | `/private/tmp/sshelter-task1-fix-round2-merge.log` |

合計 **105 passed / 0 failed**。保留並通過原回歸：`group_schema_gate_and_inherited_empty_route_upload_and_resolve_on_peer`、`effective_missing_and_cyclic_routes_require_review_and_preserve_dirty_rows`、`route_review_uses_targets_from_other_scopes_in_the_candidate_snapshot`、`remote_relationship_conflict_is_cached_for_review_and_dirty_hosts_are_not_pushed`。`git diff --check` 通過。未重跑 broad／完整 suite，依 controller 指示留待最後整合驗證。

### 變更範圍與限制

四個 owned 檔案：`record_merge.rs`、`record_repository.rs`、`record_round.rs`、`record_round_tests.rs`。沒有 frontend、MCP、schema promotion、release workflow 或依賴變更；沒有真實 hosts、credentials、relay 操作，所有資料均為既有 TestDevice／FakeRelay／暫存 fixture。未發現本輪剩餘阻擋問題；完整 integration 與 Beta gate 仍由 controller 執行。

Round 2 commit：`f6bcf98edc56f3b99591649330dc9175e7dc1464` — `fix(sync): separate upload review from connection warnings`。提交全程持有 `/private/tmp/sshelter-index.lock`，確認原 index 為空，僅 stage 上列四個 scoped 路徑。
