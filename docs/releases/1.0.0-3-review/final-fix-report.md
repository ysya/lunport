# Final findings fix wave: I1 / M1 / M2

Base/source before this wave: `5eb8b7f0c9094c34c9c47ac0a8819d9e1bfd2350`, branch `codex/groups-mcp-beta3`. Final source commit is appended after the guarded exact-manifest commit. One wave; no subagents, full suite, UI/native app launch, CI, push, merge, publication, real credentials, real hosts, real grants, Production or relay changes by this worker. Root owns mounted QA and remaining integration gates.

## Verified implementation decisions

- I1: `record_commands::overview_from` computes `group_deletion_token` from the **same repository snapshot** that produces its Groups/hosts. SHA-256 hashes a versioned public projection containing every visible Group record (ID/scope/parent/defaults/revision/diagnostics) plus every host (ID/scope/raw payload/revision/effective payload/provenance/group diagnostics). All outside ancestors and affected membership dependencies are included. No secret store, private key bytes, process-local generation or persisted schema change enters this contract.
- `delete_group` retains root revision CAS, computes the snapshot and compares the submitted review token **before any candidate cloning/materialization/tombstone**. The native `edit` wrapper already holds lifecycle and reruns the transform inside `mutate_records` against the actual current state after account gating; the same frozen token is checked again there. Missing/empty/stale tokens fail closed. Existing unreadable-authority checks remain intact.
- Conservative cost: unrelated visible Group/host edits also expire a review. Sync bookkeeping alone (last_sync_ms) does not. This avoids ordinary sync refreshing the dialog forever, while binding all materialization inputs. Full public projection hashing adds work proportional to the visible records at overview generation/deletion.
- Frozen frontend candidate now carries the token alongside root ID/revision and counts. Opening a dialog uses `overview.group_deletion_token`; submitting passes that original token, never the refreshed overview's token. On error the dialog closes, a records-status refresh is attempted, and a dedicated deletion-area alert asks for review again. No retry or silent reapproval. Missing overview token disables deletion with visible refresh guidance. Root's mounted feedback removed a duplicate form-level copy of the deletion error.
- M1: open the file and apply `Read::take(32 MiB + 1)` before reading; reject the sentinel extra byte. No metadata-only precheck/TOCTOU. Existing corrupt/partial-tail/error handling is unchanged.
- M2: latest ten **stateless** audit rows use a view key from the serialized public event plus occurrence number. Distinct historical events sharing process-local IDs remain distinct; even identical events/timestamps/IDs get unique sibling keys. Existing events retain keys when a different event is prepended. No audit persistence/transport identity migration.
- M3 explicitly deferred as directed: no broad concurrency formatting or CLI refactor. Existing Rust dead-code warnings and Vite chunk advisory remain, with no warning-free claim.

## Exact interface changes

- Rust `RecordOverview.group_deletion_token: String`; matching required manual TypeScript `RecordOverview.group_deletion_token: string`.
- Rust command `records_group_delete(app, id, revision, snapshot_token: Option<String>)`; optional input exists only to give old/missing-token calls a deliberate fail-closed repository error. Tauri JS argument is `snapshotToken`.
- Repository `delete_group(state, id, expected_revision, reviewed_snapshot: Option<&str>, now)` and `deletion_snapshot_token(&RepositorySnapshot)`.
- `GroupDeletionCandidate.snapshotToken: string`; `beginGroupDeletion(state, counts, snapshotToken)`; `deleteRecordGroup(id, revision, snapshotToken)`.
- No generated binding uses these manual overview/command interfaces; no generated binding changes required. Existing shared Group rotation fixture now obtains/passes a fresh review token.

## RED evidence

All log paths below are under `/private/tmp/`.

- `sshelter-final-fix-i1-red.log`: original root-only deletion accepted a changed descendant while root revision was unchanged. 1 failed, 2550 filtered, cargo exit 101. New test initially exercised original four-argument implementation; after observing failure it was adapted to submit the reviewed token.
- `sshelter-final-fix-m1-red.log`: extracted original unbounded reader consumed 34 MiB (35,651,584 bytes), expected 32 MiB + 1 (33,554,433). 1 failed, 2550 filtered, cargo exit 101. Extraction preserved original behavior before the bounded implementation.
- `sshelter-final-fix-m2-red.log`: original entry.id identity failed both historical-duplicate uniqueness and new-event prepend identity assertions. 2 failed. Initial shell wrapper returned tail's exit 0; the child Vitest exit was not separately captured, so only its explicit failed-test result is claimed.
- `sshelter-final-fix-missing-token-ui-red.log`: missing-token UI lacked recovery text. 1 failed / 21 passed, Vitest exit 1; adding visible guidance then passed.

## Final focused GREEN evidence

- `cargo test --offline --locked --manifest-path src-tauri/Cargo.toml --lib group_` -> **25 passed**, 0 failed, 2529 filtered, 1.33s, exit 0. `sshelter-final-fix-groups-green.log`. Includes Group codec/inheritance/round/leave/rotation and MCP/deploy inherited target tests. New deletion matrix covers root revision, new descendant, moved-in descendant, changed descendant defaults, moved-out descendant, host join, host leave, host settings, and an ancestor outside the deleted subtree. All eight non-root cases assert root revision stayed unchanged; all reject without modifying original state or creating tombstones. Fresh explicit review succeeds, preserves effective host fields, detaches affected hosts, and leaves unaffected host payloads unchanged. Missing/empty token tests fail closed; existing credential-reference materialization regression retained.
- `cargo test --offline --locked --manifest-path src-tauri/Cargo.toml --lib audit_` -> **7 passed**, 0 failed, 2547 filtered, 0.10s, exit 0 outside sandbox. `sshelter-final-fix-audit-unsandboxed-green.log`. New tests verify exact bounded reader consumption and oversized actual open-file rejection. Existing restart/cap/partial-tail/failure/no-output/no-auth tests pass.
- The first audit run was **6 passed / 1 failed**, exit 101 in `sshelter-final-fix-audit-green.log`: existing `session::broker::tests::connect_audit_preserves_exit_status_without_terminal_output` hit `PermissionDenied/Operation not permitted` binding a temporary Unix socket at broker.rs:938. Source confirmed FakeEngine/MemKeychain and disposable `/tmp` socket, so the same focused seven-test command was rerun with tool-approved escalation and passed. No real credentials or remote host was used.
- `npm test -- src/components/records/group-review-fixes.test.ts src/components/records/groups.test.tsx src/components/McpPane.test.tsx src/components/records/settings-boundary.test.tsx src/lib/mcp-audit-rows.test.ts src/lib/records.test.ts` -> **6 files / 49 tests passed**, 0 failed, 549ms, exit 0, `sshelter-final-fix-frontend-final.log`. Includes final error-presentation change and missing-token recovery.
- `npx tsc --noEmit` -> exit 0, `sshelter-final-fix-tsc.log`.
- `git diff --check` -> exit 0 before commit.
- Earlier focused 4-deletion-test GREEN and 31-test FE GREEN remain in their logs; final broader affected checks above supersede them. An intermediate Rust compile found the old four-argument rotation-test call and was corrected before final checks.
- Rust final checks report the same 3 dead-code warnings (`record_import::deselect_key_copy`, `FreshAccountProof.observed_schema`, `config::edit::set_host_enabled`). No full Rust/FE, Vite, Development bundle or native CI was run by this worker. Prior 15 production warnings/Vite chunk advisory and all final-review Declined to judge limits remain for Root integration receipt.

## Exact owned product manifest (15 files)

1. `src-tauri/src/mcp.rs`
2. `src-tauri/src/mcp/deployment_audit_tests.rs`
3. `src-tauri/src/sync/record_commands.rs`
4. `src-tauri/src/sync/record_groups.rs`
5. `src-tauri/src/sync/record_groups_tests.rs`
6. `src-tauri/src/sync/record_rotation_tests.rs`
7. `src/components/SettingsDialog.tsx`
8. `src/components/records/GroupEditor.tsx`
9. `src/components/records/fixtures.ts`
10. `src/components/records/group-editor.ts`
11. `src/components/records/group-review-fixes.test.ts`
12. `src/components/records/groups.test.tsx`
13. `src/lib/records.ts`
14. `src/lib/mcp-audit-rows.ts`
15. `src/lib/mcp-audit-rows.test.ts`

Root's release docs/evidence and ignored ledger/harness were preserved and excluded. This report is ignored task evidence, not product content. Commit is guarded by `fcntl.flock('/private/tmp/sshelter-index.lock')`, expected HEAD, expected branch, empty index, and exact staged-manifest comparison.

Final source commit: `30c4a4c689b86a95bb17b8cc4fae90bb3469b686`. Guarded commit succeeded; exact 15-file manifest, index empty.
