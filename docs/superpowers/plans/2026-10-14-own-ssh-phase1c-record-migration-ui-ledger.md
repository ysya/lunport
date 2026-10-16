# Records Migration UI Ledger

Pre-flight: inspected current WorkspaceGate/App, component-only account words, exact native MigrationPreview/Receipt/Pending DTO structs and schema2 join gate error. Native migration is currently scaffolded, not exercised by frontend tests.

Ruling: failed join offers an older-account preview option without parsing error strings or claiming the account's schema. The native preview is authoritative. Keep code only in parent/child component memory; clear both after successful preview/cancel.

Ruling: token/preview/code never enter QueryClient; only native public status and pending metadata do. Cancel prior status queries before applying a migration status result, so a paused-Legacy reply cannot undo activation. Existing higher Records generation wins; completed Records mode is not downgraded by a late incomplete Legacy receipt.

Ruling: no confirm before can_confirm plus explicit old-clients-stopped-or-compatible consent. Partial receipt is pending, not success; resume the stored migration ID without creating a new operation or parsing it from an error.

Root ruling: active Legacy migration needs explicit records_pause_legacy()->RecordStatus after saved-edits acknowledgment. Preview prepare is read-only and rejects an unpaused Legacy runtime. Added callback/overlay seam and direct pause status publication, with a deferred pre-pause status response regression.

Preview teardown and late preview completion call only records_migration_cancel(token), which drops the native memory cache. Failed confirm keeps review but marks the token consumed; recovery uses public pending IDs. Codes clear on successful preview/cancel/exit, never QueryClient or storage. Partial outcome is shown as pending and does not claim rollback.

Compatibility worker confirms leave/rotation were not GREEN yet; no guessed command/component success added. Root supplied their proposed DTO for a later owned follow-up.

Final verification: focused73/73; full61files/926tests; tsc and Vite production build GREEN. Logs /private/tmp/sshelter-records-migration-{ui-final-focused,full-vitest-final,build-final}.log. Existing large-bundle advisory remains. No actual migration/credential/relay calls executed by this worker; root owns isolated native smoke and broader Rust gates. Exact frontend+App+plan ownership only.
