# Account Migration Implementation Ledger

## Verified contracts and rulings

- Binding source: migration design sections 6, 7.1 and 7.3; active-runtime plan. Ownership is new record_migration API/source/publication/tests and this plan/ledger only. No legacy writers, common state, native/UI, account/round, leave or rotation files changed here.
- Ordinary schema2 Join remains a zero-write NeedsMigration refusal. Dedicated prepare accepts optional entered words in Zeroizing memory; explicit old-client stopped/compatible consent plus fresh source digest is required before journal, credential staging or network mutation. New/pending Records device sources use authenticated relay state and existing Local metadata, with no implicit external config/pin/password import.
- Caller-owned lifecycle -> vault -> format_publication locks surround migration. External file/credential/network work occurs outside Core. Root runtime commit_migration_candidate takes Doc -> Core, saves before activation and rejects stale/blocked/active Legacy. Legacy must be explicitly paused. Profile try_lock excludes simultaneous processes; redirected working paths fail preflight.
- Verified relay/src/index.ts capacity is 4096 retained+new rows, 1048576 aggregate ciphertext+nonce bytes, 65536 ciphertext bytes per row and 1048576 push body. Client batches are additionally limited to 200. Account gate replacement footprint is reserved before journaling or credentials.
- Full authenticated seq0 account and selected-space baselines validate envelope identity, known public/secret versions, decryption, sequence completeness and space encryption identity. Future or invalid primary/account formats and rotation refuse before mutation. Schema1 alias rows remain encrypted sources; stable typed host IDs preserve existing schema2 edits, tombstones and pins. Late old-source changes retain review ciphertext and pause. Accepted typed rows missing from the final baseline block activation.
- Original state bytes are captured read-only before confirmation and backed up exactly; absence remains absent in the original receipt. Unsaved Doc text is protected separately with source/digests, and managed disk edits become Local review copies without overwriting shared hosts or source files. Pin and alias password copy needs unique hostname/port correspondence. Credential destination accepts absent/same only; original password accounts and code are never deleted.
- read_vault is used throughout. Every existing encrypted entry is validated, identical original/working encrypted snapshots are retained, and migration never publishes a staged vault over the live file or changes the master. Resume validates the latest vault and preserves later Local material/settings. Metadata rebase keeps later Local additions/edits/deletions; atomic LocalImportReceipt protects retries after a lost separate journal receipt.
- Journal version1 contains public IDs, fixed candidate metadata, ciphertext, digests, static diagnostics, credential status and per-batch/file receipts. It contains no words, password, passphrase or private-key plaintext. All working files are atomic0600. Network/files are separately resumable, with no multi-file atomic claim. Rate-limit backoff persists. Missing scoped credential can resume through resume_with_code; no original words are overwritten.
- v1 converts directly with bounded readonly decoding; it never invokes the mutable legacy upgrader or removes the original chain. Unjoined paused Legacy converts to Local without sync-code credential access or relay. Existing schema3 second-device baselines preserve native edits/tombstones/pins instead of reapplying old templates.

## TDD evidence

All fixtures use temporary files, MemKeychain and FakeRelay. No real SSH home, OS credential, relay, app launch, push or merge was used. Failed fixture setup was corrected before behavioral RED receipts were counted.

| Scope | Observed RED | GREEN log |
| --- | --- | --- |
| Initial readonly/consent/schema/typed preservation | 5 failed, 1 passed | /private/tmp/sshelter-record-migration-initial-green.log (6 passed) |
| Durable recovery, late old sources, atomic receipt | 2 failed, 10 passed | /private/tmp/sshelter-record-migration-recovery-green.log (12 passed) |
| Pins/passwords/unsaved documents | 3 failed, 15 passed | /private/tmp/sshelter-record-migration-preservation-green.log (18 passed) |
| Local-only/pending Join/known secret versions/late files | 3 failed, 21 passed | /private/tmp/sshelter-record-migration-completeness-green.log (24 passed) |
| Gate footprint, final row completeness, supplied-code retry | 3 failed, 27 passed | Included in final 32 GREEN |
| Actual primary future format and changed space identity | 5 failed, 27 passed with prior publication REDs | /private/tmp/sshelter-record-migration-final-green.log (32 passed) |
| Managed disk edit/new device implicit source/latest vault additions | 3 failed | /private/tmp/sshelter-record-migration-source-boundary-green.log (3 passed); /private/tmp/sshelter-record-migration-all-green.log (35 passed) |
| Concurrent Records Local host deletion | 1 failed | /private/tmp/sshelter-record-migration-final-formal-green.log (36 passed) |

Focused commands use CARGO_TARGET_DIR=/Users/ysya/project/sideproj/sshelter/src-tauri/target cargo test --offline --locked --lib sync::record_migration. Scratch harness sources were copied to /private/tmp/sshelter-migration-harness to keep unfinished code outside registration. Actual registered worktree first passed 35 tests in /private/tmp/sshelter-record-migration-formal-green.log; final registered worktree passed 36 tests in /private/tmp/sshelter-record-migration-final-formal-green.log after the deletion fix (0 failed, 2355 filtered out). No subsequent Rust source changes were made before commit.

## Integration handoff and cost

Root owns public native wrappers/preview cache, explicit pause/resume UI, pending migration guard on legacy resume and account-affecting operations, and Agent cache/status wake. Runtime commit contract is used without an outer Doc lock. Compatibility owner retains ordinary join/round/leave/rotation, and was notified that publishing a legacy Own schema1 keyslot requires an explicit same-ID upgrade CAS from its retained opaque row rather than duplicate records/sealed metadata. Existing legacy Vault material maps to the same Local key ID; schema1 Synced metadata upgrades to schema2 during migration.

Cost decision: one journal module split into readonly source and durable publication; reuse importer, typed merge, readonly vault, existing crypto/atomic writers and root runtime activation. Verification stayed focused after meaningful changes; root owns complete integration/platform checks. No live account/device cutover is asserted.
