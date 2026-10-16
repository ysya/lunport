# Confirmed Local File Import Plan

Standing authorization: implement the approved phase 1c design using temporary files and memory credentials only. This task owns only the new record_import module, its tests and this plan/ledger.

**Goal:** Explicitly confirmed file previews become Local v3 hosts and selected copied keys through a resumable public journal. No relay operations or source deletion.

**Architecture:** prepare and explicit key selection remain read-only in memory. Confirm holds lifecycle -> vault -> format_publication, re-previews with the exact ID mapping and source digest, and saves a bounded metadata-only journal before staging. Staging retains original state/vault bytes, validates all existing vault entries with the truly read-only reader, then adds selected copies to an encrypted staged vault. New master credentials are confined to migration:<id>:<recognized vault account> until absent/same promotion. Publication uses separate 0600 atomic vault and state writes. State commit rebases the public overlay against the latest generation, saves before memory publication, and preserves already-applied edits/tombstones on retry.

**Interfaces:** prepare(source, options) -> PreparedImport; select_key_copy(prepared, key_id) records public consent exposed by selected_copies; confirm(env, prepared) -> ImportReceipt; resume(env, id) -> ImportReceipt; pending_imports(env) -> Result<Vec<PendingImport>, AppError>. Runtime snapshot/commit_candidate take only core, so imports may own the outer locks without reentry. Root owns registration and native/UI integration.

## Rulings and costs

- File provenance must be absolute; relay virtual paths are refused before any file read. Confirmation uses fresh importer resolution and stable host/key IDs.
- Do not serialize the full explicit env map. Journal keeps resolved provenance, source/options digests and public ID mappings; after interruption only the previously confirmed bounded sources and selections may be staged.
- The journal and receipts contain public host/key metadata and consent, never private text, passphrase or master credentials. Read selected private files into Zeroizing buffers, cap at 1 MiB, and validate supported OpenSSH material/public identity.
- Keep all original bytes and credential accounts. Stage byte copies preserve existing entries/settings; all existing entries must decrypt before the mutable stage loader opens them. A differing credential under a promotion account is a recoverable refusal.
- No multi-file atomic claim. Vault publication can succeed while state save fails; journal mappings and encrypted copies remain for retry. LocalImportReceipt is persisted in the same state candidate as the entire overlay. Journal completion receipts are updated afterward; retry never infers ownership from host payload/version, so later edits, moves and removals remain intact.
- Concurrent changes require a fresh state overlay, exact-generation candidate commit and bounded retry; ID/alias/material collisions refuse without replacing newer state.

## Focused TDD

- [x] RED/GREEN: cancellation/empty key selections, stable source digest, virtual provenance refusal.
- [x] RED/GREEN: selected-copy source preservation, changed private source, metadata/secret hygiene.
- [x] RED/GREEN: corrupt/keyless original vault preservation, existing entries/settings/master preservation.
- [x] RED/GREEN: new-master promotion failure/collision, per-file interruption/retry, failed state save preserving core/generation.
- [x] RED/GREEN: concurrent edits, alias/ID collision and completed edit/tombstone preservation.
- [x] Run scratch harness before root registration, then focused real module tests; commit exact paths under the shared index lock.
