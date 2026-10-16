# Confirmed Local Import Ledger

## Scope and contracts

This task owns record_import.rs, record_import_tests.rs and its plan/ledger only. Root owns registration, LocalState.import_receipts and native/UI integration; runtime worker owns core persistence. No real home, credentials, relay, application launch, push or merge was used.

Implemented prepare/select/confirm/resume/pending_imports. Preview and explicitly selected key inspection stay in memory. Default selections are empty. Confirmation re-previews actual bounded provenance with the original host/key IDs and source digest before creating a journal. Every destination is checked before any directory/credential/file mutation. Runtime write-block and generation exhaustion also refuse before journaling.

The journal contains resolved source provenance, mappings, copy consent, public metadata and digests. Full env values stay in memory; only their digest is saved. Selected private sources use bounded regular-file reads (1 MiB including a growth check), Zeroizing buffers, supported OpenSSH parsing and public/private/passphrase identity validation. Sources are never renamed, removed or chmodded.

Under lifecycle -> vault -> format_publication, staging retains original state/vault bytes. All original and partial-stage entries decrypt through read_vault before Vault::open can operate on the stage. Existing ciphertext entries/settings/master accounts are retained. New master writes are scoped to migration:<id>:<recognized vault account>; public master receipts are durable before credential writes. Promotion accepts absent/same destinations, verifies readback and retains staged credentials. No delete method can cross the scoped adapter.

Vault and state publish separately using 0600 atomic writes. Candidate state is saved separately in the stage before its main commit. Exact-generation commit retries rebuild a public overlay against the latest snapshot, preserving unrelated Host CRUD and metadata. Root's public LocalImportReceipt is atomically saved with the entire overlay; journal completion is later. Matching receipts preserve edits, reviewed provenance, tombstones, moves and removed keys. Without a receipt, even identical existing IDs are collisions.

## Observed RED and fixes

- Initial API RED: 7 expected missing-feature failures / 1 virtual-source pass. /private/tmp/sshelter-local-import-red.log.
- Partial stage receipt interruption could adopt a newer original vault while retaining an older stage, losing a newer entry. Observed RED /private/tmp/sshelter-local-import-partial-stage-red.log. Fixed by persisting originals_captured plus the exact baseline digest before any stage writer/backup; changed originals now refuse recoverably.
- Published material removed before state activation could leave invalid local metadata. Observed RED /private/tmp/sshelter-local-import-published-material-red.log. Fixed by read-only material/digest/public/passphrase checks before state publication; completed atomic receipts intentionally preserve later deletions.
- Atomic receipt/write-block/identical-ID/pending discovery regressions: pre-fix scratch 18 passed, 5 expected failures. /private/tmp/sshelter-local-import-receipt-gate-red.log. Replaced record-content ownership guesses with state receipts, gated writes early, and added bounded recovery discovery.
- Shared source copying briefly caught incomplete concurrent field/import edits; no other owner's files were changed. The final harness copied the current shared types and ran the actual implementations.

## Verification

Scratch focused import suite: 25/25 GREEN, /private/tmp/sshelter-local-import-25-green.log. It covers cancellation, stale config/key digests, unsupported/oversized material, empty-copy credential silence, original vault errors/settings/master, promotion failure/conflict, seven per-step interruptions, failed main state save preserving memory/generation, generation race plus actual unrelated Host creation, receipt crash then edits/tombstones/key deletion, exact alias/ID conflicts, public pending discovery and scoped profile destinations.

Root registered the module; real-crate focused suite 25/25 GREEN, /private/tmp/sshelter-local-import-real-green.log. Baseline shared warnings only. No full suite is run here; root owns integration and platform checks.

## Rulings, limits and costs

- After a fully staged snapshot, resume uses that exact confirmed snapshot, never adds newly discovered sources. Before staging, only the previously confirmed resolved files/selections may be read and must retain their canonical identities/digests.
- A changed baseline vault or conflicting promotion account is retained for recovery and refused; no destructive rollback or overwrite is attempted.
- A failed state publication may leave extra encrypted vault entries and promoted staged credentials; the durable journal, exact IDs and retained originals allow retry. This is not a multi-file atomic transaction.
- Recovery discovery reads no credentials/private sources and emits only import_id/phase/counts. Individual journal cap 8 MiB, aggregate scan cap 1024 entries/16 MiB; corrupt/oversized journals remain visible as invalid, and scan/I/O errors are explicit.
- Journals, stage snapshots, original backups and master receipts are retained. This increases local disk and credential usage; cleanup requires a later explicit policy rather than deleting recoverable material here.
- Existing Vault serialization has its documented temporary plaintext serde copies; this task retains its Zeroizing entry lifetime and never exposes plaintext through journal/state/debug/error output.
- Local file import never joins, gates or pushes a relay account. Legacy account migration is a separately assigned later operation.
