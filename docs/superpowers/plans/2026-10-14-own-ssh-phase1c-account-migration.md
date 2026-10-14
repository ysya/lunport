# Confirmed Account Migration Plan

Standing authorization: implement phase1c specification section 7 with isolated fixtures. Ownership: new record_migration module/tests and this plan/ledger. Root owns native/UI/runtime mode activation; compatibility worker owns ordinary account/round/leave/rotation. Preserve their changes.

Goal: read-only memory preview, explicit old-client compatibility consent, full seq0 source confirmation, public/ciphertext journal, protected original backups, schema3 account gate, bounded resumable network batches, then save-before-runtime activation. Both paused Legacy v1/v2 and records pending/new Join source identities are supported. Original SSH configuration, alias-keyed relay rows, vault/master and host password accounts remain intact.

Interfaces: prepare(env, entered_code: Option<Zeroizing<String>>) -> PreparedMigration; preview(&self) -> &MigrationPreview; confirm(env, prepared, MigrationConsent { old_clients_stopped_or_compatible }) -> MigrationReceipt; resume(env,id); resume_with_code(env,id,Zeroizing<String>); pending_migrations(env). Public DTOs expose only digests, counts, IDs, phase and static review codes. Native caches PreparedMigration in bounded memory.

Architecture: acquire lifecycle -> vault -> format_publication -> brief core snapshots; process-wide profile migration file lock; all filesystem/source/credential work outside core. Fresh authenticated seq0 account and selected-space pulls are mandatory. Legacy source rows retain ciphertext; typed records already present win over initial conversion, including tombstones and pins. Dirty legacy/config edits become retained local review copies. Managed disk entries are compared with retained legacy templates from the same bounded read-only preview. Records device migration imports no external configuration or old pin/password sources implicitly. Confirmation rehashes source and documents before mutation. Persist fixed IDs/candidate/outgoing encrypted items and protected original bytes before credential writes. Capacity counts original plus candidate rows at 4096 and 1MiB per chain, 65536 ciphertext per row, 200 items and 1MiB push body. Every accepted batch receipt is saved before the next network mutation. Retry fresh-pulls recover lost remote receipts without overwriting existing typed rows.

Vault is validated with read_vault and copied as identical encrypted bytes to protected working/original snapshots; existing usable legacy Vault slots gain public Local metadata. Migration never replaces the live vault. Resume validates the latest vault read-only and preserves later Local material/settings and metadata. No external private file is read or copied without separate explicit copy consent. Alias passwords use migration-scoped staging and absent/same final destination; old accounts are retained. Pins apply only when a unique alias mapping proves the same hostname/port. Unsupported/missing material and uncertain pin/password correspondence retain sources and public diagnostics.

Activation is separate atomic per-file publication, retaining journal and originals. Runtime saves validated state before one memory/mode switch. Root-owned runtime activation acquires Doc -> Core internally, saves first and clears the opposing legacy state/Doc; native wrappers clear Agent caches afterward. Concurrent Records Local CRUD rebases on the latest Local state, including deletions; atomic import receipts prevent completed retries from overwriting user edits. Account marker Active is the completion gate; interrupted publishing resumes, never downgrades schema. A newer/invalid format, rotation, incomplete pull, decryption/source conflict, changed legacy source or insufficient capacity refuses recoverably.

## TDD sequence

- [x] RED/GREEN read-only/cancel and explicit old-client consent, stale source, full seq0 and schema4 refusal.
- [x] RED/GREEN deterministic mapping, existing typed edits/tombstones/pins, old rows and configuration preserved, dirty local review copies.
- [x] RED/GREEN capacity rows/bytes/item/body limits before account gate.
- [x] RED/GREEN journal-first, scoped code/password, credential denial, exact backups and no plaintext state/journal/debug.
- [x] RED/GREEN each network/file interruption and lost receipt, 429/5xx retry, state save failure with unchanged core/generation.
- [x] RED/GREEN Legacy v1/v2 and new/pending Join, simultaneous-device conversion and late old-source differences.
- [x] Formal focused verification (36 passed), exact-path conventional commit under advisory index lock.

Cost ruling: reuse importer, public typed merge, readonly vault and existing outer locks; one migration journal module. No destructive cleanup, live relay/OS credentials, app launch, push/merge, or unrelated refactor. Device cutover remains outside local fixture verification.
