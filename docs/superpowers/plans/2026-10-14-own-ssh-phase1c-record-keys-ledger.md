# Record Key Publication Ledger

## Implemented and coordinated

Owned files: new record_keys.rs/tests; narrow extension to owned record_import.rs/tests; record-keys plan/ledger. Root registers native modules and commands; compatibility worker owns record_account::download_key and its fresh-pull integration. No other agent's edits were reverted.

Public import_local(env,name,Zeroizing<String>,EntryOrigin) and generate_local(env,name,KeyAlgorithm,comment,Option<Zeroizing<String>>) return LocalKeyReceipt { import_id,key_id,public }. These are always Local and never add outgoing relay records. Source is capped at 1 MiB, names validated, supported OpenSSH private/public/fingerprint/encryption identity derived and verified. The input moves into VaultEntry's zeroizing lifetime only after all fallible public-data extraction.

Shared journal engine supports Files/Material/Synced source kinds with a metadata-only digest. Memory and download provenance are virtual and never opened as files. Material retries decrypt only already-staged encrypted entries. First stage/metadata failure before durable encryption explicitly requires input again and never claims successful key creation. Existing public options/mappings, profile guards, baseline-vault digest, original byte copies, scoped master receipts and absent/same promotion remain intact.

activate_synced(env,key_id,public,Zeroizing<String>) returns the same receipt and requires caller-held lifecycle. It takes only vault -> format_publication, reads no files or credentials while core is held, and preserves the authoritative account ID while assigning a new vault ID. The journal stores public chain/keyslot Record and expected LocalKeyMetadata. Final public overlay CAS compares chain and full Record revision/payload plus captured local metadata; seq/dirty transport acknowledgments are deliberately excluded and latest values survive. Conflict/Deleted/shared gates and wrong private/public/passphrase identity refuse; no old encrypted entry, file, original master or passphrase account is deleted/overwritten.

Atomic LocalImportReceipt is written with state. It is checked before every stage step on retry, so a lost/stale journal phase cannot revive removed materials or reread unavailable sources after a completed import. User key renames/removals and unrelated concurrent metadata are retained. Separate vault/state publication remains resumable, not multi-file atomic.

## TDD receipts

- Initial key API RED: 1 pass / 2 expected missing-feature failures. /private/tmp/sshelter-record-keys-red.log.
- Synced activation RED: 9 pass / 2 expected activation/stage failures. /private/tmp/sshelter-record-keys-synced-red.log.
- Lost separate journal phase RED: source was reread after the state receipt had already committed; unavailable source caused refusal. /private/tmp/sshelter-record-keys-lost-phase-red.log. Fixed by checking the atomic state receipt before any staging/private-source read.
- Scratch keys initial 3/3, then 11/11 and 14/14 GREEN. /private/tmp/sshelter-record-keys-initial-green.log, /private/tmp/sshelter-record-keys-green.log, /private/tmp/sshelter-record-keys-14-green.log.
- Formal registered real-crate keys 16/16 GREEN: /private/tmp/sshelter-record-keys-real-green.log.
- Formal file import regression 26/26 GREEN: /private/tmp/sshelter-record-keys-import-real-green.log. Scratch prior 25/25 /private/tmp/sshelter-record-keys-import-regression-green.log.
- Coverage: supported/encrypted/local generation/private hygiene; invalid names/material/caps; six durable-step retries for local and synced sources; failed main state save preserving core/generation; exact account ID/new vault ID resume; original/coherent/conflicting material retention; latest authority/local CAS; concurrent independent local key rename; independent transport receipts; post-completion rename/removal; gates/tombstones; lost journal phase with unavailable source.
- Root/compatibility owns downloader end-to-end tests and full library/platform CI. No full suite, real credentials, relay, app launch, push or merge was run here.

## Rulings and costs

- Incoming Conflict material requires later explicit replacement/review; this activation API refuses it. A coherent explicit copy may point to a new vault ID while retaining every old encrypted entry/reference.
- Newly generated or supplied private input is not claimed durable until it reaches the encrypted stage. If failure happens earlier, the journal stays public and requires re-supplied input; no old data changes.
- On state save failure, encrypted entries/promoted credentials may already exist, but exact mappings, source/authority receipts and retained originals permit retry. Changed baselines/authority/local metadata refuse recoverably instead of overwriting newer data.
- Original plaintext source files are never touched; virtual sources never reach a file reader. Journals/state/debug/errors contain public metadata/digests, not private text or separate passphrase values.
- Stage/original/master receipts are retained until a later approved cleanup policy. Existing documented serde temporary copies remain a limitation; private source buffers/entries/passphrases use Zeroizing/zeroizing Drop.
