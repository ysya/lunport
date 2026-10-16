# Local Record Key Publication Plan

Standing authorization: implement local key import/generation after the confirmed file-import journal foundation. This task owns new record_keys.rs/tests, a narrow extension to the owned record_import journal engine, and this plan/ledger. Root owns module registration and native/UI integration; other agents own account/sync/runtime.

**Goal:** Explicit native key import/generation and synced download activation create schema2 LocalKeyMetadata and encrypted vault material with recoverable separate vault/state publication. No legacy slots/config writers or implicit relay upload.

**Interfaces:** import_local(env, name, Zeroizing<String>, EntryOrigin) -> LocalKeyReceipt { import_id, key_id, public }; generate_local(env, name, KeyAlgorithm, comment, Option<Zeroizing<String>>) -> LocalKeyReceipt. activate_synced(env, key_id, public, Zeroizing<String>) -> LocalKeyReceipt requires caller-held lifecycle and takes only vault -> publication. Root's existing pending_imports/resume exposes recovery IDs.

**Architecture:** Validate supported bounded OpenSSH material and derive metadata from its private/public/encrypted identity. Move the input into VaultEntry, whose Drop zeroizes it. Extend the existing public journal with an explicit material source kind and private-byte digest, never private text. New material is sealed into the existing staged vault using migration-scoped master credentials; the shared engine then promotes absent/same, publishes vault, rebases Local metadata against the latest state and atomically saves an import receipt with state. A retry reads only already-staged encrypted material, never a virtual source path. Before material was durably staged, failure is explicit and requires the caller to provide it again; no successful key creation is claimed.

## Constraints and costs

- Source input capped at 1 MiB; key name uses existing public key-name validation. No passphrase is persisted separately or in public metadata.
- Existing vault entries, settings, account and Local metadata remain intact. Every stage and destination passes the existing profile boundary before mutations.
- Native import is always Local. Generated keys use the existing in-memory generator. No OS credential store in tests, real home/config, relay, app launch, push or merge.
- Lifecycle -> vault -> format_publication -> brief core snapshot; private parsing/credentials/source reads occur outside core. Strict candidate save precedes memory/generation.
- Separate atomic files, retained receipts/original bytes/scoped credentials and exact stable IDs; no multi-file atomic or destructive rollback claim.
- Matching atomic import receipts preserve subsequent rename/removal. A conflicting key ID or changed material refuses recoverably.

## Focused TDD

- [x] RED/GREEN bounded supported import, metadata/private identity, invalid names/material, secret hygiene.
- [x] RED/GREEN local generation and no account/relay changes.
- [x] RED/GREEN vault -> state failure and exact resume from encrypted stage, including partial-stage receipt interruptions.
- [x] RED/GREEN concurrent unrelated key metadata preserved, original vault/settings/master retained, deletion/rename after receipt crash.
- [x] Scratch GREEN, root registration, focused real-crate tests for both key and file imports, exact-path conventional commit under the shared index lock.

## Synced activation extension

The explicit downloader supplies fresh persisted authoritative account metadata and private input. Journal stores the public keyslot Record/chain and expected local material. It writes to a fresh vault ID, while state keeps the account key ID. Final overlay CAS compares chain, public record revision/payload and captured local metadata; it preserves independent seq/dirty transport receipts. Conflict/Deleted/blocked account gates and mismatched public/private/fingerprint/encryption identity refuse. Old encrypted entries, master accounts, files and passphrase credentials are retained.
