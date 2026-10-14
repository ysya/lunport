# Own SSH Phase 1c-1 Record Primitives Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Provide pure typed schema 2 host/keyslot records, deterministic migration IDs, and a version 3 state contract without changing the live runtime owner or writing user data.

**Architecture:** Preserve Record/LocalRecord/Envelope and their existing LWW transport. New typed payloads and validators live in sync/records_v3; the version 3 structure remains passive data until SyncCore is switched by a later plan. Validation separates persisted missing-key hosts from hosts ready to connect.

**Tech Stack:** Rust, serde/serde_json, existing sha2 and ssh-key dependencies.

**Spec:** docs/superpowers/specs/2026-10-14-own-ssh-phase1c-migration-design.md sections 5/6; docs/superpowers/specs/2026-10-10-own-ssh-client-design.md sections 5.1/5.2/5.4; existing session/directory.rs pin and five-jump contracts.

## Global Constraints

- Host payload schema 2, keyslot payload schema 2, account schema_version 3, local state version 3 each have independent validation.
- The migration hash domain is sshelter-host-migration-v1; hash length-prefixed UTF-8 space ID and old record ID and encode the first eight bytes as 16 lowercase hex characters.
- Collisions with legacy alias IDs or other migration sources are errors, never random re-rolls.
- Do not call ssh -G, execute config directives, initialize a vault/Keychain/relay, or launch the application.
- No new dependencies; no second mutable state owner; preserve sealed private-key transport.
- Ownership is new src-tauri/src/sync/records_v3 files and this plan. Root registers the module and owns runtime wiring; do not edit their files.
- Use existing worktree codex/own-ssh-phase1c; stage exact owned paths only.

## Review Focus

- Tombstones with empty or old payloads must remain decodable without becoming live hosts.
- Cross-space duplicate aliases must fail alias resolution as ambiguous, while IDs remain usable.
- Missing key references must be saveable but must never turn into a connectable key authentication method.
- Public metadata fingerprints must match public key bytes; conflicting local material must fail without fallback.
- Editing hostname or port on the same host ID must clear its pin in the same pure update operation.

---

### Task 1: Typed host and keyslot validation

**Files:** Create src-tauri/src/sync/records_v3/{mod.rs,types.rs,validate.rs,tests.rs}.

**Interfaces:**
- Consumes: sync::record::{Record,LocalRecord,RecordKind}; sync::crypto::is_chain_id; sync::slot_rules::is_slot_id; ssh_key::PublicKey.
- Produces: HostPayload, HostRecord { id, scope, payload }, HostScope::{Local,Space{space_id}}, KeySlotPayload, StoredHostKey, ImportedSettings, AuthKind; validate_host(&HostRecord), validate_keyslot(id,&KeySlotPayload), validate_hosts(&[HostRecord]); decode_host(&Record,HostScope) and decode_keyslot(&Record) returning TypedRecord::{Live,Tombstone}; resolve_alias(&[HostRecord],alias); key_material_matches(&KeySlotPayload,public_key,fingerprint); replace_host_payload(&HostRecord,HostPayload).

- [ ] **Step 1: Write failing tests with literal fixtures.**

```rust
#[test]
fn a_missing_key_is_saveable_but_not_ready_to_connect() {
    let mut host = host("0000000000000001", "web");
    host.payload.auth = AuthKind::Key;
    host.payload.key_id = Some("a".repeat(32));
    assert!(validate_host(&host).is_ok());
    assert!(matches!(connection_readiness(&host, &Default::default()), ConnectionReadiness::NeedsKey(_)));
}
```

Add cases for schema 1/99, invalid 16/32/64 hex IDs, port zero, empty endpoint, invalid CLI alias, duplicate aliases inside a scope, cross-scope alias ambiguity, duplicate IDs, missing jump endpoints, self-jump, cycles, repeated hops, more than five total jumps, public-key fingerprint mismatch, unsupported imported settings, tombstone payload compatibility, and pin clearing on endpoint change.

- [ ] **Step 2: Run the focused tests and inspect expected RED assertions.** Root registers pub mod records_v3 once test skeleton compiles. Run `CARGO_TARGET_DIR=/Users/ysya/project/sideproj/sshelter/src-tauri/target cargo test --offline --locked --lib sync::records_v3`. Expected: assertions fail because the initial validation/readiness/update stubs do not implement their contracts.
- [ ] **Step 3: Implement the minimum typed validation, decode, and pure update behavior.** Host payload follows formal spec fields auth/key_id/jump/timeouts/host_key/tags/notes/imported; no unsupported forwarding or encoding fields. Preserve missing key references as NeedsKey; reject malformed required auth fields. Parse complete public key bytes with ssh-key and recompute SHA256 fingerprint. Flatten the first jump's nested chain and then later explicit jumps, matching the broker contract; refuse repeated IDs and cycles before connecting.
- [ ] **Step 4: Run the same focused command.** Expected: all Task 1 tests PASS, zero failures.
- [ ] **Step 5: Commit owned code and update this plan's ledger.** `git add src-tauri/src/sync/records_v3 docs/superpowers/plans/2026-10-14-own-ssh-phase1c-1-record-primitives.md`; commit message `feat(sync): add typed host and keyslot record primitives`.

### Task 2: Deterministic migration ID preflight

**Files:** Create src-tauri/src/sync/records_v3/migration_ids.rs; modify mod.rs/tests.rs.

**Interfaces:**
- Consumes: sha2::{Digest,Sha256}; Task 1 RecordValidationError.
- Produces: migration_host_id(space_id,old_record_id)->Result<String,RecordValidationError>; preflight_host_ids(sources:&[MigrationSource],reserved_ids:&BTreeSet<String>)->Result<BTreeMap<MigrationSource,String>,RecordValidationError>.

- [ ] **Step 1: Write failing tests for a literal hash vector and ambiguous concatenation.**

```rust
assert_ne!(migration_host_id(&space, "ab").unwrap(), migration_host_id(&other_space, "ab").unwrap());
assert!(matches!(preflight_host_ids(&sources, &reserved), Err(RecordValidationError::MigrationCollision { .. })));
```

Derive the literal SHA256 vector independently with Python hashlib; include non-ASCII old alias bytes, legacy ID reservation, source deduplication, and malformed space IDs.
- [ ] **Step 2: Run focused tests.** Expected: hash/collision assertions FAIL with the initial empty-ID/no-collision implementation.
- [ ] **Step 3: Hash domain bytes then a big-endian u64 UTF-8 byte length and bytes for each source field.** Reject collisions without changing the mapping, using a sorted map so source input order cannot affect results.
- [ ] **Step 4: Run focused tests.** Expected: all migration tests PASS.
- [ ] **Step 5: Commit exact owned files.** Commit message `feat(sync): derive stable migration host ids` and ledger the result.

### Task 3: Passive v3 state and read-only legacy decoder

**Files:** Create src-tauri/src/sync/records_v3/state.rs; modify mod.rs/tests.rs.

**Interfaces:**
- Consumes: existing read-only sync::state::SyncState and sync::state_v2::{SyncStateV2,AccountState,SealedRecord}; Task 1 typed validators.
- Produces: SyncStateV3, LocalState, SpaceStateV3, LocalKeyMetadata, DecodedState::{V1,V2,V3}; decode_state(&str)->Result<DecodedState,RecordValidationError>; validate_state(&SyncStateV3); account_meta(app_version)->MetaPayload and validate_account_meta(&MetaPayload).

- [ ] **Step 1: Write RED tests proving local hosts/key metadata survive decoding, plaintext private-key/secret fields are rejected, v1/v2 decoding performs no upgrade or writes, and a newer version is rejected.**

```rust
assert!(matches!(decode_state(&serde_json::to_string(&state).unwrap()), Ok(DecodedState::V3(_))));
assert!(matches!(decode_state(r#"{"version":99}"#), Err(RecordValidationError::UnsupportedSchema { kind: "state", .. })));
```

Include account meta format 3 independently from host/keyslot format 2, secret RecordKind values rejected in public caches, tombstones retained, duplicate host IDs across local/spaces rejected, and cache keys matching record kind/id.
- [ ] **Step 2: Run focused tests.** Expected: the initial decoder refusal fails the valid-state assertions.
- [ ] **Step 3: Implement pure decoding and validation.** No save/load commands, no fs calls, no locks, no registry. Reuse AccountState's public records and sealed envelope storage, remove SpaceState's file_name, preserve cursors/baseline/unknown sealed envelopes, and retain legacy source states unchanged. Local key metadata contains vault ID and public metadata only.
- [ ] **Step 4: Run focused tests plus the project's safe full library suite.** Run `CARGO_TARGET_DIR=/Users/ysya/project/sideproj/sshelter/src-tauri/target cargo test --offline --locked --lib -- --skip secrets_round_trip_smoke --skip store_and_load_and_remove`. Expected: all new tests PASS; report any full-suite failures by name. Root confirms the exact real-Keychain test exclusions before running the broad command.
- [ ] **Step 5: Commit exact owned paths.** Commit message `feat(sync): define passive v3 state and legacy decoding` and record tests.

## Snapshot and key resolver handoff

The next runtime plan should make SyncCore the sole owner of either legacy or records mode and retain generation/unsaved/save_blocked in that owner. Create immutable host/key metadata snapshots under the core lock for HostDirectory::resolve; never hold a core lock while prompting, network I/O, or vault decryption. Pin mutations compare the current endpoint and expected previous pin under that same owner lock and persist before reporting success. Record key resolution treats account keyslot metadata as authoritative, compares local public bytes/fingerprint before signing, and refuses same-ID differences; KeyStore::key currently cannot express mismatch errors, so a records adapter must make mismatch unavailable and private_text return an explicit error, or evolve the trait deliberately in the runtime plan.

## Rulings

- The dispatch listed key_ids/jumpHostId/encoding/forwarding, but the binding formal spec and existing engine support auth/key_id/jump. Root confirmed the formal spec controls; unsupported fields are not invented.
- This plan supplies passive data and pure decoding only. Importer preview, runtime repository activation, migration journal, real device acceptance, and CI registration are separate owner tasks; passing these tests is not migration activation evidence.
