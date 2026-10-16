# Pure typed record transport ledger

Owned files: new sync/record_merge.rs, record_merge_tests.rs, this ledger and the focused plan. Root owns sync/mod.rs registration. No legacy decoder, filesystem writer, network, vault or Keychain calls added to this module.

## TDD evidence

- Initial stub: 17/17 expected failures, /private/tmp/sshelter-record-merge-red.log.
- Older typed tombstone vs newer opaque revision: expected failure, /private/tmp/sshelter-record-merge-extra-red.log; preserves complete original section/cursor and returns InvalidPull/OpaqueConflict when canonical cache cannot represent both revisions safely.
- Safe key/space readers and unknown outer fields: expected failures, /private/tmp/sshelter-record-merge-readers-red.log and record-merge-shape-readers-red.log.
- Authenticated unsupported payload header LWW: expected failure, /private/tmp/sshelter-record-merge-opaque-red.log. Opaque revisions with readable headers use native timestamp/deleted/device ordering, retain ciphertext, and only advance transport metadata.
- Relay safe-integer limits: two expected failures, /private/tmp/sshelter-record-merge-seq-red.log; out-of-range pull watermark or accepted receipt cannot poison cached sequences.
- Final scratch and real-crate focused commands recorded below after verification. Scratch uses actual crypto/record/typed validators, transport shells and an isolated target; real-crate focused verification confirms production type compatibility.

## Contracts and rulings

- account_gate checks maximum authenticated observed future schema conservatively before any material merge. Supported Meta winner uses native Record LWW; an older publishing marker cannot override newer cached active metadata. Schema 3 without a marker is compatible. Valid account-gated/publishing markers, invalid markers, schema 2 and schema 4+ return exact original sections and expose their gate. Marker IDs and digests use the common validated MigrationGate type.
- Gate evidence is pure. The active round must durably save shared_writes_blocked/migration_gate before allowing shared operations, fail closed in memory when gate persistence fails, and require fresh account authentication for shared commands after restart. account_outgoing's cached compatibility guard alone is not fresh authorization.
- Only shape-valid public Host schema 2/KeySlot schema 2 and known account Meta/Space/Device payloads become typed public cache. Legacy alias hosts, schema 1 Own keyslots, unknown kinds/schemas/outer fields and malformed/authentication-mismatched records remain sealed with fixed diagnostics. Envelope tombstones cannot delete records without matching authenticated body semantics. Self/dangling/alias conflicts remain cached for NeedsReview; this merge does not resolve relationships or write files.
- Secrets are persisted only as envelopes. Temporary plaintext byte buffers and successfully parsed JSON string values are zeroized, including unsupported schema/identity exits. LWW compares secret headers with a null payload copy; encrypted outgoing preserves the original nonce/ciphertext. No secret values or decoder error text enter diagnostics. Malformed partial serde parse internals are controlled by the library; no absolute allocator-level memory-erasure claim.
- key_secret returns a zeroizing private copy only behind live recognized keyslot metadata; activation must also validate authoritative public key/fingerprint. space_keys requires live recognized Space metadata and matching account chain before returning intended live ChainKeys. Both accessors perform no I/O and callers still require a fresh account gate.
- Pull baseline/since/watermark/unique identity/unique sequence and relay safe-integer bounds are checked before advancing. Baseline starts at zero; established cursor may use current cursor or deliberate full zero replay. Unknown ciphertext retention permits future decoding. Opaque dirty collisions abort the complete merge without discarding dirty work.
- TypedOutgoing snapshots full public revision, including device/payload/deleted, or exact secret nonce/ciphertext/deleted identity. Receipts clear only a matching current dirty snapshot with valid sequence; accepted rows are applied despite a later error/freeze, and never advance pull cursor.
- Client-only gate preflight does not promise atomic relay freeze. Server changes between preflight and push remain a separate protocol limitation; no server lock or cross-chain atomic migration claim.

## Validation

- Scratch: cargo test --offline --locked --manifest-path /private/tmp/sshelter-record-merge-harness/Cargo.toml; 27 passed, 0 failed. Log: /private/tmp/sshelter-record-merge-complete-green.log.
- Formal: CARGO_TARGET_DIR=/Users/ysya/project/sideproj/sshelter/src-tauri/target cargo test --offline --locked --manifest-path src-tauri/Cargo.toml --lib sync::record_merge::tests; 27 passed, 0 failed, 2226 filtered. Log: /private/tmp/sshelter-record-merge-formal-green.log.
- No full suite was run concurrently and no real home/OS Keychain/vault/relay was accessed. Root performs final integrated suite after active runtime cutover.
