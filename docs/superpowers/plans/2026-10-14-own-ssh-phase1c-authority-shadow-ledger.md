# Authenticated opaque authority shadow ledger

Narrow concrete correctness finding, one TDD fix pass, no new features or repeat review. Parent released record_repository/tests and records_v3/state ownership, approved optional public-safe SealedRecord header and minimal constructor defaults. Parent explicitly approved including pre-existing released Repo/tests/state validation diffs; they are preserved. Other parent runtime/native/round/adapter files were not edited or staged. records_v3/tests.rs keeps its parent baseline changes unstaged; only the required SealedRecord ctor None default is committed there.

## Contract

`SealedRecord.public_identity: Option<VerifiedPublicIdentity>` defaults None and is omitted when absent. It contains only `id`, `version`, `updated_at_ms`, `device_id`, `deleted`. A typed merger creates it only after AEAD + kind/idHash/deleted verification, bounded known Host16hex (space) or KeySlot32hex (account) identity and valid fixed revision/device headers. It never contains payload, secret-kind/unknown-kind identity, private key, passphrase or credentials. Borrowed identities validate before any header string is copied from zeroizing JSON. v3 shape validation rejects wrong kind/scope/id/header/deleted or unknown hint fields.

Recognized strict legacy alias/text1 and Own1 remain sealed source evidence without hints. Invalid authenticated identities cannot manufacture a shadow. Unsupported outer headers may supply fixed authenticated public ordering evidence without admitting their payload.

Repository preserves typed cache and local material for inspection, compares the existing actual LWW (timestamp, tombstone, smaller device id; not version or transport seq), and returns NeedsReview for a winning opaque Host / Conflict with no vault reference for a winning account KeySlot. Account opaque authority blocks an invented Local material fallback even without prior typed account metadata. Unknown entities are not manufactured as typed rows. Older opaque records leave coherent known rows usable. A newer supported pull replaces/removes the opaque evidence and restores normal readiness. Persisted evidence survives v3 restart without decrypting secret material or accessing Keychain.

Existing session record_directory rejects every blocked hop before engine creation; record_material rejects non-Available KeyView before vault/material access. No native commands, filesystem writer, Keychain/vault implementation, network operation or rotation behavior was expanded; its two constructors only get None defaults. Legacy constructors also get None, preserving default serialized shape.

## Evidence

- Isolated latest-main copied crate: `/private/tmp/sshelter-authority-shadow-harness/src-tauri`.
- RED `/private/tmp/sshelter-authority-shadow-red.log`:8 tests,6 expected behavioral failures (stale Host/KeySlot readiness, LWW shadow, extended header, known replacement initial denial, persisted invalid hint acceptance);2 existing negative/legacy behaviors passed. Mechanical ctor syntax errors were corrected only in the harness and are not counted as behavioral RED.
- GREEN10 regressions: authenticated newer Host + resolve/restart, key authority with/without old account public row and host KeyConflict, exact LWW ties/tombstone/version exclusion, newer supported Host/KeySlot clear, unsupported outer header, invalid identity, legacy alias1/Own1, invalid/secret/unknown persisted hints and ciphertext privacy.
- Latest-source scratch full record filter258/258: `/private/tmp/sshelter-authority-shadow-record-green.log`.
- Actual-worktree `CARGO_TARGET_DIR=/Users/ysya/project/sideproj/sshelter/src-tauri/target cargo test --offline --locked --manifest-path src-tauri/Cargo.toml --lib sync::record_`258/258,15.36s: `/private/tmp/sshelter-authority-shadow-main-record-green.log`.
- Actual-worktree safe full command same prefix, `--lib -- --skip secrets::tests::round_trip_set_get_delete --skip askpass::tests::env_secret_takes_priority_over_keychain --skip askpass::tests::missing_account_and_no_env_yields_none`:2436 passed,0 failed,0 ignored,3 filtered,134.77s. Log `/private/tmp/sshelter-authority-shadow-main-safe-suite.log`.
- No new dependencies, no real home/Keychain/vault/relay/app execution, no push/merge. Exact staged paths and `git diff --cached --check` are checked under `/private/tmp/sshelter-index.lock` flock; parent commits remaining integration dependencies afterward and performs immutable final review.

Evidence is trusted local persisted cache of an earlier authenticated merge, not a server-wide lock or a new protocol. Legacy v2 reconcile logic is unchanged. Missing optional evidence alone makes no unauthenticated identity assertion; subsequent full authenticated pulls can populate it. Unsupported records remain ciphertext and are never converted into arbitrary tombstones.
