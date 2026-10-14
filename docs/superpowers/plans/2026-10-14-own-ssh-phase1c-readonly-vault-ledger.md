# SDD ledger — plan: docs/superpowers/plans/2026-10-14-own-ssh-phase1c-readonly-vault.md

Pre-flight: no changes to writer API or existing Vault::open; wrapper methods reuse immutable ids/get/settings only. Parent broker consumes read_vault and the read-only wrapper.
Ruling: Missing vault is an empty read-only view, and an empty file with valid vault structure skips Keychain — preserves lazy first-use behavior and avoids unnecessary credential prompts — callers must distinguish a missing requested key through get returning None.
Ruling: Source parse and credential failures use static messages — protects invalid JSON/credential values from diagnostics — detailed low-level credential failure cause is intentionally not exposed.

RED: cargo test --offline --locked --lib readonly_vault → 10 tests, 3 passed, 7 failed for expected old-loader behavior (/private/tmp/sshelter-readonly-vault-red.log). Corruption renamed the source; keyless returned archival error; empty source queried credentials; bad credential text leaked its sentinel; version0 was accepted; unbounded growth helper and oversized file had no cap.
Ruling: Read-only account validation accepts only legacy vault:key or existing constructor vault:key:<16 lowercase hex> before credential access — prevents a tampered source from querying host:/sync: accounts — malformed nonstandard old headers are refused only by this reader, with writable loader unchanged.
Ruling: File type/size are checked before open and again on the opened descriptor; Take(limit+1) handles later growth — no new filesystem mutation path — the wrapper is a snapshot and does not claim a multi-file atomic transaction.

GREEN: 10/10 readonly_vault tests passed (/private/tmp/sshelter-readonly-vault-green.log). All 39/39 vault::store tests passed including 29 existing writable/archive regressions (/private/tmp/sshelter-readonly-vault-store-regression.log). Existing Vault::open/get/writer methods unchanged; read-only wrapper delegates the existing zeroizing sanitized get.
Verification: git diff --check clean; diff adds only reader helpers and spy/tempfile tests to vault/store.rs. No recursive rustfmt, actual home, real Keychain, relay, app launch, push or merge. Parent integrates read_vault into its broker adapter and performs branch-wide checks.
Task 1: complete; exact reader/plan/ledger commit follows under shared index lock.
