# Development writer boundaries implementation plan

> **For agentic workers:** Use superpowers:executing-plans for this delegated implementation. The parent owns integration and independent review.

**Goal:** Reject every legacy write outside the development profile before filesystem, vault, Keychain, or Include effects.

**Architecture:** All direct writers consume `fsutil::check_write(&Path) -> Result<(), AppError>`. Multi-path operations preflight the complete set before their first effect. Legacy editable config traversal validates main paths, Include patterns and matched files; profile home supplies tilde expansion.

**Tech Stack:** Rust, existing tempfile fixtures, MemKeychain and FakeRelay.

**Spec:** docs/superpowers/specs/2026-10-14-own-ssh-phase1c-migration-design.md section 4.

## Global constraints

- Debug uses Development; release without development-profile uses Production.
- No real home, Keychain, relay, app launch, push, or merge.
- External import sources are read-only; move imports must reject before vault mutation.
- Existing Production semantics remain unchanged.
- Own config/{commands,include,newfile}, sync/{space_files,slot_files,local_keys,upgrade}, vault/{export,store}, settings_io only.

## Review focus

- A later external source in a multi-file operation must reject before an earlier internal source moves.
- An existing redirected or dangling symlink must reject before chmod, unlink, or rename.
- An unmatched external Include pattern must reject before neighboring backup migration.
- A public-key destination denial must preserve the private key and prevent vault/Keychain creation.
- A denied source move must preserve source bytes, main config, local state and vault.

### Task 1: Preflight legacy editable config

**Files:** config/commands.rs, config/include.rs, config/newfile.rs.
**Interfaces:** consumes check_write, writes_are_confined, home_dir and with_test_write_policy.

- [x] Add boundary tests for external main files, absolute/parent/env/tilde/symlink Include paths, missing external Include globs, backup migration and new-file planning.
- [x] Run `cargo test --offline --locked --lib boundary_` and verify refusal assertions fail.
- [x] Guard main and Include traversal, selected new-file target, persist, restore and backup migration before mutations; use profile home.
- [x] Rerun the boundary tests and existing config tests.

Test assertion shape:
```rust
fsutil::with_test_write_policy(WritePolicy::Confined { root }, || {
    assert!(load_doc_migrated(&main).is_err());
});
assert_eq!(std::fs::read(&external).unwrap(), before);
```

### Task 2: Preflight slot, space, vault and import operations

**Files:** sync/slot_files.rs, sync/space_files.rs, sync/local_keys.rs, sync/upgrade.rs, vault/export.rs, vault/store.rs.
**Interfaces:** same fsutil helpers; existing explicit SyncEnv fixtures.

- [x] Add boundary tests for private/public remove/retire, link sources, space Include callbacks, multi-source keep, denied vault destination, denied key move and copy-only import.
- [x] Run the boundary test filter and verify failures show existing unauthorized effects.
- [x] Validate every path before operations: `for path in paths { fsutil::check_write(path)?; }`; vault checks precede ensure_key; upgrade checks precede Keychain/relay.
- [x] Rerun boundary tests and the existing affected module tests.

### Task 3: Settings export and final audit

**Files:** settings_io.rs; this plan and its ledger.
**Interfaces:** helper `write_settings(path: &Path, json: &str) -> Result<(), AppError>` for command IO.

- [x] Add denied overwrite/create regression tests, run RED, introduce guarded helper, run GREEN.
- [x] Audit every direct mutation in owned production functions; add a regression for any uncovered multi-path ordering.
- [x] Run affected module tests and `git diff --check`; the parent runs the credential-safe full library suite on the integrated branch.
- [x] Stage exact owned paths and commit `fix: confine development legacy filesystem writers`.
