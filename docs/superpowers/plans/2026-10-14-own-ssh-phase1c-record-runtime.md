# Active Record Runtime Implementation Plan

> **For agentic workers:** Use superpowers:executing-plans and test-driven-development. Autonomous implementation is already authorized.

**Goal:** Activate bounded, non-destructive v3 startup and durable edits under the existing SyncCore.

**Architecture:** A read-only startup probe selects Legacy/Records/Blocked before credentials or legacy loaders. SyncCore remains the one runtime owner. User candidates validate and atomic-save before replacing memory and advancing generation.

**Tech Stack:** Rust, existing records_v3 validators, fsutil atomic writes, SyncEnv and SyncCore.

**Spec:** docs/superpowers/specs/2026-10-14-own-ssh-phase1c-migration-design.md sections 5, 7 and 8; docs/superpowers/plans/2026-10-14-own-ssh-phase1c-active-runtime.md.

## Global Constraints

- No app launch, real home/Keychain/relay, migration, push or merge.
- Probe never writes, renames, repairs, upgrades or reads credentials.
- Version 1/2 remain Legacy; missing state becomes fresh version 3; invalid/future/error becomes Blocked.
- Active records and legacy state are mutually exclusive inside SyncCore, default Legacy for existing fixtures.
- Candidate save failures preserve old memory and generation; no events or external callbacks while core is held.
- Background network receipts and retry remain a separately coordinated task.

## Review Focus

- Non-regular files or redirected state paths must not hang startup or get treated as missing.
- Large/invalid/future bytes remain untouched and block mutations before credentials.
- Disk save failure must not publish a new in-memory host/pin or generation.
- A stale candidate cannot replace newer host, account or remote state.
- Legacy operations cannot mutate Records/Blocked, even if legacy fields temporarily coexist.

### Task 1: Bounded startup probe and active persistence

**Files:** Create src-tauri/src/sync/record_runtime.rs and focused record_runtime_tests.

**Interfaces:** RuntimeFormat default Legacy; StartupProbe::Records { state, fresh } / Legacy { state: DecodedState } / Blocked { reason }; probe_startup(path,name); save_active(path,state).

- [x] Write and observe RED tests for missing/fresh, typed legacy, valid3, malformed/future/UTF8, oversized/nonregular/symlink state, validation refusal and atomic 0600 persistence.
- [x] Implement bounded read-only probe, fresh identity construction, shape validation and existing atomic write.
- [x] Run scratch harness to GREEN then root registers the new module for formal tests.

### Task 2: One-core active mutation and legacy refusal

**Files:** Extend owned record_runtime.rs/tests; modify runtime.rs only after compatibility worker releases ownership.

**Interfaces:** activate_probe(core,probe), snapshot(env)->(state,generation), commit_candidate(env,expected_generation,candidate)->generation, mutate_records(env,pure transform)->generation; save_core dispatches active format and legacy helpers refuse Records/Blocked.

- [x] Observe RED for mutually exclusive activation, blocked save/snapshot, generation conflict, failed save preserving old state, successful durable replacement and legacy refusal.
- [x] Add narrow Core fields/dispatch after compatibility handoff; implement locked candidate commits without external callbacks.
- [x] Root owns engine startup/network dispatch; run focused integration suite and commit exact owned paths under shared index lock.

## Verified interfaces and handoff

- probe_startup(path,name) returns Records/fresh, paused Legacy source, or Blocked with non-secret kind/reason.
- activate_probe(core,probe) validates and changes the single model, clears keys/upgrade/swap state and advances generation; later activation requires caller-held lifecycle/vault/publication.
- snapshot(env) returns (SyncStateV3,generation); commit_candidate and mutate_records acquire only core, shape-validate and atomic-save before memory/generation changes.
- A failed user save preserves old records/generation/unsaved. Successful commits always persist and bump, including identical candidates by root's receipt ruling.
- read_account_keys validates state, reads only current code and verifies account chain; no pending-code promotion or cleanup.
- Existing v2 commit/mutate/format observer/material transactions refuse Records, Blocked, paused Legacy or coexisting records. save_core dispatches explicit active format and retains background unsaved retry semantics.
- Future v3 background content/seq/dirty writers must also advance snapshot generation or rebase latest under core; legacy no-generation segment commits cannot be copied blindly.
- Root owns module registration, engine/native/session integration and final whole-suite gate.
