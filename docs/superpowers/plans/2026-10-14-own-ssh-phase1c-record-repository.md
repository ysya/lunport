# Record Repository Implementation Plan

> **For agentic workers:** Use superpowers:executing-plans with test-driven-development for this owned pure repository task. The user has authorized autonomous implementation.

**Goal:** Provide immutable v3 host edits and connection/key snapshots for the single SyncCore owner.

**Architecture:** Read Local and selected, available spaces into an owned snapshot. Every edit transforms a clone; runtime lock, generation, persistence, vault material verification and notification stay with SyncCore and its adapters.

**Tech Stack:** Rust, existing serde/serde_json and records_v3 public validators.

**Spec:** docs/superpowers/specs/2026-10-14-own-ssh-phase1c-migration-design.md sections 5 and 8.

## Global Constraints

- New host IDs are 16 lowercase hex supplied by the caller.
- Local hosts never upload; selected space changes become dirty records.
- Private keys remain sealed or in vault; no filesystem, Keychain, relay or signing operations here.
- Preserve kind/id cache keys, seq, monotonic timestamps, device ID and LWW revision identity.
- Ordinary UI edits cannot forge a host pin; pin CAS checks the saved endpoint and prior key identity.
- Account key metadata and tombstones override same-ID local material without fallback.

## Review Focus

- Remote changes at the same timestamp but another device invalidate an optimistic edit.
- Destination tombstones retain relay seq and their higher LWW timestamp when a host moves back.
- Pinning after an endpoint edit refuses the stale server identity.
- Account key tombstones and mismatched public material block connection without losing valid state.
- Imported unsupported settings preserve preview records, while invalid jump routes never reach an engine.

### Task 1: Immutable repository and snapshot

**Files:** Create src-tauri/src/sync/record_repository.rs and src-tauri/src/sync/record_repository_tests/mod.rs. Registering sync/mod.rs belongs to root.

**Interfaces:** snapshot/list_hosts/get_host/find_by_alias/resolve_host_chain; create_host/update_host/delete_host/move_host returning Result<SyncStateV3, RepositoryError>; pin_host_key endpoint+previous-key CAS; list_keys/resolve_key metadata views. HostView exposes HostRecord, RecordRevision and HostReadiness. KeyView exposes authoritative public metadata and coherent vault reference only.

- [x] Write failing behavior tests using real records_v3 types for clone isolation, revision conflict, scope availability, alias ambiguity, pin CAS, atomic moves, route validation and key authority.
- [x] Run an offline /private/tmp Cargo harness with repository API stubs; expect each new behavior assertion to fail.
- [x] Implement pure snapshot decoding and clone transforms using checked monotonic timestamps/version increments.
- [x] Run the harness to GREEN and root registers the module; formal focused tests passed. Root owns the final shared whole-suite gate.
- [x] Inspect the owned diff, stage only owned files under the shared Git index lock, and commit using Conventional Commits.

## Implementation decisions

- The already supplied execution method and autonomous authorization replace a further plan approval pause.
- The isolated harness uses actual repository source and production v3 types/validators. Legacy runtime-only dependencies are data-only harness declarations; formal root validation remains required.
- Missing imported jump references are preserved only when existing unsupported settings require review; resolve still fails before engine construction.

- Valid remote relationship conflicts are retained for review and repair. Individual malformed payloads are still rejected by the production decoder; aliases and IDs never choose an arbitrary duplicate record.
- Transition validation rejects newly introduced route defects while unchanged unrelated defects do not block repairing another host.
