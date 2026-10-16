# Legacy v2 forward-format guard

Spec: `docs/superpowers/specs/2026-10-14-own-ssh-phase1c-migration-design.md`, section 7.2.
Authorization: user approved autonomous implementation in the isolated worktree. No live data, relay, Keychain, app launch, push, or merge.

## Global constraints

Own only sync/round.rs, merge.rs, account.rs, slots.rs, rotation.rs and agent/wiring.rs plus this plan and its ledger. Preserve others edits. English source and conventional commits. Temp-home fixtures, MemKeychain and FakeRelay only. A client preflight is not a relay lock and cannot guarantee a concurrent relay migration stops between requests.

## Task 1: Freeze state before file preparation

Interfaces: merge_account returns the original account section except remote_schema_version when any newer live account meta is observed; run_round preflights account before prepare_files and reuses its response. Subsequent known-newer rounds only poll account, preserving all records/cursors/dirty state.

1. Write regression tests for newer meta plus tombstones/unreadable records, missing space file, unchanged account and space cursor/cache, and account-only future polling.
2. Run focused cargo tests. Expected: fail on state or file mutation.
3. Implement merge pre-scan and run_round account preflight, retain the starting section when blocked.
4. Run focused tests. Expected: pass and compatible accounts still synchronize.

## Task 2: Guard non-round writes

Interfaces: known newer state prevents tail slot maintenance, agent wiring, pending swap, rotation progress, leave/join/rejoin and local slot writes. Read-only exports remain available.

1. Add regressions for blocked leave, local key delivery/delete/move, missing local slot material and rotation progression.
2. Run focused cargo tests. Expected: fail because writes remain possible.
3. Implement guards at the shared mutation boundaries, rechecking leave under doc/core lock.
4. Run focused tests. Expected: pass.

## Task 3: Verify and hand off

1. Run `CARGO_TARGET_DIR=/Users/ysya/project/sideproj/sshelter/src-tauri/target cargo test --offline --locked -- --skip secrets::tests::round_trip_set_get_delete --skip askpass::tests::env_secret_takes_priority_over_keychain --skip askpass::tests::missing_account_and_no_env_yields_none`. Expected: all safe fixture tests pass.
2. Review exact owned diff and run git diff --check. Expected: no whitespace defects or unrelated staged files.
3. Exact-path commit `fix(sync): preserve legacy data for newer account formats`.
4. Return tests, commit, limitations and remaining review needs to root; root owns whole-branch fresh review.

## Review focus

A failed preflight must not prepare, diff, apply, upload or delete synced space data. A known newer format must also stop every local maintenance tail. Known blocked state must never clear on a partial pull, and meta must be inspected before sealed cleanup. Guard direct shared local mutation entrypoints as well as background tails. Race limitation is explicit: client checks do not provide atomic relay enforcement.


## Task 4: Coordinate development-profile entrypoint guards

Root extended ownership to engine.rs and slot_setup.rs for shared writer preflight. Before relay/Keychain/vault or filesystem side effects, validate state/vault/slot/public destinations and the entire loaded document using the writer worker shared helper. State set-aside and engine lock open must check both paths. Keep source files read-only when only reading them; reject mutations outside the profile.

1. Add boundary regressions for outside state rename, outside lock symlink, public key cleanup, vault delete/move with escaping .pub symlink and account creation with escaping state symlink.
2. Run boundary tests. Expected: regressions fail from side effects before rejection.
3. Add shared entrypoint path validation; run boundary tests and full safe suite. Expected: pass.
4. Commit exact coordinated paths separately if compatibility commit already exists, otherwise keep the final patch reviewable and explain the profile dependency.


## Task 5: Preserve a future local state during legacy startup

Root review extended the portable compatibility scope to local state downgrade protection. Probe valid JSON version greater than STATE_VERSION_V2 before set-aside; retain bytes in place, mark save_blocked, and prevent background/tail writes or credentials access. Corrupt JSON may retain the existing archive behavior.

1. Write RED v3/v4 unchanged-bytes/no-archive/NoCredentials tests and blocked background-tail test.
2. Run future_local_state filter. Expected: fail from archive or file repair.
3. Implement forward local format detection and blocked-runtime guards.
4. Run targeted tests and whole safe suite excluding all three OSKeychain tests. Expected: pass.
