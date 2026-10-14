# Own SSH phase 1c final review fixes ledger

One coherent fix wave for the two accepted Important/P1 findings on immutable HEAD `2e26433ef79cd1df64f3927f80aaf2b82a758727`. No new feature, repeat broad review, user migration, push, merge or release. Binding design: `docs/superpowers/specs/2026-10-14-own-ssh-phase1c-migration-design.md`; scope/steps: adjacent final-review-fixes plan.

## Startup snapshot ownership

`engine::initialize` previously probed source bytes before retrying the cross-process lock and reused that snapshot for credentials/activation. The prior owner could finish a newer record save or legacy-to-record cutover during the retry; the new owner then activated stale state and replaced the newer source on first save.

A narrow production-used `startup_probe_with_lock` seam first reproduced the unchanged sequence. It now repeats the bounded read after successful lock acquisition, and only that selection feeds existing credential loading and activation. A failed lock still returns the earlier read-only selection; initialize blocks saves and returns before credentials/worker creation. No state format, lock retries, credential API or persistence API changed.

Three deterministic tests use a real temporary-file lock. The holder saves immediately in the retry callback before explicit unlock. They assert newer same-device host data survives a real `mutate_records` first candidate save, speculative missing-file identity cannot replace newly created state, and completed legacy-to-record cutover activates Records mode. No OS credentials, external server, application/UI or actual user data is accessed by these regressions.

## Winning opaque Host mutation authority

Cached typed Host revisions were previously allowed to update/delete/move/pin despite newer authenticated unsupported authority. A sufficiently late local timestamp could make the old endpoint/pin Ready again, or move it to Local outside the sealed source scope.

`ensure_host_authority` compares source-space sealed public evidence to its typed cache through existing `opaque_shadows` (actual timestamp/tombstone/device LWW). `checked_host` applies it for update/delete/move, and pin applies it before endpoint/CAS checks or idempotent acceptance. Rejection is `OpaqueHostAuthority(id)` before candidate construction. The typed cache, unsupported ciphertext, local public/material references and restart evidence remain unchanged. Existing duplicate-ID creation refuses recreation; unrelated creation remains available.

The check is independent of `NeedsReview`, so normal imported review and existing route repair remain editable. Older LWW unsupported evidence does not block known data; a newer supported authenticated replacement clears the evidence and restores all repository mutation paths. `VerifiedPublicIdentity`, secret-kind exclusion, legacy alias/Own1 behavior and key authority rules are unchanged.

## Evidence

All commands run in `/Users/ysya/.codex/worktrees/own-ssh-phase1c/sshelter` using:

```sh
CARGO_TARGET_DIR=/Users/ysya/project/sideproj/sshelter/src-tauri/target /opt/homebrew/bin/cargo test --offline --locked --manifest-path src-tauri/Cargo.toml --lib <filter>
```

| Check | Result | Log |
| --- | --- | --- |
| Startup RED `startup_lock_wait` | 0 passed, 3 expected behavioral failures | `/private/tmp/sshelter-final-review-startup-red.log` |
| Repository RED `sync::record_repository::tests::shadow` | 14 passed, 6 expected mutation failures | `/private/tmp/sshelter-final-review-authority-red.log` |
| Engine GREEN `sync::engine::tests` | 22 passed, 0 failed | `/private/tmp/sshelter-final-review-startup-green.log` |
| All record modules GREEN `sync::record_` | 268 passed, 0 failed | `/private/tmp/sshelter-final-review-record-green.log` |
| Final integrated safe Rust suite | 2449 passed, 0 failed, 3 actual OS credential tests filtered; 137.47s | `/private/tmp/sshelter-final-review-safe-suite.log` |

The integrated command replaces `<filter>` with `-- --skip secrets::tests::round_trip_set_get_delete --skip askpass::tests::env_secret_takes_priority_over_keychain --skip askpass::tests::missing_account_and_no_env_yields_none`, preserving the established exclusion of three actual OS credential tests. The existing three dead-code warnings (`deselect_key_copy`, `observed_schema`, `set_host_enabled`) remain visible in the logs. These backend-only changes do not repeat frontend/profile/UI checks recorded in the active integration ledger. Linux/Windows CI and root scoped immutable re-review remain separate gates.

Owned staged paths only: engine.rs, record_repository.rs, record_repository_tests/shadow.rs and this fix plan/ledger. Commit uses `/private/tmp/sshelter-index.lock` with fcntl flock, asserts the shared index starts empty, checks exact staged paths and whitespace, and never stages another agent's files.

Final integrated verification includes all 13 newly added regression/control tests after formatting and precise authority-error assertions. `git diff --check` passed; only the five owned paths are included in the fix commit. No unresolved failure remains in this fix scope.
