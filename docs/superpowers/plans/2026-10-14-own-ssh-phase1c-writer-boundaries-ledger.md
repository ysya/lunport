# SDD ledger — plan: docs/superpowers/plans/2026-10-14-own-ssh-phase1c-writer-boundaries.md

Pre-flight: all tasks consume the parent-owned fsutil policy API; agreed signatures match.
Ruling: Parent review is the independent final review for this delegated patch — no recursive reviewer dispatch — parent integrates and checks the complete worktree.

Task 1/2 RED: cargo test --offline --locked --lib boundary_ → 19 tests, 17 failed; 15 direct writer denial assertions failed for expected missing guards. Allowed source-copy regression passed.
Task 1/2 partial GREEN: 22 tests, 20 passed; all owned tests passed. Two parent runtime tests still in their RED phase.
Ruling: migrate_legacy_backups returns Result<bool, AppError> so boundary denial cannot be logged and silently accepted — existing non-boundary IO failures retain prior logged-and-skipped behavior — callers outside this module would require adapting if any are added.
Ruling: Conservative denial of redirected/dangling symlinks applies to unlink/rename too — consistent immutable profile boundary — Development cannot replace such links through the old editor.
Ruling: Parent extended ownership to sync/files.rs to cover callback preflight — complete environment/document and space path checks precede file creation or state persistence.
Task 3 RED attempt blocked by concurrent round.rs syntax error; reported to parent and did not alter that file.

Task 3 RED: 28 tests, 23 passed, 5 failed for expected behavior: settings overwrite, new environment-expanded Include escape, persisted external Include, backup destination check after Include callback, and prepare_files creation before external-main refusal.
Ruling: Writable document validation also checks new in-memory Include directives before persist — otherwise a sandbox config could introduce an escaped Include even after its original load was validated — Development may reject legacy Include syntax it cannot statically expand.
Ruling: settings_export IO extracted unchanged before the denial test to make the preexisting dialog-mediated filesystem effect fixture-testable — guard added only after actual overwrite refusal assertion failed.

Final audit RED: 31 matching tests, 29 passed; unmatched wildcard directory symlink and later reserved name collision failed. Fix: validate every wildcard prefix and reserve candidate names across the full source list before any link.

Final caller RED: timestamped backup candidate symlink outside the root caused Include callback before denial. Parent supplied fsutil::check_backup_write; all caller preflights now consume it before Include, state, vault or keychain effects.
Ruling: Extra upgrade directory scans only run under Confined policy — strict destination checks remain no-ops in Production — preserves the original Production upgrade behavior for unused unreadable directories.

Verification: 25/25 owned boundary tests GREEN; 360/360 affected regressions GREEN (config 147, files 27, space_files 17, slot_files 7, local_keys 68, upgrade 47, vault/export 14, vault/store 29, settings_io 4).
Integration: parent session/auth fixture constant typo temporarily blocked four filters; parent fixed it and all four reran GREEN. Compat local_snapshot temporarily rejected allowed external source copy; its preflight split restored the existing 68 local_keys tests and explicit copy boundary test.
Ruling: Parent owns the full library/Windows integration verification — this agent ran every affected owned module plus scoped boundary fixtures — remaining whole-branch risk is reported for parent validation.
Final review: owned diff reviewed; no additional owned findings. Parent performs the independent integrated review. git diff --check clean.
Task 1/2/3: complete; exact-path commit follows under the shared index lock.

Review fix pass: findings 3 and 5 assigned to this worker; root owns other wiring sections and compat owns caller sites in slots.rs.
Review finding 3 plan: add blocked Fix regression for save_blocked, future local state and newer account; run RED; share the refresh eligibility gate under doc → core lock before restore_include; rerun wiring tests.
Review finding 5 plan: extract the existing retirement name-selection phase unchanged; add planning denial and stable execution collision tests; run RED; validate both private/public retirement destinations in the plan before caller vault/Keychain changes; recheck during execution without choosing a different name. Compat adds the full caller-side regression.
Ruling: RetirementPlan preserves the existing private-file suffix selection contract; execution refuses a later private-destination collision instead of re-picking after vault changes — avoids overwriting another copy — caller may need to retry after a concurrent file creation.

Review finding 3 RED: blocked_fix_checks_write_eligibility failed because save_blocked Fix wrote the agent Include into main config before refresh rejected it (/private/tmp/sshelter-review-fix3-red.log).
Review finding 5 RED: retirement_plan_rejects_outside_public_destination and retirement_execution_preserves_a_destination_occupied_after_planning failed; suffix/read-only planning regression passed (/private/tmp/sshelter-review-fix5-red.log).
Ruling: Shared check_writes_allowed runs after acquiring doc and briefly acquires core; it releases core before persist hooks reacquire it — protects the same eligibility conditions as refresh without deadlocking the existing lock order — requires lifecycle writers to retain the documented doc-before-core order.

Review fix pass GREEN: all 30 agent::wiring tests passed (/private/tmp/sshelter-review-wiring-green.log), including blocked save/future/newer cases and parent endpoint quoting regression. All 10 sync::slot_files tests passed (/private/tmp/sshelter-review-fix5-green.log), including original suffix collisions and 3 new retirement plan/execution cases.
Review finding 3 wiring remains unstaged for parent combined render+guard commit to preserve section ownership. Finding 5 pure planner/executor and this ledger are committed as exact paths under shared index lock; compat owns the full caller regression and pre-vault call sites. No new review pass requested.
