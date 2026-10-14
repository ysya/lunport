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
