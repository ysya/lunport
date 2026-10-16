# Own SSH client, plan 1c-0b: enforce development isolation

> Execute under the user's standing authorization for autonomous decisions while resting. English product code; Traditional Chinese final checklist. Never launch the app before the writer boundary is complete.

**Spec:** `docs/superpowers/specs/2026-10-14-own-ssh-phase1c-migration-design.md`, section 4. Profile primitives are in the preceding foundation plan. No schema migration or real vault access.

**Ownership:** root owns fsutil, profile, secrets, home callers, app initialization, updater, IPC/MCP and host-start. A separate writer-boundary worker owns config and direct file writers. Compatibility and new record types are independent tasks with their own plans. Shared lib/module registrations and CI changes belong to root.

## Interfaces

- `fsutil::home_dir() -> Result<PathBuf, AppError>`: Production retains OS home; Development uses app data/sandbox-home.
- `fsutil::check_write(&Path) -> Result<(), AppError>`: PermissionDenied maps to ForbiddenPath; all other I/O errors preserve their kind.
- `fsutil::check_write_io(&Path) -> io::Result<()>`: the same check for I/O-returning lock/rename/remove callers.
- `fsutil::writes_are_confined() -> bool`: current policy only; no environment switch.
- `cfg(test) fsutil::with_test_write_policy(WritePolicy, FnOnce() -> T) -> T`: scoped thread-local restoration, including unwind. Unit temp fixtures remain unrestricted by default. CURRENT itself is never test-special-cased; integration tests link the normal library.

## Task 1: common file boundary and roots

1. Add scoped policy injection and initially permissive check helpers, then temp-sentinel tests: atomic_write and ensure_dir cannot create outside dirs; backup cannot copy outside; prune cannot delete an outside mirror. Watch tests fail before enforcement.
2. Implement checks by `WritePolicy::check`. Non-test Development root is `app_data_root()`; Production unrestricted. Check atomic destination before mkdir/temp, ensure_dir before any existence/permissions, backup both mirror directory and destination before mkdir/copy, prune mirror and each candidate before deletion.
3. Compute app data from CURRENT.identifier; Development backups under that same root; Production roaming backups unchanged. Pure build profile tests already exercise these paths. Keychain SERVICE = CURRENT.keychain_service.
4. Home callers keys, known_hosts and discover use the profile home; Include/newfile caller wiring belongs to writer worker.
5. Run focused fsutil/profile/policy tests; exact-path commit.

## Task 2: app and clients agree before initialization

1. Add profile identifier/product verification returning an error on mismatch; test mismatches and exact Production and Development names RED/GREEN.
2. Perform verification at Tauri setup before showing windows or initializing MCP/sync/agent/session. Enable single-instance in either profile once identifiers differ. Development does not register updater or autostart plugins; beta updater commands also reject Development before network/state access.
3. Add `tauri.dev.conf.json` merge override with dev identifier/product/window title and updater artifact disabled; add explicit tauri:dev and tauri:build:dev scripts (feature required on release dev build). Verify against Tauri's official docs.
4. Windows session/agent pipe wrappers consume CURRENT.pipe_role. Unix agent IdentityAgent in Development is an absolute sandbox socket path, not OS-home tilde.
5. Runtime file removal, IPC lock/socket creation, sync lock and unreadable-state rename, host-spawn lock each validate paths before first side effect. A denied dev lock must not become an ignorable unavailable lock that launches another app.
6. Test outside locks/socket/owned MCP file unchanged, no directory creation; test host-start policy rejection prevents start closure. Tests use scoped policy and temp paths only. Run focused affected tests and normal-library profile matrix.

## Task 3: writer completeness, build and review

1. Integrate worker's direct-writer boundary patch; inspect fresh rg inventory of production fs create/write/copy/link/rename/remove/set_permissions/open and trace each to a guard. Fix gaps with sentinel tests.
2. Run whole Rust suite with only the three real credential-store tests skipped; OpenSSH required. Run frontend tests, typecheck/build; no app launch or originals modified.
3. Run debug, ordinary release, release development-feature profile integration tests. Local release matrix may disable optimization for speed; debug assertions stay false and CI will use defaults.
4. Review immutable branch patch independently; meaningful findings get reproducing tests and fixes. No main merge, release or actual migration. A new draft feature PR may be used for macOS/Linux/Windows CI under the user's autonomous completion instruction; never push shared next/main branches.

## Review focus

- Every filesystem mutation is checked before other changes, including existing symlinks, missing parents, rollback and ACL changes.
- Reads for preview/import remain read-only; writable legacy loader rejects escaped Includes.
- Production storage/service names and IPC remain compatible.
- Debug and CLI profile selection are immutable and identical; Tauri mismatch fails before initialization.
- Unit policy injection does not conceal normal-library behavior.

## Decisions

User requested Brave-like accountless chain sync: client-encrypted records may be held by relay, local vault key stays in OS credential store. No blockchain assumption. Preserve local-only default. No real credentials, external server writes or app launches are part of this development verification.
