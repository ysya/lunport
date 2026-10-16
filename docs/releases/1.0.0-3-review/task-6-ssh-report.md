# Task 6 narrow real SSH installer coverage

Base: `85a902e21bd0bb2d27efbedd6bd03bf4145c355f`; branch: `codex/groups-mcp-beta3`.
Commit: `5eb8b7f0c9094c34c9c47ac0a8819d9e1bfd2350` — `test(keys): cover public deployment over real SSH`.

## Scope and actual path

Owned manifest: `src-tauri/src/session/deploy.rs` (only a macOS/Linux test child declaration) and new `src-tauri/src/session/deploy_ssh_tests.rs`. No production behavior or visibility changes and no new dependencies. The test is a child of deployment so it directly executes private production `script` and `classify`, without copying the installer.

One integration test composes existing `Server`, `tools`, fixture VaultAuth, `TestPolicy`, and `RusshEngine`. Authentication/host keys are fresh disposable fixture keys; the destination is only the fixture loopback sshd, with `SH_SHELL`. The fixture does not isolate the remote login HOME. Every installer command therefore overrides and exports HOME using POSIX single-quote escaping before invoking the actual generated script; the success HOME deliberately contains both spaces and a single quote. Remote stdin/stdout/stderr are checked for absence of PTYs in that command.

Assertions cover literal `SSHELTER_ADDED` plus normal exit/status 0 and production Added classification; literal `SSHELTER_PRESENT` plus status 0 and AlreadyPresent; exact preservation of a CRLF sentinel and an unterminated last line, canonical key appended once, all bytes identical on repeat, `.ssh` 0700 and `authorized_keys` 0600 on both runs; refusing an authorized_keys symlink with exit 70 and RemoteFailed while the outside TempDir target bytes and symlink remain unchanged. All files are TempDir-scoped.

## Verification

Exact command (run through a log-capturing Python wrapper):

```sh
SSHELTER_REQUIRE_OPENSSH=1 cargo test --offline --locked --manifest-path src-tauri/Cargo.toml --lib session::deploy::ssh_tests::real_ssh_installer_preserves_bytes_is_idempotent_and_refuses_symlinks -- --exact --nocapture
```

Result: **1 passed / 0 failed / 0 ignored / 2548 filtered out**, execution 0.67 seconds, **EXIT_CODE=0**; log: `/private/tmp/sshelter-task6-real-ssh-green.log`. Disposable loopback execution uses approved sandbox escalation. The OpenSSH requirement prevents a tools-missing skip from appearing green.

`rustfmt --edition 2021 src-tauri/src/session/deploy_ssh_tests.rs` exited 0. Initial `git diff --check` exited 0. Final staged `git diff --cached --check` exited 0 before commit. Post-commit `git diff --check HEAD^ HEAD` exited 0; log `/private/tmp/sshelter-task6-real-ssh-diff-check.log`. Test compilation has only the existing 3 dead-code warnings (`deselect_key_copy`, `observed_schema`, `set_host_enabled`); no new warning.

Commit held `fcntl.flock` on `/private/tmp/sshelter-index.lock`; asserted exact base HEAD, expected branch and empty index; staged exactly the two-file owned manifest and checked staged-set equality/whitespace. Index is empty after commit; only Root release drafts remain untracked.

## Limits and honest evidence

This extends integration coverage of the already TDD-implemented Task5 installer. No newly observed RED is claimed, and no controlled production mutation was run. The test would detect loss of append newline/byte preservation, incorrect markers/classification, duplicate append, removed permission correction, PTY allocation, or symlink following. Existing engine ending/cancel/auth fixtures and full safe suites remain Root-owned and were not repeated here.

Executed platform is local macOS with a disposable POSIX OpenSSH server; the new child is compiled only for macOS/Linux. Remote Windows installation remains unsupported. No Windows-to-POSIX runtime coverage, Linux runtime, native UI, OS credential store, real hosts, grants, relays, installed Production, push, merge or release verification is claimed. Root owns full checks, independent final branch review and publication.

Root release drafts and ignored ledger/QA are preserved and excluded from the owned commit. This ignored report is not force-added.
