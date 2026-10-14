# Own SSH phase 1c active integration

This ledger records the active records runtime integration and its verification. The binding migration design and active runtime plan define the implementation scope. Real user migration, a merge into the shared branch, and a release remain separate operations.

## Implemented behavior

- Startup probes bounded state bytes before legacy loaders or credentials. Missing state opens a records workspace; existing v1/v2 state stays paused until an explicit legacy choice or migration. Unsupported or malformed state stays unchanged and blocks writes.
- One SyncCore owns format, records, legacy state, keys, and generation. Durable candidate commits precede memory activation. The migration activation barrier takes Doc then Core after caller-held lifecycle, vault, and publication locks; stale generation, failed save, blocked runtime, or mismatched account keys preserve the original runtime.
- The session broker selects a directory dynamically through the same lifecycle mutex. Records resolve stable host IDs, all jump hosts, public key authority, actual vault identity, OS username, and endpoint-aware host-key pinning. Records never use legacy SSH config or private file fallback.
- Native host revisions are decimal strings to preserve full u64 values in JavaScript. New host creation clears caller-supplied host-key trust. Shared edits refresh the account compatibility gate before saving against the latest state.
- Account creation, join, pending resume, spaces, local key import and generation, explicit key sync, and downloaded key activation are connected through native commands. Code display is a separate action; status DTOs contain public metadata only.
- Record imports use expiring memory previews and durable resumable publication. Migration preview and confirm/resume commands use a separate memory cache; successful cutover clears legacy agent approvals and unlocked keys.
- Legacy config, agent, MCP execution, deployment, and late writer paths refuse record/blocked/paused mode. MCP record inspection exposes endpoint and routing metadata while omitting notes and imported directive values.

## Verification evidence

| Check | Result | Evidence |
| --- | --- | --- |
| Active runtime including migration activation and explicit legacy pause | 32 passed | /private/tmp/sshelter-legacy-pause-green.log |
| All active record modules including canonical unsupported authority and mutation guards | 268 passed | /private/tmp/sshelter-final-review-record-green.log |
| Full safe Rust suite after final fixes | 2449 passed, 0 failed, 3 credential tests filtered | /private/tmp/sshelter-final-review-safe-suite.log |
| Native adapters and two-device host/key flow | 5 passed before migration guard addition | /private/tmp/sshelter-native-two-device.log |
| Frontend suite, TypeScript and production asset build | 942 passed plus successful build | /private/tmp/sshelter-lifecycle-ui-build.log |
| Normal-library debug profile | 3 passed | /private/tmp/sshelter-profile-final-debug.log |
| Normal-library release profile | 3 passed | /private/tmp/sshelter-profile-final-release.log |
| Normal-library release development feature | 3 passed | /private/tmp/sshelter-profile-final-release-dev.log |

The release profile matrix disables debug assertions but uses reduced optimization for validation. It does not prove an optimized installer build. The two-device test uses temporary homes, a memory Keychain, and a fake relay. It verifies that hosts arrive without private material, an explicit key publication enables download, downloaded material matches the authoritative public identity, and original SSH config bytes stay unchanged.

## Native smoke test

A debug macOS bundle was built at `src-tauri/target/debug/bundle/macos/SSHelter Dev.app` with the Development identifier and data directory. The actual native window opened the records workspace. A disposable host named `development-smoke-test` targeting `example.invalid` was created through the UI and remained present after workspace refresh. Keys and account panels rendered correctly. No SSH connection, private key generation, real account creation or user migration was performed. The Development fixture remains available for inspection.

## Completion gates

Account migration and leave/rotation formal registration are complete. Native commands return their real partial-operation receipts; migration resume accepts optional recovery words through Zeroizing native memory. Pending migration journals block account and shared effects before credentials while Local host/key work stays available. Canonical unsupported authority protection retains cached bodies for inspection but prevents stale connections and material fallback, including after restart. The immutable whole-branch review and its single scoped fix re-review are complete; both Important/P1 findings were addressed, with no new Critical/Important breakage. Draft pull request CI remains unstarted because push was rejected by automatic approval review. The user checklist reports each result with its actual verification boundary.

## Final immutable review and fix wave

The independent whole-branch review used HEAD `2e26433ef79cd1df64f3927f80aaf2b82a758727` and found two Important/P1 defects: startup reused a snapshot taken before acquiring the process lock, and ordinary Host mutation could bypass winning authenticated opaque authority. One fix wave, `e38a3b760758a3573aaa22f3a0987caa01fe613d`, reprobes after successful lock acquisition and guards update/delete/move/pin through the canonical LWW predicate. Behavioral RED preceded fixes; startup 22, record 268 and integrated safe Rust 2449 tests passed afterward. See the adjacent final-review-fixes ledger for commands and logs. The one immutable scoped re-review inspected `2e26433..e38a3b7` and the RED/GREEN logs: both findings ADDRESSED; no new Critical/Important breakage and no out-of-scope observations. The reviewer ran read-only checks and did not repeat the suite.

The attempted push to `github.com/ysya/sshelter` was rejected by automatic approval review because specific authorization to transmit the branch was absent. No push, draft PR or remote CI happened. The branch and managed worktree remain available locally; merge, release, deployment and real user migration remain separate operations.

The final fixed debug Development bundle was rebuilt successfully (55.06s Rust build; `/private/tmp/sshelter-final-fixed-dev-bundle.log`, exit 0). The prior Dev process was closed, the new bundle launched, and the public `development-smoke-test` fixture remained present across restart and refresh; the Host detail showed Local/Ready/Saved. No connect, account creation, private key generation or real migration was performed. The bundle build emits 15 library dead-code warnings; the safe test build emits three. They do not fail compilation, and no optimized release acceptance is claimed.

User handoff: `docs/2026-10-14-sync-chain-review-checklist.md`. Named feature branch and managed worktree are preserved for review.
