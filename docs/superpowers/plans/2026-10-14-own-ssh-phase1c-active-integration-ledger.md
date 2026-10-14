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
| All active record modules including canonical unsupported authority | 258 passed | /private/tmp/sshelter-authority-shadow-main-record-green.log |
| Full safe Rust suite | 2436 passed, 3 credential tests filtered | /private/tmp/sshelter-authority-shadow-main-safe-suite.log |
| Native adapters and two-device host/key flow | 5 passed before migration guard addition | /private/tmp/sshelter-native-two-device.log |
| Frontend suite, TypeScript and production asset build | 942 passed plus successful build | /private/tmp/sshelter-lifecycle-ui-build.log |
| Normal-library debug profile | 3 passed | /private/tmp/sshelter-profile-final-debug.log |
| Normal-library release profile | 3 passed | /private/tmp/sshelter-profile-final-release.log |
| Normal-library release development feature | 3 passed | /private/tmp/sshelter-profile-final-release-dev.log |

The release profile matrix disables debug assertions but uses reduced optimization for validation. It does not prove an optimized installer build. The two-device test uses temporary homes, a memory Keychain, and a fake relay. It verifies that hosts arrive without private material, an explicit key publication enables download, downloaded material matches the authoritative public identity, and original SSH config bytes stay unchanged.

## Native smoke test

A debug macOS bundle was built at `src-tauri/target/debug/bundle/macos/SSHelter Dev.app` with the Development identifier and data directory. The actual native window opened the records workspace. A disposable host named `development-smoke-test` targeting `example.invalid` was created through the UI and remained present after workspace refresh. Keys and account panels rendered correctly. No SSH connection, private key generation, real account creation or user migration was performed. The Development fixture remains available for inspection.

## Completion gates

Account migration and leave/rotation formal registration are complete. Native commands return their real partial-operation receipts; migration resume accepts optional recovery words through Zeroizing native memory. Pending migration journals block account and shared effects before credentials while Local host/key work stays available. Canonical unsupported authority protection retains cached bodies for inspection but prevents stale connections and material fallback, including after restart. An immutable independent review and draft pull request CI will be recorded when they finish. The final user checklist will report each result with its actual verification boundary.
