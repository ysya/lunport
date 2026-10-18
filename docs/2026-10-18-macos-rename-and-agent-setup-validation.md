# macOS rename and multi-agent setup validation

## Baseline and scope

The published v1.7.0-2 archive has a `Lunport.app` root and Lunport display metadata, while retaining the compatible executable and bundle identifiers. The pinned updater implementation replaces contents at the installed path. An isolated pre-change Development app under `SSHelter Dev.app` retained that directory when its Contents were updated. Its application menu already displayed Lunport Dev: the other computer's exact stale Dock label was not reproduced locally.

Production installations, personal client configurations, login items and credential stores were not modified by these checks. Native fixtures lived beneath the existing Development data directory and used its sandbox home.

## Automated checks

- TypeScript and production Vite build passed. The existing main-chunk size warning remains.
- Frontend: 96 files, 1,132 tests passed.
- macOS safe Rust suite before the final authorization narrowing: 2,664 passed, 2 ignored, 10 filtered. The final focused migration suite passed all 14 checks, including the added system file-operation test. The existing real-Keychain and PAM exclusions were retained. The restricted tool sandbox initially prevented the existing `ps`-based process cleanup checks; the suite passed in its normal process environment.
- Migration fixtures cover repeated execution, a later update, destination conflicts including an empty directory, link failure rollback, a concurrently occupied rollback path, interrupted move recovery, unrelated journals, Development write confinement, enabled/disabled login entries and retained arguments/unknown plist keys.
- Authorization cancellation is fault-injected after an actual filesystem permission denial. It leaves the old app usable and a later retry succeeds. The fixed Foundation operation was also executed through both real system-script quoting layers at ordinary user privileges: Unicode, spaces, apostrophes and shell syntax remained literal, and an occupied destination was preserved. An administrator password dialog was not completed automatically.
- Client fixtures cover JSON/TOML preservation, unrelated same-name servers, existing Lunport identity reuse, disabled Codex entries, malformed input with redacted parser errors, concurrent edits, fresh setup, restrictive file/backup permissions and symbolic-link refusal.
- Portable commands and install links cover Unicode, spaces, quotes, shell syntax, the VS Code envelope and persistent Linux AppImage paths. The new owner-only Windows DACL test runs in Windows CI.

## Native Development app

1. Replaced Contents of the old-name fixture with the packaged candidate, matching the existing updater's layout. Opening the old path automatically produced sibling `Lunport Dev.app` and a relative `SSHelter Dev.app → Lunport Dev.app` symlink. The app opened normally with the Lunport Dev menu.
2. Invoked the original absolute executable path with `--mcp`. MCP initialize succeeded and tools/list returned five tools. AI access remained off, with zero allowed hosts; no SSH command was executed.
3. Used the actual Add buttons for Codex, Claude Code and Claude Desktop. Each became Configured. The three sandbox settings files retained their unrelated fixture entries and original settings; backup files were created and JSON settings were owner-only. No real external client was registered.
4. Other agent opened manual setup. JSON/TOML selection worked with keyboard confirmation; the preview used the canonical new app path and separate `--mcp` argument. The native Save dialog exported TOML into the disposable fixture folder, and the output was verified.
5. Replaced Contents of the canonical app with the final candidate to simulate a subsequent update. The legacy symlink remained valid and launching through it reopened the app normally. The final minimum-size 800×560 settings view kept all controls accessible by scrolling, including the three-column tool selector and action area.

Cursor/VS Code installation URLs are generated and tested against their documented formats. Development deliberately does not open these external registration flows. Real client reload/installation approval and the other computer's pinned Dock label remain platform acceptance checks; no Connected state is inferred from a configuration write. Full cross-platform check results are attached to the pull request.
