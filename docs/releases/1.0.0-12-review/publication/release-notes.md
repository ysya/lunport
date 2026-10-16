This beta fixes two issues reported after Beta 11.

- SSH connections now continue after host-key approval when an unrelated background sync round finishes during pin preparation. The pin is checked and saved atomically against current route, public-key authority and previous fingerprint. Sync receipts and unrelated changes are preserved. Changed security context, cancellation and revoked MCP access still fail closed.
- Library sync can include existing hosts and Groups when a migrated chain retains recognized legacy alias/text source records. The original ciphertext is preserved unchanged. Authentication failures, unsupported identities and legacy aliases that shadow typed host IDs still block inclusion. Incomplete-download and unreadable-identity messages are now distinct.

Validated with 2,594 macOS safe Rust tests, a 16-test Library suite, two-device encrypted-chain fixtures and actual loopback OpenSSH login/exec for unknown and changed fingerprints during background sync. [Windows CI](https://github.com/ysya/sshelter/actions/runs/38839305132) passed the complete safe suite, all three profiles, app and CLI builds, real console checks and OpenSSH client/engine login checks.

The affected production chain is on another Mac and was not available here. Its exact data still needs acceptance after updating both devices; no reset, chain deletion or vault changes are required by this fix.

Includes Beta 11 host-editor and Records MCP improvements. Restart or reconnect your MCP client after updating to refresh its tools. New or changed fingerprints still require your explicit decision in SSHelter.

Beta update channel only. Stable remains v0.16.0. The macOS CoreAudio startup guard remains in place; this does not claim to cure the system audio deadlock.
