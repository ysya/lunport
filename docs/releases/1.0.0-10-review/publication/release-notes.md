macOS startup and recovery safeguards

- Check CoreAudio in a bounded, killable child process before creating macOS WebViews. Errors and timeouts show a native Retry / Diagnostics / Keep Running alert.
- Keep background SSH/MCP broker, CLI Connect and ASKPASS independent of GUI health checks. Apply the same guard to main, authentication, host-key and key-approval windows.
- Replace WebContent's default automatic reload with an explicit native recovery choice and a one-reload-per-window limit. Keep native diagnostics available when web rendering is unavailable.
- Preserve existing windows, SSH backend state and unsaved edits when a health check fails; pending security prompts are denied without adding trust or remembered approval. WebContent process death can still lose memory-only drafts.

Validation: 1,056 frontend tests, 2,566 local macOS safe Rust tests, Development fault injection and native UI checks; Linux and Windows CI passed. The first remote macOS test job stalled and was cancelled; its retry subsequently passed, and local equivalent tests passed. See docs/2026-10-16-macos-startup-guard-validation.md at the release source for evidence and remaining device checks.

This prevents detectable pre-WebView CoreAudio failures from becoming an unexplained black window. It does not fix the underlying system audio deadlock or guarantee detection of later GPU stalls. Actual hardware sleep/wake, physical global shortcuts and additional-device UI validation remain pending.

Beta update channel only. Stable remains unchanged.
