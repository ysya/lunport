# Library management validation

## Group ordering and compatibility

Group rows can move among siblings by pointer drag, the row menu, or Alt/Option + Up/Down. Reset restores name ordering. Root and nested Groups use the same rank list without changing parent relationships, Group payloads or connection defaults. Hidden and unselected Group IDs retain their positions. The native macOS Development App verified root drag, child menu moves, keyboard focus retention, name reset and persistence after restart. Pointer gestures preserve Tauri's native file-drop support used by SSH key import on Windows.

Account ordering is an encrypted `meta:library-group-order` record with payload schema 1. The account wire schema remains 4 and Group payload schema remains 1. Existing timestamp/device ordering resolves concurrent offline changes; the latest complete ordering wins. A revision and expected-ID comparison rejects stale UI edits. Future or unreadable order metadata stays retained and prevents overwriting that identity.

The compatibility harness runs against the actual published v1.2.0 source, commit `cc3ce196cad26775ddf5d3cbd9c8d189a8b79fa8`, in a disposable archive. It proves that the old decoder retains the new ciphertext, continues ordinary sync writes and can still edit Groups. The old app displays name ordering. Run `bash scripts/validate-group-order-compat.sh`; Linux CI runs the same harness. New-client tests prove that an upgraded old cache admits its retained ordering even with an empty delta pull. This regression failed before the retained-cache admission fix and passes afterward. Newer dirty ordering and unsupported future formats retain their authority.

The local state decoder adds version 5 for local ordering, typed navigation caches and authenticated navigation hints. On first publication of these data, the exact previous v3/v4 state is saved as `sync-state-v<version>-<sha256>.backup.json` before replacement. Tests cover exact bytes, one-time backup, remote metadata publication and restart. Mixed-device sync compatibility does not imply local binary downgrade compatibility: restoring an old binary requires restoring the saved previous state. Leaving sync remaps ordered Group IDs to preserved local Groups; rotation retains the independent account ordering.

## Known hosts

Settings → Connections and host details open the same manager. Lunport identities show endpoint, algorithm, fingerprint, verification time, originating device and local/synced scope. Verify uses the existing trust flow. Forget clears only the selected pin, validates the exact endpoint, revision and displayed identity under the existing state lock, and respects shared-write gates. Three native tests cover those contracts and retained connection/key settings.

The separate OpenSSH tab reuses the existing local-file manager with search, reload, fingerprint copy, hashed-name labeling and confirmation. Removal checks a digest of the complete displayed line as well as its position/host field, then uses existing backups and atomic writes. A same-host key replacement is rejected without touching the file. CRLF/LF line endings yield the same displayed-line digest.

Native review found that the shared file panel needed its own TooltipProvider when opened from Records. A populated-panel render regression reproduced the failure before the fix, then passed. Native Settings now displays both ordinary and hashed fixtures, and search/reset works. The native review opened and cancelled identity-forget confirmation; backend tests exercise actual mutations in isolated fixtures.

## Manual connection checks

Check port resolves the saved effective endpoint, applies a three-second total deadline and limits concurrent checks to four. It tries up to eight DNS addresses concurrently, closes successful sockets immediately, reads no login credentials and makes no trust decision. A target edit/deletion invalidates an in-flight result. Jump-host routes direct users to Verify fingerprint through the existing configured route instead of probing the destination directly.

Native review used a disposable loopback listener to verify reachable and refused results. Two native tests verify real TCP success/refusal and that a failed address cannot hide a reachable address. UI labels describe each check and its time; a failure does not label the server offline. This is TCP reachability, not ICMP ping or continuous monitoring.

## Checks and cleanup

- TypeScript, all 86 frontend files / 1,078 tests, and the production Vite build pass.
- The complete safe macOS Rust suite passes; personal credential tests and Linux PAM paths are delegated to their existing isolated CI jobs. Focused navigation, stale-edit, compatibility, leave, rotation, backup, pin and file-removal regressions pass.
- Screenshots are retained in [the native review directory](ui-review/2026-10-17-library-management/).
- Development App test state and sandbox known_hosts were restored byte-for-byte from their pre-review backup after quitting the app. Only this review's format backup was removed; the disposable TCP server was stopped. Production App data and the personal SSH file were not used.
- No dependencies, published identifiers, updater keys, signing identity or native file-drop configuration changed.
