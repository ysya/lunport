# Records Tray Implementation Plan

Approved binding design and standing autonomous authorization apply. Ownership: src-tauri/src/tray.rs and this dedicated plan/ledger; root owns engine/lib integration. Do not alter other workers' files.

Goal: menu entries identify records by stable host ID and refuse unavailable routes or a retired runtime mode without reading legacy configuration, Keychain or private material in Records.

Architecture: pure public repository snapshot -> bounded menu entry DTOs -> existing thin Tauri menu builder. Menu clicks spawn a worker; publication/core guards validate the latest mode, then record route readiness before launching --id. Legacy clicks must pass the current Legacy/unpaused/no-records/save-block guard before reading doc. No lifecycle/vault/credential access and no main-menu thread locks.

- [x] RED pure data tests: stable IDs, duplicate aliases/context, blocked readiness and jumps, capacity, selected spaces, duplicate IDs, safe labels and legacy/current-mode guards.
- [x] GREEN implementation: reusable menu builder, pub rebuild_record_tray(app,state), guarded records/legacy click worker.
- [x] Focused tray tests only; inspect diff, exact three-path conventional commit under shared index flock. Root integrates events and owns whole Rust gate.

Records Available is metadata coherence only. The session broker verifies physical/private material; the tray never opens it. A publication guard on click workers keeps a retired menu event from crossing mode publication while terminal detection and process spawn run, without holding core/doc during external process work.

Verification: initial focused RED had 3 existing tests pass / 8 new tests fail. Final focused tray suite passed 13/13 (3 existing + 10 new), with shared safe fixture tests only. No app, terminal, Keychain, relay or real user host accessed. Root owns event integration and whole Rust gate.
