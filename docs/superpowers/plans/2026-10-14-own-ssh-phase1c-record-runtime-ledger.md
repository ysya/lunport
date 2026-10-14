# Active Record Runtime Ledger

Pre-flight: verified current v3 shape validation allows global relationship conflicts; existing runtime core owns state/generation/account keys and compatibility publication/material guards. runtime.rs reserved by compatibility worker until explicit handoff.
Ruling: probe cap 64 MiB matches bounded vault ceiling; oversized inputs block without read/rename — keeps startup memory bounded with room for multiple chains — cost if wrong: raise explicit bound with migration review.
Ruling: fresh identity reuses SyncStateV2::fresh construction only, never its loader or saver — preserves existing entropy/default relay contract without legacy side effects — cost if wrong: small constructor extraction.

Task 1 RED: 9 startup/persistence behaviors failed against API stubs (3 imported AppError tests passed). Task 1 GREEN: 9/9 runtime behaviors in isolated harness; same-source v3 validators, production legacy data declarations and atomic-write implementation, no live app/credentials/network.
Ruling: StartupProbe::Blocked carries public error kind and generic reason, never raw unvalidated fields — avoids secret/log leaks from malformed future bytes — cost if wrong: less diagnostic detail in UI.
Ruling: Legacy probe activation sets legacy_paused until explicit old-workspace choice/migration; v1 remains pure source without a v2 shell or auto upgrade — preserves originals — cost if wrong: user must choose before old features resume.
Ruling: activate_probe is startup-only unless caller holds lifecycle/vault/format_publication before core during later migration — prevents crossing a live material transaction — cost if wrong: late activation must add those locks.
Compatibility handoff: e369d07 released runtime.rs after 488 focused tests. Root whole-gate compile snapshot completed before core fields were added; root owns unrelated five fixture/repository test contract fixes.

Task 2 RED: official active-runtime API stubs failed all14 new behaviors (one matched pre-existing active saver test passed); log /private/tmp/sshelter-record-runtime-active-red.log. Typed test panic closures corrected explicitly before meaningful RED.
Task 2 GREEN: real crate record_runtime 26/26, then additional observers/unsaved/activation coverage 29/29.
Ruling: successful candidate calls always durably persist and advance generation, including identical candidates — root requires receipt durability — cost if wrong: extra save for idempotent pin calls.
Ruling: whole-state candidate CAS requires every future v3 content/seq/dirty mutation to advance snapshot generation, or latest-state rebase under core — prevents overwriting background changes — cost if wrong: background API integration must add generation updates.
Ruling: active-state snapshot refuses competing legacy fields; legacy guards independently refuse records Some even if the format was temporarily left Legacy — enforces one active owner — cost if wrong: fixture/activation must clear competing fields.
Shared schema changes synchronized: migration_gate None and shared_writes_blocked false in both owned constructors; shape validation covers these markers without blocking valid relationship conflicts.
Final verification: cargo test --manifest-path src-tauri/Cargo.toml --offline --lib sync::record_runtime:: →29 passed; sync::runtime:: →8 passed; sync::round:: →58 passed. All use existing main target cache and safe fixtures. Logs /private/tmp/sshelter-record-runtime-final.log, /private/tmp/sshelter-runtime-legacy-regressions.log, /private/tmp/sshelter-round-legacy-regressions.log.
Root owns final whole-safe-suite and independent integration review; requested no duplicate whole gate.
