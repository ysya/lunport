# Records Tray Ledger

Pre-flight: inspected existing tray menu/click worker, repository public snapshot and chain API, SyncCore format/pause flags, launch_for_id and root event dispatch. No current tray edits from other workers.

Ruling: duplicate global IDs produce one disabled conflict row instead of duplicate menu IDs or an arbitrary host. Duplicate aliases retain stable IDs and display Local/space context; ambiguous display labels additionally show the full host ID.

Ruling: all-hop public readiness is checked before offering/clicking a connection. Available metadata is not private-material availability; broker remains authoritative for actual vault material.

Ruling: menu callback only parses event and spawns a thread; latest mode guards and publication lock stay off the menu thread. Legacy guard rejects Records/Blocked/paused/dual-owner/save-blocked state before doc access; no lifecycle/vault/Keychain acquisitions.

Verification: real-crate cargo test --offline --lib tray:: completed 13/13 GREEN; log /private/tmp/sshelter-record-tray-final.log. Added nonfirst-hop readiness and identical space-name/short-prefix regressions after initial 8-test RED. Rustfmt and git diff --check clean. rebuild_record_tray remains unused until root wires TauriEvents.status, as expected. No whole Rust suite rerun.
