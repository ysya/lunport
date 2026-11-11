//! Sync: the Records library and its central sync.
//!
//! - `records_v3`: the pure record model (hosts, groups, keys, the local state and its versions); `record_*`: the repository,
//!   import, migration review, export, conflicts, keys and the Tauri commands around it; `central/`: Passkey accounts and
//!   end-to-end encrypted multi-device sync (`sync/central/mod.rs` has its own map). `transports`, `tunnel_rules`, `pam_records`
//!   and `databases` are the records that ride along in the Catalog.
//! - `crypto`, `record`, `reconcile`: record encryption and the sealed-record encoding `AccountState` keeps.
//! - `state`, `state_v2`, `slot_rules`: the formats of the retired Legacy workspace, kept to decode an old state file, its sealed
//!   key material and its key-slot file names for the migration review and central's backup admission. Nothing writes them.
//! - `relay`: the historical chain relay's types the old states carry and the poll timing helpers central's round reuses.
//! - `env`: the engine's boundary (keychain, events, clock); `runtime`: `SyncCore`, the app's one state holder; `engine`: the
//!   Tauri shell (the engine lock, the `lunport-sync` background thread that runs `central::round`, the events).
//! - `testkit` (tests only): a disposable device with a home, a keychain and a state path.

pub mod records_v3;
pub mod record_repository;
pub mod record_groups;
pub mod group_order;
pub mod record_library;
pub mod record_runtime;
pub mod record_commands;
pub mod record_export;
pub mod record_merge;
pub mod record_conflicts;
pub mod central;
pub mod record_import;
pub mod record_keys;
pub mod record_account;
pub mod record_round;
pub mod record_migration;
pub mod record_leave;
pub mod record_rotation;
pub mod crypto;
pub mod engine;
pub mod env;
pub mod reconcile;
pub mod record;
pub mod relay;
pub mod runtime;
#[cfg(windows)]
pub mod slot_files_windows;
pub mod slot_rules;
pub mod state;
pub mod state_v2;
#[cfg(test)]
pub mod testkit;
pub mod databases;
pub mod pam_records;
pub mod transports;
pub mod tunnel_rules;

#[cfg(windows)]
pub(crate) mod central_files_windows;
