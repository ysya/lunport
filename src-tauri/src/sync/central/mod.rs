//! Central sync protocol. Not connected to production transport until device authorization,
//! verified membership and migration are in place. Login alone never supplies content keys.
pub mod api;
pub mod account_access;
pub mod browser;
pub mod bootstrap;
pub mod client_state;
pub mod credentials;
pub mod controller;
pub mod devices;
pub mod joining;
pub mod commands;
pub mod crypto;
pub mod membership;
pub mod library_page;
pub mod oidc;
pub mod pairing;
pub mod payload;
pub mod recovery;
pub mod recovery_read;
pub mod replacement_archive;
pub mod rekey;
pub mod round;
pub mod rotation;
pub mod rotation_runtime;
pub mod replica;
pub mod trust;
pub mod wire;
pub mod workspace;

#[cfg(test)]
mod device_tests;
