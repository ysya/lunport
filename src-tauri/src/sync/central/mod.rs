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
pub mod migration;
mod migration_history;
pub mod library_page;
pub mod oidc;
pub mod pairing;
pub mod payload;
mod projection;
mod projection_cache;
pub mod projection_state;
mod projection_local;
mod projection_capture;
mod projection_delta;
pub(super) use projection_delta::Delta as LibraryDelta;
pub mod recovery;
pub mod recovery_read;
pub mod active_read;
mod active_flow;
pub mod recovery_state;
pub mod recovery_credentials;
pub mod recovery_flow;
pub mod recovery_revalidation;
pub mod replacement_archive;
pub mod replacement;
pub mod replacement_flow;
mod replacement_proof;
pub(crate) mod replacement_publication;
mod owner;
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

#[cfg(test)]
pub(super) use projection_state::tests::material_fixture as material_fixture_for_test;

#[cfg(test)]
pub(super) use projection_capture::public_candidate as capture_for_test;

#[cfg(test)]
pub(super) use projection_state::tests::initial as library_fixture_for_test;
#[cfg(test)]
pub(super) use projection_delta::tests::append as append_library_for_test;
