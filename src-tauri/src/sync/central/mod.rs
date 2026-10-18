//! Central sync protocol. Not connected to production transport until device authorization,
//! verified membership and migration are in place. Login alone never supplies content keys.
pub mod api;
pub mod browser;
pub mod bootstrap;
pub mod client_state;
pub mod credentials;
pub mod controller;
pub mod commands;
pub mod crypto;
pub mod membership;
pub mod oidc;
pub mod pairing;
pub mod recovery;
pub mod rekey;
pub mod replica;
pub mod trust;
pub mod wire;
pub mod workspace;
