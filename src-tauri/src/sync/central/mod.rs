//! Central sync protocol. Not connected to production transport until device authorization,
//! verified membership and migration are in place. Login alone never supplies content keys.
pub mod crypto;
pub mod membership;
pub mod oidc;
pub mod wire;
