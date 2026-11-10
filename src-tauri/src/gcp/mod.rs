//! Google Cloud for the SSH engine: a saved host whose first hop
//! is a GCE instance can be reached through Identity-Aware Proxy TCP forwarding, with no `gcloud` process. `relay` is the SSH Relay v4
//! wire format as gcloud speaks it, `iap` the WebSocket tunnel with its reconnects, `auth` the Google credentials read from the files
//! `gcloud auth login` leaves behind, `oslogin` and `pam` the REST calls the broker makes before connecting (the POSIX username, the key
//! registration, the Privileged Access Manager grant check), and `rest` the blocking client behind them.
//!
//! `cli` finds and runs the gcloud executable for the account actions of the Google Cloud page, the one place
//! Lunport runs gcloud.
//!
//! `cloudsql` is the Cloud SQL Admin API behind the saved databases: an instance's connect settings, the client certificate Cloud SQL
//! signs for a key made for one connection, and a project's PostgreSQL instances. `cloudsql_tls` dials the instance with that
//! certificate, over TLS 1.3, and checks the server certificate against the instance's own certificate authorities.
//!
//! `relay.rs` and `iap.rs` are ported from gcloud (Apache License 2.0); see `NOTICE.md` in this directory.

pub mod auth;
pub mod cli;
pub mod cloudsql;
pub mod cloudsql_tls;
pub mod credentials;
pub mod iap;
pub mod oslogin;
pub mod pam;
pub mod relay;
pub mod rest;
#[cfg(test)]
pub mod testing;
