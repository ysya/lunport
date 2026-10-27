//! Google Cloud for the SSH engine (design: `docs/superpowers/specs/2026-10-25-gcp-iap-oslogin-design.md`): a saved host whose first hop
//! is a GCE instance can be reached through Identity-Aware Proxy TCP forwarding, with no `gcloud` process. `relay` is the SSH Relay v4
//! wire format as gcloud speaks it, `iap` the WebSocket tunnel with its reconnects, `auth` the Google credentials read from the files
//! `gcloud auth login` leaves behind, `oslogin` and `pam` the REST calls the broker makes before connecting (the POSIX username, the key
//! registration, the Privileged Access Manager grant check), and `rest` the blocking client behind them.
//!
//! `cli` finds and runs the gcloud executable for the account actions of the Google Cloud page (design 2026-10-27), the one place
//! Lunport runs gcloud.
//!
//! `relay.rs` and `iap.rs` are ported from gcloud (Apache License 2.0); see `NOTICE.md` in this directory.

pub mod auth;
pub mod cli;
pub mod credentials;
pub mod iap;
pub mod oslogin;
pub mod pam;
pub mod relay;
pub mod rest;
#[cfg(test)]
pub mod testing;
