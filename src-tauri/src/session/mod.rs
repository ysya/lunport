//! The session broker (own-ssh spec §4, §7): it opens SSH sessions for its clients over the local IPC socket — `sshelter connect` in this
//! version, the MCP adapter in phase 2 — asks the client (or the app's window, for host keys) what a login needs, and relays the
//! terminal. Every SSH call it makes blocks, so it runs on plain threads, never in async code and never on the UI thread.

pub mod auth;
pub mod connect;
pub mod directory;
pub mod pins;
pub mod protocol;
pub mod ssh_config_directory;
pub mod ssh_g;
#[cfg(test)]
pub mod testing;
