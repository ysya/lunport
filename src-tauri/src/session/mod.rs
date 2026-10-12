//! The session broker (own-ssh spec §4, §7): it opens SSH sessions for its clients over the local IPC socket — `sshelter connect` in this
//! version, the MCP adapter in phase 2 — asks the client (or the app's window, for host keys) what a login needs, and relays the
//! terminal. Every SSH call it makes blocks, so it runs on plain threads, never in async code and never on the UI thread.

use std::path::{Path, PathBuf};

/// The broker's socket in the app's data directory (spec §4): `<app data>/ipc/sock`. The CLI finds it the same way, without the app.
pub fn socket_path(app_data: &Path) -> PathBuf {
    ipc_dir(app_data).join("sock")
}

/// The broker's directory (its `lock` and `sock`; `ipc::server::listen_unix` makes it owner-only).
pub fn ipc_dir(app_data: &Path) -> PathBuf {
    app_data.join("ipc")
}

pub mod auth;
pub mod broker;
pub mod connect;
pub mod directory;
pub mod pins;
pub mod protocol;
pub mod relay;
pub mod ssh_config_directory;
pub mod ssh_g;
#[cfg(test)]
pub mod testing;
