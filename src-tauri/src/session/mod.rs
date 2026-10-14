//! The session broker (own-ssh spec §4, §7): it opens SSH sessions for its clients over the local IPC endpoint (a socket on macOS and
//! Linux, a named pipe on Windows) — protocol-1 `sshelter connect` and the protocol-2 MCP adapter — asks the client (or the app's
//! window, for host keys) what a login needs, and relays the terminal. Every SSH call it makes blocks, so it runs on plain threads, never
//! in async code and never on the UI thread.

use std::path::{Path, PathBuf};

/// The broker's socket in the app's data directory (spec §4): `<app data>/ipc/sock`. The CLI finds it the same way, without the app.
/// Windows has the named pipe instead (`pipe_name`).
#[cfg(unix)]
pub fn socket_path(app_data: &Path) -> PathBuf {
    ipc_dir(app_data).join("sock")
}

/// The broker's named pipe on Windows (spec §4): `\\.\pipe\sshelter-session-<…>`, named after the user as the agent's pipe is. The CLI
/// finds it the same way, without the app.
#[cfg(windows)]
pub fn pipe_name() -> std::io::Result<String> {
    crate::ipc::pipe_windows::pipe_name_for(crate::app_profile::CURRENT.pipe_role(crate::app_profile::IpcRole::Session))
}

/// The broker's directory: its `lock`, and on macOS and Linux its `sock` (`ipc::server::take_lock` makes it owner-only).
pub fn ipc_dir(app_data: &Path) -> PathBuf {
    app_data.join("ipc")
}

/// The broker's state in the app (`AppState::session`).
#[derive(Default)]
pub struct SessionRuntime {
    pub auth_questions: std::sync::Arc<auth_window::AuthHub>,
    /// The host key questions waiting for the window.
    pub host_keys: std::sync::Arc<hostkey_window::HostKeyHub>,
    /// The broker, once `app::start` built it.
    pub broker: std::sync::Mutex<Option<std::sync::Arc<broker::Broker>>>,
    pub status: std::sync::Mutex<app::BrokerStatus>,
}

pub mod app;
pub mod auth;
pub mod auth_window;
pub mod broker;
pub mod connect;
pub mod directory;
pub mod format_directory;
pub mod record_directory;
pub mod record_material;
pub(crate) mod os_identity;
pub mod hostkey_window;
pub mod pins;
pub mod protocol;
pub mod relay;
pub mod ssh_config_directory;
pub mod ssh_g;
#[cfg(test)]
pub mod testing;
