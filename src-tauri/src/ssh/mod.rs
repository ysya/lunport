//! SSHelter's own SSH engine (own-ssh spec §4, §6): the interface the broker, the CLI and the MCP adapter use (`SshEngine`, `Session`,
//! `ShellChannel`, `HostKeyPolicy`, `AuthSource`), a fake for their tests, and the russh-backed engine behind the interface.
//!
//! russh is imported by exactly one file, `russh_engine.rs`; a test below keeps it that way. Swapping the engine later means replacing
//! that file.

mod channel;
mod error;
#[cfg(test)]
pub mod fake;
mod traits;
mod types;

pub use channel::{ByteQueue, ExitCell, QueueRead, QueuedShell, ShellInput};
pub use error::{AuthError, ConnectError, SessionError};
pub use traits::{AuthSource, HostKeyPolicy, Session, ShellChannel, SshEngine};
pub use types::{
    AuthMethod, DisconnectKind, DisconnectReason, Ended, ExecResult, Exit, Hop, HopRef, HostId, HostKey, HostKeyVerdict, Phase, Prompt,
    Pty, RsaHash, Secret, Signature, Target, DEFAULT_CONNECT_TIMEOUT, DEFAULT_KEEPALIVE_EVERY, DEFAULT_KEEPALIVE_MAX_MISSED,
};
