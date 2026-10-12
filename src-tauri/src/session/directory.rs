//! Where the broker finds saved hosts (own-ssh spec §5.1, §6.2 step 1, §7.1): a host by alias or by host id, resolved into the jump chain
//! the engine connects through, with the pinned host keys in `Hop::pinned`; pinning a key the person trusted; and the keychain account
//! of a host's saved password. In this version the hosts are the app's ssh_config blocks, through a temporary adapter
//! (`ssh_config_directory.rs`; plan 1c replaces it with host records). The broker sees only this trait.

use std::fmt;

use super::protocol::HostQuery;
use crate::ssh::{HostId, HostKey, Target};

/// A pinned host key and when it was pinned (milliseconds since the Unix epoch).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PinnedKey {
    pub key: HostKey,
    pub pinned_at_ms: u64,
}

/// Why a host could not be found or a pin not written. The text is the sentence to show the user.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DirectoryError {
    /// No saved host matches.
    NotFound(String),
    /// Several saved hosts have this alias; the client has to name one by its id (spec §7.1).
    Ambiguous(String),
    /// The host is saved, but SSHelter's own client cannot connect to it (a ProxyCommand, a key that is not in SSHelter).
    Unsupported(String),
    /// Reading the saved hosts or the pins, or writing a pin, failed.
    Failed(String),
}

impl fmt::Display for DirectoryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DirectoryError::NotFound(text) | DirectoryError::Ambiguous(text) | DirectoryError::Unsupported(text) | DirectoryError::Failed(text) => {
                f.write_str(text)
            }
        }
    }
}

impl std::error::Error for DirectoryError {}

/// The saved hosts, as the broker needs them. Implementations are called from the broker's connection threads, never from async code.
pub trait HostDirectory: Send + Sync {
    /// The saved host `query` names, with its jump hosts in front (each a saved host too), ready for the engine. The pin of each hop is in
    /// `Hop::pinned`. A chain that loops or names a host that is not saved is an error here, before anything connects.
    fn resolve(&self, query: &HostQuery) -> Result<Target, DirectoryError>;

    /// The key pinned for `host`, if any. An error reading the pins is `Err`, never "nothing pinned": a host that was pinned must not
    /// look new because a file could not be read.
    fn pinned(&self, host: &HostId) -> Result<Option<PinnedKey>, DirectoryError>;

    /// Pins `key` for `host`: the person trusted it in the window. Pinning the key that is pinned already is fine; when another key was
    /// pinned in the meantime, nothing is written and the call fails.
    fn pin(&self, host: &HostId, key: &HostKey) -> Result<(), DirectoryError>;

    /// Replaces the pin of `host` with `key`: the person accepted a changed key. Only while `previous` is still the pinned key (or `key`
    /// already is); otherwise nothing is written and the call fails.
    fn replace_pin(&self, host: &HostId, previous: &HostKey, key: &HostKey) -> Result<(), DirectoryError>;

    /// The keychain account of the saved password of `host` (spec §5.5: `host:<host id>`).
    fn password_account(&self, host: &HostId) -> String;
}
