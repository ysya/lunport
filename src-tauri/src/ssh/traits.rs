//! The engine interface, as spec §6.1 writes it. Everything here is synchronous: the broker, the CLI and the MCP adapter run on plain
//! threads, and the engine hides its own runtime. Nothing in this file names russh.
//!
//! Two additions to the spec's block, both forced by the engine's job: `ShellChannel` is `Send + Sync` (a shell is read on one thread
//! while another writes, which needs a shared reference), and `AuthSource::public_key` exists (russh's public-key login announces the
//! public key before it asks for a signature, and neither `Hop` nor `sign` carries it).

use std::time::{Duration, Instant};

use super::error::{AuthError, ConnectError, SessionError};
use super::types::{DisconnectReason, ExecResult, Exit, HopRef, HostKey, HostKeyVerdict, Prompt, Pty, RsaHash, Secret, Signature, Target};

/// Opens connections. Implemented by the russh engine and by the fake used in broker, MCP and CLI tests.
pub trait SshEngine: Send + Sync {
    /// Connects to every hop of `target` in order, checks each hop's host key with `host_keys`, logs in with `auth`, and returns the
    /// session that owns the whole chain. Blocks until it is done or has failed; every wait inside is bounded.
    ///
    /// A host key that is not pinned never waits for the user: the call fails with `ConnectError::HostKeyUnknown` (or `HostKeyMismatch`)
    /// carrying the key the server presented, and the caller connects again once the user has decided (spec §6.2 step 3).
    fn connect(&self, target: &Target, host_keys: &dyn HostKeyPolicy, auth: &dyn AuthSource) -> Result<Box<dyn Session>, ConnectError>;
}

/// One live connection (a whole jump chain), owned by whoever holds it. Dropping it closes it.
pub trait Session: Send + Sync {
    /// Opens a PTY shell on the destination host. Any number of channels can be open at once.
    fn shell(&self, pty: Pty) -> Result<Box<dyn ShellChannel>, SessionError>;

    /// Runs `command` without a PTY and collects its output, for at most `timeout`. Output beyond `output_cap` bytes (stdout and stderr
    /// together) is not read: the engine asks for the channel to be closed, sets `truncated` and ends the result as `Ended::Truncated`. A command that ends without a
    /// status, a timeout and the cap are results, not errors, and the connection survives all three.
    ///
    /// `timeout` bounds the wait for the command's output. The engine bounds the other waits of the call on their own (opening the channel,
    /// handing a request to the connection), so on a connection that has stopped answering the call can outlast a short `timeout`; it
    /// then ends as `Ended::TimedOut`, or fails with `SessionError::Timeout` (a request was not taken) or `SessionError::Channel` (the
    /// channel did not open).
    fn exec(&self, command: &str, timeout: Duration, output_cap: usize) -> Result<ExecResult, SessionError>;

    /// Whether the connection (every hop of it) is still up, judged from the connection's own state and never from an error variant.
    fn is_alive(&self) -> bool;

    /// Why the connection ended, taken from the outermost hop that recorded a reason. `None` while it is alive.
    fn disconnect_reason(&self) -> Option<DisconnectReason>;

    /// Closes the connection: an explicit disconnect on every hop, innermost first. Safe to call twice.
    fn close(&self);
}

/// An open shell. `read` blocks, so a shell is read on one thread while another writes.
pub trait ShellChannel: Send + Sync {
    /// Sends keystrokes (or pasted text) to the shell's stdin. A connection whose peer has stopped reading does not take them: after a
    /// while (the russh engine waits 30 s) the call fails with `SessionError::Timeout`.
    fn write(&self, data: &[u8]) -> Result<(), SessionError>;

    /// Reads terminal output (stdout and stderr arrive merged on a PTY) into `buf` and returns how many bytes it wrote. Blocks until
    /// there is something to read. 0 means the shell has ended and everything it wrote has been read; `buf` must not be empty.
    ///
    /// Reading is what keeps the connection healthy: the engine drains the channel on its own, into a bounded buffer, and when the
    /// reader falls so far behind that the buffer is full it drops the newest output and puts a one-line notice in the stream.
    fn read(&self, buf: &mut [u8]) -> Result<usize, SessionError>;

    /// The terminal was resized. Sent to the server right away; the server ignores a resize that arrives before the PTY exists, so a
    /// caller that has a size to apply sends it after `Session::shell` returns (the broker remembers the last one, spec §7.2). A
    /// connection whose peer has stopped reading does not take it: after a few seconds the call fails with `SessionError::Timeout`.
    fn window_change(&self, cols: u16, rows: u16) -> Result<(), SessionError>;

    /// How the shell ended; `None` until it has. When `read` has returned 0 this is `Some`.
    fn exited(&self) -> Option<Exit>;

    /// Closes the channel (the connection stays up). A blocked `read` returns 0.
    fn close(&self);
}

/// Decides whether a server's host key is trusted.
pub trait HostKeyPolicy: Send + Sync {
    /// Called while the handshake is in progress, so it must be fast and must not block: a lookup, never a dialog.
    fn check(&self, hop: &HopRef, key: &HostKey) -> HostKeyVerdict;
}

/// Where the engine gets signatures and secrets. Implemented by the broker, which decides who is asked (spec §6.1, decision 7).
pub trait AuthSource: Send + Sync {
    /// The public half of the vault key `key_id` as an OpenSSH line (`<algorithm> <base64> [comment]`); `None` when there is no such key,
    /// in which case the key method is skipped.
    fn public_key(&self, key_id: &str) -> Option<String>;

    /// Signs `data` with the vault key `key_id` and returns the signature blob. For an RSA key `rsa_hash` is the hash to use; the engine
    /// never calls this for an RSA key it would have to sign with SHA-1. Must be quick: passphrases, vault unlocking and approvals are
    /// done before `connect` is called, because the connection waits for the answer without reading the socket.
    fn sign(&self, key_id: &str, data: &[u8], rsa_hash: Option<RsaHash>) -> Result<Signature, AuthError>;

    /// The password for `hop`, or `None` when there is none: the password method is then skipped. When a hop starts with the password
    /// method the engine calls this before it opens the connection, so asking the user here is fine; as a fallback after a refused key
    /// it is called during the login and must be quick.
    fn password(&self, hop: &HopRef) -> Option<Secret>;

    /// The answers to one keyboard-interactive round, one per prompt, given before `deadline`; `None` abandons the login and the engine
    /// drops the connection. An answer that arrives after the deadline is not used either.
    fn interactive(&self, hop: &HopRef, prompts: &[Prompt], deadline: Instant) -> Option<Vec<Secret>>;
}
