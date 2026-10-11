//! The data that crosses the engine interface (own-ssh spec §6.1). Plain data only: no russh type and no vault type appears here, so the
//! broker, the fake engine and a future hand-written engine can all use it.

use std::fmt;
use std::time::Duration;

use zeroize::Zeroizing;

/// The defaults of a host record (spec §5.1: `connect_timeout_secs` 15, `keepalive_secs` 30, `keepalive_max_missed` 3).
pub const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(15);
pub const DEFAULT_KEEPALIVE_EVERY: Duration = Duration::from_secs(30);
pub const DEFAULT_KEEPALIVE_MAX_MISSED: u32 = 3;

/// A password, passphrase or answer. Zeroed when dropped.
pub type Secret = Zeroizing<String>;

/// The id of a stored host record. It survives renames; the broker looks hosts up by it.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct HostId(pub String);

impl HostId {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl From<&str> for HostId {
    fn from(id: &str) -> HostId {
        HostId(id.to_string())
    }
}

impl From<String> for HostId {
    fn from(id: String) -> HostId {
        HostId(id)
    }
}

impl fmt::Display for HostId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Which hop a callback or an error is about: enough to name it in a dialog or a message and to look it up again.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HopRef {
    pub id: HostId,
    pub alias: String,
    pub hostname: String,
    pub port: u16,
    pub user: String,
}

/// A server's host key in the form a host record stores it (spec §5.1).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HostKey {
    /// The key type as OpenSSH names it: `ssh-ed25519`, `ecdsa-sha2-nistp256`, `ssh-rsa` (the key type, whatever hash the signature used).
    pub algorithm: String,
    /// The public key in SSH wire format (the bytes behind the base64 of an OpenSSH public key line).
    pub public_key: Vec<u8>,
    /// `SHA256:…`, as `ssh-keygen -l` prints it.
    pub fingerprint: String,
}

impl HostKey {
    /// From an OpenSSH public key line (`<algorithm> <base64> [comment]`). `None` when the line is not a key this app understands.
    pub fn from_openssh_line(line: &str) -> Option<HostKey> {
        let key = ssh_key::PublicKey::from_openssh(line.trim()).ok()?;
        Some(HostKey {
            algorithm: key.algorithm().to_string(),
            public_key: key.to_bytes().ok()?,
            fingerprint: key.fingerprint(ssh_key::HashAlg::Sha256).to_string(),
        })
    }
}

/// What a `HostKeyPolicy` says about the key a server presented.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HostKeyVerdict {
    /// The key is the one pinned for this host: go on.
    Pinned,
    /// Nothing is pinned for this host yet.
    Unknown,
    /// Something is pinned and this is not it. `pinned` is the key on record.
    Mismatch { pinned: HostKey },
}

/// The hash an RSA login signature uses. There is no SHA-1 variant on purpose: the engine refuses to sign with it (spec §6.3 b).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RsaHash {
    Sha256,
    Sha512,
}

/// A signature in the SSH wire form of the agent protocol: `string algorithm || string signature` (what `Material::sign` returns).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Signature(pub Vec<u8>);

/// One keyboard-interactive prompt.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Prompt {
    pub text: String,
    /// Whether what the user types may be shown.
    pub echo: bool,
}

/// A way to log in. `Hop::auth` is the one a hop starts with.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AuthMethod {
    /// Public-key login with the vault key `key_id`.
    Key { key_id: String },
    Password,
    Interactive,
}

impl AuthMethod {
    /// The method's name in the SSH protocol and in messages.
    pub fn name(&self) -> &'static str {
        match self {
            AuthMethod::Key { .. } => "publickey",
            AuthMethod::Password => "password",
            AuthMethod::Interactive => "keyboard-interactive",
        }
    }
}

/// One connection of a chain: a stored host with everything the engine needs to reach it and log in.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Hop {
    pub id: HostId,
    pub alias: String,
    pub hostname: String,
    pub port: u16,
    pub user: String,
    /// Where the login sequence starts. The sequence is key, password, keyboard-interactive, in that order; it starts at `auth` and moves
    /// on to the next method only when the server refuses (see `Hop::auth_sequence`).
    pub auth: AuthMethod,
    /// The key on record for this host. When it is set the handshake offers only that key's algorithm family, so a server that later
    /// adds another key type is not mistaken for a changed key. Whether a presented key is trusted is `HostKeyPolicy`'s decision.
    pub pinned: Option<HostKey>,
    /// TCP connect plus handshake must finish within this. Once the connection is open, the engine waits for the server's answer to the
    /// handshake and to each login request for this long at most, and less when `keepalive_every` is shorter: three quarters of it, but
    /// not under a second (a silence that outlasts the interval makes the engine's SSH library spin before the login is done).
    pub connect_timeout: Duration,
    /// How long the link may be silent before a keepalive is sent; `Duration::ZERO` turns keepalive off.
    pub keepalive_every: Duration,
    /// Unanswered keepalives tolerated: a dead link is noticed after (`keepalive_max_missed` + 1) × `keepalive_every`. 0 = never give up.
    pub keepalive_max_missed: u32,
    /// `TCP_NODELAY` on the socket of the first hop (set it for shells; Nagle delays keystroke echo).
    pub nodelay: bool,
}

impl Hop {
    /// A hop with the spec's default timeouts and `nodelay` on.
    pub fn new(id: &str, alias: &str, hostname: &str, port: u16, user: &str, auth: AuthMethod) -> Hop {
        Hop {
            id: HostId::from(id),
            alias: alias.to_string(),
            hostname: hostname.to_string(),
            port,
            user: user.to_string(),
            auth,
            pinned: None,
            connect_timeout: DEFAULT_CONNECT_TIMEOUT,
            keepalive_every: DEFAULT_KEEPALIVE_EVERY,
            keepalive_max_missed: DEFAULT_KEEPALIVE_MAX_MISSED,
            nodelay: true,
        }
    }

    pub fn reference(&self) -> HopRef {
        HopRef { id: self.id.clone(), alias: self.alias.clone(), hostname: self.hostname.clone(), port: self.port, user: self.user.clone() }
    }

    /// The methods to try, in order: from `auth` to the end of key, password, keyboard-interactive.
    pub fn auth_sequence(&self) -> Vec<AuthMethod> {
        match &self.auth {
            AuthMethod::Key { .. } => vec![self.auth.clone(), AuthMethod::Password, AuthMethod::Interactive],
            AuthMethod::Password => vec![AuthMethod::Password, AuthMethod::Interactive],
            AuthMethod::Interactive => vec![AuthMethod::Interactive],
        }
    }
}

/// A host record resolved for connecting: the jump chain and the destination, in the order they are connected. `hops` is never empty;
/// the last hop is the destination, every earlier one is a jump host.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Target {
    pub hops: Vec<Hop>,
}

/// The terminal a shell is opened with.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Pty {
    /// `$TERM` of the user's terminal, e.g. `xterm-256color`.
    pub term: String,
    pub cols: u16,
    pub rows: u16,
}

/// How a command ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ended {
    /// It ran to its end and reported an exit status.
    Exited,
    /// It was killed by a signal (`signal` says which); there is no exit status.
    Signaled,
    /// It was still running when the caller's timeout passed; the engine asked for the channel to be closed (the connection stays
    /// usable; on a connection that has stopped answering, that request is given up after a few seconds and the command runs on until
    /// the connection ends). `exit_code` can still be set: a command that has exited keeps its channel open for as long as a background
    /// job it started holds the output, and then it ends as `TimedOut` with the status it reported.
    TimedOut,
    /// Its output reached the caller's cap and the engine asked for the channel to be closed, as for `TimedOut` (`ExecResult::truncated`
    /// is true). Its exit status is unknown, and the connection is still alive and usable: this is not a lost connection.
    Truncated,
    /// The engine lost track of it: the channel ended without an exit status or a signal because the connection was lost.
    /// Never read this as exit code 0.
    Disconnected,
}

/// The result of `Session::exec`. Output is raw bytes: not decoded, line endings untouched (Windows OpenSSH ends lines with CRLF).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExecResult {
    pub ended: Ended,
    pub exit_code: Option<u32>,
    /// The signal name without the `SIG` prefix (`KILL`, `TERM`, …) when `ended` is `Signaled`.
    pub signal: Option<String>,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    /// The output reached the cap: `stdout` and `stderr` together are what fitted, the rest was not read. True exactly when `ended` is
    /// `Truncated`.
    pub truncated: bool,
}

/// How a shell ended.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Exit {
    Code(u32),
    /// Killed by this signal (name without the `SIG` prefix).
    Signal(String),
    /// The channel ended without a status: the connection was lost, or the server closed the channel.
    Disconnected,
}

/// Which part of connecting ran out of time.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Phase {
    Tcp,
    Handshake,
    Auth,
}

/// Why a connection ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DisconnectKind {
    /// `Session::close` (or dropping the session).
    ClosedByUs,
    /// The server sent a disconnect message.
    ClosedByPeer,
    /// `keepalive_max_missed` + 1 keepalives went unanswered.
    KeepaliveTimeout,
    /// The link broke (reset, end of stream).
    ConnectionLost,
    /// Anything else (a protocol error, an internal failure).
    Other,
}

/// The first recorded end of a connection, taken from the outermost hop that recorded one (spec §6.2 step 2).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DisconnectReason {
    /// The hop that recorded it.
    pub hop: HopRef,
    pub kind: DisconnectKind,
    /// A sentence for logs; never contains a key or a password.
    pub detail: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sync::slot_rules::test_keys;

    #[test]
    fn a_host_key_is_read_from_an_openssh_line_with_its_sha256_fingerprint() {
        let key = HostKey::from_openssh_line(&format!("{} root@server\n", test_keys::PLAIN_PUBLIC)).expect("an ed25519 line");
        assert_eq!(key.algorithm, "ssh-ed25519");
        let blob = key.public_key.clone();
        assert_eq!(&blob[..4], &[0, 0, 0, 11], "the wire format starts with the length of the algorithm name");
        assert_eq!(&blob[4..15], b"ssh-ed25519");
        assert_eq!(key.fingerprint, test_keys::PLAIN_FINGERPRINT);

        let key = HostKey::from_openssh_line(test_keys::ECDSA_PUBLIC).expect("an ecdsa line");
        assert_eq!((key.algorithm.as_str(), key.fingerprint.as_str()), ("ecdsa-sha2-nistp256", test_keys::ECDSA_FINGERPRINT));

        let key = HostKey::from_openssh_line(test_keys::RSA_PUBLIC).expect("an rsa line");
        assert_eq!((key.algorithm.as_str(), key.fingerprint.as_str()), ("ssh-rsa", test_keys::RSA_FINGERPRINT));
    }

    #[test]
    fn something_that_is_not_a_key_line_is_not_a_host_key() {
        assert_eq!(HostKey::from_openssh_line(""), None);
        assert_eq!(HostKey::from_openssh_line("ssh-ed25519"), None);
        assert_eq!(HostKey::from_openssh_line("ssh-ed25519 not-base64!"), None);
        assert_eq!(HostKey::from_openssh_line("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5"), None, "a blob that is cut short");
    }

    #[test]
    fn a_hop_starts_with_the_defaults_of_a_host_record_and_names_itself() {
        let hop = Hop::new("id-web", "web", "web.example.com", 2222, "deploy", AuthMethod::Password);
        assert_eq!((hop.connect_timeout, hop.keepalive_every, hop.keepalive_max_missed, hop.nodelay), (Duration::from_secs(15), Duration::from_secs(30), 3, true));
        assert_eq!(hop.pinned, None);
        let reference = hop.reference();
        assert_eq!((reference.id.as_str(), reference.alias.as_str(), reference.hostname.as_str(), reference.port, reference.user.as_str()), ("id-web", "web", "web.example.com", 2222, "deploy"));
        assert_eq!(reference.id.to_string(), "id-web");
    }

    #[test]
    fn the_login_sequence_runs_from_the_start_method_to_the_end_of_key_password_interactive() {
        let hop = |auth| Hop::new("h", "h", "h", 22, "u", auth);
        let key = AuthMethod::Key { key_id: "k1".into() };
        assert_eq!(hop(key.clone()).auth_sequence(), vec![key, AuthMethod::Password, AuthMethod::Interactive]);
        assert_eq!(hop(AuthMethod::Password).auth_sequence(), vec![AuthMethod::Password, AuthMethod::Interactive]);
        assert_eq!(hop(AuthMethod::Interactive).auth_sequence(), vec![AuthMethod::Interactive]);
    }

    #[test]
    fn auth_methods_carry_their_protocol_names() {
        assert_eq!(AuthMethod::Key { key_id: "k".into() }.name(), "publickey");
        assert_eq!(AuthMethod::Password.name(), "password");
        assert_eq!(AuthMethod::Interactive.name(), "keyboard-interactive");
    }
}
