//! The engine's errors. Their `Display` text is the sentence the user sees (own-ssh spec §11); none of them carries a key or a password.
//! A failure behind a jump host is reported on the hop where it happened (`Unreachable`'s `reason` names the jump host when the jump host
//! could not reach the next one); spec §11's `Could not connect through {jump alias}: {reason}` is the broker's wording of it, as are the
//! sentences that need the keepalive seconds or "while the command was running".

use std::fmt;

use super::types::{AuthMethod, HopRef, HostKey, Phase};

/// Why `SshEngine::connect` did not produce a session.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ConnectError {
    /// The target has no hops, or lists a host twice (a jump loop).
    BadJumpChain { why: String },
    /// DNS or TCP failed, or the jump host could not open a connection to `hop`.
    Unreachable { hop: HopRef, reason: String },
    /// The Google Cloud IAP tunnel that carries `hop` could not be opened. `text` is the whole sentence (design 2026-10-25, "Error
    /// texts"): it names the instance and the account, which `Unreachable`'s "Could not reach host:port" would not. `code` is the relay's
    /// close code when IAP closed the tunnel (4033: not authorized), for the broker's note about a grant IAP does not see yet.
    Tunnel { hop: HopRef, text: String, code: Option<u16> },
    /// `hop` did not answer in time: its `connect_timeout` ran out during `phase`, or the server stopped answering the login. The wait for
    /// the handshake and for each login request can end sooner than `connect_timeout` when the keepalive interval is short (see `Hop`).
    Timeout { hop: HopRef, phase: Phase },
    /// Nothing is pinned for `hop` and the server presented `key`. The caller asks the user, pins the key and connects again.
    HostKeyUnknown { hop: HopRef, key: HostKey },
    /// `hop` presented `key`, but `pinned` is on record.
    HostKeyMismatch { hop: HopRef, key: HostKey, pinned: HostKey },
    /// The two sides share no host key algorithm. `ours` and `theirs` are the lists.
    NoCommonHostKeyAlgorithm { hop: HopRef, ours: Vec<String>, theirs: Vec<String> },
    /// Every method was refused or could not be tried. `tried` lists the methods that were attempted, possibly none (a key that is not in
    /// the vault, no password to give); `reason` explains what the method list alone does not (for example that the server accepts RSA
    /// keys only with SHA-1); empty for a plain refusal. `password_wanted`: the server's last list of login methods still has the password
    /// method and no password was tried on this connection (the auth source had none, or the login did not get to the method): a password
    /// typed now could get in. The caller can ask the person and connect again with the hop as it is: the methods go in the same order, and
    /// `AuthSource::password` returns the typed password from memory at once, because nobody may wait for a person while a connection is
    /// open (spec §6.2 step 4). Putting the password first would drop the key from a server that wants `publickey,password`; only a hop
    /// with no password method in its sequence (one that starts with keyboard-interactive) is connected again with the password first.
    AuthFailed { hop: HopRef, tried: Vec<AuthMethod>, reason: String, password_wanted: bool },
    /// Login stopped on our side (signer failure, cancelled or overdue prompt) and the connection was dropped.
    AuthAbandoned { hop: HopRef, reason: String },
    /// Any other protocol or I/O failure, as text.
    Protocol { hop: HopRef, text: String },
}

fn phase_text(phase: Phase) -> &'static str {
    match phase {
        Phase::Tcp => "the TCP connection",
        Phase::Handshake => "the SSH handshake",
        Phase::Auth => "login",
    }
}

impl fmt::Display for ConnectError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ConnectError::BadJumpChain { why } => write!(f, "The jump chain cannot be used: {why}"),
            ConnectError::Unreachable { hop, reason } => write!(f, "Could not reach {}:{} ({reason}).", hop.hostname, hop.port),
            ConnectError::Tunnel { text, .. } => f.write_str(text),
            ConnectError::Timeout { hop, phase } => write!(f, "Could not reach {}:{} (timed out during {}).", hop.hostname, hop.port, phase_text(*phase)),
            ConnectError::HostKeyUnknown { hop, .. } => write!(f, "The host key of {} has not been confirmed yet.", hop.alias),
            ConnectError::HostKeyMismatch { hop, .. } => write!(f, "The host key of {} changed. Connection refused.", hop.alias),
            ConnectError::NoCommonHostKeyAlgorithm { hop, ours, theirs } => {
                write!(f, "Could not agree on a host key algorithm with {}: the server offers {}, Lunport accepts {}.", hop.alias, theirs.join(", "), ours.join(", "))?;
                if theirs.iter().any(|name| name == "ssh-rsa") && !ours.iter().any(|name| name == "ssh-rsa") {
                    write!(f, " Lunport does not use ssh-rsa (SHA-1).")?;
                }
                Ok(())
            }
            ConnectError::AuthFailed { hop, tried, reason, .. } => {
                if tried.is_empty() {
                    write!(f, "Authentication failed for {}@{} (no login method could be tried).", hop.user, hop.alias)?;
                } else {
                    let names: Vec<&str> = tried.iter().map(AuthMethod::name).collect();
                    write!(f, "Authentication failed for {}@{} (tried: {}).", hop.user, hop.alias, names.join(", "))?;
                }
                if !reason.is_empty() {
                    write!(f, " {reason}")?;
                }
                Ok(())
            }
            ConnectError::AuthAbandoned { hop, reason } => write!(f, "Authentication for {} was abandoned ({reason}).", hop.alias),
            ConnectError::Protocol { text, .. } => write!(f, "SSH error: {text}"),
        }
    }
}

impl std::error::Error for ConnectError {}

/// Why a call on a live session failed. A command that was cut short is not an error: it is an `ExecResult` with `Ended::TimedOut`, `Ended::Truncated` or `Ended::Disconnected`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SessionError {
    /// The connection has ended; `Session::disconnect_reason` says why.
    Closed,
    /// A channel could not be opened or used (refused by the server, or the request failed).
    Channel(String),
    /// The connection did not take a request in time: the other end has stopped reading (a dead link that keepalive has not given up on
    /// yet), so there was no room to hand the request over. The connection may recover, or end by itself.
    Timeout,
}

impl fmt::Display for SessionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SessionError::Closed => write!(f, "The connection is closed."),
            SessionError::Channel(text) => write!(f, "SSH error: {text}"),
            SessionError::Timeout => write!(f, "The connection did not take the request in time."),
        }
    }
}

impl std::error::Error for SessionError {}

/// Why `AuthSource::sign` could not produce a signature.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AuthError {
    /// The key is not in the vault (any more) or has no private half on this computer.
    KeyUnavailable(String),
    /// The vault is locked, or the user refused to unlock it or to approve the use of the key.
    Refused(String),
    /// Signing itself failed.
    Failed(String),
}

impl fmt::Display for AuthError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AuthError::KeyUnavailable(why) => write!(f, "the key is not available: {why}"),
            AuthError::Refused(why) => write!(f, "the key was not released: {why}"),
            AuthError::Failed(why) => write!(f, "signing failed: {why}"),
        }
    }
}

impl std::error::Error for AuthError {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ssh::types::HostId;

    fn hop() -> HopRef {
        HopRef { id: HostId::from("h1"), alias: "web".into(), hostname: "web.example.com".into(), port: 2222, user: "deploy".into() }
    }

    fn key() -> HostKey {
        HostKey { algorithm: "ssh-ed25519".into(), public_key: vec![1, 2, 3], fingerprint: "SHA256:abc".into() }
    }

    /// The sentences are the ones in spec §11; the broker and the CLI show them as they are.
    #[test]
    fn connect_errors_read_like_the_messages_of_the_spec() {
        let cases = [
            (ConnectError::Unreachable { hop: hop(), reason: "connection refused".into() }, "Could not reach web.example.com:2222 (connection refused)."),
            (ConnectError::Timeout { hop: hop(), phase: Phase::Tcp }, "Could not reach web.example.com:2222 (timed out during the TCP connection)."),
            (ConnectError::Timeout { hop: hop(), phase: Phase::Handshake }, "Could not reach web.example.com:2222 (timed out during the SSH handshake)."),
            (ConnectError::Timeout { hop: hop(), phase: Phase::Auth }, "Could not reach web.example.com:2222 (timed out during login)."),
            (ConnectError::HostKeyMismatch { hop: hop(), key: key(), pinned: key() }, "The host key of web changed. Connection refused."),
            (ConnectError::HostKeyUnknown { hop: hop(), key: key() }, "The host key of web has not been confirmed yet."),
            (
                ConnectError::AuthFailed {
                    hop: hop(),
                    tried: vec![AuthMethod::Key { key_id: "k1".into() }, AuthMethod::Password],
                    reason: String::new(),
                    password_wanted: false,
                },
                "Authentication failed for deploy@web (tried: publickey, password).",
            ),
            (ConnectError::AuthAbandoned { hop: hop(), reason: "the prompt timed out".into() }, "Authentication for web was abandoned (the prompt timed out)."),
            (ConnectError::Protocol { hop: hop(), text: "Key exchange failed".into() }, "SSH error: Key exchange failed"),
            (ConnectError::BadJumpChain { why: "web appears twice".into() }, "The jump chain cannot be used: web appears twice"),
            // An IAP tunnel sentence is shown as it is: it names the instance, not the hostname and port the relay never uses.
            (ConnectError::Tunnel { hop: hop(), text: "IAP could not reach port 22 on jumpbox: nothing is listening.".into(), code: Some(4003) }, "IAP could not reach port 22 on jumpbox: nothing is listening."),
        ];
        for (error, text) in cases {
            assert_eq!(error.to_string(), text);
        }
    }

    #[test]
    fn an_auth_failure_reason_follows_the_sentence() {
        let error = ConnectError::AuthFailed {
            hop: hop(),
            tried: vec![AuthMethod::Key { key_id: "k1".into() }],
            reason: "The server only accepts RSA keys signed with SHA-1, which Lunport does not do.".into(),
            password_wanted: false,
        };
        assert_eq!(
            error.to_string(),
            "Authentication failed for deploy@web (tried: publickey). The server only accepts RSA keys signed with SHA-1, which Lunport does not do."
        );

        let nothing_tried =
            ConnectError::AuthFailed { hop: hop(), tried: vec![], reason: "The key k1 is not available on this computer.".into(), password_wanted: false };
        assert_eq!(
            nothing_tried.to_string(),
            "Authentication failed for deploy@web (no login method could be tried). The key k1 is not available on this computer."
        );
    }

    /// Whether a password could still get in is for the broker, not for the user's sentence.
    #[test]
    fn a_wanted_password_does_not_change_the_sentence() {
        let wanted = ConnectError::AuthFailed { hop: hop(), tried: vec![AuthMethod::Key { key_id: "k1".into() }], reason: String::new(), password_wanted: true };
        assert_eq!(wanted.to_string(), "Authentication failed for deploy@web (tried: publickey).");
    }

    #[test]
    fn no_common_algorithm_names_both_lists_and_explains_ssh_rsa() {
        let plain = ConnectError::NoCommonHostKeyAlgorithm { hop: hop(), ours: vec!["ssh-ed25519".into()], theirs: vec!["ssh-dss".into()] };
        assert_eq!(plain.to_string(), "Could not agree on a host key algorithm with web: the server offers ssh-dss, Lunport accepts ssh-ed25519.");
        let legacy = ConnectError::NoCommonHostKeyAlgorithm { hop: hop(), ours: vec!["ssh-ed25519".into(), "rsa-sha2-512".into()], theirs: vec!["ssh-rsa".into()] };
        assert_eq!(
            legacy.to_string(),
            "Could not agree on a host key algorithm with web: the server offers ssh-rsa, Lunport accepts ssh-ed25519, rsa-sha2-512. Lunport does not use ssh-rsa (SHA-1)."
        );
    }

    #[test]
    fn session_and_auth_errors_have_plain_messages() {
        assert_eq!(SessionError::Closed.to_string(), "The connection is closed.");
        assert_eq!(SessionError::Channel("channel open refused".into()).to_string(), "SSH error: channel open refused");
        assert_eq!(SessionError::Timeout.to_string(), "The connection did not take the request in time.");
        assert_eq!(AuthError::Refused("the vault is locked".into()).to_string(), "the key was not released: the vault is locked");
        assert_eq!(AuthError::KeyUnavailable("no such key".into()).to_string(), "the key is not available: no such key");
        assert_eq!(AuthError::Failed("bad key".into()).to_string(), "signing failed: bad key");
    }
}
