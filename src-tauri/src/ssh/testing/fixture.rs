//! Test setup shared by the engine tests: a scratch sshd that accepts one fresh user key, and the hops that reach it.

use super::harness::{generate_key, KeyKind, Sshd, SshdOptions, TestKey, Tools};
use crate::ssh::{AuthMethod, Hop, HostKey, Target};

/// A `/bin/sh` for the scratch sshd's shells (a line of its `extra_config`), so that the prompt depends on nobody's shell setup: the
/// interactive shell is the same POSIX sh on every machine, not the developer's zsh and its configuration. `ForceCommand` runs through
/// the user's login shell with `-c` and replaces every command, so it hands a requested command on to `eval`, which keeps `exec` usable
/// on the same server.
pub const SH_SHELL: &str = "ForceCommand if [ -n \"$SSH_ORIGINAL_COMMAND\" ]; then eval \"$SSH_ORIGINAL_COMMAND\"; else exec /bin/sh; fi";

pub struct Server {
    pub sshd: Sshd,
    /// The user key sshd accepts.
    pub key: TestKey,
    _keys: tempfile::TempDir,
}

impl Server {
    /// A scratch sshd with an Ed25519 host key, accepting one fresh Ed25519 user key. `extra_config` goes in front of the defaults.
    pub fn start(tools: &Tools, extra_config: &[&str]) -> Server {
        Server::start_with(tools, &[KeyKind::Ed25519], KeyKind::Ed25519, extra_config)
    }

    pub fn start_with(tools: &Tools, host_keys: &[KeyKind], user_key: KeyKind, extra_config: &[&str]) -> Server {
        let keys = tempfile::tempdir().expect("temp dir for the user key");
        let key = generate_key(tools, keys.path(), "user", user_key);
        let sshd = Sshd::start(
            tools,
            SshdOptions {
                host_keys: host_keys.to_vec(),
                extra_config: extra_config.iter().map(|line| line.to_string()).collect(),
                authorized_keys: vec![key.public_line.clone()],
            },
        );
        Server { sshd, key, _keys: keys }
    }

    /// The first host key, in the form a host record stores it.
    pub fn host_key(&self) -> HostKey {
        self.host_keys().remove(0)
    }

    /// Every host key the server has, in the order of its `HostKey` lines.
    pub fn host_keys(&self) -> Vec<HostKey> {
        self.sshd.host_public_lines.iter().map(|line| HostKey::from_openssh_line(line).expect("the host key line parses")).collect()
    }

    /// A hop to this server with the given login. `port` is the server's own, or a proxy's in front of it. The host id is `host-<alias>`.
    pub fn hop_with(&self, alias: &str, port: u16, auth: AuthMethod) -> Hop {
        Hop::new(&format!("host-{alias}"), alias, "127.0.0.1", port, &self.sshd.user, auth)
    }

    /// A hop that logs in with the vault key registered under `key_id` (the user key of this server), on the server's own port.
    pub fn hop(&self, alias: &str, key_id: &str) -> Hop {
        self.hop_with(alias, self.sshd.port, AuthMethod::Key { key_id: key_id.to_string() })
    }

    /// A direct target on the server's own port, logging in with the key registered under `key_id`.
    pub fn target(&self, key_id: &str) -> Target {
        Target { hops: vec![self.hop("server", key_id)] }
    }

    /// An auth source that holds this server's user key under `key_id`.
    pub fn vault(&self, key_id: &str) -> super::doubles::VaultAuth {
        super::doubles::VaultAuth::new().with_key(key_id, &self.key.private_text)
    }
}
