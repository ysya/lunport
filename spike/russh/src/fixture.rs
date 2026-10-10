//! Test setup shared by the integration tests: a scratch sshd that accepts one fresh Ed25519 user key, and the connect-and-log-in steps.

use russh::client::Config;
use russh::keys::HashAlg;

use crate::client::{connect, login_with_key_file, Connection, HostKeyVerdict};
use crate::harness::{generate_key, KeyKind, Sshd, SshdOptions, TestKey, Tools};
use crate::within;

pub struct Server {
    pub sshd: Sshd,
    /// The user key sshd accepts.
    pub key: TestKey,
    _keys: tempfile::TempDir,
}

impl Server {
    /// A scratch sshd with an Ed25519 host key, accepting one fresh Ed25519 user key. `extra_config` goes in front of the defaults.
    pub fn start(tools: &Tools, extra_config: &[&str]) -> Server {
        Server::start_with(tools, KeyKind::Ed25519, KeyKind::Ed25519, extra_config)
    }

    pub fn start_with(tools: &Tools, host_key: KeyKind, user_key: KeyKind, extra_config: &[&str]) -> Server {
        let keys = tempfile::tempdir().expect("temp dir for the user key");
        let key = generate_key(tools, keys.path(), "user", user_key);
        let sshd = Sshd::start(
            tools,
            SshdOptions {
                host_key,
                extra_config: extra_config.iter().map(|line| line.to_string()).collect(),
                authorized_keys: vec![key.public_line.clone()],
            },
        );
        Server { sshd, key, _keys: keys }
    }

    /// "SHA256:..." of this server's host key, computed with the ssh-key that russh pins.
    pub fn host_fingerprint(&self) -> String {
        russh::keys::PublicKey::from_openssh(&self.sshd.host_public_line)
            .expect("russh parses the host key line")
            .fingerprint(HashAlg::Sha256)
            .to_string()
    }

    /// Log `connection` in with the user key; panics (with sshd's log) when the server refuses.
    pub async fn login(&self, connection: &mut Connection) {
        let result = within(30, "publickey login", login_with_key_file(&mut connection.handle, &self.sshd.user, &self.key.private_path))
            .await
            .expect("the login call");
        assert!(result.success(), "sshd refused the user key; its log: {}", self.sshd.log());
    }

    /// Connect to `port` (this server's own, or a proxy's in front of it) and log in.
    pub async fn connect_and_login(&self, port: u16, config: Config, verdict: HostKeyVerdict) -> Connection {
        let mut connection = within(30, "connect", connect(port, config, verdict)).await.expect("connect");
        self.login(&mut connection).await;
        connection
    }

    /// The common case: default config, host key accepted, logged in.
    pub async fn session(&self) -> Connection {
        self.connect_and_login(self.sshd.port, Config::default(), HostKeyVerdict::AcceptAny).await
    }
}
