//! Task 2: russh's `Signer`, backed by the app's vault (`Material::sign`), logs in to a scratch sshd with every key type the vault signs.
#![cfg(feature = "app-vault")]

use russh::client::{AuthResult, Config};
use russh::keys::HashAlg;
use russh_spike::client::{connect, exec, HostKeyVerdict};
use russh_spike::fixture::Server;
use russh_spike::harness::{generate_key, tools, KeyKind, Tools};
use russh_spike::signer::VaultSigner;
use russh_spike::{fact, within};
use sshelter_lib::vault::material::open;

struct Login {
    result: AuthResult,
    signer: VaultSigner,
    /// What `best_supported_rsa_hash` said, as russh gave it: `Some(Some(hash))` = the server lists rsa-sha2-*; `Some(None)` = it sends
    /// `server-sig-algs` and lists ssh-rsa only; `None` = it sent no `server-sig-algs` at all.
    raw_hash: Option<Option<HashAlg>>,
    /// The same, flattened: `None` means plain ssh-rsa (SHA-1), whichever of the two ways above got there.
    hash_alg: Option<HashAlg>,
    /// What `echo` printed over the session that the vault's signature opened (empty when the login failed).
    echoed: String,
}

/// Logs in to `server` presenting `presented_public_line` and signing with the vault entry made from `signing_key_text`, then runs `echo`.
/// The two come from one key pair, except in the negative control at the end of this file.
async fn log_in_through_the_vault(server: &Server, presented_public_line: &str, signing_key_text: &str) -> Login {
    let material = open(signing_key_text, None).expect("the vault opens the OpenSSH key ssh-keygen wrote");
    let mut signer = VaultSigner::new(material);
    let public = russh::keys::PublicKey::from_openssh(presented_public_line).expect("russh parses the public key line");

    let mut connection = within(30, "connect", connect(server.sshd.port, Config::default(), HostKeyVerdict::AcceptAny)).await.expect("connect");
    let raw_hash = within(10, "server-sig-algs", connection.handle.best_supported_rsa_hash()).await.expect("best_supported_rsa_hash");
    let hash_alg = raw_hash.flatten();
    let result = within(30, "authenticate_publickey_with", connection.handle.authenticate_publickey_with(server.sshd.user.as_str(), public, hash_alg, &mut signer))
        .await
        .expect("authenticate_publickey_with");
    let echoed = if result.success() {
        within(20, "exec after the login", exec(&connection.handle, "echo vault-ok")).await.expect("exec").text()
    } else {
        String::new()
    };
    Login { result, signer, raw_hash, hash_alg, echoed }
}

/// A scratch sshd with a `host_key` host key (and `server_config` in front of its defaults) that accepts a fresh `kind` user key, and the vault login to it.
async fn login_with(tools: &Tools, kind: KeyKind, host_key: KeyKind, server_config: &[&str]) -> (Login, Server) {
    let server = Server::start_with(tools, host_key, kind, server_config);
    let login = log_in_through_the_vault(&server, &server.key.public_line, &server.key.private_text).await;
    (login, server)
}

#[tokio::test(flavor = "multi_thread")]
async fn an_ed25519_key_in_the_vault_logs_in() {
    let Some(tools) = tools() else { return };
    let (login, server) = login_with(&tools, KeyKind::Ed25519, KeyKind::Ed25519, &[]).await;
    assert!(login.result.success(), "refused; sshd log: {}", server.sshd.log());
    assert_eq!(login.signer.last_algorithm.as_deref(), Some("ssh-ed25519"));
    assert_eq!((login.signer.calls, login.signer.last_flags), (1, 0));
    assert_eq!(login.echoed, "vault-ok\n");
}

#[tokio::test(flavor = "multi_thread")]
async fn an_ecdsa_p256_key_in_the_vault_logs_in() {
    let Some(tools) = tools() else { return };
    let (login, server) = login_with(&tools, KeyKind::EcdsaP256, KeyKind::Ed25519, &[]).await;
    assert!(login.result.success(), "refused; sshd log: {}", server.sshd.log());
    assert_eq!(login.signer.last_algorithm.as_deref(), Some("ecdsa-sha2-nistp256"));
    assert_eq!((login.signer.calls, login.signer.last_flags), (1, 0));
    assert_eq!(login.echoed, "vault-ok\n");
}

#[tokio::test(flavor = "multi_thread")]
async fn an_rsa_3072_key_in_the_vault_logs_in_with_a_sha2_signature() {
    let Some(tools) = tools() else { return };
    let (login, server) = login_with(&tools, KeyKind::Rsa3072, KeyKind::Ed25519, &[]).await;
    assert!(login.result.success(), "refused; sshd log: {}", server.sshd.log());
    let algorithm = login.signer.last_algorithm.clone().unwrap_or_default();
    fact("signer.rsa.best_supported_rsa_hash_raw", format!("{:?}", login.raw_hash));
    fact("signer.rsa.hash_alg_offered_by_russh", format!("{:?}", login.hash_alg));
    fact("signer.rsa.algorithm_on_the_wire", &algorithm);
    assert!(algorithm == "rsa-sha2-512" || algorithm == "rsa-sha2-256", "a modern server must get a SHA-2 RSA signature, got {algorithm}");
    assert!(login.hash_alg.is_some());
    assert_eq!(login.echoed, "vault-ok\n");
}

/// Review Focus 1. A legacy server (old router, NAS firmware) offers only ssh-rsa for the host key and accepts only ssh-rsa (SHA-1) user signatures.
/// russh must still talk to it with its default algorithm lists, and the vault must sign with flag 0. Skipped where the OpenSSH build
/// refuses SHA-1 signatures altogether (set SPIKE_SKIP_SHA1=1, e.g. on RHEL/Fedora crypto policies).
#[tokio::test(flavor = "multi_thread")]
async fn an_rsa_key_in_the_vault_logs_in_to_a_server_that_only_speaks_ssh_rsa_sha1() {
    if std::env::var("SPIKE_SKIP_SHA1").is_ok_and(|v| v == "1") {
        eprintln!("skipped: SPIKE_SKIP_SHA1=1");
        return;
    }
    let Some(tools) = tools() else { return };
    let (login, server) =
        login_with(&tools, KeyKind::Rsa3072, KeyKind::Rsa3072, &["HostKeyAlgorithms ssh-rsa", "PubkeyAcceptedAlgorithms ssh-rsa"]).await;
    fact("signer.sha1_only.best_supported_rsa_hash_raw", format!("{:?}", login.raw_hash));
    fact("signer.sha1_only.hash_alg_offered_by_russh", format!("{:?}", login.hash_alg));
    fact("signer.sha1_only.algorithm_on_the_wire", login.signer.last_algorithm.clone().unwrap_or_default());
    assert!(login.result.success(), "refused; sshd log: {}", server.sshd.log());
    assert_eq!(login.hash_alg, None, "no rsa-sha2 variant on offer, so russh must ask for ssh-rsa");
    assert_eq!(login.signer.last_flags, 0);
    assert_eq!(login.signer.last_algorithm.as_deref(), Some("ssh-rsa"));
    assert_eq!(login.echoed, "vault-ok\n");
}

/// The negative control: sshd really verifies what the vault signs. The server knows key A; russh presents A's public key but the vault holds B.
#[tokio::test(flavor = "multi_thread")]
async fn a_signature_from_another_key_is_refused() {
    let Some(tools) = tools() else { return };
    let server = Server::start(&tools, &[]);
    let other_dir = tempfile::tempdir().unwrap();
    let other = generate_key(&tools, other_dir.path(), "other", KeyKind::Ed25519);

    let login = log_in_through_the_vault(&server, &server.key.public_line, &other.private_text).await;
    assert!(!login.result.success(), "sshd accepted a signature made by a different key");
    assert_eq!(login.signer.calls, 1, "russh asked the vault once and the server said no");
    assert!(login.echoed.is_empty());
}
