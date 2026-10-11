//! Connecting: host keys, login with vault keys, and the ways a connection attempt fails.

use std::time::{Duration, Instant};

use super::{accepted_logins, engine, LOG_LOGINS};
use crate::ssh::testing::doubles::{SignCall, TestPolicy, VaultAuth};
use crate::ssh::testing::fixture::Server;
use crate::ssh::testing::harness::{generate_key, tools, KeyKind};
use crate::ssh::testing::proxy::{Mode, Proxy};
use crate::ssh::testing::{eventually, fact};
use crate::ssh::{AuthError, AuthMethod, ConnectError, Hop, HostKey, Phase, RsaHash, Target};
use crate::sync::slot_rules::test_keys;

/// A policy that trusts everything, as a `&dyn`-able value.
fn trusting() -> std::sync::Arc<TestPolicy> {
    TestPolicy::trusting()
}

// ---------------------------------------------------------------------------------------------------------------------------------
// Host keys (spec §6.2 step 3). The engine never waits for a person: an unpinned key fails the connect with the key that was seen.

#[test]
fn an_unknown_host_key_fails_fast_with_the_key_the_server_presented_and_leaves_no_connection_behind() {
    let Some(tools) = tools() else { return };
    let server = Server::start(&tools, &[LOG_LOGINS]);
    let proxy = Proxy::start(server.sshd.port);
    let hop = server.hop_with("web", proxy.port, AuthMethod::Key { key_id: "k1".into() });
    let policy = TestPolicy::knowing_nothing();

    let started = Instant::now();
    let error = engine().connect_chain(&Target { hops: vec![hop.clone()] }, &*policy, &server.vault("k1")).err().expect("an unknown key stops the connect");
    assert!(started.elapsed() < Duration::from_secs(5), "no waiting for a person: {:?}", started.elapsed());
    match error {
        ConnectError::HostKeyUnknown { hop: seen, key } => {
            assert_eq!(seen.alias, "web");
            assert_eq!(key, server.host_key());
        }
        other => panic!("expected HostKeyUnknown, got {other:?}"),
    }
    assert_eq!(policy.seen().len(), 1, "the policy was asked once");
    eventually("the proxy to see the connection closed", 5, || proxy.open_connections() == 0);
    assert_eq!(accepted_logins(&server), 0, "nobody logged in");
}

#[test]
fn after_the_user_pins_the_key_the_same_policy_lets_the_next_connect_through() {
    let Some(tools) = tools() else { return };
    let server = Server::start(&tools, &[LOG_LOGINS]);
    let hop = server.hop("web", "k1");
    let target = Target { hops: vec![hop.clone()] };
    let policy = TestPolicy::knowing_nothing();
    let engine = engine();

    let ConnectError::HostKeyUnknown { key, .. } = engine.connect_chain(&target, &*policy, &server.vault("k1")).err().expect("first time") else {
        panic!("expected HostKeyUnknown");
    };
    policy.pin(&hop.reference(), key);
    let connection = engine.connect_chain(&target, &*policy, &server.vault("k1")).expect("second time, the key is pinned");
    assert!(connection.is_open());
    eventually("sshd to log the login", 3, || accepted_logins(&server) == 1);
}

#[test]
fn a_changed_host_key_is_a_mismatch_that_carries_the_observed_and_the_pinned_key() {
    let Some(tools) = tools() else { return };
    let server = Server::start(&tools, &[]);
    let hop = server.hop("web", "k1");
    let policy = TestPolicy::knowing_nothing();
    let old = HostKey::from_openssh_line(test_keys::PLAIN_PUBLIC).expect("a key line");
    policy.pin(&hop.reference(), old.clone());

    match engine().connect_chain(&Target { hops: vec![hop] }, &*policy, &server.vault("k1")) {
        Err(ConnectError::HostKeyMismatch { key, pinned, .. }) => assert_eq!((key, pinned), (server.host_key(), old)),
        other => panic!("expected HostKeyMismatch, got {:?}", other.err()),
    }
}

/// `Hop::pinned` narrows the host key algorithms offered to the one family. The server has an ed25519 and an RSA key; the pin is the RSA one.
/// With the family restriction the handshake lands on the RSA key (a match); without it the client's first choice, ed25519, comes up
/// and would be reported as a changed key (the control).
#[test]
fn a_pinned_key_narrows_the_handshake_to_its_algorithm_family() {
    let Some(tools) = tools() else { return };
    let server = Server::start_with(&tools, &[KeyKind::Ed25519, KeyKind::Rsa3072], KeyKind::Ed25519, &[]);
    let rsa_key = server.host_keys().remove(1);
    assert_eq!(rsa_key.algorithm, "ssh-rsa");

    let mut hop = server.hop("web", "k1");
    let policy = TestPolicy::knowing_nothing();
    policy.pin(&hop.reference(), rsa_key.clone());

    // The engine owns the runtime that drives a connection: it must outlive the `Connection`, or the connection ends under the test.
    let engine = engine();
    let control = engine.connect_chain(&Target { hops: vec![hop.clone()] }, &*policy, &server.vault("k1"));
    assert!(matches!(control, Err(ConnectError::HostKeyMismatch { ref key, .. }) if key.algorithm == "ssh-ed25519"), "without the restriction: {:?}", control.err());

    hop.pinned = Some(rsa_key.clone());
    let connection = engine.connect_chain(&Target { hops: vec![hop] }, &*policy, &server.vault("k1")).expect("the RSA family was offered");
    assert!(connection.is_open());
    assert_eq!(policy.seen().last().map(|(_, key)| key.clone()), Some(rsa_key));
}

#[test]
fn a_server_that_only_has_an_ssh_rsa_host_key_has_nothing_in_common_and_the_message_says_why() {
    let Some(tools) = tools() else { return };
    let server = Server::start_with(&tools, &[KeyKind::Rsa3072], KeyKind::Ed25519, &["HostKeyAlgorithms ssh-rsa"]);
    let error = engine().connect_chain(&server.target("k1"), &*trusting(), &server.vault("k1")).err().expect("SHA-1 host keys are refused");
    fact("host_key.no_common_algorithm.error", format!("{error:?}"));
    match &error {
        ConnectError::NoCommonHostKeyAlgorithm { ours, theirs, .. } => {
            assert_eq!(theirs, &["ssh-rsa".to_string()]);
            assert!(!ours.iter().any(|name| name == "ssh-rsa") && ours.iter().any(|name| name == "ssh-ed25519"), "our list: {ours:?}");
        }
        other => panic!("expected NoCommonHostKeyAlgorithm, got {other:?}"),
    }
    assert!(error.to_string().contains("SHA-1"), "the sentence explains: {error}");
}

// ---------------------------------------------------------------------------------------------------------------------------------
// Login with vault keys (spec §6.3 b: the engine refuses to sign RSA with SHA-1).

fn log_in_with_a_key_of(kind: KeyKind) -> Option<Vec<SignCall>> {
    let tools = tools()?;
    let server = Server::start_with(&tools, &[KeyKind::Ed25519], kind, &[LOG_LOGINS]);
    let auth = server.vault("k1");
    // The engine owns the runtime that drives a connection: it must outlive the `Connection`, or the connection ends under the test.
    let engine = engine();
    let connection = engine.connect_chain(&server.target("k1"), &*trusting(), &auth).expect("the vault key logs in");
    assert_eq!(connection.hop_count(), 1);
    assert!(connection.is_open());
    eventually("sshd to log the login", 3, || accepted_logins(&server) == 1);
    Some(auth.sign_calls())
}

#[test]
fn an_ed25519_key_in_the_vault_logs_in() {
    let Some(calls) = log_in_with_a_key_of(KeyKind::Ed25519) else { return };
    assert_eq!(calls, vec![SignCall { key_id: "k1".into(), rsa_hash: None, algorithm: Some("ssh-ed25519".into()) }]);
}

#[test]
fn an_ecdsa_p256_key_in_the_vault_logs_in() {
    let Some(calls) = log_in_with_a_key_of(KeyKind::EcdsaP256) else { return };
    assert_eq!(calls, vec![SignCall { key_id: "k1".into(), rsa_hash: None, algorithm: Some("ecdsa-sha2-nistp256".into()) }]);
}

#[test]
fn an_rsa_3072_key_in_the_vault_logs_in_with_a_sha2_signature() {
    let Some(calls) = log_in_with_a_key_of(KeyKind::Rsa3072) else { return };
    assert_eq!(calls.len(), 1);
    let algorithm = calls[0].algorithm.clone().unwrap_or_default();
    fact("signer.rsa.algorithm_on_the_wire", &algorithm);
    assert!(algorithm == "rsa-sha2-512" || algorithm == "rsa-sha2-256", "a modern server gets a SHA-2 signature, got {algorithm}");
    assert!(matches!(calls[0].rsa_hash, Some(RsaHash::Sha512) | Some(RsaHash::Sha256)));
}

/// The server knows key A and is shown A's public key, but the vault signs with B: the server checks the signature and says no.
#[test]
fn a_signature_made_by_another_key_is_refused() {
    let Some(tools) = tools() else { return };
    let server = Server::start(&tools, &[LOG_LOGINS]);
    let other_dir = tempfile::tempdir().unwrap();
    let other = generate_key(&tools, other_dir.path(), "other", KeyKind::Ed25519);
    let auth = VaultAuth::new().with_key("k1", &other.private_text).presenting_public_key("k1", &server.key.public_line);

    let error = engine().connect_chain(&server.target("k1"), &*trusting(), &auth).err().expect("a wrong signature must not log in");
    assert!(matches!(&error, ConnectError::AuthFailed { tried, .. } if *tried == [AuthMethod::Key { key_id: "k1".into() }]), "{error:?}");
    assert_eq!(auth.sign_calls().len(), 1, "the server asked for the signature once and refused it");
    assert_eq!(accepted_logins(&server), 0);
}

/// A key the server does not list is refused before any signature is asked for.
#[test]
fn a_key_the_server_does_not_know_is_refused_without_a_signature() {
    let Some(tools) = tools() else { return };
    let server = Server::start(&tools, &[]);
    let stranger_dir = tempfile::tempdir().unwrap();
    let stranger = generate_key(&tools, stranger_dir.path(), "stranger", KeyKind::Ed25519);
    let auth = VaultAuth::new().with_key("k1", &stranger.private_text);

    let error = engine().connect_chain(&server.target("k1"), &*trusting(), &auth).err().expect("an unknown key must not log in");
    assert!(matches!(error, ConnectError::AuthFailed { .. }), "{error:?}");
    assert!(auth.sign_calls().is_empty(), "the server never got as far as asking for a signature");
}

/// Review focus: SHA-1. The server accepts RSA login signatures only as `ssh-rsa` (SHA-1). The engine must refuse to make such a
/// signature: `sign` is never called, and the failure says why.
#[test]
fn an_rsa_key_is_never_signed_with_sha1() {
    if std::env::var("SSHELTER_SKIP_SHA1").is_ok_and(|value| value == "1") {
        eprintln!("skipped: SSHELTER_SKIP_SHA1=1");
        return;
    }
    let Some(tools) = tools() else { return };
    let server = Server::start_with(&tools, &[KeyKind::Ed25519], KeyKind::Rsa3072, &["PubkeyAcceptedAlgorithms ssh-rsa", LOG_LOGINS]);
    let auth = server.vault("k1");

    let error = engine().connect_chain(&server.target("k1"), &*trusting(), &auth).err().expect("a SHA-1-only server cannot be logged in to");
    match &error {
        ConnectError::AuthFailed { tried, reason, .. } => {
            assert_eq!(*tried, [AuthMethod::Key { key_id: "k1".into() }]);
            assert!(reason.contains("SHA-1"), "the reason names SHA-1: {reason}");
        }
        other => panic!("expected AuthFailed, got {other:?}"),
    }
    assert!(auth.sign_calls().is_empty(), "the vault was never asked to sign: {:?}", auth.sign_calls());
    assert_eq!(accepted_logins(&server), 0);
}

#[test]
fn a_key_that_is_not_in_the_vault_is_skipped_and_the_failure_says_so() {
    let Some(tools) = tools() else { return };
    let server = Server::start(&tools, &[]);
    let error = engine().connect_chain(&server.target("missing"), &*trusting(), &VaultAuth::new()).err().expect("no key, no login");
    match error {
        ConnectError::AuthFailed { tried, reason, .. } => {
            assert!(tried.is_empty(), "nothing was tried: {tried:?}");
            assert!(reason.contains("missing"), "the reason names the key: {reason}");
        }
        other => panic!("expected AuthFailed, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------------------------------------------------------------
// Failures to connect, and the login that is abandoned.

fn a_port_nobody_listens_on() -> u16 {
    std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap().local_addr().unwrap().port()
}

#[test]
fn a_port_with_nothing_behind_it_is_unreachable_and_says_connection_refused() {
    let hop = Hop::new("h1", "gone", "127.0.0.1", a_port_nobody_listens_on(), "tester", AuthMethod::Password);
    let error = engine().connect_chain(&Target { hops: vec![hop.clone()] }, &*trusting(), &VaultAuth::new()).err().expect("nothing listens there");
    assert!(matches!(&error, ConnectError::Unreachable { reason, .. } if reason.contains("refused")), "{error:?}");
    let text = error.to_string();
    assert!(text.starts_with(&format!("Could not reach 127.0.0.1:{} (", hop.port)) && text.ends_with(").") && text.contains("refused"), "{text}");
    // The operating system's own words differ (Windows says "no connection could be made because the target machine actively refused it").
    #[cfg(unix)]
    assert_eq!(text, format!("Could not reach 127.0.0.1:{} (connection refused).", hop.port));
}

#[test]
fn a_name_that_does_not_resolve_is_unreachable() {
    let hop = Hop::new("h1", "nowhere", "does-not-exist.invalid", 22, "tester", AuthMethod::Password);
    let started = Instant::now();
    let error = engine().connect_chain(&Target { hops: vec![hop] }, &*trusting(), &VaultAuth::new()).err().expect("the name cannot be resolved");
    assert!(matches!(error, ConnectError::Unreachable { .. }), "{error:?}");
    assert!(started.elapsed() < Duration::from_secs(10), "DNS failures are quick: {:?}", started.elapsed());
}

/// Review focus: a server that accepts the TCP connection and then says nothing. russh has no handshake timeout; the engine's is the
/// host record's `connect_timeout`.
#[test]
fn a_handshake_that_never_gets_an_answer_times_out_after_the_connect_timeout() {
    let Some(tools) = tools() else { return };
    let server = Server::start(&tools, &[]);
    let proxy = Proxy::start(server.sshd.port);
    proxy.set(Mode::Blackhole);
    let mut hop = server.hop_with("web", proxy.port, AuthMethod::Key { key_id: "k1".into() });
    hop.connect_timeout = Duration::from_secs(2);

    let started = Instant::now();
    let error = engine().connect_chain(&Target { hops: vec![hop] }, &*trusting(), &server.vault("k1")).err().expect("nothing answers");
    let waited = started.elapsed();
    fact("handshake_stall.waited_ms", waited.as_millis());
    assert!(matches!(error, ConnectError::Timeout { phase: Phase::Handshake, .. }), "{error:?}");
    assert!(waited >= Duration::from_millis(1800) && waited < Duration::from_secs(6), "waited {waited:?}");
}

/// The server accepts the connection and the handshake and then goes silent in the middle of the login. After the handshake the first
/// thing the engine asks the auth source is the public key, so this one turns the link into a black hole at that moment.
#[test]
fn a_server_that_stops_answering_during_the_login_times_out_in_the_auth_phase() {
    use crate::ssh::{AuthSource, HopRef, Prompt, Secret, Signature};
    use std::sync::Arc;

    struct GoesQuiet {
        inner: VaultAuth,
        proxy: Arc<Proxy>,
    }
    impl AuthSource for GoesQuiet {
        fn public_key(&self, key_id: &str) -> Option<String> {
            self.proxy.set(Mode::Blackhole);
            self.inner.public_key(key_id)
        }
        fn sign(&self, key_id: &str, data: &[u8], rsa_hash: Option<RsaHash>) -> Result<Signature, AuthError> {
            self.inner.sign(key_id, data, rsa_hash)
        }
        fn password(&self, hop: &HopRef) -> Option<Secret> {
            self.inner.password(hop)
        }
        fn interactive(&self, hop: &HopRef, prompts: &[Prompt], deadline: Instant) -> Option<Vec<Secret>> {
            self.inner.interactive(hop, prompts, deadline)
        }
    }

    let Some(tools) = tools() else { return };
    let server = Server::start(&tools, &[]);
    let proxy = Arc::new(Proxy::start(server.sshd.port));
    let mut hop = server.hop_with("web", proxy.port, AuthMethod::Key { key_id: "k1".into() });
    hop.connect_timeout = Duration::from_secs(2);
    let auth = GoesQuiet { inner: server.vault("k1"), proxy: Arc::clone(&proxy) };

    let started = Instant::now();
    let error = engine().connect_chain(&Target { hops: vec![hop] }, &*trusting(), &auth).err().expect("the server went quiet");
    let waited = started.elapsed();
    assert!(matches!(error, ConnectError::Timeout { phase: Phase::Auth, .. }), "{error:?}");
    assert!(waited >= Duration::from_millis(1800) && waited < Duration::from_secs(6), "waited {waited:?}");
    // A black hole holds the bytes of both directions and so keeps the proxy's connection open; letting them through shows that the
    // engine's side was closed, which the proxy then notices.
    proxy.set(Mode::Forward);
    eventually("the proxy to see the connection dropped", 5, || proxy.open_connections() == 0);
}

/// Review focus: the vault is locked. `sign` fails; the login is abandoned with a clear error, quickly, and the connection is dropped
/// (russh's session is stuck waiting for the signature, so it cannot be reused).
#[test]
fn a_signer_that_fails_abandons_the_login_and_drops_the_connection() {
    let Some(tools) = tools() else { return };
    let server = Server::start(&tools, &[]);
    let proxy = Proxy::start(server.sshd.port);
    let hop = server.hop_with("web", proxy.port, AuthMethod::Key { key_id: "k1".into() });
    let auth = server.vault("k1").failing_to_sign(AuthError::Refused("the vault is locked".into()));

    let started = Instant::now();
    let error = engine().connect_chain(&Target { hops: vec![hop] }, &*trusting(), &auth).err().expect("the vault would not sign");
    assert!(started.elapsed() < Duration::from_secs(5), "no hang: {:?}", started.elapsed());
    assert!(matches!(&error, ConnectError::AuthAbandoned { reason, .. } if reason.contains("the vault is locked")), "{error:?}");
    assert!(error.to_string().starts_with("Authentication for web was abandoned"), "{error}");
    eventually("the proxy to see the connection closed", 5, || proxy.open_connections() == 0);
}

#[test]
fn an_empty_chain_and_a_chain_that_lists_a_host_twice_are_refused_before_anything_connects() {
    let engine = engine();
    let hop = Hop::new("h1", "web", "127.0.0.1", a_port_nobody_listens_on(), "tester", AuthMethod::Password);
    let empty = engine.connect_chain(&Target { hops: vec![] }, &*trusting(), &VaultAuth::new());
    assert!(matches!(empty, Err(ConnectError::BadJumpChain { .. })));
    let loop_ = engine.connect_chain(&Target { hops: vec![hop.clone(), hop] }, &*trusting(), &VaultAuth::new());
    assert!(matches!(loop_, Err(ConnectError::BadJumpChain { ref why }) if why.contains("web")), "{:?}", loop_.err());
}
