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

/// Runs `work` on a helper thread and waits `seconds` for its result, so that a call that a timeout should have cut short fails the test
/// instead of hanging the run (the shape of `bounded` in `channel.rs`, which returns nothing).
fn bounded<T: Send + 'static>(seconds: u64, work: impl FnOnce() -> T + Send + 'static) -> T {
    let (finished, done) = std::sync::mpsc::channel();
    let runner = std::thread::spawn(move || {
        let _ = finished.send(work());
    });
    match done.recv_timeout(Duration::from_secs(seconds)) {
        Ok(result) => {
            runner.join().unwrap();
            result
        }
        Err(std::sync::mpsc::RecvTimeoutError::Timeout) => panic!("the call did not return within {seconds} s: a timeout of the engine does not work"),
        Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => std::panic::resume_unwind(runner.join().unwrap_err()),
    }
}

/// A vault double that runs `at_public_key` when the engine asks it for the public key of the login. That is the first thing the engine
/// asks the auth source once the handshake is done, so a test can change the link at exactly that moment.
struct LinkTrouble {
    inner: VaultAuth,
    at_public_key: Box<dyn Fn() + Send + Sync>,
}

impl LinkTrouble {
    fn new(inner: VaultAuth, at_public_key: impl Fn() + Send + Sync + 'static) -> LinkTrouble {
        LinkTrouble { inner, at_public_key: Box::new(at_public_key) }
    }
}

impl crate::ssh::AuthSource for LinkTrouble {
    fn public_key(&self, key_id: &str) -> Option<String> {
        (self.at_public_key)();
        crate::ssh::AuthSource::public_key(&self.inner, key_id)
    }
    fn sign(&self, key_id: &str, data: &[u8], rsa_hash: Option<RsaHash>) -> Result<crate::ssh::Signature, AuthError> {
        crate::ssh::AuthSource::sign(&self.inner, key_id, data, rsa_hash)
    }
    fn password(&self, hop: &crate::ssh::HopRef) -> Option<crate::ssh::Secret> {
        crate::ssh::AuthSource::password(&self.inner, hop)
    }
    fn interactive(&self, hop: &crate::ssh::HopRef, prompts: &[crate::ssh::Prompt], deadline: Instant) -> Option<Vec<crate::ssh::Secret>> {
        crate::ssh::AuthSource::interactive(&self.inner, hop, prompts, deadline)
    }
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

/// `best_supported_rsa_hash` is asked for RSA keys only. This server still accepts `ssh-rsa` next to Ed25519, which for an RSA key would
/// mean "SHA-1 only"; an Ed25519 key must not be held to that.
#[test]
fn an_ed25519_key_logs_in_to_a_server_that_also_accepts_ssh_rsa() {
    let Some(tools) = tools() else { return };
    let server = Server::start_with(&tools, &[KeyKind::Ed25519], KeyKind::Ed25519, &["PubkeyAcceptedAlgorithms ssh-ed25519,ssh-rsa", LOG_LOGINS]);
    let auth = server.vault("k1");
    // The engine owns the runtime that drives a connection: it must outlive the `Connection`, or the connection ends under the test.
    let engine = engine();
    let connection = engine.connect_chain(&server.target("k1"), &*trusting(), &auth).expect("the Ed25519 key logs in");
    assert!(connection.is_open());
    eventually("sshd to log the login", 3, || accepted_logins(&server) == 1);
    assert_eq!(auth.sign_calls(), vec![SignCall { key_id: "k1".into(), rsa_hash: None, algorithm: Some("ssh-ed25519".into()) }]);
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

    let (target, auth) = (Target { hops: vec![hop] }, server.vault("k1"));
    let started = Instant::now();
    let error = bounded(10, move || engine().connect_chain(&target, &*trusting(), &auth).err()).expect("nothing answers");
    let waited = started.elapsed();
    fact("handshake_stall.waited_ms", waited.as_millis());
    assert!(matches!(error, ConnectError::Timeout { phase: Phase::Handshake, .. }), "{error:?}");
    assert!(waited >= Duration::from_millis(1800) && waited < Duration::from_secs(6), "waited {waited:?}");
}

/// Review focus: a server that sends its version line and then says nothing. By then russh has started its session task; when the handshake
/// times out the task would be left behind with the socket (and, after the keepalive interval, spin on it), so the engine closes the socket
/// itself and the server sees the end of the connection.
#[test]
fn a_handshake_that_times_out_after_the_version_exchange_does_not_leave_the_socket_open() {
    use std::io::{Read, Write};
    use std::sync::atomic::{AtomicBool, Ordering};

    let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
    let port = listener.local_addr().unwrap().port();
    let ended = std::sync::Arc::new(AtomicBool::new(false));
    let server = {
        let ended = std::sync::Arc::clone(&ended);
        std::thread::spawn(move || {
            let (mut socket, _) = listener.accept().unwrap();
            socket.write_all(b"SSH-2.0-quiet\r\n").unwrap();
            // Takes in whatever the client sends until the client's end of the connection is closed.
            let mut buffer = [0u8; 4096];
            while matches!(socket.read(&mut buffer), Ok(count) if count > 0) {}
            ended.store(true, Ordering::SeqCst);
        })
    };
    let mut hop = Hop::new("h1", "quiet", "127.0.0.1", port, "tester", AuthMethod::Key { key_id: "k1".into() });
    hop.connect_timeout = Duration::from_secs(1);

    // The engine stays alive to the end: shutting it down ends every task it runs, and that would hide the one that is left behind.
    let engine = std::sync::Arc::new(engine());
    let (runner, target) = (std::sync::Arc::clone(&engine), Target { hops: vec![hop] });
    let error = bounded(10, move || runner.connect_chain(&target, &*trusting(), &VaultAuth::new()).err()).expect("the handshake never finishes");
    assert!(matches!(error, ConnectError::Timeout { phase: Phase::Handshake, .. }), "{error:?}");
    eventually("the server to see the engine close its end of the connection", 5, || ended.load(Ordering::SeqCst));
    server.join().unwrap();
}

/// The server accepts the connection and the handshake and then goes silent in the middle of the login. After the handshake the first
/// thing the engine asks the auth source is the public key, so this one turns the link into a black hole at that moment.
#[test]
fn a_server_that_stops_answering_during_the_login_times_out_in_the_auth_phase() {
    let Some(tools) = tools() else { return };
    let server = Server::start(&tools, &[]);
    let proxy = std::sync::Arc::new(Proxy::start(server.sshd.port));
    let mut hop = server.hop_with("web", proxy.port, AuthMethod::Key { key_id: "k1".into() });
    hop.connect_timeout = Duration::from_secs(2);
    let quiet = std::sync::Arc::clone(&proxy);
    let auth = LinkTrouble::new(server.vault("k1"), move || quiet.set(Mode::Blackhole));

    // The engine outlives the call, so that what the proxy sees afterwards is what the engine itself closed.
    let engine = std::sync::Arc::new(engine());
    let (runner, target) = (std::sync::Arc::clone(&engine), Target { hops: vec![hop] });
    let started = Instant::now();
    let error = bounded(10, move || runner.connect_chain(&target, &*trusting(), &auth).err()).expect("the server went quiet");
    let waited = started.elapsed();
    assert!(matches!(error, ConnectError::Timeout { phase: Phase::Auth, .. }), "{error:?}");
    assert!(waited >= Duration::from_millis(1800) && waited < Duration::from_secs(6), "waited {waited:?}");
    // A black hole holds the bytes of both directions and so keeps the proxy's connection open; letting them through shows that the
    // engine's side was closed, which the proxy then notices.
    proxy.set(Mode::Forward);
    eventually("the proxy to see the connection dropped", 5, || proxy.open_connections() == 0);
}

/// Review focus: the connection dies while the engine waits for the server's answer to a login request. russh then reports a refusal with
/// no method left; the engine has to tell the two apart, because the user should be told that the link was lost, not that a key was
/// refused.
#[test]
fn a_connection_that_is_cut_while_the_login_waits_for_the_server_is_lost_and_not_refused() {
    let Some(tools) = tools() else { return };
    let server = Server::start(&tools, &[]);
    // With the key in the vault the wait is for the answer to the public-key request; without it the engine asks the server what it offers
    // (`none`) and the wait is for that answer.
    for (vault, waiting_for) in [(server.vault("k1"), "the public-key request"), (VaultAuth::new(), "the request for the methods on offer")] {
        let proxy = std::sync::Arc::new(Proxy::start(server.sshd.port));
        let mut hop = server.hop_with("web", proxy.port, AuthMethod::Key { key_id: "k1".into() });
        hop.connect_timeout = Duration::from_secs(5);
        // From the moment the engine asks for the public key the server hears nothing; 600 ms later the link is cut.
        let link = std::sync::Arc::clone(&proxy);
        let auth = LinkTrouble::new(vault, move || {
            link.set(Mode::Blackhole);
            let link = std::sync::Arc::clone(&link);
            std::thread::spawn(move || {
                std::thread::sleep(Duration::from_millis(600));
                link.set(Mode::Cut);
            });
        });

        let target = Target { hops: vec![hop] };
        let started = Instant::now();
        let error = bounded(15, move || engine().connect_chain(&target, &*trusting(), &auth).err()).expect("the link was cut");
        let waited = started.elapsed();
        assert!(matches!(&error, ConnectError::Unreachable { reason, .. } if reason.contains("lost")), "waiting for {waiting_for}: {error:?}");
        assert!(waited >= Duration::from_millis(500) && waited < Duration::from_secs(4), "waiting for {waiting_for}: waited {waited:?}");
    }
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
