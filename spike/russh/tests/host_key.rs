//! Task 3c, part 2: the host key callback. `check_server_key` is the only place the engine learns the server's key; it can say yes, no,
//! or take its time (the confirmation window).

use std::borrow::Cow;
use std::time::{Duration, Instant};

use russh::client::Config;
use russh::keys::{Algorithm, HashAlg};
use russh::Preferred;
use russh_spike::client::{connect, exec, login_with_key_file, HostKeyQuestion, HostKeyVerdict};
use russh_spike::fixture::Server;
use russh_spike::harness::{tools, KeyKind, Tools};
use russh_spike::{fact, within};
use tokio::sync::mpsc;

#[tokio::test(flavor = "multi_thread")]
async fn accepting_the_key_connects_and_the_handler_saw_the_servers_fingerprint() {
    let Some(tools) = tools() else { return };
    let server = Server::start(&tools, &[]);
    let connection = within(30, "connect", connect(server.sshd.port, Config::default(), HostKeyVerdict::AcceptAny)).await.unwrap();
    assert_eq!(*connection.observed.host_keys.lock().unwrap(), vec![server.host_fingerprint()]);
}

#[tokio::test(flavor = "multi_thread")]
async fn rejecting_the_key_fails_the_connect_with_unknown_key() {
    let Some(tools) = tools() else { return };
    let server = Server::start(&tools, &[]);
    let error = within(30, "connect", connect(server.sshd.port, Config::default(), HostKeyVerdict::RejectAll)).await.err().expect("a rejected host key must fail the connect");
    fact("host_key.reject.error", format!("{error:?}"));
    assert!(matches!(error, russh::Error::UnknownKey), "got {error:?}");
}

/// Both "a key we have never seen" and "a key that changed" reach the engine's policy as the same callback, and a no from either is the
/// same error: the engine must remember WHY it said no (`HostKeyMismatch` vs the user declining) because russh does not tell.
#[tokio::test(flavor = "multi_thread")]
async fn a_pinned_fingerprint_that_matches_connects_and_one_that_differs_is_refused() {
    let Some(tools) = tools() else { return };
    let server = Server::start(&tools, &[]);

    let pinned = HostKeyVerdict::Pinned(server.host_fingerprint());
    within(30, "connect with the right pin", connect(server.sshd.port, Config::default(), pinned)).await.unwrap();

    let wrong = HostKeyVerdict::Pinned("SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_string());
    let error = within(30, "connect with the wrong pin", connect(server.sshd.port, Config::default(), wrong)).await.err().expect("a changed key must fail");
    assert!(matches!(error, russh::Error::UnknownKey), "got {error:?}");
}

/// The broker asks in the app window: the handshake waits for the answer and goes on afterwards.
#[tokio::test(flavor = "multi_thread")]
async fn the_answer_can_arrive_seconds_later_and_the_connection_goes_on() {
    let Some(tools) = tools() else { return };
    let server = Server::start(&tools, &[]);
    let (questions, mut inbox) = mpsc::unbounded_channel::<HostKeyQuestion>();
    let fingerprint = server.host_fingerprint();
    let asker = tokio::spawn(async move {
        let question = inbox.recv().await.expect("the handler asks");
        assert_eq!(question.fingerprint, fingerprint);
        tokio::time::sleep(Duration::from_secs(2)).await;
        let _ = question.reply.send(true);
        question.algorithm
    });

    let started = Instant::now();
    let mut connection = within(30, "connect", connect(server.sshd.port, Config::default(), HostKeyVerdict::Ask(questions))).await.unwrap();
    assert!(started.elapsed() >= Duration::from_secs(2), "the handshake did not wait for the answer");
    fact("host_key.ask.algorithm", asker.await.unwrap());
    server.login(&mut connection).await;
    assert_eq!(within(20, "exec", exec(&connection.handle, "echo asked")).await.unwrap().text(), "asked\n");
}

/// A fact, not a requirement: sshd drops a connection that has not logged in within `LoginGraceTime` (default 120 s), and the time the
/// user needs to read the host key dialog counts. With 3 s of grace and an answer after 6 s, this shows how the connect fails.
///
/// The design expected: the connect fails. What happened (macOS, OpenSSH 10.3p1, russh 0.64.1): the connect RETURNED Ok, 6 s in, and the
/// connection was already dead. So the observation goes one step further than the brief: it logs in afterwards and prints what that
/// does (`login_after`, `disconnect_seen`), next to a control with sshd's default grace time, where the same 6 s delay is harmless.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "an observation for the report: run with --ignored --nocapture"]
async fn observe_an_answer_slower_than_the_servers_login_grace_time() {
    let Some(tools) = tools() else { return };
    observe_a_six_second_answer(&tools, "host_key.slow_answer", &["LoginGraceTime 3"]).await;
    observe_a_six_second_answer(&tools, "host_key.slow_answer_control_default_grace", &[]).await;
}

/// Connects with a host key answer that takes 6 s, then logs in, and prints what each step did under `prefix`.
async fn observe_a_six_second_answer(tools: &Tools, prefix: &str, server_config: &[&str]) {
    let server = Server::start(tools, server_config);
    let (questions, mut inbox) = mpsc::unbounded_channel::<HostKeyQuestion>();
    tokio::spawn(async move {
        let question = inbox.recv().await.expect("the handler asks");
        tokio::time::sleep(Duration::from_secs(6)).await;
        let _ = question.reply.send(true);
    });
    let started = Instant::now();
    let outcome = within(30, "connect", connect(server.sshd.port, Config::default(), HostKeyVerdict::Ask(questions))).await;
    // the design expected: with a short LoginGraceTime the connect fails once the answer comes late
    fact(&format!("{prefix}.outcome"), match &outcome {
        Ok(_) => "connected".to_string(),
        Err(error) => format!("failed: {error:?}"),
    });
    fact(&format!("{prefix}.after_ms"), started.elapsed().as_millis());

    let Ok(mut connection) = outcome else { return };
    // `connected` looks fine from the outside: the handle is open and russh has seen no disconnect yet.
    fact(&format!("{prefix}.handle_closed_right_after_connect"), connection.handle.is_closed());
    let login = within(30, "login", login_with_key_file(&mut connection.handle, &server.sshd.user, &server.key.private_path)).await;
    fact(&format!("{prefix}.login_after"), match &login {
        Ok(result) => format!("{result:?}"),
        Err(error) => format!("failed: {error:?}"),
    });
    tokio::time::sleep(Duration::from_millis(500)).await;
    fact(&format!("{prefix}.disconnect_seen"), format!("{:?}", connection.observed.disconnect.lock().unwrap()));
}

/// Review Focus 2. A server whose host key algorithm russh does not offer: the error names both lists, which is what the user message needs.
/// (The client is limited to rsa-sha2-256 host keys; the server only has ssh-ed25519. The same error is what a legacy server with only
/// ssh-dss or only a cipher russh dropped would produce.)
#[tokio::test(flavor = "multi_thread")]
async fn no_common_host_key_algorithm_names_both_lists() {
    const ONLY_RSA_SHA256: &[Algorithm] = &[Algorithm::Rsa { hash: Some(HashAlg::Sha256) }];
    let Some(tools) = tools() else { return };
    let server = Server::start_with(&tools, KeyKind::Ed25519, KeyKind::Ed25519, &["HostKeyAlgorithms ssh-ed25519"]);
    let config = Config { preferred: Preferred { key: Cow::Borrowed(ONLY_RSA_SHA256), ..Preferred::DEFAULT }, ..Config::default() };

    let error = within(30, "connect", connect(server.sshd.port, config, HostKeyVerdict::AcceptAny)).await.err().expect("no common algorithm must fail");
    fact("host_key.no_common_algorithm.error", format!("{error:?}"));
    match error {
        russh::Error::NoCommonAlgo { kind, ours, theirs } => {
            fact("host_key.no_common_algorithm.kind", format!("{kind:?}"));
            assert!(theirs.iter().any(|name| name == "ssh-ed25519"), "the server's list: {theirs:?}");
            assert!(ours.iter().any(|name| name == "rsa-sha2-256"), "our list: {ours:?}");
        }
        other => panic!("expected NoCommonAlgo, got {other:?}"),
    }
}

/// Not in the brief (ruled by the controller after Task 2's review). Phase 1 takes `ssh-rsa` (SHA-1) out of the host key list. A server whose
/// only host key algorithm is ssh-rsa then has nothing in common with us: what does russh report? The list is russh's own default minus
/// `Algorithm::Rsa { hash: None }`, so it is exactly what the engine will set. Two positive controls make the failure attributable to the
/// list alone: the same server accepts russh's defaults, and the shorter list works against an ordinary server.
#[tokio::test(flavor = "multi_thread")]
async fn a_host_key_list_without_ssh_rsa_has_nothing_in_common_with_a_server_that_only_has_ssh_rsa() {
    let Some(tools) = tools() else { return };
    let legacy = Server::start_with(&tools, KeyKind::Rsa3072, KeyKind::Ed25519, &["HostKeyAlgorithms ssh-rsa"]);
    let modern = Server::start(&tools, &[]);
    let without_ssh_rsa = || Config {
        preferred: Preferred {
            key: Cow::Owned(Preferred::DEFAULT.key.iter().filter(|algorithm| !matches!(algorithm, Algorithm::Rsa { hash: None })).cloned().collect()),
            ..Preferred::DEFAULT
        },
        ..Config::default()
    };
    fact("host_key.russh_default_key_list", format!("{:?}", Preferred::DEFAULT.key));
    fact("host_key.list_without_ssh_rsa", format!("{:?}", without_ssh_rsa().preferred.key));

    // Control 1: the server really does have only an RSA host key, and russh's defaults (which still offer ssh-rsa) take it.
    let connection = within(30, "connect with the default list", connect(legacy.sshd.port, Config::default(), HostKeyVerdict::AcceptAny)).await.unwrap();
    assert_eq!(*connection.observed.host_keys.lock().unwrap(), vec![legacy.host_fingerprint()]);
    // Control 2: the shorter list is a working list.
    within(30, "connect to an ed25519 server without ssh-rsa", connect(modern.sshd.port, without_ssh_rsa(), HostKeyVerdict::AcceptAny)).await.unwrap();

    let error = within(30, "connect without ssh-rsa", connect(legacy.sshd.port, without_ssh_rsa(), HostKeyVerdict::AcceptAny))
        .await
        .err()
        .expect("a list without ssh-rsa must not connect to a server that only has ssh-rsa");
    fact("host_key.no_common_algorithm.ssh_rsa_only_server.error", format!("{error:?}"));
    match error {
        russh::Error::NoCommonAlgo { kind, ours, theirs } => {
            assert_eq!(format!("{kind:?}"), "Key");
            assert_eq!(theirs, ["ssh-rsa"], "the server's list");
            assert!(!ours.iter().any(|name| name == "ssh-rsa"), "our list: {ours:?}");
            assert!(ours.iter().any(|name| name == "rsa-sha2-512") && ours.iter().any(|name| name == "rsa-sha2-256"), "our list: {ours:?}");
        }
        other => panic!("expected NoCommonAlgo, got {other:?}"),
    }
}
