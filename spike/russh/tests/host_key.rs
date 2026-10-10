//! Task 3c, part 2: the host key callback. `check_server_key` is the only place the engine learns the server's key; it can say yes, no,
//! or take its time (the confirmation window).

use std::borrow::Cow;
use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use russh::client::{AuthResult, Config, Handle, KeyboardInteractiveAuthResponse};
use russh::keys::{Algorithm, HashAlg};
use russh::Preferred;
use russh_spike::client::{connect, exec, login_with_key_file, HostKeyQuestion, HostKeyVerdict, SpikeHandler};
use russh_spike::fixture::Server;
use russh_spike::harness::{tools, KeyKind, Tools};
use russh_spike::proxy::{Mode, Proxy};
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
/// user needs to read the host key dialog counts: the wait for the answer runs on the server's clock while nothing reads the socket (russh
/// awaits `check_server_key` inline in its session loop, client/mod.rs:2018). With 3 s of grace and an answer after 6 s:
///
/// The design expected: the connect fails. What happened (macOS, OpenSSH 10.3p1, russh 0.64.1): the connect RETURNED Ok, 6 s in, on a
/// connection that sshd had already dropped or was about to drop. So the observation goes beyond the brief: right after the connect it makes a first call (`authenticate_none`,
/// before any print or file read), repeats it 200 ms later, logs in, and prints what each did, next to a control with sshd's default grace
/// time, where the same 6 s delay is harmless. What the first call returns is a race (see `FirstCall`), and not always a dead-session one:
/// this sshd enforces its grace time only coarsely, so the first call is sometimes still answered normally (a refusal listing `PublicKey`)
/// just before sshd drops the connection, and only the call 200 ms later fails. A good answer therefore does not prove the session is
/// alive either. The tally for a cut link is
/// `observe_the_first_call_after_a_link_was_cut_during_the_host_key_prompt`, and the pinned version of this finding is
/// `a_connect_that_returned_ok_on_a_dead_session_is_found_out_by_the_first_call`. (It is not built on a short `LoginGraceTime`: this sshd
/// enforces the grace time only to within several seconds, see `observe_when_sshd_drops_a_connection_that_stays_quiet`.)
#[tokio::test(flavor = "multi_thread")]
#[ignore = "an observation for the report: run with --ignored --nocapture"]
async fn observe_an_answer_slower_than_the_servers_login_grace_time() {
    let Some(tools) = tools() else { return };
    observe_a_six_second_answer(&tools, "host_key.slow_answer", &["LoginGraceTime 3"]).await;
    observe_a_six_second_answer(&tools, "host_key.slow_answer_control_default_grace", &[]).await;
}

/// Connects with a host key answer that takes 6 s, then makes calls on the new handle and prints what each step did under `prefix`.
async fn observe_a_six_second_answer(tools: &Tools, prefix: &str, server_config: &[&str]) {
    let server = Server::start(tools, server_config);
    let (questions, mut inbox) = mpsc::unbounded_channel::<HostKeyQuestion>();
    tokio::spawn(async move {
        let question = inbox.recv().await.expect("the handler asks");
        tokio::time::sleep(Duration::from_secs(6)).await;
        let _ = question.reply.send(true);
    });
    let started = Instant::now();
    let mut outcome = within(30, "connect", connect(server.sshd.port, Config::default(), HostKeyVerdict::Ask(questions))).await;
    let connected_after = started.elapsed();

    // The very first thing after `connect` returns: no print and no file read in between. The first version of this observation printed two
    // facts and read the key file first, which gave the session time to notice its end, so it only ever saw one of the ways a call can fail.
    let closed_before_any_call = outcome.as_ref().ok().map(|connection| connection.handle.is_closed());
    let first_call = match outcome.as_mut() {
        Ok(connection) => Some(within(20, "authenticate_none right after connect", connection.handle.authenticate_none(server.sshd.user.as_str())).await),
        Err(_) => None,
    };

    // the design expected: with a short LoginGraceTime the connect fails once the answer comes late
    fact(&format!("{prefix}.outcome"), match &outcome {
        Ok(_) => "connected".to_string(),
        Err(error) => format!("failed: {error:?}"),
    });
    fact(&format!("{prefix}.after_ms"), connected_after.as_millis());
    let (Ok(mut connection), Some(first_call)) = (outcome, first_call) else { return };
    fact(&format!("{prefix}.first_call_after_connect"), format!("{first_call:?}"));
    tokio::time::sleep(Duration::from_millis(200)).await;
    let later = within(20, "authenticate_none 200 ms later", connection.handle.authenticate_none(server.sshd.user.as_str())).await;
    fact(&format!("{prefix}.call_200ms_later"), format!("{later:?}"));

    // `connected` looks fine from the outside: the handle was open and russh had seen no disconnect yet.
    fact(&format!("{prefix}.handle_closed_right_after_connect"), closed_before_any_call.unwrap_or(false));
    let login = within(30, "login", login_with_key_file(&mut connection.handle, &server.sshd.user, &server.key.private_path)).await;
    fact(&format!("{prefix}.login_after"), match &login {
        Ok(result) => format!("{result:?}"),
        Err(error) => format!("failed: {error:?}"),
    });
    tokio::time::sleep(Duration::from_millis(500)).await;
    fact(&format!("{prefix}.disconnect_seen"), format!("{:?}", connection.observed.disconnect.lock().unwrap()));
}

/// The calls whose answer, right after a `connect` that returned Ok on a dead session, is worth telling apart.
#[derive(Clone, Copy)]
enum FirstCall {
    AuthenticateNone,
    KeyboardInteractive,
    BestSupportedRsaHash,
}

const FIRST_CALLS: [FirstCall; 3] = [FirstCall::AuthenticateNone, FirstCall::KeyboardInteractive, FirstCall::BestSupportedRsaHash];

impl FirstCall {
    fn name(self) -> &'static str {
        match self {
            FirstCall::AuthenticateNone => "authenticate_none",
            FirstCall::KeyboardInteractive => "authenticate_keyboard_interactive_start",
            FirstCall::BestSupportedRsaHash => "best_supported_rsa_hash",
        }
    }

    /// Makes the call and returns what came back as a short label and as `Debug` text. Every wait is bounded.
    async fn make(self, handle: &mut Handle<SpikeHandler>, user: &str) -> (&'static str, String) {
        match self {
            FirstCall::AuthenticateNone => {
                let result = within(20, "authenticate_none", handle.authenticate_none(user)).await;
                (label(&result, auth_label), format!("{result:?}"))
            }
            FirstCall::KeyboardInteractive => {
                let result = within(20, "keyboard-interactive start", handle.authenticate_keyboard_interactive_start(user, None::<String>)).await;
                (label(&result, keyboard_label), format!("{result:?}"))
            }
            FirstCall::BestSupportedRsaHash => {
                let result = within(20, "best_supported_rsa_hash", handle.best_supported_rsa_hash()).await;
                (label(&result, |_| "answered"), format!("{result:?}"))
            }
        }
    }
}

/// The short names of the ways such a call can end. A live server's refusal lists the methods it still offers (`failure_listing_methods`);
/// `empty_failure` is what a session that ended under the request leaves behind (russh turns the closed reply channel into a refusal with an
/// empty method set); the errors are russh's own variants.
fn label<T>(result: &Result<T, russh::Error>, ok: impl Fn(&T) -> &'static str) -> &'static str {
    match result {
        Ok(value) => ok(value),
        Err(russh::Error::SendError) => "send_error",
        Err(russh::Error::RecvError) => "recv_error",
        Err(russh::Error::Inconsistent) => "inconsistent",
        Err(_) => "other_error",
    }
}

fn auth_label(result: &AuthResult) -> &'static str {
    match result {
        AuthResult::Success => "success",
        AuthResult::Failure { remaining_methods, .. } if remaining_methods.is_empty() => "empty_failure",
        AuthResult::Failure { .. } => "failure_listing_methods",
    }
}

fn keyboard_label(result: &KeyboardInteractiveAuthResponse) -> &'static str {
    match result {
        KeyboardInteractiveAuthResponse::Success => "success",
        KeyboardInteractiveAuthResponse::Failure { remaining_methods, .. } if remaining_methods.is_empty() => "empty_failure",
        KeyboardInteractiveAuthResponse::Failure { .. } => "failure_listing_methods",
        KeyboardInteractiveAuthResponse::InfoRequest { .. } => "info_request",
    }
}

/// What one round of the loop below saw.
struct Round {
    first_call: &'static str,
    first_call_raw: String,
    is_closed_after_the_first_call: bool,
    /// The handler's recorded `disconnected` reason, polled for up to 1 s.
    recorded_reason: Option<String>,
    /// What the `Handle` future yielded.
    handle_future: String,
}

/// One round: a fresh connection through a proxy; the link is cut 0.3 s into the host key prompt and the answer (yes) comes at 0.6 s; then
/// `call` is the FIRST thing done with the handle `connect` returned. `Err` carries the error when `connect` itself failed.
async fn a_round_with_the_link_cut_during_the_prompt(server: &Server, call: FirstCall) -> Result<Round, String> {
    let proxy = Arc::new(Proxy::start(server.sshd.port).await);
    let (questions, mut inbox) = mpsc::unbounded_channel::<HostKeyQuestion>();
    let asker = tokio::spawn({
        let proxy = Arc::clone(&proxy);
        async move {
            let question = inbox.recv().await.expect("the handler asks");
            tokio::time::sleep(Duration::from_millis(300)).await;
            proxy.set(Mode::Cut);
            tokio::time::sleep(Duration::from_millis(300)).await;
            let _ = question.reply.send(true);
        }
    });
    let mut connection = match within(30, "connect", connect(proxy.port, Config::default(), HostKeyVerdict::Ask(questions))).await {
        Ok(connection) => connection,
        Err(error) => {
            let _ = within(5, "the asker", asker).await;
            return Err(format!("{error:?}"));
        }
    };

    let (first_call, first_call_raw) = call.make(&mut connection.handle, &server.sshd.user).await;
    let is_closed_after_the_first_call = connection.handle.is_closed();
    let _ = within(5, "the asker", asker).await;
    let recorded_reason = within(5, "poll the recorded reason", async {
        for _ in 0..100 {
            let reason = connection.observed.disconnect.lock().unwrap().clone();
            if reason.is_some() {
                return reason;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        None
    })
    .await;
    let handle_future = format!("{:?}", within(5, "the Handle future", &mut connection.handle).await);
    Ok(Round { first_call, first_call_raw, is_closed_after_the_first_call, recorded_reason, handle_future })
}

/// The pinned version of the observations around it (fix round 1): `connect` returns Ok on a session that is already over, and the first
/// call on the handle finds that out. The link under the connection is cut by a proxy 0.3 s into the host key prompt and the answer comes
/// at 0.6 s. (A short server-side `LoginGraceTime` cannot make this deterministic: a test with `LoginGraceTime 1` and an answer at 2 s found
/// a LIVE connection, because this sshd enforces the grace time only to within several seconds, see
/// `observe_when_sshd_drops_a_connection_that_stays_quiet`.) What a call returns on such a handle is a race between the call and the session
/// task noticing the end, so each call may end in either of its two dead-session ways: `authenticate_none` in an EMPTY refusal (the request
/// was queued, then the session ended and russh turned the closed reply channel into a refusal without methods) or a bare `SendError` (the
/// task had already ended); keyboard-interactive in `RecvError` or `SendError`. A live server's refusal lists `PublicKey`
/// (tests/auth_methods.rs), so an empty list is a usable "the session died" signal, but the reliable evidence is the session's liveness:
/// `is_closed()` and the `Handle` future, checked here too. An engine that mapped only `SendError` to "connection lost" would report an
/// empty refusal as bad credentials (spec section 6.2, step 4). `best_supported_rsa_hash` is left out on purpose: see the tally below.
#[tokio::test(flavor = "multi_thread")]
async fn a_connect_that_returned_ok_on_a_dead_session_is_found_out_by_the_first_call() {
    let Some(tools) = tools() else { return };
    let server = Server::start(&tools, &[]);
    for (call, dead_ways) in [
        (FirstCall::AuthenticateNone, ["empty_failure", "send_error"]),
        (FirstCall::KeyboardInteractive, ["recv_error", "send_error"]),
    ] {
        // the design expected: the connect fails when the link dies during the host key prompt (or, at least, the first call gets an answer)
        let round = a_round_with_the_link_cut_during_the_prompt(&server, call).await.expect("connect returns Ok although the link is gone");
        fact(&format!("host_key.link_cut.{}.first_call", call.name()), &round.first_call_raw);
        fact(&format!("host_key.link_cut.{}.recorded_reason", call.name()), format!("{:?}", round.recorded_reason));
        assert!(
            dead_ways.contains(&round.first_call),
            "{}: a dead session gives one of {dead_ways:?}, got {} ({})",
            call.name(),
            round.first_call,
            round.first_call_raw
        );
        assert!(round.is_closed_after_the_first_call, "{}: the session is over, so the handle must say so", call.name());
        assert!(round.handle_future.starts_with("Err("), "{}: the Handle future ends with an error, got {}", call.name(), round.handle_future);
    }
}

/// A fact, not a requirement (fix round 1): when does this sshd really drop an unauthenticated connection that goes quiet after the banners?
/// The review expected `LoginGraceTime 1` to be enforced at about 1 s, which would have allowed a 2.5 s regular test; a first version of one
/// found a live connection at 2 s. Raw TCP, no russh: the client sends its banner and then nothing, and the time until sshd closes the
/// connection is measured. `PerSourcePenalties no`: with the default, the second connection from 127.0.0.1 that exceeded the grace time is
/// refused without a banner (`grace-exceeded` adds 10 s of penalty, enforcement begins at 15 s). That keyword needs OpenSSH 9.8 or newer,
/// which is why it is here, in an ignored test, and not in the harness's defaults.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "an observation for the report: run with --ignored --nocapture"]
async fn observe_when_sshd_drops_a_connection_that_stays_quiet() {
    let Some(tools) = tools() else { return };
    for (grace, samples) in [(1u32, 5usize), (3, 3)] {
        let server = Server::start(&tools, &[&format!("LoginGraceTime {grace}"), "PerSourcePenalties no"]);
        let mut seconds = Vec::new();
        for _ in 0..samples {
            seconds.push(within(40, "a quiet connection to be dropped", seconds_until_sshd_drops_a_quiet_connection(server.sshd.port)).await);
        }
        fact(&format!("host_key.grace_enforcement.login_grace_{grace}.seconds_until_dropped"), seconds.join(" | "));
    }
}

/// Raw TCP: banners are exchanged, then the client says nothing. Returns how long until sshd closes the connection.
async fn seconds_until_sshd_drops_a_quiet_connection(port: u16) -> String {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let mut stream = tokio::net::TcpStream::connect((std::net::Ipv4Addr::LOCALHOST, port)).await.expect("connect to the scratch sshd");
    let mut banner = [0u8; 64];
    let read = stream.read(&mut banner).await.unwrap_or(0);
    if !banner[..read].starts_with(b"SSH-2.0-") {
        return "refused without a banner".to_string();
    }
    stream.write_all(b"SSH-2.0-spike-probe\r\n").await.expect("send our banner");
    let started = Instant::now();
    let mut buffer = [0u8; 4096];
    loop {
        match tokio::time::timeout(Duration::from_secs(20), stream.read(&mut buffer)).await {
            Err(_) => return "still open after 20 s".to_string(),
            Ok(Ok(0)) | Ok(Err(_)) => return format!("{:.2} s", started.elapsed().as_secs_f64()),
            Ok(Ok(_)) => continue, // sshd's key exchange init
        }
    }
}

/// A fact, not a requirement. The same "connect says Ok on a dead connection" as above, caused by the NETWORK instead of the server's grace
/// time: a proxy cuts the link 0.3 s into the host key prompt and the answer (yes) comes at 0.6 s. What the first call on the handle returns
/// is a race between that call and the session task noticing the end, so the scenario is run 51 times (17 for each of three calls) and the
/// answers are tallied: `empty_failure` (`authenticate_*`: the request was queued, then the session ended), `recv_error` (keyboard-
/// interactive), `inconsistent` (`best_supported_rsa_hash`) and `send_error` (anything, once the session task had already ended). Next to
/// them, the evidence that does not depend on the race: `is_closed()`, the handler's recorded reason, and what the `Handle` future yields.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "an observation for the report: run with --ignored --nocapture"]
async fn observe_the_first_call_after_a_link_was_cut_during_the_host_key_prompt() {
    const ROUNDS: usize = 51;
    let Some(tools) = tools() else { return };
    // `PerSourcePenalties no`: every cut connection is a 1 s "noauth" penalty for 127.0.0.1, and enforcement (refusing the source without a
    // banner) begins at 15 s, which 51 rounds in 33 s would reach. The keyword needs OpenSSH 9.8 or newer, hence only in this ignored test.
    let server = Server::start(&tools, &["PerSourcePenalties no"]);

    let mut by_call: BTreeMap<&str, BTreeMap<&str, usize>> = BTreeMap::new();
    let mut total: BTreeMap<&str, usize> = ["empty_failure", "recv_error", "inconsistent", "send_error"].into_iter().map(|name| (name, 0)).collect();
    let mut examples: BTreeMap<(&str, &str), String> = BTreeMap::new();
    let (mut closed, mut reasons, mut handle_futures, mut connect_failures) = (BTreeMap::new(), BTreeMap::new(), BTreeMap::new(), BTreeMap::new());
    for round in 0..ROUNDS {
        let call = FIRST_CALLS[round % FIRST_CALLS.len()];
        match a_round_with_the_link_cut_during_the_prompt(&server, call).await {
            Err(error) => *connect_failures.entry(error).or_insert(0) += 1,
            Ok(seen) => {
                *by_call.entry(call.name()).or_default().entry(seen.first_call).or_insert(0) += 1;
                *total.entry(seen.first_call).or_insert(0) += 1;
                examples.entry((call.name(), seen.first_call)).or_insert(seen.first_call_raw);
                *closed.entry(seen.is_closed_after_the_first_call).or_insert(0) += 1;
                *reasons.entry(seen.recorded_reason.unwrap_or_else(|| "none within 1 s".to_string())).or_insert(0) += 1;
                *handle_futures.entry(seen.handle_future).or_insert(0) += 1;
            }
        }
    }
    let prefix = "host_key.cut_during_prompt";
    fact(&format!("{prefix}.rounds"), ROUNDS);
    fact(&format!("{prefix}.connect_failed"), format!("{connect_failures:?}"));
    for (call, tally) in &by_call {
        fact(&format!("{prefix}.first_call.{call}"), format!("{tally:?}"));
    }
    fact(&format!("{prefix}.first_call.total"), format!("{total:?}"));
    for ((call, label), raw) in &examples {
        fact(&format!("{prefix}.example.{call}.{label}"), raw);
    }
    fact(&format!("{prefix}.is_closed_after_the_first_call"), format!("{closed:?}"));
    fact(&format!("{prefix}.recorded_reason"), format!("{reasons:?}"));
    fact(&format!("{prefix}.handle_future"), format!("{handle_futures:?}"));
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
