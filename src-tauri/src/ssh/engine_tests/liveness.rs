//! How long a connection lives and how it ends: keepalive, a cut link, closing and dropping (spec §6.2 steps 2, 3 and 5).

use std::time::{Duration, Instant};

use super::{accepted_logins, engine, open_session, open_session_to, settle, LOG_LOGINS};
use crate::ssh::testing::fixture::Server;
use crate::ssh::testing::harness::tools;
use crate::ssh::testing::proxy::{Mode, Proxy};
use crate::ssh::testing::{eventually, fact};
use crate::ssh::{AuthMethod, DisconnectKind, SessionError, Target};

const MIB: usize = 1024 * 1024;

/// A server behind a proxy, a session through it, and the proxy to misbehave with.
fn session_through_a_proxy(server: &Server, keepalive_every: Duration, max_missed: u32) -> (Box<dyn crate::ssh::Session>, Proxy) {
    let proxy = Proxy::start(server.sshd.port);
    let mut hop = server.hop_with("web", proxy.port, AuthMethod::Key { key_id: "k1".into() });
    hop.keepalive_every = keepalive_every;
    hop.keepalive_max_missed = max_missed;
    let session = open_session_to(&engine(), &Target { hops: vec![hop] }, &server.vault("k1"));
    (session, proxy)
}

/// russh's keepalive is "nothing received for this long", and a link that goes quiet is noticed after (max_missed + 1) × every; the
/// spike measured 3044 ms for 1 s and 2 on macOS. The bounds are wide, the point is the order of magnitude and the reason.
#[test]
fn keepalive_closes_a_silent_link_and_the_reason_says_so() {
    let Some(tools) = tools() else { return };
    let server = Server::start(&tools, &[]);
    let (session, proxy) = session_through_a_proxy(&server, Duration::from_secs(1), 2);
    assert!(session.is_alive() && session.disconnect_reason().is_none());

    proxy.set(Mode::Blackhole);
    let silenced = Instant::now();
    eventually("keepalive to give up on the silent link", 20, || !session.is_alive());
    let noticed_after = silenced.elapsed();
    fact("keepalive.interval_1s_max_2.noticed_after_ms", noticed_after.as_millis());
    assert!(noticed_after >= Duration::from_secs(2) && noticed_after <= Duration::from_secs(10), "noticed after {noticed_after:?}");

    let reason = session.disconnect_reason().expect("a dead session says why");
    assert_eq!((reason.kind, reason.hop.alias.as_str()), (DisconnectKind::KeepaliveTimeout, "web"), "{reason:?}");
    assert_eq!(session.exec("echo never", Duration::from_secs(5), MIB), Err(SessionError::Closed));
}

#[test]
fn a_link_that_answers_keeps_the_session_alive_across_several_intervals() {
    let Some(tools) = tools() else { return };
    let server = Server::start(&tools, &[]);
    let (session, _proxy) = session_through_a_proxy(&server, Duration::from_secs(1), 2);

    std::thread::sleep(Duration::from_secs(6));
    assert!(session.is_alive(), "the session was closed while the peer was answering: {:?}", session.disconnect_reason());
    assert_eq!(session.exec("echo still-here", Duration::from_secs(10), MIB).unwrap().stdout, b"still-here\n");
}

#[test]
fn a_link_that_is_cut_while_idle_is_noticed_as_a_lost_connection() {
    let Some(tools) = tools() else { return };
    let server = Server::start(&tools, &[]);
    let (session, proxy) = session_through_a_proxy(&server, Duration::ZERO, 0);

    proxy.set(Mode::Cut);
    eventually("the cut to be noticed", 10, || !session.is_alive());
    let reason = session.disconnect_reason().expect("a dead session says why");
    fact("cut_while_idle.reason", format!("{:?} {}", reason.kind, reason.detail));
    assert_eq!(reason.kind, DisconnectKind::ConnectionLost, "{reason:?}");
}

#[test]
fn closing_a_session_sends_a_disconnect_and_the_reason_is_ours() {
    let Some(tools) = tools() else { return };
    let server = Server::start(&tools, &[LOG_LOGINS]);
    let session = open_session(&engine(), &server);
    eventually("sshd to log the login", 3, || accepted_logins(&server) == 1);
    settle(session.as_ref());

    session.close();
    session.close();
    assert!(!session.is_alive());
    let reason = session.disconnect_reason().expect("closed");
    assert_eq!(reason.kind, DisconnectKind::ClosedByUs);
    eventually("sshd to log a disconnect message (a dropped socket would not be one)", 5, || server.sshd.log().contains("Received disconnect"));
}

#[test]
fn dropping_a_session_closes_the_connection_with_a_disconnect() {
    let Some(tools) = tools() else { return };
    let server = Server::start(&tools, &[LOG_LOGINS]);
    let session = open_session(&engine(), &server);
    eventually("sshd to log the login", 3, || accepted_logins(&server) == 1);
    settle(session.as_ref());

    drop(session);
    eventually("sshd to log a disconnect message", 5, || server.sshd.log().contains("Received disconnect"));
}

/// Review focus: an idle connection must cost nothing. With a 1 s keepalive the session sends a probe every second and gets an answer;
/// that must not turn into a busy loop. The process-wide CPU time is only meaningful when nothing else runs, so a child process of the
/// test binary does the measuring.
#[cfg(unix)]
#[test]
fn an_authenticated_connection_that_idles_with_keepalive_does_not_burn_cpu() {
    use crate::ssh::testing::{cpu_time_ms, fact_in, is_child, rerun_alone};

    const NAME: &str = "ssh::engine_tests::liveness::an_authenticated_connection_that_idles_with_keepalive_does_not_burn_cpu";
    let Some(tools) = tools() else { return };
    if !is_child() {
        let output = rerun_alone(NAME);
        let used: u128 = fact_in(&output, "idle.authenticated.cpu_ms").expect("the child measured").parse().expect("a number");
        assert!(used < 500, "2.5 s of idling used {used} ms of CPU");
        return;
    }
    let server = Server::start(&tools, &[]);
    let (session, _proxy) = session_through_a_proxy(&server, Duration::from_secs(1), 3);
    std::thread::sleep(Duration::from_millis(1000));
    let before = cpu_time_ms();
    std::thread::sleep(Duration::from_millis(2500));
    fact("idle.authenticated.cpu_ms", cpu_time_ms() - before);
    assert!(session.is_alive());
}

/// Review focus: russh starts its keepalive timer when the server's version line is in, and until the login is done only a packet from
/// the server re-arms it, so an interval that passes in silence makes russh's session loop spin until the server speaks again. The engine
/// has to give up first: with a 2 s interval and a 6 s connect timeout it stops waiting for a handshake that has gone quiet after 1.5 s
/// (`stall_limit`), not after 6 s. The server here sends its version line and then nothing. The CPU time of the process is only
/// meaningful when nothing else runs in it, so a child process of the test binary does the measuring.
#[cfg(unix)]
#[test]
fn a_handshake_that_goes_quiet_is_given_up_on_before_the_keepalive_interval_makes_russh_spin() {
    use std::io::{Read, Write};
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;

    use crate::ssh::testing::doubles::{TestPolicy, VaultAuth};
    use crate::ssh::testing::{cpu_time_ms, fact_in, is_child, rerun_alone};
    use crate::ssh::{ConnectError, Hop, Phase};

    const NAME: &str = "ssh::engine_tests::liveness::a_handshake_that_goes_quiet_is_given_up_on_before_the_keepalive_interval_makes_russh_spin";
    if !is_child() {
        let output = rerun_alone(NAME);
        let measured = |key: &str| -> u128 { fact_in(&output, key).expect("the child measured").parse().expect("a number") };
        let waited = measured("quiet_handshake.waited_ms");
        let (during, after) = (measured("quiet_handshake.cpu_during_call_ms"), measured("quiet_handshake.cpu_after_call_ms"));
        assert!(waited < 3000, "the engine waited {waited} ms for a quiet handshake with a keepalive interval of 2000 ms");
        assert!(during < 500 && after < 500, "a quiet handshake used {during} ms of CPU during the call and {after} ms in the 2 s after it");
        return;
    }
    let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).expect("a port for the quiet server");
    let port = listener.local_addr().expect("its address").port();
    let ended = Arc::new(AtomicBool::new(false));
    let server = {
        let ended = Arc::clone(&ended);
        std::thread::spawn(move || {
            let (mut socket, _) = listener.accept().expect("the engine connects");
            socket.write_all(b"SSH-2.0-quiet\r\n").expect("the version line goes out");
            // Takes in whatever the client sends until the client's end of the connection is closed.
            let mut buffer = [0u8; 4096];
            while matches!(socket.read(&mut buffer), Ok(count) if count > 0) {}
            ended.store(true, Ordering::SeqCst);
        })
    };
    let mut hop = Hop::new("h1", "quiet", "127.0.0.1", port, "tester", AuthMethod::Key { key_id: "k1".into() });
    hop.keepalive_every = Duration::from_secs(2);
    hop.connect_timeout = Duration::from_secs(6);

    // The engine stays alive to the end: shutting it down ends every task it runs, and that would hide one that is left behind spinning.
    let engine = engine();
    let (cpu_before, started) = (cpu_time_ms(), Instant::now());
    let error = engine.connect_chain(&Target { hops: vec![hop] }, &*TestPolicy::trusting(), &VaultAuth::new()).err().expect("the handshake never finishes");
    fact("quiet_handshake.waited_ms", started.elapsed().as_millis());
    fact("quiet_handshake.cpu_during_call_ms", cpu_time_ms() - cpu_before);
    // The interval runs out 2 s after the server's last packet; a task the engine left behind would spin from then on.
    let cpu_before = cpu_time_ms();
    std::thread::sleep(Duration::from_secs(2));
    fact("quiet_handshake.cpu_after_call_ms", cpu_time_ms() - cpu_before);
    assert!(matches!(error, ConnectError::Timeout { phase: Phase::Handshake, .. }), "{error:?}");
    eventually("the server to see the engine close its end of the connection", 5, || ended.load(Ordering::SeqCst));
    server.join().expect("the quiet server thread");
}

/// The same for the login: the server takes the public-key request and then says nothing. The wait for its answer is bounded by
/// `stall_limit` as well, so with a 2 s interval and a 6 s connect timeout it ends after 1.5 s, not after 6 s.
#[cfg(unix)]
#[test]
fn a_login_that_goes_quiet_is_given_up_on_before_the_keepalive_interval_makes_russh_spin() {
    use std::sync::Arc;

    use crate::ssh::testing::doubles::{TestPolicy, VaultAuth};
    use crate::ssh::testing::{cpu_time_ms, fact_in, is_child, rerun_alone};
    use crate::ssh::{AuthError, AuthSource, ConnectError, HopRef, Phase, Prompt, RsaHash, Secret, Signature};

    /// A vault double that turns the link into a black hole when the engine asks it for the public key, the first thing it asks once the
    /// handshake is done.
    struct QuietAtLogin {
        inner: VaultAuth,
        link: Arc<Proxy>,
    }

    impl AuthSource for QuietAtLogin {
        fn public_key(&self, key_id: &str) -> Option<String> {
            self.link.set(Mode::Blackhole);
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

    const NAME: &str = "ssh::engine_tests::liveness::a_login_that_goes_quiet_is_given_up_on_before_the_keepalive_interval_makes_russh_spin";
    let Some(tools) = tools() else { return };
    if !is_child() {
        let output = rerun_alone(NAME);
        let measured = |key: &str| -> u128 { fact_in(&output, key).expect("the child measured").parse().expect("a number") };
        let waited = measured("quiet_login.waited_ms");
        let (during, after) = (measured("quiet_login.cpu_during_call_ms"), measured("quiet_login.cpu_after_call_ms"));
        assert!(waited < 3000, "the engine waited {waited} ms for a quiet login with a keepalive interval of 2000 ms");
        assert!(during < 500 && after < 500, "a quiet login used {during} ms of CPU during the call and {after} ms in the 2 s after it");
        return;
    }
    let server = Server::start(&tools, &[]);
    let proxy = Arc::new(Proxy::start(server.sshd.port));
    let mut hop = server.hop_with("web", proxy.port, AuthMethod::Key { key_id: "k1".into() });
    hop.keepalive_every = Duration::from_secs(2);
    hop.connect_timeout = Duration::from_secs(6);
    let auth = QuietAtLogin { inner: server.vault("k1"), link: Arc::clone(&proxy) };

    // The engine stays alive to the end: shutting it down ends every task it runs, and that would hide one that is left behind spinning.
    let engine = engine();
    let (cpu_before, started) = (cpu_time_ms(), Instant::now());
    let error = engine.connect_chain(&Target { hops: vec![hop] }, &*TestPolicy::trusting(), &auth).err().expect("the server went quiet");
    fact("quiet_login.waited_ms", started.elapsed().as_millis());
    fact("quiet_login.cpu_during_call_ms", cpu_time_ms() - cpu_before);
    // The interval runs out 2 s after the server's last packet; a task the engine left behind would spin from then on.
    let cpu_before = cpu_time_ms();
    std::thread::sleep(Duration::from_secs(2));
    fact("quiet_login.cpu_after_call_ms", cpu_time_ms() - cpu_before);
    assert!(matches!(error, ConnectError::Timeout { phase: Phase::Auth, .. }), "{error:?}");
}
