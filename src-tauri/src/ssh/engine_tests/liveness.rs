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
