//! Task 3d: a link that misbehaves (the proxy in src/proxy.rs): keepalive, a connection dropped mid-command, a handshake that never answers.

use std::time::{Duration, Instant};

use russh::client::Config;
use russh_spike::client::{connect, drain, exec, HostKeyVerdict};
use russh_spike::fixture::Server;
use russh_spike::harness::tools;
use russh_spike::proxy::{Mode, Proxy};
use russh_spike::{fact, within};

fn keepalive_config(interval_secs: u64, max: usize) -> Config {
    Config { keepalive_interval: Some(Duration::from_secs(interval_secs)), keepalive_max: max, ..Config::default() }
}

/// russh's `keepalive_interval` is "nothing received for this long", and `keepalive_max` is how many unanswered probes it tolerates. The spec's
/// `keepalive_secs` / `keepalive_max_missed` map onto them; this measures how long a silent link takes to be noticed.
#[tokio::test(flavor = "multi_thread")]
async fn keepalive_closes_a_silent_link_and_reports_keepalive_timeout() {
    let Some(tools) = tools() else { return };
    let server = Server::start(&tools, &[]);
    let proxy = Proxy::start(server.sshd.port).await;
    let connection = server.connect_and_login(proxy.port, keepalive_config(1, 2), HostKeyVerdict::AcceptAny).await;

    proxy.set(Mode::Blackhole);
    let silenced = Instant::now();
    let reason = connection.observed.wait_for_disconnect(30).await;
    let noticed_after = silenced.elapsed();
    fact("keepalive.interval_1s_max_2.noticed_after_ms", noticed_after.as_millis());
    fact("keepalive.interval_1s_max_2.reason", &reason);
    assert!(reason.contains("KeepaliveTimeout"), "the reason was {reason}");
    assert!(noticed_after >= Duration::from_secs(2), "noticed after only {noticed_after:?}");
    assert!(noticed_after <= Duration::from_secs(10), "noticed after {noticed_after:?}");

    // After that the handle is dead: an exec fails promptly instead of hanging.
    let result = within(10, "exec on the dead connection", exec(&connection.handle, "echo never")).await;
    assert!(result.is_err(), "exec on a connection that russh closed returned {result:?}");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_link_that_answers_keeps_the_session_alive_across_several_intervals() {
    let Some(tools) = tools() else { return };
    let server = Server::start(&tools, &[]);
    let proxy = Proxy::start(server.sshd.port).await;
    let connection = server.connect_and_login(proxy.port, keepalive_config(1, 2), HostKeyVerdict::AcceptAny).await;

    tokio::time::sleep(Duration::from_secs(6)).await;
    assert!(connection.observed.disconnect.lock().unwrap().is_none(), "the session was closed while the peer was answering");
    assert_eq!(within(20, "exec", exec(&connection.handle, "echo still-here")).await.unwrap().text(), "still-here\n");
}

/// Review Focus 3, second half. The link dies while a command runs: the exec must END, with no exit status, instead of waiting for ever
/// or inventing an exit code.
#[tokio::test(flavor = "multi_thread")]
async fn a_connection_cut_during_an_exec_ends_it_without_an_exit_status() {
    let Some(tools) = tools() else { return };
    let server = Server::start(&tools, &[]);
    let proxy = Proxy::start(server.sshd.port).await;
    let connection = server.connect_and_login(proxy.port, Config::default(), HostKeyVerdict::AcceptAny).await;

    let mut channel = within(20, "open a session channel", connection.handle.channel_open_session()).await.unwrap();
    channel.exec(true, "sleep 30").await.unwrap();
    tokio::time::sleep(Duration::from_millis(500)).await;

    proxy.set(Mode::Cut);
    let cut = Instant::now();
    let out = within(10, "the exec to end after the cut", drain(&mut channel)).await;
    fact("cut_during_exec.ended_after_ms", cut.elapsed().as_millis());
    assert_eq!(out.exit_status, None);
    let reason = connection.observed.wait_for_disconnect(10).await;
    fact("cut_during_exec.reason", &reason);
}

/// russh's `Config` has no connect or handshake timeout, and `client::connect` waits for the server's banner for as long as it takes.
/// The engine must wrap the whole connect in `tokio::time::timeout`.
#[tokio::test(flavor = "multi_thread")]
async fn a_handshake_that_never_gets_an_answer_needs_our_own_timeout() {
    let Some(tools) = tools() else { return };
    let server = Server::start(&tools, &[]);
    let proxy = Proxy::start(server.sshd.port).await;
    proxy.set(Mode::Blackhole);

    let started = Instant::now();
    let outcome = tokio::time::timeout(Duration::from_secs(2), connect(proxy.port, Config::default(), HostKeyVerdict::AcceptAny)).await;
    fact("handshake_stall.waited_ms", started.elapsed().as_millis());
    assert!(outcome.is_err(), "connect finished against a link that delivers nothing");
}
