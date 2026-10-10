//! Task 3e, part 1: a two-hop jump the way the engine will build it: sshd A -> direct-tcpip -> `into_stream` -> `connect_stream` -> sshd B.
//! (OpenSSH's own `ssh -J` refuses to jump through the host it is going to, so there are two scratch servers.)

use std::time::Duration;

use russh::client::Config;
use russh::Disconnect;
use russh_spike::client::{connect_over, exec, Connection, HostKeyVerdict};
use russh_spike::fixture::Server;
use russh_spike::harness::tools;
use russh_spike::proxy::{Mode, Proxy};
use russh_spike::{fact, within};

/// Opens a direct-tcpip channel from `first` to `second`'s port and runs a whole SSH handshake over it.
async fn handshake_through(first: &Connection, second: &Server, verdict: HostKeyVerdict) -> Result<Connection, russh::Error> {
    let channel = first.handle.channel_open_direct_tcpip("127.0.0.1", u32::from(second.sshd.port), "127.0.0.1", 0).await?;
    connect_over(channel.into_stream(), Config::default(), verdict).await
}

#[tokio::test(flavor = "multi_thread")]
async fn a_two_hop_jump_runs_a_command_on_the_second_host() {
    let Some(tools) = tools() else { return };
    let (a, b) = (Server::start(&tools, &[]), Server::start(&tools, &[]));
    let first = a.session().await;

    let mut second = within(30, "the second handshake", handshake_through(&first, &b, HostKeyVerdict::AcceptAny)).await.expect("jump");
    b.login(&mut second).await;
    let out = within(20, "exec on B", exec(&second.handle, "echo hop-$((20+22))")).await.unwrap();
    assert_eq!(out.text(), "hop-42\n");

    // The second handshake really was with B: each hop checks its own host key.
    assert_eq!(*second.observed.host_keys.lock().unwrap(), vec![b.host_fingerprint()]);
    assert_ne!(b.host_fingerprint(), a.host_fingerprint());
    assert_eq!(*first.observed.host_keys.lock().unwrap(), vec![a.host_fingerprint()]);
}

#[tokio::test(flavor = "multi_thread")]
async fn the_second_hop_checks_its_own_host_key_and_the_first_hop_survives_a_refusal() {
    let Some(tools) = tools() else { return };
    let (a, b) = (Server::start(&tools, &[]), Server::start(&tools, &[]));
    let first = a.session().await;

    let error = within(30, "the second handshake", handshake_through(&first, &b, HostKeyVerdict::RejectAll)).await.err().expect("refused");
    assert!(matches!(error, russh::Error::UnknownKey), "got {error:?}");
    assert_eq!(within(20, "exec on A", exec(&first.handle, "echo a-still-works")).await.unwrap().text(), "a-still-works\n");
}

/// The jump target is a port nothing listens on: sshd A's refusal comes back as a channel-open failure, quickly, and A stays usable.
#[tokio::test(flavor = "multi_thread")]
async fn a_jump_to_a_closed_port_fails_cleanly() {
    let Some(tools) = tools() else { return };
    let (a, b) = (Server::start(&tools, &[]), Server::start(&tools, &[]));
    let first = a.session().await;
    let closed_port = b.sshd.port;
    drop(b);
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;

    let started = std::time::Instant::now();
    let result = within(20, "open a direct-tcpip channel to a closed port", first.handle.channel_open_direct_tcpip("127.0.0.1", u32::from(closed_port), "127.0.0.1", 0)).await;
    let error = result.err().expect("nothing listens there");
    fact("jump.closed_port.error", format!("{error:?}"));
    fact("jump.closed_port.after_ms", started.elapsed().as_millis());
    assert!(matches!(error, russh::Error::ChannelOpenFailure(_)), "got {error:?}");
    assert_eq!(within(20, "exec on A", exec(&first.handle, "echo a-still-works")).await.unwrap().text(), "a-still-works\n");
}

/// Hop lifetimes: when the outer connection goes away, the inner one (carried inside it) must end too, or the broker leaks sessions.
///
/// It does end. What differs from the brief is HOW the end shows up. The brief waited for the second hop's `Handler::disconnected`
/// (`wait_for_disconnect(10)`) and that timed out: "timed out after 10 s: russh to report the disconnect". Measured, and asserted below:
/// the second hop's `Handle` future resolves at once and `is_closed()` is true, but russh never calls `disconnected` for it. In
/// `client::Session::run` the inner stream is shut down BEFORE the callback; the shutdown sends an EOF through the first hop's channel, which
/// fails because the first hop is gone, and the `?` returns first. So the end-of-session signal an engine can rely on is the `Handle` future
/// (or `is_closed()`), not the callback. What that future yields (BrokenPipe, "channel closed") is the SECONDARY error of the failed
/// shutdown, not the cause: the cause is only in the first hop's own record (`first.observed`), so an inner hop's disconnect reason has to
/// be taken from the outer hop.
#[tokio::test(flavor = "multi_thread")]
async fn closing_the_first_hop_ends_the_second() {
    let Some(tools) = tools() else { return };
    let (a, b) = (Server::start(&tools, &[]), Server::start(&tools, &[]));
    let first = a.session().await;
    let mut second = within(30, "the second handshake", handshake_through(&first, &b, HostKeyVerdict::AcceptAny)).await.expect("jump");
    b.login(&mut second).await;

    within(20, "disconnect the first hop", first.handle.disconnect(Disconnect::ByApplication, "", "en")).await.unwrap();
    // the design expected: `second.observed.wait_for_disconnect(10)` returns a reason, as it does for a single hop (tests/keepalive.rs)
    let ended = within(10, "the second hop to end after the first was disconnected", &mut second.handle).await;
    fact("jump.close_first_hop.second_hop_end", format!("{ended:?}"));
    assert!(ended.is_err(), "the second hop's session task must end with an error when its carrier is gone, got {ended:?}");
    fact("jump.close_first_hop.second_hop_is_closed", second.handle.is_closed());
    assert!(second.handle.is_closed(), "the session task has ended, so the handle must say so");
    let reason = second.observed.disconnect.lock().unwrap().clone();
    fact("jump.close_first_hop.second_hop_reason", format!("{reason:?}"));
    assert_eq!(reason, None, "russh called Handler::disconnected for an inner hop: the callback has become usable, update the comment above");
    // The cause is in the first hop's own record (the wait is bounded and does not depend on which of the two ends is recorded first).
    let first_reason = first.observed.wait_for_disconnect(10).await;
    fact("jump.close_first_hop.first_hop_reason", &first_reason);
    assert_eq!(first_reason, "Error(Disconnect)", "a disconnect we asked for reaches our own handler as Error(Disconnect)");
}

/// A fact, not a requirement (found while investigating the test above): what the second hop sees when the first goes away in the two
/// other ways a broker can lose it. 1) The TCP link under the first hop dies. 2) The first hop's `Handle` is dropped while the second hop
/// is in use (an easy thing to do: the engine only needs the channel's stream, not the outer handle), and then the second is dropped too.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "an observation for the report: run with --ignored --nocapture"]
async fn observe_how_the_second_hop_learns_that_the_first_is_gone() {
    let Some(tools) = tools() else { return };
    let (a, b) = (Server::start(&tools, &[]), Server::start(&tools, &[]));

    // 1) The link under the first hop dies.
    let proxy = Proxy::start(a.sshd.port).await;
    let first = a.connect_and_login(proxy.port, Config::default(), HostKeyVerdict::AcceptAny).await;
    let mut second = within(30, "the second handshake", handshake_through(&first, &b, HostKeyVerdict::AcceptAny)).await.expect("jump");
    b.login(&mut second).await;
    proxy.set(Mode::Cut);
    let cut = std::time::Instant::now();
    let second_observed = second.observed.clone();
    let ended = within(10, "the second hop to end after the cut", second.handle).await;
    fact("jump.cut_first_hop.second_hop_end", format!("{ended:?}"));
    fact("jump.cut_first_hop.second_hop_end_after_ms", cut.elapsed().as_millis());
    tokio::time::sleep(Duration::from_millis(300)).await;
    fact("jump.cut_first_hop.second_hop_reason", format!("{:?}", second_observed.disconnect.lock().unwrap()));
    fact("jump.cut_first_hop.first_hop_reason", format!("{:?}", first.observed.disconnect.lock().unwrap()));

    // 2) The first hop's Handle is dropped; the second keeps being used.
    let first = a.session().await;
    let first_observed = first.observed.clone();
    let mut second = within(30, "the second handshake", handshake_through(&first, &b, HostKeyVerdict::AcceptAny)).await.expect("jump");
    b.login(&mut second).await;
    drop(first.handle);
    tokio::time::sleep(Duration::from_secs(1)).await;
    fact("jump.drop_first_handle.second_hop_closed", second.handle.is_closed());
    fact("jump.drop_first_handle.first_hop_reason", format!("{:?}", first_observed.disconnect.lock().unwrap()));
    let out = within(10, "exec on the second hop", exec(&second.handle, "echo second-works")).await;
    fact("jump.drop_first_handle.exec_on_second_hop", format!("{:?}", out.map(|out| out.text())));
    drop(second);
    tokio::time::sleep(Duration::from_secs(1)).await;
    fact("jump.drop_both_handles.first_hop_reason", format!("{:?}", first_observed.disconnect.lock().unwrap()));
}
