//! Jump hosts: a chain of connections, each carried inside the one before it (spec §6.2 step 2).

use std::time::{Duration, Instant};

use super::{accepted_logins, engine, settle, ShellProbe, LOG_LOGINS, SHELL_SERVER};
use crate::ssh::testing::doubles::{TestPolicy, VaultAuth};
use crate::ssh::testing::fixture::Server;
use crate::ssh::testing::harness::{tools, Tools};
use crate::ssh::testing::proxy::{Mode, Proxy};
use crate::ssh::testing::{closed_port, eventually, fact};
use crate::ssh::{AuthMethod, ConnectError, DisconnectKind, Ended, Pty, Session, SshEngine, Target};

const MIB: usize = 1024 * 1024;

/// Two scratch servers, `a` (the jump host) and `b` (the destination), and one vault holding both user keys.
struct Pair {
    a: Server,
    b: Server,
    vault: VaultAuth,
}

fn pair(tools: &Tools, config_a: &[&str], config_b: &[&str]) -> Pair {
    let (a, b) = (Server::start(tools, config_a), Server::start(tools, config_b));
    let vault = VaultAuth::new().with_key("ka", &a.key.private_text).with_key("kb", &b.key.private_text);
    Pair { a, b, vault }
}

fn key(id: &str) -> AuthMethod {
    AuthMethod::Key { key_id: id.to_string() }
}

/// `a` reached on `port_a` (its own, or a proxy's), then `b` as `a` sees it, on `port_b`.
fn chain(pair: &Pair, port_a: u16, port_b: u16) -> Target {
    Target { hops: vec![pair.a.hop_with("a", port_a, key("ka")), pair.b.hop_with("b", port_b, key("kb"))] }
}

fn open(pair: &Pair, target: &Target) -> Box<dyn Session> {
    engine().connect(target, &*TestPolicy::trusting(), &pair.vault).expect("the chain connects")
}

/// The server port in what `$SSH_CONNECTION` held for a command ("client-ip client-port server-ip server-port"): the port of the sshd
/// that ran it. It tells the hosts of a chain apart, which an `echo` cannot (it prints the same on every host).
fn server_port_in(ssh_connection: &str) -> Option<u16> {
    ssh_connection.split_whitespace().nth(3)?.parse().ok()
}

#[test]
fn a_two_hop_jump_runs_a_command_on_the_second_host_and_checks_each_hops_own_host_key() {
    let Some(tools) = tools() else { return };
    let pair = pair(&tools, &[], &[]);
    let policy = TestPolicy::trusting();
    let target = chain(&pair, pair.a.sshd.port, pair.b.sshd.port);

    let session = engine().connect(&target, &*policy, &pair.vault).expect("the chain connects");
    // The command prints the sshd's view of the connection it runs in; the server port in it is the port of the host that ran it.
    let result = session.exec("echo hop-$((20+22)) $SSH_CONNECTION", Duration::from_secs(20), MIB).unwrap();
    assert_eq!(result.ended, Ended::Exited);
    let output = String::from_utf8_lossy(&result.stdout).into_owned();
    let connection = output.strip_prefix("hop-42 ").unwrap_or_else(|| panic!("unexpected output {output:?}"));
    assert_eq!(
        server_port_in(connection),
        Some(pair.b.sshd.port),
        "the command did not run on the second host: {output:?} (a listens on {}, b on {})",
        pair.a.sshd.port,
        pair.b.sshd.port
    );

    assert_ne!(pair.a.host_key(), pair.b.host_key());
    let seen: Vec<(String, _)> = policy.seen().into_iter().map(|(hop, key)| (hop.alias, key)).collect();
    assert_eq!(seen, vec![("a".to_string(), pair.a.host_key()), ("b".to_string(), pair.b.host_key())], "each hop was checked against its own key");
}

/// The destination's host key is unknown: the chain stops there with the key it presented, and the jump host's connection does not linger.
#[test]
fn an_unknown_key_on_the_second_hop_stops_the_chain_and_closes_the_first_hop() {
    let Some(tools) = tools() else { return };
    let pair = pair(&tools, &[], &[]);
    let proxy_a = Proxy::start(pair.a.sshd.port);
    let target = chain(&pair, proxy_a.port, pair.b.sshd.port);
    let policy = TestPolicy::knowing_nothing();
    policy.pin(&target.hops[0].reference(), pair.a.host_key());

    // The engine is held until the proxy has been looked at: dropping the last owner of its runtime closes every socket there is, and that
    // would hide a jump host that `connect` left open.
    let engine = engine();
    let error = engine.connect(&target, &*policy, &pair.vault).err().expect("b is not pinned");
    match error {
        ConnectError::HostKeyUnknown { hop, key } => assert_eq!((hop.alias.as_str(), key), ("b", pair.b.host_key())),
        other => panic!("expected HostKeyUnknown, got {other:?}"),
    }
    eventually("the proxy to see the first hop closed", 5, || proxy_a.open_connections() == 0);
}

/// Review focus: the jump host cannot reach the next host. The message names the jump host, comes quickly, and nothing lingers.
#[test]
fn a_jump_to_a_closed_port_fails_cleanly_and_names_the_jump_host() {
    let Some(tools) = tools() else { return };
    let pair = pair(&tools, &[], &[]);
    let proxy_a = Proxy::start(pair.a.sshd.port);
    let target = chain(&pair, proxy_a.port, closed_port());

    let engine = engine(); // held until the proxy has been looked at, as in the test above
    let started = Instant::now();
    let error = engine.connect(&target, &*TestPolicy::trusting(), &pair.vault).err().expect("nothing listens there");
    fact("jump.closed_port.after_ms", started.elapsed().as_millis());
    match &error {
        ConnectError::Unreachable { hop, reason } => assert_eq!((hop.alias.as_str(), reason.as_str()), ("b", "a could not connect to it")),
        other => panic!("expected Unreachable, got {other:?}"),
    }
    assert!(started.elapsed() < Duration::from_secs(10));
    eventually("the proxy to see the first hop closed", 5, || proxy_a.open_connections() == 0);
}

#[test]
fn a_jump_host_that_does_not_allow_forwarding_is_named_in_the_error() {
    let Some(tools) = tools() else { return };
    let pair = pair(&tools, &["AllowTcpForwarding no"], &[]);
    let proxy_a = Proxy::start(pair.a.sshd.port);
    let target = chain(&pair, proxy_a.port, pair.b.sshd.port);
    let engine = engine(); // held until the proxy has been looked at, as above
    let error = engine.connect(&target, &*TestPolicy::trusting(), &pair.vault).err().expect("forwarding is off");
    assert!(matches!(&error, ConnectError::Unreachable { hop, reason } if hop.alias == "b" && reason == "a does not allow forwarding"), "{error:?}");
    eventually("the proxy to see the first hop closed", 5, || proxy_a.open_connections() == 0);
}

/// The destination refuses the login: the error names it, and the jump host's connection does not linger. The vault holds the jump
/// host's user key under the destination's key id, and the destination does not list that key.
#[test]
fn a_second_hop_that_refuses_the_login_is_named_and_the_first_hop_is_closed() {
    let Some(tools) = tools() else { return };
    let pair = pair(&tools, &[], &[]);
    let vault = VaultAuth::new().with_key("ka", &pair.a.key.private_text).with_key("kb", &pair.a.key.private_text);
    let proxy_a = Proxy::start(pair.a.sshd.port);
    let target = chain(&pair, proxy_a.port, pair.b.sshd.port);
    let engine = engine(); // held until the proxy has been looked at, as above
    let error = engine.connect(&target, &*TestPolicy::trusting(), &vault).err().expect("b does not list the key");
    assert!(matches!(&error, ConnectError::AuthFailed { hop, tried, .. } if hop.alias == "b" && tried.contains(&key("kb"))), "{error:?}");
    eventually("the proxy to see the first hop closed", 5, || proxy_a.open_connections() == 0);
}

#[test]
fn closing_the_session_disconnects_every_hop() {
    let Some(tools) = tools() else { return };
    let pair = pair(&tools, &[LOG_LOGINS], &[LOG_LOGINS]);
    let session = open(&pair, &chain(&pair, pair.a.sshd.port, pair.b.sshd.port));
    eventually("both servers to log the login", 3, || accepted_logins(&pair.a) == 1 && accepted_logins(&pair.b) == 1);
    settle(session.as_ref());

    session.close();
    eventually("the destination to log a disconnect message", 5, || pair.b.sshd.log().contains("Received disconnect"));
    eventually("the jump host to log a disconnect message", 5, || pair.a.sshd.log().contains("Received disconnect"));
}

/// More than one jump (spec decision 4, ProxyJump with several levels): the third hop is opened with a `direct-tcpip` request on a session
/// whose own transport is a channel of the first one, and closing has three hops to disconnect, the innermost first.
#[test]
fn a_three_hop_chain_runs_a_command_on_the_last_host_and_closing_disconnects_every_hop() {
    let Some(tools) = tools() else { return };
    let (a, b, c) = (Server::start(&tools, &[LOG_LOGINS]), Server::start(&tools, &[LOG_LOGINS]), Server::start(&tools, &[LOG_LOGINS]));
    let vault = VaultAuth::new().with_key("ka", &a.key.private_text).with_key("kb", &b.key.private_text).with_key("kc", &c.key.private_text);
    let target = Target {
        hops: vec![a.hop_with("a", a.sshd.port, key("ka")), b.hop_with("b", b.sshd.port, key("kb")), c.hop_with("c", c.sshd.port, key("kc"))],
    };
    let policy = TestPolicy::trusting();

    // The engine is held in a binding: it owns the runtime that drives the three connections.
    let engine = engine();
    let session = engine.connect(&target, &*policy, &vault).expect("the chain connects");
    eventually("all three servers to log the login", 3, || accepted_logins(&a) == 1 && accepted_logins(&b) == 1 && accepted_logins(&c) == 1);

    // This also settles the destination (see `settle`) before the session is closed.
    let result = session.exec("echo $SSH_CONNECTION", Duration::from_secs(20), MIB).unwrap();
    assert_eq!((result.ended, result.exit_code), (Ended::Exited, Some(0)));
    let output = String::from_utf8_lossy(&result.stdout).into_owned();
    assert_eq!(
        server_port_in(&output),
        Some(c.sshd.port),
        "the command did not run on the third host: {output:?} (a listens on {}, b on {}, c on {})",
        a.sshd.port,
        b.sshd.port,
        c.sshd.port
    );
    let aliases: Vec<String> = policy.seen().into_iter().map(|(hop, _)| hop.alias).collect();
    assert_eq!(aliases, ["a", "b", "c"], "each hop was checked, in order");

    session.close();
    eventually("the destination to log a disconnect message", 5, || c.sshd.log().contains("Received disconnect"));
    eventually("the second host to log a disconnect message", 5, || b.sshd.log().contains("Received disconnect"));
    eventually("the first host to log a disconnect message", 5, || a.sshd.log().contains("Received disconnect"));
}

/// The outer link dies: the reason is the outer hop's own record. The inner hop only learns that its carrier is gone (spec §6.2 step 2).
#[test]
fn when_the_outer_link_is_cut_the_reason_is_the_outer_hops() {
    let Some(tools) = tools() else { return };
    let pair = pair(&tools, &[], &[]);
    let proxy_a = Proxy::start(pair.a.sshd.port);
    let session = open(&pair, &chain(&pair, proxy_a.port, pair.b.sshd.port));
    assert!(session.is_alive());

    proxy_a.set(Mode::Cut);
    eventually("the cut to be noticed", 10, || !session.is_alive());
    let reason = session.disconnect_reason().expect("a dead session says why");
    fact("jump.outer_cut.reason", format!("{:?} {} {}", reason.kind, reason.hop.alias, reason.detail));
    assert_eq!((reason.hop.alias.as_str(), reason.kind), ("a", DisconnectKind::ConnectionLost), "{reason:?}");
}

/// Not measured in the spike (spec §16): the inner hop ends first while the outer one is fine. A proxy between `a` and `b` is cut. The
/// whole chain must come down, and the reason must be the inner hop's, not the "closed by us" that the teardown makes the outer hop record.
#[test]
fn when_the_inner_hop_ends_first_the_chain_comes_down_and_the_reason_is_the_inner_hops() {
    let Some(tools) = tools() else { return };
    let pair = pair(&tools, &[LOG_LOGINS], &[]);
    let proxy_b = Proxy::start(pair.b.sshd.port);
    let session = open(&pair, &chain(&pair, pair.a.sshd.port, proxy_b.port));
    eventually("the jump host to log the login", 3, || accepted_logins(&pair.a) == 1);

    proxy_b.set(Mode::Cut);
    eventually("the loss of the inner hop to be noticed", 10, || !session.is_alive());
    let reason = session.disconnect_reason().expect("a dead session says why");
    fact("jump.inner_first.reason", format!("{:?} {} {}", reason.kind, reason.hop.alias, reason.detail));
    assert_eq!((reason.hop.alias.as_str(), reason.kind), ("b", DisconnectKind::ConnectionLost), "{reason:?}");
    eventually("the outer hop to be disconnected as well", 10, || pair.a.sshd.log().contains("Received disconnect"));
    assert_eq!(session.disconnect_reason().map(|again| again.hop.alias), Some("b".to_string()), "the reason does not change afterwards");
}

/// The watcher takes the first look at the reason before it tears the other hops down, so that what the teardown makes every hop record
/// (`ClosedByUs`) cannot become the answer. The test above asks for the reason as soon as the session is dead, which is before the watcher's
/// next look, so it would pass without that first look. Here nobody asks until the chain is down (the connection to the jump host is closed).
#[test]
fn a_reason_nobody_asked_for_before_the_chain_came_down_is_still_the_inner_hops() {
    let Some(tools) = tools() else { return };
    let pair = pair(&tools, &[], &[]);
    let proxy_a = Proxy::start(pair.a.sshd.port);
    let proxy_b = Proxy::start(pair.b.sshd.port);
    let session = open(&pair, &chain(&pair, proxy_a.port, proxy_b.port));
    eventually("the first hop to be counted", 3, || proxy_a.open_connections() == 1);

    proxy_b.set(Mode::Cut);
    eventually("the watcher to bring the outer hop down as well", 10, || proxy_a.open_connections() == 0);
    assert!(!session.is_alive());
    let reason = session.disconnect_reason().expect("a dead session says why");
    assert_eq!((reason.hop.alias.as_str(), reason.kind), ("b", DisconnectKind::ConnectionLost), "{reason:?}");
}

/// Review focus: flow control through a jump. Sixteen times russh's 2 MiB window of output has to cross two hops.
#[test]
fn a_large_output_crosses_a_jump_without_stalling() {
    const SIZE: usize = 32 * MIB;
    let Some(tools) = tools() else { return };
    let pair = pair(&tools, &[], &[]);
    let session = open(&pair, &chain(&pair, pair.a.sshd.port, pair.b.sshd.port));

    let started = Instant::now();
    // The command first prints the sshd's view of its connection on stderr, so that the test can tell which host ran it.
    let command = format!("echo \"$SSH_CONNECTION\" >&2; head -c {SIZE} /dev/zero");
    let result = session.exec(&command, Duration::from_secs(120), 64 * MIB).unwrap();
    fact("jump.long_output.mib_per_second", format!("{:.1}", SIZE as f64 / 1_048_576.0 / started.elapsed().as_secs_f64()));
    assert_eq!((result.stdout.len(), result.ended, result.exit_code), (SIZE, Ended::Exited, Some(0)));
    assert_eq!(server_port_in(&String::from_utf8_lossy(&result.stderr)), Some(pair.b.sshd.port), "the command did not run on the second host");
}

#[test]
fn a_shell_on_the_second_host_works_through_the_jump() {
    let Some(tools) = tools() else { return };
    let pair = pair(&tools, &[], SHELL_SERVER);
    let session = open(&pair, &chain(&pair, pair.a.sshd.port, pair.b.sshd.port));

    let probe = ShellProbe::start(session.shell(Pty { term: "xterm-256color".into(), cols: 100, rows: 30 }).unwrap());
    probe.wait_for_text(20, "$ ").expect("a prompt");
    assert_eq!(probe.stty_size().expect("stty answers"), "30 100");
    probe.type_line("exit 4");
    eventually("the shell to report its exit", 10, || probe.shell.exited().is_some());
    assert_eq!(probe.shell.exited(), Some(crate::ssh::Exit::Code(4)));
}

/// Review focus: the tunnel branch of `connect_hop` has no `SocketGuard`, and needs none. A destination behind a jump host that sends
/// its version line and then nothing is given up on after `stall_limit` (1.5 s here: a 2 s keepalive interval, a 6 s connect timeout),
/// and the handshake task that russh started on the tunnel is detached by that. It ends because `connect_chain` disconnects the jump
/// host next, which closes the channel the task was reading and writing. A task left behind would spin once the interval had passed
/// (spec §6.2 step 2, and Task 9's test of the same wait on a socket), so the CPU time of the call and of the 2 s after it is measured;
/// the process-wide CPU time is only meaningful when nothing else runs, so a child process of the test binary does the measuring. The
/// jump host's connection must be closed afterwards, and so must the destination's end of the tunnel.
#[cfg(unix)]
#[test]
fn a_destination_that_goes_quiet_behind_a_jump_host_is_given_up_on_and_leaves_nothing_behind() {
    use std::io::{Read, Write};
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;

    use crate::ssh::testing::{cpu_time_ms, fact_in, is_child, rerun_alone};
    use crate::ssh::{Hop, Phase};

    const NAME: &str = "ssh::engine_tests::jump::a_destination_that_goes_quiet_behind_a_jump_host_is_given_up_on_and_leaves_nothing_behind";
    let Some(tools) = tools() else { return };
    if !is_child() {
        let output = rerun_alone(NAME);
        let measured = |key: &str| -> u128 { fact_in(&output, key).expect("the child measured").parse().expect("a number") };
        let waited = measured("quiet_jump.waited_ms");
        let (during, after) = (measured("quiet_jump.cpu_during_call_ms"), measured("quiet_jump.cpu_after_call_ms"));
        assert!(waited < 3000, "the engine waited {waited} ms for a quiet destination with a keepalive interval of 2000 ms");
        assert!(during < 500 && after < 500, "a quiet destination used {during} ms of CPU during the call and {after} ms in the 2 s after it");
        return;
    }
    let jump = Server::start(&tools, &[]);
    let proxy = Proxy::start(jump.sshd.port);
    let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).expect("a port for the quiet destination");
    let port = listener.local_addr().expect("its address").port();
    let ended = Arc::new(AtomicBool::new(false));
    let destination = {
        let ended = Arc::clone(&ended);
        std::thread::spawn(move || {
            let (mut socket, _) = listener.accept().expect("the jump host connects");
            socket.write_all(b"SSH-2.0-quiet\r\n").expect("the version line goes out");
            // Takes in whatever the engine sends until the jump host closes its end of the tunnel.
            let mut buffer = [0u8; 4096];
            while matches!(socket.read(&mut buffer), Ok(count) if count > 0) {}
            ended.store(true, Ordering::SeqCst);
        })
    };
    let mut quiet = Hop::new("host-quiet", "quiet", "127.0.0.1", port, "tester", key("kb"));
    quiet.keepalive_every = Duration::from_secs(2);
    quiet.connect_timeout = Duration::from_secs(6);
    let target = Target { hops: vec![jump.hop_with("a", proxy.port, key("ka")), quiet] };

    // The engine stays alive to the end: shutting it down ends every task it runs, and that would hide one that is left behind spinning.
    let engine = engine();
    let (cpu_before, started) = (cpu_time_ms(), Instant::now());
    let error = engine.connect_chain(&target, &*TestPolicy::trusting(), &jump.vault("ka")).err().expect("the destination never finishes its handshake");
    fact("quiet_jump.waited_ms", started.elapsed().as_millis());
    fact("quiet_jump.cpu_during_call_ms", cpu_time_ms() - cpu_before);
    assert!(matches!(&error, ConnectError::Timeout { hop, phase: Phase::Handshake } if hop.alias == "quiet"), "{error:?}");

    eventually("the proxy to see the first hop closed", 5, || proxy.open_connections() == 0);
    eventually("the destination to see the jump host close its end of the tunnel", 5, || ended.load(Ordering::SeqCst));
    fact("quiet_jump.closed_after_ms", started.elapsed().as_millis());
    // The interval runs out 2 s after the destination's last packet; a task the engine left behind would spin from then on.
    let cpu_before = cpu_time_ms();
    std::thread::sleep(Duration::from_secs(2));
    fact("quiet_jump.cpu_after_call_ms", cpu_time_ms() - cpu_before);
    destination.join().expect("the quiet destination thread");
}
