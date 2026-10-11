//! Jump hosts: a chain of connections, each carried inside the one before it (spec §6.2 step 2).

use std::time::{Duration, Instant};

use super::{accepted_logins, engine, settle, ShellProbe, LOG_LOGINS, SHELL_SERVER};
use crate::ssh::testing::doubles::{TestPolicy, VaultAuth};
use crate::ssh::testing::fixture::Server;
use crate::ssh::testing::harness::{tools, Tools};
use crate::ssh::testing::proxy::{Mode, Proxy};
use crate::ssh::testing::{eventually, fact};
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

#[test]
fn a_two_hop_jump_runs_a_command_on_the_second_host_and_checks_each_hops_own_host_key() {
    let Some(tools) = tools() else { return };
    let pair = pair(&tools, &[], &[]);
    let policy = TestPolicy::trusting();
    let target = chain(&pair, pair.a.sshd.port, pair.b.sshd.port);

    let session = engine().connect(&target, &*policy, &pair.vault).expect("the chain connects");
    let result = session.exec("echo hop-$((20+22))", Duration::from_secs(20), MIB).unwrap();
    assert_eq!((result.stdout.as_slice(), result.ended), (b"hop-42\n".as_slice(), Ended::Exited));

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

    let error = engine().connect(&target, &*policy, &pair.vault).err().expect("b is not pinned");
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
    let closed_port = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap().local_addr().unwrap().port();
    let proxy_a = Proxy::start(pair.a.sshd.port);
    let target = chain(&pair, proxy_a.port, closed_port);

    let started = Instant::now();
    let error = engine().connect(&target, &*TestPolicy::trusting(), &pair.vault).err().expect("nothing listens there");
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
    let target = chain(&pair, pair.a.sshd.port, pair.b.sshd.port);
    let error = engine().connect(&target, &*TestPolicy::trusting(), &pair.vault).err().expect("forwarding is off");
    assert!(matches!(&error, ConnectError::Unreachable { hop, reason } if hop.alias == "b" && reason == "a does not allow forwarding"), "{error:?}");
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

/// Review focus: flow control through a jump. Sixteen times russh's 2 MiB window of output has to cross two hops.
#[test]
fn a_large_output_crosses_a_jump_without_stalling() {
    const SIZE: usize = 32 * MIB;
    let Some(tools) = tools() else { return };
    let pair = pair(&tools, &[], &[]);
    let session = open(&pair, &chain(&pair, pair.a.sshd.port, pair.b.sshd.port));

    let started = Instant::now();
    let result = session.exec(&format!("head -c {SIZE} /dev/zero"), Duration::from_secs(120), 64 * MIB).unwrap();
    fact("jump.long_output.mib_per_second", format!("{:.1}", SIZE as f64 / 1_048_576.0 / started.elapsed().as_secs_f64()));
    assert_eq!((result.stdout.len(), result.ended, result.exit_code), (SIZE, Ended::Exited, Some(0)));
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
