//! Google Cloud IAP transports (design 2026-10-25): a first hop reached through the relay instead of TCP. The relay is a fake
//! (`gcp::testing::FakeRelay`) in front of a scratch sshd; the tunnel itself is tested in `gcp::iap`.

use std::sync::Arc;
use std::time::{Duration, Instant};

use super::{settle, ShellProbe, SHELL_SERVER};
use crate::gcp::auth::{StaticToken, TokenSource};
use crate::gcp::iap::IapError;
use crate::gcp::testing::{Behaviour, FakeRelay};
use crate::ssh::russh_engine::{EngineOptions, RusshEngine};
use crate::ssh::testing::doubles::{TestPolicy, VaultAuth};
use crate::ssh::testing::fixture::Server;
use crate::ssh::testing::harness::tools;
use crate::ssh::testing::{closed_port, eventually};
use crate::ssh::{AuthMethod, ConnectError, DisconnectKind, Ended, Hop, IapTarget, Phase, Pty, SshEngine, Target, Transport};

const TOKEN: &str = "t0k";
const MIB: usize = 1024 * 1024;

fn iap_target(relay: &FakeRelay) -> IapTarget {
    IapTarget {
        project: "eng-dev-396409".into(),
        zone: "asia-east1-b".into(),
        instance: "jumpbox".into(),
        interface: "nic0".into(),
        account: Some("frank@retower.io".into()),
        url_root: Some(relay.url_root.clone()),
    }
}

/// A hop to `server` through `relay`, logging in with the vault key `key_id`.
fn iap_hop(server: &Server, relay: &FakeRelay, alias: &str, key_id: &str) -> Hop {
    let mut hop = server.hop(alias, key_id);
    hop.transport = Transport::GcpIap(iap_target(relay));
    hop
}

/// A hop to a jump box that no sshd backs (the relay refuses or stalls before any SSH happens).
fn unreachable_iap_hop(relay: &FakeRelay) -> Hop {
    let mut hop = Hop::new("host-jumpbox", "jumpbox", "127.0.0.1", 22, "frank_retower_io", AuthMethod::Key { key_id: "k1".into() });
    hop.transport = Transport::GcpIap(iap_target(relay));
    hop
}

fn engine_with(tokens: Option<Arc<dyn TokenSource>>) -> RusshEngine {
    RusshEngine::with_options(EngineOptions { worker_threads: 2, gcp_tokens: tokens, ..EngineOptions::default() })
}

fn engine() -> RusshEngine {
    engine_with(Some(Arc::new(StaticToken(TOKEN.into()))))
}

fn tunnel_text(error: &ConnectError) -> String {
    match error {
        ConnectError::Tunnel { text, .. } => {
            assert_eq!(error.to_string(), *text, "a tunnel sentence is shown as it is");
            text.clone()
        }
        other => panic!("expected a tunnel error, got {other:?}"),
    }
}

#[test]
fn a_shell_and_a_command_work_through_the_relay() {
    let Some(tools) = tools() else { return };
    let server = Server::start(&tools, SHELL_SERVER);
    let relay = FakeRelay::start(server.sshd.port, TOKEN);
    let target = Target { hops: vec![iap_hop(&server, &relay, "jumpbox", "k1")] };
    let session = engine().connect(&target, &*TestPolicy::trusting(), &server.vault("k1")).expect("the hop connects through the relay");
    let result = session.exec("echo hop-$((20+22))", Duration::from_secs(20), MIB).unwrap();
    assert_eq!((result.ended, String::from_utf8_lossy(&result.stdout).trim()), (Ended::Exited, "hop-42"));
    let probe = ShellProbe::start(session.shell(Pty { term: "xterm".into(), cols: 80, rows: 24 }).expect("a shell opens"));
    probe.type_line("echo relay-$((40+2))");
    probe.wait_for_text(10, "relay-42").expect("the shell answers through the relay");
    assert_eq!((relay.connects(), relay.reconnects()), (1, 0));
    session.close();
    // The relay's answer to sshd leaving (`FakeRelay` closes with 1000 "target closed") can race our close and be written down; what
    // never follows our own close is IAP refusing the account.
    let end = session.tunnel_end();
    assert!(!matches!(end, Some(IapError::Closed { code: 4033, .. })), "closing the session is no IAP refusal: {end:?}");
}

#[test]
fn output_survives_a_dropped_websocket() {
    let Some(tools) = tools() else { return };
    let server = Server::start(&tools, SHELL_SERVER);
    let relay = FakeRelay::start(server.sshd.port, TOKEN);
    let target = Target { hops: vec![iap_hop(&server, &relay, "jumpbox", "k1")] };
    let session = engine().connect(&target, &*TestPolicy::trusting(), &server.vault("k1")).expect("the hop connects through the relay");
    settle(&*session);
    relay.set(Behaviour::DropAfter(200_000));
    let result = session.exec("head -c 1000000 /dev/zero | tr '\\0' x", Duration::from_secs(60), 2 * MIB).unwrap();
    assert_eq!(result.ended, Ended::Exited, "{}", String::from_utf8_lossy(&result.stderr));
    assert_eq!(result.stdout.len(), 1_000_000, "every byte came through the reconnected tunnel");
    assert!(result.stdout.iter().all(|byte| *byte == b'x'));
    assert_eq!(relay.reconnects(), 1);
    assert!(session.is_alive());
}

/// Design 2026-10-25, "Error texts": when the relay ends the session, the connection's reason is the relay's sentence, not russh's
/// end-of-file on the pipe.
#[test]
fn a_relay_that_ends_the_session_is_why_the_connection_ended() {
    let Some(tools) = tools() else { return };
    let server = Server::start(&tools, SHELL_SERVER);
    let relay = FakeRelay::start(server.sshd.port, TOKEN);
    let target = Target { hops: vec![iap_hop(&server, &relay, "jumpbox", "k1")] };
    let session = engine().connect(&target, &*TestPolicy::trusting(), &server.vault("k1")).expect("the hop connects through the relay");
    settle(&*session);
    assert_eq!(session.tunnel_end(), None, "the tunnel is up");
    relay.set(Behaviour::CloseAfter(0, 4033, "not authorized"));
    let _ = session.exec("echo poke", Duration::from_secs(10), MIB);
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    while session.is_alive() && std::time::Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(20));
    }
    assert!(!session.is_alive(), "the relay ended the session");
    // The tunnel wrote down why it ended before the connection saw its end, so the first look after `is_alive` turned false has it
    // (design 2026-10-26, Tunnels through a host that needs a grant).
    assert_eq!(session.tunnel_end(), Some(IapError::Closed { code: 4033, reason: "not authorized".into() }));
    let reason = session.disconnect_reason().expect("a dead session says why");
    assert_eq!((reason.kind, reason.detail.as_str()), (DisconnectKind::ConnectionLost, "the relay closed the tunnel (4033: not authorized)"));
}

#[test]
fn a_jump_through_an_iap_first_hop_reaches_a_second_server() {
    let Some(tools) = tools() else { return };
    let (a, b) = (Server::start(&tools, &[]), Server::start(&tools, &[]));
    let relay = FakeRelay::start(a.sshd.port, TOKEN);
    let vault = VaultAuth::new().with_key("ka", &a.key.private_text).with_key("kb", &b.key.private_text);
    let target = Target { hops: vec![iap_hop(&a, &relay, "a", "ka"), b.hop("b", "kb")] };
    let session = engine().connect(&target, &*TestPolicy::trusting(), &vault).expect("the chain connects");
    // `$SSH_CONNECTION` ends with the server port of the sshd that ran the command: b's, not a's.
    let result = session.exec("echo $SSH_CONNECTION", Duration::from_secs(20), MIB).unwrap();
    let output = String::from_utf8_lossy(&result.stdout).into_owned();
    assert_eq!(output.split_whitespace().nth(3), Some(b.sshd.port.to_string().as_str()), "{output:?}");
}

#[test]
fn a_transport_on_a_later_hop_is_a_bad_jump_chain() {
    let relay = FakeRelay::start(closed_port(), TOKEN);
    let first = Hop::new("host-a", "a", "127.0.0.1", 22, "u", AuthMethod::Key { key_id: "k1".into() });
    let mut second = Hop::new("host-b", "b", "127.0.0.1", 22, "u", AuthMethod::Key { key_id: "k1".into() });
    second.transport = Transport::GcpIap(iap_target(&relay));
    let error = engine().connect(&Target { hops: vec![first, second] }, &*TestPolicy::trusting(), &VaultAuth::new()).err().expect("refused");
    match error {
        ConnectError::BadJumpChain { why } => assert_eq!(why, "b connects through Google Cloud IAP and cannot be reached through a jump host"),
        other => panic!("{other:?}"),
    }
    assert_eq!(relay.connects(), 0, "nothing was connected");
}

#[test]
fn close_codes_and_a_refused_handshake_have_their_sentences() {
    let relay = FakeRelay::start(closed_port(), TOKEN);
    let target = Target { hops: vec![unreachable_iap_hop(&relay)] };
    let policy = TestPolicy::trusting();
    let vault = VaultAuth::new();

    relay.set(Behaviour::CloseAtOpen(4003, "failed to connect to backend"));
    let text = tunnel_text(&engine().connect(&target, &*policy, &vault).err().expect("refused"));
    assert_eq!(text, "IAP could not reach port 22 on jumpbox: nothing is listening, or the firewall does not allow 35.235.240.0/20.");

    relay.set(Behaviour::CloseAtOpen(4033, "not authorized"));
    let error = engine().connect(&target, &*policy, &vault).err().expect("refused");
    assert_eq!(tunnel_text(&error), "frank@retower.io is not authorized to tunnel to jumpbox through IAP.");
    // The close code travels with the sentence: the broker adds a note to a 4033 that follows a fresh PAM grant.
    assert!(matches!(error, ConnectError::Tunnel { code: Some(4033), .. }), "{error:?}");

    relay.set(Behaviour::CloseAtOpen(4010, "destination read failed"));
    let text = tunnel_text(&engine().connect(&target, &*policy, &vault).err().expect("refused"));
    assert_eq!(text, "IAP closed the tunnel to jumpbox (4010: destination read failed).");

    relay.set(Behaviour::RefuseHandshake(403));
    let text = tunnel_text(&engine().connect(&target, &*policy, &vault).err().expect("refused"));
    assert_eq!(
        text,
        "Google Cloud IAP refused the tunnel to jumpbox (HTTP 403): check that frank@retower.io has roles/iap.tunnelResourceAccessor on the instance, and for production that a PAM grant is active."
    );

    let other = FakeRelay::start(closed_port(), "other");
    let target = Target { hops: vec![unreachable_iap_hop(&other)] };
    let text = tunnel_text(&engine().connect(&target, &*policy, &vault).err().expect("refused"));
    assert!(text.contains("(HTTP 401)"), "{text}");
}

#[test]
fn a_relay_that_never_answers_times_out_in_the_tcp_phase_and_leaves_no_task_behind() {
    let relay = FakeRelay::start(closed_port(), TOKEN);
    relay.set(Behaviour::NeverSucceed);
    let mut hop = unreachable_iap_hop(&relay);
    hop.connect_timeout = Duration::from_secs(2);
    let started = Instant::now();
    let error = engine().connect(&Target { hops: vec![hop] }, &*TestPolicy::trusting(), &VaultAuth::new()).err().expect("timed out");
    assert!(matches!(error, ConnectError::Timeout { phase: Phase::Tcp, .. }), "{error:?}");
    assert!(started.elapsed() < Duration::from_secs(6), "the connect gave up at its timeout, not later");
    eventually("the relay saw the socket go", 3, || relay.open_connections() == 0);
}

#[test]
fn an_engine_without_a_token_source_says_so() {
    let relay = FakeRelay::start(closed_port(), TOKEN);
    let target = Target { hops: vec![unreachable_iap_hop(&relay)] };
    let text = tunnel_text(&engine_with(None).connect(&target, &*TestPolicy::trusting(), &VaultAuth::new()).err().expect("refused"));
    assert_eq!(text, "Google Cloud credentials are not configured.");
    assert_eq!(relay.connects(), 0);
}
