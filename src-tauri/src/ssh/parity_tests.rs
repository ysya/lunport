//! The same scenarios against the fake engine and the real one (plan 1b): wherever the broker relies on how an engine behaves, the fake
//! must behave like the real engine, or the broker's tests would pass against behaviour the app never sees. Each scenario is written once,
//! as a function of an engine, a target and an auth source, and runs twice: against `FakeEngine`, and against `RusshEngine` with the
//! in-process server (logins) or a scratch OpenSSH behind a proxy (shells and a cut link).

use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

use zeroize::Zeroizing;

use super::fake::{FakeEngine, FakeLogin, FakeMethods};
use super::russh_engine::toy_server::{ToyLogin, ToyServer};
use super::russh_engine::{EngineOptions, RusshEngine};
use super::testing::eventually;
use super::testing::fixture::Server;
use super::testing::harness::tools;
use super::testing::proxy::{Mode, Proxy};
use super::{
    AuthError, AuthMethod, AuthSource, ConnectError, DisconnectKind, DisconnectReason, Exit, Hop, HopRef, HostKey, HostKeyPolicy, HostKeyVerdict, Prompt, Pty,
    RsaHash, Secret, SessionError, ShellChannel, Signature, SshEngine, Target,
};
use crate::sync::slot_rules::test_keys;

const USER: &str = "tester";
const PASSWORD: &str = "correct horse battery staple";

fn locked<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Both the host key policy and the auth source of a login scenario: it answers from fixed values and writes down, in order, every
/// question the engine asked.
#[derive(Default)]
struct Recorder {
    /// The policy pins every key when true, and knows none otherwise.
    trust: bool,
    password: Option<String>,
    answers: Option<Vec<String>>,
    answer_delay: Duration,
    log: Mutex<Vec<String>>,
    /// How long each `interactive` call was given.
    waits: Mutex<Vec<Duration>>,
}

impl Recorder {
    fn trusting() -> Recorder {
        Recorder { trust: true, ..Recorder::default() }
    }

    fn log(&self) -> Vec<String> {
        locked(&self.log).clone()
    }
}

impl HostKeyPolicy for Recorder {
    fn check(&self, hop: &HopRef, _key: &HostKey) -> HostKeyVerdict {
        locked(&self.log).push(format!("host key {}", hop.alias));
        if self.trust {
            HostKeyVerdict::Pinned
        } else {
            HostKeyVerdict::Unknown
        }
    }
}

impl AuthSource for Recorder {
    fn public_key(&self, key_id: &str) -> Option<String> {
        locked(&self.log).push(format!("public key {key_id}"));
        Some(test_keys::PLAIN_PUBLIC.to_string())
    }

    /// Never reached: both servers refuse the key before they ask for a signature.
    fn sign(&self, key_id: &str, _data: &[u8], _rsa_hash: Option<RsaHash>) -> Result<Signature, AuthError> {
        locked(&self.log).push(format!("sign {key_id}"));
        Err(AuthError::Refused("not in this test".to_string()))
    }

    fn password(&self, hop: &HopRef) -> Option<Secret> {
        locked(&self.log).push(format!("password {}", hop.alias));
        self.password.clone().map(Zeroizing::new)
    }

    fn interactive(&self, hop: &HopRef, _prompts: &[Prompt], deadline: Instant) -> Option<Vec<Secret>> {
        locked(&self.log).push(format!("interactive {}", hop.alias));
        locked(&self.waits).push(deadline.saturating_duration_since(Instant::now()));
        std::thread::sleep(self.answer_delay);
        self.answers.clone().map(|answers| answers.into_iter().map(Zeroizing::new).collect())
    }
}

// ---------------------------------------------------------------------------------------------------------------------------------
// Logins. The server refuses every key and offers the password method and one keyboard-interactive prompt, both taking `PASSWORD`:
// the in-process server, or a fake server with the same methods.

fn fake_logins() -> FakeEngine {
    FakeEngine::new().with_login(FakeLogin::Server(FakeMethods::password(PASSWORD).and_interactive("Password: ", PASSWORD)))
}

fn toy() -> ToyServer {
    ToyServer::start(ToyLogin { user: USER.to_string(), password: PASSWORD.to_string(), prompt: "Password: ".to_string(), rounds: None })
}

fn real_engine() -> RusshEngine {
    RusshEngine::with_options(EngineOptions { worker_threads: 2, ..EngineOptions::default() })
}

fn login_target(port: u16, auth: AuthMethod) -> Target {
    Target { hops: vec![Hop::new("host-login", "login", "127.0.0.1", port, USER, auth)] }
}

/// Runs `scenario` against the fake (any port: nothing is connected) and against the real engine and the in-process server.
fn both_logins(scenario: impl Fn(&dyn SshEngine, u16)) {
    scenario(&fake_logins(), 22);
    let server = toy();
    scenario(&real_engine(), server.port);
}

fn password_first_is_asked_before_the_host_key(engine: &dyn SshEngine, port: u16) {
    let recorder = Recorder { password: Some(PASSWORD.to_string()), ..Recorder::default() };
    let error = engine.connect(&login_target(port, AuthMethod::Password), &recorder, &recorder).err().expect("the host key is not trusted");
    assert!(matches!(error, ConnectError::HostKeyUnknown { .. }), "{error:?}");
    assert_eq!(recorder.log(), ["password login", "host key login"]);
}

#[test]
fn the_password_of_a_password_first_hop_is_asked_for_before_its_host_key() {
    both_logins(password_first_is_asked_before_the_host_key);
}

fn missing_password_goes_on_to_keyboard_interactive(engine: &dyn SshEngine, port: u16) {
    let recorder = Recorder { answers: Some(vec![PASSWORD.to_string()]), ..Recorder::trusting() };
    engine.connect(&login_target(port, AuthMethod::Password), &recorder, &recorder).expect("keyboard-interactive gets in");
    assert_eq!(recorder.log(), ["password login", "host key login", "interactive login"]);
}

#[test]
fn a_missing_password_goes_on_to_keyboard_interactive() {
    both_logins(missing_password_goes_on_to_keyboard_interactive);
}

fn refused_key_without_password_wants_one(engine: &dyn SshEngine, port: u16) {
    let recorder = Recorder { answers: Some(vec!["wrong".to_string()]), ..Recorder::trusting() };
    let error = engine.connect(&login_target(port, AuthMethod::Key { key_id: "k1".to_string() }), &recorder, &recorder).err().expect("refused");
    match error {
        ConnectError::AuthFailed { tried, reason, password_wanted, .. } => {
            assert_eq!(tried, [AuthMethod::Key { key_id: "k1".to_string() }, AuthMethod::Interactive]);
            assert_eq!(reason, "No password was given.");
            assert!(password_wanted);
        }
        other => panic!("expected AuthFailed, got {other:?}"),
    }
    assert_eq!(recorder.log(), ["host key login", "public key k1", "password login", "interactive login"]);
}

#[test]
fn a_refused_key_with_no_password_to_give_says_a_password_is_wanted() {
    both_logins(refused_key_without_password_wants_one);
}

fn prompt_gets_at_least_a_minute(engine: &dyn SshEngine, port: u16) {
    let recorder = Recorder { answers: Some(vec![PASSWORD.to_string()]), ..Recorder::trusting() };
    let mut target = login_target(port, AuthMethod::Interactive);
    target.hops[0].connect_timeout = Duration::from_secs(1);
    engine.connect(&target, &recorder, &recorder).expect("the right answer gets in");
    let waits = locked(&recorder.waits).clone();
    assert!(waits.len() == 1 && waits[0] > Duration::from_secs(59) && waits[0] <= Duration::from_secs(60), "{waits:?}");
}

#[test]
fn a_keyboard_interactive_prompt_gets_at_least_a_minute() {
    both_logins(prompt_gets_at_least_a_minute);
}

fn cancelled_prompt_abandons(engine: &dyn SshEngine, port: u16) {
    let recorder = Recorder::trusting();
    match engine.connect(&login_target(port, AuthMethod::Interactive), &recorder, &recorder).err().expect("abandoned") {
        ConnectError::AuthAbandoned { reason, .. } => assert_eq!(reason, "the prompt was cancelled"),
        other => panic!("expected AuthAbandoned, got {other:?}"),
    }
}

#[test]
fn a_cancelled_prompt_abandons_the_login() {
    both_logins(cancelled_prompt_abandons);
}

fn late_answer_abandons(engine: &dyn SshEngine, port: u16) {
    let recorder = Recorder { answers: Some(vec![PASSWORD.to_string()]), answer_delay: Duration::from_millis(300), ..Recorder::trusting() };
    match engine.connect(&login_target(port, AuthMethod::Interactive), &recorder, &recorder).err().expect("abandoned") {
        ConnectError::AuthAbandoned { reason, .. } => assert_eq!(reason, "the prompt was answered after its deadline"),
        other => panic!("expected AuthAbandoned, got {other:?}"),
    }
}

#[test]
fn an_answer_after_the_deadline_abandons_the_login() {
    let wait = Duration::from_millis(100);
    late_answer_abandons(&fake_logins().with_prompt_wait(wait), 22);
    let server = toy();
    late_answer_abandons(&RusshEngine::with_options(EngineOptions { prompt_wait: Some(wait), worker_threads: 2, ..EngineOptions::default() }), server.port);
}

fn unreachable_after_the_password(engine: &dyn SshEngine, port: u16) {
    let recorder = Recorder { password: Some(PASSWORD.to_string()), ..Recorder::trusting() };
    let error = engine.connect(&login_target(port, AuthMethod::Password), &recorder, &recorder).err().expect("nothing listens there");
    assert!(matches!(error, ConnectError::Unreachable { .. }), "{error:?}");
    assert_eq!(recorder.log(), ["password login"], "asked before the connection was tried, and nothing after");
}

#[test]
fn an_unreachable_password_first_hop_was_asked_for_its_password_first() {
    let closed_port = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap().local_addr().unwrap().port();
    let refused = ConnectError::Unreachable { hop: login_target(closed_port, AuthMethod::Password).hops[0].reference(), reason: "connection refused".to_string() };
    unreachable_after_the_password(&fake_logins().failing_with(refused), closed_port);
    unreachable_after_the_password(&real_engine(), closed_port);
}

// ---------------------------------------------------------------------------------------------------------------------------------
// Shells. The server prints a prompt when a shell opens: a scratch OpenSSH with `/bin/sh` behind a proxy that can cut the link, or a
// fake that prints "$ ".

/// Reads `shell` on a thread of its own until it ends; `None` when it has not ended within `seconds`.
fn read_to_end(shell: &Arc<dyn ShellChannel>, seconds: u64) -> Option<Vec<u8>> {
    let (done, finished) = std::sync::mpsc::channel();
    let reader = Arc::clone(shell);
    std::thread::spawn(move || {
        let (mut all, mut buf) = (Vec::new(), [0u8; 4096]);
        while let Ok(count) = reader.read(&mut buf) {
            if count == 0 {
                break;
            }
            all.extend_from_slice(&buf[..count]);
        }
        let _ = done.send(all);
    });
    finished.recv_timeout(Duration::from_secs(seconds)).ok()
}

/// Waits until the shell has printed something (its prompt): a shell closed before that can leave a process behind on a macOS sshd.
fn first_output(shell: &Arc<dyn ShellChannel>) {
    let (done, printed) = std::sync::mpsc::channel();
    let reader = Arc::clone(shell);
    std::thread::spawn(move || {
        let mut buf = [0u8; 1];
        let _ = done.send(reader.read(&mut buf));
    });
    let count = printed.recv_timeout(Duration::from_secs(20)).expect("the shell prints a prompt").expect("the read works");
    assert_eq!(count, 1);
}

struct ShellWorld {
    engine: Box<dyn SshEngine>,
    target: Target,
    auth: Box<dyn AuthSource>,
    cut: Box<dyn Fn()>,
    _keep: Vec<Box<dyn std::any::Any>>,
}

fn fake_shells() -> ShellWorld {
    let engine = Arc::new(FakeEngine::new().with_shell_output(b"$ "));
    let target = Target { hops: vec![Hop::new("host-shell", "shell", "127.0.0.1", 22, USER, AuthMethod::Key { key_id: "k1".to_string() })] };
    let lost = DisconnectReason { hop: target.hops[0].reference(), kind: DisconnectKind::ConnectionLost, detail: "connection reset by peer".to_string() };
    let cutter = Arc::clone(&engine);
    ShellWorld { engine: Box::new(SharedFake(engine)), target, auth: Box::new(Recorder::default()), cut: Box::new(move || cutter.disconnect_now(lost.clone())), _keep: Vec::new() }
}

/// A `FakeEngine` shared with the closure that cuts its link.
struct SharedFake(Arc<FakeEngine>);

impl SshEngine for SharedFake {
    fn connect(&self, target: &Target, host_keys: &dyn HostKeyPolicy, auth: &dyn AuthSource) -> Result<Box<dyn super::Session>, ConnectError> {
        self.0.connect(target, host_keys, auth)
    }
}

fn real_shells() -> Option<ShellWorld> {
    let tools = tools()?;
    let server = Server::start(&tools, &["ForceCommand if [ -n \"$SSH_ORIGINAL_COMMAND\" ]; then eval \"$SSH_ORIGINAL_COMMAND\"; else exec /bin/sh; fi"]);
    let proxy = Arc::new(Proxy::start(server.sshd.port));
    let target = Target { hops: vec![server.hop_with("shell", proxy.port, AuthMethod::Key { key_id: "k1".to_string() })] };
    let auth = Box::new(server.vault("k1"));
    let cutter = Arc::clone(&proxy);
    Some(ShellWorld { engine: Box::new(real_engine()), target, auth, cut: Box::new(move || cutter.set(Mode::Cut)), _keep: vec![Box::new(server), Box::new(proxy)] })
}

fn pty() -> Pty {
    Pty { term: "xterm-256color".to_string(), cols: 80, rows: 24 }
}

fn closing_a_shell_ends_it_as_disconnected(world: &ShellWorld) {
    let session = world.engine.connect(&world.target, &*super::testing::doubles::TestPolicy::trusting(), &*world.auth).expect("connects");
    let shell: Arc<dyn ShellChannel> = Arc::from(session.shell(pty()).expect("a shell"));
    first_output(&shell);
    shell.close();
    read_to_end(&shell, 10).expect("a shell we closed ends");
    assert_eq!(shell.exited(), Some(Exit::Disconnected));
    assert_eq!(shell.write(b"echo after\n"), Ok(()), "a shell we closed ourselves still takes input");
    assert!(session.is_alive(), "only the shell was closed");
}

#[test]
fn a_shell_we_close_ends_as_disconnected_and_still_takes_input() {
    closing_a_shell_ends_it_as_disconnected(&fake_shells());
    if let Some(world) = real_shells() {
        closing_a_shell_ends_it_as_disconnected(&world);
    }
}

fn input_after_the_session_closed_fails(world: &ShellWorld) {
    let session = world.engine.connect(&world.target, &*super::testing::doubles::TestPolicy::trusting(), &*world.auth).expect("connects");
    let shell: Arc<dyn ShellChannel> = Arc::from(session.shell(pty()).expect("a shell"));
    first_output(&shell);
    session.close();
    read_to_end(&shell, 10).expect("closing the session ends its shells");
    assert_eq!(shell.exited(), Some(Exit::Disconnected));
    assert_eq!(shell.write(b"x"), Err(SessionError::Closed));
    assert_eq!(shell.window_change(100, 30), Err(SessionError::Closed));
    assert!(!session.is_alive());
    assert_eq!(session.disconnect_reason().map(|reason| reason.kind), Some(DisconnectKind::ClosedByUs));
}

#[test]
fn input_fails_with_closed_once_the_session_is_closed() {
    input_after_the_session_closed_fails(&fake_shells());
    if let Some(world) = real_shells() {
        input_after_the_session_closed_fails(&world);
    }
}

fn a_cut_link_ends_the_shells(world: &ShellWorld) {
    let session = world.engine.connect(&world.target, &*super::testing::doubles::TestPolicy::trusting(), &*world.auth).expect("connects");
    let shell: Arc<dyn ShellChannel> = Arc::from(session.shell(pty()).expect("a shell"));
    first_output(&shell);
    (world.cut)();
    read_to_end(&shell, 15).expect("a shell on a cut link ends");
    assert_eq!(shell.exited(), Some(Exit::Disconnected));
    eventually("the session to notice", 10, || !session.is_alive());
    assert_eq!(session.disconnect_reason().map(|reason| reason.kind), Some(DisconnectKind::ConnectionLost));
}

#[test]
fn a_cut_link_ends_the_shells_and_the_session_says_the_connection_was_lost() {
    a_cut_link_ends_the_shells(&fake_shells());
    if let Some(world) = real_shells() {
        a_cut_link_ends_the_shells(&world);
    }
}
