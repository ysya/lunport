//! A scripted engine for the tests of the broker, the MCP adapter and the CLI (own-ssh spec §12). It implements the same traits as the
//! russh engine and touches no network: the "server" is a script, and what the code under test did is recorded for the assertions.
//! Where the broker relies on how the real engine behaves (the order of the password question, the login sequence, the deadline of a
//! prompt, how shells end), the fake behaves the same way, and `ssh/parity_tests.rs` runs the same scenarios against both.
//! Test code only (`#[cfg(test)]` in `ssh/mod.rs`).

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError, Weak};
use std::time::{Duration, Instant};

use super::channel::{ByteQueue, ExitCell, QueuedShell, ShellInput};
use super::error::{ConnectError, SessionError};
use super::forward::{ForwardSpec, ForwardStatus, Forwarder};
use super::traits::{AuthSource, HostKeyPolicy, Session, ShellChannel, SshEngine};
use super::types::{AuthMethod, DisconnectKind, DisconnectReason, Ended, ExecResult, Exit, Hop, HopRef, HostKey, HostKeyVerdict, Prompt, Pty, RsaHash, Secret, Target};
use crate::gcp::iap::IapError;
use crate::sync::slot_rules::test_keys;

fn locked<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

/// How the fake server of a host answers a login.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FakeLogin {
    /// Every login succeeds and the auth source is not consulted, except for the password of a hop that starts with the password
    /// method: the real engine asks for it before it connects (before the host key is checked), and so does the fake.
    Accept,
    /// A server that offers these methods; the login runs the real engine's sequence against them (see `FakeMethods`).
    Server(FakeMethods),
}

/// The login methods a fake server offers and what each one accepts. The login goes through the hop's methods in order
/// (`Hop::auth_sequence`), as the real engine does: a method the server has said it does not offer is skipped without asking the auth
/// source, a refusal moves on to the next method on the same connection, a method the source has nothing for (no such key, no password)
/// is skipped, and the end is `AuthFailed` with the methods tried and `password_wanted`. A failed signature, a cancelled or late prompt
/// and a wrong number of answers abandon the login.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct FakeMethods {
    /// Public-key login is offered, and any signature is accepted (the fake has no public key to check one with).
    pub key: bool,
    /// Password login is offered, and only this password is accepted.
    pub password: Option<String>,
    /// Keyboard-interactive is offered: one round with these prompts, and only these answers are accepted.
    pub interactive: Option<FakeRound>,
}

/// One keyboard-interactive round of a fake server.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FakeRound {
    pub prompts: Vec<Prompt>,
    pub answers: Vec<String>,
}

impl FakeMethods {
    /// Public-key login only, accepting any signature.
    pub fn key() -> FakeMethods {
        FakeMethods { key: true, ..FakeMethods::default() }
    }

    /// Password login only, accepting `password`.
    pub fn password(password: &str) -> FakeMethods {
        FakeMethods { password: Some(password.to_string()), ..FakeMethods::default() }
    }

    /// Keyboard-interactive only: one prompt (no echo), accepting `answer`.
    pub fn interactive(prompt: &str, answer: &str) -> FakeMethods {
        FakeMethods::default().and_interactive(prompt, answer)
    }

    /// These methods, and keyboard-interactive too: one prompt (no echo), accepting `answer`.
    pub fn and_interactive(mut self, prompt: &str, answer: &str) -> FakeMethods {
        self.interactive = Some(FakeRound { prompts: vec![Prompt { text: prompt.to_string(), echo: false }], answers: vec![answer.to_string()] });
        self
    }

    /// A server that offers no login method at all.
    pub fn none() -> FakeMethods {
        FakeMethods::default()
    }

    fn offers(&self, method: &AuthMethod) -> bool {
        match method {
            AuthMethod::Key { .. } => self.key,
            AuthMethod::Password => self.password.is_some(),
            AuthMethod::Interactive => self.interactive.is_some(),
        }
    }

    /// The methods the server lists after a refusal.
    fn offered(&self) -> Vec<AuthMethod> {
        [AuthMethod::Key { key_id: String::new() }, AuthMethod::Password, AuthMethod::Interactive].into_iter().filter(|method| self.offers(method)).collect()
    }
}

/// Everything the code under test did to the fake, in order.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FakeEvent {
    /// A successful connect: the alias of every hop, jumps first.
    Connect { aliases: Vec<String> },
    Exec { command: String, timeout: Duration, output_cap: usize },
    ShellOpened { term: String, cols: u16, rows: u16 },
    ShellInput(Vec<u8>),
    WindowChange { cols: u16, rows: u16 },
    ShellClosed,
    Closed,
}

/// The key a fake server presents unless the script says otherwise: the ed25519 key of `test_keys::plain()`.
pub fn default_server_key() -> HostKey {
    HostKey::from_openssh_line(test_keys::PLAIN_PUBLIC).expect("the test key parses")
}

struct Script {
    host_key: HostKey,
    host_keys: HashMap<String, HostKey>,
    login: FakeLogin,
    logins: HashMap<String, FakeLogin>,
    connect_error: Option<ConnectError>,
    /// How many more connects `connect_error` fails; `None` for all of them.
    connect_error_times: Option<usize>,
    exec: HashMap<String, ExecResult>,
    shell_output: Vec<Vec<u8>>,
    shell_exit: Exit,
    shell_ends_at_once: bool,
    shell_error: Option<SessionError>,
    write_errors: VecDeque<SessionError>,
    disconnect: Option<DisconnectReason>,
    banner: Option<String>,
    prompt_wait: Option<Duration>,
}

struct Shared {
    script: Mutex<Script>,
    events: Mutex<Vec<FakeEvent>>,
    /// Every session handed out, for `disconnect_now`.
    sessions: Mutex<Vec<Weak<SessionState>>>,
    /// The remote side of every shell opened, in order, for the tests that act as the server.
    shells: Mutex<Vec<FakeShell>>,
}

impl Shared {
    fn record(&self, event: FakeEvent) {
        locked(&self.events).push(event);
    }
}

/// The scripted engine. Build it with the `with_*` methods; the defaults are: the server presents `default_server_key()`, every login
/// succeeds, every command exits 0 with no output, a shell prints nothing and runs until it is closed, the connection never drops.
pub struct FakeEngine {
    shared: Arc<Shared>,
}

impl Default for FakeEngine {
    fn default() -> Self {
        FakeEngine::new()
    }
}

impl FakeEngine {
    pub fn new() -> FakeEngine {
        let script = Script {
            host_key: default_server_key(),
            host_keys: HashMap::new(),
            login: FakeLogin::Accept,
            logins: HashMap::new(),
            connect_error: None,
            connect_error_times: None,
            exec: HashMap::new(),
            shell_output: Vec::new(),
            shell_exit: Exit::Code(0),
            shell_ends_at_once: false,
            shell_error: None,
            write_errors: VecDeque::new(),
            disconnect: None,
            banner: None,
            prompt_wait: None,
        };
        let shared = Shared { script: Mutex::new(script), events: Mutex::new(Vec::new()), sessions: Mutex::new(Vec::new()), shells: Mutex::new(Vec::new()) };
        FakeEngine { shared: Arc::new(shared) }
    }

    fn script(self, change: impl FnOnce(&mut Script)) -> FakeEngine {
        change(&mut locked(&self.shared.script));
        self
    }

    /// The key every fake server presents.
    pub fn with_host_key(self, key: HostKey) -> FakeEngine {
        self.script(|script| script.host_key = key)
    }

    /// The key the server of one host (by alias) presents, for jump chains.
    pub fn with_host_key_for(self, alias: &str, key: HostKey) -> FakeEngine {
        self.script(|script| {
            script.host_keys.insert(alias.to_string(), key);
        })
    }

    pub fn with_login(self, login: FakeLogin) -> FakeEngine {
        self.script(|script| script.login = login)
    }

    /// How the server of one host (by alias) answers a login, for jump chains.
    pub fn with_login_for(self, alias: &str, login: FakeLogin) -> FakeEngine {
        self.script(|script| {
            script.logins.insert(alias.to_string(), login);
        })
    }

    /// `connect` fails with this error, as the real engine fails on the hop the error names: after that hop's password was asked for
    /// (a hop that starts with the password method), and before its host key is checked. An error that names no hop
    /// (`BadJumpChain`) comes before anything else.
    pub fn failing_with(self, error: ConnectError) -> FakeEngine {
        self.script(|script| script.connect_error = Some(error))
    }

    /// `failing_with`, for the next `times` connects only; after them, connects go through.
    pub fn failing_times(self, times: usize, error: ConnectError) -> FakeEngine {
        self.script(|script| {
            script.connect_error = Some(error);
            script.connect_error_times = Some(times);
        })
    }

    /// What `exec(command, …)` returns for exactly this command line (cut to the caller's `output_cap`, as the real engine does).
    pub fn with_exec(self, command: &str, result: ExecResult) -> FakeEngine {
        self.script(|script| {
            script.exec.insert(command.to_string(), result);
        })
    }

    /// A chunk the next shells print as soon as they open.
    pub fn with_shell_output(self, chunk: &[u8]) -> FakeEngine {
        self.script(|script| script.shell_output.push(chunk.to_vec()))
    }

    /// How a shell ends when it ends by itself at once (`with_shell_ending_at_once`). A shell the code under test closes ends as
    /// `Exit::Disconnected`, as with the real engine; a test ends a running shell its own way with `FakeShell::end`.
    pub fn with_shell_exit(self, exit: Exit) -> FakeEngine {
        self.script(|script| script.shell_exit = exit)
    }

    /// Shells end as soon as their scripted output has been produced, as a typed `exit` would, with the `with_shell_exit` status.
    pub fn with_shell_ending_at_once(self) -> FakeEngine {
        self.script(|script| script.shell_ends_at_once = true)
    }

    /// `Session::shell` fails with this error (a channel the server would not open: `SessionError::Channel`).
    pub fn with_shell_error(self, error: SessionError) -> FakeEngine {
        self.script(|script| script.shell_error = Some(error))
    }

    /// The next writes to a shell fail with these errors, one each, in order (a link that does not take the input:
    /// `SessionError::Timeout`); after them, writes go through again. A failed write records no input.
    pub fn with_write_errors(self, errors: Vec<SessionError>) -> FakeEngine {
        self.script(|script| script.write_errors = errors.into())
    }

    /// Every session connects fine and is over right away, for this reason.
    pub fn disconnecting_with(self, reason: DisconnectReason) -> FakeEngine {
        self.script(|script| script.disconnect = Some(reason))
    }

    /// Every server sends this banner once its host key is accepted, before the login (`AuthSource::banner`).
    pub fn with_banner(self, text: &str) -> FakeEngine {
        self.script(|script| script.banner = Some(text.to_string()))
    }

    /// How long a person gets to answer a keyboard-interactive round; by default, as in the real engine, 4 × the hop's connect timeout
    /// and at least 60 s (`EngineOptions::prompt_wait`).
    pub fn with_prompt_wait(self, wait: Duration) -> FakeEngine {
        self.script(|script| script.prompt_wait = Some(wait))
    }

    /// Everything the code under test has done so far.
    pub fn events(&self) -> Vec<FakeEvent> {
        locked(&self.shared.events).clone()
    }

    /// The remote side of every shell opened so far, in order.
    pub fn shells(&self) -> Vec<FakeShell> {
        locked(&self.shared.shells).clone()
    }

    /// Every live session ends now for `reason`, as a connection does when its link is cut or the server goes away: `is_alive` turns
    /// false, `disconnect_reason` says why, and every shell opened on it ends as `Exit::Disconnected` after what it printed.
    pub fn disconnect_now(&self, reason: DisconnectReason) {
        for session in self.live_sessions() {
            session.end(reason.clone());
        }
    }

    /// The Google Cloud IAP tunnel that carries every live session's first hop ends now for `end` (the relay closed it, the credentials
    /// need a person), and each session ends with it, as with the real engine: `tunnel_end` answers `end` (written down before
    /// `is_alive` turns false, as the real tunnel writes its record before the connection can see its end), `disconnect_reason` gives
    /// the tunnel's sentence on the first hop, and the shells end as on `disconnect_now`. A session that is over already keeps its end.
    pub fn end_tunnel_now(&self, end: IapError) {
        for session in self.live_sessions() {
            let reason = DisconnectReason { hop: session.first.clone(), kind: DisconnectKind::ConnectionLost, detail: end.to_string() };
            session.end_with(reason, Some(end.clone()));
        }
    }

    fn live_sessions(&self) -> Vec<Arc<SessionState>> {
        locked(&self.shared.sessions).iter().filter_map(Weak::upgrade).collect()
    }
}

fn check_chain(target: &Target) -> Result<(), ConnectError> {
    if target.hops.is_empty() {
        return Err(ConnectError::BadJumpChain { why: "the target has no hosts".to_string() });
    }
    let mut seen = HashSet::new();
    for hop in &target.hops {
        if !seen.insert(&hop.id) {
            return Err(ConnectError::BadJumpChain { why: format!("{} appears twice", hop.alias) });
        }
    }
    Ok(())
}

/// The hop an error is about; `None` for an error about the whole chain.
fn hop_of(error: &ConnectError) -> Option<&HopRef> {
    match error {
        ConnectError::BadJumpChain { .. } => None,
        ConnectError::Unreachable { hop, .. }
        | ConnectError::Tunnel { hop, .. }
        | ConnectError::Timeout { hop, .. }
        | ConnectError::HostKeyUnknown { hop, .. }
        | ConnectError::HostKeyMismatch { hop, .. }
        | ConnectError::NoCommonHostKeyAlgorithm { hop, .. }
        | ConnectError::AuthFailed { hop, .. }
        | ConnectError::AuthAbandoned { hop, .. }
        | ConnectError::Protocol { hop, .. } => Some(hop),
    }
}

impl SshEngine for FakeEngine {
    fn connect(&self, target: &Target, host_keys: &dyn HostKeyPolicy, auth: &dyn AuthSource) -> Result<Box<dyn Session>, ConnectError> {
        check_chain(target)?;
        let (login_default, logins, key_default, keys, scripted_error, banner, prompt_wait) = {
            let mut script = locked(&self.shared.script);
            // A failure scripted for so many connects is spent by this one.
            let scripted_error = match script.connect_error_times {
                Some(0) => None,
                Some(left) => {
                    script.connect_error_times = Some(left - 1);
                    script.connect_error.clone()
                }
                None => script.connect_error.clone(),
            };
            (
                script.login.clone(),
                script.logins.clone(),
                script.host_key.clone(),
                script.host_keys.clone(),
                scripted_error,
                script.banner.clone(),
                script.prompt_wait,
            )
        };
        if let Some(error) = scripted_error.as_ref().filter(|error| hop_of(error).is_none()) {
            return Err(error.clone());
        }
        for hop in &target.hops {
            let reference = hop.reference();
            // A hop that starts with the password method has its password asked for before anything is connected (`AuthSource::password`).
            let prefetched = (hop.auth == AuthMethod::Password).then(|| auth.password(&reference));
            if let Some(error) = scripted_error.as_ref().filter(|error| hop_of(error).is_some_and(|failing| failing.id == hop.id)) {
                return Err(error.clone());
            }
            let key = keys.get(&hop.alias).unwrap_or(&key_default).clone();
            // A pinned hop offers only its pin's key type in the handshake, as in the real engine: a server whose key is of another type has
            // nothing in common with it.
            if let Some(ours) = hop.pinned.as_ref().filter(|pinned| pinned.algorithm != key.algorithm).and_then(|pinned| offered_for_pin(&pinned.algorithm)) {
                return Err(ConnectError::NoCommonHostKeyAlgorithm { hop: reference, ours, theirs: vec![key.algorithm] });
            }
            match host_keys.check(&reference, &key) {
                HostKeyVerdict::Pinned => {}
                HostKeyVerdict::Unknown => return Err(ConnectError::HostKeyUnknown { hop: reference, key }),
                HostKeyVerdict::Mismatch { pinned } => return Err(ConnectError::HostKeyMismatch { hop: reference, key, pinned }),
            }
            if let Some(banner) = &banner {
                auth.banner(&reference, banner);
            }
            match logins.get(&hop.alias).unwrap_or(&login_default) {
                FakeLogin::Accept => {}
                FakeLogin::Server(methods) => fake_login(hop, methods, auth, prefetched, prompt_wait)?,
            }
        }
        if let Some(error) = scripted_error {
            // It names a hop that is not in this chain: the script is about another target, and it still fails this one.
            return Err(error);
        }
        self.shared.record(FakeEvent::Connect { aliases: target.hops.iter().map(|hop| hop.alias.clone()).collect() });
        let disconnect = locked(&self.shared.script).disconnect.clone();
        let destination = target.hops.last().map(Hop::reference).ok_or_else(|| ConnectError::BadJumpChain { why: "the target has no hosts".to_string() })?;
        let state = Arc::new(SessionState {
            destination,
            first: target.hops[0].reference(),
            closed: Mutex::new(disconnect),
            tunnel_end: Mutex::new(None),
            shells: Mutex::new(Vec::new()),
        });
        locked(&self.shared.sessions).push(Arc::downgrade(&state));
        Ok(Box::new(FakeSession { shared: Arc::clone(&self.shared), state }))
    }
}

/// The host key algorithms the real engine offers a server for a hop pinned to a key of type `pinned` (`russh_engine::host_key_algorithms`):
/// the key's own family, which for an RSA key is the rsa-sha2 pair and never SHA-1 `ssh-rsa`. `None` for a type the engine cannot restrict
/// the offer by: one it does not offer (DSA, security keys) or a name it cannot parse. The handshake then offers everything, and the pin is
/// left to the host key policy.
fn offered_for_pin(pinned: &str) -> Option<Vec<String>> {
    match pinned {
        "ssh-rsa" => Some(vec!["rsa-sha2-512".to_string(), "rsa-sha2-256".to_string()]),
        "ssh-ed25519" | "ecdsa-sha2-nistp256" | "ecdsa-sha2-nistp384" | "ecdsa-sha2-nistp521" => Some(vec![pinned.to_string()]),
        _ => None,
    }
}

/// The time a person gets for one keyboard-interactive round: the script's, or the real engine's default (4 × the connect timeout, at
/// least 60 s).
fn prompt_deadline(hop: &Hop, prompt_wait: Option<Duration>) -> Instant {
    let wait = prompt_wait.unwrap_or_else(|| hop.connect_timeout.saturating_mul(4).max(Duration::from_secs(60)));
    let now = Instant::now();
    now.checked_add(wait).unwrap_or_else(|| now + Duration::from_secs(60 * 60 * 24 * 365))
}

/// The real engine's login sequence (`russh_engine::authenticate`) against the methods of a fake server.
fn fake_login(hop: &Hop, server: &FakeMethods, auth: &dyn AuthSource, mut prefetched: Option<Option<Secret>>, prompt_wait: Option<Duration>) -> Result<(), ConnectError> {
    let reference = hop.reference();
    let abandoned = |reason: &str| ConnectError::AuthAbandoned { hop: reference.clone(), reason: reason.to_string() };
    let mut tried: Vec<AuthMethod> = Vec::new();
    let mut reasons: Vec<String> = Vec::new();
    // What the server has said it offers; nothing until it has answered a request.
    let mut offered: Option<Vec<AuthMethod>> = None;
    let lists = |offered: &Option<Vec<AuthMethod>>, method: &AuthMethod| {
        offered.as_ref().is_some_and(|list| list.iter().any(|listed| std::mem::discriminant(listed) == std::mem::discriminant(method)))
    };
    let refusal = |reasons: &mut Vec<String>, tried: &[AuthMethod]| -> Result<Vec<AuthMethod>, ConnectError> {
        let list = server.offered();
        if list.is_empty() {
            reasons.push("The server offers no login method.".to_string());
            return Err(ConnectError::AuthFailed { hop: reference.clone(), tried: tried.to_vec(), reason: reasons.join(" "), password_wanted: false });
        }
        Ok(list)
    };
    for method in hop.auth_sequence() {
        if offered.is_some() && !lists(&offered, &method) {
            continue;
        }
        let accepted = match &method {
            AuthMethod::Key { key_id } => {
                if auth.public_key(key_id).is_none() {
                    reasons.push(format!("The key {key_id} is not available on this computer."));
                    None
                } else {
                    tried.push(method.clone());
                    if server.key {
                        auth.sign(key_id, b"fake-challenge", Some(RsaHash::Sha512)).map_err(|error| abandoned(&error.to_string()))?;
                        Some(true)
                    } else {
                        Some(false)
                    }
                }
            }
            AuthMethod::Password => match prefetched.take().unwrap_or_else(|| auth.password(&reference)) {
                None => {
                    reasons.push("No password was given.".to_string());
                    None
                }
                Some(given) => {
                    tried.push(method.clone());
                    Some(server.password.as_deref() == Some(given.as_str()))
                }
            },
            AuthMethod::Interactive => {
                tried.push(method.clone());
                match &server.interactive {
                    None => Some(false),
                    Some(round) => {
                        let deadline = prompt_deadline(hop, prompt_wait);
                        let Some(given) = auth.interactive(&reference, &round.prompts, deadline) else { return Err(abandoned("the prompt was cancelled")) };
                        if Instant::now() > deadline {
                            return Err(abandoned("the prompt was answered after its deadline"));
                        }
                        if given.len() != round.prompts.len() {
                            return Err(abandoned("the answers do not match the prompts"));
                        }
                        Some(given.iter().map(|answer| answer.as_str()).eq(round.answers.iter().map(String::as_str)))
                    }
                }
            }
        };
        match accepted {
            Some(true) => return Ok(()),
            Some(false) => offered = Some(refusal(&mut reasons, &tried)?),
            // Skipped before the server said anything: the real engine asks it (`none`) what it offers.
            None if offered.is_none() => offered = Some(refusal(&mut reasons, &tried)?),
            None => {}
        }
    }
    let password_wanted = lists(&offered, &AuthMethod::Password) && !tried.contains(&AuthMethod::Password);
    Err(ConnectError::AuthFailed { hop: reference, tried, reason: reasons.join(" "), password_wanted })
}

/// What a session and the shells opened on it share: whether (and why) it is over.
struct SessionState {
    destination: HopRef,
    /// The first hop, which an IAP tunnel would carry (`FakeEngine::end_tunnel_now`).
    first: HopRef,
    closed: Mutex<Option<DisconnectReason>>,
    /// Why the first hop's IAP tunnel ended, when `end_tunnel_now` ended the session; written while `closed` is held, before it is set.
    tunnel_end: Mutex<Option<IapError>>,
    /// The queue, exit cell and "session over" flag of every shell opened here: when the session ends, so do they, as they do on a lost
    /// connection. A shell is added while `closed` is held (see `shell`) and `end` ends them while it holds `closed`, so none is missed.
    shells: Mutex<Vec<(Arc<ByteQueue>, Arc<ExitCell>, Arc<AtomicBool>)>>,
}

impl SessionState {
    /// Ends the session for `reason` unless it is over already; true when this call ended it.
    fn end(&self, reason: DisconnectReason) -> bool {
        self.end_with(reason, None)
    }

    /// `end`, with why the first hop's IAP tunnel ended written down first when the tunnel is what ended it.
    fn end_with(&self, reason: DisconnectReason, tunnel_end: Option<IapError>) -> bool {
        let mut closed = locked(&self.closed);
        if closed.is_some() {
            return false;
        }
        if tunnel_end.is_some() {
            *locked(&self.tunnel_end) = tunnel_end;
        }
        *closed = Some(reason);
        for (queue, exit, over) in locked(&self.shells).iter() {
            over.store(true, Ordering::SeqCst);
            exit.set(Exit::Disconnected);
            queue.close();
        }
        true
    }
}

struct FakeSession {
    shared: Arc<Shared>,
    state: Arc<SessionState>,
}

/// The remote side of a shell the fake opened: a test prints into it and ends it, as the server would.
#[derive(Clone)]
pub struct FakeShell {
    queue: Arc<ByteQueue>,
    exit: Arc<ExitCell>,
}

impl FakeShell {
    /// The server prints `bytes`.
    pub fn print(&self, bytes: &[u8]) {
        self.queue.push(bytes.to_vec());
    }

    /// The shell ends as `exit` (the user typed `exit`, a signal killed it); what it printed before can still be read.
    pub fn end(&self, exit: Exit) {
        self.exit.set(exit);
        self.queue.close();
    }
}

struct FakeShellInput {
    shared: Arc<Shared>,
    queue: Arc<ByteQueue>,
    exit: Arc<ExitCell>,
    /// The session is over: input fails with `Closed`, as on the real engine (a shell we closed ourselves still takes input there).
    session_over: Arc<AtomicBool>,
}

impl ShellInput for FakeShellInput {
    fn write(&self, bytes: &[u8]) -> Result<(), SessionError> {
        if self.session_over.load(Ordering::SeqCst) {
            return Err(SessionError::Closed);
        }
        if let Some(error) = locked(&self.shared.script).write_errors.pop_front() {
            return Err(error);
        }
        self.shared.record(FakeEvent::ShellInput(bytes.to_vec()));
        Ok(())
    }

    fn window_change(&self, cols: u16, rows: u16) -> Result<(), SessionError> {
        if self.session_over.load(Ordering::SeqCst) {
            return Err(SessionError::Closed);
        }
        self.shared.record(FakeEvent::WindowChange { cols, rows });
        Ok(())
    }

    /// Our own close: the channel ends without a status, as with the real engine.
    fn close(&self) {
        self.shared.record(FakeEvent::ShellClosed);
        self.exit.set(Exit::Disconnected);
        self.queue.close();
    }
}

/// `result` with its output cut to `cap` bytes (stdout first, then stderr); when something was cut, `truncated` is set and the command
/// ended as `Truncated`, as in the real engine.
fn capped(mut result: ExecResult, cap: usize) -> ExecResult {
    if result.stdout.len() + result.stderr.len() > cap {
        result.stdout.truncate(cap);
        result.stderr.truncate(cap - result.stdout.len());
        result.truncated = true;
        result.ended = Ended::Truncated;
        result.exit_code = None;
        result.signal = None;
    }
    result
}

/// A forward the fake opened. It listens on nothing and carries nothing: it runs until it is stopped or its session ends, as the real
/// one does (which then also says that the SSH connection ended; the tunnel manager says the same when a forward does not).
struct FakeForwarder {
    session: Arc<SessionState>,
    port: u16,
    stopped: AtomicBool,
}

impl Forwarder for FakeForwarder {
    fn status(&self) -> ForwardStatus {
        let running = !self.stopped.load(Ordering::SeqCst) && locked(&self.session.closed).is_none();
        ForwardStatus { running, port: self.port, connections: 0, error: None }
    }

    fn stop(&self) {
        self.stopped.store(true, Ordering::SeqCst);
    }
}

impl Session for FakeSession {
    /// A forward as `FakeForwarder` says; its status names the port asked for. Checked and refused as on the real engine: a spec that is
    /// not valid, a session that is over.
    fn forward(&self, spec: &ForwardSpec) -> Result<Box<dyn Forwarder>, SessionError> {
        spec.validate().map_err(SessionError::Channel)?;
        if !self.is_alive() {
            return Err(SessionError::Closed);
        }
        Ok(Box::new(FakeForwarder { session: Arc::clone(&self.state), port: spec.port, stopped: AtomicBool::new(false) }))
    }

    fn shell(&self, pty: Pty) -> Result<Box<dyn ShellChannel>, SessionError> {
        let (output, exit, ends_at_once, error) = {
            let script = locked(&self.shared.script);
            (script.shell_output.clone(), script.shell_exit.clone(), script.shell_ends_at_once, script.shell_error.clone())
        };
        let (queue, cell, over) = (ByteQueue::new(1024 * 1024), ExitCell::new(), Arc::new(AtomicBool::new(false)));
        for chunk in output {
            queue.push(chunk);
        }
        if ends_at_once {
            cell.set(exit);
            queue.close();
        }
        {
            // The check that the session is alive and the registration of the new shell are made under one lock, so a close on another
            // thread runs either before this (the call fails with `Closed` and records nothing) or after it (and ends this shell with the
            // others): no shell is left open on a closed session. The lock covers only these steps, because a thread that opens shells in
            // a loop would otherwise keep a close waiting. (`self.is_alive()` would lock `closed` again here.)
            let closed = locked(&self.state.closed);
            if closed.is_some() {
                return Err(SessionError::Closed);
            }
            if let Some(error) = error {
                return Err(error);
            }
            self.shared.record(FakeEvent::ShellOpened { term: pty.term, cols: pty.cols, rows: pty.rows });
            locked(&self.state.shells).push((Arc::clone(&queue), Arc::clone(&cell), Arc::clone(&over)));
            locked(&self.shared.shells).push(FakeShell { queue: Arc::clone(&queue), exit: Arc::clone(&cell) });
        }
        let input = FakeShellInput { shared: Arc::clone(&self.shared), queue: Arc::clone(&queue), exit: Arc::clone(&cell), session_over: over };
        Ok(Box::new(QueuedShell::new(Box::new(input), queue, cell)))
    }

    fn exec(&self, command: &str, timeout: Duration, output_cap: usize) -> Result<ExecResult, SessionError> {
        if !self.is_alive() {
            return Err(SessionError::Closed);
        }
        self.shared.record(FakeEvent::Exec { command: command.to_string(), timeout, output_cap });
        let scripted = locked(&self.shared.script).exec.get(command).cloned();
        let result = scripted.unwrap_or(ExecResult {
            ended: Ended::Exited,
            exit_code: Some(0),
            signal: None,
            stdout: Vec::new(),
            stderr: Vec::new(),
            truncated: false,
        });
        Ok(capped(result, output_cap))
    }

    fn is_alive(&self) -> bool {
        locked(&self.state.closed).is_none()
    }

    fn disconnect_reason(&self) -> Option<DisconnectReason> {
        locked(&self.state.closed).clone()
    }

    fn tunnel_end(&self) -> Option<IapError> {
        locked(&self.state.tunnel_end).clone()
    }

    fn close(&self) {
        let reason = DisconnectReason { hop: self.state.destination.clone(), kind: DisconnectKind::ClosedByUs, detail: "closed by the caller".to_string() };
        if self.state.end(reason) {
            self.shared.record(FakeEvent::Closed);
        }
    }
}

/// "Dropping it closes it" (the `Session` contract): a session that is dropped without `close` is closed here.
impl Drop for FakeSession {
    fn drop(&mut self) {
        self.close();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ssh::error::AuthError;
    use crate::ssh::forward::ForwardKind;
    use crate::ssh::types::{HostId, Secret, Signature};
    use std::time::Instant;
    use zeroize::Zeroizing;

    const SHORT: Duration = Duration::from_millis(100);

    fn hop(alias: &str) -> Hop {
        Hop::new(&format!("id-{alias}"), alias, &format!("{alias}.example.com"), 22, "deploy", AuthMethod::Key { key_id: format!("key-{alias}") })
    }

    fn password_first(alias: &str) -> Hop {
        Hop::new(&format!("id-{alias}"), alias, &format!("{alias}.example.com"), 22, "deploy", AuthMethod::Password)
    }

    /// Pins one fingerprint; everything else is unknown, or a mismatch when `pinned` is set.
    struct Policy {
        accepted: Option<String>,
        pinned: Option<HostKey>,
    }

    impl HostKeyPolicy for Policy {
        fn check(&self, _hop: &HopRef, key: &HostKey) -> HostKeyVerdict {
            match (&self.accepted, &self.pinned) {
                (Some(fingerprint), _) if *fingerprint == key.fingerprint => HostKeyVerdict::Pinned,
                (_, Some(pinned)) => HostKeyVerdict::Mismatch { pinned: pinned.clone() },
                _ => HostKeyVerdict::Unknown,
            }
        }
    }

    fn trusting() -> Policy {
        Policy { accepted: Some(default_server_key().fingerprint), pinned: None }
    }

    /// Records what it was asked and answers from fixed values.
    #[derive(Default)]
    struct Auth {
        password: Option<String>,
        answers: Option<Vec<String>>,
        sign_fails: bool,
        asked: Mutex<Vec<String>>,
    }

    impl AuthSource for Auth {
        fn public_key(&self, key_id: &str) -> Option<String> {
            locked(&self.asked).push(format!("public_key {key_id}"));
            Some(test_keys::PLAIN_PUBLIC.to_string())
        }
        fn sign(&self, key_id: &str, _data: &[u8], _rsa_hash: Option<RsaHash>) -> Result<Signature, AuthError> {
            locked(&self.asked).push(format!("sign {key_id}"));
            if self.sign_fails {
                Err(AuthError::Refused("the vault is locked".into()))
            } else {
                Ok(Signature(vec![1, 2, 3]))
            }
        }
        fn password(&self, hop: &HopRef) -> Option<Secret> {
            locked(&self.asked).push(format!("password {}", hop.alias));
            self.password.clone().map(Zeroizing::new)
        }
        fn interactive(&self, hop: &HopRef, prompts: &[Prompt], _deadline: Instant) -> Option<Vec<Secret>> {
            locked(&self.asked).push(format!("interactive {} {}", hop.alias, prompts.len()));
            self.answers.clone().map(|answers| answers.into_iter().map(Zeroizing::new).collect())
        }
        fn banner(&self, hop: &HopRef, text: &str) {
            locked(&self.asked).push(format!("banner {} {text}", hop.alias));
        }
    }

    fn connect(engine: &FakeEngine, target: &Target, auth: &Auth) -> Result<Box<dyn Session>, ConnectError> {
        engine.connect(target, &trusting(), auth)
    }

    fn direct(alias: &str) -> Target {
        Target { hops: vec![hop(alias)] }
    }

    fn asked(auth: &Auth) -> Vec<String> {
        locked(&auth.asked).clone()
    }

    fn exec(session: &dyn Session, command: &str) -> ExecResult {
        session.exec(command, SHORT, 1024).unwrap()
    }

    fn server(methods: FakeMethods) -> FakeEngine {
        FakeEngine::new().with_login(FakeLogin::Server(methods))
    }

    #[test]
    fn by_default_everything_succeeds_and_the_calls_are_recorded() {
        let engine = FakeEngine::new();
        let session = connect(&engine, &direct("web"), &Auth::default()).expect("connects");
        assert!(session.is_alive());
        let result = session.exec("uptime", SHORT, 4096).unwrap();
        assert_eq!((result.ended, result.exit_code, result.truncated), (Ended::Exited, Some(0), false));
        assert!(result.stdout.is_empty() && result.stderr.is_empty());
        assert_eq!(
            engine.events(),
            vec![FakeEvent::Connect { aliases: vec!["web".into()] }, FakeEvent::Exec { command: "uptime".into(), timeout: SHORT, output_cap: 4096 }]
        );
    }

    #[test]
    fn a_scripted_exec_result_comes_back_for_exactly_that_command_and_is_cut_to_the_cap() {
        let killed = ExecResult { ended: Ended::Signaled, exit_code: None, signal: Some("KILL".into()), stdout: b"partial".to_vec(), stderr: vec![], truncated: false };
        let chatty = ExecResult { ended: Ended::Exited, exit_code: Some(3), signal: None, stdout: b"abc".to_vec(), stderr: b"defg".to_vec(), truncated: false };
        let engine = FakeEngine::new().with_exec("sleep 99", killed.clone()).with_exec("chatty", chatty.clone());
        let session = connect(&engine, &direct("web"), &Auth::default()).unwrap();
        assert_eq!(exec(session.as_ref(), "sleep 99"), killed);
        assert_eq!(exec(session.as_ref(), "sleep 98").exit_code, Some(0));

        let cut = session.exec("sleep 99", SHORT, 4).unwrap();
        assert_eq!((cut.stdout.as_slice(), cut.truncated, cut.ended, cut.signal), (b"part".as_slice(), true, Ended::Truncated, None));

        // The cap is a limit, not a threshold: output that exactly fills it is whole and keeps its status.
        assert_eq!(session.exec("sleep 99", SHORT, 7).unwrap(), killed);
        assert_eq!(session.exec("chatty", SHORT, 7).unwrap(), chatty);

        // stdout and stderr share the cap, stdout first; a command that was cut has no status to report.
        let cut = session.exec("chatty", SHORT, 5).unwrap();
        assert_eq!((cut.stdout.as_slice(), cut.stderr.as_slice()), (b"abc".as_slice(), b"de".as_slice()));
        assert_eq!((cut.ended, cut.truncated, cut.exit_code, cut.signal), (Ended::Truncated, true, None, None));
        let cut = session.exec("chatty", SHORT, 2).unwrap();
        assert_eq!((cut.stdout.as_slice(), cut.stderr.as_slice()), (b"ab".as_slice(), b"".as_slice()));
    }

    #[test]
    fn the_host_key_verdicts_become_the_connect_errors_the_real_engine_gives() {
        let engine = FakeEngine::new();
        let unknown = Policy { accepted: None, pinned: None };
        match engine.connect(&direct("web"), &unknown, &Auth::default()) {
            Err(ConnectError::HostKeyUnknown { hop, key }) => assert_eq!((hop.alias.as_str(), key), ("web", default_server_key())),
            other => panic!("expected HostKeyUnknown, got {:?}", other.err()),
        }
        let other_key = HostKey { algorithm: "ssh-ed25519".into(), public_key: vec![9], fingerprint: "SHA256:other".into() };
        let changed = Policy { accepted: None, pinned: Some(other_key.clone()) };
        match engine.connect(&direct("web"), &changed, &Auth::default()) {
            Err(ConnectError::HostKeyMismatch { key, pinned, .. }) => assert_eq!((key, pinned), (default_server_key(), other_key)),
            other => panic!("expected HostKeyMismatch, got {:?}", other.err()),
        }
        assert_eq!(engine.events(), vec![], "a failed connect leaves no event");

        // The script decides which key a server presents: the same for every host, or its own for one host of a chain.
        let presented = HostKey { algorithm: "ssh-ed25519".into(), public_key: vec![7], fingerprint: "SHA256:presented".into() };
        let engine = FakeEngine::new().with_host_key(presented.clone());
        match engine.connect(&direct("web"), &unknown, &Auth::default()) {
            Err(ConnectError::HostKeyUnknown { key, .. }) => assert_eq!(key, presented),
            other => panic!("expected HostKeyUnknown, got {:?}", other.err()),
        }
        let engine = FakeEngine::new().with_host_key_for("db", presented.clone());
        let chain = Target { hops: vec![hop("bastion"), hop("db")] };
        match connect(&engine, &chain, &Auth::default()) {
            Err(ConnectError::HostKeyUnknown { hop, key }) => assert_eq!((hop.alias.as_str(), key), ("db", presented)),
            other => panic!("expected the db to present its own key, got {:?}", other.err()),
        }
    }

    /// A pinned hop offers only its pin's key type, as the real engine's handshake does: a server whose key is of another type has nothing
    /// in common with it, and without the pin the same server presents its key as usual.
    #[test]
    fn a_pin_of_another_key_type_finds_no_common_algorithm() {
        let engine = FakeEngine::new();
        let ecdsa = HostKey::from_openssh_line(test_keys::ECDSA_PUBLIC).unwrap();
        let mut pinned = hop("web");
        pinned.pinned = Some(ecdsa.clone());
        match connect(&engine, &Target { hops: vec![pinned] }, &Auth::default()) {
            Err(ConnectError::NoCommonHostKeyAlgorithm { hop, ours, theirs }) => {
                assert_eq!((hop.alias.as_str(), ours, theirs), ("web", vec!["ecdsa-sha2-nistp256".to_string()], vec!["ssh-ed25519".to_string()]));
            }
            other => panic!("expected NoCommonHostKeyAlgorithm, got {:?}", other.err()),
        }
        let mut same_type = hop("web");
        same_type.pinned = Some(default_server_key());
        assert!(connect(&engine, &Target { hops: vec![same_type] }, &Auth::default()).is_ok());
    }

    /// The offer as the real engine makes it (`russh_engine::host_key_algorithms`): an RSA pin is offered as the rsa-sha2 pair and never as
    /// SHA-1 `ssh-rsa`, and a pin of a type the engine cannot restrict the offer by (DSA, a security key, a name it cannot parse)
    /// restricts nothing: the server presents its key as usual, and the policy is what judges it.
    #[test]
    fn an_rsa_pin_is_offered_as_the_rsa_sha2_pair_and_a_pin_the_engine_cannot_restrict_by_restricts_nothing() {
        let pinned_to = |key: HostKey| {
            let mut pinned = hop("web");
            pinned.pinned = Some(key);
            Target { hops: vec![pinned] }
        };
        let rsa = HostKey::from_openssh_line(test_keys::RSA_PUBLIC).unwrap();
        match connect(&FakeEngine::new(), &pinned_to(rsa.clone()), &Auth::default()) {
            Err(ConnectError::NoCommonHostKeyAlgorithm { ours, theirs, .. }) => {
                assert_eq!((ours, theirs), (vec!["rsa-sha2-512".to_string(), "rsa-sha2-256".to_string()], vec!["ssh-ed25519".to_string()]));
            }
            other => panic!("expected NoCommonHostKeyAlgorithm, got {:?}", other.err()),
        }
        // A server whose key is an RSA key has the pin's family in common.
        let rsa_server = FakeEngine::new().with_host_key(rsa.clone());
        let accepts_rsa = Policy { accepted: Some(rsa.fingerprint.clone()), pinned: None };
        assert!(rsa_server.connect(&pinned_to(rsa), &accepts_rsa, &Auth::default()).is_ok());

        for algorithm in ["ssh-dss", "sk-ssh-ed25519@openssh.com", "not-an-algorithm"] {
            let odd = HostKey { algorithm: algorithm.into(), public_key: vec![1], fingerprint: "SHA256:odd".into() };
            assert!(connect(&FakeEngine::new(), &pinned_to(odd), &Auth::default()).is_ok(), "a pin of {algorithm} restricts nothing");
        }
    }

    /// The real engine's sequence against a server that offers only passwords: the key goes first and is refused, then the password.
    #[test]
    fn a_password_server_refuses_the_key_then_checks_the_password_and_says_when_one_is_wanted() {
        let engine = server(FakeMethods::password("hunter2"));
        let right = Auth { password: Some("hunter2".into()), ..Auth::default() };
        assert!(connect(&engine, &direct("web"), &right).is_ok());
        assert_eq!(asked(&right), ["public_key key-web", "password web"]);

        let key = AuthMethod::Key { key_id: "key-web".into() };
        let wrong = Auth { password: Some("letmein".into()), ..Auth::default() };
        assert!(
            matches!(connect(&engine, &direct("web"), &wrong), Err(ConnectError::AuthFailed { tried, password_wanted: false, .. }) if tried == [key.clone(), AuthMethod::Password])
        );

        let none = Auth::default();
        assert!(
            matches!(connect(&engine, &direct("web"), &none), Err(ConnectError::AuthFailed { tried, password_wanted: true, .. }) if tried == [key]),
            "no password: the method is skipped, and a typed one could get in"
        );

        let by_password = Target { hops: vec![password_first("pw")] };
        let unknown = Policy { accepted: None, pinned: None };
        let asked_first = Auth { password: Some("hunter2".into()), ..Auth::default() };
        assert!(matches!(engine.connect(&by_password, &unknown, &asked_first), Err(ConnectError::HostKeyUnknown { .. })));
        assert_eq!(asked(&asked_first), ["password pw"], "a hop that starts with the password method is asked before its host key is looked at");
        let once = Auth { password: Some("hunter2".into()), ..Auth::default() };
        assert!(connect(&engine, &by_password, &once).is_ok());
        assert_eq!(asked(&once), ["password pw"], "asked once, before the host key, and not again during the login");
    }

    /// A password nobody has is skipped and keyboard-interactive comes next, when the server offers it, as in the real engine.
    #[test]
    fn a_missing_password_goes_on_to_keyboard_interactive() {
        let engine = server(FakeMethods::password("hunter2").and_interactive("Password: ", "hunter2"));
        let auth = Auth { answers: Some(vec!["hunter2".into()]), ..Auth::default() };
        connect(&engine, &Target { hops: vec![password_first("pw")] }, &auth).expect("keyboard-interactive gets in");
        assert_eq!(asked(&auth), ["password pw", "interactive pw 1"]);
    }

    #[test]
    fn a_keyboard_interactive_server_sends_the_prompts_and_compares_the_answers() {
        let prompts = vec![Prompt { text: "Verification code: ".into(), echo: true }];
        let engine = server(FakeMethods { interactive: Some(FakeRound { prompts, answers: vec!["123456".into()] }), ..FakeMethods::default() });
        let right = Auth { answers: Some(vec!["123456".into()]), ..Auth::default() };
        assert!(connect(&engine, &direct("web"), &right).is_ok());
        assert_eq!(asked(&right), ["public_key key-web", "interactive web 1"], "the password method is not offered, so it is not asked for");
        let wrong = Auth { answers: Some(vec!["000000".into()]), ..Auth::default() };
        assert!(matches!(connect(&engine, &direct("web"), &wrong), Err(ConnectError::AuthFailed { .. })));
        assert!(matches!(connect(&engine, &direct("web"), &Auth::default()), Err(ConnectError::AuthAbandoned { .. })), "a cancelled prompt abandons the login");

        // A number of answers that does not match the number of prompts is not a wrong answer: the login is abandoned, as in the real engine.
        for answers in [vec![], vec!["123456".to_string(), "654321".to_string()]] {
            let mismatched = Auth { answers: Some(answers), ..Auth::default() };
            match connect(&engine, &direct("web"), &mismatched) {
                Err(ConnectError::AuthAbandoned { reason, .. }) => assert_eq!(reason, "the answers do not match the prompts"),
                other => panic!("expected the login to be abandoned, got {:?}", other.err()),
            }
        }
    }

    /// Records how long `interactive` was given, then answers after `delay`.
    struct Clocked {
        delay: Duration,
        given: Mutex<Vec<Duration>>,
    }

    impl AuthSource for Clocked {
        fn public_key(&self, _key_id: &str) -> Option<String> {
            None
        }
        fn sign(&self, _key_id: &str, _data: &[u8], _rsa_hash: Option<RsaHash>) -> Result<Signature, AuthError> {
            Err(AuthError::KeyUnavailable("none".into()))
        }
        fn password(&self, _hop: &HopRef) -> Option<Secret> {
            None
        }
        fn interactive(&self, _hop: &HopRef, _prompts: &[Prompt], deadline: Instant) -> Option<Vec<Secret>> {
            locked(&self.given).push(deadline.saturating_duration_since(Instant::now()));
            std::thread::sleep(self.delay);
            Some(vec![Zeroizing::new("123456".to_string())])
        }
    }

    /// As in the real engine: a person gets 4 × the hop's connect timeout and at least a minute, and an answer after the deadline is not used.
    #[test]
    fn a_prompt_gets_four_connect_timeouts_and_at_least_a_minute_and_a_late_answer_abandons_the_login() {
        let engine = server(FakeMethods::interactive("Code: ", "123456"));
        let auth = Clocked { delay: Duration::ZERO, given: Mutex::new(Vec::new()) };
        for connect_timeout in [Duration::from_secs(1), Duration::from_secs(20), Duration::MAX] {
            let mut hop = Hop::new("id-mfa", "mfa", "mfa.example.com", 22, "deploy", AuthMethod::Interactive);
            hop.connect_timeout = connect_timeout;
            engine.connect(&Target { hops: vec![hop] }, &trusting(), &auth).expect("the right code gets in");
        }
        let given = locked(&auth.given).clone();
        assert!(given[0] > Duration::from_secs(59) && given[0] <= Duration::from_secs(60), "{given:?}");
        assert!(given[1] > Duration::from_secs(79) && given[1] <= Duration::from_secs(80), "{given:?}");
        assert!(given[2] > Duration::from_secs(60 * 60 * 24 * 364), "an absurd connect timeout saturates instead of panicking: {given:?}");

        let late = server(FakeMethods::interactive("Code: ", "123456")).with_prompt_wait(Duration::from_millis(50));
        let slow = Clocked { delay: Duration::from_millis(200), given: Mutex::new(Vec::new()) };
        let target = Target { hops: vec![Hop::new("id-mfa", "mfa", "mfa.example.com", 22, "deploy", AuthMethod::Interactive)] };
        match late.connect(&target, &trusting(), &slow) {
            Err(ConnectError::AuthAbandoned { reason, .. }) => assert_eq!(reason, "the prompt was answered after its deadline"),
            other => panic!("expected the late answer to abandon the login, got {:?}", other.err()),
        }
    }

    #[test]
    fn a_key_server_asks_for_a_signature_with_the_key_of_the_hop_and_a_failed_signature_abandons_the_login() {
        let engine = server(FakeMethods::key());
        let auth = Auth::default();
        assert!(connect(&engine, &direct("web"), &auth).is_ok());
        assert_eq!(asked(&auth), ["public_key key-web", "sign key-web"]);
        let locked_vault = Auth { sign_fails: true, ..Auth::default() };
        assert!(matches!(connect(&engine, &direct("web"), &locked_vault), Err(ConnectError::AuthAbandoned { .. })));
    }

    #[test]
    fn a_jump_chain_is_checked_hop_by_hop_and_each_hop_can_be_scripted() {
        let engine = FakeEngine::new().with_login_for("bastion", FakeLogin::Server(FakeMethods::none()));
        let target = Target { hops: vec![hop("bastion"), hop("db")] };
        match connect(&engine, &target, &Auth::default()) {
            Err(ConnectError::AuthFailed { hop, tried, reason, password_wanted }) => {
                assert_eq!(hop.alias, "bastion");
                assert_eq!(tried, [AuthMethod::Key { key_id: "key-bastion".into() }]);
                assert_eq!((reason.as_str(), password_wanted), ("The server offers no login method.", false));
            }
            other => panic!("expected the bastion to refuse, got {:?}", other.err()),
        }
        let engine = FakeEngine::new();
        let session = connect(&engine, &target, &Auth::default()).expect("connects");
        assert_eq!(engine.events(), vec![FakeEvent::Connect { aliases: vec!["bastion".into(), "db".into()] }]);
        drop(session);
        assert_eq!(engine.events().last(), Some(&FakeEvent::Closed), "dropping a session closes it");
    }

    #[test]
    fn a_chain_with_a_repeated_host_or_no_host_is_a_bad_jump_chain() {
        let engine = FakeEngine::new();
        let looping = Target { hops: vec![hop("web"), hop("web")] };
        assert!(matches!(connect(&engine, &looping, &Auth::default()), Err(ConnectError::BadJumpChain { .. })));
        assert!(matches!(connect(&engine, &Target { hops: vec![] }, &Auth::default()), Err(ConnectError::BadJumpChain { .. })));
    }

    /// The real engine asks a password-first hop for its password before it opens the connection, so a host that turns out to be
    /// unreachable has been asked already; the fake fails on the hop the error names, after that question.
    #[test]
    fn a_scripted_connect_failure_comes_on_its_hop_after_that_hops_password_was_asked_for() {
        let error = ConnectError::Unreachable { hop: hop("web").reference(), reason: "connection refused".into() };
        let engine = FakeEngine::new().failing_with(error.clone());
        assert_eq!(connect(&engine, &direct("web"), &Auth::default()).err(), Some(error));

        let unreachable = ConnectError::Unreachable { hop: password_first("pw").reference(), reason: "connection refused".into() };
        let engine = FakeEngine::new().failing_with(unreachable.clone()).with_banner("hello");
        let auth = Auth { password: Some("hunter2".into()), ..Auth::default() };
        assert_eq!(connect(&engine, &Target { hops: vec![hop("bastion"), password_first("pw")] }, &auth).err(), Some(unreachable));
        assert_eq!(asked(&auth), ["banner bastion hello", "password pw"], "the jump host got in, the destination's password was asked for, then it failed");
    }

    /// Runs a test body on its own thread and gives it 10 s: `ShellChannel::read` has no deadline, so a fake that stopped closing its
    /// queue would hang the suite instead of failing the test (the same runner as the tests of `channel.rs`).
    fn bounded(body: impl FnOnce() + Send + 'static) {
        let (finished, done) = std::sync::mpsc::channel();
        let runner = std::thread::spawn(move || {
            body();
            let _ = finished.send(());
        });
        match done.recv_timeout(Duration::from_secs(10)) {
            Ok(()) => runner.join().unwrap(),
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => panic!("the test body did not finish within 10 s: a call is blocked"),
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => std::panic::resume_unwind(runner.join().unwrap_err()),
        }
    }

    fn read_some(shell: &dyn ShellChannel) -> Vec<u8> {
        let mut buf = [0u8; 256];
        let count = shell.read(&mut buf).unwrap();
        buf[..count].to_vec()
    }

    fn pty() -> Pty {
        Pty { term: "xterm-256color".into(), cols: 80, rows: 24 }
    }

    #[test]
    fn a_shell_prints_its_script_records_the_input_and_ends_as_disconnected_when_we_close_it() {
        bounded(|| {
            let engine = FakeEngine::new().with_shell_output(b"welcome\r\n").with_shell_exit(Exit::Code(7));
            let session = connect(&engine, &direct("web"), &Auth::default()).unwrap();
            let shell = session.shell(pty()).unwrap();
            assert_eq!(read_some(shell.as_ref()), b"welcome\r\n");
            shell.write(b"ls\n").unwrap();
            shell.window_change(100, 30).unwrap();
            assert_eq!(shell.exited(), None);
            shell.close();
            assert_eq!(read_some(shell.as_ref()), b"", "a closed shell reads 0");
            assert_eq!(shell.exited(), Some(Exit::Disconnected), "a channel we close ends without a status, as with the real engine");
            assert_eq!(
                engine.events(),
                vec![
                    FakeEvent::Connect { aliases: vec!["web".into()] },
                    FakeEvent::ShellOpened { term: "xterm-256color".into(), cols: 80, rows: 24 },
                    FakeEvent::ShellInput(b"ls\n".to_vec()),
                    FakeEvent::WindowChange { cols: 100, rows: 30 },
                    FakeEvent::ShellClosed,
                ]
            );
        });
    }

    #[test]
    fn a_shell_that_ends_at_once_reports_its_exit_after_the_output() {
        bounded(|| {
            let engine = FakeEngine::new().with_shell_output(b"bye\r\n").with_shell_exit(Exit::Signal("HUP".into())).with_shell_ending_at_once();
            let session = connect(&engine, &direct("web"), &Auth::default()).unwrap();
            let shell = session.shell(Pty { term: "dumb".into(), cols: 80, rows: 24 }).unwrap();
            assert_eq!(read_some(shell.as_ref()), b"bye\r\n");
            assert_eq!(read_some(shell.as_ref()), b"");
            assert_eq!(shell.exited(), Some(Exit::Signal("HUP".into())));
        });
    }

    /// A test plays the server: it prints into a running shell and ends it with the status it chooses.
    #[test]
    fn a_test_can_print_into_a_running_shell_and_end_it() {
        bounded(|| {
            let engine = FakeEngine::new();
            let session = connect(&engine, &direct("web"), &Auth::default()).unwrap();
            let shell = session.shell(pty()).unwrap();
            let remote = engine.shells().pop().expect("the shell's remote side");
            remote.print(b"$ ");
            assert_eq!(read_some(shell.as_ref()), b"$ ");
            remote.print(b"logout\r\n");
            remote.end(Exit::Code(3));
            assert_eq!(read_some(shell.as_ref()), b"logout\r\n", "what was printed before the end is still read");
            assert_eq!(read_some(shell.as_ref()), b"");
            assert_eq!(shell.exited(), Some(Exit::Code(3)));
            assert!(session.is_alive(), "the shell ended, the connection did not");
        });
    }

    #[test]
    fn a_scripted_disconnect_makes_every_call_fail_and_say_why() {
        let reason = DisconnectReason { hop: hop("web").reference(), kind: DisconnectKind::KeepaliveTimeout, detail: "no answer".into() };
        let engine = FakeEngine::new().disconnecting_with(reason.clone());
        let session = connect(&engine, &direct("web"), &Auth::default()).unwrap();
        assert!(!session.is_alive());
        assert_eq!(session.disconnect_reason(), Some(reason));
        assert_eq!(session.exec("uptime", SHORT, 16), Err(SessionError::Closed));
        assert!(matches!(session.shell(Pty { term: "dumb".into(), cols: 80, rows: 24 }), Err(SessionError::Closed)));
    }

    /// The link goes away in the middle of a session: the shells end after what they printed, input fails, and the reason is the one given.
    #[test]
    fn a_disconnect_now_ends_the_live_sessions_and_their_shells_and_says_why() {
        bounded(|| {
            let engine = FakeEngine::new();
            let session = connect(&engine, &direct("web"), &Auth::default()).unwrap();
            let shell = session.shell(pty()).unwrap();
            engine.shells()[0].print(b"half a line");
            let reason = DisconnectReason { hop: hop("web").reference(), kind: DisconnectKind::ConnectionLost, detail: "connection reset by peer".into() };
            engine.disconnect_now(reason.clone());
            assert_eq!(read_some(shell.as_ref()), b"half a line");
            assert_eq!(read_some(shell.as_ref()), b"");
            assert_eq!(shell.exited(), Some(Exit::Disconnected));
            assert!(!session.is_alive());
            assert_eq!(session.disconnect_reason(), Some(reason));
            assert_eq!(shell.write(b"x"), Err(SessionError::Closed));
            assert!(!engine.events().contains(&FakeEvent::Closed), "the connection was lost, not closed by us");
        });
    }

    /// The IAP tunnel of a chain's first hop ends: the session ends with it, says why on that hop as the real engine does, and keeps
    /// the tunnel's end; a session that ended another way, or that we closed, has none.
    #[test]
    fn an_ended_iap_tunnel_ends_the_session_and_says_why() {
        bounded(|| {
            let engine = FakeEngine::new();
            let chain = connect(&engine, &Target { hops: vec![hop("bastion"), hop("web")] }, &Auth::default()).unwrap();
            let shell = chain.shell(pty()).unwrap();
            assert_eq!(chain.tunnel_end(), None, "a live session's tunnel has not ended");
            let end = IapError::Closed { code: 4033, reason: "not authorized".into() };
            engine.end_tunnel_now(end.clone());
            assert!(!chain.is_alive());
            assert_eq!(chain.tunnel_end(), Some(end.clone()));
            let reason = DisconnectReason { hop: hop("bastion").reference(), kind: DisconnectKind::ConnectionLost, detail: "the relay closed the tunnel (4033: not authorized)".into() };
            assert_eq!(chain.disconnect_reason(), Some(reason));
            assert_eq!(read_some(shell.as_ref()), b"");
            assert_eq!(shell.exited(), Some(Exit::Disconnected));

            let lost = connect(&engine, &direct("web"), &Auth::default()).unwrap();
            engine.disconnect_now(DisconnectReason { hop: hop("web").reference(), kind: DisconnectKind::ConnectionLost, detail: "reset".into() });
            engine.end_tunnel_now(end.clone());
            assert_eq!(lost.tunnel_end(), None, "the session was over before the tunnel ended");
            let closed = connect(&engine, &direct("web"), &Auth::default()).unwrap();
            closed.close();
            engine.end_tunnel_now(end);
            assert_eq!(closed.tunnel_end(), None);
            assert_eq!(engine.events().iter().filter(|event| **event == FakeEvent::Closed).count(), 1, "only our own close is recorded");
        });
    }

    /// A forward listens on nothing: it runs until it is stopped or its session ends, and a session that is over refuses one, as the
    /// real engine does.
    #[test]
    fn a_forward_runs_until_it_is_stopped_or_its_session_ends() {
        let spec = ForwardSpec { kind: ForwardKind::Local, bind_address: "127.0.0.1".into(), port: 15432, target_host: "db.internal".into(), target_port: 5432 };
        let engine = FakeEngine::new();
        let session = connect(&engine, &direct("web"), &Auth::default()).unwrap();
        let stopped = session.forward(&spec).unwrap();
        assert_eq!(stopped.status(), ForwardStatus { running: true, port: 15432, connections: 0, error: None });
        stopped.stop();
        assert!(!stopped.status().running);
        let lost = session.forward(&spec).unwrap();
        engine.end_tunnel_now(IapError::Closed { code: 4033, reason: "not authorized".into() });
        assert!(!lost.status().running);
        assert_eq!(session.forward(&spec).err(), Some(SessionError::Closed));
        let invalid = ForwardSpec { bind_address: "localhost".into(), ..spec };
        let live = connect(&engine, &direct("web"), &Auth::default()).unwrap();
        assert_eq!(live.forward(&invalid).err(), Some(SessionError::Channel("Enter an IPv4 or IPv6 listening address.".into())));
    }

    /// As with the real engine: input to a shell fails with `Closed` once the session is over, but a shell we closed ourselves still
    /// takes it; scripted write errors (a link that does not take the input) come first and record nothing.
    #[test]
    fn input_fails_once_the_session_is_over_and_scripted_errors_come_first() {
        bounded(|| {
            let engine = FakeEngine::new().with_write_errors(vec![SessionError::Timeout]);
            let session = connect(&engine, &direct("web"), &Auth::default()).unwrap();
            let first = session.shell(pty()).unwrap();
            assert_eq!(first.write(b"lost"), Err(SessionError::Timeout));
            assert_eq!(first.write(b"kept"), Ok(()));
            first.close();
            assert_eq!(first.write(b"after our close"), Ok(()), "the real engine takes it too");
            let second = session.shell(pty()).unwrap();
            session.close();
            assert_eq!(second.write(b"x"), Err(SessionError::Closed));
            assert_eq!(second.window_change(100, 30), Err(SessionError::Closed));
            let inputs: Vec<Vec<u8>> = engine.events().into_iter().filter_map(|event| if let FakeEvent::ShellInput(bytes) = event { Some(bytes) } else { None }).collect();
            assert_eq!(inputs, [b"kept".to_vec(), b"after our close".to_vec()]);
        });
    }

    #[test]
    fn a_scripted_shell_error_is_what_shell_returns() {
        let engine = FakeEngine::new().with_shell_error(SessionError::Channel("channel open refused".into()));
        let session = connect(&engine, &direct("web"), &Auth::default()).unwrap();
        assert_eq!(session.shell(pty()).err(), Some(SessionError::Channel("channel open refused".into())));
        assert!(engine.shells().is_empty());
    }

    #[test]
    fn closing_is_recorded_once() {
        bounded(|| {
            let engine = FakeEngine::new();
            let session = connect(&engine, &direct("web"), &Auth::default()).unwrap();
            let shell = session.shell(Pty { term: "dumb".into(), cols: 80, rows: 24 }).unwrap();
            assert!(session.is_alive() && session.disconnect_reason().is_none());
            session.close();
            session.close();
            assert!(!session.is_alive());
            let reason = session.disconnect_reason().expect("closed");
            assert_eq!((reason.kind, reason.hop.alias.as_str(), reason.hop.id), (DisconnectKind::ClosedByUs, "web", HostId::from("id-web")));
            assert_eq!(read_some(shell.as_ref()), b"", "closing the session ends the shells opened from it");
            assert_eq!(shell.exited(), Some(Exit::Disconnected));
            assert!(matches!(session.shell(Pty { term: "dumb".into(), cols: 80, rows: 24 }), Err(SessionError::Closed)), "a closed session opens no shells");
            assert_eq!(
                engine.events(),
                vec![FakeEvent::Connect { aliases: vec!["web".into()] }, FakeEvent::ShellOpened { term: "dumb".into(), cols: 80, rows: 24 }, FakeEvent::Closed]
            );
            drop(session);
            assert_eq!(engine.events().iter().filter(|event| **event == FakeEvent::Closed).count(), 1, "dropping a closed session closes nothing more");

            // A shell opened while another thread closes the session is either refused or ended by that close; none is left open. Many scripted
            // chunks make a shell slow to build, which gives a close that is not synchronised with `shell` the time to slip in.
            let racing = (0..64).fold(FakeEngine::new(), |engine, _| engine.with_shell_output(b"x"));
            for _ in 0..200 {
                let session: Arc<dyn Session> = Arc::from(connect(&racing, &direct("web"), &Auth::default()).unwrap());
                let closer = std::thread::spawn({
                    let session = Arc::clone(&session);
                    move || session.close()
                });
                let mut opened = Vec::new();
                for _ in 0..10_000 {
                    match session.shell(Pty { term: "dumb".into(), cols: 80, rows: 24 }) {
                        Ok(shell) => opened.push(shell),
                        Err(_) => break,
                    }
                }
                closer.join().unwrap();
                assert!(opened.iter().all(|shell| shell.exited() == Some(Exit::Disconnected)), "a shell opened while the session was closing was left open");
            }
        });
    }

    #[test]
    fn a_scripted_banner_is_handed_to_the_auth_source_of_each_hop() {
        let engine = FakeEngine::new().with_banner("Authorized use only.");
        let auth = Auth::default();
        connect(&engine, &Target { hops: vec![hop("bastion"), hop("db")] }, &auth).expect("connects");
        assert_eq!(asked(&auth), ["banner bastion Authorized use only.", "banner db Authorized use only."]);
    }
}
