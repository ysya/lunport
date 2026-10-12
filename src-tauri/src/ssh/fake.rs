//! A scripted engine for the tests of the broker, the MCP adapter and the CLI (own-ssh spec §12). It implements the same traits as the
//! russh engine and touches no network: the "server" is a script, and what the code under test did is recorded for the assertions.
//! Test code only (`#[cfg(test)]` in `ssh/mod.rs`).

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use super::channel::{ByteQueue, ExitCell, QueuedShell, ShellInput};
use super::error::{ConnectError, SessionError};
use super::traits::{AuthSource, HostKeyPolicy, Session, ShellChannel, SshEngine};
use super::types::{AuthMethod, DisconnectKind, DisconnectReason, Ended, ExecResult, Exit, Hop, HopRef, HostKey, HostKeyVerdict, Prompt, Pty, RsaHash, Secret, Target};
use crate::sync::slot_rules::test_keys;

fn locked<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

/// How the fake server answers a login.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FakeLogin {
    /// Every login succeeds and the auth source is not consulted, with one exception that holds for every kind of login: a hop that
    /// starts with the password method has its password asked for before its host key is checked, as the real engine does.
    Accept,
    /// Every method is refused: `AuthFailed`, with the hop's whole `Hop::auth_sequence()` as `tried`.
    Refuse,
    /// The hop's key method: the fake asks the auth source for a signature over a fixed challenge and accepts any signature it gets
    /// (it has no public key to verify with). A signing error abandons the login, as in the real engine.
    Signature,
    /// The fake asks `AuthSource::password` and accepts only `expected`. `None` skips the method, so nothing was tried and the login fails.
    /// A hop that starts with the password method is asked before its host key is checked; any other hop is asked during the login.
    Password(String),
    /// The fake sends `prompts` to `AuthSource::interactive` and accepts only `answers`. `None` (a cancelled prompt) abandons the login,
    /// and so does a number of answers that differs from the number of prompts, as in the real engine; the right number of wrong answers
    /// is a refusal.
    Interactive { prompts: Vec<Prompt>, answers: Vec<String> },
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
    exec: HashMap<String, ExecResult>,
    shell_output: Vec<Vec<u8>>,
    shell_exit: Exit,
    shell_ends_at_once: bool,
    disconnect: Option<DisconnectReason>,
}

struct Shared {
    script: Mutex<Script>,
    events: Mutex<Vec<FakeEvent>>,
}

impl Shared {
    fn record(&self, event: FakeEvent) {
        locked(&self.events).push(event);
    }
}

/// The scripted engine. Build it with the `with_*` methods; the defaults are: the server presents `default_server_key()`, every login
/// succeeds, every command exits 0 with no output, a shell prints nothing and exits with code 0 when it is closed, the connection never drops.
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
            exec: HashMap::new(),
            shell_output: Vec::new(),
            shell_exit: Exit::Code(0),
            shell_ends_at_once: false,
            disconnect: None,
        };
        FakeEngine { shared: Arc::new(Shared { script: Mutex::new(script), events: Mutex::new(Vec::new()) }) }
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

    /// `connect` fails with this error before anything else happens.
    pub fn failing_with(self, error: ConnectError) -> FakeEngine {
        self.script(|script| script.connect_error = Some(error))
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

    /// How shells end (when they are closed, or at once with `with_shell_ending_at_once`).
    pub fn with_shell_exit(self, exit: Exit) -> FakeEngine {
        self.script(|script| script.shell_exit = exit)
    }

    /// Shells end as soon as their scripted output has been produced, as a typed `exit` would.
    pub fn with_shell_ending_at_once(self) -> FakeEngine {
        self.script(|script| script.shell_ends_at_once = true)
    }

    /// Every session connects fine and is over right away, for this reason.
    pub fn disconnecting_with(self, reason: DisconnectReason) -> FakeEngine {
        self.script(|script| script.disconnect = Some(reason))
    }

    /// Everything the code under test has done so far.
    pub fn events(&self) -> Vec<FakeEvent> {
        locked(&self.shared.events).clone()
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

impl SshEngine for FakeEngine {
    fn connect(&self, target: &Target, host_keys: &dyn HostKeyPolicy, auth: &dyn AuthSource) -> Result<Box<dyn Session>, ConnectError> {
        check_chain(target)?;
        let (login_default, logins, key_default, keys, scripted_error) = {
            let script = locked(&self.shared.script);
            (script.login.clone(), script.logins.clone(), script.host_key.clone(), script.host_keys.clone(), script.connect_error.clone())
        };
        if let Some(error) = scripted_error {
            return Err(error);
        }
        for hop in &target.hops {
            let reference = hop.reference();
            // A hop that starts with the password method has its password asked for before anything is connected (`AuthSource::password`).
            let prefetched = (hop.auth == AuthMethod::Password).then(|| auth.password(&reference));
            let key = keys.get(&hop.alias).unwrap_or(&key_default).clone();
            match host_keys.check(&reference, &key) {
                HostKeyVerdict::Pinned => {}
                HostKeyVerdict::Unknown => return Err(ConnectError::HostKeyUnknown { hop: reference, key }),
                HostKeyVerdict::Mismatch { pinned } => return Err(ConnectError::HostKeyMismatch { hop: reference, key, pinned }),
            }
            fake_login(hop, logins.get(&hop.alias).unwrap_or(&login_default), auth, prefetched)?;
        }
        self.shared.record(FakeEvent::Connect { aliases: target.hops.iter().map(|hop| hop.alias.clone()).collect() });
        let disconnect = locked(&self.shared.script).disconnect.clone();
        let destination = target.hops.last().map(Hop::reference).ok_or_else(|| ConnectError::BadJumpChain { why: "the target has no hosts".to_string() })?;
        Ok(Box::new(FakeSession { shared: Arc::clone(&self.shared), destination, closed: Mutex::new(disconnect), shells: Mutex::new(Vec::new()) }))
    }
}

fn fake_login(hop: &Hop, login: &FakeLogin, auth: &dyn AuthSource, prefetched: Option<Option<Secret>>) -> Result<(), ConnectError> {
    let reference = hop.reference();
    let refused = |tried: Vec<AuthMethod>| ConnectError::AuthFailed { hop: reference.clone(), tried, reason: String::new() };
    let abandoned = |reason: &str| ConnectError::AuthAbandoned { hop: reference.clone(), reason: reason.to_string() };
    match login {
        FakeLogin::Accept => Ok(()),
        FakeLogin::Refuse => Err(refused(hop.auth_sequence())),
        FakeLogin::Signature => {
            let AuthMethod::Key { key_id } = &hop.auth else { return Err(refused(vec![])) };
            auth.sign(key_id, b"fake-challenge", Some(RsaHash::Sha512)).map(|_| ()).map_err(|error| abandoned(&error.to_string()))
        }
        FakeLogin::Password(expected) => match prefetched.unwrap_or_else(|| auth.password(&reference)) {
            None => Err(ConnectError::AuthFailed { hop: reference.clone(), tried: vec![], reason: "No password was given.".to_string() }),
            Some(given) if given.as_str() == expected => Ok(()),
            Some(_) => Err(refused(vec![AuthMethod::Password])),
        },
        FakeLogin::Interactive { prompts, answers } => {
            let deadline = std::time::Instant::now() + Duration::from_secs(60);
            match auth.interactive(&reference, prompts, deadline) {
                None => Err(abandoned("the prompt was cancelled")),
                Some(given) if given.len() != prompts.len() => Err(abandoned("the answers do not match the prompts")),
                Some(given) if given.iter().map(|answer| answer.as_str()).eq(answers.iter().map(String::as_str)) => Ok(()),
                Some(_) => Err(refused(vec![AuthMethod::Interactive])),
            }
        }
    }
}

struct FakeSession {
    shared: Arc<Shared>,
    destination: HopRef,
    closed: Mutex<Option<DisconnectReason>>,
    /// The queue and exit cell of every shell opened here: when the session ends, so do they, as they do on a lost connection.
    /// A shell is added while `closed` is held (see `shell`) and `close` ends them while it holds `closed`, so none is missed.
    shells: Mutex<Vec<(Arc<ByteQueue>, Arc<ExitCell>)>>,
}

struct FakeShellInput {
    shared: Arc<Shared>,
    queue: Arc<ByteQueue>,
    exit: Arc<ExitCell>,
}

impl ShellInput for FakeShellInput {
    fn write(&self, bytes: &[u8]) -> Result<(), SessionError> {
        self.shared.record(FakeEvent::ShellInput(bytes.to_vec()));
        Ok(())
    }

    fn window_change(&self, cols: u16, rows: u16) -> Result<(), SessionError> {
        self.shared.record(FakeEvent::WindowChange { cols, rows });
        Ok(())
    }

    fn close(&self) {
        self.shared.record(FakeEvent::ShellClosed);
        self.exit.set(locked(&self.shared.script).shell_exit.clone());
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

impl Session for FakeSession {
    fn shell(&self, pty: Pty) -> Result<Box<dyn ShellChannel>, SessionError> {
        let (output, exit, ends_at_once) = {
            let script = locked(&self.shared.script);
            (script.shell_output.clone(), script.shell_exit.clone(), script.shell_ends_at_once)
        };
        let (queue, cell) = (ByteQueue::new(1024 * 1024), ExitCell::new());
        for chunk in output {
            queue.push(chunk);
        }
        if ends_at_once {
            cell.set(exit);
            queue.close();
        }
        {
            // The check that the session is alive and the registration of the new shell are made under one lock, so a `close()` on another
            // thread runs either before this (the call fails with `Closed` and records nothing) or after it (and ends this shell with the
            // others): no shell is left open on a closed session. The lock covers only these steps, because a thread that opens shells in
            // a loop would otherwise keep `close()` waiting. (`self.is_alive()` would lock `closed` again here.)
            let closed = locked(&self.closed);
            if closed.is_some() {
                return Err(SessionError::Closed);
            }
            self.shared.record(FakeEvent::ShellOpened { term: pty.term, cols: pty.cols, rows: pty.rows });
            locked(&self.shells).push((Arc::clone(&queue), Arc::clone(&cell)));
        }
        let input = FakeShellInput { shared: Arc::clone(&self.shared), queue: Arc::clone(&queue), exit: Arc::clone(&cell) };
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
        locked(&self.closed).is_none()
    }

    fn disconnect_reason(&self) -> Option<DisconnectReason> {
        locked(&self.closed).clone()
    }

    fn close(&self) {
        let mut closed = locked(&self.closed);
        if closed.is_none() {
            *closed = Some(DisconnectReason { hop: self.destination.clone(), kind: DisconnectKind::ClosedByUs, detail: "closed by the caller".to_string() });
            self.shared.record(FakeEvent::Closed);
            for (queue, exit) in locked(&self.shells).iter() {
                exit.set(Exit::Disconnected);
                queue.close();
            }
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
    use crate::ssh::types::{HostId, Secret, Signature};
    use std::time::Instant;
    use zeroize::Zeroizing;

    const SHORT: Duration = Duration::from_millis(100);

    fn hop(alias: &str) -> Hop {
        Hop::new(&format!("id-{alias}"), alias, &format!("{alias}.example.com"), 22, "deploy", AuthMethod::Key { key_id: format!("key-{alias}") })
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
    }

    fn connect(engine: &FakeEngine, target: &Target, auth: &Auth) -> Result<Box<dyn Session>, ConnectError> {
        engine.connect(target, &trusting(), auth)
    }

    fn direct(alias: &str) -> Target {
        Target { hops: vec![hop(alias)] }
    }

    fn exec(session: &dyn Session, command: &str) -> ExecResult {
        session.exec(command, SHORT, 1024).unwrap()
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

    #[test]
    fn a_password_login_asks_the_auth_source_and_checks_the_answer() {
        let engine = FakeEngine::new().with_login(FakeLogin::Password("hunter2".into()));
        let right = Auth { password: Some("hunter2".into()), ..Auth::default() };
        assert!(connect(&engine, &direct("web"), &right).is_ok());
        assert_eq!(*locked(&right.asked), vec!["password web".to_string()]);

        let wrong = Auth { password: Some("letmein".into()), ..Auth::default() };
        assert!(matches!(connect(&engine, &direct("web"), &wrong), Err(ConnectError::AuthFailed { tried, .. }) if tried == [AuthMethod::Password]));

        let none = Auth::default();
        assert!(matches!(connect(&engine, &direct("web"), &none), Err(ConnectError::AuthFailed { tried, .. }) if tried.is_empty()), "no password: the method is skipped");

        let by_password = Target { hops: vec![Hop::new("id-pw", "pw", "pw.example.com", 22, "deploy", AuthMethod::Password)] };
        let unknown = Policy { accepted: None, pinned: None };
        let asked = Auth { password: Some("hunter2".into()), ..Auth::default() };
        assert!(matches!(engine.connect(&by_password, &unknown, &asked), Err(ConnectError::HostKeyUnknown { .. })));
        assert_eq!(*locked(&asked.asked), vec!["password pw".to_string()], "a hop that starts with the password method is asked before its host key is looked at");
    }

    #[test]
    fn a_keyboard_interactive_login_sends_the_prompts_and_compares_the_answers() {
        let prompts = vec![Prompt { text: "Verification code: ".into(), echo: true }];
        let engine = FakeEngine::new().with_login(FakeLogin::Interactive { prompts, answers: vec!["123456".into()] });
        let right = Auth { answers: Some(vec!["123456".into()]), ..Auth::default() };
        assert!(connect(&engine, &direct("web"), &right).is_ok());
        assert_eq!(*locked(&right.asked), vec!["interactive web 1".to_string()]);
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

    #[test]
    fn a_signature_login_asks_for_the_key_of_the_hop_and_a_refusal_abandons_it() {
        let engine = FakeEngine::new().with_login(FakeLogin::Signature);
        let auth = Auth::default();
        assert!(connect(&engine, &direct("web"), &auth).is_ok());
        assert_eq!(*locked(&auth.asked), vec!["sign key-web".to_string()]);
        let locked_vault = Auth { sign_fails: true, ..Auth::default() };
        assert!(matches!(connect(&engine, &direct("web"), &locked_vault), Err(ConnectError::AuthAbandoned { .. })));
    }

    #[test]
    fn a_jump_chain_is_checked_hop_by_hop_and_each_hop_can_be_scripted() {
        let engine = FakeEngine::new().with_login_for("bastion", FakeLogin::Refuse);
        let target = Target { hops: vec![hop("bastion"), hop("db")] };
        match connect(&engine, &target, &Auth::default()) {
            Err(ConnectError::AuthFailed { hop, tried, .. }) => {
                assert_eq!(hop.alias, "bastion");
                assert_eq!(tried, target.hops[0].auth_sequence(), "a refusal has tried every method of the hop's sequence");
                assert_eq!(tried.len(), 3, "key, password, keyboard-interactive");
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

    #[test]
    fn a_scripted_connect_failure_is_returned_as_it_is() {
        let error = ConnectError::Unreachable { hop: hop("web").reference(), reason: "connection refused".into() };
        let engine = FakeEngine::new().failing_with(error.clone());
        assert_eq!(connect(&engine, &direct("web"), &Auth::default()).err(), Some(error));
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

    #[test]
    fn a_shell_prints_its_script_records_the_input_and_ends_when_closed() {
        bounded(|| {
            let engine = FakeEngine::new().with_shell_output(b"welcome\r\n").with_shell_exit(Exit::Code(7));
            let session = connect(&engine, &direct("web"), &Auth::default()).unwrap();
            let shell = session.shell(Pty { term: "xterm-256color".into(), cols: 80, rows: 24 }).unwrap();
            assert_eq!(read_some(shell.as_ref()), b"welcome\r\n");
            shell.write(b"ls\n").unwrap();
            shell.window_change(100, 30).unwrap();
            assert_eq!(shell.exited(), None);
            shell.close();
            assert_eq!(read_some(shell.as_ref()), b"", "a closed shell reads 0");
            assert_eq!(shell.exited(), Some(Exit::Code(7)));
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
}
