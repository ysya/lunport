//! A shell between the engine and a client (own-ssh spec §7.2): open it at the client's last known size and send that size again once
//! it is ready, pump its output to the client, take the client's keystrokes and resizes, and say how it ended (`exited`, after an
//! `event` that explains a lost connection or a refused shell; a lost connection is never exit status 0). When the client goes away the
//! shell and the session are closed from a plain thread, after the shell's first output or a few seconds (plan 1b R22: a shell closed
//! before its prompt can strand a process on a macOS sshd).

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

use super::auth::printable;
use super::connect::Connected;
use super::protocol::{kinds, Event, ServerMessage, DATA_CHUNK};
use crate::ssh::{DisconnectKind, DisconnectReason, Exit, Pty, Session, SessionError, ShellChannel, Target};

fn locked<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

/// How long a shell the client left is given to print something before it is closed anyway (plan 1b R22).
pub const SETTLE: Duration = Duration::from_secs(3);

/// The longest signal name that is passed on to the client: the names of RFC 4254 §6.10 have at most 6 characters, `RTMIN+31` has 8.
const SIGNAL_NAME_MAX: usize = 32;

/// What the client is told when the name of the signal that ended the shell is not one it could read.
const UNKNOWN_SIGNAL: &str = "UNKNOWN";

/// The name of the signal that ended the shell, in a form that is safe to pass on: a server names it (`Sig::Custom` carries any text it
/// sends), and a program reads it, so only upper case letters, digits, `_`, `+` and `-` pass, up to `SIGNAL_NAME_MAX` of them. Anything
/// else is `UNKNOWN`, which no signal is called, so a client that maps names to numbers finds none.
fn signal_name(name: &str) -> String {
    let safe = !name.is_empty() && name.len() <= SIGNAL_NAME_MAX && name.bytes().all(|byte| matches!(byte, b'A'..=b'Z' | b'0'..=b'9' | b'_' | b'+' | b'-'));
    if safe { name.to_string() } else { UNKNOWN_SIGNAL.to_string() }
}

/// Sends `message` to the client. Everything the relay says goes through here (the shell's own output, `ClientLink::send_data`, is the one
/// exception), and this is where the text in it is made safe to print, as `ConnectFailure::new` does for a failure: some of it was written
/// by a server (the `Display` of a protocol error can quote the bytes the peer sent, a signal has whatever name the server gave it), the
/// rest comes from the person's configuration (aliases) or from the client's request, and none of it may reach a terminal with an escape
/// sequence or a carriage return in it. A text that has no such character comes out as it went in. The `match` names every kind of
/// message on purpose: a new one has to be put in one of the arms.
pub fn tell(link: &dyn ClientLink, message: ServerMessage) -> std::io::Result<()> {
    let message = match message {
        ServerMessage::Event(Event::Error { kind, text }) => ServerMessage::Event(Event::Error { kind, text: printable(&text) }),
        ServerMessage::Event(Event::Disconnected { reason }) => ServerMessage::Event(Event::Disconnected { reason: printable(&reason) }),
        ServerMessage::Event(Event::Banner { text }) => ServerMessage::Event(Event::Banner { text: printable(&text) }),
        ServerMessage::Exited { code, signal } => ServerMessage::Exited { code, signal: signal.map(|name| signal_name(&name)) },
        // The relay asks no questions (the owner's text is made printable where it is built: `shown_prompt`), `Opened` carries the
        // broker's own number, and `Connected` carries nothing.
        message @ (ServerMessage::Opened { .. } | ServerMessage::Question(_) | ServerMessage::Event(Event::Connected)) => message,
    };
    link.send(&message)
}

/// The client end of a shell: where its output and messages go. A write that fails means the client is gone.
pub trait ClientLink: Send + Sync {
    fn send(&self, message: &ServerMessage) -> std::io::Result<()>;
    fn send_data(&self, bytes: &[u8]) -> std::io::Result<()>;
}

/// What the client's side (the thread that reads its connection) and the shell's side (the thread that pumps output) share for one
/// shell: the shell once it is open, the last size the client sent, whether the client is gone, and why the app ends the session.
pub struct ShellControl {
    shell: Mutex<Option<Arc<dyn ShellChannel>>>,
    alias: Mutex<String>,
    size: Mutex<Option<(u16, u16)>>,
    gone: AtomicBool,
    /// The shell was asked to close (once is enough).
    closed: AtomicBool,
    /// Set when the app ends the session (it is quitting): the sentence the client is told.
    ended_by_app: Mutex<Option<String>>,
    /// When the shell opened, and whether it has printed anything yet (for `settle`).
    printed: Mutex<(Option<Instant>, bool)>,
    first_output: Condvar,
    settle: Duration,
}

impl Default for ShellControl {
    fn default() -> Self {
        ShellControl::new()
    }
}

impl ShellControl {
    pub fn new() -> ShellControl {
        ShellControl::with_settle(SETTLE)
    }

    /// The same, with another settle time (tests).
    pub fn with_settle(settle: Duration) -> ShellControl {
        ShellControl {
            shell: Mutex::new(None),
            alias: Mutex::new(String::new()),
            size: Mutex::new(None),
            gone: AtomicBool::new(false),
            closed: AtomicBool::new(false),
            ended_by_app: Mutex::new(None),
            printed: Mutex::new((None, false)),
            first_output: Condvar::new(),
            settle,
        }
    }

    /// The client's terminal has this size: remembered, and sent to the shell when it is open (spec §7.2).
    pub fn resize(&self, cols: u16, rows: u16) {
        *locked(&self.size) = Some((cols, rows));
        let shell = locked(&self.shell).clone();
        if let Some(shell) = shell {
            if let Err(error) = shell.window_change(cols, rows) {
                eprintln!("[session] a window size did not reach the shell: {error}");
            }
        }
    }

    /// Keystrokes from the client. Before the shell is open there is nowhere for them to go (the CLI sends none then). A write the link
    /// did not take in time is not the end of the connection (keepalive decides that): the client is told, and the shell goes on.
    pub fn input(&self, bytes: &[u8], link: &dyn ClientLink) {
        let shell = locked(&self.shell).clone();
        let Some(shell) = shell else { return };
        match shell.write(bytes) {
            Ok(()) | Err(SessionError::Closed) => {}
            Err(SessionError::Timeout) => {
                let alias = locked(&self.alias).clone();
                let text = format!("What you typed did not reach {alias} in time: the connection is not responding.");
                let _ = tell(link, ServerMessage::Event(Event::Error { kind: kinds::INPUT.to_string(), text }));
            }
            Err(error) => eprintln!("[session] input did not reach the shell: {error}"),
        }
    }

    /// The client went away (its connection ended, or it sent `close`): the shell is closed once it has printed something or `settle`
    /// has passed since it opened, so that a shell closed right after it opened does not strand a process on the server. Blocks for at
    /// most that long; call it from a plain thread.
    pub fn owner_gone(&self) {
        self.gone.store(true, Ordering::SeqCst);
        self.close_settled();
    }

    /// The app ends the session (it is quitting): the client is told `reason`, then the shell is closed as for `owner_gone`.
    pub fn end(&self, reason: &str) {
        *locked(&self.ended_by_app) = Some(reason.to_string());
        self.close_settled();
    }

    pub fn is_gone(&self) -> bool {
        self.gone.load(Ordering::SeqCst)
    }

    fn close_settled(&self) {
        let shell = locked(&self.shell).clone();
        let Some(shell) = shell else { return };
        if shell.exited().is_some() || self.closed.load(Ordering::SeqCst) {
            return;
        }
        let mut printed = locked(&self.printed);
        while !printed.1 {
            let Some(opened) = printed.0 else { break };
            let left = (opened + self.settle).saturating_duration_since(Instant::now());
            if left.is_zero() {
                break;
            }
            printed = self.first_output.wait_timeout(printed, left).unwrap_or_else(PoisonError::into_inner).0;
        }
        drop(printed);
        self.close_now();
    }

    /// Closes the shell, once.
    fn close_now(&self) {
        let shell = locked(&self.shell).clone();
        if let Some(shell) = shell {
            if !self.closed.swap(true, Ordering::SeqCst) {
                shell.close();
            }
        }
    }

    fn opened(&self, shell: Arc<dyn ShellChannel>) {
        *locked(&self.printed) = (Some(Instant::now()), false);
        *locked(&self.shell) = Some(shell);
    }

    fn printed(&self) {
        let mut printed = locked(&self.printed);
        if !printed.1 {
            printed.1 = true;
            self.first_output.notify_all();
        }
    }
}

/// The sentence for a connection that ended (spec §11), about the hop that recorded the end; a dead keepalive says how many seconds went
/// without an answer: (`keepalive_max_missed` + 1) × `keepalive_secs` of that hop.
pub fn lost_sentence(reason: &DisconnectReason, target: &Target) -> String {
    let alias = &reason.hop.alias;
    match reason.kind {
        DisconnectKind::KeepaliveTimeout => {
            let hop = target.hops.iter().find(|hop| hop.id == reason.hop.id);
            let seconds = hop.map(|hop| hop.keepalive_every.as_secs().saturating_mul(u64::from(hop.keepalive_max_missed) + 1)).unwrap_or(0);
            format!("Connection to {alias} lost (no response for {seconds} seconds).")
        }
        DisconnectKind::ClosedByPeer => format!("Connection to {alias} closed by the server."),
        DisconnectKind::ConnectionLost => format!("Connection to {alias} lost ({}).", reason.detail),
        DisconnectKind::ClosedByUs => format!("Connection to {alias} closed."),
        DisconnectKind::Other => format!("Connection to {alias} ended ({}).", reason.detail),
    }
}

/// What the client is told when its shell has ended: an event that explains an end without a status, then `exited`.
fn ending(exit: Option<Exit>, session: &dyn Session, target: &Target, alias: &str) -> (Option<Event>, ServerMessage) {
    let no_status = ServerMessage::Exited { code: None, signal: None };
    match exit {
        Some(Exit::Code(code)) => (None, ServerMessage::Exited { code: Some(code), signal: None }),
        Some(Exit::Signal(signal)) => (None, ServerMessage::Exited { code: None, signal: Some(signal) }),
        Some(Exit::Refused(why)) => {
            (Some(Event::Error { kind: kinds::SHELL.to_string(), text: format!("SSHelter could not open a shell on {alias}: {why}.") }), no_status)
        }
        Some(Exit::Disconnected) | None => {
            let reason = if session.is_alive() {
                format!("The shell on {alias} ended without an exit status.")
            } else {
                match session.disconnect_reason() {
                    Some(reason) => lost_sentence(&reason, target),
                    None => format!("Connection to {alias} lost."),
                }
            };
            (Some(Event::Disconnected { reason }), no_status)
        }
    }
}

/// Runs the client's shell on the session `connected` holds, then closes the session; returns when both are done. Call it from a plain
/// thread: the engine's calls block. `pty` is what the client asked for; the size is the last one it sent, if it sent one since.
pub fn run_shell(connected: Connected, pty: Pty, link: &dyn ClientLink, control: &ShellControl, session_id: &str) {
    let Connected { session, target } = connected;
    let alias = target.hops.last().map(|hop| hop.alias.clone()).unwrap_or_default();
    *locked(&control.alias) = alias.clone();
    let (cols, rows) = locked(&control.size).unwrap_or((pty.cols, pty.rows));
    let shell: Arc<dyn ShellChannel> = match session.shell(Pty { cols, rows, ..pty }) {
        Ok(shell) => Arc::from(shell),
        Err(error) => {
            let text = format!("SSHelter could not open a shell on {alias}: {}.", error.to_string().trim_end_matches('.'));
            let _ = tell(link, ServerMessage::Event(Event::Error { kind: kinds::SHELL.to_string(), text }));
            let _ = tell(link, ServerMessage::Exited { code: None, signal: None });
            session.close();
            return;
        }
    };
    control.opened(Arc::clone(&shell));
    if tell(link, ServerMessage::Opened { session_id: session_id.to_string() }).is_err() {
        control.gone.store(true, Ordering::SeqCst);
    }
    // The size the client sent while the shell was being opened, or the one it was opened with: sent once more now that the PTY exists
    // (spec §7.2: a resize before the shell is ready is ignored by the server).
    let (cols, rows) = locked(&control.size).unwrap_or((cols, rows));
    if let Err(error) = shell.window_change(cols, rows) {
        eprintln!("[session] the window size did not reach the new shell: {error}");
    }
    if control.is_gone() {
        control.close_settled();
    }
    let mut buf = vec![0u8; DATA_CHUNK];
    loop {
        let count = match shell.read(&mut buf) {
            Ok(0) | Err(_) => break,
            Ok(count) => count,
        };
        control.printed();
        if !control.is_gone() && link.send_data(&buf[..count]).is_err() {
            // The client is gone (its terminal has printed, so the shell is settled): close it, and drain it until it ends.
            control.gone.store(true, Ordering::SeqCst);
            control.close_now();
        }
    }
    if !control.is_gone() {
        let ended_by_app = locked(&control.ended_by_app).clone();
        let (event, exited) = match ended_by_app {
            Some(reason) => (Some(Event::Disconnected { reason }), ServerMessage::Exited { code: None, signal: None }),
            None => ending(shell.exited(), session.as_ref(), &target, &alias),
        };
        if let Some(event) = event {
            let _ = tell(link, ServerMessage::Event(event));
        }
        let _ = tell(link, exited);
    }
    session.close();
}

#[cfg(test)]
mod tests {
    use std::time::Instant;

    use super::*;
    use crate::session::testing::locked;
    use crate::ssh::fake::{FakeEngine, FakeEvent};
    use crate::ssh::{AuthMethod, DisconnectKind, DisconnectReason, Hop, SessionError, SshEngine};

    /// The client side, recorded.
    #[derive(Default)]
    struct Recorder {
        sent: Mutex<Vec<Sent>>,
    }

    #[derive(Clone, Debug, PartialEq, Eq)]
    enum Sent {
        Message(ServerMessage),
        Data(Vec<u8>),
    }

    impl ClientLink for Recorder {
        fn send(&self, message: &ServerMessage) -> std::io::Result<()> {
            locked(&self.sent).push(Sent::Message(message.clone()));
            Ok(())
        }
        fn send_data(&self, bytes: &[u8]) -> std::io::Result<()> {
            locked(&self.sent).push(Sent::Data(bytes.to_vec()));
            Ok(())
        }
    }

    impl Recorder {
        fn sent(&self) -> Vec<Sent> {
            locked(&self.sent).clone()
        }

        /// The output, joined, and the control messages, in order.
        fn split(&self) -> (Vec<u8>, Vec<ServerMessage>) {
            let mut output = Vec::new();
            let mut messages = Vec::new();
            for sent in self.sent() {
                match sent {
                    Sent::Data(bytes) => output.extend(bytes),
                    Sent::Message(message) => messages.push(message),
                }
            }
            (output, messages)
        }
    }

    fn target() -> Target {
        Target { hops: vec![Hop::new("id-web", "web", "web.example.com", 22, "deploy", AuthMethod::Password)] }
    }

    fn pty() -> Pty {
        Pty { term: "xterm-256color".into(), cols: 80, rows: 24 }
    }

    /// Runs the shell on a thread of its own, as the broker does, with a short settle time for the tests.
    struct Running {
        engine: Arc<FakeEngine>,
        link: Arc<Recorder>,
        control: Arc<ShellControl>,
        pump: Option<std::thread::JoinHandle<()>>,
    }

    fn start(engine: FakeEngine, control: ShellControl) -> Running {
        let engine = Arc::new(engine);
        let session = engine.connect(&target(), &*crate::ssh::testing::doubles::TestPolicy::trusting(), &crate::ssh::testing::doubles::VaultAuth::new()).unwrap();
        let (link, control) = (Arc::new(Recorder::default()), Arc::new(control));
        let pump = {
            let (link, control) = (Arc::clone(&link), Arc::clone(&control));
            std::thread::spawn(move || run_shell(Connected { session, target: target() }, pty(), link.as_ref(), &control, "7"))
        };
        Running { engine, link, control, pump: Some(pump) }
    }

    impl Running {
        fn wait_for_shell(&self) -> crate::ssh::fake::FakeShell {
            crate::ssh::testing::eventually("the shell to open", 5, || !self.engine.shells().is_empty());
            self.engine.shells().remove(0)
        }

        /// Waits for the pump to finish (the shell ended and the session is closed).
        fn finish(&mut self) {
            let pump = self.pump.take().expect("running");
            let deadline = Instant::now() + Duration::from_secs(10);
            while !pump.is_finished() {
                assert!(Instant::now() < deadline, "the shell's thread did not finish");
                std::thread::sleep(Duration::from_millis(10));
            }
            pump.join().unwrap();
        }
    }

    #[test]
    fn a_shell_opens_at_the_last_size_sends_it_again_and_relays_output_until_it_exits() {
        let control = ShellControl::new();
        control.resize(100, 30);
        let mut running = start(FakeEngine::new(), control);
        let remote = running.wait_for_shell();
        remote.print(b"$ ");
        remote.print(b"bye\r\n");
        remote.end(Exit::Code(3));
        running.finish();
        let (output, messages) = running.link.split();
        assert_eq!(output, b"$ bye\r\n");
        assert_eq!(messages, [ServerMessage::Opened { session_id: "7".into() }, ServerMessage::Exited { code: Some(3), signal: None }]);
        let events = running.engine.events();
        assert!(events.contains(&FakeEvent::ShellOpened { term: "xterm-256color".into(), cols: 100, rows: 30 }), "opened at the size the client sent last: {events:?}");
        assert!(events.contains(&FakeEvent::WindowChange { cols: 100, rows: 30 }), "and that size sent again once the shell is ready (spec §7.2)");
        assert_eq!(events.last(), Some(&FakeEvent::Closed), "the session is closed after its shell");
    }

    #[test]
    fn keystrokes_and_resizes_reach_the_shell_and_input_that_times_out_is_reported_without_ending_it() {
        let mut running = start(FakeEngine::new().with_write_errors(vec![SessionError::Timeout]), ShellControl::new());
        let remote = running.wait_for_shell();
        running.control.input(b"lost", running.link.as_ref());
        running.control.input(b"ls\r", running.link.as_ref());
        running.control.resize(120, 40);
        remote.end(Exit::Code(0));
        running.finish();
        let events = running.engine.events();
        assert!(events.contains(&FakeEvent::ShellInput(b"ls\r".to_vec())) && events.contains(&FakeEvent::WindowChange { cols: 120, rows: 40 }), "{events:?}");
        let (_, messages) = running.link.split();
        assert_eq!(
            messages[1],
            ServerMessage::Event(Event::Error { kind: kinds::INPUT.into(), text: "What you typed did not reach web in time: the connection is not responding.".into() })
        );
        assert_eq!(messages.last(), Some(&ServerMessage::Exited { code: Some(0), signal: None }), "the shell went on and ended normally");
    }

    #[test]
    fn a_shell_killed_by_a_signal_says_which() {
        let mut running = start(FakeEngine::new(), ShellControl::new());
        running.wait_for_shell().end(Exit::Signal("KILL".into()));
        running.finish();
        assert_eq!(running.link.split().1.last(), Some(&ServerMessage::Exited { code: None, signal: Some("KILL".into()) }));
    }

    /// A lost connection is a disconnect with its reason, never exit status 0 (spec §7.1, §11).
    #[test]
    fn a_lost_connection_is_reported_with_its_reason_and_no_exit_status() {
        let mut running = start(FakeEngine::new(), ShellControl::new());
        running.wait_for_shell().print(b"half a line");
        let hop = target().hops[0].reference();
        running.engine.disconnect_now(DisconnectReason { hop, kind: DisconnectKind::ConnectionLost, detail: "connection reset by peer".into() });
        running.finish();
        let (output, messages) = running.link.split();
        assert_eq!(output, b"half a line");
        assert_eq!(
            &messages[1..],
            [
                ServerMessage::Event(Event::Disconnected { reason: "Connection to web lost (connection reset by peer).".into() }),
                ServerMessage::Exited { code: None, signal: None },
            ]
        );
    }

    /// Spec §11: `{n}` = (`keepalive_max_missed` + 1) × `keepalive_secs` of the hop that went silent.
    #[test]
    fn a_link_that_stopped_answering_keepalives_says_for_how_long() {
        let reason = |kind, detail: &str| DisconnectReason { hop: target().hops[0].reference(), kind, detail: detail.into() };
        let hops = target();
        assert_eq!(lost_sentence(&reason(DisconnectKind::KeepaliveTimeout, "silent"), &hops), "Connection to web lost (no response for 120 seconds).");
        assert_eq!(lost_sentence(&reason(DisconnectKind::ClosedByPeer, "the server closed the connection: bye"), &hops), "Connection to web closed by the server.");
        assert_eq!(lost_sentence(&reason(DisconnectKind::ConnectionLost, "broken pipe"), &hops), "Connection to web lost (broken pipe).");
        assert_eq!(lost_sentence(&reason(DisconnectKind::ClosedByUs, "closed"), &hops), "Connection to web closed.");
        assert_eq!(lost_sentence(&reason(DisconnectKind::Other, "protocol error"), &hops), "Connection to web ended (protocol error).");
        let mut quick = target();
        quick.hops[0].keepalive_every = Duration::from_secs(10);
        quick.hops[0].keepalive_max_missed = 2;
        assert_eq!(lost_sentence(&reason(DisconnectKind::KeepaliveTimeout, "silent"), &quick), "Connection to web lost (no response for 30 seconds).");
    }

    #[test]
    fn a_refused_terminal_or_a_shell_that_cannot_open_is_an_error_with_the_reason() {
        let refused = FakeEngine::new().with_shell_exit(Exit::Refused("the server refused to allocate a terminal (PTY)".into())).with_shell_ending_at_once();
        let mut running = start(refused, ShellControl::new());
        running.finish();
        assert_eq!(
            &running.link.split().1[1..],
            [
                ServerMessage::Event(Event::Error { kind: kinds::SHELL.into(), text: "SSHelter could not open a shell on web: the server refused to allocate a terminal (PTY).".into() }),
                ServerMessage::Exited { code: None, signal: None },
            ]
        );

        let mut failing = start(FakeEngine::new().with_shell_error(SessionError::Channel("channel open refused".into())), ShellControl::new());
        failing.finish();
        assert_eq!(
            failing.link.split().1,
            [
                ServerMessage::Event(Event::Error { kind: kinds::SHELL.into(), text: "SSHelter could not open a shell on web: SSH error: channel open refused.".into() }),
                ServerMessage::Exited { code: None, signal: None },
            ]
        );
    }

    /// Plan 1b R22: the client left right after the shell opened; the shell is closed once it has printed something, not before.
    #[test]
    fn when_the_client_goes_away_the_shell_is_closed_after_its_first_output_and_nothing_more_is_sent() {
        let mut running = start(FakeEngine::new(), ShellControl::with_settle(Duration::from_secs(5)));
        let remote = running.wait_for_shell();
        let started = Instant::now();
        let leaving = {
            let control = Arc::clone(&running.control);
            std::thread::spawn(move || control.owner_gone())
        };
        std::thread::sleep(Duration::from_millis(300));
        assert!(!running.engine.events().contains(&FakeEvent::ShellClosed), "not closed before the shell printed anything");
        remote.print(b"$ ");
        leaving.join().unwrap();
        assert!(started.elapsed() < Duration::from_secs(3), "closed soon after the first output: {:?}", started.elapsed());
        running.finish();
        let events = running.engine.events();
        assert!(events.contains(&FakeEvent::ShellClosed) && events.last() == Some(&FakeEvent::Closed), "{events:?}");
        assert_eq!(running.link.split().1, [ServerMessage::Opened { session_id: "7".into() }], "the client is gone: nothing more is sent to it");
    }

    #[test]
    fn a_shell_that_never_prints_is_closed_once_the_settle_time_has_passed() {
        let mut running = start(FakeEngine::new(), ShellControl::with_settle(Duration::from_millis(300)));
        running.wait_for_shell();
        let started = Instant::now();
        running.control.owner_gone();
        assert!(started.elapsed() >= Duration::from_millis(250), "it waited for the settle time: {:?}", started.elapsed());
        running.finish();
        assert!(running.engine.events().contains(&FakeEvent::ShellClosed));
    }

    #[test]
    fn quitting_the_app_ends_the_shell_and_tells_the_client_why() {
        let mut running = start(FakeEngine::new(), ShellControl::with_settle(Duration::from_millis(100)));
        running.wait_for_shell().print(b"$ ");
        running.control.end("SSHelter quit, so the connection to web was closed.");
        running.finish();
        assert_eq!(
            &running.link.split().1[1..],
            [
                ServerMessage::Event(Event::Disconnected { reason: "SSHelter quit, so the connection to web was closed.".into() }),
                ServerMessage::Exited { code: None, signal: None },
            ]
        );
        assert_eq!(running.engine.events().last(), Some(&FakeEvent::Closed));
    }

    /// What a client is shown outside the shell's own output may carry bytes a server chose (an error's text quotes the peer's bytes, a
    /// signal has whatever name the server gave it): none of it reaches the terminal as an escape sequence (spec §7.1's `printable` rule).
    #[test]
    fn every_text_the_relay_frames_is_printable_wherever_it_came_from() {
        let escape = "\u{1b}[2J\u{1b}]0;x\u{7}";

        // A lost connection: the detail of the engine's error can quote the peer's bytes (`invalid label: '…'`).
        let mut lost = start(FakeEngine::new(), ShellControl::new());
        lost.wait_for_shell().print(b"$ ");
        let hop = target().hops[0].reference();
        lost.engine.disconnect_now(DisconnectReason { hop, kind: DisconnectKind::Other, detail: format!("invalid label: '{escape}'") });
        lost.finish();
        assert_eq!(
            &lost.link.split().1[1..],
            [
                ServerMessage::Event(Event::Disconnected { reason: "Connection to web ended (invalid label: '?[2J?]0;x?').".into() }),
                ServerMessage::Exited { code: None, signal: None },
            ]
        );

        // A shell killed by a signal the server named as it pleased.
        let mut killed = start(FakeEngine::new(), ShellControl::new());
        killed.wait_for_shell().end(Exit::Signal("\u{1b}[2J".into()));
        killed.finish();
        let exited = killed.link.split().1.pop();
        assert_eq!(exited, Some(ServerMessage::Exited { code: None, signal: Some("UNKNOWN".into()) }), "{exited:?}");

        // A shell the engine could not open: its error text.
        let mut failing = start(FakeEngine::new().with_shell_error(SessionError::Channel(format!("refused {escape}"))), ShellControl::new());
        failing.finish();
        assert_eq!(
            failing.link.split().1[0],
            ServerMessage::Event(Event::Error { kind: kinds::SHELL.into(), text: "SSHelter could not open a shell on web: SSH error: refused ?[2J?]0;x?.".into() })
        );

        // A refused terminal or shell: the reason the engine gives.
        let refused = FakeEngine::new().with_shell_exit(Exit::Refused(format!("refused {escape}"))).with_shell_ending_at_once();
        let mut refusing = start(refused, ShellControl::new());
        refusing.finish();
        assert_eq!(
            refusing.link.split().1[1],
            ServerMessage::Event(Event::Error { kind: kinds::SHELL.into(), text: "SSHelter could not open a shell on web: refused ?[2J?]0;x?.".into() })
        );

        // The sentence for the app quitting carries the alias of the host, which the person's configuration wrote.
        let mut quitting = start(FakeEngine::new(), ShellControl::with_settle(Duration::from_millis(100)));
        quitting.wait_for_shell().print(b"$ ");
        quitting.control.end(&format!("SSHelter quit, so the connection to {escape} was closed."));
        quitting.finish();
        assert_eq!(
            quitting.link.split().1[1],
            ServerMessage::Event(Event::Disconnected { reason: "SSHelter quit, so the connection to ?[2J?]0;x? was closed.".into() })
        );
    }

    /// The names SSH gives signals (RFC 4254 §6.10, and the real-time ones) are kept; anything else a server might send is `UNKNOWN`.
    #[test]
    fn a_signal_name_passes_only_in_the_form_signals_are_named() {
        for name in ["KILL", "TERM", "USR1", "RTMIN+3", "RTMAX-1", "ABRT", "X_Y"] {
            assert_eq!(signal_name(name), name);
        }
        let long = "A".repeat(SIGNAL_NAME_MAX + 1);
        for name in ["", "kill", "SIGKILL@example.com", "K ILL", "KILL\n", "\u{1b}[2J", "KİLL", long.as_str()] {
            assert_eq!(signal_name(name), "UNKNOWN", "{name:?}");
        }
        assert_eq!(signal_name(&"A".repeat(SIGNAL_NAME_MAX)), "A".repeat(SIGNAL_NAME_MAX), "up to the limit it passes");
    }
}
