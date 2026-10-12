//! A shell between the engine and a client (own-ssh spec §7.2): open it at the client's last known size and send that size again once
//! it is ready, pump its output to the client, take the client's keystrokes and resizes, and say how it ended (`exited`, after an
//! `event` that explains a lost connection or a refused shell; a lost connection is never exit status 0). When the client goes away the
//! shell and the session are closed from a plain thread, after the shell's first output or a few seconds (plan 1b R22: a shell closed
//! before its prompt can strand a process on a macOS sshd). The app ends a session when it quits, and that can happen at any step, the
//! opening of the shell included: `ShellControl::end` leaves the reason, and the step the session is at looks for it, as it does for a
//! client that has gone away.

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

/// The most characters of the text of an error or of a disconnect that a client is sent. A server chooses some of that text (an error's
/// `Display` quotes the bytes the peer sent) and can make it larger than a frame, which holds 1 MiB: an event that does not fit is not
/// written, and the client would be left with the `exited` that follows and no reason. A sentence is a few hundred characters.
pub const TEXT_MAX_CHARS: usize = 512;

/// `text` cut to `TEXT_MAX_CHARS` characters, on a character boundary, with `…` after what is left when it was longer.
fn shortened(mut text: String) -> String {
    if let Some((end, _)) = text.char_indices().nth(TEXT_MAX_CHARS) {
        text.truncate(end);
        text.push('…');
    }
    text
}

/// The name of the signal that ended the shell, in a form that is safe to pass on: a server names it (`Sig::Custom` carries any text it
/// sends), and a program reads it, so only upper case letters, digits, `_`, `+` and `-` pass, up to `SIGNAL_NAME_MAX` of them. Anything
/// else is `UNKNOWN`, which no signal is called, so a client that maps names to numbers finds none.
fn signal_name(name: &str) -> String {
    let safe = !name.is_empty() && name.len() <= SIGNAL_NAME_MAX && name.bytes().all(|byte| matches!(byte, b'A'..=b'Z' | b'0'..=b'9' | b'_' | b'+' | b'-'));
    if safe { name.to_string() } else { UNKNOWN_SIGNAL.to_string() }
}

/// `message` as it is sent to the client. Everything the relay says goes through here (the shell's own output, `ClientLink::send_data`,
/// is the one exception), and this is where the text in it is made safe to print, as `ConnectFailure::new` does for a failure: some of
/// it was written by a server (the `Display` of a protocol error can quote the bytes the peer sent, a signal has whatever name the
/// server gave it), the rest comes from the person's configuration (aliases) or from the client's request, and none of it may reach a
/// terminal with an escape sequence or a carriage return in it, and none of it may be larger than a frame. A text that has no such
/// character and is short comes out as it went in. The text of an error or of a disconnect is cut to `TEXT_MAX_CHARS` after it is made
/// printable; a banner is not, because it is long by nature (the engine keeps at most 64 KiB of it, which fits a frame). The `match`
/// names every kind of message on purpose: a new one has to be put in one of the arms.
fn made_safe(message: ServerMessage) -> ServerMessage {
    match message {
        ServerMessage::Event(Event::Error { kind, text }) => ServerMessage::Event(Event::Error { kind, text: shortened(printable(&text)) }),
        ServerMessage::Event(Event::Disconnected { reason }) => ServerMessage::Event(Event::Disconnected { reason: shortened(printable(&reason)) }),
        ServerMessage::Event(Event::Banner { text }) => ServerMessage::Event(Event::Banner { text: printable(&text) }),
        ServerMessage::Exited { code, signal } => ServerMessage::Exited { code, signal: signal.map(|name| signal_name(&name)) },
        // The relay asks no questions (the owner's text is made printable where it is built: `shown_prompt`), `Opened` carries the
        // broker's own number, and `Connected` carries nothing.
        message @ (ServerMessage::Opened { .. } | ServerMessage::Question(_) | ServerMessage::Event(Event::Connected)) => message,
    }
}

/// Sends `message` to the client, made safe (`made_safe`).
pub fn tell(link: &dyn ClientLink, message: ServerMessage) -> std::io::Result<()> {
    tell_all(link, vec![message])
}

/// Sends `messages` to the client, each one made safe (`made_safe`), in order and as one piece (`ClientLink::send_all`): what ends a
/// session is an explanation and then `exited`, and nothing else may be written between them.
pub fn tell_all(link: &dyn ClientLink, messages: Vec<ServerMessage>) -> std::io::Result<()> {
    let messages: Vec<ServerMessage> = messages.into_iter().map(made_safe).collect();
    link.send_all(&messages)
}

/// The client end of a shell: where its output and messages go. A write that fails means the client is gone.
pub trait ClientLink: Send + Sync {
    fn send(&self, message: &ServerMessage) -> std::io::Result<()>;

    /// Sends `messages` one after the other with nothing else written in between: what ends a session (an explanation, then `exited`) is
    /// said as one piece, or a frame of another thread could come between the two. A link that several threads write to holds its writer
    /// for the whole sequence; this default, for a link only one thread writes to, tries every message and gives the first error.
    fn send_all(&self, messages: &[ServerMessage]) -> std::io::Result<()> {
        let mut result = Ok(());
        for message in messages {
            let sent = self.send(message);
            if result.is_ok() {
                result = sent;
            }
        }
        result
    }

    fn send_data(&self, bytes: &[u8]) -> std::io::Result<()>;
}

/// Why a shell is not wanted (any more), as `ShellControl::over` says it.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Over {
    /// The client went away: it is told nothing.
    Gone,
    /// The app ends the session (it is quitting): the client is told this sentence.
    Quit(String),
}

/// Where a shell is in its life, for the wait that comes before closing it (`ShellControl::close_settled`).
#[derive(Default)]
struct Life {
    /// When the shell opened; the settle time counts from then.
    opened_at: Option<Instant>,
    /// It has printed something.
    printed: bool,
    /// It has ended and its output was read to the end: there is nothing left to close.
    ended: bool,
}

/// What the client's side (the thread that reads its connection) and the shell's side (the thread that pumps output) share for one
/// shell: the shell once it is open, the last size the client sent, whether the client is gone, and why the app ends the session.
pub struct ShellControl {
    shell: Mutex<Option<Arc<dyn ShellChannel>>>,
    alias: Mutex<String>,
    /// The last size the client sent. It is held while a size is sent to the shell (`resize`, `send_size`), so that two sizes reach the
    /// shell in the order they were set, and the last one sent is the last one set.
    size: Mutex<Option<(u16, u16)>>,
    gone: AtomicBool,
    /// The shell was asked to close (once is enough).
    closed: AtomicBool,
    /// Set when the app ends the session (it is quitting): the sentence the client is told.
    ended_by_app: Mutex<Option<String>>,
    life: Mutex<Life>,
    /// Notified when `life` changes: the shell printed something, or ended.
    life_changed: Condvar,
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
            life: Mutex::new(Life::default()),
            life_changed: Condvar::new(),
            settle,
        }
    }

    /// The client's terminal has this size: remembered, and sent to the shell when it is open (spec §7.2). Sent under the lock of the
    /// remembered size, so that a size cannot overtake a newer one on its way to the shell (`send_size` does the same).
    pub fn resize(&self, cols: u16, rows: u16) {
        let mut size = locked(&self.size);
        *size = Some((cols, rows));
        let shell = locked(&self.shell).clone();
        if let Some(shell) = shell {
            if let Err(error) = shell.window_change(cols, rows) {
                eprintln!("[session] a window size did not reach the shell: {error}");
            }
        }
        drop(size);
    }

    /// Sends the shell the size the client sent last, or `opened_with` when it sent none: once the PTY exists, because a resize sent
    /// before that is ignored by the server (spec §7.2).
    fn send_size(&self, shell: &dyn ShellChannel, opened_with: (u16, u16)) {
        let size = locked(&self.size);
        let (cols, rows) = size.unwrap_or(opened_with);
        if let Err(error) = shell.window_change(cols, rows) {
            eprintln!("[session] the window size did not reach the new shell: {error}");
        }
        drop(size);
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
    /// most that long; call it from a plain thread. A shell that is not open yet is not opened (`run_shell` looks before it opens it),
    /// and one that is being opened is closed when the engine has opened it.
    pub fn owner_gone(&self) {
        self.gone.store(true, Ordering::SeqCst);
        self.close_settled();
    }

    /// The app ends the session (it is quitting), whatever it is doing: the client is told `reason`, then the shell is closed as for
    /// `owner_gone`. Before the shell is open the reason is left for `run_shell`, which opens none, or closes the one the engine was
    /// still opening. A shell that ended by itself before it was closed reports its own end, not this reason. Blocks for at most the
    /// settle time; call it from a plain thread.
    pub fn end(&self, reason: &str) {
        *locked(&self.ended_by_app) = Some(reason.to_string());
        self.close_settled();
    }

    pub fn is_gone(&self) -> bool {
        self.gone.load(Ordering::SeqCst)
    }

    /// The app's reason for ending the session, once `end` has left one.
    pub(super) fn quit_reason(&self) -> Option<String> {
        locked(&self.ended_by_app).clone()
    }

    /// Why no shell is wanted any more, if it is not: a client that left is told nothing, so it wins over the app quitting.
    fn over(&self) -> Option<Over> {
        if self.is_gone() {
            return Some(Over::Gone);
        }
        self.quit_reason().map(Over::Quit)
    }

    /// Closes the shell once it has printed something, or `settle` after it opened, or never when it has ended by itself. A shell that
    /// is not open yet is left alone: `run_shell` looks at `over` once it is.
    fn close_settled(&self) {
        let shell = locked(&self.shell).clone();
        let Some(shell) = shell else { return };
        if shell.exited().is_some() || self.closed.load(Ordering::SeqCst) {
            return;
        }
        let mut life = locked(&self.life);
        while !life.printed && !life.ended {
            let Some(opened) = life.opened_at else { break };
            let left = (opened + self.settle).saturating_duration_since(Instant::now());
            if left.is_zero() {
                break;
            }
            life = self.life_changed.wait_timeout(life, left).unwrap_or_else(PoisonError::into_inner).0;
        }
        let ended = life.ended;
        drop(life);
        if !ended {
            self.close_now();
        }
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
        locked(&self.life).opened_at = Some(Instant::now());
        *locked(&self.shell) = Some(shell);
    }

    fn printed(&self) {
        let mut life = locked(&self.life);
        if !life.printed {
            life.printed = true;
            self.life_changed.notify_all();
        }
    }

    /// The shell's output was read to the end: a wait to close it need not go on.
    fn ended(&self) {
        locked(&self.life).ended = true;
        self.life_changed.notify_all();
    }
}

/// The sentence for a connection that ended (spec §11), about the hop that recorded the end; a dead keepalive says how many seconds went
/// without an answer: (`keepalive_max_missed` + 1) × `keepalive_secs` of that hop. The detail is the engine's text, which can quote what
/// a server sent: it is made printable when it is sent (`tell`).
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

/// How the end of a connection is told: spec §11's sentence for the hop that recorded it.
fn connection_lost(session: &dyn Session, target: &Target, alias: &str) -> String {
    match session.disconnect_reason() {
        Some(reason) => lost_sentence(&reason, target),
        None => format!("Connection to {alias} lost."),
    }
}

/// What the client is told when its shell has ended: an event that explains an end without a status, then `exited`. `quit` is the app's
/// reason when it ended the session: it explains a shell that ended because it was closed, but a shell that ended on its own before it
/// was closed (its exit code, its signal, a refused terminal) reports that.
fn ending(exit: Option<Exit>, quit: Option<String>, session: &dyn Session, target: &Target, alias: &str) -> Vec<ServerMessage> {
    let no_status = ServerMessage::Exited { code: None, signal: None };
    let explained = |event: Event| vec![ServerMessage::Event(event), no_status.clone()];
    match exit {
        Some(Exit::Code(code)) => vec![ServerMessage::Exited { code: Some(code), signal: None }],
        Some(Exit::Signal(signal)) => vec![ServerMessage::Exited { code: None, signal: Some(signal) }],
        Some(Exit::Refused(why)) => explained(Event::Error { kind: kinds::SHELL.to_string(), text: format!("SSHelter could not open a shell on {alias}: {why}.") }),
        Some(Exit::Disconnected) | None => {
            let reason = match quit {
                Some(reason) => reason,
                None if session.is_alive() => format!("The shell on {alias} ended without an exit status."),
                None => connection_lost(session, target, alias),
            };
            explained(Event::Disconnected { reason })
        }
    }
}

/// What the client is told when the engine could not open the shell. A connection that is gone is told as it is everywhere
/// (`connection_lost`); otherwise the reason is a clause of the sentence, so it does not start with a capital.
fn no_shell(error: &SessionError, session: &dyn Session, target: &Target, alias: &str) -> Vec<ServerMessage> {
    let no_status = ServerMessage::Exited { code: None, signal: None };
    if !session.is_alive() {
        return vec![ServerMessage::Event(Event::Disconnected { reason: connection_lost(session, target, alias) }), no_status];
    }
    let why = match error {
        SessionError::Closed => "the connection is closed".to_string(),
        SessionError::Timeout => "the connection did not take the request in time".to_string(),
        SessionError::Channel(text) => format!("SSH error: {text}"),
    };
    let text = format!("SSHelter could not open a shell on {alias}: {}.", why.trim_end_matches('.'));
    vec![ServerMessage::Event(Event::Error { kind: kinds::SHELL.to_string(), text }), no_status]
}

/// What the client is told when the session is over before it had a shell: nothing when it has gone away, the app's reason when the app
/// ended the session.
fn say_over(link: &dyn ClientLink, over: Over) {
    if let Over::Quit(reason) = over {
        let _ = tell_all(link, vec![ServerMessage::Event(Event::Disconnected { reason }), ServerMessage::Exited { code: None, signal: None }]);
    }
}

/// Runs the client's shell on the session `connected` holds, then closes the session; returns when both are done. Call it from a plain
/// thread: the engine's calls block. `pty` is what the client asked for; the size is the last one it sent, if it sent one since.
///
/// The client may leave, or the app may end the session, at any step. Before the shell is opened that is looked at, and then no shell is
/// opened. While the engine opens it, nothing can be done but wait for it, and a shell that opens for nobody is not announced to the
/// client and is closed after its first output, like one the client leaves behind.
pub fn run_shell(connected: Connected, pty: Pty, link: &dyn ClientLink, control: &ShellControl, session_id: &str) {
    let Connected { session, target } = connected;
    let alias = target.hops.last().map(|hop| hop.alias.clone()).unwrap_or_default();
    *locked(&control.alias) = alias.clone();
    if let Some(over) = control.over() {
        say_over(link, over);
        session.close();
        return;
    }
    let (cols, rows) = locked(&control.size).unwrap_or((pty.cols, pty.rows));
    let shell: Arc<dyn ShellChannel> = match session.shell(Pty { cols, rows, ..pty }) {
        Ok(shell) => Arc::from(shell),
        Err(error) => {
            match control.over() {
                Some(over) => say_over(link, over),
                None => {
                    let _ = tell_all(link, no_shell(&error, session.as_ref(), &target, &alias));
                }
            }
            session.close();
            return;
        }
    };
    control.opened(Arc::clone(&shell));
    // Looked at only now that the shell is there for `owner_gone` and `end` to see: one that came earlier found nothing to close and left
    // it to this thread, and one that comes later closes the shell itself.
    let mut forwarding = control.over().is_none();
    if forwarding && tell(link, ServerMessage::Opened { session_id: session_id.to_string() }).is_err() {
        control.gone.store(true, Ordering::SeqCst);
        forwarding = false;
    }
    if forwarding {
        // The size the client sent while the shell was being opened, or the one it was opened with: sent once more now that the PTY exists
        // (spec §7.2: a resize before the shell is ready is ignored by the server).
        control.send_size(shell.as_ref(), (cols, rows));
    }
    std::thread::scope(|scope| {
        if !forwarding {
            // Nobody is waiting for this shell. It is closed once it has printed something (or the settle time has passed), by a thread
            // of its own: this one reads what the shell prints, which is how the wait learns that it has.
            scope.spawn(|| control.close_settled());
        }
        let mut buf = vec![0u8; DATA_CHUNK];
        loop {
            let count = match shell.read(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(count) => count,
            };
            control.printed();
            if forwarding && !control.is_gone() && link.send_data(&buf[..count]).is_err() {
                // The client is gone (its terminal has printed, so the shell is settled): close it, and drain it until it ends.
                control.gone.store(true, Ordering::SeqCst);
                forwarding = false;
                control.close_now();
            }
        }
        control.ended();
    });
    if !control.is_gone() {
        let _ = tell_all(link, ending(shell.exited(), control.quit_reason(), session.as_ref(), &target, &alias));
    }
    session.close();
}

#[cfg(test)]
mod tests {
    use std::time::Instant;

    use super::*;
    use crate::session::testing::{locked, Gate, GatedEngine};
    use crate::ssh::fake::{FakeEngine, FakeEvent};
    use crate::ssh::{AuthMethod, DisconnectKind, DisconnectReason, Hop, SessionError, SshEngine};

    /// The client side, recorded. It can be made to go away part of the way through, as a client does: output frames after the first
    /// `data_limit` of them, and `Opened`, are then refused (and not recorded).
    #[derive(Default)]
    struct Recorder {
        sent: Mutex<Vec<Sent>>,
        /// How many messages each call of `send_all` was handed (`send` is called through it: one call, whatever the count).
        calls: Mutex<Vec<usize>>,
        data_limit: Option<usize>,
        refuses_opened: bool,
    }

    #[derive(Clone, Debug, PartialEq, Eq)]
    enum Sent {
        Message(ServerMessage),
        Data(Vec<u8>),
    }

    fn broken_pipe() -> std::io::Error {
        std::io::Error::new(std::io::ErrorKind::BrokenPipe, "the client is gone")
    }

    impl ClientLink for Recorder {
        fn send(&self, message: &ServerMessage) -> std::io::Result<()> {
            if self.refuses_opened && matches!(message, ServerMessage::Opened { .. }) {
                return Err(broken_pipe());
            }
            locked(&self.sent).push(Sent::Message(message.clone()));
            Ok(())
        }
        fn send_all(&self, messages: &[ServerMessage]) -> std::io::Result<()> {
            locked(&self.calls).push(messages.len());
            messages.iter().map(|message| self.send(message)).fold(Ok(()), |result, sent| result.and(sent))
        }
        fn send_data(&self, bytes: &[u8]) -> std::io::Result<()> {
            let mut sent = locked(&self.sent);
            if self.data_limit.is_some_and(|limit| sent.iter().filter(|each| matches!(each, Sent::Data(_))).count() >= limit) {
                return Err(broken_pipe());
            }
            sent.push(Sent::Data(bytes.to_vec()));
            Ok(())
        }
    }

    impl Recorder {
        /// A client that takes this many output frames and then goes away.
        fn leaving_after(data_frames: usize) -> Recorder {
            Recorder { data_limit: Some(data_frames), ..Recorder::default() }
        }

        /// A client that is gone before it is told the shell opened.
        fn gone_before_opened() -> Recorder {
            Recorder { refuses_opened: true, ..Recorder::default() }
        }

        fn sent(&self) -> Vec<Sent> {
            locked(&self.sent).clone()
        }

        /// How many messages each call of `send_all` was handed, in order.
        fn calls(&self) -> Vec<usize> {
            locked(&self.calls).clone()
        }

        fn was_told_opened(&self) -> bool {
            self.sent().iter().any(|each| matches!(each, Sent::Message(ServerMessage::Opened { .. })))
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
        start_to(engine, control, Recorder::default())
    }

    /// Like `start`, for a client that is `link`.
    fn start_to(engine: FakeEngine, control: ShellControl, link: Recorder) -> Running {
        let engine = Arc::new(engine);
        start_on(Arc::clone(&engine), engine.as_ref(), control, link)
    }

    /// Like `start_to`, with the session opened by `engine`, which wraps `fake` (so that the tests can see what `fake` was asked).
    fn start_on(fake: Arc<FakeEngine>, engine: &dyn SshEngine, control: ShellControl, link: Recorder) -> Running {
        let session = engine.connect(&target(), &*crate::ssh::testing::doubles::TestPolicy::trusting(), &crate::ssh::testing::doubles::VaultAuth::new()).unwrap();
        let (link, control) = (Arc::new(link), Arc::new(control));
        let pump = {
            let (link, control) = (Arc::clone(&link), Arc::clone(&control));
            std::thread::spawn(move || run_shell(Connected { session, target: target() }, pty(), link.as_ref(), &control, "7"))
        };
        Running { engine: fake, link, control, pump: Some(pump) }
    }

    /// A shell that is slow to open: `Session::shell` waits at the gate that comes back with it, until the test releases it.
    fn start_holding_the_shell(fake: FakeEngine, control: ShellControl) -> (Running, Arc<Gate>) {
        let fake = Arc::new(fake);
        let gated = GatedEngine::new(Arc::clone(&fake)).holding_shells();
        let gate = Arc::clone(&gated.shell);
        (start_on(fake, &gated, control, Recorder::default()), gate)
    }

    impl Running {
        /// The server's side of the shell, once it is open and the relay has it (the fake lists a shell a moment before `run_shell`
        /// has it, and a call to `end` or `owner_gone` in between would find none to close): the client has been told it opened.
        fn wait_for_shell(&self) -> crate::ssh::fake::FakeShell {
            crate::ssh::testing::eventually("the shell to open", 5, || !self.engine.shells().is_empty());
            crate::ssh::testing::eventually("the client to be told it opened", 5, || self.link.was_told_opened());
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
        let settle = Duration::from_millis(600);
        let mut running = start(FakeEngine::new(), ShellControl::with_settle(settle));
        running.wait_for_shell();
        // The settle time counts from the moment the shell opened, which the control wrote down: `owner_gone` does not return before it is
        // over, however long the machine took to get this thread going meanwhile.
        let opened_at = locked(&running.control.life).opened_at.expect("the shell is open");
        running.control.owner_gone();
        assert!(Instant::now() >= opened_at + settle, "it waited for the settle time");
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

    /// What ends a shell is an explanation and `exited`: the relay hands them to the link together, so that nothing another thread
    /// writes comes between them.
    #[test]
    fn what_ends_a_shell_is_handed_to_the_link_as_one_piece() {
        let mut lost = start(FakeEngine::new(), ShellControl::new());
        lost.wait_for_shell().print(b"$ ");
        let hop = target().hops[0].reference();
        lost.engine.disconnect_now(DisconnectReason { hop, kind: DisconnectKind::ConnectionLost, detail: "connection reset by peer".into() });
        lost.finish();
        assert_eq!(lost.link.calls(), [1, 2], "`opened`, then the explanation and `exited` together");

        let control = ShellControl::with_settle(Duration::from_millis(100));
        control.end("SSHelter quit, so the connection to web was closed.");
        let mut ended = start(FakeEngine::new(), control);
        ended.finish();
        assert_eq!(ended.link.calls(), [2], "the app ended the session before its shell opened");

        let mut failing = start(FakeEngine::new().with_shell_error(SessionError::Channel("refused".into())), ShellControl::new());
        failing.finish();
        assert_eq!(failing.link.calls(), [2], "a shell that could not be opened");
    }

    /// A text a server chose can be as long as it likes (an error's `Display` quotes what the peer sent), and a frame holds 1 MiB: the
    /// text of an error or of a disconnect is cut to a sentence's worth of characters, on a character boundary, so that the event is not
    /// dropped for not fitting and the client left with an exit and no reason. A banner is a long text by nature: the engine bounds it.
    #[test]
    fn the_text_of_an_error_or_a_disconnect_is_cut_to_a_sentence_and_a_banner_is_not() {
        let told = |message: ServerMessage| {
            let link = Recorder::default();
            tell(&link, message).unwrap();
            link.split().1.remove(0)
        };
        let error = |text: String| ServerMessage::Event(Event::Error { kind: kinds::SHELL.into(), text });
        let disconnected = |reason: String| ServerMessage::Event(Event::Disconnected { reason });
        // The cut is made at 512 characters, not at 512 bytes, and never inside a character of two bytes or three.
        for c in ['x', 'é', '漢'] {
            let cut = format!("{}…", c.to_string().repeat(512));
            assert_eq!(told(error(c.to_string().repeat(2000))), error(cut.clone()), "an error of {c}");
            assert_eq!(told(disconnected(c.to_string().repeat(2000))), disconnected(cut), "a disconnect of {c}");
        }
        // Up to the limit a text passes as it is; one character more and it is cut.
        assert_eq!(told(error("é".repeat(512))), error("é".repeat(512)));
        assert_eq!(told(error("é".repeat(513))), error(format!("{}…", "é".repeat(512))));
        // The limit is on the text as the client reads it: what `printable` shortens (a carriage return before a line feed) counts as one.
        assert_eq!(told(error("a\r\n".repeat(400))), error(format!("{}…", "a\n".repeat(256))));
        assert_eq!(told(error("\u{1b}".repeat(600))), error(format!("{}…", "?".repeat(512))));
        // A banner is as long as the server made it (within what the engine keeps), and is only made printable.
        let banner = format!("{}\u{1b}[2J", "b".repeat(5000));
        assert_eq!(told(ServerMessage::Event(Event::Banner { text: banner })), ServerMessage::Event(Event::Banner { text: format!("{}?[2J", "b".repeat(5000)) }));
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

    const QUIT: &str = "SSHelter quit, so the connection to web was closed.";

    fn quit_messages() -> [ServerMessage; 2] {
        [ServerMessage::Event(Event::Disconnected { reason: QUIT.into() }), ServerMessage::Exited { code: None, signal: None }]
    }

    /// Plan 1b-1 review, Task 10 Important 2: the app ends the session before the shell is open. No shell is opened for it, the client
    /// is told why, and the session is closed.
    #[test]
    fn a_session_the_app_ended_before_its_shell_opened_gets_no_shell_and_the_client_is_told_why() {
        let control = ShellControl::with_settle(Duration::from_millis(100));
        control.end(QUIT);
        let mut running = start(FakeEngine::new(), control);
        running.finish();
        assert_eq!(running.link.split().1, quit_messages(), "no `Opened`: the client never had a shell");
        assert_eq!(running.engine.events(), [FakeEvent::Connect { aliases: vec!["web".into()] }, FakeEvent::Closed], "no shell was opened on the server");
    }

    /// The same while `Session::shell` is still going on, which can take seconds: the shell it opens is closed as soon as it has printed
    /// something, the client is told why (and was never told the shell opened), and its output is not passed on.
    #[test]
    fn the_app_ending_a_session_while_its_shell_opens_closes_the_shell_and_tells_the_client() {
        let (mut running, opening) = start_holding_the_shell(FakeEngine::new().with_shell_output(b"$ "), ShellControl::with_settle(Duration::from_secs(5)));
        crate::ssh::testing::eventually("the shell to be being opened", 5, || opening.entered() == 1);
        running.control.end(QUIT);
        opening.release();
        running.finish();
        let (output, messages) = running.link.split();
        assert_eq!(messages, quit_messages());
        assert_eq!(output, b"", "what the shell printed was not passed on");
        let events = running.engine.events();
        assert_eq!(&events[1..], [FakeEvent::ShellOpened { term: "xterm-256color".into(), cols: 80, rows: 24 }, FakeEvent::ShellClosed, FakeEvent::Closed], "{events:?}");
    }

    /// A shell that ended on its own before the app closed it reports how it ended: its exit status is not a quit.
    #[test]
    fn a_shell_that_ended_by_itself_while_the_app_ended_the_session_reports_its_own_status() {
        let ending = FakeEngine::new().with_shell_exit(Exit::Code(0)).with_shell_ending_at_once();
        let (mut running, opening) = start_holding_the_shell(ending, ShellControl::new());
        crate::ssh::testing::eventually("the shell to be being opened", 5, || opening.entered() == 1);
        running.control.end(QUIT);
        opening.release();
        running.finish();
        assert_eq!(running.link.split().1, [ServerMessage::Exited { code: Some(0), signal: None }]);
    }

    /// Plan 1b-1 review, Task 10 Minor 1: the client leaves while the shell is being opened. It is not told the shell opened, and the
    /// shell is closed once it has printed (not after the whole settle time, with the thread that reads its output waiting for it).
    #[test]
    fn a_client_that_leaves_while_the_shell_opens_is_not_told_it_opened_and_the_shell_is_closed_after_its_first_output() {
        let (mut running, opening) = start_holding_the_shell(FakeEngine::new().with_shell_output(b"$ "), ShellControl::with_settle(Duration::from_secs(5)));
        crate::ssh::testing::eventually("the shell to be being opened", 5, || opening.entered() == 1);
        running.control.owner_gone();
        let released = Instant::now();
        opening.release();
        running.finish();
        assert!(released.elapsed() < Duration::from_secs(3), "closed after the first output, not after the settle time: {:?}", released.elapsed());
        assert_eq!(running.link.split(), (Vec::new(), Vec::new()), "the client is gone: nothing is sent to it");
        let events = running.engine.events();
        assert_eq!(&events[2..], [FakeEvent::ShellClosed, FakeEvent::Closed], "{events:?}");
    }

    /// The client left before the shell was opened at all: none is.
    #[test]
    fn a_client_that_left_before_the_shell_opened_gets_no_shell() {
        let control = ShellControl::with_settle(Duration::from_millis(100));
        control.owner_gone();
        let mut running = start(FakeEngine::new(), control);
        running.finish();
        assert_eq!(running.link.split(), (Vec::new(), Vec::new()));
        assert_eq!(running.engine.events(), [FakeEvent::Connect { aliases: vec!["web".into()] }, FakeEvent::Closed]);
    }

    /// A session whose only shell is the one it was given.
    struct OneShell(Mutex<Option<Box<dyn ShellChannel>>>);

    impl Session for OneShell {
        fn shell(&self, _pty: Pty) -> Result<Box<dyn ShellChannel>, SessionError> {
            locked(&self.0).take().ok_or(SessionError::Closed)
        }
        fn exec(&self, _command: &str, _timeout: Duration, _output_cap: usize) -> Result<crate::ssh::ExecResult, SessionError> {
            Err(SessionError::Closed)
        }
        fn is_alive(&self) -> bool {
            true
        }
        fn disconnect_reason(&self) -> Option<DisconnectReason> {
            None
        }
        fn close(&self) {}
    }

    /// A shell that ends at once and keeps the sizes sent to it, in the order they arrived; the first size sent waits at a gate before it
    /// is kept (a link that is slow to take it).
    struct SizeShell {
        sizes: Arc<Mutex<Vec<(u16, u16)>>>,
        calls: std::sync::atomic::AtomicUsize,
        slow_first: Arc<Gate>,
    }

    impl ShellChannel for SizeShell {
        fn write(&self, _data: &[u8]) -> Result<(), SessionError> {
            Ok(())
        }
        fn read(&self, _buf: &mut [u8]) -> Result<usize, SessionError> {
            Ok(0)
        }
        fn window_change(&self, cols: u16, rows: u16) -> Result<(), SessionError> {
            if self.calls.fetch_add(1, Ordering::SeqCst) == 0 {
                self.slow_first.pass();
            }
            locked(&self.sizes).push((cols, rows));
            Ok(())
        }
        fn exited(&self) -> Option<Exit> {
            Some(Exit::Code(0))
        }
        fn close(&self) {}
    }

    /// Plan 1b-1 review, Task 10 Minor 4: the size sent again once the shell is open and a resize that comes meanwhile are sent one after
    /// the other, in the order the sizes were set: the shell must not be left with the older one.
    #[test]
    fn a_resize_that_comes_while_the_size_is_sent_again_is_not_overtaken_by_it() {
        let sizes = Arc::new(Mutex::new(Vec::new()));
        let slow_first = Gate::closed();
        let shell = SizeShell { sizes: Arc::clone(&sizes), calls: std::sync::atomic::AtomicUsize::new(0), slow_first: Arc::clone(&slow_first) };
        let control = Arc::new(ShellControl::new());
        control.resize(100, 30);
        let link = Arc::new(Recorder::default());
        let pump = {
            let (control, link) = (Arc::clone(&control), Arc::clone(&link));
            let connected = Connected { session: Box::new(OneShell(Mutex::new(Some(Box::new(shell))))), target: target() };
            std::thread::spawn(move || run_shell(connected, pty(), link.as_ref(), &control, "7"))
        };
        crate::ssh::testing::eventually("the size to be being sent again", 5, || slow_first.entered() == 1);
        let resizing = {
            let control = Arc::clone(&control);
            std::thread::spawn(move || control.resize(120, 40))
        };
        std::thread::sleep(Duration::from_millis(200));
        slow_first.release();
        pump.join().unwrap();
        resizing.join().unwrap();
        assert_eq!(*locked(&sizes), [(100, 30), (120, 40)], "the size set last is the size sent last");
    }

    /// Plan 1b-1 review, Task 10 Minor 6: the connection was gone when the shell was to be opened. That is a lost connection, said as one
    /// (spec §11), and not "could not open a shell … The connection is closed."; and a reason that is only a clause of a sentence does
    /// not begin with a capital.
    #[test]
    fn a_shell_that_cannot_be_opened_on_a_lost_connection_says_how_it_was_lost() {
        let hop = target().hops[0].reference();
        let lost = DisconnectReason { hop, kind: DisconnectKind::ConnectionLost, detail: "connection reset by peer".into() };
        let mut dead = start(FakeEngine::new().disconnecting_with(lost), ShellControl::new());
        dead.finish();
        assert_eq!(
            dead.link.split().1,
            [
                ServerMessage::Event(Event::Disconnected { reason: "Connection to web lost (connection reset by peer).".into() }),
                ServerMessage::Exited { code: None, signal: None },
            ]
        );
        assert_eq!(dead.engine.events(), [FakeEvent::Connect { aliases: vec!["web".into()] }], "no shell was opened on the dead connection");

        // A link that did not take the request in time is not a lost connection: the sentence names the reason in lower case.
        let mut slow = start(FakeEngine::new().with_shell_error(SessionError::Timeout), ShellControl::new());
        slow.finish();
        assert_eq!(
            slow.link.split().1,
            [
                ServerMessage::Event(Event::Error { kind: kinds::SHELL.into(), text: "SSHelter could not open a shell on web: the connection did not take the request in time.".into() }),
                ServerMessage::Exited { code: None, signal: None },
            ]
        );
    }

    /// Plan 1b-1 review, Task 10 Minor 5: a shell the server closed without an exit status while the connection lives.
    #[test]
    fn a_shell_the_server_ended_without_a_status_while_the_connection_lives_says_so() {
        let mut running = start(FakeEngine::new(), ShellControl::new());
        running.wait_for_shell().end(Exit::Disconnected);
        running.finish();
        assert_eq!(
            &running.link.split().1[1..],
            [
                ServerMessage::Event(Event::Disconnected { reason: "The shell on web ended without an exit status.".into() }),
                ServerMessage::Exited { code: None, signal: None },
            ]
        );
    }

    /// The client goes away in the middle of the shell's output: what was sent stays sent, the shell is closed once, nothing more is
    /// told (nobody is there), and the session is closed.
    #[test]
    fn a_client_whose_link_fails_in_the_middle_of_the_output_loses_its_shell() {
        let mut running = start_to(FakeEngine::new(), ShellControl::new(), Recorder::leaving_after(1));
        let remote = running.wait_for_shell();
        remote.print(b"one");
        crate::ssh::testing::eventually("the first output to reach the client", 5, || running.link.split().0 == b"one");
        remote.print(b"two");
        running.finish();
        let (output, messages) = running.link.split();
        assert_eq!((output.as_slice(), messages.as_slice()), (b"one".as_slice(), [ServerMessage::Opened { session_id: "7".into() }].as_slice()));
        assert!(running.control.is_gone());
        let events = running.engine.events();
        assert_eq!(events.iter().filter(|event| **event == FakeEvent::ShellClosed).count(), 1, "{events:?}");
        assert_eq!(events.last(), Some(&FakeEvent::Closed));
    }

    /// The client is gone before it is told the shell opened: nothing is sent to it, and its shell is closed once it has printed.
    #[test]
    fn a_client_that_cannot_be_told_the_shell_opened_loses_its_shell() {
        let mut running = start_to(FakeEngine::new().with_shell_output(b"$ "), ShellControl::new(), Recorder::gone_before_opened());
        running.finish();
        assert_eq!(running.link.split(), (Vec::new(), Vec::new()), "not told, and the prompt was not passed on either");
        assert!(running.control.is_gone());
        let events = running.engine.events();
        assert_eq!(&events[2..], [FakeEvent::ShellClosed, FakeEvent::Closed], "{events:?}");
    }

    /// A jump host's keepalive is its own: the seconds in the sentence are those of the hop that went silent, not the destination's.
    #[test]
    fn a_jump_hosts_keepalive_gives_the_seconds_of_its_own_link() {
        let mut jump = Hop::new("id-jump", "jump", "jump.example.com", 22, "deploy", AuthMethod::Password);
        jump.keepalive_every = Duration::from_secs(15);
        jump.keepalive_max_missed = 1;
        let web = Hop::new("id-web", "web", "web.example.com", 22, "deploy", AuthMethod::Password);
        let through_jump = Target { hops: vec![jump.clone(), web.clone()] };
        let silent = |hop: &Hop| DisconnectReason { hop: hop.reference(), kind: DisconnectKind::KeepaliveTimeout, detail: "silent".into() };
        assert_eq!(lost_sentence(&silent(&jump), &through_jump), "Connection to jump lost (no response for 30 seconds).");
        assert_eq!(lost_sentence(&silent(&web), &through_jump), "Connection to web lost (no response for 120 seconds).");
    }

    /// The wait before a shell nobody wants is closed is not served when the shell ends by itself meanwhile: there is nothing left to close,
    /// and the session is not kept for the rest of the settle time.
    #[test]
    fn a_shell_nobody_wants_that_ends_by_itself_is_not_waited_for_and_not_closed() {
        let (mut running, opening) = start_holding_the_shell(FakeEngine::new(), ShellControl::with_settle(Duration::from_secs(5)));
        crate::ssh::testing::eventually("the shell to be being opened", 5, || opening.entered() == 1);
        running.control.owner_gone();
        opening.release();
        crate::ssh::testing::eventually("the shell to open", 5, || !running.engine.shells().is_empty());
        std::thread::sleep(Duration::from_millis(200));
        let ended = Instant::now();
        running.engine.shells().remove(0).end(Exit::Code(0));
        running.finish();
        assert!(ended.elapsed() < Duration::from_secs(3), "not kept for the settle time: {:?}", ended.elapsed());
        let events = running.engine.events();
        assert!(!events.contains(&FakeEvent::ShellClosed), "a shell that has ended is not closed: {events:?}");
        assert_eq!(events.last(), Some(&FakeEvent::Closed));
    }
}
