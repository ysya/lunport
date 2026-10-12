//! The session broker (own-ssh spec §4, §7.2): it serves the clients that connect to the local IPC socket, one session per connection.
//! A connection says `hello`, asks for a shell (`open_shell`), and owns the session from then on: what the login needs is asked of it,
//! its keystrokes and resizes go to the shell, and when it goes away the session is closed. The connection's own thread reads it; a
//! second thread connects and pumps the shell. No read timeout applies once `open_shell` has arrived: an idle shell stays open for as
//! long as its terminal does. A session is in the broker's table from `open_shell` on, connecting and open alike, so that the app sees
//! it and, when it quits, can end it and tell its client why.

use std::collections::{BTreeMap, HashMap};
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{self, RecvTimeoutError, SyncSender};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use zeroize::Zeroizing;

use super::auth::{KeyStore, Owner, Reply};
use super::connect::{CancelToken, ConnectFailure, Connector, HostKeyConfirmer, CANCELLED};
use super::directory::HostDirectory;
use super::protocol::{decode, kinds, read_frame, write_control, write_data, ClientKind, ClientMessage, Event, Frame, FrameError, HostQuery, Question, QuestionKind, ServerMessage, PROTOCOL_VERSION};
use super::relay::{run_shell, tell, tell_all, ClientLink, ShellControl, SETTLE};
use crate::ipc::peer::{self, ProcInfo};
use crate::ipc::server::{Handler, Stream};
use crate::ssh::{Hop, HostId, Pty, SshEngine};
use crate::sync::env::Keychain;

fn locked<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

/// How long a new connection may take for each of its first two messages, `hello` and `open_shell`.
const HELLO_WAIT: Duration = Duration::from_secs(10);

/// How long the app waits in `end_all` when it quits, so that a shell that has not printed anything yet is still told why its session
/// ended. Such a shell is closed, and only then its client told, once it has printed something or `SETTLE` has passed since it opened (a
/// channel closed before its prompt can strand a process on a macOS sshd): a wait of `SETTLE` itself can run out just before the client
/// is told, so this is `SETTLE` and two seconds more, for closing the shell and the connection and telling the client. A shell that is
/// still being opened when the app quits may need longer than this (`end_all` says what becomes of its client).
pub const QUIT_WAIT: Duration = SETTLE.saturating_add(Duration::from_secs(2));

/// The sentence a client is told when the app quits under its session (spec §4).
pub fn quit_reason(alias: &str) -> String {
    format!("SSHelter quit, so the connection to {alias} was closed.")
}

/// Where a session is: asking the client what the login needs and connecting, or open (its shell is being opened, or is open).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SessionState {
    Connecting,
    Open,
}

/// A session, for the app (it keeps running while there are some, and ends them when it quits) and, in a later version, for the list of
/// sessions (spec §10). It is in the table from the moment the client asked for a shell, not only once the connection is made: a client
/// at a question, or at the host key window, has a session.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SessionInfo {
    pub id: u64,
    /// The saved host's alias; until the connect has looked the host up (`Connecting`), what the client asked for.
    pub alias: String,
    /// `None` until the connect has looked the host up, unless the client asked for the host by its id.
    pub host_id: Option<HostId>,
    pub state: SessionState,
    /// Who asked for it: the process chain of the client, outermost first, without SSHelter's own executable (spec §7.2); `None` when it
    /// could not be told. Recorded now, shown from phase 2 on.
    pub requested_by: Option<Vec<String>>,
    /// When the client asked for the shell.
    pub started_at_ms: u64,
}

/// What the connection's thread and the session's thread share for one session, and what the table keeps of it for `end_all`.
#[derive(Clone)]
struct Conn {
    id: u64,
    link: Arc<FrameLink>,
    /// A handle on the connection, to close it with (`hang_up`).
    closer: Arc<Stream>,
    owner: Arc<ConnectionOwner>,
    control: Arc<ShellControl>,
    cancel: CancelToken,
}

/// Who has given the client of a session that was still being connected the outcome of the connect. Whoever comes second leaves it
/// alone, so the client is told once. (An open session is told by the relay.)
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Told {
    No,
    /// `end_all` is telling it that the app is quitting. The telling thread closes the connection too, once it has written that (the
    /// client reads it before it reads the end of the stream), and only then takes the session out of the table: `end_all` returns when
    /// the table is empty, and every client it ended has to have been told by then. The session's own thread leaves the entry alone.
    ByEndAll,
    /// The session's thread told it why the connect failed.
    BySession,
}

struct Entry {
    info: SessionInfo,
    told: Told,
    conn: Conn,
}

#[derive(Default)]
struct Table {
    entries: BTreeMap<u64, Entry>,
    /// `end_all` has started: the app is quitting, and no session is started any more.
    quitting: bool,
}

/// The broker. One per app; its handler serves the IPC socket.
pub struct Broker {
    engine: Arc<dyn SshEngine>,
    directory: Arc<dyn HostDirectory>,
    keys: Arc<dyn KeyStore>,
    keychain: Arc<dyn Keychain>,
    confirmer: Arc<dyn HostKeyConfirmer>,
    /// How long a new connection may take for each of `hello` and `open_shell`.
    hello_wait: Duration,
    table: Mutex<Table>,
    /// Notified whenever a session leaves the table (`end_all` waits on it).
    changed: Condvar,
    next_id: AtomicU64,
}

impl Broker {
    pub fn new(
        engine: Arc<dyn SshEngine>,
        directory: Arc<dyn HostDirectory>,
        keys: Arc<dyn KeyStore>,
        keychain: Arc<dyn Keychain>,
        confirmer: Arc<dyn HostKeyConfirmer>,
    ) -> Arc<Broker> {
        Broker::with_hello_wait(engine, directory, keys, keychain, confirmer, HELLO_WAIT)
    }

    /// The same, with another time for a new connection to say `hello` and `open_shell` (the tests do not wait ten seconds).
    fn with_hello_wait(
        engine: Arc<dyn SshEngine>,
        directory: Arc<dyn HostDirectory>,
        keys: Arc<dyn KeyStore>,
        keychain: Arc<dyn Keychain>,
        confirmer: Arc<dyn HostKeyConfirmer>,
        hello_wait: Duration,
    ) -> Arc<Broker> {
        Arc::new(Broker {
            engine,
            directory,
            keys,
            keychain,
            confirmer,
            hello_wait,
            table: Mutex::new(Table::default()),
            changed: Condvar::new(),
            next_id: AtomicU64::new(0),
        })
    }

    /// The IPC server's handler: each connection is served on the thread the server gives it.
    pub fn handler(self: &Arc<Broker>) -> Handler {
        let broker = Arc::clone(self);
        Arc::new(move |stream, pid| broker.serve(stream, pid))
    }

    /// The sessions there are now, oldest first: those being connected as well as those that are open.
    pub fn sessions(&self) -> Vec<SessionInfo> {
        locked(&self.table).entries.values().map(|entry| entry.info.clone()).collect()
    }

    /// Whether any client has a session, one that is still being connected (it is at a question, or at the host key window) as much as
    /// one that is open.
    pub fn has_sessions(&self) -> bool {
        !locked(&self.table).entries.is_empty()
    }

    /// The app is quitting (spec §4): every session ends, its client told why, and no new one starts. Waits up to `wait` for the table to
    /// empty, which is when every client has been told: the app exits when this returns, so a client that was not told by then hears
    /// nothing (its terminal says "The connection to SSHelter ended."). The app gives it `QUIT_WAIT`.
    ///
    /// A session that is still being connected is cancelled at once; its client is told, its connection closed, and then the session
    /// leaves the table, on a thread of its own. Nothing waits for what the session's own thread is doing (a question, the host key
    /// window, the engine's connect, which cannot be interrupted): that thread finishes by itself, closes what it connected, and opens
    /// no shell. One that is open, or whose shell is being opened, is ended through the relay, which closes its shell once it has
    /// printed something (or `SETTLE` after it opened) and then tells its client; it leaves the table when its thread is over, which is
    /// after that.
    ///
    /// A shell that is still being opened when the app quits cannot be hurried: `Session::shell` is a blocking engine call as well, and
    /// the shell is closed, and its client told, once the engine is through with it. If that takes longer than `wait` (it may take
    /// longer than `QUIT_WAIT`), `end_all` returns first, the app exits, and the connection of that client ends without a word: its
    /// terminal says "The connection to SSHelter ended." instead of why.
    pub fn end_all(self: &Arc<Broker>, wait: Duration) {
        let (connecting, open) = {
            let mut table = locked(&self.table);
            table.quitting = true;
            let (mut connecting, mut open) = (Vec::new(), Vec::new());
            for entry in table.entries.values_mut() {
                match entry.info.state {
                    SessionState::Connecting if entry.told == Told::No => {
                        entry.told = Told::ByEndAll;
                        connecting.push((entry.info.alias.clone(), entry.conn.clone()));
                    }
                    // The client of a session whose connect has failed is being told why; it is not told the app quit as well.
                    SessionState::Connecting => {}
                    SessionState::Open => open.push((entry.info.alias.clone(), Arc::clone(&entry.conn.control))),
                }
            }
            (connecting, open)
        };
        for (alias, conn) in connecting {
            // Whatever the session waits for gives up at once. Telling the client can block (a client that has stopped reading), so it is
            // done on a thread of its own, which closes the connection when it has (the session's thread leaves that to it, `serve`) and
            // only then takes the session out of the table: not before, or `end_all` would return with the client untold.
            conn.cancel.cancel();
            conn.owner.gone();
            let broker = Arc::clone(self);
            std::thread::spawn(move || {
                say_quit(conn.link.as_ref(), &alias);
                hang_up(&conn.closer);
                broker.told_quit(conn.id);
            });
        }
        for (alias, control) in open {
            std::thread::spawn(move || control.end(&quit_reason(&alias)));
        }
        let deadline = Instant::now() + wait;
        let mut table = locked(&self.table);
        while !table.entries.is_empty() {
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                break;
            }
            table = self.changed.wait_timeout(table, left).unwrap_or_else(PoisonError::into_inner).0;
        }
    }

    /// Serves one client connection until it ends (the thread the IPC server gives it).
    pub fn serve(self: &Arc<Broker>, stream: Stream, pid: Option<u32>) {
        let Ok(writer) = stream.try_clone() else { return };
        let link = Arc::new(FrameLink::new(writer));
        let mut reader = stream;
        let refuse = |kind: &str, text: &str| {
            let _ = tell(link.as_ref(), ServerMessage::Event(Event::Error { kind: kind.to_string(), text: text.to_string() }));
        };
        // `hello`, then `open_shell`, each within a short time (a connection is one of 64 and costs a thread); from then on no read timeout
        // (an idle shell is not a dead client).
        let _ = set_read_timeout(&reader, Some(self.hello_wait));
        if !greet(&mut reader, link.as_ref()) {
            return;
        }
        let requested_by = requester_of(pid);
        let (host, pty) = match first_frame(&mut reader) {
            First::Silent => return,
            First::Control(payload) => match decode::<ClientMessage>(&payload) {
                Ok(ClientMessage::OpenShell { host, pty }) => (host, pty),
                Ok(ClientMessage::Exec {}) => return refuse(kinds::UNSUPPORTED, "Running a command through SSHelter's sessions is not supported yet."),
                Ok(_) | Err(_) => return refuse(kinds::PROTOCOL, "SSHelter expected open_shell."),
            },
            First::Data | First::Broken => return refuse(kinds::PROTOCOL, "SSHelter expected open_shell."),
        };
        let _ = set_read_timeout(&reader, None);
        let owner = Arc::new(ConnectionOwner::new(Arc::clone(&link)));
        let control = Arc::new(ShellControl::new());
        let cancel = CancelToken::default();
        control.resize(pty.cols, pty.rows);
        let Ok(closer) = reader.try_clone() else { return };
        let id = self.next_id.fetch_add(1, Ordering::SeqCst) + 1;
        let conn = Conn { id, link: Arc::clone(&link), closer: Arc::new(closer), owner: Arc::clone(&owner), control: Arc::clone(&control), cancel: cancel.clone() };
        // From here on the session is in the table, whatever it is doing, so that the app sees it and can end it.
        if !self.enter(&conn, &host, requested_by) {
            return say_quit(link.as_ref(), &host.to_string());
        }
        let worker = {
            let (broker, conn) = (Arc::clone(self), conn.clone());
            let pty = Pty { term: pty.term, cols: pty.cols, rows: pty.rows };
            std::thread::Builder::new().name("sshelter-session".to_string()).spawn(move || {
                let _over = SessionOver { broker: &broker, conn: &conn };
                broker.run_session(&conn, &host, pty);
            })
        };
        let Ok(worker) = worker else {
            return self.could_not_start(&conn);
        };
        // The client's messages, until it closes or goes away.
        loop {
            match read_frame(&mut reader) {
                Ok(Some(Frame::Data(bytes))) => control.input(&bytes, link.as_ref()),
                Ok(Some(Frame::Control(payload))) => match decode::<ClientMessage>(&payload) {
                    Ok(ClientMessage::WindowChange { cols, rows }) => control.resize(cols, rows),
                    Ok(ClientMessage::Answer { question_id, value, cancel: cancelled }) => owner.answer(&question_id, value.map(Zeroizing::new), cancelled),
                    Ok(ClientMessage::Close) => break,
                    Ok(_) | Err(_) => refuse(kinds::PROTOCOL, "SSHelter did not expect that message."),
                },
                Ok(None) | Err(_) => break,
            }
        }
        // The owner is gone: whatever waits for it gives up, and the shell (once it has printed something) and the session are closed.
        cancel.cancel();
        owner.gone();
        control.owner_gone();
        let _ = worker.join();
    }

    /// The thread for the session could not be started: its client is told so, and then the session leaves the table and its connection
    /// is closed (`forget`). Unless `end_all` marked the entry in the meantime: it tells the client that the app is quitting, closes the
    /// connection and takes the entry out, and the client is not told both.
    fn could_not_start(&self, conn: &Conn) {
        if self.claim(conn.id) {
            could_not_open(conn.link.as_ref(), kinds::CONNECT, "SSHelter could not start the session.");
        }
        self.forget(conn.id);
    }

    /// Puts the session in the table, still connecting; `false` when the app is quitting (`end_all` has started), and none is started.
    fn enter(&self, conn: &Conn, query: &HostQuery, requested_by: Option<Vec<String>>) -> bool {
        let started_at_ms = SystemTime::now().duration_since(UNIX_EPOCH).map(|elapsed| elapsed.as_millis() as u64).unwrap_or(0);
        let host_id = match query {
            HostQuery::Id(id) => Some(HostId::from(id.as_str())),
            HostQuery::Alias(_) => None,
        };
        let info = SessionInfo { id: conn.id, alias: query.to_string(), host_id, state: SessionState::Connecting, requested_by, started_at_ms };
        let mut table = locked(&self.table);
        if table.quitting {
            return false;
        }
        table.entries.insert(conn.id, Entry { info, told: Told::No, conn: conn.clone() });
        true
    }

    /// The session's thread is over (or was never started: `could_not_start`): the session leaves the table. Says whom the client of a
    /// session that was still being connected has been told by. The entry of a client `end_all` is telling stays, however the thread
    /// ended: the telling thread takes it out when it has told the client (`told_quit`), because `end_all` must not return before. When
    /// the entry is this thread's to take out, its connection is closed first (one `shutdown`, under the table's lock): `end_all` returns
    /// as soon as the table is empty, and every client it ended must be able to read the end of its stream by then.
    fn forget(&self, id: u64) -> Told {
        let mut table = locked(&self.table);
        let told = table.entries.get(&id).map_or(Told::No, |entry| entry.told);
        if told != Told::ByEndAll {
            if let Some(entry) = table.entries.remove(&id) {
                hang_up(&entry.conn.closer);
            }
        }
        drop(table);
        self.changed.notify_all();
        told
    }

    /// `end_all` has told the client of a session that was still being connected that the app quit, and has closed its connection: the
    /// session leaves the table, which lets `end_all` return.
    fn told_quit(&self, id: u64) {
        locked(&self.table).entries.remove(&id);
        self.changed.notify_all();
    }

    /// Whether the caller may tell the client of a session that is still connecting how its connect ended; `false` when `end_all` has
    /// told it already.
    fn claim(&self, id: u64) -> bool {
        match locked(&self.table).entries.get_mut(&id) {
            Some(entry) if entry.told != Told::No => false,
            Some(entry) => {
                entry.told = Told::BySession;
                true
            }
            // The session's thread takes its entry out itself, when it is over, which is after it has claimed. Only `end_all`, once it
            // has told the client, takes one out from under a thread that is still running.
            None => false,
        }
    }

    /// The connect has made a session to `destination`: the session becomes an open one. `false` when `end_all` has told its client the
    /// app is quitting while the connect was going on: the session is then closed, not given a shell.
    fn promote(&self, id: u64, destination: &Hop) -> bool {
        let mut table = locked(&self.table);
        let Some(entry) = table.entries.get_mut(&id) else { return false };
        if entry.told != Told::No {
            return false;
        }
        entry.info.state = SessionState::Open;
        entry.info.alias = destination.alias.clone();
        entry.info.host_id = Some(destination.id.clone());
        true
    }

    /// The session thread: connects, then runs the shell. A failure is told to the client (unless it is gone) as an error and an exit
    /// without a status.
    fn run_session(&self, conn: &Conn, host: &HostQuery, pty: Pty) {
        let connector = Connector {
            engine: self.engine.as_ref(),
            directory: self.directory.as_ref(),
            keys: self.keys.as_ref(),
            keychain: self.keychain.as_ref(),
            confirmer: self.confirmer.as_ref(),
        };
        let connected = match connector.connect(host, conn.owner.as_ref(), &conn.cancel) {
            Ok(connected) => connected,
            Err(failure) => {
                if failure.kind != CANCELLED && !conn.control.is_gone() && self.claim(conn.id) {
                    let failure = conn.owner.failure_told(failure);
                    could_not_open(conn.link.as_ref(), &failure.kind, &failure.text);
                }
                return;
            }
        };
        let Some(destination) = connected.target.hops.last() else { return };
        if !self.promote(conn.id, destination) {
            connected.session.close();
            return;
        }
        run_shell(connected, pty, conn.link.as_ref(), &conn.control, &conn.id.to_string());
    }
}

/// What becomes of a session whichever way its thread ends, a panic included (the thread unwinds through this): it leaves the table, its
/// connection closed first (`forget`), which ends the reader of `serve` and tells the client. `end_all` closes the connection of a client
/// it told the app is quitting, after it has told it, so `forget` leaves that one to it.
struct SessionOver<'a> {
    broker: &'a Broker,
    conn: &'a Conn,
}

impl Drop for SessionOver<'_> {
    fn drop(&mut self) {
        self.broker.forget(self.conn.id);
    }
}

/// A session that could not be opened: the error, then `exited` without a status (spec §7.2), written as one piece.
fn could_not_open(link: &dyn ClientLink, kind: &str, text: &str) {
    let error = ServerMessage::Event(Event::Error { kind: kind.to_string(), text: text.to_string() });
    let _ = tell_all(link, vec![error, ServerMessage::Exited { code: None, signal: None }]);
}

/// Tells a client that the app quit under its session (spec §4): the sentence and `exited`, written as one piece. Another thread of the
/// session may be writing to the client at the same moment (a banner, a notice, a question), and none of it may come between them.
fn say_quit(link: &dyn ClientLink, alias: &str) {
    let _ = tell_all(link, vec![ServerMessage::Event(Event::Disconnected { reason: quit_reason(alias) }), ServerMessage::Exited { code: None, signal: None }]);
}

/// What a connection said when the broker looked for one of its first two messages.
enum First {
    Control(Zeroizing<Vec<u8>>),
    /// Keystrokes.
    Data,
    /// A frame that cannot be read, so the stream is out of step: the client can still be told so.
    Broken,
    /// The client closed the connection, or nothing could be read from it (it said nothing for too long): nobody is there to be told.
    Silent,
}

fn first_frame(reader: &mut Stream) -> First {
    match read_frame(reader) {
        Ok(Some(Frame::Control(payload))) => First::Control(payload),
        Ok(Some(Frame::Data(_))) => First::Data,
        Ok(None) | Err(FrameError::Io(_)) => First::Silent,
        Err(_) => First::Broken,
    }
}

/// The protocol version a `hello` names, whatever else it says.
fn hello_version(payload: &[u8]) -> Option<u64> {
    let message: serde_json::Value = serde_json::from_slice(payload).ok()?;
    if message.get("type")?.as_str()? != "hello" {
        return None;
    }
    message.get("version")?.as_u64()
}

/// Reads the first message of a connection, which has to be the `hello` of `sshelter connect` in this protocol version. Anything else is
/// refused by name with an `error` event (spec §7.2), and `false` comes back: the connection is closed, and nothing was started. The
/// version is looked at first: a client of another version may say hello in ways this version cannot read, and what helps its user then
/// is to be told to quit SSHelter and open it again, whoever the client says it is.
fn greet(reader: &mut Stream, link: &dyn ClientLink) -> bool {
    let refuse = |kind: &str, text: String| {
        let _ = tell(link, ServerMessage::Event(Event::Error { kind: kind.to_string(), text }));
        false
    };
    match first_frame(reader) {
        First::Silent => false,
        First::Broken => refuse(kinds::PROTOCOL, "SSHelter could not read the first message.".to_string()),
        First::Data => refuse(kinds::PROTOCOL, "The first message must be hello.".to_string()),
        First::Control(payload) => {
            if let Some(version) = hello_version(&payload).filter(|version| *version != u64::from(PROTOCOL_VERSION)) {
                let text = format!("This sshelter speaks protocol {version} and the SSHelter that is running speaks {PROTOCOL_VERSION}. Quit SSHelter and open it again.");
                return refuse(kinds::PROTOCOL, text);
            }
            match decode::<ClientMessage>(&payload) {
                Ok(ClientMessage::Hello { client: ClientKind::Connect, version: PROTOCOL_VERSION, .. }) => true,
                Ok(ClientMessage::Hello { client: ClientKind::Mcp, .. }) => refuse(kinds::UNSUPPORTED, "The MCP adapter cannot use SSHelter's sessions yet.".to_string()),
                Ok(ClientMessage::Hello { .. }) | Err(_) => refuse(kinds::PROTOCOL, "SSHelter could not read the first message.".to_string()),
                Ok(_) => refuse(kinds::PROTOCOL, "The first message must be hello.".to_string()),
            }
        }
    }
}

#[cfg(unix)]
fn set_read_timeout(stream: &Stream, timeout: Option<Duration>) -> std::io::Result<()> {
    stream.set_read_timeout(timeout)
}

/// A Windows pipe has no read timeout.
#[cfg(windows)]
fn set_read_timeout(_stream: &Stream, _timeout: Option<Duration>) -> std::io::Result<()> {
    Ok(())
}

/// Closes the connection both ways: the client reads its end, and a read blocked on it returns.
#[cfg(unix)]
fn hang_up(stream: &Stream) {
    let _ = stream.shutdown(std::net::Shutdown::Both);
}

/// The broker does not serve Windows clients in this version (plan 1b: `sshelter connect` is macOS and Linux); nothing to close.
#[cfg(windows)]
fn hang_up(_stream: &Stream) {}

/// The client's connection, as the relay writes to it: whole frames under one lock. `exited` is the last thing a client is told: once it
/// has been written, nothing else is. A thread that did not know the session was over, because it passed its check just before the
/// session ended, would otherwise put a question or a banner after it.
struct FrameLink {
    writer: Mutex<Writer>,
}

struct Writer {
    stream: Stream,
    /// `exited` has been written.
    finished: bool,
}

impl FrameLink {
    fn new(stream: Stream) -> FrameLink {
        FrameLink { writer: Mutex::new(Writer { stream, finished: false }) }
    }
}

/// Why nothing is written to a client any more once it has been told the session is over.
fn after_exited() -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::BrokenPipe, "the client has been told that the session is over")
}

impl ClientLink for FrameLink {
    fn send(&self, message: &ServerMessage) -> std::io::Result<()> {
        self.send_all(std::slice::from_ref(message))
    }

    /// All the messages under one hold of the writer. A message too large for a frame is not written at all and leaves the stream in
    /// step, so the ones after it are written still (`exited` must reach the client); the caller is told. Any other error means the
    /// client is gone.
    fn send_all(&self, messages: &[ServerMessage]) -> std::io::Result<()> {
        let mut writer = locked(&self.writer);
        let mut unwritten = Ok(());
        for message in messages {
            // Looked at for every message: one that follows `exited` in the same sequence is not written either.
            if writer.finished {
                return Err(after_exited());
            }
            match write_control(&mut writer.stream, message) {
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::InvalidInput => {
                    if unwritten.is_ok() {
                        unwritten = Err(error);
                    }
                }
                Err(error) => return Err(error),
            }
            if matches!(message, ServerMessage::Exited { .. }) {
                writer.finished = true;
            }
        }
        unwritten
    }

    fn send_data(&self, bytes: &[u8]) -> std::io::Result<()> {
        let mut writer = locked(&self.writer);
        if writer.finished {
            return Err(after_exited());
        }
        write_data(&mut writer.stream, bytes)
    }
}

/// The questions an owner has asked.
#[derive(Default)]
struct Questions {
    /// The client is gone (`ConnectionOwner::gone`): a question asked from now on is `Gone` at once.
    gone: bool,
    /// The questions waiting for an answer, by id. Emptied when the client is gone, which wakes every waiting `ask` with `Gone`.
    waiting: HashMap<String, SyncSender<Reply>>,
}

/// The owner of a session: its client. A question goes out as a `question` frame; the connection's reader delivers the answer.
struct ConnectionOwner {
    link: Arc<FrameLink>,
    questions: Mutex<Questions>,
    next_question: AtomicU64,
    /// A question was too large to send (`ask`), although the client is there: see `failure_told`.
    unshown: AtomicBool,
}

/// The end of the sentence about a login that ended because the owner gave no answer to a keyboard-interactive prompt, as the engine
/// writes it, and as it reads when the question could not be shown to the owner.
const PROMPT_CANCELLED: &str = "(the prompt was cancelled).";
const PROMPT_NOT_SHOWN: &str = "(the prompt could not be shown).";

impl ConnectionOwner {
    fn new(link: Arc<FrameLink>) -> ConnectionOwner {
        ConnectionOwner { link, questions: Mutex::new(Questions::default()), next_question: AtomicU64::new(0), unshown: AtomicBool::new(false) }
    }

    /// `failure` as the client is told it. A prompt too large for a frame (a server can write one) is not shown, which `ask` answers as
    /// `Gone`, like a client that has left, and the engine, which is told only that nobody answered, calls the prompt cancelled. Nobody
    /// cancelled it: the sentence says it could not be shown.
    fn failure_told(&self, failure: ConnectFailure) -> ConnectFailure {
        if self.unshown.load(Ordering::SeqCst) && failure.kind == kinds::AUTH {
            if let Some(sentence) = failure.text.strip_suffix(PROMPT_CANCELLED) {
                return ConnectFailure { text: format!("{sentence}{PROMPT_NOT_SHOWN}"), ..failure };
            }
        }
        failure
    }

    fn question_id(&self) -> String {
        format!("q{}", self.next_question.fetch_add(1, Ordering::SeqCst) + 1)
    }

    /// The client's answer to `question_id` (a late or unknown one is dropped). The value can be a password: it arrives in a `Zeroizing`,
    /// moved there where it was read, so that no way out of here, an early one included, leaves a plain copy of it behind.
    fn answer(&self, question_id: &str, value: Option<Zeroizing<String>>, cancelled: bool) {
        let Some(waiting) = locked(&self.questions).waiting.remove(question_id) else { return };
        let reply = match value {
            Some(value) if !cancelled => Reply::Answer(value),
            _ => Reply::Cancelled,
        };
        let _ = waiting.try_send(reply);
    }

    /// The client is gone: whatever waits for an answer is given up on, and nothing is asked any more.
    fn gone(&self) {
        let mut questions = locked(&self.questions);
        questions.gone = true;
        questions.waiting.clear();
    }

    fn is_gone(&self) -> bool {
        locked(&self.questions).gone
    }
}

impl Owner for ConnectionOwner {
    fn ask(&self, kind: QuestionKind, text: &str, echo: bool, deadline: Option<Instant>) -> Reply {
        let question_id = self.question_id();
        let (answer, answered) = mpsc::sync_channel(1);
        {
            // Checked and inserted under one lock: a question cannot be added after `gone` has emptied the table, and wait out its deadline.
            let mut questions = locked(&self.questions);
            if questions.gone {
                return Reply::Gone;
            }
            questions.waiting.insert(question_id.clone(), answer);
        }
        let deadline_ms = deadline.map(|deadline| deadline.saturating_duration_since(Instant::now()).as_millis() as u64);
        let question = Question { question_id: question_id.clone(), kind, text: text.to_string(), echo, deadline_ms };
        if let Err(error) = tell(self.link.as_ref(), ServerMessage::Question(question)) {
            locked(&self.questions).waiting.remove(&question_id);
            // A question that does not fit in a frame is not written at all (the stream is good, and the client may be there); any
            // other failure means the client is gone.
            if error.kind() == std::io::ErrorKind::InvalidInput {
                self.unshown.store(true, Ordering::SeqCst);
            }
            return Reply::Gone;
        }
        let reply = match deadline {
            None => answered.recv().map_err(|_| RecvTimeoutError::Disconnected),
            Some(deadline) => answered.recv_timeout(deadline.saturating_duration_since(Instant::now())),
        };
        match reply {
            Ok(reply) => reply,
            Err(RecvTimeoutError::Timeout) => {
                locked(&self.questions).waiting.remove(&question_id);
                Reply::TimedOut
            }
            Err(RecvTimeoutError::Disconnected) => Reply::Gone,
        }
    }

    /// Nothing is shown to a client that is gone, or is being told the session is over: it would come after the sentence that ends it, or
    /// in the middle of it.
    fn host_key_notice(&self, text: &str) {
        if self.is_gone() {
            return;
        }
        let question = Question { question_id: self.question_id(), kind: QuestionKind::HostKeyNotice, text: text.to_string(), echo: false, deadline_ms: None };
        let _ = tell(self.link.as_ref(), ServerMessage::Question(question));
    }

    fn banner(&self, text: &str) {
        if self.is_gone() {
            return;
        }
        let _ = tell(self.link.as_ref(), ServerMessage::Event(Event::Banner { text: text.to_string() }));
    }
}

/// The process chain without SSHelter's own executable: `sshelter connect` is SSHelter, and the person's program is what started it.
pub fn without_own_executable(chain: Vec<ProcInfo>, own: Option<&Path>) -> Vec<ProcInfo> {
    let Some(own) = own else { return chain };
    chain.into_iter().filter(|process| process.path.as_deref().map(Path::new) != Some(own)).collect()
}

/// Who connected (spec §7.2): the peer's process chain, without SSHelter's own executable, named as `ipc::peer` names programs.
pub fn requester_of(pid: Option<u32>) -> Option<Vec<String>> {
    let own = std::env::current_exe().ok().map(|path| std::fs::canonicalize(&path).unwrap_or(path));
    let chain = without_own_executable(peer::process_chain(pid?), own.as_deref());
    peer::identify(&chain).map(|program| program.chain)
}

#[cfg(all(test, unix))]
mod tests {
    use std::io::Write;
    use std::os::unix::net::UnixStream;
    use std::time::Instant;

    use super::*;
    use crate::session::protocol::{read_frame, write_control, write_data, write_frame, Frame, PtyRequest, QuestionKind, CONTROL, DATA, MAX_FRAME};
    use crate::session::testing::{locked, Decision, FakeConfirmer, FakeDirectory, FakeKeys, GatedEngine, WaitingConfirmer};
    use crate::ssh::fake::{default_server_key, FakeEngine, FakeEvent, FakeLogin, FakeMethods, FakeShell};
    use crate::ipc::peer::ProcInfo;
    use crate::ssh::{AuthMethod, AuthSource, ConnectError, DisconnectKind, DisconnectReason, Exit, HostKeyPolicy, Session, SessionError, Target};
    use crate::sync::testkit::MemKeychain;

    /// What the client received.
    #[derive(Clone, Debug, PartialEq, Eq)]
    enum Got {
        Message(ServerMessage),
        Data(Vec<u8>),
    }

    /// A client of the broker, speaking the protocol over a socket.
    struct Client {
        stream: UnixStream,
    }

    impl Client {
        fn connect(sock: &Path) -> Client {
            let stream = UnixStream::connect(sock).expect("the broker listens");
            stream.set_read_timeout(Some(Duration::from_secs(15))).unwrap();
            Client { stream }
        }

        fn send(&mut self, message: &ClientMessage) {
            write_control(&mut self.stream, message).expect("the broker reads");
        }

        fn hello(&mut self) {
            self.send(&ClientMessage::Hello { client: ClientKind::Connect, version: PROTOCOL_VERSION, client_info: None });
        }

        fn open(&mut self, alias: &str) {
            self.hello();
            self.send(&ClientMessage::OpenShell { host: HostQuery::Alias(alias.into()), pty: PtyRequest { cols: 80, rows: 24, term: "xterm-256color".into() } });
        }

        fn type_text(&mut self, text: &str) {
            write_data(&mut self.stream, text.as_bytes()).unwrap();
        }

        /// The next thing the broker sent; `None` once it has closed the connection.
        fn next(&mut self) -> Option<Got> {
            match read_frame(&mut self.stream).expect("a frame or the end") {
                None => None,
                Some(Frame::Control(payload)) => Some(Got::Message(decode::<ServerMessage>(&payload).expect("a server message"))),
                Some(Frame::Data(bytes)) => Some(Got::Data(bytes.to_vec())),
            }
        }

        fn next_message(&mut self) -> ServerMessage {
            loop {
                match self.next() {
                    Some(Got::Message(message)) => return message,
                    Some(Got::Data(_)) => continue,
                    None => panic!("the broker closed the connection"),
                }
            }
        }

        /// Everything until the broker closes the connection: the output, and the messages.
        fn rest(&mut self) -> (Vec<u8>, Vec<ServerMessage>) {
            let (mut output, mut messages) = (Vec::new(), Vec::new());
            while let Some(got) = self.next() {
                match got {
                    Got::Data(bytes) => output.extend(bytes),
                    Got::Message(message) => messages.push(message),
                }
            }
            (output, messages)
        }

        fn answer(&mut self, question_id: &str, value: Option<&str>) {
            self.send(&ClientMessage::Answer { question_id: question_id.into(), value: value.map(str::to_string), cancel: value.is_none() });
        }

        /// What the broker has written that can be read now, without waiting for more, and whether it has closed the connection by now.
        fn ready_now(&mut self) -> (Vec<Got>, bool) {
            self.stream.set_nonblocking(true).unwrap();
            let mut got = Vec::new();
            let closed = loop {
                match read_frame(&mut self.stream) {
                    Ok(Some(Frame::Control(payload))) => got.push(Got::Message(decode::<ServerMessage>(&payload).expect("a server message"))),
                    Ok(Some(Frame::Data(bytes))) => got.push(Got::Data(bytes.to_vec())),
                    Ok(None) => break true,
                    Err(FrameError::Io(error)) if error.kind() == std::io::ErrorKind::WouldBlock => break false,
                    Err(error) => panic!("a frame, the end of the stream, or nothing yet: {error}"),
                }
            };
            self.stream.set_nonblocking(false).unwrap();
            (got, closed)
        }
    }

    struct World {
        broker: Arc<Broker>,
        engine: Arc<FakeEngine>,
        /// The gates of the engine's connects and shell opens: open, unless the test closed one when it made the world.
        gates: Arc<GatedEngine>,
        directory: Arc<FakeDirectory>,
        sock: std::path::PathBuf,
        _dir: tempfile::TempDir,
    }

    /// A broker over `engine`, `directory` and `confirmer`, listening on a socket in a short temp directory (macOS limits socket paths).
    fn world_with(engine: FakeEngine, directory: FakeDirectory, confirmer: Arc<dyn HostKeyConfirmer>, keychain: MemKeychain) -> World {
        world_gated(engine, directory, confirmer, keychain, |gated| gated)
    }

    /// Like `world_with`, with the gates of the engine made by `gate` (`GatedEngine::holding_connects`, `holding_shells`).
    fn world_gated(engine: FakeEngine, directory: FakeDirectory, confirmer: Arc<dyn HostKeyConfirmer>, keychain: MemKeychain, gate: impl FnOnce(GatedEngine) -> GatedEngine) -> World {
        let (engine, directory) = (Arc::new(engine), Arc::new(directory));
        let gates = Arc::new(gate(GatedEngine::new(Arc::clone(&engine))));
        let broker = Broker::new(
            Arc::clone(&gates) as Arc<dyn SshEngine>,
            Arc::clone(&directory) as Arc<dyn HostDirectory>,
            Arc::new(FakeKeys::new()),
            Arc::new(keychain),
            confirmer,
        );
        let dir = tempfile::Builder::new().prefix("sb").tempdir_in("/tmp").unwrap();
        let ipc = dir.path().join("ipc");
        assert_eq!(crate::ipc::server::listen_unix(&ipc, broker.handler()).unwrap(), crate::ipc::server::Started::Running);
        World { broker, engine, gates, directory, sock: ipc.join("sock"), _dir: dir }
    }

    /// Like `world`, with a broker that gives a new connection `hello_wait` for each of `hello` and `open_shell`.
    fn world_waiting(hello_wait: Duration) -> World {
        let (engine, directory) = (Arc::new(FakeEngine::new()), Arc::new(pinned_web()));
        let gates = Arc::new(GatedEngine::new(Arc::clone(&engine)));
        let broker = Broker::with_hello_wait(
            Arc::clone(&gates) as Arc<dyn SshEngine>,
            Arc::clone(&directory) as Arc<dyn HostDirectory>,
            Arc::new(FakeKeys::new()),
            Arc::new(saved_password()),
            Arc::new(FakeConfirmer::default()),
            hello_wait,
        );
        let dir = tempfile::Builder::new().prefix("sb").tempdir_in("/tmp").unwrap();
        let ipc = dir.path().join("ipc");
        assert_eq!(crate::ipc::server::listen_unix(&ipc, broker.handler()).unwrap(), crate::ipc::server::Started::Running);
        World { broker, engine, gates, directory, sock: ipc.join("sock"), _dir: dir }
    }

    /// `web` is pinned and its password is saved: it connects without a question.
    fn world(engine: FakeEngine) -> World {
        world_gated(engine, pinned_web(), Arc::new(FakeConfirmer::default()), saved_password(), |gated| gated)
    }

    fn pinned_web() -> FakeDirectory {
        FakeDirectory::new().with_host("web", AuthMethod::Password).with_pin("web", default_server_key())
    }

    fn saved_password() -> MemKeychain {
        let keychain = MemKeychain::default();
        keychain.set("host:id-web", "saved").unwrap();
        keychain
    }

    fn remote(world: &World) -> FakeShell {
        crate::ssh::testing::eventually("the shell to open", 10, || !world.engine.shells().is_empty());
        world.engine.shells().remove(0)
    }

    fn no_status() -> ServerMessage {
        ServerMessage::Exited { code: None, signal: None }
    }

    #[test]
    fn a_client_opens_a_shell_over_the_socket_types_into_it_and_gets_its_exit_status() {
        let world = world(FakeEngine::new());
        let mut client = Client::connect(&world.sock);
        client.open("web");
        assert_eq!(client.next_message(), ServerMessage::Opened { session_id: "1".into() });
        client.type_text("ls\r");
        client.send(&ClientMessage::WindowChange { cols: 120, rows: 40 });
        let shell = remote(&world);
        shell.print(b"file.txt\r\n");
        crate::ssh::testing::eventually("the input to reach the shell", 5, || world.engine.events().contains(&FakeEvent::ShellInput(b"ls\r".to_vec())));
        crate::ssh::testing::eventually("the resize to reach the shell", 5, || world.engine.events().contains(&FakeEvent::WindowChange { cols: 120, rows: 40 }));
        shell.end(Exit::Code(5));
        let (output, messages) = client.rest();
        assert_eq!(output, b"file.txt\r\n");
        assert_eq!(messages, [ServerMessage::Exited { code: Some(5), signal: None }]);
        crate::ssh::testing::eventually("the session to be closed and forgotten", 5, || world.broker.sessions().is_empty());
        assert_eq!(world.engine.events().last(), Some(&FakeEvent::Closed));
    }

    #[test]
    fn the_client_is_told_to_look_at_the_window_while_the_host_key_is_confirmed_there() {
        let keychain = MemKeychain::default();
        keychain.set("host:id-web", "saved").unwrap();
        let world = world_with(FakeEngine::new(), FakeDirectory::new().with_host("web", AuthMethod::Password), Arc::new(FakeConfirmer::deciding(vec![Decision::Trust])), keychain);
        let mut client = Client::connect(&world.sock);
        client.open("web");
        match client.next_message() {
            ServerMessage::Question(question) => {
                assert_eq!((question.kind, question.text.as_str(), question.echo, question.deadline_ms), (QuestionKind::HostKeyNotice, "Waiting for you to confirm web's host key in SSHelter.", false, None));
            }
            other => panic!("expected the notice, got {other:?}"),
        }
        assert_eq!(client.next_message(), ServerMessage::Opened { session_id: "1".into() });
        assert!(world.directory.pins().contains_key(&HostId::from("id-web")));
    }

    #[test]
    fn a_password_the_login_wants_is_asked_of_the_client_and_its_answer_gets_in() {
        let directory = FakeDirectory::new().with_host("web", AuthMethod::Key { key_id: "k-plain".into() }).with_pin("web", default_server_key());
        let world = world_with(FakeEngine::new().with_login(FakeLogin::Server(FakeMethods::password("right"))), directory, Arc::new(FakeConfirmer::default()), MemKeychain::default());
        let mut client = Client::connect(&world.sock);
        client.open("web");
        let ServerMessage::Question(question) = client.next_message() else { panic!("expected a question") };
        assert_eq!((question.kind, question.text.as_str(), question.echo), (QuestionKind::Password, "deploy@web's password: ", false));
        let deadline_ms = question.deadline_ms.expect("a deadline");
        assert!((55_000..=60_000).contains(&deadline_ms), "{deadline_ms}");
        client.answer(&question.question_id, Some("right"));
        assert_eq!(client.next_message(), ServerMessage::Opened { session_id: "1".into() });
    }

    #[test]
    fn a_cancelled_question_ends_the_connect_with_an_error_and_no_exit_status() {
        let directory = FakeDirectory::new().with_host("web", AuthMethod::Key { key_id: "k-plain".into() }).with_pin("web", default_server_key());
        let world = world_with(FakeEngine::new().with_login(FakeLogin::Server(FakeMethods::password("right"))), directory, Arc::new(FakeConfirmer::default()), MemKeychain::default());
        let mut client = Client::connect(&world.sock);
        client.open("web");
        let ServerMessage::Question(question) = client.next_message() else { panic!("expected a question") };
        client.answer(&question.question_id, None);
        assert_eq!(
            client.rest().1,
            [
                ServerMessage::Event(Event::Error { kind: kinds::AUTH.into(), text: "Authentication for web was abandoned (the password was not given).".into() }),
                no_status(),
            ]
        );
    }

    #[test]
    fn a_host_that_cannot_be_connected_is_an_error_then_an_exit_without_a_status() {
        let world = world(FakeEngine::new());
        let mut client = Client::connect(&world.sock);
        client.open("mail");
        assert_eq!(client.rest().1, [ServerMessage::Event(Event::Error { kind: kinds::HOST.into(), text: "No saved host is called mail.".into() }), no_status()]);
    }

    #[test]
    fn another_protocol_version_exec_and_the_mcp_client_are_refused_by_name() {
        let world = world(FakeEngine::new());
        let refused = |messages: &[ClientMessage]| {
            let mut client = Client::connect(&world.sock);
            for message in messages {
                client.send(message);
            }
            client.rest().1
        };
        let error = |kind: &str, text: &str| vec![ServerMessage::Event(Event::Error { kind: kind.into(), text: text.into() })];
        assert_eq!(
            refused(&[ClientMessage::Hello { client: ClientKind::Connect, version: 2, client_info: None }]),
            error(kinds::PROTOCOL, "This sshelter speaks protocol 2 and the SSHelter that is running speaks 1. Quit SSHelter and open it again.")
        );
        assert_eq!(refused(&[ClientMessage::Hello { client: ClientKind::Mcp, version: PROTOCOL_VERSION, client_info: None }]), error(kinds::UNSUPPORTED, "The MCP adapter cannot use SSHelter's sessions yet."));
        assert_eq!(
            refused(&[ClientMessage::Hello { client: ClientKind::Connect, version: PROTOCOL_VERSION, client_info: None }, ClientMessage::Exec {}]),
            error(kinds::UNSUPPORTED, "Running a command through SSHelter's sessions is not supported yet.")
        );
        assert_eq!(refused(&[ClientMessage::Close]), error(kinds::PROTOCOL, "The first message must be hello."));
        assert!(world.engine.events().is_empty(), "nothing was connected");
    }

    #[test]
    fn a_session_is_listed_while_it_runs() {
        let world = world(FakeEngine::new());
        let mut client = Client::connect(&world.sock);
        client.open("web");
        assert_eq!(client.next_message(), ServerMessage::Opened { session_id: "1".into() });
        let sessions = world.broker.sessions();
        assert_eq!(sessions.len(), 1);
        assert_eq!((sessions[0].id, sessions[0].alias.as_str(), sessions[0].host_id.as_ref().map(HostId::as_str)), (1, "web", Some("id-web")));
        assert_eq!(sessions[0].state, SessionState::Open);
        assert!(world.broker.has_sessions());
        remote(&world).end(Exit::Code(0));
        client.rest();
        crate::ssh::testing::eventually("the session to be forgotten", 5, || !world.broker.has_sessions());
    }

    /// The terminal was closed: the broker sees the end of the connection and closes the session (spec §7.2).
    #[test]
    fn when_the_client_goes_away_its_session_is_closed() {
        let world = world(FakeEngine::new());
        let mut client = Client::connect(&world.sock);
        client.open("web");
        assert_eq!(client.next_message(), ServerMessage::Opened { session_id: "1".into() });
        remote(&world).print(b"$ ");
        drop(client);
        crate::ssh::testing::eventually("the session to be closed", 10, || world.engine.events().contains(&FakeEvent::Closed));
        assert_eq!(world.engine.events().iter().filter(|event| **event == FakeEvent::ShellClosed).count(), 1, "the shell is closed once");
        crate::ssh::testing::eventually("and forgotten", 5, || !world.broker.has_sessions());
    }

    /// The client left while the window asked about the host key: the question is withdrawn and nothing more is connected.
    #[test]
    fn the_window_stops_waiting_when_the_client_goes_away() {
        let confirmer = Arc::new(WaitingConfirmer::default());
        let world = world_with(FakeEngine::new(), FakeDirectory::new().with_host("web", AuthMethod::Password), Arc::clone(&confirmer) as Arc<dyn HostKeyConfirmer>, MemKeychain::default());
        let mut client = Client::connect(&world.sock);
        client.open("web");
        // The password is asked first (the hop starts with it); the host key comes next, and with it the notice that the window has it.
        let ServerMessage::Question(question) = client.next_message() else { panic!("expected the password question") };
        assert_eq!(question.kind, QuestionKind::Password);
        client.answer(&question.question_id, Some("typed"));
        let ServerMessage::Question(notice) = client.next_message() else { panic!("expected the notice about the window") };
        assert_eq!(notice.kind, QuestionKind::HostKeyNotice);
        crate::ssh::testing::eventually("the window to be asked", 5, || *locked(&confirmer.asked) == 1);
        drop(client);
        crate::ssh::testing::eventually("the window to be told its question is withdrawn", 5, || *locked(&confirmer.withdrawn));
        assert_eq!(*locked(&confirmer.asked), 1, "asked once, and not again");
        crate::ssh::testing::eventually("the connect to give up", 10, || !world.broker.has_sessions());
        assert!(world.engine.events().is_empty(), "nothing was connected");
    }

    /// The IPC server gives every connection a read timeout (an agent connection that idles is dropped); a session must not inherit it.
    #[test]
    fn an_idle_session_is_not_ended_by_a_read_timeout() {
        let world = world(FakeEngine::new());
        let (mut ours, theirs) = UnixStream::pair().unwrap();
        theirs.set_read_timeout(Some(Duration::from_millis(200))).unwrap();
        // The read timeout is an option of the socket, shared by every handle of it: this one shows what the broker leaves it at.
        let probe = theirs.try_clone().unwrap();
        let broker = Arc::clone(&world.broker);
        std::thread::spawn(move || broker.serve(theirs, None));
        write_control(&mut ours, &ClientMessage::Hello { client: ClientKind::Connect, version: PROTOCOL_VERSION, client_info: None }).unwrap();
        write_control(&mut ours, &ClientMessage::OpenShell { host: HostQuery::Alias("web".into()), pty: PtyRequest { cols: 80, rows: 24, term: "dumb".into() } }).unwrap();
        let mut client = Client { stream: ours };
        client.stream.set_read_timeout(Some(Duration::from_secs(15))).unwrap();
        assert_eq!(client.next_message(), ServerMessage::Opened { session_id: "1".into() });
        assert_eq!(probe.read_timeout().unwrap(), None, "the connection of an open session has no read timeout at all");
        std::thread::sleep(Duration::from_millis(800));
        client.stream.write_all(&[0, 0, 0, 3, crate::session::protocol::DATA, b'o', b'k']).unwrap();
        crate::ssh::testing::eventually("input after the idle time to reach the shell", 5, || world.engine.events().contains(&FakeEvent::ShellInput(b"ok".to_vec())));
        assert!(world.broker.has_sessions());
    }

    /// Spec §4: quitting the app ends every session; each client is told why.
    #[test]
    fn quitting_ends_every_session_and_tells_each_client_why() {
        let world = world(FakeEngine::new());
        let mut client = Client::connect(&world.sock);
        client.open("web");
        assert_eq!(client.next_message(), ServerMessage::Opened { session_id: "1".into() });
        remote(&world).print(b"$ ");
        let started = Instant::now();
        world.broker.end_all(Duration::from_secs(10));
        assert!(started.elapsed() < Duration::from_secs(5), "{:?}", started.elapsed());
        assert!(!world.broker.has_sessions());
        assert_eq!(client.rest().1, [ServerMessage::Event(Event::Disconnected { reason: "SSHelter quit, so the connection to web was closed.".into() }), no_status()]);
    }

    /// The whole way with the real engine: a client asks the broker for a shell on a scratch OpenSSH, the host key is confirmed in the
    /// (scripted) window and pinned, the shell runs a command, and its exit status comes back.
    #[test]
    fn a_real_shell_on_a_scratch_sshd_through_the_socket() {
        let Some(tools) = crate::ssh::testing::harness::tools() else { return };
        let server = crate::ssh::testing::fixture::Server::start(&tools, &["ForceCommand if [ -n \"$SSH_ORIGINAL_COMMAND\" ]; then eval \"$SSH_ORIGINAL_COMMAND\"; else exec /bin/sh; fi"]);
        let directory = Arc::new(FakeDirectory::new().with_hop(server.hop_with("lab", server.sshd.port, AuthMethod::Key { key_id: "k1".into() })));
        let broker = Broker::new(
            Arc::new(crate::ssh::russh_engine::RusshEngine::new()),
            Arc::clone(&directory) as Arc<dyn HostDirectory>,
            Arc::new(FakeKeys::new().with_key("k1", "lab key", &server.key.private_text)),
            Arc::new(MemKeychain::default()),
            Arc::new(FakeConfirmer::deciding(vec![Decision::Trust])),
        );
        let dir = tempfile::Builder::new().prefix("sb").tempdir_in("/tmp").unwrap();
        crate::ipc::server::listen_unix(&dir.path().join("ipc"), broker.handler()).unwrap();
        let mut client = Client::connect(&dir.path().join("ipc").join("sock"));
        client.open("lab");
        assert!(matches!(client.next_message(), ServerMessage::Question(Question { kind: QuestionKind::HostKeyNotice, .. })));
        assert_eq!(client.next_message(), ServerMessage::Opened { session_id: "1".into() });
        assert_eq!(directory.pins().get(&HostId::from("host-lab")).map(|pin| pin.key.clone()), Some(server.host_key()), "the key the server presented is pinned");

        let mut seen = Vec::new();
        let mut read_until = |client: &mut Client, needle: &str| {
            while !String::from_utf8_lossy(&seen).contains(needle) {
                match client.next() {
                    Some(Got::Data(bytes)) => seen.extend(bytes),
                    other => panic!("waiting for {needle:?}, got {other:?} after {:?}", String::from_utf8_lossy(&seen)),
                }
            }
        };
        read_until(&mut client, "$ ");
        client.type_text("echo SSHELTER_$((6*7))\r");
        read_until(&mut client, "SSHELTER_42");
        client.type_text("exit 7\r");
        assert_eq!(client.rest().1, [ServerMessage::Exited { code: Some(7), signal: None }]);
        crate::ssh::testing::eventually("the session to be forgotten", 10, || !broker.has_sessions());
    }

    #[test]
    fn the_requester_chain_leaves_out_sshelters_own_executable() {
        let process = |pid: u32, path: &str| ProcInfo { pid, ppid: pid + 1, path: Some(path.into()), argv: vec![path.into()] };
        let own = Path::new("/Applications/SSHelter.app/Contents/MacOS/sshelter");
        let chain = vec![process(10, "/Applications/SSHelter.app/Contents/MacOS/sshelter"), process(11, "/bin/zsh"), process(12, "/System/Applications/Utilities/Terminal.app/Contents/MacOS/Terminal")];
        let kept = without_own_executable(chain, Some(own));
        assert_eq!(kept.iter().map(|process| process.pid).collect::<Vec<_>>(), [11, 12]);
        assert_eq!(without_own_executable(vec![process(10, "/usr/bin/ssh")], None).len(), 1, "nothing to leave out when the own path is unknown");
    }

    /// A question larger than a frame is not written (nothing of it reaches the stream), the owner answers `Gone` at once, and the stream
    /// is still good for what comes next: the frame limit is the broker's own, not a sign that the client is gone.
    #[test]
    fn an_oversized_question_is_gone_writes_nothing_and_leaves_the_stream_usable() {
        let (mut ours, theirs) = UnixStream::pair().unwrap();
        let owner = ConnectionOwner::new(Arc::new(FrameLink::new(theirs)));
        let started = Instant::now();
        let reply = owner.ask(QuestionKind::Interactive, &"x".repeat(MAX_FRAME), false, Some(Instant::now() + Duration::from_secs(30)));
        assert!(matches!(reply, Reply::Gone), "{reply:?}");
        assert!(started.elapsed() < Duration::from_secs(2), "it did not wait for its deadline: {:?}", started.elapsed());
        assert!(locked(&owner.questions).waiting.is_empty(), "the question is forgotten");
        owner.host_key_notice("after");
        ours.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        match read_frame(&mut ours).unwrap() {
            Some(Frame::Control(payload)) => match decode::<ServerMessage>(&payload).unwrap() {
                ServerMessage::Question(question) => assert_eq!((question.kind, question.text.as_str()), (QuestionKind::HostKeyNotice, "after"), "the first thing on the stream"),
                other => panic!("{other:?}"),
            },
            other => panic!("{other:?}"),
        }
    }

    fn quit_sentence() -> ServerMessage {
        ServerMessage::Event(Event::Disconnected { reason: "SSHelter quit, so the connection to web was closed.".into() })
    }

    /// What a client has been told, and can read at once, when `end_all` is done with it: the quit sentence and `exited`, and the
    /// connection is closed after them.
    fn told_quit() -> (Vec<Got>, bool) {
        (vec![Got::Message(quit_sentence()), Got::Message(no_status())], true)
    }

    /// Plan 1b-1 review, Task 11 Important 2: a client that is being asked a question (here the password) has a session as much as one
    /// whose shell is open. The app does not quit under it without saying why, and the window it closes does not quit the app.
    #[test]
    fn a_client_at_a_password_question_has_a_session_and_is_told_why_when_the_app_quits() {
        let directory = FakeDirectory::new().with_host("web", AuthMethod::Key { key_id: "k-plain".into() }).with_pin("web", default_server_key());
        let world = world_with(FakeEngine::new().with_login(FakeLogin::Server(FakeMethods::password("right"))), directory, Arc::new(FakeConfirmer::default()), MemKeychain::default());
        let mut client = Client::connect(&world.sock);
        client.open("web");
        let ServerMessage::Question(question) = client.next_message() else { panic!("expected the password question") };
        assert_eq!(question.kind, QuestionKind::Password);
        assert!(world.broker.has_sessions(), "a client at a question has a session");
        let sessions = world.broker.sessions();
        assert_eq!(
            (sessions.len(), sessions[0].id, sessions[0].alias.as_str(), sessions[0].host_id.clone(), sessions[0].state),
            (1, 1, "web", None, SessionState::Connecting),
            "listed as connecting, under the alias the client asked for, before the host has been looked up"
        );
        world.broker.end_all(Duration::from_secs(5));
        assert_eq!(client.rest().1, [quit_sentence(), no_status()]);
        crate::ssh::testing::eventually("the session to be forgotten", 5, || !world.broker.has_sessions());
        assert!(world.engine.events().is_empty(), "nothing was connected");
    }

    /// What the app tells a client it ends is read before the end of the connection, and `end_all` does not return before the client
    /// has been told: here the client's connection is busy, so the telling has to wait, while the session's own thread (woken by the
    /// cancel) is done with its connect long before. That thread ending is not the telling: the app exits when `end_all` returns, so it
    /// is not let go before, and the thread must not close the connection under the telling either.
    #[test]
    fn the_connection_of_a_client_the_app_told_it_is_quitting_is_closed_after_it_was_told() {
        let directory = FakeDirectory::new().with_host("web", AuthMethod::Key { key_id: "k-plain".into() }).with_pin("web", default_server_key());
        let world = world_with(FakeEngine::new().with_login(FakeLogin::Server(FakeMethods::password("right"))), directory, Arc::new(FakeConfirmer::default()), MemKeychain::default());
        let mut client = Client::connect(&world.sock);
        client.open("web");
        let ServerMessage::Question(_) = client.next_message() else { panic!("expected the password question") };
        let link = Arc::clone(&locked(&world.broker.table).entries[&1].conn.link);
        let busy = locked(&link.writer);
        let ending = {
            let broker = Arc::clone(&world.broker);
            std::thread::spawn(move || broker.end_all(Duration::from_secs(10)))
        };
        // Long enough for the session's thread to be over: the cancel wakes its question at once.
        std::thread::sleep(Duration::from_millis(300));
        assert!(!ending.is_finished(), "end_all returned while its client had not been told");
        assert!(world.broker.has_sessions(), "the session stays in the table until its client has been told");
        drop(busy);
        ending.join().unwrap();
        assert_eq!(client.ready_now(), told_quit(), "all of it can be read at the moment end_all returns, and the connection is closed after it");
        assert!(!world.broker.has_sessions());
    }

    /// The app exits as soon as `end_all` returns, so every client it ended has been told by then, not a few microseconds later (the
    /// session's thread, woken by the cancel, used to empty the table before the telling thread had written a byte).
    #[test]
    fn when_end_all_returns_the_clients_of_the_connecting_sessions_have_been_told_and_their_connections_closed() {
        for run in 1..=30 {
            let directory = FakeDirectory::new().with_host("web", AuthMethod::Key { key_id: "k-plain".into() }).with_pin("web", default_server_key());
            let world = world_with(FakeEngine::new().with_login(FakeLogin::Server(FakeMethods::password("right"))), directory, Arc::new(FakeConfirmer::default()), MemKeychain::default());
            let mut client = Client::connect(&world.sock);
            client.open("web");
            let ServerMessage::Question(_) = client.next_message() else { panic!("expected the password question") };
            world.broker.end_all(Duration::from_secs(5));
            assert_eq!(client.ready_now(), told_quit(), "run {run}");
            assert!(!world.broker.has_sessions(), "run {run}");
        }
    }

    /// The engine's connect cannot be interrupted, and the app does not wait for it: the client is told, and the session leaves the
    /// table, while the connect goes on. (The thread that runs it closes what it connects, when it gets through.)
    #[test]
    fn end_all_does_not_wait_for_an_engine_connect_that_cannot_be_interrupted() {
        let world = world_gated(FakeEngine::new(), pinned_web(), Arc::new(FakeConfirmer::default()), saved_password(), |gated| gated.holding_connects());
        let mut client = Client::connect(&world.sock);
        client.open("web");
        crate::ssh::testing::eventually("the connect to be going on", 5, || world.gates.connect.entered() == 1);
        let control = Arc::clone(&locked(&world.broker.table).entries[&1].conn.control);
        let started = Instant::now();
        world.broker.end_all(Duration::from_secs(4));
        assert!(started.elapsed() < Duration::from_secs(2), "end_all waited for the connect: {:?}", started.elapsed());
        assert_eq!(client.ready_now(), told_quit());
        assert!(!world.broker.has_sessions(), "the session is gone from the table while its connect goes on");
        assert!(world.engine.events().is_empty(), "the connect has not finished");
        world.gates.connect.release();
        crate::ssh::testing::eventually("everything of the session to be over", 5, || Arc::strong_count(&control) == 1);
        assert_eq!(world.engine.events(), [FakeEvent::Connect { aliases: vec!["web".into()] }, FakeEvent::Closed], "connected, closed at once, and no shell opened");
    }

    /// The same while the shell is being opened, which can take seconds: the shell is closed once the engine has opened it, the client was
    /// never told it opened, and is told why it ended.
    #[test]
    fn a_client_whose_shell_is_still_opening_when_the_app_quits_is_told_why_and_loses_the_shell() {
        let keychain = saved_password();
        let world = world_gated(FakeEngine::new().with_shell_output(b"$ "), pinned_web(), Arc::new(FakeConfirmer::default()), keychain, |gated| gated.holding_shells());
        let mut client = Client::connect(&world.sock);
        client.open("web");
        crate::ssh::testing::eventually("the shell to be being opened", 5, || world.gates.shell.entered() == 1);
        assert!(world.broker.has_sessions());
        let control = Arc::clone(&locked(&world.broker.table).entries[&1].conn.control);
        let ending = {
            let broker = Arc::clone(&world.broker);
            std::thread::spawn(move || broker.end_all(Duration::from_secs(10)))
        };
        // The shell may only open once the app has said why the session ends: that is the case this test is about.
        crate::ssh::testing::eventually("the session to be ended while its shell is being opened", 5, || control.quit_reason().is_some());
        world.gates.shell.release();
        ending.join().unwrap();
        assert_eq!(client.rest(), (Vec::new(), vec![quit_sentence(), no_status()]), "never told the shell opened, and its prompt was not passed on");
        let events = world.engine.events();
        assert_eq!(&events[1..], [FakeEvent::ShellOpened { term: "xterm-256color".into(), cols: 80, rows: 24 }, FakeEvent::ShellClosed, FakeEvent::Closed], "{events:?}");
        assert!(!world.broker.has_sessions());
    }

    /// A connect that is still going on when the app starts to quit: the client is told at once (the engine's connect cannot be
    /// interrupted, and the app does not wait for it), and when the connect finishes meanwhile it ends at once: no shell is opened.
    #[test]
    fn a_connect_that_finishes_after_the_app_started_to_quit_ends_at_once_and_its_client_was_told_meanwhile() {
        let world = world_gated(FakeEngine::new(), pinned_web(), Arc::new(FakeConfirmer::default()), saved_password(), |gated| gated.holding_connects());
        let mut client = Client::connect(&world.sock);
        client.stream.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
        client.open("web");
        crate::ssh::testing::eventually("the connect to be going on", 5, || world.gates.connect.entered() == 1);
        let control = Arc::clone(&locked(&world.broker.table).entries[&1].conn.control);
        let ending = {
            let broker = Arc::clone(&world.broker);
            std::thread::spawn(move || broker.end_all(Duration::from_secs(10)))
        };
        assert_eq!(client.next_message(), quit_sentence(), "told while the engine is still connecting");
        assert_eq!(client.next_message(), no_status());
        assert!(world.engine.events().is_empty(), "the connect has not finished");
        world.gates.connect.release();
        ending.join().unwrap();
        assert_eq!(client.rest(), (Vec::new(), Vec::new()), "nothing more is said");
        // `end_all` does not wait for the session's thread, so the connect that got through is closed in its own time.
        crate::ssh::testing::eventually("everything of the session to be over", 5, || Arc::strong_count(&control) == 1);
        assert_eq!(world.engine.events(), [FakeEvent::Connect { aliases: vec!["web".into()] }, FakeEvent::Closed], "connected, and closed at once: no shell");
        assert!(!world.broker.has_sessions());
    }

    /// A client that asks for a shell after the app started to quit gets the same answer.
    #[test]
    fn a_client_that_asks_for_a_shell_while_the_app_quits_is_told_so() {
        let world = world(FakeEngine::new());
        world.broker.end_all(Duration::from_millis(10));
        let mut client = Client::connect(&world.sock);
        client.open("web");
        assert_eq!(client.rest().1, [quit_sentence(), no_status()]);
        assert!(world.engine.events().is_empty(), "nothing was connected");
    }

    /// A `Conn` on a socket pair, for the tests of the table: the client's end is returned too.
    fn conn_on_a_socket_pair(id: u64) -> (Conn, UnixStream) {
        let (ours, theirs) = UnixStream::pair().unwrap();
        let link = Arc::new(FrameLink::new(theirs.try_clone().unwrap()));
        let conn = Conn {
            id,
            link: Arc::clone(&link),
            closer: Arc::new(theirs),
            owner: Arc::new(ConnectionOwner::new(link)),
            control: Arc::new(ShellControl::new()),
            cancel: CancelToken::default(),
        };
        (conn, ours)
    }

    /// The client of a session that is still connecting is told how the connect ended by one of two parties, `end_all` (the app is
    /// quitting) or the session's thread (it failed), and by one only; and a connect that has a session by then does not make it an open one.
    #[test]
    fn the_outcome_of_a_connect_is_told_by_one_party_and_a_session_told_the_app_quit_is_not_opened() {
        let world = world(FakeEngine::new());
        let web = Hop::new("id-web", "web", "web.example.com", 22, "deploy", AuthMethod::Password);
        let query = HostQuery::Alias("web".into());

        let (failing, mut failing_client) = conn_on_a_socket_pair(1);
        assert!(world.broker.enter(&failing, &query, None));
        assert!(world.broker.claim(1), "the first to tell");
        assert!(!world.broker.claim(1), "and nobody after it");
        assert!(!world.broker.promote(1, &web), "a session whose client was told the connect failed is not opened");
        assert_eq!(world.broker.forget(1), Told::BySession);
        // `failing` still holds the connection: only `forget` can have closed it.
        failing_client.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        assert!(matches!(read_frame(&mut failing_client), Ok(None)), "the connection is closed by the time its entry is out of the table");

        let (quitting, mut client) = conn_on_a_socket_pair(2);
        assert!(world.broker.enter(&quitting, &query, None));
        // The client's connection is busy, so the telling by `end_all` waits; the entry stays until it has told the client.
        let busy = locked(&quitting.link.writer);
        world.broker.end_all(Duration::ZERO);
        assert!(!world.broker.claim(2), "end_all told it first");
        assert!(!world.broker.promote(2, &web), "a connect that finishes after end_all started does not make an open session");
        assert_eq!(world.broker.forget(2), Told::ByEndAll, "the session's thread ending says who tells the client");
        assert!(world.broker.has_sessions(), "and leaves the entry to the telling, which removes it once the client has been told");
        drop(busy);
        client.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let mut told = Vec::new();
        while let Some(Frame::Control(payload)) = read_frame(&mut client).unwrap() {
            told.push(decode::<ServerMessage>(&payload).unwrap());
        }
        assert_eq!(told, [quit_sentence(), no_status()]);
        crate::ssh::testing::eventually("the entry to leave once its client was told", 5, || !world.broker.has_sessions());
        assert!(!world.broker.claim(2), "a session whose client end_all told stays told, also when its entry is gone");
        assert!(!world.broker.promote(2, &web), "nor is a session whose entry is gone made an open one");
        assert!(!world.broker.enter(&conn_on_a_socket_pair(3).0, &query, None), "and no session is started once the app is quitting");
    }

    /// Plan 1b-1 review, Task 11 Minor 1: a question asked after the owner was told the client is gone is not written and not waited for
    /// (the client may have sent `close` and not hung up yet).
    #[test]
    fn a_question_asked_after_the_client_is_gone_is_neither_written_nor_waited_for() {
        let (mut ours, theirs) = client_and_broker_ends();
        let owner = ConnectionOwner::new(Arc::new(FrameLink::new(theirs)));
        owner.gone();
        let started = Instant::now();
        let reply = owner.ask(QuestionKind::Password, "p", false, Some(Instant::now() + Duration::from_secs(3)));
        assert!(matches!(reply, Reply::Gone), "{reply:?}");
        assert!(started.elapsed() < Duration::from_secs(1), "it did not wait for its deadline: {:?}", started.elapsed());
        // Nothing was written: with the owner dropped the stream ends, and that is the first thing the client reads.
        drop(owner);
        assert!(matches!(read_frame(&mut ours), Ok(None)), "no question was written");
    }

    /// The two ends of a connection for a test of the broker's side of it: the client's end has a read timeout, so that a test which
    /// waits for something that was not written fails instead of hanging. (It is set now: macOS refuses to set it on a socket whose
    /// peer is gone.)
    fn client_and_broker_ends() -> (UnixStream, UnixStream) {
        let (ours, theirs) = UnixStream::pair().unwrap();
        ours.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        (ours, theirs)
    }

    /// Everything that was written to the client, until its stream ends: the owner (and with it the link) has to be dropped first.
    fn written_to(ours: &mut UnixStream) -> Vec<ServerMessage> {
        let mut told = Vec::new();
        while let Some(frame) = read_frame(ours).unwrap() {
            match frame {
                Frame::Control(payload) => told.push(decode::<ServerMessage>(&payload).unwrap()),
                Frame::Data(bytes) => panic!("unexpected output: {:?}", bytes.to_vec()),
            }
        }
        told
    }

    /// A banner or a notice for a client that is gone is not written: it would come after the sentence that ends the session, or in the
    /// middle of it.
    #[test]
    fn a_banner_or_a_notice_for_a_client_that_is_gone_is_not_written() {
        let (mut ours, theirs) = client_and_broker_ends();
        let owner = ConnectionOwner::new(Arc::new(FrameLink::new(theirs)));
        owner.banner("early");
        owner.gone();
        owner.banner("late");
        owner.host_key_notice("late");
        drop(owner);
        assert_eq!(written_to(&mut ours), [ServerMessage::Event(Event::Banner { text: "early".into() })], "only what came before the client was gone");
    }

    /// `exited` is the last thing a client is told: a thread that did not know the session was over (it passed its check just before
    /// `end_all` ended it) says what it had to say after it, and it is not written.
    #[test]
    fn nothing_is_written_to_a_client_after_exited() {
        let (mut ours, theirs) = client_and_broker_ends();
        let link = Arc::new(FrameLink::new(theirs));
        let owner = ConnectionOwner::new(Arc::clone(&link));
        say_quit(link.as_ref(), "web");
        owner.banner("late");
        owner.host_key_notice("late");
        let reply = owner.ask(QuestionKind::Password, "p", false, Some(Instant::now() + Duration::from_secs(3)));
        assert!(matches!(reply, Reply::Gone), "a question that cannot be written is not waited for: {reply:?}");
        assert!(link.send_data(b"late").is_err(), "no output either");
        drop(owner);
        drop(link);
        assert_eq!(written_to(&mut ours), [quit_sentence(), no_status()]);

        // Not within one sequence either.
        let (mut ours, theirs) = client_and_broker_ends();
        let link = FrameLink::new(theirs);
        let late = ServerMessage::Event(Event::Banner { text: "late".into() });
        assert!(link.send_all(&[no_status(), late]).is_err());
        drop(link);
        assert_eq!(written_to(&mut ours), [no_status()]);
    }

    /// A client link that records how it was handed its messages: each call, with the messages of it.
    #[derive(Default)]
    struct CallRecorder {
        calls: Mutex<Vec<Vec<ServerMessage>>>,
    }

    impl ClientLink for CallRecorder {
        fn send(&self, message: &ServerMessage) -> std::io::Result<()> {
            locked(&self.calls).push(vec![message.clone()]);
            Ok(())
        }
        fn send_all(&self, messages: &[ServerMessage]) -> std::io::Result<()> {
            locked(&self.calls).push(messages.to_vec());
            Ok(())
        }
        fn send_data(&self, _bytes: &[u8]) -> std::io::Result<()> {
            Ok(())
        }
    }

    /// What ends a session is an explanation and `exited`; they are handed to the link together, so that nothing is written between them.
    #[test]
    fn what_ends_a_session_is_handed_to_the_link_as_one_piece() {
        let link = CallRecorder::default();
        say_quit(&link, "web");
        could_not_open(&link, kinds::CONNECT, "SSHelter could not start the session.");
        assert_eq!(
            *locked(&link.calls),
            [vec![quit_sentence(), no_status()], vec![ServerMessage::Event(Event::Error { kind: kinds::CONNECT.into(), text: "SSHelter could not start the session.".into() }), no_status()]]
        );
    }

    /// The messages of one `send_all` follow each other on the wire, however many threads write meanwhile.
    #[test]
    fn the_messages_of_one_send_all_are_written_with_nothing_between_them() {
        let (mut ours, theirs) = client_and_broker_ends();
        let link = Arc::new(FrameLink::new(theirs));
        let banner = |text: &str| ServerMessage::Event(Event::Banner { text: text.to_string() });
        let stop = Arc::new(AtomicBool::new(false));
        let others: Vec<_> = (0..4)
            .map(|_| {
                let (link, stop) = (Arc::clone(&link), Arc::clone(&stop));
                std::thread::spawn(move || {
                    while !stop.load(Ordering::SeqCst) {
                        let _ = link.send(&banner("other"));
                    }
                })
            })
            .collect();
        let reader = std::thread::spawn(move || written_to(&mut ours));
        for _ in 0..500 {
            link.send_all(&[banner("first"), banner("second")]).unwrap();
        }
        stop.store(true, Ordering::SeqCst);
        for other in others {
            other.join().unwrap();
        }
        drop(link);
        let texts: Vec<String> = reader.join().unwrap().into_iter().map(|message| if let ServerMessage::Event(Event::Banner { text }) = message { text } else { panic!("{message:?}") }).collect();
        assert_eq!(texts.iter().filter(|text| *text == "first").count(), 500);
        for (at, text) in texts.iter().enumerate() {
            if text == "first" {
                assert_eq!(texts.get(at + 1).map(String::as_str), Some("second"), "something was written between the two messages, at {at}");
            }
        }
    }

    /// A message too large for a frame is not written at all and leaves the stream in step: the ones after it are still written (the
    /// `exited` that ends the session must reach the client), and the caller is told.
    #[test]
    fn a_message_too_large_for_a_frame_does_not_keep_the_ones_after_it_from_being_written() {
        let (mut ours, theirs) = client_and_broker_ends();
        let link = FrameLink::new(theirs);
        let huge = ServerMessage::Event(Event::Banner { text: "x".repeat(MAX_FRAME) });
        let error = link.send_all(&[huge, no_status()]).expect_err("the first message does not fit");
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
        drop(link);
        assert_eq!(written_to(&mut ours), [no_status()]);
    }

    /// An answer is used by the question it names while that waits; to an unknown or an overdue question it is dropped, and an answer
    /// that is also marked as cancelled is a cancel.
    #[test]
    fn an_answer_reaches_the_question_it_names_and_a_late_or_unknown_one_is_dropped() {
        let (_ours, theirs) = UnixStream::pair().unwrap();
        let owner = Arc::new(ConnectionOwner::new(Arc::new(FrameLink::new(theirs))));
        let typed = |text: &str| Some(Zeroizing::new(text.to_string()));
        let ask = |owner: &Arc<ConnectionOwner>, wait: Duration| {
            let owner = Arc::clone(owner);
            std::thread::spawn(move || owner.ask(QuestionKind::Password, "p", false, Some(Instant::now() + wait)))
        };
        let waiting = |owner: &ConnectionOwner| locked(&owner.questions).waiting.len();

        let asking = ask(&owner, Duration::from_secs(10));
        crate::ssh::testing::eventually("the question to wait", 5, || waiting(&owner) == 1);
        owner.answer("q99", typed("nobody asked"), false);
        assert_eq!(waiting(&owner), 1, "an answer to a question nobody asked is dropped");
        owner.answer("q1", typed("right"), false);
        assert!(matches!(asking.join().unwrap(), Reply::Answer(answer) if answer.as_str() == "right"));

        let asking = ask(&owner, Duration::from_secs(10));
        crate::ssh::testing::eventually("the question to wait", 5, || waiting(&owner) == 1);
        owner.answer("q2", typed("typed, then Ctrl-C"), true);
        assert!(matches!(asking.join().unwrap(), Reply::Cancelled));

        let asking = ask(&owner, Duration::from_millis(100));
        assert!(matches!(asking.join().unwrap(), Reply::TimedOut));
        owner.answer("q3", typed("too late"), false);
        assert_eq!(waiting(&owner), 0, "the question that ran out is forgotten, and a late answer to it is dropped");
    }

    /// Plan 1b-1 review, Task 11 Minor 3: whatever a client says first that the broker cannot use, it is told so before the connection
    /// is closed. The version comes first: a client of another protocol version may say hello in ways this version cannot read.
    #[test]
    fn a_first_message_the_broker_cannot_use_is_answered_before_the_connection_closes() {
        let world = world(FakeEngine::new());
        let error = |kind: &str, text: &str| vec![ServerMessage::Event(Event::Error { kind: kind.into(), text: text.into() })];
        let other_version = error(kinds::PROTOCOL, "This sshelter speaks protocol 2 and the SSHelter that is running speaks 1. Quit SSHelter and open it again.");
        let unreadable = error(kinds::PROTOCOL, "SSHelter could not read the first message.");
        let not_hello = error(kinds::PROTOCOL, "The first message must be hello.");
        let not_open_shell = error(kinds::PROTOCOL, "SSHelter expected open_shell.");
        let hello = br#"{"type":"hello","client":"connect","version":1}"#;
        // What the client writes, as frames (type, payload), and what it must be told.
        let cases: Vec<(&str, Vec<(u8, &[u8])>, Vec<ServerMessage>)> = vec![
            ("a client kind this version does not know, of another version", vec![(CONTROL, br#"{"type":"hello","client":"agent","version":2}"#)], other_version.clone()),
            ("an mcp client of another version: the version is what to tell", vec![(CONTROL, br#"{"type":"hello","client":"mcp","version":2}"#)], other_version.clone()),
            ("a hello without a version", vec![(CONTROL, br#"{"type":"hello","client":"connect"}"#)], unreadable.clone()),
            ("text that is not JSON", vec![(CONTROL, b"hello?")], unreadable.clone()),
            ("a frame of a type there is not", vec![(3, b"x")], unreadable.clone()),
            ("keystrokes before anything else", vec![(DATA, b"typed ahead")], not_hello.clone()),
            ("a message that is not hello", vec![(CONTROL, br#"{"type":"close"}"#)], not_hello.clone()),
            ("keystrokes where open_shell was due", vec![(CONTROL, hello), (DATA, b"typed ahead")], not_open_shell.clone()),
            ("an open_shell that cannot be read", vec![(CONTROL, hello), (CONTROL, br#"{"type":"open_shell"}"#)], not_open_shell.clone()),
        ];
        for (what, frames, told) in cases {
            let mut client = Client::connect(&world.sock);
            for (kind, payload) in frames {
                write_frame(&mut client.stream, kind, payload).unwrap();
            }
            assert_eq!(client.rest().1, told, "{what}");
        }
        assert!(world.engine.events().is_empty(), "nothing was connected");
    }

    /// Plan 1b-1 review, Task 11 Minor 4: a connection is one of the 64 the server takes and costs a thread; one that says nothing, or
    /// says hello and then nothing, is closed after the time `hello` and `open_shell` are given, not kept for ever.
    #[test]
    fn a_connection_that_does_not_say_hello_and_then_open_shell_in_time_is_closed() {
        let world = world_waiting(Duration::from_millis(300));
        let silent_from = |client: &mut Client| {
            client.stream.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
            let started = Instant::now();
            assert!(client.next().is_none(), "closed by the broker, not still open");
            started.elapsed()
        };
        let mut nothing = Client::connect(&world.sock);
        assert!(silent_from(&mut nothing) < Duration::from_secs(3));
        let mut only_hello = Client::connect(&world.sock);
        only_hello.hello();
        assert!(silent_from(&mut only_hello) < Duration::from_secs(3));
        // The bound is for the two first messages: a client that makes them is not on the clock any more.
        let mut client = Client::connect(&world.sock);
        client.open("web");
        assert_eq!(client.next_message(), ServerMessage::Opened { session_id: "1".into() });
        std::thread::sleep(Duration::from_millis(900));
        let control = Arc::clone(&locked(&world.broker.table).entries[&1].conn.control);
        assert!(world.broker.has_sessions() && !control.is_gone(), "an idle session is not given up on after the time hello is given");
    }

    /// Plan 1b-1 review, Task 11 Minor 5: the client leaves while the engine is still connecting, which cannot be interrupted. When the
    /// connect gets through, its session is closed, and no shell is opened on the server for nobody.
    #[test]
    fn a_client_that_leaves_while_the_engine_connects_gets_no_shell_opened_for_it() {
        let world = world_gated(FakeEngine::new(), pinned_web(), Arc::new(FakeConfirmer::default()), saved_password(), |gated| gated.holding_connects());
        let mut client = Client::connect(&world.sock);
        client.open("web");
        crate::ssh::testing::eventually("the connect to be going on", 5, || world.gates.connect.entered() == 1);
        let cancel = locked(&world.broker.table).entries[&1].conn.cancel.clone();
        drop(client);
        crate::ssh::testing::eventually("the broker to see that the client has gone", 5, || cancel.is_cancelled());
        world.gates.connect.release();
        crate::ssh::testing::eventually("the session to be forgotten", 10, || !world.broker.has_sessions());
        assert_eq!(world.engine.events(), [FakeEvent::Connect { aliases: vec!["web".into()] }, FakeEvent::Closed], "connected, closed at once, and no shell opened");
    }

    /// An engine whose connect panics.
    struct PanickingEngine;

    impl SshEngine for PanickingEngine {
        fn connect(&self, _target: &Target, _host_keys: &dyn HostKeyPolicy, _auth: &dyn AuthSource) -> Result<Box<dyn Session>, ConnectError> {
            panic!("the engine panicked (this panic is the test)");
        }
    }

    /// Plan 1b-1 review, Task 11 Minor 6: a panic on the session's thread must not leave the session in the table, with its client
    /// connected to nothing for ever.
    #[test]
    fn a_panic_on_the_sessions_thread_still_forgets_the_session_and_hangs_up() {
        let broker = Broker::new(Arc::new(PanickingEngine), Arc::new(pinned_web()), Arc::new(FakeKeys::new()), Arc::new(saved_password()), Arc::new(FakeConfirmer::default()));
        let dir = tempfile::Builder::new().prefix("sb").tempdir_in("/tmp").unwrap();
        crate::ipc::server::listen_unix(&dir.path().join("ipc"), broker.handler()).unwrap();
        let mut client = Client::connect(&dir.path().join("ipc").join("sock"));
        client.stream.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        client.open("web");
        assert!(client.next().is_none(), "the connection is closed");
        crate::ssh::testing::eventually("the session to be forgotten", 5, || !broker.has_sessions());
    }

    /// Plan 1b-1 review, Task 11 Minor 7: a session that could not be started, as when the thread for it cannot be made, is an error and
    /// an exit without a status, like every other session that could not be opened (spec §7.2). A client that is told only the error
    /// waits for the exit.
    #[test]
    fn a_session_that_could_not_be_started_is_an_error_and_an_exit_without_a_status() {
        let (mut ours, theirs) = UnixStream::pair().unwrap();
        ours.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        could_not_open(&FrameLink::new(theirs), kinds::CONNECT, "SSHelter could not start the session.");
        let mut told = Vec::new();
        while let Some(Frame::Control(payload)) = read_frame(&mut ours).unwrap() {
            told.push(decode::<ServerMessage>(&payload).unwrap());
            if told.len() == 2 {
                break;
            }
        }
        assert_eq!(told, [ServerMessage::Event(Event::Error { kind: kinds::CONNECT.into(), text: "SSHelter could not start the session.".into() }), no_status()]);
    }

    /// Texts a server chose can be larger than a frame (1 MiB): the text of a failure to connect, of a shell that cannot be opened and of a
    /// lost connection reaches the client cut to a sentence, with the exit after it. Left whole, the event does not fit in a frame and is
    /// not written, and the client learns that the session exited and not why.
    #[test]
    fn a_reason_larger_than_a_frame_still_reaches_the_client_cut_to_a_sentence() {
        let web = Hop::new("id-web", "web", "web.example.com", 22, "deploy", AuthMethod::Password);
        let huge = "x".repeat(2 * MAX_FRAME);
        let lost = DisconnectReason { hop: web.reference(), kind: DisconnectKind::Other, detail: huge.clone() };
        let engines = [
            ("a connect that fails", FakeEngine::new().failing_with(ConnectError::Protocol { hop: web.reference(), text: huge.clone() }), Some(kinds::CONNECT)),
            ("a shell that cannot be opened", FakeEngine::new().with_shell_error(SessionError::Channel(huge.clone())), Some(kinds::SHELL)),
            ("a connection that was lost", FakeEngine::new().disconnecting_with(lost), None),
        ];
        for (what, engine, kind) in engines {
            let world = world(engine);
            let mut client = Client::connect(&world.sock);
            client.open("web");
            let (_, messages) = client.rest();
            assert_eq!(messages.len(), 2, "{what}: the reason and the exit, and not the exit alone: {messages:?}");
            let (message_kind, text) = match &messages[0] {
                ServerMessage::Event(Event::Error { kind, text }) => (Some(kind.as_str()), text),
                ServerMessage::Event(Event::Disconnected { reason }) => (None, reason),
                other => panic!("{what}: expected a reason first, got {other:?}"),
            };
            assert_eq!(message_kind, kind, "{what}");
            assert!(text.ends_with("xxx…") && text.chars().count() == 513, "{what}: {} characters, ending in {:?}", text.chars().count(), &text[text.len().saturating_sub(8)..]);
            assert_eq!(messages[1], no_status(), "{what}");
        }
    }

    /// The app waits `QUIT_WAIT` in `end_all` when it quits: a shell that has not printed yet is closed (and its client told why) only
    /// once the settle time since it opened is over, so the wait has to be longer than that, with room for what comes after it.
    #[test]
    fn the_quit_wait_outlasts_the_settle_time_of_a_shell_that_has_not_printed() {
        assert_eq!(QUIT_WAIT, SETTLE + Duration::from_secs(2));
        let world = world(FakeEngine::new());
        let mut client = Client::connect(&world.sock);
        client.open("web");
        assert_eq!(client.next_message(), ServerMessage::Opened { session_id: "1".into() });
        let started = Instant::now();
        world.broker.end_all(QUIT_WAIT);
        assert!(started.elapsed() < QUIT_WAIT, "everything was over before the wait: {:?}", started.elapsed());
        assert!(started.elapsed() > Duration::from_secs(1), "(the shell had printed nothing, so it was kept open for the settle time: {:?})", started.elapsed());
        assert_eq!(client.ready_now(), told_quit(), "told by the time end_all returned");
        assert_eq!(world.engine.events().last(), Some(&FakeEvent::Closed));
    }

    /// A shell that is still being opened when the app quits cannot be hurried: the engine's call cannot be interrupted. `end_all` gives
    /// up when its time is over, and the client has not been told by then (the app exits, and its terminal says the connection ended).
    /// Were the process to go on, the client would hear why once the engine is through.
    #[test]
    fn end_all_gives_up_on_a_shell_that_is_still_being_opened_when_its_time_is_over() {
        let world = world_gated(FakeEngine::new().with_shell_output(b"$ "), pinned_web(), Arc::new(FakeConfirmer::default()), saved_password(), |gated| gated.holding_shells());
        let mut client = Client::connect(&world.sock);
        client.open("web");
        crate::ssh::testing::eventually("the shell to be being opened", 5, || world.gates.shell.entered() == 1);
        let started = Instant::now();
        world.broker.end_all(Duration::from_millis(300));
        assert!(started.elapsed() >= Duration::from_millis(300) && started.elapsed() < Duration::from_secs(3), "gave up when its time was over: {:?}", started.elapsed());
        assert!(world.broker.has_sessions(), "the session is still there");
        assert_eq!(client.ready_now(), (Vec::new(), false), "and its client has been told nothing");
        world.gates.shell.release();
        assert_eq!(client.rest(), (Vec::new(), vec![quit_sentence(), no_status()]));
    }

    /// Plan 1b-1 review round 2, Task 11 Minor 2: the thread for a session cannot be made. Its client is told so, unless the app quit
    /// meanwhile: `end_all` tells it that (and closes the connection), and a client is not told both.
    #[test]
    fn a_session_whose_thread_could_not_be_made_is_told_so_unless_the_app_is_quitting() {
        let world = world(FakeEngine::new());
        let query = HostQuery::Alias("web".into());

        let (conn, mut client) = conn_on_a_socket_pair(1);
        client.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        assert!(world.broker.enter(&conn, &query, None));
        world.broker.could_not_start(&conn);
        assert!(!world.broker.has_sessions());
        drop(conn);
        assert_eq!(
            written_to(&mut client),
            [ServerMessage::Event(Event::Error { kind: kinds::CONNECT.into(), text: "SSHelter could not start the session.".into() }), no_status()]
        );

        let (conn, mut client) = conn_on_a_socket_pair(2);
        client.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        assert!(world.broker.enter(&conn, &query, None));
        // The telling by `end_all` waits for the connection, which is busy: the entry is marked, and still there.
        let busy = locked(&conn.link.writer);
        world.broker.end_all(Duration::ZERO);
        let starting = {
            let (broker, conn) = (Arc::clone(&world.broker), conn.clone());
            std::thread::spawn(move || broker.could_not_start(&conn))
        };
        crate::ssh::testing::eventually("it to tell the client nothing, and so have nothing to wait for", 5, || starting.is_finished());
        assert!(world.broker.has_sessions(), "and the entry is left to the telling, which removes it");
        drop(busy);
        starting.join().unwrap();
        crate::ssh::testing::eventually("the entry to leave once its client was told", 5, || !world.broker.has_sessions());
        drop(conn);
        assert_eq!(written_to(&mut client), [quit_sentence(), no_status()], "told that the app quit, and not that the session could not be started as well");
    }

    /// Plan 1b-1 review, Task 11 Minor 8: a server's keyboard-interactive prompt too large for a frame cannot be shown, and nobody
    /// cancelled it: the login ends, and the client is told what happened, and not that the prompt was cancelled.
    #[test]
    fn a_prompt_too_large_to_send_ends_the_login_as_one_that_could_not_be_shown() {
        let directory = FakeDirectory::new().with_host("web", AuthMethod::Interactive).with_pin("web", default_server_key());
        let engine = FakeEngine::new().with_login(FakeLogin::Server(FakeMethods::interactive(&"x".repeat(MAX_FRAME), "answer")));
        let world = world_with(engine, directory, Arc::new(FakeConfirmer::default()), MemKeychain::default());
        let mut client = Client::connect(&world.sock);
        client.open("web");
        assert_eq!(
            client.rest().1,
            [
                ServerMessage::Event(Event::Error { kind: kinds::AUTH.into(), text: "Authentication for web was abandoned (the prompt could not be shown).".into() }),
                no_status(),
            ]
        );
        // A prompt that was cancelled, by the person, still reads so (spec §11).
        let world = world_with(
            FakeEngine::new().with_login(FakeLogin::Server(FakeMethods::interactive("Password: ", "answer"))),
            FakeDirectory::new().with_host("web", AuthMethod::Interactive).with_pin("web", default_server_key()),
            Arc::new(FakeConfirmer::default()),
            MemKeychain::default(),
        );
        let mut client = Client::connect(&world.sock);
        client.open("web");
        let ServerMessage::Question(question) = client.next_message() else { panic!("expected the prompt") };
        client.answer(&question.question_id, None);
        assert_eq!(
            client.rest().1,
            [
                ServerMessage::Event(Event::Error { kind: kinds::AUTH.into(), text: "Authentication for web was abandoned (the prompt was cancelled).".into() }),
                no_status(),
            ]
        );
    }

    /// Plan 1b-1 review, Task 11 Minor 9: who asked for a session is worked out once, when the connection is accepted, from the pid of the
    /// peer (spec §7.2): its process chain without SSHelter's own executable. A client of this test is this process.
    #[test]
    fn a_session_records_who_asked_for_it_from_the_pid_of_the_peer() {
        let world = world(FakeEngine::new());
        let mut client = Client::connect(&world.sock);
        client.open("web");
        assert_eq!(client.next_message(), ServerMessage::Opened { session_id: "1".into() });
        let recorded = world.broker.sessions()[0].requested_by.clone();
        assert_eq!(recorded, requester_of(Some(std::process::id())), "the chain of the pid the server saw on the other end, which is ours");
        if let Some(chain) = recorded {
            let own = std::env::current_exe().unwrap();
            let own_name = own.file_name().unwrap().to_string_lossy().to_string();
            assert!(!chain.is_empty() && chain.iter().all(|name| !own_name.starts_with(name.as_str()) && !name.starts_with(own_name.as_str())), "this test's own executable is not in {chain:?}");
        }
        assert_eq!(requester_of(None), None, "a peer whose pid is not known is not guessed");
        assert_eq!(requester_of(Some(u32::MAX)), None, "nor one whose process cannot be read");
    }

    /// A client whose host key waits in the app's window when the app quits: the window is told its question is withdrawn, and the client
    /// is told why, like one at a question of its own.
    #[test]
    fn a_client_waiting_for_the_host_key_window_is_told_why_and_the_window_is_released_when_the_app_quits() {
        let confirmer = Arc::new(WaitingConfirmer::default());
        let world = world_with(FakeEngine::new(), FakeDirectory::new().with_host("web", AuthMethod::Password), Arc::clone(&confirmer) as Arc<dyn HostKeyConfirmer>, MemKeychain::default());
        let mut client = Client::connect(&world.sock);
        client.open("web");
        let ServerMessage::Question(question) = client.next_message() else { panic!("expected the password question") };
        client.answer(&question.question_id, Some("typed"));
        let ServerMessage::Question(notice) = client.next_message() else { panic!("expected the notice about the window") };
        assert_eq!(notice.kind, QuestionKind::HostKeyNotice);
        crate::ssh::testing::eventually("the window to be asked", 5, || *locked(&confirmer.asked) == 1);
        assert!(world.broker.has_sessions(), "a client waiting for the window has a session");
        world.broker.end_all(Duration::from_secs(5));
        assert_eq!(client.rest().1, [quit_sentence(), no_status()]);
        // The window is released by the session's own thread, which `end_all` does not wait for.
        crate::ssh::testing::eventually("the window to be told its question is withdrawn", 5, || *locked(&confirmer.withdrawn));
        assert!(world.engine.events().is_empty(), "nothing was connected");
    }

    /// The app quits under a real shell on a scratch OpenSSH: the shell is closed once it has printed its prompt, the client is told why
    /// (it did not hear of a lost connection or an exit status), and the session is gone.
    #[test]
    fn quitting_ends_a_real_shell_on_a_scratch_sshd_and_tells_the_client_why() {
        let Some(tools) = crate::ssh::testing::harness::tools() else { return };
        let server = crate::ssh::testing::fixture::Server::start(&tools, &["ForceCommand if [ -n \"$SSH_ORIGINAL_COMMAND\" ]; then eval \"$SSH_ORIGINAL_COMMAND\"; else exec /bin/sh; fi"]);
        let directory = Arc::new(FakeDirectory::new().with_hop(server.hop_with("lab", server.sshd.port, AuthMethod::Key { key_id: "k1".into() })));
        let broker = Broker::new(
            Arc::new(crate::ssh::russh_engine::RusshEngine::new()),
            Arc::clone(&directory) as Arc<dyn HostDirectory>,
            Arc::new(FakeKeys::new().with_key("k1", "lab key", &server.key.private_text)),
            Arc::new(MemKeychain::default()),
            Arc::new(FakeConfirmer::deciding(vec![Decision::Trust])),
        );
        let dir = tempfile::Builder::new().prefix("sb").tempdir_in("/tmp").unwrap();
        crate::ipc::server::listen_unix(&dir.path().join("ipc"), broker.handler()).unwrap();
        let mut client = Client::connect(&dir.path().join("ipc").join("sock"));
        client.open("lab");
        assert!(matches!(client.next_message(), ServerMessage::Question(Question { kind: QuestionKind::HostKeyNotice, .. })));
        assert_eq!(client.next_message(), ServerMessage::Opened { session_id: "1".into() });
        let mut seen = Vec::new();
        while !String::from_utf8_lossy(&seen).contains("$ ") {
            match client.next() {
                Some(Got::Data(bytes)) => seen.extend(bytes),
                other => panic!("waiting for the prompt, got {other:?} after {:?}", String::from_utf8_lossy(&seen)),
            }
        }
        broker.end_all(Duration::from_secs(10));
        assert_eq!(
            client.rest().1,
            [ServerMessage::Event(Event::Disconnected { reason: "SSHelter quit, so the connection to lab was closed.".into() }), no_status()]
        );
        assert!(!broker.has_sessions());
    }
}
