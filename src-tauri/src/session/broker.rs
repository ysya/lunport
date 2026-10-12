//! The session broker (own-ssh spec §4, §7.2): it serves the clients that connect to the local IPC socket, one session per connection.
//! A connection says `hello`, asks for a shell (`open_shell`), and owns the session from then on: what the login needs is asked of it,
//! its keystrokes and resizes go to the shell, and when it goes away the session is closed. The connection's own thread reads it; a
//! second thread connects and pumps the shell. No read timeout applies once `hello` has arrived: an idle shell stays open for as long as
//! its terminal does.

use std::collections::{BTreeMap, HashMap};
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{self, RecvTimeoutError, SyncSender};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use zeroize::Zeroizing;

use super::auth::{KeyStore, Owner, Reply};
use super::connect::{CancelToken, Connector, HostKeyConfirmer, CANCELLED};
use super::directory::HostDirectory;
use super::protocol::{decode, kinds, read_frame, write_control, write_data, ClientKind, ClientMessage, Event, Frame, HostQuery, Question, QuestionKind, ServerMessage, PROTOCOL_VERSION};
use super::relay::{run_shell, ClientLink, ShellControl};
use crate::ipc::peer::{self, ProcInfo};
use crate::ipc::server::{Handler, Stream};
use crate::ssh::{HostId, Pty, SshEngine};
use crate::sync::env::Keychain;

fn locked<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

/// How long a new connection may take to say `hello`.
const HELLO_WAIT: Duration = Duration::from_secs(10);

/// The sentence a client is told when the app quits under its session (spec §4).
pub fn quit_reason(alias: &str) -> String {
    format!("SSHelter quit, so the connection to {alias} was closed.")
}

/// A session that is open: for the app (keep running while there are some, end them when quitting) and, in a later version, for the
/// list of sessions (spec §10).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SessionInfo {
    pub id: u64,
    pub alias: String,
    pub host_id: HostId,
    /// Who asked for it: the process chain of the client, outermost first, without SSHelter's own executable (spec §7.2); `None` when it
    /// could not be told. Recorded now, shown from phase 2 on.
    pub requested_by: Option<Vec<String>>,
    pub started_at_ms: u64,
}

struct Entry {
    info: SessionInfo,
    control: Arc<ShellControl>,
}

/// The broker. One per app; its handler serves the IPC socket.
pub struct Broker {
    engine: Arc<dyn SshEngine>,
    directory: Arc<dyn HostDirectory>,
    keys: Arc<dyn KeyStore>,
    keychain: Arc<dyn Keychain>,
    confirmer: Arc<dyn HostKeyConfirmer>,
    sessions: Mutex<BTreeMap<u64, Entry>>,
    /// Notified whenever a session leaves `sessions` (`end_all` waits on it).
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
        Arc::new(Broker { engine, directory, keys, keychain, confirmer, sessions: Mutex::new(BTreeMap::new()), changed: Condvar::new(), next_id: AtomicU64::new(0) })
    }

    /// The IPC server's handler: each connection is served on the thread the server gives it.
    pub fn handler(self: &Arc<Broker>) -> Handler {
        let broker = Arc::clone(self);
        Arc::new(move |stream, pid| broker.serve(stream, pid))
    }

    /// The sessions that are open now, oldest first.
    pub fn sessions(&self) -> Vec<SessionInfo> {
        locked(&self.sessions).values().map(|entry| entry.info.clone()).collect()
    }

    pub fn has_sessions(&self) -> bool {
        !locked(&self.sessions).is_empty()
    }

    /// The app is quitting (spec §4): every session ends, its client told why. Waits up to `wait` for them to close (each closes its own
    /// shell and connection on its own thread).
    pub fn end_all(&self, wait: Duration) {
        let entries: Vec<(String, Arc<ShellControl>)> = locked(&self.sessions).values().map(|entry| (entry.info.alias.clone(), Arc::clone(&entry.control))).collect();
        for (alias, control) in entries {
            std::thread::spawn(move || control.end(&quit_reason(&alias)));
        }
        let deadline = Instant::now() + wait;
        let mut sessions = locked(&self.sessions);
        while !sessions.is_empty() {
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                break;
            }
            sessions = self.changed.wait_timeout(sessions, left).unwrap_or_else(PoisonError::into_inner).0;
        }
    }

    /// Serves one client connection until it ends (the thread the IPC server gives it).
    pub fn serve(self: &Arc<Broker>, stream: Stream, pid: Option<u32>) {
        let Ok(writer) = stream.try_clone() else { return };
        let link = Arc::new(FrameLink { writer: Mutex::new(writer) });
        let mut reader = stream;
        let refuse = |kind: &str, text: &str| {
            let _ = link.send(&ServerMessage::Event(Event::Error { kind: kind.to_string(), text: text.to_string() }));
        };
        // `hello` first, within a short time; from then on no read timeout (an idle shell is not a dead client).
        let _ = set_read_timeout(&reader, Some(HELLO_WAIT));
        match next_message(&mut reader) {
            Some(ClientMessage::Hello { client: ClientKind::Connect, version: PROTOCOL_VERSION, .. }) => {}
            Some(ClientMessage::Hello { client: ClientKind::Mcp, .. }) => return refuse(kinds::UNSUPPORTED, "The MCP adapter cannot use SSHelter's sessions yet."),
            Some(ClientMessage::Hello { version, .. }) => {
                return refuse(
                    kinds::PROTOCOL,
                    &format!("This sshelter speaks protocol {version} and the SSHelter that is running speaks {PROTOCOL_VERSION}. Quit SSHelter and open it again."),
                )
            }
            Some(_) => return refuse(kinds::PROTOCOL, "The first message must be hello."),
            None => return,
        }
        let _ = set_read_timeout(&reader, None);
        let requested_by = requester_of(pid);
        let (host, pty) = match next_message(&mut reader) {
            Some(ClientMessage::OpenShell { host, pty }) => (host, pty),
            Some(ClientMessage::Exec {}) => return refuse(kinds::UNSUPPORTED, "Running a command through SSHelter's sessions is not supported yet."),
            Some(_) => return refuse(kinds::PROTOCOL, "SSHelter expected open_shell."),
            None => return,
        };
        let owner = Arc::new(ConnectionOwner { link: Arc::clone(&link), questions: Mutex::new(HashMap::new()), next_question: AtomicU64::new(0) });
        let control = Arc::new(ShellControl::new());
        let cancel = CancelToken::default();
        control.resize(pty.cols, pty.rows);
        let Ok(closer) = reader.try_clone() else { return };
        let worker = {
            let (broker, owner, control, cancel, link) = (Arc::clone(self), Arc::clone(&owner), Arc::clone(&control), cancel.clone(), Arc::clone(&link));
            let pty = Pty { term: pty.term, cols: pty.cols, rows: pty.rows };
            let id = self.next_id.fetch_add(1, Ordering::SeqCst) + 1;
            std::thread::Builder::new().name("sshelter-session".to_string()).spawn(move || {
                broker.run_session(id, &host, pty, owner.as_ref(), link.as_ref(), &control, &cancel, requested_by);
                // The session is over: the connection is closed, which ends the reader below and tells the client.
                hang_up(&closer);
            })
        };
        let Ok(worker) = worker else { return refuse(kinds::CONNECT, "SSHelter could not start the session.") };
        // The client's messages, until it closes or goes away.
        loop {
            match read_frame(&mut reader) {
                Ok(Some(Frame::Data(bytes))) => control.input(&bytes, link.as_ref()),
                Ok(Some(Frame::Control(payload))) => match decode::<ClientMessage>(&payload) {
                    Ok(ClientMessage::WindowChange { cols, rows }) => control.resize(cols, rows),
                    Ok(ClientMessage::Answer { question_id, value, cancel }) => owner.answer(&question_id, value, cancel),
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

    /// The session thread: connects, then runs the shell. A failure is told to the client (unless it is gone) as an error and an exit
    /// without a status.
    #[allow(clippy::too_many_arguments)]
    fn run_session(
        &self,
        id: u64,
        host: &HostQuery,
        pty: Pty,
        owner: &dyn Owner,
        link: &dyn ClientLink,
        control: &Arc<ShellControl>,
        cancel: &CancelToken,
        requested_by: Option<Vec<String>>,
    ) {
        let connector = Connector {
            engine: self.engine.as_ref(),
            directory: self.directory.as_ref(),
            keys: self.keys.as_ref(),
            keychain: self.keychain.as_ref(),
            confirmer: self.confirmer.as_ref(),
        };
        let connected = match connector.connect(host, owner, cancel) {
            Ok(connected) => connected,
            Err(failure) => {
                if failure.kind != CANCELLED && !control.is_gone() {
                    let _ = link.send(&ServerMessage::Event(Event::Error { kind: failure.kind, text: failure.text }));
                    let _ = link.send(&ServerMessage::Exited { code: None, signal: None });
                }
                return;
            }
        };
        let Some(destination) = connected.target.hops.last() else { return };
        let started_at_ms = SystemTime::now().duration_since(UNIX_EPOCH).map(|elapsed| elapsed.as_millis() as u64).unwrap_or(0);
        let info = SessionInfo { id, alias: destination.alias.clone(), host_id: destination.id.clone(), requested_by, started_at_ms };
        locked(&self.sessions).insert(id, Entry { info, control: Arc::clone(control) });
        run_shell(connected, pty, link, control, &id.to_string());
        locked(&self.sessions).remove(&id);
        self.changed.notify_all();
    }
}

/// `read_frame` and `decode` for the first messages; `None` for the end of the stream or anything that is not a control message.
fn next_message(reader: &mut Stream) -> Option<ClientMessage> {
    match read_frame(reader) {
        Ok(Some(Frame::Control(payload))) => decode(&payload).ok(),
        _ => None,
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

/// The client's connection, as the relay writes to it: whole frames under one lock.
struct FrameLink {
    writer: Mutex<Stream>,
}

impl ClientLink for FrameLink {
    fn send(&self, message: &ServerMessage) -> std::io::Result<()> {
        write_control(&mut *locked(&self.writer), message)
    }

    fn send_data(&self, bytes: &[u8]) -> std::io::Result<()> {
        write_data(&mut *locked(&self.writer), bytes)
    }
}

/// The owner of a session: its client. A question goes out as a `question` frame; the connection's reader delivers the answer.
struct ConnectionOwner {
    link: Arc<FrameLink>,
    /// The questions waiting for an answer, by id. Emptied when the client is gone, which wakes every waiting `ask` with `Gone`.
    questions: Mutex<HashMap<String, SyncSender<Reply>>>,
    next_question: AtomicU64,
}

impl ConnectionOwner {
    fn question_id(&self) -> String {
        format!("q{}", self.next_question.fetch_add(1, Ordering::SeqCst) + 1)
    }

    /// The client's answer to `question_id` (a late or unknown one is dropped).
    fn answer(&self, question_id: &str, value: Option<String>, cancel: bool) {
        let Some(waiting) = locked(&self.questions).remove(question_id) else { return };
        let reply = match value {
            Some(value) if !cancel => Reply::Answer(Zeroizing::new(value)),
            _ => Reply::Cancelled,
        };
        let _ = waiting.try_send(reply);
    }

    fn gone(&self) {
        locked(&self.questions).clear();
    }
}

impl Owner for ConnectionOwner {
    fn ask(&self, kind: QuestionKind, text: &str, echo: bool, deadline: Option<Instant>) -> Reply {
        let question_id = self.question_id();
        let (answer, answered) = mpsc::sync_channel(1);
        locked(&self.questions).insert(question_id.clone(), answer);
        let deadline_ms = deadline.map(|deadline| deadline.saturating_duration_since(Instant::now()).as_millis() as u64);
        let question = Question { question_id: question_id.clone(), kind, text: text.to_string(), echo, deadline_ms };
        if self.link.send(&ServerMessage::Question(question)).is_err() {
            locked(&self.questions).remove(&question_id);
            return Reply::Gone;
        }
        let reply = match deadline {
            None => answered.recv().map_err(|_| RecvTimeoutError::Disconnected),
            Some(deadline) => answered.recv_timeout(deadline.saturating_duration_since(Instant::now())),
        };
        match reply {
            Ok(reply) => reply,
            Err(RecvTimeoutError::Timeout) => {
                locked(&self.questions).remove(&question_id);
                Reply::TimedOut
            }
            Err(RecvTimeoutError::Disconnected) => Reply::Gone,
        }
    }

    fn host_key_notice(&self, text: &str) {
        let question = Question { question_id: self.question_id(), kind: QuestionKind::HostKeyNotice, text: text.to_string(), echo: false, deadline_ms: None };
        let _ = self.link.send(&ServerMessage::Question(question));
    }

    fn banner(&self, text: &str) {
        let _ = self.link.send(&ServerMessage::Event(Event::Banner { text: text.to_string() }));
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
    use crate::session::protocol::{read_frame, write_control, write_data, Frame, PtyRequest, QuestionKind};
    use crate::session::testing::{locked, Decision, FakeConfirmer, FakeDirectory, FakeKeys, WaitingConfirmer};
    use crate::ssh::fake::{default_server_key, FakeEngine, FakeEvent, FakeLogin, FakeMethods, FakeShell};
    use crate::ipc::peer::ProcInfo;
    use crate::ssh::{AuthMethod, Exit};
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
    }

    struct World {
        broker: Arc<Broker>,
        engine: Arc<FakeEngine>,
        directory: Arc<FakeDirectory>,
        sock: std::path::PathBuf,
        _dir: tempfile::TempDir,
    }

    /// A broker over `engine`, `directory` and `confirmer`, listening on a socket in a short temp directory (macOS limits socket paths).
    fn world_with(engine: FakeEngine, directory: FakeDirectory, confirmer: Arc<dyn HostKeyConfirmer>, keychain: MemKeychain) -> World {
        let (engine, directory) = (Arc::new(engine), Arc::new(directory));
        let broker = Broker::new(
            Arc::clone(&engine) as Arc<dyn SshEngine>,
            Arc::clone(&directory) as Arc<dyn HostDirectory>,
            Arc::new(FakeKeys::new()),
            Arc::new(keychain),
            confirmer,
        );
        let dir = tempfile::Builder::new().prefix("sb").tempdir_in("/tmp").unwrap();
        let ipc = dir.path().join("ipc");
        assert_eq!(crate::ipc::server::listen_unix(&ipc, broker.handler()).unwrap(), crate::ipc::server::Started::Running);
        World { broker, engine, directory, sock: ipc.join("sock"), _dir: dir }
    }

    /// `web` is pinned and its password is saved: it connects without a question.
    fn world(engine: FakeEngine) -> World {
        let keychain = MemKeychain::default();
        keychain.set("host:id-web", "saved").unwrap();
        world_with(engine, FakeDirectory::new().with_host("web", AuthMethod::Password).with_pin("web", default_server_key()), Arc::new(FakeConfirmer::default()), keychain)
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
        assert_eq!((sessions[0].id, sessions[0].alias.as_str(), sessions[0].host_id.as_str()), (1, "web", "id-web"));
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
        let ServerMessage::Question(_) = client.next_message() else { panic!("expected the password question") };
        // The password is asked first (the hop starts with it); the host key comes next.
        drop(client);
        crate::ssh::testing::eventually("the connect to give up", 10, || !world.broker.has_sessions() && *locked(&confirmer.asked) <= 1);
        assert!(world.engine.events().is_empty(), "nothing was connected");
    }

    /// The IPC server gives every connection a read timeout (an agent connection that idles is dropped); a session must not inherit it.
    #[test]
    fn an_idle_session_is_not_ended_by_a_read_timeout() {
        let world = world(FakeEngine::new());
        let (mut ours, theirs) = UnixStream::pair().unwrap();
        theirs.set_read_timeout(Some(Duration::from_millis(200))).unwrap();
        let broker = Arc::clone(&world.broker);
        std::thread::spawn(move || broker.serve(theirs, None));
        write_control(&mut ours, &ClientMessage::Hello { client: ClientKind::Connect, version: PROTOCOL_VERSION, client_info: None }).unwrap();
        write_control(&mut ours, &ClientMessage::OpenShell { host: HostQuery::Alias("web".into()), pty: PtyRequest { cols: 80, rows: 24, term: "dumb".into() } }).unwrap();
        let mut client = Client { stream: ours };
        client.stream.set_read_timeout(Some(Duration::from_secs(15))).unwrap();
        assert_eq!(client.next_message(), ServerMessage::Opened { session_id: "1".into() });
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
}
