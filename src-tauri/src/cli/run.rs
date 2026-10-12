//! The I/O of `sshelter connect` (own-ssh spec §7.3): the broker's frames are read on a thread of their own, the person's keys on
//! another, the signals (SIGWINCH, SIGINT, SIGTERM, SIGHUP, SIGQUIT) on a third with tokio's signal handling; everything meets in one
//! queue, and the client (`client.rs`) says what to do with each.

use std::collections::VecDeque;
use std::io::{Read, Write};
use std::os::fd::AsFd;
use std::os::unix::net::UnixStream;
use std::sync::mpsc::{Receiver, Sender};

use serde::Serialize;
use zeroize::{Zeroize, Zeroizing};

use super::client::{Action, Client, Input};
use super::terminal::Tty;
use crate::session::protocol::{decode, read_frame, write_control, write_data, write_frame, Frame, HostQuery, ServerMessage, CONTROL};

/// Runs one session over `stream`, connected to the broker, until it ends; returns the program's exit code. `inputs` brings the keys,
/// resizes and signals (`stdin_thread`, `signal_thread`); the broker's frames join it from a thread started here.
pub fn run(stream: UnixStream, host: HostQuery, term: String, tty: &mut Tty, inputs: (Sender<Input>, Receiver<Input>), stdout: &mut dyn Write, stderr: &mut dyn Write) -> i32 {
    let (sender, receiver) = inputs;
    let size = tty.size().unwrap_or((80, 24));
    let Ok(mut reader) = stream.try_clone() else {
        let _ = writeln!(stderr, "The connection to SSHelter failed.");
        return 255;
    };
    let mut writer = stream;
    spawn_worker("sshelter-broker", sender, move |sender| loop {
        let input = match read_frame(&mut reader) {
            Ok(Some(Frame::Control(payload))) => match decode::<ServerMessage>(&payload) {
                Ok(message) => Input::Message(message),
                Err(_) => continue,
            },
            Ok(Some(Frame::Data(bytes))) => Input::Output(bytes.to_vec()),
            Ok(None) | Err(_) => Input::Closed,
        };
        let closed = matches!(input, Input::Closed);
        if sender.send(input).is_err() || closed {
            return;
        }
    });
    let (mut client, actions) = Client::start(host, term, size);
    let mut queue = Queue::new(receiver);
    if let Some(code) = perform(actions, &mut writer, tty, &mut queue, stdout, stderr) {
        return code;
    }
    while let Some(input) = queue.next() {
        let actions = client.handle(input);
        if let Some(code) = perform(actions, &mut writer, tty, &mut queue, stdout, stderr) {
            return code;
        }
    }
    255
}

/// What the loop reads from: the queue the three threads fill, and what the loop took out of it to look at and put back in front.
struct Queue {
    receiver: Receiver<Input>,
    kept: VecDeque<Input>,
}

impl Queue {
    fn new(receiver: Receiver<Input>) -> Queue {
        Queue { receiver, kept: VecDeque::new() }
    }

    /// The next input, in the order it was queued; `None` once every thread that fills the queue is gone.
    fn next(&mut self) -> Option<Input> {
        self.kept.pop_front().or_else(|| self.receiver.recv().ok())
    }

    /// Throws away what the person typed and the stdin thread has already queued; everything else stays, in order. (What is thrown away is
    /// wiped as it is dropped, see `Input::Stdin`.) A question switches the terminal with `TCSAFLUSH`, which throws away what the
    /// terminal has not delivered yet, but a line the stdin thread had read before that is in the queue (behind the question), where the
    /// flush cannot reach it and the question would take it as its answer. A line the thread has read but not queued yet at this
    /// moment is not caught: it arrives after, as typed text.
    fn forget_typed(&mut self) {
        while let Ok(input) = self.receiver.try_recv() {
            self.kept.push_back(input);
        }
        self.kept.retain(|input| !matches!(input, Input::Stdin(_)));
    }
}

/// Does what the client said, in order; `Some(code)` when it is time to exit. A broker that no longer takes what is sent is a broker that
/// went away: its end of the connection arrives as `Input::Closed` from the reader.
fn perform(actions: Vec<Action>, writer: &mut UnixStream, tty: &mut Tty, queue: &mut Queue, stdout: &mut dyn Write, stderr: &mut dyn Write) -> Option<i32> {
    for action in actions {
        match action {
            Action::Send(message) => {
                let _ = write_control(writer, &message);
            }
            Action::Answer { question_id, value } => {
                // The password stays in `value`, which is wiped as it is dropped at the end of this arm; `write_answer` wipes the rest.
                let _ = write_answer(writer, &question_id, &value);
            }
            Action::SendData(mut bytes) => {
                let _ = write_data(writer, &bytes);
                // Keystrokes can be a password too (typed at a prompt the shell shows).
                bytes.zeroize();
            }
            Action::Stdout(bytes) => {
                let _ = stdout.write_all(&bytes);
                let _ = stdout.flush();
            }
            Action::Stderr(text) => {
                let _ = stderr.write_all(text.as_bytes());
                let _ = stderr.flush();
            }
            Action::Mode(mode, discard_input) => {
                if let Err(error) = tty.set_mode(mode, discard_input) {
                    let _ = writeln!(stderr, "sshelter: cannot set the terminal: {error}");
                }
                if discard_input {
                    queue.forget_typed();
                }
            }
            Action::Exit(code) => {
                tty.restore();
                return Some(code);
            }
        }
    }
    None
}

/// The protocol's answer message (`ClientMessage::Answer` with a value) written from borrowed strings, so that the password is not
/// copied into a message that would have to be wiped; `an_answer_is_the_protocols_message_byte_for_byte_and_fits_the_buffer_it_is_built_in`
/// keeps the two the same.
#[derive(Serialize)]
struct AnswerJson<'a> {
    #[serde(rename = "type")]
    kind: &'static str,
    question_id: &'a str,
    value: &'a str,
    cancel: bool,
}

/// How many bytes the JSON of an answer can take: a byte of either string takes six at most (`\u00XX`), the rest of the message 60.
fn answer_room(question_id: &str, value: &str) -> usize {
    64 + 6 * (question_id.len() + value.len())
}

/// The JSON of an answer. It is built in a buffer that has room for all of it from the start, because a `Vec` that grows frees its old
/// allocation with a part of the password in it, and the buffer is wiped when it is dropped.
fn answer_json(question_id: &str, value: &str) -> std::io::Result<Zeroizing<Vec<u8>>> {
    let mut json = Zeroizing::new(Vec::with_capacity(answer_room(question_id, value)));
    serde_json::to_writer(&mut *json, &AnswerJson { kind: "answer", question_id, value, cancel: false })?;
    Ok(json)
}

/// Writes the answer to a question as one control frame. The password is in three places for a moment: the caller's string (wiped by
/// whoever owns it), the JSON (wiped here) and the frame `write_frame` builds from it (wiped there).
fn write_answer(writer: &mut impl Write, question_id: &str, value: &str) -> std::io::Result<()> {
    write_frame(writer, CONTROL, &answer_json(question_id, value)?)
}

/// Reads the person's keys into the queue until standard input ends (or the program does).
pub fn stdin_thread(sender: Sender<Input>) {
    // Not through `std::io::stdin()`: its buffer keeps a copy of what is read through it, for as long as the program runs, unless the
    // read is at least as large as that buffer (8 KiB; measured: a read of 8191 bytes leaves what was typed in it, one of 8192 does
    // not), and what is typed can be a password. A duplicate of the descriptor is read directly, with no buffer of std's in between.
    match std::io::stdin().as_fd().try_clone_to_owned() {
        Ok(descriptor) => keys_thread(std::fs::File::from(descriptor), sender),
        Err(_) => keys_thread(std::io::stdin(), sender),
    }
}

/// `read_keys` on a thread of its own.
fn keys_thread(source: impl Read + Send + 'static, sender: Sender<Input>) {
    spawn_worker("sshelter-keys", sender, move |sender| read_keys(source, &sender));
}

/// Queues what `source` (the terminal) delivers, as typed text; a read of nothing is the end of input (Ctrl-D), and a failed one is
/// the end of the terminal. Returns when the terminal failed or the loop is gone.
fn read_keys(mut source: impl Read, sender: &Sender<Input>) {
    let mut buf = [0u8; 4096];
    loop {
        let input = match source.read(&mut buf) {
            // A question ends on Ctrl-D; the next question reads again.
            Ok(0) => Input::StdinEnd,
            Ok(count) => {
                let typed = Input::Stdin(Zeroizing::new(buf[..count].to_vec()));
                // What was typed may be a password: the copy that stays on this stack is wiped as well.
                buf[..count].zeroize();
                typed
            }
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(_) => {
                let _ = sender.send(Input::StdinEnd);
                return;
            }
        };
        if sender.send(input).is_err() {
            return;
        }
    }
}

/// Starts `work` on a thread of its own. If that thread panics (the panic hook has put the terminal back by then), or cannot be started,
/// the queue is told (`Input::Failed`) and the program ends: the loop would otherwise go on, in the mode the terminal was in, with nobody
/// reading the keys or the signals or the broker.
fn spawn_worker(name: &str, sender: Sender<Input>, work: impl FnOnce(Sender<Input>) + Send + 'static) {
    let failed = sender.clone();
    let started = std::thread::Builder::new().name(name.to_string()).spawn(move || {
        let _watch = Watch(sender.clone());
        work(sender);
    });
    if started.is_err() {
        let _ = failed.send(Input::Failed);
    }
}

/// Dropped by a thread that is unwinding from a panic, it tells the queue.
struct Watch(Sender<Input>);

impl Drop for Watch {
    fn drop(&mut self) {
        if std::thread::panicking() {
            let _ = self.0.send(Input::Failed);
        }
    }
}

/// What the queue is told when `signal` stops the program or cancels a question: Ctrl-C cancels the question on the terminal (and ends
/// the program when there is none); every other signal ends it, with the number its exit status (128 + n) is made of.
fn input_for(signal: i32) -> Input {
    if signal == libc::SIGINT {
        Input::Interrupt
    } else {
        Input::Stop(signal)
    }
}

/// Turns the signals into inputs: a resize (SIGWINCH, read with `size`), Ctrl-C (SIGINT), Ctrl-backslash (SIGQUIT), and the end of the
/// terminal or a request to stop (SIGHUP, SIGTERM). A question keeps `ISIG` on (Ctrl-C cancels it), so Ctrl-backslash at a hidden
/// password would deliver SIGQUIT too, and its default action ends the program with echo still off: neither the panic hook nor `Drop`
/// run on a signal. With handlers in place none of them ends the program on its own: the client decides, and the terminal is put back
/// first.
pub fn signal_thread(sender: Sender<Input>, size: impl Fn() -> Option<(u16, u16)> + Send + 'static) -> std::io::Result<()> {
    use tokio::signal::unix::{signal, SignalKind};
    let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build()?;
    // The handlers are installed here, before the thread runs: a signal that comes right after this returns finds them in place.
    let (mut resize, mut interrupt, mut terminate, mut hangup, mut quit) = runtime.block_on(async {
        Ok::<_, std::io::Error>((
            signal(SignalKind::window_change())?,
            signal(SignalKind::interrupt())?,
            signal(SignalKind::terminate())?,
            signal(SignalKind::hangup())?,
            signal(SignalKind::quit())?,
        ))
    })?;
    spawn_worker("sshelter-signals", sender, move |sender| {
        runtime.block_on(async move {
            loop {
                let input = tokio::select! {
                    _ = resize.recv() => match size() {
                        Some((cols, rows)) => Input::Resize(cols, rows),
                        None => continue,
                    },
                    _ = interrupt.recv() => input_for(libc::SIGINT),
                    _ = terminate.recv() => input_for(libc::SIGTERM),
                    _ = hangup.recv() => input_for(libc::SIGHUP),
                    _ = quit.recv() => input_for(libc::SIGQUIT),
                };
                if sender.send(input).is_err() {
                    return;
                }
            }
        })
    });
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use super::*;
    use crate::cli::terminal::fake::FakeTermios;
    use crate::cli::terminal::TermiosApi;
    use crate::session::broker::Broker;
    use crate::session::connect::HostKeyConfirmer;
    use crate::session::directory::HostDirectory;
    use crate::session::testing::{FakeConfirmer, FakeDirectory, FakeKeys};
    use crate::ssh::fake::{default_server_key, FakeEngine, FakeEvent, FakeLogin, FakeMethods};
    use crate::ssh::testing::eventually;
    use crate::ssh::{AuthMethod, Exit, SshEngine};
    use crate::sync::env::Keychain;
    use crate::sync::testkit::MemKeychain;

    /// A `Write` the test can read while the run goes on.
    #[derive(Clone, Default)]
    struct Shared(Arc<Mutex<Vec<u8>>>);

    impl Write for Shared {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl Shared {
        fn text(&self) -> String {
            String::from_utf8_lossy(&self.0.lock().unwrap()).into_owned()
        }
    }

    struct Setup {
        engine: Arc<FakeEngine>,
        termios: Arc<FakeTermios>,
        keys: Sender<Input>,
        stdout: Shared,
        stderr: Shared,
        run: std::thread::JoinHandle<i32>,
    }

    /// A terminal that, when the CLI switches it to a question's prompt mode and throws the typeahead away (`TCSAFLUSH`), has a line
    /// arrive in the queue: one the stdin thread had read and queued just before the flush, behind the question.
    struct FeedsAtFlush {
        inner: Arc<FakeTermios>,
        queue: Sender<Input>,
        line: Mutex<Option<Vec<u8>>>,
    }

    impl TermiosApi for FeedsAtFlush {
        fn get(&self) -> std::io::Result<libc::termios> {
            self.inner.get()
        }
        fn set(&self, termios: &libc::termios, discard_input: bool) -> std::io::Result<()> {
            if discard_input {
                if let Some(line) = self.line.lock().unwrap().take() {
                    self.queue.send(Input::Stdin(Zeroizing::new(line))).unwrap();
                }
            }
            self.inner.set(termios, discard_input)
        }
        fn size(&self) -> Option<(u16, u16)> {
            self.inner.size()
        }
    }

    /// `sshelter connect web` against a broker over `engine` and `directory`, on the other end of a socket pair, with a fake terminal.
    fn connect(engine: FakeEngine, directory: FakeDirectory, keychain: MemKeychain) -> Setup {
        connect_typing_ahead(engine, directory, keychain, None)
    }

    /// `connect`, and `typed_ahead` arrives in the queue as the terminal is flushed for the first question.
    fn connect_typing_ahead(engine: FakeEngine, directory: FakeDirectory, keychain: MemKeychain, typed_ahead: Option<&[u8]>) -> Setup {
        let engine = Arc::new(engine);
        let broker = Broker::new(
            Arc::clone(&engine) as Arc<dyn SshEngine>,
            Arc::new(directory) as Arc<dyn HostDirectory>,
            Arc::new(FakeKeys::new()),
            Arc::new(keychain) as Arc<dyn Keychain>,
            Arc::new(FakeConfirmer::default()) as Arc<dyn HostKeyConfirmer>,
        );
        let (ours, theirs) = UnixStream::pair().unwrap();
        std::thread::spawn(move || broker.serve(theirs, None));
        let termios = FakeTermios::new();
        let (sender, receiver) = std::sync::mpsc::channel();
        let (stdout, stderr) = (Shared::default(), Shared::default());
        let terminal: Arc<dyn TermiosApi> = match typed_ahead {
            Some(line) => Arc::new(FeedsAtFlush { inner: Arc::clone(&termios), queue: sender.clone(), line: Mutex::new(Some(line.to_vec())) }),
            None => Arc::clone(&termios) as Arc<dyn TermiosApi>,
        };
        let run = {
            let (sender, mut stdout, mut stderr) = (sender.clone(), stdout.clone(), stderr.clone());
            std::thread::spawn(move || {
                let mut tty = Tty::new(terminal).unwrap();
                run(ours, HostQuery::Alias("web".into()), "xterm-256color".into(), &mut tty, (sender, receiver), &mut stdout, &mut stderr)
            })
        };
        Setup { engine, termios, keys: sender, stdout, stderr, run }
    }

    fn finish(setup: Setup) -> (i32, Setup) {
        eventually("the run to end", 10, || setup.run.is_finished());
        let Setup { engine, termios, keys, stdout, stderr, run } = setup;
        let code = run.join().unwrap();
        (code, Setup { engine, termios, keys, stdout, stderr, run: std::thread::spawn(|| 0) })
    }

    fn raw(termios: &FakeTermios) -> bool {
        termios.now().c_lflag & libc::ICANON == 0
    }

    #[test]
    fn the_cli_opens_a_shell_relays_keys_and_output_and_exits_with_the_shells_status() {
        let keychain = MemKeychain::default();
        keychain.set("host:id-web", "saved").unwrap();
        let setup = connect(FakeEngine::new(), FakeDirectory::new().with_host("web", AuthMethod::Password).with_pin("web", default_server_key()), keychain);
        eventually("the terminal to be raw", 10, || raw(&setup.termios));
        setup.keys.send(Input::Stdin(Zeroizing::new(b"ls\r".to_vec()))).unwrap();
        eventually("the keys to reach the shell", 10, || setup.engine.events().contains(&FakeEvent::ShellInput(b"ls\r".to_vec())));
        let remote = setup.engine.shells().remove(0);
        remote.print(b"file.txt\r\n");
        eventually("the output to reach the terminal", 10, || setup.stdout.text() == "file.txt\r\n");
        setup.keys.send(Input::Resize(100, 30)).unwrap();
        eventually("the resize to reach the shell", 10, || setup.engine.events().contains(&FakeEvent::WindowChange { cols: 100, rows: 30 }));
        remote.end(Exit::Code(3));
        let (code, setup) = finish(setup);
        assert_eq!(code, 3);
        assert!(setup.termios.is_start(&setup.termios.now()), "the terminal is as it was");
        assert_eq!(setup.stderr.text(), "");
    }

    #[test]
    fn a_question_is_asked_at_the_terminal_and_the_answer_gets_in() {
        let directory = FakeDirectory::new().with_host("web", AuthMethod::Key { key_id: "k-plain".into() }).with_pin("web", default_server_key());
        let setup = connect(FakeEngine::new().with_login(FakeLogin::Server(FakeMethods::password("right"))), directory, MemKeychain::default());
        eventually("the question", 10, || setup.stderr.text() == "deploy@web's password: ");
        let prompt = setup.termios.sets.lock().unwrap().last().copied().unwrap();
        assert!(prompt.1, "typeahead thrown away");
        assert_eq!((prompt.0.c_lflag & libc::ECHO, prompt.0.c_lflag & libc::ICANON), (0, libc::ICANON), "no echo, line editing on");
        setup.keys.send(Input::Stdin(Zeroizing::new(b"right\n".to_vec()))).unwrap();
        eventually("the shell to open", 10, || raw(&setup.termios));
        setup.engine.shells().remove(0).end(Exit::Code(0));
        let (code, setup) = finish(setup);
        assert_eq!((code, setup.stderr.text()), (0, "deploy@web's password: \n".to_string()));
    }

    #[test]
    fn a_host_that_cannot_be_reached_is_said_and_the_status_is_255() {
        let setup = connect(FakeEngine::new(), FakeDirectory::new(), MemKeychain::default());
        let (code, setup) = finish(setup);
        assert_eq!((code, setup.stderr.text()), (255, "No saved host is called web.\n".to_string()));
        assert_eq!(setup.termios.sets.lock().unwrap().iter().filter(|(termios, _)| !setup.termios.is_start(termios)).count(), 0, "the terminal was never changed");
    }

    /// The terminal is closed (SIGHUP) while the shell runs: the CLI tells the broker, puts the terminal back and ends; the broker closes
    /// the session.
    #[test]
    fn a_closed_terminal_ends_the_session() {
        let keychain = MemKeychain::default();
        keychain.set("host:id-web", "saved").unwrap();
        let setup = connect(FakeEngine::new(), FakeDirectory::new().with_host("web", AuthMethod::Password).with_pin("web", default_server_key()), keychain);
        eventually("the terminal to be raw", 10, || raw(&setup.termios));
        setup.engine.shells().remove(0).print(b"$ ");
        setup.keys.send(Input::Stop(libc::SIGHUP)).unwrap();
        let (code, setup) = finish(setup);
        assert_eq!(code, 128 + libc::SIGHUP);
        assert!(setup.termios.is_start(&setup.termios.now()));
        eventually("the session to be closed", 10, || setup.engine.events().contains(&FakeEvent::Closed));
    }

    /// Every signal the CLI takes over becomes the input that ends the session the way a shell would report it: the terminal is put back
    /// first, the broker is told, and the status is 128 + the signal's number (131 for SIGQUIT, which Ctrl-backslash sends at a question).
    #[test]
    fn each_signal_the_cli_takes_over_ends_the_session_with_128_plus_its_number() {
        use crate::cli::client::Client;
        use crate::cli::terminal::Mode;
        use crate::session::protocol::{ClientMessage, ServerMessage};
        assert_eq!(128 + libc::SIGQUIT, 131);
        for (signal, status) in [(libc::SIGINT, 130), (libc::SIGTERM, 143), (libc::SIGHUP, 129), (libc::SIGQUIT, 131)] {
            let (mut client, _) = Client::start(HostQuery::Alias("web".into()), "xterm-256color".into(), (80, 24));
            client.handle(Input::Message(ServerMessage::Opened { session_id: "1".into() }));
            assert_eq!(client.handle(input_for(signal)), [Action::Mode(Mode::Cooked, false), Action::Send(ClientMessage::Close), Action::Exit(status)], "signal {signal}");
        }
    }

    /// The handlers are process-wide and stay for the life of the process, so the test that raises the signals for real runs alone, in a
    /// process of its own (`rerun_alone`); a signal that was not taken over would end that process, and the test with it.
    #[test]
    fn the_signals_the_cli_takes_over_reach_the_queue_instead_of_ending_the_program() {
        use crate::ssh::testing::{is_child, rerun_alone};
        const NAME: &str = "cli::run::tests::the_signals_the_cli_takes_over_reach_the_queue_instead_of_ending_the_program";
        if !is_child() {
            rerun_alone(NAME);
            return;
        }
        let (sender, receiver) = std::sync::mpsc::channel();
        signal_thread(sender, || Some((100, 30))).expect("the handlers are installed");
        let next = |signal: i32| {
            // SAFETY: `raise` only sends the signal to this thread, and every signal raised here has a handler by now.
            assert_eq!(unsafe { libc::raise(signal) }, 0);
            receiver.recv_timeout(std::time::Duration::from_secs(10)).unwrap_or_else(|_| panic!("signal {signal} did not arrive"))
        };
        assert!(matches!(next(libc::SIGWINCH), Input::Resize(100, 30)));
        assert!(matches!(next(libc::SIGINT), Input::Interrupt));
        assert!(matches!(next(libc::SIGTERM), Input::Stop(libc::SIGTERM)));
        assert!(matches!(next(libc::SIGHUP), Input::Stop(libc::SIGHUP)));
        assert!(matches!(next(libc::SIGQUIT), Input::Stop(libc::SIGQUIT)));
        // A panic on the signal thread (here: in the callback that reads the size) is told to the queue as well.
        let (failing, told) = std::sync::mpsc::channel();
        signal_thread(failing, || panic!("the size failed")).expect("a second set of handlers");
        assert!(matches!(next(libc::SIGWINCH), Input::Resize(100, 30)));
        assert!(matches!(told.recv_timeout(std::time::Duration::from_secs(10)), Ok(Input::Failed)));
    }

    /// The stdin thread read a line and queued it behind the question before the terminal was flushed for it: the flush cannot reach a
    /// line that is already in the queue, so the loop drops it, and it is not taken as the answer.
    #[test]
    fn a_line_queued_just_before_a_question_is_not_taken_as_its_answer() {
        let directory = FakeDirectory::new().with_host("web", AuthMethod::Key { key_id: "k-plain".into() }).with_pin("web", default_server_key());
        let engine = FakeEngine::new().with_login(FakeLogin::Server(FakeMethods::password("right")));
        let setup = connect_typing_ahead(engine, directory, MemKeychain::default(), Some(b"hunter2\n"));
        eventually("the question", 10, || setup.stderr.text().starts_with("deploy@web's password: "));
        // The queue is in order: once this output has been printed, whatever was queued before it has been looked at.
        setup.keys.send(Input::Output(b"marker".to_vec())).unwrap();
        eventually("the marker", 10, || setup.stdout.text() == "marker");
        assert_eq!(setup.stderr.text(), "deploy@web's password: ", "the question still waits for its answer");
        let prompt = setup.termios.now();
        assert_eq!((prompt.c_lflag & libc::ECHO, prompt.c_lflag & libc::ICANON), (0, libc::ICANON), "still the prompt mode");
        setup.keys.send(Input::Stdin(Zeroizing::new(b"right\n".to_vec()))).unwrap();
        eventually("the shell to open", 10, || raw(&setup.termios));
        setup.engine.shells().remove(0).end(Exit::Code(0));
        let (code, setup) = finish(setup);
        assert_eq!((code, setup.stderr.text()), (0, "deploy@web's password: \n".to_string()));
    }

    /// What was typed and queued is dropped when a question flushes the terminal; every other input stays, in the order it came, and
    /// what is typed after the flush is the question's.
    #[test]
    fn forgetting_the_typed_keeps_every_other_input_in_order() {
        let (sender, receiver) = std::sync::mpsc::channel();
        let mut queue = Queue::new(receiver);
        sender.send(Input::Output(b"a".to_vec())).unwrap();
        sender.send(Input::Stdin(Zeroizing::new(b"hunter2\n".to_vec()))).unwrap();
        sender.send(Input::Resize(100, 30)).unwrap();
        sender.send(Input::Stdin(Zeroizing::new(b"more".to_vec()))).unwrap();
        sender.send(Input::StdinEnd).unwrap();
        queue.forget_typed();
        sender.send(Input::Stdin(Zeroizing::new(b"after".to_vec()))).unwrap();
        drop(sender);
        let rest: Vec<Input> = std::iter::from_fn(|| queue.next()).collect();
        assert_eq!(format!("{rest:?}"), "[Output([97]), Resize(100, 30), StdinEnd, Stdin(<hidden>)]");
        assert!(matches!(&rest[3], Input::Stdin(bytes) if &bytes[..] == b"after"), "typed after the flush: the question's own");
    }

    /// What was typed may be a password: it is wiped wherever it is dropped, whichever path of the loop drops it. That is the type's doing,
    /// so this fails to compile if what `Input::Stdin` or `Action::Answer` carries stops being wiped on drop.
    #[test]
    fn what_was_typed_is_wiped_wherever_it_is_dropped() {
        fn wiped_on_drop<T: zeroize::ZeroizeOnDrop>(_: &T) {}
        let Input::Stdin(typed) = Input::Stdin(Zeroizing::new(b"hunter2\n".to_vec())) else { unreachable!() };
        wiped_on_drop(&typed);
        let Action::Answer { value, .. } = (Action::Answer { question_id: "q1".into(), value: Zeroizing::new("hunter2".to_string()) }) else { unreachable!() };
        wiped_on_drop(&value);
    }

    /// A source of keys that is whatever the closure says each read is.
    struct Keyboard<F>(F);

    impl<F: FnMut(&mut [u8]) -> std::io::Result<usize>> Read for Keyboard<F> {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            (self.0)(buf)
        }
    }

    #[test]
    fn the_keys_are_queued_as_typed_and_the_end_of_input_is_told_and_a_failing_terminal_ends_the_thread() {
        // One read at a time: what is typed, an interrupted read, the end of input (Ctrl-D: a read of 0 bytes), more, then a failure.
        let mut script = std::collections::VecDeque::from([Ok(b"ls\r".to_vec()), Err(std::io::ErrorKind::Interrupted.into()), Ok(vec![]), Ok(b"x".to_vec())]);
        let keyboard = Keyboard(move |buf: &mut [u8]| match script.pop_front() {
            Some(Ok(bytes)) => {
                buf[..bytes.len()].copy_from_slice(&bytes);
                Ok(bytes.len())
            }
            Some(Err(error)) => Err(error),
            None => Err(std::io::Error::other("the terminal went away")),
        });
        let (sender, receiver) = std::sync::mpsc::channel();
        read_keys(keyboard, &sender);
        drop(sender);
        let queued: Vec<Input> = receiver.iter().collect();
        assert_eq!(format!("{queued:?}"), "[Stdin(<hidden>), StdinEnd, Stdin(<hidden>), StdinEnd]", "an interrupted read is read again; the failure is the end");
        assert!(matches!(&queued[0], Input::Stdin(bytes) if &bytes[..] == b"ls\r"));
        assert!(matches!(&queued[2], Input::Stdin(bytes) if &bytes[..] == b"x"));
    }

    #[test]
    fn the_keys_thread_stops_when_the_loop_is_gone() {
        let (sender, receiver) = std::sync::mpsc::channel();
        drop(receiver);
        // A keyboard that never stops typing: the thread has to be the one that stops.
        let keyboard = Keyboard(|buf: &mut [u8]| {
            buf[0] = b'x';
            Ok(1)
        });
        read_keys(keyboard, &sender);
    }

    #[test]
    fn a_worker_that_panics_tells_the_queue_and_one_that_returns_does_not() {
        let (sender, receiver) = std::sync::mpsc::channel();
        spawn_worker("test-quiet", sender.clone(), |_| {});
        spawn_worker("test-panics", sender.clone(), |_| panic!("the worker failed"));
        drop(sender);
        // The queue ends when both workers are gone.
        let told: Vec<String> = receiver.iter().map(|input| format!("{input:?}")).collect();
        assert_eq!(told, ["Failed"]);
    }

    /// A panic on the thread that reads the keys: the panic hook puts the terminal back, but the loop would go on reading from nobody. It
    /// ends the program instead, with 255, the terminal as it was, and the broker told.
    #[test]
    fn a_panic_on_a_thread_of_the_program_ends_the_run_with_255_the_terminal_put_back_and_the_broker_told() {
        let keychain = MemKeychain::default();
        keychain.set("host:id-web", "saved").unwrap();
        let setup = connect(FakeEngine::new(), FakeDirectory::new().with_host("web", AuthMethod::Password).with_pin("web", default_server_key()), keychain);
        eventually("the terminal to be raw", 10, || raw(&setup.termios));
        setup.engine.shells().remove(0).print(b"$ ");
        let keyboard = Keyboard(|_: &mut [u8]| -> std::io::Result<usize> { panic!("the keyboard failed") });
        keys_thread(keyboard, setup.keys.clone());
        let (code, setup) = finish(setup);
        assert_eq!(code, 255);
        assert!(setup.termios.is_start(&setup.termios.now()), "the terminal is as it was");
        assert_eq!(setup.stderr.text(), "\nsshelter: an internal error stopped this session.\n");
        eventually("the session to be closed", 10, || setup.engine.events().contains(&FakeEvent::Closed));
    }

    /// What `Action::Answer` puts on the wire is the protocol's answer message, byte for byte (the CLI writes it from borrowed strings so
    /// that the password is in no message it would have to wipe), and it is built in a buffer that has room for it from the start: a
    /// `Vec` that grows frees its old allocation with a part of the password in it.
    #[test]
    fn an_answer_is_the_protocols_message_byte_for_byte_and_fits_the_buffer_it_is_built_in() {
        use crate::session::protocol::ClientMessage;
        let controls = "\u{1}".repeat(50);
        for value in ["hunter2", "", "x".repeat(300).as_str(), "quote\" back\\slash tab\t \u{e9} \u{5bc6}\u{78bc} \u{1f511}", controls.as_str()] {
            for question_id in ["q1", "", "0123456789abcdef0123456789abcdef0123"] {
                let json = answer_json(question_id, value).unwrap();
                let protocol = serde_json::to_vec(&ClientMessage::Answer { question_id: question_id.into(), value: Some(value.into()), cancel: false }).unwrap();
                assert_eq!(&json[..], &protocol[..], "{question_id:?} {value:?}");
                assert!(json.len() <= answer_room(question_id, value), "{} bytes in a room of {}", json.len(), answer_room(question_id, value));
                assert!(json.capacity() >= answer_room(question_id, value));
            }
        }
        // The worst case is what the room is for: a control character takes six bytes in JSON, and the rest of the message at most 64.
        let json = answer_json("", &controls).unwrap();
        assert_eq!(json.len(), 6 * controls.len() + 60);
        assert!(answer_room("", &controls) >= json.len());
    }

    /// A long password with characters JSON has to escape gets to the broker whole.
    #[test]
    fn a_long_password_with_awkward_characters_gets_in_whole() {
        let password = format!("p\"w\\ tab\t \u{5bc6}\u{78bc} {}", "x".repeat(300));
        let directory = FakeDirectory::new().with_host("web", AuthMethod::Key { key_id: "k-plain".into() }).with_pin("web", default_server_key());
        let setup = connect(FakeEngine::new().with_login(FakeLogin::Server(FakeMethods::password(&password))), directory, MemKeychain::default());
        eventually("the question", 10, || setup.stderr.text() == "deploy@web's password: ");
        setup.keys.send(Input::Stdin(Zeroizing::new(format!("{password}\n").into_bytes()))).unwrap();
        eventually("the shell to open", 10, || raw(&setup.termios));
        setup.engine.shells().remove(0).end(Exit::Code(0));
        let (code, setup) = finish(setup);
        assert_eq!((code, setup.stderr.text()), (0, "deploy@web's password: \n".to_string()));
    }
}
