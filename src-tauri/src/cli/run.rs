//! The I/O of `sshelter connect` (own-ssh spec §7.3): the broker's frames are read on a thread of their own, the person's keys on
//! another, the signals (SIGWINCH, SIGINT, SIGTERM, SIGHUP, SIGQUIT) on a third with tokio's signal handling; everything meets in one
//! queue, and the client (`client.rs`) says what to do with each.

use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::sync::mpsc::{Receiver, Sender};

use super::client::{Action, Client, Input};
use super::terminal::Tty;
use crate::session::protocol::{decode, read_frame, write_control, write_data, Frame, HostQuery, ServerMessage};

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
    std::thread::spawn(move || loop {
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
    if let Some(code) = perform(actions, &mut writer, tty, stdout, stderr) {
        return code;
    }
    while let Ok(input) = receiver.recv() {
        let actions = client.handle(input);
        if let Some(code) = perform(actions, &mut writer, tty, stdout, stderr) {
            return code;
        }
    }
    255
}

/// Does what the client said, in order; `Some(code)` when it is time to exit. A broker that no longer takes what is sent is a broker that
/// went away: its end of the connection arrives as `Input::Closed` from the reader.
fn perform(actions: Vec<Action>, writer: &mut UnixStream, tty: &mut Tty, stdout: &mut dyn Write, stderr: &mut dyn Write) -> Option<i32> {
    for action in actions {
        match action {
            Action::Send(message) => {
                let _ = write_control(writer, &message);
            }
            Action::SendData(bytes) => {
                let _ = write_data(writer, &bytes);
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
            }
            Action::Exit(code) => {
                tty.restore();
                return Some(code);
            }
        }
    }
    None
}

/// Reads the person's keys into the queue until standard input ends (or the program does).
pub fn stdin_thread(sender: Sender<Input>) {
    std::thread::spawn(move || {
        let mut stdin = std::io::stdin().lock();
        let mut buf = [0u8; 4096];
        loop {
            match stdin.read(&mut buf) {
                Ok(0) => {
                    // A question ends on Ctrl-D; the next question reads again.
                    if sender.send(Input::StdinEnd).is_err() {
                        return;
                    }
                }
                Ok(count) => {
                    if sender.send(Input::Stdin(buf[..count].to_vec())).is_err() {
                        return;
                    }
                }
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
                Err(_) => {
                    let _ = sender.send(Input::StdinEnd);
                    return;
                }
            }
        }
    });
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
    std::thread::spawn(move || {
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

    /// `sshelter connect web` against a broker over `engine` and `directory`, on the other end of a socket pair, with a fake terminal.
    fn connect(engine: FakeEngine, directory: FakeDirectory, keychain: MemKeychain) -> Setup {
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
        let run = {
            let (termios, sender, mut stdout, mut stderr) = (Arc::clone(&termios), sender.clone(), stdout.clone(), stderr.clone());
            std::thread::spawn(move || {
                let mut tty = Tty::new(termios).unwrap();
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
        setup.keys.send(Input::Stdin(b"ls\r".to_vec())).unwrap();
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
        setup.keys.send(Input::Stdin(b"right\n".to_vec())).unwrap();
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
    }
}
