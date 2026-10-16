//! `sshelter connect` over the broker's named pipe (plan 1b-3 Task 3): the loop (`run::run`) on Windows against the real broker, served
//! on a pipe of the test's own (`pipe_windows::listen`, reached with `pipe_windows::connect` as the CLI reaches it), with a fake engine
//! and a fake console under the real `Tty`. The keys are typed into the fake console and read by the keys thread
//! (`run::console_keys_thread`), so they go through the reads that no change of mode may span; the terminal's output goes to writers that
//! keep what they are given, as the console's output does (`Output::console`: whole characters only).

use std::io::Write;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use super::console::fake::Call;
use super::console::{input_mode, ENABLE_LINE_INPUT};
use super::console_inputs::CTRL_CLOSE_EVENT;
use super::client::{Request, PAUSE_PROMPT};
use super::run::{console_keys_thread, queue, run, watch_size, ControlEvents, Output, Over, Watchdog, STOP_GRACE};
use super::terminal::fake::FakeConsole;
use super::terminal::{Mode, Tty};
use crate::ipc::pipe_windows;
use crate::ipc::server::Started;
use crate::session::broker::Broker;
use crate::session::connect::HostKeyConfirmer;
use crate::session::directory::HostDirectory;
use crate::session::protocol::HostQuery;
use crate::session::testing::{FakeConfirmer, FakeDirectory, FakeKeys};
use crate::ssh::fake::{default_server_key, FakeEngine, FakeEvent, FakeLogin, FakeMethods};
use crate::ssh::testing::eventually;
use crate::ssh::{AuthMethod, Exit, SshEngine};
use crate::sync::env::Keychain;
use crate::sync::testkit::MemKeychain;

/// A `Write` the test reads while the run goes on.
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
    /// The broker the run talks to (`end_all`: Lunport quits).
    broker: Arc<Broker>,
    console: Arc<FakeConsole>,
    stdout: Shared,
    stderr: Shared,
    /// What the console's control events do in this run.
    events: Arc<ControlEvents>,
    /// The watchdog would have ended the program (it ends a test's run only by saying so).
    fired: Arc<AtomicBool>,
    /// The run's exit code, and whether the console was back at its start when `run` returned: looked at before the `Tty` is dropped,
    /// whose `Drop` puts the console back as well and would hide a run that did not.
    run: std::thread::JoinHandle<(i32, bool)>,
    /// Holds the listener's lock.
    _dir: tempfile::TempDir,
}

/// `sshelter connect web` against a broker over `engine`, `directory` and `keychain`, served on a pipe of its own, with a fake console on
/// which `typed_ahead` was typed before the run began.
fn connect(engine: FakeEngine, directory: FakeDirectory, keychain: MemKeychain, typed_ahead: &str) -> Setup {
    connect_pausing(engine, directory, keychain, typed_ahead, false)
}

/// `connect`, and with `pause_on_error` as `sshelter connect --pause-on-error web`.
fn connect_pausing(engine: FakeEngine, directory: FakeDirectory, keychain: MemKeychain, typed_ahead: &str, pause_on_error: bool) -> Setup {
    static NEXT: AtomicUsize = AtomicUsize::new(0);
    let engine = Arc::new(engine);
    let broker = Broker::new(
        Arc::clone(&engine) as Arc<dyn SshEngine>,
        Arc::new(directory) as Arc<dyn HostDirectory>,
        Arc::new(FakeKeys::new()),
        Arc::new(keychain) as Arc<dyn Keychain>,
        Arc::new(FakeConfirmer::default()) as Arc<dyn HostKeyConfirmer>,
    );
    let dir = tempfile::tempdir().unwrap();
    let pipe = format!("sshelter-cli-test-{}-{}", std::process::id(), NEXT.fetch_add(1, Ordering::SeqCst));
    assert_eq!(pipe_windows::listen(&dir.path().join("ipc"), &pipe, "sshelter-session", broker.handler()).unwrap(), Started::Running);
    let stream = pipe_windows::connect(&pipe, Duration::from_secs(5)).expect("the broker serves its pipe");
    let console = FakeConsole::new();
    if !typed_ahead.is_empty() {
        console.type_text(typed_ahead);
    }
    let (stdout, stderr) = (Shared::default(), Shared::default());
    let mut tty = Tty::new(console.clone()).unwrap();
    let (inputs, queue) = queue();
    // The watchdog does not end this process: it says that it would have.
    let fired = Arc::new(AtomicBool::new(false));
    let firing = Arc::clone(&fired);
    let watchdog = Watchdog::start(tty.restorer(), STOP_GRACE, move |_| firing.store(true, Ordering::SeqCst)).unwrap();
    let over = Over::default();
    let events = Arc::new(ControlEvents::new(inputs.clone(), watchdog.clone(), over.clone()));
    tty.take_over().unwrap();
    console_keys_thread(inputs.clone(), tty.keys(), || {});
    let run = {
        let (console, stdout, stderr) = (Arc::clone(&console), stdout.clone(), stderr.clone());
        std::thread::spawn(move || {
            let size = Arc::clone(&console);
            let _size = watch_size(inputs.clone(), Duration::from_millis(50), move || *size.size.lock().unwrap());
            let request = Request { host: HostQuery::Alias("web".into()), pause_on_error };
            let code = run(stream, request, "xterm-256color".into(), &mut tty, (inputs, queue), Output::console(stdout), Output::console(stderr));
            let restored = console.now() == console.start;
            over.set();
            watchdog.stand_down();
            (code, restored)
        })
    };
    Setup { engine, broker, console, stdout, stderr, events, fired, run, _dir: dir }
}

/// `web` is pinned and its password is saved: it connects without a question.
fn pinned_web() -> FakeDirectory {
    FakeDirectory::new().with_host("web", AuthMethod::Password).with_pin("web", default_server_key())
}

fn saved_password() -> MemKeychain {
    let keychain = MemKeychain::default();
    keychain.set("host:id-web", "saved").unwrap();
    keychain
}

fn raw(console: &FakeConsole) -> bool {
    console.now().input_mode & ENABLE_LINE_INPUT == 0
}

/// The run's end, which the run came to itself (not the watchdog): its exit code, whether it put the console back itself, and the rest
/// of the setup. The fake console goes away after it, so that the keys thread, which waits in its read, ends too.
fn finish(setup: Setup) -> (i32, bool, Setup) {
    eventually("the run to end", 10, || setup.run.is_finished());
    let Setup { engine, broker, console, stdout, stderr, events, fired, run, _dir } = setup;
    let (code, restored) = run.join().unwrap();
    console.go_away();
    assert!(!fired.load(Ordering::SeqCst), "the run ended without the watchdog");
    (code, restored, Setup { engine, broker, console, stdout, stderr, events, fired, run: std::thread::spawn(|| (0, true)), _dir })
}

/// Spec §7.3 on Windows: over the pipe a shell opens, the console goes raw, what is typed on it (and what was typed before the shell
/// opened, which stayed in the console) reaches the shell, the shell's output reaches the console, a new window size reaches the shell,
/// and the shell's status is the program's, with the console back at its start.
#[test]
fn sshelter_connect_runs_a_shell_over_the_pipe_and_exits_with_its_status() {
    let setup = connect(FakeEngine::new(), pinned_web(), saved_password(), "pwd\r");
    eventually("the console to be raw", 10, || raw(&setup.console));
    eventually("what was typed ahead to reach the shell", 10, || setup.engine.events().contains(&FakeEvent::ShellInput(b"pwd\r".to_vec())));
    setup.console.type_text("ls \u{5bc6}\r");
    eventually("the keys to reach the shell", 10, || setup.engine.events().contains(&FakeEvent::ShellInput("ls \u{5bc6}\r".as_bytes().to_vec())));
    let remote = setup.engine.shells().remove(0);
    remote.print("file \u{1f511}.txt\r\n".as_bytes());
    eventually("the output to reach the console", 10, || setup.stdout.text() == "file \u{1f511}.txt\r\n");
    *setup.console.size.lock().unwrap() = Some((100, 30));
    eventually("the size to reach the shell", 10, || setup.engine.events().contains(&FakeEvent::WindowChange { cols: 100, rows: 30 }));
    remote.end(Exit::Code(3));
    let (code, restored, setup) = finish(setup);
    assert_eq!(code, 3);
    assert!(restored, "the console is as it was");
    assert_eq!(setup.stderr.text(), "");
}

/// A question is asked on the console in the mode that hides what is typed, after what was typed before it was thrown away (it must not
/// become a part of the password); the answer gets in, and the shell opens.
#[test]
fn a_question_is_asked_on_the_console_and_the_answer_gets_in() {
    let directory = FakeDirectory::new().with_host("web", AuthMethod::Key { key_id: "k-plain".into() }).with_pin("web", default_server_key());
    let engine = FakeEngine::new().with_login(FakeLogin::Server(FakeMethods::password("right")));
    let setup = connect(engine, directory, MemKeychain::default(), "hunt");
    eventually("the question", 10, || setup.stderr.text() == "deploy@web's password: ");
    let hidden = input_mode(setup.console.start.input_mode, Mode::Prompt { echo: false });
    assert_eq!(setup.console.now().input_mode, hidden, "line editing, no echo");
    assert!(setup.console.all_read(), "what was typed before the question was thrown away");
    setup.console.type_text("right\r\n");
    eventually("the shell to open", 10, || raw(&setup.console));
    setup.engine.shells().remove(0).end(Exit::Code(0));
    let (code, restored, setup) = finish(setup);
    // No line break of the CLI's own after the hidden answer: the console moved to the next line on Enter (`QUESTION_READ_ENDS_ITS_LINE`).
    assert_eq!((code, setup.stderr.text()), (0, "deploy@web's password: ".to_string()));
    assert!(restored, "the console is as it was");
}

/// Final wave (F11): Lunport quits while a hidden question waits for its answer. The console layer ends the question's line read with an
/// Enter of its own, on which a real console moves to the next line (`QUESTION_READ_ENDS_ITS_LINE`): the reason follows the prompt with no
/// line break of the CLI's own (this fake console has no cursor). A console that refuses that Enter leaves the question's line read going,
/// and its prompt the last line: the CLI starts the next line itself before the reason.
#[test]
fn an_end_under_a_question_starts_the_reason_on_a_line_of_its_own_when_the_console_did_not() {
    for refused in [false, true] {
        let directory = FakeDirectory::new().with_host("web", AuthMethod::Key { key_id: "k-plain".into() }).with_pin("web", default_server_key());
        let engine = FakeEngine::new().with_login(FakeLogin::Server(FakeMethods::password("right")));
        let setup = connect(engine, directory, MemKeychain::default(), "");
        eventually("the question", 10, || setup.stderr.text() == "deploy@web's password: ");
        eventually("the question's line read", 10, || setup.console.reads_in_progress() == 1);
        if refused {
            setup.console.fail(|call| *call == Call::Wake);
        }
        setup.broker.end_all(Duration::from_secs(5));
        let (code, restored, setup) = finish(setup);
        let line_break = if refused { "\n" } else { "" };
        let said = format!("deploy@web's password: {line_break}Lunport quit, so the connection to web was closed.\n");
        assert_eq!((code, setup.stderr.text()), (255, said), "the console refused the Enter: {refused}");
        assert!(restored, "the console is as it was");
    }
}

/// `--pause-on-error` on Windows (spec §7.3): a connect that fails before the shell opens leaves its reason and the prompt on the console,
/// and the Enter that ends the pause is read in a line read that hides what is typed (the console reads nothing while it is cooked); the
/// line typed while connecting was thrown away first, so it does not end the pause. The console ends the line on Enter itself (no line
/// break of the CLI's own), and the program ends with 255, the console back at its start.
#[test]
fn with_pause_on_error_a_failed_connect_waits_on_the_console_for_enter() {
    let setup = connect_pausing(FakeEngine::new(), FakeDirectory::new(), MemKeychain::default(), "ls\r\n", true);
    eventually("the prompt", 10, || setup.stderr.text().ends_with(PAUSE_PROMPT));
    eventually("the line read", 10, || setup.console.reads_in_progress() == 1);
    let hidden = input_mode(setup.console.start.input_mode, Mode::Prompt { echo: false });
    assert_eq!(setup.console.now().input_mode, hidden, "line editing, no echo");
    assert!(setup.console.all_read(), "what was typed while connecting was thrown away");
    std::thread::sleep(Duration::from_millis(300));
    assert!(!setup.run.is_finished(), "it waits for Enter");
    setup.console.type_text("\r\n");
    let (code, restored, setup) = finish(setup);
    assert_eq!((code, setup.stderr.text()), (255, format!("No saved host is called web.\n{PAUSE_PROMPT}")));
    assert!(restored, "the console is as it was");
}

/// The console closed (`CTRL_CLOSE_EVENT`) during the shell: the session ends as SIGHUP ends it (129), the broker is told, the console is
/// put back, and the handler returns only once that is done (Windows ends the process when it does).
#[test]
fn the_console_closed_ends_the_session_with_129_before_the_handler_returns() {
    let setup = connect(FakeEngine::new(), pinned_web(), saved_password(), "");
    eventually("the console to be raw", 10, || raw(&setup.console));
    setup.engine.shells().remove(0).print(b"$ ");
    eventually("the prompt", 10, || setup.stdout.text() == "$ ");
    let handled = {
        let events = Arc::clone(&setup.events);
        std::thread::spawn(move || events.handle(CTRL_CLOSE_EVENT))
    };
    let (code, restored, setup) = finish(setup);
    assert_eq!(code, 129);
    assert!(restored, "the console is as it was");
    eventually("the handler to return", 10, || handled.is_finished());
    assert!(handled.join().unwrap());
    eventually("the session to be closed", 10, || setup.engine.events().contains(&FakeEvent::Closed));
}

/// The console went away (a read fails): the session ends as SIGHUP ends it, with the console put back.
#[test]
fn a_console_that_went_away_ends_the_session_with_129() {
    let setup = connect(FakeEngine::new(), pinned_web(), saved_password(), "");
    eventually("the console to be raw", 10, || raw(&setup.console));
    setup.engine.shells().remove(0).print(b"$ ");
    setup.console.go_away();
    let (code, restored, setup) = finish(setup);
    assert_eq!(code, 129);
    assert!(restored, "the console is as it was");
    eventually("the session to be closed", 10, || setup.engine.events().contains(&FakeEvent::Closed));
}
