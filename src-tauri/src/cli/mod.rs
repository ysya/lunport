//! `sshelter connect` (own-ssh spec §7.3): the terminal's end of a session in the app, on macOS and Linux (a terminal, termios and
//! signals) and on Windows (a console, its modes and its control events; plan 1b-3).

pub mod client;
// The Windows console without the Windows calls (`terminal_windows.rs` adds them): built on Windows, and in every platform's tests.
#[cfg(any(windows, test))]
pub mod console;
// What the Windows console reads and is given, and its control events, without the Windows calls (`inputs_windows.rs` makes them):
// built on Windows, and in every platform's tests.
#[cfg(any(windows, test))]
pub mod console_inputs;
#[cfg(all(test, unix))]
mod e2e_tests;
#[cfg(windows)]
mod inputs_windows;
#[cfg(all(test, windows))]
mod pipe_tests;
#[cfg(all(test, windows))]
mod real_console_tests;
pub mod run;
pub mod signal;
#[cfg(unix)]
pub mod terminal;
#[cfg(windows)]
#[path = "terminal_windows.rs"]
pub mod terminal;

use std::ffi::OsString;
#[cfg(unix)]
use std::os::unix::net::UnixStream;
use std::sync::Arc;

use crate::session::protocol::HostQuery;
use client::{Request, PAUSE_PROMPT};

/// What `sshelter connect` prints when the app does not answer after it was started (spec §7.3, §11).
pub const NOT_STARTED: &str = "SSHelter did not start within 12 seconds.";

/// The flag of `Request::pause_on_error`, before the host: SSHelter's Connect gives it to a terminal that closes its window with the
/// program (spec §7.4). It is not in the usage, which is for people.
pub const PAUSE_ON_ERROR: &str = "--pause-on-error";

/// What `sshelter connect` prints when standard input is not a terminal (spec §7.3).
pub const NEEDS_TERMINAL: &str = "sshelter connect needs a terminal.";

/// How `sshelter connect` is used.
pub const USAGE: &str = "usage: sshelter connect <alias>\n       sshelter connect --id <host id>";

/// What the arguments after `connect` ask for: the host, an alias or `--id` and a host id, after `--pause-on-error` when it is given.
pub fn parse_args(args: &[String]) -> Result<Request, String> {
    let (pause_on_error, args) = match args {
        [flag, rest @ ..] if flag == PAUSE_ON_ERROR => (true, rest),
        _ => (false, args),
    };
    let host = match args {
        [flag, id] if flag == "--id" && !id.is_empty() && !id.starts_with('-') => HostQuery::Id(id.clone()),
        [alias] if !alias.is_empty() && !alias.starts_with('-') => HostQuery::Alias(alias.clone()),
        _ => return Err(USAGE.to_string()),
    };
    Ok(Request { host, pause_on_error })
}

/// `--pause-on-error` before the session: throws away what was typed while the CLI waited for SSHelter (`discard`: a line typed then must
/// not end the wait before its prompt was seen), then waits for Enter on `input` (standard input, the terminal as it was: its own line
/// editing, echo on), a line's end. The end of input and a failed read end the wait too (a terminal that went away; no standard input;
/// a standard input another program left non-blocking, which Connect's new window never has). No signal is taken over yet: Ctrl-C and a
/// closed window end the program the default way.
fn wait_for_enter(discard: impl FnOnce(), mut input: impl std::io::Read) {
    discard();
    let mut byte = [0u8; 1];
    loop {
        match input.read(&mut byte) {
            Ok(1) if byte[0] == b'\n' || byte[0] == b'\r' => return,
            Ok(1) => {}
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
            Ok(_) | Err(_) => return,
        }
    }
}

/// What the CLI says when it ends before the session (`text`, on `stderr`), and, with `--pause-on-error`, `PAUSE_PROMPT` under it and the
/// wait for Enter (`wait`). The exit code, 1.
fn ended_before_the_session(text: &str, request: &Request, wait: impl FnOnce(), stderr: &mut dyn std::io::Write) -> i32 {
    let _ = writeln!(stderr, "{text}");
    if request.pause_on_error {
        let _ = write!(stderr, "{PAUSE_PROMPT}");
        let _ = stderr.flush();
        wait();
    }
    1
}

/// The arguments after `connect` as text. One that is not text (not UTF-8; on Windows, not UTF-16) cannot name a host either: the usage.
fn texts(args: &[OsString]) -> Result<Vec<String>, String> {
    args.iter().map(|arg| arg.clone().into_string().map_err(|_| USAGE.to_string())).collect()
}

/// The terminal type the shell is opened for: `$TERM`, or `xterm-256color` without one (spec §7.3).
pub fn term_from(value: Option<std::ffi::OsString>) -> String {
    value.and_then(|value| value.into_string().ok()).filter(|term| !term.is_empty()).unwrap_or_else(|| "xterm-256color".to_string())
}

/// `sshelter connect <arguments>`: returns the exit code (main.rs exits with it). Started before anything of Tauri. The order is fixed:
/// the arguments are looked at first (the usage, and 2), then the terminal (`sshelter connect needs a terminal.`, and 1), and only then is
/// SSHelter reached, or started.
#[cfg(unix)]
pub fn run_connect(args: &[OsString]) -> i32 {
    let request = match texts(args).and_then(|args| parse_args(&args)) {
        Ok(request) => request,
        Err(usage) => {
            eprintln!("{usage}");
            return 2;
        }
    };
    let term = term_from(std::env::var_os("TERM"));
    let signals = |inputs, terminal, watchdog, size: Arc<dyn terminal::TermiosApi>| run::signal_thread(inputs, terminal, watchdog, move || size.size());
    // What was typed is thrown away by setting the terminal's attributes as they are, with `discard_input`.
    let discard = || {
        use terminal::TermiosApi;
        let _ = terminal::StdinTermios.get().and_then(|attributes| terminal::StdinTermios.set(&attributes, true));
    };
    let wait = || wait_for_enter(discard, std::io::stdin());
    session(request, term, Arc::new(terminal::StdinTermios), reach_broker, signals, wait, &mut std::io::stderr())
}

/// The connection to the broker, at `<app data>/ipc/sock` (found without the app): if nothing answers there SSHelter is started, hidden,
/// under the same locks as the MCP adapter's start, and waited for.
#[cfg(unix)]
fn reach_broker() -> Result<UnixStream, String> {
    use crate::host_start::{ensure_started, start_host, take_spawn_locks, START_WAIT};

    let socket = match crate::fsutil::app_data_root() {
        Ok(root) => crate::session::socket_path(&root),
        Err(error) => return Err(format!("sshelter: {error}")),
    };
    ensure_started(|| UnixStream::connect(&socket).ok(), take_spawn_locks, start_host, START_WAIT, NOT_STARTED)
}

/// One session on the terminal `api`; `reach` finds the broker, starting SSHelter if it must, and `signals` takes over the signals
/// (`run::signal_thread`). The terminal comes first: a program that has none must not start the app just to say so. Writes what the CLI
/// says before the session to `stderr` (the terminal's); with `--pause-on-error`, SSHelter that cannot be reached is said and then
/// `wait` waits for Enter (`wait_for_enter`).
#[cfg(unix)]
fn session(
    request: Request,
    term: String,
    api: Arc<dyn terminal::TermiosApi>,
    reach: impl FnOnce() -> Result<UnixStream, String>,
    signals: impl FnOnce(run::Inputs, terminal::Restorer, run::Watchdog, Arc<dyn terminal::TermiosApi>) -> std::io::Result<()>,
    wait: impl FnOnce(),
    stderr: &mut dyn std::io::Write,
) -> i32 {
    let size = Arc::clone(&api);
    let mut tty = match terminal::Tty::new(api) {
        Ok(tty) => tty,
        Err(_) => {
            let _ = writeln!(stderr, "{NEEDS_TERMINAL}");
            return 1;
        }
    };
    let stream = match reach() {
        Ok(stream) => stream,
        Err(text) => return ended_before_the_session(&text, &request, wait, stderr),
    };
    let terminal = tty.restorer();
    terminal::restore_on_panic(terminal.clone());
    let (inputs, queue) = run::queue();
    // Without its handlers the program could not keep its terminal: Ctrl-C or Ctrl-backslash at a hidden password would end it with
    // echo off, and Ctrl-Z would stop it raw. So it does not start, and it says so before the terminal has been changed.
    let watchdog = match run::Watchdog::start(terminal.clone(), run::STOP_GRACE, |code| std::process::exit(code)) {
        Ok(watchdog) => watchdog,
        Err(error) => {
            let _ = writeln!(stderr, "sshelter: cannot take over the terminal's signals: {error}");
            return 1;
        }
    };
    if let Err(error) = signals(inputs.clone(), terminal, watchdog.clone(), size) {
        watchdog.stand_down();
        let _ = writeln!(stderr, "sshelter: cannot take over the terminal's signals: {error}");
        return 1;
    }
    let hung_up = watchdog.clone();
    run::stdin_thread(inputs.clone(), move || hung_up.arm(128 + signal::HUP));
    let code = run::run(stream, request, term, &mut tty, (inputs, queue), own_writer(std::io::stdout()), own_writer(std::io::stderr()));
    watchdog.stand_down();
    code
}

/// Standard output or error for the terminal's writer: a duplicate of its descriptor, written directly. Std's handle holds a lock (and
/// stdout a buffer) while it writes, and a writer stuck on a terminal that does not take its output would hold them; std's handle is
/// used only when the descriptor cannot be had.
#[cfg(unix)]
fn own_writer<W: std::io::Write + std::os::fd::AsFd + std::os::fd::AsRawFd + Send + 'static>(handle: W) -> run::Output {
    match handle.as_fd().try_clone_to_owned() {
        Ok(descriptor) => run::Output::of(std::fs::File::from(descriptor)),
        Err(_) => run::Output::of(handle),
    }
}

/// `sshelter connect <arguments>` on Windows: returns the exit code (main.rs exits with it). The order is Unix's, with the console's
/// steps in it: the arguments first (the usage, and 2); then the console of the process that started this one is attached when this
/// one has none (a release build is a GUI program; attaching sets the process's control handlers aside, so none is installed before),
/// and only then are the console's buffers looked up (`StdConsole::new`: a GUI program's standard handles are usually not valid before
/// the attach); then the console check (`sshelter connect needs a terminal.`, and 1), and SSHelter reached, or started. The console is
/// changed only once every way out can put it back (`session`).
#[cfg(windows)]
pub fn run_connect(args: &[OsString]) -> i32 {
    let request = match texts(args).and_then(|args| parse_args(&args)) {
        Ok(request) => request,
        Err(usage) => {
            // The console first, only so that the usage reaches it (a release build has none of its own); nothing else is done.
            inputs_windows::attach_console();
            eprintln!("{usage}");
            return 2;
        }
    };
    inputs_windows::attach_console();
    let console = Arc::new(terminal::StdConsole::new());
    let term = term_from(std::env::var_os("TERM"));
    let outputs = {
        let console = Arc::clone(&console);
        move || {
            use windows_sys::Win32::System::Console::{STD_ERROR_HANDLE, STD_OUTPUT_HANDLE};
            (inputs_windows::own_output(STD_OUTPUT_HANDLE, &console), inputs_windows::own_output(STD_ERROR_HANDLE, &console))
        }
    };
    // Before the session the console is as it was (its line editing, echo on): what was typed is thrown away from the input `StdConsole`
    // found, and std reads standard input. (A console `StdConsole` opened as `CONIN$`, for a program started without a standard input,
    // reads as empty there, so there is no pause; the helper and Windows Terminal always give one.)
    let input = Arc::clone(&console);
    let discard = move || {
        let _ = terminal::ConsoleApi::flush_input(&*input);
    };
    let wait = move || wait_for_enter(discard, std::io::stdin());
    session(request, term, console, reach_broker, inputs_windows::take_over_control_events, outputs, wait, &mut std::io::stderr())
}

/// How long a connect waits while every instance of the broker's pipe serves another client (the broker makes the next one at once).
#[cfg(windows)]
const PIPE_BUSY_WAIT: std::time::Duration = std::time::Duration::from_secs(2);

/// The connection to the broker, on its named pipe (found without the app, spec §4): if nobody serves it SSHelter is started, hidden,
/// under the same locks as the MCP adapter's start, and waited for, as on Unix. A pipe of that name that is not the user's own is not
/// SSHelter's (another program made it): it is said so, and SSHelter is not started for it, nor is anything said to it.
#[cfg(windows)]
fn reach_broker() -> Result<crate::ipc::pipe_windows::PipeStream, String> {
    use crate::host_start::{ensure_started, start_host, take_spawn_locks, START_WAIT};
    let name = crate::session::pipe_name().map_err(|error| format!("sshelter: {error}"))?;
    let answering = || match crate::ipc::pipe_windows::connect(&name, PIPE_BUSY_WAIT) {
        Ok(stream) => Some(Ok(stream)),
        Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => Some(Err(refused(&error))),
        // Nobody serves the pipe, or every instance stayed busy: SSHelter is started (one that runs already takes over the start).
        Err(_) => None,
    };
    ensure_started(answering, take_spawn_locks, start_host, START_WAIT, NOT_STARTED)?
}

/// What is said when the broker's pipe cannot be used: the sentence `connect` gives a pipe another program made, and otherwise (the system
/// refused to open the pipe) the system's reason.
#[cfg(any(windows, test))]
fn refused(error: &std::io::Error) -> String {
    match error.raw_os_error() {
        None => error.to_string(),
        Some(_) => format!("sshelter: cannot connect to SSHelter ({error})"),
    }
}

/// One session on the console `api`; `reach` finds the broker, starting SSHelter if it must, `control_events` takes the console's control
/// events over (`inputs_windows::take_over_control_events`), and `outputs` gives the terminal's standard output and error. The console
/// comes first: a program that has none must not start the app just to say so. Then every way out of the program is put in place (the
/// panic hook's restore, the watchdog, the control events) before the console is changed at all (`Tty::take_over`): until then a Ctrl-C
/// ends the program the default way, and the console is as it was. Writes what the CLI says before the session to `stderr`; with
/// `--pause-on-error`, SSHelter that cannot be reached is said and then `wait` waits for Enter (`wait_for_enter`), the console as it was.
#[cfg(windows)]
#[allow(clippy::too_many_arguments)]
fn session(
    request: Request,
    term: String,
    api: Arc<dyn terminal::ConsoleApi>,
    reach: impl FnOnce() -> Result<crate::ipc::pipe_windows::PipeStream, String>,
    control_events: impl FnOnce(run::ControlEvents) -> std::io::Result<()>,
    outputs: impl FnOnce() -> (run::Output, run::Output),
    wait: impl FnOnce(),
    stderr: &mut dyn std::io::Write,
) -> i32 {
    let mut tty = match terminal::Tty::new(Arc::clone(&api)) {
        Ok(tty) => tty,
        Err(_) => {
            let _ = writeln!(stderr, "{NEEDS_TERMINAL}");
            return 1;
        }
    };
    let stream = match reach() {
        Ok(stream) => stream,
        Err(text) => return ended_before_the_session(&text, &request, wait, stderr),
    };
    let terminal = tty.restorer();
    terminal::restore_on_panic(terminal.clone());
    let (inputs, queue) = run::queue();
    let watchdog = match run::Watchdog::start(terminal, run::STOP_GRACE, |code| std::process::exit(code)) {
        Ok(watchdog) => watchdog,
        Err(error) => {
            let _ = writeln!(stderr, "sshelter: cannot take over the console's control keys: {error}");
            return 1;
        }
    };
    // Without its handler a Ctrl-C at a hidden password, or the window closed, would end the program with the console as it set it.
    let over = run::Over::default();
    if let Err(error) = control_events(run::ControlEvents::new(inputs.clone(), watchdog.clone(), over.clone())) {
        watchdog.stand_down();
        let _ = writeln!(stderr, "sshelter: cannot take over the console's control keys: {error}");
        return 1;
    }
    // Every way out can put the console back now. A console without virtual terminal sequences cannot be taken over, and says so.
    if let Err(error) = tty.take_over() {
        watchdog.stand_down();
        let _ = writeln!(stderr, "sshelter: {error}");
        return 1;
    }
    let gone = watchdog.clone();
    run::console_keys_thread(inputs.clone(), tty.keys(), move || gone.arm(128 + signal::HUP));
    let size = Arc::clone(&api);
    let _size = run::watch_size(inputs.clone(), run::SIZE_CHECK, move || size.size());
    let (stdout, stderr_output) = outputs();
    let code = run::run(stream, request, term, &mut tty, (inputs, queue), stdout, stderr_output);
    // The run put the console back on every way it ends; a control handler that waits returns once it is (`run::ControlEvents`).
    tty.restore();
    over.set();
    watchdog.stand_down();
    code
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(list: &[&str]) -> Vec<String> {
        list.iter().map(|arg| arg.to_string()).collect()
    }

    #[cfg(unix)]
    fn os_args(list: &[&str]) -> Vec<OsString> {
        list.iter().map(OsString::from).collect()
    }

    #[test]
    fn an_alias_or_an_id_names_the_host_and_anything_else_shows_the_usage() {
        assert_eq!(parse_args(&args(&["web"])), Ok(HostQuery::Alias("web".into()).into()));
        assert_eq!(parse_args(&args(&["--id", "0123456789abcdef"])), Ok(HostQuery::Id("0123456789abcdef".into()).into()));
        let wrong: [&[&str]; 11] = [
            &[],
            &["--id"],
            &["web", "db"],
            &["-oProxyCommand=x"],
            &["--id", "-x"],
            &[""],
            &["--new-tab", "web"],
            &["--pause-on-error"],
            &["web", "--pause-on-error"],
            &["--pause-on-error", "--pause-on-error", "web"],
            &["--id", "--pause-on-error", "web"],
        ];
        for wrong in wrong {
            assert_eq!(parse_args(&args(wrong)), Err(USAGE.to_string()), "{wrong:?}");
        }
    }

    /// SSHelter's Connect puts `--pause-on-error` before the host (spec §7.4); the usage, which is for people, does not show it.
    #[test]
    fn pause_on_error_comes_before_the_host() {
        assert_eq!(parse_args(&args(&["--pause-on-error", "web"])), Ok(Request { host: HostQuery::Alias("web".into()), pause_on_error: true }));
        assert_eq!(parse_args(&args(&["--pause-on-error", "--id", "0123"])), Ok(Request { host: HostQuery::Id("0123".into()), pause_on_error: true }));
        assert!(!USAGE.contains("pause"), "{USAGE}");
    }

    /// The wait for Enter before the session ends at a line's end (LF, or CR as some terminals send it), at the end of input, and on a
    /// failed read, and reads no further than the Enter.
    #[test]
    fn the_wait_for_enter_ends_at_a_line_end_the_end_of_input_or_a_failed_read() {
        for (typed, left) in [(&b"\n"[..], &b""[..]), (&b"abc\ndef"[..], &b"def"[..]), (&b"abc\rdef"[..], &b"def"[..]), (&b"abc"[..], &b""[..])] {
            let mut input = typed;
            wait_for_enter(|| {}, &mut input);
            assert_eq!(input, left, "{typed:?}");
        }
        struct Failing;
        impl std::io::Read for Failing {
            fn read(&mut self, _: &mut [u8]) -> std::io::Result<usize> {
                Err(std::io::Error::other("gone"))
            }
        }
        wait_for_enter(|| {}, Failing);
    }

    /// What was typed while the CLI waited for SSHelter is thrown away before the wait reads: a line typed then ("is it stuck?") does not
    /// end the wait the moment its prompt appears; the Enter typed after it does.
    #[test]
    fn the_wait_for_enter_throws_away_what_was_typed_before_it() {
        use std::cell::RefCell;
        use std::rc::Rc;
        /// A terminal's input: what was typed before the prompt, then what is typed after it.
        struct Typed {
            before: Rc<RefCell<Vec<u8>>>,
            after: Vec<u8>,
        }
        impl std::io::Read for Typed {
            fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
                let mut before = self.before.borrow_mut();
                let from = if before.is_empty() { &mut self.after } else { &mut *before };
                let count = buf.len().min(from.len());
                buf[..count].copy_from_slice(&from[..count]);
                from.drain(..count);
                Ok(count)
            }
        }
        let before = Rc::new(RefCell::new(b"x\n".to_vec()));
        let mut input = Typed { before: Rc::clone(&before), after: b"\n".to_vec() };
        wait_for_enter(|| before.borrow_mut().clear(), &mut input);
        assert!(input.after.is_empty(), "the Enter typed after the prompt ended the wait");
        let before = Rc::new(RefCell::new(b"x\n".to_vec()));
        let mut input = Typed { before: Rc::clone(&before), after: b"\n".to_vec() };
        wait_for_enter(|| {}, &mut input);
        assert_eq!(input.after, b"\n", "without the discard the line typed before ends it: the test can tell");
    }

    #[test]
    fn the_terminal_type_is_term_or_xterm_256color() {
        assert_eq!(term_from(Some("screen-256color".into())), "screen-256color");
        assert_eq!(term_from(Some("".into())), "xterm-256color");
        assert_eq!(term_from(None), "xterm-256color");
    }

    /// Wrong arguments are the first thing looked at: the usage and 2, before a terminal is asked for or SSHelter is reached.
    #[cfg(unix)]
    #[test]
    fn wrong_arguments_exit_2_before_anything_else() {
        assert_eq!(run_connect(&os_args(&[])), 2);
        assert_eq!(run_connect(&os_args(&["-oProxyCommand=x"])), 2);
        assert_eq!(run_connect(&os_args(&["web", "db"])), 2);
    }

    /// An argument that is not UTF-8 cannot name a host (aliases and host ids are text): the usage, and 2, like any other wrong one.
    #[cfg(unix)]
    #[test]
    fn an_argument_that_is_not_text_gets_the_usage() {
        use std::os::unix::ffi::OsStringExt;
        let not_text = OsString::from_vec(b"w\xffb".to_vec());
        assert_eq!(texts(&[not_text.clone()]), Err(USAGE.to_string()));
        assert_eq!(texts(&[OsString::from("--id"), not_text.clone()]), Err(USAGE.to_string()));
        assert_eq!(texts(&os_args(&["--id", "0123"])), Ok(args(&["--id", "0123"])));
        assert_eq!(run_connect(&[not_text]), 2);
    }

    #[cfg(unix)]
    mod before_the_session {
        use std::io;

        use super::*;
        use crate::cli::terminal::fake::FakeTermios;
        use crate::cli::terminal::TermiosApi;

        /// Standard input that is not a terminal (a pipe, a file, /dev/null): its attributes cannot be read, as `tcgetattr` fails there.
        struct NotATerminal;

        impl TermiosApi for NotATerminal {
            fn get(&self) -> io::Result<libc::termios> {
                Err(io::Error::from_raw_os_error(libc::ENOTTY))
            }
            fn set(&self, _: &libc::termios, _: bool) -> io::Result<()> {
                panic!("a terminal that is not there is never set")
            }
            fn size(&self) -> Option<(u16, u16)> {
                None
            }
        }

        fn session_on(api: Arc<dyn TermiosApi>, reach: impl FnOnce() -> Result<UnixStream, String>) -> (i32, String) {
            let signals = |_, _, _, _| -> io::Result<()> { panic!("the signals are not taken over before SSHelter answers") };
            session_with(api, reach, signals)
        }

        fn session_with(
            api: Arc<dyn TermiosApi>,
            reach: impl FnOnce() -> Result<UnixStream, String>,
            signals: impl FnOnce(run::Inputs, terminal::Restorer, run::Watchdog, Arc<dyn TermiosApi>) -> io::Result<()>,
        ) -> (i32, String) {
            let wait = || panic!("nothing waits for Enter without --pause-on-error");
            session_asked(HostQuery::Alias("web".into()).into(), api, reach, signals, wait)
        }

        fn session_asked(
            request: Request,
            api: Arc<dyn TermiosApi>,
            reach: impl FnOnce() -> Result<UnixStream, String>,
            signals: impl FnOnce(run::Inputs, terminal::Restorer, run::Watchdog, Arc<dyn TermiosApi>) -> io::Result<()>,
            wait: impl FnOnce(),
        ) -> (i32, String) {
            let mut said = Vec::new();
            let code = super::super::session(request, "xterm-256color".into(), api, reach, signals, wait, &mut said);
            (code, String::from_utf8(said).unwrap())
        }

        /// Without its signal handlers the program could not keep the terminal (Ctrl-C or Ctrl-backslash at a hidden password would end
        /// it with echo off, Ctrl-Z would stop it raw): it says so and ends with 1, before the terminal was changed at all.
        #[test]
        fn signals_that_cannot_be_taken_over_end_the_cli_before_the_terminal_is_changed() {
            let terminal = FakeTermios::new();
            let (ours, theirs) = UnixStream::pair().unwrap();
            let failing = |_, _, _, _| -> io::Result<()> { Err(io::Error::other("no handlers")) };
            assert_eq!(session_with(terminal.clone(), move || Ok(ours), failing), (1, "sshelter: cannot take over the terminal's signals: no handlers\n".to_string()));
            assert!(terminal.sets.lock().unwrap().is_empty(), "the terminal was not changed");
            theirs.set_nonblocking(true).unwrap();
            let read = std::io::Read::read(&mut &theirs, &mut [0u8; 64]);
            assert!(!matches!(read, Ok(count) if count > 0), "nothing was asked of SSHelter: {read:?}");
        }

        /// Without a terminal on standard input the CLI says so and ends with 1 (spec §7.3), and it does so before it reaches SSHelter, let
        /// alone starts it: a program that cannot talk to a terminal must not launch the app just to say that.
        #[test]
        fn without_a_terminal_the_cli_says_so_before_it_reaches_or_starts_sshelter() {
            let reach = || -> Result<UnixStream, String> { panic!("SSHelter must not be reached, let alone started, without a terminal") };
            assert_eq!(session_on(Arc::new(NotATerminal), reach), (1, "sshelter connect needs a terminal.\n".to_string()));
        }

        /// Spec §11: when nothing answers after SSHelter was started, the sentence and 1; the terminal was never changed.
        #[test]
        fn when_nothing_answers_the_cli_says_sshelter_did_not_start_and_leaves_the_terminal_alone() {
            let terminal = FakeTermios::new();
            assert_eq!(session_on(terminal.clone(), || Err(NOT_STARTED.to_string())), (1, "SSHelter did not start within 12 seconds.\n".to_string()));
            assert!(terminal.sets.lock().unwrap().is_empty(), "the terminal was not changed");
        }

        /// Spec §7.3, `--pause-on-error`: SSHelter that cannot be reached is said, the prompt follows, and the program waits for Enter
        /// (once) before it ends with 1; the terminal is left as it was, with its own line editing for that Enter. Without a terminal there
        /// is nothing to wait on: the sentence, and 1.
        #[test]
        fn with_pause_on_error_sshelter_that_cannot_be_reached_is_said_and_waits_for_enter() {
            let terminal = FakeTermios::new();
            let request = Request { host: HostQuery::Alias("web".into()), pause_on_error: true };
            let signals = |_, _, _, _| -> io::Result<()> { panic!("the signals are not taken over before SSHelter answers") };
            let mut waits = 0;
            let said = session_asked(request.clone(), terminal.clone(), || Err(NOT_STARTED.to_string()), signals, || waits += 1);
            assert_eq!(said, (1, "SSHelter did not start within 12 seconds.\nPress Enter to exit.".to_string()));
            assert_eq!(waits, 1);
            assert!(terminal.sets.lock().unwrap().is_empty(), "the terminal was not changed");
            let reach = || -> Result<UnixStream, String> { panic!("SSHelter must not be reached, let alone started, without a terminal") };
            let wait = || panic!("nothing to wait on without a terminal");
            assert_eq!(session_asked(request, Arc::new(NotATerminal), reach, signals, wait), (1, "sshelter connect needs a terminal.\n".to_string()));
        }

        /// The CLI's own setup failing (its signals cannot be taken over) is said and ends with 1 at once, `--pause-on-error` or not:
        /// the pause is for SSHelter's answer, and the terminal was not changed.
        #[test]
        fn with_pause_on_error_the_clis_own_setup_failing_does_not_wait() {
            let terminal = FakeTermios::new();
            let (ours, _theirs) = UnixStream::pair().unwrap();
            let request = Request { host: HostQuery::Alias("web".into()), pause_on_error: true };
            let failing = |_, _, _, _| -> io::Result<()> { Err(io::Error::other("no handlers")) };
            let wait = || panic!("the CLI's own failure does not wait for Enter");
            let said = session_asked(request, terminal.clone(), move || Ok(ours), failing, wait);
            assert_eq!(said, (1, "sshelter: cannot take over the terminal's signals: no handlers\n".to_string()));
            assert!(terminal.sets.lock().unwrap().is_empty(), "the terminal was not changed");
        }
    }

    #[cfg(windows)]
    mod before_the_session_on_windows {
        use std::io;
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::Mutex;
        use std::time::Duration;

        use super::*;
        use crate::cli::terminal::fake::{Call, FakeConsole};
        use crate::cli::terminal::Setting;
        use crate::ipc::pipe_windows::{self, PipeStream};
        use crate::ipc::server::{Handler, Started};

        /// A connection to a pipe of the test's own, whose server end is kept open (in SSHelter's place: nothing is said to it here).
        fn a_pipe() -> (PipeStream, tempfile::TempDir) {
            static NEXT: AtomicUsize = AtomicUsize::new(0);
            let dir = tempfile::tempdir().unwrap();
            let name = format!("sshelter-cli-session-test-{}-{}", std::process::id(), NEXT.fetch_add(1, Ordering::SeqCst));
            let kept = Arc::new(Mutex::new(Vec::new()));
            let handler: Handler = Arc::new(move |stream, _pid| kept.lock().unwrap().push(stream));
            assert_eq!(pipe_windows::listen(&dir.path().join("ipc"), &name, "sshelter-test", handler).unwrap(), Started::Running);
            (pipe_windows::connect(&name, Duration::from_secs(5)).unwrap(), dir)
        }

        fn session_with(
            console: Arc<FakeConsole>,
            reach: impl FnOnce() -> Result<PipeStream, String>,
            control_events: impl FnOnce(run::ControlEvents) -> io::Result<()>,
        ) -> (i32, String) {
            let wait = || panic!("nothing waits for Enter without --pause-on-error");
            session_asked(HostQuery::Alias("web".into()).into(), console, reach, control_events, wait)
        }

        fn session_asked(
            request: Request,
            console: Arc<FakeConsole>,
            reach: impl FnOnce() -> Result<PipeStream, String>,
            control_events: impl FnOnce(run::ControlEvents) -> io::Result<()>,
            wait: impl FnOnce(),
        ) -> (i32, String) {
            let mut said = Vec::new();
            let outputs = || -> (run::Output, run::Output) { panic!("these sessions end before the run") };
            let code = super::super::session(request, "xterm-256color".into(), console, reach, control_events, outputs, wait, &mut said);
            (code, String::from_utf8(said).unwrap())
        }

        /// Spec §7.3: input that is not a console is said, with 1, before SSHelter is reached, let alone started.
        #[test]
        fn without_a_console_the_cli_says_so_before_it_reaches_or_starts_sshelter() {
            let console = FakeConsole::new();
            console.fail(|call| *call == Call::Get(Setting::InputMode));
            let reach = || -> Result<PipeStream, String> { panic!("SSHelter must not be reached, let alone started, without a console") };
            let events = |_| -> io::Result<()> { panic!("nothing is taken over without a console") };
            assert_eq!(session_with(console, reach, events), (1, "sshelter connect needs a terminal.\n".to_string()));
        }

        /// Spec §11: when nothing answers after SSHelter was started, the sentence and 1; the console was never changed.
        #[test]
        fn when_nothing_answers_the_cli_says_sshelter_did_not_start_and_leaves_the_console_alone() {
            let console = FakeConsole::new();
            let events = |_| -> io::Result<()> { panic!("nothing is taken over before SSHelter answers") };
            assert_eq!(session_with(console.clone(), || Err(NOT_STARTED.to_string()), events), (1, "SSHelter did not start within 12 seconds.\n".to_string()));
            assert!(console.changes().is_empty(), "the console was not changed");
        }

        /// Spec §7.3, `--pause-on-error`: SSHelter that cannot be reached is said, the prompt follows, and the program waits for Enter
        /// (once), the console as it was (its own line editing), before it ends with 1.
        #[test]
        fn with_pause_on_error_sshelter_that_cannot_be_reached_is_said_and_waits_for_enter() {
            let console = FakeConsole::new();
            let request = Request { host: HostQuery::Alias("web".into()), pause_on_error: true };
            let events = |_| -> io::Result<()> { panic!("nothing is taken over before SSHelter answers") };
            let mut waits = 0;
            let said = session_asked(request, console.clone(), || Err(NOT_STARTED.to_string()), events, || waits += 1);
            assert_eq!(said, (1, "SSHelter did not start within 12 seconds.\nPress Enter to exit.".to_string()));
            assert_eq!(waits, 1);
            assert!(console.changes().is_empty(), "the console was not changed");
        }

        /// The CLI's own setup failing (the control events cannot be taken over; a console without virtual terminal sequences) is said and
        /// ends with 1 at once, `--pause-on-error` or not: the pause is for SSHelter's answer.
        #[test]
        fn with_pause_on_error_the_clis_own_setup_failing_does_not_wait() {
            let request = Request { host: HostQuery::Alias("web".into()), pause_on_error: true };
            let console = FakeConsole::new();
            let (stream, _dir) = a_pipe();
            let failing = |_| -> io::Result<()> { Err(io::Error::other("no handler")) };
            let wait = || panic!("the CLI's own failure does not wait for Enter");
            let said = session_asked(request.clone(), console, move || Ok(stream), failing, wait);
            assert_eq!(said, (1, "sshelter: cannot take over the console's control keys: no handler\n".to_string()));
            let console = FakeConsole::new();
            console.refuse(|call| matches!(call, Call::Set(Setting::OutputMode, _)));
            let (stream, _dir) = a_pipe();
            let events = |_| -> io::Result<()> { Ok(()) };
            let (code, said) = session_asked(request, console, move || Ok(stream), events, || panic!("the CLI's own failure does not wait for Enter"));
            assert_eq!(code, 1);
            assert!(said.starts_with("sshelter: the console does not support virtual terminal sequences ("), "{said}");
        }

        /// Without its control handler the program could not keep the console (Ctrl-C at a hidden password, or the window closed, would end
        /// it with the console as it set it): it says so and ends with 1, before the console was changed at all.
        #[test]
        fn control_events_that_cannot_be_taken_over_end_the_cli_before_the_console_is_changed() {
            let console = FakeConsole::new();
            let (stream, _dir) = a_pipe();
            let failing = |_| -> io::Result<()> { Err(io::Error::other("no handler")) };
            let said = session_with(console.clone(), move || Ok(stream), failing);
            assert_eq!(said, (1, "sshelter: cannot take over the console's control keys: no handler\n".to_string()));
            assert!(console.changes().is_empty(), "the console was not changed");
        }

        /// Every way out is in place before the console is changed: when the control events are taken over (the last of them) the console
        /// is as it was. A console without virtual terminal sequences cannot be taken over: it says so, ends with 1, and is left as it was.
        #[test]
        fn every_way_out_is_in_place_before_the_console_is_changed_and_a_legacy_console_is_said() {
            let console = FakeConsole::new();
            console.refuse(|call| matches!(call, Call::Set(Setting::OutputMode, _)));
            let (stream, _dir) = a_pipe();
            let unchanged = Arc::new(Mutex::new(None));
            let events = {
                let (console, unchanged) = (Arc::clone(&console), Arc::clone(&unchanged));
                move |_| -> io::Result<()> {
                    *unchanged.lock().unwrap() = Some(console.changes().is_empty());
                    Ok(())
                }
            };
            let (code, said) = session_with(console.clone(), move || Ok(stream), events);
            assert_eq!(*unchanged.lock().unwrap(), Some(true), "the control events were taken over before any change");
            assert_eq!(code, 1);
            assert!(said.starts_with("sshelter: the console does not support virtual terminal sequences ("), "{said}");
            assert_eq!(console.now(), console.start, "left as it was");
        }
    }

    /// Windows: a broker's pipe another program made is refused with `connect`'s own sentence; one the system refuses (an SSHelter that
    /// runs elevated makes a pipe a program that does not cannot open) with the system's reason.
    #[test]
    fn a_pipe_that_cannot_be_used_is_said_why() {
        let squatted = std::io::Error::new(std::io::ErrorKind::PermissionDenied, r"Another program is using SSHelter's session pipe (\\.\pipe\x)");
        assert_eq!(refused(&squatted), r"Another program is using SSHelter's session pipe (\\.\pipe\x)");
        let denied = std::io::Error::from_raw_os_error(5);
        assert!(refused(&denied).starts_with("sshelter: cannot connect to SSHelter ("), "{}", refused(&denied));
    }

    /// Spec §11: the sentence, exactly, when the app does not answer.
    #[test]
    fn when_nothing_answers_after_the_start_the_cli_says_sshelter_did_not_start() {
        use crate::host_start::{ensure_started, SpawnLocks};
        let mut starts = 0;
        let result: Result<(), String> = ensure_started(
            || None,
            || SpawnLocks::Held(()),
            || {
                starts += 1;
                Ok(())
            },
            std::time::Duration::ZERO,
            NOT_STARTED,
        );
        assert_eq!((result, starts), (Err("SSHelter did not start within 12 seconds.".to_string()), 1));
    }
}
