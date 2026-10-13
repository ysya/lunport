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

/// What `sshelter connect` prints when the app does not answer after it was started (spec §7.3, §11).
pub const NOT_STARTED: &str = "SSHelter did not start within 12 seconds.";

/// What `sshelter connect` prints when standard input is not a terminal (spec §7.3).
pub const NEEDS_TERMINAL: &str = "sshelter connect needs a terminal.";

/// How `sshelter connect` is used.
pub const USAGE: &str = "usage: sshelter connect <alias>\n       sshelter connect --id <host id>";

/// The host the arguments after `connect` name: an alias, or `--id` and a host id.
pub fn parse_args(args: &[String]) -> Result<HostQuery, String> {
    match args {
        [flag, id] if flag == "--id" && !id.is_empty() && !id.starts_with('-') => Ok(HostQuery::Id(id.clone())),
        [alias] if !alias.is_empty() && !alias.starts_with('-') => Ok(HostQuery::Alias(alias.clone())),
        _ => Err(USAGE.to_string()),
    }
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
    let host = match texts(args).and_then(|args| parse_args(&args)) {
        Ok(host) => host,
        Err(usage) => {
            eprintln!("{usage}");
            return 2;
        }
    };
    let term = term_from(std::env::var_os("TERM"));
    let signals = |inputs, terminal, watchdog, size: Arc<dyn terminal::TermiosApi>| run::signal_thread(inputs, terminal, watchdog, move || size.size());
    session(host, term, Arc::new(terminal::StdinTermios), reach_broker, signals, &mut std::io::stderr())
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
/// says before the session to `stderr` (the terminal's).
#[cfg(unix)]
fn session(
    host: HostQuery,
    term: String,
    api: Arc<dyn terminal::TermiosApi>,
    reach: impl FnOnce() -> Result<UnixStream, String>,
    signals: impl FnOnce(run::Inputs, terminal::Restorer, run::Watchdog, Arc<dyn terminal::TermiosApi>) -> std::io::Result<()>,
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
        Err(text) => {
            let _ = writeln!(stderr, "{text}");
            return 1;
        }
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
    let code = run::run(stream, host, term, &mut tty, (inputs, queue), own_writer(std::io::stdout()), own_writer(std::io::stderr()));
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
    let host = match texts(args).and_then(|args| parse_args(&args)) {
        Ok(host) => host,
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
    session(host, term, console, reach_broker, inputs_windows::take_over_control_events, outputs, &mut std::io::stderr())
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
/// ends the program the default way, and the console is as it was. Writes what the CLI says before the session to `stderr`.
#[cfg(windows)]
fn session(
    host: HostQuery,
    term: String,
    api: Arc<dyn terminal::ConsoleApi>,
    reach: impl FnOnce() -> Result<crate::ipc::pipe_windows::PipeStream, String>,
    control_events: impl FnOnce(run::ControlEvents) -> std::io::Result<()>,
    outputs: impl FnOnce() -> (run::Output, run::Output),
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
        Err(text) => {
            let _ = writeln!(stderr, "{text}");
            return 1;
        }
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
    let code = run::run(stream, host, term, &mut tty, (inputs, queue), stdout, stderr_output);
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
        assert_eq!(parse_args(&args(&["web"])), Ok(HostQuery::Alias("web".into())));
        assert_eq!(parse_args(&args(&["--id", "0123456789abcdef"])), Ok(HostQuery::Id("0123456789abcdef".into())));
        for wrong in [&[][..], &["--id"], &["web", "db"], &["-oProxyCommand=x"], &["--id", "-x"], &[""], &["--new-tab", "web"]] {
            assert_eq!(parse_args(&args(wrong)), Err(USAGE.to_string()), "{wrong:?}");
        }
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
            let mut said = Vec::new();
            let code = super::super::session(HostQuery::Alias("web".into()), "xterm-256color".into(), api, reach, signals, &mut said);
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
