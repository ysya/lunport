//! `sshelter connect` (own-ssh spec §7.3): the terminal's end of a session in the app. macOS and Linux in this version; on Windows it
//! says so (plan 1b; the Windows console is phase 3).

#[cfg(unix)]
pub mod client;
#[cfg(unix)]
pub mod run;
#[cfg(unix)]
pub mod terminal;

use crate::session::protocol::HostQuery;

/// What `sshelter connect` prints when the app does not answer after it was started (spec §7.3, §11).
pub const NOT_STARTED: &str = "SSHelter did not start within 12 seconds.";

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

/// The terminal type the shell is opened for: `$TERM`, or `xterm-256color` without one (spec §7.3).
pub fn term_from(value: Option<std::ffi::OsString>) -> String {
    value.and_then(|value| value.into_string().ok()).filter(|term| !term.is_empty()).unwrap_or_else(|| "xterm-256color".to_string())
}

/// `sshelter connect <arguments>`: returns the exit code (main.rs exits with it). Started before anything of Tauri.
#[cfg(unix)]
pub fn run_connect(args: &[String]) -> i32 {
    use std::os::unix::net::UnixStream;
    use std::sync::Arc;

    use crate::host_start::{ensure_started, start_host, take_spawn_locks, START_WAIT};

    let host = match parse_args(args) {
        Ok(host) => host,
        Err(usage) => {
            eprintln!("{usage}");
            return 2;
        }
    };
    let socket = match crate::fsutil::app_data_root() {
        Ok(root) => crate::session::socket_path(&root),
        Err(error) => {
            eprintln!("sshelter: {error}");
            return 1;
        }
    };
    let stream = match ensure_started(|| UnixStream::connect(&socket).ok(), take_spawn_locks, start_host, START_WAIT, NOT_STARTED) {
        Ok(stream) => stream,
        Err(text) => {
            eprintln!("{text}");
            return 1;
        }
    };
    let mut tty = match terminal::Tty::new(Arc::new(terminal::StdinTermios)) {
        Ok(tty) => tty,
        Err(_) => {
            eprintln!("sshelter connect needs a terminal.");
            return 1;
        }
    };
    terminal::restore_on_panic(tty.restorer());
    let (sender, receiver) = std::sync::mpsc::channel();
    run::stdin_thread(sender.clone());
    if let Err(error) = run::signal_thread(sender.clone(), || terminal::TermiosApi::size(&terminal::StdinTermios)) {
        eprintln!("sshelter: cannot follow the terminal's size: {error}");
    }
    let term = term_from(std::env::var_os("TERM"));
    run::run(stream, host, term, &mut tty, (sender, receiver), &mut std::io::stdout(), &mut std::io::stderr())
}

/// Windows: the console work is phase 3 (spec §13, §16). A release build has no console, so the sentence shows only where one exists.
#[cfg(windows)]
pub fn run_connect(_args: &[String]) -> i32 {
    eprintln!("sshelter connect is not supported on Windows yet.");
    1
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(list: &[&str]) -> Vec<String> {
        list.iter().map(|arg| arg.to_string()).collect()
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
