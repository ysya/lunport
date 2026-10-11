//! Integration tests of the russh engine against a scratch OpenSSH server (own-ssh spec §12). Each test starts its own sshd; a test
//! returns early, printing "skipped", where the OpenSSH tools are missing (`SSHELTER_REQUIRE_OPENSSH=1` turns that into a failure).

mod connect;
mod exec;
mod liveness;
mod shell;

use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use super::russh_engine::{EngineOptions, RusshEngine};
use super::testing::doubles::{TestPolicy, VaultAuth};
use super::testing::fixture::Server;
use super::{Session, ShellChannel, SshEngine, Target};

/// The scratch sshd starts `/bin/sh` for a shell, so the interactive shell is the same POSIX sh on every machine and its prompt does not
/// depend on the developer's zsh configuration. (`ForceCommand` runs through the user's login shell with `-c`, and it replaces every
/// command, so it hands a requested command on to `eval` to keep `exec` usable on the same server.)
const SHELL_SERVER: &[&str] = &["ForceCommand if [ -n \"$SSH_ORIGINAL_COMMAND\" ]; then eval \"$SSH_ORIGINAL_COMMAND\"; else exec /bin/sh; fi"];

/// An engine with a small runtime, one per test.
fn engine() -> RusshEngine {
    RusshEngine::with_options(EngineOptions { worker_threads: 2, ..EngineOptions::default() })
}

/// sshd logs accepted logins at INFO; the default of the harness is ERROR.
const LOG_LOGINS: &str = "LogLevel INFO";

/// How many public-key logins sshd has accepted (needs `LOG_LOGINS`).
fn accepted_logins(server: &Server) -> usize {
    server.sshd.log().lines().filter(|line| line.contains("Accepted publickey")).count()
}

/// Connects to `server` through the trait, the way the broker will: a trusting policy and the server's user key under the id `k1`.
fn open_session(engine: &RusshEngine, server: &Server) -> Box<dyn Session> {
    open_session_to(engine, &server.target("k1"), &server.vault("k1"))
}

fn open_session_to(engine: &RusshEngine, target: &Target, auth: &VaultAuth) -> Box<dyn Session> {
    engine.connect(target, &*TestPolicy::trusting(), auth).expect("the engine connects")
}

/// Runs a command that does nothing, so that sshd has finished setting the session up. A client that leaves while sshd is still busy with
/// that (on macOS it takes a moment after the login has been logged: BSM auditing) makes sshd die on a broken pipe before it reads the
/// disconnect message, and then no "Received disconnect" is ever logged: a test that looks for the message must settle first.
fn settle(session: &dyn Session) {
    session.exec("true", Duration::from_secs(20), 1024).expect("a command runs");
}

/// Reads a shell on a thread of its own, as the broker will, so a test can wait for text to show up without ever blocking on the shell.
struct ShellProbe {
    shell: Arc<dyn ShellChannel>,
    seen: Arc<Mutex<Vec<u8>>>,
}

impl ShellProbe {
    fn start(shell: Box<dyn ShellChannel>) -> ShellProbe {
        let shell: Arc<dyn ShellChannel> = Arc::from(shell);
        let seen = Arc::new(Mutex::new(Vec::new()));
        let (reader, sink) = (Arc::clone(&shell), Arc::clone(&seen));
        std::thread::spawn(move || {
            let mut buf = [0u8; 4096];
            while let Ok(count) = reader.read(&mut buf) {
                if count == 0 {
                    break;
                }
                sink.lock().unwrap_or_else(PoisonError::into_inner).extend_from_slice(&buf[..count]);
            }
        });
        ShellProbe { shell, seen }
    }

    fn text(&self) -> String {
        String::from_utf8_lossy(&self.seen.lock().unwrap_or_else(PoisonError::into_inner)).into_owned()
    }

    /// Waits up to `seconds` until `find` returns something for everything read so far; `Err` carries the text read when time ran out.
    fn wait_for<T>(&self, seconds: u64, find: impl Fn(&str) -> Option<T>) -> Result<T, String> {
        let deadline = Instant::now() + Duration::from_secs(seconds);
        loop {
            let text = self.text();
            if let Some(found) = find(&text) {
                return Ok(found);
            }
            if Instant::now() >= deadline {
                return Err(text);
            }
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    fn wait_for_text(&self, seconds: u64, needle: &str) -> Result<(), String> {
        self.wait_for(seconds, |text| text.contains(needle).then_some(()))
    }

    /// Types `line` and presses Enter.
    fn type_line(&self, line: &str) {
        self.shell.write(format!("{line}\n").as_bytes()).expect("the shell takes input");
    }

    /// Asks the shell for the terminal size and returns "<rows> <cols>". The PTY echoes the command as `SIZE[%s]`, the answer reads
    /// `SIZE[40 120]`: only the answer has two numbers between the brackets.
    fn stty_size(&self) -> Result<String, String> {
        let before = self.text().len();
        self.type_line("printf 'SIZE[%s]\\n' \"$(stty size)\"");
        self.wait_for(10, |text| size_in(&text[before..]))
    }
}

fn size_in(output: &str) -> Option<String> {
    output.split("SIZE[").skip(1).find_map(|rest| {
        let inside = rest.split(']').next()?;
        let numbers: Vec<&str> = inside.split(' ').collect();
        let digits = |text: &&str| !text.is_empty() && text.bytes().all(|byte| byte.is_ascii_digit());
        (numbers.len() == 2 && numbers.iter().all(digits)).then(|| inside.to_string())
    })
}

#[test]
fn only_the_answer_counts_not_the_echoed_command() {
    assert_eq!(size_in("printf 'SIZE[%s]\\n' \"$(stty size)\"\r\nSIZE[40 120]\r\n"), Some("40 120".to_string()));
    assert_eq!(size_in("printf 'SIZE[%s]\\n' \"$(stty size)\"\r\n"), None);
    assert_eq!(size_in("SIZE[0 0]"), Some("0 0".to_string()));
    assert_eq!(size_in("SIZE[40]"), None);
    assert_eq!(size_in("SIZE[40 12x]"), None);
}
