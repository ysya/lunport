//! TEMPORARY, with `ssh_config_directory.rs` (plan 1c deletes both, when host records replace the ssh_config blocks): `ssh -G` with a
//! deadline, the source of host settings that the app gives the adapter (`Sources::effective`).
//!
//! `ssh -G` resolves the settings of a host without connecting, but it does not always come back quickly: it runs the `Match exec`
//! commands of the config and waits for them (a `sleep 2` in one makes it take two seconds), and it reads the `Include`d files, which may
//! sit on a mount that hangs. The broker asks for the settings of every host of a chain at each connect and each reconnect, on the thread
//! that serves the client: a `ssh -G` that never ends would stall the connect with no word to the person, keep its process and do the same
//! at the next try. `effective_within` is `config::intel::effective_config` with a deadline.
//!
//! Which config: the app wires the source without `-F` (`effective_within(alias, None, EFFECTIVE_DEADLINE)`), so `ssh` reads the default
//! config files, `~/.ssh/config` and the system's `ssh_config`, as today's Connect does (`effective_config(alias, None)`). That is on
//! purpose: `sshelter connect` replaces `ssh <alias>`, which reads those files, and the broker has to see the settings `ssh <alias>` would
//! use. Tests give `-F` and a config file of their own.
//!
//! What happens at the deadline: `ssh` started as the leader of a process group of its own (Unix), so the group is killed, and with it the
//! `Match exec` command that `ssh` was waiting for. The killed `ssh` is reaped on a thread of its own: a process that sits in the kernel
//! (a hung mount) dies only when the call returns, and the answer must not wait for that. The pipes are read on threads too, so that
//! neither a full pipe nor a pipe that never ends can hold the answer up: a process that `Match exec` left in the background holds the
//! pipes of an `ssh` that has ended, so they get `PIPE_GRACE` to end and then what was read is the answer. (That process is not killed:
//! it is the person's own command, `ssh <alias>` leaves it behind as well, and a group is only safe to signal while its leader has not
//! been reaped, because its id may be given to another process after that.) On Windows there is no group to kill: only `ssh` is.

use std::io::Read;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::sync::mpsc::{self, Receiver};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

/// How long the app lets one `ssh -G` run. Long enough for a `Match exec` command that does some real work (a lookup on the network, say),
/// short enough that the person who waits for the connect is not left wondering.
pub const EFFECTIVE_DEADLINE: Duration = Duration::from_secs(10);

/// How long the pipes of an `ssh -G` that has ended get to reach end-of-file. Its output is in them already; a process that it started
/// and that is still running holds them open, and the output read so far is then the answer.
const PIPE_GRACE: Duration = Duration::from_secs(1);

/// The longest pause between two looks at whether `ssh -G` has ended (a quick one is seen sooner: the pause starts at a millisecond).
const LONGEST_POLL: Duration = Duration::from_millis(20);

/// `ssh -G <alias>` (with `-F <config_path>` when one is given): the effective settings of a host as (keyword in lower case, value)
/// pairs, repeated keywords kept, like `config::intel::effective_config` but with a deadline. `alias` has to be a saved host (the adapter
/// checks that before it asks): it becomes an argument of `ssh`. `Err` is a sentence for the person: `ssh` is not there, could not be
/// started, did not finish within the deadline (and was killed with what it had started), or failed with the first line it complained about.
pub fn effective_within(alias: &str, config_path: Option<&Path>, deadline: Duration) -> Result<Vec<(String, String)>, String> {
    let mut command = crate::process::background_command("ssh");
    if let Some(path) = config_path {
        command.arg("-F").arg(path);
    }
    // `--`: whatever `alias` looks like, it is the host and never an option of `ssh`.
    command.arg("-G").arg("--").arg(alias);
    command.stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped());
    as_leader_of_its_own_group(&mut command);
    let mut child = crate::process::spawn(&mut command).map_err(|error| match error.kind() {
        std::io::ErrorKind::NotFound => "ssh was not found on this computer.".to_string(),
        _ => format!("ssh could not be started: {error}"),
    })?;
    let readers = read_in_background(child.stdout.take()).and_then(|stdout| Ok((stdout, read_in_background(child.stderr.take())?)));
    let (stdout, stderr) = match readers {
        Ok(readers) => readers,
        Err(error) => {
            give_up(child);
            return Err(format!("ssh -G could not be read: {error}"));
        }
    };
    let started = Instant::now();
    let mut pause = Duration::from_millis(1);
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) => {
                let left = deadline.saturating_sub(started.elapsed());
                if left.is_zero() {
                    give_up(child);
                    return Err(format!("ssh -G did not finish within {}.", in_words(deadline)));
                }
                std::thread::sleep(pause.min(left));
                pause = (pause * 2).min(LONGEST_POLL);
            }
            Err(error) => {
                give_up(child);
                return Err(format!("ssh -G could not be waited for: {error}"));
            }
        }
    };
    let until = Instant::now() + PIPE_GRACE;
    let ((stdout, stdout_error), (stderr, _)) = (stdout.collect(until), stderr.collect(until));
    if !status.success() {
        let stderr = String::from_utf8_lossy(&stderr);
        return Err(stderr.lines().next().unwrap_or("ssh -G failed").trim().to_string());
    }
    // Settings that were read in part are not settings: a missing line would read as "not set".
    if let Some(error) = stdout_error {
        return Err(format!("ssh -G could not be read: {error}"));
    }
    Ok(parse(&String::from_utf8_lossy(&stdout)))
}

/// The lines of `ssh -G`'s output as (keyword in lower case, value) pairs; the same reading as `effective_config`'s.
fn parse(stdout: &str) -> Vec<(String, String)> {
    stdout
        .lines()
        .map(str::trim_end)
        .filter(|line| !line.is_empty())
        .map(|line| {
            let (keyword, rest) = match line.split_once(char::is_whitespace) {
                Some((keyword, rest)) => (keyword, rest.trim_start()),
                None => (line, ""),
            };
            (keyword.to_lowercase(), rest.to_string())
        })
        .collect()
}

/// "10 seconds", "1 second", "0.5 seconds".
fn in_words(deadline: Duration) -> String {
    let seconds = deadline.as_secs_f64();
    if seconds.fract() == 0.0 {
        format!("{} {}", seconds as u64, if seconds == 1.0 { "second" } else { "seconds" })
    } else {
        format!("{seconds:.1} seconds")
    }
}

/// Starts the command as the leader of a process group of its own (Unix), so that what it starts can be killed with it.
fn as_leader_of_its_own_group(command: &mut Command) {
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        command.process_group(0);
    }
    #[cfg(not(unix))]
    let _ = command;
}

/// Ends `child` and, on Unix, everything it started, and has it reaped on a thread of its own (see the module documentation).
fn give_up(mut child: Child) {
    end_with_its_group(&mut child);
    let _ = std::thread::Builder::new().name("sshelter-ssh-g-reaper".to_string()).spawn(move || {
        let _ = child.wait();
    });
}

#[cfg(unix)]
fn end_with_its_group(child: &mut Child) {
    // The group id is the pid of `child` (`as_leader_of_its_own_group`), and the pid is still its own: `child` has not been waited for,
    // so a process that has ended since keeps its pid as a zombie.
    // SAFETY: `killpg` sends a signal and nothing else, to the group of the process this function started.
    if unsafe { libc::killpg(child.id() as libc::pid_t, libc::SIGKILL) } != 0 {
        let _ = child.kill();
    }
}

#[cfg(not(unix))]
fn end_with_its_group(child: &mut Child) {
    let _ = child.kill();
}

/// One pipe of the child, read on a thread of its own: a full pipe cannot stop the child, and a pipe that never ends cannot stop us.
struct PipeReader {
    bytes: Arc<Mutex<Vec<u8>>>,
    /// How the reading ended: at end-of-file, or with the error that stopped it.
    ended: Receiver<std::io::Result<()>>,
}

fn read_in_background(pipe: Option<impl Read + Send + 'static>) -> std::io::Result<PipeReader> {
    let bytes = Arc::new(Mutex::new(Vec::new()));
    let (finished, ended) = mpsc::channel();
    let sink = Arc::clone(&bytes);
    std::thread::Builder::new().name("sshelter-ssh-g-pipe".to_string()).spawn(move || {
        let mut result = Ok(());
        if let Some(mut pipe) = pipe {
            let mut chunk = [0u8; 4096];
            loop {
                match pipe.read(&mut chunk) {
                    Ok(0) => break,
                    Ok(count) => sink.lock().unwrap_or_else(PoisonError::into_inner).extend_from_slice(&chunk[..count]),
                    // A signal that arrives during the read is no end of file: read again.
                    Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
                    Err(error) => {
                        result = Err(error);
                        break;
                    }
                }
            }
        }
        let _ = finished.send(result);
    })?;
    Ok(PipeReader { bytes, ended })
}

impl PipeReader {
    /// What the pipe has delivered by `until` (or when it ends, if that comes first), and the error that ended the reading, if one did.
    fn collect(&self, until: Instant) -> (Vec<u8>, Option<std::io::Error>) {
        let error = match self.ended.recv_timeout(until.saturating_duration_since(Instant::now())) {
            Ok(Err(error)) => Some(error),
            _ => None,
        };
        (self.bytes.lock().unwrap_or_else(PoisonError::into_inner).clone(), error)
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    /// A pipe that cannot be read to its end is an error, with what was read before it: settings read in part are not settings.
    #[test]
    fn a_pipe_that_fails_while_it_is_read_is_reported_with_what_was_read_before() {
        struct Breaks(u8);
        impl Read for Breaks {
            fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
                self.0 += 1;
                match self.0 {
                    1 => {
                        buffer[..6].copy_from_slice(b"user x");
                        Ok(6)
                    }
                    _ => Err(std::io::Error::other("the pipe broke")),
                }
            }
        }
        let broken = read_in_background(Some(Breaks(0))).unwrap().collect(Instant::now() + Duration::from_secs(5));
        assert_eq!((broken.0.as_slice(), broken.1.map(|error| error.to_string())), (&b"user x"[..], Some("the pipe broke".to_string())));
        let whole = read_in_background(Some(&b"user x"[..])).unwrap().collect(Instant::now() + Duration::from_secs(5));
        assert_eq!((whole.0.as_slice(), whole.1.is_none()), (&b"user x"[..], true));
    }

    #[test]
    fn a_deadline_is_worded_in_seconds() {
        assert_eq!(in_words(Duration::from_secs(10)), "10 seconds");
        assert_eq!(in_words(Duration::from_secs(1)), "1 second");
        assert_eq!(in_words(Duration::from_millis(500)), "0.5 seconds");
    }

    /// The answer is the one `effective_config` gives, line for line, and so are the complaints of a `ssh -G` that fails; an alias that
    /// looks like an option is a host name for `ssh`, never an option.
    #[test]
    fn it_answers_what_effective_config_answers_and_complains_the_way_it_does() {
        let Some(_tools) = crate::ssh::testing::harness::tools() else { return };
        let dir = tempfile::tempdir().unwrap();
        let config = dir.path().join("config");
        std::fs::write(
            &config,
            "Host bastion\n  HostName gate.example.com\n  User ops\nHost db\n  HostName 10.0.0.5\n  Port 2222\n  ProxyJump bastion\n  IdentityFile ~/.ssh/a\n  IdentityFile ~/.ssh/b\n  SendEnv LANG LC_*\n",
        )
        .unwrap();
        for alias in ["bastion", "db", "unlisted"] {
            let bounded = effective_within(alias, Some(&config), EFFECTIVE_DEADLINE).unwrap();
            assert_eq!(bounded, crate::config::intel::effective_config(alias, Some(&config)).unwrap(), "{alias}");
            assert!(bounded.iter().any(|(key, _)| key == "hostname"), "{alias}: an answer, not an empty one");
        }
        let broken = dir.path().join("broken");
        std::fs::write(&broken, "Host x\n  Bogus yes\n").unwrap();
        let error = effective_within("x", Some(&broken), EFFECTIVE_DEADLINE).unwrap_err();
        assert!(error.contains("Bad configuration option"), "{error}");
        assert_eq!(Err(error), crate::config::intel::effective_config("x", Some(&broken)).map_err(|error| error.to_string()));
        let missing = dir.path().join("missing");
        let error = effective_within("x", Some(&missing), EFFECTIVE_DEADLINE).unwrap_err();
        assert_eq!(Err(error), crate::config::intel::effective_config("x", Some(&missing)).map_err(|error| error.to_string()));
        let option = effective_within("-oProxyCommand=evil", Some(&config), EFFECTIVE_DEADLINE).unwrap_err();
        assert!(option.contains("invalid characters"), "a host name, which ssh rejects, and not an option it would take: {option}");
    }

    /// `Match exec` commands run during `ssh -G`, which waits for them. These tests use `sleep` and a shell, and look at processes with
    /// `ps`.
    #[cfg(unix)]
    mod match_exec {
        use std::path::Path;
        use std::time::Instant;

        use super::*;
        use crate::session::directory::{DirectoryError, HostDirectory};
        use crate::session::pins::PinStore;
        use crate::session::protocol::HostQuery;
        use crate::session::ssh_config_directory::{Sources, SshConfigDirectory};

        /// `ps -o <what> -p <pid>` for one process: what `ps` printed, trimmed (empty when there is no such process).
        fn ps(what: &str, pid: u32) -> String {
            let out = crate::process::output(std::process::Command::new("ps").args(["-ww", "-o", what, "-p", &pid.to_string()])).expect("ps runs");
            String::from_utf8_lossy(&out.stdout).trim().to_string()
        }

        /// Whether the process exists and is not a zombie (a process that is dead and not collected yet has state `Z`).
        fn is_running(pid: u32) -> bool {
            let state = ps("stat=", pid);
            !state.is_empty() && !state.starts_with('Z')
        }

        /// Waits up to `within` for the process to be gone.
        fn gone_within(pid: u32, within: Duration) -> bool {
            let until = Instant::now() + within;
            while is_running(pid) {
                if Instant::now() >= until {
                    return false;
                }
                std::thread::sleep(Duration::from_millis(50));
            }
            true
        }

        /// The pid that a `Match exec` command of a test wrote into `pidfile`.
        fn pid_in(pidfile: &Path) -> u32 {
            let text = std::fs::read_to_string(pidfile).unwrap_or_else(|error| panic!("the Match exec command did not run ({error})"));
            text.trim().parse().unwrap_or_else(|_| panic!("not a pid: {text:?}"))
        }

        /// Ends a `sleep` that a test started when it is dropped, so that a failing test leaves nothing behind. (Only a process that is a
        /// `sleep` still: a pid that was reused is left alone.)
        struct EndSleep(u32);

        impl Drop for EndSleep {
            fn drop(&mut self) {
                if ps("command=", self.0).starts_with("sleep") {
                    // SAFETY: SIGKILL to the one process `ps` has just shown to be the `sleep` this test started.
                    unsafe { libc::kill(self.0 as libc::pid_t, libc::SIGKILL) };
                }
            }
        }

        /// A `Match exec` command that does not end stalls `ssh -G` (it waits for the command): the answer is a failure with a sentence, at
        /// the deadline; the command is killed with `ssh` (its process group); and the resolve of the host fails with that sentence
        /// instead of waiting.
        #[test]
        fn a_stalled_match_exec_fails_the_resolve_at_the_deadline_and_leaves_no_process() {
            let Some(_tools) = crate::ssh::testing::harness::tools() else { return };
            let dir = tempfile::tempdir().unwrap();
            let (config, pidfile) = (dir.path().join("config"), dir.path().join("sleep.pid"));
            std::fs::write(
                &config,
                format!("Match exec \"echo $$ > '{}'; exec sleep 30\"\n  User viaexec\nHost slow\n  HostName slow.example.com\n", pidfile.display()),
            )
            .unwrap();
            let (doc_path, ssh_g_path) = (config.clone(), config.clone());
            let sources = Sources {
                doc: Box::new(move || crate::config::include::load_doc(&doc_path).map_err(|error| error.to_string())),
                effective: Box::new(move |alias| effective_within(alias, Some(&ssh_g_path), Duration::from_secs(1))),
                vault_key: Box::new(|_| None),
                password_saved: Box::new(|_| false),
            };
            let directory = SshConfigDirectory::new(sources, PinStore::new(dir.path().join("host-pins.json")));
            let started = Instant::now();
            let answer = directory.resolve(&HostQuery::Alias("slow".into()));
            let elapsed = started.elapsed();
            let sleeper = pid_in(&pidfile);
            let _cleanup = EndSleep(sleeper);
            assert_eq!(
                answer,
                Err(DirectoryError::Failed("SSHelter cannot read the settings of slow: ssh -G did not finish within 1 second.".to_string())),
                "after {elapsed:?}"
            );
            assert!(elapsed >= Duration::from_secs(1) && elapsed < Duration::from_secs(5), "the deadline is 1 second; it took {elapsed:?}");
            assert!(gone_within(sleeper, Duration::from_secs(3)), "the `sleep` (pid {sleeper}) of the Match exec is still running");
            let listing = crate::process::output(std::process::Command::new("ps").args(["-axww", "-o", "stat=,command="])).unwrap();
            let leftovers: Vec<String> = String::from_utf8_lossy(&listing.stdout)
                .lines()
                .filter(|line| line.contains(dir.path().to_str().unwrap()) && !line.trim_start().starts_with('Z'))
                .map(str::to_string)
                .collect();
            assert!(leftovers.is_empty(), "processes of the stalled ssh -G are left: {leftovers:?}");
        }

        /// A process that `Match exec` leaves behind keeps `ssh`'s pipes open; once `ssh` is gone its answer is complete, and the pipe that
        /// never ends does not hold it up.
        #[test]
        fn a_process_left_behind_by_match_exec_does_not_hold_the_answer_up() {
            let Some(_tools) = crate::ssh::testing::harness::tools() else { return };
            let dir = tempfile::tempdir().unwrap();
            let (config, pidfile) = (dir.path().join("config"), dir.path().join("sleep.pid"));
            std::fs::write(
                &config,
                format!("Match exec \"sleep 30 & echo $! > '{}'; true\"\nHost leftover\n  HostName leftover.example.com\n", pidfile.display()),
            )
            .unwrap();
            let started = Instant::now();
            let answer = effective_within("leftover", Some(&config), EFFECTIVE_DEADLINE);
            let elapsed = started.elapsed();
            let _cleanup = EndSleep(pid_in(&pidfile));
            let answer = answer.expect("ssh -G finished");
            assert!(answer.contains(&("hostname".to_string(), "leftover.example.com".to_string())), "{answer:?}");
            assert!(elapsed < Duration::from_secs(5), "the answer waited for the process that was left behind: {elapsed:?}");
        }
    }
}
