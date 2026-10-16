//! Starting SSHelter in the background for a client that needs it and finds it not running (own-ssh spec §4): the MCP adapter, and
//! `sshelter connect` from plan 1b on. Both start the same thing, the app as a host (`--host`, its window hidden), under the same two
//! locks, so that they never start two. Moved here from `mcp.rs` unchanged, but for four things: the message for "nothing answered" is
//! the caller's (spec §11 gives the CLI its own); the flag is `--host`, with the old `--mcp-host` still accepted (an update's
//! "Install & restart" starts the app again with the arguments it was started with); the line it writes to stderr starts with `[host]`
//! (not `[mcp]`); and the thread that reaps the app it started is `sshelter-host-wait` (not `sshelter-mcp-host-wait`).

use std::fs::{File, OpenOptions, TryLockError};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{Mutex, MutexGuard, PoisonError};
use std::thread;
use std::time::{Duration, Instant};

use crate::error::AppError;
use crate::fsutil;

/// First argument that starts SSHelter as the host of its clients (main.rs): the desktop app, in the background.
pub const HOST_FLAG: &str = "--host";
/// The host flag before plan 1b. Still accepted, for the restart of an app that was started with it.
pub const LEGACY_HOST_FLAG: &str = "--mcp-host";

/// Whether `arg`, the first argument (main.rs reads the mode from it), starts SSHelter as a host.
pub fn is_host_flag(arg: &str) -> bool {
    arg == HOST_FLAG || arg == LEGACY_HOST_FLAG
}

/// How long a client waits for the SSHelter it started, and how often it looks.
pub(crate) const START_WAIT: Duration = Duration::from_secs(12);
const START_POLL: Duration = Duration::from_millis(120);

/// Serializes starting SSHelter between this process's calls, which can run in parallel (the MCP adapter's tool calls).
static SPAWN_LOCK: Mutex<()> = Mutex::new(());

/// What a call got when it asked for the spawn locks.
pub(crate) enum SpawnLocks<G> {
    /// Start SSHelter while holding `G`.
    Held(G),
    /// Another client kept `mcp-spawn.lock` past the deadline: it may be stopped in the middle
    /// of a start (its AI CLI or its terminal suspended, for example).
    Busy,
    /// The development write policy refused the lock; starting without it is unsafe.
    Denied(String),
}

/// Return what `answering` finds (a bridge, a socket) once it answers. If nothing does, take the
/// spawn locks and look again: a parallel call or another client may have started SSHelter
/// meanwhile. Only if still nothing answers, start SSHelter once and wait for it. Several
/// near-simultaneous starts could each claim the single instance before the others see it
/// (macOS), and leave two SSHelters running; so when another client keeps the locks too long,
/// look once more instead of starting a second one. `no_answer` is the error when nothing
/// answers in the end.
pub(crate) fn ensure_started<T, G>(
    mut answering: impl FnMut() -> Option<T>,
    lock: impl FnOnce() -> SpawnLocks<G>,
    start: impl FnOnce() -> Result<(), String>,
    wait: Duration,
    no_answer: &str,
) -> Result<T, String> {
    if let Some(found) = answering() {
        return Ok(found);
    }
    let _locks = match lock() {
        SpawnLocks::Held(locks) => locks,
        SpawnLocks::Busy => return answering().ok_or_else(|| no_answer.to_string()),
        SpawnLocks::Denied(reason) => return Err(reason),
    };
    if let Some(found) = answering() {
        return Ok(found);
    }
    start()?;
    let deadline = Instant::now() + wait;
    while Instant::now() < deadline {
        thread::sleep(START_POLL);
        if let Some(found) = answering() {
            return Ok(found);
        }
    }
    Err(no_answer.to_string())
}

/// `SPAWN_LOCK`, and `mcp-spawn.lock` unless it can't be taken here.
pub(crate) type SpawnGuards = (MutexGuard<'static, ()>, Option<File>);

pub(crate) fn take_spawn_locks() -> SpawnLocks<SpawnGuards> {
    // The deadline counts from before this call waits for this process's other calls (the adapter's
    // tool calls), so a call never waits much longer than `START_WAIT` for the locks.
    let deadline = Instant::now() + START_WAIT;
    take_spawn_locks_at(spawn_lock_path().map_err(|e| e.to_string()), deadline)
}

/// Takes `SPAWN_LOCK` (this process's calls), then the exclusive file lock on `path`, by
/// default `mcp-spawn.lock` in the app data directory (other clients: other AI sessions, other
/// terminals), which the system releases when its holder exits. Dropping the guards releases both.
/// A file lock that can't be taken here at all (no app data directory, a file system without
/// locks) is skipped, as before there was one: only this process's calls wait for each other.
fn take_spawn_locks_at(
    path: Result<PathBuf, String>,
    deadline: Instant,
) -> SpawnLocks<SpawnGuards> {
    let calls = SPAWN_LOCK.lock().unwrap_or_else(PoisonError::into_inner);
    let file = match path {
        Ok(path) => lock_file_until(&path, deadline),
        Err(e) => FileLock::Unavailable(e),
    };
    match file {
        FileLock::Held(file) => SpawnLocks::Held((calls, Some(file))),
        FileLock::Busy => SpawnLocks::Busy,
        FileLock::Denied(reason) => SpawnLocks::Denied(reason),
        FileLock::Unavailable(reason) => {
            eprintln!("[host] starting SSHelter without mcp-spawn.lock: {reason}");
            SpawnLocks::Held((calls, None))
        }
    }
}

/// The lock file keeps the name it had when only the MCP adapter started SSHelter: a 0.17 adapter
/// and a newer client on the same computer still take the same lock.
fn spawn_lock_path() -> Result<PathBuf, AppError> {
    Ok(crate::fsutil::app_data_root()?.join("mcp-spawn.lock"))
}

enum FileLock {
    Held(File),
    /// Someone else still held it at the deadline.
    Busy,
    /// It can't be opened or locked here.
    Unavailable(String),
    Denied(String),
}

/// Open `path`, creating it and its directory, and take an exclusive lock on it, trying until
/// `deadline`.
fn lock_file_until(path: &Path, deadline: Instant) -> FileLock {
    if let Err(error) = fsutil::check_write(path) {
        return FileLock::Denied(error.to_string());
    }
    let opened = path
        .parent()
        .map_or(Ok(()), fsutil::ensure_dir_secure)
        .map_err(|e| e.to_string())
        .and_then(|()| {
            OpenOptions::new()
                .create(true)
                .truncate(false)
                .write(true)
                .open(path)
                .map_err(|e| e.to_string())
        });
    let file = match opened {
        Ok(file) => file,
        Err(e) => return FileLock::Unavailable(format!("cannot open {}: {e}", path.display())),
    };
    loop {
        match file.try_lock() {
            Ok(()) => return FileLock::Held(file),
            Err(TryLockError::WouldBlock) if Instant::now() < deadline => thread::sleep(START_POLL),
            Err(TryLockError::WouldBlock) => return FileLock::Busy,
            Err(TryLockError::Error(e)) => {
                return FileLock::Unavailable(format!("cannot lock {}: {e}", path.display()))
            }
        }
    }
}

/// Start SSHelter in the background, or, when it already runs, hand over to it (single
/// instance): the running SSHelter rewrites the MCP runtime file and starts the broker's socket
/// again if it is not listening (lib.rs `on_second_launch`).
pub(crate) fn start_host() -> Result<(), String> {
    let exe = std::env::current_exe().map_err(|e| format!("cannot locate SSHelter: {e}"))?;
    let mut host = crate::process::spawn(&mut host_command(&exe))
        .map_err(|e| format!("cannot start SSHelter desktop: {e}"))?;
    // A launch that hands over exits at once: reap it instead of leaving a zombie behind.
    let _ = thread::Builder::new()
        .name("sshelter-host-wait".to_string())
        .spawn(move || {
            let _ = host.wait();
        });
    Ok(())
}

/// `--host` decides the hand-over and keeps SSHelter running when its window closes;
/// `SSHELTER_START_HIDDEN=1` keeps the window hidden at this start only (lib.rs `starts_hidden`).
fn host_command(exe: &Path) -> Command {
    let mut command = Command::new(exe);
    command
        .arg(HOST_FLAG)
        .env(crate::START_HIDDEN_ENV, "1")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    detach_from_client(&mut command);
    command
}

/// Start the host outside the client's process group: an AI tool that ends its session by killing
/// its MCP server's process group, or a terminal tab that is closed with `sshelter connect` in it,
/// must not take SSHelter down with it.
fn detach_from_client(command: &mut Command) {
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        command.process_group(0);
    }
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        use windows_sys::Win32::System::Threading::{CREATE_NEW_PROCESS_GROUP, DETACHED_PROCESS};
        // Its own process group: the client's console Ctrl+C / Ctrl+Break does not reach it.
        // No console: closing the console the AI tool runs in does not end it either.
        command.creation_flags(CREATE_NEW_PROCESS_GROUP | DETACHED_PROCESS);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;

    const NO_ANSWER: &str = "nothing answered";

    #[test]
    fn the_host_flag_is_the_new_one_and_the_old_one_is_still_accepted() {
        assert!(is_host_flag("--host"));
        assert!(is_host_flag("--mcp-host"));
        assert!(!is_host_flag("--mcp"));
        assert!(!is_host_flag("--host=1"));
        assert!(!is_host_flag("--mcp-host=1"));
        assert!(!is_host_flag("connect"));
    }

    #[test]
    fn a_call_that_finds_a_bridge_once_it_holds_the_locks_starts_nothing() {
        // Another call or adapter started SSHelter while this one waited for the locks.
        let mut answers = [None, Some("bridge")].into_iter();
        let found = ensure_started(
            || answers.next().flatten(),
            || SpawnLocks::Held(()),
            || panic!("SSHelter already answers: starting it again could run two"),
            Duration::ZERO,
            NO_ANSWER,
        );
        assert_eq!(found, Ok("bridge"));
    }

    #[test]
    fn parallel_calls_start_sshelter_once() {
        let running = Arc::new(AtomicBool::new(false));
        let starts = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let locks = Arc::new(Mutex::new(()));
        let calls: Vec<_> = (0..4)
            .map(|_| {
                let (running, starts, locks) = (running.clone(), starts.clone(), locks.clone());
                thread::spawn(move || {
                    ensure_started(
                        || running.load(Ordering::SeqCst).then_some(()),
                        || SpawnLocks::Held(locks.lock().unwrap()),
                        || {
                            starts.fetch_add(1, Ordering::SeqCst);
                            // Its bridge answers a little later, as a real start's does.
                            let running = running.clone();
                            thread::spawn(move || {
                                thread::sleep(Duration::from_millis(50));
                                running.store(true, Ordering::SeqCst);
                            });
                            Ok(())
                        },
                        Duration::from_secs(5),
                        NO_ANSWER,
                    )
                })
            })
            .collect();
        for call in calls {
            assert_eq!(call.join().unwrap(), Ok(()));
        }
        assert_eq!(starts.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn no_answer_after_the_start_says_what_to_do() {
        let mut starts = 0;
        let result: Result<(), String> = ensure_started(
            || None,
            || SpawnLocks::Held(()),
            || {
                starts += 1;
                Ok(())
            },
            Duration::ZERO,
            NO_ANSWER,
        );
        assert_eq!(result, Err(NO_ANSWER.to_string()));
        assert_eq!(starts, 1);
    }

    #[test]
    fn when_another_adapter_keeps_the_locks_one_more_look_decides() {
        let no_start = || -> Result<(), String> { panic!("the other adapter may be starting it") };
        let mut answers = [None, Some("bridge")].into_iter();
        let found = ensure_started(
            || answers.next().flatten(),
            || SpawnLocks::<()>::Busy,
            no_start,
            Duration::ZERO,
            NO_ANSWER,
        );
        assert_eq!(found, Ok("bridge"));

        let found: Result<(), String> =
            ensure_started(|| None, || SpawnLocks::<()>::Busy, no_start, Duration::ZERO, NO_ANSWER);
        assert_eq!(found, Err(NO_ANSWER.to_string()));
    }

    fn held(lock: FileLock) -> File {
        match lock {
            FileLock::Held(file) => file,
            FileLock::Busy => panic!("busy"),
            FileLock::Unavailable(e) | FileLock::Denied(e) => panic!("{e}"),
        }
    }

    #[test]
    fn the_spawn_lock_file_lets_one_adapter_in_at_a_time() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("app-data").join("mcp-spawn.lock");
        let first = held(lock_file_until(&path, Instant::now()));
        let second = lock_file_until(&path, Instant::now());
        assert!(matches!(second, FileLock::Busy));
        drop(first);
        // Free again: taken, even if it takes a few tries.
        let soon = Instant::now() + Duration::from_secs(5);
        held(lock_file_until(&path, soon));
    }

    #[test]
    fn a_spawn_lock_held_past_the_deadline_ends_the_call_after_one_more_ping() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("mcp-spawn.lock");
        // Another adapter holds it, stopped in the middle of a start.
        let _other = held(lock_file_until(&path, Instant::now()));
        let mut pings = 0;
        let began = Instant::now();
        let result: Result<(), String> = ensure_started(
            || {
                pings += 1;
                None
            },
            || take_spawn_locks_at(Ok(path.clone()), began + Duration::from_millis(300)),
            || panic!("the other adapter may be starting it"),
            Duration::from_secs(5),
            NO_ANSWER,
        );
        assert_eq!(result, Err(NO_ANSWER.to_string()));
        assert_eq!(pings, 2, "the first look, and one more at the deadline");
        assert!(began.elapsed() >= Duration::from_millis(300));
        assert!(began.elapsed() < Duration::from_secs(5));
    }

    #[test]
    fn without_a_lock_file_the_call_still_starts_sshelter() {
        let dir = tempfile::tempdir().unwrap();
        let not_a_dir = dir.path().join("file");
        std::fs::write(&not_a_dir, b"").unwrap();
        let path = not_a_dir.join("mcp-spawn.lock");
        assert!(matches!(
            lock_file_until(&path, Instant::now()),
            FileLock::Unavailable(_)
        ));

        let mut starts = 0;
        let mut answers = [None, None, Some("bridge")].into_iter();
        let found = ensure_started(
            || answers.next().flatten(),
            || take_spawn_locks_at(Ok(path.clone()), Instant::now()),
            || {
                starts += 1;
                Ok(())
            },
            Duration::from_secs(5),
            NO_ANSWER,
        );
        assert_eq!(found, Ok("bridge"));
        assert_eq!(starts, 1);
    }

    #[test]
    fn a_client_starts_the_host_with_the_new_flag_and_its_window_hidden() {
        use std::ffi::OsStr;
        let command = host_command(Path::new("/usr/bin/sshelter"));
        let args: Vec<_> = command.get_args().collect();
        assert_eq!(args, [OsStr::new(HOST_FLAG)]);
        let flag = command
            .get_envs()
            .find(|(key, _)| *key == OsStr::new(crate::START_HIDDEN_ENV))
            .and_then(|(_, value)| value);
        assert!(crate::starts_hidden(flag));
    }

    #[cfg(unix)]
    #[test]
    fn the_host_starts_in_its_own_process_group() {
        let mut command = Command::new("cat");
        command.stdin(Stdio::piped()).stdout(Stdio::null());
        detach_from_client(&mut command);
        let mut child = crate::process::spawn(&mut command).unwrap();
        let pid = child.id() as libc::pid_t;
        let group = unsafe { libc::getpgid(pid) };
        let ours = unsafe { libc::getpgid(0) };
        drop(child.stdin.take()); // `cat` exits at end of input.
        child.wait().unwrap();
        assert_eq!(group, pid);
        assert_ne!(group, ours);
    }
}

#[cfg(test)]
mod profile_boundary_tests {
    use super::*;
    #[test]
    fn a_profile_denial_never_starts_the_app_or_creates_an_outside_lock() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("outside/lock");
        let mut starts = 0;
        crate::fsutil::with_test_write_policy(crate::write_policy::WritePolicy::Confined { root: temp.path().join("dev") }, || {
            let result: Result<(), String> = ensure_started(|| None, || take_spawn_locks_at(Ok(path.clone()), Instant::now()), || { starts += 1; Ok(()) }, Duration::ZERO, "no answer");
            assert!(result.is_err());
        });
        assert_eq!(starts, 0);
        assert!(!temp.path().join("outside").exists());
    }
}
