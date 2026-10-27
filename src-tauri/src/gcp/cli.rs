//! The gcloud CLI, for the account actions of the Google Cloud page (design 2026-10-27, Finding gcloud; Running gcloud). Everything else
//! Lunport does with Google reads gcloud's files and calls Google itself; only signing in, removing an account and changing gcloud's
//! active account run gcloud, since those are gcloud's own state.
//!
//! `locate` finds the executable: a GUI app on macOS does not get the login shell's `PATH`, so after Lunport's own `PATH` it looks in the
//! places gcloud's installers use and, last, asks the login shell once. `run` starts it with an argument list (never through a shell),
//! with stdin closed and prompts off, bounded and cancellable, one run at a time. Its output is never logged.

use std::io::{BufRead, BufReader, Read};
use std::path::{Path, PathBuf};
use std::process::{ExitStatus, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Mutex, PoisonError};
use std::time::{Duration, Instant};

/// How long the login shell may take to say where gcloud is.
const SHELL_BOUND: Duration = Duration::from_secs(5);

/// The file names gcloud's executable has here.
fn executable_names(windows: bool) -> &'static [&'static str] {
    if windows {
        &["gcloud.cmd", "gcloud.exe"]
    } else {
        &["gcloud"]
    }
}

/// The directories gcloud's installers put it in, after `PATH`: Homebrew (formula and cask, Apple silicon and Intel), the official
/// archive in the home folder, the Linux packages and snap; on Windows the Cloud SDK installer's per-user and machine-wide places.
pub fn known_places(var: &dyn Fn(&str) -> Option<String>, home: Option<&Path>, windows: bool) -> Vec<PathBuf> {
    let set = |name: &str| var(name).filter(|value| !value.is_empty());
    if windows {
        let sdk = |root: String| PathBuf::from(format!("{root}\\Google\\Cloud SDK\\google-cloud-sdk\\bin"));
        return ["LOCALAPPDATA", "ProgramFiles(x86)", "ProgramFiles"].into_iter().filter_map(set).map(sdk).collect();
    }
    let mut places: Vec<PathBuf> = [
        "/opt/homebrew/bin",
        "/usr/local/bin",
        "/opt/homebrew/share/google-cloud-sdk/bin",
        "/usr/local/share/google-cloud-sdk/bin",
        "/opt/homebrew/Caskroom/google-cloud-sdk/latest/google-cloud-sdk/bin",
        "/usr/local/Caskroom/google-cloud-sdk/latest/google-cloud-sdk/bin",
    ]
    .into_iter()
    .map(PathBuf::from)
    .collect();
    if let Some(home) = home {
        places.push(home.join("google-cloud-sdk").join("bin"));
    }
    places.extend(["/usr/lib/google-cloud-sdk/bin", "/usr/share/google-cloud-sdk/bin", "/snap/bin", "/usr/bin"].into_iter().map(PathBuf::from));
    places
}

/// Whether `path` is a file this computer can run: a regular file (a link to one included) and, on Unix, one with an execute bit.
pub fn is_executable(path: &Path) -> bool {
    let Ok(meta) = std::fs::metadata(path) else { return false };
    if !meta.is_file() {
        return false;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        meta.permissions().mode() & 0o111 != 0
    }
    #[cfg(not(unix))]
    true
}

/// Where gcloud is, looked for in order: each directory of `PATH`, the installers' places (`known_places`), then, away from Windows,
/// what `shell` answers (the login shell's own lookup, `login_shell_lookup`, which runs only when nothing else found it).
pub fn locate_in(var: &dyn Fn(&str) -> Option<String>, home: Option<&Path>, windows: bool, shell: &dyn Fn() -> Option<PathBuf>) -> Option<PathBuf> {
    let mut dirs: Vec<PathBuf> = var("PATH").map(|path| std::env::split_paths(&path).collect()).unwrap_or_default();
    dirs.extend(known_places(var, home, windows));
    locate_among(&dirs, windows, shell)
}

/// The first executable gcloud in `dirs`, in order, else (away from Windows) what `shell` answers.
pub fn locate_among(dirs: &[PathBuf], windows: bool, shell: &dyn Fn() -> Option<PathBuf>) -> Option<PathBuf> {
    let found = dirs
        .iter()
        .flat_map(|dir| executable_names(windows).iter().map(move |name| dir.join(name)))
        .find(|candidate| candidate.is_absolute() && is_executable(candidate));
    match found {
        Some(path) => Some(path),
        None if !windows => shell(),
        None => None,
    }
}

/// What a login shell's `command -v gcloud` printed, when it is an answer: the last non-empty line, one absolute path to an executable
/// file named `gcloud`. An interactive shell may print a banner first; an alias or a function (`command -v` prints those as they are
/// defined) is no answer.
pub fn shell_answer(stdout: &str) -> Option<PathBuf> {
    let line = stdout.lines().map(str::trim).rfind(|line| !line.is_empty())?;
    let path = PathBuf::from(line);
    (path.is_absolute() && path.file_name().is_some_and(|name| name == "gcloud") && is_executable(&path)).then_some(path)
}

/// The login shell's answer to where gcloud is (`$SHELL -i -l -c 'command -v gcloud'`): interactive as well as a login shell, since
/// gcloud's installer adds itself to `PATH` in `.zshrc` or `.bashrc`, which only an interactive shell reads. stdin is closed and the
/// shell is stopped after `bound`. `None` when `shell` is not an absolute path to an executable file, or when no answer came.
pub fn login_shell_lookup(shell: &Path, bound: Duration) -> Option<PathBuf> {
    if !shell.is_absolute() || !is_executable(shell) {
        return None;
    }
    let mut command = crate::process::background_command(shell);
    command.args(["-i", "-l", "-c", "command -v gcloud"]).stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::null());
    let mut child = crate::process::spawn(&mut command).ok()?;
    let mut stdout = child.stdout.take()?;
    let (sent, received) = mpsc::channel();
    std::thread::spawn(move || {
        let mut text = String::new();
        let _ = stdout.read_to_string(&mut text);
        let _ = sent.send(text);
    });
    let deadline = Instant::now() + bound;
    loop {
        match child.try_wait() {
            Ok(Some(_)) => break,
            Ok(None) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(50)),
            _ => {
                let _ = child.kill();
                let _ = child.wait();
                return None;
            }
        }
    }
    shell_answer(&received.recv_timeout(Duration::from_secs(1)).ok()?)
}

/// What `locate` last found, for the app's run.
static LOCATED: Mutex<Option<PathBuf>> = Mutex::new(None);

/// Where gcloud is on this computer, found once for the app's run (`locate_in` over this process's environment and `$SHELL`, `/bin/sh`
/// when that is not an absolute path) and looked for again when the file found is gone.
pub fn locate() -> Option<PathBuf> {
    let mut located = LOCATED.lock().unwrap_or_else(PoisonError::into_inner);
    if let Some(path) = located.as_ref().filter(|path| is_executable(path)) {
        return Some(path.clone());
    }
    let shell = || {
        let shell = std::env::var_os("SHELL").map(PathBuf::from).filter(|shell| shell.is_absolute()).unwrap_or_else(|| PathBuf::from("/bin/sh"));
        login_shell_lookup(&shell, SHELL_BOUND)
    };
    *located = locate_in(&|name| std::env::var(name).ok(), dirs::home_dir().as_deref(), cfg!(windows), &shell);
    located.clone()
}

/// Forgets where gcloud was, so the next `locate` looks again (the page's **Check again**).
pub fn relocate() {
    *LOCATED.lock().unwrap_or_else(PoisonError::into_inner) = None;
}

/// One gcloud run: the executable, its arguments (never one string a shell would split) and how long it may take.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Run {
    pub path: PathBuf,
    pub args: Vec<String>,
    pub bound: Duration,
}

/// What a finished run printed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Output {
    pub stdout: String,
    pub stderr: String,
}

/// Why a run gave no success.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CliError {
    /// Another gcloud action is still running.
    Busy,
    Cancelled,
    TimedOut { bound: Duration },
    /// gcloud ended with a failure; `line` is what it said about it (`failure_line`).
    Failed { line: String },
    /// gcloud could not be started.
    Spawn(String),
}

impl CliError {
    /// The sentence for the person: `action` completes "gcloud could not …" (`sign in`, `remove frank@example.com`).
    pub fn sentence(&self, action: &str) -> String {
        match self {
            CliError::Busy => "Another gcloud action is still running.".into(),
            CliError::Cancelled => "Cancelled.".into(),
            CliError::TimedOut { bound } => {
                let minutes = bound.as_secs().div_ceil(60).max(1);
                format!("gcloud did not finish within {minutes} minute{}.", if minutes == 1 { "" } else { "s" })
            }
            CliError::Failed { line } if line.is_empty() => format!("gcloud could not {action}."),
            CliError::Failed { line } => format!("gcloud could not {action}: {line}"),
            CliError::Spawn(reason) => format!("Lunport could not start gcloud: {reason}"),
        }
    }
}

/// The longest line `failure_line` keeps, in characters.
const MAX_LINE: usize = 300;

/// What gcloud said about a failure: its last `ERROR:` line (without the prefix), else its last non-empty line, cut to `MAX_LINE`
/// characters.
pub fn failure_line(stderr: &str) -> String {
    let lines: Vec<&str> = stderr.lines().map(str::trim).filter(|line| !line.is_empty()).collect();
    let line = lines.iter().rev().find_map(|line| line.strip_prefix("ERROR:")).map(str::trim).or_else(|| lines.last().copied()).unwrap_or("");
    line.chars().take(MAX_LINE).collect()
}

/// The sign-in page gcloud asks the browser to open, when `line` names one: its first `https://accounts.google.com/` word.
pub fn sign_in_url(line: &str) -> Option<String> {
    line.split_whitespace().find(|word| word.starts_with("https://accounts.google.com/")).map(str::to_string)
}

/// Whether a run is going on: gcloud's actions change gcloud's own files, so they never overlap.
static RUNNING: AtomicBool = AtomicBool::new(false);

/// Taken by every test that runs gcloud, in any module: `RUNNING` is process-wide.
#[cfg(test)]
pub(crate) static TEST_RUNS: Mutex<()> = Mutex::new(());

/// Holds `RUNNING` for one run.
struct Turn;

impl Turn {
    fn take() -> Option<Turn> {
        RUNNING.compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire).is_ok().then_some(Turn)
    }
}

impl Drop for Turn {
    fn drop(&mut self) {
        RUNNING.store(false, Ordering::Release);
    }
}

/// Runs gcloud as `run` says, with stdin closed and `CLOUDSDK_CORE_DISABLE_PROMPTS=1` (a question takes its default instead of waiting
/// for an answer nobody can type), on Windows without a console window. Every line gcloud writes to stderr is handed to `on_line` as it
/// comes (the sign-in dialog shows the sign-in page's address from it). `cancel` is looked at every 100 ms; a cancelled run, or one past
/// its bound, is killed. Blocks: a plain thread or `spawn_blocking`.
pub fn run(run: &Run, cancel: &AtomicBool, on_line: &mut dyn FnMut(&str)) -> Result<Output, CliError> {
    let _turn = Turn::take().ok_or(CliError::Busy)?;
    let mut command = crate::process::background_command(&run.path);
    command.args(&run.args).env("CLOUDSDK_CORE_DISABLE_PROMPTS", "1").stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped());
    let mut child = crate::process::spawn(&mut command).map_err(|error| CliError::Spawn(error.to_string()))?;
    let (Some(mut stdout), Some(stderr)) = (child.stdout.take(), child.stderr.take()) else {
        let _ = child.kill();
        let _ = child.wait();
        return Err(CliError::Spawn("its output could not be read".into()));
    };
    let (lines_sent, lines) = mpsc::channel::<String>();
    let errors = std::thread::spawn(move || {
        for line in BufReader::new(stderr).lines().map_while(Result::ok) {
            if lines_sent.send(line).is_err() {
                break;
            }
        }
    });
    let output = std::thread::spawn(move || {
        let mut text = String::new();
        let _ = stdout.read_to_string(&mut text);
        text
    });
    let deadline = Instant::now() + run.bound;
    let mut stderr_text = String::new();
    let mut take_lines = |stderr_text: &mut String| {
        for line in lines.try_iter() {
            on_line(&line);
            stderr_text.push_str(&line);
            stderr_text.push('\n');
        }
    };
    let status: ExitStatus = loop {
        take_lines(&mut stderr_text);
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) => {}
            Err(error) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(CliError::Spawn(error.to_string()));
            }
        }
        let stop = if cancel.load(Ordering::Acquire) {
            Some(CliError::Cancelled)
        } else if Instant::now() >= deadline {
            Some(CliError::TimedOut { bound: run.bound })
        } else {
            None
        };
        if let Some(stop) = stop {
            let _ = child.kill();
            let _ = child.wait();
            return Err(stop);
        }
        std::thread::sleep(Duration::from_millis(100));
    };
    // The streams close with the process (a grandchild that kept them open is not waited for past a second).
    let _ = errors.join();
    take_lines(&mut stderr_text);
    let stdout = output.join().unwrap_or_default();
    if status.success() {
        Ok(Output { stdout, stderr: stderr_text })
    } else {
        Err(CliError::Failed { line: failure_line(&stderr_text) })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    use super::TEST_RUNS as SERIAL;

    fn env(pairs: &[(&str, String)]) -> impl Fn(&str) -> Option<String> {
        let map: BTreeMap<String, String> = pairs.iter().map(|(k, v)| (k.to_string(), v.clone())).collect();
        move |name| map.get(name).cloned()
    }

    #[cfg(unix)]
    fn script(dir: &Path, name: &str, body: &str) -> PathBuf {
        use std::os::unix::fs::PermissionsExt;
        let path = dir.join(name);
        std::fs::write(&path, format!("#!/bin/sh\n{body}\n")).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
        path
    }

    #[cfg(unix)]
    #[test]
    fn gcloud_is_found_in_the_first_directory_that_has_it_else_by_the_shell() {
        let root = tempfile::tempdir().unwrap();
        let (first, second, empty) = (root.path().join("first"), root.path().join("second"), root.path().join("empty"));
        for dir in [&first, &second, &empty] {
            std::fs::create_dir_all(dir).unwrap();
        }
        let in_second = script(&second, "gcloud", "exit 0");
        std::fs::write(first.join("gcloud"), "not a program").unwrap();
        let from_shell = || Some(PathBuf::from("/from/the/shell/gcloud"));
        let dirs = [first.clone(), second.clone()];
        assert_eq!(locate_among(&dirs, false, &from_shell), Some(in_second), "a file that cannot run is passed over");
        let in_first = script(&first, "gcloud", "exit 0");
        assert_eq!(locate_among(&dirs, false, &from_shell), Some(in_first), "the first directory wins");
        assert_eq!(locate_among(&[empty.clone()], false, &from_shell), Some(PathBuf::from("/from/the/shell/gcloud")), "the shell, last");
        assert_eq!(locate_among(&[empty], true, &from_shell), None, "no shell on Windows");
    }

    #[test]
    fn path_comes_before_the_installers_places_and_the_home_archive_is_one_of_them() {
        let home = PathBuf::from("/home/frank");
        let places = known_places(&|_| None, Some(&home), false);
        assert!(places.contains(&home.join("google-cloud-sdk/bin")));
        assert!(places.contains(&PathBuf::from("/opt/homebrew/bin")));
        // `locate_in` looks in PATH first: a gcloud there is found before any known place's.
        let root = tempfile::tempdir().unwrap();
        #[cfg(unix)]
        {
            let gcloud = script(root.path(), "gcloud", "exit 0");
            let path = env(&[("PATH", root.path().display().to_string())]);
            assert_eq!(locate_in(&path, Some(&home), false, &|| None), Some(gcloud));
        }
    }

    #[test]
    fn the_windows_places_are_the_cloud_sdk_installers() {
        let var = env(&[("LOCALAPPDATA", r"C:\Users\frank\AppData\Local".into()), ("ProgramFiles", r"C:\Program Files".into())]);
        let places: Vec<String> = known_places(&var, None, true).iter().map(|p| p.display().to_string()).collect();
        assert_eq!(
            places,
            [r"C:\Users\frank\AppData\Local\Google\Cloud SDK\google-cloud-sdk\bin", r"C:\Program Files\Google\Cloud SDK\google-cloud-sdk\bin"]
        );
    }

    #[cfg(unix)]
    #[test]
    fn the_shell_answer_is_one_absolute_path_to_gcloud() {
        let root = tempfile::tempdir().unwrap();
        let gcloud = script(root.path(), "gcloud", "exit 0");
        let shown = gcloud.display().to_string();
        assert_eq!(shell_answer(&format!("Welcome back!\n{shown}\n")), Some(gcloud.clone()), "a banner before it");
        assert_eq!(shell_answer("gcloud\n"), None, "relative");
        assert_eq!(shell_answer("alias gcloud='docker run gcloud'\n"), None, "an alias");
        assert_eq!(shell_answer(""), None);
        let other = script(root.path(), "gsutil", "exit 0");
        assert_eq!(shell_answer(&other.display().to_string()), None, "another program");
    }

    #[cfg(unix)]
    #[test]
    fn the_login_shell_is_asked_and_a_slow_one_is_stopped() {
        let root = tempfile::tempdir().unwrap();
        let gcloud = script(root.path(), "gcloud", "exit 0");
        let shell = script(root.path(), "fake-shell", &format!("echo 'motd'; echo '{}'", gcloud.display()));
        assert_eq!(login_shell_lookup(&shell, Duration::from_secs(5)), Some(gcloud));
        let slow = script(root.path(), "slow-shell", "sleep 5");
        let started = Instant::now();
        assert_eq!(login_shell_lookup(&slow, Duration::from_millis(200)), None);
        assert!(started.elapsed() < Duration::from_secs(3));
        assert_eq!(login_shell_lookup(Path::new("sh"), Duration::from_secs(1)), None, "not an absolute path");
    }

    #[test]
    fn the_failure_line_is_gclouds_error_else_its_last_line() {
        assert_eq!(failure_line("Revoking...\nERROR: (gcloud.auth.revoke) No credentials available to revoke.\n"), "(gcloud.auth.revoke) No credentials available to revoke.");
        assert_eq!(failure_line("one\n\ntwo\n"), "two");
        assert_eq!(failure_line(""), "");
        assert_eq!(failure_line(&"x".repeat(400)).chars().count(), MAX_LINE);
    }

    #[test]
    fn sentences() {
        assert_eq!(CliError::Failed { line: "boom".into() }.sentence("sign in"), "gcloud could not sign in: boom");
        assert_eq!(CliError::Failed { line: String::new() }.sentence("sign in"), "gcloud could not sign in.");
        assert_eq!(CliError::TimedOut { bound: Duration::from_secs(300) }.sentence("sign in"), "gcloud did not finish within 5 minutes.");
        assert_eq!(CliError::TimedOut { bound: Duration::from_secs(30) }.sentence("sign in"), "gcloud did not finish within 1 minute.");
        assert_eq!(CliError::Busy.sentence("sign in"), "Another gcloud action is still running.");
    }

    #[test]
    fn the_sign_in_page_is_read_from_gclouds_line() {
        assert_eq!(
            sign_in_url("    https://accounts.google.com/o/oauth2/auth?response_type=code&client_id=x"),
            Some("https://accounts.google.com/o/oauth2/auth?response_type=code&client_id=x".into())
        );
        assert_eq!(sign_in_url("Your browser has been opened to visit:"), None);
        assert_eq!(sign_in_url("https://example.com/not-google"), None);
    }

    #[cfg(unix)]
    fn quick(path: PathBuf, args: &[&str], bound: Duration) -> Run {
        Run { path, args: args.iter().map(|arg| arg.to_string()).collect(), bound }
    }

    #[cfg(unix)]
    #[test]
    fn a_run_hands_over_its_arguments_lines_and_output_without_prompts() {
        let _serial = SERIAL.lock().unwrap_or_else(PoisonError::into_inner);
        let root = tempfile::tempdir().unwrap();
        let gcloud = script(root.path(), "gcloud", r#"echo "args:$1|$2"; echo "prompts:$CLOUDSDK_CORE_DISABLE_PROMPTS" >&2; echo "  https://accounts.google.com/o/oauth2/auth?x=1" >&2; read line; echo "stdin:$line""#);
        let mut seen = vec![];
        let output = run(&quick(gcloud, &["auth", "frank@example.com"], Duration::from_secs(10)), &AtomicBool::new(false), &mut |line| seen.push(line.to_string())).unwrap();
        assert_eq!(output.stdout, "args:auth|frank@example.com\nstdin:\n", "stdin is closed, so read gets nothing");
        assert_eq!(seen, ["prompts:1", "  https://accounts.google.com/o/oauth2/auth?x=1"]);
        assert_eq!(seen.iter().find_map(|line| sign_in_url(line)).as_deref(), Some("https://accounts.google.com/o/oauth2/auth?x=1"));
    }

    #[cfg(unix)]
    #[test]
    fn a_failed_run_says_gclouds_error_and_a_slow_or_cancelled_one_is_killed() {
        let _serial = SERIAL.lock().unwrap_or_else(PoisonError::into_inner);
        let root = tempfile::tempdir().unwrap();
        let failing = script(root.path(), "failing", "echo 'ERROR: (gcloud.auth.login) There was a problem.' >&2; exit 1");
        assert_eq!(run(&quick(failing, &[], Duration::from_secs(10)), &AtomicBool::new(false), &mut |_| {}), Err(CliError::Failed { line: "(gcloud.auth.login) There was a problem.".into() }));

        let slow = script(root.path(), "slow", "sleep 5");
        let started = Instant::now();
        assert_eq!(run(&quick(slow.clone(), &[], Duration::from_millis(300)), &AtomicBool::new(false), &mut |_| {}), Err(CliError::TimedOut { bound: Duration::from_millis(300) }));
        assert!(started.elapsed() < Duration::from_secs(3), "killed, not waited for");

        let cancel = AtomicBool::new(true);
        assert_eq!(run(&quick(slow, &[], Duration::from_secs(10)), &cancel, &mut |_| {}), Err(CliError::Cancelled));
    }

    #[cfg(unix)]
    #[test]
    fn one_run_at_a_time() {
        let _serial = SERIAL.lock().unwrap_or_else(PoisonError::into_inner);
        let root = tempfile::tempdir().unwrap();
        let slow = script(root.path(), "slow", "sleep 1");
        let first = std::thread::spawn(move || run(&quick(slow, &[], Duration::from_secs(10)), &AtomicBool::new(false), &mut |_| {}));
        let started = Instant::now();
        while !RUNNING.load(Ordering::Acquire) && started.elapsed() < Duration::from_secs(5) {
            std::thread::sleep(Duration::from_millis(10));
        }
        let quick_one = script(root.path(), "quick", "exit 0");
        assert_eq!(run(&quick(quick_one.clone(), &[], Duration::from_secs(10)), &AtomicBool::new(false), &mut |_| {}), Err(CliError::Busy));
        assert!(first.join().unwrap().is_ok());
        assert!(run(&quick(quick_one, &[], Duration::from_secs(10)), &AtomicBool::new(false), &mut |_| {}).is_ok(), "the turn is given back");
    }
}
