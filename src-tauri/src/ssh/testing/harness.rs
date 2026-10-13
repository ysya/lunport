//! A scratch OpenSSH server for the engine's integration tests: a temp directory, a free localhost port, throwaway host keys and
//! authorized_keys, and `sshd -D -e -f <config>` run as the current user (no root, no PAM). Nothing here reads or writes the real
//! `~/.ssh`: the system `ssh` client used by `system_ssh` gets `-F /dev/null`.
//!
//! Ported from the phase-0 spike's harness (the `spike/` crate that plan 1a deleted), checked on macOS with OpenSSH 10.3p1: `Port 0` is
//! rejected ("Badly formatted port number"), so the port is picked first; sshd prints one harmless line `BSM audit: ... setaudit_addr
//! failed: Operation not permitted`; password and keyboard-interactive login cannot work without PAM, so this sshd offers public keys
//! only.
//! Every test starts its own sshd. A test that needs one sshd for a long loop adds `PerSourcePenalties no` to its `extra_config`
//! (OpenSSH 9.8 and later know the keyword, older ones refuse the config, so it cannot be a default) — only after checking with `sshd -t`
//! that the runner's OpenSSH knows the keyword (9.8 and later); no test in the suite passes it today.
//!
//! **A signal that kills the test process leaves its sshd behind.** `Drop` does not run then, and nothing else ties the sshd to the test
//! process: the listener keeps running and its temp directory stays. The harness cleans up after the fact. `Sshd::start` writes
//! `owner.pid` (the test process's pid, then the sshd's) into the directory, and every `Sshd::start` begins by sweeping the
//! `sshelter-sshd-*` directories of the temp dir whose owner no longer exists (`sweep_stale`). So such a listener and directory stay until
//! the next `Sshd::start` of any test process. By hand: `pkill -f 'sshelter-sshd-.*/sshd_config'` and `rm -r "${TMPDIR:-/tmp}"/sshelter-sshd-*`.
//!
//! **`Drop` and the sweep end the sessions with the listener.** For every connection the sshd forks a process (`sshd-session`), and that
//! one forks another for the login, which forks the shell or the command; none of them stays in the listener's process group (the
//! per-connection process starts a session of its own, and a shell another one), so killing the listener's group does not reach them, and
//! they outlive a listener that is only killed. A login with a shell on a PTY then held that PTY for ever, and enough of them used up the
//! PTYs of the machine. The parent chain is what links them, and it is lost the moment the listener dies (the children go to init). So the
//! listener is stopped first, its descendants are read from `ps`, and all of them are killed (`kill_family`).
//!
//! That reaches what is still attached when the server is dropped (a connection or a login that a test left open). It cannot reach what
//! was orphaned earlier. A test closes its client first, the session processes then exit, and a shell child that is stuck on the server
//! stays behind with its PTY. (On macOS a shell child blocks for ever in opening its tty when the master is closed before the PTY is set
//! up, which is what happens to a shell that is closed right after it was opened.) That is prevented, not cleaned up: a test closes a
//! shell only once the prompt is there.

use std::io::Read;
use std::net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::sync::mpsc::{self, Receiver};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

/// How long one run of a helper tool (ssh-keygen, sshd -t, id, ssh) may take. A tool still running after that is killed and fails the
/// test, so a stuck one cannot hang CI.
const TOOL_TIMEOUT: Duration = Duration::from_secs(30);

/// After a tool was killed (or has exited) its pipes can stay open: a grandchild may have inherited them. Each reader gets this long to
/// reach end-of-file; after that the output collected so far is used and the readers are left to end on their own. The two readers are
/// waited for one after the other, so a tool that ended while a grandchild holds both pipes delays its result by up to twice this.
const PIPE_GRACE: Duration = Duration::from_secs(2);

/// `Command::output()` with a deadline of `TOOL_TIMEOUT`. A tool that cannot be started, or does not finish in time, fails the test.
fn run_bounded(command: &mut Command) -> Output {
    run_within(command, TOOL_TIMEOUT).unwrap_or_else(|message| panic!("{message}"))
}

/// One pipe, read on its own thread so a chatty tool cannot fill it and block. The bytes land in `buffer` as they arrive and `done`
/// fires at end-of-file.
struct PipeReader {
    buffer: Arc<Mutex<Vec<u8>>>,
    done: Receiver<()>,
}

fn read_in_background(pipe: Option<impl Read + Send + 'static>) -> PipeReader {
    let buffer = Arc::new(Mutex::new(Vec::new()));
    let (finished, done) = mpsc::channel();
    let sink = Arc::clone(&buffer);
    std::thread::spawn(move || {
        if let Some(mut pipe) = pipe {
            let mut chunk = [0u8; 8192];
            loop {
                match pipe.read(&mut chunk) {
                    Ok(0) => break,
                    Ok(count) => sink.lock().unwrap_or_else(PoisonError::into_inner).extend_from_slice(&chunk[..count]),
                    // A signal that arrives during the read is no end of file: read again.
                    Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
                    Err(_) => break,
                }
            }
        }
        let _ = finished.send(());
    });
    PipeReader { buffer, done }
}

impl PipeReader {
    /// Waits up to `grace` for end-of-file and returns what was read, and whether the pipe really ended.
    fn collect(&self, grace: Duration) -> (Vec<u8>, bool) {
        let ended = self.done.recv_timeout(grace).is_ok();
        (self.buffer.lock().unwrap_or_else(PoisonError::into_inner).clone(), ended)
    }
}

/// `Command::output()` with a deadline: stdin is closed, stdout and stderr are captured, and a tool still running after `timeout` is
/// killed. `Err` carries the command line and the tool's stderr so far. It returns the error instead of panicking so that the unit test
/// of the deadline leaves no "panicked at" line in the output of `--nocapture` runs.
///
/// The readers are bounded too: when a grandchild keeps the pipes open after the tool is gone, waiting for end-of-file would last as
/// long as the grandchild lives, so each reader gets `PIPE_GRACE` and then the output so far is used (the spike's deferred Minor 2). The
/// readers are waited for one after the other: up to `2 * PIPE_GRACE` after a tool that ended by itself, `PIPE_GRACE` after a kill (only
/// stderr is waited for then).
pub(super) fn run_within(command: &mut Command, timeout: Duration) -> Result<Output, String> {
    run_within_reading(command, Stdio::null(), timeout)
}

/// `run_within`, with `stdin` as the tool's standard input instead of nothing.
pub(super) fn run_within_reading(command: &mut Command, stdin: Stdio, timeout: Duration) -> Result<Output, String> {
    command.stdin(stdin).stdout(Stdio::piped()).stderr(Stdio::piped());
    let mut child = crate::process::spawn(command).map_err(|error| format!("cannot run {command:?}: {error}"))?;
    let (stdout, stderr) = (read_in_background(child.stdout.take()), read_in_background(child.stderr.take()));
    let deadline = Instant::now() + timeout;
    let status = loop {
        match child.try_wait().map_err(|error| format!("cannot wait for {command:?}: {error}"))? {
            Some(status) => break status,
            None if Instant::now() >= deadline => {
                let _ = child.kill();
                let _ = child.wait();
                let (stderr, _) = stderr.collect(PIPE_GRACE);
                return Err(format!(
                    "{command:?} did not finish within {timeout:?} and was killed; its stderr so far: {}",
                    String::from_utf8_lossy(&stderr)
                ));
            }
            None => std::thread::sleep(Duration::from_millis(20)),
        }
    };
    let ((stdout, stdout_ended), (stderr, stderr_ended)) = (stdout.collect(PIPE_GRACE), stderr.collect(PIPE_GRACE));
    if !(stdout_ended && stderr_ended) {
        eprintln!("{command:?} ended, but a process it started still holds its output pipes open; using the output read so far");
    }
    Ok(Output { status, stdout, stderr })
}

/// The OpenSSH programs the tests need.
pub struct Tools {
    pub sshd: PathBuf,
    pub ssh: PathBuf,
    pub ssh_keygen: PathBuf,
}

/// `Some` when sshd, ssh and ssh-keygen are all found. When they are not: `SSHELTER_REQUIRE_OPENSSH=1` (CI) makes that a failure on
/// Unix; anything else prints "skipped" and the caller returns early. Windows never runs the scratch-sshd tests (Win32-OpenSSH's sshd
/// must run as a service, which the workflow sets up), so there the answer is always a skip.
pub fn tools() -> Option<Tools> {
    let found = find_sshd().and_then(|sshd| Some(Tools { sshd, ssh: find_in_path("ssh")?, ssh_keygen: find_in_path("ssh-keygen")? }));
    if found.is_none() {
        let required = cfg!(unix) && std::env::var("SSHELTER_REQUIRE_OPENSSH").is_ok_and(|value| value == "1");
        assert!(!required, "sshd, ssh and ssh-keygen are required (SSHELTER_REQUIRE_OPENSSH=1)");
        eprintln!("skipped: sshd, ssh or ssh-keygen is not found (or this is not a Unix machine)");
    }
    found
}

/// sshd re-executes itself and insists on an absolute path, and a normal user rarely has it on PATH (Linux keeps it in /usr/sbin).
fn find_sshd() -> Option<PathBuf> {
    if !cfg!(unix) {
        return None;
    }
    ["/usr/sbin/sshd", "/usr/local/sbin/sshd", "/opt/homebrew/sbin/sshd", "/usr/bin/sshd"]
        .iter()
        .map(PathBuf::from)
        .find(|path| path.is_file())
        .or_else(|| find_in_path("sshd"))
}

fn find_in_path(name: &str) -> Option<PathBuf> {
    let file = if cfg!(windows) { format!("{name}.exe") } else { name.to_string() };
    std::env::split_paths(&std::env::var_os("PATH")?).map(|dir| dir.join(&file)).find(|path| path.is_file())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeyKind {
    Ed25519,
    EcdsaP256,
    EcdsaP521,
    Rsa3072,
}

impl KeyKind {
    fn keygen_args(self) -> &'static [&'static str] {
        match self {
            KeyKind::Ed25519 => &["-t", "ed25519"],
            KeyKind::EcdsaP256 => &["-t", "ecdsa", "-b", "256"],
            KeyKind::EcdsaP521 => &["-t", "ecdsa", "-b", "521"],
            KeyKind::Rsa3072 => &["-t", "rsa", "-b", "3072"],
        }
    }
}

/// A key pair made by ssh-keygen, in the OpenSSH private key format the vault reads.
pub struct TestKey {
    pub private_path: PathBuf,
    pub private_text: String,
    /// `<type> <base64> sshelter-test`: the authorized_keys form.
    pub public_line: String,
}

/// Whether the vault reads this OpenSSH private key: its own predicate (`open` does not answer `Unreadable`), so that a fix of the
/// vault's parsing reaches this harness without a change here.
fn readable_by_the_vault(private_text: &str) -> bool {
    crate::vault::material::agent_can_read(private_text)
}

/// Makes a key pair with ssh-keygen, one the vault reads. `ssh-key` 0.6.7 alone cannot read an ECDSA private key whose secret number
/// OpenSSH wrote shorter than the curve's size: it writes the number in its shortest form, without its leading zero bytes, and the parser
/// insists on the full length. That is a number whose first byte is zero and whose second byte has its top bit clear (with that bit set, a
/// sign byte makes up the length again): about 1 P-256 or P-384 key in 512 and 1 P-521 key in 4 (measured with ssh-keygen from OpenSSH
/// 10.3p1: 5 of 1500 P-256 keys, 3 of 600 P-384 keys and 77 of 300 P-521 keys). The vault pads the number first (`vault::short_scalar`),
/// so every key ssh-keygen makes is one it reads, and one it cannot read is a fault of the vault, not of the engine under test.
pub fn generate_key(tools: &Tools, dir: &Path, name: &str, kind: KeyKind) -> TestKey {
    let private_path = dir.join(name);
    let mut public_path = private_path.clone().into_os_string();
    public_path.push(".pub");
    let out = run_bounded(
        Command::new(&tools.ssh_keygen).args(["-q", "-N", "", "-C", "sshelter-test"]).args(kind.keygen_args()).arg("-f").arg(&private_path),
    );
    assert!(out.status.success(), "ssh-keygen failed: {}", String::from_utf8_lossy(&out.stderr));
    let private_text = std::fs::read_to_string(&private_path).expect("read the private key");
    // A throwaway test key: printed whole, so that a key the vault cannot read can be reproduced.
    assert!(readable_by_the_vault(&private_text), "the vault cannot read a {kind:?} key ssh-keygen made:\n{private_text}");
    TestKey {
        private_text,
        public_line: std::fs::read_to_string(&public_path).expect("read the public key").trim().to_string(),
        private_path,
    }
}

pub struct SshdOptions {
    /// The types of the host keys the server has, in the order of its `HostKey` lines.
    pub host_keys: Vec<KeyKind>,
    /// Lines for sshd_config. sshd keeps the FIRST value of a keyword, so these come before the defaults below and may override them.
    pub extra_config: Vec<String>,
    /// Public key lines for authorized_keys.
    pub authorized_keys: Vec<String>,
}

impl Default for SshdOptions {
    fn default() -> Self {
        SshdOptions { host_keys: vec![KeyKind::Ed25519], extra_config: Vec::new(), authorized_keys: Vec::new() }
    }
}

/// A running scratch sshd. Dropping it kills the listener and every process that descends from it (module doc) and removes the
/// directory.
///
/// **The limit:** `Drop` does not run when a signal kills the test process (`kill -9`, a CI runner cancelling the job), and nothing else
/// ties the sshd to that process. The listener then keeps running and its directory stays until the next `Sshd::start` (of any test
/// process) sweeps them, see `sweep_stale` and `owner.pid`. By hand: `pkill -f 'sshelter-sshd-.*/sshd_config'` and
/// `rm -r "${TMPDIR:-/tmp}"/sshelter-sshd-*`.
pub struct Sshd {
    pub port: u16,
    /// The account sshd authenticates: the user running the tests (without root, sshd can only log in that user).
    pub user: String,
    /// The host keys in authorized_keys form, in the order of `SshdOptions::host_keys`.
    pub host_public_lines: Vec<String>,
    dir: tempfile::TempDir,
    child: Child,
}

impl Sshd {
    pub fn start(tools: &Tools, options: SshdOptions) -> Sshd {
        assert!(!options.host_keys.is_empty(), "a server needs at least one host key");
        // What a test process killed by a signal left behind (module doc) goes first, before this server adds to it.
        sweep_stale(&std::env::temp_dir());
        // Asked before the first sshd starts: a panic in here must not leave a listener behind.
        let user = current_user();
        let dir = tempfile::Builder::new().prefix(DIR_PREFIX).tempdir().expect("temp dir");
        let host_keys: Vec<TestKey> =
            options.host_keys.iter().enumerate().map(|(index, kind)| generate_key(tools, dir.path(), &format!("hostkey{index}"), *kind)).collect();
        let authorized = dir.path().join("authorized_keys");
        let lines: String = options.authorized_keys.iter().map(|line| format!("{line}\n")).collect();
        std::fs::write(&authorized, lines).expect("write authorized_keys");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&authorized, std::fs::Permissions::from_mode(0o600)).expect("chmod authorized_keys");
        }
        let config_path = dir.path().join("sshd_config");
        let log_path = dir.path().join("sshd.log");
        let key_paths: Vec<&Path> = host_keys.iter().map(|key| key.private_path.as_path()).collect();
        for attempt in 1..=3 {
            let port = free_port();
            std::fs::write(&config_path, config_text(port, &key_paths, &authorized, &options.extra_config)).expect("write sshd_config");
            // `-t` checks the config and the keys without starting anything, so a typo fails here, in sshd's own words.
            let check = run_bounded(Command::new(&tools.sshd).arg("-t").arg("-f").arg(&config_path));
            assert!(
                check.status.success(),
                "sshd -t rejected the config:\n{}\n--- config:\n{}",
                String::from_utf8_lossy(&check.stderr),
                std::fs::read_to_string(&config_path).unwrap_or_default()
            );
            let log = std::fs::File::create(&log_path).expect("create sshd.log");
            let mut command = Command::new(&tools.sshd);
            command.args(["-D", "-e", "-f"]).arg(&config_path).stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::from(log));
            let mut child = crate::process::spawn(&mut command).expect("start sshd");
            // At once: a later sweep finds this sshd through the file if a signal kills this process before `Drop` can run.
            if let Err(error) = write_owner_file(dir.path(), std::process::id(), child.id()) {
                stop(&mut child);
                panic!("cannot write {OWNER_FILE}: {error}");
            }
            if wait_for_banner(&mut child, port) {
                let host_public_lines = host_keys.iter().map(|key| key.public_line.clone()).collect();
                return Sshd { port, user, host_public_lines, dir, child };
            }
            stop(&mut child);
            eprintln!("sshd did not come up on port {port} (attempt {attempt}); its log:\n{}", std::fs::read_to_string(&log_path).unwrap_or_default());
        }
        panic!("sshd did not start in 3 attempts");
    }

    /// The first host key in authorized_keys form.
    pub fn host_public_line(&self) -> &str {
        &self.host_public_lines[0]
    }

    /// What sshd wrote to stderr (`LogLevel ERROR` unless a test asks for more).
    pub fn log(&self) -> String {
        std::fs::read_to_string(self.dir.path().join("sshd.log")).unwrap_or_default()
    }
}

impl Drop for Sshd {
    fn drop(&mut self) {
        stop(&mut self.child);
    }
}

/// Kills the sshd that `child` is and everything that descends from it (module doc), and collects the sshd. The family is only looked up
/// while the sshd still runs (or is a zombie that has not been collected): its pid then belongs to nobody else.
fn stop(child: &mut Child) {
    #[cfg(unix)]
    if matches!(child.try_wait(), Ok(None)) {
        let _ = kill_family(child.id());
    }
    let _ = child.kill();
    let _ = child.wait();
}

/// The start of the name of every scratch directory (`tempfile` adds random characters); the sweep looks for it.
const DIR_PREFIX: &str = "sshelter-sshd-";

/// The file in a scratch directory that says whose it is: the pid of the test process on the first line, the pid of its sshd on the second.
const OWNER_FILE: &str = "owner.pid";

/// Writes `owner.pid`. It goes to a temporary name first and is renamed, so that a sweep that runs at the same moment finds either no
/// file or a whole one.
fn write_owner_file(dir: &Path, owner: u32, sshd: u32) -> std::io::Result<()> {
    let temporary = dir.join(format!("{OWNER_FILE}.tmp"));
    std::fs::write(&temporary, format!("{owner}\n{sshd}\n"))?;
    std::fs::rename(&temporary, dir.join(OWNER_FILE))
}

/// The two pids of `owner.pid`, or `None` when the file is missing or is not exactly two lines with a pid each.
#[cfg(unix)]
fn read_owner_file(dir: &Path) -> Option<(u32, u32)> {
    let text = std::fs::read_to_string(dir.join(OWNER_FILE)).ok()?;
    let mut lines = text.lines();
    let (owner, sshd) = (parse_pid(lines.next()?)?, parse_pid(lines.next()?)?);
    lines.next().is_none().then_some((owner, sshd))
}

/// A pid, but never one that `kill` would treat as more than one process: 0 is the caller's whole process group and 1 is init (and -1,
/// which does not parse as a `u32`, is every process the caller may signal).
#[cfg(unix)]
fn parse_pid(line: &str) -> Option<u32> {
    line.trim().parse::<u32>().ok().filter(|pid| (2..=i32::MAX as u32).contains(pid))
}

/// One sweep at a time in this process: two tests that start a server together would otherwise both handle the same stale directory.
#[cfg(unix)]
static SWEEP: Mutex<()> = Mutex::new(());

/// How long the sweep waits for an sshd it has killed to disappear.
#[cfg(unix)]
const KILL_WAIT: Duration = Duration::from_secs(5);

/// Cleans up after test processes that a signal killed before `Drop` could run (module doc). In every `sshelter-sshd-*` directory of
/// `root` (the temp dir) whose `owner.pid` names a process that no longer exists:
/// - the sshd of that directory is killed, but only if its command line still names this directory's `sshd_config`: a pid can be reused
///   by an unrelated program, and such a program is never killed;
/// - the directory is removed in every case, since the directory of a dead owner is nobody else's.
///
/// Left alone: a directory whose owner still lives (another test, perhaps of another process), one without a usable `owner.pid` (made
/// by an older harness, or by a test that is still starting its server), one that is not a directory of the current user, and one
/// whose sshd cannot be checked because `ps` does not work. One line is printed for every directory that is swept. It assumes that `root`
/// is not shared with processes of another pid namespace, and it never panics: a sweep that cannot do its work must not fail the test
/// that started it.
#[cfg(unix)]
fn sweep_stale(root: &Path) {
    use std::os::unix::fs::MetadataExt;
    let _one_at_a_time = SWEEP.lock().unwrap_or_else(PoisonError::into_inner);
    let Ok(entries) = std::fs::read_dir(root) else { return };
    // SAFETY: geteuid has no preconditions.
    let me = unsafe { libc::geteuid() };
    for entry in entries.flatten() {
        if !entry.file_name().to_string_lossy().starts_with(DIR_PREFIX) {
            continue;
        }
        // `DirEntry::metadata` does not follow a symbolic link, so a link to a directory is not a directory here.
        let Ok(metadata) = entry.metadata() else { continue };
        if metadata.is_dir() && metadata.uid() == me {
            sweep_directory(&entry.path());
        }
    }
}

#[cfg(unix)]
fn sweep_directory(dir: &Path) {
    let Some((owner, sshd)) = read_owner_file(dir) else { return };
    if process_exists(owner) {
        return;
    }
    let config = dir.join("sshd_config").to_string_lossy().into_owned();
    let sshd_fate = match command_line_of(sshd) {
        Err(error) => {
            eprintln!("not sweeping {}: cannot tell what pid {sshd} is: {error}", dir.display());
            return;
        }
        Ok(None) => format!("its sshd (pid {sshd}) is gone already"),
        Ok(Some(command)) if !command.contains(&config) => format!("pid {sshd}, once its sshd, is another program now ({command}) and is left running"),
        Ok(Some(_)) => match kill_family(sshd) {
            Err(error) => format!("its sshd (pid {sshd}) could not be killed: {error}"),
            Ok(()) if wait_until_gone(sshd, &config) => format!("its sshd (pid {sshd}) killed"),
            Ok(()) => format!("its sshd (pid {sshd}) is still there {KILL_WAIT:?} after SIGKILL"),
        },
    };
    let directory_fate = match std::fs::remove_dir_all(dir) {
        Ok(()) => "directory removed".to_string(),
        // The loser of two sweeps that run at the same time finds the directory gone: that is the result it wanted, not an error.
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => "directory already removed".to_string(),
        Err(error) => format!("directory not removed: {error}"),
    };
    eprintln!("swept {}: its test process (pid {owner}) is gone; {sshd_fate}; {directory_fate}", dir.display());
}

/// Whether a process with this pid exists. A process of another user (`EPERM`) exists; so does a zombie.
#[cfg(unix)]
fn process_exists(pid: u32) -> bool {
    // SAFETY: signal 0 only checks that the process exists, and `pid` is at least 2 (`parse_pid`), so it names one process.
    let result = unsafe { libc::kill(pid as libc::pid_t, 0) };
    result == 0 || std::io::Error::last_os_error().raw_os_error() != Some(libc::ESRCH)
}

/// SIGKILL for the sshd `pid` and for every process that descends from it: the processes it forked for its connections, and the shells and
/// commands of the logins on them (module doc). What a descendant has started in a way that leaves the parent chain (the background job
/// of a shell that has ended) is not found. The result is that of the kill of the sshd itself.
///
/// The family is frozen before it is killed: every process found is stopped (SIGKILL works on a stopped process), and the look is
/// repeated until it finds nothing new. A process that forks between the look and the kill would escape, and once its parent is gone
/// nothing links it to the sshd any more; a stopped process forks nothing. A login that is just being set up is the case that needs this.
#[cfg(unix)]
fn kill_family(pid: u32) -> std::io::Result<()> {
    let mut family = vec![pid];
    // At most ten looks: a family that keeps growing is not one that a teardown can wait for.
    for _ in 0..10 {
        for &member in &family {
            // SAFETY: as in `kill_process`, every member names one process: the sshd's own pid, or a pid that `descendants_of` parsed.
            unsafe { libc::kill(member as libc::pid_t, libc::SIGSTOP) };
        }
        let found: Vec<u32> = descendants_of(pid).into_iter().filter(|member| !family.contains(member)).collect();
        if found.is_empty() {
            break;
        }
        family.extend(found);
    }
    let result = kill_process(pid);
    for &member in &family[1..] {
        let _ = kill_process(member);
    }
    result
}

/// Every process that descends from `root`: its children, their children and so on, from one snapshot of `ps`. Empty when `ps` does not
/// work: a teardown that cannot look the family up kills what it can and must not fail the test.
#[cfg(unix)]
fn descendants_of(root: u32) -> Vec<u32> {
    let Ok(out) = run_within(Command::new("ps").args(["-ax", "-o", "pid=,ppid="]), Duration::from_secs(5)) else { return Vec::new() };
    let mut children: std::collections::HashMap<u32, Vec<u32>> = std::collections::HashMap::new();
    for line in String::from_utf8_lossy(&out.stdout).lines() {
        let mut fields = line.split_whitespace();
        if let (Some(pid), Some(parent)) = (fields.next().and_then(parse_pid), fields.next().and_then(|field| field.parse::<u32>().ok())) {
            children.entry(parent).or_default().push(pid);
        }
    }
    let (mut family, mut waiting) = (Vec::new(), vec![root]);
    while let Some(parent) = waiting.pop() {
        for &child in children.get(&parent).map(Vec::as_slice).unwrap_or_default() {
            if child != root && !family.contains(&child) {
                family.push(child);
                waiting.push(child);
            }
        }
    }
    family
}

#[cfg(unix)]
fn kill_process(pid: u32) -> std::io::Result<()> {
    // SAFETY: as in `process_exists`, `pid` names one process.
    if unsafe { libc::kill(pid as libc::pid_t, libc::SIGKILL) } == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

/// What `ps` shows as the command line of `pid`; `Ok(None)` when no process has that pid. A zombie (dead, but its parent has not collected it
/// yet) shows as `<defunct>` on macOS and as `[name] <defunct>` on Linux, which is not a command line anybody looks for. `Err` when `ps`
/// itself does not work (not found, hung, or an answer that is neither a command line nor "no such process").
#[cfg(unix)]
fn command_line_of(pid: u32) -> Result<Option<String>, String> {
    // `-ww`: the whole command line, whatever the width of a terminal or an exported COLUMNS.
    let out = run_within(Command::new("ps").args(["-ww", "-o", "command=", "-p"]).arg(pid.to_string()), TOOL_TIMEOUT)?;
    let line = String::from_utf8_lossy(&out.stdout).trim().to_string();
    if !line.is_empty() {
        return Ok(Some(line));
    }
    // `ps -p` prints nothing and exits with 1 when no process has the pid; anything else is a `ps` that does not work here.
    if out.status.code() == Some(1) && out.stderr.is_empty() {
        return Ok(None);
    }
    Err(format!("ps -p {pid} printed nothing and exited with {:?}: {}", out.status.code(), String::from_utf8_lossy(&out.stderr).trim()))
}

/// Waits (up to `KILL_WAIT`) until `pid` no longer runs the sshd of `config`: it is gone, it is a zombie, or its pid has been reused.
#[cfg(unix)]
fn wait_until_gone(pid: u32, config: &str) -> bool {
    let deadline = Instant::now() + KILL_WAIT;
    loop {
        match command_line_of(pid) {
            Ok(None) => return true,
            Ok(Some(command)) if !command.contains(config) => return true,
            _ if Instant::now() >= deadline => return false,
            _ => std::thread::sleep(Duration::from_millis(50)),
        }
    }
}

/// Windows never runs the scratch-sshd tests (see `tools`), so there is nothing to sweep.
#[cfg(not(unix))]
fn sweep_stale(_root: &Path) {}

fn config_text(port: u16, host_keys: &[&Path], authorized_keys: &Path, extra: &[String]) -> String {
    let mut lines: Vec<String> = extra.to_vec();
    lines.extend([format!("Port {port}"), "ListenAddress 127.0.0.1".to_string()]);
    lines.extend(host_keys.iter().map(|key| format!("HostKey \"{}\"", key.display())));
    lines.extend([
        "PidFile none".to_string(),
        "UsePAM no".to_string(),
        "PasswordAuthentication no".to_string(),
        "KbdInteractiveAuthentication no".to_string(),
        "PubkeyAuthentication yes".to_string(),
        format!("AuthorizedKeysFile \"{}\"", authorized_keys.display()),
        "StrictModes no".to_string(),
        // sshd runs ~/.ssh/rc by default, which would let the developer's real home directory into the test.
        "PermitUserRC no".to_string(),
        "LogLevel ERROR".to_string(),
    ]);
    lines.join("\n") + "\n"
}

fn free_port() -> u16 {
    TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind a free port").local_addr().expect("local address").port()
}

/// Waits (up to 10 s) for an SSH banner on `port` from a sshd that is still running; false when the child exits first or nothing greets.
fn wait_for_banner(child: &mut Child, port: u16) -> bool {
    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline {
        if child.try_wait().ok().flatten().is_some() {
            return false;
        }
        if let Ok(mut stream) = TcpStream::connect_timeout(&SocketAddr::from((Ipv4Addr::LOCALHOST, port)), Duration::from_millis(500)) {
            let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
            let mut banner = [0u8; 8];
            if stream.read_exact(&mut banner).is_ok() && &banner == b"SSH-2.0-" {
                // Somebody else may own the port (the pick can race with another test): ours must still be alive a moment later.
                std::thread::sleep(Duration::from_millis(200));
                return child.try_wait().ok().flatten().is_none();
            }
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    false
}

fn current_user() -> String {
    let out = run_bounded(Command::new("id").arg("-un"));
    assert!(out.status.success(), "id -un failed");
    String::from_utf8_lossy(&out.stdout).trim().to_string()
}

/// Runs the system `ssh` client against `sshd`. `-F /dev/null` keeps it from reading the real ~/.ssh/config; the agent and known_hosts are off.
/// It gives up connecting after 10 s (`ConnectTimeout`) and is killed, with the test failing, if the whole run takes longer than `TOOL_TIMEOUT`.
pub fn system_ssh(tools: &Tools, sshd: &Sshd, identity: &Path, remote_command: &str) -> Output {
    run_bounded(
        Command::new(&tools.ssh)
            .args(["-F", "/dev/null", "-p"])
            .arg(sshd.port.to_string())
            .arg("-i")
            .arg(identity)
            .args([
                "-o",
                "IdentitiesOnly=yes",
                "-o",
                "IdentityAgent=none",
                "-o",
                "BatchMode=yes",
                "-o",
                "StrictHostKeyChecking=no",
                "-o",
                "UserKnownHostsFile=/dev/null",
                "-o",
                "ConnectTimeout=10",
                "-o",
                "LogLevel=ERROR",
            ])
            .arg(format!("{}@127.0.0.1", sshd.user))
            .arg(remote_command),
    )
}

#[cfg(test)]
mod tests {
    use std::process::Command;
    use std::time::{Duration, Instant};

    use super::*;

    /// A tool that outlives its deadline is killed instead of waited for, and the error names it and carries its stderr so far.
    /// (`exec` makes sleep replace sh, so killing it leaves no child holding the pipes; the stderr sentence is split by `printf`, so
    /// finding it whole in the message proves the pipe was really read.)
    #[cfg(unix)]
    #[test]
    fn a_tool_that_outlives_its_deadline_is_killed_and_named() {
        let started = Instant::now();
        let message = run_within(Command::new("sh").args(["-c", "printf 'no %s yet\\n' answer >&2; exec sleep 5"]), Duration::from_millis(500))
            .expect_err("a tool that outlives its deadline must be an error");
        assert!(message.contains("exec sleep 5"), "the message names the command: {message}");
        assert!(message.contains("did not finish within 500ms and was killed"), "the message says what happened: {message}");
        assert!(message.contains("no answer yet"), "the message carries the stderr so far: {message}");
        assert!(started.elapsed() < Duration::from_secs(4), "killed at the deadline, not waited for: {:?}", started.elapsed());
    }

    /// The spike's deferred Minor 2. The tool is killed at its deadline, but a background `sleep` it started still holds the output
    /// pipes. Waiting for end-of-file would take as long as that `sleep` lives; the runner must give up after `PIPE_GRACE` instead.
    #[cfg(unix)]
    #[test]
    fn a_process_that_keeps_the_pipes_open_after_the_kill_does_not_hold_the_runner() {
        let started = Instant::now();
        let message = run_within(Command::new("sh").args(["-c", "sleep 8 & printf 'partial\\n' >&2; exec sleep 30"]), Duration::from_millis(400))
            .expect_err("the tool outlives its deadline");
        let elapsed = started.elapsed();
        assert!(message.contains("did not finish within 400ms and was killed"), "{message}");
        assert!(message.contains("partial"), "the stderr read so far is kept: {message}");
        assert!(elapsed >= Duration::from_millis(400) + PIPE_GRACE - Duration::from_millis(200), "the readers were given their grace: {elapsed:?}");
        assert!(elapsed < Duration::from_secs(6), "but not until the background sleep ended (8 s): {elapsed:?}");
    }

    #[test]
    fn a_tool_that_cannot_be_started_is_an_error_that_names_it() {
        let message = run_within(&mut Command::new("/nonexistent/sshelter-tool"), Duration::from_secs(5)).expect_err("there is no such tool");
        assert!(message.contains("cannot run") && message.contains("/nonexistent/sshelter-tool"), "{message}");
    }

    /// Four MiB on stdout and on stderr is far more than a pipe holds: the readers must keep up or the tool would block until the deadline.
    #[cfg(unix)]
    #[test]
    fn output_far_larger_than_a_pipe_arrives_complete_and_does_not_deadlock() {
        let started = Instant::now();
        let out = run_within(Command::new("sh").args(["-c", "head -c 4194304 /dev/zero; head -c 4194304 /dev/zero >&2"]), Duration::from_secs(20))
            .expect("the tool finishes");
        assert!(out.status.success());
        assert_eq!((out.stdout.len(), out.stderr.len()), (4_194_304, 4_194_304));
        assert!(started.elapsed() < Duration::from_secs(10), "took {:?}", started.elapsed());
    }

    #[cfg(unix)]
    #[test]
    fn the_exit_code_and_both_streams_come_back_like_output_does() {
        let out = run_within(Command::new("sh").args(["-c", "printf out; printf err >&2; exit 3"]), Duration::from_secs(20)).expect("the tool finishes");
        assert_eq!(out.status.code(), Some(3));
        assert_eq!((out.stdout.as_slice(), out.stderr.as_slice()), (b"out".as_slice(), b"err".as_slice()));
    }

    /// `Command::output()` closes stdin and so does `run_within`: a tool that reads it sees end-of-file at once instead of waiting for input.
    #[cfg(unix)]
    #[test]
    fn stdin_is_closed_so_a_tool_that_reads_it_does_not_wait() {
        let started = Instant::now();
        let out = run_within(&mut Command::new("cat"), Duration::from_secs(20)).expect("the tool finishes");
        assert!(out.status.success() && out.stdout.is_empty());
        assert!(started.elapsed() < Duration::from_secs(5), "took {:?}", started.elapsed());
    }

    /// The scratch sshd works with the system ssh client, so a later failure is the engine's, not the harness's.
    #[test]
    fn the_system_ssh_client_logs_in_to_the_scratch_sshd_and_gets_the_exit_code() {
        let Some(tools) = tools() else { return };
        let keys = tempfile::tempdir().unwrap();
        let key = generate_key(&tools, keys.path(), "user", KeyKind::Ed25519);
        let sshd = Sshd::start(&tools, SshdOptions { authorized_keys: vec![key.public_line.clone()], ..SshdOptions::default() });

        let out = system_ssh(&tools, &sshd, &key.private_path, "echo harness-ok; exit 5");
        assert_eq!(
            String::from_utf8_lossy(&out.stdout),
            "harness-ok\n",
            "ssh stderr: {}; sshd log: {}",
            String::from_utf8_lossy(&out.stderr),
            sshd.log()
        );
        assert_eq!(out.status.code(), Some(5));
    }

    /// The negative control: a key that is not in authorized_keys is refused, so the test above proves the server really checks keys.
    #[test]
    fn a_key_that_is_not_in_authorized_keys_is_refused() {
        let Some(tools) = tools() else { return };
        let keys = tempfile::tempdir().unwrap();
        let allowed = generate_key(&tools, keys.path(), "allowed", KeyKind::Ed25519);
        let stranger = generate_key(&tools, keys.path(), "stranger", KeyKind::Ed25519);
        let sshd = Sshd::start(&tools, SshdOptions { authorized_keys: vec![allowed.public_line.clone()], ..SshdOptions::default() });

        let out = system_ssh(&tools, &sshd, &stranger.private_path, "echo must-not-run");
        assert_eq!(out.status.code(), Some(255), "ssh exits 255 when it cannot log in");
        assert!(out.stdout.is_empty());
    }

    /// A P-256 key made by ssh-keygen whose secret number OpenSSH wrote in 31 bytes (it starts with a zero byte, and the next byte's top bit
    /// is clear): `ssh-key` 0.6.7 alone refuses it for its length, and the vault pads the number (`vault::short_scalar`) and reads it. It has
    /// no use anywhere else.
    const KEY_WITH_A_SHORT_SCALAR: &str = "-----BEGIN OPENSSH PRIVATE KEY-----\n\
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAaAAAABNlY2RzYS\n\
1zaGEyLW5pc3RwMjU2AAAACG5pc3RwMjU2AAAAQQSuW0Nk03fDQ13F6fng1wB9jKTOZRrA\n\
gvYrf2SP7Kb9Vme+68pkttmFg6RPsQzG79ZoRUz41uJ+GWc4IrB7xjCNAAAAoEqbIrdKmy\n\
K3AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBK5bQ2TTd8NDXcXp\n\
+eDXAH2MpM5lGsCC9it/ZI/spv1WZ77rymS22YWDpE+xDMbv1mhFTPjW4n4ZZzgisHvGMI\n\
0AAAAfYEFcmxx3tGd8wan73CnFtcul1j9y5R24/F1yRgGWwgAAAAVwcm9iZQECAwQ=\n\
-----END OPENSSH PRIVATE KEY-----\n";

    #[test]
    fn a_key_with_a_short_ecdsa_scalar_is_read_by_the_vault_though_ssh_key_alone_refuses_it() {
        let error = ssh_key::PrivateKey::from_openssh(KEY_WITH_A_SHORT_SCALAR).err().expect("ssh-key 0.6.7 alone refuses this key");
        assert!(error.to_string().contains("length"), "refused for its length, not for some other reason: {error}");
        assert!(readable_by_the_vault(KEY_WITH_A_SHORT_SCALAR), "the vault pads the secret number and reads the key");
        let Some(tools) = tools() else { return };
        let keys = tempfile::tempdir().unwrap();
        let key = generate_key(&tools, keys.path(), "good", KeyKind::Ed25519);
        assert!(readable_by_the_vault(&key.private_text));
    }

    /// About one P-256 key in 512 has a secret number that OpenSSH writes shorter than 32 bytes, which `ssh-key` alone cannot read and the
    /// vault can: of 150 keys ssh-keygen makes, the vault reads every one.
    #[test]
    fn the_keys_the_harness_hands_out_can_all_be_read_by_the_vault() {
        let Some(tools) = tools() else { return };
        let keys = tempfile::tempdir().unwrap();
        for index in 0..150 {
            let key = generate_key(&tools, keys.path(), &format!("p256-{index}"), KeyKind::EcdsaP256);
            assert!(readable_by_the_vault(&key.private_text), "key {index} cannot be read");
        }
    }

    /// A short secret number in keys ssh-keygen encrypted itself, with every cipher the vault opens: OpenSSH's own output for the AEAD
    /// ciphers' tag and for chacha20-poly1305's block of 8, where the vault's tests otherwise build the keys themselves. About one P-521 key
    /// in 4 has a short number, so ssh-keygen makes keys until one does (40 at most: all 40 fail with a chance of 0.75^40, about 1 in
    /// 100 000), and `-p` encrypts it with one bcrypt round, fast in a debug build.
    #[test]
    fn a_p521_key_with_a_short_secret_number_opens_whatever_cipher_ssh_keygen_encrypted_it_with() {
        use crate::vault::material::{self, OpenError};
        let Some(tools) = tools() else { return };
        let keys = tempfile::tempdir().unwrap();
        let short = (0..40)
            .map(|index| generate_key(&tools, keys.path(), &format!("p521-{index}"), KeyKind::EcdsaP521))
            .find(|key| ssh_key::PrivateKey::from_openssh(&key.private_text).is_err_and(|error| error.to_string().contains("length")))
            .expect("about one P-521 key in 4 has a short secret number, and none of 40 had one");
        let public = material::public_key_data(&short.public_line).expect("the public key parses");
        for (index, cipher) in material::SUPPORTED_CIPHERS.iter().enumerate() {
            let path = keys.path().join(format!("encrypted-{index}"));
            std::fs::copy(&short.private_path, &path).expect("copy the private key");
            let out = run_bounded(
                Command::new(&tools.ssh_keygen).args(["-q", "-p", "-P", "", "-N", "pass", "-a", "1", "-Z", cipher]).arg("-f").arg(&path),
            );
            assert!(out.status.success(), "{cipher}: ssh-keygen -p failed: {}", String::from_utf8_lossy(&out.stderr));
            let text = std::fs::read_to_string(&path).expect("read the encrypted key");
            let refused = ssh_key::PrivateKey::from_openssh(&text).expect("ssh-key parses the encrypted key").decrypt("pass").err();
            assert_eq!(refused, Some(ssh_key::Error::Encoding(ssh_encoding::Error::Length)), "{cipher}: setup: still short, ssh-key alone can't decrypt it");
            let opened = material::open(&text, Some("pass")).unwrap_or_else(|error| panic!("{cipher}: {error:?}\n{text}"));
            assert_eq!(opened.key_data(), public, "{cipher}");
            assert_eq!(material::open(&text, Some("wrong")).err(), Some(OpenError::WrongPassphrase), "{cipher}");
        }
    }

    /// A server can have several host keys; the first line of `host_public_lines` is the first `HostKey`.
    #[test]
    fn a_scratch_sshd_can_have_more_than_one_host_key() {
        let Some(tools) = tools() else { return };
        let sshd = Sshd::start(&tools, SshdOptions { host_keys: vec![KeyKind::Ed25519, KeyKind::Rsa3072], ..SshdOptions::default() });
        assert_eq!(sshd.host_public_lines.len(), 2);
        assert!(sshd.host_public_line().starts_with("ssh-ed25519 "), "{}", sshd.host_public_line());
        assert!(sshd.host_public_lines[1].starts_with("ssh-rsa "), "{}", sshd.host_public_lines[1]);
    }

    /// Dropping the server stops the listener, so a finished test leaves nothing behind on its port.
    #[test]
    fn dropping_the_scratch_sshd_closes_its_port() {
        let Some(tools) = tools() else { return };
        let sshd = Sshd::start(&tools, SshdOptions::default());
        let port = sshd.port;
        assert!(TcpStream::connect_timeout(&SocketAddr::from((Ipv4Addr::LOCALHOST, port)), Duration::from_secs(2)).is_ok());
        drop(sshd);
        let deadline = Instant::now() + Duration::from_secs(5);
        while Instant::now() < deadline {
            if TcpStream::connect_timeout(&SocketAddr::from((Ipv4Addr::LOCALHOST, port)), Duration::from_millis(300)).is_err() {
                return;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        panic!("port {port} still accepts connections 5 s after the server was dropped");
    }

    /// Whether a process runs. A zombie (dead, but its parent has not collected it yet) does not: `ps` shows it as `<defunct>`.
    #[cfg(unix)]
    fn is_running(pid: u32) -> bool {
        match command_line_of(pid) {
            Ok(None) => false,
            Ok(Some(command)) => !command.contains("<defunct>"),
            Err(_) => true,
        }
    }

    /// Waits (up to `seconds`) until none of `pids` runs; the ones that still do otherwise.
    #[cfg(unix)]
    fn still_running_after(pids: &[u32], seconds: u64) -> Vec<u32> {
        let deadline = Instant::now() + Duration::from_secs(seconds);
        loop {
            let alive: Vec<u32> = pids.iter().copied().filter(|pid| is_running(*pid)).collect();
            if alive.is_empty() || Instant::now() >= deadline {
                return alive;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    /// For every connection the listener forks a process (`sshd-session`; a copy of sshd before OpenSSH 9.8), in a session of its own. A
    /// test that left a connection open used to leave these processes behind when its server was dropped. A connection that is only open
    /// (no login) forks the same process, which keeps this test cheap.
    #[cfg(unix)]
    #[test]
    fn dropping_the_scratch_sshd_also_ends_the_session_processes_it_forked() {
        let Some(tools) = tools() else { return };
        let sshd = Sshd::start(&tools, SshdOptions::default());
        let listener = sshd.child.id();
        let before = descendants_of(listener);
        let _connection = TcpStream::connect_timeout(&SocketAddr::from((Ipv4Addr::LOCALHOST, sshd.port)), Duration::from_secs(2)).expect("connect");
        let deadline = Instant::now() + Duration::from_secs(10);
        let forked = loop {
            if let Some(pid) = descendants_of(listener).into_iter().find(|pid| !before.contains(pid)) {
                break pid;
            }
            assert!(Instant::now() < deadline, "the listener forked no process for the connection");
            std::thread::sleep(Duration::from_millis(20));
        };
        assert!(is_running(forked), "pid {forked} was forked for the connection and runs");

        drop(sshd);
        assert_eq!(still_running_after(&[forked], 2), Vec::<u32>::new(), "the process forked for the connection outlived the server");
    }

    /// The case that used up the PTYs: a login with a command on a PTY (`ssh -tt`) that is still open when the server is dropped. The
    /// chain is the listener, `sshd-session [priv]`, `sshd-session user@tty` and the command; none of the three stays in the listener's
    /// process group (the first starts a session of its own, the command on its PTY another), so a process group would not reach them.
    #[cfg(unix)]
    #[test]
    fn dropping_the_scratch_sshd_also_ends_a_login_on_a_pty_that_is_still_open() {
        let Some(tools) = tools() else { return };
        let keys = tempfile::tempdir().unwrap();
        let user = generate_key(&tools, keys.path(), "user", KeyKind::Ed25519);
        let sshd = Sshd::start(&tools, SshdOptions { authorized_keys: vec![user.public_line.clone()], ..SshdOptions::default() });
        let listener = sshd.child.id();
        let mut command = Command::new(&tools.ssh);
        command
            .args(["-F", "/dev/null", "-tt", "-p"])
            .arg(sshd.port.to_string())
            .arg("-i")
            .arg(&user.private_path)
            .args(["-o", "IdentitiesOnly=yes", "-o", "IdentityAgent=none", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=no"])
            .args(["-o", "UserKnownHostsFile=/dev/null", "-o", "ConnectTimeout=10", "-o", "LogLevel=ERROR"])
            .arg(format!("{}@127.0.0.1", sshd.user))
            .arg("sleep 30")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        let _client = KillOnDrop(crate::process::spawn(&mut command).expect("start ssh"));

        // The login is up when the command runs on the server: a descendant of the listener whose command line is `sleep 30`.
        let deadline = Instant::now() + Duration::from_secs(15);
        let family = loop {
            let family = descendants_of(listener);
            if family.iter().any(|pid| command_line_of(*pid) == Ok(Some("sleep 30".to_string()))) {
                break family;
            }
            assert!(Instant::now() < deadline, "the login never ran its command; the listener's family: {family:?}");
            std::thread::sleep(Duration::from_millis(50));
        };
        assert!(family.len() >= 3, "the session processes and the command descend from the listener: {family:?}");

        drop(sshd);
        assert_eq!(still_running_after(&family, 2), Vec::<u32>::new(), "processes of the login outlived the server (the client is still connected)");
    }

    /// The pid of a process that has run and been waited for: no process has it now.
    #[cfg(unix)]
    fn a_dead_pid() -> u32 {
        let mut child = crate::process::spawn(&mut Command::new("true")).expect("run true");
        let pid = child.id();
        child.wait().expect("wait for true");
        pid
    }

    /// Kills and collects its process when dropped, so that a failing assertion leaves nothing running.
    #[cfg(unix)]
    struct KillOnDrop(Child);

    #[cfg(unix)]
    impl Drop for KillOnDrop {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }

    /// A signal that kills the test process skips `Drop`, so its sshd keeps listening and its directory stays (module doc). The next
    /// `Sshd::start` must find both through `owner.pid` and clean up. The dead owner is made up (the pid of a process that has exited),
    /// since this test process cannot be killed here. The first server stays in scope on purpose: if an assertion fails, its `Drop`
    /// still kills the listener and removes what is left of the directory. (It is also why this test does not `forget` it: the sshd is
    /// this process's own child, and a child that was killed stays a zombie until its parent collects it.)
    #[cfg(unix)]
    #[test]
    fn the_next_start_kills_the_sshd_of_a_dead_test_process_and_removes_its_directory() {
        let Some(tools) = tools() else { return };
        let mut stale = Sshd::start(&tools, SshdOptions::default());
        let (dir, sshd_pid) = (stale.dir.path().to_path_buf(), stale.child.id());
        assert_eq!(read_owner_file(&dir), Some((std::process::id(), sshd_pid)), "owner.pid names this test process and its sshd");

        // While its owner lives, a sweep leaves the server alone.
        sweep_stale(&std::env::temp_dir());
        assert!(dir.exists() && stale.child.try_wait().unwrap().is_none(), "the server of a live owner is not touched by a sweep");

        // From here on it looks like the server of a test process that a signal has killed.
        write_owner_file(&dir, a_dead_pid(), sshd_pid).expect("rewrite owner.pid");
        let _next = Sshd::start(&tools, SshdOptions::default()); // the sweep is the first thing it does

        assert!(!dir.exists(), "the directory of the dead owner is removed");
        let status = stale.child.try_wait().expect("ask for the exit status").expect("the sweep killed the sshd"); // this also collects the zombie
        assert_eq!(std::os::unix::process::ExitStatusExt::signal(&status), Some(libc::SIGKILL), "killed by the sweep, not by itself: {status:?}");
        assert_eq!(command_line_of(sshd_pid), Ok(None), "ps knows no such process any more");
    }

    /// What the sweep must not do. The directory of a dead owner is removed in any case, but the sshd pid in its file may belong to
    /// another program by now: only a process whose command line names the directory's own `sshd_config` is killed, and `sleep 30` here
    /// does not. A directory whose owner file is missing or makes no sense is not judged at all.
    #[cfg(unix)]
    #[test]
    fn a_sweep_removes_a_dead_owners_directory_but_kills_only_a_process_that_names_it() {
        if tools().is_none() {
            return;
        }
        let root = tempfile::tempdir().unwrap();
        let make = |name: &str| {
            let dir = root.path().join(format!("{DIR_PREFIX}{name}"));
            std::fs::create_dir(&dir).unwrap();
            std::fs::write(dir.join("sshd_config"), "Port 1\n").unwrap();
            dir
        };
        let (reused, no_file, garbage) = (make("reused-pid"), make("no-owner-file"), make("garbage-owner-file"));
        std::fs::write(garbage.join(OWNER_FILE), "not a pid\n").unwrap();
        let mut other = KillOnDrop(
            crate::process::spawn(Command::new("sleep").arg("30").stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null())).expect("start sleep"),
        );
        write_owner_file(&reused, a_dead_pid(), other.0.id()).unwrap();

        sweep_stale(root.path());

        assert!(!reused.exists(), "the directory of the dead owner is removed");
        assert!(other.0.try_wait().unwrap().is_none(), "the sleep is still running: its command line does not name the directory");
        assert!(no_file.exists() && garbage.exists(), "a directory without a usable owner.pid is left alone");
    }
}
