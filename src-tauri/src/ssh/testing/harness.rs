//! A scratch OpenSSH server for the engine's integration tests: a temp directory, a free localhost port, throwaway host keys and
//! authorized_keys, and `sshd -D -e -f <config>` run as the current user (no root, no PAM). Nothing here reads or writes the real
//! `~/.ssh`: the system `ssh` client used by `system_ssh` gets `-F /dev/null`.
//!
//! Ported from the phase-0 spike (`spike/russh/src/harness.rs`, checked on macOS with OpenSSH 10.3p1): `Port 0` is rejected ("Badly
//! formatted port number"), so the port is picked first; sshd prints one harmless line `BSM audit: ... setaudit_addr failed:
//! Operation not permitted`; password and keyboard-interactive login cannot work without PAM, so this sshd offers public keys only.
//! Every test starts its own sshd. A test that needs one sshd for a long loop adds `PerSourcePenalties no` to its `extra_config`
//! (OpenSSH 9.8 and later know the keyword, older ones refuse the config, so it cannot be a default).

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

/// After a tool was killed (or has exited) its pipes can stay open: a grandchild may have inherited them. The readers get this long to
/// reach end-of-file; after that the output collected so far is used and the readers are left to end on their own.
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
                    Ok(0) | Err(_) => break,
                    Ok(count) => sink.lock().unwrap_or_else(PoisonError::into_inner).extend_from_slice(&chunk[..count]),
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
/// long as the grandchild lives, so the readers get `PIPE_GRACE` and then the output so far is used (the spike's deferred Minor 2).
pub(super) fn run_within(command: &mut Command, timeout: Duration) -> Result<Output, String> {
    command.stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped());
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
    Rsa3072,
}

impl KeyKind {
    fn keygen_args(self) -> &'static [&'static str] {
        match self {
            KeyKind::Ed25519 => &["-t", "ed25519"],
            KeyKind::EcdsaP256 => &["-t", "ecdsa", "-b", "256"],
            KeyKind::Rsa3072 => &["-t", "rsa", "-b", "3072"],
        }
    }
}

/// A key pair made by ssh-keygen, in the OpenSSH private key format the vault reads.
pub struct TestKey {
    pub kind: KeyKind,
    pub private_path: PathBuf,
    pub private_text: String,
    /// `<type> <base64> sshelter-test`: the authorized_keys form.
    pub public_line: String,
}

/// Whether the vault's parser (`ssh-key` 0.6.7, which `Material::open` uses) reads this OpenSSH private key.
fn readable_by_the_vault(private_text: &str) -> bool {
    ssh_key::PrivateKey::from_openssh(private_text).is_ok()
}

/// Makes a key pair with ssh-keygen. A key the vault's parser cannot read is thrown away and another is made: `ssh-key` 0.6.7 cannot
/// read an ECDSA private key whose secret number starts with a zero byte (OpenSSH then writes the number in its shortest form and the
/// parser insists on the full length). Measured with ssh-keygen from OpenSSH 10.3p1: 5 of 1500 P-256 keys, 3 of 600 P-384 keys and 77
/// of 300 P-521 keys. A test that signs with such a key through the vault would fail one run in 256 for a reason that has nothing to do
/// with the engine. (Reported with the plan as a gap in the vault: `Material::open` answers `Unreadable` for these keys.)
pub fn generate_key(tools: &Tools, dir: &Path, name: &str, kind: KeyKind) -> TestKey {
    let private_path = dir.join(name);
    let mut public_path = private_path.clone().into_os_string();
    public_path.push(".pub");
    for attempt in 1..=20 {
        let out = run_bounded(
            Command::new(&tools.ssh_keygen).args(["-q", "-N", "", "-C", "sshelter-test"]).args(kind.keygen_args()).arg("-f").arg(&private_path),
        );
        assert!(out.status.success(), "ssh-keygen failed: {}", String::from_utf8_lossy(&out.stderr));
        let private_text = std::fs::read_to_string(&private_path).expect("read the private key");
        if readable_by_the_vault(&private_text) {
            return TestKey {
                kind,
                private_text,
                public_line: std::fs::read_to_string(&public_path).expect("read the public key").trim().to_string(),
                private_path,
            };
        }
        eprintln!("ssh-keygen made a {kind:?} key that the vault's parser cannot read (attempt {attempt}); making another");
        let _ = std::fs::remove_file(&private_path);
        let _ = std::fs::remove_file(&public_path);
    }
    panic!("20 {kind:?} keys in a row could not be read by the vault's parser");
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

/// A running scratch sshd. Dropping it kills the listener (connections already open end when their client goes away).
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
        // Asked before the first sshd starts: a panic in here must not leave a listener behind.
        let user = current_user();
        let dir = tempfile::Builder::new().prefix("sshelter-sshd-").tempdir().expect("temp dir");
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
            if wait_for_banner(&mut child, port) {
                let host_public_lines = host_keys.iter().map(|key| key.public_line.clone()).collect();
                return Sshd { port, user, host_public_lines, dir, child };
            }
            let _ = child.kill();
            let _ = child.wait();
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
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

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

    /// `ssh-key` 0.6.7 cannot read an ECDSA key whose secret number starts with a zero byte; this P-256 key, made by ssh-keygen, is one of
    /// them (`Material::open` says `Unreadable` for it). It has no use anywhere else.
    const KEY_THE_VAULT_CANNOT_READ: &str = "-----BEGIN OPENSSH PRIVATE KEY-----\n\
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAaAAAABNlY2RzYS\n\
1zaGEyLW5pc3RwMjU2AAAACG5pc3RwMjU2AAAAQQSuW0Nk03fDQ13F6fng1wB9jKTOZRrA\n\
gvYrf2SP7Kb9Vme+68pkttmFg6RPsQzG79ZoRUz41uJ+GWc4IrB7xjCNAAAAoEqbIrdKmy\n\
K3AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBK5bQ2TTd8NDXcXp\n\
+eDXAH2MpM5lGsCC9it/ZI/spv1WZ77rymS22YWDpE+xDMbv1mhFTPjW4n4ZZzgisHvGMI\n\
0AAAAfYEFcmxx3tGd8wan73CnFtcul1j9y5R24/F1yRgGWwgAAAAVwcm9iZQECAwQ=\n\
-----END OPENSSH PRIVATE KEY-----\n";

    #[test]
    fn a_key_the_vaults_parser_cannot_read_is_told_apart_from_one_it_can() {
        let error = ssh_key::PrivateKey::from_openssh(KEY_THE_VAULT_CANNOT_READ).err().expect("the parser refuses this key");
        assert!(error.to_string().contains("length"), "refused for its length, not for some other reason: {error}");
        assert!(!readable_by_the_vault(KEY_THE_VAULT_CANNOT_READ));
        let Some(tools) = tools() else { return };
        let keys = tempfile::tempdir().unwrap();
        let key = generate_key(&tools, keys.path(), "good", KeyKind::Ed25519);
        assert!(readable_by_the_vault(&key.private_text));
    }

    /// About one P-256 key in 256 is one the vault cannot read: of 150 keys the harness hands out, none may be.
    #[test]
    fn the_keys_the_harness_hands_out_can_all_be_read_by_the_vault() {
        let Some(tools) = tools() else { return };
        let keys = tempfile::tempdir().unwrap();
        for index in 0..150 {
            let key = generate_key(&tools, keys.path(), &format!("p256-{index}"), KeyKind::EcdsaP256);
            assert!(readable_by_the_vault(&key.private_text), "key {index} cannot be read");
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
}
