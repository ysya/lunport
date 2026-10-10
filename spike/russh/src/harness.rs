//! A scratch OpenSSH server for the spike's tests.
//!
//! src-tauri has no sshd harness (`agent/openssh_tests.rs` only runs ssh-keygen and ssh-add against SSHelter's own agent), so this
//! builds one: a temp directory, a free localhost port, a throwaway host key and authorized_keys, and `sshd -D -e -f <config>` run
//! as the current user (no root, no PAM). Nothing here reads or writes the real ~/.ssh: the system `ssh` client used by
//! `system_ssh` gets `-F /dev/null`.
//!
//! Checked by hand on macOS (OpenSSH 10.3p1) before this plan was written: `Port 0` is rejected ("Badly formatted port number"), so
//! the port is picked first; sshd prints one harmless line `BSM audit: ... setaudit_addr failed: Operation not permitted`;
//! password and keyboard-interactive login cannot work without PAM, so this sshd offers public keys only.

use std::io::Read;
use std::net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

/// The OpenSSH programs the tests need.
pub struct Tools {
    pub sshd: PathBuf,
    pub ssh: PathBuf,
    pub ssh_keygen: PathBuf,
}

/// `Some` when sshd, ssh and ssh-keygen are all found. When they are not: `SSHELTER_REQUIRE_OPENSSH=1` (CI) makes that a failure, as in
/// `agent/openssh_tests.rs`; anything else prints "skipped" and the caller returns early.
pub fn tools() -> Option<Tools> {
    let found = find_sshd().and_then(|sshd| Some(Tools { sshd, ssh: find_in_path("ssh")?, ssh_keygen: find_in_path("ssh-keygen")? }));
    if found.is_none() {
        let required = std::env::var("SSHELTER_REQUIRE_OPENSSH").is_ok_and(|v| v == "1");
        assert!(!required, "sshd, ssh and ssh-keygen are required (SSHELTER_REQUIRE_OPENSSH=1)");
        eprintln!("skipped: sshd, ssh or ssh-keygen is not found (or this is not a Unix machine)");
    }
    found
}

/// sshd re-executes itself and insists on an absolute path, and a normal user rarely has it on PATH (Linux keeps it in /usr/sbin).
/// No scratch sshd on Windows: Win32-OpenSSH's sshd must run as a service, which `spike-windows.yml` sets up instead.
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
    #[cfg(windows)]
    {
        // The Win32-OpenSSH in System32 first: Git for Windows puts MSYS2 copies of ssh and ssh-keygen on PATH (see agent/openssh_tests.rs).
        if let Some(root) = std::env::var_os("SystemRoot") {
            let path = Path::new(&root).join("System32").join("OpenSSH").join(&file);
            if path.is_file() {
                return Some(path);
            }
        }
    }
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
    /// `<type> <base64> spike`: the authorized_keys form.
    pub public_line: String,
}

pub fn generate_key(tools: &Tools, dir: &Path, name: &str, kind: KeyKind) -> TestKey {
    let private_path = dir.join(name);
    let out = Command::new(&tools.ssh_keygen)
        .args(["-q", "-N", "", "-C", "spike"])
        .args(kind.keygen_args())
        .arg("-f")
        .arg(&private_path)
        .output()
        .expect("run ssh-keygen");
    assert!(out.status.success(), "ssh-keygen failed: {}", String::from_utf8_lossy(&out.stderr));
    let mut public_path = private_path.clone().into_os_string();
    public_path.push(".pub");
    TestKey {
        kind,
        private_text: std::fs::read_to_string(&private_path).expect("read the private key"),
        public_line: std::fs::read_to_string(&public_path).expect("read the public key").trim().to_string(),
        private_path,
    }
}

pub struct SshdOptions {
    /// The host key's type.
    pub host_key: KeyKind,
    /// Lines for sshd_config. sshd keeps the FIRST value of a keyword, so these come before the defaults below and may override them.
    pub extra_config: Vec<String>,
    /// Public key lines for authorized_keys.
    pub authorized_keys: Vec<String>,
}

impl Default for SshdOptions {
    fn default() -> Self {
        SshdOptions { host_key: KeyKind::Ed25519, extra_config: Vec::new(), authorized_keys: Vec::new() }
    }
}

/// A running scratch sshd. Dropping it kills the listener (connections already open end when their client goes away).
pub struct Sshd {
    pub port: u16,
    /// The account sshd authenticates: the user running the tests (without root, sshd can only log in that user).
    pub user: String,
    /// The host key in authorized_keys form.
    pub host_public_line: String,
    dir: tempfile::TempDir,
    child: Child,
}

impl Sshd {
    pub fn start(tools: &Tools, options: SshdOptions) -> Sshd {
        let dir = tempfile::Builder::new().prefix("spike-sshd-").tempdir().expect("temp dir");
        let host_key = generate_key(tools, dir.path(), "hostkey", options.host_key);
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
        for attempt in 1..=3 {
            let port = free_port();
            std::fs::write(&config_path, config_text(port, &host_key.private_path, &authorized, &options.extra_config)).expect("write sshd_config");
            // `-t` checks the config and the keys without starting anything, so a typo fails here, in sshd's own words.
            let check = Command::new(&tools.sshd).arg("-t").arg("-f").arg(&config_path).output().expect("run sshd -t");
            assert!(
                check.status.success(),
                "sshd -t rejected the config:\n{}\n--- config:\n{}",
                String::from_utf8_lossy(&check.stderr),
                std::fs::read_to_string(&config_path).unwrap_or_default()
            );
            let log = std::fs::File::create(&log_path).expect("create sshd.log");
            let mut child = Command::new(&tools.sshd)
                .args(["-D", "-e", "-f"])
                .arg(&config_path)
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::from(log))
                .spawn()
                .expect("start sshd");
            if wait_for_banner(&mut child, port) {
                return Sshd { port, user: current_user(), host_public_line: host_key.public_line, dir, child };
            }
            let _ = child.kill();
            let _ = child.wait();
            eprintln!("sshd did not come up on port {port} (attempt {attempt}); its log:\n{}", std::fs::read_to_string(&log_path).unwrap_or_default());
        }
        panic!("sshd did not start in 3 attempts");
    }

    /// What sshd wrote to stderr (LogLevel ERROR: a few lines at most).
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

fn config_text(port: u16, host_key: &Path, authorized_keys: &Path, extra: &[String]) -> String {
    let mut lines: Vec<String> = extra.to_vec();
    lines.extend([
        format!("Port {port}"),
        "ListenAddress 127.0.0.1".to_string(),
        format!("HostKey \"{}\"", host_key.display()),
        "PidFile none".to_string(),
        "UsePAM no".to_string(),
        "PasswordAuthentication no".to_string(),
        "KbdInteractiveAuthentication no".to_string(),
        "PubkeyAuthentication yes".to_string(),
        format!("AuthorizedKeysFile \"{}\"", authorized_keys.display()),
        "StrictModes no".to_string(),
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
    let out = Command::new("id").arg("-un").output().expect("run id -un");
    assert!(out.status.success(), "id -un failed");
    String::from_utf8_lossy(&out.stdout).trim().to_string()
}

/// Runs the system `ssh` client against `sshd`. `-F /dev/null` keeps it from reading the real ~/.ssh/config; the agent and known_hosts are off.
pub fn system_ssh(tools: &Tools, sshd: &Sshd, identity: &Path, remote_command: &str) -> std::process::Output {
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
            "LogLevel=ERROR",
        ])
        .arg(format!("{}@127.0.0.1", sshd.user))
        .arg(remote_command)
        .output()
        .expect("run ssh")
}
