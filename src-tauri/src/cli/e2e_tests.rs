//! `sshelter connect` the whole way (plan 1b): the CLI's loop, the broker on a real socket, the real engine, and a scratch OpenSSH.
//! The doubles: the terminal (a `FakeTermios` under the real `Tty`; the keys go in through `Inputs::send`, so no keys, signal or
//! watchdog thread runs, nor `own_writer`, `reach_broker` or main.rs), standard output and error (`Shared`), the host directory
//! (`FakeDirectory`), the key store (`FakeKeys`), the keychain (`MemKeychain`), and the window that confirms host keys
//! (`FakeConfirmer`, scripted).

use std::io::Write;
use std::os::unix::net::UnixStream;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use super::client::Input;
use super::run::{queue, run, Inputs};
use super::terminal::fake::FakeTermios;
use super::terminal::Tty;
use crate::session::broker::Broker;
use crate::session::connect::HostKeyConfirmer;
use crate::session::directory::HostDirectory;
use crate::session::protocol::HostQuery;
use crate::session::testing::{Decision, FakeConfirmer, FakeDirectory, FakeKeys};
use crate::ssh::russh_engine::RusshEngine;
use crate::ssh::testing::eventually;
use crate::ssh::testing::fixture::Server;
use crate::ssh::testing::harness::tools;
use crate::ssh::testing::proxy::{Mode, Proxy};
use crate::ssh::{AuthMethod, HostId};
use crate::sync::testkit::MemKeychain;

/// A shell of `/bin/sh` for the scratch sshd (as the engine's own tests use), so the prompt does not depend on anyone's shell setup.
const SHELL: &str = "ForceCommand if [ -n \"$SSH_ORIGINAL_COMMAND\" ]; then eval \"$SSH_ORIGINAL_COMMAND\"; else exec /bin/sh; fi";

/// A `Write` the test reads while the run goes on.
#[derive(Clone, Default)]
struct Shared(Arc<Mutex<Vec<u8>>>);

impl Write for Shared {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl Shared {
    fn text(&self) -> String {
        String::from_utf8_lossy(&self.0.lock().unwrap()).into_owned()
    }
}

struct Session {
    termios: Arc<FakeTermios>,
    keys: Inputs,
    stdout: Shared,
    stderr: Shared,
    /// The exit code, and whether the terminal was back as it was when `run` returned: looked at before the `Tty` is dropped, whose
    /// `Drop` puts the terminal back as well and would hide a run that did not.
    run: std::thread::JoinHandle<(i32, bool)>,
    directory: Arc<FakeDirectory>,
    broker: Arc<Broker>,
    _dir: tempfile::TempDir,
}

/// How `sshelter connect` ended.
struct Ended {
    code: i32,
    /// The run put the terminal back itself.
    restored: bool,
    stdout: String,
    stderr: String,
    directory: Arc<FakeDirectory>,
    broker: Arc<Broker>,
}

impl Session {
    /// What the CLI wrote, for a failure message.
    fn said(&self) -> String {
        format!("sshelter connect wrote to stderr {:?} and to stdout {:?}", self.stderr.text(), self.stdout.text())
    }

    /// Waits up to `seconds` for `condition`. The CLI ending before it, or the time running out, fails the test at once, with what the
    /// CLI wrote.
    fn wait_for(&self, what: &str, seconds: u64, condition: impl Fn(&Session) -> bool) {
        let deadline = Instant::now() + Duration::from_secs(seconds);
        loop {
            // The run's end is looked at first: a condition met as it ended counts.
            let ended = self.run.is_finished();
            if condition(self) {
                return;
            }
            assert!(!ended, "sshelter connect ended before {what}; {}", self.said());
            assert!(Instant::now() < deadline, "timed out after {seconds} s waiting for {what}; {}", self.said());
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    fn type_text(&self, text: &str) {
        let typed = self.keys.send(Input::Stdin(zeroize::Zeroizing::new(text.as_bytes().to_vec())));
        assert!(typed.is_ok(), "sshelter connect had ended before {text:?} was typed; {}", self.said());
    }

    /// The end, which must come within 30 s.
    fn finish(self) -> Ended {
        self.wait_for("sshelter connect to end", 30, |session| session.run.is_finished());
        let (code, restored) = self.run.join().unwrap();
        Ended { code, restored, stdout: self.stdout.text(), stderr: self.stderr.text(), directory: self.directory, broker: self.broker }
    }
}

impl Ended {
    /// The broker has forgotten the session (it leaves the broker's table once its thread is over).
    fn forgotten(&self) {
        eventually("the broker to forget the session", 10, || !self.broker.has_sessions());
    }
}

/// `sshelter connect lab`, where `lab` is a scratch sshd reached on `port` (its own, or a proxy's) with its user key in the vault.
fn connect(server: &Server, port: u16, decisions: Vec<Decision>) -> Session {
    let directory = Arc::new(FakeDirectory::new().with_hop(server.hop_with("lab", port, AuthMethod::Key { key_id: "k1".into() })));
    let broker = Broker::new(
        Arc::new(RusshEngine::new()),
        Arc::clone(&directory) as Arc<dyn HostDirectory>,
        Arc::new(FakeKeys::new().with_key("k1", "lab key", &server.key.private_text)),
        Arc::new(MemKeychain::default()),
        Arc::new(FakeConfirmer::deciding(decisions)) as Arc<dyn HostKeyConfirmer>,
    );
    let dir = tempfile::Builder::new().prefix("sc").tempdir_in("/tmp").unwrap();
    let ipc = crate::session::ipc_dir(dir.path());
    crate::ipc::server::listen_unix(&ipc, broker.handler()).unwrap();
    let stream = UnixStream::connect(crate::session::socket_path(dir.path())).unwrap();
    let termios = FakeTermios::new();
    let (inputs, queue) = queue();
    let (stdout, stderr) = (Shared::default(), Shared::default());
    let run = {
        let (termios, inputs, stdout, stderr) = (Arc::clone(&termios), inputs.clone(), stdout.clone(), stderr.clone());
        std::thread::spawn(move || {
            let mut tty = Tty::new(termios.clone()).unwrap();
            let code = run(stream, HostQuery::Alias("lab".into()), "xterm-256color".into(), &mut tty, (inputs, queue), Box::new(stdout), Box::new(stderr));
            (code, termios.is_start(&termios.now()))
        })
    };
    Session { termios, keys: inputs, stdout, stderr, run, directory, broker, _dir: dir }
}

fn raw(termios: &FakeTermios) -> bool {
    termios.now().c_lflag & libc::ICANON == 0
}

/// The first contact: the host key is confirmed in the window and pinned, the shell runs a command, and its exit status is the CLI's.
#[test]
fn sshelter_connect_confirms_the_host_key_runs_a_shell_and_exits_with_its_status() {
    let Some(tools) = tools() else { return };
    let server = Server::start(&tools, &[SHELL]);
    let session = connect(&server, server.sshd.port, vec![Decision::Trust]);
    session.wait_for("the shell to open", 30, |session| raw(&session.termios));
    session.wait_for("a prompt", 20, |session| session.stdout.text().contains("$ "));
    session.type_text("echo SSHELTER_$((6*7))\r");
    session.wait_for("the command's output", 20, |session| session.stdout.text().contains("SSHELTER_42"));
    session.type_text("exit 7\r");
    let ended = session.finish();
    assert_eq!(ended.code, 7);
    assert_eq!(ended.stderr, "Waiting for you to confirm lab's host key in SSHelter.\n");
    assert!(ended.restored, "the terminal is as it was");
    assert_eq!(ended.directory.pins().get(&HostId::from("host-lab")).map(|pin| pin.key.clone()), Some(server.host_key()));
    ended.forgotten();
}

/// The person does not trust the key: nothing is pinned, the CLI says so and exits 255, as ssh does for a refused key.
#[test]
fn a_host_key_the_person_does_not_trust_ends_sshelter_connect() {
    let Some(tools) = tools() else { return };
    let server = Server::start(&tools, &[SHELL]);
    let session = connect(&server, server.sshd.port, vec![Decision::Refuse]);
    let ended = session.finish();
    assert_eq!(ended.code, 255);
    assert_eq!(ended.stderr, "Waiting for you to confirm lab's host key in SSHelter.\nThe host key of lab has not been confirmed yet.\n");
    assert_eq!(ended.stdout, "", "no shell was opened, and nothing of one was shown");
    assert!(ended.restored, "the terminal is as it was");
    assert!(ended.directory.pins().is_empty());
    ended.forgotten();
}

/// The link is cut while the shell runs: the CLI puts the terminal back, says the connection was lost, and exits 255 — never 0.
#[test]
fn a_connection_lost_in_the_middle_of_a_shell_is_said_and_the_status_is_255() {
    let Some(tools) = tools() else { return };
    let server = Server::start(&tools, &[SHELL]);
    let proxy = Proxy::start(server.sshd.port);
    let session = connect(&server, proxy.port, vec![Decision::Trust]);
    session.wait_for("a prompt", 30, |session| session.stdout.text().contains("$ "));
    proxy.set(Mode::Cut);
    let ended = session.finish();
    assert_eq!(ended.code, 255);
    assert_eq!(ended.stderr, "Waiting for you to confirm lab's host key in SSHelter.\n\nConnection to lab lost (early eof).\n");
    assert!(ended.restored, "the terminal is as it was");
    ended.forgotten();
}
