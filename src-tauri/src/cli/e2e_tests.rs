//! `sshelter connect` the whole way (plan 1b): the CLI's loop with a fake terminal, the broker on a real socket, the real engine, and a
//! scratch OpenSSH. The window that confirms host keys is scripted; nothing else is a double.

use std::io::Write;
use std::os::unix::net::UnixStream;
use std::sync::mpsc::Sender;
use std::sync::{Arc, Mutex};

use super::client::Input;
use super::run::run;
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
    keys: Sender<Input>,
    stdout: Shared,
    stderr: Shared,
    run: std::thread::JoinHandle<i32>,
    directory: Arc<FakeDirectory>,
    _dir: tempfile::TempDir,
}

impl Session {
    fn type_text(&self, text: &str) {
        self.keys.send(Input::Stdin(zeroize::Zeroizing::new(text.as_bytes().to_vec()))).unwrap();
    }

    fn finish(self) -> (i32, String, Arc<FakeTermios>, Arc<FakeDirectory>) {
        eventually("sshelter connect to end", 30, || self.run.is_finished());
        let stderr = self.stderr.text();
        (self.run.join().unwrap(), stderr, self.termios, self.directory)
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
    let (sender, receiver) = std::sync::mpsc::channel();
    let (stdout, stderr) = (Shared::default(), Shared::default());
    let run = {
        let (termios, sender, mut stdout, mut stderr) = (Arc::clone(&termios), sender.clone(), stdout.clone(), stderr.clone());
        std::thread::spawn(move || {
            let mut tty = Tty::new(termios).unwrap();
            run(stream, HostQuery::Alias("lab".into()), "xterm-256color".into(), &mut tty, (sender, receiver), &mut stdout, &mut stderr)
        })
    };
    Session { termios, keys: sender, stdout, stderr, run, directory, _dir: dir }
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
    eventually("the shell to open", 30, || raw(&session.termios));
    eventually("a prompt", 20, || session.stdout.text().contains("$ "));
    session.type_text("echo SSHELTER_$((6*7))\r");
    eventually("the command's output", 20, || session.stdout.text().contains("SSHELTER_42"));
    session.type_text("exit 7\r");
    let (code, stderr, termios, directory) = session.finish();
    assert_eq!(code, 7);
    assert_eq!(stderr, "Waiting for you to confirm lab's host key in SSHelter.\n");
    assert!(termios.is_start(&termios.now()), "the terminal is as it was");
    assert_eq!(directory.pins().get(&HostId::from("host-lab")).map(|pin| pin.key.clone()), Some(server.host_key()));
}

/// The person does not trust the key: nothing is pinned, the CLI says so and exits 255, as ssh does for a refused key.
#[test]
fn a_host_key_the_person_does_not_trust_ends_sshelter_connect() {
    let Some(tools) = tools() else { return };
    let server = Server::start(&tools, &[SHELL]);
    let session = connect(&server, server.sshd.port, vec![Decision::Refuse]);
    let (code, stderr, termios, directory) = session.finish();
    assert_eq!(code, 255);
    assert_eq!(stderr, "Waiting for you to confirm lab's host key in SSHelter.\nThe host key of lab has not been confirmed yet.\n");
    assert!(termios.is_start(&termios.now()));
    assert!(directory.pins().is_empty());
}

/// The link is cut while the shell runs: the CLI puts the terminal back, says the connection was lost, and exits 255 — never 0.
#[test]
fn a_connection_lost_in_the_middle_of_a_shell_is_said_and_the_status_is_255() {
    let Some(tools) = tools() else { return };
    let server = Server::start(&tools, &[SHELL]);
    let proxy = Proxy::start(server.sshd.port);
    let session = connect(&server, proxy.port, vec![Decision::Trust]);
    eventually("a prompt", 30, || session.stdout.text().contains("$ "));
    proxy.set(Mode::Cut);
    let (code, stderr, termios, _) = session.finish();
    assert_eq!(code, 255);
    assert_eq!(stderr, "Waiting for you to confirm lab's host key in SSHelter.\n\nConnection to lab lost (early eof).\n");
    assert!(termios.is_start(&termios.now()));
}
