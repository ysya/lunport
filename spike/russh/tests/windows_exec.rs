//! Task 4: connect, log in and run a command, against the OpenSSH server described by the environment. `spike-windows.yml` sets
//! SPIKE_SSH_PORT, SPIKE_SSH_USER and SPIKE_SSH_KEY (a passphrase-less OpenSSH private key) for the Windows runner's own sshd. Nothing in the
//! flow is Windows-specific; the job is what makes it so. Without those variables the first test prints "skipped" and passes, and the second
//! test (not built on Windows, see below) runs the same flow against a scratch sshd, so the flow is exercised on every Unix machine that has OpenSSH.

use std::path::Path;

use russh::client::Config;
use russh_spike::client::{connect, exec, login_with_key_file, HostKeyVerdict};
#[cfg(not(windows))]
use russh_spike::fixture::Server;
#[cfg(not(windows))]
use russh_spike::harness::tools;
use russh_spike::{fact, within};

async fn connect_log_in_and_exec(port: u16, user: &str, key: &Path) {
    let mut connection = within(60, "connect", connect(port, Config::default(), HostKeyVerdict::AcceptAny)).await.expect("connect");
    fact("windows.host_key", connection.observed.host_keys.lock().unwrap().join(","));
    let result = within(60, "publickey login", login_with_key_file(&mut connection.handle, user, key)).await.expect("login call");
    assert!(result.success(), "the server refused the key");

    let hello = within(60, "echo", exec(&connection.handle, "echo spike-windows-ok")).await.expect("exec");
    fact("windows.echo_stdout", format!("{:?}", hello.text()));
    assert!(hello.text().contains("spike-windows-ok"), "stdout was {:?}", hello.text());
    assert_eq!(hello.exit_status, Some(0));

    let exit = within(60, "exit 3", exec(&connection.handle, "exit 3")).await.expect("exec");
    assert_eq!(exit.exit_status, Some(3), "the remote exit code must come back through the server too");
}

#[tokio::test(flavor = "multi_thread")]
async fn connect_log_in_and_exec_against_the_server_in_the_environment() {
    let (Ok(port), Ok(user), Ok(key)) = (std::env::var("SPIKE_SSH_PORT"), std::env::var("SPIKE_SSH_USER"), std::env::var("SPIKE_SSH_KEY")) else {
        eprintln!("skipped: SPIKE_SSH_PORT, SPIKE_SSH_USER and SPIKE_SSH_KEY are not all set");
        return;
    };
    connect_log_in_and_exec(port.parse().expect("SPIKE_SSH_PORT is a port number"), &user, Path::new(&key)).await;
}

/// The rehearsal: the same flow against a scratch sshd (skipped where there is no sshd). Not built on Windows: Win32-OpenSSH's sshd must run
/// as a service, so the job there uses the runner's own server through the test above, and this test binary does not reference the Unix-only
/// scratch-sshd harness.
#[cfg(not(windows))]
#[tokio::test(flavor = "multi_thread")]
async fn the_same_flow_against_a_scratch_sshd() {
    let Some(tools) = tools() else { return };
    let server = Server::start(&tools, &[]);
    connect_log_in_and_exec(server.sshd.port, &server.sshd.user, &server.key.private_path).await;
}
