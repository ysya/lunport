//! The engine against the OpenSSH server that the environment describes: on Windows, the runner's own server, which test-windows.yml
//! starts and authorizes a throwaway key on (a scratch sshd cannot run there). The test is the same everywhere. Without
//! `SSHELTER_TEST_SSH_PORT`, `SSHELTER_TEST_SSH_USER` and `SSHELTER_TEST_SSH_KEY` (a passphrase-less OpenSSH private key) it prints
//! "skipped" and passes.

use std::time::Duration;

use super::engine;
use crate::ssh::testing::doubles::{TestPolicy, VaultAuth};
use crate::ssh::testing::fact;
use crate::ssh::{AuthMethod, Ended, Hop, SshEngine, Target};

#[test]
fn connect_log_in_and_exec_against_the_server_in_the_environment() {
    let (Ok(port), Ok(user), Ok(key_path)) = (
        std::env::var("SSHELTER_TEST_SSH_PORT"),
        std::env::var("SSHELTER_TEST_SSH_USER"),
        std::env::var("SSHELTER_TEST_SSH_KEY"),
    ) else {
        eprintln!("skipped: SSHELTER_TEST_SSH_PORT, SSHELTER_TEST_SSH_USER and SSHELTER_TEST_SSH_KEY are not all set");
        return;
    };
    let private_key = std::fs::read_to_string(&key_path).unwrap_or_else(|error| panic!("cannot read {key_path}: {error}"));
    let auth = VaultAuth::new().with_key("k1", &private_key);
    let policy = TestPolicy::trusting();
    let hop = Hop::new("host-env", "env", "127.0.0.1", port.parse().expect("SSHELTER_TEST_SSH_PORT is a port number"), &user, AuthMethod::Key { key_id: "k1".into() });

    let session = engine().connect(&Target { hops: vec![hop] }, &*policy, &auth).expect("the engine connects and logs in");
    if let Some((_, key)) = policy.seen().first() {
        fact("environment.host_key", format!("{} {}", key.algorithm, key.fingerprint));
    }

    // The output is raw bytes: Windows OpenSSH ends a line with CRLF, a Unix sshd with LF.
    let hello = session.exec("echo sshelter-engine-ok", Duration::from_secs(60), 1 << 20).expect("exec");
    fact("environment.echo_stdout", format!("{:?}", String::from_utf8_lossy(&hello.stdout)));
    assert!(String::from_utf8_lossy(&hello.stdout).contains("sshelter-engine-ok"), "stdout was {:?}", hello.stdout);
    assert_eq!((hello.ended, hello.exit_code), (Ended::Exited, Some(0)));

    let exit = session.exec("exit 3", Duration::from_secs(60), 1 << 20).expect("exec");
    assert_eq!((exit.ended, exit.exit_code), (Ended::Exited, Some(3)), "the remote exit code must come back through the server too");
    assert!(session.is_alive());
}
