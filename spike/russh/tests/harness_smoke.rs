//! Task 2, step 1: the scratch sshd works with the system ssh client, so a later failure is russh's or the vault's, not the harness's.

use russh_spike::harness::{generate_key, system_ssh, tools, KeyKind, Sshd, SshdOptions};

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
