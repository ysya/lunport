//! What the engine tells the broker besides a session or an error (plan 1b): whether a password typed now could still get in
//! (`ConnectError::AuthFailed::password_wanted`), the server's banner (`AuthSource::banner`), and why a shell was refused
//! (`Exit::Refused`).

use super::{engine, open_session, ShellProbe, SHELL_SERVER};
use crate::ssh::russh_engine::toy_server::{ToyLogin, ToyServer};
use crate::ssh::testing::doubles::{TestPolicy, VaultAuth};
use crate::ssh::testing::eventually;
use crate::ssh::testing::fixture::Server;
use crate::ssh::testing::harness::tools;
use crate::ssh::{AuthMethod, ConnectError, Exit, Hop, Pty, SshEngine, Target};
use crate::sync::slot_rules::test_keys;

/// The in-process server: it refuses every key and offers password and keyboard-interactive.
fn toy() -> (ToyServer, ToyLogin) {
    let login = ToyLogin { user: "tester".to_string(), password: "correct horse battery staple".to_string(), prompt: "Password: ".to_string(), rounds: None };
    (ToyServer::start(login.clone()), login)
}

fn toy_target(server: &ToyServer, login: &ToyLogin, auth: AuthMethod) -> Target {
    Target { hops: vec![Hop::new("host-toy", "toy", "127.0.0.1", server.port, &login.user, auth)] }
}

/// The key is refused and the auth source has no password, but the server offers the password method: a password the person types
/// now could get in, and the failure says so (the broker asks and connects again with the password first).
#[test]
fn a_refused_key_with_no_password_to_give_says_a_password_is_wanted() {
    let (server, login) = toy();
    // Keyboard-interactive gets a wrong answer, so the login ends refused (`AuthFailed`) rather than abandoned.
    let auth = VaultAuth::new().with_key("k1", &test_keys::plain()).with_answers(&["wrong"]);
    let target = toy_target(&server, &login, AuthMethod::Key { key_id: "k1".to_string() });
    match engine().connect(&target, &*TestPolicy::trusting(), &auth).err().expect("the login fails") {
        ConnectError::AuthFailed { tried, password_wanted, .. } => {
            assert_eq!(tried, vec![AuthMethod::Key { key_id: "k1".to_string() }, AuthMethod::Interactive]);
            assert!(password_wanted, "the server offers password and none was tried");
        }
        other => panic!("expected AuthFailed, got {other:?}"),
    }
    assert_eq!(auth.password_asked_for().len(), 1, "the source was asked during the login and had nothing");
}

/// A password that was tried and refused is not reported as wanted: whether to ask the person for another one is the broker's call,
/// made from `tried`.
#[test]
fn a_password_that_was_tried_is_not_reported_as_wanted() {
    let (server, login) = toy();
    let auth = VaultAuth::new().with_password("wrong").with_answers(&["also wrong"]);
    let error = engine().connect(&toy_target(&server, &login, AuthMethod::Password), &*TestPolicy::trusting(), &auth).err().expect("refused");
    assert!(
        matches!(&error, ConnectError::AuthFailed { tried, password_wanted: false, .. } if *tried == [AuthMethod::Password, AuthMethod::Interactive]),
        "{error:?}"
    );
}

/// A server that does not offer the password method never wants one, and the auth source is not even asked.
#[test]
fn a_server_without_the_password_method_never_wants_a_password() {
    let Some(tools) = tools() else { return };
    let server = Server::start(&tools, &[]);
    // The vault holds a key the server does not know: sshd accepts only its own fresh user key.
    let auth = VaultAuth::new().with_key("other", &test_keys::plain());
    let error = engine().connect(&Target { hops: vec![server.hop("server", "other")] }, &*TestPolicy::trusting(), &auth).err().expect("refused");
    assert!(matches!(&error, ConnectError::AuthFailed { password_wanted: false, .. }), "{error:?}");
    assert!(auth.password_asked_for().is_empty(), "the server does not offer the method, so the source is not asked");
}

/// The text of the server's banner (sshd's `Banner`) reaches the auth source, as OpenSSH shows it to the user.
#[test]
fn the_servers_banner_reaches_the_auth_source() {
    let Some(tools) = tools() else { return };
    let dir = tempfile::tempdir().expect("temp dir for the banner");
    let banner = dir.path().join("banner");
    std::fs::write(&banner, "Authorized use only.\nActivity is logged.\n").expect("write the banner");
    let server = Server::start(&tools, &[&format!("Banner {}", banner.display())]);
    let auth = server.vault("k1");
    let _session = engine().connect(&server.target("k1"), &*TestPolicy::trusting(), &auth).expect("the engine connects");
    let banners = auth.banners();
    assert_eq!(banners.len(), 1, "{banners:?}");
    assert_eq!((banners[0].0.alias.as_str(), banners[0].1.as_str()), ("server", "Authorized use only.\nActivity is logged.\n"));
}

/// A server that allows no terminal (`PermitTTY no`) refuses the PTY request: the shell ends at once with that reason instead of a bare
/// "disconnected", and the connection stays up.
#[test]
fn a_refused_terminal_ends_the_shell_with_the_reason_and_the_connection_stays_up() {
    let Some(tools) = tools() else { return };
    let mut config = vec!["PermitTTY no"];
    config.extend_from_slice(SHELL_SERVER);
    let server = Server::start(&tools, &config);
    let session = open_session(&engine(), &server);
    let probe = ShellProbe::start(session.shell(Pty { term: "xterm-256color".to_string(), cols: 80, rows: 24 }).expect("the requests go out"));
    eventually("the shell to end", 10, || probe.shell.exited().is_some());
    assert_eq!(probe.shell.exited(), Some(Exit::Refused("the server refused to allocate a terminal (PTY)".to_string())));
    assert!(session.is_alive(), "only the shell was refused");
}
