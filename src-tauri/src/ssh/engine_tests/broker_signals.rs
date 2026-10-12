//! What the engine tells the broker besides a session or an error (plan 1b): whether a password typed now could still get in
//! (`ConnectError::AuthFailed::password_wanted`), the server's banner (`AuthSource::banner`), and why a shell was refused
//! (`Exit::Refused`).

use std::time::Duration;

use super::{engine, open_session, ShellProbe, SHELL_SERVER};
use crate::ssh::russh_engine::toy_server::{Refusal, ToyBehavior, ToyLogin, ToyServer};
use crate::ssh::russh_engine::{BANNER_CUT_NOTICE, MAX_BANNER_BYTES};
use crate::ssh::testing::doubles::{TestPolicy, VaultAuth};
use crate::ssh::testing::eventually;
use crate::ssh::testing::fixture::Server;
use crate::ssh::testing::harness::tools;
use crate::ssh::{AuthMethod, ConnectError, Exit, Hop, Pty, Session, SshEngine, Target};
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
/// now could get in, and the failure says so (the broker asks, then connects again with the same method order and the typed password
/// ready for `AuthSource::password`).
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

/// A hop that starts with keyboard-interactive has no password method in its sequence, so the source is never asked for one; when the
/// answers are wrong and the server offers the password method all the same, a typed password could get in.
#[test]
fn a_refused_keyboard_interactive_login_says_a_password_is_wanted_when_the_server_also_offers_one() {
    let (server, login) = toy();
    let auth = VaultAuth::new().with_answers(&["wrong"]);
    let error = engine().connect(&toy_target(&server, &login, AuthMethod::Interactive), &*TestPolicy::trusting(), &auth).err().expect("refused");
    assert!(
        matches!(&error, ConnectError::AuthFailed { tried, password_wanted: true, .. } if *tried == [AuthMethod::Interactive]),
        "{error:?}"
    );
    assert!(auth.password_asked_for().is_empty(), "a keyboard-interactive hop never reaches the password method, so the source is not asked");
}

/// A key that is not in the vault is skipped without a word to the server; the engine then asks the server what it offers (the `none`
/// method), finds the password method, and the source has no password to give. Nothing was tried, and a password could get in.
#[test]
fn a_key_missing_from_the_vault_and_no_password_to_give_says_a_password_is_wanted() {
    let Some(tools) = tools() else { return };
    // The scratch sshd offers publickey only (the harness turns the other methods off); here it is told to list the password method too.
    // No password is ever sent to it.
    let server = Server::start(&tools, &["PasswordAuthentication yes"]);
    let auth = VaultAuth::new();
    let error = engine().connect(&server.target("k1"), &*TestPolicy::trusting(), &auth).err().expect("nothing could be tried");
    match &error {
        ConnectError::AuthFailed { tried, reason, password_wanted, .. } => {
            assert!(tried.is_empty(), "nothing was tried: {error:?}");
            assert!(reason.contains("not available") && reason.contains("No password was given"), "{reason}");
            assert!(*password_wanted, "the list of the `none` probe has the password method, and none was tried");
        }
        other => panic!("expected AuthFailed, got {other:?}"),
    }
    assert_eq!(auth.calls_in_order(), vec!["public_key", "password"], "the key is not there, the password is asked for, there is no prompt to answer");
}

/// A server that wants the key first and the password next (`AuthenticationMethods publickey,password`): the first connect reports the
/// password as wanted, with the key already through; connecting again with the hop's own method order and the typed password at hand
/// sends the key and then the password, without waiting for anybody. A hop connected again with the password method first never offers
/// the key, so it cannot get in: that is why the order is not changed (the password the server finally refuses here is not a real one).
#[test]
fn a_server_that_wants_a_key_and_then_a_password_needs_the_hops_own_method_order() {
    let Some(tools) = tools() else { return };
    let server = Server::start(&tools, &["AuthenticationMethods publickey,password", "PasswordAuthentication yes", "PerSourcePenalties no"]);
    let key = AuthMethod::Key { key_id: "k1".to_string() };

    let first = server.vault("k1");
    let error = engine().connect(&server.target("k1"), &*TestPolicy::trusting(), &first).err().expect("the password is missing");
    assert!(
        matches!(&error, ConnectError::AuthFailed { tried, password_wanted: true, .. } if *tried == [key.clone()]),
        "the key went through and the password is wanted: {error:?}"
    );

    let again = server.vault("k1").with_password("typed by the person");
    let error = engine().connect(&server.target("k1"), &*TestPolicy::trusting(), &again).err().expect("the server refuses the password");
    assert!(
        matches!(&error, ConnectError::AuthFailed { tried, password_wanted: false, .. } if *tried == [key.clone(), AuthMethod::Password]),
        "the key and then the password were sent: {error:?}"
    );
    assert_eq!(again.calls_in_order(), vec!["public_key", "sign", "password"], "the password is asked for after the key, and answered from memory");

    let password_first = server.vault("k1").with_password("typed by the person");
    let hop = server.hop_with("server", server.sshd.port, AuthMethod::Password);
    let error = engine().connect(&Target { hops: vec![hop] }, &*TestPolicy::trusting(), &password_first).err().expect("the server wants the key first");
    assert!(matches!(&error, ConnectError::AuthFailed { tried, .. } if *tried == [AuthMethod::Password]), "{error:?}");
    assert!(password_first.sign_calls().is_empty(), "the key is not part of a password-first sequence");
}

/// A server that sends its banner before the first question: the engine hands the banner over before it puts the question to the auth
/// source, so that the person reads the server's notice before being asked for a password or a code.
#[test]
fn a_banner_sent_before_a_keyboard_interactive_prompt_is_handed_over_before_the_prompt() {
    let login = ToyLogin { user: "tester".to_string(), password: "correct horse battery staple".to_string(), prompt: "Password: ".to_string(), rounds: None };
    let server = ToyServer::start_with(login.clone(), ToyBehavior { banner: Some("Authorized use only.\n".to_string()), ..ToyBehavior::default() });
    let auth = VaultAuth::new().with_answers(&[&login.password]);
    let _session = engine().connect(&toy_target(&server, &login, AuthMethod::Interactive), &*TestPolicy::trusting(), &auth).expect("the login succeeds");
    assert_eq!(auth.calls_in_order(), vec!["banner", "interactive"], "the banner comes first");
    let banners = auth.banners();
    assert_eq!((banners.len(), banners[0].0.alias.as_str(), banners[0].1.as_str()), (1, "toy", "Authorized use only.\n"), "{banners:?}");
}

/// A server that sends far more banner than the engine keeps (here 222 KiB in one packet, which is under the 256 KiB russh accepts): the
/// auth source gets the first 64 KiB as the server wrote them and one line that says the rest was dropped, through the handler that takes
/// the banner as it arrives.
#[test]
fn a_banner_longer_than_the_cap_reaches_the_auth_source_cut_short() {
    let banner = "a banner line that the server repeats\n".repeat(6_000);
    assert!(banner.len() > 3 * MAX_BANNER_BYTES);
    let login = ToyLogin { user: "tester".to_string(), password: "correct horse battery staple".to_string(), prompt: "Password: ".to_string(), rounds: None };
    let server = ToyServer::start_with(login.clone(), ToyBehavior { banner: Some(banner.clone()), ..ToyBehavior::default() });
    let auth = VaultAuth::new().with_password(&login.password);
    let _session = engine().connect(&toy_target(&server, &login, AuthMethod::Password), &*TestPolicy::trusting(), &auth).expect("the login succeeds");
    let banners = auth.banners();
    assert_eq!(banners.len(), 1, "one delivery, at the end of the login");
    let text = &banners[0].1;
    // The cap falls inside a line, so a line break and the notice follow the 64 KiB.
    assert_eq!(text.len(), MAX_BANNER_BYTES + 1 + BANNER_CUT_NOTICE.len());
    assert!(text.starts_with(&banner[..MAX_BANNER_BYTES]), "the text before the cap is what the server sent");
    assert!(text.ends_with(&format!("\n{BANNER_CUT_NOTICE}")), "then the one line");
}

/// Logs in to a toy server that turns down `refusal`, opens a shell and waits until it has ended.
fn shell_refused_by_toy(refusal: Refusal) -> (ToyServer, Box<dyn Session>, ShellProbe) {
    let login = ToyLogin { user: "tester".to_string(), password: "correct horse battery staple".to_string(), prompt: "Password: ".to_string(), rounds: None };
    let server = ToyServer::start_with(login.clone(), ToyBehavior { refuses: Some(refusal), ..ToyBehavior::default() });
    let auth = VaultAuth::new().with_password(&login.password);
    let session = engine().connect(&toy_target(&server, &login, AuthMethod::Password), &*TestPolicy::trusting(), &auth).expect("the login succeeds");
    let probe = ShellProbe::start(session.shell(Pty { term: "xterm-256color".to_string(), cols: 80, rows: 24 }).expect("the requests go out"));
    eventually("the shell to end", 10, || probe.shell.exited().is_some());
    (server, session, probe)
}

/// The server accepts the terminal and refuses the shell: the shell ends as refused, with that reason, and the connection is still good
/// for the next channel.
#[test]
fn a_refused_shell_request_ends_the_shell_with_the_reason_and_the_connection_stays_up() {
    let (_server, session, probe) = shell_refused_by_toy(Refusal::Shell);
    assert_eq!(probe.shell.exited(), Some(Exit::Refused("the server refused to start a shell".to_string())));
    assert!(session.is_alive(), "only the shell was refused");
    let result = session.exec("true", Duration::from_secs(10), 1024).expect("the connection takes the next channel");
    assert_eq!(result.exit_code, Some(0));
}

/// The same for the terminal, on a server that is always there (the scratch sshd test above is skipped where OpenSSH is missing, and on
/// Windows always).
#[test]
fn a_refused_terminal_request_ends_the_shell_with_the_reason_on_the_toy_server_too() {
    let (_server, session, probe) = shell_refused_by_toy(Refusal::Pty);
    assert_eq!(probe.shell.exited(), Some(Exit::Refused("the server refused to allocate a terminal (PTY)".to_string())));
    assert!(session.is_alive(), "only the terminal was refused");
}
