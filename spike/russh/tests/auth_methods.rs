//! Task 3c, part 1: what a key-only server says to the other login methods. The success paths of password and keyboard-interactive need a
//! real host (a scratch sshd has no PAM): "verify on a real host" in the report. What runs here is the call sequence up to the server's
//! refusal, and the list of methods the refusal carries (the `tried` list of `ConnectError::AuthFailed`).

use russh::client::{AuthResult, Config, KeyboardInteractiveAuthResponse};
use russh::MethodKind;
use russh_spike::auth::{login_keyboard_interactive, login_password};
use russh_spike::client::{connect, HostKeyVerdict};
use russh_spike::fixture::Server;
use russh_spike::harness::tools;
use russh_spike::{fact, within};

async fn unauthenticated(server: &Server) -> russh_spike::client::Connection {
    within(30, "connect", connect(server.sshd.port, Config::default(), HostKeyVerdict::AcceptAny)).await.unwrap()
}

#[tokio::test(flavor = "multi_thread")]
async fn authenticate_none_lists_the_methods_the_server_offers() {
    let Some(tools) = tools() else { return };
    let server = Server::start(&tools, &[]);
    let mut connection = unauthenticated(&server).await;

    let result = within(20, "authenticate_none", connection.handle.authenticate_none(server.sshd.user.as_str())).await.unwrap();
    let AuthResult::Failure { remaining_methods, partial_success } = result else { panic!("a key-only server accepted `none`") };
    fact("auth.none.remaining_methods", format!("{remaining_methods:?}"));
    assert!(!partial_success);
    assert!(remaining_methods.contains(&MethodKind::PublicKey));
    assert!(!remaining_methods.contains(&MethodKind::Password));
    assert!(!remaining_methods.contains(&MethodKind::KeyboardInteractive));
}

#[tokio::test(flavor = "multi_thread")]
async fn a_password_is_refused_by_a_key_only_server_and_the_refusal_lists_what_remains() {
    let Some(tools) = tools() else { return };
    let server = Server::start(&tools, &[]);
    let mut connection = unauthenticated(&server).await;

    let result = within(20, "password login", login_password(&mut connection.handle, &server.sshd.user, "not-the-password")).await.unwrap();
    let AuthResult::Failure { remaining_methods, .. } = result else { panic!("the password was accepted") };
    fact("auth.password.remaining_methods", format!("{remaining_methods:?}"));
    assert!(remaining_methods.contains(&MethodKind::PublicKey));
}

#[tokio::test(flavor = "multi_thread")]
async fn keyboard_interactive_is_refused_by_a_key_only_server() {
    let Some(tools) = tools() else { return };
    let server = Server::start(&tools, &[]);
    let mut connection = unauthenticated(&server).await;

    let response = within(20, "keyboard-interactive start", connection.handle.authenticate_keyboard_interactive_start(server.sshd.user.as_str(), None::<String>))
        .await
        .unwrap();
    assert!(matches!(response, KeyboardInteractiveAuthResponse::Failure { .. }), "got {response:?}");

    // The helper that will drive the prompts on a real host agrees: refused, and it never asked a question.
    let mut connection = unauthenticated(&server).await;
    let mut asked = 0;
    let accepted = within(
        20,
        "keyboard-interactive login",
        login_keyboard_interactive(&mut connection.handle, &server.sshd.user, |_, _, _| {
            asked += 1;
            Vec::new()
        }),
    )
    .await
    .unwrap();
    assert!(!accepted);
    assert_eq!(asked, 0);
}
