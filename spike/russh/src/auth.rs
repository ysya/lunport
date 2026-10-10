//! Password and keyboard-interactive login helpers.
//!
//! A scratch sshd cannot say yes to either (no PAM, so no password check for the user running the tests): only the refusal paths run
//! in `tests/auth_methods.rs`. The success paths of these helpers must be verified on a real host; the spike report says so.

use russh::client::{AuthResult, Handle, KeyboardInteractiveAuthResponse, Prompt};

use crate::client::SpikeHandler;

pub async fn login_password(handle: &mut Handle<SpikeHandler>, user: &str, password: &str) -> Result<AuthResult, russh::Error> {
    handle.authenticate_password(user, password).await
}

/// Keyboard-interactive: `answer(name, instructions, prompts)` returns one string per prompt, for as many rounds as the server asks.
/// `Ok(true)` when the server accepted, `Ok(false)` when it refused.
pub async fn login_keyboard_interactive(
    handle: &mut Handle<SpikeHandler>,
    user: &str,
    mut answer: impl FnMut(&str, &str, &[Prompt]) -> Vec<String>,
) -> Result<bool, russh::Error> {
    let mut response = handle.authenticate_keyboard_interactive_start(user, None::<String>).await?;
    loop {
        match response {
            KeyboardInteractiveAuthResponse::Success => return Ok(true),
            KeyboardInteractiveAuthResponse::Failure { .. } => return Ok(false),
            KeyboardInteractiveAuthResponse::InfoRequest { name, instructions, prompts } => {
                let answers = answer(&name, &instructions, &prompts);
                response = handle.authenticate_keyboard_interactive_respond(answers).await?;
            }
        }
    }
}
