//! Asking the person at this computer to confirm what Lunport is about to do: on macOS with Touch ID or the Mac's password, through
//! LocalAuthentication (`os_auth.m`). Other systems have no such question here; the page asks in a dialog of its own instead.

use serde::Serialize;

/// How the person confirms that prod writes may be unlocked.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[cfg_attr(test, derive(ts_rs::TS))]
#[cfg_attr(test, ts(export, export_to = "../../src/bindings/"))]
#[serde(rename_all = "snake_case")]
pub enum UnlockMethod {
    /// The system asks: Touch ID, or the Mac's password.
    System,
    /// The page asks in a dialog of Lunport's own.
    Dialog,
}

/// What `confirm` answers where the system cannot ask.
const UNAVAILABLE: &str = "Touch ID is not available.";

/// How this computer confirms an unlock: `System` where the system can ask for Touch ID or the Mac's password, else `Dialog`.
pub fn unlock_method() -> UnlockMethod {
    if system::available() {
        UnlockMethod::System
    } else {
        UnlockMethod::Dialog
    }
}

/// Asks the person to confirm with Touch ID or the Mac's password; the system shows "<app> is trying to {reason}." It blocks until the
/// person answers, for 120 seconds at most, so it runs on a blocking thread, never on the main thread or the async runtime. A refusal, a
/// cancel and no answer in time are `Ok(false)`; a computer where the system cannot ask is an error.
pub fn confirm(reason: &str) -> Result<bool, String> {
    answer(system::confirm(reason))
}

/// What the system's answer means: 1 allowed, 0 refused or cancelled, anything else not available.
fn answer(code: i32) -> Result<bool, String> {
    match code {
        1 => Ok(true),
        0 => Ok(false),
        _ => Err(UNAVAILABLE.to_string()),
    }
}

#[cfg(target_os = "macos")]
mod system {
    use std::ffi::{c_char, c_int, CString};

    // os_auth.m: 1 allowed (or able to ask), 0 refused or cancelled (or unable to ask), -1 unavailable.
    extern "C" {
        fn os_auth_available() -> c_int;
        fn os_auth_confirm(reason: *const c_char) -> c_int;
    }

    pub(super) fn available() -> bool {
        // SAFETY: it takes nothing, and only asks LocalAuthentication whether the policy can be evaluated.
        unsafe { os_auth_available() == 1 }
    }

    pub(super) fn confirm(reason: &str) -> i32 {
        let reason = CString::new(reason.replace('\0', "?")).expect("no NUL is left");
        // SAFETY: `reason` is a NUL-terminated string that outlives the call, and the shim copies it before it returns.
        unsafe { os_auth_confirm(reason.as_ptr()) }
    }
}

/// Where Lunport has no system question to ask: nothing can be confirmed.
#[cfg(not(target_os = "macos"))]
mod system {
    pub(super) fn available() -> bool {
        false
    }

    pub(super) fn confirm(_reason: &str) -> i32 {
        -1
    }
}

/// How this computer confirms an unlock, for the page: whether it asks the system, or shows its own dialog first.
#[tauri::command]
pub async fn os_unlock_method(window: tauri::WebviewWindow) -> Result<UnlockMethod, String> {
    crate::session::tunnels::main_only(&window, "Database")?;
    tauri::async_runtime::spawn_blocking(unlock_method).await.map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_systems_answers_read_as_allowed_refused_or_not_available() {
        assert_eq!(answer(1), Ok(true));
        assert_eq!(answer(0), Ok(false));
        assert_eq!(answer(-1), Err("Touch ID is not available.".to_string()));
        assert_eq!(answer(7), Err("Touch ID is not available.".to_string()), "an answer the shim never gives");
    }

    #[test]
    fn unlock_methods_are_written_in_snake_case() {
        assert_eq!(serde_json::to_value(UnlockMethod::System).unwrap(), serde_json::json!("system"));
        assert_eq!(serde_json::to_value(UnlockMethod::Dialog).unwrap(), serde_json::json!("dialog"));
    }

    /// A smoke test: it only proves that the shim links and that asking the Mac whether it can ask brings up no prompt. Which answer the
    /// Mac gives depends on the Mac, so it is not checked. (`confirm` is never called here, since it would ask.)
    #[cfg(target_os = "macos")]
    #[test]
    fn the_mac_tells_whether_it_can_ask_without_asking() {
        let _ = unlock_method();
    }

    #[cfg(not(target_os = "macos"))]
    #[test]
    fn other_systems_confirm_in_lunports_dialog() {
        assert_eq!(unlock_method(), UnlockMethod::Dialog);
        assert_eq!(confirm("unlock writes on Orders (PROD) for 15 minutes"), Err("Touch ID is not available.".to_string()));
    }
}
