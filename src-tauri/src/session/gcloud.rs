//! The Google Cloud page's account actions (design 2026-10-27, The Accounts tab): sign an account in again, add one, make one gcloud's
//! active account, remove one. Each runs gcloud itself (`gcp::cli`), since each changes gcloud's own state for every tool on this computer;
//! the page asks the person first, in words that say so. Every account named is an email address (`transports::is_email`), checked here
//! before gcloud starts, and gcloud gets it as an argument of its own. One action runs at a time, bounded and cancellable.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use tauri::{Emitter, Manager};

use crate::gcp::{auth, cli};
use crate::state::AppState;
use crate::sync::transports;

/// The event that carries the sign-in page's address to the main window while gcloud waits for the browser.
pub const SIGN_IN_URL_EVENT: &str = "gcp://sign-in-url";

/// What the person asked gcloud to do.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
#[cfg_attr(test, derive(ts_rs::TS))]
#[cfg_attr(test, ts(export, export_to = "../../src/bindings/", tag = "kind", rename_all = "snake_case"))]
pub enum AccountAction {
    /// Sign `account` in again, in the browser, whatever gcloud holds for it, without making it the active account.
    SignIn { account: String },
    /// Sign a new account in, in the browser, without making it the active account.
    Add,
    /// Make `account` gcloud's active account (in its active configuration).
    Activate { account: String },
    /// Revoke `account`'s sign-in at Google and remove its credentials from this computer.
    Remove { account: String },
}

impl AccountAction {
    /// The account the action names, if it names one.
    pub fn account(&self) -> Option<&str> {
        match self {
            AccountAction::SignIn { account } | AccountAction::Activate { account } | AccountAction::Remove { account } => Some(account),
            AccountAction::Add => None,
        }
    }

    /// gcloud's arguments for the action, or the sentence why there are none: an account that is not an email address never reaches
    /// gcloud.
    pub fn args(&self) -> Result<Vec<String>, String> {
        if self.account().is_some_and(|account| !transports::is_email(account)) {
            return Err("Enter the Google account as an email address.".into());
        }
        let args: Vec<&str> = match self {
            AccountAction::SignIn { account } => vec!["auth", "login", account, "--force", "--no-activate", "--brief"],
            AccountAction::Add => vec!["auth", "login", "--no-activate", "--brief"],
            AccountAction::Activate { account } => vec!["config", "set", "account", account],
            AccountAction::Remove { account } => vec!["auth", "revoke", account],
        };
        Ok(args.into_iter().map(str::to_string).collect())
    }

    /// How long gcloud may take: a sign-in waits for the person in the browser.
    pub fn bound(&self) -> Duration {
        match self {
            AccountAction::SignIn { .. } | AccountAction::Add => Duration::from_secs(5 * 60),
            AccountAction::Activate { .. } => Duration::from_secs(30),
            AccountAction::Remove { .. } => Duration::from_secs(60),
        }
    }

    /// What "gcloud could not …" says the action was.
    fn verb(&self) -> String {
        match self {
            AccountAction::SignIn { .. } | AccountAction::Add => "sign in".into(),
            AccountAction::Activate { .. } => "change its active account".into(),
            AccountAction::Remove { account } => format!("remove {account}"),
        }
    }
}

/// How an action ended well: the account it was about (for Add, the one that signed in, when Lunport could tell) and the sentence.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[cfg_attr(test, derive(ts_rs::TS))]
#[cfg_attr(test, ts(export, export_to = "../../src/bindings/"))]
pub struct AccountActionView {
    pub account: Option<String>,
    pub message: String,
}

/// Where gcloud is on this computer, as the Accounts tab says it: its path, or none.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[cfg_attr(test, derive(ts_rs::TS))]
#[cfg_attr(test, ts(export, export_to = "../../src/bindings/"))]
pub struct GcloudCliView {
    pub path: Option<String>,
}

/// What the Accounts tab says when gcloud is nowhere Lunport looks.
pub const NOT_FOUND: &str = "Lunport could not find gcloud on this computer. Install the Google Cloud CLI, then press Check again.";

/// The accounts gcloud holds credentials for in `dir`, as the page lists them: email addresses only.
fn listed_accounts(dir: &Path) -> Vec<String> {
    auth::credentialed_accounts(dir).into_iter().filter(|name| transports::is_email(name)).collect()
}

/// The account gcloud said it signed in, from its "You are now logged in as [frank@example.com]." line.
pub fn logged_in_as(stderr: &str) -> Option<String> {
    let rest = stderr.split("You are now logged in as [").nth(1)?;
    let account = rest.split(']').next()?;
    transports::is_email(account).then(|| account.to_string())
}

/// The sentence of an action that went well, and the account it was about. For Add that is the account gcloud now holds that it did
/// not hold `before`, else the one gcloud's own line names.
pub fn finished(action: &AccountAction, before: &[String], after: &[String], stderr: &str) -> AccountActionView {
    match action {
        AccountAction::SignIn { account } => AccountActionView { account: Some(account.clone()), message: format!("Signed in as {account}.") },
        AccountAction::Add => {
            let account = after.iter().find(|name| !before.contains(name)).cloned().or_else(|| logged_in_as(stderr));
            let message = account.as_ref().map_or_else(|| "Signed in.".to_string(), |account| format!("Signed in as {account}."));
            AccountActionView { account, message }
        }
        AccountAction::Activate { account } => AccountActionView { account: Some(account.clone()), message: format!("gcloud now uses {account}.") },
        AccountAction::Remove { account } => AccountActionView { account: Some(account.clone()), message: format!("Removed {account} from gcloud on this computer.") },
    }
}

/// Runs `action` with the gcloud at `path` over gcloud's directory `dir`, handing each sign-in page address gcloud prints to
/// `on_url`, and then has `tokens` forget what it cached: gcloud's credentials changed under it. Blocks.
pub fn perform(action: &AccountAction, path: PathBuf, dir: &Path, tokens: &dyn auth::TokenSource, cancel: &AtomicBool, on_url: &mut dyn FnMut(String)) -> Result<AccountActionView, String> {
    let args = action.args()?;
    let before = listed_accounts(dir);
    let run = cli::Run { path, args, bound: action.bound() };
    let output = cli::run(&run, cancel, &mut |line| {
        if let Some(url) = cli::sign_in_url(line) {
            on_url(url);
        }
    });
    tokens.forget();
    let output = output.map_err(|error| error.sentence(&action.verb()))?;
    Ok(finished(action, &before, &listed_accounts(dir), &output.stderr))
}

/// The cancel flag of the action running now, for `gcp_account_cancel`.
static RUNNING: Mutex<Option<Arc<AtomicBool>>> = Mutex::new(None);

fn main_only(window: &tauri::WebviewWindow) -> Result<(), String> {
    if window.label() == "main" {
        Ok(())
    } else {
        Err("Google Cloud settings are available in the main window only.".into())
    }
}

/// Where gcloud is on this computer (`cli::locate`, found once for the app's run).
#[tauri::command]
pub async fn gcp_cli_status(window: tauri::WebviewWindow) -> Result<GcloudCliView, String> {
    main_only(&window)?;
    let path = tauri::async_runtime::spawn_blocking(cli::locate).await.map_err(|error| error.to_string())?;
    Ok(GcloudCliView { path: path.map(|path| path.display().to_string()) })
}

/// Looks for gcloud again (the Accounts tab's **Check again**).
#[tauri::command]
pub async fn gcp_cli_locate_again(window: tauri::WebviewWindow) -> Result<GcloudCliView, String> {
    main_only(&window)?;
    cli::relocate();
    gcp_cli_status(window).await
}

/// Runs one account action (design 2026-10-27, The Accounts tab) and answers how it ended. The page confirmed it with the person first.
/// While gcloud waits for the browser, each sign-in page address it prints goes to the main window as `SIGN_IN_URL_EVENT`.
#[tauri::command]
pub async fn gcp_account_action(app: tauri::AppHandle, window: tauri::WebviewWindow, action: AccountAction) -> Result<AccountActionView, String> {
    main_only(&window)?;
    action.args()?;
    tauri::async_runtime::spawn_blocking(move || {
        let path = cli::locate().ok_or(NOT_FOUND)?;
        let tokens = app.state::<AppState>().gcp.tokens();
        let cancel = Arc::new(AtomicBool::new(false));
        *RUNNING.lock().unwrap_or_else(PoisonError::into_inner) = Some(Arc::clone(&cancel));
        let dir = auth::config_dir(&|name| std::env::var(name).ok(), dirs::home_dir().as_deref(), cfg!(windows));
        let outcome = perform(&action, path, &dir, &*tokens, &cancel, &mut |url| {
            let _ = app.emit_to("main", SIGN_IN_URL_EVENT, url);
        });
        RUNNING.lock().unwrap_or_else(PoisonError::into_inner).take();
        outcome
    })
    .await
    .map_err(|error| error.to_string())?
}

/// Stops the account action running now, if one is (the sign-in dialog's **Cancel**).
#[tauri::command]
pub fn gcp_account_cancel(window: tauri::WebviewWindow) -> Result<(), String> {
    main_only(&window)?;
    if let Some(cancel) = RUNNING.lock().unwrap_or_else(PoisonError::into_inner).as_ref() {
        cancel.store(true, Ordering::Release);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gcp::auth::{AuthError, Token, TokenSource};
    use std::sync::atomic::AtomicUsize;

    fn action(kind: &str, account: Option<&str>) -> AccountAction {
        let mut value = serde_json::json!({ "kind": kind });
        if let Some(account) = account {
            value["account"] = account.into();
        }
        serde_json::from_value(value).unwrap()
    }

    #[test]
    fn each_action_has_gclouds_arguments_and_never_switches_the_active_account_by_signing_in() {
        let frank = Some("frank@example.com");
        assert_eq!(action("sign_in", frank).args().unwrap(), ["auth", "login", "frank@example.com", "--force", "--no-activate", "--brief"]);
        assert_eq!(action("add", None).args().unwrap(), ["auth", "login", "--no-activate", "--brief"]);
        assert_eq!(action("activate", frank).args().unwrap(), ["config", "set", "account", "frank@example.com"]);
        assert_eq!(action("remove", frank).args().unwrap(), ["auth", "revoke", "frank@example.com"]);
        assert_eq!(action("sign_in", frank).bound(), Duration::from_secs(300));
    }

    #[test]
    fn an_account_that_is_not_an_email_address_never_reaches_gcloud() {
        for account in ["--all", "frank@example.com --all", "frank", "a;b@example.com", ""] {
            assert!(action("remove", Some(account)).args().is_err(), "{account:?}");
        }
        assert!(serde_json::from_value::<AccountAction>(serde_json::json!({ "kind": "remove", "account": "a@example.com", "extra": 1 })).is_err());
    }

    #[test]
    fn the_new_account_is_the_one_gcloud_holds_now_else_the_one_it_names() {
        let before = vec!["frank@example.com".to_string()];
        let after = vec!["frank@example.com".to_string(), "ops@example.com".to_string()];
        assert_eq!(finished(&AccountAction::Add, &before, &after, "").account.as_deref(), Some("ops@example.com"));
        let again = finished(&AccountAction::Add, &after, &after, "\nYou are now logged in as [ops@example.com].\n");
        assert_eq!((again.account.as_deref(), again.message.as_str()), (Some("ops@example.com"), "Signed in as ops@example.com."));
        assert_eq!(finished(&AccountAction::Add, &after, &after, "").message, "Signed in.");
        assert_eq!(finished(&action("remove", Some("ops@example.com")), &after, &before, "").message, "Removed ops@example.com from gcloud on this computer.");
    }

    struct Counting(AtomicUsize);

    impl TokenSource for Counting {
        fn access_token(&self, _account: Option<&str>) -> Result<Token, AuthError> {
            Err(AuthError::Network("unused".into()))
        }
        fn forget(&self) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }

    #[cfg(unix)]
    fn fake_gcloud(dir: &Path, body: &str) -> PathBuf {
        use std::os::unix::fs::PermissionsExt;
        let path = dir.join("gcloud");
        std::fs::write(&path, format!("#!/bin/sh\n{body}\n")).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
        path
    }

    use crate::gcp::cli::TEST_RUNS as SERIAL;

    #[cfg(unix)]
    #[test]
    fn an_add_runs_gcloud_streams_the_sign_in_page_and_finds_the_new_account() {
        let _serial = SERIAL.lock().unwrap_or_else(PoisonError::into_inner);
        let root = tempfile::tempdir().unwrap();
        let config = root.path().join("config");
        std::fs::create_dir_all(&config).unwrap();
        let adc = r#"{"type":"authorized_user","client_id":"c","client_secret":"s","refresh_token":"r","account":"ops@example.com"}"#;
        let gcloud = fake_gcloud(
            root.path(),
            &format!(
                "echo 'Your browser has been opened to visit:' >&2; echo '    https://accounts.google.com/o/oauth2/auth?state=1' >&2; mkdir -p '{dir}/legacy_credentials/ops@example.com'; echo '{adc}' > '{dir}/legacy_credentials/ops@example.com/adc.json'",
                dir = config.display()
            ),
        );
        let tokens = Counting(AtomicUsize::new(0));
        let mut urls = vec![];
        let view = perform(&AccountAction::Add, gcloud, &config, &tokens, &AtomicBool::new(false), &mut |url| urls.push(url)).unwrap();
        assert_eq!(view.account.as_deref(), Some("ops@example.com"));
        assert_eq!(urls, ["https://accounts.google.com/o/oauth2/auth?state=1"]);
        assert_eq!(tokens.0.load(Ordering::SeqCst), 1, "the token cache is dropped");
    }

    #[cfg(unix)]
    #[test]
    fn a_failed_removal_says_gclouds_error_and_still_drops_the_token_cache() {
        let _serial = SERIAL.lock().unwrap_or_else(PoisonError::into_inner);
        let root = tempfile::tempdir().unwrap();
        let gcloud = fake_gcloud(root.path(), "echo 'ERROR: (gcloud.auth.revoke) Could not revoke.' >&2; exit 1");
        let tokens = Counting(AtomicUsize::new(0));
        let error = perform(&action("remove", Some("frank@example.com")), gcloud, root.path(), &tokens, &AtomicBool::new(false), &mut |_| {}).unwrap_err();
        assert_eq!(error, "gcloud could not remove frank@example.com: (gcloud.auth.revoke) Could not revoke.");
        assert_eq!(tokens.0.load(Ordering::SeqCst), 1);
    }
}
