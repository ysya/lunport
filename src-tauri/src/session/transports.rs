//! The app's commands for a host's transport (design 2026-10-25): save or remove the device-local record, and ask OS Login for the
//! username the editor fills in. Definitions are device-local; connections read them through `RecordDirectory`.

use std::sync::Arc;

use serde::Serialize;
use tauri::Manager;

use crate::gcp::auth::{self, FileStore};
use crate::gcp::rest::{GcpClient, RestClient};
use crate::state::AppState;
use crate::sync::record_commands::RecordOverview;
use crate::sync::transports::{self, HostTransport};

/// What the editor's **Use OS Login username** button learns: the account asked, its POSIX username (none when the project has no OS
/// Login account for it yet) and, for the host's key, whether OS Login already has it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[cfg_attr(test, derive(ts_rs::TS))]
#[cfg_attr(test, ts(export, export_to = "../../src/bindings/"))]
pub struct OsLoginProfileView {
    pub account: String,
    pub username: Option<String>,
    pub key_registered: Option<bool>,
}

/// The view for `account` on `project`; `label` is the account as shown (the email, resolved by the caller when `account` is `None`),
/// `public_key` the host's key as an OpenSSH line. Reads only: the first connection registers a missing key.
pub fn os_login_profile(gcp: &dyn GcpClient, label: &str, account: Option<&str>, project: &str, public_key: Option<&str>) -> Result<OsLoginProfileView, String> {
    let profile = gcp.login_profile(account, project).map_err(|error| error.to_string())?;
    Ok(OsLoginProfileView {
        account: label.to_string(),
        username: profile.username().map(str::to_string),
        key_registered: public_key.map(|line| profile.has_key(line)),
    })
}

fn main_only(window: &tauri::WebviewWindow) -> Result<(), String> {
    if window.label() == "main" {
        Ok(())
    } else {
        Err("Transport settings are available in the main window only.".into())
    }
}

/// Saves (`Some`) or removes (`None`) a host's transport against the value the editor displayed.
fn edit(app: &tauri::AppHandle, host_id: &str, expected: Option<HostTransport>, transport: Option<HostTransport>) -> Result<RecordOverview, String> {
    crate::sync::engine::with_env(app, |env| {
        crate::sync::record_commands::edit_records(env, |state, now| {
            transports::set(state, host_id, expected.as_ref(), transport.clone(), now).map_err(|error| crate::error::AppError::Other(error.to_string()))
        })
    })
    .map_err(|error| error.to_string())?
    .map_err(|error| error.to_string())
}

/// The vault key's OpenSSH public line, as the broker's key store reads it (Records workspace only).
fn vault_public_line(app: &tauri::AppHandle, key_id: &str) -> Option<String> {
    let state = app.state::<AppState>();
    let core = state.sync.core.lock().unwrap();
    let key = crate::sync::record_repository::resolve_key(core.records.as_ref()?, key_id).ok()?;
    key.public.map(|public| public.public_key)
}

/// gcloud's active account, for the view's label when the transport names none.
fn active_account_label() -> String {
    let dir = auth::config_dir(&|name| std::env::var(name).ok(), dirs::home_dir().as_deref(), cfg!(windows));
    auth::active_account(&dir).unwrap_or_else(|| "the active gcloud account".to_string())
}

#[tauri::command]
pub async fn transports_save(app: tauri::AppHandle, window: tauri::WebviewWindow, transport: HostTransport, expected: Option<HostTransport>) -> Result<RecordOverview, String> {
    main_only(&window)?;
    tauri::async_runtime::spawn_blocking(move || edit(&app, &transport.host_id.clone(), expected, Some(transport))).await.map_err(|error| error.to_string())?
}

#[tauri::command]
pub async fn transports_delete(app: tauri::AppHandle, window: tauri::WebviewWindow, expected: HostTransport) -> Result<RecordOverview, String> {
    main_only(&window)?;
    tauri::async_runtime::spawn_blocking(move || edit(&app, &expected.host_id.clone(), Some(expected), None)).await.map_err(|error| error.to_string())?
}

#[tauri::command]
pub async fn transports_oslogin_profile(
    app: tauri::AppHandle,
    window: tauri::WebviewWindow,
    account: Option<String>,
    project: String,
    key_id: Option<String>,
) -> Result<OsLoginProfileView, String> {
    main_only(&window)?;
    if project.is_empty() || !project.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-') {
        return Err("Enter the Google Cloud project id.".into());
    }
    let account = account.filter(|account| !account.trim().is_empty());
    // The account names a directory under gcloud's config: the same rule as a saved transport, before it reaches a path.
    if account.as_deref().is_some_and(|account| !crate::sync::transports::is_email(account)) {
        return Err("Enter the Google account as an email address.".into());
    }
    tauri::async_runtime::spawn_blocking(move || {
        let public_key = key_id.as_deref().and_then(|id| vault_public_line(&app, id));
        let label = account.clone().unwrap_or_else(active_account_label);
        let gcp = RestClient::new(Arc::new(FileStore::from_environment()));
        os_login_profile(&gcp, &label, account.as_deref(), &project, public_key.as_deref())
    })
    .await
    .map_err(|error| error.to_string())?
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gcp::oslogin::{LoginProfile, PosixAccount};
    use crate::gcp::pam::Grant;
    use crate::gcp::rest::{GcpClient, GcpError};
    use crate::sync::record_commands;
    use crate::sync::records_v3::SyncStateV3;
    use crate::sync::transports::{self, HostTransport, TransportKind};
    use serde_json::json;

    const HOST: &str = "0000000000000001";
    const KEY_LINE: &str = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGvBwpCj0GQWLW0hG8bQ4qJ8r7ZcXx9x2nH0f0e3Q1aB";

    fn state() -> SyncStateV3 {
        serde_json::from_value(json!({"version":4,"device_id":"dddddddddddddddddddddddddddddddd","device_name":"fixture","relay_url":"http://127.0.0.1","last_sync_ms":null,"last_error":null})).unwrap()
    }

    fn iap() -> HostTransport {
        HostTransport {
            host_id: HOST.into(),
            kind: TransportKind::GcpIap {
                project: "eng-dev-396409".into(),
                zone: "asia-east1-b".into(),
                instance: "jumpbox".into(),
                interface: "nic0".into(),
                account: None,
                os_login: false,
                pam: None,
            },
        }
    }

    struct Profile(LoginProfile);

    impl GcpClient for Profile {
        fn login_profile(&self, _: Option<&str>, _: &str) -> Result<LoginProfile, GcpError> {
            Ok(self.0.clone())
        }
        fn import_ssh_public_key(&self, _: Option<&str>, _: &str, _: &str) -> Result<LoginProfile, GcpError> {
            panic!("the editor's lookup never imports")
        }
        fn grants(&self, _: Option<&str>, _: &str, _: &str, _: &str) -> Result<Vec<Grant>, GcpError> {
            panic!("the editor's lookup never searches grants")
        }
        fn create_grant(&self, _: Option<&str>, _: &str, _: &str, _: &str, _: u32, _: &str) -> Result<Grant, GcpError> {
            panic!("the editor's lookup never requests grants")
        }
        fn get_grant(&self, _: Option<&str>, _: &str) -> Result<Grant, GcpError> {
            panic!("the editor's lookup never reads grants")
        }
    }

    #[test]
    fn the_record_overview_carries_the_saved_transports() {
        let saved = transports::set(&state(), HOST, None, Some(iap()), 1).unwrap();
        let overview = serde_json::to_value(record_commands::overview_from(&saved, 1, None).unwrap()).unwrap();
        assert_eq!(overview["transports"], json!([iap()]));
        let removed = transports::set(&saved, HOST, Some(&iap()), None, 2).unwrap();
        let overview = serde_json::to_value(record_commands::overview_from(&removed, 1, None).unwrap()).unwrap();
        assert_eq!(overview["transports"], json!([]));
    }

    #[test]
    fn the_profile_view_reports_the_username_and_whether_the_key_is_registered() {
        let profile = LoginProfile {
            posix_accounts: vec![PosixAccount { username: "frank_retower_io".into(), primary: true, operating_system_type: Some("LINUX".into()) }],
            ssh_public_keys: vec![format!("{KEY_LINE} frank@retower.pub")],
        };
        let view = os_login_profile(&Profile(profile.clone()), "frank@retower.io", Some("frank@retower.io"), "eng-dev-396409", Some(KEY_LINE)).unwrap();
        assert_eq!(
            serde_json::to_value(&view).unwrap(),
            json!({"account": "frank@retower.io", "username": "frank_retower_io", "key_registered": true})
        );
        let view = os_login_profile(&Profile(profile.clone()), "frank@retower.io", Some("frank@retower.io"), "eng-dev-396409", None).unwrap();
        assert_eq!(view.key_registered, None, "without a key there is nothing to check");
        let other_key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOtherBlobOtherBlobOtherBlobOtherBlobOtherBlob";
        let view = os_login_profile(&Profile(profile), "frank@retower.io", Some("frank@retower.io"), "eng-dev-396409", Some(other_key)).unwrap();
        assert_eq!(view.key_registered, Some(false));
        let empty = os_login_profile(&Profile(LoginProfile::default()), "frank@retower.io", None, "eng-dev-396409", None).unwrap();
        assert_eq!((empty.username, empty.account.as_str()), (None, "frank@retower.io"));
    }
}
