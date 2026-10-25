//! The app's commands for a host's transport (design 2026-10-25): save or remove the device-local record, ask OS Login for the
//! username the editor fills in, and show or request the Privileged Access Manager grant a transport needs (design 2026-10-25, PAM
//! grant requests). Definitions are device-local; connections read them through `RecordDirectory`.

use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::Serialize;
use tauri::Manager;

use crate::gcp::auth::{self, FileStore};
use crate::gcp::pam;
use crate::gcp::rest::{GcpClient, RestClient};
use crate::state::AppState;
use crate::sync::record_commands::RecordOverview;
use crate::sync::transports::{self, HostTransport, TransportKind};

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

/// What the Google Cloud panel shows of a transport's Privileged Access Manager grant: `active` (which entitlement, until when),
/// `activating` (which entitlement), `none`, or `error` (the API's sentence).
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[cfg_attr(test, derive(ts_rs::TS))]
#[cfg_attr(test, ts(export, export_to = "../../src/bindings/"))]
pub struct PamStatusView {
    pub entitlement: Option<String>,
    pub state: String,
    #[cfg_attr(test, ts(type = "number | null"))]
    pub active_until_ms: Option<u64>,
    pub message: Option<String>,
}

impl PamStatusView {
    fn none() -> PamStatusView {
        PamStatusView { entitlement: None, state: "none".into(), active_until_ms: None, message: None }
    }
}

fn epoch_ms(time: SystemTime) -> u64 {
    time.duration_since(UNIX_EPOCH).unwrap_or_default().as_millis() as u64
}

/// The grant state of `transport`, over every entitlement it lists: a connection passes while any holds a grant, so the entitlement whose
/// grant lasts longest is named, with its end; else one that is activating; else none, or the API's sentence when a search failed and
/// no entitlement answered with a grant.
pub fn pam_status(gcp: &dyn GcpClient, transport: &HostTransport) -> PamStatusView {
    let TransportKind::GcpIap { project, account, pam, .. } = &transport.kind;
    let Some(pam) = pam else { return PamStatusView::none() };
    let now = SystemTime::now();
    // The longest-lasting active grant (an ACTIVE grant PAM did not date counts, below every dated one), the first activating one, the
    // first refusal.
    let mut active: Option<(String, Option<SystemTime>)> = None;
    let mut activating: Option<String> = None;
    let mut refused: Option<String> = None;
    for entitlement in &pam.entitlements {
        match gcp.grants(account.as_deref(), project, &pam.location, entitlement) {
            Ok(grants) => {
                for grant in pam::in_flight(&grants) {
                    if grant.state == "ACTIVE" {
                        let until = grant.until();
                        if until.is_some_and(|until| until <= now) {
                            continue;
                        }
                        if active.as_ref().is_none_or(|(_, best)| until > *best) {
                            active = Some((entitlement.clone(), until));
                        }
                    } else if activating.is_none() {
                        activating = Some(entitlement.clone());
                    }
                }
            }
            Err(error) => {
                refused.get_or_insert_with(|| error.to_string());
            }
        }
    }
    if let Some((entitlement, until)) = active {
        return PamStatusView { entitlement: Some(entitlement), state: "active".into(), active_until_ms: until.map(epoch_ms), message: None };
    }
    if let Some(entitlement) = activating {
        return PamStatusView { entitlement: Some(entitlement), state: "activating".into(), active_until_ms: None, message: None };
    }
    if let Some(message) = refused {
        return PamStatusView { entitlement: None, state: "error".into(), active_until_ms: None, message: Some(message) };
    }
    PamStatusView::none()
}

/// Requests a grant on the first entitlement `transport` lists (as the connect does), remembers the request as the transport's defaults
/// through `remember`, waits for the grant to become active and answers its state. `pam_request_with` takes the polling and the wait.
pub fn pam_request(gcp: &dyn GcpClient, remember: &dyn Fn(&str, u32) -> Result<(), String>, transport: &HostTransport, justification: &str, duration_secs: u32) -> Result<PamStatusView, String> {
    pam_request_with(gcp, remember, transport, justification, duration_secs, &|| false, Duration::from_secs(2), Duration::from_secs(60))
}

#[allow(clippy::too_many_arguments)]
pub fn pam_request_with(
    gcp: &dyn GcpClient,
    remember: &dyn Fn(&str, u32) -> Result<(), String>,
    transport: &HostTransport,
    justification: &str,
    duration_secs: u32,
    cancelled: &dyn Fn() -> bool,
    poll_every: Duration,
    wait: Duration,
) -> Result<PamStatusView, String> {
    let TransportKind::GcpIap { project, account, pam, .. } = &transport.kind;
    let Some(pam) = pam else { return Err("This transport requires no grant.".into()) };
    let Some(entitlement) = pam.entitlements.first() else { return Err("This transport names no PAM entitlement.".into()) };
    let place = pam::Entitlement { account: account.as_deref(), project, location: &pam.location, entitlement };
    // A failed memory write does not fail the request: the grant exists either way.
    let remembered = || {
        let _ = remember(justification, duration_secs);
    };
    let grant = pam::request_and_wait(gcp, &place, justification, duration_secs, &remembered, poll_every, wait, cancelled).map_err(|error| error.sentence(entitlement))?;
    let (_, active_until) = pam::active_span(&grant, SystemTime::now(), duration_secs);
    Ok(PamStatusView { entitlement: Some(entitlement.clone()), state: "active".into(), active_until_ms: Some(epoch_ms(active_until)), message: None })
}

/// The form's rules, the transport editor's: whole minutes from 1 to 480, a justification with something in it, on one line, at most 512
/// characters. The sentences are the editor's too.
fn checked_request(justification: &str, duration_secs: u32) -> Result<String, String> {
    if duration_secs < 60 || duration_secs > transports::MAX_DURATION_SECS || duration_secs % 60 != 0 {
        return Err("Enter a grant duration between 1 and 480 minutes.".into());
    }
    let justification = justification.trim();
    if justification.is_empty() {
        return Err("Enter a justification.".into());
    }
    if justification.chars().count() > transports::MAX_JUSTIFICATION_CHARS || justification.chars().any(char::is_control) {
        return Err("Keep the justification under 512 characters on one line.".into());
    }
    Ok(justification.to_string())
}

/// The saved transport of `host_id` (Records workspace only).
fn transport_of(app: &tauri::AppHandle, host_id: &str) -> Result<HostTransport, String> {
    let state = app.state::<AppState>();
    let core = state.sync.core.lock().unwrap();
    let records = core.records.as_ref().ok_or("The saved records are unavailable.")?;
    transports::get(records, host_id).ok_or_else(|| "This host has no transport.".to_string())
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

#[tauri::command]
pub async fn transports_pam_status(app: tauri::AppHandle, window: tauri::WebviewWindow, host_id: String) -> Result<PamStatusView, String> {
    main_only(&window)?;
    if !transports::is_id(&host_id) {
        return Err("Invalid host identity.".into());
    }
    tauri::async_runtime::spawn_blocking(move || {
        let transport = transport_of(&app, &host_id)?;
        let gcp = RestClient::new(Arc::new(FileStore::from_environment()));
        Ok(pam_status(&gcp, &transport))
    })
    .await
    .map_err(|error| error.to_string())?
}

#[tauri::command]
pub async fn transports_pam_request(app: tauri::AppHandle, window: tauri::WebviewWindow, host_id: String, justification: String, duration_secs: u32) -> Result<PamStatusView, String> {
    main_only(&window)?;
    if !transports::is_id(&host_id) {
        return Err("Invalid host identity.".into());
    }
    let justification = checked_request(&justification, duration_secs)?;
    tauri::async_runtime::spawn_blocking(move || {
        let transport = transport_of(&app, &host_id)?;
        let gcp = RestClient::new(Arc::new(FileStore::from_environment()));
        let remember = |justification: &str, duration_secs: u32| -> Result<(), String> {
            crate::sync::engine::with_env(&app, |env| {
                crate::sync::record_commands::edit_records(env, |state, now| {
                    transports::remember_grant_request(state, &host_id, justification, duration_secs, now).map_err(|error| crate::error::AppError::Other(error.to_string()))
                })
            })
            .map_err(|error| error.to_string())?
            .map(|_| ())
            .map_err(|error| error.to_string())
        };
        pam_request(&gcp, &remember, &transport, &justification, duration_secs)
    })
    .await
    .map_err(|error| error.to_string())?
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gcp::oslogin::{LoginProfile, PosixAccount};
    use crate::gcp::pam::{self, Grant};
    use crate::gcp::rest::{GcpClient, GcpError};
    use crate::sync::record_commands;
    use crate::sync::records_v3::SyncStateV3;
    use crate::sync::transports::{self, HostTransport, PamCheck, TransportKind};
    use serde_json::json;
    use std::collections::{BTreeMap, VecDeque};
    use std::sync::Mutex;
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

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

    /// `iap()` with a PAM check on `entitlements`, as the panel sees a production host.
    fn with_pam(entitlements: &[&str]) -> HostTransport {
        let mut transport = iap();
        let TransportKind::GcpIap { account, pam, .. } = &mut transport.kind;
        *account = Some("frank@retower.io".into());
        *pam = Some(PamCheck { entitlements: entitlements.iter().map(|e| e.to_string()).collect(), location: "global".into(), duration_secs: 1800, justification: Some("restart app-api".into()) });
        transport
    }

    fn grant(name: &str, state: &str, granted: Option<SystemTime>, secs: u32) -> Grant {
        Grant { name: name.into(), state: state.into(), requested_duration: Some(pam::duration_text(secs)), access_grant_time: granted.map(pam::rfc3339), justification: Some("restart app-api".into()) }
    }

    fn ms(time: SystemTime) -> u64 {
        time.duration_since(UNIX_EPOCH).unwrap().as_millis() as u64
    }

    /// The end of a grant as the view computes it: from the grant time as written (whole seconds) plus the duration.
    fn ends(granted: SystemTime, secs: u32) -> u64 {
        ms(pam::parse_rfc3339(&pam::rfc3339(granted)).unwrap() + Duration::from_secs(u64::from(secs)))
    }

    /// PAM as the panel sees it: each entitlement's grants (or the API's refusal), what was requested, and the states a requested grant
    /// goes through when read back.
    #[derive(Default)]
    struct Pam {
        grants: Mutex<BTreeMap<String, Result<Vec<Grant>, String>>>,
        created: Mutex<Vec<(String, u32, String)>>,
        states: Mutex<VecDeque<&'static str>>,
        read: Mutex<Vec<String>>,
    }

    impl Pam {
        fn answering(&self, entitlement: &str, grants: Result<Vec<Grant>, &str>) {
            self.grants.lock().unwrap().insert(entitlement.into(), grants.map_err(str::to_string));
        }
        fn refusal(message: &str) -> GcpError {
            GcpError::Refused { api: "Privileged Access Manager", message: message.into() }
        }
    }

    impl GcpClient for Pam {
        fn login_profile(&self, _: Option<&str>, _: &str) -> Result<LoginProfile, GcpError> {
            panic!("the panel's grant state never reads OS Login")
        }
        fn import_ssh_public_key(&self, _: Option<&str>, _: &str, _: &str) -> Result<LoginProfile, GcpError> {
            panic!("the panel never imports a key")
        }
        fn grants(&self, account: Option<&str>, project: &str, location: &str, entitlement: &str) -> Result<Vec<Grant>, GcpError> {
            assert_eq!((account, project, location), (Some("frank@retower.io"), "eng-dev-396409", "global"));
            match self.grants.lock().unwrap().get(entitlement) {
                Some(Ok(grants)) => Ok(grants.clone()),
                Some(Err(message)) => Err(Pam::refusal(message)),
                None => Ok(Vec::new()),
            }
        }
        fn create_grant(&self, _: Option<&str>, project: &str, location: &str, entitlement: &str, duration_secs: u32, justification: &str) -> Result<Grant, GcpError> {
            self.created.lock().unwrap().push((entitlement.into(), duration_secs, justification.into()));
            Ok(grant(&format!("projects/{project}/locations/{location}/entitlements/{entitlement}/grants/g1"), "ACTIVATING", None, duration_secs))
        }
        fn get_grant(&self, _: Option<&str>, name: &str) -> Result<Grant, GcpError> {
            self.read.lock().unwrap().push(name.into());
            let state = self.states.lock().unwrap().pop_front().expect("a state to read");
            Ok(grant(name, state, (state == "ACTIVE").then(SystemTime::now), 2700))
        }
    }

    /// Design 2026-10-25 (PAM grant requests): the panel names the entitlement whose grant lasts longest, since a connection passes
    /// while any of them holds, and when it ends.
    #[test]
    fn pam_status_names_the_entitlement_that_holds_the_grant_and_the_latest_end() {
        let now = SystemTime::now();
        let gcp = Pam::default();
        gcp.answering("prod-operate", Ok(vec![grant("g-op", "ACTIVE", Some(now - Duration::from_secs(600)), 1800)]));
        gcp.answering("prod-admin", Ok(vec![grant("g-old", "ENDED", Some(now - Duration::from_secs(7200)), 1800), grant("g-ad", "ACTIVE", Some(now - Duration::from_secs(300)), 3600)]));
        let view = pam_status(&gcp, &with_pam(&["prod-operate", "prod-admin"]));
        assert_eq!((view.state.as_str(), view.entitlement.as_deref(), view.message), ("active", Some("prod-admin"), None));
        assert_eq!(view.active_until_ms, Some(ends(now - Duration::from_secs(300), 3600)));
        let only = pam_status(&gcp, &with_pam(&["prod-operate"]));
        assert_eq!((only.entitlement.as_deref(), only.active_until_ms), (Some("prod-operate"), Some(ends(now - Duration::from_secs(600), 1800))));
    }

    #[test]
    fn pam_status_reports_activating_none_and_the_apis_sentence() {
        let now = SystemTime::now();
        let gcp = Pam::default();
        gcp.answering("prod-operate", Ok(vec![grant("g-op", "ACTIVATING", None, 1800)]));
        let view = pam_status(&gcp, &with_pam(&["prod-operate", "prod-admin"]));
        assert_eq!((view.state.as_str(), view.entitlement.as_deref(), view.active_until_ms, view.message), ("activating", Some("prod-operate"), None, None));
        // Nothing in flight: an ended grant, and an ACTIVE one whose time is up, are no grant.
        gcp.answering("prod-operate", Ok(vec![grant("g-op", "ENDED", Some(now - Duration::from_secs(7200)), 1800), grant("g-stale", "ACTIVE", Some(now - Duration::from_secs(7200)), 1800)]));
        let view = pam_status(&gcp, &with_pam(&["prod-operate", "prod-admin"]));
        assert_eq!((view.state.as_str(), view.entitlement, view.active_until_ms, view.message), ("none", None, None, None));
        // The API refused one entitlement's search: its sentence, unless another entitlement answers with a grant.
        gcp.answering("prod-operate", Err("quota exceeded"));
        let view = pam_status(&gcp, &with_pam(&["prod-operate", "prod-admin"]));
        assert_eq!((view.state.as_str(), view.entitlement, view.active_until_ms), ("error", None, None));
        assert_eq!(view.message, Some(Pam::refusal("quota exceeded").to_string()));
        gcp.answering("prod-admin", Ok(vec![grant("g-ad", "ACTIVE", Some(now), 1800)]));
        let view = pam_status(&gcp, &with_pam(&["prod-operate", "prod-admin"]));
        assert_eq!((view.state.as_str(), view.entitlement.as_deref()), ("active", Some("prod-admin")));
        // No PAM check: nothing to report.
        let view = pam_status(&gcp, &iap());
        assert_eq!((view.state.as_str(), view.entitlement, view.message), ("none", None, None));
    }

    #[test]
    fn pam_request_requests_the_first_entitlement_remembers_and_waits_for_active() {
        let gcp = Pam::default();
        *gcp.states.lock().unwrap() = ["ACTIVATING", "ACTIVE"].into();
        let remembered = Mutex::new(Vec::new());
        let remember = |justification: &str, duration_secs: u32| {
            remembered.lock().unwrap().push((justification.to_string(), duration_secs));
            Ok(())
        };
        let before = SystemTime::now();
        let view = pam_request_with(&gcp, &remember, &with_pam(&["prod-operate", "prod-admin"]), "restart app-api after the deploy", 2700, &|| false, Duration::from_millis(1), Duration::from_secs(5)).unwrap();
        assert_eq!((view.state.as_str(), view.entitlement.as_deref(), view.message), ("active", Some("prod-operate"), None));
        assert!(view.active_until_ms.is_some_and(|until| until >= ms(before + Duration::from_secs(2700)) - 1000), "{:?}", view.active_until_ms);
        assert_eq!(gcp.created.lock().unwrap().as_slice(), [("prod-operate".to_string(), 2700, "restart app-api after the deploy".to_string())]);
        assert_eq!(gcp.read.lock().unwrap().len(), 2, "read back until ACTIVE");
        assert_eq!(remembered.lock().unwrap().as_slice(), [("restart app-api after the deploy".to_string(), 2700)]);
        // A grant that will not become active: its state, in the sentence the connect uses too.
        let denied = Pam::default();
        *denied.states.lock().unwrap() = ["DENIED"].into();
        let error = pam_request_with(&denied, &remember, &with_pam(&["prod-operate"]), "x", 1800, &|| false, Duration::from_millis(1), Duration::from_secs(5)).err();
        assert_eq!(error, Some("The prod-operate grant did not become active (state: DENIED).".to_string()));
        assert_eq!(remembered.lock().unwrap().len(), 2, "a request that ended denied was still a request, and is remembered");
        // A transport without a PAM check has nothing to request.
        let error = pam_request_with(&gcp, &remember, &iap(), "x", 1800, &|| false, Duration::from_millis(1), Duration::from_secs(5)).err();
        assert_eq!(error, Some("This transport requires no grant.".to_string()));
        assert_eq!(remembered.lock().unwrap().len(), 2, "nothing more was remembered");
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
