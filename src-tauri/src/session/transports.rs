//! The app's commands for a host's transport (design 2026-10-25): ask OS Login for the username the editor fills in, and show or
//! request the Privileged Access Manager grant a transport needs (design 2026-10-25, PAM grant requests). A route is saved, changed
//! and removed with its host (`records_host_create`, `records_host_update`, `records_host_delete`; design 2026-10-26, Commands);
//! connections read it through `RecordDirectory`. `gcp_accounts` lists the Google accounts gcloud holds credentials for on this computer
//! and whether each sign-in works.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::Serialize;
use tauri::Manager;

use crate::gcp::auth;
use crate::gcp::pam;
use crate::gcp::rest::GcpClient;
use crate::state::AppState;
use crate::sync::records_v3;
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

/// What the Google Cloud page and the host editor's account picker learn of gcloud on this computer: whether its config directory is
/// there, the account it is signed in as, and each account it holds credentials for with the state of that sign-in.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[cfg_attr(test, derive(ts_rs::TS))]
#[cfg_attr(test, ts(export, export_to = "../../src/bindings/"))]
pub struct GcloudAccountsView {
    pub config_found: bool,
    pub active: Option<String>,
    pub accounts: Vec<GcloudAccountView>,
}

/// One gcloud account and whether its sign-in works: `signed_in` (a token was had), `expired` (Google refused the refresh token, so the
/// person signs in again) or `unknown` (the check could not be made; `message` is the sentence why).
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[cfg_attr(test, derive(ts_rs::TS))]
#[cfg_attr(test, ts(export, export_to = "../../src/bindings/"))]
pub struct GcloudAccountView {
    pub account: String,
    pub state: String,
    pub message: Option<String>,
}

impl GcloudAccountView {
    /// The line for `account` given how asking for its token went: a token had is `signed_in`; a refresh token Google refused is `expired`
    /// (the page words the cure itself, `gcloud auth login <account>`); anything else is `unknown` with the error's own sentence, which
    /// names no secret.
    fn from_check(account: &str, check: Result<(), auth::AuthError>) -> GcloudAccountView {
        let (state, message) = match check {
            Ok(()) => ("signed_in", None),
            Err(auth::AuthError::SignInExpired { .. }) => ("expired", None),
            Err(error) => ("unknown", Some(error.to_string())),
        };
        GcloudAccountView { account: account.to_string(), state: state.to_string(), message }
    }
}

/// Whether gcloud's sign-in for `account` works: its token is asked for by name, which refreshes it against Google unless the source holds
/// a fresh one, and dropped at once. Blocks like the source does (a plain thread or `spawn_blocking`, never async code).
pub fn account_state(tokens: &dyn auth::TokenSource, account: &str) -> GcloudAccountView {
    GcloudAccountView::from_check(account, tokens.access_token(Some(account)).map(drop))
}

/// How long `gcp_accounts` waits for Google before it answers with what it has.
const ACCOUNTS_BOUND: Duration = Duration::from_secs(20);

/// gcloud's directory `dir` as the page and the account picker see it: whether it is there, its active account, and each account that
/// holds credentials with its sign-in checked through `tokens` (design 2026-10-26, Commands). Nothing is written under `dir`, and a
/// directory that is not there is `config_found: false`, not an error.
///
/// Everything blocking runs off the async runtime, and all of it within `bound`: the checks run at once, one thread each, and a check
/// that has not come back when the bound is up is `unknown` with the token service's "timed out" sentence while the others keep their
/// answers. A check still running then ends on its own, within the token source's own timeout.
pub async fn gcloud_accounts(dir: PathBuf, tokens: Arc<dyn auth::TokenSource>, bound: Duration) -> Result<GcloudAccountsView, String> {
    let deadline = tokio::time::Instant::now() + bound;
    let listing = tokio::task::spawn_blocking(move || (dir.is_dir(), auth::active_account(&dir), auth::credentialed_accounts(&dir)));
    let (config_found, active, names) = tokio::time::timeout_at(deadline, listing)
        .await
        .map_err(|_| "Reading gcloud's folder took too long.".to_string())?
        .map_err(|error| error.to_string())?;
    let checks: Vec<_> = names
        .iter()
        .map(|name| {
            let (tokens, name) = (Arc::clone(&tokens), name.clone());
            tokio::task::spawn_blocking(move || account_state(&*tokens, &name))
        })
        .collect();
    let mut accounts = Vec::with_capacity(checks.len());
    for (name, check) in names.iter().zip(checks) {
        accounts.push(match tokio::time::timeout_at(deadline, check).await {
            Ok(Ok(line)) => line,
            Ok(Err(_)) => GcloudAccountView::from_check(name, Err(auth::AuthError::Network("the check stopped unexpectedly".into()))),
            Err(_) => GcloudAccountView::from_check(name, Err(auth::AuthError::Network("timed out".into()))),
        });
    }
    Ok(GcloudAccountsView { config_found, active, accounts })
}

/// The form's rules, the transport editor's: whole minutes from 1 to 480, a justification with something in it, on one line, at most 512
/// characters. The sentences are the editor's too.
fn checked_request(justification: &str, duration_secs: u32) -> Result<String, String> {
    if !(60..=transports::MAX_DURATION_SECS).contains(&duration_secs) || !duration_secs.is_multiple_of(60) {
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

/// The host a grant command names: the bare id the panel sends (a transport's `host_id`, what `transport_of` looks up), not the record's
/// `transport:` wire id.
fn checked_host_id(host_id: &str) -> Result<(), String> {
    if !records_v3::is_host_id(host_id) {
        return Err("Invalid host identity.".into());
    }
    Ok(())
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

/// The vault key's OpenSSH public line, as the broker's key store reads it (Records workspace only).
fn vault_public_line(app: &tauri::AppHandle, key_id: &str) -> Option<String> {
    let state = app.state::<AppState>();
    let core = state.sync.core.lock().unwrap();
    let key = crate::sync::record_repository::resolve_key(core.records.as_ref()?, key_id).ok()?;
    key.public.map(|public| public.public_key)
}

/// gcloud's config directory on this computer, where the token source looks too (`CLOUDSDK_CONFIG`, `~/.config/gcloud`,
/// `%APPDATA%\gcloud`).
fn gcloud_config_dir() -> PathBuf {
    auth::config_dir(&|name| std::env::var(name).ok(), dirs::home_dir().as_deref(), cfg!(windows))
}

/// gcloud's active account, for the view's label when the transport names none.
fn active_account_label() -> String {
    auth::active_account(&gcloud_config_dir()).unwrap_or_else(|| "the active gcloud account".to_string())
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
        let gcp = app.state::<AppState>().gcp.clone();
        os_login_profile(&*gcp, &label, account.as_deref(), &project, public_key.as_deref())
    })
    .await
    .map_err(|error| error.to_string())?
}

#[tauri::command]
pub async fn transports_pam_status(app: tauri::AppHandle, window: tauri::WebviewWindow, host_id: String) -> Result<PamStatusView, String> {
    main_only(&window)?;
    checked_host_id(&host_id)?;
    tauri::async_runtime::spawn_blocking(move || {
        let transport = transport_of(&app, &host_id)?;
        let gcp = app.state::<AppState>().gcp.clone();
        Ok(pam_status(&*gcp, &transport))
    })
    .await
    .map_err(|error| error.to_string())?
}

#[tauri::command]
pub async fn transports_pam_request(app: tauri::AppHandle, window: tauri::WebviewWindow, host_id: String, justification: String, duration_secs: u32) -> Result<PamStatusView, String> {
    main_only(&window)?;
    checked_host_id(&host_id)?;
    let justification = checked_request(&justification, duration_secs)?;
    tauri::async_runtime::spawn_blocking(move || {
        let transport = transport_of(&app, &host_id)?;
        let gcp = app.state::<AppState>().gcp.clone();
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
        pam_request(&*gcp, &remember, &transport, &justification, duration_secs)
    })
    .await
    .map_err(|error| error.to_string())?
}

/// The Google accounts gcloud holds credentials for on this computer and whether each sign-in works, for the Google Cloud page and the
/// host editor's account picker (design 2026-10-26, Commands). Checked through the client's own token source, so a check warms the
/// calls that follow; bounded to `ACCOUNTS_BOUND` overall.
#[tauri::command]
pub async fn gcp_accounts(app: tauri::AppHandle, window: tauri::WebviewWindow) -> Result<GcloudAccountsView, String> {
    main_only(&window)?;
    let tokens = app.state::<AppState>().gcp.tokens();
    gcloud_accounts(gcloud_config_dir(), tokens, ACCOUNTS_BOUND).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gcp::auth::{AuthError, StaticToken, Token, TokenSource};
    use crate::gcp::oslogin::{LoginProfile, PosixAccount};
    use crate::gcp::pam::{self, Grant};
    use crate::gcp::rest::{GcpClient, GcpError};
    use crate::sync::record_commands;
    use crate::sync::records_v3::SyncStateV3;
    use crate::sync::transports::{self, HostTransport, PamCheck, TransportKind};
    use serde_json::json;
    use std::collections::{BTreeMap, VecDeque};
    use std::path::PathBuf;
    use std::sync::{mpsc, Arc, Mutex};
    use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

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

    /// A grant that is already in flight (requested by hand, or by a connection a moment ago) is used, not requested again, and the
    /// request is not remembered as the transport's defaults: nothing was asked of PAM.
    #[test]
    fn pam_request_takes_a_grant_already_in_flight_and_requests_nothing() {
        let now = SystemTime::now();
        let gcp = Pam::default();
        gcp.answering("prod-operate", Ok(vec![grant("g-op", "ACTIVE", Some(now - Duration::from_secs(60)), 1800)]));
        let remembered = Mutex::new(Vec::<(String, u32)>::new());
        let remember = |justification: &str, duration_secs: u32| {
            remembered.lock().unwrap().push((justification.to_string(), duration_secs));
            Ok(())
        };
        let view = pam_request_with(&gcp, &remember, &with_pam(&["prod-operate", "prod-admin"]), "restart app-api", 2700, &|| false, Duration::from_millis(1), Duration::from_secs(5)).unwrap();
        assert_eq!((view.state.as_str(), view.entitlement.as_deref()), ("active", Some("prod-operate")));
        assert_eq!(view.active_until_ms, Some(ends(now - Duration::from_secs(60), 1800)), "the grant's own end, not the duration asked for");
        assert!(gcp.created.lock().unwrap().is_empty(), "nothing was requested");
        assert!(gcp.read.lock().unwrap().is_empty(), "nothing was read back");
        assert!(remembered.lock().unwrap().is_empty(), "nothing to remember");
    }

    /// The panel's grant line and Request grant name the host by a transport's `host_id`, the bare id `transport_of` looks up; checking it
    /// as the record's `transport:` wire id refused every real host.
    #[test]
    fn the_grant_commands_take_the_bare_host_id_the_panel_sends() {
        assert_eq!(checked_host_id(HOST), Ok(()));
        assert_eq!(checked_host_id(&record_commands::new_host_id().unwrap()), Ok(()), "a host id as the library makes one");
        for malformed in ["transport:0000000000000001", "", "000000000000001", "00000000000000001", "000000000000000F", "../../etc/passwd"] {
            assert_eq!(checked_host_id(malformed), Err("Invalid host identity.".to_string()), "{malformed:?}");
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

    /// What a token looks like when a fake hands one out: it must never reach a view.
    const TOKEN: &str = "ya29.never-in-a-view";
    const REFRESH_TOKEN: &str = "rt-never-in-a-view";

    /// gcloud's sign-in check scripted per account, so no Google call is made: `answers` for the accounts it was told of, `otherwise` for
    /// the rest, and a record of who was asked for.
    struct Answers {
        answers: BTreeMap<String, Result<(), AuthError>>,
        otherwise: Result<(), AuthError>,
        asked: Mutex<Vec<Option<String>>>,
    }

    impl Answers {
        /// Every account signs in.
        fn ok() -> Answers {
            Answers { answers: BTreeMap::new(), otherwise: Ok(()), asked: Mutex::new(Vec::new()) }
        }
        /// Every account gets `error`.
        fn err(error: AuthError) -> Answers {
            Answers { otherwise: Err(error), ..Answers::ok() }
        }
        /// `account` gets `answer` instead.
        fn with(mut self, account: &str, answer: Result<(), AuthError>) -> Answers {
            self.answers.insert(account.into(), answer);
            self
        }
        /// Who the source was asked for, in order of name.
        fn asked(&self) -> Vec<Option<String>> {
            let mut asked = self.asked.lock().unwrap().clone();
            asked.sort();
            asked
        }
    }

    impl TokenSource for Answers {
        fn access_token(&self, account: Option<&str>) -> Result<Token, AuthError> {
            self.asked.lock().unwrap().push(account.map(str::to_string));
            let answer = account.and_then(|account| self.answers.get(account)).unwrap_or(&self.otherwise);
            answer.clone().and_then(|()| StaticToken(TOKEN.into()).access_token(account))
        }
    }

    /// `inner`, except that the call for `hung` does not come back until `release` is dropped (five seconds at most): a Google call that
    /// gets no answer.
    struct Stalls {
        inner: Answers,
        hung: &'static str,
        release: Mutex<mpsc::Receiver<()>>,
    }

    impl TokenSource for Stalls {
        fn access_token(&self, account: Option<&str>) -> Result<Token, AuthError> {
            if account == Some(self.hung) {
                let _ = self.release.lock().unwrap().recv_timeout(Duration::from_secs(5));
            }
            self.inner.access_token(account)
        }
    }

    /// `inner`, except that the check for `broken` panics, as a bug in a token source would.
    struct Breaks {
        inner: Answers,
        broken: &'static str,
    }

    impl TokenSource for Breaks {
        fn access_token(&self, account: Option<&str>) -> Result<Token, AuthError> {
            assert_ne!(account, Some(self.broken), "a check that dies");
            self.inner.access_token(account)
        }
    }

    fn line(account: &str, state: &str, message: Option<&str>) -> GcloudAccountView {
        GcloudAccountView { account: account.into(), state: state.into(), message: message.map(str::to_string) }
    }

    /// A gcloud directory holding an `authorized_user` file for each of `accounts` (secrets and all) and, when `active` is given,
    /// that account as the active one.
    fn gcloud_dir(accounts: &[&str], active: Option<&str>) -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        for account in accounts {
            let path = auth::legacy_credentials_path(dir.path(), account);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            let file = json!({"account": account, "client_id": "cid.apps.googleusercontent.com", "client_secret": "csecret", "refresh_token": REFRESH_TOKEN, "type": "authorized_user"});
            std::fs::write(path, file.to_string()).unwrap();
        }
        if let Some(active) = active {
            std::fs::create_dir_all(dir.path().join("configurations")).unwrap();
            std::fs::write(dir.path().join("active_config"), "default\n").unwrap();
            std::fs::write(dir.path().join("configurations/config_default"), format!("[core]\naccount = {active}\n")).unwrap();
        }
        dir
    }

    #[test]
    fn account_state_maps_token_outcomes() {
        assert_eq!(account_state(&Answers::ok(), "a@example.com").state, "signed_in");
        assert_eq!(account_state(&Answers::err(AuthError::SignInExpired { account: "a@example.com".into() }), "a@example.com").state, "expired");
        let unknown = account_state(&Answers::err(AuthError::Network("offline".into())), "a@example.com");
        assert_eq!((unknown.state.as_str(), unknown.message.is_some()), ("unknown", true));
    }

    /// The token is had to prove the sign-in and dropped; an unreadable sign-in is `unknown` with the error's own sentence and nothing
    /// else; a refused refresh token is `expired`, which the page words itself (`gcloud auth login <account>`).
    #[test]
    fn a_view_names_the_account_asks_for_it_by_name_and_carries_no_token() {
        let answers = Answers::ok();
        let signed_in = account_state(&answers, "a@example.com");
        assert_eq!(signed_in, line("a@example.com", "signed_in", None));
        assert_eq!(answers.asked(), [Some("a@example.com".to_string())], "the named account, never the default one");
        let expired = account_state(&Answers::err(AuthError::SignInExpired { account: "a@example.com".into() }), "a@example.com");
        assert_eq!(expired, line("a@example.com", "expired", None));
        let file = PathBuf::from("/d/legacy_credentials/a@example.com/adc.json");
        for error in [
            AuthError::Network("offline".into()),
            AuthError::Http { status: 503 },
            AuthError::NoCredentials { account: Some("a@example.com".into()), config_dir: PathBuf::from("/d") },
            AuthError::Malformed { path: file.clone() },
            AuthError::Unsupported { path: file, kind: "service_account".into() },
        ] {
            let sentence = error.to_string();
            let unknown = account_state(&Answers::err(error), "a@example.com");
            assert_eq!(unknown, line("a@example.com", "unknown", Some(&sentence)));
        }
        let wire = serde_json::to_string(&signed_in).unwrap();
        assert!(!wire.contains(TOKEN) && !format!("{signed_in:?}").contains(TOKEN), "{wire}");
    }

    /// Design 2026-10-26 (`gcp_accounts`): each account gcloud holds credentials for, in order of name, with its sign-in checked through
    /// the token source by name; the active account; a service account listed by nobody and asked about by nobody.
    #[tokio::test]
    async fn gcloud_accounts_lists_each_account_with_its_sign_in_state_and_the_active_one() {
        let dir = gcloud_dir(&["ops@example.com", "frank@example.com", "late@example.com"], Some("ops@example.com"));
        std::fs::create_dir_all(dir.path().join("legacy_credentials/robot")).unwrap();
        std::fs::write(dir.path().join("legacy_credentials/robot/adc.json"), r#"{"type":"service_account","client_email":"robot@example.com"}"#).unwrap();
        let answers = Arc::new(
            Answers::ok()
                .with("ops@example.com", Err(AuthError::SignInExpired { account: "ops@example.com".into() }))
                .with("late@example.com", Err(AuthError::Network("offline".into()))),
        );
        let view = gcloud_accounts(dir.path().to_path_buf(), answers.clone(), Duration::from_secs(10)).await.unwrap();
        assert_eq!(
            view,
            GcloudAccountsView {
                config_found: true,
                active: Some("ops@example.com".into()),
                accounts: vec![
                    line("frank@example.com", "signed_in", None),
                    line("late@example.com", "unknown", Some("Google's token service could not be reached: offline.")),
                    line("ops@example.com", "expired", None),
                ],
            }
        );
        assert_eq!(answers.asked(), [Some("frank@example.com".to_string()), Some("late@example.com".to_string()), Some("ops@example.com".to_string())]);
        // The shape the page reads, and nothing of the files' secrets or the tokens in it.
        let wire = serde_json::to_value(&view).unwrap();
        assert_eq!(
            wire,
            json!({
                "config_found": true,
                "active": "ops@example.com",
                "accounts": [
                    {"account": "frank@example.com", "state": "signed_in", "message": null},
                    {"account": "late@example.com", "state": "unknown", "message": "Google's token service could not be reached: offline."},
                    {"account": "ops@example.com", "state": "expired", "message": null},
                ]
            })
        );
        let text = wire.to_string();
        assert!(![TOKEN, REFRESH_TOKEN, "csecret"].iter().any(|secret| text.contains(secret)), "{text}");
    }

    /// Review Focus 4: no gcloud directory is `config_found: false` and no error; gcloud with nobody signed in is found, with no accounts;
    /// the active account is reported even when this computer holds no credentials for it. Reading creates nothing under gcloud's directory
    /// and makes no Google call when there is no account to check.
    #[tokio::test]
    async fn gcloud_accounts_without_a_directory_or_accounts_answers_what_is_there_and_no_error() {
        let parent = tempfile::tempdir().unwrap();
        let missing = parent.path().join("gcloud");
        let answers = Arc::new(Answers::err(AuthError::Network("never asked".into())));
        let view = gcloud_accounts(missing.clone(), answers.clone(), Duration::from_secs(10)).await.unwrap();
        assert_eq!(view, GcloudAccountsView { config_found: false, active: None, accounts: Vec::new() });
        assert!(!missing.exists(), "nothing was created");

        let bare = tempfile::tempdir().unwrap();
        let view = gcloud_accounts(bare.path().to_path_buf(), answers.clone(), Duration::from_secs(10)).await.unwrap();
        assert_eq!(view, GcloudAccountsView { config_found: true, active: None, accounts: Vec::new() });

        let signed_out = gcloud_dir(&[], Some("ghost@example.com"));
        std::fs::create_dir_all(signed_out.path().join("legacy_credentials/robot")).unwrap();
        std::fs::write(signed_out.path().join("legacy_credentials/robot/adc.json"), r#"{"type":"service_account"}"#).unwrap();
        let view = gcloud_accounts(signed_out.path().to_path_buf(), answers.clone(), Duration::from_secs(10)).await.unwrap();
        assert_eq!(view, GcloudAccountsView { config_found: true, active: Some("ghost@example.com".into()), accounts: Vec::new() });
        assert!(answers.asked().is_empty(), "no account, so nothing was asked of Google");
    }

    /// Design 2026-10-26: every check is bounded and the command is bounded overall. A check that gets no answer is `unknown` with the
    /// token service's own "timed out" sentence, and the others are not held back: the last account, checked after the one that hangs,
    /// still answers.
    #[tokio::test]
    async fn a_check_that_does_not_answer_in_time_is_unknown_and_holds_back_no_other() {
        let dir = gcloud_dir(&["a@example.com", "b@example.com", "c@example.com"], None);
        let (release, wait) = mpsc::channel();
        let tokens = Arc::new(Stalls {
            inner: Answers::ok().with("c@example.com", Err(AuthError::SignInExpired { account: "c@example.com".into() })),
            hung: "b@example.com",
            release: Mutex::new(wait),
        });
        let started = Instant::now();
        let view = gcloud_accounts(dir.path().to_path_buf(), tokens, Duration::from_millis(500)).await;
        let waited = started.elapsed();
        drop(release); // lets the stalled call go, whatever the assertions below say
        let view = view.unwrap();
        assert!(waited >= Duration::from_millis(400) && waited < Duration::from_secs(4), "bounded by the 500 ms asked for, not by the stall: {waited:?}");
        assert_eq!(
            view.accounts,
            [
                line("a@example.com", "signed_in", None),
                line("b@example.com", "unknown", Some("Google's token service could not be reached: timed out.")),
                line("c@example.com", "expired", None),
            ]
        );
    }

    /// A check whose thread dies (a bug in a token source) costs that account its answer, not the page the others.
    #[tokio::test]
    async fn a_check_that_dies_is_unknown_and_holds_back_no_other() {
        let dir = gcloud_dir(&["a@example.com", "b@example.com", "c@example.com"], None);
        let tokens = Arc::new(Breaks { inner: Answers::ok(), broken: "b@example.com" });
        let view = gcloud_accounts(dir.path().to_path_buf(), tokens, Duration::from_secs(10)).await.unwrap();
        assert_eq!(
            view.accounts,
            [
                line("a@example.com", "signed_in", None),
                line("b@example.com", "unknown", Some("Google's token service could not be reached: the check stopped unexpectedly.")),
                line("c@example.com", "signed_in", None),
            ]
        );
    }
}
