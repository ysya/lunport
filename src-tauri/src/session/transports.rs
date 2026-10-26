//! The app's commands for a host's transport (design 2026-10-25): ask OS Login for the username the editor fills in, and show or
//! request the Privileged Access Manager grant a transport needs (design 2026-10-25, PAM grant requests). A route is saved, changed
//! and removed with its host (`records_host_create`, `records_host_update`, `records_host_delete`; design 2026-10-26, Commands);
//! connections read it through `RecordDirectory`. `gcp_accounts` lists the Google accounts gcloud holds credentials for on this computer
//! and whether each sign-in works; `gcp_pam_grants` lists the grants the saved routes require, one row per entitlement, and
//! `transports_pam_request` requests the entitlement the person chose. `transports_iap_probe` checks a host's route (design 2026-10-26,
//! Check through IAP): it opens a tunnel to the route's instance on the host's port and closes it again, with no grant request, no
//! sign-in prompt and no SSH.

use std::collections::BTreeSet;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde::Serialize;
use tauri::Manager;

use crate::connection_probe::{BUSY, CHECKS};
use crate::gcp::auth;
use crate::gcp::iap::{self, IapError};
use crate::gcp::pam;
use crate::gcp::rest::GcpClient;
use crate::ssh::IapTarget;
use crate::state::AppState;
use crate::sync::record_repository as repo;
use crate::sync::records_v3::{self, SyncStateV3};
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

/// What the grants found on one entitlement amount to at a moment: the end of the longest-lasting active one (`None` for an `ACTIVE`
/// grant PAM did not date, which counts below every dated one; one whose time is up counts for nothing), else a grant on its way, else
/// nothing. A route's status (`pam_status`) and each row of the Access grants section (`pam_grants`) both decide through this.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Standing {
    Active(Option<SystemTime>),
    Activating,
    Nothing,
}

impl Standing {
    fn of(grants: &[pam::Grant], now: SystemTime) -> Standing {
        let mut active: Option<Option<SystemTime>> = None;
        let mut activating = false;
        for grant in pam::in_flight(grants) {
            if grant.state == "ACTIVE" {
                let until = grant.until();
                if until.is_some_and(|until| until <= now) {
                    continue;
                }
                if active.is_none_or(|best| until > best) {
                    active = Some(until);
                }
            } else {
                activating = true;
            }
        }
        match active {
            Some(until) => Standing::Active(until),
            None if activating => Standing::Activating,
            None => Standing::Nothing,
        }
    }
}

/// The grant state of `transport`, over every entitlement it lists: a connection passes while any holds a grant, so the entitlement whose
/// grant lasts longest is named, with its end; else one that is activating; else none, or the API's sentence when a search failed and
/// no entitlement answered with a grant.
pub fn pam_status(gcp: &dyn GcpClient, transport: &HostTransport) -> PamStatusView {
    let TransportKind::GcpIap { project, account, pam, .. } = &transport.kind;
    let Some(pam) = pam else { return PamStatusView::none() };
    let now = SystemTime::now();
    // The longest-lasting active grant, the first activating one, the first refusal.
    let mut active: Option<(String, Option<SystemTime>)> = None;
    let mut activating: Option<String> = None;
    let mut refused: Option<String> = None;
    for entitlement in &pam.entitlements {
        match gcp.grants(account.as_deref(), project, &pam.location, entitlement) {
            Ok(grants) => match Standing::of(&grants, now) {
                Standing::Active(until) => {
                    if active.as_ref().is_none_or(|(_, best)| until > *best) {
                        active = Some((entitlement.clone(), until));
                    }
                }
                Standing::Activating => {
                    activating.get_or_insert_with(|| entitlement.clone());
                }
                Standing::Nothing => {}
            },
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

/// One row of the Google Cloud page's Access grants section: an entitlement some route requires (the account, project, location and
/// entitlement id together), the state of the grants on it for that account (`active` with its end, `activating`, `none`, or `error`
/// with the API's sentence), and the hosts whose routes name it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[cfg_attr(test, derive(ts_rs::TS))]
#[cfg_attr(test, ts(export, export_to = "../../src/bindings/"))]
pub struct PamGrantView {
    /// The Google account the grants are searched as: the one the routes name, or gcloud's active account for routes that name none; none
    /// when a route names none and gcloud has no active account to resolve it to.
    pub account: Option<String>,
    pub project: String,
    pub location: String,
    pub entitlement: String,
    pub state: String,
    #[cfg_attr(test, ts(type = "number | null"))]
    pub active_until_ms: Option<u64>,
    pub message: Option<String>,
    /// The hosts whose routes name this entitlement, in the order of the routes.
    pub host_ids: Vec<String>,
}

impl PamGrantView {
    /// The row for `place`, with no host yet: one search of the account's grants on that entitlement, decided as `pam_status` decides.
    fn read(gcp: &dyn GcpClient, place: &pam::Entitlement<'_>, now: SystemTime) -> PamGrantView {
        let (state, active_until_ms, message) = match gcp.grants(place.account, place.project, place.location, place.entitlement) {
            Ok(grants) => match Standing::of(&grants, now) {
                Standing::Active(until) => ("active", until.map(epoch_ms), None),
                Standing::Activating => ("activating", None, None),
                Standing::Nothing => ("none", None, None),
            },
            Err(error) => ("error", None, Some(error.to_string())),
        };
        PamGrantView {
            account: place.account.map(str::to_string),
            project: place.project.to_string(),
            location: place.location.to_string(),
            entitlement: place.entitlement.to_string(),
            state: state.to_string(),
            active_until_ms,
            message,
            host_ids: Vec::new(),
        }
    }
}

/// The rows of the Access grants section for `transports` (design 2026-10-26, Commands): one per distinct account, project, location and
/// entitlement id among the entitlements the routes require, in the order the routes list them, each searched once however many hosts
/// name it, with the ids of those hosts. A route that names no account is `active`'s (gcloud's active account) and shares its rows with
/// the routes that name that account; with no active account it stays accountless, and the client resolves it as it does for a
/// connection. A route that requires no grant has no row. Blocks like the client does (a plain thread or `spawn_blocking`), one bounded
/// call after another.
pub fn pam_grants(gcp: &dyn GcpClient, active: Option<&str>, transports: &[HostTransport]) -> Vec<PamGrantView> {
    let now = SystemTime::now();
    let mut rows: Vec<PamGrantView> = Vec::new();
    for transport in transports {
        let TransportKind::GcpIap { project, account, pam, .. } = &transport.kind;
        let Some(pam) = pam else { continue };
        let account = account.as_deref().or(active);
        for entitlement in &pam.entitlements {
            let known = rows.iter().position(|row| row.account.as_deref() == account && row.project == *project && row.location == pam.location && row.entitlement == *entitlement);
            let index = known.unwrap_or_else(|| {
                rows.push(PamGrantView::read(gcp, &pam::Entitlement { account, project, location: &pam.location, entitlement }, now));
                rows.len() - 1
            });
            if !rows[index].host_ids.contains(&transport.host_id) {
                rows[index].host_ids.push(transport.host_id.clone());
            }
        }
    }
    rows
}

/// The routes of `records` whose host the library has, in host-id order. A route whose host is gone (deleted on another device, or in a
/// space this computer does not keep) is ignored, as the Catalog's tunnels tolerate a host that is missing (design 2026-10-26, Deleting a
/// host): the Access grants section names only hosts the person can see.
fn live_routes(records: &SyncStateV3) -> Result<Vec<HostTransport>, String> {
    let hosts: BTreeSet<String> = repo::list_hosts(records).map_err(|error| error.to_string())?.into_iter().map(|view| view.host.id).collect();
    Ok(transports::view(records).into_iter().filter(|route| hosts.contains(&route.host_id)).collect())
}

/// Requests a grant on `entitlement` (one `transport` lists; the first it lists when none is named, as the connect does), remembers the
/// request on this computer through `remember`, waits for the grant to become active and answers its state. `pam_request_with` takes the
/// polling and the wait.
pub fn pam_request(gcp: &dyn GcpClient, remember: &dyn Fn(&str, u32) -> Result<(), String>, transport: &HostTransport, justification: &str, duration_secs: u32, entitlement: Option<&str>) -> Result<PamStatusView, String> {
    pam_request_with(gcp, remember, transport, justification, duration_secs, entitlement, &|| false, Duration::from_secs(2), Duration::from_secs(60))
}

#[allow(clippy::too_many_arguments)]
pub fn pam_request_with(
    gcp: &dyn GcpClient,
    remember: &dyn Fn(&str, u32) -> Result<(), String>,
    transport: &HostTransport,
    justification: &str,
    duration_secs: u32,
    entitlement: Option<&str>,
    cancelled: &dyn Fn() -> bool,
    poll_every: Duration,
    wait: Duration,
) -> Result<PamStatusView, String> {
    let TransportKind::GcpIap { project, account, pam, .. } = &transport.kind;
    let Some(pam) = pam else { return Err("This transport requires no grant.".into()) };
    let entitlement = match entitlement {
        Some(chosen) => pam.entitlements.iter().find(|listed| *listed == chosen).ok_or("This transport does not list that entitlement.")?,
        None => pam.entitlements.first().ok_or("This transport names no PAM entitlement.")?,
    };
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
/// holds credentials with its sign-in checked through `tokens` (design 2026-10-26, Commands). Only an email address is an account here:
/// a route can name nothing else (`is_email`, the rule the route editor applies) and the picker must never offer one the editor would
/// then refuse, so a folder named otherwise, such as `default` (gcloud's folder for an empty account), is neither listed nor checked.
/// Nothing is written under `dir`, and a directory that is not there is `config_found: false`, not an error.
///
/// Everything blocking runs off the async runtime, and all of it within `bound`: the checks run at once, one thread each, and a check
/// that has not come back when the bound is up is `unknown` with the token service's "timed out" sentence while the others keep their
/// answers. A check still running then ends on its own, within the token source's own timeout.
pub async fn gcloud_accounts(dir: PathBuf, tokens: Arc<dyn auth::TokenSource>, bound: Duration) -> Result<GcloudAccountsView, String> {
    let deadline = tokio::time::Instant::now() + bound;
    let listing = tokio::task::spawn_blocking(move || (dir.is_dir(), auth::active_account(&dir), auth::credentialed_accounts(&dir)));
    let (config_found, active, mut names) = tokio::time::timeout_at(deadline, listing)
        .await
        .map_err(|_| "Reading gcloud's folder took too long.".to_string())?
        .map_err(|error| error.to_string())?;
    names.retain(|name| transports::is_email(name));
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

/// What **Check through IAP** learns of a host's route (design 2026-10-26, Check through IAP): `reachable` (the relay connected to the
/// instance's port), `denied` (IAP, or the Google sign-in, refused this computer's account) or `unreachable` (anything else that ended
/// the open, running out of time included). `latency_ms` is how long the tunnel took to open, when it did; `elapsed_ms` how long the
/// whole check took; `checked_at_ms` when it ended; `message` the sentence why, for a check that did not reach the instance.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[cfg_attr(test, derive(ts_rs::TS))]
#[cfg_attr(test, ts(export, export_to = "../../src/bindings/"))]
pub struct IapProbeView {
    pub status: String,
    #[cfg_attr(test, ts(type = "number | null"))]
    pub latency_ms: Option<u64>,
    #[cfg_attr(test, ts(type = "number"))]
    pub elapsed_ms: u64,
    #[cfg_attr(test, ts(type = "number"))]
    pub checked_at_ms: u64,
    pub message: Option<String>,
}

/// What a refusal by IAP itself says, and what a route that requires a grant adds to it.
const IAP_REFUSED: &str = "IAP refused this Google account.";
const REQUEST_A_GRANT: &str = "Request a grant, then check again.";
/// What a check says when the tunnel did not open in time.
const IAP_SILENT: &str = "IAP did not answer in time.";
/// How long a check through IAP waits for the tunnel to open, as every call to Google is bounded.
const IAP_CHECK_BOUND: Duration = Duration::from_secs(20);

impl IapProbeView {
    /// For a route that requires a grant, a refusal by IAP points to requesting one: a grant that ended or never came is the usual
    /// reason IAP refuses an account that is signed in. Nothing else is touched: a sign-in that failed is not a missing grant.
    fn pointing_to_the_grant(mut self) -> IapProbeView {
        if self.message.as_deref() == Some(IAP_REFUSED) {
            self.message = Some(format!("{IAP_REFUSED} {REQUEST_A_GRANT}"));
        }
        self
    }
}

fn millis(duration: Duration) -> u64 {
    duration.as_millis() as u64
}

/// Opens an IAP tunnel to `port` of the instance `target` names, as its account, and closes it at once, for `deadline` at most (design
/// 2026-10-26, Check through IAP). `iap::open` returns once the relay answers the connect with success, that is once the relay has
/// reached the instance's port, so that is `reachable`. The relay refusing the handshake with 403 or closing the tunnel with 4033 "not
/// authorized" is IAP refusing the account, and a sign-in that gives no token is `denied` too, with the sentence of why; every other
/// end of the open, and the deadline, is `unreachable` with its text. Nothing is asked of the person (no grant, no sign-in) and nothing
/// is sent through the tunnel: no SSH, so no host key and no login.
pub async fn probe_iap(target: &IapTarget, port: u16, tokens: Arc<dyn auth::TokenSource>, deadline: Duration) -> IapProbeView {
    let started = Instant::now();
    let opened = tokio::time::timeout(deadline, iap::open(target.endpoint(port), tokens, target.account.clone(), auth::user_agent())).await;
    let opening = started.elapsed();
    let (status, message) = match opened {
        Ok(Ok(tunnel)) => {
            drop(tunnel);
            ("reachable", None)
        }
        Ok(Err(IapError::Refused { status: 403 } | IapError::Closed { code: 4033, .. })) => ("denied", Some(IAP_REFUSED.to_string())),
        Ok(Err(IapError::Credentials(error))) => ("denied", Some(error.to_string())),
        Ok(Err(error)) => ("unreachable", Some(error.to_string())),
        Err(_) => ("unreachable", Some(IAP_SILENT.to_string())),
    };
    IapProbeView {
        status: status.to_string(),
        latency_ms: (status == "reachable").then(|| millis(opening)),
        elapsed_ms: millis(started.elapsed()),
        checked_at_ms: epoch_ms(SystemTime::now()),
        message,
    }
}

/// What a check of one host's route is made of.
struct Probe {
    target: IapTarget,
    port: u16,
    /// Whether the route requires a Privileged Access Manager grant, so that IAP's refusal can point to requesting one.
    requires_grant: bool,
}

/// What a check of `host_id`'s route needs, read from one state (design 2026-10-26, Check through IAP): the instance and account the
/// route names, as a connection takes them (`RecordDirectory`), and the port the host is saved with, its effective one, which a group
/// may supply and a connection dials. A host whose group settings need review has no effective port to trust, so the check, like the
/// port check, declines.
fn probe_target(records: &SyncStateV3, host_id: &str) -> Result<Probe, String> {
    let TransportKind::GcpIap { project, zone, instance, interface, account, pam, .. } = transports::get(records, host_id).ok_or("This host has no transport.")?.kind;
    let host = repo::get_host(records, host_id).map_err(|error| error.to_string())?;
    if host.group_error.is_some() {
        return Err("Review the host’s group settings before checking it through IAP.".into());
    }
    Ok(Probe { target: IapTarget { project, zone, instance, interface, account, url_root: None }, port: host.effective_payload.port, requires_grant: pam.is_some() })
}

/// One of the places for connection checks at once, which the port check takes from too; with none free, the port check's sentence.
fn check_place() -> Result<tokio::sync::SemaphorePermit<'static>, String> {
    CHECKS.try_acquire().map_err(|_| BUSY.to_string())
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

/// What a check of `host_id`'s route needs, from the saved records (Records workspace only).
fn probe_target_of(app: &tauri::AppHandle, host_id: &str) -> Result<Probe, String> {
    let state = app.state::<AppState>();
    let core = state.sync.core.lock().unwrap();
    probe_target(core.records.as_ref().ok_or("The saved records are unavailable.")?, host_id)
}

/// The routes of the saved hosts (Records workspace only): what the Access grants section is made of.
fn host_routes(app: &tauri::AppHandle) -> Result<Vec<HostTransport>, String> {
    let state = app.state::<AppState>();
    let core = state.sync.core.lock().unwrap();
    live_routes(core.records.as_ref().ok_or("The saved records are unavailable.")?)
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

/// Requests a grant for `host_id`'s route and waits for it: on `entitlement`, which the route must list, or on the first it lists when
/// none is named (design 2026-10-26, Commands). The justification and length are remembered on this computer, never in the route.
#[tauri::command]
pub async fn transports_pam_request(app: tauri::AppHandle, window: tauri::WebviewWindow, host_id: String, justification: String, duration_secs: u32, entitlement: Option<String>) -> Result<PamStatusView, String> {
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
        pam_request(&*gcp, &remember, &transport, &justification, duration_secs, entitlement.as_deref())
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

/// The rows of the Google Cloud page's Access grants section (design 2026-10-26, Commands): one per entitlement the saved routes
/// require, with the state of the grant on it, read now. Google is asked once for each, as the account its routes name or, for routes
/// that name none, as gcloud's active account; every call is bounded by the client's own timeout and none asks the person for anything.
#[tauri::command]
pub async fn gcp_pam_grants(app: tauri::AppHandle, window: tauri::WebviewWindow) -> Result<Vec<PamGrantView>, String> {
    main_only(&window)?;
    tauri::async_runtime::spawn_blocking(move || {
        let routes = host_routes(&app)?;
        let gcp = app.state::<AppState>().gcp.clone();
        let active = auth::active_account(&gcloud_config_dir());
        Ok(pam_grants(&*gcp, active.as_deref(), &routes))
    })
    .await
    .map_err(|error| error.to_string())?
}

/// Checks whether this computer reaches the instance `host_id`'s route names, on the host's port, through IAP with its Google sign-in
/// (design 2026-10-26, Check through IAP): a tunnel is opened as the route's account and closed at once (`probe_iap`), for 20 s at most
/// and among the four connection checks at once the port check shares. It never requests a grant or asks for a sign-in, and attempts
/// no SSH. A refusal by IAP on a route that requires a grant says to request one.
#[tauri::command]
pub async fn transports_iap_probe(app: tauri::AppHandle, window: tauri::WebviewWindow, host_id: String) -> Result<IapProbeView, String> {
    main_only(&window)?;
    checked_host_id(&host_id)?;
    let tokens = app.state::<AppState>().gcp.tokens();
    let probe = tauri::async_runtime::spawn_blocking(move || probe_target_of(&app, &host_id)).await.map_err(|error| error.to_string())??;
    let _place = check_place()?;
    let view = probe_iap(&probe.target, probe.port, tokens, IAP_CHECK_BOUND).await;
    Ok(if probe.requires_grant { view.pointing_to_the_grant() } else { view })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gcp::auth::{AuthError, StaticToken, Token, TokenSource};
    use crate::gcp::oslogin::{LoginProfile, PosixAccount};
    use crate::gcp::pam::{self, Grant};
    use crate::gcp::rest::{GcpClient, GcpError};
    use crate::gcp::testing::{Behaviour, FakeRelay};
    use crate::sync::record_commands;
    use crate::sync::record_groups;
    use crate::sync::record_repository as repo;
    use crate::sync::records_v3::{GroupDefaults, GroupPayload, HostPayload, HostScope, SyncStateV3};
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

    /// The route of `host_id` that names `account` (none: gcloud's active one) and requires a grant on `entitlements`, in project
    /// `eng-dev-396409`, PAM location `global`.
    fn pam_route(host_id: &str, account: Option<&str>, entitlements: &[&str]) -> HostTransport {
        let mut route = with_pam(entitlements);
        route.host_id = host_id.into();
        let TransportKind::GcpIap { account: named, .. } = &mut route.kind;
        *named = account.map(str::to_string);
        route
    }

    /// `route` in another project and another PAM location.
    fn placed(mut route: HostTransport, project: &str, location: &str) -> HostTransport {
        let TransportKind::GcpIap { project: saved, pam, .. } = &mut route.kind;
        *saved = project.into();
        pam.as_mut().expect("a route that requires a grant").location = location.into();
        route
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

    /// One call to PAM as it was made: account, project, location, entitlement.
    type Call = (Option<String>, String, String, String);

    fn call(account: Option<&str>, project: &str, location: &str, entitlement: &str) -> Call {
        (account.map(str::to_string), project.into(), location.into(), entitlement.into())
    }

    /// PAM for the Access grants rows and for requesting a chosen entitlement, which are not tied to one account, project or location as
    /// `Pam` is: every search and every request is recorded as it was made, an entitlement's grants (or PAM's refusal) are what was set
    /// for its id (none set: it holds none), and a grant requested is active at once, as when PAM approves on the spot.
    #[derive(Default)]
    struct FakeGcp {
        answers: Mutex<BTreeMap<String, Result<Vec<Grant>, String>>>,
        searched: Mutex<Vec<Call>>,
        created: Mutex<Vec<(Call, u32, String)>>,
    }

    impl FakeGcp {
        /// `entitlement` holds a grant that began a minute ago and lasts 30 minutes; the others hold none.
        fn active_on(entitlement: &str) -> FakeGcp {
            let gcp = FakeGcp::default();
            gcp.answering(entitlement, Ok(vec![grant("g-active", "ACTIVE", Some(SystemTime::now() - Duration::from_secs(60)), 1800)]));
            gcp
        }
        /// No entitlement holds a grant; one requested is active at once.
        fn grants_at_once() -> FakeGcp {
            FakeGcp::default()
        }
        fn answering(&self, entitlement: &str, grants: Result<Vec<Grant>, &str>) {
            self.answers.lock().unwrap().insert(entitlement.into(), grants.map_err(str::to_string));
        }
        fn searched(&self) -> Vec<Call> {
            self.searched.lock().unwrap().clone()
        }
        fn created(&self) -> Vec<(Call, u32, String)> {
            self.created.lock().unwrap().clone()
        }
    }

    impl GcpClient for FakeGcp {
        fn login_profile(&self, _: Option<&str>, _: &str) -> Result<LoginProfile, GcpError> {
            panic!("grants never read OS Login")
        }
        fn import_ssh_public_key(&self, _: Option<&str>, _: &str, _: &str) -> Result<LoginProfile, GcpError> {
            panic!("grants never import a key")
        }
        fn grants(&self, account: Option<&str>, project: &str, location: &str, entitlement: &str) -> Result<Vec<Grant>, GcpError> {
            self.searched.lock().unwrap().push(call(account, project, location, entitlement));
            match self.answers.lock().unwrap().get(entitlement) {
                Some(Ok(grants)) => Ok(grants.clone()),
                Some(Err(message)) => Err(Pam::refusal(message)),
                None => Ok(Vec::new()),
            }
        }
        fn create_grant(&self, account: Option<&str>, project: &str, location: &str, entitlement: &str, duration_secs: u32, justification: &str) -> Result<Grant, GcpError> {
            self.created.lock().unwrap().push((call(account, project, location, entitlement), duration_secs, justification.into()));
            let name = format!("projects/{project}/locations/{location}/entitlements/{entitlement}/grants/g1");
            Ok(grant(&name, "ACTIVE", Some(SystemTime::now()), duration_secs))
        }
        fn get_grant(&self, _: Option<&str>, _: &str) -> Result<Grant, GcpError> {
            panic!("a grant requested is active at once, so none is read back")
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
        let view = pam_request_with(&gcp, &remember, &with_pam(&["prod-operate", "prod-admin"]), "restart app-api after the deploy", 2700, None, &|| false, Duration::from_millis(1), Duration::from_secs(5)).unwrap();
        assert_eq!((view.state.as_str(), view.entitlement.as_deref(), view.message), ("active", Some("prod-operate"), None));
        assert!(view.active_until_ms.is_some_and(|until| until >= ms(before + Duration::from_secs(2700)) - 1000), "{:?}", view.active_until_ms);
        assert_eq!(gcp.created.lock().unwrap().as_slice(), [("prod-operate".to_string(), 2700, "restart app-api after the deploy".to_string())]);
        assert_eq!(gcp.read.lock().unwrap().len(), 2, "read back until ACTIVE");
        assert_eq!(remembered.lock().unwrap().as_slice(), [("restart app-api after the deploy".to_string(), 2700)]);
        // A grant that will not become active: its state, in the sentence the connect uses too.
        let denied = Pam::default();
        *denied.states.lock().unwrap() = ["DENIED"].into();
        let error = pam_request_with(&denied, &remember, &with_pam(&["prod-operate"]), "x", 1800, None, &|| false, Duration::from_millis(1), Duration::from_secs(5)).err();
        assert_eq!(error, Some("The prod-operate grant did not become active (state: DENIED).".to_string()));
        assert_eq!(remembered.lock().unwrap().len(), 2, "a request that ended denied was still a request, and is remembered");
        // A transport without a PAM check has nothing to request.
        let error = pam_request_with(&gcp, &remember, &iap(), "x", 1800, None, &|| false, Duration::from_millis(1), Duration::from_secs(5)).err();
        assert_eq!(error, Some("This transport requires no grant.".to_string()));
        assert_eq!(remembered.lock().unwrap().len(), 2, "nothing more was remembered");
    }

    /// A grant that is already in flight (requested by hand, or by a connection a moment ago) is used, not requested again, and the
    /// request is not remembered on this computer: nothing was asked of PAM.
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
        let view = pam_request_with(&gcp, &remember, &with_pam(&["prod-operate", "prod-admin"]), "restart app-api", 2700, None, &|| false, Duration::from_millis(1), Duration::from_secs(5)).unwrap();
        assert_eq!((view.state.as_str(), view.entitlement.as_deref()), ("active", Some("prod-operate")));
        assert_eq!(view.active_until_ms, Some(ends(now - Duration::from_secs(60), 1800)), "the grant's own end, not the duration asked for");
        assert!(gcp.created.lock().unwrap().is_empty(), "nothing was requested");
        assert!(gcp.read.lock().unwrap().is_empty(), "nothing was read back");
        assert!(remembered.lock().unwrap().is_empty(), "nothing to remember");
    }

    /// Design 2026-10-26 (`gcp_pam_grants`): the Access grants section has one row per entitlement the routes name, whichever hosts name
    /// it. An entitlement is the account, project, location and entitlement id together, and a route that names no account is gcloud's
    /// active account's, so it shares its rows with the routes that name that account. Each row is read from Google once.
    #[test]
    fn grants_are_one_row_per_entitlement_across_routes() {
        let routes = [pam_route("0000000000000001", None, &["prod-operate", "prod-admin"]), pam_route("0000000000000002", Some("frank@example.com"), &["prod-operate"])];
        let gcp = FakeGcp::active_on("prod-operate");
        let rows = pam_grants(&gcp, Some("frank@example.com"), &routes);
        let operate = rows.iter().find(|r| r.entitlement == "prod-operate").unwrap();
        assert_eq!(operate.host_ids, ["0000000000000001", "0000000000000002"]);
        assert_eq!(operate.state, "active");
        assert_eq!(rows.iter().filter(|r| r.entitlement == "prod-admin").count(), 1);
        // Rows come in the order the routes list their entitlements; the route that names no account is searched as the account it
        // resolves to, and each row is searched once.
        assert_eq!(rows.iter().map(|r| r.entitlement.as_str()).collect::<Vec<_>>(), ["prod-operate", "prod-admin"]);
        assert_eq!(
            gcp.searched(),
            [call(Some("frank@example.com"), "eng-dev-396409", "global", "prod-operate"), call(Some("frank@example.com"), "eng-dev-396409", "global", "prod-admin")]
        );
    }

    /// What the page reads of a row: the account the grants were searched as, the entitlement's address, its state, and the hosts that
    /// need it.
    #[test]
    fn a_row_carries_what_the_page_reads() {
        let granted = SystemTime::now() - Duration::from_secs(300);
        let gcp = FakeGcp::default();
        gcp.answering("prod-operate", Ok(vec![grant("g", "ACTIVE", Some(granted), 1800)]));
        gcp.answering("prod-admin", Err("quota exceeded"));
        let rows = pam_grants(&gcp, Some("frank@example.com"), &[pam_route("0000000000000001", None, &["prod-operate", "prod-admin"])]);
        assert_eq!(
            serde_json::to_value(&rows).unwrap(),
            json!([
                {
                    "account": "frank@example.com", "project": "eng-dev-396409", "location": "global", "entitlement": "prod-operate",
                    "state": "active", "active_until_ms": ends(granted, 1800), "message": null, "host_ids": ["0000000000000001"],
                },
                {
                    "account": "frank@example.com", "project": "eng-dev-396409", "location": "global", "entitlement": "prod-admin",
                    "state": "error", "active_until_ms": null, "message": Pam::refusal("quota exceeded").to_string(), "host_ids": ["0000000000000001"],
                },
            ])
        );
    }

    /// "As `pam_status` decides it": a row is what `pam_status` reports over a route that lists only that entitlement, for every kind of
    /// answer: the longest of several active grants, an active one PAM did not date, one still on its way, none (an ended grant, and an
    /// active one whose time is up, are no grant), and the API's own sentence when the search is refused.
    #[test]
    fn a_row_is_decided_as_pam_status_decides_it() {
        let now = SystemTime::now();
        let ago = |secs: u64| Some(now - Duration::from_secs(secs));
        let gcp = FakeGcp::default();
        gcp.answering("two-active", Ok(vec![grant("g-old", "ENDED", ago(7200), 1800), grant("g-short", "ACTIVE", ago(600), 1800), grant("g-long", "ACTIVE", ago(300), 3600)]));
        gcp.answering("undated", Ok(vec![grant("g", "ACTIVE", None, 1800)]));
        gcp.answering("activating", Ok(vec![grant("g", "ACTIVATING", None, 1800)]));
        gcp.answering("scheduled", Ok(vec![grant("g", "SCHEDULED", None, 1800)]));
        gcp.answering("nothing-live", Ok(vec![grant("g-end", "ENDED", ago(7200), 1800), grant("g-stale", "ACTIVE", ago(7200), 1800)]));
        gcp.answering("refused", Err("quota exceeded"));
        let names = ["two-active", "undated", "activating", "scheduled", "nothing-live", "refused", "no-grants-at-all"];
        let rows = pam_grants(&gcp, Some("frank@example.com"), &[pam_route("0000000000000001", None, &names)]);
        assert_eq!(rows.iter().map(|r| r.entitlement.as_str()).collect::<Vec<_>>(), names);
        for row in &rows {
            let alone = pam_status(&gcp, &pam_route("0000000000000001", Some("frank@example.com"), &[row.entitlement.as_str()]));
            assert_eq!((row.state.as_str(), row.active_until_ms, row.message.as_deref()), (alone.state.as_str(), alone.active_until_ms, alone.message.as_deref()), "{}", row.entitlement);
        }
        // And what they are, so that the two cannot drift together.
        let states: Vec<_> = rows.iter().map(|r| (r.state.as_str(), r.active_until_ms)).collect();
        let long = Some(ends(now - Duration::from_secs(300), 3600));
        assert_eq!(states, [("active", long), ("active", None), ("activating", None), ("activating", None), ("none", None), ("error", None), ("none", None)]);
        assert_eq!(rows[5].message, Some(Pam::refusal("quota exceeded").to_string()));
        assert!(rows.iter().enumerate().all(|(index, row)| (index == 5) == row.message.is_some()), "only the refused search carries a sentence");
    }

    /// An entitlement is its account, project, location and id together: the same id under another account, project or location is a
    /// row of its own, searched on its own. A route that names no account while gcloud has no active one is searched as it is, no
    /// account, which the client resolves as it does for a connection.
    #[test]
    fn rows_stay_apart_when_the_account_project_or_location_differ() {
        let routes = [
            pam_route("0000000000000001", None, &["prod-operate"]),
            pam_route("0000000000000002", Some("ann@example.com"), &["prod-operate"]),
            placed(pam_route("0000000000000003", Some("ann@example.com"), &["prod-operate"]), "other-project-123456", "global"),
            placed(pam_route("0000000000000004", Some("ann@example.com"), &["prod-operate"]), "eng-dev-396409", "europe-west1"),
        ];
        let gcp = FakeGcp::default();
        let rows = pam_grants(&gcp, None, &routes);
        let places: Vec<_> = rows.iter().map(|r| (r.account.as_deref(), r.project.as_str(), r.location.as_str(), r.host_ids.clone())).collect();
        assert_eq!(
            places,
            [
                (None, "eng-dev-396409", "global", vec!["0000000000000001".to_string()]),
                (Some("ann@example.com"), "eng-dev-396409", "global", vec!["0000000000000002".to_string()]),
                (Some("ann@example.com"), "other-project-123456", "global", vec!["0000000000000003".to_string()]),
                (Some("ann@example.com"), "eng-dev-396409", "europe-west1", vec!["0000000000000004".to_string()]),
            ]
        );
        assert_eq!(
            gcp.searched(),
            [
                call(None, "eng-dev-396409", "global", "prod-operate"),
                call(Some("ann@example.com"), "eng-dev-396409", "global", "prod-operate"),
                call(Some("ann@example.com"), "other-project-123456", "global", "prod-operate"),
                call(Some("ann@example.com"), "eng-dev-396409", "europe-west1", "prod-operate"),
            ]
        );
        // Once gcloud's active account is known, the first route is ann's and shares her row.
        let gcp = FakeGcp::default();
        let rows = pam_grants(&gcp, Some("ann@example.com"), &routes);
        assert_eq!(rows.len(), 3);
        assert_eq!((rows[0].account.as_deref(), rows[0].host_ids.as_slice()), (Some("ann@example.com"), ["0000000000000001".to_string(), "0000000000000002".to_string()].as_slice()));
        assert_eq!(gcp.searched().len(), 3);
    }

    /// A route that requires no grant has no row, and nothing is asked of Google for it; an entitlement a route lists twice is one row
    /// that names the host once.
    #[test]
    fn a_route_without_a_grant_check_has_no_row_and_a_host_is_named_once() {
        let gcp = FakeGcp::default();
        assert!(pam_grants(&gcp, Some("frank@example.com"), &[]).is_empty());
        assert!(pam_grants(&gcp, Some("frank@example.com"), &[iap()]).is_empty());
        assert!(gcp.searched().is_empty(), "no grant is required, so nothing is searched");
        let rows = pam_grants(&gcp, Some("frank@example.com"), &[iap(), pam_route("0000000000000002", None, &["prod-operate", "prod-operate"])]);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].host_ids, ["0000000000000002"]);
        assert_eq!(gcp.searched().len(), 1);
    }

    /// Design 2026-10-26 (`transports_pam_request`): a request is for the entitlement the person chose, which the route must list, and
    /// the answer names it; left out, it is the first, as the connect asks (`pam_request_requests_the_first_entitlement_...`).
    #[test]
    fn a_request_asks_for_the_chosen_listed_entitlement() {
        let route = pam_route("0000000000000001", None, &["prod-operate", "prod-admin"]);
        let remembered = Mutex::new(Vec::new());
        let remember = |justification: &str, duration_secs: u32| {
            remembered.lock().unwrap().push((justification.to_string(), duration_secs));
            Ok(())
        };
        let gcp = FakeGcp::grants_at_once();
        let view = pam_request_with(&gcp, &remember, &route, "Deploy hotfix", 1800, Some("prod-admin"), &|| false, Duration::ZERO, Duration::from_secs(1)).unwrap();
        assert_eq!((view.state.as_str(), view.entitlement.as_deref(), view.message), ("active", Some("prod-admin"), None));
        assert!(view.active_until_ms.is_some());
        // The entitlement chosen was the one searched and requested, with the form's words, and what was asked is remembered.
        assert_eq!(gcp.searched(), [call(None, "eng-dev-396409", "global", "prod-admin")]);
        assert_eq!(gcp.created(), [(call(None, "eng-dev-396409", "global", "prod-admin"), 1800, "Deploy hotfix".to_string())]);
        assert_eq!(remembered.lock().unwrap().as_slice(), [("Deploy hotfix".to_string(), 1800)]);
        // One the route does not list is refused before Google is asked anything, and nothing is remembered.
        for unlisted in ["other", "PROD-ADMIN", ""] {
            let untouched = FakeGcp::grants_at_once();
            let error = pam_request_with(&untouched, &remember, &route, "x", 1800, Some(unlisted), &|| false, Duration::ZERO, Duration::from_secs(1)).err();
            assert_eq!(error, Some("This transport does not list that entitlement.".to_string()), "{unlisted:?}");
            assert!(untouched.searched().is_empty() && untouched.created().is_empty(), "{unlisted:?}");
        }
        assert_eq!(remembered.lock().unwrap().len(), 1, "a refused request remembers nothing");
        // A route that requires no grant has nothing to choose.
        let error = pam_request_with(&gcp, &remember, &iap(), "x", 1800, Some("prod-admin"), &|| false, Duration::ZERO, Duration::from_secs(1)).err();
        assert_eq!(error, Some("This transport requires no grant.".to_string()));
    }

    /// Design 2026-10-26 (Deleting a host): the page ignores a route whose host is gone, as the Catalog's tunnels tolerate orphans, so
    /// no row names a host the person cannot see.
    #[test]
    fn the_grants_page_ignores_a_route_whose_host_is_gone() {
        let host: HostPayload = serde_json::from_value(json!({"schema": 2, "alias": "prod-jump", "hostname": "prod-jump.example.com", "auth": "password"})).unwrap();
        let gone = "0000000000000002";
        let saved = repo::create_host(&state(), HOST, HostScope::Local, host, 1).unwrap();
        let saved = transports::set(&saved, HOST, None, Some(pam_route(HOST, None, &["prod-operate"])), 2).unwrap();
        let saved = transports::set(&saved, gone, None, Some(pam_route(gone, None, &["prod-operate"])), 3).unwrap();
        assert_eq!(transports::view(&saved).len(), 2, "the library holds both routes");
        assert_eq!(live_routes(&saved).unwrap(), [pam_route(HOST, None, &["prod-operate"])]);
        let rows = pam_grants(&FakeGcp::default(), Some("frank@example.com"), &live_routes(&saved).unwrap());
        assert_eq!(rows.iter().map(|r| r.host_ids.clone()).collect::<Vec<_>>(), [vec![HOST.to_string()]]);
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
    /// the token source by name; the active account; a service account, and folders that are no email address (R31: the picker offers
    /// only accounts a route accepts, and R32: this layer is the one that knows what a route can name, while `credentialed_accounts` is
    /// gcloud's own view), listed by nobody and asked about by nobody.
    #[tokio::test]
    async fn gcloud_accounts_lists_each_account_with_its_sign_in_state_and_the_active_one() {
        let not_emails = ["default", "frank@localhost", "frank smith@example.com"];
        let mut folders = vec!["ops@example.com", "frank@example.com", "late@example.com"];
        folders.extend(not_emails);
        let dir = gcloud_dir(&folders, Some("ops@example.com"));
        // gcloud's own view has them (good `authorized_user` files all); only the command's filter keeps them out.
        let gcloud_sees = auth::credentialed_accounts(dir.path());
        assert!(not_emails.iter().all(|name| gcloud_sees.iter().any(|seen| seen == name)), "{gcloud_sees:?}");
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

    /// A TCP server that echoes everything, on the test's runtime: the instance's port, which the fake relay connects to (the one the
    /// `gcp::iap` tests use).
    async fn echo_server() -> u16 {
        let listener = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            while let Ok((mut socket, _)) = listener.accept().await {
                tokio::spawn(async move {
                    let (mut read, mut write) = socket.split();
                    let _ = tokio::io::copy(&mut read, &mut write).await;
                });
            }
        });
        port
    }

    /// The instance of `iap()` as the account `account` reaches it, through `relay`: nothing in these tests may reach Google's own relay.
    fn iap_target(relay: &FakeRelay, account: Option<&str>) -> IapTarget {
        IapTarget {
            project: "eng-dev-396409".into(),
            zone: "asia-east1-b".into(),
            instance: "jumpbox".into(),
            interface: "nic0".into(),
            account: account.map(str::to_string),
            url_root: Some(relay.url_root.clone()),
        }
    }

    /// The token the fake relay accepts.
    fn tokens() -> Arc<dyn TokenSource> {
        Arc::new(StaticToken(TOKEN.into()))
    }

    /// Design 2026-10-26 (Check through IAP): the check opens a tunnel and closes it. A relay that connects is `reachable`; one that
    /// refuses the handshake with 403, or closes the tunnel with 4033 instead of announcing the session, is IAP refusing the account
    /// (`denied`); any other end of the open, 4003 "failed to connect to backend" for one, is `unreachable` with the relay's reason.
    /// (The Close that ends the open is `CloseAtOpen`: `CloseAfter` comes after the announcement, when the open is over, see below.)
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_probe_reports_reachable_denied_and_unreachable() {
        let relay = FakeRelay::start(echo_server().await, TOKEN);
        let target = iap_target(&relay, None);
        let began = ms(SystemTime::now());
        let reachable = probe_iap(&target, 22, tokens(), Duration::from_secs(5)).await;
        assert_eq!((reachable.status.as_str(), reachable.message.as_deref()), ("reachable", None));
        assert!(reachable.latency_ms.is_some_and(|latency| latency <= reachable.elapsed_ms), "{reachable:?}");
        assert!(reachable.checked_at_ms >= began && reachable.checked_at_ms <= ms(SystemTime::now()), "{reachable:?}");
        assert_eq!(relay.connects(), 1);

        relay.set(Behaviour::RefuseHandshake(403));
        let refused = probe_iap(&target, 22, tokens(), Duration::from_secs(5)).await;
        assert_eq!((refused.status.as_str(), refused.latency_ms, refused.message.as_deref()), ("denied", None, Some("IAP refused this Google account.")));

        relay.set(Behaviour::CloseAtOpen(4033, "not authorized"));
        let unauthorized = probe_iap(&target, 22, tokens(), Duration::from_secs(5)).await;
        assert_eq!((unauthorized.status.as_str(), unauthorized.latency_ms, unauthorized.message.as_deref()), ("denied", None, Some("IAP refused this Google account.")));

        relay.set(Behaviour::CloseAtOpen(4003, "failed to connect to backend"));
        let unreachable = probe_iap(&target, 22, tokens(), Duration::from_secs(5)).await;
        assert_eq!(
            (unreachable.status.as_str(), unreachable.latency_ms, unreachable.message.as_deref()),
            ("unreachable", None, Some("the relay closed the tunnel (4003: failed to connect to backend)"))
        );

        // Anything else that ends the open says what it was.
        relay.set(Behaviour::RefuseHandshake(503));
        let failed = probe_iap(&target, 22, tokens(), Duration::from_secs(5)).await;
        assert_eq!((failed.status.as_str(), failed.message.as_deref()), ("unreachable", Some("the relay refused the WebSocket handshake with HTTP 503")));
    }

    /// The tunnel is asked for the port the check is given, on the instance the target names: read off the connect request a relay
    /// that hangs up receives (the fake relay answers any port, so it cannot tell). A relay that hangs up is `unreachable`.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_probe_asks_the_relay_for_the_given_port_of_the_targets_instance() {
        use tokio::io::AsyncReadExt;
        let listener = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let url_root = format!("ws://127.0.0.1:{}/v4", listener.local_addr().unwrap().port());
        let request_line = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let (mut seen, mut buffer) = (Vec::new(), [0u8; 1024]);
            while !seen.windows(4).any(|end| end == b"\r\n\r\n") {
                match socket.read(&mut buffer).await.unwrap() {
                    0 => break,
                    count => seen.extend_from_slice(&buffer[..count]),
                }
            }
            String::from_utf8_lossy(&seen).lines().next().unwrap_or_default().to_string()
        });
        let target = IapTarget {
            project: "eng-dev-396409".into(),
            zone: "asia-east1-b".into(),
            instance: "jumpbox".into(),
            interface: "nic1".into(),
            account: None,
            url_root: Some(url_root),
        };
        let view = probe_iap(&target, 2222, tokens(), Duration::from_secs(5)).await;
        assert_eq!(view.status, "unreachable", "{view:?}");
        let line = request_line.await.unwrap();
        assert!(line.starts_with("GET /v4/connect?"), "{line}");
        for wanted in ["project=eng-dev-396409", "port=2222", "zone=asia-east1-b", "instance=jumpbox", "interface=nic1"] {
            assert!(line.contains(wanted), "{wanted} in {line}");
        }
    }

    /// "Reachable" is the relay having connected to the instance's port, which is when it announces the session. A Close that follows
    /// the announcement (`CloseAfter`) ends a tunnel that was open; it does not undo the connection the check is about.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_close_after_the_session_is_announced_does_not_undo_the_connection() {
        let relay = FakeRelay::start(echo_server().await, TOKEN);
        relay.set(Behaviour::CloseAfter(0, 4033, "not authorized"));
        let view = probe_iap(&iap_target(&relay, None), 22, tokens(), Duration::from_secs(5)).await;
        assert_eq!((view.status.as_str(), view.message.as_deref()), ("reachable", None));
    }

    /// The check opens the tunnel as the account the route names (none: gcloud's active account, as a connection asks), with Lunport's
    /// user agent, and leaves nothing open at the relay: the tunnel is closed at once.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_probe_opens_the_tunnel_as_the_routes_account_and_closes_it() {
        let relay = FakeRelay::start(echo_server().await, TOKEN);
        let named = Arc::new(Answers::ok());
        let view = probe_iap(&iap_target(&relay, Some("frank@retower.io")), 22, named.clone(), Duration::from_secs(5)).await;
        assert_eq!(view.status, "reachable");
        assert_eq!(named.asked(), [Some("frank@retower.io".to_string())]);
        let user_agent = relay.last_headers().into_iter().find(|(name, _)| name == "user-agent").map(|(_, value)| value);
        assert_eq!(user_agent, Some(auth::user_agent()));
        let deadline = Instant::now() + Duration::from_secs(3);
        while relay.open_connections() > 0 && Instant::now() < deadline {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert_eq!(relay.open_connections(), 0, "the relay saw the socket go");
        let active = Arc::new(Answers::ok());
        probe_iap(&iap_target(&relay, None), 22, active.clone(), Duration::from_secs(5)).await;
        assert_eq!(active.asked(), [None], "a route that names no account asks for gcloud's active one");
        assert_eq!(relay.connects(), 2);
    }

    /// A sign-in that gives no token is `denied` with the sentence the person is used to (`gcloud auth login <account>`), and the relay
    /// is never asked.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_sign_in_that_gives_no_token_is_denied_with_its_sentence() {
        let relay = FakeRelay::start(echo_server().await, TOKEN);
        let expired = AuthError::SignInExpired { account: "frank@retower.io".into() };
        let sentence = expired.to_string();
        let view = probe_iap(&iap_target(&relay, Some("frank@retower.io")), 22, Arc::new(Answers::err(expired)), Duration::from_secs(5)).await;
        assert_eq!((view.status.as_str(), view.latency_ms, view.message), ("denied", None, Some(sentence)));
        assert_eq!(relay.connects(), 0, "without a token nothing reached the relay");
    }

    /// The check is bounded: a relay that opens the WebSocket and never announces the session is `unreachable` once the time is up.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_relay_that_does_not_answer_is_unreachable_when_the_time_is_up() {
        let relay = FakeRelay::start(echo_server().await, TOKEN);
        relay.set(Behaviour::NeverSucceed);
        let started = Instant::now();
        let view = probe_iap(&iap_target(&relay, None), 22, tokens(), Duration::from_millis(300)).await;
        let waited = started.elapsed();
        assert_eq!((view.status.as_str(), view.latency_ms, view.message.as_deref()), ("unreachable", None, Some("IAP did not answer in time.")));
        assert!(waited >= Duration::from_millis(300) && waited < Duration::from_secs(2), "bounded by the deadline asked for: {waited:?}");
        assert!(view.elapsed_ms >= 300, "{view:?}");
    }

    /// What the pane reads, whichever way the check ended, and never the token the tunnel was opened with.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_view_carries_what_the_pane_reads_and_no_token() {
        let relay = FakeRelay::start(echo_server().await, TOKEN);
        for behaviour in [Behaviour::Bridge, Behaviour::RefuseHandshake(403), Behaviour::CloseAtOpen(4003, "failed to connect to backend"), Behaviour::NeverSucceed] {
            relay.set(behaviour);
            let view = probe_iap(&iap_target(&relay, None), 22, tokens(), Duration::from_millis(500)).await;
            let wire = serde_json::to_value(&view).unwrap();
            let keys: Vec<&str> = wire.as_object().unwrap().keys().map(String::as_str).collect();
            assert_eq!(keys, ["checked_at_ms", "elapsed_ms", "latency_ms", "message", "status"], "{behaviour:?}");
            assert!(wire["elapsed_ms"].is_u64() && wire["checked_at_ms"].is_u64(), "{wire}");
            let text = wire.to_string();
            assert!(!text.contains(TOKEN) && !format!("{view:?}").contains(TOKEN), "{behaviour:?}: {text}");
        }
        let offline = Arc::new(Answers::err(AuthError::Network("offline".into())));
        let view = probe_iap(&iap_target(&relay, None), 22, offline, Duration::from_millis(500)).await;
        assert!(!serde_json::to_string(&view).unwrap().contains(TOKEN));
    }

    /// For a route that requires a grant, IAP's refusal points to requesting one: a grant that ended or never came is the usual reason
    /// a signed-in account is refused. A sign-in that failed is not a missing grant, and nothing but a refusal gets the pointer.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn only_a_refusal_by_iap_points_to_requesting_a_grant() {
        let relay = FakeRelay::start(echo_server().await, TOKEN);
        let target = iap_target(&relay, None);
        relay.set(Behaviour::RefuseHandshake(403));
        let refused = probe_iap(&target, 22, tokens(), Duration::from_secs(5)).await;
        assert_eq!(refused.clone().pointing_to_the_grant().message.as_deref(), Some("IAP refused this Google account. Request a grant, then check again."));
        relay.set(Behaviour::CloseAtOpen(4033, "not authorized"));
        let unauthorized = probe_iap(&target, 22, tokens(), Duration::from_secs(5)).await;
        assert_eq!(unauthorized.pointing_to_the_grant().message.as_deref(), Some("IAP refused this Google account. Request a grant, then check again."));

        let expired = probe_iap(&target, 22, Arc::new(Answers::err(AuthError::SignInExpired { account: "frank@retower.io".into() })), Duration::from_secs(5)).await;
        assert_eq!(expired.clone().pointing_to_the_grant(), expired, "a sign-in that failed is not a missing grant");
        relay.set(Behaviour::CloseAtOpen(4003, "failed to connect to backend"));
        let unreachable = probe_iap(&target, 22, tokens(), Duration::from_secs(5)).await;
        assert_eq!(unreachable.clone().pointing_to_the_grant(), unreachable);
        relay.set(Behaviour::Bridge);
        let reachable = probe_iap(&target, 22, tokens(), Duration::from_secs(5)).await;
        assert_eq!(reachable.clone().pointing_to_the_grant(), reachable);
    }

    /// A library with host `HOST` saved with `port` and `route` as its route.
    fn saved_with(port: u16, route: HostTransport) -> SyncStateV3 {
        let host: HostPayload = serde_json::from_value(json!({"schema": 2, "alias": "prod-jump", "hostname": "prod-jump.example.com", "port": port, "auth": "password"})).unwrap();
        let saved = repo::create_host(&state(), HOST, HostScope::Local, host, 1).unwrap();
        transports::set(&saved, HOST, None, Some(route), 2).unwrap()
    }

    /// The tunnel goes to the instance the route names, as the account it names, on the port the host is saved with, which a connection
    /// dials too; a route with a grant check says so, so that a refusal can point to it.
    #[test]
    fn a_check_goes_to_the_routes_instance_on_the_hosts_port() {
        let saved = saved_with(2222, pam_route(HOST, Some("frank@retower.io"), &["prod-operate"]));
        let probe = probe_target(&saved, HOST).unwrap();
        let instance = |account: Option<&str>| IapTarget {
            project: "eng-dev-396409".into(),
            zone: "asia-east1-b".into(),
            instance: "jumpbox".into(),
            interface: "nic0".into(),
            account: account.map(str::to_string),
            url_root: None,
        };
        assert_eq!(probe.target, instance(Some("frank@retower.io")));
        assert_eq!((probe.port, probe.requires_grant), (2222, true));
        let plain = probe_target(&saved_with(22, iap()), HOST).unwrap();
        assert_eq!((plain.target, plain.port, plain.requires_grant), (instance(None), 22, false));
        // The endpoint it makes carries that port, and no URL root of a fake.
        let endpoint = probe.target.endpoint(probe.port);
        assert_eq!((endpoint.port, endpoint.url_root), (2222, None));
    }

    /// A port the host's group supplies is the effective one; a group that cannot be resolved leaves no effective port, so the check
    /// refuses to guess one (the port check refuses in the same case).
    #[test]
    fn a_port_the_hosts_group_supplies_is_the_one_checked() {
        let group = "00000000000000a1";
        let defaults = GroupDefaults { port: Some(2200), ..GroupDefaults::default() };
        let payload = GroupPayload { schema: 1, name: "Prod".into(), parent_id: None, defaults };
        let grouped = record_groups::create_group(&state(), group, HostScope::Local, payload, true, 1).unwrap();
        let host: HostPayload = serde_json::from_value(json!({"schema": 3, "alias": "prod-jump", "hostname": "prod-jump.example.com", "port": 22, "auth": "password", "group_id": group, "inherit": ["port"]})).unwrap();
        let saved = repo::create_host(&grouped, HOST, HostScope::Local, host, 2).unwrap();
        let saved = transports::set(&saved, HOST, None, Some(iap()), 3).unwrap();
        assert_eq!(probe_target(&saved, HOST).unwrap().port, 2200, "the group's port, not the 22 the host itself holds");
        let mut broken = saved.clone();
        broken.local.groups.clear();
        assert_eq!(probe_target(&broken, HOST).err(), Some("Review the host’s group settings before checking it through IAP.".to_string()));
    }

    /// A host with no route has no tunnel to check; a route whose host is gone has no port to check.
    #[test]
    fn a_host_without_a_route_or_a_route_without_a_host_has_nothing_to_check() {
        let host: HostPayload = serde_json::from_value(json!({"schema": 2, "alias": "prod-jump", "hostname": "prod-jump.example.com", "auth": "password"})).unwrap();
        let plain = repo::create_host(&state(), HOST, HostScope::Local, host, 1).unwrap();
        assert_eq!(probe_target(&plain, HOST).err(), Some("This host has no transport.".to_string()));
        let orphan = transports::set(&state(), HOST, None, Some(iap()), 1).unwrap();
        assert!(probe_target(&orphan, HOST).is_err());
    }

    /// The check takes one of the four places the port check takes from, and the port check's sentence says when none is free.
    #[test]
    fn a_check_through_iap_shares_the_port_checks_four_places() {
        let all_four = CHECKS.try_acquire_many(4).expect("no check is running in a test");
        assert_eq!(check_place().err(), Some("Four connection checks are already running. Try again shortly.".to_string()));
        drop(all_four);
        let first = check_place().expect("a place is free again");
        let rest = CHECKS.try_acquire_many(3).expect("one place is taken, three are free");
        assert!(check_place().is_err(), "the fourth place was the check's own");
        drop((first, rest));
        assert_eq!(CHECKS.available_permits(), 4);
    }
}
