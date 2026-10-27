//! The Google Cloud page's Access tab (design 2026-10-27, The Access tab; The PAM commands): Privileged Access Manager on its own, not
//! through a host. `overview` lists every entitlement the person may request, searched in the scopes the routes use (their projects, as
//! their accounts) and in the scopes the person added, with the entitlements the routes name even when the search does not return
//! them; each with the state of the grants on it, the hosts that need it and the memory of its last request. `gcp_pam_request` requests
//! on one of them by its full name, and remembers the request in the library.
//!
//! Every Google call is bounded by the client's own timeout; the overview makes at most `PARALLEL` at once and starts none after
//! `OVERVIEW_BOUND`, and none asks the person anything.

use std::collections::BTreeMap;
use std::sync::Mutex;
use std::time::{Duration, Instant, SystemTime};

use serde::Serialize;
use tauri::Manager;

use super::transports::{self as commands, PamStatusView, Standing};
use crate::gcp::pam::{self, EntitlementInfo, EntitlementName};
use crate::gcp::rest::GcpClient;
use crate::state::AppState;
use crate::sync::pam_records::{self, GrantRequestMemory, PamScope};
use crate::sync::record_commands::RecordOverview;
use crate::sync::transports::{self, HostTransport, TransportKind};

/// How many calls the overview makes at once.
const PARALLEL: usize = 4;
/// After this long the overview starts no more calls: what is left reads as not answered in time.
const OVERVIEW_BOUND: Duration = Duration::from_secs(60);
/// What a scope or an entitlement the overview did not get to says.
const LATE: &str = "Google did not answer in time.";
/// A grant's length when nothing else says one: the route's own default.
const DEFAULT_SECS: u32 = 30 * 60;

/// One place the Access tab looks: a scope routes use (`from_routes`, the hosts whose routes use it, no id) or one the person added (its
/// id, the account as saved: none is gcloud's active account), and the search's sentence when it failed.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[cfg_attr(test, derive(ts_rs::TS))]
#[cfg_attr(test, ts(export, export_to = "../../src/bindings/"))]
pub struct PamScopeView {
    pub id: Option<String>,
    pub parent: String,
    pub location: String,
    pub account: Option<String>,
    pub from_routes: bool,
    pub host_ids: Vec<String>,
    pub message: Option<String>,
}

/// A role a grant gives, and the resource it is given on.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[cfg_attr(test, derive(ts_rs::TS))]
#[cfg_attr(test, ts(export, export_to = "../../src/bindings/"))]
pub struct PamRoleView {
    pub role: String,
    pub resource: String,
}

/// One entitlement the person may request, as one account (none: gcloud's active account, when it has none either).
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[cfg_attr(test, derive(ts_rs::TS))]
#[cfg_attr(test, ts(export, export_to = "../../src/bindings/"))]
pub struct PamEntitlementView {
    pub account: Option<String>,
    /// The full name, `<parent>/locations/<location>/entitlements/<id>`.
    pub name: String,
    pub parent: String,
    pub location: String,
    pub entitlement: String,
    /// The most a request may ask for, when the search said.
    pub max_duration_secs: Option<u32>,
    pub needs_approval: bool,
    pub roles: Vec<PamRoleView>,
    /// `active` (with its end), `activating`, `approval_awaited`, `none`, or `error` (with the API's sentence).
    pub state: String,
    #[cfg_attr(test, ts(type = "number | null"))]
    pub active_until_ms: Option<u64>,
    pub message: Option<String>,
    /// The hosts whose routes name it.
    pub host_ids: Vec<String>,
    /// The library's memory of the last request on it.
    pub memory: Option<GrantRequestMemory>,
    /// The length the request form starts from without a memory: the default of a route that names it, else 30 minutes, within the
    /// entitlement's maximum.
    pub default_duration_secs: u32,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[cfg_attr(test, derive(ts_rs::TS))]
#[cfg_attr(test, ts(export, export_to = "../../src/bindings/"))]
pub struct PamOverview {
    pub scopes: Vec<PamScopeView>,
    pub entitlements: Vec<PamEntitlementView>,
}

/// Where a search is made: the account it is made as (resolved: a route's or scope's own, else gcloud's active one), the parent and the
/// location.
type Place = (Option<String>, String, String);

/// `f` of every item, at most `PARALLEL` at once, starting none after `deadline` (those are `late()`), in the items' order.
fn bounded<T: Sync, R: Send>(items: &[T], deadline: Instant, f: &(dyn Fn(&T) -> R + Sync), late: &(dyn Fn() -> R + Sync)) -> Vec<R> {
    let next = Mutex::new(0usize);
    let results: Mutex<Vec<Option<R>>> = Mutex::new((0..items.len()).map(|_| None).collect());
    std::thread::scope(|scope| {
        for _ in 0..PARALLEL.min(items.len()) {
            scope.spawn(|| loop {
                let index = {
                    let mut next = next.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
                    let index = *next;
                    *next += 1;
                    index
                };
                let Some(item) = items.get(index) else { break };
                let result = if Instant::now() < deadline { f(item) } else { late() };
                results.lock().unwrap_or_else(|poisoned| poisoned.into_inner())[index] = Some(result);
            });
        }
    });
    results.into_inner().unwrap_or_else(|poisoned| poisoned.into_inner()).into_iter().map(|result| result.unwrap_or_else(late)).collect()
}

/// The resolved account of a route or scope: its own, else gcloud's active one.
fn resolved(account: Option<&str>, active: Option<&str>) -> Option<String> {
    account.or(active).map(str::to_string)
}

/// The places routes look in: one per account, project and location among the routes that require a grant, with their hosts.
fn route_places(routes: &[HostTransport], active: Option<&str>) -> Vec<(Place, Vec<String>)> {
    let mut places: Vec<(Place, Vec<String>)> = vec![];
    for route in routes {
        let TransportKind::GcpIap { project, account, pam, .. } = &route.kind;
        let Some(pam) = pam else { continue };
        let place = (resolved(account.as_deref(), active), format!("projects/{project}"), pam.location.clone());
        match places.iter_mut().find(|(known, _)| *known == place) {
            Some((_, hosts)) if !hosts.contains(&route.host_id) => hosts.push(route.host_id.clone()),
            Some(_) => {}
            None => places.push((place, vec![route.host_id.clone()])),
        }
    }
    places
}

/// The Access tab's overview (design 2026-10-27, The PAM commands): the places to look (`routes`' and `added`), and every entitlement
/// found there or named by a route, with its state. Blocks; at most `PARALLEL` calls at once, none started after `deadline`.
pub fn overview(gcp: &dyn GcpClient, active: Option<&str>, routes: &[HostTransport], added: &[PamScope], memories: &[GrantRequestMemory], deadline: Instant) -> PamOverview {
    let from_routes = route_places(routes, active);
    let mut places: Vec<Place> = from_routes.iter().map(|(place, _)| place.clone()).collect();
    for scope in added {
        let place = (resolved(scope.account.as_deref(), active), scope.parent.clone(), scope.location.clone());
        if !places.contains(&place) {
            places.push(place);
        }
    }
    let searched: Vec<Result<Vec<EntitlementInfo>, String>> = bounded(
        &places,
        deadline,
        &|(account, parent, location)| gcp.search_entitlements(account.as_deref(), &format!("{parent}/locations/{location}")).map_err(|error| error.to_string()),
        &|| Err(LATE.to_string()),
    );
    let outcome = |place: &Place| searched[places.iter().position(|known| known == place).expect("searched")].as_ref().err().cloned();
    let mut scopes: Vec<PamScopeView> = from_routes
        .iter()
        .map(|(place, hosts)| PamScopeView { id: None, parent: place.1.clone(), location: place.2.clone(), account: place.0.clone(), from_routes: true, host_ids: hosts.clone(), message: outcome(place) })
        .collect();
    scopes.extend(added.iter().map(|scope| PamScopeView {
        id: Some(scope.id.clone()),
        parent: scope.parent.clone(),
        location: scope.location.clone(),
        account: scope.account.clone(),
        from_routes: false,
        host_ids: vec![],
        message: outcome(&(resolved(scope.account.as_deref(), active), scope.parent.clone(), scope.location.clone())),
    }));

    // One row per account and entitlement: what the searches found, then what the routes name.
    let mut rows: BTreeMap<(Option<String>, String), (Option<EntitlementInfo>, Vec<String>, Option<u32>)> = BTreeMap::new();
    for (place, found) in places.iter().zip(&searched) {
        for info in found.iter().flatten() {
            rows.entry((place.0.clone(), info.name.clone())).or_insert((None, vec![], None)).0 = Some(info.clone());
        }
    }
    for route in routes {
        let TransportKind::GcpIap { project, account, pam, .. } = &route.kind;
        let Some(pam) = pam else { continue };
        for id in &pam.entitlements {
            let name = EntitlementName::in_project(project, &pam.location, id).full();
            let row = rows.entry((resolved(account.as_deref(), active), name)).or_insert((None, vec![], None));
            if !row.1.contains(&route.host_id) {
                row.1.push(route.host_id.clone());
            }
            row.2.get_or_insert(pam.duration_secs);
        }
    }
    let keys: Vec<(Option<String>, String)> = rows.keys().cloned().collect();
    let now = SystemTime::now();
    let states: Vec<(String, Option<u64>, Option<String>)> = bounded(
        &keys,
        deadline,
        &|(account, name)| match gcp.grants(account.as_deref(), name) {
            Ok(grants) => {
                let (state, until) = Standing::of(&grants, now).view();
                (state.to_string(), until, None)
            }
            Err(error) => ("error".to_string(), None, Some(error.to_string())),
        },
        &|| ("error".to_string(), None, Some(LATE.to_string())),
    );
    let entitlements = keys
        .into_iter()
        .zip(states)
        .filter_map(|((account, name), (state, active_until_ms, message))| {
            let parts = EntitlementName::parse(&name)?;
            let (info, host_ids, route_default) = rows.remove(&(account.clone(), name.clone()))?;
            let max_duration_secs = info.as_ref().and_then(|info| info.max_duration_secs);
            let default_duration_secs = route_default.unwrap_or(DEFAULT_SECS).min(max_duration_secs.map_or(u32::MAX, |max| max / 60 * 60).max(60));
            Some(PamEntitlementView {
                account,
                parent: parts.parent,
                location: parts.location,
                entitlement: parts.id,
                max_duration_secs,
                needs_approval: info.as_ref().is_some_and(|info| info.needs_approval),
                roles: info.map(|info| info.roles.into_iter().map(|(role, resource)| PamRoleView { role, resource }).collect()).unwrap_or_default(),
                state,
                active_until_ms,
                message,
                host_ids,
                memory: memories.iter().find(|memory| memory.name == name).cloned(),
                default_duration_secs,
                name,
            })
        })
        .collect();
    PamOverview { scopes, entitlements }
}

/// Whether the Access tab lists `name` for `account` (resolved): an entitlement a route names, or one in a place a route uses or the
/// person added, as that account. `gcp_pam_request` asks for nothing else.
pub fn listed(name: &str, account: Option<&str>, active: Option<&str>, routes: &[HostTransport], added: &[PamScope]) -> bool {
    let Some(parts) = EntitlementName::parse(name) else { return false };
    let who = resolved(account, active);
    let named = routes.iter().any(|route| {
        let TransportKind::GcpIap { project, account, pam, .. } = &route.kind;
        pam.as_ref().is_some_and(|pam| {
            resolved(account.as_deref(), active) == who && pam.entitlements.iter().any(|id| EntitlementName::in_project(project, &pam.location, id).full() == name)
        })
    });
    let place = (who.clone(), parts.parent.clone(), parts.location.clone());
    named
        || route_places(routes, active).iter().any(|(known, _)| *known == place)
        || added.iter().any(|scope| (resolved(scope.account.as_deref(), active), scope.parent.clone(), scope.location.clone()) == place)
}

/// The entitlement ids `account` may request in `project`'s `location`, for the host editor's suggestions; none when the search fails.
pub fn suggestions(gcp: &dyn GcpClient, account: Option<&str>, project: &str, location: &str) -> Vec<String> {
    let mut ids: Vec<String> = gcp
        .search_entitlements(account, &format!("projects/{project}/locations/{location}"))
        .unwrap_or_default()
        .into_iter()
        .filter_map(|info| EntitlementName::parse(&info.name).map(|name| name.id))
        .collect();
    ids.sort();
    ids.dedup();
    ids
}

/// What the overview reads from the saved records: the routes of the hosts the library has, the scopes the person added, the memories.
fn saved(app: &tauri::AppHandle) -> Result<(Vec<HostTransport>, Vec<PamScope>, Vec<GrantRequestMemory>), String> {
    let state = app.state::<AppState>();
    let core = state.sync.core.lock().unwrap();
    let records = core.records.as_ref().ok_or("The saved records are unavailable.")?;
    Ok((commands::live_routes(records)?, pam_records::scopes(records), pam_records::memories(records)))
}

fn checked_account(account: Option<&str>) -> Result<(), String> {
    if account.is_some_and(|account| !transports::is_email(account)) {
        return Err("Enter the Google account as an email address.".into());
    }
    Ok(())
}

fn active_account() -> Option<String> {
    crate::gcp::auth::active_account(&commands::gcloud_config_dir())
}

/// The Access tab's overview, read now (design 2026-10-27, The PAM commands).
#[tauri::command]
pub async fn gcp_pam_overview(app: tauri::AppHandle, window: tauri::WebviewWindow) -> Result<PamOverview, String> {
    commands::main_only(&window)?;
    tauri::async_runtime::spawn_blocking(move || {
        let (routes, added, memories) = saved(&app)?;
        let gcp = app.state::<AppState>().gcp.clone();
        Ok(overview(&*gcp, active_account().as_deref(), &routes, &added, &memories, Instant::now() + OVERVIEW_BOUND))
    })
    .await
    .map_err(|error| error.to_string())?
}

/// Requests a grant on the entitlement `name` as `account` (none: gcloud's active account), one the Access tab lists, and waits for it:
/// until it is active, or, for an entitlement an approver approves, until it waits for the approver. The request is remembered in the
/// library for that entitlement.
#[tauri::command]
pub async fn gcp_pam_request(app: tauri::AppHandle, window: tauri::WebviewWindow, account: Option<String>, name: String, justification: String, duration_secs: u32) -> Result<PamStatusView, String> {
    commands::main_only(&window)?;
    checked_account(account.as_deref())?;
    let justification = commands::checked_request(&justification, duration_secs)?;
    tauri::async_runtime::spawn_blocking(move || {
        let (routes, added, _) = saved(&app)?;
        if !listed(&name, account.as_deref(), active_account().as_deref(), &routes, &added) {
            return Err("Lunport does not list that entitlement for this account.".to_string());
        }
        let id = EntitlementName::parse(&name).map(|parts| parts.id).unwrap_or_default();
        let gcp = app.state::<AppState>().gcp.clone();
        let remember = |name: &str, justification: &str, duration_secs: u32| -> Result<(), String> {
            crate::sync::engine::with_env(&app, |env| {
                crate::sync::record_commands::edit_records(env, |state, now| Ok(pam_records::remember(state, name, justification, duration_secs, None, now).unwrap_or_else(|| state.clone())))
            })
            .map_err(|error| error.to_string())?
            .map(|_| ())
            .map_err(|error| error.to_string())
        };
        commands::request_on(&*gcp, account.as_deref(), &name, &id, &justification, duration_secs, &remember, &|| false, Duration::from_secs(2), Duration::from_secs(60))
    })
    .await
    .map_err(|error| error.to_string())?
}

/// Adds a search scope (design 2026-10-27, The Access tab): a parent, a location and an account (none: gcloud's active account).
#[tauri::command]
pub async fn gcp_pam_scope_save(app: tauri::AppHandle, window: tauri::WebviewWindow, parent: String, location: String, account: Option<String>) -> Result<RecordOverview, String> {
    commands::main_only(&window)?;
    let id = crate::sync::record_commands::new_host_id().map_err(|error| error.to_string())?;
    let scope = PamScope { id, parent: parent.trim().to_string(), location: location.trim().to_string(), account: account.map(|account| account.trim().to_string()).filter(|account| !account.is_empty()) };
    scope.validate()?;
    edit_scopes(app, move |state, now| pam_records::save_scope(state, scope.clone(), now)).await
}

/// Removes the search scope `id`.
#[tauri::command]
pub async fn gcp_pam_scope_remove(app: tauri::AppHandle, window: tauri::WebviewWindow, id: String) -> Result<RecordOverview, String> {
    commands::main_only(&window)?;
    edit_scopes(app, move |state, now| pam_records::remove_scope(state, &id, now)).await
}

async fn edit_scopes(
    app: tauri::AppHandle,
    transform: impl Fn(&crate::sync::records_v3::SyncStateV3, u64) -> Result<crate::sync::records_v3::SyncStateV3, String> + Send + 'static,
) -> Result<RecordOverview, String> {
    tauri::async_runtime::spawn_blocking(move || {
        crate::sync::engine::with_env(&app, |env| crate::sync::record_commands::edit_records(env, |state, now| transform(state, now).map_err(crate::error::AppError::Other)))
            .map_err(|error| error.to_string())?
            .map_err(|error| error.to_string())
    })
    .await
    .map_err(|error| error.to_string())?
}

/// The entitlement ids `account` may request in `project`'s `location` (the host editor's suggestions); none when Google cannot say.
#[tauri::command]
pub async fn gcp_pam_suggestions(app: tauri::AppHandle, window: tauri::WebviewWindow, account: Option<String>, project: String, location: String) -> Result<Vec<String>, String> {
    commands::main_only(&window)?;
    checked_account(account.as_deref())?;
    if !pam::is_project_id(&project) || !pam::is_resource_id(&location) {
        return Ok(vec![]);
    }
    tauri::async_runtime::spawn_blocking(move || {
        let gcp = app.state::<AppState>().gcp.clone();
        suggestions(&*gcp, account.as_deref(), &project, &location)
    })
    .await
    .map_err(|error| error.to_string())
}

#[cfg(test)]
#[path = "pam_tests.rs"]
mod tests;
