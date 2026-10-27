//! Transports: how a device reaches a saved host when not over plain TCP (design 2026-10-25, Google Cloud IAP). One `Meta` record per
//! host, `transport:<host-id>`, in the envelope tunnel rules use. In a library that uses central sync a route is the library's (design
//! 2026-10-26, Inside Lunport, routes take tunnel rules' central path): `set` writes the account's row, as `tunnel_rules::set` does, under
//! the same write gate, and capture publishes it in the Catalog. Without central sync (no account, or the older chain-mode account)
//! routes live in `local.transports` only, so `set` consults neither the account nor opaque shadows, and an account join leaves them
//! alone. Saving the first local one raises the local state version to `STATE_VERSION`, which an older Lunport refuses to open.
//!
//! The routes a device saved alone (before its library used central sync, or with an earlier release) move into a central library by
//! one publish step (design 2026-10-26, Existing routes move in; R64a): `local_routes` walks them, and `publish_local` makes the ones the
//! library takes its rows. A capture never takes them; the central dispatch runs the step before its capture, once this device's rows
//! hold the library's latest Catalog.
//!
//! The host editor saves a route with its host, in one edit, and deleting a host removes its route in the same edit (design 2026-10-26,
//! Commands): `RouteChange`, `apply_route_change` and `remove_route` are what the host commands apply after the host write.
//!
//! What a grant request taught this device about a host (the justification and the length) is not part of the route: it stays in
//! `local.transport_grants` as a `GrantMemory`, under `SYNC_STATE_VERSION` (design 2026-10-26), so that requesting a grant never edits
//! the route.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::error::AppError;

use super::central::{
    self,
    payload::{catalog_fits, Catalog},
};
use super::record::{record_key, LocalRecord, Record, RecordKind};
use super::record_repository::{self as repo, RepositoryError};
use super::records_v3::{self, SyncStateV3};

pub const PREFIX: &str = "transport:";
pub const STATE_VERSION: u32 = records_v3::TRANSPORT_STATE_VERSION;
/// The local state version of grant memory and of the library's route rows.
pub const SYNC_STATE_VERSION: u32 = records_v3::TRANSPORT_SYNC_STATE_VERSION;
const MAX_ENTITLEMENTS: usize = 8;
/// The most routes one library holds, as many as it holds tunnels (design 2026-10-26, Room in the Catalog). The central Catalog enforces it.
pub const MAX_ROUTES: usize = 256;
/// The refusal of a save that would leave the library's Catalog too large for one sync record (design 2026-10-26, Room in the Catalog).
pub const NO_ROOM: &str = "This library has no room for more routes or tunnels: together they would exceed what one sync record holds. Remove a route or a tunnel, then try again.";
/// The refusal of a save whose displayed route is no longer the saved one: `set`'s compare-and-set (`RepositoryError::RouteChanged`).
pub const ROUTE_CHANGED: &str = "The host's route changed while you were editing; reload and try again.";
/// What the host editor says of a library whose writes are blocked. A route write refused for that reason reads the same (`refusal`).
pub const SYNC_PAUSED: &str = "Sync changes are paused while account data is reviewed.";

/// A host's transport: which host, and how this device reaches it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(test, derive(ts_rs::TS))]
#[cfg_attr(test, ts(export, export_to = "../../src/bindings/"))]
pub struct HostTransport {
    pub host_id: String,
    pub kind: TransportKind,
}

/// The ways a host can be reached other than TCP. One variant so far.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
#[cfg_attr(test, derive(ts_rs::TS))]
#[cfg_attr(test, ts(export, export_to = "../../src/bindings/", tag = "type", rename_all = "snake_case"))]
pub enum TransportKind {
    /// A Google Cloud IAP TCP-forwarding tunnel to a GCE instance.
    GcpIap {
        project: String,
        zone: String,
        instance: String,
        #[serde(default = "default_interface")]
        interface: String,
        /// The Google account whose gcloud credentials are used; `None` for gcloud's active account.
        #[serde(default)]
        account: Option<String>,
        /// Register the host's key with OS Login when needed and check the username before connecting.
        #[serde(default)]
        os_login: bool,
        /// Require an in-flight Privileged Access Manager grant before connecting.
        #[serde(default)]
        pam: Option<PamCheck>,
    },
}

/// Which PAM entitlements may carry the grant, and where they live.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(test, derive(ts_rs::TS))]
#[cfg_attr(test, ts(export, export_to = "../../src/bindings/"))]
pub struct PamCheck {
    pub entitlements: Vec<String>,
    #[serde(default = "default_location")]
    pub location: String,
    /// How long a grant requested from Lunport asks for by default: seconds, whole minutes, 1–480 minutes; 30 minutes at first (design
    /// 2026-10-25, PAM grant requests). The length last asked for stays on the device that asked (`GrantMemory`), not here.
    #[serde(default = "default_duration")]
    pub duration_secs: u32,
    /// The justification last sent with a request, as earlier releases kept it here. It is remembered on the device now (`GrantMemory`);
    /// no request writes this field any more.
    #[serde(default)]
    pub justification: Option<String>,
}

/// What this device's last grant request for a host taught it (design 2026-10-26, Grant requests): the justification given and the
/// length asked for, offered again next time. It stays on this device, beside the route, so that requesting a grant never edits the
/// route, which syncs with its host.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(test, derive(ts_rs::TS))]
#[cfg_attr(test, ts(export, export_to = "../../src/bindings/"))]
pub struct GrantMemory {
    pub justification: String,
    pub duration_secs: u32,
}

fn default_interface() -> String {
    "nic0".to_string()
}

fn default_location() -> String {
    "global".to_string()
}

fn default_duration() -> u32 {
    30 * 60
}

/// The longest grant Lunport asks for; PAM's own maximum (the entitlement's) applies on top, in PAM's words.
pub(crate) const MAX_DURATION_SECS: u32 = 480 * 60;
pub(crate) const MAX_JUSTIFICATION_CHARS: usize = 512;

/// A grant length Lunport asks for: whole minutes, 1–480.
fn is_grant_duration(secs: u32) -> bool {
    (60..=MAX_DURATION_SECS).contains(&secs) && secs.is_multiple_of(60)
}

/// A justification as one line: at most `MAX_JUSTIFICATION_CHARS` characters, none of them a control character.
fn is_justification_line(text: &str) -> bool {
    text.chars().count() <= MAX_JUSTIFICATION_CHARS && !text.chars().any(char::is_control)
}

impl GrantMemory {
    /// One sentence about the first field that is not acceptable, else `Ok`: the rules of the request form.
    pub fn validate(&self) -> Result<(), String> {
        if !is_grant_duration(self.duration_secs) {
            return Err("Enter a grant duration between 1 and 480 minutes.".into());
        }
        if self.justification.is_empty() {
            return Err("Enter a justification.".into());
        }
        if !is_justification_line(&self.justification) {
            return Err("Keep the justification under 512 characters on one line.".into());
        }
        Ok(())
    }
}

impl HostTransport {
    /// One sentence about the first field that is not acceptable, else `Ok`.
    pub fn validate(&self) -> Result<(), String> {
        if !records_v3::is_host_id(&self.host_id) {
            return Err("Invalid host identity.".into());
        }
        let TransportKind::GcpIap { project, zone, instance, interface, account, pam, .. } = &self.kind;
        if !is_project(project) {
            return Err("Enter the Google Cloud project id.".into());
        }
        if !is_resource_name(zone) {
            return Err("Enter the zone of the instance.".into());
        }
        if !is_resource_name(instance) {
            return Err("Enter the instance name.".into());
        }
        if !is_interface(interface) {
            return Err("Enter a network interface such as nic0.".into());
        }
        if account.as_deref().is_some_and(|account| !is_email(account)) {
            return Err("Enter the Google account as an email address.".into());
        }
        if let Some(pam) = pam {
            if pam.entitlements.is_empty() {
                return Err("Enter at least one PAM entitlement.".into());
            }
            if pam.entitlements.len() > MAX_ENTITLEMENTS {
                return Err(format!("Enter at most {MAX_ENTITLEMENTS} PAM entitlements."));
            }
            if !pam.entitlements.iter().all(|entitlement| is_resource_name(entitlement)) {
                return Err("Enter PAM entitlement ids such as prod-operate.".into());
            }
            if !is_resource_name(&pam.location) {
                return Err("Enter the PAM location, such as global.".into());
            }
            if !is_grant_duration(pam.duration_secs) {
                return Err("Enter a grant duration between 1 and 480 minutes.".into());
            }
            if pam.justification.as_deref().is_some_and(|text| !is_justification_line(text)) {
                return Err("Keep the justification under 512 characters on one line.".into());
            }
        }
        Ok(())
    }
}

/// A project id (`eng-dev-396409`: 6–30 characters, lowercase letters, digits and dashes, starting with a letter) or a project number.
fn is_project(text: &str) -> bool {
    let number = (6..=20).contains(&text.len()) && text.bytes().all(|byte| byte.is_ascii_digit());
    let id = (6..=30).contains(&text.len())
        && text.starts_with(|c: char| c.is_ascii_lowercase())
        && !text.ends_with('-')
        && text.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-');
    number || id
}

/// A GCE-style resource name: 1–63 characters, lowercase letters, digits and dashes, starting with a letter, not ending with a dash.
fn is_resource_name(text: &str) -> bool {
    (1..=63).contains(&text.len())
        && text.starts_with(|c: char| c.is_ascii_lowercase())
        && !text.ends_with('-')
        && text.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
}

/// `nic0` … `nic7`.
fn is_interface(text: &str) -> bool {
    text.strip_prefix("nic").is_some_and(|rest| rest.len() == 1 && rest.bytes().all(|byte| (b'0'..=b'7').contains(&byte)))
}

/// A Google account as an email address, in the characters an address and a directory name share: the account names a directory under
/// gcloud's config (`legacy_credentials/<account>/adc.json`), so no path separators, colons, whitespace or control characters. The
/// frontend's `transportProblem` applies the same rule.
pub(crate) fn is_email(text: &str) -> bool {
    let Some((local, domain)) = text.split_once('@') else { return false };
    let local_ok = !local.is_empty() && local.chars().all(|c| c.is_ascii_alphanumeric() || "._%+'-".contains(c));
    let labels: Vec<&str> = domain.split('.').collect();
    let domain_ok = labels.len() >= 2 && labels.iter().all(|label| !label.is_empty() && label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-'));
    text.len() <= 254 && local_ok && domain_ok
}

/// The record payload: `{ "schema": 1, "transport": … }`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Payload {
    pub schema: u32,
    pub transport: HostTransport,
}

pub fn is_id(id: &str) -> bool {
    id.strip_prefix(PREFIX).is_some_and(records_v3::is_host_id)
}

pub fn wire_id(host_id: &str) -> String {
    format!("{PREFIX}{host_id}")
}

/// The transport a live record holds, when the record is one of ours, names the host its id names and passes validation.
pub fn decode(record: &Record) -> Option<HostTransport> {
    if record.deleted || record.kind != RecordKind::Meta || !is_id(&record.id) {
        return None;
    }
    let payload: Payload = serde_json::from_value(record.payload.clone()).ok()?;
    (payload.schema == 1 && wire_id(&payload.transport.host_id) == record.id && payload.transport.validate().is_ok()).then_some(payload.transport)
}

/// Whether a stored record is well-formed: a tombstone with no payload, or a live record that decodes.
pub fn valid(record: &Record) -> bool {
    record.kind == RecordKind::Meta
        && is_id(&record.id)
        && record.version > 0
        && super::slot_rules::is_slot_id(&record.device_id)
        && if record.deleted { record.payload.is_null() } else { decode(record).is_some() }
}

/// Every live transport: for each host, the library's route when it holds one, else the one saved on this device; in host-id order.
pub fn view(state: &SyncStateV3) -> Vec<HostTransport> {
    let mut routes: BTreeMap<String, HostTransport> =
        state.local.transports.values().filter_map(|row| decode(&row.record)).map(|route| (route.host_id.clone(), route)).collect();
    if let Some(account) = &state.account {
        for route in account.records.values().filter_map(|row| decode(&row.record)) {
            routes.insert(route.host_id.clone(), route);
        }
    }
    routes.into_values().collect()
}

/// The transport of one host, if it has one: the library's route when it holds one, else the one saved on this device.
pub fn get(state: &SyncStateV3, host_id: &str) -> Option<HostTransport> {
    library_route(state, host_id)
        .or_else(|| state.local.transports.get(&record_key(RecordKind::Meta, &wire_id(host_id))).and_then(|row| decode(&row.record)))
}

/// Whether the route `get` reads for `host_id` is the library's, so it syncs wherever the host does (design 2026-10-26, Where routes
/// sync).
pub fn synced(state: &SyncStateV3, host_id: &str) -> bool {
    library_route(state, host_id).is_some()
}

/// The library's route for `host_id`: a live `transport:` row of the account.
fn library_route(state: &SyncStateV3, host_id: &str) -> Option<HostTransport> {
    state.account.as_ref()?.records.get(&record_key(RecordKind::Meta, &wire_id(host_id))).and_then(|row| decode(&row.record))
}

/// Whether routes and tunnels are the library's here: it uses central sync (this device's central owner has cut over) and this device
/// keeps the library's rows in its account. Otherwise, with no account or the older chain-mode one, routes stay on this device (design
/// 2026-10-26, Where routes sync) and nothing publishes a Catalog.
pub(crate) fn central_library(state: &SyncStateV3) -> bool {
    records_v3::central_cutover(state) && state.account.is_some()
}

/// The room check of a save in a library that uses central sync (design 2026-10-26, Room in the Catalog): the Catalog `next` would
/// publish must fit in one sync record, else `RepositoryError::NoRoom`. Only what the library must publish counts, not the routes saved
/// on this device alone, which simply stay there while there is no room. A Catalog that cannot be built refuses the save with its own
/// sentence, under `field` and `id`. Removing a route or a tunnel is never checked.
pub(crate) fn ensure_room(next: &SyncStateV3, field: &'static str, id: &str) -> Result<(), RepositoryError> {
    let catalog = central::catalog_of(next, &Catalog::default()).map_err(|error| repo::invalid(field, id, &error.to_string()))?;
    if catalog_fits(&catalog) {
        Ok(())
    } else {
        Err(RepositoryError::NoRoom)
    }
}

/// Where the routes saved on this device alone stand in a library that uses central sync (design 2026-10-26, Existing routes move in;
/// Room in the Catalog; R64a, R65): what the publish step would move into the library, and which stay for want of room.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct LocalRoutes {
    /// The routes the library takes, in host-id order.
    pub fit: Vec<HostTransport>,
    /// The hosts whose routes stay on this device because the library has no room for them.
    pub no_room: BTreeSet<String>,
}

/// One pass over the routes saved on this device alone (`local.transports`, keyed `meta:transport:<host id>`, so in host-id order) of a
/// library that uses central sync. A route whose host this device does not have, or that the library holds a row for (a route, or a
/// removed one's tombstone), is passed over and the walk goes on. Every other route joins the Catalog the library would publish, as the
/// capture builds it from the one last read (the ledger's), while that Catalog fits: the first route that does not (one past
/// `MAX_ROUTES`, or an encoding past one sync record) stops the walk, and it and every later route the library could have taken stay on
/// this device for want of room. Outside a central library nothing moves.
pub(crate) fn local_routes(state: &SyncStateV3) -> Result<LocalRoutes, AppError> {
    let mut walk = LocalRoutes::default();
    let Some(account) = state.account.as_ref().filter(|_| central_library(state) && !state.local.transports.is_empty()) else {
        return Ok(walk);
    };
    let unread = Catalog::default();
    let last_read = state.local.central_projection.as_ref().map_or(&unread, |ledger| &ledger.catalog);
    let mut catalog = central::catalog_of(state, last_read)?;
    let mut full = false;
    for row in state.local.transports.values() {
        let Some(route) = decode(&row.record) else { continue };
        if account.records.contains_key(&record_key(RecordKind::Meta, &row.record.id)) || repo::get_host(state, &route.host_id).is_err() {
            continue;
        }
        if !full {
            catalog.transports.push(without_justification(route.clone()));
            full = catalog.transports.len() > MAX_ROUTES || !catalog_fits(&catalog);
        }
        if full {
            walk.no_room.insert(route.host_id);
        } else {
            walk.fit.push(route);
        }
    }
    Ok(walk)
}

/// The publish step's move (design 2026-10-26, Existing routes move in; R64a): in a library that uses central sync whose writes are not
/// blocked, each route `local_routes` lets in becomes the library's row (`write_library`: dirty, so the next capture publishes it, and
/// without a justification) and leaves `local.transports`; nothing else changes. `None` when no route moves. When the step runs is its
/// caller's to decide: the central dispatch runs it before its capture, once this device's rows hold the library's latest Catalog.
pub(crate) fn publish_local(state: &SyncStateV3, now: u64) -> Result<Option<SyncStateV3>, AppError> {
    if !central_library(state) || records_v3::account_writes_blocked(state) {
        return Ok(None);
    }
    let fit = local_routes(state)?.fit;
    if fit.is_empty() {
        return Ok(None);
    }
    let mut next = state.clone();
    for route in fit {
        let host_id = route.host_id.clone();
        next = write_library(&next, &host_id, Some(route), now).map_err(|error| AppError::Other(refusal(error)))?;
    }
    Ok(Some(next))
}

/// Saves `route` on this device alone (`local.transports`), as a route is saved outside a central library: the Catalog merge leaves
/// there a route this device added that the merged Catalog has no room for (design 2026-10-27, When it does not fit), and the publish
/// step moves it in once there is room.
pub(crate) fn keep_on_this_device(state: &SyncStateV3, route: HostTransport, now: u64) -> Result<SyncStateV3, RepositoryError> {
    let host_id = route.host_id.clone();
    write(state, &host_id, Some(route), now)
}

/// Whether the map holds anything, tombstones included: they too need the state version.
pub fn has_data(state: &SyncStateV3) -> bool {
    !state.local.transports.is_empty()
}

/// Saves (`Some`) or removes (`None`) the transport of `host_id`, provided `expected` is what `get` reads now: the compare-and-set the
/// editor relies on, refused with `RepositoryError::RouteChanged` (`ROUTE_CHANGED`). In a library that uses central sync the route is
/// the library's: a library whose writes are blocked refuses it, and the account's row is written (`write_library`, which leaves out a
/// justification an earlier release kept), so a save must leave the Catalog room (`NO_ROOM`). Otherwise the route is saved on this
/// device and the version raised to `STATE_VERSION`. A removal also forgets what grant requests taught this device about the host
/// (`grant_memory`).
pub fn set(state: &SyncStateV3, host_id: &str, expected: Option<&HostTransport>, transport: Option<HostTransport>, now: u64) -> Result<SyncStateV3, RepositoryError> {
    if !records_v3::is_host_id(host_id) {
        return Err(repo::invalid("transport", host_id, "Invalid host identity."));
    }
    let library = central_library(state);
    if library && records_v3::account_writes_blocked(state) {
        return Err(RepositoryError::ReadOnlyAccount);
    }
    if get(state, host_id).as_ref() != expected {
        return Err(RepositoryError::RouteChanged);
    }
    if let Some(transport) = &transport {
        transport.validate().map_err(|reason| repo::invalid("transport", host_id, &reason))?;
        if transport.host_id != host_id {
            return Err(repo::invalid("transport", host_id, "The transport names another host."));
        }
    }
    let removal = transport.is_none();
    let mut next = if library { write_library(state, host_id, transport, now)? } else { write(state, host_id, transport, now)? };
    if removal {
        next.local.transport_grants.remove(host_id);
    }
    Ok(next)
}

/// The route half of a combined host save (design 2026-10-26, Commands): the route as the editor displayed it (`expected`, none for a
/// host without one) and the route to save (`kind`, none to remove the route). It names no host: the command that carries it supplies
/// the id, so a new host's route takes the new host's id.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(test, derive(ts_rs::TS))]
#[cfg_attr(test, ts(export, export_to = "../../src/bindings/"))]
pub struct RouteChange {
    pub expected: Option<HostTransport>,
    pub kind: Option<TransportKind>,
}

/// `change` applied to the route of `host_id`: `set`, with the route to save named for the host. A change that leaves the route as it
/// is, provided `expected` is what `get` reads now, writes nothing: saving a host without touching its route leaves no tombstone for a
/// route that never was (which would raise the state version for someone who never used a route), nor moves a route kept on this device
/// into the library.
pub fn apply_route_change(state: &SyncStateV3, host_id: &str, change: &RouteChange, now: u64) -> Result<SyncStateV3, RepositoryError> {
    let route = change.kind.clone().map(|kind| HostTransport { host_id: host_id.into(), kind });
    if records_v3::is_host_id(host_id) && route == change.expected && get(state, host_id) == change.expected {
        return Ok(state.clone());
    }
    set(state, host_id, change.expected.as_ref(), route, now)
}

/// Removes the route of `host_id`, if it has one, as deleting the host does (design 2026-10-26, Deleting a host); a host with no route
/// is left as it is.
pub fn remove_route(state: &SyncStateV3, host_id: &str, now: u64) -> Result<SyncStateV3, RepositoryError> {
    apply_route_change(state, host_id, &RouteChange { expected: get(state, host_id), kind: None }, now)
}

/// How a refused route write reads where it is shown, for the combined host save and for MCP's route tools: a library whose writes are
/// blocked reads as the host editor's own sentence (`SYNC_PAUSED`), and every other refusal as it reads already. The compare-and-set and
/// the room check are sentences themselves (`ROUTE_CHANGED`, `NO_ROOM`).
pub fn refusal(error: RepositoryError) -> String {
    match error {
        RepositoryError::ReadOnlyAccount => SYNC_PAUSED.to_string(),
        other => other.to_string(),
    }
}

/// What this device remembers of its last grant request for `host_id`, if it made one (design 2026-10-26, Grant requests).
pub fn grant_memory(state: &SyncStateV3, host_id: &str) -> Option<GrantMemory> {
    state.local.transport_grants.get(host_id).cloned()
}

/// Whether the state holds anything that needs `SYNC_STATE_VERSION`: grant memory, or a route of the library (a `transport:` row of
/// the account), which a Lunport that does not know that version could not publish.
pub fn needs_sync_version(state: &SyncStateV3) -> bool {
    !state.local.transport_grants.is_empty() || has_library_rows(state)
}

/// Whether the account holds rows of the library's routes (`transport:` rows, tombstones included).
pub fn has_library_rows(state: &SyncStateV3) -> bool {
    state.account.as_ref().is_some_and(|account| account.records.values().any(|row| row.record.kind == RecordKind::Meta && is_id(&row.record.id)))
}

/// What a grant request taught this device about the host (design 2026-10-26, Grant requests): the duration asked for and the
/// justification given, offered again next time. They are kept on this device beside the route, not in it, so a request never edits the
/// route. Written without a compare-and-set (the editor may be showing the route meanwhile); the route must exist and require a grant,
/// and the request form's rules apply to what is remembered. The state version is raised to `SYNC_STATE_VERSION`.
pub fn remember_grant_request(state: &SyncStateV3, host_id: &str, justification: &str, duration_secs: u32, _now: u64) -> Result<SyncStateV3, RepositoryError> {
    let Some(transport) = get(state, host_id) else { return Err(repo::invalid("transport", host_id, "This host has no transport.")) };
    let TransportKind::GcpIap { pam, .. } = &transport.kind;
    if pam.is_none() {
        return Err(repo::invalid("transport", host_id, "This transport requires no grant."));
    }
    let memory = GrantMemory { justification: justification.to_string(), duration_secs };
    memory.validate().map_err(|reason| repo::invalid("transport", host_id, &reason))?;
    let mut next = state.clone();
    next.local.transport_grants.insert(host_id.to_string(), memory);
    next.version = next.version.max(SYNC_STATE_VERSION);
    Ok(next)
}

/// A route's record payload, or a tombstone's `null`.
fn payload_of(transport: Option<&HostTransport>) -> serde_json::Value {
    match transport {
        Some(transport) => serde_json::to_value(Payload { schema: 1, transport: transport.clone() }).expect("a transport serializes"),
        None => serde_json::Value::Null,
    }
}

fn write(state: &SyncStateV3, host_id: &str, transport: Option<HostTransport>, now: u64) -> Result<SyncStateV3, RepositoryError> {
    let wire = wire_id(host_id);
    let key = record_key(RecordKind::Meta, &wire);
    let previous = state.local.transports.get(&key);
    let earlier: Vec<&Record> = previous.map(|row| &row.record).into_iter().collect();
    let mut record = repo::ordered_record(state, &wire, payload_of(transport.as_ref()), transport.is_none(), now, &earlier)?;
    record.kind = RecordKind::Meta;
    let mut next = state.clone();
    next.local.transports.insert(key, LocalRecord { record, seq: previous.map_or(0, |row| row.seq), dirty: false });
    next.version = next.version.max(STATE_VERSION);
    Ok(next)
}

/// Writes the library's row for `host_id` (`central_library`), dirty so that the next capture publishes it, as `tunnel_rules::set`
/// writes a rule's. The row holds the route as the Catalog does, without the justification an earlier release kept in it (the editor
/// sends such a route back as it displayed it), so what is read back is what the library publishes. The copy this device kept before the
/// library held the route goes: the row supersedes it, and a tombstone would otherwise let it come back. A save must leave the Catalog
/// room: at most `MAX_ROUTES` routes, counted first because the Catalog would refuse a longer list with a sentence of its own, and an
/// encoding that fits in one record (`ensure_room`). The version is raised to `SYNC_STATE_VERSION`, which the library's rows need.
fn write_library(state: &SyncStateV3, host_id: &str, transport: Option<HostTransport>, now: u64) -> Result<SyncStateV3, RepositoryError> {
    let transport = transport.map(without_justification);
    let wire = wire_id(host_id);
    let key = record_key(RecordKind::Meta, &wire);
    let mut next = state.clone();
    next.local.transports.remove(&key);
    next.version = next.version.max(SYNC_STATE_VERSION);
    let records = &mut next.account.as_mut().expect("a library that uses central sync keeps its rows in the account").records;
    let previous = records.get(&key);
    let earlier: Vec<&Record> = previous.map(|row| &row.record).into_iter().collect();
    let mut record = repo::ordered_record(state, &wire, payload_of(transport.as_ref()), transport.is_none(), now, &earlier)?;
    record.kind = RecordKind::Meta;
    let seq = previous.map_or(0, |row| row.seq);
    records.insert(key, LocalRecord { record, seq, dirty: true });
    if transport.is_some() {
        if records.values().filter(|row| decode(&row.record).is_some()).count() > MAX_ROUTES {
            return Err(RepositoryError::NoRoom);
        }
        ensure_room(&next, "transport", host_id)?;
    }
    Ok(next)
}

/// A route as the library holds it: without the justification earlier releases kept in it. The device that asked remembers that
/// (`GrantMemory`); it never syncs (design 2026-10-26, On the wire).
pub(crate) fn without_justification(mut route: HostTransport) -> HostTransport {
    let TransportKind::GcpIap { pam, .. } = &mut route.kind;
    if let Some(pam) = pam {
        pam.justification = None;
    }
    route
}

/// Re-keys what this device keeps by host id to the ids `host_ids` gives the hosts (old → new), as an adoption gives the hosts it
/// imports theirs (design 2026-10-26, Existing routes move in): each entry of `local.transports` whose host the map names, a route or a
/// removed one's tombstone, is written again under the host's new id, and what grant requests taught this device about that host
/// (`local.transport_grants`) moves with it. Ids the map does not name keep theirs.
pub fn rekey_local(state: &mut SyncStateV3, host_ids: &BTreeMap<String, String>, now: u64) -> Result<(), RepositoryError> {
    let mut next = state.clone();
    // Every old entry leaves before any new one is written, so a new id that is another entry's old id cannot be overwritten.
    let mut moved = vec![];
    for (key, row) in &state.local.transports {
        let Some((old, new)) = row.record.id.strip_prefix(PREFIX).and_then(|old| Some((old, host_ids.get(old)?))) else { continue };
        let route = match decode(&row.record) {
            Some(route) => Some(HostTransport { host_id: new.clone(), ..route }),
            None if row.record.deleted => None,
            None => return Err(repo::invalid("transport", old, "invalid transport metadata")),
        };
        next.local.transports.remove(key);
        moved.push((new, route));
    }
    for (new, route) in moved {
        next = write(&next, new, route, now)?;
    }
    let remembered: Vec<_> = host_ids.iter().filter_map(|(old, new)| Some((new.clone(), next.local.transport_grants.remove(old)?))).collect();
    next.local.transport_grants.extend(remembered);
    *state = next;
    Ok(())
}

/// What an adoption or a replacement keeps of `source`'s routes (design 2026-10-26, Existing routes move in; R22): every route that
/// applies on `source`, the library's as well as this device's own (`view`), becomes a route saved on this device in `next`, under the
/// id the merge gives its host (`host_ids`: old → new), and what grant requests taught this device about that host moves with it
/// (`rekey_local`). A route or grant memory whose host the map does not name goes with that host. Both of `next`'s maps are rebuilt
/// from `source`'s.
pub fn follow_hosts(source: &SyncStateV3, next: &mut SyncStateV3, host_ids: &BTreeMap<String, String>, now: u64) -> Result<(), RepositoryError> {
    next.local.transports.clear();
    for route in view(source).into_iter().filter(|route| host_ids.contains_key(&route.host_id)) {
        let host_id = route.host_id.clone();
        *next = write(next, &host_id, Some(route), now)?;
    }
    next.local.transport_grants =
        source.local.transport_grants.iter().filter(|(host_id, _)| host_ids.contains_key(*host_id)).map(|(host_id, memory)| (host_id.clone(), memory.clone())).collect();
    rekey_local(next, host_ids, now)
}

/// Leaving an account keeps the transport of every host that stays on this device (a live record in `next.local.hosts`), the library's
/// routes included, as one saved on this device, under the new local id the leave plan gave a space host (`host_ids`: old → new), and
/// drops the transports of the hosts that go. What grant requests taught this device follows the same hosts, under the same ids (R8).
/// Both of `next`'s maps are rebuilt from `before`'s.
pub fn preserve_on_leave(before: &SyncStateV3, next: &mut SyncStateV3, host_ids: &BTreeMap<String, String>, now: u64) -> Result<(), RepositoryError> {
    next.local.transports.clear();
    for mut transport in view(before) {
        if let Some(local_id) = host_ids.get(&transport.host_id) {
            transport.host_id = local_id.clone();
        }
        if !stays_on_this_device(next, &transport.host_id) {
            continue;
        }
        let host_id = transport.host_id.clone();
        *next = write(next, &host_id, Some(transport), now)?;
    }
    let remembered = before
        .local
        .transport_grants
        .iter()
        .map(|(host_id, memory)| (host_ids.get(host_id).unwrap_or(host_id), memory))
        .filter(|(host_id, _)| stays_on_this_device(next, host_id))
        .map(|(host_id, memory)| (host_id.clone(), memory.clone()))
        .collect();
    next.local.transport_grants = remembered;
    Ok(())
}

/// Whether a host stays on this device when it leaves an account: a live record of `next.local.hosts`.
fn stays_on_this_device(next: &SyncStateV3, host_id: &str) -> bool {
    next.local.hosts.get(&record_key(RecordKind::Host, host_id)).is_some_and(|host| !host.record.deleted)
}

#[cfg(test)]
#[path = "transports_tests.rs"]
pub(crate) mod tests;
