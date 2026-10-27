//! Privileged Access Manager in the library (design 2026-10-27, Search scopes and grant memory in the library): the search scopes the
//! person added (where Lunport asks Google which entitlements they may request), and the grant memory (the justification and length last
//! used for an entitlement). One `Meta` record each, `pam_scope:<id>` and `pam_request:<id>`, in the envelope tunnel rules use.
//!
//! In a library that uses central sync (`transports::central_library`) both are the library's: account rows, dirty until the capture
//! publishes them in the Catalog (`pam_scopes`, `pam_requests`), rebuilt from the Catalog by both projections. Otherwise (no account, or
//! the older chain-mode account) they stay on this device in `local.pam_records`, and a publish step moves them into the library once it
//! uses central sync (`publish_local`), as the routes a device kept alone move in. Either way they need `STATE_VERSION`, which an older
//! Lunport refuses to open.
//!
//! A grant request never fails for its memory: `remember` writes what it can and otherwise leaves the state as it was. The library keeps
//! the `MAX_REQUESTS` memories written most recently on this device, and drops the oldest when the Catalog has no room.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::central::{
    self,
    payload::{catalog_fits, Catalog},
};
use super::record::{record_key, LocalRecord, Record, RecordKind};
use super::record_repository as repo;
use super::records_v3::{self, SyncStateV3};
use super::transports;
use crate::gcp::pam::{is_parent, is_resource_id, EntitlementName};

pub const SCOPE_PREFIX: &str = "pam_scope:";
pub const REQUEST_PREFIX: &str = "pam_request:";
/// The local state version of these records, local or the library's.
pub const STATE_VERSION: u32 = records_v3::PAM_STATE_VERSION;
/// The most search scopes and grant memories one library holds (design 2026-10-27). The Catalog enforces both.
pub const MAX_SCOPES: usize = 64;
pub const MAX_REQUESTS: usize = 32;
/// The refusal of a scope save that would leave the Catalog too large for one sync record.
pub const NO_SCOPE_ROOM: &str = "This library has no room for more search scopes: together with routes and tunnels they would exceed what one sync record holds. Remove a scope, a route or a tunnel, then try again.";
/// What a scope save says of a library whose writes are blocked, as a route save does.
const SYNC_PAUSED: &str = transports::SYNC_PAUSED;

/// Where Lunport asks Google which entitlements an account may request: a parent (`projects/<id>`, `folders/<number>`,
/// `organizations/<number>`), a location, and the account (`None`: gcloud's active account on each computer).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(test, derive(ts_rs::TS))]
#[cfg_attr(test, ts(export, export_to = "../../src/bindings/"))]
pub struct PamScope {
    pub id: String,
    pub parent: String,
    pub location: String,
    pub account: Option<String>,
}

impl PamScope {
    pub fn validate(&self) -> Result<(), String> {
        if !records_v3::is_host_id(&self.id) {
            return Err("Invalid search scope identity.".into());
        }
        if !is_parent(&self.parent) {
            return Err("Enter a project ID, or a folder or organization number.".into());
        }
        if !is_resource_id(&self.location) {
            return Err("Enter the PAM location, such as global.".into());
        }
        if self.account.as_deref().is_some_and(|account| !transports::is_email(account)) {
            return Err("Enter the Google account as an email address.".into());
        }
        Ok(())
    }

    /// What makes two scopes the same place to look: the parent, the location and the account together.
    fn place(&self) -> (&str, &str, Option<&str>) {
        (&self.parent, &self.location, self.account.as_deref())
    }
}

/// The justification and length last used for an entitlement (its full name), offered again next time, on every computer of the library.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(test, derive(ts_rs::TS))]
#[cfg_attr(test, ts(export, export_to = "../../src/bindings/"))]
pub struct GrantRequestMemory {
    pub name: String,
    pub justification: String,
    pub duration_secs: u32,
}

impl GrantRequestMemory {
    pub fn validate(&self) -> Result<(), String> {
        if EntitlementName::parse(&self.name).is_none() {
            return Err("Invalid entitlement name.".into());
        }
        transports::GrantMemory { justification: self.justification.clone(), duration_secs: self.duration_secs }.validate()
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ScopePayload {
    pub schema: u32,
    pub scope: PamScope,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RequestPayload {
    pub schema: u32,
    pub request: GrantRequestMemory,
}

fn hex16(text: &str) -> bool {
    records_v3::is_host_id(text)
}

pub fn is_scope_id(id: &str) -> bool {
    id.strip_prefix(SCOPE_PREFIX).is_some_and(hex16)
}

pub fn is_request_id(id: &str) -> bool {
    id.strip_prefix(REQUEST_PREFIX).is_some_and(hex16)
}

/// Whether `id` names one of these records.
pub fn is_id(id: &str) -> bool {
    is_scope_id(id) || is_request_id(id)
}

pub fn scope_wire_id(id: &str) -> String {
    format!("{SCOPE_PREFIX}{id}")
}

/// The record id of an entitlement's memory: the first 16 hex digits of the SHA-256 of its full name, so every device names it alike.
pub fn request_wire_id(name: &str) -> String {
    let digest = Sha256::digest(name.as_bytes());
    let hex: String = digest.iter().take(8).map(|byte| format!("{byte:02x}")).collect();
    format!("{REQUEST_PREFIX}{hex}")
}

pub fn decode_scope(record: &Record) -> Option<PamScope> {
    if record.deleted || record.kind != RecordKind::Meta || !is_scope_id(&record.id) {
        return None;
    }
    let payload: ScopePayload = serde_json::from_value(record.payload.clone()).ok()?;
    (payload.schema == 1 && scope_wire_id(&payload.scope.id) == record.id && payload.scope.validate().is_ok()).then_some(payload.scope)
}

pub fn decode_request(record: &Record) -> Option<GrantRequestMemory> {
    if record.deleted || record.kind != RecordKind::Meta || !is_request_id(&record.id) {
        return None;
    }
    let payload: RequestPayload = serde_json::from_value(record.payload.clone()).ok()?;
    (payload.schema == 1 && request_wire_id(&payload.request.name) == record.id && payload.request.validate().is_ok()).then_some(payload.request)
}

/// Whether a stored record is well-formed: a tombstone with no payload, or a live record that decodes.
pub fn valid(record: &Record) -> bool {
    record.kind == RecordKind::Meta
        && is_id(&record.id)
        && record.version > 0
        && super::slot_rules::is_slot_id(&record.device_id)
        && if record.deleted {
            record.payload.is_null()
        } else if is_scope_id(&record.id) {
            decode_scope(record).is_some()
        } else {
            decode_request(record).is_some()
        }
}

fn scope_payload(scope: &PamScope) -> serde_json::Value {
    serde_json::to_value(ScopePayload { schema: 1, scope: scope.clone() }).expect("a scope serializes")
}

fn request_payload(request: &GrantRequestMemory) -> serde_json::Value {
    serde_json::to_value(RequestPayload { schema: 1, request: request.clone() }).expect("a memory serializes")
}

/// The rows these records live in now: the account's in a library that uses central sync, else this device's own.
fn rows(state: &SyncStateV3) -> Vec<&LocalRecord> {
    if transports::central_library(state) {
        let account = state.account.as_ref().expect("a central library keeps its rows in the account");
        account.records.values().filter(|row| row.record.kind == RecordKind::Meta && is_id(&row.record.id)).collect()
    } else {
        state.local.pam_records.values().collect()
    }
}

/// The search scopes the person added, by id.
pub fn scopes(state: &SyncStateV3) -> Vec<PamScope> {
    rows(state).into_iter().filter_map(|row| decode_scope(&row.record)).collect()
}

/// Every grant memory, the most recently written on this device first.
pub fn memories(state: &SyncStateV3) -> Vec<GrantRequestMemory> {
    let mut found: Vec<(u64, GrantRequestMemory)> = rows(state).into_iter().filter_map(|row| Some((row.record.updated_at_ms, decode_request(&row.record)?))).collect();
    found.sort_by(|a, b| b.0.cmp(&a.0).then_with(|| a.1.name.cmp(&b.1.name)));
    found.into_iter().map(|(_, memory)| memory).collect()
}

/// The memory of the entitlement `name`, if a request on it left one.
pub fn memory(state: &SyncStateV3, name: &str) -> Option<GrantRequestMemory> {
    let key = record_key(RecordKind::Meta, &request_wire_id(name));
    let row = if transports::central_library(state) { state.account.as_ref()?.records.get(&key) } else { state.local.pam_records.get(&key) };
    row.and_then(|row| decode_request(&row.record)).filter(|memory| memory.name == name)
}

/// Whether the state holds any of these records, tombstones included, anywhere: they need `STATE_VERSION`.
pub fn has_data(state: &SyncStateV3) -> bool {
    !state.local.pam_records.is_empty() || has_library_rows(state)
}

/// Whether the account holds library rows of these records (tombstones included).
pub fn has_library_rows(state: &SyncStateV3) -> bool {
    state.account.as_ref().is_some_and(|account| account.records.values().any(|row| row.record.kind == RecordKind::Meta && is_id(&row.record.id)))
}

/// Writes the record `wire` (a live payload, or a tombstone for `None`): the account's dirty row in a library that uses central sync,
/// else this device's own (where a removal simply forgets it). The version is raised to `STATE_VERSION`.
fn write(state: &SyncStateV3, wire: &str, payload: Option<serde_json::Value>, now: u64) -> Result<SyncStateV3, String> {
    let key = record_key(RecordKind::Meta, wire);
    let central = transports::central_library(state);
    let mut next = state.clone();
    next.version = next.version.max(STATE_VERSION);
    if !central && payload.is_none() {
        next.local.pam_records.remove(&key);
        return Ok(next);
    }
    let map = if central { &state.account.as_ref().expect("checked").records } else { &state.local.pam_records };
    let previous = map.get(&key);
    let earlier: Vec<&Record> = previous.map(|row| &row.record).into_iter().collect();
    let deleted = payload.is_none();
    let mut record = repo::ordered_record(state, wire, payload.unwrap_or(serde_json::Value::Null), deleted, now, &earlier).map_err(|error| error.to_string())?;
    record.kind = RecordKind::Meta;
    let row = LocalRecord { record, seq: previous.map_or(0, |row| row.seq), dirty: central };
    if central {
        next.local.pam_records.remove(&key);
        next.account.as_mut().expect("checked").records.insert(key, row);
    } else {
        next.local.pam_records.insert(key, row);
    }
    Ok(next)
}

/// Whether the Catalog `state` would publish fits in one sync record (only asked in a library that uses central sync).
fn fits(state: &SyncStateV3) -> Result<bool, String> {
    let catalog = central::catalog_of(state, &Catalog::default()).map_err(|error| error.to_string())?;
    Ok(catalog_fits(&catalog))
}

/// A library whose writes are blocked refuses these writes, as it refuses a route's.
fn blocked(state: &SyncStateV3) -> bool {
    transports::central_library(state) && records_v3::account_writes_blocked(state)
}

/// Saves a new search scope. One scope per parent, location and account; at most `MAX_SCOPES`; in a library that uses central sync the
/// Catalog must keep room for it (`NO_SCOPE_ROOM`), and a library whose writes are blocked refuses it.
pub fn save_scope(state: &SyncStateV3, scope: PamScope, now: u64) -> Result<SyncStateV3, String> {
    scope.validate()?;
    if blocked(state) {
        return Err(SYNC_PAUSED.into());
    }
    let current = scopes(state);
    if current.iter().any(|other| other.id != scope.id && other.place() == scope.place()) {
        return Err("Lunport already looks there.".into());
    }
    if !current.iter().any(|other| other.id == scope.id) && current.len() >= MAX_SCOPES {
        return Err(format!("A library holds at most {MAX_SCOPES} search scopes."));
    }
    let next = write(state, &scope_wire_id(&scope.id), Some(scope_payload(&scope)), now)?;
    if transports::central_library(&next) && !fits(&next)? {
        return Err(NO_SCOPE_ROOM.into());
    }
    Ok(next)
}

/// Removes the search scope `id`; a scope that is not there is no error. Removing never runs out of room.
pub fn remove_scope(state: &SyncStateV3, id: &str, now: u64) -> Result<SyncStateV3, String> {
    if !records_v3::is_host_id(id) {
        return Err("Invalid search scope identity.".into());
    }
    if blocked(state) {
        return Err(SYNC_PAUSED.into());
    }
    if !scopes(state).iter().any(|scope| scope.id == id) {
        return Ok(state.clone());
    }
    write(state, &scope_wire_id(id), None, now)
}

/// Remembers a grant request on the entitlement `name` (design 2026-10-27): its memory is written, the memories beyond the
/// `MAX_REQUESTS` most recent are dropped, and in a library that uses central sync older memories are dropped while the Catalog would not
/// fit. `legacy_host` names the host whose memory an earlier release kept by host (`local.transport_grants`): that one is forgotten,
/// since this memory replaces it. `None` when nothing could be written (an invalid memory, a blocked library, no room even for this one);
/// the request stands either way.
pub fn remember(state: &SyncStateV3, name: &str, justification: &str, duration_secs: u32, legacy_host: Option<&str>, now: u64) -> Option<SyncStateV3> {
    let memory = GrantRequestMemory { name: name.to_string(), justification: justification.to_string(), duration_secs };
    if memory.validate().is_err() || blocked(state) {
        return None;
    }
    let wire = request_wire_id(name);
    let mut next = write(state, &wire, Some(request_payload(&memory)), now).ok()?;
    if let Some(host) = legacy_host {
        next.local.transport_grants.remove(host);
    }
    // The oldest go first: past the most a library holds, then while the Catalog has no room.
    let oldest_other = |state: &SyncStateV3| {
        let mut others: Vec<(u64, String)> =
            rows(state).into_iter().filter(|row| row.record.id != wire && decode_request(&row.record).is_some()).map(|row| (row.record.updated_at_ms, row.record.id.clone())).collect();
        others.sort();
        others.into_iter().next().map(|(_, id)| id)
    };
    while memories(&next).len() > MAX_REQUESTS {
        let oldest = oldest_other(&next)?;
        next = write(&next, &oldest, None, now).ok()?;
    }
    if transports::central_library(&next) {
        while !fits(&next).ok()? {
            let oldest = oldest_other(&next)?;
            next = write(&next, &oldest, None, now).ok()?;
        }
    }
    Some(next)
}

/// The publish step (design 2026-10-27, like routes': design 2026-10-26, Existing routes move in): in a library that uses central sync
/// whose writes are not blocked, the records this device kept alone become the library's rows, unless the library has a row of the same
/// id: scopes while the Catalog has room (the others stay here), memories while it has room (the others are dropped: a memory is a
/// convenience). `None` when nothing moves.
pub(crate) fn publish_local(state: &SyncStateV3, now: u64) -> Result<Option<SyncStateV3>, String> {
    if !transports::central_library(state) || records_v3::account_writes_blocked(state) || state.local.pam_records.is_empty() {
        return Ok(None);
    }
    let account = state.account.as_ref().expect("a central library keeps its rows in the account");
    let mut next = state.clone();
    for (key, row) in &state.local.pam_records {
        let payload = if let Some(scope) = decode_scope(&row.record) {
            Some(scope_payload(&scope))
        } else {
            decode_request(&row.record).map(|memory| request_payload(&memory))
        };
        let taken = account.records.contains_key(key);
        let Some(payload) = payload.filter(|_| !taken && !records_v3::account_writes_blocked(state)) else {
            next.local.pam_records.remove(key);
            continue;
        };
        let moved = write(&next, &row.record.id, Some(payload), now)?;
        if fits(&moved)? {
            next = moved;
        } else if is_request_id(&row.record.id) {
            next.local.pam_records.remove(key);
        }
    }
    Ok((next != *state).then_some(next))
}

/// Leaving an account keeps every scope and memory of the library, and this device's own, as this device's own records: none names a
/// host, so all of them stay. A first publication, an adoption and a replacement keep them the same way (`initial_projection`), for
/// the publish step to move in.
pub fn preserve_on_leave(before: &SyncStateV3, next: &mut SyncStateV3, now: u64) -> Result<(), String> {
    let mut kept = std::collections::BTreeMap::new();
    let library = before.account.as_ref().map(|account| account.records.values().filter(|row| row.record.kind == RecordKind::Meta && is_id(&row.record.id)).collect::<Vec<_>>()).unwrap_or_default();
    for row in before.local.pam_records.values().chain(library) {
        if row.record.deleted {
            kept.remove(&row.record.id);
        } else if valid(&row.record) {
            kept.insert(row.record.id.clone(), row.record.payload.clone());
        }
    }
    next.local.pam_records.clear();
    for (id, payload) in kept {
        let key = record_key(RecordKind::Meta, &id);
        let mut record = repo::ordered_record(next, &id, payload, false, now, &[]).map_err(|error| error.to_string())?;
        record.kind = RecordKind::Meta;
        next.local.pam_records.insert(key, LocalRecord { record, seq: 0, dirty: false });
    }
    if !next.local.pam_records.is_empty() {
        next.version = next.version.max(STATE_VERSION);
    }
    Ok(())
}

/// The library's scopes and memories as the Catalog holds them, in `original`'s order and then new ones by id (`projection_local::catalog_of`).
pub(crate) fn catalog_lists(state: &SyncStateV3, original: &Catalog) -> Result<(Vec<PamScope>, Vec<GrantRequestMemory>), ()> {
    let account = state.account.as_ref().ok_or(())?;
    let mut scopes = std::collections::BTreeMap::new();
    let mut requests = std::collections::BTreeMap::new();
    for row in account.records.values().filter(|row| row.record.kind == RecordKind::Meta && is_id(&row.record.id)) {
        if !valid(&row.record) {
            return Err(());
        }
        if let Some(scope) = decode_scope(&row.record) {
            scopes.insert(scope.id.clone(), scope);
        } else if let Some(memory) = decode_request(&row.record) {
            requests.insert(memory.name.clone(), memory);
        }
    }
    let mut next_scopes: Vec<PamScope> = original.pam_scopes.iter().filter_map(|old| scopes.remove(&old.id)).collect();
    next_scopes.extend(scopes.into_values());
    let mut next_requests: Vec<GrantRequestMemory> = original.pam_requests.iter().filter_map(|old| requests.remove(&old.name)).collect();
    next_requests.extend(requests.into_values());
    Ok((next_scopes, next_requests))
}

/// The account rows of the Catalog's scopes and memories, as both projections write them: `(wire id, payload)`.
pub(crate) fn catalog_rows(catalog: &Catalog) -> Vec<(String, serde_json::Value)> {
    catalog
        .pam_scopes
        .iter()
        .map(|scope| (scope_wire_id(&scope.id), scope_payload(scope)))
        .chain(catalog.pam_requests.iter().map(|memory| (request_wire_id(&memory.name), request_payload(memory))))
        .collect()
}

/// Whether the Catalog's lists are well-formed: within their limits, each item valid, scope ids and places unique, one memory per
/// entitlement.
pub(crate) fn valid_catalog(catalog: &Catalog) -> bool {
    let mut ids = std::collections::BTreeSet::new();
    let mut places = std::collections::BTreeSet::new();
    let mut names = std::collections::BTreeSet::new();
    catalog.pam_scopes.len() <= MAX_SCOPES
        && catalog.pam_requests.len() <= MAX_REQUESTS
        && catalog.pam_scopes.iter().all(|scope| scope.validate().is_ok() && ids.insert(&scope.id) && places.insert(scope.place()))
        && catalog.pam_requests.iter().all(|memory| memory.validate().is_ok() && names.insert(&memory.name))
}

#[cfg(test)]
#[path = "pam_records_tests.rs"]
pub(crate) mod tests;
