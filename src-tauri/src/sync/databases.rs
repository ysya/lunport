//! Saved databases in the library: the Cloud SQL for PostgreSQL instances a person connects to. One `Meta` record each, `database:<id>`, in
//! the envelope tunnel rules use.
//!
//! They are stored the way search scopes and grant memory are (`pam_records`). In a library that uses central sync
//! (`transports::central_library`) a database is the library's: an account row, written dirty until the capture publishes it in the
//! Catalog (`databases`), rebuilt from the Catalog by both projections. Otherwise (no account, or the older chain-mode account) it stays on
//! this device in `local.databases`, and a library that uses central sync reads its own rows only; a publish step moves the databases a
//! device kept alone into the library once it uses central sync (`publish_local`), as it moves routes. Either way the records need
//! `STATE_VERSION`, which an older Lunport refuses to open.
//!
//! The library holds a database without the justification of a grant request: that is remembered on the device that asked, and never
//! syncs, so every write leaves it out (`payload_of`) and a Catalog that carries one is refused, as one with such a route is.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use super::central::payload::Catalog;
use super::record::{record_key, LocalRecord, Record, RecordKind};
use super::record_repository::{self as repo, RepositoryError};
use super::records_v3::{self, SyncStateV3};
use super::transports::{self, PamCheck};
use crate::gcp::pam::is_resource_id;

pub const PREFIX: &str = "database:";
/// The local state version of saved databases, local or the library's.
pub const STATE_VERSION: u32 = records_v3::DATABASE_STATE_VERSION;
/// The most saved databases one library holds, as many as it holds tunnels and routes.
pub const MAX_DATABASES: usize = 256;

/// The database engine of an instance. One so far.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(test, derive(ts_rs::TS))]
#[cfg_attr(test, ts(export, export_to = "../../src/bindings/"))]
pub enum DatabaseEngine {
    Postgres,
}

/// What a database is used for, which decides how carefully Lunport treats a connection to it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(test, derive(ts_rs::TS))]
#[cfg_attr(test, ts(export, export_to = "../../src/bindings/"))]
pub enum DatabaseEnvironment {
    Dev,
    Staging,
    Prod,
}

/// How an instance is reached. One so far.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(test, derive(ts_rs::TS))]
#[cfg_attr(test, ts(export, export_to = "../../src/bindings/"))]
pub enum DatabaseNetwork {
    /// Over the instance's public IP address.
    Public,
}

/// A Cloud SQL instance a person connects to: where it lives, which account signs in and whether a Privileged Access Manager grant is
/// needed first.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(test, derive(ts_rs::TS))]
#[cfg_attr(test, ts(export, export_to = "../../src/bindings/"))]
pub struct SavedDatabase {
    pub id: String,
    pub name: String,
    pub engine: DatabaseEngine,
    /// The Google Cloud project that holds the instance.
    pub project: String,
    /// The region of the instance, such as `asia-east1`.
    pub region: String,
    /// The Cloud SQL instance name.
    pub instance: String,
    pub environment: DatabaseEnvironment,
    pub network: DatabaseNetwork,
    /// The Google account whose gcloud credentials are used; `None` for gcloud's active account.
    #[serde(default)]
    pub account: Option<String>,
    /// The database to open on the instance, such as `postgres`.
    pub default_database: String,
    /// Require an in-flight Privileged Access Manager grant before connecting.
    #[serde(default)]
    pub pam: Option<PamCheck>,
    /// The port on 127.0.0.1 where this device offers the database to local clients; `None` offers none.
    #[serde(default)]
    pub local_port: Option<u16>,
}

impl SavedDatabase {
    /// One sentence about the first field that is not acceptable, else `Ok`.
    pub fn validate(&self) -> Result<(), String> {
        if !records_v3::is_host_id(&self.id) {
            return Err("Invalid database identity.".into());
        }
        if self.name.trim().is_empty() || self.name.chars().count() > 128 || self.name.chars().any(char::is_control) {
            return Err("Enter a database name (up to 128 characters).".into());
        }
        if !transports::is_project(&self.project) {
            return Err("Enter a Google Cloud project id.".into());
        }
        if !is_resource_id(&self.region) {
            return Err("Enter the instance's region, such as asia-east1.".into());
        }
        if !is_instance_name(&self.instance) {
            return Err("Enter the Cloud SQL instance name.".into());
        }
        if self.account.as_deref().is_some_and(|account| !transports::is_email(account)) {
            return Err("Enter the Google account as an email address.".into());
        }
        if self.default_database.trim().is_empty() || self.default_database.chars().count() > 63 || self.default_database.chars().any(char::is_control) {
            return Err("Enter the database to open, such as postgres.".into());
        }
        if let Some(pam) = &self.pam {
            transports::validate_pam(pam)?;
        }
        if self.local_port.is_some_and(|port| !(1024..=u16::MAX).contains(&port)) {
            return Err("Choose a local port from 1024 to 65535.".into());
        }
        Ok(())
    }

    /// What Cloud SQL calls the instance: `project:region:instance`.
    pub fn connection_name(&self) -> String {
        format!("{}:{}:{}", self.project, self.region, self.instance)
    }

    pub fn is_prod(&self) -> bool {
        self.environment == DatabaseEnvironment::Prod
    }
}

/// A Cloud SQL instance name: 1–98 characters, lowercase letters, digits and dashes, starting with a letter, not ending with a dash.
fn is_instance_name(text: &str) -> bool {
    (1..=98).contains(&text.len())
        && text.starts_with(|c: char| c.is_ascii_lowercase())
        && !text.ends_with('-')
        && text.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
}

/// The record payload: `{ "schema": 1, "database": … }`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Payload {
    pub schema: u32,
    pub database: SavedDatabase,
}

pub fn is_id(id: &str) -> bool {
    id.strip_prefix(PREFIX).is_some_and(records_v3::is_host_id)
}

pub fn wire_id(id: &str) -> String {
    format!("{PREFIX}{id}")
}

/// The database a live record holds, when the record is one of ours, names the database its id names and passes validation.
pub fn decode(record: &Record) -> Option<SavedDatabase> {
    if record.deleted || record.kind != RecordKind::Meta || !is_id(&record.id) {
        return None;
    }
    let payload: Payload = serde_json::from_value(record.payload.clone()).ok()?;
    (payload.schema == 1 && wire_id(&payload.database.id) == record.id && payload.database.validate().is_ok()).then_some(payload.database)
}

/// Whether a stored record is well-formed: a tombstone with no payload, or a live record that decodes.
pub fn valid(record: &Record) -> bool {
    record.kind == RecordKind::Meta
        && is_id(&record.id)
        && record.version > 0
        && super::slot_rules::is_slot_id(&record.device_id)
        && if record.deleted { record.payload.is_null() } else { decode(record).is_some() }
}

/// A database as the library holds it: without the justification of a grant request, as a route is held (`transports::without_justification`).
fn without_justification(mut database: SavedDatabase) -> SavedDatabase {
    if let Some(pam) = &mut database.pam {
        pam.justification = None;
    }
    database
}

/// The record payload of a database, in the library's form (`without_justification`).
fn payload_of(database: &SavedDatabase) -> serde_json::Value {
    serde_json::to_value(Payload { schema: 1, database: without_justification(database.clone()) }).expect("a database serializes")
}

/// A saved database as the library lists it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Stored {
    pub database: SavedDatabase,
    /// Whether it is the library's, so it syncs wherever the library does, rather than this device's own.
    pub synced: bool,
    /// Whether the library's writes are blocked, so it cannot be changed now.
    pub blocked: bool,
}

/// The account's rows of saved databases, tombstones included, whether or not the library uses central sync now.
fn library_rows(state: &SyncStateV3) -> impl Iterator<Item = &LocalRecord> {
    state.account.iter().flat_map(|account| account.records.values()).filter(|row| row.record.kind == RecordKind::Meta && is_id(&row.record.id))
}

/// The rows saved databases live in now: the account's in a library that uses central sync, else this device's own.
fn rows(state: &SyncStateV3) -> Vec<&LocalRecord> {
    if transports::central_library(state) {
        library_rows(state).collect()
    } else {
        state.local.databases.values().collect()
    }
}

/// Every live saved database, in id order.
pub fn view(state: &SyncStateV3) -> Vec<Stored> {
    let synced = transports::central_library(state);
    let blocked = synced && records_v3::account_writes_blocked(state);
    rows(state).into_iter().filter_map(|row| Some(Stored { database: decode(&row.record)?, synced, blocked })).collect()
}

/// Whether the state holds any saved database, tombstones included, anywhere: they need `STATE_VERSION`.
pub fn has_data(state: &SyncStateV3) -> bool {
    !state.local.databases.is_empty() || has_library_rows(state)
}

/// Whether the account holds library rows of saved databases (tombstones included).
pub fn has_library_rows(state: &SyncStateV3) -> bool {
    library_rows(state).next().is_some()
}

const IN_ACCOUNT: &str = "a library that uses central sync keeps its rows in the account";

/// A row of the record `wire`: a live payload, or a tombstone (`None`), numbered after `previous`.
fn row_of(state: &SyncStateV3, wire: &str, payload: Option<serde_json::Value>, now: u64, previous: Option<&LocalRecord>, dirty: bool) -> Result<LocalRecord, RepositoryError> {
    let earlier: Vec<&Record> = previous.map(|row| &row.record).into_iter().collect();
    let deleted = payload.is_none();
    let mut record = repo::ordered_record(state, wire, payload.unwrap_or(serde_json::Value::Null), deleted, now, &earlier)?;
    record.kind = RecordKind::Meta;
    Ok(LocalRecord { record, seq: previous.map_or(0, |row| row.seq), dirty })
}

/// Writes the record `wire` (a live payload, or a tombstone for `None`): the account's dirty row in a library that uses central sync,
/// else this device's own (where a removal simply forgets it). The version is raised to `STATE_VERSION`.
fn write(state: &SyncStateV3, wire: &str, payload: Option<serde_json::Value>, now: u64) -> Result<SyncStateV3, RepositoryError> {
    let key = record_key(RecordKind::Meta, wire);
    let central = transports::central_library(state);
    let mut next = state.clone();
    next.version = next.version.max(STATE_VERSION);
    if !central && payload.is_none() {
        next.local.databases.remove(&key);
        return Ok(next);
    }
    let previous = if central { state.account.as_ref().expect(IN_ACCOUNT).records.get(&key) } else { state.local.databases.get(&key) };
    let row = row_of(state, wire, payload, now, previous, central)?;
    if central {
        // The copy this device kept before the library held the database goes: the row supersedes it.
        next.local.databases.remove(&key);
        next.account.as_mut().expect(IN_ACCOUNT).records.insert(key, row);
    } else {
        next.local.databases.insert(key, row);
    }
    Ok(next)
}

/// Saves (`Some`) or removes (`None`) the database `id`, provided `expected` is what `view` reads now: the compare-and-set the editor
/// relies on. A new database is refused past `MAX_DATABASES`. In a library that uses central sync the database is the library's: a
/// library whose writes are blocked refuses it (`RepositoryError::ReadOnlyAccount`), the account's row is written (a removal is a dirty
/// tombstone) and a save must leave the Catalog room (`RepositoryError::NoRoom`). Otherwise the database is kept on this device. The
/// version is raised to `STATE_VERSION`; removing a database that is not there changes nothing. A justification the saved database
/// carries is not stored (`without_justification`).
pub fn set(state: &SyncStateV3, id: &str, expected: Option<&SavedDatabase>, database: Option<SavedDatabase>, now: u64) -> Result<SyncStateV3, RepositoryError> {
    let wire = wire_id(id);
    if !is_id(&wire) {
        return Err(repo::invalid("database", id, "Invalid database identity."));
    }
    let central = transports::central_library(state);
    if central && records_v3::account_writes_blocked(state) {
        return Err(RepositoryError::ReadOnlyAccount);
    }
    let current = view(state);
    let stored = current.iter().find(|row| row.database.id == id).map(|row| &row.database);
    if stored != expected {
        return Err(repo::invalid("database", id, "This database changed on another device. Refresh and try again."));
    }
    let payload = match &database {
        Some(database) => {
            database.validate().map_err(|reason| repo::invalid("database", id, &reason))?;
            if database.id != id {
                return Err(repo::invalid("database", id, "The database identity changed."));
            }
            if expected.is_none() && current.len() >= MAX_DATABASES {
                return Err(repo::invalid("database", id, &format!("The maximum of {MAX_DATABASES} saved databases has been reached.")));
            }
            Some(payload_of(database))
        }
        None if stored.is_none() => return Ok(state.clone()),
        None => None,
    };
    let next = write(state, &wire, payload, now)?;
    if database.is_some() && central {
        transports::ensure_room(&next, "database", id)?;
    }
    Ok(next)
}

/// The publish step, as for routes and search scopes: in a library that uses central sync whose writes are not blocked, the databases
/// this device kept alone become the library's rows (dirty, so the next capture publishes them), unless the library has a row of the
/// same id, a removed one's included: the library's wins, and this device's copy goes. A database moves only while the library has room
/// for it (at most `MAX_DATABASES`, and a Catalog that fits in one sync record); one that does not stays on this device. `None` when
/// nothing moves. When the step runs is its caller's to decide (`projection_capture::move_local_routes`).
pub(crate) fn publish_local(state: &SyncStateV3, now: u64) -> Result<Option<SyncStateV3>, String> {
    if !transports::central_library(state) || records_v3::account_writes_blocked(state) || state.local.databases.is_empty() {
        return Ok(None);
    }
    let account = state.account.as_ref().expect(IN_ACCOUNT);
    let mut next = state.clone();
    for (key, row) in &state.local.databases {
        let Some(database) = decode(&row.record).filter(|_| !account.records.contains_key(key)) else {
            next.local.databases.remove(key);
            continue;
        };
        if view(&next).len() >= MAX_DATABASES {
            continue;
        }
        let moved = write(&next, &row.record.id, Some(payload_of(&database)), now).map_err(transports::refusal)?;
        match transports::ensure_room(&moved, "database", &database.id) {
            Ok(()) => next = moved,
            Err(RepositoryError::NoRoom) => {}
            Err(other) => return Err(transports::refusal(other)),
        }
    }
    Ok((next != *state).then_some(next))
}

/// Leaving a library for another keeps every database of the library and this device's own as this device's own records: none names a
/// host, so all of them stay (a removed one does not come back). A first publication, an adoption and a replacement keep them the same
/// way (`initial_projection`), for the publish step to move into the new library. The version is raised only when one stays.
pub fn preserve_on_leave(before: &SyncStateV3, next: &mut SyncStateV3, now: u64) -> Result<(), String> {
    let mut kept = BTreeMap::new();
    for row in before.local.databases.values().chain(library_rows(before)) {
        if row.record.deleted {
            kept.remove(&row.record.id);
        } else if valid(&row.record) {
            kept.insert(row.record.id.clone(), row.record.payload.clone());
        }
    }
    next.local.databases.clear();
    for (id, payload) in kept {
        let row = row_of(next, &id, Some(payload), now, None, false).map_err(transports::refusal)?;
        next.local.databases.insert(record_key(RecordKind::Meta, &id), row);
    }
    if !next.local.databases.is_empty() {
        next.version = next.version.max(STATE_VERSION);
    }
    Ok(())
}

/// The library's databases as the Catalog holds them, in `original`'s order and then new ones by id (`projection_local::catalog_of`):
/// the account's rows with a removed one left out and no justification. The databases saved on this device alone are not the library's:
/// like routes, they join the Catalog only once the publish step has made them its rows (`publish_local`), so that a capture never
/// holds the Catalog against a basis older than the library's. `None` when a row is not well-formed: the Catalog cannot be built.
pub(crate) fn catalog_list(state: &SyncStateV3, original: &Catalog) -> Option<Vec<SavedDatabase>> {
    state.account.as_ref()?;
    let mut found = BTreeMap::new();
    for row in library_rows(state) {
        if !valid(&row.record) {
            return None;
        }
        if let Some(database) = decode(&row.record) {
            found.insert(database.id.clone(), without_justification(database));
        }
    }
    let mut next: Vec<SavedDatabase> = original.databases.iter().filter_map(|old| found.remove(&old.id)).collect();
    next.extend(found.into_values());
    Some(next)
}

/// The account rows of the Catalog's databases, as both projections write them: `(wire id, payload)`.
pub(crate) fn catalog_rows(catalog: &Catalog) -> Vec<(String, serde_json::Value)> {
    catalog.databases.iter().map(|database| (wire_id(&database.id), payload_of(database))).collect()
}

/// Whether the Catalog's databases are well-formed: at most `MAX_DATABASES`, each valid, ids unique, and none with the justification of
/// a grant request (it is remembered on the device that asked, so a Catalog that carries one is refused when built and read).
pub(crate) fn valid_catalog(catalog: &Catalog) -> bool {
    let mut ids = BTreeSet::new();
    catalog.databases.len() <= MAX_DATABASES
        && catalog.databases.iter().all(|database| {
            database.validate().is_ok() && database.pam.as_ref().is_none_or(|pam| pam.justification.is_none()) && ids.insert(&database.id)
        })
}

#[cfg(test)]
#[path = "databases_tests.rs"]
pub(crate) mod tests;
