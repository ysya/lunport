//! Device-local PostgreSQL profiles. The metadata and cleanup journal commit together.
//! Database passwords are kept under separate, randomly assigned OS credential accounts.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File, OpenOptions};
use std::io::ErrorKind;
use std::net::IpAddr;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use super::tunnels::{main_only, snapshot};
use crate::fsutil;
use crate::ssh::{self, Transport};
use crate::sync::record_repository;
use crate::sync::records_v3::{self, HostScope, SyncStateV3};
use crate::sync::transports::{self, HostTransport, TransportKind};

const VERSION: u32 = 1;
const FILE_NAME: &str = "profiles.json";
const PROFILE_PREFIX: &str = "postgres-";
const CREDENTIAL_PREFIX: &str = "standard-postgres:";
const INVALID_STORE: &str = "The local PostgreSQL profiles could not be read.";
const SAVE_FAILED: &str = "The local PostgreSQL profiles could not be saved.";
const NOT_FOUND: &str = "This PostgreSQL profile no longer exists.";
const STALE: &str = "This PostgreSQL profile changed. Reload it and try again.";
const ROUTE_GONE: &str = "The saved SSH route changed or is unavailable. Select an SSH host again.";
const PASSWORD_REQUIRED: &str = "Enter the PostgreSQL password to connect.";
const CREDENTIAL_SAVE_FAILED: &str =
    "The PostgreSQL password could not be saved in the device credential store.";

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[cfg_attr(test, derive(ts_rs::TS))]
#[cfg_attr(test, ts(export, export_to = "../../src/bindings/"))]
#[serde(deny_unknown_fields)]
pub struct StandardPostgresDraft {
    pub name: String,
    pub host: String,
    pub port: u16,
    pub database: String,
    pub username: String,
    pub via_host: Option<String>,
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
#[cfg_attr(test, derive(ts_rs::TS))]
#[cfg_attr(test, ts(export, export_to = "../../src/bindings/"))]
pub struct StandardPostgresProfile {
    pub id: String,
    pub name: String,
    pub host: String,
    pub port: u16,
    pub database: String,
    pub username: String,
    pub via_host: Option<String>,
    pub has_password: bool,
    pub route_unavailable: bool,
    pub route_revision: Option<String>,
    pub revision: String,
}

impl StandardPostgresDraft {
    fn validate(&self) -> Result<(), String> {
        valid_text(&self.name, 128, "name")?;
        valid_text(&self.database, 1024, "database name")?;
        valid_text(&self.username, 1024, "username")?;
        if !valid_host(&self.host) {
            return Err("Enter a DNS hostname or IP address in the PostgreSQL host field.".into());
        }
        if self.port == 0 {
            return Err("Enter a PostgreSQL port from 1 to 65535.".into());
        }
        if self
            .via_host
            .as_deref()
            .is_some_and(|id| !records_v3::is_host_id(id))
        {
            return Err(ROUTE_GONE.into());
        }
        Ok(())
    }

    fn same_connection(&self, other: &Self) -> bool {
        self.host == other.host
            && self.port == other.port
            && self.database == other.database
            && self.username == other.username
            && self.via_host == other.via_host
    }
}

fn valid_text(text: &str, max_chars: usize, field: &str) -> Result<(), String> {
    if text.trim().is_empty()
        || text.chars().count() > max_chars
        || text.chars().any(char::is_control)
    {
        return Err(format!(
            "Enter a PostgreSQL {field} without control characters, up to {max_chars} characters."
        ));
    }
    Ok(())
}

fn valid_host(host: &str) -> bool {
    if host.parse::<IpAddr>().is_ok() {
        return true;
    }
    let labels = host.strip_suffix('.').unwrap_or(host);
    labels.len() <= 253
        && rustls::pki_types::DnsName::try_from(host).is_ok()
        && labels.split('.').all(|label| {
            (1..=63).contains(&label.len())
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        })
}

fn checked_password(password: &str) -> Result<(), String> {
    if password.is_empty() {
        return Err(PASSWORD_REQUIRED.into());
    }
    if password.contains('\0') {
        return Err("A PostgreSQL password cannot contain a null character.".into());
    }
    Ok(())
}

fn random_token() -> Result<String, String> {
    let mut bytes = [0u8; 16];
    getrandom::fill(&mut bytes).map_err(|_| SAVE_FAILED.to_string())?;
    Ok(bytes.iter().map(|byte| format!("{byte:02x}")).collect())
}

fn is_hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn valid_id(value: &str, prefix: &str) -> bool {
    value
        .strip_prefix(prefix)
        .is_some_and(|token| is_hex(token, 32))
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct SavedProfile {
    draft: StandardPostgresDraft,
    revision: String,
    credential_id: Option<String>,
    route_pin: Option<String>,
}

impl SavedProfile {
    fn view(&self, id: &str, route_revision: Option<String>) -> StandardPostgresProfile {
        let route_unavailable = self.draft.via_host.is_some()
            && (route_revision.is_none() || self.route_pin != route_revision);
        StandardPostgresProfile {
            id: id.into(),
            name: self.draft.name.clone(),
            host: self.draft.host.clone(),
            port: self.draft.port,
            database: self.draft.database.clone(),
            username: self.draft.username.clone(),
            via_host: self.draft.via_host.clone(),
            has_password: self.credential_id.is_some() && !route_unavailable,
            route_unavailable,
            route_revision,
            revision: self.revision.clone(),
        }
    }

    fn password(
        &self,
        typed: Option<String>,
        credentials: &impl Credentials,
    ) -> Result<String, String> {
        let password = match typed {
            Some(password) => Some(password),
            None => match self.credential_id.as_deref() {
                Some(id) => credentials.get(id)?,
                None => None,
            },
        };
        let mut password = Zeroizing::new(password.ok_or(PASSWORD_REQUIRED)?);
        checked_password(&password)?;
        Ok(std::mem::take(&mut *password))
    }

    fn current_route(&self, state: Option<&SyncStateV3>) -> Result<Option<Route>, String> {
        let Some(id) = &self.draft.via_host else {
            return Ok(None);
        };
        let route = Route::resolve(state, id)?;
        if self.route_pin.as_deref() != Some(&route.pin) {
            return Err(ROUTE_GONE.into());
        }
        Ok(Some(route))
    }
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ProfileFile {
    version: u32,
    profiles: BTreeMap<String, SavedProfile>,
    pending_cleanup: BTreeSet<String>,
}

impl Default for ProfileFile {
    fn default() -> Self {
        Self {
            version: VERSION,
            profiles: BTreeMap::new(),
            pending_cleanup: BTreeSet::new(),
        }
    }
}

impl ProfileFile {
    fn valid(&self) -> bool {
        let mut credentials = BTreeSet::new();
        self.version == VERSION
            && self
                .pending_cleanup
                .iter()
                .all(|id| valid_id(id, CREDENTIAL_PREFIX))
            && self.profiles.iter().all(|(id, profile)| {
                valid_id(id, PROFILE_PREFIX)
                    && is_hex(&profile.revision, 32)
                    && profile.draft.validate().is_ok()
                    && profile.route_pin.is_some() == profile.draft.via_host.is_some()
                    && profile
                        .route_pin
                        .as_deref()
                        .is_none_or(|pin| is_hex(pin, 64))
                    && profile.credential_id.as_ref().is_none_or(|credential| {
                        valid_id(credential, CREDENTIAL_PREFIX)
                            && !self.pending_cleanup.contains(credential)
                            && credentials.insert(credential)
                    })
            })
    }
}

trait Credentials {
    fn get(&self, id: &str) -> Result<Option<String>, String>;
    fn set(&self, id: &str, password: &str) -> Result<(), String>;
    fn delete(&self, id: &str) -> Result<(), String>;
}

struct OsCredentials;

impl Credentials for OsCredentials {
    fn get(&self, id: &str) -> Result<Option<String>, String> {
        crate::secrets::get(id).map_err(|_| {
            "The PostgreSQL password could not be read from the device credential store.".into()
        })
    }

    fn set(&self, id: &str, password: &str) -> Result<(), String> {
        crate::secrets::set(id, password).map_err(|_| CREDENTIAL_SAVE_FAILED.into())
    }

    fn delete(&self, id: &str) -> Result<(), String> {
        crate::secrets::delete(id).map_err(|_| {
            "The PostgreSQL password could not be removed from the device credential store.".into()
        })
    }
}

struct Save {
    id: Option<String>,
    expected_revision: Option<String>,
    expected_route: Option<String>,
    draft: StandardPostgresDraft,
    password: Option<Zeroizing<String>>,
    forget_password: bool,
}

/// The lock spans the metadata load, CAS check and writes, including any credential staging.
/// App instances always acquire it on a blocking thread.
struct Store {
    path: PathBuf,
    current: ProfileFile,
    _lock: File,
}

impl Store {
    fn open(root: &Path) -> Result<Self, String> {
        match fs::symlink_metadata(root) {
            Ok(metadata) if metadata.is_dir() => {}
            Err(error) if error.kind() == ErrorKind::NotFound => {}
            _ => return Err(INVALID_STORE.into()),
        }
        fsutil::ensure_private_dir(root).map_err(|_| INVALID_STORE.to_string())?;
        let lock_path = root.join("lock");
        fsutil::check_write(&lock_path).map_err(|_| INVALID_STORE.to_string())?;
        match fs::symlink_metadata(&lock_path) {
            Ok(metadata) if metadata.is_file() => {}
            Err(error) if error.kind() == ErrorKind::NotFound => {}
            _ => return Err(INVALID_STORE.into()),
        }
        let load_error = || INVALID_STORE.to_string();
        let lock = OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(lock_path)
            .map_err(|_| load_error())?;
        lock.lock().map_err(|_| load_error())?;

        let path = root.join(FILE_NAME);
        let current = match fs::symlink_metadata(&path) {
            Ok(metadata) if metadata.is_file() => {
                let contents = fs::read(&path).map_err(|_| load_error())?;
                let current: ProfileFile =
                    serde_json::from_slice(&contents).map_err(|_| load_error())?;
                if !current.valid() {
                    return Err(load_error());
                }
                current
            }
            Err(error) if error.kind() == ErrorKind::NotFound => ProfileFile::default(),
            _ => return Err(load_error()),
        };
        Ok(Self {
            path,
            current,
            _lock: lock,
        })
    }

    fn persist(&mut self, next: ProfileFile) -> Result<(), String> {
        let contents = serde_json::to_vec(&next).map_err(|_| SAVE_FAILED.to_string())?;
        fsutil::atomic_write(&self.path, &contents, 0o600).map_err(|_| SAVE_FAILED.to_string())?;
        self.current = next;
        Ok(())
    }

    fn get(&self, id: &str) -> Result<&SavedProfile, String> {
        self.current
            .profiles
            .get(id)
            .ok_or_else(|| NOT_FOUND.into())
    }

    fn list(&self, state: Option<&SyncStateV3>) -> Vec<StandardPostgresProfile> {
        let mut views: Vec<_> = self
            .current
            .profiles
            .iter()
            .map(|(id, profile)| {
                let route_revision = profile
                    .draft
                    .via_host
                    .as_ref()
                    .and_then(|host_id| Route::resolve(state, host_id).ok())
                    .map(|route| route.pin);
                profile.view(id, route_revision)
            })
            .collect();
        views.sort_by(|a, b| a.name.cmp(&b.name).then(a.id.cmp(&b.id)));
        views
    }

    fn retry_cleanup(&mut self, credentials: &impl Credentials) {
        if self.current.pending_cleanup.is_empty() {
            return;
        }
        let mut next = self.current.clone();
        next.pending_cleanup
            .retain(|id| credentials.delete(id).is_err());
        if next.pending_cleanup != self.current.pending_cleanup {
            // Removal is idempotent. Retain the journal if its write fails.
            let _ = self.persist(next);
        }
    }

    fn save(
        &mut self,
        request: Save,
        credentials: &impl Credentials,
        state: Option<&SyncStateV3>,
    ) -> Result<StandardPostgresProfile, String> {
        let Save {
            id,
            expected_revision,
            expected_route,
            draft,
            password,
            forget_password,
        } = request;
        draft.validate()?;
        if let Some(password) = &password {
            if forget_password {
                return Err("Choose whether to save or forget the PostgreSQL password.".into());
            }
            checked_password(password)?;
        }
        let route_pin = draft
            .via_host
            .as_deref()
            .map(|id| Route::resolve(state, id).map(|route| route.pin))
            .transpose()?;
        let (id, previous) = match (id, expected_revision) {
            (Some(id), Some(expected)) => {
                let previous = self.get(&id)?;
                if previous.revision != expected {
                    return Err(STALE.into());
                }
                (id, Some(previous.clone()))
            }
            (None, None) => {
                let id = format!("{PROFILE_PREFIX}{}", random_token()?);
                if self.current.profiles.contains_key(&id) {
                    return Err(SAVE_FAILED.into());
                }
                (id, None)
            }
            _ => return Err(STALE.into()),
        };
        let route_replaced = previous.as_ref().is_some_and(|profile| {
            profile.draft.via_host == draft.via_host && profile.route_pin != route_pin
        });
        if route_replaced && (expected_route.is_none() || route_pin != expected_route) {
            return Err(
                "The SSH route changed. Reopen the connection settings and select the host again."
                    .into(),
            );
        }
        let keeps_password = !forget_password
            && previous.as_ref().is_some_and(|profile| {
                profile.draft.same_connection(&draft) && profile.route_pin == route_pin
            });
        let old_credential = previous.and_then(|profile| profile.credential_id);
        let mut next_profile = SavedProfile {
            draft,
            revision: random_token()?,
            credential_id: keeps_password.then(|| old_credential.clone()).flatten(),
            route_pin,
        };

        self.retry_cleanup(credentials);
        if let Some(password) = password {
            let id = format!("{CREDENTIAL_PREFIX}{}", random_token()?);
            let mut staged = self.current.clone();
            if staged
                .profiles
                .values()
                .any(|profile| profile.credential_id.as_ref() == Some(&id))
                || !staged.pending_cleanup.insert(id.clone())
            {
                return Err(SAVE_FAILED.into());
            }
            // Persist the orphan's account name before writing the OS credential.
            self.persist(staged)?;
            if let Err(error) = credentials.set(&id, &password) {
                self.retry_cleanup(credentials);
                return Err(error);
            }
            next_profile.credential_id = Some(id);
        }

        let mut next = self.current.clone();
        if let Some(new_id) = &next_profile.credential_id {
            next.pending_cleanup.remove(new_id);
        }
        if let Some(old_id) =
            old_credential.filter(|id| Some(id) != next_profile.credential_id.as_ref())
        {
            next.pending_cleanup.insert(old_id);
        }
        let view = next_profile.view(&id, next_profile.route_pin.clone());
        next.profiles.insert(id, next_profile);
        let result = self.persist(next);
        self.retry_cleanup(credentials);
        result.map(|()| view)
    }

    fn delete(
        &mut self,
        id: &str,
        expected_revision: &str,
        credentials: &impl Credentials,
    ) -> Result<(), String> {
        self.retry_cleanup(credentials);
        let profile = self.get(id)?;
        if profile.revision != expected_revision {
            return Err(STALE.into());
        }
        let mut next = self.current.clone();
        if let Some(credential) = &profile.credential_id {
            next.pending_cleanup.insert(credential.clone());
        }
        next.profiles.remove(id);
        self.persist(next)?;
        self.retry_cleanup(credentials);
        Ok(())
    }
}

#[derive(Serialize)]
enum RouteAuthority<'a> {
    Local {
        device: &'a str,
    },
    Account {
        chain: &'a str,
        relay: &'a str,
    },
    Central {
        account: &'a str,
        origin: &'a str,
        device: &'a str,
    },
}

#[derive(Serialize)]
struct IapEndpoint {
    project: String,
    zone: String,
    instance: String,
    interface: String,
    account: Option<String>,
}

impl IapEndpoint {
    fn matches(&self, actual: &ssh::IapTarget) -> bool {
        self.project == actual.project
            && self.zone == actual.zone
            && self.instance == actual.instance
            && self.interface == actual.interface
            && self.account == actual.account
            && actual.url_root.is_none()
    }
}

#[derive(Serialize)]
struct RouteHop {
    id: String,
    scope: HostScope,
    hostname: String,
    port: u16,
    user: String,
    iap: Option<IapEndpoint>,
}

impl RouteHop {
    fn matches(&self, actual: &ssh::Hop) -> bool {
        self.id == actual.id.as_str()
            && self.hostname == actual.hostname
            && self.port == actual.port
            && (self.user.is_empty() || self.user == actual.user)
            && match (&self.iap, &actual.transport) {
                (None, Transport::Tcp) => true,
                (Some(expected), Transport::GcpIap(actual)) => expected.matches(actual),
                _ => false,
            }
    }
}

struct Route {
    pin: String,
    hops: Vec<RouteHop>,
}

impl Route {
    fn resolve(state: Option<&SyncStateV3>, host_id: &str) -> Result<Self, String> {
        let state = state.ok_or(ROUTE_GONE)?;
        let chain = record_repository::resolve_host_chain(state, host_id)
            .map_err(|_| ROUTE_GONE.to_string())?;
        let hops = chain
            .into_iter()
            .map(|hop| {
                if hop.group_error.is_some() {
                    return Err(ROUTE_GONE.to_string());
                }
                let iap =
                    transports::get(state, &hop.host.id).map(|HostTransport { kind, .. }| {
                        let TransportKind::GcpIap {
                            project,
                            zone,
                            instance,
                            interface,
                            account,
                            ..
                        } = kind;
                        IapEndpoint {
                            project,
                            zone,
                            instance,
                            interface,
                            account,
                        }
                    });
                Ok(RouteHop {
                    id: hop.host.id,
                    scope: hop.host.scope,
                    hostname: hop.effective_payload.hostname,
                    port: hop.effective_payload.port,
                    user: hop.effective_payload.user,
                    iap,
                })
            })
            .collect::<Result<Vec<_>, String>>()?;
        let scopes = hops
            .iter()
            .map(|hop| Self::authority(state, &hop.scope))
            .collect::<Result<Vec<_>, String>>()?;
        let bytes = serde_json::to_vec(&(&hops, scopes)).map_err(|_| ROUTE_GONE.to_string())?;
        let pin = format!("{:x}", Sha256::digest(bytes));
        Ok(Self { pin, hops })
    }

    fn authority<'a>(
        state: &'a SyncStateV3,
        scope: &HostScope,
    ) -> Result<RouteAuthority<'a>, String> {
        if matches!(scope, HostScope::Local) {
            return Ok(RouteAuthority::Local {
                device: &state.device_id,
            });
        }
        if let Some(central) = state
            .local
            .central
            .as_ref()
            .filter(|value| value.control.cutover)
        {
            return Ok(RouteAuthority::Central {
                account: &central.control.account_id,
                origin: &central.control.profile.origin,
                device: &central.control.device.id,
            });
        }
        let account = state.account.as_ref().ok_or(ROUTE_GONE)?;
        Ok(RouteAuthority::Account {
            chain: &account.chain_id,
            relay: &state.relay_url,
        })
    }

    fn matches(&self, target: &ssh::Target) -> bool {
        self.hops.len() == target.hops.len()
            && self
                .hops
                .iter()
                .zip(&target.hops)
                .all(|(expected, actual)| expected.matches(actual))
    }
}

fn local_store() -> Result<Store, String> {
    let root = fsutil::app_data_root().map_err(|_| INVALID_STORE.to_string())?;
    Store::open(&root.join("standard-postgres"))
}

fn route_snapshot(app: &tauri::AppHandle, needed: bool) -> Option<SyncStateV3> {
    if needed {
        snapshot(app).ok()
    } else {
        None
    }
}

/// Resolve the current, pinned route before looking up the credential or starting a connection.
pub(crate) fn open_profile(
    app: &tauri::AppHandle,
    id: &str,
    expected_revision: Option<&str>,
    password: Option<String>,
) -> Result<(StandardPostgresProfile, String), String> {
    let mut password = Zeroizing::new(password);
    let store = local_store()?;
    let profile = store.get(id)?;
    if Some(profile.revision.as_str()) != expected_revision {
        return Err("The PostgreSQL connection changed. Reopen it from Databases.".into());
    }
    let state = route_snapshot(app, profile.draft.via_host.is_some());
    profile.current_route(state.as_ref())?;
    let password = profile.password(password.take(), &OsCredentials)?;
    Ok((profile.view(id, profile.route_pin.clone()), password))
}

fn current_route(
    app: &tauri::AppHandle,
    profile: &StandardPostgresProfile,
) -> Result<Option<Route>, String> {
    let store = local_store()?;
    let saved = store.get(&profile.id)?;
    if saved.revision != profile.revision {
        return Err(STALE.into());
    }
    let state = route_snapshot(app, saved.draft.via_host.is_some());
    saved.current_route(state.as_ref())
}

/// Recheck the profile and its route immediately before sending a PostgreSQL password.
pub(crate) fn check_current(
    app: &tauri::AppHandle,
    profile: &StandardPostgresProfile,
) -> Result<(), String> {
    current_route(app, profile).map(drop)
}

/// Compare the host the connector used with the pin before starting the PostgreSQL forward.
pub(crate) fn check_ssh_target(
    app: &tauri::AppHandle,
    profile: &StandardPostgresProfile,
    target: &ssh::Target,
) -> Result<(), String> {
    if current_route(app, profile)?.is_some_and(|route| route.matches(target)) {
        Ok(())
    } else {
        Err(ROUTE_GONE.into())
    }
}

#[tauri::command]
pub async fn standard_postgres_list(
    app: tauri::AppHandle,
    window: tauri::WebviewWindow,
) -> Result<Vec<StandardPostgresProfile>, String> {
    main_only(&window, "PostgreSQL")?;
    tauri::async_runtime::spawn_blocking(move || {
        let store = local_store()?;
        let state = route_snapshot(
            &app,
            store
                .current
                .profiles
                .values()
                .any(|profile| profile.draft.via_host.is_some()),
        );
        Ok(store.list(state.as_ref()))
    })
    .await
    .map_err(|_| INVALID_STORE.to_string())?
}

#[tauri::command]
pub async fn standard_postgres_save(
    app: tauri::AppHandle,
    window: tauri::WebviewWindow,
    id: Option<String>,
    expected_revision: Option<String>,
    expected_route: Option<String>,
    draft: StandardPostgresDraft,
    password: Option<String>,
    forget_password: bool,
) -> Result<StandardPostgresProfile, String> {
    let password = password.map(Zeroizing::new);
    main_only(&window, "PostgreSQL")?;
    tauri::async_runtime::spawn_blocking(move || {
        let mut store = local_store()?;
        let state = route_snapshot(&app, draft.via_host.is_some());
        let request = Save {
            id,
            expected_revision,
            expected_route,
            draft,
            password,
            forget_password,
        };
        store.save(request, &OsCredentials, state.as_ref())
    })
    .await
    .map_err(|_| SAVE_FAILED.to_string())?
}

#[tauri::command]
pub async fn standard_postgres_delete(
    window: tauri::WebviewWindow,
    id: String,
    expected_revision: String,
) -> Result<(), String> {
    main_only(&window, "PostgreSQL")?;
    tauri::async_runtime::spawn_blocking(move || {
        local_store()?.delete(&id, &expected_revision, &OsCredentials)
    })
    .await
    .map_err(|_| SAVE_FAILED.to_string())?
}

#[cfg(test)]
#[path = "standard_postgres_profiles_tests.rs"]
mod tests;
