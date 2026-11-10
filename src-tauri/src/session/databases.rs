//! Saved Cloud SQL databases for the Databases page: the view it lists, and the commands that list, save, delete, start and stop them,
//! show, replace and remove the password of a database's local port, unlock and lock writes to a prod database through that port, and
//! show and request the Privileged Access Manager grant a database needs.
use super::broker::Broker;
use super::connect::CancelToken;
use super::database_ports::{ensure_password, password_account, replace_password, DatabasePorts, NO_LOCAL_PORT, STAY_LOCKED, WRITABLE_WINDOW};
use super::database_upstream::CloudSqlUpstream;
use super::transports::{pam_status_for, PamStatusView};
use super::tunnels::{main_only, snapshot};
use crate::gcp::rest::GcpClient;
use crate::os_auth::{self, UnlockMethod};
use crate::{
    error::AppError,
    state::AppState,
    sync::{
        databases::{self, SavedDatabase},
        env::{Keychain, OsKeychain, SyncEnv},
        records_v3::SyncStateV3,
        transports,
    },
};
use serde::Serialize;
use std::{cell::RefCell, collections::BTreeSet, sync::Arc};
use tauri::Manager;
use zeroize::Zeroizing;

/// What a command is refused with when the database it names is not there.
const GONE: &str = "The saved database no longer exists.";

/// Where the local port of a database stands on this device.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize)]
#[cfg_attr(test, derive(ts_rs::TS))]
#[cfg_attr(test, ts(export, export_to = "../../src/bindings/"))]
#[serde(rename_all = "snake_case")]
pub enum DatabasePhase {
    #[default]
    Stopped,
    Starting,
    Running,
    Stopping,
    Error,
}

impl DatabasePhase {
    /// Starting, running or stopping: the port holds its address or its connections here.
    pub(crate) fn busy(self) -> bool {
        matches!(self, Self::Starting | Self::Running | Self::Stopping)
    }
}

/// What this device runs for a database. It never syncs: another device runs, or does not run, its own.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
#[cfg_attr(test, derive(ts_rs::TS))]
#[cfg_attr(test, ts(export, export_to = "../../src/bindings/"))]
pub struct DatabaseLive {
    pub phase: DatabasePhase,
    /// The port on 127.0.0.1 the database is offered on while it runs.
    pub port: Option<u16>,
    /// How many client connections are open now.
    pub connections: u32,
    /// Until when writes are allowed through the port, in milliseconds since the Unix epoch; none while it is locked.
    #[cfg_attr(test, ts(type = "number | null"))]
    pub writable_until_ms: Option<u64>,
    /// Why the port failed to start or stopped, as a sentence.
    pub error: Option<String>,
}

/// A saved database as the Databases page lists it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[cfg_attr(test, derive(ts_rs::TS))]
#[cfg_attr(test, ts(export, export_to = "../../src/bindings/"))]
pub struct DatabaseView {
    pub database: SavedDatabase,
    pub live: DatabaseLive,
    /// Whether it is the library's, so it syncs wherever the library does, rather than this device's own.
    pub synced: bool,
    /// Whether the library's writes are blocked, so it cannot be changed now.
    pub blocked: bool,
    /// Whether its record is gone while it still runs here, so that it is listed only to be stopped.
    pub removed: bool,
}

/// Every saved database with what this device runs for it (`ports`), by name and then by identity. A database that runs here although its
/// record is gone is listed too, so that it can be stopped.
fn views(state: &SyncStateV3, ports: &DatabasePorts) -> Vec<DatabaseView> {
    let mut views: Vec<DatabaseView> = databases::view(state)
        .into_iter()
        .map(|row| DatabaseView { live: ports.live(&row.database.id), database: row.database, synced: row.synced, blocked: row.blocked, removed: false })
        .collect();
    let saved: BTreeSet<String> = views.iter().map(|view| view.database.id.clone()).collect();
    let removed = ports.unsaved(&|id| saved.contains(id));
    views.extend(removed.into_iter().map(|(database, live)| DatabaseView { database, live, synced: false, blocked: true, removed: true }));
    views.sort_by_cached_key(|view| (view.database.name.to_lowercase(), view.database.id.clone()));
    views
}

/// Saves (`Some`) or removes (`None`) the database `id` in one edit of the library, provided `expected` is what the list shows. A saved
/// database is answered as that edit stored it, which is how the list shows it from then on.
fn edit(env: &SyncEnv, id: &str, expected: Option<&SavedDatabase>, database: Option<SavedDatabase>) -> Result<Option<SavedDatabase>, String> {
    let stored = RefCell::new(None);
    crate::sync::record_commands::edit_records(env, |state, now| {
        let next = databases::set(state, id, expected, database.clone(), now).map_err(|error| AppError::Other(transports::refusal(error)))?;
        *stored.borrow_mut() = databases::view(&next).into_iter().find(|row| row.database.id == id).map(|row| row.database);
        Ok(next)
    })
    .map_err(|error| error.to_string())?;
    Ok(stored.into_inner())
}

/// Saves `database`, a new one when its id is empty, provided `expected` is the database as the list shows it, and answers it as the
/// list shows it now: the editor compares its next save against that.
fn save(env: &SyncEnv, mut database: SavedDatabase, expected: Option<SavedDatabase>) -> Result<SavedDatabase, String> {
    if database.id.is_empty() {
        database.id = crate::sync::record_commands::new_host_id().map_err(|_| "Could not create a database identity.".to_string())?;
    }
    let id = database.id.clone();
    edit(env, &id, expected.as_ref(), Some(database))?.ok_or_else(|| "The saved database could not be read back.".to_string())
}

/// Deletes `expected`, provided it is the database as the list shows it.
fn delete(env: &SyncEnv, expected: SavedDatabase) -> Result<(), String> {
    let id = expected.id.clone();
    edit(env, &id, Some(&expected), None).map(|_| ())
}

/// Runs `change` on the library as this device holds it now.
fn in_library<T>(app: &tauri::AppHandle, change: impl FnOnce(&SyncEnv) -> Result<T, String>) -> Result<T, String> {
    crate::sync::engine::with_env(app, change).map_err(|e| e.to_string())?
}

/// Runs `change` on the library, unless the database `id` runs here: a running database is not changed.
fn unless_running<T>(app: &tauri::AppHandle, id: &str, change: impl FnOnce(&SyncEnv) -> Result<T, String>) -> Result<T, String> {
    app.state::<AppState>().session.databases.edit(id, || in_library(app, change))
}

/// Deletes a database through `delete_record`, unless it runs here, and then lets go of what this device had for it: its certificate and
/// the password of its port (a database that never had one is deleted just the same). A delete that is refused changes nothing. The edit
/// lock is held to the end, so that no password is made for the database in between.
fn delete_database(ports: &DatabasePorts, keychain: &dyn Keychain, id: &str, delete_record: impl FnOnce() -> Result<(), String>) -> Result<(), String> {
    ports.edit(id, || {
        delete_record()?;
        ports.release(id);
        let removed = keychain.delete(&password_account(id));
        removed.map_err(|error| format!("The database was deleted, but its password could not be removed from the keychain: {error}"))
    })
}

/// Refuses the database `id` unless it is saved, or runs here although its record is gone: a password is kept only for a database that
/// has a port.
fn saved_or_running(state: &SyncStateV3, ports: &DatabasePorts, id: &str) -> Result<(), String> {
    if ports.running(id) || databases::view(state).iter().any(|row| row.database.id == id) {
        Ok(())
    } else {
        Err(GONE.to_string())
    }
}

/// The saved database `id` as the library holds it, or the sentence that it is not there.
fn saved(state: &SyncStateV3, id: &str) -> Result<SavedDatabase, String> {
    databases::view(state).into_iter().map(|row| row.database).find(|database| database.id == id).ok_or_else(|| GONE.to_string())
}

/// The grant state of the saved database `id` as the page's grant line shows it, read the way a host's route is (`pam_status_for`): for
/// the database's account, in its project, over every entitlement its grant check lists. A database with no grant check is `none`. Blocks
/// on a PAM call for each entitlement, so it runs on a blocking thread.
fn grant_status(gcp: &dyn GcpClient, state: &SyncStateV3, id: &str) -> Result<PamStatusView, String> {
    let database = saved(state, id)?;
    Ok(pam_status_for(gcp, database.account.as_deref(), &database.project, database.pam.as_ref()))
}

/// A password as the page receives it: the command answers with a plain string, so this is where it leaves its `Zeroizing` wrapper.
fn revealed(mut password: Zeroizing<String>) -> String {
    std::mem::take(&mut *password)
}

/// The password the apps sign in to the database `id`'s port with: the one this device keeps, else a new one, so that the person can copy
/// it into an app before the database has ever started. It is read under the edit lock a start holds, so that the password shown is the
/// one the port is started with.
fn port_password(ports: &DatabasePorts, keychain: &dyn Keychain, id: &str, library: impl FnOnce() -> Result<SyncStateV3, String>) -> Result<String, String> {
    let _editing = ports.editing();
    saved_or_running(&library()?, ports, id)?;
    ensure_password(keychain, id).map(revealed)
}

/// Makes a new password for the database `id`'s port. The keychain keeps it first: when it cannot, the port goes on with the old one,
/// which the page still shows. Then a port that runs asks it of the connections that come from now on, and those that are open go on. A
/// port that does not run is given none: its next start reads the keychain.
fn rotate_port_password(ports: &DatabasePorts, keychain: &dyn Keychain, id: &str, library: impl FnOnce() -> Result<SyncStateV3, String>) -> Result<String, String> {
    let _editing = ports.editing();
    saved_or_running(&library()?, ports, id)?;
    let password = replace_password(keychain, id)?;
    ports.set_password(id, password.clone());
    Ok(revealed(password))
}

/// Unlocks writes on the prod database `id`'s port for `WRITABLE_WINDOW` once the person confirms it, and answers when the window ends,
/// in milliseconds since the Unix epoch. Where the system can ask (`UnlockMethod::System`), `confirm` asks for Touch ID or the Mac's
/// password, and blocks until the person answers; what the page says does not count there. Elsewhere the page asks in a dialog of its
/// own first (`confirmed_in_app`). A database that cannot be unlocked is refused before anybody is asked; the window opens on the port the
/// person was asked about, and counts from the moment they confirmed.
fn unlock_writes(ports: &DatabasePorts, id: &str, method: UnlockMethod, confirmed_in_app: bool, confirm: impl FnOnce(&str) -> Result<bool, String>) -> Result<u64, String> {
    let checked = ports.unlockable(id)?;
    let confirmed = match method {
        UnlockMethod::System => {
            confirm(&format!("unlock writes on {} (PROD) for {} minutes", checked.name(), WRITABLE_WINDOW.as_secs() / 60)) == Ok(true)
        }
        UnlockMethod::Dialog => confirmed_in_app,
    };
    if !confirmed {
        return Err(STAY_LOCKED.to_string());
    }
    ports.unlock(&checked, ports.now())
}

/// The app's session broker, started when it is not yet: its gates are the ones hosts ask for a grant through, and a database's grant
/// goes through them as well.
fn started_broker(app: &tauri::AppHandle) -> Result<Arc<Broker>, String> {
    super::app::start(app);
    let broker = app.state::<AppState>().session.broker.lock().unwrap().clone();
    broker.ok_or_else(|| "Lunport's connection service is unavailable. Restart Lunport and try again.".to_string())
}

/// Starts the saved database `id` on its local port, with the password this device keeps for it. The port is registered with the broker,
/// so that quitting the app stops it, and its grant questions go through the broker's gates, which hosts use as well.
fn start(app: &tauri::AppHandle, id: &str) -> Result<(), String> {
    let broker = started_broker(app)?;
    let state = app.state::<AppState>();
    let ports = &state.session.databases;
    ports.use_upstream(|| Arc::new(CloudSqlUpstream::for_app(app, &broker)));
    // The database is read and started under the edit lock, so that no save comes in between.
    let _editing = ports.editing();
    let database = saved(&snapshot(app)?, id)?;
    if database.local_port.is_none() {
        return Err(NO_LOCAL_PORT.to_string());
    }
    let password = ensure_password(&OsKeychain, id)?;
    let quit = CancelToken::default();
    let registration = broker.register_tunnel(quit.clone())?;
    ports.start(&database, password, quit, Box::new(registration))
}

#[tauri::command]
pub async fn databases_list(app: tauri::AppHandle, window: tauri::WebviewWindow) -> Result<Vec<DatabaseView>, String> {
    main_only(&window, "Database")?;
    tauri::async_runtime::spawn_blocking(move || Ok(views(&snapshot(&app)?, &app.state::<AppState>().session.databases)))
        .await
        .map_err(|e| e.to_string())?
}

#[tauri::command]
pub async fn databases_save(
    app: tauri::AppHandle,
    window: tauri::WebviewWindow,
    database: SavedDatabase,
    expected: Option<SavedDatabase>,
) -> Result<SavedDatabase, String> {
    main_only(&window, "Database")?;
    tauri::async_runtime::spawn_blocking(move || {
        let id = database.id.clone();
        unless_running(&app, &id, |env| save(env, database, expected))
    })
    .await
    .map_err(|e| e.to_string())?
}

#[tauri::command]
pub async fn databases_delete(app: tauri::AppHandle, window: tauri::WebviewWindow, expected: SavedDatabase) -> Result<(), String> {
    main_only(&window, "Database")?;
    tauri::async_runtime::spawn_blocking(move || {
        let id = expected.id.clone();
        // Nothing that was had for a deleted database stays: its certificate and its port password go with it.
        delete_database(&app.state::<AppState>().session.databases, &OsKeychain, &id, || in_library(&app, |env| delete(env, expected)))
    })
    .await
    .map_err(|e| e.to_string())?
}

#[tauri::command]
pub async fn databases_start(app: tauri::AppHandle, window: tauri::WebviewWindow, id: String) -> Result<(), String> {
    main_only(&window, "Database")?;
    tauri::async_runtime::spawn_blocking(move || start(&app, &id)).await.map_err(|e| e.to_string())?
}

#[tauri::command]
pub fn databases_stop(app: tauri::AppHandle, window: tauri::WebviewWindow, id: String) -> Result<(), String> {
    main_only(&window, "Database")?;
    app.state::<AppState>().session.databases.stop(&id);
    Ok(())
}

/// The password of the database's local port, which the Databases page shows so that it can be copied into an app. The first ask makes it,
/// so that it is there before the database has ever started.
#[tauri::command]
pub async fn databases_port_password(app: tauri::AppHandle, window: tauri::WebviewWindow, id: String) -> Result<String, String> {
    main_only(&window, "Database")?;
    tauri::async_runtime::spawn_blocking(move || port_password(&app.state::<AppState>().session.databases, &OsKeychain, &id, || snapshot(&app)))
        .await
        .map_err(|e| e.to_string())?
}

/// Replaces the password of the database's local port and answers the new one. Connections that are open go on; new ones need it.
#[tauri::command]
pub async fn databases_rotate_port_password(app: tauri::AppHandle, window: tauri::WebviewWindow, id: String) -> Result<String, String> {
    main_only(&window, "Database")?;
    tauri::async_runtime::spawn_blocking(move || rotate_port_password(&app.state::<AppState>().session.databases, &OsKeychain, &id, || snapshot(&app)))
        .await
        .map_err(|e| e.to_string())?
}

/// Unlocks writes on a running prod database's local port for fifteen minutes, and answers when they lock again, in milliseconds since
/// the Unix epoch. Where the system can ask, the person confirms with Touch ID or the Mac's password; elsewhere the page confirms first,
/// in a dialog of its own, and says so with `confirmed_in_app`.
#[tauri::command]
pub async fn databases_unlock_writes(app: tauri::AppHandle, window: tauri::WebviewWindow, id: String, confirmed_in_app: bool) -> Result<u64, String> {
    main_only(&window, "Database")?;
    // The system's question waits for the person for up to two minutes: on a blocking thread, never on the main thread or the async
    // runtime.
    tauri::async_runtime::spawn_blocking(move || {
        unlock_writes(&app.state::<AppState>().session.databases, &id, os_auth::unlock_method(), confirmed_in_app, os_auth::confirm)
    })
    .await
    .map_err(|e| e.to_string())?
}

/// Locks writes on the database's local port again before its fifteen minutes are up.
#[tauri::command]
pub fn databases_lock_writes(app: tauri::AppHandle, window: tauri::WebviewWindow, id: String) -> Result<(), String> {
    main_only(&window, "Database")?;
    app.state::<AppState>().session.databases.lock(&id);
    Ok(())
}

/// Closes the database's idle connections that carry the read-only lock, so that their apps connect again, and answers how many.
#[tauri::command]
pub fn databases_reconnect_locked(app: tauri::AppHandle, window: tauri::WebviewWindow, id: String) -> Result<u32, String> {
    main_only(&window, "Database")?;
    Ok(app.state::<AppState>().session.databases.reconnect_locked(&id))
}

/// The Privileged Access Manager grant the saved database needs, as the grant line of its row shows it: the entitlement that holds a grant
/// and until when, one that is activating, none, or the API's sentence. Read the way a host's route is.
#[tauri::command]
pub async fn databases_pam_status(app: tauri::AppHandle, window: tauri::WebviewWindow, id: String) -> Result<PamStatusView, String> {
    main_only(&window, "Database")?;
    tauri::async_runtime::spawn_blocking(move || {
        let gcp = app.state::<AppState>().gcp.clone();
        grant_status(&*gcp, &snapshot(&app)?, &id)
    })
    .await
    .map_err(|e| e.to_string())?
}

/// Asks for the grant the saved database needs, as a connection to it does when none is held (the Request-a-grant window, through the
/// gates hosts use), and answers when the grant is active, or with the sentence of why not. It blocks for as long as the person takes to
/// answer, and then for the request, on a blocking thread.
#[tauri::command]
pub async fn databases_request_grant(app: tauri::AppHandle, window: tauri::WebviewWindow, id: String) -> Result<(), String> {
    main_only(&window, "Database")?;
    tauri::async_runtime::spawn_blocking(move || {
        let broker = started_broker(&app)?;
        let database = saved(&snapshot(&app)?, &id)?;
        CloudSqlUpstream::for_app(&app, &broker).request_grant(&database, &CancelToken::default())
    })
    .await
    .map_err(|e| e.to_string())?
}

#[cfg(test)]
#[path = "databases_tests.rs"]
mod tests;
