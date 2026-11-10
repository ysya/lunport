//! Saved Cloud SQL databases for the Databases page: the view it lists, and the commands that list, save, delete, start and stop them, and
//! show, replace and remove the password of a database's local port.
use super::connect::CancelToken;
use super::database_ports::{ensure_password, password_account, replace_password, DatabasePorts, NO_LOCAL_PORT};
use super::database_upstream::CloudSqlUpstream;
use super::tunnels::{main_only, snapshot};
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

/// Starts the saved database `id` on its local port, with the password this device keeps for it. The port is registered with the broker,
/// so that quitting the app stops it, and its grant questions go through the broker's gates, which hosts use as well.
fn start(app: &tauri::AppHandle, id: &str) -> Result<(), String> {
    super::app::start(app);
    let state = app.state::<AppState>();
    let broker = state.session.broker.lock().unwrap().clone().ok_or("Lunport's connection service is unavailable. Restart Lunport and try again.")?;
    let ports = &state.session.databases;
    ports.use_upstream(|| Arc::new(CloudSqlUpstream::for_app(app, &broker)));
    // The database is read and started under the edit lock, so that no save comes in between.
    let _editing = ports.editing();
    let database = databases::view(&snapshot(app)?).into_iter().map(|row| row.database).find(|database| database.id == id).ok_or(GONE)?;
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::session::database_ports::tests::{wait_until, App, FakeUpstream};
    use crate::sync::{
        databases::{
            tests::{database, state},
            DatabaseEnvironment,
        },
        record_runtime, records_v3,
        testkit::{MemKeychain, TestClock, TestDevice},
        transports::{tests::in_central_mode, PamCheck},
    };
    use serde_json::json;
    use std::sync::atomic::Ordering;
    use std::time::{Duration, Instant};
    use zeroize::Zeroizing;

    const ORDERS: &str = "00000000000000a1";
    const ANALYTICS: &str = "00000000000000a2";
    const ORDERS_COPY: &str = "00000000000000a3";
    const STALE: &str = "This database changed on another device. Refresh and try again.";
    /// A port password as the keychain holds one: 24 bytes as URL-safe base64.
    const STORED: &str = "c3RvcmVkLXBvcnQtcGFzc3dvcmQtMDEy";

    /// A dev database named `name` in `acme-dev-654321`, without a local port.
    fn named(id: &str, name: &str) -> SavedDatabase {
        SavedDatabase {
            name: name.into(),
            environment: DatabaseEnvironment::Dev,
            project: "acme-dev-654321".into(),
            local_port: None,
            ..database(id)
        }
    }

    /// A device whose records are active and empty.
    fn device() -> TestDevice {
        let d = TestDevice::new("databases", &TestClock::new());
        let record_runtime::StartupProbe::Records { mut state, .. } = record_runtime::probe_startup(&d.env().state_path, "databases") else {
            panic!("fresh records")
        };
        state.relay_url = crate::sync::testkit::RELAY_URL.into();
        record_runtime::activate_probe(&mut d.runtime.core.lock().unwrap(), record_runtime::StartupProbe::Records { state, fresh: false }).unwrap();
        d
    }

    /// What `databases_list` shows the device now.
    fn listed(d: &TestDevice) -> Vec<DatabaseView> {
        views(&record_runtime::snapshot(&d.env()).unwrap().0, &DatabasePorts::default())
    }

    fn new_with_justification() -> SavedDatabase {
        SavedDatabase {
            id: String::new(),
            pam: Some(PamCheck {
                entitlements: vec!["prod-operate".into()],
                location: "global".into(),
                duration_secs: 1800,
                justification: Some("restart orders-pg".into()),
            }),
            ..database(ORDERS)
        }
    }

    #[test]
    fn databases_list_shows_saved_databases_as_stopped() {
        assert!(views(&state(), &DatabasePorts::default()).is_empty());
        let orders = database(ORDERS);
        let analytics = named(ANALYTICS, "analytics");
        let copy = named(ORDERS_COPY, "Orders");
        let mut saved = state();
        for (database, now) in [(&orders, 10), (&analytics, 11), (&copy, 12)] {
            saved = databases::set(&saved, &database.id, None, Some(database.clone()), now).unwrap();
        }
        let listed = views(&saved, &DatabasePorts::default());
        let by_name: Vec<&SavedDatabase> = listed.iter().map(|view| &view.database).collect();
        assert_eq!(by_name, vec![&analytics, &orders, &copy], "by name whatever the case, then by identity");
        for view in &listed {
            assert_eq!(view.live, DatabaseLive::default());
            assert_eq!(view.live.phase, DatabasePhase::Stopped);
            assert!(!view.synced && !view.blocked && !view.removed, "a database kept on this device alone is neither the library's nor held back");
        }
    }

    #[test]
    fn a_library_database_is_listed_as_synced_and_a_paused_library_blocks_it() {
        let library = databases::set(&in_central_mode(state()), ORDERS, None, Some(database(ORDERS)), 10).unwrap();
        let listed = views(&library, &DatabasePorts::default());
        assert_eq!(listed.len(), 1);
        assert!(listed[0].synced && !listed[0].blocked && !listed[0].removed);
        let mut paused = library;
        paused.shared_writes_blocked = true;
        let listed = views(&paused, &DatabasePorts::default());
        assert!(listed[0].synced && listed[0].blocked && !listed[0].removed);
    }

    #[test]
    fn a_running_database_is_listed_with_its_port_and_one_deleted_elsewhere_to_be_stopped() {
        let ports = DatabasePorts::new(Arc::new(FakeUpstream::default()));
        let saved = databases::set(&state(), ORDERS, None, Some(database(ORDERS)), 10).unwrap();
        // Started on a port the system picks; the record keeps its own.
        let started = SavedDatabase { local_port: Some(0), ..database(ORDERS) };
        ports.start(&started, Zeroizing::new("c2VjcmV0LXBvcnQtcGFzc3dvcmQtMDEy".into()), CancelToken::default(), Box::new(())).unwrap();
        let listed = views(&saved, &ports);
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].database, database(ORDERS), "the record as it is saved");
        assert_eq!(listed[0].live, ports.live(ORDERS));
        assert_eq!(listed[0].live.phase, DatabasePhase::Running);
        assert!(listed[0].live.port.is_some_and(|port| port != 0));
        assert!(!listed[0].removed);
        // Deleted on another device while it runs here: it is listed as it runs, to be stopped.
        let deleted = databases::set(&saved, ORDERS, Some(&database(ORDERS)), None, 11).unwrap();
        let listed = views(&deleted, &ports);
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].database, started);
        assert!(listed[0].removed && listed[0].blocked && !listed[0].synced);
        assert_eq!(listed[0].live.phase, DatabasePhase::Running);
        ports.stop(ORDERS);
        let end = Instant::now() + Duration::from_secs(10);
        while ports.running(ORDERS) {
            assert!(Instant::now() < end, "the port stops");
            std::thread::sleep(Duration::from_millis(5));
        }
        assert!(views(&deleted, &ports).is_empty(), "once stopped it is gone");
    }

    #[test]
    fn a_view_serializes_with_snake_case_phases_and_null_gaps() {
        let view = DatabaseView { database: database(ORDERS), live: DatabaseLive::default(), synced: false, blocked: false, removed: false };
        let value = serde_json::to_value(&view).unwrap();
        assert_eq!(value["live"], json!({"phase": "stopped", "port": null, "connections": 0, "writable_until_ms": null, "error": null}));
        assert_eq!(value["database"], serde_json::to_value(database(ORDERS)).unwrap());
        assert_eq!((value["synced"].clone(), value["blocked"].clone(), value["removed"].clone()), (json!(false), json!(false), json!(false)));
        let phases = [DatabasePhase::Stopped, DatabasePhase::Starting, DatabasePhase::Running, DatabasePhase::Stopping, DatabasePhase::Error];
        let written: Vec<_> = phases.iter().map(|phase| serde_json::to_value(phase).unwrap()).collect();
        assert_eq!(written, vec![json!("stopped"), json!("starting"), json!("running"), json!("stopping"), json!("error")]);
    }

    #[test]
    fn databases_save_returns_the_database_as_listed() {
        let d = device();
        let asked = new_with_justification();
        let saved = save(&d.env(), asked.clone(), None).unwrap();
        assert!(records_v3::is_host_id(&saved.id), "a new database gets an identity: {}", saved.id);
        assert_eq!(saved.pam.as_ref().map(|pam| pam.justification.clone()), Some(None), "the library holds no justification");
        assert_eq!(saved, SavedDatabase { id: saved.id.clone(), pam: asked.pam.clone().map(|pam| PamCheck { justification: None, ..pam }), ..asked });
        let shown = listed(&d);
        assert_eq!(shown.len(), 1);
        assert_eq!(shown[0].database, saved, "the editor gets back what the list shows");
        // The returned database is what the next save is compared against.
        let renamed = SavedDatabase { name: "Orders (replica)".into(), ..saved.clone() };
        assert_eq!(save(&d.env(), renamed.clone(), Some(saved)).unwrap(), renamed);
        assert_eq!(listed(&d)[0].database, renamed);
    }

    #[test]
    fn every_new_database_gets_an_identity_of_its_own() {
        let d = device();
        let first = save(&d.env(), SavedDatabase { id: String::new(), ..database(ORDERS) }, None).unwrap();
        let second = save(&d.env(), SavedDatabase { id: String::new(), ..named(ANALYTICS, "Analytics") }, None).unwrap();
        assert!(records_v3::is_host_id(&first.id) && records_v3::is_host_id(&second.id));
        assert_ne!(first.id, second.id);
        assert_eq!(listed(&d).len(), 2);
        // A database that has an identity keeps it.
        let kept = save(&d.env(), named(ORDERS_COPY, "Reports"), None).unwrap();
        assert_eq!(kept.id, ORDERS_COPY);
    }

    #[test]
    fn a_refused_save_reads_as_its_sentence() {
        let d = device();
        let saved = save(&d.env(), SavedDatabase { id: String::new(), ..database(ORDERS) }, None).unwrap();
        // Saved as new again while it exists: another device saved it first.
        assert_eq!(save(&d.env(), saved.clone(), None), Err(STALE.to_string()));
        // Saved from a copy that is no longer the stored one.
        let outdated = SavedDatabase { name: "Outdated".into(), ..saved.clone() };
        assert_eq!(save(&d.env(), SavedDatabase { local_port: None, ..saved.clone() }, Some(outdated)), Err(STALE.to_string()));
        // A value the library refuses.
        let invalid = SavedDatabase { region: String::new(), ..saved.clone() };
        assert_eq!(save(&d.env(), invalid, Some(saved.clone())), Err("Enter the instance's region, such as asia-east1.".to_string()));
        assert_eq!(listed(&d)[0].database, saved, "nothing was saved");
    }

    #[test]
    fn deleting_removes_the_database_only_when_it_is_the_one_shown() {
        let d = device();
        let saved = save(&d.env(), SavedDatabase { id: String::new(), ..database(ORDERS) }, None).unwrap();
        let other = save(&d.env(), named(ANALYTICS, "Analytics"), None).unwrap();
        let outdated = SavedDatabase { name: "Outdated".into(), ..saved.clone() };
        assert_eq!(delete(&d.env(), outdated), Err(STALE.to_string()));
        assert_eq!(listed(&d).len(), 2, "a stale delete removes nothing");
        delete(&d.env(), saved.clone()).unwrap();
        assert_eq!(listed(&d).iter().map(|view| view.database.clone()).collect::<Vec<_>>(), vec![other]);
        assert_eq!(delete(&d.env(), saved), Err(STALE.to_string()), "it is gone already");
    }

    // ---- Port passwords ----

    /// A library that holds the prod database `Orders`.
    fn library() -> SyncStateV3 {
        databases::set(&state(), ORDERS, None, Some(database(ORDERS)), 10).unwrap()
    }

    /// What `databases_port_password` answers for `Orders`.
    fn shown(ports: &DatabasePorts, keychain: &MemKeychain) -> Result<String, String> {
        port_password(ports, keychain, ORDERS, || Ok(library()))
    }

    /// What `databases_rotate_port_password` answers for `Orders`.
    fn rotated(ports: &DatabasePorts, keychain: &MemKeychain) -> Result<String, String> {
        rotate_port_password(ports, keychain, ORDERS, || Ok(library()))
    }

    /// Starts `Orders` as `databases_start` does, on a port the system picks, with the password the keychain keeps for it.
    fn started(ports: &DatabasePorts, keychain: &MemKeychain) -> u16 {
        let running = SavedDatabase { local_port: Some(0), ..database(ORDERS) };
        ports.start(&running, ensure_password(keychain, ORDERS).unwrap(), CancelToken::default(), Box::new(())).unwrap();
        ports.live(ORDERS).port.expect("a running port has a port")
    }

    /// An app signed in to `port` with `password`.
    fn signed_in(port: u16, password: &str) -> App {
        let mut app = App::connect(port);
        app.startup(&[("user", "frank"), ("database", "orders")]);
        app.sign_in(password);
        app
    }

    /// An app that `port` refuses for its password.
    fn refused(port: u16, password: &str) {
        let mut app = App::connect(port);
        app.startup(&[("user", "frank"), ("database", "orders")]);
        app.asked_for_password();
        app.password(password);
        assert_eq!(app.error().0, "28P01", "a wrong password");
    }

    #[test]
    fn the_password_command_returns_the_stored_password() {
        let (ports, keychain) = (DatabasePorts::default(), MemKeychain::default());
        keychain.set(&password_account(ORDERS), STORED).unwrap();
        assert_eq!(shown(&ports, &keychain), Ok(STORED.to_string()));
        assert_eq!(shown(&ports, &keychain), Ok(STORED.to_string()), "every time it is asked for");
        assert_eq!(keychain.entry(&password_account(ORDERS)).as_deref(), Some(STORED), "showing it changes nothing");
    }

    #[test]
    fn a_password_shown_before_the_first_start_is_the_one_the_port_asks_for() {
        let (ports, keychain) = (DatabasePorts::new(Arc::new(FakeUpstream::default())), MemKeychain::default());
        // The person copies the password into an app before the database has ever run.
        let first = shown(&ports, &keychain).unwrap();
        assert_eq!(first.len(), 32);
        assert_eq!(keychain.entry(&password_account(ORDERS)).as_deref(), Some(first.as_str()), "kept for the start");
        assert_eq!(shown(&ports, &keychain), Ok(first.clone()), "the same one again");
        let port = started(&ports, &keychain);
        signed_in(port, &first).round_trip(b"select 1");
        // The database stops and starts again: the password is the same.
        ports.stop(ORDERS);
        wait_until("the port stopped", || !ports.running(ORDERS));
        assert_eq!(shown(&ports, &keychain), Ok(first.clone()));
        signed_in(started(&ports, &keychain), &first).round_trip(b"select 2");
    }

    #[test]
    fn a_database_that_is_not_saved_has_no_password_shown_or_made() {
        let (ports, keychain) = (DatabasePorts::default(), MemKeychain::default());
        let gone = || Ok(state());
        assert_eq!(port_password(&ports, &keychain, ORDERS, gone), Err(GONE.to_string()));
        assert_eq!(rotate_port_password(&ports, &keychain, ORDERS, gone), Err(GONE.to_string()));
        assert_eq!(keychain.entry(&password_account(ORDERS)), None, "nothing was made");
        // A library that cannot be read gives no password either.
        let unreadable = || Err("The library could not be read.".to_string());
        assert_eq!(port_password(&ports, &keychain, ORDERS, unreadable), Err("The library could not be read.".to_string()));
        assert_eq!(rotate_port_password(&ports, &keychain, ORDERS, unreadable), Err("The library could not be read.".to_string()));
        assert_eq!(keychain.entry(&password_account(ORDERS)), None);
    }

    #[test]
    fn a_database_that_runs_after_its_record_is_gone_still_has_its_password() {
        let (ports, keychain) = (DatabasePorts::new(Arc::new(FakeUpstream::default())), MemKeychain::default());
        let port = started(&ports, &keychain);
        let stored = keychain.entry(&password_account(ORDERS)).expect("the start made it");
        let gone = || Ok(state());
        assert_eq!(port_password(&ports, &keychain, ORDERS, gone), Ok(stored.clone()));
        let renewed = rotate_port_password(&ports, &keychain, ORDERS, gone).unwrap();
        assert_ne!(renewed, stored);
        refused(port, &stored);
        signed_in(port, &renewed);
    }

    #[test]
    fn a_keychain_that_fails_is_reported_without_a_password() {
        let (ports, keychain) = (DatabasePorts::default(), MemKeychain::default());
        keychain.set(&password_account(ORDERS), STORED).unwrap();
        keychain.fail_reads.store(true, Ordering::SeqCst);
        let error = shown(&ports, &keychain).unwrap_err();
        assert_eq!(error, "The database's password could not be read from the keychain: keychain error: locked");
        assert!(!error.contains(STORED));
        keychain.fail_reads.store(false, Ordering::SeqCst);
        keychain.fail_writes_to(&password_account(ORDERS), true);
        let error = rotated(&ports, &keychain).unwrap_err();
        assert_eq!(error, "The database's password could not be saved in the keychain: keychain error: denied");
        assert_eq!(keychain.entry(&password_account(ORDERS)).as_deref(), Some(STORED));
    }

    #[test]
    fn rotating_replaces_the_password_for_new_connections() {
        let (ports, keychain) = (DatabasePorts::new(Arc::new(FakeUpstream::default())), MemKeychain::default());
        let first = shown(&ports, &keychain).unwrap();
        let port = started(&ports, &keychain);
        let mut open = signed_in(port, &first);
        let second = rotated(&ports, &keychain).unwrap();
        assert_eq!(second.len(), 32);
        assert_ne!(second, first, "a new password");
        assert_eq!(keychain.entry(&password_account(ORDERS)).as_deref(), Some(second.as_str()), "the keychain holds it");
        assert_eq!(shown(&ports, &keychain), Ok(second.clone()), "and the page shows it from now on");
        // The connection that is open goes on; a new one is let in with the new password only.
        open.round_trip(b"select * from orders where unpaid");
        refused(port, &first);
        let mut fresh = signed_in(port, &second);
        fresh.round_trip(b"select 2");
        open.round_trip(b"commit");
        // Every rotation makes another one.
        let third = rotated(&ports, &keychain).unwrap();
        assert!(third != first && third != second);
        refused(port, &second);
        signed_in(port, &third);
    }

    #[test]
    fn a_password_the_keychain_cannot_keep_is_not_handed_to_the_port() {
        let (ports, keychain) = (DatabasePorts::new(Arc::new(FakeUpstream::default())), MemKeychain::default());
        let first = shown(&ports, &keychain).unwrap();
        let port = started(&ports, &keychain);
        keychain.fail_writes_to(&password_account(ORDERS), true);
        assert!(rotated(&ports, &keychain).unwrap_err().starts_with("The database's password could not be saved in the keychain"));
        keychain.fail_writes_to(&password_account(ORDERS), false);
        assert_eq!(keychain.entry(&password_account(ORDERS)).as_deref(), Some(first.as_str()), "the stored password stays");
        assert_eq!(shown(&ports, &keychain), Ok(first.clone()));
        signed_in(port, &first).round_trip(b"select 1");
    }

    #[test]
    fn rotating_a_stopped_database_leaves_the_new_password_for_its_next_start() {
        let (ports, keychain) = (DatabasePorts::new(Arc::new(FakeUpstream::default())), MemKeychain::default());
        let first = shown(&ports, &keychain).unwrap();
        started(&ports, &keychain);
        ports.stop(ORDERS);
        wait_until("the port stopped", || !ports.running(ORDERS));
        let second = rotated(&ports, &keychain).unwrap();
        assert_ne!(second, first);
        assert_eq!(keychain.entry(&password_account(ORDERS)).as_deref(), Some(second.as_str()));
        assert!(!ports.running(ORDERS), "rotating does not start it");
        // The next start reads the keychain, which holds the new password.
        let port = started(&ports, &keychain);
        refused(port, &first);
        signed_in(port, &second).round_trip(b"select 1");
        // A database that never ran can be rotated too.
        let (other, new_keychain) = (DatabasePorts::default(), MemKeychain::default());
        let fresh = rotated(&other, &new_keychain).unwrap();
        assert_eq!(shown(&other, &new_keychain), Ok(fresh));
    }

    #[test]
    fn showing_and_rotating_a_password_wait_for_a_start_or_an_edit() {
        // A start reads the password and starts the port under the edit lock: a password made or replaced in between would not be the port's.
        let (ports, keychain) = (DatabasePorts::default(), MemKeychain::default());
        for rotate in [false, true] {
            let before = keychain.entry(&password_account(ORDERS));
            let editing = ports.editing();
            let (done, finished) = std::sync::mpsc::channel();
            std::thread::scope(|scope| {
                scope.spawn(|| done.send(if rotate { rotated(&ports, &keychain) } else { shown(&ports, &keychain) }).unwrap());
                assert!(finished.recv_timeout(Duration::from_millis(200)).is_err(), "it waits while an edit holds the lock (rotating: {rotate})");
                assert_eq!(keychain.entry(&password_account(ORDERS)), before, "and changes nothing meanwhile");
                drop(editing);
                let answer = finished.recv_timeout(Duration::from_secs(10)).expect("it goes on once the lock is free");
                assert_eq!(answer.as_ref().ok(), keychain.entry(&password_account(ORDERS)).as_ref(), "it answers the password the keychain holds");
            });
        }
    }

    #[test]
    fn deleting_a_database_removes_its_password() {
        let d = device();
        let upstream = Arc::new(FakeUpstream::default());
        let (ports, keychain) = (DatabasePorts::new(upstream.clone()), MemKeychain::default());
        let orders = save(&d.env(), SavedDatabase { id: String::new(), ..database(ORDERS) }, None).unwrap();
        let analytics = save(&d.env(), named(ANALYTICS, "Analytics"), None).unwrap();
        let password = ensure_password(&keychain, &orders.id).unwrap();
        ensure_password(&keychain, &analytics.id).unwrap();
        let account = password_account(&orders.id);
        // A delete that is refused (the list showed another version of it) leaves the password where it is.
        let outdated = SavedDatabase { name: "Outdated".into(), ..orders.clone() };
        assert_eq!(delete_database(&ports, &keychain, &orders.id, || delete(&d.env(), outdated)), Err(STALE.to_string()));
        assert_eq!(keychain.entry(&account).as_deref(), Some(password.as_str()), "a refused delete keeps the password");
        assert_eq!(upstream.released.load(Ordering::SeqCst), 0, "and what was had for the database");
        assert_eq!(listed(&d).len(), 2);
        // The delete that goes through takes the password with it, and the certificate had for the database.
        delete_database(&ports, &keychain, &orders.id, || delete(&d.env(), orders.clone())).unwrap();
        assert_eq!(keychain.entry(&account), None);
        assert_eq!(upstream.released.load(Ordering::SeqCst), 1);
        assert!(keychain.entry(&password_account(&analytics.id)).is_some(), "another database keeps its own");
        assert_eq!(listed(&d).iter().map(|view| view.database.clone()).collect::<Vec<_>>(), vec![analytics.clone()]);
        delete_database(&ports, &keychain, &analytics.id, || delete(&d.env(), analytics.clone())).unwrap();
        assert_eq!(keychain.entry(&password_account(&analytics.id)), None);
        // A database that never had a password is deleted just the same.
        let never = save(&d.env(), named(ORDERS_COPY, "Reports"), None).unwrap();
        assert_eq!(keychain.entry(&password_account(&never.id)), None);
        delete_database(&ports, &keychain, &never.id, || delete(&d.env(), never.clone())).unwrap();
        assert!(listed(&d).is_empty());
    }

    #[test]
    fn a_running_database_is_not_deleted_and_keeps_its_password() {
        let d = device();
        let (ports, keychain) = (DatabasePorts::new(Arc::new(FakeUpstream::default())), MemKeychain::default());
        let saved = save(&d.env(), SavedDatabase { id: String::new(), ..database(ORDERS) }, None).unwrap();
        let running = SavedDatabase { local_port: Some(0), ..saved.clone() };
        ports.start(&running, ensure_password(&keychain, &saved.id).unwrap(), CancelToken::default(), Box::new(())).unwrap();
        let delete_it = || delete_database(&ports, &keychain, &saved.id, || delete(&d.env(), saved.clone()));
        assert_eq!(delete_it(), Err("Stop Orders before you change it.".to_string()));
        assert!(keychain.entry(&password_account(&saved.id)).is_some(), "the password its port asks for stays");
        assert_eq!(listed(&d).len(), 1);
        ports.stop(&saved.id);
        wait_until("the port stopped", || !ports.running(&saved.id));
        delete_it().unwrap();
        assert_eq!(keychain.entry(&password_account(&saved.id)), None);
        assert!(listed(&d).is_empty());
    }

    #[test]
    fn a_password_the_keychain_will_not_release_is_reported_once_the_database_is_gone() {
        let d = device();
        let (ports, keychain) = (DatabasePorts::default(), MemKeychain::default());
        let saved = save(&d.env(), SavedDatabase { id: String::new(), ..database(ORDERS) }, None).unwrap();
        let password = ensure_password(&keychain, &saved.id).unwrap();
        keychain.fail_deletes.store(true, Ordering::SeqCst);
        let error = delete_database(&ports, &keychain, &saved.id, || delete(&d.env(), saved.clone())).unwrap_err();
        assert_eq!(error, "The database was deleted, but its password could not be removed from the keychain: keychain error: denied");
        assert!(!error.contains(password.as_str()));
        assert!(listed(&d).is_empty(), "the record is gone");
    }
}
