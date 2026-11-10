//! Saved Cloud SQL databases for the Databases page: the view it lists, and the commands that list, save, delete, start and stop them.
use super::connect::CancelToken;
use super::database_ports::{ensure_password, CloudSqlUpstream, DatabasePorts, NO_LOCAL_PORT};
use super::tunnels::{main_only, snapshot};
use crate::{
    error::AppError,
    state::AppState,
    sync::{
        databases::{self, SavedDatabase},
        env::{OsKeychain, SyncEnv},
        records_v3::SyncStateV3,
        transports,
    },
};
use serde::Serialize;
use std::{cell::RefCell, collections::BTreeSet, sync::Arc};
use tauri::Manager;

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

/// Runs `change` on the library, unless the database `id` runs here: a running database is not changed.
fn unless_running<T>(app: &tauri::AppHandle, id: &str, change: impl FnOnce(&SyncEnv) -> Result<T, String>) -> Result<T, String> {
    app.state::<AppState>().session.databases.edit(id, || crate::sync::engine::with_env(app, change).map_err(|e| e.to_string())?)
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
    let database =
        databases::view(&snapshot(app)?).into_iter().map(|row| row.database).find(|database| database.id == id).ok_or("The saved database no longer exists.")?;
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
        unless_running(&app, &id, |env| delete(env, expected))
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::session::database_ports::tests::FakeUpstream;
    use crate::sync::{
        databases::{
            tests::{database, state},
            DatabaseEnvironment,
        },
        record_runtime, records_v3,
        testkit::{TestClock, TestDevice},
        transports::{tests::in_central_mode, PamCheck},
    };
    use serde_json::json;
    use std::time::{Duration, Instant};
    use zeroize::Zeroizing;

    const ORDERS: &str = "00000000000000a1";
    const ANALYTICS: &str = "00000000000000a2";
    const ORDERS_COPY: &str = "00000000000000a3";
    const STALE: &str = "This database changed on another device. Refresh and try again.";

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
}
