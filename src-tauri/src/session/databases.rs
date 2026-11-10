//! Saved Cloud SQL databases for the Databases page: the view it lists, and the commands that list, save and delete them.
use super::tunnels::{main_only, snapshot};
use crate::{
    error::AppError,
    sync::{
        databases::{self, SavedDatabase},
        env::SyncEnv,
        record_repository::RepositoryError,
        records_v3::{RecordValidationError, SyncStateV3},
    },
};
use serde::Serialize;
use std::cell::RefCell;

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

/// Every saved database with what this device runs for it, by name and then by identity.
fn views(state: &SyncStateV3) -> Vec<DatabaseView> {
    let mut views: Vec<DatabaseView> = databases::view(state)
        .into_iter()
        .map(|row| DatabaseView { database: row.database, live: DatabaseLive::default(), synced: row.synced, blocked: row.blocked, removed: false })
        .collect();
    views.sort_by_cached_key(|view| (view.database.name.to_lowercase(), view.database.id.clone()));
    views
}

/// A refused write as the sentence the editor shows: the reason the database checks gave, else the library's own sentence.
fn refusal(error: RepositoryError) -> String {
    match error {
        RepositoryError::Validation(RecordValidationError::Invalid { reason, .. }) => reason,
        other => crate::sync::transports::refusal(other),
    }
}

/// Saves (`Some`) or removes (`None`) the database `id` in one edit of the library, provided `expected` is what the list shows. A saved
/// database is answered as that edit stored it, which is how the list shows it from then on.
fn edit(env: &SyncEnv, id: &str, expected: Option<&SavedDatabase>, database: Option<SavedDatabase>) -> Result<Option<SavedDatabase>, String> {
    let stored = RefCell::new(None);
    crate::sync::record_commands::edit_records(env, |state, now| {
        let next = databases::set(state, id, expected, database.clone(), now).map_err(|error| AppError::Other(refusal(error)))?;
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

#[tauri::command]
pub async fn databases_list(app: tauri::AppHandle, window: tauri::WebviewWindow) -> Result<Vec<DatabaseView>, String> {
    main_only(&window, "Database")?;
    tauri::async_runtime::spawn_blocking(move || Ok(views(&snapshot(&app)?)))
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
    tauri::async_runtime::spawn_blocking(move || crate::sync::engine::with_env(&app, |env| save(env, database, expected)).map_err(|e| e.to_string())?)
        .await
        .map_err(|e| e.to_string())?
}

#[tauri::command]
pub async fn databases_delete(app: tauri::AppHandle, window: tauri::WebviewWindow, expected: SavedDatabase) -> Result<(), String> {
    main_only(&window, "Database")?;
    tauri::async_runtime::spawn_blocking(move || crate::sync::engine::with_env(&app, |env| delete(env, expected)).map_err(|e| e.to_string())?)
        .await
        .map_err(|e| e.to_string())?
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sync::{
        databases::{
            tests::{database, state},
            DatabaseEnvironment,
        },
        record_repository::RepositoryError,
        record_runtime, records_v3,
        testkit::{TestClock, TestDevice},
        transports::{tests::in_central_mode, PamCheck, NO_ROOM, SYNC_PAUSED},
    };
    use serde_json::json;

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
        views(&record_runtime::snapshot(&d.env()).unwrap().0)
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
        assert!(views(&state()).is_empty());
        let orders = database(ORDERS);
        let analytics = named(ANALYTICS, "analytics");
        let copy = named(ORDERS_COPY, "Orders");
        let mut saved = state();
        for (database, now) in [(&orders, 10), (&analytics, 11), (&copy, 12)] {
            saved = databases::set(&saved, &database.id, None, Some(database.clone()), now).unwrap();
        }
        let listed = views(&saved);
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
        let listed = views(&library);
        assert_eq!(listed.len(), 1);
        assert!(listed[0].synced && !listed[0].blocked && !listed[0].removed);
        let mut paused = library;
        paused.shared_writes_blocked = true;
        let listed = views(&paused);
        assert!(listed[0].synced && listed[0].blocked && !listed[0].removed);
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

    #[test]
    fn the_librarys_own_refusals_read_as_sentences() {
        assert_eq!(refusal(RepositoryError::NoRoom), NO_ROOM);
        assert_eq!(refusal(RepositoryError::ReadOnlyAccount), SYNC_PAUSED);
        let invalid = databases::set(&state(), ORDERS, None, Some(SavedDatabase { name: " ".into(), ..database(ORDERS) }), 1).unwrap_err();
        assert_eq!(refusal(invalid), "Enter a database name (up to 128 characters).");
    }
}
