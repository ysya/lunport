//! The Databases page's commands as the page uses them: the list, saving and deleting, the password of a database's local port, and
//! unlocking writes to a prod database.

use super::*;
use crate::gcp::auth::AuthError;
use crate::gcp::cloudsql::{ConnectSettings, EphemeralCert, EphemeralKey, InstanceRef};
use crate::gcp::oslogin::LoginProfile;
use crate::gcp::pam::{duration_text, rfc3339, Grant};
use crate::gcp::rest::GcpError;
use crate::session::database_ports::tests::{t0, wait_until, App, Clock, FakeUpstream};
use crate::session::database_ports::WRITABLE_WINDOW;
use crate::session::transports::pam_status;
use crate::sync::{
    databases::{
        tests::{database, state},
        DatabaseEnvironment,
    },
    record_runtime, records_v3,
    testkit::{MemKeychain, TestClock, TestDevice},
    transports::{tests::in_central_mode, HostTransport, PamCheck, TransportKind},
};
use serde_json::json;
use std::collections::BTreeMap;
use std::sync::atomic::Ordering;
use std::sync::Mutex;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
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
fn what_connecting_or_locking_reads_marks_a_running_database_changed() {
    let running = guarded();
    let changes = [
        SavedDatabase { project: "acme-dev-654321".into(), ..running.clone() },
        SavedDatabase { region: "europe-west1".into(), ..running.clone() },
        SavedDatabase { instance: "billing-pg".into(), ..running.clone() },
        SavedDatabase { account: Some("ops@example.com".into()), ..running.clone() },
        SavedDatabase { account: None, ..running.clone() },
        SavedDatabase { environment: DatabaseEnvironment::Staging, ..running.clone() },
        SavedDatabase { pam: None, ..running.clone() },
        SavedDatabase { pam: Some(PamCheck { duration_secs: 3600, ..running.pam.clone().unwrap() }), ..running.clone() },
        SavedDatabase { local_port: Some(6544), ..running.clone() },
        SavedDatabase { local_port: None, ..running.clone() },
    ];
    for saved in &changes {
        assert!(changed_for_port(&running, saved), "{saved:?}");
    }
    // What is only shown is no change to the port.
    let shown_only = SavedDatabase { name: "Orders (prod)".into(), default_database: "orders".into(), ..running.clone() };
    assert!(!changed_for_port(&running, &shown_only));
    assert!(!changed_for_port(&running, &running));
}

#[test]
fn a_running_database_saved_anew_elsewhere_is_marked_changed_and_shown_as_it_locks() {
    let ports = DatabasePorts::new(Arc::new(FakeUpstream::default()));
    // A port the system leaves free, saved with the database, so that the port runs exactly what is saved.
    let free = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap().local_addr().unwrap().port();
    let orders = SavedDatabase { local_port: Some(free), ..database(ORDERS) };
    let saved = databases::set(&state(), ORDERS, None, Some(orders.clone()), 10).unwrap();
    ports.start(&orders, Zeroizing::new(STORED.into()), CancelToken::default(), Box::new(())).unwrap();
    let listed = views(&saved, &ports);
    assert!(!listed[0].changed, "it runs what is saved");
    assert_eq!(listed[0].environment, DatabaseEnvironment::Prod);
    // Another device renames it: nothing a connection reads has changed.
    let renamed = SavedDatabase { name: "Orders (prod)".into(), ..orders.clone() };
    assert!(!views(&databases::set(&saved, ORDERS, Some(&orders), Some(renamed), 11).unwrap(), &ports)[0].changed);
    // It saves it as dev: the row says it changed, and it is still shown and locked as prod until it is started again.
    let dev = SavedDatabase { environment: DatabaseEnvironment::Dev, ..orders.clone() };
    let saved_as_dev = databases::set(&saved, ORDERS, Some(&orders), Some(dev.clone()), 11).unwrap();
    let listed = views(&saved_as_dev, &ports);
    assert_eq!(listed[0].database, dev, "the record as it is saved");
    assert!(listed[0].changed);
    assert_eq!(listed[0].environment, DatabaseEnvironment::Prod);
    // Once stopped, it is listed as it is saved.
    ports.stop(ORDERS);
    wait_until("the port stopped", || !ports.running(ORDERS));
    let listed = views(&saved_as_dev, &ports);
    assert!(!listed[0].changed);
    assert_eq!(listed[0].environment, DatabaseEnvironment::Dev);
    // A dev database that runs and is saved as prod elsewhere is shown as prod at once.
    ports.start(&dev, Zeroizing::new(STORED.into()), CancelToken::default(), Box::new(())).unwrap();
    let listed = views(&saved, &ports);
    assert!(listed[0].changed);
    assert_eq!(listed[0].environment, DatabaseEnvironment::Prod);
    ports.stop(ORDERS);
    wait_until("the port stopped", || !ports.running(ORDERS));
}

#[test]
fn a_view_serializes_with_snake_case_phases_and_null_gaps() {
    let view = DatabaseView {
        database: database(ORDERS),
        live: DatabaseLive::default(),
        synced: false,
        blocked: false,
        removed: false,
        changed: false,
        environment: DatabaseEnvironment::Prod,
    };
    let value = serde_json::to_value(&view).unwrap();
    assert_eq!(value["live"], json!({"phase": "stopped", "port": null, "connections": 0, "writable_until_ms": null, "error": null}));
    assert_eq!(value["database"], serde_json::to_value(database(ORDERS)).unwrap());
    assert_eq!((value["synced"].clone(), value["blocked"].clone(), value["removed"].clone()), (json!(false), json!(false), json!(false)));
    assert_eq!((value["changed"].clone(), value["environment"].clone()), (json!(false), json!("prod")));
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
fn a_password_removed_from_the_keychain_outside_lunport_is_made_anew_for_the_running_port() {
    let (ports, keychain) = (DatabasePorts::new(Arc::new(FakeUpstream::default())), MemKeychain::default());
    let first = shown(&ports, &keychain).unwrap();
    let port = started(&ports, &keychain);
    // Someone removes it with the system's keychain app while the database runs: the page shows a new one, which the keychain keeps.
    keychain.delete(&password_account(ORDERS)).unwrap();
    let renewed = shown(&ports, &keychain).unwrap();
    assert_ne!(renewed, first);
    assert_eq!(keychain.entry(&password_account(ORDERS)).as_deref(), Some(renewed.as_str()));
    // The port asks for the password the page shows.
    signed_in(port, &renewed).round_trip(b"select 1");
    refused(port, &first);
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

// ---- Unlocking writes ----

const STAY_LOCKED: &str = "Writes stay locked.";

/// Ports on `clock` with `database` running on a port the system picks.
fn running_on(clock: &Clock, database: SavedDatabase) -> DatabasePorts {
    let ports = DatabasePorts::new(Arc::new(FakeUpstream::default())).timed_by(clock.clocks(), Duration::from_millis(10));
    let started = SavedDatabase { local_port: Some(0), ..database };
    ports.start(&started, Zeroizing::new(STORED.into()), CancelToken::default(), Box::new(())).unwrap();
    ports
}

/// `time` in milliseconds since the Unix epoch.
fn ms(time: SystemTime) -> u64 {
    time.duration_since(UNIX_EPOCH).unwrap().as_millis() as u64
}

#[test]
fn the_dialog_method_requires_an_in_app_confirmation() {
    let clock = Clock::new();
    let ports = running_on(&clock, database(ORDERS));
    let not_asked = |_: &str| -> Result<bool, String> { panic!("the system is not asked where Lunport's dialog confirms") };
    assert_eq!(unlock_writes(&ports, ORDERS, UnlockMethod::Dialog, false, not_asked), Err(STAY_LOCKED.to_string()));
    assert_eq!(ports.live(ORDERS).writable_until_ms, None, "nothing was unlocked");
    let until = ms(t0() + WRITABLE_WINDOW);
    assert_eq!(unlock_writes(&ports, ORDERS, UnlockMethod::Dialog, true, not_asked), Ok(until));
    assert_eq!(ports.live(ORDERS).writable_until_ms, Some(until));
}

#[test]
fn the_system_method_asks_the_person_whatever_the_page_says() {
    let clock = Clock::new();
    let ports = running_on(&clock, database(ORDERS));
    let asked = RefCell::new(Vec::new());
    // The person answers the system's question after `taking`.
    let answers = |answer: Result<bool, String>, taking: Duration| {
        let (asked, clock) = (&asked, &clock);
        move |reason: &str| {
            asked.borrow_mut().push(reason.to_string());
            clock.at(taking);
            answer
        }
    };
    // Cancelled, or a Mac that cannot ask after all: writes stay locked, even where the page says it confirmed.
    assert_eq!(unlock_writes(&ports, ORDERS, UnlockMethod::System, true, answers(Ok(false), Duration::ZERO)), Err(STAY_LOCKED.to_string()));
    let unavailable = Err("Touch ID is not available.".to_string());
    assert_eq!(unlock_writes(&ports, ORDERS, UnlockMethod::System, true, answers(unavailable, Duration::ZERO)), Err(STAY_LOCKED.to_string()));
    assert_eq!(ports.live(ORDERS).writable_until_ms, None);
    // Confirmed after a minute and a half: the fifteen minutes count from then.
    let taking = Duration::from_secs(90);
    assert_eq!(unlock_writes(&ports, ORDERS, UnlockMethod::System, false, answers(Ok(true), taking)), Ok(ms(t0() + taking + WRITABLE_WINDOW)));
    assert_eq!(*asked.borrow(), vec!["unlock writes on Orders (PROD) for 15 minutes"; 3]);
}

#[test]
fn the_systems_question_names_the_database_without_the_characters_that_reorder_text() {
    let ports = running_on(&Clock::new(), SavedDatabase { name: "Ord\u{202e}ers".into(), ..database(ORDERS) });
    let asked = RefCell::new(Vec::new());
    let declined = |reason: &str| {
        asked.borrow_mut().push(reason.to_string());
        Ok(false)
    };
    assert_eq!(unlock_writes(&ports, ORDERS, UnlockMethod::System, false, declined), Err(STAY_LOCKED.to_string()));
    assert_eq!(*asked.borrow(), vec!["unlock writes on Ord?ers (PROD) for 15 minutes"]);
}

#[test]
fn nobody_is_asked_to_unlock_what_cannot_be_unlocked() {
    let never = |_: &str| -> Result<bool, String> { panic!("the person is not asked") };
    // A database that does not run.
    let stopped = DatabasePorts::new(Arc::new(FakeUpstream::default()));
    let not_running = Err("Start the database before you unlock writes.".to_string());
    assert_eq!(unlock_writes(&stopped, ORDERS, UnlockMethod::System, true, never), not_running);
    // A dev database.
    let dev = running_on(&Clock::new(), named(ANALYTICS, "Analytics"));
    assert_eq!(unlock_writes(&dev, ANALYTICS, UnlockMethod::System, true, never), Err("Only prod databases are locked.".to_string()));
    assert_eq!(unlock_writes(&dev, ANALYTICS, UnlockMethod::Dialog, true, never), Err("Only prod databases are locked.".to_string()));
}

#[test]
fn a_database_started_again_while_the_person_confirms_stays_locked() {
    let clock = Clock::new();
    let ports = running_on(&clock, database(ORDERS));
    let start_again = || {
        let started = SavedDatabase { local_port: Some(0), ..database(ORDERS) };
        ports.start(&started, Zeroizing::new(STORED.into()), CancelToken::default(), Box::new(())).unwrap();
    };
    let stop = || {
        ports.stop(ORDERS);
        wait_until("the port stopped", || ports.live(ORDERS).phase == DatabasePhase::Stopped);
    };
    // While the system's question is open, the person stops the database (and could edit it) and starts it again, then confirms: the
    // port that runs now is not the one they were asked about.
    let restarted = |_: &str| -> Result<bool, String> {
        stop();
        start_again();
        Ok(true)
    };
    assert_eq!(unlock_writes(&ports, ORDERS, UnlockMethod::System, false, restarted), Err(STAY_LOCKED.to_string()));
    assert_eq!(ports.live(ORDERS).phase, DatabasePhase::Running);
    assert_eq!(ports.live(ORDERS).writable_until_ms, None, "the port that runs now is locked");
    // Stopped and not started again, it is not running.
    let stopped = |_: &str| -> Result<bool, String> {
        stop();
        Ok(true)
    };
    assert_eq!(unlock_writes(&ports, ORDERS, UnlockMethod::System, false, stopped), Err("Start the database before you unlock writes.".to_string()));
    // The port it was asked about, still running, is unlocked.
    start_again();
    assert!(unlock_writes(&ports, ORDERS, UnlockMethod::System, false, |_: &str| Ok(true)).is_ok());
}

// ---- Grants ----

/// The prod database `Orders` with a grant check on `prod-operate` and `prod-admin`.
fn guarded() -> SavedDatabase {
    SavedDatabase {
        pam: Some(PamCheck { entitlements: vec!["prod-operate".into(), "prod-admin".into()], location: "global".into(), duration_secs: 1800, justification: None }),
        ..database(ORDERS)
    }
}

/// A library that holds `database`.
fn library_of(database: SavedDatabase) -> SyncStateV3 {
    databases::set(&state(), &database.id.clone(), None, Some(database), 10).unwrap()
}

/// An active grant, given `ago` before `now` and requested for `secs` seconds.
fn active_grant(name: &str, now: SystemTime, ago: u64, secs: u32) -> Grant {
    Grant { name: name.into(), state: "ACTIVE".into(), requested_duration: Some(duration_text(secs)), access_grant_time: Some(rfc3339(now - Duration::from_secs(ago))), justification: None }
}

/// Google's PAM as the grant read sees it: the grants each entitlement holds (or PAM's refusal of the search), and every search made.
#[derive(Default)]
struct Pam {
    answers: Mutex<BTreeMap<String, Result<Vec<Grant>, String>>>,
    searched: Mutex<Vec<(Option<String>, String)>>,
}

impl Pam {
    fn answering(&self, entitlement: &str, grants: Result<Vec<Grant>, &str>) {
        self.answers.lock().unwrap().insert(entitlement.into(), grants.map_err(str::to_string));
    }

    fn searched(&self) -> Vec<(Option<String>, String)> {
        self.searched.lock().unwrap().clone()
    }
}

impl GcpClient for Pam {
    fn login_profile(&self, _: Option<&str>, _: &str) -> Result<LoginProfile, GcpError> {
        panic!("a grant read never reads OS Login")
    }

    fn import_ssh_public_key(&self, _: Option<&str>, _: &str, _: &str) -> Result<LoginProfile, GcpError> {
        panic!("a grant read never imports a key")
    }

    fn grants(&self, account: Option<&str>, entitlement: &str) -> Result<Vec<Grant>, GcpError> {
        self.searched.lock().unwrap().push((account.map(str::to_string), entitlement.to_string()));
        let id = entitlement.rsplit('/').next().unwrap();
        match self.answers.lock().unwrap().get(id) {
            Some(Ok(grants)) => Ok(grants.clone()),
            Some(Err(message)) => Err(GcpError::Refused { api: "Privileged Access Manager", message: message.clone() }),
            None => Ok(Vec::new()),
        }
    }

    fn create_grant(&self, _: Option<&str>, _: &str, _: u32, _: &str) -> Result<Grant, GcpError> {
        panic!("a grant read never requests a grant")
    }

    fn get_grant(&self, _: Option<&str>, _: &str) -> Result<Grant, GcpError> {
        panic!("a grant read never reads a grant back")
    }
}

const OPERATE: &str = "projects/acme-prod-123456/locations/global/entitlements/prod-operate";
const ADMIN: &str = "projects/acme-prod-123456/locations/global/entitlements/prod-admin";

#[test]
fn a_databases_grant_is_read_the_way_a_hosts_is() {
    let now = SystemTime::now();
    let gcp = Pam::default();
    gcp.answering("prod-operate", Ok(vec![active_grant("g-op", now, 600, 1800)]));
    gcp.answering("prod-admin", Ok(vec![active_grant("g-ad", now, 300, 3600)]));
    let database = guarded();
    let view = grant_status(&gcp, &library_of(database.clone()), ORDERS).unwrap();
    // The entitlement whose grant lasts longest, with its end.
    assert_eq!((view.state.as_str(), view.entitlement.as_deref(), view.message.as_deref()), ("active", Some("prod-admin"), None));
    assert!(view.active_until_ms.is_some());
    // Asked as the database's account, in its project and PAM location, for each entitlement of its grant check.
    let account = Some("frank@example.com".to_string());
    assert_eq!(gcp.searched(), vec![(account.clone(), OPERATE.to_string()), (account.clone(), ADMIN.to_string())]);
    // A host whose route asks for the same grant reads exactly the same.
    let route = HostTransport {
        host_id: "0000000000000001".into(),
        kind: TransportKind::GcpIap {
            project: database.project.clone(),
            zone: "asia-east1-b".into(),
            instance: "jumpbox".into(),
            interface: "nic0".into(),
            account: database.account.clone(),
            os_login: false,
            pam: database.pam.clone(),
        },
    };
    assert_eq!(pam_status(&gcp, &route), view);
}

#[test]
fn a_databases_grant_read_reports_none_activating_and_the_apis_sentence() {
    let now = SystemTime::now();
    let gcp = Pam::default();
    let library = library_of(guarded());
    let read = |gcp: &Pam| grant_status(gcp, &library, ORDERS).unwrap();
    // No grant anywhere.
    let none = read(&gcp);
    assert_eq!((none.state.as_str(), none.entitlement, none.active_until_ms, none.message), ("none", None, None, None));
    // One on its way.
    let activating = Grant { state: "ACTIVATING".into(), access_grant_time: None, ..active_grant("g-op", now, 0, 1800) };
    gcp.answering("prod-operate", Ok(vec![activating]));
    let view = read(&gcp);
    assert_eq!((view.state.as_str(), view.entitlement.as_deref(), view.active_until_ms), ("activating", Some("prod-operate"), None));
    // An ACTIVE grant whose time is up counts for nothing, as for a host.
    gcp.answering("prod-operate", Ok(vec![active_grant("g-stale", now, 7200, 1800)]));
    assert_eq!(read(&gcp).state, "none");
    // The API refused a search and nothing else answered with a grant: its sentence.
    gcp.answering("prod-operate", Err("quota exceeded"));
    let refused = read(&gcp);
    assert_eq!((refused.state.as_str(), refused.entitlement), ("error", None));
    assert_eq!(refused.message.as_deref(), Some("Privileged Access Manager refused the request: quota exceeded."));
}

#[test]
fn a_database_with_no_grant_check_reads_no_grant() {
    let gcp = Pam::default();
    let view = grant_status(&gcp, &library_of(database(ORDERS)), ORDERS).unwrap();
    assert_eq!((view.state.as_str(), view.entitlement, view.active_until_ms, view.message), ("none", None, None, None));
    assert!(gcp.searched().is_empty(), "there is nothing to ask PAM");
}

#[test]
fn a_grant_is_neither_read_nor_requested_for_a_database_that_is_not_saved() {
    let gcp = Pam::default();
    assert_eq!(grant_status(&gcp, &state(), ORDERS), Err(GONE.to_string()));
    assert_eq!(saved(&state(), ORDERS), Err(GONE.to_string()));
    assert!(gcp.searched().is_empty());
    // Another database's identity finds nothing either.
    assert_eq!(saved(&library_of(guarded()), ANALYTICS), Err(GONE.to_string()));
    assert_eq!(saved(&library_of(guarded()), ORDERS), Ok(guarded()));
}

// ---- Listing instances ----

/// The Cloud SQL Admin API as the New database dialog asks it: what it answers for any project, and every list asked.
struct Instances {
    answer: Result<Vec<InstanceSummary>, GcpError>,
    asked: Mutex<Vec<(Option<String>, String)>>,
}

impl Instances {
    fn answering(answer: Result<Vec<InstanceSummary>, GcpError>) -> Instances {
        Instances { answer, asked: Mutex::default() }
    }

    fn asked(&self) -> Vec<(Option<String>, String)> {
        self.asked.lock().unwrap().clone()
    }
}

impl SqlAdmin for Instances {
    fn connect_settings(&self, _: Option<&str>, _: &InstanceRef) -> Result<ConnectSettings, GcpError> {
        panic!("listing instances never reads connect settings")
    }

    fn ephemeral_cert(&self, _: Option<&str>, _: &InstanceRef, _: &EphemeralKey) -> Result<EphemeralCert, GcpError> {
        panic!("listing instances never asks for a certificate")
    }

    fn list_instances(&self, account: Option<&str>, project: &str) -> Result<Vec<InstanceSummary>, GcpError> {
        self.asked.lock().unwrap().push((account.map(str::to_string), project.to_string()));
        self.answer.clone()
    }
}

fn instance(name: &str, iam_authentication: bool) -> InstanceSummary {
    InstanceSummary { name: name.into(), region: "asia-east1".into(), database_version: "POSTGRES_16".into(), public_ip: true, private_ip: false, iam_authentication }
}

#[test]
fn the_instance_picker_lists_what_the_api_lists_for_the_account_and_project() {
    let found = vec![instance("orders-pg", true), instance("reports-pg", false)];
    let sql = Instances::answering(Ok(found.clone()));
    assert_eq!(list_instances(&sql, Some("frank@example.com"), "acme-prod-123456"), Ok(found.clone()));
    // No account asks for gcloud's active one.
    assert_eq!(list_instances(&sql, None, "acme-dev-654321"), Ok(found));
    assert_eq!(sql.asked(), vec![(Some("frank@example.com".to_string()), "acme-prod-123456".to_string()), (None, "acme-dev-654321".to_string())]);
    // A project with no PostgreSQL instance lists none.
    assert_eq!(list_instances(&Instances::answering(Ok(Vec::new())), None, "acme-dev-654321"), Ok(Vec::new()));
}

#[test]
fn a_project_that_is_not_one_lists_none_and_asks_google_nothing() {
    let sql = Instances::answering(Ok(vec![instance("orders-pg", true)]));
    for project in ["", "acme", "ACME-PROD-123456", "acme-prod-", "acme prod 123456", "../acme-prod-123456", "acme-prod-123456/instances", "projects/acme-prod-123456", "acme-prod-123456?x=1"] {
        assert_eq!(list_instances(&sql, Some("frank@example.com"), project), Ok(Vec::new()), "{project:?}");
    }
    assert!(sql.asked().is_empty());
}

#[test]
fn an_account_that_is_not_an_address_is_refused_before_google_is_asked() {
    let sql = Instances::answering(Ok(vec![instance("orders-pg", true)]));
    let refusal = Err("Enter the Google account as an email address.".to_string());
    // The account names a directory under gcloud's config, so only an address can be one.
    for account in ["", "frank", "frank@example", "../frank@example.com", " frank@example.com", "frank/ops@example.com"] {
        assert_eq!(list_instances(&sql, Some(account), "acme-prod-123456"), refusal, "{account:?}");
    }
    // The account is judged first, as for the entitlement suggestions.
    assert_eq!(list_instances(&sql, Some("frank"), "acme"), refusal);
    assert!(sql.asked().is_empty());
}

#[test]
fn a_listing_that_fails_reads_as_the_sentence_that_says_why_the_list_is_empty() {
    let failing = |error: GcpError| list_instances(&Instances::answering(Err(error)), Some("frank@example.com"), "acme-dev-654321");
    let disabled = "The Cloud SQL Admin API is not enabled in acme-dev-654321. Enable it in the Google Cloud console, then try again.";
    assert_eq!(
        failing(GcpError::Refused { api: "Cloud SQL Admin", message: disabled.into() }),
        Err(format!("Cloud SQL Admin refused the request: {disabled}"))
    );
    assert_eq!(
        failing(GcpError::Denied { api: "Cloud SQL Admin", status: 403, account: "frank@example.com".into() }),
        Err("frank@example.com may not call the Cloud SQL Admin API (HTTP 403).".to_string())
    );
    assert_eq!(failing(GcpError::Network("operation timed out".into())), Err("Google's API could not be reached: operation timed out.".to_string()));
    // A sign-in that expired says which account signs in again.
    assert_eq!(
        failing(GcpError::Auth(AuthError::SignInExpired { account: "frank@example.com".into() })),
        Err("Google sign-in for frank@example.com has expired or was revoked; run `gcloud auth login frank@example.com` and connect again.".to_string())
    );
}
