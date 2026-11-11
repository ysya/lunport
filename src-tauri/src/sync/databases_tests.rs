use super::*;
use crate::sync::central::{catalog_of, payload::Catalog};
use crate::sync::records_v3::{decode_state, validate_state, DecodedState, RecordValidationError, PAM_STATE_VERSION};
use crate::sync::transports::{
    tests::{filled_past_the_limit_with_tunnels, filled_short_of, in_central_mode},
    NO_ROOM,
};
use serde_json::json;

const ID: &str = "00000000000000d1";
const OTHER: &str = "00000000000000d2";
const THIRD: &str = "00000000000000d3";
const KEY: &str = "meta:database:00000000000000d1";

const NAME: &str = "Enter a database name (up to 128 characters).";
const PROJECT: &str = "Enter a Google Cloud project id.";
const REGION: &str = "Enter the instance's region, such as asia-east1.";
const INSTANCE: &str = "Enter the Cloud SQL instance name.";
const ACCOUNT: &str = "Enter the Google account as an email address.";
const DEFAULT_DATABASE: &str = "Enter the database to open, such as postgres.";
const LOCAL_PORT: &str = "Choose a local port from 1024 to 65535.";
const IDENTITY: &str = "Invalid database identity.";
const STALE: &str = "This database changed on another device. Refresh and try again.";

pub(crate) fn state() -> SyncStateV3 {
    serde_json::from_value(json!({"version":4,"device_id":"dddddddddddddddddddddddddddddddd","device_name":"fixture","relay_url":"http://127.0.0.1","last_sync_ms":null,"last_error":null})).unwrap()
}

/// A prod database in `acme-prod-123456`, reached through the account `frank@example.com`, with a local port of its own.
pub(crate) fn database(id: &str) -> SavedDatabase {
    SavedDatabase {
        id: id.into(),
        name: "Orders".into(),
        engine: DatabaseEngine::Postgres,
        project: "acme-prod-123456".into(),
        region: "asia-east1".into(),
        instance: "orders-pg".into(),
        environment: DatabaseEnvironment::Prod,
        network: DatabaseNetwork::Public,
        account: Some("frank@example.com".into()),
        default_database: "postgres".into(),
        pam: None,
        local_port: Some(6543),
    }
}

/// `state` with `database` saved on this device alone, as Lunport saved it before its library used central sync, whatever the library
/// uses now.
pub(crate) fn saved_on_this_device(state: &SyncStateV3, database: &SavedDatabase) -> SyncStateV3 {
    let wire = wire_id(&database.id);
    let mut next = state.clone();
    next.local.databases.insert(record_key(RecordKind::Meta, &wire), row_of(state, &wire, Some(payload_of(database)), 1, None, false).unwrap());
    next.version = next.version.max(STATE_VERSION);
    next
}

/// `state` with `database` as a row of the library's account, written the way a projection writes it: not dirty, whatever the library
/// uses now.
fn library_row(state: &mut SyncStateV3, database: &SavedDatabase) {
    let wire = wire_id(&database.id);
    let row = row_of(state, &wire, Some(payload_of(database)), 1, None, false).unwrap();
    state.account.as_mut().unwrap().records.insert(record_key(RecordKind::Meta, &wire), row);
    state.version = state.version.max(STATE_VERSION);
}

/// `database(ID)` after `change`.
fn changed(change: impl FnOnce(&mut SavedDatabase)) -> SavedDatabase {
    let mut database = database(ID);
    change(&mut database);
    database
}

fn reload(state: &SyncStateV3) -> SyncStateV3 {
    let DecodedState::V3(restored) = decode_state(&serde_json::to_string(state).unwrap()).unwrap() else { panic!("the state decodes") };
    *restored
}

/// `record` after `change`.
fn tweaked(record: &Record, change: impl FnOnce(&mut Record)) -> Record {
    let mut record = record.clone();
    change(&mut record);
    record
}

fn ids(state: &SyncStateV3) -> Vec<String> {
    view(state).into_iter().map(|row| row.database.id).collect()
}

fn pam(entitlements: &[&str]) -> PamCheck {
    PamCheck { entitlements: entitlements.iter().map(|name| name.to_string()).collect(), location: "global".into(), duration_secs: 1800, justification: None }
}

/// `state` with the library's writes blocked, as while an account operation is pending.
fn blocked(mut state: SyncStateV3) -> SyncStateV3 {
    state.shared_writes_blocked = true;
    state
}

#[test]
fn a_database_saved_without_central_sync_stays_on_this_device_and_needs_version_12() {
    let base = state();
    assert!(!has_data(&base));
    let next = set(&base, ID, None, Some(database(ID)), 10).unwrap();
    assert_eq!((base.version, next.version, STATE_VERSION), (4, 12, 12));
    let rows = view(&next);
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].database, database(ID));
    assert!(!rows[0].synced && !rows[0].blocked, "a database kept on this device is neither synced nor held back by a library");
    assert!(next.local.databases.contains_key(KEY));
    assert!(next.account.is_none());
    assert!(has_data(&next));
    assert_eq!(view(&reload(&next)), view(&next));
    let mut older = next.clone();
    older.version = 11;
    assert!(validate_state(&older).is_err(), "a release that knows only version 11 never meets these records");
}

#[test]
fn validation_rejects_each_bad_field() {
    assert_eq!(database(ID).validate(), Ok(()));
    let optional_fields_unset = changed(|d| (d.account, d.pam, d.local_port) = (None, None, None));
    assert_eq!(optional_fields_unset.validate(), Ok(()));
    let cases = [
        (changed(|d| d.name = String::new()), NAME),
        (changed(|d| d.name = "   ".into()), NAME),
        (changed(|d| d.name = "x".repeat(129)), NAME),
        (changed(|d| d.name = "Orders\nprod".into()), NAME),
        (changed(|d| d.project = String::new()), PROJECT),
        (changed(|d| d.project = "Acme-Prod-123456".into()), PROJECT),
        (changed(|d| d.project = "acme".into()), PROJECT),
        (changed(|d| d.region = String::new()), REGION),
        (changed(|d| d.region = "Asia-East1".into()), REGION),
        (changed(|d| d.region = "asia-east1-".into()), REGION),
        (changed(|d| d.region = "1asia".into()), REGION),
        (changed(|d| d.instance = String::new()), INSTANCE),
        (changed(|d| d.instance = "Orders-pg".into()), INSTANCE),
        (changed(|d| d.instance = "1orders".into()), INSTANCE),
        (changed(|d| d.instance = "orders-".into()), INSTANCE),
        (changed(|d| d.instance = "orders_pg".into()), INSTANCE),
        (changed(|d| d.instance = format!("o{}", "r".repeat(98))), INSTANCE),
        (changed(|d| d.account = Some("frank".into())), ACCOUNT),
        (changed(|d| d.account = Some("frank@".into())), ACCOUNT),
        (changed(|d| d.account = Some(String::new())), ACCOUNT),
        (changed(|d| d.default_database = String::new()), DEFAULT_DATABASE),
        (changed(|d| d.default_database = "   ".into()), DEFAULT_DATABASE),
        (changed(|d| d.default_database = "d".repeat(64)), DEFAULT_DATABASE),
        (changed(|d| d.default_database = "post\tgres".into()), DEFAULT_DATABASE),
        (changed(|d| d.local_port = Some(0)), LOCAL_PORT),
        (changed(|d| d.local_port = Some(1023)), LOCAL_PORT),
        (changed(|d| d.id = String::new()), IDENTITY),
        (changed(|d| d.id = "00000000000000D1".into()), IDENTITY),
        (changed(|d| d.id = "00000000000000d".into()), IDENTITY),
        (changed(|d| d.id = format!("{ID}0")), IDENTITY),
    ];
    for (bad, sentence) in cases {
        assert_eq!(bad.validate(), Err(sentence.to_string()), "{bad:?}");
    }
}

#[test]
fn validation_accepts_the_edges_of_each_rule() {
    for good in [
        changed(|d| d.name = "n".repeat(128)),
        changed(|d| d.project = "123456".into()),
        changed(|d| d.region = "a".into()),
        changed(|d| d.instance = "o".repeat(98)),
        changed(|d| d.instance = "o9-9o".into()),
        changed(|d| d.default_database = "d".repeat(63)),
        changed(|d| d.local_port = Some(1024)),
        changed(|d| d.local_port = Some(65535)),
    ] {
        assert_eq!(good.validate(), Ok(()), "{good:?}");
    }
}

#[test]
fn a_database_that_requires_a_grant_is_checked_as_a_hosts_route_is() {
    let required = changed(|d| d.pam = Some(pam(&["prod-operate"])));
    assert_eq!(required.validate(), Ok(()));
    let no_entitlement = changed(|d| d.pam = Some(pam(&[])));
    assert_eq!(no_entitlement.validate(), Err("Enter at least one PAM entitlement.".to_string()));
    let bad_name = changed(|d| d.pam = Some(pam(&["Prod Operate"])));
    assert_eq!(bad_name.validate(), Err("Enter PAM entitlement ids such as prod-operate.".to_string()));
    let bad_length = changed(|d| d.pam = Some(PamCheck { duration_secs: 7, ..pam(&["prod-operate"]) }));
    assert_eq!(bad_length.validate(), Err("Enter a grant duration between 1 and 480 minutes.".to_string()));
    assert!(set(&state(), ID, None, Some(no_entitlement), 1).is_err(), "a save runs the same check");
}

#[test]
fn a_stale_expected_value_is_refused() {
    let saved = set(&state(), ID, None, Some(database(ID)), 1).unwrap();
    let older = changed(|d| d.name = "Orders (old name)".into());
    let newer = changed(|d| d.name = "Orders (new name)".into());
    // The refusal a tunnel rule gives: a validation error that names the record and says it changed on another device.
    let error = set(&saved, ID, Some(&older), Some(newer), 2).unwrap_err();
    let RepositoryError::Validation(RecordValidationError::Invalid { field, id, reason }) = &error else { panic!("not a validation error: {error:?}") };
    assert_eq!((*field, id.as_str(), reason.as_str()), ("database", ID, STALE), "an edit of a value another device replaced");
    let refused = repo::invalid("database", ID, STALE);
    assert_eq!(set(&saved, ID, None, Some(older.clone()), 2), Err(refused.clone()), "a new database under an id that is taken");
    assert_eq!(set(&saved, ID, Some(&older), None, 2), Err(refused.clone()), "a removal of a value another device replaced");
    assert_eq!(set(&state(), ID, Some(&database(ID)), None, 2), Err(refused), "a removal of what is not there");
    assert_eq!(ids(&saved), [ID], "a refusal changes nothing");
}

#[test]
fn a_save_keeps_the_identity_and_checks_the_fields() {
    let base = state();
    assert_eq!(set(&base, ID, None, Some(database(OTHER)), 1), Err(repo::invalid("database", ID, "The database identity changed.")));
    assert_eq!(set(&base, "xyz", None, Some(database("xyz")), 1), Err(repo::invalid("database", "xyz", IDENTITY)));
    assert_eq!(set(&base, ID, None, Some(changed(|d| d.instance = "Orders".into())), 1), Err(repo::invalid("database", ID, INSTANCE)));
}

#[test]
fn the_257th_database_is_refused() {
    let id_of = |n: usize| format!("{:016x}", 0x100 + n);
    let mut full = state();
    for n in 0..MAX_DATABASES {
        full = set(&full, &id_of(n), None, Some(database(&id_of(n))), 1).unwrap();
    }
    assert_eq!(view(&full).len(), 256);
    let extra = id_of(MAX_DATABASES);
    assert_eq!(
        set(&full, &extra, None, Some(database(&extra)), 2),
        Err(repo::invalid("database", &extra, "The maximum of 256 saved databases has been reached.")),
    );
    let first = view(&full).remove(0).database;
    let renamed = SavedDatabase { name: "Renamed".into(), ..first.clone() };
    assert!(set(&full, &first.id, Some(&first), Some(renamed), 3).is_ok(), "editing one of the 256 is no new database");
    let freed = set(&full, &first.id, Some(&first), None, 3).unwrap();
    assert!(set(&freed, &extra, None, Some(database(&extra)), 4).is_ok(), "a removal frees a place");
}

#[test]
fn deleting_removes_the_database_from_the_view() {
    let both = set(&set(&state(), ID, None, Some(database(ID)), 1).unwrap(), OTHER, None, Some(database(OTHER)), 2).unwrap();
    assert_eq!(ids(&both), [ID, OTHER]);
    let one = set(&both, ID, Some(&database(ID)), None, 3).unwrap();
    assert_eq!(ids(&one), [OTHER]);
    assert!(!one.local.databases.contains_key(KEY), "this device's own removal simply forgets it");
    let none = set(&one, OTHER, Some(&database(OTHER)), None, 4).unwrap();
    assert!(view(&none).is_empty() && none.local.databases.is_empty() && !has_data(&none));
    assert_eq!(none.version, 12, "a version is never lowered");
    assert!(set(&none, ID, Some(&database(ID)), None, 5).is_err(), "it is gone for good");
}

#[test]
fn deleting_what_is_not_there_writes_nothing() {
    let base = state();
    assert_eq!(set(&base, ID, None, None, 1), Ok(base.clone()), "no version is raised for a library that never held a database");
    let central = in_central_mode(state());
    assert_eq!(set(&central, ID, None, None, 1), Ok(central.clone()));
}

#[test]
fn in_a_central_library_a_database_is_a_dirty_account_row_and_a_removal_a_tombstone() {
    let library = in_central_mode(state());
    let next = set(&library, ID, None, Some(database(ID)), 1).unwrap();
    let row = &next.account.as_ref().unwrap().records[KEY];
    assert!(row.dirty && next.local.databases.is_empty());
    let rows = view(&next);
    assert_eq!((rows.len(), rows[0].synced, rows[0].blocked), (1, true, false));
    assert_eq!(rows[0].database, database(ID));
    assert_eq!(next.version, STATE_VERSION);
    validate_state(&next).unwrap();
    assert_eq!(view(&reload(&next)), rows);

    let removed = set(&next, ID, Some(&database(ID)), None, 2).unwrap();
    let tombstone = &removed.account.as_ref().unwrap().records[KEY];
    assert!(tombstone.dirty && tombstone.record.deleted && tombstone.record.payload.is_null(), "a library removal is a tombstone the capture publishes");
    assert!(view(&removed).is_empty());
    assert!(has_data(&removed), "a tombstone still needs version 12");
    validate_state(&removed).unwrap();
    let revived = set(&removed, ID, None, Some(database(ID)), 3).unwrap();
    assert_eq!(revived.account.as_ref().unwrap().records[KEY].record.version, 3, "a saved-again database continues the identity's revisions");
}

#[test]
fn a_central_library_reads_its_own_rows_and_a_save_supersedes_the_copy_kept_on_this_device() {
    let own = set(&state(), ID, None, Some(database(ID)), 1).unwrap();
    let library = in_central_mode(own);
    assert!(view(&library).is_empty(), "the copy kept on this device is not the library's yet");
    assert!(has_data(&library), "it still needs version 12");
    let saved = set(&library, ID, None, Some(database(ID)), 2).unwrap();
    assert!(saved.local.databases.is_empty(), "the library's row supersedes it");
    assert_eq!(ids(&saved), [ID]);
}

#[test]
fn a_full_catalog_refuses_one_more_database_but_always_allows_removal() {
    let full = filled_past_the_limit_with_tunnels(in_central_mode(state()));
    assert_eq!(set(&full, ID, None, Some(database(ID)), 1).unwrap_err().to_string(), NO_ROOM);
    let held = set(&in_central_mode(state()), ID, None, Some(database(ID)), 1).unwrap();
    let crowded = filled_past_the_limit_with_tunnels(held);
    assert!(set(&crowded, ID, Some(&database(ID)), None, 2).is_ok(), "removal never fails the check");
    let mut chain = full;
    chain.local.central = None;
    assert!(set(&chain, ID, None, Some(database(ID)), 3).is_ok(), "without central sync there is no Catalog to fit");
}

#[test]
fn a_blocked_library_refuses_database_edits_but_this_devices_own_are_free() {
    let library = set(&in_central_mode(state()), ID, None, Some(database(ID)), 1).unwrap();
    let paused = blocked(library);
    assert!(view(&paused)[0].blocked);
    assert_eq!(set(&paused, OTHER, None, Some(database(OTHER)), 2), Err(RepositoryError::ReadOnlyAccount));
    assert_eq!(set(&paused, ID, Some(&database(ID)), None, 2), Err(RepositoryError::ReadOnlyAccount));
    let mut chain = state();
    chain.account = Some(crate::sync::state_v2::AccountState::new(&"a".repeat(64)));
    let chain = blocked(chain);
    let next = set(&chain, ID, None, Some(database(ID)), 1).unwrap();
    assert!(next.local.databases.contains_key(KEY) && next.account.as_ref().unwrap().records.is_empty(), "a chain-mode account is left alone");
    assert!(!view(&next)[0].blocked && !view(&next)[0].synced);
}

#[test]
fn stored_databases_below_version_12_or_failing_their_rules_are_refused() {
    let local = set(&state(), ID, None, Some(database(ID)), 1).unwrap();
    validate_state(&local).unwrap();
    let mut older = local.clone();
    older.version = 11;
    assert!(validate_state(&older).is_err());
    let mut broken = local.clone();
    broken.local.databases.get_mut(KEY).unwrap().record.payload["database"]["instance"] = json!("Orders");
    assert!(validate_state(&broken).is_err());
    let mut misnamed = local.clone();
    misnamed.local.databases.get_mut(KEY).unwrap().record.payload["database"]["id"] = json!(OTHER);
    assert!(validate_state(&misnamed).is_err(), "a record names the database its id names");
    let mut misfiled = local;
    let row = misfiled.local.databases.remove(KEY).unwrap();
    misfiled.local.databases.insert("meta:database:00000000000000d2".into(), row);
    assert!(validate_state(&misfiled).is_err(), "a row is filed under its own key");

    let library = set(&in_central_mode(state()), ID, None, Some(database(ID)), 1).unwrap();
    validate_state(&library).unwrap();
    let mut older = library.clone();
    older.version = PAM_STATE_VERSION;
    assert!(validate_state(&older).is_err());
    let mut broken = library.clone();
    broken.account.as_mut().unwrap().records.get_mut(KEY).unwrap().record.payload["database"]["region"] = json!("Asia");
    assert!(validate_state(&broken).is_err());
    let mut misnamed = library.clone();
    misnamed.account.as_mut().unwrap().records.get_mut(KEY).unwrap().record.payload["database"]["id"] = json!(OTHER);
    assert!(validate_state(&misnamed).is_err());
    let mut tombstone = set(&library, ID, Some(&database(ID)), None, 2).unwrap();
    validate_state(&tombstone).unwrap();
    tombstone.version = 11;
    assert!(validate_state(&tombstone).is_err(), "even a removed database needs the version");
}

#[test]
fn a_record_is_valid_only_in_the_envelope_of_its_id() {
    let stored = set(&state(), ID, None, Some(database(ID)), 1).unwrap().local.databases[KEY].record.clone();
    assert!(valid(&stored) && decode(&stored) == Some(database(ID)));
    assert_eq!(stored.id, wire_id(ID));
    assert!(!valid(&tweaked(&stored, |r| r.kind = RecordKind::Host)), "a database is a Meta record");
    assert!(!valid(&tweaked(&stored, |r| r.version = 0)));
    assert!(!valid(&tweaked(&stored, |r| r.device_id = "device".into())));
    assert!(!valid(&tweaked(&stored, |r| r.payload["schema"] = json!(2))), "only schema 1 is known");
    assert!(!valid(&tweaked(&stored, |r| r.payload["extra"] = json!(true))));
    assert!(!valid(&tweaked(&stored, |r| r.id = wire_id(OTHER))), "a record names the database its id names");
    assert!(!valid(&tweaked(&stored, |r| r.deleted = true)), "a tombstone carries no payload");
    let removed = tweaked(&stored, |r| (r.deleted, r.payload) = (true, serde_json::Value::Null));
    assert!(valid(&removed), "a tombstone is valid");
    assert!(decode(&removed).is_none(), "and holds no database");
}

#[test]
fn only_a_database_id_names_a_database_record() {
    assert_eq!(PREFIX, "database:");
    assert_eq!(wire_id(ID), "database:00000000000000d1");
    assert!(is_id("database:00000000000000d1"));
    let others = [
        "",
        "database:",
        "database:xyz",
        "database:00000000000000D1",
        "database:00000000000000d11",
        ID,
        "tunnel:00000000000000d1",
        "transport:00000000000000d1",
        "pam_scope:00000000000000d1",
    ];
    for other in others {
        assert!(!is_id(other), "{other}");
    }
}

#[test]
fn a_database_decodes_without_its_optional_fields_and_refuses_unknown_ones() {
    let minimal = json!({"id":ID,"name":"Orders","engine":"postgres","project":"acme-prod-123456","region":"asia-east1","instance":"orders-pg",
        "environment":"prod","network":"public","default_database":"postgres"});
    let decoded: SavedDatabase = serde_json::from_value(minimal.clone()).unwrap();
    assert_eq!((decoded.account, decoded.pam, decoded.local_port), (None, None, None));
    for (field, value) in [("password", json!("secret")), ("engine", json!("mysql")), ("environment", json!("production")), ("network", json!("private"))] {
        let mut other = minimal.clone();
        other[field] = value;
        assert!(serde_json::from_value::<SavedDatabase>(other).is_err(), "{field}");
    }
    let mut missing = minimal;
    missing.as_object_mut().unwrap().remove("default_database");
    assert!(serde_json::from_value::<SavedDatabase>(missing).is_err(), "the database to open is required");
    assert_eq!(serde_json::to_value(DatabaseEngine::Postgres).unwrap(), "postgres");
    assert_eq!(serde_json::to_value(DatabaseNetwork::Public).unwrap(), "public");
    let environments = [DatabaseEnvironment::Dev, DatabaseEnvironment::Staging, DatabaseEnvironment::Prod];
    assert_eq!(serde_json::to_value(environments).unwrap(), json!(["dev", "staging", "prod"]));
}

#[test]
fn a_database_names_its_connection_and_knows_when_it_is_prod() {
    let prod = database(ID);
    assert_eq!(prod.connection_name(), "acme-prod-123456:asia-east1:orders-pg");
    assert!(prod.is_prod());
    for environment in [DatabaseEnvironment::Dev, DatabaseEnvironment::Staging] {
        assert!(!SavedDatabase { environment, ..prod.clone() }.is_prod());
    }
    let dev = SavedDatabase { project: "acme-dev-654321".into(), instance: "orders-dev".into(), ..prod };
    assert_eq!(dev.connection_name(), "acme-dev-654321:asia-east1:orders-dev");
}

// ---- Central sync: the Catalog, the publish step and leaving ----

/// A grant requirement that carries the justification of an earlier request.
fn remembered() -> PamCheck {
    PamCheck { justification: Some("restart orders".into()), ..pam(&["prod-operate"]) }
}

#[test]
fn saving_a_database_with_a_justification_stores_it_without_one() {
    let sent = changed(|d| d.pam = Some(remembered()));
    let stored = changed(|d| d.pam = Some(pam(&["prod-operate"])));
    assert_ne!(sent, stored);
    for (whose, base) in [("this device's own", state()), ("the library's", in_central_mode(state()))] {
        let saved = set(&base, ID, None, Some(sent.clone()), 1).unwrap();
        assert_eq!(view(&saved)[0].database, stored, "{whose}: what is read back is what the Catalog may carry");
        let row = saved.account.as_ref().and_then(|account| account.records.get(KEY)).or_else(|| saved.local.databases.get(KEY)).unwrap();
        assert_eq!(row.record.payload["database"]["pam"]["justification"], serde_json::Value::Null, "{whose}");
        assert_eq!(row.record.payload["database"]["pam"]["entitlements"], json!(["prod-operate"]), "the rest of the requirement stays");
        let again = set(&saved, ID, Some(&stored), Some(sent.clone()), 2).unwrap();
        assert_eq!(view(&again)[0].database, stored, "{whose}: the editor sends the database back as it displayed it");
    }
    let library = set(&in_central_mode(state()), ID, None, Some(sent), 1).unwrap();
    let catalog = catalog_of(&library, &Catalog::default()).unwrap();
    assert_eq!(catalog.databases, vec![stored], "the row can be published");
    catalog.validate().unwrap();
}

#[test]
fn the_publish_step_moves_this_devices_databases_into_the_library() {
    let own = set(&set(&state(), ID, None, Some(database(ID)), 1).unwrap(), OTHER, None, Some(database(OTHER)), 2).unwrap();
    assert_eq!(publish_local(&own, 3), Ok(None), "without central sync nothing moves");
    let library = in_central_mode(own);
    assert!(view(&library).is_empty(), "a central library reads its own rows");
    let moved = publish_local(&library, 3).unwrap().expect("both move");
    assert!(moved.local.databases.is_empty());
    assert_eq!(ids(&moved), [ID, OTHER]);
    assert!(view(&moved).iter().all(|row| row.synced && !row.blocked));
    let rows: Vec<_> = moved.account.as_ref().unwrap().records.values().filter(|row| is_id(&row.record.id)).collect();
    assert!(rows.len() == 2 && rows.iter().all(|row| row.dirty), "dirty, so the next capture publishes them");
    assert_eq!(moved.version, STATE_VERSION);
    validate_state(&moved).unwrap();
    assert_eq!(catalog_of(&moved, &Catalog::default()).unwrap().databases, vec![database(ID), database(OTHER)]);
    assert_eq!(publish_local(&moved, 4), Ok(None), "nothing more moves");
    assert_eq!(publish_local(&blocked(library.clone()), 3), Ok(None), "a library whose writes are blocked takes none");
    assert_eq!(publish_local(&in_central_mode(state()), 3), Ok(None), "nor does a library with nothing to move in");
}

#[test]
fn the_publish_step_leaves_a_database_the_library_holds_a_row_for() {
    // The library holds ID, and removed OTHER; this device saved both before, differently, and THIRD besides.
    let mut library = set(&in_central_mode(state()), ID, None, Some(database(ID)), 1).unwrap();
    library = set(&library, OTHER, None, Some(database(OTHER)), 2).unwrap();
    library = set(&library, OTHER, Some(&database(OTHER)), None, 3).unwrap();
    let mine = |id: &str| SavedDatabase { name: "Mine".into(), ..database(id) };
    let held = [ID, OTHER, THIRD].iter().fold(library, |state, id| saved_on_this_device(&state, &mine(id)));
    let moved = publish_local(&held, 4).unwrap().expect("one moves");
    assert!(moved.local.databases.is_empty(), "the other two give way");
    let names: Vec<_> = view(&moved).into_iter().map(|row| (row.database.id, row.database.name)).collect();
    assert_eq!(names, [(ID.to_string(), "Orders".to_string()), (THIRD.to_string(), "Mine".to_string())], "the library's row wins, and a removed database stays removed");
}

#[test]
fn the_publish_step_keeps_what_the_library_has_no_room_for() {
    // In a Catalog that fits but would not with one more database, the database stays on this device.
    let brink = filled_short_of(in_central_mode(state()), |catalog| catalog.databases.push(database(ID)));
    let held = saved_on_this_device(&brink, &database(ID));
    assert_eq!(publish_local(&held, 2), Ok(None));
    assert!(held.local.databases.contains_key(KEY) && view(&held).is_empty());
    // A library that holds the most databases takes no more, whatever their size.
    let id_of = |n: usize| format!("{:016x}", 0x100 + n);
    let mut full = in_central_mode(state());
    for n in 0..MAX_DATABASES {
        library_row(&mut full, &database(&id_of(n)));
    }
    assert_eq!(view(&full).len(), MAX_DATABASES);
    let extra = saved_on_this_device(&full, &database(&id_of(MAX_DATABASES)));
    assert_eq!(publish_local(&extra, 2), Ok(None));
    assert_eq!(extra.local.databases.len(), 1);
}

#[test]
fn a_database_that_would_push_the_catalog_past_one_record_is_refused_though_it_fits_before() {
    let brink = filled_short_of(in_central_mode(state()), |catalog| catalog.databases.push(database(ID)));
    assert_eq!(set(&brink, ID, None, Some(database(ID)), 2).unwrap_err().to_string(), NO_ROOM, "the Catalog measured after the save, not before");
    let free = set(&in_central_mode(state()), ID, None, Some(database(ID)), 2).unwrap();
    let crowded = filled_past_the_limit_with_tunnels(free);
    assert!(set(&crowded, ID, Some(&database(ID)), None, 3).is_ok(), "a removal needs no room");
}

#[test]
fn leaving_keeps_every_database_as_this_devices_own() {
    let mut library = set(&in_central_mode(state()), ID, None, Some(database(ID)), 1).unwrap();
    library = set(&library, OTHER, None, Some(database(OTHER)), 2).unwrap();
    library = set(&library, OTHER, Some(&database(OTHER)), None, 3).unwrap();
    // This device kept copies of the removed one and of a third database alone.
    let before = [OTHER, THIRD].iter().fold(library, |state, id| saved_on_this_device(&state, &database(id)));
    let mut left = before.clone();
    (left.account, left.local.central, left.local.databases) = (None, None, Default::default());
    preserve_on_leave(&before, &mut left, 4).unwrap();
    assert_eq!(ids(&left), [ID, THIRD], "the library's databases and this device's own stay, a removed one does not come back");
    assert!(left.local.databases.values().all(|row| !row.dirty && valid(&row.record)));
    assert_eq!(left.version, STATE_VERSION);
    validate_state(&left).unwrap();
    let mut nothing = state();
    preserve_on_leave(&state(), &mut nothing, 4).unwrap();
    assert!(nothing.local.databases.is_empty() && nothing.version == 4, "no database, no version raised");
}
