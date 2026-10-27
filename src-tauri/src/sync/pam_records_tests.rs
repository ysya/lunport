use super::*;
use crate::sync::central::{catalog_of, payload::Catalog};
use crate::sync::records_v3::{decode_state, validate_state, DecodedState, SyncStateV3, CENTRAL_STATE_VERSION};
use crate::sync::transports::tests::{central_with_host, filled_short_of, in_central_mode};
use serde_json::json;

const HOST: &str = "0000000000000001";
const S1: &str = "00000000000000a1";
const S2: &str = "00000000000000a2";
const OPERATE: &str = "projects/acme-prod-123456/locations/global/entitlements/prod-operate";
const DEV: &str = "projects/acme-dev-654321/locations/global/entitlements/dev-operate";

fn state() -> SyncStateV3 {
    serde_json::from_value(json!({"version":4,"device_id":"dddddddddddddddddddddddddddddddd","device_name":"fixture","relay_url":"http://127.0.0.1","last_sync_ms":null,"last_error":null})).unwrap()
}

fn scope(id: &str, parent: &str) -> PamScope {
    PamScope { id: id.into(), parent: parent.into(), location: "global".into(), account: Some("frank@example.com".into()) }
}

fn memory_of(name: &str, justification: &str) -> GrantRequestMemory {
    GrantRequestMemory { name: name.into(), justification: justification.into(), duration_secs: 1800 }
}

fn reload(state: &SyncStateV3) -> SyncStateV3 {
    let DecodedState::V3(restored) = decode_state(&serde_json::to_string(state).unwrap()).unwrap() else { panic!("the state decodes") };
    *restored
}

#[test]
fn a_scope_saved_without_central_sync_stays_on_this_device_and_needs_version_11() {
    let base = state();
    assert!(!has_data(&base));
    let next = save_scope(&base, scope(S1, "projects/acme-dev-654321"), 10).unwrap();
    assert_eq!((next.version, STATE_VERSION), (11, 11));
    assert_eq!(scopes(&next), vec![scope(S1, "projects/acme-dev-654321")]);
    assert!(next.local.pam_records.contains_key("meta:pam_scope:00000000000000a1"));
    assert_eq!(scopes(&reload(&next)), scopes(&next));
    let mut older = next.clone();
    older.version = 10;
    assert!(validate_state(&older).is_err(), "a release that knows only version 10 never meets these records");
    let gone = remove_scope(&next, S1, 11).unwrap();
    assert!(scopes(&gone).is_empty() && gone.local.pam_records.is_empty(), "this device's own removal simply forgets it");
}

#[test]
fn a_scope_is_checked_and_one_place_is_looked_at_once() {
    let base = state();
    for (parent, location, account) in [
        ("projects/acme", "global", None),
        ("folders/abc", "global", None),
        ("projects/acme-dev-654321", "Global", None),
        ("projects/acme-dev-654321", "global", Some("frank")),
    ] {
        let bad = PamScope { id: S1.into(), parent: parent.into(), location: location.into(), account: account.map(str::to_string) };
        assert!(save_scope(&base, bad, 1).is_err(), "{parent} {location} {account:?}");
    }
    let one = save_scope(&base, scope(S1, "folders/123456789012"), 1).unwrap();
    assert_eq!(save_scope(&one, scope(S2, "folders/123456789012"), 2).unwrap_err(), "Lunport already looks there.");
    let other_account = PamScope { account: Some("ops@example.com".into()), ..scope(S2, "folders/123456789012") };
    assert_eq!(scopes(&save_scope(&one, other_account, 2).unwrap()).len(), 2, "another account is another place");
    let mut full = base.clone();
    for n in 0..MAX_SCOPES {
        full = save_scope(&full, PamScope { id: format!("{:016x}", 0x100 + n), ..scope(S1, &format!("projects/acme-dev-{:06}", n)) }, 1).unwrap();
    }
    assert_eq!(save_scope(&full, scope(S2, "projects/acme-prod-123456"), 2).unwrap_err(), "A library holds at most 64 search scopes.");
}

#[test]
fn in_a_central_library_scopes_and_memories_are_dirty_account_rows_in_the_catalog() {
    let library = central_with_host(HOST);
    let next = save_scope(&library, scope(S1, "projects/acme-dev-654321"), 1).unwrap();
    let row = &next.account.as_ref().unwrap().records["meta:pam_scope:00000000000000a1"];
    assert!(row.dirty && next.local.pam_records.is_empty());
    let next = remember(&next, OPERATE, "restart app-api", 1800, None, 2).unwrap();
    assert_eq!(memory(&next, OPERATE), Some(memory_of(OPERATE, "restart app-api")));
    let catalog = catalog_of(&next, &Catalog::default()).unwrap();
    assert_eq!(catalog.pam_scopes, vec![scope(S1, "projects/acme-dev-654321")]);
    assert_eq!(catalog.pam_requests, vec![memory_of(OPERATE, "restart app-api")]);
    validate_state(&next).unwrap();
    assert_eq!(next.version, STATE_VERSION);
    let removed = remove_scope(&next, S1, 3).unwrap();
    assert!(removed.account.as_ref().unwrap().records["meta:pam_scope:00000000000000a1"].record.deleted, "a library removal is a tombstone the capture publishes");
    assert!(catalog_of(&removed, &Catalog::default()).unwrap().pam_scopes.is_empty());
}

#[test]
fn a_catalog_without_scopes_or_memories_serializes_as_before() {
    let catalog = Catalog::default();
    assert_eq!(serde_json::to_value(&catalog).unwrap(), json!({ "collections": [], "group_orders": [] }));
    let with = Catalog { pam_scopes: vec![scope(S1, "projects/acme-dev-654321")], pam_requests: vec![memory_of(DEV, "debug")], ..Catalog::default() };
    let text = serde_json::to_value(&with).unwrap();
    assert_eq!(text["pam_scopes"][0]["parent"], "projects/acme-dev-654321");
    assert_eq!(text["pam_requests"][0]["name"], DEV);
    with.validate().unwrap();
}

#[test]
fn the_catalog_refuses_too_many_or_bad_items() {
    let scopes: Vec<PamScope> = (0..=MAX_SCOPES).map(|n| PamScope { id: format!("{:016x}", 0x100 + n), ..scope(S1, &format!("projects/acme-dev-{:06}", n)) }).collect();
    assert!(Catalog { pam_scopes: scopes, ..Catalog::default() }.validate().is_err());
    let names: Vec<GrantRequestMemory> = (0..=MAX_REQUESTS).map(|n| memory_of(&format!("projects/acme-dev-654321/locations/global/entitlements/e{n}"), "x")).collect();
    assert!(Catalog { pam_requests: names, ..Catalog::default() }.validate().is_err());
    let twice = vec![scope(S1, "projects/acme-dev-654321"), scope(S2, "projects/acme-dev-654321")];
    assert!(Catalog { pam_scopes: twice, ..Catalog::default() }.validate().is_err(), "one place once");
    assert!(Catalog { pam_requests: vec![memory_of("not-a-name", "x")], ..Catalog::default() }.validate().is_err());
}

#[test]
fn a_memory_is_one_per_entitlement_and_the_32_most_recent_stay() {
    let mut next = remember(&state(), OPERATE, "restart app-api", 1800, None, 1).unwrap();
    next = remember(&next, OPERATE, "deploy hotfix", 3600, None, 2).unwrap();
    assert_eq!(memories(&next), vec![GrantRequestMemory { name: OPERATE.into(), justification: "deploy hotfix".into(), duration_secs: 3600 }]);
    for n in 0..MAX_REQUESTS {
        next = remember(&next, &format!("projects/acme-dev-654321/locations/global/entitlements/e{n}"), "x", 1800, None, 10 + n as u64).unwrap();
    }
    assert_eq!(memories(&next).len(), MAX_REQUESTS);
    assert_eq!(memory(&next, OPERATE), None, "the least recently written went");
    assert!(memory(&next, "projects/acme-dev-654321/locations/global/entitlements/e0").is_some());
}

#[test]
fn a_memory_that_cannot_be_written_leaves_the_state_alone() {
    assert!(remember(&state(), OPERATE, "", 1800, None, 1).is_none(), "an empty justification is never remembered");
    assert!(remember(&state(), OPERATE, "x", 7, None, 1).is_none(), "nor a length the form refuses");
    let mut paused = central_with_host(HOST);
    paused.shared_writes_blocked = true;
    assert!(remember(&paused, OPERATE, "restart app-api", 1800, None, 1).is_none());
}

#[test]
fn a_memory_replaces_the_hosts_memory_an_earlier_release_kept() {
    let mut base = state();
    base.version = 10;
    base.local.transport_grants.insert(HOST.into(), transports::GrantMemory { justification: "old".into(), duration_secs: 1800 });
    let next = remember(&base, OPERATE, "new", 1800, Some(HOST), 1).unwrap();
    assert!(next.local.transport_grants.is_empty());
    assert_eq!(memory(&next, OPERATE).unwrap().justification, "new");
}

#[test]
fn in_a_full_library_older_memories_make_room_and_a_scope_is_refused() {
    let brink = filled_short_of(central_with_host(HOST), |catalog| catalog.pam_scopes.push(scope(S1, "projects/acme-dev-654321")));
    assert_eq!(save_scope(&brink, scope(S1, "projects/acme-dev-654321"), 2).unwrap_err(), NO_SCOPE_ROOM);

    let with_old = remember(&central_with_host(HOST), DEV, "old work", 1800, None, 1).unwrap();
    let brink = filled_short_of(with_old, |catalog| catalog.pam_requests.push(memory_of(OPERATE, "restart app-api")));
    let next = remember(&brink, OPERATE, "restart app-api", 1800, None, 5).expect("the older memory makes room");
    assert_eq!(memory(&next, DEV), None);
    assert!(memory(&next, OPERATE).is_some());
}

#[test]
fn the_publish_step_moves_this_devices_records_into_the_library() {
    let own = save_scope(&state(), scope(S1, "projects/acme-dev-654321"), 1).unwrap();
    let own = remember(&own, OPERATE, "restart app-api", 1800, None, 2).unwrap();
    let library = in_central_mode(own);
    assert!(scopes(&library).is_empty(), "a central library reads its own rows");
    let moved = publish_local(&library, 3).unwrap().expect("both move");
    assert!(moved.local.pam_records.is_empty());
    assert_eq!(scopes(&moved), vec![scope(S1, "projects/acme-dev-654321")]);
    assert_eq!(memory(&moved, OPERATE).map(|m| m.justification), Some("restart app-api".into()));
    validate_state(&moved).unwrap();
    assert_eq!(publish_local(&moved, 4).unwrap(), None, "nothing more moves");
    let mut paused = library.clone();
    paused.shared_writes_blocked = true;
    assert_eq!(publish_local(&paused, 3).unwrap(), None);
}

#[test]
fn leaving_keeps_every_scope_and_memory_as_this_devices_own() {
    let library = central_with_host(HOST);
    let library = save_scope(&library, scope(S1, "projects/acme-dev-654321"), 1).unwrap();
    let library = remember(&library, OPERATE, "restart app-api", 1800, None, 2).unwrap();
    let mut left = library.clone();
    left.account = None;
    left.local.central = None;
    preserve_on_leave(&library, &mut left, 3).unwrap();
    assert_eq!(scopes(&left), vec![scope(S1, "projects/acme-dev-654321")]);
    assert!(memory(&left, OPERATE).is_some());
    assert_eq!(left.version, STATE_VERSION);
}

#[test]
fn library_rows_below_version_11_or_failing_their_rules_are_refused() {
    let library = save_scope(&central_with_host(HOST), scope(S1, "projects/acme-dev-654321"), 1).unwrap();
    validate_state(&library).unwrap();
    let mut older = library.clone();
    older.version = CENTRAL_STATE_VERSION.max(10);
    assert!(validate_state(&older).is_err());
    let mut broken = library.clone();
    let row = broken.account.as_mut().unwrap().records.get_mut("meta:pam_scope:00000000000000a1").unwrap();
    row.record.payload["scope"]["parent"] = json!("projects/x");
    assert!(validate_state(&broken).is_err());
    let mut misnamed = library;
    let row = misnamed.account.as_mut().unwrap().records.get_mut("meta:pam_scope:00000000000000a1").unwrap();
    row.record.payload["scope"]["id"] = json!(S2);
    assert!(validate_state(&misnamed).is_err(), "a record names the scope its id names");
}

#[test]
fn a_memorys_id_is_the_hash_of_its_name_on_every_device() {
    assert_eq!(request_wire_id(OPERATE), request_wire_id(OPERATE));
    assert_ne!(request_wire_id(OPERATE), request_wire_id(DEV));
    assert!(is_request_id(&request_wire_id(OPERATE)));
    assert!(!is_id("pam_scope:xyz") && !is_id("transport:0000000000000001"));
}
