use super::*;
use crate::sync::{
    crypto,
    fake_relay::FakeRelay,
    record_account, record_groups, record_round,
    records_v3::*,
    testkit::{TestClock, TestDevice},
};
use serde_json::json;
const HOST: &str = "0000000000000001";
const GROUP: &str = "0000000000000002";
fn device(relay: &std::sync::Arc<FakeRelay>) -> TestDevice {
    let d = TestDevice::new("library", relay, &TestClock::new());
    let env = d.env();
    let record_runtime::StartupProbe::Records { mut state, .. } =
        record_runtime::probe_startup(&env.state_path, "library")
    else {
        panic!("fresh records")
    };
    state.relay_url = crate::sync::testkit::RELAY_URL.into();
    record_runtime::activate_probe(
        &mut d.runtime.core.lock().unwrap(),
        record_runtime::StartupProbe::Records {
            state,
            fresh: false,
        },
    )
    .unwrap();
    d
}
fn state(d: &TestDevice) -> SyncStateV3 {
    record_runtime::snapshot(&d.env()).unwrap().0
}
fn host(alias: &str) -> HostPayload {
    serde_json::from_value(
        json!({"schema":2,"alias":alias,"hostname":"fixture.invalid","auth":"password"}),
    )
    .unwrap()
}
fn add(d: &TestDevice, grouped: bool) {
    record_runtime::mutate_records(&d.env(), |s| {
        let mut next = s.clone();
        let mut payload = host("web");
        if grouped {
            next = record_groups::create_group(&next, GROUP, HostScope::Local, serde_json::from_value(json!({"schema":1,"name":"Production","parent_id":null,"defaults":{"user":"deploy"}})).unwrap(), true, 1).unwrap();
            payload.schema = GROUPED_HOST_SCHEMA;
            payload.group_id = Some(GROUP.into());
            payload.inherit = vec![InheritedField::User];
            payload.user = "fallback".into();
        }
        repo::create_host(&next, HOST, HostScope::Local, payload, 2).map_err(|e| AppError::Other(e.to_string()))
    }).unwrap();
}
#[test]
fn setup_preserves_identity_payload_inheritance_and_needs_explicit_group_upgrade() {
    let relay = FakeRelay::new();
    let d = device(&relay);
    add(&d, true);
    let before = repo::get_host(&state(&d), HOST).unwrap();
    record_account::create_account(&d.env(), "library").unwrap();
    assert!(enable(&d.env(), false).is_err());
    assert!(!enabled(&state(&d)));
    assert_eq!(
        repo::get_host(&state(&d), HOST).unwrap().host.scope,
        HostScope::Local
    );
    let id = space_id(&state(&d)).unwrap();
    enable(&d.env(), true).unwrap();
    let after = state(&d);
    assert!(enabled(&after));
    assert_eq!(space_id(&after).as_deref(), Some(id.as_str()));
    let saved = repo::get_host(&after, HOST).unwrap();
    assert_eq!(saved.host.payload, before.host.payload);
    assert_eq!(saved.effective_payload, before.effective_payload);
    assert_eq!(
        saved.host.scope,
        HostScope::Space {
            space_id: id.clone()
        }
    );
    assert!(
        after.local.hosts[&record_key(RecordKind::Host, HOST)]
            .record
            .deleted
    );
    assert!(after.spaces[&id].records[&record_key(RecordKind::Group, GROUP)].dirty);
    let repeated = after.clone();
    enable(&d.env(), true).unwrap();
    assert_eq!(state(&d).spaces.len(), repeated.spaces.len());
    assert_eq!(
        repo::get_host(&state(&d), HOST).unwrap().revision,
        saved.revision
    );
}
#[test]
fn joined_device_reuses_library_and_offline_changes_persist_then_reach_other_device() {
    let relay = FakeRelay::new();
    let a = device(&relay);
    let created = record_account::create_account(&a.env(), "first").unwrap();
    enable(&a.env(), false).unwrap();
    record_round::sync_once(&a.env()).unwrap();
    let b = device(&relay);
    add(&b, false);
    record_account::join_account(&b.env(), &created.code, "second").unwrap();
    assert!(!enabled(&state(&b))); // Joining alone cannot silently include old device data.
    enable(&b.env(), false).unwrap();
    assert_eq!(space_id(&state(&a)), space_id(&state(&b)));
    assert_eq!(state(&b).spaces.len(), 1);
    record_round::sync_once(&b.env()).unwrap();
    record_round::sync_once(&a.env()).unwrap();
    relay.set_offline(true);
    let saved = repo::get_host(&state(&b), HOST).unwrap();
    crate::sync::record_commands::edit_records(&b.env(), |s, now| {
        let mut payload = saved.host.payload.clone();
        payload.notes = "edited offline".into();
        repo::update_host(s, HOST, &saved.revision, payload, now)
            .map_err(|e| AppError::Other(e.to_string()))
    })
    .unwrap();
    let disk = std::fs::read(&b.env().state_path).unwrap();
    let DecodedState::V3(reloaded) = decode_state(std::str::from_utf8(&disk).unwrap()).unwrap()
    else {
        panic!("records")
    };
    assert_eq!(
        repo::get_host(&reloaded, HOST).unwrap().host.payload.notes,
        "edited offline"
    );
    assert!(record_round::sync_once(&b.env()).is_err());
    relay.set_offline(false);
    record_round::sync_once(&b.env()).unwrap();
    record_round::sync_once(&a.env()).unwrap();
    assert_eq!(
        repo::get_host(&state(&a), HOST).unwrap().host.payload.notes,
        "edited offline"
    );
}
#[test]
fn new_imported_records_are_included_atomically_without_copying_private_keys() {
    let relay = FakeRelay::new();
    let d = device(&relay);
    record_account::create_account(&d.env(), "library").unwrap();
    enable(&d.env(), false).unwrap();
    crate::sync::record_keys::import_local(
        &d.env(),
        "fixture",
        zeroize::Zeroizing::new(crate::sync::slot_rules::test_keys::plain()),
        crate::vault::store::EntryOrigin::Imported,
    )
    .unwrap();
    let keys = state(&d).local.keys;
    let vault_path = crate::vault::store::vault_path(&d.env().state_path);
    let vault = std::fs::read(&vault_path).unwrap();
    let source = d.home.path().join("library-import");
    std::fs::write(&source, "Host imported\n  HostName fixture.invalid\n").unwrap();
    let options = crate::sync::records_v3::importer::ImportOptions::new(d.home.path().into());
    let prepared = crate::sync::record_import::prepare(&source, &options).unwrap();
    let receipt = crate::sync::record_import::confirm(&d.env(), prepared).unwrap();
    let next = state(&d);
    assert_ne!(
        repo::get_host(&next, &receipt.host_ids[0])
            .unwrap()
            .host
            .scope,
        HostScope::Local
    );
    assert_eq!(next.local.keys, keys);
    assert_eq!(std::fs::read(vault_path).unwrap(), vault);
    let resumed = crate::sync::record_import::resume(&d.env(), &receipt.import_id).unwrap();
    assert_eq!(resumed.host_ids, receipt.host_ids);
    assert_eq!(repo::list_hosts(&state(&d)).unwrap().len(), 1);
    assert!(crypto::is_chain_id(&space_id(&next).unwrap()));
}

#[test]
fn offline_format_upgrades_and_observed_account_blocks_never_bypass_the_gate() {
    let relay = FakeRelay::new();
    let d = device(&relay);
    add(&d, false);
    record_account::create_account(&d.env(), "library").unwrap();
    enable(&d.env(), false).unwrap();
    relay.set_offline(true);
    let before = state(&d);
    assert!(
        crate::sync::record_commands::edit_records(&d.env(), |s, now| {
            record_groups::create_group(
                s,
                GROUP,
                creation_scope(s).unwrap(),
                serde_json::from_value(
                    json!({"schema":1,"name":"Needs upgrade","parent_id":null,"defaults":{}}),
                )
                .unwrap(),
                true,
                now,
            )
            .map_err(|e| AppError::Other(e.to_string()))
        })
        .is_err()
    );
    assert_eq!(state(&d), before);
    record_runtime::mutate_records(&d.env(), |s| {
        let mut next = s.clone();
        next.shared_writes_blocked = true;
        Ok(next)
    })
    .unwrap();
    let saved = repo::get_host(&state(&d), HOST).unwrap();
    assert!(
        crate::sync::record_commands::edit_records(&d.env(), |s, now| repo::update_host(
            s,
            HOST,
            &saved.revision,
            host("blocked"),
            now
        )
        .map_err(|e| AppError::Other(e.to_string())))
        .is_err()
    );
    assert_eq!(
        repo::get_host(&state(&d), HOST).unwrap().host.payload.alias,
        "web"
    );
}

#[test]
fn grouping_keeps_effective_settings_and_checks_the_reviewed_revision() {
    let relay = FakeRelay::new();
    let d = device(&relay);
    add(&d, true);
    record_account::create_account(&d.env(), "library").unwrap();
    enable(&d.env(), true).unwrap();
    let before = state(&d);
    let saved = repo::get_host(&before, HOST).unwrap();
    let moved = set_host_group(&before, HOST, &saved.revision, None, 100).unwrap();
    let ungrouped = repo::get_host(&moved, HOST).unwrap();
    assert!(ungrouped.host.payload.group_id.is_none());
    assert_eq!(
        ungrouped.effective_payload.user,
        saved.effective_payload.user
    );
    assert!(set_host_group(&moved, HOST, &saved.revision, Some(GROUP), 101).is_err());
    let grouped = set_host_group(&moved, HOST, &ungrouped.revision, Some(GROUP), 102).unwrap();
    assert_eq!(
        repo::get_host(&grouped, HOST)
            .unwrap()
            .effective_payload
            .user,
        "deploy"
    );
}

#[test]
fn changing_group_across_retained_transport_sections_is_one_revision_checked_edit() {
    let relay = FakeRelay::new();
    let d = device(&relay);
    add(&d, true);
    record_account::create_account(&d.env(), "library").unwrap();
    enable(&d.env(), true).unwrap();
    let legacy = record_account::create_space(&d.env(), "Retained section").unwrap();
    let other = "0000000000000004";
    record_runtime::mutate_records(&d.env(), |s| record_groups::create_group(s,other,HostScope::Space { space_id:legacy.clone() },serde_json::from_value(json!({"schema":1,"name":"Another Group","parent_id":null,"defaults":{"user":"ops"}})).unwrap(),true,100).map_err(|e| AppError::Other(e.to_string()))).unwrap();
    let before = state(&d);
    let saved = repo::get_host(&before, HOST).unwrap();
    let mut payload = saved.host.payload.clone();
    payload.group_id = Some(other.into());
    let changed = update_host(&before, HOST, &saved.revision, payload.clone(), false, 101).unwrap();
    let after = repo::get_host(&changed, HOST).unwrap();
    assert_eq!(after.host.scope, HostScope::Space { space_id: legacy });
    assert_eq!(after.effective_payload.user, "ops");
    assert_eq!(after.host.id, HOST);
    assert!(update_host(&changed, HOST, &saved.revision, payload, false, 102).is_err());
}
#[test]
fn failed_child_creation_resumes_without_creating_another_library() {
    let relay = FakeRelay::new();
    let d = device(&relay);
    add(&d, false);
    record_account::create_account(&d.env(), "library").unwrap();
    relay.fail_creates_with_429(1);
    assert!(enable(&d.env(), false).is_err());
    let pending = state(&d).pending_account.unwrap();
    record_account::resume_pending(&d.env(), None).unwrap();
    enable(&d.env(), false).unwrap();
    assert_eq!(space_id(&state(&d)), pending.space_id);
    assert_eq!(state(&d).spaces.len(), 1);
}
#[test]
fn ambiguous_destination_preserves_existing_records_without_partial_inclusion() {
    let relay = FakeRelay::new();
    let d = device(&relay);
    add(&d, false);
    record_account::create_account(&d.env(), "library").unwrap();
    enable(&d.env(), false).unwrap();
    record_runtime::mutate_records(&d.env(), |s| {
        repo::create_host(s, "0000000000000003", HostScope::Local, host("web"), 100)
            .map_err(|e| AppError::Other(e.to_string()))
    })
    .unwrap();
    let before = state(&d);
    assert!(enable(&d.env(), false).is_err());
    let after = state(&d);
    assert_eq!(after.local, before.local);
    assert_eq!(
        repo::get_host(&after, "0000000000000003")
            .unwrap()
            .host
            .scope,
        HostScope::Local
    );
    assert_eq!(
        repo::get_host(&after, HOST).unwrap().host.payload,
        repo::get_host(&before, HOST).unwrap().host.payload
    );
}
