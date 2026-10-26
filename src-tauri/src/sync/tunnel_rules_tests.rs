use super::*;
use crate::{
    ssh::forward::ForwardKind,
    sync::{
        crypto::ChainKeys,
        record::{Envelope, ACCOUNT_META_ID},
        record_merge,
        records_v3::*,
        relay::PullResponse,
        state_v2::{sealed_key, AccountState, SealedRecord},
    },
};
use serde_json::json;
const A: &str = "0000000000000001";
const B: &str = "0000000000000002";
pub(super) fn state() -> SyncStateV3 {
    serde_json::from_value(json!({"version":4,"device_id":"dddddddddddddddddddddddddddddddd","device_name":"fixture","relay_url":"http://127.0.0.1","last_sync_ms":null,"last_error":null})).unwrap()
}
pub(super) fn rule(id: &str) -> TunnelRule {
    TunnelRule {
        id: id.into(),
        host_id: A.into(),
        name: "Production database".into(),
        forward: ForwardSpec {
            kind: ForwardKind::Local,
            bind_address: "127.0.0.1".into(),
            port: 15432,
            target_host: "db.internal".into(),
            target_port: 5432,
        },
    }
}
fn account() -> (SyncStateV3, ChainKeys) {
    let mut state = state();
    let keys = ChainKeys::generate().unwrap();
    let mut account = AccountState::new(&keys.chain_id);
    account.baseline_established = true;
    account.cursor_seq = 1;
    account.remote_schema_version = Some(4);
    let mut record = repo::ordered_record(
        &state,
        ACCOUNT_META_ID,
        json!({"schema_version":4,"created_by_app_version":"fixture"}),
        false,
        1,
        &[],
    )
    .unwrap();
    record.kind = RecordKind::Meta;
    account.records.insert(
        record_key(RecordKind::Meta, ACCOUNT_META_ID),
        LocalRecord {
            record,
            seq: 1,
            dirty: false,
        },
    );
    state.account = Some(account);
    (state, keys)
}
fn envelope(keys: &ChainKeys, record: &Record, seq: u64) -> Envelope {
    let item = record_merge::encode_record(keys, record, 0).unwrap();
    Envelope {
        id_hash: item.id_hash,
        kind: item.kind,
        seq,
        nonce: item.nonce,
        ciphertext: item.ciphertext,
        deleted: item.deleted,
    }
}
#[test]
fn local_definitions_round_trip_without_running_state_or_host_schema_changes() {
    let base = state();
    let rule = rule(A);
    let next = set(&base, None, A, None, Some(rule.clone()), 10).unwrap();
    assert_eq!(next.version, super::STATE_VERSION);
    assert_eq!(next.local.hosts, base.local.hosts);
    assert_eq!(next.local.groups, base.local.groups);
    let text = serde_json::to_string(&next).unwrap();
    let DecodedState::V3(restored) = decode_state(&text).unwrap() else {
        panic!()
    };
    assert_eq!(view(&restored)[0].rule, rule);
    assert!(!text.contains("connections") && !text.contains("running"));
    let deleted = set(&restored, None, A, Some(&rule), None, 11).unwrap();
    assert!(view(&deleted).is_empty());
    assert!(set(&deleted, None, A, Some(&rule), None, 12).is_err());
}
#[test]
fn independent_device_edits_merge_per_rule_and_deletions_do_not_resurrect() {
    let (base, keys) = account();
    let first = rule(A);
    let second = rule(B);
    let one = set(&base, Some(&keys), A, None, Some(first.clone()), 10).unwrap();
    let mut other = base.clone();
    other.device_id = "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee".into();
    let other = set(&other, Some(&keys), B, None, Some(second.clone()), 11).unwrap();
    let record =
        &one.account.as_ref().unwrap().records[&record_key(RecordKind::Meta, &wire_id(A))].record;
    let result = record_merge::merge_account(
        other.account.as_ref().unwrap(),
        &keys,
        &PullResponse {
            records: vec![envelope(&keys, record, 2)],
            latest_seq: 2,
        },
        1,
    );
    assert_eq!(result.gate, record_merge::AccountGate::Compatible);
    let mut merged = other;
    merged.account = Some(result.section);
    assert_eq!(view(&merged).len(), 2);
    assert_eq!(
        record_merge::account_outgoing(merged.account.as_ref().unwrap(), &keys)
            .unwrap()
            .len(),
        1,
        "only the other device's independent edit remains dirty"
    );
    let removed = set(&merged, Some(&keys), A, Some(&first), None, 12).unwrap();
    let tombstone = &removed.account.as_ref().unwrap().records
        [&record_key(RecordKind::Meta, &wire_id(A))]
        .record;
    let result = record_merge::merge_account(
        one.account.as_ref().unwrap(),
        &keys,
        &PullResponse {
            records: vec![envelope(&keys, tombstone, 3)],
            latest_seq: 3,
        },
        1,
    );
    let key = record_key(RecordKind::Meta, &wire_id(A));
    assert_eq!(result.conflicts, vec![key.clone()]);
    assert!(matches!(
        &result.section.recovery.conflicts[&key][0].remote,
        crate::sync::record_conflicts::RecordVersion::Public(row) if row.record.deleted
    ));
    assert!(
        record_merge::account_outgoing(&result.section, &keys)
            .unwrap()
            .is_empty(),
        "an unacknowledged edit cannot silently overwrite the remote deletion"
    );

    // Once this device has read back its accepted edit, a subsequent deletion wins.
    let accepted = record_merge::merge_account(
        one.account.as_ref().unwrap(),
        &keys,
        &PullResponse {
            records: vec![envelope(&keys, record, 2)],
            latest_seq: 2,
        },
        1,
    );
    let result = record_merge::merge_account(
        &accepted.section,
        &keys,
        &PullResponse {
            records: vec![envelope(&keys, tombstone, 3)],
            latest_seq: 3,
        },
        2,
    );
    assert!(result.conflicts.is_empty());
    let mut merged = one;
    merged.account = Some(result.section);
    assert!(view(&merged).is_empty());
}
#[test]
fn metadata_retained_by_an_old_client_is_admitted_without_another_relay_row() {
    let (base, keys) = account();
    let rule = rule(A);
    let next = set(&base, Some(&keys), A, None, Some(rule.clone()), 10).unwrap();
    let record =
        &next.account.as_ref().unwrap().records[&record_key(RecordKind::Meta, &wire_id(A))].record;
    let item = envelope(&keys, record, 2);
    let mut older = base;
    let account = older.account.as_mut().unwrap();
    account.cursor_seq = 2;
    account.sealed.insert(
        sealed_key("meta", &item.id_hash),
        SealedRecord {
            envelope: item,
            dirty: false,
            public_identity: None,
        },
    );
    let result = record_merge::merge_account(
        account,
        &keys,
        &PullResponse {
            records: vec![],
            latest_seq: 2,
        },
        2,
    );
    assert_eq!(result.gate, record_merge::AccountGate::Compatible);
    older.account = Some(result.section);
    assert_eq!(view(&older)[0].rule, rule);
    assert!(older.account.unwrap().sealed.is_empty());
}
#[test]
fn future_opaque_rules_and_stale_edits_are_preserved() {
    let (base, keys) = account();
    let original = rule(A);
    let saved = set(&base, Some(&keys), A, None, Some(original.clone()), 10).unwrap();
    let mut changed = original.clone();
    changed.forward.target_port = 5433;
    let newer = set(
        &saved,
        Some(&keys),
        A,
        Some(&original),
        Some(changed.clone()),
        11,
    )
    .unwrap();
    assert!(set(&newer, Some(&keys), A, Some(&original), None, 12).is_err());
    let mut future = newer.account.as_ref().unwrap().records
        [&record_key(RecordKind::Meta, &wire_id(A))]
        .record
        .clone();
    future.version += 1;
    future.updated_at_ms += 1;
    future.payload["schema"] = json!(2);
    let item = envelope(&keys, &future, 2);
    let result = record_merge::merge_account(
        saved.account.as_ref().unwrap(),
        &keys,
        &PullResponse {
            records: vec![item],
            latest_seq: 2,
        },
        1,
    );
    assert_eq!(result.gate, record_merge::AccountGate::Compatible);
    let mut blocked = saved;
    blocked.account = Some(result.section);
    assert!(view(&blocked)[0].blocked);
    assert!(set(&blocked, Some(&keys), A, Some(&original), None, 12).is_err());
    assert_eq!(blocked.account.as_ref().unwrap().sealed.len(), 1);
    // An older client has no verified hint yet. Start and write guards still use
    // the authenticated wire identity, even before the next background merge.
    for row in blocked.account.as_mut().unwrap().sealed.values_mut() {
        row.public_identity = None;
    }
    assert!(blocked_by_opaque(&blocked, Some(&keys), &wire_id(A)));
    assert!(!blocked_by_opaque(&blocked, Some(&keys), &wire_id(B)));
}
/// Tunnels share the Catalog's room with routes in a library that uses central sync (design 2026-10-26, Room in the Catalog).
#[test]
fn a_full_catalog_refuses_one_more_tunnel_in_central_mode() {
    use crate::sync::transports::{
        tests::{central_with_host, filled_past_the_limit_with_tunnels},
        NO_ROOM,
    };
    let full = filled_past_the_limit_with_tunnels(central_with_host(A));
    assert_eq!(
        set(&full, None, B, None, Some(rule(B)), 10)
            .unwrap_err()
            .to_string(),
        NO_ROOM
    );
    let saved = view(&full).remove(0).rule;
    assert!(
        set(&full, None, &saved.id, Some(&saved), None, 11).is_ok(),
        "removal never fails the check"
    );
    let mut chain = full;
    chain.local.central = None;
    assert!(
        set(&chain, None, B, None, Some(rule(B)), 12).is_ok(),
        "without central sync there is no Catalog to fit"
    );
}
#[test]
fn local_rules_publish_once_when_joining_sync_and_wrong_keys_do_not_promote() {
    let original = rule(A);
    let local = set(&state(), None, A, None, Some(original.clone()), 10).unwrap();
    let (account, keys) = account();
    let mut next = local;
    next.account = account.account;
    publish_local(&mut next, Some(&ChainKeys::generate().unwrap()), 11).unwrap();
    assert!(!view(&next)[0].synced);
    publish_local(&mut next, Some(&keys), 12).unwrap();
    assert!(view(&next)[0].synced);
    let published = next.account.clone();
    publish_local(&mut next, Some(&keys), 13).unwrap();
    assert_eq!(published, next.account);
    let deleted = set(&next, Some(&keys), A, Some(&original), None, 14).unwrap();
    let mut deleted = deleted;
    publish_local(&mut deleted, Some(&keys), 15).unwrap();
    assert!(view(&deleted).is_empty());
}

#[test]
fn leave_sync_remaps_preserved_hosts_and_never_resurrects_deleted_local_rules() {
    let first = rule(A);
    let second = rule(B);
    let local = set(&state(), None, A, None, Some(first.clone()), 10).unwrap();
    let (account, keys) = account();
    let mut before = local;
    before.account = account.account;
    publish_local(&mut before, Some(&keys), 11).unwrap();
    before = set(&before, Some(&keys), B, None, Some(second.clone()), 12).unwrap();
    before = set(&before, Some(&keys), A, Some(&first), None, 13).unwrap();
    let local_id = "0000000000000099";
    let mut next = before.clone();
    next.account = None;
    next.local.hosts.insert(record_key(RecordKind::Host, local_id), LocalRecord { record: Record { kind: RecordKind::Host, id: local_id.into(), version: 1, updated_at_ms: 1, device_id: next.device_id.clone(), deleted: false, payload: json!({"schema":2,"alias":"preserved","hostname":"fixture.invalid","auth":"password"}) }, seq: 0, dirty: false });
    preserve_on_leave(
        &before,
        &mut next,
        &[(A.into(), local_id.into())].into(),
        14,
    )
    .unwrap();
    let rows = view(&next);
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].rule.id, B);
    assert_eq!(rows[0].rule.host_id, local_id);
    assert!(!rows[0].synced);
    validate_state(&next).unwrap();
    let mut not_kept = before.clone();
    not_kept.account = None;
    preserve_on_leave(&before, &mut not_kept, &Default::default(), 14).unwrap();
    assert!(view(&not_kept).is_empty());
}

#[test]
fn rules_survive_real_sync_rounds_code_rotation_and_account_detach() {
    use crate::sync::{
        fake_relay::FakeRelay,
        record_account, record_commands, record_leave, record_rotation, record_round,
        record_runtime::{self, StartupProbe},
        testkit::{TestClock, TestDevice},
    };
    let relay = FakeRelay::new();
    let clock = TestClock::new();
    let a = TestDevice::new("tunnels-a", &relay, &clock);
    let b = TestDevice::new("tunnels-b", &relay, &clock);
    for (index, device) in [&a, &b].into_iter().enumerate() {
        let StartupProbe::Records { mut state, .. } =
            record_runtime::probe_startup(&device.env().state_path, "fixture")
        else {
            panic!()
        };
        state.relay_url = crate::sync::testkit::RELAY_URL.into();
        if index == 0 {
            // only the originating device has this local SSH host
            state.local.hosts.insert(record_key(RecordKind::Host, A), LocalRecord { record: Record { kind: RecordKind::Host, id: A.into(), version: 1, updated_at_ms: 1, device_id: state.device_id.clone(), deleted: false, payload: json!({"schema":2,"alias":"database","hostname":"fixture.invalid","auth":"password"}) }, seq: 0, dirty: false });
        }
        record_runtime::activate_probe(
            &mut device.runtime.core.lock().unwrap(),
            StartupProbe::Records {
                state,
                fresh: false,
            },
        )
        .unwrap();
    }
    let original = rule(A);
    record_commands::edit_records(&a.env(), |state, now| {
        set(state, None, A, None, Some(original.clone()), now)
            .map_err(|e| crate::error::AppError::Other(e.to_string()))
    })
    .unwrap();
    let created = record_account::create_account(&a.env(), "a").unwrap();
    assert!(created.complete);
    record_round::sync_once(&a.env()).unwrap();
    record_account::join_account(&b.env(), &created.code, "b").unwrap();
    let (on_b, _) = record_runtime::snapshot(&b.env()).unwrap();
    assert_eq!(view(&on_b)[0].rule, original);
    assert!(view(&on_b)[0].synced);
    assert!(on_b.local.hosts.is_empty());
    let keys = b.runtime.core.lock().unwrap().account_keys.clone().unwrap();
    let mut changed = original.clone();
    changed.forward.port = 0;
    record_commands::edit_records(&b.env(), |state, now| {
        set(
            state,
            Some(&keys),
            A,
            Some(&original),
            Some(changed.clone()),
            now,
        )
        .map_err(|e| crate::error::AppError::Other(e.to_string()))
    })
    .unwrap();
    record_round::sync_once(&b.env()).unwrap();
    record_round::sync_once(&a.env()).unwrap();
    let (on_a, _) = record_runtime::snapshot(&a.env()).unwrap();
    assert_eq!(view(&on_a)[0].rule, changed);
    let rotated = record_rotation::start_rotation(&a.env(), "a").unwrap();
    assert!(rotated.complete);
    let (on_a, _) = record_runtime::snapshot(&a.env()).unwrap();
    assert_eq!(view(&on_a)[0].rule, changed);
    let detached = record_leave::leave_account(&a.env()).unwrap();
    assert!(detached.complete);
    let (local, _) = record_runtime::snapshot(&a.env()).unwrap();
    assert_eq!(view(&local)[0].rule, changed);
    assert!(!view(&local)[0].synced);
    let DecodedState::V3(restored) =
        decode_state(&std::fs::read_to_string(&a.env().state_path).unwrap()).unwrap()
    else {
        panic!()
    };
    assert_eq!(view(&restored)[0].rule, changed);
}
