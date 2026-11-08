use super::*;
use crate::{
    ssh::forward::ForwardKind,
    sync::{
        crypto::ChainKeys,
        record::ACCOUNT_META_ID,
        records_v3::*,
        state_v2::AccountState,
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
/// A tunnel's save is refused when the Catalog would not fit after it, though it fits before: the room check measures the state the
/// save makes, not the one it starts from (final review, deferred Task 5 test).
#[test]
fn a_tunnel_that_would_push_the_catalog_past_one_record_is_refused_though_it_fits_before() {
    use crate::sync::transports::{
        tests::{central_with_host, filled_short_of},
        NO_ROOM,
    };
    let brink = filled_short_of(central_with_host(A), |catalog| catalog.tunnels.push(rule(B)));
    assert_eq!(
        set(&brink, None, B, None, Some(rule(B)), 10)
            .unwrap_err()
            .to_string(),
        NO_ROOM
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
