use super::*;
use crate::sync::{
    crypto::ChainKeys, record::ACCOUNT_META_ID, record_merge, records_v3::*, relay::PullResponse,
    state_v2::AccountState,
};
use serde_json::json;

const A: &str = "0000000000000001";
const B: &str = "0000000000000002";
fn state() -> SyncStateV3 {
    let mut s: SyncStateV3 = serde_json::from_value(json!({"version":4,
        "device_id":"dddddddddddddddddddddddddddddddd","device_name":"fixture",
        "relay_url":"http://127.0.0.1","last_sync_ms":null,"last_error":null}))
    .unwrap();
    for (id, name) in [(A, "Alpha"), (B, "Beta")] {
        let mut r = repo::ordered_record(
            &s,
            id,
            json!({"schema":1,"name":name,"parent_id":null,"defaults":{}}),
            false,
            1,
            &[],
        )
        .unwrap();
        r.kind = RecordKind::Group;
        s.local.groups.insert(
            record_key(RecordKind::Group, id),
            repo::cached(r, 0, &crate::sync::records_v3::HostScope::Local),
        );
    }
    s
}
fn account() -> (SyncStateV3, ChainKeys) {
    let mut s = state();
    let keys = ChainKeys::generate().unwrap();
    let mut a = AccountState::new(&keys.chain_id);
    a.baseline_established = true;
    a.cursor_seq = 1;
    a.remote_schema_version = Some(4);
    let mut r = repo::ordered_record(
        &s,
        ACCOUNT_META_ID,
        json!({"schema_version":4,"created_by_app_version":"fixture"}),
        false,
        1,
        &[],
    )
    .unwrap();
    r.kind = RecordKind::Meta;
    a.records.insert(
        record_key(RecordKind::Meta, ACCOUNT_META_ID),
        LocalRecord {
            record: r,
            seq: 1,
            dirty: false,
        },
    );
    s.account = Some(a);
    (s, keys)
}
#[test]
fn local_order_persists_without_modifying_groups_or_inheritance() {
    let s = state();
    let n = set(&s, &[], None, vec![B.into(), A.into()], 10).unwrap();
    assert_eq!(n.local.groups, s.local.groups);
    assert_eq!(n.local.hosts, s.local.hosts);
    assert_eq!(n.version, NAVIGATION_STATE_VERSION);
    let text = serde_json::to_string(&n).unwrap();
    let DecodedState::V3(decoded) = decode_state(&text).unwrap() else {
        panic!()
    };
    assert_eq!(view(&decoded).ids, vec![B, A]);
    let group = crate::sync::record_groups::list_groups(&n)
        .unwrap()
        .remove(0);
    let mut renamed = group.group.payload.clone();
    renamed.name = "Renamed".into();
    let n =
        crate::sync::record_groups::update_group(&n, &group.group.id, &group.revision, renamed, 11)
            .unwrap();
    assert_eq!(view(&n).ids, vec![B, A]);
}
#[test]
fn stale_edits_duplicate_and_unknown_ids_fail_without_losing_order() {
    let s = state();
    let n = set(&s, &[], None, vec![B.into(), A.into()], 10).unwrap();
    assert!(set(&n, &[], None, vec![], 11).is_err());
    assert!(set(&s, &[], None, vec![A.into(), A.into()], 10).is_err());
    assert!(set(&s, &[], None, vec!["0000000000000099".into()], 10).is_err());
    assert!(set(&s, &[], None, vec!["bad".into()], 10).is_err());
    assert!(decode(&Record {
        kind: RecordKind::Meta,
        id: RECORD_ID.into(),
        version: 1,
        updated_at_ms: 1,
        device_id: s.device_id,
        deleted: false,
        payload: json!({"schema":2,"ids":[]})
    })
    .is_none());
}
#[test]
fn account_order_is_independent_encrypted_metadata_and_round_trips_between_devices() {
    let (s, keys) = account();
    let n = set(&s, &[], None, vec![B.into(), A.into()], 10).unwrap();
    assert_eq!(n.local, s.local);
    let next = n.account.as_ref().unwrap();
    let outgoing = record_merge::account_outgoing(next, &keys).unwrap();
    assert_eq!(outgoing.len(), 1);
    let row = &next.records[&record_key(RecordKind::Meta, RECORD_ID)];
    let item = record_merge::encode_record(&keys, &row.record, 0).unwrap();
    assert!(!item.ciphertext.contains(A));
    let pulled = PullResponse {
        latest_seq: 2,
        records: vec![crate::sync::record::Envelope {
            id_hash: item.id_hash,
            kind: item.kind,
            seq: 2,
            nonce: item.nonce,
            ciphertext: item.ciphertext,
            deleted: false,
        }],
    };
    let merged = record_merge::merge_account(s.account.as_ref().unwrap(), &keys, &pulled, 1);
    assert_eq!(merged.gate, record_merge::AccountGate::Compatible);
    let mut second = s.clone();
    second.account = Some(merged.section);
    assert_eq!(view(&second).ids, vec![B, A]);
    assert_eq!(second.local.groups, s.local.groups);
    let old = view(&second);
    let reset = set(&second, &old.ids, old.revision.as_ref(), vec![], 1).unwrap();
    assert_eq!(view(&reset).ids, Vec::<String>::new());
    assert!(view(&reset).revision.unwrap().updated_at_ms > old.revision.unwrap().updated_at_ms);
}
#[test]
fn account_gate_and_newer_opaque_order_cannot_be_overwritten() {
    let (mut s, keys) = account();
    s.shared_writes_blocked = true;
    assert!(set(&s, &[], None, vec![A.into()], 10).is_err());
    s.shared_writes_blocked = false;
    let future = Record {
        kind: RecordKind::Meta,
        id: RECORD_ID.into(),
        version: 1,
        updated_at_ms: 5,
        device_id: s.device_id.clone(),
        deleted: false,
        payload: json!({"schema":99,"ids":[A]}),
    };
    let item = record_merge::encode_record(&keys, &future, 0).unwrap();
    let pulled = PullResponse {
        latest_seq: 2,
        records: vec![crate::sync::record::Envelope {
            id_hash: item.id_hash,
            kind: item.kind,
            seq: 2,
            nonce: item.nonce,
            ciphertext: item.ciphertext,
            deleted: false,
        }],
    };
    let merged = record_merge::merge_account(s.account.as_ref().unwrap(), &keys, &pulled, 1);
    assert_eq!(merged.gate, record_merge::AccountGate::Compatible);
    s.account = Some(merged.section);
    validate_state(&s).unwrap();
    assert!(view(&s).blocked);
    assert!(set(&s, &[], None, vec![B.into()], 10).is_err());
}

#[test]
fn concurrent_offline_orders_converge_without_losing_group_edits() {
    let (first, keys) = account();
    let mut second = first.clone();
    second.device_id = "e".repeat(32);
    let a = set(&first, &[], None, vec![B.into(), A.into()], 20).unwrap();
    let b = set(&second, &[], None, vec![A.into(), B.into()], 30).unwrap();
    let pull = |state: &SyncStateV3| {
        let row =
            &state.account.as_ref().unwrap().records[&record_key(RecordKind::Meta, RECORD_ID)];
        let item = record_merge::encode_record(&keys, &row.record, 0).unwrap();
        PullResponse {
            latest_seq: 2,
            records: vec![crate::sync::record::Envelope {
                id_hash: item.id_hash,
                kind: item.kind,
                seq: 2,
                nonce: item.nonce,
                ciphertext: item.ciphertext,
                deleted: false,
            }],
        }
    };
    let merged_a = record_merge::merge_account(a.account.as_ref().unwrap(), &keys, &pull(&b), 1);
    let merged_b = record_merge::merge_account(b.account.as_ref().unwrap(), &keys, &pull(&a), 1);
    let mut a = a;
    a.account = Some(merged_a.section);
    let mut b = b;
    b.account = Some(merged_b.section);
    assert_eq!(view(&a).ids, vec![A, B]);
    assert_eq!(view(&a).ids, view(&b).ids);
    assert_eq!(a.local.groups, first.local.groups);
    assert_eq!(b.local.groups, first.local.groups);
}

#[test]
fn unreadable_navigation_cannot_be_overwritten_but_legacy_meta_does_not_block_ordering() {
    use crate::sync::state_v2::{sealed_key, SealedRecord};
    let (mut s, keys) = account();
    let hash = crate::sync::crypto::id_hash(&keys, "meta", RECORD_ID);
    let row = SealedRecord {
        envelope: crate::sync::record::Envelope {
            kind: "meta".into(),
            id_hash: hash.clone(),
            seq: 2,
            nonce: "unreadable".into(),
            ciphertext: "unreadable".into(),
            deleted: false,
        },
        dirty: false,
        public_identity: None,
    };
    s.account
        .as_mut()
        .unwrap()
        .sealed
        .insert(sealed_key("meta", &hash), row);
    assert!(blocked_by_opaque(&s, Some(&keys)));
    assert!(blocked_by_opaque(&s, None));
    let mut row = s
        .account
        .as_mut()
        .unwrap()
        .sealed
        .remove(&sealed_key("meta", &hash))
        .unwrap();
    row.envelope.id_hash = crate::sync::crypto::id_hash(&keys, "meta", "legacy-metadata");
    s.account
        .as_mut()
        .unwrap()
        .sealed
        .insert(sealed_key("meta", &row.envelope.id_hash), row);
    assert!(!blocked_by_opaque(&s, Some(&keys)));
}

#[test]
fn upgrading_an_old_client_admits_retained_order_without_another_remote_change() {
    use crate::sync::state_v2::{sealed_key, SealedRecord};
    let (mut old, keys) = account();
    let written = set(&old, &[], None, vec![B.into(), A.into()], 10).unwrap();
    let record =
        &written.account.as_ref().unwrap().records[&record_key(RecordKind::Meta, RECORD_ID)].record;
    let item = record_merge::encode_record(&keys, record, 0).unwrap();
    let envelope = crate::sync::record::Envelope {
        id_hash: item.id_hash,
        kind: item.kind,
        seq: 2,
        nonce: item.nonce,
        ciphertext: item.ciphertext,
        deleted: false,
    };
    let account = old.account.as_mut().unwrap();
    account.cursor_seq = 2;
    account.sealed.insert(
        sealed_key("meta", &envelope.id_hash),
        SealedRecord {
            envelope,
            dirty: false,
            public_identity: None,
        },
    );
    let merged = record_merge::merge_account(
        account,
        &keys,
        &PullResponse {
            records: vec![],
            latest_seq: 2,
        },
        2,
    );
    assert_eq!(merged.gate, record_merge::AccountGate::Compatible);
    old.account = Some(merged.section);
    assert_eq!(view(&old).ids, vec![B, A]);
    assert!(old.account.as_ref().unwrap().sealed.is_empty());
    assert!(
        record_merge::account_outgoing(old.account.as_ref().unwrap(), &keys)
            .unwrap()
            .is_empty()
    );
}

#[test]
fn retained_order_keeps_newer_dirty_edits_and_authenticates_future_format_headers() {
    use crate::sync::state_v2::{sealed_key, SealedRecord};
    for future in [false, true] {
        let (s, keys) = account();
        let mut retained = set(&s, &[], None, vec![B.into(), A.into()], 10).unwrap();
        let key = record_key(RecordKind::Meta, RECORD_ID);
        let mut record = retained
            .account
            .as_mut()
            .unwrap()
            .records
            .remove(&key)
            .unwrap()
            .record;
        if future {
            record.payload["schema"] = json!(99);
            record.updated_at_ms = 30;
        }
        let item = record_merge::encode_record(&keys, &record, 0).unwrap();
        let mut current = set(&s, &[], None, vec![A.into(), B.into()], 20).unwrap();
        let account = current.account.as_mut().unwrap();
        account.cursor_seq = 2;
        account.sealed.insert(
            sealed_key("meta", &item.id_hash),
            SealedRecord {
                envelope: crate::sync::record::Envelope {
                    id_hash: item.id_hash,
                    kind: item.kind,
                    seq: 2,
                    nonce: item.nonce,
                    ciphertext: item.ciphertext,
                    deleted: false,
                },
                dirty: false,
                public_identity: None,
            },
        );
        let merged = record_merge::merge_account(
            account,
            &keys,
            &PullResponse {
                records: vec![],
                latest_seq: 2,
            },
            2,
        );
        assert_eq!(merged.gate, record_merge::AccountGate::Compatible);
        current.account = Some(merged.section);
        validate_state(&current).unwrap();
        let account = current.account.as_ref().unwrap();
        assert!(account.records[&key].dirty);
        assert_eq!(view(&current).blocked, future);
        if future {
            assert!(account
                .sealed
                .values()
                .next()
                .unwrap()
                .public_identity
                .is_some());
        } else {
            assert_eq!(view(&current).ids, vec![A, B]);
            assert!(account.sealed.is_empty());
            assert_eq!(
                record_merge::account_outgoing(account, &keys)
                    .unwrap()
                    .len(),
                1
            );
        }
    }
}
