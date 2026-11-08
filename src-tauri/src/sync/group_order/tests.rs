use super::*;
use crate::sync::{
    crypto::ChainKeys, record::ACCOUNT_META_ID, records_v3::*, state_v2::AccountState,
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
