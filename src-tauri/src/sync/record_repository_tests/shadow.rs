use super::*;
use crate::sync::record::{Envelope, ACCOUNT_META_ID};
use crate::sync::relay::PullResponse;
use crate::sync::{crypto::ChainKeys, record_merge, records_v3, state_v2::sealed_key};
use serde_json::json;

const KEY: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
fn fixture() -> (SyncStateV3, ChainKeys, ChainKeys) {
    let account_keys = ChainKeys::generate().unwrap();
    let space_keys = ChainKeys::generate().unwrap();
    let mut s = state();
    let mut account = AccountState::new(&account_keys.chain_id);
    account.cursor_seq = 9;
    account.baseline_established = true;
    account.records.insert(
        record_key(RecordKind::Meta, ACCOUNT_META_ID),
        LocalRecord {
            record: Record {
                kind: RecordKind::Meta,
                id: ACCOUNT_META_ID.into(),
                version: 1,
                updated_at_ms: 1,
                device_id: s.device_id.clone(),
                deleted: false,
                payload: json!({"schema_version":3,"created_by_app_version":"fixture"}),
            },
            seq: 1,
            dirty: false,
        },
    );
    s.account = Some(account);
    let mut space = SpaceStateV3 {
        selected: true,
        cursor_seq: 7,
        baseline_established: true,
        ..Default::default()
    };
    space.records.insert(
        record_key(RecordKind::Host, ID),
        cached(ID, payload("web"), 7),
    );
    s.spaces.insert(space_keys.chain_id.clone(), space);
    (s, account_keys, space_keys)
}
fn envelope(keys: &ChainKeys, r: &Record, seq: u64) -> Envelope {
    let item = record_merge::encode_record(keys, r, 0).unwrap();
    Envelope {
        kind: item.kind,
        id_hash: item.id_hash,
        nonce: item.nonce,
        ciphertext: item.ciphertext,
        seq,
        deleted: item.deleted,
    }
}
fn apply_host(s: &mut SyncStateV3, keys: &ChainKeys, row: Envelope) {
    let old = &s.spaces[&keys.chain_id];
    let merged = record_merge::merge_space(
        old,
        keys,
        &PullResponse {
            latest_seq: 10,
            records: vec![row],
        },
        0,
        &record_merge::AccountGate::Compatible,
    );
    assert_eq!(merged.gate, record_merge::AccountGate::Compatible);
    s.spaces.insert(keys.chain_id.clone(), merged.section);
}
fn apply_slot(s: &mut SyncStateV3, keys: &ChainKeys, row: Envelope) {
    let merged = record_merge::merge_account(
        s.account.as_ref().unwrap(),
        keys,
        &PullResponse {
            latest_seq: 10,
            records: vec![row],
        },
        0,
    );
    assert_eq!(merged.gate, record_merge::AccountGate::Compatible);
    s.account = Some(merged.section);
}
fn future_host() -> Record {
    Record {
        kind: RecordKind::Host,
        id: ID.into(),
        version: 5,
        updated_at_ms: 200,
        device_id: "e".repeat(32),
        deleted: false,
        payload: json!({"schema":3,"hostname":"future.test"}),
    }
}
fn local_key(s: &mut SyncStateV3) {
    s.local.keys.insert(
        KEY.into(),
        LocalKeyMetadata {
            vault_id: "a".repeat(32),
            public: slot(PUBLIC),
        },
    );
}
fn future_slot() -> Record {
    Record {
        kind: RecordKind::KeySlot,
        id: KEY.into(),
        version: 2,
        updated_at_ms: 200,
        device_id: "e".repeat(32),
        deleted: false,
        payload: json!({"schema":3,"future":"unrecognized public identity"}),
    }
}
fn restart(s: &SyncStateV3) -> SyncStateV3 {
    let records_v3::DecodedState::V3(state) =
        records_v3::decode_state(&serde_json::to_string(s).unwrap()).unwrap()
    else {
        panic!("v3")
    };
    *state
}
#[test]
fn newer_authenticated_unsupported_host_keeps_cache_but_blocks_every_readiness_path_after_restart()
{
    let (mut s, _, keys) = fixture();
    let before = s.spaces[&keys.chain_id].records.clone();
    apply_host(&mut s, &keys, envelope(&keys, &future_host(), 10));
    assert_eq!(s.spaces[&keys.chain_id].records, before);
    assert_eq!(
        get_host(&s, ID).unwrap().readiness,
        HostReadiness::NeedsReview
    );
    assert_eq!(
        resolve_host_chain(&s, ID).unwrap()[0].readiness,
        HostReadiness::NeedsReview
    );
    assert_eq!(
        get_host(&restart(&s), ID).unwrap().readiness,
        HostReadiness::NeedsReview
    );
}
#[test]
fn unsupported_account_key_authority_cannot_fall_back_to_available_local_material() {
    for cached_public in [true, false] {
        let (mut s, keys, _) = fixture();
        local_key(&mut s);
        if cached_public {
            account_key(&mut s, KEY, slot(PUBLIC), false);
        }
        let space_id = s.spaces.keys().next().unwrap().clone();
        let host = s
            .spaces
            .get_mut(&space_id)
            .unwrap()
            .records
            .get_mut(&record_key(RecordKind::Host, ID))
            .unwrap();
        host.record.payload["auth"] = json!("key");
        host.record.payload["key_id"] = json!(KEY);
        let local = s.local.clone();
        apply_slot(&mut s, &keys, envelope(&keys, &future_slot(), 10));
        assert_eq!(s.local, local);
        let key = resolve_key(&s, KEY).unwrap();
        assert_eq!(key.status, KeyStatus::Conflict);
        assert!(key.vault_id.is_none());
        assert_eq!(
            get_host(&s, ID).unwrap().readiness,
            HostReadiness::KeyConflict(KEY.into())
        );
        assert_eq!(
            resolve_key(&restart(&s), KEY).unwrap().status,
            KeyStatus::Conflict
        );
    }
}
#[test]
fn opaque_shadow_uses_timestamp_tombstone_and_smaller_device_lww_not_version_or_sequence() {
    for (time, device, deleted, want) in [
        (99, "a", false, HostReadiness::Ready),
        (100, "e", false, HostReadiness::Ready),
        (100, "a", false, HostReadiness::NeedsReview),
        (100, "e", true, HostReadiness::NeedsReview),
    ] {
        let (mut s, _, keys) = fixture();
        let mut r = future_host();
        r.version = u64::MAX;
        r.updated_at_ms = time;
        r.device_id = device.repeat(32);
        r.deleted = deleted;
        apply_host(&mut s, &keys, envelope(&keys, &r, 10));
        assert_eq!(get_host(&s, ID).unwrap().readiness, want);
    }
}
#[test]
fn newer_supported_host_clears_opaque_authority_and_restores_readiness() {
    let (mut s, _, keys) = fixture();
    apply_host(&mut s, &keys, envelope(&keys, &future_host(), 10));
    assert_eq!(
        get_host(&s, ID).unwrap().readiness,
        HostReadiness::NeedsReview
    );
    let mut supported = cached(ID, payload("updated"), 10).record;
    supported.updated_at_ms = 300;
    let old = &s.spaces[&keys.chain_id];
    let merged = record_merge::merge_space(
        old,
        &keys,
        &PullResponse {
            latest_seq: 11,
            records: vec![envelope(&keys, &supported, 11)],
        },
        0,
        &record_merge::AccountGate::Compatible,
    );
    assert_eq!(merged.gate, record_merge::AccountGate::Compatible);
    s.spaces.insert(keys.chain_id.clone(), merged.section);
    assert!(s.spaces[&keys.chain_id].sealed.is_empty());
    let view = get_host(&restart(&s), ID).unwrap();
    assert_eq!(view.readiness, HostReadiness::Ready);
    assert_eq!(view.host.payload.alias, "updated");
}
#[test]
fn authenticated_extended_outer_host_header_still_blocks_stale_typed_cache() {
    let (mut s, _, keys) = fixture();
    let mut value = serde_json::to_value(future_host()).unwrap();
    value["future_header"] = json!(true);
    let sealed =
        crate::sync::crypto::seal(&keys, "host", ID, &serde_json::to_vec(&value).unwrap()).unwrap();
    apply_host(
        &mut s,
        &keys,
        Envelope {
            kind: "host".into(),
            id_hash: sealed.id_hash,
            nonce: sealed.nonce,
            ciphertext: sealed.ciphertext,
            seq: 10,
            deleted: false,
        },
    );
    assert_eq!(
        get_host(&s, ID).unwrap().readiness,
        HostReadiness::NeedsReview
    );
}
#[test]
fn invalid_authenticated_identity_never_manufactures_a_public_shadow() {
    let (mut s, _, keys) = fixture();
    let mut row = future_host();
    row.id = OTHER.into();
    let sealed =
        crate::sync::crypto::seal(&keys, "host", ID, &serde_json::to_vec(&row).unwrap()).unwrap();
    apply_host(
        &mut s,
        &keys,
        Envelope {
            kind: "host".into(),
            id_hash: sealed.id_hash,
            nonce: sealed.nonce,
            ciphertext: sealed.ciphertext,
            seq: 10,
            deleted: false,
        },
    );
    assert_eq!(get_host(&s, ID).unwrap().readiness, HostReadiness::Ready);
    let value = serde_json::to_value(&s.spaces[&keys.chain_id].sealed).unwrap();
    assert!(value
        .as_object()
        .unwrap()
        .values()
        .all(|row| row.get("public_identity").is_none()));
}
#[test]
fn recognized_legacy_alias_and_own_sources_do_not_block_known_records() {
    let (mut s, account, space) = fixture();
    local_key(&mut s);
    account_key(&mut s, KEY, slot(PUBLIC), false);
    let mut alias = future_host();
    alias.payload = json!({"schema":1,"text":"Host old-alias\n HostName legacy.test\n"});
    apply_host(&mut s, &space, envelope(&space, &alias, 10));
    let mut own = future_slot();
    own.payload = json!({"schema":1,"name":"old-own","mode":"own","origin_device_id":"d".repeat(32),"created_at_ms":1,"public_key":null,"fingerprint":null,"key_type":null,"has_passphrase":null});
    apply_slot(&mut s, &account, envelope(&account, &own, 10));
    let s = restart(&s);
    assert_eq!(get_host(&s, ID).unwrap().readiness, HostReadiness::Ready);
    assert_eq!(resolve_key(&s, KEY).unwrap().status, KeyStatus::Available);
    for sealed in [
        &s.account.as_ref().unwrap().sealed,
        &s.spaces[&space.chain_id].sealed,
    ] {
        let value = serde_json::to_value(sealed).unwrap();
        assert!(value
            .as_object()
            .unwrap()
            .values()
            .all(|row| row.get("public_identity").is_none()));
    }
}
#[test]
fn persisted_identity_hints_reject_secret_kinds_wrong_shapes_and_deleted_mismatch() {
    let (mut s, keys, space) = fixture();
    apply_host(&mut s, &space, envelope(&space, &future_host(), 10));
    let value = serde_json::to_value(&s).unwrap();
    let wire = sealed_key("host", &crate::sync::crypto::id_hash(&space, "host", ID));
    for (field, replacement) in [
        ("id", json!("not-a-public-host-id")),
        ("device_id", json!("invalid actor")),
        ("deleted", json!(true)),
        ("version", json!(0)),
    ] {
        let mut bad = value.clone();
        bad["spaces"][&space.chain_id]["sealed"][&wire]["public_identity"] = json!({"id":ID,"version":1,"updated_at_ms":200,"device_id":"e".repeat(32),"deleted":false});
        bad["spaces"][&space.chain_id]["sealed"][&wire]["public_identity"][field] = replacement;
        assert!(records_v3::decode_state(&bad.to_string()).is_err());
    }
    let secret = Record {
        kind: RecordKind::Key,
        id: KEY.into(),
        version: 1,
        updated_at_ms: 1,
        device_id: "d".repeat(32),
        deleted: false,
        payload: json!({"schema":9,"private_key":"synthetic secret sentinel"}),
    };
    apply_slot(&mut s, &keys, envelope(&keys, &secret, 10));
    let mut bad = serde_json::to_value(&s).unwrap();
    let wire = sealed_key("key", &crate::sync::crypto::id_hash(&keys, "key", KEY));
    bad["account"]["sealed"][&wire]["public_identity"] =
        json!({"id":KEY,"version":1,"updated_at_ms":1,"device_id":"d".repeat(32),"deleted":false});
    assert!(records_v3::decode_state(&bad.to_string()).is_err());
    assert!(!serde_json::to_string(&s)
        .unwrap()
        .contains("synthetic secret sentinel"));
}

#[test]
fn newer_supported_keyslot_restores_matching_local_material_after_shadow() {
    let (mut s, keys, _) = fixture();
    local_key(&mut s);
    account_key(&mut s, KEY, slot(PUBLIC), false);
    apply_slot(&mut s, &keys, envelope(&keys, &future_slot(), 10));
    assert_eq!(resolve_key(&s, KEY).unwrap().status, KeyStatus::Conflict);
    let mut known = s.account.as_ref().unwrap().records[&record_key(RecordKind::KeySlot, KEY)]
        .record
        .clone();
    known.version = 3;
    known.updated_at_ms = 300;
    let merge = record_merge::merge_account(
        s.account.as_ref().unwrap(),
        &keys,
        &PullResponse {
            latest_seq: 11,
            records: vec![envelope(&keys, &known, 11)],
        },
        0,
    );
    assert_eq!(merge.gate, record_merge::AccountGate::Compatible);
    s.account = Some(merge.section);
    assert!(s.account.as_ref().unwrap().sealed.is_empty());
    let view = resolve_key(&restart(&s), KEY).unwrap();
    assert_eq!(view.status, KeyStatus::Available);
    assert_eq!(
        view.vault_id.as_deref(),
        Some("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
    );
}
#[test]
fn unknown_kinds_and_secret_identity_strings_never_become_persisted_hints() {
    let (mut s, keys, _) = fixture();
    let private_id = "synthetic secret identity sentinel";
    let raw = json!({"kind":"future-widget","id":private_id,"version":1,"updated_at_ms":200,"device_id":"d".repeat(32),"deleted":false,"payload":{"private":"synthetic private sentinel"}});
    let sealed = crate::sync::crypto::seal(
        &keys,
        "future-widget",
        private_id,
        &serde_json::to_vec(&raw).unwrap(),
    )
    .unwrap();
    apply_slot(
        &mut s,
        &keys,
        Envelope {
            kind: "future-widget".into(),
            id_hash: sealed.id_hash.clone(),
            nonce: sealed.nonce,
            ciphertext: sealed.ciphertext,
            seq: 10,
            deleted: false,
        },
    );
    let serialized = serde_json::to_string(&s).unwrap();
    assert!(!serialized.contains(private_id));
    assert!(!serialized.contains("synthetic private sentinel"));
    let mut value = serde_json::to_value(&s).unwrap();
    let wire = sealed_key("future-widget", &sealed.id_hash);
    assert!(value["account"]["sealed"][&wire]
        .get("public_identity")
        .is_none());
    value["account"]["sealed"][&wire]["public_identity"] =
        json!({"id":KEY,"version":1,"updated_at_ms":1,"device_id":"d".repeat(32),"deleted":false});
    assert!(records_v3::decode_state(&value.to_string()).is_err());
}
