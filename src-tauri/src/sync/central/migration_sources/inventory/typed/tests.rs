use super::*;
fn frame<'a>(
    kind: &'a str,
    id: &'a str,
    payload: &'a serde_json::value::RawValue,
    deleted: bool,
) -> View<'a> {
    View {
        kind,
        id,
        version: 1,
        updated_at_ms: 1,
        device_id: "dddddddddddddddddddddddddddddddd",
        deleted,
        payload,
    }
}
fn raw(value: &str) -> Box<serde_json::value::RawValue> {
    serde_json::value::RawValue::from_string(value.into()).unwrap()
}
#[test]
fn every_modern_public_payload_is_typed_and_nonempty_deletion_bodies_are_preserved() {
    let account = Scope::Account("a".repeat(64));
    let local = Scope::Local;
    let bodies = [
        (
            "host",
            "1111111111111111",
            &local,
            r#"{"schema":2,"alias":"synthetic","hostname":"fixture.invalid","auth":"password"}"#,
        ),
        (
            "group",
            "2222222222222222",
            &local,
            r#"{"schema":1,"name":"group"}"#,
        ),
        (
            "meta",
            crate::sync::record::ACCOUNT_META_ID,
            &account,
            r#"{"schema_version":4,"created_by_app_version":"test"}"#,
        ),
        (
            "meta",
            crate::sync::group_order::RECORD_ID,
            &account,
            r#"{"schema":1,"ids":["2222222222222222"]}"#,
        ),
    ];
    for (kind, id, scope, body) in bodies {
        let body = raw(body);
        assert!(admit(scope, &frame(kind, id, &body, false)).is_ok());
        assert!(admit(scope, &frame(kind, id, &body, true)).is_ok());
    }
    let empty = raw("null");
    assert!(matches!(
        admit(&local, &frame("host", "1111111111111111", &empty, true)).unwrap(),
        KnownData::Deleted
    ));
}
#[test]
fn legacy_host_text_stays_inert_and_old_slot_mode_remains_a_source_fact() {
    let space = Scope::Space("a".repeat(64));
    let body = raw(
        r#"{"schema":1,"text":"Host web\n  Include /synthetic/not-opened\n  ProxyCommand never-executed\n"}"#,
    );
    let KnownData::LegacyHost(host) = admit(&space, &frame("host", "web", &body, false)).unwrap()
    else {
        panic!()
    };
    assert!(host.text.contains("never-executed"));
    let body = raw(
        r#"{"schema":1,"name":"own","mode":"own","origin_device_id":"legacy","created_at_ms":1,"public_key":null,"fingerprint":null,"key_type":null,"has_passphrase":null}"#,
    );
    assert!(matches!(
        admit(
            &Scope::Account("a".repeat(64)),
            &frame("keyslot", "11111111111111111111111111111111", &body, false)
        )
        .unwrap(),
        KnownData::LegacySlot(_)
    ));
}
#[test]
fn unknown_future_duplicate_and_secret_public_fields_never_produce_a_known_record() {
    let scope = Scope::Local;
    for value in [
        r#"{"schema":99,"alias":"synthetic","hostname":"fixture.invalid","auth":"password"}"#,
        r#"{"schema":2,"schema":2,"alias":"synthetic","hostname":"fixture.invalid","auth":"password"}"#,
        r#"{"schema":2,"alias":"synthetic","hostname":"fixture.invalid","auth":"password","private_key":"PRIVATE_SENTINEL"}"#,
    ] {
        let value = raw(value);
        for deleted in [false, true] {
            let error = admit(&scope, &frame("host", "1111111111111111", &value, deleted))
                .err()
                .unwrap();
            assert!(!error.to_string().contains("SENTINEL"));
        }
    }
    let value = raw("null");
    assert!(admit(&scope, &frame("future", "unknown", &value, true)).is_err());
    let value = raw(r#"{"schema":1,"password":"PRIVATE_SENTINEL"}"#);
    assert!(admit(
        &Scope::Account("a".repeat(64)),
        &frame("password", "reserved", &value, false)
    )
    .is_err());
}
#[test]
fn old_device_metadata_is_explicit_data_and_does_not_accept_future_fields_or_wrong_scope() {
    let value = raw(
        r#"{"schema":1,"name":"old device","platform":"synthetic","joined_at_ms":1,"last_seen_ms":2,"keys":[],"spaces":[],"slots":[]}"#,
    );
    let account = Scope::Account("a".repeat(64));
    assert!(matches!(
        admit(
            &account,
            &frame("device", "11111111111111111111111111111111", &value, false)
        )
        .unwrap(),
        KnownData::Device(_)
    ));
    assert!(admit(
        &Scope::Local,
        &frame("device", "11111111111111111111111111111111", &value, false)
    )
    .is_err());
    let value = raw(
        r#"{"schema":1,"name":"old device","platform":"synthetic","joined_at_ms":1,"last_seen_ms":2,"keys":[],"future_secret":"PRIVATE_SENTINEL"}"#,
    );
    assert!(admit(
        &account,
        &frame("device", "11111111111111111111111111111111", &value, false)
    )
    .is_err());
}

#[test]
fn collection_slot_rotation_and_legacy_space_key_are_typed_without_becoming_control_proofs() {
    use crate::sync::{crypto::ChainKeys, record::SpaceKeyPayload, slot_rules::test_keys};
    let account = Scope::Account("a".repeat(64));
    let value = raw(&format!(
        r#"{{"schema":1,"name":"collection","slug":"inert-label","created_at_ms":1,"previous_id":"{}"}}"#,
        "b".repeat(64)
    ));
    assert!(matches!(
        admit(&account, &frame("space", &"c".repeat(64), &value, false)).unwrap(),
        KnownData::Collection(_)
    ));
    let key = ChainKeys::generate().unwrap();
    let value = raw(&serde_json::to_string(&SpaceKeyPayload::from_keys(&key)).unwrap());
    assert!(matches!(
        admit(&account, &frame("spacekey", &key.chain_id, &value, false)).unwrap(),
        KnownData::LegacySpaceKey
    ));
    let value = raw(
        r#"{"rotated_at_ms":1,"by_device_id":"dddddddddddddddddddddddddddddddd","by_device_name":"old"}"#,
    );
    assert!(matches!(
        admit(
            &account,
            &frame(
                "meta",
                "rotation:dddddddddddddddddddddddddddddddd",
                &value,
                false
            )
        )
        .unwrap(),
        KnownData::Rotation(_)
    ));
    let original = test_keys::encrypted();
    let parsed = crate::vault::material::parse(&original).unwrap();
    let public = parsed.public_key().to_openssh().unwrap();
    let fingerprint = parsed
        .public_key()
        .fingerprint(ssh_key::HashAlg::Sha256)
        .to_string();
    let value=raw(&serde_json::json!({"schema":2,"name":"shared","public_key":public,"fingerprint":fingerprint,"key_type":"ssh-ed25519","has_passphrase":true,"created_at_ms":1,"origin_device_id":"d".repeat(32)}).to_string());
    assert!(matches!(
        admit(&account, &frame("keyslot", &"1".repeat(32), &value, false)).unwrap(),
        KnownData::Keyslot(_)
    ));
    let public = public
        .split_whitespace()
        .take(2)
        .collect::<Vec<_>>()
        .join(" ");
    let value=raw(&serde_json::json!({"schema":1,"name":"old_shared","mode":"synced","public_key":public,"fingerprint":fingerprint,"key_type":"ssh-ed25519","has_passphrase":true,"created_at_ms":1,"origin_device_id":"d".repeat(32)}).to_string());
    assert!(matches!(
        admit(&account, &frame("keyslot", &"1".repeat(32), &value, false)).unwrap(),
        KnownData::LegacySlot(_)
    ));
}
#[test]
fn an_unknown_late_authenticated_frame_blocks_the_entire_known_input_result() {
    use crate::sync::{
        crypto::{self, ChainKeys},
        record::{LocalRecord, Record, RecordKind},
        state_v2::{AccountState, SealedRecord},
    };
    let parent = ChainKeys::generate().unwrap();
    let id = "unhandled";
    let bytes=Zeroizing::new(serde_json::json!({"kind":"future","id":id,"version":1,"updated_at_ms":1,"device_id":"d".repeat(32),"deleted":false,"payload":{"schema":1,"future_secret":"PRIVATE_SENTINEL"}}).to_string().into_bytes());
    let sealed = crypto::seal(&parent, "future", id, &bytes).unwrap();
    let row = SealedRecord {
        envelope: crate::sync::record::Envelope {
            id_hash: sealed.id_hash,
            kind: "future".into(),
            seq: 1,
            nonce: sealed.nonce,
            ciphertext: sealed.ciphertext,
            deleted: false,
        },
        dirty: false,
        public_identity: None,
    };
    let mut account = AccountState::new(&parent.chain_id);
    account.sealed.insert(row.key(), row);
    let mut state:SyncStateV3=serde_json::from_value(serde_json::json!({"version":7,"device_id":"d".repeat(32),"device_name":"Synthetic","relay_url":"https://relay.example","last_sync_ms":null,"last_error":null})).unwrap();
    state.account = Some(account);
    state.local.hosts.insert("host:1111111111111111".into(),LocalRecord{record:Record{kind:RecordKind::Host,id:"1111111111111111".into(),version:1,updated_at_ms:1,device_id:"d".repeat(32),deleted:false,payload:serde_json::json!({"schema":2,"alias":"valid_prefix","hostname":"fixture.invalid","auth":"password"})},seq:0,dirty:false});
    let sources = Sources::discover(&state, Some(&parent)).unwrap();
    let inventory = Inventory::from_state(&sources, &state).unwrap();
    assert_eq!(inventory.rows().len(), 2);
    assert!(!inventory
        .admit_known()
        .err()
        .unwrap()
        .to_string()
        .contains("SENTINEL"));
}

#[test]
fn known_inputs_keep_public_data_and_extract_exact_native_private_entries_without_cache_or_io() {
    use crate::sync::{
        crypto::ChainKeys,
        record::{LocalRecord, Record, RecordKind},
        slot_rules::test_keys,
        state_v2::{AccountState, SealedRecord},
    };
    let parent = ChainKeys::generate().unwrap();
    let original = test_keys::encrypted();
    let id = "1".repeat(32);
    let mut state:SyncStateV3=serde_json::from_value(serde_json::json!({"version":7,"device_id":"d".repeat(32),"device_name":"Synthetic","relay_url":"https://relay.example","last_sync_ms":null,"last_error":null})).unwrap();
    let mut account = AccountState::new(&parent.chain_id);
    let key = SealedRecord::seal(
        &parent,
        &Record {
            kind: RecordKind::Key,
            id: id.clone(),
            version: 2,
            updated_at_ms: 3,
            device_id: state.device_id.clone(),
            deleted: false,
            payload: serde_json::json!({"schema":1,"private_key":original}),
        },
        0,
    )
    .unwrap();
    account.sealed.insert(key.key(), key);
    state.account = Some(account);
    state.local.hosts.insert("host:1111111111111111".into(),LocalRecord{record:Record{kind:RecordKind::Host,id:"1111111111111111".into(),version:1,updated_at_ms:1,device_id:state.device_id.clone(),deleted:false,payload:serde_json::json!({"schema":2,"alias":"known","hostname":"fixture.invalid","auth":"password"})},seq:0,dirty:false});
    let sources = Sources::discover(&state, Some(&parent)).unwrap();
    let known = Inventory::from_state(&sources, &state)
        .unwrap()
        .admit_known()
        .unwrap();
    assert_eq!(known.rows().len(), 2);
    assert!(known.rows().iter().any(|row| row.kind == "host"
        && matches!(&row.data,KnownData::Host(host) if host.alias=="known")));
    let keys = known.into_keys();
    assert_eq!(keys.len(), 1);
    assert_eq!(keys[0].id, id);
    assert_eq!(keys[0].version, 2);
    assert_eq!(keys[0].updated_at_ms, 3);
    assert!(keys[0].dirty);
    assert!(keys[0].material.as_ref().unwrap().private() == original);
}
