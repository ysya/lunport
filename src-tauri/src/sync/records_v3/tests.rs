use super::*;
use crate::sync::record::{Record, RecordKind};
use crate::sync::slot_rules::test_keys;
use std::collections::BTreeSet;

pub(super) fn host(id: &str, alias: &str) -> HostRecord {
    HostRecord {
        id: id.into(),
        scope: HostScope::Local,
        payload: HostPayload {
            schema: 2,
            alias: alias.into(),
            hostname: "web.example.com".into(),
            port: 22,
            user: "".into(),
            auth: AuthKind::Password,
            key_id: None,
            jump: vec![],
            keepalive_secs: 30,
            keepalive_max_missed: 3,
            connect_timeout_secs: 15,
            host_key: None,
            tags: vec![],
            notes: "".into(),
            imported: None,
        },
    }
}
fn slot() -> KeySlotPayload {
    KeySlotPayload {
        schema: 2,
        name: "Production".into(),
        public_key: test_keys::PLAIN_PUBLIC.into(),
        fingerprint: "SHA256:9Q3QMhBJBcoUNE88XYEQbCPlcFByPPyVPJ6enJtQ+ew".into(),
        key_type: "ssh-ed25519".into(),
        has_passphrase: false,
        created_at_ms: 1,
        origin_device_id: "d".repeat(32),
    }
}
fn record(kind: RecordKind, id: &str, deleted: bool, payload: serde_json::Value) -> Record {
    Record {
        kind,
        id: id.into(),
        version: 1,
        updated_at_ms: 1,
        device_id: "d".repeat(32),
        deleted,
        payload,
    }
}

#[test]
fn invalid_schema_ids_ports_endpoints_and_auth_fields_are_rejected() {
    let valid = host("0000000000000001", "web");
    assert!(validate_host(&valid).is_ok());
    for schema in [1, 99] {
        let mut h = valid.clone();
        h.payload.schema = schema;
        assert!(matches!(
            validate_host(&h),
            Err(RecordValidationError::UnsupportedSchema { kind: "host", .. })
        ));
    }
    for id in ["short", "000000000000000G", "000000000000000A"] {
        let mut h = valid.clone();
        h.id = id.into();
        assert!(validate_host(&h).is_err());
    }
    let mut h = valid.clone();
    h.payload.port = 0;
    assert!(validate_host(&h).is_err());
    let mut h = valid.clone();
    h.payload.hostname.clear();
    assert!(validate_host(&h).is_err());
    for alias in ["-bad", "two words", "a*", ""] {
        let mut h = valid.clone();
        h.payload.alias = alias.into();
        assert!(validate_host(&h).is_err());
    }
    let mut h = valid.clone();
    h.payload.connect_timeout_secs = 0;
    assert!(validate_host(&h).is_err());
    let mut h = valid.clone();
    h.payload.auth = AuthKind::Key;
    assert!(validate_host(&h).is_err());
    let mut h = valid;
    h.scope = HostScope::Space {
        space_id: "a".repeat(16),
    };
    assert!(validate_host(&h).is_err());
}

#[test]
fn a_missing_key_is_saveable_but_never_ready_to_connect() {
    let mut h = host("0000000000000001", "web");
    h.payload.auth = AuthKind::Key;
    h.payload.key_id = Some("a".repeat(32));
    assert!(validate_host(&h).is_ok());
    assert_eq!(
        connection_readiness(&h, &BTreeSet::new()),
        Ok(ConnectionReadiness::NeedsKey("a".repeat(32)))
    );
    assert_eq!(
        connection_readiness(&h, &BTreeSet::from(["a".repeat(32)])),
        Ok(ConnectionReadiness::Ready)
    );
    h.payload.key_id = Some("short".into());
    assert!(validate_host(&h).is_err());
}

#[test]
fn unsupported_settings_require_review_but_annotations_do_not_block() {
    let mut h = host("0000000000000001", "web");
    h.payload.imported = Some(ImportedSettings {
        source: "fixture/config".into(),
        at_ms: 1,
        unsupported: vec![UnsupportedSetting {
            keyword: "ProxyCommand".into(),
            value: "anything".into(),
            requires_review: true,
        }],
    });
    assert_eq!(
        connection_readiness(&h, &BTreeSet::new()),
        Ok(ConnectionReadiness::NeedsReview)
    );
    h.payload.imported.as_mut().unwrap().unsupported[0].requires_review = false;
    assert_eq!(
        connection_readiness(&h, &BTreeSet::new()),
        Ok(ConnectionReadiness::Ready)
    );
    let legacy: UnsupportedSetting =
        serde_json::from_str(r#"{"keyword":"Match","value":"exec anything"}"#).unwrap();
    assert!(legacy.requires_review);
}

#[test]
fn duplicate_ids_and_same_scope_aliases_fail_while_cross_scope_aliases_are_ambiguous() {
    let a = host("0000000000000001", "web");
    let b = host("0000000000000002", "web");
    assert!(matches!(
        validate_hosts(&[a.clone(), b.clone()]),
        Err(RecordValidationError::AliasConflict { .. })
    ));
    let mut b = b;
    b.scope = HostScope::Space {
        space_id: "a".repeat(64),
    };
    assert!(validate_hosts(&[a.clone(), b.clone()]).is_ok());
    assert!(matches!(
        resolve_alias(&[a.clone(), b], "web"),
        Err(RecordValidationError::AmbiguousAlias(_))
    ));
    let mut same_id = a.clone();
    same_id.payload.alias = "db".into();
    assert!(matches!(
        validate_hosts(&[a, same_id]),
        Err(RecordValidationError::DuplicateId(_))
    ));
}

#[test]
fn jump_graph_rejects_missing_endpoints_self_cycles_repeats_and_total_depth() {
    let mut a = host("0000000000000001", "web");
    let mut b = host("0000000000000002", "jump");
    a.payload.jump = vec![b.id.clone()];
    assert!(matches!(
        validate_hosts(&[a.clone()]),
        Err(RecordValidationError::MissingJump { .. })
    ));
    assert!(validate_hosts(&[a.clone(), b.clone()]).is_ok());
    b.payload.jump = vec![a.id.clone()];
    assert!(matches!(
        validate_hosts(&[a.clone(), b.clone()]),
        Err(RecordValidationError::JumpCycle(_))
    ));
    a.payload.jump = vec![a.id.clone()];
    assert!(validate_host(&a).is_err());
    a.payload.jump = vec![b.id.clone(), b.id.clone()];
    b.payload.jump.clear();
    assert!(validate_host(&a).is_err());
    let mut hosts: Vec<_> = (1..=7)
        .map(|i| host(&format!("{i:016x}"), &format!("host{i}")))
        .collect();
    for i in 1..7 {
        hosts[i].payload.jump = vec![hosts[i - 1].id.clone()];
    }
    assert!(matches!(
        validate_hosts(&hosts),
        Err(RecordValidationError::JumpDepth(_))
    ));
}

#[test]
fn tombstones_do_not_require_live_payload_and_wrong_record_kinds_are_rejected() {
    for payload in [
        serde_json::json!({}),
        serde_json::json!({"schema":1,"text":"Host old"}),
        serde_json::json!(null),
    ] {
        let r = record(RecordKind::Host, "0000000000000001", true, payload);
        assert_eq!(
            decode_host(&r, HostScope::Local),
            Ok(TypedRecord::Tombstone { id: r.id.clone() })
        );
    }
    let r = record(
        RecordKind::KeySlot,
        &"a".repeat(32),
        true,
        serde_json::json!({}),
    );
    assert_eq!(
        decode_keyslot(&r),
        Ok(TypedRecord::Tombstone { id: r.id.clone() })
    );
    assert!(matches!(
        decode_host(&r, HostScope::Local),
        Err(RecordValidationError::WrongKind { .. })
    ));
    let h = host("0000000000000001", "web");
    assert_eq!(
        decode_host(
            &record(
                RecordKind::Host,
                &h.id,
                false,
                serde_json::to_value(&h.payload).unwrap()
            ),
            HostScope::Local
        ),
        Ok(TypedRecord::Live(h))
    );
    let r = record(
        RecordKind::Host,
        "0000000000000001",
        false,
        serde_json::json!({"schema":99}),
    );
    assert!(matches!(
        decode_host(&r, HostScope::Local),
        Err(RecordValidationError::UnsupportedSchema { found: 99, .. })
    ));
}

#[test]
fn authoritative_key_identity_refuses_local_mismatch_and_malformed_public_bytes() {
    let slot = slot();
    assert!(validate_keyslot(&"a".repeat(32), &slot).is_ok());
    assert!(key_material_matches(&slot, test_keys::PLAIN_PUBLIC, &slot.fingerprint).is_ok());
    assert!(matches!(
        key_material_matches(&slot, test_keys::ECDSA_PUBLIC, &slot.fingerprint),
        Err(RecordValidationError::PublicKeyMismatch(_))
    ));
    let mut wrong = slot.clone();
    wrong.fingerprint = "SHA256:wrong".into();
    assert!(validate_keyslot(&"a".repeat(32), &wrong).is_err());
    let mut wrong = slot.clone();
    wrong.public_key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5".into();
    assert!(validate_keyslot(&"a".repeat(32), &wrong).is_err());
    let mut wrong = slot;
    wrong.schema = 1;
    assert!(matches!(
        validate_keyslot(&"a".repeat(32), &wrong),
        Err(RecordValidationError::UnsupportedSchema {
            kind: "keyslot",
            ..
        })
    ));
}

#[test]
fn editing_the_endpoint_clears_its_pin_and_rename_keeps_it_on_the_same_id() {
    let mut original = host("0000000000000001", "web");
    original.payload.host_key = Some(StoredHostKey {
        algorithm: "ssh-ed25519".into(),
        public_key: test_keys::PLAIN_PUBLIC
            .split_whitespace()
            .nth(1)
            .unwrap()
            .into(),
        fingerprint: slot().fingerprint,
        pinned_at_ms: 1,
        pinned_by_device_id: "d".repeat(32),
    });
    let mut renamed = original.payload.clone();
    renamed.alias = "renamed".into();
    let changed = replace_host_payload(&original, renamed).unwrap();
    assert_eq!(changed.id, original.id);
    assert_eq!(changed.payload.host_key, original.payload.host_key);
    for (hostname, port) in [("new.example.com", 22), ("web.example.com", 2222)] {
        let mut edit = original.payload.clone();
        edit.hostname = hostname.into();
        edit.port = port;
        let changed = replace_host_payload(&original, edit).unwrap();
        assert_eq!(changed.id, original.id);
        assert!(changed.payload.host_key.is_none());
    }
}

#[test]
fn migration_ids_match_independent_hash_vectors_and_utf8_byte_lengths() {
    assert_eq!(
        migration_host_id(&"a".repeat(64), "web").unwrap(),
        "97ae2d71de67d6f1"
    );
    assert_eq!(
        migration_host_id(&"a".repeat(64), "主機").unwrap(),
        "631a98777505db35"
    );
    assert_ne!(
        migration_host_id(&"a".repeat(64), "web").unwrap(),
        migration_host_id(&"b".repeat(64), "web").unwrap()
    );
    assert!(migration_host_id("invalid-space", "web").is_err());
    assert!(migration_host_id(&"a".repeat(64), "").is_err());
}

#[test]
fn migration_preflight_preserves_mapping_order_deduplicates_sources_and_refuses_reserved_ids() {
    let a = MigrationSource {
        space_id: "a".repeat(64),
        old_record_id: "web".into(),
    };
    let b = MigrationSource {
        space_id: "b".repeat(64),
        old_record_id: "web".into(),
    };
    let map = preflight_host_ids(&[a.clone(), b.clone(), a.clone()], &BTreeSet::new()).unwrap();
    assert_eq!(map.len(), 2);
    assert_eq!(map[&a], "97ae2d71de67d6f1");
    assert_eq!(
        map,
        preflight_host_ids(&[b, a.clone()], &BTreeSet::new()).unwrap()
    );
    assert!(
        matches!(preflight_host_ids(&[a.clone()], &BTreeSet::from(["97ae2d71de67d6f1".into()])), Err(RecordValidationError::MigrationCollision {id,..}) if id=="97ae2d71de67d6f1")
    );
    let legacy = MigrationSource {
        space_id: "c".repeat(64),
        old_record_id: "97ae2d71de67d6f1".into(),
    };
    assert!(matches!(
        preflight_host_ids(&[a, legacy], &BTreeSet::new()),
        Err(RecordValidationError::MigrationCollision { .. })
    ));
}
