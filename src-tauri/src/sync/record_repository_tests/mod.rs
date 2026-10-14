use super::*;
use crate::sync::state_v2::AccountState;
const ID: &str = "0000000000000001";
const OTHER: &str = "0000000000000002";
const PUBLIC: &str =
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIF5M9xdffT0p33BD1LiLFTiEvrjv4IZMFADC81ex4ndf";
const FP: &str = "SHA256:9Q3QMhBJBcoUNE88XYEQbCPlcFByPPyVPJ6enJtQ+ew";
const ECDSA: &str = "ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBEjFNKVD5g/ngM+x8oESowshddffHjvh+l4MYyyXDZMfnXpzylT6xjkTiMop0/8K1KN1+LyseBdXlLj6j5m8mvU=";
fn state() -> SyncStateV3 {
    SyncStateV3 {
        version: 3,
        device_id: "d".repeat(32),
        device_name: "fixture".into(),
        relay_url: "http://127.0.0.1:8787".into(),
        account: None,
        spaces: Default::default(),
        local: Default::default(),
        rotation: None,
        relay_features: None,
        legacy_v1_backup: None,
        phrase_cleanup_pending: false,
        notices: vec![],
        last_sync_ms: None,
        last_error: None,
    }
}
fn payload(alias: &str) -> HostPayload {
    HostPayload {
        schema: 2,
        alias: alias.into(),
        hostname: "server.example.com".into(),
        port: 22,
        user: "deploy".into(),
        auth: AuthKind::Password,
        key_id: None,
        jump: vec![],
        keepalive_secs: 30,
        keepalive_max_missed: 3,
        connect_timeout_secs: 15,
        host_key: None,
        tags: vec![],
        notes: String::new(),
        imported: None,
    }
}
fn cached(id: &str, p: HostPayload, seq: u64) -> LocalRecord {
    LocalRecord {
        record: Record {
            kind: RecordKind::Host,
            id: id.into(),
            version: 4,
            updated_at_ms: 100,
            device_id: "d".repeat(32),
            deleted: false,
            payload: serde_json::to_value(p).unwrap(),
        },
        seq,
        dirty: false,
    }
}
fn with_host() -> SyncStateV3 {
    let mut s = state();
    s.local.hosts.insert(
        record_key(RecordKind::Host, ID),
        cached(ID, payload("web"), 7),
    );
    s
}
fn with_spaces() -> SyncStateV3 {
    let mut s = with_host();
    s.account = Some(AccountState::new(&"b".repeat(64)));
    for c in ["a", "c"] {
        s.spaces.insert(
            c.repeat(64),
            SpaceStateV3 {
                selected: true,
                ..Default::default()
            },
        );
    }
    s
}
fn scope(c: &str) -> HostScope {
    HostScope::Space {
        space_id: c.repeat(64),
    }
}
fn pin() -> StoredHostKey {
    StoredHostKey {
        algorithm: "ssh-ed25519".into(),
        public_key: PUBLIC.split_whitespace().nth(1).unwrap().into(),
        fingerprint: FP.into(),
        pinned_at_ms: 1,
        pinned_by_device_id: "d".repeat(32),
    }
}
fn slot(line: &str) -> KeySlotPayload {
    let key = ssh_key::PublicKey::from_openssh(line).unwrap();
    KeySlotPayload {
        schema: 2,
        name: "key".into(),
        public_key: line.into(),
        fingerprint: key.fingerprint(ssh_key::HashAlg::Sha256).to_string(),
        key_type: key.algorithm().as_str().into(),
        has_passphrase: false,
        created_at_ms: 1,
        origin_device_id: "d".repeat(32),
    }
}
fn account_key(s: &mut SyncStateV3, id: &str, p: KeySlotPayload, deleted: bool) {
    s.account.as_mut().unwrap().records.insert(
        record_key(RecordKind::KeySlot, id),
        LocalRecord {
            record: Record {
                kind: RecordKind::KeySlot,
                id: id.into(),
                version: 1,
                updated_at_ms: 100,
                device_id: "d".repeat(32),
                deleted,
                payload: serde_json::to_value(p).unwrap(),
            },
            seq: 9,
            dirty: false,
        },
    );
}

#[test]
fn create_is_local_by_default_scope_unpinned_and_does_not_mutate_input() {
    let s = state();
    let before = s.clone();
    let mut p = payload("web");
    p.host_key = Some(pin());
    let next = create_host(&s, ID, HostScope::Local, p, 10).unwrap();
    assert_eq!(s, before);
    let h = get_host(&next, ID).unwrap();
    assert!(h.host.payload.host_key.is_none());
    assert_eq!(h.revision.updated_at_ms, 10);
    assert_eq!(h.revision.version, 1);
    assert!(!next.local.hosts[&record_key(RecordKind::Host, ID)].dirty);
}
#[test]
fn edits_reject_same_clock_remote_device_revision_and_leave_input_unchanged() {
    let s = with_host();
    let expected = get_host(&s, ID).unwrap().revision;
    let mut remote = s.clone();
    remote
        .local
        .hosts
        .get_mut(&record_key(RecordKind::Host, ID))
        .unwrap()
        .record
        .device_id = "e".repeat(32);
    let before = remote.clone();
    assert!(matches!(
        update_host(&remote, ID, &expected, payload("edited"), 101),
        Err(RepositoryError::RevisionConflict { .. })
    ));
    assert_eq!(remote, before);
}
#[test]
fn edits_keep_server_pin_and_clear_it_when_endpoint_changes() {
    let mut s = with_host();
    s.local
        .hosts
        .get_mut(&record_key(RecordKind::Host, ID))
        .unwrap()
        .record
        .payload["host_key"] = serde_json::to_value(pin()).unwrap();
    let h = get_host(&s, ID).unwrap();
    let mut edited = payload("renamed");
    edited.host_key = None;
    let next = update_host(&s, ID, &h.revision, edited, 50).unwrap();
    assert_eq!(
        get_host(&next, ID).unwrap().host.payload.host_key,
        Some(pin())
    );
    assert_eq!(get_host(&next, ID).unwrap().revision.updated_at_ms, 101);
    let mut edited = h.host.payload;
    edited.port = 2222;
    edited.host_key = Some(pin());
    let next = update_host(&s, ID, &h.revision, edited, 50).unwrap();
    assert!(get_host(&next, ID).unwrap().host.payload.host_key.is_none());
    assert_eq!(s.local.hosts[&record_key(RecordKind::Host, ID)].seq, 7);
}
#[test]
fn cross_scope_aliases_are_visible_and_unscoped_lookup_is_ambiguous() {
    let mut s = with_spaces();
    s.spaces.get_mut(&"a".repeat(64)).unwrap().records.insert(
        record_key(RecordKind::Host, OTHER),
        cached(OTHER, payload("web"), 8),
    );
    assert_eq!(list_hosts(&s).unwrap().len(), 2);
    assert!(matches!(
        find_by_alias(&s, "web"),
        Err(RepositoryError::Validation(
            RecordValidationError::AmbiguousAlias(_)
        ))
    ));
    assert_eq!(get_host(&s, OTHER).unwrap().host.scope, scope("a"));
    s.spaces.get_mut(&"a".repeat(64)).unwrap().selected = false;
    assert_eq!(find_by_alias(&s, "web").unwrap().host.id, ID);
}
#[test]
fn duplicate_active_ids_and_same_scope_aliases_are_rejected() {
    let mut s = with_spaces();
    s.spaces.get_mut(&"a".repeat(64)).unwrap().records.insert(
        record_key(RecordKind::Host, ID),
        cached(ID, payload("other"), 8),
    );
    assert_eq!(snapshot(&s).unwrap().hosts.len(), 2);
    assert!(matches!(
        get_host(&s, ID),
        Err(RepositoryError::Validation(
            RecordValidationError::DuplicateId(_)
        ))
    ));
    let s = with_host();
    assert!(matches!(
        create_host(&s, OTHER, HostScope::Local, payload("web"), 101),
        Err(RepositoryError::Validation(
            RecordValidationError::AliasConflict { .. }
        ))
    ));
}
#[test]
fn moves_are_atomic_preserve_id_and_leave_scope_specific_tombstones() {
    let s = with_spaces();
    let h = get_host(&s, ID).unwrap();
    let space = move_host(&s, ID, &h.revision, scope("a"), 101).unwrap();
    let k = record_key(RecordKind::Host, ID);
    assert_eq!(s, with_spaces());
    assert!(space.local.hosts[&k].record.deleted);
    assert!(!space.local.hosts[&k].dirty);
    assert!(space.spaces[&"a".repeat(64)].records[&k].dirty);
    assert_eq!(get_host(&space, ID).unwrap().host.id, ID);
    let h = get_host(&space, ID).unwrap();
    let next = move_host(&space, ID, &h.revision, scope("c"), 102).unwrap();
    assert!(next.spaces[&"a".repeat(64)].records[&k].record.deleted);
    assert!(next.spaces[&"a".repeat(64)].records[&k].dirty);
    assert_eq!(get_host(&next, ID).unwrap().host.scope, scope("c"));
    let h = get_host(&next, ID).unwrap();
    let local = move_host(&next, ID, &h.revision, HostScope::Local, 103).unwrap();
    assert!(!local.local.hosts[&k].dirty);
    assert!(!local.local.hosts[&k].record.deleted);
}
#[test]
fn moving_back_retains_destination_seq_and_newer_tombstone_ordering() {
    let mut s = with_spaces();
    let k = record_key(RecordKind::Host, ID);
    let mut tomb = cached(ID, payload("old"), 91);
    tomb.record.deleted = true;
    tomb.record.updated_at_ms = 500;
    tomb.record.version = 20;
    s.spaces
        .get_mut(&"a".repeat(64))
        .unwrap()
        .records
        .insert(k.clone(), tomb);
    let h = get_host(&s, ID).unwrap();
    let next = move_host(&s, ID, &h.revision, scope("a"), 101).unwrap();
    let r = &next.spaces[&"a".repeat(64)].records[&k];
    assert_eq!(r.seq, 91);
    assert_eq!(r.record.updated_at_ms, 501);
    assert_eq!(r.record.version, 21);
}
#[test]
fn unavailable_spaces_refuse_creation_and_moves_and_reserve_inactive_ids() {
    let mut s = with_spaces();
    s.spaces.get_mut(&"a".repeat(64)).unwrap().selected = false;
    let before = s.clone();
    let h = get_host(&s, ID).unwrap();
    assert!(matches!(
        move_host(&s, ID, &h.revision, scope("a"), 101),
        Err(RepositoryError::SpaceUnavailable(_))
    ));
    assert!(create_host(&s, OTHER, scope("f"), payload("db"), 101).is_err());
    assert_eq!(s, before);
    s.spaces.get_mut(&"a".repeat(64)).unwrap().records.insert(
        record_key(RecordKind::Host, OTHER),
        cached(OTHER, payload("hidden"), 1),
    );
    assert!(matches!(
        create_host(&s, OTHER, HostScope::Local, payload("db"), 101),
        Err(RepositoryError::Validation(
            RecordValidationError::DuplicateId(_)
        ))
    ));
    s.spaces.get_mut(&"c".repeat(64)).unwrap().missing = true;
    assert!(move_host(&s, ID, &h.revision, scope("c"), 101).is_err());
}
#[test]
fn deletion_tombstones_preserve_seq_and_cannot_leave_a_live_dangling_jump() {
    let s = with_host();
    let h = get_host(&s, ID).unwrap();
    let next = delete_host(&s, ID, &h.revision, 101).unwrap();
    let r = &next.local.hosts[&record_key(RecordKind::Host, ID)];
    assert!(r.record.deleted);
    assert_eq!(r.seq, 7);
    assert!(!r.dirty);
    assert_eq!(r.record.payload, serde_json::Value::Null);
    let mut dependent = payload("dependent");
    dependent.jump = vec![ID.into()];
    let s = create_host(&s, OTHER, HostScope::Local, dependent, 101).unwrap();
    assert!(matches!(
        delete_host(&s, ID, &h.revision, 102),
        Err(RepositoryError::Validation(
            RecordValidationError::MissingJump { .. }
        ))
    ));
    assert!(get_host(&s, ID).is_ok());
}
#[test]
fn pin_cas_refuses_changed_endpoint_or_previous_key_and_is_idempotent() {
    let s = with_host();
    let ep = HostEndpoint {
        hostname: "server.example.com".into(),
        port: 22,
    };
    let pinned = pin_host_key(&s, ID, &ep, None, pin(), 111).unwrap();
    let saved = get_host(&pinned, ID)
        .unwrap()
        .host
        .payload
        .host_key
        .unwrap();
    assert_eq!(saved.pinned_at_ms, 111);
    assert_eq!(saved.pinned_by_device_id, s.device_id);
    assert!(get_host(&s, ID).unwrap().host.payload.host_key.is_none());
    assert_eq!(
        pin_host_key(&pinned, ID, &ep, None, pin(), 112).unwrap(),
        pinned
    );
    let mut changed = pin();
    changed.public_key = "different".into();
    assert!(matches!(
        pin_host_key(&pinned, ID, &ep, Some(&changed), pin(), 112),
        Ok(_)
    ));
    let stale = HostEndpoint {
        hostname: ep.hostname.clone(),
        port: 2222,
    };
    assert!(matches!(
        pin_host_key(&pinned, ID, &stale, Some(&saved), pin(), 112),
        Err(RepositoryError::EndpointChanged(_))
    ));
    assert!(matches!(
        pin_host_key(&s, ID, &ep, Some(&saved), pin(), 112),
        Err(RepositoryError::PinConflict(_))
    ));
}
#[test]
fn jump_snapshot_inherits_only_first_route_and_enforces_five_total_jumps() {
    let mut s = state();
    for n in 1..=7 {
        let id = format!("{n:016x}");
        s.local.hosts.insert(
            record_key(RecordKind::Host, &id),
            cached(&id, payload(&format!("h{n}")), 1),
        );
    }
    let set = |s: &mut SyncStateV3, n: u64, jumps: Vec<u64>| {
        s.local
            .hosts
            .get_mut(&record_key(RecordKind::Host, &format!("{n:016x}")))
            .unwrap()
            .record
            .payload["jump"] = serde_json::json!(jumps
            .into_iter()
            .map(|n| format!("{n:016x}"))
            .collect::<Vec<_>>());
    };
    set(&mut s, 1, vec![2, 3]);
    set(&mut s, 2, vec![4]);
    set(&mut s, 3, vec![5]);
    assert_eq!(
        resolve_host_chain(&s, ID)
            .unwrap()
            .iter()
            .map(|h| h.host.id.clone())
            .collect::<Vec<_>>(),
        vec![
            "0000000000000004",
            "0000000000000002",
            "0000000000000003",
            ID
        ]
    );
    set(&mut s, 1, vec![2, 3, 6, 7]);
    assert_eq!(resolve_host_chain(&s, ID).unwrap().len(), 6);
    set(&mut s, 4, vec![5]);
    assert!(matches!(
        resolve_host_chain(&s, ID),
        Err(RepositoryError::Validation(
            RecordValidationError::JumpDepth(_)
        ))
    ));
}
#[test]
fn missing_cycles_and_repeated_jump_routes_are_rejected_without_mutating_input() {
    let s = with_host();
    let mut p = payload("db");
    p.jump = vec![OTHER.into()];
    assert!(matches!(
        create_host(&s, "0000000000000003", HostScope::Local, p, 101),
        Err(RepositoryError::Validation(
            RecordValidationError::MissingJump { .. }
        ))
    ));
    let mut s = with_host();
    let mut p = payload("b");
    p.jump = vec![ID.into()];
    s.local
        .hosts
        .insert(record_key(RecordKind::Host, OTHER), cached(OTHER, p, 1));
    s.local
        .hosts
        .get_mut(&record_key(RecordKind::Host, ID))
        .unwrap()
        .record
        .payload["jump"] = serde_json::json!([OTHER]);
    assert_eq!(
        get_host(&s, ID).unwrap().readiness,
        HostReadiness::NeedsReview
    );
    assert!(matches!(
        resolve_host_chain(&s, ID),
        Err(RepositoryError::Validation(
            RecordValidationError::JumpCycle(_)
        ))
    ));
    s.local
        .hosts
        .get_mut(&record_key(RecordKind::Host, ID))
        .unwrap()
        .record
        .payload["jump"] = serde_json::json!([OTHER, OTHER]);
    assert!(matches!(
        snapshot(&s),
        Err(RepositoryError::Validation(
            RecordValidationError::RepeatedJump { .. }
        ))
    ));
}
#[test]
fn missing_material_is_saveable_and_synced_account_metadata_is_authoritative() {
    let mut s = with_spaces();
    let key = "a".repeat(32);
    let mut p = payload("web");
    p.auth = AuthKind::Key;
    p.key_id = Some(key.clone());
    s.local
        .hosts
        .insert(record_key(RecordKind::Host, ID), cached(ID, p, 1));
    assert_eq!(
        get_host(&s, ID).unwrap().readiness,
        HostReadiness::NeedsKey(key.clone())
    );
    account_key(&mut s, &key, slot(PUBLIC), false);
    assert_eq!(
        resolve_key(&s, &key).unwrap().status,
        KeyStatus::NeedsMaterial
    );
    s.local.keys.insert(
        key.clone(),
        LocalKeyMetadata {
            vault_id: "f".repeat(32),
            public: slot(PUBLIC),
        },
    );
    let view = resolve_key(&s, &key).unwrap();
    assert_eq!(view.authority, KeyAuthority::Account);
    assert_eq!(view.vault_id, Some("f".repeat(32)));
    assert_eq!(get_host(&s, ID).unwrap().readiness, HostReadiness::Ready);
    account_key(&mut s, &key, slot(PUBLIC), true);
    assert_eq!(resolve_key(&s, &key).unwrap().status, KeyStatus::Deleted);
    assert!(resolve_key(&s, &key).unwrap().vault_id.is_none());
    assert_eq!(
        get_host(&s, ID).unwrap().readiness,
        HostReadiness::NeedsKey(key)
    );
}
#[test]
fn key_conflicts_persist_as_status_without_local_fallback_or_snapshot_failure() {
    let mut s = with_spaces();
    let key = "a".repeat(32);
    account_key(&mut s, &key, slot(PUBLIC), false);
    let ecdsa = ECDSA.to_string();
    s.local.keys.insert(
        key.clone(),
        LocalKeyMetadata {
            vault_id: key.clone(),
            public: slot(&ecdsa),
        },
    );
    let mut p = payload("web");
    p.auth = AuthKind::Key;
    p.key_id = Some(key.clone());
    s.local
        .hosts
        .insert(record_key(RecordKind::Host, ID), cached(ID, p, 1));
    let before = s.clone();
    let view = resolve_key(&s, &key).unwrap();
    assert_eq!(view.status, KeyStatus::Conflict);
    assert_eq!(view.public, Some(slot(PUBLIC)));
    assert!(view.vault_id.is_none());
    assert_eq!(
        get_host(&s, ID).unwrap().readiness,
        HostReadiness::KeyConflict(key)
    );
    assert_eq!(s, before);
}
#[test]
fn malformed_cache_keys_and_plain_secrets_are_refused_and_opaque_sealed_data_is_preserved() {
    let mut s = with_host();
    let r = s
        .local
        .hosts
        .remove(&record_key(RecordKind::Host, ID))
        .unwrap();
    s.local.hosts.insert("host:wrong".into(), r);
    assert!(snapshot(&s).is_err());
    let mut secret_state = with_spaces();
    let mut secret = cached(ID, payload("placeholder"), 0);
    secret.record.kind = RecordKind::Key;
    secret.record.id = "a".repeat(32);
    secret.record.payload = serde_json::json!({"fixture": "sealed-only"});
    secret_state
        .account
        .as_mut()
        .unwrap()
        .records
        .insert(record_key(RecordKind::Key, &secret.record.id), secret);
    assert!(snapshot(&secret_state).is_err());
    let mut s = with_spaces();
    let key = "opaque:hash".to_string();
    let sealed = crate::sync::state_v2::SealedRecord {
        envelope: crate::sync::record::Envelope {
            id_hash: "hash".into(),
            kind: "opaque".into(),
            seq: 8,
            nonce: "opaque".into(),
            ciphertext: "opaque".into(),
            deleted: false,
        },
        dirty: false,
    };
    s.account
        .as_mut()
        .unwrap()
        .sealed
        .insert(key.clone(), sealed.clone());
    let h = get_host(&s, ID).unwrap();
    let next = update_host(&s, ID, &h.revision, payload("renamed"), 101).unwrap();
    assert_eq!(next.account.unwrap().sealed[&key], sealed);
}

#[test]
fn unrelated_remote_route_conflicts_do_not_block_connecting_or_repairing_valid_hosts() {
    let mut s = with_host();
    let mut broken = payload("broken");
    broken.jump = vec!["000000000000000f".into()];
    s.local.hosts.insert(
        record_key(RecordKind::Host, OTHER),
        cached(OTHER, broken, 1),
    );
    assert_eq!(
        get_host(&s, OTHER).unwrap().readiness,
        HostReadiness::NeedsReview
    );
    assert_eq!(resolve_host_chain(&s, ID).unwrap().len(), 1);
    let h = get_host(&s, ID).unwrap();
    let edited = update_host(&s, ID, &h.revision, payload("renamed"), 101).unwrap();
    assert_eq!(get_host(&edited, ID).unwrap().host.payload.alias, "renamed");
    let broken = get_host(&s, OTHER).unwrap();
    let repaired = update_host(&s, OTHER, &broken.revision, payload("repaired"), 101).unwrap();
    assert_eq!(
        get_host(&repaired, OTHER).unwrap().readiness,
        HostReadiness::Ready
    );
}
#[test]
fn reviewed_import_can_preserve_a_missing_jump_but_never_resolve_it() {
    let s = state();
    let mut p = payload("imported");
    p.jump = vec![OTHER.into()];
    p.imported = Some(ImportedSettings {
        source: "fixture/config".into(),
        at_ms: 1,
        unsupported: vec![UnsupportedSetting {
            keyword: "ProxyJump".into(),
            value: "unresolved".into(),
            requires_review: true,
        }],
    });
    let saved = create_host(&s, ID, HostScope::Local, p, 100).unwrap();
    assert_eq!(
        get_host(&saved, ID).unwrap().readiness,
        HostReadiness::NeedsReview
    );
    assert!(matches!(
        resolve_host_chain(&saved, ID),
        Err(RepositoryError::Validation(
            RecordValidationError::MissingJump { .. }
        ))
    ));
}

#[test]
fn pin_replacement_compares_public_identity_and_never_overwrites_a_newer_pin() {
    let s = with_spaces();
    let endpoint = HostEndpoint {
        hostname: "server.example.com".into(),
        port: 22,
    };
    let pinned = pin_host_key(&s, ID, &endpoint, None, pin(), 101).unwrap();
    let public = slot(ECDSA);
    let different = StoredHostKey {
        algorithm: public.key_type,
        public_key: ECDSA.split_whitespace().nth(1).unwrap().into(),
        fingerprint: public.fingerprint,
        pinned_at_ms: 9,
        pinned_by_device_id: "f".repeat(32),
    };
    let before = pinned.clone();
    assert!(matches!(
        pin_host_key(&pinned, ID, &endpoint, None, different.clone(), 102),
        Err(RepositoryError::PinConflict(_))
    ));
    assert_eq!(pinned, before);
    let replaced =
        pin_host_key(&pinned, ID, &endpoint, Some(&pin()), different.clone(), 102).unwrap();
    let saved = get_host(&replaced, ID)
        .unwrap()
        .host
        .payload
        .host_key
        .unwrap();
    assert_eq!(saved.pinned_at_ms, 102);
    assert_eq!(saved.pinned_by_device_id, "d".repeat(32));
    assert!(matches!(
        pin_host_key(&replaced, ID, &endpoint, Some(&pin()), pin(), 103),
        Err(RepositoryError::PinConflict(_))
    ));
    assert_eq!(
        pin_host_key(&replaced, ID, &endpoint, Some(&pin()), different, 103).unwrap(),
        replaced
    );
}
#[test]
fn local_edits_cannot_inject_pins_and_space_updates_keep_seq_and_mark_dirty() {
    let s = with_spaces();
    let h = get_host(&s, ID).unwrap();
    let mut p = payload("changed");
    p.host_key = Some(pin());
    let next = update_host(&s, ID, &h.revision, p, 101).unwrap();
    assert!(get_host(&next, ID).unwrap().host.payload.host_key.is_none());
    let h = get_host(&s, ID).unwrap();
    let mut next = move_host(&s, ID, &h.revision, scope("a"), 101).unwrap();
    let k = record_key(RecordKind::Host, ID);
    next.spaces
        .get_mut(&"a".repeat(64))
        .unwrap()
        .records
        .get_mut(&k)
        .unwrap()
        .seq = 27;
    let h = get_host(&next, ID).unwrap();
    let saved = update_host(&next, ID, &h.revision, payload("new"), 100).unwrap();
    let r = &saved.spaces[&"a".repeat(64)].records[&k];
    assert_eq!(r.seq, 27);
    assert!(r.dirty);
    assert_eq!(r.record.updated_at_ms, 102);
}
#[test]
fn ordering_overflow_never_wraps_or_changes_the_original_state() {
    for field in ["version", "timestamp"] {
        let mut s = with_host();
        let r = &mut s
            .local
            .hosts
            .get_mut(&record_key(RecordKind::Host, ID))
            .unwrap()
            .record;
        if field == "version" {
            r.version = u64::MAX;
        } else {
            r.updated_at_ms = u64::MAX;
        }
        let h = get_host(&s, ID).unwrap();
        let before = s.clone();
        assert!(matches!(
            update_host(&s, ID, &h.revision, payload("new"), 101),
            Err(RepositoryError::OrderingOverflow(_))
        ));
        assert_eq!(s, before);
    }
}
#[test]
fn valid_remote_alias_conflicts_can_be_listed_and_repaired_by_id() {
    let mut s = with_host();
    s.local.hosts.insert(
        record_key(RecordKind::Host, OTHER),
        cached(OTHER, payload("web"), 1),
    );
    assert_eq!(list_hosts(&s).unwrap().len(), 2);
    assert_eq!(
        get_host(&s, ID).unwrap().readiness,
        HostReadiness::NeedsReview
    );
    assert!(matches!(
        find_by_alias(&s, "web"),
        Err(RepositoryError::Validation(
            RecordValidationError::AmbiguousAlias(_)
        ))
    ));
    let h = get_host(&s, OTHER).unwrap();
    let repaired = update_host(&s, OTHER, &h.revision, payload("other"), 101).unwrap();
    assert_eq!(find_by_alias(&repaired, "web").unwrap().host.id, ID);
    assert_eq!(
        get_host(&repaired, ID).unwrap().readiness,
        HostReadiness::Ready
    );
}
#[test]
fn invalid_account_host_caches_or_chain_ids_are_not_accepted_as_a_valid_snapshot() {
    let mut s = with_spaces();
    s.account.as_mut().unwrap().records.insert(
        record_key(RecordKind::Host, OTHER),
        cached(OTHER, payload("bad"), 1),
    );
    assert!(matches!(
        snapshot(&s),
        Err(RepositoryError::Validation(
            RecordValidationError::WrongKind { .. }
        ))
    ));
    let mut s = with_spaces();
    s.account.as_mut().unwrap().chain_id = "not-a-chain".into();
    assert!(snapshot(&s).is_err());
    let mut s = with_spaces();
    s.spaces.insert(
        "not-a-chain".into(),
        SpaceStateV3 {
            selected: true,
            ..Default::default()
        },
    );
    assert!(snapshot(&s).is_err());
}
#[test]
fn account_format_freeze_and_invalid_record_ordering_fail_without_losing_local_access() {
    let mut s = with_spaces();
    s.account.as_mut().unwrap().remote_schema_version = Some(4);
    let h = get_host(&s, ID).unwrap();
    assert!(matches!(
        move_host(&s, ID, &h.revision, scope("a"), 101),
        Err(RepositoryError::ReadOnlyAccount)
    ));
    assert!(update_host(&s, ID, &h.revision, payload("local"), 101).is_ok());
    s.account.as_mut().unwrap().remote_schema_version = Some(3);
    s.account.as_mut().unwrap().frozen = Some(
        serde_json::from_value(serde_json::json!({"detected_at_ms": 100, "markers": []})).unwrap(),
    );
    assert!(matches!(
        move_host(&s, ID, &h.revision, scope("a"), 101),
        Err(RepositoryError::ReadOnlyAccount)
    ));
    assert!(update_host(&s, ID, &h.revision, payload("local"), 101).is_ok());
    let mut s = with_host();
    s.local
        .hosts
        .get_mut(&record_key(RecordKind::Host, ID))
        .unwrap()
        .record
        .device_id = "invalid".into();
    assert!(snapshot(&s).is_err());
}

#[test]
fn a_unique_alias_cannot_select_one_of_two_active_records_with_the_same_id() {
    let mut s = with_spaces();
    s.spaces.get_mut(&"a".repeat(64)).unwrap().records.insert(
        record_key(RecordKind::Host, ID),
        cached(ID, payload("other-alias"), 8),
    );
    assert!(matches!(
        find_by_alias(&s, "web"),
        Err(RepositoryError::Validation(
            RecordValidationError::DuplicateId(_)
        ))
    ));
    assert!(matches!(
        resolve_host_chain(&s, ID),
        Err(RepositoryError::Validation(
            RecordValidationError::DuplicateId(_)
        ))
    ));
    assert!(list_hosts(&s)
        .unwrap()
        .iter()
        .all(|h| h.readiness == HostReadiness::NeedsReview));
}
