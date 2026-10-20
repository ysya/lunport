use super::super::typed::{LegacyHost, LegacySlot};
use super::*;
use crate::sync::{
    central::{migration_history, migration_materials::Materials, payload::Data},
    fake_relay::FakeRelay,
    records_v3::SpaceStateV3,
    state_v2::AccountState,
    testkit::{MemKeychain, TestClock, TestDevice},
};
fn state() -> SyncStateV3 {
    let (owner, _, _) = migration_history::tests::initial();
    let mut state: SyncStateV3 = serde_json::from_value(serde_json::json!({"version":8,"device_id":"d".repeat(32),"device_name":"Synthetic","relay_url":owner.control.profile.origin,"last_sync_ms":null,"last_error":null})).unwrap();
    state.local.central = Some(owner);
    let mut account = AccountState::new(&"a".repeat(64));
    let id = "b".repeat(64);
    account.records.insert(record_key(RecordKind::Space, &id), LocalRecord { record: Record { kind: RecordKind::Space, id, version:1, updated_at_ms:1, device_id: state.device_id.clone(), deleted:false, payload:serde_json::json!({"schema":1,"name":"Legacy","slug":"legacy","created_at_ms":1}) }, seq:1, dirty:false });
    state.account = Some(account);
    state.spaces.insert("b".repeat(64), SpaceStateV3::default());
    state
}
fn host(alias: &str, text: &str, position: Position, version: u64) -> KnownInput {
    KnownInput { location: Location { scope: Scope::Space("b".repeat(64)), position, key: format!("host:{alias}"), index: version as usize }, sequence: version, dirty: false, kind: "host".into(), id: alias.into(), version, updated_at_ms: version, device_id: "d".repeat(32), deleted: false,
        data: KnownData::LegacyHost(LegacyHost { schema:1, text:Zeroizing::new(format!("Host {alias}\n  HostName {alias}.invalid\n  PreferredAuthentications password,keyboard-interactive\n{text}")) }) }
}
#[test]
fn all_old_host_versions_and_tombstones_use_stable_ids_with_complete_jump_links() {
    let mut state = state();
    let mut deleted = host("removed", "", Position::Current, 3);
    deleted.deleted = true;
    deleted.data = KnownData::Deleted;
    let known = Known {
        rows: vec![
            host("web", "  User original\n", Position::Retained, 1),
            host(
                "web",
                "  User current\n  ProxyJump bastion\n",
                Position::Sealed,
                2,
            ),
            host("bastion", "", Position::Sealed, 1),
            deleted,
        ],
    };
    let known = known.normalize_legacy(&mut state, None).unwrap();
    records_v3::validate_state(&state).unwrap();
    let web = records_v3::migration_host_id(&"b".repeat(64), "web").unwrap();
    let bastion = records_v3::migration_host_id(&"b".repeat(64), "bastion").unwrap();
    assert_eq!(known.rows()[0].id, web);
    assert_eq!(known.rows()[1].id, web);
    let KnownData::Host(old) = &known.rows()[0].data else {
        panic!()
    };
    assert_eq!(old.user, "original");
    let KnownData::Host(current) = &known.rows()[1].data else {
        panic!()
    };
    assert_eq!(current.user, "current");
    assert_eq!(current.jump[0], bastion);
    assert!(known.rows()[3].deleted);
    assert_eq!(
        known.rows()[3].id,
        records_v3::migration_host_id(&"b".repeat(64), "removed").unwrap()
    );
    assert_eq!(state.spaces[&"b".repeat(64)].records.len(), 3);
}
#[test]
fn includes_commands_missing_keys_and_colliding_modern_ids_require_review() {
    for text in [
        "  Include /synthetic/never-opened\n",
        "  ProxyCommand touch /synthetic/never-executed\n",
        "  IdentityFile /synthetic/missing\n",
        "  # -----BEGIN OPENSSH PRIVATE KEY-----\n",
    ] {
        let mut state = state();
        let known = Known {
            rows: vec![host("web", text, Position::Sealed, 1)],
        };
        assert!(known.normalize_legacy(&mut state, None).is_err(), "{text}");
    }
    let mut state = state();
    let mut modern = host("unused", "", Position::Current, 1);
    modern.id = records_v3::migration_host_id(&"b".repeat(64), "web").unwrap();
    modern.data = KnownData::Host(serde_json::from_value(serde_json::json!({"schema":2,"alias":"existing","hostname":"existing.invalid","auth":"password"})).unwrap());
    assert!(Known {
        rows: vec![host("web", "", Position::Sealed, 1), modern]
    }
    .normalize_legacy(&mut state, None)
    .is_err());
}
#[test]
fn old_own_slot_uses_only_captured_managed_bytes_and_preserves_original_container() {
    let device = TestDevice::new("old-own-slot", &FakeRelay::new(), &TestClock::new());
    let env = device.env();
    std::fs::create_dir_all(env.state_path.parent().unwrap()).unwrap();
    let mut state = state();
    std::fs::write(&env.state_path, serde_json::to_vec(&state).unwrap()).unwrap();
    let id = "1".repeat(32);
    let name = crate::sync::slot_rules::slot_file_name("old-own", &id);
    let root = env.ssh_dir.join("sshelter/keys");
    std::fs::create_dir_all(&root).unwrap();
    let raw = crate::sync::slot_rules::test_keys::encrypted();
    std::fs::write(root.join(name), &raw).unwrap();
    let files = Files::capture(&env, None).unwrap();
    let slot = KnownInput {
        location: Location {
            scope: Scope::Account("a".repeat(64)),
            position: Position::Current,
            key: format!("keyslot:{id}"),
            index: 0,
        },
        sequence: 1,
        dirty: false,
        kind: "keyslot".into(),
        id: id.clone(),
        version: 1,
        updated_at_ms: 1,
        device_id: "d".repeat(32),
        deleted: false,
        data: KnownData::LegacySlot(LegacySlot {
            schema: 1,
            name: "old-own".into(),
            mode: crate::sync::slot_rules::SlotMode::Own,
            origin_device_id: "legacy".into(),
            created_at_ms: 1,
            public_key: None,
            fingerprint: None,
            key_type: None,
            has_passphrase: None,
        }),
    };
    let known = Known { rows: vec![slot] }
        .normalize_legacy(&mut state, Some(&files))
        .unwrap();
    let keys = crate::sync::central::crypto::VaultKeys::generate().unwrap();
    let materials = Materials::from_files_with_key_inputs(
        &state,
        &keys,
        &files,
        &MemKeychain::default(),
        &BTreeMap::new(),
        known.key_inputs().unwrap(),
    )
    .unwrap();
    assert!(materials.active.contains_key(&id));
    let history = crate::sync::central::migration_library::prepare(&state, &known, materials)
        .unwrap()
        .into_rows();
    assert!(history.iter().any(|(i, data)| i.kind == "key"
        && i.id == id
        && matches!(data, Data::Key(private) if private.private() == raw)));
    assert!(files
        .bytes
        .values()
        .any(|bytes| bytes.as_slice() == raw.as_bytes()));
}
