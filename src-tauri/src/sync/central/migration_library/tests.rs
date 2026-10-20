use super::*;
use crate::sync::{
    central::{
        migration_history,
        migration_sources::{Inventory, Sources},
    },
    crypto::ChainKeys,
    record_conflicts::{RecordConflict, RecordVersion},
    records_v3::SpaceStateV3,
    testkit::MemKeychain,
};
use crate::vault::store;
use serde_json::json;
fn fixture() -> (SyncStateV3, Known, Materials) {
    fixture_with_tunnels(false)
}
fn fixture_with_tunnels(tunnels: bool) -> (SyncStateV3, Known, Materials) {
    let (owner, keys, _) = migration_history::tests::initial();
    let parent = ChainKeys::generate().unwrap();
    let child = ChainKeys::generate().unwrap();
    let mut state:SyncStateV3=serde_json::from_value(json!({"version":8,"device_id":"d".repeat(32),"device_name":"Synthetic","relay_url":owner.control.profile.origin,"last_sync_ms":null,"last_error":null})).unwrap();
    state.local.central = Some(owner);
    let mut account = AccountState::new(&parent.chain_id);
    let secret = crate::sync::state_v2::SealedRecord::seal(
        &parent,
        &Record {
            kind: RecordKind::SpaceKey,
            id: child.chain_id.clone(),
            version: 1,
            updated_at_ms: 1,
            device_id: state.device_id.clone(),
            deleted: false,
            payload: serde_json::to_value(crate::sync::record::SpaceKeyPayload::from_keys(
                &child,
            ))
            .unwrap(),
        },
        1,
    )
    .unwrap();
    account.sealed.insert(secret.key(), secret);
    account.records.insert(
        record_key(RecordKind::Space, &child.chain_id),
        row(
            RecordKind::Space,
            &child.chain_id,
            json!({"schema":1,"name":"unselected","slug":"retained","created_at_ms":1}),
            1,
        ),
    );
    let local = row(
        RecordKind::Host,
        "1111111111111111",
        json!({"schema":2,"alias":"local","hostname":"fixture.invalid","auth":"password"}),
        2,
    );
    state
        .local
        .hosts
        .insert(record_key(local.record.kind, &local.record.id), local);
    let mut shared = SpaceStateV3 {
        selected: false,
        missing: false,
        ..Default::default()
    };
    let host = row(
        RecordKind::Host,
        "2222222222222222",
        json!({"schema":2,"alias":"current","hostname":"fixture.invalid","auth":"password"}),
        3,
    );
    shared
        .records
        .insert(record_key(host.record.kind, &host.record.id), host.clone());
    let mut old = host;
    old.record.version = 1;
    old.record.payload["alias"] = "retained".into();
    shared.recovery.bases.insert(
        record_key(old.record.kind, &old.record.id),
        RecordVersion::Public(old),
    );
    state.spaces.insert(child.chain_id, shared);
    state.account = Some(account);
    if tunnels {
        let rule = |id: &str, name: &str| json!({"schema":1,"rule":{"id":id,"name":name,"host_id":"1111111111111111","forward":{"kind":"local","bind_address":"127.0.0.1","port":15432,"target_host":"migration-db.internal","target_port":5432}}});
        let local = row(
            RecordKind::Meta,
            "tunnel:3333333333333333",
            rule("3333333333333333", "Current tunnel"),
            2,
        );
        state
            .local
            .tunnel_rules
            .insert(record_key(RecordKind::Meta, &local.record.id), local);
        let prior = row(
            RecordKind::Meta,
            "tunnel:4444444444444444",
            rule("4444444444444444", "Historical tunnel"),
            1,
        );
        let mut deleted = prior.clone();
        deleted.record.version = 2;
        deleted.record.deleted = true;
        deleted.record.payload = serde_json::Value::Null;
        let account = state.account.as_mut().unwrap();
        let key = record_key(RecordKind::Meta, &prior.record.id);
        account.records.insert(key.clone(), deleted);
        account
            .recovery
            .bases
            .insert(key, RecordVersion::Public(prior));
    }
    let sources = Sources::discover(&state, Some(&parent)).unwrap();
    let known = Inventory::from_state(&sources, &state)
        .unwrap()
        .admit_known()
        .unwrap();
    let memory = MemKeychain::default();
    let read = store::read_vault_image(br#"{"version":1,"entries":{}}"#, &memory).unwrap();
    let materials = Materials::from_vault(&state, &keys, &read, &BTreeMap::new()).unwrap();
    (state, known, materials)
}
fn row(kind: RecordKind, id: &str, payload: serde_json::Value, version: u64) -> LocalRecord {
    LocalRecord {
        record: Record {
            kind,
            id: id.into(),
            version,
            updated_at_ms: version,
            device_id: "d".repeat(32),
            deleted: false,
            payload,
        },
        seq: version,
        dirty: false,
    }
}
#[test]
fn local_unselected_and_retained_structured_values_are_preserved_and_current_values_come_last() {
    let (state, known, materials) = fixture();
    let before = serde_json::to_vec(&state).unwrap();
    let rows = prepare(&state, &known, materials).unwrap().into_rows();
    let aliases: Vec<_> = rows
        .iter()
        .filter_map(|(_, data)| match data {
            Data::Host(host) => Some(host.alias.as_str()),
            _ => None,
        })
        .collect();
    assert!(aliases.contains(&"retained"));
    assert!(aliases.contains(&"local"));
    assert_eq!(aliases.last(), Some(&"current"));
    assert!(rows.iter().any(|(_,data)|matches!(data,Data::Catalog(catalog)if catalog.collections.iter().any(|c|c.name=="unselected"))));
    assert_eq!(serde_json::to_vec(&state).unwrap(), before);
}
#[test]
fn missing_collections_or_unresolved_source_conflicts_never_return_a_partial_history() {
    for conflict in [false, true] {
        let (mut state, known, materials) = fixture();
        let space = state.spaces.values_mut().next().unwrap();
        if conflict {
            let local = space.records.values().next().unwrap().clone();
            let key = record_key(local.record.kind, &local.record.id);
            space.recovery.conflicts.insert(
                key,
                vec![RecordConflict {
                    base: None,
                    local: RecordVersion::Public(local.clone()),
                    remote: RecordVersion::Public(local),
                }],
            );
        } else {
            space.missing = true;
        }
        assert!(prepare(&state, &known, materials).is_err());
    }
}

#[test]
fn an_archived_source_material_candidate_preserves_original_encryption_and_passes_history_encryption_validation(
) {
    use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
    let (_device, package, keys, owner, original) =
        crate::sync::central::source_package::tests::fixture();
    let before = package.encode_local().unwrap();
    let rows = package
        .structured_history(&keys, &BTreeMap::new())
        .unwrap()
        .into_rows();
    assert!(rows
        .iter()
        .any(|(_, value)| matches!(value,Data::Key(private) if private.private()==original)));
    let signer = crypto::DeviceKeys::decode_secret(&B64.encode([1u8; 64])).unwrap();
    let encrypted = migration_history::prepare(
        &owner,
        &keys,
        &signer,
        migration_history::Context {
            operation: "7".repeat(32),
            inventory_digest: "9".repeat(64),
            sources: vec![],
        },
        &rows,
    )
    .unwrap();
    assert_eq!(encrypted.rows.len(), rows.len());
    assert!(!encrypted.rows.is_empty());
    assert!(package.encode_local().unwrap().as_slice() == before.as_slice());
}
#[test]
fn mutating_a_package_state_without_its_captured_image_cannot_create_record_inputs_or_history() {
    let (_device, mut package, keys, _, _) = crate::sync::central::source_package::tests::fixture();
    package.state.device_name = "not the archived state".into();
    assert!(package.record_inputs().is_err());
    assert!(package.structured_history(&keys, &BTreeMap::new()).is_err());
}

#[test]
fn final_key_metadata_and_container_use_current_material_after_retained_names_and_same_key_variants(
) {
    use crate::sync::records_v3::{KeySlotPayload, LocalKeyMetadata};
    let (device, package, keys, _, original) =
        crate::sync::central::source_package::tests::fixture();
    let mut state = package.state.clone();
    let id = "1".repeat(32);
    let parsed = crate::vault::material::parse(&original).unwrap();
    let public = KeySlotPayload {
        schema: 2,
        name: "current_name".into(),
        public_key: parsed.public_key().to_openssh().unwrap(),
        fingerprint: parsed
            .public_key()
            .fingerprint(ssh_key::HashAlg::Sha256)
            .to_string(),
        key_type: parsed.public_key().algorithm().as_str().into(),
        has_passphrase: true,
        created_at_ms: 1,
        origin_device_id: state.device_id.clone(),
    };
    state.local.keys.insert(
        id.clone(),
        LocalKeyMetadata {
            vault_id: id.clone(),
            public: public.clone(),
        },
    );
    let mut old = public.clone();
    old.name = "retained_name".into();
    state.account.as_mut().unwrap().recovery.bases.insert(
        record_key(RecordKind::KeySlot, &id),
        RecordVersion::Public(row(
            RecordKind::KeySlot,
            &id,
            serde_json::to_value(&old).unwrap(),
            1,
        )),
    );
    let alternate = original.replace('\n', "\r\n");
    let vault_path = store::vault_path(&device.env().state_path);
    let mut vault = store::Vault::open(&vault_path, &device.keychain, 0).unwrap();
    vault
        .put(
            &device.keychain,
            &id,
            &store::VaultEntry {
                private_key: original.clone(),
                public_key: public.public_key.clone(),
                fingerprint: public.fingerprint.clone(),
                origin: store::EntryOrigin::Imported,
                added_at_ms: 1,
            },
        )
        .unwrap();
    vault
        .put(
            &device.keychain,
            "retained_variant",
            &store::VaultEntry {
                private_key: alternate.clone(),
                public_key: public.public_key.clone(),
                fingerprint: public.fingerprint.clone(),
                origin: store::EntryOrigin::Imported,
                added_at_ms: 0,
            },
        )
        .unwrap();
    let before = std::fs::read(&vault_path).unwrap();
    let read = store::read_vault(&vault_path, &device.keychain).unwrap();
    let materials = Materials::from_vault(&state, &keys, &read, &BTreeMap::new()).unwrap();
    let known = Inventory::from_state(&package.sources, &state)
        .unwrap()
        .admit_known()
        .unwrap();
    let rows = prepare(&state, &known, materials).unwrap().into_rows();
    let final_public = rows
        .iter()
        .rev()
        .find_map(|(identity, data)| match data {
            Data::Keyslot(slot) if identity.id == id => Some(slot),
            _ => None,
        })
        .unwrap();
    assert_eq!(final_public.public, public);
    let final_private = rows
        .iter()
        .rev()
        .find_map(|(identity, data)| match data {
            Data::Key(private) if identity.id == id => Some(private),
            _ => None,
        })
        .unwrap();
    assert!(final_private.private() == original);
    final_private.validate_against(&id, final_public).unwrap();
    assert!(rows
        .iter()
        .any(|(_, data)| matches!(data,Data::Keyslot(slot)if slot.public.name=="retained_name")));
    assert!(rows
        .iter()
        .any(|(_, data)| matches!(data,Data::Key(private)if private.private()==alternate)));
    assert_eq!(std::fs::read(&vault_path).unwrap(), before);
}

#[test]
fn a_known_null_navigation_tombstone_remains_an_explicit_empty_order() {
    let (_device, package, keys, _, _) = crate::sync::central::source_package::tests::fixture();
    let mut state = package.state.clone();
    let mut deleted = row(
        RecordKind::Meta,
        crate::sync::group_order::RECORD_ID,
        serde_json::Value::Null,
        1,
    );
    deleted.record.deleted = true;
    state.account.as_mut().unwrap().records.insert(
        record_key(RecordKind::Meta, crate::sync::group_order::RECORD_ID),
        deleted,
    );
    let known = Inventory::from_state(&package.sources, &state)
        .unwrap()
        .admit_known()
        .unwrap();
    let memory = MemKeychain::default();
    let read = store::read_vault_image(br#"{"version":1,"entries":{}}"#, &memory).unwrap();
    let materials = Materials::from_vault(&state, &keys, &read, &BTreeMap::new()).unwrap();
    let rows = prepare(&state, &known, materials).unwrap().into_rows();
    let final_catalog = rows
        .iter()
        .rev()
        .find_map(|(_, data)| match data {
            Data::Catalog(value) => Some(value),
            _ => None,
        })
        .unwrap();
    assert!(final_catalog
        .group_orders
        .iter()
        .any(|order| order.scope == HostScope::Local && order.ids.is_empty()));
}
#[test]
fn current_legacy_text_is_not_silently_treated_as_a_complete_structured_source() {
    let (owner, keys, _) = migration_history::tests::initial();
    let parent = ChainKeys::generate().unwrap();
    let child = ChainKeys::generate().unwrap();
    let mut state:SyncStateV3=serde_json::from_value(json!({"version":8,"device_id":"d".repeat(32),"device_name":"Synthetic","relay_url":owner.control.profile.origin,"last_sync_ms":null,"last_error":null})).unwrap();
    state.local.central = Some(owner);
    let mut account = AccountState::new(&parent.chain_id);
    let secret = crate::sync::state_v2::SealedRecord::seal(
        &parent,
        &Record {
            kind: RecordKind::SpaceKey,
            id: child.chain_id.clone(),
            version: 1,
            updated_at_ms: 1,
            device_id: state.device_id.clone(),
            deleted: false,
            payload: serde_json::to_value(crate::sync::record::SpaceKeyPayload::from_keys(&child))
                .unwrap(),
        },
        1,
    )
    .unwrap();
    account.sealed.insert(secret.key(), secret);
    account.records.insert(
        record_key(RecordKind::Space, &child.chain_id),
        row(
            RecordKind::Space,
            &child.chain_id,
            json!({"schema":1,"name":"legacy","slug":"legacy","created_at_ms":1}),
            1,
        ),
    );
    state.account = Some(account);
    let host = crate::sync::state_v2::SealedRecord::seal(
        &child,
        &Record {
            kind: RecordKind::Host,
            id: "legacy_alias".into(),
            version: 1,
            updated_at_ms: 1,
            device_id: state.device_id.clone(),
            deleted: false,
            payload: json!({"schema":1,"text":"Host legacy_alias\n  HostName fixture.invalid\n"}),
        },
        1,
    )
    .unwrap();
    let mut space = SpaceStateV3::default();
    space.sealed.insert(host.key(), host);
    state.spaces.insert(child.chain_id, space);
    let sources = Sources::discover(&state, Some(&parent)).unwrap();
    let known = Inventory::from_state(&sources, &state)
        .unwrap()
        .admit_known()
        .unwrap();
    let memory = MemKeychain::default();
    let read = store::read_vault_image(br#"{"version":1,"entries":{}}"#, &memory).unwrap();
    let materials = Materials::from_vault(&state, &keys, &read, &BTreeMap::new()).unwrap();
    assert!(prepare(&state, &known, materials).is_err());
}

#[test]
fn retained_only_hosts_and_key_metadata_cannot_reappear_as_current_after_migration() {
    use crate::sync::{
        central::{inventory_keys::Capture, migration_files::Files, source_package::Package},
        record_conflicts::RecordVersion,
    };
    let (device, package, keys, owner, raw) =
        crate::sync::central::source_package::tests::fixture();
    let mut state = package.state.clone();
    let key_id = "3".repeat(32);
    let host_id = "3333333333333333";
    let parsed = crate::vault::material::parse(&raw).unwrap();
    let slot = crate::sync::records_v3::KeySlotPayload {
        schema: 2,
        name: "retained_only".into(),
        public_key: parsed.public_key().to_openssh().unwrap(),
        fingerprint: parsed
            .public_key()
            .fingerprint(ssh_key::HashAlg::Sha256)
            .to_string(),
        key_type: parsed.public_key().algorithm().as_str().into(),
        has_passphrase: true,
        created_at_ms: 1,
        origin_device_id: state.device_id.clone(),
    };
    state.account.as_mut().unwrap().recovery.bases.insert(
        record_key(RecordKind::KeySlot, &key_id),
        RecordVersion::Public(row(
            RecordKind::KeySlot,
            &key_id,
            serde_json::to_value(slot).unwrap(),
            1,
        )),
    );
    let old = row(
        RecordKind::Host,
        host_id,
        json!({"schema":2,"alias":"retained_only","hostname":"fixture.invalid","auth":"password"}),
        1,
    );
    let child = ChainKeys::generate().unwrap();
    // Keep the retained host scoped to a known unselected collection.
    state.account.as_mut().unwrap().records.insert(
        record_key(RecordKind::Space, &child.chain_id),
        row(
            RecordKind::Space,
            &child.chain_id,
            json!({"schema":1,"name":"Unselected","slug":"unselected","created_at_ms":1}),
            1,
        ),
    );
    let mut space = SpaceStateV3::default();
    space.recovery.bases.insert(
        record_key(RecordKind::Host, host_id),
        RecordVersion::Public(old),
    );
    let group_id = "4444444444444444";
    space.recovery.bases.insert(
        record_key(RecordKind::Group, group_id),
        RecordVersion::Public(row(
            RecordKind::Group,
            group_id,
            json!({"schema":1,"name":"retained_only_group"}),
            1,
        )),
    );
    state.spaces.insert(child.chain_id.clone(), space);
    let original_book = package.sources.encode_local().unwrap();
    let parent_value: serde_json::Value = serde_json::from_slice(&original_book).unwrap();
    let parent = &parent_value["keys"][0];
    let parent_key = ChainKeys::from_parts(
        parent["chain_id"].as_str().unwrap(),
        parent["auth_token"].as_str().unwrap(),
        parent["encryption_key"].as_str().unwrap(),
    )
    .unwrap();
    let secret = crate::sync::state_v2::SealedRecord::seal(
        &parent_key,
        &Record {
            kind: RecordKind::SpaceKey,
            id: child.chain_id.clone(),
            version: 1,
            updated_at_ms: 1,
            device_id: state.device_id.clone(),
            deleted: false,
            payload: serde_json::to_value(crate::sync::record::SpaceKeyPayload::from_keys(&child))
                .unwrap(),
        },
        0,
    )
    .unwrap();
    state
        .account
        .as_mut()
        .unwrap()
        .sealed
        .insert(secret.key(), secret);
    let env = device.env();
    std::fs::write(&env.state_path, serde_json::to_vec(&state).unwrap()).unwrap();
    let files = Files::capture(&env, None).unwrap();
    let observer = Capture::new(&device.keychain);
    Materials::from_files(&state, &keys, &files, &observer, &BTreeMap::new()).unwrap();
    let package = Package::assemble(
        &state,
        env.state_path.file_name().unwrap().to_str().unwrap(),
        files,
        Sources::discover(&state, Some(&parent_key)).unwrap(),
        observer.finish().unwrap(),
    )
    .unwrap();
    let history = package
        .structured_history(&keys, &BTreeMap::new())
        .unwrap()
        .into_rows();
    for (kind, id) in [
        ("host", host_id),
        ("group", group_id),
        ("keyslot", key_id.as_str()),
        ("key", key_id.as_str()),
    ] {
        let last = history
            .iter()
            .rev()
            .find(|(identity, _)| identity.kind == kind && identity.id == id)
            .unwrap();
        assert!(
            matches!(last.1, Data::Deleted),
            "retained-only {kind} became current"
        );
    }
    assert!(history
        .iter()
        .any(|(_, data)| matches!(data,Data::Key(private)if private.private()==raw)));
    let (_, _, signer) = migration_history::tests::initial();
    migration_history::prepare(
        &owner,
        &keys,
        &signer,
        migration_history::Context {
            operation: "7".repeat(32),
            inventory_digest: "9".repeat(64),
            sources: vec![],
        },
        &history,
    )
    .unwrap();
}

#[test]
fn migration_retains_local_tunnels_and_deleted_tunnel_history_without_reactivating_it() {
    let (state, known, materials) = fixture_with_tunnels(true);
    let before = serde_json::to_vec(&state).unwrap();
    let rows = prepare(&state, &known, materials).unwrap().into_rows();
    let catalogs: Vec<_> = rows
        .iter()
        .filter_map(|(_, d)| {
            if let Data::Catalog(c) = d {
                Some(c)
            } else {
                None
            }
        })
        .collect();
    assert!(catalogs
        .iter()
        .any(|c| c.tunnels.iter().any(|r| r.name == "Historical tunnel")));
    let current = catalogs.last().unwrap();
    assert_eq!(current.tunnels.len(), 1);
    assert_eq!(current.tunnels[0].name, "Current tunnel");
    assert_eq!(serde_json::to_vec(&state).unwrap(), before);
}
