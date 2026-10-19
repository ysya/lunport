use super::*;
use crate::sync::{
    central::{
        migration::legacy_checkpoint,
        migration_freeze::{Phase, Progress, ProofStep},
        migration_history,
        migration_sources::{Position, Scope},
        payload::{Data, Identity},
    },
    record::{record_key, LocalRecord, Record, RecordKind},
    relay::PullResponse,
    testkit::TestDevice,
};
fn replace(device: &TestDevice, mut package: Package, bytes: &[u8]) -> Package {
    std::fs::write(
        device
            .env()
            .state_path
            .parent()
            .unwrap()
            .join("sync-state.retained"),
        bytes,
    )
    .unwrap();
    package.files = Files::capture(&device.env(), None).unwrap();
    package
}
fn image(package: &Package) -> SyncStateV3 {
    serde_json::from_slice(&package.files.bytes[Path::new("data/sync-state.retained")]).unwrap()
}
fn host(id: &str, alias: &str) -> LocalRecord {
    LocalRecord {
        record: Record {
            kind: RecordKind::Host,
            id: id.into(),
            version: 1,
            updated_at_ms: 10,
            device_id: "d".repeat(32),
            deleted: false,
            payload: serde_json::json!({"schema":2,"alias":alias,"hostname":"retained.invalid","auth":"password"}),
        },
        seq: 0,
        dirty: true,
    }
}
fn freeze(package: Package, owner: &Workspace, operation: &str) -> Result<Package, AppError> {
    let (_, _, signer) = migration_history::tests::initial();
    let intent = package
        .sources
        .intent(owner, &signer, &operation, &"8".repeat(64), None)?;
    let parent = &package.state.account.as_ref().unwrap().chain_id;
    let progress = Progress {
        proof: vec![ProofStep {
            digest: intent.digest()?,
            intent,
        }],
        sources: vec![legacy_checkpoint(parent, 0, &[])?],
        phase: Phase::Frozen,
        next: vec![],
    };
    let snapshot = package.sources.admit_frozen(
        owner,
        &operation,
        &progress,
        None,
        parent,
        PullResponse {
            records: vec![],
            latest_seq: 0,
        },
    )?;
    package.with_frozen(&operation, &progress, None, vec![snapshot])
}
#[test]
fn unique_historical_host_survives_real_archival_restore_and_never_becomes_current() {
    let (device, package, keys, owner, _) = super::tests::fixture();
    let id = "1111111111111111";
    let mut retained = image(&package);
    retained.local.hosts.insert(
        record_key(RecordKind::Host, id),
        host(id, "only-in-old-image"),
    );
    let package = replace(&device, package, &serde_json::to_vec(&retained).unwrap());
    let rows = package.record_inputs().unwrap();
    assert_eq!(rows.rows().len(), 1);
    assert!(rows.rows()[0].location.position == Position::Retained);
    assert!(rows.rows()[0].location.scope == Scope::Local);
    let env = device.env();
    let life = env.runtime.lifecycle.lock().unwrap();
    let archive = package.archive(&env, &life, &owner, 0).unwrap();
    let restored = Package::restore(
        &env,
        &owner.control.profile.profile().unwrap(),
        archive.receipt(),
    )
    .unwrap();
    let restored = freeze(restored, &owner, archive.receipt().operation()).unwrap();
    let context = restored.migration_context(archive.receipt()).unwrap();
    let rows = restored
        .structured_history(&keys, &BTreeMap::new())
        .unwrap()
        .into_rows();
    assert!(rows.iter().any(|(i, data)| i.kind == "host"
        && i.id == id
        && matches!(data, Data::Host(value) if value.alias == "only-in-old-image")));
    assert!(matches!(
        rows.iter()
            .rev()
            .find(|(i, _)| i.kind == "host" && i.id == id)
            .unwrap()
            .1,
        Data::Deleted
    ));
    let (_, _, signer) = migration_history::tests::initial();
    let plan = migration_history::prepare(&owner, &keys, &signer, context, &rows).unwrap();
    assert!(!plan.before().control.cutover);
    assert!(restored.state.local.hosts.is_empty());
}
#[test]
fn opaque_unsupported_foreign_or_unknown_state_images_block_semantic_inventory() {
    for case in [
        "opaque",
        "schema",
        "unknown-field",
        "parent",
        "origin",
        "central-outbox",
        "missing-backup",
        "uncovered-backup",
    ] {
        let (device, package, keys, _, _) = super::tests::fixture();
        let mut retained = image(&package);
        let mut value = serde_json::to_value(&retained).unwrap();
        match case {
            "schema" => value["version"] = 999.into(),
            "unknown-field" => value["unreviewed_secret"] = "SECRET-SENTINEL".into(),
            "parent" => value["account"]["chain_id"] = "f".repeat(64).into(),
            "origin" => value["relay_url"] = "https://other.invalid".into(),
            "missing-backup" => value["legacy_v1_backup"] = "old-backup-only-in-retained-state".into(),
            "uncovered-backup" => value["legacy_v1_backup"] = "vault.json".into(),
            "central-outbox" => {
                retained.version = records_v3::CENTRAL_STATE_VERSION;
                retained.local.central = package.state.local.central.clone();
                retained.local.central.as_mut().unwrap().identity_slot = Some("c".repeat(32));
                value = serde_json::to_value(retained).unwrap();
            }
            _ => {}
        }
        let bytes = if case == "opaque" {
            vec![0, 255, 0]
        } else {
            serde_json::to_vec(&value).unwrap()
        };
        let package = replace(&device, package, &bytes);
        assert!(package.record_inputs().is_err(), "{case}");
        assert!(
            package.structured_history(&keys, &BTreeMap::new()).is_err(),
            "{case}"
        );
        assert_eq!(
            package.files.bytes[Path::new("data/sync-state.retained")].as_slice(),
            bytes.as_slice()
        );
    }
}
#[test]
fn a_historical_clean_cursor_above_the_frozen_source_blocks_completion() {
    let (device, package, _, owner, _) = super::tests::fixture();
    let mut retained = image(&package);
    retained.account.as_mut().unwrap().cursor_seq = 1;
    let package = replace(&device, package, &serde_json::to_vec(&retained).unwrap());
    assert!(package.record_inputs().is_ok());
    assert!(freeze(package, &owner, &"7".repeat(32)).is_err());
}
#[test]
fn a_historical_copy_cannot_replace_a_different_current_host_or_vote_in_reconciliation() {
    let (device, package, keys, owner, _) = super::tests::fixture();
    let id = "1111111111111111";
    let mut retained = image(&package);
    retained
        .local
        .hosts
        .insert(record_key(RecordKind::Host, id), host(id, "old-A"));
    let mut package = replace(&device, package, &serde_json::to_vec(&retained).unwrap());
    package
        .state
        .local
        .hosts
        .insert(record_key(RecordKind::Host, id), host(id, "current-B"));
    std::fs::write(
        &device.env().state_path,
        serde_json::to_vec(&package.state).unwrap(),
    )
    .unwrap();
    package.files = Files::capture(&device.env(), None).unwrap();
    let package = freeze(package, &owner, &"7".repeat(32)).unwrap();
    let rows = package
        .structured_history(&keys, &BTreeMap::new())
        .unwrap()
        .into_rows();
    let identity = Identity {
        kind: "host".into(),
        id: id.into(),
        scope: Some(records_v3::HostScope::Local),
    };
    assert!(rows
        .iter()
        .any(|(i, value)| i == &identity
            && matches!(value, Data::Host(host) if host.alias == "old-A")));
    assert!(
        matches!(&rows.iter().rev().find(|(i, _)| i == &identity).unwrap().1, Data::Host(host) if host.alias == "current-B")
    );
}

fn old_local_key(package: &Package, raw: &str, physical: &str) -> SyncStateV3 {
    let mut retained = image(package);
    let parsed = crate::vault::material::parse(raw).unwrap();
    retained.local.keys.insert(
        "1".repeat(32),
        records_v3::LocalKeyMetadata {
            vault_id: physical.into(),
            public: records_v3::KeySlotPayload {
                schema: records_v3::KEYSLOT_SCHEMA,
                name: "Retained local-only label".into(),
                public_key: parsed.public_key().to_openssh().unwrap(),
                fingerprint: parsed
                    .public_key()
                    .fingerprint(ssh_key::HashAlg::Sha256)
                    .to_string(),
                key_type: parsed.public_key().algorithm().as_str().into(),
                has_passphrase: parsed.is_encrypted(),
                created_at_ms: 1,
                origin_device_id: retained.device_id.clone(),
            },
        },
    );
    retained
}
#[test]
fn old_local_only_key_labels_and_original_encrypted_bytes_survive_as_inactive_history() {
    let (device, package, keys, _, raw) = super::tests::fixture();
    let retained = old_local_key(&package, &raw, &"3".repeat(32));
    let package = replace(&device, package, &serde_json::to_vec(&retained).unwrap());
    let materials = package.materials(&keys, &BTreeMap::new()).unwrap();
    assert!(!materials.active.contains_key(&"1".repeat(32)));
    let rows = package
        .structured_history(&keys, &BTreeMap::new())
        .unwrap()
        .into_rows();
    assert!(rows.iter().any(|(identity, data)| identity.id == "1".repeat(32) && matches!(data, Data::Keyslot(slot) if slot.public.name == "Retained local-only label" && slot.public.has_passphrase)));
    assert!(rows
        .iter()
        .any(|(identity, data)| identity.id == "1".repeat(32)
            && matches!(data, Data::Key(private) if private.private() == raw)));
    for kind in ["keyslot", "key"] {
        assert!(matches!(
            rows.iter()
                .rev()
                .find(|(identity, _)| identity.id == "1".repeat(32) && identity.kind == kind)
                .unwrap()
                .1,
            Data::Deleted
        ));
    }
    assert!(package.state.local.keys.is_empty());
}
#[test]
fn missing_or_inconsistent_old_local_key_pointers_block_material_and_history_admission() {
    for case in ["missing", "passphrase-mismatch"] {
        let (device, package, keys, _, raw) = super::tests::fixture();
        let mut retained = old_local_key(
            &package,
            &raw,
            &if case == "missing" {
                "9".repeat(32)
            } else {
                "3".repeat(32)
            },
        );
        if case == "passphrase-mismatch" {
            retained
                .local
                .keys
                .get_mut(&"1".repeat(32))
                .unwrap()
                .public
                .has_passphrase = false;
        }
        let package = replace(&device, package, &serde_json::to_vec(&retained).unwrap());
        assert!(
            package.materials(&keys, &BTreeMap::new()).is_err(),
            "{case}"
        );
        assert!(
            package.structured_history(&keys, &BTreeMap::new()).is_err(),
            "{case}"
        );
    }
}

#[test]
fn different_historical_material_with_the_same_logical_key_id_never_replaces_current_material() {
    use crate::vault::{
        material,
        store::{self, EntryOrigin, Vault, VaultEntry},
    };
    let (device, package, keys, _, old_raw) = super::tests::fixture();
    let retained = old_local_key(&package, &old_raw, &"3".repeat(32));
    let mut package = replace(&device, package, &serde_json::to_vec(&retained).unwrap());
    let new_raw = crate::sync::slot_rules::test_keys::plain();
    let current = old_local_key(&package, &new_raw, &"4".repeat(32));
    package.state.local.keys = current.local.keys;
    package
        .state
        .local
        .keys
        .get_mut(&"1".repeat(32))
        .unwrap()
        .public
        .name = "Current new key".into();
    let env = device.env();
    std::fs::write(&env.state_path, serde_json::to_vec(&package.state).unwrap()).unwrap();
    let parsed = material::parse(&new_raw).unwrap();
    Vault::open(&store::vault_path(&env.state_path), &device.keychain, 100)
        .unwrap()
        .put(
            &device.keychain,
            &"4".repeat(32),
            &VaultEntry {
                private_key: new_raw.clone(),
                public_key: parsed.public_key().to_openssh().unwrap(),
                fingerprint: parsed
                    .public_key()
                    .fingerprint(ssh_key::HashAlg::Sha256)
                    .to_string(),
                origin: EntryOrigin::Imported,
                added_at_ms: 100,
            },
        )
        .unwrap();
    package.files = Files::capture(&env, None).unwrap();
    let rows = package
        .structured_history(&keys, &BTreeMap::new())
        .unwrap()
        .into_rows();
    assert!(rows
        .iter()
        .any(|(identity, data)| identity.id == "1".repeat(32)
            && matches!(data, Data::Key(private) if private.private() == old_raw)));
    assert!(
        matches!(&rows.iter().rev().find(|(identity, _)| identity.id == "1".repeat(32) && identity.kind == "key").unwrap().1, Data::Key(private) if private.private() == new_raw)
    );
    assert!(
        matches!(&rows.iter().rev().find(|(identity, _)| identity.id == "1".repeat(32) && identity.kind == "keyslot").unwrap().1, Data::Keyslot(slot) if slot.public.name == "Current new key")
    );
}

#[test]
fn completed_import_snapshots_join_package_history_without_resurrecting_later_removals() {
    use crate::sync::{record_import, record_runtime, records_v3::importer::ImportOptions};
    let (device, package, keys, _, _) = super::tests::fixture();
    let env = device.env();
    record_runtime::activate_probe(
        &mut device.runtime.core.lock().unwrap(),
        record_runtime::probe_startup(&env.state_path, "import-history"),
    )
    .unwrap();
    let source = device.home.path().join("historical-import");
    let private = device.home.path().join("historical-private");
    std::fs::write(&private, crate::sync::slot_rules::test_keys::encrypted()).unwrap();
    std::fs::write(
        &source,
        format!(
            "Host retained-import
 HostName retained-import.invalid
 IdentityFile {}
",
            private.display()
        ),
    )
    .unwrap();
    let mut prepared =
        record_import::prepare(&source, &ImportOptions::new(device.home.path().into())).unwrap();
    let key = prepared.preview().key_references[0].key_id.clone();
    record_import::select_key_copy(&mut prepared, &key).unwrap();
    let receipt = record_import::confirm(&env, prepared).unwrap();
    let host_id = receipt.host_ids[0].clone();
    record_runtime::mutate_records(&env, |state| {
        let mut next = state.clone();
        next.local
            .hosts
            .remove(&record_key(RecordKind::Host, &host_id));
        next.local.keys.remove(&key);
        if let Some(row) = next
            .account
            .as_mut()
            .and_then(|a| a.records.get_mut(&record_key(RecordKind::KeySlot, &key)))
        {
            row.record.deleted = true;
            row.record.payload = serde_json::Value::Null;
            row.record.version += 1;
            row.record.updated_at_ms += 1;
            row.dirty = true;
        }
        Ok(next)
    })
    .unwrap();
    let selected = record_runtime::snapshot(&env).unwrap().0;
    let package = Package::assemble(
        &selected,
        &package.state_name,
        Files::capture(&env, None).unwrap(),
        package.sources,
        package.decryptors,
    )
    .unwrap();
    let history = package
        .structured_history(&keys, &BTreeMap::new())
        .unwrap()
        .into_rows();
    assert!(history
        .iter()
        .any(|(identity, data)| identity.kind == "host"
            && identity.id == host_id
            && matches!(data, Data::Host(host) if host.alias == "retained-import")));
    assert!(matches!(
        history
            .iter()
            .rev()
            .find(|(identity, _)| identity.kind == "host" && identity.id == host_id)
            .unwrap()
            .1,
        Data::Deleted
    ));
    assert!(history
        .iter()
        .any(|(identity, data)| identity.id == key && matches!(data, Data::Key(_))));
    assert!(matches!(
        history
            .iter()
            .rev()
            .find(|(identity, _)| identity.kind == "keyslot" && identity.id == key)
            .unwrap()
            .1,
        Data::Deleted
    ));
    assert!(!package
        .state
        .local
        .hosts
        .contains_key(&record_key(RecordKind::Host, &host_id)));
    assert!(!package.state.local.keys.contains_key(&key));
}
#[test]
fn v1_and_v2_backups_convert_hosts_after_real_archive_restore_without_activating_history() {
    for version in [1, 2] {
        let (device, package, keys, owner, _) = super::tests::fixture();
        let parent = package.state.account.as_ref().unwrap().chain_id.clone();
        let mut row = host("old-alias", "unused");
        row.record.payload = serde_json::json!({"schema":1,"text":"Host old-alias\n  HostName legacy.invalid\n  PreferredAuthentications password,keyboard-interactive\n"});
        let bytes = if version == 1 {
            serde_json::to_vec(&serde_json::json!({"version":1,"chain_id":parent,"device_id":"d".repeat(32),"device_name":"Old","relay_url":package.state.relay_url,"cursor_seq":0,"password_sync":false,"records":{"host:old-alias":row},"sealed":{},"last_sync_ms":null,"last_error":null})).unwrap()
        } else {
            let mut old = crate::sync::state_v2::SyncStateV2::fresh("Old").unwrap();
            old.relay_url = package.state.relay_url.clone();
            old.account = Some(crate::sync::state_v2::AccountState::new(&parent));
            let mut space = crate::sync::state_v2::SpaceState::new("old");
            space.records.insert("host:old-alias".into(), row);
            old.spaces.insert(parent.clone(), space);
            serde_json::to_vec(&old).unwrap()
        };
        let package = replace(&device, package, &bytes);
        let env = device.env();
        let life = env.runtime.lifecycle.lock().unwrap();
        let archived = package.archive(&env, &life, &owner, 0).unwrap();
        let restored = Package::restore(
            &env,
            &owner.control.profile.profile().unwrap(),
            archived.receipt(),
        )
        .unwrap();
        let frozen = freeze(restored, &owner, archived.receipt().operation()).unwrap();
        let history = frozen
            .structured_history(&keys, &BTreeMap::new())
            .unwrap()
            .into_rows();
        let id = records_v3::migration_host_id(&parent, "old-alias").unwrap();
        assert!(history.iter().any(|(i, data)| i.kind == "host"
            && i.id == id
            && matches!(data,Data::Host(host) if host.hostname == "legacy.invalid")));
        assert!(matches!(
            history
                .iter()
                .rev()
                .find(|(i, _)| i.kind == "host" && i.id == id)
                .unwrap()
                .1,
            Data::Deleted
        ));
        assert_eq!(
            frozen.files.bytes[Path::new("data/sync-state.retained")].as_slice(),
            bytes
        );
        let (_, _, signer) = migration_history::tests::initial();
        migration_history::prepare(
            &owner,
            &keys,
            &signer,
            frozen.migration_context(archived.receipt()).unwrap(),
            &history,
        )
        .unwrap();
    }
}
#[test]
fn old_backup_unknown_fields_missing_original_keys_and_stronger_floors_block_without_data_loss() {
    for case in ["unknown", "key", "floor"] {
        let (device, package, _, owner, _) = super::tests::fixture();
        let parent = package.state.account.as_ref().unwrap().chain_id.clone();
        let mut value = serde_json::json!({"version":1,"chain_id":parent,"device_id":"d".repeat(32),"device_name":"Old","relay_url":package.state.relay_url,"cursor_seq":0,"password_sync":false,"records":{},"last_sync_ms":null,"last_error":null});
        match case {
            "unknown" => value["unexpected_secret"] = "SOURCE-SENTINEL".into(),
            "key" => value["chain_id"] = "f".repeat(64).into(),
            _ => value["cursor_seq"] = 1.into(),
        }
        let bytes = serde_json::to_vec(&value).unwrap();
        let package = replace(&device, package, &bytes);
        if case == "floor" {
            assert!(freeze(package, &owner, &"1".repeat(32)).is_err());
        } else {
            assert!(package.record_inputs().is_err());
        }
        assert_eq!(
            std::fs::read(
                device
                    .env()
                    .state_path
                    .parent()
                    .unwrap()
                    .join("sync-state.retained")
            )
            .unwrap(),
            bytes
        );
    }
}

#[cfg(test)]
mod completed_migration_evidence {
    use super::*;
    use crate::sync::record_migration::{self, inventory::read_all, MigrationConsent};
    use crate::sync::{
        central::{
            inventory_keys::Snapshot, migration_files::Files, migration_history,
            migration_sources::Sources, payload::Data, source_package::Package,
        },
        fake_relay::FakeRelay,
        record_runtime,
        testkit::{TestClock, TestDevice},
    };
    #[test]
    fn actual_completed_local_migration_evidence_is_read_without_replaying_original_paths() {
        let d=TestDevice::with_main_config("legacy-captured",&FakeRelay::new(),&TestClock::new(),"Host local\n HostName local.test\n PreferredAuthentications password,keyboard-interactive\n");
        {
            let mut core = d.runtime.core.lock().unwrap();
            core.state.as_mut().unwrap().device_id = "a".repeat(32);
            core.legacy_paused = true;
        }
        std::fs::create_dir_all(d.env().state_path.parent().unwrap()).unwrap();
        std::fs::write(
            &d.env().state_path,
            serde_json::to_vec(&d.runtime.core.lock().unwrap().state).unwrap(),
        )
        .unwrap();
        let receipt = record_migration::confirm(
            &d.env(),
            record_migration::prepare(&d.env(), None).unwrap(),
            MigrationConsent {
                old_clients_stopped_or_compatible: true,
            },
        )
        .unwrap();
        assert!(receipt.complete);
        let mut selected = record_runtime::snapshot(&d.env()).unwrap().0;
        let captured = Files::capture(&d.env(), None).unwrap();
        let original_path = d.env().ssh_dir.join("config");
        std::fs::remove_file(&original_path).unwrap();
        assert!(!original_path.exists());
        let images = read_all(&selected, &captured.bytes).unwrap();
        assert_eq!(images.states.len(), 1);
        assert_eq!(images.legacy.len(), 1);
        assert!(images
            .admitted
            .iter()
            .any(|path| path.extension().is_some_and(|v| v == "config")));
        for case in ["pending", "missing", "unknown", "document"] {
            let mut files = captured.bytes.clone();
            let base = Path::new("data/migrations").join(&receipt.migration_id);
            match case {
                "pending" => {
                    let mut value: serde_json::Value =
                        serde_json::from_slice(&files[&base.join("journal.json")]).unwrap();
                    value["phase"] = "publishing".into();
                    files.insert(
                        base.join("journal.json"),
                        Zeroizing::new(serde_json::to_vec(&value).unwrap()),
                    );
                }
                "missing" => {
                    files.remove(&base.join("state.json"));
                }
                "unknown" => {
                    files.insert(
                        base.join("unknown.source"),
                        Zeroizing::new(b"SENTINEL".to_vec()),
                    );
                }
                _ => {
                    let path = files
                        .keys()
                        .find(|path| path.extension().is_some_and(|v| v == "config"))
                        .unwrap()
                        .clone();
                    files.insert(path, Zeroizing::new(b"CHANGED SOURCE".to_vec()));
                }
            }
            assert!(read_all(&selected, &files).is_err(), "{case}");
        }
        let (owner, keys, _) = migration_history::tests::initial();
        selected.version = records_v3::CENTRAL_STATE_VERSION;
        selected.relay_url = owner.control.profile.origin.clone();
        selected.local.central = Some(owner.clone());
        std::fs::write(&d.env().state_path, serde_json::to_vec(&selected).unwrap()).unwrap();
        let package = Package::assemble(
            &selected,
            d.env().state_path.file_name().unwrap().to_str().unwrap(),
            Files::capture(&d.env(), None).unwrap(),
            Sources::discover(&selected, None).unwrap(),
            Snapshot::decode_local(br#"{"version":1,"keys":[]}"#).unwrap(),
        )
        .unwrap();
        let history = package
            .structured_history(&keys, &BTreeMap::new())
            .unwrap()
            .into_rows();
        assert!(history
            .iter()
            .any(|(_, data)| matches!(data,Data::Host(host) if host.hostname=="local.test")));
        let env = d.env();
        let life = env.runtime.lifecycle.lock().unwrap();
        let archive = package.archive(&env, &life, &owner, 0).unwrap();
        let restored = Package::restore(
            &env,
            &owner.control.profile.profile().unwrap(),
            archive.receipt(),
        )
        .unwrap();
        restored
            .structured_history(&keys, &BTreeMap::new())
            .unwrap();
    }
}

#[test]
fn unjoined_v2_own_slots_remain_retained_public_metadata_without_cloud_authority() {
    use crate::sync::{fake_relay::FakeRelay, state_v2, testkit::TestClock};
    let d = TestDevice::new("unjoined-v2-slots", &FakeRelay::new(), &TestClock::new());
    let env = d.env();
    std::fs::create_dir_all(env.state_path.parent().unwrap()).unwrap();
    let (owner, keys, _) = migration_history::tests::initial();
    let selected:SyncStateV3=serde_json::from_value(serde_json::json!({"version":8,"device_id":"d".repeat(32),"device_name":"Synthetic","relay_url":owner.control.profile.origin,"local":{"central":owner},"last_sync_ms":null,"last_error":null})).unwrap();
    std::fs::write(&env.state_path, serde_json::to_vec(&selected).unwrap()).unwrap();
    let id = "1".repeat(32);
    let name = crate::sync::slot_rules::slot_file_name("own", &id);
    let mut old = state_v2::SyncStateV2::fresh("Old unjoined").unwrap();
    old.key_slots.insert(id.clone(),serde_json::from_value(serde_json::json!({"file_name":name,"payload":{"schema":1,"name":"own","mode":"own","origin_device_id":"legacy","created_at_ms":1,"public_key":null,"fingerprint":null,"key_type":null,"has_passphrase":null}})).unwrap());
    std::fs::write(
        env.state_path
            .parent()
            .unwrap()
            .join("sync-state.v2-backup"),
        serde_json::to_vec(&old).unwrap(),
    )
    .unwrap();
    let root = env.ssh_dir.join("sshelter/keys");
    std::fs::create_dir_all(&root).unwrap();
    let raw = crate::sync::slot_rules::test_keys::encrypted();
    std::fs::write(root.join(name), &raw).unwrap();
    let package = Package::assemble(
        &selected,
        env.state_path.file_name().unwrap().to_str().unwrap(),
        Files::capture(&env, None).unwrap(),
        Sources::discover(&selected, None).unwrap(),
        Snapshot::decode_local(br#"{"version":1,"keys":[]}"#).unwrap(),
    )
    .unwrap();
    assert!(package.sources.chains().is_empty());
    let input = package.record_inputs().unwrap();
    assert!(input.rows().iter().all(
        |row| row.location.position == Position::Retained && row.location.scope == Scope::Local
    ));
    let history = package
        .structured_history(&keys, &BTreeMap::new())
        .unwrap()
        .into_rows();
    assert!(history.iter().any(|(identity, data)| identity.kind == "key"
        && identity.id == id
        && matches!(data,Data::Key(private) if private.private()==raw)));
    assert!(matches!(
        history
            .iter()
            .rev()
            .find(|(identity, _)| identity.kind == "keyslot" && identity.id == id)
            .unwrap()
            .1,
        Data::Deleted
    ));
    assert_eq!(
        std::fs::read(root.join(crate::sync::slot_rules::slot_file_name("own", &id))).unwrap(),
        raw.as_bytes()
    );
}
