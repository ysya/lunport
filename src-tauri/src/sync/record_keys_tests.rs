use super::*;
use crate::sync::fake_relay::FakeRelay;
use crate::sync::record_runtime::{probe_startup, RuntimeFormat, StartupProbe};
use crate::sync::slot_rules::test_keys;
use crate::sync::testkit::{TestClock, TestDevice};
use crate::vault::store::{read_vault, vault_path};
use std::fs;
fn device() -> TestDevice {
    let device = TestDevice::new("keyrecord", &FakeRelay::new(), &TestClock::new());
    let StartupProbe::Records { state, .. } = probe_startup(&device.env().state_path, "Key test")
    else {
        panic!("fresh records")
    };
    {
        let mut core = device.runtime.core.lock().unwrap();
        core.state = None;
        core.records = Some(*state);
        core.format = RuntimeFormat::Records;
    }
    device
}
#[test]
fn local_key_import_binds_public_private_and_encryption_identity_without_plaintext_metadata() {
    for text in [test_keys::plain(), test_keys::encrypted()] {
        let device = device();
        let expected = crate::vault::material::parse(&text).unwrap();
        let receipt = import_local(
            &device.env(),
            "work",
            Zeroizing::new(text.clone()),
            EntryOrigin::Imported,
        )
        .unwrap();
        let state = device.runtime.core.lock().unwrap().records.clone().unwrap();
        assert!(state.account.is_none());
        assert!(state.spaces.is_empty());
        assert!(state.local.hosts.is_empty());
        assert_eq!(state.local.keys[&receipt.key_id].public, receipt.public);
        assert_eq!(receipt.public.schema, 2);
        assert_eq!(receipt.public.has_passphrase, expected.is_encrypted());
        assert_eq!(
            crate::vault::material::public_key_data(&receipt.public.public_key).unwrap(),
            *expected.public_key().key_data()
        );
        let vault = read_vault(&vault_path(&device.env().state_path), &device.keychain).unwrap();
        assert_eq!(
            vault.get(&receipt.key_id).unwrap().unwrap().private_key,
            text
        );
        let journal = fs::read_to_string(
            device
                .env()
                .state_path
                .parent()
                .unwrap()
                .join("imports")
                .join(&receipt.import_id)
                .join("journal.json"),
        )
        .unwrap();
        for rendered in [
            journal,
            serde_json::to_string(&state).unwrap(),
            format!("{receipt:?}"),
            format!("{state:?}"),
        ] {
            assert!(!rendered.contains("BEGIN OPENSSH PRIVATE KEY"));
            assert!(!rendered.contains(text.lines().nth(1).unwrap()));
        }
    }
}
#[test]
fn local_generation_seals_material_and_keeps_passphrase_out_of_journals_and_state() {
    let device = device();
    let receipt = generate_local(
        &device.env(),
        "generated",
        KeyAlgorithm::Ed25519,
        "fixture",
        Some(Zeroizing::new("passphrase_PRIVATE_SENTINEL".into())),
    )
    .unwrap();
    let state = device.runtime.core.lock().unwrap().records.clone().unwrap();
    assert!(receipt.public.has_passphrase);
    let vault = read_vault(&vault_path(&device.env().state_path), &device.keychain).unwrap();
    let entry = vault.get(&receipt.key_id).unwrap().unwrap();
    assert_eq!(entry.origin, EntryOrigin::Generated);
    assert!(
        crate::vault::material::open(&entry.private_key, Some("passphrase_PRIVATE_SENTINEL"))
            .is_ok()
    );
    let journal = fs::read_to_string(
        device
            .env()
            .state_path
            .parent()
            .unwrap()
            .join("imports")
            .join(&receipt.import_id)
            .join("journal.json"),
    )
    .unwrap();
    for rendered in [
        journal,
        serde_json::to_string(&state).unwrap(),
        format!("{receipt:?}"),
    ] {
        assert!(!rendered.contains("passphrase_PRIVATE_SENTINEL"));
        assert!(!rendered.contains("BEGIN OPENSSH PRIVATE KEY"));
    }
}
#[test]
fn invalid_name_unsupported_and_oversized_material_create_no_journal_or_vault() {
    let device = device();
    for (name, text) in [
        ("../bad", test_keys::plain()),
        ("work", test_keys::security_key()),
        ("work", test_keys::encrypted_with_3des_label()),
        ("work", "PRIVATE_SENTINEL".repeat(100_000)),
    ] {
        let error = import_local(
            &device.env(),
            name,
            Zeroizing::new(text),
            EntryOrigin::Imported,
        )
        .unwrap_err();
        assert!(!error.to_string().contains("PRIVATE_SENTINEL"));
        assert!(!device
            .env()
            .state_path
            .parent()
            .unwrap()
            .join("imports")
            .exists());
        assert!(!vault_path(&device.env().state_path).exists());
        assert!(device
            .runtime
            .core
            .lock()
            .unwrap()
            .records
            .as_ref()
            .unwrap()
            .local
            .keys
            .is_empty());
    }
}
#[test]
fn each_durable_key_publication_step_resumes_from_encrypted_stage_with_exact_ids() {
    use crate::sync::record_import::{pending_imports, resume, with_test_step, PublishStep};
    for stop in [
        PublishStep::VaultStaged,
        PublishStep::Staged,
        PublishStep::MasterPromoted,
        PublishStep::VaultSaved,
        PublishStep::BeforeStateSave,
        PublishStep::StateSaved,
    ] {
        let device = device();
        assert!(with_test_step(
            move |step| if step == stop {
                Err(AppError::Other("test interruption".into()))
            } else {
                Ok(())
            },
            || import_local(
                &device.env(),
                "work",
                Zeroizing::new(test_keys::plain()),
                EntryOrigin::Imported
            )
        )
        .is_err());
        let pending = pending_imports(&device.env()).unwrap();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].host_count, 0);
        assert_eq!(pending[0].key_count, 1);
        let receipt = resume(&device.env(), &pending[0].import_id).unwrap();
        assert_eq!(receipt.copied_key_ids.len(), 1);
        let state = device.runtime.core.lock().unwrap().records.clone().unwrap();
        assert_eq!(state.local.keys.len(), 1);
        assert!(state.local.import_receipts.contains_key(&receipt.import_id));
        let vault = read_vault(&vault_path(&device.env().state_path), &device.keychain).unwrap();
        assert_eq!(
            vault
                .get(&receipt.copied_key_ids[0])
                .unwrap()
                .unwrap()
                .private_key,
            test_keys::plain()
        );
        assert_eq!(resume(&device.env(), &receipt.import_id).unwrap(), receipt);
    }
}
#[test]
fn a_failed_key_state_save_preserves_core_generation_and_can_resume_added_ciphertext() {
    use crate::sync::record_import::{pending_imports, resume, with_test_step, PublishStep};
    let device = device();
    let path = device.env().state_path;
    let injected = path.clone();
    let before = device.runtime.core.lock().unwrap().records.clone().unwrap();
    let generation = device.runtime.core.lock().unwrap().generation;
    assert!(with_test_step(
        move |step| {
            if step == PublishStep::BeforeStateSave {
                fs::create_dir(&injected).unwrap();
            }
            Ok(())
        },
        || import_local(
            &device.env(),
            "work",
            Zeroizing::new(test_keys::plain()),
            EntryOrigin::Imported
        )
    )
    .is_err());
    assert_eq!(device.runtime.core.lock().unwrap().generation, generation);
    assert_eq!(
        device
            .runtime
            .core
            .lock()
            .unwrap()
            .records
            .as_ref()
            .unwrap(),
        &before
    );
    assert!(vault_path(&path).exists());
    fs::remove_dir(&path).unwrap();
    let pending = pending_imports(&device.env()).unwrap();
    resume(&device.env(), &pending[0].import_id).unwrap();
    assert_eq!(
        device
            .runtime
            .core
            .lock()
            .unwrap()
            .records
            .as_ref()
            .unwrap()
            .local
            .keys
            .len(),
        1
    );
}
#[test]
fn concurrent_unrelated_key_metadata_edits_survive_local_key_publication() {
    use crate::sync::record_import::{with_test_step, PublishStep};
    let device = std::sync::Arc::new(device());
    let old = import_local(
        &device.env(),
        "old",
        Zeroizing::new(test_keys::ecdsa()),
        EntryOrigin::Imported,
    )
    .unwrap();
    let old_id = old.key_id.clone();
    let hook_device = device.clone();
    let mut once = false;
    let receipt = with_test_step(
        move |step| {
            if step == PublishStep::BeforeStateSave && !once {
                once = true;
                crate::sync::record_runtime::mutate_records(&hook_device.env(), |state| {
                    let mut next = state.clone();
                    next.local.keys.get_mut(&old_id).unwrap().public.name = "renamed".into();
                    Ok(next)
                })
                .unwrap();
            }
            Ok(())
        },
        || {
            import_local(
                &device.env(),
                "new",
                Zeroizing::new(test_keys::plain()),
                EntryOrigin::Imported,
            )
        },
    )
    .unwrap();
    let state = device.runtime.core.lock().unwrap().records.clone().unwrap();
    assert_eq!(state.local.keys.len(), 2);
    assert_eq!(state.local.keys[&old.key_id].public.name, "renamed");
    assert_eq!(state.local.keys[&receipt.key_id].public.name, "new");
    let vault = read_vault(&vault_path(&device.env().state_path), &device.keychain).unwrap();
    assert_eq!(vault.ids().len(), 2);
    assert_eq!(
        vault.get(&old.key_id).unwrap().unwrap().private_key,
        test_keys::ecdsa()
    );
}
#[test]
fn completed_key_receipt_preserves_a_later_local_rename_or_removal() {
    use crate::sync::record_import::{pending_imports, resume, with_test_step, PublishStep};
    for remove in [false, true] {
        let device = device();
        assert!(with_test_step(
            |step| if step == PublishStep::StateSaved {
                Err(AppError::Other("receipt interrupted".into()))
            } else {
                Ok(())
            },
            || import_local(
                &device.env(),
                "work",
                Zeroizing::new(test_keys::plain()),
                EntryOrigin::Imported
            )
        )
        .is_err());
        let pending = pending_imports(&device.env()).unwrap();
        let state = device.runtime.core.lock().unwrap().records.clone().unwrap();
        let id = state.local.keys.keys().next().unwrap().clone();
        crate::sync::record_runtime::mutate_records(&device.env(), |state| {
            let mut next = state.clone();
            if remove {
                next.local.keys.remove(&id);
            } else {
                next.local.keys.get_mut(&id).unwrap().public.name = "changed".into();
            }
            Ok(next)
        })
        .unwrap();
        let current = device.runtime.core.lock().unwrap().records.clone().unwrap();
        resume(&device.env(), &pending[0].import_id).unwrap();
        assert_eq!(
            device
                .runtime
                .core
                .lock()
                .unwrap()
                .records
                .as_ref()
                .unwrap(),
            &current
        );
    }
}
fn account_key(device: &TestDevice, id: &str, text: &str) -> KeySlotPayload {
    let private = crate::vault::material::parse(text).unwrap();
    let public = KeySlotPayload {
        schema: 2,
        name: "shared".into(),
        public_key: private.public_key().to_openssh().unwrap(),
        fingerprint: private
            .public_key()
            .fingerprint(ssh_key::HashAlg::Sha256)
            .to_string(),
        key_type: private.public_key().algorithm().as_str().into(),
        has_passphrase: private.is_encrypted(),
        created_at_ms: 1,
        origin_device_id: "e".repeat(32),
    };
    let payload = public.clone();
    crate::sync::record_runtime::mutate_records(&device.env(), |state| {
        use crate::sync::record::{record_key, LocalRecord, Record, RecordKind};
        let mut next = state.clone();
        let mut account = crate::sync::state_v2::AccountState::new(&"a".repeat(64));
        account.remote_schema_version = Some(3);
        account.baseline_established = true;
        account.records.insert(
            record_key(RecordKind::KeySlot, id),
            LocalRecord {
                record: Record {
                    kind: RecordKind::KeySlot,
                    id: id.into(),
                    version: 4,
                    updated_at_ms: 88,
                    device_id: "e".repeat(32),
                    deleted: false,
                    payload: serde_json::to_value(&payload).unwrap(),
                },
                seq: 8,
                dirty: false,
            },
        );
        next.account = Some(account);
        Ok(next)
    })
    .unwrap();
    public
}
#[test]
fn explicit_synced_activation_uses_authoritative_key_id_and_a_new_vault_id() {
    let device = device();
    let id = "b".repeat(32);
    let public = account_key(&device, &id, &test_keys::plain());
    let account = device
        .runtime
        .core
        .lock()
        .unwrap()
        .records
        .as_ref()
        .unwrap()
        .account
        .clone();
    let _lifecycle = device.runtime.lifecycle.lock().unwrap();
    let receipt = activate_synced(
        &device.env(),
        &id,
        public.clone(),
        Zeroizing::new(test_keys::plain()),
    )
    .unwrap();
    assert_eq!(receipt.key_id, id);
    assert_eq!(receipt.public, public);
    let state = device.runtime.core.lock().unwrap().records.clone().unwrap();
    assert_eq!(state.account, account);
    let material = &state.local.keys[&id];
    assert_ne!(material.vault_id, id);
    assert_eq!(material.public, public);
    let vault = read_vault(&vault_path(&device.env().state_path), &device.keychain).unwrap();
    let entry = vault.get(&material.vault_id).unwrap().unwrap();
    assert_eq!(entry.origin, EntryOrigin::Synced);
    assert_eq!(entry.private_key, test_keys::plain());
}
#[test]
fn synced_activation_never_replaces_a_conflicting_local_key_or_old_vault_material() {
    let device = device();
    let old = import_local(
        &device.env(),
        "old",
        Zeroizing::new(test_keys::ecdsa()),
        EntryOrigin::Imported,
    )
    .unwrap();
    let id = "b".repeat(32);
    let public = account_key(&device, &id, &test_keys::plain());
    crate::sync::record_runtime::mutate_records(&device.env(), |state| {
        let mut next = state.clone();
        next.local
            .keys
            .insert(id.clone(), next.local.keys[&old.key_id].clone());
        Ok(next)
    })
    .unwrap();
    let before = device.runtime.core.lock().unwrap().records.clone().unwrap();
    let bytes = fs::read(vault_path(&device.env().state_path)).unwrap();
    let _lifecycle = device.runtime.lifecycle.lock().unwrap();
    assert!(activate_synced(
        &device.env(),
        &id,
        public,
        Zeroizing::new(test_keys::plain())
    )
    .is_err());
    assert_eq!(
        device
            .runtime
            .core
            .lock()
            .unwrap()
            .records
            .as_ref()
            .unwrap(),
        &before
    );
    assert_eq!(
        fs::read(vault_path(&device.env().state_path)).unwrap(),
        bytes
    );
}
#[test]
fn synced_activation_refuses_wrong_private_identity_or_encryption_flag_before_journaling() {
    for flag in [false, true] {
        let device = device();
        let id = "b".repeat(32);
        let mut public = account_key(&device, &id, &test_keys::plain());
        let private = if flag {
            public.has_passphrase = true;
            test_keys::plain()
        } else {
            test_keys::ecdsa()
        };
        let _lifecycle = device.runtime.lifecycle.lock().unwrap();
        assert!(activate_synced(&device.env(), &id, public, Zeroizing::new(private)).is_err());
        assert!(!device
            .env()
            .state_path
            .parent()
            .unwrap()
            .join("imports")
            .exists());
        assert!(!vault_path(&device.env().state_path).exists());
    }
}
#[test]
fn latest_authoritative_keyslot_revision_change_blocks_staged_synced_publication() {
    use crate::sync::record_import::{pending_imports, with_test_step, PublishStep};
    let device = std::sync::Arc::new(device());
    let id = "b".repeat(32);
    let public = account_key(&device, &id, &test_keys::plain());
    let hook_device = device.clone();
    let hook_id = id.clone();
    let _lifecycle = device.runtime.lifecycle.lock().unwrap();
    assert!(with_test_step(
        move |step| {
            if step == PublishStep::Staged {
                crate::sync::record_runtime::mutate_records(&hook_device.env(), |state| {
                    let mut next = state.clone();
                    let row = next
                        .account
                        .as_mut()
                        .unwrap()
                        .records
                        .get_mut(&crate::sync::record::record_key(
                            crate::sync::record::RecordKind::KeySlot,
                            &hook_id,
                        ))
                        .unwrap();
                    row.record.version += 1;
                    row.record.payload["name"] = serde_json::json!("changed-authority");
                    Ok(next)
                })
                .unwrap();
            }
            Ok(())
        },
        || activate_synced(
            &device.env(),
            &id,
            public,
            Zeroizing::new(test_keys::plain())
        )
    )
    .is_err());
    assert!(!vault_path(&device.env().state_path).exists());
    assert!(device
        .runtime
        .core
        .lock()
        .unwrap()
        .records
        .as_ref()
        .unwrap()
        .local
        .keys
        .is_empty());
    assert_eq!(pending_imports(&device.env()).unwrap().len(), 1);
}
#[test]
fn synced_state_save_failure_resumes_the_exact_new_vault_mapping_without_old_data_loss() {
    use crate::sync::record_import::{pending_imports, resume, with_test_step, PublishStep};
    let device = device();
    let id = "b".repeat(32);
    let public = account_key(&device, &id, &test_keys::plain());
    let state_path = device.env().state_path;
    let retained = state_path.with_extension("saved-for-test");
    let fault_path = state_path.clone();
    let fault_retained = retained.clone();
    let before = device.runtime.core.lock().unwrap().records.clone().unwrap();
    let generation = device.runtime.core.lock().unwrap().generation;
    {
        let _lifecycle = device.runtime.lifecycle.lock().unwrap();
        assert!(with_test_step(
            move |step| {
                if step == PublishStep::BeforeStateSave {
                    fs::rename(&fault_path, &fault_retained).unwrap();
                    fs::create_dir(&fault_path).unwrap();
                }
                Ok(())
            },
            || activate_synced(
                &device.env(),
                &id,
                public,
                Zeroizing::new(test_keys::plain())
            )
        )
        .is_err());
    }
    assert_eq!(device.runtime.core.lock().unwrap().generation, generation);
    assert_eq!(
        device
            .runtime
            .core
            .lock()
            .unwrap()
            .records
            .as_ref()
            .unwrap(),
        &before
    );
    let vault = read_vault(&vault_path(&state_path), &device.keychain).unwrap();
    let staged_id = vault.ids()[0].clone();
    assert_ne!(staged_id, id);
    fs::remove_dir(&state_path).unwrap();
    fs::rename(&retained, &state_path).unwrap();
    let pending = pending_imports(&device.env()).unwrap();
    resume(&device.env(), &pending[0].import_id).unwrap();
    assert_eq!(
        device
            .runtime
            .core
            .lock()
            .unwrap()
            .records
            .as_ref()
            .unwrap()
            .local
            .keys[&id]
            .vault_id,
        staged_id
    );
}
#[test]
fn synced_explicit_copy_retains_coherent_old_material_and_its_original_reference() {
    let device = device();
    let old = import_local(
        &device.env(),
        "old",
        Zeroizing::new(test_keys::plain()),
        EntryOrigin::Imported,
    )
    .unwrap();
    let id = "b".repeat(32);
    let public = account_key(&device, &id, &test_keys::plain());
    crate::sync::record_runtime::mutate_records(&device.env(), |state| {
        let mut next = state.clone();
        next.local
            .keys
            .insert(id.clone(), state.local.keys[&old.key_id].clone());
        Ok(next)
    })
    .unwrap();
    let main = vault_path(&device.env().state_path);
    let before = read_vault(&main, &device.keychain).unwrap();
    let old_entry = before.get(&old.key_id).unwrap().unwrap();
    let _lifecycle = device.runtime.lifecycle.lock().unwrap();
    activate_synced(
        &device.env(),
        &id,
        public,
        Zeroizing::new(test_keys::plain()),
    )
    .unwrap();
    let state = device.runtime.core.lock().unwrap().records.clone().unwrap();
    assert_eq!(state.local.keys[&old.key_id].vault_id, old.key_id);
    assert_ne!(state.local.keys[&id].vault_id, old.key_id);
    let vault = read_vault(&main, &device.keychain).unwrap();
    assert_eq!(vault.ids().len(), 2);
    assert_eq!(vault.get(&old.key_id).unwrap().unwrap(), old_entry);
    assert_eq!(vault.key_account(), before.key_account());
}
#[test]
fn synced_authority_cas_preserves_independent_transport_receipts() {
    use crate::sync::record_import::{with_test_step, PublishStep};
    let device = std::sync::Arc::new(device());
    let id = "b".repeat(32);
    let public = account_key(&device, &id, &test_keys::plain());
    let hook_device = device.clone();
    let hook_id = id.clone();
    let _lifecycle = device.runtime.lifecycle.lock().unwrap();
    with_test_step(
        move |step| {
            if step == PublishStep::Staged {
                crate::sync::record_runtime::mutate_records(&hook_device.env(), |state| {
                    let mut next = state.clone();
                    let row = next
                        .account
                        .as_mut()
                        .unwrap()
                        .records
                        .get_mut(&crate::sync::record::record_key(
                            crate::sync::record::RecordKind::KeySlot,
                            &hook_id,
                        ))
                        .unwrap();
                    row.seq = 9;
                    row.dirty = true;
                    Ok(next)
                })
                .unwrap();
            }
            Ok(())
        },
        || {
            activate_synced(
                &device.env(),
                &id,
                public,
                Zeroizing::new(test_keys::plain()),
            )
        },
    )
    .unwrap();
    let state = device.runtime.core.lock().unwrap().records.clone().unwrap();
    let account = state.account.unwrap();
    let row = &account.records
        [&crate::sync::record::record_key(crate::sync::record::RecordKind::KeySlot, &id)];
    assert_eq!(row.seq, 9);
    assert!(row.dirty);
    assert_eq!(row.record.version, 4);
}
#[test]
fn synced_activation_resumes_every_durable_step_with_the_same_authoritative_and_vault_ids() {
    use crate::sync::record_import::{pending_imports, resume, with_test_step, PublishStep};
    for stop in [
        PublishStep::VaultStaged,
        PublishStep::Staged,
        PublishStep::MasterPromoted,
        PublishStep::VaultSaved,
        PublishStep::BeforeStateSave,
        PublishStep::StateSaved,
    ] {
        let device = device();
        let id = "b".repeat(32);
        let public = account_key(&device, &id, &test_keys::plain());
        {
            let _lifecycle = device.runtime.lifecycle.lock().unwrap();
            assert!(with_test_step(
                move |step| if step == stop {
                    Err(AppError::Other("download interrupted".into()))
                } else {
                    Ok(())
                },
                || activate_synced(
                    &device.env(),
                    &id,
                    public,
                    Zeroizing::new(test_keys::plain())
                )
            )
            .is_err());
        }
        let pending = pending_imports(&device.env()).unwrap();
        let path = device
            .env()
            .state_path
            .parent()
            .unwrap()
            .join("imports")
            .join(&pending[0].import_id)
            .join("journal.json");
        let journal: serde_json::Value = serde_json::from_slice(&fs::read(path).unwrap()).unwrap();
        let vault_id = journal["keys"][&id]["vault_id"]
            .as_str()
            .unwrap()
            .to_string();
        let receipt = resume(&device.env(), &pending[0].import_id).unwrap();
        assert_eq!(receipt.copied_key_ids, [id.clone()]);
        assert_eq!(
            device
                .runtime
                .core
                .lock()
                .unwrap()
                .records
                .as_ref()
                .unwrap()
                .local
                .keys[&id]
                .vault_id,
            vault_id
        );
        assert_eq!(
            read_vault(&vault_path(&device.env().state_path), &device.keychain)
                .unwrap()
                .get(&vault_id)
                .unwrap()
                .unwrap()
                .private_key,
            test_keys::plain()
        );
    }
}
#[test]
fn blocked_or_deleted_account_key_metadata_never_activates_private_material() {
    for blocked in [false, true] {
        let device = device();
        let id = "b".repeat(32);
        let public = account_key(&device, &id, &test_keys::plain());
        crate::sync::record_runtime::mutate_records(&device.env(), |state| {
            let mut next = state.clone();
            if blocked {
                next.shared_writes_blocked = true;
            } else {
                next.account
                    .as_mut()
                    .unwrap()
                    .records
                    .get_mut(&crate::sync::record::record_key(
                        crate::sync::record::RecordKind::KeySlot,
                        &id,
                    ))
                    .unwrap()
                    .record
                    .deleted = true;
            }
            Ok(next)
        })
        .unwrap();
        let _lifecycle = device.runtime.lifecycle.lock().unwrap();
        assert!(activate_synced(
            &device.env(),
            &id,
            public,
            Zeroizing::new(test_keys::plain())
        )
        .is_err());
        assert!(!device
            .env()
            .state_path
            .parent()
            .unwrap()
            .join("imports")
            .exists());
        assert!(!vault_path(&device.env().state_path).exists());
    }
}
