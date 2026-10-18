use super::*;
use crate::sync::{
    central::{
        api::{DeviceSession, DeviceState},
        crypto::{self, DeviceKeys},
        oidc::LoginTokens,
        wire::WrapHeader,
    },
    env::Keychain,
    fake_relay::FakeRelay,
    record_keys,
    slot_rules::test_keys,
    testkit::{MemKeychain, TestClock, TestDevice},
};
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use std::time::{Duration, Instant};

pub(in crate::sync) fn fixture() -> TestDevice {
    let (mut state, keys, _) = central::library_fixture_for_test();
    let signer = DeviceKeys::decode_secret(&B64.encode([1u8; 64])).unwrap();
    let owner = state.local.central.as_mut().unwrap();
    let anchor = owner.control.anchor.as_ref().unwrap();
    owner.own_wraps = vec![crypto::wrap_keys(
        &keys,
        &signer,
        WrapHeader {
            origin: anchor.origin.clone(),
            account_id: anchor.account_id.clone(),
            genesis_hash: anchor.genesis_hash.clone(),
            vault_id: owner.control.personal_vault.clone().unwrap(),
            key_epoch: "1".into(),
            membership_head: owner.control.highwater.as_ref().unwrap().head.clone(),
            author: owner.control.device.id.clone(),
            recipient: owner.control.device.id.clone(),
            recipient_key: signer.public().encryption,
        },
    )
    .unwrap()];
    let device = TestDevice::new("central-local", &FakeRelay::new(), &TestClock::new());
    record_runtime::save_active(&device.env().state_path, &state).unwrap();
    let probe = record_runtime::probe_startup(&device.env().state_path, "central-local");
    record_runtime::activate_probe(&mut device.runtime.core.lock().unwrap(), probe).unwrap();
    let owner = state.local.central.as_ref().unwrap();
    let profile = owner.control.profile.profile().unwrap();
    let encoded = Zeroizing::new(serde_json::json!({"version":1,"locator":profile.locator,"id":owner.control.device.id,"keys":&*signer.encode_secret(),"credential":"d".repeat(64)}).to_string());
    device
        .keychain
        .set(
            &profile
                .device_slot("device", owner.identity_slot.as_deref())
                .unwrap(),
            &encoded,
        )
        .unwrap();
    device
}
fn state(d: &TestDevice) -> SyncStateV3 {
    record_runtime::snapshot(&d.env()).unwrap().0
}
fn scope(d: &TestDevice) -> Invocation {
    let (state, generation) = record_runtime::snapshot(&d.env()).unwrap();
    invocation(&state).unwrap().with_generation(generation)
}
fn create(d: &TestDevice, raw: String) -> record_keys::LocalKeyReceipt {
    record_keys::import_local_scoped(
        &d.env(),
        "work",
        Zeroizing::new(raw),
        EntryOrigin::Imported,
        Some(&scope(d)),
    )
    .unwrap()
}
fn journal_path(d: &TestDevice, id: &str) -> PathBuf {
    Paths::new(&d.env(), id).unwrap().journal
}
fn pending_id(d: &TestDevice) -> String {
    pending_imports(&d.env())
        .unwrap()
        .into_iter()
        .find(|p| p.phase != "active")
        .unwrap()
        .import_id
}
fn selected_slot(d: &TestDevice) -> String {
    let s = state(d);
    let o = s.local.central.as_ref().unwrap();
    o.control
        .profile
        .profile()
        .unwrap()
        .device_slot("device", o.identity_slot.as_deref())
        .unwrap()
}
fn expired_session(d: &TestDevice) -> Arc<Session> {
    selected_session(d, Duration::ZERO)
}
pub(in crate::sync) fn selected_session(d: &TestDevice, lifetime: Duration) -> Arc<Session> {
    let s = state(d);
    let o = s.local.central.as_ref().unwrap();
    Arc::new(Session {
        profile: o.control.profile.clone(),
        identity: Some(Arc::new(
            DeviceIdentity::load_selected(
                &d.keychain,
                &o.control.profile.profile().unwrap(),
                o.identity_slot.as_deref(),
                false,
            )
            .unwrap(),
        )),
        tokens: Arc::new(LoginTokens {
            issuer: o.control.profile.issuer.clone(),
            subject: o.control.profile.subject.clone(),
            nonce: Zeroizing::new("synthetic nonce".into()),
            access: Zeroizing::new("synthetic access".into()),
            refresh: None,
            expires_in: lifetime,
        }),
        device: Some(DeviceSession::synthetic_for_test(
            o.control.account_id.clone(),
            DeviceState::Active,
            o.control.auth_epoch,
            lifetime,
        )),
        device_access_denied: false,
        tokens_started: Instant::now(),
    })
}
#[test]
fn offline_import_preserves_original_container_and_atomically_installs_protected_source_and_ciphertext(
) {
    for raw in [test_keys::plain(), test_keys::encrypted()] {
        let d = fixture();
        let before = state(&d);
        assert!(d.runtime.core.lock().unwrap().central_session.is_none());
        let receipt = create(&d, raw.clone());
        let s = state(&d);
        assert_eq!(
            s.local.import_receipts.len(),
            before.local.import_receipts.len() + 1
        );
        assert_eq!(
            s.local
                .central
                .as_ref()
                .unwrap()
                .replica
                .as_ref()
                .unwrap()
                .pending
                .len(),
            2
        );
        assert_eq!(
            receipt.public.origin_device_id,
            s.local.central.as_ref().unwrap().control.device.id
        );
        let view = crate::sync::record_repository::resolve_key(&s, &receipt.key_id).unwrap();
        assert_eq!(
            view.status,
            crate::sync::record_repository::KeyStatus::Available
        );
        let vault = validate_vault(&store::vault_path(&d.env().state_path), &d.keychain).unwrap();
        let entry = vault.get(view.vault_id.as_ref().unwrap()).unwrap().unwrap();
        assert_eq!(entry.private_key, raw);
        assert!(crate::session::record_material::matches(&view, &entry));
        let saved: SyncStateV3 =
            serde_json::from_slice(&fs::read(&d.env().state_path).unwrap()).unwrap();
        assert_eq!(s, saved);
        assert!(pending_imports(&d.env()).unwrap().is_empty());
        assert!(d.relay.calls().is_empty());
        for rendered in [
            serde_json::to_string(&s).unwrap(),
            fs::read_to_string(journal_path(&d, &receipt.import_id)).unwrap(),
            format!("{receipt:?}"),
        ] {
            assert!(!rendered.contains("BEGIN OPENSSH PRIVATE KEY"));
            assert!(!rendered.contains(raw.lines().nth(1).unwrap()));
        }
        let public = view.public.unwrap();
        let later = crate::sync::record_repository::rename_key(
            &s,
            &receipt.key_id,
            &public,
            "later_name",
            300,
        )
        .unwrap();
        record_runtime::commit_candidate(
            &d.env(),
            record_runtime::snapshot(&d.env()).unwrap().1,
            later,
        )
        .unwrap();
        d.keychain.delete(&selected_slot(&d)).unwrap();
        assert_eq!(
            super::super::resume(&d.env(), &receipt.import_id)
                .unwrap()
                .copied_key_ids,
            vec![receipt.key_id.clone()]
        );
        assert_eq!(
            state(&d).local.keys[&receipt.key_id].public.name,
            "later_name"
        );
    }
}
#[test]
fn expired_oauth_and_device_grants_do_not_prevent_offline_encrypted_local_creation() {
    let d = fixture();
    let session = expired_session(&d);
    d.runtime.core.lock().unwrap().central_session = Some(session);
    let receipt = create(&d, test_keys::plain());
    assert!(state(&d).local.keys.contains_key(&receipt.key_id));
    assert!(d.relay.calls().is_empty());
}
#[test]
fn missing_stale_or_absent_invocation_and_missing_os_identity_stop_before_destination_writes() {
    for kind in 0..4 {
        let d = fixture();
        let before = state(&d);
        let mut invocation = scope(&d);
        if kind == 0 {
            invocation.device = "0".repeat(32);
            assert_ne!(invocation.device, scope(&d).device);
        }
        if kind == 1 {
            invocation.genesis = "f".repeat(64);
        }
        if kind == 3 {
            d.keychain.delete(&selected_slot(&d)).unwrap();
        }
        assert!(record_keys::import_local_scoped(
            &d.env(),
            "work",
            Zeroizing::new(test_keys::plain()),
            EntryOrigin::Imported,
            if kind == 2 { None } else { Some(&invocation) }
        )
        .is_err());
        assert_eq!(state(&d), before);
        assert!(!d
            .env()
            .state_path
            .parent()
            .unwrap()
            .join("imports")
            .exists());
        assert!(!store::vault_path(&d.env().state_path).exists());
    }
}
#[test]
fn every_crash_boundary_resumes_the_same_intent_and_completed_retry_preserves_later_removal() {
    for boundary in [
        PublishStep::JournalPrepared,
        PublishStep::VaultStaged,
        PublishStep::Staged,
        PublishStep::MasterPromoted,
        PublishStep::VaultSaved,
        PublishStep::BeforeStateSave,
        PublishStep::StateSaved,
    ] {
        let d = fixture();
        let invocation = scope(&d);
        let result = with_test_step(
            move |at| {
                if at == boundary {
                    Err(failure("synthetic crash"))
                } else {
                    Ok(())
                }
            },
            || {
                record_keys::import_local_scoped(
                    &d.env(),
                    "work",
                    Zeroizing::new(test_keys::encrypted()),
                    EntryOrigin::Imported,
                    Some(&invocation),
                )
            },
        );
        assert!(result.is_err(), "{boundary:?}");
        let dir = d.env().state_path.parent().unwrap().join("imports");
        let operation = fs::read_dir(&dir)
            .unwrap()
            .next()
            .unwrap()
            .unwrap()
            .file_name()
            .to_str()
            .unwrap()
            .to_owned();
        let before: Journal =
            serde_json::from_slice(&fs::read(journal_path(&d, &operation)).unwrap()).unwrap();
        let intent_digest = before.central_intent.as_ref().unwrap().digest().unwrap();
        let receipt = super::super::resume(&d.env(), &operation).unwrap();
        let after: Journal =
            serde_json::from_slice(&fs::read(journal_path(&d, &operation)).unwrap()).unwrap();
        assert_eq!(
            after.central_intent.as_ref().unwrap().digest().unwrap(),
            intent_digest
        );
        let id = &receipt.copied_key_ids[0];
        let s = state(&d);
        let view = crate::sync::record_repository::resolve_key(&s, id).unwrap();
        assert_eq!(
            view.status,
            crate::sync::record_repository::KeyStatus::Available
        );
        let mut removed = s.clone();
        removed.local.keys.remove(id);
        removed
            .account
            .as_mut()
            .unwrap()
            .records
            .remove(&record_key(RecordKind::KeySlot, id));
        record_runtime::commit_candidate(
            &d.env(),
            record_runtime::snapshot(&d.env()).unwrap().1,
            removed.clone(),
        )
        .unwrap();
        super::super::resume(&d.env(), &operation).unwrap();
        assert_eq!(state(&d), removed);
        assert!(pending_imports(&d.env()).unwrap().is_empty());
    }
}
#[test]
fn session_or_protected_credential_change_cannot_complete_an_in_flight_local_publication() {
    for boundary in [
        PublishStep::VaultStaged,
        PublishStep::MasterPromoted,
        PublishStep::BeforeStateSave,
    ] {
        for protected in [false, true] {
            let d = Arc::new(fixture());
            let invocation = scope(&d);
            let slot = selected_slot(&d);
            let session = expired_session(&d);
            d.runtime.core.lock().unwrap().central_session = Some(session);
            let runtime = Arc::clone(&d);
            let keychain = Arc::clone(&d);
            let before = state(&d);
            let result = with_test_step(
                move |at| {
                    if at == boundary {
                        if protected {
                            keychain.keychain.delete(&slot)?;
                        } else {
                            runtime.runtime.core.lock().unwrap().central_session = None;
                        }
                    }
                    Ok(())
                },
                || {
                    record_keys::import_local_scoped(
                        &d.env(),
                        "work",
                        Zeroizing::new(test_keys::plain()),
                        EntryOrigin::Imported,
                        Some(&invocation),
                    )
                },
            );
            assert!(result.is_err(), "{boundary:?} protected={protected}");
            assert_eq!(state(&d), before);
            assert!(!pending_id(&d).is_empty());
            if boundary != PublishStep::BeforeStateSave {
                assert!(!store::vault_path(&d.env().state_path).exists());
            }
        }
    }
}
#[test]
fn unfinished_legacy_or_tampered_intent_journals_are_retained_without_private_publication() {
    for remove in [false, true] {
        let d = fixture();
        let invocation = scope(&d);
        let _ = with_test_step(
            |at| {
                if at == PublishStep::Staged {
                    Err(failure("synthetic crash"))
                } else {
                    Ok(())
                }
            },
            || {
                record_keys::import_local_scoped(
                    &d.env(),
                    "work",
                    Zeroizing::new(test_keys::plain()),
                    EntryOrigin::Imported,
                    Some(&invocation),
                )
            },
        );
        let id = pending_id(&d);
        let path = journal_path(&d, &id);
        let mut value: serde_json::Value =
            serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        if remove {
            value.as_object_mut().unwrap().remove("central_intent");
        } else {
            value["central_intent"]["pending"][1]["latest"]["content_hash"] = "f".repeat(64).into();
        }
        fs::write(&path, serde_json::to_vec(&value).unwrap()).unwrap();
        let before = state(&d);
        assert!(super::super::resume(&d.env(), &id).is_err());
        assert_eq!(state(&d), before);
        assert!(!store::vault_path(&d.env().state_path).exists());
        assert!(path.exists());
    }
}
struct NoIdentityPrompt<'a> {
    inner: &'a MemKeychain,
    slot: String,
}
impl Keychain for NoIdentityPrompt<'_> {
    fn get(&self, account: &str) -> Result<Option<String>, AppError> {
        assert_ne!(account, self.slot, "selected device identity cannot prompt");
        self.inner.get(account)
    }
    fn get_noninteractive(&self, account: &str) -> Result<Option<String>, AppError> {
        self.inner.get(account)
    }
    fn set(&self, account: &str, secret: &str) -> Result<(), AppError> {
        self.inner.set(account, secret)
    }
    fn delete(&self, account: &str) -> Result<(), AppError> {
        self.inner.delete(account)
    }
}
#[test]
fn selected_identity_reads_are_noninteractive_and_existing_protected_entries_are_preserved() {
    let d = fixture();
    let invocation = scope(&d);
    let mut vault = Vault::open(&store::vault_path(&d.env().state_path), &d.keychain, 1).unwrap();
    let raw = test_keys::plain();
    let parsed = crate::vault::material::parse(&raw).unwrap();
    let old = VaultEntry {
        private_key: raw,
        public_key: parsed.public_key().to_openssh().unwrap(),
        fingerprint: parsed
            .public_key()
            .fingerprint(ssh_key::HashAlg::Sha256)
            .to_string(),
        origin: EntryOrigin::Imported,
        added_at_ms: 1,
    };
    vault
        .put_new_batch(
            &d.keychain,
            &BTreeMap::from([("f".repeat(32), old.clone())]),
        )
        .unwrap();
    let keychain = NoIdentityPrompt {
        inner: &d.keychain,
        slot: selected_slot(&d),
    };
    let mut env = d.env();
    env.keychain = &keychain;
    let receipt = record_keys::import_local_scoped(
        &env,
        "work",
        Zeroizing::new(test_keys::encrypted()),
        EntryOrigin::Imported,
        Some(&invocation),
    )
    .unwrap();
    let vault = validate_vault(&store::vault_path(&env.state_path), &keychain).unwrap();
    assert_eq!(
        vault.get(&"f".repeat(32)).unwrap().unwrap().private_key,
        old.private_key
    );
    assert!(vault.get(&receipt.key_id).unwrap().is_some());
}

#[test]
fn stale_generation_and_equivalent_replaced_native_session_cannot_retarget_an_in_flight_request() {
    let d = Arc::new(fixture());
    let stale = scope(&d);
    let (mut later, generation) = record_runtime::snapshot(&d.env()).unwrap();
    later.device_name = "later local edit".into();
    record_runtime::commit_candidate(&d.env(), generation, later).unwrap();
    assert!(record_keys::import_local_scoped(
        &d.env(),
        "work",
        Zeroizing::new(test_keys::plain()),
        EntryOrigin::Imported,
        Some(&stale)
    )
    .is_err());
    assert!(!d
        .env()
        .state_path
        .parent()
        .unwrap()
        .join("imports")
        .exists());
    let selected = expired_session(&d);
    d.runtime.core.lock().unwrap().central_session = Some(Arc::clone(&selected));
    let equivalent = expired_session(&d);
    let active = Arc::clone(&d);
    let invocation = scope(&d);
    let before = state(&d);
    let result = with_test_step(
        move |at| {
            if at == PublishStep::BeforeStateSave {
                active.runtime.core.lock().unwrap().central_session = Some(Arc::clone(&equivalent));
            }
            Ok(())
        },
        || {
            record_keys::import_local_scoped(
                &d.env(),
                "work",
                Zeroizing::new(test_keys::plain()),
                EntryOrigin::Imported,
                Some(&invocation),
            )
        },
    );
    assert!(result.is_err());
    assert_eq!(state(&d), before);
}
#[test]
fn strict_vault_and_state_write_faults_preserve_recoverable_intent_and_block_uncertain_durability()
{
    use record_runtime::{with_replacement_write_hook, ReplacementWriteStage as WriteStage};
    for active_vault in [false, true] {
        for stop in [
            WriteStage::FileSync,
            WriteStage::SourceRecheck,
            WriteStage::Rename,
            WriteStage::DirectorySync,
        ] {
            let d = fixture();
            let invocation = scope(&d);
            let before = state(&d);
            d.runtime.core.lock().unwrap().central_session = Some(expired_session(&d));
            let target = if active_vault {
                store::vault_path(&d.env().state_path)
            } else {
                d.env().state_path.clone()
            };
            let result = with_replacement_write_hook(
                Box::new(move |stage, path| {
                    if path == target && stage == stop {
                        Err(failure("synthetic write fault"))
                    } else {
                        Ok(())
                    }
                }),
                || {
                    record_keys::import_local_scoped(
                        &d.env(),
                        "work",
                        Zeroizing::new(test_keys::plain()),
                        EntryOrigin::Imported,
                        Some(&invocation),
                    )
                },
            );
            assert!(result.is_err(), "vault={active_vault} stop={stop:?}");
            assert_eq!(state(&d), before);
            if stop == WriteStage::DirectorySync {
                let core = d.runtime.core.lock().unwrap();
                assert!(core.save_blocked.is_some());
                assert!(core.central_session.is_none());
                drop(core);
                let probe = record_runtime::probe_startup(&d.env().state_path, "restart");
                record_runtime::activate_probe(&mut d.runtime.core.lock().unwrap(), probe).unwrap();
            }
            let id = fs::read_dir(d.env().state_path.parent().unwrap().join("imports"))
                .unwrap()
                .next()
                .unwrap()
                .unwrap()
                .file_name()
                .to_str()
                .unwrap()
                .to_owned();
            let receipt = super::super::resume(&d.env(), &id).unwrap();
            assert_eq!(
                crate::sync::record_repository::resolve_key(&state(&d), &receipt.copied_key_ids[0])
                    .unwrap()
                    .status,
                crate::sync::record_repository::KeyStatus::Available
            );
        }
    }
}
#[test]
fn local_edits_made_during_vault_publication_survive_and_unreadable_intent_storage_never_panics() {
    let d = Arc::new(fixture());
    let invocation = scope(&d);
    let active = Arc::clone(&d);
    let receipt = with_test_step(
        move |at| {
            if at == PublishStep::VaultSaved {
                let (mut state, generation) = record_runtime::snapshot(&active.env())?;
                state.device_name = "local B created while staging".into();
                record_runtime::commit_candidate(&active.env(), generation, state)?;
            }
            Ok(())
        },
        || {
            record_keys::import_local_scoped(
                &d.env(),
                "work",
                Zeroizing::new(test_keys::plain()),
                EntryOrigin::Imported,
                Some(&invocation),
            )
        },
    )
    .unwrap();
    assert_eq!(state(&d).device_name, "local B created while staging");
    assert!(state(&d).local.keys.contains_key(&receipt.key_id));
    let path = journal_path(&d, &receipt.import_id);
    let mut journal: serde_json::Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    journal["central_intent"]["receipt"]["body"]["slot"]["storage"] =
        serde_json::to_value(central::payload::KeyStorage::Hardware).unwrap();
    fs::write(&path, serde_json::to_vec(&journal).unwrap()).unwrap();
    assert!(super::super::resume(&d.env(), &receipt.import_id).is_err());
}

#[test]
fn generated_key_recovers_the_exact_original_container_from_the_first_durable_ciphertext_intent() {
    let d = fixture();
    let invocation = scope(&d);
    let result = with_test_step(
        |at| {
            if at == PublishStep::JournalPrepared {
                Err(failure("synthetic crash before vault staging"))
            } else {
                Ok(())
            }
        },
        || {
            record_keys::generate_local_scoped(
                &d.env(),
                "generated",
                crate::vault::generate::KeyAlgorithm::Ed25519,
                "recovery fixture",
                Some(Zeroizing::new("PRIVATE synthetic passphrase".into())),
                Some(&invocation),
            )
        },
    );
    assert!(result.is_err());
    assert!(!store::vault_path(&d.env().state_path).exists());
    let id = pending_id(&d);
    let j: Journal = serde_json::from_slice(&fs::read(journal_path(&d, &id)).unwrap()).unwrap();
    let before = state(&d);
    let context = Context::load(&d.env(), &before).unwrap();
    let expected = context
        .recover(&d.env(), &before, &j)
        .unwrap()
        .pop_first()
        .unwrap()
        .1;
    assert_eq!(expected.origin, EntryOrigin::Generated);
    let receipt = super::super::resume(&d.env(), &id).unwrap();
    let vault = validate_vault(&store::vault_path(&d.env().state_path), &d.keychain).unwrap();
    let actual = vault.get(&receipt.copied_key_ids[0]).unwrap().unwrap();
    assert_eq!(actual.private_key, expected.private_key);
    assert_eq!(actual.origin, EntryOrigin::Generated);
    assert!(crate::vault::material::open(
        &actual.private_key,
        Some("PRIVATE synthetic passphrase")
    )
    .is_ok());
}

#[test]
fn offline_rename_captures_public_ciphertext_without_changing_private_draft_source_or_vault() {
    for raw in [test_keys::plain(), test_keys::encrypted()] {
        let d = fixture();
        let receipt = create(&d, raw.clone());
        let before = state(&d);
        let vault_before = fs::read(store::vault_path(&d.env().state_path)).unwrap();
        let private_before = before
            .local
            .central
            .as_ref()
            .unwrap()
            .replica
            .as_ref()
            .unwrap()
            .pending
            .values()
            .find(|p| p.latest.envelope.header.kind == "key")
            .unwrap()
            .clone();
        rename(
            &d.env(),
            &scope(&d),
            &receipt.key_id,
            &receipt.public,
            "renamed_offline",
        )
        .unwrap();
        let after = state(&d);
        assert_eq!(
            before.local.central_projection,
            after.local.central_projection
        );
        assert_eq!(
            vault_before,
            fs::read(store::vault_path(&d.env().state_path)).unwrap()
        );
        let pending = &after
            .local
            .central
            .as_ref()
            .unwrap()
            .replica
            .as_ref()
            .unwrap()
            .pending;
        assert_eq!(
            pending
                .values()
                .find(|p| p.latest.envelope.header.kind == "key")
                .unwrap(),
            &private_before
        );
        let context = Context::load(&d.env(), &after).unwrap();
        let public = &pending
            .values()
            .find(|p| p.latest.envelope.header.kind == "keyslot")
            .unwrap()
            .latest;
        let plain = public
            .envelope
            .verify(&context.identity.keys.public().signing)
            .unwrap()
            .open(&context.keys)
            .unwrap();
        let admitted =
            central::payload::admit(&context.keys, &public.envelope.header, &plain).unwrap();
        let central::payload::Data::Keyslot(slot) = admitted.data else {
            panic!("public slot")
        };
        assert_eq!(slot.public.name, "renamed_offline");
        let view = crate::sync::record_repository::resolve_key(&after, &receipt.key_id).unwrap();
        assert_eq!(
            view.status,
            crate::sync::record_repository::KeyStatus::Available
        );
        let entry = validate_vault(&store::vault_path(&d.env().state_path), &d.keychain)
            .unwrap()
            .get(&receipt.key_id)
            .unwrap()
            .unwrap();
        assert_eq!(entry.private_key, raw);
        assert!(crate::session::record_material::matches(&view, &entry));
        assert!(d.relay.calls().is_empty());
        d.runtime.core.lock().unwrap().central_session = Some(expired_session(&d));
        rename(
            &d.env(),
            &scope(&d),
            &receipt.key_id,
            &view.public.unwrap(),
            "renamed_again",
        )
        .unwrap();
        assert_eq!(
            crate::sync::record_repository::resolve_key(&state(&d), &receipt.key_id)
                .unwrap()
                .status,
            crate::sync::record_repository::KeyStatus::Available
        );
    }
}
#[test]
fn rename_failure_or_changed_request_preserves_current_name_and_ciphertext() {
    for missing_identity in [false, true] {
        let d = fixture();
        let receipt = create(&d, test_keys::plain());
        let before = state(&d);
        let mut expected = scope(&d);
        if missing_identity {
            d.keychain.delete(&selected_slot(&d)).unwrap();
        } else {
            expected.generation = "0".into();
            assert_ne!(expected.generation, scope(&d).generation);
        }
        assert!(rename(
            &d.env(),
            &expected,
            &receipt.key_id,
            &receipt.public,
            "new_name"
        )
        .is_err());
        assert_eq!(state(&d), before);
    }
}
