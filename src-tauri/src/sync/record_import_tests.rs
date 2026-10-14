use super::*;
use crate::sync::env::Keychain;
use crate::sync::fake_relay::FakeRelay;
use crate::sync::record_runtime::{probe_startup, RuntimeFormat, StartupProbe};
use crate::sync::slot_rules::test_keys;
use crate::sync::testkit::{MemKeychain, TestClock, TestDevice};
use crate::vault::store::{read_vault, vault_path, Vault};
use std::fs;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

#[derive(Default)]
struct Credentials {
    inner: MemKeychain,
    reads: AtomicUsize,
    writes: AtomicUsize,
    deletes: AtomicUsize,
    fail_promotion: AtomicBool,
}
impl Keychain for Credentials {
    fn get(&self, account: &str) -> Result<Option<String>, AppError> {
        self.reads.fetch_add(1, Ordering::SeqCst);
        self.inner.get(account)
    }
    fn set(&self, account: &str, secret: &str) -> Result<(), AppError> {
        self.writes.fetch_add(1, Ordering::SeqCst);
        if self.fail_promotion.load(Ordering::SeqCst) && account.starts_with("vault:key") {
            return Err(AppError::Other("promotion denied PRIVATE_SENTINEL".into()));
        }
        self.inner.set(account, secret)
    }
    fn delete(&self, account: &str) -> Result<(), AppError> {
        self.deletes.fetch_add(1, Ordering::SeqCst);
        self.inner.delete(account)
    }
}
struct Fixture {
    device: TestDevice,
    source: PathBuf,
    private: PathBuf,
    credentials: Credentials,
}
impl Fixture {
    fn new() -> Self {
        let relay = FakeRelay::new();
        let clock = TestClock::new();
        let device = TestDevice::new("import", &relay, &clock);
        let env = device.env();
        let StartupProbe::Records { state, .. } = probe_startup(&env.state_path, "Import test")
        else {
            panic!("fresh state")
        };
        {
            let mut core = device.runtime.core.lock().unwrap();
            core.state = None;
            core.format = RuntimeFormat::Records;
            core.records = Some(*state);
        }
        let source = device.home.path().join("external-config");
        let private = device.home.path().join("external-private");
        fs::write(&private, test_keys::plain()).unwrap();
        fs::write(
            &source,
            format!(
                "Host imported\n HostName imported.example\n User fixture\n IdentityFile {}\n",
                private.display()
            ),
        )
        .unwrap();
        Self {
            device,
            source,
            private,
            credentials: Credentials::default(),
        }
    }
    fn env(&self) -> SyncEnv<'_> {
        let mut env = self.device.env();
        env.keychain = &self.credentials;
        env
    }
    fn prepared(&self) -> PreparedImport {
        prepare(
            &self.source,
            &ImportOptions::new(self.device.home.path().into()),
        )
        .unwrap()
    }
    fn with_copy(&self) -> PreparedImport {
        let mut prepared = self.prepared();
        let id = prepared.preview().key_references[0].key_id.clone();
        select_key_copy(&mut prepared, &id).unwrap();
        prepared
    }
    fn state(&self) -> crate::sync::records_v3::SyncStateV3 {
        self.device
            .runtime
            .core
            .lock()
            .unwrap()
            .records
            .clone()
            .unwrap()
    }
    fn imports(&self) -> PathBuf {
        self.env().state_path.parent().unwrap().join("imports")
    }
}
#[test]
fn cancelling_a_preview_and_explicit_key_selection_changes_nothing() {
    let fixture = Fixture::new();
    let before = fixture.state();
    let private = fs::read(&fixture.private).unwrap();
    let prepared = fixture.with_copy();
    assert!(!format!("{:?}", prepared.preview()).contains("BEGIN OPENSSH PRIVATE KEY"));
    drop(prepared);
    assert_eq!(fixture.state(), before);
    assert_eq!(fs::read(&fixture.private).unwrap(), private);
    assert!(!fixture.imports().exists());
    assert!(!vault_path(&fixture.env().state_path).exists());
    assert_eq!(fixture.credentials.writes.load(Ordering::SeqCst), 0);
}
#[test]
fn confirmation_rehashes_changed_configuration_before_any_journal_or_credential_write() {
    let fixture = Fixture::new();
    let prepared = fixture.prepared();
    fs::write(&fixture.source, "Host changed\n HostName changed.example\n").unwrap();
    assert!(confirm(&fixture.env(), prepared).is_err());
    assert!(!fixture.imports().exists());
    assert!(fixture.state().local.hosts.is_empty());
    assert_eq!(fixture.credentials.writes.load(Ordering::SeqCst), 0);
}
#[test]
fn empty_copy_selection_imports_local_hosts_without_vault_or_credential_writes() {
    let fixture = Fixture::new();
    let original = fs::read(&fixture.private).unwrap();
    let receipt = confirm(&fixture.env(), fixture.prepared()).unwrap();
    assert_eq!(receipt.host_ids.len(), 1);
    assert!(receipt.copied_key_ids.is_empty());
    assert_eq!(fixture.state().local.hosts.len(), 1);
    assert!(fixture.state().local.keys.is_empty());
    assert!(fixture.state().spaces.is_empty());
    assert!(!vault_path(&fixture.env().state_path).exists());
    assert_eq!(fixture.credentials.writes.load(Ordering::SeqCst), 0);
    assert_eq!(fs::read(&fixture.private).unwrap(), original);
    assert_eq!(
        resume(&fixture.env(), &receipt.import_id).unwrap().host_ids,
        receipt.host_ids
    );
}
#[test]
fn selected_copy_preserves_original_and_keeps_plaintext_out_of_state_journal_and_debug() {
    let fixture = Fixture::new();
    let private = fs::read_to_string(&fixture.private).unwrap();
    let prepared = fixture.with_copy();
    let receipt = confirm(&fixture.env(), prepared).unwrap();
    let state = fixture.state();
    assert_eq!(state.local.keys.len(), 1);
    assert_eq!(fs::read_to_string(&fixture.private).unwrap(), private);
    let material = &state.local.keys[&receipt.copied_key_ids[0]];
    let vault = read_vault(&vault_path(&fixture.env().state_path), &fixture.credentials).unwrap();
    assert_eq!(
        vault.get(&material.vault_id).unwrap().unwrap().private_key,
        private
    );
    let journal = fs::read_to_string(
        fixture
            .imports()
            .join(&receipt.import_id)
            .join("journal.json"),
    )
    .unwrap();
    for text in [
        journal,
        serde_json::to_string(&state).unwrap(),
        format!("{state:?}"),
        format!("{receipt:?}"),
    ] {
        assert!(!text.contains("BEGIN OPENSSH PRIVATE KEY"));
        assert!(!text.contains(private.lines().nth(1).unwrap()));
    }
    assert_eq!(fixture.credentials.deletes.load(Ordering::SeqCst), 0);
}
#[test]
fn a_changed_selected_private_source_invalidates_confirmation_without_mutation() {
    let fixture = Fixture::new();
    let prepared = fixture.with_copy();
    fs::write(&fixture.private, test_keys::ecdsa()).unwrap();
    assert!(confirm(&fixture.env(), prepared).is_err());
    assert!(!fixture.imports().exists());
    assert!(fixture.state().local.hosts.is_empty());
    assert_eq!(fixture.credentials.writes.load(Ordering::SeqCst), 0);
}
#[test]
fn corrupt_and_keyless_original_vaults_remain_original_on_refusal() {
    for bytes in [b"invalid vault".to_vec(), br#"{"version":2,"key_account":"vault:key:0123456789abcdef","entries":{"old":{"nonce":"AA==","ciphertext":"AA=="}}}"#.to_vec()] {
        let fixture = Fixture::new();
        let path = vault_path(&fixture.env().state_path);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(&path, &bytes).unwrap();
        assert!(confirm(&fixture.env(), fixture.with_copy()).is_err());
        assert_eq!(fs::read(&path).unwrap(), bytes);
        assert!(!fs::read_dir(path.parent().unwrap()).unwrap().any(|entry| { let name = entry.unwrap().file_name(); let name = name.to_string_lossy(); name.starts_with("vault.unreadable") || name.starts_with("vault.keyless") }));
        assert_eq!(fixture.credentials.writes.load(Ordering::SeqCst), 0);
        assert!(fixture.state().local.hosts.is_empty());
    }
}
#[test]
fn new_master_promotion_failure_keeps_a_resumable_journal_and_staged_material() {
    let fixture = Fixture::new();
    fixture
        .credentials
        .fail_promotion
        .store(true, Ordering::SeqCst);
    let error = confirm(&fixture.env(), fixture.with_copy()).unwrap_err();
    assert!(!error.to_string().contains("PRIVATE_SENTINEL"));
    assert!(fixture.state().local.hosts.is_empty());
    assert!(!vault_path(&fixture.env().state_path).exists());
    let id = fs::read_dir(fixture.imports())
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .file_name()
        .to_string_lossy()
        .into_owned();
    assert!(fixture.imports().join(&id).join("vault.json").exists());
    fixture
        .credentials
        .fail_promotion
        .store(false, Ordering::SeqCst);
    assert_eq!(resume(&fixture.env(), &id).unwrap().copied_key_ids.len(), 1);
    assert_eq!(fixture.state().local.hosts.len(), 1);
}
#[test]
fn virtual_relay_labels_are_never_opened_as_local_import_sources() {
    assert!(prepare(
        Path::new("relay:space:host"),
        &ImportOptions::new(PathBuf::from("/tmp"))
    )
    .is_err());
}
#[test]
fn every_publication_boundary_can_resume_the_same_ids_without_source_deletion() {
    for stop in [
        PublishStep::JournalPrepared,
        PublishStep::VaultStaged,
        PublishStep::Staged,
        PublishStep::MasterPromoted,
        PublishStep::VaultSaved,
        PublishStep::BeforeStateSave,
        PublishStep::StateSaved,
    ] {
        let fixture = Fixture::new();
        let prepared = fixture.with_copy();
        let host_id = prepared.preview().candidates[0].id.clone();
        let private = fs::read(&fixture.private).unwrap();
        let result = with_test_step(
            move |step| {
                if step == stop {
                    Err(failure("simulated interruption"))
                } else {
                    Ok(())
                }
            },
            || confirm(&fixture.env(), prepared),
        );
        assert!(result.is_err(), "{stop:?}");
        let id = fs::read_dir(fixture.imports())
            .unwrap()
            .next()
            .unwrap()
            .unwrap()
            .file_name()
            .to_string_lossy()
            .into_owned();
        let receipt = resume(&fixture.env(), &id).unwrap();
        assert_eq!(receipt.host_ids, [host_id]);
        assert_eq!(fixture.state().local.hosts.len(), 1);
        assert_eq!(fixture.state().local.keys.len(), 1);
        assert_eq!(fs::read(&fixture.private).unwrap(), private);
        assert_eq!(resume(&fixture.env(), &id).unwrap(), receipt);
        assert_eq!(fixture.credentials.deletes.load(Ordering::SeqCst), 0);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            for path in [
                fixture.env().state_path,
                vault_path(&fixture.env().state_path),
                fixture.imports().join(&id).join("journal.json"),
            ] {
                assert_eq!(
                    fs::metadata(path).unwrap().permissions().mode() & 0o777,
                    0o600
                );
            }
        }
    }
}
#[test]
fn failed_main_state_save_leaves_generation_memory_and_encrypted_material_recoverable() {
    let fixture = std::sync::Arc::new(Fixture::new());
    let before = fixture.state();
    let generation = fixture.device.runtime.core.lock().unwrap().generation;
    let path = fixture.env().state_path;
    let hook_path = path.clone();
    let result = with_test_step(
        move |step| {
            if step == PublishStep::BeforeStateSave {
                fs::create_dir(&hook_path).unwrap();
            }
            Ok(())
        },
        || confirm(&fixture.env(), fixture.with_copy()),
    );
    assert!(result.is_err());
    assert_eq!(fixture.state(), before);
    assert_eq!(
        fixture.device.runtime.core.lock().unwrap().generation,
        generation
    );
    assert!(vault_path(&path).exists());
    let id = fs::read_dir(fixture.imports())
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .file_name()
        .to_string_lossy()
        .into_owned();
    let journal: Journal = serde_json::from_slice(
        &fs::read(fixture.imports().join(&id).join("journal.json")).unwrap(),
    )
    .unwrap();
    assert_eq!(journal.phase, Phase::VaultPublished);
    fs::remove_dir(&path).unwrap(); // Only the empty test fault directory.
    resume(&fixture.env(), &id).unwrap();
    assert_eq!(fixture.state().local.hosts.len(), 1);
}
#[test]
fn concurrent_host_crud_is_rebased_after_vault_staging_and_generation_races() {
    for stop in [PublishStep::Staged, PublishStep::BeforeStateSave] {
        let fixture = std::sync::Arc::new(Fixture::new());
        let hook_fixture = fixture.clone();
        let mut unrelated = fixture.prepared().preview().candidates[0].payload.clone();
        unrelated.alias = "unrelated".into();
        unrelated.hostname = "concurrent.example".into();
        unrelated.auth = crate::sync::records_v3::AuthKind::Interactive;
        unrelated.key_id = None;
        let mut once = false;
        let receipt = with_test_step(
            move |step| {
                if step == stop && !once {
                    once = true;
                    record_runtime::mutate_records(&hook_fixture.env(), |state| {
                        let mut next = crate::sync::record_repository::create_host(
                            state,
                            &"f".repeat(16),
                            HostScope::Local,
                            unrelated.clone(),
                            1,
                        )
                        .map_err(|_| failure("fixture concurrent host creation failed"))?;
                        next.device_name = "Concurrent user edit".into();
                        Ok(next)
                    })
                    .unwrap();
                }
                Ok(())
            },
            || confirm(&fixture.env(), fixture.with_copy()),
        )
        .unwrap();
        assert_eq!(receipt.host_ids.len(), 1);
        assert_eq!(fixture.state().device_name, "Concurrent user edit");
        assert_eq!(fixture.state().local.hosts.len(), 2);
        assert_eq!(
            fixture.state().local.hosts[&record_key(RecordKind::Host, &"f".repeat(16))]
                .record
                .payload["hostname"],
            "concurrent.example"
        );
        assert!(fixture.device.runtime.core.lock().unwrap().generation >= 2);
    }
}
#[test]
fn retries_preserve_post_publication_host_edits_and_tombstones() {
    for delete in [false, true] {
        let fixture = Fixture::new();
        let prepared = fixture.prepared();
        let host_id = prepared.preview().candidates[0].id.clone();
        assert!(with_test_step(
            |step| if step == PublishStep::StateSaved {
                Err(failure("receipt interrupted"))
            } else {
                Ok(())
            },
            || confirm(&fixture.env(), prepared)
        )
        .is_err());
        record_runtime::mutate_records(&fixture.env(), |state| {
            let mut next = state.clone();
            let row = next
                .local
                .hosts
                .get_mut(&record_key(RecordKind::Host, &host_id))
                .unwrap();
            row.record.version += 1;
            row.record.updated_at_ms += 1;
            row.record.deleted = delete;
            if !delete {
                row.record.payload["hostname"] = serde_json::json!("edited.example");
            }
            Ok(next)
        })
        .unwrap();
        let edited = fixture.state();
        let id = fs::read_dir(fixture.imports())
            .unwrap()
            .next()
            .unwrap()
            .unwrap()
            .file_name()
            .to_string_lossy()
            .into_owned();
        resume(&fixture.env(), &id).unwrap();
        assert_eq!(fixture.state(), edited);
    }
}
#[test]
fn alias_and_host_id_collisions_are_rejected_before_staging_or_credentials() {
    for same_id in [false, true] {
        let fixture = Fixture::new();
        let prepared = fixture.with_copy();
        let mut host = prepared.preview().candidates[0].clone();
        if !same_id {
            host.id = "f".repeat(16);
        } else {
            host.payload.alias = "another".into();
        }
        host.payload.imported = None;
        record_runtime::mutate_records(&fixture.env(), |state| {
            crate::sync::record_repository::create_host(
                state,
                &host.id,
                HostScope::Local,
                host.payload.clone(),
                1,
            )
            .map_err(|_| failure("fixture host creation failed"))
        })
        .unwrap();
        let before = fixture.state();
        assert!(confirm(&fixture.env(), prepared).is_err());
        assert_eq!(fixture.state(), before);
        assert!(!fixture.imports().exists());
        assert_eq!(fixture.credentials.writes.load(Ordering::SeqCst), 0);
    }
}
#[test]
fn original_vault_entries_settings_bytes_and_master_are_retained() {
    let fixture = Fixture::new();
    let path = vault_path(&fixture.env().state_path);
    let old_id = "e".repeat(32);
    let old_private = test_keys::ecdsa();
    let key = crate::vault::material::parse(&old_private).unwrap();
    let entry = crate::vault::store::VaultEntry {
        private_key: old_private,
        public_key: key.public_key().to_openssh().unwrap(),
        fingerprint: key
            .public_key()
            .fingerprint(ssh_key::HashAlg::Sha256)
            .to_string(),
        origin: crate::vault::store::EntryOrigin::Generated,
        added_at_ms: 1,
    };
    let mut original = Vault::open(&path, &fixture.credentials, 1).unwrap();
    original.put(&fixture.credentials, &old_id, &entry).unwrap();
    original
        .set_settings(crate::vault::store::AgentSettings {
            remember_minutes: 9,
            always_ask: true,
        })
        .unwrap();
    let bytes = fs::read(&path).unwrap();
    let view = read_vault(&path, &fixture.credentials).unwrap();
    let account = view.key_account().to_string();
    let master = fixture.credentials.inner.entry(&account).unwrap();
    fixture.credentials.writes.store(0, Ordering::SeqCst);
    let receipt = confirm(&fixture.env(), fixture.with_copy()).unwrap();
    let now = read_vault(&path, &fixture.credentials).unwrap();
    assert_eq!(now.ids().len(), 2);
    assert_eq!(now.get(&old_id).unwrap().unwrap(), entry);
    assert_eq!(now.settings(), view.settings());
    assert_eq!(now.key_account(), account);
    assert_eq!(fixture.credentials.inner.entry(&account).unwrap(), master);
    assert_eq!(fixture.credentials.writes.load(Ordering::SeqCst), 0);
    assert_eq!(fixture.credentials.deletes.load(Ordering::SeqCst), 0);
    assert_eq!(
        fs::read(
            fixture
                .imports()
                .join(receipt.import_id)
                .join("original-vault.json")
        )
        .unwrap(),
        bytes
    );
}
#[test]
fn a_differing_promotion_credential_is_never_overwritten_or_deleted() {
    let fixture = std::sync::Arc::new(Fixture::new());
    let hook_fixture = fixture.clone();
    assert!(with_test_step(
        move |step| {
            if step == PublishStep::Staged {
                let id = fs::read_dir(hook_fixture.imports())
                    .unwrap()
                    .next()
                    .unwrap()
                    .unwrap()
                    .file_name();
                let header: serde_json::Value = serde_json::from_slice(
                    &fs::read(hook_fixture.imports().join(id).join("vault.json")).unwrap(),
                )
                .unwrap();
                hook_fixture
                    .credentials
                    .inner
                    .set(
                        header["key_account"].as_str().unwrap(),
                        "differing preserved credential",
                    )
                    .unwrap();
            }
            Ok(())
        },
        || confirm(&fixture.env(), fixture.with_copy())
    )
    .is_err());
    let id = fs::read_dir(fixture.imports())
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .file_name();
    let header: serde_json::Value =
        serde_json::from_slice(&fs::read(fixture.imports().join(id).join("vault.json")).unwrap())
            .unwrap();
    assert_eq!(
        fixture
            .credentials
            .inner
            .entry(header["key_account"].as_str().unwrap())
            .unwrap(),
        "differing preserved credential"
    );
    assert!(!vault_path(&fixture.env().state_path).exists());
    assert!(fixture.state().local.hosts.is_empty());
    assert_eq!(fixture.credentials.deletes.load(Ordering::SeqCst), 0);
}
#[test]
fn journals_never_persist_unused_explicit_environment_values() {
    let fixture = Fixture::new();
    let mut options = ImportOptions::new(fixture.device.home.path().into());
    options
        .env
        .insert("UNUSED_SECRET".into(), "passphrase_PRIVATE_SENTINEL".into());
    let prepared = prepare(&fixture.source, &options).unwrap();
    assert!(!format!("{prepared:?}").contains("PRIVATE_SENTINEL"));
    let receipt = confirm(&fixture.env(), prepared).unwrap();
    let journal = fs::read_to_string(
        fixture
            .imports()
            .join(receipt.import_id)
            .join("journal.json"),
    )
    .unwrap();
    assert!(!journal.contains("PRIVATE_SENTINEL"));
    assert!(!journal.contains("UNUSED_SECRET"));
}
#[test]
fn unsupported_or_oversized_private_sources_are_refused_without_a_journal() {
    let fixture = Fixture::new();
    for private in [
        test_keys::security_key(),
        test_keys::encrypted_with_3des_label(),
        "-----BEGIN RSA PRIVATE KEY-----\\nPRIVATE_SENTINEL".into(),
    ] {
        fs::write(&fixture.private, private).unwrap();
        let mut prepared = fixture.prepared();
        let id = prepared.preview().key_references[0].key_id.clone();
        let error = select_key_copy(&mut prepared, &id).unwrap_err();
        assert!(!error.to_string().contains("PRIVATE_SENTINEL"));
        assert!(!fixture.imports().exists());
    }
    fs::File::create(&fixture.private)
        .unwrap()
        .set_len(MAX_PRIVATE_SOURCE_BYTES + 1)
        .unwrap();
    let mut prepared = fixture.prepared();
    let id = prepared.preview().key_references[0].key_id.clone();
    assert!(select_key_copy(&mut prepared, &id).is_err());
    assert!(!fixture.imports().exists());
}
#[test]
fn partial_staging_cannot_replace_a_vault_that_changed_before_resume() {
    let fixture = Fixture::new();
    assert!(with_test_step(
        |step| if step == PublishStep::VaultStaged {
            Err(failure("stage receipt interrupted"))
        } else {
            Ok(())
        },
        || confirm(&fixture.env(), fixture.with_copy())
    )
    .is_err());
    let path = vault_path(&fixture.env().state_path);
    let text = test_keys::ecdsa();
    let key = crate::vault::material::parse(&text).unwrap();
    let entry = VaultEntry {
        private_key: text,
        public_key: key.public_key().to_openssh().unwrap(),
        fingerprint: key
            .public_key()
            .fingerprint(ssh_key::HashAlg::Sha256)
            .to_string(),
        origin: EntryOrigin::Generated,
        added_at_ms: 1,
    };
    let mut original = Vault::open(&path, &fixture.credentials, 1).unwrap();
    original
        .put(&fixture.credentials, &"e".repeat(32), &entry)
        .unwrap();
    let bytes = fs::read(&path).unwrap();
    let id = fs::read_dir(fixture.imports())
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .file_name()
        .to_string_lossy()
        .into_owned();
    assert!(resume(&fixture.env(), &id).is_err());
    assert_eq!(fs::read(&path).unwrap(), bytes);
    assert!(fixture.state().local.hosts.is_empty());
}
#[test]
fn retry_refuses_when_already_published_material_was_removed_before_state_activation() {
    let fixture = Fixture::new();
    let prepared = fixture.with_copy();
    let key_id = prepared.preview().key_references[0].key_id.clone();
    assert!(with_test_step(
        |step| if step == PublishStep::BeforeStateSave {
            Err(failure("state publication interrupted"))
        } else {
            Ok(())
        },
        || confirm(&fixture.env(), prepared)
    )
    .is_err());
    let main = vault_path(&fixture.env().state_path);
    let mut vault = Vault::open(&main, &fixture.credentials, 1).unwrap();
    vault.remove(&key_id).unwrap();
    let bytes = fs::read(&main).unwrap();
    let id = fs::read_dir(fixture.imports())
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .file_name()
        .to_string_lossy()
        .into_owned();
    assert!(resume(&fixture.env(), &id).is_err());
    assert_eq!(fs::read(&main).unwrap(), bytes);
    assert!(fixture.state().local.hosts.is_empty());
    assert!(fixture.state().local.keys.is_empty());
}
#[test]
fn atomic_state_receipt_preserves_removed_keys_and_reviewed_hosts_after_receipt_crash() {
    let fixture = Fixture::new();
    let prepared = fixture.with_copy();
    let host_id = prepared.preview().candidates[0].id.clone();
    let key_id = prepared.preview().key_references[0].key_id.clone();
    assert!(with_test_step(
        |step| if step == PublishStep::StateSaved {
            Err(failure("journal receipt interrupted"))
        } else {
            Ok(())
        },
        || confirm(&fixture.env(), prepared)
    )
    .is_err());
    let id = fs::read_dir(fixture.imports())
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .file_name()
        .to_string_lossy()
        .into_owned();
    assert!(fixture.state().local.import_receipts.contains_key(&id));
    record_runtime::mutate_records(&fixture.env(), |state| {
        let mut next = state.clone();
        next.local.keys.remove(&key_id);
        let host = next
            .local
            .hosts
            .get_mut(&record_key(RecordKind::Host, &host_id))
            .unwrap();
        host.record.payload["imported"] = serde_json::Value::Null;
        host.record.payload["notes"] = serde_json::json!("Reviewed by the user");
        host.record.version += 1;
        host.record.updated_at_ms += 1;
        Ok(next)
    })
    .unwrap();
    let main = vault_path(&fixture.env().state_path);
    Vault::open(&main, &fixture.credentials, 1)
        .unwrap()
        .remove(&key_id)
        .unwrap();
    let state = fixture.state();
    let bytes = fs::read(&main).unwrap();
    resume(&fixture.env(), &id).unwrap();
    assert_eq!(fixture.state(), state);
    assert_eq!(fs::read(&main).unwrap(), bytes);
    assert!(fixture.state().local.keys.is_empty());
}
#[test]
fn even_identical_existing_host_ids_are_collisions_without_an_atomic_import_receipt() {
    let fixture = Fixture::new();
    let prepared = fixture.with_copy();
    let host = prepared.preview().candidates[0].clone();
    record_runtime::mutate_records(&fixture.env(), |state| {
        crate::sync::record_repository::create_host(
            state,
            &host.id,
            HostScope::Local,
            host.payload.clone(),
            u64::MAX - 10,
        )
        .map_err(|_| failure("fixture host creation failed"))
    })
    .unwrap();
    let before = fixture.state();
    assert!(confirm(&fixture.env(), prepared).is_err());
    assert_eq!(fixture.state(), before);
    assert!(!fixture.imports().exists());
    assert_eq!(fixture.credentials.writes.load(Ordering::SeqCst), 0);
}
#[test]
fn blocked_writes_and_exhausted_generation_refuse_before_journal_vault_or_credentials() {
    for exhausted in [false, true] {
        let fixture = Fixture::new();
        let prepared = fixture.with_copy();
        {
            let mut core = fixture.device.runtime.core.lock().unwrap();
            if exhausted {
                core.generation = u64::MAX;
            } else {
                core.save_blocked = Some("write blocked".into());
            }
        }
        assert!(confirm(&fixture.env(), prepared).is_err());
        assert!(!fixture.imports().exists());
        assert!(!vault_path(&fixture.env().state_path).exists());
        assert!(fixture.state().local.hosts.is_empty());
        assert_eq!(fixture.credentials.writes.load(Ordering::SeqCst), 0);
    }
}
#[test]
fn pending_discovery_is_bounded_public_and_reads_no_credentials_or_private_sources() {
    let fixture = Fixture::new();
    assert!(pending_imports(&fixture.env()).unwrap().is_empty());
    assert!(!fixture.imports().exists());
    assert!(with_test_step(
        |step| if step == PublishStep::BeforeStateSave {
            Err(failure("state publication interrupted"))
        } else {
            Ok(())
        },
        || confirm(&fixture.env(), fixture.with_copy())
    )
    .is_err());
    fixture.credentials.reads.store(0, Ordering::SeqCst);
    let writes = fixture.credentials.writes.load(Ordering::SeqCst);
    fs::write(&fixture.private, "private source no longer available").unwrap();
    let pending = pending_imports(&fixture.env()).unwrap();
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].phase, "vault_published");
    assert_eq!(pending[0].host_count, 1);
    assert_eq!(pending[0].key_count, 1);
    assert_eq!(fixture.credentials.reads.load(Ordering::SeqCst), 0);
    assert_eq!(fixture.credentials.writes.load(Ordering::SeqCst), writes);
    assert!(!format!("{pending:?}").contains("PRIVATE KEY"));
    let journal = fixture
        .imports()
        .join(&pending[0].import_id)
        .join("journal.json");
    fs::OpenOptions::new()
        .write(true)
        .open(&journal)
        .unwrap()
        .set_len(MAX_JOURNAL_BYTES + 1)
        .unwrap();
    assert_eq!(pending_imports(&fixture.env()).unwrap()[0].phase, "invalid");
    assert_eq!(fs::metadata(journal).unwrap().len(), MAX_JOURNAL_BYTES + 1);
    assert_eq!(fixture.credentials.reads.load(Ordering::SeqCst), 0);
}
#[test]
fn encrypted_material_flag_and_public_identity_are_bound_to_selected_consent() {
    let fixture = Fixture::new();
    fs::write(&fixture.private, test_keys::encrypted()).unwrap();
    let prepared = fixture.with_copy();
    let key_id = prepared.preview().key_references[0].key_id.clone();
    assert!(prepared.selected_copies()[&key_id].has_passphrase);
    assert!(with_test_step(
        |step| if step == PublishStep::Staged {
            Err(failure("staged receipt interrupted"))
        } else {
            Ok(())
        },
        || confirm(&fixture.env(), prepared)
    )
    .is_err());
    let pending = pending_imports(&fixture.env()).unwrap();
    let path = fixture
        .imports()
        .join(&pending[0].import_id)
        .join("journal.json");
    let mut journal: Journal = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    journal.keys.get_mut(&key_id).unwrap().public.has_passphrase = false;
    fs::write(&path, serde_json::to_vec(&journal).unwrap()).unwrap();
    assert!(resume(&fixture.env(), &pending[0].import_id).is_err());
    assert!(!vault_path(&fixture.env().state_path).exists());
    assert!(fixture.state().local.keys.is_empty());
    assert_eq!(fixture.credentials.deletes.load(Ordering::SeqCst), 0);
}
#[test]
fn explicit_source_reads_are_allowed_outside_a_confined_profile_but_destinations_are_not() {
    let fixture = Fixture::new();
    let root = fixture.env().state_path.parent().unwrap().to_path_buf();
    let receipt = crate::fsutil::with_test_write_policy(
        crate::write_policy::WritePolicy::Confined { root: root.clone() },
        || confirm(&fixture.env(), fixture.with_copy()),
    )
    .unwrap();
    assert!(fixture.private.exists());
    assert_eq!(receipt.copied_key_ids.len(), 1);
    let denied = Fixture::new();
    let outside = tempfile::tempdir().unwrap();
    let mut env = denied.env();
    env.state_path = outside.path().join("sync-state.json");
    assert!(crate::fsutil::with_test_write_policy(
        crate::write_policy::WritePolicy::Confined { root },
        || confirm(&env, denied.with_copy())
    )
    .is_err());
    assert!(fs::read_dir(outside.path()).unwrap().next().is_none());
    assert_eq!(denied.credentials.writes.load(Ordering::SeqCst), 0);
}
