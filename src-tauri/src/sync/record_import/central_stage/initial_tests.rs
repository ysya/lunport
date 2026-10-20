use super::*;
use crate::sync::{
    central::{initial_projection_for_test, InitialProjection},
    env::Keychain,
    fake_relay::FakeRelay,
    testkit::{TestClock, TestDevice},
};
pub(super) fn fixture() -> (TestDevice, InitialProjection) {
    let (initial, _) = initial_projection_for_test();
    let device = TestDevice::new("initial-stage", &FakeRelay::new(), &TestClock::new());
    record_runtime::save_active(&device.env().state_path, initial.source()).unwrap();
    let probe = record_runtime::probe_startup(&device.env().state_path, "initial-stage");
    record_runtime::activate_probe(&mut device.runtime.core.lock().unwrap(), probe).unwrap();
    let material = &initial.delta().plan().materials()[&"1".repeat(32)];
    let mut vault = Vault::open(
        &store::vault_path(&device.env().state_path),
        &device.keychain,
        100,
    )
    .unwrap();
    vault
        .put_new_batch(
            &device.keychain,
            &BTreeMap::from([(
                "3".repeat(32),
                VaultEntry {
                    private_key: material.private().private().to_owned(),
                    public_key: material.metadata.public.public_key.clone(),
                    fingerprint: material.metadata.public.fingerprint.clone(),
                    origin: EntryOrigin::Synced,
                    added_at_ms: 100,
                },
            )]),
        )
        .unwrap();
    (device, initial)
}
struct NoPrompt<'a>(&'a dyn Keychain);
impl Keychain for NoPrompt<'_> {
    fn get(&self, _: &str) -> Result<Option<String>, AppError> {
        panic!("foreground credential read");
    }
    fn set(&self, _: &str, _: &str) -> Result<(), AppError> {
        panic!("foreground credential write");
    }
    fn delete(&self, _: &str) -> Result<(), AppError> {
        panic!("credential delete");
    }
    fn get_noninteractive(&self, account: &str) -> Result<Option<String>, AppError> {
        self.0.get_noninteractive(account)
    }
    fn set_noninteractive(&self, account: &str, secret: &str) -> Result<(), AppError> {
        self.0.set_noninteractive(account, secret)
    }
}
#[test]
fn initial_stage_archives_actual_source_and_preserves_every_active_vault_byte_without_prompts() {
    let (device, initial) = fixture();
    let guard = NoPrompt(&device.keychain);
    let mut env = device.env();
    env.keychain = &guard;
    let before = fs::read(&env.state_path).unwrap();
    let vault_before = fs::read(store::vault_path(&env.state_path)).unwrap();
    let staged = prepare_initial(&env, &initial).unwrap();
    assert!(staged.journal.initial.is_some());
    assert_eq!(staged.summary().phase, "central_staged");
    assert_eq!(staged.mapping().len(), 1);
    assert_ne!(staged.mapping()[&"1".repeat(32)], "3".repeat(32));
    assert_eq!(fs::read(&staged.paths.original_state).unwrap(), before);
    assert_eq!(fs::read(&env.state_path).unwrap(), before);
    assert_eq!(
        fs::read(store::vault_path(&env.state_path)).unwrap(),
        vault_before
    );
    let archived: SyncStateV3 =
        serde_json::from_slice(&fs::read(&staged.paths.original_state).unwrap()).unwrap();
    assert!(!archived.local.central.as_ref().unwrap().control.cutover);
    assert!(archived.local.central_projection.is_none());
    assert_eq!(
        archived.local.keys[&"1".repeat(32)].vault_id,
        "3".repeat(32)
    );
    let background = crate::sync::env::NonInteractiveKeychain(env.keychain);
    let scoped = ScopedKeychain {
        inner: &background,
        import_id: staged.operation(),
        receipts: &staged.paths.masters,
    };
    // The old vault's master is reused; all new data is still inert in a separate encrypted file.
    let view = validate_vault(&staged.paths.vault, &scoped).unwrap();
    let old = view.get(&"3".repeat(32)).unwrap().unwrap();
    let new = view
        .get(&staged.mapping()[&"1".repeat(32)])
        .unwrap()
        .unwrap();
    assert_eq!(old.private_key, new.private_key);
    assert_eq!(view.ids().len(), 2);
    let staged_bytes = fs::read(&staged.paths.vault).unwrap();
    let resumed = resume_initial(&env, staged.operation(), &initial).unwrap();
    assert_eq!(resumed.mapping(), staged.mapping());
    assert_eq!(fs::read(&resumed.paths.vault).unwrap(), staged_bytes);
    assert!(publish(
        &env,
        staged.operation(),
        &super::super::super::central::crypto::VaultKeys::generate().unwrap()
    )
    .is_err());
    assert!(record_runtime::snapshot(&env).unwrap().0 == *initial.source());
}
#[test]
fn initial_journal_cannot_be_resumed_as_an_ordinary_delta_or_a_different_initial_plan() {
    let (device, initial) = fixture();
    let env = device.env();
    let staged = prepare_initial(&env, &initial).unwrap();
    assert!(resume(&env, staged.operation(), initial.delta()).is_err());
    let (different, _) = initial_projection_for_test();
    assert!(resume_initial(&env, staged.operation(), &different).is_err());
    let mut journal: Journal =
        serde_json::from_slice(&fs::read(&staged.paths.journal).unwrap()).unwrap();
    let mut changed = serde_json::to_value(journal.initial.as_ref().unwrap()).unwrap();
    changed["manifest"] = serde_json::Value::String("f".repeat(64));
    journal.initial = Some(serde_json::from_value(changed).unwrap());
    save(&staged.paths, &journal).unwrap();
    assert!(resume_initial(&env, staged.operation(), &initial).is_err());
    assert!(
        !record_runtime::snapshot(&env)
            .unwrap()
            .0
            .local
            .central
            .unwrap()
            .control
            .cutover
    );
}
#[test]
fn source_b_after_staging_blocks_retry_and_retains_both_original_and_staged_material() {
    let (device, initial) = fixture();
    let env = device.env();
    let staged = prepare_initial(&env, &initial).unwrap();
    let staged_bytes = fs::read(&staged.paths.vault).unwrap();
    record_runtime::mutate_records(&env, |state| {
        let mut next = state.clone();
        next.device_name = "late local B".into();
        Ok(next)
    })
    .unwrap();
    assert!(resume_initial(&env, staged.operation(), &initial).is_err());
    assert_eq!(
        record_runtime::snapshot(&env).unwrap().0.device_name,
        "late local B"
    );
    assert_eq!(fs::read(&staged.paths.vault).unwrap(), staged_bytes);
    assert!(
        validate_vault(&store::vault_path(&env.state_path), env.keychain)
            .unwrap()
            .get(&"3".repeat(32))
            .unwrap()
            .is_some()
    );
}

#[test]
fn unavailable_noninteractive_master_blocks_before_any_initial_stage_or_source_write() {
    use std::sync::atomic::Ordering;
    let (device, initial) = fixture();
    let before = fs::read(&device.env().state_path).unwrap();
    let original_vault = fs::read(store::vault_path(&device.env().state_path)).unwrap();
    device.keychain.fail_reads.store(true, Ordering::SeqCst);
    let guard = NoPrompt(&device.keychain);
    let mut env = device.env();
    env.keychain = &guard;
    assert!(prepare_initial(&env, &initial).is_err());
    assert_eq!(fs::read(&env.state_path).unwrap(), before);
    assert_eq!(
        fs::read(store::vault_path(&env.state_path)).unwrap(),
        original_vault
    );
    assert!(super::super::pending_imports(&env).unwrap().is_empty());
}

#[test]
fn interruptions_keep_the_same_initial_operation_mapping_and_ciphertext_on_resume() {
    use crate::sync::record_import::{with_test_step, PublishStep};
    for stop in [PublishStep::JournalPrepared, PublishStep::VaultStaged] {
        let (device, initial) = fixture();
        let env = device.env();
        let original = fs::read(&env.state_path).unwrap();
        let result = with_test_step(
            move |step| {
                if step == stop {
                    Err(failure("synthetic interruption"))
                } else {
                    Ok(())
                }
            },
            || prepare_initial(&env, &initial),
        );
        assert!(result.is_err());
        let pending = super::super::pending_imports(&env).unwrap();
        assert_eq!(pending.len(), 1);
        let operation = &pending[0].import_id;
        let paths = Paths::new(&env, operation).unwrap();
        let journal: Journal = serde_json::from_slice(&fs::read(&paths.journal).unwrap()).unwrap();
        let staged_bytes = paths
            .vault
            .exists()
            .then(|| fs::read(&paths.vault).unwrap());
        let staged = resume_initial(&env, operation, &initial).unwrap();
        assert_eq!(
            staged.mapping(),
            journal
                .bindings
                .iter()
                .map(|(id, b)| (id.clone(), b.protected_id.clone()))
                .collect()
        );
        if let Some(bytes) = staged_bytes {
            assert_eq!(fs::read(&paths.vault).unwrap(), bytes);
        }
        assert_eq!(fs::read(&env.state_path).unwrap(), original);
        assert!(
            !record_runtime::snapshot(&env)
                .unwrap()
                .0
                .local
                .central
                .unwrap()
                .control
                .cutover
        );
    }
}

#[test]
fn readback_can_form_only_an_inert_initial_candidate_and_the_ordinary_writer_rejects_it() {
    let (device, initial) = fixture();
    let env = device.env();
    let staged = prepare_initial(&env, &initial).unwrap();
    let before = initial.source().clone();
    let manifest = initial.manifest().to_owned();
    let view = validate_vault(
        &staged.paths.vault,
        &ScopedKeychain {
            inner: env.keychain,
            import_id: staged.operation(),
            receipts: &staged.paths.masters,
        },
    )
    .unwrap();
    let prepared = initial
        .finish(&view, &staged.mapping(), staged.operation())
        .unwrap();
    assert!(prepared.source() == &before);
    assert_eq!(prepared.manifest(), manifest);
    assert_eq!(
        prepared.candidate().local.keys[&"1".repeat(32)].vault_id,
        staged.mapping()[&"1".repeat(32)]
    );
    assert!(
        prepared
            .candidate()
            .local
            .central
            .as_ref()
            .unwrap()
            .control
            .cutover
    );
    assert!(record_runtime::commit_candidate(
        &env,
        record_runtime::snapshot(&env).unwrap().1,
        prepared.candidate().clone()
    )
    .is_err());
    assert!(record_runtime::snapshot(&env).unwrap().0 == before);
    assert!(
        !record_runtime::read_saved_records(&env.state_path)
            .unwrap()
            .local
            .central
            .unwrap()
            .control
            .cutover
    );
}
#[test]
fn an_initial_library_without_managed_private_keys_still_stages_without_creating_a_master() {
    let (initial, _) = crate::sync::central::initial_empty_projection_for_test();
    assert!(!initial.delta().has_changes());
    let device = TestDevice::new("empty-initial-stage", &FakeRelay::new(), &TestClock::new());
    let env = device.env();
    record_runtime::save_active(&env.state_path, initial.source()).unwrap();
    record_runtime::activate_probe(
        &mut device.runtime.core.lock().unwrap(),
        record_runtime::probe_startup(&env.state_path, "empty"),
    )
    .unwrap();
    let staged = prepare_initial(&env, &initial).unwrap();
    assert_eq!(staged.summary().phase, "central_staged");
    assert!(staged.mapping().is_empty());
    assert!(staged.journal.staged_key_account.is_none());
    assert!(!staged.paths.vault.exists());
    assert!(!store::vault_path(&env.state_path).exists());
    let resumed = resume_initial(&env, staged.operation(), &initial).unwrap();
    assert!(resumed.mapping().is_empty());
    assert!(record_runtime::snapshot(&env).unwrap().0 == *initial.source());
}

#[test]
fn initial_stage_can_create_its_first_scoped_vault_master_without_a_credential_prompt() {
    let initial = crate::sync::central::initial_fresh_projection_for_test();
    let device = TestDevice::new("fresh-initial-stage", &FakeRelay::new(), &TestClock::new());
    record_runtime::save_active(&device.env().state_path, initial.source()).unwrap();
    let probe = record_runtime::probe_startup(&device.env().state_path, "fresh-initial-stage");
    record_runtime::activate_probe(&mut device.runtime.core.lock().unwrap(), probe).unwrap();
    let guard = NoPrompt(&device.keychain);
    let mut env = device.env();
    env.keychain = &guard;
    let before = fs::read(&env.state_path).unwrap();
    assert!(!store::vault_path(&env.state_path).exists());
    let staged = prepare_initial(&env, &initial).unwrap();
    let account = staged.journal.staged_key_account.as_ref().unwrap();
    assert!(device
        .keychain
        .entry(&format!("migration:{}:{account}", staged.operation()))
        .is_some());
    assert!(device.keychain.entry(account).is_none());
    assert_eq!(fs::read(&env.state_path).unwrap(), before);
    assert!(!store::vault_path(&env.state_path).exists());
    let exact = fs::read(&staged.paths.vault).unwrap();
    let resumed = resume_initial(&env, staged.operation(), &initial).unwrap();
    assert_eq!(resumed.mapping(), staged.mapping());
    assert_eq!(fs::read(&resumed.paths.vault).unwrap(), exact);
}
