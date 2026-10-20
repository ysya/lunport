use super::*;
fn prepared() -> (
    crate::sync::testkit::TestDevice,
    InitialProjection,
    Staged,
    Zeroizing<Vec<u8>>,
    Option<Zeroizing<Vec<u8>>>,
) {
    let (d, initial) = super::super::initial_tests::fixture();
    let env = d.env();
    let before = bounded_read(&env.state_path, record_runtime::MAX_STATE_BYTES).unwrap();
    let vault = optional_bytes(
        &store::vault_path(&env.state_path),
        store::MAX_READ_ONLY_VAULT_BYTES,
    )
    .unwrap();
    let staged = prepare_initial(&env, &initial).unwrap();
    (d, initial, staged, before, vault)
}
#[test]
fn material_readback_proves_an_additive_image_and_rejects_changed_mappings_or_ciphertext() {
    for changed in ["mapping", "ciphertext", "original", "master"] {
        let (d, initial, staged, state, vault) = prepared();
        let env = d.env();
        let proof = from_stage(
            &env,
            &initial,
            staged.operation(),
            &state,
            vault.as_ref().map(|b| b.as_slice()),
        )
        .unwrap();
        proof.matches(&initial, staged.operation()).unwrap();
        assert!(proof.replacement().is_none());
        let (other, _) = crate::sync::central::initial_projection_for_test();
        assert!(proof.matches(&other, staged.operation()).is_err());
        if changed == "mapping" {
            let mut journal: Journal = serde_json::from_slice(
                &bounded_read(&staged.paths.journal, MAX_JOURNAL_BYTES).unwrap(),
            )
            .unwrap();
            journal.bindings.values_mut().next().unwrap().protected_id = "9".repeat(32);
            save(&staged.paths, &journal).unwrap();
        } else if changed == "ciphertext" {
            fs::write(&staged.paths.vault, b"changed staged ciphertext").unwrap();
        } else if changed == "original" {
            fs::write(&staged.paths.original_vault, b"changed original bytes").unwrap();
        } else {
            fs::write(&staged.paths.masters, b"[\"an-unrelated-credential-role\"]").unwrap();
        }
        assert!(from_stage(
            &env,
            &initial,
            staged.operation(),
            &state,
            vault.as_ref().map(|b| b.as_slice())
        )
        .is_err());
    }
}
#[test]
fn a_prepared_phase_proves_only_its_existing_whitelisted_outputs() {
    use crate::sync::record_import::{with_test_step, PublishStep};
    let (d, initial) = super::super::initial_tests::fixture();
    let env = d.env();
    let state = bounded_read(&env.state_path, record_runtime::MAX_STATE_BYTES).unwrap();
    let vault = optional_bytes(
        &store::vault_path(&env.state_path),
        store::MAX_READ_ONLY_VAULT_BYTES,
    )
    .unwrap();
    assert!(with_test_step(
        |step| if step == PublishStep::JournalPrepared {
            Err(failure("synthetic first journal stop"))
        } else {
            Ok(())
        },
        || prepare_initial(&env, &initial)
    )
    .is_err());
    let pending = super::super::super::pending_imports(&env).unwrap();
    let operation = &pending[0].import_id;
    let proof = from_stage(
        &env,
        &initial,
        operation,
        &state,
        vault.as_ref().map(|b| b.as_slice()),
    )
    .unwrap();
    assert_eq!(proof.files().count(), 1);
    assert!(proof.replacement().is_none());
    let path = Paths::new(&env, operation)
        .unwrap()
        .dir
        .join("unknown-source");
    fs::write(&path, b"retained B").unwrap();
    assert!(from_stage(
        &env,
        &initial,
        operation,
        &state,
        vault.as_ref().map(|b| b.as_slice())
    )
    .is_err());
    assert!(path.exists());
}

#[test]
fn a_first_scoped_master_must_exist_and_be_promoted_before_the_active_image_is_proved() {
    use crate::sync::{
        env::Keychain,
        fake_relay::FakeRelay,
        testkit::{TestClock, TestDevice},
    };
    let initial = crate::sync::central::initial_fresh_projection_for_test();
    let d = TestDevice::new("fresh-effects", &FakeRelay::new(), &TestClock::new());
    let env = d.env();
    record_runtime::save_active(&env.state_path, initial.source()).unwrap();
    let probe = record_runtime::probe_startup(&env.state_path, "fresh-effects");
    record_runtime::activate_probe(&mut d.runtime.core.lock().unwrap(), probe).unwrap();
    let state = bounded_read(&env.state_path, record_runtime::MAX_STATE_BYTES).unwrap();
    let staged = prepare_initial(&env, &initial).unwrap();
    let account = staged.journal.staged_key_account.as_ref().unwrap();
    let proof = from_stage(&env, &initial, staged.operation(), &state, None).unwrap();
    assert!(proof.replacement().is_none());
    fs::write(
        store::vault_path(&env.state_path),
        bounded_read(&staged.paths.vault, store::MAX_READ_ONLY_VAULT_BYTES).unwrap(),
    )
    .unwrap();
    assert!(from_stage(&env, &initial, staged.operation(), &state, None).is_err());
    assert!(d.keychain.entry(account).is_none());
    let scoped = ScopedKeychain {
        inner: &d.keychain,
        import_id: staged.operation(),
        receipts: &staged.paths.masters,
    };
    scoped.promote(account).unwrap();
    assert!(from_stage(&env, &initial, staged.operation(), &state, None)
        .unwrap()
        .replacement()
        .is_some());
    d.keychain.delete(&scoped.scoped(account).unwrap()).unwrap();
    assert!(from_stage(&env, &initial, staged.operation(), &state, None).is_err());
    assert!(d.keychain.entry(&scoped.scoped(account).unwrap()).is_none());
    assert!(record_runtime::snapshot(&env).unwrap().0 == *initial.source());
}
