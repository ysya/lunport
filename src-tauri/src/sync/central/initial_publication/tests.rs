use super::*;
use crate::sync::{
    central::migration_dispatch, env::Keychain, record_runtime, testkit::MemKeychain,
};
use std::sync::atomic::{AtomicBool, Ordering};
fn make_private(env: &SyncEnv) {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(
        env.state_path.parent().unwrap(),
        std::fs::Permissions::from_mode(0o700),
    )
    .unwrap();
}

#[test]
fn first_publication_reservation_pins_one_stage_and_observation_without_changing_source_or_core() {
    let (d, keys, verified) = migration_dispatch::verified_fixture_for_test();
    let env = d.env();
    make_private(&env);
    let before = record_runtime::snapshot(&env).unwrap();
    let context = prepare(&env, verified, &keys).unwrap();
    let reservation = serde_json::to_vec(&context.reservation).unwrap();
    let shadow = serde_json::to_vec(context.initial.shadow()).unwrap();
    assert!(hex(context.operation(), 32));
    context.check(&env, &keys).unwrap();
    assert_eq!(record_runtime::snapshot(&env).unwrap(), before);
    d.runtime.core.lock().unwrap().generation = 0;
    let next = prepare(
        &env,
        migration_dispatch::verified_for_test(&env, &keys),
        &keys,
    )
    .unwrap();
    assert_eq!(serde_json::to_vec(&next.reservation).unwrap(), reservation);
    assert_eq!(serde_json::to_vec(next.initial.shadow()).unwrap(), shadow);
    assert!(
        !record_runtime::snapshot(&env)
            .unwrap()
            .0
            .local
            .central
            .as_ref()
            .unwrap()
            .control
            .cutover
    );
}
struct Fault<'a> {
    inner: &'a MemKeychain,
    role: String,
    after: bool,
    armed: AtomicBool,
}
impl Keychain for Fault<'_> {
    fn get(&self, k: &str) -> Result<Option<String>, AppError> {
        self.inner.get(k)
    }
    fn get_noninteractive(&self, k: &str) -> Result<Option<String>, AppError> {
        self.inner.get_noninteractive(k)
    }
    fn set(&self, k: &str, v: &str) -> Result<(), AppError> {
        self.inner.set(k, v)
    }
    fn delete(&self, _: &str) -> Result<(), AppError> {
        panic!("no deletion")
    }
    fn set_noninteractive(&self, k: &str, v: &str) -> Result<(), AppError> {
        let fail = k == self.role && self.armed.swap(false, Ordering::SeqCst);
        if fail && !self.after {
            return Err(invalid());
        }
        self.inner.set_noninteractive(k, v)?;
        if fail && self.after {
            return Err(invalid());
        }
        Ok(())
    }
}
#[test]
fn reservation_write_failure_before_or_after_persistence_has_no_material_effect_and_reuses_saved_identity(
) {
    for after in [false, true] {
        let (d, keys, verified) = migration_dispatch::verified_fixture_for_test();
        let env = d.env();
        make_private(&env);
        let role = role(&verified.loaded).unwrap();
        let before_files =
            crate::sync::central::migration_files::Files::capture(&env, None).unwrap();
        let fault = Fault {
            inner: &d.keychain,
            role: role.clone(),
            after,
            armed: AtomicBool::new(true),
        };
        let mut interrupted = d.env();
        interrupted.keychain = &fault;
        assert!(prepare(&interrupted, verified, &keys).is_err());
        let saved = d.keychain.entry(&role);
        assert_eq!(saved.is_some(), after);
        before_files.require_unchanged(&env, None).unwrap();
        let context = prepare(
            &env,
            migration_dispatch::verified_for_test(&env, &keys),
            &keys,
        )
        .unwrap();
        if let Some(saved) = saved {
            assert_eq!(serde_json::to_string(&context.reservation).unwrap(), saved);
        }
    }
}
#[test]
fn unknown_or_changed_reservation_is_never_replaced_and_stale_source_cannot_reserve() {
    for case in [
        "policy",
        "operation",
        "manifest",
        "cursor",
        "observed",
        "unknown",
        "corrupt",
    ] {
        let (d, keys, verified) = migration_dispatch::verified_fixture_for_test();
        let env = d.env();
        make_private(&env);
        let context = prepare(&env, verified, &keys).unwrap();
        let role = role(&context.loaded).unwrap();
        let mut value = serde_json::to_value(&context.reservation).unwrap();
        match case {
            "policy" => value[case] = "unknown".into(),
            "operation" => value[case] = "invalid".into(),
            "manifest" => value[case] = "9".repeat(64).into(),
            "cursor" => value[case]["revision"] = 0.into(),
            "observed" => value[case] = u64::MAX.into(),
            "unknown" => value[case] = true.into(),
            _ => {}
        }
        let encoded = if case == "corrupt" {
            "broken".into()
        } else {
            serde_json::to_string(&value).unwrap()
        };
        d.keychain.set(&role, &encoded).unwrap();
        assert!(context.check(&env, &keys).is_err());
        assert!(prepare(
            &env,
            migration_dispatch::verified_for_test(&env, &keys),
            &keys
        )
        .is_err());
        assert_eq!(d.keychain.entry(&role).unwrap(), encoded);
    }
    let (d, keys, verified) = migration_dispatch::verified_fixture_for_test();
    let env = d.env();
    make_private(&env);
    let role = role(&verified.loaded).unwrap();
    std::fs::write(&env.state_path, b"source B").unwrap();
    assert!(prepare(&env, verified, &keys).is_err());
    assert!(d.keychain.entry(&role).is_none());
}

#[test]
fn reserved_initial_stage_uses_only_the_protected_operation_and_cannot_create_a_second_transaction()
{
    let (d, keys, verified) = migration_dispatch::verified_fixture_for_test();
    let env = d.env();
    make_private(&env);
    let context = prepare(&env, verified, &keys).unwrap();
    let before = record_runtime::snapshot(&env).unwrap();
    let staged =
        crate::sync::record_import::central_stage::prepare_initial_reserved(&env, &context, &keys)
            .unwrap();
    assert_eq!(staged.operation(), context.operation());
    assert_eq!(record_runtime::snapshot(&env).unwrap(), before);
    let pending = crate::sync::record_import::pending_imports(&env).unwrap();
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].import_id, context.operation());
    let retried=crate::sync::record_import::central_stage::prepare_initial_reserved(&env,&context,&keys).unwrap();
    assert_eq!(retried.operation(),context.operation());
    assert_eq!(retried.mapping(),staged.mapping());
    assert_eq!(record_runtime::snapshot(&env).unwrap(),before);
    assert_eq!(
        crate::sync::record_import::pending_imports(&env)
            .unwrap()
            .len(),
        1
    );
    let resumed = crate::sync::record_import::central_stage::resume_initial(
        &env,
        context.operation(),
        context.projection(),
    )
    .unwrap();
    assert_eq!(resumed.operation(), context.operation());
    assert_eq!(resumed.mapping(), staged.mapping());
    assert!(
        !record_runtime::snapshot(&env)
            .unwrap()
            .0
            .local
            .central
            .as_ref()
            .unwrap()
            .control
            .cutover
    );
}
#[test]
fn changed_source_or_missing_consent_blocks_reserved_staging_before_file_or_master_effects() {
    for missing in [false, true] {
        let (d, keys, verified) = migration_dispatch::verified_fixture_for_test();
        let env = d.env();
        make_private(&env);
        let context = prepare(&env, verified, &keys).unwrap();
        if missing {
            let role = context
                .loaded
                .plan
                .before()
                .control
                .profile
                .profile()
                .unwrap()
                .device_slot(
                    "source-migration-review",
                    context.loaded.plan.before().identity_slot.as_deref(),
                )
                .unwrap();
            d.keychain.delete(&role).unwrap();
        } else {
            std::fs::write(&env.state_path, b"source B").unwrap();
        }
        assert!(
            crate::sync::record_import::central_stage::prepare_initial_reserved(
                &env, &context, &keys
            )
            .is_err()
        );
        assert!(!env
            .state_path
            .parent()
            .unwrap()
            .join("imports")
            .join(context.operation())
            .exists());
    }
}

#[test]
fn exact_reserved_stage_outputs_are_the_only_new_files_accepted_by_source_validation() {
    use std::{fs, path::Path};
    let (d, keys, verified) = migration_dispatch::verified_fixture_for_test();
    let env = d.env();
    make_private(&env);
    let prepared = prepare(&env, verified, &keys).unwrap();
    crate::sync::record_import::central_stage::prepare_initial_reserved(&env, &prepared, &keys)
        .unwrap();
    let effects =
        crate::sync::record_import::central_stage::initial_effects(&env, &prepared, &keys).unwrap();
    assert!(effects
        .files()
        .all(|(p, _)| p.starts_with(Path::new("data/imports").join(prepared.operation()))));
    assert!(
        !record_runtime::snapshot(&env)
            .unwrap()
            .0
            .local
            .central
            .as_ref()
            .unwrap()
            .control
            .cutover
    );
    fs::write(
        env.state_path.parent().unwrap().join("sync-state.new-B"),
        b"new B",
    )
    .unwrap();
    assert!(
        crate::sync::record_import::central_stage::initial_effects(&env, &prepared, &keys).is_err()
    );
}
#[test]
fn unknown_owned_entries_or_modified_source_copies_never_become_exclusions() {
    use std::fs;
    for unknown in [true, false] {
        let (d, keys, verified) = migration_dispatch::verified_fixture_for_test();
        let env = d.env();
        make_private(&env);
        let prepared = prepare(&env, verified, &keys).unwrap();
        crate::sync::record_import::central_stage::prepare_initial_reserved(&env, &prepared, &keys)
            .unwrap();
        let directory = env
            .state_path
            .parent()
            .unwrap()
            .join("imports")
            .join(prepared.operation());
        let path = directory.join(if unknown {
            "unknown-private-source"
        } else {
            "original-state.json"
        });
        fs::write(&path, b"source B").unwrap();
        assert!(
            crate::sync::record_import::central_stage::initial_effects(&env, &prepared, &keys)
                .is_err()
        );
        assert!(fs::read(path).is_ok());
    }
}

#[test]
fn exact_additive_vault_replacement_is_proved_without_masking_a_new_source_or_activating_core() {
    use std::fs;
    let (d, keys, verified) = migration_dispatch::verified_material_fixture_for_test();
    let env = d.env();
    make_private(&env);
    let prepared = prepare(&env, verified, &keys).unwrap();
    let before = record_runtime::snapshot(&env).unwrap();
    let vault = crate::vault::store::vault_path(&env.state_path);
    let original = fs::read(&vault).unwrap();
    let staged =
        crate::sync::record_import::central_stage::prepare_initial_reserved(&env, &prepared, &keys)
            .unwrap();
    assert_eq!(staged.mapping().len(), 1);
    assert!(
        crate::sync::record_import::central_stage::initial_effects(&env, &prepared, &keys)
            .unwrap()
            .replacement()
            .is_none()
    );
    let path = env
        .state_path
        .parent()
        .unwrap()
        .join("imports")
        .join(prepared.operation())
        .join("vault.json");
    let proposed = fs::read(path).unwrap();
    assert_ne!(proposed, original);
    // Model the exact vault rename before its phase write. Core still contains the old source.
    fs::write(&vault, &proposed).unwrap();
    let effects =
        crate::sync::record_import::central_stage::initial_effects(&env, &prepared, &keys).unwrap();
    let (_, old, new) = effects.replacement().unwrap();
    assert_eq!(old.unwrap(), original);
    assert_eq!(new, proposed);
    assert_eq!(record_runtime::snapshot(&env).unwrap(), before);
    fs::write(
        env.state_path
            .parent()
            .unwrap()
            .join("sync-state.unrelated-B"),
        b"unrelated B",
    )
    .unwrap();
    assert!(
        crate::sync::record_import::central_stage::initial_effects(&env, &prepared, &keys).is_err()
    );
    assert_eq!(fs::read(vault).unwrap(), proposed);
}

#[test]
fn cold_reentry_restores_the_same_protected_stage_and_shadow_after_an_exact_vault_replacement() {
    use std::fs;
    let (d, keys, verified) = migration_dispatch::verified_material_fixture_for_test();
    let env = d.env();
    make_private(&env);
    let prepared = prepare(&env, verified, &keys).unwrap();
    let operation = prepared.operation().to_string();
    let observed = prepared.reservation.observed;
    let shadow = serde_json::to_vec(prepared.projection().shadow()).unwrap();
    let source = record_runtime::snapshot(&env).unwrap().0;
    let staged =
        crate::sync::record_import::central_stage::prepare_initial_reserved(&env, &prepared, &keys)
            .unwrap();
    let mapping = staged.mapping();
    let directory = env
        .state_path
        .parent()
        .unwrap()
        .join("imports")
        .join(&operation);
    let vault = crate::vault::store::vault_path(&env.state_path);
    let proposed = fs::read(directory.join("vault.json")).unwrap();
    fs::write(&vault, &proposed).unwrap();
    let tree = || {
        fs::read_dir(&directory)
            .unwrap()
            .map(|e| {
                let e = e.unwrap();
                (e.file_name(), fs::read(e.path()).unwrap())
            })
            .collect::<std::collections::BTreeMap<_, _>>()
    };
    let exact = tree();
    drop(prepared);
    d.runtime.core.lock().unwrap().generation = 0;
    struct ReadOnly<'a>(&'a MemKeychain);
    impl Keychain for ReadOnly<'_> {
        fn get(&self, _: &str) -> Result<Option<String>, AppError> {
            panic!("no interactive read during cold publication recovery")
        }
        fn get_noninteractive(&self, k: &str) -> Result<Option<String>, AppError> {
            self.0.get_noninteractive(k)
        }
        fn set(&self, _: &str, _: &str) -> Result<(), AppError> {
            panic!("no credential write during recovery")
        }
        fn set_noninteractive(&self, _: &str, _: &str) -> Result<(), AppError> {
            panic!("no protected write during recovery")
        }
        fn delete(&self, _: &str) -> Result<(), AppError> {
            panic!("no credential deletion")
        }
    }
    let guard = ReadOnly(&d.keychain);
    let mut safe = d.env();
    safe.keychain = &guard;
    let restored = resume(&safe, &keys, &std::collections::BTreeMap::new()).unwrap();
    assert_eq!(restored.operation(), operation);
    assert_eq!(restored.reservation.observed, observed);
    assert_eq!(
        serde_json::to_vec(restored.projection().shadow()).unwrap(),
        shadow
    );
    assert_eq!(tree(), exact);
    assert_eq!(fs::read(vault).unwrap(), proposed);
    assert_eq!(record_runtime::snapshot(&env).unwrap().0, source);
    assert_eq!(
        crate::sync::record_import::central_stage::resume_initial(
            &env,
            &operation,
            restored.projection()
        )
        .unwrap()
        .mapping(),
        mapping
    );
}
#[test]
fn cold_reservation_only_reentry_does_not_create_a_stage_and_missing_reservation_is_not_recreated()
{
    let (d, keys, verified) = migration_dispatch::verified_fixture_for_test();
    let env = d.env();
    make_private(&env);
    let prepared = prepare(&env, verified, &keys).unwrap();
    let operation = prepared.operation().to_string();
    let role = role(&prepared.loaded).unwrap();
    drop(prepared);
    d.runtime.core.lock().unwrap().generation = 0;
    let restored = resume(&env, &keys, &std::collections::BTreeMap::new()).unwrap();
    assert_eq!(restored.operation(), operation);
    assert!(!env
        .state_path
        .parent()
        .unwrap()
        .join("imports")
        .join(&operation)
        .exists());
    d.keychain.delete(&role).unwrap();
    assert!(resume(&env, &keys, &std::collections::BTreeMap::new()).is_err());
    assert!(d.keychain.entry(&role).is_none());
}
#[test]
fn an_unknown_stage_file_or_new_source_blocks_cold_recovery_without_removing_evidence() {
    use std::fs;
    for unknown in [false, true] {
        let (d, keys, verified) = migration_dispatch::verified_fixture_for_test();
        let env = d.env();
        make_private(&env);
        let prepared = prepare(&env, verified, &keys).unwrap();
        let operation = prepared.operation().to_string();
        crate::sync::record_import::central_stage::prepare_initial_reserved(&env, &prepared, &keys)
            .unwrap();
        drop(prepared);
        d.runtime.core.lock().unwrap().generation = 0;
        let path = if unknown {
            env.state_path
                .parent()
                .unwrap()
                .join("imports")
                .join(&operation)
                .join("unknown-B")
        } else {
            env.state_path.parent().unwrap().join("sync-state.new-B")
        };
        fs::write(&path, b"new B").unwrap();
        assert!(resume(&env, &keys, &std::collections::BTreeMap::new()).is_err());
        assert_eq!(fs::read(path).unwrap(), b"new B");
    }
}

#[test]
fn dedicated_initial_publication_activates_only_the_exact_consented_verified_managed_library() {
    use std::fs;
    let (d, keys, verified) = migration_dispatch::verified_material_fixture_for_test();
    let env = d.env();
    make_private(&env);
    let prepared = prepare(&env, verified, &keys).unwrap();
    let original = fs::read(&env.state_path).unwrap();
    let before = record_runtime::snapshot(&env).unwrap();
    assert!(
        record_runtime::save_active(&env.state_path, prepared.projection().shadow())
            .unwrap_err()
            .to_string()
            .contains("First central library activation")
    );
    assert_eq!(fs::read(&env.state_path).unwrap(), original);
    let staged =
        crate::sync::record_import::central_stage::prepare_initial_reserved(&env, &prepared, &keys)
            .unwrap();
    let mapping = staged.mapping();
    let result =
        crate::sync::record_import::central_stage::publish_initial(&env, &prepared, &keys).unwrap();
    assert_eq!(result.phase, "central_active");
    let (state, generation) = record_runtime::snapshot(&env).unwrap();
    assert_eq!(generation, before.1 + 1);
    assert_eq!(
        state.version,
        crate::sync::records_v3::CENTRAL_STATE_VERSION
    );
    assert!(state.local.central.as_ref().unwrap().control.cutover);
    assert!(state.local.central_projection.is_some());
    assert_eq!(
        state.local.keys[&"1".repeat(32)].vault_id,
        mapping[&"1".repeat(32)]
    );
    assert!(state
        .local
        .import_receipts
        .contains_key(prepared.operation()));
    assert!(crate::sync::record_import::pending_imports(&env)
        .unwrap()
        .is_empty());
    let directory = env
        .state_path
        .parent()
        .unwrap()
        .join("imports")
        .join(prepared.operation());
    assert_eq!(
        fs::read(directory.join("original-state.json")).unwrap(),
        original
    );
    let view = crate::vault::store::read_vault(
        &crate::vault::store::vault_path(&env.state_path),
        &d.keychain,
    )
    .unwrap();
    assert_eq!(
        view.get(&"3".repeat(32)).unwrap().unwrap().private_key,
        view.get(&mapping[&"1".repeat(32)])
            .unwrap()
            .unwrap()
            .private_key
    );
    assert!(record_runtime::commit_candidate(
        &env,
        generation,
        prepared.projection().shadow().clone()
    )
    .is_err());
}
#[test]
fn a_late_source_before_state_save_blocks_cutover_and_preserves_the_additive_vault() {
    use crate::sync::record_import::{with_test_step, PublishStep};
    use std::fs;
    let (d, keys, verified) = migration_dispatch::verified_material_fixture_for_test();
    let env = d.env();
    make_private(&env);
    let prepared = prepare(&env, verified, &keys).unwrap();
    let before = record_runtime::snapshot(&env).unwrap();
    let source = fs::read(&env.state_path).unwrap();
    crate::sync::record_import::central_stage::prepare_initial_reserved(&env, &prepared, &keys)
        .unwrap();
    let new_source = env.state_path.parent().unwrap().join("sync-state.late-B");
    let target = new_source.clone();
    let result = with_test_step(
        move |step| {
            if step == PublishStep::BeforeStateSave {
                fs::write(&target, b"late B")?;
            }
            Ok(())
        },
        || crate::sync::record_import::central_stage::publish_initial(&env, &prepared, &keys),
    );
    assert!(result.is_err());
    assert_eq!(record_runtime::snapshot(&env).unwrap(), before);
    assert_eq!(fs::read(&env.state_path).unwrap(), source);
    assert_eq!(fs::read(new_source).unwrap(), b"late B");
    let view = crate::vault::store::read_vault(
        &crate::vault::store::vault_path(&env.state_path),
        &d.keychain,
    )
    .unwrap();
    assert!(view.get(&"3".repeat(32)).unwrap().is_some());
    assert_eq!(view.ids().len(), 2);
}

#[test]
fn a_lost_saved_state_response_finishes_only_the_same_receipt_and_preserves_later_active_edits() {
    use crate::sync::record_import::{with_test_step, PublishStep};
    use std::fs;
    let (d, keys, verified) = migration_dispatch::verified_material_fixture_for_test();
    let env = d.env();
    make_private(&env);
    let prepared = prepare(&env, verified, &keys).unwrap();
    let operation = prepared.operation().to_string();
    crate::sync::record_import::central_stage::prepare_initial_reserved(&env, &prepared, &keys)
        .unwrap();
    let result = with_test_step(
        |step| {
            if step == PublishStep::StateSaved {
                Err(invalid())
            } else {
                Ok(())
            }
        },
        || crate::sync::record_import::central_stage::publish_initial(&env, &prepared, &keys),
    );
    assert!(result.is_err());
    assert!(
        record_runtime::snapshot(&env)
            .unwrap()
            .0
            .local
            .central
            .as_ref()
            .unwrap()
            .control
            .cutover
    );
    assert!(crate::sync::record_import::pending_imports(&env)
        .unwrap()
        .is_empty());
    record_runtime::mutate_records(&env, |state| {
        let mut next = state.clone();
        next.device_name = "later active edit".into();
        Ok(next)
    })
    .unwrap();
    let later = record_runtime::snapshot(&env).unwrap();
    let vault = fs::read(crate::vault::store::vault_path(&env.state_path)).unwrap();
    drop(prepared);
    let completed =
        crate::sync::record_import::central_stage::complete_initial_saved(&env, &operation)
            .unwrap();
    assert_eq!(completed.phase, "central_active");
    assert_eq!(record_runtime::snapshot(&env).unwrap(), later);
    assert_eq!(
        fs::read(crate::vault::store::vault_path(&env.state_path)).unwrap(),
        vault
    );
    crate::sync::record_import::central_stage::complete_initial_saved(&env, &operation).unwrap();
    assert_eq!(record_runtime::snapshot(&env).unwrap(), later);
}
#[test]
fn an_uncertain_post_rename_directory_sync_blocks_old_core_until_saved_state_reload() {
    use crate::sync::record_runtime::{with_replacement_write_hook, ReplacementWriteStage};
    let (d, keys, verified) = migration_dispatch::verified_material_fixture_for_test();
    let env = d.env();
    make_private(&env);
    let prepared = prepare(&env, verified, &keys).unwrap();
    let operation = prepared.operation().to_string();
    crate::sync::record_import::central_stage::prepare_initial_reserved(&env, &prepared, &keys)
        .unwrap();
    let source = record_runtime::snapshot(&env).unwrap();
    let result = with_replacement_write_hook(
        Box::new(|step, path| {
            if step == ReplacementWriteStage::DirectorySync
                && path.file_name().is_some_and(|n| n == "sync-state.json")
            {
                Err(invalid())
            } else {
                Ok(())
            }
        }),
        || crate::sync::record_import::central_stage::publish_initial(&env, &prepared, &keys),
    );
    assert!(result.is_err());
    {
        let core = d.runtime.core.lock().unwrap();
        assert!(core.save_blocked.is_some());
        assert!(core.central_session.is_none());
        assert_eq!(record_runtime::active_state(&core).unwrap(), &source.0);
    }
    let probe = record_runtime::probe_startup(&env.state_path, "reload");
    record_runtime::activate_probe(&mut d.runtime.core.lock().unwrap(), probe).unwrap();
    let loaded = record_runtime::snapshot(&env).unwrap();
    assert!(loaded.0.local.central.as_ref().unwrap().control.cutover);
    assert_eq!(
        crate::sync::record_import::central_stage::complete_initial_saved(&env, &operation)
            .unwrap()
            .phase,
        "central_active"
    );
    assert_eq!(record_runtime::snapshot(&env).unwrap(), loaded);
}
