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
    assert!(
        crate::sync::record_import::central_stage::prepare_initial_reserved(&env, &context, &keys)
            .is_err()
    );
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
