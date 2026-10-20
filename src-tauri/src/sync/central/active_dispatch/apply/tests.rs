use super::*;
use crate::sync::{
    central::{
        crypto::{self, DeviceKeys},
        wire::WrapHeader,
    },
    env::Keychain,
    fake_relay::FakeRelay,
    record_import::{self, with_test_step, PublishStep},
    record_repository,
    testkit::{MemKeychain, TestClock, TestDevice},
};
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use std::fs;
use zeroize::Zeroizing;
fn state(d: &TestDevice) -> SyncStateV3 {
    record_runtime::snapshot(&d.env()).unwrap().0
}
fn receiver() -> (TestDevice, String, crate::vault::store::VaultEntry) {
    let (mut state, keys, _, id, entry) = crate::sync::central::material_fixture_for_test();
    state.local.keys.clear();
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
    let d = TestDevice::new("automatic-receive", &FakeRelay::new(), &TestClock::new());
    record_runtime::save_active(&d.env().state_path, &state).unwrap();
    let probe = record_runtime::probe_startup(&d.env().state_path, "automatic-receive");
    record_runtime::activate_probe(&mut d.runtime.core.lock().unwrap(), probe).unwrap();
    let owner = state.local.central.as_ref().unwrap();
    let profile = owner.control.profile.profile().unwrap();
    let stored = Zeroizing::new(serde_json::json!({"version":1,"locator":profile.locator,"id":owner.control.device.id,"keys":&*signer.encode_secret(),"credential":"d".repeat(64)}).to_string());
    d.keychain
        .set(
            &profile
                .device_slot("device", owner.identity_slot.as_deref())
                .unwrap(),
            &stored,
        )
        .unwrap();
    d.runtime.core.lock().unwrap().central_session = Some(
        crate::sync::record_import::central_local::tests::selected_session(
            &d,
            Duration::from_secs(300),
        ),
    );
    (d, id, entry)
}
struct NoPrompt<'a> {
    inner: &'a MemKeychain,
    fail_write: bool,
}
impl Keychain for NoPrompt<'_> {
    fn get(&self, _: &str) -> Result<Option<String>, AppError> {
        panic!("automatic publication cannot prompt for credentials")
    }
    fn set(&self, _: &str, _: &str) -> Result<(), AppError> {
        panic!("automatic publication cannot use interactive writes")
    }
    fn delete(&self, _: &str) -> Result<(), AppError> {
        panic!("automatic publication cannot delete a credential")
    }
    fn get_noninteractive(&self, role: &str) -> Result<Option<String>, AppError> {
        self.inner.get(role)
    }
    fn set_noninteractive(&self, role: &str, secret: &str) -> Result<(), AppError> {
        if self.fail_write {
            Err(invalid())
        } else {
            self.inner.set(role, secret)
        }
    }
}
fn count_journals(d: &TestDevice) -> usize {
    fs::read_dir(d.env().state_path.parent().unwrap().join("imports"))
        .map(|entries| entries.count())
        .unwrap_or(0)
}
#[test]
fn a_new_received_private_key_is_automatically_protected_without_prompt_and_noop_has_no_journal_churn(
) {
    let (d, id, expected) = receiver();
    let keychain = NoPrompt {
        inner: &d.keychain,
        fail_write: false,
    };
    let probe = crate::sync::central::active_dispatch::tests::AssertUnlocked {
        runtime: &d.runtime,
    };
    let mut env = d.env();
    env.keychain = &keychain;
    env.events = &probe;
    let report = once(&env).unwrap();
    assert!(report.published);
    assert_eq!(report.keys, 1);
    let view = record_repository::resolve_key(&state(&d), &id).unwrap();
    assert_eq!(view.status, record_repository::KeyStatus::Available);
    let protected = crate::vault::store::read_vault(
        &crate::vault::store::vault_path(&env.state_path),
        &Background(&keychain),
    )
    .unwrap()
    .get(view.vault_id.as_ref().unwrap())
    .unwrap()
    .unwrap();
    assert_eq!(protected.private_key, expected.private_key);
    assert!(crate::session::record_material::matches(&view, &protected));
    let journals = count_journals(&d);
    let vault = fs::read(crate::vault::store::vault_path(&env.state_path)).unwrap();
    let again = once(&env).unwrap();
    assert!(!again.published);
    assert_eq!(again.keys, 0);
    assert_eq!(count_journals(&d), journals);
    assert_eq!(
        fs::read(crate::vault::store::vault_path(&env.state_path)).unwrap(),
        vault
    );
}
#[test]
fn a_noninteractive_write_failure_keeps_source_state_and_resumes_the_same_pending_stage() {
    let (d, id, _) = receiver();
    let before = state(&d);
    let blocked = NoPrompt {
        inner: &d.keychain,
        fail_write: true,
    };
    let mut env = d.env();
    env.keychain = &blocked;
    assert!(once(&env).is_err());
    assert_eq!(state(&d), before);
    assert!(!crate::vault::store::vault_path(&env.state_path).exists());
    let pending = record_import::pending_imports(&env).unwrap();
    assert_eq!(pending.len(), 1);
    let operation = pending[0].import_id.clone();
    let allowed = NoPrompt {
        inner: &d.keychain,
        fail_write: false,
    };
    env.keychain = &allowed;
    once(&env).unwrap();
    assert!(record_import::pending_imports(&env).unwrap().is_empty());
    assert_eq!(count_journals(&d), 1);
    assert!(d
        .env()
        .state_path
        .parent()
        .unwrap()
        .join("imports")
        .join(operation)
        .exists());
    assert_eq!(
        record_repository::resolve_key(&state(&d), &id)
            .unwrap()
            .status,
        record_repository::KeyStatus::Available
    );
}
#[test]
fn a_crash_after_staging_retries_the_existing_operation_instead_of_creating_another() {
    let (d, id, _) = receiver();
    let result = with_test_step(
        |step| {
            if step == PublishStep::VaultStaged {
                Err(invalid())
            } else {
                Ok(())
            }
        },
        || once(&d.env()),
    );
    assert!(result.is_err());
    let pending = record_import::pending_imports(&d.env()).unwrap();
    assert_eq!(pending.len(), 1);
    once(&d.env()).unwrap();
    assert_eq!(count_journals(&d), 1);
    assert_eq!(
        record_repository::resolve_key(&state(&d), &id)
            .unwrap()
            .status,
        record_repository::KeyStatus::Available
    );
}
#[test]
fn a_later_uncaptured_local_b_is_preserved_and_capture_allows_the_same_stage_to_finish() {
    let (d, id, _) = receiver();
    let d = Arc::new(d);
    let active = Arc::clone(&d);
    let result = with_test_step(
        move |step| {
            if step == PublishStep::VaultSaved {
                let (records, generation) = record_runtime::snapshot(&active.env())?;
                let payload = serde_json::from_value(serde_json::json!({"schema":2,"alias":"local_b_while_activating","hostname":"fixture.invalid","auth":"password"})).unwrap();
                let records = record_repository::create_host(
                    &records,
                    "00000000000000ff",
                    crate::sync::records_v3::HostScope::Local,
                    payload,
                    900,
                )
                .map_err(|_| invalid())?;
                record_runtime::commit_candidate(&active.env(), generation, records)?;
            }
            Ok(())
        },
        || once(&d.env()),
    );
    assert!(result.is_err());
    assert_eq!(
        state(&d)
            .local
            .hosts
            .values()
            .next()
            .unwrap()
            .record
            .payload["alias"],
        "local_b_while_activating"
    );
    once(&d.env()).unwrap();
    assert_eq!(count_journals(&d), 1);
    assert_eq!(
        state(&d)
            .local
            .hosts
            .values()
            .next()
            .unwrap()
            .record
            .payload["alias"],
        "local_b_while_activating"
    );
    assert_eq!(
        record_repository::resolve_key(&state(&d), &id)
            .unwrap()
            .status,
        record_repository::KeyStatus::Available
    );
}
#[test]
fn an_unrecognized_pending_import_blocks_automatic_publication_without_touching_source() {
    let (d, _, _) = receiver();
    let before = state(&d);
    let dir = d
        .env()
        .state_path
        .parent()
        .unwrap()
        .join("imports")
        .join("0".repeat(32));
    crate::fsutil::ensure_dir_secure(&dir).unwrap();
    fs::write(dir.join("journal.json"), b"{}").unwrap();
    assert!(once(&d.env()).is_err());
    assert_eq!(state(&d), before);
    assert!(!crate::vault::store::vault_path(&d.env().state_path).exists());
}
