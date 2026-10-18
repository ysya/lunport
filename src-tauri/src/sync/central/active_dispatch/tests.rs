use super::*;
use crate::sync::{
    central::{crypto, rekey, wire::canonical},
    env::Keychain,
    record_import::central_local::{
        self,
        tests::{fixture as local_fixture, selected_session},
    },
    record_keys,
    slot_rules::test_keys,
    testkit::TestDevice,
};
use crate::vault::store::{self, EntryOrigin};
use std::{
    fs,
    sync::atomic::{AtomicUsize, Ordering},
};
use zeroize::Zeroizing;
fn state(d: &TestDevice) -> SyncStateV3 {
    record_runtime::snapshot(&d.env()).unwrap().0
}
pub(super) fn fixture() -> (TestDevice, String) {
    let d = local_fixture();
    let (before, generation) = record_runtime::snapshot(&d.env()).unwrap();
    let invocation = central_local::invocation(&before)
        .unwrap()
        .with_generation(generation);
    let key = record_keys::import_local_scoped(
        &d.env(),
        "work",
        Zeroizing::new(test_keys::plain()),
        EntryOrigin::Imported,
        Some(&invocation),
    )
    .unwrap();
    d.runtime.core.lock().unwrap().central_session =
        Some(selected_session(&d, Duration::from_secs(300)));
    (d, key.key_id)
}
fn role(d: &TestDevice) -> String {
    let s = state(d);
    let o = s.local.central.unwrap();
    o.control
        .profile
        .profile()
        .unwrap()
        .device_slot("device", o.identity_slot.as_deref())
        .unwrap()
}
fn reply(operation: &Operation, d: &TestDevice) -> PushReply {
    let s = state(d);
    let replica = s.local.central.as_ref().unwrap().replica.as_ref().unwrap();
    let mut sequence = replica.checkpoint.sequence;
    let mut hash = replica.checkpoint.history_hash.clone();
    let mut receipts = vec![];
    for row in &operation.records {
        sequence += 1;
        let digest = rekey::envelope_digest(row).unwrap();
        hash = crypto::hash(
            &canonical(&["lunport-history-v2", &hash, &sequence.to_string(), &digest]).unwrap(),
        );
        receipts.push(serde_json::json!({"operation_id":row.header.operation_id,"record_id":row.header.record_id,"revision":(super::super::wire::number(&row.header.expected_revision,true).unwrap()+1).to_string(),"sequence":sequence.to_string(),"digest":digest,"history_hash":hash}));
    }
    serde_json::from_value(serde_json::json!({"receipts":receipts,"sequence":sequence.to_string(),"history_hash":hash})).unwrap()
}
#[test]
fn exact_sent_bytes_are_durable_before_transport_and_claims_do_not_change_material_or_checkpoint() {
    let (d, _) = fixture();
    let before = state(&d);
    let vault = fs::read(store::vault_path(&d.env().state_path)).unwrap();
    let batch = prepare(&d.env(), None).unwrap();
    assert_eq!(batch.waiting_private, 1);
    let operation = batch.operation.unwrap();
    assert_eq!(operation.records.len(), 1);
    let sent = state(&d);
    assert_eq!(
        sent.local.central_projection,
        before.local.central_projection
    );
    assert_eq!(sent.local.keys, before.local.keys);
    assert_eq!(sent.account, before.account);
    operation
        .with_transport(&d.env(), |_, _, rows| {
            let disk: SyncStateV3 =
                serde_json::from_slice(&fs::read(&d.env().state_path).unwrap()).unwrap();
            for row in rows {
                assert_eq!(
                    &disk
                        .local
                        .central
                        .as_ref()
                        .unwrap()
                        .replica
                        .as_ref()
                        .unwrap()
                        .pending[&row.header.record_id]
                        .sent
                        .as_ref()
                        .unwrap()
                        .envelope,
                    row
                );
            }
            Ok(())
        })
        .unwrap();
    operation.claims(&d.env(), &reply(&operation, &d)).unwrap();
    let after = state(&d);
    assert_eq!(
        after
            .local
            .central
            .as_ref()
            .unwrap()
            .replica
            .as_ref()
            .unwrap()
            .checkpoint,
        before
            .local
            .central
            .as_ref()
            .unwrap()
            .replica
            .as_ref()
            .unwrap()
            .checkpoint
    );
    assert_eq!(after.local.keys, before.local.keys);
    assert_eq!(
        after.local.central_projection,
        before.local.central_projection
    );
    assert_eq!(
        fs::read(store::vault_path(&d.env().state_path)).unwrap(),
        vault
    );
    assert!(prepare(&d.env(), None).unwrap().operation.is_none());
}
#[test]
fn absent_expired_or_denied_grants_never_mark_pending_rows_sent() {
    for kind in 0..3 {
        let (d, _) = fixture();
        let mut session = selected_session(
            &d,
            if kind == 1 {
                Duration::ZERO
            } else {
                Duration::from_secs(300)
            },
        );
        if kind == 2 {
            Arc::get_mut(&mut session).unwrap().device_access_denied = true;
        }
        d.runtime.core.lock().unwrap().central_session =
            if kind == 0 { None } else { Some(session) };
        let before = state(&d);
        let disk = fs::read(&d.env().state_path).unwrap();
        assert!(prepare(&d.env(), None).is_err());
        assert_eq!(state(&d), before);
        assert_eq!(fs::read(&d.env().state_path).unwrap(), disk);
    }
}
#[test]
fn response_loss_or_restart_reuses_exact_persisted_operations() {
    let (d, _) = fixture();
    let first = prepare(&d.env(), None).unwrap().operation.unwrap();
    let _ = first.with_transport(&d.env(), |_, _, _| Err::<(), _>(invalid()));
    let probe = record_runtime::probe_startup(&d.env().state_path, "restarted");
    record_runtime::activate_probe(&mut d.runtime.core.lock().unwrap(), probe).unwrap();
    d.runtime.core.lock().unwrap().central_session =
        Some(selected_session(&d, Duration::from_secs(300)));
    let retried = prepare(&d.env(), None).unwrap().operation.unwrap();
    assert_eq!(first.records, retried.records);
}
#[test]
fn later_local_b_is_preserved_when_sent_a_response_is_published() {
    let (d, id) = fixture();
    let operation = prepare(&d.env(), None).unwrap().operation.unwrap();
    let (before, generation) = record_runtime::snapshot(&d.env()).unwrap();
    let invocation = central_local::invocation(&before)
        .unwrap()
        .with_generation(generation);
    central_local::rename(
        &d.env(),
        &invocation,
        &id,
        &before.local.keys[&id].public,
        "later_b",
    )
    .unwrap();
    let latest = state(&d);
    operation
        .with_transport(&d.env(), |_, _, _| Ok(()))
        .unwrap();
    operation.claims(&d.env(), &reply(&operation, &d)).unwrap();
    let after = state(&d);
    assert_eq!(after.local.keys[&id].public.name, "later_b");
    let opaque = &operation.records[0].header.record_id;
    assert_eq!(
        after
            .local
            .central
            .as_ref()
            .unwrap()
            .replica
            .as_ref()
            .unwrap()
            .pending[opaque]
            .latest,
        latest
            .local
            .central
            .as_ref()
            .unwrap()
            .replica
            .as_ref()
            .unwrap()
            .pending[opaque]
            .latest
    );
}
#[test]
fn protected_role_and_equivalent_session_changes_stop_old_batches_before_or_after_callback() {
    for kind in 0..3 {
        let (d, _) = fixture();
        let operation = prepare(&d.env(), None).unwrap().operation.unwrap();
        let before = state(&d);
        let calls = AtomicUsize::new(0);
        if kind == 0 {
            d.keychain.delete(&role(&d)).unwrap();
        }
        if kind == 1 {
            d.runtime.core.lock().unwrap().central_session =
                Some(selected_session(&d, Duration::from_secs(300)));
        }
        let result = operation.with_transport(&d.env(), |_, _, _| {
            calls.fetch_add(1, Ordering::SeqCst);
            if kind == 2 {
                d.keychain.delete(&role(&d))?;
            }
            Ok(())
        });
        assert!(result.is_err());
        assert_eq!(calls.load(Ordering::SeqCst), usize::from(kind == 2));
        assert_eq!(state(&d), before);
    }
}
#[test]
fn strict_ciphertext_write_faults_never_return_an_undurable_operation() {
    use record_runtime::{with_replacement_write_hook, ReplacementWriteStage as Stage};
    for stop in [
        Stage::FileSync,
        Stage::SourceRecheck,
        Stage::Rename,
        Stage::DirectorySync,
    ] {
        let (d, _) = fixture();
        let before = state(&d);
        let path = d.env().state_path.clone();
        let result = with_replacement_write_hook(
            Box::new(move |at, target| {
                if target == path && at == stop {
                    Err(invalid())
                } else {
                    Ok(())
                }
            }),
            || prepare(&d.env(), None),
        );
        assert!(result.is_err());
        assert_eq!(state(&d), before);
        if stop == Stage::DirectorySync {
            assert!(d.runtime.core.lock().unwrap().save_blocked.is_some());
            assert!(d.runtime.core.lock().unwrap().central_session.is_none());
            let probe = record_runtime::probe_startup(&d.env().state_path, "restarted");
            record_runtime::activate_probe(&mut d.runtime.core.lock().unwrap(), probe).unwrap();
        }
        d.runtime.core.lock().unwrap().central_session =
            Some(selected_session(&d, Duration::from_secs(300)));
        assert!(prepare(&d.env(), None).unwrap().operation.is_some());
    }
}
#[test]
fn a_later_public_deletion_blocks_already_prepared_private_transport() {
    let (d, id) = fixture();
    let public = prepare(&d.env(), None).unwrap().operation.unwrap();
    let (mut current, generation) = record_runtime::snapshot(&d.env()).unwrap();
    let context = Context::load(&d.env(), &current).unwrap();
    super::super::outbox::tests::accept(&mut current, context.keys(), public.records[0].clone());
    record_runtime::commit_candidate(&d.env(), generation, current).unwrap();
    let private = prepare(&d.env(), None).unwrap().operation.unwrap();
    assert_eq!(private.records[0].header.kind, "key");
    let (mut removed, generation) = record_runtime::snapshot(&d.env()).unwrap();
    removed.local.keys.remove(&id);
    removed
        .account
        .as_mut()
        .unwrap()
        .records
        .remove(&crate::sync::record::record_key(
            crate::sync::record::RecordKind::KeySlot,
            &id,
        ));
    record_runtime::commit_candidate(&d.env(), generation, removed).unwrap();
    let after_removal = state(&d);
    let captured =
        super::super::capture_public(&after_removal, context.keys(), context.signer()).unwrap();
    let blocked = outbox::prepare(&captured, context.keys(), context.signer(), None).unwrap();
    assert!(blocked.records.iter().all(|row| row.header.kind != "key"));
    assert!(blocked.waiting_private > 0);
    let calls = AtomicUsize::new(0);
    assert!(private
        .with_transport(&d.env(), |_, _, _| {
            calls.fetch_add(1, Ordering::SeqCst);
            Ok(())
        })
        .is_err());
    assert_eq!(calls.load(Ordering::SeqCst), 0);
}

struct RekeyDuringProtectedRead<'a> {
    device: &'a TestDevice,
    armed: std::sync::atomic::AtomicBool,
}
impl Keychain for RekeyDuringProtectedRead<'_> {
    fn get(&self, account: &str) -> Result<Option<String>, AppError> {
        self.device.keychain.get(account)
    }
    fn get_noninteractive(&self, account: &str) -> Result<Option<String>, AppError> {
        let value = self.device.keychain.get_noninteractive(account)?;
        if self.armed.swap(false, Ordering::SeqCst) {
            let (mut records, generation) = record_runtime::snapshot(&self.device.env())?;
            records.local.central.as_mut().unwrap().control.phase =
                super::super::client_state::Phase::Rekey;
            record_runtime::commit_candidate(&self.device.env(), generation, records)?;
        }
        Ok(value)
    }
    fn set(&self, account: &str, secret: &str) -> Result<(), AppError> {
        self.device.keychain.set(account, secret)
    }
    fn delete(&self, account: &str) -> Result<(), AppError> {
        self.device.keychain.delete(account)
    }
}
#[test]
fn a_known_rekey_arriving_during_protected_read_blocks_http_even_with_the_same_native_session() {
    let (d, _) = fixture();
    let operation = prepare(&d.env(), None).unwrap().operation.unwrap();
    let selected = d
        .runtime
        .core
        .lock()
        .unwrap()
        .central_session
        .clone()
        .unwrap();
    let keychain = RekeyDuringProtectedRead {
        device: &d,
        armed: std::sync::atomic::AtomicBool::new(true),
    };
    let mut env = d.env();
    env.keychain = &keychain;
    let calls = AtomicUsize::new(0);
    assert!(operation
        .with_transport(&env, |_, _, _| {
            calls.fetch_add(1, Ordering::SeqCst);
            Ok(())
        })
        .is_err());
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    assert!(Arc::ptr_eq(
        d.runtime
            .core
            .lock()
            .unwrap()
            .central_session
            .as_ref()
            .unwrap(),
        &selected
    ));
}

#[test]
fn removed_or_rolled_back_saved_sent_evidence_cannot_enter_transport() {
    for missing in [false, true] {
        let (d, _) = fixture();
        let original = fs::read(&d.env().state_path).unwrap();
        let operation = prepare(&d.env(), None).unwrap().operation.unwrap();
        if missing {
            fs::remove_file(&d.env().state_path).unwrap();
        } else {
            fs::write(&d.env().state_path, original).unwrap();
        }
        let calls = AtomicUsize::new(0);
        assert!(operation
            .with_transport(&d.env(), |_, _, _| {
                calls.fetch_add(1, Ordering::SeqCst);
                Ok(())
            })
            .is_err());
        assert_eq!(calls.load(Ordering::SeqCst), 0);
    }
}

pub(in crate::sync) struct AssertUnlocked<'a> {
    pub runtime: &'a crate::sync::runtime::SyncRuntime,
}
impl crate::sync::env::SyncEvents for AssertUnlocked<'_> {
    fn status(&self) {
        assert!(
            self.runtime.lifecycle.try_lock().is_ok(),
            "status callback cannot hold lifecycle"
        );
        assert!(
            self.runtime.vault.try_lock().is_ok(),
            "status callback cannot hold vault"
        );
        assert!(
            self.runtime.format_publication.try_lock().is_ok(),
            "status callback cannot hold publication"
        );
        assert!(
            self.runtime.core.try_lock().is_ok(),
            "status callback cannot hold Core"
        );
    }
    fn applied(&self, _: usize) {
        self.status();
    }
    fn conflict(&self, _: &[crate::sync::dto::SyncConflict]) {
        self.status();
    }
    fn approval(&self, _: &[crate::sync::dto::ApprovalNotice]) {
        self.status();
    }
    fn notice(&self, _: &crate::sync::state_v2::SyncNotice) {
        self.status();
    }
    fn wake(&self) {}
}
#[test]
fn notifications_after_rename_and_claims_never_hold_runtime_locks() {
    let (d, id) = fixture();
    let probe = AssertUnlocked {
        runtime: &d.runtime,
    };
    let mut env = d.env();
    env.events = &probe;
    let operation = prepare(&env, None).unwrap().operation.unwrap();
    let (before, generation) = record_runtime::snapshot(&env).unwrap();
    let invocation = central_local::invocation(&before)
        .unwrap()
        .with_generation(generation);
    central_local::rename(
        &env,
        &invocation,
        &id,
        &before.local.keys[&id].public,
        "notify_name",
    )
    .unwrap();
    operation.claims(&env, &reply(&operation, &d)).unwrap();
}
