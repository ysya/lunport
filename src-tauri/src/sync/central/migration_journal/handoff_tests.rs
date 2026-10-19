use super::*;
use crate::sync::{
    env::Keychain,
    record_runtime,
    testkit::{MemKeychain, TestDevice},
};
use std::{
    fs,
    sync::atomic::{AtomicBool, Ordering},
};
fn fixture() -> (TestDevice, VaultKeys) {
    let (d, keys) = super::super::capture_dispatch::ready_for_test(false);
    super::super::source_complete::ensure(&d.env(), &keys)
        .unwrap()
        .unwrap();
    source_plan::ensure(&d.env(), &keys, &BTreeMap::new()).unwrap();
    (d, keys)
}
fn tree(env: &SyncEnv) -> BTreeMap<std::ffi::OsString, Vec<u8>> {
    fs::read_dir(
        env.state_path
            .parent()
            .unwrap()
            .join("central-source-archives"),
    )
    .unwrap()
    .map(|e| {
        let e = e.unwrap();
        (e.file_name(), fs::read(e.path()).unwrap())
    })
    .collect()
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
        panic!("no credential deletion")
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
fn complete_source_and_bound_plan_enter_the_same_small_journal_without_consent_or_core_changes() {
    let (d, keys) = fixture();
    let env = d.env();
    let before = record_runtime::snapshot(&env).unwrap();
    let loaded = ensure(&env, &keys, &BTreeMap::new()).unwrap();
    assert!(loaded.journal.progress.is_none());
    assert!(loaded.journal.verified.is_none());
    assert!(loaded.journal.encode().unwrap().len() < 32768);
    let receipt = loaded.cursor.receipt().clone();
    let exact = tree(&env);
    assert_eq!(record_runtime::snapshot(&env).unwrap(), before);
    drop(loaded);
    d.runtime.core.lock().unwrap().generation = 0;
    let restored = ensure(&env, &keys, &BTreeMap::new()).unwrap();
    assert_eq!(restored.cursor.receipt(), &receipt);
    assert_eq!(tree(&env), exact);
    assert_eq!(record_runtime::snapshot(&env).unwrap().0, before.0);
    assert_eq!(record_runtime::snapshot(&env).unwrap().1, 0);
    let owner = restored.package.state.local.central.as_ref().unwrap();
    assert!(owner.control.library.is_none());
    assert!(!owner.control.cutover);
}
#[test]
fn direct_complete_source_entry_also_persists_and_binds_the_plan() {
    let (d, keys) = super::super::capture_dispatch::ready_for_test(false);
    super::super::source_complete::ensure(&d.env(), &keys)
        .unwrap()
        .unwrap();
    let loaded = ensure(&d.env(), &keys, &BTreeMap::new()).unwrap();
    assert_eq!(
        loaded.journal.source.ciphertext_hash,
        loaded.plan.manifest.body.inventory_digest
    );
    let exact = tree(&d.env());
    assert!(ensure(&d.env(), &keys, &BTreeMap::new()).is_ok());
    assert_eq!(tree(&d.env()), exact);
}
#[test]
fn cold_first_journal_reentry_reuses_exact_ciphertext_after_either_cursor_write_failure() {
    for after in [false, true] {
        let (d, keys) = fixture();
        let env = d.env();
        let owner = record_runtime::snapshot(&env)
            .unwrap()
            .0
            .local
            .central
            .unwrap();
        let fault = Fault {
            inner: &d.keychain,
            role: owner
                .control
                .profile
                .profile()
                .unwrap()
                .slot("source-migration-cursor"),
            after,
            armed: AtomicBool::new(true),
        };
        let mut interrupted = d.env();
        interrupted.keychain = &fault;
        assert!(ensure(&interrupted, &keys, &BTreeMap::new()).is_err());
        let exact = tree(&env);
        d.runtime.core.lock().unwrap().generation = 0;
        let loaded = ensure(&env, &keys, &BTreeMap::new()).unwrap();
        assert_eq!(tree(&env), exact);
        assert!(loaded.journal.progress.is_none());
        let receipt = loaded.cursor.receipt().clone();
        drop(loaded);
        assert_eq!(
            ensure(&env, &keys, &BTreeMap::new())
                .unwrap()
                .cursor
                .receipt(),
            &receipt
        );
    }
}
#[test]
fn unknown_or_duplicate_pending_journal_is_retained_and_never_admitted() {
    for duplicate in [false, true] {
        let (d, keys) = fixture();
        let env = d.env();
        let planned = source_plan::ensure(&env, &keys, &BTreeMap::new()).unwrap();
        let owner = planned.package.state.local.central.as_ref().unwrap();
        let life = env.runtime.lifecycle.lock().unwrap();
        let bytes = if duplicate {
            Journal::planned(
                &planned.cursor,
                planned.source_cursor.receipt().clone(),
                planned.ancestors,
                owner,
            )
            .unwrap()
            .encode()
            .unwrap()
        } else {
            Zeroizing::new(b"UNKNOWN_JOURNAL".to_vec())
        };
        for _ in 0..if duplicate { 2 } else { 1 } {
            source_archive::next(
                &env,
                &life,
                owner,
                planned.cursor.receipt().next_ordinal().unwrap(),
                planned.cursor.receipt(),
                &bytes,
            )
            .unwrap();
        }
        drop(life);
        let exact = tree(&env);
        assert!(ensure(&env, &keys, &BTreeMap::new()).is_err());
        assert_eq!(tree(&env), exact);
    }
}
#[test]
fn new_source_or_missing_capture_ancestry_blocks_cold_planned_reentry() {
    for missing in [false, true] {
        let (d, keys) = fixture();
        let env = d.env();
        let loaded = ensure(&env, &keys, &BTreeMap::new()).unwrap();
        if missing {
            let hash = &loaded.journal.ancestors[0].ciphertext_hash;
            let path = tree(&env)
                .into_iter()
                .find(|(_, bytes)| super::super::crypto::hash(bytes) == *hash)
                .unwrap()
                .0;
            fs::remove_file(
                env.state_path
                    .parent()
                    .unwrap()
                    .join("central-source-archives")
                    .join(path),
            )
            .unwrap();
        } else {
            fs::write(&env.state_path, b"new source B").unwrap();
        }
        let exact = tree(&env);
        assert!(ensure(&env, &keys, &BTreeMap::new()).is_err());
        assert_eq!(tree(&env), exact);
    }
}
#[test]
fn later_progress_also_recovers_one_exact_blob_after_a_failed_cursor_write_before_persistence() {
    let (d, keys) = fixture();
    let env = d.env();
    let loaded = ensure(&env, &keys, &BTreeMap::new()).unwrap();
    let owner = loaded.package.state.local.central.as_ref().unwrap();
    let signer = controller::context(&env).unwrap();
    let signer = &signer.identity.as_ref().unwrap().keys;
    let next = loaded
        .with_progress(super::tests::progress(&loaded.plan, 0), owner)
        .unwrap()
        .unwrap();
    let bytes = next.encode().unwrap();
    let fault = Fault {
        inner: &d.keychain,
        role: owner
            .control
            .profile
            .profile()
            .unwrap()
            .slot("source-migration-cursor"),
        after: false,
        armed: AtomicBool::new(true),
    };
    let mut interrupted = d.env();
    interrupted.keychain = &fault;
    let life = env.runtime.lifecycle.lock().unwrap();
    let ordinal = loaded.cursor.receipt().next_ordinal().unwrap();
    assert!(next
        .store(
            &interrupted,
            &life,
            owner,
            &keys,
            signer,
            &loaded.cursor,
            ordinal
        )
        .is_err());
    let exact = tree(&env);
    let retry = Journal::decode(&bytes)
        .unwrap()
        .store(&env, &life, owner, &keys, signer, &loaded.cursor, ordinal)
        .unwrap();
    assert_eq!(tree(&env), exact);
    assert_eq!(retry.journal.progress.as_ref().unwrap().staged(), 0);
    drop(life);
    assert!(ensure(&env, &keys, &BTreeMap::new()).is_ok());
}

#[test]
fn cold_planned_entry_reconstructs_one_pending_progress_step_without_another_request() {
    let (d, keys) = fixture();
    let env = d.env();
    let loaded = ensure(&env, &keys, &BTreeMap::new()).unwrap();
    let owner = loaded.package.state.local.central.as_ref().unwrap();
    let session = controller::context(&env).unwrap();
    let signer = &session.identity.as_ref().unwrap().keys;
    let fault = Fault {
        inner: &d.keychain,
        role: owner
            .control
            .profile
            .profile()
            .unwrap()
            .slot("source-migration-cursor"),
        after: false,
        armed: AtomicBool::new(true),
    };
    let mut interrupted = d.env();
    interrupted.keychain = &fault;
    let life = env.runtime.lifecycle.lock().unwrap();
    let next = loaded
        .with_progress(super::tests::progress(&loaded.plan, 1), owner)
        .unwrap()
        .unwrap();
    assert!(next
        .store(
            &interrupted,
            &life,
            owner,
            &keys,
            signer,
            &loaded.cursor,
            loaded.cursor.receipt().next_ordinal().unwrap()
        )
        .is_err());
    drop(life);
    let exact = tree(&env);
    d.runtime.core.lock().unwrap().generation = 0;
    let restored = ensure(&env, &keys, &BTreeMap::new()).unwrap();
    assert_eq!(restored.journal.progress.as_ref().unwrap().staged(), 1);
    assert_eq!(tree(&env), exact);
}
#[test]
fn an_unbound_signed_plan_and_journal_never_pass_the_runtime_whole_source_gate() {
    let (d, keys) = super::super::capture_dispatch::ready_for_test(false);
    let env = d.env();
    let source = source_complete::ensure(&env, &keys).unwrap().unwrap();
    let owner = source.package.state.local.central.as_ref().unwrap();
    let session = controller::context(&env).unwrap();
    let signer = &session.identity.as_ref().unwrap().keys;
    let history = source
        .package
        .structured_history(&keys, &BTreeMap::new())
        .unwrap()
        .into_rows();
    let plan = super::super::migration_history::prepare(
        owner,
        &keys,
        signer,
        source
            .package
            .migration_context(source.cursor.receipt())
            .unwrap(),
        &history,
    )
    .unwrap();
    let life = env.runtime.lifecycle.lock().unwrap();
    let archive = source_archive::next(
        &env,
        &life,
        owner,
        source.cursor.receipt().next_ordinal().unwrap(),
        source.cursor.receipt(),
        &plan.encode_local().unwrap(),
    )
    .unwrap();
    let cursor = source
        .cursor
        .advance(&env, &life, owner, &archive)
        .unwrap()
        .cursor;
    let mut ancestors = source.ancestors;
    ancestors.push(cursor.receipt().clone());
    Journal::planned(&cursor, source.cursor.receipt().clone(), ancestors, owner)
        .unwrap()
        .store(
            &env,
            &life,
            owner,
            &keys,
            signer,
            &cursor,
            cursor.receipt().next_ordinal().unwrap(),
        )
        .unwrap();
    drop(life);
    let exact = tree(&env);
    assert!(ensure(&env, &keys, &BTreeMap::new()).is_err());
    assert_eq!(tree(&env), exact);
}
