use super::*;
use crate::sync::{env::Keychain, testkit::MemKeychain};
use std::{
    collections::BTreeMap,
    fs,
    sync::atomic::{AtomicBool, Ordering},
};
fn tree(env: &SyncEnv) -> BTreeMap<std::ffi::OsString, Vec<u8>> {
    let root = env
        .state_path
        .parent()
        .unwrap()
        .join("central-source-archives");
    if !root.exists() {
        return BTreeMap::new();
    }
    fs::read_dir(root)
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
        panic!("complete-source transition cannot delete credentials")
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
fn incomplete_or_unstarted_capture_never_creates_complete_source_evidence() {
    let (d, keys, _) = source_capture::tests::fixture(false);
    let env = d.env();
    assert!(ensure(&env, &keys).unwrap().is_none());
    assert!(tree(&env).is_empty());
    source_capture::start_or_resume(&env, &keys, &BTreeMap::new()).unwrap();
    let before = tree(&env);
    assert!(ensure(&env, &keys).unwrap().is_none());
    assert_eq!(tree(&env), before);
}
#[test]
fn complete_source_roundtrips_through_the_protected_predecessor_and_never_changes_live_core() {
    for joined in [false, true] {
        let (d, keys) = capture_dispatch::ready_for_test(joined);
        let env = d.env();
        let before = record_runtime::snapshot(&env).unwrap();
        let complete = ensure(&env, &keys).unwrap().unwrap();
        assert_eq!(complete.ancestors.len() as u64, complete.cursor.revision());
        let original = complete.package.encode_local().unwrap();
        assert!(Package::complete_frame(&original));
        complete
            .package
            .structured_history(&keys, &BTreeMap::new())
            .unwrap();
        let exact = tree(&env);
        let receipt = complete.cursor.receipt().clone();
        drop(complete);
        let restored = ensure(&env, &keys).unwrap().unwrap();
        assert_eq!(restored.cursor.receipt(), &receipt);
        assert_eq!(
            restored.package.encode_local().unwrap().as_slice(),
            original.as_slice()
        );
        assert_eq!(tree(&env), exact);
        assert_eq!(record_runtime::snapshot(&env).unwrap(), before);
        assert!(
            !restored
                .package
                .state
                .local
                .central
                .as_ref()
                .unwrap()
                .control
                .cutover
        );
    }
}
#[test]
fn compact_complete_source_needs_no_second_source_copy_or_protected_write() {
    for after in [false, true] {
        let (d, keys) = capture_dispatch::ready_for_test(true);
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
        let exact = tree(&env);
        let before = ensure(&interrupted, &keys).unwrap().unwrap();
        assert!(fault.armed.load(Ordering::SeqCst));
        assert_eq!(tree(&env), exact);
        let receipt = before.cursor.receipt().clone();
        d.runtime.core.lock().unwrap().generation = 0;
        let complete = ensure(&env, &keys).unwrap().unwrap();
        assert_eq!(tree(&env), exact);
        assert_eq!(complete.ancestors.len() as u64, complete.cursor.revision());
        assert_eq!(complete.cursor.receipt(), &receipt);
    }
}
#[test]
fn unknown_or_duplicate_complete_step_blobs_cannot_replace_the_expected_package() {
    for duplicate in [false, true] {
        let (d, keys) = capture_dispatch::ready_for_test(false);
        let env = d.env();
        let owner = record_runtime::snapshot(&env)
            .unwrap()
            .0
            .local
            .central
            .unwrap();
        let life = env.runtime.lifecycle.lock().unwrap();
        // Keep the Session allocation alive while using the synthetic signer.
        let session = controller::context(&env).unwrap();
        let signer = &session.identity.as_ref().unwrap().keys;
        let loaded = Journal::load(&env, &life, &owner, signer).unwrap().unwrap();
        let (package, _, before, _) = loaded.into_complete().unwrap();
        let bytes = if duplicate {
            package.encode_local().unwrap()
        } else {
            zeroize::Zeroizing::new(b"UNKNOWN_COMPLETE_SOURCE".to_vec())
        };
        source_archive::next(
            &env,
            &life,
            &owner,
            before.receipt().next_ordinal().unwrap(),
            before.receipt(),
            &bytes,
        )
        .unwrap();
        if duplicate {
            source_archive::next(
                &env,
                &life,
                &owner,
                before.receipt().next_ordinal().unwrap(),
                before.receipt(),
                &bytes,
            )
            .unwrap();
        }
        drop(life);
        let exact = tree(&env);
        assert!(ensure(&env, &keys).is_err());
        assert_eq!(tree(&env), exact);
    }
}
#[test]
fn missing_predecessor_or_a_new_source_file_blocks_complete_source_reentry() {
    for missing in [false, true] {
        let (d, keys) = capture_dispatch::ready_for_test(false);
        let env = d.env();
        let complete = ensure(&env, &keys).unwrap().unwrap();
        if missing {
            let hash = &complete.cursor.previous().unwrap().ciphertext_hash;
            let files = tree(&env);
            let name = files
                .iter()
                .find(|(_, bytes)| super::super::crypto::hash(bytes) == *hash)
                .unwrap()
                .0;
            fs::remove_file(
                env.state_path
                    .parent()
                    .unwrap()
                    .join("central-source-archives")
                    .join(name),
            )
            .unwrap();
        } else {
            fs::write(&env.state_path, b"new source B").unwrap();
        }
        let exact = tree(&env);
        assert!(ensure(&env, &keys).is_err());
        assert_eq!(tree(&env), exact);
    }
}
