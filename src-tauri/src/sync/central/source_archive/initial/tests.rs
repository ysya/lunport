use super::*;
use crate::sync::{
    env::Keychain,
    fake_relay::FakeRelay,
    testkit::{MemKeychain, TestClock, TestDevice},
};
use std::{
    fs,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Mutex,
    },
};
fn fixture() -> (TestDevice, Workspace) {
    let d = TestDevice::new("initial-source", &FakeRelay::new(), &TestClock::new());
    fs::create_dir_all(d.env().state_path.parent().unwrap()).unwrap();
    let (owner, _, _) = crate::sync::central::migration_history::tests::initial();
    (d, owner)
}
struct Fault<'a> {
    inner: &'a MemKeychain,
    role: String,
    fail: Mutex<Option<(usize, bool)>>,
    writes: AtomicUsize,
}
impl Fault<'_> {
    fn arm(&self, n: usize, after: bool) {
        self.writes.store(0, Ordering::SeqCst);
        *self.fail.lock().unwrap() = Some((n, after));
    }
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
        panic!("initialization must never delete credentials")
    }
    fn set_noninteractive(&self, k: &str, v: &str) -> Result<(), AppError> {
        if k != self.role {
            return self.inner.set_noninteractive(k, v);
        }
        let n = self.writes.fetch_add(1, Ordering::SeqCst) + 1;
        let failure = *self.fail.lock().unwrap();
        if failure == Some((n, false)) {
            return Err(invalid());
        }
        self.inner.set_noninteractive(k, v)?;
        if failure == Some((n, true)) {
            return Err(invalid());
        }
        Ok(())
    }
}
fn tree(d: &TestDevice) -> Vec<(String, Vec<u8>)> {
    let root = d
        .env()
        .state_path
        .parent()
        .unwrap()
        .join("central-source-archives");
    let mut files = Vec::new();
    if root.exists() {
        for entry in fs::read_dir(root).unwrap() {
            let e = entry.unwrap();
            files.push((
                e.file_name().to_str().unwrap().to_owned(),
                fs::read(e.path()).unwrap(),
            ));
        }
    }
    files.sort_by(|a, b| a.0.cmp(&b.0));
    files
}
#[test]
fn interrupted_first_reservation_never_creates_outputs_and_recovers_its_saved_operation() {
    for after in [false, true] {
        let (d, owner) = fixture();
        let protected = Fault {
            inner: &d.keychain,
            role: role(&owner).unwrap(),
            fail: Mutex::new(None),
            writes: AtomicUsize::new(0),
        };
        protected.arm(1, after);
        let mut env = d.env();
        env.keychain = &protected;
        let life = env.runtime.lifecycle.lock().unwrap();
        let plain = Zeroizing::new(b"PRIVATE_INITIAL_SOURCE".to_vec());
        assert!(initialize(&env, &life, &owner, 73, &plain).is_err());
        assert!(tree(&d).is_empty());
        let reserved = Initial::load(&env, &owner).unwrap();
        assert_eq!(reserved.is_some(), after);
        protected.arm(usize::MAX, false);
        let loaded = initialize(&env, &life, &owner, 0, &plain).unwrap();
        assert_eq!(loaded.bytes.as_slice(), plain.as_slice());
        assert_eq!(loaded.cursor.revision(), 1);
        if let Some(before) = reserved {
            assert_eq!(loaded.cursor.receipt().context, before.context);
        }
        let saved = d.keychain.entry(&role(&owner).unwrap()).unwrap();
        assert!(!saved.contains("PRIVATE_INITIAL_SOURCE"));
        assert!(matches!(
            Initial::load(&env, &owner).unwrap().unwrap().stage,
            Stage::Attached { .. }
        ));
    }
}
#[test]
fn receipt_and_attachment_failures_reuse_exact_ciphertext_after_process_reentry() {
    for step in [2, 3] {
        for after in [false, true] {
            let (d, owner) = fixture();
            let protected = Fault {
                inner: &d.keychain,
                role: role(&owner).unwrap(),
                fail: Mutex::new(None),
                writes: AtomicUsize::new(0),
            };
            protected.arm(step, after);
            let mut env = d.env();
            env.keychain = &protected;
            let life = env.runtime.lifecycle.lock().unwrap();
            let plain = Zeroizing::new(b"ORIGINAL_PACKAGE".to_vec());
            assert!(initialize(&env, &life, &owner, 91, &plain).is_err());
            let exact = tree(&d);
            assert_eq!(exact.len(), 2);
            let reserved = Initial::load(&env, &owner).unwrap().unwrap();
            protected.arm(usize::MAX, false);
            // A restarted runtime can have generation zero; the saved archive ordinal remains 91.
            let loaded = initialize(&env, &life, &owner, 0, &plain).unwrap();
            assert_eq!(tree(&d), exact);
            assert_eq!(loaded.cursor.receipt().context, reserved.context);
            assert_eq!(loaded.cursor.receipt().context.generation, "91");
            assert!(matches!(
                Initial::load(&env, &owner).unwrap().unwrap().stage,
                Stage::Attached { .. }
            ));
        }
    }
}
#[test]
fn first_cursor_write_failure_before_or_after_success_restores_the_completed_original() {
    for after in [false, true] {
        let (d, owner) = fixture();
        let cursor_role = owner
            .control
            .profile
            .profile()
            .unwrap()
            .slot("source-migration-cursor");
        let protected = Fault {
            inner: &d.keychain,
            role: cursor_role,
            fail: Mutex::new(None),
            writes: AtomicUsize::new(0),
        };
        protected.arm(1, after);
        let mut env = d.env();
        env.keychain = &protected;
        let life = env.runtime.lifecycle.lock().unwrap();
        let plain = Zeroizing::new(b"SOURCE".to_vec());
        assert!(initialize(&env, &life, &owner, 4, &plain).is_err());
        let exact = tree(&d);
        assert!(matches!(
            Initial::load(&env, &owner).unwrap().unwrap().stage,
            Stage::Complete { .. }
        ));
        protected.arm(usize::MAX, false);
        initialize(&env, &life, &owner, 0, &plain).unwrap();
        assert_eq!(tree(&d), exact);
    }
}
#[test]
fn changed_source_owner_or_selection_cannot_replace_a_pending_or_attached_operation() {
    let (d, owner) = fixture();
    let protected = Fault {
        inner: &d.keychain,
        role: role(&owner).unwrap(),
        fail: Mutex::new(None),
        writes: AtomicUsize::new(0),
    };
    protected.arm(2, false);
    let mut env = d.env();
    env.keychain = &protected;
    let life = env.runtime.lifecycle.lock().unwrap();
    let plain = Zeroizing::new(b"ORIGINAL".to_vec());
    assert!(initialize(&env, &life, &owner, 5, &plain).is_err());
    let exact = tree(&d);
    let before = d.keychain.entry(&role(&owner).unwrap()).unwrap();
    assert!(initialize(&env, &life, &owner, 5, &Zeroizing::new(b"CHANGED".to_vec())).is_err());
    let mut changed = owner.clone();
    changed.identity_slot = Some("8".repeat(32));
    assert!(initialize(&env, &life, &changed, 5, &plain).is_err());
    assert_eq!(d.keychain.entry(&role(&owner).unwrap()).unwrap(), before);
    assert_eq!(tree(&d), exact);
    protected.arm(usize::MAX, false);
    initialize(&env, &life, &owner, 0, &plain).unwrap();
    assert!(initialize(&env, &life, &owner, 0, &Zeroizing::new(b"CHANGED".to_vec())).is_err());
    assert_eq!(tree(&d), exact);
}
#[test]
fn attached_cursor_or_completed_blob_marker_and_key_loss_never_reinitializes_or_repairs() {
    for missing in ["cursor", "blob", "marker", "key"] {
        let (d, owner) = fixture();
        let env = d.env();
        let life = env.runtime.lifecycle.lock().unwrap();
        let plain = Zeroizing::new(b"SOURCE".to_vec());
        let first = initialize(&env, &life, &owner, 5, &plain).unwrap();
        let initial = d.keychain.entry(&role(&owner).unwrap()).unwrap();
        match missing {
            "cursor" => d
                .keychain
                .delete(
                    &owner
                        .control
                        .profile
                        .profile()
                        .unwrap()
                        .slot("source-migration-cursor"),
                )
                .unwrap(),
            "key" => d
                .keychain
                .delete(
                    &first
                        .cursor
                        .receipt()
                        .context
                        .key_role(&owner.control.profile.profile().unwrap())
                        .unwrap(),
                )
                .unwrap(),
            _ => {
                let name = if missing == "blob" {
                    first.cursor.receipt().context.filename().unwrap()
                } else {
                    first.cursor.receipt().context.marker()
                };
                fs::remove_file(
                    env.state_path
                        .parent()
                        .unwrap()
                        .join("central-source-archives")
                        .join(name),
                )
                .unwrap();
            }
        }
        let exact = tree(&d);
        assert!(
            initialize(&env, &life, &owner, 0, &plain).is_err(),
            "{missing}"
        );
        assert_eq!(tree(&d), exact);
        assert_eq!(d.keychain.entry(&role(&owner).unwrap()).unwrap(), initial);
    }
}
#[test]
fn a_reserved_marker_without_its_master_is_never_given_a_new_key() {
    let (d, owner) = fixture();
    let env = d.env();
    let life = env.runtime.lifecycle.lock().unwrap();
    let plain = Zeroizing::new(b"SOURCE".to_vec());
    let initial = Initial {
        version: 1,
        selection: owner.identity_slot.clone(),
        context: Context::fresh(&owner, 1).unwrap(),
        source: crypto::hash(&plain),
        stage: Stage::Reserved,
    };
    initial.save(&env, &owner, None).unwrap();
    let profile = owner.control.profile.profile().unwrap();
    let key = protected_key(&env, &profile, &initial.context, true).unwrap();
    let directory = ArchiveDirectory::open(&env, Kind::Source).unwrap();
    directory
        .publish(
            &initial.context.marker(),
            crypto::hash(key.as_slice()).as_bytes(),
        )
        .unwrap();
    directory.sync().unwrap();
    let master = initial.context.key_role(&profile).unwrap();
    d.keychain.delete(&master).unwrap();
    let exact = tree(&d);
    assert!(initialize(&env, &life, &owner, 0, &plain).is_err());
    assert!(d.keychain.entry(&master).is_none());
    assert_eq!(tree(&d), exact);
}

#[test]
fn full_package_preflight_rejects_changed_sources_before_reserving_or_encrypting() {
    let (d, package, _, owner, _) = crate::sync::central::source_package::tests::fixture();
    let env = d.env();
    let life = env.runtime.lifecycle.lock().unwrap();
    fs::write(
        env.state_path.parent().unwrap().join("vault.json"),
        b"changed source",
    )
    .unwrap();
    assert!(package.initialize_source(&env, &life, &owner, 3).is_err());
    assert!(d.keychain.entry(&role(&owner).unwrap()).is_none());
    assert!(tree(&d).is_empty());
}
#[test]
fn package_reentry_excludes_only_verified_own_outputs_and_keeps_unrelated_files_obligatory() {
    let (d, package, _, owner, _) = crate::sync::central::source_package::tests::fixture();
    let protected = Fault {
        inner: &d.keychain,
        role: role(&owner).unwrap(),
        fail: Mutex::new(None),
        writes: AtomicUsize::new(0),
    };
    protected.arm(2, false);
    let mut env = d.env();
    env.keychain = &protected;
    let life = env.runtime.lifecycle.lock().unwrap();
    assert!(package.initialize_source(&env, &life, &owner, 3).is_err());
    let exact = tree(&d);
    assert_eq!(exact.len(), 2);
    let unrelated = env
        .state_path
        .parent()
        .unwrap()
        .join("central-source-archives/unrelated.lpsource");
    fs::write(&unrelated, b"unrelated retained obligation").unwrap();
    protected.arm(usize::MAX, false);
    assert!(package.initialize_source(&env, &life, &owner, 0).is_err());
    assert_eq!(protected.writes.load(Ordering::SeqCst), 0);
    assert_eq!(
        fs::read(&unrelated).unwrap(),
        b"unrelated retained obligation"
    );
    fs::remove_file(unrelated).unwrap();
    let restored = package.initialize_source(&env, &life, &owner, 0).unwrap();
    assert_eq!(restored.cursor.revision(), 1);
    assert_eq!(tree(&d), exact);
}
#[test]
fn a_reserved_key_and_marker_can_finish_before_any_ciphertext_was_published() {
    let (d, package, _, owner, _) = crate::sync::central::source_package::tests::fixture();
    let env = d.env();
    let life = env.runtime.lifecycle.lock().unwrap();
    let plain = package.encode_local().unwrap();
    let initial = Initial {
        version: 1,
        selection: owner.identity_slot.clone(),
        context: Context::fresh(&owner, 6).unwrap(),
        source: crypto::hash(&plain),
        stage: Stage::Reserved,
    };
    initial.save(&env, &owner, None).unwrap();
    let key = protected_key(
        &env,
        &owner.control.profile.profile().unwrap(),
        &initial.context,
        true,
    )
    .unwrap();
    let directory = ArchiveDirectory::open(&env, Kind::Source).unwrap();
    directory
        .publish(
            &initial.context.marker(),
            crypto::hash(key.as_slice()).as_bytes(),
        )
        .unwrap();
    directory.sync().unwrap();
    let restored = package.initialize_source(&env, &life, &owner, 0).unwrap();
    assert_eq!(restored.cursor.receipt().context, initial.context);
    assert_eq!(tree(&d).len(), 2);
}

#[test]
fn a_source_change_during_encryption_is_caught_before_any_cursor_attachment() {
    let (d, owner) = fixture();
    let env = d.env();
    let life = env.runtime.lifecycle.lock().unwrap();
    let plain = Zeroizing::new(b"SOURCE".to_vec());
    let calls = AtomicUsize::new(0);
    assert!(initialize_checked(&env, &life, &owner, 0, &plain, |_| {
        if calls.fetch_add(1, Ordering::SeqCst) == 0 {
            Ok(())
        } else {
            Err(crate::sync::runtime::superseded())
        }
    })
    .is_err());
    assert!(Cursor::load(&env, &life, &owner).unwrap().is_none());
    assert!(matches!(
        Initial::load(&env, &owner).unwrap().unwrap().stage,
        Stage::Reserved
    ));
    let exact = tree(&d);
    initialize(&env, &life, &owner, 0, &plain).unwrap();
    assert_eq!(tree(&d), exact);
}
