use super::*;
use crate::sync::{
    env::Keychain,
    fake_relay::FakeRelay,
    testkit::{MemKeychain, TestClock, TestDevice},
};
use std::{
    fs,
    sync::atomic::{AtomicBool, AtomicUsize, Ordering},
};
fn fixture() -> (TestDevice, Workspace) {
    let device = TestDevice::new("source-cursor", &FakeRelay::new(), &TestClock::new());
    fs::create_dir_all(device.env().state_path.parent().unwrap()).unwrap();
    let (owner, _, _) = crate::sync::central::migration_history::tests::initial();
    (device, owner)
}
#[test]
fn protected_cursor_advances_restores_exact_bytes_and_accepts_only_the_same_uncertain_write_retry()
{
    let (device, owner) = fixture();
    let env = device.env();
    let life = env.runtime.lifecycle.lock().unwrap();
    let a = Zeroizing::new(b"PRIVATE_SOURCE_A".to_vec());
    let first = source_archive::create(&env, &life, &owner, 5, &a).unwrap();
    let initial = Cursor::initialize(&env, &life, &owner, &first).unwrap();
    assert_eq!(initial.bytes.as_slice(), a.as_slice());
    assert_eq!(initial.cursor.revision, 1);
    let b = Zeroizing::new(b"PRIVATE_SOURCE_B".to_vec());
    let second = source_archive::next(&env, &life, &owner, 5, first.receipt(), &b).unwrap();
    let advanced = initial
        .cursor
        .advance(&env, &life, &owner, &second)
        .unwrap();
    assert_eq!(advanced.bytes.as_slice(), b.as_slice());
    assert_eq!(advanced.cursor.revision, 2);
    assert!(advanced.cursor.previous.as_ref() == Some(first.receipt()));
    let saved = device.keychain.entry(&role(&owner).unwrap()).unwrap();
    assert!(!saved.contains("PRIVATE_SOURCE"));
    device.keychain.fail_writes_to(&role(&owner).unwrap(), true);
    let retry = initial
        .cursor
        .advance(&env, &life, &owner, &second)
        .unwrap();
    assert!(retry.cursor == advanced.cursor);
    assert!(Cursor::load(&env, &life, &owner).unwrap().unwrap().cursor == advanced.cursor);
    assert!(Cursor::initialize(&env, &life, &owner, &first).is_err());
    let third = source_archive::next(
        &env,
        &life,
        &owner,
        6,
        second.receipt(),
        &Zeroizing::new(b"C".to_vec()),
    )
    .unwrap();
    assert!(initial.cursor.advance(&env, &life, &owner, &third).is_err());
    assert_eq!(
        device.keychain.entry(&role(&owner).unwrap()).unwrap(),
        saved
    );
}
#[test]
fn crossed_operations_and_older_source_generations_cannot_replace_the_protected_cursor() {
    let (device, owner) = fixture();
    let env = device.env();
    let life = env.runtime.lifecycle.lock().unwrap();
    let plain = Zeroizing::new(b"source".to_vec());
    let first = source_archive::create(&env, &life, &owner, 7, &plain).unwrap();
    let current = Cursor::initialize(&env, &life, &owner, &first)
        .unwrap()
        .cursor;
    let other = source_archive::create(&env, &life, &owner, 8, &plain).unwrap();
    assert!(current.advance(&env, &life, &owner, &other).is_err());
    let older = source_archive::next(&env, &life, &owner, 6, first.receipt(), &plain).unwrap();
    assert!(current.advance(&env, &life, &owner, &older).is_err());
    assert!(current.advance(&env, &life, &owner, &first).is_err());
    assert!(Cursor::load(&env, &life, &owner).unwrap().unwrap().cursor == current);
}
#[test]
fn a_missing_known_cursor_never_reinitializes_it_on_advance() {
    let (device, owner) = fixture();
    let env = device.env();
    let life = env.runtime.lifecycle.lock().unwrap();
    let plain = Zeroizing::new(b"source".to_vec());
    let first = source_archive::create(&env, &life, &owner, 0, &plain).unwrap();
    let current = Cursor::initialize(&env, &life, &owner, &first)
        .unwrap()
        .cursor;
    let next = source_archive::next(&env, &life, &owner, 1, first.receipt(), &plain).unwrap();
    device.keychain.delete(&role(&owner).unwrap()).unwrap();
    assert!(current.advance(&env, &life, &owner, &next).is_err());
    assert!(device.keychain.entry(&role(&owner).unwrap()).is_none());
}
#[test]
fn missing_source_blob_marker_or_master_never_repairs_or_recreates_resume_inputs() {
    for missing in ["blob", "marker", "master"] {
        let (device, owner) = fixture();
        let env = device.env();
        let life = env.runtime.lifecycle.lock().unwrap();
        let plain = Zeroizing::new(b"source".to_vec());
        let archived = source_archive::create(&env, &life, &owner, 0, &plain).unwrap();
        Cursor::initialize(&env, &life, &owner, &archived).unwrap();
        let profile = owner.control.profile.profile().unwrap();
        let master = profile.slot(&format!(
            "source-archive-{}",
            archived.receipt().operation()
        ));
        let cursor_before = device.keychain.entry(&role(&owner).unwrap()).unwrap();
        if missing == "master" {
            device.keychain.delete(&master).unwrap();
        } else {
            let ext = if missing == "blob" {
                "lpsource"
            } else {
                "sha256"
            };
            let path = fs::read_dir(
                env.state_path
                    .parent()
                    .unwrap()
                    .join("central-source-archives"),
            )
            .unwrap()
            .map(Result::unwrap)
            .map(|entry| entry.path())
            .find(|path| path.extension().and_then(|v| v.to_str()) == Some(ext))
            .unwrap();
            fs::remove_file(path).unwrap();
        }
        assert!(Cursor::load(&env, &life, &owner).is_err(), "{missing}");
        assert_eq!(
            device.keychain.entry(&role(&owner).unwrap()).unwrap(),
            cursor_before
        );
        if missing == "master" {
            assert!(device.keychain.entry(&master).is_none());
        }
    }
}
#[test]
fn corrupt_metadata_or_a_different_device_storage_selection_never_loads_or_overwrites_progress() {
    let (device, owner) = fixture();
    let env = device.env();
    let life = env.runtime.lifecycle.lock().unwrap();
    let plain = Zeroizing::new(b"source".to_vec());
    let archive = source_archive::create(&env, &life, &owner, 0, &plain).unwrap();
    Cursor::initialize(&env, &life, &owner, &archive).unwrap();
    let cursor_role = role(&owner).unwrap();
    let original = device.keychain.entry(&cursor_role).unwrap();
    for case in ["version", "revision", "selection", "unknown", "ciphertext"] {
        let mut value: serde_json::Value = serde_json::from_str(&original).unwrap();
        match case {
            "version" => value["version"] = 2.into(),
            "revision" => value["revision"] = 0.into(),
            "selection" => value["selection"] = "8".repeat(32).into(),
            "unknown" => value["other"] = true.into(),
            _ => value["receipt"]["ciphertext_hash"] = "0".repeat(64).into(),
        }
        let encoded = serde_json::to_string(&value).unwrap();
        device.keychain.set(&cursor_role, &encoded).unwrap();
        assert!(Cursor::load(&env, &life, &owner).is_err(), "{case}");
        assert!(
            Cursor::initialize(&env, &life, &owner, &archive).is_err(),
            "{case}"
        );
        assert_eq!(device.keychain.entry(&cursor_role).unwrap(), encoded);
    }
    device.keychain.set(&cursor_role, &original).unwrap();
    let mut changed = owner.clone();
    changed.identity_slot = Some("7".repeat(32));
    assert!(Cursor::load(&env, &life, &changed).is_err());
}
struct NoPrompt<'a> {
    inner: &'a MemKeychain,
    fail_after: AtomicBool,
    writes: AtomicUsize,
}
impl Keychain for NoPrompt<'_> {
    fn get(&self, _: &str) -> Result<Option<String>, AppError> {
        panic!("interactive credential read")
    }
    fn set(&self, _: &str, _: &str) -> Result<(), AppError> {
        panic!("interactive credential write")
    }
    fn delete(&self, _: &str) -> Result<(), AppError> {
        panic!("credential deletion")
    }
    fn get_noninteractive(&self, account: &str) -> Result<Option<String>, AppError> {
        self.inner.get_noninteractive(account)
    }
    fn set_noninteractive(&self, account: &str, value: &str) -> Result<(), AppError> {
        self.writes.fetch_add(1, Ordering::SeqCst);
        self.inner.set_noninteractive(account, value)?;
        if self.fail_after.swap(false, Ordering::SeqCst) {
            return Err(AppError::Other("uncertain write".into()));
        }
        Ok(())
    }
}
#[test]
fn a_write_that_succeeds_then_reports_failure_restores_the_same_cursor_without_prompting_or_reencrypting(
) {
    let (device, owner) = fixture();
    let protected = NoPrompt {
        inner: &device.keychain,
        fail_after: AtomicBool::new(true),
        writes: AtomicUsize::new(0),
    };
    let mut env = device.env();
    let life = env.runtime.lifecycle.lock().unwrap();
    let a = Zeroizing::new(b"source A".to_vec());
    let first = source_archive::create(&env, &life, &owner, 0, &a).unwrap();
    env.keychain = &protected;
    assert!(Cursor::initialize(&env, &life, &owner, &first).is_err());
    let restored = Cursor::load(&env, &life, &owner).unwrap().unwrap();
    assert_eq!(restored.bytes.as_slice(), a.as_slice());
    let retry = Cursor::initialize(&env, &life, &owner, &first).unwrap();
    assert!(retry.cursor == restored.cursor);
    assert_eq!(protected.writes.load(Ordering::SeqCst), 1);
    let b = Zeroizing::new(b"source B".to_vec());
    let second = source_archive::next(&env, &life, &owner, 1, first.receipt(), &b).unwrap();
    protected.fail_after.store(true, Ordering::SeqCst);
    assert!(restored
        .cursor
        .advance(&env, &life, &owner, &second)
        .is_err());
    let saved = Cursor::load(&env, &life, &owner).unwrap().unwrap();
    assert_eq!(saved.cursor.revision, 2);
    assert_eq!(saved.bytes.as_slice(), b.as_slice());
    assert!(
        restored
            .cursor
            .advance(&env, &life, &owner, &second)
            .unwrap()
            .cursor
            == saved.cursor
    );
    assert_eq!(protected.writes.load(Ordering::SeqCst), 2);
}
