use super::*;
use crate::sync::{
    env::Keychain,
    testkit::{MemKeychain, TestDevice},
};
use std::{
    fs,
    sync::atomic::{AtomicBool, Ordering},
};
fn fixture() -> (TestDevice, VaultKeys) {
    let (device, keys) = super::super::capture_dispatch::ready_for_test(false);
    source_complete::ensure(&device.env(), &keys)
        .unwrap()
        .unwrap();
    (device, keys)
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
        panic!("planning cannot delete credentials")
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
fn plan_reentry_retains_the_exact_randomized_plan_and_all_source_ancestry_without_consent_or_cutover(
) {
    let (d, keys) = fixture();
    let env = d.env();
    let before = record_runtime::snapshot(&env).unwrap();
    let planned = ensure(&env, &keys, &BTreeMap::new()).unwrap();
    let bytes = planned
        .plan
        .encode_with_source(&planned.source_cursor)
        .unwrap();
    let receipt = planned.cursor.receipt().clone();
    let exact = tree(&env);
    assert_eq!(
        planned.plan.manifest.body.inventory_digest,
        planned.source_cursor.receipt().ciphertext_hash
    );
    assert_eq!(planned.ancestors.len() as u64, planned.cursor.revision());
    drop(planned);
    let restored = ensure(&env, &keys, &BTreeMap::new()).unwrap();
    assert_eq!(
        restored
            .plan
            .encode_with_source(&restored.source_cursor)
            .unwrap()
            .as_slice(),
        bytes.as_slice()
    );
    assert_eq!(restored.cursor.receipt(), &receipt);
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
    assert!(restored
        .package
        .state
        .local
        .central
        .as_ref()
        .unwrap()
        .control
        .library
        .is_none());
}
#[test]
fn cold_reentry_never_regenerates_a_plan_after_cursor_write_failure() {
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
        let planned = ensure(&env, &keys, &BTreeMap::new()).unwrap();
        assert_eq!(tree(&env), exact);
        let bytes = planned
            .plan
            .encode_with_source(&planned.source_cursor)
            .unwrap();
        drop(planned);
        let again = ensure(&env, &keys, &BTreeMap::new()).unwrap();
        assert_eq!(
            again
                .plan
                .encode_with_source(&again.source_cursor)
                .unwrap()
                .as_slice(),
            bytes.as_slice()
        );
        assert_eq!(tree(&env), exact);
    }
}
#[test]
fn a_signed_but_different_history_or_unknown_or_duplicate_plan_candidate_is_never_admitted() {
    use super::super::payload::{Collection, Data};
    for case in ["different_history", "unknown", "duplicate", "wrong_cursor"] {
        let (d, keys) = fixture();
        let env = d.env();
        let source = source_complete::ensure(&env, &keys).unwrap().unwrap();
        let owner = source.package.state.local.central.as_ref().unwrap();
        let session = controller::context(&env).unwrap();
        let signer = &session.identity.as_ref().unwrap().keys;
        let context = source
            .package
            .migration_context(source.cursor.receipt())
            .unwrap();
        let mut history = source
            .package
            .structured_history(&keys, &BTreeMap::new())
            .unwrap()
            .into_rows();
        if case == "different_history" {
            let Data::Catalog(catalog) = &mut history[0].1 else {
                panic!("expected catalog")
            };
            catalog.collections.push(Collection {
                id: "a".repeat(64),
                name: "wrong plan collection".into(),
            });
        }
        let plan = migration_history::prepare(owner, &keys, signer, context, &history).unwrap();
        let original = plan.encode_with_source(&source.cursor).unwrap();
        let bytes = if case == "unknown" {
            zeroize::Zeroizing::new(b"UNKNOWN_PRIVATE_PLAN".to_vec())
        } else if case == "wrong_cursor" {
            let mut value: serde_json::Value = serde_json::from_slice(&original).unwrap();
            value["source_cursor"]["revision"] = 0.into();
            zeroize::Zeroizing::new(serde_json::to_vec(&value).unwrap())
        } else {
            original
        };
        {
            let life = env.runtime.lifecycle.lock().unwrap();
            source_archive::next(
                &env,
                &life,
                owner,
                source.cursor.receipt().next_ordinal().unwrap(),
                source.cursor.receipt(),
                &bytes,
            )
            .unwrap();
            if case == "duplicate" {
                source_archive::next(
                    &env,
                    &life,
                    owner,
                    source.cursor.receipt().next_ordinal().unwrap(),
                    source.cursor.receipt(),
                    &bytes,
                )
                .unwrap();
            }
        }
        let exact = tree(&env);
        assert!(ensure(&env, &keys, &BTreeMap::new()).is_err(), "{case}");
        assert_eq!(tree(&env), exact);
    }
}
#[test]
fn a_new_source_file_or_missing_complete_source_prevents_plan_reentry_without_repair() {
    for missing in [false, true] {
        let (d, keys) = fixture();
        let env = d.env();
        let planned = ensure(&env, &keys, &BTreeMap::new()).unwrap();
        if missing {
            let hash = &planned.source_cursor.receipt().ciphertext_hash;
            let all = tree(&env);
            let name = all
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
        assert!(ensure(&env, &keys, &BTreeMap::new()).is_err());
        assert_eq!(tree(&env), exact);
    }
}
