use super::*;
use std::fs;
use crate::sync::{
    central::{
        migration::legacy_checkpoint,
        migration_freeze::{Phase as FreezePhase, Progress, ProofStep},
        migration_history,
        migration_progress::Progress as MigrationProgress,
    },
    env::Keychain,
    relay::PullResponse,
    testkit::TestDevice,
};
pub(super) fn fixture() -> (TestDevice, Workspace, VaultKeys, DeviceKeys, Loaded) {
    fixture_with(0)
}
pub(super) fn fixture_with(extra: usize) -> (TestDevice, Workspace, VaultKeys, DeviceKeys, Loaded) {
    fixture_sized(extra, None)
}
pub(super) fn fixture_capacity(
    total: usize,
) -> (TestDevice, Workspace, VaultKeys, DeviceKeys, Loaded) {
    fixture_sized(0, Some(total))
}
fn fixture_sized(
    extra: usize,
    total: Option<usize>,
) -> (TestDevice, Workspace, VaultKeys, DeviceKeys, Loaded) {
    let (device, package, keys, owner, _) = crate::sync::central::source_package::tests::fixture();
    let (_, _, signer) = migration_history::tests::initial();
    let env = device.env();
    let life = env.runtime.lifecycle.lock().unwrap();
    let first = package.archive(&env, &life, &owner, 0).unwrap();
    let cursor1 = Cursor::initialize(&env, &life, &owner, &first)
        .unwrap()
        .cursor;
    let operation = first.receipt().operation().to_string();
    let preview = first.receipt().ciphertext_hash.clone();
    let intent = package
        .sources
        .intent(&owner, &signer, &operation, &preview, None)
        .unwrap();
    let parent = package.state.account.as_ref().unwrap().chain_id.clone();
    let progress = Progress {
        proof: vec![ProofStep {
            digest: intent.digest().unwrap(),
            intent,
        }],
        sources: vec![legacy_checkpoint(&parent, 0, &[]).unwrap()],
        phase: FreezePhase::Frozen,
        next: vec![],
    };
    let snapshot = package
        .sources
        .admit_frozen(
            &owner,
            &operation,
            &progress,
            None,
            &parent,
            PullResponse {
                records: vec![],
                latest_seq: 0,
            },
        )
        .unwrap();
    let package = package
        .with_frozen(&operation, &progress, None, vec![snapshot])
        .unwrap();
    let second = source_archive::next(
        &env,
        &life,
        &owner,
        0,
        first.receipt(),
        &package.encode_local().unwrap(),
    )
    .unwrap();
    let cursor2 = cursor1
        .advance(&env, &life, &owner, &second)
        .unwrap()
        .cursor;
    let context = package.migration_context(second.receipt()).unwrap();
    let mut history = package
        .structured_history(&keys, &std::collections::BTreeMap::new())
        .unwrap()
        .into_rows();
    for index in 1..=total.map_or(extra, |total| total.checked_sub(history.len()).unwrap()) {
        history.push((super::super::payload::Identity {
            kind: "host".into(), id: format!("{:016x}", if total.is_some() {index % 1024 + 1} else {index}), scope: Some(crate::sync::records_v3::HostScope::Local),
        }, super::super::payload::Data::Host(serde_json::from_value(serde_json::json!({"schema":2,"alias":format!("capacity-{index}"),"hostname":"capacity.invalid","auth":"password"})).unwrap())));
    }
    let plan = migration_history::prepare(&owner, &keys, &signer, context, &history).unwrap();
    let third = source_archive::next(
        &env,
        &life,
        &owner,
        0,
        second.receipt(),
        &plan.encode_local().unwrap(),
    )
    .unwrap();
    let cursor3 = cursor2.advance(&env, &life, &owner, &third).unwrap().cursor;
    let journal = Journal::planned(
        &cursor3,
        second.receipt().clone(),
        vec![
            first.receipt().clone(),
            second.receipt().clone(),
            third.receipt().clone(),
        ],
        &owner,
    )
    .unwrap();
    let loaded = journal
        .store(&env, &life, &owner, &keys, &signer, &cursor3, 0)
        .unwrap();
    drop(life);
    (device, owner, keys, signer, loaded)
}
pub(super) fn progress(plan: &Plan, staged: u64) -> Known {
    let body = serde_json::json!({"manifest":plan.manifest,"manifest_digest":plan.manifest.digest().unwrap(),"phase":"staging","staged":staged.to_string(),"history_hash":if staged==0{"0".repeat(64)}else{plan.rows[staged as usize-1].history_hash.clone()},"retired":"0"});
    serde_json::from_value::<MigrationProgress>(body)
        .unwrap()
        .verify(plan, None)
        .unwrap()
}
#[test]
fn referenced_journal_restores_source_plan_and_saved_floor_without_reembedding_private_sources() {
    let (device, owner, keys, signer, loaded) = fixture();
    let env = device.env();
    let life = env.runtime.lifecycle.lock().unwrap();
    assert_eq!(loaded.cursor.revision(), 4);
    loaded.require_unchanged(&env).unwrap();
    let encoded = loaded.journal.encode().unwrap();
    assert!(encoded.len() < 16384);
    assert!(!String::from_utf8_lossy(&encoded).contains("PRIVATE KEY"));
    let manifest = loaded.plan.manifest.clone();
    let rows = loaded.plan.rows.clone();
    let source = loaded.journal.source.clone();
    let next = loaded
        .with_progress(progress(&loaded.plan, 2), &owner)
        .unwrap()
        .unwrap();
    let advanced = next
        .store(&env, &life, &owner, &keys, &signer, &loaded.cursor, 0)
        .unwrap();
    assert_eq!(advanced.cursor.revision(), 5);
    assert!(advanced.journal.source == source);
    assert!(advanced.plan.rows == rows);
    advanced.require_unchanged(&env).unwrap();
    drop((loaded, advanced));
    let restored = Journal::load(&env, &life, &owner, &keys, &signer)
        .unwrap()
        .unwrap();
    assert!(restored.plan.manifest == manifest);
    assert!(restored.plan.rows == rows);
    assert_eq!(restored.journal.progress.as_ref().unwrap().staged(), 2);
    assert!(restored
        .with_progress(progress(&restored.plan, 2), &owner)
        .unwrap()
        .is_none());
    assert!(restored
        .with_progress(progress(&restored.plan, 1), &owner)
        .is_err());
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
#[test]
fn stale_journal_writes_or_new_unique_source_data_do_not_replace_existing_progress() {
    let (device, owner, keys, signer, loaded) = fixture();
    let env = device.env();
    let life = env.runtime.lifecycle.lock().unwrap();
    let next = loaded
        .with_progress(progress(&loaded.plan, 2), &owner)
        .unwrap()
        .unwrap();
    let stale = loaded
        .with_progress(progress(&loaded.plan, 1), &owner)
        .unwrap()
        .unwrap();
    let advanced = next
        .store(&env, &life, &owner, &keys, &signer, &loaded.cursor, 0)
        .unwrap();
    assert!(stale
        .store(&env, &life, &owner, &keys, &signer, &loaded.cursor, 0)
        .is_err());
    let role = owner
        .control
        .profile
        .profile()
        .unwrap()
        .slot("source-migration-cursor");
    let before = device.keychain.entry(&role).unwrap();
    std::fs::write(
        env.state_path.parent().unwrap().join("sync-state.new-B"),
        b"unique source B",
    )
    .unwrap();
    assert!(advanced.require_unchanged(&env).is_err());
    let next = advanced
        .with_progress(progress(&advanced.plan, 3), &owner)
        .unwrap()
        .unwrap();
    assert!(next
        .store(&env, &life, &owner, &keys, &signer, &advanced.cursor, 0)
        .is_err());
    assert_eq!(device.keychain.entry(&role).unwrap(), before);
}
#[test]
fn missing_or_changed_referenced_ciphertext_blocks_restore_without_repair() {
    let (device, owner, keys, signer, loaded) = fixture();
    let env = device.env();
    let life = env.runtime.lifecycle.lock().unwrap();
    let role = owner
        .control
        .profile
        .profile()
        .unwrap()
        .slot("source-migration-cursor");
    let before = device.keychain.entry(&role).unwrap();
    let root = env
        .state_path
        .parent()
        .unwrap()
        .join("central-source-archives");
    let plan = std::fs::read_dir(root)
        .unwrap()
        .map(Result::unwrap)
        .map(|v| v.path())
        .find(|path| {
            path.extension().and_then(|v| v.to_str()) == Some("lpsource")
                && std::fs::read(path).is_ok_and(|bytes| {
                    super::super::crypto::hash(&bytes) == loaded.journal.plan.ciphertext_hash
                })
        })
        .unwrap();
    std::fs::remove_file(plan).unwrap();
    assert!(Journal::load(&env, &life, &owner, &keys, &signer).is_err());
    assert_eq!(device.keychain.entry(&role).unwrap(), before);
}
#[test]
fn journal_lineage_and_counter_tampering_never_form_a_valid_current_or_successor() {
    let (device, owner, keys, signer, loaded) = fixture();
    let env = device.env();
    let life = env.runtime.lifecycle.lock().unwrap();
    let bytes = loaded.journal.encode().unwrap();
    let original: serde_json::Value = serde_json::from_slice(&bytes[8..]).unwrap();
    for case in [
        "missing",
        "duplicate",
        "revision",
        "source",
        "unknown",
        "version",
    ] {
        let mut value = original.clone();
        match case {
            "missing" => {
                value["ancestors"].as_array_mut().unwrap().pop();
            }
            "duplicate" => value["ancestors"][1] = value["ancestors"][0].clone(),
            "revision" => value["revision"] = 999.into(),
            "source" => value["source"]["ciphertext_hash"] = "0".repeat(64).into(),
            "unknown" => value["other"] = true.into(),
            _ => value["version"] = 2.into(),
        }
        let mut encoded = MAGIC.to_vec();
        encoded.extend(serde_json::to_vec(&value).unwrap());
        match Journal::decode(&encoded) {
            Ok(journal) => assert!(journal.current(&loaded.cursor, &owner).is_err(), "{case}"),
            Err(_) => {}
        }
    }
    assert!(Journal::decode(&vec![b' '; CAP + 1]).is_err());
    assert!(Journal::load(
        &env,
        &life,
        &owner,
        &VaultKeys::generate().unwrap(),
        &signer
    )
    .is_err());
    let role = owner
        .control
        .profile
        .profile()
        .unwrap()
        .slot("source-migration-cursor");
    let previous = device.keychain.entry(&role).unwrap();
    let next = loaded
        .with_progress(progress(&loaded.plan, 2), &owner)
        .unwrap()
        .unwrap();
    let advanced = next
        .store(&env, &life, &owner, &keys, &signer, &loaded.cursor, 0)
        .unwrap();
    let protected = device.keychain.entry(&role).unwrap();
    let mut bad = advanced
        .with_progress(progress(&advanced.plan, 3), &owner)
        .unwrap()
        .unwrap();
    bad.progress = Some(progress(&advanced.plan, 1));
    assert!(bad
        .store(&env, &life, &owner, &keys, &signer, &advanced.cursor, 0)
        .is_err());
    assert_eq!(device.keychain.entry(&role).unwrap(), protected);
    assert_ne!(protected, previous);
}

pub(super) struct Uncertain<'a> {
    pub(super) inner: &'a crate::sync::testkit::MemKeychain,
    pub(super) after: std::sync::atomic::AtomicBool,
    pub(super) writes: std::sync::atomic::AtomicUsize,
}
impl Keychain for Uncertain<'_> {
    fn get(&self, _: &str) -> Result<Option<String>, AppError> {
        panic!("interactive read")
    }
    fn set(&self, _: &str, _: &str) -> Result<(), AppError> {
        panic!("interactive write")
    }
    fn delete(&self, _: &str) -> Result<(), AppError> {
        panic!("delete")
    }
    fn get_noninteractive(&self, role: &str) -> Result<Option<String>, AppError> {
        self.inner.get_noninteractive(role)
    }
    fn set_noninteractive(&self, role: &str, value: &str) -> Result<(), AppError> {
        use std::sync::atomic::Ordering::SeqCst;
        self.writes.fetch_add(1, SeqCst);
        self.inner.set_noninteractive(role, value)?;
        if self.after.swap(false, SeqCst) {
            return Err(AppError::Other("uncertain cursor write".into()));
        }
        Ok(())
    }
}
#[test]
fn a_committed_cursor_write_that_reports_failure_reuses_the_same_small_journal_and_ciphertext() {
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering::SeqCst};
    let (device, owner, keys, signer, loaded) = fixture();
    let protected = Uncertain {
        inner: &device.keychain,
        after: AtomicBool::new(true),
        writes: AtomicUsize::new(0),
    };
    let mut env = device.env();
    env.keychain = &protected;
    let life = env.runtime.lifecycle.lock().unwrap();
    let root = env
        .state_path
        .parent()
        .unwrap()
        .join("central-source-archives");
    let count = std::fs::read_dir(&root).unwrap().count();
    let next = loaded
        .with_progress(progress(&loaded.plan, 2), &owner)
        .unwrap()
        .unwrap();
    let encoded = next.encode().unwrap();
    assert!(next
        .store(&env, &life, &owner, &keys, &signer, &loaded.cursor, 0)
        .is_err());
    let retry = Journal::decode(&encoded)
        .unwrap()
        .store(&env, &life, &owner, &keys, &signer, &loaded.cursor, 0)
        .unwrap();
    assert_eq!(retry.journal.progress.as_ref().unwrap().staged(), 2);
    retry.require_unchanged(&env).unwrap();
    assert_eq!(std::fs::read_dir(root).unwrap().count(), count + 1);
    assert_eq!(protected.writes.load(SeqCst), 1);
    assert!(retry.plan.rows == loaded.plan.rows);
}

fn captured_outer(device: &TestDevice, template: &Package, keys: &VaultKeys) -> Package {
    use super::super::{
        inventory_keys::Capture, migration_files::Files, migration_materials::Materials,
        migration_sources::Sources,
    };
    let env = device.env();
    let state: crate::sync::records_v3::SyncStateV3 =
        serde_json::from_slice(&fs::read(&env.state_path).unwrap()).unwrap();
    let files = Files::capture(&env, None).unwrap();
    let observer = Capture::new(&device.keychain);
    Materials::from_files(&state, keys, &files, &observer, &BTreeMap::new()).unwrap();
    drop(source_archive::captured::read_all(&files.bytes, &observer).unwrap());
    let sources = Sources::decode_local(&template.sources.encode_local().unwrap(), &state).unwrap();
    let decryptors = observer.finish().unwrap();
    let roles: serde_json::Value =
        serde_json::from_slice(&decryptors.encode_local().unwrap()).unwrap();
    let package = Package::assemble(
        &state,
        env.state_path.file_name().unwrap().to_str().unwrap(),
        files,
        sources,
        decryptors,
    )
    .unwrap();
    for key in roles["keys"].as_array().unwrap() {
        let role = key["role"].as_str().unwrap();
        assert!(!role.contains(":device:"));
        device.keychain.delete(role).unwrap();
    }
    package
}
#[test]
fn captured_old_direct_frozen_plan_and_planned_journal_verify_without_original_identity_or_files() {
    let (device, owner, keys, signer, loaded) = fixture();
    let env = device.env();
    let advanced = {
        let life = env.runtime.lifecycle.lock().unwrap();
        loaded
            .with_progress(progress(&loaded.plan, 2), &owner)
            .unwrap()
            .unwrap()
            .store(&env, &life, &owner, &keys, &signer, &loaded.cursor, 0)
            .unwrap()
    };
    let package = captured_outer(&device, &advanced.package, &keys);
    let encoded = package.encode_local().unwrap();
    fs::remove_dir_all(
        env.state_path
            .parent()
            .unwrap()
            .join("central-source-archives"),
    )
    .unwrap();
    let restored = Package::decode_local(&encoded).unwrap();
    assert!(restored.materials(&keys, &BTreeMap::new()).is_ok());
    assert!(restored.structured_history(&keys, &BTreeMap::new()).is_ok());
    assert!(restored
        .materials(&VaultKeys::generate().unwrap(), &BTreeMap::new())
        .is_err());
    assert_eq!(
        restored.encode_local().unwrap().as_slice(),
        encoded.as_slice()
    );
    assert!(
        !restored
            .state
            .local
            .central
            .as_ref()
            .unwrap()
            .control
            .cutover
    );
}
#[test]
fn captured_plan_cannot_hide_additional_signed_payloads_or_roll_back_journal_progress() {
    for extra in [0, 1] {
        let (device, owner, keys, signer, loaded) = fixture_with(extra);
        let env = device.env();
        if extra == 0 {
            let life = env.runtime.lifecycle.lock().unwrap();
            let advanced = loaded
                .with_progress(progress(&loaded.plan, 2), &owner)
                .unwrap()
                .unwrap()
                .store(&env, &life, &owner, &keys, &signer, &loaded.cursor, 0)
                .unwrap();
            let mut lower = Journal::decode(&advanced.journal.encode().unwrap()).unwrap();
            lower.ancestors.push(advanced.cursor.receipt().clone());
            lower.revision += 1;
            lower.progress = Some(progress(&advanced.plan, 1));
            source_archive::next(
                &env,
                &life,
                &owner,
                0,
                advanced.cursor.receipt(),
                &lower.encode().unwrap(),
            )
            .unwrap();
        }
        let package = captured_outer(&device, &loaded.package, &keys);
        let original = package.encode_local().unwrap();
        assert!(package.materials(&keys, &BTreeMap::new()).is_err());
        assert!(package.structured_history(&keys, &BTreeMap::new()).is_err());
        assert_eq!(
            package.encode_local().unwrap().as_slice(),
            original.as_slice()
        );
        package.files.require_unchanged(&env, None).unwrap();
    }
}
#[test]
fn captured_modern_source_bound_plan_preserves_all_actual_capture_ancestors() {
    let (device, keys) = super::super::capture_dispatch::ready_for_test(false);
    let env = device.env();
    super::super::source_complete::ensure(&env, &keys)
        .unwrap()
        .unwrap();
    let planned = super::super::source_plan::ensure(&env, &keys, &BTreeMap::new()).unwrap();
    let package = captured_outer(&device, &planned.package, &keys);
    let original = package.encode_local().unwrap();
    assert!(package.materials(&keys, &BTreeMap::new()).is_ok());
    assert!(package.structured_history(&keys, &BTreeMap::new()).is_ok());
    assert_eq!(
        package.encode_local().unwrap().as_slice(),
        original.as_slice()
    );
}

#[test]
fn signed_captured_plan_survives_content_key_rotation_without_promoting_planned_rows_to_a_history_floor(
) {
    use super::super::credentials::DeviceIdentity;
    use zeroize::Zeroizing;
    let (device, owner, keys, signer, loaded) = fixture();
    let mut package = captured_outer(&device, &loaded.package, &keys);
    let profile = owner.control.profile.profile().unwrap();
    let role = profile
        .device_slot("device", owner.identity_slot.as_deref())
        .unwrap();
    device.keychain.set(&role,&Zeroizing::new(serde_json::json!({"version":1,"locator":profile.locator,"id":owner.control.device.id,"keys":&*signer.encode_secret(),"credential":"d".repeat(64)}).to_string())).unwrap();
    let identity = DeviceIdentity::load_selected(
        &device.keychain,
        &profile,
        owner.identity_slot.as_deref(),
        false,
    )
    .unwrap();
    let later = keys.next_epoch().unwrap();
    assert!(package
        .structured_history(&later, &BTreeMap::new())
        .is_err());
    package
        .capture_historical_snapshots(
            &identity,
            &|old| {
                DeviceIdentity::load_selected(
                    &device.keychain,
                    &old.control.profile.profile()?,
                    old.identity_slot.as_deref(),
                    false,
                )
            },
            &later,
            &BTreeMap::new(),
        )
        .unwrap();
    let bytes = package.encode_local().unwrap();
    device.keychain.delete(&role).unwrap();
    let restored = Package::decode_local(&bytes).unwrap();
    assert!(!restored
        .structured_history(&later, &BTreeMap::new())
        .unwrap()
        .into_rows()
        .is_empty());
    assert!(restored.historical_floors().unwrap().is_empty());
    assert!(
        !restored
            .state
            .local
            .central
            .as_ref()
            .unwrap()
            .control
            .cutover
    );
    assert_eq!(
        restored.encode_local().unwrap().as_slice(),
        bytes.as_slice()
    );
}
