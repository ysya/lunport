use super::*;
use crate::sync::{
    central::{
        migration::legacy_checkpoint,
        migration_freeze::{Phase, ProofStep},
        migration_history,
    },
    relay::PullResponse,
    testkit::TestDevice,
};
use std::fs;
fn fixture() -> (TestDevice, Workspace, DeviceKeys, Loaded) {
    let (device, package, _, owner, _) = super::super::source_package::tests::fixture();
    let (_, _, signer) = migration_history::tests::initial();
    let env = device.env();
    let life = env.runtime.lifecycle.lock().unwrap();
    let first = package.archive(&env, &life, &owner, 0).unwrap();
    let initial = Cursor::initialize(&env, &life, &owner, &first).unwrap();
    let begun = Journal::begin(&initial.cursor, &package, &signer)
        .unwrap()
        .store(&env, &life, &owner, &signer, &initial.cursor, 0)
        .unwrap();
    assert_eq!(begun.cursor.revision(), 2);
    drop(life);
    (device, owner, signer, begun)
}
fn progress(loaded: &Loaded) -> Progress {
    let parent = loaded
        .package
        .state
        .account
        .as_ref()
        .unwrap()
        .chain_id
        .clone();
    Progress {
        proof: vec![ProofStep {
            digest: loaded.intent().digest().unwrap(),
            intent: loaded.intent().clone(),
        }],
        sources: vec![legacy_checkpoint(&parent, 0, &[]).unwrap()],
        phase: Phase::Frozen,
        next: vec![],
    }
}
#[test]
fn freeze_intent_and_partial_fetch_survive_real_encrypted_cursor_roundtrips() {
    let (device, owner, signer, begun) = fixture();
    let env = device.env();
    let life = env.runtime.lifecycle.lock().unwrap();
    begun.require_unchanged(&env).unwrap();
    let intent = begun.intent().clone();
    drop(begun);
    let begun = Journal::load(&env, &life, &owner, &signer)
        .unwrap()
        .unwrap();
    assert!(begun.intent() == &intent);
    assert!(begun.fetching().is_none());
    let progress = progress(&begun);
    let frozen = begun
        .with_progress(&owner, &progress)
        .unwrap()
        .store(&env, &life, &owner, &signer, &begun.cursor, 0)
        .unwrap();
    let parent = frozen
        .package
        .state
        .account
        .as_ref()
        .unwrap()
        .chain_id
        .clone();
    assert_eq!(
        frozen
            .fetching()
            .unwrap()
            .next_source(&frozen.package.sources, &frozen.package.state)
            .unwrap(),
        Some(parent.clone())
    );
    let snapshot = frozen
        .package
        .sources
        .admit_frozen(
            &owner,
            frozen.intent().body.migration_id.as_str(),
            &progress,
            None,
            &parent,
            PullResponse {
                records: vec![],
                latest_seq: 0,
            },
        )
        .unwrap();
    let fetched = frozen
        .with_snapshot(&owner, snapshot)
        .unwrap()
        .store(&env, &life, &owner, &signer, &frozen.cursor, 0)
        .unwrap();
    assert_eq!(fetched.cursor.revision(), 4);
    fetched.require_unchanged(&env).unwrap();
    drop(fetched);
    let fetched = Journal::load(&env, &life, &owner, &signer)
        .unwrap()
        .unwrap();
    let (complete, ancestors, cursor, outputs) = fetched.into_complete().unwrap();
    assert_eq!(ancestors.len(), cursor.revision() as usize);
    complete
        .files
        .require_unchanged_after_archive(&env, None, &outputs)
        .unwrap();
    let (_, keys, _) = migration_history::tests::initial();
    complete
        .structured_history(&keys, &std::collections::BTreeMap::new())
        .unwrap();
    assert!(
        !complete
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
fn stale_progress_missing_ancestors_and_changed_sources_preserve_the_cursor_and_originals() {
    let (device, owner, signer, begun) = fixture();
    let env = device.env();
    let life = env.runtime.lifecycle.lock().unwrap();
    let progress = progress(&begun);
    let next = begun.with_progress(&owner, &progress).unwrap();
    let stale = begun.with_progress(&owner, &progress).unwrap();
    let saved = next
        .store(&env, &life, &owner, &signer, &begun.cursor, 0)
        .unwrap();
    let retry = stale
        .store(&env, &life, &owner, &signer, &begun.cursor, 0)
        .unwrap();
    assert!(retry.cursor == saved.cursor);
    let role = owner
        .control
        .profile
        .profile()
        .unwrap()
        .slot("source-migration-cursor");
    let before = device.keychain.entry(&role).unwrap();
    let mut dropping = saved.successor(&owner).unwrap();
    dropping.fetching = None;
    assert!(dropping
        .store(&env, &life, &owner, &signer, &saved.cursor, 0)
        .is_err());
    let root = env.state_path.parent().unwrap();
    fs::write(root.join("sync-state-new-B"), b"UNIQUE_B").unwrap();
    let next = saved.with_progress(&owner, &progress).unwrap();
    assert!(next
        .store(&env, &life, &owner, &signer, &saved.cursor, 0)
        .is_err());
    assert_eq!(device.keychain.entry(&role).unwrap(), before);
    assert_eq!(
        fs::read(root.join("sync-state-new-B")).unwrap(),
        b"UNIQUE_B"
    );
    fs::remove_file(root.join("sync-state-new-B")).unwrap();
    let profile = owner.control.profile.profile().unwrap();
    let original = &saved.journal.source;
    let archived = source_archive::resume(
        &env,
        &life,
        &owner,
        original,
        &source_archive::restore(&env, &profile, original).unwrap(),
    )
    .unwrap();
    let first_path = archived
        .outputs(
            &env,
            &profile,
            &source_archive::restore(&env, &profile, original).unwrap(),
        )
        .unwrap()
        .files()
        .find(|(p, _)| p.extension().is_some_and(|s| s == "lpsource"))
        .unwrap()
        .0
        .to_path_buf();
    fs::remove_file(root.join(first_path.strip_prefix("data").unwrap())).unwrap();
    assert!(Journal::load(&env, &life, &owner, &signer).is_err());
    assert_eq!(device.keychain.entry(&role).unwrap(), before);
}
#[test]
fn corrupt_or_crossed_journal_fields_do_not_get_repaired() {
    let (device, owner, signer, begun) = fixture();
    let env = device.env();
    let life = env.runtime.lifecycle.lock().unwrap();
    let encoded = begun.journal.encode().unwrap();
    let original: serde_json::Value = serde_json::from_slice(&encoded[8..]).unwrap();
    for case in [
        "version", "revision", "source", "ancestry", "book", "intent", "unknown",
    ] {
        let mut value = original.clone();
        match case {
            "version" => value["version"] = 99.into(),
            "revision" => value["revision"] = 99.into(),
            "source" => value["source"]["ciphertext_hash"] = "0".repeat(64).into(),
            "ancestry" => value["ancestors"] = serde_json::json!([]),
            "book" => value["book"] = "{}".into(),
            "intent" => value["intent"]["body"]["preview_digest"] = "0".repeat(64).into(),
            _ => value["unknown"] = true.into(),
        }
        let mut bytes = MAGIC.to_vec();
        bytes.extend(serde_json::to_vec(&value).unwrap());
        if let Ok(journal) = Journal::decode(&bytes) {
            assert!(
                journal.before(&begun.cursor, &owner).is_err()
                    || journal
                        .inputs(
                            &env,
                            &owner,
                            &signer,
                            Cursor::load(&env, &life, &owner).unwrap().unwrap().outputs
                        )
                        .is_err(),
                "{case}"
            );
        }
    }
    let mut other = owner.clone();
    other.identity_slot = Some("a".repeat(32));
    assert!(Journal::load(&env, &life, &other, &signer).is_err());
    assert!(Journal::decode(&vec![0; CAP + 1]).is_err());
}
fn archive_images(env: &SyncEnv) -> std::collections::BTreeMap<std::path::PathBuf, Vec<u8>> {
    fs::read_dir(
        env.state_path
            .parent()
            .unwrap()
            .join("central-source-archives"),
    )
    .unwrap()
    .map(|e| {
        let path = e.unwrap().path();
        let bytes = fs::read(&path).unwrap();
        (path, bytes)
    })
    .collect()
}
#[test]
fn failed_cursor_write_resumes_only_the_exact_orphan_without_new_ciphertext() {
    let (device, owner, signer, begun) = fixture();
    let env = device.env();
    let life = env.runtime.lifecycle.lock().unwrap();
    let progress = progress(&begun);
    let role = owner
        .control
        .profile
        .profile()
        .unwrap()
        .slot("source-migration-cursor");
    let before = device.keychain.entry(&role).unwrap();
    device.keychain.fail_writes_to(&role, true);
    assert!(begun
        .with_progress(&owner, &progress)
        .unwrap()
        .store(&env, &life, &owner, &signer, &begun.cursor, 0)
        .is_err());
    let orphaned = archive_images(&env);
    let loaded = Journal::load(&env, &life, &owner, &signer)
        .unwrap()
        .unwrap();
    assert!(loaded.cursor == begun.cursor);
    // A different step cannot adopt or erase the retained orphan.
    assert!(loaded
        .successor(&owner)
        .unwrap()
        .store(&env, &life, &owner, &signer, &loaded.cursor, 0)
        .is_err());
    assert_eq!(archive_images(&env), orphaned);
    assert_eq!(device.keychain.entry(&role).unwrap(), before);
    device.keychain.fail_writes_to(&role, false);
    let resumed = loaded
        .with_progress(&owner, &progress)
        .unwrap()
        .store(&env, &life, &owner, &signer, &loaded.cursor, 0)
        .unwrap();
    assert_eq!(resumed.cursor.revision(), 3);
    assert_eq!(archive_images(&env), orphaned);
    resumed.require_unchanged(&env).unwrap();
}
#[test]
fn a_successful_cursor_write_with_a_lost_reply_accepts_its_exact_saved_snapshot() {
    use crate::sync::{env::Keychain, testkit::MemKeychain};
    use std::sync::atomic::{AtomicBool, Ordering};
    struct Lost<'a> {
        inner: &'a MemKeychain,
        once: AtomicBool,
    }
    impl Keychain for Lost<'_> {
        fn get(&self, _: &str) -> Result<Option<String>, AppError> {
            panic!("must not prompt")
        }
        fn get_noninteractive(&self, role: &str) -> Result<Option<String>, AppError> {
            self.inner.get(role)
        }
        fn set(&self, _: &str, _: &str) -> Result<(), AppError> {
            panic!("must not prompt")
        }
        fn set_noninteractive(&self, role: &str, value: &str) -> Result<(), AppError> {
            self.inner.set(role, value)?;
            if self.once.swap(false, Ordering::SeqCst) {
                return Err(invalid());
            }
            Ok(())
        }
        fn delete(&self, _: &str) -> Result<(), AppError> {
            panic!("must not erase")
        }
    }
    let (device, owner, signer, begun) = fixture();
    let lost = Lost {
        inner: &device.keychain,
        once: AtomicBool::new(true),
    };
    let mut env = device.env();
    env.keychain = &lost;
    let life = env.runtime.lifecycle.lock().unwrap();
    let progress = progress(&begun);
    assert!(begun
        .with_progress(&owner, &progress)
        .unwrap()
        .store(&env, &life, &owner, &signer, &begun.cursor, 0)
        .is_err());
    let before = archive_images(&env);
    let retry = begun
        .with_progress(&owner, &progress)
        .unwrap()
        .store(&env, &life, &owner, &signer, &begun.cursor, 0)
        .unwrap();
    assert_eq!(retry.cursor.revision(), 3);
    assert_eq!(archive_images(&env), before);
}
#[test]
fn a_new_local_source_cannot_be_hidden_by_an_authenticated_pending_blob() {
    let (device, owner, signer, begun) = fixture();
    let env = device.env();
    let life = env.runtime.lifecycle.lock().unwrap();
    let progress = progress(&begun);
    let role = owner
        .control
        .profile
        .profile()
        .unwrap()
        .slot("source-migration-cursor");
    let before = device.keychain.entry(&role).unwrap();
    device.keychain.fail_writes_to(&role, true);
    assert!(begun
        .with_progress(&owner, &progress)
        .unwrap()
        .store(&env, &life, &owner, &signer, &begun.cursor, 0)
        .is_err());
    let orphaned = archive_images(&env);
    fs::write(
        env.state_path.parent().unwrap().join("sync-state-new-B"),
        b"UNIQUE_B",
    )
    .unwrap();
    device.keychain.fail_writes_to(&role, false);
    assert!(begun
        .with_progress(&owner, &progress)
        .unwrap()
        .store(&env, &life, &owner, &signer, &begun.cursor, 0)
        .is_err());
    assert_eq!(device.keychain.entry(&role).unwrap(), before);
    assert_eq!(archive_images(&env), orphaned);
}
#[test]
fn parent_discovery_remains_pending_until_its_exact_extended_freeze_is_saved() {
    use crate::sync::{
        crypto::ChainKeys,
        record::{Record, RecordKind, SpaceKeyPayload, SpacePayload},
        state_v2::SealedRecord,
    };
    let (device, owner, signer, begun) = fixture();
    let env = device.env();
    let life = env.runtime.lifecycle.lock().unwrap();
    let encoded: serde_json::Value =
        serde_json::from_slice(&begun.package.sources.encode_local().unwrap()).unwrap();
    let parent = ChainKeys::from_parts(
        encoded["parent"].as_str().unwrap(),
        encoded["keys"][0]["auth_token"].as_str().unwrap(),
        encoded["keys"][0]["encryption_key"].as_str().unwrap(),
    )
    .unwrap();
    let child = ChainKeys::generate().unwrap();
    let mut rows = vec![];
    for (kind, payload) in [
        (
            RecordKind::Space,
            serde_json::to_value(SpacePayload {
                schema: 1,
                name: "Discovered".into(),
                slug: "discovered".into(),
                created_at_ms: 1,
                previous_id: None,
            })
            .unwrap(),
        ),
        (
            RecordKind::SpaceKey,
            serde_json::to_value(SpaceKeyPayload::from_keys(&child)).unwrap(),
        ),
    ] {
        rows.push(
            SealedRecord::seal(
                &parent,
                &Record {
                    kind,
                    id: child.chain_id.clone(),
                    version: 1,
                    updated_at_ms: 1,
                    device_id: "d".repeat(32),
                    deleted: false,
                    payload,
                },
                rows.len() as u64 + 1,
            )
            .unwrap()
            .envelope,
        );
    }
    let response = PullResponse {
        records: rows,
        latest_seq: 2,
    };
    let mut progress = progress(&begun);
    progress.sources = vec![legacy_checkpoint(&parent.chain_id, 2, &response.records).unwrap()];
    let frozen = begun
        .with_progress(&owner, &progress)
        .unwrap()
        .store(&env, &life, &owner, &signer, &begun.cursor, 0)
        .unwrap();
    let snapshot = frozen
        .package
        .sources
        .admit_frozen(
            &owner,
            frozen.intent().body.migration_id.as_str(),
            &progress,
            None,
            &parent.chain_id,
            response.clone(),
        )
        .unwrap();
    let expanded = Sources::decode_local(
        &frozen.package.sources.encode_local().unwrap(),
        &frozen.package.state,
    )
    .unwrap()
    .with_parent_discovery(&owner, &snapshot)
    .unwrap();
    let fetched = frozen
        .with_snapshot(&owner, snapshot)
        .unwrap()
        .store(&env, &life, &owner, &signer, &frozen.cursor, 0)
        .unwrap();
    let pending = fetched
        .with_discovery(&owner, &signer, expanded)
        .unwrap()
        .store(&env, &life, &owner, &signer, &fetched.cursor, 0)
        .unwrap();
    assert_eq!(pending.package.sources.chains().len(), 1);
    assert_eq!(pending.intent().body.revision, "2");
    drop(pending);
    let pending = Journal::load(&env, &life, &owner, &signer)
        .unwrap()
        .unwrap();
    assert_eq!(pending.package.sources.chains().len(), 1);
    let mut extended = progress.clone();
    extended.proof.push(ProofStep {
        digest: pending.intent().digest().unwrap(),
        intent: pending.intent().clone(),
    });
    extended.phase = Phase::Freezing;
    extended.next = vec![child.chain_id.clone()];
    let expanded = pending
        .with_progress(&owner, &extended)
        .unwrap()
        .store(&env, &life, &owner, &signer, &pending.cursor, 0)
        .unwrap();
    assert_eq!(expanded.package.sources.chains().len(), 2);
    assert!(expanded.with_progress(&owner, &progress).is_err());
    extended
        .sources
        .push(legacy_checkpoint(&child.chain_id, 0, &[]).unwrap());
    extended.sources.sort_by(|a, b| a.chain_id.cmp(&b.chain_id));
    extended.phase = Phase::Frozen;
    extended.next.clear();
    let frozen = expanded
        .with_progress(&owner, &extended)
        .unwrap()
        .store(&env, &life, &owner, &signer, &expanded.cursor, 0)
        .unwrap();
    let snapshot = frozen
        .package
        .sources
        .admit_frozen(
            &owner,
            frozen.intent().body.migration_id.as_str(),
            &extended,
            None,
            &child.chain_id,
            PullResponse {
                records: vec![],
                latest_seq: 0,
            },
        )
        .unwrap();
    let fetched = frozen
        .with_snapshot(&owner, snapshot)
        .unwrap()
        .store(&env, &life, &owner, &signer, &frozen.cursor, 0)
        .unwrap();
    let (complete, _, _, _) = fetched.into_complete().unwrap();
    assert!(complete.state.spaces.is_empty());
    assert_eq!(complete.sources.chains().len(), 2);
}
