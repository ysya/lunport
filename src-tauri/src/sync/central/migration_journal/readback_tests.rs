use super::{tests::fixture, *};
use crate::sync::central::{migration_progress::Progress, migration_verify::Page};
pub(super) fn retired(plan: &Plan) -> Known {
    serde_json::from_value::<Progress>(serde_json::json!({
        "manifest":plan.manifest,"manifest_digest":plan.manifest.digest().unwrap(),"phase":"retired",
        "staged":plan.rows.len().to_string(),"history_hash":plan.manifest.body.target_history_hash,
        "retired":plan.manifest.body.sources.len().to_string()
    })).unwrap().verify(plan, None).unwrap()
}
pub(super) fn page(plan: &Plan, start: usize, end: usize) -> Page {
    serde_json::from_value(serde_json::json!({
        "records":&plan.rows[start..end],"sequence":plan.rows.len().to_string(),
        "history_hash":plan.manifest.body.target_history_hash,"epoch":1,"phase":"ready",
        "membership_head":plan.before().control.highwater.as_ref().unwrap().head,
    }))
    .unwrap()
}
#[test]
fn actual_readback_prefix_survives_protected_journal_restart_and_only_full_tail_finishes() {
    let (device, owner, keys, signer, loaded) = fixture();
    let env = device.env();
    let life = env.runtime.lifecycle.lock().unwrap();
    assert!(loaded.verifier(&keys).is_err());
    let loaded = loaded
        .with_progress(retired(&loaded.plan), &owner)
        .unwrap()
        .unwrap()
        .store(&env, &life, &owner, &keys, &signer, &loaded.cursor, 0)
        .unwrap();
    let mut verifier = loaded.verifier(&keys).unwrap();
    verifier
        .admit(&loaded.plan, &keys, page(&loaded.plan, 0, 2))
        .unwrap();
    let journal = loaded.with_readback(&verifier, &owner).unwrap().unwrap();
    let saved = journal
        .store(&env, &life, &owner, &keys, &signer, &loaded.cursor, 0)
        .unwrap();
    let rows = saved.plan.rows.clone();
    drop((loaded, saved, verifier));
    let restored = Journal::load(&env, &life, &owner, &keys, &signer)
        .unwrap()
        .unwrap();
    assert!(restored.plan.rows == rows);
    let mut verifier = restored.verifier(&keys).unwrap();
    assert_eq!(verifier.sequence(), 2);
    assert!(restored.with_readback(&verifier, &owner).unwrap().is_none());
    assert!(restored
        .verifier(&keys)
        .unwrap()
        .finish(&restored.plan, &keys)
        .is_err());
    verifier
        .admit(
            &restored.plan,
            &keys,
            page(&restored.plan, 2, restored.plan.rows.len()),
        )
        .unwrap();
    let finished = restored
        .with_readback(&verifier, &owner)
        .unwrap()
        .unwrap()
        .store(&env, &life, &owner, &keys, &signer, &restored.cursor, 0)
        .unwrap();
    finished.require_unchanged(&env).unwrap();
    let committed = finished
        .verifier(&keys)
        .unwrap()
        .finish(&finished.plan, &keys)
        .unwrap();
    assert!(!committed.workspace().control.cutover);
    assert!(
        !finished
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
fn a_saved_readback_floor_cannot_be_cleared_decreased_forged_or_moved_before_retirement() {
    let (device, owner, keys, signer, loaded) = fixture();
    let env = device.env();
    let life = env.runtime.lifecycle.lock().unwrap();
    let loaded = loaded
        .with_progress(retired(&loaded.plan), &owner)
        .unwrap()
        .unwrap()
        .store(&env, &life, &owner, &keys, &signer, &loaded.cursor, 0)
        .unwrap();
    let mut verifier = loaded.verifier(&keys).unwrap();
    verifier
        .admit(&loaded.plan, &keys, page(&loaded.plan, 0, 2))
        .unwrap();
    let saved = loaded
        .with_readback(&verifier, &owner)
        .unwrap()
        .unwrap()
        .store(&env, &life, &owner, &keys, &signer, &loaded.cursor, 0)
        .unwrap();
    let role = owner
        .control
        .profile
        .profile()
        .unwrap()
        .slot("source-migration-cursor");
    let protected = device.keychain.entry(&role).unwrap();
    let zero = Verifier::new(&saved.plan, saved.journal.progress.as_ref().unwrap()).unwrap();
    assert!(saved.with_readback(&zero, &owner).is_err());
    for case in ["clear", "decrease", "hash", "manifest", "nonretired"] {
        let mut journal = saved.successor(&owner).unwrap();
        match case {
            "clear" => journal.verified = None,
            "nonretired" => {
                journal.progress = Some(super::tests::progress(
                    &saved.plan,
                    saved.plan.rows.len() as u64,
                ))
            }
            _ => {
                let mut value = serde_json::to_value(journal.verified.as_ref().unwrap()).unwrap();
                match case {
                    "decrease" => {
                        value["sequence"] = 1.into();
                        value["history_hash"] = saved.plan.rows[0].history_hash.clone().into();
                    }
                    "hash" => value["history_hash"] = "0".repeat(64).into(),
                    _ => value["manifest"] = "0".repeat(64).into(),
                }
                journal.verified = Some(serde_json::from_value(value).unwrap());
            }
        }
        assert!(
            journal
                .store(&env, &life, &owner, &keys, &signer, &saved.cursor, 0)
                .is_err(),
            "{case}"
        );
        assert_eq!(device.keychain.entry(&role).unwrap(), protected, "{case}");
    }
}

#[test]
fn uncertain_protected_readback_write_resumes_the_same_ciphertext_once_without_a_prompt() {
    use super::tests::Uncertain;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering::SeqCst};
    let (device, owner, keys, signer, loaded) = fixture();
    let env = device.env();
    let life = env.runtime.lifecycle.lock().unwrap();
    let loaded = loaded
        .with_progress(retired(&loaded.plan), &owner)
        .unwrap()
        .unwrap()
        .store(&env, &life, &owner, &keys, &signer, &loaded.cursor, 0)
        .unwrap();
    let mut verifier = loaded.verifier(&keys).unwrap();
    verifier
        .admit(&loaded.plan, &keys, page(&loaded.plan, 0, 2))
        .unwrap();
    let protected = Uncertain {
        inner: &device.keychain,
        after: AtomicBool::new(true),
        writes: AtomicUsize::new(0),
    };
    let mut safe = device.env();
    safe.keychain = &protected;
    let root = env
        .state_path
        .parent()
        .unwrap()
        .join("central-source-archives");
    let count = std::fs::read_dir(&root).unwrap().count();
    let next = loaded.with_readback(&verifier, &owner).unwrap().unwrap();
    let encoded = next.encode().unwrap();
    assert!(next
        .store(&safe, &life, &owner, &keys, &signer, &loaded.cursor, 0)
        .is_err());
    let resumed = Journal::decode(&encoded)
        .unwrap()
        .store(&safe, &life, &owner, &keys, &signer, &loaded.cursor, 0)
        .unwrap();
    assert_eq!(resumed.verifier(&keys).unwrap().sequence(), 2);
    assert_eq!(protected.writes.load(SeqCst), 1);
    assert_eq!(std::fs::read_dir(&root).unwrap().count(), count + 1);
    resumed.require_unchanged(&safe).unwrap();
    assert!(resumed.plan.rows == loaded.plan.rows);
}
