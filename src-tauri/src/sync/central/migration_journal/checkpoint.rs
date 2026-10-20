//! Bound planned-progress archives while preserving the protected source/plan highwater.
//! Older immutable receipts remain readable; only verified progress metadata is checkpointed.
use super::*;
pub(super) const ARCHIVE_WINDOW: u64 = 8;
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(in crate::sync::central) struct Checkpoint {
    version: u32,
    progress: Option<Known>,
    verified: Option<Prefix>,
}
fn after(plan: &Plan, next: &Journal, old: &Journal) -> Result<(), AppError> {
    if let Some(progress) = &next.progress {
        progress.validate(plan)?;
    }
    if let Some(old) = &old.progress {
        next.progress
            .as_ref()
            .ok_or_else(invalid)?
            .require_after(plan, old)?;
    }
    if let Some(prefix) = &next.verified {
        if next
            .progress
            .as_ref()
            .is_none_or(|p| p.phase() != Phase::Retired)
        {
            return Err(invalid());
        }
        prefix.validate(plan)?;
    }
    if let Some(old) = &old.verified {
        next.verified
            .as_ref()
            .ok_or_else(invalid)?
            .require_after(plan, old)?;
    }
    Ok(())
}
pub(super) fn restore(cursor: &Cursor, plan: &Plan, journal: &mut Journal) -> Result<(), AppError> {
    let Some(saved) = cursor.progress_checkpoint() else {
        return Ok(());
    };
    if saved.version != 1 || cursor.revision() < ARCHIVE_WINDOW {
        return Err(invalid());
    }
    let mut next = Journal::decode(&journal.encode()?)?;
    next.progress = saved.progress.clone();
    next.verified = saved.verified.clone();
    after(plan, &next, journal)?;
    *journal = next;
    Ok(())
}
pub(super) fn store(
    mut next: Journal,
    env: &SyncEnv,
    life: &MutexGuard<'_, ()>,
    owner: &Workspace,
    keys: &VaultKeys,
    signer: &DeviceKeys,
    before: &Cursor,
    current: Restored,
) -> Result<Loaded, AppError> {
    if !current.cursor.same_archive(before) {
        return Err(crate::sync::runtime::superseded());
    }
    next.before(before, owner)?;
    let old = Journal::restored(env, owner, keys, signer, current)?;
    if next.source != old.journal.source
        || next.plan != old.journal.plan
        || next.ancestors[..next.ancestors.len() - 1] != old.journal.ancestors
        || next.ancestors.last() != Some(before.receipt())
    {
        return Err(invalid());
    }
    after(&old.plan, &next, &old.journal)?;
    old.require_unchanged(env)?;
    let saved = Checkpoint {
        version: 1,
        progress: next.progress.take(),
        verified: next.verified.take(),
    };
    if old.cursor.progress_checkpoint() == Some(&saved) {
        return Ok(old);
    }
    if old.cursor != *before {
        return Err(crate::sync::runtime::superseded());
    }
    // A single protected write binds metadata to the immutable source/plan cursor. No second
    // optional slot, new archive key or ciphertext is created for each HTTP response.
    let current = before.checkpoint(env, owner, saved)?;
    old.require_unchanged(env)?;
    if Cursor::load(env, life, owner)?.ok_or_else(invalid)?.cursor != current.cursor {
        return Err(crate::sync::runtime::superseded());
    }
    Journal::restored(env, owner, keys, signer, current)
}

#[cfg(all(test, any(unix, windows)))]
mod tests {
    use super::super::tests::{fixture_with, progress, Uncertain};
    use super::*;
    use crate::sync::env::Keychain;
    #[test]
    fn progress_beyond_archive_window_survives_restart_with_constant_ciphertext_count() {
        let (device, owner, keys, signer, mut loaded) = fixture_with(70);
        let env = device.env();
        let life = env.runtime.lifecycle.lock().unwrap();
        let root = env
            .state_path
            .parent()
            .unwrap()
            .join("central-source-archives");
        for staged in 0..=70 {
            let next = loaded
                .with_progress(progress(&loaded.plan, staged), &owner)
                .unwrap()
                .unwrap();
            loaded = next
                .store(&env, &life, &owner, &keys, &signer, &loaded.cursor, 0)
                .unwrap();
            if staged % 7 == 0 {
                loaded = Journal::load(&env, &life, &owner, &keys, &signer)
                    .unwrap()
                    .unwrap();
            }
        }
        assert_eq!(loaded.progress().unwrap().staged(), 70);
        assert_eq!(loaded.cursor.revision(), ARCHIVE_WINDOW);
        assert_eq!(
            std::fs::read_dir(&root).unwrap().count(),
            ARCHIVE_WINDOW as usize + 1
        );
        assert!(loaded
            .with_progress(progress(&loaded.plan, 69), &owner)
            .is_err());
        let role = owner
            .control
            .profile
            .profile()
            .unwrap()
            .slot("source-migration-cursor");
        let saved = device.keychain.entry(&role).unwrap();
        let mut broken: serde_json::Value = serde_json::from_str(&saved).unwrap();
        broken.as_object_mut().unwrap().remove("checkpoint");
        device
            .keychain
            .set_noninteractive(&role, &broken.to_string())
            .unwrap();
        assert!(Journal::load(&env, &life, &owner, &keys, &signer).is_err());
        device.keychain.set_noninteractive(&role, &saved).unwrap();
        let restored = Journal::load(&env, &life, &owner, &keys, &signer)
            .unwrap()
            .unwrap();
        assert_eq!(restored.progress().unwrap().staged(), 70);
        restored.require_unchanged(&env).unwrap();
    }
    #[test]
    fn uncertain_checkpoint_write_reuses_exact_progress_and_rejects_stale_successors() {
        use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering::SeqCst};
        let (device, owner, keys, signer, mut loaded) = fixture_with(40);
        let env = device.env();
        let life = env.runtime.lifecycle.lock().unwrap();
        for staged in 0..ARCHIVE_WINDOW - 4 {
            loaded = loaded
                .with_progress(progress(&loaded.plan, staged), &owner)
                .unwrap()
                .unwrap()
                .store(&env, &life, &owner, &keys, &signer, &loaded.cursor, 0)
                .unwrap();
        }
        assert_eq!(loaded.cursor.revision(), ARCHIVE_WINDOW);
        let uncertain = Uncertain {
            inner: &device.keychain,
            after: AtomicBool::new(true),
            writes: AtomicUsize::new(0),
        };
        let mut env = device.env();
        env.keychain = &uncertain;
        let next = loaded
            .with_progress(progress(&loaded.plan, 29), &owner)
            .unwrap()
            .unwrap();
        let encoded = next.encode().unwrap();
        assert!(next
            .store(&env, &life, &owner, &keys, &signer, &loaded.cursor, 0)
            .is_err());
        let resumed = Journal::decode(&encoded)
            .unwrap()
            .store(&env, &life, &owner, &keys, &signer, &loaded.cursor, 0)
            .unwrap();
        assert_eq!(resumed.progress().unwrap().staged(), 29);
        assert_eq!(uncertain.writes.load(SeqCst), 1);
        let stale = loaded
            .with_progress(progress(&loaded.plan, 28), &owner)
            .unwrap()
            .unwrap();
        assert!(stale
            .store(&env, &life, &owner, &keys, &signer, &loaded.cursor, 0)
            .is_err());
    }
}

#[cfg(all(test, any(unix, windows)))]
mod compatibility_tests {
    use super::super::{
        readback_tests::{page, retired},
        tests::{fixture_with, progress},
    };
    use super::*;
    #[test]
    fn an_exact_legacy_pending_archive_at_the_checkpoint_boundary_is_attached_before_compacting() {
        let (device, owner, keys, signer, mut loaded) = fixture_with(40);
        let env = device.env();
        let life = env.runtime.lifecycle.lock().unwrap();
        for staged in 0..ARCHIVE_WINDOW - 4 {
            loaded = loaded
                .with_progress(progress(&loaded.plan, staged), &owner)
                .unwrap()
                .unwrap()
                .store(&env, &life, &owner, &keys, &signer, &loaded.cursor, 0)
                .unwrap();
        }
        let next = loaded
            .with_progress(progress(&loaded.plan, 29), &owner)
            .unwrap()
            .unwrap();
        source_archive::next(
            &env,
            &life,
            &owner,
            loaded.cursor.receipt().next_ordinal().unwrap(),
            loaded.cursor.receipt(),
            &next.encode().unwrap(),
        )
        .unwrap();
        let resumed = loaded
            .recover_pending(&env, &life, &owner, &keys, &signer)
            .unwrap()
            .unwrap();
        assert_eq!(resumed.cursor.revision(), ARCHIVE_WINDOW + 1);
        assert_eq!(resumed.progress().unwrap().staged(), 29);
        let compact = resumed
            .with_progress(progress(&resumed.plan, 30), &owner)
            .unwrap()
            .unwrap()
            .store(&env, &life, &owner, &keys, &signer, &resumed.cursor, 0)
            .unwrap();
        assert_eq!(compact.cursor.revision(), resumed.cursor.revision());
        assert_eq!(compact.progress().unwrap().staged(), 30);
    }
    #[test]
    fn cached_verified_prefix_requires_the_actual_saved_prefix_and_both_vault_keys() {
        let (device, owner, keys, signer, loaded) = super::super::tests::fixture();
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
        let next = loaded.with_readback(&verifier, &owner).unwrap().unwrap();
        loaded.remember_verifier(&env, verifier).unwrap();
        assert_eq!(loaded.verifier_cached(&env, &keys).unwrap().sequence(), 0);
        let saved = next
            .store(&env, &life, &owner, &keys, &signer, &loaded.cursor, 0)
            .unwrap();
        let verifier = saved.verifier(&keys).unwrap();
        assert_eq!(verifier.sequence(), 2);
        saved.remember_verifier(&env, verifier).unwrap();
        assert!(saved
            .verifier_cached(&env, &VaultKeys::generate().unwrap())
            .is_err());
        assert_eq!(saved.verifier_cached(&env, &keys).unwrap().sequence(), 2);
    }
    #[test]
    #[ignore = "explicit synthetic maximum-history staging/readback benchmark"]
    fn native_capacity_16384_rows_keeps_constant_archive_count_and_resumes_cold() {
        let started = std::time::Instant::now();
        let (device, owner, keys, signer, mut loaded) =
            super::super::tests::fixture_capacity(16384);
        eprintln!("capacity: prepared 16384 rows in {:?}", started.elapsed());
        let env = device.env();
        let life = env.runtime.lifecycle.lock().unwrap();
        for staged in (0..=16384).step_by(32) {
            loaded = loaded
                .with_progress(progress(&loaded.plan, staged), &owner)
                .unwrap()
                .unwrap()
                .store(&env, &life, &owner, &keys, &signer, &loaded.cursor, 0)
                .unwrap();
            if staged % 2048 == 0 {
                eprintln!("capacity: staged {}, {:?}", staged, started.elapsed());
            }
            if staged == 8192 {
                env.runtime.core.lock().unwrap().migration_plan = None;
                loaded = Journal::load(&env, &life, &owner, &keys, &signer)
                    .unwrap()
                    .unwrap();
            }
        }
        eprintln!("capacity: staged 16384 rows in {:?}", started.elapsed());
        loaded = loaded
            .with_progress(retired(&loaded.plan), &owner)
            .unwrap()
            .unwrap()
            .store(&env, &life, &owner, &keys, &signer, &loaded.cursor, 0)
            .unwrap();
        let root = env
            .state_path
            .parent()
            .unwrap()
            .join("central-source-archives");
        let count = std::fs::read_dir(&root).unwrap().count();
        for after in (0..16384).step_by(32) {
            let mut verifier = loaded.verifier_cached(&env, &keys).unwrap();
            assert_eq!(verifier.sequence(), after as u64);
            verifier
                .admit(&loaded.plan, &keys, page(&loaded.plan, after, after + 32))
                .unwrap();
            let next = loaded.with_readback(&verifier, &owner).unwrap().unwrap();
            loaded.remember_verifier(&env, verifier).unwrap();
            loaded = next
                .store(&env, &life, &owner, &keys, &signer, &loaded.cursor, 0)
                .unwrap();
            if after % 2048 == 0 {
                eprintln!("capacity: verified {}, {:?}", after + 32, started.elapsed());
            }
            if after == 8192 {
                let mut core = env.runtime.core.lock().unwrap();
                core.migration_plan = None;
                core.migration_verifier = None;
                drop(core);
                loaded = Journal::load(&env, &life, &owner, &keys, &signer)
                    .unwrap()
                    .unwrap();
            }
        }
        loaded
            .verifier_cached(&env, &keys)
            .unwrap()
            .finish(&loaded.plan, &keys)
            .unwrap();
        assert_eq!(loaded.cursor.revision(), ARCHIVE_WINDOW);
        assert_eq!(std::fs::read_dir(&root).unwrap().count(), count);
        assert_eq!(count, ARCHIVE_WINDOW as usize + 1);
        loaded.require_unchanged(&env).unwrap();
        eprintln!(
            "capacity: 16384 rows staged and verified, {} archive files, {:?}",
            count,
            started.elapsed()
        );
    }
}
