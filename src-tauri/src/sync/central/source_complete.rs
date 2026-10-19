//! Durable complete-source evidence only. Planning, consent and cutover remain separate.
use super::{
    capture_dispatch,
    capture_journal::Journal,
    controller::{self, Session},
    crypto::VaultKeys,
    source_archive::{self, Outputs, Receipt},
    source_capture,
    source_cursor::Cursor,
    source_package::Package,
    wire::invalid,
};
use crate::{
    error::AppError,
    sync::{env::SyncEnv, record_runtime, records_v3::SyncStateV3},
};
use std::sync::Arc;
/// Native-only passive evidence; no runtime, IPC representation or publication methods.
pub(super) struct Completed {
    pub package: Package,
    pub ancestors: Vec<Receipt>,
    pub cursor: Cursor,
    pub outputs: Outputs,
}
pub(super) fn check(
    env: &SyncEnv,
    state: &SyncStateV3,
    generation: u64,
    session: &Arc<Session>,
    keys: &VaultKeys,
) -> Result<(), AppError> {
    let (current, current_generation) = record_runtime::snapshot(env)?;
    if &current != state
        || current_generation != generation
        || !Arc::ptr_eq(&controller::context(env)?, session)
    {
        return Err(crate::sync::runtime::superseded());
    }
    source_capture::require_target(
        env,
        state.local.central.as_ref().ok_or_else(invalid)?,
        session,
        keys,
    )
}
/// Returns None only for no cursor or a capture that still has frozen-source work to do.
/// A complete result remains bound to every original file and protected receipt.
pub(super) fn ensure(env: &SyncEnv, keys: &VaultKeys) -> Result<Option<Completed>, AppError> {
    controller::require_enabled()?;
    let life = env.runtime.lifecycle.lock().unwrap();
    let _vault = env
        .runtime
        .vault
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let _publication = env.runtime.format_publication.lock().unwrap();
    let (state, generation) = record_runtime::snapshot(env)?;
    let session = controller::context(env)?;
    check(env, &state, generation, &session, keys)?;
    let owner = state.local.central.as_ref().ok_or_else(invalid)?;
    let signer = &session.identity.as_ref().ok_or_else(invalid)?.keys;
    let Some(saved) = Cursor::load(env, &life, owner)? else {
        return Ok(None);
    };
    let (package, ancestors, cursor, outputs) = if Package::complete_frame(&saved.bytes) {
        Journal::completed_source(env, owner, signer, saved)?
    } else {
        let loaded = Journal::load(env, &life, owner, signer)?.ok_or_else(invalid)?;
        if !capture_dispatch::ready(&loaded)? {
            return Ok(None);
        }
        if loaded.compact() {
            let (package, ancestors, cursor, outputs) = loaded.into_complete()?;
            package.files.require_unchanged_after_archive(
                env,
                package.state.legacy_v1_backup.as_deref(),
                &outputs,
            )?;
            check(env, &state, generation, &session, keys)?;
            return Ok(Some(Completed {
                package,
                ancestors,
                cursor,
                outputs,
            }));
        }
        let (package, mut ancestors, before, outputs) = loaded.into_complete()?;
        let bytes = package.encode_local()?;
        let ordinal = before.receipt().next_ordinal()?;
        let pending =
            source_archive::resume_next(env, owner, before.receipt(), ordinal, &bytes, &outputs)?;
        let (archived, outputs) = match pending {
            Some((archived, proof)) => (Some(archived), outputs.merge(proof)?),
            None => (None, outputs),
        };
        package.files.require_unchanged_after_archive(
            env,
            package.state.legacy_v1_backup.as_deref(),
            &outputs,
        )?;
        check(env, &state, generation, &session, keys)?;
        let archived = match archived {
            Some(archived) => archived,
            None => {
                outputs.require_room_for_snapshot(bytes.len())?;
                source_archive::next(env, &life, owner, ordinal, before.receipt(), &bytes)?
            }
        };
        let proof = archived.outputs(env, &owner.control.profile.profile()?, &bytes)?;
        let outputs = outputs.merge(proof)?;
        package.files.require_unchanged_after_archive(
            env,
            package.state.legacy_v1_backup.as_deref(),
            &outputs,
        )?;
        check(env, &state, generation, &session, keys)?;
        let saved = before.advance(env, &life, owner, &archived)?;
        ancestors.push(saved.cursor.receipt().clone());
        // Verify the predecessor-derived bytes through the same cold-read path before returning.
        let checked = Journal::completed_source(env, owner, signer, saved)?;
        if checked.1 != ancestors {
            return Err(invalid());
        }
        checked
    };
    if package.state != state {
        return Err(crate::sync::runtime::superseded());
    }
    package.files.require_unchanged_after_archive(
        env,
        package.state.legacy_v1_backup.as_deref(),
        &outputs,
    )?;
    check(env, &state, generation, &session, keys)?;
    Ok(Some(Completed {
        package,
        ancestors,
        cursor,
        outputs,
    }))
}
#[cfg(all(test, unix))]
mod tests;
