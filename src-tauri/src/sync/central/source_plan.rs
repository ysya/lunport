//! Durable randomized plan selection. A signed/stored plan is not human consent or upload authority.
use super::{
    capture_journal::Journal,
    controller,
    crypto::VaultKeys,
    migration_history::{self, Plan},
    payload::KeyStorage,
    source_archive::{self, Outputs, Receipt},
    source_complete,
    source_cursor::{Cursor, Restored},
    source_package::Package,
    wire::invalid,
};
use crate::{
    error::AppError,
    sync::{env::SyncEnv, record_runtime},
};
use std::collections::BTreeMap;
pub(super) struct Planned {
    pub package: Package,
    pub source_cursor: Cursor,
    pub plan: Plan,
    pub ancestors: Vec<Receipt>,
    pub cursor: Cursor,
    pub outputs: Outputs,
}
pub(super) fn restored(
    env: &SyncEnv,
    owner: &super::workspace::Workspace,
    keys: &VaultKeys,
    signer: &super::crypto::DeviceKeys,
    references: &BTreeMap<String, KeyStorage>,
    saved: Restored,
) -> Result<Planned, AppError> {
    let source_cursor = Plan::source_cursor(&saved.bytes)?;
    let parent = source_cursor.restored_parent(env, owner, &saved.cursor)?;
    let (package, ancestors, cursor, outputs) =
        Journal::completed_source(env, owner, signer, parent)?;
    let context = package.migration_context(cursor.receipt())?;
    let plan = Plan::decode_local(&saved.bytes, owner, keys, signer, &context)?;
    let history = package.structured_history(keys, references)?.into_rows();
    plan.matches_history(keys, &history)?;
    if plan.encode_with_source(&cursor)?.as_slice() != saved.bytes.as_slice() {
        return Err(invalid());
    }
    let mut ancestors = ancestors;
    ancestors.push(saved.cursor.receipt().clone());
    if ancestors.len() as u64 != saved.cursor.revision() {
        return Err(invalid());
    }
    let outputs = outputs.merge(saved.outputs)?;
    Ok(Planned {
        package,
        source_cursor: cursor,
        plan,
        ancestors,
        cursor: saved.cursor,
        outputs,
    })
}
/// Call only after complete-source evidence is present. Existing plan bytes always win over regeneration.
pub(super) fn ensure(
    env: &SyncEnv,
    keys: &VaultKeys,
    references: &BTreeMap<String, KeyStorage>,
) -> Result<Planned, AppError> {
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
    source_complete::check(env, &state, generation, &session, keys)?;
    let owner = state.local.central.as_ref().ok_or_else(invalid)?;
    let signer = &session.identity.as_ref().ok_or_else(invalid)?.keys;
    let saved = Cursor::load(env, &life, owner)?.ok_or_else(invalid)?;
    let planned = if Package::complete_frame(&saved.bytes) || Journal::frame(&saved.bytes) {
        let (package, _, before, outputs) = Journal::completed_source(env, owner, signer, saved)?;
        let context = package.migration_context(before.receipt())?;
        let history = package.structured_history(keys, references)?.into_rows();
        let ordinal = before.receipt().next_ordinal()?;
        let candidate =
            source_archive::candidate_next(env, owner, before.receipt(), ordinal, &outputs)?;
        let bytes = if let Some(bytes) = candidate {
            if Plan::source_cursor(&bytes)? != before {
                return Err(invalid());
            }
            let plan = Plan::decode_local(&bytes, owner, keys, signer, &context)?;
            plan.matches_history(keys, &history)?;
            if plan.encode_with_source(&before)?.as_slice() != bytes.as_slice() {
                return Err(invalid());
            }
            bytes
        } else {
            migration_history::prepare(owner, keys, signer, context, &history)?
                .encode_with_source(&before)?
        };
        let pending =
            source_archive::resume_next(env, owner, before.receipt(), ordinal, &bytes, &outputs)?;
        let (archived, outputs) = match pending {
            Some((archive, proof)) => (Some(archive), outputs.merge(proof)?),
            None => (None, outputs),
        };
        package.files.require_unchanged_after_archive(
            env,
            package.state.legacy_v1_backup.as_deref(),
            &outputs,
        )?;
        source_complete::check(env, &state, generation, &session, keys)?;
        let archived = match archived {
            Some(archive) => archive,
            None => {
                outputs.require_room_for_snapshot(bytes.len())?;
                source_archive::next(env, &life, owner, ordinal, before.receipt(), &bytes)?
            }
        };
        let outputs =
            outputs.merge(archived.outputs(env, &owner.control.profile.profile()?, &bytes)?)?;
        package.files.require_unchanged_after_archive(
            env,
            package.state.legacy_v1_backup.as_deref(),
            &outputs,
        )?;
        source_complete::check(env, &state, generation, &session, keys)?;
        restored(
            env,
            owner,
            keys,
            signer,
            references,
            before.advance(env, &life, owner, &archived)?,
        )?
    } else {
        restored(env, owner, keys, signer, references, saved)?
    };
    if planned.package.state != state {
        return Err(crate::sync::runtime::superseded());
    }
    planned.package.files.require_unchanged_after_archive(
        env,
        planned.package.state.legacy_v1_backup.as_deref(),
        &planned.outputs,
    )?;
    source_complete::check(env, &state, generation, &session, keys)?;
    Ok(planned)
}
#[cfg(all(test, unix))]
mod tests;
