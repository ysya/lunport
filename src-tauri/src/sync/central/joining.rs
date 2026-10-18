//! Acquire only encrypted replica material after out-of-band device approval. No library publication.
use super::{
    api::{Api, VaultResource},
    client_state::Phase,
    controller,
    crypto::WrappedKeys,
    rekey::{self, Checkpoint, SignedRekey},
    replica::Replica,
    wire::{invalid, number},
    workspace::Workspace,
};
use crate::{
    error::AppError,
    sync::{env::SyncEnv, record_runtime},
};
use serde::Deserialize;
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct EpochBundle {
    manifest: SignedRekey,
    wraps: Vec<WrappedKeys>,
}
pub fn initialize(env: &SyncEnv) -> Result<(), AppError> {
    controller::require_enabled()?;
    super::round::check_cooldown(env)?;
    let _lifecycle = env.runtime.lifecycle.lock().unwrap();
    let before = record_runtime::snapshot(env)?
        .0
        .local
        .central
        .ok_or_else(invalid)?;
    if before.replacement.is_some() {
        return Err(invalid());
    }
    if before.replica.is_some() || before.control.pairing_confirmation.is_none() {
        return Ok(());
    }
    if !matches!(before.control.phase, Phase::Enrolled | Phase::Rekey) {
        return Err(AppError::Other(
            "Vault verification is waiting for account recovery or key rotation.".into(),
        ));
    }
    let session = controller::context(env)?;
    let identity = session.identity.as_ref().ok_or_else(invalid)?;
    let api = Api::new(&before.control.profile.origin)?;
    let remote = controller::overview(env, &api, &session)?;
    if remote.proof.as_ref() != before.control.proof.as_ref()
        || remote.auth_epoch != before.control.auth_epoch
    {
        return Err(crate::sync::runtime::superseded());
    }
    let confirmation = before
        .control
        .pairing_confirmation
        .as_ref()
        .ok_or_else(invalid)?;
    if confirmation.minimums.len() != 1 || remote.vaults.len() != 1 || remote.phase != "ready" {
        return Err(invalid());
    }
    let minimum = &confirmation.minimums[0];
    let epoch = number(&minimum.key_epoch, false)?;
    let current = remote.vaults.get(&minimum.vault).ok_or_else(invalid)?;
    if current.epoch < epoch {
        return Err(invalid());
    }
    let chain = before.control.verified_chain()?;
    let mut next = before.clone();
    next.replica = Some(Replica::join(
        minimum.vault.clone(),
        minimum.creation_head.clone(),
        number(&minimum.creation_authorization_epoch, false)?,
        Checkpoint {
            epoch,
            sequence: number(&minimum.sequence, true)?,
            history_hash: minimum.history_hash.clone(),
        },
    )?);
    for target in 2..=epoch {
        let reply = api.vault(
            session.device.as_ref().ok_or_else(invalid)?,
            &minimum.vault,
            VaultResource::EpochWraps { epoch: target },
        )?;
        super::round::require_success(env, &reply)?;
        let bundle: EpochBundle = reply.decode()?;
        if number(&bundle.manifest.body.to_epoch, false)? != target {
            return Err(invalid());
        }
        rekey::verify_committed_wraps(&chain, &bundle.manifest, &bundle.wraps)?;
        next.epochs.push(bundle.manifest);
    }
    if current.epoch > epoch {
        // Intermediate ciphertext may already be gone. Keep the authenticated approval minimum
        // intact; the rotation executor bridges every signed source checkpoint before rebuilding
        // the latest cache. Do not pin an individual future wrap from a possibly cancelled attempt.
        next.control.phase = Phase::Rekey;
        next.validate()?;
        return publish(env, &before, &next);
    }
    if current.rekey {
        next.control.phase = Phase::Rekey;
    }
    let reply = api.vault(
        session.device.as_ref().ok_or_else(invalid)?,
        &minimum.vault,
        VaultResource::Wrap,
    )?;
    super::round::require_success(env, &reply)?;
    let wrap: WrappedKeys = reply.decode()?;
    if number(&wrap.header.key_epoch, false)? != epoch {
        return Err(invalid());
    }
    next.own_wraps.push(wrap.clone());
    next.validate()?;
    let author = chain
        .author_at(&wrap.header.membership_head, &wrap.header.author)
        .ok_or_else(invalid)?;
    wrap.open(&identity.keys, &wrap.header, &author.signing)?;
    publish(env, &before, &next)
}
fn publish(env: &SyncEnv, before: &Workspace, next: &Workspace) -> Result<(), AppError> {
    record_runtime::mutate_records(env, |records| {
        if records.local.central.as_ref() != Some(before) {
            return Err(crate::sync::runtime::superseded());
        }
        let mut next_records = records.clone();
        next_records.local.central = Some(next.clone());
        Ok(next_records)
    })?;
    Ok(())
}
