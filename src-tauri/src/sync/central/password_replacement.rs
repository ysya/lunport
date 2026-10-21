//! Password-authorized device recovery in the existing Records Core and physical library.
//! The old owner/outbox survives until full read + encrypted archive + typed publication.
use super::{
    api::{Api, Control, DeviceState},
    client_state::Phase,
    controller,
    membership::{Action, TrustAnchor},
    owner::OwnerPath,
    replacement::{self, Route},
    wire::invalid,
};
use crate::{
    error::AppError,
    sync::{env::SyncEnv, record_runtime},
};

pub(super) fn pending(env: &SyncEnv) -> Result<bool, AppError> {
    Ok(record_runtime::snapshot(env)?
        .0
        .local
        .central
        .as_ref()
        .and_then(|o| o.replacement.as_ref())
        .is_some_and(|i| i.route == Route::SyncPassword))
}
pub(super) fn begin(env: &SyncEnv, password: &str) -> Result<(), AppError> {
    super::round::check_cooldown(env)?;
    super::unlock_flow::cancel(env);
    let intent = replacement::prepare(env, Route::SyncPassword)?;
    let _life = env.runtime.lifecycle.lock().unwrap();
    let source = OwnerPath::Current.snapshot(env)?;
    let session = super::replacement_flow::selected_session(env, &source, &intent.operation)?;
    let before = replacement::initialize_candidate(env, &intent.operation, &session)?;
    super::replacement_archive::reserve_reconnected_key(env)?;
    let path = OwnerPath::Replacement(intent.operation.clone());
    let api = Api::new(&source.control.profile.origin)?;
    let remote = controller::overview(env, &api, &session)?;
    let proof = remote.proof.ok_or_else(invalid)?;
    let anchor = TrustAnchor {
        origin: source.control.profile.origin.clone(),
        account_id: source.control.account_id.clone(),
        genesis_hash: remote.genesis_hash.ok_or_else(invalid)?,
    };
    if source
        .control
        .anchor
        .as_ref()
        .is_some_and(|old| old != &anchor)
        || remote.auth_epoch < source.control.auth_epoch
        || remote.phase != "ready"
        || remote.barrier.is_some()
    {
        return Err(AppError::Other("Device access is still changing. Keep an approved device online to finish key rotation, then reconnect. Local data is retained.".into()));
    }
    proof.verify(&anchor, source.control.highwater.as_ref())?;
    if session.device.as_ref().ok_or_else(invalid)?.device_state == DeviceState::Active {
        let confirmation = remote.pairing_confirmation.as_ref().ok_or_else(invalid)?;
        let pending = controller::load_pairing(
            env,
            &source.control.profile.profile()?,
            session.identity.as_ref().ok_or_else(invalid)?,
            &confirmation.request_id,
        )?;
        require_unlock(&proof, &confirmation.approved_head)?;
        let mut next = before.clone();
        if next.control.pending_request.as_ref() != Some(pending.request())
            && next.control.anchor.is_none()
        {
            next.control = next.control.begin_pairing(&pending)?;
        }
        next.control = if next.control.anchor.is_some() {
            next.control.observe_proof(proof, remote.auth_epoch)?
        } else {
            next.control.accept_pairing(&pending, confirmation, proof)?
        };
        next.control.auth_epoch = remote.auth_epoch;
        path.publish(env, &before, &next)?;
        drop(_life);
        return resume_read(env);
    }
    if before.control.anchor.is_some() {
        return Err(invalid());
    }
    let pending = controller::pending_pairing(
        env,
        &source.control.profile.profile()?,
        session.identity.as_ref().ok_or_else(invalid)?,
        &anchor,
    )?;
    let mut next = before.clone();
    next.control = next.control.begin_pairing(&pending)?;
    next.control.auth_epoch = remote.auth_epoch;
    path.publish(env, &before, &next)?;
    let reply = api.control(
        session.device.as_ref().ok_or_else(invalid)?,
        Control::Enrollment,
        &serde_json::json!({"request": pending.request()}),
    )?;
    super::round::require_success(env, &reply)?;
    super::unlock_flow::begin_at(env, password, path, session)
}
fn require_unlock(proof: &super::trust::ControlProof, approved: &str) -> Result<(), AppError> {
    let anchor = TrustAnchor {
        origin: proof.genesis.origin.clone(),
        account_id: proof.genesis.account_id.clone(),
        genesis_hash: super::crypto::hash(&proof.genesis.canonical()?),
    };
    let chain = proof.verify(&anchor, None)?;
    let revision = chain.revision_of(approved).ok_or_else(invalid)?;
    if proof
        .nodes
        .get(revision.checked_sub(1).ok_or_else(invalid)?)
        .is_none_or(|n| n.body.action != Action::Unlock)
    {
        return Err(invalid());
    }
    Ok(())
}
pub(super) fn resume_read(env: &SyncEnv) -> Result<(), AppError> {
    let _life = env.runtime.lifecycle.lock().unwrap();
    let source = OwnerPath::Current.snapshot(env)?;
    let intent = source.replacement.as_ref().ok_or_else(invalid)?;
    if intent.route != Route::SyncPassword || source.control.phase == Phase::SignedOut {
        return Err(invalid());
    }
    let session = super::replacement_flow::selected_session(env, &source, &intent.operation)?;
    let api = Api::new(&source.control.profile.origin)?;
    let remote = controller::overview(env, &api, &session)?;
    let proof = remote.proof.ok_or_else(invalid)?;
    let before = intent.candidate.as_deref().ok_or_else(invalid)?;
    let confirmation = remote.pairing_confirmation.as_ref().ok_or_else(invalid)?;
    require_unlock(&proof, &confirmation.approved_head)?;
    let pending = controller::load_pairing(
        env,
        &source.control.profile.profile()?,
        session.identity.as_ref().ok_or_else(invalid)?,
        &confirmation.request_id,
    )?;
    pending.accept(confirmation, &proof)?;
    let mut next = before.clone();
    if before.control.anchor.is_none() {
        next.control = next.control.accept_pairing(&pending, confirmation, proof)?;
    } else {
        next.control = next.control.observe_proof(proof, remote.auth_epoch)?;
    }
    next.control.auth_epoch = remote.auth_epoch;
    OwnerPath::Replacement(intent.operation.clone()).publish(env, before, &next)?;
    let generation = super::crypto::random_id(16)?;
    *env.runtime.central_replacement_generation.lock().unwrap() = Some(generation.clone());
    super::replacement_flow::stage_active(
        env,
        &intent.operation,
        &generation,
        session,
        std::time::Instant::now(),
    )
}
pub(super) fn advance_unlock(env: &SyncEnv) -> Result<bool, AppError> {
    let keychain = super::credentials::Background(env.keychain);
    let background = SyncEnv { keychain: &keychain, ssh_dir: env.ssh_dir.clone(), state_path: env.state_path.clone(), home: env.home.clone(), ..*env };
    super::unlock_flow::advance(&background)
}
pub(super) fn background(
    env: &SyncEnv,
    report: &mut super::round::Report,
) -> Result<bool, AppError> {
    let keychain = super::credentials::Background(env.keychain);
    let background = SyncEnv { keychain: &keychain, ssh_dir: env.ssh_dir.clone(), state_path: env.state_path.clone(), home: env.home.clone(), ..*env };
    background_inner(&background, report)
}
fn background_inner(env: &SyncEnv, report: &mut super::round::Report) -> Result<bool, AppError> {
    let source = OwnerPath::Current.snapshot(env)?;
    let Some(intent) = source
        .replacement
        .as_ref()
        .filter(|i| i.route == Route::SyncPassword)
    else {
        return Ok(false);
    };
    if source.control.phase == Phase::SignedOut || !controller::status(env)?.account_authenticated {
        return Ok(true);
    }
    let reading = env
        .runtime
        .central_replacement_read
        .lock()
        .unwrap()
        .is_some();
    if !reading {
        if intent
            .candidate
            .as_deref()
            .is_none_or(|c| c.control.anchor.is_none())
        {
            return Ok(true);
        }
        resume_read(env)?;
        report.more = true;
    } else {
        let progress = super::replacement_flow::advance(env, &intent.operation)?;
        report.more = progress.phase != "complete";
        if !report.more {
            // The explicit recovery consent follows the verified new identity only after publication.
            super::automatic::start(env)?;
        }
    }
    Ok(true)
}
