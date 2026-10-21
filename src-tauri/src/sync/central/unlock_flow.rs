//! Foreground account unlock: complete authenticated read, then additive device enrollment.
use super::{
    api::{Api, Control, DeviceState},
    controller::{self, Session},
    pairing::PendingPairing,
    recovery::{RecoveryKit, RecoveryReadProof},
    recovery_read::{HistoryPage, ReadSession, RecoveryReply},
    trust::ControlProof,
    unlock_join::Prepared,
    wire::invalid,
    workspace::Workspace,
};
use crate::{
    error::AppError,
    sync::{env::SyncEnv, record_runtime},
};
use std::{
    sync::Arc,
    time::{Duration, Instant},
};
pub(crate) struct Reading {
    before: Workspace,
    anchor: super::membership::TrustAnchor,
    session: Arc<Session>,
    pending: PendingPairing,
    kit: Option<RecoveryKit>,
    source: ControlProof,
    read_proof: RecoveryReadProof,
    read: Option<ReadSession>,
    prepared: Option<Prepared>,
}
fn owner(env: &SyncEnv) -> Result<Workspace, AppError> {
    record_runtime::snapshot(env)?
        .0
        .local
        .central
        .ok_or_else(invalid)
}
pub(super) fn active(env: &SyncEnv) -> bool {
    env.runtime.central_unlock.lock().unwrap().is_some()
}
pub(super) fn cancel(env: &SyncEnv) {
    env.runtime.central_unlock.lock().unwrap().take();
}
pub(super) fn begin_password(env: &SyncEnv, password: &str) -> Result<(), AppError> {
    let _life = env.runtime.lifecycle.lock().unwrap();
    super::round::check_cooldown(env)?;
    let before = owner(env)?;
    if before.control.phase != super::client_state::Phase::AwaitingApproval
        || before.replacement.is_some()
    {
        return Err(invalid());
    }
    let session = controller::context(env)?;
    let identity = session.identity.as_ref().ok_or_else(invalid)?;
    let device = session.device.as_ref().ok_or_else(invalid)?;
    let request = before
        .control
        .pending_request
        .as_ref()
        .ok_or_else(invalid)?;
    request.verify_live(env.now())?;
    let anchor = super::membership::TrustAnchor {
        origin: request.origin.clone(),
        account_id: request.account_id.clone(),
        genesis_hash: request.genesis_hash.clone(),
    };
    let api = Api::new(&anchor.origin)?;
    let remote = controller::overview(env, &api, &session)?;
    if remote.auth_epoch != before.control.auth_epoch
        || remote.phase != "ready"
        || remote.vaults.len() != 1
    {
        return Err(AppError::Other(
            "The account changed. Refresh sign-in and try unlocking again.".into(),
        ));
    }
    let source = remote.proof.ok_or_else(invalid)?;
    let chain = source.verify(&anchor, None)?;
    let registry = super::unlock_store::read(env, &session, &chain)?.ok_or_else(|| {
        AppError::Other(
            "Set a sync unlock password on your first device before connecting this device.".into(),
        )
    })?;
    if !registry.uses_current_authority(&chain) {
        return Err(AppError::Other(
            "Update the sync unlock method on an approved device, then try again.".into(),
        ));
    }
    let envelope = registry
        .signed()
        .body
        .slots
        .iter()
        .find(|e| e.header.binding == super::unlock_envelope::Binding::Password)
        .ok_or_else(|| {
            AppError::Other(
                "Set a sync unlock password on your first device, then connect this device.".into(),
            )
        })?;
    let kit = envelope
        .open_password(password, chain.current().anchor(), 1)
        .map_err(|_| {
            AppError::Other("Could not unlock sync. Check your sync unlock password.".into())
        })?;
    kit.current_keys(&chain)?;
    let pending = controller::load_pairing(
        env,
        &session.profile.profile()?,
        identity,
        &request.request_id,
    )?;
    if pending.request() != request {
        return Err(invalid());
    }
    let read_proof = kit.read_proof(&chain, request, remote.auth_epoch, env.now())?;
    let reply = api.control(
        device,
        Control::RecoveryRead,
        &serde_json::json!({"proof":read_proof}),
    )?;
    super::round::require_success(env, &reply)?;
    let response: RecoveryReply = reply.decode()?;
    let read = ReadSession::begin_fresh(&before, &kit, source.clone(), response, env.now())?;
    *env.runtime.central_unlock.lock().unwrap() = Some(Reading {
        before,
        anchor,
        session,
        pending,
        kit: Some(kit),
        source,
        read_proof,
        read: Some(read),
        prepared: None,
    });
    Ok(())
}
/// At most eight history pages and twenty seconds per foreground step. No secret enters progress.
pub(super) fn advance(env: &SyncEnv) -> Result<bool, AppError> {
    let _life = env.runtime.lifecycle.lock().unwrap();
    super::round::check_cooldown(env)?;
    let mut holder = env.runtime.central_unlock.lock().unwrap();
    let Some(work) = holder.as_mut() else {
        return Ok(false);
    };
    let current = owner(env)?;
    let session = controller::context(env)?;
    if current != work.before || !Arc::ptr_eq(&session, &work.session) {
        holder.take();
        return Err(crate::sync::runtime::superseded());
    }
    let api = Api::new(&session.profile.origin)?;
    let device = session.device.as_ref().ok_or_else(invalid)?;
    let started = Instant::now();
    for _ in 0..8 {
        if started.elapsed() >= Duration::from_secs(20) {
            return Ok(true);
        }
        let Some(read) = work.read.as_mut() else {
            break;
        };
        if read.position() == read.total() {
            let verified = work.read.take().ok_or_else(invalid)?.finish()?;
            work.prepared = Some(Prepared::create(
                &verified,
                work.kit.as_ref().ok_or_else(invalid)?,
                &session.identity.as_ref().ok_or_else(invalid)?.keys,
                &work.pending,
                env.now(),
            )?);
            work.kit.take();
            break;
        }
        let before = read.position();
        let reply=api.control(device,Control::RecoveryHistory,&serde_json::json!({"proof":work.read_proof,"vault":read.vault(),"since":before.to_string()}))?;
        super::round::require_success(env, &reply)?;
        let page: HistoryPage = reply.decode()?;
        read.append(page)?;
        if read.position() <= before {
            return Err(invalid());
        }
    }
    if work.prepared.is_none() {
        return Ok(true);
    }
    let prepared = work.prepared.as_ref().ok_or_else(invalid)?;
    // Re-register first: an interrupted join may already have committed and invalidated the old session.
    let mut renewed = super::bootstrap::register(env, &session, &api)?;
    if renewed.device.as_ref().ok_or_else(invalid)?.device_state != DeviceState::Active {
        let reply = api.control(
            renewed.device.as_ref().ok_or_else(invalid)?,
            Control::UnlockJoin,
            prepared,
        )?;
        super::round::require_success(env, &reply)?;
        renewed = super::bootstrap::register(env, &session, &api)?;
    }
    let remote = controller::overview(env, &api, &renewed)?;
    if remote.phase != "ready" {
        return Ok(true);
    }
    if renewed.device.as_ref().ok_or_else(invalid)?.device_state != DeviceState::Active {
        return Err(invalid());
    }
    let proof = remote.proof.ok_or_else(invalid)?;
    let minimum = prepared
        .proof(&work.source)
        .verify(&work.anchor, None)?
        .highwater();
    proof.verify(&work.anchor, Some(&minimum))?;
    if remote.pairing_confirmation.as_ref() != Some(&prepared.confirmation) {
        return Err(invalid());
    }
    let mut next = work.before.clone();
    next.control = next
        .control
        .accept_pairing(&work.pending, &prepared.confirmation, proof)?;
    next.control.auth_epoch = remote.auth_epoch;
    next.validate()?;
    record_runtime::mutate_records(env, |records| {
        if records.local.central.as_ref() != Some(&work.before) {
            return Err(crate::sync::runtime::superseded());
        }
        let mut result = records.clone();
        result.local.central = Some(next.clone());
        Ok(result)
    })?;
    env.runtime.core.lock().unwrap().central_session = Some(Arc::new(renewed));
    holder.take();
    Ok(false)
}
