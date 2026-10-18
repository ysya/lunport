//! Foreground native recovery driver. The UI sees progress and one dedicated new-kit reveal.
//! Incomplete, unadopted ciphertext reads remain native memory only; a completed journal is durable.
use super::{
    api::{AccountOverview, Api, Control, DeviceState, Reply},
    bootstrap,
    client_state::Phase,
    controller::{self, Session},
    crypto,
    recovery::{RecoveryKit, RecoveryReadProof, RecoverySeed},
    recovery_credentials,
    recovery_read::{HistoryPage, ReadSession, RecoveryReply},
    recovery_state::{PreparedRecovery, RecoveryState},
    round,
    wire::invalid,
    workspace::Workspace,
};
use crate::{
    error::AppError,
    sync::{env::SyncEnv, record_runtime},
};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    sync::{atomic::Ordering, Arc},
    time::{Duration, Instant},
};
pub struct Reading {
    before: Workspace,
    operation: String,
    old_kit: RecoveryKit,
    seed: Option<RecoverySeed>,
    proof: RecoveryReadProof,
    read: Option<ReadSession>,
    prepared: Option<PreparedRecovery>,
    total: u64,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Progress {
    pub phase: String,
    pub operation: Option<String>,
    pub verified: u64,
    pub total: u64,
    pub root_fingerprint: Option<String>,
}
fn progress(
    phase: &str,
    operation: Option<&str>,
    verified: u64,
    total: u64,
    root: Option<&str>,
) -> Progress {
    Progress {
        phase: phase.into(),
        operation: operation.map(str::to_string),
        verified,
        total,
        root_fingerprint: root.map(str::to_string),
    }
}
fn workspace(env: &SyncEnv) -> Result<Workspace, AppError> {
    record_runtime::snapshot(env)?
        .0
        .local
        .central
        .ok_or_else(invalid)
}
fn package(owner: &Workspace) -> Result<&super::recovery_state::Package, AppError> {
    match owner.recovery.as_ref() {
        Some(RecoveryState::Pending { package }) => Ok(package),
        _ => Err(invalid()),
    }
}
fn count(env: &SyncEnv) {
    let mut core = env.runtime.core.lock().unwrap();
    core.central_poll.requests = core.central_poll.requests.saturating_add(1);
}
fn call(
    env: &SyncEnv,
    action: impl FnOnce() -> Result<Reply, AppError>,
) -> Result<Reply, AppError> {
    round::check_cooldown(env)?;
    count(env);
    let reply = action()?;
    round::require_success(env, &reply)?;
    Ok(reply)
}
fn overview(env: &SyncEnv, api: &Api, session: &Session) -> Result<AccountOverview, AppError> {
    round::check_cooldown(env)?;
    count(env);
    controller::overview(env, api, session)
}
fn check_session(owner: &Workspace, session: &Session) -> Result<(), AppError> {
    if session.profile != owner.control.profile
        || session
            .identity
            .as_ref()
            .is_none_or(|id| id.device() != owner.control.device)
        || session
            .device
            .as_ref()
            .is_none_or(|d| d.account_id != owner.control.account_id || d.expired())
    {
        return Err(invalid());
    }
    Ok(())
}
fn publish(env: &SyncEnv, before: &Workspace, next: &Workspace) -> Result<(), AppError> {
    record_runtime::mutate_records(env, |records| {
        if records.local.central.as_ref() != Some(before) {
            return Err(crate::sync::runtime::superseded());
        }
        let mut candidate = records.clone();
        candidate.local.central = Some(next.clone());
        Ok(candidate)
    })?;
    Ok(())
}
pub fn status(env: &SyncEnv) -> Result<Progress, AppError> {
    controller::require_enabled()?;
    let owner = workspace(env)?;
    if let Some(state) = &owner.recovery {
        let admission = state.admission();
        return Ok(progress(
            match state {
                RecoveryState::Pending { package } if package.submitted => "submitted",
                RecoveryState::Pending { .. } => "backup_required",
                RecoveryState::Accepted {
                    credentials_cleared: false,
                    ..
                } => "cleanup_required",
                RecoveryState::Accepted { .. } => "complete",
            },
            Some(state.operation()),
            admission.checkpoint.sequence,
            admission.checkpoint.sequence,
            Some(&admission.anchor.genesis_hash),
        ));
    }
    match env.runtime.central_recovery_read.try_lock() {
        Ok(read) => Ok(read.as_ref().map_or_else(
            || progress("idle", None, 0, 0, None),
            |r| {
                progress(
                    "reading",
                    Some(&r.operation),
                    r.read.as_ref().map_or(r.total, ReadSession::position),
                    r.total,
                    Some(&r.old_kit.anchor().genesis_hash),
                )
            },
        )),
        Err(_) => Ok(progress("reading", None, 0, 0, None)),
    }
}
pub fn cancel(env: &SyncEnv) {
    env.runtime
        .central_recovery_cancel
        .store(true, Ordering::SeqCst);
    if let Ok(mut read) = env.runtime.central_recovery_read.try_lock() {
        read.take();
    }
}
fn cancelled(env: &SyncEnv) -> Result<(), AppError> {
    if env.runtime.central_recovery_cancel.load(Ordering::SeqCst) {
        Err(AppError::Other("Recovery verification was cancelled. Local data and any saved recovery intent are retained.".into()))
    } else {
        Ok(())
    }
}
/// A missing code is allowed only to resume compact protected secrets left before Core publication.
pub fn begin(env: &SyncEnv, encoded_kit: Option<&str>) -> Result<Progress, AppError> {
    controller::require_enabled()?;
    controller::refresh(env)?;
    let lifecycle = env.runtime.lifecycle.lock().unwrap();
    round::check_cooldown(env)?;
    let before = workspace(env)?;
    if before.control.phase != Phase::AwaitingApproval
        || before.control.anchor.is_some()
        || before.recovery.is_some()
        || env.runtime.central_recovery_read.lock().unwrap().is_some()
    {
        return Err(invalid());
    }
    env.runtime
        .central_recovery_cancel
        .store(false, Ordering::SeqCst);
    let session = controller::context(env)?;
    check_session(&before, &session)?;
    let device = session.device.as_ref().ok_or_else(invalid)?;
    if device.device_state != DeviceState::Pending {
        return Err(AppError::Other("This device is already enrolled. Resume its saved recovery or trusted-device approval.".into()));
    }
    let api = Api::new(&before.control.profile.origin)?;
    count(env);
    let info = api.info()?;
    if info.oidc != before.control.profile.oidc
        || !info
            .features
            .iter()
            .any(|feature| feature == "recovery-history")
    {
        return Err(invalid());
    }
    let remote = overview(env, &api, &session)?;
    if remote.auth_epoch != before.control.auth_epoch {
        return Err(AppError::Other(
            "Refresh the account checkpoint before recovery. Local data is retained.".into(),
        ));
    }
    let proof = remote.proof.as_ref().ok_or_else(invalid)?;
    let orphan = recovery_credentials::resume_orphan(env, &before, proof)?;
    let (old_kit, seed, operation) = if let Some(orphan) = orphan {
        if let Some(encoded) = encoded_kit {
            if RecoveryKit::parse(encoded)?.encode_secret()?.as_str()
                != orphan.old_kit.encode_secret()?.as_str()
            {
                return Err(invalid());
            }
        }
        (orphan.old_kit, orphan.seed, orphan.operation)
    } else {
        (
            RecoveryKit::parse(encoded_kit.ok_or_else(invalid)?)?,
            RecoverySeed::generate()?,
            crypto::random_id(16)?,
        )
    };
    if old_kit.anchor().origin != before.control.profile.origin
        || old_kit.anchor().account_id != before.control.account_id
    {
        return Err(invalid());
    }
    let chain = proof.verify(old_kit.anchor(), None)?;
    let request = before
        .control
        .pending_request
        .as_ref()
        .ok_or_else(invalid)?;
    if remote.vaults.len() != 1
        || remote
            .devices
            .iter()
            .find(|d| d.device == before.control.device)
            .and_then(|d| d.request.as_ref())
            != Some(request)
    {
        return Err(invalid());
    }
    let read_proof = old_kit.read_proof(&chain, request, remote.auth_epoch, env.now())?;
    let reply = call(env, || {
        api.control(
            device,
            Control::RecoveryRead,
            &serde_json::json!({"proof":read_proof}),
        )
    })?;
    if reply.status == 202 {
        return Err(AppError::Other(
            "Recovery is waiting for device revocation to finish. Keep your kit and retry.".into(),
        ));
    }
    let response: RecoveryReply = reply.decode()?;
    let read = ReadSession::begin_fresh(&before, &old_kit, proof.clone(), response, env.now())?;
    if !remote.vaults.contains_key(read.vault()) {
        return Err(invalid());
    }
    let total = read.total();
    cancelled(env)?;
    *env.runtime.central_recovery_read.lock().unwrap() = Some(Reading {
        before,
        operation,
        old_kit,
        seed: Some(seed),
        proof: read_proof,
        read: Some(read),
        prepared: None,
        total,
    });
    let result = advance_locked(env);
    if env.runtime.central_recovery_cancel.load(Ordering::SeqCst) {
        env.runtime.central_recovery_read.lock().unwrap().take();
    }
    drop(lifecycle);
    result?;
    status(env)
}
pub fn advance(env: &SyncEnv) -> Result<Progress, AppError> {
    controller::require_enabled()?;
    controller::resume(env, false)?;
    let lifecycle = env.runtime.lifecycle.lock().unwrap();
    let result = advance_locked(env);
    if env.runtime.central_recovery_cancel.load(Ordering::SeqCst) {
        env.runtime.central_recovery_read.lock().unwrap().take();
    }
    drop(lifecycle);
    result?;
    status(env)
}
fn advance_locked(env: &SyncEnv) -> Result<(), AppError> {
    round::check_cooldown(env)?;
    let started = Instant::now();
    let mut holder = env.runtime.central_recovery_read.lock().unwrap();
    let state = holder.as_mut().ok_or_else(invalid)?;
    cancelled(env)?;
    if workspace(env)? != state.before {
        return Err(crate::sync::runtime::superseded());
    }
    let session = controller::context(env)?;
    check_session(&state.before, &session)?;
    let device = session.device.as_ref().ok_or_else(invalid)?;
    if device.auth_epoch != state.before.control.auth_epoch {
        return Err(invalid());
    }
    let api = Api::new(&state.before.control.profile.origin)?;
    let mut requests = 0;
    if let Some(read) = state.read.as_mut() {
        while read.position() < read.total()
            && requests < 32
            && started.elapsed() < Duration::from_secs(30)
        {
            cancelled(env)?;
            let page: HistoryPage = call(env, || api.control(device, Control::RecoveryHistory,
                &serde_json::json!({"proof":state.proof,"vault":read.vault(),"since":read.position().to_string()})))?.decode()?;
            read.append(page)?;
            requests += 1;
        }
        if read.position() != read.total() {
            return Ok(());
        }
        let verified = state.read.take().ok_or_else(invalid)?.finish()?;
        state.prepared = Some(PreparedRecovery::create(
            verified,
            &state.old_kit,
            &session.identity.as_ref().ok_or_else(invalid)?.keys,
            state.seed.take().ok_or_else(invalid)?,
            state.operation.clone(),
            env.now(),
        )?);
    }
    cancelled(env)?;
    let prepared = state.prepared.as_ref().ok_or_else(invalid)?;
    let permit = recovery_credentials::stage(env, &state.before, prepared, &state.old_kit)?;
    cancelled(env)?;
    recovery_credentials::install(env, &state.before, &prepared.package, permit)?;
    holder.take();
    Ok(())
}
fn register(env: &SyncEnv, session: &Session, api: &Api) -> Result<Session, AppError> {
    count(env);
    bootstrap::register(env, session, api)
}
/// The user confirms the newly revealed kit and understands that prior devices lose cloud access.
/// Once submitted, retries reuse the exact signed operation; a stale first-send plan is retained.
pub fn confirm(env: &SyncEnv, operation: &str) -> Result<Progress, AppError> {
    controller::require_enabled()?;
    let lifecycle = env.runtime.lifecycle.lock().unwrap();
    let mut before = workspace(env)?;
    if matches!(before.recovery, Some(RecoveryState::Accepted { .. })) {
        if before
            .recovery
            .as_ref()
            .is_none_or(|r| r.operation() != operation)
        {
            return Err(invalid());
        }
        recovery_credentials::cleanup(env)?;
        drop(lifecycle);
        return status(env);
    }
    let source = package(&before)?;
    if before
        .control
        .denied_devices
        .contains(&before.control.device.id)
    {
        return Err(invalid());
    }
    if source.operation != operation {
        return Err(invalid());
    }
    let api = Api::new(&before.control.profile.origin)?;
    let session = controller::context(env)?;
    let mut session = register(env, &session, &api)?;
    check_session(&before, &session)?;
    let remote = overview(env, &api, &session)?;
    let already_accepted = remote
        .proof
        .as_ref()
        .is_some_and(|proof| source.admission.verify(proof).is_ok());
    if !already_accepted {
        // Never re-upload a previously sent plan after observing a newer independent barrier.
        if remote.proof.as_ref() != Some(&source.source_proof)
            || remote.auth_epoch != source.admission.authorization_epoch
            || remote.vaults.len() != 1
            || remote
                .vaults
                .get(&source.admission.vault)
                .is_none_or(|v| v.epoch != source.admission.checkpoint.epoch)
            || remote
                .denied
                .iter()
                .any(|id| id == &source.admission.device.id)
        {
            return Err(AppError::Other("The recovery checkpoint changed. The saved kit and operation are retained for revalidation.".into()));
        }
        if !source.submitted {
            if remote.phase != "ready" || remote.barrier.is_some() {
                return Err(invalid());
            }
            recovery_credentials::confirm_backup(env, operation)?;
            before = workspace(env)?;
            let source = package(&before)?;
            source.require_first_send(
                &before,
                remote.proof.as_ref().ok_or_else(invalid)?,
                remote.auth_epoch,
                env.now(),
            )?;
            recovery_credentials::verify_pending(env, &before)?;
            let mut next = before.clone();
            match next.recovery.as_mut() {
                Some(RecoveryState::Pending { package }) => package.submitted = true,
                _ => return Err(invalid()),
            }
            publish(env, &before, &next)?;
            before = next;
        }
        let source = package(&before)?;
        let wraps = BTreeMap::from([(source.admission.vault.clone(), source.wraps.clone())]);
        let response = call(env, || {
            api.control(
                session.device.as_ref().ok_or_else(invalid)?,
                Control::Recover,
                &serde_json::json!({"node":source.node,"wraps":wraps}),
            )
        })?;
        if ![200, 202].contains(&response.status) {
            return Err(invalid());
        }
        session = register(env, &session, &api)?;
    }
    let mut remote = overview(env, &api, &session)?;
    let source = package(&before)?;
    source
        .admission
        .verify(remote.proof.as_ref().ok_or_else(invalid)?)?;
    if remote.phase != "ready" || remote.barrier.is_some() {
        call(env, || {
            api.control(
                session.device.as_ref().ok_or_else(invalid)?,
                Control::ResumeBarrier,
                &serde_json::json!({}),
            )
        })?;
        remote = overview(env, &api, &session)?;
    }
    if remote.phase != "ready" || remote.barrier.is_some() {
        env.runtime.core.lock().unwrap().central_session = Some(Arc::new(session));
        drop(lifecycle);
        return status(env);
    }
    if remote.vaults.len() != 1
        || remote
            .vaults
            .get(&source.admission.vault)
            .is_none_or(|v| v.epoch < source.admission.checkpoint.epoch)
    {
        return Err(invalid());
    }
    let mut next = source.accepted(
        &before,
        remote.proof.ok_or_else(invalid)?,
        remote.auth_epoch,
    )?;
    next.control = next
        .control
        .remember_denials(remote.denied.iter().map(String::as_str))?;
    publish(env, &before, &next)?;
    env.runtime.core.lock().unwrap().central_session = Some(Arc::new(session));
    recovery_credentials::cleanup(env)?;
    drop(lifecycle);
    env.events.status();
    env.events.wake_implicit();
    status(env)
}
