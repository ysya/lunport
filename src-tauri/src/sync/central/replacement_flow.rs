//! Explicit staged replacement. Account login never changes the current protected identity.
use super::{
    active_flow,
    api::{Api, Control, DeviceState},
    bootstrap,
    client_state::Phase,
    controller::{self, Session},
    credentials::DeviceIdentity,
    crypto,
    devices::PairingReveal,
    membership::TrustAnchor,
    owner::OwnerPath,
    replacement::{self, Route},
    replacement_publication::Authorization,
    wire::invalid,
    workspace::Workspace,
};
use crate::{error::AppError, sync::env::SyncEnv};
use serde::Serialize;
use std::sync::Arc;

pub struct Reading {
    operation: String,
    generation: String,
    session: Arc<Session>,
    active: active_flow::Reading,
}
#[derive(Serialize)]
pub struct Progress {
    pub phase: String,
    pub operation: Option<String>,
    pub verified: u64,
    pub total: u64,
    pub root_fingerprint: Option<String>,
    pub route: Option<Route>,
    pub unresolved_archives: usize,
}
fn current(env: &SyncEnv) -> Result<Workspace, AppError> {
    OwnerPath::Current.snapshot(env)
}
fn check(env: &SyncEnv, generation: &str) -> Result<(), AppError> {
    if env
        .runtime
        .central_replacement_generation
        .lock()
        .unwrap()
        .as_deref()
        != Some(generation)
    {
        return Err(AppError::Other("Device verification was paused or replaced. Saved identities, approval and local data are retained.".into()));
    }
    Ok(())
}
fn publish(
    env: &SyncEnv,
    generation: &str,
    path: &OwnerPath,
    before: &Workspace,
    next: &Workspace,
) -> Result<(), AppError> {
    let gate = env.runtime.central_replacement_generation.lock().unwrap();
    if gate.as_deref() != Some(generation) {
        return Err(crate::sync::runtime::superseded());
    }
    path.publish(env, before, next)
}
pub fn status(env: &SyncEnv) -> Result<Progress, AppError> {
    controller::require_enabled()?;
    let owner = current(env)?;
    let mut result = Progress {
        phase: "idle".into(),
        operation: None,
        verified: 0,
        total: 0,
        root_fingerprint: owner
            .control
            .anchor
            .as_ref()
            .map(|a| a.genesis_hash.clone()),
        route: None,
        unresolved_archives: owner
            .replacement_archives
            .iter()
            .filter(|a| a.needs_reconciliation)
            .count(),
    };
    if let Some(intent) = &owner.replacement {
        result.operation = Some(intent.operation.clone());
        result.route = Some(intent.route);
        result.phase = "paused".into();
        if let Some(candidate) = &intent.candidate {
            result.root_fingerprint = candidate
                .control
                .anchor
                .as_ref()
                .map(|a| a.genesis_hash.clone())
                .or(result.root_fingerprint);
            if candidate.control.phase == Phase::AwaitingApproval {
                result.phase = "awaiting_approval".into();
            }
        }
        if let Ok(read) = env.runtime.central_replacement_read.try_lock() {
            if let Some(read) = read.as_ref().filter(|r| {
                r.operation == intent.operation
                    && env
                        .runtime
                        .central_replacement_generation
                        .lock()
                        .unwrap()
                        .as_deref()
                        == Some(r.generation.as_str())
            }) {
                result.phase = "reading".into();
                result.verified = read.active.position();
                result.total = read.active.total();
            }
        }
    } else if let Some(last) = owner.replacement_archives.last() {
        result.phase = "complete".into();
        result.operation = Some(last.receipt.context.operation.clone());
        result.route = Some(last.route);
    }
    Ok(result)
}
/// Pauses memory-only verification. It never claims to undo an already committed server approval
/// or local switch. The final publication and cancellation are ordered by the same generation gate.
pub fn cancel(env: &SyncEnv) {
    env.runtime
        .central_replacement_generation
        .lock()
        .unwrap()
        .take();
    if let Ok(mut read) = env.runtime.central_replacement_read.try_lock() {
        read.take();
    }
}
fn count(env: &SyncEnv) {
    let mut core = env.runtime.core.lock().unwrap();
    core.central_poll.requests = core.central_poll.requests.saturating_add(1);
}
fn selected_session(
    env: &SyncEnv,
    owner: &Workspace,
    operation: &str,
) -> Result<Arc<Session>, AppError> {
    let account = controller::context(env)?;
    if account.profile != owner.control.profile
        || account
            .tokens_started
            .elapsed()
            .saturating_add(std::time::Duration::from_secs(5))
            >= account.tokens.expires_in
    {
        return Err(AppError::Other(
            "Sign in again to continue device replacement.".into(),
        ));
    }
    let profile = owner.control.profile.profile()?;
    let identity = DeviceIdentity::load_selected(env.keychain, &profile, Some(operation), true)?;
    if owner.replacement.as_ref().and_then(|i| i.device.as_ref()) != Some(&identity.device()) {
        return Err(invalid());
    }
    let template = Session {
        profile: account.profile.clone(),
        identity: Some(Arc::new(identity)),
        tokens: Arc::clone(&account.tokens),
        device: None,
        device_access_denied: false,
        tokens_started: account.tokens_started,
    };
    count(env);
    let session = bootstrap::register(env, &template, &Api::new(&owner.control.profile.origin)?)?;
    Ok(Arc::new(session))
}
/// Repeated explicit starts reuse the durable operation and selected OS identity. A pending
/// approval is harmless to resume; an active flag without its protected OOB proof is rejected.
pub fn begin_trusted(env: &SyncEnv) -> Result<Progress, AppError> {
    controller::require_enabled()?;
    super::round::check_cooldown(env)?;
    let generation = crypto::random_id(16)?;
    *env.runtime.central_replacement_generation.lock().unwrap() = Some(generation.clone());
    let intent = replacement::prepare(env, Route::TrustedDevice)?;
    let lifecycle = env.runtime.lifecycle.lock().unwrap();
    check(env, &generation)?;
    env.runtime.central_replacement_read.lock().unwrap().take();
    let source = current(env)?;
    let operation = intent.operation;
    let path = OwnerPath::Replacement(operation.clone());
    if source.control.phase == Phase::SignedOut {
        return Err(invalid());
    }
    let session = selected_session(env, &source, &operation)?;
    check(env, &generation)?;
    let before = {
        let gate = env.runtime.central_replacement_generation.lock().unwrap();
        if gate.as_deref() != Some(&generation) {
            return Err(crate::sync::runtime::superseded());
        }
        replacement::initialize_candidate(env, &operation, &session)?
    };
    let api = Api::new(&source.control.profile.origin)?;
    count(env);
    let remote = controller::overview(env, &api, &session)?;
    check(env, &generation)?;
    let identity = session.identity.as_ref().ok_or_else(invalid)?;
    if remote.auth_epoch < before.control.auth_epoch || remote.denied.contains(&identity.id) {
        return Err(invalid());
    }
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
    {
        return Err(invalid());
    }
    proof.verify(&anchor, source.control.highwater.as_ref())?;
    let profile = source.control.profile.profile()?;
    if session.device.as_ref().ok_or_else(invalid)?.device_state == DeviceState::Pending {
        if before.control.anchor.is_some() {
            return Err(invalid());
        }
        let pending = controller::pending_pairing(env, &profile, identity, &anchor)?;
        check(env, &generation)?;
        let mut next = before.clone();
        next.control = before.control.begin_pairing(&pending)?;
        next.control.auth_epoch = remote.auth_epoch;
        publish(env, &generation, &path, &before, &next)?;
        check(env, &generation)?;
        count(env);
        let reply = api.control(
            session.device.as_ref().ok_or_else(invalid)?,
            Control::Enrollment,
            &serde_json::json!({"request":pending.request()}),
        )?;
        check(env, &generation)?;
        super::round::require_success(env, &reply)?;
        drop(lifecycle);
        env.events.status();
        return status(env);
    }
    let mut next = before.clone();
    if before.control.anchor.is_none() {
        let confirmation = remote.pairing_confirmation.as_ref().ok_or_else(invalid)?;
        let pending = controller::load_pairing(env, &profile, identity, &confirmation.request_id)?;
        if next.control.pending_request.as_ref() != Some(pending.request()) {
            next.control = next.control.begin_pairing(&pending)?;
        }
        next.control = next.control.accept_pairing(&pending, confirmation, proof)?;
    } else {
        next.control = next.control.observe_proof(proof, remote.auth_epoch)?;
    }
    next.control.auth_epoch = remote.auth_epoch;
    next.control = next
        .control
        .remember_denials(remote.denied.iter().map(String::as_str))?;
    if next.control.phase == Phase::Revoked {
        return Err(invalid());
    }
    if remote.phase != "ready" || remote.vaults.values().any(|v| v.rekey) {
        next.control.phase = Phase::Rekey;
    }
    publish(env, &generation, &path, &before, &next)?;
    if remote.phase != "ready" || remote.barrier.is_some() {
        drop(lifecycle);
        env.events.status();
        return status(env);
    }
    let source = current(env)?;
    let active =
        active_flow::Reading::begin(env, path, Arc::clone(&session), Some(source), &|| {
            check(env, &generation)
        })?;
    let gate = env.runtime.central_replacement_generation.lock().unwrap();
    if gate.as_deref() != Some(&generation) {
        return Err(crate::sync::runtime::superseded());
    }
    *env.runtime.central_replacement_read.lock().unwrap() = Some(Reading {
        operation,
        generation: generation.clone(),
        session,
        active,
    });
    drop(gate);
    drop(lifecycle);
    env.events.status();
    status(env)
}
/// Dedicated reveal only. Never place this secret in status/events or a query/mutation cache.
pub fn pairing_code(env: &SyncEnv, operation: &str) -> Result<PairingReveal, AppError> {
    controller::require_enabled()?;
    let _lifecycle = env.runtime.lifecycle.lock().unwrap();
    let source = current(env)?;
    let intent = source.replacement.as_ref().ok_or_else(invalid)?;
    if intent.operation != operation || intent.route != Route::TrustedDevice {
        return Err(invalid());
    }
    let path = OwnerPath::Replacement(operation.into());
    let staged = path.snapshot(env)?;
    if staged.control.phase != Phase::AwaitingApproval {
        return Err(invalid());
    }
    let request = staged
        .control
        .pending_request
        .as_ref()
        .ok_or_else(invalid)?;
    let profile = source.control.profile.profile()?;
    let identity = DeviceIdentity::load_selected(env.keychain, &profile, Some(operation), true)?;
    if identity.device() != staged.control.device {
        return Err(invalid());
    }
    let pairing = controller::load_pairing(env, &profile, &identity, &request.request_id)?;
    if pairing.request() != request {
        return Err(invalid());
    }
    request.verify_live(env.now())?;
    Ok(PairingReveal {
        code: pairing.code()?.to_string(),
        expires_at_ms: request.expires_at_ms.clone(),
    })
}
pub fn advance(env: &SyncEnv, operation: &str) -> Result<Progress, AppError> {
    controller::require_enabled()?;
    let lifecycle = env.runtime.lifecycle.lock().unwrap();
    let mut holder = env.runtime.central_replacement_read.lock().unwrap();
    let reading = holder.as_mut().ok_or_else(invalid)?;
    if reading.operation != operation {
        return Err(invalid());
    }
    check(env, &reading.generation)?;
    if !reading
        .active
        .advance(env, &|| check(env, &reading.generation))?
    {
        drop(holder);
        drop(lifecycle);
        return status(env);
    }
    let reading = holder.take().ok_or_else(invalid)?;
    drop(holder);
    let (read, own_bridges, source_bridges) = reading.active.finish()?;
    let authority =
        Authorization::prepare(env, reading.session, read, own_bridges, source_bridges)?;
    let mut gate = env.runtime.central_replacement_generation.lock().unwrap();
    if gate.as_deref() != Some(&reading.generation) {
        return Err(crate::sync::runtime::superseded());
    }
    authority.publish(env, &lifecycle)?;
    gate.take();
    drop(gate);
    drop(lifecycle);
    env.events.status();
    env.events.wake_implicit();
    status(env)
}
