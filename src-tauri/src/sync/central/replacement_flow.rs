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
use serde::{Deserialize, Serialize};
use std::{sync::Arc, time::Instant};

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
    pub backup_confirmed: bool,
}
/// Public concurrency fence only. This grants no content keys or publication authority.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Invocation {
    pub generation: String,
    pub scope: String,
    pub route: Route,
    pub operation: Option<String>,
}
fn source_scope(owner: &Workspace) -> Result<String, AppError> {
    let profile = serde_json::to_string(&owner.control.profile).map_err(|_| invalid())?;
    Ok(crypto::hash(&super::wire::canonical(&[
        "lunport-replacement-ui-scope-v1",
        &profile,
        &owner.control.account_id,
        &owner.control.device.id,
        &owner.control.device.keys.signing,
        &owner.control.device.keys.encryption,
        owner
            .control
            .anchor
            .as_ref()
            .map_or("", |a| a.genesis_hash.as_str()),
    ])?))
}
/// Short metadata-only reservation. OS credentials, durable preparation and network follow only
/// when the caller still owns this exact invocation. UI reservations are serialized by the client.
pub fn reserve_invocation(env: &SyncEnv, route: Route) -> Result<Invocation, AppError> {
    controller::require_enabled()?;
    let mut gate = env.runtime.central_replacement_generation.lock().unwrap();
    let owner = current(env)?;
    if owner.control.phase == Phase::SignedOut
        || owner.bootstrap.is_some()
        || owner
            .recovery
            .as_ref()
            .is_some_and(|r| r.requires_cleanup())
        || owner.replacement.as_ref().is_some_and(|i| i.route != route)
    {
        return Err(invalid());
    }
    if owner.replacement.is_none() {
        let reading = env
            .runtime
            .central_recovery_read
            .try_lock()
            .map_err(|_| invalid())?;
        if reading.is_some() {
            return Err(invalid());
        }
    }
    if owner.replacement.is_some() {
        super::recovery_flow::cancel_replacement(env);
        if let Ok(mut read) = env.runtime.central_replacement_read.try_lock() {
            read.take();
        }
    }
    let invocation = Invocation {
        generation: crypto::random_id(16)?,
        scope: source_scope(&owner)?,
        route,
        operation: owner.replacement.as_ref().map(|i| i.operation.clone()),
    };
    *gate = Some(invocation.generation.clone());
    *env.runtime.central_replacement_ui.lock().unwrap() = Some(invocation.clone());
    Ok(invocation)
}
fn check_invocation(
    env: &SyncEnv,
    invocation: &Invocation,
    operation: Option<&str>,
) -> Result<(), AppError> {
    controller::require_enabled()?;
    if !super::wire::hex(&invocation.generation, 32)
        || !super::wire::hex(&invocation.scope, 64)
        || invocation
            .operation
            .as_ref()
            .is_some_and(|o| !super::wire::hex(o, 32))
    {
        return Err(invalid());
    }
    let gate = env.runtime.central_replacement_generation.lock().unwrap();
    if gate.as_deref() != Some(invocation.generation.as_str())
        || env.runtime.central_replacement_ui.lock().unwrap().as_ref() != Some(invocation)
    {
        return Err(crate::sync::runtime::superseded());
    }
    let owner = current(env)?;
    if owner.control.phase == Phase::SignedOut || source_scope(&owner)? != invocation.scope {
        return Err(invalid());
    }
    match &owner.replacement {
        Some(intent)
            if intent.route == invocation.route
                && invocation
                    .operation
                    .as_ref()
                    .is_none_or(|o| o == &intent.operation)
                && operation.is_none_or(|o| o == intent.operation) =>
        {
            Ok(())
        }
        None if invocation.operation.is_none() && operation.is_none() => Ok(()),
        _ => Err(invalid()),
    }
}
pub fn cancel_invocation(env: &SyncEnv, invocation: &Invocation) -> Result<Progress, AppError> {
    controller::require_enabled()?;
    let mut gate = env.runtime.central_replacement_generation.lock().unwrap();
    let mut public = env.runtime.central_replacement_ui.lock().unwrap();
    if gate.as_deref() == Some(invocation.generation.as_str())
        && public.as_ref() == Some(invocation)
    {
        gate.take();
        public.take();
        if current(env)?.replacement.is_some() {
            super::recovery_flow::cancel_replacement(env);
        }
        if let Ok(mut read) = env.runtime.central_replacement_read.try_lock() {
            read.take();
        }
    }
    drop(public);
    drop(gate);
    status(env)
}
pub fn start_invocation(
    env: &SyncEnv,
    invocation: &Invocation,
    encoded_kit: Option<&str>,
) -> Result<Progress, AppError> {
    check_invocation(env, invocation, None)?;
    match invocation.route {
        Route::TrustedDevice => begin_trusted_at(env, invocation.generation.clone()),
        Route::RecoveryKit => begin_recovery_at(env, encoded_kit, invocation.generation.clone()),
    }
}
pub fn continue_invocation(
    env: &SyncEnv,
    invocation: &Invocation,
    operation: &str,
) -> Result<Progress, AppError> {
    check_invocation(env, invocation, Some(operation))?;
    if status(env)?.phase == "recovering" {
        advance_recovery_at(env, operation, invocation.generation.clone())
    } else {
        advance_at(env, operation, &invocation.generation)
    }
}
pub fn revalidate_invocation(
    env: &SyncEnv,
    invocation: &Invocation,
    operation: &str,
    encoded_kit: Option<&str>,
) -> Result<Progress, AppError> {
    check_invocation(env, invocation, Some(operation))?;
    if invocation.route != Route::RecoveryKit {
        return Err(invalid());
    }
    revalidate_recovery_at(env, operation, encoded_kit, invocation.generation.clone())
}
pub fn confirm_invocation(
    env: &SyncEnv,
    invocation: &Invocation,
    operation: &str,
) -> Result<Progress, AppError> {
    check_invocation(env, invocation, Some(operation))?;
    if invocation.route != Route::RecoveryKit {
        return Err(invalid());
    }
    confirm_recovery_at(env, operation, invocation.generation.clone())
}
pub fn reveal_pairing_invocation(
    env: &SyncEnv,
    invocation: &Invocation,
    operation: &str,
) -> Result<PairingReveal, AppError> {
    check_invocation(env, invocation, Some(operation))?;
    if invocation.route != Route::TrustedDevice {
        return Err(invalid());
    }
    let shown = pairing_code_at(env, operation, Some(&invocation.generation))?;
    check_invocation(env, invocation, Some(operation))?;
    Ok(shown)
}
pub fn reveal_kit_invocation(
    env: &SyncEnv,
    invocation: &Invocation,
    operation: &str,
) -> Result<super::bootstrap::RecoveryReveal, AppError> {
    check_invocation(env, invocation, Some(operation))?;
    if invocation.route != Route::RecoveryKit {
        return Err(invalid());
    }
    let shown = recovery_kit_at(env, operation, Some(&invocation.generation))?;
    check_invocation(env, invocation, Some(operation))?;
    Ok(shown)
}
fn current(env: &SyncEnv) -> Result<Workspace, AppError> {
    OwnerPath::Current.snapshot(env)
}
pub(super) fn check(env: &SyncEnv, generation: &str) -> Result<(), AppError> {
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
        backup_confirmed: false,
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
        if intent.route == Route::RecoveryKit
            && intent.candidate.is_some()
            && owner.control.phase != Phase::SignedOut
        {
            let recovery = super::recovery_flow::staged_status(
                env,
                &intent.operation,
                intent.candidate.as_deref().ok_or_else(invalid)?,
            )?;
            result.phase = match recovery.phase.as_str() {
                "reading" => "recovering",
                "complete" => "verification_required",
                "idle" => "paused",
                other => other,
            }
            .into();
            result.verified = recovery.verified;
            result.total = recovery.total;
            result.backup_confirmed = recovery.backup_confirmed;
            result.root_fingerprint = recovery.root_fingerprint.or(result.root_fingerprint);
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
        result.backup_confirmed = last.route == Route::RecoveryKit && owner.recovery.is_some();
    }
    Ok(result)
}
/// Pauses memory-only verification. It never claims to undo an already committed server approval
/// or local switch. The final publication and cancellation are ordered by the same generation gate.
pub fn cancel(env: &SyncEnv) {
    let mut gate = env.runtime.central_replacement_generation.lock().unwrap();
    gate.take();
    env.runtime.central_replacement_ui.lock().unwrap().take();
    super::recovery_flow::cancel_replacement(env);
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
    let generation = crypto::random_id(16)?;
    *env.runtime.central_replacement_generation.lock().unwrap() = Some(generation.clone());
    begin_trusted_at(env, generation)
}
fn begin_trusted_at(env: &SyncEnv, generation: String) -> Result<Progress, AppError> {
    let started = Instant::now();
    controller::require_enabled()?;
    super::round::check_cooldown(env)?;
    check(env, &generation)?;
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
    stage_active(env, &operation, &generation, session, started)?;
    drop(lifecycle);
    env.events.status();
    status(env)
}
fn stage_active(
    env: &SyncEnv,
    operation: &str,
    generation: &str,
    session: Arc<Session>,
    started: Instant,
) -> Result<(), AppError> {
    let path = OwnerPath::Replacement(operation.into());
    let active = active_flow::Reading::begin_at(
        env,
        path,
        Arc::clone(&session),
        Some(current(env)?),
        &|| check(env, generation),
        started,
    )?;
    let gate = env.runtime.central_replacement_generation.lock().unwrap();
    if gate.as_deref() != Some(generation) {
        return Err(crate::sync::runtime::superseded());
    }
    *env.runtime.central_replacement_read.lock().unwrap() = Some(Reading {
        operation: operation.into(),
        generation: generation.into(),
        session,
        active,
    });
    Ok(())
}
fn recovery_generation(env: &SyncEnv) -> Result<String, AppError> {
    let mut gate = env.runtime.central_replacement_generation.lock().unwrap();
    if gate.is_none() {
        *gate = Some(crypto::random_id(16)?);
    }
    gate.clone().ok_or_else(invalid)
}
fn recovery_scope(
    env: &SyncEnv,
    operation: &str,
    generation: &str,
    started: Instant,
) -> Result<super::recovery_flow::Scope, AppError> {
    check(env, generation)?;
    let source = current(env)?;
    let intent = source.replacement.as_ref().ok_or_else(invalid)?;
    if source.control.phase == Phase::SignedOut
        || intent.operation != operation
        || intent.route != Route::RecoveryKit
    {
        return Err(invalid());
    }
    let session = selected_session(env, &source, operation)?;
    check(env, generation)?;
    super::recovery_flow::Scope::replacement(operation, session, generation, started)
}
fn begin_recovered_baseline(
    env: &SyncEnv,
    operation: &str,
    generation: &str,
    started: Instant,
) -> Result<Progress, AppError> {
    let lifecycle = env.runtime.lifecycle.lock().unwrap();
    check(env, generation)?;
    let source = current(env)?;
    let intent = source.replacement.as_ref().ok_or_else(invalid)?;
    if intent.operation != operation
        || intent.route != Route::RecoveryKit
        || intent
            .candidate
            .as_ref()
            .and_then(|c| c.recovery.as_ref())
            .is_none_or(|r| r.requires_cleanup())
    {
        return Err(invalid());
    }
    let session = selected_session(env, &source, operation)?;
    stage_active(env, operation, generation, session, started)?;
    drop(lifecycle);
    env.events.status();
    status(env)
}
pub fn begin_recovery(env: &SyncEnv, encoded_kit: Option<&str>) -> Result<Progress, AppError> {
    begin_recovery_at(env, encoded_kit, recovery_generation(env)?)
}
fn begin_recovery_at(
    env: &SyncEnv,
    encoded_kit: Option<&str>,
    generation: String,
) -> Result<Progress, AppError> {
    check(env, &generation)?;
    let started = Instant::now();
    controller::require_enabled()?;
    super::round::check_cooldown(env)?;
    if current(env)?
        .replacement
        .as_ref()
        .is_some_and(|i| i.route != Route::RecoveryKit)
    {
        return Err(invalid());
    }
    let intent = replacement::prepare(env, Route::RecoveryKit)?;
    let operation = intent.operation;
    let lifecycle = env.runtime.lifecycle.lock().unwrap();
    check(env, &generation)?;
    {
        let mut read = env.runtime.central_replacement_read.lock().unwrap();
        if read.as_ref().is_some_and(|r| r.generation != generation) {
            read.take();
        }
    }
    super::recovery_flow::discard_superseded(env, &generation);
    let source = current(env)?;
    let session = selected_session(env, &source, &operation)?;
    {
        let gate = env.runtime.central_replacement_generation.lock().unwrap();
        if gate.as_deref() != Some(&generation) {
            return Err(crate::sync::runtime::superseded());
        }
        replacement::initialize_candidate(env, &operation, &session)?;
    }
    let scope =
        super::recovery_flow::Scope::replacement(&operation, session, &generation, started)?;
    drop(lifecycle);
    let progress = super::recovery_flow::status_at(env, &scope)?;
    if progress.phase == "complete" {
        return begin_recovered_baseline(env, &operation, &generation, started);
    }
    if progress.phase == "idle" {
        super::recovery_flow::start_at(env, scope, encoded_kit, false)?;
    }
    env.events.status();
    status(env)
}
pub fn advance_recovery(env: &SyncEnv, operation: &str) -> Result<Progress, AppError> {
    let generation = env
        .runtime
        .central_replacement_generation
        .lock()
        .unwrap()
        .clone()
        .ok_or_else(invalid)?;
    advance_recovery_at(env, operation, generation)
}
fn advance_recovery_at(
    env: &SyncEnv,
    operation: &str,
    generation: String,
) -> Result<Progress, AppError> {
    let started = Instant::now();
    controller::require_enabled()?;
    let lifecycle = env.runtime.lifecycle.lock().unwrap();
    let scope = recovery_scope(env, operation, &generation, started)?;
    drop(lifecycle);
    super::recovery_flow::advance_at(env, &scope)?;
    env.events.status();
    status(env)
}
pub fn revalidate_recovery(
    env: &SyncEnv,
    operation: &str,
    encoded_kit: Option<&str>,
) -> Result<Progress, AppError> {
    revalidate_recovery_at(env, operation, encoded_kit, recovery_generation(env)?)
}
fn revalidate_recovery_at(
    env: &SyncEnv,
    operation: &str,
    encoded_kit: Option<&str>,
    generation: String,
) -> Result<Progress, AppError> {
    let started = Instant::now();
    controller::require_enabled()?;
    let lifecycle = env.runtime.lifecycle.lock().unwrap();
    let scope = recovery_scope(env, operation, &generation, started)?;
    drop(lifecycle);
    super::recovery_flow::start_at(env, scope, encoded_kit, true)?;
    env.events.status();
    status(env)
}
pub fn recovery_kit(
    env: &SyncEnv,
    operation: &str,
) -> Result<super::bootstrap::RecoveryReveal, AppError> {
    recovery_kit_at(env, operation, None)
}
fn recovery_kit_at(
    env: &SyncEnv,
    operation: &str,
    generation: Option<&str>,
) -> Result<super::bootstrap::RecoveryReveal, AppError> {
    controller::require_enabled()?;
    let _lifecycle = env.runtime.lifecycle.lock().unwrap();
    if let Some(generation) = generation {
        check(env, generation)?;
    }
    let source = current(env)?;
    if source.control.phase == Phase::SignedOut
        || source
            .replacement
            .as_ref()
            .is_none_or(|i| i.route != Route::RecoveryKit || i.operation != operation)
    {
        return Err(invalid());
    }
    super::recovery_credentials::reveal_at(env, &OwnerPath::Replacement(operation.into()))
}
pub fn confirm_recovery(env: &SyncEnv, operation: &str) -> Result<Progress, AppError> {
    confirm_recovery_at(env, operation, recovery_generation(env)?)
}
fn confirm_recovery_at(
    env: &SyncEnv,
    operation: &str,
    generation: String,
) -> Result<Progress, AppError> {
    let started = Instant::now();
    controller::require_enabled()?;
    let lifecycle = env.runtime.lifecycle.lock().unwrap();
    let scope = recovery_scope(env, operation, &generation, started)?;
    drop(lifecycle);
    let progress = super::recovery_flow::confirm_at(env, &scope, operation)?;
    if progress.phase == "complete" {
        begin_recovered_baseline(env, operation, &generation, started)
    } else {
        env.events.status();
        status(env)
    }
}
/// Dedicated reveal only. Never place this secret in status/events or a query/mutation cache.
pub fn pairing_code(env: &SyncEnv, operation: &str) -> Result<PairingReveal, AppError> {
    pairing_code_at(env, operation, None)
}
fn pairing_code_at(
    env: &SyncEnv,
    operation: &str,
    generation: Option<&str>,
) -> Result<PairingReveal, AppError> {
    controller::require_enabled()?;
    let _lifecycle = env.runtime.lifecycle.lock().unwrap();
    if let Some(generation) = generation {
        check(env, generation)?;
    }
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
    let generation = env
        .runtime
        .central_replacement_generation
        .lock()
        .unwrap()
        .clone()
        .ok_or_else(invalid)?;
    advance_at(env, operation, &generation)
}
fn advance_at(env: &SyncEnv, operation: &str, generation: &str) -> Result<Progress, AppError> {
    controller::require_enabled()?;
    let lifecycle = env.runtime.lifecycle.lock().unwrap();
    check(env, generation)?;
    let mut holder = env.runtime.central_replacement_read.lock().unwrap();
    let reading = holder.as_mut().ok_or_else(invalid)?;
    if reading.operation != operation || reading.generation != generation {
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
