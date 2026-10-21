//! Native account lifecycle. No access, refresh, device secret or content key is a frontend DTO.
use super::{
    api::{AccountOverview, Api, Control, DeviceSession, DeviceState, RegistrationOutcome},
    client_state::{Phase, ProfileData, State},
    credentials::{self, DeviceIdentity, Profile, SessionAttempt},
    membership::TrustAnchor,
    oidc::{LoginTokens, OidcConfig},
    pairing::PendingPairing,
    wire::invalid,
    workspace::Workspace,
};
use super::authentication::Config as LoginConfig;
use crate::{
    error::AppError,
    sync::{env::SyncEnv, record_runtime},
};
use serde::Serialize;
use std::{sync::Arc, time::Instant};
use zeroize::Zeroizing;
pub struct Session {
    pub profile: ProfileData,
    pub identity: Option<Arc<DeviceIdentity>>,
    pub tokens: Arc<LoginTokens>,
    pub device: Option<DeviceSession>,
    pub device_access_denied: bool,
    pub tokens_started: Instant,
}
#[derive(Clone, Debug, Serialize)]
pub struct Status {
    pub available: bool,
    pub configured: bool,
    pub phase: String,
    pub service: Option<String>,
    pub account_id: Option<String>,
    pub device_id: Option<String>,
    pub has_session: bool,
    pub needs_recovery: bool,
    pub replacement_pending: bool,
    pub needs_reconciliation: bool,
    pub can_sync: bool,
    pub login_pending: bool,
    pub root_fingerprint: Option<String>,
    pub membership_head: Option<String>,
    pub authorization_epoch: Option<String>,
    pub pending: usize,
    pub conflicts: usize,
    pub error: Option<String>,
}
pub fn enabled() -> bool {
    cfg!(any(
        test,
        all(
            feature = "central-sync",
            any(target_os = "macos", target_os = "linux", windows)
        )
    ))
}

pub fn require_enabled() -> Result<(), AppError> {
    if enabled() {
        Ok(())
    } else {
        Err(AppError::Other(
            "This build does not enable central account synchronization.".into(),
        ))
    }
}
pub fn status(env: &SyncEnv) -> Result<Status, AppError> {
    let login_pending = env.runtime.central_login.lock().unwrap().is_some();
    let core = env.runtime.core.lock().unwrap();
    let records = record_runtime::active_state(&core)?;
    let ws = records.local.central.as_ref();
    let phase = ws.map_or("signed_out", |w| match w.control.phase {
        Phase::Setup => "setup",
        Phase::AwaitingApproval => "awaiting_approval",
        Phase::BackupRequired => "backup_required",
        Phase::Enrolled => "enrolled",
        Phase::Active => "active",
        Phase::Rekey => "rekey",
        Phase::Revoked => "revoked",
        Phase::SignedOut => "signed_out",
    });
    Ok(Status {
        available: enabled(),
        login_pending,
        root_fingerprint: ws
            .and_then(|w| w.control.anchor.as_ref())
            .map(|a| a.genesis_hash.clone()),
        membership_head: ws
            .and_then(|w| w.control.highwater.as_ref())
            .map(|h| h.head.clone()),
        authorization_epoch: ws.map(|w| w.control.auth_epoch.to_string()),
        configured: ws.is_some(),
        phase: phase.into(),
        // A service is selected by the user, never inherited from a distributor's build URL.
        service: ws.map(|w| w.control.profile.origin.clone())
            .or_else(|| super::server_change::service_for(&env.state_path)),
        account_id: ws.map(|w| w.control.account_id.clone()),
        device_id: ws.map(|w| w.control.device.id.clone()),
        has_session: core
            .central_session
            .as_ref()
            .is_some_and(|s| s.device.as_ref().is_some_and(|d| !d.expired())),
        needs_recovery: core.central_session.as_ref().is_some_and(|s| {
            s.device_access_denied
                || s.identity.is_none()
                || s.device
                    .as_ref()
                    .is_some_and(|d| d.device_state == DeviceState::Active)
                    && ws.is_some_and(|w| w.control.anchor.is_none())
        }),
        replacement_pending: ws.is_some_and(|w| w.replacement.is_some()),
        needs_reconciliation: ws.is_some_and(super::replacement_reconciliation::required),
        can_sync: ws.is_some_and(Workspace::can_upload)
            && core
                .central_session
                .as_ref()
                .is_some_and(|s| s.device.as_ref().is_some_and(|d| !d.expired())),
        pending: ws
            .and_then(|w| w.replica.as_ref())
            .map_or(0, |r| r.pending.len()),
        conflicts: ws
            .and_then(|w| w.replica.as_ref())
            .map_or(0, |r| r.conflicts.values().map(Vec::len).sum()),
        error: core.central_user_action.clone(),
    })
}
/// A lost Recover reply or an account-only barrier can leave a fresh API grant ahead
/// of an unanchored pending owner. This retains account access only: it neither
/// adopts a root nor bypasses pairing/recovery proofs or the upload gates.
pub(crate) fn session_epoch_matches(control: &State, epoch: u64, state: DeviceState) -> bool {
    epoch == control.auth_epoch
        || epoch > control.auth_epoch
            && control.anchor.is_none()
            && control.pending_request.is_some()
            && (state == DeviceState::Active
                || matches!(control.phase, Phase::AwaitingApproval | Phase::SignedOut))
}
pub fn checked_config<C: Clone+Into<LoginConfig>>(env: &SyncEnv, service: &str, config: &C) -> Result<(), AppError> {
    let config: LoginConfig=config.clone().into();
    config.validate()?;
    if matches!(&config,LoginConfig::Passkey(c) if c.origin!=service){return Err(invalid());}
    let (records, _) = record_runtime::snapshot(env)?;
    if records
        .local
        .central
        .as_ref()
        .is_some_and(|w| w.control.profile.origin != service || w.control.profile.login != config)
    {
        return Err(AppError::Other("The account service's sign-in settings changed. Verify the service before signing in again.".into()));
    }
    Ok(())
}
fn current_login(env: &SyncEnv, operation: Option<&str>) -> Result<(), AppError> {
    if let Some(operation) = operation {
        if env
            .runtime
            .central_login
            .lock()
            .unwrap()
            .as_ref()
            .map(|(id, _)| id.as_str())
            != Some(operation)
        {
            return Err(AppError::Other("Sign-in was cancelled or replaced.".into()));
        }
    }
    Ok(())
}
pub fn overview(env: &SyncEnv, api: &Api, session: &Session) -> Result<AccountOverview, AppError> {
    let device = session
        .device
        .as_ref()
        .ok_or_else(|| AppError::Other("Sign in or recover this device's account keys.".into()))?;
    let reply = api.account(device)?;
    super::round::require_success(env, &reply)?;
    let value: AccountOverview = reply.decode()?;
    value.validate(device)?;
    if value.proof.as_ref().is_some_and(|p| {
        p.genesis.origin != session.profile.origin || p.genesis.account_id != device.account_id
    }) {
        return Err(invalid());
    }
    Ok(value)
}
pub(super) fn pending_pairing(
    env: &SyncEnv,
    profile: &Profile,
    identity: &DeviceIdentity,
    anchor: &TrustAnchor,
) -> Result<PendingPairing, AppError> {
    let slot = identity.slot(profile, "pairing")?;
    if let Some(encoded) = env.keychain.get(&slot)? {
        let pending = PendingPairing::restore(&Zeroizing::new(encoded), &identity.device())?;
        let r = pending.request();
        if r.origin != anchor.origin
            || r.account_id != anchor.account_id
            || r.genesis_hash != anchor.genesis_hash
        {
            return Err(invalid());
        }
        if r.verify_live(env.now()).is_ok() {
            return Ok(pending);
        }
        // An approval of this exact request may have committed after the account snapshot was
        // read. Preserve its only OOB secret before publishing an expired-request replacement.
        // One retained entry is sufficient with the single lifecycle owner and server request CAS.
        let retained = identity.slot(profile, "pairing-retained")?;
        let encoded = pending.encode_secret()?;
        env.keychain.set(&retained, &encoded)?;
        let readback = Zeroizing::new(env.keychain.get(&retained)?.ok_or_else(invalid)?);
        let verified = PendingPairing::restore(&readback, &identity.device())?;
        if verified.encode_secret()?.as_str() != encoded.as_str() {
            return Err(invalid());
        }
    }
    let pending = PendingPairing::begin(anchor, &identity.id, &identity.keys, env.now())?;
    env.keychain.set(&slot, &pending.encode_secret()?)?;
    let check = PendingPairing::restore(
        &Zeroizing::new(env.keychain.get(&slot)?.ok_or_else(invalid)?),
        &identity.device(),
    )?;
    if check.request() != pending.request() {
        return Err(invalid());
    }
    Ok(check)
}
pub(super) fn load_pairing(
    env: &SyncEnv,
    profile: &Profile,
    identity: &DeviceIdentity,
    request: &str,
) -> Result<PendingPairing, AppError> {
    if !super::wire::hex(request, 32) {
        return Err(invalid());
    }
    for kind in ["pairing", "pairing-retained"] {
        if let Some(value) = env.keychain.get(&identity.slot(profile, kind)?)? {
            let encoded = Zeroizing::new(value);
            if let Ok(pending) = PendingPairing::restore(&encoded, &identity.device()) {
                if pending.request().request_id == request {
                    return Ok(pending);
                }
            }
        }
    }
    Err(AppError::Other("The saved device approval proof is unavailable. Local data is retained; use device recovery.".into()))
}
/// A verified ID token supplies issuer/sub; service metadata never supplies a replacement subject.
/// Caller owns the user-initiated flow; mutations merge only the central section into latest Records.
pub fn establish<C: Into<LoginConfig>>(
    env: &SyncEnv,
    service: &str,
    config: C,
    tokens: LoginTokens,
    operation: Option<&str>,
) -> Result<Status, AppError> {
    establish_tokens(
        env,
        service,
        config.into(),
        Arc::new(tokens),
        Instant::now(),
        operation,
        true,
    )
}
fn establish_tokens(
    env: &SyncEnv,
    service: &str,
    config: LoginConfig,
    tokens: Arc<LoginTokens>,
    started: Instant,
    operation: Option<&str>,
    new_login: bool,
) -> Result<Status, AppError> {
    require_enabled()?;
    let lifecycle = env.runtime.lifecycle.lock().unwrap();
    establish_locked(
        env, service, config, tokens, started, operation, new_login, false, None,
    )?;
    drop(lifecycle);
    env.runtime.note_activity(env.now());
    env.events.status();
    env.events.wake_implicit();
    status(env)
}
fn establish_locked(
    env: &SyncEnv,
    service: &str,
    config: LoginConfig,
    tokens: Arc<LoginTokens>,
    started: Instant,
    operation: Option<&str>,
    new_login: bool,
    resumed: bool,
    budget: Option<&super::request_budget::Budget>,
) -> Result<(), AppError> {
    if !new_login
        && !resumed
        && !env
            .runtime
            .core
            .lock()
            .unwrap()
            .central_session
            .as_ref()
            .is_some_and(|s| Arc::ptr_eq(&s.tokens, &tokens))
    {
        return Err(crate::sync::runtime::superseded());
    }
    current_login(env, operation)?;
    checked_config(env, service, &config)?;
    if tokens.issuer != config.issuer() {
        return Err(invalid());
    }
    let profile = Profile::new(service, &tokens.issuer, &tokens.subject)?;
    let profile_data = ProfileData {
        origin: profile.origin.clone(),
        issuer: profile.issuer.clone(),
        subject: profile.subject.clone(),
        locator: profile.locator.clone(),
        login: config.clone(),
    };
    let (snapshot, _) = record_runtime::snapshot(env)?;
    let previous = snapshot.local.central.clone();
    if previous
        .as_ref()
        .is_some_and(|w| w.control.profile != profile_data)
    {
        return Err(invalid());
    }
    if new_login {
        credentials::save_refresh(env.keychain, &profile, &config, &tokens)?;
    }
    current_login(env, operation)?;
    let identity = if previous.is_some() {
        DeviceIdentity::load_selected(
            env.keychain,
            &profile,
            previous.as_ref().and_then(|w| w.identity_slot.as_deref()),
            true,
        )
        .ok()
        .filter(|id| {
            previous
                .as_ref()
                .is_some_and(|w| id.device() == w.control.device)
        })
    } else {
        Some(DeviceIdentity::load_or_create(
            env.keychain,
            &profile,
            true,
        )?)
    };
    let api = match budget {
        Some(budget) => Api::bounded(service, budget)?,
        None => Api::new(service)?,
    };
    let mut session = Session {
        profile: profile_data.clone(),
        identity: identity.map(Arc::new),
        tokens,
        device: None,
        device_access_denied: false,
        tokens_started: started,
    };
    let mut workspace = previous.clone();
    if let Some(identity) = &session.identity {
        super::round::check_cooldown(env)?;
        let attempt =
            SessionAttempt::prepare_with_reset(env.keychain, &profile, identity, env.now(), true)?;
        let registered = api.register_outcome(
            &profile,
            identity,
            &attempt,
            &session.tokens,
            &snapshot.device_name,
            env.now(),
        );
        session.device = match registered? {
            RegistrationOutcome::Accepted(device) => Some(device),
            RegistrationOutcome::Rejected(reply) if reply.status == 403 && previous.is_some() => {
                // Retain the verified IdP login for account-only management. A service refusal is
                // not a signed membership removal and must not permanently mark this device denied.
                session.device_access_denied = true;
                None
            }
            RegistrationOutcome::Rejected(reply) => {
                super::round::require_success(env, &reply)?;
                return Err(invalid());
            }
        };
        if session.device.is_some() {
            current_login(env, operation)?;
            if previous.as_ref().is_some_and(|w| {
                session
                    .device
                    .as_ref()
                    .is_none_or(|d| d.account_id != w.control.account_id)
            }) {
                return Err(AppError::Other("The service returned a different account for this sign-in. Local trust and data are retained.".into()));
            }
            let remote = overview(env, &api, &session)?;
            let mut public = match previous.as_ref() {
                Some(w) => w.control.clone(),
                None => State::new(
                    profile_data,
                    session.device.as_ref().unwrap().account_id.clone(),
                    identity.device(),
                    remote.auth_epoch,
                )?,
            };
            let recovery_reserved = previous.as_ref().is_some_and(|w| {
                (w.replacement.is_some() && w.control.anchor.is_none())
                    || matches!(
                        w.recovery,
                        Some(super::recovery_state::RecoveryState::Pending { .. })
                    )
            }) || previous
                .as_ref()
                .filter(|w| w.control.anchor.is_none())
                .map(|w| super::recovery_credentials::has_intent(env, w))
                .transpose()?
                .unwrap_or(false);
            if recovery_reserved {
                // Login retains account access while an explicit recovery/replacement is reserved.
                // It cannot bypass that intent through the original identity's pairing/root adoption.
                if public.phase == Phase::SignedOut && public.pending_request.is_some() {
                    public.phase = Phase::AwaitingApproval;
                }
            } else {
                if public.anchor.is_some() {
                    match remote.proof {
                        Some(proof) => {
                            public = public.observe_proof(proof, remote.auth_epoch)?;
                            if public.phase == Phase::SignedOut {
                                public.phase =
                                    if previous.as_ref().is_some_and(|w| w.bootstrap.is_some()) {
                                        Phase::BackupRequired
                                    } else if public.cutover && public.library.is_some() {
                                        Phase::Active
                                    } else {
                                        Phase::Enrolled
                                    };
                            }
                            if (remote.phase == "revocation_pending"
                                || remote.vaults.values().any(|v| v.rekey))
                                && public.phase != Phase::BackupRequired
                                && public.phase != Phase::Revoked
                            {
                                public.phase = Phase::Rekey;
                            }
                        }
                        None if previous.as_ref().is_some_and(|w| w.bootstrap.is_some()) => {
                            if public.phase == Phase::SignedOut {
                                public.phase = Phase::BackupRequired;
                            }
                        }
                        None => return Err(AppError::Other(
                            "The existing account Vault is unavailable. Local data is retained."
                                .into(),
                        )),
                    }
                } else if let Some(proof) = remote.proof {
                    let anchor = TrustAnchor {
                        origin: service.into(),
                        account_id: public.account_id.clone(),
                        genesis_hash: remote.genesis_hash.ok_or_else(invalid)?,
                    };
                    if session.device.as_ref().unwrap().device_state == DeviceState::Pending {
                        let pending = pending_pairing(env, &profile, identity, &anchor)?;
                        #[derive(Serialize)]
                        struct Request<'a> {
                            request: &'a super::membership::Enrollment,
                        }
                        let reply = api.control(
                            session.device.as_ref().unwrap(),
                            Control::Enrollment,
                            &Request {
                                request: pending.request(),
                            },
                        )?;
                        super::round::require_success(env, &reply)?;
                        public = public.begin_pairing(&pending)?;
                    } else if public.pending_request.is_some() {
                        if public.phase == Phase::SignedOut {
                            public.phase = Phase::AwaitingApproval;
                        }
                        let confirmation =
                            remote.pairing_confirmation.as_ref().ok_or_else(invalid)?;
                        let pending =
                            load_pairing(env, &profile, identity, &confirmation.request_id)?;
                        if public.pending_request.as_ref() != Some(pending.request()) {
                            public = public.begin_pairing(&pending)?;
                        }
                        public = public.accept_pairing(&pending, confirmation, proof)?;
                    }
                } else if public.pending_request.is_some() {
                    return Err(AppError::Other("The pending account Vault is temporarily unavailable. Keep this device's pairing request and retry.".into()));
                }
                if remote.auth_epoch < public.auth_epoch {
                    return Err(invalid());
                }
                public.auth_epoch = remote.auth_epoch;
                public = public.remember_denials(remote.denied.iter().map(String::as_str))?;
            }
            public.validate()?;
            let next = workspace.get_or_insert(Workspace::new(public.clone())?);
            next.control = public;
            if next.control.phase == Phase::Active && !next.can_upload() {
                next.control.phase = Phase::Rekey;
            }
        }
    }
    // Cancellation and final publication share this gate; a cancelled flow cannot publish later.
    let commit_gate = env.runtime.central_login.lock().unwrap();
    if operation.is_some() && commit_gate.as_ref().map(|(id, _)| id.as_str()) != operation {
        return Err(AppError::Other("Sign-in was cancelled or replaced.".into()));
    }
    record_runtime::mutate_records(env, |current| {
        if current.local.central != previous {
            return Err(crate::sync::runtime::superseded());
        }
        let mut next = current.clone();
        next.local.central = workspace.clone();
        Ok(next)
    })?;
    {
        let mut core = env.runtime.core.lock().unwrap();
        core.central_user_action = if session.device_access_denied {
            Some("This device's cloud authorization was refused. Account access is retained for device management and recovery; local trust and data are unchanged.".into())
        } else {
            None
        };
        if new_login {
            // A verified fresh sign-in repairs local retry state. A server's
            // separate Retry-After deadline is never cleared by signing in.
            core.central_poll.retry_at = None;
            core.central_poll.failures = 0;
            core.central_poll.requests = 0;
        }
        core.adoption_read = None;
        core.migration_plan = None;
        core.migration_verifier = None;
        core.central_session = Some(Arc::new(session));
    }
    drop(commit_gate);
    Ok(())
}
/// Resume a saved, already-approved/pairing profile without opening UI or inventing an identity.
/// Token rotation and opaque registration remain serialized with foreground account operations.
pub fn resume(env: &SyncEnv, force_session: bool) -> Result<bool, AppError> {
    resume_with_budget(env, force_session, None)
}
pub(super) fn resume_bounded(
    env: &SyncEnv,
    force_session: bool,
    budget: &super::request_budget::Budget,
) -> Result<bool, AppError> {
    resume_with_budget(env, force_session, Some(budget))
}
fn resume_with_budget(
    env: &SyncEnv,
    force_session: bool,
    budget: Option<&super::request_budget::Budget>,
) -> Result<bool, AppError> {
    if !enabled() {
        return Ok(false);
    }
    let lifecycle = env.runtime.lifecycle.lock().unwrap();
    if env.runtime.central_login.lock().unwrap().is_some() {
        return Ok(false);
    }
    let (records, _) = record_runtime::snapshot(env)?;
    let Some(workspace) = records.local.central.as_ref() else {
        return Ok(false);
    };
    if matches!(
        workspace.control.phase,
        Phase::SignedOut | Phase::Revoked | Phase::BackupRequired | Phase::Setup
    ) {
        return Ok(false);
    }
    let existing = env.runtime.core.lock().unwrap().central_session.clone();
    if existing
        .as_ref()
        .is_some_and(|s| s.profile != workspace.control.profile)
    {
        return Err(invalid());
    }
    if !force_session && existing.as_ref().is_some_and(|s| s.device_access_denied) {
        return Ok(false);
    }
    let token_margin = std::time::Duration::from_secs(60);
    if !force_session
        && existing.as_ref().is_some_and(|s| {
            s.tokens_started.elapsed().saturating_add(token_margin) < s.tokens.expires_in
                && s.device.as_ref().is_some_and(|d| {
                    !d.expired()
                        && session_epoch_matches(&workspace.control, d.auth_epoch, d.device_state)
                        && d.account_id == workspace.control.account_id
                })
                && s.identity
                    .as_ref()
                    .is_some_and(|id| id.device() == workspace.control.device)
        })
    {
        return Ok(true);
    }
    let background = credentials::Background(env.keychain);
    let safe_env = SyncEnv {
        doc: env.doc,
        backed_up: env.backed_up,
        retention: env.retention,
        runtime: env.runtime,
        ssh_dir: env.ssh_dir.clone(),
        state_path: env.state_path.clone(),
        home: env.home.clone(),
        keychain: &background,
        relays: env.relays,
        events: env.events,
        clock: env.clock,
        platform: env.platform,
    };
    let profile = workspace.control.profile.profile()?;
    let identity = DeviceIdentity::load_selected(
        &background,
        &profile,
        workspace.identity_slot.as_deref(),
        false,
    )?;
    if identity.device() != workspace.control.device {
        return Err(invalid());
    }
    let (tokens, started) = match existing {
        Some(session)
            if session
                .tokens_started
                .elapsed()
                .saturating_add(token_margin)
                < session.tokens.expires_in =>
        {
            (Arc::clone(&session.tokens), session.tokens_started)
        }
        _ => {
            let http = match budget {
                Some(budget) => {
                    budget.remaining()?;
                    super::oidc::BoundedHttp::bounded(budget)?
                }
                None => super::oidc::BoundedHttp::new()?,
            };
            let tokens = credentials::renew(
                &background,
                &profile,
                &workspace.control.profile.login,
                false,
                &http,
            )?;
            (Arc::new(tokens), Instant::now())
        }
    };
    establish_locked(
        &safe_env,
        &profile.origin,
        workspace.control.profile.login.clone(),
        tokens,
        started,
        None,
        false,
        true,
        budget,
    )?;
    let ready = env
        .runtime
        .core
        .lock()
        .unwrap()
        .central_session
        .as_ref()
        .is_some_and(|s| s.device.as_ref().is_some_and(|d| !d.expired()));
    drop(lifecycle);
    env.events.status();
    Ok(ready)
}
pub fn context(env: &SyncEnv) -> Result<Arc<Session>, AppError> {
    env.runtime
        .core
        .lock()
        .unwrap()
        .central_session
        .clone()
        .ok_or_else(|| AppError::Other("Sign in to manage this account.".into()))
}
/// Foreground status refresh; it never rewrites a refresh-token family or opens a browser.
pub fn refresh(env: &SyncEnv) -> Result<Status, AppError> {
    let session = context(env)?;
    if session
        .tokens_started
        .elapsed()
        .saturating_add(std::time::Duration::from_secs(5))
        >= session.tokens.expires_in
    {
        return Err(AppError::Other(
            "Sign in again to refresh this account.".into(),
        ));
    }
    establish_tokens(
        env,
        &session.profile.origin,
        session.profile.login.clone(),
        Arc::clone(&session.tokens),
        session.tokens_started,
        None,
        false,
    )
}
/// Local sign-out is durable even when the service is offline. Keep pinned trust and encrypted edits.
pub fn sign_out(env: &SyncEnv) -> Result<Status, AppError> {
    require_enabled()?;
    super::recovery_flow::cancel(env);
    super::replacement_flow::cancel(env);
    if let Some((_, Some(cancel))) = env.runtime.central_login.lock().unwrap().take() {
        cancel.cancel();
    }
    let lifecycle = env.runtime.lifecycle.lock().unwrap();
    env.runtime.central_recovery_read.lock().unwrap().take();
    super::unlock_flow::cancel(env);
    let (records, _) = record_runtime::snapshot(env)?;
    let before = records.local.central.as_ref().ok_or_else(invalid)?;
    let profile = before.control.profile.profile()?;
    let session = env.runtime.core.lock().unwrap().central_session.clone();
    record_runtime::mutate_records(env, |records| {
        if records.local.central.as_ref() != Some(before) {
            return Err(crate::sync::runtime::superseded());
        }
        let mut next = records.clone();
        next.local
            .central
            .as_mut()
            .ok_or_else(invalid)?
            .control
            .phase = Phase::SignedOut;
        Ok(next)
    })?;
    {
        let mut core = env.runtime.core.lock().unwrap();
        core.central_session = None;
        core.adoption_read = None;
        core.migration_plan = None;
        core.migration_verifier = None;
        core.central_user_action = None;
    }
    let cleanup = credentials::forget_refresh(env.keychain, &profile).and_then(|_| {
        credentials::forget_session_attempt(env.keychain, &profile, before.identity_slot.as_deref())
    });
    // This call cannot undo local sign-out; a short-lived opaque server session also expires independently.
    if let Some(device) = session.as_ref().and_then(|s| s.device.as_ref()) {
        if let Ok(api) = Api::new(&profile.origin) {
            let _ = api.control(device, Control::Logout, &serde_json::json!({}));
        }
    }
    if let (Some(session), super::authentication::Config::Passkey(config)) = (session.as_ref(), &before.control.profile.login) {
        if let Ok(http) = super::oidc::BoundedHttp::new() {
            let token = session.tokens.refresh.as_deref().map(|s| s.as_str()).unwrap_or(session.tokens.access.as_str());
            let _ = super::passkey::logout(config, token, &http);
        }
    }
    drop(lifecycle);
    env.events.status();
    cleanup?;
    status(env)
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::sync::{
        fake_relay::FakeRelay,
        record_repository as repo,
        records_v3::HostScope,
        testkit::{TestClock, TestDevice},
    };
    fn device() -> TestDevice {
        let d = TestDevice::new("a", &FakeRelay::new(), &TestClock::new());
        let env = d.env();
        let probe = record_runtime::probe_startup(&env.state_path, "central");
        record_runtime::activate_probe(&mut d.runtime.core.lock().unwrap(), probe).unwrap();
        d
    }
    fn tokens(config: &OidcConfig, subject: &str) -> LoginTokens {
        // Synthetic internal tokens; the native browser/OIDC boundary has separate verification tests.
        LoginTokens {
            issuer: config.issuer.clone(),
            subject: subject.into(),
            nonce: Zeroizing::new("SYNTHETIC-NONCE".into()),
            access: Zeroizing::new("SYNTHETIC-ACCESS".into()),
            refresh: Some(Zeroizing::new("SYNTHETIC-REFRESH".into())),
            expires_in: std::time::Duration::from_secs(300),
        }
    }
    #[test]
    fn sign_in_preserves_local_library_and_keeps_all_credentials_out_of_public_state_and_status() {
        use serde_json::json;
        let d = device();
        let env = d.env();
        let mut server = mockito::Server::new();
        let cfg = OidcConfig {
            issuer: "https://identity.test".into(),
            client_id: "native".into(),
            scopes: vec!["lunport:sync".into()],
            audience: Some("api".into()),
        };
        let profile = Profile::new(&server.url(), &cfg.issuer, "subject").unwrap();
        let now = env.now();
        let register = server
            .mock("POST", "/v2/session")
            .match_header("authorization", "Bearer SYNTHETIC-ACCESS")
            .with_header("content-type", "application/json")
            .with_body(
                json!({"account_id":"a".repeat(64),"account_locator":profile.locator,
                "device_state":"pending","auth_epoch":1,"expires_at_ms":now+300000})
                .to_string(),
            )
            .expect(1)
            .create();
        let view=server.mock("GET","/v2/account").with_header("content-type","application/json")
            .with_body(json!({"account_id":"a".repeat(64),"device_state":"pending","auth_epoch":1,"phase":"ready","proof":null,
                "genesis_hash":null,"pairing_confirmation":null}).to_string()).expect(1).create();
        record_runtime::mutate_records(&env,|s|repo::create_host(s,"0000000000000001",HostScope::Local,
            serde_json::from_value(json!({"schema":2,"alias":"local","hostname":"fixture.invalid","auth":"password"})).unwrap(),1).map_err(|e|AppError::Other(e.to_string()))).unwrap();
        let before = record_runtime::snapshot(&env).unwrap().0;
        let result = establish(
            &env,
            &server.url(),
            cfg.clone(),
            tokens(&cfg, "subject"),
            None,
        )
        .unwrap();
        assert_eq!(result.phase, "setup");
        assert!(!result.can_sync);
        assert!(result.has_session);
        let (after, generation) = record_runtime::snapshot(&env).unwrap();
        assert_eq!(before.local.hosts, after.local.hosts);
        assert!(after.account.is_none());
        assert!(after
            .local
            .central
            .as_ref()
            .unwrap()
            .control
            .anchor
            .is_none());
        let public =
            serde_json::to_string(&after).unwrap() + &serde_json::to_string(&result).unwrap();
        assert!(!public.contains("SYNTHETIC-ACCESS"));
        assert!(!public.contains("SYNTHETIC-REFRESH"));
        let context = context(&env).unwrap();
        let identity = context.identity.as_ref().unwrap();
        assert!(!public.contains(identity.credential()));
        assert!(!public.contains(&*identity.keys.encode_secret()));
        assert!(establish(
            &env,
            &server.url(),
            cfg.clone(),
            tokens(&cfg, "another-subject"),
            None
        )
        .is_err());
        assert_eq!(
            record_runtime::snapshot(&env).unwrap(),
            (after.clone(), generation)
        );
        // Even a pre-root pending identity is not silently replaced if its OS credential is lost.
        let public_device = after.local.central.as_ref().unwrap().control.device.clone();
        env.keychain.delete(&profile.slot("device")).unwrap();
        let result = establish(
            &env,
            &server.url(),
            cfg.clone(),
            tokens(&cfg, "subject"),
            None,
        )
        .unwrap();
        assert!(result.needs_recovery);
        assert!(!result.has_session);
        assert_eq!(
            record_runtime::snapshot(&env)
                .unwrap()
                .0
                .local
                .central
                .as_ref()
                .unwrap()
                .control
                .device,
            public_device
        );
        assert!(env.keychain.get(&profile.slot("device")).unwrap().is_none());
        register.assert();
        view.assert();
    }
    #[test]
    fn cancellation_during_the_final_account_response_prevents_late_state_publication() {
        let d = Arc::new(device());
        let env = d.env();
        let mut server = mockito::Server::new();
        let cfg = OidcConfig {
            issuer: "https://identity.test".into(),
            client_id: "native".into(),
            scopes: vec![],
            audience: Some("api".into()),
        };
        let profile = Profile::new(&server.url(), &cfg.issuer, "subject").unwrap();
        let now = env.now();
        server.mock("POST","/v2/session").with_header("content-type","application/json").with_body(
            serde_json::json!({"account_id":"a".repeat(64),"account_locator":profile.locator,"device_state":"pending","auth_epoch":1,"expires_at_ms":now+300000}).to_string()).create();
        let cancelled = Arc::clone(&d);
        server.mock("GET","/v2/account").with_header("content-type","application/json").with_body_from_request(move |_| {
            cancelled.runtime.central_login.lock().unwrap().take();
            serde_json::json!({"account_id":"a".repeat(64),"device_state":"pending","auth_epoch":1,"phase":"ready","proof":null,"genesis_hash":null,"pairing_confirmation":null}).to_string().into_bytes()
        }).create();
        *d.runtime.central_login.lock().unwrap() = Some(("operation".into(), None));
        let before = record_runtime::snapshot(&env).unwrap();
        assert!(establish(
            &env,
            &server.url(),
            cfg.clone(),
            tokens(&cfg, "subject"),
            Some("operation")
        )
        .is_err());
        assert_eq!(record_runtime::snapshot(&env).unwrap(), before);
        assert!(context(&env).is_err());
    }
    #[test]
    fn renewing_an_expired_pairing_keeps_a_late_committed_approval_usable() {
        use super::super::{
            crypto::DeviceKeys,
            membership::{Action, Genesis, SignedMembership},
            pairing::{tests::minima, PairingInvite},
            trust::ControlProof,
        };
        let d = device();
        let env = d.env();
        let profile =
            Profile::new("https://relay.test", "https://identity.test", "opaque").unwrap();
        let identity = DeviceIdentity::load_or_create(env.keychain, &profile, true).unwrap();
        let first = DeviceKeys::generate().unwrap();
        let recovery = DeviceKeys::generate().unwrap();
        let (genesis, anchor) = Genesis::create(
            &profile.origin,
            &"a".repeat(64),
            &"f".repeat(32),
            &first,
            &recovery,
        )
        .unwrap();
        let trusted = genesis.trust(&anchor).unwrap();
        let original = pending_pairing(&env, &profile, &identity, &anchor).unwrap();
        let invite = PairingInvite::from_code(
            &original.code().unwrap(),
            original.request(),
            &anchor,
            env.now(),
        )
        .unwrap();
        let mut members = trusted.devices().clone();
        members.insert(identity.id.clone(), identity.keys.public());
        let node = SignedMembership::sign(
            trusted.proposal(
                &"f".repeat(32),
                Action::Add,
                Some(original.request().clone()),
                members,
                trusted.recovery().clone(),
                env.now(),
            ),
            &first,
        )
        .unwrap();
        let confirmation = invite
            .confirm(&trusted, &node, &"c".repeat(64), minima(trusted.head()))
            .unwrap();
        let expires = super::super::wire::number(&original.request().expires_at_ms, false).unwrap();
        d.clock.advance(expires.saturating_sub(env.now()) + 10);
        let renewed = pending_pairing(&env, &profile, &identity, &anchor).unwrap();
        assert_ne!(renewed.request().request_id, original.request().request_id);
        let retained =
            load_pairing(&env, &profile, &identity, &original.request().request_id).unwrap();
        assert_eq!(
            retained.encode_secret().unwrap().as_str(),
            original.encode_secret().unwrap().as_str()
        );
        assert_eq!(
            load_pairing(&env, &profile, &identity, &renewed.request().request_id)
                .unwrap()
                .request(),
            renewed.request()
        );
        let state = State::new(
            ProfileData {
                origin: profile.origin.clone(),
                issuer: profile.issuer.clone(),
                subject: profile.subject.clone(),
                locator: profile.locator.clone(),
                login: crate::sync::central::authentication::Config::Oidc(OidcConfig {
                    issuer: profile.issuer.clone(),
                    client_id: "native".into(),
                    scopes: vec![],
                    audience: Some("api".into()),
                }),
            },
            anchor.account_id.clone(),
            identity.device(),
            2,
        )
        .unwrap()
        .begin_pairing(&original)
        .unwrap();
        let accepted = state
            .accept_pairing(
                &retained,
                &confirmation,
                ControlProof {
                    genesis,
                    nodes: vec![node],
                },
            )
            .unwrap();
        assert_eq!(accepted.anchor.as_ref(), Some(&anchor));
        assert_eq!(accepted.phase, Phase::Enrolled);
    }
    #[test]
    fn failed_retained_pairing_readback_preserves_the_only_original_secret() {
        use super::super::{crypto::DeviceKeys, membership::Genesis};
        use crate::sync::env::Keychain;
        struct Lost<'a> {
            source: &'a dyn Keychain,
            retained: String,
        }
        impl Keychain for Lost<'_> {
            fn get(&self, key: &str) -> Result<Option<String>, AppError> {
                if key == self.retained {
                    Ok(None)
                } else {
                    self.source.get(key)
                }
            }
            fn set(&self, key: &str, value: &str) -> Result<(), AppError> {
                if key == self.retained {
                    Ok(())
                } else {
                    self.source.set(key, value)
                }
            }
            fn delete(&self, _: &str) -> Result<(), AppError> {
                panic!("pairing renewal must not delete proof")
            }
        }
        let d = device();
        let profile =
            Profile::new("https://relay.test", "https://identity.test", "opaque").unwrap();
        let identity = DeviceIdentity::load_or_create(&d.keychain, &profile, true).unwrap();
        let (_, anchor) = Genesis::create(
            &profile.origin,
            &"a".repeat(64),
            &"f".repeat(32),
            &DeviceKeys::generate().unwrap(),
            &DeviceKeys::generate().unwrap(),
        )
        .unwrap();
        let original = pending_pairing(&d.env(), &profile, &identity, &anchor).unwrap();
        let encoded = d.keychain.get(&profile.slot("pairing")).unwrap();
        let expiry = super::super::wire::number(&original.request().expires_at_ms, false).unwrap();
        d.clock.advance(expiry.saturating_sub(d.env().now()) + 10);
        let lost = Lost {
            source: &d.keychain,
            retained: profile.slot("pairing-retained"),
        };
        let env = SyncEnv {
            keychain: &lost,
            ..d.env()
        };
        assert!(pending_pairing(&env, &profile, &identity, &anchor).is_err());
        assert_eq!(d.keychain.get(&profile.slot("pairing")).unwrap(), encoded);
    }
}
