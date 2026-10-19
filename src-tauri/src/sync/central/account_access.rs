//! IdP-only account management metadata. It confers no Vault membership or decryption authority.
use super::{
    api::Api,
    controller, round,
    wire::{hex, invalid, MAX_SAFE_INTEGER},
};
use crate::{
    error::AppError,
    sync::{env::SyncEnv, record_runtime},
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RemoteDevice {
    id: String,
    name: String,
    created_at_ms: u64,
    state: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RemoteAccess {
    account_locator: String,
    auth_epoch: u64,
    barrier_pending: bool,
    devices: Vec<RemoteDevice>,
}
#[derive(Serialize)]
pub struct Device {
    pub id: String,
    pub name: String,
    pub created_at_ms: String,
    pub state: String,
    pub current: bool,
}
#[derive(Serialize)]
pub struct Registry {
    pub authorization_epoch: String,
    pub barrier_pending: bool,
    pub devices: Vec<Device>,
}
pub fn registry(env: &SyncEnv) -> Result<Registry, AppError> {
    controller::require_enabled()?;
    round::check_cooldown(env)?;
    let _lifecycle = env.runtime.lifecycle.lock().unwrap();
    let current = record_runtime::snapshot(env)?
        .0
        .local
        .central
        .ok_or_else(invalid)?;
    let session = controller::context(env)?;
    if session.profile != current.control.profile {
        return Err(invalid());
    }
    if session
        .tokens_started
        .elapsed()
        .saturating_add(std::time::Duration::from_secs(5))
        >= session.tokens.expires_in
    {
        return Err(AppError::Other(
            "Sign in again to manage account access.".into(),
        ));
    }
    fetch(env, &current, &session.tokens)
}
fn fetch(
    env: &SyncEnv,
    current: &super::workspace::Workspace,
    tokens: &super::oidc::LoginTokens,
) -> Result<Registry, AppError> {
    let profile = current.control.profile.profile()?;
    let reply = Api::new(&profile.origin)?.device_access(&profile, tokens)?;
    round::require_success(env, &reply)?;
    let remote: RemoteAccess = reply.decode()?;
    let mut seen = BTreeSet::new();
    if remote.account_locator != profile.locator
        || remote.auth_epoch < current.control.auth_epoch
        || remote.auth_epoch > MAX_SAFE_INTEGER
        || remote.devices.len() > 128
        || remote.devices.iter().any(|d| {
            !hex(&d.id, 32)
                || !seen.insert(&d.id)
                || d.name.len() > 80
                || d.name.chars().any(char::is_control)
                || d.created_at_ms == 0
                || d.created_at_ms > MAX_SAFE_INTEGER
                || !["active", "pending", "revoked"].contains(&d.state.as_str())
        })
    {
        return Err(invalid());
    }
    // This endpoint intentionally has no signed root proof. Its labels are service metadata,
    // never a replacement for anchored membership, denial pins, keys or local trust highwaters.
    Ok(Registry {
        authorization_epoch: remote.auth_epoch.to_string(),
        barrier_pending: remote.barrier_pending,
        devices: remote
            .devices
            .into_iter()
            .map(|d| Device {
                current: d.id == current.control.device.id,
                id: d.id,
                name: d.name,
                created_at_ms: d.created_at_ms.to_string(),
                state: d.state,
            })
            .collect(),
    })
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Selection {
    pub device: String,
    pub authorization_epoch: String,
    pub created_at_ms: String,
}
pub struct Prepared {
    pub(super) profile: super::client_state::ProfileData,
    account: String,
    anchor: Option<super::membership::TrustAnchor>,
    device: String,
    selection: Selection,
}
fn selected(registry: &Registry, selection: &Selection) -> Result<(), AppError> {
    if !hex(&selection.device, 32)
        || super::wire::number(&selection.authorization_epoch, false)? == 0
        || super::wire::number(&selection.created_at_ms, false)? == 0
        || registry.authorization_epoch != selection.authorization_epoch
        || !registry
            .devices
            .iter()
            .any(|d| d.id == selection.device && d.created_at_ms == selection.created_at_ms)
    {
        return Err(AppError::Other(
            "The selected account device changed. Refresh the device list before revoking access."
                .into(),
        ));
    }
    Ok(())
}
pub fn prepare_revoke(env: &SyncEnv, selection: Selection) -> Result<Prepared, AppError> {
    controller::require_enabled()?;
    let registry = registry(env)?;
    selected(&registry, &selection)?;
    let _lifecycle = env.runtime.lifecycle.lock().unwrap();
    let current = record_runtime::snapshot(env)?
        .0
        .local
        .central
        .ok_or_else(invalid)?;
    if current.control.phase == super::client_state::Phase::SignedOut {
        return Err(invalid());
    }
    Ok(Prepared {
        profile: current.control.profile,
        account: current.control.account_id,
        anchor: current.control.anchor,
        device: current.control.device.id,
        selection,
    })
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Ack {
    access_revoked: bool,
    rekey_pending: Option<bool>,
    barrier_pending: Option<bool>,
    retry_after_seconds: Option<u64>,
}
pub fn complete_revoke(
    env: &SyncEnv,
    prepared: Prepared,
    fresh: super::oidc::FreshLoginTokens,
    operation: &str,
) -> Result<super::devices::RevokeResult, AppError> {
    controller::require_enabled()?;
    round::check_cooldown(env)?;
    let lifecycle = env.runtime.lifecycle.lock().unwrap();
    let before = record_runtime::snapshot(env)?
        .0
        .local
        .central
        .ok_or_else(invalid)?;
    if before.control.profile != prepared.profile
        || before.control.account_id != prepared.account
        || before.control.anchor != prepared.anchor
        || before.control.device.id != prepared.device
        || before.control.phase == super::client_state::Phase::SignedOut
    {
        return Err(crate::sync::runtime::superseded());
    }
    let tokens = fresh.tokens();
    let profile = prepared.profile.profile()?;
    if tokens.issuer != profile.issuer || tokens.subject != profile.subject {
        return Err(invalid());
    }
    let registry = fetch(env, &before, tokens)?;
    selected(&registry, &prepared.selection)?;
    // Cancellation wins until the fresh, bound selection is committed as durable intent. Once
    // accepted, logout waits on lifecycle; it cannot roll back an already dispatched revoke.
    let mut gate = env.runtime.central_login.lock().unwrap();
    if gate.as_ref().map(|(id, _)| id.as_str()) != Some(operation) {
        return Err(AppError::Other(
            "Account authentication was cancelled or replaced.".into(),
        ));
    }
    super::credentials::save_refresh(env.keychain, &profile, &prepared.profile.login, tokens)?;
    let public = before
        .control
        .remember_denials([prepared.selection.device.as_str()])?;
    record_runtime::mutate_records(env, |records| {
        if records.local.central.as_ref() != Some(&before) {
            return Err(crate::sync::runtime::superseded());
        }
        let mut records = records.clone();
        records.local.central.as_mut().ok_or_else(invalid)?.control = public.clone();
        Ok(records)
    })?;
    gate.take();
    drop(gate);
    let result = (|| {
        let reply = Api::new(&profile.origin)?.revoke_device_access(
            &profile,
            &fresh,
            &prepared.selection.device,
        )?;
        round::require_success(env, &reply)?;
        if ![200, 202].contains(&reply.status) {
            return Err(invalid());
        }
        let ack: Ack = reply.decode()?;
        if ack.retry_after_seconds.is_some_and(|s| s > 3600)
            || ack.access_revoked && (reply.status != 200 || ack.barrier_pending == Some(true))
        {
            return Err(invalid());
        }
        let view = fetch(env, &before, fresh.tokens())?;
        if super::wire::number(&view.authorization_epoch, false)?
            < super::wire::number(&prepared.selection.authorization_epoch, false)?
        {
            return Err(invalid());
        }
        let target = view
            .devices
            .iter()
            .find(|d| {
                d.id == prepared.selection.device
                    && d.created_at_ms == prepared.selection.created_at_ms
            })
            .ok_or_else(invalid)?;
        let confirmed = ack.access_revoked && target.state == "revoked" && !view.barrier_pending;
        Ok((
            confirmed,
            ack.rekey_pending.unwrap_or(true),
            !confirmed || view.barrier_pending,
        ))
    })();
    let identity = env
        .runtime
        .core
        .lock()
        .unwrap()
        .central_session
        .as_ref()
        .and_then(|s| s.identity.clone());
    let tokens = std::sync::Arc::new(fresh.into_tokens());
    env.runtime.core.lock().unwrap().central_session =
        Some(std::sync::Arc::new(controller::Session {
            profile: prepared.profile,
            identity,
            tokens,
            device: None,
            device_access_denied: true,
            tokens_started: std::time::Instant::now(),
        }));
    drop(lifecycle);
    env.events.status();
    // Independent of the action outcome, retain the fresh account login. A revoked/missing
    // device remains account-only; no replacement identity, root or key is invented.
    let _ = controller::refresh(env);
    let (access_revoked, rekey_pending, barrier_pending) = result?;
    Ok(super::devices::RevokeResult {
        status: controller::status(env)?,
        access_revoked,
        rekey_pending,
        barrier_pending,
    })
}
