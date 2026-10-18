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
    let profile = session.profile.profile()?;
    let reply = Api::new(&profile.origin)?.device_access(&profile, &session.tokens)?;
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
