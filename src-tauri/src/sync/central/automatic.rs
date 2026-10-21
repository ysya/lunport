//! One explicit sign-in-and-sync consent, then bounded automatic setup/adoption and ordinary sync.
use super::{
    client_state::Phase,
    controller::{self, Status},
    wire::invalid,
};
use crate::{
    error::AppError,
    sync::{env::SyncEnv, record_runtime},
};
use serde::{Deserialize, Serialize};
#[derive(Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Consent {
    version: u32,
    origin: String,
    account: String,
    device: String,
}
fn consent_for(owner: &super::workspace::Workspace) -> Consent {
    Consent {
        version: 1,
        origin: owner.control.profile.origin.clone(),
        account: owner.control.account_id.clone(),
        device: owner.control.device.id.clone(),
    }
}
fn permitted(env: &SyncEnv, owner: &super::workspace::Workspace) -> Result<bool, AppError> {
    let profile = owner.control.profile.profile()?;
    let Some(encoded) = env
        .keychain
        .get_noninteractive(&profile.slot("automatic-sync"))?
    else {
        return Ok(false);
    };
    if encoded.len() > 2048 {
        return Err(invalid());
    }
    let saved: Consent = serde_json::from_str(&encoded).map_err(|_| invalid())?;
    Ok(saved == consent_for(owner))
}
/// Called only after the user chooses Sign in and sync. Never implied by opening Settings.
pub(crate) fn start(env: &SyncEnv) -> Result<Progress, AppError> {
    {
        let _life = env.runtime.lifecycle.lock().unwrap();
        super::unlock_flow::cancel(env);
        let session = controller::context(env)?;
        let info = super::api::Api::new(&session.profile.origin)?.info()?;
        if !info.features.iter().any(|f| f == "account-unlock-v1") {
            return Err(AppError::Other(
                "Update your sync server to enable automatic encrypted sync.".into(),
            ));
        }
        let state = record_runtime::snapshot(env)?.0;
        let owner = state.local.central.as_ref().ok_or_else(invalid)?;
        let profile = owner.control.profile.profile()?;
        let consent = consent_for(owner);
        let encoded = serde_json::to_string(&consent).map_err(|_| invalid())?;
        env.keychain
            .set(&profile.slot("automatic-sync"), &encoded)?;
        if env
            .keychain
            .get(&profile.slot("automatic-sync"))?
            .as_deref()
            != Some(&encoded)
        {
            return Err(invalid());
        }
        record_runtime::mutate_records(env, |records| {
            if records.local.central.as_ref() != Some(owner) {
                return Err(crate::sync::runtime::superseded());
            }
            let mut next = records.clone();
            next.local
                .central
                .as_mut()
                .ok_or_else(invalid)?
                .automatic_sync = true;
            Ok(next)
        })?;
    }
    env.events.wake();
    status(env)
}
#[derive(Serialize)]
pub(crate) struct Progress {
    pub phase: &'static str,
    pub status: Status,
}
pub(crate) fn status(env: &SyncEnv) -> Result<Progress, AppError> {
    let status = controller::status(env)?;
    let phase = if !status.configured || status.phase == "signed_out" {
        "signed_out"
    } else if status.needs_recovery {
        "needs_attention"
    } else if super::unlock_flow::active(env) {
        "connecting"
    } else if !status.has_session {
        "sign_in_required"
    } else {
        match status.phase.as_str() {
            "setup" | "backup_required" => "password_setup",
            "awaiting_approval" => "password_unlock",
            "enrolled" => "syncing",
            "active" => "ready",
            _ => "needs_attention",
        }
    };
    Ok(Progress { phase, status })
}
pub(crate) fn password(env: &SyncEnv, password: &str) -> Result<Progress, AppError> {
    let current = controller::status(env)?;
    if !current.has_session {
        return Err(AppError::Other("Sign in before unlocking sync.".into()));
    }
    match current.phase.as_str() {
        "setup" => {
            if password.chars().count() < 12 || password.len() > 1024 {
                return Err(AppError::Other(
                    "Use at least 12 characters for your sync unlock password.".into(),
                ));
            }
            let prepared = super::bootstrap::prepare(env)?;
            super::bootstrap::confirm_password(
                env,
                prepared.root_fingerprint.as_deref().ok_or_else(invalid)?,
                password,
            )?;
        }
        "backup_required" => {
            super::bootstrap::confirm_password(
                env,
                current.root_fingerprint.as_deref().ok_or_else(invalid)?,
                password,
            )?;
        }
        "awaiting_approval" => super::unlock_flow::begin_password(env, password)?,
        _ => return Err(invalid()),
    }
    env.events.wake();
    status(env)
}
pub(crate) fn step(env: &SyncEnv) -> Result<Progress, AppError> {
    super::round::sync_once(env)?;
    status(env)
}
pub(super) fn background(
    env: &SyncEnv,
    report: &mut super::round::Report,
) -> Result<bool, AppError> {
    if super::unlock_flow::active(env) {
        report.more = super::unlock_flow::advance(env)?;
        if !report.more {
            super::joining::initialize(env)?;
            report.more = true;
        }
        return Ok(true);
    }
    let state = record_runtime::snapshot(env)?.0;
    let Some(owner) = state.local.central.as_ref() else {
        return Ok(false);
    };
    if !owner.automatic_sync
        || owner.control.phase != Phase::Enrolled
        || owner.control.cutover
        || !permitted(env, owner)?
    {
        return Ok(false);
    }
    if owner.replacement.is_some()
        || owner.recovery.is_some()
        || state.account.is_some()
        || !owner.replacement_archives.is_empty()
    {
        return Err(AppError::Other(
            "Automatic setup requires a fresh sync workspace.".into(),
        ));
    }
    // Restore or renew the OS-protected session before resuming an interrupted first sync.
    if !controller::resume(env, false)? {
        return Ok(true);
    }
    super::joining::initialize(env)?;
    super::migration_flow::automatic_background(env, report)?;
    Ok(true)
}
