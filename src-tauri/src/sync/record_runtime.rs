//! Active records startup and persistence; runtime state stays under the existing SyncCore.

use crate::error::AppError;
use crate::sync::records_v3::{
    decode_state, validate_state, DecodedState, RecordValidationError, SyncStateV3, STATE_VERSION,
};
use crate::sync::state_v2::SyncStateV2;
use serde::{Deserialize, Serialize};
use std::fs::{self, OpenOptions};
use std::io::{ErrorKind, Read};
use std::path::Path;

pub const MAX_STATE_BYTES: u64 = 64 * 1024 * 1024;
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RuntimeFormat {
    #[default]
    Legacy,
    Records,
    Blocked,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StartupErrorKind {
    Io,
    UnsupportedVersion,
    InvalidData,
    TooLarge,
    UnsafePath,
    Identity,
}
#[derive(Clone, Debug, PartialEq)]
pub enum StartupProbe {
    Records {
        state: Box<SyncStateV3>,
        fresh: bool,
    },
    Legacy {
        state: DecodedState,
    },
    Blocked {
        kind: StartupErrorKind,
        reason: String,
    },
}
fn blocked(kind: StartupErrorKind, reason: impl Into<String>) -> StartupProbe {
    StartupProbe::Blocked {
        kind,
        reason: reason.into(),
    }
}
fn fresh_records(device_name: &str) -> Result<SyncStateV3, AppError> {
    // Construction only: no legacy loader, saver or upgrade may run here.
    let identity = SyncStateV2::fresh(device_name)?;
    Ok(SyncStateV3 {
        version: STATE_VERSION,
        device_id: identity.device_id,
        device_name: identity.device_name,
        relay_url: identity.relay_url,
        account: None,
        spaces: Default::default(),
        local: Default::default(),
        rotation: None,
        migration_gate: None,
        shared_writes_blocked: false,
        pending_account: None,
        relay_features: None,
        legacy_v1_backup: None,
        phrase_cleanup_pending: false,
        notices: vec![],
        last_sync_ms: None,
        last_error: None,
    })
}
/// Inspect bounded bytes only. A missing file does not create a directory, state or credential.
pub fn probe_startup(path: &Path, device_name: &str) -> StartupProbe {
    // Applying the existing profile boundary is read-only and prevents a redirected dev state path.
    if crate::fsutil::check_write(path).is_err() {
        return blocked(
            StartupErrorKind::UnsafePath,
            "sync state path is outside this profile",
        );
    }
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == ErrorKind::NotFound => {
            return match fresh_records(device_name) {
                Ok(state) => StartupProbe::Records {
                    state: Box::new(state),
                    fresh: true,
                },
                Err(_) => blocked(
                    StartupErrorKind::Identity,
                    "cannot create a new device identity",
                ),
            };
        }
        Err(error) => {
            return blocked(
                StartupErrorKind::Io,
                format!("cannot inspect sync state: {error}"),
            )
        }
    };
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        return blocked(
            StartupErrorKind::UnsafePath,
            "sync state must be a regular file",
        );
    }
    if metadata.len() > MAX_STATE_BYTES {
        return blocked(
            StartupErrorKind::TooLarge,
            "sync state exceeds the supported size limit",
        );
    }
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        // Refuse a replaced symlink and do not block if a regular file was replaced by a FIFO.
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    let file = match options.open(path) {
        Ok(file) => file,
        Err(error) => {
            return blocked(
                StartupErrorKind::Io,
                format!("cannot open sync state: {error}"),
            )
        }
    };
    let opened = match file.metadata() {
        Ok(metadata) => metadata,
        Err(error) => {
            return blocked(
                StartupErrorKind::Io,
                format!("cannot inspect opened sync state: {error}"),
            )
        }
    };
    if !opened.is_file() {
        return blocked(
            StartupErrorKind::UnsafePath,
            "sync state must be a regular file",
        );
    }
    if opened.len() > MAX_STATE_BYTES {
        return blocked(
            StartupErrorKind::TooLarge,
            "sync state exceeds the supported size limit",
        );
    }
    let mut bytes = Vec::new();
    if let Err(error) = file.take(MAX_STATE_BYTES + 1).read_to_end(&mut bytes) {
        return blocked(
            StartupErrorKind::Io,
            format!("cannot read sync state: {error}"),
        );
    }
    if bytes.len() as u64 > MAX_STATE_BYTES {
        return blocked(
            StartupErrorKind::TooLarge,
            "sync state exceeds the supported size limit",
        );
    }
    let text = match std::str::from_utf8(&bytes) {
        Ok(text) => text,
        Err(_) => {
            return blocked(
                StartupErrorKind::InvalidData,
                "sync state is not valid UTF-8; original file retained",
            )
        }
    };
    match decode_state(text) {
        Ok(DecodedState::V3(state)) => StartupProbe::Records {
            state,
            fresh: false,
        },
        Ok(state) => StartupProbe::Legacy { state },
        Err(RecordValidationError::UnsupportedSchema { found, .. }) => blocked(
            StartupErrorKind::UnsupportedVersion,
            format!(
                "sync state has an unsupported format (version {found}); original file retained"
            ),
        ),
        Err(_) => blocked(
            StartupErrorKind::InvalidData,
            "sync state is malformed; original file retained",
        ),
    }
}
/// Shape validation allows valid remote relationship conflicts to remain available for repair.
pub fn save_active(path: &Path, state: &SyncStateV3) -> Result<(), AppError> {
    validate_state(state)
        .map_err(|_| AppError::Other("cannot save invalid record state".into()))?;
    let bytes = serde_json::to_vec_pretty(state)
        .map_err(|_| AppError::Other("cannot serialize record state".into()))?;
    if bytes.len() as u64 > MAX_STATE_BYTES {
        return Err(AppError::Other(
            "record state exceeds the supported size limit".into(),
        ));
    }
    match fs::symlink_metadata(path) {
        Ok(metadata) if !metadata.is_file() || metadata.file_type().is_symlink() => {
            return Err(AppError::Other("sync state must be a regular file".into()));
        }
        Err(error) if error.kind() != ErrorKind::NotFound => return Err(error.into()),
        _ => {}
    }
    if state.version >= crate::sync::records_v3::GROUP_STATE_VERSION && path.exists() {
        use sha2::{Digest, Sha256};
        let mut options = OpenOptions::new();
        options.read(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
        }
        let file = options.open(path)?;
        if !file.metadata()?.is_file() {
            return Err(AppError::Other("sync source must be a regular file".into()));
        }
        let mut source = Vec::new();
        file.take(MAX_STATE_BYTES + 1).read_to_end(&mut source)?;
        let value: serde_json::Value = serde_json::from_slice(&source)
            .map_err(|_| AppError::Other("cannot read format upgrade source".into()))?;
        if let Some(source_version) = value
            .get("version")
            .and_then(serde_json::Value::as_u64)
            .filter(|v| *v >= 3 && *v < state.version as u64)
        {
            let digest = format!("{:x}", Sha256::digest(&source));
            let backup =
                path.with_file_name(format!("sync-state-v{source_version}-{digest}.backup.json"));
            match fs::symlink_metadata(&backup) {
                Ok(meta) if !meta.is_file() || meta.file_type().is_symlink() => {
                    return Err(AppError::Other(
                        "format backup must be a regular file".into(),
                    ))
                }
                Ok(_) => {
                    if fs::read(&backup)? != source {
                        return Err(AppError::Other(
                            "format backup does not match source".into(),
                        ));
                    }
                }
                Err(e) if e.kind() == ErrorKind::NotFound => {
                    crate::fsutil::atomic_write(&backup, &source, 0o600)?
                }
                Err(e) => return Err(e.into()),
            }
        }
    }
    crate::fsutil::atomic_write(path, &bytes, 0o600)
}

/// Startup only, or after the caller acquires lifecycle/vault/publication before core for migration.
pub fn activate_probe(
    core: &mut crate::sync::runtime::SyncCore,
    probe: StartupProbe,
) -> Result<(), AppError> {
    match &probe {
        StartupProbe::Records { state, .. } => validate_state(state)
            .map_err(|_| AppError::Other("cannot activate invalid record state".into()))?,
        StartupProbe::Legacy {
            state: DecodedState::V3(_),
        } => return Err(AppError::Other("invalid legacy startup selection".into())),
        _ => {}
    }
    let generation = core
        .generation
        .checked_add(1)
        .ok_or_else(|| AppError::Other("sync state generation exhausted".into()))?;
    core.state = None;
    core.records = None;
    core.legacy = None;
    core.account_keys = None;
    core.save_blocked = None;
    core.unsaved = false;
    core.swap_pending = false;
    core.swap_failures = 0;
    core.conflict_streak = 0;
    core.failed_rounds = 0;
    core.batch_failures = 0;
    core.relay_checked = None;
    core.rounds = 0;
    core.legacy_paused = true;
    core.generation = generation;
    match probe {
        StartupProbe::Records { state, .. } => {
            core.format = RuntimeFormat::Records;
            core.records = Some(*state);
        }
        StartupProbe::Legacy {
            state: DecodedState::V1(state),
        } => {
            core.format = RuntimeFormat::Legacy;
            core.legacy = Some(*state);
        }
        StartupProbe::Legacy {
            state: DecodedState::V2(state),
        } => {
            core.format = RuntimeFormat::Legacy;
            core.state = Some(*state);
        }
        StartupProbe::Blocked { reason, .. } => {
            core.format = RuntimeFormat::Blocked;
            core.save_blocked = Some(reason);
        }
        StartupProbe::Legacy {
            state: DecodedState::V3(_),
        } => unreachable!("validated startup selection"),
    }
    Ok(())
}
pub(crate) fn active_state(
    core: &crate::sync::runtime::SyncCore,
) -> Result<&SyncStateV3, AppError> {
    if core.format != RuntimeFormat::Records {
        return Err(AppError::Other(
            core.save_blocked
                .clone()
                .unwrap_or_else(|| "record workspace is not active".into()),
        ));
    }
    if core.state.is_some() || core.legacy.is_some() {
        return Err(AppError::Other(
            "record runtime contains legacy state".into(),
        ));
    }
    core.records
        .as_ref()
        .ok_or_else(|| AppError::Other("record workspace is not initialized".into()))
}
fn writes_allowed(core: &crate::sync::runtime::SyncCore) -> Result<(), AppError> {
    if let Some(reason) = &core.save_blocked {
        return Err(AppError::Other(reason.clone()));
    }
    active_state(core)?;
    Ok(())
}
pub fn snapshot(env: &crate::sync::env::SyncEnv) -> Result<(SyncStateV3, u64), AppError> {
    let core = env.runtime.core.lock().unwrap();
    Ok((active_state(&core)?.clone(), core.generation))
}
fn persist_candidate(
    core: &mut crate::sync::runtime::SyncCore,
    path: &Path,
    mut candidate: SyncStateV3,
) -> Result<u64, AppError> {
    writes_allowed(core)?;
    if candidate.version == STATE_VERSION && crate::sync::record_groups::has_group_data(&candidate)
    {
        candidate.version = crate::sync::records_v3::GROUP_STATE_VERSION;
    }
    candidate = crate::sync::record_library::include_new_records(candidate, core.account_keys.as_ref());
    if crate::sync::group_order::has_navigation_data(&candidate) {
        candidate.version = candidate.version.max(crate::sync::records_v3::NAVIGATION_STATE_VERSION);
    }
    if let Some(before) = core.records.as_ref() {
        candidate = crate::sync::record_groups::invalidate_changed_pins(before, candidate)
            .map_err(|e| AppError::Other(e.to_string()))?;
    }
    crate::sync::record_conflicts::upgrade_state(&mut candidate);
    let generation = core
        .generation
        .checked_add(1)
        .ok_or_else(|| AppError::Other("sync state generation exhausted".into()))?;
    save_active(path, &candidate)?;
    // Key loading belongs outside core. An account change must not keep keys from the prior chain.
    if core.account_keys.as_ref().is_some_and(|keys| {
        candidate
            .account
            .as_ref()
            .map(|account| account.chain_id.as_str())
            != Some(keys.chain_id.as_str())
    }) {
        core.account_keys = None;
    }
    core.records = Some(candidate);
    core.generation = generation;
    core.unsaved = false;
    Ok(generation)
}
/// Core only: safe while a caller already owns lifecycle/vault/publication. Never reacquire them here.
pub fn commit_candidate(
    env: &crate::sync::env::SyncEnv,
    expected_generation: u64,
    candidate: SyncStateV3,
) -> Result<u64, AppError> {
    let mut core = env.runtime.core.lock().unwrap();
    writes_allowed(&core)?;
    if core.generation != expected_generation {
        return Err(crate::sync::runtime::superseded());
    }
    persist_candidate(&mut core, &env.state_path, candidate)
}
/// Explicit workspace pause is memory-only; it never loads credentials, upgrades, or saves sources.
pub fn pause_legacy_workspace(env: &crate::sync::env::SyncEnv) -> Result<(), AppError> {
    let _lifecycle = env.runtime.lifecycle.lock().unwrap();
    let _publication = env.runtime.format_publication.lock().unwrap();
    let _doc = env.doc.lock().unwrap();
    let mut core = env.runtime.core.lock().unwrap();
    if core.format != RuntimeFormat::Legacy || core.save_blocked.is_some() || core.unsaved {
        return Err(AppError::Other(
            "the legacy workspace must be durable and available before pausing".into(),
        ));
    }
    if core.legacy_paused {
        return Ok(());
    }
    let generation = core
        .generation
        .checked_add(1)
        .ok_or_else(|| AppError::Other("sync state generation exhausted".into()))?;
    core.legacy_paused = true;
    core.generation = generation;
    Ok(())
}
/// Caller owns lifecycle -> vault -> publication; this method takes the final Doc -> Core barrier.
pub fn commit_migration_candidate(
    env: &crate::sync::env::SyncEnv,
    expected_generation: u64,
    mut candidate: SyncStateV3,
    keys: Option<crate::sync::crypto::ChainKeys>,
) -> Result<u64, AppError> {
    let mut doc = env.doc.lock().unwrap();
    let mut core = env.runtime.core.lock().unwrap();
    if core.generation != expected_generation {
        return Err(crate::sync::runtime::superseded());
    }
    if core.format == RuntimeFormat::Blocked || core.save_blocked.is_some() {
        return Err(AppError::Other(
            "migration activation is blocked on this device".into(),
        ));
    }
    if core.format == RuntimeFormat::Legacy && !core.legacy_paused {
        return Err(AppError::Other(
            "pause the legacy workspace before migration activation".into(),
        ));
    }
    if keys.as_ref().is_some_and(|keys| {
        candidate.account.as_ref().map(|a| a.chain_id.as_str()) != Some(keys.chain_id.as_str())
    }) {
        return Err(AppError::Other(
            "migration account identity does not match its keys".into(),
        ));
    }
    core.generation
        .checked_add(1)
        .ok_or_else(|| AppError::Other("sync state generation exhausted".into()))?;
    if crate::sync::group_order::has_navigation_data(&candidate) {
        candidate.version = candidate.version.max(crate::sync::records_v3::NAVIGATION_STATE_VERSION);
    }
    save_active(&env.state_path, &candidate)?;
    activate_probe(
        &mut core,
        StartupProbe::Records {
            state: Box::new(candidate),
            fresh: false,
        },
    )?;
    core.account_keys = keys;
    *doc = None;
    Ok(core.generation)
}
/// The transform must be pure: no clock, credentials, network or event callbacks under core.
/// Apply prepared overlays to the latest state here; disk failure preserves the original core.
pub fn mutate_records(
    env: &crate::sync::env::SyncEnv,
    transform: impl FnOnce(&SyncStateV3) -> Result<SyncStateV3, AppError>,
) -> Result<u64, AppError> {
    let mut core = env.runtime.core.lock().unwrap();
    writes_allowed(&core)?;
    let candidate = transform(active_state(&core)?)?;
    persist_candidate(&mut core, &env.state_path, candidate)
}
/// Call outside runtime locks; current mnemonic only, no staged-code promotion or cleanup.
pub fn read_account_keys(
    state: &SyncStateV3,
    keychain: &dyn crate::sync::env::Keychain,
) -> Result<Option<crate::sync::crypto::ChainKeys>, AppError> {
    validate_state(state)
        .map_err(|_| AppError::Other("cannot read keys for invalid record state".into()))?;
    let Some(account) = &state.account else {
        return Ok(None);
    };
    let phrase = keychain
        .get(crate::sync::state::MNEMONIC_ACCOUNT)
        .map_err(|_| AppError::Other("the sync code could not be read".into()))?
        .ok_or_else(|| AppError::Other("the sync code is unavailable on this device".into()))?;
    let keys = crate::sync::crypto::derive_account(&phrase)
        .map_err(|_| AppError::Other("the sync code is invalid".into()))?;
    if keys.chain_id != account.chain_id {
        return Err(AppError::Other(
            "the sync code belongs to a different account".into(),
        ));
    }
    Ok(Some(keys))
}

#[cfg(test)]
#[path = "record_runtime_tests/mod.rs"]
mod tests;
