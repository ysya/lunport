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
/// Native read-only saved-state evidence. Missing/changed/future data is never repaired here.
pub(crate) fn read_saved_records(path: &Path) -> Result<SyncStateV3, AppError> {
    let mut options = OpenOptions::new(); options.read(true);
    #[cfg(unix)] { use std::os::unix::fs::OpenOptionsExt; options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK); }
    let file = options.open(path)?;
    if !file.metadata()?.is_file() { return Err(AppError::Other("saved state must be a regular file".into())); }
    let mut bytes = Vec::new(); file.take(MAX_STATE_BYTES + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_STATE_BYTES { return Err(AppError::Other("saved state exceeds the supported limit".into())); }
    let state: SyncStateV3 = serde_json::from_slice(&bytes).map_err(|_| AppError::Other("saved state is unreadable; reload before synchronization".into()))?;
    validate_state(&state).map_err(|_| AppError::Other("saved state is invalid; reload before synchronization".into()))?;
    Ok(state)
}
/// Shape validation allows valid remote relationship conflicts to remain available for repair.
pub fn save_active(path: &Path, state: &SyncStateV3) -> Result<(), AppError> {
    save_active_with_authority(path,state,None,None)
}
struct ReplacementSave<'a> {
    authority:&'a crate::sync::central::replacement_publication::Authorization,
    archive:&'a crate::sync::central::replacement_archive::Permit,
    generation:u64,
    published:std::cell::Cell<bool>,
}
enum ProjectionAuthority<'a> {
    Library(&'a crate::sync::record_import::central_stage::Publication),
    Local(&'a crate::sync::record_import::central_local::Publication),
    Dispatch(&'a crate::sync::central::active_dispatch::Publication),
    Initial(&'a crate::sync::record_import::central_stage::InitialPublication<'a>),
}
impl ProjectionAuthority<'_> {
    fn is_initial(&self)->bool {matches!(self,Self::Initial(_))}
    fn candidate(&self) -> &SyncStateV3 {
        match self {
            Self::Library(a) => a.candidate(),
            Self::Local(a) => a.candidate(),
            Self::Dispatch(a) => a.candidate(),
            Self::Initial(a) => a.candidate(),
        }
    }
    fn generation(&self) -> u64 {
        match self {
            Self::Library(a) => a.generation(),
            Self::Local(a) => a.generation(),
            Self::Dispatch(a) => a.generation(),
            Self::Initial(a) => a.generation(),
        }
    }
    fn verify_core(&self, core: &crate::sync::runtime::SyncCore) -> Result<(), AppError> {
        match self {
            Self::Library(a) => a.verify_core(core),
            Self::Local(a) => a.verify_core(core),
            Self::Dispatch(a) => a.verify_core(core),
            Self::Initial(a) => a.verify_core(core),
        }
    }
    fn verify_records(
        &self,
        before: &SyncStateV3,
        after: &SyncStateV3,
        generation: u64,
    ) -> Result<(), AppError> {
        match self {
            Self::Library(a) => a.verify_records(before, after, generation),
            Self::Local(a) => a.verify_records(before, after, generation),
            Self::Dispatch(a) => a.verify_records(before, after, generation),
            Self::Initial(a) => a.verify_records(before, after, generation),
        }
    }
    fn verify_vault(&self, path: &Path) -> Result<(), AppError> {
        match self {
            Self::Library(a) => a.verify_vault(path),
            Self::Local(a) => a.verify_vault(path),
            Self::Dispatch(a) => a.verify_vault(path),
            Self::Initial(a) => a.verify_vault(path),
        }
    }
}
struct ProjectionSave<'a> {
    authority:ProjectionAuthority<'a>,
    published:std::cell::Cell<bool>,
}
fn save_active_with_authority(
    path: &Path,
    state: &SyncStateV3,
    replacement: Option<&ReplacementSave<'_>>,
    projection: Option<&ProjectionSave<'_>>,
) -> Result<(), AppError> {
    if replacement.is_some() && projection.is_some() {
        return Err(AppError::Other("central publication authorities cannot be combined".into()));
    }
    if projection.is_some() && !path.exists() {
        return Err(AppError::Other("The saved central projection source is missing; stage retained.".into()));
    }
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
    if replacement.is_some() && !path.exists(){return Err(AppError::Other("The archived source state is missing. Local data and identities are retained.".into()));}
    if path.exists() {
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
        let previous_version = value.get("version").and_then(serde_json::Value::as_u64).unwrap_or(0);
        let initial_projection=projection.is_some_and(|p|p.authority.is_initial());
        if replacement.is_none() && projection.is_none() && state.local.central_projection.is_some() && value.get("local").and_then(|v|v.get("central_projection")).is_none_or(|v|v.is_null()) {
            return Err(AppError::Other("First central library activation requires its verified initial publication transaction. Original data is retained.".into()));
        }
        if projection.is_some() && previous_version != u64::from(state.version) && !initial_projection {
            return Err(AppError::Other("The saved central source format changed. Source and stage are retained; reload before publishing.".into()));
        }
        if initial_projection {
            let previous:SyncStateV3=serde_json::from_value(value.clone()).map_err(|_|AppError::Other("Cannot validate initial central source.".into()))?;
            validate_state(&previous).map_err(|_|AppError::Other("Cannot validate initial central source.".into()))?;
            let authority=&projection.unwrap().authority;
            authority.verify_records(&previous,state,authority.generation())?;
            authority.verify_vault(path)?;
        } else if previous_version >= crate::sync::records_v3::CENTRAL_STATE_VERSION as u64 {
            if previous_version > state.version as u64 {
                return Err(AppError::Other("The central workspace format cannot be downgraded. Original data has been retained.".into()));
            }
            let previous: SyncStateV3 = serde_json::from_value(value.clone()).map_err(|_|AppError::Other("Cannot validate the existing central workspace. Original data has been retained.".into()))?;
            validate_state(&previous).map_err(|_|AppError::Other("Cannot validate the existing central workspace. Original data has been retained.".into()))?;
            if previous.local.central_projection != state.local.central_projection && projection.is_none() {
                return Err(AppError::Other("Central library projection needs its verified publication transaction. Original data is retained.".into()));
            }
            if let Some(replacement)=replacement {
                replacement.authority.verify_records(&previous,state,replacement.archive,replacement.generation)?;
            } else {
                crate::sync::central::workspace::verify_publication(previous.local.central.as_ref(),state.local.central.as_ref())?;
                if let Some(projection)=projection {projection.authority.verify_records(&previous,state,projection.authority.generation())?;projection.authority.verify_vault(path)?;}
            }
        }
        if let Some(source_version) = value
            .get("version")
            .and_then(serde_json::Value::as_u64)
            // The dedicated initial authority already verified the exact durable source package
            // and stage snapshot. An extra generic backup would be an unproved new source file.
            .filter(|v| !initial_projection && *v >= 3 && *v < state.version as u64)
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
    if let Some(replacement)=replacement {write_replacement_atomic(path,&bytes,state,replacement)}
    else if let Some(projection)=projection {write_central_atomic(path,&bytes,&projection.published,|previous|{projection.authority.verify_records(previous,state,projection.authority.generation())?;projection.authority.verify_vault(path)})}
    else {crate::fsutil::atomic_write(path, &bytes, 0o600)}
}
#[cfg(test)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ReplacementWriteStage { FileSync, SourceRecheck, Rename, DirectorySync }
#[cfg(test)]
type ReplacementWriteHook = Box<dyn FnMut(ReplacementWriteStage, &Path) -> Result<(), AppError>>;
#[cfg(test)]
thread_local! {
    static REPLACEMENT_WRITE_HOOK: std::cell::RefCell<Option<ReplacementWriteHook>> = const { std::cell::RefCell::new(None) };
}
#[cfg(test)]
pub(crate) fn with_replacement_write_hook<T>(hook: ReplacementWriteHook, action: impl FnOnce() -> T) -> T {
    struct Restore(Option<ReplacementWriteHook>);
    impl Drop for Restore { fn drop(&mut self) { REPLACEMENT_WRITE_HOOK.with(|value| *value.borrow_mut() = self.0.take()); } }
    let _restore = Restore(REPLACEMENT_WRITE_HOOK.with(|value| value.replace(Some(hook))));
    action()
}
#[cfg(test)]
pub(crate) fn replacement_write_stage(stage: ReplacementWriteStage, path: &Path) -> Result<(), AppError> {
    REPLACEMENT_WRITE_HOOK.with(|value| match value.borrow_mut().as_mut() { Some(hook) => hook(stage, path), None => Ok(()) })
}
/// The existing app publication gate serializes material transactions. This additionally
/// rechecks the archived source just before rename; it is not cross-process write exclusion.
fn write_replacement_atomic(path:&Path,bytes:&[u8],state:&SyncStateV3,replacement:&ReplacementSave<'_>)->Result<(),AppError>{
    write_central_atomic(path,bytes,&replacement.published,|previous|replacement.authority.verify_records(previous,state,replacement.archive,replacement.generation))
}
fn write_central_atomic(path:&Path,bytes:&[u8],published:&std::cell::Cell<bool>,verify:impl Fn(&SyncStateV3)->Result<(),AppError>)->Result<(),AppError>{
    use std::io::Write;
    crate::fsutil::check_write(path)?;
    let parent=path.parent().ok_or_else(||AppError::Other("sync state has no parent".into()))?;
    crate::fsutil::ensure_dir_secure(parent)?;
    let mut temp=tempfile::NamedTempFile::new_in(parent)?;
    #[cfg(unix)] {use std::os::unix::fs::PermissionsExt;temp.as_file().set_permissions(fs::Permissions::from_mode(0o600))?;}
    temp.write_all(bytes)?;
    #[cfg(test)] replacement_write_stage(ReplacementWriteStage::FileSync,path)?;
    temp.as_file().sync_all()?;
    #[cfg(test)] replacement_write_stage(ReplacementWriteStage::SourceRecheck,path)?;
    let mut options=OpenOptions::new();options.read(true);
    #[cfg(unix)] {use std::os::unix::fs::OpenOptionsExt;options.custom_flags(libc::O_NOFOLLOW|libc::O_NONBLOCK);}
    let source=options.open(path)?;
    if !source.metadata()?.is_file(){return Err(AppError::Other("sync source must be a regular file".into()));}
    let mut original=Vec::new();source.take(MAX_STATE_BYTES+1).read_to_end(&mut original)?;
    if original.len() as u64>MAX_STATE_BYTES{return Err(AppError::Other("sync source exceeds the supported limit".into()));}
    let previous:SyncStateV3=serde_json::from_slice(&original).map_err(|_|AppError::Other("Cannot validate archived source state.".into()))?;
    validate_state(&previous).map_err(|_|AppError::Other("Cannot validate archived source state.".into()))?;
    verify(&previous)?;
    #[cfg(test)] replacement_write_stage(ReplacementWriteStage::Rename,path)?;
    temp.persist(path).map_err(|error|AppError::Io(error.error))?;
    published.set(true);
    #[cfg(test)] replacement_write_stage(ReplacementWriteStage::DirectorySync,path)?;
    #[cfg(unix)] {fs::File::open(parent)?.sync_all()?;}
    Ok(())
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
    core.central_session = None;
    core.central_user_action = None;
    core.central_migration = None;
    core.adoption_read = None;
    core.migration_plan = None;
    core.migration_verifier = None;
    core.central_migration_frozen = false;
    core.central_poll = Default::default();
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
fn library_changed(before: &SyncStateV3, after: &SyncStateV3) -> bool {
    let mut proposed = after.clone();
    proposed.version = before.version;
    proposed.local.central = before.local.central.clone();
    &proposed != before
}

fn persist_candidate(
    core: &mut crate::sync::runtime::SyncCore,
    path: &Path,
    mut candidate: SyncStateV3,
) -> Result<u64, AppError> {
    writes_allowed(core)?;
    if core.central_migration_frozen {
        if library_changed(active_state(core)?, &candidate) {return Err(crate::sync::central::migration_flow::edit_error());}
    }
    if candidate.version == STATE_VERSION && crate::sync::record_groups::has_group_data(&candidate)
    {
        candidate.version = crate::sync::records_v3::GROUP_STATE_VERSION;
    }
    crate::sync::central::workspace::verify_publication(
        core.records.as_ref().and_then(|s| s.local.central.as_ref()),candidate.local.central.as_ref())?;
    if candidate.local.central.is_some() {
        candidate.version = candidate.version.max(crate::sync::records_v3::CENTRAL_STATE_VERSION);
    }
    // Projection receipts are replaced only by their typed publication transaction, never by
    // an ordinary local edit/account operation (including a stale snapshot without the ledger).
    if core.records.as_ref().and_then(|s|s.local.central_projection.as_ref()) != candidate.local.central_projection.as_ref() {
        return Err(AppError::Other("Central library projection needs its verified publication transaction. Local data is retained.".into()));
    }
    let central_cutover = candidate.local.central.as_ref().is_some_and(|c|c.control.cutover);
    if central_cutover && !core.records.as_ref().and_then(|s|s.local.central.as_ref()).is_some_and(|c|c.control.cutover) {
        candidate.local.credential_approvals.clear();
    }
    if !central_cutover && !core.central_migration_frozen {
        candidate = crate::sync::record_library::include_new_records(candidate, core.account_keys.as_ref());
    }
    if crate::sync::group_order::has_navigation_data(&candidate) {
        candidate.version = candidate.version.max(crate::sync::records_v3::NAVIGATION_STATE_VERSION);
    }
    if let Some(before) = core.records.as_ref() {
        candidate = crate::sync::record_groups::invalidate_changed_pins(before, candidate)
            .map_err(|e| AppError::Other(e.to_string()))?;
    }
    crate::sync::record_conflicts::upgrade_state(&mut candidate);
    if core.central_migration_frozen && library_changed(active_state(core)?, &candidate) {
        return Err(crate::sync::central::migration_flow::edit_error());
    }
    let generation = core
        .generation
        .checked_add(1)
        .ok_or_else(|| AppError::Other("sync state generation exhausted".into()))?;
    save_active(path, &candidate)?;
    // Key loading belongs outside core. An account change must not keep keys from the prior chain.
    if central_cutover || core.account_keys.as_ref().is_some_and(|keys| {
        candidate
            .account
            .as_ref()
            .map(|account| account.chain_id.as_str())
            != Some(keys.chain_id.as_str())
    }) {
        core.account_keys = None;
    }
    if core.central_session.as_ref().is_some_and(|session| {
        candidate.local.central.as_ref().is_none_or(|central| {
            central.control.profile != session.profile
                || matches!(central.control.phase,
                    crate::sync::central::client_state::Phase::SignedOut
                    | crate::sync::central::client_state::Phase::Revoked)
                || session.identity.as_ref().is_some_and(|identity| identity.device() != central.control.device)
                || session.device.as_ref().is_some_and(|s| s.account_id != central.control.account_id
                    || !crate::sync::central::controller::session_epoch_matches(&central.control, s.auth_epoch, s.device_state))
        })
    }) {
        core.central_session = None;
        core.adoption_read = None;
        core.migration_plan = None;
        core.migration_verifier = None;
    }
    core.records = Some(candidate);
    core.generation = generation;
    core.unsaved = false;
    Ok(generation)
}
/// Consume the only typed exception to ordinary central identity publication. No network,
/// credential UI, repository material writes or fallback occur while publication/Core are held.
pub(crate) fn publish_replacement(
    env:&crate::sync::env::SyncEnv,
    authority:&crate::sync::central::replacement_publication::Authorization,
    archive:crate::sync::central::replacement_archive::Permit,
)->Result<u64,AppError>{
    let _publication=env.runtime.format_publication.lock().unwrap();
    let mut core=env.runtime.core.lock().unwrap();writes_allowed(&core)?;
    let source=active_state(&core)?;
    archive.verify_source(source,core.generation)?;
    let candidate=authority.records(source,archive.receipt().clone())?;
    authority.verify_records(source,&candidate,&archive,core.generation)?;
    let generation=core.generation.checked_add(1).ok_or_else(||AppError::Other("sync generation exhausted".into()))?;
    let context=ReplacementSave{authority,archive:&archive,generation:core.generation,published:std::cell::Cell::new(false)};
    if let Err(error)=save_active_with_authority(&env.state_path,&candidate,Some(&context),None) {
        if context.published.get(){
            core.save_blocked=Some("Device replacement reached disk but durability could not be confirmed. Restart Lunport to reload the saved owner; all identities and archives are retained.".into());
            core.central_session=None;
        }
        return Err(error);
    }
    if candidate.local.central.as_ref().is_some_and(|owner|owner.control.cutover){core.account_keys=None;}
    core.records=Some(candidate);core.generation=generation;core.unsaved=false;
    core.central_session=Some(std::sync::Arc::clone(authority.session()));core.central_poll=Default::default();core.central_user_action=None;
    Ok(generation)
}
/// Typed central projection only. Caller owns lifecycle -> vault -> publication; no network or
/// protected credential operation is permitted here while the single Core is held.
pub(crate) fn publish_projection(
    env: &crate::sync::env::SyncEnv,
    authority: &crate::sync::record_import::central_stage::Publication,
) -> Result<u64, AppError> {
    publish_central_material(env, ProjectionAuthority::Library(authority))
}
pub(crate) fn publish_local_material(
    env: &crate::sync::env::SyncEnv,
    authority: &crate::sync::record_import::central_local::Publication,
) -> Result<u64, AppError> {
    publish_central_material(env, ProjectionAuthority::Local(authority))
}
pub(crate) fn publish_dispatch(
    env: &crate::sync::env::SyncEnv,
    authority: &crate::sync::central::active_dispatch::Publication,
) -> Result<u64, AppError> {
    publish_central_material(env, ProjectionAuthority::Dispatch(authority))
}
pub(in crate::sync) fn publish_initial_projection(
    env: &crate::sync::env::SyncEnv,
    authority: &crate::sync::record_import::central_stage::InitialPublication<'_>,
) -> Result<u64, AppError> {
    publish_central_material(env, ProjectionAuthority::Initial(authority))
}

fn publish_central_material(
    env: &crate::sync::env::SyncEnv,
    authority: ProjectionAuthority<'_>,
) -> Result<u64, AppError> {
    let mut core = env.runtime.core.lock().unwrap();
    writes_allowed(&core)?;
    authority.verify_core(&core)?;
    let generation = core
        .generation
        .checked_add(1)
        .ok_or_else(|| AppError::Other("sync generation exhausted".into()))?;
    let context = ProjectionSave {
        authority,
        published: std::cell::Cell::new(false),
    };
    if let Err(error) =
        save_active_with_authority(&env.state_path, context.authority.candidate(), None, Some(&context))
    {
        if context.published.get() {
            core.save_blocked=Some("Central library reached disk but durability is uncertain. Restart to reload; all source material and stages are retained.".into());
            core.central_session = None;
            core.adoption_read = None;
            core.migration_plan = None;
            core.migration_verifier = None;
        }
        return Err(error);
    }
    core.records = Some(context.authority.candidate().clone());
    core.generation = generation;
    core.unsaved = false;
    core.account_keys = None;
    Ok(generation)
}
/// Read any protected edit barrier before Core. A caller may already own lifecycle/vault/publication;
/// this method never reacquires those gates. The final generation check still owns Core.
pub fn commit_candidate(
    env: &crate::sync::env::SyncEnv,
    expected_generation: u64,
    candidate: SyncStateV3,
) -> Result<u64, AppError> {
    let before = snapshot(env)?.0;
    if library_changed(&before, &candidate) {
        crate::sync::central::migration_flow::refresh_edit_gate(env)?;
    }
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
    if library_changed(active_state(&core)?, &candidate) {
        let generation = core.generation;
        drop(core);
        crate::sync::central::migration_flow::refresh_edit_gate(env)?;
        core = env.runtime.core.lock().unwrap();
        if core.generation != generation { return Err(crate::sync::runtime::superseded()); }
    }
    persist_candidate(&mut core, &env.state_path, candidate)
}
/// Call outside runtime locks; current mnemonic only, no staged-code promotion or cleanup.
pub fn read_account_keys(
    state: &SyncStateV3,
    keychain: &dyn crate::sync::env::Keychain,
) -> Result<Option<crate::sync::crypto::ChainKeys>, AppError> {
    validate_state(state)
        .map_err(|_| AppError::Other("cannot read keys for invalid record state".into()))?;
    if state.local.central.as_ref().is_some_and(|c|c.control.cutover) { return Ok(None); }
    let Some(account) = &state.account else {
        return Ok(None);
    };
    let phrase = keychain
        .get(crate::sync::state::MNEMONIC_ACCOUNT)
        .map_err(|_| AppError::Other("the sync code could not be read".into()))?
        .ok_or_else(|| AppError::Other("the sync code is unavailable on this device".into()))?;
    let phrase = zeroize::Zeroizing::new(phrase);
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
