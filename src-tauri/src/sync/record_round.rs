//! The records state's write gates, shared by the commands and the session broker: the state file must be writable and a
//! regular file, the state loaded, and no account migration pending.
use crate::error::AppError;
use crate::sync::env::SyncEnv;

fn error(message: &str) -> AppError {
    AppError::Other(message.into())
}
/// Check the only write boundary in this transport before credential/network callbacks.
/// No SSH config, agent or vault path is touched by active record transport.
pub(crate) fn preflight_local(env: &SyncEnv) -> Result<(), AppError> {
    crate::fsutil::check_write(&env.state_path)?;
    require_no_pending_migration(env)?;
    match std::fs::symlink_metadata(&env.state_path) {
        Ok(metadata) if !metadata.is_file() || metadata.file_type().is_symlink() => {
            return Err(error("record state must be a regular file"))
        }
        Err(e) if e.kind() != std::io::ErrorKind::NotFound => return Err(e.into()),
        _ => {}
    }
    let mut core = env.runtime.core.lock().unwrap();
    if let Some(reason) = &core.save_blocked {
        return Err(error(reason));
    }
    crate::sync::record_runtime::active_state(&core)?;
    if core.generation == u64::MAX {
        return Err(error("record state generation exhausted"));
    }
    if core.unsaved {
        crate::sync::runtime::save_core(&mut core, &env.state_path)?;
    }
    Ok(())
}
/// Call while holding lifecycle. Bounded journal inspection precedes credentials and shared IO.
pub(crate) fn require_no_pending_migration(env: &SyncEnv) -> Result<(), AppError> {
    if !crate::sync::record_migration::pending_migrations(env)?.is_empty() {
        return Err(error(
            "finish the pending account migration before changing shared data",
        ));
    }
    Ok(())
}
