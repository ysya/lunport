//! Sealed native proof interface shared by migration and approved-device adoption.
use super::{controller::Session, crypto::VaultKeys, initial_projection::Candidate};
use crate::{
    error::AppError,
    sync::{env::SyncEnv, record_import::central_stage::InitialEffects},
};
use std::{
    path::Path,
    sync::{Arc, MutexGuard},
};
pub(super) mod sealed {
    pub trait Sealed {}
}
pub(in crate::sync) trait InitialTransaction: sealed::Sealed {
    fn projection(&self) -> &Candidate;
    fn operation(&self) -> &str;
    fn generation(&self) -> u64;
    fn session(&self) -> &Arc<Session>;
    fn check_identity_locked(
        &self,
        env: &SyncEnv,
        keys: &VaultKeys,
        life: &MutexGuard<'_, ()>,
    ) -> Result<(), AppError>;
    fn check_locked(
        &self,
        env: &SyncEnv,
        keys: &VaultKeys,
        life: &MutexGuard<'_, ()>,
    ) -> Result<(), AppError>;
    fn original_import_root(&self) -> bool;
    fn original_state<'a>(&'a self, env: &SyncEnv) -> Result<&'a [u8], AppError>;
    fn original_vault<'a>(&'a self, env: &SyncEnv) -> Result<Option<&'a [u8]>, AppError>;
    fn verify_files_at(
        &self,
        state_path: &Path,
        ssh_dir: &Path,
        effects: &InitialEffects,
    ) -> Result<(), AppError>;
    fn check_effects_locked(
        &self,
        env: &SyncEnv,
        keys: &VaultKeys,
        life: &MutexGuard<'_, ()>,
        effects: &InitialEffects,
    ) -> Result<(), AppError> {
        self.check_identity_locked(env, keys, life)?;
        effects.matches(self.projection(), self.operation())?;
        self.verify_files_at(&env.state_path, &env.ssh_dir, effects)
    }
}
impl sealed::Sealed for super::initial_publication::Prepared {}
impl InitialTransaction for super::initial_publication::Prepared {
    fn projection(&self) -> &Candidate {
        self.projection()
    }
    fn operation(&self) -> &str {
        self.operation()
    }
    fn generation(&self) -> u64 {
        self.generation()
    }
    fn session(&self) -> &Arc<Session> {
        self.session()
    }
    fn check_identity_locked(
        &self,
        env: &SyncEnv,
        keys: &VaultKeys,
        life: &MutexGuard<'_, ()>,
    ) -> Result<(), AppError> {
        self.check_identity_locked(env, keys, life)
    }
    fn check_locked(
        &self,
        env: &SyncEnv,
        keys: &VaultKeys,
        life: &MutexGuard<'_, ()>,
    ) -> Result<(), AppError> {
        self.check_locked(env, keys, life)
    }
    fn original_import_root(&self) -> bool {
        self.original_import_root()
    }
    fn original_state<'a>(&'a self, env: &SyncEnv) -> Result<&'a [u8], AppError> {
        self.original_state(env)
    }
    fn original_vault<'a>(&'a self, env: &SyncEnv) -> Result<Option<&'a [u8]>, AppError> {
        self.original_vault(env)
    }
    fn verify_files_at(
        &self,
        state_path: &Path,
        ssh_dir: &Path,
        effects: &InitialEffects,
    ) -> Result<(), AppError> {
        self.verify_files_at(state_path, ssh_dir, effects)
    }
}

pub(in crate::sync) fn verify_saved(
    env: &SyncEnv,
    life: &MutexGuard<'_, ()>,
    current: &super::workspace::Workspace,
    original: &crate::sync::records_v3::SyncStateV3,
    operation: &str,
    manifest: &str,
    observed: u64,
) -> Result<(), AppError> {
    let before = original
        .local
        .central
        .as_ref()
        .ok_or_else(super::wire::invalid)?;
    if before.replacement_archives.is_empty()
        && before
            .control
            .proof
            .as_ref()
            .ok_or_else(super::wire::invalid)?
            .genesis
            .first
            == before.control.device
    {
        super::initial_publication::Prepared::verify_saved_reservation(
            env, life, current, original, operation, manifest, observed,
        )
    } else {
        super::adoption::verify_saved(
            env, life, current, original, operation, manifest, observed,
        )
    }
}
pub(super) fn complete_saved(env: &SyncEnv) -> Result<(), AppError> {
    let state = crate::sync::record_runtime::snapshot(env)?.0;
    let owner = state
        .local
        .central
        .as_ref()
        .ok_or_else(super::wire::invalid)?;
    if owner.replacement_archives.is_empty()
        && owner
            .control
            .proof
            .as_ref()
            .ok_or_else(super::wire::invalid)?
            .genesis
            .first
            == owner.control.device
    {
        super::initial_publication::complete_saved(env)
    } else {
        super::adoption::complete_saved(env)
    }
}
