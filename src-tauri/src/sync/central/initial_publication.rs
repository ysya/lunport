//! Protected first-publication reservation. This passive preparation cannot activate Core state.
use super::{
    controller::{self, Session},
    crypto::{self, VaultKeys},
    initial_projection::Candidate,
    migration_dispatch::Verified,
    migration_journal::{review::Approval, Loaded},
    source_complete,
    source_cursor::Cursor,
    wire::{hex, invalid, MAX_SAFE_INTEGER},
};
use crate::{error::AppError, sync::env::SyncEnv};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use zeroize::Zeroizing;
const CAP: usize = 32768;
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Reservation {
    version: u32,
    policy: String,
    cursor: Cursor,
    manifest: String,
    operation: String,
    observed: u64,
}
pub(in crate::sync) struct Prepared {
    initial: Candidate,
    loaded: Loaded,
    approval: Approval,
    generation: u64,
    session: Arc<Session>,
    reservation: Reservation,
}
fn role(loaded: &Loaded) -> Result<String, AppError> {
    let owner = loaded.plan.before();
    owner.control.profile.profile()?.device_slot(
        "source-migration-publication",
        owner.identity_slot.as_deref(),
    )
}
impl Reservation {
    fn validate(&self, loaded: &Loaded) -> Result<(), AppError> {
        if self.version != 1
            || self.policy != "initial-publication-v1"
            || self.cursor != loaded.cursor
            || self.manifest != loaded.plan.manifest.digest()?
            || !hex(&self.operation, 32)
            || self.observed > MAX_SAFE_INTEGER
        {
            return Err(invalid());
        }
        self.cursor.validate(loaded.plan.before())
    }
}
fn read(env: &SyncEnv, loaded: &Loaded) -> Result<Option<Reservation>, AppError> {
    let Some(encoded) = env
        .keychain
        .get_noninteractive(&role(loaded)?)?
        .map(Zeroizing::new)
    else {
        return Ok(None);
    };
    if encoded.len() > CAP {
        return Err(invalid());
    }
    let reservation: Reservation = serde_json::from_str(&encoded).map_err(|_| invalid())?;
    reservation.validate(loaded)?;
    Ok(Some(reservation))
}
fn reserve(env: &SyncEnv, loaded: &Loaded) -> Result<Reservation, AppError> {
    if let Some(saved) = read(env, loaded)? {
        return Ok(saved);
    }
    let reservation = Reservation {
        version: 1,
        policy: "initial-publication-v1".into(),
        cursor: loaded.cursor.clone(),
        manifest: loaded.plan.manifest.digest()?,
        operation: crypto::random_id(16)?,
        observed: env.now(),
    };
    reservation.validate(loaded)?;
    let encoded = Zeroizing::new(serde_json::to_string(&reservation).map_err(|_| invalid())?);
    if encoded.len() > CAP {
        return Err(invalid());
    }
    env.keychain.set_noninteractive(&role(loaded)?, &encoded)?;
    let checked = read(env, loaded)?.ok_or_else(invalid)?;
    if checked != reservation {
        return Err(invalid());
    }
    Ok(checked)
}
impl Prepared {
    pub(in crate::sync) fn projection(&self) -> &Candidate {
        &self.initial
    }
    pub fn operation(&self) -> &str {
        &self.reservation.operation
    }
    pub fn check(&self, env: &SyncEnv, keys: &VaultKeys) -> Result<(), AppError> {
        let life = env.runtime.lifecycle.lock().unwrap();
        let _vault = env
            .runtime
            .vault
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let _publication = env.runtime.format_publication.lock().unwrap();
        self.check_locked(env, keys, &life)
    }
    pub(in crate::sync) fn check_identity_locked(
        &self,
        env: &SyncEnv,
        keys: &VaultKeys,
        life: &std::sync::MutexGuard<'_, ()>,
    ) -> Result<(), AppError> {
        source_complete::check(
            env,
            &self.loaded.package.state,
            self.generation,
            &self.session,
            keys,
        )?;
        self.approval.require_current(env, &self.loaded)?;
        if self.initial.source() != &self.loaded.package.state
            || self.initial.manifest() != self.reservation.manifest
            || self.initial.observed() != self.reservation.observed
        {
            return Err(invalid());
        }
        if Cursor::load(env, life, self.loaded.plan.before())?
            .ok_or_else(invalid)?
            .cursor
            != self.loaded.cursor
            || read(env, &self.loaded)?.as_ref() != Some(&self.reservation)
        {
            return Err(invalid());
        }
        Ok(())
    }
    pub(in crate::sync) fn check_locked(
        &self,
        env: &SyncEnv,
        keys: &VaultKeys,
        life: &std::sync::MutexGuard<'_, ()>,
    ) -> Result<(), AppError> {
        self.check_identity_locked(env, keys, life)?;
        self.loaded.require_unchanged(env)
    }
    pub(in crate::sync) fn original_state<'a>(
        &'a self,
        env: &SyncEnv,
    ) -> Result<&'a [u8], AppError> {
        let name = env.state_path.file_name().ok_or_else(invalid)?;
        self.loaded
            .package
            .files
            .bytes
            .get(&std::path::Path::new("data").join(name))
            .map(|b| b.as_slice())
            .ok_or_else(invalid)
    }
    pub(in crate::sync) fn original_vault<'a>(
        &'a self,
        env: &SyncEnv,
    ) -> Result<Option<&'a [u8]>, AppError> {
        let path = crate::vault::store::vault_path(&env.state_path);
        let name = path.file_name().ok_or_else(invalid)?;
        Ok(self
            .loaded
            .package
            .files
            .bytes
            .get(&std::path::Path::new("data").join(name))
            .map(|b| b.as_slice()))
    }
    pub(in crate::sync) fn check_effects_locked(
        &self,
        env: &SyncEnv,
        keys: &VaultKeys,
        life: &std::sync::MutexGuard<'_, ()>,
        effects: &crate::sync::record_import::central_stage::InitialEffects,
    ) -> Result<(), AppError> {
        self.check_identity_locked(env, keys, life)?;
        effects.matches(self.projection(), self.operation())?;
        self.loaded.package.files.require_unchanged_after_initial(
            env,
            self.loaded.package.state.legacy_v1_backup.as_deref(),
            &self.loaded.outputs,
            effects,
        )
    }
}
pub(super) fn prepare(
    env: &SyncEnv,
    verified: Verified,
    keys: &VaultKeys,
) -> Result<Prepared, AppError> {
    controller::require_enabled()?;
    let life = env.runtime.lifecycle.lock().unwrap();
    let _vault = env
        .runtime
        .vault
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let _publication = env.runtime.format_publication.lock().unwrap();
    source_complete::check(
        env,
        &verified.loaded.package.state,
        verified.generation,
        &verified.session,
        keys,
    )?;
    verified.approval.require_current(env, &verified.loaded)?;
    verified.loaded.require_unchanged(env)?;
    if Cursor::load(env, &life, verified.loaded.plan.before())?
        .ok_or_else(invalid)?
        .cursor
        != verified.loaded.cursor
    {
        return Err(invalid());
    }
    let reservation = reserve(env, &verified.loaded)?;
    let initial = Candidate::prepare(
        &verified.loaded.package.state,
        &verified.loaded.plan,
        verified.committed,
        keys,
        reservation.observed,
    )?;
    let prepared = Prepared {
        initial,
        loaded: verified.loaded,
        approval: verified.approval,
        generation: verified.generation,
        session: verified.session,
        reservation,
    };
    prepared.check_locked(env, keys, &life)?;
    Ok(prepared)
}
/// Restore only a previously reserved completed-readback transaction. Never create a new
/// reservation or permit ordinary migration transport to ignore owned stage outputs.
pub(super) fn resume(
    env: &SyncEnv,
    keys: &VaultKeys,
    references: &std::collections::BTreeMap<String, super::payload::KeyStorage>,
) -> Result<Prepared, AppError> {
    controller::require_enabled()?;
    let life = env.runtime.lifecycle.lock().unwrap();
    let _vault = env
        .runtime
        .vault
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let _publication = env.runtime.format_publication.lock().unwrap();
    let (state, generation) = crate::sync::record_runtime::snapshot(env)?;
    let session = controller::context(env)?;
    source_complete::check(env, &state, generation, &session, keys)?;
    let owner = state.local.central.as_ref().ok_or_else(invalid)?;
    let signer = &session.identity.as_ref().ok_or_else(invalid)?.keys;
    let (loaded, committed) =
        super::migration_journal::restore_initial(env, &life, owner, keys, signer, references)?;
    if loaded.package.state != state {
        return Err(crate::sync::runtime::superseded());
    }
    let approval = super::migration_journal::review::accepted(env, &loaded)?;
    let reservation = read(env, &loaded)?.ok_or_else(invalid)?;
    let initial = Candidate::prepare(
        &loaded.package.state,
        &loaded.plan,
        committed,
        keys,
        reservation.observed,
    )?;
    let prepared = Prepared {
        initial,
        loaded,
        approval,
        generation,
        session,
        reservation,
    };
    prepared.check_identity_locked(env, keys, &life)?;
    let directory = env
        .state_path
        .parent()
        .ok_or_else(invalid)?
        .join("imports")
        .join(prepared.operation());
    match std::fs::symlink_metadata(directory) {
        Ok(_) => {
            drop(
                crate::sync::record_import::central_stage::initial_effects_locked(
                    env, &prepared, keys, &life,
                )?,
            );
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            prepared.check_locked(env, keys, &life)?
        }
        Err(error) => return Err(error.into()),
    }
    Ok(prepared)
}
#[cfg(all(test, unix))]
mod tests;
