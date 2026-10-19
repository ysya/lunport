//! Protected source-snapshot highwater only. No journal, consent, phase or publication authority.
use super::{
    source_archive::{self, Archived, Receipt},
    wire::{invalid, MAX_SAFE_INTEGER},
    workspace::Workspace,
};
use crate::{error::AppError, sync::env::SyncEnv};
use serde::{Deserialize, Serialize};
use std::sync::MutexGuard;
use zeroize::Zeroizing;
const CAP: usize = 16384;
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Cursor {
    version: u32,
    revision: u64,
    selection: Option<String>,
    previous: Option<Receipt>,
    receipt: Receipt,
}
pub(super) struct Restored {
    pub cursor: Cursor,
    pub bytes: Zeroizing<Vec<u8>>,
}
fn role(owner: &Workspace) -> Result<String, AppError> {
    Ok(owner
        .control
        .profile
        .profile()?
        .slot("source-migration-cursor"))
}
impl Cursor {
    fn validate(&self, owner: &Workspace) -> Result<(), AppError> {
        if self.version != 1
            || self.revision == 0
            || self.revision > MAX_SAFE_INTEGER
            || self.selection != owner.identity_slot
            || (self.revision == 1) != self.previous.is_none()
        {
            return Err(invalid());
        }
        self.receipt.matches_selected(owner)?;
        if let Some(previous) = &self.previous {
            previous.matches_selected(owner)?;
            if !self.receipt.follows(previous)? {
                return Err(invalid());
            }
        }
        Ok(())
    }
    fn encode(&self) -> Result<Zeroizing<String>, AppError> {
        let value = Zeroizing::new(serde_json::to_string(self).map_err(|_| invalid())?);
        if value.len() > CAP {
            return Err(invalid());
        }
        Ok(value)
    }
    fn saved(env: &SyncEnv, owner: &Workspace) -> Result<Option<Self>, AppError> {
        let Some(encoded) = env
            .keychain
            .get_noninteractive(&role(owner)?)?
            .map(Zeroizing::new)
        else {
            return Ok(None);
        };
        if encoded.len() > CAP {
            return Err(invalid());
        }
        let value: Self = serde_json::from_str(&encoded).map_err(|_| invalid())?;
        value.validate(owner)?;
        Ok(Some(value))
    }
    pub fn receipt(&self) -> &Receipt {
        &self.receipt
    }
    fn restore(self, env: &SyncEnv, owner: &Workspace) -> Result<Restored, AppError> {
        self.validate(owner)?;
        let bytes = source_archive::restore(env, &owner.control.profile.profile()?, &self.receipt)?;
        Ok(Restored {
            cursor: self,
            bytes,
        })
    }
    /// None means no cursor was read, never permission to ignore existing source obligations.
    pub fn load(
        env: &SyncEnv,
        _life: &MutexGuard<'_, ()>,
        owner: &Workspace,
    ) -> Result<Option<Restored>, AppError> {
        Self::saved(env, owner)?
            .map(|cursor| cursor.restore(env, owner))
            .transpose()
    }
    /// The future driver must prove fresh initialization and revalidate its session/source first.
    pub fn initialize(
        env: &SyncEnv,
        _life: &MutexGuard<'_, ()>,
        owner: &Workspace,
        archived: &Archived,
    ) -> Result<Restored, AppError> {
        let next = Self {
            version: 1,
            revision: 1,
            selection: owner.identity_slot.clone(),
            previous: None,
            receipt: archived.receipt().clone(),
        };
        Self::persist(env, owner, None, next)
    }
    pub fn advance(
        &self,
        env: &SyncEnv,
        _life: &MutexGuard<'_, ()>,
        owner: &Workspace,
        archived: &Archived,
    ) -> Result<Restored, AppError> {
        self.validate(owner)?;
        let next = Self {
            version: 1,
            revision: self.revision.checked_add(1).ok_or_else(invalid)?,
            selection: self.selection.clone(),
            previous: Some(self.receipt.clone()),
            receipt: archived.receipt().clone(),
        };
        Self::persist(env, owner, Some(self), next)
    }
    fn persist(
        env: &SyncEnv,
        owner: &Workspace,
        before: Option<&Self>,
        next: Self,
    ) -> Result<Restored, AppError> {
        next.validate(owner)?;
        let current = Self::saved(env, owner)?;
        if current.as_ref() == Some(&next) {
            return next.restore(env, owner);
        }
        if current.as_ref() != before {
            return Err(AppError::Other("Source migration progress changed or is unavailable. Original snapshots are retained.".into()));
        }
        // Confirm the durable ciphertext before changing the protected highwater.
        drop(source_archive::restore(
            env,
            &owner.control.profile.profile()?,
            &next.receipt,
        )?);
        let encoded = next.encode()?;
        env.keychain.set_noninteractive(&role(owner)?, &encoded)?;
        let checked = Self::saved(env, owner)?.ok_or_else(invalid)?;
        if checked != next {
            return Err(invalid());
        }
        checked.restore(env, owner)
    }
}

#[cfg(test)]
mod tests;
