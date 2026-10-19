//! Protected source-snapshot and verified-progress highwater. No consent or publication authority.
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    checkpoint: Option<super::migration_journal::checkpoint::Checkpoint>,
}
pub(super) struct Restored {
    pub cursor: Cursor,
    pub bytes: Zeroizing<Vec<u8>>,
    pub outputs: source_archive::Outputs,
}
fn role(owner: &Workspace) -> Result<String, AppError> {
    Ok(owner
        .control
        .profile
        .profile()?
        .slot("source-migration-cursor"))
}
impl Cursor {
    pub(super) fn validate(&self, owner: &Workspace) -> Result<(), AppError> {
        if !matches!(
            (self.version, self.checkpoint.is_some()),
            (1, false) | (2, true)
        ) || self.revision == 0
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
    pub(super) fn same_archive(&self, other: &Self) -> bool {
        self.revision == other.revision
            && self.selection == other.selection
            && self.previous == other.previous
            && self.receipt == other.receipt
    }
    pub(super) fn progress_checkpoint(
        &self,
    ) -> Option<&super::migration_journal::checkpoint::Checkpoint> {
        self.checkpoint.as_ref()
    }
    /// Only the planned driver can mint this opaque, validated continuation. Store it atomically
    /// with the existing archive highwater so missing metadata can never fall back to older progress.
    pub(super) fn checkpoint(
        &self,
        env: &SyncEnv,
        owner: &Workspace,
        checkpoint: super::migration_journal::checkpoint::Checkpoint,
    ) -> Result<Restored, AppError> {
        self.validate(owner)?;
        let mut next = self.clone();
        next.version = 2;
        next.checkpoint = Some(checkpoint);
        Self::persist(env, owner, Some(self), next)
    }
    pub fn revision(&self) -> u64 {
        self.revision
    }
    pub fn previous(&self) -> Option<&Receipt> {
        self.previous.as_ref()
    }
    pub fn receipt(&self) -> &Receipt {
        &self.receipt
    }
    fn restore(self, env: &SyncEnv, owner: &Workspace) -> Result<Restored, AppError> {
        self.validate(owner)?;
        let (bytes, outputs) = source_archive::restore_with_outputs(
            env,
            &owner.control.profile.profile()?,
            &self.receipt,
        )?;
        Ok(Restored {
            cursor: self,
            bytes,
            outputs,
        })
    }
    /// Read-only predecessor proof pinned by an actual protected child. This cannot rewind storage.
    pub fn restored_parent(
        &self,
        env: &SyncEnv,
        owner: &Workspace,
        child: &Cursor,
    ) -> Result<Restored, AppError> {
        self.validate(owner)?;
        child.validate(owner)?;
        if self.revision.checked_add(1) != Some(child.revision)
            || self.selection != child.selection
            || child.previous.as_ref() != Some(&self.receipt)
        {
            return Err(invalid());
        }
        self.clone().restore(env, owner)
    }
    /// Read-only ancestry proof pinned by the actual current cursor and its authenticated journal.
    /// The complete lineage includes the current receipt. This never writes historical progress.
    pub fn restored_ancestor(
        &self,
        env: &SyncEnv,
        owner: &Workspace,
        current: &Cursor,
        lineage: &[Receipt],
    ) -> Result<Restored, AppError> {
        self.validate(owner)?;
        current.validate(owner)?;
        if self.selection != current.selection
            || self.revision > current.revision
            || lineage.len() as u64 != current.revision
            || lineage.last() != Some(current.receipt())
            || lineage.get(self.revision as usize - 1) != Some(self.receipt())
            || (self.revision > 1 && lineage.get(self.revision as usize - 2) != self.previous())
            || (current.revision > 1
                && lineage.get(current.revision as usize - 2) != current.previous())
        {
            return Err(invalid());
        }
        let mut seen = std::collections::BTreeSet::new();
        for receipt in lineage {
            receipt.matches_selected(owner)?;
            if !seen.insert(&receipt.ciphertext_hash) {
                return Err(invalid());
            }
        }
        for pair in lineage.windows(2) {
            if !pair[1].follows(&pair[0])? {
                return Err(invalid());
            }
        }
        self.clone().restore(env, owner)
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
            checkpoint: None,
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
        if self.checkpoint.is_some() {
            return Err(invalid());
        }
        let next = Self {
            version: 1,
            revision: self.revision.checked_add(1).ok_or_else(invalid)?,
            selection: self.selection.clone(),
            previous: Some(self.receipt.clone()),
            receipt: archived.receipt().clone(),
            checkpoint: None,
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
