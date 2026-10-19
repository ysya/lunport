//! Referenced planned-migration progress only. No consent, complete inventory or cutover permit.
use super::{
    crypto::{DeviceKeys, VaultKeys},
    migration_history::Plan,
    migration_progress::{Known, Phase},
    migration_verify::{Prefix, Verifier},
    source_archive::{self, Outputs, Receipt},
    source_cursor::{Cursor, Restored},
    source_package::Package,
    wire::invalid,
    workspace::Workspace,
};
use crate::{error::AppError, sync::env::SyncEnv};
use serde::{Deserialize, Serialize};
use std::sync::MutexGuard;
use zeroize::Zeroizing;
const MAGIC: &[u8; 8] = b"LPMIGJ1\0";
const CAP: usize = 1024 * 1024;
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Journal {
    version: u32,
    revision: u64,
    source: Receipt,
    plan: Receipt,
    ancestors: Vec<Receipt>,
    progress: Option<Known>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    verified: Option<Prefix>,
}
pub(super) struct Loaded {
    pub journal: Journal,
    pub cursor: Cursor,
    pub package: Package,
    pub plan: Plan,
    pub outputs: Outputs,
}
struct Inputs {
    package: Package,
    plan: Plan,
    outputs: Outputs,
}
impl Journal {
    /// Creates metadata only. The caller still owes full source normalization and explicit consent.
    pub fn planned(
        cursor: &Cursor,
        source: Receipt,
        ancestors: Vec<Receipt>,
        owner: &Workspace,
    ) -> Result<Self, AppError> {
        let result = Self {
            version: 1,
            revision: cursor.revision().checked_add(1).ok_or_else(invalid)?,
            source,
            plan: cursor.receipt().clone(),
            ancestors,
            progress: None,
            verified: None,
        };
        result.before(cursor, owner)?;
        Ok(result)
    }
    fn lineage(&self, owner: &Workspace) -> Result<(), AppError> {
        if self.version != 1
            || self.ancestors.is_empty()
            || self.ancestors.len() > 254
            || self.revision != self.ancestors.len() as u64 + 1
            || !self.ancestors.contains(&self.source)
            || !self.ancestors.contains(&self.plan)
            || !self.plan.follows(&self.source)?
        {
            return Err(invalid());
        }
        let mut seen = std::collections::BTreeSet::new();
        for receipt in &self.ancestors {
            receipt.matches_selected(owner)?;
            if !seen.insert(&receipt.ciphertext_hash) {
                return Err(invalid());
            }
        }
        for pair in self.ancestors.windows(2) {
            if !pair[1].follows(&pair[0])? {
                return Err(invalid());
            }
        }
        Ok(())
    }
    fn before(&self, cursor: &Cursor, owner: &Workspace) -> Result<(), AppError> {
        self.lineage(owner)?;
        if self.revision != cursor.revision().checked_add(1).ok_or_else(invalid)?
            || self.ancestors.last() != Some(cursor.receipt())
        {
            return Err(invalid());
        }
        Ok(())
    }
    fn current(&self, cursor: &Cursor, owner: &Workspace) -> Result<(), AppError> {
        self.lineage(owner)?;
        cursor.receipt().matches_selected(owner)?;
        if self.revision != cursor.revision()
            || self.ancestors.last() != cursor.previous()
            || !cursor
                .receipt()
                .follows(self.ancestors.last().ok_or_else(invalid)?)?
        {
            return Err(invalid());
        }
        Ok(())
    }
    fn encode(&self) -> Result<Zeroizing<Vec<u8>>, AppError> {
        let mut bytes = Zeroizing::new(Vec::new());
        bytes.extend_from_slice(MAGIC);
        serde_json::to_writer(&mut *bytes, self).map_err(|_| invalid())?;
        if bytes.len() > CAP {
            return Err(invalid());
        }
        Ok(bytes)
    }
    fn decode(bytes: &[u8]) -> Result<Self, AppError> {
        if bytes.len() > CAP || !bytes.starts_with(MAGIC) {
            return Err(invalid());
        }
        serde_json::from_slice(&bytes[8..]).map_err(|_| invalid())
    }
    fn inputs(
        &self,
        env: &SyncEnv,
        owner: &Workspace,
        keys: &VaultKeys,
        signer: &DeviceKeys,
        mut outputs: Outputs,
    ) -> Result<Inputs, AppError> {
        self.lineage(owner)?;
        let profile = owner.control.profile.profile()?;
        let mut package = None;
        let mut encoded_plan = None;
        for receipt in &self.ancestors {
            let (bytes, proof) = source_archive::restore_with_outputs(env, &profile, receipt)?;
            outputs = outputs.merge(proof)?;
            if receipt == &self.source {
                package = Some(Package::decode_local(&bytes)?);
            }
            if receipt == &self.plan {
                encoded_plan = Some(bytes);
            }
        }
        let package = package.ok_or_else(invalid)?;
        if package.state.local.central.as_ref() != Some(owner) {
            return Err(invalid());
        }
        let context = package.migration_context(&self.source)?;
        let plan = Plan::decode_local(
            &encoded_plan.ok_or_else(invalid)?,
            owner,
            keys,
            signer,
            &context,
        )?;
        if let Some(progress) = &self.progress {
            progress.validate(&plan)?;
        }
        if let Some(prefix) = &self.verified {
            if self
                .progress
                .as_ref()
                .is_none_or(|p| p.phase() != Phase::Retired)
            {
                return Err(invalid());
            }
            prefix.validate(&plan)?;
        }
        Ok(Inputs {
            package,
            plan,
            outputs,
        })
    }
    fn restored(
        env: &SyncEnv,
        owner: &Workspace,
        keys: &VaultKeys,
        signer: &DeviceKeys,
        saved: Restored,
    ) -> Result<Loaded, AppError> {
        let journal = Self::decode(&saved.bytes)?;
        journal.current(&saved.cursor, owner)?;
        let inputs = journal.inputs(env, owner, keys, signer, saved.outputs)?;
        Ok(Loaded {
            journal,
            cursor: saved.cursor,
            package: inputs.package,
            plan: inputs.plan,
            outputs: inputs.outputs,
        })
    }
    pub fn load(
        env: &SyncEnv,
        life: &MutexGuard<'_, ()>,
        owner: &Workspace,
        keys: &VaultKeys,
        signer: &DeviceKeys,
    ) -> Result<Option<Loaded>, AppError> {
        Cursor::load(env, life, owner)?
            .map(|saved| Self::restored(env, owner, keys, signer, saved))
            .transpose()
    }
    /// Validate both source facts and protected cursor again; all remote effects need fresh gates.
    pub fn store(
        self,
        env: &SyncEnv,
        life: &MutexGuard<'_, ()>,
        owner: &Workspace,
        keys: &VaultKeys,
        signer: &DeviceKeys,
        before: &Cursor,
        generation: u64,
    ) -> Result<Loaded, AppError> {
        let current = Cursor::load(env, life, owner)?.ok_or_else(invalid)?;
        let encoded = self.encode()?;
        // A protected write may have succeeded before reporting failure: use that exact snapshot.
        if current.cursor.revision() == self.revision
            && current.bytes.as_slice() == encoded.as_slice()
        {
            return Self::restored(env, owner, keys, signer, current);
        }
        if &current.cursor != before {
            return Err(invalid());
        }
        self.before(before, owner)?;
        let previous = if current.bytes.starts_with(MAGIC) {
            let old = Self::decode(&current.bytes)?;
            old.current(before, owner)?;
            Some(old)
        } else {
            None
        };
        let inputs = self.inputs(env, owner, keys, signer, current.outputs)?;
        if let Some(old) = previous {
            if old.source != self.source
                || old.plan != self.plan
                || self.ancestors[..self.ancestors.len() - 1] != old.ancestors
            {
                return Err(invalid());
            }
            if let Some(minimum) = old.progress {
                self.progress
                    .as_ref()
                    .ok_or_else(invalid)?
                    .require_after(&inputs.plan, &minimum)?;
            }
            if let Some(minimum) = &old.verified {
                self.verified
                    .as_ref()
                    .ok_or_else(invalid)?
                    .require_after(&inputs.plan, minimum)?;
            }
        } else if before.receipt() != &self.plan
            || self.progress.is_some()
            || self.verified.is_some()
        {
            return Err(invalid());
        }
        inputs.package.files.require_unchanged_after_archive(
            env,
            inputs.package.state.legacy_v1_backup.as_deref(),
            &inputs.outputs,
        )?;
        inputs.outputs.require_room_for_snapshot(encoded.len())?;
        let snapshot =
            source_archive::next(env, life, owner, generation, before.receipt(), &encoded)?;
        let saved = before.advance(env, life, owner, &snapshot)?;
        Self::restored(env, owner, keys, signer, saved)
    }
}
impl Loaded {
    fn successor(&self, owner: &Workspace) -> Result<Journal, AppError> {
        self.journal.current(&self.cursor, owner)?;
        let mut ancestors = self.journal.ancestors.clone();
        ancestors.push(self.cursor.receipt().clone());
        let next = Journal {
            version: 1,
            revision: self.cursor.revision().checked_add(1).ok_or_else(invalid)?,
            source: self.journal.source.clone(),
            plan: self.journal.plan.clone(),
            ancestors,
            progress: self.journal.progress.clone(),
            verified: self.journal.verified.clone(),
        };
        next.before(&self.cursor, owner)?;
        Ok(next)
    }
    pub fn verifier(&self, keys: &VaultKeys) -> Result<Verifier, AppError> {
        let retired = self.journal.progress.as_ref().ok_or_else(invalid)?;
        match &self.journal.verified {
            Some(prefix) => Verifier::resume(&self.plan, retired, keys, prefix),
            None => Verifier::new(&self.plan, retired),
        }
    }
    /// Derive a floor from actual native readback, never from remote status counters.
    pub fn with_readback(
        &self,
        verifier: &Verifier,
        owner: &Workspace,
    ) -> Result<Option<Journal>, AppError> {
        self.journal.current(&self.cursor, owner)?;
        let retired = self.journal.progress.as_ref().ok_or_else(invalid)?;
        retired.validate(&self.plan)?;
        if retired.phase() != Phase::Retired {
            return Err(invalid());
        }
        let prefix = verifier.snapshot(&self.plan)?;
        if self.journal.verified.as_ref() == Some(&prefix) {
            return Ok(None);
        }
        if let Some(previous) = &self.journal.verified {
            prefix.require_after(&self.plan, previous)?;
        }
        let mut journal = self.successor(owner)?;
        journal.verified = Some(prefix);
        Ok(Some(journal))
    }
    pub fn with_progress(
        &self,
        next: Known,
        owner: &Workspace,
    ) -> Result<Option<Journal>, AppError> {
        self.journal.current(&self.cursor, owner)?;
        next.validate(&self.plan)?;
        if self.journal.progress.as_ref() == Some(&next) {
            return Ok(None);
        }
        if let Some(minimum) = &self.journal.progress {
            next.require_after(&self.plan, minimum)?;
        }
        let mut journal = self.successor(owner)?;
        journal.progress = Some(next);
        Ok(Some(journal))
    }
    pub fn require_unchanged(&self, env: &SyncEnv) -> Result<(), AppError> {
        self.package.files.require_unchanged_after_archive(
            env,
            self.package.state.legacy_v1_backup.as_deref(),
            &self.outputs,
        )
    }
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod readback_tests;
