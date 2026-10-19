//! Referenced planned-migration progress only. No consent, complete inventory or cutover permit.
use super::{
    controller,
    crypto::{DeviceKeys, VaultKeys},
    migration_history::Plan,
    migration_progress::{Known, Phase},
    migration_verify::{Prefix, Verifier},
    payload::KeyStorage,
    source_archive::{self, Outputs, Receipt},
    source_complete,
    source_cursor::{Cursor, Restored},
    source_package::Package,
    source_plan,
    wire::invalid,
    workspace::Workspace,
};
use crate::{error::AppError, sync::env::SyncEnv};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, sync::MutexGuard};
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
/// Starts or resumes the durable planned phase. This does not grant human consent.
/// Capture must be complete; a pre-existing journal is restored without regenerating its plan.
pub(super) fn ensure(
    env: &SyncEnv,
    keys: &VaultKeys,
    references: &BTreeMap<String, KeyStorage>,
) -> Result<Loaded, AppError> {
    controller::require_enabled()?;
    // Do not hold runtime locks while entering the plan driver, which owns the same locks.
    // Recheck the exact protected cursor, state and session after acquiring them again below.
    let planned = {
        let life = env.runtime.lifecycle.lock().unwrap();
        let (state, generation) = crate::sync::record_runtime::snapshot(env)?;
        let session = controller::context(env)?;
        source_complete::check(env, &state, generation, &session, keys)?;
        let owner = state.local.central.as_ref().ok_or_else(invalid)?;
        let saved = Cursor::load(env, &life, owner)?.ok_or_else(invalid)?;
        Package::complete_frame(&saved.bytes)
    };
    let planned = if planned {
        Some(source_plan::ensure(env, keys, references)?)
    } else {
        None
    };
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
    let current = Cursor::load(env, &life, owner)?.ok_or_else(invalid)?;
    let mut loaded = if current.bytes.starts_with(MAGIC) {
        Journal::restored(env, owner, keys, signer, current)?
    } else {
        let planned = match planned {
            Some(planned) => planned,
            None => source_plan::restored(env, owner, keys, signer, references, current)?,
        };
        if Cursor::load(env, &life, owner)?.ok_or_else(invalid)?.cursor != planned.cursor
            || planned.package.state != state
        {
            return Err(crate::sync::runtime::superseded());
        }
        Journal::planned(
            &planned.cursor,
            planned.source_cursor.receipt().clone(),
            planned.ancestors,
            owner,
        )?
        .store(
            env,
            &life,
            owner,
            keys,
            signer,
            &planned.cursor,
            planned.cursor.receipt().next_ordinal()?,
        )?
    };
    loaded.require_bound(env, owner, keys, signer, references)?;
    if let Some(next) = loaded.recover_pending(env, &life, owner, keys, signer)? {
        loaded = next;
        loaded.require_bound(env, owner, keys, signer, references)?;
    }
    if loaded.package.state != state {
        return Err(crate::sync::runtime::superseded());
    }
    loaded.require_unchanged(env)?;
    source_complete::check(env, &state, generation, &session, keys)?;
    Ok(loaded)
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
        let pending = source_archive::resume_next(
            env,
            owner,
            before.receipt(),
            generation,
            &encoded,
            &inputs.outputs,
        )?;
        let (snapshot, outputs) = match pending {
            Some((snapshot, proof)) => (Some(snapshot), inputs.outputs.merge(proof)?),
            None => (None, inputs.outputs),
        };
        inputs.package.files.require_unchanged_after_archive(
            env,
            inputs.package.state.legacy_v1_backup.as_deref(),
            &outputs,
        )?;
        let snapshot = match snapshot {
            Some(snapshot) => snapshot,
            None => {
                outputs.require_room_for_snapshot(encoded.len())?;
                source_archive::next(env, life, owner, generation, before.receipt(), &encoded)?
            }
        };
        let outputs =
            outputs.merge(snapshot.outputs(env, &owner.control.profile.profile()?, &encoded)?)?;
        inputs.package.files.require_unchanged_after_archive(
            env,
            inputs.package.state.legacy_v1_backup.as_deref(),
            &outputs,
        )?;
        let saved = before.advance(env, life, owner, &snapshot)?;
        Self::restored(env, owner, keys, signer, saved)
    }
}
impl Loaded {
    fn recover_pending(
        &self,
        env: &SyncEnv,
        life: &MutexGuard<'_, ()>,
        owner: &Workspace,
        keys: &VaultKeys,
        signer: &DeviceKeys,
    ) -> Result<Option<Loaded>, AppError> {
        let ordinal = self.cursor.receipt().next_ordinal()?;
        let Some(bytes) = source_archive::candidate_next(
            env,
            owner,
            self.cursor.receipt(),
            ordinal,
            &self.outputs,
        )?
        else {
            return Ok(None);
        };
        let pending = Journal::decode(&bytes)?;
        pending.before(&self.cursor, owner)?;
        // Reconstruct exactly one typed progress/readback transition. An authenticated blob
        // does not authorize changing source/plan bindings or inventing another journal step.
        let expected = if pending.progress != self.journal.progress {
            if pending.verified != self.journal.verified {
                return Err(invalid());
            }
            self.with_progress(pending.progress.clone().ok_or_else(invalid)?, owner)?
        } else if pending.verified != self.journal.verified {
            let verifier = Verifier::resume(
                &self.plan,
                self.journal.progress.as_ref().ok_or_else(invalid)?,
                keys,
                pending.verified.as_ref().ok_or_else(invalid)?,
            )?;
            self.with_readback(&verifier, owner)?
        } else {
            return Err(invalid());
        }
        .ok_or_else(invalid)?;
        if expected.encode()?.as_slice() != bytes.as_slice() {
            return Err(invalid());
        }
        Ok(Some(expected.store(
            env,
            life,
            owner,
            keys,
            signer,
            &self.cursor,
            ordinal,
        )?))
    }
    /// Runtime gate: fixtures or independently signed plans do not establish whole-source coverage.
    fn require_bound(
        &self,
        env: &SyncEnv,
        owner: &Workspace,
        keys: &VaultKeys,
        signer: &DeviceKeys,
        references: &BTreeMap<String, KeyStorage>,
    ) -> Result<(), AppError> {
        let bytes =
            source_archive::restore(env, &owner.control.profile.profile()?, &self.journal.plan)?;
        let source = Plan::source_cursor(&bytes)?;
        if source.receipt() != &self.journal.source
            || self.journal.ancestors.get(source.revision() as usize) != Some(&self.journal.plan)
        {
            return Err(invalid());
        }
        let mut lineage = self.journal.ancestors.clone();
        lineage.push(self.cursor.receipt().clone());
        let saved = source.restored_ancestor(env, owner, &self.cursor, &lineage)?;
        let (package, ancestors, _, _) =
            super::capture_journal::Journal::completed_source(env, owner, signer, saved)?;
        if ancestors.as_slice() != &self.journal.ancestors[..source.revision() as usize]
            || package.encode_local()?.as_slice() != self.package.encode_local()?.as_slice()
            || self.plan.encode_with_source(&source)?.as_slice() != bytes.as_slice()
        {
            return Err(invalid());
        }
        self.plan.matches_history(
            keys,
            &package.structured_history(keys, references)?.into_rows(),
        )
    }
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

#[cfg(all(test, unix))]
mod handoff_tests;
