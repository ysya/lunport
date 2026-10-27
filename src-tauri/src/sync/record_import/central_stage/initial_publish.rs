//! Dedicated first-library cutover. Ordinary central projection publication stays separate.
use super::*;
use crate::sync::{
    central::{api::DeviceState, client_state::Phase as AccountPhase, InitialTransaction},
    records_v3::LocalImportReceipt,
    runtime::SyncCore,
};
use std::{path::PathBuf, sync::Arc};
pub(in crate::sync) struct Publication<'a> {
    prepared: &'a dyn InitialTransaction,
    effects: &'a InitialEffects,
    candidate: SyncStateV3,
    state_path: PathBuf,
    ssh_dir: PathBuf,
    vault_digest: Option<String>,
}
impl Publication<'_> {
    pub(in crate::sync) fn candidate(&self) -> &SyncStateV3 {
        &self.candidate
    }
    pub(in crate::sync) fn generation(&self) -> u64 {
        self.prepared.generation()
    }
    pub(in crate::sync) fn verify_core(&self, core: &SyncCore) -> Result<(), AppError> {
        if core.generation != self.generation()
            || core
                .central_session
                .as_ref()
                .is_none_or(|s| !Arc::ptr_eq(s, self.prepared.session()))
        {
            return Err(crate::sync::runtime::superseded());
        }
        self.verify_records(
            record_runtime::active_state(core)?,
            &self.candidate,
            self.generation(),
        )
    }
    pub(in crate::sync) fn verify_records(
        &self,
        before: &SyncStateV3,
        candidate: &SyncStateV3,
        generation: u64,
    ) -> Result<(), AppError> {
        let owner = before
            .local
            .central
            .as_ref()
            .ok_or_else(|| failure("initial publication has no source owner"))?;
        let after = candidate
            .local
            .central
            .as_ref()
            .ok_or_else(|| failure("initial publication has no proposed owner"))?;
        if self.prepared.projection().reconciliation() {
            central::verify_reconciliation_completed(before, candidate)?;
        }
        let session = self.prepared.session();
        let grant = session
            .device
            .as_ref()
            .ok_or_else(|| failure("initial publication has no device session"))?;
        if before != self.prepared.projection().source()
            || candidate != &self.candidate
            || generation != self.generation()
            || !self.prepared.projection().reconciliation()
                && (before.local.central_projection.is_some()
                    || owner.control.cutover
                    || owner.control.phase != AccountPhase::Enrolled)
            || self.prepared.projection().reconciliation()
                && !matches!(
                    owner.control.phase,
                    AccountPhase::Enrolled | AccountPhase::Active
                )
            || candidate.version != central::initial_candidate_version(candidate)
            || candidate.local.central_projection.is_none()
            || !after.control.cutover
            || after.control.phase != AccountPhase::Active
            || owner.control.profile != after.control.profile
            || owner.control.anchor != after.control.anchor
            || owner.control.device != after.control.device
            || owner.identity_slot != after.identity_slot
            || session.profile != owner.control.profile
            || session.device_access_denied
            || grant.expired()
            || grant.device_state != DeviceState::Active
            || grant.account_id != owner.control.account_id
            || grant.auth_epoch != owner.control.auth_epoch
            || session
                .identity
                .as_ref()
                .is_none_or(|i| i.device() != owner.control.device)
            || session
                .tokens_started
                .elapsed()
                .saturating_add(std::time::Duration::from_secs(5))
                >= session.tokens.expires_in
        {
            return Err(failure("initial publication source, session or candidate changed; all evidence is retained"));
        }
        crate::sync::records_v3::validate_state(candidate)
            .map_err(|_| failure("initial publication candidate is invalid"))
    }
    pub(in crate::sync) fn verify_vault(&self, path: &Path) -> Result<(), AppError> {
        if path != self.state_path
            || optional_bytes(&store::vault_path(path), store::MAX_READ_ONLY_VAULT_BYTES)?
                .as_ref()
                .map(|b| digest(b))
                != self.vault_digest
        {
            return Err(failure(
                "initial active vault changed before state publication",
            ));
        }
        // No credential or Core operation occurs here. The atomic state writer repeats this
        // exact full source-file comparison immediately before its rename.
        self.prepared
            .verify_files_at(path, &self.ssh_dir, self.effects)
    }
}
fn receipt(j: &Journal) -> Result<LocalImportReceipt, AppError> {
    let initial = j
        .initial
        .as_ref()
        .ok_or_else(|| failure("initial receipt has no projection binding"))?;
    let bytes = serde_json::to_vec(&(
        "lunport-initial-library-publication-v1",
        &j.operation,
        initial,
        &j.profile,
        &j.anchor,
        &j.device,
        &j.identity_slot,
        &j.vault,
        &j.checkpoint,
        j.at_ms,
        &j.source_state_digest,
        &j.source_vault_digest,
        &j.staged_vault_digest,
        &j.staged_key_account,
        &j.bindings,
    ))
    .map_err(|_| failure("cannot bind initial publication receipt"))?;
    Ok(LocalImportReceipt {
        source_digest: digest(&bytes),
        host_ids: vec![],
        key_ids: j.bindings.keys().cloned().collect(),
    })
}
pub(super) fn matches_receipt(
    saved: Option<&LocalImportReceipt>,
    j: &Journal,
) -> Result<bool, AppError> {
    match saved {
        None => Ok(false),
        Some(saved) if saved == &receipt(j)? => Ok(true),
        Some(_) => Err(failure(
            "initial operation conflicts with a different durable receipt",
        )),
    }
}
pub(in crate::sync) fn publish(
    env: &SyncEnv,
    prepared: &dyn InitialTransaction,
    keys: &central::crypto::VaultKeys,
) -> Result<PendingImport, AppError> {
    input::with_background(env, |safe| {
        let life = safe.runtime.lifecycle.lock().unwrap();
        let _vault = safe
            .runtime
            .vault
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let _publication = safe.runtime.format_publication.lock().unwrap();
        drop(initial_effects_locked(safe, prepared, keys, &life)?);
        let paths = Paths::new(safe, prepared.operation())?;
        let mut journal: Journal =
            serde_json::from_slice(&bounded_read(&paths.journal, MAX_JOURNAL_BYTES)?)
                .map_err(|_| failure("initial publication journal is unreadable"))?;
        validate_header(&journal, prepared.operation())?;
        verify_delta(&journal, Input::Initial(prepared.projection()))?;
        if journal.phase == Phase::Active {
            return Err(failure(
                "initial active stage requires its saved-state completion path",
            ));
        }
        execute(
            safe,
            &paths,
            &mut journal,
            Input::Initial(prepared.projection()),
        )?;
        drop(initial_effects_locked(safe, prepared, keys, &life)?);
        let scoped = ScopedKeychain {
            inner: safe.keychain,
            import_id: prepared.operation(),
            receipts: &paths.masters,
        };
        if let Some(account) = journal.staged_key_account.as_deref() {
            scoped.promote(account)?;
        }
        super::super::step(super::super::PublishStep::MasterPromoted)?;
        publication::active_vault(safe, &paths, &journal)?;
        super::super::step(super::super::PublishStep::VaultSaved)?;
        if journal.phase != Phase::VaultPublished {
            journal.phase = Phase::VaultPublished;
            save(&paths, &journal)?;
        }
        let effects = initial_effects_locked(safe, prepared, keys, &life)?;
        let vault = validate_vault(&store::vault_path(&safe.state_path), safe.keychain)?;
        let finished = prepared.projection().finish_readback(
            keys,
            &vault,
            &journal
                .bindings
                .iter()
                .map(|(id, b)| (id.clone(), b.protected_id.clone()))
                .collect(),
            prepared.operation(),
        )?;
        let mut candidate = finished.candidate().clone();
        candidate
            .local
            .import_receipts
            .insert(prepared.operation().into(), receipt(&journal)?);
        let authority = Publication {
            prepared,
            effects: &effects,
            candidate,
            state_path: safe.state_path.clone(),
            ssh_dir: safe.ssh_dir.clone(),
            vault_digest: journal.staged_vault_digest.clone(),
        };
        prepared.check_effects_locked(safe, keys, &life, &effects)?;
        super::super::step(super::super::PublishStep::BeforeStateSave)?;
        record_runtime::publish_initial_projection(safe, &authority)?;
        super::super::step(super::super::PublishStep::StateSaved)?;
        journal.phase = Phase::Active;
        save(&paths, &journal)?;
        Ok(summary(&journal))
    })
}

/// A successful state save may outlive its phase write or response. Prove the durable receipt
/// and original protected reservation, then finish bookkeeping without touching active data.
pub(in crate::sync) fn complete_saved(
    env: &SyncEnv,
    operation: &str,
) -> Result<PendingImport, AppError> {
    input::with_background(env, |safe| {
        let life = safe.runtime.lifecycle.lock().unwrap();
        let _vault = safe
            .runtime
            .vault
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let _publication = safe.runtime.format_publication.lock().unwrap();
        let (state, _) = record_runtime::snapshot(safe)?;
        let owner = state
            .local
            .central
            .as_ref()
            .ok_or_else(|| failure("saved initial publication has no owner"))?;
        if !owner.control.cutover || state.local.central_projection.is_none() {
            return Err(failure("initial publication has no saved active library"));
        }
        let paths = Paths::new(safe, operation)?;
        let mut journal: Journal =
            serde_json::from_slice(&bounded_read(&paths.journal, MAX_JOURNAL_BYTES)?)
                .map_err(|_| failure("saved initial stage is unreadable"))?;
        validate_header(&journal, operation)?;
        let initial = journal
            .initial
            .as_ref()
            .ok_or_else(|| failure("saved stage has no initial binding"))?;
        if journal.profile != owner.control.profile
            || Some(&journal.anchor) != owner.control.anchor.as_ref()
            || journal.device != owner.control.device
            || journal.identity_slot != owner.identity_slot
            || Some(journal.vault.as_str()) != owner.control.personal_vault.as_deref()
            || !matches_receipt(state.local.import_receipts.get(operation), &journal)?
        {
            return Err(failure(
                "saved initial publication receipt or selected owner differs",
            ));
        }
        if journal.phase == Phase::Active {
            return Ok(summary(&journal));
        }
        let source = bounded_read(&paths.original_state, record_runtime::MAX_STATE_BYTES)?;
        if journal.source_state_digest.as_ref() != Some(&digest(&source)) {
            return Err(failure("saved initial source snapshot changed"));
        }
        let original: SyncStateV3 = serde_json::from_slice(&source)
            .map_err(|_| failure("saved initial source is unreadable"))?;
        crate::sync::records_v3::validate_state(&original)
            .map_err(|_| failure("saved initial source is invalid"))?;
        if !initial.matches_source(&original)? {
            return Err(failure(
                "saved initial source does not match its projection binding",
            ));
        }
        central::verify_initial_saved(
            safe,
            &life,
            owner,
            &original,
            operation,
            initial.manifest(),
            initial.observed(),
        )?;
        journal.phase = Phase::Active;
        save(&paths, &journal)?;
        Ok(summary(&journal))
    })
}
