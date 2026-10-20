//! The only intended exception to ordinary identity/selector immutability.
//! Archive metadata is public; private identity/session/content keys never belong here.
use super::{
    membership::{Action, Device},
    rekey::Checkpoint,
    replacement::Route,
    replacement_archive::Receipt,
    trust::Highwater,
    wire::{hex, invalid, MAX_SAFE_INTEGER},
    workspace::Workspace,
};
use crate::error::AppError;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Archive {
    pub receipt: Receipt,
    pub previous_selection: Option<String>,
    pub highwater: Option<Highwater>,
    pub minimums: Vec<Checkpoint>,
    pub creation_head: Option<String>,
    pub creation_authorization_epoch: Option<u64>,
    pub target: Device,
    pub approved_head: String,
    pub route: Route,
    pub needs_reconciliation: bool,
}
impl Archive {
    pub fn validate(&self, owner: &Workspace) -> Result<(), AppError> {
        self.receipt.validate()?;
        let context = &self.receipt.context;
        let control = &owner.control;
        let anchor = control.anchor.as_ref().ok_or_else(invalid)?;
        let chain = control.verified_chain()?;
        self.target.keys.validate()?;
        if context.origin != control.profile.origin
            || context.locator != control.profile.locator
            || context.account != control.account_id
            || context
                .genesis
                .as_ref()
                .is_some_and(|root| root != &anchor.genesis_hash)
            || !hex(&self.target.id, 32)
            || self.target.id == context.device.id
            || self.target.keys.signing == context.device.keys.signing
            || self.target.keys.encryption == context.device.keys.encryption
            || self
                .previous_selection
                .as_ref()
                .is_some_and(|value| !hex(value, 32) || value == &context.operation)
            || !hex(&self.approved_head, 64)
            || !chain.contains_device(&self.approved_head, &self.target)
            || self.minimums.len() > 2
        {
            return Err(invalid());
        }
        let revision = chain.revision_of(&self.approved_head).ok_or_else(invalid)?;
        let node = control
            .proof
            .as_ref()
            .ok_or_else(invalid)?
            .nodes
            .get(revision.checked_sub(1).ok_or_else(invalid)?)
            .ok_or_else(invalid)?;
        if node.body.action
            != match self.route {
                Route::TrustedDevice => Action::Add,
                Route::RecoveryKit => Action::Recover,
            }
            || node
                .body
                .enrollment
                .as_ref()
                .is_none_or(|request| request.device != self.target)
        {
            return Err(invalid());
        }
        if let Some(highwater) = &self.highwater {
            if context.genesis.is_none()
                || chain.revision_of(&highwater.head) != usize::try_from(highwater.revision).ok()
            {
                return Err(invalid());
            }
        }
        if context.genesis.is_none() && (!self.minimums.is_empty() || self.highwater.is_some()) {
            return Err(invalid());
        }
        match (
            &self.creation_head,
            self.creation_authorization_epoch,
            self.minimums.is_empty(),
        ) {
            (None, None, true) => {}
            (Some(head), Some(epoch), false)
                if chain.has_head(head) && epoch > 0 && epoch <= MAX_SAFE_INTEGER => {}
            _ => return Err(invalid()),
        }
        for minimum in &self.minimums {
            if !(1..=65).contains(&minimum.epoch)
                || minimum.sequence > 16384
                || !hex(&minimum.history_hash, 64)
                || minimum.sequence == 0 && minimum.history_hash != "0".repeat(64)
            {
                return Err(invalid());
            }
        }
        Ok(())
    }
}

/// Native-only authority. It owns the completed read and exact independently registered session.
/// Public Workspace/Archive/Intent values cannot construct it.
pub(crate) struct Authorization {
    operation: String,
    session: std::sync::Arc<super::controller::Session>,
    read: super::active_read::VerifiedLibrary,
    source_bridges: Vec<super::recovery_revalidation::Bridge>,
    candidate: Workspace,
}
impl Authorization {
    pub(super) fn prepare(
        env: &crate::sync::env::SyncEnv,
        session: std::sync::Arc<super::controller::Session>,
        read: super::active_read::VerifiedLibrary,
        own_bridges: Vec<super::recovery_revalidation::Bridge>,
        source_bridges: Vec<super::recovery_revalidation::Bridge>,
    ) -> Result<Self, AppError> {
        super::controller::require_enabled()?;
        let source = super::owner::OwnerPath::Current.snapshot(env)?;
        let intent = source.replacement.as_ref().ok_or_else(invalid)?;
        let staged = intent.candidate.as_deref().ok_or_else(invalid)?;
        if staged != read.previous_owner()
            || source.control.phase == super::client_state::Phase::SignedOut
        {
            return Err(invalid());
        }
        let identity = session.identity.as_ref().ok_or_else(invalid)?;
        let grant = session.device.as_ref().ok_or_else(invalid)?;
        let profile = source.control.profile.profile()?;
        let stored = super::credentials::DeviceIdentity::load_selected(
            env.keychain,
            &profile,
            Some(&intent.operation),
            true,
        )?;
        if session.device_access_denied
            || session.profile != source.control.profile
            || identity.device() != staged.control.device
            || stored.device() != identity.device()
            || stored.credential() != identity.credential()
            || identity.slot(&profile, "device")?
                != profile.device_slot("device", Some(&intent.operation))?
            || grant.account_id != source.control.account_id
            || grant.device_state != super::api::DeviceState::Active
            || grant.auth_epoch != read.auth_epoch()
            || grant.expired()
        {
            return Err(invalid());
        }
        match intent.route {
            Route::TrustedDevice => {
                if staged.recovery.is_some() || intent.recovery_confirmation.is_some() {
                    return Err(invalid());
                }
                let confirmation = staged
                    .control
                    .pairing_confirmation
                    .as_ref()
                    .ok_or_else(invalid)?;
                let pending = super::controller::load_pairing(
                    env,
                    &profile,
                    identity,
                    &confirmation.request_id,
                )?;
                pending.accept(confirmation, read.proof())?;
            }
            Route::RecoveryKit => {
                let Some(super::recovery_state::RecoveryState::Accepted {
                    operation,
                    admission,
                    ..
                }) = staged.recovery.as_ref()
                else {
                    return Err(invalid());
                };
                if operation != &intent.operation
                    || intent.recovery_confirmation.as_ref() != Some(admission)
                {
                    return Err(invalid());
                }
                admission.verify(read.proof())?;
            }
        }
        super::replacement_proof::active_read(&source, &read, &source_bridges)?;
        let mut candidate = staged.clone();
        candidate.control.proof = Some(read.proof().clone());
        candidate.control.highwater = Some(read.chain().highwater());
        candidate.control.auth_epoch = read.auth_epoch();
        candidate
            .control
            .denied_devices
            .extend(source.control.denied_devices.iter().cloned());
        candidate
            .control
            .denied_devices
            .insert(source.control.device.id.clone());
        candidate.control.cutover = source.control.cutover;
        candidate.control.library = source.control.library.clone();
        candidate.replica = Some(read.replica().clone());
        candidate.epochs = read.epochs().to_vec();
        candidate.observed_epochs = vec![];
        if let Some((floors, _, _)) = super::replacement_proof::minimums(staged)? {
            let mut known = floors[0].clone();
            for bridge in &own_bridges {
                let mut digests = vec![];
                for row in &bridge.digests {
                    if super::wire::number(&row.sequence, false)? > known.sequence {
                        digests.push(row.clone());
                    }
                }
                let selected = super::recovery_revalidation::Bridge {
                    epoch: bridge.epoch,
                    digests,
                };
                let next = super::recovery_revalidation::finish_bridge(
                    read.chain(),
                    &read.replica().vault,
                    read.epochs(),
                    &known,
                    &selected,
                )?;
                candidate.last_epoch_acceptance = Some(super::workspace::EpochAcceptance {
                    from: known,
                    manifest: super::recovery_revalidation::manifest(read.epochs(), bridge.epoch)?
                        .clone(),
                    source_suffix: selected.digests,
                });
                known = next;
            }
        }
        candidate.own_wraps.retain(|wrap| {
            super::wire::number(&wrap.header.key_epoch, false).ok() != Some(read.checkpoint().epoch)
        });
        candidate.own_wraps.push(read.wrap().clone());
        let ready = read.phase() == "ready"
            && candidate.control.require_key_recipients().is_ok()
            && read
                .replica()
                .verify_write_authority(
                    read.chain(),
                    read.auth_epoch(),
                    read.checkpoint().epoch,
                    read.epochs(),
                )
                .is_ok();
        candidate.control.phase = if !ready {
            super::client_state::Phase::Rekey
        } else if candidate.control.cutover && candidate.control.library.is_some() {
            super::client_state::Phase::Active
        } else {
            super::client_state::Phase::Enrolled
        };
        candidate.validate()?;
        Ok(Self {
            operation: intent.operation.clone(),
            session,
            read,
            source_bridges,
            candidate,
        })
    }
    /// Archive the latest full Core outside publication/Core locks. Local edits may win this
    /// race; retry only a superseded generation, never an I/O or authorization failure.
    /// The caller owns the existing lifecycle gate through the final publication.
    pub(super) fn publish(
        &self,
        env: &crate::sync::env::SyncEnv,
        lifecycle: &std::sync::MutexGuard<'_, ()>,
    ) -> Result<u64, AppError> {
        for _ in 0..3 {
            let (source, generation) = crate::sync::record_runtime::snapshot(env)?;
            self.source(source.local.central.as_ref().ok_or_else(invalid)?)?;
            let archive = super::replacement_archive::prepare(
                env,
                lifecycle,
                &source,
                generation,
                &self.operation,
            )?;
            match crate::sync::record_runtime::publish_replacement(env, self, archive) {
                Err(error) if crate::sync::runtime::is_superseded(&error) => continue,
                result => return result,
            }
        }
        Err(crate::sync::runtime::superseded())
    }
    pub(crate) fn session(&self) -> &std::sync::Arc<super::controller::Session> {
        &self.session
    }
    /// Recheck the latest source after HTTP and archive I/O; independent local B is retained.
    pub(crate) fn source(&self, source: &Workspace) -> Result<(), AppError> {
        let intent = source.replacement.as_ref().ok_or_else(invalid)?;
        if intent.operation != self.operation
            || intent.candidate.as_deref() != Some(self.read.previous_owner())
            || source.control.phase == super::client_state::Phase::SignedOut
            || self
                .session
                .device
                .as_ref()
                .is_none_or(|grant| grant.expired())
        {
            return Err(invalid());
        }
        super::replacement_proof::active_read(source, &self.read, &self.source_bridges)
    }
    pub(crate) fn candidate(
        &self,
        source: &Workspace,
        receipt: Receipt,
    ) -> Result<Workspace, AppError> {
        self.source(source)?;
        if receipt.context.operation != self.operation
            || receipt.context.device != source.control.device
        {
            return Err(invalid());
        }
        let mut candidate = self.candidate.clone();
        // A newer local denial/consent state cannot disappear while the archive is being written.
        candidate
            .control
            .denied_devices
            .extend(source.control.denied_devices.iter().cloned());
        candidate.control.cutover = source.control.cutover;
        candidate.control.library = source.control.library.clone();
        if self
            .read
            .chain()
            .current()
            .devices()
            .keys()
            .any(|id| candidate.control.denied_devices.contains(id))
        {
            candidate.control.phase = super::client_state::Phase::Rekey;
        }
        let (minimums, creation_head, creation_authorization_epoch) =
            match super::replacement_proof::minimums(source)? {
                Some((minimums, head, epoch)) => (minimums, Some(head), Some(epoch)),
                None => (vec![], None, None),
            };
        let intent = source.replacement.as_ref().ok_or_else(invalid)?;
        let approved_head = match intent.route {
            Route::TrustedDevice => candidate
                .control
                .pairing_confirmation
                .as_ref()
                .ok_or_else(invalid)?
                .approved_head
                .clone(),
            Route::RecoveryKit => candidate
                .recovery
                .as_ref()
                .ok_or_else(invalid)?
                .admission()
                .approved_head
                .clone(),
        };
        // Even a clean old cache has device-bound local-material receipts. Rebuild its live
        // projection through reviewed reconciliation before allowing the new identity to sync.
        candidate.replacement_archives = source.replacement_archives.clone();
        candidate.replacement_archives.push(Archive {
            receipt,
            previous_selection: source.identity_slot.clone(),
            highwater: source.control.highwater.clone(),
            minimums,
            creation_head,
            creation_authorization_epoch,
            target: candidate.control.device.clone(),
            approved_head,
            route: intent.route,
            needs_reconciliation: true,
        });
        candidate.validate()?;
        Ok(candidate)
    }
    pub(crate) fn records(
        &self,
        source: &crate::sync::records_v3::SyncStateV3,
        receipt: Receipt,
    ) -> Result<crate::sync::records_v3::SyncStateV3, AppError> {
        let owner = source.local.central.as_ref().ok_or_else(invalid)?;
        let mut next = source.clone();
        next.local.central = Some(self.candidate(owner, receipt.clone())?);
        if source.local.central_projection.is_some() || source.local.central_cache_source.is_some()
        {
            next.local.central_projection = None;
            next.local.central_cache_source = Some(Box::new(receipt));
        }
        next.local.credential_approvals.clear();
        next.version = next
            .version
            .max(crate::sync::records_v3::CENTRAL_STATE_VERSION);
        crate::sync::records_v3::validate_state(&next).map_err(|_| invalid())?;
        Ok(next)
    }
    pub(crate) fn verify_records(
        &self,
        source: &crate::sync::records_v3::SyncStateV3,
        next: &crate::sync::records_v3::SyncStateV3,
        archive: &super::replacement_archive::Permit,
        generation: u64,
    ) -> Result<(), AppError> {
        archive.verify_source(source, generation)?;
        if &self.records(source, archive.receipt().clone())? != next {
            return Err(invalid());
        }
        Ok(())
    }
}
