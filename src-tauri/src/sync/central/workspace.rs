//! Public central account/replica state lives in the existing Records state owned by SyncCore.
use super::{
    client_state::{Phase, State},
    crypto::WrappedKeys,
    rekey::{Checkpoint, SignedRekey, SourceDigest, SourceExtension},
    replica::Replica,
    wire::{invalid, number},
};
use crate::error::AppError;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EpochAcceptance {
    pub from: Checkpoint,
    pub manifest: SignedRekey,
    pub source_suffix: Vec<SourceDigest>,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BootstrapPackage {
    pub wraps: Vec<WrappedKeys>,
    pub submitted: bool,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Workspace {
    pub control: State,
    pub replica: Option<Replica>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recovery: Option<super::recovery_state::RecoveryState>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rotation: Option<super::rotation::Journal>,
    #[serde(default)]
    pub epochs: Vec<SignedRekey>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub observed_epochs: Vec<SignedRekey>,
    pub last_epoch_acceptance: Option<EpochAcceptance>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bootstrap: Option<BootstrapPackage>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub own_wraps: Vec<WrappedKeys>,
}
impl Workspace {
    pub fn new(control: State) -> Result<Self, AppError> {
        let state = Self {
            control,
            replica: None,
            recovery: None,
            rotation: None,
            epochs: vec![],
            observed_epochs: vec![],
            last_epoch_acceptance: None,
            bootstrap: None,
            own_wraps: vec![],
        };
        state.validate()?;
        Ok(state)
    }
    pub fn validate(&self) -> Result<(), AppError> {
        self.control.validate()?;
        if let Some(recovery) = &self.recovery {
            recovery.validate(self)?;
        }
        if self.epochs.len() > 64 || self.observed_epochs.len() > 64 {
            return Err(invalid());
        }
        if self.own_wraps.len() > 65 {
            return Err(invalid());
        }
        if !self.own_wraps.is_empty() {
            let chain = self.control.verified_chain()?;
            let a = chain.current().anchor();
            let mut epochs = BTreeSet::new();
            for wrap in &self.own_wraps {
                let h = &wrap.header;
                if h.origin != a.origin
                    || h.account_id != a.account_id
                    || h.genesis_hash != a.genesis_hash
                    || self.control.personal_vault.as_deref() != Some(h.vault_id.as_str())
                    || h.recipient != self.control.device.id
                    || h.recipient_key != self.control.device.keys.encryption
                    || number(&h.key_epoch, false)? > 65
                    || !epochs.insert(&h.key_epoch)
                    || !chain.contains_device(&h.membership_head, &self.control.device)
                {
                    return Err(invalid());
                }
                let author = chain
                    .author_at(&h.membership_head, &h.author)
                    .ok_or_else(invalid)?;
                wrap.verify_author(&author.signing)?;
            }
        }
        if let Some(package) = &self.bootstrap {
            if !matches!(
                self.control.phase,
                Phase::BackupRequired | Phase::SignedOut | Phase::Revoked
            ) || self.replica.is_some()
            {
                return Err(invalid());
            }
            let chain = self.control.verified_chain()?;
            if self
                .control
                .proof
                .as_ref()
                .ok_or_else(invalid)?
                .genesis
                .first
                != self.control.device
                || package.wraps.len() != 2
                || self.control.recovery_backup_confirmed && !package.submitted
            {
                return Err(invalid());
            }
            let genesis = &self.control.proof.as_ref().ok_or_else(invalid)?.genesis;
            let mut recipients = std::collections::BTreeMap::from([(
                genesis.first.id.clone(),
                genesis.first.keys.clone(),
            )]);
            recipients.insert("recovery".into(), genesis.recovery.clone());
            for wrap in &package.wraps {
                let h = &wrap.header;
                let public = recipients.remove(&h.recipient).ok_or_else(invalid)?;
                if h.origin != self.control.profile.origin
                    || h.account_id != self.control.account_id
                    || self
                        .control
                        .anchor
                        .as_ref()
                        .map(|a| a.genesis_hash.as_str())
                        != Some(h.genesis_hash.as_str())
                    || self.control.personal_vault.as_deref() != Some(h.vault_id.as_str())
                    || h.key_epoch != "1"
                    || h.membership_head != chain.current().anchor().genesis_hash
                    || h.author != self.control.device.id
                    || h.recipient_key != public.encryption
                {
                    return Err(invalid());
                }
                wrap.verify_author(&self.control.device.keys.signing)?;
            }
        }
        if let Some(replica) = &self.replica {
            let chain = self.control.verified_chain()?;
            replica.validate(&chain)?;
            if self.control.phase == Phase::Active && replica.needs_epoch_rebuild {
                return Err(invalid());
            }
            if replica.pending.values().any(|p| {
                p.latest.envelope.header.author != self.control.device.id
                    || p.sent
                        .as_ref()
                        .is_some_and(|sent| sent.envelope.header.author != self.control.device.id)
            }) {
                return Err(invalid());
            }

            if self.control.personal_vault.as_deref() != Some(replica.vault.as_str())
                || replica.checkpoint.epoch != self.epochs.len() as u64 + 1
            {
                return Err(invalid());
            }
            if let Some(confirmation) = &self.control.pairing_confirmation {
                let minimum = confirmation
                    .minimums
                    .iter()
                    .find(|m| m.vault == replica.vault)
                    .ok_or_else(invalid)?;
                let expected = Checkpoint {
                    epoch: number(&minimum.key_epoch, false)?,
                    sequence: number(&minimum.sequence, true)?,
                    history_hash: minimum.history_hash.clone(),
                };
                if replica.creation_head != minimum.creation_head
                    || replica.creation_authorization_epoch
                        != number(&minimum.creation_authorization_epoch, false)?
                    || replica.checkpoint.epoch < expected.epoch
                    || replica.checkpoint.epoch == expected.epoch
                        && replica.minimum.as_ref() != Some(&expected)
                {
                    return Err(invalid());
                }
            }
            let mut revision = chain
                .revision_of(&replica.creation_head)
                .ok_or_else(invalid)?;
            let mut auth = 0;
            let mut sequence = 0;
            let mut ids = BTreeSet::new();
            for (index, manifest) in self.epochs.iter().enumerate() {
                manifest.verify_historical(&chain, &replica.vault)?;
                let b = &manifest.body;
                let next = chain.revision_of(&b.membership_head).ok_or_else(invalid)?;
                let next_auth = number(&b.authorization_epoch, false)?;
                let next_sequence = number(&b.source_sequence, true)?;
                if number(&b.from_epoch, false)? != index as u64 + 1
                    || next < revision
                    || next_auth <= auth
                    || next_sequence < sequence
                    || !ids.insert(&b.rotation_id)
                {
                    return Err(invalid());
                }
                revision = next;
                auth = next_auth;
                sequence = next_sequence;
            }
            if !self.observed_epochs.is_empty() {
                if !self.observed_epochs.starts_with(&self.epochs) {
                    return Err(invalid());
                }
                let mut previous_revision = chain
                    .revision_of(&replica.creation_head)
                    .ok_or_else(invalid)?;
                let mut previous_auth = 0;
                let mut previous_sequence = 0;
                let mut rotations = BTreeSet::new();
                for (index, manifest) in self.observed_epochs.iter().enumerate() {
                    manifest.verify_historical(&chain, &replica.vault)?;
                    let body = &manifest.body;
                    let revision = chain
                        .revision_of(&body.membership_head)
                        .ok_or_else(invalid)?;
                    let auth = number(&body.authorization_epoch, false)?;
                    let sequence = number(&body.source_sequence, true)?;
                    if number(&body.from_epoch, false)? != index as u64 + 1
                        || revision < previous_revision
                        || auth <= previous_auth
                        || sequence < previous_sequence
                        || !rotations.insert(&body.rotation_id)
                    {
                        return Err(invalid());
                    }
                    previous_revision = revision;
                    previous_auth = auth;
                    previous_sequence = sequence;
                }
                if self.control.phase == Phase::Active
                    && (self.observed_epochs.len() != self.epochs.len()
                        || replica.needs_epoch_rebuild)
                {
                    return Err(invalid());
                }
            }
            if let Some(evidence) = &self.last_epoch_acceptance {
                if self.epochs.last() != Some(&evidence.manifest) {
                    return Err(invalid());
                }
                let mut extension = SourceExtension::new(
                    &evidence.manifest,
                    &chain,
                    &replica.vault,
                    &evidence.from,
                )?;
                for page in evidence.source_suffix.chunks(256) {
                    extension.append(page)?;
                }
                let target = extension.finish()?;
                if replica.checkpoint.epoch != target.epoch
                    || replica.checkpoint.sequence < target.sequence
                    || replica.checkpoint.sequence == target.sequence
                        && replica.checkpoint.history_hash != target.history_hash
                {
                    return Err(invalid());
                }
            } else if let Some(last) = self.epochs.last() {
                // A fresh peer never knew the earlier epoch. Its authenticated pairing minimum
                // replaces a source-extension proof only for that initial, already-rotated history.
                let approved_head = if let Some(confirmation) = &self.control.pairing_confirmation {
                    confirmation.approved_head.as_str()
                } else {
                    match self.recovery.as_ref() {
                        Some(super::recovery_state::RecoveryState::Accepted {
                            admission, ..
                        }) => admission.approved_head.as_str(),
                        _ => return Err(invalid()),
                    }
                };
                let minimum = replica.minimum.as_ref().ok_or_else(invalid)?;
                if minimum.epoch != replica.checkpoint.epoch
                    || minimum.sequence < number(&last.body.source_sequence, true)?
                    || chain
                        .revision_of(&last.body.membership_head)
                        .ok_or_else(invalid)?
                        > chain.revision_of(approved_head).ok_or_else(invalid)?
                {
                    return Err(invalid());
                }
            }
        } else if !self.epochs.is_empty()
            || !self.observed_epochs.is_empty()
            || self.last_epoch_acceptance.is_some()
        {
            return Err(invalid());
        }
        if let Some(journal) = &self.rotation {
            if self.control.phase == Phase::Active {
                return Err(invalid());
            }
            journal.validate(self)?;
        }
        Ok(())
    }
    pub fn verify_transition(&self, next: &Self) -> Result<(), AppError> {
        next.validate()?;
        self.control.verify_transition(&next.control)?;
        if let Some(recovery) = &self.recovery {
            recovery.verify_transition(next)?;
        } else if matches!(
            next.recovery,
            Some(super::recovery_state::RecoveryState::Accepted { .. })
        ) {
            return Err(invalid());
        }
        if !next.observed_epochs.starts_with(&self.observed_epochs) {
            return Err(invalid());
        }
        if let Some(journal) = &self.rotation {
            journal.verify_transition(next.rotation.as_ref(), next)?;
        }
        if let Some(before) = &self.bootstrap {
            if next.bootstrap.as_ref().is_some_and(|after| {
                before.wraps != after.wraps || before.submitted && !after.submitted
            }) {
                return Err(invalid());
            }
        }
        for wrap in &self.own_wraps {
            if !next.own_wraps.iter().any(|known| known == wrap) {
                return Err(invalid());
            }
        }

        match (&self.replica, &next.replica) {
            (Some(before), Some(after)) => {
                if before.vault != after.vault
                    || before.creation_head != after.creation_head
                    || before.creation_authorization_epoch != after.creation_authorization_epoch
                {
                    return Err(invalid());
                }
                if after.checkpoint.epoch == before.checkpoint.epoch {
                    if before.needs_epoch_rebuild != after.needs_epoch_rebuild
                        || before.minimum != after.minimum
                        || self.epochs != next.epochs
                        || after.checkpoint.sequence < before.checkpoint.sequence
                        || after.checkpoint.sequence == before.checkpoint.sequence
                            && after.checkpoint.history_hash != before.checkpoint.history_hash
                    {
                        return Err(invalid());
                    }
                } else {
                    if after.checkpoint.epoch != before.checkpoint.epoch + 1
                        || next.epochs.len() != self.epochs.len() + 1
                        || next.epochs[..self.epochs.len()] != self.epochs
                    {
                        return Err(invalid());
                    }
                    let evidence = next.last_epoch_acceptance.as_ref().ok_or_else(invalid)?;
                    if evidence.from != before.checkpoint {
                        return Err(invalid());
                    }
                    let chain = next.control.verified_chain()?;
                    let mut extension = SourceExtension::new(
                        &evidence.manifest,
                        &chain,
                        &after.vault,
                        &before.checkpoint,
                    )?;
                    if evidence.source_suffix.len() > 16384 {
                        return Err(invalid());
                    }
                    if before.minimum.as_ref().is_some_and(|m| {
                        m.sequence
                            > number(&evidence.manifest.body.source_sequence, true).unwrap_or(0)
                    }) {
                        return Err(invalid());
                    }
                    let mut claims = std::collections::BTreeMap::new();
                    for pending in before.pending.values() {
                        if let Some(claim) = &pending.claimed {
                            let sent = pending.sent.as_ref().ok_or_else(invalid)?;
                            if number(&sent.envelope.header.key_epoch, false)?
                                == before.checkpoint.epoch
                            {
                                let seq = number(&claim.sequence, false)?;
                                if seq <= before.checkpoint.sequence
                                    || seq > number(&evidence.manifest.body.source_sequence, true)?
                                {
                                    return Err(invalid());
                                }
                                if claims.insert(seq, claim).is_some() {
                                    return Err(invalid());
                                }
                            }
                        }
                    }
                    for row in &evidence.source_suffix {
                        extension.append(std::slice::from_ref(row))?;
                        let position = extension.position()?;
                        if before.minimum.as_ref().is_some_and(|m| {
                            m.sequence == position.sequence
                                && m.history_hash != position.history_hash
                        }) {
                            return Err(invalid());
                        }

                        if let Some(claim) = claims.remove(&position.sequence) {
                            if claim.digest != row.digest
                                || claim.history_hash != position.history_hash
                            {
                                return Err(invalid());
                            }
                        }
                    }
                    if !claims.is_empty() {
                        return Err(invalid());
                    }
                    // Activation publishes the complete signed target checkpoint, before later normal pulls.
                    if after.minimum.as_ref() != Some(&after.checkpoint) {
                        return Err(invalid());
                    }
                    if extension.finish()? != after.checkpoint {
                        return Err(invalid());
                    }
                }
            }
            (Some(_), None) => return Err(invalid()),
            (None, Some(_))
                if matches!(
                    self.recovery,
                    Some(super::recovery_state::RecoveryState::Pending { .. })
                ) && matches!(
                    next.recovery,
                    Some(super::recovery_state::RecoveryState::Accepted { .. })
                ) =>
            {
                // The preceding typed journal transition requires the exact fully admitted cache,
                // immutable kit-signed minimum, epoch trail and own next-head bridge wrap.
            }
            (None, Some(after)) => {
                if after.checkpoint.sequence != 0
                    || after.checkpoint.history_hash != "0".repeat(64)
                    || !after.current.is_empty()
                {
                    return Err(invalid());
                }
                if next.control.pairing_confirmation.is_none()
                    && (after.checkpoint.epoch != 1 || !next.epochs.is_empty())
                {
                    return Err(invalid());
                }
            }
            (None, None) => {}
        }
        Ok(())
    }
    pub fn require_key_recipients(&self) -> Result<(), AppError> {
        if self.recovery.as_ref().is_some_and(|r| r.requires_cleanup()) {
            return Err(AppError::Other(
                "Finish recovery credential cleanup before publishing content keys.".into(),
            ));
        }
        self.control.require_key_recipients()
    }
    pub fn can_upload(&self) -> bool {
        !self.recovery.as_ref().is_some_and(|r| r.requires_cleanup())
            && self.control.cloud_writes_allowed()
            && self.rotation.is_none()
            && (self.observed_epochs.is_empty() || self.observed_epochs.len() == self.epochs.len())
            && self.replica.as_ref().is_some_and(|r| {
                r.baseline_ready()
                    && self.control.verified_chain().is_ok_and(|chain| {
                        r.verify_write_authority(
                            &chain,
                            self.control.auth_epoch,
                            r.checkpoint.epoch,
                            &self.epochs,
                        )
                        .is_ok()
                    })
            })
            && self.validate().is_ok()
    }
}
/// Called by every Records publication path. Logout preserves the pinned root and encrypted outbox.
pub fn verify_publication(
    before: Option<&Workspace>,
    after: Option<&Workspace>,
) -> Result<(), AppError> {
    match (before, after) {
        (Some(before), Some(after)) => before.verify_transition(after),
        (Some(before), None)
            if before.control.anchor.is_some()
                || before.control.cutover
                || before.recovery.is_some() =>
        {
            Err(invalid())
        }
        (None, Some(after)) if after.recovery.is_some() => Err(invalid()),
        (_, Some(after)) => after.validate(),
        _ => Ok(()),
    }
}
#[cfg(test)]
pub(crate) mod tests {
    use super::super::{
        client_state::ProfileData, credentials::Profile, oidc::OidcConfig, trust::ControlProof,
    };
    use super::*;
    pub(crate) fn enrolled() -> Workspace {
        let f: serde_json::Value =
            serde_json::from_str(include_str!("../../../../fixtures/central-sync-v2.json"))
                .unwrap();
        let proof = ControlProof {
            genesis: serde_json::from_value(f["genesis"].clone()).unwrap(),
            nodes: vec![],
        };
        let profile =
            Profile::new(&proof.genesis.origin, "https://identity.test", "opaque").unwrap();
        let control = State::new(
            ProfileData {
                origin: profile.origin,
                issuer: profile.issuer.clone(),
                subject: profile.subject,
                locator: profile.locator,
                oidc: OidcConfig {
                    issuer: profile.issuer,
                    client_id: "native".into(),
                    audience: Some("api".into()),
                    scopes: vec!["lunport:sync".into()],
                },
            },
            proof.genesis.account_id.clone(),
            proof.genesis.first.clone(),
            1,
        )
        .unwrap();
        let control = control
            .prepare_bootstrap(
                proof,
                serde_json::from_value(f["anchor"].clone()).unwrap(),
                "c".repeat(64),
            )
            .unwrap()
            .confirm_backup()
            .unwrap()
            .finish_bootstrap()
            .unwrap();
        let mut workspace = Workspace::new(control).unwrap();
        workspace.replica = Some(
            Replica::new(
                "c".repeat(64),
                workspace.control.highwater.as_ref().unwrap().head.clone(),
                workspace.control.auth_epoch,
            )
            .unwrap(),
        );
        workspace.validate().unwrap();
        workspace
    }
    #[test]
    fn account_root_replica_and_cutover_cannot_be_removed_or_rolled_back_by_a_later_publication() {
        let mut first = enrolled();
        assert!(!first.can_upload());
        first.control.cutover = true;
        let head = first.control.highwater.as_ref().unwrap().head.clone();
        first.control = first
            .control
            .approve_library("d".repeat(64), &head)
            .unwrap();
        assert!(first.can_upload());
        assert!(verify_publication(Some(&first), None).is_err());
        let mut next = first.clone();
        next.control.cutover = false;
        assert!(first.verify_transition(&next).is_err());
        let mut next = first.clone();
        next.replica = None;
        assert!(first.verify_transition(&next).is_err());
        let mut next = first.clone();
        next.replica.as_mut().unwrap().checkpoint.history_hash = "9".repeat(64);
        assert!(first.verify_transition(&next).is_err());
        let mut next = first.clone();
        next.control.phase = super::super::client_state::Phase::SignedOut;
        first.verify_transition(&next).unwrap();
        assert!(!next.can_upload());
        assert_eq!(first.replica, next.replica);
    }
    #[test]
    fn a_cloud_access_barrier_at_the_same_signed_head_cannot_resume_old_key_writes() {
        let mut first = enrolled();
        first.control.cutover = true;
        let head = first.control.highwater.as_ref().unwrap().head.clone();
        first.control = first
            .control
            .approve_library("d".repeat(64), &head)
            .unwrap();
        assert!(first.can_upload());
        let mut next = first.clone();
        next.control = first
            .control
            .observe_proof(first.control.proof.clone().unwrap(), 2)
            .unwrap();
        assert_eq!(next.control.phase, super::super::client_state::Phase::Rekey);
        assert!(!next.can_upload());
        next.control.phase = super::super::client_state::Phase::Active;
        assert!(!next.can_upload());
        let chain = next.control.verified_chain().unwrap();
        assert!(next
            .replica
            .as_mut()
            .unwrap()
            .prepare_send(&chain, 1, 2, &[])
            .is_err());
    }
    #[test]
    fn rekey_activation_proves_inflight_receipt_inclusion_before_clearing_its_old_ciphertext() {
        use super::super::{
            crypto::{self, VaultKeys},
            rekey::{SourceDigest, Version},
            replica::{Draft, Pending, Receipt},
        };
        let f: serde_json::Value =
            serde_json::from_str(include_str!("../../../../fixtures/central-rekey-v2.json"))
                .unwrap();
        let original: serde_json::Value =
            serde_json::from_str(include_str!("../../../../fixtures/central-sync-v2.json"))
                .unwrap();
        let source: Vec<Version> = serde_json::from_value(f["source_rows"].clone()).unwrap();
        let target: Vec<Version> = serde_json::from_value(f["target_rows"].clone()).unwrap();
        let manifest: SignedRekey = serde_json::from_value(f["manifest"].clone()).unwrap();
        let mut before = enrolled();
        let proof = serde_json::from_value(f["proof"].clone()).unwrap();
        before.control = before.control.observe_proof(proof, 4).unwrap();
        before.control.cutover = true;
        let head = before.control.highwater.as_ref().unwrap().head.clone();
        before.control = before
            .control
            .approve_library("d".repeat(64), &head)
            .unwrap();
        before.control.phase = super::super::client_state::Phase::Rekey;
        let sent = Draft {
            local_revision: 1,
            content_hash: crypto::hash(original["plaintext"].as_str().unwrap().as_bytes()),
            envelope: source[0].envelope.clone(),
        };
        let receipt = Receipt {
            operation_id: sent.envelope.header.operation_id.clone(),
            record_id: sent.envelope.header.record_id.clone(),
            revision: source[0].revision.clone(),
            sequence: source[0].sequence.clone(),
            digest: source[0].digest.clone(),
            history_hash: source[0].history_hash.clone(),
        };
        before.replica.as_mut().unwrap().pending.insert(
            receipt.record_id.clone(),
            Pending {
                latest: sent.clone(),
                sent: Some(sent),
                claimed: Some(receipt),
            },
        );
        before.validate().unwrap();
        let chain = before.control.verified_chain().unwrap();
        let wraps = serde_json::from_value::<Vec<super::super::crypto::WrappedKeys>>(
            f["target_wraps"].clone(),
        )
        .unwrap();
        use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
        let signer = super::super::crypto::DeviceKeys::decode_secret(&B64.encode([1; 64])).unwrap();
        let keys: VaultKeys = super::super::rekey::open_committed_keys(
            &chain,
            &manifest,
            &wraps,
            &before.control.device.id,
            &signer,
        )
        .unwrap();
        let mut staging = before.replica.clone().unwrap();
        staging.checkpoint.epoch = 2;
        staging.minimum = Some(Checkpoint {
            epoch: 2,
            sequence: 2,
            history_hash: manifest.body.target_history_hash.clone(),
        });
        let target_checkpoint = Checkpoint {
            epoch: 2,
            sequence: 2,
            history_hash: manifest.body.target_history_hash.clone(),
        };
        let page = staging
            .prepare_page(&chain, &keys, &target, &target_checkpoint)
            .unwrap();
        assert!(page.next.pending.is_empty());
        let mut after = before.clone();
        after.replica = Some(page.next);
        after.epochs.push(manifest.clone());
        after.last_epoch_acceptance = Some(EpochAcceptance {
            from: before.replica.as_ref().unwrap().checkpoint.clone(),
            manifest,
            source_suffix: source
                .iter()
                .map(|r| SourceDigest {
                    sequence: r.sequence.clone(),
                    digest: r.digest.clone(),
                })
                .collect(),
        });
        before.verify_transition(&after).unwrap();
        let mut forked = before.clone();
        forked
            .replica
            .as_mut()
            .unwrap()
            .pending
            .values_mut()
            .next()
            .unwrap()
            .claimed
            .as_mut()
            .unwrap()
            .history_hash = "9".repeat(64);
        assert!(forked.verify_transition(&after).is_err());
    }
    #[test]
    fn a_new_peer_uses_its_authenticated_post_rekey_minimum_without_inventing_an_old_checkpoint() {
        use super::super::{
            crypto::DeviceKeys,
            membership::{Action, MembershipBody, SignedMembership},
            pairing::{PairingInvite, PendingPairing, VaultMinimum},
            replica::Replica,
        };
        use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
        let fixture: serde_json::Value =
            serde_json::from_str(include_str!("../../../../fixtures/central-rekey-v2.json"))
                .unwrap();
        let mut proof: ControlProof = serde_json::from_value(fixture["proof"].clone()).unwrap();
        let anchor = serde_json::from_value(fixture["anchor"].clone()).unwrap();
        let chain = proof.verify(&anchor, None).unwrap();
        let signer = DeviceKeys::decode_secret(&B64.encode([1; 64])).unwrap();
        let peer = DeviceKeys::generate().unwrap();
        let pending =
            PendingPairing::begin(&anchor, &"e".repeat(32), &peer, 1_700_000_000_000).unwrap();
        let mut members = chain.current().devices().clone();
        members.insert(pending.request().device.id.clone(), peer.public());
        let node = SignedMembership::sign(
            MembershipBody {
                origin: anchor.origin.clone(),
                account_id: anchor.account_id.clone(),
                genesis_hash: anchor.genesis_hash.clone(),
                revision: (chain.current().revision() + 1).to_string(),
                previous_head: chain.current().head().into(),
                author: proof.genesis.first.id.clone(),
                action: Action::Add,
                issued_at_ms: "1700000000001".into(),
                enrollment: Some(pending.request().clone()),
                devices: members,
                recovery: chain.current().recovery().clone(),
            },
            &signer,
        )
        .unwrap();
        let manifest: SignedRekey = serde_json::from_value(fixture["manifest"].clone()).unwrap();
        let minimum = VaultMinimum {
            vault: manifest.body.vault_id.clone(),
            creation_head: anchor.genesis_hash.clone(),
            creation_authorization_epoch: "2".into(),
            key_epoch: "2".into(),
            sequence: manifest.body.source_sequence.clone(),
            history_hash: manifest.body.target_history_hash.clone(),
        };
        let invite = PairingInvite::from_code(
            &pending.code().unwrap(),
            pending.request(),
            &anchor,
            1_700_000_000_001,
        )
        .unwrap();
        let confirmation = invite
            .confirm(
                chain.current(),
                &node,
                &minimum.vault,
                vec![minimum.clone()],
            )
            .unwrap();
        proof.nodes.push(node);
        let state = State::new(
            enrolled().control.profile,
            anchor.account_id.clone(),
            pending.request().device.clone(),
            5,
        )
        .unwrap()
        .begin_pairing(&pending)
        .unwrap()
        .accept_pairing(&pending, &confirmation, proof)
        .unwrap();
        let mut ws = Workspace::new(state).unwrap();
        ws.epochs = vec![manifest];
        ws.replica = Some(
            Replica::join(
                minimum.vault.clone(),
                minimum.creation_head.clone(),
                2,
                Checkpoint {
                    epoch: 2,
                    sequence: 2,
                    history_hash: minimum.history_hash,
                },
            )
            .unwrap(),
        );
        ws.validate().unwrap();
        assert!(!ws.can_upload());
        assert!(!ws.replica.as_ref().unwrap().baseline_ready());
        let mut invalid = ws.clone();
        invalid
            .control
            .pairing_confirmation
            .as_mut()
            .unwrap()
            .minimums[0]
            .sequence = "1".into();
        invalid
            .replica
            .as_mut()
            .unwrap()
            .minimum
            .as_mut()
            .unwrap()
            .sequence = 1;
        assert!(invalid.validate().is_err());
        let mut invalid = ws.clone();
        invalid.control.pairing_confirmation = None;
        assert!(invalid.validate().is_err());
        assert!(enrolled().verify_transition(&ws).is_err());
    }
}
