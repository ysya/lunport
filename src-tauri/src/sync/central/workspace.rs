//! Public central account/replica state lives in the existing Records state owned by SyncCore.
use super::{
    client_state::State,
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
pub struct Workspace {
    pub control: State,
    pub replica: Option<Replica>,
    #[serde(default)]
    pub epochs: Vec<SignedRekey>,
    pub last_epoch_acceptance: Option<EpochAcceptance>,
}
impl Workspace {
    pub fn new(control: State) -> Result<Self, AppError> {
        let state = Self {
            control,
            replica: None,
            epochs: vec![],
            last_epoch_acceptance: None,
        };
        state.validate()?;
        Ok(state)
    }
    pub fn validate(&self) -> Result<(), AppError> {
        self.control.validate()?;
        if self.epochs.len() > 64 {
            return Err(invalid());
        }
        if let Some(replica) = &self.replica {
            let chain = self.control.verified_chain()?;
            replica.validate(&chain)?;
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
            } else if !self.epochs.is_empty() {
                return Err(invalid());
            }
        } else if !self.epochs.is_empty() || self.last_epoch_acceptance.is_some() {
            return Err(invalid());
        }
        Ok(())
    }
    pub fn verify_transition(&self, next: &Self) -> Result<(), AppError> {
        next.validate()?;
        self.control.verify_transition(&next.control)?;
        match (&self.replica, &next.replica) {
            (Some(before), Some(after)) => {
                if before.vault != after.vault
                    || before.creation_head != after.creation_head
                    || before.creation_authorization_epoch != after.creation_authorization_epoch
                {
                    return Err(invalid());
                }
                if after.checkpoint.epoch == before.checkpoint.epoch {
                    if before.minimum != after.minimum
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
    pub fn can_upload(&self) -> bool {
        self.control.cloud_writes_allowed()
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
        (Some(before), None) if before.control.anchor.is_some() || before.control.cutover => {
            Err(invalid())
        }
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
}
