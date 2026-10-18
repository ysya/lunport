//! Public, crash-resumable recovery journal and the immutable kit-signed initial replica minimum.
//! Private kit strings live in protected OS entries owned by the foreground recovery driver.
use super::{
    client_state::Phase,
    crypto::{self, DeviceKeys, WrappedKeys},
    membership::{personal_vault_id, Action, Device, SignedMembership, TrustAnchor},
    recovery::{RecoveryKit, RecoverySeed},
    recovery_read::VerifiedRecovery,
    rekey::{Checkpoint, SignedRekey},
    replica::Replica,
    trust::{ControlProof, VerifiedChain},
    wire::{canonical, hex, invalid, number, WrapHeader, MAX_SAFE_INTEGER},
    workspace::Workspace,
};
use crate::error::AppError;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Admission {
    pub anchor: TrustAnchor,
    pub previous_head: String,
    pub approved_head: String,
    pub request_id: String,
    pub device: Device,
    pub vault: String,
    pub checkpoint: Checkpoint,
    pub authorization_epoch: u64,
    pub signature: String,
}
impl Admission {
    fn canonical(&self) -> Result<Vec<u8>, AppError> {
        self.device.keys.validate()?;
        if !hex(&self.device.id, 32) {
            return Err(invalid());
        }
        if ![
            &self.previous_head,
            &self.approved_head,
            &self.checkpoint.history_hash,
        ]
        .iter()
        .all(|v| hex(v, 64))
            || !hex(&self.request_id, 32)
            || self.vault != personal_vault_id(&self.anchor)?
            || self.authorization_epoch < 2
            || self.authorization_epoch >= MAX_SAFE_INTEGER
            || self.checkpoint.epoch == 0
            || self.checkpoint.epoch > 65
            || self.checkpoint.sequence > 16384
            || self.checkpoint.sequence == 0 && self.checkpoint.history_hash != "0".repeat(64)
        {
            return Err(invalid());
        }
        canonical(&[
            "lunport-recovery-admission-v2",
            &self.anchor.origin,
            &self.anchor.account_id,
            &self.anchor.genesis_hash,
            &self.previous_head,
            &self.approved_head,
            &self.request_id,
            &self.device.id,
            &self.device.keys.signing,
            &self.device.keys.encryption,
            &self.vault,
            &self.checkpoint.epoch.to_string(),
            &self.checkpoint.sequence.to_string(),
            &self.checkpoint.history_hash,
            &self.authorization_epoch.to_string(),
        ])
    }
    pub fn verify(&self, proof: &ControlProof) -> Result<VerifiedChain, AppError> {
        let chain = proof.verify(&self.anchor, None)?;
        let revision = chain.revision_of(&self.approved_head).ok_or_else(invalid)?;
        let node = proof
            .nodes
            .get(revision.checked_sub(1).ok_or_else(invalid)?)
            .ok_or_else(invalid)?;
        if node.body.action != Action::Recover
            || node.body.author != "recovery"
            || node.body.previous_head != self.previous_head
            || node
                .body
                .enrollment
                .as_ref()
                .is_none_or(|r| r.request_id != self.request_id || r.device != self.device)
        {
            return Err(invalid());
        }
        let authority = chain.recovery_at(&self.previous_head).ok_or_else(invalid)?;
        crypto::verify(&authority.signing, &self.canonical()?, &self.signature)?;
        Ok(chain)
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Package {
    #[serde(default)]
    pub attempt: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revalidation: Option<super::recovery_revalidation::Evidence>,
    pub operation: String,
    pub source_proof: ControlProof,
    pub node: SignedMembership,
    pub admission: Admission,
    pub wraps: Vec<WrappedKeys>,
    pub replica: Replica,
    pub epochs: Vec<SignedRekey>,
    pub backup_confirmed: bool,
    pub submitted: bool,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "phase", rename_all = "snake_case", deny_unknown_fields)]
pub enum RecoveryState {
    Pending {
        package: Box<Package>,
    },
    Accepted {
        operation: String,
        admission: Admission,
        credentials_cleared: bool,
    },
}
/// Native-only prepared result. A server DTO cannot mint the completed-read capability used here.
pub struct PreparedRecovery {
    pub package: Package,
    pub kit: RecoveryKit,
}
impl PreparedRecovery {
    pub fn create(
        read: VerifiedRecovery,
        old_kit: &RecoveryKit,
        identity: &DeviceKeys,
        seed: RecoverySeed,
        operation: String,
        now: u64,
    ) -> Result<Self, AppError> {
        if !hex(&operation, 32) || identity.public() != read.request().device.keys {
            return Err(invalid());
        }
        read.request().verify_live(now)?;
        let old = old_kit.current_keys(read.chain())?;
        let anchor = read.chain().current().anchor();
        let recovery = seed.keys(&anchor.origin, &anchor.account_id)?;
        let node = SignedMembership::sign(
            read.chain().current().proposal(
                "recovery",
                Action::Recover,
                Some(read.request().clone()),
                BTreeMap::from([(read.request().device.id.clone(), identity.public())]),
                recovery.public(),
                now,
            ),
            &old,
        )?;
        let mut proof = read.proof().clone();
        proof.nodes.push(node.clone());
        let chain = proof.verify(anchor, Some(&read.chain().highwater()))?;
        let kit = seed.bind(&chain)?;
        let mut admission = Admission {
            anchor: anchor.clone(),
            previous_head: read.chain().current().head().into(),
            approved_head: chain.current().head().into(),
            request_id: read.request().request_id.clone(),
            device: read.request().device.clone(),
            vault: read.replica().vault.clone(),
            checkpoint: read.checkpoint().clone(),
            authorization_epoch: read.auth_epoch(),
            signature: String::new(),
        };
        admission.signature = old.sign(&admission.canonical()?);
        let mut wraps = vec![];
        for (recipient, public) in [
            (admission.device.id.as_str(), identity.public()),
            ("recovery", recovery.public()),
        ] {
            wraps.push(crypto::wrap_keys(
                read.keys(),
                identity,
                WrapHeader {
                    origin: anchor.origin.clone(),
                    account_id: anchor.account_id.clone(),
                    genesis_hash: anchor.genesis_hash.clone(),
                    vault_id: admission.vault.clone(),
                    key_epoch: admission.checkpoint.epoch.to_string(),
                    membership_head: admission.approved_head.clone(),
                    author: admission.device.id.clone(),
                    recipient: recipient.into(),
                    recipient_key: public.encryption,
                },
            )?);
        }
        let package = Package {
            attempt: 0,
            revalidation: None,
            operation,
            source_proof: read.proof().clone(),
            node,
            admission,
            wraps,
            replica: read.replica().clone(),
            epochs: read.epochs().to_vec(),
            backup_confirmed: false,
            submitted: false,
        };
        package.validate(read.previous_owner())?;
        Ok(Self { package, kit })
    }
}
impl Package {
    pub fn proof(&self) -> ControlProof {
        let mut proof = self.source_proof.clone();
        proof.nodes.push(self.node.clone());
        proof
    }
    pub fn validate(&self, owner: &Workspace) -> Result<(), AppError> {
        if self.attempt > MAX_SAFE_INTEGER
            || self.attempt == 0 && self.revalidation.is_some()
            || self.attempt > 0 && self.revalidation.is_none()
            || !hex(&self.operation, 32)
            || owner.control.anchor.is_some()
            || owner.control.cutover
            || owner.control.library.is_some()
            || owner.replica.is_some()
            || owner.bootstrap.is_some()
            || !matches!(
                owner.control.phase,
                Phase::AwaitingApproval | Phase::SignedOut | Phase::Revoked
            )
            || self.admission.device != owner.control.device
            || self.admission.anchor.origin != owner.control.profile.origin
            || self.admission.anchor.account_id != owner.control.account_id
            || owner.control.pending_request.as_ref() != self.node.body.enrollment.as_ref()
                && !(owner.control.phase == Phase::Revoked
                    && owner.control.pending_request.is_none())
            || self.submitted && !self.backup_confirmed
            || self.source_proof.nodes.len() >= 1024
            || self.wraps.len() != 2
            || !self.replica.pending.is_empty()
            || !self.replica.conflicts.is_empty()
            || self.replica.checkpoint != self.admission.checkpoint
            || self.replica.minimum.as_ref() != Some(&self.admission.checkpoint)
            || !self.replica.baseline_ready()
        {
            return Err(invalid());
        }
        if let Some(evidence) = &self.revalidation {
            evidence.verify(self)?;
        }
        let proof = self.proof();
        let chain = self.admission.verify(&proof)?;
        let source = self.source_proof.verify(&self.admission.anchor, None)?;
        if source.current().head() != self.admission.previous_head
            || chain.current().head() != self.admission.approved_head
        {
            return Err(invalid());
        }
        let mut recipients = BTreeSet::new();
        for wrap in &self.wraps {
            let h = &wrap.header;
            let public = if h.recipient == "recovery" {
                chain.current().recovery()
            } else {
                chain
                    .current()
                    .devices()
                    .get(&h.recipient)
                    .ok_or_else(invalid)?
            };
            if !recipients.insert(h.recipient.clone())
                || h.origin != self.admission.anchor.origin
                || h.account_id != self.admission.anchor.account_id
                || h.genesis_hash != self.admission.anchor.genesis_hash
                || h.vault_id != self.admission.vault
                || number(&h.key_epoch, false)? != self.admission.checkpoint.epoch
                || h.membership_head != self.admission.approved_head
                || h.author != self.admission.device.id
                || h.recipient_key != public.encryption
            {
                return Err(invalid());
            }
            wrap.verify_author(&self.admission.device.keys.signing)?;
        }
        if !recipients.contains("recovery") || !recipients.contains(&self.admission.device.id) {
            return Err(invalid());
        }
        self.accepted(owner, proof, self.admission.authorization_epoch + 1)?
            .validate()
    }
    /// Stale unsubmitted control is retained for revalidation, never sent optimistically.
    pub fn require_first_send(
        &self,
        owner: &Workspace,
        proof: &ControlProof,
        auth_epoch: u64,
        now: u64,
    ) -> Result<(), AppError> {
        self.validate(owner)?;
        if !self.backup_confirmed
            || self.submitted
            || owner.control.phase != Phase::AwaitingApproval
            || proof != &self.source_proof
            || auth_epoch != self.admission.authorization_epoch
            || number(&self.node.body.issued_at_ms, false)?.abs_diff(now) > 300000
        {
            return Err(invalid());
        }
        self.node
            .body
            .enrollment
            .as_ref()
            .ok_or_else(invalid)?
            .verify_live(now)
    }
    /// Exact submitted Recover prefix plus a completed child barrier is checked by the driver.
    /// This pure builder also validates the anchored prefix; it never trusts a server 'active' label.
    pub fn accepted(
        &self,
        owner: &Workspace,
        proof: ControlProof,
        auth_epoch: u64,
    ) -> Result<Workspace, AppError> {
        let chain = self.admission.verify(&proof)?;
        if auth_epoch <= self.admission.authorization_epoch
            || auth_epoch < owner.control.auth_epoch
            || proof.nodes.get(self.source_proof.nodes.len()) != Some(&self.node)
            || !proof.nodes.starts_with(&self.source_proof.nodes)
            || proof.genesis != self.source_proof.genesis
        {
            return Err(invalid());
        }
        let mut next = owner.clone();
        next.control.anchor = Some(self.admission.anchor.clone());
        next.control.proof = Some(proof);
        next.control.highwater = Some(chain.highwater());
        next.control.auth_epoch = auth_epoch;
        next.control.pending_request = None;
        next.control.personal_vault = Some(self.admission.vault.clone());
        next.control.phase = if !owner
            .control
            .denied_devices
            .contains(&self.admission.device.id)
            && chain.contains_device(chain.current().head(), &self.admission.device)
        {
            Phase::Rekey
        } else {
            Phase::Revoked
        };
        let mut removed = BTreeSet::from([self.source_proof.genesis.first.id.clone()]);
        for node in &next.control.proof.as_ref().ok_or_else(invalid)?.nodes {
            removed.extend(node.body.devices.keys().cloned());
        }
        removed.retain(|id| !chain.current().devices().contains_key(id));
        next.control.denied_devices.extend(removed);
        next.replica = Some(self.replica.clone());
        next.epochs = self.epochs.clone();
        next.observed_epochs = self.epochs.clone();
        next.own_wraps = self
            .wraps
            .iter()
            .filter(|w| w.header.recipient == self.admission.device.id)
            .cloned()
            .collect();
        next.recovery = Some(RecoveryState::Accepted {
            operation: self.operation.clone(),
            admission: self.admission.clone(),
            credentials_cleared: false,
        });
        Ok(next)
    }
}
impl RecoveryState {
    pub fn operation(&self) -> &str {
        match self {
            Self::Pending { package } => &package.operation,
            Self::Accepted { operation, .. } => operation,
        }
    }

    pub fn admission(&self) -> &Admission {
        match self {
            Self::Pending { package } => &package.admission,
            Self::Accepted { admission, .. } => admission,
        }
    }
    pub fn requires_cleanup(&self) -> bool {
        !matches!(
            self,
            Self::Accepted {
                credentials_cleared: true,
                ..
            }
        )
    }
    pub fn validate(&self, workspace: &Workspace) -> Result<(), AppError> {
        match self {
            Self::Pending { package } => package.validate(workspace),
            Self::Accepted {
                operation,
                admission,
                ..
            } => {
                if !hex(operation, 32) {
                    return Err(invalid());
                }
                let control = &workspace.control;
                admission.verify(control.proof.as_ref().ok_or_else(invalid)?)?;
                let replica = workspace.replica.as_ref().ok_or_else(invalid)?;
                if control.anchor.as_ref() != Some(&admission.anchor)
                    || control.device != admission.device
                    || control.personal_vault.as_ref() != Some(&admission.vault)
                    || control.auth_epoch <= admission.authorization_epoch
                    || control.pairing_confirmation.is_some()
                    || replica.creation_head != admission.anchor.genesis_hash
                    || replica.creation_authorization_epoch != 2
                    || replica.checkpoint.epoch < admission.checkpoint.epoch
                    || replica.checkpoint.epoch == admission.checkpoint.epoch
                        && replica.minimum.as_ref() != Some(&admission.checkpoint)
                {
                    return Err(invalid());
                }
                Ok(())
            }
        }
    }
    pub fn verify_transition(&self, after: &Workspace) -> Result<(), AppError> {
        match (self, after.recovery.as_ref()) {
            (Self::Pending { package: before }, Some(Self::Pending { package: next })) => {
                let mut expected = before.clone();
                expected.backup_confirmed = next.backup_confirmed;
                expected.submitted = next.submitted;
                if &expected == next {
                    if before.backup_confirmed && !next.backup_confirmed
                        || before.submitted && !next.submitted
                    {
                        return Err(invalid());
                    }
                } else {
                    super::recovery_revalidation::verify_replacement(before, next)?;
                }
            }
            (
                Self::Pending { package },
                Some(Self::Accepted {
                    admission,
                    credentials_cleared: false,
                    operation,
                }),
            ) => {
                if operation != &package.operation
                    || !package.backup_confirmed
                    || !package.submitted
                    || admission != &package.admission
                    || after.replica.as_ref() != Some(&package.replica)
                    || after.epochs != package.epochs
                    || !package
                        .wraps
                        .iter()
                        .filter(|w| w.header.recipient == package.admission.device.id)
                        .all(|w| after.own_wraps.contains(w))
                {
                    return Err(invalid());
                }
            }
            (
                Self::Accepted {
                    admission: before,
                    credentials_cleared: cleared,
                    operation: before_operation,
                },
                Some(Self::Accepted {
                    admission: next,
                    credentials_cleared: next_cleared,
                    operation: next_operation,
                }),
            ) => {
                if before_operation != next_operation
                    || before != next
                    || *cleared && !*next_cleared
                {
                    return Err(invalid());
                }
            }
            _ => return Err(invalid()),
        }
        Ok(())
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::super::{
        pairing::PendingPairing,
        recovery_read::{self, HistoryPage, ReadSession, RecoveryReply, RecoveryVault},
    };
    use super::*;
    pub(crate) fn prepared(
        rotated: bool,
    ) -> (Workspace, PreparedRecovery, DeviceKeys, RecoveryKit) {
        let (read, old, identity) = recovery_read::tests::verified_fresh_case(1, rotated);
        let before = read.previous_owner().clone();
        let prepared = PreparedRecovery::create(
            read,
            &old,
            &identity,
            RecoverySeed::generate().unwrap(),
            "c".repeat(32),
            1000,
        )
        .unwrap();
        (before, prepared, identity, old)
    }
    fn pending(before: &Workspace, package: &Package) -> Workspace {
        let mut state = before.clone();
        state.recovery = Some(RecoveryState::Pending {
            package: Box::new(package.clone()),
        });
        before.verify_transition(&state).unwrap();
        state
    }
    fn mark_submitted(before: &Workspace) -> Workspace {
        let mut next = before.clone();
        if let Some(RecoveryState::Pending { package }) = &mut next.recovery {
            package.backup_confirmed = true;
            package.submitted = true;
        } else {
            panic!("missing pending recovery");
        }
        before.verify_transition(&next).unwrap();
        next
    }
    #[test]
    fn backup_submission_and_authority_cleanup_are_monotonic_and_survive_restart() {
        let (before, prepared, identity, _) = prepared(false);
        let first = pending(&before, &prepared.package);
        let stored = serde_json::to_string(&first).unwrap();
        assert!(!stored.contains("fixture.invalid"));
        assert!(!stored.contains("LPREC2:"));
        let loaded: Workspace = serde_json::from_str(&stored).unwrap();
        assert_eq!(first, loaded);
        assert!(super::super::workspace::verify_publication(Some(&first), None).is_err());
        assert!(super::super::workspace::verify_publication(None, Some(&first)).is_err());
        let mut confirmed = first.clone();
        let package = match &mut confirmed.recovery {
            Some(RecoveryState::Pending { package }) => package,
            _ => panic!(),
        };
        assert!(package
            .require_first_send(
                &first,
                &package.source_proof,
                package.admission.authorization_epoch,
                1000
            )
            .is_err());
        package.backup_confirmed = true;
        first.verify_transition(&confirmed).unwrap();
        let package = match &confirmed.recovery {
            Some(RecoveryState::Pending { package }) => package,
            _ => panic!(),
        };
        package
            .require_first_send(
                &confirmed,
                &package.source_proof,
                package.admission.authorization_epoch,
                1000,
            )
            .unwrap();
        assert!(package
            .require_first_send(
                &confirmed,
                &package.source_proof,
                package.admission.authorization_epoch + 1,
                1000
            )
            .is_err());
        assert!(package
            .require_first_send(
                &confirmed,
                &package.source_proof,
                package.admission.authorization_epoch,
                1000000
            )
            .is_err());
        let incomplete = package
            .accepted(
                &confirmed,
                package.proof(),
                package.admission.authorization_epoch + 1,
            )
            .unwrap();
        assert!(confirmed.verify_transition(&incomplete).is_err());
        let sent = mark_submitted(&confirmed);
        assert!(sent.verify_transition(&confirmed).is_err());
        let package = match &sent.recovery {
            Some(RecoveryState::Pending { package }) => package,
            _ => panic!(),
        };
        let mut accepted = package
            .accepted(
                &sent,
                package.proof(),
                package.admission.authorization_epoch + 1,
            )
            .unwrap();
        sent.verify_transition(&accepted).unwrap();
        assert_eq!(accepted.control.phase, Phase::Rekey);
        assert!(accepted.control.denied_devices.contains(&"1".repeat(32)));
        assert!(accepted.require_key_recipients().is_err());
        assert!(!accepted.can_upload());
        let chain = accepted.control.verified_chain().unwrap();
        let own = &accepted.own_wraps[0];
        let keys = own
            .open(&identity, &own.header, &identity.public().signing)
            .unwrap();
        for base in accepted.replica.as_ref().unwrap().current.values() {
            let h = &base.version.envelope.header;
            let author = chain.author_at(&h.membership_head, &h.author).unwrap();
            base.version
                .envelope
                .verify(&author.signing)
                .unwrap()
                .open(&keys)
                .unwrap();
        }
        let old_accepted = accepted.clone();
        if let Some(RecoveryState::Accepted {
            credentials_cleared,
            ..
        }) = &mut accepted.recovery
        {
            *credentials_cleared = true;
        }
        old_accepted.verify_transition(&accepted).unwrap();
        accepted.require_key_recipients().unwrap();
        assert!(accepted.verify_transition(&old_accepted).is_err());
        let mut removed = accepted.clone();
        removed.recovery = None;
        assert!(accepted.verify_transition(&removed).is_err());
        let mut signed_out = accepted.clone();
        signed_out.control.phase = Phase::SignedOut;
        accepted.verify_transition(&signed_out).unwrap();
    }
    #[test]
    fn recovery_receipt_authenticates_initial_rotated_history_without_inventing_pairing_confirmation(
    ) {
        let (before, prepared, _, _) = prepared(true);
        let state = mark_submitted(&pending(&before, &prepared.package));
        let accepted = prepared
            .package
            .accepted(
                &state,
                prepared.package.proof(),
                prepared.package.admission.authorization_epoch + 1,
            )
            .unwrap();
        state.verify_transition(&accepted).unwrap();
        assert!(accepted.control.pairing_confirmation.is_none());
        assert_eq!(accepted.replica.as_ref().unwrap().checkpoint.epoch, 2);
        let mut rolled_back = accepted.clone();
        rolled_back
            .replica
            .as_mut()
            .unwrap()
            .minimum
            .as_mut()
            .unwrap()
            .sequence = 0;
        rolled_back
            .replica
            .as_mut()
            .unwrap()
            .minimum
            .as_mut()
            .unwrap()
            .history_hash = "0".repeat(64);
        assert!(rolled_back.validate().is_err());
        let mut forged = accepted.clone();
        if let Some(RecoveryState::Accepted { admission, .. }) = &mut forged.recovery {
            admission.checkpoint.history_hash = "f".repeat(64);
        }
        assert!(forged.validate().is_err());
        assert!(before.verify_transition(&accepted).is_err());
    }
    #[test]
    fn stale_or_substituted_recovery_packages_cannot_be_published_or_reconciled() {
        let (before, prepared, _, _) = prepared(false);
        let original = pending(&before, &prepared.package);
        let mut changed = original.clone();
        if let Some(RecoveryState::Pending { package }) = &mut changed.recovery {
            package.operation = "d".repeat(32);
        }
        assert!(original.verify_transition(&changed).is_err());
        let mut wrong = prepared.package.clone();
        wrong.node.signature = "invalid".into();
        assert!(wrong.validate(&before).is_err());
        let mut substituted = prepared.package.clone();
        substituted.wraps[0].header.recipient_key =
            DeviceKeys::generate().unwrap().public().encryption;
        assert!(substituted.validate(&before).is_err());
        assert!(prepared
            .package
            .accepted(
                &before,
                prepared.package.source_proof.clone(),
                prepared.package.admission.authorization_epoch + 1
            )
            .is_err());
        assert!(prepared
            .package
            .accepted(
                &before,
                prepared.package.proof(),
                prepared.package.admission.authorization_epoch
            )
            .is_err());
        let mut revoked = original.clone();
        revoked.control = revoked
            .control
            .remember_denials([revoked.control.device.id.as_str()])
            .unwrap();
        original.verify_transition(&revoked).unwrap();
        assert_eq!(revoked.control.phase, Phase::Revoked);
        assert!(revoked.require_key_recipients().is_err());
        let mut signed_out = original.clone();
        signed_out.control.phase = Phase::SignedOut;
        original.verify_transition(&signed_out).unwrap();
        assert!(signed_out.verify_transition(&before).is_err());
    }
    #[test]
    fn the_new_kit_can_recover_a_second_loss_before_content_rotation() {
        let (before, prepared, _, old_kit) = prepared(false);
        let state = mark_submitted(&pending(&before, &prepared.package));
        let accepted = prepared
            .package
            .accepted(
                &state,
                prepared.package.proof(),
                prepared.package.admission.authorization_epoch + 1,
            )
            .unwrap();
        let identity = DeviceKeys::generate().unwrap();
        let pending =
            PendingPairing::begin(prepared.kit.anchor(), &"3".repeat(32), &identity, 1001).unwrap();
        let control = super::super::client_state::State::new(
            before.control.profile.clone(),
            before.control.account_id.clone(),
            pending.request().device.clone(),
            accepted.control.auth_epoch,
        )
        .unwrap()
        .begin_pairing(&pending)
        .unwrap();
        let second = Workspace::new(control).unwrap();
        let replica = accepted.replica.as_ref().unwrap();
        let response = || RecoveryReply {
            membership_head: prepared.package.admission.approved_head.clone(),
            auth_epoch: accepted.control.auth_epoch,
            results: vec![RecoveryVault {
                vault: replica.vault.clone(),
                epoch: 1,
                phase: "rekey_pending".into(),
                wrap: prepared
                    .package
                    .wraps
                    .iter()
                    .find(|w| w.header.recipient == "recovery")
                    .unwrap()
                    .clone(),
                committed: None,
                commits: vec![],
                sequence: replica.checkpoint.sequence.to_string(),
                history_hash: replica.checkpoint.history_hash.clone(),
            }],
        };
        assert!(ReadSession::begin_fresh(
            &second,
            &old_kit,
            prepared.package.proof(),
            response(),
            1001
        )
        .is_err());
        let mut read = ReadSession::begin_fresh(
            &second,
            &prepared.kit,
            prepared.package.proof(),
            response(),
            1001,
        )
        .unwrap();
        read.append(HistoryPage {
            records: replica
                .current
                .values()
                .map(|b| b.version.clone())
                .collect(),
            sequence: replica.checkpoint.sequence.to_string(),
            history_hash: replica.checkpoint.history_hash.clone(),
            membership_head: prepared.package.admission.approved_head.clone(),
            epoch: 1,
            phase: "rekey_pending".into(),
        })
        .unwrap();
        let next = PreparedRecovery::create(
            read.finish().unwrap(),
            &prepared.kit,
            &identity,
            RecoverySeed::generate().unwrap(),
            "e".repeat(32),
            1001,
        )
        .unwrap();
        next.package.validate(&second).unwrap();
        let chain = next
            .package
            .admission
            .verify(&next.package.proof())
            .unwrap();
        next.kit.current_keys(&chain).unwrap();
        assert!(prepared.kit.current_keys(&chain).is_err());
    }
}
