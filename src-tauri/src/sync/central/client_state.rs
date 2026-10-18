//! Serializable public control state for the existing SyncCore owner. No token/secret belongs here.
//! A cutover is monotonic. Receiving central ciphertext must not publish it into a still-legacy
//! repository, where an old worker could otherwise upload it under the retired shared code.
use super::{
    credentials::Profile,
    membership::{Device, Enrollment, TrustAnchor},
    oidc::OidcConfig,
    pairing::{PairingConfirmation, PendingPairing},
    trust::{ControlProof, Highwater, VerifiedChain},
    wire::{hex, invalid, MAX_SAFE_INTEGER},
};
use crate::error::AppError;
use serde::{Deserialize, Serialize};
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProfileData {
    pub origin: String,
    pub issuer: String,
    pub subject: String,
    pub locator: String,
    pub oidc: OidcConfig,
}
impl ProfileData {
    pub fn profile(&self) -> Result<Profile, AppError> {
        let profile = Profile::new(&self.origin, &self.issuer, &self.subject)?;
        self.oidc.validate()?;
        if profile.locator != self.locator
            || self.oidc.issuer != self.issuer
            || self
                .oidc
                .audience
                .as_ref()
                .is_none_or(|aud| aud == &self.oidc.client_id)
        {
            return Err(invalid());
        }
        Ok(profile)
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Phase {
    Setup,
    AwaitingApproval,
    BackupRequired,
    Enrolled,
    Active,
    Rekey,
    Revoked,
    SignedOut,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LibraryApproval {
    pub policy: u32,
    pub preview_digest: String,
    pub membership_head: String,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct State {
    pub profile: ProfileData,
    pub account_id: String,
    pub device: Device,
    pub auth_epoch: u64,
    pub phase: Phase,
    pub anchor: Option<TrustAnchor>,
    pub proof: Option<ControlProof>,
    pub highwater: Option<Highwater>,
    pub pending_request: Option<Enrollment>,
    pub personal_vault: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pairing_confirmation: Option<PairingConfirmation>,
    pub recovery_backup_confirmed: bool,
    pub cutover: bool,
    pub library: Option<LibraryApproval>,
}
impl State {
    pub fn new(
        profile: ProfileData,
        account_id: String,
        device: Device,
        auth_epoch: u64,
    ) -> Result<Self, AppError> {
        let state = Self {
            profile,
            account_id,
            device,
            auth_epoch,
            phase: Phase::Setup,
            anchor: None,
            proof: None,
            highwater: None,
            pending_request: None,
            personal_vault: None,
            pairing_confirmation: None,
            recovery_backup_confirmed: false,
            cutover: false,
            library: None,
        };
        state.validate()?;
        Ok(state)
    }
    pub fn validate(&self) -> Result<(), AppError> {
        self.profile.profile()?;
        self.device.keys.validate()?;
        if !hex(&self.account_id, 64)
            || !hex(&self.device.id, 32)
            || self.auth_epoch == 0
            || self.auth_epoch > MAX_SAFE_INTEGER
            || self.personal_vault.as_ref().is_some_and(|id| !hex(id, 64))
        {
            return Err(invalid());
        }
        match (&self.anchor, &self.proof, &self.highwater) {
            (Some(anchor), Some(proof), Some(highwater)) => {
                if anchor.origin != self.profile.origin || anchor.account_id != self.account_id {
                    return Err(invalid());
                }
                let chain = proof.verify(anchor, Some(highwater))?;
                if chain.highwater() != *highwater {
                    return Err(invalid());
                }
                if matches!(
                    self.phase,
                    Phase::BackupRequired | Phase::Enrolled | Phase::Active | Phase::Rekey
                ) && chain.current().devices().get(&self.device.id) != Some(&self.device.keys)
                {
                    return Err(invalid());
                }
                if let Some(confirmation) = &self.pairing_confirmation {
                    confirmation.validate_minimums(&chain)?;
                    if self.personal_vault.as_deref() != Some(confirmation.personal_vault.as_str())
                        || !proof.nodes.iter().enumerate().any(|(i, node)| {
                            node.body.action == super::membership::Action::Add
                                && node.body.enrollment.as_ref().is_some_and(|r| {
                                    r.request_id == confirmation.request_id
                                        && r.device == self.device
                                })
                                && chain.head_at(i + 1) == Some(confirmation.approved_head.as_str())
                        })
                    {
                        return Err(invalid());
                    }
                }
                if let Some(library) = &self.library {
                    if library.policy != 1
                        || !hex(&library.preview_digest, 64)
                        || !chain.has_head(&library.membership_head)
                    {
                        return Err(invalid());
                    }
                }
            }
            (None, None, None) => {
                if self.pairing_confirmation.is_some()
                    || self.library.is_some()
                    || self.cutover
                    || matches!(
                        self.phase,
                        Phase::BackupRequired | Phase::Enrolled | Phase::Active | Phase::Rekey
                    )
                {
                    return Err(invalid());
                }
            }
            _ => return Err(invalid()),
        }
        if matches!(self.phase, Phase::Active | Phase::Rekey)
            && (!self.cutover || self.library.is_none() || self.personal_vault.is_none())
        {
            return Err(invalid());
        }
        if let Some(request) = &self.pending_request {
            request.verify_signature()?;
            if request.origin != self.profile.origin
                || request.account_id != self.account_id
                || request.device != self.device
                || self.phase != Phase::AwaitingApproval
            {
                return Err(invalid());
            }
        } else if self.phase == Phase::AwaitingApproval {
            return Err(invalid());
        }
        Ok(())
    }
    pub fn begin_pairing(&self, pending: &PendingPairing) -> Result<Self, AppError> {
        if self.anchor.is_some() || self.cutover || pending.request().device != self.device {
            return Err(invalid());
        }
        let mut next = self.clone();
        next.pending_request = Some(pending.request().clone());
        next.phase = Phase::AwaitingApproval;
        next.validate()?;
        Ok(next)
    }
    pub fn accept_pairing(
        &self,
        pending: &PendingPairing,
        confirmation: &PairingConfirmation,
        proof: ControlProof,
    ) -> Result<Self, AppError> {
        if self.phase != Phase::AwaitingApproval
            || self.pending_request.as_ref() != Some(pending.request())
            || self.anchor.is_some()
        {
            return Err(invalid());
        }
        let chain = pending.accept(confirmation, &proof)?;
        let mut next = self.clone();
        next.anchor = Some(chain.current().anchor().clone());
        next.highwater = Some(chain.highwater());
        next.proof = Some(proof);
        next.phase = Phase::Enrolled;
        next.personal_vault = Some(confirmation.personal_vault.clone());
        next.pairing_confirmation = Some(confirmation.clone());
        next.pending_request = None;
        next.validate()?;
        Ok(next)
    }
    /// Called after local creation with this device's own genesis signature. UI backup confirmation
    /// and the server bootstrap ACK are separate steps; this alone grants no data upload permission.
    pub fn prepare_bootstrap(
        &self,
        proof: ControlProof,
        anchor: TrustAnchor,
        vault: String,
    ) -> Result<Self, AppError> {
        if self.anchor.is_some()
            || self.cutover
            || !proof.nodes.is_empty()
            || proof.genesis.first != self.device
            || !hex(&vault, 64)
        {
            return Err(invalid());
        }
        let chain = proof.verify(&anchor, None)?;
        let mut next = self.clone();
        next.anchor = Some(anchor);
        next.highwater = Some(chain.highwater());
        next.proof = Some(proof);
        next.personal_vault = Some(vault);
        next.phase = Phase::BackupRequired;
        next.validate()?;
        Ok(next)
    }
    pub fn confirm_backup(&self) -> Result<Self, AppError> {
        if self.phase != Phase::BackupRequired {
            return Err(invalid());
        }
        let mut next = self.clone();
        next.recovery_backup_confirmed = true;
        Ok(next)
    }
    pub fn finish_bootstrap(&self) -> Result<Self, AppError> {
        if self.phase != Phase::BackupRequired || !self.recovery_backup_confirmed {
            return Err(invalid());
        }
        let mut next = self.clone();
        next.phase = Phase::Enrolled;
        next.validate()?;
        Ok(next)
    }
    pub fn observe_proof(&self, proof: ControlProof, auth_epoch: u64) -> Result<Self, AppError> {
        if auth_epoch < self.auth_epoch || auth_epoch > MAX_SAFE_INTEGER {
            return Err(invalid());
        }
        let anchor = self.anchor.as_ref().ok_or_else(invalid)?;
        let chain = proof.verify(anchor, self.highwater.as_ref())?;
        let previous = self.verified_chain()?;
        let security_changed = chain.security_revision() > previous.security_revision();
        let extra_access_barrier = auth_epoch - self.auth_epoch
            > chain.current().revision() - previous.current().revision();
        let mut next = self.clone();
        if matches!(next.phase, Phase::Active | Phase::Rekey)
            && (security_changed || extra_access_barrier)
        {
            next.phase = Phase::Rekey;
        }
        next.auth_epoch = auth_epoch;
        next.highwater = Some(chain.highwater());
        if chain.current().devices().get(&self.device.id) != Some(&self.device.keys) {
            next.phase = Phase::Revoked;
        }
        next.proof = Some(proof);
        next.validate()?;
        Ok(next)
    }
    /// H's verified migration receipt must be persisted before setting cutover. No automatic
    /// fallback to the legacy worker is allowed after this boundary, including logout/restart.
    pub fn approve_library(
        &self,
        preview_digest: String,
        expected_head: &str,
    ) -> Result<Self, AppError> {
        if !self.cutover
            || self.phase != Phase::Enrolled
            || self
                .highwater
                .as_ref()
                .is_none_or(|h| h.head != expected_head)
            || !hex(&preview_digest, 64)
        {
            return Err(invalid());
        }
        let mut next = self.clone();
        next.library = Some(LibraryApproval {
            policy: 1,
            preview_digest,
            membership_head: expected_head.into(),
        });
        next.phase = Phase::Active;
        next.validate()?;
        Ok(next)
    }
    pub fn verify_transition(&self, next: &Self) -> Result<(), AppError> {
        next.validate()?;
        if self.profile != next.profile
            || self.account_id != next.account_id
            || self.device != next.device
            || self.cutover && !next.cutover
            || next.auth_epoch < self.auth_epoch
            || self.pairing_confirmation.is_some()
                && self.pairing_confirmation != next.pairing_confirmation
        {
            return Err(invalid());
        }
        if let Some(anchor) = &self.anchor {
            if next.anchor.as_ref() != Some(anchor) {
                return Err(invalid());
            }
            next.proof
                .as_ref()
                .ok_or_else(invalid)?
                .verify(anchor, self.highwater.as_ref())?;
        }
        Ok(())
    }
    pub fn verified_chain(&self) -> Result<VerifiedChain, AppError> {
        self.proof.as_ref().ok_or_else(invalid)?.verify(
            self.anchor.as_ref().ok_or_else(invalid)?,
            self.highwater.as_ref(),
        )
    }
    pub fn cloud_writes_allowed(&self) -> bool {
        self.cutover
            && self.phase == Phase::Active
            && self.library.is_some()
            && self.validate().is_ok()
    }
}
#[cfg(test)]
mod tests {
    use super::super::{
        crypto::DeviceKeys,
        membership::{Action, Genesis, SignedMembership},
    };
    use super::*;
    fn setup() -> (State, DeviceKeys) {
        let keys = DeviceKeys::generate().unwrap();
        let profile = Profile::new("https://relay.test", "https://id.test", "opaque").unwrap();
        let state = State::new(
            ProfileData {
                origin: profile.origin,
                issuer: profile.issuer.clone(),
                subject: profile.subject,
                locator: profile.locator,
                oidc: OidcConfig {
                    issuer: profile.issuer,
                    client_id: "native".into(),
                    scopes: vec!["lunport:sync".into()],
                    audience: Some("api".into()),
                },
            },
            "a".repeat(64),
            Device {
                id: "f".repeat(32),
                keys: keys.public(),
            },
            1,
        )
        .unwrap();
        (state, keys)
    }
    #[test]
    fn login_and_server_active_claims_do_not_enable_upload_or_anchor_a_root() {
        let (state, _) = setup();
        assert!(!state.cloud_writes_allowed());
        assert!(state.anchor.is_none());
        let mut fake = state.clone();
        fake.phase = Phase::Active;
        assert!(fake.validate().is_err());
        assert!(state
            .approve_library("b".repeat(64), &"c".repeat(64))
            .is_err());
    }
    #[test]
    fn pairing_state_adopts_a_root_only_after_oob_confirmation_and_retains_the_original_on_failure()
    {
        use super::super::pairing::PairingInvite;
        let (first, first_keys) = setup();
        let (genesis, anchor) = Genesis::create(
            &first.profile.origin,
            &first.account_id,
            &first.device.id,
            &first_keys,
            &DeviceKeys::generate().unwrap(),
        )
        .unwrap();
        let previous = genesis.trust(&anchor).unwrap();
        let next_keys = DeviceKeys::generate().unwrap();
        let next = State::new(
            first.profile.clone(),
            first.account_id.clone(),
            Device {
                id: "d".repeat(32),
                keys: next_keys.public(),
            },
            1,
        )
        .unwrap();
        let pending = PendingPairing::begin(&anchor, &next.device.id, &next_keys, 1000).unwrap();
        let waiting = next.begin_pairing(&pending).unwrap();
        let invite =
            PairingInvite::from_code(&pending.code().unwrap(), pending.request(), &anchor, 1100)
                .unwrap();
        let mut devices = previous.devices().clone();
        devices.insert(next.device.id.clone(), next.device.keys.clone());
        let node = SignedMembership::sign(
            previous.proposal(
                &first.device.id,
                Action::Add,
                Some(pending.request().clone()),
                devices,
                previous.recovery().clone(),
                1200,
            ),
            &first_keys,
        )
        .unwrap();
        let confirmation = invite
            .confirm(
                &previous,
                &node,
                &"c".repeat(64),
                super::super::pairing::tests::minima(previous.head()),
            )
            .unwrap();
        let proof = ControlProof {
            genesis,
            nodes: vec![node],
        };
        let mut bad = confirmation.clone();
        bad.mac = "AA==".into();
        assert!(waiting
            .accept_pairing(&pending, &bad, proof.clone())
            .is_err());
        assert!(waiting.anchor.is_none());
        let paired = waiting
            .accept_pairing(&pending, &confirmation, proof)
            .unwrap();
        assert_eq!(paired.anchor.as_ref(), Some(&anchor));
        assert_eq!(paired.phase, Phase::Enrolled);
        assert!(!paired.cloud_writes_allowed());
        waiting.verify_transition(&paired).unwrap();
        assert_eq!(
            paired.personal_vault.as_deref(),
            Some(confirmation.personal_vault.as_str())
        );
        let restored: State =
            serde_json::from_str(&serde_json::to_string(&paired).unwrap()).unwrap();
        restored.validate().unwrap();
        assert_eq!(restored.pairing_confirmation.as_ref(), Some(&confirmation));
        let before = super::super::workspace::Workspace::new(restored).unwrap();
        let mut joined = before.clone();
        let minimum = &confirmation.minimums[0];
        joined.replica = Some(
            super::super::replica::Replica::join(
                minimum.vault.clone(),
                minimum.creation_head.clone(),
                minimum.creation_authorization_epoch.parse().unwrap(),
                super::super::rekey::Checkpoint {
                    epoch: minimum.key_epoch.parse().unwrap(),
                    sequence: minimum.sequence.parse().unwrap(),
                    history_hash: minimum.history_hash.clone(),
                },
            )
            .unwrap(),
        );
        before.verify_transition(&joined).unwrap();
        joined.replica.as_mut().unwrap().minimum = None;
        assert!(joined.validate().is_err());
    }
    #[test]
    fn bootstrap_backup_library_confirmation_and_cutover_are_distinct_monotonic_boundaries() {
        let (state, keys) = setup();
        let (genesis, anchor) = Genesis::create(
            &state.profile.origin,
            &state.account_id,
            &state.device.id,
            &keys,
            &DeviceKeys::generate().unwrap(),
        )
        .unwrap();
        let prepared = state
            .prepare_bootstrap(
                ControlProof {
                    genesis,
                    nodes: vec![],
                },
                anchor,
                "b".repeat(64),
            )
            .unwrap();
        assert!(prepared.finish_bootstrap().is_err());
        assert!(!prepared.cloud_writes_allowed());
        let enrolled = prepared
            .confirm_backup()
            .unwrap()
            .finish_bootstrap()
            .unwrap();
        assert!(!enrolled.cloud_writes_allowed());
        let mut cutover = enrolled.clone();
        cutover.cutover = true;
        let active = cutover
            .approve_library("d".repeat(64), &cutover.highwater.as_ref().unwrap().head)
            .unwrap();
        assert!(active.cloud_writes_allowed());
        assert!(active.verify_transition(&enrolled).is_err());
        let json = serde_json::to_string(&active).unwrap();
        assert!(!json.contains("credential"));
        assert!(!json.contains("private_key"));
        assert!(serde_json::from_str::<State>(&json)
            .unwrap()
            .validate()
            .is_ok());
    }
    #[test]
    fn stale_enablement_and_account_proof_rollback_do_not_silently_change_recipient_scope() {
        let (state, keys) = setup();
        let (genesis, anchor) = Genesis::create(
            &state.profile.origin,
            &state.account_id,
            &state.device.id,
            &keys,
            &DeviceKeys::generate().unwrap(),
        )
        .unwrap();
        let mut enrolled = state
            .prepare_bootstrap(
                ControlProof {
                    genesis,
                    nodes: vec![],
                },
                anchor,
                "b".repeat(64),
            )
            .unwrap()
            .confirm_backup()
            .unwrap()
            .finish_bootstrap()
            .unwrap();
        enrolled.cutover = true;
        let old_head = enrolled.highwater.as_ref().unwrap().head.clone();
        let current = enrolled.verified_chain().unwrap();
        let proposal = current.current().proposal(
            &state.device.id,
            Action::Recovery,
            None,
            current.current().devices().clone(),
            DeviceKeys::generate().unwrap().public(),
            1000,
        );
        let node = SignedMembership::sign(proposal, &keys).unwrap();
        let mut proof = enrolled.proof.clone().unwrap();
        proof.nodes.push(node);
        let updated = enrolled.observe_proof(proof, 2).unwrap();
        assert!(updated.approve_library("d".repeat(64), &old_head).is_err());
        assert!(updated.verify_transition(&enrolled).is_err());
    }
}
