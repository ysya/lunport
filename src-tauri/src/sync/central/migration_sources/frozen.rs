//! Pure complete frozen response admission. No HTTP, token release or migration authority.
use super::*;
use crate::sync::{
    central::{
        migration::{legacy_checkpoint, Source},
        migration_freeze::Known,
    },
    record::Envelope,
    relay::PullResponse,
};
#[derive(Clone, PartialEq, Eq)]
pub(super) struct Target {
    profile: String,
    anchor: super::super::membership::TrustAnchor,
    vault: String,
    device: String,
    identity_slot: Option<String>,
    head: String,
    auth_epoch: u64,
    key_epoch: u64,
}
impl Target {
    pub(super) fn same_account(&self, other: &Self) -> bool {
        self.profile == other.profile && self.anchor == other.anchor && self.vault == other.vault
    }

    pub(super) fn binding(&self) -> Result<String, AppError> {
        let auth = self.auth_epoch.to_string();
        let key = self.key_epoch.to_string();
        Ok(super::super::crypto::hash(&super::super::wire::canonical(
            &[
                "lunport-frozen-source-local-context-v1",
                &self.profile,
                &self.anchor.origin,
                &self.anchor.account_id,
                &self.anchor.genesis_hash,
                &self.vault,
                &self.device,
                if self.identity_slot.is_some() {
                    "present"
                } else {
                    "absent"
                },
                self.identity_slot.as_deref().unwrap_or(""),
                &self.head,
                &auth,
                &key,
            ],
        )?))
    }
    pub(super) fn current(owner: &Workspace) -> Result<Self, AppError> {
        if owner.control.cutover || owner.control.phase != Phase::Enrolled {
            return Err(invalid());
        }
        Self::historical(owner)
    }
    /// Scope comparison for passive captured facts. Never a legacy transport target.
    pub(super) fn historical(owner: &Workspace) -> Result<Self, AppError> {
        owner.validate()?;
        Ok(Self {
            profile: owner.control.profile.locator.clone(),
            anchor: owner.control.anchor.clone().ok_or_else(invalid)?,
            vault: owner.control.personal_vault.clone().ok_or_else(invalid)?,
            device: owner.control.device.id.clone(),
            identity_slot: owner.identity_slot.clone(),
            head: owner
                .control
                .highwater
                .as_ref()
                .ok_or_else(invalid)?
                .head
                .clone(),
            auth_epoch: owner.control.auth_epoch,
            key_epoch: owner.replica.as_ref().ok_or_else(invalid)?.checkpoint.epoch,
        })
    }
}
#[derive(Clone, PartialEq, Eq)]
pub(super) struct Context {
    pub target: Target,
    pub operation: String,
    pub preview: String,
    pub keybook: String,
}
pub(in crate::sync::central) struct FrozenSnapshot {
    checkpoint: Source,
    records: Vec<Envelope>,
    context: Context,
    progress: Progress,
}
impl FrozenSnapshot {
    pub fn checkpoint(&self) -> &Source {
        &self.checkpoint
    }
    pub(super) fn into_records(self) -> Vec<Envelope> {
        self.records
    }
    pub fn records(&self) -> &[Envelope] {
        &self.records
    }
    pub(super) fn progress(&self) -> &Progress {
        &self.progress
    }
    pub(super) fn context(&self) -> &Context {
        &self.context
    }
}
impl Sources {
    pub fn admit_frozen(
        &self,
        owner: &Workspace,
        operation: &str,
        progress: &Progress,
        minimum: Option<&Known>,
        chain: &str,
        response: PullResponse,
    ) -> Result<FrozenSnapshot, AppError> {
        let context = self.progress_context(owner, operation, progress, minimum)?;
        if !self.keys.contains_key(chain)
            || chain != self.parent
                && !self.parent.is_empty()
                && !progress
                    .sources
                    .iter()
                    .any(|source| source.chain_id == self.parent)
        {
            return Err(invalid());
        }
        let expected = progress
            .sources
            .iter()
            .find(|source| source.chain_id == chain)
            .ok_or_else(invalid)?;
        let actual = legacy_checkpoint(chain, response.latest_seq, &response.records)?;
        if &actual != expected {
            return Err(invalid());
        }
        for envelope in &response.records {
            drop(self.open(
                chain,
                &SealedRecord {
                    envelope: envelope.clone(),
                    dirty: false,
                    public_identity: None,
                },
            )?);
        }
        Ok(FrozenSnapshot {
            checkpoint: actual,
            progress: progress.clone(),
            records: response.records,
            context,
        })
    }
    /// Native legacy GET only: release a bearer after exact target and signed frozen-source checks.
    pub(in crate::sync::central) fn frozen_bearer(
        &self,
        service: &str,
        owner: &Workspace,
        operation: &str,
        progress: &Progress,
        minimum: Option<&Known>,
        chain: &str,
    ) -> Result<Zeroizing<String>, AppError> {
        self.require_service(service)?;
        let context = self.progress_context(owner, operation, progress, minimum)?;
        if owner.control.profile.origin != service
            || context.target != Target::current(owner)?
            || !hex(chain, 64)
            || !progress
                .sources
                .iter()
                .any(|source| source.chain_id == chain)
            || (chain != self.parent
                && !self.parent.is_empty()
                && !progress
                    .sources
                    .iter()
                    .any(|source| source.chain_id == self.parent))
        {
            return Err(invalid());
        }
        let key = self.keys.get(chain).ok_or_else(invalid)?;
        Ok(Zeroizing::new(key.token.to_string()))
    }
    pub(super) fn progress_context(
        &self,
        owner: &Workspace,
        operation: &str,
        progress: &Progress,
        minimum: Option<&Known>,
    ) -> Result<Context, AppError> {
        owner.validate()?;
        owner.require_key_recipients()?;
        if owner.control.phase != Phase::Enrolled || owner.control.cutover {
            return Err(invalid());
        }
        let vault = owner
            .control
            .personal_vault
            .as_deref()
            .ok_or_else(invalid)?;
        progress.verify(&owner.control.verified_chain()?, operation, vault, minimum)?;
        let latest = &progress.proof.last().ok_or_else(invalid)?.intent.body;
        self.require_service(&latest.origin)?;
        if latest.parent_chain != self.parent || latest.chains != self.chains() {
            return Err(invalid());
        }
        let target = Target {
            profile: owner.control.profile.locator.clone(),
            anchor: owner.control.anchor.clone().ok_or_else(invalid)?,
            vault: latest.vault_id.clone(),
            device: latest.author.clone(),
            identity_slot: owner.identity_slot.clone(),
            head: latest.membership_head.clone(),
            auth_epoch: super::super::wire::number(&latest.authorization_epoch, false)?,
            key_epoch: super::super::wire::number(&latest.key_epoch, false)?,
        };
        Ok(Context {
            target,
            operation: latest.migration_id.clone(),
            preview: latest.preview_digest.clone(),
            keybook: super::super::crypto::hash(&self.encode_local()?),
        })
    }
}

#[cfg(test)]
pub(in crate::sync::central::migration_sources) mod tests {
    use super::*;
    use crate::sync::central::migration_freeze::{Phase as FreezePhase, ProofStep};
    pub(super) fn fixture() -> (
        Sources,
        Workspace,
        Progress,
        String,
        String,
        PullResponse,
        PullResponse,
    ) {
        let (_, sources, owner, progress, parent, child, parent_response, child_response) =
            fixture_with_state();
        (
            sources,
            owner,
            progress,
            parent,
            child,
            parent_response,
            child_response,
        )
    }
    pub(in crate::sync::central::migration_sources) fn fixture_with_state() -> (
        SyncStateV3,
        Sources,
        Workspace,
        Progress,
        String,
        String,
        PullResponse,
        PullResponse,
    ) {
        let (state, parent, child) = super::super::records::tests::fixture();
        let sources = Sources::discover(&state, Some(&parent)).unwrap();
        let (owner, _, signer) = super::super::super::migration_history::tests::initial();
        let intent = sources
            .intent(&owner, &signer, &"7".repeat(32), &"8".repeat(64), None)
            .unwrap();
        let mut records: Vec<_> = state
            .account
            .as_ref()
            .unwrap()
            .sealed
            .values()
            .map(|v| v.envelope.clone())
            .collect();
        for (index, row) in records.iter_mut().enumerate() {
            row.seq = index as u64 + 1;
        }
        let parent_response = PullResponse {
            records,
            latest_seq: 5,
        };
        let mut records: Vec<_> = state.spaces[&child.chain_id]
            .sealed
            .values()
            .map(|v| v.envelope.clone())
            .collect();
        for (index, row) in records.iter_mut().enumerate() {
            row.seq = index as u64 + 1;
        }
        let child_response = PullResponse {
            records,
            latest_seq: 3,
        };
        let progress = Progress {
            proof: vec![ProofStep {
                digest: intent.digest().unwrap(),
                intent,
            }],
            sources: vec![legacy_checkpoint(
                &parent.chain_id,
                parent_response.latest_seq,
                &parent_response.records,
            )
            .unwrap()],
            phase: FreezePhase::Freezing,
            next: vec![child.chain_id.clone()],
        };
        (
            state,
            sources,
            owner,
            progress,
            parent.chain_id,
            child.chain_id,
            parent_response,
            child_response,
        )
    }
    #[test]
    fn complete_parent_snapshot_and_later_unselected_child_must_match_their_exact_frozen_checkpoints(
    ) {
        let (sources, owner, mut progress, parent, child, parent_response, child_response) =
            fixture();
        let operation = "7".repeat(32);
        let admitted = sources
            .admit_frozen(
                &owner,
                &operation,
                &progress,
                None,
                &parent,
                parent_response.clone(),
            )
            .unwrap();
        assert_eq!(admitted.records(), parent_response.records);
        assert_eq!(admitted.checkpoint().chain_id, parent);
        assert!(sources
            .admit_frozen(
                &owner,
                &operation,
                &progress,
                None,
                &child,
                child_response.clone()
            )
            .is_err());
        let minimum = progress
            .verify(
                &owner.control.verified_chain().unwrap(),
                &operation,
                owner.control.personal_vault.as_deref().unwrap(),
                None,
            )
            .unwrap();
        progress.sources.push(
            legacy_checkpoint(&child, child_response.latest_seq, &child_response.records).unwrap(),
        );
        progress.sources.sort_by(|a, b| a.chain_id.cmp(&b.chain_id));
        progress.phase = FreezePhase::Frozen;
        progress.next.clear();
        let admitted = sources
            .admit_frozen(
                &owner,
                &operation,
                &progress,
                Some(&minimum),
                &child,
                child_response.clone(),
            )
            .unwrap();
        let mut missing_parent = progress.clone();
        missing_parent
            .sources
            .retain(|source| source.chain_id != parent);
        missing_parent.phase = FreezePhase::Freezing;
        missing_parent.next = vec![parent.clone()];
        assert!(sources
            .admit_frozen(
                &owner,
                &operation,
                &missing_parent,
                None,
                &child,
                child_response.clone()
            )
            .is_err());

        assert_eq!(admitted.records(), child_response.records);
        assert_eq!(admitted.checkpoint().sequence, "3");
    }
    #[test]
    fn omitted_extra_mutated_rows_and_cursor_digest_or_queued_chain_mismatch_never_become_an_empty_or_partial_snapshot(
    ) {
        let (sources, owner, progress, parent, child, response, _) = fixture();
        let operation = "7".repeat(32);
        for change in [
            "omit",
            "extra",
            "ciphertext",
            "cursor",
            "deletion",
            "hash",
            "nonce",
        ] {
            let mut response = response.clone();
            match change {
                "omit" => {
                    response.records.pop();
                }
                "extra" => response.records.push(response.records[0].clone()),
                "ciphertext" => response.records[0].ciphertext = "AAAA".into(),
                "cursor" => response.latest_seq += 1,
                "deletion" => response.records[0].deleted = !response.records[0].deleted,
                "hash" => response.records[0].id_hash = "f".repeat(64),
                _ => response.records[0].nonce = "AAAA".into(),
            }
            assert!(
                sources
                    .admit_frozen(&owner, &operation, &progress, None, &parent, response)
                    .is_err(),
                "{change}"
            );
        }
        assert!(sources
            .admit_frozen(
                &owner,
                &operation,
                &progress,
                None,
                &parent,
                PullResponse {
                    records: vec![],
                    latest_seq: 0
                }
            )
            .is_err());
        assert!(sources
            .admit_frozen(
                &owner,
                &operation,
                &progress,
                None,
                &child,
                PullResponse {
                    records: vec![],
                    latest_seq: 0
                }
            )
            .is_err());
        assert!(sources
            .admit_frozen(
                &owner,
                &operation,
                &progress,
                None,
                &"a".repeat(64),
                response.clone()
            )
            .is_err());
        let mut wrong = progress.clone();
        wrong.sources[0].count = "0".into();
        assert!(sources
            .admit_frozen(&owner, &operation, &wrong, None, &parent, response.clone())
            .is_err());
        wrong = progress;
        wrong.sources[0].ciphertext_digest = "0".repeat(64);
        assert!(sources
            .admit_frozen(&owner, &operation, &wrong, None, &parent, response)
            .is_err());
    }
    #[test]
    fn recomputed_service_checkpoint_cannot_bypass_ciphertext_authentication_or_inner_header_checks(
    ) {
        let (sources, owner, mut progress, parent, _, mut response, _) = fixture();
        response.records[0].ciphertext =
            base64::Engine::encode(&base64::engine::general_purpose::STANDARD, [0u8; 32]);
        progress.sources[0] =
            legacy_checkpoint(&parent, response.latest_seq, &response.records).unwrap();
        assert!(sources
            .admit_frozen(&owner, &"7".repeat(32), &progress, None, &parent, response)
            .is_err());
        let (sources, owner, mut progress, parent, _, mut response, _) = fixture();
        response.records[0].deleted = !response.records[0].deleted;
        progress.sources[0] =
            legacy_checkpoint(&parent, response.latest_seq, &response.records).unwrap();
        assert!(sources
            .admit_frozen(&owner, &"7".repeat(32), &progress, None, &parent, response)
            .is_err());
    }
    #[test]
    fn foreign_operation_proof_owner_and_prior_minimum_rollback_are_rejected() {
        let (sources, owner, progress, parent, child, response, child_response) = fixture();
        let operation = "7".repeat(32);
        assert!(sources
            .admit_frozen(
                &owner,
                &"9".repeat(32),
                &progress,
                None,
                &parent,
                response.clone()
            )
            .is_err());
        let mut changed = progress.clone();
        changed.proof[0].intent.signature = "AAAA".into();
        assert!(sources
            .admit_frozen(
                &owner,
                &operation,
                &changed,
                None,
                &parent,
                response.clone()
            )
            .is_err());
        let mut other = owner.clone();
        other.control.phase = Phase::SignedOut;
        assert!(sources
            .admit_frozen(
                &other,
                &operation,
                &progress,
                None,
                &parent,
                response.clone()
            )
            .is_err());
        other = owner.clone();
        other.control.anchor.as_mut().unwrap().account_id = "e".repeat(64);
        assert_ne!(other.control.anchor, owner.control.anchor);
        assert!(sources
            .admit_frozen(
                &other,
                &operation,
                &progress,
                None,
                &parent,
                response.clone()
            )
            .is_err());
        let mut complete = progress.clone();
        complete.sources.push(
            legacy_checkpoint(&child, child_response.latest_seq, &child_response.records).unwrap(),
        );
        complete.sources.sort_by(|a, b| a.chain_id.cmp(&b.chain_id));
        complete.next.clear();
        complete.phase = FreezePhase::Frozen;
        let minimum = complete
            .verify(
                &owner.control.verified_chain().unwrap(),
                &operation,
                owner.control.personal_vault.as_deref().unwrap(),
                None,
            )
            .unwrap();
        assert!(sources
            .admit_frozen(
                &owner,
                &operation,
                &progress,
                Some(&minimum),
                &parent,
                response
            )
            .is_err());
    }
}

#[cfg(test)]
mod transport_tests {
    use super::*;
    use crate::sync::central::api::{Api, DeviceSession, DeviceState};
    use std::time::Duration;
    #[test]
    fn frozen_get_preparation_requires_current_pinned_target_and_only_releases_a_frozen_chain_bearer(
    ) {
        let (sources, owner, progress, parent, child, _, _) = super::tests::fixture();
        let service = &owner.control.profile.origin;
        let api = Api::new(service).unwrap();
        let session = DeviceSession::synthetic_for_test(
            owner.control.account_id.clone(),
            DeviceState::Active,
            owner.control.auth_epoch,
            Duration::from_secs(300),
        );
        let operation = &progress.proof.last().unwrap().intent.body.migration_id;
        let (path, bearer) = api
            .prepare_frozen_source(
                &session, &owner, &sources, operation, &progress, None, &parent,
            )
            .unwrap();
        assert_eq!(path, format!("/v1/chains/{parent}/records?since=0"));
        assert_eq!(bearer.as_str(), sources.keys[&parent].token.as_str());
        for denied in [&child, &"0".repeat(64), &format!("{parent}/../other")] {
            assert!(api
                .prepare_frozen_source(
                    &session, &owner, &sources, operation, &progress, None, denied
                )
                .is_err());
        }
        assert!(Api::new("https://different.test")
            .unwrap()
            .prepare_frozen_source(&session, &owner, &sources, operation, &progress, None, &parent)
            .is_err());
        assert!(api
            .prepare_frozen_source(
                &session,
                &owner,
                &sources,
                &"9".repeat(32),
                &progress,
                None,
                &parent
            )
            .is_err());
        let mut invalid_proof = progress.clone();
        invalid_proof.proof[0].digest = "0".repeat(64);
        assert!(api
            .prepare_frozen_source(
                &session,
                &owner,
                &sources,
                operation,
                &invalid_proof,
                None,
                &parent
            )
            .is_err());
        let mut signed_out = owner.clone();
        signed_out.control.phase = Phase::SignedOut;
        assert!(api
            .prepare_frozen_source(
                &session,
                &signed_out,
                &sources,
                operation,
                &progress,
                None,
                &parent
            )
            .is_err());
        for rejected in [
            DeviceSession::synthetic_for_test(
                owner.control.account_id.clone(),
                DeviceState::Pending,
                1,
                Duration::from_secs(300),
            ),
            DeviceSession::synthetic_for_test(
                "0".repeat(64),
                DeviceState::Active,
                1,
                Duration::from_secs(300),
            ),
            DeviceSession::synthetic_for_test(
                owner.control.account_id.clone(),
                DeviceState::Active,
                owner.control.auth_epoch + 1,
                Duration::from_secs(300),
            ),
            DeviceSession::synthetic_for_test(
                owner.control.account_id.clone(),
                DeviceState::Active,
                1,
                Duration::ZERO,
            ),
        ] {
            assert!(api
                .prepare_frozen_source(
                    &rejected, &owner, &sources, operation, &progress, None, &parent
                )
                .is_err());
        }
        let budget =
            crate::sync::central::request_budget::Budget::limited(0, Duration::from_secs(30));
        let bounded = Api::bounded(service, &budget).unwrap();
        let exhausted = bounded
            .frozen_source(
                &session, &owner, &sources, operation, &progress, None, &parent,
            )
            .err()
            .unwrap();
        assert!(crate::sync::central::request_budget::Budget::exhausted(
            &exhausted
        ));
        assert_eq!(budget.used(), 0);
        let budget =
            crate::sync::central::request_budget::Budget::limited(1, Duration::from_secs(30));
        let foreign = Api::bounded("https://different.test", &budget).unwrap();
        assert!(foreign
            .frozen_source(&session, &owner, &sources, operation, &progress, None, &parent)
            .is_err());
        assert_eq!(budget.used(), 0);
        // The live driver separately fences session identity/credential-slot selection. This
        // transport checks the active account grant, fixed origin and authenticated source proof.
    }
}
