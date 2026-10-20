//! Read-only proof that a joining device's legacy cloud sources already reached this Vault.
//! The signed initial target and its complete authenticated read remain separate requirements.
use super::*;
use crate::sync::central::{
    active_read::VerifiedLibrary,
    crypto,
    migration::SignedMigration,
    migration_sources::{Inventory, Sources},
    trust::ControlProof,
};
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Retired {
    manifest: SignedMigration,
    manifest_digest: String,
    phase: String,
    staged: String,
    history_hash: String,
    retired: String,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Evidence {
    version: u32,
    proof: ControlProof,
    status: Retired,
}
/// Native-only preflight; serialized evidence must be revalidated before use.
pub(in crate::sync::central) struct Witness {
    evidence: Evidence,
    checkpoint: Checkpoint,
}
fn retained() -> AppError {
    AppError::Other("These legacy cloud sources have not been proved fully migrated and permanently retired into this Vault. Original data is retained.".into())
}
impl Evidence {
    fn checkpoint(&self, owner: &Workspace) -> Result<Checkpoint, AppError> {
        if self.version != 1 {
            return Err(invalid());
        }
        let anchor = owner.control.anchor.as_ref().ok_or_else(invalid)?;
        let chain = self
            .proof
            .verify(anchor, owner.control.highwater.as_ref())?;
        let status = &self.status;
        let manifest = &status.manifest;
        let b = &manifest.body;
        let author = chain
            .author_at(&b.membership_head, &b.author)
            .ok_or_else(invalid)?;
        crypto::verify(&author.signing, &b.canonical()?, &manifest.signature)?;
        if b.origin != anchor.origin
            || b.account_id != anchor.account_id
            || b.genesis_hash != anchor.genesis_hash
            || owner.control.personal_vault.as_ref() != Some(&b.vault_id)
            || number(&b.key_epoch, false)? != 1
            || number(&b.authorization_epoch, false)? > owner.control.auth_epoch
            || status.manifest_digest != manifest.digest()?
            || status.phase != "retired"
            || status.staged != b.target_sequence
            || status.history_hash != b.target_history_hash
            || number(&status.retired, true)? != b.sources.len() as u64
        {
            return Err(retained());
        }
        Ok(Checkpoint {
            epoch: 1,
            sequence: number(&b.target_sequence, false)?,
            history_hash: b.target_history_hash.clone(),
        })
    }
    pub(super) fn control_minimum(
        &self,
        owner: &Workspace,
    ) -> Result<super::captured::ControlMinimum, AppError> {
        drop(self.checkpoint(owner)?);
        let chain = self.proof.verify(
            owner.control.anchor.as_ref().ok_or_else(invalid)?,
            owner.control.highwater.as_ref(),
        )?;
        Ok(super::captured::ControlMinimum {
            highwater: chain.highwater(),
            auth_epoch: number(&self.status.manifest.body.authorization_epoch, false)?,
        })
    }
    pub(super) fn witness(&self, owner: &Workspace) -> Result<Witness, AppError> {
        Ok(Witness {
            checkpoint: self.checkpoint(owner)?,
            evidence: self.clone(),
        })
    }
    pub(super) fn require_read(
        &self,
        read: &VerifiedLibrary,
        transcript: &Transcript,
    ) -> Result<(), AppError> {
        let floor = self.checkpoint(read.previous_owner())?;
        // The reader's membership chain must extend the same signed manifest, even after rekey.
        let b = &self.status.manifest.body;
        let author = read
            .chain()
            .author_at(&b.membership_head, &b.author)
            .ok_or_else(invalid)?;
        crypto::verify(
            &author.signing,
            &b.canonical()?,
            &self.status.manifest.signature,
        )?;
        let bridges: Vec<_> = transcript
            .bridges
            .iter()
            .filter(|bridge| bridge.epoch > floor.epoch)
            .cloned()
            .collect();
        let translated = super::super::replacement_proof::extend_minimums(
            read.chain(),
            &b.vault_id,
            read.epochs(),
            std::slice::from_ref(&floor),
            &bridges,
            read.checkpoint().epoch,
        )?;
        if translated
            .iter()
            .any(|prefix| !read.verifies_prefix(prefix))
        {
            return Err(retained());
        }
        Ok(())
    }
}
impl Witness {
    pub(super) fn checkpoint(&self) -> &Checkpoint {
        &self.checkpoint
    }
    pub(super) fn evidence(&self) -> Evidence {
        self.evidence.clone()
    }
    pub(in crate::sync::central) fn require_inventory(
        &self,
        owner: &Workspace,
        sources: &Sources,
        inventory: &Inventory,
    ) -> Result<(), AppError> {
        if self.evidence.checkpoint(owner)? != self.checkpoint
            || sources.legacy_origin() != Some(owner.control.profile.origin.as_str())
        {
            return Err(retained());
        }
        inventory.require_retired_sources(&self.evidence.status.manifest.body.sources)?;
        if sources.chains().iter().any(|id| {
            !self
                .evidence
                .status
                .manifest
                .body
                .sources
                .iter()
                .any(|source| &source.chain_id == id)
        }) {
            return Err(retained());
        }
        Ok(())
    }
}
pub(super) fn fetch(
    env: &SyncEnv,
    scope: &Scope,
    owner: &Workspace,
    selected: &Arc<Session>,
    budget: &Budget,
) -> Result<Witness, AppError> {
    scope.check(env)?;
    super::super::source_capture::require_selected(env, owner, selected)?;
    let api = Api::bounded(&owner.control.profile.origin, budget)?;
    let device = selected.device.as_ref().ok_or_else(invalid)?;
    let overview = api.account(device)?;
    scope.check(env)?;
    super::super::round::require_success(env, &overview)?;
    let overview: super::super::api::AccountOverview = overview.decode()?;
    overview.validate(device)?;
    if overview.account_id != owner.control.account_id
        || overview.auth_epoch != owner.control.auth_epoch
        || overview.device_state != super::super::api::DeviceState::Active
        || overview.denied.contains(&owner.control.device.id)
    {
        return Err(invalid());
    }
    let proof = overview.proof.ok_or_else(invalid)?;
    let reply = api.migration_status(
        device,
        owner
            .control
            .personal_vault
            .as_deref()
            .ok_or_else(invalid)?,
        false,
    )?;
    scope.check(env)?;
    super::super::round::require_success(env, &reply)?;
    Evidence {
        version: 1,
        proof,
        status: reply.decode()?,
    }
    .witness(owner)
}
