//! Active-device full-snapshot admission. This is distinct from pending-device kit-PoP recovery.
//! Completed reads contain native keys only and grant no repository/Core publication authority.
use super::{
    client_state::Phase,
    credentials::DeviceIdentity,
    recovery_read::{Baseline, HistoryPage, RecoveryVault},
    recovery_revalidation::Bridge,
    rekey::{self, Checkpoint, SignedRekey},
    replacement_proof::{extend_minimums, minimums},
    replica::Replica,
    trust::{ControlProof, VerifiedChain},
    wire::{invalid, number, MAX_SAFE_INTEGER},
    workspace::Workspace,
};
use crate::error::AppError;

/// Ciphertext and account checkpoint assembled from bounded authenticated API responses.
#[derive(Clone)]
pub struct Snapshot {
    pub membership_head: String,
    pub auth_epoch: u64,
    pub vault: RecoveryVault,
}
pub struct ReadSession {
    before: Workspace,
    proof: ControlProof,
    auth_epoch: u64,
    baseline: Baseline,
}
/// A saved Replica or service DTO cannot construct this completed-read capability.
pub struct VerifiedLibrary {
    session: ReadSession,
}
impl ReadSession {
    pub fn begin(
        before: &Workspace,
        identity: &DeviceIdentity,
        proof: ControlProof,
        snapshot: Snapshot,
        bridges: &[Bridge],
    ) -> Result<Self, AppError> {
        before.validate()?;
        let Snapshot {
            membership_head,
            auth_epoch,
            vault: source,
        } = snapshot;
        let control = &before.control;
        let anchor = control.anchor.as_ref().ok_or_else(invalid)?;
        let profile = control.profile.profile()?;
        if !matches!(
            control.phase,
            Phase::Enrolled | Phase::Active | Phase::Rekey
        ) || before.replacement.is_some()
            || before.bootstrap.is_some()
            || control.device != identity.device()
            || control.denied_devices.contains(&identity.id)
            || auth_epoch < control.auth_epoch
            || auth_epoch > MAX_SAFE_INTEGER
            || identity.slot(&profile, "device")?
                != profile.device_slot("device", before.identity_slot.as_deref())?
        {
            return Err(invalid());
        }
        let chain = proof.verify(anchor, control.highwater.as_ref())?;
        if membership_head != chain.current().head()
            || chain.current().devices().get(&identity.id) != Some(&identity.keys.public())
            || control.personal_vault.as_deref() != Some(source.vault.as_str())
            || !source.commits.starts_with(&before.epochs)
            || !source.commits.starts_with(&before.observed_epochs)
        {
            return Err(invalid());
        }
        let checked = Baseline::snapshot(&chain, source, auth_epoch)?;
        let source = checked.source();
        let target = checked.target();
        let h = &source.wrap.header;
        if h.origin != anchor.origin
            || h.account_id != anchor.account_id
            || h.genesis_hash != anchor.genesis_hash
            || h.vault_id != source.vault
            || h.recipient != identity.id
            || h.recipient_key != identity.keys.public().encryption
            || number(&h.key_epoch, false)? != target.epoch
            || !chain.contains_device(&h.membership_head, &control.device)
        {
            return Err(invalid());
        }
        let author = chain
            .author_at(&h.membership_head, &h.author)
            .ok_or_else(invalid)?;
        let keys = source.wrap.open(&identity.keys, h, &author.signing)?;
        if let Some(bundle) = &source.committed {
            let body = &bundle.manifest.body;
            if chain.revision_of(&h.membership_head).ok_or_else(invalid)?
                < chain
                    .revision_of(&body.membership_head)
                    .ok_or_else(invalid)?
                || target.sequence < number(&body.source_sequence, true)?
            {
                return Err(invalid());
            }
            if bundle
                .wraps
                .iter()
                .any(|wrap| wrap.header.recipient == identity.id)
            {
                let committed = rekey::open_committed_keys(
                    &chain,
                    &bundle.manifest,
                    &bundle.wraps,
                    &identity.id,
                    &identity.keys,
                )?;
                keys.verify_same(&committed)?;
            }
        }
        let (floors, creation, creation_auth) = if let Some(minimums) = minimums(before)? {
            minimums
        } else {
            if proof.genesis.first != control.device {
                return Err(invalid());
            }
            (
                vec![Checkpoint {
                    epoch: 1,
                    sequence: 0,
                    history_hash: "0".repeat(64),
                }],
                anchor.genesis_hash.clone(),
                2,
            )
        };
        let pinned = extend_minimums(
            &chain,
            &source.vault,
            &source.commits,
            &floors,
            bridges,
            target.epoch,
        )?;
        // Keep the original authenticated minimum when already in this epoch. Otherwise the
        // signed source bridges provide the new epoch's minimum, not a service latest hint.
        let minimum = if let Some(replica) = &before.replica {
            if replica.checkpoint.epoch == target.epoch {
                replica.minimum.clone()
            } else {
                pinned.last().cloned()
            }
        } else if before.control.pairing_confirmation.is_some() || target.epoch > 1 {
            pinned.last().cloned()
        } else {
            None
        };
        let mut baseline = Baseline::new(chain, keys, checked, creation, creation_auth)?;
        baseline.replica.minimum = minimum;
        baseline.replica.validate(&baseline.chain)?;
        baseline.pin_prefixes(pinned)?;
        baseline.retain_prefix_hashes()?;
        Ok(Self {
            before: before.clone(),
            proof,
            auth_epoch,
            baseline,
        })
    }
    pub(super) fn previous_owner(&self) -> &Workspace {
        &self.before
    }
    pub(super) fn proof(&self) -> &ControlProof {
        &self.proof
    }
    pub(super) fn auth_epoch(&self) -> u64 {
        self.auth_epoch
    }
    pub(super) fn chain(&self) -> &VerifiedChain {
        &self.baseline.chain
    }
    pub(super) fn checkpoint(&self) -> &Checkpoint {
        &self.baseline.target
    }
    pub(super) fn epochs(&self) -> &[SignedRekey] {
        &self.baseline.source.commits
    }
    pub(super) fn replica(&self) -> &Replica {
        &self.baseline.replica
    }
    pub(super) fn pin_prefixes(&mut self, minimums: Vec<Checkpoint>) -> Result<(), AppError> {
        self.baseline.pin_prefixes(minimums)
    }
    pub fn position(&self) -> u64 {
        self.baseline.position()
    }
    pub fn total(&self) -> u64 {
        self.baseline.target.sequence
    }
    pub fn vault(&self) -> &str {
        &self.baseline.source.vault
    }
    pub fn append(&mut self, page: HistoryPage) -> Result<(), AppError> {
        self.baseline.append(page)
    }
    pub fn finish(self) -> Result<VerifiedLibrary, AppError> {
        self.baseline.complete()?;
        Ok(VerifiedLibrary { session: self })
    }
}
impl VerifiedLibrary {
    pub(super) fn wrap(&self) -> &super::crypto::WrappedKeys {
        &self.session.baseline.source.wrap
    }
    pub(super) fn phase(&self) -> &str {
        &self.session.baseline.source.phase
    }
    pub(super) fn verifies_prefix(&self, minimum: &Checkpoint) -> bool {
        self.session.baseline.verifies_prefix(minimum)
    }
    pub fn previous_owner(&self) -> &Workspace {
        &self.session.before
    }
    pub fn proof(&self) -> &ControlProof {
        &self.session.proof
    }
    pub fn auth_epoch(&self) -> u64 {
        self.session.auth_epoch
    }
    pub fn checkpoint(&self) -> &Checkpoint {
        &self.session.baseline.target
    }
    pub fn chain(&self) -> &VerifiedChain {
        &self.session.baseline.chain
    }
    pub fn keys(&self) -> &super::crypto::VaultKeys {
        &self.session.baseline.keys
    }
    pub fn replica(&self) -> &Replica {
        &self.session.baseline.replica
    }
    pub fn epochs(&self) -> &[SignedRekey] {
        &self.session.baseline.source.commits
    }
}

#[cfg(test)]
mod tests {
    use super::super::{
        crypto,
        recovery_read::tests::{active_case, ActiveCase},
        rekey::{self, Version},
        wire::canonical,
    };
    use super::*;
    fn begin(c: &ActiveCase) -> Result<ReadSession, AppError> {
        ReadSession::begin(
            &c.owner,
            &c.identity,
            c.proof.clone(),
            c.snapshot.clone(),
            &c.bridges,
        )
    }
    fn page(c: &ActiveCase, rows: &[Version]) -> HistoryPage {
        HistoryPage {
            records: rows.to_vec(),
            sequence: c.snapshot.vault.sequence.clone(),
            history_hash: c.snapshot.vault.history_hash.clone(),
            membership_head: c.snapshot.membership_head.clone(),
            epoch: c.snapshot.vault.epoch,
            phase: c.snapshot.vault.phase.clone(),
        }
    }
    #[test]
    fn full_original_device_reads_preserve_the_known_scope_across_empty_current_and_rotated_snapshots(
    ) {
        for count in [0, 33] {
            for rotated in [false, true] {
                let c = active_case(count, rotated);
                let mut reader = begin(&c).unwrap();
                for rows in c.rows.chunks(32) {
                    reader.append(page(&c, rows)).unwrap();
                }
                let verified = reader.finish().unwrap();
                assert_eq!(verified.checkpoint().sequence, count);
                assert_eq!(verified.replica().current.len() as u64, count);
                assert_eq!(verified.previous_owner(), &c.owner);
                assert_eq!(verified.proof(), &c.proof);
                assert_eq!(verified.auth_epoch(), c.snapshot.auth_epoch);
                assert_eq!(verified.epochs(), c.snapshot.vault.commits);
                verified.keys().verify_same(&c.keys).unwrap();
                assert!(!serde_json::to_string(verified.replica())
                    .unwrap()
                    .contains("fixture.invalid"));
            }
        }
    }
    #[test]
    fn late_page_failure_preserves_only_the_native_verified_prefix_and_cannot_complete() {
        let c = active_case(33, false);
        let mut reader = begin(&c).unwrap();
        reader.append(page(&c, &c.rows[..32])).unwrap();
        assert_eq!(reader.position(), 32);
        let mut wrong = page(&c, &c.rows[32..]);
        wrong.membership_head = "f".repeat(64);
        assert!(reader.append(wrong).is_err());
        assert_eq!(reader.position(), 32);
        let mut wrong = page(&c, &c.rows[32..]);
        wrong.records[0].envelope.signature = "AA==".into();
        assert!(reader.append(wrong).is_err());
        assert_eq!(reader.position(), 32);
        assert!(reader.finish().is_err());
    }
    #[test]
    fn mismatched_source_identity_scope_and_checkpoint_never_mint_a_reader_even_for_empty_history()
    {
        for mutation in 0..10 {
            let mut c = active_case(0, false);
            match mutation {
                0 => c.snapshot.membership_head = "f".repeat(64),
                1 => c.snapshot.auth_epoch = 1,
                2 => c.snapshot.vault.vault = "f".repeat(64),
                3 => c.snapshot.vault.wrap.header.recipient = "f".repeat(32),
                4 => {
                    c.snapshot.vault.wrap.header.recipient_key =
                        crypto::DeviceKeys::generate().unwrap().public().encryption
                }
                5 => c.owner.identity_slot = Some("d".repeat(32)),
                6 => c.owner.control.phase = Phase::SignedOut,
                7 => c
                    .owner
                    .control
                    .denied_devices
                    .insert(c.identity.id.clone())
                    .then_some(())
                    .unwrap(),
                8 => c.snapshot.vault.history_hash = "f".repeat(64),
                _ => c.snapshot.vault.phase = "revocation_pending".into(),
            }
            assert!(begin(&c).is_err(), "mutation {mutation}");
        }
        let c = active_case(1, false);
        let wrong = active_case(1, false);
        assert!(ReadSession::begin(
            &c.owner,
            &wrong.identity,
            c.proof.clone(),
            c.snapshot.clone(),
            &c.bridges
        )
        .is_err());
        assert!(ReadSession::begin(
            &c.owner,
            &c.identity,
            wrong.proof,
            c.snapshot.clone(),
            &c.bridges
        )
        .is_err());
    }
    #[test]
    fn committed_epoch_cannot_use_an_aborted_wrap_or_omit_the_original_source_extension() {
        let mut c = active_case(0, true);
        c.snapshot.vault.wrap = crypto::wrap_keys(
            &c.keys.next_epoch().unwrap(),
            &c.identity.keys,
            c.snapshot.vault.wrap.header.clone(),
        )
        .unwrap();
        assert!(begin(&c).is_err());
        let mut c = active_case(2, true);
        c.bridges.clear();
        assert!(begin(&c).is_err());
        let mut c = active_case(2, true);
        c.bridges[0].digests[0].digest = "f".repeat(64);
        assert!(begin(&c).is_err());
        let mut c = active_case(2, true);
        c.snapshot.vault.committed.as_mut().unwrap().wraps.pop();
        assert!(begin(&c).is_err());
        let mut c = active_case(2, true);
        c.snapshot.vault.commits.clear();
        assert!(begin(&c).is_err());
    }
    #[test]
    fn both_partial_verified_history_and_an_unread_higher_minimum_are_pinned() {
        let mut c = active_case(2, false);
        let current = c
            .owner
            .replica
            .as_ref()
            .unwrap()
            .prepare_page(
                &c.proof
                    .verify(c.owner.control.anchor.as_ref().unwrap(), None)
                    .unwrap(),
                &c.keys,
                &c.rows[..1],
                &Checkpoint {
                    epoch: 1,
                    sequence: 1,
                    history_hash: c.rows[0].history_hash.clone(),
                },
            )
            .unwrap()
            .next;
        c.owner.replica = Some(current);
        c.owner.replica.as_mut().unwrap().minimum = Some(Checkpoint {
            epoch: 1,
            sequence: 2,
            history_hash: c.rows[1].history_hash.clone(),
        });
        c.owner.validate().unwrap();
        let mut reader = begin(&c).unwrap();
        reader.append(page(&c, &c.rows)).unwrap();
        reader.finish().unwrap();
        c.snapshot.vault.sequence = "1".into();
        c.snapshot.vault.history_hash = c.rows[0].history_hash.clone();
        assert!(begin(&c).is_err());
    }
    #[test]
    fn every_signed_version_is_admitted_even_when_a_later_valid_update_supersedes_it() {
        use super::super::payload::{self, Data, Identity};
        use crate::sync::records_v3::HostScope;
        let mut c = active_case(2, false);
        let id = Identity {
            kind: "host".into(),
            id: "0000000000000001".into(),
            scope: Some(HostScope::Local),
        };
        let valid=payload::encode(&id,&Data::Host(serde_json::from_value(serde_json::json!({"schema":2,"alias":"latest-valid","hostname":"fixture.invalid","auth":"password"})).unwrap())).unwrap();
        let invalid=serde_json::to_vec(&serde_json::json!({"schema":1,"id":id.id,"scope":id.scope,"payload":{"schema":2,"alias":"bad-old","hostname":"fixture.invalid","auth":"password","password":"PRIVATE-LOCAL-SENTINEL"}})).unwrap();
        let mut previous = "0".repeat(64);
        for (index, bytes) in [invalid.as_slice(), valid.as_slice()]
            .into_iter()
            .enumerate()
        {
            let row = &mut c.rows[index];
            let mut h = row.envelope.header.clone();
            h.record_id = id.opaque(&c.keys).unwrap();
            h.expected_revision = index.to_string();
            row.revision = (index + 1).to_string();
            row.envelope = crypto::seal_record(&c.keys, &c.identity.keys, h, bytes).unwrap();
            row.digest = rekey::envelope_digest(&row.envelope).unwrap();
            row.history_hash = crypto::hash(
                &canonical(&["lunport-history-v2", &previous, &row.sequence, &row.digest]).unwrap(),
            );
            previous = row.history_hash.clone();
        }
        c.snapshot.vault.history_hash = previous;
        let mut reader = begin(&c).unwrap();
        assert!(reader.append(page(&c, &c.rows)).is_err());
        assert_eq!(reader.position(), 0);
        assert!(reader.finish().is_err());
    }
}
