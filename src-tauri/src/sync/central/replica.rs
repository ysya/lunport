//! Durable ciphertext replica/outbox. A receipt is only a claim until signed history confirms it.
//! Callers validate decoded library payloads before publishing PreparedPage under the SyncCore CAS.
use super::{
    crypto::{self, DeviceKeys, RecordEnvelope, VaultKeys},
    rekey::{self, Checkpoint, SignedRekey, Version},
    trust::VerifiedChain,
    wire::{canonical, hex, invalid, number, RecordHeader, MAX_SAFE_INTEGER},
};
use crate::error::AppError;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use zeroize::Zeroizing;
const ZERO: &str = "0000000000000000000000000000000000000000000000000000000000000000";
const CAP: usize = 32 * 1024 * 1024;
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Receipt {
    pub operation_id: String,
    pub record_id: String,
    pub revision: String,
    pub sequence: String,
    pub digest: String,
    pub history_hash: String,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Draft {
    pub local_revision: u64,
    pub content_hash: String,
    pub envelope: RecordEnvelope,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Pending {
    pub latest: Draft,
    pub sent: Option<Draft>,
    pub claimed: Option<Receipt>,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Base {
    pub version: Version,
    pub content_hash: String,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Conflict {
    pub base: Option<Base>,
    pub local: Draft,
    pub remote: Base,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Replica {
    pub vault: String,
    pub creation_head: String,
    pub creation_authorization_epoch: u64,
    pub checkpoint: Checkpoint,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub needs_epoch_rebuild: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub minimum: Option<Checkpoint>,
    pub current: BTreeMap<String, Base>,
    pub pending: BTreeMap<String, Pending>,
    pub conflicts: BTreeMap<String, Vec<Conflict>>,
}
/// Plaintext never belongs to persistent replica state or a frontend DTO.
pub struct Opened {
    pub version: Version,
    pub plaintext: Zeroizing<Vec<u8>>,
    pub publish: bool,
}
pub struct PreparedPage {
    pub next: Replica,
    pub opened: Vec<Opened>,
    pub publish_baseline: bool,
}
impl Receipt {
    fn validate(&self) -> Result<(), AppError> {
        if !hex(&self.operation_id, 32)
            || !hex(&self.record_id, 64)
            || !hex(&self.digest, 64)
            || !hex(&self.history_hash, 64)
            || number(&self.sequence, false)? > 16384
        {
            return Err(invalid());
        }
        number(&self.revision, false)?;
        Ok(())
    }
    fn matches(&self, draft: &Draft) -> Result<(), AppError> {
        self.validate()?;
        let h = &draft.envelope.header;
        if self.operation_id != h.operation_id
            || self.record_id != h.record_id
            || number(&self.revision, false)? != number(&h.expected_revision, true)? + 1
            || self.digest != rekey::envelope_digest(&draft.envelope)?
        {
            return Err(invalid());
        }
        Ok(())
    }
}
impl Replica {
    pub fn new(
        vault: String,
        creation_head: String,
        creation_authorization_epoch: u64,
    ) -> Result<Self, AppError> {
        if !hex(&vault, 64)
            || !hex(&creation_head, 64)
            || creation_authorization_epoch == 0
            || creation_authorization_epoch > MAX_SAFE_INTEGER
        {
            return Err(invalid());
        }
        Ok(Self {
            vault,
            creation_head,
            creation_authorization_epoch,
            checkpoint: Checkpoint {
                epoch: 1,
                sequence: 0,
                history_hash: ZERO.into(),
            },
            needs_epoch_rebuild: false,
            minimum: None,
            current: BTreeMap::new(),
            pending: BTreeMap::new(),
            conflicts: BTreeMap::new(),
        })
    }
    pub fn join(
        vault: String,
        creation_head: String,
        creation_authorization_epoch: u64,
        minimum: Checkpoint,
    ) -> Result<Self, AppError> {
        if minimum.epoch == 0
            || minimum.epoch > 65
            || minimum.sequence > 16384
            || !hex(&minimum.history_hash, 64)
            || minimum.sequence == 0 && minimum.history_hash != ZERO
        {
            return Err(invalid());
        }
        let mut replica = Self::new(vault, creation_head, creation_authorization_epoch)?;
        replica.checkpoint.epoch = minimum.epoch;
        replica.minimum = Some(minimum);
        Ok(replica)
    }
    pub fn baseline_ready(&self) -> bool {
        !self.needs_epoch_rebuild
            && self.minimum.as_ref().is_none_or(|m| {
                m.epoch == self.checkpoint.epoch && self.checkpoint.sequence >= m.sequence
            })
    }
    pub fn validate(&self, chain: &VerifiedChain) -> Result<(), AppError> {
        if !hex(&self.vault, 64)
            || !chain.has_head(&self.creation_head)
            || self.creation_authorization_epoch == 0
            || self.creation_authorization_epoch > MAX_SAFE_INTEGER
            || self.checkpoint.epoch == 0
            || self.checkpoint.epoch > MAX_SAFE_INTEGER
            || self.checkpoint.sequence > 16384
            || !hex(&self.checkpoint.history_hash, 64)
            || self.checkpoint.sequence == 0 && self.checkpoint.history_hash != ZERO
            || self.current.len() > 4096
            || self.pending.len() > 4096
            || self.conflicts.len() > 4096
            || serde_json::to_vec(self).map_err(|_| invalid())?.len() > CAP
        {
            return Err(invalid());
        }
        if let Some(minimum) = &self.minimum {
            if minimum.epoch != self.checkpoint.epoch
                || minimum.sequence > 16384
                || !hex(&minimum.history_hash, 64)
                || minimum.sequence == 0 && minimum.history_hash != ZERO
                || minimum.sequence == self.checkpoint.sequence
                    && minimum.history_hash != self.checkpoint.history_hash
            {
                return Err(invalid());
            }
        }
        let check_envelope = |id: &str, envelope: &RecordEnvelope| -> Result<(), AppError> {
            let h = &envelope.header;
            let anchor = chain.current().anchor();
            if !hex(id, 64)
                || h.record_id != id
                || h.origin != anchor.origin
                || h.account_id != anchor.account_id
                || h.genesis_hash != anchor.genesis_hash
                || h.vault_id != self.vault
                || number(&h.key_epoch, false)? > self.checkpoint.epoch
            {
                return Err(invalid());
            }
            let author = chain
                .author_at(&h.membership_head, &h.author)
                .ok_or_else(invalid)?;
            envelope.verify(&author.signing)?;
            Ok(())
        };
        let check_draft = |id: &str, d: &Draft| -> Result<(), AppError> {
            if d.local_revision == 0 || !hex(&d.content_hash, 64) {
                return Err(invalid());
            }
            check_envelope(id, &d.envelope)
        };
        let check_base = |id: &str, b: &Base| -> Result<(), AppError> {
            let v = &b.version;
            let h = &v.envelope.header;
            if !hex(&b.content_hash, 64)
                || !hex(&v.history_hash, 64)
                || number(&v.revision, false)? != number(&h.expected_revision, true)? + 1
                || number(&v.sequence, false)? > self.checkpoint.sequence
                || v.digest != rekey::envelope_digest(&v.envelope)?
            {
                return Err(invalid());
            }
            check_envelope(id, &v.envelope)
        };
        let mut operations = BTreeSet::new();
        for (id, b) in &self.current {
            check_base(id, b)?;
        }
        for (id, p) in &self.pending {
            check_draft(id, &p.latest)?;
            if !operations.insert(&p.latest.envelope.header.operation_id) {
                return Err(invalid());
            }
            if let Some(sent) = &p.sent {
                check_draft(id, sent)?;
                if sent.local_revision > p.latest.local_revision
                    || sent.local_revision == p.latest.local_revision
                        && sent.content_hash != p.latest.content_hash
                    || sent.envelope.header.kind != p.latest.envelope.header.kind
                    || sent.envelope.header.operation_id == p.latest.envelope.header.operation_id
                        && sent != &p.latest
                {
                    return Err(invalid());
                }
                if sent.envelope.header.operation_id != p.latest.envelope.header.operation_id
                    && !operations.insert(&sent.envelope.header.operation_id)
                {
                    return Err(invalid());
                }
            }
            if let Some(claim) = &p.claimed {
                claim.matches(p.sent.as_ref().ok_or_else(invalid)?)?;
            }
        }
        let mut count = 0;
        for (id, conflicts) in &self.conflicts {
            if conflicts.is_empty() || conflicts.len() > 16 {
                return Err(invalid());
            }
            for c in conflicts {
                count += 1;
                if count > 8192 {
                    return Err(invalid());
                }
                if let Some(base) = &c.base {
                    check_base(id, base)?;
                }
                check_draft(id, &c.local)?;
                check_base(id, &c.remote)?;
            }
        }
        Ok(())
    }
    /// Capture immutable local bytes before network work. Never overwrite a still-uncertain transmission.
    pub fn enqueue(
        &mut self,
        chain: &VerifiedChain,
        keys: &VaultKeys,
        signer: &DeviceKeys,
        mut local_revision: u64,
        mut header: RecordHeader,
        plaintext: &[u8],
    ) -> Result<(), AppError> {
        if local_revision == 0 {
            return Err(invalid());
        }
        let id = header.record_id.clone();
        let content_hash = crypto::hash(plaintext);
        let base = self
            .current
            .get(&id)
            .map_or("0", |b| b.version.revision.as_str());
        if let Some(p) = self.pending.get(&id) {
            if p.latest.content_hash == content_hash
                && p.latest.envelope.header.kind == header.kind
                && p.latest.envelope.header.deleted == header.deleted
            {
                let old = &p.latest.envelope.header;
                if p.sent.is_some()
                    || old.expected_revision == base
                        && old.membership_head == chain.current().head()
                        && number(&old.key_epoch, false)? == self.checkpoint.epoch
                {
                    return Ok(());
                }
                // Same immutable local edit, rebased onto newly verified transport state.
                local_revision = p.latest.local_revision;
            } else if local_revision <= p.latest.local_revision {
                return Err(invalid());
            }
        } else if self.current.get(&id).is_some_and(|b| {
            b.content_hash == content_hash
                && b.version.envelope.header.kind == header.kind
                && b.version.envelope.header.deleted == header.deleted
        }) {
            return Ok(());
        }
        header.expected_revision = base.into();
        header.operation_id = crypto::random_id(16)?;
        let envelope = crypto::seal_record(keys, signer, header, plaintext)?;
        chain.current().verify_write(
            &envelope,
            &self.vault,
            self.checkpoint.epoch,
            &envelope.header.author,
        )?;
        let previous = self.pending.get(&id);
        let next = Pending {
            latest: Draft {
                local_revision,
                content_hash,
                envelope,
            },
            sent: previous.and_then(|p| p.sent.clone()),
            claimed: previous.and_then(|p| p.claimed.clone()),
        };
        let mut candidate = self.clone();
        candidate.pending.insert(id, next);
        candidate.validate(chain)?;
        *self = candidate;
        Ok(())
    }
    pub fn verify_write_authority(
        &self,
        chain: &VerifiedChain,
        authorization_epoch: u64,
        minimum_epoch: u64,
        commits: &[SignedRekey],
    ) -> Result<(), AppError> {
        rekey::require_write_epoch(
            chain,
            &self.vault,
            self.checkpoint.epoch,
            minimum_epoch,
            &self.creation_head,
            commits,
        )?;
        let (head, auth) = if let Some(last) = commits.last() {
            (
                &last.body.membership_head,
                number(&last.body.authorization_epoch, false)?,
            )
        } else {
            (&self.creation_head, self.creation_authorization_epoch)
        };
        let revision = chain.revision_of(head).ok_or_else(invalid)? as u64;
        // Normal membership additions each account for one auth-epoch advance. Extra cloud-access
        // revocations at an unchanged signed head cannot be hidden behind a service readiness flag.
        if authorization_epoch == 0
            || authorization_epoch > MAX_SAFE_INTEGER
            || auth.checked_add(chain.current().revision() - revision) != Some(authorization_epoch)
        {
            return Err(invalid());
        }
        Ok(())
    }
    /// Persist this candidate before dispatching returned bytes. All retries use exactly the sent operation.
    pub fn prepare_send(
        &mut self,
        chain: &VerifiedChain,
        minimum_epoch: u64,
        authorization_epoch: u64,
        commits: &[SignedRekey],
    ) -> Result<Vec<RecordEnvelope>, AppError> {
        if !self.baseline_ready() {
            return Err(AppError::Other("Wait for the approved device's complete data checkpoint before uploading. Local changes are retained.".into()));
        }
        self.verify_write_authority(chain, authorization_epoch, minimum_epoch, commits)?;
        let mut candidate = self.clone();
        let mut rows = Vec::new();
        for (id, p) in &mut candidate.pending {
            if rows.len() == 32 {
                break;
            }
            if self.conflicts.get(id).is_some_and(|c| !c.is_empty()) || p.claimed.is_some() {
                continue;
            }
            let draft = p.sent.as_ref().unwrap_or(&p.latest);
            let h = &draft.envelope.header;
            // Changed membership/epoch and a newly accepted base require explicit reconciliation/rebase.
            if h.membership_head != chain.current().head()
                || number(&h.key_epoch, false)? != self.checkpoint.epoch
                || number(&h.expected_revision, true)?
                    != self
                        .current
                        .get(id)
                        .map_or(Ok(0), |b| number(&b.version.revision, false))?
            {
                continue;
            }
            chain.current().verify_write(
                &draft.envelope,
                &self.vault,
                self.checkpoint.epoch,
                &h.author,
            )?;
            let sent = draft.clone();
            rows.push(sent.envelope.clone());
            p.sent = Some(sent);
        }
        candidate.validate(chain)?;
        *self = candidate;
        Ok(rows)
    }
    pub fn note_receipt(
        &mut self,
        chain: &VerifiedChain,
        receipt: Receipt,
    ) -> Result<(), AppError> {
        let pending = self.pending.get(&receipt.record_id).ok_or_else(invalid)?;
        receipt.matches(pending.sent.as_ref().ok_or_else(invalid)?)?;
        if number(
            &pending
                .sent
                .as_ref()
                .ok_or_else(invalid)?
                .envelope
                .header
                .key_epoch,
            false,
        )? == self.checkpoint.epoch
            && number(&receipt.sequence, false)? <= self.checkpoint.sequence
        {
            return Err(invalid());
        }

        if pending.claimed.as_ref().is_some_and(|old| old != &receipt) {
            return Err(invalid());
        }
        let mut candidate = self.clone();
        let record_id = receipt.record_id.clone();
        candidate.pending.get_mut(&record_id).unwrap().claimed = Some(receipt);
        candidate.validate(chain)?;
        *self = candidate;
        Ok(())
    }
    /// Verification is transactional in memory. No partial page, cursor or conflict escapes on failure.
    pub fn prepare_page(
        &self,
        chain: &VerifiedChain,
        keys: &VaultKeys,
        rows: &[Version],
        advertised: &Checkpoint,
    ) -> Result<PreparedPage, AppError> {
        self.validate(chain)?;
        if advertised.epoch != self.checkpoint.epoch
            || advertised.sequence < self.checkpoint.sequence
            || advertised.sequence > 16384
            || !hex(&advertised.history_hash, 64)
            || rows.len() > 32
            || rows.is_empty() && advertised != &self.checkpoint
        {
            return Err(invalid());
        }
        if self
            .minimum
            .as_ref()
            .is_some_and(|m| advertised.sequence < m.sequence)
        {
            return Err(invalid());
        }
        for p in self.pending.values() {
            if let Some(claim) = &p.claimed {
                if number(
                    &p.sent
                        .as_ref()
                        .ok_or_else(invalid)?
                        .envelope
                        .header
                        .key_epoch,
                    false,
                )? == advertised.epoch
                    && number(&claim.sequence, false)? > advertised.sequence
                {
                    return Err(invalid());
                }
            }
        }
        let mut next = self.clone();
        let mut opened = Vec::new();
        let mut bytes = 0;
        for row in rows {
            let h = &row.envelope.header;
            let seq = next.checkpoint.sequence + 1;
            let previous = next.current.get(&h.record_id).cloned();
            if number(&row.sequence, false)? != seq
                || seq > advertised.sequence
                || number(&row.revision, false)?
                    != previous
                        .as_ref()
                        .map_or(Ok(0), |b| number(&b.version.revision, false))?
                        + 1
                || number(&h.expected_revision, true)? + 1 != number(&row.revision, false)?
                || previous
                    .as_ref()
                    .is_some_and(|b| b.version.envelope.header.kind != h.kind)
                || h.origin != chain.current().anchor().origin
                || h.account_id != chain.current().anchor().account_id
                || h.genesis_hash != chain.current().anchor().genesis_hash
                || h.vault_id != self.vault
                || number(&h.key_epoch, false)? != self.checkpoint.epoch
                || row.digest != rekey::envelope_digest(&row.envelope)?
            {
                return Err(invalid());
            }
            let history_hash = crypto::hash(&canonical(&[
                "lunport-history-v2",
                &next.checkpoint.history_hash,
                &seq.to_string(),
                &row.digest,
            ])?);
            if self
                .minimum
                .as_ref()
                .is_some_and(|m| m.sequence == seq && m.history_hash != history_hash)
            {
                return Err(invalid());
            }
            if row.history_hash != history_hash {
                return Err(invalid());
            }
            let author = chain
                .author_at(&h.membership_head, &h.author)
                .ok_or_else(invalid)?;
            let plaintext = row.envelope.verify(&author.signing)?.open(keys)?;
            bytes += serde_json::to_vec(&row.envelope)
                .map_err(|_| invalid())?
                .len();
            if bytes > 2 * 1024 * 1024 {
                return Err(invalid());
            }
            let content_hash = crypto::hash(&plaintext);
            let remote = Base {
                version: row.clone(),
                content_hash: content_hash.clone(),
            };
            let mut clear = false;
            if let Some(p) = next.pending.get_mut(&h.record_id) {
                if let Some(claim) = &p.claimed {
                    let sent_epoch = number(
                        &p.sent
                            .as_ref()
                            .ok_or_else(invalid)?
                            .envelope
                            .header
                            .key_epoch,
                        false,
                    )?;
                    if sent_epoch == self.checkpoint.epoch
                        && number(&claim.sequence, false)? == seq
                        && (claim.operation_id != h.operation_id
                            || claim.digest != row.digest
                            || claim.history_hash != row.history_hash
                            || claim.revision != row.revision)
                    {
                        return Err(invalid());
                    }
                }
                if let Some(sent) = p
                    .sent
                    .as_ref()
                    .filter(|d| d.envelope.header.operation_id == h.operation_id)
                {
                    let old = &sent.envelope.header;
                    if sent.content_hash != content_hash
                        || old.kind != h.kind
                        || old.deleted != h.deleted
                        || old.expected_revision != h.expected_revision
                    {
                        return Err(invalid());
                    }
                    clear = p.latest.local_revision == sent.local_revision
                        && p.latest.content_hash == sent.content_hash;
                    p.sent = None;
                    p.claimed = None;
                } else if content_hash != p.latest.content_hash
                    && previous.as_ref().map(|b| &b.content_hash) != Some(&content_hash)
                {
                    let conflict = Conflict {
                        base: previous.clone(),
                        local: p.latest.clone(),
                        remote: remote.clone(),
                    };
                    let versions = next.conflicts.entry(h.record_id.clone()).or_default();
                    if !versions.contains(&conflict) {
                        versions.push(conflict);
                    }
                }
            }
            if clear {
                next.pending.remove(&h.record_id);
            }
            next.current.insert(h.record_id.clone(), remote);
            next.checkpoint = Checkpoint {
                epoch: self.checkpoint.epoch,
                sequence: seq,
                history_hash,
            };
            opened.push(Opened {
                version: row.clone(),
                plaintext,
                publish: next.baseline_ready() && !next.pending.contains_key(&h.record_id),
            });
        }
        if next.checkpoint.sequence == advertised.sequence
            && next.checkpoint.history_hash != advertised.history_hash
        {
            return Err(invalid());
        }
        next.validate(chain)?;
        let publish_baseline = !self.baseline_ready() && next.baseline_ready();
        Ok(PreparedPage {
            next,
            opened,
            publish_baseline,
        })
    }
}
#[cfg(test)]
mod tests {
    use super::super::{membership::TrustAnchor, trust::ControlProof};
    use super::*;
    use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
    struct Case {
        proof: ControlProof,
        anchor: TrustAnchor,
        keys: VaultKeys,
        signer: DeviceKeys,
        header: RecordHeader,
        replica: Replica,
    }
    fn case() -> Case {
        let fixture: serde_json::Value =
            serde_json::from_str(include_str!("../../../../fixtures/central-sync-v2.json"))
                .unwrap();
        let anchor = serde_json::from_value(fixture["anchor"].clone()).unwrap();
        let proof = ControlProof {
            genesis: serde_json::from_value(fixture["genesis"].clone()).unwrap(),
            nodes: vec![],
        };
        let chain = proof.verify(&anchor, None).unwrap();
        let mut header: RecordHeader =
            serde_json::from_value(fixture["record"]["header"].clone()).unwrap();
        header.membership_head = chain.current().head().into();
        let replica =
            Replica::new(header.vault_id.clone(), chain.current().head().into(), 1).unwrap();
        Case {
            proof,
            anchor,
            keys: VaultKeys::from_bytes(&[3; 64]).unwrap(),
            signer: DeviceKeys::decode_secret(&B64.encode([1; 64])).unwrap(),
            header,
            replica,
        }
    }
    fn row(envelope: RecordEnvelope, sequence: u64, previous: &str) -> Version {
        let digest = rekey::envelope_digest(&envelope).unwrap();
        let history_hash = crypto::hash(
            &canonical(&[
                "lunport-history-v2",
                previous,
                &sequence.to_string(),
                &digest,
            ])
            .unwrap(),
        );
        Version {
            revision: (number(&envelope.header.expected_revision, true).unwrap() + 1).to_string(),
            sequence: sequence.to_string(),
            envelope,
            digest,
            history_hash,
        }
    }
    fn checkpoint(row: &Version) -> Checkpoint {
        Checkpoint {
            epoch: 1,
            sequence: number(&row.sequence, false).unwrap(),
            history_hash: row.history_hash.clone(),
        }
    }
    fn receipt(row: &Version) -> Receipt {
        Receipt {
            operation_id: row.envelope.header.operation_id.clone(),
            record_id: row.envelope.header.record_id.clone(),
            revision: row.revision.clone(),
            sequence: row.sequence.clone(),
            digest: row.digest.clone(),
            history_hash: row.history_hash.clone(),
        }
    }
    #[test]
    fn an_inflight_a_ack_never_clears_a_later_local_b_even_after_serialized_restart() {
        let mut c = case();
        let chain = c.proof.verify(&c.anchor, None).unwrap();
        let id = c.header.record_id.clone();
        c.replica
            .enqueue(
                &chain,
                &c.keys,
                &c.signer,
                1,
                c.header.clone(),
                b"private synthetic A",
            )
            .unwrap();
        let sent = c.replica.prepare_send(&chain, 1, 1, &[]).unwrap();
        assert_eq!(sent.len(), 1);
        c.replica
            .enqueue(
                &chain,
                &c.keys,
                &c.signer,
                2,
                c.header.clone(),
                b"private synthetic B",
            )
            .unwrap();
        let a = row(sent[0].clone(), 1, ZERO);
        c.replica.note_receipt(&chain, receipt(&a)).unwrap();
        let encoded = serde_json::to_string(&c.replica).unwrap();
        assert!(!encoded.contains("private synthetic"));
        let restored: Replica = serde_json::from_str(&encoded).unwrap();
        restored.validate(&chain).unwrap();
        let page = restored
            .prepare_page(&chain, &c.keys, std::slice::from_ref(&a), &checkpoint(&a))
            .unwrap();
        assert!(!page.opened[0].publish);
        assert_eq!(&*page.opened[0].plaintext, b"private synthetic A");
        assert_eq!(page.next.pending[&id].latest.local_revision, 2);
        assert!(page.next.pending[&id].sent.is_none());
        let mut next = page.next;
        assert!(next.prepare_send(&chain, 1, 1, &[]).unwrap().is_empty());
        next.enqueue(
            &chain,
            &c.keys,
            &c.signer,
            3,
            c.header,
            b"private synthetic B",
        )
        .unwrap();
        assert_eq!(next.pending[&id].latest.local_revision, 2);
        let b = next.prepare_send(&chain, 1, 1, &[]).unwrap().pop().unwrap();
        assert_eq!(b.header.expected_revision, "1");
        assert!(next.note_receipt(&chain, receipt(&a)).is_err());
        assert!(next.pending[&id].sent.is_some());
        let b = row(b, 2, &a.history_hash);
        next.note_receipt(&chain, receipt(&b)).unwrap();
        assert!(!next.pending.is_empty());
        let done = next
            .prepare_page(&chain, &c.keys, std::slice::from_ref(&b), &checkpoint(&b))
            .unwrap();
        assert!(done.opened[0].publish);
        assert!(done.next.pending.is_empty());
        assert_eq!(done.next.checkpoint.sequence, 2);
    }
    #[test]
    fn response_loss_reuses_exact_operation_and_a_receipt_alone_keeps_the_dirty_edit() {
        let mut c = case();
        let chain = c.proof.verify(&c.anchor, None).unwrap();
        c.replica
            .enqueue(&chain, &c.keys, &c.signer, 1, c.header, b"offline")
            .unwrap();
        let first = c.replica.prepare_send(&chain, 1, 1, &[]).unwrap();
        let mut restarted: Replica =
            serde_json::from_str(&serde_json::to_string(&c.replica).unwrap()).unwrap();
        assert_eq!(first, restarted.prepare_send(&chain, 1, 1, &[]).unwrap());
        let accepted = row(first[0].clone(), 1, ZERO);
        restarted.note_receipt(&chain, receipt(&accepted)).unwrap();
        assert_eq!(restarted.checkpoint.sequence, 0);
        assert_eq!(restarted.pending.len(), 1);
        assert!(restarted
            .prepare_send(&chain, 1, 1, &[])
            .unwrap()
            .is_empty());
        let mut lie = receipt(&accepted);
        lie.digest = "9".repeat(64);
        let before = restarted.clone();
        assert!(restarted.note_receipt(&chain, lie).is_err());
        assert_eq!(before, restarted);
        assert!(restarted
            .prepare_page(
                &chain,
                &c.keys,
                &[],
                &Checkpoint {
                    epoch: 1,
                    sequence: 0,
                    history_hash: ZERO.into()
                }
            )
            .is_err());
    }
    #[test]
    fn concurrent_edits_preserve_base_local_and_remote_ciphertexts_without_overwriting_local() {
        let mut c = case();
        let chain = c.proof.verify(&c.anchor, None).unwrap();
        let id = c.header.record_id.clone();
        let first = crypto::seal_record(&c.keys, &c.signer, c.header.clone(), b"base").unwrap();
        let first = row(first, 1, ZERO);
        let page = c
            .replica
            .prepare_page(
                &chain,
                &c.keys,
                std::slice::from_ref(&first),
                &checkpoint(&first),
            )
            .unwrap();
        c.replica = page.next;
        c.replica
            .enqueue(&chain, &c.keys, &c.signer, 2, c.header.clone(), b"local")
            .unwrap();
        let mut h = c.header;
        h.expected_revision = "1".into();
        h.operation_id = "8".repeat(32);
        let remote = row(
            crypto::seal_record(&c.keys, &c.signer, h, b"remote").unwrap(),
            2,
            &first.history_hash,
        );
        let page = c
            .replica
            .prepare_page(
                &chain,
                &c.keys,
                std::slice::from_ref(&remote),
                &checkpoint(&remote),
            )
            .unwrap();
        assert!(!page.opened[0].publish);
        let conflict = &page.next.conflicts[&id][0];
        assert_eq!(conflict.base.as_ref().unwrap().version, first);
        assert_eq!(conflict.remote.version, remote);
        assert_eq!(conflict.local, page.next.pending[&id].latest);
        let mut next = page.next;
        assert!(next.prepare_send(&chain, 1, 1, &[]).unwrap().is_empty());
        let restored: Replica =
            serde_json::from_str(&serde_json::to_string(&next).unwrap()).unwrap();
        assert_eq!(next, restored);
    }
    #[test]
    fn a_bad_later_row_rejects_the_whole_page_and_preserves_the_prior_checkpoint() {
        let c = case();
        let chain = c.proof.verify(&c.anchor, None).unwrap();
        let a = row(
            crypto::seal_record(&c.keys, &c.signer, c.header.clone(), b"A").unwrap(),
            1,
            ZERO,
        );
        let mut h = c.header;
        h.expected_revision = "1".into();
        h.operation_id = "7".repeat(32);
        let b = row(
            crypto::seal_record(&c.keys, &c.signer, h, b"B").unwrap(),
            2,
            &a.history_hash,
        );
        let mut bad = b.clone();
        bad.history_hash = "9".repeat(64);
        let before = c.replica.clone();
        assert!(c
            .replica
            .prepare_page(&chain, &c.keys, &[a.clone(), bad], &checkpoint(&b))
            .is_err());
        assert_eq!(before, c.replica);
        let mut bad = b.clone();
        bad.envelope.ciphertext.replace_range(0..4, "AAAA");
        assert!(c
            .replica
            .prepare_page(&chain, &c.keys, &[a, bad], &checkpoint(&b))
            .is_err());
        assert!(c
            .replica
            .prepare_page(&chain, &c.keys, &[], &checkpoint(&b))
            .is_err());
    }
    #[test]
    fn a_paired_device_stages_history_until_the_approved_minimum_and_rejects_withholding_or_forks()
    {
        let c = case();
        let chain = c.proof.verify(&c.anchor, None).unwrap();
        let a = row(
            crypto::seal_record(&c.keys, &c.signer, c.header.clone(), b"A").unwrap(),
            1,
            ZERO,
        );
        let mut h = c.header.clone();
        h.expected_revision = "1".into();
        h.operation_id = "8".repeat(32);
        let b = row(
            crypto::seal_record(&c.keys, &c.signer, h, b"B").unwrap(),
            2,
            &a.history_hash,
        );
        let mut replica = Replica::join(
            c.header.vault_id.clone(),
            chain.current().head().into(),
            1,
            checkpoint(&b),
        )
        .unwrap();
        assert!(!replica.baseline_ready());
        assert!(replica.prepare_send(&chain, 1, 1, &[]).is_err());
        assert!(replica
            .prepare_page(&chain, &c.keys, std::slice::from_ref(&a), &checkpoint(&a))
            .is_err());
        let page = replica
            .prepare_page(&chain, &c.keys, std::slice::from_ref(&a), &checkpoint(&b))
            .unwrap();
        assert!(!page.opened[0].publish);
        assert!(!page.publish_baseline);
        assert!(!page.next.baseline_ready());
        let ready = page
            .next
            .prepare_page(&chain, &c.keys, std::slice::from_ref(&b), &checkpoint(&b))
            .unwrap();
        assert!(ready.publish_baseline);
        assert!(ready.next.baseline_ready());
        assert_eq!(ready.next.current.len(), 1);
        let mut wrong = c.header;
        wrong.expected_revision = "1".into();
        wrong.operation_id = "9".repeat(32);
        let fork = row(
            crypto::seal_record(&c.keys, &c.signer, wrong, b"fork").unwrap(),
            2,
            &a.history_hash,
        );
        assert!(page
            .next
            .prepare_page(&chain, &c.keys, &[fork.clone()], &checkpoint(&fork))
            .is_err());
    }
}
