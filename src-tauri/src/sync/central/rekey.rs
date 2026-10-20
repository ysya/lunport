//! Signed content-epoch transitions and a byte-preserving, full-history re-encryption plan.
use super::{
    crypto::{self, DeviceKeys, RecordEnvelope, VaultKeys, WrappedKeys},
    membership::TrustedMembership,
    trust::VerifiedChain,
    wire::{canonical, hex, invalid, number, origin, WrapHeader, MAX_SAFE_INTEGER},
};
use crate::error::AppError;
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
const ZERO: &str = "0000000000000000000000000000000000000000000000000000000000000000";
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RekeyBody {
    pub origin: String,
    pub account_id: String,
    pub genesis_hash: String,
    pub vault_id: String,
    pub rotation_id: String,
    pub authorization_epoch: String,
    pub from_epoch: String,
    pub to_epoch: String,
    pub membership_head: String,
    pub author: String,
    pub source_sequence: String,
    pub source_history_hash: String,
    pub target_history_hash: String,
    pub wraps_digest: String,
}
impl RekeyBody {
    pub fn canonical(&self) -> Result<Vec<u8>, AppError> {
        if !origin(&self.origin)
            || ![
                &self.account_id,
                &self.genesis_hash,
                &self.vault_id,
                &self.membership_head,
                &self.source_history_hash,
                &self.target_history_hash,
                &self.wraps_digest,
            ]
            .iter()
            .all(|v| hex(v, 64))
            || !hex(&self.rotation_id, 32)
            || !hex(&self.author, 32)
        {
            return Err(invalid());
        }
        number(&self.authorization_epoch, false)?;
        let from = number(&self.from_epoch, false)?;
        let to = number(&self.to_epoch, false)?;
        let count = number(&self.source_sequence, true)?;
        if to != from + 1
            || from + 1 > MAX_SAFE_INTEGER
            || count > 16384
            || count == 0 && (self.source_history_hash != ZERO || self.target_history_hash != ZERO)
        {
            return Err(invalid());
        }
        canonical(&[
            "lunport-rekey-v2",
            &self.origin,
            &self.account_id,
            &self.genesis_hash,
            &self.vault_id,
            &self.rotation_id,
            &self.authorization_epoch,
            &self.from_epoch,
            &self.to_epoch,
            &self.membership_head,
            &self.author,
            &self.source_sequence,
            &self.source_history_hash,
            &self.target_history_hash,
            &self.wraps_digest,
        ])
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedRekey {
    pub body: RekeyBody,
    pub signature: String,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Checkpoint {
    pub epoch: u64,
    pub sequence: u64,
    pub history_hash: String,
}
impl SignedRekey {
    pub fn sign(body: RekeyBody, keys: &DeviceKeys) -> Result<Self, AppError> {
        let signature = keys.sign(&body.canonical()?);
        Ok(Self { body, signature })
    }
    pub fn verify(
        &self,
        member: &TrustedMembership,
        auth_epoch: u64,
        vault: &str,
        source: &Checkpoint,
        actor: &str,
    ) -> Result<(), AppError> {
        let b = &self.body;
        let author = member.devices().get(actor).ok_or_else(invalid)?;
        if b.origin != member.anchor().origin
            || b.account_id != member.anchor().account_id
            || b.genesis_hash != member.anchor().genesis_hash
            || b.vault_id != vault
            || b.author != actor
            || b.membership_head != member.head()
            || number(&b.authorization_epoch, false)? != auth_epoch
            || number(&b.from_epoch, false)? != source.epoch
            || number(&b.source_sequence, true)? != source.sequence
            || b.source_history_hash != source.history_hash
        {
            return Err(invalid());
        }
        crypto::verify(&author.signing, &b.canonical()?, &self.signature)
    }
}
/// The local anchor/chain, rather than a server readiness flag, authenticates an epoch transition.
impl SignedRekey {
    pub fn verify_historical(&self, chain: &VerifiedChain, vault: &str) -> Result<(), AppError> {
        let b = &self.body;
        let anchor = chain.current().anchor();
        let author = chain
            .author_at(&b.membership_head, &b.author)
            .ok_or_else(invalid)?;
        if b.origin != anchor.origin
            || b.account_id != anchor.account_id
            || b.genesis_hash != anchor.genesis_hash
            || b.vault_id != vault
        {
            return Err(invalid());
        }
        crypto::verify(&author.signing, &b.canonical()?, &self.signature)
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceDigest {
    pub sequence: String,
    pub digest: String,
}
/// Streaming suffix proof: bounded pages cannot replace or skip the device's already known prefix.
pub struct SourceExtension<'a> {
    manifest: &'a SignedRekey,
    sequence: u64,
    hash: String,
}
impl<'a> SourceExtension<'a> {
    pub fn new(
        manifest: &'a SignedRekey,
        chain: &VerifiedChain,
        vault: &str,
        known: &Checkpoint,
    ) -> Result<Self, AppError> {
        manifest.verify_historical(chain, vault)?;
        if known.epoch != number(&manifest.body.from_epoch, false)?
            || known.sequence > number(&manifest.body.source_sequence, true)?
            || !hex(&known.history_hash, 64)
            || known.sequence == 0 && known.history_hash != ZERO
        {
            return Err(invalid());
        }
        Ok(Self {
            manifest,
            sequence: known.sequence,
            hash: known.history_hash.clone(),
        })
    }
    pub fn append(&mut self, page: &[SourceDigest]) -> Result<(), AppError> {
        if page.is_empty() || page.len() > 256 {
            return Err(invalid());
        }
        // Validate a whole page before publishing its progress to a resumable caller.
        let mut sequence = self.sequence;
        let mut hash = self.hash.clone();
        for row in page {
            sequence += 1;
            if number(&row.sequence, false)? != sequence
                || !hex(&row.digest, 64)
                || sequence > number(&self.manifest.body.source_sequence, true)?
            {
                return Err(invalid());
            }
            hash = advance(&hash, sequence, &row.digest)?;
        }
        self.sequence = sequence;
        self.hash = hash;
        Ok(())
    }
    pub fn position(&self) -> Result<Checkpoint, AppError> {
        Ok(Checkpoint {
            epoch: number(&self.manifest.body.from_epoch, false)?,
            sequence: self.sequence,
            history_hash: self.hash.clone(),
        })
    }
    pub fn finish(self) -> Result<Checkpoint, AppError> {
        if self.sequence != number(&self.manifest.body.source_sequence, true)?
            || self.hash != self.manifest.body.source_history_hash
        {
            return Err(invalid());
        }
        Ok(Checkpoint {
            epoch: number(&self.manifest.body.to_epoch, false)?,
            sequence: self.sequence,
            history_hash: self.manifest.body.target_history_hash.clone(),
        })
    }
}
/// creation_head is the locally pinned, authenticated creation checkpoint, never a server hint.
/// Full transition history is retained; a missing rotation or a later known revoke keeps writes frozen.
pub fn require_write_epoch(
    chain: &VerifiedChain,
    vault: &str,
    epoch: u64,
    minimum: u64,
    creation_head: &str,
    commits: &[SignedRekey],
) -> Result<(), AppError> {
    if epoch == 0
        || epoch > MAX_SAFE_INTEGER
        || minimum == 0
        || epoch < minimum
        || commits.len() > 64
        || commits.len() as u64 != epoch - 1
    {
        return Err(invalid());
    }
    let mut revision = chain.revision_of(creation_head).ok_or_else(invalid)?;
    let mut auth = 0;
    let mut sequence = 0;
    let mut rotations = BTreeSet::new();
    for (index, commit) in commits.iter().enumerate() {
        commit.verify_historical(chain, vault)?;
        let b = &commit.body;
        let next_revision = chain.revision_of(&b.membership_head).ok_or_else(invalid)?;
        let next_auth = number(&b.authorization_epoch, false)?;
        let next_sequence = number(&b.source_sequence, true)?;
        if number(&b.from_epoch, false)? != index as u64 + 1
            || next_revision < revision
            || next_auth <= auth
            || next_sequence < sequence
            || !rotations.insert(&b.rotation_id)
        {
            return Err(invalid());
        }
        revision = next_revision;
        auth = next_auth;
        sequence = next_sequence;
    }
    if revision < chain.security_revision() {
        return Err(AppError::Other(
        "Content keys have not been rotated past the latest known device revocation. Local changes are retained.".into()));
    }
    Ok(())
}
pub fn wraps_digest(wraps: &[WrappedKeys]) -> Result<String, AppError> {
    if wraps.is_empty() || wraps.len() > 65 {
        return Err(invalid());
    }
    let mut sorted: Vec<_> = wraps.iter().collect();
    sorted.sort_by(|a, b| a.header.recipient.cmp(&b.header.recipient));
    let mut entries = Vec::new();
    let mut prior = None;
    for wrap in sorted {
        if prior.as_ref() == Some(&wrap.header.recipient) {
            return Err(invalid());
        }
        prior = Some(wrap.header.recipient.clone());
        crypto::decode(&wrap.encapsulated_key, 32, 32)?;
        crypto::decode(&wrap.ciphertext, 80, 80)?;
        crypto::decode(&wrap.signature, 64, 64)?;
        entries.push(vec![
            B64.encode(wrap.header.canonical()?),
            wrap.encapsulated_key.clone(),
            wrap.ciphertext.clone(),
            wrap.signature.clone(),
        ]);
    }
    Ok(crypto::hash(
        &serde_json::to_vec(&("lunport-rekey-wraps-v2", entries)).map_err(|_| invalid())?,
    ))
}
/// A valid individual wrap could belong to a cancelled attempt at the same head/epoch.
/// Authenticate the complete committed recipient set before adopting its content key.
pub fn verify_committed_wraps(
    chain: &VerifiedChain,
    manifest: &SignedRekey,
    wraps: &[WrappedKeys],
) -> Result<(), AppError> {
    manifest.verify_historical(chain, &manifest.body.vault_id)?;
    let b = &manifest.body;
    if wraps_digest(wraps)? != b.wraps_digest {
        return Err(invalid());
    }
    let mut expected = chain
        .devices_at(&b.membership_head)
        .ok_or_else(invalid)?
        .clone();
    expected.insert(
        "recovery".into(),
        chain
            .recovery_at(&b.membership_head)
            .ok_or_else(invalid)?
            .clone(),
    );
    if wraps.len() != expected.len() {
        return Err(invalid());
    }
    let author = chain
        .author_at(&b.membership_head, &b.author)
        .ok_or_else(invalid)?;
    for wrap in wraps {
        let h = &wrap.header;
        let public = expected.remove(&h.recipient).ok_or_else(invalid)?;
        if h.origin != b.origin
            || h.account_id != b.account_id
            || h.genesis_hash != b.genesis_hash
            || h.vault_id != b.vault_id
            || h.key_epoch != b.to_epoch
            || h.membership_head != b.membership_head
            || h.author != b.author
            || h.recipient_key != public.encryption
        {
            return Err(invalid());
        }
        wrap.verify_author(&author.signing)?;
    }
    Ok(())
}
pub fn open_committed_keys(
    chain: &VerifiedChain,
    manifest: &SignedRekey,
    wraps: &[WrappedKeys],
    recipient: &str,
    keys: &DeviceKeys,
) -> Result<VaultKeys, AppError> {
    verify_committed_wraps(chain, manifest, wraps)?;
    let own = wraps
        .iter()
        .find(|w| w.header.recipient == recipient)
        .ok_or_else(invalid)?;
    let author = chain
        .author_at(&manifest.body.membership_head, &manifest.body.author)
        .ok_or_else(invalid)?;
    own.open(keys, &own.header, &author.signing)
}

pub fn envelope_digest(envelope: &RecordEnvelope) -> Result<String, AppError> {
    Ok(crypto::hash(&canonical(&[
        "lunport-operation-v2",
        std::str::from_utf8(&envelope.header.canonical()?).map_err(|_| invalid())?,
        &envelope.nonce,
        &envelope.ciphertext,
        &envelope.signature,
    ])?))
}
fn advance(previous: &str, sequence: u64, digest: &str) -> Result<String, AppError> {
    Ok(crypto::hash(&canonical(&[
        "lunport-history-v2",
        previous,
        &sequence.to_string(),
        digest,
    ])?))
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Version {
    pub revision: String,
    pub sequence: String,
    pub envelope: RecordEnvelope,
    pub digest: String,
    pub history_hash: String,
}
/// No Serialize/Debug: the derived content keys remain memory-only; the journal persists wraps/rows.
pub struct Plan {
    pub keys: VaultKeys,
    pub rows: Vec<Version>,
    pub wraps: Vec<WrappedKeys>,
    pub manifest: SignedRekey,
}
pub fn prepare(
    chain: &VerifiedChain,
    device: &str,
    signer: &DeviceKeys,
    vault: &str,
    auth_epoch: u64,
    old_keys: &VaultKeys,
    source: &Checkpoint,
    known_prefix: &Checkpoint,
    rows: &[Version],
) -> Result<Plan, AppError> {
    let current = chain.current();
    let anchor = current.anchor();
    if !hex(vault, 64)
        || current.devices().get(device) != Some(&signer.public())
        || source.epoch == 0
        || source.epoch >= MAX_SAFE_INTEGER
        || source.sequence > 16384
        || rows.len() as u64 != source.sequence
        || known_prefix.epoch != source.epoch
        || known_prefix.sequence > source.sequence
        || !hex(&source.history_hash, 64)
        || !hex(&known_prefix.history_hash, 64)
        || known_prefix.sequence == 0 && known_prefix.history_hash != ZERO
    {
        return Err(invalid());
    }
    let keys = old_keys.next_epoch()?;
    let mut versions: BTreeMap<String, (u64, String)> = BTreeMap::new();
    let mut operations = BTreeSet::new();
    let mut source_bytes = 0usize;
    let mut source_hash = ZERO.to_string();
    let mut target_hash = ZERO.to_string();
    let mut target = Vec::with_capacity(rows.len());
    let mut bytes = 0usize;
    for (index, row) in rows.iter().enumerate() {
        let seq = (index + 1) as u64;
        let env = &row.envelope;
        let h = &env.header;
        let author = chain
            .author_at(&h.membership_head, &h.author)
            .ok_or_else(invalid)?;
        source_bytes += serde_json::to_vec(env).map_err(|_| invalid())?.len();
        if source_bytes > 32 * 1024 * 1024 || !operations.insert(h.operation_id.clone()) {
            return Err(invalid());
        }
        let previous = versions.get(&h.record_id);
        let revision = previous.map_or(0, |(rev, _)| *rev) + 1;
        if number(&row.sequence, false)? != seq
            || number(&row.revision, false)? != revision
            || number(&h.expected_revision, true)? != revision - 1
            || previous.is_some_and(|(_, kind)| kind != &h.kind)
            || h.origin != anchor.origin
            || h.account_id != anchor.account_id
            || h.genesis_hash != anchor.genesis_hash
            || h.vault_id != vault
            || number(&h.key_epoch, false)? != source.epoch
            || row.digest != envelope_digest(env)?
        {
            return Err(invalid());
        }
        source_hash = advance(&source_hash, seq, &row.digest)?;
        if row.history_hash != source_hash
            || known_prefix.sequence == seq && known_prefix.history_hash != source_hash
        {
            return Err(AppError::Other(
                "The retained history was changed or rolled back. Original data has been retained."
                    .into(),
            ));
        }
        let plaintext = env.verify(&author.signing)?.open(old_keys)?;
        let mut header = h.clone();
        header.key_epoch = (source.epoch + 1).to_string();
        header.membership_head = current.head().into();
        header.author = device.into();
        let envelope = crypto::seal_record(&keys, signer, header, &plaintext)?;
        let digest = envelope_digest(&envelope)?;
        target_hash = advance(&target_hash, seq, &digest)?;
        let next = Version {
            revision: row.revision.clone(),
            sequence: row.sequence.clone(),
            envelope,
            digest,
            history_hash: target_hash.clone(),
        };
        bytes += serde_json::to_vec(&next.envelope)
            .map_err(|_| invalid())?
            .len();
        if bytes > 32 * 1024 * 1024 {
            return Err(invalid());
        }
        target.push(next);
        versions.insert(h.record_id.clone(), (revision, h.kind.clone()));
        if versions.len() > 4096 {
            return Err(invalid());
        }
    }
    if source_hash != source.history_hash {
        return Err(invalid());
    }
    let mut wraps = Vec::new();
    let mut recipients = current.devices().clone();
    recipients.insert("recovery".into(), current.recovery().clone());
    for (recipient, key) in recipients {
        wraps.push(crypto::wrap_keys(
            &keys,
            signer,
            WrapHeader {
                origin: anchor.origin.clone(),
                account_id: anchor.account_id.clone(),
                genesis_hash: anchor.genesis_hash.clone(),
                vault_id: vault.into(),
                key_epoch: (source.epoch + 1).to_string(),
                membership_head: current.head().into(),
                recipient,
                recipient_key: key.encryption,
                author: device.into(),
            },
        )?);
    }
    let body = RekeyBody {
        origin: anchor.origin.clone(),
        account_id: anchor.account_id.clone(),
        genesis_hash: anchor.genesis_hash.clone(),
        vault_id: vault.into(),
        rotation_id: crypto::random_id(16)?,
        authorization_epoch: auth_epoch.to_string(),
        from_epoch: source.epoch.to_string(),
        to_epoch: (source.epoch + 1).to_string(),
        membership_head: current.head().into(),
        author: device.into(),
        source_sequence: source.sequence.to_string(),
        source_history_hash: source_hash,
        target_history_hash: target_hash,
        wraps_digest: wraps_digest(&wraps)?,
    };
    let manifest = SignedRekey::sign(body, signer)?;
    manifest.verify(current, auth_epoch, vault, source, device)?;
    Ok(Plan {
        keys,
        rows: target,
        wraps,
        manifest,
    })
}
#[cfg(test)]
mod tests {
    use super::super::{membership::TrustAnchor, trust::ControlProof};
    use super::*;
    struct Case {
        proof: ControlProof,
        anchor: TrustAnchor,
        signer: DeviceKeys,
        old: VaultKeys,
        source: Checkpoint,
        known: Checkpoint,
        rows: Vec<Version>,
        old_wraps: Vec<WrappedKeys>,
        plan: Plan,
    }
    fn case() -> Case {
        let fixture: serde_json::Value =
            serde_json::from_str(include_str!("../../../../fixtures/central-sync-v2.json"))
                .unwrap();
        let anchor: TrustAnchor = serde_json::from_value(fixture["anchor"].clone()).unwrap();
        let proof = ControlProof {
            genesis: serde_json::from_value(fixture["genesis"].clone()).unwrap(),
            nodes: serde_json::from_value(fixture["membership_nodes"].clone()).unwrap(),
        };
        let chain = proof.verify(&anchor, None).unwrap();
        let signer = DeviceKeys::decode_secret(&B64.encode([1u8; 64])).unwrap();
        let second = DeviceKeys::decode_secret(&B64.encode([2u8; 64])).unwrap();
        let old = VaultKeys::from_bytes(&[3u8; 64]).unwrap();
        let envelope: RecordEnvelope = serde_json::from_value(fixture["record"].clone()).unwrap();
        let vault = envelope.header.vault_id.clone();
        let digest = envelope_digest(&envelope).unwrap();
        let hash = advance(ZERO, 1, &digest).unwrap();
        let known = Checkpoint {
            epoch: 1,
            sequence: 1,
            history_hash: hash.clone(),
        };
        let first = Version {
            revision: "1".into(),
            sequence: "1".into(),
            envelope: envelope.clone(),
            digest,
            history_hash: hash.clone(),
        };
        let mut header = envelope.header;
        header.author = "d".repeat(32);
        header.expected_revision = "1".into();
        header.operation_id = "2".repeat(32);
        let envelope =
            crypto::seal_record(&old, &second, header, b"second retained revision").unwrap();
        let digest = envelope_digest(&envelope).unwrap();
        let hash = advance(&hash, 2, &digest).unwrap();
        let second = Version {
            revision: "2".into(),
            sequence: "2".into(),
            envelope,
            digest,
            history_hash: hash.clone(),
        };
        let source = Checkpoint {
            epoch: 1,
            sequence: 2,
            history_hash: hash,
        };
        let rows = vec![first, second];
        let plan = prepare(
            &chain,
            &"f".repeat(32),
            &signer,
            &vault,
            4,
            &old,
            &source,
            &known,
            &rows,
        )
        .unwrap();
        let mut recipients = chain.current().devices().clone();
        recipients.insert("recovery".into(), chain.current().recovery().clone());
        let old_wraps = recipients
            .into_iter()
            .map(|(recipient, key)| {
                crypto::wrap_keys(
                    &old,
                    &signer,
                    WrapHeader {
                        origin: anchor.origin.clone(),
                        account_id: anchor.account_id.clone(),
                        genesis_hash: anchor.genesis_hash.clone(),
                        vault_id: vault.clone(),
                        key_epoch: "1".into(),
                        membership_head: chain.current().head().into(),
                        recipient,
                        recipient_key: key.encryption,
                        author: "f".repeat(32),
                    },
                )
                .unwrap()
            })
            .collect();
        Case {
            proof,
            anchor,
            signer,
            old,
            source,
            known,
            rows,
            old_wraps,
            plan,
        }
    }
    #[test]
    fn rekey_preserves_all_history_including_a_revoked_authors_revision_and_rejects_rollback() {
        let c = case();
        let chain = c.proof.verify(&c.anchor, None).unwrap();
        assert!(chain.current().devices().get(&"d".repeat(32)).is_none());
        for (old, new) in c.rows.iter().zip(&c.plan.rows) {
            assert_eq!(old.revision, new.revision);
            assert_eq!(old.sequence, new.sequence);
            assert_eq!(
                old.envelope.header.operation_id,
                new.envelope.header.operation_id
            );
            assert_eq!(old.envelope.header.record_id, new.envelope.header.record_id);
            assert_ne!(old.envelope.ciphertext, new.envelope.ciphertext);
            let author = chain
                .author_at(
                    &old.envelope.header.membership_head,
                    &old.envelope.header.author,
                )
                .unwrap();
            let source = old
                .envelope
                .verify(&author.signing)
                .unwrap()
                .open(&c.old)
                .unwrap();
            let target = new
                .envelope
                .verify(&c.signer.public().signing)
                .unwrap()
                .open(&c.plan.keys)
                .unwrap();
            assert_eq!(&*source, &*target);
            assert!(new
                .envelope
                .verify(&c.signer.public().signing)
                .unwrap()
                .open(&c.old)
                .is_err());
        }
        assert_eq!(c.plan.wraps.len(), 2);
        let opened = open_committed_keys(
            &chain,
            &c.plan.manifest,
            &c.plan.wraps,
            &"f".repeat(32),
            &c.signer,
        )
        .unwrap();
        let public = &c.signer.public().signing;
        assert_eq!(
            &*c.plan.rows[0]
                .envelope
                .verify(public)
                .unwrap()
                .open(&opened)
                .unwrap(),
            &*c.plan.rows[0]
                .envelope
                .verify(public)
                .unwrap()
                .open(&c.plan.keys)
                .unwrap()
        );
        let mut substituted = c.plan.wraps.clone();
        substituted[0] = c.old_wraps[0].clone();
        assert!(open_committed_keys(
            &chain,
            &c.plan.manifest,
            &substituted,
            &"f".repeat(32),
            &c.signer
        )
        .is_err());
        assert!(open_committed_keys(
            &chain,
            &c.plan.manifest,
            &c.plan.wraps[..1],
            &"f".repeat(32),
            &c.signer
        )
        .is_err());

        assert_eq!(
            c.plan.manifest.body.wraps_digest,
            wraps_digest(&c.plan.wraps).unwrap()
        );
        let rollback = Checkpoint {
            history_hash: "9".repeat(64),
            ..c.known.clone()
        };
        let vault = &c.rows[0].envelope.header.vault_id;
        assert!(prepare(
            &chain,
            &"f".repeat(32),
            &c.signer,
            vault,
            4,
            &c.old,
            &c.source,
            &rollback,
            &c.rows
        )
        .is_err());
        let mut altered = c.rows.clone();
        altered[1].revision = "3".into();
        assert!(prepare(
            &chain,
            &"f".repeat(32),
            &c.signer,
            vault,
            4,
            &c.old,
            &c.source,
            &c.known,
            &altered
        )
        .is_err());
    }
    #[test]
    fn offline_prefix_proofs_reject_forks_skips_truncation_and_false_server_readiness() {
        let c = case();
        let chain = c.proof.verify(&c.anchor, None).unwrap();
        let vault = &c.plan.manifest.body.vault_id;
        let rows = vec![SourceDigest {
            sequence: "2".into(),
            digest: c.rows[1].digest.clone(),
        }];
        let mut proof = SourceExtension::new(&c.plan.manifest, &chain, vault, &c.known).unwrap();
        proof.append(&rows).unwrap();
        let target = proof.finish().unwrap();
        assert_eq!(target.epoch, 2);
        assert_eq!(
            target.history_hash,
            c.plan.manifest.body.target_history_hash
        );
        assert!(
            SourceExtension::new(&c.plan.manifest, &chain, vault, &c.known)
                .unwrap()
                .finish()
                .is_err()
        );
        let fork = Checkpoint {
            history_hash: "9".repeat(64),
            ..c.known.clone()
        };
        let mut proof = SourceExtension::new(&c.plan.manifest, &chain, vault, &fork).unwrap();
        proof.append(&rows).unwrap();
        assert!(proof.finish().is_err());
        let mut proof = SourceExtension::new(&c.plan.manifest, &chain, vault, &c.known).unwrap();
        assert!(proof
            .append(&[SourceDigest {
                sequence: "3".into(),
                digest: rows[0].digest.clone()
            }])
            .is_err());
        proof.append(&rows).unwrap();
        assert!(proof.finish().is_ok());
        let created = chain.head_at(0).unwrap();
        assert!(require_write_epoch(&chain, vault, 1, 1, created, &[]).is_err());
        assert!(require_write_epoch(
            &chain,
            vault,
            2,
            1,
            created,
            std::slice::from_ref(&c.plan.manifest)
        )
        .is_ok());
        assert!(require_write_epoch(
            &chain,
            vault,
            3,
            1,
            created,
            std::slice::from_ref(&c.plan.manifest)
        )
        .is_err());
        assert!(require_write_epoch(
            &chain,
            vault,
            2,
            3,
            created,
            std::slice::from_ref(&c.plan.manifest)
        )
        .is_err());
        let mut early = c.plan.manifest.body.clone();
        early.membership_head = created.into();
        let early = SignedRekey::sign(early, &c.signer).unwrap();
        assert!(require_write_epoch(&chain, vault, 2, 1, created, &[early]).is_err());
    }
    #[test]
    #[ignore = "explicit synthetic rekey fixture generation only"]
    fn emit_rekey_fixture() {
        let c = case();
        let fixture = serde_json::json!({"fixture":"SYNTHETIC REKEY DATA ONLY","anchor":c.anchor,"proof":c.proof,"source":c.source,"known_prefix":c.known,"source_rows":c.rows,"source_wraps":c.old_wraps,"target_rows":c.plan.rows,"target_wraps":c.plan.wraps,"manifest":c.plan.manifest,"manifest_canonical_base64":B64.encode(c.plan.manifest.body.canonical().unwrap())});
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../fixtures/central-rekey-v2.json");
        std::fs::write(path, serde_json::to_vec_pretty(&fixture).unwrap()).unwrap();
    }
}
