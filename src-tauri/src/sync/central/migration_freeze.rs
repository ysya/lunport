//! Signed monotonic source-freeze metadata. Old bearers/keys never belong in this protocol.
use super::{
    crypto::{self, DeviceKeys},
    membership::TrustedMembership,
    migration::Source,
    trust::VerifiedChain,
    wire::{canonical, hex, invalid, number, origin},
};
use crate::error::AppError;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Body {
    pub origin: String,
    pub account_id: String,
    pub genesis_hash: String,
    pub vault_id: String,
    pub migration_id: String,
    pub authorization_epoch: String,
    pub key_epoch: String,
    pub membership_head: String,
    pub author: String,
    /// Digest of a randomized encrypted preview, never plaintext inventory.
    pub preview_digest: String,
    pub parent_chain: String,
    pub revision: String,
    pub previous_digest: String,
    pub chains: Vec<String>,
}
impl Body {
    pub fn canonical(&self) -> Result<Vec<u8>, AppError> {
        if !origin(&self.origin)
            || !self.origin.starts_with("https://")
            || ![
                &self.account_id,
                &self.genesis_hash,
                &self.vault_id,
                &self.membership_head,
                &self.preview_digest,
            ]
            .iter()
            .all(|v| hex(v, 64))
            || !hex(&self.migration_id, 32)
            || !hex(&self.author, 32)
            || self.chains.len() > 65
        {
            return Err(invalid());
        }
        number(&self.authorization_epoch, false)?;
        number(&self.key_epoch, false)?;
        let revision = number(&self.revision, false)?;
        if revision > 65
            || if revision == 1 {
                !self.previous_digest.is_empty()
            } else {
                !hex(&self.previous_digest, 64)
            }
        {
            return Err(invalid());
        }
        let mut previous = "";
        for chain in &self.chains {
            if !hex(chain, 64) || chain.as_str() <= previous {
                return Err(invalid());
            }
            previous = chain;
        }
        if !self.parent_chain.is_empty()
            && (!hex(&self.parent_chain, 64) || !self.chains.contains(&self.parent_chain))
        {
            return Err(invalid());
        }
        let mut fields: Vec<&str> = vec![
            "lunport-migration-freeze-v2",
            &self.origin,
            &self.account_id,
            &self.genesis_hash,
            &self.vault_id,
            &self.migration_id,
            &self.authorization_epoch,
            &self.key_epoch,
            &self.membership_head,
            &self.author,
            &self.preview_digest,
            &self.parent_chain,
            &self.revision,
            &self.previous_digest,
        ];
        let count = self.chains.len().to_string();
        fields.push(&count);
        fields.extend(self.chains.iter().map(String::as_str));
        canonical(&fields)
    }
    pub fn source_order(&self) -> Vec<&str> {
        let mut result = vec![];
        if !self.parent_chain.is_empty() {
            result.push(self.parent_chain.as_str());
        }
        result.extend(
            self.chains
                .iter()
                .filter(|chain| *chain != &self.parent_chain)
                .map(String::as_str),
        );
        result
    }
    pub fn extends(&self, previous: &Body, previous_digest: &str) -> Result<(), AppError> {
        self.canonical()?;
        previous.canonical()?;
        if self.origin != previous.origin
            || self.account_id != previous.account_id
            || self.genesis_hash != previous.genesis_hash
            || self.vault_id != previous.vault_id
            || self.migration_id != previous.migration_id
            || self.parent_chain != previous.parent_chain
            || self.preview_digest != previous.preview_digest
            || self.previous_digest != previous_digest
            || number(&self.revision, false)? != number(&previous.revision, false)? + 1
            || number(&self.authorization_epoch, false)?
                < number(&previous.authorization_epoch, false)?
            || number(&self.key_epoch, false)? < number(&previous.key_epoch, false)?
            || previous
                .chains
                .iter()
                .any(|chain| !self.chains.contains(chain))
        {
            return Err(invalid());
        }
        Ok(())
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedFreeze {
    pub body: Body,
    pub signature: String,
}
impl SignedFreeze {
    pub fn sign(body: Body, keys: &DeviceKeys) -> Result<Self, AppError> {
        let signature = keys.sign(&body.canonical()?);
        Ok(Self { body, signature })
    }
    pub fn digest(&self) -> Result<String, AppError> {
        crypto::decode(&self.signature, 64, 64)?;
        let body = String::from_utf8(self.body.canonical()?).map_err(|_| invalid())?;
        Ok(crypto::hash(&canonical(&[
            "lunport-migration-freeze-proof-v2",
            &body,
            &self.signature,
        ])?))
    }
    pub fn verify(
        &self,
        member: &TrustedMembership,
        auth_epoch: u64,
        key_epoch: u64,
        vault: &str,
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
            || number(&b.key_epoch, false)? != key_epoch
        {
            return Err(invalid());
        }
        crypto::verify(&author.signing, &b.canonical()?, &self.signature)
    }
    fn verify_historical(
        &self,
        chain: &VerifiedChain,
        operation: &str,
        vault: &str,
    ) -> Result<(), AppError> {
        let b = &self.body;
        let anchor = chain.current().anchor();
        let author = chain
            .author_at(&b.membership_head, &b.author)
            .ok_or_else(invalid)?;
        if b.origin != anchor.origin
            || b.account_id != anchor.account_id
            || b.genesis_hash != anchor.genesis_hash
            || b.vault_id != vault
            || b.migration_id != operation
        {
            return Err(invalid());
        }
        crypto::verify(&author.signing, &b.canonical()?, &self.signature)
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProofStep {
    pub intent: SignedFreeze,
    pub digest: String,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Phase {
    Freezing,
    Frozen,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Progress {
    pub proof: Vec<ProofStep>,
    pub sources: Vec<Source>,
    pub phase: Phase,
    pub next: Vec<String>,
}
/// Persist only after a complete verified response. Frozen source snapshots cannot advance/reset.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Known {
    revision: usize,
    digest: String,
    sources: Vec<Source>,
}
impl Progress {
    pub fn verify(
        &self,
        chain: &VerifiedChain,
        operation: &str,
        vault: &str,
        minimum: Option<&Known>,
    ) -> Result<Known, AppError> {
        if self.proof.is_empty()
            || self.proof.len() > 65
            || self.sources.len() > 65
            || self.next.len() > 8
        {
            return Err(invalid());
        }
        for (index, step) in self.proof.iter().enumerate() {
            step.intent.verify_historical(chain, operation, vault)?;
            if step.intent.digest()? != step.digest
                || number(&step.intent.body.revision, false)? != index as u64 + 1
            {
                return Err(invalid());
            }
            if index > 0 {
                step.intent.body.extends(
                    &self.proof[index - 1].intent.body,
                    &self.proof[index - 1].digest,
                )?;
            }
        }
        let latest = self.proof.last().ok_or_else(invalid)?;
        let mut seen = BTreeSet::new();
        let mut previous = "";
        for source in &self.sources {
            source.canonical()?;
            if source.chain_id.as_str() <= previous
                || !latest.intent.body.chains.contains(&source.chain_id)
                || !seen.insert(source.chain_id.as_str())
            {
                return Err(invalid());
            }
            previous = &source.chain_id;
        }
        let next: Vec<_> = latest
            .intent
            .body
            .source_order()
            .into_iter()
            .filter(|chain| !seen.contains(chain))
            .take(8)
            .collect();
        if self.next.iter().map(String::as_str).collect::<Vec<_>>() != next
            || (self.phase == Phase::Frozen)
                != (self.sources.len() == latest.intent.body.chains.len())
        {
            return Err(invalid());
        }
        if let Some(minimum) = minimum {
            if minimum.revision == 0
                || minimum.revision > self.proof.len()
                || self.proof[minimum.revision - 1].digest != minimum.digest
                || minimum
                    .sources
                    .iter()
                    .any(|source| !self.sources.contains(source))
            {
                return Err(invalid());
            }
        }
        Ok(Known {
            revision: self.proof.len(),
            digest: latest.digest.clone(),
            sources: self.sources.clone(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::super::{membership::TrustAnchor, trust::ControlProof};
    use super::*;
    use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
    fn fixture() -> (serde_json::Value, Progress, Progress, VerifiedChain) {
        let f: serde_json::Value = serde_json::from_str(include_str!(
            "../../../../fixtures/central-source-freeze-v2.json"
        ))
        .unwrap();
        let original: serde_json::Value =
            serde_json::from_str(include_str!("../../../../fixtures/central-sync-v2.json"))
                .unwrap();
        let anchor: TrustAnchor = serde_json::from_value(original["anchor"].clone()).unwrap();
        let proof = ControlProof {
            genesis: serde_json::from_value(original["genesis"].clone()).unwrap(),
            nodes: vec![],
        };
        let chain = proof.verify(&anchor, None).unwrap();
        let first = serde_json::from_value(f["first"].clone()).unwrap();
        let extended = serde_json::from_value(f["extended"].clone()).unwrap();
        (f, first, extended, chain)
    }
    #[test]
    fn worker_canonical_signature_and_monotonic_extension_match() {
        let (fixture, first, extended, chain) = fixture();
        let step = &first.proof[0];
        assert_eq!(
            B64.encode(step.intent.body.canonical().unwrap()),
            fixture["canonical_base64"]
        );
        assert_eq!(step.intent.digest().unwrap(), step.digest);
        let keys = DeviceKeys::decode_secret(&B64.encode([1u8; 64])).unwrap();
        assert_eq!(
            SignedFreeze::sign(step.intent.body.clone(), &keys).unwrap(),
            step.intent
        );
        step.intent
            .verify(chain.current(), 1, 1, &"c".repeat(64), &"f".repeat(32))
            .unwrap();
        let known = first
            .verify(&chain, &"7".repeat(32), &"c".repeat(64), None)
            .unwrap();
        let known = serde_json::from_str::<Known>(&serde_json::to_string(&known).unwrap()).unwrap();
        extended
            .verify(&chain, &"7".repeat(32), &"c".repeat(64), Some(&known))
            .unwrap();
        assert_eq!(step.intent.body.source_order()[0], "3".repeat(64));
    }
    #[test]
    fn replay_missing_sources_changed_snapshots_and_false_completion_never_advance() {
        let (_, first, extended, chain) = fixture();
        let known = extended
            .verify(&chain, &"7".repeat(32), &"c".repeat(64), None)
            .unwrap();
        assert!(first
            .verify(&chain, &"7".repeat(32), &"c".repeat(64), Some(&known))
            .is_err());
        let mut changed = extended.clone();
        changed.sources.clear();
        assert!(changed
            .verify(&chain, &"7".repeat(32), &"c".repeat(64), Some(&known))
            .is_err());
        let mut changed = extended.clone();
        changed.sources[0].ciphertext_digest = "9".repeat(64);
        assert!(changed
            .verify(&chain, &"7".repeat(32), &"c".repeat(64), Some(&known))
            .is_err());
        let mut changed = extended.clone();
        changed.phase = Phase::Frozen;
        assert!(changed
            .verify(&chain, &"7".repeat(32), &"c".repeat(64), None)
            .is_err());
        let mut changed = extended;
        changed.next.reverse();
        assert!(changed
            .verify(&chain, &"7".repeat(32), &"c".repeat(64), None)
            .is_err());
    }
    #[test]
    fn even_resigned_extensions_cannot_drop_sources_or_change_parent_preview_or_operation() {
        let (_, _, extended, chain) = fixture();
        let keys = DeviceKeys::decode_secret(&B64.encode([1u8; 64])).unwrap();
        for field in [
            "chains",
            "parent_chain",
            "preview_digest",
            "migration_id",
            "previous_digest",
            "revision",
        ] {
            let mut changed = extended.clone();
            let mut body = serde_json::to_value(&changed.proof[1].intent.body).unwrap();
            body[field] = if field == "chains" {
                serde_json::json!(["3".repeat(64)])
            } else if field == "revision" {
                "3".into()
            } else if field == "migration_id" {
                "9".repeat(32).into()
            } else {
                "9".repeat(64).into()
            };
            let body: Body = serde_json::from_value(body).unwrap();
            if let Ok(intent) = SignedFreeze::sign(body, &keys) {
                changed.proof[1] = ProofStep {
                    digest: intent.digest().unwrap(),
                    intent,
                };
                assert!(
                    changed
                        .verify(&chain, &"7".repeat(32), &"c".repeat(64), None)
                        .is_err(),
                    "{field}"
                );
            }
        }
    }
    #[test]
    fn signature_scope_unknown_fields_and_capacity_are_strict() {
        let (fixture, first, _, chain) = fixture();
        let step = &first.proof[0];
        assert!(step
            .intent
            .verify(chain.current(), 2, 1, &"c".repeat(64), &"f".repeat(32))
            .is_err());
        assert!(step
            .intent
            .verify(chain.current(), 1, 2, &"c".repeat(64), &"f".repeat(32))
            .is_err());
        assert!(first
            .verify(&chain, &"9".repeat(32), &"c".repeat(64), None)
            .is_err());
        let mut changed = first.clone();
        changed.proof[0].intent.signature = B64.encode([0u8; 64]);
        changed.proof[0].digest = changed.proof[0].intent.digest().unwrap();
        assert!(changed
            .verify(&chain, &"7".repeat(32), &"c".repeat(64), None)
            .is_err());
        let mut value = fixture["first"].clone();
        value["token"] = "synthetic-raw-bearer".into();
        assert!(serde_json::from_value::<Progress>(value).is_err());
        let mut body = step.intent.body.clone();
        body.chains = vec!["1".repeat(64); 66];
        assert!(body.canonical().is_err());
        let mut body = step.intent.body.clone();
        body.chains.reverse();
        assert!(body.canonical().is_err());
        let mut body = step.intent.body.clone();
        body.revision = "66".into();
        body.previous_digest = "9".repeat(64);
        assert!(body.canonical().is_err());
    }
}
