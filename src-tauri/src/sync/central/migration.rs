//! Signed initial-library migration checkpoint; carries ciphertext commitments only.
use super::{
    crypto::{self, DeviceKeys},
    membership::TrustedMembership,
    wire::{canonical, hex, invalid, number, origin, MAX_SAFE_INTEGER},
};
use crate::error::AppError;
use crate::sync::record::Envelope;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Source {
    pub chain_id: String,
    pub sequence: String,
    pub count: String,
    pub ciphertext_digest: String,
}
impl Source {
    fn canonical(&self) -> Result<Vec<u8>, AppError> {
        let count = number(&self.count, true)?;
        if !hex(&self.chain_id, 64)
            || !hex(&self.ciphertext_digest, 64)
            || count > 4096
            || count > number(&self.sequence, true)?
        {
            return Err(invalid());
        }
        canonical(&[
            "lunport-migration-source-v2",
            &self.chain_id,
            &self.sequence,
            &self.count,
            &self.ciphertext_digest,
        ])
    }
}
/// Hash the complete frozen ciphertext snapshot; unknown legacy record kinds are retained.
/// This is a commitment check, separate from decrypting/admitting every inventory item.
pub fn legacy_checkpoint(
    chain: &str,
    latest_seq: u64,
    records: &[Envelope],
) -> Result<Source, AppError> {
    if !hex(chain, 64) || latest_seq > MAX_SAFE_INTEGER || records.len() > 4096 {
        return Err(invalid());
    }
    let mut sorted: Vec<&Envelope> = records.iter().collect();
    sorted.sort_by(|a, b| a.id_hash.cmp(&b.id_hash));
    let mut previous = "";
    let mut sequences = BTreeSet::new();
    let mut bytes = 0usize;
    for record in &sorted {
        if !hex(&record.id_hash, 64)
            || record.id_hash.as_str() <= previous
            || record.seq == 0
            || record.seq > latest_seq
            || !sequences.insert(record.seq)
            || record.kind.is_empty()
            || record.kind.len() > 16
            || !record.kind.bytes().all(|v| v.is_ascii_lowercase())
            || record.nonce.len() > 64
            || record.ciphertext.len() > 65536
        {
            return Err(invalid());
        }
        previous = &record.id_hash;
        crypto::decode(&record.nonce, 1, 48)?;
        crypto::decode(&record.ciphertext, 1, 49152)?;
        bytes += record.nonce.len() + record.ciphertext.len();
        if bytes > 1048576 {
            return Err(invalid());
        }
    }
    let encoded = serde_json::to_vec(&("lunport-legacy-snapshot-v1", chain, latest_seq, sorted))
        .map_err(|_| invalid())?;
    Ok(Source {
        chain_id: chain.into(),
        sequence: latest_seq.to_string(),
        count: records.len().to_string(),
        ciphertext_digest: crypto::hash(&encoded),
    })
}

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
    /// Commitment to the randomized, encrypted complete native inventory/archive.
    pub inventory_digest: String,
    pub target_sequence: String,
    pub target_history_hash: String,
    pub wraps_digest: String,
    pub sources: Vec<Source>,
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
                &self.inventory_digest,
                &self.target_history_hash,
                &self.wraps_digest,
            ]
            .iter()
            .all(|v| hex(v, 64))
            || !hex(&self.migration_id, 32)
            || !hex(&self.author, 32)
            || self.sources.len() > 65
            || number(&self.target_sequence, false)? > 16384
        {
            return Err(invalid());
        }
        number(&self.authorization_epoch, false)?;
        number(&self.key_epoch, false)?;
        let mut fields: Vec<String> = [
            "lunport-migration-v2",
            &self.origin,
            &self.account_id,
            &self.genesis_hash,
            &self.vault_id,
            &self.migration_id,
            &self.authorization_epoch,
            &self.key_epoch,
            &self.membership_head,
            &self.author,
            &self.inventory_digest,
            &self.target_sequence,
            &self.target_history_hash,
            &self.wraps_digest,
        ]
        .iter()
        .map(|v| v.to_string())
        .collect();
        fields.push(self.sources.len().to_string());
        let mut previous = "";
        for source in &self.sources {
            if source.chain_id.as_str() <= previous {
                return Err(invalid());
            }
            previous = &source.chain_id;
            fields.push(String::from_utf8(source.canonical()?).map_err(|_| invalid())?);
        }
        canonical(&fields.iter().map(String::as_str).collect::<Vec<_>>())
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedMigration {
    pub body: Body,
    pub signature: String,
}
impl SignedMigration {
    pub fn sign(body: Body, keys: &DeviceKeys) -> Result<Self, AppError> {
        let signature = keys.sign(&body.canonical()?);
        Ok(Self { body, signature })
    }
    pub fn digest(&self) -> Result<String, AppError> {
        crypto::decode(&self.signature, 64, 64)?;
        let body = String::from_utf8(self.body.canonical()?).map_err(|_| invalid())?;
        Ok(crypto::hash(&canonical(&[
            "lunport-migration-commit-v2",
            &body,
            &self.signature,
        ])?))
    }
    pub fn verify(
        &self,
        member: &TrustedMembership,
        authorization_epoch: u64,
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
            || number(&b.authorization_epoch, false)? != authorization_epoch
            || number(&b.key_epoch, false)? != key_epoch
        {
            return Err(invalid());
        }
        crypto::verify(&author.signing, &b.canonical()?, &self.signature)
    }
}

#[cfg(test)]
mod tests {
    use super::super::{membership::TrustAnchor, trust::ControlProof};
    use super::*;
    use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
    fn fixture() -> (serde_json::Value, SignedMigration, TrustedMembership) {
        let fixture: serde_json::Value = serde_json::from_str(include_str!(
            "../../../../fixtures/central-migration-v2.json"
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
        let manifest = serde_json::from_value(fixture["manifest"].clone()).unwrap();
        (fixture, manifest, chain.current().clone())
    }
    #[test]
    fn canonical_signature_and_digest_match_worker_fixture() {
        let (fixture, manifest, member) = fixture();
        assert_eq!(
            B64.encode(manifest.body.canonical().unwrap()),
            fixture["manifest_canonical_base64"]
        );
        assert_eq!(manifest.digest().unwrap(), fixture["manifest_digest"]);
        manifest
            .verify(
                &member,
                1,
                1,
                &manifest.body.vault_id,
                &manifest.body.author,
            )
            .unwrap();
        let keys = DeviceKeys::decode_secret(&B64.encode([1u8; 64])).unwrap();
        assert_eq!(
            SignedMigration::sign(manifest.body.clone(), &keys).unwrap(),
            manifest
        );
    }
    #[test]
    fn complete_legacy_snapshot_matches_worker_and_preserves_unknown_kinds() {
        let (fixture, _, _) = fixture();
        let snapshot = &fixture["legacy_snapshot"];
        let rows: Vec<Envelope> = serde_json::from_value(snapshot["records"].clone()).unwrap();
        let chain = snapshot["chain_id"].as_str().unwrap();
        let checkpoint = legacy_checkpoint(chain, 3, &rows).unwrap();
        assert_eq!(checkpoint.ciphertext_digest, snapshot["ciphertext_digest"]);
        let mut reverse = rows.clone();
        reverse.reverse();
        assert_eq!(legacy_checkpoint(chain, 3, &reverse).unwrap(), checkpoint);
        let mut duplicate = rows.clone();
        duplicate.push(rows[0].clone());
        assert!(legacy_checkpoint(chain, 3, &duplicate).is_err());
        let mut wrong = rows.clone();
        wrong[0].seq = 4;
        assert!(legacy_checkpoint(chain, 3, &wrong).is_err());
        let mut wrong = rows.clone();
        wrong[0].seq = rows[1].seq;
        assert!(legacy_checkpoint(chain, 3, &wrong).is_err());
        let mut wrong = rows.clone();
        wrong[0].ciphertext.push('=');
        assert!(legacy_checkpoint(chain, 3, &wrong).is_err());
        assert!(legacy_checkpoint(chain, MAX_SAFE_INTEGER + 1, &rows).is_err());
        let mut removed = rows;
        removed.pop();
        assert_ne!(legacy_checkpoint(chain, 3, &removed).unwrap(), checkpoint);
    }
    #[test]
    fn legacy_snapshot_capacity_and_encoding_are_never_truncated() {
        let (fixture, _, _) = fixture();
        let snapshot = &fixture["legacy_snapshot"];
        let rows: Vec<Envelope> = serde_json::from_value(snapshot["records"].clone()).unwrap();
        let chain = snapshot["chain_id"].as_str().unwrap();
        for field in ["nonce", "ciphertext", "kind"] {
            let mut value = serde_json::to_value(&rows).unwrap();
            value[0][field] = "".into();
            let invalid: Vec<Envelope> = serde_json::from_value(value).unwrap();
            assert!(legacy_checkpoint(chain, 3, &invalid).is_err());
        }
        let mut invalid = rows.clone();
        invalid[0].ciphertext = "Y".repeat(65540);
        assert!(legacy_checkpoint(chain, 3, &invalid).is_err());
        let oversized: Vec<_> = (1..=17)
            .map(|index| Envelope {
                id_hash: format!("{index:064x}"),
                seq: index,
                ciphertext: "Y".repeat(65536),
                ..rows[0].clone()
            })
            .collect();
        assert!(legacy_checkpoint(chain, 17, &oversized).is_err());
        assert!(legacy_checkpoint(chain, 4097, &vec![rows[0].clone(); 4097]).is_err());
    }
    #[test]
    fn every_scope_and_commitment_is_signed() {
        let (_, original, member) = fixture();
        for field in [
            "origin",
            "account_id",
            "genesis_hash",
            "vault_id",
            "migration_id",
            "authorization_epoch",
            "key_epoch",
            "membership_head",
            "author",
            "inventory_digest",
            "target_sequence",
            "target_history_hash",
            "wraps_digest",
        ] {
            let mut value = serde_json::to_value(&original).unwrap();
            let old = value["body"][field].as_str().unwrap();
            value["body"][field] = if field == "origin" {
                "https://other.test".into()
            } else if ["authorization_epoch", "key_epoch", "target_sequence"].contains(&field) {
                "2".into()
            } else {
                (if old.starts_with('9') { "8" } else { "9" })
                    .repeat(old.len())
                    .into()
            };
            let changed: SignedMigration = serde_json::from_value(value).unwrap();
            assert!(
                changed
                    .verify(
                        &member,
                        1,
                        1,
                        &original.body.vault_id,
                        &original.body.author
                    )
                    .is_err(),
                "{field}"
            );
        }
        let mut changed = original.clone();
        changed.body.sources[0].ciphertext_digest = "9".repeat(64);
        assert!(changed
            .verify(
                &member,
                1,
                1,
                &original.body.vault_id,
                &original.body.author
            )
            .is_err());
    }
    #[test]
    fn source_order_duplicates_and_capacity_are_strict() {
        let (_, manifest, _) = fixture();
        let mut body = manifest.body.clone();
        body.sources.swap(0, 1);
        assert!(body.canonical().is_err());
        let mut body = manifest.body.clone();
        body.sources.push(body.sources[1].clone());
        assert!(body.canonical().is_err());
        let mut body = manifest.body.clone();
        body.sources = vec![body.sources[0].clone(); 66];
        assert!(body.canonical().is_err());
        for value in ["0", "01", "-1", "16385", "9007199254740992"] {
            let mut body = manifest.body.clone();
            body.target_sequence = value.into();
            assert!(body.canonical().is_err());
        }
        let mut body = manifest.body.clone();
        body.sources[0].count = "3".into();
        assert!(body.canonical().is_err());
        let mut body = manifest.body.clone();
        body.sources[0].sequence = "9007199254740992".into();
        assert!(body.canonical().is_err());
        let mut body = manifest.body;
        body.sources.clear();
        assert!(body.canonical().is_ok());
    }
    #[test]
    fn unknown_fields_wrong_types_and_noncanonical_signature_are_rejected() {
        let (mut fixture, manifest, _) = fixture();
        fixture["manifest"]["body"]["local_path"] = "/synthetic/path".into();
        assert!(serde_json::from_value::<SignedMigration>(fixture["manifest"].clone()).is_err());
        let mut value = serde_json::to_value(&manifest).unwrap();
        value["body"]["sources"][0]["count"] = 1.into();
        assert!(serde_json::from_value::<SignedMigration>(value).is_err());
        let mut changed = manifest;
        changed.signature.push('=');
        assert!(changed.digest().is_err());
    }
}
