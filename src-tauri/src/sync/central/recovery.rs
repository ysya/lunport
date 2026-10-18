//! Offline recovery is separate from legacy sync codes and SSH private-key export.
use super::{
    crypto::{self, DeviceKeys},
    membership::{Enrollment, TrustAnchor},
    trust::VerifiedChain,
    wire::{canonical, hex, invalid, origin, MAX_SAFE_INTEGER},
};
use crate::error::AppError;
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use bip39::{Language, Mnemonic};
use hkdf::Hkdf;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use zeroize::{Zeroize, Zeroizing};
const PREFIX: &str = "LPREC2:";
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryReadProof {
    pub request_id: String,
    pub membership_head: String,
    pub auth_epoch: String,
    pub signature: String,
}
impl RecoveryReadProof {
    fn create(
        chain: &VerifiedChain,
        request: &Enrollment,
        epoch: u64,
        keys: &DeviceKeys,
        now: u64,
    ) -> Result<Self, AppError> {
        request.verify_live(now)?;
        let anchor = chain.current().anchor();
        if epoch == 0
            || epoch > MAX_SAFE_INTEGER
            || request.origin != anchor.origin
            || request.account_id != anchor.account_id
            || request.genesis_hash != anchor.genesis_hash
            || keys.public() != *chain.current().recovery()
        {
            return Err(invalid());
        }
        let epoch = epoch.to_string();
        let bytes = canonical(&[
            "lunport-recovery-read-v2",
            &anchor.origin,
            &anchor.account_id,
            &anchor.genesis_hash,
            chain.current().head(),
            &epoch,
            &B64.encode(request.canonical()?),
            &request.signature,
        ])?;
        Ok(Self {
            request_id: request.request_id.clone(),
            membership_head: chain.current().head().into(),
            auth_epoch: epoch,
            signature: keys.sign(&bytes),
        })
    }
}
pub struct RecoverySeed(Zeroizing<Vec<u8>>);
pub struct RecoveryKit {
    anchor: TrustAnchor,
    phrase: Zeroizing<String>,
}
fn derive(seed: &[u8], anchor: &TrustAnchor) -> Result<DeviceKeys, AppError> {
    if seed.len() != 32 || !origin(&anchor.origin) || !hex(&anchor.account_id, 64) {
        return Err(invalid());
    }
    // Root cannot enter this salt: genesis itself contains the derived recovery public keys.
    let salt = canonical(&[
        "lunport-recovery-authority-v2",
        &anchor.origin,
        &anchor.account_id,
    ])?;
    let mut independent = Zeroizing::new([0u8; 64]);
    let kdf = Hkdf::<Sha256>::new(Some(&salt), seed);
    kdf.expand(b"ed25519-signing", &mut independent[..32])
        .map_err(|_| invalid())?;
    kdf.expand(b"x25519-encryption", &mut independent[32..])
        .map_err(|_| invalid())?;
    let encoded = Zeroizing::new(B64.encode(&*independent));
    DeviceKeys::decode_secret(&encoded)
}
impl RecoverySeed {
    pub fn generate() -> Result<Self, AppError> {
        let mut seed = Zeroizing::new(vec![0u8; 32]);
        getrandom::fill(&mut seed).map_err(|_| invalid())?;
        Ok(Self(seed))
    }
    pub fn keys(&self, service: &str, account: &str) -> Result<DeviceKeys, AppError> {
        derive(
            &self.0,
            &TrustAnchor {
                origin: service.into(),
                account_id: account.into(),
                genesis_hash: String::new(),
            },
        )
    }
    /// Only bind after a signed proof establishes this as the current recovery authority.
    pub fn bind(self, chain: &VerifiedChain) -> Result<RecoveryKit, AppError> {
        let anchor = chain.current().anchor();
        if derive(&self.0, anchor)?.public() != *chain.current().recovery() {
            return Err(invalid());
        }
        let mnemonic = Mnemonic::from_entropy(&self.0).map_err(|_| invalid())?;
        Ok(RecoveryKit {
            anchor: anchor.clone(),
            phrase: Zeroizing::new(mnemonic.to_string()),
        })
    }
}
impl RecoveryKit {
    pub fn anchor(&self) -> &TrustAnchor {
        &self.anchor
    }
    pub fn encode_secret(&self) -> Result<Zeroizing<String>, AppError> {
        #[derive(Serialize)]
        struct Stored<'a> {
            version: u32,
            anchor: &'a TrustAnchor,
            phrase: &'a str,
        }
        let bytes = Zeroizing::new(
            serde_json::to_vec(&Stored {
                version: 2,
                anchor: &self.anchor,
                phrase: &self.phrase,
            })
            .map_err(|_| invalid())?,
        );
        let encoded = Zeroizing::new(B64.encode(&*bytes));
        Ok(Zeroizing::new(format!("{PREFIX}{}", &*encoded)))
    }
    pub fn parse(encoded: &str) -> Result<Self, AppError> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Stored {
            version: u32,
            anchor: TrustAnchor,
            phrase: String,
        }
        impl Drop for Stored {
            fn drop(&mut self) {
                self.phrase.zeroize();
            }
        }
        if encoded.len() > 4096 {
            return Err(invalid());
        }
        let value = encoded.trim().strip_prefix(PREFIX).ok_or_else(invalid)?;
        let bytes = Zeroizing::new(crypto::decode(value, 1, 3072)?);
        let stored: Stored = serde_json::from_slice(&bytes).map_err(|_| invalid())?;
        if stored.version != 2
            || !origin(&stored.anchor.origin)
            || !hex(&stored.anchor.account_id, 64)
            || !hex(&stored.anchor.genesis_hash, 64)
            || stored.phrase.len() > 256
        {
            return Err(invalid());
        }
        let mnemonic = Mnemonic::parse_in_normalized(Language::English, &stored.phrase)
            .map_err(|_| invalid())?;
        if mnemonic.word_count() != 24 {
            return Err(invalid());
        }
        Ok(Self {
            anchor: stored.anchor.clone(),
            phrase: Zeroizing::new(mnemonic.to_string()),
        })
    }
    /// Only for resuming the same protected, unsubmitted new-kit intent after a local write loss.
    pub(super) fn resume_seed(&self, anchor: &TrustAnchor) -> Result<RecoverySeed, AppError> {
        if &self.anchor != anchor {
            return Err(invalid());
        }
        let mnemonic = Mnemonic::parse_in_normalized(Language::English, &*self.phrase)
            .map_err(|_| invalid())?;
        Ok(RecoverySeed(Zeroizing::new(mnemonic.to_entropy())))
    }
    pub fn read_proof(
        &self,
        chain: &VerifiedChain,
        request: &Enrollment,
        auth_epoch: u64,
        now: u64,
    ) -> Result<RecoveryReadProof, AppError> {
        RecoveryReadProof::create(chain, request, auth_epoch, &self.current_keys(chain)?, now)
    }
    pub fn current_keys(&self, chain: &VerifiedChain) -> Result<DeviceKeys, AppError> {
        self.keys_at(chain, chain.current().head())
    }
    /// Historical use is for opening an accepted recovery wrap, never for authorizing fresh writes.
    pub fn keys_at(&self, chain: &VerifiedChain, head: &str) -> Result<DeviceKeys, AppError> {
        if chain.current().anchor() != &self.anchor {
            return Err(invalid());
        }
        let mnemonic = Mnemonic::parse_in_normalized(Language::English, &*self.phrase)
            .map_err(|_| invalid())?;
        let seed = Zeroizing::new(mnemonic.to_entropy());
        let keys = derive(&seed, &self.anchor)?;
        if chain.recovery_at(head) != Some(&keys.public()) {
            return Err(AppError::Other(
                "This recovery kit is not authorized for that account checkpoint.".into(),
            ));
        }
        Ok(keys)
    }
}
#[cfg(test)]
mod tests {
    use super::super::{
        membership::{Action, Genesis, SignedMembership},
        trust::ControlProof,
    };
    use super::*;
    #[test]
    fn recovery_read_proof_matches_independent_noble_ed25519_vector() {
        let fixture: serde_json::Value =
            serde_json::from_str(include_str!("../../../../fixtures/central-sync-v2.json"))
                .unwrap();
        let anchor: TrustAnchor = serde_json::from_value(fixture["anchor"].clone()).unwrap();
        let request: Enrollment = serde_json::from_value(fixture["enrollment"].clone()).unwrap();
        let chain = ControlProof {
            genesis: serde_json::from_value(fixture["genesis"].clone()).unwrap(),
            nodes: vec![],
        }
        .verify(&anchor, None)
        .unwrap();
        let keys = DeviceKeys::decode_secret(&B64.encode([4u8; 64])).unwrap();
        let proof = RecoveryReadProof::create(&chain, &request, 2, &keys, 1700000001000).unwrap();
        assert_eq!(proof.signature,"Hew0YHcd5iC9IMlFAR7eVr4AupLij37GR36JonaHmWwDIgzg9e6s9n+5GsA1CCK2sAR4IKzFQAgnmJp/lUBCBw==");
    }
    #[test]
    fn recovery_read_proof_is_bound_to_current_authority_request_scope_and_epoch() {
        let first = DeviceKeys::generate().unwrap();
        let seed = RecoverySeed::generate().unwrap();
        let keys = seed.keys("https://relay.test", &"a".repeat(64)).unwrap();
        let (genesis, anchor) = Genesis::create(
            "https://relay.test",
            &"a".repeat(64),
            &"f".repeat(32),
            &first,
            &keys,
        )
        .unwrap();
        let chain = ControlProof {
            genesis,
            nodes: vec![],
        }
        .verify(&anchor, None)
        .unwrap();
        let kit = seed.bind(&chain).unwrap();
        let request = Enrollment::create(
            &anchor,
            &"d".repeat(32),
            &DeviceKeys::generate().unwrap(),
            1000,
        )
        .unwrap();
        let proof = kit.read_proof(&chain, &request, 2, 1100).unwrap();
        let bytes = canonical(&[
            "lunport-recovery-read-v2",
            &anchor.origin,
            &anchor.account_id,
            &anchor.genesis_hash,
            chain.current().head(),
            "2",
            &B64.encode(request.canonical().unwrap()),
            &request.signature,
        ])
        .unwrap();
        crypto::verify(&keys.public().signing, &bytes, &proof.signature).unwrap();
        assert_eq!(proof.request_id, request.request_id);
        assert!(kit.read_proof(&chain, &request, 0, 1100).is_err());
        assert!(kit.read_proof(&chain, &request, 2, 10000000).is_err());
        let altered = canonical(&[
            "lunport-recovery-read-v2",
            &anchor.origin,
            &anchor.account_id,
            &anchor.genesis_hash,
            chain.current().head(),
            "3",
            &B64.encode(request.canonical().unwrap()),
            &request.signature,
        ])
        .unwrap();
        assert!(crypto::verify(&keys.public().signing, &altered, &proof.signature).is_err());
        let json = serde_json::to_string(&proof).unwrap();
        assert!(!json.contains("phrase"));
        assert!(!json.contains(&*kit.phrase));
    }
    #[test]
    fn recovery_authority_matches_independent_webcrypto_hkdf_and_noble_key_vectors() {
        // Synthetic seed 0x09; independently derived with Node WebCrypto HKDF and Noble Ed/X25519.
        let seed = RecoverySeed(Zeroizing::new(vec![9u8; 32]));
        let keys = seed
            .keys("https://relay.test", &"a".repeat(64))
            .unwrap()
            .public();
        assert_eq!(keys.signing, "7QtYAenm7btiflG+BK2sq8E1ks6HvM7z/AA80cV4i/k=");
        assert_eq!(
            keys.encryption,
            "oEk7gfzx3cwHmfB9xRf2WPK0i+pl4bp8d6YzbQhRFRY="
        );
        assert_ne!(
            seed.keys("https://another.test", &"a".repeat(64))
                .unwrap()
                .public(),
            keys
        );
        assert_ne!(
            seed.keys("https://relay.test", &"b".repeat(64))
                .unwrap()
                .public(),
            keys
        );
    }
    #[test]
    fn offline_kit_roundtrips_and_is_bound_to_root_account_and_separate_recovery_keys() {
        let first = DeviceKeys::generate().unwrap();
        let seed = RecoverySeed::generate().unwrap();
        let recovery = seed.keys("https://relay.test", &"a".repeat(64)).unwrap();
        let (genesis, anchor) = Genesis::create(
            "https://relay.test",
            &"a".repeat(64),
            &"f".repeat(32),
            &first,
            &recovery,
        )
        .unwrap();
        let proof = ControlProof {
            genesis,
            nodes: vec![],
        };
        let chain = proof.verify(&anchor, None).unwrap();
        let kit = seed.bind(&chain).unwrap();
        let encoded = kit.encode_secret().unwrap();
        let decoded = RecoveryKit::parse(&encoded).unwrap();
        assert_eq!(decoded.anchor(), &anchor);
        assert_eq!(
            decoded.current_keys(&chain).unwrap().public(),
            recovery.public()
        );
        assert_ne!(recovery.public(), first.public());
        assert!(RecoveryKit::parse(&kit.phrase).is_err());
        assert!(RecoveryKit::parse("legacy sync code").is_err());
        let other = RecoverySeed::generate().unwrap();
        assert!(other.bind(&chain).is_err());
        let wrong = RecoveryKit {
            anchor: TrustAnchor {
                account_id: "b".repeat(64),
                ..anchor
            },
            phrase: Zeroizing::new(decoded.phrase.to_string()),
        };
        assert!(wrong.current_keys(&chain).is_err());
    }
    #[test]
    fn new_kit_opens_a_bridge_even_when_the_new_device_is_lost_before_content_rekey() {
        use super::super::{
            crypto::{seal_record, wrap_keys, VaultKeys},
            wire::{RecordHeader, WrapHeader},
        };
        let first = DeviceKeys::generate().unwrap();
        let seed = RecoverySeed::generate().unwrap();
        let old_recovery = seed.keys("https://relay.test", &"a".repeat(64)).unwrap();
        let (genesis, anchor) = Genesis::create(
            "https://relay.test",
            &"a".repeat(64),
            &"f".repeat(32),
            &first,
            &old_recovery,
        )
        .unwrap();
        let mut proof = ControlProof {
            genesis,
            nodes: vec![],
        };
        let previous = proof.verify(&anchor, None).unwrap();
        let next_seed = RecoverySeed::generate().unwrap();
        let next_recovery = next_seed.keys(&anchor.origin, &anchor.account_id).unwrap();
        let node = SignedMembership::sign(
            previous.current().proposal(
                &"f".repeat(32),
                Action::Recovery,
                None,
                previous.current().devices().clone(),
                next_recovery.public(),
                1000,
            ),
            &first,
        )
        .unwrap();
        proof.nodes.push(node);
        let changed = proof.verify(&anchor, Some(&previous.highwater())).unwrap();
        let new_kit = next_seed.bind(&changed).unwrap();
        let old_keys = VaultKeys::generate().unwrap();
        let header = WrapHeader {
            origin: anchor.origin.clone(),
            account_id: anchor.account_id.clone(),
            genesis_hash: anchor.genesis_hash.clone(),
            vault_id: "c".repeat(64),
            key_epoch: "1".into(),
            membership_head: changed.current().head().into(),
            recipient: "recovery".into(),
            recipient_key: next_recovery.public().encryption,
            author: "f".repeat(32),
        };
        let bridge = wrap_keys(&old_keys, &first, header.clone()).unwrap();
        let opened = bridge
            .open(
                &new_kit.current_keys(&changed).unwrap(),
                &header,
                &first.public().signing,
            )
            .unwrap();
        let record = seal_record(
            &old_keys,
            &first,
            RecordHeader {
                origin: anchor.origin,
                account_id: anchor.account_id,
                genesis_hash: anchor.genesis_hash,
                vault_id: "c".repeat(64),
                record_id: old_keys.record_id("host", "source").unwrap(),
                key_epoch: "1".into(),
                membership_head: previous.current().head().into(),
                author: "f".repeat(32),
                operation_id: "1".repeat(32),
                expected_revision: "0".into(),
                kind: "host".into(),
                deleted: false,
            },
            b"original protected material unchanged",
        )
        .unwrap();
        assert_eq!(
            &*record
                .verify(&first.public().signing)
                .unwrap()
                .open(&opened)
                .unwrap(),
            b"original protected material unchanged"
        );
        assert!(bridge
            .open(&old_recovery, &header, &first.public().signing)
            .is_err());
    }
    #[test]
    fn rotation_stops_old_kit_authority_but_still_opens_only_its_verified_historical_checkpoint() {
        let first = DeviceKeys::generate().unwrap();
        let seed = RecoverySeed::generate().unwrap();
        let recovery = seed.keys("https://relay.test", &"a".repeat(64)).unwrap();
        let (genesis, anchor) = Genesis::create(
            "https://relay.test",
            &"a".repeat(64),
            &"f".repeat(32),
            &first,
            &recovery,
        )
        .unwrap();
        let mut proof = ControlProof {
            genesis,
            nodes: vec![],
        };
        let chain = proof.verify(&anchor, None).unwrap();
        let kit = seed.bind(&chain).unwrap();
        let new_seed = RecoverySeed::generate().unwrap();
        let new_recovery = new_seed.keys(&anchor.origin, &anchor.account_id).unwrap();
        let node = SignedMembership::sign(
            chain.current().proposal(
                &"f".repeat(32),
                Action::Recovery,
                None,
                chain.current().devices().clone(),
                new_recovery.public(),
                1000,
            ),
            &first,
        )
        .unwrap();
        proof.nodes.push(node);
        let changed = proof.verify(&anchor, Some(&chain.highwater())).unwrap();
        assert!(kit.current_keys(&changed).is_err());
        assert_eq!(
            kit.keys_at(&changed, &anchor.genesis_hash)
                .unwrap()
                .public(),
            recovery.public()
        );
        let new_kit = new_seed.bind(&changed).unwrap();
        assert_eq!(
            new_kit.current_keys(&changed).unwrap().public(),
            new_recovery.public()
        );
        assert!(new_kit.keys_at(&changed, &anchor.genesis_hash).is_err());
    }
}
