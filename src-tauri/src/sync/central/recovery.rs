//! Offline recovery is separate from legacy sync codes and SSH private-key export.
use super::{
    crypto::{self, DeviceKeys},
    membership::TrustAnchor,
    trust::VerifiedChain,
    wire::{canonical, hex, invalid, origin},
};
use crate::error::AppError;
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use bip39::{Language, Mnemonic};
use hkdf::Hkdf;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use zeroize::{Zeroize, Zeroizing};
const PREFIX: &str = "LPREC2:";
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
