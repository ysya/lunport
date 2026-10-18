use super::wire::{canonical, invalid, RecordHeader, WrapHeader, MAX_PLAINTEXT_BYTES};
use crate::error::AppError;
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    XChaCha20Poly1305, XNonce,
};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use hmac::{Hmac, Mac};
use hpke::{
    aead::ChaCha20Poly1305, kdf::HkdfSha256, kem::X25519HkdfSha256, Deserializable,
    Kem as KemTrait, OpModeR, OpModeS, Serializable,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;
type Kem = X25519HkdfSha256;

pub fn hash(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
pub(crate) fn decode(text: &str, minimum: usize, maximum: usize) -> Result<Vec<u8>, AppError> {
    if text.len() > maximum.div_ceil(3) * 4 {
        return Err(invalid());
    }
    let bytes = B64.decode(text).map_err(|_| invalid())?;
    if bytes.len() < minimum || bytes.len() > maximum || B64.encode(&bytes) != text {
        return Err(invalid());
    }
    Ok(bytes)
}
pub fn random_id(bytes: usize) -> Result<String, AppError> {
    if !matches!(bytes, 16 | 32) {
        return Err(invalid());
    }
    let mut value = vec![0; bytes];
    getrandom::fill(&mut value).map_err(|_| invalid())?;
    Ok(value.iter().map(|b| format!("{b:02x}")).collect())
}
/// Independent keys; never SSH keys. Only the encoded secret goes to OS secure storage.
pub struct DeviceKeys {
    signing: SigningKey,
    encryption: <Kem as KemTrait>::PrivateKey,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublicKeys {
    pub signing: String,
    pub encryption: String,
}
impl PublicKeys {
    pub fn validate(&self) -> Result<(), AppError> {
        verifying_key(&self.signing)?;
        let key = decode(&self.encryption, 32, 32)?;
        if key.iter().all(|b| *b == 0) {
            return Err(invalid());
        }
        <Kem as KemTrait>::PublicKey::from_bytes(&key).map_err(|_| invalid())?;
        Ok(())
    }
}
impl DeviceKeys {
    pub fn generate() -> Result<Self, AppError> {
        let mut entropy = Zeroizing::new([0u8; 64]);
        getrandom::fill(&mut *entropy).map_err(|_| invalid())?;
        let signing = SigningKey::from_bytes(entropy[..32].try_into().map_err(|_| invalid())?);
        let (encryption, _) = Kem::derive_keypair(&entropy[32..]);
        Ok(Self {
            signing,
            encryption,
        })
    }
    pub fn public(&self) -> PublicKeys {
        PublicKeys {
            signing: B64.encode(self.signing.verifying_key().to_bytes()),
            encryption: B64.encode(Kem::sk_to_pk(&self.encryption).to_bytes()),
        }
    }
    pub fn encode_secret(&self) -> Zeroizing<String> {
        let mut bytes = Zeroizing::new([0u8; 64]);
        bytes[..32].copy_from_slice(self.signing.as_bytes());
        self.encryption.write_exact(&mut bytes[32..]);
        Zeroizing::new(B64.encode(&*bytes))
    }
    pub fn decode_secret(encoded: &str) -> Result<Self, AppError> {
        let bytes = Zeroizing::new(decode(encoded, 64, 64)?);
        Ok(Self {
            signing: SigningKey::from_bytes(bytes[..32].try_into().map_err(|_| invalid())?),
            encryption: <Kem as KemTrait>::PrivateKey::from_bytes(&bytes[32..])
                .map_err(|_| invalid())?,
        })
    }
    pub fn sign(&self, bytes: &[u8]) -> String {
        B64.encode(self.signing.sign(bytes).to_bytes())
    }
}
fn verifying_key(encoded: &str) -> Result<VerifyingKey, AppError> {
    let bytes = decode(encoded, 32, 32)?;
    let key = VerifyingKey::from_bytes(bytes.as_slice().try_into().map_err(|_| invalid())?)
        .map_err(|_| invalid())?;
    if key.is_weak() {
        return Err(invalid());
    }
    Ok(key)
}
pub fn verify(trusted_public_key: &str, bytes: &[u8], signature: &str) -> Result<(), AppError> {
    let bytes_sig = decode(signature, 64, 64)?;
    let signature = Signature::from_slice(&bytes_sig).map_err(|_| invalid())?;
    verifying_key(trusted_public_key)?
        .verify_strict(bytes, &signature)
        .map_err(|_| invalid())
}
/// Index and content keys are independent, random, and not derived from an earlier epoch.
pub struct VaultKeys(Zeroizing<[u8; 64]>);
impl VaultKeys {
    pub fn generate() -> Result<Self, AppError> {
        let mut bytes = Zeroizing::new([0u8; 64]);
        getrandom::fill(&mut *bytes).map_err(|_| invalid())?;
        Ok(Self(bytes))
    }
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, AppError> {
        if bytes.len() != 64 {
            return Err(invalid());
        }
        let mut key = Zeroizing::new([0; 64]);
        key.copy_from_slice(bytes);
        Ok(Self(key))
    }
    pub fn record_id(&self, kind: &str, id: &str) -> Result<String, AppError> {
        let mut mac =
            <Hmac<Sha256> as Mac>::new_from_slice(&self.0[..32]).map_err(|_| invalid())?;
        mac.update(&canonical(&["lunport-record-index-v2", kind, id])?);
        Ok(mac
            .finalize()
            .into_bytes()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect())
    }
    pub fn next_epoch(&self) -> Result<Self, AppError> {
        let mut next = Self::generate()?;
        next.0[..32].copy_from_slice(&self.0[..32]);
        Ok(next)
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecordEnvelope {
    pub header: RecordHeader,
    pub nonce: String,
    pub ciphertext: String,
    pub signature: String,
}
fn author_bytes(
    domain: &str,
    header: &[u8],
    nonce: &str,
    ciphertext: &[u8],
) -> Result<Vec<u8>, AppError> {
    canonical(&[domain, &B64.encode(header), nonce, &hash(ciphertext)])
}
pub fn seal_record(
    keys: &VaultKeys,
    author: &DeviceKeys,
    header: RecordHeader,
    plaintext: &[u8],
) -> Result<RecordEnvelope, AppError> {
    if plaintext.len() > MAX_PLAINTEXT_BYTES {
        return Err(invalid());
    }
    let aad = header.canonical()?;
    let mut nonce = [0; 24];
    getrandom::fill(&mut nonce).map_err(|_| invalid())?;
    let ciphertext = XChaCha20Poly1305::new_from_slice(&keys.0[32..])
        .map_err(|_| invalid())?
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: plaintext,
                aad: &aad,
            },
        )
        .map_err(|_| invalid())?;
    let nonce = B64.encode(nonce);
    let signature = author.sign(&author_bytes(
        "lunport-record-author-v2",
        &aad,
        &nonce,
        &ciphertext,
    )?);
    Ok(RecordEnvelope {
        header,
        nonce,
        ciphertext: B64.encode(ciphertext),
        signature,
    })
}
pub struct VerifiedRecord<'a> {
    envelope: &'a RecordEnvelope,
    nonce: Vec<u8>,
    ciphertext: Vec<u8>,
}
impl RecordEnvelope {
    /// Caller resolves this key from an already verified membership and checks the epoch/scope.
    pub fn verify(&self, trusted_author: &str) -> Result<VerifiedRecord<'_>, AppError> {
        let header = self.header.canonical()?;
        let nonce = decode(&self.nonce, 24, 24)?;
        let ciphertext = decode(&self.ciphertext, 16, MAX_PLAINTEXT_BYTES + 16)?;
        verify(
            trusted_author,
            &author_bytes(
                "lunport-record-author-v2",
                &header,
                &self.nonce,
                &ciphertext,
            )?,
            &self.signature,
        )?;
        Ok(VerifiedRecord {
            envelope: self,
            nonce,
            ciphertext,
        })
    }
}
impl VerifiedRecord<'_> {
    pub fn open(self, keys: &VaultKeys) -> Result<Zeroizing<Vec<u8>>, AppError> {
        let aad = self.envelope.header.canonical()?;
        XChaCha20Poly1305::new_from_slice(&keys.0[32..])
            .map_err(|_| invalid())?
            .decrypt(
                XNonce::from_slice(&self.nonce),
                Payload {
                    msg: &self.ciphertext,
                    aad: &aad,
                },
            )
            .map(Zeroizing::new)
            .map_err(|_| invalid())
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WrappedKeys {
    pub header: WrapHeader,
    pub encapsulated_key: String,
    pub ciphertext: String,
    pub signature: String,
}
pub fn wrap_keys(
    keys: &VaultKeys,
    author: &DeviceKeys,
    header: WrapHeader,
) -> Result<WrappedKeys, AppError> {
    let context = header.canonical()?;
    let recipient =
        <Kem as KemTrait>::PublicKey::from_bytes(&decode(&header.recipient_key, 32, 32)?)
            .map_err(|_| invalid())?;
    // HPKE's OS RNG can panic on entropy failure. No weaker RNG or plaintext fallback is allowed.
    let result = std::panic::catch_unwind(|| {
        hpke::single_shot_seal::<ChaCha20Poly1305, HkdfSha256, Kem>(
            &OpModeS::Base,
            &recipient,
            &context,
            &keys.0[..],
            &context,
        )
    })
    .map_err(|_| invalid())?;
    let (enc, ciphertext) = result.map_err(|_| invalid())?;
    let encapsulated_key = B64.encode(enc.to_bytes());
    let signature = author.sign(&author_bytes(
        "lunport-wrap-author-v2",
        &context,
        &encapsulated_key,
        &ciphertext,
    )?);
    Ok(WrappedKeys {
        header,
        encapsulated_key,
        ciphertext: B64.encode(ciphertext),
        signature,
    })
}
impl WrappedKeys {
    /// The trusted membership supplies author/recipient keys; the server is never a trust root.
    pub fn open(
        &self,
        recipient: &DeviceKeys,
        expected: &WrapHeader,
        trusted_author: &str,
    ) -> Result<VaultKeys, AppError> {
        if &self.header != expected || recipient.public().encryption != self.header.recipient_key {
            return Err(invalid());
        }
        let context = self.header.canonical()?;
        let enc =
            <Kem as KemTrait>::EncappedKey::from_bytes(&decode(&self.encapsulated_key, 32, 32)?)
                .map_err(|_| invalid())?;
        let ciphertext = decode(&self.ciphertext, 80, 80)?;
        verify(
            trusted_author,
            &author_bytes(
                "lunport-wrap-author-v2",
                &context,
                &self.encapsulated_key,
                &ciphertext,
            )?,
            &self.signature,
        )?;
        let plaintext = Zeroizing::new(
            hpke::single_shot_open::<ChaCha20Poly1305, HkdfSha256, Kem>(
                &OpModeR::Base,
                &recipient.encryption,
                &enc,
                &context,
                &ciphertext,
                &context,
            )
            .map_err(|_| invalid())?,
        );
        VaultKeys::from_bytes(&plaintext)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    fn header() -> RecordHeader {
        RecordHeader {
            origin: "https://relay.example".into(),
            account_id: "a".repeat(64),
            genesis_hash: "b".repeat(64),
            vault_id: "c".repeat(64),
            record_id: "d".repeat(64),
            key_epoch: "1".into(),
            membership_head: "e".repeat(64),
            author: "f".repeat(32),
            operation_id: "1".repeat(32),
            expected_revision: "0".into(),
            kind: "host".into(),
            deleted: false,
        }
    }
    #[test]
    fn independent_keys_round_trip_without_debug_or_plaintext_storage() {
        let device = DeviceKeys::generate().unwrap();
        let encoded = device.encode_secret();
        let restored = DeviceKeys::decode_secret(&encoded).unwrap();
        assert_eq!(device.public(), restored.public());
        device.public().validate().unwrap();
        let vault = VaultKeys::generate().unwrap();
        let envelope = seal_record(&vault, &device, header(), b"synthetic SSH material").unwrap();
        assert!(!serde_json::to_string(&envelope)
            .unwrap()
            .contains("synthetic SSH material"));
        assert_eq!(
            &*envelope
                .verify(&device.public().signing)
                .unwrap()
                .open(&vault)
                .unwrap(),
            b"synthetic SSH material"
        );
        let mut wrong = envelope.clone();
        wrong.header.expected_revision = "1".into();
        assert!(wrong.verify(&device.public().signing).is_err());
        assert!(envelope
            .verify(&DeviceKeys::generate().unwrap().public().signing)
            .is_err());
        let next = vault.next_epoch().unwrap();
        assert_eq!(
            vault.record_id("host", "id").unwrap(),
            next.record_id("host", "id").unwrap()
        );
        assert!(envelope
            .verify(&device.public().signing)
            .unwrap()
            .open(&next)
            .is_err());
    }
    #[test]
    fn hpke_wrap_binds_exact_recipient_epoch_and_trust_context() {
        let author = DeviceKeys::generate().unwrap();
        let recipient = DeviceKeys::generate().unwrap();
        let vault = VaultKeys::generate().unwrap();
        let header = WrapHeader {
            origin: "https://relay.example".into(),
            account_id: "a".repeat(64),
            genesis_hash: "b".repeat(64),
            vault_id: "c".repeat(64),
            key_epoch: "1".into(),
            membership_head: "e".repeat(64),
            recipient: "d".repeat(32),
            recipient_key: recipient.public().encryption,
            author: "f".repeat(32),
        };
        let wrapped = wrap_keys(&vault, &author, header.clone()).unwrap();
        let opened = wrapped
            .open(&recipient, &header, &author.public().signing)
            .unwrap();
        assert_eq!(opened.0[..], vault.0[..]);
        let mut changed = header.clone();
        changed.key_epoch = "2".into();
        assert!(wrapped
            .open(&recipient, &changed, &author.public().signing)
            .is_err());
        assert!(wrapped
            .open(
                &DeviceKeys::generate().unwrap(),
                &header,
                &author.public().signing
            )
            .is_err());
        assert!(wrapped
            .open(&recipient, &header, &recipient.public().signing)
            .is_err());
    }
    #[test]
    fn weak_keys_noncanonical_encodings_and_ambiguous_numbers_are_rejected() {
        let mut weak = [0; 32];
        weak[0] = 1;
        assert!(verifying_key(&B64.encode(weak)).is_err());
        assert!(decode("AQ", 1, 1).is_err());
        assert!(super::super::wire::number("01", true).is_err());
        let mut h = header();
        h.kind = "password".into();
        assert!(h.canonical().is_err());
        h = header();
        h.key_epoch = "9007199254740992".into();
        assert!(h.canonical().is_err());
    }
}

#[cfg(test)]
mod vectors {
    use super::*;
    #[test]
    fn opens_fixed_interop_fixture_and_rejects_context_substitution() {
        let fixture: serde_json::Value =
            serde_json::from_str(include_str!("../../../../fixtures/central-sync-v2.json"))
                .unwrap();
        let recipient =
            DeviceKeys::decode_secret(fixture["recipient_secret"].as_str().unwrap()).unwrap();
        let wrapped: WrappedKeys = serde_json::from_value(fixture["wrap"].clone()).unwrap();
        let author = fixture["author_public"]["signing"].as_str().unwrap();
        let keys = wrapped.open(&recipient, &wrapped.header, author).unwrap();
        assert_eq!(
            B64.encode(&*keys.0),
            fixture["vault_keys"].as_str().unwrap()
        );
        let envelope: RecordEnvelope = serde_json::from_value(fixture["record"].clone()).unwrap();
        assert_eq!(
            B64.encode(envelope.header.canonical().unwrap()),
            fixture["record_aad_base64"].as_str().unwrap()
        );
        assert_eq!(
            &*envelope.verify(author).unwrap().open(&keys).unwrap(),
            fixture["plaintext"].as_str().unwrap().as_bytes()
        );
        let mut changed = envelope.clone();
        changed.header.membership_head = "9".repeat(64);
        assert!(changed.verify(author).is_err());
    }
    #[test]
    #[ignore = "explicit fixture regeneration only; contains synthetic test keys"]
    fn emit_interop_fixture() {
        use super::super::membership::{Action, Enrollment, Genesis, SignedMembership};
        let author = DeviceKeys::decode_secret(&B64.encode([1u8; 64])).unwrap();
        let recipient = DeviceKeys::decode_secret(&B64.encode([2u8; 64])).unwrap();
        let recovery = DeviceKeys::decode_secret(&B64.encode([4u8; 64])).unwrap();
        let vault = VaultKeys::from_bytes(&[3u8; 64]).unwrap();
        let (genesis, anchor) = Genesis::create(
            "https://relay.example",
            &"a".repeat(64),
            &"f".repeat(32),
            &author,
            &recovery,
        )
        .unwrap();
        let first = genesis.trust(&anchor).unwrap();
        let enrollment =
            Enrollment::create(&anchor, &"d".repeat(32), &recipient, 1_700_000_000_000).unwrap();
        let mut members = first.devices().clone();
        members.insert(enrollment.device.id.clone(), enrollment.device.keys.clone());
        let added = SignedMembership::sign(
            first.proposal(
                &"f".repeat(32),
                Action::Add,
                Some(enrollment.clone()),
                members,
                first.recovery().clone(),
                1_700_000_001_000,
            ),
            &author,
        )
        .unwrap();
        let approved = first.apply(&added).unwrap();
        let revoked = SignedMembership::sign(
            approved.proposal(
                &"f".repeat(32),
                Action::Revoke,
                None,
                first.devices().clone(),
                first.recovery().clone(),
                1_700_000_002_000,
            ),
            &author,
        )
        .unwrap();
        let current = approved.apply(&revoked).unwrap();
        let header = RecordHeader {
            origin: anchor.origin.clone(),
            account_id: anchor.account_id.clone(),
            genesis_hash: anchor.genesis_hash.clone(),
            vault_id: "c".repeat(64),
            record_id: vault.record_id("host", "0000000000000001").unwrap(),
            key_epoch: "1".into(),
            membership_head: approved.head().into(),
            author: "f".repeat(32),
            operation_id: "1".repeat(32),
            expected_revision: "0".into(),
            kind: "host".into(),
            deleted: false,
        };
        let record = seal_record(
            &vault,
            &author,
            header.clone(),
            b"synthetic interop plaintext",
        )
        .unwrap();
        let wrap_header = WrapHeader {
            origin: header.origin.clone(),
            account_id: header.account_id.clone(),
            genesis_hash: header.genesis_hash.clone(),
            vault_id: header.vault_id.clone(),
            key_epoch: "1".into(),
            membership_head: header.membership_head.clone(),
            recipient: "d".repeat(32),
            recipient_key: recipient.public().encryption,
            author: header.author.clone(),
        };
        let wrapped = wrap_keys(&vault, &author, wrap_header.clone()).unwrap();
        let fixture = serde_json::json!({"fixture":"SYNTHETIC TEST KEYS ONLY - never use in an account","author_public":author.public(),"recipient_secret":&*recipient.encode_secret(),"vault_keys":B64.encode([3u8;64]),"record":record,"record_aad_base64":B64.encode(header.canonical().unwrap()),"plaintext":"synthetic interop plaintext","wrap":wrapped,"wrap_context_base64":B64.encode(wrap_header.canonical().unwrap()),"anchor":anchor,"genesis":genesis,"genesis_canonical_base64":B64.encode(genesis.canonical().unwrap()),"enrollment":enrollment,"enrollment_canonical_base64":B64.encode(enrollment.canonical().unwrap()),"membership_nodes":[added,revoked],"membership_canonical_base64":[B64.encode(added.body.canonical().unwrap()),B64.encode(revoked.body.canonical().unwrap())],"current_membership_head":current.head()});
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../fixtures/central-sync-v2.json");
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, serde_json::to_vec_pretty(&fixture).unwrap()).unwrap();
    }
}
