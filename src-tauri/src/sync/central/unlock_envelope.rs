//! Native-only account unlock. The service stores ciphertext, never PRF output or a password.
//! This wraps the existing recovery authority, not Vault content keys or a device identity.
use super::{
    crypto,
    membership::TrustAnchor,
    recovery::RecoveryKit,
    wire::{canonical, hex, invalid, number, origin},
};
use crate::error::AppError;
use argon2::{Algorithm, Argon2, Params, Version};
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    XChaCha20Poly1305, XNonce,
};
use hkdf::Hkdf;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use zeroize::Zeroizing;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub(super) enum Binding {
    // Raw native hmac-secret domain, deliberately distinct from browser WebAuthn PRF.
    NativePrf { credential_hash: String },
    Password,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Header {
    pub version: u32,
    pub anchor: TrustAnchor,
    pub generation: String,
    pub binding: Binding,
    pub salt: String,
}
impl Header {
    pub(super) fn aad(&self) -> Result<Vec<u8>, AppError> {
        if self.version != 1
            || !origin(&self.anchor.origin)
            || !self.anchor.origin.starts_with("https://")
            || !hex(&self.anchor.account_id, 64)
            || !hex(&self.anchor.genesis_hash, 64)
        {
            return Err(invalid());
        }
        number(&self.generation, false)?;
        crypto::decode(&self.salt, 32, 32)?;
        let (method, credential) = match &self.binding {
            Binding::NativePrf { credential_hash } if hex(credential_hash, 64) => (
                "native-hmac-secret-hkdf-sha256-v1",
                credential_hash.as_str(),
            ),
            Binding::Password => ("argon2id-v19-m65536-t3-p1-hkdf-sha256-v1", ""),
            _ => return Err(invalid()),
        };
        canonical(&[
            "lunport-account-unlock-v1",
            &self.anchor.origin,
            &self.anchor.account_id,
            &self.anchor.genesis_hash,
            &self.generation,
            method,
            credential,
            &self.salt,
        ])
    }
    pub fn new(anchor: TrustAnchor, generation: u64, binding: Binding) -> Result<Self, AppError> {
        let mut salt = [0; 32];
        getrandom::fill(&mut salt).map_err(|_| invalid())?;
        let result = Self {
            version: 1,
            anchor,
            generation: generation.to_string(),
            binding,
            salt: B64.encode(salt),
        };
        result.aad()?;
        Ok(result)
    }
    fn expand(&self, input: &[u8]) -> Result<Zeroizing<[u8; 32]>, AppError> {
        let aad = self.aad()?;
        let salt = crypto::decode(&self.salt, 32, 32)?;
        let mut key = Zeroizing::new([0; 32]);
        Hkdf::<Sha256>::new(Some(&salt), input)
            .expand(&aad, &mut *key)
            .map_err(|_| invalid())?;
        Ok(key)
    }
    fn prf_key(&self, native_output: &[u8]) -> Result<Zeroizing<[u8; 32]>, AppError> {
        if !matches!(self.binding, Binding::NativePrf { .. }) || native_output.len() != 32 {
            return Err(invalid());
        }
        self.expand(native_output)
    }
    fn password_key(&self, password: &str) -> Result<Zeroizing<[u8; 32]>, AppError> {
        self.aad()?;
        if self.binding != Binding::Password || password.is_empty() || password.len() > 1024 {
            return Err(invalid());
        }
        // Fixed resource bounds: the untrusted envelope cannot choose KDF cost or algorithms.
        let salt = crypto::decode(&self.salt, 32, 32)?;
        let params = Params::new(65536, 3, 1, Some(32)).map_err(|_| invalid())?;
        let mut derived = Zeroizing::new([0; 32]);
        Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
            .hash_password_into(password.as_bytes(), &salt, &mut *derived)
            .map_err(|_| invalid())?;
        self.expand(&*derived)
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Envelope {
    pub header: Header,
    pub nonce: String,
    pub ciphertext: String,
}
impl Envelope {
    fn seal(header: Header, key: &[u8], kit: &RecoveryKit) -> Result<Self, AppError> {
        if kit.anchor() != &header.anchor {
            return Err(invalid());
        }
        let aad = header.aad()?;
        let secret = kit.encode_secret()?;
        let mut nonce = [0; 24];
        getrandom::fill(&mut nonce).map_err(|_| invalid())?;
        let ciphertext = XChaCha20Poly1305::new_from_slice(key)
            .map_err(|_| invalid())?
            .encrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: secret.as_bytes(),
                    aad: &aad,
                },
            )
            .map_err(|_| invalid())?;
        Ok(Self {
            header,
            nonce: B64.encode(nonce),
            ciphertext: B64.encode(ciphertext),
        })
    }
    fn open(
        &self,
        key: &[u8],
        expected: &TrustAnchor,
        minimum: u64,
    ) -> Result<RecoveryKit, AppError> {
        if &self.header.anchor != expected
            || minimum == 0
            || number(&self.header.generation, false)? < minimum
        {
            return Err(invalid());
        }
        let nonce = crypto::decode(&self.nonce, 24, 24)?;
        let ciphertext = crypto::decode(&self.ciphertext, 17, 4112)?;
        let aad = self.header.aad()?;
        let plaintext = Zeroizing::new(
            XChaCha20Poly1305::new_from_slice(key)
                .map_err(|_| invalid())?
                .decrypt(
                    XNonce::from_slice(&nonce),
                    Payload {
                        msg: &ciphertext,
                        aad: &aad,
                    },
                )
                .map_err(|_| invalid())?,
        );
        let kit = RecoveryKit::parse(std::str::from_utf8(&plaintext).map_err(|_| invalid())?)?;
        if kit.anchor() != expected {
            return Err(invalid());
        }
        Ok(kit)
    }
    pub fn seal_prf(
        header: Header,
        native_output: &[u8],
        kit: &RecoveryKit,
    ) -> Result<Self, AppError> {
        let key = header.prf_key(native_output)?;
        Self::seal(header, &*key, kit)
    }
    pub fn open_prf(
        &self,
        native_output: &[u8],
        expected: &TrustAnchor,
        minimum: u64,
    ) -> Result<RecoveryKit, AppError> {
        let key = self.header.prf_key(native_output)?;
        self.open(&*key, expected, minimum)
    }
    pub fn seal_password(
        header: Header,
        password: &str,
        kit: &RecoveryKit,
    ) -> Result<Self, AppError> {
        if password.chars().count() < 12 {
            return Err(invalid());
        }
        let key = header.password_key(password)?;
        Self::seal(header, &*key, kit)
    }
    pub fn open_password(
        &self,
        password: &str,
        expected: &TrustAnchor,
        minimum: u64,
    ) -> Result<RecoveryKit, AppError> {
        let key = self.header.password_key(password)?;
        self.open(&*key, expected, minimum)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sync::central::{
        crypto::DeviceKeys, membership::Genesis, recovery::RecoverySeed, trust::ControlProof,
    };
    fn fixture() -> (RecoveryKit, Header) {
        let first = DeviceKeys::generate().unwrap();
        let seed = RecoverySeed::generate().unwrap();
        let authority = seed.keys("https://sync.example", &"a".repeat(64)).unwrap();
        let (genesis, anchor) = Genesis::create(
            "https://sync.example",
            &"a".repeat(64),
            &"b".repeat(32),
            &first,
            &authority,
        )
        .unwrap();
        let proof = ControlProof {
            genesis,
            nodes: vec![],
        };
        let kit = seed.bind(&proof.verify(&anchor, None).unwrap()).unwrap();
        (
            kit,
            Header::new(
                anchor,
                2,
                Binding::NativePrf {
                    credential_hash: "c".repeat(64),
                },
            )
            .unwrap(),
        )
    }
    #[test]
    fn prf_ciphertext_is_scoped_randomized_and_contains_no_recovery_secret() {
        let (kit, header) = fixture();
        let a = Envelope::seal_prf(header.clone(), &[7; 32], &kit).unwrap();
        let b = Envelope::seal_prf(header, &[7; 32], &kit).unwrap();
        assert_ne!(a.nonce, b.nonce);
        assert_ne!(a.ciphertext, b.ciphertext);
        assert_eq!(
            *a.open_prf(&[7; 32], kit.anchor(), 2)
                .unwrap()
                .encode_secret()
                .unwrap(),
            *kit.encode_secret().unwrap()
        );
        let public = serde_json::to_string(&a).unwrap();
        assert!(!public.contains("LPREC2:"));
        assert!(!public.contains(&*kit.encode_secret().unwrap()));
        assert!(a.open_prf(&[8; 32], kit.anchor(), 2).is_err());
        assert!(a.open_prf(&[7; 31], kit.anchor(), 2).is_err());
        assert!(a.open_prf(&[7; 32], kit.anchor(), 3).is_err());
    }
    #[test]
    fn altered_context_credential_method_nonce_or_ciphertext_cannot_unlock() {
        let (kit, header) = fixture();
        let envelope = Envelope::seal_prf(header, &[7; 32], &kit).unwrap();
        for change in 0..8 {
            let mut bad = envelope.clone();
            match change {
                0 => bad.header.anchor.origin = "https://other.example".into(),
                1 => bad.header.anchor.account_id = "d".repeat(64),
                2 => bad.header.anchor.genesis_hash = "e".repeat(64),
                3 => bad.header.generation = "3".into(),
                4 => {
                    bad.header.binding = Binding::NativePrf {
                        credential_hash: "f".repeat(64),
                    }
                }
                5 => bad.header.binding = Binding::Password,
                6 => bad.nonce = B64.encode([3; 24]),
                _ => bad.ciphertext = B64.encode([4; 128]),
            }
            assert!(bad.open_prf(&[7; 32], &bad.header.anchor, 1).is_err());
        }
    }
    #[test]
    fn fallback_password_roundtrips_with_fixed_cost_and_cannot_replace_prf_binding() {
        let (kit, _) = fixture();
        let header = Header::new(kit.anchor().clone(), 1, Binding::Password).unwrap();
        assert!(Envelope::seal_password(header.clone(), "short", &kit).is_err());
        let envelope =
            Envelope::seal_password(header, "a long synthetic sync password", &kit).unwrap();
        assert_eq!(
            envelope
                .open_password("a long synthetic sync password", kit.anchor(), 1)
                .unwrap()
                .anchor(),
            kit.anchor()
        );
        assert!(envelope
            .open_password("wrong synthetic sync password", kit.anchor(), 1)
            .is_err());
        assert!(envelope.open_prf(&[7; 32], kit.anchor(), 1).is_err());
    }
}
