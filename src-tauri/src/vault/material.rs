//! 私鑰的解析、解密與簽章(金鑰保管庫 spec §5.2、§5.5、§15)。只收 OpenSSH 格式。`ssh-key` 0.6.7 的 RSA 簽章有錯(組私鑰時把 `p` 傳了兩次),
//! RSA 改用 `rsa` 套件從 n、e、d、p、q 組私鑰;Ed25519 與 ECDSA 用 `ssh-key` 自己的簽章。解開的私鑰只在記憶體,`ssh-key` 的私密欄位 drop 時清掉。

use rsa::signature::{RandomizedSigner, SignatureEncoding};
use ssh_encoding::Encode;
use ssh_key::private::{KeypairData, RsaKeypair};
use ssh_key::public::KeyData;
use ssh_key::{PrivateKey, PublicKey};

use crate::error::AppError;

pub const SSH_AGENT_RSA_SHA2_256: u32 = 0x02;
pub const SSH_AGENT_RSA_SHA2_512: u32 = 0x04;

/// `ssh-key` 0.6.7 解得開的私鑰加密方式(spike 實測)。不在清單上的(例如 3des-cbc)不必問 passphrase:一定解不開。
pub const SUPPORTED_CIPHERS: &[&str] = &[
    "aes128-ctr",
    "aes192-ctr",
    "aes256-ctr",
    "aes128-cbc",
    "aes192-cbc",
    "aes256-cbc",
    "aes128-gcm@openssh.com",
    "aes256-gcm@openssh.com",
    "chacha20-poly1305@openssh.com",
];

#[derive(Debug, PartialEq, Eq)]
pub enum OpenError {
    /// 有 passphrase,沒有給。
    NeedsPassphrase,
    /// passphrase 不對(加密方式是支援的那幾種,所以錯的一定是 passphrase)。
    WrongPassphrase,
    /// 這種加密方式解不開。
    UnsupportedCipher(String),
    /// 不是 OpenSSH 格式的私鑰,或讀不懂。
    Unreadable,
}

/// 解開的私鑰。
pub struct Material {
    key: PrivateKey,
}

/// 公鑰那一行(`<type> <base64> [comment]`)的 `KeyData`:列出 agent 的金鑰、比對簽章請求用,不必解密私鑰。
pub fn public_key_data(public_key_line: &str) -> Option<KeyData> {
    PublicKey::from_openssh(public_key_line.trim()).ok().map(|key| key.key_data().clone())
}

pub fn is_encrypted(private_key: &str) -> bool {
    PrivateKey::from_openssh(private_key).is_ok_and(|key| key.is_encrypted())
}

/// 解析私鑰原文;有 passphrase 的用 `passphrase` 解開。
pub fn open(private_key: &str, passphrase: Option<&str>) -> Result<Material, OpenError> {
    let key = PrivateKey::from_openssh(private_key).map_err(|_| OpenError::Unreadable)?;
    if !key.is_encrypted() {
        return Ok(Material { key });
    }
    let cipher = key.cipher().as_str().to_string();
    if !SUPPORTED_CIPHERS.contains(&cipher.as_str()) {
        return Err(OpenError::UnsupportedCipher(cipher));
    }
    let Some(passphrase) = passphrase else { return Err(OpenError::NeedsPassphrase) };
    key.decrypt(passphrase).map(|key| Material { key }).map_err(|_| OpenError::WrongPassphrase)
}

fn signing_failed(e: impl std::fmt::Display) -> AppError {
    AppError::Other(format!("signing failed: {e}"))
}

/// `ssh-key` 0.6.7 的轉換用 `[p, p]` 組私鑰,`rsa` 驗證時拒絕;這裡用 `[p, q]`。
fn rsa_private_key(keypair: &RsaKeypair) -> Result<rsa::RsaPrivateKey, AppError> {
    let invalid = || AppError::Other("the RSA key is not valid".to_string());
    let n = rsa::BigUint::try_from(&keypair.public.n).map_err(|_| invalid())?;
    let e = rsa::BigUint::try_from(&keypair.public.e).map_err(|_| invalid())?;
    let d = rsa::BigUint::try_from(&keypair.private.d).map_err(|_| invalid())?;
    let p = rsa::BigUint::try_from(&keypair.private.p).map_err(|_| invalid())?;
    let q = rsa::BigUint::try_from(&keypair.private.q).map_err(|_| invalid())?;
    rsa::RsaPrivateKey::from_components(n, e, d, vec![p, q]).map_err(|_| invalid())
}

/// `string 演算法, string 簽章`。
fn signature_blob(algorithm: &str, raw: &[u8]) -> Result<Vec<u8>, AppError> {
    let mut blob = Vec::new();
    algorithm.encode(&mut blob).map_err(signing_failed)?;
    raw.encode(&mut blob).map_err(signing_failed)?;
    Ok(blob)
}

impl Material {
    pub fn key_data(&self) -> KeyData {
        self.key.public_key().key_data().clone()
    }

    /// 簽章,回傳 agent 協定的 signature blob。RSA 依 flag 選 SHA-512、SHA-256,沒有 flag 用 SHA-1(`ssh-rsa`,同 OpenSSH 的 agent)。
    pub fn sign(&self, data: &[u8], flags: u32) -> Result<Vec<u8>, AppError> {
        match self.key.key_data() {
            KeypairData::Rsa(keypair) => {
                let private = rsa_private_key(keypair)?;
                let mut rng = rand_core::OsRng;
                if flags & SSH_AGENT_RSA_SHA2_512 != 0 {
                    let signature = rsa::pkcs1v15::SigningKey::<sha2::Sha512>::new(private)
                        .try_sign_with_rng(&mut rng, data)
                        .map_err(signing_failed)?;
                    signature_blob("rsa-sha2-512", &signature.to_vec())
                } else if flags & SSH_AGENT_RSA_SHA2_256 != 0 {
                    let signature = rsa::pkcs1v15::SigningKey::<sha2::Sha256>::new(private)
                        .try_sign_with_rng(&mut rng, data)
                        .map_err(signing_failed)?;
                    signature_blob("rsa-sha2-256", &signature.to_vec())
                } else {
                    let signature = rsa::pkcs1v15::SigningKey::<sha1::Sha1>::new(private)
                        .try_sign_with_rng(&mut rng, data)
                        .map_err(signing_failed)?;
                    signature_blob("ssh-rsa", &signature.to_vec())
                }
            }
            _ => {
                use signature::Signer;
                let signature: ssh_key::Signature = self.key.try_sign(data).map_err(signing_failed)?;
                let mut blob = Vec::new();
                signature.encode(&mut blob).map_err(signing_failed)?;
                Ok(blob)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sync::slot_rules::test_keys;
    use ssh_encoding::Decode;

    /// Verify an Ed25519, ECDSA or rsa-sha2 signature blob with ssh-key.
    fn verify(public_line: &str, data: &[u8], blob: &[u8]) {
        use signature::Verifier;
        let key = public_key_data(public_line).unwrap();
        let signature = ssh_key::Signature::decode(&mut &blob[..]).unwrap();
        key.verify(data, &signature).unwrap();
    }

    /// Split a signature blob into (algorithm, raw signature).
    fn split(blob: &[u8]) -> (String, Vec<u8>) {
        let mut r = blob;
        let algorithm = String::decode(&mut r).unwrap();
        let raw = Vec::<u8>::decode(&mut r).unwrap();
        (algorithm, raw)
    }

    #[test]
    fn ed25519_and_ecdsa_sign_and_verify() {
        for (private, public) in [(test_keys::plain(), test_keys::PLAIN_PUBLIC), (test_keys::ecdsa(), test_keys::ECDSA_PUBLIC)] {
            let material = open(&private, None).unwrap();
            assert_eq!(material.key_data(), public_key_data(public).unwrap());
            let blob = material.sign(b"hello", 0).unwrap();
            verify(public, b"hello", &blob);
        }
    }

    #[test]
    fn rsa_signs_with_the_hash_the_flags_ask_for() {
        let material = open(&test_keys::rsa(), None).unwrap();
        let blob = material.sign(b"hello", SSH_AGENT_RSA_SHA2_512).unwrap();
        assert_eq!(split(&blob).0, "rsa-sha2-512");
        verify(test_keys::RSA_PUBLIC, b"hello", &blob);
        let blob = material.sign(b"hello", SSH_AGENT_RSA_SHA2_256).unwrap();
        assert_eq!(split(&blob).0, "rsa-sha2-256");
        verify(test_keys::RSA_PUBLIC, b"hello", &blob);

        // No flag: legacy ssh-rsa (SHA-1), which ssh-key 0.6.7 cannot decode; verify with the rsa crate.
        let (algorithm, raw) = split(&material.sign(b"hello", 0).unwrap());
        assert_eq!(algorithm, "ssh-rsa");
        use rsa::signature::Verifier as _;
        let ssh_key::public::KeyData::Rsa(public) = public_key_data(test_keys::RSA_PUBLIC).unwrap() else { panic!("rsa") };
        let n = rsa::BigUint::try_from(&public.n).unwrap();
        let e = rsa::BigUint::try_from(&public.e).unwrap();
        let verifying = rsa::pkcs1v15::VerifyingKey::<sha1::Sha1>::new(rsa::RsaPublicKey::new(n, e).unwrap());
        verifying.verify(b"hello", &rsa::pkcs1v15::Signature::try_from(raw.as_slice()).unwrap()).unwrap();
    }

    #[test]
    fn an_encrypted_key_needs_the_right_passphrase() {
        let text = test_keys::encrypted();
        assert!(is_encrypted(&text));
        assert!(!is_encrypted(&test_keys::plain()));
        assert_eq!(open(&text, None).err(), Some(OpenError::NeedsPassphrase));
        assert_eq!(open(&text, Some("wrong")).err(), Some(OpenError::WrongPassphrase));
        let material = open(&text, Some("test-passphrase")).unwrap();
        verify(test_keys::ENC_PUBLIC, b"x", &material.sign(b"x", 0).unwrap());
    }

    /// 加密過的測試私鑰,標頭裡的加密方式改標成 `3des-cbc`(`ssh-key` 0.6.7 讀得懂、但解不開)。只換標頭裡的名稱,金鑰的位元組不動。
    fn encrypted_with_3des_label() -> String {
        use base64::{engine::general_purpose::STANDARD, Engine as _};
        let bytes = STANDARD.decode(test_keys::ENC_BODY.concat()).unwrap();
        let (magic, rest) = bytes.split_at(b"openssh-key-v1\0".len());
        let (old_len, after_len) = rest.split_at(4);
        assert_eq!(old_len, 10u32.to_be_bytes(), "the fixture is expected to start with `aes256-ctr`");
        let (old_name, tail) = after_len.split_at(10);
        assert_eq!(old_name, b"aes256-ctr");
        let mut relabelled = magic.to_vec();
        relabelled.extend_from_slice(&8u32.to_be_bytes());
        relabelled.extend_from_slice(b"3des-cbc");
        relabelled.extend_from_slice(tail);
        let b64 = STANDARD.encode(relabelled);
        let lines: Vec<&str> = b64.as_bytes().chunks(70).map(|c| std::str::from_utf8(c).unwrap()).collect();
        test_keys::armor(&lines)
    }

    #[test]
    fn an_unsupported_cipher_is_reported_before_any_passphrase_is_tried() {
        // `ssh-key` 對「passphrase 不對」與「解不開這種加密方式」回同一種錯誤(連對的 passphrase 都會被當成錯的),所以要先看加密方式。
        let text = encrypted_with_3des_label();
        assert!(is_encrypted(&text));
        let expected = Some(OpenError::UnsupportedCipher("3des-cbc".to_string()));
        assert_eq!(open(&text, None).err(), expected);
        assert_eq!(open(&text, Some("test-passphrase")).err(), expected);
    }

    #[test]
    fn non_openssh_keys_are_unreadable() {
        let pem = "-----BEGIN RSA PRIVATE KEY-----\nMIIBOgIBAAJBAK\n-----END RSA PRIVATE KEY-----\n";
        assert_eq!(open(pem, None).err(), Some(OpenError::Unreadable));
        assert_eq!(open("not a key", None).err(), Some(OpenError::Unreadable));
        assert!(!is_encrypted(pem));
    }

    #[test]
    fn public_key_lines_parse_with_or_without_a_comment() {
        let bare = public_key_data(test_keys::PLAIN_PUBLIC).unwrap();
        let commented = public_key_data(&format!("{} someone@host\n", test_keys::PLAIN_PUBLIC)).unwrap();
        assert_eq!(bare, commented);
        assert_eq!(public_key_data("garbage"), None);
    }
}
