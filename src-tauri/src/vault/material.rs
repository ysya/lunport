//! 私鑰的解析、解密與簽章(金鑰保管庫 spec §5.2、§5.5、§15)。只收 OpenSSH 格式。`ssh-key` 0.6.7 的 RSA 簽章有錯(組私鑰時把 `p` 傳了兩次),
//! RSA 改用 `rsa` 套件從 n、e、d、p、q 組私鑰;Ed25519 與 ECDSA 用 `ssh-key` 自己的簽章。`ssh-key` 0.6.7 也讀不懂純量短了的 ECDSA 金鑰(OpenSSH 省掉 mpint 的
//! 前導零),`parse` 與 `open` 的解密在它讀不懂時交給 `short_scalar` 補零再讀。解開的私鑰只在記憶體,`ssh-key` 的私密欄位 drop 時清掉。

use rsa::signature::{RandomizedSigner, SignatureEncoding};
use ssh_encoding::Encode;
use ssh_key::private::{KeypairData, RsaKeypair};
use ssh_key::public::KeyData;
use ssh_key::{Algorithm, PrivateKey, PublicKey};

use crate::error::AppError;
use crate::vault::short_scalar;

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
    /// passphrase 不對,或加密內容損毀(加密方式是支援的那幾種,但 `ssh-key` 解密失敗時分不出是哪一個)。
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

/// agent 簽得了這種金鑰嗎:Ed25519、ECDSA、RSA。`sk-*`(FIDO 安全金鑰,簽章要靠硬體)與 DSA 不行。這是唯一的規則:agent 列出金鑰、比對簽章請求
/// (`agent::broker`),和「Only in SSHelter」收不收這把金鑰(`sync::slots::set_delivery`)都看它 —— 簽不了的金鑰不列出,也不搬進保管庫。
pub fn agent_can_sign(data: &KeyData) -> bool {
    matches!(data.algorithm(), Algorithm::Ed25519 | Algorithm::Ecdsa { .. } | Algorithm::Rsa { .. })
}

/// 這把私鑰有沒有加密。目前只有測試用到,所以只在測試編譯。
#[cfg(test)]
pub fn is_encrypted(private_key: &str) -> bool {
    PrivateKey::from_openssh(private_key).is_ok_and(|key| key.is_encrypted())
}

/// agent 讀得懂這把私鑰嗎(`open` 不回 `Unreadable`)?`inspect_private_key`(同步讀標頭用的)只看標頭與公鑰段,`ssh-key` 另外會挑剔其他欄位
/// (例如不是 UTF-8 的 comment):讀不懂的金鑰搬進保管庫之後 agent 打不開它,所以「Only in SSHelter」先用它擋下(`sync::slots::set_delivery`)。
/// 要 passphrase(`NeedsPassphrase`)與加密方式解不開(`UnsupportedCipher`,有自己的訊息)都是解析成功,算讀得懂。
pub fn agent_can_read(private_key: &str) -> bool {
    !matches!(open(private_key, None), Err(OpenError::Unreadable))
}

/// 這把私鑰要是加密過、加密方式又不在 `SUPPORTED_CIPHERS` 上,回傳那個名稱(`open` 回 `UnsupportedCipher` 的判斷)。
fn unsupported_cipher_of(key: &PrivateKey) -> Option<String> {
    if !key.is_encrypted() {
        return None;
    }
    let cipher = key.cipher().as_str();
    (!SUPPORTED_CIPHERS.contains(&cipher)).then(|| cipher.to_string())
}

/// 私鑰原文的加密方式 agent 解不開(例如 `3des-cbc`)就回傳它的名稱;沒有加密、解得開,或讀不懂(那是 `open` 要回報的 `Unreadable`)都是 None。
/// 不必 passphrase,也不解密:「Only in SSHelter」用它在搬進保管庫之前拒絕這把金鑰。
pub fn unsupported_cipher(private_key: &str) -> Option<String> {
    PrivateKey::from_openssh(private_key).ok().and_then(|key| unsupported_cipher_of(&key))
}

/// 解析私鑰原文,不解密(加密的金鑰解析得了,私鑰段還是密文)。`ssh-key` 讀不懂、但只是沒有加密的 ECDSA 金鑰純量短了的,由 `short_scalar` 補零再讀;
/// 其他讀不懂的回 None。保管庫裡讀私鑰的地方(`open`、`export::export_text`)都走這裡,免得一把金鑰 agent 簽得了、匯出卻說讀不懂。
pub fn parse(private_key: &str) -> Option<PrivateKey> {
    PrivateKey::from_openssh(private_key).ok().or_else(|| short_scalar::parse(private_key))
}

/// Parses the private key text; one with a passphrase is decrypted with `passphrase`. `ssh-key` cannot decrypt an ECDSA key whose scalar
/// is short even with the right passphrase: it refuses the scalar for its length (`Error::Encoding(Length)`), and only then does
/// `short_scalar` decrypt the key once more (a second bcrypt) and pad the scalar; if that fails too, it is `WrongPassphrase`. Any other
/// failure is `WrongPassphrase` at once: a wrong passphrase is `ssh-key`'s `Error::Crypto` (the checkints differ, or an AEAD tag does not
/// match), and trying it again would only double the wait for the answer.
pub fn open(private_key: &str, passphrase: Option<&str>) -> Result<Material, OpenError> {
    let key = parse(private_key).ok_or(OpenError::Unreadable)?;
    if let Some(cipher) = unsupported_cipher_of(&key) {
        return Err(OpenError::UnsupportedCipher(cipher));
    }
    if !key.is_encrypted() {
        return Ok(Material { key });
    }
    let Some(passphrase) = passphrase else { return Err(OpenError::NeedsPassphrase) };
    match key.decrypt(passphrase) {
        Ok(key) => Ok(Material { key }),
        Err(ssh_key::Error::Encoding(ssh_encoding::Error::Length)) => {
            short_scalar::decrypt(private_key, passphrase).map(|key| Material { key }).ok_or(OpenError::WrongPassphrase)
        }
        Err(_) => Err(OpenError::WrongPassphrase),
    }
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

    /// 用 ssh-key 驗證 Ed25519、ECDSA 或 rsa-sha2 的簽章 blob。
    fn verify(public_line: &str, data: &[u8], blob: &[u8]) {
        use signature::Verifier;
        let key = public_key_data(public_line).unwrap();
        let signature = ssh_key::Signature::decode(&mut &blob[..]).unwrap();
        key.verify(data, &signature).unwrap();
    }

    /// 把簽章 blob 拆成(演算法, 原始簽章)。
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

    /// OpenSSH writes the ECDSA scalar as an mpint and leaves out its leading zero bytes: when the first byte is zero and the next one's top
    /// bit is clear, the scalar comes out shorter than the curve (about 1 key in 512 that `ssh-keygen` makes for P-256 and P-384, 1 in 4
    /// for P-521). `ssh-key` 0.6.7 refuses such a key (`length invalid`), and the agent used to say it could not read it; `short_scalar`
    /// pads the scalar. A signature that verifies shows that the scalar put back is the original one.
    #[test]
    fn an_ecdsa_key_whose_scalar_lost_its_leading_zero_opens_and_signs() {
        for (what, private, public) in [
            ("p256", test_keys::ecdsa_short_p256(), test_keys::ECDSA_SHORT_P256_PUBLIC),
            ("p384", test_keys::ecdsa_short_p384(), test_keys::ECDSA_SHORT_P384_PUBLIC),
            ("p521", test_keys::ecdsa_short_p521(), test_keys::ECDSA_SHORT_P521_PUBLIC),
        ] {
            assert!(PrivateKey::from_openssh(&private).is_err(), "{what}: setup: ssh-key 0.6.7 alone can't read it");
            let material = open(&private, None).unwrap_or_else(|e| panic!("{what}: {e:?}"));
            assert_eq!(material.key_data(), public_key_data(public).unwrap(), "{what}");
            verify(public, b"hello", &material.sign(b"hello", 0).unwrap());
            assert!(agent_can_read(&private), "{what}");
            assert!(!is_encrypted(&private), "{what}");
        }
    }

    /// 加密的也一樣:`ssh-key` 用對的 passphrase 解不開純量短了的金鑰,不能當成 passphrase 不對。
    #[test]
    fn an_encrypted_ecdsa_key_with_a_short_scalar_still_needs_the_right_passphrase() {
        let text = test_keys::ecdsa_short_p256_encrypted();
        assert!(is_encrypted(&text));
        assert_eq!(unsupported_cipher(&text), None);
        assert_eq!(open(&text, None).err(), Some(OpenError::NeedsPassphrase));
        assert_eq!(open(&text, Some("wrong")).err(), Some(OpenError::WrongPassphrase));
        let material = open(&text, Some("test-passphrase")).unwrap();
        assert_eq!(material.key_data(), public_key_data(test_keys::ECDSA_SHORT_P256_PUBLIC).unwrap());
        verify(test_keys::ECDSA_SHORT_P256_PUBLIC, b"x", &material.sign(b"x", 0).unwrap());
        assert!(agent_can_read(&text));
    }

    /// `ssh-key` refuses a short scalar for its length even with the right passphrase, and only that error is worth a second try, which
    /// costs a second bcrypt. A wrong passphrase is `ssh-key`'s `Crypto` (the checkints differ, or an AEAD tag does not match) and costs
    /// one: `short_scalar` derives no key for it.
    #[test]
    fn only_a_length_error_has_short_scalar_decrypt_the_key_again() {
        let derivations = || short_scalar::KEY_DERIVATIONS.with(std::cell::Cell::get);
        let (public, section) = test_keys::EcdsaSection::of(test_keys::ECDSA_SHORT_P256_BODY);
        for cipher in [ssh_key::Cipher::Aes256Ctr, ssh_key::Cipher::Aes256Cbc, ssh_key::Cipher::Aes256Gcm, ssh_key::Cipher::ChaCha20Poly1305] {
            let text = test_keys::openssh_key(cipher, &test_keys::one_round_bcrypt(), &public, &section.padded(cipher.block_size()), "pass");
            let key = PrivateKey::from_openssh(&text).unwrap();
            assert_eq!(key.decrypt("wrong").err(), Some(ssh_key::Error::Crypto), "{cipher}: setup: ssh-key's answer to a wrong passphrase");
            assert_eq!(key.decrypt("pass").err(), Some(ssh_key::Error::Encoding(ssh_encoding::Error::Length)), "{cipher}: setup: and to the right one");
            let before = derivations();
            assert_eq!(open(&text, Some("wrong")).err(), Some(OpenError::WrongPassphrase), "{cipher}");
            assert_eq!(derivations(), before, "{cipher}: a wrong passphrase is not tried a second time");
            open(&text, Some("pass")).unwrap_or_else(|e| panic!("{cipher}: {e:?}"));
            assert_eq!(derivations(), before + 1, "{cipher}: the right one is, once, after ssh-key refused the scalar's length");
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

        // 沒有 flag:舊的 ssh-rsa(SHA-1),ssh-key 0.6.7 解不了,改用 rsa 套件驗證。
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

    #[test]
    fn an_unsupported_cipher_is_reported_before_any_passphrase_is_tried() {
        // `ssh-key` 對「passphrase 不對」與「解不開這種加密方式」回同一種錯誤(連對的 passphrase 都會被當成錯的),所以要先看加密方式。
        let text = test_keys::encrypted_with_3des_label();
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

    #[test]
    fn the_agent_signs_only_with_ed25519_ecdsa_and_rsa_keys() {
        for (kind, public) in [("ed25519", test_keys::PLAIN_PUBLIC.to_string()), ("ecdsa", test_keys::ECDSA_PUBLIC.to_string()), ("rsa", test_keys::RSA_PUBLIC.to_string())] {
            assert!(agent_can_sign(&public_key_data(&public).unwrap()), "{kind}");
        }
        // 讀得懂的公鑰,agent 卻簽不了:安全金鑰的簽章要靠硬體,DSA 不支援。
        for (kind, public) in [("sk-ed25519", test_keys::sk_public()), ("dsa", test_keys::dsa_public())] {
            let data = public_key_data(&public).unwrap_or_else(|| panic!("{kind}: setup: the public key parses"));
            assert!(!agent_can_sign(&data), "{kind}");
        }
    }

    /// `inspect_private_key` 只看標頭與公鑰段;`ssh-key` 另外會挑剔其他欄位(例如不是 UTF-8 的 comment)。agent 讀不懂的金鑰不能搬進保管庫。
    #[test]
    fn a_key_ssh_key_rejects_is_not_readable_by_the_agent() {
        use crate::sync::slot_rules::inspect_private_key;
        let broken = test_keys::unreadable_comment();
        assert!(inspect_private_key(&broken).is_ok(), "setup: SP3 reads its header and public key");
        assert_eq!(open(&broken, None).err(), Some(OpenError::Unreadable), "setup: but the agent's parser does not");
        assert!(!agent_can_read(&broken));
        assert!(!agent_can_read("not a key"));
        assert!(!agent_can_read("-----BEGIN RSA PRIVATE KEY-----\nMIIBOgIBAAJBAK\n-----END RSA PRIVATE KEY-----\n"), "not the OpenSSH format");
    }

    /// 解析得了就算讀得懂:沒有加密的、要 passphrase 的(`NeedsPassphrase`),以及加密方式解不開的(`UnsupportedCipher`:另有訊息說明,不是讀不懂)。
    #[test]
    fn a_key_that_parses_is_readable_whatever_else_is_wrong_with_it() {
        for (what, key) in [
            ("plain", test_keys::plain()),
            ("ecdsa", test_keys::ecdsa()),
            ("rsa", test_keys::rsa()),
            ("passphrase", test_keys::encrypted()),
            ("unsupported cipher", test_keys::encrypted_with_3des_label()),
        ] {
            assert!(agent_can_read(&key), "{what}");
        }
    }

    #[test]
    fn an_encryption_the_agent_cannot_open_is_named_without_a_passphrase() {
        assert_eq!(unsupported_cipher(&test_keys::encrypted_with_3des_label()), Some("3des-cbc".to_string()));
        assert_eq!(unsupported_cipher(&test_keys::encrypted()), None, "aes256-ctr is on the supported list");
        assert_eq!(unsupported_cipher(&test_keys::plain()), None, "no encryption at all");
        assert_eq!(unsupported_cipher("not a key"), None, "an unreadable key is `open`'s to report");
        // `open` 與這個判斷是同一條規則:認得出的加密方式才有機會問 passphrase。
        assert_eq!(open(&test_keys::encrypted_with_3des_label(), Some("test-passphrase")).err(), Some(OpenError::UnsupportedCipher("3des-cbc".to_string())));
    }
}
