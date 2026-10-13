//! 補回 OpenSSH 省掉的 ECDSA 私鑰純量前導零。OpenSSH 把 ECDSA 私鑰的純量(private scalar)寫成 mpint,前面的零位元組會省掉;`ssh-key` 0.6.7 的
//! `EcdsaPrivateKey::decode` 只接受剛好 32/48/66 位元組(或多一個 0x00 的符號位),短了就回 `length invalid`,`material::open` 跟著回 `Unreadable`。
//! `ssh-keygen -t ecdsa` 產生的 P-256、P-384 金鑰大約每 256 把有 1 把這樣,P-521 每 4 把有 1 把(521 位元的最高位元組只有 1 個位元,2^519 以下的
//! 純量都短一個位元組)。這裡在 `ssh-key` 讀不懂時自己拆開 `openssh-key-v1` 容器,把純量補回固定長度、重算 padding,再包回沒有加密的容器交給
//! `ssh-key` 讀 —— checkint、公私鑰相符、comment、padding 的檢查都還是它做。加密的金鑰要先解開才看得到純量,所以 `decrypt` 用 `ssh-key` 公開的
//! `Kdf`、`Cipher` 自己解密,其餘相同。
//!
//! ssh-key 0.7.0-rc.11 的 `EcdsaPrivateKey::decode` 會補零,但有 32 位元組的下限,P-256 短一個位元組的仍然解不開;0.7 也還是預覽版(ssh-encoding 0.3、
//! rsa 0.10 rc),整個 app 的公鑰、指紋都靠 ssh-key,所以不升級,在這裡補。

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use ssh_encoding::{Decode, Encode, Reader as _};
use ssh_key::public::KeyData;
use ssh_key::{Cipher, Kdf, PrivateKey};
use zeroize::Zeroizing;

const MAGIC: &[u8] = b"openssh-key-v1\0";
/// 標頭與結尾(拆開來寫,同 `test_keys`:免得掃描私鑰的工具把原始碼當成一把金鑰)。
const BEGIN: &str = concat!("-----BEGIN ", "OPENSSH", " PRIVATE KEY-----");
const END: &str = concat!("-----END ", "OPENSSH", " PRIVATE KEY-----");

/// 各曲線純量的固定長度(`ssh-key` 的 `EcdsaPrivateKey<SIZE>`)。
fn scalar_size(algorithm: &str, curve: &str) -> Option<usize> {
    match (algorithm, curve) {
        ("ecdsa-sha2-nistp256", "nistp256") => Some(32),
        ("ecdsa-sha2-nistp384", "nistp384") => Some(48),
        ("ecdsa-sha2-nistp521", "nistp521") => Some(66),
        _ => None,
    }
}

/// 拆開的 `openssh-key-v1` 容器(一把金鑰)。
struct Container {
    cipher: Cipher,
    kdf: Kdf,
    /// 公鑰段的內容。
    public: Vec<u8>,
    /// 私鑰段的內容:沒加密的是明文,加密的是密文。
    private: Zeroizing<Vec<u8>>,
    /// AEAD 加密方式(`*-gcm@openssh.com`、chacha20-poly1305)接在密文後面的 tag。
    tag: Option<[u8; 16]>,
}

/// 私鑰原文拆成容器:標頭與結尾之間的 base64,再照格式讀出每個欄位。格式不對(多把金鑰、結尾後面還有東西……)回 None。
fn container(private_key: &str) -> Option<Container> {
    let mut lines = private_key.lines().map(str::trim).filter(|line| !line.is_empty());
    if lines.next()? != BEGIN {
        return None;
    }
    let mut body = String::new();
    let mut ended = false;
    for line in lines {
        if ended {
            return None;
        }
        if line == END {
            ended = true;
        } else {
            body.push_str(line);
        }
    }
    if !ended {
        return None;
    }
    let bytes = Zeroizing::new(STANDARD.decode(body).ok()?);
    let mut reader = &bytes[..];
    let mut magic = [0u8; MAGIC.len()];
    reader.read(&mut magic).ok()?;
    if magic != MAGIC {
        return None;
    }
    let cipher = Cipher::decode(&mut reader).ok()?;
    let kdf = Kdf::decode(&mut reader).ok()?;
    if u32::decode(&mut reader).ok()? != 1 {
        return None;
    }
    let public = Vec::<u8>::decode(&mut reader).ok()?;
    let private = Zeroizing::new(Vec::<u8>::decode(&mut reader).ok()?);
    let tag = if cipher.has_tag() {
        let mut tag = [0u8; 16];
        reader.read(&mut tag).ok()?;
        Some(tag)
    } else {
        None
    };
    reader.is_finished().then_some(Container { cipher, kdf, public, private, tag })
}

/// 私鑰段明文(`checkint ×2, string 演算法, string 曲線, string 公鑰點, mpint 純量, string comment, padding`)裡的 ECDSA 純量比曲線的固定長度短,
/// 就補零、重算 padding(沒有加密的容器:8 的倍數),回傳新的私鑰段。不是 ECDSA、純量長度正常(`ssh-key` 自己讀得懂,或是真的太長)、格式不對都回 None。
/// `block_size` 是原本容器的 block 大小:padding 要少於一個 block(同 `ssh-key` 的檢查)。
fn repadded(section: &[u8], block_size: usize) -> Option<Zeroizing<Vec<u8>>> {
    let mut reader = section;
    let checkint1 = u32::decode(&mut reader).ok()?;
    let checkint2 = u32::decode(&mut reader).ok()?;
    let algorithm = String::decode(&mut reader).ok()?;
    let curve = String::decode(&mut reader).ok()?;
    let size = scalar_size(&algorithm, &curve)?;
    let point = Vec::<u8>::decode(&mut reader).ok()?;
    let scalar = Zeroizing::new(Vec::<u8>::decode(&mut reader).ok()?);
    let comment = String::decode(&mut reader).ok()?;
    let padding_is_valid = reader.len() < block_size && reader.iter().zip(1u8..).all(|(byte, expected)| *byte == expected);
    if !padding_is_valid || scalar.len() >= size {
        return None;
    }

    let mut padded = Zeroizing::new(vec![0u8; size]);
    padded[size - scalar.len()..].copy_from_slice(&scalar);
    let mut out = Zeroizing::new(Vec::new());
    checkint1.encode(&mut *out).ok()?;
    checkint2.encode(&mut *out).ok()?;
    algorithm.encode(&mut *out).ok()?;
    curve.encode(&mut *out).ok()?;
    point.encode(&mut *out).ok()?;
    padded.encode(&mut *out).ok()?;
    comment.encode(&mut *out).ok()?;
    let mut pad = 1u8;
    while out.len() % Cipher::None.block_size() != 0 {
        out.push(pad);
        pad += 1;
    }
    Some(out)
}

/// 把補好的私鑰段與原本的公鑰段包回沒有加密的 `openssh-key-v1` 容器,交給 `ssh-key` 讀。
fn read_unencrypted(public: &[u8], section: &[u8]) -> Option<PrivateKey> {
    let mut bytes = Zeroizing::new(MAGIC.to_vec());
    Cipher::None.encode(&mut *bytes).ok()?;
    Kdf::None.encode(&mut *bytes).ok()?;
    1u32.encode(&mut *bytes).ok()?;
    public.encode(&mut *bytes).ok()?;
    section.encode(&mut *bytes).ok()?;
    PrivateKey::from_bytes(&bytes).ok()
}

/// `ssh-key` 讀不懂的私鑰原文:沒有加密的 ECDSA 金鑰、純量短了,就補零後再讀一次。其他情況(加密的、不是 ECDSA 的、純量長度正常、格式不對)回 None,
/// 讓呼叫端維持原本的錯誤。
pub fn parse(private_key: &str) -> Option<PrivateKey> {
    let container = container(private_key)?;
    if container.cipher.is_some() {
        return None;
    }
    let section = repadded(&container.private, Cipher::None.block_size())?;
    read_unencrypted(&container.public, &section)
}

/// `ssh-key` 用這個 passphrase 解不開的加密私鑰:是 ECDSA 的就自己解密(`ssh-key` 公開的 `Kdf`、`Cipher`),純量短了就補零後再讀。passphrase 不對
/// (解出來的不是私鑰段)、沒有加密、不是 ECDSA(先看公鑰段,省下一次 bcrypt)、純量長度正常都回 None。
pub fn decrypt(private_key: &str, passphrase: &str) -> Option<PrivateKey> {
    let container = container(private_key)?;
    if container.cipher.is_none() || !KeyData::decode(&mut &container.public[..]).is_ok_and(|key| key.is_ecdsa()) {
        return None;
    }
    let (key, iv) = container.kdf.derive_key_and_iv(container.cipher, passphrase).ok()?;
    let mut plaintext = container.private;
    container.cipher.decrypt(&key, &iv, &mut plaintext, container.tag).ok()?;
    let section = repadded(&plaintext, container.cipher.block_size())?;
    read_unencrypted(&container.public, &section)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sync::slot_rules::test_keys;

    /// 測試金鑰的純量在原文裡真的短了(不然測的不是這個問題)。
    fn scalar_len(private_key: &str) -> usize {
        let container = container(private_key).unwrap();
        let mut reader = &container.private[..];
        for _ in 0..2 {
            u32::decode(&mut reader).unwrap();
        }
        for _ in 0..3 {
            Vec::<u8>::decode(&mut reader).unwrap();
        }
        Vec::<u8>::decode(&mut reader).unwrap().len()
    }

    #[test]
    fn a_short_scalar_is_padded_to_the_curve_and_the_rest_of_the_key_is_kept() {
        for (what, private, public, short, size) in [
            ("p256", test_keys::ecdsa_short_p256(), test_keys::ECDSA_SHORT_P256_PUBLIC, 31, 32),
            ("p384", test_keys::ecdsa_short_p384(), test_keys::ECDSA_SHORT_P384_PUBLIC, 47, 48),
            ("p521", test_keys::ecdsa_short_p521(), test_keys::ECDSA_SHORT_P521_PUBLIC, 65, 66),
        ] {
            assert_eq!(scalar_len(&private), short, "{what}: setup: the scalar lost a leading zero");
            assert!(PrivateKey::from_openssh(&private).is_err(), "{what}: setup: ssh-key 0.6.7 alone can't read it");
            let key = parse(&private).unwrap_or_else(|| panic!("{what}"));
            assert_eq!(key.public_key().key_data(), &ssh_key::PublicKey::from_openssh(public).unwrap().key_data().clone(), "{what}");
            let ssh_key::private::KeypairData::Ecdsa(keypair) = key.key_data() else { panic!("{what}: ecdsa") };
            let scalar = match keypair {
                ssh_key::private::EcdsaKeypair::NistP256 { private, .. } => private.as_slice().to_vec(),
                ssh_key::private::EcdsaKeypair::NistP384 { private, .. } => private.as_slice().to_vec(),
                ssh_key::private::EcdsaKeypair::NistP521 { private, .. } => private.as_slice().to_vec(),
            };
            assert_eq!(scalar.len(), size, "{what}");
            assert_eq!(scalar[0], 0, "{what}: the leading zero is back");
        }
        assert_eq!(parse(&test_keys::ecdsa_short_p256()).unwrap().comment(), "scratch-short-256");
    }

    #[test]
    fn keys_ssh_key_reads_or_rejects_for_other_reasons_are_left_alone() {
        assert!(parse(&test_keys::ecdsa()).is_none(), "a full-length scalar is ssh-key's to read");
        assert!(parse(&test_keys::plain()).is_none(), "not ECDSA");
        assert!(parse(&test_keys::rsa()).is_none(), "not ECDSA");
        assert!(parse(&test_keys::ecdsa_short_p256_encrypted()).is_none(), "encrypted: `decrypt` is the way in");
        assert!(parse("not a key").is_none());
        assert!(parse(&format!("{}\ntrailing", test_keys::ecdsa_short_p256())).is_none(), "text after the end line");
        assert!(parse(&test_keys::ecdsa_short_p256().replace("OPENSSH PRIVATE", "EC PRIVATE")).is_none());
    }

    #[test]
    fn an_encrypted_short_scalar_opens_with_the_right_passphrase_only() {
        let text = test_keys::ecdsa_short_p256_encrypted();
        assert_eq!(PrivateKey::from_openssh(&text).unwrap().decrypt("test-passphrase").err(), Some(ssh_key::Error::Encoding(ssh_encoding::Error::Length)), "setup: ssh-key 0.6.7 can't decrypt it");
        let key = decrypt(&text, "test-passphrase").unwrap();
        assert_eq!(key.public_key().key_data(), &ssh_key::PublicKey::from_openssh(test_keys::ECDSA_SHORT_P256_PUBLIC).unwrap().key_data().clone());
        assert!(!key.is_encrypted());
        assert!(decrypt(&text, "wrong").is_none());
        assert!(decrypt(&test_keys::ecdsa_short_p256(), "test-passphrase").is_none(), "not encrypted");
        assert!(decrypt(&test_keys::encrypted(), "test-passphrase").is_none(), "not ECDSA");
    }
}
