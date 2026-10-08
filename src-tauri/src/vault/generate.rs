//! 在 SSHelter 裡產生金鑰(金鑰保管庫 spec §7.5「Generate key」):Ed25519(預設)、RSA 3072/4096、ECDSA P-256,可加 passphrase。
//! 用 `ssh-key` 產生(不跑 `ssh-keygen`),私鑰直接交給保管庫,不寫任何檔案。

use rand_core::OsRng;
use serde::{Deserialize, Serialize};
use ssh_key::private::{KeypairData, RsaKeypair};
use ssh_key::{Algorithm, EcdsaCurve, LineEnding, PrivateKey};
use zeroize::Zeroizing;

use crate::error::AppError;

/// 可以產生的金鑰種類。
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(test, derive(ts_rs::TS))]
#[cfg_attr(test, ts(export, export_to = "../../src/bindings/"))]
pub enum KeyAlgorithm {
    Ed25519,
    Rsa3072,
    Rsa4096,
    EcdsaP256,
}

/// 產生一把新的私鑰,回傳 OpenSSH 格式的原文(有 passphrase 就是加密的)。comment 在加密之前放:加密之後的 `PrivateKey` 不帶 comment
/// (它在加密的那一段裡)。passphrase 是空字串等於沒有。RSA 要幾秒,呼叫端不能在主執行緒上呼叫。
pub fn generate(algorithm: KeyAlgorithm, comment: &str, passphrase: Option<&str>) -> Result<Zeroizing<String>, AppError> {
    let failed = |e: ssh_key::Error| AppError::Other(format!("cannot generate the key: {e}"));
    let mut rng = OsRng;
    let mut key = match algorithm {
        KeyAlgorithm::Ed25519 => PrivateKey::random(&mut rng, Algorithm::Ed25519).map_err(failed)?,
        KeyAlgorithm::EcdsaP256 => PrivateKey::random(&mut rng, Algorithm::Ecdsa { curve: EcdsaCurve::NistP256 }).map_err(failed)?,
        KeyAlgorithm::Rsa3072 | KeyAlgorithm::Rsa4096 => {
            let bits = if algorithm == KeyAlgorithm::Rsa3072 { 3072 } else { 4096 };
            let pair = RsaKeypair::random(&mut rng, bits).map_err(failed)?;
            PrivateKey::new(KeypairData::from(pair), "").map_err(failed)?
        }
    };
    key.set_comment(comment);
    let key = match passphrase.filter(|p| !p.is_empty()) {
        Some(passphrase) => key.encrypt(&mut rng, passphrase).map_err(failed)?,
        None => key,
    };
    key.to_openssh(LineEnding::LF).map_err(failed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sync::slot_rules::inspect_private_key;

    /// 每一種都產生得出 agent 用得了的 OpenSSH 私鑰,類型對。
    #[test]
    fn each_kind_makes_a_key_the_agent_can_use() {
        for (algorithm, key_type) in [
            (KeyAlgorithm::Ed25519, "ssh-ed25519"),
            (KeyAlgorithm::EcdsaP256, "ecdsa-sha2-nistp256"),
            (KeyAlgorithm::Rsa3072, "ssh-rsa"),
        ] {
            let text = generate(algorithm, "me@laptop", None).unwrap();
            let facts = inspect_private_key(&text).unwrap();
            assert_eq!(facts.key_type, key_type);
            assert!(!facts.has_passphrase);
            assert!(crate::vault::material::agent_can_read(&text), "{key_type}");
        }
    }

    /// RSA 3072 就是 3072 位元(`PrivateKey::random` 的 RSA 一律是 4096,不能用它)。
    #[test]
    fn rsa_3072_has_3072_bits() {
        let text = generate(KeyAlgorithm::Rsa3072, "", None).unwrap();
        let key = ssh_key::PrivateKey::from_openssh(text.as_str()).unwrap();
        let rsa = key.public_key().key_data().rsa().expect("an RSA key");
        let modulus = rsa.n.as_positive_bytes().expect("a positive modulus");
        assert_eq!(modulus.len() * 8, 3072);
    }

    /// RSA 4096 就是 4096 位元。
    #[test]
    fn rsa_4096_has_4096_bits() {
        let text = generate(KeyAlgorithm::Rsa4096, "", None).unwrap();
        let key = ssh_key::PrivateKey::from_openssh(text.as_str()).unwrap();
        let rsa = key.public_key().key_data().rsa().expect("an RSA key");
        let modulus = rsa.n.as_positive_bytes().expect("a positive modulus");
        assert_eq!(modulus.len() * 8, 4096);
    }

    /// 產生的金鑰 agent 真的簽得了:走 agent 的簽章路徑(有 passphrase 的用它解開),簽出來的簽章驗得過。RSA 是 `ssh-key` 轉出來的金鑰,最需要這一關。
    #[test]
    fn a_generated_key_signs_what_the_agent_asks_it_to_sign() {
        use crate::vault::material::{open, SSH_AGENT_RSA_SHA2_256};
        use signature::Verifier;
        use ssh_encoding::Decode;
        for (algorithm, passphrase) in [(KeyAlgorithm::Ed25519, None), (KeyAlgorithm::EcdsaP256, None), (KeyAlgorithm::Rsa3072, Some("pw"))] {
            let text = generate(algorithm, "", passphrase).unwrap();
            let material = open(&text, passphrase).unwrap();
            let blob = material.sign(b"hello", SSH_AGENT_RSA_SHA2_256).unwrap();
            let signature = ssh_key::Signature::decode(&mut &blob[..]).unwrap();
            material.key_data().verify(b"hello", &signature).unwrap();
        }
    }

    /// 有 passphrase:私鑰是加密的,解得開,comment 還在(在加密之前放進去)。空字串等於沒有。
    #[test]
    fn a_passphrase_encrypts_the_key_and_keeps_its_comment() {
        let text = generate(KeyAlgorithm::Ed25519, "me@laptop", Some("correct horse")).unwrap();
        assert!(inspect_private_key(&text).unwrap().has_passphrase);
        let key = ssh_key::PrivateKey::from_openssh(text.as_str()).unwrap();
        assert!(key.decrypt("wrong").is_err());
        assert_eq!(key.decrypt("correct horse").unwrap().comment(), "me@laptop");

        let plain = generate(KeyAlgorithm::Ed25519, "me@laptop", Some("")).unwrap();
        assert!(!inspect_private_key(&plain).unwrap().has_passphrase);
        assert_eq!(ssh_key::PrivateKey::from_openssh(plain.as_str()).unwrap().comment(), "me@laptop");
    }
}
