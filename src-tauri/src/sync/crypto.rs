//! 助記詞與加密。安全模型見 spec §2/§4: 助記詞是唯一祕密, 所有派生值可重算。

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use bip39::{Language, Mnemonic};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::Sha256;

use crate::error::AppError;

const HKDF_SALT: &[u8] = b"sshelter-sync-v1";
const NONCE_LEN: usize = 24;

/// 從助記詞派生出的一組 chain 金鑰。`enc_key` 不公開: 只能透過 `seal`/`open` 使用。
#[derive(Clone)]
pub struct ChainKeys {
    /// 可公開的 chain 識別(hex)。
    pub chain_id: String,
    /// 中繼的 bearer token(hex); 中繼只存它的 SHA-256。
    pub auth_token: String,
    enc_key: [u8; 32],
}

impl std::fmt::Debug for ChainKeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // 絕不印出 enc_key 或 token。
        f.debug_struct("ChainKeys").field("chain_id", &self.chain_id).finish_non_exhaustive()
    }
}

/// 24 個英文字的 BIP39 助記詞(256-bit entropy)。
pub fn generate_mnemonic() -> Result<String, AppError> {
    let m = Mnemonic::generate_in(Language::English, 24)
        .map_err(|e| AppError::Other(format!("cannot generate recovery words: {e}")))?;
    Ok(m.to_string())
}

/// 正規化使用者輸入: 小寫、單一空白; 字數與 BIP39 checksum 不對就拒絕。
pub fn normalize_mnemonic(input: &str) -> Result<String, AppError> {
    let words: Vec<String> = input.split_whitespace().map(|w| w.to_lowercase()).collect();
    if words.len() != 24 {
        return Err(AppError::Other(format!(
            "recovery phrase must be 24 words (got {})",
            words.len()
        )));
    }
    let joined = words.join(" ");
    Mnemonic::parse_in(Language::English, &joined)
        .map_err(|e| AppError::Other(format!("invalid recovery phrase: {e}")))?;
    Ok(joined)
}

fn hkdf_expand(hk: &Hkdf<Sha256>, info: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    hk.expand(info, &mut out).expect("32 bytes is a valid HKDF-SHA256 output length");
    out
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// 助記詞 → seed(BIP39, 空 passphrase) → HKDF 三個用途分離的 32-byte 值。
pub fn derive_keys(mnemonic: &str) -> Result<ChainKeys, AppError> {
    let normalized = normalize_mnemonic(mnemonic)?;
    let m = Mnemonic::parse_in(Language::English, &normalized)
        .map_err(|e| AppError::Other(format!("invalid recovery phrase: {e}")))?;
    let seed = m.to_seed("");
    let hk = Hkdf::<Sha256>::new(Some(HKDF_SALT), &seed);
    Ok(ChainKeys {
        chain_id: hex(&hkdf_expand(&hk, b"sshelter/v1/chain-id")),
        auth_token: hex(&hkdf_expand(&hk, b"sshelter/v1/auth")),
        enc_key: hkdf_expand(&hk, b"sshelter/v1/enc"),
    })
}

/// 中繼看到的記錄識別: HMAC-SHA256(enc_key, kind || "\n" || id), 連 alias 都不外洩。
pub fn id_hash(keys: &ChainKeys, kind: &str, id: &str) -> String {
    // `chacha20poly1305::aead::KeyInit` 與 `hmac::Mac` 都提供 `new_from_slice`;
    // 不指名 trait 會是 E0034(multiple applicable items in scope)。
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(&keys.enc_key)
        .expect("HMAC accepts any key length");
    mac.update(kind.as_bytes());
    mac.update(b"\n");
    mac.update(id.as_bytes());
    hex(&mac.finalize().into_bytes())
}

/// 加密後的記錄本體。`id_hash` 是中繼看到的識別; nonce/ciphertext 為 base64。
#[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct Sealed {
    pub id_hash: String,
    pub nonce: String,
    pub ciphertext: String,
}

/// AAD 綁 chain 與 id_hash(不是明文 id): 接收端只有 id_hash 也能驗證。
fn aad(keys: &ChainKeys, kind: &str, id_hash: &str) -> Vec<u8> {
    format!("{}\n{}\n{}", keys.chain_id, kind, id_hash).into_bytes()
}

pub fn seal(keys: &ChainKeys, kind: &str, id: &str, plaintext: &[u8]) -> Result<Sealed, AppError> {
    let mut nonce = [0u8; NONCE_LEN];
    getrandom::fill(&mut nonce).map_err(|e| AppError::Other(format!("cannot draw nonce: {e}")))?;
    let hash = id_hash(keys, kind, id);
    let cipher = XChaCha20Poly1305::new(Key::from_slice(&keys.enc_key));
    let aad = aad(keys, kind, &hash);
    let ciphertext = cipher
        .encrypt(XNonce::from_slice(&nonce), Payload { msg: plaintext, aad: &aad })
        .map_err(|_| AppError::Other("encryption failed".to_string()))?;
    Ok(Sealed {
        id_hash: hash,
        nonce: B64.encode(nonce),
        ciphertext: B64.encode(ciphertext),
    })
}

pub fn open(keys: &ChainKeys, kind: &str, id_hash: &str, sealed: &Sealed) -> Result<Vec<u8>, AppError> {
    let nonce = B64
        .decode(&sealed.nonce)
        .map_err(|_| AppError::Other("record nonce is not valid base64".to_string()))?;
    if nonce.len() != NONCE_LEN {
        return Err(AppError::Other("record nonce has the wrong length".to_string()));
    }
    let ciphertext = B64
        .decode(&sealed.ciphertext)
        .map_err(|_| AppError::Other("record ciphertext is not valid base64".to_string()))?;
    let cipher = XChaCha20Poly1305::new(Key::from_slice(&keys.enc_key));
    let aad = aad(keys, kind, id_hash);
    cipher
        .decrypt(XNonce::from_slice(&nonce), Payload { msg: &ciphertext, aad: &aad })
        .map_err(|_| AppError::Other("record cannot be decrypted with this chain".to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    const WORDS: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art";

    #[test]
    fn generated_mnemonic_has_24_valid_words() {
        let words = generate_mnemonic().unwrap();
        assert_eq!(words.split_whitespace().count(), 24);
        assert_eq!(normalize_mnemonic(&words).unwrap(), words);
    }

    #[test]
    fn normalize_accepts_messy_input_and_rejects_bad_words() {
        let messy = format!("  {}\n", WORDS.to_uppercase().replace(' ', "   "));
        assert_eq!(normalize_mnemonic(&messy).unwrap(), WORDS);
        assert!(normalize_mnemonic("abandon abandon").is_err());
        let bad = WORDS.replacen("art", "zzzz", 1);
        assert!(normalize_mnemonic(&bad).is_err());
        let wrong_checksum = WORDS.replacen("art", "abandon", 1);
        assert!(normalize_mnemonic(&wrong_checksum).is_err());
    }

    #[test]
    fn derivation_is_deterministic_and_domain_separated() {
        let a = derive_keys(WORDS).unwrap();
        let b = derive_keys(WORDS).unwrap();
        assert_eq!(a.chain_id, b.chain_id);
        assert_eq!(a.auth_token, b.auth_token);
        assert_eq!(a.chain_id.len(), 64);
        assert_eq!(a.auth_token.len(), 64);
        assert_ne!(a.chain_id, a.auth_token);
        let other = generate_mnemonic().unwrap();
        assert_ne!(derive_keys(&other).unwrap().chain_id, a.chain_id);
    }

    #[test]
    fn derivation_matches_pinned_vectors() {
        // spec §4 的已知答案向量(PBKDF2-HMAC-SHA512 → HKDF-SHA256 → hex)。
        // 改了 salt、info、分隔符或編碼,這裡就會炸 —— 這是互通性的護欄,不得更新數值遷就實作。
        let keys = derive_keys(WORDS).unwrap();
        assert_eq!(keys.chain_id, "4eb6631d45882eb3a0c2541383de4263fc056a1bc851718d66d2f664ae77bf4c");
        assert_eq!(keys.auth_token, "8bef1a101b57ae1888a071b3e559b4253eb06572ff4fd021b5ef1ab97747e543");
        assert_eq!(
            id_hash(&keys, "host", "web-1"),
            "41fc9eb6d727b31a34350586bcee7619a7983fd8d695e7bebde44e51e937113a"
        );
    }

    #[test]
    fn id_hash_hides_the_id_but_is_stable() {
        let keys = derive_keys(WORDS).unwrap();
        let h1 = id_hash(&keys, "host", "web-1");
        assert_eq!(h1, id_hash(&keys, "host", "web-1"));
        assert_ne!(h1, id_hash(&keys, "key", "web-1"));
        assert_eq!(h1.len(), 64);
        assert!(!h1.contains("web"));
    }

    #[test]
    fn seal_open_round_trip_and_aad_binding() {
        let keys = derive_keys(WORDS).unwrap();
        let sealed = seal(&keys, "host", "web-1", b"Host web-1\n  HostName 10.0.0.9\n").unwrap();
        assert_eq!(sealed.id_hash, id_hash(&keys, "host", "web-1"));
        assert_eq!(
            open(&keys, "host", &sealed.id_hash, &sealed).unwrap(),
            b"Host web-1\n  HostName 10.0.0.9\n"
        );
        // 同一密文換 id_hash / kind 都要失敗(AAD 綁定)。
        assert!(open(&keys, "host", &id_hash(&keys, "host", "db-1"), &sealed).is_err());
        assert!(open(&keys, "key", &sealed.id_hash, &sealed).is_err());
        // 別的 chain 開不了。
        let other = derive_keys(&generate_mnemonic().unwrap()).unwrap();
        assert!(open(&other, "host", &sealed.id_hash, &sealed).is_err());
        // 每次 nonce 不同。
        let again = seal(&keys, "host", "web-1", b"x").unwrap();
        assert_ne!(again.nonce, sealed.nonce);
    }

    #[test]
    fn open_rejects_corrupt_base64() {
        let keys = derive_keys(WORDS).unwrap();
        let sealed = Sealed { id_hash: "00".repeat(32), nonce: "!!".to_string(), ciphertext: "!!".to_string() };
        assert!(open(&keys, "host", &sealed.id_hash, &sealed).is_err());
    }
}
