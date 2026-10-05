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
/// v2 帳戶與 space0 的 HKDF salt(spec §5.1)。
const HKDF_SALT_V2: &[u8] = b"sshelter-sync-v2";
const NONCE_LEN: usize = 24;

/// 一組 chain 金鑰。v1、帳戶與 space0 由助記詞推導;新建的 space 由 `generate` 隨機產生,或以 `from_parts` 由 `spacekey`
/// 記錄的欄位重建。`enc_key` 不公開:只經 `seal`/`open`/`id_hash` 使用,唯一的匯出口是 `enc_key_b64`(只用來寫 `spacekey` 記錄)。
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
        .map_err(|e| AppError::Other(format!("cannot generate a sync code: {e}")))?;
    Ok(m.to_string())
}

/// 正規化使用者輸入: 小寫、單一空白; 字數與 BIP39 checksum 不對就拒絕。
pub fn normalize_mnemonic(input: &str) -> Result<String, AppError> {
    let words: Vec<String> = input.split_whitespace().map(|w| w.to_lowercase()).collect();
    if words.len() != 24 {
        return Err(AppError::Other(format!("a sync code has 24 words (got {})", words.len())));
    }
    let joined = words.join(" ");
    Mnemonic::parse_in(Language::English, &joined).map_err(|e| AppError::Other(format!("invalid sync code: {e}")))?;
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

/// 助記詞 → seed(BIP39 英文 24 詞、空 passphrase,64 bytes;v1 §4 與 v2 §5.1 相同)。
fn seed_of(mnemonic: &str) -> Result<[u8; 64], AppError> {
    let normalized = normalize_mnemonic(mnemonic)?;
    let m = Mnemonic::parse_in(Language::English, &normalized)
        .map_err(|e| AppError::Other(format!("invalid sync code: {e}")))?;
    Ok(m.to_seed(""))
}

/// 同一個 PRK 展開一組 chain 金鑰:info = `{prefix}/chain-id`、`{prefix}/auth`、`{prefix}/enc`(全 ASCII)。
fn chain_keys(hk: &Hkdf<Sha256>, prefix: &str) -> ChainKeys {
    ChainKeys {
        chain_id: hex(&hkdf_expand(hk, format!("{prefix}/chain-id").as_bytes())),
        auth_token: hex(&hkdf_expand(hk, format!("{prefix}/auth").as_bytes())),
        enc_key: hkdf_expand(hk, format!("{prefix}/enc").as_bytes()),
    }
}

/// 助記詞 → seed(BIP39, 空 passphrase) → HKDF 三個用途分離的 32-byte 值。
pub fn derive_keys(mnemonic: &str) -> Result<ChainKeys, AppError> {
    let seed = seed_of(mnemonic)?;
    Ok(chain_keys(&Hkdf::<Sha256>::new(Some(HKDF_SALT), &seed), "sshelter/v1"))
}

/// v2 帳戶 chain(spec §5.1):位置、權杖、金鑰都由同步碼推導。salt 與 v1 不同,所以同一組同步碼的 v1 chain
/// 與帳戶 chain 互不相關。
pub fn derive_account(mnemonic: &str) -> Result<ChainKeys, AppError> {
    let seed = seed_of(mnemonic)?;
    Ok(chain_keys(&Hkdf::<Sha256>::new(Some(HKDF_SALT_V2), &seed), "sshelter/v2/account"))
}

/// v1 升級建立的第一個 space(spec §5.1、§5.2):推導值讓兩台同時升級的電腦建出同一個 space(同一個 chain id、
/// 同一把金鑰)。之後新建的 space 一律用 `ChainKeys::generate`。
pub fn derive_space0(mnemonic: &str) -> Result<ChainKeys, AppError> {
    let seed = seed_of(mnemonic)?;
    Ok(chain_keys(&Hkdf::<Sha256>::new(Some(HKDF_SALT_V2), &seed), "sshelter/v2/space0"))
}

/// chain id 與權杖的格式:64 字元小寫 hex(relay 只接受這個格式)。space id 就是 space 的 chain id,也用它檢查。
pub fn is_chain_id(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

impl ChainKeys {
    /// 新建 space 的位置、權杖與金鑰(spec §5.1):各 32 bytes 的 OS CSPRNG 隨機值,不由同步碼推導。
    pub fn generate() -> Result<Self, AppError> {
        let mut bytes = [0u8; 96];
        getrandom::fill(&mut bytes).map_err(|e| AppError::Other(format!("cannot draw random space keys: {e}")))?;
        let mut enc_key = [0u8; 32];
        enc_key.copy_from_slice(&bytes[64..]);
        Ok(Self { chain_id: hex(&bytes[..32]), auth_token: hex(&bytes[32..64]), enc_key })
    }

    /// 由 `spacekey` 記錄的欄位重建(spec §4.1):chain id 與權杖必須是 64 字元小寫 hex,金鑰是 32 bytes 的標準
    /// base64。記錄來自帳戶裡的其他裝置:格式不對就拒絕 —— chain id 之後會被組進 URL 與檔名。
    pub fn from_parts(chain_id: &str, auth_token: &str, enc_key_b64: &str) -> Result<Self, AppError> {
        if !is_chain_id(chain_id) || !is_chain_id(auth_token) {
            return Err(AppError::Other("space key record has a malformed chain id or token".to_string()));
        }
        let malformed_key = || AppError::Other("space key record has a malformed key".to_string());
        let key = B64.decode(enc_key_b64).map_err(|_| malformed_key())?;
        let enc_key: [u8; 32] = key.try_into().map_err(|_| malformed_key())?;
        Ok(Self { chain_id: chain_id.to_string(), auth_token: auth_token.to_string(), enc_key })
    }

    /// `enc_key` 的標準 base64。只寫進以帳戶金鑰加密的 `spacekey` 記錄(spec §4.1),絕不進 log 或狀態檔明文。
    pub fn enc_key_b64(&self) -> String {
        B64.encode(self.enc_key)
    }
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
        // UI 一律稱「sync code」:錯誤訊息也是。
        assert_eq!(normalize_mnemonic("abandon abandon").unwrap_err().to_string(), "a sync code has 24 words (got 2)");
        let bad = WORDS.replacen("art", "zzzz", 1);
        let err = normalize_mnemonic(&bad).unwrap_err().to_string();
        assert!(err.starts_with("invalid sync code: ") && !err.contains("zzzz"), "{err}");
        let wrong_checksum = WORDS.replacen("art", "abandon", 1);
        assert!(normalize_mnemonic(&wrong_checksum).unwrap_err().to_string().starts_with("invalid sync code: "));
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

    #[test]
    fn v2_derivation_matches_pinned_vectors() {
        // Sync v2 spec §5.4 的已知答案向量(PBKDF2-HMAC-SHA512 → HKDF-SHA256,salt "sshelter-sync-v2")。
        // 互通性的護欄:失敗時錯的是實作,不得更新數值遷就實作。
        let account = derive_account(WORDS).unwrap();
        assert_eq!(account.chain_id, "082945de8b6ccadf9733e9c3748fd20abf985b1d6383f5435e40d67de185a3b0");
        assert_eq!(account.auth_token, "ed4b3b81f2fbfde9301257b81d9dd8e6c645b294ef02b3604438f8eb2d4a8151");
        let space0 = derive_space0(WORDS).unwrap();
        assert_eq!(space0.chain_id, "5bd662442f3b55718252c1db03629cf93cf468716e58893929282d9a135c739d");
        assert_eq!(space0.auth_token, "2f851361bce6b438424c0da70fa750b65f6313cbf3c9fda83cd7d5b932b40e47");
        assert_eq!(
            id_hash(&account, "space", &space0.chain_id),
            "0a3ea2ee708cd088904ee4e3756d6af1316ae8f56ba14c8c1fd6249fc0b68150"
        );
        assert_eq!(
            id_hash(&space0, "host", "web-1"),
            "fc773d220b5c6c97c19239671b3ee3521046fbbc27946694dd00e702db208b09"
        );
        // space0 的 `spacekey` payload 由推導值決定(spec §5.2):兩台同時升級必須寫出相同的 enc_key。
        assert_eq!(space0.enc_key_b64(), "BeE35vhhIezzB5xj8JnzEC3AypnBSUfvLjZ72sp+4Nc=");
    }

    #[test]
    fn v2_chains_are_separate_from_v1_and_from_each_other() {
        let v1 = derive_keys(WORDS).unwrap();
        let account = derive_account(WORDS).unwrap();
        let space0 = derive_space0(WORDS).unwrap();
        let ids = [&v1.chain_id, &v1.auth_token, &account.chain_id, &account.auth_token, &space0.chain_id, &space0.auth_token];
        for (i, a) in ids.iter().enumerate() {
            assert!(is_chain_id(a), "{a} is 64 lowercase hex");
            for b in &ids[i + 1..] {
                assert_ne!(a, b);
            }
        }
        // 金鑰也各自獨立:同一個 (kind, id) 的 id_hash 都不同。
        assert_ne!(id_hash(&account, "host", "web-1"), id_hash(&space0, "host", "web-1"));
        assert_ne!(id_hash(&account, "host", "web-1"), id_hash(&v1, "host", "web-1"));
        // 輸入正規化與 v1 相同:大小寫與多餘空白不影響推導。
        let messy = format!("  {}\n", WORDS.to_uppercase().replace(' ', "  "));
        assert_eq!(derive_account(&messy).unwrap().chain_id, account.chain_id);
        assert!(derive_account("abandon abandon").is_err());
        assert!(derive_space0("abandon abandon").is_err());
    }

    #[test]
    fn generated_space_keys_are_random_well_formed_and_usable() {
        let a = ChainKeys::generate().unwrap();
        let b = ChainKeys::generate().unwrap();
        assert!(is_chain_id(&a.chain_id) && is_chain_id(&a.auth_token));
        assert_ne!(a.chain_id, a.auth_token);
        assert_ne!(a.chain_id, b.chain_id);
        assert_ne!(a.enc_key_b64(), b.enc_key_b64());
        // 三個值各自獨立:金鑰不得與 relay 看得到的 chain id、權杖共用位元組,權杖也要隨機。
        let key_hex = hex(&B64.decode(a.enc_key_b64()).unwrap());
        assert_ne!(key_hex, a.chain_id);
        assert_ne!(key_hex, a.auth_token);
        assert_ne!(a.auth_token, b.auth_token);
        // 記錄加密與 v1 相同,只是 (chain_id, 金鑰) 換成這個 space 的值(spec §5.3)。
        let sealed = seal(&a, "host", "web-1", b"Host web-1\n").unwrap();
        assert_eq!(open(&a, "host", &sealed.id_hash, &sealed).unwrap(), b"Host web-1\n");
        assert!(open(&b, "host", &sealed.id_hash, &sealed).is_err());
    }

    #[test]
    fn space_keys_round_trip_through_their_record_fields_and_reject_malformed_ones() {
        let keys = ChainKeys::generate().unwrap();
        let back = ChainKeys::from_parts(&keys.chain_id, &keys.auth_token, &keys.enc_key_b64()).unwrap();
        assert_eq!(back.chain_id, keys.chain_id);
        assert_eq!(back.auth_token, keys.auth_token);
        assert_eq!(id_hash(&back, "host", "web-1"), id_hash(&keys, "host", "web-1"));
        let key = keys.enc_key_b64();
        // chain id 會被組進 URL 與檔名:只接受 64 字元小寫 hex。
        assert!(ChainKeys::from_parts("../../v1/pull", &keys.auth_token, &key).is_err());
        assert!(ChainKeys::from_parts(&keys.chain_id.to_uppercase(), &keys.auth_token, &key).is_err());
        assert!(ChainKeys::from_parts(&keys.chain_id[..63], &keys.auth_token, &key).is_err());
        assert!(ChainKeys::from_parts(&keys.chain_id, "tok", &key).is_err());
        // 金鑰:必須是剛好 32 bytes 的標準 base64。
        assert!(ChainKeys::from_parts(&keys.chain_id, &keys.auth_token, "!!").is_err());
        assert!(ChainKeys::from_parts(&keys.chain_id, &keys.auth_token, &B64.encode([7u8; 16])).is_err());
        // 只收標準 base64(含 padding):URL-safe 字母表、少了 padding 都拒絕。
        let k = B64.encode([0xfbu8; 32]); // 標準字母表含 '+' '/'
        assert!(ChainKeys::from_parts(&keys.chain_id, &keys.auth_token, &k).is_ok());
        assert!(ChainKeys::from_parts(&keys.chain_id, &keys.auth_token, k.trim_end_matches('=')).is_err());
        assert!(ChainKeys::from_parts(&keys.chain_id, &keys.auth_token, &k.replace('+', "-").replace('/', "_")).is_err());
        assert!(!is_chain_id(""));
        assert!(!is_chain_id(&"g".repeat(64)));
    }

    #[test]
    fn chain_keys_debug_never_shows_the_token_or_key() {
        let keys = ChainKeys::generate().unwrap();
        let shown = format!("{keys:?}");
        assert!(shown.contains(&keys.chain_id));
        assert!(!shown.contains(&keys.auth_token));
        assert!(!shown.contains(&keys.enc_key_b64()));
    }
}
