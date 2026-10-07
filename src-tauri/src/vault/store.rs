//! 金鑰保管庫檔(key roadmap 第 2 階段 spec §4.1):這台電腦持有的私鑰,存在 `sync-state.json` 旁邊的 `vault.json`。每一筆以
//! XChaCha20-Poly1305 個別加密(AAD = `sshelter-vault-v1` + 換行 + 插槽 id),金鑰是 32 bytes 的隨機值,base64 存在系統 keychain 的
//! `vault:key`。私鑰原文原樣保存:有 passphrase 的仍是加密狀態(spec §5.5)。檔頭只有格式版本與這台的 agent 設定(不含祕密)。
//! 寫入一律原子(`slot_files::write_private`:暫存檔 → rename)、只有擁有者能讀寫:Unix 的暫存檔先設 0600 再寫;Windows 的暫存檔繼承資料夾的權限,
//! rename 之後才設成只給擁有者的 DACL(檔案裡只有密文與不含祕密的檔頭,這段空檔可以接受)。

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, Zeroizing};

use crate::error::AppError;
use crate::fsutil;
use crate::sync::crypto::{open_raw, seal_raw};
use crate::sync::env::Keychain;
use crate::sync::runtime::SyncRuntime;
use crate::sync::slot_files;

pub const VAULT_FILE: &str = "vault.json";
pub const VAULT_KEY_ACCOUNT: &str = "vault:key";
/// 記住核准的預設時間(分鐘;spec §5.3)。
pub const DEFAULT_REMEMBER_MINUTES: u32 = 240;
const VAULT_VERSION: u32 = 1;
const AAD_PREFIX: &str = "sshelter-vault-v1";

/// 保管庫檔的路徑:和 `sync-state.json` 同一個資料夾。
pub fn vault_path(state_path: &Path) -> PathBuf {
    state_path.with_file_name(VAULT_FILE)
}

/// 這筆私鑰從哪裡來(spec §4.1):在這台產生、從檔案匯入、或從帳戶同步來。補寫帳戶裡的 `key`(SP3 §6.6)時,只有同步來的才不必這台的同意。
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EntryOrigin {
    Generated,
    Imported,
    Synced,
}

/// 保管庫裡的一筆(解密之後)。`private_key` 是 OpenSSH 私鑰的原文;整筆離開作用域時,這個 `String` 會清零,但 serde 在序列化與反序列化的
/// 途中可能留下暫時的副本,那些清不到(盡力而為)。
#[derive(Clone, PartialEq, Serialize, Deserialize)]
pub struct VaultEntry {
    pub private_key: String,
    pub public_key: String,
    pub fingerprint: String,
    pub origin: EntryOrigin,
    pub added_at_ms: u64,
}

impl std::fmt::Debug for VaultEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VaultEntry")
            .field("fingerprint", &self.fingerprint)
            .field("origin", &self.origin)
            .finish_non_exhaustive()
    }
}

impl Drop for VaultEntry {
    fn drop(&mut self) {
        self.private_key.zeroize();
    }
}

fn default_remember_minutes() -> u32 {
    DEFAULT_REMEMBER_MINUTES
}

/// 這台電腦的 agent 設定(spec §4.3,只能比每把金鑰的設定更嚴):記住核准多久、這台一律每次都問。
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentSettings {
    #[serde(default = "default_remember_minutes")]
    pub remember_minutes: u32,
    #[serde(default)]
    pub always_ask: bool,
}

impl Default for AgentSettings {
    fn default() -> Self {
        Self { remember_minutes: DEFAULT_REMEMBER_MINUTES, always_ask: false }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct SealedEntry {
    nonce: String,
    ciphertext: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct VaultFile {
    version: u32,
    #[serde(default)]
    settings: AgentSettings,
    #[serde(default)]
    entries: BTreeMap<String, SealedEntry>,
}

impl Default for VaultFile {
    fn default() -> Self {
        Self { version: VAULT_VERSION, settings: AgentSettings::default(), entries: BTreeMap::new() }
    }
}

#[derive(Debug)]
pub enum VaultError {
    /// 防禦用:已開啟的保管庫有項目卻沒有金鑰(`get`、`put`)。`open` 之後不會發生:有項目卻缺金鑰的檔案在 `open` 就搬到旁邊了,回的是 `Unreadable`。
    KeyMissing,
    /// 讀不懂、或有項目卻缺 keychain 的 `vault:key` 的保管庫檔:已搬到同一個資料夾的 `kept_as`(搬不動是 None),之後從空的保管庫開始(spec §4.1、§11)。
    Unreadable { kept_as: Option<String>, reason: String },
    /// 更新版 SSHelter 寫的格式:原地不動,保管庫停用。
    Newer { version: u32 },
    Other(AppError),
}

impl std::fmt::Display for VaultError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            VaultError::KeyMissing => write!(f, "the vault's key is missing from the keychain, so its keys can't be opened"),
            VaultError::Unreadable { kept_as: Some(name), reason } => {
                write!(f, "the vault file was unreadable ({reason}); it was kept as {name}")
            }
            VaultError::Unreadable { kept_as: None, reason } => write!(f, "the vault file is unreadable ({reason})"),
            VaultError::Newer { version } => write!(f, "the vault was written by a newer SSHelter (format {version})"),
            VaultError::Other(e) => write!(f, "{e}"),
        }
    }
}

impl From<AppError> for VaultError {
    fn from(e: AppError) -> Self {
        VaultError::Other(e)
    }
}

impl From<VaultError> for AppError {
    fn from(e: VaultError) -> Self {
        match e {
            VaultError::Other(inner) => inner,
            other => AppError::Other(other.to_string()),
        }
    }
}

fn aad(slot_id: &str) -> Vec<u8> {
    format!("{AAD_PREFIX}\n{slot_id}").into_bytes()
}

fn invalid_key() -> VaultError {
    VaultError::Other(AppError::Other("the vault key in the keychain is not valid".to_string()))
}

fn read_key(keychain: &dyn Keychain) -> Result<Option<Zeroizing<[u8; 32]>>, VaultError> {
    let Some(text) = keychain.get(VAULT_KEY_ACCOUNT)? else { return Ok(None) };
    let text = Zeroizing::new(text);
    let bytes = Zeroizing::new(B64.decode(text.as_bytes()).map_err(|_| invalid_key())?);
    if bytes.len() != 32 {
        return Err(invalid_key());
    }
    // 直接在 `Zeroizing` 裡填,不經過一份沒人清的 `[u8; 32]`。
    let mut key = Zeroizing::new([0u8; 32]);
    key.copy_from_slice(&bytes);
    Ok(Some(key))
}

/// 檔案的 `version`。只看這個欄位:新版的檔案結構可能讀不進這一版的型別,不該因此被當成讀不懂的檔案搬走(同 `state_v2::state_version`)。
fn file_version(bytes: &[u8]) -> Result<u32, serde_json::Error> {
    #[derive(Deserialize)]
    struct Probe {
        version: u32,
    }
    serde_json::from_slice::<Probe>(bytes).map(|probe| probe.version)
}

/// 不能用的檔案搬到同一個資料夾的 `vault.<kind>-<ms>.json`(`kind`:`unreadable` 是讀不懂、`keyless` 是金鑰不見;同 Sync v2 對讀不懂的狀態檔的處理):
/// 之後的存檔寫到原路徑,不搬就會蓋掉它。`rename` 會取代已經存在的目標,所以先找第一個沒人用的名字(`-1`、`-2`……),先前保留的那一份不會被蓋掉。
fn set_aside(path: &Path, kind: &str, now_ms: u64, reason: String) -> VaultError {
    let mut name = format!("vault.{kind}-{now_ms}.json");
    let mut n = 0u32;
    // `symlink_metadata`:連懸空的 symlink 也算已經有東西在那個名字上。
    while std::fs::symlink_metadata(path.with_file_name(&name)).is_ok() {
        n += 1;
        name = format!("vault.{kind}-{now_ms}-{n}.json");
    }
    match std::fs::rename(path, path.with_file_name(&name)) {
        Ok(()) => VaultError::Unreadable { kept_as: Some(name), reason },
        Err(_) => VaultError::Unreadable { kept_as: None, reason },
    }
}

/// 開著的保管庫。改動(`put`、`remove`、`set_settings`)立刻寫回檔案;同一個行程裡的寫入要經 `with_vault` 互斥。
pub struct Vault {
    path: PathBuf,
    key: Option<Zeroizing<[u8; 32]>>,
    file: VaultFile,
}

/// 只列路徑與插槽 id,不印出金鑰與密文(`derive(Debug)` 會把 `Zeroizing` 裡的 32 bytes 印出來)。
impl std::fmt::Debug for Vault {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Vault").field("path", &self.path).field("ids", &self.ids()).finish_non_exhaustive()
    }
}

impl Vault {
    /// 開啟 `path` 的保管庫。檔案不存在 → 空的(什麼都不寫,金鑰也還不產生)。先只看 `version`:比本 app 新的格式原地不動,回 `Newer`。
    /// 讀不懂的檔案、或有項目卻缺 keychain 的 `vault:key` 的檔案(spec §11)不覆寫,搬到旁邊(`vault.unreadable-<ms>.json`、`vault.keyless-<ms>.json`)並回
    /// `Unreadable`;下一次開啟從空的保管庫開始,第一次 `put` 才產生新的金鑰。keychain 讀取出錯(可能只是暫時鎖著)或存的值不是 32 bytes 的 base64
    /// 時回 `Other`,什麼都不搬。
    pub fn open(path: &Path, keychain: &dyn Keychain, now_ms: u64) -> Result<Vault, VaultError> {
        let bytes = match std::fs::read(path) {
            Ok(bytes) => bytes,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Ok(Vault { path: path.to_path_buf(), key: None, file: VaultFile::default() });
            }
            Err(e) => return Err(VaultError::Other(AppError::Io(e))),
        };
        match file_version(&bytes) {
            Ok(version) if version > VAULT_VERSION => return Err(VaultError::Newer { version }),
            Ok(_) => {}
            Err(e) => return Err(set_aside(path, "unreadable", now_ms, e.to_string())),
        }
        let file = match serde_json::from_slice::<VaultFile>(&bytes) {
            Ok(file) => file,
            Err(e) => return Err(set_aside(path, "unreadable", now_ms, e.to_string())),
        };
        let key = read_key(keychain)?;
        if key.is_none() && !file.entries.is_empty() {
            return Err(set_aside(path, "keyless", now_ms, "the vault's key is missing from the keychain".to_string()));
        }
        Ok(Vault { path: path.to_path_buf(), key, file })
    }

    /// 保管庫裡的插槽 id(排序過)。
    pub fn ids(&self) -> Vec<String> {
        self.file.entries.keys().cloned().collect()
    }

    pub fn get(&self, slot_id: &str) -> Result<Option<VaultEntry>, VaultError> {
        let Some(sealed) = self.file.entries.get(slot_id) else { return Ok(None) };
        let key = self.key.as_ref().ok_or(VaultError::KeyMissing)?;
        let plaintext = Zeroizing::new(open_raw(key, &aad(slot_id), &sealed.nonce, &sealed.ciphertext)?);
        // 不帶 serde_json 的訊息:它會把出問題的字串值原文放進去(`invalid type: string "…"`),那可能就是私鑰。
        let entry = serde_json::from_slice::<VaultEntry>(&plaintext)
            .map_err(|_| VaultError::Other(AppError::Other("a vault entry is not readable".to_string())))?;
        Ok(Some(entry))
    }

    /// 放進(或取代)一筆,立刻存檔。第一次存東西時才產生金鑰並寫進 keychain。
    pub fn put(&mut self, keychain: &dyn Keychain, slot_id: &str, entry: &VaultEntry) -> Result<(), VaultError> {
        self.ensure_key(keychain)?;
        let key = self.key.as_ref().ok_or(VaultError::KeyMissing)?;
        let plaintext = Zeroizing::new(
            serde_json::to_vec(entry).map_err(|e| VaultError::Other(AppError::Other(e.to_string())))?,
        );
        let (nonce, ciphertext) = seal_raw(key, &aad(slot_id), &plaintext)?;
        self.file.entries.insert(slot_id.to_string(), SealedEntry { nonce, ciphertext });
        self.save()
    }

    /// 拿掉一筆並存檔;回傳原本有沒有。
    pub fn remove(&mut self, slot_id: &str) -> Result<bool, VaultError> {
        if self.file.entries.remove(slot_id).is_none() {
            return Ok(false);
        }
        self.save()?;
        Ok(true)
    }

    pub fn settings(&self) -> &AgentSettings {
        &self.file.settings
    }

    pub fn set_settings(&mut self, settings: AgentSettings) -> Result<(), VaultError> {
        self.file.settings = settings;
        self.save()
    }

    /// 確保 `self.key` 有值(已有、keychain 裡有、或第一次存東西時新產生並寫進 keychain),金鑰留在 `self.key`,不再複製出去。
    fn ensure_key(&mut self, keychain: &dyn Keychain) -> Result<(), VaultError> {
        if self.key.is_some() {
            return Ok(());
        }
        if let Some(key) = read_key(keychain)? {
            self.key = Some(key);
            return Ok(());
        }
        if !self.file.entries.is_empty() {
            return Err(VaultError::KeyMissing);
        }
        let mut key = Zeroizing::new([0u8; 32]);
        getrandom::fill(key.as_mut()).map_err(|e| VaultError::Other(AppError::Other(format!("cannot draw the vault key: {e}"))))?;
        let encoded = Zeroizing::new(B64.encode(key.as_ref()));
        keychain.set(VAULT_KEY_ACCOUNT, &encoded)?;
        self.key = Some(key);
        Ok(())
    }

    fn save(&self) -> Result<(), VaultError> {
        let bytes = serde_json::to_vec_pretty(&self.file).map_err(|e| VaultError::Other(AppError::Other(e.to_string())))?;
        let dir = self.path.parent();
        if let Some(dir) = dir {
            // 資料夾不存在才建立,而且只有擁有者能進去(Unix 0700;同 `state_v2::save`);已經存在的不動。
            fsutil::ensure_dir_secure(dir)?;
        }
        slot_files::write_private(&self.path, &bytes)?;
        // 盡力而為:rename 只改了資料夾裡的項目,把資料夾也 fsync,斷電之後新的檔案才一定在(同 `fsutil::atomic_write`);失敗不影響結果。
        #[cfg(unix)]
        {
            if let Some(dir) = dir {
                let _ = std::fs::File::open(dir).and_then(|d| d.sync_all());
            }
        }
        Ok(())
    }
}

/// 持有 `runtime.vault` 開啟保管庫並執行 `f`:同一個行程裡改動保管庫的地方都經過這裡,寫入不會互相蓋掉。鎖只護著 `()`,沒有狀態會因為先前某次 panic 而不一致,
/// 所以被毒化(poisoned)的鎖照常取用,不讓一次 panic 之後保管庫永遠打不開。
pub fn with_vault<T>(
    runtime: &SyncRuntime,
    path: &Path,
    keychain: &dyn Keychain,
    now_ms: u64,
    f: impl FnOnce(&mut Vault) -> Result<T, VaultError>,
) -> Result<T, VaultError> {
    let _guard = runtime.vault.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    let mut vault = Vault::open(path, keychain, now_ms)?;
    f(&mut vault)
}

/// 保管庫檔裡的插槽 id。不讀 keychain、不搬任何檔案:同步的每一輪用它確認「只在 SSHelter」的插槽還在保管庫裡(金鑰保管庫 spec §11)。
/// 檔案不存在 → 空的;讀不懂 → `Unreadable { kept_as: None, .. }`;更新版的格式 → `Newer`。
pub fn stored_ids(path: &Path) -> Result<BTreeSet<String>, VaultError> {
    let bytes = match std::fs::read(path) {
        Ok(bytes) => bytes,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(BTreeSet::new()),
        Err(e) => return Err(VaultError::Other(AppError::Io(e))),
    };
    let unreadable = |e: serde_json::Error| VaultError::Unreadable { kept_as: None, reason: e.to_string() };
    let version = file_version(&bytes).map_err(unreadable)?;
    if version > VAULT_VERSION {
        return Err(VaultError::Newer { version });
    }
    let file = serde_json::from_slice::<VaultFile>(&bytes).map_err(unreadable)?;
    Ok(file.entries.keys().cloned().collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sync::runtime::SyncRuntime;
    use crate::sync::slot_rules::test_keys;
    use crate::sync::testkit::MemKeychain;

    fn entry(text: &str) -> VaultEntry {
        VaultEntry {
            private_key: text.to_string(),
            public_key: test_keys::PLAIN_PUBLIC.to_string(),
            fingerprint: test_keys::PLAIN_FINGERPRINT.to_string(),
            origin: EntryOrigin::Synced,
            added_at_ms: 5,
        }
    }

    #[test]
    fn an_absent_vault_opens_empty_and_writes_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(VAULT_FILE);
        let keychain = MemKeychain::default();
        let vault = Vault::open(&path, &keychain, 1).unwrap();
        assert!(vault.ids().is_empty());
        assert_eq!(vault.settings(), &AgentSettings::default());
        assert!(!path.exists(), "nothing is written until something is stored");
        assert_eq!(keychain.entry(VAULT_KEY_ACCOUNT), None, "no key is drawn until something is stored");
    }

    #[test]
    fn entries_round_trip_and_the_file_never_holds_the_private_key() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(VAULT_FILE);
        let keychain = MemKeychain::default();
        let mut vault = Vault::open(&path, &keychain, 1).unwrap();
        vault.put(&keychain, "a".repeat(32).as_str(), &entry(&test_keys::plain())).unwrap();

        let text = std::fs::read_to_string(&path).unwrap();
        assert!(!text.contains(test_keys::PLAIN_BODY[1]), "the file holds no private key text");
        assert!(!text.contains("PRIVATE KEY"));
        assert!(keychain.entry(VAULT_KEY_ACCOUNT).is_some(), "the key lives in the keychain");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600, "only the owner can read the vault file");
        }

        let reopened = Vault::open(&path, &keychain, 2).unwrap();
        assert_eq!(reopened.ids(), vec!["a".repeat(32)]);
        let got = reopened.get(&"a".repeat(32)).unwrap().unwrap();
        assert_eq!(got.private_key, test_keys::plain());
        assert_eq!(got.fingerprint, test_keys::PLAIN_FINGERPRINT);
        assert_eq!(got.origin, EntryOrigin::Synced);
        assert_eq!(reopened.get(&"b".repeat(32)).unwrap(), None);
    }

    #[test]
    fn a_missing_keychain_key_sets_the_file_aside_and_the_next_put_starts_fresh() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(VAULT_FILE);
        let keychain = MemKeychain::default();
        let mut vault = Vault::open(&path, &keychain, 1).unwrap();
        vault.put(&keychain, &"a".repeat(32), &entry(&test_keys::plain())).unwrap();
        let original = std::fs::read(&path).unwrap();

        // 鑰匙圈裡的 `vault:key` 不見了:舊檔搬到旁邊保留(spec §11),不蓋掉、也不留在原處讓之後的存檔蓋掉。
        let empty = MemKeychain::default();
        match Vault::open(&path, &empty, 2) {
            Err(VaultError::Unreadable { kept_as: Some(name), reason }) => {
                assert_eq!(name, "vault.keyless-2.json");
                assert_eq!(reason, "the vault's key is missing from the keychain");
            }
            other => panic!("expected Unreadable, got {other:?}"),
        }
        assert_eq!(empty.entry(VAULT_KEY_ACCOUNT), None, "opening never draws a replacement key");
        assert!(!path.exists(), "vault.json is gone, so nothing can overwrite the old entries");
        assert_eq!(std::fs::read(dir.path().join("vault.keyless-2.json")).unwrap(), original, "the kept file has the original bytes");

        // 下一次 `put` 從空的保管庫開始、產生新的金鑰,讀得回來。
        let mut fresh = Vault::open(&path, &empty, 3).unwrap();
        assert!(fresh.ids().is_empty());
        fresh.put(&empty, &"b".repeat(32), &entry(&test_keys::plain())).unwrap();
        assert!(empty.entry(VAULT_KEY_ACCOUNT).is_some(), "the first put drew a new key");
        let got = Vault::open(&path, &empty, 4).unwrap().get(&"b".repeat(32)).unwrap().unwrap();
        assert_eq!(got.private_key, test_keys::plain());
    }

    #[test]
    fn a_locked_or_malformed_keychain_key_moves_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(VAULT_FILE);
        let keychain = MemKeychain::default();
        let mut vault = Vault::open(&path, &keychain, 1).unwrap();
        vault.put(&keychain, &"a".repeat(32), &entry(&test_keys::plain())).unwrap();
        let original = std::fs::read(&path).unwrap();

        // 鑰匙圈暫時鎖著(讀取出錯)不是「金鑰不見」:檔案留在原處。
        keychain.fail_reads.store(true, std::sync::atomic::Ordering::SeqCst);
        assert!(matches!(Vault::open(&path, &keychain, 2), Err(VaultError::Other(_))));
        keychain.fail_reads.store(false, std::sync::atomic::Ordering::SeqCst);
        // 存的值不是 32 bytes 的 base64:一樣只回錯誤、不動檔案。
        let short = B64.encode([1u8; 16]);
        for bad in ["not base64!", short.as_str()] {
            let broken = MemKeychain::default();
            broken.set(VAULT_KEY_ACCOUNT, bad).unwrap();
            assert!(matches!(Vault::open(&path, &broken, 3), Err(VaultError::Other(_))), "{bad}");
        }
        assert_eq!(std::fs::read(&path).unwrap(), original);
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 1, "nothing was set aside");
        assert_eq!(Vault::open(&path, &keychain, 4).unwrap().ids(), vec!["a".repeat(32)], "it opens once the keychain answers");
    }

    #[test]
    fn a_key_already_in_the_keychain_is_reused_not_replaced() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(VAULT_FILE);
        let keychain = MemKeychain::default();
        let stored = B64.encode([9u8; 32]);
        keychain.set(VAULT_KEY_ACCOUNT, &stored).unwrap();
        let mut vault = Vault::open(&path, &keychain, 1).unwrap();
        vault.put(&keychain, &"a".repeat(32), &entry(&test_keys::plain())).unwrap();
        assert_eq!(keychain.entry(VAULT_KEY_ACCOUNT), Some(stored), "the stored key stays");
        let got = Vault::open(&path, &keychain, 2).unwrap().get(&"a".repeat(32)).unwrap().unwrap();
        assert_eq!(got.private_key, test_keys::plain());
    }

    #[test]
    fn an_entry_copied_under_another_slot_id_does_not_open() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(VAULT_FILE);
        let keychain = MemKeychain::default();
        let mut vault = Vault::open(&path, &keychain, 1).unwrap();
        vault.put(&keychain, &"a".repeat(32), &entry(&test_keys::plain())).unwrap();
        let mut file: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        let sealed = file["entries"][&"a".repeat(32)].clone();
        file["entries"][&"b".repeat(32)] = sealed;
        std::fs::write(&path, serde_json::to_vec(&file).unwrap()).unwrap();

        let reopened = Vault::open(&path, &keychain, 2).unwrap();
        assert!(reopened.get(&"b".repeat(32)).is_err(), "the AAD binds each entry to its slot id");
    }

    /// 解密之後讀不懂的一筆(格式對不上):錯誤只說讀不懂,不帶 serde_json 的訊息 —— 它會把出問題的字串值原文放進去,那可能就是私鑰。
    #[test]
    fn an_entry_in_the_wrong_shape_is_reported_without_quoting_it() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(VAULT_FILE);
        let keychain = MemKeychain::default();
        let slot = "a".repeat(32);
        let mut vault = Vault::open(&path, &keychain, 1).unwrap();
        vault.put(&keychain, &slot, &entry(&test_keys::plain())).unwrap();
        let key: [u8; 32] = B64.decode(keychain.entry(VAULT_KEY_ACCOUNT).unwrap()).unwrap().try_into().unwrap();

        // 兩種 serde_json 會引用值的錯誤:型別不對(`invalid type: string "…"`)與不認得的列舉值(`unknown variant `…``)。
        let wrong_shapes = [
            br#"{"private_key":"k","public_key":"p","fingerprint":"f","origin":"synced","added_at_ms":"TOP-SECRET-TEXT"}"#.as_slice(),
            br#"{"private_key":"k","public_key":"p","fingerprint":"f","origin":"TOP-SECRET-TEXT","added_at_ms":5}"#.as_slice(),
        ];
        for plaintext in wrong_shapes {
            let (nonce, ciphertext) = seal_raw(&key, &aad(&slot), plaintext).unwrap();
            let mut file: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
            file["entries"][&slot] = serde_json::json!({ "nonce": nonce, "ciphertext": ciphertext });
            std::fs::write(&path, serde_json::to_vec(&file).unwrap()).unwrap();

            let error = Vault::open(&path, &keychain, 2).unwrap().get(&slot).unwrap_err();
            let shown = error.to_string();
            assert!(!shown.contains("TOP-SECRET-TEXT"), "the error quotes the entry: {shown}");
            assert_eq!(shown, "a vault entry is not readable");
            assert!(!format!("{error:?}").contains("TOP-SECRET-TEXT"), "nor does its Debug form");
        }
    }

    #[test]
    fn an_unreadable_file_is_set_aside_and_a_newer_one_is_left_alone() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(VAULT_FILE);
        let keychain = MemKeychain::default();
        std::fs::write(&path, b"{ not json").unwrap();
        match Vault::open(&path, &keychain, 77) {
            Err(VaultError::Unreadable { kept_as: Some(name), .. }) => {
                assert_eq!(name, "vault.unreadable-77.json");
                assert!(dir.path().join(&name).exists());
            }
            other => panic!("expected Unreadable, got {other:?}"),
        }
        assert!(!path.exists());
        assert!(Vault::open(&path, &keychain, 78).unwrap().ids().is_empty(), "the next open starts empty");

        std::fs::write(&path, br#"{"version": 99, "entries": {}}"#).unwrap();
        assert!(matches!(Vault::open(&path, &keychain, 79), Err(VaultError::Newer { version: 99 })));
        assert!(path.exists(), "a file from a newer SSHelter is never moved");
    }

    #[test]
    fn a_newer_file_in_another_shape_stays_where_it_is() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(VAULT_FILE);
        let keychain = MemKeychain::default();
        // 這裡的 `entries` 是陣列,v1 的型別讀不進去:只有 `version` 決定它算不算更新的格式。
        let original = br#"{"version": 2, "entries": []}"#;
        std::fs::write(&path, original).unwrap();
        assert!(matches!(Vault::open(&path, &keychain, 5), Err(VaultError::Newer { version: 2 })));
        assert_eq!(std::fs::read(&path).unwrap(), original.to_vec(), "the file is untouched");
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 1, "nothing was set aside");
    }

    #[test]
    fn setting_aside_in_the_same_millisecond_keeps_every_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(VAULT_FILE);
        let keychain = MemKeychain::default();
        let texts = ["{ first", "{ second", "{ third"];
        let mut names = Vec::new();
        for text in texts {
            std::fs::write(&path, text).unwrap();
            match Vault::open(&path, &keychain, 9) {
                Err(VaultError::Unreadable { kept_as: Some(name), .. }) => names.push(name),
                other => panic!("expected Unreadable, got {other:?}"),
            }
        }
        assert_eq!(names, ["vault.unreadable-9.json", "vault.unreadable-9-1.json", "vault.unreadable-9-2.json"]);
        for (name, text) in names.iter().zip(texts) {
            assert_eq!(std::fs::read_to_string(dir.path().join(name)).unwrap(), text, "{name} keeps its own bytes");
        }
    }

    #[test]
    fn settings_have_defaults_and_persist() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(VAULT_FILE);
        let keychain = MemKeychain::default();
        let mut vault = Vault::open(&path, &keychain, 1).unwrap();
        assert_eq!(vault.settings().remember_minutes, DEFAULT_REMEMBER_MINUTES);
        vault.set_settings(AgentSettings { remember_minutes: 60, always_ask: true }).unwrap();
        let reopened = Vault::open(&path, &keychain, 2).unwrap();
        assert_eq!(reopened.settings(), &AgentSettings { remember_minutes: 60, always_ask: true });
    }

    #[test]
    fn remove_drops_an_entry_and_reports_whether_it_was_there() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(VAULT_FILE);
        let keychain = MemKeychain::default();
        let mut vault = Vault::open(&path, &keychain, 1).unwrap();
        vault.put(&keychain, &"a".repeat(32), &entry(&test_keys::plain())).unwrap();
        assert!(vault.remove(&"a".repeat(32)).unwrap());
        assert!(!vault.remove(&"a".repeat(32)).unwrap());
        assert!(Vault::open(&path, &keychain, 2).unwrap().ids().is_empty());
    }

    #[test]
    fn with_vault_holds_the_runtime_lock_while_it_runs() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(VAULT_FILE);
        let keychain = MemKeychain::default();
        let runtime = SyncRuntime::default();
        with_vault(&runtime, &path, &keychain, 1, |vault| {
            assert!(runtime.vault.try_lock().is_err(), "held during the closure");
            vault.put(&keychain, &"a".repeat(32), &entry(&test_keys::plain()))
        })
        .unwrap();
        assert!(runtime.vault.try_lock().is_ok(), "released afterwards");
    }

    #[test]
    fn a_poisoned_lock_does_not_break_the_vault() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(VAULT_FILE);
        let keychain = MemKeychain::default();
        let runtime = SyncRuntime::default();
        let panicked = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _ = with_vault(&runtime, &path, &keychain, 1, |_vault| -> Result<(), VaultError> {
                panic!("a panic while the vault lock is held")
            });
        }));
        assert!(panicked.is_err());
        assert!(runtime.vault.is_poisoned(), "the panic poisoned the lock");
        // 鎖只護著 `()`,沒有什麼狀態會因為上一次的 panic 而不一致:照常開得起來、寫得進去。
        with_vault(&runtime, &path, &keychain, 2, |vault| vault.put(&keychain, &"a".repeat(32), &entry(&test_keys::plain()))).unwrap();
        assert_eq!(Vault::open(&path, &keychain, 3).unwrap().ids(), vec!["a".repeat(32)]);
    }

    #[cfg(unix)]
    #[test]
    fn a_new_vault_folder_is_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let folder = dir.path().join("data");
        let path = folder.join(VAULT_FILE);
        let keychain = MemKeychain::default();
        let mut vault = Vault::open(&path, &keychain, 1).unwrap();
        vault.put(&keychain, &"a".repeat(32), &entry(&test_keys::plain())).unwrap();
        assert_eq!(std::fs::metadata(&folder).unwrap().permissions().mode() & 0o777, 0o700, "created owner-only");
        assert_eq!(Vault::open(&path, &keychain, 2).unwrap().ids(), vec!["a".repeat(32)]);
    }

    #[test]
    fn the_debug_output_hides_the_private_key() {
        let shown = format!("{:?}", entry(&test_keys::plain()));
        assert!(!shown.contains("PRIVATE KEY"));
        assert!(shown.contains(test_keys::PLAIN_FINGERPRINT));
    }

    #[test]
    fn the_vault_debug_output_hides_the_key_and_the_sealed_entries() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(VAULT_FILE);
        let keychain = MemKeychain::default();
        let mut vault = Vault::open(&path, &keychain, 1).unwrap();
        vault.put(&keychain, &"a".repeat(32), &entry(&test_keys::plain())).unwrap();
        let key = B64.decode(keychain.entry(VAULT_KEY_ACCOUNT).unwrap()).unwrap();
        let shown = format!("{vault:?}");
        assert!(shown.contains(&"a".repeat(32)), "the slot ids are listed");
        assert!(!shown.contains(&format!("{key:?}")), "the key bytes are not printed");
        assert!(!shown.contains("ciphertext"), "the sealed entries are not printed");
    }

    /// 同步的每一輪只看保管庫裡有哪些插槽 id(`stored_ids`):不讀 keychain,讀不懂、更新版的檔案都只回錯誤,檔案留在原處。
    #[test]
    fn stored_ids_reads_only_the_ids_and_never_moves_the_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(VAULT_FILE);
        assert!(stored_ids(&path).unwrap().is_empty(), "a missing file holds nothing");

        let keychain = MemKeychain::default();
        let mut vault = Vault::open(&path, &keychain, 1).unwrap();
        vault.put(&keychain, &"a".repeat(32), &entry(&test_keys::plain())).unwrap();
        vault.put(&keychain, &"b".repeat(32), &entry(&test_keys::plain())).unwrap();
        // 鑰匙圈鎖著也一樣讀得到:`stored_ids` 不開任何一筆。
        keychain.fail_reads.store(true, std::sync::atomic::Ordering::SeqCst);
        assert_eq!(stored_ids(&path).unwrap(), BTreeSet::from(["a".repeat(32), "b".repeat(32)]));

        std::fs::write(&path, b"{ not json").unwrap();
        assert!(matches!(stored_ids(&path), Err(VaultError::Unreadable { kept_as: None, .. })));
        assert_eq!(std::fs::read(&path).unwrap(), b"{ not json".to_vec(), "the unreadable file stays where it is");
        std::fs::write(&path, br#"{"version": 99, "entries": {}}"#).unwrap();
        assert!(matches!(stored_ids(&path), Err(VaultError::Newer { version: 99 })));
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 1, "nothing was set aside");
    }

    #[test]
    fn the_vault_file_sits_beside_the_sync_state_file() {
        let state = Path::new("data").join("sync-state.json");
        assert_eq!(vault_path(&state), Path::new("data").join(VAULT_FILE));
    }
}
