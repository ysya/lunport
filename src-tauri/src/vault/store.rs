//! 金鑰保管庫檔(key roadmap 第 2 階段 spec §4.1):這台電腦持有的私鑰,存在 `sync-state.json` 旁邊的 `vault.json`。每一筆以
//! XChaCha20-Poly1305 個別加密(AAD = `sshelter-vault-v1` + 換行 + 插槽 id),金鑰是 32 bytes 的隨機值,base64 存在系統 keychain 的
//! `vault:key`。私鑰原文原樣保存:有 passphrase 的仍是加密狀態(spec §5.5)。檔頭只有格式版本與這台的 agent 設定(不含祕密)。
//! 寫入一律原子、只有擁有者能讀寫(`slot_files::write_private`;Windows 是只給擁有者的 DACL)。

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, Zeroizing};

use crate::error::AppError;
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

/// 保管庫裡的一筆(解密之後)。`private_key` 是 OpenSSH 私鑰的原文;離開作用域時清掉。
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
    /// 保管庫檔裡有金鑰,keychain 裡卻沒有 `vault:key`:不產生新的(會讓既有的每一筆都解不開),保管庫停用(spec §11)。
    KeyMissing,
    /// 讀不懂的保管庫檔:已搬到同一個資料夾的 `kept_as`(搬不動是 None),之後從空的保管庫開始(spec §4.1)。
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
    let key: [u8; 32] = bytes.as_slice().try_into().map_err(|_| invalid_key())?;
    Ok(Some(Zeroizing::new(key)))
}

/// 讀不懂的檔案搬到同一個資料夾的 `vault.unreadable-<ms>.json`(同 Sync v2 對讀不懂的狀態檔的處理):之後的存檔寫到原路徑,不搬就會蓋掉它。
fn set_aside(path: &Path, now_ms: u64, reason: String) -> VaultError {
    let name = format!("vault.unreadable-{now_ms}.json");
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
    /// 開啟 `path` 的保管庫。檔案不存在 → 空的(什麼都不寫,金鑰也還不產生);有金鑰的檔案一定要 keychain 裡有 `vault:key`。
    pub fn open(path: &Path, keychain: &dyn Keychain, now_ms: u64) -> Result<Vault, VaultError> {
        let bytes = match std::fs::read(path) {
            Ok(bytes) => bytes,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Ok(Vault { path: path.to_path_buf(), key: None, file: VaultFile::default() });
            }
            Err(e) => return Err(VaultError::Other(AppError::Io(e))),
        };
        let file = match serde_json::from_slice::<VaultFile>(&bytes) {
            Ok(file) if file.version > VAULT_VERSION => return Err(VaultError::Newer { version: file.version }),
            Ok(file) => file,
            Err(e) => return Err(set_aside(path, now_ms, e.to_string())),
        };
        let key = read_key(keychain)?;
        if key.is_none() && !file.entries.is_empty() {
            return Err(VaultError::KeyMissing);
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
        let entry = serde_json::from_slice::<VaultEntry>(&plaintext)
            .map_err(|e| VaultError::Other(AppError::Other(format!("a vault entry is not readable: {e}"))))?;
        Ok(Some(entry))
    }

    /// 放進(或取代)一筆,立刻存檔。第一次存東西時才產生金鑰並寫進 keychain。
    pub fn put(&mut self, keychain: &dyn Keychain, slot_id: &str, entry: &VaultEntry) -> Result<(), VaultError> {
        let key = self.ensure_key(keychain)?;
        let plaintext = Zeroizing::new(
            serde_json::to_vec(entry).map_err(|e| VaultError::Other(AppError::Other(e.to_string())))?,
        );
        let (nonce, ciphertext) = seal_raw(&key, &aad(slot_id), &plaintext)?;
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

    fn ensure_key(&mut self, keychain: &dyn Keychain) -> Result<Zeroizing<[u8; 32]>, VaultError> {
        if let Some(key) = &self.key {
            return Ok(key.clone());
        }
        if let Some(key) = read_key(keychain)? {
            self.key = Some(key.clone());
            return Ok(key);
        }
        if !self.file.entries.is_empty() {
            return Err(VaultError::KeyMissing);
        }
        let mut key = Zeroizing::new([0u8; 32]);
        getrandom::fill(key.as_mut()).map_err(|e| VaultError::Other(AppError::Other(format!("cannot draw the vault key: {e}"))))?;
        let encoded = Zeroizing::new(B64.encode(key.as_ref()));
        keychain.set(VAULT_KEY_ACCOUNT, &encoded)?;
        self.key = Some(key.clone());
        Ok(key)
    }

    fn save(&self) -> Result<(), VaultError> {
        let bytes = serde_json::to_vec_pretty(&self.file).map_err(|e| VaultError::Other(AppError::Other(e.to_string())))?;
        if let Some(dir) = self.path.parent() {
            std::fs::create_dir_all(dir).map_err(|e| VaultError::Other(AppError::Io(e)))?;
        }
        slot_files::write_private(&self.path, &bytes)?;
        Ok(())
    }
}

/// 持有 `runtime.vault` 開啟保管庫並執行 `f`:同一個行程裡改動保管庫的地方都經過這裡,寫入不會互相蓋掉。
pub fn with_vault<T>(
    runtime: &SyncRuntime,
    path: &Path,
    keychain: &dyn Keychain,
    now_ms: u64,
    f: impl FnOnce(&mut Vault) -> Result<T, VaultError>,
) -> Result<T, VaultError> {
    let _guard = runtime.vault.lock().unwrap();
    let mut vault = Vault::open(path, keychain, now_ms)?;
    f(&mut vault)
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

        let reopened = Vault::open(&path, &keychain, 2).unwrap();
        assert_eq!(reopened.ids(), vec!["a".repeat(32)]);
        let got = reopened.get(&"a".repeat(32)).unwrap().unwrap();
        assert_eq!(got.private_key, test_keys::plain());
        assert_eq!(got.fingerprint, test_keys::PLAIN_FINGERPRINT);
        assert_eq!(got.origin, EntryOrigin::Synced);
        assert_eq!(reopened.get(&"b".repeat(32)).unwrap(), None);
    }

    #[test]
    fn a_missing_keychain_key_is_reported_and_never_replaced() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(VAULT_FILE);
        let keychain = MemKeychain::default();
        let mut vault = Vault::open(&path, &keychain, 1).unwrap();
        vault.put(&keychain, &"a".repeat(32), &entry(&test_keys::plain())).unwrap();

        let empty = MemKeychain::default();
        assert!(matches!(Vault::open(&path, &empty, 2), Err(VaultError::KeyMissing)));
        assert_eq!(empty.entry(VAULT_KEY_ACCOUNT), None, "no new key replaces the lost one");
        assert!(std::fs::read_to_string(&path).unwrap().contains(&"a".repeat(32)), "the file is untouched");
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

    #[test]
    fn the_vault_file_sits_beside_the_sync_state_file() {
        let state = Path::new("data").join("sync-state.json");
        assert_eq!(vault_path(&state), Path::new("data").join(VAULT_FILE));
    }
}
