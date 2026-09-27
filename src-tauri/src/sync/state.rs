//! 本機同步狀態(`sync-state.json`,0600)與助記詞的 keychain 保管。
//! 助記詞永不落成純文字檔;派生值只在記憶體。

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::error::AppError;
use crate::fsutil;
use crate::secrets;
use crate::sync::record::{Envelope, LocalRecord, SCHEMA_VERSION};

pub const STATE_VERSION: u32 = 1;

/// 建置時由 CI 以 `SSHELTER_RELAY_URL` 注入正式中繼;沒設定、或設成空字串(GitHub Actions 對未設定的
/// repository variable 會給空字串)都退回本機 `wrangler dev`。
pub const DEFAULT_RELAY_URL: &str = relay_url_or_default(option_env!("SSHELTER_RELAY_URL"));

const LOCAL_RELAY_URL: &str = "http://127.0.0.1:8787";

const fn relay_url_or_default(injected: Option<&'static str>) -> &'static str {
    match injected {
        Some(url) if !url.is_empty() => url,
        _ => LOCAL_RELAY_URL,
    }
}

pub const MNEMONIC_ACCOUNT: &str = "sync:mnemonic";

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct SyncState {
    pub version: u32,
    /// None = 尚未建立/加入 chain。
    pub chain_id: Option<String>,
    pub device_id: String,
    pub device_name: String,
    pub relay_url: String,
    /// 已套用到本機的最大中繼序號。
    pub cursor_seq: u64,
    /// 本機是否參與密碼同步(Phase B 使用;A 只持久化)。
    pub password_sync: bool,
    /// chain 的 `meta.schema_version`(收到後持久化);比 `SCHEMA_VERSION` 新 → 唯讀模式。
    #[serde(default)]
    pub remote_schema_version: Option<u32>,
    /// 剛 Join 後 false:第一輪是「以 chain 為準」的基線輪,不做本機 diff(spec §6);Create 的 chain 是空的,直接 true。
    #[serde(default)]
    pub baseline_established: bool,
    /// Leave 時 keychain 裡的助記詞刪不掉:持久化這個待辦,重啟後仍顯示警示與重試。
    #[serde(default)]
    pub phrase_cleanup_pending: bool,
    /// 明文快取,key = `record_key(kind, id)`;只放本版會處理的種類(host/device/meta)。
    pub records: BTreeMap<String, LocalRecord>,
    /// 本版不處理的種類(key/password/未知 kind)的原始密文 envelope,key = `"{kind}:{id_hash}"`。
    /// 絕不解密進這裡:祕密只能落在 keychain 或 `~/.ssh/<name>`(spec §2)。
    #[serde(default)]
    pub sealed: BTreeMap<String, Envelope>,
    pub last_sync_ms: Option<u64>,
    pub last_error: Option<String>,
}

impl SyncState {
    pub fn fresh(device_name: &str) -> Result<Self, AppError> {
        let mut bytes = [0u8; 16];
        getrandom::fill(&mut bytes)
            .map_err(|e| AppError::Other(format!("cannot create device id: {e}")))?;
        Ok(Self {
            version: STATE_VERSION,
            chain_id: None,
            device_id: bytes.iter().map(|b| format!("{b:02x}")).collect(),
            device_name: device_name.to_string(),
            relay_url: DEFAULT_RELAY_URL.to_string(),
            cursor_seq: 0,
            password_sync: false,
            remote_schema_version: None,
            baseline_established: false,
            phrase_cleanup_pending: false,
            records: BTreeMap::new(),
            sealed: BTreeMap::new(),
            last_sync_ms: None,
            last_error: None,
        })
    }

    pub fn joined(&self) -> bool {
        self.chain_id.is_some()
    }

    /// chain 用了比本 app 新的格式:只套用可理解的記錄、不上傳(spec §10)。
    pub fn read_only(&self) -> bool {
        self.remote_schema_version.is_some_and(|v| v > SCHEMA_VERSION)
    }
}

pub fn state_path() -> Result<PathBuf, AppError> {
    Ok(fsutil::app_data_root()?.join("sync-state.json"))
}

pub fn load(path: &Path) -> Result<Option<SyncState>, AppError> {
    let bytes = match std::fs::read(path) {
        Ok(b) => b,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(AppError::Io(e)),
    };
    // 先只看版本,避免新版欄位讓整個反序列化失敗時給出誤導訊息。
    #[derive(Deserialize)]
    struct Probe {
        version: u32,
    }
    let probe: Probe = serde_json::from_slice(&bytes)
        .map_err(|e| AppError::Other(format!("sync state is unreadable: {e}")))?;
    if probe.version > STATE_VERSION {
        return Err(AppError::Other(format!(
            "sync state was written by a newer SSHelter (version {}); update the app",
            probe.version
        )));
    }
    let state: SyncState = serde_json::from_slice(&bytes)
        .map_err(|e| AppError::Other(format!("sync state is unreadable: {e}")))?;
    Ok(Some(state))
}

pub fn save(path: &Path, state: &SyncState) -> Result<(), AppError> {
    if let Some(dir) = path.parent() {
        fsutil::ensure_dir_secure(dir)?;
    }
    let bytes = serde_json::to_vec_pretty(state)
        .map_err(|e| AppError::Other(format!("cannot serialize sync state: {e}")))?;
    fsutil::atomic_write(path, &bytes, 0o600)
}

pub fn store_mnemonic(words: &str) -> Result<(), AppError> {
    secrets::set(MNEMONIC_ACCOUNT, words)
}

pub fn load_mnemonic() -> Result<Option<String>, AppError> {
    secrets::get(MNEMONIC_ACCOUNT)
}

pub fn clear_mnemonic() -> Result<(), AppError> {
    secrets::delete(MNEMONIC_ACCOUNT)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fresh_state_is_not_joined_and_has_a_device_id() {
        let s = SyncState::fresh("MacBook").unwrap();
        assert!(!s.joined());
        assert!(!s.read_only());
        assert_eq!(s.device_id.len(), 32);
        assert_eq!(s.device_name, "MacBook");
        assert_eq!(s.version, STATE_VERSION);
        assert_eq!(s.relay_url, DEFAULT_RELAY_URL);
        assert!(s.sealed.is_empty());
        assert!(!s.baseline_established);
        assert!(!s.phrase_cleanup_pending);
    }

    #[test]
    fn read_only_follows_the_persisted_remote_schema_version() {
        let mut s = SyncState::fresh("A").unwrap();
        s.remote_schema_version = Some(SCHEMA_VERSION);
        assert!(!s.read_only());
        s.remote_schema_version = Some(SCHEMA_VERSION + 1);
        assert!(s.read_only());
    }

    #[test]
    fn sealed_envelopes_survive_save_and_load_without_being_decoded() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("sync-state.json");
        let mut s = SyncState::fresh("A").unwrap();
        s.sealed.insert(
            "password:ff".to_string(),
            Envelope { id_hash: "ff".into(), kind: "password".into(), seq: 4, nonce: "n".into(), ciphertext: "c".into(), deleted: false },
        );
        save(&path, &s).unwrap();
        let text = std::fs::read_to_string(&path).unwrap();
        assert!(text.contains("\"ciphertext\": \"c\""), "envelope is stored verbatim: {text}");
        assert_eq!(load(&path).unwrap().unwrap().sealed, s.sealed);
    }

    #[test]
    fn save_then_load_round_trips() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("sync-state.json");
        let mut s = SyncState::fresh("A").unwrap();
        s.chain_id = Some("ab".repeat(32));
        s.cursor_seq = 7;
        save(&path, &s).unwrap();
        let back = load(&path).unwrap().expect("state exists");
        assert_eq!(back, s);
        assert!(back.joined());
    }

    #[test]
    fn missing_file_means_not_joined() {
        let dir = tempfile::tempdir().unwrap();
        assert!(load(&dir.path().join("nope.json")).unwrap().is_none());
    }

    #[test]
    fn corrupt_or_newer_state_is_an_error_not_a_panic() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("sync-state.json");
        std::fs::write(&path, b"{ not json").unwrap();
        assert!(load(&path).is_err());
        std::fs::write(&path, format!("{{\"version\": {} }}", STATE_VERSION + 1)).unwrap();
        let err = load(&path).unwrap_err();
        assert!(err.to_string().contains("newer"), "got: {err}");
    }

    #[cfg(unix)]
    #[test]
    fn state_file_is_private() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("sync-state.json");
        save(&path, &SyncState::fresh("A").unwrap()).unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }

    #[test]
    fn empty_or_missing_injected_relay_url_falls_back_to_local() {
        assert_eq!(relay_url_or_default(None), "http://127.0.0.1:8787");
        assert_eq!(relay_url_or_default(Some("")), "http://127.0.0.1:8787");
        assert_eq!(relay_url_or_default(Some("https://relay.example.com")), "https://relay.example.com");
    }
}
