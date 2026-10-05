//! v1 的本機同步狀態(`sync-state.json` 的 `version: 1` 格式):只用來讀取並升級(Sync v2 spec §7.6;讀檔在
//! `state_v2::load`)。另有兩版共用的狀態檔路徑、內建 relay 與同步碼的 keychain account。

use std::collections::BTreeMap;
use std::path::PathBuf;

use serde::Deserialize;
#[cfg(test)]
use serde::Serialize;

use crate::error::AppError;
use crate::fsutil;
use crate::sync::record::{Envelope, LocalRecord};
#[cfg(test)]
use crate::sync::record::SCHEMA_VERSION;

/// 只有測試用(`SyncState::fresh`):升級讀 v1 狀態檔,版本號由 `state_v2::load` 判斷。
#[cfg(test)]
pub const STATE_VERSION: u32 = 1;

/// 內建中繼:建置時由 CI 以 `SSHELTER_RELAY_URL` 注入。沒設定、或設成空字串(GitHub Actions 對未設定的
/// repository variable 會給空字串)時分兩種模式:debug 建置退回本機 `wrangler dev`(開發用);release 建置
/// **沒有內建中繼**(空字串)—— 需要同步的使用者在 Settings → Sync 自行填入中繼網址,填好之前不能 Create/Join。
pub const DEFAULT_RELAY_URL: &str = default_relay_url(option_env!("SSHELTER_RELAY_URL"), cfg!(debug_assertions));

const LOCAL_RELAY_URL: &str = "http://127.0.0.1:8787";

const fn default_relay_url(injected: Option<&'static str>, debug: bool) -> &'static str {
    match injected {
        Some(url) if !url.is_empty() => url,
        _ if debug => LOCAL_RELAY_URL,
        _ => "",
    }
}

pub const MNEMONIC_ACCOUNT: &str = "sync:mnemonic";

/// v1 狀態檔的內容,**只讀**:升級(`upgrade::upgrade_v1`)與啟動(`engine::startup`,`joined`)讀它。建構(`fresh`)、`read_only` 與序列化只有測試用 ——
/// v2 不寫 v1 格式,v1 的狀態檔升級時原樣複製成備份(`state_v2::back_up_legacy`)。
#[derive(Clone, Debug, PartialEq, Deserialize)]
#[cfg_attr(test, derive(Serialize))]
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
    #[cfg(test)]
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

    /// chain 用了比本 app 新的格式:只套用可理解的記錄、不上傳(spec §10)。只有測試用:升級讀的是狀態檔裡的欄位,v2 的唯讀判斷在 `SyncStateV2::read_only`。
    #[cfg(test)]
    pub fn read_only(&self) -> bool {
        self.remote_schema_version.is_some_and(|v| v > SCHEMA_VERSION)
    }
}

pub fn state_path() -> Result<PathBuf, AppError> {
    Ok(fsutil::app_data_root()?.join("sync-state.json"))
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
    fn an_injected_relay_url_is_the_default_in_every_build() {
        assert_eq!(default_relay_url(Some("https://relay.example.com"), false), "https://relay.example.com");
        assert_eq!(default_relay_url(Some("https://relay.example.com"), true), "https://relay.example.com");
    }

    #[test]
    fn without_an_injected_relay_debug_builds_use_the_local_relay_and_release_builds_have_none() {
        // 沒設定與空字串(GitHub Actions 對未設定的 repository variable 給的值)一樣處理。
        for injected in [None, Some("")] {
            assert_eq!(default_relay_url(injected, true), "http://127.0.0.1:8787");
            assert_eq!(default_relay_url(injected, false), "", "release builds ask the user for a relay");
        }
    }
}
