//! 同步引擎與外界的邊界:app 狀態的鎖、`~/.ssh`、狀態檔路徑、keychain、relay、事件與時鐘。production 由
//! `AppHandle` 組出(`engine`),測試以暫存目錄、記憶體 keychain、假 relay 與記錄事件的替身組出(`testkit`)——
//! 引擎本身不碰 Tauri,多台裝置的情境因此能在同一個測試裡決定性地重現。

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::config::model::SshConfigDoc;
use crate::error::AppError;
use crate::sync::dto::{ApprovalNotice, SyncConflict};
use crate::sync::relay::{RelayApi, RelayClient};
use crate::sync::runtime::SyncRuntime;
use crate::sync::state_v2::SyncNotice;

/// OS keychain 的抽象(account 名稱見 `state::MNEMONIC_ACCOUNT`、`state_v2::NEXT_MNEMONIC_ACCOUNT`)。
pub trait Keychain: Send + Sync {
    fn get(&self, account: &str) -> Result<Option<String>, AppError>;
    fn set(&self, account: &str, secret: &str) -> Result<(), AppError>;
    /// 不存在也算成功(清理路徑要能重複執行)。
    fn delete(&self, account: &str) -> Result<(), AppError>;
}

/// 真正的 OS keychain(`secrets`)。
pub struct OsKeychain;

impl Keychain for OsKeychain {
    fn get(&self, account: &str) -> Result<Option<String>, AppError> {
        crate::secrets::get(account)
    }
    fn set(&self, account: &str, secret: &str) -> Result<(), AppError> {
        crate::secrets::set(account, secret)
    }
    fn delete(&self, account: &str) -> Result<(), AppError> {
        crate::secrets::delete(account)
    }
}

pub trait Clock: Send + Sync {
    fn now_ms(&self) -> u64;
}

pub struct SystemClock;

impl Clock for SystemClock {
    fn now_ms(&self) -> u64 {
        SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_millis() as u64).unwrap_or(0)
    }
}

/// 依 relay URL 建立 v2 client。**只能在同步執行緒或 `spawn_blocking` 裡呼叫**(`reqwest::blocking`)。
pub trait RelayConnector: Send + Sync {
    fn connect(&self, base_url: &str) -> Result<Box<dyn RelayApi>, AppError>;
}

pub struct HttpRelays;

impl RelayConnector for HttpRelays {
    fn connect(&self, base_url: &str) -> Result<Box<dyn RelayApi>, AppError> {
        Ok(Box::new(RelayClient::new(base_url)?))
    }
}

/// 引擎對外的通知。**呼叫端不得持有任何鎖**:production 會重建 tray(同步等待主執行緒)、組狀態、發 Tauri 事件。
/// 唯一的例外是 `wake`(見該方法)。
pub trait SyncEvents: Send + Sync {
    /// `sync://status`:狀態變了(production 自己組 `SyncOverview`)。
    fn status(&self);
    /// `sync://applied`:引擎寫了 space 檔或整份重載了 doc(`hosts` = 套用的主機數,重載為 0);production 也重建 tray。
    fn applied(&self, hosts: usize);
    fn conflict(&self, conflicts: &[SyncConflict]);
    fn approval(&self, waiting: &[ApprovalNotice]);
    /// `sync://notice`:新的提示(也存進 `SyncStateV2::notices`)。
    fn notice(&self, notice: &SyncNotice);
    /// 請背景執行緒立刻再跑一輪。**可以在持有 doc / backed_up 鎖時呼叫**:存檔 hook(`files::note_written`)由
    /// `persist_file` 的呼叫端在 doc 鎖內呼叫它。所以實作必須是不阻塞的送出 —— 不拿 app 狀態的鎖(doc / backed_up /
    /// core)、不等主執行緒、不碰 Tauri(`engine::wake` 就是這樣:對背景執行緒的 channel 送出)。
    fn wake(&self);
    /// 順便的喚醒(存檔 hook、視窗取得焦點):同 `wake`,但退避期間(被限流、relay 出錯、keychain 失敗之後,spec §6.4)要等到退避結束才開始一輪;
    /// 一樣可以在持有 doc / backed_up 鎖時呼叫,所以一樣必須是不阻塞的送出。不分得出差別的實作(測試的替身)當成一般的 `wake`。
    fn wake_implicit(&self) {
        self.wake();
    }
}

/// 引擎每個操作需要的一切。生命週期 `'a` 綁在 app 狀態(或測試的替身)上;用完即丟,不跨執行緒保存。
pub struct SyncEnv<'a> {
    pub doc: &'a Mutex<Option<SshConfigDoc>>,
    pub backed_up: &'a Mutex<HashSet<PathBuf>>,
    pub retention: &'a Mutex<Option<usize>>,
    pub runtime: &'a SyncRuntime,
    /// `~/.ssh`(space 檔在 `~/.ssh/sshelter/`)。
    pub ssh_dir: PathBuf,
    /// `sync-state.json` 的路徑。
    pub state_path: PathBuf,
    /// 只給測試:載入 doc 時 Include 的 `~` 指向這裡(`config::include::with_test_home`)。production 為 None。
    pub home: Option<PathBuf>,
    pub keychain: &'a dyn Keychain,
    pub relays: &'a dyn RelayConnector,
    pub events: &'a dyn SyncEvents,
    pub clock: &'a dyn Clock,
    /// `std::env::consts::OS`(裝置記錄的 platform)。
    pub platform: &'static str,
}

impl SyncEnv<'_> {
    pub fn now(&self) -> u64 {
        self.clock.now_ms()
    }

    pub fn retention(&self) -> Option<usize> {
        *self.retention.lock().unwrap()
    }

    pub fn relay(&self, base_url: &str) -> Result<Box<dyn RelayApi>, AppError> {
        self.relays.connect(base_url)
    }

    /// 重新載入整份 config(主 config 與它 Include 的檔案)。測試時 `~` 指向測試的家目錄。
    pub fn load_doc(&self, main: &Path) -> Result<SshConfigDoc, AppError> {
        match &self.home {
            #[cfg(test)]
            Some(home) => crate::config::include::with_test_home(home, || crate::config::commands::load_doc_migrated(main)),
            _ => crate::config::commands::load_doc_migrated(main),
        }
    }
}
