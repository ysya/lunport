//! The sync engine's boundary with the outside: the app's runtime, `~/.ssh`, the state file path, the keychain, the events and
//! the clock. Production builds it from the `AppHandle` (`engine`); tests build it from a temporary directory, an in-memory
//! keychain and recording events (`testkit`), so the engine never touches Tauri.

use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::error::AppError;
use crate::sync::runtime::SyncRuntime;

/// OS keychain 的抽象(account 名稱見 `state::MNEMONIC_ACCOUNT`、`state_v2::NEXT_MNEMONIC_ACCOUNT`)。
pub trait Keychain: Send + Sync {
    fn get(&self, account: &str) -> Result<Option<String>, AppError>;
    /// Must never unlock, prompt, or fall back to an interactive read. Unknown implementations fail closed.
    fn get_noninteractive(&self, _account:&str)->Result<Option<String>,AppError> {
        Err(AppError::Other("needs interaction: this credential source has no verified noninteractive read".into()))
    }
    /// Explicit background credential updates may not unlock or prompt either.
    fn set_noninteractive(&self,_account:&str,_secret:&str)->Result<(),AppError> {
        Err(AppError::Other("needs interaction: this credential source has no verified noninteractive update".into()))
    }
    fn set(&self, account: &str, secret: &str) -> Result<(), AppError>;
    /// 不存在也算成功(清理路徑要能重複執行)。
    fn delete(&self, account: &str) -> Result<(), AppError>;
}

/// 真正的 OS keychain(`secrets`)。
pub struct OsKeychain;

impl Keychain for OsKeychain {
    fn get_noninteractive(&self,account:&str)->Result<Option<String>,AppError> {crate::secrets::get_noninteractive(account)}
    fn set_noninteractive(&self,account:&str,secret:&str)->Result<(),AppError> {crate::secrets::set_noninteractive(account,secret)}
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

/// A per-call read-only view. In particular, a stale passphrase cannot cause an interactive credential deletion.
pub struct NonInteractiveKeychain<'a>(pub &'a dyn Keychain);
impl Keychain for NonInteractiveKeychain<'_> {
    fn get(&self, account:&str)->Result<Option<String>,AppError>{self.0.get_noninteractive(account)}
    fn get_noninteractive(&self, account:&str)->Result<Option<String>,AppError>{self.0.get_noninteractive(account)}
    fn set(&self,_:&str,_:&str)->Result<(),AppError>{Err(AppError::Other("needs interaction: credential writes are disabled".into()))}
    fn delete(&self,_:&str)->Result<(),AppError>{Err(AppError::Other("needs interaction: credential deletion is disabled".into()))}
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

/// 引擎對外的通知。**呼叫端不得持有任何鎖**:production 會重建 tray(同步等待主執行緒)、組狀態、發 Tauri 事件。
/// 唯一的例外是 `wake`(見該方法)。
pub trait SyncEvents: Send + Sync {
    /// `central://status` 與 `records://status`:狀態變了(production 自己組狀態)。
    fn status(&self);
    /// 請背景執行緒立刻再跑一輪。**可以在持有鎖時呼叫**,所以實作必須是不阻塞的送出 —— 不拿 app 狀態的鎖、不等主執行緒、不碰 Tauri
    /// (`engine::wake` 就是這樣:對背景執行緒的 channel 送出)。
    fn wake(&self);
    /// 順便的喚醒(視窗取得焦點):同 `wake`,但退避期間要等到退避結束才開始一輪;一樣必須是不阻塞的送出。不分得出差別的實作(測試的
    /// 替身)當成一般的 `wake`。
    fn wake_implicit(&self) {
        self.wake();
    }
}

/// 引擎每個操作需要的一切。生命週期 `'a` 綁在 app 狀態(或測試的替身)上;用完即丟,不跨執行緒保存。
pub struct SyncEnv<'a> {
    pub runtime: &'a SyncRuntime,
    /// `~/.ssh`.
    pub ssh_dir: PathBuf,
    /// `sync-state.json` 的路徑。
    pub state_path: PathBuf,
    /// 只給測試:`~` 指向這裡。production 為 None。
    pub home: Option<PathBuf>,
    pub keychain: &'a dyn Keychain,
    pub events: &'a dyn SyncEvents,
    pub clock: &'a dyn Clock,
    /// `std::env::consts::OS`(裝置記錄的 platform)。
    pub platform: &'static str,
}

impl SyncEnv<'_> {
    pub fn now(&self) -> u64 {
        self.clock.now_ms()
    }
}
