//! The app's one sync state holder (`SyncCore`): generation, the records state and the account keys under one lock, plus the
//! runtime's other locks (lifecycle, vault, publication) and the activity clock the poll interval reads. Any lifecycle or
//! structural change bumps the generation (`record_runtime::mutate_records`), so an in-flight round's commit is dropped and
//! the round rerun. Lock order: lifecycle → core.

use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Mutex;

use crate::error::AppError;
use crate::sync::crypto::ChainKeys;
use crate::sync::record_runtime::RuntimeFormat;
use crate::sync::records_v3::SyncStateV3;
use crate::sync::state::SyncState;
use crate::sync::state_v2::SyncStateV2;

/// 被搶先(generation 變了)的輪次或提交:不是錯誤,呼叫端丟棄本輪。
pub const SUPERSEDED: &str = "sync round superseded by a newer sync state";

/// generation / 狀態 / 金鑰永遠一起快照、一起替換。
/// - `format`: `Records`, or `Legacy` for a saved OpenSSH workspace that only the migration review may read, or `Blocked`.
/// - `state` / `legacy`: that saved workspace's v2 / v1 state, decoded at startup and never written: the migration review and
///   central's source capture read it.
/// - `account_keys`: the chain-mode records account's keys, derived from the keychain's sync code (a chain-mode library that never
///   cut over to central still decodes its account rows with them).
/// - `unsaved`: the state in memory was not written yet; the next round saves it before any network work.
/// - `save_blocked`: startup could not read the state file (I/O) or another process holds the engine lock: this session never writes.
/// - `conflict_streak`, `failed_rounds`, `batch_failures`, `records_pull_cost`, `relay_checked`, `rounds`, `swap_pending`,
///   `swap_failures`: the chain rounds' bookkeeping, kept for the state they decode.
#[derive(Default)]
pub struct SyncCore {
    pub generation: u64,
    pub format: RuntimeFormat,
    pub state: Option<SyncStateV2>,
    pub legacy: Option<SyncState>,
    pub records: Option<SyncStateV3>,
    /// Ephemeral native credentials only; the public central state remains in records.local.central.
    pub central_session: Option<std::sync::Arc<crate::sync::central::controller::Session>>,
    pub central_user_action: Option<String>,
    pub central_migration: Option<crate::sync::central::migration_flow::Cached>,
    pub(crate) central_migration_frozen: bool,
    pub(crate) migration_plan: Option<Box<crate::sync::central::CachedPlan>>,
    pub(crate) migration_verifier: Option<Box<crate::sync::central::CachedVerifier>>,
    pub(crate) adoption_read: Option<Box<crate::sync::central::adoption::ReadingCache>>,
    pub central_poll: crate::sync::central::round::Polling,
    pub account_keys: Option<ChainKeys>,
    pub unsaved: bool,
    pub save_blocked: Option<String>,
    pub conflict_streak: u32,
    pub failed_rounds: u32,
    pub batch_failures: u32,
    /// Most recent Records child-pull (HTTP requests, charged batch items), including deferred retries.
    pub records_pull_cost: (usize, usize),
    pub relay_checked: Option<String>,
    pub rounds: u64,
    pub swap_pending: bool,
    pub swap_failures: u32,
}

/// Tauri 管理的同步執行期狀態(`AppState::sync`)。`lifecycle`:帳戶與伺服器的變更全程互斥(含網路與 keychain);`syncing`:同一時間
/// 只跑一輪。`focused` / `last_activity_ms`:視窗在前景、最近一次操作的時間,決定輪詢間隔(`relay::next_poll_delay`)。
#[derive(Default)]
pub struct SyncRuntime {
    pub core: Mutex<SyncCore>,
    pub central_login: Mutex<Option<(String, Option<crate::sync::central::browser::LoginCancellation>)>>,
    pub central_recovery_read: Mutex<Option<crate::sync::central::recovery_flow::Reading>>,
    pub central_recovery_cancel: AtomicBool,
    pub(crate) central_unlock: Mutex<Option<Box<crate::sync::central::unlock_flow::Reading>>>,
    pub(crate) central_replacement_read: Mutex<Option<crate::sync::central::replacement_flow::Reading>>,
    pub(crate) central_replacement_generation: Mutex<Option<String>>,
    pub(crate) central_replacement_ui: Mutex<Option<crate::sync::central::replacement_flow::Invocation>>,
    pub lifecycle: std::sync::Arc<Mutex<()>>,
    /// 保管庫檔(`vault::store`)的寫入互斥:開檔、改動、存檔全程持有(`vault::store::with_vault`)。同步執行緒與命令共用。
    pub vault: Mutex<()>,
    /// Serializes newer-format publication with local material transactions. Acquire vault first for
    /// a transaction; observers acquire only this lock, then core. Never acquire vault while holding
    /// this lock unless the transaction already owns vault; never start a transaction under core.
    pub(crate) format_publication: Mutex<()>,
    pub syncing: AtomicBool,
    pub focused: AtomicBool,
    pub last_activity_ms: AtomicU64,
}

impl SyncRuntime {
    /// 使用者在 app 裡做了事(Sync 命令、存檔):接下來幾分鐘以一般間隔輪詢。直接記下這一次的時間(不取較大值):時鐘往回調之後,
    /// 之前記下、現在看來在「未來」的時間會一直壓過新的操作,新的操作就不算數了。
    pub fn note_activity(&self, now_ms: u64) {
        self.last_activity_ms.store(now_ms, Ordering::SeqCst);
    }

    /// 視窗到前景 / 離開前景。回到前景也算一次操作。
    pub fn set_focused(&self, focused: bool, now_ms: u64) {
        self.focused.store(focused, Ordering::SeqCst);
        if focused {
            self.note_activity(now_ms);
        }
    }
}

pub fn superseded() -> AppError {
    AppError::Other(SUPERSEDED.to_string())
}

pub fn is_superseded(e: &AppError) -> bool {
    matches!(e, AppError::Other(m) if m == SUPERSEDED)
}

/// 持久化 core 裡的狀態(呼叫端持有 core 鎖)並維護 `unsaved`。`save_blocked` 時一律拒絕、不標 `unsaved`。
/// A saved OpenSSH workspace (`RuntimeFormat::Legacy`) is read-only: the migration review is its only way forward.
pub fn save_core(core: &mut SyncCore, state_path: &Path) -> Result<(), AppError> {
    if let Some(reason) = &core.save_blocked {
        return Err(AppError::Other(reason.clone()));
    }
    let result = match core.format {
        RuntimeFormat::Records => crate::sync::record_runtime::active_state(core)
            .and_then(|state| crate::sync::record_runtime::save_active(state_path, state)),
        RuntimeFormat::Blocked => return Err(AppError::Other("sync workspace is blocked".into())),
        RuntimeFormat::Legacy => return Err(AppError::Other("The saved OpenSSH workspace is read-only; import it into the library.".into())),
    };
    core.unsaved = result.is_err();
    result
}
