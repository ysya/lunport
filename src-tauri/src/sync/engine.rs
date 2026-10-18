//! 同步引擎的 Tauri 外殼(Sync v2 spec §7):行程間同步鎖、啟動(載入 v2 狀態,或等待 v1 升級)、背景執行緒(輪詢
//! 間隔與 `429` 退避,spec §6.4)、存檔 hook、事件與 Tauri commands。引擎本體在 `round`、`account`、`spaces`、`upgrade`
//! (以 `SyncEnv` 注入外界、可單元測試);這裡只把 `AppHandle` 組成 `SyncEnv`。網路一律在同步執行緒或
//! `spawn_blocking` 裡;鎖順序固定:lifecycle → doc → backed_up → core。

use std::fs::{File, OpenOptions, TryLockError};
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, Sender};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

use tauri::{AppHandle, Emitter, Manager};

use crate::config::model::Item;
use crate::error::AppError;
use crate::fsutil;
use crate::state::AppState;
use crate::sync::account::{self, account_keys_from_keychain};
use crate::sync::crypto::ChainKeys;
use crate::sync::dto::{self, ApprovalNotice, PendingApprovalView, ReviewOutcome, ReviewedVersion, SyncConflict, SyncOverview};
use crate::sync::env::{Clock, HttpRelays, Keychain, OsKeychain, SyncEnv, SyncEvents, SystemClock};
use crate::sync::files;
use crate::sync::round;
use crate::sync::runtime::save_core;
use crate::sync::spaces;
use crate::sync::state::{self as v1_state, SyncState as LegacyState, MNEMONIC_ACCOUNT};
use crate::sync::state_v2::{self, LoadedState, SyncNotice, SyncStateV2};
use crate::sync::upgrade;

/// app data 目錄裡的行程間同步鎖:一個 OS 使用者同時只有一個行程跑同步引擎。
const ENGINE_LOCK_FILE: &str = "sync.lock";
pub(crate) const ANOTHER_ENGINE_MESSAGE: &str = "Sync is running in another Lunport process — quit it to use sync here";

/// 喚醒背景執行緒的原因(`wake`、`wake_implicit`):退避期間(spec §6.4)只有順便的喚醒要等。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Wake {
    /// 使用者要同步(Sync now)、Sync 命令,以及引擎自己的後續(一步做完了、要馬上再跑):立刻跑一輪。
    Now,
    /// 順便的喚醒(存檔、視窗取得焦點):退避期間要等到退避結束才跑。
    Implicit,
}

/// 喚醒背景執行緒的通道;由存檔 hook 與 commands 共用,故放全域。
static WAKER: OnceLock<Mutex<Option<Sender<Wake>>>> = OnceLock::new();
/// 行程間同步鎖的 handle:鎖跟著這個 File,所以要活到行程結束。
static ENGINE_LOCK: OnceLock<File> = OnceLock::new();
/// 這個行程取得了同步鎖、跑著同步引擎。false(別的行程持有鎖、或單元測試)時存檔 hook 什麼都不做。
static ENGINE_ACTIVE: AtomicBool = AtomicBool::new(false);
/// `persist_file` 只有路徑與 doc、沒有 AppHandle;存檔 hook 靠它組出 `SyncEnv`。只在 `initialize` 設定。
static APP: OnceLock<AppHandle> = OnceLock::new();

/// 這個行程是否跑著同步引擎。搬進 space 檔的命令用它拒絕沒有引擎的行程(`migrate::refuse_while_sync_inactive`)。
/// Legacy entry points must check under their transaction lock, before credentials or files.
pub(crate) fn legacy_mode_allowed(core:&crate::sync::runtime::SyncCore)->Result<(),AppError>{
    if core.format != crate::sync::record_runtime::RuntimeFormat::Legacy || core.legacy_paused {
        return Err(AppError::Other("Legacy SSH operations are unavailable in this workspace; use the records interface.".into()));
    }
    if let Some(reason)=&core.save_blocked { return Err(AppError::Other(reason.clone())); }
    Ok(())
}
pub(crate) fn require_legacy(runtime:&crate::sync::runtime::SyncRuntime)->Result<(),AppError>{legacy_mode_allowed(&runtime.core.lock().unwrap())}

pub fn engine_active() -> bool {
    ENGINE_ACTIVE.load(Ordering::SeqCst)
}

fn send(wake: Wake) {
    if let Some(slot) = WAKER.get() {
        if let Some(tx) = slot.lock().unwrap().as_ref() {
            let _ = tx.send(wake);
        }
    }
}

/// 請背景執行緒立刻再跑一輪:`sync_now`、Sync 命令、引擎自己做完一步之後的再跑(`SyncEvents::wake`),以及 config 重載帶進 app 以外的修改(`config_load`:要讓同步輪次先看到它)。
/// 退避期間(被限流、relay 出錯、keychain 失敗之後)也立刻執行 —— 使用者明確要同步,或引擎剛有進展(失敗的輪數已經歸零),或本機狀態必須先對上磁碟。
pub fn wake() {
    send(Wake::Now);
}

/// 順便的喚醒:存檔 hook、視窗取得焦點(`SyncEvents::wake_implicit`)。平常一樣立刻再跑一輪;退避期間(`round::backoff_window`)要等到退避結束才跑
/// (spec §6.4):不然每一次存檔、每一次切回視窗,都對還在限流或出錯的 relay 再發一輪請求,退避就形同虛設。
pub fn wake_implicit() {
    send(Wake::Implicit);
}

/// 主視窗到前景 / 離開前景(`WindowEvent::Focused`):決定輪詢間隔(`relay::next_poll_delay`);回到前景立刻同步一輪(順便的喚醒:退避期間要等)。
pub fn window_focused(app: &AppHandle, focused: bool) {
    let state = app.state::<AppState>();
    state.sync.set_focused(focused, SystemClock.now_ms());
    if focused {
        wake_implicit();
    }
}

/// production 的事件:Tauri events + tray。**呼叫端不持有任何鎖**(建立 tray menu 會同步等待主執行緒)。
struct TauriEvents {
    app: AppHandle,
}

#[cfg(all(test, windows))]
#[path = "engine_windows_tests.rs"]
mod windows_tests;

impl SyncEvents for TauriEvents {
    fn status(&self) {
        if let Ok(status)=crate::sync::record_commands::status(&self.app) { let _=self.app.emit("records://status",&status); }
        let records={let state=self.app.state::<AppState>();let core=state.sync.core.lock().unwrap();if core.format==crate::sync::record_runtime::RuntimeFormat::Records{core.records.clone()}else{None}};
        if let Some(records)=records {
            if let Err(error) = crate::tray::rebuild_record_tray(&self.app,&records) {
                crate::diagnostics::tauri_error("tray_update_failed", &error);
            }
            return;
        }
        if let Ok(Ok(overview)) = with_env(&self.app, dto::overview) {
            let _ = self.app.emit("sync://status", &overview);
        }
    }

    fn applied(&self, hosts: usize) {
        let aliases = {
            let state = self.app.state::<AppState>();
            let doc_lock = state.doc.lock().unwrap();
            doc_lock.as_ref().map(crate::tray::tray_aliases)
        };
        if let Some(aliases) = aliases {
            let _ = crate::tray::rebuild_tray(&self.app, &aliases);
        }
        let _ = self.app.emit("sync://applied", &hosts);
    }

    fn conflict(&self, conflicts: &[SyncConflict]) {
        let _ = self.app.emit("sync://conflict", conflicts);
    }

    fn approval(&self, waiting: &[ApprovalNotice]) {
        let _ = self.app.emit("sync://approval", waiting);
    }

    fn notice(&self, notice: &SyncNotice) {
        let _ = self.app.emit("sync://notice", notice);
    }

    fn wake(&self) {
        wake();
    }

    fn wake_implicit(&self) {
        wake_implicit();
    }
}

/// 以 app 的狀態、OS keychain、HTTP relay 與系統時鐘組出 `SyncEnv`。
pub(crate) fn with_env<T>(app: &AppHandle, f: impl FnOnce(&SyncEnv) -> T) -> Result<T, AppError> {
    let state = app.state::<AppState>();
    let events = TauriEvents { app: app.clone() };
    let noninteractive=crate::sync::env::NonInteractiveKeychain(&OsKeychain);
    let credentials:&dyn Keychain=if state.background_credentials_only.load(Ordering::SeqCst){&noninteractive}else{&OsKeychain};
    let env = SyncEnv {
        doc: &state.doc,
        backed_up: &state.backed_up,
        retention: &state.backup_retention,
        runtime: &state.sync,
        ssh_dir: crate::keys::ssh_dir()?,
        state_path: v1_state::state_path()?,
        home: None,
        keychain: credentials,
        relays: &HttpRelays,
        events: &events,
        clock: &SystemClock,
        platform: std::env::consts::OS,
    };
    Ok(f(&env))
}

/// `persist_file` 寫完任何檔案後呼叫(呼叫端持有 doc 鎖)。space 檔的 app 編輯在存檔當下規劃(`files::note_written`)。
/// 同步引擎在別的行程、或單元測試裡:什麼都不做。
pub fn note_file_written(path: &Path, items: &[Item]) {
    if !ENGINE_ACTIVE.load(Ordering::SeqCst) {
        return;
    }
    let Some(app) = APP.get() else { return };
    let _ = with_env(app, |env| { require_legacy(env.runtime)?; files::note_written(env, path, items); Ok::<_,AppError>(()) });
}

/// config 的命令改了主機區塊(改 `IdentityFile`、新增、刪除、改名、搬動、複製……),而且已經放掉 doc 與 backed_up 的鎖之後呼叫:馬上更新 agent 的設定
/// (`agent::wiring::refresh_env`,金鑰保管庫 spec §6「何時重寫:主機的 `IdentityFile` 變了」)。不然要等下一次同步嘗試的最後(前景約 45 秒、閒置 5 分鐘、
/// 退避時最長約 15 分鐘):這段時間 `ssh` 對剛指到保管庫金鑰的主機沒有 `IdentityAgent`,只看得到插槽旁的 `.pub`;這台第一次用到保管庫的金鑰時,主 config 的
/// Include 也還沒放。`refresh_env` 自己依序拿 doc → backed_up → core,所以不能在存檔 hook(`note_file_written`,呼叫端持有 doc 鎖)裡做。內容沒變就什麼都不寫:
/// `agent/config` 一樣就不寫,Include 已經在第一行就不動主 config(`wiring::refresh`)。
/// 更新不成只記到 stderr,存檔本身不算失敗(下一次同步嘗試的最後會再更新)。同步引擎在別的行程、或單元測試裡:什麼都不做(同 `note_file_written`)。
pub fn refresh_agent_config() {
    if !ENGINE_ACTIVE.load(Ordering::SeqCst) {
        return;
    }
    let Some(app) = APP.get() else { return };
    match with_env(app, |env| { require_legacy(env.runtime)?; crate::agent::wiring::refresh_env(env) }) {
        Ok(Ok(_)) => {}
        Ok(Err(e)) | Err(e) => eprintln!("[agent] could not update the agent config: {e}"),
    }
}

/// 背景執行緒的一次等待(每一輪結束時由 `round::next_delay` 與 `round::backoff_window` 決定):`deadline` 之前不跑下一輪,除非被喚醒(`runs_on`)。
#[derive(Clone, Copy, Debug)]
struct Wait {
    /// 最晚什麼時候跑下一輪(輪詢間隔,或退避的間隔)。
    deadline: Instant,
    /// 退避(連續被限流、relay 出錯,或 keychain 失敗之後,spec §6.4)擋到什麼時候:這之前順便的喚醒(`Wake::Implicit`)不能提早開始一輪。不晚於 `deadline`。
    hold_until: Instant,
    defer_explicit: bool,
}

impl Wait {
    /// 啟動:第一輪馬上跑(spec §6.4、§7.6)—— 沒有什麼要先等的。
    fn launch(now: Instant) -> Self {
        Self { deadline: now, hold_until: now, defer_explicit: false }
    }

    /// 一輪結束之後:`delay` 之後再跑下一輪;`backoff` 是這一輪之後退避還要擋多久(沒有退避 → 0)。
    fn after_round(now: Instant, delay: Duration, backoff: Duration) -> Self {
        Self { deadline: now + delay, hold_until: now + backoff.min(delay), defer_explicit: false }
    }

    /// Explicit wakes bypass legacy backoff; Records also defers them until cooldown ends.
    fn runs_on(&self, wake: Wake, now: Instant) -> bool {
        (wake == Wake::Now && !self.defer_explicit) || now >= self.hold_until
    }
}

/// 等到該跑下一輪了(回 `Ok`):`deadline` 到了,或收到一個現在就該跑的喚醒(`Wait::runs_on`)。退避期間收到順便的喚醒:收下、記著,退避一結束就跑(不必等到 `deadline`:
/// 閒置的電腦輪詢間隔比退避長),沒有收到就等到 `deadline`。喚醒的通道斷了(app 結束)→ `Err`。
fn wait_for_round(rx: &Receiver<Wake>, wait: &Wait) -> Result<(), RecvTimeoutError> {
    let mut held = false;
    loop {
        let until = if held { wait.hold_until } else { wait.deadline };
        match rx.recv_timeout(until.saturating_duration_since(Instant::now())) {
            Ok(wake) if wait.runs_on(wake, Instant::now()) => return Ok(()),
            Ok(_) => held = true,
            Err(RecvTimeoutError::Timeout) => return Ok(()),
            Err(e @ RecvTimeoutError::Disconnected) => return Err(e),
        }
    }
}

/// 背景執行緒:啟動時馬上跑第一輪,之後每一輪結束依 `round::next_delay`(輪詢間隔、退避,spec §6.4)等下一輪。一輪之前先把已經排隊的喚醒全部收掉(一次搬 60 台主機
/// 會排上百則)。
fn worker_loop(app: AppHandle, rx: Receiver<Wake>) {
    let (mut delay, mut backoff) = (crate::sync::relay::IDLE_POLL_INTERVAL, Duration::ZERO);
    let mut wait = Wait::launch(Instant::now());
    let mut records = false;
    loop {
        if wait_for_round(&rx, &wait).is_err() {
            return;
        }
        while rx.try_recv().is_ok() {}
        if app.state::<AppState>().background_credentials_only.load(Ordering::SeqCst) {
            wait=Wait::after_round(Instant::now(),crate::sync::relay::IDLE_POLL_INTERVAL,Duration::ZERO);continue;
        }
        if let Ok(next) = with_env(&app, |env| {
            let (format,legacy) = { let core=env.runtime.core.lock().unwrap(); (core.format,core.format == crate::sync::record_runtime::RuntimeFormat::Legacy && !core.legacy_paused && core.save_blocked.is_none()) };
            if legacy { let _ = round::sync_once(env); }
            else if format==crate::sync::record_runtime::RuntimeFormat::Records { let _=crate::sync::record_round::sync_once(env); }
            (round::next_delay(env), round::backoff_window(env), format == crate::sync::record_runtime::RuntimeFormat::Records)
        }) {
            (delay, backoff, records) = next;
        }
        wait = Wait::after_round(Instant::now(), delay, backoff);
        // Records Sync now coalesces during a failed round's cooldown. It must not
        // turn a relay rejection into an unbounded stream of manual retries.
        wait.defer_explicit = records;
    }
}

/// 狀態檔讀不懂(損毀,或更新版 Lunport 寫的)時,把它搬到同一目錄的 `sync-state.unreadable-<ms>.json`:
/// 之後的任何存檔都會把新狀態寫到原路徑,不搬就會蓋掉它。回傳新檔名;搬不動回傳 I/O 錯誤。
fn set_aside_unreadable_state(path: &Path, timestamp_ms: u64) -> std::io::Result<String> {
    let name = format!("sync-state.unreadable-{timestamp_ms}.json");
    let destination = path.with_file_name(&name);
    fsutil::check_write_io(path)?;
    fsutil::check_write_io(&destination)?;
    std::fs::rename(path, destination)?;
    Ok(name)
}

/// 狀態檔還留在原路徑時附在說明後面的提示;同一段完整說明也放進 `save_blocked`。
const STATE_LEFT_IN_PLACE: &str = "; the sync state file was left in place — restart Lunport to retry";
pub(crate) const FUTURE_LOCAL_STATE_MESSAGE: &str = "this sync state uses a newer local format";

/// 啟動時 `state_v2::load` 失敗:回傳(要放進 `last_error` 的說明, `save_blocked`)。
/// - 內容錯誤(`AppError::Other`:讀不懂的 JSON、更新版的格式)→ 搬到旁邊保留,之後照常存新狀態。搬不動 →
///   這個 session 不寫狀態。
/// - 其他(I/O 錯誤)可能只是暫時的 → 檔案留在原地,這個 session 不寫狀態。
fn unreadable_state_outcome(path: &Path, timestamp_ms: u64, error: &AppError) -> (String, Option<String>) {
    let left_in_place = |message: String| {
        let message = format!("{message}{STATE_LEFT_IN_PLACE}");
        (message.clone(), Some(message))
    };
    let future_version = std::fs::read(path).ok().and_then(|bytes| serde_json::from_slice::<serde_json::Value>(&bytes).ok())
        .and_then(|value| value.get("version").and_then(serde_json::Value::as_u64));
    if let Some(version) = future_version.filter(|version| *version > u64::from(state_v2::STATE_VERSION_V2)) {
        return left_in_place(format!("{FUTURE_LOCAL_STATE_MESSAGE} (version {version}); update Lunport before changing sync"));
    }
    match error {
        AppError::Other(_) => match set_aside_unreadable_state(path, timestamp_ms) {
            Ok(name) => (format!("{error}; the old file was kept as {name}"), None),
            Err(e) => left_in_place(format!("{error}; could not set the old file aside: {e}")),
        },
        _ => left_in_place(error.to_string()),
    }
}

/// 啟動時的狀態(`startup`):給 core 的狀態、帳戶金鑰、等待升級的 v1 狀態,以及要不要立刻寫一次狀態檔。
#[derive(Debug)]
struct Startup {
    state: SyncStateV2,
    keys: Option<ChainKeys>,
    legacy: Option<LegacyState>,
    /// 未加入的 v1 狀態直接換成 v2:啟動時寫一次。
    save_now: bool,
    /// 換碼在「狀態已換成新帳戶、keychain 還沒換」之間中斷,而這次啟動 keychain 還是寫不進去:新碼留在 `sync:mnemonic-next`,
    /// 之後每一輪再試(`SyncCore::swap_pending`)。
    swap_pending: bool,
}

/// 依讀到的狀態檔決定啟動狀態(純邏輯,keychain 注入)。
/// - v2:已加入就從 keychain 推導帳戶金鑰,失敗時說明放進 `last_error`(同 v1 的分類)。
/// - v1 且已加入:等背景執行緒升級(spec §7.6),core 先放一個未加入的 v2 外殼。
/// - v1 且未加入:直接換成 v2。
/// - 沒有檔案 / 讀不懂:全新狀態(讀不懂的說明放進 `last_error`)。
fn startup(loaded: Result<LoadedState, AppError>, keychain: &dyn Keychain, device_name: &str) -> Result<Startup, AppError> {
    Ok(match loaded {
        Ok(LoadedState::Current(s)) => {
            let mut s = *s;
            let mut keys = None;
            let mut swap_pending = false;
            if let Some(chain) = s.account.as_ref().map(|a| a.chain_id.clone()) {
                match account_keys_from_keychain(keychain.get(MNEMONIC_ACCOUNT), &chain) {
                    Ok(k) => keys = Some(k),
                    // 換碼(更換同步碼的第 7 步,或其他電腦的重新加入)在「狀態已換成新帳戶、keychain 還是舊碼」之間中斷:以暫存的新碼補完。
                    // keychain 還是寫不進去時沿用暫存碼推導的金鑰、保留暫存碼,下次再換 —— 說明是 keychain 的事,不是「離開再加入」。
                    Err(_) if s.read_only() => {
                        if let Ok(Some((_, staged_keys))) = account::staged_code_for(keychain, &chain) {
                            keys = Some(staged_keys);
                            swap_pending = true;
                        }
                        s.last_error = Some(account::READ_ONLY_MESSAGE.to_string());
                    }
                    Err(message) => match crate::sync::rotation::finish_interrupted_switch(keychain, &chain) {
                        Some(done) => {
                            keys = Some(done.keys);
                            if !done.promoted {
                                s.last_error = Some(crate::sync::rotation::SWAP_PENDING_MESSAGE.to_string());
                                swap_pending = true;
                            }
                        }
                        None => s.last_error = Some(message),
                    },
                }
            }
            Startup { state: s, keys, legacy: None, save_now: false, swap_pending }
        }
        Ok(LoadedState::Legacy(v1)) if v1.joined() => {
            Startup { state: upgrade::shell_state(&v1), keys: None, legacy: Some(*v1), save_now: false, swap_pending: false }
        }
        Ok(LoadedState::Legacy(v1)) => {
            Startup { state: upgrade::shell_state(&v1), keys: None, legacy: None, save_now: true, swap_pending: false }
        }
        Ok(LoadedState::Missing) => {
            Startup { state: SyncStateV2::fresh(device_name)?, keys: None, legacy: None, save_now: false, swap_pending: false }
        }
        Err(e) => {
            let mut s = SyncStateV2::fresh(device_name)?;
            s.last_error = Some(e.to_string());
            Startup { state: s, keys: None, legacy: None, save_now: false, swap_pending: false }
        }
    })
}

/// 取不到同步鎖時要顯示的說明。
fn engine_lock_error(e: &dyn std::fmt::Display) -> String {
    format!("sync is off in this Lunport process: the sync lock could not be taken ({e}); restart Lunport to retry")
}

/// 同步鎖被別的行程拿著時最多試幾次、每次之間等多久(合計約 2 秒;app 內更新時舊行程還沒結束)。
const ENGINE_LOCK_ATTEMPTS: u32 = 10;
const ENGINE_LOCK_RETRY_DELAY: Duration = Duration::from_millis(200);

/// 取得 `<dir>/sync.lock` 的獨占鎖。回傳的 File 要一直活著。別的行程一直持有 → `ANOTHER_ENGINE_MESSAGE`。
fn acquire_engine_lock(dir: &Path) -> Result<File, String> {
    acquire_engine_lock_with(dir, ENGINE_LOCK_ATTEMPTS, || std::thread::sleep(ENGINE_LOCK_RETRY_DELAY))
}

/// `acquire_engine_lock` 的本體:最多試 `attempts` 次,兩次之間呼叫 `pause`(測試注入,不必真的等)。
fn acquire_engine_lock_with(dir: &Path, attempts: u32, mut pause: impl FnMut()) -> Result<File, String> {
    fsutil::check_write(dir).map_err(|e| engine_lock_error(&e))?;
    fsutil::check_write(&dir.join(ENGINE_LOCK_FILE)).map_err(|e| engine_lock_error(&e))?;
    fsutil::ensure_dir_secure(dir).map_err(|e| engine_lock_error(&e))?;
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(dir.join(ENGINE_LOCK_FILE))
        .map_err(|e| engine_lock_error(&e))?;
    let mut attempt = 1;
    loop {
        match file.try_lock() {
            Ok(()) => return Ok(file),
            Err(TryLockError::WouldBlock) if attempt < attempts => {
                attempt += 1;
                pause();
            }
            Err(TryLockError::WouldBlock) => return Err(ANOTHER_ENGINE_MESSAGE.to_string()),
            Err(TryLockError::Error(e)) => return Err(engine_lock_error(&e)),
        }
    }
}

/// Select the startup snapshot and cross-process lock before credentials or runtime activation.
fn startup_probe_with_lock(
    mut probe: impl FnMut() -> crate::sync::record_runtime::StartupProbe,
    take_lock: impl FnOnce() -> Result<File, String>,
) -> (crate::sync::record_runtime::StartupProbe, Result<File, String>) {
    let mut selected = probe();
    let lock = take_lock();
    if lock.is_ok() {
        // The prior owner may finish a save or cutover while this process waits for the lock.
        // Only the snapshot read under ownership can feed credentials, activation and first save.
        selected = probe();
    }
    (selected, lock)
}

/// 啟動:取得同步鎖,載入狀態(v2;v1 交給背景執行緒升級),推導帳戶金鑰,開背景執行緒。狀態壞掉不阻擋 app 啟動
/// (`unreadable_state_outcome`)。拿不到同步鎖的行程只讀一份狀態給 UI 看:不搬狀態檔、不讀 keychain、不開背景
/// 執行緒、存檔 hook 不動作,`save_blocked` 讓所有會寫狀態的命令一律拒絕。
pub fn initialize(app: &AppHandle) -> Result<(), AppError> {
    use crate::sync::record_runtime::{self, StartupProbe};
    let _ = APP.set(app.clone());
    let state = app.state::<AppState>();
    let (probe, lock) = startup_probe_with_lock(
        || match v1_state::state_path() {
            Ok(path) => record_runtime::probe_startup(&path, &default_device_name()),
            Err(_) => StartupProbe::Blocked {
                kind: record_runtime::StartupErrorKind::Io,
                reason: "cannot locate sync state".into(),
            },
        },
        || fsutil::app_data_root()
            .map_err(|e| engine_lock_error(&e))
            .and_then(|root| acquire_engine_lock(&root)),
    );
    match lock {
        Ok(file) => { let _=ENGINE_LOCK.set(file); ENGINE_ACTIVE.store(true,Ordering::SeqCst); }
        Err(reason) => {
            let mut core=state.sync.core.lock().unwrap();record_runtime::activate_probe(&mut core,probe)?;
            core.save_blocked=Some(reason);return Ok(());
        }
    }
    let keys = match &probe {
        StartupProbe::Records{state:records,..} => {
            Some(read_startup_account_keys(records,&OsKeychain,state.background_credentials_only.load(Ordering::SeqCst)))
        },
        _ => None,
    };
    {
        let mut core=state.sync.core.lock().unwrap();record_runtime::activate_probe(&mut core,probe)?;
        match keys {
            Some(Ok(keys))=>core.account_keys=keys,
            Some(Err(_))=>{if let Some(s)=core.records.as_mut(){s.last_error=Some("The sync code is unavailable in this device's credential store.".into());}},
            None=>{},
        }
    }
    let(tx,rx)=mpsc::channel();*WAKER.get_or_init(||Mutex::new(None)).lock().unwrap()=Some(tx);
    let handle=app.clone();std::thread::Builder::new().name("sshelter-sync".into()).spawn(move||worker_loop(handle,rx)).map_err(AppError::Io)?;
    Ok(())
}

/// Explicit Production legacy choice only; startup leaves these bytes and credentials untouched.
pub(crate) fn resume_legacy(app:&AppHandle)->Result<(),AppError>{
    crate::app_profile::CURRENT.require_legacy_ssh().map_err(|e|AppError::Other(e.into()))?;
    let state=app.state::<AppState>();let lifecycle=state.sync.lifecycle.lock().unwrap();
    // with_env only constructs borrowed adapters; pending_migrations only scans bounded files.
    // Neither reacquires lifecycle, vault, publication, doc, or core (see their definitions).
    let pending = with_env(app, crate::sync::record_migration::pending_migrations)??;
    if !pending.is_empty() {
        return Err(AppError::Other("Finish the pending account migration before reopening the legacy workspace.".into()));
    }
    let publication=state.sync.format_publication.lock().unwrap();
    let loaded={let core=state.sync.core.lock().unwrap();
        if core.format!=crate::sync::record_runtime::RuntimeFormat::Legacy || core.save_blocked.is_some(){return Err(AppError::Other("legacy workspace is unavailable".into()));}
        if !core.legacy_paused{return Ok(());}
        match (&core.state,&core.legacy){(Some(s),None)=>LoadedState::Current(Box::new(s.clone())),(None,Some(s))=>LoadedState::Legacy(Box::new(s.clone())),_=>return Err(AppError::Other("legacy state is unavailable".into()))}
    };
    let start=startup(Ok(loaded),&OsKeychain,&default_device_name())?;
    {let mut core=state.sync.core.lock().unwrap();let generation=core.generation.checked_add(1).ok_or_else(||AppError::Other("sync state generation exhausted".into()))?;
        core.state=Some(start.state);core.legacy=start.legacy;core.account_keys=start.keys;core.swap_pending=start.swap_pending;core.legacy_paused=false;core.generation=generation;
        if start.save_now{save_core(&mut core,&v1_state::state_path()?)?;}
    }
    drop(publication);drop(lifecycle);crate::agent::start(app);wake();Ok(())
}

fn default_device_name() -> String {
    std::env::var("COMPUTERNAME")
        .or_else(|_| std::env::var("HOSTNAME"))
        .ok()
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| format!("Lunport on {}", std::env::consts::OS))
}

/// spawn_blocking 的 JoinHandle 錯誤 → AppError(`sync::migrate` 的 command 共用)。
pub(crate) fn join_error(e: tauri::Error) -> AppError {
    AppError::Other(format!("sync task failed: {e}"))
}

/// 在 `spawn_blocking` 裡跑一個引擎動作(`reqwest::blocking` 不能在 tokio runtime 內呼叫;等鎖與寫磁碟也不在主執行
/// 緒上)。`lifecycle` = 全程持有 lifecycle 鎖(帳戶與 space 結構的變更)。動作完成、lifecycle 鎖放掉之後才發 `sync://status`,而且就在這個阻塞的執行緒上發:
/// 組 `SyncOverview`(`dto::overview`)要拿 core 鎖、讀目錄,不該佔著 tokio 的 worker。
///
/// `f` 裡發的事件(`SyncEvents::applied` 重建 tray,要同步等主執行緒)是在**持有 lifecycle 鎖**時發的 —— 這是安全的,因為主執行緒上沒有任何程式碼拿 lifecycle 鎖:
/// 只有這裡(blocking 執行緒)拿它,背景同步執行緒碰它只用 `try_lock`(`rotation::retry_pending_swap`,拿不到就算了)。所以主執行緒等這些事件完成時,不可能卡在
/// 這把鎖上。以後不要在主執行緒、或會被主執行緒等待的地方拿 lifecycle 鎖,否則就死結。
async fn run<T: Send + 'static>(
    app: AppHandle,
    lifecycle: bool,
    f: impl FnOnce(&SyncEnv) -> Result<T, AppError> + Send + 'static,
) -> Result<T, AppError> {
    let handle = app.clone();
    tauri::async_runtime::spawn_blocking(move || {
        let state = handle.state::<AppState>();
        state.sync.note_activity(SystemClock.now_ms());
        let guard = lifecycle.then(|| state.sync.lifecycle.lock().unwrap());
        let result = with_env(&handle, |env| { require_legacy(env.runtime)?; f(env) });
        drop(guard);
        let _ = with_env(&handle, |env| env.events.status());
        result?
    })
    .await
    .map_err(join_error)?
}

/// 動作完成後的最新狀態。
async fn run_then_overview(
    app: AppHandle,
    lifecycle: bool,
    f: impl FnOnce(&SyncEnv) -> Result<(), AppError> + Send + 'static,
) -> Result<SyncOverview, AppError> {
    run(app, lifecycle, move |env| {
        f(env)?;
        dto::overview(env)
    })
    .await
}

#[tauri::command]
pub async fn sync_overview(app: AppHandle) -> Result<SyncOverview, AppError> {
    tauri::async_runtime::spawn_blocking(move || with_env(&app, dto::overview)?).await.map_err(join_error)?
}

/// 使用者明確要求立刻同步一輪(Sync now);算一次操作。退避期間(被限流、relay 出錯之後)也立刻執行 —— 只有存檔、視窗取得焦點這類順便的喚醒才要等(`wake_implicit`)。
#[tauri::command]
pub fn sync_now(app: AppHandle) -> Result<(), AppError> {
    app.state::<AppState>().sync.note_activity(SystemClock.now_ms());
    wake();
    Ok(())
}

/// 建立帳戶(spec §7.3):回傳同步碼(呼叫端只放在元件狀態裡,不進查詢快取)。
#[tauri::command]
pub async fn sync_create_account(app: AppHandle, device_name: String) -> Result<String, AppError> {
    run(app, true, move |env| account::create_account(env, &device_name)).await
}

#[tauri::command]
pub async fn sync_join_account(app: AppHandle, words: String, device_name: String) -> Result<SyncOverview, AppError> {
    run_then_overview(app, true, move |env| account::join_account(env, &words, &device_name)).await
}

/// 離開帳戶:這台的 space 檔搬到 `~/.ssh/sshelter-local/`、主 config 改以一般的 Include 引入,ssh 照常可用(留下
/// `SyncNotice::LeftAccount`;搬不過去就什麼都不改、回錯誤)。`delete_remote`(這台是最後一台時)一併刪除帳戶與所有
/// space 的 chain。未加入時只重試 keychain 清理。
#[tauri::command]
pub async fn sync_leave_account(app: AppHandle, delete_remote: bool) -> Result<SyncOverview, AppError> {
    run_then_overview(app, true, move |env| account::leave_account(env, delete_remote)).await
}

#[tauri::command]
pub async fn sync_show_words(app: AppHandle) -> Result<String, AppError> {
    run(app, false, account::show_words).await
}

#[tauri::command]
pub async fn sync_set_relay_url(app: AppHandle, url: String) -> Result<SyncOverview, AppError> {
    run_then_overview(app, true, move |env| account::set_relay_url(env, &url)).await
}

/// 重新查一次 `GET /v1/info`(使用者更新 relay 之後)。
#[tauri::command]
pub async fn sync_check_relay(app: AppHandle) -> Result<SyncOverview, AppError> {
    run_then_overview(app, false, |env| account::check_relay(env).map(|_| ())).await
}

#[tauri::command]
pub async fn sync_set_device_name(app: AppHandle, name: String) -> Result<SyncOverview, AppError> {
    run_then_overview(app, false, move |env| account::set_device_name(env, &name)).await
}

/// 只把裝置從清單移除,**不是撤權**(要撤銷遺失的電腦請更換同步碼);UI 文案必須如此說明。
#[tauri::command]
pub async fn sync_forget_device(app: AppHandle, device_id: String) -> Result<SyncOverview, AppError> {
    run_then_overview(app, false, move |env| account::forget_device(env, &device_id)).await
}

#[tauri::command]
pub async fn sync_create_space(app: AppHandle, name: String) -> Result<SyncOverview, AppError> {
    run_then_overview(app, true, move |env| spaces::create_space(env, &name).map(|_| ())).await
}

#[tauri::command]
pub async fn sync_rename_space(app: AppHandle, space_id: String, name: String) -> Result<SyncOverview, AppError> {
    run_then_overview(app, true, move |env| spaces::rename_space(env, &space_id, &name)).await
}

#[tauri::command]
pub async fn sync_delete_space(app: AppHandle, space_id: String) -> Result<SyncOverview, AppError> {
    run_then_overview(app, true, move |env| spaces::delete_space(env, &space_id)).await
}

#[tauri::command]
pub async fn sync_select_space(app: AppHandle, space_id: String) -> Result<SyncOverview, AppError> {
    run_then_overview(app, true, move |env| spaces::select_space(env, &space_id)).await
}

#[tauri::command]
pub async fn sync_unselect_space(app: AppHandle, space_id: String) -> Result<SyncOverview, AppError> {
    run_then_overview(app, true, move |env| spaces::unselect_space(env, &space_id)).await
}

/// relay 上的 chain 不見了、帳戶仍有這個 space(spec §9):用這台的內容重建。
#[tauri::command]
pub async fn sync_rebuild_space(app: AppHandle, space_id: String) -> Result<SyncOverview, AppError> {
    run_then_overview(app, true, move |env| spaces::rebuild_space(env, &space_id)).await
}

#[tauri::command]
pub async fn sync_pending_approvals(app: AppHandle) -> Result<Vec<PendingApprovalView>, AppError> {
    run(app, false, dto::pending_approvals).await
}

/// 核准、拒絕之後附上最新狀態;`changed` 是使用者看過、卻已經不是待核准那一版的主機。
async fn run_review(
    app: AppHandle,
    f: impl FnOnce(&SyncEnv) -> Result<spaces::Reviewed, AppError> + Send + 'static,
) -> Result<ReviewOutcome, AppError> {
    run(app, true, move |env| {
        let reviewed = f(env)?;
        Ok(ReviewOutcome { applied: reviewed.applied as u64, changed: reviewed.changed, overview: dto::overview(env)? })
    })
    .await
}

fn reviewed_versions(approvals: &[ReviewedVersion]) -> Vec<(String, String)> {
    approvals.iter().map(|v| (v.alias.clone(), v.digest.clone())).collect()
}

/// 核准(spec §7.4;「全部核准」= 傳入整個清單)。`approvals` 是對話框顯示的版本(`PendingApprovalView` 的 `alias` 與
/// `digest`):只套用清單上仍是那一版的;較新的版本留在清單上、列在回傳的 `changed`(UI:已變更,請重新確認)。
#[tauri::command]
pub async fn sync_approve(app: AppHandle, space_id: String, approvals: Vec<ReviewedVersion>) -> Result<ReviewOutcome, AppError> {
    run_review(app, move |env| spaces::approve(env, &space_id, &reviewed_versions(&approvals))).await
}

/// 拒絕(spec §7.4):丟棄對話框顯示的版本(同 `sync_approve` 的 `approvals` 與 `changed`),本機維持原狀。
#[tauri::command]
pub async fn sync_reject(app: AppHandle, space_id: String, approvals: Vec<ReviewedVersion>) -> Result<ReviewOutcome, AppError> {
    run_review(app, move |env| spaces::reject(env, &space_id, &reviewed_versions(&approvals))).await
}

/// 搬移精靈「搬進一個 space」(spec §7.2)。
#[tauri::command]
pub async fn sync_move_hosts_to_space(
    app: AppHandle,
    aliases: Vec<String>,
    space_id: String,
    tag_by_file: bool,
) -> Result<crate::sync::migrate::MigrationReport, AppError> {
    run(app, false, move |env| crate::sync::migrate::move_hosts_into_space(env, engine_active(), aliases, &space_id, tag_by_file)).await
}

/// 搬移精靈「一個來源檔建立一個 space」(spec §7.2)。
#[tauri::command]
pub async fn sync_move_files_to_new_spaces(
    app: AppHandle,
    groups: Vec<crate::sync::migrate::NewSpaceGroup>,
    tag_by_file: bool,
) -> Result<crate::sync::migrate::MigrationReport, AppError> {
    run(app, true, move |env| crate::sync::migrate::move_into_new_spaces(env, engine_active(), groups, tag_by_file)).await
}

/// 搬移精靈列出的、不能搬進 space 的主機與原因。
#[tauri::command]
pub async fn sync_unmovable_hosts(app: AppHandle) -> Result<Vec<crate::sync::migrate::MigrationFailure>, AppError> {
    run(app, false, crate::sync::migrate::unmovable_hosts).await
}

/// 還沒設定的金鑰(SP3 spec §7.1):讀 config,不改任何東西。
#[tauri::command]
pub async fn sync_key_candidates(app: AppHandle) -> Result<crate::sync::slot_setup::KeyCandidates, AppError> {
    run(app, false, crate::sync::slot_setup::key_candidates).await
}

/// 依使用者的決定建立或沿用插槽並改寫主機(SP3 spec §6.1)。結構性變更:持有 lifecycle 鎖。
#[tauri::command]
pub async fn sync_setup_keys(app: AppHandle, choices: Vec<crate::sync::slot_setup::KeyChoice>) -> Result<SyncOverview, AppError> {
    run_then_overview(app, true, move |env| crate::sync::slot_setup::setup_keys(env, engine_active(), choices).map(|_| ())).await
}

/// 改成同步或停止同步(SP3 spec §6.3)。寫帳戶記錄:持有 lifecycle 鎖。
#[tauri::command]
pub async fn sync_key_set_mode(app: AppHandle, slot_id: String, mode: crate::sync::slot_rules::SlotMode) -> Result<SyncOverview, AppError> {
    run_then_overview(app, true, move |env| crate::sync::slots::set_mode(env, &slot_id, mode)).await
}

/// 在這台為插槽挑一把金鑰(只改這台)。
#[tauri::command]
pub async fn sync_key_pick(app: AppHandle, slot_id: String, path: String) -> Result<SyncOverview, AppError> {
    run_then_overview(app, false, move |env| crate::sync::slots::pick(env, &slot_id, &path)).await
}

/// 改用同步的金鑰(只改這台)。
#[tauri::command]
pub async fn sync_key_use_synced(app: AppHandle, slot_id: String) -> Result<SyncOverview, AppError> {
    run_then_overview(app, false, move |env| crate::sync::slots::use_synced(env, &slot_id)).await
}

/// 刪除沒有主機用到的副本(只改這台)。
#[tauri::command]
pub async fn sync_key_delete_copy(app: AppHandle, slot_id: String) -> Result<SyncOverview, AppError> {
    run_then_overview(app, false, move |env| crate::sync::slots::delete_copy(env, &slot_id)).await
}

/// 這台的插槽改成只在 Lunport,或改回檔案(金鑰保管庫 spec §4.3;只改這台)。
#[tauri::command]
pub async fn sync_key_set_delivery(app: AppHandle, slot_id: String, vault: bool) -> Result<SyncOverview, AppError> {
    run_then_overview(app, false, move |env| crate::sync::slots::set_delivery(env, &slot_id, vault)).await
}

/// 「Move」:這台還是檔案的插槽全部搬進保管庫(金鑰保管庫 spec §8)。不持有 lifecycle 鎖(同 `sync_key_set_delivery`)。
#[tauri::command]
pub async fn sync_key_move_all_into_vault(app: AppHandle) -> Result<crate::sync::dto::MoveIntoVaultResult, AppError> {
    run(app, false, |env| {
        let failed = crate::sync::slots::move_all_into_vault(env)?;
        Ok(crate::sync::dto::MoveIntoVaultResult { overview: dto::overview(env)?, failed })
    })
    .await
}

/// 「Export private key…」(金鑰保管庫 spec §7.3.2):把這個插槽在保管庫裡的私鑰存成使用者選的檔案。存檔對話框由這裡開(同 `settings_export`):
/// 路徑一定來自使用者,畫面沒辦法指定要寫到哪。內容先準備好:保管庫打不開、passphrase 加不上,就不開對話框。取消 → None。
/// 寫檔交給 `vault::export::save_export`:不能寫到 `~/.ssh/sshelter/` 底下,檔案只有擁有者能讀寫。家目錄同引擎(`keys::ssh_dir` 的上一層)。
#[tauri::command]
pub async fn sync_key_export_private(app: AppHandle, slot_id: String, passphrase: Option<String>) -> Result<Option<String>, AppError> {
    use tauri_plugin_dialog::DialogExt;
    let passphrase = passphrase.map(zeroize::Zeroizing::new);
    let (name, text) =
        run(app.clone(), false, move |env| crate::sync::slots::export_private(env, &slot_id, passphrase.as_ref().map(|p| p.as_str()))).await?;
    let Some(picked) = app.dialog().file().set_file_name(&name).blocking_save_file() else { return Ok(None) };
    let path = picked.into_path().map_err(|e| AppError::Other(e.to_string()))?;
    let ssh_dir = crate::keys::ssh_dir()?;
    let home = ssh_dir.parent().ok_or_else(|| AppError::Other("cannot determine the home directory".to_string()))?;
    crate::vault::export::save_export(&path, home, text.as_str())?;
    Ok(Some(path.to_string_lossy().into_owned()))
}

/// 「New key」→ Paste(金鑰保管庫 spec §7.5):貼上的私鑰加進 Lunport,成為只在這台的金鑰。回傳最新狀態與新插槽的 id。
#[tauri::command]
pub async fn sync_key_import_text(app: AppHandle, name: String, text: String) -> Result<crate::sync::dto::NewKeyResult, AppError> {
    let text = zeroize::Zeroizing::new(text);
    run(app, false, move |env| {
        let slot_id = crate::sync::local_keys::import_text(env, &name, &text)?;
        Ok(crate::sync::dto::NewKeyResult { overview: dto::overview(env)?, slot_id })
    })
    .await
}

/// 「New key」→ From a file 與 `~/.ssh` 的「Import」:`keep_file` = Keep the file too,否則 Move into Lunport。
#[tauri::command]
pub async fn sync_key_import_file(app: AppHandle, name: String, path: String, keep_file: bool) -> Result<crate::sync::dto::ImportResult, AppError> {
    run(app, false, move |env| {
        let imported = crate::sync::local_keys::import_file(env, &name, &path, keep_file)?;
        Ok(crate::sync::dto::ImportResult {
            overview: dto::overview(env)?,
            slot_id: imported.slot_id,
            rewritten_hosts: imported.rewritten_hosts,
            removed_file: imported.removed_file,
            file_kept: imported.file_kept,
        })
    })
    .await
}

/// 選了金鑰檔之後的預覽(只讀)。
#[tauri::command]
pub async fn sync_key_preview_file(app: AppHandle, path: String) -> Result<crate::sync::dto::KeyFilePreview, AppError> {
    run(app, false, move |env| crate::sync::local_keys::preview_file(env, &path)).await
}

/// 「Generate key」(金鑰保管庫 spec §7.5)。產生 RSA 要幾秒:在 `run` 的 blocking 執行緒上做,不卡住畫面。
#[tauri::command]
pub async fn sync_key_generate(
    app: AppHandle,
    name: String,
    algorithm: crate::vault::generate::KeyAlgorithm,
    comment: String,
    passphrase: Option<String>,
) -> Result<crate::sync::dto::NewKeyResult, AppError> {
    let passphrase = passphrase.map(zeroize::Zeroizing::new);
    run(app, false, move |env| {
        let slot_id = crate::sync::local_keys::generate_key(env, &name, algorithm, &comment, passphrase.as_ref().map(|p| p.as_str()))?;
        Ok(crate::sync::dto::NewKeyResult { overview: dto::overview(env)?, slot_id })
    })
    .await
}

/// 更換同步碼(spec §7.5):第 1 步在這裡做完,之後由背景執行緒逐步推進;進度在 `SyncOverview::rotation`,完成時
/// 留下 `SyncNotice::NewSyncCode`(UI 以 `sync_show_words` 顯示新同步碼)。
#[tauri::command]
pub async fn sync_change_sync_code(app: AppHandle) -> Result<SyncOverview, AppError> {
    run_then_overview(app, true, crate::sync::rotation::start_rotation).await
}

/// 取消更換同步碼:只能在凍結之前(`SyncRotationView::cancellable`)。
#[tauri::command]
pub async fn sync_cancel_sync_code_change(app: AppHandle) -> Result<SyncOverview, AppError> {
    run_then_overview(app, true, crate::sync::rotation::cancel_rotation).await
}

/// 同步碼已在別台更換(`SyncOverview::frozen`):輸入新同步碼重新加入,保留勾選、檔名與未上傳的修改。
#[tauri::command]
pub async fn sync_rejoin_account(app: AppHandle, words: String) -> Result<SyncOverview, AppError> {
    run_then_overview(app, true, move |env| crate::sync::rotation::rejoin_account(env, &words)).await
}

/// 使用者看過了一則提示(`SyncOverview::notices` 的 index)。
#[tauri::command]
pub async fn sync_dismiss_notice(app: AppHandle, index: usize) -> Result<SyncOverview, AppError> {
    // 看過提示不是結構性變更:只改 `notices`、不換 generation —— 在途的輪次照常提交(它們只在尾端加提示),不必為了
    // 一則提示整輪重跑、多查一次 relay。
    run_then_overview(app, false, move |env| {
        let mut core = env.runtime.core.lock().unwrap();
        if let Some(reason) = &core.save_blocked {
            return Err(AppError::Other(reason.clone()));
        }
        let s = core.state.as_mut().ok_or_else(|| AppError::Other("sync is not initialized".to_string()))?;
        if index >= s.notices.len() {
            return Err(AppError::NotFound("that notice is already gone".to_string()));
        }
        s.notices.remove(index);
        save_core(&mut core, &env.state_path)
    })
    .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sync::testkit::MemKeychain;

    const WORDS: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art";

    #[test]
    fn legacy_commands_refuse_records_blocked_and_unconfirmed_startup(){
        let mut core=crate::sync::runtime::SyncCore::default();
        assert!(legacy_mode_allowed(&core).is_ok());
        for (format,paused) in [(crate::sync::record_runtime::RuntimeFormat::Records,false),(crate::sync::record_runtime::RuntimeFormat::Blocked,false),(crate::sync::record_runtime::RuntimeFormat::Legacy,true)]{
            core.format=format;core.legacy_paused=paused;assert!(legacy_mode_allowed(&core).is_err());
        }
    }
    #[test]
    fn newer_account_startup_keeps_both_keychain_codes_without_promoting_the_swap() {
        let keychain = MemKeychain::default();
        let next_words = crate::sync::crypto::generate_mnemonic().unwrap();
        let next_keys = crate::sync::crypto::derive_account(&next_words).unwrap();
        keychain.set(MNEMONIC_ACCOUNT, WORDS).unwrap();
        keychain.set(crate::sync::state_v2::NEXT_MNEMONIC_ACCOUNT, &next_words).unwrap();
        let mut state = SyncStateV2::fresh("Box").unwrap();
        state.account = Some(crate::sync::state_v2::AccountState::new(&next_keys.chain_id));
        state.account.as_mut().unwrap().remote_schema_version = Some(3);
        let started = startup(Ok(LoadedState::Current(Box::new(state.clone()))), &keychain, "Box").unwrap();
        assert_eq!(keychain.entry(MNEMONIC_ACCOUNT).as_deref(), Some(WORDS));
        assert_eq!(keychain.entry(crate::sync::state_v2::NEXT_MNEMONIC_ACCOUNT).as_deref(), Some(next_words.as_str()));
        assert_eq!(started.keys.unwrap().chain_id, next_keys.chain_id, "the staged code may authenticate read-only format polling");
        assert!(started.swap_pending, "the postponed swap remains pending");
        state.last_error = Some(account::READ_ONLY_MESSAGE.to_string());
        assert_eq!(started.state, state);
    }

    #[test]
    fn startup_loads_v2_keys_and_queues_a_joined_v1_state_for_the_upgrade() {
        let keychain = MemKeychain::default();
        keychain.set(MNEMONIC_ACCOUNT, WORDS).unwrap();
        let account = crate::sync::crypto::derive_account(WORDS).unwrap();
        let mut v2 = SyncStateV2::fresh("Box").unwrap();
        v2.account = Some(crate::sync::state_v2::AccountState::new(&account.chain_id));
        let start = startup(Ok(LoadedState::Current(Box::new(v2.clone()))), &keychain, "Box").unwrap();
        assert_eq!(start.keys.unwrap().chain_id, account.chain_id);
        assert!(start.legacy.is_none() && !start.save_now);
        // keychain 裡沒有同步碼:不推導金鑰,說明放進 last_error。
        let empty = MemKeychain::default();
        let start = startup(Ok(LoadedState::Current(Box::new(v2.clone()))), &empty, "Box").unwrap();
        assert!(start.keys.is_none());
        assert_eq!(start.state.last_error.as_deref(), Some("the sync code is missing from the keychain; leave and join again"));
        // 沒有金鑰不等於沒加入:狀態仍是已加入(帳戶、勾選的 space 都還在),UI 看到的是「同步碼不見了」,不是「請先建立或加入」。
        assert!(start.state.joined() && start.state.account == v2.account);
        // keychain 讀不到(上鎖、被拒):同樣仍是已加入;說明叫使用者解鎖 keychain,也不洩漏任何同步碼。
        let locked = MemKeychain::default();
        locked.set(MNEMONIC_ACCOUNT, WORDS).unwrap();
        locked.fail_reads.store(true, std::sync::atomic::Ordering::SeqCst);
        let start = startup(Ok(LoadedState::Current(Box::new(v2))), &locked, "Box").unwrap();
        assert!(start.keys.is_none() && !start.swap_pending);
        assert!(start.state.joined(), "an unreadable keychain is not 'not joined'");
        let message = start.state.last_error.as_deref().unwrap();
        assert!(message.starts_with("could not read the sync code from the keychain (") && message.ends_with("unlock the keychain and restart Lunport"), "{message}");
        assert!(!message.contains("abandon"), "the sync code never reaches the message");
        // 已加入的 v1:等升級;core 放未加入的外殼(沿用裝置身分)。
        let mut v1 = LegacyState::fresh("Old").unwrap();
        v1.chain_id = Some("ab".repeat(32));
        let start = startup(Ok(LoadedState::Legacy(Box::new(v1.clone()))), &keychain, "Box").unwrap();
        assert!(start.legacy.is_some() && !start.state.joined());
        assert_eq!((start.state.device_id.as_str(), start.state.device_name.as_str()), (v1.device_id.as_str(), "Old"));
        // 沒加入的 v1:直接換成 v2,啟動時寫一次。
        v1.chain_id = None;
        let start = startup(Ok(LoadedState::Legacy(Box::new(v1))), &keychain, "Box").unwrap();
        assert!(start.legacy.is_none() && start.save_now);
        let start = startup(Err(AppError::Other("sync state is unreadable: boom".into())), &keychain, "Box").unwrap();
        assert_eq!(start.state.last_error.as_deref(), Some("sync state is unreadable: boom"));
    }

    #[test]
    fn startup_finishes_a_sync_code_switch_that_was_interrupted() {
        // 狀態已換成新帳戶,keychain 還是舊碼、新碼還在 `sync:mnemonic-next`。
        let new_words = crate::sync::crypto::generate_mnemonic().unwrap();
        let keychain = MemKeychain::default();
        keychain.set(MNEMONIC_ACCOUNT, WORDS).unwrap();
        keychain.set(crate::sync::state_v2::NEXT_MNEMONIC_ACCOUNT, &new_words).unwrap();
        let account = crate::sync::crypto::derive_account(&new_words).unwrap();
        let mut v2 = SyncStateV2::fresh("Box").unwrap();
        v2.account = Some(crate::sync::state_v2::AccountState::new(&account.chain_id));
        let start = startup(Ok(LoadedState::Current(Box::new(v2))), &keychain, "Box").unwrap();
        assert_eq!(start.keys.unwrap().chain_id, account.chain_id);
        assert!(start.state.last_error.is_none());
        assert_eq!(keychain.entry(MNEMONIC_ACCOUNT), Some(new_words));
        assert_eq!(keychain.entry(crate::sync::state_v2::NEXT_MNEMONIC_ACCOUNT), None);
    }

    #[test]
    fn startup_keeps_the_new_code_when_the_keychain_cannot_be_updated_and_retries_next_time() {
        let new_words = crate::sync::crypto::generate_mnemonic().unwrap();
        let keychain = MemKeychain::default();
        keychain.set(MNEMONIC_ACCOUNT, WORDS).unwrap();
        keychain.set(crate::sync::state_v2::NEXT_MNEMONIC_ACCOUNT, &new_words).unwrap();
        keychain.fail_writes_to(MNEMONIC_ACCOUNT, true);
        let account = crate::sync::crypto::derive_account(&new_words).unwrap();
        let mut v2 = SyncStateV2::fresh("Box").unwrap();
        v2.account = Some(crate::sync::state_v2::AccountState::new(&account.chain_id));
        let start = startup(Ok(LoadedState::Current(Box::new(v2.clone()))), &keychain, "Box").unwrap();
        // 狀態已經是新帳戶:沿用暫存碼推導的金鑰,新碼與舊碼都留著;說明是 keychain 的事 —— 不是「離開再加入」。
        assert_eq!(start.keys.unwrap().chain_id, account.chain_id);
        assert_eq!(start.state.last_error.as_deref(), Some(crate::sync::rotation::SWAP_PENDING_MESSAGE));
        assert!(start.swap_pending);
        assert_eq!(keychain.entry(crate::sync::state_v2::NEXT_MNEMONIC_ACCOUNT), Some(new_words.clone()));
        assert_eq!(keychain.entry(MNEMONIC_ACCOUNT).as_deref(), Some(WORDS));
        // 下次啟動 keychain 寫得進去了:補完。
        keychain.fail_writes_to(MNEMONIC_ACCOUNT, false);
        let start = startup(Ok(LoadedState::Current(Box::new(v2))), &keychain, "Box").unwrap();
        assert!(start.keys.is_some() && start.state.last_error.is_none() && !start.swap_pending);
        assert_eq!(keychain.entry(MNEMONIC_ACCOUNT), Some(new_words));
        assert_eq!(keychain.entry(crate::sync::state_v2::NEXT_MNEMONIC_ACCOUNT), None);
    }

    #[test]
    fn startup_leaves_a_staged_code_of_another_account_alone() {
        let keychain = MemKeychain::default();
        keychain.set(MNEMONIC_ACCOUNT, WORDS).unwrap();
        let staged = crate::sync::crypto::generate_mnemonic().unwrap();
        keychain.set(crate::sync::state_v2::NEXT_MNEMONIC_ACCOUNT, &staged).unwrap();
        // 狀態的帳戶既不是 keychain 的同步碼、也不是暫存碼推導出的帳戶。
        let third = crate::sync::crypto::derive_account(&crate::sync::crypto::generate_mnemonic().unwrap()).unwrap();
        let mut v2 = SyncStateV2::fresh("Box").unwrap();
        v2.account = Some(crate::sync::state_v2::AccountState::new(&third.chain_id));
        let start = startup(Ok(LoadedState::Current(Box::new(v2))), &keychain, "Box").unwrap();
        assert!(start.keys.is_none() && !start.swap_pending);
        assert!(start.state.last_error.as_deref().unwrap().contains("different sync account"), "{:?}", start.state.last_error);
        assert_eq!(keychain.entry(MNEMONIC_ACCOUNT).as_deref(), Some(WORDS));
        assert_eq!(keychain.entry(crate::sync::state_v2::NEXT_MNEMONIC_ACCOUNT), Some(staged));
    }

    // ── 退避期間,順便的喚醒不會提早開始一輪(spec §6.4);「Sync now」與引擎自己的再跑照常立刻執行 ──

    #[test]
    fn a_save_or_focus_during_a_backoff_waits_for_the_window_to_end_but_sync_now_does_not() {
        let now = Instant::now();
        let second = Duration::from_secs;
        // 退避:等 90 秒,這 90 秒都是退避。
        let backoff = Wait::after_round(now, second(90), second(90));
        assert!(!backoff.runs_on(Wake::Implicit, now + second(10)), "a save during the backoff waits");
        assert!(!backoff.runs_on(Wake::Implicit, now + second(89)), "so does a window focus");
        assert!(backoff.runs_on(Wake::Implicit, now + second(90)), "once the window has ended it runs");
        assert!(backoff.runs_on(Wake::Now, now + second(10)), "Sync now still runs at once");
        // 閒置的電腦輪詢間隔是 5 分鐘、退避只有 90 秒:存檔等的是退避,退避一結束就跑,不必等輪詢間隔。
        let idle = Wait::after_round(now, second(300), second(90));
        assert!(!idle.runs_on(Wake::Implicit, now + second(89)) && idle.runs_on(Wake::Implicit, now + second(90)));
        // 沒有退避時,順便的喚醒照舊立刻跑一輪;啟動時的第一輪不等。
        let normal = Wait::after_round(now, second(45), Duration::ZERO);
        assert!(normal.runs_on(Wake::Implicit, now + second(1)) && normal.runs_on(Wake::Now, now + second(1)));
        assert!(Wait::launch(now).runs_on(Wake::Implicit, now));
    }

    #[test]
    fn records_sync_now_respects_the_existing_failure_cooldown() {
        let now = Instant::now();
        let mut wait = Wait::after_round(now, Duration::from_secs(300), Duration::from_secs(90));
        wait.defer_explicit = true;
        assert!(!wait.runs_on(Wake::Now, now + Duration::from_secs(1)));
        assert!(!wait.runs_on(Wake::Implicit, now + Duration::from_secs(89)));
        assert!(wait.runs_on(Wake::Now, now + Duration::from_secs(90)));
    }

    #[test]
    fn the_worker_sleeps_through_a_backoff_when_saves_wake_it() {
        let (tx, rx) = mpsc::channel();
        let window = Duration::from_millis(250);
        let wait = Wait::after_round(Instant::now(), window, window);
        // 存檔、再切回視窗:兩個順便的喚醒都排在通道裡。
        tx.send(Wake::Implicit).unwrap();
        tx.send(Wake::Implicit).unwrap();
        wait_for_round(&rx, &wait).unwrap();
        assert!(Instant::now() >= wait.deadline, "the round did not start before the window ended");
        assert!(rx.try_recv().is_err(), "the held wakes were taken off the channel");
    }

    #[test]
    fn a_save_held_by_the_backoff_starts_the_round_when_the_window_ends_not_at_the_poll_interval() {
        let (tx, rx) = mpsc::channel();
        // 閒置:輪詢間隔 30 秒,退避 250 毫秒。
        let wait = Wait::after_round(Instant::now(), Duration::from_secs(30), Duration::from_millis(250));
        tx.send(Wake::Implicit).unwrap();
        wait_for_round(&rx, &wait).unwrap();
        let ended = Instant::now();
        assert!(ended >= wait.hold_until, "not before the backoff ended");
        assert!(ended < wait.deadline, "but at that point, not at the poll interval");
    }

    #[test]
    fn sync_now_starts_a_round_at_once_during_a_backoff_even_behind_held_saves() {
        let (tx, rx) = mpsc::channel();
        let wait = Wait::after_round(Instant::now(), Duration::from_secs(30), Duration::from_secs(30));
        tx.send(Wake::Implicit).unwrap();
        tx.send(Wake::Now).unwrap();
        wait_for_round(&rx, &wait).unwrap();
        assert!(Instant::now() < wait.hold_until, "an explicit wake does not wait for the window");
    }

    #[test]
    fn the_worker_wakes_on_a_save_outside_a_backoff_and_stops_when_the_channel_closes() {
        let (tx, rx) = mpsc::channel();
        let wait = Wait::after_round(Instant::now(), Duration::from_secs(30), Duration::ZERO);
        tx.send(Wake::Implicit).unwrap();
        wait_for_round(&rx, &wait).unwrap();
        assert!(Instant::now() < wait.deadline, "outside a backoff a save starts the round at once");
        drop(tx);
        assert!(wait_for_round(&rx, &wait).is_err(), "the sender is gone: the worker stops");
    }

    #[test]
    fn boundary_unreadable_state_cannot_be_moved_outside_the_profile() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("dev");
        let path = dir.path().join("production-state.json");
        std::fs::write(&path, b"keep").unwrap();
        crate::fsutil::with_test_write_policy(crate::write_policy::WritePolicy::Confined { root }, || {
            assert_eq!(set_aside_unreadable_state(&path, 123).unwrap_err().kind(), std::io::ErrorKind::PermissionDenied);
        });
        assert_eq!(std::fs::read(path).unwrap(), b"keep");
        assert!(!dir.path().join("sync-state.unreadable-123.json").exists());
    }

    #[cfg(unix)]
    #[test]
    fn boundary_engine_lock_cannot_follow_a_link_to_another_profile() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("dev");
        std::fs::create_dir(&root).unwrap();
        let outside = dir.path().join("production-lock");
        std::fs::write(&outside, b"keep").unwrap();
        std::os::unix::fs::symlink(&outside, root.join(ENGINE_LOCK_FILE)).unwrap();
        crate::fsutil::with_test_write_policy(crate::write_policy::WritePolicy::Confined { root: root.clone() }, || {
            assert!(acquire_engine_lock_with(&root, 1, || {}).is_err());
        });
        assert_eq!(std::fs::read(outside).unwrap(), b"keep");
    }

    #[test]
    fn future_local_state_is_preserved_and_startup_never_reads_the_keychain() {
        struct NoCredentials;
        impl Keychain for NoCredentials {
            fn get(&self, _: &str) -> Result<Option<String>, AppError> { panic!("future state must not read credentials") }
            fn set(&self, _: &str, _: &str) -> Result<(), AppError> { panic!("future state must not write credentials") }
            fn delete(&self, _: &str) -> Result<(), AppError> { panic!("future state must not delete credentials") }
        }
        for version in [3, 4] {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("sync-state.json");
            let bytes = serde_json::to_vec(&serde_json::json!({"version": version, "account": {"chain_id": "future-account"}, "records": {"unreadable": "retained"}})).unwrap();
            std::fs::write(&path, &bytes).unwrap();
            let error = state_v2::load(&path).unwrap_err();
            let (message, blocked) = unreadable_state_outcome(&path, 1234, &error);
            assert!(blocked.is_some(), "newer local formats cannot be replaced by a fresh v2 state");
            assert_eq!(std::fs::read(&path).unwrap(), bytes);
            assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 1, "no unreadable archive may be created");
            let start = startup(Err(AppError::Other(message)), &NoCredentials, "Old client").unwrap();
            assert!(start.keys.is_none() && start.legacy.is_none() && !start.save_now && !start.swap_pending);
        }
    }

    #[test]
    fn an_unreadable_state_file_is_set_aside_instead_of_overwritten() {
        // 只用暫存目錄,絕不碰真正的 app data。
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("sync-state.json");
        std::fs::write(&path, b"{ not json").unwrap();
        let error = AppError::Other("sync state is unreadable: boom".to_string());
        let (message, blocked) = unreadable_state_outcome(&path, 1234, &error);
        assert_eq!(message, "sync state is unreadable: boom; the old file was kept as sync-state.unreadable-1234.json");
        assert!(blocked.is_none(), "once it is set aside, saving a fresh state is safe");
        assert!(!path.exists(), "a fresh state saved later can no longer overwrite it");
        assert_eq!(std::fs::read(dir.path().join("sync-state.unreadable-1234.json")).unwrap(), b"{ not json");
        let (failed, blocked) = unreadable_state_outcome(&path, 1235, &error);
        assert!(failed.starts_with("sync state is unreadable: boom; could not set the old file aside: "), "got: {failed}");
        assert!(failed.ends_with("; the sync state file was left in place — restart Lunport to retry"), "got: {failed}");
        assert_eq!(blocked.as_deref(), Some(failed.as_str()));
    }

    #[test]
    fn a_state_file_that_cannot_be_read_right_now_stays_in_place_and_blocks_saving() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("sync-state.json");
        std::fs::write(&path, b"{ \"version\": 2 }").unwrap();
        let io = AppError::Io(std::io::Error::other("device busy"));
        let (message, blocked) = unreadable_state_outcome(&path, 1234, &io);
        assert_eq!(message, "io error: device busy; the sync state file was left in place — restart Lunport to retry");
        assert_eq!(blocked.as_deref(), Some(message.as_str()));
        assert!(path.exists(), "a transient read error must not move a healthy state aside");
    }

    #[test]
    fn only_one_handle_can_hold_the_sync_lock() {
        let dir = tempfile::tempdir().unwrap();
        let first = acquire_engine_lock(dir.path()).expect("the first process takes the lock");
        assert!(dir.path().join("sync.lock").is_file());
        let mut pauses = 0;
        assert_eq!(
            acquire_engine_lock_with(dir.path(), ENGINE_LOCK_ATTEMPTS, || pauses += 1).unwrap_err(),
            "Sync is running in another Lunport process — quit it to use sync here",
            "a second holder is refused while the first one lives"
        );
        assert_eq!(pauses, ENGINE_LOCK_ATTEMPTS - 1, "it retried before giving up");
        drop(first);
        assert!(acquire_engine_lock(dir.path()).is_ok(), "released once the holder goes away");
    }

    #[test]
    fn a_sync_lock_released_while_retrying_is_taken() {
        // 用明確的 `unlock()`:別的測試同時在 spawn 子行程,子行程在 exec 之前會短暫握著這個 handle 的複本。
        let dir = tempfile::tempdir().unwrap();
        let old_process = acquire_engine_lock(dir.path()).unwrap();
        let mut pauses = 0;
        let taken = acquire_engine_lock_with(dir.path(), ENGINE_LOCK_ATTEMPTS, || {
            pauses += 1;
            if pauses == 3 {
                old_process.unlock().unwrap();
            }
        });
        assert!(taken.is_ok(), "the lock is taken on the attempt after the old process let go");
        assert_eq!(pauses, 3);
    }

    fn startup_host(alias: &str) -> crate::sync::records_v3::HostPayload {
        serde_json::from_value(serde_json::json!({
            "schema": 2, "alias": alias, "hostname": "startup.invalid", "port": 22,
            "user": "fixture", "auth": "password", "key_id": null, "jump": [],
            "keepalive_secs": 30, "keepalive_max_missed": 3, "connect_timeout_secs": 15,
            "host_key": null, "tags": [], "notes": "", "imported": null
        }))
        .unwrap()
    }

    // The previous owner writes while the real OS lock is held; no timing sleeps or credentials.
    fn startup_after_holder_write(initial: Option<Vec<u8>>) -> crate::sync::testkit::TestDevice {
        use crate::sync::testkit::{TestClock, TestDevice};
        use crate::sync::{
            record_repository as repo, record_runtime as runtime, records_v3::HostScope,
        };
        let relay = crate::sync::fake_relay::FakeRelay::new();
        let device = TestDevice::new("a", &relay, &TestClock::new());
        let path = device.env().state_path;
        let runtime::StartupProbe::Records {
            state: mut latest, ..
        } = runtime::probe_startup(&path, "holder-final")
        else {
            panic!("temporary missing state")
        };
        if let Some(bytes) = initial {
            if let Ok(crate::sync::records_v3::DecodedState::V3(previous)) =
                crate::sync::records_v3::decode_state(std::str::from_utf8(&bytes).unwrap())
            {
                latest.device_id = previous.device_id;
            }
            fsutil::atomic_write(&path, &bytes, 0o600).unwrap();
        }
        let latest = repo::create_host(
            &latest,
            "0000000000000001",
            HostScope::Local,
            startup_host("holder-final"),
            300,
        )
        .unwrap();
        let root = path.parent().unwrap();
        let old_process = acquire_engine_lock(root).unwrap();
        let (probe, lock) = startup_probe_with_lock(
            || runtime::probe_startup(&path, "contender"),
            || {
                acquire_engine_lock_with(root, 2, || {
                    runtime::save_active(&path, &latest).unwrap();
                    old_process.unlock().unwrap();
                })
            },
        );
        let _lock = lock.expect("the contender owns the lock after the holder's final save");
        runtime::activate_probe(&mut device.runtime.core.lock().unwrap(), probe).unwrap();
        assert_eq!(
            device.runtime.core.lock().unwrap().format,
            runtime::RuntimeFormat::Records,
            "a completed cutover must select records mode"
        );
        runtime::mutate_records(&device.env(), |selected| {
            repo::create_host(
                selected,
                "0000000000000002",
                HostScope::Local,
                startup_host("first-save"),
                400,
            )
            .map_err(|error| AppError::Other(error.to_string()))
        })
        .unwrap();
        let runtime::StartupProbe::Records {
            state: saved,
            fresh: false,
        } = runtime::probe_startup(&path, "unused")
        else {
            panic!("persisted records")
        };
        assert_eq!(
            saved.device_id, latest.device_id,
            "do not persist a speculative contender identity"
        );
        assert_eq!(
            repo::get_host(&saved, "0000000000000001")
                .unwrap()
                .host
                .payload
                .alias,
            "holder-final",
            "first save must retain the previous owner's final host"
        );
        assert_eq!(saved.device_name, "holder-final");
        assert_eq!(
            repo::get_host(&saved, "0000000000000002")
                .unwrap()
                .host
                .payload
                .alias,
            "first-save"
        );
        device
    }

    #[test]
    fn startup_lock_wait_retains_latest_records_through_first_save() {
        use crate::sync::record_runtime::{probe_startup, StartupProbe};
        let temp = tempfile::tempdir().unwrap();
        let StartupProbe::Records { mut state, .. } =
            probe_startup(&temp.path().join("missing"), "stale")
        else {
            panic!("records")
        };
        state.device_id = "d".repeat(32);
        let state = crate::sync::record_repository::create_host(
            &state,
            "0000000000000001",
            crate::sync::records_v3::HostScope::Local,
            startup_host("stale"),
            100,
        )
        .unwrap();
        startup_after_holder_write(Some(serde_json::to_vec(&state).unwrap()));
    }

    #[test]
    fn startup_lock_wait_recognizes_legacy_to_records_cutover() {
        startup_after_holder_write(Some(
            serde_json::to_vec(&SyncStateV2::fresh("legacy").unwrap()).unwrap(),
        ));
    }

    #[test]
    fn startup_lock_wait_retains_newly_created_state_instead_of_speculative_identity() {
        startup_after_holder_write(None);
    }

    #[test]
    fn a_sync_lock_that_cannot_be_opened_reports_the_error() {
        let dir = tempfile::tempdir().unwrap();
        let not_a_dir = dir.path().join("not-a-dir");
        std::fs::write(&not_a_dir, b"").unwrap();
        let message =
            acquire_engine_lock_with(&not_a_dir, ENGINE_LOCK_ATTEMPTS, || panic!("only a held lock is retried")).unwrap_err();
        assert!(message.starts_with("sync is off in this Lunport process: the sync lock could not be taken ("), "got: {message}");
        assert!(message.ends_with("); restart Lunport to retry"), "got: {message}");
        assert_eq!(acquire_engine_lock(&not_a_dir).unwrap_err(), message);
    }
}

/// Startup must not unlock the OS credential store merely because an MCP adapter started the host.
fn read_startup_account_keys(records:&crate::sync::records_v3::SyncStateV3,source:&dyn Keychain,background:bool)->Result<Option<crate::sync::crypto::ChainKeys>,AppError>{
    let noninteractive=crate::sync::env::NonInteractiveKeychain(source);
    crate::sync::record_runtime::read_account_keys(records,if background{&noninteractive}else{source})
}
#[cfg(test)]
mod noninteractive_startup_tests {
    use super::*;
    struct Locked;
    impl Keychain for Locked {
        fn get(&self,_:&str)->Result<Option<String>,AppError>{panic!("headless startup must not invoke interactive credential reads")}
        fn set(&self,_:&str,_:&str)->Result<(),AppError>{panic!()}
        fn delete(&self,_:&str)->Result<(),AppError>{panic!()}
    }
    #[test]
    fn hidden_host_startup_account_and_vault_reads_fail_closed_without_os_prompts(){
        let mut records:crate::sync::records_v3::SyncStateV3=serde_json::from_value(serde_json::json!({"version":3,"device_id":"a".repeat(32),"device_name":"fixture","relay_url":"http://127.0.0.1:8787","account":null,"spaces":{},"local":{"hosts":{},"keys":{}},"rotation":null,"relay_features":null,"legacy_v1_backup":null,"phrase_cleanup_pending":false,"migration_gate":null,"shared_writes_blocked":false,"pending_account":null,"notices":[],"last_sync_ms":null,"last_error":null})).unwrap();
        let phrase=crate::sync::crypto::generate_mnemonic().unwrap();let keys=crate::sync::crypto::derive_account(&phrase).unwrap();records.account=Some(crate::sync::state_v2::AccountState::new(&keys.chain_id));
        assert!(read_startup_account_keys(&records,&Locked,true).is_err());
        let dir=tempfile::tempdir().unwrap();let path=dir.path().join("vault.json");let bytes=br#"{"version":2,"key_account":"vault:key:0123456789abcdef","entries":{"slot":{"nonce":"x","ciphertext":"x"}}}"#;std::fs::write(&path,bytes).unwrap();
        assert!(crate::vault::store::read_vault(&path,&crate::sync::env::NonInteractiveKeychain(&Locked)).is_err());assert_eq!(std::fs::read(path).unwrap(),bytes);
    }
}
