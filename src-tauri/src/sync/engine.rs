//! The sync engine's Tauri shell: the cross-process engine lock, startup (the records probe and the account keys), the
//! `lunport-sync` background thread that runs central sync's rounds with their poll intervals and backoff, and the events
//! the engine sends the window. Everything that touches the network runs on that thread or in `spawn_blocking`; the lock
//! order is lifecycle → core.

use std::fs::{File, OpenOptions, TryLockError};
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, Sender};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

use tauri::{AppHandle, Emitter, Manager};

use crate::error::AppError;
use crate::fsutil;
use crate::state::AppState;
use crate::sync::env::{Clock, Keychain, OsKeychain, SyncEnv, SyncEvents, SystemClock};

/// app data 目錄裡的行程間同步鎖:一個 OS 使用者同時只有一個行程跑同步引擎。
const ENGINE_LOCK_FILE: &str = "sync.lock";
pub(crate) const ANOTHER_ENGINE_MESSAGE: &str = "Sync is running in another Lunport process — quit it to use sync here";
/// The background thread's stack. A round can run central sync's first publication, whose frames hold whole library states and need
/// about 2 MiB in a debug build, more on Windows: a default thread's whole stack. Tests get the same from `.cargo/config.toml`.
const SYNC_THREAD_STACK: usize = 8 * 1024 * 1024;

/// 喚醒背景執行緒的原因(`wake`、`wake_implicit`):退避期間只有順便的喚醒要等。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Wake {
    /// 使用者要同步(Sync now)、Sync 命令,以及引擎自己的後續(一步做完了、要馬上再跑):立刻跑一輪。
    Now,
    /// 順便的喚醒(視窗取得焦點):退避期間要等到退避結束才跑。
    Implicit,
}

/// 喚醒背景執行緒的通道;由 commands 與事件共用,故放全域。
static WAKER: OnceLock<Mutex<Option<Sender<Wake>>>> = OnceLock::new();
/// 行程間同步鎖的 handle:鎖跟著這個 File,所以要活到行程結束。
static ENGINE_LOCK: OnceLock<File> = OnceLock::new();
/// 這個行程取得了同步鎖、跑著同步引擎。
static ENGINE_ACTIVE: AtomicBool = AtomicBool::new(false);

/// 這個行程是否跑著同步引擎(取得了同步鎖)。
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
        if let Ok(Ok(status)) = with_env(&self.app, crate::sync::central::controller::status) {
            let _ = self.app.emit("central://status", &status);
        }
        if let Ok(status) = crate::sync::record_commands::status(&self.app) {
            let _ = self.app.emit("records://status", &status);
        }
        let records = {
            let state = self.app.state::<AppState>();
            let core = state.sync.core.lock().unwrap();
            if core.format == crate::sync::record_runtime::RuntimeFormat::Records { core.records.clone() } else { None }
        };
        if let Some(records) = records {
            if let Err(error) = crate::tray::rebuild_record_tray(&self.app, &records) {
                crate::diagnostics::tauri_error("tray_update_failed", &error);
            }
        }
    }

    fn wake(&self) {
        wake();
    }

    fn wake_implicit(&self) {
        wake_implicit();
    }
}

/// 以 app 的狀態、OS keychain 與系統時鐘組出 `SyncEnv`。
pub(crate) fn with_env<T>(app: &AppHandle, f: impl FnOnce(&SyncEnv) -> T) -> Result<T, AppError> {
    let state = app.state::<AppState>();
    let noninteractive = crate::sync::env::NonInteractiveKeychain(&OsKeychain);
    let credentials: &dyn Keychain = if state.background_credentials_only.load(Ordering::SeqCst) {
        &noninteractive
    } else {
        &OsKeychain
    };
    with_keychain(app, credentials, f)
}
/// Central renewal permits only verified no-UI credential updates. Legacy adapters remain read-only.
pub(crate) fn with_background_account_env<T>(
    app: &AppHandle,
    f: impl FnOnce(&SyncEnv) -> T,
) -> Result<T, AppError> {
    let credentials = crate::sync::central::credentials::Background(&OsKeychain);
    with_keychain(app, &credentials, f)
}
fn with_keychain<T>(
    app: &AppHandle,
    credentials: &dyn Keychain,
    f: impl FnOnce(&SyncEnv) -> T,
) -> Result<T, AppError> {
    let state = app.state::<AppState>();
    let events = TauriEvents { app: app.clone() };
    let env = SyncEnv {
        runtime: &state.sync,
        ssh_dir: crate::fsutil::ssh_dir()?,
        state_path: crate::sync::state::state_path()?,
        home: None,
        keychain: credentials,
        events: &events,
        clock: &SystemClock,
        platform: std::env::consts::OS,
    };
    Ok(f(&env))
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
        // The desktop client uses central account sync exclusively. Legacy readers remain
        // available to explicit migration, but never run a background push/pull round.
        delay = crate::sync::relay::IDLE_POLL_INTERVAL;
        backoff = Duration::ZERO;
        records = app.state::<AppState>().sync.core.lock().unwrap().format
            == crate::sync::record_runtime::RuntimeFormat::Records;
        if let Ok(Some((central_delay, central_backoff))) =
            with_background_account_env(&app, |env| {
                if !crate::sync::central::round::configured(env) {
                    return None;
                }
                let _ = crate::sync::central::round::sync_once(env);
                Some((
                    crate::sync::central::round::next_delay(env),
                    crate::sync::central::round::cooldown(env),
                ))
            })
        {
            delay = delay.max(central_delay);
            backoff = backoff.max(central_backoff);
            records = true;
        }
        wait = Wait::after_round(Instant::now(), delay, backoff);
        // Records Sync now coalesces during a failed round's cooldown. It must not
        // turn a relay rejection into an unbounded stream of manual retries.
        wait.defer_explicit = records;
    }
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
    let state = app.state::<AppState>();
    let mut selected_server = None;
    let (probe, lock) = startup_probe_with_lock(
        || {
            selected_server = None;
            match crate::sync::central::server_change::load() {
                Ok(active) => {
                    let probe = record_runtime::probe_startup(&active.path, &default_device_name());
                    selected_server = Some(active);
                    probe
                }
                Err(_) => StartupProbe::Blocked {
                    kind: record_runtime::StartupErrorKind::Io,
                    reason: "cannot locate sync state".into(),
                },
            }
        },
        || fsutil::app_data_root()
            .map_err(|e| engine_lock_error(&e))
            .and_then(|root| acquire_engine_lock(&root)),
    );
    if let Some(active) = selected_server {
        crate::sync::central::server_change::bind(active);
    }
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
    let handle=app.clone();std::thread::Builder::new().name(crate::identity::thread_name("sync")).stack_size(SYNC_THREAD_STACK).spawn(move||worker_loop(handle,rx)).map_err(AppError::Io)?;
    Ok(())
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

#[cfg(test)]
mod tests {
    use super::*;

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
        let device = TestDevice::new("a", &TestClock::new());
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
            serde_json::to_vec(&crate::sync::state_v2::SyncStateV2::fresh("legacy").unwrap()).unwrap(),
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
