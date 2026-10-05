//! Sync v2 的執行期狀態(spec §7.1):generation、狀態、帳戶金鑰同一把鎖(`SyncCore`),以及「局部提交」——
//! 一輪裡的每個提交只改它自己的區段(帳戶、某一個 space、或頂層欄位),在 core 鎖內比 generation;絕不以本輪開始時
//! 的整份狀態副本覆蓋(spec §12 #8)。任何生命週期或結構性變更都換 generation(`mutate`),在途輪次的提交因此全部
//! 作廢、整輪重跑。鎖順序固定:lifecycle → doc → backed_up → core。

use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Mutex;

use crate::error::AppError;
use crate::sync::crypto::ChainKeys;
use crate::sync::env::SyncEnv;
use crate::sync::state::SyncState as LegacyState;
use crate::sync::state_v2::{self, SyncStateV2};

/// 被搶先(generation 變了)的輪次或提交:不是錯誤,呼叫端丟棄本輪。
pub const SUPERSEDED: &str = "sync round superseded by a newer sync state";
/// v1 升級完成之前(`SyncCore::legacy`)不寫狀態檔、不接受會改狀態的命令:磁碟上還是 v1 的狀態檔。
pub const UPGRADING_MESSAGE: &str = "SSHelter is upgrading sync on this device; try again in a moment";

/// generation / 狀態 / 金鑰永遠一起快照、一起替換。
/// - `account_keys`:由 keychain 的同步碼推導(`derive_account`);space 的金鑰每次從帳戶的 `spacekey` 密文解開,不另存。
/// - `legacy`:啟動時讀到的 v1 狀態,等背景執行緒做 v1 升級(spec §7.6);升級完成前 `state` 是給 UI 看的 v2 外殼。
/// - `unsaved`:記憶體裡的狀態還沒寫成功;下一輪在任何網路操作前先重存(同 v1)。
/// - `save_blocked`:啟動時狀態檔讀不到(I/O)或別的行程持有同步鎖:這個 session 一律不寫狀態(同 v1)。
/// - `conflict_streak`:連續幾輪以推送衝突收尾;`failed_rounds`:連續幾輪被限流、relay 回 `5xx`,或 keychain 給不出同步碼(升級讀 `sync:mnemonic`、更換同步碼的各步讀
///   `sync:mnemonic-next`、補換碼的重試寫 `sync:mnemonic`,後者另以 `swap_failures` 逐次加長)(退避,spec §6.4);
///   `batch_failures`:連續幾次批次查詢回 `5xx`(第 2 次起改逐條查詢,一條壞掉的 chain 不能擋住其他的)。
/// - `relay_checked`:這個行程查過 `GET /v1/info` 的 relay URL(spec §6.4:啟動時與 URL 改變時各查一次)。
/// - `rounds`:輪數;舊版 relay 沒有批次查詢時,space 每 3 輪才查一次(spec §6.4)。
/// - `swap_pending`:更換同步碼的最後一步(或其他電腦的重新加入)已經把狀態換成新帳戶,keychain 的同步碼卻還沒換成新碼(寫不進去):
///   新碼留在 `sync:mnemonic-next`,每一輪結束時再試(`rotation::retry_pending_swap`);啟動時發現同樣的情形也設起來。
/// - `swap_failures`:`swap_pending` 的重試連續失敗了幾次。它算失敗的輪數(`failed_rounds` 取兩者較大的),所以寫不進去的 keychain(每次可能都跳出系統的授權視窗)
///   也退避到 90 秒、3 分、6 分……最長 15 分鐘;只靠 `failed_rounds` 的話,一般輪次一結束就把它歸零,重試永遠停在第一段。
#[derive(Default)]
pub struct SyncCore {
    pub generation: u64,
    pub state: Option<SyncStateV2>,
    pub account_keys: Option<ChainKeys>,
    pub legacy: Option<LegacyState>,
    pub unsaved: bool,
    pub save_blocked: Option<String>,
    pub conflict_streak: u32,
    pub failed_rounds: u32,
    pub batch_failures: u32,
    pub relay_checked: Option<String>,
    pub rounds: u64,
    pub swap_pending: bool,
    pub swap_failures: u32,
}

/// Tauri 管理的同步執行期狀態(`AppState::sync`)。`lifecycle`:建立 / 加入 / 離開帳戶、改 relay URL、更換同步碼
/// 全程互斥(含網路與 keychain);`syncing`:同一時間只跑一輪。`focused` / `last_activity_ms`:視窗在前景、最近一次
/// 操作的時間 —— 決定輪詢間隔(`relay::next_poll_delay`)。
#[derive(Default)]
pub struct SyncRuntime {
    pub core: Mutex<SyncCore>,
    pub lifecycle: Mutex<()>,
    pub syncing: AtomicBool,
    pub focused: AtomicBool,
    pub last_activity_ms: AtomicU64,
}

impl SyncRuntime {
    /// 使用者在 app 裡做了事(存檔、Sync 命令):接下來幾分鐘以一般間隔輪詢。直接記下這一次的時間(不取較大值):時鐘往回調之後,
    /// 之前記下、現在看來在「未來」的時間會一直壓過新的操作,新的操作就不算數了。同時呼叫的兩次差個幾毫秒,無所謂哪一次留下。
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
pub fn save_core(core: &mut SyncCore, state_path: &Path) -> Result<(), AppError> {
    if let Some(reason) = &core.save_blocked {
        return Err(AppError::Other(reason.clone()));
    }
    if core.legacy.is_some() {
        return Err(AppError::Other(UPGRADING_MESSAGE.to_string()));
    }
    let result = match core.state.as_ref() {
        Some(s) => state_v2::save(state_path, s),
        None => Ok(()),
    };
    core.unsaved = result.is_err();
    result
}

/// 局部提交:在 core 鎖內比 generation,對**最新**的狀態套用 `f`(只改呼叫端負責的區段),然後持久化。generation
/// 變了 → `SUPERSEDED`,什麼都不改。`f` 回 Err 時不存檔(它在回錯誤之前做的修改不會復原,所以 `f` 要在修改之前就決定
/// 要不要拒絕)。
///
/// **Err 也可能出現在 `f` 已經套用之後**:存檔失敗(修改留在記憶體、標 `unsaved`,下一輪在任何網路操作前先重存),或
/// `save_blocked` / v1 升級還沒完成(`save_core` 直接拒絕、不標 `unsaved`)—— 先改記憶體、再存檔(v1 就是這個順序)。
/// 呼叫端不能把 Err 當成「什麼都沒改」。
pub fn commit<T>(env: &SyncEnv, generation: u64, f: impl FnOnce(&mut SyncStateV2) -> Result<T, AppError>) -> Result<T, AppError> {
    let mut core = env.runtime.core.lock().unwrap();
    if core.generation != generation {
        return Err(superseded());
    }
    let s = core.state.as_mut().ok_or_else(superseded)?;
    let out = f(s)?;
    save_core(&mut core, &env.state_path)?;
    Ok(out)
}

/// 命令對狀態的修改:先拿 doc 鎖(與套用 + 發布的交易互斥,順序 doc → core),在同一個 core 臨界區「改狀態 + 換
/// generation + 持久化」。`f` 回錯誤(命令被拒絕)時什麼都不改、不換 generation —— 所以 `f` 必須在任何修改之前就
/// 決定要不要拒絕。`save_blocked` 時直接拒絕。`f` 成功之後存檔才失敗:狀態與 generation 都已經換了(標 `unsaved`),
/// 同樣回 Err。
pub fn mutate<T>(env: &SyncEnv, f: impl FnOnce(&mut SyncStateV2) -> Result<T, AppError>) -> Result<T, AppError> {
    let _doc = env.doc.lock().unwrap();
    let mut core = env.runtime.core.lock().unwrap();
    if let Some(reason) = &core.save_blocked {
        return Err(AppError::Other(reason.clone()));
    }
    if core.legacy.is_some() {
        return Err(AppError::Other(UPGRADING_MESSAGE.to_string()));
    }
    let s = core.state.as_mut().ok_or_else(|| AppError::Other("sync is not initialized".to_string()))?;
    let out = f(s)?;
    core.generation += 1;
    save_core(&mut core, &env.state_path)?;
    Ok(out)
}

/// 狀態的唯讀快照。
pub fn snapshot(env: &SyncEnv) -> Option<SyncStateV2> {
    env.runtime.core.lock().unwrap().state.clone()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sync::testkit::{TestClock, TestDevice};
    use crate::sync::fake_relay::FakeRelay;

    #[test]
    fn a_commit_updates_only_the_latest_state_and_refuses_after_a_generation_change() {
        let (relay, clock) = (FakeRelay::new(), TestClock::new());
        let d = TestDevice::new("a", &relay, &clock);
        let env = d.env();
        let generation = env.runtime.core.lock().unwrap().generation;
        commit(&env, generation, |s| {
            s.last_error = Some("one".into());
            Ok(())
        })
        .unwrap();
        // 另一個命令換了 generation:舊 generation 的提交被拒絕,狀態不變。
        mutate(&env, |s| {
            s.device_name = "Renamed".into();
            Ok(())
        })
        .unwrap();
        let refused = commit(&env, generation, |s| {
            s.last_error = Some("two".into());
            Ok(())
        });
        assert!(refused.as_ref().is_err_and(is_superseded));
        let s = snapshot(&env).unwrap();
        assert_eq!((s.last_error.as_deref(), s.device_name.as_str()), (Some("one"), "Renamed"));
        // 兩次都落盤。
        match state_v2::load(&env.state_path).unwrap() {
            state_v2::LoadedState::Current(saved) => assert_eq!(saved.device_name, "Renamed"),
            other => panic!("expected the saved v2 state, got {other:?}"),
        }
    }

    #[test]
    fn new_activity_counts_even_after_the_clock_was_set_back() {
        let runtime = SyncRuntime::default();
        let now = 1_700_000_000_000u64;
        // 時鐘往回調了一小時:之前記下的時間現在看來在一小時之後(超過一個 `ACTIVE_WINDOW`,`next_poll_delay` 不算它)。
        runtime.note_activity(now + 60 * 60 * 1000);
        runtime.note_activity(now);
        let last = runtime.last_activity_ms.load(Ordering::SeqCst);
        assert_eq!(last, now, "the new activity is what counts");
        let delay = crate::sync::relay::next_poll_delay(1, false, last, now + 1000, 0);
        assert_eq!(delay, std::time::Duration::from_secs(45), "polled as a device in use, not as an idle one");
    }

    #[test]
    fn a_refused_mutation_changes_nothing() {
        let (relay, clock) = (FakeRelay::new(), TestClock::new());
        let d = TestDevice::new("a", &relay, &clock);
        let env = d.env();
        let before = env.runtime.core.lock().unwrap().generation;
        assert!(mutate(&env, |_| Err::<(), _>(AppError::Other("no".into()))).is_err());
        assert_eq!(env.runtime.core.lock().unwrap().generation, before);
        env.runtime.core.lock().unwrap().save_blocked = Some("left in place".into());
        assert_eq!(mutate(&env, |_| Ok(())).unwrap_err().to_string(), "left in place");
        let mut core = env.runtime.core.lock().unwrap();
        assert_eq!(save_core(&mut core, &env.state_path).unwrap_err().to_string(), "left in place");
        assert!(!core.unsaved, "retrying cannot help; only a restart can");
    }

    #[test]
    fn a_state_that_cannot_be_written_stays_unsaved_until_a_save_succeeds() {
        let (relay, clock) = (FakeRelay::new(), TestClock::new());
        let d = TestDevice::new("a", &relay, &clock);
        let env = d.env();
        // 狀態檔所在的 `data` 被一個一般檔案擋住:存不了(任何平台、包括 root 都一樣)。
        let blocker = d.home.path().join("data");
        std::fs::write(&blocker, b"in the way").unwrap();
        let generation = env.runtime.core.lock().unwrap().generation;
        let refused = commit(&env, generation, |s| {
            s.last_error = Some("kept".into());
            Ok(())
        });
        assert!(refused.is_err(), "the write failed");
        {
            let core = env.runtime.core.lock().unwrap();
            assert!(core.unsaved, "memory is ahead of the disk: the next round saves it before it touches the network");
            // 先改記憶體、再存檔(v1 就是這個順序),存檔失敗時修改留著。
            assert_eq!(core.state.as_ref().unwrap().last_error.as_deref(), Some("kept"));
        }
        let refused = mutate(&env, |s| {
            s.device_name = "Renamed".into();
            Ok(())
        });
        assert!(refused.is_err());
        assert!(env.runtime.core.lock().unwrap().unsaved);
        // 擋路的東西移開、下一次存檔成功:標記清掉,內容落盤。
        std::fs::remove_file(&blocker).unwrap();
        {
            let mut core = env.runtime.core.lock().unwrap();
            save_core(&mut core, &env.state_path).unwrap();
            assert!(!core.unsaved);
        }
        match state_v2::load(&env.state_path).unwrap() {
            state_v2::LoadedState::Current(saved) => assert_eq!((saved.device_name.as_str(), saved.last_error.as_deref()), ("Renamed", Some("kept"))),
            other => panic!("expected the saved v2 state, got {other:?}"),
        }
    }
}
