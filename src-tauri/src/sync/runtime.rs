//! Sync v2 的執行期狀態(spec §7.1):generation、狀態、帳戶金鑰同一把鎖(`SyncCore`),以及「局部提交」——
//! 一輪裡的每個提交只改它自己的區段(帳戶、某一個 space、或頂層欄位),在 core 鎖內比 generation;絕不以本輪開始時
//! 的整份狀態副本覆蓋(spec §12 #8)。任何生命週期或結構性變更都換 generation(`mutate`),在途輪次的提交因此全部
//! 作廢、整輪重跑。鎖順序固定:lifecycle → doc → backed_up → core。

use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Mutex, MutexGuard};

use crate::error::AppError;
use crate::sync::crypto::ChainKeys;
use crate::sync::env::SyncEnv;
use crate::sync::record_runtime::RuntimeFormat;
use crate::sync::records_v3::SyncStateV3;
use crate::sync::state::SyncState as LegacyState;
use crate::sync::state_v2::{self, SyncStateV2};

/// 被搶先(generation 變了)的輪次或提交:不是錯誤,呼叫端丟棄本輪。
pub const SUPERSEDED: &str = "sync round superseded by a newer sync state";
/// v1 升級完成之前(`SyncCore::legacy`)不寫狀態檔、不接受會改狀態的命令:磁碟上還是 v1 的狀態檔。
pub const UPGRADING_MESSAGE: &str = "Lunport is upgrading sync on this device; try again in a moment";

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
    pub format: RuntimeFormat,
    pub records: Option<SyncStateV3>,
    /// Ephemeral native credentials only; the public central state remains in records.local.central.
    pub central_session: Option<std::sync::Arc<crate::sync::central::controller::Session>>,
    pub central_user_action: Option<String>,
    pub central_poll: crate::sync::central::round::Polling,
    /// Probe-selected legacy sources wait for explicit workspace choice or migration.
    pub legacy_paused: bool,
    pub state: Option<SyncStateV2>,
    pub account_keys: Option<ChainKeys>,
    pub legacy: Option<LegacyState>,
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

/// Tauri 管理的同步執行期狀態(`AppState::sync`)。`lifecycle`:建立 / 加入 / 離開帳戶、改 relay URL、更換同步碼
/// 全程互斥(含網路與 keychain);`syncing`:同一時間只跑一輪。`focused` / `last_activity_ms`:視窗在前景、最近一次
/// 操作的時間 —— 決定輪詢間隔(`relay::next_poll_delay`)。
#[derive(Default)]
pub struct SyncRuntime {
    pub core: Mutex<SyncCore>,
    pub central_login: Mutex<Option<(String, Option<crate::sync::central::browser::LoginCancellation>)>>,
    pub central_recovery_read: Mutex<Option<crate::sync::central::recovery_flow::Reading>>,
    pub central_recovery_cancel: AtomicBool,
    pub(crate) central_replacement_read: Mutex<Option<crate::sync::central::replacement_flow::Reading>>,
    pub(crate) central_replacement_generation: Mutex<Option<String>>,
    pub(crate) central_replacement_ui: Mutex<Option<crate::sync::central::replacement_flow::Invocation>>,
    pub lifecycle: std::sync::Arc<Mutex<()>>,
    /// 保管庫檔(`vault::store`)的寫入互斥:開檔、改動、存檔全程持有(`vault::store::with_vault`)。同步執行緒、命令與 agent 共用。
    pub vault: Mutex<()>,
    /// Serializes newer-format publication with local material transactions. Acquire vault first for
    /// a transaction; observers acquire only this lock, then core. Never acquire vault while holding
    /// this lock unless the transaction already owns vault; never start a transaction under doc/core.
    pub(crate) format_publication: Mutex<()>,
    #[cfg(test)]
    pub(crate) material_wait_probe: Mutex<Option<std::sync::Arc<dyn Fn() + Send + Sync>>>,
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

/// Owns local material writes through their final state commit. Waiting for vault leaves format
/// observation unblocked. The latest gate check after vault -> publication acquisition is the
/// transaction's linearization point; a later observer waits until this transaction completes.
/// Nested helpers must use this token's vault access rather than locking runtime.vault again.
pub(crate) struct MaterialTransaction<'a> {
    runtime: &'a SyncRuntime,
    _vault: MutexGuard<'a, ()>,
    _publication: MutexGuard<'a, ()>,
}

impl<'a> MaterialTransaction<'a> {
    pub fn begin(env: &SyncEnv<'a>) -> Result<Self, AppError> {
        crate::sync::account::check_local_write_paths(env)?;
        #[cfg(test)]
        {
            let probe = env.runtime.material_wait_probe.lock().unwrap().clone();
            if let Some(probe) = probe { probe(); }
        }
        let vault = env.runtime.vault.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let publication = env.runtime.format_publication.lock().unwrap();
        {
            let core = env.runtime.core.lock().unwrap();
            legacy_writes_allowed(&core)?;
            let state = core.state.as_ref().ok_or_else(|| AppError::Other("sync is not initialized".to_string()))?;
            crate::sync::account::format_writes_allowed(state)?;
        }
        Ok(Self { runtime: env.runtime, _vault: vault, _publication: publication })
    }

    /// Same open/change/save semantics as store::with_vault, under this token's existing vault lock.
    pub fn with_vault<T>(&self, env: &SyncEnv, f: impl FnOnce(&mut crate::vault::store::Vault) -> Result<T, crate::vault::store::VaultError>) -> Result<T, crate::vault::store::VaultError> {
        assert!(std::ptr::eq(self.runtime, env.runtime), "material token belongs to a different runtime");
        let mut vault = crate::vault::store::Vault::open(&crate::vault::store::vault_path(&env.state_path), env.keychain, env.now())?;
        f(&mut vault)
    }
}

/// Old file, slot and upgrade helpers must never enter an active records or paused workspace.
pub(crate) fn legacy_writes_allowed(core: &SyncCore) -> Result<(), AppError> {
    if core.format != RuntimeFormat::Legacy || core.records.is_some() || core.legacy_paused {
        return Err(AppError::Other("legacy SSH workspace is not active".into()));
    }
    Ok(())
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
    let result = match core.format {
        RuntimeFormat::Records => crate::sync::record_runtime::active_state(core)
            .and_then(|state| crate::sync::record_runtime::save_active(state_path, state)),
        RuntimeFormat::Blocked => return Err(AppError::Other("sync workspace is blocked".into())),
        RuntimeFormat::Legacy => {
            legacy_writes_allowed(core)?;
            if core.legacy.is_some() {
                return Err(AppError::Other(UPGRADING_MESSAGE.to_string()));
            }
            match core.state.as_ref() {
                Some(state) => state_v2::save(state_path, state),
                None => Ok(()),
            }
        }
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
    legacy_writes_allowed(&core)?;
    if core.generation != generation {
        return Err(superseded());
    }
    let s = core.state.as_mut().ok_or_else(superseded)?;
    crate::sync::account::format_writes_allowed(s)?;
    let out = f(s)?;
    save_core(&mut core, &env.state_path)?;
    Ok(out)
}

/// The observer is the only commit allowed after a newer gate is already present. Its caller owns
/// format_publication; only gate/error may be changed, retaining cursors and pending work. Same
/// account/relay evidence survives local generation changes; absent/replaced state refuses it.
pub(crate) fn commit_format_observation(env: &SyncEnv, chain_id: &str, relay_url: &str, f: impl FnOnce(&mut SyncStateV2) -> Result<(), AppError>) -> Result<(), AppError> {
    let mut core = env.runtime.core.lock().unwrap();
    legacy_writes_allowed(&core)?;
    let state = core.state.as_mut().ok_or_else(superseded)?;
    if state.relay_url != relay_url || state.account.as_ref().map(|account| account.chain_id.as_str()) != Some(chain_id) {
        return Err(superseded());
    }
    f(state)?;
    save_core(&mut core, &env.state_path)
}

/// 命令對狀態的修改:先拿 doc 鎖(與套用 + 發布的交易互斥,順序 doc → core),在同一個 core 臨界區「改狀態 + 換
/// generation + 持久化」。`f` 回錯誤(命令被拒絕)時什麼都不改、不換 generation —— 所以 `f` 必須在任何修改之前就
/// 決定要不要拒絕。`save_blocked` 時直接拒絕。`f` 成功之後存檔才失敗:狀態與 generation 都已經換了(標 `unsaved`),
/// 同樣回 Err。
pub fn mutate<T>(env: &SyncEnv, f: impl FnOnce(&mut SyncStateV2) -> Result<T, AppError>) -> Result<T, AppError> {
    let _doc = env.doc.lock().unwrap();
    let mut core = env.runtime.core.lock().unwrap();
    legacy_writes_allowed(&core)?;
    if let Some(reason) = &core.save_blocked {
        return Err(AppError::Other(reason.clone()));
    }
    if core.legacy.is_some() {
        return Err(AppError::Other(UPGRADING_MESSAGE.to_string()));
    }
    let s = core.state.as_mut().ok_or_else(|| AppError::Other("sync is not initialized".to_string()))?;
    crate::sync::account::format_writes_allowed(s)?;
    let out = f(s)?;
    core.generation += 1;
    save_core(&mut core, &env.state_path)?;
    Ok(out)
}

/// 狀態的唯讀快照。
pub fn snapshot(env: &SyncEnv) -> Option<SyncStateV2> {
    let core = env.runtime.core.lock().unwrap();
    legacy_writes_allowed(&core).ok()?;
    core.state.clone()
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
    fn latest_newer_format_refuses_stale_state_mutation_and_regular_commit() {
        let (relay, clock) = (FakeRelay::new(), TestClock::new());
        let d = TestDevice::new("a", &relay, &clock);
        let env = d.env();
        let keys = crate::sync::crypto::ChainKeys::generate().unwrap();
        {
            let mut core = env.runtime.core.lock().unwrap();
            let mut account = crate::sync::state_v2::AccountState::new(&keys.chain_id);
            account.remote_schema_version = Some(3);
            core.state.as_mut().unwrap().account = Some(account);
        }
        let before = snapshot(&env).unwrap();
        let generation = env.runtime.core.lock().unwrap().generation;
        let called = AtomicBool::new(false);
        assert_eq!(mutate(&env, |_| { called.store(true, Ordering::SeqCst); Ok(()) }).unwrap_err().to_string(), crate::sync::account::READ_ONLY_MESSAGE);
        assert_eq!(commit(&env, generation, |_| { called.store(true, Ordering::SeqCst); Ok(()) }).unwrap_err().to_string(), crate::sync::account::READ_ONLY_MESSAGE);
        assert!(!called.load(Ordering::SeqCst));
        assert_eq!(snapshot(&env).unwrap(), before);
        assert_eq!(env.runtime.core.lock().unwrap().generation, generation);
    }

    #[test]
    fn delayed_newer_format_observation_survives_a_material_commit_generation_change() {
        use crate::sync::record::{Envelope, RecordKind, ACCOUNT_META_ID};
        let (_relay, _clock, a, _b, _words, _personal) = crate::sync::round::tests::pair();
        let env = a.env();
        let before = snapshot(&env).unwrap();
        let (generation, keys) = { let core = env.runtime.core.lock().unwrap(); (core.generation, core.account_keys.clone().unwrap()) };
        let mut future = crate::sync::state_v2::AccountState::new(&keys.chain_id);
        crate::sync::merge::put_account_record(&mut future, RecordKind::Meta, ACCOUNT_META_ID,
            serde_json::json!({"schema_version":3}), false, "future-device", u64::MAX - 1);
        let pulled = crate::sync::relay::PullResponse { records: crate::sync::merge::account_outgoing(&future, &keys).unwrap().into_iter().map(|out| Envelope {
            id_hash: out.item.id_hash, kind: out.item.kind, seq: 1, nonce: out.item.nonce, ciphertext: out.item.ciphertext, deleted: false,
        }).collect(), latest_seq: 1 };
        let transaction = MaterialTransaction::begin(&env).unwrap();
        let (sent, received) = std::sync::mpsc::channel();
        std::thread::scope(|scope| {
            let observer = scope.spawn(|| { sent.send(()).unwrap(); crate::sync::round::observe_account_format(&env, generation, &before, &keys, &pulled) });
            received.recv_timeout(std::time::Duration::from_secs(5)).unwrap();
            assert!(env.runtime.format_publication.try_lock().is_err());
            mutate(&env, |state| { state.device_name = "committed local change".into(); Ok(()) }).unwrap();
            assert!(!snapshot(&env).unwrap().read_only(), "observer waits for the active transaction");
            drop(transaction);
            assert!(observer.join().unwrap().unwrap(), "same account evidence must survive its new generation");
        });
        let mut expected = before;
        expected.device_name = "committed local change".into();
        expected.account.as_mut().unwrap().remote_schema_version = Some(3);
        expected.last_error = Some(crate::sync::account::READ_ONLY_MESSAGE.to_string());
        assert_eq!(snapshot(&env).unwrap(), expected);
        assert_eq!(env.runtime.core.lock().unwrap().generation, generation + 1);
        assert_eq!(MaterialTransaction::begin(&env).err().unwrap().to_string(), crate::sync::account::READ_ONLY_MESSAGE);
    }

    #[test]
    fn format_observation_refuses_replaced_account_relay_or_absent_legacy_state() {
        use crate::sync::record::{Envelope, RecordKind, ACCOUNT_META_ID};
        for replacement in ["account", "relay", "state"] {
            let (_relay, _clock, a, _b, _words, _personal) = crate::sync::round::tests::pair();
            let env = a.env(); let before = snapshot(&env).unwrap();
            let (generation, keys) = { let core = env.runtime.core.lock().unwrap(); (core.generation, core.account_keys.clone().unwrap()) };
            let mut future = crate::sync::state_v2::AccountState::new(&keys.chain_id);
            crate::sync::merge::put_account_record(&mut future, RecordKind::Meta, ACCOUNT_META_ID, serde_json::json!({"schema_version":3}), false, "future-device", u64::MAX - 1);
            let pulled = crate::sync::relay::PullResponse { records: crate::sync::merge::account_outgoing(&future, &keys).unwrap().into_iter().map(|out| Envelope {
                id_hash: out.item.id_hash, kind: out.item.kind, seq: 1, nonce: out.item.nonce, ciphertext: out.item.ciphertext, deleted: false,
            }).collect(), latest_seq: 1 };
            {
                let mut core = env.runtime.core.lock().unwrap(); core.generation += 1;
                match replacement {
                    "account" => core.state.as_mut().unwrap().account.as_mut().unwrap().chain_id = "replacement-account".into(),
                    "relay" => core.state.as_mut().unwrap().relay_url = "https://replacement.test".into(),
                    "state" => core.state = None,
                    _ => unreachable!(),
                }
            }
            let latest = snapshot(&env);
            assert!(crate::sync::round::observe_account_format(&env, generation, &before, &keys, &pulled).as_ref().is_err_and(is_superseded));
            assert_eq!(snapshot(&env), latest, "{replacement}");
            assert_eq!(env.runtime.core.lock().unwrap().generation, generation + 1);
        }
    }

    #[test]
    fn material_transaction_holds_the_publication_boundary_through_state_commit() {
        let (_relay, _clock, a, _b, _words, _personal) = crate::sync::round::tests::pair();
        let env = a.env();
        let transaction = MaterialTransaction::begin(&env).unwrap();
        assert!(env.runtime.vault.try_lock().is_err());
        assert!(env.runtime.format_publication.try_lock().is_err());
        transaction.with_vault(&env, |vault| { assert!(vault.get("missing")?.is_none()); Ok(()) }).unwrap();
        mutate(&env, |state| { state.device_name = "material transaction committed".into(); Ok(()) }).unwrap();
        assert!(env.runtime.format_publication.try_lock().is_err(), "held through the commit");
        drop(transaction);
        assert!(env.runtime.vault.try_lock().is_ok());
        assert!(env.runtime.format_publication.try_lock().is_ok());
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
