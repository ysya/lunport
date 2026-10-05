//! 一輪同步(spec §7.1):準備 space 檔 → 讀檔與不變式(以 space 為單位)→ 本機 diff → 一個批次請求取得帳戶與各
//! space 的新記錄(deferred 補抓、舊 relay 退回逐條查詢)→ **先處理帳戶**(有更換標記就記下 `frozen` 並停止)→ 提交
//! 帳戶並調整 space 檔 → 逐一提交 space(各自全有或全無、只更新自己的區段)→ 上傳(帳戶與各 space 分開;`409 frozen`
//! 立刻停止)→ 刪除排定的 chain → 事件。網路一律不持有 doc/core 鎖;每個提交都在 core 鎖內比 generation。

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::atomic::Ordering;
use std::time::Duration;

use crate::error::AppError;
use crate::sync::account::{record_relay_info, READ_ONLY_MESSAGE};
use crate::sync::crypto::ChainKeys;
use crate::sync::dto::{ApprovalNotice, SyncConflict};
use crate::sync::env::SyncEnv;
use crate::sync::files::{
    apply_and_commit_space, gather, prepare_files, reset_space_for_rematerialize, space_emptied, space_path, Applied, Gathered,
};
use crate::sync::merge::{
    account_outgoing, apply_pushed_account, apply_pushed_space, device_name, merge_account, merge_space, plan_device,
    plan_hosts, push_outgoing, space_deleted_by, space_entry, space_key_slot, space_keys, space_outgoing,
    unpushed_host_effects,
};
use crate::sync::record::{record_key, RecordKind, RotationMarkerPayload, SpaceKeyPayload};
use crate::sync::relay::{
    backoff_delay, next_poll_delay, BatchPullItem, BatchPullResult, PullResponse, RelayApi, RelayError, FEATURE_PULL_BATCH, MAX_BATCH_PULL,
};
use crate::sync::runtime::{commit, is_superseded, save_core, SyncCore};
use crate::sync::spaces::{reconcile_space_files, ReconcileError, Reconciled};
use crate::sync::state_v2::{AccountState, FreezeInfo, SyncStateV2};

pub const ACCOUNT_GONE_MESSAGE: &str =
    "This sync account no longer exists on the relay (deleted from another device or expired) — leave it on this device";
pub const SPACE_GONE_MESSAGE: &str =
    "this space's data is missing on the relay — rebuild it from this device, or delete the space";
pub const MISSING_KEY_MESSAGE: &str = "the key for this space has not arrived from the sync account yet";
pub const RATE_LIMITED_MESSAGE: &str = "the relay is limiting requests from this network; sync retries automatically in a few minutes";
pub const RELAY_TROUBLE_MESSAGE: &str = "the relay had trouble answering; sync retries with a growing delay";
const STUCK_CONFLICTS_MESSAGE: &str =
    "Some changes could not be uploaded because the relay holds a newer version this SSHelter cannot read — update SSHelter";
/// 連續這麼多輪以推送衝突收尾之後,不再立刻重跑(同 v1)。
const CONFLICT_RETRY_LIMIT: u32 = 3;
/// 舊版 relay(沒有批次查詢)時,space 每幾輪查一次;帳戶 chain 每輪都查(spec §6.4)。
const LEGACY_SPACE_EVERY: u64 = 3;

/// 一條 chain 這一輪拉到的結果。
#[derive(Debug)]
enum Fetched {
    Ok(PullResponse),
    NotFound,
    /// 被限流,或批次因 `deferred` / 整批 `429` 沒輪到:cursor 不推進。
    Missed,
}

/// `run_round` 的結果。B3b 的更換同步碼第 2 步靠它決定要往下走、讓給別台、還是等一下再跑:
/// - `frozen`:relay 對某次上傳回了 `409 frozen`(spec §6.4)—— 這一輪的上傳到此為止、dirty 保留。`mark_frozen_chains` 時
///   已記進狀態。
/// - `markers`:這一輪拉帳戶 chain 時看到的更換標記(`meta` `rotation:*`;spec §7.1 第 4 步)—— 這一輪在套用任何東西、
///   上傳任何東西之前就停了,帳戶的 cursor 沒推進。`mark_frozen_chains` 時已和 `frozen` 狀態一起記進狀態;`false`(這台
///   自己正在更換同步碼)時**不記進狀態**,只回報,讓不讓給對方由呼叫端決定。
/// - `backoff`:這一輪以被限流(`429`)或 relay 出錯(`5xx`、讀不懂的回應、某個 space 的儲存額度滿了)收尾,拿不到帳戶的
///   那一輪也算:呼叫端不要立刻再跑(`run_round` 自己也不會為這種一輪要求立刻重跑),等 `next_delay`。
#[derive(Debug, Default, PartialEq)]
pub struct RoundOutcome {
    pub frozen: bool,
    pub markers: Vec<RotationMarkerPayload>,
    pub backoff: bool,
}

/// `pull_all` 的結果。
#[derive(Debug, Default)]
struct Pulled {
    fetched: BTreeMap<String, Fetched>,
    /// 有 chain(或整批)被限流:這一輪以退避收尾。
    limited: bool,
    /// relay 回 `5xx`(整批或單條):這一輪以退避收尾。
    failed: bool,
    /// 這一輪的批次查詢回了 `5xx`(連續第幾次由呼叫端記在 `SyncCore::batch_failures`)。
    batch_failed: bool,
    /// 這一輪至少有一次批次查詢成功(呼叫端把 `batch_failures` 歸零)。
    batch_ok: bool,
}

/// 批次查詢(spec §6.4):每批 ≤ 64 條;有 `deferred` 時**只**把 deferred 的項目排在最前面立刻再發一批;沒取得的 chain
/// 不推進 cursor。舊版 relay(`Unsupported`)或已知沒有批次功能時逐條 `GET`。
/// relay 的一條 chain 出錯會讓整批回 `5xx`:`batch_failures`(之前連續失敗的次數)加上這一次達到 2,就在這一輪改逐條
/// `GET`,一條壞掉的 chain 不能擋住其他的(它自己記為沒取得、這一輪以退避收尾)。整批 `429` 一律不重試、也不改逐條
/// —— 被拒絕的批次照樣扣了整批的配額,只能退避。任何一個 `429`(整批、批次裡的一項、逐條查詢)之後這一輪都不再對 relay
/// 發請求:沒輪到的 chain(deferred、還沒送的、逐條查詢剩下的)一律當成沒取得,cursor 不推進。
fn pull_all(relay: &dyn RelayApi, targets: &[BatchPullItem], mut batch: bool, batch_failures: u32) -> Result<Pulled, RelayError> {
    let mut out = Pulled::default();
    let mut queue: Vec<BatchPullItem> = targets.to_vec();
    while batch && !queue.is_empty() {
        let take = queue.len().min(MAX_BATCH_PULL);
        let chunk: Vec<BatchPullItem> = queue[..take].to_vec();
        match relay.pull_batch(&chunk) {
            Ok(entries) => {
                out.batch_ok = true;
                let mut deferred = Vec::new();
                for (item, entry) in chunk.into_iter().zip(entries) {
                    match entry.result {
                        BatchPullResult::Ok(resp) => {
                            out.fetched.insert(item.chain.clone(), Fetched::Ok(resp));
                        }
                        BatchPullResult::NotFound => {
                            out.fetched.insert(item.chain.clone(), Fetched::NotFound);
                        }
                        BatchPullResult::RateLimited => {
                            out.limited = true;
                            out.fetched.insert(item.chain.clone(), Fetched::Missed);
                        }
                        BatchPullResult::Deferred => deferred.push(item),
                    }
                }
                if deferred.len() == take {
                    // relay 一項都沒執行(第一項應該一律執行):不再重試,這些 chain 本輪不推進。
                    for item in deferred {
                        out.fetched.insert(item.chain.clone(), Fetched::Missed);
                    }
                    deferred = Vec::new();
                }
                let rest = queue.split_off(take);
                queue = deferred;
                queue.extend(rest);
                if out.limited {
                    // 批次裡有 chain 被限流:不再補抓 deferred 的、也不再送後面的批次。
                    for item in queue.drain(..) {
                        out.fetched.insert(item.chain.clone(), Fetched::Missed);
                    }
                }
            }
            Err(RelayError::RateLimited) => {
                out.limited = true;
                for item in queue.drain(..) {
                    out.fetched.insert(item.chain.clone(), Fetched::Missed);
                }
            }
            Err(RelayError::Unsupported(_)) => batch = false,
            Err(RelayError::Http(code)) if code >= 500 => {
                out.failed = true;
                out.batch_failed = true;
                if batch_failures + 1 >= 2 {
                    batch = false; // 連續第二次:這一輪改逐條查詢
                } else {
                    for item in queue.drain(..) {
                        out.fetched.insert(item.chain.clone(), Fetched::Missed);
                    }
                }
            }
            Err(e) => return Err(e),
        }
    }
    for item in queue {
        if out.limited {
            // 逐條查詢碰到 `429` 之後不再發請求:剩下的都沒取得。
            out.fetched.insert(item.chain, Fetched::Missed);
            continue;
        }
        let fetched = match relay.pull(&item.chain, &item.token, item.since) {
            Ok(resp) => Fetched::Ok(resp),
            Err(RelayError::NotFound) => Fetched::NotFound,
            Err(RelayError::RateLimited) => {
                out.limited = true;
                Fetched::Missed
            }
            Err(RelayError::Http(code)) if code >= 500 => {
                out.failed = true;
                Fetched::Missed
            }
            Err(RelayError::BadResponse(_)) => {
                out.failed = true;
                Fetched::Missed
            }
            Err(e) => return Err(e),
        };
        out.fetched.insert(item.chain, fetched);
    }
    Ok(out)
}

/// 下一輪之前等多久(spec §6.4 + relay 配額,`relay::next_poll_delay`):正在用時 max(45 秒, 2 秒 × 這輪要查的 chain
/// 數),閒置時約 5 分鐘;連續被限流或 relay 回 `5xx` 時依序退避到最長 15 分鐘。
pub fn next_delay(env: &SyncEnv) -> Duration {
    let core = env.runtime.core.lock().unwrap();
    let spaces = core.state.as_ref().map(|s| s.spaces.values().filter(|sp| sp.selected && !sp.missing).count()).unwrap_or(0);
    next_poll_delay(
        1 + spaces,
        env.runtime.focused.load(Ordering::SeqCst),
        env.runtime.last_activity_ms.load(Ordering::SeqCst),
        env.now(),
        core.failed_rounds,
    )
}

/// 這一輪結束之後,退避還要擋多久:連續被限流、relay 出錯,或 keychain 失敗(`failed_rounds` > 0)之後的 `relay::backoff_delay`(spec §6.4),沒有失敗 → 0。退避期間順便的喚醒
/// (存檔、視窗取得焦點:`engine::wake_implicit`)不會提早開始一輪,退避一結束就跑;使用者按「Sync now」與引擎自己做完一步之後的再跑(`engine::wake`)照常立刻執行。
/// 它不長於 `next_delay`(後者取它與輪詢間隔的較大者):閒置的電腦輪詢間隔是 5 分鐘、退避只有 90 秒,存檔等的是退避、不是輪詢間隔。
pub fn backoff_window(env: &SyncEnv) -> Duration {
    backoff_delay(env.runtime.core.lock().unwrap().failed_rounds)
}

/// 一輪同步。錯誤寫進 `last_error`(只寫在產生它的那一代狀態上 —— `prepare_files` 換了 generation 之後才失敗的例外,由
/// `run_round` 寫)並發 `sync://status`,永不 panic;被搶先、主 config 在載入之後被外部改過(`Conflict`:重跑)都不算錯誤。
pub fn sync_once(env: &SyncEnv) -> Result<(), AppError> {
    if env.runtime.syncing.swap(true, Ordering::SeqCst) {
        return Ok(()); // 已在同步中
    }
    // v1 升級先做(spec §7.6)。失敗時 v1 狀態檔不動、ssh 讀得到的主機一直留在被列出的檔案裡(細節見 `upgrade` 的模組說明),錯誤顯示在
    // 狀態列(不寫狀態檔),下一輪接著做完(spec §9)。升級進行中使用者離開了(`superseded`)不是升級的錯誤;錯誤說明只寫在產生它的那一代
    // 狀態上,離開之後的狀態不留「could not upgrade」。
    let (legacy, generation) = {
        let core = env.runtime.core.lock().unwrap();
        (core.legacy.clone(), core.generation)
    };
    if let Some(v1) = legacy {
        let result = crate::sync::upgrade::upgrade_v1(env, &v1);
        env.runtime.syncing.store(false, Ordering::SeqCst);
        let outcome = match result {
            Ok(_) => Ok(()),
            Err(e) if is_superseded(&e) => Ok(()),
            Err(e) => {
                let mut core = env.runtime.core.lock().unwrap();
                if core.generation == generation {
                    if let Some(s) = core.state.as_mut() {
                        s.last_error = Some(format!("SSHelter could not upgrade this device's sync yet: {e}"));
                    }
                }
                Err(e)
            }
        };
        env.events.status();
        return outcome;
    }
    // 先補存上次沒寫進磁碟的狀態;然後 generation / 狀態 / 金鑰一次快照(同一把鎖)。
    let (generation, snapshot, save_error) = {
        let mut core = env.runtime.core.lock().unwrap();
        let save_error = if core.unsaved { save_core(&mut core, &env.state_path).err() } else { None };
        let snapshot = match (core.state.as_ref(), core.account_keys.as_ref()) {
            (Some(s), Some(k)) if s.joined() => Some((s.clone(), k.clone())),
            _ => None,
        };
        (core.generation, snapshot, save_error)
    };
    let result = match (snapshot, save_error) {
        // 狀態還寫不進磁碟:不在未落盤的狀態上做任何網路操作。
        (_, Some(e)) => Err(e),
        // 這台正在更換同步碼:由更換流程推進(第 2 步裡面會跑一般輪次)。
        (Some((s, keys)), None) if s.rotation.is_some() && s.frozen().is_none() => {
            crate::sync::rotation::drive_rotation(env, generation, s, keys)
        }
        (Some((s, keys)), None) => run_round(env, generation, s, keys, true).map(|_| ()),
        (None, None) => Ok(()),
    };
    env.runtime.syncing.store(false, Ordering::SeqCst);
    let outcome = match result {
        Ok(()) => Ok(()),
        Err(e) if is_superseded(&e) => Ok(()),
        Err(e) => {
            let mut core = env.runtime.core.lock().unwrap();
            if core.generation == generation {
                note_error(&mut core, env, &e);
            }
            Err(e)
        }
    };
    // 更換同步碼的最後一步留下的 keychain 換碼:補做(`rotation::retry_pending_swap`;沒有待補的就什麼都不做)。
    crate::sync::rotation::retry_pending_swap(env);
    env.events.status();
    outcome
}

/// 把一輪的錯誤寫進 `last_error` 並存檔(存不了就留在記憶體,`unsaved` 讓下一輪先補寫)。呼叫端持有 core 鎖。
fn note_error(core: &mut SyncCore, env: &SyncEnv, e: &AppError) {
    if let Some(s) = core.state.as_mut() {
        s.last_error = Some(e.to_string());
    }
    let _ = save_core(core, &env.state_path);
}

/// relay 的能力(spec §6.4):每個行程、每個 relay URL 查一次 `GET /v1/info`(用這一輪的連線,結果照 `check_relay` 記下);查不到
/// (離線等)就當作未知、先試批次。被限流(`429`)回 `Err`:不能當成「支援批次」照樣送出批次查詢 —— 呼叫端這一輪不再對 relay 發
/// 任何請求、以退避收尾。
fn relay_supports_batch(env: &SyncEnv, s: &SyncStateV2, relay: &dyn RelayApi) -> Result<bool, RelayError> {
    let checked = env.runtime.core.lock().unwrap().relay_checked.as_deref() == Some(s.relay_url.as_str());
    let features = if checked {
        s.relay_features.clone().filter(|f| f.url == s.relay_url)
    } else {
        match relay.info() {
            Ok(info) => Some(record_relay_info(env, &s.relay_url, &info)),
            Err(RelayError::RateLimited) => return Err(RelayError::RateLimited),
            Err(_) => None,
        }
    };
    Ok(features.is_none_or(|f| f.supports(FEATURE_PULL_BATCH)))
}

/// 這台已偵測到帳戶被更換同步碼(spec §7.5):不做任何網路寫入。只收到 push `409 frozen`、還沒有標記時,讀帳戶 chain
/// 取得標記(誰更換的),好讓狀態列說明。那一次讀取被限流(`429`)或 relay 出錯(`5xx`)時同 `finish`:這一輪以退避收尾
/// (`note_backoff`:連續失敗的輪數加一、狀態列說明),不立刻再查;讀到了就把計數歸零、清掉之前留下的退避說明。
fn refresh_markers(env: &SyncEnv, generation: u64, s: &SyncStateV2, keys: &ChainKeys, relay: &dyn RelayApi) -> Result<RoundOutcome, AppError> {
    if s.frozen().is_some_and(|f| !f.markers.is_empty()) {
        return Ok(RoundOutcome::default());
    }
    let pulled = match relay.pull(&keys.chain_id, &keys.auth_token, 0) {
        Ok(pulled) => pulled,
        Err(RelayError::RateLimited) => {
            note_backoff(env, generation, true, false);
            return Ok(RoundOutcome { backoff: true, ..RoundOutcome::default() });
        }
        Err(RelayError::Http(code)) if code >= 500 => {
            note_backoff(env, generation, false, true);
            return Ok(RoundOutcome { backoff: true, ..RoundOutcome::default() });
        }
        Err(e) => return Err(e.into()),
    };
    env.runtime.core.lock().unwrap().failed_rounds = 0;
    let markers = merge_account(&AccountState::new(&keys.chain_id), keys, &pulled).markers;
    let backoff_message = |m: Option<&str>| m.is_some_and(|m| m == RATE_LIMITED_MESSAGE || m == RELAY_TROUBLE_MESSAGE);
    if !markers.is_empty() || backoff_message(s.last_error.as_deref()) {
        commit(env, generation, |latest| {
            if !markers.is_empty() {
                if let Some(f) = latest.account.as_mut().and_then(|a| a.frozen.as_mut()) {
                    f.markers = markers;
                }
            }
            if backoff_message(latest.last_error.as_deref()) {
                latest.last_error = None;
            }
            Ok(())
        })?;
    }
    Ok(RoundOutcome::default())
}

fn space_name(account: Option<&AccountState>, space_id: &str) -> String {
    account.and_then(|a| space_entry(a, space_id)).map(|e| e.name).unwrap_or_else(|| space_id[..8.min(space_id.len())].to_string())
}

/// 記下凍結(push `409 frozen`,spec §6.4):這一輪停止所有上傳、保留 dirty;下一輪讀帳戶 chain 取得標記。
fn mark_frozen(env: &SyncEnv, generation: u64) -> Result<(), AppError> {
    let now = env.now();
    commit(env, generation, |latest| {
        if let Some(account) = latest.account.as_mut() {
            if account.frozen.is_none() {
                account.frozen = Some(FreezeInfo { detected_at_ms: now, markers: Vec::new() });
            }
        }
        Ok(())
    })
}

/// 一輪(spec §7.1)。`generation`/`s`/`keys` 是 `sync_once` 在同一把 core 鎖內取得的快照。回傳 `RoundOutcome`:
/// - `frozen`:上傳撞到凍結的 chain(`409 frozen`),這一輪的上傳到此為止、dirty 保留;
/// - `markers`:拉帳戶 chain 時看到的更換標記(`meta` `rotation:*`),這一輪在套用、上傳任何東西之前就停了;
/// - `backoff`:這一輪以被限流或 relay 出錯收尾(含拿不到帳戶、`GET /v1/info` 被限流、提早結束的那幾種),連續失敗的輪數已經加一、
///   狀態列已經說明 —— 呼叫端不要立刻再跑,等 `next_delay`。
///
/// `mark_frozen_chains` = false 時(這台自己正在更換同步碼,spec §7.5 第 2 步)凍結與更換標記都**不記進狀態**,只回報給呼叫端,
/// 讓不讓給對方由它決定;true 時兩者都記下(`frozen`,之後的輪次不做任何網路寫入)。
pub fn run_round(env: &SyncEnv, generation: u64, s: SyncStateV2, keys: ChainKeys, mark_frozen_chains: bool) -> Result<RoundOutcome, AppError> {
    let relay = env.relay(&s.relay_url)?;
    if s.frozen().is_some() {
        return refresh_markers(env, generation, &s, &keys, relay.as_ref());
    }
    let batch = match relay_supports_batch(env, &s, relay.as_ref()) {
        Ok(batch) => batch,
        // `GET /v1/info` 被限流:這一輪不再對 relay 發任何請求(什麼都沒同步到,不更新 `last_sync_ms`),退避之後再試。
        Err(_) => {
            finish(env, generation, &s, None, 0, true, false)?;
            return Ok(RoundOutcome { backoff: true, ..RoundOutcome::default() });
        }
    };

    // 1. space 檔與 Include 清單。doc 還沒載入:安靜跳過(config 載入時會喚醒下一輪)。
    let prepared = match prepare_files(env) {
        Ok(Some(prepared)) => prepared,
        Ok(None) => return Ok(RoundOutcome::default()),
        // 主 config 在載入之後被外部改過、Include 清單寫不進去:`prepare_files` 已經重載 doc,並在放掉所有鎖之後發過
        // `applied(0)`(這裡不再發)。不是要顯示的錯誤:下一輪以磁碟上的內容重做,馬上跑。
        Err(AppError::Conflict(_)) => {
            env.events.wake();
            return Ok(RoundOutcome::default());
        }
        Err(e) => {
            // `prepare_files` 讀寫的是最新的狀態,可能先換了 generation(重新長出不見的 space 檔、做完取消勾選)才失敗;
            // `sync_once` 只把錯誤寫在產生它的那一代狀態上,這時錯誤會晚一輪才出現 —— generation 變了就在這裡寫。
            let mut core = env.runtime.core.lock().unwrap();
            if core.generation != generation {
                note_error(&mut core, env, &e);
            }
            return Err(e);
        }
    };
    if prepared.reloaded {
        env.events.applied(0);
    }
    if env.runtime.core.lock().unwrap().generation != generation {
        // 準備檔案時改了狀態(重新長出不見的檔案、做完取消勾選):這一輪的快照已作廢。
        env.events.wake();
        return Ok(RoundOutcome::default());
    }

    // 2. 讀檔、不變式(以 space 為單位:違反的 space 這一輪跳過,其他照常)。chain 不見了的 space 等使用者處理。
    let mut targets: Vec<(String, PathBuf)> = Vec::new();
    for (id, sp) in s.spaces.iter().filter(|(_, sp)| sp.selected && !sp.missing) {
        targets.push((id.clone(), space_path(env, &sp.file_name)?));
    }
    let (gathered, reloaded) = gather(env, &targets)?;
    if reloaded {
        env.events.applied(0);
    }
    let now = env.now();
    let mut work = s.clone();
    let mut healthy: BTreeMap<String, Gathered> = BTreeMap::new();
    let mut paused: BTreeMap<String, String> = BTreeMap::new();
    let mut rerun = false;
    for (id, result) in gathered {
        match result {
            Err(message) => {
                paused.insert(id, message);
            }
            Ok(g) => {
                let sp = work.spaces.get_mut(&id).expect("gathered from the snapshot");
                if space_emptied(&g.blocks, sp) {
                    // space 檔被清空、快取裡卻還有主機:從 chain 重新長出(下一輪是基線輪),不做本機 diff。
                    reset_space_for_rematerialize(sp);
                    eprintln!("[sync] a space file was emptied; restoring its hosts from the sync chain");
                    rerun = true;
                    paused.insert(id, String::new());
                    continue;
                }
                healthy.insert(id, g);
            }
        }
    }

    // 3. 本機 diff(外部編輯,時間戳 = 檔案 mtime)與裝置心跳 → dirty,在任何網路操作前持久化。有東西變了才存:平常什麼都沒
    //    變的一輪不必先重寫一次狀態檔(每次都是整份 JSON 重寫加 fsync)。
    let device_id = work.device_id.clone();
    let mut changed = false;
    for (id, g) in &healthy {
        let sp = work.spaces.get_mut(id).expect("healthy space");
        if sp.baseline_established {
            let external_at = g.modified_ms.min(now);
            changed |= plan_hosts(sp, &g.blocks, &device_id, |_| external_at) > 0;
        }
    }
    let selected: Vec<String> = work.spaces.iter().filter(|(_, sp)| sp.selected).map(|(id, _)| id.clone()).collect();
    let (name, platform) = (work.device_name.clone(), env.platform);
    changed |= plan_device(work.account.as_mut().expect("joined"), &device_id, &name, platform, &selected, now);
    // 暫停的 space:重新長出的(訊息是空的)一定要存;違反不變式的,訊息和狀態裡的一樣就不必再存。
    changed |= paused
        .iter()
        .any(|(id, message)| message.is_empty() || s.spaces.get(id).and_then(|sp| sp.last_error.as_deref()) != Some(message.as_str()));
    if changed {
        commit(env, generation, |latest| {
            latest.account = work.account.clone();
            for (id, message) in &paused {
                if let (Some(l), Some(w)) = (latest.spaces.get_mut(id), work.spaces.get(id)) {
                    *l = w.clone();
                    if !message.is_empty() {
                        l.last_error = Some(message.clone());
                    }
                }
            }
            for id in healthy.keys() {
                if let (Some(l), Some(w)) = (latest.spaces.get_mut(id), work.spaces.get(id)) {
                    *l = w.clone();
                }
            }
            Ok(())
        })?;
    }
    if rerun && healthy.is_empty() {
        env.events.wake();
        return Ok(RoundOutcome::default());
    }

    // 4. 一個批次請求:帳戶 chain 一律排第一;舊 relay 的 space 每 3 輪查一次 —— 但還有沒上傳的記錄的 space(上一次的上傳撞到
    //    衝突、或剛修改過)每一輪都查:不先拿到 relay 上的版本,上傳只會一直撞衝突,連續 3 輪之後還會誤報「relay 上有這個
    //    SSHelter 讀不懂的版本」。唯讀的帳戶例外:它從不上傳,dirty 的記錄一直都在,照這條規則會每一輪都查。
    let rounds = {
        let mut core = env.runtime.core.lock().unwrap();
        core.rounds += 1;
        core.rounds
    };
    let account = work.account.clone().expect("joined");
    let mut items = vec![BatchPullItem { chain: keys.chain_id.clone(), token: keys.auth_token.clone(), since: account.cursor_seq }];
    let legacy_slot = rounds % LEGACY_SPACE_EVERY == 1;
    let uploads = !work.read_only();
    for id in healthy.keys() {
        if !(batch || legacy_slot || (uploads && work.spaces[id].records.values().any(|l| l.dirty))) {
            continue;
        }
        if let Some(space) = space_keys(&account, &keys, id) {
            items.push(BatchPullItem { chain: space.chain_id, token: space.auth_token, since: work.spaces[id].cursor_seq });
        }
    }
    let batch_failures = env.runtime.core.lock().unwrap().batch_failures;
    let pulled_all = pull_all(relay.as_ref(), &items, batch, batch_failures).map_err(AppError::from)?;
    {
        let mut core = env.runtime.core.lock().unwrap();
        if pulled_all.batch_failed {
            core.batch_failures = core.batch_failures.saturating_add(1);
        } else if pulled_all.batch_ok {
            core.batch_failures = 0;
        }
    }
    let (mut fetched, mut limited, mut failed) = (pulled_all.fetched, pulled_all.limited, pulled_all.failed);

    // 5. 帳戶的結果一律先處理。
    let pulled = match fetched.remove(&keys.chain_id) {
        Some(Fetched::Ok(p)) => p,
        Some(Fetched::NotFound) => return Err(AppError::Other(ACCOUNT_GONE_MESSAGE.to_string())),
        Some(Fetched::Missed) | None => {
            // 沒拿到帳戶(被限流、relay 出錯):不處理任何 space、不上傳,退避後再試。什麼都沒同步到,所以不更新
            // `last_sync_ms`;沒有 429 / 5xx 的訊號卻拿不到(relay 一項都沒執行)也當成 relay 出錯。
            failed = failed || !limited;
            finish(env, generation, &work, None, 0, limited, failed)?;
            return Ok(RoundOutcome { backoff: true, ..RoundOutcome::default() });
        }
    };
    let merged_account = merge_account(&account, &keys, &pulled);
    if merged_account.skipped > 0 {
        eprintln!("[sync] {} account record(s) could not be read and were skipped", merged_account.skipped);
    }
    if !merged_account.markers.is_empty() {
        let markers = merged_account.markers;
        // 這台自己正在更換同步碼(`mark_frozen_chains` = false)時不記進狀態,只回報給呼叫端(spec §7.5「兩台同時更換」:
        // 讓不讓給對方由它決定);兩種情況這一輪都在套用任何東西、上傳任何東西之前就停了。
        if mark_frozen_chains {
            commit(env, generation, |latest| {
                if let Some(a) = latest.account.as_mut() {
                    a.frozen = Some(FreezeInfo { detected_at_ms: now, markers: markers.clone() });
                }
                Ok(())
            })?;
        }
        note_backoff(env, generation, limited, failed);
        return Ok(RoundOutcome { markers, backoff: limited || failed, ..RoundOutcome::default() });
    }
    work.account = Some(merged_account.section);
    let reconciled = match commit_account(env, generation, work.account.as_ref().expect("joined")) {
        Ok((reconciled, committed)) if reconciled.touched => {
            for notice in &reconciled.notices {
                env.events.notice(notice);
            }
            // 改名或刪除了 space 檔:這一輪拉到的 space 結果作廢(cursor 沒推進),立刻重跑 —— 被限流或 relay 出錯了就等退避。
            env.events.applied(0);
            note_backoff(env, committed, limited, failed);
            if !limited && !failed {
                env.events.wake();
            }
            return Ok(RoundOutcome { backoff: limited || failed, ..RoundOutcome::default() });
        }
        Ok((reconciled, _)) => reconciled,
        // 帳戶已經存檔;調整 space 檔時主 config 在載入之後被外部改過:`commit_account` 已發過 `applied(0)`,檔案那一半
        // 由下一輪做完,馬上跑(不是要顯示的錯誤)。這一輪被限流或 relay 出錯了就不立刻重跑,等退避。
        Err(AppError::Conflict(_)) => {
            note_backoff(env, generation, limited, failed);
            if !limited && !failed {
                env.events.wake();
            }
            return Ok(RoundOutcome { backoff: limited || failed, ..RoundOutcome::default() });
        }
        Err(e) => return Err(e),
    };
    for notice in &reconciled.notices {
        env.events.notice(notice);
    }

    // 6. 逐一提交 space:每個都是獨立交易,失敗不回退其他已提交的部分。
    let account_now = work.account.clone().expect("joined");
    let mut applied_hosts = 0usize;
    let mut conflicts: Vec<SyncConflict> = Vec::new();
    let mut held: Vec<ApprovalNotice> = Vec::new();
    for (id, g) in &healthy {
        let Some(space) = space_keys(&account_now, &keys, id) else {
            space_error(env, generation, id, MISSING_KEY_MESSAGE)?;
            continue;
        };
        let pulled = match fetched.remove(&space.chain_id) {
            Some(Fetched::Ok(p)) => p,
            Some(Fetched::NotFound) => {
                // 帳戶仍有這個 space(已 tombstone 的在上一步就移除了):暫停,等使用者選重建或刪除(spec §9)。
                commit(env, generation, |latest| {
                    if let Some(sp) = latest.spaces.get_mut(id) {
                        sp.missing = true;
                        sp.last_error = Some(SPACE_GONE_MESSAGE.to_string());
                    }
                    Ok(())
                })?;
                work.spaces.get_mut(id).expect("healthy").missing = true;
                continue;
            }
            Some(Fetched::Missed) | None => continue,
        };
        let section = work.spaces[id].clone();
        let merged = merge_space(&section, &space, &pulled, &g.blocks, |d| device_name(&account_now, d));
        if merged.skipped > 0 {
            eprintln!("[sync] {} remote record(s) could not be read and were skipped", merged.skipped);
        }
        let mut next = merged.section;
        let mut effects = merged.effects;
        if !section.baseline_established {
            // 基線輪(剛勾選,或 space 檔不見了 / 被清空):以 chain 為準;重新長出時保留的未上傳修改一起寫回。
            effects.extend(unpushed_host_effects(&next, &g.blocks));
            next.baseline_established = true;
            rerun = true;
        }
        next.last_error = None;
        let path = space_path(env, &section.file_name)?;
        match apply_and_commit_space(env, generation, id, &path, &g.fingerprint, &effects, &next) {
            Ok(Applied::FileChanged) => rerun = true,
            Ok(Applied::Committed { wrote, save_error }) => {
                if wrote {
                    applied_hosts += effects.len();
                }
                let name = space_name(Some(&account_now), id);
                if !merged.conflicts.is_empty() {
                    conflicts.push(SyncConflict { space_id: id.clone(), space_name: name.clone(), aliases: merged.conflicts });
                }
                if !merged.held.is_empty() {
                    held.push(ApprovalNotice { space_id: id.clone(), space_name: name, aliases: merged.held });
                }
                work.spaces.insert(id.clone(), next);
                if let Some(e) = save_error {
                    announce(env, applied_hosts, &conflicts, &held);
                    return Err(e); // 狀態沒落盤:不在未落盤的狀態上上傳
                }
            }
            Err(e) if is_superseded(&e) => {
                announce(env, applied_hosts, &conflicts, &held);
                return Err(e);
            }
            Err(e) => space_error(env, generation, id, &e.to_string())?,
        }
    }
    announce(env, applied_hosts, &conflicts, &held);

    // 7. 上傳(唯讀模式不上傳)。帳戶與各 space 分開;撞到凍結的 chain 就停止這一輪所有上傳。被限流(任何一個 `429`)之後
    //    這一輪不再對 relay 發任何請求:不上傳、不刪 chain。
    let read_only = work.read_only();
    let mut push_conflicts = 0usize;
    if !read_only && !limited {
        let account = work.account.clone().expect("joined");
        let outgoing = account_outgoing(&account, &keys)?;
        if !outgoing.is_empty() {
            // 先記下已被接受的批次(凍結或出錯之前送出的照樣算數),再看凍結,最後才看錯誤。
            let pushed = push_outgoing(relay.as_ref(), &keys.chain_id, &keys.auth_token, &outgoing);
            push_conflicts += pushed.conflicts;
            if !pushed.accepted.is_empty() {
                commit(env, generation, |latest| {
                    if let Some(a) = latest.account.as_mut() {
                        apply_pushed_account(a, &outgoing, &pushed);
                    }
                    Ok(())
                })?;
                if let Some(a) = work.account.as_mut() {
                    apply_pushed_account(a, &outgoing, &pushed);
                }
            }
            if pushed.frozen {
                return frozen_out(env, generation, mark_frozen_chains, limited, failed);
            }
            match pushed.error {
                None => {}
                Some(RelayError::RateLimited) => limited = true,
                Some(RelayError::Http(code)) if code >= 500 => failed = true,
                // 帳戶 chain 的上傳被拒(儲存額度滿了、relay 認為請求不合規格、回答對不上):同一份上傳下一輪還會再被拒 —— 這一輪
                // 結束,而且算失敗(`failed_rounds`,退避);錯誤本身由 `sync_once` 寫進 `last_error`。
                Some(e @ (RelayError::QuotaExceeded | RelayError::InvalidRequest(_) | RelayError::BadResponse(_))) => {
                    let mut core = env.runtime.core.lock().unwrap();
                    core.failed_rounds = core.failed_rounds.saturating_add(1);
                    return Err(e.into());
                }
                // 連不上 relay 這類傳輸的錯誤:整輪結束(同 v1,不退避)。
                Some(e) => return Err(e.into()),
            }
        }
        if !limited {
            let (chain_limited, chain_failed) = delete_chains(env, generation, &work, &keys, relay.as_ref())?;
            limited |= chain_limited;
            failed |= chain_failed;
        }
        for id in healthy.keys() {
            if limited {
                break;
            }
            let Some(section) = work.spaces.get(id).filter(|sp| !sp.missing) else { continue };
            let Some(space) = space_keys(work.account.as_ref().expect("joined"), &keys, id) else { continue };
            let outgoing = space_outgoing(section, &space)?;
            if outgoing.is_empty() {
                continue;
            }
            // 同帳戶:先記下已被接受的批次,再看凍結,最後才看錯誤。
            let pushed = push_outgoing(relay.as_ref(), &space.chain_id, &space.auth_token, &outgoing);
            push_conflicts += pushed.conflicts;
            if !pushed.accepted.is_empty() {
                commit(env, generation, |latest| {
                    if let Some(sp) = latest.spaces.get_mut(id) {
                        apply_pushed_space(sp, &outgoing, &pushed);
                    }
                    Ok(())
                })?;
            }
            if pushed.frozen {
                return frozen_out(env, generation, mark_frozen_chains, limited, failed);
            }
            match pushed.error {
                None => {}
                Some(RelayError::RateLimited) => limited = true,
                Some(RelayError::Http(code)) if code >= 500 => failed = true,
                Some(RelayError::NotFound) => {
                    commit(env, generation, |latest| {
                        if let Some(sp) = latest.spaces.get_mut(id) {
                            sp.missing = true;
                            sp.last_error = Some(SPACE_GONE_MESSAGE.to_string());
                        }
                        Ok(())
                    })?;
                }
                // 只屬於這條 chain 的問題(儲存額度滿了、relay 認為請求不合規格、回答對不上):記在這個 space 上讓它暫停,
                // 其他 space 照常上傳。額度滿了算這一輪失敗(退避):同樣的上傳不必每一輪都再送一次。
                Some(RelayError::QuotaExceeded) => {
                    let name = space_name(work.account.as_ref(), id);
                    space_error(env, generation, id, &format!("space \"{name}\" is over the relay's storage limit: remove hosts or large blocks from it"))?;
                    failed = true;
                }
                Some(e @ (RelayError::InvalidRequest(_) | RelayError::BadResponse(_))) => {
                    let name = space_name(work.account.as_ref(), id);
                    space_error(
                        env,
                        generation,
                        id,
                        &format!("space \"{name}\" could not be uploaded ({e}); sync retries — if this keeps happening, update SSHelter or the relay"),
                    )?;
                }
                // 連不上 relay 這類傳輸的錯誤:整輪結束。
                Some(e) => return Err(e.into()),
            }
        }
    }

    // 8. 收尾:最後同步時間、狀態列訊息、衝突重跑與退避。被限流或 relay 出錯的一輪不立刻重跑 —— 推送衝突的 `retry` 已經排除
    //    這兩種,基線輪、檔案在讀取後被改過的 `rerun` 也一樣,等退避。
    let retry = finish(env, generation, &work, Some(now), push_conflicts, limited, failed)?;
    if retry || (rerun && !limited && !failed) {
        env.events.wake();
    }
    Ok(RoundOutcome { backoff: limited || failed, ..RoundOutcome::default() })
}

/// 提交帳戶區段(spec §7.1 第 5 步)並依新的記錄調整這台的 space 檔(改名、別台刪除、Include 順序)。動了檔案就
/// 重載 doc、換 generation —— 這一輪的 space 結果作廢。回傳調整的結果與提交之後的 generation(動了檔案就是換過的那一個)。
///
/// 調整檔案失敗(`reconcile_space_files` 的任何 Err):doc 可能已被它整份重載(`Conflict`,或前面的步驟已經動過檔案),
/// 所以放掉所有鎖之後發出失敗之前已經存進狀態的提示與 `applied(0)`,再回傳這個 Err。帳戶區段在那之前已經存檔;`Conflict`
/// (主 config 在載入之後被外部改過)由呼叫端當成「下一輪做完、馬上重跑」。
fn commit_account(env: &SyncEnv, generation: u64, account: &AccountState) -> Result<(Reconciled, u64), AppError> {
    let mut doc_lock = env.doc.lock().unwrap();
    {
        let mut core = env.runtime.core.lock().unwrap();
        if core.generation != generation {
            return Err(crate::sync::runtime::superseded());
        }
        if let Some(s) = core.state.as_mut() {
            s.account = Some(account.clone());
        }
        save_core(&mut core, &env.state_path)?;
    }
    let Some(doc) = doc_lock.as_mut() else { return Ok((Reconciled::default(), generation)) };
    let mut backed_up = env.backed_up.lock().unwrap();
    let result = reconcile_space_files(env, doc, &mut backed_up, env.retention());
    drop(backed_up);
    let reconciled = match result {
        Ok(reconciled) => reconciled,
        Err(ReconcileError { error, notices }) => {
            drop(doc_lock);
            for notice in &notices {
                env.events.notice(notice);
            }
            env.events.applied(0);
            return Err(error);
        }
    };
    if !reconciled.touched {
        return Ok((reconciled, generation));
    }
    let main = doc.files[0].path.clone();
    match env.load_doc(&main) {
        Ok(fresh) => *doc_lock = Some(fresh),
        Err(e) => {
            drop(doc_lock);
            for notice in &reconciled.notices {
                env.events.notice(notice);
            }
            return Err(e);
        }
    }
    // 仍持有 doc 鎖:每個換 generation 的寫入者都持有它,所以換過之後的就是這一個。
    let mut core = env.runtime.core.lock().unwrap();
    core.generation += 1;
    Ok((reconciled, core.generation))
}

/// 只屬於一個 space 的錯誤(spec §9):記在那個 space 上,這一輪跳過它,其他照常。
fn space_error(env: &SyncEnv, generation: u64, space_id: &str, message: &str) -> Result<(), AppError> {
    commit(env, generation, |latest| {
        if let Some(sp) = latest.spaces.get_mut(space_id) {
            sp.last_error = Some(message.to_string());
        }
        Ok(())
    })
}

/// push 撞到凍結的 chain(spec §6.4):停止這一輪所有上傳、保留 dirty。這一輪在撞到凍結之前已經被限流或 relay 出錯
/// (`limited` / `failed`)就以退避收尾(`note_backoff`、`RoundOutcome::backoff`)。
fn frozen_out(env: &SyncEnv, generation: u64, mark: bool, limited: bool, failed: bool) -> Result<RoundOutcome, AppError> {
    if mark {
        mark_frozen(env, generation)?;
    }
    note_backoff(env, generation, limited, failed);
    Ok(RoundOutcome { frozen: true, backoff: limited || failed, ..RoundOutcome::default() })
}

/// 提早結束、以退避收尾的一輪(更換標記、主 config 衝突、改了 space 檔、凍結;回報 `RoundOutcome::backoff`):同 `finish`,連續
/// 失敗的輪數加一、狀態列說明被限流或 relay 出錯 —— 背景執行緒等多久(`next_delay`)才會和回報的 `backoff` 一致。`last_error` 只寫在
/// `generation` 那一代的狀態上(同 `sync_once`:別的命令換過 generation,這個說明就不屬於它)。沒被限流、relay 也沒出錯就什麼都不做。
/// 更換同步碼的第 3 至 7 步失敗時也用它(`rotation::step_failed`),退避的規則和一般輪次一致。
pub(crate) fn note_backoff(env: &SyncEnv, generation: u64, limited: bool, failed: bool) {
    if !(limited || failed) {
        return;
    }
    let mut core = env.runtime.core.lock().unwrap();
    core.failed_rounds = core.failed_rounds.saturating_add(1);
    if core.generation != generation {
        return;
    }
    if let Some(s) = core.state.as_mut() {
        s.last_error = Some(if limited { RATE_LIMITED_MESSAGE } else { RELAY_TROUBLE_MESSAGE }.to_string());
    }
    // 存不了就留在記憶體(`unsaved`),下一輪先補寫。
    let _ = save_core(&mut core, &env.state_path);
}

/// 刪除這台刪掉的 space 的 chain(spec §7.2):tombstone 都已上傳(`space` 與 `spacekey` 記錄不再 dirty)、而且這個
/// space 仍算已刪除(`space_deleted_by`)才 `DELETE`;chain 已經不在也算完成。失敗的留到下一輪。回傳(被限流, relay 出錯):
/// `429` 就在那裡停(其餘的留到下一輪),呼叫端當成 `limited`、這一輪不再對 relay 發請求;`5xx` 算這一輪失敗(`failed`,退避),
/// 其餘的照常刪。
fn delete_chains(env: &SyncEnv, generation: u64, work: &SyncStateV2, keys: &ChainKeys, relay: &dyn RelayApi) -> Result<(bool, bool), AppError> {
    let Some(account) = work.account.as_ref() else { return Ok((false, false)) };
    let mut done = Vec::new();
    let (mut limited, mut failed) = (false, false);
    for sealed in &account.chain_deletes {
        let Ok(record) = sealed.open(keys) else {
            done.push(sealed.envelope.ciphertext.clone()); // 打不開的不可能刪得掉
            continue;
        };
        if space_deleted_by(account, keys, &record.id).is_none() {
            done.push(sealed.envelope.ciphertext.clone()); // 刪除被取代了(兩筆 tombstone 都輸給較新的記錄):不刪
            continue;
        }
        let uploaded = !account.records.get(&record_key(RecordKind::Space, &record.id)).is_some_and(|l| l.dirty)
            && !account.sealed.get(&space_key_slot(keys, &record.id)).is_some_and(|s| s.dirty);
        if !uploaded {
            continue; // tombstone 還沒上傳
        }
        let Ok(space) = serde_json::from_value::<SpaceKeyPayload>(record.payload).map_err(|_| ()).and_then(|p| p.to_keys(&record.id).map_err(|_| ())) else {
            done.push(sealed.envelope.ciphertext.clone());
            continue;
        };
        match relay.delete_chain(&space.chain_id, &space.auth_token) {
            Ok(()) | Err(RelayError::NotFound) => done.push(sealed.envelope.ciphertext.clone()),
            Err(RelayError::RateLimited) => {
                limited = true;
                break;
            }
            Err(e) => {
                failed |= matches!(e, RelayError::Http(code) if code >= 500);
                eprintln!("[sync] could not delete a removed space's chain yet: {e}");
            }
        }
    }
    if !done.is_empty() {
        commit(env, generation, |latest| {
            if let Some(a) = latest.account.as_mut() {
                a.chain_deletes.retain(|s| !done.contains(&s.envelope.ciphertext));
            }
            Ok(())
        })?;
    }
    Ok((limited, failed))
}

fn announce(env: &SyncEnv, applied: usize, conflicts: &[SyncConflict], held: &[ApprovalNotice]) {
    if applied > 0 {
        env.events.applied(applied);
    }
    if !conflicts.is_empty() {
        env.events.conflict(conflicts);
    }
    if !held.is_empty() {
        env.events.approval(held);
    }
}

/// 一輪的收尾:`last_sync_ms`、狀態列訊息(衝突一直解不開 / 被限流 / relay 出錯 / 唯讀)、
/// 連續衝突與退避的輪數。回傳是否要因為推送衝突立刻再跑一輪(被限流或 relay 出錯時不立刻重跑)。`synced_at` = 這一輪完成
/// 了帳戶的拉取的時間;沒拿到帳戶的那一輪是 `None`(什麼都沒同步到,不更新 `last_sync_ms`)。
fn finish(env: &SyncEnv, generation: u64, work: &SyncStateV2, synced_at: Option<u64>, conflicts: usize, limited: bool, failed: bool) -> Result<bool, AppError> {
    let mut core = env.runtime.core.lock().unwrap();
    if core.generation != generation {
        return Err(crate::sync::runtime::superseded());
    }
    let streak = if conflicts == 0 { 0 } else { core.conflict_streak.saturating_add(1) };
    let stuck = streak >= CONFLICT_RETRY_LIMIT;
    core.conflict_streak = streak;
    core.failed_rounds = if limited || failed { core.failed_rounds.saturating_add(1) } else { 0 };
    let read_only = work.read_only();
    if let Some(s) = core.state.as_mut() {
        if synced_at.is_some() {
            s.last_sync_ms = synced_at;
        }
        s.last_error = if stuck {
            Some(STUCK_CONFLICTS_MESSAGE.to_string())
        } else if limited {
            Some(RATE_LIMITED_MESSAGE.to_string())
        } else if failed {
            Some(RELAY_TROUBLE_MESSAGE.to_string())
        } else {
            read_only.then(|| READ_ONLY_MESSAGE.to_string())
        };
    }
    save_core(&mut core, &env.state_path)?;
    Ok(conflicts > 0 && !stuck && !limited && !failed)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::sync::account::{create_account, join_account};
    use crate::sync::fake_relay::FakeRelay;
    use crate::sync::merge::{put_account_record, space_entries};
    use crate::sync::record::{rotation_meta_id, RotationMarkerPayload};
    use crate::sync::spaces::{approve, create_space, delete_space, reject, rename_space, select_space, Reviewed};
    use crate::sync::state_v2::SyncNotice;
    use crate::sync::env::{Clock, RelayConnector};
    use crate::sync::relay::{BatchPullEntry, PushItem, PushOutcome, RelayInfo};
    use crate::sync::testkit::{AppliedProbe, TestClock, TestDevice};
    use std::sync::atomic::AtomicUsize;
    use std::sync::Arc;

    /// 跑到不再要求立刻重跑為止(最多 10 輪)。
    pub(crate) fn settle(d: &TestDevice) {
        for _ in 0..10 {
            let before = d.events.wakes();
            let _ = sync_once(&d.env());
            if d.events.wakes() == before {
                return;
            }
        }
        panic!("sync never settled");
    }

    /// A 建立帳戶(Personal),B 加入並勾選 Personal;兩台都同步完。
    pub(crate) fn pair() -> (Arc<FakeRelay>, Arc<TestClock>, TestDevice, TestDevice, String, String) {
        let (relay, clock) = (FakeRelay::new(), TestClock::new());
        let a = TestDevice::new("a", &relay, &clock);
        let b = TestDevice::new("b", &relay, &clock);
        let words = create_account(&a.env(), "MacBook-A").unwrap();
        settle(&a);
        join_account(&b.env(), &words, "MacBook-B").unwrap();
        let personal = a.state().spaces.keys().next().unwrap().clone();
        select_space(&b.env(), &personal).unwrap();
        settle(&b);
        settle(&a);
        (relay, clock, a, b, words, personal)
    }

    /// 核准對話框顯示的內容:這個 space 每台等待核准的主機與那一版的內容指紋(`approve` / `reject` 只認使用者看過的那一版)。
    pub(crate) fn shown(d: &TestDevice, space_id: &str) -> Vec<(String, String)> {
        d.state().spaces[space_id].pending_approvals.iter().map(|(alias, p)| (alias.clone(), crate::sync::spaces::review_digest(p))).collect()
    }

    #[test]
    fn a_host_saved_on_one_device_arrives_on_the_other() {
        let (_relay, _clock, a, b, _words, personal) = pair();
        a.save_in_app(&a.space_path(&personal), "Host web\n  HostName 10.0.0.1\n");
        settle(&a);
        settle(&b);
        assert_eq!(b.read(&b.space_path(&personal)), "Host web\n  HostName 10.0.0.1\n");
        assert!(b.state().spaces[&personal].records.values().all(|l| !l.dirty));
        // 外部編輯(另一個編輯器)也一樣,反方向。
        b.write_externally(&b.space_path(&personal), "Host web\n  HostName 10.0.0.2\n");
        settle(&b);
        settle(&a);
        assert_eq!(a.read(&a.space_path(&personal)), "Host web\n  HostName 10.0.0.2\n");
        assert!(a.events.applied.lock().unwrap().contains(&1));
    }

    #[test]
    fn spaces_created_renamed_and_deleted_on_one_device_follow_on_the_others() {
        let (relay, _clock, a, b, _words, _personal) = pair();
        let work = create_space(&a.env(), "Work").unwrap();
        a.save_in_app(&a.space_path(&work), "Host db\n");
        settle(&a);
        settle(&b);
        let entries = space_entries(b.state().account.as_ref().unwrap());
        assert!(entries.iter().any(|e| e.id == work && e.name == "Work"), "B sees the new space");
        assert!(!b.state().spaces.contains_key(&work), "but does not sync it until it is selected");
        select_space(&b.env(), &work).unwrap();
        settle(&b);
        assert_eq!(b.read(&b.space_path(&work)), "Host db\n");
        // A 改名:B 的檔案跟著改名、Include 跟著換。
        rename_space(&a.env(), &work, "Office").unwrap();
        settle(&a);
        settle(&b);
        let renamed = b.space_path(&work);
        assert_eq!(renamed.file_name().unwrap().to_string_lossy(), format!("office-{}.config", &work[..8]));
        assert_eq!(b.read(&renamed), "Host db\n");
        assert!(b.main_config().contains(&format!("office-{}.config", &work[..8])));
        assert!(!b.main_config().contains(&format!("work-{}.config", &work[..8])));
        // A 刪除:tombstone 上傳之後才刪 chain(上傳被限流的那一輪不刪);B 移除檔案與狀態,留下提示。
        delete_space(&a.env(), &work).unwrap();
        relay.fail_pushes_with_429(1);
        let _ = sync_once(&a.env());
        assert!(relay.exists(&work), "the tombstones are not on the relay yet");
        settle(&a);
        assert!(!relay.exists(&work), "the chain is deleted once the tombstones are on the relay");
        assert!(a.state().account.as_ref().unwrap().chain_deletes.is_empty());
        settle(&b);
        assert!(!renamed.exists());
        assert!(!b.state().spaces.contains_key(&work));
        assert!(b.state().notices.contains(&SyncNotice::SpaceDeleted { name: "Office".into(), by_device: "MacBook-A".into() }));
        assert!(b.events.notices.lock().unwrap().iter().any(|n| matches!(n, SyncNotice::SpaceDeleted { .. })));
    }

    #[test]
    fn a_delete_racing_a_rename_wins_everywhere() {
        let (relay, _clock, a, b, _words, _personal) = pair();
        let work = create_space(&a.env(), "Work").unwrap();
        settle(&a);
        settle(&b);
        select_space(&b.env(), &work).unwrap();
        settle(&b);
        // A 刪除(還沒上傳)的同時,B 改名並先上傳:B 的改名贏了 `space` 記錄,A 的 `spacekey` tombstone 卻照樣上去 ——
        // 沒有金鑰的 space 每台都當成已刪除,chain 也刪掉。
        delete_space(&a.env(), &work).unwrap();
        rename_space(&b.env(), &work, "Office").unwrap();
        settle(&b);
        settle(&a);
        assert!(!relay.exists(&work), "the delete wins: the spacekey tombstone outlives the rename");
        assert!(a.state().account.as_ref().unwrap().chain_deletes.is_empty());
        settle(&b);
        assert!(!b.state().spaces.contains_key(&work));
        assert!(b.state().notices.contains(&SyncNotice::SpaceDeleted { name: "Office".into(), by_device: "MacBook-A".into() }));
        assert!(select_space(&b.env(), &work).is_err(), "a deleted space cannot be selected again");
    }

    #[test]
    fn a_rename_never_overwrites_a_file_on_another_device() {
        let (_relay, _clock, a, b, _words, personal) = pair();
        let blocker = b.ssh_dir().join("sshelter").join(format!("lab-{}.config", &personal[..8]));
        std::fs::write(&blocker, "Host mine\n").unwrap();
        rename_space(&a.env(), &personal, "Lab").unwrap();
        settle(&a);
        settle(&b);
        assert_eq!(b.read(&blocker), "Host mine\n");
        assert!(b.space_path(&personal).ends_with(format!("personal-{}.config", &personal[..8])));
        let blocked = |name: &str| {
            b.state().notices.iter().filter(|n| matches!(n, SyncNotice::RenameBlocked { name: shown, .. } if shown == name)).count()
        };
        assert_eq!(blocked("Lab"), 1);
        // 使用者關掉提示之後,同一個目標仍被擋:每一輪都重試改名,但不再加回提示、也不再發 `sync://notice`。
        b.runtime.core.lock().unwrap().state.as_mut().unwrap().notices.clear();
        let emitted = b.events.notices.lock().unwrap().len();
        a.save_in_app(&a.space_path(&personal), "Host web\n");
        settle(&a);
        settle(&b);
        settle(&b);
        assert_eq!(blocked("Lab"), 0);
        assert_eq!(b.events.notices.lock().unwrap().len(), emitted);
        // 目標換了(又改名,新的檔名也被擋)→ 再提示一次。
        let garage = b.ssh_dir().join("sshelter").join(format!("garage-{}.config", &personal[..8]));
        std::fs::write(&garage, "Host theirs\n").unwrap();
        rename_space(&a.env(), &personal, "Garage").unwrap();
        settle(&a);
        settle(&b);
        assert_eq!(blocked("Garage"), 1);
        assert_eq!(b.events.notices.lock().unwrap().len(), emitted + 1);
        // 擋路的檔案移走之後,下一輪就改名,記號清掉;另一個擋路的檔案從頭到尾沒被動過。
        std::fs::remove_file(&garage).unwrap();
        settle(&b);
        assert!(b.space_path(&personal).ends_with(format!("garage-{}.config", &personal[..8])));
        assert!(b.state().spaces[&personal].rename_blocked.is_none());
        assert_eq!(b.read(&blocker), "Host mine\n");
    }

    #[test]
    fn each_space_commits_on_its_own_and_a_broken_space_pauses_alone() {
        let (_relay, _clock, a, b, _words, personal) = pair();
        let work = create_space(&a.env(), "Work").unwrap();
        settle(&a);
        settle(&b);
        select_space(&b.env(), &work).unwrap();
        settle(&b);
        // B 的 Personal 被手改成含 Include:只有它暫停。
        b.write_externally(&b.space_path(&personal), "Host x\n  Include ~/.ssh/extra.config\n");
        a.save_in_app(&a.space_path(&work), "Host db\n");
        a.save_in_app(&a.space_path(&personal), "Host web\n");
        settle(&a);
        let personal_cursor = b.state().spaces[&personal].cursor_seq;
        settle(&b);
        let s = b.state();
        assert!(s.spaces[&personal].last_error.as_deref().unwrap().contains("Include"));
        assert_eq!(s.spaces[&personal].cursor_seq, personal_cursor, "the paused space does not move");
        assert!(s.spaces[&work].last_error.is_none());
        assert_eq!(b.read(&b.space_path(&work)), "Host db\n", "the other space syncs as usual");
        // 修好之後照常同步。
        b.write_externally(&b.space_path(&personal), "Host x\n");
        settle(&b);
        settle(&a);
        assert!(b.state().spaces[&personal].last_error.is_none());
        assert!(a.read(&a.space_path(&personal)).contains("Host x\n"));
    }

    #[test]
    fn risky_settings_from_another_device_wait_for_approval() {
        let (_relay, _clock, a, b, _words, personal) = pair();
        b.save_in_app(&b.space_path(&personal), "Host web\n  HostName 10.0.0.1\n");
        settle(&b);
        settle(&a);
        a.save_in_app(&a.space_path(&personal), "Host web\n  HostName 10.0.0.1\n  ProxyCommand nc %h 22\n");
        settle(&a);
        settle(&b);
        assert_eq!(b.read(&b.space_path(&personal)), "Host web\n  HostName 10.0.0.1\n", "held, not applied");
        let approvals = b.events.approvals.lock().unwrap().clone();
        assert_eq!(approvals, vec![ApprovalNotice { space_id: personal.clone(), space_name: "Personal".into(), aliases: vec!["web".into()] }]);
        assert_eq!(b.state().spaces[&personal].pending_approvals["web"].from_device, "MacBook-A");
        // 下一輪也不會把舊版當成本機修改推回去。
        settle(&b);
        settle(&a);
        assert!(a.read(&a.space_path(&personal)).contains("ProxyCommand"));
        assert_eq!(approve(&b.env(), &personal, &shown(&b, &personal)).unwrap(), Reviewed { applied: 1, changed: Vec::new() });
        assert!(b.read(&b.space_path(&personal)).contains("ProxyCommand nc %h 22"));
        // 拒絕:B 維持原狀;之後 B 在本機修改,照 LWW 推送、蓋過 A 的版本。
        a.save_in_app(&a.space_path(&personal), "Host web\n  HostName 10.0.0.1\n  ProxyCommand nc evil.example 22\n");
        settle(&a);
        settle(&b);
        assert_eq!(reject(&b.env(), &personal, &shown(&b, &personal)).unwrap(), Reviewed { applied: 1, changed: Vec::new() });
        settle(&b);
        assert!(b.read(&b.space_path(&personal)).contains("nc %h 22"));
        b.save_in_app(&b.space_path(&personal), "Host web\n  HostName 10.0.0.9\n");
        settle(&b);
        settle(&a);
        assert_eq!(a.read(&a.space_path(&personal)), "Host web\n  HostName 10.0.0.9\n");
        assert!(b.state().spaces[&personal].records.values().all(|l| !l.dirty), "the push was not stuck on a conflict");
    }

    #[test]
    fn a_baseline_round_reviews_every_risky_host_at_once() {
        let (relay, clock) = (FakeRelay::new(), TestClock::new());
        let a = TestDevice::new("a", &relay, &clock);
        let words = create_account(&a.env(), "MacBook-A").unwrap();
        let personal = a.state().spaces.keys().next().unwrap().clone();
        a.save_in_app(&a.space_path(&personal), "Host web\n  ForwardAgent yes\nHost db\n  ProxyCommand nc %h 22\nHost plain\n");
        settle(&a);
        let b = TestDevice::new("b", &relay, &clock);
        join_account(&b.env(), &words, "MacBook-B").unwrap();
        select_space(&b.env(), &personal).unwrap();
        settle(&b);
        assert_eq!(b.read(&b.space_path(&personal)), "Host plain\n");
        let approvals = b.events.approvals.lock().unwrap().clone();
        assert_eq!(approvals.len(), 1, "one review for the whole baseline");
        assert_eq!(approvals[0].aliases, vec!["db".to_string(), "web".to_string()]);
        assert_eq!(approve(&b.env(), &personal, &shown(&b, &personal)).unwrap().applied, 2);
        let text = b.read(&b.space_path(&personal));
        assert!(text.contains("ForwardAgent yes") && text.contains("ProxyCommand"));
    }

    #[test]
    fn a_version_that_arrives_after_the_review_is_never_approved_unseen() {
        let (_relay, _clock, a, b, _words, personal) = pair();
        a.save_in_app(&a.space_path(&personal), "Host web\n  ProxyCommand nc first 22\n");
        settle(&a);
        settle(&b);
        let reviewed = shown(&b, &personal); // 對話框顯示的是第一版
        assert_eq!(reviewed.len(), 1);
        // 對話框還開著,A 又改了一次:B 的下一輪把待核准的換成較新的版本。
        a.save_in_app(&a.space_path(&personal), "Host web\n  ProxyCommand nc second 22\n");
        settle(&a);
        settle(&b);
        assert!(b.state().spaces[&personal].pending_approvals["web"].text.contains("second"));
        let out = approve(&b.env(), &personal, &reviewed).unwrap();
        assert_eq!(out, Reviewed { applied: 0, changed: vec!["web".to_string()] }, "the user never saw the second version");
        assert!(!b.read(&b.space_path(&personal)).contains("ProxyCommand"), "neither version was applied");
        // 重新顯示之後核准的是第二版。
        assert_eq!(approve(&b.env(), &personal, &shown(&b, &personal)).unwrap().applied, 1);
        assert!(b.read(&b.space_path(&personal)).contains("nc second 22"));
    }

    #[test]
    fn an_include_list_that_cannot_be_written_reruns_the_round_instead_of_reporting_an_error() {
        let (_relay, _clock, a, _b, _words, _personal) = pair();
        let work = create_space(&a.env(), "Work").unwrap();
        settle(&a);
        let work_file = a.space_path(&work);
        // 取消勾選做到一半(狀態已是 `selected` = false、檔案還在),主 config 同時被另一個編輯器改過:新的 Include 清單
        // 寫不進去。
        a.runtime.core.lock().unwrap().state.as_mut().unwrap().spaces.get_mut(&work).unwrap().selected = false;
        let edited = format!("{}# edited elsewhere\n", a.main_config());
        a.write_externally(&a.main_path(), &edited);
        let (applied, wakes) = (a.events.applied.lock().unwrap().len(), a.events.wakes());
        sync_once(&a.env()).unwrap();
        assert_eq!(a.events.applied.lock().unwrap()[applied..], [0], "prepare_files reported the reload once; the round adds nothing");
        assert_eq!(a.events.wakes(), wakes + 1, "the next round runs right away");
        assert!(a.state().last_error.is_none(), "not an error for the status bar");
        assert!(work_file.exists(), "nothing is removed while the list on the disk still names it");
        assert_eq!(a.main_config(), edited);
        // 下一輪以重載後的 doc 做完:清單先換掉、檔案才刪,外部的編輯保留。
        settle(&a);
        assert!(!work_file.exists() && !a.state().spaces.contains_key(&work));
        assert!(a.main_config().contains("# edited elsewhere"));
        assert!(a.state().last_error.is_none());
    }

    #[test]
    fn a_rename_from_another_device_waits_for_a_main_config_edited_elsewhere() {
        let (_relay, _clock, a, b, _words, personal) = pair();
        let old = a.space_path(&personal);
        a.save_in_app(&old, "Host web\n");
        settle(&a);
        settle(&b);
        rename_space(&b.env(), &personal, "Home Lab").unwrap();
        settle(&b);
        let edited = format!("{}# edited elsewhere\n", a.main_config());
        a.write_externally(&a.main_path(), &edited);
        // 帳戶記錄已經存檔、改名寫不進 Include:doc 重載,`applied(0)` 只發一次、在鎖都放掉之後;不是錯誤,馬上重跑。
        let probe = AppliedProbe::new(&a);
        let mut env = a.env();
        env.events = &probe;
        sync_once(&env).unwrap();
        assert_eq!(*probe.all_free.lock().unwrap(), vec![true]);
        assert_eq!(probe.wakes(), 1);
        assert!(a.state().last_error.is_none());
        assert_eq!(a.read(&old), "Host web\n", "nothing was renamed while the list on the disk names the old file");
        assert_eq!(a.main_config(), edited);
        // 下一輪做完改名,外部的編輯保留。
        settle(&a);
        let renamed = a.space_path(&personal);
        assert!(renamed != old && !old.exists());
        assert_eq!(a.read(&renamed), "Host web\n");
        assert!(a.main_config().contains("# edited elsewhere"));
    }

    #[test]
    fn a_prepare_failure_after_the_state_changed_is_recorded_in_the_same_round() {
        let (_relay, _clock, a, _b, _words, _personal) = pair();
        let work = create_space(&a.env(), "Work").unwrap();
        settle(&a);
        // 取消勾選做到一半;狀態檔所在的 `data` 被一個一般檔案擋住:`prepare_files` 刪了檔、換了 generation,存檔才失敗。
        a.runtime.core.lock().unwrap().state.as_mut().unwrap().spaces.get_mut(&work).unwrap().selected = false;
        let data = a.home.path().join("data");
        std::fs::remove_dir_all(&data).unwrap();
        std::fs::write(&data, b"in the way").unwrap();
        let err = sync_once(&a.env()).unwrap_err();
        assert_eq!(a.state().last_error, Some(err.to_string()), "shown now, not one round later");
    }

    #[test]
    fn deferred_chains_go_first_in_the_next_batch_ahead_of_the_unsent_ones() {
        // 70 條 chain(> 64):第一批送 64 條、relay 只做前 10 條;下一批先放 deferred 的 54 條,再接還沒送的 6 條。
        let relay = FakeRelay::new();
        let token = "1".repeat(64);
        let targets: Vec<BatchPullItem> = (0..70)
            .map(|i| {
                let chain = format!("{i:02x}{}", "a".repeat(62));
                relay.create_chain(&chain, &token).unwrap();
                BatchPullItem { chain, token: token.clone(), since: 0 }
            })
            .collect();
        relay.set_budget(Some(10));
        relay.clear_calls();
        let pulled = pull_all(relay.as_ref(), &targets, true, 0).unwrap();
        assert!(!pulled.limited && !pulled.failed && pulled.batch_ok);
        assert_eq!(pulled.fetched.len(), 70);
        assert!(pulled.fetched.values().all(|f| matches!(f, Fetched::Ok(_))), "every chain was fetched in the end");
        let calls = relay.calls();
        let second: Vec<&str> = calls[1].trim_start_matches("batch:").split(',').collect();
        assert_eq!(second.len(), 60);
        assert_eq!(second[0], "0aaaaaaa", "the first deferred chain leads the next batch");
        assert_eq!(second[54], "40aaaaaa", "the chains never sent come after the deferred ones");
        // 整批 429:全部沒拿到,cursor 都不推進,也不改逐條查詢(被拒絕的批次照樣扣配額)。
        relay.fail_batches_with_429(1);
        relay.clear_calls();
        let pulled = pull_all(relay.as_ref(), &targets[..3], true, 0).unwrap();
        assert!(pulled.limited);
        assert!(pulled.fetched.values().all(|f| matches!(f, Fetched::Missed)));
        assert!(!relay.calls().iter().any(|c| c.starts_with("pull:")), "a rate-limited batch is never retried chain by chain");
    }

    #[test]
    fn one_broken_chain_fails_the_batch_and_the_second_failure_falls_back_to_single_pulls() {
        let relay = FakeRelay::new();
        let token = "1".repeat(64);
        let targets: Vec<BatchPullItem> = ["a", "b", "c"]
            .iter()
            .map(|c| {
                let chain = c.repeat(64);
                relay.create_chain(&chain, &token).unwrap();
                BatchPullItem { chain, token: token.clone(), since: 0 }
            })
            .collect();
        relay.set_broken(&targets[1].chain, true);
        // 第一次:整批 5xx,什麼都沒拿到,這一輪以退避收尾。
        let first = pull_all(relay.as_ref(), &targets, true, 0).unwrap();
        assert!(first.batch_failed && first.failed && !first.batch_ok);
        assert!(first.fetched.values().all(|f| matches!(f, Fetched::Missed)));
        // 連續第二次:這一輪改逐條查詢,壞掉的那一條不擋住其他的。
        relay.clear_calls();
        let second = pull_all(relay.as_ref(), &targets, true, 1).unwrap();
        assert!(second.batch_failed && second.failed);
        assert!(matches!(second.fetched[&targets[0].chain], Fetched::Ok(_)));
        assert!(matches!(second.fetched[&targets[1].chain], Fetched::Missed));
        assert!(matches!(second.fetched[&targets[2].chain], Fetched::Ok(_)));
        assert_eq!(relay.calls().iter().filter(|c| c.starts_with("pull:")).count(), 3);
    }

    #[test]
    fn deferred_chains_are_asked_again_first_and_wait_for_their_turn() {
        let (relay, _clock, a, b, _words, personal) = pair();
        let work = create_space(&a.env(), "Work").unwrap();
        settle(&a);
        settle(&b);
        select_space(&b.env(), &work).unwrap();
        settle(&b);
        a.save_in_app(&a.space_path(&personal), "Host web\n");
        a.save_in_app(&a.space_path(&work), "Host db\n");
        settle(&a);
        relay.set_budget(Some(1));
        relay.clear_calls();
        settle(&b);
        let batches: Vec<String> = relay.calls().into_iter().filter(|c| c.starts_with("batch:")).collect();
        let account = b.state().account.as_ref().unwrap().chain_id[..8].to_string();
        let (s1, s2) = if personal < work { (&personal[..8], &work[..8]) } else { (&work[..8], &personal[..8]) };
        assert_eq!(batches[..3], [format!("batch:{account},{s1},{s2}"), format!("batch:{s1},{s2}"), format!("batch:{s2}")]);
        assert_eq!(b.read(&b.space_path(&personal)), "Host web\n");
        assert_eq!(b.read(&b.space_path(&work)), "Host db\n");
    }

    #[test]
    fn an_old_relay_falls_back_to_single_pulls_and_spaces_every_third_round() {
        let (relay, _clock, a, b, _words, personal) = pair();
        relay.set_legacy(true);
        for d in [&a, &b] {
            d.runtime.core.lock().unwrap().relay_checked = None;
        }
        a.save_in_app(&a.space_path(&personal), "Host web\n");
        settle(&a);
        relay.clear_calls();
        let account = b.state().account.as_ref().unwrap().chain_id[..8].to_string();
        let mut seen = false;
        for _ in 0..3 {
            sync_once(&b.env()).unwrap();
            seen |= b.read(&b.space_path(&personal)) == "Host web\n";
        }
        let calls = relay.calls();
        assert!(!calls.iter().any(|c| c.starts_with("batch:")), "{calls:?}");
        assert_eq!(calls.iter().filter(|c| **c == format!("pull:{account}")).count(), 3, "the account every round");
        assert_eq!(calls.iter().filter(|c| **c == format!("pull:{}", &personal[..8])).count(), 1, "a space every third round");
        assert!(seen);
        assert!(!b.state().relay_features.unwrap().supports("pull-batch"));
    }

    #[test]
    fn the_poll_cadence_follows_focus_and_activity_and_backs_off_on_429() {
        let (relay, clock, _a, b, _words, _personal) = pair();
        // 剛同步過(有操作):一般間隔;視窗不在前景、幾分鐘沒有操作:約 5 分鐘。
        b.runtime.set_focused(true, clock.now_ms());
        assert_eq!(next_delay(&b.env()), Duration::from_secs(45));
        b.runtime.set_focused(false, clock.now_ms());
        clock.advance(10 * 60 * 1000);
        assert_eq!(next_delay(&b.env()), Duration::from_secs(300));
        // app 裡存檔 = 操作。
        b.save_in_app(&b.space_path(&_personal), "Host web\n");
        assert_eq!(next_delay(&b.env()), Duration::from_secs(45));
        b.runtime.set_focused(true, clock.now_ms());
        relay.fail_batches_with_429(2);
        sync_once(&b.env()).unwrap();
        assert_eq!(b.state().last_error.as_deref(), Some(RATE_LIMITED_MESSAGE));
        assert_eq!(next_delay(&b.env()), Duration::from_secs(90));
        sync_once(&b.env()).unwrap();
        assert_eq!(next_delay(&b.env()), Duration::from_secs(180));
        sync_once(&b.env()).unwrap();
        assert_eq!(next_delay(&b.env()), Duration::from_secs(45));
        assert!(b.state().last_error.is_none());
    }

    #[test]
    fn a_broken_space_chain_cannot_block_the_others() {
        let (relay, _clock, a, b, _words, personal) = pair();
        let work = create_space(&a.env(), "Work").unwrap();
        settle(&a);
        settle(&b);
        select_space(&b.env(), &work).unwrap();
        settle(&b);
        a.save_in_app(&a.space_path(&work), "Host db\n");
        settle(&a);
        relay.set_broken(&personal, true);
        // 第一輪:整批 5xx,什麼都沒套用、以退避收尾。
        sync_once(&b.env()).unwrap();
        assert_eq!(b.read(&b.space_path(&work)), "");
        assert_eq!(b.state().last_error.as_deref(), Some(RELAY_TROUBLE_MESSAGE));
        assert_eq!(b.runtime.core.lock().unwrap().batch_failures, 1);
        // 第二輪:改逐條查詢,Work 照常同步;壞掉的 Personal 只是這一輪沒拿到。
        sync_once(&b.env()).unwrap();
        assert_eq!(b.read(&b.space_path(&work)), "Host db\n");
        assert_eq!(b.runtime.core.lock().unwrap().failed_rounds, 2, "the delay keeps growing while the relay fails");
        relay.set_broken(&personal, false);
        settle(&b);
        let core = b.runtime.core.lock().unwrap();
        assert_eq!((core.batch_failures, core.failed_rounds), (0, 0));
    }

    /// 模擬另一台(id `dev-z`)更換了同步碼:舊帳戶寫入標記並凍結舊帳戶與 space chain。
    pub(crate) fn rotate_elsewhere(d: &TestDevice, relay: &FakeRelay) {
        let (keys, spaces) = {
            let core = d.runtime.core.lock().unwrap();
            let s = core.state.as_ref().unwrap();
            let keys = core.account_keys.clone().unwrap();
            let spaces: Vec<ChainKeys> = s.spaces.keys().filter_map(|id| space_keys(s.account.as_ref().unwrap(), &keys, id)).collect();
            (keys, spaces)
        };
        let mut marker_account = AccountState::new(&keys.chain_id);
        let marker = RotationMarkerPayload { rotated_at_ms: 1, by_device_id: "dev-z".into(), by_device_name: "MacBook-Z".into() };
        put_account_record(&mut marker_account, RecordKind::Meta, &rotation_meta_id("dev-z"), serde_json::to_value(marker).unwrap(), false, "dev-z", 1);
        let outgoing = account_outgoing(&marker_account, &keys).unwrap();
        assert!(push_outgoing(relay, &keys.chain_id, &keys.auth_token, &outgoing).error.is_none());
        relay.freeze_chain(&keys.chain_id, &keys.auth_token).unwrap();
        for space in spaces {
            relay.freeze_chain(&space.chain_id, &space.auth_token).unwrap();
        }
    }

    #[test]
    fn a_rotation_marker_freezes_this_device_before_anything_else_happens() {
        let (relay, _clock, a, b, _words, personal) = pair();
        a.save_in_app(&a.space_path(&personal), "Host web\n");
        settle(&a);
        rotate_elsewhere(&a, &relay);
        b.save_in_app(&b.space_path(&personal), "Host local\n");
        relay.clear_calls();
        settle(&b);
        let s = b.state();
        assert!(relay.is_frozen(&s.account.as_ref().unwrap().chain_id));
        let frozen = s.frozen().unwrap();
        assert_eq!(frozen.markers[0].by_device_name, "MacBook-Z");
        assert_eq!(b.read(&b.space_path(&personal)), "Host local\n", "no space result was applied");
        assert!(s.spaces[&personal].records["host:local"].dirty, "the local edit is kept for the new account");
        assert!(!relay.calls().iter().any(|c| c.starts_with("push:")), "nothing is uploaded");
        // 之後的輪次不做任何網路寫入。
        relay.clear_calls();
        settle(&b);
        assert!(relay.calls().iter().all(|c| !c.starts_with("push:") && !c.starts_with("create:") && !c.starts_with("freeze:")));
    }

    #[test]
    fn a_frozen_push_stops_uploads_and_the_next_round_reads_the_markers() {
        let (relay, _clock, a, b, _words, personal) = pair();
        // B 已經拉過帳戶、還沒看到標記時,另一台凍結了所有 chain:B 的推送被擋下。
        rotate_elsewhere(&a, &relay);
        {
            // B 的帳戶 cursor 已在標記之後:這一輪的拉取看不到標記,只會在推送時撞到凍結。
            let keys = b.runtime.core.lock().unwrap().account_keys.clone().unwrap();
            let latest = relay.pull(&keys.chain_id, &keys.auth_token, 0).unwrap().latest_seq;
            b.runtime.core.lock().unwrap().state.as_mut().unwrap().account.as_mut().unwrap().cursor_seq = latest;
        }
        b.save_in_app(&b.space_path(&personal), "Host local\n");
        // 這台自己在更換同步碼時(`mark_frozen_chains` = false):只回報,不記進狀態。
        let (generation, s, keys) = {
            let core = b.runtime.core.lock().unwrap();
            (core.generation, core.state.clone().unwrap(), core.account_keys.clone().unwrap())
        };
        assert!(run_round(&b.env(), generation, s, keys, false).unwrap().frozen);
        assert!(b.state().frozen().is_none());
        sync_once(&b.env()).unwrap();
        let s = b.state();
        assert!(s.frozen().unwrap().markers.is_empty(), "a 409 alone has no marker yet");
        assert!(s.spaces[&personal].records["host:local"].dirty);
        sync_once(&b.env()).unwrap();
        assert_eq!(b.state().frozen().unwrap().markers[0].by_device_name, "MacBook-Z");
    }

    #[test]
    fn a_missing_account_and_a_missing_space_are_reported() {
        let (relay, _clock, a, b, _words, personal) = pair();
        let space = {
            let core = a.runtime.core.lock().unwrap();
            space_keys(core.state.as_ref().unwrap().account.as_ref().unwrap(), core.account_keys.as_ref().unwrap(), &personal).unwrap()
        };
        relay.delete_chain(&space.chain_id, &space.auth_token).unwrap();
        settle(&b);
        let s = b.state();
        assert!(s.spaces[&personal].missing);
        assert_eq!(s.spaces[&personal].last_error.as_deref(), Some(SPACE_GONE_MESSAGE));
        // 重建:以同一組位置與權杖重新建立,上傳這台的內容。
        b.save_in_app(&b.space_path(&personal), "Host web\n");
        crate::sync::spaces::rebuild_space(&b.env(), &personal).unwrap();
        settle(&b);
        assert!(!relay.rows(&personal).is_empty());
        let keys = a.runtime.core.lock().unwrap().account_keys.clone().unwrap();
        relay.delete_chain(&keys.chain_id, &keys.auth_token).unwrap();
        assert_eq!(sync_once(&a.env()).unwrap_err().to_string(), ACCOUNT_GONE_MESSAGE);
        assert_eq!(a.state().last_error.as_deref(), Some(ACCOUNT_GONE_MESSAGE));
    }

    #[test]
    fn an_emptied_space_file_is_restored_from_the_chain_instead_of_deleting_every_host() {
        let (_relay, _clock, a, b, _words, personal) = pair();
        a.save_in_app(&a.space_path(&personal), "Host web\nHost db\n");
        settle(&a);
        settle(&b);
        b.write_externally(&b.space_path(&personal), "");
        settle(&b);
        let text = b.read(&b.space_path(&personal));
        assert!(text.contains("Host web") && text.contains("Host db"), "{text}");
        settle(&a);
        assert_eq!(a.read(&a.space_path(&personal)), "Host web\nHost db\n", "no tombstone reached the other device");
    }

    #[test]
    fn a_push_that_stops_part_way_keeps_what_the_relay_accepted() {
        let (relay, _clock, a, _b, _words, personal) = pair();
        // 250 台主機 = 兩批(每批 ≤ 200);第一批寫進去之後 chain 的儲存額度就滿了(413)。
        let text: String = (0..250).map(|i| format!("Host h{i}\n  HostName 10.0.{}.{}\n", i / 200, i % 200)).collect();
        a.save_in_app(&a.space_path(&personal), &text);
        relay.set_push_quota(Some(1));
        // 額度滿了是這個 space 的問題,不是整輪的錯誤:記在 space 上,這一輪算失敗(退避)。
        sync_once(&a.env()).unwrap();
        let s = a.state();
        let message = s.spaces[&personal].last_error.as_deref().unwrap();
        assert!(message.contains("\"Personal\"") && message.contains("storage limit"), "{message}");
        assert_eq!(a.runtime.core.lock().unwrap().failed_rounds, 1);
        let dirty = s.spaces[&personal].records.values().filter(|l| l.dirty).count();
        assert_eq!(dirty, 50, "the 200 records the relay accepted are clean; only the second batch waits");
        // 額度恢復之後,剩下的照常上傳,訊息清掉。
        relay.set_push_quota(None);
        settle(&a);
        let s = a.state();
        assert!(s.spaces[&personal].records.values().all(|l| !l.dirty));
        assert!(s.spaces[&personal].last_error.is_none());
    }

    #[test]
    fn a_relay_restored_from_an_older_backup_gets_this_devices_records_again() {
        let (relay, _clock, a, b, _words, personal) = pair();
        a.save_in_app(&a.space_path(&personal), "Host web\n");
        settle(&a);
        let backup = relay.rows(&personal).last().map(|e| e.seq).unwrap_or(0);
        a.save_in_app(&a.space_path(&personal), "Host web\nHost db\n");
        settle(&a);
        settle(&b);
        sync_once(&a.env()).unwrap(); // A 的 cursor 走到 db 之後
        // 自架 relay 從舊備份還原:db 不見了,watermark 倒退到 A 的 cursor 之下。
        relay.roll_back(&personal, backup);
        settle(&a);
        assert!(relay.rows(&personal).len() >= 2, "A uploaded what the relay lost");
        let c = TestDevice::new("c", &relay, &a.clock);
        join_account(&c.env(), &_words, "MacBook-C").unwrap();
        select_space(&c.env(), &personal).unwrap();
        settle(&c);
        let text = c.read(&c.space_path(&personal));
        assert!(text.contains("Host web\n") && text.contains("Host db\n"), "{text}");
        assert!(c.events.statuses() > 0, "every round ends with a status event");
    }

    #[test]
    fn a_vanished_space_file_comes_back_from_the_chain_with_unpushed_edits() {
        let (relay, _clock, a, b, _words, personal) = pair();
        a.save_in_app(&a.space_path(&personal), "Host web\nHost db\n");
        settle(&a);
        settle(&b);
        relay.set_offline(true);
        b.save_in_app(&b.space_path(&personal), "Host web\n  User offline\nHost db\n");
        let _ = sync_once(&b.env());
        relay.set_offline(false);
        std::fs::remove_file(b.space_path(&personal)).unwrap();
        settle(&b);
        let text = b.read(&b.space_path(&personal));
        assert!(text.contains("Host db\n") && text.contains("User offline"), "{text}");
        settle(&a);
        assert!(a.read(&a.space_path(&personal)).contains("User offline"), "the offline edit was not tombstoned");
    }

    // ── 第 1 輪審查的修正:`RoundOutcome` 的契約、一個滿了的 space 不擋住其他 space、限流之後這一輪不再發請求 ──

    /// `run_round` 要的快照(generation / 狀態 / 金鑰,同一把鎖)。
    fn snapshot(d: &TestDevice) -> (u64, SyncStateV2, ChainKeys) {
        let core = d.runtime.core.lock().unwrap();
        (core.generation, core.state.clone().unwrap(), core.account_keys.clone().unwrap())
    }

    /// 假 relay 的外殼出的錯:`FakeRelay::set_push_quota` 是全域的,沒辦法只讓其中一條 chain 的儲存額度滿,所以另外包一層。
    #[derive(Clone, Default)]
    struct Faults {
        /// 指定那條 chain 的上傳回這個錯誤。
        push: Option<(String, fn() -> RelayError)>,
        /// 所有 chain 的 `DELETE` 回這個錯誤。
        delete: Option<fn() -> RelayError>,
        /// `DELETE` 被呼叫了幾次(含回錯誤的)。
        deletes: Arc<AtomicUsize>,
        /// `GET /v1/info` 回這個錯誤。
        info: Option<fn() -> RelayError>,
        /// 批次查詢一項都沒執行、全部回 `deferred`(沒有 `429`、也沒有 `5xx`)。
        defer_batches: bool,
    }

    struct Faulty {
        inner: Arc<FakeRelay>,
        faults: Faults,
    }

    impl RelayApi for Faulty {
        fn info(&self) -> Result<RelayInfo, RelayError> {
            match self.faults.info {
                Some(error) => Err(error()),
                None => self.inner.info(),
            }
        }
        fn create_chain(&self, chain_id: &str, token: &str) -> Result<(), RelayError> {
            self.inner.create_chain(chain_id, token)
        }
        fn delete_chain(&self, chain_id: &str, token: &str) -> Result<(), RelayError> {
            self.faults.deletes.fetch_add(1, Ordering::SeqCst);
            match self.faults.delete {
                Some(error) => Err(error()),
                None => self.inner.delete_chain(chain_id, token),
            }
        }
        fn freeze_chain(&self, chain_id: &str, token: &str) -> Result<(), RelayError> {
            self.inner.freeze_chain(chain_id, token)
        }
        fn pull(&self, chain_id: &str, token: &str, since: u64) -> Result<PullResponse, RelayError> {
            self.inner.pull(chain_id, token, since)
        }
        fn pull_batch(&self, items: &[BatchPullItem]) -> Result<Vec<BatchPullEntry>, RelayError> {
            if self.faults.defer_batches {
                return Ok(items.iter().map(|i| BatchPullEntry { chain: i.chain.clone(), result: BatchPullResult::Deferred }).collect());
            }
            self.inner.pull_batch(items)
        }
        fn push(&self, chain_id: &str, token: &str, items: &[PushItem]) -> Result<PushOutcome, RelayError> {
            if let Some((chain, error)) = &self.faults.push {
                if chain == chain_id {
                    return Err(error());
                }
            }
            self.inner.push(chain_id, token, items)
        }
    }

    struct FaultyConnector {
        relay: Arc<FakeRelay>,
        faults: Faults,
    }

    impl RelayConnector for FaultyConnector {
        fn connect(&self, _base_url: &str) -> Result<Box<dyn RelayApi>, AppError> {
            Ok(Box::new(Faulty { inner: Arc::clone(&self.relay), faults: self.faults.clone() }))
        }
    }

    /// 跑一輪(一般輪次的模式),relay 照 `faults` 出錯。
    fn run_with_faults(d: &TestDevice, relay: &Arc<FakeRelay>, faults: &Faults) -> Result<RoundOutcome, AppError> {
        let connector = FaultyConnector { relay: Arc::clone(relay), faults: faults.clone() };
        let mut env = d.env();
        env.relays = &connector;
        let (generation, s, keys) = snapshot(d);
        run_round(&env, generation, s, keys, true)
    }

    fn quota_exceeded() -> RelayError {
        RelayError::QuotaExceeded
    }

    fn rate_limited() -> RelayError {
        RelayError::RateLimited
    }

    #[test]
    fn a_marker_on_the_pull_is_reported_and_only_recorded_when_this_device_is_not_rotating() {
        let (relay, _clock, a, b, _words, personal) = pair();
        rotate_elsewhere(&a, &relay);
        b.save_in_app(&b.space_path(&personal), "Host local\n");
        let cursor = b.state().account.as_ref().unwrap().cursor_seq;
        relay.clear_calls();
        // 這台自己正在更換同步碼(`mark_frozen_chains` = false):回報標記,什麼都不記、不套用、不上傳。
        let (generation, s, keys) = snapshot(&b);
        let out = run_round(&b.env(), generation, s, keys, false).unwrap();
        assert_eq!(out.markers.len(), 1);
        assert_eq!(out.markers[0].by_device_name, "MacBook-Z");
        assert!(!out.frozen && !out.backoff);
        let s = b.state();
        assert!(s.frozen().is_none(), "reported, not recorded");
        assert_eq!(s.account.as_ref().unwrap().cursor_seq, cursor, "nothing from the account was applied");
        assert!(s.spaces[&personal].records["host:local"].dirty, "the local edit is kept");
        assert!(!relay.calls().iter().any(|c| c.starts_with("push:")), "nothing is uploaded");
        // 一般的一輪(`true`):照舊記下,同時也回報。
        let (generation, s, keys) = snapshot(&b);
        let out = run_round(&b.env(), generation, s, keys, true).unwrap();
        assert_eq!(out.markers.len(), 1);
        assert_eq!(b.state().frozen().unwrap().markers, out.markers);
    }

    #[test]
    fn a_round_that_ends_limited_or_failed_asks_for_a_backoff() {
        let (relay, _clock, _a, b, _words, personal) = pair();
        let run = |d: &TestDevice| {
            let (generation, s, keys) = snapshot(d);
            run_round(&d.env(), generation, s, keys, false).unwrap()
        };
        let account = b.state().account.as_ref().unwrap().chain_id.clone();
        assert!(!run(&b).backoff, "a healthy round does not");
        relay.fail_batches_with_429(1);
        assert!(run(&b).backoff, "a whole-batch 429");
        relay.fail_batches_with_5xx(1);
        assert!(run(&b).backoff, "a batch 5xx");
        relay.set_rate_limited(&account, true);
        assert!(run(&b).backoff, "the account chain could not be pulled");
        relay.set_rate_limited(&account, false);
        relay.set_rate_limited(&personal, true);
        assert!(run(&b).backoff, "a space chain was limited");
        relay.set_rate_limited(&personal, false);
        assert!(!run(&b).backoff);
    }

    #[test]
    fn a_space_over_the_relays_storage_limit_is_paused_alone_and_does_not_block_the_next_one() {
        let (relay, _clock, a, _b, _words, personal) = pair();
        let work = create_space(&a.env(), "Work").unwrap();
        settle(&a);
        a.save_in_app(&a.space_path(&personal), "Host web\n");
        a.save_in_app(&a.space_path(&work), "Host db\n");
        // 兩個 space 都有東西要上傳;依 id 排在前面的那條 chain 回 `413`。
        let mut ids = [personal.clone(), work.clone()];
        ids.sort();
        let [full, other] = ids;
        let name = if full == personal { "Personal" } else { "Work" };
        let faults = Faults { push: Some((full.clone(), quota_exceeded)), ..Faults::default() };
        let out = run_with_faults(&a, &relay, &faults).unwrap();
        assert!(out.backoff, "a full space makes the round a failed one");
        let s = a.state();
        let message = s.spaces[&full].last_error.clone().unwrap();
        assert!(message.contains(&format!("space \"{name}\"")) && message.contains("storage limit"), "{message}");
        assert!(s.spaces[&full].records.values().any(|l| l.dirty), "the full space keeps its edit");
        assert!(s.spaces[&other].last_error.is_none());
        assert!(s.spaces[&other].records.values().all(|l| !l.dirty) && !relay.rows(&other).is_empty(), "the next space was still uploaded");
        assert_eq!(a.runtime.core.lock().unwrap().failed_rounds, 1);
        // 之後(額度有空間了):這個 space 照常上傳,訊息清掉。
        settle(&a);
        let s = a.state();
        assert!(s.spaces[&full].last_error.is_none() && s.spaces[&full].records.values().all(|l| !l.dirty));
        assert!(!relay.rows(&full).is_empty());
    }

    #[test]
    fn an_upload_error_of_one_chain_pauses_that_space_and_a_transport_error_still_ends_the_round() {
        let (relay, _clock, a, _b, _words, personal) = pair();
        let work = create_space(&a.env(), "Work").unwrap();
        settle(&a);
        a.save_in_app(&a.space_path(&personal), "Host web\n");
        a.save_in_app(&a.space_path(&work), "Host db\n");
        let mut ids = [personal.clone(), work.clone()];
        ids.sort();
        let [first, second] = ids;
        // relay 認為請求不合規格、或回答和請求對不上:只暫停那個 space,下一個照常上傳。
        let errors: [fn() -> RelayError; 2] = [
            || RelayError::InvalidRequest("a push takes 1 to 200 records".to_string()),
            || RelayError::BadResponse("a push of 3 records was answered with 2 results".to_string()),
        ];
        for error in errors {
            let faults = Faults { push: Some((first.clone(), error)), ..Faults::default() };
            run_with_faults(&a, &relay, &faults).unwrap();
            let s = a.state();
            let message = s.spaces[&first].last_error.clone().unwrap();
            assert!(message.contains("could not be uploaded"), "{message}");
            assert!(s.spaces[&first].records.values().any(|l| l.dirty));
            assert!(s.spaces[&second].records.values().all(|l| !l.dirty), "the next space was still uploaded");
        }
        // 連不上 relay 這類傳輸的錯誤照舊結束這一輪:後面的 space 這一輪不上傳。
        a.save_in_app(&a.space_path(&second), "Host db\n  User x\n");
        let unreachable: fn() -> RelayError = || RelayError::Unreachable("offline".to_string());
        let faults = Faults { push: Some((first.clone(), unreachable)), ..Faults::default() };
        let err = run_with_faults(&a, &relay, &faults).unwrap_err();
        assert!(err.to_string().contains("cannot reach"), "{err}");
        assert!(a.state().spaces[&second].records.values().any(|l| l.dirty), "the round ended at the transport error");
    }

    #[test]
    fn a_baseline_round_that_ends_rate_limited_waits_for_the_backoff_instead_of_rerunning_at_once() {
        let (relay, _clock, a, b, _words, _personal) = pair();
        let work = create_space(&a.env(), "Work").unwrap();
        settle(&a);
        settle(&b);
        select_space(&b.env(), &work).unwrap(); // Work 還要跑基線輪;B 的裝置記錄也變了,要上傳
        relay.fail_pushes_with_429(1);
        let wakes = b.events.wakes();
        sync_once(&b.env()).unwrap();
        assert_eq!(b.state().last_error.as_deref(), Some(RATE_LIMITED_MESSAGE));
        assert!(b.state().spaces[&work].baseline_established, "the baseline itself was done");
        assert_eq!(b.events.wakes(), wakes, "a rate-limited round waits for the backoff");
        settle(&b);
        assert!(b.state().last_error.is_none());
    }

    #[test]
    fn a_rate_limited_round_does_not_rerun_at_once_after_a_space_file_was_renamed() {
        let (relay, _clock, a, b, _words, personal) = pair();
        let work = create_space(&a.env(), "Work").unwrap();
        settle(&a);
        settle(&b);
        select_space(&b.env(), &work).unwrap();
        settle(&b);
        rename_space(&a.env(), &personal, "Lab").unwrap();
        settle(&a);
        // B 的下一輪:帳戶拉到改名(檔案要改名,這一輪的 space 結果作廢),同時 Work 的 chain 被限流。
        let old = b.space_path(&personal);
        relay.set_rate_limited(&work, true);
        let wakes = b.events.wakes();
        sync_once(&b.env()).unwrap();
        let renamed = b.space_path(&personal);
        assert!(renamed != old && renamed.exists() && !old.exists(), "the file was renamed");
        assert_eq!(b.events.wakes(), wakes, "rate-limited: wait for the backoff");
        // 回報退避的這一輪也照樣算一次失敗:背景執行緒等的時間跟著拉長,狀態列說明為什麼。
        assert_eq!(b.runtime.core.lock().unwrap().failed_rounds, 1);
        assert_eq!(b.state().last_error.as_deref(), Some(RATE_LIMITED_MESSAGE));
        relay.set_rate_limited(&work, false);
        settle(&b);
        assert!(b.state().last_error.is_none());
        assert_eq!(b.runtime.core.lock().unwrap().failed_rounds, 0);
    }

    #[test]
    fn a_rate_limited_round_does_not_rerun_at_once_when_the_rename_could_not_be_written_either() {
        let (relay, _clock, a, b, _words, personal) = pair();
        let work = create_space(&a.env(), "Work").unwrap();
        settle(&a);
        settle(&b);
        rename_space(&b.env(), &personal, "Home Lab").unwrap();
        settle(&b);
        // A 的主 config 被另一個編輯器改過:帳戶記錄存了檔、改名寫不進 Include(`Conflict`);同一輪 Work 的 chain 被限流。
        let old = a.space_path(&personal);
        let edited = format!("{}# edited elsewhere\n", a.main_config());
        a.write_externally(&a.main_path(), &edited);
        relay.set_rate_limited(&work, true);
        let (applied, wakes) = (a.events.applied.lock().unwrap().len(), a.events.wakes());
        sync_once(&a.env()).unwrap();
        assert_eq!(a.events.applied.lock().unwrap()[applied..], [0], "the reload is still reported once");
        assert_eq!(a.events.wakes(), wakes, "rate-limited: the file half waits for the backoff");
        assert!(old.exists() && a.main_config() == edited, "nothing was renamed or overwritten");
        assert_eq!(a.runtime.core.lock().unwrap().failed_rounds, 1, "a round that asks for a backoff counts as a failed one");
        assert_eq!(a.state().last_error.as_deref(), Some(RATE_LIMITED_MESSAGE));
        // 退避之後做完。
        relay.set_rate_limited(&work, false);
        settle(&a);
        assert!(!old.exists() && a.main_config().contains("# edited elsewhere"));
    }

    #[test]
    fn a_429_on_the_account_push_stops_the_chain_deletes_and_the_space_pushes() {
        let (relay, _clock, a, _b, _words, personal) = pair();
        let work = create_space(&a.env(), "Work").unwrap();
        settle(&a);
        delete_space(&a.env(), &work).unwrap(); // tombstone 要上傳,chain 的 `DELETE` 排在後面
        // 第一輪:tombstone 上傳了,chain 的 `DELETE` 被限流 —— 還排在 `chain_deletes`,而且已經可以刪了。
        let faults = Faults { delete: Some(rate_limited), ..Faults::default() };
        run_with_faults(&a, &relay, &faults).unwrap();
        let account = a.state().account.unwrap();
        assert_eq!(account.chain_deletes.len(), 1);
        assert!(account.records.values().all(|l| !l.dirty) && account.sealed.values().all(|s| !s.dirty), "the tombstones are uploaded");
        // 第二輪:帳戶又有東西要上傳(裝置名稱),那次上傳被限流 —— 這一輪不再刪 chain,也不上傳 space。
        crate::sync::account::set_device_name(&a.env(), "Renamed").unwrap();
        a.save_in_app(&a.space_path(&personal), "Host web\n");
        relay.fail_pushes_with_429(1);
        relay.clear_calls();
        sync_once(&a.env()).unwrap();
        let calls = relay.calls();
        assert_eq!(calls.iter().filter(|c| c.starts_with("push:")).count(), 1, "only the rejected account push: {calls:?}");
        assert!(!calls.iter().any(|c| c.starts_with("delete:")), "{calls:?}");
        assert!(relay.exists(&work));
        assert!(a.state().spaces[&personal].records.values().any(|l| l.dirty));
        assert_eq!(a.state().last_error.as_deref(), Some(RATE_LIMITED_MESSAGE));
        // 退避之後做完:tombstone 上傳、chain 刪除、space 上傳。
        settle(&a);
        assert!(!relay.exists(&work));
        assert!(a.state().spaces[&personal].records.values().all(|l| !l.dirty));
    }

    #[test]
    fn a_429_on_a_space_push_stops_the_next_space() {
        let (relay, _clock, a, _b, _words, personal) = pair();
        let work = create_space(&a.env(), "Work").unwrap();
        settle(&a);
        a.save_in_app(&a.space_path(&personal), "Host web\n");
        a.save_in_app(&a.space_path(&work), "Host db\n");
        relay.fail_pushes_with_429(1);
        relay.clear_calls();
        let wakes = a.events.wakes();
        sync_once(&a.env()).unwrap();
        let pushes: Vec<String> = relay.calls().into_iter().filter(|c| c.starts_with("push:")).collect();
        assert_eq!(pushes.len(), 1, "{pushes:?}");
        assert_eq!(a.state().last_error.as_deref(), Some(RATE_LIMITED_MESSAGE));
        assert_eq!(a.events.wakes(), wakes);
        settle(&a);
        assert!(!relay.rows(&personal).is_empty() && !relay.rows(&work).is_empty());
    }

    #[test]
    fn a_429_on_a_chain_delete_stops_the_remaining_deletes_and_the_space_pushes() {
        let (relay, _clock, a, _b, _words, personal) = pair();
        let first = create_space(&a.env(), "Work").unwrap();
        let second = create_space(&a.env(), "Lab").unwrap();
        settle(&a);
        delete_space(&a.env(), &first).unwrap();
        delete_space(&a.env(), &second).unwrap();
        a.save_in_app(&a.space_path(&personal), "Host web\n");
        relay.clear_calls();
        let faults = Faults { delete: Some(rate_limited), ..Faults::default() };
        let out = run_with_faults(&a, &relay, &faults).unwrap();
        assert!(out.backoff);
        assert_eq!(faults.deletes.load(Ordering::SeqCst), 1, "the second delete is not even tried");
        assert_eq!(relay.calls().iter().filter(|c| c.starts_with("push:")).count(), 1, "only the account push (the tombstones)");
        assert!(a.state().spaces[&personal].records.values().any(|l| l.dirty));
        assert!(relay.exists(&first) && relay.exists(&second));
        // 之後(沒有限流了):兩條 chain 都刪掉、space 上傳。
        settle(&a);
        assert!(!relay.exists(&first) && !relay.exists(&second));
        assert!(a.state().spaces[&personal].records.values().all(|l| !l.dirty));
    }

    #[test]
    fn after_a_429_no_further_request_is_made_for_the_rest_of_the_pull() {
        let relay = FakeRelay::new();
        let token = "1".repeat(64);
        let targets: Vec<BatchPullItem> = ["a", "b", "c"]
            .iter()
            .map(|c| {
                let chain = c.repeat(64);
                relay.create_chain(&chain, &token).unwrap();
                BatchPullItem { chain, token: token.clone(), since: 0 }
            })
            .collect();
        // 逐條查詢:第一條就被限流,後面的不再發請求。
        relay.set_rate_limited(&targets[0].chain, true);
        relay.clear_calls();
        let pulled = pull_all(relay.as_ref(), &targets, false, 0).unwrap();
        assert!(pulled.limited);
        assert!(pulled.fetched.values().all(|f| matches!(f, Fetched::Missed)));
        assert_eq!(relay.calls(), vec!["pull:aaaaaaaa".to_string()]);
        // 批次:第一項被限流、預算只夠第一項 —— deferred 的不再補抓。
        relay.set_budget(Some(1));
        relay.clear_calls();
        let pulled = pull_all(relay.as_ref(), &targets, true, 0).unwrap();
        assert!(pulled.limited);
        assert_eq!(pulled.fetched.len(), 3);
        assert!(pulled.fetched.values().all(|f| matches!(f, Fetched::Missed)));
        assert_eq!(relay.calls().len(), 1, "one batch, and no re-fetch of the deferred chains");
    }

    #[test]
    fn a_round_that_could_not_pull_the_account_is_not_a_sync() {
        let (relay, _clock, _a, b, _words, _personal) = pair();
        let before = b.state().last_sync_ms.unwrap();
        let account = b.state().account.as_ref().unwrap().chain_id.clone();
        relay.set_rate_limited(&account, true);
        sync_once(&b.env()).unwrap();
        assert_eq!(b.state().last_sync_ms, Some(before), "nothing was pulled or pushed");
        assert_eq!(b.state().last_error.as_deref(), Some(RATE_LIMITED_MESSAGE));
        relay.set_rate_limited(&account, false);
        sync_once(&b.env()).unwrap();
        assert!(b.state().last_sync_ms.unwrap() > before);
        assert!(b.state().last_error.is_none());
    }

    #[test]
    fn an_old_relay_pulls_a_space_with_unuploaded_records_even_off_its_every_third_round() {
        let (relay, _clock, a, b, _words, personal) = pair();
        relay.set_legacy(true);
        for d in [&a, &b] {
            d.runtime.core.lock().unwrap().relay_checked = None;
        }
        a.save_in_app(&a.space_path(&personal), "Host web\n  User a\n");
        settle(&a);
        // B 改了同一台、還沒拿到 A 的版本;B 接下來的兩輪(第 2、3 輪)都不是輪到 space 的那一輪。不先拿到 relay 上的版本,
        // 上傳只會一直撞衝突。
        b.save_in_app(&b.space_path(&personal), "Host web\n  User b\n");
        b.runtime.core.lock().unwrap().rounds = 1;
        relay.clear_calls();
        sync_once(&b.env()).unwrap();
        sync_once(&b.env()).unwrap();
        let space = &personal[..8];
        assert!(relay.calls().iter().any(|c| c == &format!("pull:{space}")), "{:?}", relay.calls());
        assert!(b.state().spaces[&personal].records.values().all(|l| !l.dirty), "no longer stuck on a conflict");
        assert_eq!(b.runtime.core.lock().unwrap().conflict_streak, 0);
        assert!(b.state().last_error.is_none());
    }

    #[test]
    fn a_steady_round_does_not_save_the_state_before_the_pull() {
        let (relay, _clock, a, _b, _words, _personal) = pair();
        // 狀態檔所在的 `data` 被一個一般檔案擋住:任何存檔都會失敗。
        let data = a.home.path().join("data");
        std::fs::remove_dir_all(&data).unwrap();
        std::fs::write(&data, b"in the way").unwrap();
        relay.clear_calls();
        // 本機沒有任何變化:本機 diff 那一步沒有東西要存,這一輪照常去拉;存檔失敗(帳戶區段)是拉完之後的事。
        let err = sync_once(&a.env()).unwrap_err();
        assert!(relay.calls().iter().any(|c| c.starts_with("batch:")), "the round reached the pull; it failed to save later: {err}");
    }

    // ── 最終審查的修正:核准過的版本不再重問、主機留在檔案裡;失敗之前的提示照樣發出;每一種以退避收尾的結束都算失敗;跨執行緒的輪次 ──

    #[test]
    fn a_reviewed_version_is_not_asked_again_and_its_host_stays_when_the_space_file_is_emptied() {
        let (_relay, _clock, a, b, _words, personal) = pair();
        b.save_in_app(&b.space_path(&personal), "Host web\n  HostName 10.0.0.1\nHost db\n  HostName 10.0.0.2\n");
        settle(&b);
        settle(&a);
        let theirs = "Host web\n  HostName 10.0.0.1\n  ProxyCommand nc evil.example 22\nHost db\n  HostName 10.0.0.2\n  ForwardAgent yes\n";
        a.save_in_app(&a.space_path(&personal), theirs);
        settle(&a);
        settle(&b);
        // B 拒絕 web 的那一版;db 的那一版還在等。
        let web: Vec<(String, String)> = shown(&b, &personal).into_iter().filter(|(alias, _)| alias == "web").collect();
        reject(&b.env(), &personal, &web).unwrap();
        settle(&b);
        let asked = b.events.approvals.lock().unwrap().len();
        let waiting = b.state().spaces[&personal].pending_approvals["db"].clone();
        // space 檔被外部工具清空:從 chain 重新長出。
        b.write_externally(&b.space_path(&personal), "");
        for _ in 0..3 {
            settle(&b);
        }
        let sp = b.state().spaces[&personal].clone();
        assert_eq!(b.events.approvals.lock().unwrap().len(), asked, "neither version is asked again");
        assert!(sp.declined.contains_key("web") && !sp.pending_approvals.contains_key("web"), "web stays declined");
        assert_eq!(sp.pending_approvals["db"].record, waiting.record, "db still waits for the same version");
        assert_eq!(sp.pending_approvals["db"].applied, waiting.applied);
        let text = b.read(&b.space_path(&personal));
        assert!(text.contains("Host web\n  HostName 10.0.0.1\n") && text.contains("Host db\n  HostName 10.0.0.2\n"), "both hosts are back as this device had them: {text}");
        assert!(!text.contains("ProxyCommand") && !text.contains("ForwardAgent"), "{text}");
        // 之後照常:核准 db 套用的是等著的那一版;A 沒有收到任何刪除或舊的版本。
        assert_eq!(approve(&b.env(), &personal, &shown(&b, &personal)).unwrap().applied, 1);
        assert!(b.read(&b.space_path(&personal)).contains("ForwardAgent yes"));
        settle(&b);
        settle(&a);
        assert_eq!(a.read(&a.space_path(&personal)), theirs);
    }

    #[test]
    fn a_save_right_after_an_accepted_push_converges_without_a_conflict() {
        use crate::sync::testkit::{HookedConnector, Hooks};
        let (relay, _clock, a, b, _words, personal) = pair();
        let path = a.space_path(&personal);
        a.save_in_app(&path, "Host web\n  HostName 1\n");
        assert!(a.state().account.as_ref().unwrap().records.values().all(|l| !l.dirty), "the space push is the round's first upload");
        // relay 收下這一輪的上傳之後、這一輪提交它之前,app 裡又存了一次(存檔 hook 換了 generation,這一輪的提交作廢)。
        let a = Arc::new(a);
        let saver = Arc::clone(&a);
        let save_path = path.clone();
        let hooks = Hooks {
            after_push: Some(Box::new(move || saver.save_in_app(&save_path, "Host web\n  HostName 2\n"))),
            ..Hooks::default()
        };
        let connector = HookedConnector::new(&relay, hooks);
        let mut env = a.env();
        env.relays = &connector;
        let _ = sync_once(&env);
        settle(&a);
        settle(&b);
        settle(&a);
        assert_eq!(b.read(&b.space_path(&personal)), "Host web\n  HostName 2\n", "the later edit wins everywhere");
        assert_eq!(a.read(&path), "Host web\n  HostName 2\n");
        assert!(a.state().spaces[&personal].records.values().all(|l| !l.dirty), "nothing is left to upload");
        assert!(a.events.conflicts.lock().unwrap().is_empty() && b.events.conflicts.lock().unwrap().is_empty(), "no spurious conflict");
    }

    #[test]
    fn a_save_between_the_pull_and_the_apply_keeps_both_edits() {
        use crate::sync::testkit::{HookedConnector, Hooks};
        let (relay, _clock, a, b, _words, personal) = pair();
        b.save_in_app(&b.space_path(&personal), "Host web\n  HostName b\n");
        settle(&b);
        // A 的這一輪拉到 B 的修改之後、套用之前,app 裡存了另一台主機(存檔 hook 換了 generation,這一輪的套用作廢、重跑)。
        let path = a.space_path(&personal);
        let a = Arc::new(a);
        let saver = Arc::clone(&a);
        let save_path = path.clone();
        let hooks = Hooks {
            after_batch: Some(Box::new(move || saver.save_in_app(&save_path, "Host other\n  HostName a\n"))),
            ..Hooks::default()
        };
        let connector = HookedConnector::new(&relay, hooks);
        let mut env = a.env();
        env.relays = &connector;
        let _ = sync_once(&env);
        settle(&a);
        settle(&b);
        settle(&a);
        for text in [a.read(&path), b.read(&b.space_path(&personal))] {
            assert!(text.contains("Host web\n  HostName b\n") && text.contains("Host other\n  HostName a\n"), "{text}");
        }
        assert!(a.events.conflicts.lock().unwrap().is_empty() && b.events.conflicts.lock().unwrap().is_empty(), "no spurious conflict");
    }

    #[cfg(unix)]
    #[test]
    fn notices_of_a_round_whose_file_step_failed_later_are_still_announced() {
        use std::os::unix::fs::PermissionsExt;
        struct Restore(PathBuf);
        impl Drop for Restore {
            fn drop(&mut self) {
                let _ = std::fs::set_permissions(&self.0, std::fs::Permissions::from_mode(0o600));
            }
        }
        let (_relay, _clock, a, b, _words, _personal) = pair();
        let one = create_space(&a.env(), "One").unwrap();
        let two = create_space(&a.env(), "Two").unwrap();
        settle(&a);
        settle(&b);
        select_space(&b.env(), &one).unwrap();
        select_space(&b.env(), &two).unwrap();
        settle(&b);
        // A 刪了兩個 space。B 上依 id 排在後面的那個檔案讀不到(備份不了就不刪):第一個刪掉、留下提示之後,第二個失敗。
        let (first, second) = if one < two { (one.clone(), two.clone()) } else { (two.clone(), one.clone()) };
        let first_name = if first == one { "One" } else { "Two" };
        let (first_file, blocked) = (b.space_path(&first), b.space_path(&second));
        delete_space(&a.env(), &one).unwrap();
        delete_space(&a.env(), &two).unwrap();
        settle(&a);
        std::fs::set_permissions(&blocked, std::fs::Permissions::from_mode(0o000)).unwrap();
        let _restore = Restore(blocked.clone());
        if std::fs::read(&blocked).is_ok() {
            return; // root 不受權限限制:這個環境做不出讀不到的檔案,略過。
        }
        let emitted = b.events.notices.lock().unwrap().len();
        let err = sync_once(&b.env()).unwrap_err();
        let notice = SyncNotice::SpaceDeleted { name: first_name.to_string(), by_device: "MacBook-A".to_string() };
        assert!(!first_file.exists(), "the first space was removed ({err})");
        assert!(b.state().notices.contains(&notice));
        assert_eq!(b.events.notices.lock().unwrap()[emitted..], [notice], "stored and announced, although a later step failed");
    }

    #[test]
    fn a_rate_limited_relay_info_ends_the_round_before_any_pull() {
        let (relay, _clock, _a, b, _words, _personal) = pair();
        b.runtime.core.lock().unwrap().relay_checked = None; // 新的行程:`GET /v1/info` 要再查一次
        relay.clear_calls();
        let faults = Faults { info: Some(rate_limited), ..Faults::default() };
        let out = run_with_faults(&b, &relay, &faults).unwrap();
        assert!(out.backoff);
        assert!(relay.calls().is_empty(), "nothing else is sent after the 429: {:?}", relay.calls());
        assert_eq!(b.runtime.core.lock().unwrap().failed_rounds, 1);
        assert_eq!(b.state().last_error.as_deref(), Some(RATE_LIMITED_MESSAGE));
        assert!(b.runtime.core.lock().unwrap().relay_checked.is_none(), "asked again next time");
        // 之後(沒有限流了):照常查、照常同步。
        settle(&b);
        assert!(b.state().last_error.is_none());
        assert_eq!(b.runtime.core.lock().unwrap().relay_checked.as_deref(), Some(crate::sync::testkit::RELAY_URL));
    }

    #[test]
    fn a_chain_delete_the_relay_fails_makes_the_round_back_off() {
        let (relay, _clock, a, _b, _words, _personal) = pair();
        let work = create_space(&a.env(), "Work").unwrap();
        settle(&a);
        delete_space(&a.env(), &work).unwrap();
        let faults = Faults { delete: Some(|| RelayError::Http(503)), ..Faults::default() };
        let out = run_with_faults(&a, &relay, &faults).unwrap();
        assert!(out.backoff);
        assert_eq!(a.runtime.core.lock().unwrap().failed_rounds, 1);
        assert_eq!(a.state().last_error.as_deref(), Some(RELAY_TROUBLE_MESSAGE));
        assert!(relay.exists(&work) && a.state().account.as_ref().unwrap().chain_deletes.len() == 1, "left for the next round");
        settle(&a);
        assert!(!relay.exists(&work));
        assert_eq!(a.runtime.core.lock().unwrap().failed_rounds, 0);
    }

    #[test]
    fn an_old_relay_does_not_pull_a_read_only_accounts_space_every_round() {
        let (relay, _clock, a, b, _words, personal) = pair();
        relay.set_legacy(true);
        for d in [&a, &b] {
            d.runtime.core.lock().unwrap().relay_checked = None;
        }
        // B 的帳戶格式比這版新:只套用、不上傳 —— 本機的修改一直是 dirty,不能因此每一輪都查。
        b.runtime.core.lock().unwrap().state.as_mut().unwrap().account.as_mut().unwrap().remote_schema_version =
            Some(crate::sync::record::ACCOUNT_SCHEMA_VERSION + 1);
        b.save_in_app(&b.space_path(&personal), "Host web\n");
        b.runtime.core.lock().unwrap().rounds = 1; // 接下來兩輪都不是輪到 space 的那一輪
        relay.clear_calls();
        sync_once(&b.env()).unwrap();
        sync_once(&b.env()).unwrap();
        let space = format!("pull:{}", &personal[..8]);
        assert!(!relay.calls().contains(&space), "{:?}", relay.calls());
        assert!(!relay.calls().iter().any(|c| c.starts_with("push:")), "a read-only account uploads nothing");
        assert!(b.state().spaces[&personal].records.values().any(|l| l.dirty));
        // 輪到的那一輪照常查。
        sync_once(&b.env()).unwrap();
        assert!(relay.calls().contains(&space));
    }

    #[test]
    fn a_rate_limited_pull_uploads_nothing_this_round() {
        let (relay, _clock, _a, b, _words, personal) = pair();
        b.save_in_app(&b.space_path(&personal), "Host web\n");
        crate::sync::account::set_device_name(&b.env(), "Renamed").unwrap();
        // 帳戶拉到了,這個 space 的 chain 被限流:這一輪不再對 relay 發任何請求 —— 帳戶與 space 都不上傳。
        relay.set_rate_limited(&personal, true);
        relay.clear_calls();
        sync_once(&b.env()).unwrap();
        let calls = relay.calls();
        assert!(!calls.iter().any(|c| c.starts_with("push:") || c.starts_with("delete:")), "{calls:?}");
        assert_eq!(b.state().last_error.as_deref(), Some(RATE_LIMITED_MESSAGE));
        assert_eq!(b.runtime.core.lock().unwrap().failed_rounds, 1);
        relay.set_rate_limited(&personal, false);
        settle(&b);
        let s = b.state();
        assert!(s.spaces[&personal].records.values().all(|l| !l.dirty) && s.account.as_ref().unwrap().records.values().all(|l| !l.dirty));
    }

    #[test]
    fn an_early_ending_round_that_asks_for_a_backoff_counts_as_a_failed_one() {
        // 拉帳戶時看到更換標記,同一批裡另一條 chain 被限流(這台自己正在更換同步碼:只回報)。
        let (relay, _clock, a, b, _words, personal) = pair();
        rotate_elsewhere(&a, &relay);
        relay.set_rate_limited(&personal, true);
        let (generation, s, keys) = snapshot(&b);
        let out = run_round(&b.env(), generation, s, keys, false).unwrap();
        assert_eq!((out.markers.len(), out.backoff), (1, true));
        assert_eq!(b.runtime.core.lock().unwrap().failed_rounds, 1);
        assert_eq!(b.state().last_error.as_deref(), Some(RATE_LIMITED_MESSAGE));
        // 上傳撞到凍結的 chain,而這一輪的拉取已經碰到 relay 出錯(批次 `5xx`,改逐條查詢)。
        let (relay, _clock, _a, b, _words, _personal) = pair();
        let keys = b.runtime.core.lock().unwrap().account_keys.clone().unwrap();
        relay.freeze_chain(&keys.chain_id, &keys.auth_token).unwrap();
        crate::sync::account::set_device_name(&b.env(), "Renamed").unwrap(); // 帳戶有東西要上傳
        b.runtime.core.lock().unwrap().batch_failures = 1;
        relay.fail_batches_with_5xx(1);
        let (generation, s, keys) = snapshot(&b);
        let out = run_round(&b.env(), generation, s, keys, true).unwrap();
        assert!(out.frozen && out.backoff);
        assert!(b.state().frozen().is_some());
        assert_eq!(b.runtime.core.lock().unwrap().failed_rounds, 1);
        assert_eq!(b.state().last_error.as_deref(), Some(RELAY_TROUBLE_MESSAGE));
    }

    #[test]
    fn an_account_upload_the_relay_refuses_ends_the_round_with_a_backoff() {
        let (relay, _clock, a, _b, _words, _personal) = pair();
        let account = a.state().account.unwrap().chain_id;
        let errors: [fn() -> RelayError; 3] = [
            quota_exceeded,
            || RelayError::InvalidRequest("a push takes 1 to 200 records".to_string()),
            || RelayError::BadResponse("a push of 3 records was answered with 2 results".to_string()),
        ];
        for (n, error) in errors.into_iter().enumerate() {
            crate::sync::account::set_device_name(&a.env(), &format!("A{n}")).unwrap(); // 帳戶有東西要上傳
            let faults = Faults { push: Some((account.clone(), error)), ..Faults::default() };
            assert!(run_with_faults(&a, &relay, &faults).is_err());
            assert_eq!(a.runtime.core.lock().unwrap().failed_rounds, n as u32 + 1, "the same upload would be refused again: back off");
        }
        settle(&a);
        assert_eq!(a.runtime.core.lock().unwrap().failed_rounds, 0);
        assert!(a.state().account.as_ref().unwrap().records.values().all(|l| !l.dirty));
    }

    #[test]
    fn a_batch_the_relay_answered_without_running_anything_is_a_failed_round() {
        let (relay, _clock, _a, b, _words, _personal) = pair();
        // 沒有 `429`、也沒有 `5xx`,可是帳戶沒拿到(一項都沒執行):當成 relay 出錯,退避。
        let faults = Faults { defer_batches: true, ..Faults::default() };
        let out = run_with_faults(&b, &relay, &faults).unwrap();
        assert!(out.backoff);
        assert_eq!(b.runtime.core.lock().unwrap().failed_rounds, 1);
        assert_eq!(b.state().last_error.as_deref(), Some(RELAY_TROUBLE_MESSAGE));
    }

    // ── 再審查的修正:審核對話框以內容認出那一版;更換標記被限流時退避 ──

    #[test]
    fn a_dialog_never_approves_another_devices_version_that_reused_the_seq_after_a_rollback() {
        let (relay, clock, a, b, words, personal) = pair();
        let c = TestDevice::new("c", &relay, &clock);
        join_account(&c.env(), &words, "MacBook-C").unwrap();
        select_space(&c.env(), &personal).unwrap();
        settle(&c);
        a.save_in_app(&a.space_path(&personal), "Host web\n  HostName 1\n");
        settle(&a);
        settle(&b);
        settle(&c);
        let backup = relay.rows(&personal).last().unwrap().seq;
        // C 改了 web、還沒同步(web 的第 2 版);A 也改了(同樣是第 2 版)並同步,B 保留它,對話框顯示 A 的那一版。
        c.save_in_app(&c.space_path(&personal), "Host web\n  HostName 1\n  ProxyCommand nc evil 22\n");
        a.save_in_app(&a.space_path(&personal), "Host web\n  HostName 1\n  ProxyCommand nc ok 22\n");
        settle(&a);
        settle(&b);
        let dialog = shown(&b, &personal);
        let shown_seq = b.state().spaces[&personal].pending_approvals["web"].seq;
        // 自架的 relay 從備份還原;C 接著同步,它的那一版拿到同一個序號(版本號也一樣)。B 的 space 檔被別的工具清空,從 chain
        // 重新長出,等著的變成 C 的那一版。
        relay.roll_back(&personal, backup);
        settle(&c);
        let asked = b.events.approvals.lock().unwrap().len();
        b.write_externally(&b.space_path(&personal), "");
        for _ in 0..3 {
            settle(&b);
        }
        let waiting = b.state().spaces[&personal].pending_approvals["web"].clone();
        assert!(waiting.text.contains("nc evil 22"));
        assert_eq!((waiting.seq, waiting.record.version), (shown_seq, 2), "the same seq and version as the open dialog");
        assert!(b.events.approvals.lock().unwrap().len() > asked, "the other version is asked about as a new one");
        // 使用者按下對話框(仍顯示 A 的那一版)的「核准」:內容對不上,什麼都不套用。
        let file = b.read(&b.space_path(&personal));
        assert_eq!(approve(&b.env(), &personal, &dialog).unwrap(), Reviewed { applied: 0, changed: vec!["web".to_string()] });
        assert_eq!(b.read(&b.space_path(&personal)), file, "the file is untouched");
        assert!(!file.contains("nc evil 22") && file.contains("Host web\n  HostName 1\n"));
        assert!(b.state().spaces[&personal].pending_approvals.contains_key("web"), "C's version still waits for its own review");
    }

    #[test]
    fn the_reviewed_version_pulled_again_at_a_new_seq_is_still_the_one_approved() {
        let (relay, _clock, a, b, _words, personal) = pair();
        a.save_in_app(&a.space_path(&personal), "Host web\n  HostName 1\n");
        settle(&a);
        settle(&b);
        let backup = relay.rows(&personal).last().unwrap().seq;
        let proxy = "Host web\n  HostName 1\n  ProxyCommand nc ok 22\n";
        a.save_in_app(&a.space_path(&personal), proxy);
        settle(&a);
        settle(&b);
        let dialog = shown(&b, &personal);
        let first_seq = b.state().spaces[&personal].pending_approvals["web"].seq;
        settle(&a); // A 的 cursor 走到自己上傳的那一版之後(上傳本身不推進 cursor)
        // 自架的 relay 從備份還原。A 發現之後把它有的重新上傳(這次先上傳另一台主機,web 拿到新的序號);B 再拉到同一版。
        relay.roll_back(&personal, backup);
        a.save_in_app(&a.space_path(&personal), &format!("Host db\n  HostName 9\n{proxy}"));
        settle(&a);
        let asked = b.events.approvals.lock().unwrap().len();
        settle(&b);
        let waiting = b.state().spaces[&personal].pending_approvals["web"].clone();
        assert_ne!(waiting.seq, first_seq, "the same version, at a new seq");
        assert_eq!(waiting.text, proxy);
        assert_eq!(b.events.approvals.lock().unwrap().len(), asked, "not asked again");
        // 對話框還開著:內容相同,核准的就是它。
        assert_eq!(approve(&b.env(), &personal, &dialog).unwrap(), Reviewed { applied: 1, changed: Vec::new() });
        assert!(b.read(&b.space_path(&personal)).contains("nc ok 22"));
    }

    #[test]
    fn a_frozen_device_backs_off_when_reading_the_markers_is_rate_limited() {
        let (relay, _clock, a, b, _words, personal) = pair();
        // B 已經拉過帳戶、還沒看到標記時,另一台凍結了所有 chain:B 的推送撞到 409,記下沒有標記的 `frozen`。
        rotate_elsewhere(&a, &relay);
        let keys = b.runtime.core.lock().unwrap().account_keys.clone().unwrap();
        let latest = relay.pull(&keys.chain_id, &keys.auth_token, 0).unwrap().latest_seq;
        b.runtime.core.lock().unwrap().state.as_mut().unwrap().account.as_mut().unwrap().cursor_seq = latest;
        b.save_in_app(&b.space_path(&personal), "Host local\n");
        sync_once(&b.env()).unwrap();
        assert!(b.state().frozen().unwrap().markers.is_empty());
        // 接下來讀標記的那一次被限流:同 `finish`,這一輪以退避收尾,不立刻再查。
        relay.set_rate_limited(&keys.chain_id, true);
        relay.clear_calls();
        let wakes = b.events.wakes();
        sync_once(&b.env()).unwrap();
        assert_eq!(relay.calls(), vec![format!("pull:{}", &keys.chain_id[..8])], "one request, nothing else");
        assert_eq!(b.runtime.core.lock().unwrap().failed_rounds, 1);
        assert_eq!(b.state().last_error.as_deref(), Some(RATE_LIMITED_MESSAGE));
        assert_eq!(b.events.wakes(), wakes);
        assert!(next_delay(&b.env()) >= Duration::from_secs(90));
        // 限流解除:讀到標記,退避歸零、說明清掉。
        relay.set_rate_limited(&keys.chain_id, false);
        sync_once(&b.env()).unwrap();
        assert_eq!(b.state().frozen().unwrap().markers[0].by_device_name, "MacBook-Z");
        assert_eq!(b.runtime.core.lock().unwrap().failed_rounds, 0);
        assert!(b.state().last_error.is_none());
    }
}
