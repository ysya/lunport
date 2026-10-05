//! Space 操作(spec §7.2)與危險設定的核准(spec §7.4):建立、改名、刪除、勾選、取消勾選、chain 不見時重建
//! (spec §9)、核准、拒絕;以及依最新的帳戶記錄調整這台的 space 檔(`reconcile_space_files`:改名、別台刪除、
//! Include 順序 —— 同步輪次提交帳戶之後也用它)。檔案一律照 spec §4.3 的順序:勾選先建檔再列進 Include;取消勾選與
//! 刪除先移出 Include 再備份刪檔;改名以 hard link 建立新檔名、目標已存在就保留舊檔名並提示。

use std::collections::HashSet;
use std::path::PathBuf;

use sha2::{Digest, Sha256};

use crate::config::commands::persist_file;
use crate::config::model::{Item, SshConfigDoc};
use crate::error::AppError;
use crate::sync::account::{account_ready, add_selected_file, put_new_space, selected_ids, space_payload, NOT_JOINED_MESSAGE};
use crate::sync::crypto::ChainKeys;
use crate::sync::env::SyncEnv;
use crate::sync::files::{apply_effects_to_items, check_managed_items, memory_matches_disk, space_path, write_include, EngineWrite};
use crate::sync::merge::{
    device_name, plan_device, put_account_record, put_space_key, selected_include_tokens, space_deleted_by, space_entries,
    space_entry, space_key_slot, space_keys,
};
use crate::sync::reconcile::HostEffect;
use crate::sync::record::{record_key, LocalRecord, RecordKind};
use crate::sync::relay::RelayError;
use crate::sync::runtime::{mutate, save_core, SyncCore};
use crate::sync::space_files::{self, slugify, space_file_name, RenameOutcome};
use crate::sync::state_v2::{AccountState, DeclinedVersion, PendingApproval, SpaceState, SyncNotice, SyncStateV2};

/// space 名稱的長度上限(字元)。檔名只用到 slug 的前 40 字元(spec §4.3)。
const MAX_SPACE_NAME: usize = 64;

/// space 名稱:去掉前後空白,不得為空、不得含控制字元、最長 64 字元。
pub fn clean_space_name(name: &str) -> Result<String, AppError> {
    let name = name.trim();
    if name.is_empty() {
        return Err(AppError::Other("space name cannot be empty".to_string()));
    }
    if name.chars().any(char::is_control) {
        return Err(AppError::Other("space name cannot contain control characters".to_string()));
    }
    if name.chars().count() > MAX_SPACE_NAME {
        return Err(AppError::Other(format!("space name can be at most {MAX_SPACE_NAME} characters")));
    }
    Ok(name.to_string())
}

/// 帳戶裡已有同名(不分大小寫)、未刪除的 space。UI 盡量避免重名,但不作為一致性保證(spec §4.1)。
fn name_taken(account: &AccountState, keys: &ChainKeys, name: &str, except: Option<&str>) -> bool {
    space_entries(account).iter().any(|e| {
        !e.deleted
            && space_deleted_by(account, keys, &e.id).is_none()
            && Some(e.id.as_str()) != except
            && e.name.to_lowercase() == name.to_lowercase()
    })
}

/// 已加入、可以改帳戶結構時的狀態快照與帳戶金鑰。
fn ready(env: &SyncEnv) -> Result<(SyncStateV2, ChainKeys), AppError> {
    let core = env.runtime.core.lock().unwrap();
    let s = core.state.clone().ok_or_else(|| AppError::Other("sync is not initialized".to_string()))?;
    account_ready(&s, core.account_keys.as_ref())?;
    Ok((s, core.account_keys.clone().expect("checked by account_ready")))
}

fn unknown_space(space_id: &str) -> AppError {
    AppError::NotFound(format!("space {space_id} is not in this sync account"))
}

/// 帳戶裡還在的 space(`space` 與 `spacekey` 都沒有被刪除)。
fn live_entry(account: &AccountState, keys: &ChainKeys, space_id: &str) -> Result<crate::sync::merge::SpaceEntry, AppError> {
    space_entry(account, space_id)
        .filter(|e| !e.deleted && space_deleted_by(account, keys, space_id).is_none())
        .ok_or_else(|| unknown_space(space_id))
}

/// `<slug>-<id8>.config` 的 slug 部分。
fn file_slug(file_name: &str) -> &str {
    file_name.strip_suffix(".config").and_then(|stem| stem.rsplit_once('-')).map_or(file_name, |(slug, _)| slug)
}

/// `reconcile_space_files` 的結果。
#[derive(Debug, Default)]
pub struct Reconciled {
    /// 新增、刪除或改名了 space 檔:呼叫端整份重載 doc。
    pub touched: bool,
    /// 新的提示(已存進狀態;呼叫端放掉鎖之後發 `sync://notice`)。
    pub notices: Vec<SyncNotice>,
}

/// `reconcile_space_files` 失敗:錯誤本身,加上失敗之前已經存進狀態的提示 —— 呼叫端放掉鎖之後照樣發 `sync://notice`,提示絕不
/// 只存進狀態、卻從來沒有通知過。
#[derive(Debug)]
pub struct ReconcileError {
    pub error: AppError,
    pub notices: Vec<SyncNotice>,
}

impl From<AppError> for ReconcileError {
    fn from(error: AppError) -> Self {
        Self { error, notices: Vec::new() }
    }
}

/// 依最新的帳戶記錄調整這台勾選的 space 檔(spec §4.3、§7.2):
/// 1. 帳戶已刪除(tombstone)的 space:先移出 Include、再備份並刪檔、刪掉它的狀態;別台刪的留下「已在 X 刪除」提示。
/// 2. 檔名與目前的 slug 不符(改名):hard link 建立新檔名 → Include 換成新名稱 → 刪舊名;新檔名已有檔案就什麼都
///    不改、保留舊檔名並提示(不覆蓋任何檔案)。
/// 3. 名稱改變影響 Include 的順序:換成新的順序。
///
/// 呼叫端持有 doc 與 backed_up 鎖、**不持有** core 鎖。
///
/// 每一步都先寫 Include、寫進去了才動 space 檔(`space_files::remove_space_file` / `rename_space_file` 的順序),所以
/// 寫不進去就一個檔案也不會刪、不會改名。失敗(任何 Err)而 doc 可能已經和磁碟不一致時,跟 `files::prepare_files` 一樣把 `doc`
/// 整份重載(讓它回到磁碟上的內容,下一次呼叫就在正確的基礎上重做)再回傳這個 Err:
/// - `AppError::Conflict`:主 config 在載入之後被 app 以外的編輯器改過(`files::write_include` 已把 in-memory 的 Include 清單退回
///   原樣、磁碟沒動;失敗的那一步沒有動任何 space 檔);
/// - 前面的步驟已經動過 space 檔(`touched`:刪了別台刪掉的 space 檔、改了名,doc 還列著舊的)—— 後面失敗的是什麼都一樣(狀態
///   存不了、I/O……)。`touched` 隨 Err 一起丟掉、呼叫端無從得知,所以由這裡重載。
///
/// 其他錯誤(什麼檔案都還沒動)原樣回傳、不重載。重載本身也失敗就回 `AppError::Other`、`doc` 維持原樣(它是呼叫端的鎖、這裡
/// 丟不掉)。**失敗時呼叫端放掉所有鎖之後要自己發 `applied(0)`**(doc 可能被重載了,前端要重讀),並發出 `ReconcileError::notices`
/// (失敗之前的步驟已經存進狀態的提示);`Conflict` 要當成「下一輪就能做完」而不是要停下來的錯誤(前面的步驟可能已經做完了,例如
/// 先刪了別台刪掉的 space 檔,失敗的是後面的改名)。
pub fn reconcile_space_files(
    env: &SyncEnv,
    doc: &mut SshConfigDoc,
    backed_up: &mut HashSet<PathBuf>,
    retention: Option<usize>,
) -> Result<Reconciled, ReconcileError> {
    let mut out = Reconciled::default();
    match reconcile_steps(env, doc, backed_up, retention, &mut out) {
        Ok(()) => Ok(out),
        Err(e) => {
            let notices = std::mem::take(&mut out.notices);
            if !out.touched && !matches!(e, AppError::Conflict(_)) {
                return Err(ReconcileError { error: e, notices });
            }
            let main = doc.files[0].path.clone();
            let error = match env.load_doc(&main) {
                Ok(fresh) => {
                    *doc = fresh;
                    e
                }
                Err(reload) => AppError::Other(format!("{e}; reloading the config afterwards also failed: {reload}")),
            };
            Err(ReconcileError { error, notices })
        }
    }
}

/// `reconcile_space_files` 的三個步驟;結果累積在 `out`。
fn reconcile_steps(
    env: &SyncEnv,
    doc: &mut SshConfigDoc,
    backed_up: &mut HashSet<PathBuf>,
    retention: Option<usize>,
    out: &mut Reconciled,
) -> Result<(), AppError> {
    let (account, spaces, me, keys) = {
        let core = env.runtime.core.lock().unwrap();
        match core.state.as_ref() {
            Some(s) => (s.account.clone(), s.spaces.clone(), s.device_id.clone(), core.account_keys.clone()),
            None => return Ok(()),
        }
    };
    let (Some(account), Some(keys)) = (account, keys) else { return Ok(()) };
    let tokens_without = |id: &str| -> Result<Vec<String>, AppError> {
        let core = env.runtime.core.lock().unwrap();
        let s = core.state.as_ref().ok_or_else(|| AppError::Other("sync is not initialized".to_string()))?;
        let mut rest = s.spaces.clone();
        rest.remove(id);
        selected_include_tokens(s.account.as_ref(), &rest)
    };
    for (id, space) in &spaces {
        let Some(by) = space_deleted_by(&account, &keys, id) else { continue };
        let entry = space_entry(&account, id);
        let tokens = tokens_without(id)?;
        space_files::remove_space_file(&env.ssh_dir, &space.file_name, || write_include(doc, backed_up, retention, &tokens))?;
        out.touched = true; // 檔案已經刪了:接下來狀態存不了也一樣要讓 doc 追上磁碟(`reconcile_space_files` 的失敗路徑看這個旗標)
        let mut core = env.runtime.core.lock().unwrap();
        if let Some(s) = core.state.as_mut() {
            s.spaces.remove(id);
            if by != me {
                let name = entry.map(|e| e.name).filter(|n| !n.is_empty()).unwrap_or_else(|| "A space".to_string());
                let notice = SyncNotice::SpaceDeleted { name, by_device: device_name(&account, &by) };
                if !s.notices.contains(&notice) {
                    s.notices.push(notice.clone());
                    out.notices.push(notice);
                }
            }
        }
        save_core(&mut core, &env.state_path)?;
    }
    let spaces = env.runtime.core.lock().unwrap().state.as_ref().map(|s| s.spaces.clone()).unwrap_or_default();
    for (id, space) in spaces.iter().filter(|(_, s)| s.selected) {
        let Some(entry) = space_entry(&account, id).filter(|e| !e.deleted) else { continue };
        if space_deleted_by(&account, &keys, id).is_some() {
            continue;
        }
        // 只有 slug 變了才改名:檔名裡的 id 可能屬於更換同步碼之前的 space(spec §7.5 保留檔名)。不必改名了(例如又改回
        // 原來的名稱)就清掉被擋下的記號。
        if file_slug(&space.file_name) == slugify(&entry.slug) {
            if space.rename_blocked.is_some() {
                let mut core = env.runtime.core.lock().unwrap();
                if let Some(sp) = core.state.as_mut().and_then(|s| s.spaces.get_mut(id)) {
                    sp.rename_blocked = None;
                }
                save_core(&mut core, &env.state_path)?;
            }
            continue;
        }
        let expected = space_file_name(&entry.slug, id)?;
        let tokens = {
            let core = env.runtime.core.lock().unwrap();
            let s = core.state.as_ref().ok_or_else(|| AppError::Other("sync is not initialized".to_string()))?;
            let mut renamed = s.spaces.clone();
            if let Some(sp) = renamed.get_mut(id) {
                sp.file_name = expected.clone();
            }
            selected_include_tokens(s.account.as_ref(), &renamed)?
        };
        let outcome = space_files::rename_space_file(&env.ssh_dir, &space.file_name, &expected, || {
            write_include(doc, backed_up, retention, &tokens)
        })?;
        let mut core = env.runtime.core.lock().unwrap();
        let Some(s) = core.state.as_mut() else { continue };
        match outcome {
            RenameOutcome::Renamed => {
                if let Some(sp) = s.spaces.get_mut(id) {
                    sp.file_name = expected;
                    sp.rename_blocked = None;
                }
                out.touched = true;
            }
            RenameOutcome::TargetExists => {
                // 每一輪都會重試改名:同一個目標仍被擋時不再提示(使用者可能已經看過、關掉了),只在剛被擋下或目標換了
                // 的時候提示一次。
                let first = s.spaces.get_mut(id).is_some_and(|sp| {
                    let first = sp.rename_blocked.as_deref() != Some(expected.as_str());
                    sp.rename_blocked = Some(expected.clone());
                    first
                });
                let notice = SyncNotice::RenameBlocked { space_id: id.clone(), name: entry.name.clone(), file_name: expected };
                if first && !s.notices.contains(&notice) {
                    s.notices.push(notice.clone());
                    out.notices.push(notice);
                }
            }
            RenameOutcome::Unchanged => {}
        }
        save_core(&mut core, &env.state_path)?;
    }
    let tokens = {
        let core = env.runtime.core.lock().unwrap();
        let s = core.state.as_ref().ok_or_else(|| AppError::Other("sync is not initialized".to_string()))?;
        selected_include_tokens(s.account.as_ref(), &s.spaces)?
    };
    write_include(doc, backed_up, retention, &tokens)?;
    Ok(())
}

/// 帳戶記錄改了之後在 doc 鎖內調整檔案,動了檔案就重載 doc。回傳新的提示。
fn reconcile_locked(env: &SyncEnv, doc_lock: &mut Option<SshConfigDoc>) -> Result<Reconciled, ReconcileError> {
    let Some(doc) = doc_lock.as_mut() else { return Ok(Reconciled::default()) };
    let mut backed_up = env.backed_up.lock().unwrap();
    let reconciled = reconcile_space_files(env, doc, &mut backed_up, env.retention())?;
    drop(backed_up);
    if reconciled.touched {
        let main = doc.files[0].path.clone();
        match env.load_doc(&main) {
            Ok(fresh) => *doc_lock = Some(fresh),
            Err(error) => return Err(ReconcileError { error, notices: reconciled.notices }),
        }
    }
    Ok(reconciled)
}

/// `reconcile_locked` 的結果(或之前就失敗的帳戶存檔),在**放掉所有鎖之後**處理 —— 帳戶記錄已經改了(存檔失敗時在記憶體,`unsaved`
/// 讓下一輪先重存),檔案那一半沒做完的由下一輪的 reconcile 做完:
/// - 失敗時 doc 可能已被整份重載(`reconcile_space_files`:`Conflict`,或前面的步驟已經動過檔案),不論哪一種都 `applied(0)` 通知前端重讀。
/// - `Conflict`(主 config 在載入之後被外部改過、失敗的那一步沒有動任何 space 檔)不是這個動作的錯:帳戶變更已經持久化,算成功(回 Ok,
///   失敗之前的提示交給 `announce`)。
/// - 其他錯誤:失敗之前的提示在這裡發出,錯誤原樣回傳。
///
/// 呼叫端不論結果都要 `wake()`:請背景執行緒馬上上傳這筆帳戶變更(存檔失敗時先重存)、做完檔案那一半。
fn settle(env: &SyncEnv, result: Result<Reconciled, ReconcileError>) -> Result<Reconciled, AppError> {
    match result {
        Ok(reconciled) => Ok(reconciled),
        Err(ReconcileError { error, notices }) => {
            env.events.applied(0);
            match error {
                AppError::Conflict(_) => Ok(Reconciled { touched: false, notices }),
                other => {
                    for notice in &notices {
                        env.events.notice(notice);
                    }
                    Err(other)
                }
            }
        }
    }
}

/// 提交的同一個 core 臨界區裡再確認一次 `account_ready`(spec §7.5):鎖外的快照之後 —— 建立 chain 的網路呼叫、等 doc 鎖、寫檔
/// 的期間 —— 同步輪次可能已經記下 `frozen`(它只拿 core 鎖),帳戶也可能已經換掉。`keys` = core 裡現在的帳戶金鑰;`account_keys`
/// = 快照時的帳戶金鑰:帳戶必須仍是它的。
fn still_ready(s: &SyncStateV2, keys: Option<&ChainKeys>, account_keys: &ChainKeys) -> Result<(), AppError> {
    account_ready(s, keys)?;
    match s.account.as_ref() {
        Some(account) if account.chain_id == account_keys.chain_id => Ok(()),
        _ => Err(AppError::Other(NOT_JOINED_MESSAGE.to_string())),
    }
}

/// `still_ready`,對 core 裡現在的狀態與金鑰。
fn still_ready_in(core: &SyncCore, account_keys: &ChainKeys) -> Result<(), AppError> {
    let s = core.state.as_ref().ok_or_else(|| AppError::Other(NOT_JOINED_MESSAGE.to_string()))?;
    still_ready(s, core.account_keys.as_ref(), account_keys)
}

fn announce(env: &SyncEnv, reconciled: &Reconciled) {
    for notice in &reconciled.notices {
        env.events.notice(notice);
    }
    if reconciled.touched {
        env.events.applied(0);
    }
}

/// `try_create_space` 失敗的原因:relay 對建立 chain 回了 `429`(每 IP 每小時 20 次)要和其他失敗分開 —— 搬移精靈一次建立好幾個 space(`migrate::move_into_new_spaces`),
/// 第一個 `429` 之後不能再對 relay 送出建立(spec §6.4、§7.2)。
#[derive(Debug)]
pub enum CreateError {
    RateLimited,
    Other(AppError),
}

impl From<AppError> for CreateError {
    fn from(e: AppError) -> Self {
        CreateError::Other(e)
    }
}

impl From<CreateError> for AppError {
    fn from(e: CreateError) -> Self {
        match e {
            CreateError::RateLimited => RelayError::RateLimited.into(),
            CreateError::Other(e) => e,
        }
    }
}

/// 建立 space(spec §7.2):產生 chain id、權杖、金鑰 → `PUT` 建 chain → 寫入 `space` 與 `spacekey` 記錄 → 建立者
/// 預設勾選(先建檔、再加進 Include;更新自己的 `device.spaces`)。回傳 space id。
pub fn create_space(env: &SyncEnv, name: &str) -> Result<String, AppError> {
    try_create_space(env, name).map_err(AppError::from)
}

/// `create_space`,但 relay 限流(`429`)分得出來(`CreateError::RateLimited`)。
pub fn try_create_space(env: &SyncEnv, name: &str) -> Result<String, CreateError> {
    let name = clean_space_name(name)?;
    let (s, account_keys) = ready(env)?;
    let account = s.account.as_ref().expect("joined");
    if name_taken(account, &account_keys, &name, None) {
        return Err(AppError::Other(format!("a space named '{name}' already exists")).into());
    }
    let keys = ChainKeys::generate()?;
    env.relay(&s.relay_url)?.create_chain(&keys.chain_id, &keys.auth_token).map_err(|e| match e {
        RelayError::RateLimited => CreateError::RateLimited,
        other => CreateError::Other(other.into()),
    })?;
    let now = env.now();
    let payload = space_payload(&name, now, None);
    let file_name = space_file_name(&payload.slug, &keys.chain_id)?;
    {
        let mut doc_lock = env.doc.lock().unwrap();
        {
            let mut core = env.runtime.core.lock().unwrap();
            // 建立 chain 的網路呼叫期間,同步輪次可能已經記下 `frozen`:凍結的帳戶裡不建立 space(換成新同步碼重新加入時帶不過去,
            // 它的檔案與主機就沒人管了)。
            still_ready_in(&core, &account_keys)?;
            let s = core.state.as_mut().expect("checked by still_ready_in");
            let me = s.device_id.clone();
            let account = s.account.as_mut().expect("checked by still_ready_in");
            put_new_space(account, &account_keys, &keys, &payload, &me, now)?;
            let mut space = SpaceState::new(&file_name);
            space.baseline_established = true; // 新的空 chain
            s.spaces.insert(keys.chain_id.clone(), space);
            let ids = selected_ids(s);
            let device = s.device_name.clone();
            plan_device(s.account.as_mut().expect("joined"), &me, &device, env.platform, &ids, now);
            core.generation += 1;
            save_core(&mut core, &env.state_path)?;
        }
        if let Err(e) = add_selected_file(env, &mut doc_lock, &file_name) {
            eprintln!("[sync] could not prepare the new space file ({e}); the next sync round retries");
        }
    }
    env.events.applied(0);
    env.events.wake();
    Ok(keys.chain_id)
}

/// 改名(spec §7.2):更新 `space` 記錄(名稱與 slug);這台若有勾選,依 §4.3 改名檔案並更新 Include。其他勾選的
/// 電腦收到記錄後在同步輪次裡做同樣的事。帳戶記錄存檔之後,檔案那一半碰到 `Conflict`(主 config 在載入之後被外部改過)不算這個動作
/// 失敗:回 Ok,doc 重載、`applied(0)`,`wake()` 請下一輪馬上上傳並做完改名(`settle`)。帳戶記錄存不進磁碟:修改留在記憶體(`unsaved`),
/// 檔案那一半留給先重存的下一輪,照樣 `settle` 與 `wake()`,回傳存檔的錯誤。
pub fn rename_space(env: &SyncEnv, space_id: &str, name: &str) -> Result<(), AppError> {
    let name = clean_space_name(name)?;
    let (s, account_keys) = ready(env)?;
    let account = s.account.as_ref().expect("joined");
    let entry = live_entry(account, &account_keys, space_id)?;
    if entry.name == name {
        return Ok(());
    }
    if name_taken(account, &account_keys, &name, Some(space_id)) {
        return Err(AppError::Other(format!("a space named '{name}' already exists")));
    }
    let now = env.now();
    let result = {
        let mut doc_lock = env.doc.lock().unwrap();
        let saved = {
            let mut core = env.runtime.core.lock().unwrap();
            // 等 doc 鎖的期間同步輪次可能已經記下 `frozen`:在提交的這個臨界區再確認一次。
            still_ready_in(&core, &account_keys)?;
            let s = core.state.as_mut().expect("checked by still_ready_in");
            let me = s.device_id.clone();
            let account = s.account.as_mut().expect("checked by still_ready_in");
            let payload = space_payload(&name, entry.created_at_ms, entry.previous_id.clone());
            put_account_record(account, RecordKind::Space, space_id, serde_json::to_value(payload).expect("SpacePayload serializes"), false, &me, now);
            core.generation += 1;
            save_core(&mut core, &env.state_path)
        };
        match saved {
            Ok(()) => reconcile_locked(env, &mut doc_lock),
            Err(e) => Err(ReconcileError::from(e)),
        }
    };
    let outcome = settle(env, result);
    env.events.wake();
    announce(env, &outcome?);
    Ok(())
}

/// 刪除 space(spec §7.2,已確認):tombstone `space` 與 `spacekey` → 這台依 §4.3 移除 Include 與檔案(先備份)、刪掉
/// 它的狀態。chain 的 `DELETE` 排進 `chain_deletes`,等 tombstone 上傳之後由同步輪次執行 —— 別台先收到 tombstone,
/// 就不會看到「chain 不見了、帳戶卻還有這個 space」。檔案那一半碰到 `Conflict`、帳戶記錄存不進磁碟的處理同 `rename_space`。
pub fn delete_space(env: &SyncEnv, space_id: &str) -> Result<(), AppError> {
    let (s, account_keys) = ready(env)?;
    let account = s.account.as_ref().expect("joined");
    let entry = live_entry(account, &account_keys, space_id)?;
    let now = env.now();
    let result = {
        let mut doc_lock = env.doc.lock().unwrap();
        let saved = {
            let mut core = env.runtime.core.lock().unwrap();
            // 等 doc 鎖的期間同步輪次可能已經記下 `frozen`:在提交的這個臨界區再確認一次。
            still_ready_in(&core, &account_keys)?;
            let s = core.state.as_mut().expect("checked by still_ready_in");
            let me = s.device_id.clone();
            let device = s.device_name.clone();
            let ids: Vec<String> = selected_ids(s).into_iter().filter(|id| id != space_id).collect();
            let account = s.account.as_mut().expect("checked by still_ready_in");
            if space_keys(account, &account_keys, space_id).is_some() {
                let sealed = account.sealed[&space_key_slot(&account_keys, space_id)].clone();
                account.chain_deletes.push(sealed);
            }
            let payload = space_payload(&entry.name, entry.created_at_ms, entry.previous_id.clone());
            put_account_record(account, RecordKind::Space, space_id, serde_json::to_value(payload).expect("SpacePayload serializes"), true, &me, now);
            put_space_key(account, &account_keys, space_id, None, &me, now)?;
            plan_device(account, &me, &device, env.platform, &ids, now);
            core.generation += 1;
            save_core(&mut core, &env.state_path)
        };
        match saved {
            Ok(()) => reconcile_locked(env, &mut doc_lock),
            Err(e) => Err(ReconcileError::from(e)),
        }
    };
    let outcome = settle(env, result);
    env.events.wake();
    announce(env, &outcome?);
    Ok(())
}

/// 勾選(spec §7.2):依 §4.3 建立空檔(已存在就保留內容)並加進 Include → 這個 space 以基線輪開始(chain 為準)→
/// 更新 `device.spaces`。
pub fn select_space(env: &SyncEnv, space_id: &str) -> Result<(), AppError> {
    let (s, account_keys) = ready(env)?;
    let account = s.account.as_ref().expect("joined");
    let entry = live_entry(account, &account_keys, space_id)?;
    if s.spaces.contains_key(space_id) {
        return Err(AppError::Other(format!("'{}' is already synced on this device", entry.name)));
    }
    if space_keys(account, &account_keys, space_id).is_none() {
        return Err(AppError::Other(format!("the key for '{}' has not arrived yet; sync and try again", entry.name)));
    }
    let file_name = space_file_name(&entry.slug, space_id)?;
    let now = env.now();
    {
        let mut doc_lock = env.doc.lock().unwrap();
        {
            let mut core = env.runtime.core.lock().unwrap();
            // 等 doc 鎖的期間同步輪次可能已經記下 `frozen`:在提交的這個臨界區再確認一次。
            still_ready_in(&core, &account_keys)?;
            let s = core.state.as_mut().expect("checked by still_ready_in");
            s.spaces.insert(space_id.to_string(), SpaceState::new(&file_name));
            let ids = selected_ids(s);
            let (me, device) = (s.device_id.clone(), s.device_name.clone());
            plan_device(s.account.as_mut().expect("checked by still_ready_in"), &me, &device, env.platform, &ids, now);
            core.generation += 1;
            save_core(&mut core, &env.state_path)?;
        }
        if let Err(e) = add_selected_file(env, &mut doc_lock, &file_name) {
            eprintln!("[sync] could not prepare the space file ({e}); the next sync round retries");
        }
    }
    env.events.applied(0);
    env.events.wake();
    Ok(())
}

/// 取消勾選(spec §7.2,已確認):依 §4.3 先移出 Include、再備份並刪檔,刪掉這個 space 的狀態(含還沒上傳的修改 ——
/// 檔案有備份),更新 `device.spaces`。relay 與其他電腦不受影響。檔案那一步失敗時狀態留在「取消勾選做到一半」
/// (`selected` = false),下一輪做完。
pub fn unselect_space(env: &SyncEnv, space_id: &str) -> Result<(), AppError> {
    let now = env.now();
    {
        let mut doc_lock = env.doc.lock().unwrap();
        // 要動手的檔名在 doc 鎖內讀:改名(同步輪次的帳戶那一步)與其他動 space 檔的動作都在這把鎖內做,這裡看到的才是磁碟上現在的
        // 檔名。鎖外讀的快照可能是改名之前的 —— 刪的是已經不存在的舊檔名、新檔名的檔案變成沒人管的雜檔。檢查(`account_ready`)、讀
        // 檔名與提交在同一個 core 臨界區:等 doc 鎖的期間同步輪次可能已經記下 `frozen`(它只拿 core 鎖)。
        let file_name = {
            let mut core = env.runtime.core.lock().unwrap();
            {
                let s = core.state.as_ref().ok_or_else(|| AppError::Other("sync is not initialized".to_string()))?;
                account_ready(s, core.account_keys.as_ref())?;
            }
            let s = core.state.as_mut().expect("checked above");
            let file_name = s
                .spaces
                .get(space_id)
                .filter(|sp| sp.selected)
                .map(|sp| sp.file_name.clone())
                .ok_or_else(|| AppError::Other("this space is not synced on this device".to_string()))?;
            if let Some(sp) = s.spaces.get_mut(space_id) {
                sp.selected = false;
            }
            let ids = selected_ids(s);
            let (me, device) = (s.device_id.clone(), s.device_name.clone());
            plan_device(s.account.as_mut().ok_or_else(|| AppError::Other(NOT_JOINED_MESSAGE.to_string()))?, &me, &device, env.platform, &ids, now);
            core.generation += 1;
            save_core(&mut core, &env.state_path)?;
            file_name
        };
        if let Some(doc) = doc_lock.as_mut() {
            let tokens = {
                let core = env.runtime.core.lock().unwrap();
                let s = core.state.as_ref().expect("initialized");
                selected_include_tokens(s.account.as_ref(), &s.spaces)?
            };
            let mut backed_up = env.backed_up.lock().unwrap();
            let removed = space_files::remove_space_file(&env.ssh_dir, &file_name, || {
                write_include(doc, &mut backed_up, env.retention(), &tokens)
            });
            drop(backed_up);
            match removed {
                Ok(_) => {
                    let mut core = env.runtime.core.lock().unwrap();
                    if let Some(s) = core.state.as_mut() {
                        s.spaces.remove(space_id);
                    }
                    save_core(&mut core, &env.state_path)?;
                    let main = doc.files[0].path.clone();
                    *doc_lock = Some(env.load_doc(&main)?);
                }
                Err(e) => eprintln!("[sync] could not remove the space file yet ({e}); the next sync round finishes it"),
            }
        }
    }
    env.events.applied(0);
    env.events.wake();
    Ok(())
}

/// relay 上這個 space 的 chain 不見了、帳戶卻仍有它(spec §9):以同一組位置與權杖重新 `PUT`,把這台的內容全部重新
/// 上傳(cursor 歸零、每筆記錄以 seq 0 標 dirty)。記帳同 `merge_space` 的「relay 歷史倒退」:原本乾淨的記錄只是為了讓 chain
/// 重新長出來才重傳,記進 `republish`(兩台各自重建、互相輸給對方的版本不算本機修改被覆蓋);待核准與拒絕的版本記的序號也屬於
/// 舊歷史,歸零(之後本機修改時才不會拿它當 base_seq)。`PUT` 成功不代表可寫:被凍結的 chain 刪除後仍是凍結的,之後的
/// push 會回 `409 frozen`,同步輪次照 §7.5 處理。
pub fn rebuild_space(env: &SyncEnv, space_id: &str) -> Result<(), AppError> {
    let (s, account_keys) = ready(env)?;
    if !s.spaces.get(space_id).is_some_and(|sp| sp.selected && sp.missing) {
        return Err(AppError::Other("this space is not missing on the relay".to_string()));
    }
    let account = s.account.as_ref().expect("joined");
    let keys = space_keys(account, &account_keys, space_id).ok_or_else(|| unknown_space(space_id))?;
    env.relay(&s.relay_url)?.create_chain(&keys.chain_id, &keys.auth_token)?;
    mutate(env, |s| {
        // 建立 chain 的網路呼叫期間同步輪次可能已經記下 `frozen`:在提交的這個臨界區再確認一次(帳戶金鑰在離開或重新加入時才會
        // 換,那時帳戶也跟著換了 —— 對照快照時的金鑰就夠)。
        still_ready(s, Some(&account_keys), &account_keys)?;
        let sp = s.spaces.get_mut(space_id).ok_or_else(|| unknown_space(space_id))?;
        sp.missing = false;
        sp.last_error = None;
        sp.cursor_seq = 0;
        for (key, local) in sp.records.iter_mut() {
            if !local.dirty {
                sp.republish.insert(key.clone());
            }
            local.seq = 0;
            local.dirty = true;
        }
        for pending in sp.pending_approvals.values_mut() {
            pending.seq = 0;
        }
        for declined in sp.declined.values_mut() {
            declined.seq = 0;
        }
        Ok(())
    })?;
    env.events.wake();
    Ok(())
}

/// `approve` / `reject` 的結果。
#[derive(Debug, Default, PartialEq)]
pub struct Reviewed {
    /// 實際處理了幾筆:`approve` = 套用的主機數,`reject` = 丟棄的待核准版本數。
    pub applied: usize,
    /// 略過的 alias:使用者看過的版本已經不是待核准清單上的那一版(被較新的版本取代、已經處理過、或已不在清單上)。較新的待核准
    /// 版本留在清單上,呼叫端顯示「已變更,請重新確認」。
    pub changed: Vec<String>,
}

/// 一筆待核准版本的內容指紋(spec §7.4):小寫 hex 的 SHA-256,涵蓋記錄的版本號、時間戳、寫入的裝置與區塊文字 —— 整數以固定
/// 8 位元組、字串以 8 位元組長度前綴編碼,前面再加一段固定的領域字串,欄位之間不會混淆。審核對話框連同 alias 送回 `approve` /
/// `reject`,用來認出使用者看過的是哪一版:序號在 relay 的歷史倒退或 chain 重建之後會重發,版本號是每台主機各自往上數的計數
/// (兩台同時修改會寫出同一個版本號),兩者都可能指到別的內容;內容一樣、只是從頭再拉到(換了序號)時指紋不變,開著的對話框
/// 照樣對得上。
pub fn review_digest(pending: &PendingApproval) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"sshelter/review/v1");
    hasher.update(pending.record.version.to_be_bytes());
    hasher.update(pending.record.updated_at_ms.to_be_bytes());
    for field in [pending.record.device_id.as_str(), pending.text.as_str()] {
        hasher.update((field.len() as u64).to_be_bytes());
        hasher.update(field.as_bytes());
    }
    hasher.finalize().iter().map(|b| format!("{b:02x}")).collect()
}

/// 使用者看過的 `(alias, digest)` 對照這個 space 目前的待核准清單(spec §7.4):`digest` 是那一版的 `review_digest`。對得上的連同
/// alias 取出(同一個 alias 傳多次只算一次、保持傳入順序);其他 alias 列進第二個回傳值,不動清單。呼叫端必須持有 doc 鎖:待核准的
/// 記錄只會在那把鎖內被換掉(同步輪次的發布、存檔 hook、核准、拒絕)。
fn reviewed_pending(space: &SpaceState, reviewed: &[(String, String)]) -> (Vec<(String, PendingApproval)>, Vec<String>) {
    let mut current: Vec<(String, PendingApproval)> = Vec::new();
    let mut changed: Vec<String> = Vec::new();
    for (alias, digest) in reviewed {
        match space.pending_approvals.get(alias).filter(|p| review_digest(p) == *digest) {
            Some(pending) if !current.iter().any(|(a, _)| a == alias) => current.push((alias.clone(), pending.clone())),
            Some(_) => {}
            None if !changed.contains(alias) => changed.push(alias.clone()),
            None => {}
        }
    }
    // 同一個 alias 只要有一筆對得上就算處理了。
    changed.retain(|alias| !current.iter().any(|(a, _)| a == alias));
    (current, changed)
}

/// 核准(spec §7.4):套用使用者看過的待核准版本 —— 寫進 space 檔、進快取(同一般遠端效果),從待核准清單移除。`approvals` 是
/// `(alias, digest)`:使用者看過的那一版的內容指紋(`review_digest`);**只有清單上仍是那一版(內容相同)的才套用**。已經被別的版本
/// 取代(或已處理、已不在清單上)的略過、列在回傳的 `changed`,那一版留在清單上等使用者重新看過 —— 套用的絕不是使用者沒看過的內容。
/// 「全部核准」= 傳入整個清單。
///
/// space、它的檔名與待核准的記錄都在 doc 鎖內讀(待核准的記錄只會在這把鎖內被換掉;鎖外讀的快照可能已經被同步輪次或改名換掉)。
/// 沒有任何一筆對得上就什麼都不做:不寫檔、不換 generation、不發事件;空清單同樣是 no-op。同其他結構性動作:已加入、沒有被更換
/// 同步碼、沒有正在更換才能核准(`account_ready`)—— 寫檔之前檢查一次,提交的 core 臨界區再檢查一次(寫檔的期間同步輪次可能記下了
/// `frozen`,它只拿 core 鎖;那時把檔案退回原本的內容、回錯誤)。檔案寫了之後狀態才存不進磁碟:核准留在記憶體(`unsaved`,下一輪先
/// 重存),照樣 `applied(n)` 與 `wake()`,再回傳存檔的錯誤。
pub fn approve(env: &SyncEnv, space_id: &str, approvals: &[(String, String)]) -> Result<Reviewed, AppError> {
    if approvals.is_empty() {
        return Ok(Reviewed::default());
    }
    let (reviewed, saved) = {
        let mut doc_lock = env.doc.lock().unwrap();
        let (file_name, pending, changed, account_keys) = {
            let (s, account_keys) = ready(env)?;
            let space = s.spaces.get(space_id).filter(|sp| sp.selected).ok_or_else(|| AppError::Other("this space is not synced on this device".to_string()))?;
            let (pending, changed) = reviewed_pending(space, approvals);
            (space.file_name.clone(), pending, changed, account_keys)
        };
        if pending.is_empty() {
            return Ok(Reviewed { applied: 0, changed });
        }
        let path = space_path(env, &file_name)?;
        let effects: Vec<HostEffect> = pending.iter().map(|(alias, p)| HostEffect::Upsert { alias: alias.clone(), text: p.text.clone() }).collect();
        let doc = doc_lock.as_mut().ok_or_else(|| AppError::Other("no config loaded".to_string()))?;
        let stale = doc.files.iter().find(|f| f.path == path).is_none_or(|f| !memory_matches_disk(f));
        if stale {
            let main = doc.files[0].path.clone();
            *doc_lock = Some(env.load_doc(&main)?);
        }
        let doc = doc_lock.as_mut().expect("loaded");
        let idx = doc.files.iter().position(|f| f.path == path).ok_or_else(|| AppError::Other("the space file is not loaded".to_string()))?;
        check_managed_items(&doc.files[idx].items)?;
        let mut items = doc.files[idx].items.clone();
        let (changed_items, failed) = apply_effects_to_items(&mut items, &effects);
        if !failed.is_empty() {
            return Err(AppError::Other(format!("{} host(s) could not be applied; nothing was changed", failed.len())));
        }
        // 寫檔之前的內容:提交時發現不能核准了,就把檔案退回這一版。
        let mut written: Option<(Vec<Item>, bool)> = None;
        if changed_items {
            let original_newline = doc.files[idx].trailing_newline;
            doc.files[idx].trailing_newline = original_newline || doc.files[idx].items.is_empty();
            let original = std::mem::replace(&mut doc.files[idx].items, items);
            let mut backed_up = env.backed_up.lock().unwrap();
            let _engine = EngineWrite::begin();
            if let Err(e) = persist_file(doc, idx, &mut backed_up, env.retention()) {
                doc.files[idx].items = original;
                doc.files[idx].trailing_newline = original_newline;
                drop(backed_up);
                let main = doc.files[0].path.clone();
                *doc_lock = env.load_doc(&main).ok();
                return Err(e);
            }
            written = Some((original, original_newline));
        }
        // 仍持有 doc 鎖:上面讀到的待核准記錄不會在這之間被換掉。
        let mut core = env.runtime.core.lock().unwrap();
        if let Err(e) = still_ready_in(&core, &account_keys) {
            drop(core);
            if let Some((original, original_newline)) = written {
                unwrite(env, &mut doc_lock, idx, original, original_newline);
            }
            drop(doc_lock);
            env.events.applied(0);
            return Err(e);
        }
        let sp = core.state.as_mut().and_then(|s| s.spaces.get_mut(space_id)).ok_or_else(|| unknown_space(space_id))?;
        for (alias, p) in pending {
            sp.pending_approvals.remove(&alias);
            sp.declined.remove(&alias);
            sp.records.insert(record_key(RecordKind::Host, &alias), LocalRecord { record: p.record, seq: p.seq, dirty: false });
        }
        core.generation += 1;
        let saved = save_core(&mut core, &env.state_path);
        (Reviewed { applied: effects.len(), changed }, saved)
    };
    env.events.applied(reviewed.applied);
    env.events.wake();
    saved?;
    Ok(reviewed)
}

/// `approve` 寫了檔之後才發現不能核准(提交時帳戶已被凍結):把 space 檔退回寫之前的內容(`EngineWrite`:不是本機編輯)。退不回去
/// 就從磁碟整份重載 doc(呼叫端之後發 `applied(0)`)。
fn unwrite(env: &SyncEnv, doc_lock: &mut Option<SshConfigDoc>, idx: usize, original: Vec<Item>, original_newline: bool) {
    let Some(doc) = doc_lock.as_mut() else { return };
    doc.files[idx].items = original;
    doc.files[idx].trailing_newline = original_newline;
    let restored = {
        let mut backed_up = env.backed_up.lock().unwrap();
        let _engine = EngineWrite::begin();
        persist_file(doc, idx, &mut backed_up, env.retention())
    };
    if restored.is_err() {
        let main = doc.files[0].path.clone();
        *doc_lock = env.load_doc(&main).ok();
    }
}

/// 拒絕(spec §7.4):丟棄使用者看過的待核准版本,本機維持原狀,不推送任何東西;只記下被拒絕的版本(`declined`)——
/// 之後本機修改這台主機時,新版本照 LWW 推送、蓋過它。`rejections` 與 `approve` 一樣是 `(alias, digest)`:只有清單上仍是那一版
/// 的才丟棄,已被別的版本取代(或已處理、已不在清單上)的略過、列在 `changed`,那一版不會被一個舊的拒絕連帶丟掉。空清單、沒有任何
/// 一筆對得上都是 no-op(不換 generation、不發事件)。同 `approve`,已加入、沒有被更換同步碼、沒有正在更換才能拒絕(檢查與提交在同一個
/// core 臨界區)。
pub fn reject(env: &SyncEnv, space_id: &str, rejections: &[(String, String)]) -> Result<Reviewed, AppError> {
    if rejections.is_empty() {
        return Ok(Reviewed::default());
    }
    let reviewed = {
        // doc 鎖 → core 鎖,待核准的記錄在 doc 鎖內讀。前置檢查同 `runtime::mutate`(存不了狀態、v1 升級還沒完成就拒絕)加上
        // `account_ready`;自己做而不用 `mutate`,是因為沒有任何一筆要丟棄時不該換 generation(`mutate` 一律會換)。
        let _doc = env.doc.lock().unwrap();
        let mut core = env.runtime.core.lock().unwrap();
        if let Some(reason) = &core.save_blocked {
            return Err(AppError::Other(reason.clone()));
        }
        if core.legacy.is_some() {
            return Err(AppError::Other(crate::sync::runtime::UPGRADING_MESSAGE.to_string()));
        }
        {
            let s = core.state.as_ref().ok_or_else(|| AppError::Other("sync is not initialized".to_string()))?;
            account_ready(s, core.account_keys.as_ref())?;
        }
        let sp = core
            .state
            .as_mut()
            .and_then(|s| s.spaces.get_mut(space_id))
            .ok_or_else(|| AppError::Other("this space is not synced on this device".to_string()))?;
        let (pending, changed) = reviewed_pending(sp, rejections);
        if pending.is_empty() {
            return Ok(Reviewed { applied: 0, changed });
        }
        for (alias, p) in &pending {
            sp.pending_approvals.remove(alias);
            sp.declined.insert(alias.clone(), DeclinedVersion { version: p.record.version, updated_at_ms: p.record.updated_at_ms, seq: p.seq });
        }
        core.generation += 1;
        save_core(&mut core, &env.state_path)?;
        Reviewed { applied: pending.len(), changed }
    };
    env.events.status();
    Ok(reviewed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sync::account::{create_account, FROZEN_MESSAGE, ROTATING_MESSAGE};
    use crate::sync::env::Clock;
    use crate::sync::fake_relay::FakeRelay;
    use crate::sync::merge::{devices, merge_space};
    use crate::sync::reconcile::encode;
    use crate::sync::record::{Envelope, Record, SpacePayload, SCHEMA_VERSION};
    use crate::sync::relay::{PullResponse, RelayApi};
    use crate::sync::state_v2::{FreezeInfo, RotationProgress};
    use crate::sync::testkit::{AppliedProbe, TestClock, TestDevice};

    fn new_device(name: &str) -> (TestDevice, String) {
        let (relay, clock) = (FakeRelay::new(), TestClock::new());
        let d = TestDevice::new(name, &relay, &clock);
        create_account(&d.env(), name).unwrap();
        let personal = d.state().spaces.keys().next().unwrap().clone();
        (d, personal)
    }

    fn include_line(d: &TestDevice) -> String {
        d.main_config().lines().find(|l| l.starts_with("Include ~/.ssh/sshelter/")).unwrap_or_default().to_string()
    }

    fn device_spaces(d: &TestDevice) -> Vec<String> {
        let s = d.state();
        devices(s.account.as_ref().unwrap()).into_iter().find(|(id, _)| id == &s.device_id).unwrap().1.spaces
    }

    #[test]
    fn space_names_must_be_present_short_and_unique() {
        let (d, _) = new_device("a");
        assert_eq!(clean_space_name("  Work  ").unwrap(), "Work");
        assert!(clean_space_name("   ").is_err());
        assert!(clean_space_name("a\nb").is_err());
        assert!(clean_space_name(&"x".repeat(65)).is_err());
        assert_eq!(create_space(&d.env(), "personal").unwrap_err().to_string(), "a space named 'personal' already exists");
    }

    #[test]
    fn a_space_whose_chain_cannot_be_created_leaves_nothing_behind() {
        let (d, _) = new_device("a");
        let before = d.state();
        d.relay.fail_creates_with_429(1);
        assert!(create_space(&d.env(), "Work").is_err());
        assert_eq!(d.state().account, before.account, "no record was written");
        assert_eq!(d.state().spaces.len(), 1);
        assert!(create_space(&d.env(), "Work").is_ok(), "trying again works");
    }

    #[test]
    fn a_new_space_gets_its_chain_records_file_and_include_line() {
        let (d, personal) = new_device("a");
        let work = create_space(&d.env(), "Work").unwrap();
        assert!(d.relay.exists(&work));
        let s = d.state();
        let account = s.account.as_ref().unwrap();
        assert_eq!(space_entries(account).iter().map(|e| e.name.as_str()).collect::<Vec<_>>(), vec!["Personal", "Work"]);
        assert!(account.records[&format!("space:{work}")].dirty);
        let keys = d.runtime.core.lock().unwrap().account_keys.clone().unwrap();
        assert!(account.sealed[&space_key_slot(&keys, &work)].dirty);
        assert!(s.spaces[&work].baseline_established && s.spaces[&work].selected);
        assert!(d.space_path(&work).is_file());
        let (p, w) = (s.spaces[&personal].file_name.clone(), s.spaces[&work].file_name.clone());
        assert_eq!(include_line(&d), format!("Include ~/.ssh/sshelter/{p} ~/.ssh/sshelter/{w}"));
        let loaded: Vec<PathBuf> = d.doc.lock().unwrap().as_ref().unwrap().files.iter().map(|f| f.path.clone()).collect();
        assert!(loaded.contains(&d.space_path(&personal)) && loaded.contains(&d.space_path(&work)));
        let mut expected = vec![personal, work];
        expected.sort();
        assert_eq!(device_spaces(&d), expected);
    }

    #[test]
    fn renaming_moves_the_file_and_keeps_the_old_name_when_the_target_exists() {
        let (d, personal) = new_device("a");
        let old = d.space_path(&personal);
        d.save_in_app(&old, "Host web\n");
        rename_space(&d.env(), &personal, "Home Lab").unwrap();
        let s = d.state();
        assert_eq!(space_entry(s.account.as_ref().unwrap(), &personal).unwrap().slug, "home-lab");
        let new = d.space_path(&personal);
        assert_eq!(new.file_name().unwrap().to_string_lossy(), format!("home-lab-{}.config", &personal[..8]));
        assert!(!old.exists());
        assert_eq!(d.read(&new), "Host web\n");
        assert!(include_line(&d).contains("home-lab-"));
        // 新檔名已被一個不在清單上的檔案佔用:不覆蓋、保留舊檔名、提示。
        let blocker = d.ssh_dir().join("sshelter").join(format!("office-{}.config", &personal[..8]));
        std::fs::write(&blocker, "Host keep\n").unwrap();
        rename_space(&d.env(), &personal, "Office").unwrap();
        assert_eq!(d.space_path(&personal), new, "the old file name stays");
        assert_eq!(d.read(&blocker), "Host keep\n");
        assert!(matches!(&d.state().notices[..], [SyncNotice::RenameBlocked { name, .. }] if name == "Office"));
        assert_eq!(d.events.notices.lock().unwrap().len(), 1);
    }

    #[test]
    fn deleting_a_space_tombstones_it_removes_the_file_and_queues_the_chain_delete() {
        let (d, personal) = new_device("a");
        let work = create_space(&d.env(), "Work").unwrap();
        let file = d.space_path(&work);
        d.save_in_app(&file, "Host db\n");
        delete_space(&d.env(), &work).unwrap();
        assert!(!file.exists());
        assert!(!include_line(&d).contains(&work[..8]));
        let s = d.state();
        assert!(!s.spaces.contains_key(&work));
        let account = s.account.as_ref().unwrap();
        assert!(space_entry(account, &work).unwrap().deleted);
        let keys = d.runtime.core.lock().unwrap().account_keys.clone().unwrap();
        assert!(space_keys(account, &keys, &work).is_none(), "the spacekey record is a tombstone");
        assert_eq!(account.chain_deletes.len(), 1, "the chain is deleted after the tombstones are uploaded");
        assert!(d.relay.exists(&work));
        assert!(s.notices.is_empty(), "no 'deleted on another device' notice for our own delete");
        assert_eq!(device_spaces(&d), vec![personal]);
        // 備份留著。
        let backups = crate::fsutil::backup_dir_for(&file).unwrap();
        assert!(std::fs::read_dir(backups).unwrap().any(|e| e.unwrap().file_name().to_string_lossy().starts_with(&format!("work-{}", &work[..8]))));
    }

    #[test]
    fn selecting_starts_a_baseline_and_unselecting_removes_the_include_then_the_file() {
        let (d, personal) = new_device("a");
        let work = create_space(&d.env(), "Work").unwrap();
        let file = d.space_path(&work);
        unselect_space(&d.env(), &work).unwrap();
        assert!(!file.exists());
        assert!(!d.state().spaces.contains_key(&work));
        assert_eq!(device_spaces(&d), vec![personal.clone()]);
        // 留下的同名檔案(例如離開帳戶之後):勾選時保留內容,以基線輪開始。
        std::fs::write(&file, "Host left\n").unwrap();
        select_space(&d.env(), &work).unwrap();
        let s = d.state();
        assert!(!s.spaces[&work].baseline_established);
        assert_eq!(d.read(&file), "Host left\n");
        assert!(include_line(&d).contains(&work[..8]));
        assert!(select_space(&d.env(), &work).is_err(), "already selected");
    }

    fn hold(d: &TestDevice, space_id: &str, alias: &str, text: &str) {
        let keys = ChainKeys::generate().unwrap();
        let record = Record {
            kind: RecordKind::Host,
            id: alias.into(),
            version: 3,
            updated_at_ms: d.clock.now_ms(),
            device_id: "dev-b".into(),
            deleted: false,
            payload: serde_json::json!({ "schema": 1, "text": text }),
        };
        let item = encode(&keys, &record, 0).unwrap();
        let env = Envelope { id_hash: item.id_hash, kind: item.kind, seq: 7, nonce: item.nonce, ciphertext: item.ciphertext, deleted: false };
        let mut core = d.runtime.core.lock().unwrap();
        let sp = core.state.as_mut().unwrap().spaces.get_mut(space_id).unwrap();
        let merged = merge_space(sp, &keys, &PullResponse { records: vec![env], latest_seq: 7 }, &[], |_| "MacBook-B".to_string());
        assert_eq!(merged.held, vec![alias.to_string()]);
        let cursor = sp.cursor_seq;
        *sp = merged.section;
        sp.cursor_seq = cursor;
    }

    /// 審核對話框送回的那一版:alias 與它現在的內容指紋(`review_digest`)。
    fn reviewed(d: &TestDevice, space_id: &str, alias: &str) -> (String, String) {
        (alias.to_string(), review_digest(&d.state().spaces[space_id].pending_approvals[alias]))
    }

    /// 使用者看過、卻已經不是待核准清單上的那一版:內容指紋對不上。
    fn stale(alias: &str) -> (String, String) {
        (alias.to_string(), "0".repeat(64))
    }

    #[test]
    fn approving_applies_the_held_block_and_rejecting_keeps_the_local_one() {
        let (d, personal) = new_device("a");
        let file = d.space_path(&personal);
        d.save_in_app(&file, "Host db\n  User me\n");
        let proxy = "Host web\n  ProxyCommand nc %h 22\n";
        hold(&d, &personal, "web", proxy);
        hold(&d, &personal, "db", "Host db\n  ForwardAgent yes\n");
        // 不在待核准清單上的主機:略過、回報「已變更」,什麼都不動。
        let ghost = approve(&d.env(), &personal, &[stale("ghost")]).unwrap();
        assert_eq!(ghost, Reviewed { applied: 0, changed: vec!["ghost".to_string()] });
        assert_eq!(approve(&d.env(), &personal, &[reviewed(&d, &personal, "web")]).unwrap(), Reviewed { applied: 1, changed: Vec::new() });
        assert_eq!(d.read(&file), format!("Host db\n  User me\n{proxy}"));
        let s = d.state();
        let sp = &s.spaces[&personal];
        assert!(!sp.pending_approvals.contains_key("web"));
        assert_eq!(sp.records["host:web"].seq, 7);
        assert!(!sp.records["host:web"].dirty, "an approved remote record is not a local edit");
        assert_eq!(reject(&d.env(), &personal, &[reviewed(&d, &personal, "db")]).unwrap(), Reviewed { applied: 1, changed: Vec::new() });
        let sp = d.state().spaces[&personal].clone();
        assert!(sp.pending_approvals.is_empty());
        assert_eq!(sp.declined["db"].seq, 7);
        assert_eq!(d.read(&file), format!("Host db\n  User me\n{proxy}"), "rejecting changes nothing locally");
    }

    #[test]
    fn structural_changes_wait_for_a_new_sync_code_or_a_finished_rotation() {
        let (d, personal) = new_device("a");
        d.runtime.core.lock().unwrap().state.as_mut().unwrap().account.as_mut().unwrap().frozen =
            Some(FreezeInfo { detected_at_ms: 1, markers: Vec::new() });
        assert_eq!(create_space(&d.env(), "Work").unwrap_err().to_string(), FROZEN_MESSAGE);
        assert_eq!(rename_space(&d.env(), &personal, "X").unwrap_err().to_string(), FROZEN_MESSAGE);
        // 核准與拒絕也是結構性動作:同樣要等新的同步碼(空清單是 no-op,不檢查)。
        let review = [stale("web")];
        assert_eq!(approve(&d.env(), &personal, &review).unwrap_err().to_string(), FROZEN_MESSAGE);
        assert_eq!(reject(&d.env(), &personal, &review).unwrap_err().to_string(), FROZEN_MESSAGE);
        let mut core = d.runtime.core.lock().unwrap();
        let s = core.state.as_mut().unwrap();
        s.account.as_mut().unwrap().frozen = None;
        s.rotation = Some(RotationProgress::new(&"c".repeat(64), 1));
        drop(core);
        assert_eq!(delete_space(&d.env(), &personal).unwrap_err().to_string(), ROTATING_MESSAGE);
        assert_eq!(approve(&d.env(), &personal, &review).unwrap_err().to_string(), ROTATING_MESSAGE);
        assert_eq!(reject(&d.env(), &personal, &review).unwrap_err().to_string(), ROTATING_MESSAGE);
    }

    #[test]
    fn a_space_missing_on_the_relay_is_rebuilt_from_this_device() {
        let (d, personal) = new_device("a");
        d.save_in_app(&d.space_path(&personal), "Host web\n");
        assert!(rebuild_space(&d.env(), &personal).is_err(), "only a missing space can be rebuilt");
        let keys = {
            let core = d.runtime.core.lock().unwrap();
            space_keys(core.state.as_ref().unwrap().account.as_ref().unwrap(), core.account_keys.as_ref().unwrap(), &personal).unwrap()
        };
        d.relay.delete_chain(&keys.chain_id, &keys.auth_token).unwrap();
        hold(&d, &personal, "db", "Host db\n  ForwardAgent yes\n");
        {
            let mut core = d.runtime.core.lock().unwrap();
            let sp = core.state.as_mut().unwrap().spaces.get_mut(&personal).unwrap();
            sp.missing = true;
            sp.cursor_seq = 12;
            sp.records.get_mut("host:web").unwrap().dirty = false;
            sp.declined.insert("old".to_string(), DeclinedVersion { version: 2, updated_at_ms: 5, seq: 9 });
        }
        rebuild_space(&d.env(), &personal).unwrap();
        assert!(d.relay.exists(&personal));
        let sp = d.state().spaces[&personal].clone();
        assert!(!sp.missing && sp.cursor_seq == 0);
        assert!(sp.records.values().all(|l| l.dirty && l.seq == 0));
        // 同 `merge_space` 的「relay 歷史倒退」:原本乾淨的記錄只是為了讓 chain 重新長出來才重傳(輸給之後的新版不算本機修改被
        // 覆蓋);待核准與拒絕的版本記的序號也屬於舊歷史,歸零。
        assert_eq!(sp.republish.iter().map(String::as_str).collect::<Vec<_>>(), vec!["host:web"]);
        assert_eq!((sp.pending_approvals["db"].seq, sp.declined["old"].seq), (0, 0));
    }

    // ── 主 config 在 app 以外被改過:`write_include` 的 Conflict 與 `files::prepare_files` 一樣處理(寫不進去就不動 space 檔、
    //    doc 整份重載、`applied(0)` 在鎖都放掉之後) ──

    /// 另一台電腦把 `space_id` 的 `space` 記錄改成 `name` / `slug`(account 記錄的寫入者是 `dev-b`)。
    fn remote_space(d: &TestDevice, space_id: &str, name: &str, slug: &str) {
        let now = d.clock.now_ms();
        let mut core = d.runtime.core.lock().unwrap();
        let account = core.state.as_mut().unwrap().account.as_mut().unwrap();
        let created_at_ms = space_entry(account, space_id).unwrap().created_at_ms;
        let payload = SpacePayload { schema: SCHEMA_VERSION, name: name.into(), slug: slug.into(), created_at_ms, previous_id: None };
        put_account_record(account, RecordKind::Space, space_id, serde_json::to_value(payload).unwrap(), false, "dev-b", now);
    }

    /// 另一台電腦刪除了 `space_id`:`space` 與 `spacekey` 都是 tombstone。
    fn remote_delete(d: &TestDevice, space_id: &str) {
        let now = d.clock.now_ms();
        let mut core = d.runtime.core.lock().unwrap();
        let keys = core.account_keys.clone().unwrap();
        let account = core.state.as_mut().unwrap().account.as_mut().unwrap();
        let entry = space_entry(account, space_id).unwrap();
        let payload = SpacePayload { schema: SCHEMA_VERSION, name: entry.name, slug: entry.slug, created_at_ms: entry.created_at_ms, previous_id: None };
        put_account_record(account, RecordKind::Space, space_id, serde_json::to_value(payload).unwrap(), true, "dev-b", now);
        put_space_key(account, &keys, space_id, None, "dev-b", now).unwrap();
    }

    /// 載入之後主 config 被另一個編輯器改過:下一次寫它的 `persist_file` 回 Conflict。回傳磁碟上現在的內容。
    fn external_edit(d: &TestDevice) -> String {
        let edited = format!("{}# edited elsewhere\n", d.main_config());
        d.write_externally(&d.main_path(), &edited);
        edited
    }

    /// 同步輪次提交帳戶之後的呼叫方式:持有 doc 與 backed_up 鎖、不持有 core 鎖。
    fn reconcile(d: &TestDevice) -> Result<Reconciled, AppError> {
        let env = d.env();
        let mut doc_lock = d.doc.lock().unwrap();
        let doc = doc_lock.as_mut().unwrap();
        let mut backed_up = d.backed_up.lock().unwrap();
        reconcile_space_files(&env, doc, &mut backed_up, None).map_err(|e| e.error)
    }

    /// doc 裡的主 config 正是磁碟上的內容(重載過):內容相符、指紋是新的。
    fn main_doc_matches_disk(d: &TestDevice) -> bool {
        let doc = d.doc.lock().unwrap();
        let main = &doc.as_ref().unwrap().files[0];
        memory_matches_disk(main) && !crate::fsutil::has_changed(&main.path, &main.fingerprint).unwrap()
    }

    #[test]
    fn a_main_config_edited_outside_the_app_stops_reconcile_before_any_space_file_changes() {
        // 別台刪除了 Work:Include 要先換掉才能刪檔 —— 寫不進去就一個檔案也不能刪。
        let (d, _) = new_device("a");
        let work = create_space(&d.env(), "Work").unwrap();
        let work_file = d.space_path(&work);
        d.save_in_app(&work_file, "Host db\n");
        remote_delete(&d, &work);
        let edited = external_edit(&d);
        let err = reconcile(&d).unwrap_err();
        assert!(matches!(err, AppError::Conflict(_)), "{err:?}");
        assert_eq!(d.read(&work_file), "Host db\n", "the file is still there");
        assert_eq!(d.main_config(), edited, "the list on the disk and the external edit are untouched");
        assert!(d.state().spaces.contains_key(&work) && d.state().notices.is_empty(), "nothing was recorded");
        assert!(main_doc_matches_disk(&d), "the doc was reloaded from the disk");
        // 下一次:doc 與磁碟一致,清單先換掉、檔案才備份並刪除,外部的編輯保留。
        let work_name = work_file.file_name().unwrap().to_string_lossy().into_owned();
        let done = reconcile(&d).unwrap();
        assert!(done.touched);
        assert_eq!(done.notices, vec![SyncNotice::SpaceDeleted { name: "Work".into(), by_device: "dev-b".into() }]);
        assert!(!work_file.exists() && !d.state().spaces.contains_key(&work));
        assert!(!d.main_config().contains(&work_name) && d.main_config().contains("# edited elsewhere"));

        // 別台改了 Personal 的名稱:新檔名(hard link)建好之後 Include 寫不進去 —— 新檔名要移除、舊檔名原封不動。
        let (d, personal) = new_device("a");
        let old = d.space_path(&personal);
        d.save_in_app(&old, "Host web\n");
        remote_space(&d, &personal, "Home Lab", "home-lab");
        let edited = external_edit(&d);
        let err = reconcile(&d).unwrap_err();
        assert!(matches!(err, AppError::Conflict(_)), "{err:?}");
        let renamed = old.with_file_name(format!("home-lab-{}.config", &personal[..8]));
        assert_eq!(d.read(&old), "Host web\n");
        assert!(!renamed.exists(), "the new name made for the rename was removed again");
        assert_eq!(d.main_config(), edited);
        let sp = d.state().spaces[&personal].clone();
        assert_eq!((sp.file_name.as_str(), sp.rename_blocked), (old.file_name().unwrap().to_str().unwrap(), None));
        assert!(main_doc_matches_disk(&d));
        let done = reconcile(&d).unwrap();
        assert!(done.touched && !old.exists());
        assert_eq!(d.read(&renamed), "Host web\n");
        assert_eq!(d.space_path(&personal), renamed);
        assert!(d.main_config().contains(renamed.file_name().unwrap().to_str().unwrap()) && d.main_config().contains("# edited elsewhere"));

        // 別台只改了名稱、slug 沒變(不必改檔名),但 Include 的順序變了:最後那一次寫 Include 失敗也一樣。
        let (d, personal) = new_device("a");
        let work = create_space(&d.env(), "Work").unwrap();
        let before = include_line(&d);
        remote_space(&d, &work, "Aardvark", "work");
        let edited = external_edit(&d);
        let err = reconcile(&d).unwrap_err();
        assert!(matches!(err, AppError::Conflict(_)), "{err:?}");
        assert_eq!(d.main_config(), edited);
        assert_eq!(include_line(&d), before);
        assert!(main_doc_matches_disk(&d));
        let done = reconcile(&d).unwrap();
        assert!(!done.touched, "only the list changed, no file was renamed or removed");
        let (p, w) = (d.state().spaces[&personal].file_name.clone(), d.state().spaces[&work].file_name.clone());
        assert_eq!(include_line(&d), format!("Include ~/.ssh/sshelter/{w} ~/.ssh/sshelter/{p}"));
        assert!(d.main_config().contains("# edited elsewhere"));
    }

    #[test]
    fn a_conflict_in_a_space_operation_reloads_the_doc_and_reports_once_every_lock_is_free() {
        let (d, personal) = new_device("a");
        let work = create_space(&d.env(), "Work").unwrap();
        let (personal_file, work_file) = (d.space_path(&personal), d.space_path(&work));
        d.save_in_app(&personal_file, "Host web\n");
        d.save_in_app(&work_file, "Host db\n");
        let probe = AppliedProbe::new(&d);
        let mut env = d.env();
        env.events = &probe;
        // 改名:帳戶記錄已經存檔、檔案那一半碰到 Conflict —— 動作本身成功(回 Ok;下一輪的 reconcile 完成檔案那一半,`wake` 請它
        // 馬上跑),檔案沒動;doc 重載、`applied(0)` 只發一次、在鎖都放掉之後。
        let edited = external_edit(&d);
        rename_space(&env, &personal, "Home Lab").unwrap();
        assert_eq!(*probe.all_free.lock().unwrap(), vec![true]);
        assert_eq!(probe.wakes(), 1);
        assert_eq!(space_entry(d.state().account.as_ref().unwrap(), &personal).unwrap().name, "Home Lab");
        assert_eq!(d.read(&personal_file), "Host web\n");
        assert_eq!(d.main_config(), edited);
        assert!(main_doc_matches_disk(&d));
        // 刪除:同樣。
        let edited = external_edit(&d);
        delete_space(&env, &work).unwrap();
        assert_eq!(*probe.all_free.lock().unwrap(), vec![true, true]);
        assert_eq!(probe.wakes(), 2);
        assert_eq!(d.read(&work_file), "Host db\n", "the file is still there");
        assert_eq!(d.main_config(), edited);
        assert!(d.state().spaces.contains_key(&work), "the file half of the delete is left for the next round");
        assert!(main_doc_matches_disk(&d));
        // 下一輪的 reconcile 把兩件事都做完。
        let done = reconcile(&d).unwrap();
        assert!(done.touched);
        assert!(!personal_file.exists() && !work_file.exists());
        assert_eq!(d.read(&d.space_path(&personal)), "Host web\n");
        assert!(!d.state().spaces.contains_key(&work));
    }

    // ── 核准與拒絕只認使用者看過的版本((alias, 內容指紋));狀態在 doc 鎖內讀 ──

    #[test]
    fn a_pending_version_that_a_round_replaced_while_approve_waited_is_skipped_and_stays_pending() {
        use std::time::Duration;
        let (d, personal) = new_device("a");
        let file = d.space_path(&personal);
        d.save_in_app(&file, "Host db\n");
        hold(&d, &personal, "web", "Host web\n  ProxyCommand nc v1 22\n"); // seq 7:使用者看過的版本
        let shown = [reviewed(&d, &personal, "web")];
        let applied_events = d.events.applied.lock().unwrap().len();
        let (d, personal) = (&d, &personal);
        let generation = std::thread::scope(|scope| {
            // 一輪正在「套用 + 發布」:持有 doc 鎖。
            let round = d.doc.lock().unwrap();
            let waiting = scope.spawn(move || approve(&d.env(), personal, &shown));
            std::thread::sleep(Duration::from_millis(200)); // approve 已經在等 doc 鎖
            // 這一輪發布了同一台主機的較新版本(seq 12):待核准的記錄被換掉,cursor 早已越過 seq 7 與 12。
            let generation = {
                let mut core = d.runtime.core.lock().unwrap();
                let p = core.state.as_mut().unwrap().spaces.get_mut(personal).unwrap().pending_approvals.get_mut("web").unwrap();
                p.record.version += 1;
                p.seq = 12;
                p.text = "Host web\n  ProxyCommand nc v2 22\n".to_string();
                core.generation += 1;
                core.generation
            };
            drop(round);
            // 使用者看過的那一版(seq 7)已經不是待核准的版本:略過、回報已變更。
            assert_eq!(waiting.join().unwrap().unwrap(), Reviewed { applied: 0, changed: vec!["web".to_string()] });
            generation
        });
        let sp = d.state().spaces[personal].clone();
        assert_eq!(sp.pending_approvals["web"].seq, 12, "the newer version stays pending, to be reviewed again");
        assert!(sp.pending_approvals["web"].text.contains("v2"));
        assert!(!sp.records.contains_key("host:web"), "neither version reached the cache");
        assert_eq!(d.read(&file), "Host db\n", "the file keeps its previous text");
        assert_eq!(d.runtime.core.lock().unwrap().generation, generation, "nothing was applied, so nothing was invalidated");
        assert_eq!(d.events.applied.lock().unwrap().len(), applied_events, "and nothing was announced");
    }

    #[test]
    fn reviewing_a_version_that_is_no_longer_the_pending_one_changes_nothing() {
        let (d, personal) = new_device("a");
        let file = d.space_path(&personal);
        d.save_in_app(&file, "Host db\n  User me\n");
        let proxy = "Host web\n  ProxyCommand nc %h 22\n";
        hold(&d, &personal, "web", proxy);
        hold(&d, &personal, "db", "Host db\n  ForwardAgent yes\n");
        let before = d.state();
        let generation = d.runtime.core.lock().unwrap().generation;
        let (applied_events, statuses, wakes) = (d.events.applied.lock().unwrap().len(), d.events.statuses(), d.events.wakes());
        // 使用者看的是別的版本(內容指紋對不上):略過;待核准的版本還在,沒有套用、也沒有記成「已拒絕」。
        let approved = approve(&d.env(), &personal, &[stale("web")]).unwrap();
        assert_eq!(approved, Reviewed { applied: 0, changed: vec!["web".to_string()] });
        let rejected = reject(&d.env(), &personal, &[stale("db")]).unwrap();
        assert_eq!(rejected, Reviewed { applied: 0, changed: vec!["db".to_string()] });
        assert_eq!(d.state(), before);
        assert_eq!(d.read(&file), "Host db\n  User me\n");
        assert_eq!(d.runtime.core.lock().unwrap().generation, generation);
        assert_eq!((d.events.applied.lock().unwrap().len(), d.events.statuses(), d.events.wakes()), (applied_events, statuses, wakes));
        // 一批裡有的對得上、有的過時:只處理對得上的(同一個 alias 傳兩次只算一次),過時的留在清單上。
        let web = reviewed(&d, &personal, "web");
        let mixed = [web.clone(), web.clone(), stale("db")];
        assert_eq!(approve(&d.env(), &personal, &mixed).unwrap(), Reviewed { applied: 1, changed: vec!["db".to_string()] });
        let sp = d.state().spaces[&personal].clone();
        assert!(!sp.pending_approvals.contains_key("web") && sp.pending_approvals.contains_key("db"));
        assert_eq!(d.read(&file), format!("Host db\n  User me\n{proxy}"));
        let rejected = reject(&d.env(), &personal, &[reviewed(&d, &personal, "db"), web]).unwrap();
        assert_eq!(rejected, Reviewed { applied: 1, changed: vec!["web".to_string()] }, "web was approved a moment ago");
        let sp = d.state().spaces[&personal].clone();
        assert!(sp.pending_approvals.is_empty() && sp.declined.keys().map(String::as_str).collect::<Vec<_>>() == vec!["db"]);
    }

    #[test]
    fn an_empty_review_is_a_no_op() {
        let (d, personal) = new_device("a");
        hold(&d, &personal, "web", "Host web\n  ProxyCommand nc %h 22\n");
        let before = d.state();
        let generation = d.runtime.core.lock().unwrap().generation;
        let (applied_events, statuses, wakes) = (d.events.applied.lock().unwrap().len(), d.events.statuses(), d.events.wakes());
        assert_eq!(approve(&d.env(), &personal, &[]).unwrap(), Reviewed::default());
        assert_eq!(reject(&d.env(), &personal, &[]).unwrap(), Reviewed::default());
        assert_eq!(d.state(), before);
        assert_eq!(d.runtime.core.lock().unwrap().generation, generation, "no generation bump");
        assert_eq!((d.events.applied.lock().unwrap().len(), d.events.statuses(), d.events.wakes()), (applied_events, statuses, wakes));
    }

    #[test]
    fn unselecting_acts_on_the_file_the_space_has_once_the_doc_lock_is_held() {
        use std::time::Duration;
        let (d, _) = new_device("a");
        let work = create_space(&d.env(), "Work").unwrap();
        let old = d.space_path(&work);
        d.save_in_app(&old, "Host db\n");
        let renamed = old.with_file_name(format!("lab-{}.config", &work[..8]));
        let (d, work) = (&d, &work);
        std::thread::scope(|scope| {
            // 同步輪次的帳戶那一步正在改名:持有 doc 鎖,檔案換了名字、狀態裡的檔名也換了。
            let mut doc_lock = d.doc.lock().unwrap();
            let unselecting = scope.spawn(move || unselect_space(&d.env(), work));
            std::thread::sleep(Duration::from_millis(200)); // unselect 已經在等 doc 鎖
            remote_space(d, work, "Lab", "lab");
            {
                let env = d.env();
                let doc = doc_lock.as_mut().unwrap();
                let mut backed_up = d.backed_up.lock().unwrap();
                assert!(reconcile_space_files(&env, doc, &mut backed_up, None).unwrap().touched);
            }
            let main = doc_lock.as_ref().unwrap().files[0].path.clone();
            *doc_lock = Some(d.env().load_doc(&main).unwrap());
            drop(doc_lock);
            unselecting.join().unwrap().unwrap();
        });
        assert!(!renamed.exists() && !old.exists(), "the file under its new name was removed, not left behind as a stray");
        assert!(!d.state().spaces.contains_key(work));
        assert!(!include_line(d).contains(&work[..8]));
        let backups = crate::fsutil::backup_dir_for(&renamed).unwrap();
        let prefix = format!("lab-{}", &work[..8]);
        assert!(std::fs::read_dir(backups).unwrap().any(|e| e.unwrap().file_name().to_string_lossy().starts_with(&prefix)), "and it was backed up first");
    }

    #[test]
    fn a_failure_after_reconcile_already_removed_a_file_still_reloads_the_doc() {
        let (d, _) = new_device("a");
        let work = create_space(&d.env(), "Work").unwrap();
        let work_file = d.space_path(&work);
        remote_delete(&d, &work);
        // 檔案刪掉之後狀態才存不了(不是 Conflict):`data` 被一個一般檔案擋住。
        let data = d.home.path().join("data");
        std::fs::remove_dir_all(&data).unwrap();
        std::fs::write(&data, b"in the way").unwrap();
        let err = reconcile(&d).unwrap_err();
        assert!(matches!(err, AppError::Io(_)), "{err:?}");
        assert!(!work_file.exists(), "the file was removed before the state could be saved");
        let doc = d.doc.lock().unwrap();
        assert!(!doc.as_ref().unwrap().files.iter().any(|f| f.path == work_file), "the doc no longer lists the removed file");
        drop(doc);
        assert!(main_doc_matches_disk(&d));
    }

    // ── 最終審查的修正:凍結的帳戶在提交的臨界區裡再擋一次;核准只認那一版;存檔失敗、後面的步驟失敗時照樣通知 ──

    /// 同步輪次記下「同步碼在別台換掉了」(只拿 core 鎖,同 `round::mark_frozen`)。
    fn freeze(d: &TestDevice) {
        let mut core = d.runtime.core.lock().unwrap();
        core.state.as_mut().unwrap().account.as_mut().unwrap().frozen = Some(FreezeInfo { detected_at_ms: 1, markers: Vec::new() });
    }

    fn unfreeze(d: &TestDevice) {
        d.runtime.core.lock().unwrap().state.as_mut().unwrap().account.as_mut().unwrap().frozen = None;
    }

    /// `op` 在另一個執行緒裡跑;它卡在這個執行緒拿著的鎖(doc,`backed_up` = true 時是 backed_up)上的時候,同步輪次記下了
    /// `frozen`。放開鎖之後回傳 `op` 的結果。
    fn frozen_while_waiting<T: Send>(d: &TestDevice, backed_up: bool, op: impl FnOnce() -> Result<T, AppError> + Send) -> Result<T, AppError> {
        std::thread::scope(|scope| {
            let doc = (!backed_up).then(|| d.doc.lock().unwrap());
            let held = backed_up.then(|| d.backed_up.lock().unwrap());
            let waiting = scope.spawn(op);
            std::thread::sleep(std::time::Duration::from_millis(200)); // `op` 已經在等那把鎖
            freeze(d);
            drop(held);
            drop(doc);
            waiting.join().unwrap()
        })
    }

    #[test]
    fn a_space_command_is_refused_when_the_sync_code_changed_while_it_waited() {
        let (d, personal) = new_device("a");
        let work = create_space(&d.env(), "Work").unwrap();
        let home = create_space(&d.env(), "Home").unwrap();
        unselect_space(&d.env(), &home).unwrap();
        let (personal_file, work_file) = (d.space_path(&personal), d.space_path(&work));
        d.save_in_app(&personal_file, "Host db\n");
        hold(&d, &personal, "web", "Host web\n  ProxyCommand nc %h 22\n");
        d.runtime.core.lock().unwrap().state.as_mut().unwrap().spaces.get_mut(&work).unwrap().missing = true;
        let before = d.state();
        let generation = d.runtime.core.lock().unwrap().generation;
        let (web_rejected, web_approved) = (reviewed(&d, &personal, "web"), reviewed(&d, &personal, "web"));
        let dd = &d;
        let (p, w, h) = (personal.as_str(), work.as_str(), home.as_str());
        // 一個接一個:每個動作開始時帳戶都還沒凍結(鎖外的檢查都會過),等鎖的時候才凍結。
        let refused = |what: &str, result: Result<(), AppError>| {
            assert_eq!(result.map_err(|e| e.to_string()), Err(FROZEN_MESSAGE.to_string()), "{what}");
            unfreeze(dd);
        };
        refused("rename", frozen_while_waiting(dd, false, move || rename_space(&dd.env(), p, "Lab")));
        refused("delete", frozen_while_waiting(dd, false, move || delete_space(&dd.env(), w)));
        refused("select", frozen_while_waiting(dd, false, move || select_space(&dd.env(), h)));
        refused("unselect", frozen_while_waiting(dd, false, move || unselect_space(&dd.env(), w)));
        refused("rebuild", frozen_while_waiting(dd, false, move || rebuild_space(&dd.env(), w)));
        refused("reject", frozen_while_waiting(dd, false, move || reject(&dd.env(), p, &[web_rejected]).map(|_| ())));
        // 核准在 doc 鎖內檢查過、寫檔之前才等 backed_up:凍結是在檢查之後才記下的 —— 提交時再擋一次,檔案退回原本的內容。
        refused("approve", frozen_while_waiting(dd, true, move || approve(&dd.env(), p, &[web_approved]).map(|_| ())));
        assert_eq!(d.state(), before, "nothing was changed");
        assert_eq!(d.runtime.core.lock().unwrap().generation, generation);
        assert_eq!(d.read(&personal_file), "Host db\n", "the approved block was taken out again");
        assert!(work_file.is_file() && d.main_config().contains(&work_file.file_name().unwrap().to_string_lossy().to_string()));
        assert!(!d.ssh_dir().join("sshelter").join(format!("home-{}.config", &home[..8])).exists());
    }

    #[test]
    fn creating_a_space_while_a_round_records_a_changed_sync_code_creates_nothing() {
        use crate::sync::round::sync_once;
        use crate::sync::round::tests::{pair, rotate_elsewhere};
        use crate::sync::testkit::{HookedConnector, Hooks};
        use std::sync::Arc;
        let (relay, _clock, a, b, _words, _personal) = pair();
        rotate_elsewhere(&a, &relay);
        let main = b.main_config();
        let dir = b.ssh_dir().join("sshelter");
        let files = || std::fs::read_dir(&dir).unwrap().count();
        let before = files();
        // 建立 space 的 chain(網路呼叫)的那一刻,背景執行緒的一輪拉到更換標記、記下 `frozen`。
        let b = Arc::new(b);
        let round = Arc::clone(&b);
        let hooks = Hooks {
            before_create: Some(Box::new(move || {
                let _ = sync_once(&round.env());
            })),
            ..Hooks::default()
        };
        let connector = HookedConnector::new(&relay, hooks);
        let mut env = b.env();
        env.relays = &connector;
        assert_eq!(create_space(&env, "Work").unwrap_err().to_string(), FROZEN_MESSAGE);
        let s = b.state();
        assert_eq!(s.frozen().map(|f| f.markers.len()), Some(1), "the round did record the change");
        assert_eq!(s.spaces.len(), 1, "no space was added");
        assert_eq!(space_entries(s.account.as_ref().unwrap()).len(), 1, "no space record was written");
        assert_eq!(b.main_config(), main, "no Include line was added");
        assert_eq!(files(), before, "no file was created");
    }

    #[test]
    fn a_pending_entry_with_the_same_seq_and_version_but_other_content_is_not_the_reviewed_one() {
        // relay 的歷史倒退或 chain 重建之後,序號從頭再發;版本號是每台主機各自往上數的計數 —— 另一台同時修改的那一版可能拿到同一個
        // 序號、同一個版本號。對話框顯示的那一版只能以內容認出來。
        let (d, personal) = new_device("a");
        let file = d.space_path(&personal);
        d.save_in_app(&file, "Host db\n");
        hold(&d, &personal, "web", "Host web\n  ProxyCommand nc ok 22\n");
        let shown = [reviewed(&d, &personal, "web")];
        {
            let mut core = d.runtime.core.lock().unwrap();
            let p = core.state.as_mut().unwrap().spaces.get_mut(&personal).unwrap().pending_approvals.get_mut("web").unwrap();
            // 同一個序號(7)、同一個版本號(3);寫入的裝置、時間與內容都不同。
            let text = "Host web\n  ProxyCommand nc evil 22\n";
            p.record.device_id = "dev-c".into();
            p.record.updated_at_ms += 1;
            p.record.payload = serde_json::json!({ "schema": 1, "text": text });
            p.text = text.to_string();
        }
        let before = d.state();
        let changed = Reviewed { applied: 0, changed: vec!["web".to_string()] };
        assert_eq!(approve(&d.env(), &personal, &shown).unwrap(), changed);
        assert_eq!(reject(&d.env(), &personal, &shown).unwrap(), changed);
        assert_eq!(d.state(), before);
        assert_eq!(d.read(&file), "Host db\n");
        // 重新顯示之後核准的就是那一版。
        assert_eq!(approve(&d.env(), &personal, &[reviewed(&d, &personal, "web")]).unwrap().applied, 1);
        assert!(d.read(&file).contains("nc evil 22"));
    }

    #[test]
    fn the_review_digest_covers_the_content_and_not_the_seq() {
        let record = Record {
            kind: RecordKind::Host,
            id: "web".into(),
            version: 3,
            updated_at_ms: 1_700_000_000_000,
            device_id: "ab".into(),
            deleted: false,
            payload: serde_json::json!({ "schema": 1, "text": "c" }),
        };
        let pending = PendingApproval {
            record,
            seq: 7,
            text: "c".into(),
            applied: crate::sync::approval::signature(""),
            incoming: crate::sync::approval::signature("c"),
            from_device: "MacBook-B".into(),
        };
        let digest = review_digest(&pending);
        assert_eq!(digest.len(), 64);
        assert!(digest.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)));
        // 同一版換了序號(從頭再拉到):指紋不變。
        let mut moved = pending.clone();
        moved.seq = 12;
        assert_eq!(review_digest(&moved), digest);
        // 任何一個欄位不同就是另一版 —— 包括欄位之間的界線(裝置 "ab" + 文字 "c" ≠ 裝置 "a" + 文字 "bc")。
        let variants: [fn(&mut PendingApproval); 5] = [
            |p| p.record.version += 1,
            |p| p.record.updated_at_ms += 1,
            |p| p.record.device_id = "ac".into(),
            |p| p.text = "d".into(),
            |p| {
                p.record.device_id = "a".into();
                p.text = "bc".into();
            },
        ];
        for change in variants {
            let mut other = pending.clone();
            change(&mut other);
            assert_ne!(review_digest(&other), digest, "{:?}", (other.record.version, other.record.updated_at_ms, &other.record.device_id, &other.text));
        }
    }

    #[test]
    fn an_approval_whose_state_cannot_be_saved_still_reports_the_written_file() {
        let (d, personal) = new_device("a");
        let file = d.space_path(&personal);
        d.save_in_app(&file, "Host db\n");
        hold(&d, &personal, "web", "Host web\n  ProxyCommand nc %h 22\n");
        // 狀態檔所在的 `data` 被一個一般檔案擋住:space 檔寫了之後,狀態存不了。
        let data = d.home.path().join("data");
        std::fs::remove_dir_all(&data).unwrap();
        std::fs::write(&data, b"in the way").unwrap();
        let web = reviewed(&d, &personal, "web");
        let (applied, wakes) = (d.events.applied.lock().unwrap().len(), d.events.wakes());
        assert!(approve(&d.env(), &personal, &[web]).is_err());
        assert!(d.read(&file).contains("ProxyCommand nc %h 22"), "the file was written");
        assert_eq!(d.events.applied.lock().unwrap()[applied..], [1], "and the front end is told so");
        assert_eq!(d.events.wakes(), wakes + 1, "the next round saves the state before anything else");
        let core = d.runtime.core.lock().unwrap();
        assert!(core.unsaved);
        let sp = &core.state.as_ref().unwrap().spaces[&personal];
        assert!(sp.records.contains_key("host:web") && !sp.pending_approvals.contains_key("web"), "the approval is kept in memory");
    }

    #[test]
    fn a_rename_or_delete_whose_account_record_cannot_be_saved_still_wakes_the_round() {
        let (d, personal) = new_device("a");
        let work = create_space(&d.env(), "Work").unwrap();
        let (personal_file, work_file) = (d.space_path(&personal), d.space_path(&work));
        let data = d.home.path().join("data");
        std::fs::remove_dir_all(&data).unwrap();
        std::fs::write(&data, b"in the way").unwrap();
        let wakes = d.events.wakes();
        assert!(rename_space(&d.env(), &personal, "Lab").is_err());
        assert_eq!(d.events.wakes(), wakes + 1, "the next round saves the record first, then uploads it");
        assert_eq!(space_entry(d.state().account.as_ref().unwrap(), &personal).unwrap().name, "Lab", "kept in memory");
        assert!(d.runtime.core.lock().unwrap().unsaved);
        assert!(personal_file.exists(), "the file half waits until the state is saved");
        assert!(delete_space(&d.env(), &work).is_err());
        assert_eq!(d.events.wakes(), wakes + 2);
        assert!(work_file.exists());
        // 擋路的東西移開:下一輪先重存狀態,再做完檔案那一半。
        std::fs::remove_file(&data).unwrap();
        crate::sync::round::tests::settle(&d);
        assert!(!d.runtime.core.lock().unwrap().unsaved);
        assert!(!personal_file.exists() && !work_file.exists());
        assert!(d.space_path(&personal).ends_with(format!("lab-{}.config", &personal[..8])));
    }

    #[cfg(unix)]
    #[test]
    fn notices_of_the_steps_done_before_a_failure_are_still_announced() {
        use std::os::unix::fs::PermissionsExt;
        struct Restore(PathBuf);
        impl Drop for Restore {
            fn drop(&mut self) {
                let _ = std::fs::set_permissions(&self.0, std::fs::Permissions::from_mode(0o600));
            }
        }
        let (d, personal) = new_device("a");
        let one = create_space(&d.env(), "One").unwrap();
        let two = create_space(&d.env(), "Two").unwrap();
        // 別台刪了兩個 space。依 id 排在後面的那個檔案讀不到(備份不了就不刪):第一個刪掉、留下提示之後,第二個失敗。
        let (first, second) = if one < two { (one.clone(), two.clone()) } else { (two.clone(), one.clone()) };
        let first_name = if first == one { "One" } else { "Two" };
        let first_file = d.space_path(&first);
        let blocked = d.space_path(&second);
        remote_delete(&d, &first);
        remote_delete(&d, &second);
        std::fs::set_permissions(&blocked, std::fs::Permissions::from_mode(0o000)).unwrap();
        let _restore = Restore(blocked.clone());
        if std::fs::read(&blocked).is_ok() {
            return; // root 不受權限限制:這個環境做不出讀不到的檔案,略過。
        }
        let err = rename_space(&d.env(), &personal, "Lab").unwrap_err();
        let notice = SyncNotice::SpaceDeleted { name: first_name.to_string(), by_device: "dev-b".to_string() };
        assert!(!first_file.exists(), "the first space was removed ({err})");
        assert!(d.state().notices.contains(&notice));
        assert_eq!(*d.events.notices.lock().unwrap(), vec![notice], "stored and announced, although a later step failed");
        assert!(blocked.exists());
    }
}
