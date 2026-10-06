//! 帳戶生命週期(spec §7.3)與這台的同步設定:建立、加入、離開(含刪除帳戶)、relay URL 與 `GET /v1/info`、裝置
//! 名稱、Forget、顯示同步碼。網路一律在鎖外;會改帳戶的動作由呼叫端(Tauri command)全程持有 lifecycle 鎖、在
//! `spawn_blocking` 裡呼叫。

use std::path::{Path, PathBuf};

use crate::config::commands::persist_file;
use crate::config::model::{Item, SshConfigDoc};
use crate::error::AppError;
use crate::sync::crypto::{self, ChainKeys};
use crate::sync::env::{Keychain, SyncEnv};
use crate::sync::files::write_include;
use crate::sync::hosts_file::{self, release_include};
use crate::sync::merge::{
    merge_account, plan_device, put_account_record, put_space_key, space_entries, space_keys, AccountMerged,
};
use crate::sync::record::{MetaPayload, RecordKind, SpaceKeyPayload, SpacePayload, ACCOUNT_META_ID, SCHEMA_VERSION};
use crate::sync::relay::{RelayClient, RelayError, RelayInfo};
use crate::sync::rotation::{read_new_code, NewCode};
use crate::sync::runtime::{mutate, save_core, snapshot, SyncCore};
use crate::sync::space_files::{self, slugify, space_file_name, KeptFile};
use crate::sync::state::MNEMONIC_ACCOUNT;
use crate::sync::state_v2::{AccountState, RelayFeatures, SealedRecord, SpaceState, SyncNotice, SyncStateV2, NEXT_MNEMONIC_ACCOUNT};

/// 預設 space 的名稱(spec §7.3)。
pub const DEFAULT_SPACE_NAME: &str = "Personal";
pub const NO_ACCOUNT_MESSAGE: &str = "no sync account matches this sync code (check the words and the relay URL)";
pub const OLD_FORMAT_MESSAGE: &str =
    "this sync code still uses the previous sync format: update SSHelter on a device that already syncs with it, let it upgrade, then join again";
pub const NOT_JOINED_MESSAGE: &str = "join or create a sync account first";
pub const NO_KEYS_MESSAGE: &str = "the sync code is not available on this device; unlock the keychain and restart SSHelter";
pub const FROZEN_MESSAGE: &str = "the sync code was changed on another device; enter the new sync code first";
pub const ROTATING_MESSAGE: &str = "finish or cancel changing the sync code first";
pub const READ_ONLY_MESSAGE: &str = "this sync account uses a newer format; update SSHelter to keep syncing";
const NO_CONFIG_MESSAGE: &str =
    "SSHelter could not load your SSH config — create it (an empty ~/.ssh/config is fine) and reload, then try again";
const NO_RELAY_MESSAGE: &str = "enter a relay URL first (Settings → Sync → Relay URL) — this build has no built-in relay";
const OTHER_ACCOUNT_MESSAGE: &str = "the sync code in the keychain belongs to a different sync account; leave and join again";
const LEAVE_ROTATING_MESSAGE: &str =
    "a sync code change is in progress; let it finish (it resumes on its own) before this computer leaves";
/// 離開時更換同步碼卡在凍結之後、新碼已經不見(`rotation::NewCode::Gone`):這台已經離開(回成錯誤,同 `LEAVE_REPLACED_MESSAGE`)。舊帳戶已凍結、帶著更換標記,
/// `join_account` 拒絕它(「這組同步碼已被更換,請輸入新碼」,而新碼不存在),所以誰都不能再加入它 —— 文字不能說「再加入」:出路是其中一台建立新的同步帳戶,
/// 其他電腦離開舊帳戶(檔案留成本機檔案)、加入新的。`delete_remote`:要求刪除帳戶也不刪,relay 上的更換標記是其他電腦得知這件事的唯一來源。
fn leave_abandoned_message(delete_remote: bool) -> String {
    format!(
        "left the sync account on this computer, but its sync code change could not be finished (the new sync code was missing from the keychain), so the old sync account can no longer be joined — create a new sync account on one computer, and on the other computers leave the old account (their synced files stay as local files) and join the new one{}",
        if delete_remote { ". The sync account was not deleted from the relay" } else { "" }
    )
}
const LEAVE_REPLACED_MESSAGE: &str = "left the sync account on this computer, but did not delete it from the relay: its sync code was changed on another device, and the computers still on the old code learn the change from it";

/// 裝置名稱:去掉前後空白,不得為空。
pub fn clean_device_name(name: &str) -> Result<String, AppError> {
    let name = name.trim();
    if name.is_empty() {
        return Err(AppError::Other("device name cannot be empty".to_string()));
    }
    Ok(name.to_string())
}

/// 啟動時狀態檔讀不到(`save_blocked`)就拒絕會寫狀態或 keychain 的動作(同 v1);v1 升級還沒完成時也拒絕
/// (keychain 裡的同步碼還要拿來升級)。
pub fn saves_allowed(env: &SyncEnv) -> Result<(), AppError> {
    let core = env.runtime.core.lock().unwrap();
    if let Some(reason) = core.save_blocked.clone() {
        return Err(AppError::Other(reason));
    }
    if core.legacy.is_some() {
        return Err(AppError::Other(crate::sync::runtime::UPGRADING_MESSAGE.to_string()));
    }
    Ok(())
}

fn relay_configured(url: &str) -> Result<(), AppError> {
    if url.trim().is_empty() {
        Err(AppError::Other(NO_RELAY_MESSAGE.to_string()))
    } else {
        Ok(())
    }
}

/// 建立 / 加入之前 doc 必須已載入:沒有 `~/.ssh/config` 時引擎每輪都安靜跳過,加入看起來成功卻永遠不會同步。
fn config_loaded(env: &SyncEnv) -> Result<(), AppError> {
    if env.doc.lock().unwrap().is_some() {
        Ok(())
    } else {
        Err(AppError::Other(NO_CONFIG_MESSAGE.to_string()))
    }
}

/// 會改動帳戶結構的動作(space 的建立 / 改名 / 刪除 / 勾選、核准)之前的共同檢查:已加入、有帳戶金鑰、沒有被更換
/// 同步碼(spec §7.5)、沒有正在更換、帳戶格式看得懂。
pub fn account_ready(s: &SyncStateV2, keys: Option<&ChainKeys>) -> Result<(), AppError> {
    if !s.joined() {
        return Err(AppError::Other(NOT_JOINED_MESSAGE.to_string()));
    }
    if keys.is_none() {
        return Err(AppError::Other(NO_KEYS_MESSAGE.to_string()));
    }
    if s.frozen().is_some() {
        return Err(AppError::Other(FROZEN_MESSAGE.to_string()));
    }
    if s.rotation.is_some() {
        return Err(AppError::Other(ROTATING_MESSAGE.to_string()));
    }
    if s.read_only() {
        return Err(AppError::Other(READ_ONLY_MESSAGE.to_string()));
    }
    Ok(())
}

/// 啟動時從 keychain 讀同步碼 → 帳戶金鑰(失敗分成讀不到、沒有、推導不出、屬於別的帳戶四種)。失敗時回傳要放進 `last_error` 的
/// 說明;推導失敗一律用固定訊息(錯誤文字可能帶到同步碼裡的字)。推導出的 chain id 必須是狀態裡的帳戶 chain。
pub fn account_keys_from_keychain(read: Result<Option<String>, AppError>, chain_id: &str) -> Result<ChainKeys, String> {
    match read {
        Ok(Some(words)) => {
            let keys = crypto::derive_account(&words)
                .map_err(|_| "the stored sync code could not be used; leave and join again".to_string())?;
            if keys.chain_id != chain_id {
                return Err(OTHER_ACCOUNT_MESSAGE.to_string());
            }
            Ok(keys)
        }
        Ok(None) => Err("the sync code is missing from the keychain; leave and join again".to_string()),
        Err(e) => Err(format!("could not read the sync code from the keychain ({e}); unlock the keychain and restart SSHelter")),
    }
}

/// 暫存的新同步碼(更換同步碼的第 1 步、其他電腦重新加入時存在 `sync:mnemonic-next`)裡,推導得出 `chain_id` 這個帳戶的那一組:狀態
/// 已經換成新帳戶、keychain 的同步碼還沒換過去的時候,它才是這個帳戶現在的碼。沒有暫存的、或它屬於別的帳戶 → `Ok(None)`;keychain
/// 讀不到(上鎖)→ `Err`:不知道有沒有。
pub(crate) fn staged_code_for(keychain: &dyn Keychain, chain_id: &str) -> Result<Option<(String, ChainKeys)>, AppError> {
    let Some(words) = keychain.get(NEXT_MNEMONIC_ACCOUNT)? else { return Ok(None) };
    Ok(crypto::derive_account(&words).ok().filter(|keys| keys.chain_id == chain_id).map(|keys| (words, keys)))
}

/// 這台勾選的 space id(排序),寫進裝置記錄。
pub fn selected_ids(s: &SyncStateV2) -> Vec<String> {
    s.spaces.iter().filter(|(_, sp)| sp.selected).map(|(id, _)| id.clone()).collect()
}

/// 在帳戶區段寫一個新 space 的 `space` 與 `spacekey` 記錄(spec §7.2)。
pub fn put_new_space(
    account: &mut AccountState,
    account_keys: &ChainKeys,
    space: &ChainKeys,
    payload: &SpacePayload,
    device_id: &str,
    now_ms: u64,
) -> Result<(), AppError> {
    put_account_record(
        account,
        RecordKind::Space,
        &space.chain_id,
        serde_json::to_value(payload).expect("SpacePayload serializes"),
        false,
        device_id,
        now_ms,
    );
    put_space_key(account, account_keys, &space.chain_id, Some(space), device_id, now_ms)
}

/// 新 space 的 payload:slug 由名稱產生。
pub fn space_payload(name: &str, created_at_ms: u64, previous_id: Option<String>) -> SpacePayload {
    SpacePayload { schema: SCHEMA_VERSION, name: name.to_string(), slug: slugify(name), created_at_ms, previous_id }
}

/// 加入帳戶前,把狀態的帳戶部分換成 `account`(生命週期變更:換 generation、計數歸零)。呼叫端持有 doc 鎖。建立帳戶與加入帳戶都經過這裡。
///
/// 這台的插槽記錄(離開時留下的連結與副本,`~/.ssh/sshelter-local/` 的主機還用著)留著,但在另一個帳戶裡選了同步的金鑰,不算同意上傳到這個帳戶
/// (SP3 N1):學到的帳戶(`LocalSlot::learned_in`)不是這個帳戶的記錄(不知道的也算),`uploaded_fingerprint` 清掉,要上傳就在這個帳戶再選一次;
/// 它們在帳戶裡沒有時也不補寫進來(`slots::republish`)。用同一個同步碼重新加入學到它們的那個帳戶,成員還是同一批:同意照舊,照常補寫。建立的
/// 帳戶一定是另一個帳戶。更換同步碼不走這裡(`rotation::install_new_account`)。
fn install_account(env: &SyncEnv, account: AccountState, keys: ChainKeys, device_name: String, spaces: Vec<(String, SpaceState)>) -> Result<(), AppError> {
    let now = env.now();
    let mut core = env.runtime.core.lock().unwrap();
    core.generation += 1;
    core.conflict_streak = 0;
    core.failed_rounds = 0;
    core.batch_failures = 0;
    let s = core.state.as_mut().ok_or_else(|| AppError::Other("sync is not initialized".to_string()))?;
    for local in s.key_slots.values_mut().filter(|l| l.learned_in.as_deref() != Some(account.chain_id.as_str())) {
        local.uploaded_fingerprint = None;
    }
    s.device_name = device_name;
    s.account = Some(account);
    s.spaces = spaces.into_iter().collect();
    s.rotation = None;
    s.phrase_cleanup_pending = false;
    s.last_sync_ms = None;
    s.last_error = None;
    let ids = selected_ids(s);
    let (device_id, name) = (s.device_id.clone(), s.device_name.clone());
    plan_device(s.account.as_mut().expect("just set"), &device_id, &name, env.platform, &ids, now);
    core.account_keys = Some(keys);
    save_core(&mut core, &env.state_path)
}

/// 建立帳戶(spec §7.3,第一台、非 v1 升級):產生同步碼 → 推導帳戶 chain 並 `PUT` → 預設 space「Personal」(隨機,
/// 不是 space0)也 `PUT` → 存同步碼進 keychain → 寫入帳戶 `meta`、`device`、`space`、`spacekey` 並勾選 Personal(先建
/// 檔、再加進 Include)。回傳同步碼,交給使用者保存。帳戶狀態與同步碼存下之後就不再失敗:準備檔案失敗只記到
/// stderr,下一輪會再做一次。在任何網路操作之前,離開 v1 同步留下、仍列在 Include 上的 `hosts.config` 先改成本機檔案並留下
/// `left_account` 提示(`keep_leftover_v1_file`);做不到就回它的錯誤(「could not keep … (left by the previous sync) as a local
/// file (…); nothing was changed — try again」),什麼都還沒建立。
pub fn create_account(env: &SyncEnv, device_name: &str) -> Result<String, AppError> {
    let device_name = clean_device_name(device_name)?;
    saves_allowed(env)?;
    config_loaded(env)?;
    let s = snapshot(env).ok_or_else(|| AppError::Other("sync is not initialized".to_string()))?;
    if s.joined() {
        return Err(AppError::Other("already in a sync account; leave it first".to_string()));
    }
    relay_configured(&s.relay_url)?;
    // 在任何網路操作之前:做不到就什麼都還沒建立。
    keep_leftover_v1_file(env)?;
    let words = crypto::generate_mnemonic()?;
    let account_keys = crypto::derive_account(&words)?;
    let personal = ChainKeys::generate()?;
    let relay = env.relay(&s.relay_url)?;
    relay.create_chain(&account_keys.chain_id, &account_keys.auth_token)?;
    relay.create_chain(&personal.chain_id, &personal.auth_token)?;
    env.keychain.set(MNEMONIC_ACCOUNT, &words)?;
    let now = env.now();
    let mut account = AccountState::new(&account_keys.chain_id);
    account.baseline_established = true;
    put_account_record(
        &mut account,
        RecordKind::Meta,
        ACCOUNT_META_ID,
        serde_json::to_value(MetaPayload::account(env!("CARGO_PKG_VERSION"))).expect("MetaPayload serializes"),
        false,
        &s.device_id,
        now,
    );
    let payload = space_payload(DEFAULT_SPACE_NAME, now, None);
    put_new_space(&mut account, &account_keys, &personal, &payload, &s.device_id, now)?;
    let file_name = space_file_name(&payload.slug, &personal.chain_id)?;
    let mut space = SpaceState::new(&file_name);
    space.baseline_established = true; // 新的空 chain:沒有基線可言
    {
        let mut doc_lock = env.doc.lock().unwrap();
        install_account(env, account, account_keys, device_name, vec![(personal.chain_id.clone(), space)])?;
        if let Err(e) = add_selected_file(env, &mut doc_lock, &file_name) {
            eprintln!("[sync] could not prepare the new space file ({e}); the next sync round retries");
        }
    }
    env.events.applied(0);
    env.events.wake();
    Ok(words)
}

/// 勾選的 space 檔:先建好檔案、再更新 Include 清單(spec §4.3),然後重載 doc。呼叫端持有 doc 鎖、不持有 core 鎖。
pub fn add_selected_file(env: &SyncEnv, doc_lock: &mut Option<SshConfigDoc>, file_name: &str) -> Result<(), AppError> {
    let Some(doc) = doc_lock.as_mut() else { return Ok(()) };
    let tokens = {
        let core = env.runtime.core.lock().unwrap();
        let s = core.state.as_ref().ok_or_else(|| AppError::Other("sync is not initialized".to_string()))?;
        crate::sync::merge::selected_include_tokens(s.account.as_ref(), &s.spaces)?
    };
    let mut backed_up = env.backed_up.lock().unwrap();
    let retention = env.retention();
    space_files::add_space_file(&env.ssh_dir, file_name, None, || write_include(doc, &mut backed_up, retention, &tokens))?;
    drop(backed_up);
    let main = doc.files[0].path.clone();
    *doc_lock = Some(env.load_doc(&main)?);
    Ok(())
}

/// 加入帳戶(spec §7.3,新電腦):推導帳戶 chain → 從 seq 0 拉取驗證存在(`404` → 找不到帳戶,絕不建立;若是 v1
/// 的同步碼另外說明)→ 帶著 `rotation:*` 標記就拒絕(這組同步碼已被更換)→ 存同步碼進 keychain → 寫入帳戶狀態與
/// `device` 記錄。還沒有勾選任何 space:使用者接著勾選(`spaces::select_space`),每個勾選的 space 以基線輪開始。同步碼確定
/// 可以加入之後、keychain 之前,離開 v1 同步留下、仍列在 Include 上的 `hosts.config` 先改成本機檔案(同 `create_account`,錯誤
/// 也相同,什麼都還沒加入);打錯的同步碼不會搬走任何東西。
pub fn join_account(env: &SyncEnv, words: &str, device_name: &str) -> Result<(), AppError> {
    let words = crypto::normalize_mnemonic(words)?;
    let device_name = clean_device_name(device_name)?;
    saves_allowed(env)?;
    config_loaded(env)?;
    let s = snapshot(env).ok_or_else(|| AppError::Other("sync is not initialized".to_string()))?;
    if s.joined() {
        return Err(AppError::Other("already in a sync account; leave it first".to_string()));
    }
    relay_configured(&s.relay_url)?;
    let account_keys = crypto::derive_account(&words)?;
    let relay = env.relay(&s.relay_url)?;
    let pulled = match relay.pull(&account_keys.chain_id, &account_keys.auth_token, 0) {
        Ok(p) => p,
        Err(RelayError::NotFound) => {
            // v1 的 chain 還在:這組同步碼的電腦都還沒升級(spec §7.6)。
            let v1 = crypto::derive_keys(&words)?;
            let message = match relay.pull(&v1.chain_id, &v1.auth_token, 0) {
                Ok(_) => OLD_FORMAT_MESSAGE,
                Err(_) => NO_ACCOUNT_MESSAGE,
            };
            return Err(AppError::NotFound(message.to_string()));
        }
        Err(e) => return Err(e.into()),
    };
    let AccountMerged { mut section, markers, .. } = merge_account(&AccountState::new(&account_keys.chain_id), &account_keys, &pulled);
    if let Some(marker) = markers.first() {
        return Err(AppError::Other(format!(
            "this sync code was changed on {}; enter the new sync code",
            marker.by_device_name
        )));
    }
    // 同步碼確定可以加入之後才動檔案(打錯的同步碼不會搬走任何東西),keychain 與狀態之前。
    keep_leftover_v1_file(env)?;
    env.keychain.set(MNEMONIC_ACCOUNT, &words)?;
    section.baseline_established = true;
    {
        let _doc = env.doc.lock().unwrap();
        install_account(env, section, account_keys, device_name, Vec::new())?;
    }
    env.events.wake();
    Ok(())
}

/// 離開帳戶時把這台的檔案(勾選的 space 檔;放棄 v1 升級時是 v1 的 `hosts.config`)改成一般的本機檔案(spec §7.3
/// 「本機 space 檔案與 Include 保留,ssh 照常可用;它們之後就是一般的本機檔案」):搬到 `~/.ssh/sshelter-local/`,主
/// config 裡我們的 token 原地換成新路徑 —— 一般的 Include,優先順序不變,之後建立或加入別的帳戶時 `ensure_include` 也
/// 不碰它們,搬移精靈看得到這些檔案。然後重載 doc。呼叫端持有 doc 鎖、不持有 core 鎖。失敗時什麼都沒變:新路徑已移除
/// (`space_files::keep_files_local`),doc 從磁碟重載(不會比磁碟新)。更換同步碼時新帳戶沒有接續的 space 也走這條路(`rotation::install_new_account`)。
pub(crate) fn keep_files_local(env: &SyncEnv, doc_lock: &mut Option<SshConfigDoc>, files: &[PathBuf]) -> Result<Vec<KeptFile>, AppError> {
    let main = match doc_lock.as_ref() {
        Some(doc) => doc.files[0].path.clone(),
        None => env.ssh_dir.join("config"),
    };
    if doc_lock.is_none() {
        *doc_lock = Some(env.load_doc(&main)?);
    }
    let doc = doc_lock.as_mut().expect("loaded above");
    let mut backed_up = env.backed_up.lock().unwrap();
    let retention = env.retention();
    let result = space_files::keep_files_local(&env.ssh_dir, files, |kept| {
        let moved: Vec<(String, String)> = kept.iter().map(|k| (k.old_token.clone(), k.token.clone())).collect();
        if release_include(&mut doc.files[0].items, &moved, |token| our_file_exists(&env.ssh_dir, token)) {
            persist_file(doc, 0, &mut backed_up, retention)?;
        }
        Ok(())
    });
    drop(backed_up);
    *doc_lock = env.load_doc(&main).ok();
    result
}

/// 主 config 裡我們的 Include(生效中的 top-level `Include`,`~/.ssh/sshelter/` 這一層的 `.config`,明確列出或手寫的 glob)現在讀得到的一般檔案,
/// 依 Include 的順序、不重複。「我們的」token 本來就只有 `~/.ssh/sshelter/` 那一層(`hosts_file::is_our_include_token`:帶路徑分隔字元的 —— 子目錄、`../` —— 是
/// 使用者自己的 Include,不碰:搬出去之後新舊 token 對不上,清單也不歸我們改)。放棄 v1 升級(`abandoned_files`)與升級本身(使用者自己放在那裡的檔案,
/// `upgrade::upgrade_v1`)共用這個列舉。
pub(crate) fn listed_our_files(ssh_dir: &Path, items: &[Item]) -> Vec<PathBuf> {
    let mut files: Vec<PathBuf> = Vec::new();
    let dir = space_files::spaces_dir(ssh_dir);
    for item in items {
        let Item::Directive(d) = item else { continue };
        if d.key != "include" || d.serializes_as_comment() {
            continue;
        }
        for token in d.value.split_whitespace().filter(|t| hosts_file::is_our_include_token(t)) {
            let Some(rest) = token.strip_prefix(space_files::INCLUDE_DIR) else { continue };
            let found: Vec<PathBuf> = if hosts_file::is_glob_token(rest) {
                // 同 OpenSSH 的 glob(`our_file_exists`):`*` 不跨 `/`、不對到 `.` 開頭的名稱。目錄那一段照字面比對。
                let pattern = format!("{}/{rest}", glob::Pattern::escape(&dir.to_string_lossy()));
                let options = glob::MatchOptions { case_sensitive: true, require_literal_separator: true, require_literal_leading_dot: true };
                glob::glob_with(&pattern, options).map(|paths| paths.filter_map(Result::ok).collect()).unwrap_or_default()
            } else {
                vec![dir.join(rest)]
            };
            for path in found {
                if path.is_file() && !files.contains(&path) {
                    files.push(path);
                }
            }
        }
    }
    files
}

/// 放棄 v1 升級時要改成本機檔案的檔案:主 config 裡我們的 Include 現在讀得到的每個檔案(`listed_our_files`)—— 升級還沒動手時是 v1 的 `hosts.config`;
/// 做到一半時(space0 檔已經取代 `hosts.config` 列在清單上),主機就在那些檔案裡:只搬 `hosts.config` 的話,它們留在「我們的」token 底下,之後建立或加入帳戶
/// 第一次寫清單就把它們收走,主機從 ssh 消失。`hosts.config` 排第一個,而且**只有主 config 讀得到它才算**:沒有任何 Include 列著它的(升級換好清單之後移除
/// 不掉的舊檔),內容是舊的、ssh 不讀,不是主機的家(`stale_v1_file`)。
fn abandoned_files(ssh_dir: &Path, items: &[Item]) -> Vec<PathBuf> {
    let v1 = hosts_file::managed_path(ssh_dir);
    let listed = listed_our_files(ssh_dir, items);
    let mut files: Vec<PathBuf> = listed.iter().filter(|p| **p == v1).cloned().collect();
    files.extend(listed.into_iter().filter(|p| *p != v1));
    files
}

/// 放棄 v1 升級時 v1 的 `hosts.config` 還在、主 config 卻沒有任何 Include 讀它(升級換好清單之後移除不掉,狀態還是 v1 時離開):它的主機早已在列著的檔案裡
/// (使用者在那裡做的修改都比它新),留下的是過時的內容 —— 不改成本機檔案(也就不列進 `LeftAccount`:ssh 讀不到它,說它是留下的主機是誤導,之後搬移精靈匯入它還會
/// 把舊的、已刪的主機帶回來),備份後移除(`drop_stale_file`)。沒有這個檔案、或主 config 讀得到它 → None。
fn stale_v1_file(ssh_dir: &Path, items: &[Item]) -> Option<PathBuf> {
    let path = hosts_file::managed_path(ssh_dir);
    (path.is_file() && !hosts_file::lists_include(items, &hosts_file::managed_token())).then_some(path)
}

/// 備份之後移除一個 ssh 不讀、也沒有人需要的舊檔(`stale_v1_file`)。備份不了就留著不動(同升級:沒有備份絕不移除);移除失敗只留下一個沒有 Include 讀它的檔案,
/// 不影響離開 —— 兩種都只記到 stderr。
fn drop_stale_file(path: &Path) {
    if let Err(e) = crate::sync::upgrade::back_up_first(path) {
        eprintln!("[sync] a stale v1 file was left in place: {e}");
        return;
    }
    if let Err(e) = std::fs::remove_file(path).or_else(|e| if e.kind() == std::io::ErrorKind::NotFound { Ok(()) } else { Err(e) }) {
        eprintln!("[sync] a stale v1 file was backed up but could not be removed: {e}");
    }
}

/// 主 config 裡我們的一個 Include token(`~/.ssh/sshelter/<名稱>`)指的檔案還在不在(`release_include`)。判斷不了就當成還在:
/// 寧可留著一行指向不存在檔案的 Include(OpenSSH 略過它),也不讓還在的檔案從清單上消失。glob(使用者手寫的
/// `~/.ssh/sshelter/*.config`)只要目錄裡有任何一個檔案對得上就算還在。
fn our_file_exists(ssh_dir: &Path, token: &str) -> bool {
    let Some(rest) = token.strip_prefix(space_files::INCLUDE_DIR) else { return true };
    let dir = space_files::spaces_dir(ssh_dir);
    if !hosts_file::is_glob_token(rest) {
        return dir.join(rest).try_exists().unwrap_or(true);
    }
    // 同 OpenSSH 的 glob:`*` 不跨 `/`、不對到 `.` 開頭的名稱。目錄那一段照字面比對。
    let pattern = format!("{}/{rest}", glob::Pattern::escape(&dir.to_string_lossy()));
    let options = glob::MatchOptions { case_sensitive: true, require_literal_separator: true, require_literal_leading_dot: true };
    match glob::glob_with(&pattern, options) {
        Ok(paths) => paths.filter_map(Result::ok).any(|p| p.is_file()),
        Err(_) => true,
    }
}

/// 離開 v1 同步之後留下來的 `~/.ssh/sshelter/hosts.config`(v1 的離開保留這個檔案和它的 Include,ssh 照常讀它):v2 的
/// `ensure_include` 把它當成「我們的」token,建立或加入帳戶之後第一次寫 Include 清單就把它拿掉 —— 這台的主機就從 ssh 消失了。
/// 所以裝上帳戶之前,照放棄 v1 升級的做法把它改成一般的本機檔案(`keep_files_local`:搬到 `~/.ssh/sshelter-local/`、Include
/// 原地換成新路徑)並留下 `SyncNotice::LeftAccount`(存進狀態;事件在放掉所有鎖之後)。只有主 config 裡生效中的 Include 真的讀到
/// 它(明確列出,或我們目錄的 glob 涵蓋它:`hosts_file::lists_include`,`release_include` 會改寫的那幾種)才這樣做:沒列著的話
/// ssh 本來就不讀它,v2 也不碰它 —— 留在原地、什麼都不提示。檔案不在也一樣什麼都不做。做不到就什麼都不改、回錯誤
/// 「could not keep <路徑> (left by the previous sync) as a local file (…); nothing was changed — try again」(doc 已從磁碟
/// 重載、`applied(0)`)。v1 升級還沒做完時走不到這裡(`saves_allowed` 先拒絕):那時檔案歸升級處理。
fn keep_leftover_v1_file(env: &SyncEnv) -> Result<(), AppError> {
    let path = hosts_file::managed_path(&env.ssh_dir);
    if !path.try_exists()? {
        return Ok(());
    }
    let token = hosts_file::managed_token();
    let kept = {
        let mut doc_lock = env.doc.lock().unwrap();
        if doc_lock.is_none() {
            *doc_lock = Some(env.load_doc(&env.ssh_dir.join("config"))?);
        }
        if !doc_lock.as_ref().is_some_and(|doc| hosts_file::lists_include(&doc.files[0].items, &token)) {
            return Ok(());
        }
        match keep_files_local(env, &mut doc_lock, std::slice::from_ref(&path)) {
            Ok(kept) => kept,
            Err(e) => {
                drop(doc_lock);
                env.events.applied(0);
                return Err(AppError::Other(format!(
                    "could not keep {} (left by the previous sync) as a local file ({e}); nothing was changed — try again",
                    path.display()
                )));
            }
        }
    };
    if kept.is_empty() {
        return Ok(());
    }
    let notice = SyncNotice::LeftAccount { kept_files: kept.iter().map(|k| k.path.to_string_lossy().into_owned()).collect() };
    {
        let mut core = env.runtime.core.lock().unwrap();
        if let Some(s) = core.state.as_mut() {
            s.notices.push(notice.clone());
        }
        // 檔案已經搬了:狀態存不了也不中止(`unsaved` 讓之後的存檔補上),提示照樣發出。
        let _ = save_core(&mut core, &env.state_path);
    }
    env.events.notice(&notice);
    env.events.applied(0);
    Ok(())
}

/// `keep_files_local` 失敗、什麼都沒改(離開時沒有要求刪除帳戶):說明原因,請使用者再離開一次。
fn kept_error(e: AppError) -> AppError {
    AppError::Other(format!(
        "could not keep this device's synced files as local files ({e}); nothing was changed — try leaving again"
    ))
}

/// 同 `kept_error`,但這次離開在檔案動作之前已經取消了更換同步碼(第 3 步之前離開 = 取消,`decide_rotation`):不能說「什麼都沒改」,要說更換已經取消。
fn kept_error_after_cancel(e: AppError) -> AppError {
    AppError::Other(format!(
        "could not keep this device's synced files as local files ({e}); the sync code change in progress was cancelled, nothing else was changed — try leaving again"
    ))
}

/// 同上,但這次離開要求了刪除帳戶、relay 那一半已經做完:不能說「什麼都沒改」。狀態仍是已加入,再離開一次時 relay 上已經沒有的
/// chain 會略過,只剩檔案這一半要重做。
fn remote_deleted_error(e: AppError) -> AppError {
    AppError::Other(format!(
        "the sync account was deleted from the relay, but this computer's files could not be kept as local files ({e}); try leaving again"
    ))
}

/// 排隊等著刪 chain 的 space(`account.chain_deletes`:tombstone 之前那份 `spacekey` 的密文)的位置與權杖。打不開或讀不懂(例如
/// 本身就是 tombstone)→ None:沒有權杖就刪不掉。權杖只在記憶體。
fn queued_chain_keys(sealed: &SealedRecord, keys: &ChainKeys) -> Option<ChainKeys> {
    let record = sealed.open(keys).ok()?;
    serde_json::from_value::<SpaceKeyPayload>(record.payload).ok()?.to_keys(&record.id).ok()
}

/// 離開對「正在更換同步碼」的判定(`decide_rotation`)。
enum RotationVerdict {
    /// 沒有更換同步碼(或這個行程不能動狀態:後面的檢查會拒絕)。
    None,
    /// 還在第 3 步之前(沒寫標記、沒凍結任何東西):離開 = 取消。進度已經在做出判定的那個 core 臨界區清掉、generation 已換(同 `rotation::cancel_rotation`)。
    Cancelled,
    /// 已經凍結,可是暫存的新同步碼再也找不回來:這次更換再也做不完,放行 —— 進度隨帳戶一起清掉。
    Abandoned,
    /// 已經凍結、還做得完:拒絕。
    Refused,
}

/// 離開在 doc 鎖之內、**任何檔案或 relay 的動作之前**判定更換同步碼(呼叫端持有 doc 鎖與 core 鎖)。背景執行緒從不拿 lifecycle 鎖,它推進這個更換靠的是 core 鎖:
/// `begin_freezing` 在 core 鎖內把「等著凍結」存成「凍結中」(`rotation::update_rotation`)才開始寫標記。所以這個判定要在 core 鎖內做完:
/// 取消的話進度已經不在,背景執行緒那一步在 core 鎖內找不到進度、什麼都不做(沒有標記、沒有凍結);它若先一步,這裡就看到已經不能取消了。用鎖外的快照判定、
/// 之後才清除,中間背景執行緒凍結了舊帳戶,清除就把唯一的新同步碼刪了 —— 每一台都在等沒有人持有的碼。
///
/// 取消階段(第 3 步之前)新 chain 還沒建立(第 5 步才建),relay 上沒有要清的 —— 同 `cancel_rotation`。存檔失敗不中止:狀態留在記憶體(`unsaved`),
/// 離開接下來的存檔會再寫一次。
fn decide_rotation(core: &mut SyncCore, state_path: &Path, new_code_gone: bool) -> RotationVerdict {
    let Some(cancellable) = core.state.as_ref().and_then(|s| s.rotation.as_ref()).map(|r| r.cancellable()) else {
        return RotationVerdict::None;
    };
    if !cancellable {
        return if new_code_gone { RotationVerdict::Abandoned } else { RotationVerdict::Refused };
    }
    if let Some(s) = core.state.as_mut() {
        s.rotation = None;
    }
    core.generation += 1;
    let _ = save_core(core, state_path);
    RotationVerdict::Cancelled
}

// 測試的插入點(只在測試建置,而且只對目前這個執行緒):`leave_account` 一進來、拿任何鎖之前執行一件事(例如這時背景的升級剛好做完);
// `AFTER_ROTATION_DECISION` 在離開判定完更換同步碼之後、動任何檔案或 relay 之前執行一件事(例如這時背景執行緒的下一輪剛好開始)。
#[cfg(test)]
thread_local! {
    pub(crate) static BEFORE_LEAVE: std::cell::RefCell<Option<Box<dyn FnOnce()>>> = std::cell::RefCell::new(None);
    pub(crate) static AFTER_ROTATION_DECISION: std::cell::RefCell<Option<Box<dyn FnOnce()>>> = std::cell::RefCell::new(None);
}

/// 離開帳戶(spec §7.3,這台)。這台的 space 檔先改成一般的本機檔案(`keep_files_local`;做不到就什麼都不改、回錯誤),
/// 同一段 doc 鎖內作廢在途輪次並清掉狀態的帳戶部分(確保停止同步、沒有輪次再碰這些檔案),再刪 keychain 的同步碼;刪不掉
/// 就持久化 `phrase_cleanup_pending`、回報錯誤(重試入口同 v1:未加入時再呼叫一次只做 keychain 清理)。檔案搬過的話留下
/// `SyncNotice::LeftAccount`(新的路徑)。`delete_remote`(這台是裝置清單上的最後一台時,spec §7.3「刪除帳戶」):先
/// `DELETE` 每個 space chain、排在 `chain_deletes` 還沒刪的 chain(刪掉的 space,同步輪次還沒來得及刪)與帳戶 chain(已經不在
/// 的略過),做不到就在改動任何東西之前回錯誤。relay 那一半做完、檔案搬不過去時,錯誤說明帳戶已經從 relay 刪了(狀態仍是已加入,
/// 再離開一次只重做檔案這一半)。v1 升級一直做不完時,離開 = 放棄升級:v1 的 `hosts.config`,加上主 config 的 Include 現在列著的、我們的檔案
/// (升級做到一半時,主機已經在 space0 檔裡,`abandoned_files`)一樣改成本機檔案;要不要放棄,在拿到 doc 鎖之後才讀 `legacy` 決定(背景的升級也要拿 doc 鎖才能完成,
/// 所以決定到做完之間它不會換掉狀態),放棄的與一般離開搬的檔案都記進 `LeftAccount`;放棄時一併清掉升級留下的錯誤說明。
/// 更換同步碼(spec §7.5)在同一個鎖內、動任何檔案或 relay 之前判定(`decide_rotation`):第 3 步之前(還沒寫標記、沒凍結任何東西)離開 = 取消,進度當場清掉,背景
/// 的凍結不會插進來;第 3 步起其他電腦已被擋下、只能做完,拒絕離開(`LEAVE_ROTATING_MESSAGE`)—— 除非暫存的新同步碼已經不見或屬於別的帳戶(這次更換再也做不完):那時
/// 放行,relay 上什麼都不刪(標記要留給其他電腦),最後回錯誤(`leave_abandoned_message`)說明出路:舊帳戶已凍結、誰都不能再加入它,其中一台建立新的同步帳戶,其他電腦離開舊帳戶後加入新的。
/// 同步碼已在別台換掉(`frozen`,spec §7.5)時不刪帳戶:舊帳戶 chain 上的更換標記是還沒換的電腦得知這件事的唯一來源 —— 只在這台
/// 離開,最後回錯誤說明帳戶沒有從 relay 刪除。
pub fn leave_account(env: &SyncEnv, delete_remote: bool) -> Result<(), AppError> {
    #[cfg(test)]
    if let Some(hook) = BEFORE_LEAVE.with(|h| h.borrow_mut().take()) {
        hook();
    }
    // 暫存的新同步碼還找不找得回來:keychain 的讀取可能跳出系統的授權視窗,所以在拿鎖之前讀。更換同步碼只能由持有 lifecycle 鎖的命令開始、離開也全程持有它,
    // 所以這裡看不到更換,拿了鎖之後也不會冒出來;只有背景執行緒會推進或讓出一個已經存在的更換。
    let new_code_gone = match snapshot(env).and_then(|s| s.rotation) {
        Some(rotation) => matches!(read_new_code(env.keychain, &rotation), NewCode::Gone),
        None => false,
    };
    let mut kept: Vec<KeptFile> = Vec::new();
    let (mut cancelled_change, mut abandoned_change) = (false, false);
    {
        // 先拿 doc 鎖、再讀 `legacy` 決定要不要放棄升級(順序 lifecycle → doc → core):升級要拿 doc 鎖才能做完檔案階段與換狀態,所以在這個鎖內
        // 讀到的 `legacy` 到放棄做完之間不會變。不能用拿鎖之前的快照決定 —— 升級可能剛好在這之間做完,放棄就變成去搬一個已加入狀態的檔案。
        // 更換同步碼同一個道理:判定與取消在同一個 core 臨界區(`decide_rotation`),在任何檔案或 relay 的動作之前。
        let mut doc_lock = env.doc.lock().unwrap();
        let (abandon, verdict) = {
            let mut core = env.runtime.core.lock().unwrap();
            let abandon = core.save_blocked.is_none() && core.legacy.is_some();
            let verdict = if core.save_blocked.is_none() && core.legacy.is_none() {
                decide_rotation(&mut core, &env.state_path, new_code_gone)
            } else {
                RotationVerdict::None
            };
            (abandon, verdict)
        };
        match verdict {
            RotationVerdict::Refused => return Err(AppError::Other(LEAVE_ROTATING_MESSAGE.to_string())),
            RotationVerdict::Cancelled => cancelled_change = true,
            RotationVerdict::Abandoned => abandoned_change = true,
            RotationVerdict::None => {}
        }
        if abandon {
            // v1 升級一直做不完(例如 keychain 裡沒有同步碼):離開 = 放棄升級,換成未加入的 v2 狀態。
            // 要搬的檔案從主 config 現在的 Include 讀(升級做到一半時主機已經在別的檔案裡):doc 還沒載入就先載入(同 `keep_files_local`)。
            if doc_lock.is_none() {
                match env.load_doc(&env.ssh_dir.join("config")) {
                    Ok(doc) => *doc_lock = Some(doc),
                    Err(e) => {
                        drop(doc_lock);
                        env.events.applied(0);
                        return Err(kept_error(e));
                    }
                }
            }
            let (files, stale) = {
                let items = &doc_lock.as_ref().expect("loaded above").files[0].items;
                (abandoned_files(&env.ssh_dir, items), stale_v1_file(&env.ssh_dir, items))
            };
            match keep_files_local(env, &mut doc_lock, &files) {
                Ok(moved) => kept.extend(moved),
                Err(e) => {
                    drop(doc_lock);
                    env.events.applied(0);
                    return Err(kept_error(e));
                }
            }
            // 搬檔案成功(失敗時什麼都沒變)之後才處理過時的 `hosts.config`:它不在清單上,移除不影響 ssh 讀得到的主機。
            if let Some(stale) = stale {
                drop_stale_file(&stale);
            }
            let mut core = env.runtime.core.lock().unwrap();
            if core.legacy.take().is_some() {
                core.generation += 1;
                // 升級卡住時留下的錯誤說明(「could not upgrade … leave and join again」)與退避的計數:離開之後的狀態不該帶著它們。
                core.failed_rounds = 0;
                if let Some(s) = core.state.as_mut() {
                    s.last_error = None;
                }
                // 檔案已經搬了:狀態存不了也不中止(同下面的主路徑,`unsaved` 讓下一輪補寫)—— 下面照樣留下通知、發事件,最後的存檔
                // 會再試一次並回報。
                let _ = save_core(&mut core, &env.state_path);
            }
        }
    }
    #[cfg(test)]
    if let Some(hook) = AFTER_ROTATION_DECISION.with(|h| h.borrow_mut().take()) {
        hook();
    }
    if cancelled_change {
        // 取消的更換暫存的新同步碼不再有用(同 `cancel_rotation`);離開之後面失敗,也不留著它。
        let _ = env.keychain.delete(NEXT_MNEMONIC_ACCOUNT);
    }
    saves_allowed(env)?;
    let (s, keys) = {
        let core = env.runtime.core.lock().unwrap();
        (core.state.clone().ok_or_else(|| AppError::Other("sync is not initialized".to_string()))?, core.account_keys.clone())
    };
    // 同步碼已在別台換掉:刪掉舊帳戶 chain 會連它上面的更換標記一起刪掉(凍結的 chain 被 DELETE 之後仍是凍結的,記錄卻清空了),
    // 還在用舊同步碼的電腦就再也看不到是誰、為什麼換了 —— 所以只在這台離開。
    let frozen_now = || env.runtime.core.lock().unwrap().state.as_ref().is_some_and(|s| s.frozen().is_some());
    let mut replaced = delete_remote && s.frozen().is_some();
    if let Some(account) = s.account.as_ref() {
        // 卡住的更換(`abandoned_change`)也不刪 relay:舊帳戶上這台寫的更換標記,是還沒換的電腦得知「同步碼換過了」的唯一來源。
        if delete_remote && !replaced && !abandoned_change {
            let keys = keys.ok_or_else(|| {
                AppError::Other(
                    "cannot delete the account from the relay: the sync code is not available on this device; leave without deleting"
                        .to_string(),
                )
            })?;
            let relay = env.relay(&s.relay_url)?;
            let mut chains: Vec<ChainKeys> =
                space_entries(account).iter().filter(|e| !e.deleted).filter_map(|e| space_keys(account, &keys, &e.id)).collect();
            // 這台(或別台)刪掉的 space:chain 的 DELETE 還排在 `chain_deletes`、同步輪次沒來得及做。狀態一清掉就沒有權杖了,
            // 這裡不刪就永遠留在 relay 上。
            chains.extend(account.chain_deletes.iter().filter_map(|sealed| queued_chain_keys(sealed, &keys)));
            chains.push(keys.clone());
            for chain in &chains {
                // 每刪一條之前都再看一次:刪的期間,同步輪次可能剛拉到更換標記、記下 `frozen` —— 之後的都不刪(標記在最後才刪的
                // 帳戶 chain 上;舊的 space chain 也許還要讓更換的那一台複製)。
                if frozen_now() {
                    replaced = true;
                    break;
                }
                match relay.delete_chain(&chain.chain_id, &chain.auth_token) {
                    Ok(()) | Err(RelayError::NotFound) => {}
                    Err(e) => return Err(e.into()),
                }
            }
        }
        let mut doc_lock = env.doc.lock().unwrap();
        // 要搬的檔名在 doc 鎖內、從現在的狀態讀(同 `spaces::unselect_space`):改名(同步輪次的帳戶那一步)也在這把鎖內做。上面
        // 鎖外的快照可能是改名之前的 —— 搬的會是已經不在的舊檔名,改名之後的檔案就從 Include 上消失了(ssh 不再讀它的主機)。
        let files = {
            let core = env.runtime.core.lock().unwrap();
            match core.state.as_ref() {
                Some(state) => state
                    .spaces
                    .values()
                    .filter(|sp| sp.selected)
                    .map(|sp| space_files::space_file_path(&env.ssh_dir, &sp.file_name))
                    .collect::<Result<Vec<_>, _>>()?,
                None => Vec::new(),
            }
        };
        if !files.is_empty() {
            match keep_files_local(env, &mut doc_lock, &files) {
                Ok(moved) => kept.extend(moved),
                Err(e) => {
                    drop(doc_lock);
                    env.events.applied(0);
                    // 要求了刪除帳戶(而且真的刪了)時,走到這裡 relay 那一半已經做完了。
                    return Err(if delete_remote && !replaced && !abandoned_change {
                        remote_deleted_error(e)
                    } else if cancelled_change {
                        kept_error_after_cancel(e)
                    } else {
                        kept_error(e)
                    });
                }
            }
        }
        let mut core = env.runtime.core.lock().unwrap();
        core.generation += 1;
        core.account_keys = None;
        core.conflict_streak = 0;
        core.failed_rounds = 0;
        core.batch_failures = 0;
        if let Some(s) = core.state.as_mut() {
            s.account = None;
            s.spaces.clear();
            s.rotation = None;
            s.last_sync_ms = None;
            s.last_error = None;
        }
        // 寫檔失敗也不中止:沒有同步碼就推導不出金鑰,重啟也不會恢復同步;`unsaved` 讓下一輪補寫。
        let _ = save_core(&mut core, &env.state_path);
    }
    let notice = (!kept.is_empty()).then(|| SyncNotice::LeftAccount {
        kept_files: kept.iter().map(|k| k.path.to_string_lossy().into_owned()).collect(),
    });
    let _ = env.keychain.delete(NEXT_MNEMONIC_ACCOUNT);
    let cleared = env.keychain.delete(MNEMONIC_ACCOUNT);
    let saved = {
        let mut core = env.runtime.core.lock().unwrap();
        if let Some(s) = core.state.as_mut() {
            s.phrase_cleanup_pending = cleared.is_err();
            s.notices.extend(notice.clone());
        }
        save_core(&mut core, &env.state_path)
    };
    if let Some(notice) = &notice {
        env.events.notice(notice);
        env.events.applied(0);
    }
    env.events.wake();
    if let Err(e) = cleared {
        return Err(AppError::Other(format!(
            "left the sync account, but the sync code could not be removed from the keychain ({e}); use \"Remove sync code\" to retry"
        )));
    }
    if let Err(e) = saved {
        return Err(AppError::Other(format!(
            "left the sync account, but the sync state could not be saved ({e}); it will be retried automatically"
        )));
    }
    if replaced {
        return Err(AppError::Other(LEAVE_REPLACED_MESSAGE.to_string()));
    }
    if abandoned_change {
        return Err(AppError::Other(leave_abandoned_message(delete_remote)));
    }
    Ok(())
}

/// relay URL 只能在未加入時更改(spec §7.3:cursor 與 seq 屬於某一個 relay)。改了就要重查 `GET /v1/info`。
pub fn set_relay_url(env: &SyncEnv, url: &str) -> Result<(), AppError> {
    let normalized = RelayClient::validate_url(url)?;
    mutate(env, |s| {
        if s.joined() {
            return Err(AppError::Other(
                "leave the sync account before switching relays, then create or join on the new relay".to_string(),
            ));
        }
        s.relay_url = normalized;
        s.relay_features = None;
        s.last_error = None;
        Ok(())
    })?;
    env.runtime.core.lock().unwrap().relay_checked = None;
    env.events.wake();
    Ok(())
}

/// `GET /v1/info`(spec §6.4):結果與查的 URL 存進 `relay_features`。網路在鎖外。
pub fn check_relay(env: &SyncEnv) -> Result<RelayFeatures, AppError> {
    let url = snapshot(env).map(|s| s.relay_url).unwrap_or_default();
    relay_configured(&url)?;
    let info = env.relay(&url)?.info()?;
    Ok(record_relay_info(env, &url, &info))
}

/// 記下 `url` 的 `GET /v1/info` 結果(`check_relay`;同步輪次用它自己的連線查,才分得出 `429`)。查的期間 URL 被換掉(只可能
/// 在未加入時):結果屬於舊 URL,不存。
pub fn record_relay_info(env: &SyncEnv, url: &str, info: &RelayInfo) -> RelayFeatures {
    let features = RelayFeatures::from_info(url, info, env.now());
    let mut core = env.runtime.core.lock().unwrap();
    if core.state.as_ref().is_some_and(|s| s.relay_url == url) {
        core.relay_checked = Some(url.to_string());
        if let Some(s) = core.state.as_mut() {
            s.relay_features = Some(features.clone());
        }
        if core.save_blocked.is_none() {
            let _ = save_core(&mut core, &env.state_path);
        }
    }
    features
}

pub fn set_device_name(env: &SyncEnv, name: &str) -> Result<(), AppError> {
    let name = clean_device_name(name)?;
    let now = env.now();
    let platform = env.platform;
    mutate(env, |s| {
        s.device_name = name;
        let ids = selected_ids(s);
        let (device_id, device_name) = (s.device_id.clone(), s.device_name.clone());
        if let Some(account) = s.account.as_mut() {
            plan_device(account, &device_id, &device_name, platform, &ids, now);
        }
        Ok(())
    })?;
    env.events.wake();
    Ok(())
}

/// 只把裝置從清單移除(tombstone 它的 `device` 記錄)。**不是撤權**:它若還有同步碼就會繼續同步;要撤銷遺失的電腦
/// 請更換同步碼(spec §7.5)。
pub fn forget_device(env: &SyncEnv, device_id: &str) -> Result<(), AppError> {
    let now = env.now();
    mutate(env, |s| {
        if device_id == s.device_id {
            return Err(AppError::Other("use Leave to remove this device".to_string()));
        }
        let me = s.device_id.clone();
        let account = s.account.as_mut().ok_or_else(|| AppError::Other(NOT_JOINED_MESSAGE.to_string()))?;
        let key = crate::sync::record::record_key(RecordKind::Device, device_id);
        let Some(local) = account.records.get(&key).filter(|l| !l.record.deleted).cloned() else {
            return Err(AppError::NotFound(format!("device {device_id} is not in this sync account")));
        };
        put_account_record(account, RecordKind::Device, device_id, local.record.payload, true, &me, now);
        Ok(())
    })?;
    env.events.wake();
    Ok(())
}

/// Sync pane 的「Show sync code」(spec §3)。keychain 讀取:呼叫端在 `spawn_blocking` 裡。更換同步碼(或重新加入)已經把狀態換成新帳戶、
/// keychain 的同步碼卻還沒換過去時(`rotation::SWAP_PENDING_MESSAGE`),暫存的新碼才是現在這個帳戶的碼 —— 顯示它,使用者保存的才是對的那一組。
pub fn show_words(env: &SyncEnv) -> Result<String, AppError> {
    let chain = snapshot(env)
        .and_then(|s| s.account.map(|a| a.chain_id))
        .ok_or_else(|| AppError::Other(NOT_JOINED_MESSAGE.to_string()))?;
    if let Ok(Some((words, _))) = staged_code_for(env.keychain, &chain) {
        return Ok(words);
    }
    env.keychain.get(MNEMONIC_ACCOUNT)?.ok_or_else(|| AppError::Other("the sync code is not in the keychain".to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sync::fake_relay::FakeRelay;
    use crate::sync::merge::{account_outgoing, apply_pushed_account, devices, push_outgoing};
    use crate::sync::record::{rotation_meta_id, DevicePayload, RotationMarkerPayload};
    use crate::sync::env::Keychain;
    use crate::sync::relay::RelayApi;
    use crate::sync::state_v2::{RotationProgress, RotationStep};
    use crate::sync::testkit::{TestClock, TestDevice};

    const WORDS: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art";

    /// 不經過同步輪次,把這台帳戶區段的 dirty 記錄推上 relay(讓另一台加入時拉得到)。
    pub(crate) fn upload_account(d: &TestDevice) {
        let mut core = d.runtime.core.lock().unwrap();
        let keys = core.account_keys.clone().unwrap();
        let account = core.state.as_mut().unwrap().account.as_mut().unwrap();
        let outgoing = account_outgoing(account, &keys).unwrap();
        let pushed = push_outgoing(d.relay.as_ref(), &keys.chain_id, &keys.auth_token, &outgoing);
        assert!(pushed.error.is_none() && !pushed.frozen, "{:?}", pushed.error);
        apply_pushed_account(account, &outgoing, &pushed);
    }

    #[test]
    fn creating_an_account_makes_a_selected_personal_space_and_keeps_the_code() {
        let (relay, clock) = (FakeRelay::new(), TestClock::new());
        let a = TestDevice::new("a", &relay, &clock);
        let words = create_account(&a.env(), " MacBook-A ").unwrap();
        assert_eq!(words.split(' ').count(), 24);
        assert_eq!(a.keychain.entry(MNEMONIC_ACCOUNT).as_deref(), Some(words.as_str()));
        let s = a.state();
        assert_eq!(s.device_name, "MacBook-A");
        let account = s.account.as_ref().unwrap();
        assert_eq!(account.chain_id, crypto::derive_account(&words).unwrap().chain_id);
        assert!(relay.exists(&account.chain_id));
        let entries = space_entries(account);
        assert_eq!(entries.iter().map(|e| e.name.as_str()).collect::<Vec<_>>(), vec!["Personal"]);
        let personal = &entries[0].id;
        assert!(relay.exists(personal), "the Personal space chain exists");
        assert_ne!(personal, &crypto::derive_space0(&words).unwrap().chain_id, "Personal is random, not space0");
        assert!(account.records.contains_key("meta:account"));
        let device: DevicePayload = serde_json::from_value(account.records[&format!("device:{}", s.device_id)].record.payload.clone()).unwrap();
        assert_eq!(device.spaces, vec![personal.clone()]);
        let space = &s.spaces[personal];
        assert!(space.selected && space.baseline_established);
        assert!(a.space_path(personal).is_file());
        assert!(a.main_config().contains(&format!("Include ~/.ssh/sshelter/{}", space.file_name)));
        assert!(create_account(&a.env(), "A").is_err(), "already in an account");
    }

    #[test]
    fn create_and_join_need_a_name_a_relay_and_a_loaded_config() {
        let (relay, clock) = (FakeRelay::new(), TestClock::new());
        let a = TestDevice::new("a", &relay, &clock);
        assert_eq!(create_account(&a.env(), "  ").unwrap_err().to_string(), "device name cannot be empty");
        a.runtime.core.lock().unwrap().state.as_mut().unwrap().relay_url = String::new();
        assert_eq!(create_account(&a.env(), "A").unwrap_err().to_string(), NO_RELAY_MESSAGE);
        assert_eq!(join_account(&a.env(), WORDS, "A").unwrap_err().to_string(), NO_RELAY_MESSAGE);
        *a.doc.lock().unwrap() = None;
        assert_eq!(create_account(&a.env(), "A").unwrap_err().to_string(), NO_CONFIG_MESSAGE);
        assert!(a.keychain.entry(MNEMONIC_ACCOUNT).is_none(), "nothing reached the keychain");
    }

    #[test]
    fn joining_needs_an_existing_account_and_refuses_a_changed_code() {
        let (relay, clock) = (FakeRelay::new(), TestClock::new());
        let a = TestDevice::new("a", &relay, &clock);
        let b = TestDevice::new("b", &relay, &clock);
        // 沒有帳戶:不建立。
        let err = join_account(&b.env(), WORDS, "B").unwrap_err();
        assert!(matches!(&err, AppError::NotFound(m) if m == NO_ACCOUNT_MESSAGE), "{err}");
        assert!(!relay.exists(&crypto::derive_account(WORDS).unwrap().chain_id));
        // 只有 v1 的 chain:說明要先升級。
        let v1 = crypto::derive_keys(WORDS).unwrap();
        relay.create_chain(&v1.chain_id, &v1.auth_token).unwrap();
        assert_eq!(join_account(&b.env(), WORDS, "B").unwrap_err().to_string(), format!("not found: {OLD_FORMAT_MESSAGE}"));
        // 正常加入:帳戶的 space 都看得到,還沒有勾選。
        let words = create_account(&a.env(), "A").unwrap();
        upload_account(&a);
        join_account(&b.env(), &words.to_uppercase(), "B").unwrap();
        let s = b.state();
        assert!(s.spaces.is_empty());
        let account = s.account.as_ref().unwrap();
        assert_eq!(space_entries(account)[0].name, "Personal");
        assert!(account.records[&format!("device:{}", s.device_id)].dirty);
        assert_eq!(devices(account).len(), 2);
        assert_eq!(b.keychain.entry(MNEMONIC_ACCOUNT).as_deref(), Some(words.as_str()));
        // 帳戶帶著更換標記:這組同步碼已被更換,不加入。
        let c = TestDevice::new("c", &relay, &clock);
        {
            let mut core = a.runtime.core.lock().unwrap();
            let me = core.state.as_ref().unwrap().device_id.clone();
            let account = core.state.as_mut().unwrap().account.as_mut().unwrap();
            let marker = RotationMarkerPayload { rotated_at_ms: 1, by_device_id: me.clone(), by_device_name: "MacBook-A".into() };
            put_account_record(account, RecordKind::Meta, &rotation_meta_id(&me), serde_json::to_value(marker).unwrap(), false, &me, 5);
        }
        upload_account(&a);
        assert_eq!(
            join_account(&c.env(), &words, "C").unwrap_err().to_string(),
            "this sync code was changed on MacBook-A; enter the new sync code"
        );
        assert!(c.keychain.entry(MNEMONIC_ACCOUNT).is_none());
    }

    /// 主 config 與它 Include 的檔案裡,定義 `alias` 的那個檔案(ssh 會用的那一份)。
    fn host_file(d: &TestDevice, alias: &str) -> Option<std::path::PathBuf> {
        let doc = d.doc.lock().unwrap();
        let doc = doc.as_ref().unwrap();
        crate::config::include::find_host_file_index(doc, alias).map(|i| doc.files[i].path.clone())
    }

    #[test]
    fn leaving_keeps_the_space_files_as_local_files_that_ssh_still_reads() {
        let (relay, clock) = (FakeRelay::new(), TestClock::new());
        let a = TestDevice::with_main_config("a", &relay, &clock, "# main\nHost local\n");
        create_account(&a.env(), "A").unwrap();
        let personal = a.state().spaces.keys().next().unwrap().clone();
        let file = a.space_path(&personal);
        let file_name = file.file_name().unwrap().to_string_lossy().into_owned();
        a.save_in_app(&file, "Host web\n  HostName 10.0.0.1\n");
        leave_account(&a.env(), false).unwrap();
        let s = a.state();
        assert!(!s.joined() && s.spaces.is_empty() && !s.phrase_cleanup_pending);
        assert!(a.keychain.entry(MNEMONIC_ACCOUNT).is_none());
        assert!(a.runtime.core.lock().unwrap().account_keys.is_none());
        // 檔案搬到 ~/.ssh/sshelter-local/,主 config 原地改成一般的 Include(優先順序不變)。
        let kept = space_files::local_dir(&a.ssh_dir()).join(&file_name);
        assert!(!file.exists());
        assert_eq!(a.read(&kept), "Host web\n  HostName 10.0.0.1\n");
        assert_eq!(a.main_config(), format!("# main\nInclude ~/.ssh/sshelter-local/{file_name}\nHost local\n"));
        assert_eq!(s.notices, vec![SyncNotice::LeftAccount { kept_files: vec![kept.to_string_lossy().into_owned()] }]);
        assert_eq!(a.events.notices.lock().unwrap().last(), s.notices.last());
        assert_eq!(host_file(&a, "web"), Some(kept.clone()), "ssh and the app still read the host");
        // 換 relay 的流程(spec §7.3):離開 → 建立新帳戶。新帳戶的 Include 放在最頂端,舊檔案的 Include 原封不動。
        create_account(&a.env(), "A").unwrap();
        let new_name = a.state().spaces.values().next().unwrap().file_name.clone();
        assert_ne!(new_name, file_name);
        assert_eq!(
            a.main_config(),
            format!("# main\nInclude ~/.ssh/sshelter/{new_name}\nInclude ~/.ssh/sshelter-local/{file_name}\nHost local\n")
        );
        assert_eq!(host_file(&a, "web"), Some(kept));
    }

    #[test]
    fn leaving_never_reports_a_main_config_write_that_landed_as_failed() {
        use crate::config::commands::FAIL_FINGERPRINT_REREAD;
        let (relay, clock) = (FakeRelay::new(), TestClock::new());
        let a = TestDevice::with_main_config("a", &relay, &clock, "# main\nHost local\n");
        create_account(&a.env(), "A").unwrap();
        let personal = a.state().spaces.keys().next().unwrap().clone();
        let file = a.space_path(&personal);
        let file_name = file.file_name().unwrap().to_string_lossy().into_owned();
        a.save_in_app(&file, "Host web\n  HostName 10.0.0.1\n");
        // 離開寫主 config 的時候:寫入落地了,重讀指紋卻失敗 —— 以前存檔回 Err,`keep_files_local` 以為沒寫成而移除新路徑,磁碟上的主 config 卻已經列著它們,
        // 舊路徑又不在清單上:主機從 ssh 消失。
        FAIL_FINGERPRINT_REREAD.with(|f| f.set(true));
        leave_account(&a.env(), false).unwrap();
        assert!(!FAIL_FINGERPRINT_REREAD.with(|f| f.get()), "the injected failure was used");
        let kept = space_files::local_dir(&a.ssh_dir()).join(&file_name);
        assert_eq!(a.read(&kept), "Host web\n  HostName 10.0.0.1\n");
        assert!(a.main_config().contains(&format!("Include ~/.ssh/sshelter-local/{file_name}")), "{}", a.main_config());
        assert_eq!(host_file(&a, "web"), Some(kept.clone()), "ssh and the app still read the host");
        assert!(!a.state().joined());
    }

    #[test]
    fn a_failed_move_changes_nothing_and_leaving_can_be_retried() {
        let (relay, clock) = (FakeRelay::new(), TestClock::new());
        let a = TestDevice::new("a", &relay, &clock);
        create_account(&a.env(), "A").unwrap();
        crate::sync::spaces::create_space(&a.env(), "Work").unwrap();
        let files: Vec<std::path::PathBuf> = a.state().spaces.keys().map(|id| a.space_path(id)).collect();
        assert_eq!(files.len(), 2);
        // 主 config 在 app 以外被改過(doc 過時):寫回 Include 時 `persist_file` 拒絕 —— 已經建立的本機檔案全部移除。
        let edited = format!("{}# edited elsewhere\n", a.main_config());
        a.write_externally(&a.main_path(), &edited);
        let err = leave_account(&a.env(), false).unwrap_err();
        assert!(err.to_string().starts_with("could not keep this device's synced files as local files"), "{err}");
        assert!(a.state().joined());
        assert!(a.keychain.entry(MNEMONIC_ACCOUNT).is_some());
        assert!(files.iter().all(|f| f.is_file()), "the space files stay where they were");
        assert_eq!(std::fs::read_dir(space_files::local_dir(&a.ssh_dir())).unwrap().count(), 0);
        assert_eq!(a.main_config(), edited);
        // doc 已從磁碟重載:再離開一次就成功。
        leave_account(&a.env(), false).unwrap();
        assert!(!a.state().joined());
        assert!(files.iter().all(|f| !f.exists()));
        assert_eq!(std::fs::read_dir(space_files::local_dir(&a.ssh_dir())).unwrap().count(), 2);
        assert!(a.main_config().ends_with("# edited elsewhere\n"));
    }

    #[test]
    fn abandoning_the_upgrade_keeps_the_v1_hosts_as_a_local_file() {
        let (relay, clock) = (FakeRelay::new(), TestClock::new());
        let a = TestDevice::with_main_config("a", &relay, &clock, "Include ~/.ssh/sshelter/hosts.config\nHost local\n");
        let v1_file = hosts_file::managed_path(&a.ssh_dir());
        std::fs::create_dir_all(v1_file.parent().unwrap()).unwrap();
        std::fs::write(&v1_file, "Host web\n").unwrap();
        a.reload();
        let mut v1 = crate::sync::state::SyncState::fresh("A").unwrap();
        v1.chain_id = Some("ab".repeat(32));
        a.runtime.core.lock().unwrap().legacy = Some(v1);
        leave_account(&a.env(), false).unwrap();
        assert!(a.runtime.core.lock().unwrap().legacy.is_none(), "the upgrade is abandoned");
        let kept = space_files::local_dir(&a.ssh_dir()).join("hosts.config");
        assert!(!v1_file.exists());
        assert_eq!(a.read(&kept), "Host web\n");
        assert_eq!(a.main_config(), "Include ~/.ssh/sshelter-local/hosts.config\nHost local\n");
        assert_eq!(a.state().notices, vec![SyncNotice::LeftAccount { kept_files: vec![kept.to_string_lossy().into_owned()] }]);
        // 之後建立帳戶:v1 的主機照樣讀得到。
        create_account(&a.env(), "A").unwrap();
        assert!(a.main_config().contains("Include ~/.ssh/sshelter-local/hosts.config"));
        assert_eq!(host_file(&a, "web"), Some(kept));
    }

    /// 一台等著升級的 v1 裝置:主 config 是 `main`,`~/.ssh/sshelter/` 裡放著 `files`。
    fn waiting_v1_device(main: &str, files: &[(&str, &str)]) -> TestDevice {
        let (relay, clock) = (FakeRelay::new(), TestClock::new());
        let a = TestDevice::with_main_config("a", &relay, &clock, main);
        let dir = space_files::spaces_dir(&a.ssh_dir());
        std::fs::create_dir_all(&dir).unwrap();
        for (name, text) in files {
            std::fs::write(dir.join(name), text).unwrap();
        }
        a.reload();
        let mut v1 = crate::sync::state::SyncState::fresh("A").unwrap();
        v1.chain_id = Some("ab".repeat(32));
        a.runtime.core.lock().unwrap().legacy = Some(v1);
        a
    }

    #[test]
    fn abandoning_the_upgrade_keeps_every_file_our_include_lists() {
        // 升級做到一半:space0 檔已經取代 `hosts.config` 列在清單上(`hosts.config` 已移除),清單上另有使用者自己的 Include。
        let main = "Include ~/.ssh/sshelter/synced-aaaaaaaa.config ~/.ssh/other.config\nHost local\n";
        let a = waiting_v1_device(main, &[("synced-aaaaaaaa.config", "Host web\n"), ("unlisted-bbbbbbbb.config", "Host unlisted\n")]);
        leave_account(&a.env(), false).unwrap();
        assert!(a.runtime.core.lock().unwrap().legacy.is_none(), "the upgrade is abandoned");
        let dir = space_files::spaces_dir(&a.ssh_dir());
        let kept = space_files::local_dir(&a.ssh_dir()).join("synced-aaaaaaaa.config");
        assert_eq!(a.read(&kept), "Host web\n");
        assert!(!dir.join("synced-aaaaaaaa.config").exists());
        assert_eq!(a.read(&dir.join("unlisted-bbbbbbbb.config")), "Host unlisted\n", "a file the list does not name stays where it is");
        assert_eq!(a.main_config(), "Include ~/.ssh/sshelter-local/synced-aaaaaaaa.config ~/.ssh/other.config\nHost local\n");
        assert_eq!(a.state().notices, vec![SyncNotice::LeftAccount { kept_files: vec![kept.to_string_lossy().into_owned()] }]);
        // 之後建立帳戶:主機照樣讀得到(它們不再是「我們的」token)。
        create_account(&a.env(), "A").unwrap();
        assert!(a.main_config().contains("Include ~/.ssh/sshelter-local/synced-aaaaaaaa.config"));
        assert_eq!(host_file(&a, "web"), Some(kept));
    }

    #[test]
    fn abandoning_the_upgrade_keeps_the_files_a_handwritten_glob_covers() {
        let main = "Include ~/.ssh/sshelter/*.config\nHost local\n";
        let a = waiting_v1_device(main, &[("a-aaaaaaaa.config", "Host a\n"), ("b-bbbbbbbb.config", "Host b\n"), ("notes.txt", "not a config\n")]);
        leave_account(&a.env(), false).unwrap();
        let local = space_files::local_dir(&a.ssh_dir());
        assert_eq!((a.read(&local.join("a-aaaaaaaa.config")), a.read(&local.join("b-bbbbbbbb.config"))), ("Host a\n".to_string(), "Host b\n".to_string()));
        // 新路徑列在 glob 前面;glob 留在那裡(`release_include` 判斷時舊檔還在,B3a 的順序:新路徑、改清單、最後才移除舊路徑),現在它什麼都對不到。
        assert_eq!(
            a.main_config(),
            "Include ~/.ssh/sshelter-local/a-aaaaaaaa.config ~/.ssh/sshelter-local/b-bbbbbbbb.config ~/.ssh/sshelter/*.config\nHost local\n"
        );
        assert_eq!(a.read(&space_files::spaces_dir(&a.ssh_dir()).join("notes.txt")), "not a config\n");
        assert_eq!(host_file(&a, "a"), Some(local.join("a-aaaaaaaa.config")));
        assert_eq!(host_file(&a, "b"), Some(local.join("b-bbbbbbbb.config")));
    }

    #[test]
    fn abandoning_the_upgrade_keeps_the_users_own_listed_file_next_to_hosts_config() {
        // v1 只有 `hosts.config` 那個 token 是我們的:使用者自己列在 `~/.ssh/sshelter/` 的檔案(和別的 Include 在同一行)也讀得到。放棄升級把
        // `hosts.config` 與它一起改成本機檔案;沒列在清單上的檔案不碰。之後建立帳戶,它們照樣讀得到。
        let main = "# main\nInclude ~/.ssh/sshelter/hosts.config\nInclude ~/.ssh/sshelter/mine.config ~/.ssh/other.config\nHost local\n";
        let a = waiting_v1_device(main, &[("hosts.config", "Host web\n"), ("mine.config", "Host minehost\n"), ("unlisted.config", "Host unlisted\n")]);
        leave_account(&a.env(), false).unwrap();
        let (dir, local) = (space_files::spaces_dir(&a.ssh_dir()), space_files::local_dir(&a.ssh_dir()));
        assert_eq!((a.read(&local.join("hosts.config")), a.read(&local.join("mine.config"))), ("Host web\n".to_string(), "Host minehost\n".to_string()));
        assert_eq!(a.read(&dir.join("unlisted.config")), "Host unlisted\n", "a file the list does not name stays where it is");
        assert_eq!(
            a.main_config(),
            "# main\nInclude ~/.ssh/sshelter-local/hosts.config\nInclude ~/.ssh/sshelter-local/mine.config ~/.ssh/other.config\nHost local\n"
        );
        let kept_files = vec![local.join("hosts.config").to_string_lossy().into_owned(), local.join("mine.config").to_string_lossy().into_owned()];
        assert_eq!(a.state().notices, vec![SyncNotice::LeftAccount { kept_files }]);
        create_account(&a.env(), "A").unwrap();
        assert_eq!(host_file(&a, "web"), Some(local.join("hosts.config")));
        assert_eq!(host_file(&a, "minehost"), Some(local.join("mine.config")));
    }

    #[test]
    fn abandoning_the_upgrade_does_not_move_a_file_an_include_reaches_outside_our_directory() {
        let main = "Include ~/.ssh/sshelter/../outside.config\nHost local\n";
        let a = waiting_v1_device(main, &[]);
        let outside = a.ssh_dir().join("outside.config");
        std::fs::write(&outside, "Host elsewhere\n").unwrap();
        leave_account(&a.env(), false).unwrap();
        assert_eq!(a.read(&outside), "Host elsewhere\n", "the file stays where the user put it");
        assert_eq!(a.main_config(), main);
        assert!(a.state().notices.is_empty(), "nothing was kept");
        // 探針 S2:之後建立帳戶,第一次寫清單也不會把它收走 —— 它不是我們的 token(spec §4.3,`..` 之後是使用者自己的路徑),主機照樣讀得到。
        assert!(host_file(&a, "elsewhere").is_some());
        create_account(&a.env(), "A").unwrap();
        assert!(a.main_config().contains("Include ~/.ssh/sshelter/../outside.config\n"), "{}", a.main_config());
        assert!(host_file(&a, "elsewhere").is_some(), "ssh still reads the host");
    }

    #[test]
    fn the_files_the_abandon_branch_and_the_regular_branch_move_are_all_in_the_notice() {
        // 兩段都搬了檔案(`legacy` 還在、狀態卻已經是已加入 —— 只有測試做得出來):放棄升級搬 Include 列著的檔案,一般離開搬這台勾選的 space 檔
        // (沒列在清單上的那個)。`LeftAccount` 要列出全部,後面一段不能把前面一段搬的蓋掉。
        let (relay, clock) = (FakeRelay::new(), TestClock::new());
        let a = TestDevice::with_main_config("a", &relay, &clock, "# main\nHost local\n");
        create_account(&a.env(), "A").unwrap();
        let personal = a.space_path(a.state().spaces.keys().next().unwrap());
        let extra = space_files::spaces_dir(&a.ssh_dir()).join("extra-aaaaaaaa.config");
        std::fs::write(&extra, "Host extra\n").unwrap();
        a.save_in_app(&a.main_path(), "# main\nInclude ~/.ssh/sshelter/extra-aaaaaaaa.config\nHost local\n");
        let mut v1 = crate::sync::state::SyncState::fresh("A").unwrap();
        v1.chain_id = Some("ab".repeat(32));
        a.runtime.core.lock().unwrap().legacy = Some(v1);
        let local = space_files::local_dir(&a.ssh_dir());
        let moved = |p: &Path| local.join(p.file_name().unwrap()).to_string_lossy().into_owned();
        let expected = vec![moved(&extra), moved(&personal)];
        leave_account(&a.env(), false).unwrap();
        assert_eq!(a.state().notices, vec![SyncNotice::LeftAccount { kept_files: expected }]);
    }

    #[test]
    fn a_failed_keychain_cleanup_is_remembered_and_retried() {
        let (relay, clock) = (FakeRelay::new(), TestClock::new());
        let a = TestDevice::new("a", &relay, &clock);
        create_account(&a.env(), "A").unwrap();
        a.keychain.fail_deletes.store(true, std::sync::atomic::Ordering::SeqCst);
        let err = leave_account(&a.env(), false).unwrap_err();
        assert!(err.to_string().starts_with("left the sync account, but the sync code could not be removed"), "{err}");
        assert!(a.state().phrase_cleanup_pending);
        assert!(!a.state().joined(), "the account part is gone even so");
        a.keychain.fail_deletes.store(false, std::sync::atomic::Ordering::SeqCst);
        leave_account(&a.env(), false).unwrap();
        assert!(!a.state().phrase_cleanup_pending);
        assert!(a.keychain.entry(MNEMONIC_ACCOUNT).is_none());
    }

    #[test]
    fn deleting_the_account_deletes_every_chain_first() {
        let (relay, clock) = (FakeRelay::new(), TestClock::new());
        let a = TestDevice::new("a", &relay, &clock);
        create_account(&a.env(), "A").unwrap();
        let s = a.state();
        let account_chain = s.account.as_ref().unwrap().chain_id.clone();
        let personal = s.spaces.keys().next().unwrap().clone();
        leave_account(&a.env(), true).unwrap();
        assert!(!relay.exists(&account_chain) && !relay.exists(&personal));
        // relay 連不上:什麼都不改。
        let b = TestDevice::new("b", &relay, &clock);
        create_account(&b.env(), "B").unwrap();
        relay.set_offline(true);
        assert!(leave_account(&b.env(), true).is_err());
        assert!(b.state().joined());
    }

    #[test]
    fn the_relay_url_can_only_change_while_not_joined_and_is_checked_again() {
        let (relay, clock) = (FakeRelay::new(), TestClock::new());
        let a = TestDevice::new("a", &relay, &clock);
        assert!(set_relay_url(&a.env(), "http://relay.example.com").is_err(), "plain http is refused");
        set_relay_url(&a.env(), "https://other.example.com/").unwrap();
        assert_eq!(a.state().relay_url, "https://other.example.com");
        let features = check_relay(&a.env()).unwrap();
        assert!(features.supports("freeze") && features.supports("pull-batch"));
        assert_eq!(a.state().relay_features.unwrap().url, "https://other.example.com");
        set_relay_url(&a.env(), crate::sync::testkit::RELAY_URL).unwrap();
        assert!(a.state().relay_features.is_none(), "a new URL is checked again");
        create_account(&a.env(), "A").unwrap();
        assert!(set_relay_url(&a.env(), "https://third.example.com").is_err());
    }

    #[test]
    fn renaming_and_forgetting_devices_write_account_records() {
        let (relay, clock) = (FakeRelay::new(), TestClock::new());
        let a = TestDevice::new("a", &relay, &clock);
        let b = TestDevice::new("b", &relay, &clock);
        let words = create_account(&a.env(), "A").unwrap();
        upload_account(&a);
        join_account(&b.env(), &words, "B").unwrap();
        upload_account(&b);
        set_device_name(&a.env(), "Work laptop").unwrap();
        let s = a.state();
        let me: DevicePayload = serde_json::from_value(s.account.as_ref().unwrap().records[&format!("device:{}", s.device_id)].record.payload.clone()).unwrap();
        assert_eq!(me.name, "Work laptop");
        assert!(forget_device(&a.env(), &s.device_id).is_err(), "this device leaves instead");
        // A 還沒拉到 B 的裝置記錄:不認得它。
        assert!(matches!(forget_device(&a.env(), &b.state().device_id), Err(AppError::NotFound(_))));
        let b_id = b.state().device_id;
        let pulled = relay.pull(&s.account.as_ref().unwrap().chain_id, &crypto::derive_account(&words).unwrap().auth_token, 0).unwrap();
        {
            let mut core = a.runtime.core.lock().unwrap();
            let keys = core.account_keys.clone().unwrap();
            let account = core.state.as_mut().unwrap().account.as_mut().unwrap();
            *account = merge_account(account, &keys, &pulled).section;
        }
        forget_device(&a.env(), &b_id).unwrap();
        assert!(a.state().account.as_ref().unwrap().records[&format!("device:{b_id}")].record.deleted);
        assert_eq!(show_words(&a.env()).unwrap(), words);
    }

    #[test]
    fn keychain_problems_at_startup_get_distinct_messages_and_never_echo_the_code() {
        let chain = crypto::derive_account(WORDS).unwrap().chain_id;
        assert!(account_keys_from_keychain(Ok(Some(WORDS.to_string())), &chain).is_ok());
        assert_eq!(
            account_keys_from_keychain(Ok(None), &chain).unwrap_err(),
            "the sync code is missing from the keychain; leave and join again"
        );
        let locked = account_keys_from_keychain(Err(AppError::Other("keychain error: locked".into())), &chain).unwrap_err();
        assert!(locked.ends_with("unlock the keychain and restart SSHelter"), "{locked}");
        let broken = account_keys_from_keychain(Ok(Some("zebra sunshine".into())), &chain).unwrap_err();
        assert!(!broken.contains("zebra"));
        assert_eq!(account_keys_from_keychain(Ok(Some(WORDS.to_string())), &"cd".repeat(32)).unwrap_err(), OTHER_ACCOUNT_MESSAGE);
    }

    #[test]
    fn deleting_the_account_also_deletes_the_chains_queued_by_deleted_spaces() {
        let (relay, clock) = (FakeRelay::new(), TestClock::new());
        let a = TestDevice::new("a", &relay, &clock);
        create_account(&a.env(), "A").unwrap();
        let s = a.state();
        let account_chain = s.account.as_ref().unwrap().chain_id.clone();
        let personal = s.spaces.keys().next().unwrap().clone();
        // 刪掉的 space:chain 的 DELETE 排在 `chain_deletes`,等同步輪次在 tombstone 上傳之後才執行。
        let work = crate::sync::spaces::create_space(&a.env(), "Work").unwrap();
        let home = crate::sync::spaces::create_space(&a.env(), "Home").unwrap();
        crate::sync::spaces::delete_space(&a.env(), &work).unwrap();
        crate::sync::spaces::delete_space(&a.env(), &home).unwrap();
        let keys = a.runtime.core.lock().unwrap().account_keys.clone().unwrap();
        let queued: Vec<ChainKeys> =
            a.state().account.as_ref().unwrap().chain_deletes.iter().filter_map(|sealed| queued_chain_keys(sealed, &keys)).collect();
        assert_eq!(queued.len(), 2, "both chain DELETEs are still queued");
        assert!(relay.exists(&work) && relay.exists(&home));
        // 其中一條已經不在 relay 上了(別台的輪次先刪的):算做完,不擋住其他的。
        relay.delete_chain(&queued[0].chain_id, &queued[0].auth_token).unwrap();
        leave_account(&a.env(), true).unwrap();
        for chain in [&account_chain, &personal, &work, &home] {
            assert!(!relay.exists(chain), "{chain} is still on the relay");
        }
        assert!(!a.state().joined());
    }

    #[test]
    fn a_failed_move_after_the_account_was_deleted_from_the_relay_says_so_and_can_be_retried() {
        let (relay, clock) = (FakeRelay::new(), TestClock::new());
        let a = TestDevice::new("a", &relay, &clock);
        create_account(&a.env(), "A").unwrap();
        let s = a.state();
        let account_chain = s.account.as_ref().unwrap().chain_id.clone();
        let personal = s.spaces.keys().next().unwrap().clone();
        let file = a.space_path(&personal);
        let edited = format!("{}# edited elsewhere\n", a.main_config());
        a.write_externally(&a.main_path(), &edited);
        let message = leave_account(&a.env(), true).unwrap_err().to_string();
        assert!(
            message.starts_with("the sync account was deleted from the relay, but this computer's files could not be kept as local files ("),
            "{message}"
        );
        assert!(message.ends_with("); try leaving again"), "{message}");
        assert!(!message.contains("nothing was changed"), "{message}");
        assert!(!relay.exists(&account_chain) && !relay.exists(&personal), "the relay side is gone");
        assert!(a.state().joined() && file.is_file(), "this computer is untouched");
        assert_eq!(a.main_config(), edited);
        // 重試:relay 上已經沒有的 chain 略過,檔案這次搬得過去。
        leave_account(&a.env(), true).unwrap();
        assert!(!a.state().joined() && !file.exists());
        assert_eq!(std::fs::read_dir(space_files::local_dir(&a.ssh_dir())).unwrap().count(), 1);
    }

    #[test]
    fn abandoning_the_upgrade_still_reports_the_kept_files_when_the_state_cannot_be_saved() {
        let (relay, clock) = (FakeRelay::new(), TestClock::new());
        let a = TestDevice::with_main_config("a", &relay, &clock, "Include ~/.ssh/sshelter/hosts.config\nHost local\n");
        let v1_file = hosts_file::managed_path(&a.ssh_dir());
        std::fs::create_dir_all(v1_file.parent().unwrap()).unwrap();
        std::fs::write(&v1_file, "Host web\n").unwrap();
        a.reload();
        let mut v1 = crate::sync::state::SyncState::fresh("A").unwrap();
        v1.chain_id = Some("ab".repeat(32));
        a.runtime.core.lock().unwrap().legacy = Some(v1);
        // 狀態檔所在的 `data` 被一個一般檔案擋住:檔案搬過去之後存不了。
        std::fs::write(a.home.path().join("data"), b"in the way").unwrap();
        let kept = space_files::local_dir(&a.ssh_dir()).join("hosts.config");
        let message = leave_account(&a.env(), false).unwrap_err().to_string();
        assert!(message.starts_with("left the sync account, but the sync state could not be saved"), "{message}");
        // 檔案已經搬了:通知與事件照樣留下,說明它們在哪裡。
        assert_eq!(a.read(&kept), "Host web\n");
        assert!(!v1_file.exists());
        let notice = SyncNotice::LeftAccount { kept_files: vec![kept.to_string_lossy().into_owned()] };
        assert_eq!(a.state().notices, vec![notice.clone()]);
        assert_eq!(*a.events.notices.lock().unwrap(), vec![notice]);
        assert!(a.events.applied.lock().unwrap().contains(&0), "the front end is told the config was reloaded");
        let core = a.runtime.core.lock().unwrap();
        assert!(core.legacy.is_none() && core.unsaved, "abandoned in memory; the next round saves it");
    }

    /// 暫存著新同步碼、進度停在 `step` 的更換(直接寫進狀態,不經過 relay)。新同步碼確實推導得出這次更換的新帳戶。
    fn stage_rotation(d: &TestDevice, step: RotationStep) -> String {
        let words = crypto::generate_mnemonic().unwrap();
        let mut rotation = RotationProgress::new(&crypto::derive_account(&words).unwrap().chain_id, 1);
        rotation.step = step;
        d.keychain.set(NEXT_MNEMONIC_ACCOUNT, &words).unwrap();
        d.runtime.core.lock().unwrap().state.as_mut().unwrap().rotation = Some(rotation);
        words
    }

    #[test]
    fn leaving_is_refused_while_a_sync_code_change_is_past_the_point_of_no_return() {
        let (relay, clock) = (FakeRelay::new(), TestClock::new());
        let a = TestDevice::new("a", &relay, &clock);
        create_account(&a.env(), "A").unwrap();
        let s = a.state();
        let account_chain = s.account.as_ref().unwrap().chain_id.clone();
        let file = a.space_path(s.spaces.keys().next().unwrap());
        // 第 3 步(寫標記與凍結)起不能取消:其他電腦已經被擋下,只能做完。
        stage_rotation(&a, RotationStep::Freezing);
        for step in [RotationStep::Freezing, RotationStep::Copying, RotationStep::Deleting, RotationStep::Switching] {
            a.runtime.core.lock().unwrap().state.as_mut().unwrap().rotation.as_mut().unwrap().step = step;
            for delete_remote in [false, true] {
                let err = leave_account(&a.env(), delete_remote).unwrap_err();
                assert_eq!(
                    err.to_string(),
                    "a sync code change is in progress; let it finish (it resumes on its own) before this computer leaves",
                    "{step:?}"
                );
            }
        }
        assert!(a.state().joined() && a.state().rotation.is_some());
        assert!(a.keychain.entry(MNEMONIC_ACCOUNT).is_some() && a.keychain.entry(NEXT_MNEMONIC_ACCOUNT).is_some());
        assert!(relay.exists(&account_chain), "nothing was deleted from the relay");
        assert!(file.is_file());
        // keychain 讀不到(上鎖)時不知道新同步碼還在不在:一樣拒絕,不當成「已經不見」。
        a.keychain.fail_reads.store(true, std::sync::atomic::Ordering::SeqCst);
        assert_eq!(leave_account(&a.env(), false).unwrap_err().to_string(), LEAVE_ROTATING_MESSAGE);
        a.keychain.fail_reads.store(false, std::sync::atomic::Ordering::SeqCst);
        // 還在第 3 步之前:離開就是放棄這次更換。
        a.runtime.core.lock().unwrap().state.as_mut().unwrap().rotation.as_mut().unwrap().step = RotationStep::LocalChangesSent;
        leave_account(&a.env(), false).unwrap();
        assert!(!a.state().joined() && a.state().rotation.is_none());
        assert!(a.keychain.entry(NEXT_MNEMONIC_ACCOUNT).is_none());
    }

    // ── 最終修正 FW1:離開在同一個鎖內判定更換同步碼,背景的凍結不會插在判定與清除之間 ──

    /// 離開判定完更換同步碼(`AFTER_ROTATION_DECISION`)的那一刻,背景執行緒的下一輪剛好開始。
    fn next_background_round_starts_after_the_decision(a: &std::sync::Arc<TestDevice>) {
        let worker = std::sync::Arc::clone(a);
        AFTER_ROTATION_DECISION.with(|h| {
            *h.borrow_mut() = Some(Box::new(move || {
                let _ = crate::sync::round::sync_once(&worker.env());
            }))
        });
    }

    /// 舊帳戶 chain 上的更換標記數。
    fn markers_on(relay: &FakeRelay, keys: &ChainKeys) -> usize {
        merge_account(&AccountState::new(&keys.chain_id), keys, &relay.pull(&keys.chain_id, &keys.auth_token, 0).unwrap()).markers.len()
    }

    #[test]
    fn a_leave_that_cancelled_the_change_and_then_cannot_keep_the_files_says_so_and_can_be_repeated() {
        let (relay, clock) = (FakeRelay::new(), TestClock::new());
        let a = TestDevice::new("a", &relay, &clock);
        create_account(&a.env(), "A").unwrap();
        let file = a.space_path(a.state().spaces.keys().next().unwrap());
        stage_rotation(&a, RotationStep::LocalChangesSent);
        // 主 config 在 app 以外被改過:搬檔案寫回 Include 時被擋下。離開在這之前已經取消了更換 —— 錯誤不能說「什麼都沒改」。
        let edited = format!("{}# edited elsewhere\n", a.main_config());
        a.write_externally(&a.main_path(), &edited);
        let err = leave_account(&a.env(), false).unwrap_err().to_string();
        assert!(err.starts_with("could not keep this device's synced files as local files ("), "{err}");
        assert!(err.ends_with("the sync code change in progress was cancelled, nothing else was changed — try leaving again"), "{err}");
        assert!(a.state().joined() && a.state().rotation.is_none(), "still joined; the change is cancelled");
        assert!(a.keychain.entry(NEXT_MNEMONIC_ACCOUNT).is_none(), "the staged code of the cancelled change is gone");
        assert!(file.is_file() && a.main_config() == edited);
        // doc 已從磁碟重載:再離開一次就成功,不再有更換可取消。
        leave_account(&a.env(), false).unwrap();
        assert!(!a.state().joined());
    }

    #[test]
    fn leaving_while_a_change_waits_to_freeze_cancels_it_before_the_freeze() {
        use crate::sync::rotation::start_rotation;
        use crate::sync::round::tests::{pair, settle};
        let (relay, _clock, a, b, _words, _personal) = pair();
        let a = std::sync::Arc::new(a);
        let keys = a.runtime.core.lock().unwrap().account_keys.clone().unwrap();
        start_rotation(&a.env()).unwrap();
        let _ = crate::sync::round::sync_once(&a.env()); // 第 2 步做完:等著寫標記與凍結(還能取消)
        assert_eq!(a.state().rotation.unwrap().step, RotationStep::LocalChangesSent);
        // 離開剛判定完、還沒清除進度時,背景執行緒的下一輪開始。以前這一輪寫標記、凍結舊帳戶,之後離開把新同步碼刪了 —— 每一台都在等沒有人持有的碼。
        next_background_round_starts_after_the_decision(&a);
        leave_account(&a.env(), false).unwrap();
        assert!(!relay.is_frozen(&keys.chain_id), "the old account was not frozen");
        assert_eq!(markers_on(&relay, &keys), 0, "no marker was written");
        assert!(!a.state().joined() && a.state().rotation.is_none());
        assert!(a.keychain.entry(NEXT_MNEMONIC_ACCOUNT).is_none() && a.keychain.entry(MNEMONIC_ACCOUNT).is_none());
        // 另一台沒有被擋下:不會被要求輸入沒有人持有的同步碼。
        settle(&b);
        assert!(b.state().frozen().is_none());
    }

    #[test]
    fn a_step_that_began_before_leave_decided_cannot_freeze_after_it() {
        use crate::sync::rotation::{drive_rotation, start_rotation};
        use crate::sync::round::tests::{pair, settle};
        let (relay, _clock, a, b, _words, _personal) = pair();
        let a = std::sync::Arc::new(a);
        let keys = a.runtime.core.lock().unwrap().account_keys.clone().unwrap();
        start_rotation(&a.env()).unwrap();
        let _ = crate::sync::round::sync_once(&a.env());
        assert_eq!(a.state().rotation.unwrap().step, RotationStep::LocalChangesSent);
        // 背景執行緒的這一步在離開之前就開始了(拿到的是「等著凍結」的快照),卻在離開判定之後才走到寫標記那一步:進度已經被離開取消,
        // `update_rotation` 在 core 鎖內找不到它 —— 什麼都不做,不寫標記、不凍結。
        let (generation, snapshot) = {
            let core = a.runtime.core.lock().unwrap();
            (core.generation, core.state.clone().unwrap())
        };
        let worker = std::sync::Arc::clone(&a);
        let step_keys = keys.clone();
        AFTER_ROTATION_DECISION.with(|h| {
            *h.borrow_mut() = Some(Box::new(move || {
                drive_rotation(&worker.env(), generation, snapshot, step_keys).unwrap();
            }))
        });
        leave_account(&a.env(), false).unwrap();
        assert!(!relay.is_frozen(&keys.chain_id), "the old account was not frozen");
        assert_eq!(markers_on(&relay, &keys), 0, "no marker was written");
        assert!(!a.state().joined() && a.state().rotation.is_none());
        settle(&b);
        assert!(b.state().frozen().is_none());
    }

    #[test]
    fn a_change_that_can_never_finish_because_its_new_code_is_gone_can_be_left() {
        use crate::sync::rotation::{start_rotation, NEXT_CODE_GONE_AFTER_FREEZE_MESSAGE};
        use crate::sync::round::sync_once;
        use crate::sync::round::tests::{pair, settle};
        // 兩種「碼再也找不回來」:暫存的碼被刪了,或換成不屬於這次更換的另一組。
        for replacement in [None, Some(crypto::generate_mnemonic().unwrap())] {
            let (relay, _clock, a, b, words, personal) = pair();
            let file = a.space_path(&personal);
            a.save_in_app(&file, "Host web\n  HostName 10.0.0.1\n");
            settle(&a);
            start_rotation(&a.env()).unwrap();
            let _ = sync_once(&a.env());
            let _ = sync_once(&a.env());
            assert_eq!(a.state().rotation.unwrap().step, RotationStep::Copying);
            let old_account = a.state().account.unwrap().chain_id;
            match &replacement {
                None => a.keychain.delete(NEXT_MNEMONIC_ACCOUNT).unwrap(),
                Some(other) => a.keychain.set(NEXT_MNEMONIC_ACCOUNT, other).unwrap(),
            }
            for _ in 0..5 {
                let _ = sync_once(&a.env());
            }
            // 每一輪都重讀 keychain,卻再也讀不到:停在這一步;說明講的是實情(不是「重啟 SSHelter」)。
            let s = a.state();
            assert_eq!(s.rotation.as_ref().map(|r| r.step), Some(RotationStep::Copying));
            assert_eq!(s.last_error.as_deref(), Some(NEXT_CODE_GONE_AFTER_FREEZE_MESSAGE));
            // 不叫使用者重啟(每一輪都重讀 keychain),也不說「再加入」:舊帳戶已凍結,誰都加入不了它(下面證明);說的是行得通的出路。
            assert!(!NEXT_CODE_GONE_AFTER_FREEZE_MESSAGE.contains("restart") && !NEXT_CODE_GONE_AFTER_FREEZE_MESSAGE.contains("join again"));
            assert!(
                NEXT_CODE_GONE_AFTER_FREEZE_MESSAGE.contains("the old sync account can no longer be joined")
                    && NEXT_CODE_GONE_AFTER_FREEZE_MESSAGE.contains("create a new sync account on one computer")
                    && NEXT_CODE_GONE_AFTER_FREEZE_MESSAGE.contains("leave the old account and join the new one"),
                "{NEXT_CODE_GONE_AFTER_FREEZE_MESSAGE}"
            );
            // 凍結之後本來不能離開;碼不見了,這次更換再也完成不了 —— 允許離開。就算要求刪除帳戶,relay 上也什麼都不動:帳戶上的標記是還沒換的電腦得知
            // 這件事的唯一來源。回的錯誤說明這台已經離開,以及行得通的出路(舊帳戶誰都加入不了了):其中一台建立新的同步帳戶,其他電腦離開舊帳戶後加入新的。
            relay.clear_calls();
            let err = leave_account(&a.env(), true).unwrap_err().to_string();
            assert_eq!(err, leave_abandoned_message(true));
            assert!(
                err.starts_with("left the sync account on this computer, but its sync code change could not be finished")
                    && err.contains("the old sync account can no longer be joined")
                    && err.contains("create a new sync account on one computer, and on the other computers leave the old account (their synced files stay as local files) and join the new one")
                    && err.ends_with(". The sync account was not deleted from the relay"),
                "{err}"
            );
            assert!(!err.contains("join again"), "the old account refuses every join: {err}");
            assert!(!leave_abandoned_message(false).contains("not deleted from the relay"), "only said when the deletion was asked for");
            assert!(!relay.calls().iter().any(|c| c.starts_with("delete:")), "{:?}", relay.calls());
            assert!(relay.exists(&old_account) && relay.is_frozen(&old_account));
            let s = a.state();
            assert!(!s.joined() && s.rotation.is_none() && s.last_error.is_none());
            assert!(a.keychain.entry(NEXT_MNEMONIC_ACCOUNT).is_none() && a.keychain.entry(MNEMONIC_ACCOUNT).is_none());
            // 檔案照常改成本機檔案,ssh 讀得到的主機都還在。
            let kept = space_files::local_dir(&a.ssh_dir()).join(file.file_name().unwrap());
            assert_eq!(a.read(&kept), "Host web\n  HostName 10.0.0.1\n");
            assert_eq!(host_file(&a, "web"), Some(kept.clone()));
            assert_eq!(s.notices.last(), Some(&SyncNotice::LeftAccount { kept_files: vec![kept.to_string_lossy().into_owned()] }));
            // 其他電腦被擋在沒有人持有的新碼後面:它們一樣只能離開(檔案留成本機檔案)。
            settle(&b);
            assert!(b.state().frozen().is_some());
            // 文字說的就是事實:舊帳戶帶著 A 寫的更換標記,任何電腦拿舊碼加入都被拒絕(要輸入的新碼不存在)……
            assert_eq!(
                join_account(&a.env(), &words, "MacBook-A").unwrap_err().to_string(),
                "this sync code was changed on MacBook-A; enter the new sync code"
            );
            // ……行得通的出路:一台建立新的同步帳戶,其他電腦離開舊帳戶、加入新的。
            let new_words = create_account(&a.env(), "MacBook-A").unwrap();
            leave_account(&b.env(), false).unwrap();
            join_account(&b.env(), &new_words, "MacBook-B").unwrap();
            assert!(b.state().joined() && b.state().frozen().is_none());
        }
    }

    // ── 最終審查的修正:離開與重新開始時,檔案絕不悄悄從 ssh 讀的清單上消失;被換掉的帳戶不刪 ──

    #[test]
    fn leaving_while_a_round_renames_a_space_keeps_the_renamed_file_readable() {
        use crate::sync::round::sync_once;
        use crate::sync::round::tests::{pair, settle};
        use crate::sync::spaces::rename_space;
        use crate::sync::testkit::{HookedConnector, Hooks};
        use std::sync::Arc;
        let (relay, _clock, a, b, _words, personal) = pair();
        b.save_in_app(&b.space_path(&personal), "Host web\n  HostName 10.0.0.1\n");
        settle(&b);
        settle(&a);
        // A 改名,B 還沒拉到。
        rename_space(&a.env(), &personal, "Lab").unwrap();
        settle(&a);
        let old = b.space_path(&personal);
        let renamed = old.with_file_name(format!("lab-{}.config", &personal[..8]));
        // B 刪除帳戶:刪第一條 chain 的那一刻,背景執行緒的一輪拉到改名、把檔案改了名(離開的快照還是舊檔名)。
        let b = Arc::new(b);
        let round = Arc::clone(&b);
        let hooks = Hooks {
            before_delete: Some(Box::new(move || {
                let _ = sync_once(&round.env());
            })),
            ..Hooks::default()
        };
        let connector = HookedConnector::new(&relay, hooks);
        let mut env = b.env();
        env.relays = &connector;
        leave_account(&env, true).unwrap();
        assert!(!old.exists() && !renamed.exists(), "the round renamed the file, and leaving moved the renamed one");
        let kept = space_files::local_dir(&b.ssh_dir()).join(renamed.file_name().unwrap());
        assert_eq!(b.read(&kept), "Host web\n  HostName 10.0.0.1\n");
        assert_eq!(b.main_config(), format!("# main\nInclude ~/.ssh/sshelter-local/lab-{}.config\n", &personal[..8]));
        assert_eq!(host_file(&b, "web"), Some(kept.clone()), "ssh and the app still read the host");
        assert_eq!(b.state().notices, vec![SyncNotice::LeftAccount { kept_files: vec![kept.to_string_lossy().into_owned()] }]);
        assert!(!b.state().joined());
    }

    #[test]
    fn a_hosts_file_left_by_v1_sync_stays_readable_after_creating_or_joining_an_account() {
        use crate::sync::round::tests::settle;
        use crate::sync::spaces::select_space;
        let (relay, clock) = (FakeRelay::new(), TestClock::new());
        // v1 的離開保留了 `hosts.config` 與它的 Include(未加入的 v1 狀態,啟動時直接換成未加入的 v2)。
        let leftover = |name: &str| {
            let d = TestDevice::with_main_config(name, &relay, &clock, "# main\nInclude ~/.ssh/sshelter/hosts.config\nHost local\n");
            let v1_file = hosts_file::managed_path(&d.ssh_dir());
            std::fs::create_dir_all(v1_file.parent().unwrap()).unwrap();
            std::fs::write(&v1_file, format!("Host old-{name}\n  HostName 10.9.9.9\n")).unwrap();
            d.reload();
            d
        };
        let check = |d: &TestDevice, name: &str| {
            let kept = space_files::local_dir(&d.ssh_dir()).join("hosts.config");
            assert!(!hosts_file::managed_path(&d.ssh_dir()).exists());
            assert_eq!(d.read(&kept), format!("Host old-{name}\n  HostName 10.9.9.9\n"));
            assert!(d.main_config().contains("Include ~/.ssh/sshelter-local/hosts.config\n"), "{}", d.main_config());
            assert_eq!(host_file(d, &format!("old-{name}")), Some(kept.clone()), "ssh and the app still read the old hosts");
            let notice = SyncNotice::LeftAccount { kept_files: vec![kept.to_string_lossy().into_owned()] };
            assert!(d.state().notices.contains(&notice));
            assert!(d.events.notices.lock().unwrap().contains(&notice));
        };
        // 建立帳戶:Personal 的 Include 放在最頂端,v1 的檔案改成一般的本機檔案。
        let a = leftover("a");
        let words = create_account(&a.env(), "A").unwrap();
        settle(&a);
        check(&a, "a");
        let personal = a.state().spaces.keys().next().unwrap().clone();
        assert!(a.main_config().starts_with(&format!("# main\nInclude ~/.ssh/sshelter/{}\n", a.state().spaces[&personal].file_name)));
        // 加入帳戶(之後勾選 space、同步完):一樣。
        let b = leftover("b");
        join_account(&b.env(), &words, "B").unwrap();
        settle(&b);
        check(&b, "b");
        select_space(&b.env(), &personal).unwrap();
        settle(&b);
        check(&b, "b");
        // 打錯的同步碼不會搬走任何東西。
        let c = leftover("c");
        assert!(join_account(&c.env(), WORDS, "C").is_err());
        assert!(hosts_file::managed_path(&c.ssh_dir()).exists());
        assert!(c.main_config().contains("Include ~/.ssh/sshelter/hosts.config\n"));
    }

    #[test]
    fn deleting_an_account_whose_code_was_changed_elsewhere_only_leaves_this_computer() {
        use crate::sync::round::sync_once;
        use crate::sync::round::tests::{pair, rotate_elsewhere, settle};
        use crate::sync::spaces::select_space;
        use crate::sync::testkit::{HookedConnector, Hooks};
        use std::sync::Arc;
        let (relay, clock, a, b, words, personal) = pair();
        let joined = |name: &str| {
            let d = TestDevice::new(name, &relay, &clock);
            join_account(&d.env(), &words, name).unwrap();
            select_space(&d.env(), &personal).unwrap();
            settle(&d);
            d
        };
        let (c, e) = (joined("c"), joined("e"));
        let account_chain = b.state().account.unwrap().chain_id;
        // 另一台更換了同步碼:標記寫在舊帳戶 chain 上、所有 chain 凍結。
        rotate_elsewhere(&a, &relay);
        let rows = relay.rows(&account_chain).len();
        // B 已經看到了:只在這台離開,relay 上什麼都不刪。
        settle(&b);
        assert_eq!(b.state().frozen().map(|f| f.markers.len()), Some(1));
        let file_name = b.state().spaces[&personal].file_name.clone();
        relay.clear_calls();
        assert_eq!(leave_account(&b.env(), true).unwrap_err().to_string(), LEAVE_REPLACED_MESSAGE);
        assert!(!relay.calls().iter().any(|c| c.starts_with("delete:")), "{:?}", relay.calls());
        assert!(!b.state().joined(), "this computer left");
        assert!(space_files::local_dir(&b.ssh_dir()).join(&file_name).is_file(), "its files are kept as local files");
        // E 也看到了,而且它的同步碼讀不到(帳戶金鑰不在):一樣只在這台離開,不會因為刪不了就整個拒絕。
        settle(&e);
        e.runtime.core.lock().unwrap().account_keys = None;
        assert_eq!(leave_account(&e.env(), true).unwrap_err().to_string(), LEAVE_REPLACED_MESSAGE);
        assert!(!e.state().joined());
        // C 還沒看到:刪第一條 chain 的那一刻,背景執行緒的一輪才拉到更換標記 —— 之後的都不刪,帳戶 chain 與標記留著。
        assert!(c.state().frozen().is_none());
        let c = Arc::new(c);
        let round = Arc::clone(&c);
        let hooks = Hooks {
            before_delete: Some(Box::new(move || {
                let _ = sync_once(&round.env());
            })),
            ..Hooks::default()
        };
        let connector = HookedConnector::new(&relay, hooks);
        let mut env = c.env();
        env.relays = &connector;
        assert_eq!(leave_account(&env, true).unwrap_err().to_string(), LEAVE_REPLACED_MESSAGE);
        assert!(!c.state().joined());
        assert_eq!(relay.rows(&account_chain).len(), rows, "the old account and its marker stay");
        // 還在用舊同步碼的電腦照樣得知那組同步碼已經換掉了。
        let d = TestDevice::new("d", &relay, &clock);
        assert_eq!(join_account(&d.env(), &words, "D").unwrap_err().to_string(), "this sync code was changed on MacBook-Z; enter the new sync code");
    }

    #[test]
    fn a_v1_hosts_file_is_kept_local_only_when_an_include_reads_it() {
        use crate::sync::round::tests::settle;
        let (relay, clock) = (FakeRelay::new(), TestClock::new());
        let leftover = |name: &str, main: &str| {
            let d = TestDevice::with_main_config(name, &relay, &clock, main);
            let v1_file = hosts_file::managed_path(&d.ssh_dir());
            std::fs::create_dir_all(v1_file.parent().unwrap()).unwrap();
            std::fs::write(&v1_file, "Host old\n  HostName 10.9.9.9\n").unwrap();
            d.reload();
            (d, v1_file)
        };
        // 沒有任何 Include 讀它(使用者已經把那一行拿掉):ssh 本來就不讀它 —— 留在原地,什麼都不提示。
        let (d, v1_file) = leftover("d", "# main\nHost local\n");
        create_account(&d.env(), "D").unwrap();
        settle(&d);
        assert_eq!(d.read(&v1_file), "Host old\n  HostName 10.9.9.9\n", "left where it was");
        assert!(!space_files::local_dir(&d.ssh_dir()).exists());
        let file_name = d.state().spaces.values().next().unwrap().file_name.clone();
        assert_eq!(d.main_config(), format!("# main\nInclude ~/.ssh/sshelter/{file_name}\nHost local\n"));
        assert!(d.state().notices.is_empty() && d.events.notices.lock().unwrap().is_empty(), "nothing to announce");
        // 只有手寫的 glob 讀它:一樣改成本機檔案、留下提示 —— 建立帳戶時我們的清單會取代那個 glob。
        let (e, v1_file) = leftover("e", "# main\nInclude ~/.ssh/sshelter/*.config\nHost local\n");
        create_account(&e.env(), "E").unwrap();
        settle(&e);
        let kept = space_files::local_dir(&e.ssh_dir()).join("hosts.config");
        assert!(!v1_file.exists());
        assert_eq!(host_file(&e, "old"), Some(kept.clone()), "ssh and the app still read the old hosts");
        let file_name = e.state().spaces.values().next().unwrap().file_name.clone();
        assert_eq!(
            e.main_config(),
            format!("# main\nInclude ~/.ssh/sshelter/{file_name}\nInclude ~/.ssh/sshelter-local/hosts.config\nHost local\n")
        );
        assert_eq!(e.state().notices, vec![SyncNotice::LeftAccount { kept_files: vec![kept.to_string_lossy().into_owned()] }]);
    }

    #[test]
    fn leaving_with_a_hand_written_glob_include_keeps_the_hosts_readable() {
        let (relay, clock) = (FakeRelay::new(), TestClock::new());
        let a = TestDevice::new("a", &relay, &clock);
        create_account(&a.env(), "A").unwrap();
        let personal = a.state().spaces.keys().next().unwrap().clone();
        a.save_in_app(&a.space_path(&personal), "Host web\n  HostName 10.0.0.1\n");
        let file_name = a.state().spaces[&personal].file_name.clone();
        // 使用者把清單換成一行手寫的 glob,下一輪改寫清單之前就離開。
        let globbed = a.main_config().replace(&format!("Include ~/.ssh/sshelter/{file_name}"), "Include ~/.ssh/sshelter/*.config");
        a.write_externally(&a.main_path(), &globbed);
        a.reload();
        leave_account(&a.env(), false).unwrap();
        // 搬走的檔案放在 glob 原來的位置(搬出這個目錄之後 glob 就讀不到它了);glob 那時還對得到檔案,原樣留著。
        let kept = space_files::local_dir(&a.ssh_dir()).join(&file_name);
        assert_eq!(a.read(&kept), "Host web\n  HostName 10.0.0.1\n");
        assert_eq!(a.main_config(), format!("# main\nInclude ~/.ssh/sshelter-local/{file_name} ~/.ssh/sshelter/*.config\n"));
        assert_eq!(host_file(&a, "web"), Some(kept), "ssh and the app still read the host");
    }
}
