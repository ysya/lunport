//! 主機搬進 space(spec §7.2:搬移精靈「搬進一個 space」與側邊欄拖曳,沿用 v1 的搬移管線)、跨檔案的同名主機
//! (spec §4.3:ssh 套用每一份、每個設定取先讀到的值,Include 清單中排在前面的 space 檔先讀)、以及**以檔案路徑定位**的處理(既有
//! `config_rename_host`/`config_remove_host` 以第一個命中為準,同名時會誤中排在前面的那份,不能用)。

use std::collections::{BTreeMap, HashSet};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use tauri::{AppHandle, Manager};

use crate::sync::env::SyncEnv;

use crate::config::commands::{drift, load_doc_migrated, move_host, persist_file, validate_host_patterns};
use crate::config::dto::parse_tags;
use crate::config::edit::{find_host_mut, set_host_patterns, set_tags};
use crate::config::include::find_host_file_index;
use crate::config::model::{Item, SshConfigDoc};
use crate::error::AppError;
use crate::state::AppState;
use crate::sync::engine::ANOTHER_ENGINE_MESSAGE;
use crate::sync::hosts_file::{first_alias, forbidden_directive, is_syncable_block};
use crate::sync::merge::selected_space_refs;
use crate::sync::runtime::SyncRuntime;
use crate::sync::space_files::space_file_path;
use crate::sync::spaces::CreateError;

/// 目標 space 剛勾選、基線輪還沒跑完時搬進去的拒絕訊息。
pub const WAIT_FOR_FIRST_SYNC: &str = "wait for the first sync of this space to finish before moving hosts into it";
/// 目標 space 的檔案還沒載進 doc(剛勾選、剛建立):稍等一下就載進來了。
const SPACE_FILE_NOT_LOADED: &str = "the space file is not loaded yet; try again in a moment";
/// 精靈一次建立好幾個 space 時,relay 對建立回了 `429`(每 IP 每小時 20 次):這一組與剩下的組不再建立 space(spec §6.4、§7.2),約一小時後再試。
const CREATES_RATE_LIMITED: &str = "the relay is rate-limiting new spaces from this network, so no more are created now; try again in about an hour";

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(test, derive(ts_rs::TS))]
#[cfg_attr(test, ts(export, export_to = "../../src/bindings/"))]
pub struct DuplicateAlias {
    pub alias: String,
    /// 被遮蔽(ssh 不會用)的那份所在的檔案。
    pub local_file: String,
}

#[derive(Clone, Copy, Debug, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ShadowedAction {
    /// 被遮蔽的那份改名 `<alias>-local`(保留它的定義)。
    Rename,
    /// 移除被遮蔽的那份(先讀的那份留著,之後只剩它一份)。
    Remove,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(test, derive(ts_rs::TS))]
#[cfg_attr(test, ts(export, export_to = "../../src/bindings/"))]
pub struct MigrationFailure {
    pub alias: String,
    pub error: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(test, derive(ts_rs::TS))]
#[cfg_attr(test, ts(export, export_to = "../../src/bindings/"))]
pub struct MigrationReport {
    pub moved: Vec<String>,
    pub failed: Vec<MigrationFailure>,
    #[cfg_attr(test, ts(type = "number"))]
    pub tagged: u64,
}

/// `homelab.config` → `homelab`;非 `[a-z0-9_-]` 一律成 `-`。
pub fn tag_for_file(path: &Path) -> String {
    let stem = path.file_name().map(|s| s.to_string_lossy().into_owned()).unwrap_or_default();
    let stem = stem.strip_suffix(".config").or_else(|| stem.strip_suffix(".conf")).unwrap_or(&stem).to_lowercase();
    let mut out = String::new();
    for ch in stem.chars() {
        if ch.is_ascii_alphanumeric() || ch == '_' || ch == '-' {
            out.push(ch);
        } else if !out.ends_with('-') {
            out.push('-');
        }
    }
    out.trim_matches('-').to_string()
}

/// `move_host` 會搬的那個區塊:`find_host_file_index` → 該檔案裡「任一 pattern 相符」的第一個區塊。
fn block_to_move<'a>(doc: &'a SshConfigDoc, alias: &str) -> Option<&'a Item> {
    let idx = find_host_file_index(doc, alias)?;
    doc.files[idx].items.iter().find(|i| matches!(i, Item::Host(h) if h.patterns.iter().any(|p| p == alias)))
}

/// 搬進 space 前的資格檢查:那個區塊的所有 pattern 都必須具名。找不到 alias 交給 `move_host` 回報。
pub fn refuse_wildcard(doc: &SshConfigDoc, alias: &str) -> Result<(), AppError> {
    match block_to_move(doc, alias) {
        Some(Item::Host(h)) if !is_syncable_block(&h.patterns) => Err(AppError::Other(format!(
            "host '{alias}' belongs to a block with wildcard patterns and cannot be synced"
        ))),
        _ => Ok(()),
    }
}

/// 區塊含 synced hosts 不能用的內容:不能搬進 space(spec §7.2、§7.4)—— 搬進去那個 space 就違反不變式而暫停。
/// `hosts_file::forbidden_directive` 擋的每一種都算:`Include`、帶引號的 keyword、以 `=` 開頭的行、HostName / User /
/// HostKeyAlias / ProxyJump 的值有 ssh 會交給 shell 的字元、不可見字元、OpenSSH 讀法與 SSHelter 不同的 Host / Match 行。
pub fn refuse_forbidden(doc: &SshConfigDoc, alias: &str) -> Result<(), AppError> {
    match block_to_move(doc, alias).and_then(|block| forbidden_directive(std::slice::from_ref(block))) {
        Some(f) => Err(AppError::Other(format!(
            "host '{alias}' contains {}, which synced hosts cannot use; keep it in a local file",
            f.describe()
        ))),
        None => Ok(()),
    }
}

/// `target` 檔案裡已有 Host 區塊定義了 `name`(該區塊任一 pattern 等於它)。
pub fn managed_defines(doc: &SshConfigDoc, target: &Path, name: &str) -> bool {
    doc.files
        .iter()
        .filter(|f| f.path == target)
        .flat_map(|f| f.items.iter())
        .any(|i| matches!(i, Item::Host(h) if h.patterns.iter().any(|p| p == name)))
}

fn managed_first_alias(doc: &SshConfigDoc, target: &Path, name: &str) -> bool {
    doc.files.iter().filter(|f| f.path == target).flat_map(|f| f.items.iter()).any(|i| first_alias(i) == Some(name))
}

/// 搬進目標 space 檔之前的重複檢查(同 v1):目標檔已經定義了要搬的區塊的**任一** pattern 就拒絕 —— 同一個檔案裡
/// 重複的 alias 會讓那個 space 違反不變式而暫停。不同 space 之間同名是允許的(spec §4.3,UI 另外標示)。要搬的區塊本身就已經在目標檔裡(同一組先搬了 `Host a web`
/// 的 `a`,後面又列到 `web`)不是重複:訊息說它已經在那裡、是同一個區塊的另一個名字 —— 不能叫使用者去改一個剛搬走的本機主機。
pub fn refuse_already_synced(doc: &SshConfigDoc, target: &Path, alias: &str) -> Result<(), AppError> {
    if let (Some(idx), Some(Item::Host(block))) = (find_host_file_index(doc, alias), block_to_move(doc, alias)) {
        if doc.files[idx].path == target {
            let first = block.patterns.first().map_or(alias, String::as_str);
            return Err(AppError::Other(if first == alias {
                format!("'{alias}' is already in that space")
            } else {
                format!("'{alias}' is already in that space — it is another name of the host '{first}'")
            }));
        }
    }
    let moving: &[String] = match block_to_move(doc, alias) {
        Some(Item::Host(h)) => h.patterns.as_slice(),
        _ => &[],
    };
    let Some(name) = std::iter::once(alias).chain(moving.iter().map(String::as_str)).find(|name| managed_defines(doc, target, name))
    else {
        return Ok(());
    };
    let first = moving.first().map_or(alias, String::as_str);
    if name == first && managed_first_alias(doc, target, name) {
        Err(AppError::Other(format!("'{name}' is already in that space — resolve the duplicate instead")))
    } else {
        Err(AppError::Other(format!(
            "'{name}' is already used by a host in that space — remove or rename it in the local host '{first}' first"
        )))
    }
}

/// 這個行程沒有跑同步引擎時,拒絕任何「搬進 space」的動作(這個行程的同步狀態只是啟動時的快照)。訊息沿用
/// `save_blocked`;沒有記下原因(單元測試)時退回 `ANOTHER_ENGINE_MESSAGE`。呼叫端可能持有 doc 鎖。
pub fn refuse_while_sync_inactive(active: bool, sync: &SyncRuntime) -> Result<(), AppError> {
    if active {
        return Ok(());
    }
    let reason = sync.core.lock().unwrap().save_blocked.clone();
    Err(AppError::Other(reason.unwrap_or_else(|| ANOTHER_ENGINE_MESSAGE.to_string())))
}

/// 目標 space 剛勾選、基線輪還沒跑完就拒絕搬進去:搬進去的主機會被基線輪以 chain 為準直接覆蓋。
pub fn refuse_before_first_sync(sync: &SyncRuntime, space_id: &str) -> Result<(), AppError> {
    let pending = sync
        .core
        .lock()
        .unwrap()
        .state
        .as_ref()
        .and_then(|s| s.spaces.get(space_id))
        .is_some_and(|sp| !sp.baseline_established);
    if pending {
        return Err(AppError::Other(WAIT_FOR_FIRST_SYNC.to_string()));
    }
    Ok(())
}

/// 搬進一個 space 檔之前、整批共通的拒絕:這個行程沒有跑同步引擎(`refuse_while_sync_inactive`),或目標 space 剛勾選、第一輪還沒完成(`refuse_before_first_sync`)。
/// 搬移精靈(`move_hosts_into_space`)與側邊欄拖曳(`config_move_host`)共用 —— 兩邊拒絕的規則只有這一份(加上 `refuse_move_of`),不各列各的。
pub fn refuse_move_batch(sync: &SyncRuntime, active: bool, space_id: &str) -> Result<(), AppError> {
    refuse_while_sync_inactive(active, sync)?;
    refuse_before_first_sync(sync, space_id)
}

/// 把一台主機搬進 `target`(space 檔的完整路徑)之前,這一台自己的拒絕:區塊含 wildcard(`refuse_wildcard`)、含不能同步的內容 —— `Include`、帶引號的 keyword……
/// (`refuse_forbidden`),或 `target` 已經定義了要搬的區塊的任一個名字(`refuse_already_synced`)。什麼都不改。搬移精靈對每一台、側邊欄拖曳對那一台都用它。
pub fn refuse_move_of(doc: &SshConfigDoc, target: &Path, alias: &str) -> Result<(), AppError> {
    refuse_wildcard(doc, alias)?;
    refuse_forbidden(doc, alias)?;
    refuse_already_synced(doc, target, alias)
}

/// 側邊欄拖曳一台主機進 space 群組的全部拒絕:整批的(`refuse_move_batch`)加上這一台的(`refuse_move_of`),都在任何改動之前。
pub fn refuse_move_into_space(
    doc: &SshConfigDoc,
    sync: &SyncRuntime,
    active: bool,
    space_id: &str,
    target: &Path,
    alias: &str,
) -> Result<(), AppError> {
    refuse_move_batch(sync, active, space_id)?;
    refuse_move_of(doc, target, alias)
}

/// 這台勾選的 space 檔(space id, 路徑),依 Include 清單的順序(`space_files::include_order`,spec §4.3)—— 順序與主 config 的 Include 清單同一份(`merge::selected_space_refs`)。
/// 呼叫端可能持有 doc 鎖,這裡只短暫拿 core 鎖。
pub fn selected_space_files(sync: &SyncRuntime, ssh_dir: &Path) -> Vec<(String, PathBuf)> {
    let core = sync.core.lock().unwrap();
    let Some(s) = core.state.as_ref() else { return Vec::new() };
    selected_space_refs(s.account.as_ref(), &s.spaces)
        .into_iter()
        .filter_map(|r| Some((r.space_id, space_file_path(ssh_dir, &r.file_name).ok()?)))
        .collect()
}

/// 每個同步的 alias 由哪個 space 檔勝出:`spaces` 依 Include 順序,第一個定義它(第一個 pattern)的檔案。
fn winners(doc: &SshConfigDoc, spaces: &[PathBuf]) -> BTreeMap<String, PathBuf> {
    let mut out = BTreeMap::new();
    for path in spaces {
        for file in doc.files.iter().filter(|f| &f.path == path) {
            for alias in file.items.iter().filter_map(first_alias) {
                out.entry(alias.to_string()).or_insert_with(|| path.clone());
            }
        }
    }
    out
}

/// 被遮蔽的主機(spec §4.3):alias 定義在某個 space 檔、又出現在其他任何檔案(其他 space 檔或本機檔)。ssh 套用每一份、每個設定取先讀到的值;
/// Include 清單中排在前面的 space 檔(Include 在主 config 最頂端)先讀,它是勝出的那份。後讀的那幾份列出來,`local_file` = 它們所在的檔案。
/// 只列**第一個 pattern 等於 alias** 的區塊(`first_alias`):`Host a web` 的 `web` 是第二個 pattern、勝出那個檔案自己的第二個同名區塊都不列 ——
/// 前端對這些副本沒有側邊欄的處理可提供,只能請使用者在文字編輯器改那個檔案(`src/lib/sync-sidebar.ts` 的 `copiesNote`)。
pub fn duplicate_aliases(doc: &SshConfigDoc, spaces: &[PathBuf]) -> Vec<DuplicateAlias> {
    let winners = winners(doc, spaces);
    let mut out = Vec::new();
    for file in &doc.files {
        for alias in file.items.iter().filter_map(first_alias) {
            if winners.get(alias).is_some_and(|w| *w != file.path) {
                out.push(DuplicateAlias { alias: alias.to_string(), local_file: file.path.to_string_lossy().into_owned() });
            }
        }
    }
    out
}

/// 處理一筆被遮蔽的主機:以 `file`(完整路徑)定位那個檔案裡第一個 pattern 等於 `alias` 的區塊。回傳改動的檔案
/// 索引(呼叫端負責 `persist_file`)。拒絕改勝出的那份(Include 順序最前、ssh 先讀的那份;兩份 ssh 都套用)。被遮蔽的那份若在另一個 space 檔,改動照常同步。
pub fn resolve_shadowed(
    doc: &mut SshConfigDoc,
    alias: &str,
    file: &str,
    action: ShadowedAction,
    spaces: &[PathBuf],
) -> Result<usize, AppError> {
    let idx = doc
        .files
        .iter()
        .position(|f| f.path.to_string_lossy() == file)
        .ok_or_else(|| AppError::NotFound(format!("file '{file}' is not loaded")))?;
    if winners(doc, spaces).get(alias).is_some_and(|w| *w == doc.files[idx].path) {
        // 訊息裡的 "the copy ssh uses" 指勝出的那份(ssh 先讀的那份);ssh 其實兩份都套用,但這是對外的錯誤文字,只在註解裡說明、不改。
        return Err(AppError::Other("refusing to change the copy ssh uses; pick the shadowed file".to_string()));
    }
    let pos = doc.files[idx]
        .items
        .iter()
        .position(|i| first_alias(i) == Some(alias))
        .ok_or_else(|| AppError::NotFound(format!("host '{alias}' is not defined in '{file}'")))?;
    match action {
        ShadowedAction::Remove => {
            doc.files[idx].items.remove(pos);
        }
        ShadowedAction::Rename => {
            let new_alias = format!("{alias}-local");
            validate_host_patterns(std::slice::from_ref(&new_alias))?;
            let taken = doc.files.iter().flat_map(|f| f.items.iter()).any(|i| first_alias(i) == Some(new_alias.as_str()));
            if taken {
                return Err(AppError::Other(format!("host '{new_alias}' already exists; rename it in the editor instead")));
            }
            if let Item::Host(h) = &mut doc.files[idx].items[pos] {
                let mut patterns = h.patterns.clone();
                patterns[0] = new_alias;
                set_host_patterns(h, &patterns);
            }
        }
    }
    Ok(idx)
}

fn space_paths(sync: &SyncRuntime) -> Result<Vec<PathBuf>, AppError> {
    let ssh_dir = crate::keys::ssh_dir()?;
    Ok(selected_space_files(sync, &ssh_dir).into_iter().map(|(_, p)| p).collect())
}

#[tauri::command]
pub async fn sync_duplicate_aliases(app: AppHandle) -> Result<Vec<DuplicateAlias>, AppError> {
    let handle = app.clone();
    tauri::async_runtime::spawn_blocking(move || {
        let state = handle.state::<AppState>();
        let guard = state.doc.lock().unwrap();
        let doc = guard.as_ref().ok_or_else(|| AppError::Other("no config loaded".to_string()))?;
        Ok(duplicate_aliases(doc, &space_paths(&state.sync)?))
    })
    .await
    .map_err(crate::sync::engine::join_error)?
}

#[tauri::command]
pub async fn sync_resolve_shadowed(app: AppHandle, alias: String, file: String, action: ShadowedAction) -> Result<Vec<DuplicateAlias>, AppError> {
    let handle = app.clone();
    tauri::async_runtime::spawn_blocking(move || {
        let state = handle.state::<AppState>();
        let mut doc_lock = state.doc.lock().unwrap();
        let mut backed_up = state.backed_up.lock().unwrap();
        let retention = *state.backup_retention.lock().unwrap();
        let spaces = space_paths(&state.sync)?;
        resolve_shadowed_and_persist(&mut doc_lock, &alias, &file, action, &spaces, |doc, idx| {
            persist_file(doc, idx, &mut backed_up, retention)
        })
    })
    .await
    .map_err(crate::sync::engine::join_error)?
}

/// `sync_resolve_shadowed` 的改動與寫檔(`persist` 由呼叫端注入)。寫入失敗時從磁碟重載(重載也失敗就作廢 doc),
/// 再回傳原本的錯誤 —— doc 不能比磁碟新。
fn resolve_shadowed_and_persist(
    slot: &mut Option<SshConfigDoc>,
    alias: &str,
    file: &str,
    action: ShadowedAction,
    spaces: &[PathBuf],
    mut persist: impl FnMut(&mut SshConfigDoc, usize) -> Result<(), AppError>,
) -> Result<Vec<DuplicateAlias>, AppError> {
    let doc = slot.as_mut().ok_or_else(|| AppError::Other("no config loaded".to_string()))?;
    let main_path = doc.files[0].path.clone();
    let idx = resolve_shadowed(doc, alias, file, action, spaces)?;
    if let Err(e) = persist(doc, idx) {
        *slot = load_doc_migrated(&main_path).ok();
        return Err(e);
    }
    Ok(duplicate_aliases(doc, spaces))
}

/// 批次搬進一個 space 檔的核心迴圈(同 v1,可直接單元測試;`persist` 由呼叫端注入)。target、source、tag 三個寫入
/// 任一失敗就停止整批並請呼叫端重載,失敗的原因記進報告(tag 寫入失敗的那台只列在 `failed`:「moved, but its tag could not be saved」)。搬移前就拒絕的(wildcard、
/// `Include`、目標檔已有同名,`refuse_move_of`)doc 沒動過,不停批次。
fn migrate_hosts(
    doc: &mut SshConfigDoc,
    aliases: Vec<String>,
    tag_by_file: bool,
    target: &str,
    mut persist: impl FnMut(&mut SshConfigDoc, usize) -> Result<(), AppError>,
) -> (MigrationReport, bool) {
    let mut report = MigrationReport { moved: Vec::new(), failed: Vec::new(), tagged: 0 };
    let mut halted = false;
    for alias in aliases {
        if halted {
            report.failed.push(MigrationFailure { alias, error: "not attempted: an earlier move failed".to_string() });
            continue;
        }
        if let Err(e) = refuse_move_of(doc, Path::new(target), &alias) {
            report.failed.push(MigrationFailure { alias, error: e.to_string() });
            continue;
        }
        let source_tag = find_host_file_index(doc, &alias).filter(|&i| i != 0).map(|i| tag_for_file(&doc.files[i].path));
        match move_host(doc, &alias, target) {
            Ok((src, tgt)) => {
                if let Err(e) = persist(doc, tgt).and_then(|_| persist(doc, src)) {
                    report.failed.push(MigrationFailure { alias, error: e.to_string() });
                    halted = true;
                    continue;
                }
                if let (true, Some(tag)) = (tag_by_file, source_tag) {
                    let mut tags = find_host_mut(&mut doc.files[tgt].items, &alias).map(|h| parse_tags(&h.body)).unwrap_or_default();
                    if !tags.contains(&tag) {
                        tags.push(tag);
                        if let Some(host) = find_host_mut(&mut doc.files[tgt].items, &alias) {
                            set_tags(host, &tags);
                        }
                        match persist(doc, tgt) {
                            Ok(()) => report.tagged += 1,
                            // 主機已經搬過去了(目標與來源都寫好了),只有 tag 沒寫成:原因記進報告(以前只停下批次、原因就丟了),這台只列一次(在 `failed`,
                            // 說明它搬過去了);後面的主機照「前一台出錯」不再嘗試,呼叫端重載。
                            Err(e) => {
                                report.failed.push(MigrationFailure { alias, error: format!("moved, but its tag could not be saved: {e}") });
                                halted = true;
                                continue;
                            }
                        }
                    }
                }
                report.moved.push(alias);
            }
            Err(e) => report.failed.push(MigrationFailure { alias, error: e.to_string() }),
        }
    }
    (report, halted)
}

/// 搬移精靈「搬進一個 space」(spec §7.2)的本體:逐台搬進這台勾選的 `space_id` 的檔案(目標先寫、再從來源移除;兩個
/// 檔案各自經存檔 hook 產生記錄)。`tag_by_file` 時把 Include 檔的檔名加成 tag。`active` = 這個行程跑著同步引擎
/// (`engine::engine_active`)。沒有引擎、目標 space 沒勾選或第一輪還沒完成時,在任何改動之前整批拒絕。
pub fn move_hosts_into_space(
    env: &SyncEnv,
    active: bool,
    aliases: Vec<String>,
    space_id: &str,
    tag_by_file: bool,
) -> Result<MigrationReport, AppError> {
    let report = {
        let mut doc_lock = env.doc.lock().unwrap();
        let mut backed_up = env.backed_up.lock().unwrap();
        let retention = env.retention();
        let doc = doc_lock.as_mut().ok_or_else(|| AppError::Other("no config loaded".to_string()))?;
        // 整批的拒絕與側邊欄拖曳共用(`refuse_move_batch`):沒有引擎、目標 space 第一輪還沒完成。
        refuse_move_batch(env.runtime, active, space_id)?;
        let (_, target) = selected_space_files(env.runtime, &env.ssh_dir)
            .into_iter()
            .find(|(id, _)| id == space_id)
            .ok_or_else(|| AppError::Other("that space is not synced on this device".to_string()))?;
        if !doc.files.iter().any(|f| f.path == target) {
            return Err(AppError::Other(SPACE_FILE_NOT_LOADED.to_string()));
        }
        let main_path = doc.files[0].path.clone();
        let target = target.to_string_lossy().into_owned();
        let (report, needs_reload) =
            migrate_hosts(doc, aliases, tag_by_file, &target, |doc, idx| persist_file(doc, idx, &mut backed_up, retention));
        if needs_reload {
            // 有寫入失敗:in-memory doc 可能已經比磁碟新。重載讓兩邊一致;重載也失敗就整份作廢。
            drop(backed_up);
            *doc_lock = env.load_doc(&main_path).ok();
        }
        report
    };
    env.events.applied(0);
    env.events.wake();
    Ok(report)
}

/// 「一個來源檔建立一個 space」(spec §7.2)的一組:新 space 的名稱(UI 以來源檔名產生,檔名 alias 優先)與要搬進去的主機。
#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(test, derive(ts_rs::TS))]
#[cfg_attr(test, ts(export, export_to = "../../src/bindings/"))]
pub struct NewSpaceGroup {
    pub name: String,
    pub aliases: Vec<String>,
}

/// 同一個 alias 列在不只一組時,後面那些組的失敗原因。
const LISTED_IN_TWO_GROUPS: &str = "listed in more than one group";

/// 一組主機全部列為失敗(原因相同)。
fn fail_all(report: &mut MigrationReport, aliases: Vec<String>, error: &str) {
    report.failed.extend(aliases.into_iter().map(|alias| MigrationFailure { alias, error: error.to_string() }));
}

/// 一組主機搬進新 space 之前的檢查結果(`check_group`)。
struct GroupCheck {
    /// 事先就會被拒絕的主機與原因,依 `aliases` 的順序。
    refused: Vec<MigrationFailure>,
    /// 沒被拒絕的主機要搬走的區塊的每一個 pattern:搬的是整個區塊(`Host a web` 以 `a` 搬,連 `web` 一起走),所以後面的組再列到
    /// 其中任何一個名字,都是同一台主機。
    block_names: Vec<String>,
    /// 檢查時 doc 比磁碟舊、整份重載過了:呼叫端在鎖都放掉之後發 `applied(0)`。
    reloaded: bool,
}

/// doc 裡有沒有檔案的內容和載入(或上次寫入)時不同:`persist_file`、`move_host` 防止蓋掉外部修改用的同一個內容指紋(UI 的
/// `config_check_drift` 也是)。讀不到的檔案算不同,同 `persist_file`。
fn doc_drifted(doc: &SshConfigDoc) -> bool {
    drift(doc).map(|files| files.iter().any(|f| f.changed)).unwrap_or(true)
}

/// 一組主機搬進新 space 之前的檢查(持有 doc 鎖,不寫任何檔案、不碰網路)。先確認 doc 還是磁碟上的樣子:載入之後有檔案在 app 外被
/// 改過,新 space 的檔案就列不進 Include、搬不進去,留下一個空的 space(後面每一組都一樣)—— 過時了就**整份重載、換掉記憶體裡的 doc**(`load_doc_migrated`
/// 載入時也可能搬動舊的 `.bak` 檔;`GroupCheck::reloaded` 讓呼叫端在放掉鎖之後通知前端並喚醒引擎);重載不了回 Err,
/// 什麼都還沒建立。再判定會被拒絕的主機:找不到的 alias、wildcard 區塊、含不能同步的內容的區塊,與 `migrate_hosts` 搬移前的拒絕
/// 同一組規則、同樣的訊息(目標是新的空檔,不會有「目標已有同名」);沒有載入 config 時全部拒絕。
fn check_group(env: &SyncEnv, aliases: &[String]) -> Result<GroupCheck, AppError> {
    let mut doc_lock = env.doc.lock().unwrap();
    let stale_main = doc_lock.as_ref().filter(|doc| doc_drifted(doc)).map(|doc| doc.files[0].path.clone());
    let reloaded = stale_main.is_some();
    if let Some(main) = stale_main {
        let fresh =
            env.load_doc(&main).map_err(|e| AppError::Other(format!("the config changed on disk and could not be reloaded: {e}")))?;
        *doc_lock = Some(fresh);
    }
    let mut check = GroupCheck { refused: Vec::new(), block_names: Vec::new(), reloaded };
    for alias in aliases {
        let moves = match doc_lock.as_ref() {
            None => Err(AppError::Other("no config loaded".to_string())),
            Some(doc) => match block_to_move(doc, alias) {
                Some(Item::Host(h)) => refuse_wildcard(doc, alias).and_then(|()| refuse_forbidden(doc, alias)).map(|()| h.patterns.clone()),
                _ => Err(AppError::NotFound(format!("host '{alias}' not found"))),
            },
        };
        match moves {
            Ok(names) => check.block_names.extend(names),
            Err(e) => check.refused.push(MigrationFailure { alias: alias.clone(), error: e.to_string() }),
        }
    }
    Ok(check)
}

/// 新 space 已經建立、主機卻沒搬進去(`move_hosts_into_space` 失敗):留下的是一個空的 space。重試同一個名稱只會得到「已經存在」,所以報告要說 space 在哪、
/// 請使用者把主機搬進它(「搬進一個 space」),而不是叫他「稍後再試」。
fn leftover_space_message(name: &str, cause: &AppError) -> String {
    let cause = match cause {
        AppError::Other(m) if m == SPACE_FILE_NOT_LOADED => "its file is not loaded yet".to_string(),
        other => other.to_string(),
    };
    format!("the space '{name}' was created, but the hosts could not be moved into it ({cause}) — move them into that space instead of creating it again")
}

/// 這一組不再建立 space(relay 剛對建立回了 `429`):事先就會被拒絕的主機照它們自己的原因列出(重試也不會變),其餘列為被限流 —— 約一小時後再試。依 `aliases` 的順序。
fn fail_rate_limited(report: &mut MigrationReport, aliases: Vec<String>, refused: Vec<MigrationFailure>) {
    let mut reasons: std::collections::HashMap<String, String> = refused.into_iter().map(|f| (f.alias, f.error)).collect();
    for alias in aliases {
        let error = reasons.remove(&alias).unwrap_or_else(|| CREATES_RATE_LIMITED.to_string());
        report.failed.push(MigrationFailure { alias, error });
    }
}

/// 搬移精靈「一個來源檔建立一個 space」(spec §7.2):每一組先建立 space(建立者勾選,新的空 chain 不需要基線輪)、
/// 再把主機搬進去。一組的失敗不會中斷整批、也不會丟掉前面各組的結果:建立失敗、或建好之後搬不進去的那一組,主機全部列為失敗
/// (原因相同;建好之後搬不進去的,原因說出那個空 space 的名稱並請使用者把主機搬進它,`leftover_space_message`),其他組照常。
/// 每一組建立 space 之前先檢查(`check_group`):doc 比磁碟舊就整份重載 —— 不然新 space 的檔案列不進
/// Include,後面每一組都建出一個搬不進去的空 space;重載不了,這一組的主機列為失敗、不建立 space。同一台主機只搬一次:`block_to_move`
/// 永遠挑 doc 裡第一個定義它的檔案,後面的組會把前面剛搬進 space 的那一份再搬一次,所以前面的組要搬的區塊,它的每一個名字
/// (`Host a web` 的 `a` 與 `web`)之後再被列到,都列為失敗。沒有主機可搬(沒有 alias,或每一台都會被拒絕:找不到、wildcard、
/// 含不能同步的內容)的組不建立空的 space。relay 對建立 space 回 `429`(每 IP 每小時 20 次)之後,這一組與剩下的組都**不再對 relay 送出建立**
/// (spec §6.4、§7.2:`429` 絕不立刻重試),列為失敗並說明約一小時後再試(`CREATES_RATE_LIMITED`);事先就會被拒絕的主機照自己的原因列出。
pub fn move_into_new_spaces(env: &SyncEnv, active: bool, groups: Vec<NewSpaceGroup>, tag_by_file: bool) -> Result<MigrationReport, AppError> {
    refuse_while_sync_inactive(active, env.runtime)?;
    let mut report = MigrationReport { moved: Vec::new(), failed: Vec::new(), tagged: 0 };
    // 前面的組已經列過的名字:alias,加上它們要搬走的區塊的每一個 pattern。
    let mut listed: HashSet<String> = HashSet::new();
    // relay 已經對建立 space 回過 `429`:之後不再建立。
    let mut rate_limited = false;
    for group in groups {
        let (repeated, aliases): (Vec<String>, Vec<String>) = group.aliases.into_iter().partition(|alias| listed.contains(alias));
        listed.extend(aliases.iter().cloned());
        fail_all(&mut report, repeated, LISTED_IN_TWO_GROUPS);
        let check = match check_group(env, &aliases) {
            Ok(check) => check,
            Err(e) => {
                fail_all(&mut report, aliases, &e.to_string());
                continue;
            }
        };
        if check.reloaded {
            env.events.applied(0);
            // 引擎也要馬上重掃:前端的 `config_load` 看到的受管檔指紋沒變,不會喚醒它 —— 在它重掃之前,app 內的存檔會拿整個 space 檔去比過期的快取(被外部清空的檔案會被規劃成
            // 刪除每一台主機)。
            env.events.wake();
        }
        listed.extend(check.block_names);
        if check.refused.len() == aliases.len() {
            report.failed.extend(check.refused);
            continue;
        }
        if rate_limited {
            fail_rate_limited(&mut report, aliases, check.refused);
            continue;
        }
        let space_id = match crate::sync::spaces::try_create_space(env, &group.name) {
            Ok(space_id) => space_id,
            Err(CreateError::RateLimited) => {
                rate_limited = true;
                fail_rate_limited(&mut report, aliases, check.refused);
                continue;
            }
            Err(CreateError::Other(e)) => {
                fail_all(&mut report, aliases, &e.to_string());
                continue;
            }
        };
        match move_hosts_into_space(env, active, aliases.clone(), &space_id, tag_by_file) {
            Ok(part) => {
                report.moved.extend(part.moved);
                report.failed.extend(part.failed);
                report.tagged += part.tagged;
            }
            Err(e) => fail_all(&mut report, aliases, &leftover_space_message(&group.name, &e)),
        }
    }
    Ok(report)
}

/// 搬移精靈列出的、不能搬進 space 的本機主機與原因(spec §7.2、§8):不在任何勾選 space 檔裡、所有 pattern 都具名,
/// 卻含 synced hosts 不能用的內容的區塊 —— `hosts_file::forbidden_directive` 擋的每一種:`Include`、帶引號的 keyword、以 `=`
/// 開頭的行、HostName / User / HostKeyAlias / ProxyJump 的值有 ssh 會交給 shell 的字元、不可見字元、OpenSSH 讀法與 SSHelter
/// 不同的 Host / Match 行。同一個 alias 定義在好幾個檔案時,只判斷搬移會拿的那一份(`block_to_move`:doc 裡第一個定義它的檔案),
/// 清單才和實際搬移一致。
pub fn unmovable_hosts(env: &SyncEnv) -> Result<Vec<MigrationFailure>, AppError> {
    let spaces: Vec<PathBuf> = selected_space_files(env.runtime, &env.ssh_dir).into_iter().map(|(_, p)| p).collect();
    let doc_lock = env.doc.lock().unwrap();
    let doc = doc_lock.as_ref().ok_or_else(|| AppError::Other("no config loaded".to_string()))?;
    let mut out = Vec::new();
    for file in doc.files.iter().filter(|f| !spaces.contains(&f.path)) {
        for item in &file.items {
            let Item::Host(h) = item else { continue };
            if !is_syncable_block(&h.patterns) {
                continue;
            }
            let Some(alias) = h.patterns.first() else { continue };
            let Some(forbidden) = forbidden_directive(std::slice::from_ref(item)) else { continue };
            if !block_to_move(doc, alias).is_some_and(|block| std::ptr::eq(block, item)) {
                continue;
            }
            out.push(MigrationFailure {
                alias: alias.clone(),
                error: format!("contains {}, which synced hosts cannot use", forbidden.describe()),
            });
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::include::load_doc;
    use crate::config::serialize::serialize_items;
    use crate::sync::state_v2::{SpaceState, SyncStateV2};

    /// 主 config Include 一個 space 檔;兩邊都有 `web`,主 config 另有 `local-only`。
    fn fixture() -> (tempfile::TempDir, PathBuf, PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let space = dir.path().join("work-3fa2c1d9.config");
        std::fs::write(&space, "Host web\n  HostName 1\nHost only-synced\n").unwrap();
        let main = dir.path().join("config");
        std::fs::write(&main, format!("Include {}\nHost web\n  HostName 2\nHost local-only\n", space.display())).unwrap();
        (dir, main, space)
    }

    #[test]
    fn tag_for_file_strips_extensions_and_normalizes() {
        assert_eq!(tag_for_file(Path::new("/h/.ssh/config.d/homelab.config")), "homelab");
        assert_eq!(tag_for_file(Path::new("/h/.ssh/config.d/Work Stuff.conf")), "work-stuff");
        assert_eq!(tag_for_file(Path::new("/h/.ssh/config")), "config");
    }

    #[test]
    fn shadowed_copies_are_every_other_definition_of_an_alias_a_space_file_wins() {
        let dir = tempfile::tempdir().unwrap();
        let (work, home) = (dir.path().join("work-3fa2c1d9.config"), dir.path().join("home-8b01e4aa.config"));
        std::fs::write(&work, "Host web\n  HostName 1\n").unwrap();
        std::fs::write(&home, "Host web\n  HostName 2\nHost db\n").unwrap();
        let main = dir.path().join("config");
        std::fs::write(&main, format!("Include {} {}\nHost web\nHost db\nHost lone\n", home.display(), work.display())).unwrap();
        let doc = load_doc(&main).unwrap();
        // Include 順序:home 在 work 前面 —— home 的 web 勝出,work 與主 config 的被遮蔽。
        let dups = duplicate_aliases(&doc, &[home.clone(), work.clone()]);
        let pairs: Vec<(String, String)> = dups.iter().map(|d| (d.alias.clone(), d.local_file.clone())).collect();
        assert!(pairs.contains(&("web".into(), work.to_string_lossy().into_owned())));
        assert!(pairs.contains(&("web".into(), main.to_string_lossy().into_owned())));
        assert!(pairs.contains(&("db".into(), main.to_string_lossy().into_owned())));
        assert_eq!(dups.len(), 3);
    }

    #[test]
    fn resolving_a_shadowed_host_never_touches_the_copy_ssh_uses() {
        let (_dir, main, space) = fixture();
        let main_str = main.to_string_lossy().into_owned();
        let spaces = vec![space.clone()];
        let mut doc = load_doc(&main).unwrap();
        let idx = resolve_shadowed(&mut doc, "web", &main_str, ShadowedAction::Rename, &spaces).unwrap();
        assert_eq!(idx, 0);
        let main_text = serialize_items(&doc.files[0].items, true);
        assert!(main_text.contains("Host web-local\n  HostName 2\n"));
        assert!(duplicate_aliases(&doc, &spaces).is_empty());
        let mut fresh = load_doc(&main).unwrap();
        assert!(resolve_shadowed(&mut fresh, "web", &space.to_string_lossy(), ShadowedAction::Remove, &spaces).is_err());
        assert_eq!(resolve_shadowed(&mut fresh, "web", &main_str, ShadowedAction::Remove, &spaces).unwrap(), 0);
        assert!(!serialize_items(&fresh.files[0].items, true).contains("Host web\n"));
        assert!(resolve_shadowed(&mut fresh, "ghost", &main_str, ShadowedAction::Remove, &spaces).is_err());
    }

    #[test]
    fn a_failed_shadow_resolution_reloads_the_doc_so_it_is_never_ahead_of_disk() {
        let (_dir, main, space) = fixture();
        let main_str = main.to_string_lossy().into_owned();
        let mut slot = Some(load_doc(&main).unwrap());
        let err = resolve_shadowed_and_persist(&mut slot, "web", &main_str, ShadowedAction::Rename, &[space], |_, _| {
            Err(AppError::Other("disk is full".to_string()))
        })
        .unwrap_err();
        assert_eq!(err.to_string(), "disk is full");
        let main_text = serialize_items(&slot.as_ref().unwrap().files[0].items, true);
        assert!(main_text.contains("Host web\n  HostName 2\n") && !main_text.contains("web-local"));
    }

    #[test]
    fn blocks_that_cannot_sync_are_refused_by_the_block_move_host_would_pick() {
        let dir = tempfile::tempdir().unwrap();
        let main = dir.path().join("config");
        std::fs::write(&main, "Host other web *.internal\n  User ops\nHost web\nHost jump\n  Include ~/.ssh/j.config\nHost db\n").unwrap();
        let doc = load_doc(&main).unwrap();
        assert!(refuse_wildcard(&doc, "web").is_err());
        assert!(refuse_wildcard(&doc, "db").is_ok());
        assert_eq!(
            refuse_forbidden(&doc, "jump").unwrap_err().to_string(),
            "host 'jump' contains an Include line, which synced hosts cannot use; keep it in a local file"
        );
        assert!(refuse_forbidden(&doc, "db").is_ok());
    }

    #[test]
    fn names_already_in_the_target_space_are_refused() {
        let dir = tempfile::tempdir().unwrap();
        let space = dir.path().join("work-3fa2c1d9.config");
        std::fs::write(&space, "Host web-1 web\nHost bastion\n").unwrap();
        let main = dir.path().join("config");
        std::fs::write(&main, format!("Include {}\nHost web\nHost bastion jump\nHost db\n", space.display())).unwrap();
        let doc = load_doc(&main).unwrap();
        assert_eq!(
            refuse_already_synced(&doc, &space, "web").unwrap_err().to_string(),
            "'web' is already used by a host in that space — remove or rename it in the local host 'web' first"
        );
        assert_eq!(
            refuse_already_synced(&doc, &space, "jump").unwrap_err().to_string(),
            "'bastion' is already in that space — resolve the duplicate instead"
        );
        assert!(refuse_already_synced(&doc, &space, "db").is_ok());
    }

    #[test]
    fn moving_into_a_space_refuses_what_cannot_sync_without_halting_the_batch() {
        let dir = tempfile::tempdir().unwrap();
        let space = dir.path().join("work-3fa2c1d9.config");
        std::fs::write(&space, "").unwrap();
        let homelab = dir.path().join("homelab.config");
        std::fs::write(&homelab, "Host b\n  HostName 2\n").unwrap();
        let main = dir.path().join("config");
        std::fs::write(
            &main,
            format!("Include {}\nInclude {}\nHost a\n  HostName 1\nHost jump\n  Include ~/.ssh/j.config\n", space.display(), homelab.display()),
        )
        .unwrap();
        let mut doc = load_doc(&main).unwrap();
        let mut backed_up = std::collections::HashSet::new();
        let (report, needs_reload) = migrate_hosts(
            &mut doc,
            vec!["a".into(), "jump".into(), "b".into()],
            true,
            &space.to_string_lossy(),
            |doc, idx| persist_file(doc, idx, &mut backed_up, None),
        );
        assert!(!needs_reload);
        assert_eq!(report.moved, vec!["a".to_string(), "b".to_string()]);
        assert_eq!(report.failed.len(), 1);
        assert!(report.failed[0].error.contains("Include"));
        assert_eq!(report.tagged, 1, "only the host from an included file is tagged");
        let synced = std::fs::read_to_string(&space).unwrap();
        assert!(synced.contains("Host a\n") && synced.contains("Host b\n") && !synced.contains("jump"));
    }

    #[test]
    fn a_persist_failure_halts_the_batch_and_flags_a_reload() {
        let dir = tempfile::tempdir().unwrap();
        let space = dir.path().join("work-3fa2c1d9.config");
        std::fs::write(&space, "").unwrap();
        let main = dir.path().join("config");
        std::fs::write(&main, format!("Include {}\nHost a\nHost b\nHost c\n", space.display())).unwrap();
        let mut doc = load_doc(&main).unwrap();
        let mut backed_up = std::collections::HashSet::new();
        let mut calls = 0u32;
        let (report, needs_reload) = migrate_hosts(&mut doc, vec!["a".into(), "b".into(), "c".into()], false, &space.to_string_lossy(), |doc, idx| {
            calls += 1;
            if calls == 3 {
                Err(AppError::Other("disk is full".to_string()))
            } else {
                persist_file(doc, idx, &mut backed_up, None)
            }
        });
        assert!(needs_reload);
        assert_eq!(report.moved, vec!["a".to_string()]);
        assert_eq!(report.failed[1].error, "not attempted: an earlier move failed");
    }

    #[test]
    fn moving_local_hosts_into_a_space_syncs_them_to_the_other_devices() {
        use crate::sync::account::{create_account, join_account};
        use crate::sync::fake_relay::FakeRelay;
        use crate::sync::round::tests::settle;
        use crate::sync::spaces::select_space;
        use crate::sync::testkit::{TestClock, TestDevice};
        let (relay, clock) = (FakeRelay::new(), TestClock::new());
        let a = TestDevice::with_main_config("a", &relay, &clock, "# main\nHost web\n  HostName 10.0.0.1\nHost jump\n  Include ~/.ssh/j.config\n");
        let words = create_account(&a.env(), "MacBook-A").unwrap();
        let personal = a.state().spaces.keys().next().unwrap().clone();
        assert!(move_hosts_into_space(&a.env(), false, vec!["web".into()], &personal, false).is_err(), "no engine in this process");
        let report = move_hosts_into_space(&a.env(), true, vec!["web".into(), "jump".into()], &personal, false).unwrap();
        assert_eq!(report.moved, vec!["web".to_string()]);
        assert!(report.failed[0].error.contains("Include"));
        assert_eq!(a.read(&a.space_path(&personal)).trim_end(), "Host web\n  HostName 10.0.0.1");
        assert!(!a.main_config().contains("Host web"));
        settle(&a);
        let b = TestDevice::new("b", &relay, &clock);
        join_account(&b.env(), &words, "MacBook-B").unwrap();
        select_space(&b.env(), &personal).unwrap();
        settle(&b);
        assert_eq!(b.read(&b.space_path(&personal)), "Host web\n  HostName 10.0.0.1\n");
    }

    /// 帳戶裡現有的 space 名稱(依 Include 清單的順序:名稱不分大小寫)。
    fn space_names(device: &crate::sync::testkit::TestDevice) -> Vec<String> {
        crate::sync::merge::space_entries(device.state().account.as_ref().unwrap()).into_iter().map(|e| e.name).collect()
    }

    fn space_id(device: &crate::sync::testkit::TestDevice, name: &str) -> String {
        crate::sync::merge::space_entries(device.state().account.as_ref().unwrap()).into_iter().find(|e| e.name == name).unwrap().id
    }

    /// 另一個編輯器在 app 外改了這個檔案(最後多一台主機):之後 app 寫它會撞到 `Conflict`。
    fn edit_elsewhere(path: &Path) {
        let mut text = std::fs::read_to_string(path).unwrap();
        text.push_str("Host edited-elsewhere\n  HostName 9.9.9.9\n");
        std::fs::write(path, text).unwrap();
    }

    /// 第 `on` 次 `applied` 之後執行 `act`(模擬 app 外發生的事),並數 `applied` 被呼叫了幾次。
    struct ActAfterApplied {
        on: usize,
        calls: std::sync::atomic::AtomicUsize,
        act: Box<dyn Fn() + Send + Sync>,
    }

    impl ActAfterApplied {
        fn new(on: usize, act: impl Fn() + Send + Sync + 'static) -> Self {
            Self { on, calls: std::sync::atomic::AtomicUsize::new(0), act: Box::new(act) }
        }

        fn calls(&self) -> usize {
            self.calls.load(std::sync::atomic::Ordering::SeqCst)
        }
    }

    impl crate::sync::env::SyncEvents for ActAfterApplied {
        fn status(&self) {}
        fn applied(&self, _hosts: usize) {
            if self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst) + 1 == self.on {
                (self.act)();
            }
        }
        fn conflict(&self, _conflicts: &[crate::sync::dto::SyncConflict]) {}
        fn approval(&self, _waiting: &[crate::sync::dto::ApprovalNotice]) {}
        fn notice(&self, _notice: &crate::sync::state_v2::SyncNotice) {}
        fn wake(&self) {}
    }

    #[test]
    fn one_space_per_source_file_creates_the_spaces_and_lists_what_cannot_move() {
        use crate::sync::account::create_account;
        use crate::sync::fake_relay::FakeRelay;
        use crate::sync::testkit::{TestClock, TestDevice};
        let (relay, clock) = (FakeRelay::new(), TestClock::new());
        // wildcard 區塊也帶一行 Include:`unmovable_hosts` 若不略過 wildcard,這個區塊就會被列出來。
        let a = TestDevice::with_main_config(
            "a",
            &relay,
            &clock,
            "# main\nInclude ~/.ssh/homelab.config\nHost web\nHost jump\n  Include ~/.ssh/j.config\nHost * !prod\n  Include z\nHost db\n",
        );
        std::fs::write(a.ssh_dir().join("homelab.config"), "Host nas\nHost pi\n").unwrap();
        a.reload();
        create_account(&a.env(), "MacBook-A").unwrap();
        let unmovable = unmovable_hosts(&a.env()).unwrap();
        assert_eq!(unmovable.len(), 1, "wildcard blocks are not hosts and are not listed");
        assert_eq!((unmovable[0].alias.as_str(), unmovable[0].error.as_str()), ("jump", "contains an Include line, which synced hosts cannot use"));
        // 這個行程沒有同步引擎:在建立任何 space 之前整批拒絕。
        let first = vec![NewSpaceGroup { name: "homelab".into(), aliases: vec!["nas".into()] }];
        assert_eq!(move_into_new_spaces(&a.env(), false, first, true).unwrap_err().to_string(), ANOTHER_ENGINE_MESSAGE);
        assert_eq!(space_names(&a), vec!["Personal".to_string()], "nothing is created without an engine");
        let groups = vec![
            NewSpaceGroup { name: "homelab".into(), aliases: vec!["nas".into(), "pi".into()] },
            NewSpaceGroup { name: "config".into(), aliases: vec!["web".into(), "jump".into()] },
            NewSpaceGroup { name: "Personal".into(), aliases: vec!["db".into()] },
        ];
        let report = move_into_new_spaces(&a.env(), true, groups, true).unwrap();
        assert_eq!(report.moved, vec!["nas".to_string(), "pi".to_string(), "web".to_string()]);
        assert_eq!(report.failed.iter().map(|f| f.alias.as_str()).collect::<Vec<_>>(), vec!["jump", "db"]);
        assert_eq!(report.failed[1].error, "a space named 'Personal' already exists");
        assert_eq!(report.tagged, 2, "hosts from an included file get its name as a tag");
        assert_eq!(space_names(&a), vec!["config".to_string(), "homelab".to_string(), "Personal".to_string()]);
        let text = a.read(&a.space_path(&space_id(&a, "homelab")));
        assert!(text.contains("Host nas") && text.contains("Host pi") && text.contains("#tags:homelab"), "{text}");
        assert_eq!(a.read(&a.ssh_dir().join("homelab.config")).trim(), "", "moved out of the source file");
        // `config`:web 搬進來了(它在主 config,不加 tag);jump 含 Include,留在主 config。
        let text = a.read(&a.space_path(&space_id(&a, "config")));
        assert!(text.contains("Host web") && !text.contains("jump"), "{text}");
        let main = a.main_config();
        assert!(main.contains("Host jump") && main.contains("Host db") && !main.contains("Host web"), "{main}");
    }

    #[test]
    fn a_group_that_fails_after_its_space_exists_never_stops_the_others() {
        use crate::sync::account::create_account;
        use crate::sync::fake_relay::FakeRelay;
        use crate::sync::testkit::{HookedConnector, Hooks, TestClock, TestDevice};
        let (relay, clock) = (FakeRelay::new(), TestClock::new());
        let a = TestDevice::with_main_config("a", &relay, &clock, "# main\nHost web\nHost db\nHost cache\n");
        create_account(&a.env(), "MacBook-A").unwrap();
        // 第一組建立 chain 的那一刻(檢查 doc 之後、寫 Include 之前),主 config 在 app 外被改了:新 space 的檔案列不進 Include。
        let main = a.main_path();
        let hooks = Hooks { before_create: Some(Box::new(move || edit_elsewhere(&main))), ..Hooks::default() };
        let connector = HookedConnector::new(&relay, hooks);
        let mut env = a.env();
        env.relays = &connector;
        let groups = vec![
            NewSpaceGroup { name: "one".into(), aliases: vec!["web".into()] },
            NewSpaceGroup { name: "two".into(), aliases: vec!["db".into()] },
            NewSpaceGroup { name: "three".into(), aliases: vec!["cache".into()] },
        ];
        let report = move_into_new_spaces(&env, true, groups, false).unwrap();
        // 第一組搬不進去:整組列為失敗,批次繼續。第二組之前的檢查發現 doc 比磁碟舊,整份重載,之後照常建立與搬移。重試同一個名稱只會得到「已經存在」,所以說明留下的空
        // space 叫什麼、請使用者把主機搬進它,不是叫他稍後再試。
        let not_loaded = "the space 'one' was created, but the hosts could not be moved into it (its file is not loaded yet) — move them into that space instead of creating it again";
        let failed: Vec<(&str, &str)> = report.failed.iter().map(|f| (f.alias.as_str(), f.error.as_str())).collect();
        assert_eq!(failed, vec![("web", not_loaded)]);
        assert_eq!(report.moved, vec!["db".to_string(), "cache".to_string()], "the later groups still run, on the reloaded doc");
        assert_eq!(space_names(&a), vec!["one".to_string(), "Personal".to_string(), "three".to_string(), "two".to_string()]);
        // 重載之後 Include 一次列進所有 space 檔(連第一組那個空的 `one`);`db`、`cache` 在各自的 space,`web` 還在主 config。
        let main = a.main_config();
        for name in ["one", "personal", "three", "two"] {
            assert!(main.contains(&format!("sshelter/{name}-")), "{name} is listed in the Include: {main}");
        }
        assert!(main.contains("Host web") && !main.contains("Host db") && !main.contains("Host cache"), "{main}");
        assert!(main.contains("Host edited-elsewhere"), "the outside edit is kept: {main}");
        assert_eq!(a.read(&a.space_path(&space_id(&a, "one"))).trim(), "", "the failed group's space stays empty");
        assert!(a.read(&a.space_path(&space_id(&a, "two"))).contains("Host db"));
        assert!(a.read(&a.space_path(&space_id(&a, "three"))).contains("Host cache"));
    }

    #[test]
    fn a_main_config_edited_outside_the_app_is_reloaded_before_each_group_creates_its_space() {
        use crate::sync::account::create_account;
        use crate::sync::fake_relay::FakeRelay;
        use crate::sync::testkit::{TestClock, TestDevice};
        let (relay, clock) = (FakeRelay::new(), TestClock::new());
        let a = TestDevice::with_main_config("a", &relay, &clock, "# main\nHost web\nHost db\nHost cache\n");
        create_account(&a.env(), "MacBook-A").unwrap();
        // 建立 space 與搬移各發一次 `applied`:第 2 次(第一組搬完)之後,主 config 在 app 外被改了。
        let main = a.main_path();
        let editor = ActAfterApplied::new(2, move || edit_elsewhere(&main));
        let mut env = a.env();
        env.events = &editor;
        let groups = vec![
            NewSpaceGroup { name: "one".into(), aliases: vec!["web".into()] },
            NewSpaceGroup { name: "two".into(), aliases: vec!["db".into()] },
            NewSpaceGroup { name: "three".into(), aliases: vec!["cache".into()] },
        ];
        let report = move_into_new_spaces(&env, true, groups, false).unwrap();
        assert_eq!(report.moved, vec!["web".to_string(), "db".to_string(), "cache".to_string()]);
        assert!(report.failed.is_empty(), "{:?}", report.failed.iter().map(|f| (&f.alias, &f.error)).collect::<Vec<_>>());
        assert_eq!(space_names(&a), vec!["one".to_string(), "Personal".to_string(), "three".to_string(), "two".to_string()]);
        for (space, host) in [("one", "Host web"), ("two", "Host db"), ("three", "Host cache")] {
            assert!(a.read(&a.space_path(&space_id(&a, space))).contains(host), "{space} holds its host");
        }
        let main = a.main_config();
        assert!(main.contains("Host edited-elsewhere") && !main.contains("Host web") && !main.contains("Host db"), "the outside edit is kept: {main}");
        // 每個 space 建立與搬移各發一次 `applied`(3 組 = 6);過時的那一組多一次:整份重載了 doc,前端要重新載入。
        assert_eq!(editor.calls(), 7);
    }

    #[test]
    fn a_config_that_cannot_be_reloaded_fails_the_remaining_groups_without_creating_spaces() {
        use crate::sync::account::create_account;
        use crate::sync::fake_relay::FakeRelay;
        use crate::sync::testkit::{TestClock, TestDevice};
        let (relay, clock) = (FakeRelay::new(), TestClock::new());
        let a = TestDevice::with_main_config("a", &relay, &clock, "# main\nHost web\nHost db\nHost cache\n");
        create_account(&a.env(), "MacBook-A").unwrap();
        // 第一組搬完之後,主 config 在 app 外被換成讀不了的內容(不是 UTF-8):doc 過時、又重載不了。
        let main = a.main_path();
        let editor = ActAfterApplied::new(2, move || std::fs::write(&main, [0xff, 0xfe, 0xfd]).unwrap());
        let mut env = a.env();
        env.events = &editor;
        let groups = vec![
            NewSpaceGroup { name: "one".into(), aliases: vec!["web".into()] },
            NewSpaceGroup { name: "two".into(), aliases: vec!["db".into()] },
            NewSpaceGroup { name: "three".into(), aliases: vec!["cache".into()] },
        ];
        let report = move_into_new_spaces(&env, true, groups, false).unwrap();
        assert_eq!(report.moved, vec!["web".to_string()], "the first group's result is kept");
        assert_eq!(report.failed.iter().map(|f| f.alias.as_str()).collect::<Vec<_>>(), vec!["db", "cache"]);
        for failure in &report.failed {
            assert!(failure.error.starts_with("the config changed on disk and could not be reloaded: "), "{}", failure.error);
        }
        assert_eq!(space_names(&a), vec!["one".to_string(), "Personal".to_string()], "no space is created for a group that cannot move");
        assert_eq!(editor.calls(), 2, "nothing was created or reloaded after the first group");
    }

    #[test]
    fn the_refusals_are_checked_again_on_the_reloaded_doc_before_a_space_is_created() {
        use crate::sync::account::create_account;
        use crate::sync::fake_relay::FakeRelay;
        use crate::sync::testkit::{TestClock, TestDevice};
        let (relay, clock) = (FakeRelay::new(), TestClock::new());
        let a = TestDevice::with_main_config("a", &relay, &clock, "# main\nHost web\nHost db\nHost cache\n");
        create_account(&a.env(), "MacBook-A").unwrap();
        // 第一組搬完之後,另一個編輯器把 `db` 從主 config 刪掉了:第二組在重載後的 doc 上找不到它,不建立 space。
        let main = a.main_path();
        let editor = ActAfterApplied::new(2, move || {
            let text = std::fs::read_to_string(&main).unwrap();
            std::fs::write(&main, text.replace("Host db\n", "")).unwrap();
        });
        let mut env = a.env();
        env.events = &editor;
        let groups = vec![
            NewSpaceGroup { name: "one".into(), aliases: vec!["web".into()] },
            NewSpaceGroup { name: "two".into(), aliases: vec!["db".into()] },
            NewSpaceGroup { name: "three".into(), aliases: vec!["cache".into()] },
        ];
        let report = move_into_new_spaces(&env, true, groups, false).unwrap();
        assert_eq!(report.moved, vec!["web".to_string(), "cache".to_string()]);
        let failed: Vec<(&str, &str)> = report.failed.iter().map(|f| (f.alias.as_str(), f.error.as_str())).collect();
        assert_eq!(failed, vec![("db", "not found: host 'db' not found")]);
        assert_eq!(space_names(&a), vec!["one".to_string(), "Personal".to_string(), "three".to_string()], "no space for `db`");
        // 前兩組各 2 次 `applied`(建立、搬移)、第二組只多一次(重載);被拒絕的那一組什麼都沒建立。
        assert_eq!(editor.calls(), 5);
    }

    #[test]
    fn a_doc_counts_as_drifted_when_any_file_changed_or_cannot_be_read() {
        let (_dir, main, space) = fixture();
        let original = std::fs::read_to_string(&space).unwrap();
        let doc = load_doc(&main).unwrap();
        assert!(!doc_drifted(&doc), "a freshly loaded doc matches the disk");
        std::fs::write(&space, "Host other\n").unwrap();
        assert!(doc_drifted(&doc), "an included file changed, the main config did not");
        std::fs::write(&space, &original).unwrap();
        assert!(!doc_drifted(&doc), "the check is about content, not about when the file was written");
        std::fs::remove_file(&space).unwrap();
        assert!(doc_drifted(&doc), "a vanished file");
        std::fs::create_dir(&space).unwrap();
        assert!(doc_drifted(&doc), "a file that cannot be read counts too");
    }

    #[test]
    fn no_space_is_created_while_no_config_is_loaded() {
        use crate::sync::account::create_account;
        use crate::sync::fake_relay::FakeRelay;
        use crate::sync::testkit::{TestClock, TestDevice};
        let (relay, clock) = (FakeRelay::new(), TestClock::new());
        let a = TestDevice::with_main_config("a", &relay, &clock, "# main\nHost web\n");
        create_account(&a.env(), "MacBook-A").unwrap();
        // 上一次重載失敗、doc 被作廢了:沒有 doc 可以檢查或搬,也就不建立 space(`Ok` 的報告,每一台都列為失敗)。
        *a.doc.lock().unwrap() = None;
        let groups = vec![NewSpaceGroup { name: "one".into(), aliases: vec!["web".into()] }];
        let report = move_into_new_spaces(&a.env(), true, groups, false).unwrap();
        assert!(report.moved.is_empty());
        let failed: Vec<(&str, &str)> = report.failed.iter().map(|f| (f.alias.as_str(), f.error.as_str())).collect();
        assert_eq!(failed, vec![("web", "no config loaded")]);
        assert_eq!(space_names(&a), vec!["Personal".to_string()]);
    }

    #[test]
    fn a_block_moved_for_one_of_its_names_is_not_moved_again_for_another() {
        use crate::sync::account::create_account;
        use crate::sync::fake_relay::FakeRelay;
        use crate::sync::testkit::{TestClock, TestDevice};
        let (relay, clock) = (FakeRelay::new(), TestClock::new());
        // 主 config 的 `Host a web` 與 homelab.config 的 `Host web`:精靈各列一台(`a`、`web`),但搬 `a` 搬走的是整個區塊,
        // 之後 doc 裡第一個定義 `web` 的就是剛搬進 space 的那個區塊 —— 不能再搬一次。
        let a = TestDevice::with_main_config("a", &relay, &clock, "# main\nInclude ~/.ssh/homelab.config\nHost a web\n  HostName 1\n");
        std::fs::write(a.ssh_dir().join("homelab.config"), "Host web\n  HostName 2\n").unwrap();
        a.reload();
        create_account(&a.env(), "MacBook-A").unwrap();
        let groups = vec![
            NewSpaceGroup { name: "g1".into(), aliases: vec!["a".into()] },
            NewSpaceGroup { name: "g2".into(), aliases: vec!["web".into()] },
        ];
        let report = move_into_new_spaces(&a.env(), true, groups, true).unwrap();
        assert_eq!(report.moved, vec!["a".to_string()], "the block moves once");
        let failed: Vec<(&str, &str)> = report.failed.iter().map(|f| (f.alias.as_str(), f.error.as_str())).collect();
        assert_eq!(failed, vec![("web", "listed in more than one group")]);
        assert_eq!(report.tagged, 0);
        // 報告說的就是檔案裡的:整個區塊在 g1、g2 不建立 space、homelab.config 自己的 `web` 沒動。
        assert_eq!(space_names(&a), vec!["g1".to_string(), "Personal".to_string()]);
        assert_eq!(a.read(&a.space_path(&space_id(&a, "g1"))).trim_end(), "Host a web\n  HostName 1");
        assert!(!a.main_config().contains("Host a web"));
        assert_eq!(a.read(&a.ssh_dir().join("homelab.config")), "Host web\n  HostName 2\n");
    }

    #[test]
    fn an_alias_listed_in_two_groups_is_moved_once_and_reported_once() {
        use crate::sync::account::create_account;
        use crate::sync::fake_relay::FakeRelay;
        use crate::sync::testkit::{TestClock, TestDevice};
        let (relay, clock) = (FakeRelay::new(), TestClock::new());
        // `web` 同時定義在主 config 與 homelab.config:兩個來源檔各建立一組,精靈就會把同一個 alias 送兩次。
        let a = TestDevice::with_main_config("a", &relay, &clock, "# main\nInclude ~/.ssh/homelab.config\nHost web\n  HostName 1\n");
        std::fs::write(a.ssh_dir().join("homelab.config"), "Host web\n  HostName 2\n").unwrap();
        a.reload();
        create_account(&a.env(), "MacBook-A").unwrap();
        let groups = vec![
            NewSpaceGroup { name: "homelab".into(), aliases: vec!["web".into()] },
            NewSpaceGroup { name: "config".into(), aliases: vec!["web".into()] },
        ];
        let report = move_into_new_spaces(&a.env(), true, groups, true).unwrap();
        assert_eq!(report.moved, vec!["web".to_string()], "the host moves once");
        let failed: Vec<(&str, &str)> = report.failed.iter().map(|f| (f.alias.as_str(), f.error.as_str())).collect();
        assert_eq!(failed, vec![("web", "listed in more than one group")]);
        assert_eq!(report.tagged, 0);
        // 報告說的就是檔案裡的:第一組拿到主 config 的那份、第二組不建立 space、homelab.config 自己的那份沒動。
        assert_eq!(space_names(&a), vec!["homelab".to_string(), "Personal".to_string()]);
        assert_eq!(a.read(&a.space_path(&space_id(&a, "homelab"))).trim_end(), "Host web\n  HostName 1");
        assert!(!a.main_config().contains("Host web"));
        assert_eq!(a.read(&a.ssh_dir().join("homelab.config")), "Host web\n  HostName 2\n");
    }

    #[test]
    fn a_group_with_nothing_to_move_creates_no_space() {
        use crate::sync::account::create_account;
        use crate::sync::fake_relay::FakeRelay;
        use crate::sync::testkit::{TestClock, TestDevice};
        let (relay, clock) = (FakeRelay::new(), TestClock::new());
        let a = TestDevice::with_main_config(
            "a",
            &relay,
            &clock,
            "# main\nHost web\nHost db\nHost jump\n  Include ~/.ssh/j.config\nHost shared *.internal\n",
        );
        create_account(&a.env(), "MacBook-A").unwrap();
        // `refused`:每一台都會被拒絕(含 Include、找不到、屬於 wildcard 區塊),不建立空的 space;`nothing` 沒有主機;`mixed` 有一台
        // 搬得動,建立 space,它的 `phantom` 由搬移本身拒絕 —— 訊息要和事先的檢查一樣。
        let groups = vec![
            NewSpaceGroup { name: "refused".into(), aliases: vec!["jump".into(), "ghost".into(), "shared".into()] },
            NewSpaceGroup { name: "nothing".into(), aliases: vec![] },
            NewSpaceGroup { name: "mixed".into(), aliases: vec!["db".into(), "phantom".into()] },
        ];
        let report = move_into_new_spaces(&a.env(), true, groups, false).unwrap();
        assert_eq!(report.moved, vec!["db".to_string()]);
        let failed: Vec<(&str, &str)> = report.failed.iter().map(|f| (f.alias.as_str(), f.error.as_str())).collect();
        assert_eq!(
            failed,
            vec![
                ("jump", "host 'jump' contains an Include line, which synced hosts cannot use; keep it in a local file"),
                ("ghost", "not found: host 'ghost' not found"),
                ("shared", "host 'shared' belongs to a block with wildcard patterns and cannot be synced"),
                ("phantom", "not found: host 'phantom' not found"),
            ]
        );
        assert_eq!(space_names(&a), vec!["mixed".to_string(), "Personal".to_string()], "only a group with something to move gets a space");
        assert!(a.main_config().contains("Host jump") && a.main_config().contains("Host web"));
    }

    #[test]
    fn the_unmovable_list_judges_the_block_the_move_would_take() {
        use crate::sync::account::create_account;
        use crate::sync::fake_relay::FakeRelay;
        use crate::sync::testkit::{TestClock, TestDevice};
        let (relay, clock) = (FakeRelay::new(), TestClock::new());
        // `dup` 同時定義在主 config(乾淨)與 homelab.config(含 Include):搬移拿 doc 裡第一個定義它的檔案,也就是主 config 那份。
        let a = TestDevice::with_main_config(
            "a",
            &relay,
            &clock,
            "# main\nInclude ~/.ssh/homelab.config\nHost dup\n  HostName 1\nHost jump\n  Include ~/.ssh/j.config\n",
        );
        std::fs::write(a.ssh_dir().join("homelab.config"), "Host dup\n  Include ~/.ssh/q.config\nHost ok\n").unwrap();
        a.reload();
        create_account(&a.env(), "MacBook-A").unwrap();
        // 已經在勾選的 space 檔裡的區塊不是本機主機:就算它違反規則也不列(同步引擎自己會暫停那個 space)。
        let personal = a.state().spaces.keys().next().unwrap().clone();
        a.write_externally(&a.space_path(&personal), "Host trapped\n  Include ~/.ssh/z.config\n");
        a.reload();
        let listed: Vec<String> = unmovable_hosts(&a.env()).unwrap().into_iter().map(|f| f.alias).collect();
        assert!(!listed.contains(&"trapped".to_string()), "a block already in a selected space file is not a local host");
        assert!(!listed.contains(&"dup".to_string()), "the Include copy of `dup` is not the one the move takes");
        assert_eq!(listed, vec!["jump".to_string()]);
        let groups = vec![NewSpaceGroup { name: "dups".into(), aliases: vec!["dup".into()] }];
        let report = move_into_new_spaces(&a.env(), true, groups, false).unwrap();
        assert_eq!((report.moved, report.failed.len()), (vec!["dup".to_string()], 0));
        assert_eq!(a.read(&a.space_path(&space_id(&a, "dups"))).trim_end(), "Host dup\n  HostName 1");
        assert!(a.read(&a.ssh_dir().join("homelab.config")).contains("Include"), "the copy with an Include stays in its local file");
    }

    // ── 最終修正 FW4 ──

    #[test]
    fn the_include_order_is_one_rule_for_the_list_the_account_and_the_moves() {
        use crate::sync::merge::{put_account_record, selected_include_tokens, space_entries};
        use crate::sync::record::{RecordKind, SpacePayload};
        use crate::sync::space_files::{slugify, space_file_name};
        use crate::sync::state_v2::AccountState;
        // 名稱的順序和 id 的順序相反(`Zeta` 3fa2… < `Alpha` 8b01… 是 id 的順序,名稱的順序卻是 `Alpha` 先);`apple` / `Banana` 大小寫不同(原字串比,`Banana` 在 `apple` 前面;不分大小寫則反過來);
        // 兩個 `Dup` 名稱相同,只能靠 id。
        let spaces = [("Zeta", "3fa2c1d9"), ("Alpha", "8b01e4aa"), ("Banana", "1c2d3e4f"), ("apple", "9a8b7c6d"), ("Dup", "bbbbbbbb"), ("Dup", "aaaaaaaa")];
        let mut account = AccountState::new(&"c".repeat(64));
        let mut state = SyncStateV2::fresh("Box").unwrap();
        for (name, prefix) in spaces {
            let id = prefix.repeat(8);
            let payload = SpacePayload { schema: 1, name: name.into(), slug: slugify(name), created_at_ms: 1, previous_id: None };
            put_account_record(&mut account, RecordKind::Space, &id, serde_json::to_value(payload).unwrap(), false, "dev-a", 1);
            state.spaces.insert(id.clone(), SpaceState::new(&space_file_name(&slugify(name), &id).unwrap()));
        }
        let expected: Vec<String> = ["8b01e4aa", "9a8b7c6d", "1c2d3e4f", "aaaaaaaa", "bbbbbbbb", "3fa2c1d9"].iter().map(|p| p.to_string()).collect();
        // 主 config 的 Include 清單(ensure_include 寫的順序)。
        let tokens = selected_include_tokens(Some(&account), &state.spaces).unwrap();
        let token_ids: Vec<String> = tokens.iter().map(|t| t.rsplit('-').next().unwrap().trim_end_matches(".config").to_string()).collect();
        assert_eq!(token_ids, expected, "the Include list");
        // 搬移看到的 space 檔順序:同一個順序 —— 精靈與拖曳說的「前面那個 space」就是 ssh 先讀的那個。
        state.account = Some(account.clone());
        let runtime = SyncRuntime::default();
        runtime.core.lock().unwrap().state = Some(state);
        let files = selected_space_files(&runtime, Path::new("/home/f/.ssh"));
        let file_ids: Vec<String> = files.iter().map(|(id, _)| id[..8].to_string()).collect();
        assert_eq!(file_ids, expected, "the order the moves see the space files in");
        let file_tokens: Vec<String> = files.iter().map(|(_, p)| format!("~/.ssh/sshelter/{}", p.file_name().unwrap().to_string_lossy())).collect();
        assert_eq!(file_tokens, tokens, "the same files, in the same order, as the Include list");
        // 帳戶裡 space 的列出也是。
        let listed: Vec<String> = space_entries(&account).into_iter().map(|e| e.id[..8].to_string()).collect();
        assert_eq!(listed, expected, "the account's listing");
    }

    #[test]
    fn the_drag_and_the_wizard_refuse_the_same_moves_for_the_same_reasons() {
        let dir = tempfile::tempdir().unwrap();
        let space = dir.path().join("work-3fa2c1d9.config");
        std::fs::write(&space, "Host taken\n").unwrap();
        let main = dir.path().join("config");
        std::fs::write(
            &main,
            format!("Include {}\nHost db\nHost jump\n  Include ~/.ssh/j.config\nHost shared *.internal\nHost taken\n  HostName 1\n", space.display()),
        )
        .unwrap();
        let doc = load_doc(&main).unwrap();
        let id = "3fa2c1d9".repeat(8);
        let ready = runtime_with(&id, true);
        let drag = |alias: &str| refuse_move_into_space(&doc, &ready, true, &id, &space, alias).map_err(|e| e.to_string());
        // 搬得動的:不拒絕。
        assert!(drag("db").is_ok());
        // `Include`、wildcard、重複(目標檔已經定義了它)。
        assert_eq!(drag("jump").unwrap_err(), "host 'jump' contains an Include line, which synced hosts cannot use; keep it in a local file");
        assert_eq!(drag("shared").unwrap_err(), "host 'shared' belongs to a block with wildcard patterns and cannot be synced");
        assert_eq!(drag("taken").unwrap_err(), "'taken' is already in that space — resolve the duplicate instead");
        // 目標 space 第一輪還沒完成、這個行程沒有同步引擎:整批共通的拒絕,先於這一台的。
        let fresh = runtime_with(&id, false);
        assert_eq!(refuse_move_into_space(&doc, &fresh, true, &id, &space, "db").unwrap_err().to_string(), WAIT_FOR_FIRST_SYNC);
        assert_eq!(refuse_move_into_space(&doc, &ready, false, &id, &space, "db").unwrap_err().to_string(), ANOTHER_ENGINE_MESSAGE);
        assert_eq!(refuse_move_into_space(&doc, &fresh, false, &id, &space, "jump").unwrap_err().to_string(), ANOTHER_ENGINE_MESSAGE, "the batch rules come first");
        // 搬移精靈的批次搬移用同一套規則:每一台被拒絕的原因和拖曳一字不差。
        let mut wizard_doc = load_doc(&main).unwrap();
        let mut backed_up = HashSet::new();
        let aliases: Vec<String> = ["jump", "shared", "taken", "db"].iter().map(|a| a.to_string()).collect();
        let (report, _) = migrate_hosts(&mut wizard_doc, aliases, false, &space.to_string_lossy(), |d, i| persist_file(d, i, &mut backed_up, None));
        assert_eq!(report.moved, vec!["db".to_string()]);
        let from_wizard: Vec<(String, String)> = report.failed.iter().map(|f| (f.alias.clone(), f.error.clone())).collect();
        let from_drag: Vec<(String, String)> = ["jump", "shared", "taken"].iter().map(|a| (a.to_string(), drag(a).unwrap_err())).collect();
        assert_eq!(from_wizard, from_drag);
    }

    #[test]
    fn a_second_name_of_a_block_that_is_already_in_the_space_says_so_instead_of_blaming_a_local_host() {
        let dir = tempfile::tempdir().unwrap();
        let space = dir.path().join("work-3fa2c1d9.config");
        std::fs::write(&space, "").unwrap();
        let main = dir.path().join("config");
        std::fs::write(&main, format!("Include {}\nHost a web\n  HostName 1\n", space.display())).unwrap();
        let mut doc = load_doc(&main).unwrap();
        let mut backed_up = HashSet::new();
        // 一組裡列了同一個區塊的兩個名字:`a` 搬走整個區塊,`web` 就是剛搬進去的那個區塊的另一個名字,不是「本機主機 a 要先改名」。
        let (report, _) = migrate_hosts(&mut doc, vec!["a".into(), "web".into()], false, &space.to_string_lossy(), |d, i| persist_file(d, i, &mut backed_up, None));
        assert_eq!(report.moved, vec!["a".to_string()]);
        let failed: Vec<(&str, &str)> = report.failed.iter().map(|f| (f.alias.as_str(), f.error.as_str())).collect();
        assert_eq!(failed, vec![("web", "'web' is already in that space — it is another name of the host 'a'")]);
        // 同一個名字列了兩次:一樣說它已經在那裡。
        let (again, _) = migrate_hosts(&mut doc, vec!["a".into()], false, &space.to_string_lossy(), |d, i| persist_file(d, i, &mut backed_up, None));
        assert_eq!(again.failed[0].error, "'a' is already in that space");
    }

    #[test]
    fn a_failed_tag_write_is_reported_with_its_cause_and_stops_the_batch() {
        let dir = tempfile::tempdir().unwrap();
        let space = dir.path().join("work-3fa2c1d9.config");
        std::fs::write(&space, "").unwrap();
        let homelab = dir.path().join("homelab.config");
        std::fs::write(&homelab, "Host a\nHost b\n").unwrap();
        let main = dir.path().join("config");
        std::fs::write(&main, format!("Include {}\nInclude {}\n", space.display(), homelab.display())).unwrap();
        let mut doc = load_doc(&main).unwrap();
        let mut backed_up = HashSet::new();
        let mut calls = 0u32;
        // 搬 `a`:目標、來源寫好了(第 1、2 次),寫 tag 的那一次(第 3 次)失敗。
        let (report, needs_reload) = migrate_hosts(&mut doc, vec!["a".into(), "b".into()], true, &space.to_string_lossy(), |d, i| {
            calls += 1;
            if calls == 3 {
                Err(AppError::Other("disk is full".to_string()))
            } else {
                persist_file(d, i, &mut backed_up, None)
            }
        });
        assert!(needs_reload);
        // 這台只列一次(搬過去了,只有 tag 沒寫成);原因不再丟掉;後面的主機不再嘗試。
        assert!(report.moved.is_empty() && report.tagged == 0);
        let failed: Vec<(&str, &str)> = report.failed.iter().map(|f| (f.alias.as_str(), f.error.as_str())).collect();
        assert_eq!(failed, vec![("a", "moved, but its tag could not be saved: disk is full"), ("b", "not attempted: an earlier move failed")]);
        assert!(std::fs::read_to_string(&space).unwrap().contains("Host a"), "the host really moved");
    }

    #[test]
    fn a_stale_doc_reload_before_a_group_also_wakes_the_engine() {
        use crate::sync::account::create_account;
        use crate::sync::fake_relay::FakeRelay;
        use crate::sync::testkit::{TestClock, TestDevice};
        let (relay, clock) = (FakeRelay::new(), TestClock::new());
        let a = TestDevice::with_main_config("a", &relay, &clock, "# main\nHost jump\n  Include ~/.ssh/j.config\n");
        create_account(&a.env(), "MacBook-A").unwrap();
        let personal = a.state().spaces.keys().next().unwrap().clone();
        // 勾選的 space 檔在 app 外被改了(例如被外部工具清空):doc 過時了。唯一的一組全部被拒絕,所以沒有建立 space、也沒有搬移來喚醒引擎。
        a.write_externally(&a.space_path(&personal), "Host sneaked-in\n");
        let (applied, wakes) = (a.events.applied.lock().unwrap().len(), a.events.wakes());
        let groups = vec![NewSpaceGroup { name: "one".into(), aliases: vec!["jump".into()] }];
        let report = move_into_new_spaces(&a.env(), true, groups, false).unwrap();
        assert!(report.moved.is_empty() && report.failed.len() == 1);
        assert_eq!(space_names(&a), vec!["Personal".to_string()], "no space was created");
        // 整份重載了 doc:前端要重新載入,引擎也要馬上重掃 —— 前端重載時受管檔的指紋沒變,不會喚醒它;在重掃之前,app 內的存檔會拿整個檔案去比過期的快取。
        assert_eq!(a.events.applied.lock().unwrap().len(), applied + 1);
        assert_eq!(a.events.wakes(), wakes + 1, "the engine is woken beside the front end's reload");
    }

    #[test]
    fn a_rate_limited_create_stops_the_batch_without_asking_the_relay_again() {
        use crate::sync::account::create_account;
        use crate::sync::fake_relay::FakeRelay;
        use crate::sync::testkit::{TestClock, TestDevice};
        let (relay, clock) = (FakeRelay::new(), TestClock::new());
        let main = "# main\nHost x\n  HostName 1\nHost y\n  HostName 2\nHost z\n  HostName 3\nHost jump\n  Include ~/.ssh/j.config\nHost jump2\n  Include ~/.ssh/k.config\n";
        let a = TestDevice::with_main_config("a", &relay, &clock, main);
        create_account(&a.env(), "MacBook-A").unwrap();
        relay.fail_creates_with_429(10);
        relay.clear_calls();
        let groups = vec![
            NewSpaceGroup { name: "One".into(), aliases: vec!["x".into()] },
            NewSpaceGroup { name: "Two".into(), aliases: vec!["jump".into(), "y".into()] },
            NewSpaceGroup { name: "Three".into(), aliases: vec!["z".into()] },
            NewSpaceGroup { name: "Four".into(), aliases: vec!["jump2".into()] },
        ];
        let report = move_into_new_spaces(&a.env(), true, groups, false).unwrap();
        // 第一個 429 之後不再對 relay 送出建立(以前每一組都送一次,每一次都白算進每 IP 每小時 20 次的額度)。
        let creates = relay.calls().iter().filter(|c| c.starts_with("create:")).count();
        assert_eq!(creates, 1, "{:?}", relay.calls());
        let hour = "the relay is rate-limiting new spaces from this network, so no more are created now; try again in about an hour";
        let failed: Vec<(&str, &str)> = report.failed.iter().map(|f| (f.alias.as_str(), f.error.as_str())).collect();
        assert_eq!(
            failed,
            vec![
                ("x", hour),
                // 事先就會被拒絕的主機照自己的原因列出(重試也不會變);其餘等一小時。
                ("jump", "host 'jump' contains an Include line, which synced hosts cannot use; keep it in a local file"),
                ("y", hour),
                ("z", hour),
                ("jump2", "host 'jump2' contains an Include line, which synced hosts cannot use; keep it in a local file"),
            ]
        );
        assert!(report.moved.is_empty() && report.tagged == 0);
        assert_eq!(space_names(&a), vec!["Personal".to_string()], "no space was created");
        assert!(a.main_config().contains("Host x") && a.main_config().contains("Host z"), "nothing moved");
        // 其他地方建立 space 還是照舊回 relay 的訊息。
        assert_eq!(crate::sync::spaces::create_space(&a.env(), "Solo").unwrap_err().to_string(), "the relay is rate-limiting this device; try again later");
    }

    fn runtime_with(space_id: &str, baseline: bool) -> SyncRuntime {
        let runtime = SyncRuntime::default();
        let mut s = SyncStateV2::fresh("Box").unwrap();
        s.account = Some(crate::sync::state_v2::AccountState::new(&"a".repeat(64)));
        let mut space = SpaceState::new(&format!("work-{}.config", &space_id[..8]));
        space.baseline_established = baseline;
        s.spaces.insert(space_id.to_string(), space);
        runtime.core.lock().unwrap().state = Some(s);
        runtime
    }

    #[test]
    fn moves_into_a_space_need_this_process_engine_and_a_finished_first_sync() {
        let id = "3fa2c1d9".repeat(8);
        let runtime = runtime_with(&id, false);
        assert_eq!(refuse_while_sync_inactive(false, &runtime).unwrap_err().to_string(), ANOTHER_ENGINE_MESSAGE);
        runtime.core.lock().unwrap().save_blocked = Some("sync is off in this SSHelter process: boom".into());
        assert_eq!(refuse_while_sync_inactive(false, &runtime).unwrap_err().to_string(), "sync is off in this SSHelter process: boom");
        assert!(refuse_while_sync_inactive(true, &runtime).is_ok());
        assert_eq!(refuse_before_first_sync(&runtime, &id).unwrap_err().to_string(), WAIT_FOR_FIRST_SYNC);
        assert!(refuse_before_first_sync(&runtime_with(&id, true), &id).is_ok());
        let files = selected_space_files(&runtime, Path::new("/home/f/.ssh"));
        assert_eq!(files, vec![(id.clone(), PathBuf::from("/home/f/.ssh/sshelter/work-3fa2c1d9.config"))]);
    }
}
