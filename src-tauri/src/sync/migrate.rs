//! 既有主機遷入受管同步檔(spec §10):批次 move + 以原檔名上 tag;加入 chain 後「同步檔與本地同名
//! 主機」的偵測;以及**以檔案路徑定位**的處理(既有 `config_rename_host`/`config_remove_host`
//! 以第一個命中為準,會依 Include 順序誤中同步檔那份,不能用)。

use std::path::Path;

use serde::{Deserialize, Serialize};
use tauri::{AppHandle, Manager};

use crate::config::commands::{load_doc_migrated, move_host, persist_file, validate_host_patterns};
use crate::config::dto::parse_tags;
use crate::config::edit::{find_host_mut, set_host_patterns, set_tags};
use crate::config::include::find_host_file_index;
use crate::config::model::{Item, SshConfigDoc};
use crate::error::AppError;
use crate::state::AppState;
use crate::sync::engine::{SyncRuntime, ANOTHER_ENGINE_MESSAGE};
use crate::sync::hosts_file::{first_alias, is_syncable_block};

/// 剛 Join、基線輪還沒跑完時搬進同步檔的拒絕訊息(遷移精靈整批拒絕、sidebar 拖曳只在目標是同步檔時拒絕)。
pub const WAIT_FOR_FIRST_SYNC: &str = "wait for the first sync to finish before moving hosts into sync";

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(test, derive(ts_rs::TS))]
#[cfg_attr(test, ts(export, export_to = "../../src/bindings/"))]
pub struct DuplicateAlias {
    pub alias: String,
    pub local_file: String,
}

#[derive(Clone, Copy, Debug, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ShadowedAction {
    /// 本地那份改名 `<alias>-local`(保留本地定義)。
    Rename,
    /// 移除本地那份(改用同步版)。
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
    let stem = path
        .file_name()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_default();
    let stem = stem
        .strip_suffix(".config")
        .or_else(|| stem.strip_suffix(".conf"))
        .unwrap_or(&stem)
        .to_lowercase();
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

/// 遷入前的資格檢查,用**與 `move_host` 相同的定位規則**(`find_host_file_index` → 該檔案裡「任一 pattern
/// 相符」的第一個區塊):那個區塊的所有 pattern 都必須具名。找不到 alias 交給 `move_host` 回報。
pub fn refuse_wildcard(doc: &SshConfigDoc, alias: &str) -> Result<(), AppError> {
    let Some(idx) = find_host_file_index(doc, alias) else { return Ok(()) };
    let block = doc.files[idx]
        .items
        .iter()
        .find(|i| matches!(i, Item::Host(h) if h.patterns.iter().any(|p| p == alias)));
    match block {
        Some(Item::Host(h)) if !is_syncable_block(&h.patterns) => Err(AppError::Other(format!(
            "host '{alias}' belongs to a block with wildcard patterns and cannot be synced"
        ))),
        _ => Ok(()),
    }
}

/// 同步檔裡已有 Host 區塊定義了 `name`(該區塊任一 pattern 等於它)。
pub fn managed_defines(doc: &SshConfigDoc, managed: &Path, name: &str) -> bool {
    doc.files
        .iter()
        .filter(|f| f.path == managed)
        .flat_map(|f| f.items.iter())
        .any(|i| matches!(i, Item::Host(h) if h.patterns.iter().any(|p| p == name)))
}

/// 搬進同步檔之前的重複檢查(遷移精靈與 sidebar 拖進 Synced 群組共用)。同步檔已經定義了這個 alias —— 例如
/// 加入 chain 時本地就有同名主機 —— 再搬一份進去,同步檔就違反「alias 不重複」的不變式
/// (`check_managed_items`),整條同步停在讀檔階段;基線輪之前搬進去,還會被基線輪直接蓋掉。本地那份要用
/// 遮蔽面板改名或移除。`move_host` 搬的是整個區塊,所以檢查的是那個區塊的**每一個** pattern:任一個已經是
/// 同步檔裡某個 Host 區塊的 pattern 就拒絕(同步檔有 `Host a shared` 時,搬進 `Host b shared` 會留下兩個都
/// 符合 `shared` 的同步區塊)。訊息點名撞到的那個 pattern(請求的名字本身撞到時優先點名它)。
/// 不變式本身(`check_managed_items`)刻意只看第一個 alias(記錄的 key):別台裝置同步過來的區塊可以合法地
/// 共用次要名稱,收緊它會讓那些 chain 整條停下 —— 這裡只擋「從本機搬進去」這個動作。
pub fn refuse_already_synced(doc: &SshConfigDoc, managed: &Path, alias: &str) -> Result<(), AppError> {
    // 與 `move_host` 相同的定位規則:`find_host_file_index` → 該檔案裡「任一 pattern 相符」的第一個區塊。
    // 找不到就只剩請求的名字可查(`move_host` 自己會回報找不到)。
    let moving: &[String] = find_host_file_index(doc, alias)
        .and_then(|idx| {
            doc.files[idx].items.iter().find_map(|i| match i {
                Item::Host(h) if h.patterns.iter().any(|p| p == alias) => Some(h.patterns.as_slice()),
                _ => None,
            })
        })
        .unwrap_or_default();
    for name in std::iter::once(alias).chain(moving.iter().map(String::as_str)) {
        if managed_defines(doc, managed, name) {
            return Err(AppError::Other(format!("'{name}' is already in the synced file — resolve the duplicate instead")));
        }
    }
    Ok(())
}

/// 這個行程沒有跑同步引擎(拿不到同步鎖,`engine::engine_active()` 為 false)時,拒絕任何「搬進同步檔」的動作。
/// 這種行程的同步狀態是啟動時讀到的快照:`refuse_before_first_sync` 看的是過期資料(例如另一個行程剛重新
/// Join、基線輪還沒跑完)。訊息沿用這個行程的 `save_blocked`:別的行程持有鎖時正是 `ANOTHER_ENGINE_MESSAGE`;
/// 鎖因其他錯誤取不到時是那段說明,與 Sync 面板顯示的一致。沒有記下原因(單元測試)時退回
/// `ANOTHER_ENGINE_MESSAGE`。同步檔的其他編輯照常允許:對跑著引擎的那個行程而言就是外部編輯。
/// 呼叫端可能持有 doc(與 backed_up)鎖,這裡只短暫拿 core 鎖(鎖順序 doc → backed_up → core)。
pub fn refuse_while_sync_inactive(active: bool, sync: &SyncRuntime) -> Result<(), AppError> {
    if active {
        return Ok(());
    }
    let reason = sync.core.lock().unwrap().save_blocked.clone();
    Err(AppError::Other(reason.unwrap_or_else(|| ANOTHER_ENGINE_MESSAGE.to_string())))
}

/// 加入中、基線輪還沒跑完(剛 Join)就拒絕搬進同步檔:這時搬進去的主機會被基線輪以 chain 為準直接覆蓋(不算
/// 衝突、不通知)。呼叫端持有 doc(與 backed_up)鎖,這裡只短暫拿 core 鎖(鎖順序 doc → backed_up → core)。
pub fn refuse_before_first_sync(sync: &SyncRuntime) -> Result<(), AppError> {
    let pending = sync.core.lock().unwrap().state.as_ref().is_some_and(|s| s.joined() && !s.baseline_established);
    if pending {
        return Err(AppError::Other(WAIT_FOR_FIRST_SYNC.to_string()));
    }
    Ok(())
}

/// 同步檔與其他任何檔案都定義了的 alias(Include 置頂 → 同步檔那份的選項優先,本地那份仍會補上其餘選項)。
pub fn duplicate_aliases(doc: &SshConfigDoc, managed: &Path) -> Vec<DuplicateAlias> {
    let synced: Vec<&str> = doc
        .files
        .iter()
        .filter(|f| f.path == managed)
        .flat_map(|f| f.items.iter())
        .filter_map(first_alias)
        .collect();
    let mut out = Vec::new();
    for file in doc.files.iter().filter(|f| f.path != managed) {
        for alias in file.items.iter().filter_map(first_alias) {
            if synced.contains(&alias) {
                out.push(DuplicateAlias { alias: alias.to_string(), local_file: file.path.to_string_lossy().into_owned() });
            }
        }
    }
    out
}

/// 處理一筆被遮蔽的本地主機:以 `file`(完整路徑)定位那個檔案裡第一個 pattern 等於 `alias` 的
/// 區塊。回傳改動的檔案索引(呼叫端負責 `persist_file`)。拒絕碰同步檔那份。
pub fn resolve_shadowed(
    doc: &mut SshConfigDoc,
    alias: &str,
    file: &str,
    action: ShadowedAction,
    managed: &Path,
) -> Result<usize, AppError> {
    let idx = doc
        .files
        .iter()
        .position(|f| f.path.to_string_lossy() == file)
        .ok_or_else(|| AppError::NotFound(format!("file '{file}' is not loaded")))?;
    if doc.files[idx].path == managed {
        return Err(AppError::Other("refusing to change the synced copy; pick the local file".to_string()));
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

fn managed_path() -> Result<std::path::PathBuf, AppError> {
    Ok(crate::sync::hosts_file::managed_path(&crate::keys::ssh_dir()?))
}

/// 換代/寫檔都在 `spawn_blocking` 裡跑(與 Task 3 的 sync commands 同一形狀):command 本體不在主執行緒上
/// 等 doc 鎖或碰磁碟。`join_error` 來自 `sync::engine`,不重複定義。
#[tauri::command]
pub async fn sync_duplicate_aliases(app: AppHandle) -> Result<Vec<DuplicateAlias>, AppError> {
    let handle = app.clone();
    tauri::async_runtime::spawn_blocking(move || {
        let managed = managed_path()?;
        let state = handle.state::<AppState>();
        let guard = state.doc.lock().unwrap();
        let doc = guard.as_ref().ok_or_else(|| AppError::Other("no config loaded".to_string()))?;
        Ok(duplicate_aliases(doc, &managed))
    })
    .await
    .map_err(crate::sync::engine::join_error)?
}

#[tauri::command]
pub async fn sync_resolve_shadowed(app: AppHandle, alias: String, file: String, action: ShadowedAction) -> Result<Vec<DuplicateAlias>, AppError> {
    let handle = app.clone();
    tauri::async_runtime::spawn_blocking(move || {
        let managed = managed_path()?;
        let state = handle.state::<AppState>();
        let mut doc_lock = state.doc.lock().unwrap();
        let mut backed_up = state.backed_up.lock().unwrap();
        let retention = *state.backup_retention.lock().unwrap();
        resolve_shadowed_and_persist(&mut doc_lock, &alias, &file, action, &managed, |doc, idx| {
            persist_file(doc, idx, &mut backed_up, retention)
        })
    })
    .await
    .map_err(crate::sync::engine::join_error)?
}

/// `sync_resolve_shadowed` 的改動與寫檔(`persist` 由呼叫端注入,測試可模擬寫入失敗)。`resolve_shadowed`
/// 拒絕時什麼都沒改;寫入失敗時區塊已經在 in-memory doc 裡改名/移除、磁碟上卻沒有 —— doc 比磁碟新,之後任何
/// 一次成功的寫入(含同步引擎)都會把這個「失敗」的改動寫下去。所以從磁碟重載主 config(改動前記下的路徑)讓
/// 兩邊一致,重載也失敗就整份作廢(`None`),再回傳原本的錯誤 —— 同 `config_move_host` 的
/// `move_host_and_persist`。
fn resolve_shadowed_and_persist(
    slot: &mut Option<SshConfigDoc>,
    alias: &str,
    file: &str,
    action: ShadowedAction,
    managed: &Path,
    mut persist: impl FnMut(&mut SshConfigDoc, usize) -> Result<(), AppError>,
) -> Result<Vec<DuplicateAlias>, AppError> {
    let doc = slot.as_mut().ok_or_else(|| AppError::Other("no config loaded".to_string()))?;
    let main_path = doc.files[0].path.clone();
    let idx = resolve_shadowed(doc, alias, file, action, managed)?;
    if let Err(e) = persist(doc, idx) {
        *slot = load_doc_migrated(&main_path).ok();
        return Err(e);
    }
    Ok(duplicate_aliases(doc, managed))
}

/// 批次遷入的核心迴圈:不依賴 AppHandle,可直接單元測試。`persist` 由呼叫端注入(command 版是真的
/// `persist_file`,測試版能在第 N 次呼叫時模擬失敗)。`move_host` 先改 doc、才寫檔:target、source、
/// tag 三個寫入之中任一失敗,in-memory doc 就可能已經比磁碟新(半套用的搬移)—— 一律停止整批,不再
/// 嘗試後面的 alias,回傳的旗標請呼叫端從磁碟重載讓兩邊回到一致。target 與 source 都已落盤的那台
/// 算 `moved`,即使接下來的 tag 寫入才失敗。搬移前就拒絕的(wildcard、同步檔已有同名)doc 沒動過,不停批次。
/// `tag_by_file` 只替 Include 進來的檔案上 tag:主 config(`doc.files[0]`)的 tag 永遠是 "config",只是雜訊。
fn migrate_hosts(
    doc: &mut SshConfigDoc,
    aliases: Vec<String>,
    tag_by_file: bool,
    managed_str: &str,
    mut persist: impl FnMut(&mut SshConfigDoc, usize) -> Result<(), AppError>,
) -> (MigrationReport, bool) {
    let mut report = MigrationReport { moved: Vec::new(), failed: Vec::new(), tagged: 0 };
    let mut halted = false;
    for alias in aliases {
        if halted {
            report.failed.push(MigrationFailure {
                alias,
                error: "not attempted: an earlier move failed".to_string(),
            });
            continue;
        }
        if let Err(e) = refuse_wildcard(doc, &alias) {
            report.failed.push(MigrationFailure { alias, error: e.to_string() });
            continue;
        }
        if let Err(e) = refuse_already_synced(doc, Path::new(managed_str), &alias) {
            report.failed.push(MigrationFailure { alias, error: e.to_string() });
            continue;
        }
        let source_tag = find_host_file_index(doc, &alias)
            .filter(|&i| i != 0)
            .map(|i| tag_for_file(&doc.files[i].path));
        match move_host(doc, &alias, managed_str) {
            Ok((src, tgt)) => {
                if let Err(e) = persist(doc, tgt).and_then(|_| persist(doc, src)) {
                    report.failed.push(MigrationFailure { alias, error: e.to_string() });
                    halted = true;
                    continue;
                }
                if let (true, Some(tag)) = (tag_by_file, source_tag) {
                    // 先讀搬進去那個區塊自己的 tags(可變借用在這行結束),再取可變借用寫回:
                    // 兩段借用不重疊,才不會 E0502;也不用 host_summaries(它取第一個命中,遮蔽時會錯)。
                    let mut tags = find_host_mut(&mut doc.files[tgt].items, &alias)
                        .map(|h| parse_tags(&h.body))
                        .unwrap_or_default();
                    if !tags.contains(&tag) {
                        tags.push(tag);
                        if let Some(host) = find_host_mut(&mut doc.files[tgt].items, &alias) {
                            set_tags(host, &tags);
                        }
                        // target/source 都已落盤,這台已經算搬移成功;tag 只是第三次(錦上添花的)寫入 ——
                        // 失敗一樣要停批次交給呼叫端重載,但不能反悔剛剛判定的 `moved`。
                        match persist(doc, tgt) {
                            Ok(()) => report.tagged += 1,
                            Err(_) => halted = true,
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

/// 逐台搬進同步檔;每台獨立成功/失敗,任一寫入失敗就停止整批並從磁碟重載(見 `migrate_hosts`)。
/// `tag_by_file` 時把 Include 檔的檔名加成 tag(已有同名 tag 不重複;主 config 的主機不上 tag)。
/// 這個行程沒有同步引擎(`refuse_while_sync_inactive`)、或剛 Join、第一輪同步還沒完成
/// (`refuse_before_first_sync`)時,在任何改動之前整批拒絕。
#[tauri::command]
pub async fn sync_migrate_hosts(app: AppHandle, aliases: Vec<String>, tag_by_file: bool) -> Result<MigrationReport, AppError> {
    let handle = app.clone();
    tauri::async_runtime::spawn_blocking(move || {
        let managed = managed_path()?;
        let managed_str = managed.to_string_lossy().into_owned();
        let state = handle.state::<AppState>();
        let mut doc_lock = state.doc.lock().unwrap();
        let mut backed_up = state.backed_up.lock().unwrap();
        let retention = *state.backup_retention.lock().unwrap();
        let doc = doc_lock.as_mut().ok_or_else(|| AppError::Other("no config loaded".to_string()))?;
        // 先看這個行程有沒有引擎:沒有的話,下一行看的狀態是啟動時的快照。
        refuse_while_sync_inactive(crate::sync::engine::engine_active(), &state.sync)?;
        refuse_before_first_sync(&state.sync)?;
        if !doc.files.iter().any(|f| f.path == managed) {
            return Err(AppError::Other("synced hosts file is not loaded; create or join a chain first".to_string()));
        }
        let main_path = doc.files[0].path.clone();

        let (report, needs_reload) = migrate_hosts(doc, aliases, tag_by_file, &managed_str, |doc, idx| {
            persist_file(doc, idx, &mut backed_up, retention)
        });
        if needs_reload {
            // 有寫入失敗:in-memory doc 可能已經比磁碟新。重載讓兩邊一致;重載也失敗就整份作廢 —— 前端會在
            // 拿到這次報告後重新取一次設定,引擎在 doc 是 None 時安靜跳過(不寫 last_error、不存狀態)。
            *doc_lock = match load_doc_migrated(&main_path) {
                Ok(fresh) => Some(fresh),
                Err(_) => None,
            };
        }
        drop(doc_lock);
        crate::sync::engine::wake();
        Ok(report)
    })
    .await
    .map_err(crate::sync::engine::join_error)?
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::include::load_doc;
    use crate::config::serialize::serialize_items;

    /// 主 config Include 受管檔;兩邊都有 `web`,主 config 另有 `local-only`。
    fn fixture() -> (tempfile::TempDir, std::path::PathBuf, std::path::PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let managed = dir.path().join("hosts.config");
        std::fs::write(&managed, "Host web\n  HostName 1\nHost only-synced\n").unwrap();
        let main = dir.path().join("config");
        std::fs::write(&main, format!("Include {}\nHost web\n  HostName 2\nHost local-only\n", managed.display())).unwrap();
        (dir, main, managed)
    }

    #[test]
    fn tag_for_file_strips_extensions_and_normalizes() {
        assert_eq!(tag_for_file(Path::new("/h/.ssh/config.d/homelab.config")), "homelab");
        assert_eq!(tag_for_file(Path::new("/h/.ssh/config.d/Work Stuff.conf")), "work-stuff");
        assert_eq!(tag_for_file(Path::new("/h/.ssh/config")), "config");
    }

    #[test]
    fn duplicates_are_aliases_defined_both_in_managed_and_elsewhere() {
        let (_dir, main, managed) = fixture();
        let doc = load_doc(&main).unwrap();
        let dups = duplicate_aliases(&doc, &managed);
        assert_eq!(dups.len(), 1);
        assert_eq!(dups[0].alias, "web");
        assert!(dups[0].local_file.ends_with("config"));
    }

    #[test]
    fn migration_refuses_the_block_move_host_would_actually_pick() {
        let dir = tempfile::tempdir().unwrap();
        let main = dir.path().join("config");
        // `move_host` 挑的是「任一 pattern 相符」的第一個區塊:遷移 `web` 會搬到含 wildcard 的第一個,不是
        // 後面那個乾淨的 `Host web`。資格檢查必須用同一條定位規則。
        std::fs::write(&main, "Host other web *.internal\n  User ops\nHost web\nHost db\n").unwrap();
        let doc = load_doc(&main).unwrap();
        assert!(refuse_wildcard(&doc, "web").is_err());
        assert!(refuse_wildcard(&doc, "other").is_err());
        assert!(refuse_wildcard(&doc, "db").is_ok());
        assert!(refuse_wildcard(&doc, "ghost").is_ok(), "move_host reports unknown aliases itself");
    }

    #[test]
    fn resolve_shadowed_only_touches_the_named_local_file() {
        let (_dir, main, managed) = fixture();
        let main_str = main.to_string_lossy().into_owned();
        let mut doc = load_doc(&main).unwrap();
        // rename:主 config 那份改成 web-local,同步檔那份原封不動。
        let idx = resolve_shadowed(&mut doc, "web", &main_str, ShadowedAction::Rename, &managed).unwrap();
        assert_eq!(idx, 0);
        let main_text = serialize_items(&doc.files[0].items, true);
        assert!(main_text.contains("Host web-local\n  HostName 2\n"));
        assert!(!main_text.contains("Host web\n"));
        let managed_idx = doc.files.iter().position(|f| f.path == managed).unwrap();
        assert!(serialize_items(&doc.files[managed_idx].items, true).contains("Host web\n  HostName 1\n"));
        assert!(duplicate_aliases(&doc, &managed).is_empty());
        // 再 rename 一次會撞名(web-local 已存在)→ 錯,且不能改成同步檔。
        let mut doc2 = load_doc(&main).unwrap();
        std::fs::write(&main, format!("Include {}\nHost web\nHost web-local\n", managed.display())).unwrap();
        let mut doc3 = load_doc(&main).unwrap();
        assert!(resolve_shadowed(&mut doc3, "web", &main_str, ShadowedAction::Rename, &managed).is_err());
        assert!(resolve_shadowed(&mut doc2, "web", &managed.to_string_lossy(), ShadowedAction::Remove, &managed).is_err());
        // remove:只刪主 config 那份。
        let removed = resolve_shadowed(&mut doc2, "web", &main_str, ShadowedAction::Remove, &managed).unwrap();
        assert_eq!(removed, 0);
        assert!(!serialize_items(&doc2.files[0].items, true).contains("Host web\n"));
        assert!(serialize_items(&doc2.files[managed_idx].items, true).contains("Host web\n"));
        // 不存在的檔案 / alias。
        assert!(resolve_shadowed(&mut doc2, "web", "/nope/config", ShadowedAction::Remove, &managed).is_err());
        assert!(resolve_shadowed(&mut doc2, "ghost", &main_str, ShadowedAction::Remove, &managed).is_err());
    }

    #[test]
    fn already_synced_names_are_refused_by_alias_and_by_the_block_that_would_move() {
        let dir = tempfile::tempdir().unwrap();
        let managed = dir.path().join("hosts.config");
        std::fs::write(&managed, "Host web-1 web\nHost bastion\n").unwrap();
        let main = dir.path().join("config");
        std::fs::write(&main, format!("Include {}\nHost web\nHost bastion jump\nHost db\n", managed.display())).unwrap();
        let doc = load_doc(&main).unwrap();
        assert!(managed_defines(&doc, &managed, "web"), "any pattern of a synced block counts");
        assert!(managed_defines(&doc, &managed, "web-1"));
        assert!(!managed_defines(&doc, &managed, "db"));
        assert!(!managed_defines(&doc, &main, "web-1"), "only the synced file is looked at");
        assert_eq!(
            refuse_already_synced(&doc, &managed, "web").unwrap_err().to_string(),
            "'web' is already in the synced file — resolve the duplicate instead"
        );
        // 以次要 pattern 指名:`move_host` 會搬 `Host bastion jump`,同步檔裡已經有 `bastion`。
        assert_eq!(
            refuse_already_synced(&doc, &managed, "jump").unwrap_err().to_string(),
            "'bastion' is already in the synced file — resolve the duplicate instead"
        );
        assert!(refuse_already_synced(&doc, &managed, "db").is_ok());
        assert!(refuse_already_synced(&doc, &managed, "ghost").is_ok(), "move_host reports unknown aliases itself");
    }

    /// 同步檔有 `Host a shared`;主 config 有共用次要名稱的 `Host b shared`,和沒有任何重疊的 `Host c d`。
    fn secondary_overlap_fixture() -> (tempfile::TempDir, std::path::PathBuf, std::path::PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let managed = dir.path().join("hosts.config");
        std::fs::write(&managed, "Host a shared\n  HostName 1\n").unwrap();
        let main = dir.path().join("config");
        std::fs::write(&main, format!("Include {}\nHost b shared\n  HostName 2\nHost c d\n  HostName 3\n", managed.display())).unwrap();
        (dir, main, managed)
    }

    #[test]
    fn a_block_sharing_any_name_with_the_synced_file_is_refused() {
        let (_dir, main, managed) = secondary_overlap_fixture();
        let doc = load_doc(&main).unwrap();
        // `move_host` 搬整個 `Host b shared`:它的次要名稱 `shared` 已經是同步區塊 `Host a shared` 的名字。
        assert_eq!(
            refuse_already_synced(&doc, &managed, "b").unwrap_err().to_string(),
            "'shared' is already in the synced file — resolve the duplicate instead"
        );
        // 以撞到的名字本身指名:點名它。
        assert_eq!(
            refuse_already_synced(&doc, &managed, "shared").unwrap_err().to_string(),
            "'shared' is already in the synced file — resolve the duplicate instead"
        );
        // 沒有任何名字重疊的區塊照常可以搬,不論用哪個名字指名。
        assert!(refuse_already_synced(&doc, &managed, "c").is_ok());
        assert!(refuse_already_synced(&doc, &managed, "d").is_ok());
    }

    #[test]
    fn migration_refuses_a_secondary_name_collision_without_halting_the_batch() {
        let (_dir, main, managed) = secondary_overlap_fixture();
        let managed_str = managed.to_string_lossy().into_owned();
        let mut doc = load_doc(&main).unwrap();
        let mut backed_up = std::collections::HashSet::new();
        let (report, needs_reload) = migrate_hosts(
            &mut doc,
            vec!["b".to_string(), "c".to_string()],
            false,
            &managed_str,
            |doc, idx| persist_file(doc, idx, &mut backed_up, None),
        );
        assert!(!needs_reload, "a refusal before any change is not a failed write");
        assert_eq!(report.moved, vec!["c".to_string()], "the batch goes on after the refusal");
        assert_eq!(report.failed.len(), 1);
        assert_eq!(report.failed[0].alias, "b");
        assert_eq!(report.failed[0].error, "'shared' is already in the synced file — resolve the duplicate instead");
        let synced = std::fs::read_to_string(&managed).unwrap();
        assert_eq!(synced.matches("shared").count(), 1, "only one synced block matches 'shared': {synced}");
        assert!(synced.contains("Host c d\n"));
        assert!(std::fs::read_to_string(&main).unwrap().contains("Host b shared\n"), "the refused block stays local");
    }

    #[test]
    fn moves_into_sync_are_refused_in_a_process_without_the_sync_engine() {
        let runtime = SyncRuntime::default();
        assert!(refuse_while_sync_inactive(true, &runtime).is_ok());
        // 沒有記下原因時(單元測試)退回固定訊息。
        assert_eq!(
            refuse_while_sync_inactive(false, &runtime).unwrap_err().to_string(),
            "Sync is running in another SSHelter process — quit it to use sync here"
        );
        // 別的行程持有同步鎖:`initialize` 把這段訊息放進 `save_blocked`。
        runtime.core.lock().unwrap().save_blocked = Some(ANOTHER_ENGINE_MESSAGE.to_string());
        assert_eq!(
            refuse_while_sync_inactive(false, &runtime).unwrap_err().to_string(),
            "Sync is running in another SSHelter process — quit it to use sync here"
        );
        // 鎖因其他錯誤取不到:說的是那個原因(與 Sync 面板一致),不是「別的行程」。
        let lock_error = "sync is off in this SSHelter process: the sync lock could not be taken (boom); restart SSHelter to retry";
        runtime.core.lock().unwrap().save_blocked = Some(lock_error.to_string());
        assert_eq!(refuse_while_sync_inactive(false, &runtime).unwrap_err().to_string(), lock_error);
        // 跑著引擎的行程不在這裡被擋(狀態檔暫時讀不到時 `save_blocked` 也有值,但那是另一回事)。
        assert!(refuse_while_sync_inactive(true, &runtime).is_ok());
    }

    #[test]
    fn a_failed_shadow_resolution_reloads_the_doc_so_it_is_never_ahead_of_disk() {
        let (_dir, main, managed) = fixture();
        let main_str = main.to_string_lossy().into_owned();
        let mut slot = Some(load_doc(&main).unwrap());
        for action in [ShadowedAction::Rename, ShadowedAction::Remove] {
            let err = resolve_shadowed_and_persist(&mut slot, "web", &main_str, action, &managed, |_, _| {
                Err(AppError::Other("disk is full".to_string()))
            })
            .unwrap_err();
            assert_eq!(err.to_string(), "disk is full", "the original error is returned");
            let doc = slot.as_ref().expect("reloaded from disk");
            let main_text = serialize_items(&doc.files[0].items, true);
            assert!(main_text.contains("Host web\n  HostName 2\n"), "the failed change is gone from memory: {main_text}");
            assert!(!main_text.contains("web-local"));
            assert_eq!(duplicate_aliases(doc, &managed).len(), 1, "the local copy is still reported as shadowed");
        }
    }

    #[test]
    fn a_failed_shadow_resolution_drops_the_doc_when_the_reload_fails_too() {
        let (_dir, main, managed) = fixture();
        let main_str = main.to_string_lossy().into_owned();
        let mut slot = Some(load_doc(&main).unwrap());
        std::fs::remove_file(&main).unwrap(); // 重載讀不到主 config
        let err = resolve_shadowed_and_persist(&mut slot, "web", &main_str, ShadowedAction::Remove, &managed, |_, _| {
            Err(AppError::Other("disk is full".to_string()))
        })
        .unwrap_err();
        assert_eq!(err.to_string(), "disk is full");
        assert!(slot.is_none(), "an in-memory doc that is ahead of disk is dropped");
    }

    #[test]
    fn a_refused_or_successful_shadow_resolution_keeps_the_doc_in_step_with_disk() {
        let (_dir, main, managed) = fixture();
        let main_str = main.to_string_lossy().into_owned();
        let mut slot = Some(load_doc(&main).unwrap());
        let mut backed_up = std::collections::HashSet::new();
        // 拒絕(碰同步檔那份):什麼都沒改,也不重載。
        let refused = resolve_shadowed_and_persist(&mut slot, "web", &managed.to_string_lossy(), ShadowedAction::Remove, &managed, |_, _| {
            panic!("nothing to persist after a refusal")
        });
        assert!(refused.is_err());
        assert!(slot.is_some());
        let left = resolve_shadowed_and_persist(&mut slot, "web", &main_str, ShadowedAction::Rename, &managed, |doc, idx| {
            persist_file(doc, idx, &mut backed_up, None)
        })
        .unwrap();
        assert!(left.is_empty(), "no shadowed alias is left");
        assert!(std::fs::read_to_string(&main).unwrap().contains("Host web-local\n  HostName 2\n"));
    }

    #[test]
    fn moves_into_sync_wait_for_the_first_sync_after_join() {
        let runtime = SyncRuntime::default();
        assert!(refuse_before_first_sync(&runtime).is_ok(), "no state yet: nothing to wait for");
        let mut s = crate::sync::state::SyncState::fresh("Box").unwrap();
        runtime.core.lock().unwrap().state = Some(s.clone());
        assert!(refuse_before_first_sync(&runtime).is_ok(), "not joined");
        // 剛 Join:基線輪還沒跑完。
        s.chain_id = Some("ab".repeat(32));
        s.baseline_established = false;
        runtime.core.lock().unwrap().state = Some(s.clone());
        assert_eq!(
            refuse_before_first_sync(&runtime).unwrap_err().to_string(),
            "wait for the first sync to finish before moving hosts into sync"
        );
        s.baseline_established = true;
        runtime.core.lock().unwrap().state = Some(s);
        assert!(refuse_before_first_sync(&runtime).is_ok());
    }

    #[test]
    fn migration_refuses_aliases_the_synced_file_already_defines_without_halting_the_batch() {
        let (_dir, main, managed) = fixture();
        let managed_str = managed.to_string_lossy().into_owned();
        let mut doc = load_doc(&main).unwrap();
        let mut backed_up = std::collections::HashSet::new();
        let (report, needs_reload) = migrate_hosts(
            &mut doc,
            vec!["web".to_string(), "local-only".to_string()],
            false,
            &managed_str,
            |doc, idx| persist_file(doc, idx, &mut backed_up, None),
        );
        assert!(!needs_reload, "a refusal before any change is not a failed write");
        assert_eq!(report.moved, vec!["local-only".to_string()], "the batch goes on after the refusal");
        assert_eq!(report.failed.len(), 1);
        assert_eq!(report.failed[0].alias, "web");
        assert_eq!(report.failed[0].error, "'web' is already in the synced file — resolve the duplicate instead");
        let synced = std::fs::read_to_string(&managed).unwrap();
        assert_eq!(synced.matches("Host web\n").count(), 1, "no second 'Host web' in the synced file: {synced}");
        assert!(synced.contains("Host local-only"));
        let local = std::fs::read_to_string(&main).unwrap();
        assert!(local.contains("Host web\n  HostName 2\n"), "the local copy stays for the shadow panel: {local}");
    }

    #[test]
    fn tag_by_file_tags_hosts_from_included_files_only() {
        let dir = tempfile::tempdir().unwrap();
        let managed = dir.path().join("hosts.config");
        std::fs::write(&managed, "").unwrap();
        let homelab = dir.path().join("homelab.config");
        std::fs::write(&homelab, "Host b\n  HostName 2\n").unwrap();
        let main = dir.path().join("config");
        std::fs::write(&main, format!("Include {}\nInclude {}\nHost a\n  HostName 1\n", managed.display(), homelab.display())).unwrap();
        let mut doc = load_doc(&main).unwrap();
        let managed_str = managed.to_string_lossy().into_owned();
        let mut backed_up = std::collections::HashSet::new();
        let (report, needs_reload) = migrate_hosts(
            &mut doc,
            vec!["a".to_string(), "b".to_string()],
            true,
            &managed_str,
            |doc, idx| persist_file(doc, idx, &mut backed_up, None),
        );
        assert!(!needs_reload);
        assert_eq!(report.moved, vec!["a".to_string(), "b".to_string()]);
        assert_eq!(report.tagged, 1, "only the host from an included file is tagged");
        // 從磁碟重新讀:主 config 的主機沒有 "config" tag,Include 檔的主機帶檔名 tag。
        let hosts = crate::config::dto::host_summaries(&load_doc(&main).unwrap());
        let tags_of = |alias: &str| hosts.iter().find(|h| h.alias == alias).map(|h| h.tags.clone()).unwrap();
        assert!(tags_of("a").is_empty(), "the main config's hosts get no 'config' tag");
        assert_eq!(tags_of("b"), vec!["homelab".to_string()]);
        assert!(hosts.iter().all(|h| h.source_file == managed.to_string_lossy()), "both moved into the synced file");
    }

    #[test]
    fn migrate_hosts_halts_the_batch_at_the_first_persist_failure_and_flags_a_reload() {
        let dir = tempfile::tempdir().unwrap();
        let managed = dir.path().join("hosts.config");
        std::fs::write(&managed, "").unwrap();
        let main = dir.path().join("config");
        std::fs::write(&main, format!("Include {}\nHost a\nHost b\nHost c\n", managed.display())).unwrap();
        let mut doc = load_doc(&main).unwrap();
        let managed_str = managed.to_string_lossy().into_owned();

        // 第 3 次 persist 呼叫(alias "b" 的 target 寫入)模擬失敗:"a" 已經整台落盤,"b" 半套用,
        // "c" 完全沒碰過。
        let mut backed_up = std::collections::HashSet::new();
        let mut calls = 0u32;
        let (report, needs_reload) = migrate_hosts(
            &mut doc,
            vec!["a".to_string(), "b".to_string(), "c".to_string()],
            false,
            &managed_str,
            |doc, idx| {
                calls += 1;
                if calls == 3 {
                    Err(AppError::Other("disk is full".to_string()))
                } else {
                    persist_file(doc, idx, &mut backed_up, None)
                }
            },
        );

        assert!(needs_reload, "a persist failure must ask the caller to reload from disk");
        assert_eq!(report.moved, vec!["a".to_string()], "only the fully-persisted move counts");
        assert_eq!(report.failed.len(), 2);
        assert_eq!(report.failed[0].alias, "b");
        assert!(report.failed[0].error.contains("disk is full"), "{}", report.failed[0].error);
        assert_eq!(report.failed[1].alias, "c");
        assert_eq!(report.failed[1].error, "not attempted: an earlier move failed");
    }
}
