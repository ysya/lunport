//! 既有主機遷入受管同步檔(spec §10):批次 move + 以原檔名上 tag;加入 chain 後「同步檔與本地同名
//! 主機」的偵測;以及**以檔案路徑定位**的處理(既有 `config_rename_host`/`config_remove_host`
//! 以第一個命中為準,會依 Include 順序誤中同步檔那份,不能用)。

use std::path::Path;

use serde::{Deserialize, Serialize};
use tauri::{AppHandle, Manager};

use crate::config::commands::{move_host, persist_file, validate_host_patterns};
use crate::config::dto::parse_tags;
use crate::config::edit::{find_host_mut, set_host_patterns, set_tags};
use crate::config::include::find_host_file_index;
use crate::config::model::{Item, SshConfigDoc};
use crate::error::AppError;
use crate::state::AppState;
use crate::sync::hosts_file::is_syncable_block;

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

fn first_alias(item: &Item) -> Option<&str> {
    match item {
        Item::Host(h) => h.patterns.first().map(String::as_str),
        _ => None,
    }
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
        let doc = doc_lock.as_mut().ok_or_else(|| AppError::Other("no config loaded".to_string()))?;
        let idx = resolve_shadowed(doc, &alias, &file, action, &managed)?;
        persist_file(doc, idx, &mut backed_up, retention)?;
        Ok(duplicate_aliases(doc, &managed))
    })
    .await
    .map_err(crate::sync::engine::join_error)?
}

/// 逐台搬進同步檔;每台獨立成功/失敗。`tag_by_file` 時把原檔名加成 tag(已有同名 tag 不重複)。
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
        if !doc.files.iter().any(|f| f.path == managed) {
            return Err(AppError::Other("synced hosts file is not loaded; create or join a chain first".to_string()));
        }

        let mut report = MigrationReport { moved: Vec::new(), failed: Vec::new(), tagged: 0 };
        for alias in aliases {
            if let Err(e) = refuse_wildcard(doc, &alias) {
                report.failed.push(MigrationFailure { alias, error: e.to_string() });
                continue;
            }
            let source_tag = find_host_file_index(doc, &alias).map(|i| tag_for_file(&doc.files[i].path));
            match move_host(doc, &alias, &managed_str) {
                Ok((src, tgt)) => {
                    if let Err(e) = persist_file(doc, tgt, &mut backed_up, retention)
                        .and_then(|_| persist_file(doc, src, &mut backed_up, retention))
                    {
                        report.failed.push(MigrationFailure { alias, error: e.to_string() });
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
                            if persist_file(doc, tgt, &mut backed_up, retention).is_ok() {
                                report.tagged += 1;
                            }
                        }
                    }
                    report.moved.push(alias);
                }
                Err(e) => report.failed.push(MigrationFailure { alias, error: e.to_string() }),
            }
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
}
