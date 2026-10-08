use std::collections::HashSet;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use tauri::State;

use crate::config::dto::{host_detail, host_summaries, HostDetail, HostSummary};
use crate::config::edit;
use crate::config::include::{find_host_file_index, load_doc};
use crate::config::model::{Directive, Item};
use crate::config::newfile::{self, NewFilePlan};
use crate::config::serialize::serialize_items;
use crate::error::AppError;
use crate::fsutil;
use crate::state::AppState;

// ─── Command DTOs ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(test, derive(ts_rs::TS))]
#[cfg_attr(test, ts(export, export_to = "../../src/bindings/"))]
pub struct HostFieldChange {
    pub keyword: String,
    pub value: String,
    pub remove: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(test, derive(ts_rs::TS))]
#[cfg_attr(test, ts(export, export_to = "../../src/bindings/"))]
pub struct LoadResult {
    pub files: Vec<String>,
    pub hosts: Vec<HostSummary>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(test, derive(ts_rs::TS))]
#[cfg_attr(test, ts(export, export_to = "../../src/bindings/"))]
pub struct DriftInfo {
    pub path: String,
    pub changed: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(test, derive(ts_rs::TS))]
#[cfg_attr(test, ts(export, export_to = "../../src/bindings/"))]
pub struct BackupInfo {
    /// Full path to the `.bak` file (in the managed file's mirror dir under the backups root).
    pub path: String,
    /// The managed config file this backup snapshots.
    pub file: String,
    /// Backup timestamp (unix millis, parsed from the `<name>.<millis>.bak` filename).
    #[cfg_attr(test, ts(type = "number"))]
    pub timestamp_ms: u64,
}

// ─── Testable helper functions ────────────────────────────────────────────────

/// Default ~/.ssh/config path (uses dirs::home_dir). Errors if home dir is unknown.
pub fn default_config_path() -> Result<PathBuf, AppError> {
    let home = dirs::home_dir()
        .ok_or_else(|| AppError::Other("cannot determine home directory".to_string()))?;
    Ok(home.join(".ssh").join("config"))
}

/// Apply a batch of field changes to a host (set or remove per change). Returns the index of the
/// ConfigFile that was modified. Errors NotFound if the alias isn't in any loaded file.
pub fn apply_changes(
    doc: &mut crate::config::model::SshConfigDoc,
    alias: &str,
    changes: &[HostFieldChange],
) -> Result<usize, AppError> {
    let idx = find_host_file_index(doc, alias)
        .ok_or_else(|| AppError::NotFound(format!("host '{}' not found", alias)))?;

    let host = edit::find_host_mut(&mut doc.files[idx].items, alias)
        .ok_or_else(|| AppError::NotFound(format!("host '{}' not found in file", alias)))?;

    for change in changes {
        if change.remove {
            edit::remove_host_field(host, &change.keyword.to_lowercase());
        } else {
            edit::set_host_field(host, &change.keyword, &change.value);
        }
    }

    Ok(idx)
}

/// Validate rename pattern tokens: the list must be non-empty and every token must be
/// non-empty with no whitespace, no `#`, no newline (newlines are whitespace), and no
/// leading `-` (which reads as an option, never a hostname).
pub fn validate_host_patterns(patterns: &[String]) -> Result<(), AppError> {
    if patterns.is_empty() {
        return Err(AppError::Other("at least one host pattern is required".to_string()));
    }
    for p in patterns {
        if p.is_empty() {
            return Err(AppError::Other("host patterns must not be empty".to_string()));
        }
        if p.chars().any(|c| c.is_whitespace()) {
            return Err(AppError::Other(format!(
                "host pattern '{}' must not contain whitespace",
                p
            )));
        }
        if p.contains('#') {
            return Err(AppError::Other(format!(
                "host pattern '{}' must not contain '#'",
                p
            )));
        }
        if p.starts_with('-') {
            return Err(AppError::Other(format!(
                "host pattern '{}' must not start with '-'",
                p
            )));
        }
    }
    Ok(())
}

/// Rename a host: replace the pattern tokens of the block currently matching `alias` with
/// `patterns` (losslessly — only the Host header line changes). Rejects when the new FIRST
/// pattern exactly equals the alias (first pattern) of a DIFFERENT existing host block; a
/// same-block rename (incl. no-op) is fine. Returns the index of the modified ConfigFile.
pub fn rename_host(
    doc: &mut crate::config::model::SshConfigDoc,
    alias: &str,
    patterns: &[String],
) -> Result<usize, AppError> {
    use crate::config::model::Item;

    validate_host_patterns(patterns)?;

    let idx = find_host_file_index(doc, alias)
        .ok_or_else(|| AppError::NotFound(format!("host '{}' not found", alias)))?;
    let target_pos = doc.files[idx]
        .items
        .iter()
        .position(|it| matches!(it, Item::Host(h) if h.patterns.iter().any(|p| p == alias)))
        .ok_or_else(|| AppError::NotFound(format!("host '{}' not found in file", alias)))?;

    // Collision guard: the new first pattern must not be the primary alias of ANOTHER block.
    let new_first = patterns[0].as_str();
    for (fi, cf) in doc.files.iter().enumerate() {
        for (ii, item) in cf.items.iter().enumerate() {
            if fi == idx && ii == target_pos {
                continue; // the block being renamed may keep (or reorder to) its own alias
            }
            if let Item::Host(h) = item {
                if h.patterns.first().map(String::as_str) == Some(new_first) {
                    return Err(AppError::Other(format!("host '{}' already exists", new_first)));
                }
            }
        }
    }

    if let Item::Host(h) = &mut doc.files[idx].items[target_pos] {
        edit::set_host_patterns(h, patterns);
    }
    Ok(idx)
}

/// True when the LAST physical line of `items` is blank (or the file has no lines at all).
/// Recurses into the trailing Host/Match block body — the parser folds inter-block blank
/// lines into the PRECEDING block's body, so the last top-level item alone can't tell.
fn ends_with_blank_line(items: &[crate::config::model::Item]) -> bool {
    use crate::config::model::Item;
    match items.last() {
        None => true, // empty file: an appended block needs no separator
        Some(Item::Blank(_)) => true,
        Some(Item::Comment(_)) | Some(Item::Directive(_)) => false,
        // A block header is itself a line, so an empty body means "ends in the header line".
        Some(Item::Host(h)) => !h.body.is_empty() && ends_with_blank_line(&h.body),
        Some(Item::Match(m)) => !m.body.is_empty() && ends_with_blank_line(&m.body),
    }
}

/// Move the WHOLE Host block matching `alias` (its `Item::Host` with every raw line and
/// comment inside the block, emitted verbatim) from its source file to the END of
/// `target_file`, separated by one blank line when the target doesn't already end with one
/// (matching how `config_add_host` appends). `target_file` must EXACTLY equal a loaded
/// managed file's path (else ForbiddenPath); moving within the same file is refused.
/// Returns `(source_idx, target_idx)` — the caller persists BOTH files.
pub fn move_host(
    doc: &mut crate::config::model::SshConfigDoc,
    alias: &str,
    target_file: &str,
) -> Result<(usize, usize), AppError> {
    use crate::config::model::Item;

    let tgt = doc
        .files
        .iter()
        .position(|f| f.path.to_string_lossy() == target_file)
        .ok_or_else(|| AppError::ForbiddenPath(target_file.to_string()))?;
    let src = find_host_file_index(doc, alias)
        .ok_or_else(|| AppError::NotFound(format!("host '{}' not found", alias)))?;
    if src == tgt {
        return Err(AppError::Other(format!(
            "host '{}' is already in '{}'",
            alias, target_file
        )));
    }
    let pos = doc.files[src]
        .items
        .iter()
        .position(|it| matches!(it, Item::Host(h) if h.patterns.iter().any(|p| p == alias)))
        .ok_or_else(|| AppError::NotFound(format!("host '{}' not found in file", alias)))?;

    // Drift pre-check on BOTH files BEFORE mutating: a two-file write can only be half
    // rolled back, so refuse up front when either file changed on disk. (persist_file
    // re-checks at write time — this just closes most of the partial-failure window.)
    for &i in &[src, tgt] {
        match fsutil::has_changed(&doc.files[i].path, &doc.files[i].fingerprint) {
            Ok(false) => {}
            Ok(true) | Err(_) => {
                return Err(AppError::Conflict(
                    doc.files[i].path.to_string_lossy().to_string(),
                ));
            }
        }
    }

    let block = doc.files[src].items.remove(pos);
    if !ends_with_blank_line(&doc.files[tgt].items) {
        doc.files[tgt].items.push(Item::Blank(String::new()));
    }
    doc.files[tgt].items.push(block);
    Ok((src, tgt))
}

/// Duplicate the Host block matching `alias` within the SAME file: a verbatim copy appended
/// at the end (blank-line separated, like `move_host`) with ONLY the `Host` header line's
/// patterns replaced by `new_alias`. `new_alias` follows the rename token rules and must not
/// collide with ANY existing host's first pattern. Returns the modified ConfigFile index.
pub fn duplicate_host(
    doc: &mut crate::config::model::SshConfigDoc,
    alias: &str,
    new_alias: &str,
) -> Result<usize, AppError> {
    use crate::config::model::Item;

    validate_host_patterns(&[new_alias.to_string()])?;

    for cf in &doc.files {
        for item in &cf.items {
            if let Item::Host(h) = item {
                if h.patterns.first().map(String::as_str) == Some(new_alias) {
                    return Err(AppError::Other(format!("host '{}' already exists", new_alias)));
                }
            }
        }
    }

    let idx = find_host_file_index(doc, alias)
        .ok_or_else(|| AppError::NotFound(format!("host '{}' not found", alias)))?;
    let pos = doc.files[idx]
        .items
        .iter()
        .position(|it| matches!(it, Item::Host(h) if h.patterns.iter().any(|p| p == alias)))
        .ok_or_else(|| AppError::NotFound(format!("host '{}' not found in file", alias)))?;

    let mut copy = match &doc.files[idx].items[pos] {
        Item::Host(h) => h.clone(),
        _ => unreachable!("position() matched Item::Host"),
    };
    // Lossless header rewrite (Wave-rename op): only the Host line re-renders on the copy;
    // every body line keeps its raw bytes.
    edit::set_host_patterns(&mut copy, &[new_alias.to_string()]);

    if !ends_with_blank_line(&doc.files[idx].items) {
        doc.files[idx].items.push(Item::Blank(String::new()));
    }
    doc.files[idx].items.push(Item::Host(copy));
    Ok(idx)
}

/// Resolve `path` to a LOADED managed file's index: exact string match first, then
/// canonical-path equality (consistent with how restore validates targets). Anything
/// else — unmanaged files, traversal attempts — is ForbiddenPath.
pub fn find_managed_file(
    doc: &crate::config::model::SshConfigDoc,
    path: &str,
) -> Result<usize, AppError> {
    if let Some(i) = doc.files.iter().position(|f| f.path.to_string_lossy() == path) {
        return Ok(i);
    }
    let forbidden = || AppError::ForbiddenPath(path.to_string());
    let requested = PathBuf::from(path).canonicalize().map_err(|_| forbidden())?;
    for (i, cf) in doc.files.iter().enumerate() {
        if let Ok(managed) = cf.path.canonicalize() {
            if managed == requested {
                return Ok(i);
            }
        }
    }
    Err(forbidden())
}

/// Enable/disable ONE option line of a host, addressed by its position in the host's directive
/// list — the exact order `HostDetail.options` is emitted in (every body `Item::Directive`, in
/// document order, comments/blanks skipped). Addressing by keyword alone is ambiguous the moment
/// a block holds an enabled and a disabled line with the same keyword (e.g. an active
/// `IdentityFile a` next to a commented `# IdentityFile b`), so `index` picks the line and
/// `keyword` is only a sanity check: a mismatch means the caller's view of the host is stale and
/// the toggle is refused instead of risking the wrong line. Returns the modified ConfigFile index.
pub fn set_option_enabled(
    doc: &mut crate::config::model::SshConfigDoc,
    alias: &str,
    keyword: &str,
    index: usize,
    enabled: bool,
) -> Result<usize, AppError> {
    use crate::config::model::Item;

    let idx = find_host_file_index(doc, alias)
        .ok_or_else(|| AppError::NotFound(format!("host '{}' not found", alias)))?;

    let host = edit::find_host_mut(&mut doc.files[idx].items, alias)
        .ok_or_else(|| AppError::NotFound(format!("host '{}' not found in file", alias)))?;

    let directive = host
        .body
        .iter_mut()
        .filter_map(|item| match item {
            Item::Directive(d) => Some(d),
            _ => None,
        })
        .nth(index)
        .ok_or_else(|| {
            AppError::NotFound(format!(
                "option index {} out of range for host '{}'",
                index, alias
            ))
        })?;

    if directive.key != keyword.to_lowercase() {
        return Err(AppError::Other(format!(
            "option at index {} of host '{}' is '{}', not '{}' — the view is stale, reload and retry",
            index, alias, directive.keyword, keyword
        )));
    }

    edit::set_directive_enabled(directive, enabled);
    Ok(idx)
}

// 測試的插入點(只在測試建置,而且只對目前這個執行緒):`persist_file` 寫完之後,下一次重讀指紋失敗(例如檔案剛好被別的程式鎖住、暫時讀不到)。
#[cfg(test)]
thread_local! {
    pub(crate) static FAIL_FINGERPRINT_REREAD: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// Serialize file `idx`, back it up once (tracked in `backed_up`), atomic-write at 0o600, and
/// refresh its in-memory fingerprint. Backups go to the file's MIRROR dir under
/// `fsutil::backups_root()` — never next to the file, where a glob `Include` would read them as
/// live config. `retention` = how many `.bak` snapshots to keep per file (None = unlimited); old
/// ones are pruned right after a successful backup, and a prune failure never fails the save.
pub fn persist_file(
    doc: &mut crate::config::model::SshConfigDoc,
    idx: usize,
    backed_up: &mut HashSet<PathBuf>,
    retention: Option<usize>,
) -> Result<(), AppError> {
    let path = doc.files[idx].path.clone();

    // Conflict guard: never overwrite a file that changed on disk since we loaded/last wrote it
    // (an external editor, `ssh-keygen -R`, etc.). A vanished file is also a conflict. On Conflict
    // the caller must reload (config_load), which re-syncs in-memory state from disk — so this also
    // bounds the in-memory/disk divergence window. The first write of a session is compared against
    // the load-time fingerprint; subsequent writes against the fingerprint refreshed below.
    match fsutil::has_changed(&path, &doc.files[idx].fingerprint) {
        Ok(false) => {}
        Ok(true) | Err(_) => {
            return Err(AppError::Conflict(path.to_string_lossy().to_string()));
        }
    }

    let trailing_newline = doc.files[idx].trailing_newline;
    let text = serialize_items(&doc.files[idx].items, trailing_newline);

    if !backed_up.contains(&path) {
        fsutil::backup(&path)?;
        backed_up.insert(path.clone());
        if let Some(keep) = retention {
            if let Err(e) = fsutil::prune_backups(&path, keep) {
                eprintln!("[backup] prune failed for {}: {e}", path.display());
            }
        }
    }

    fsutil::atomic_write(&path, text.as_bytes(), 0o600)?;
    // 寫入已經落地(磁碟上就是 `text`):重讀指紋失敗(檔案剛好被別的程式鎖住、暫時讀不到)不能讓這次存檔被當成失敗 —— 呼叫端會照「沒寫成」回復別的東西
    // (例如離開帳戶時移除新路徑),磁碟上的主 config 卻已經列著它們。退回以剛寫的位元組算指紋(`fsutil::fingerprint_of`,`mtime_ms` = 0):`has_changed` 只比內容雜湊,
    // 所以之後磁碟上的內容若不是這份,下一次存檔照樣發現衝突。整個指紋一起比的地方(`load_wakes_sync`、`files::prepare_files`、`files::apply_and_commit_space`)最多多
    // 一次重掃或喚醒(重載之後 doc 裡就是真的指紋),見 `fsutil::fingerprint_of`。
    doc.files[idx].fingerprint = fingerprint_after_write(&path, text.as_bytes());

    // 同步 hook:app 對受管同步檔的編輯在存檔當下規劃(呼叫端持有 doc 鎖,鎖順序維持 doc → sync core)。
    // 其他檔案、以及單元測試(沒有經過 `sync::engine::initialize`)都是 no-op。
    crate::sync::engine::note_file_written(&path, &doc.files[idx].items);

    Ok(())
}

/// 寫入落地之後的指紋:重讀磁碟上的檔案;讀不到就用剛寫的 `written` 算(`persist_file`)。
fn fingerprint_after_write(path: &Path, written: &[u8]) -> fsutil::Fingerprint {
    #[cfg(test)]
    if FAIL_FINGERPRINT_REREAD.with(|f| f.replace(false)) {
        return fsutil::fingerprint_of(written);
    }
    fsutil::file_fingerprint(path).unwrap_or_else(|_| fsutil::fingerprint_of(written))
}

/// Drift status for every loaded file (compares on-disk hash vs stored fingerprint).
pub fn drift(doc: &crate::config::model::SshConfigDoc) -> Result<Vec<DriftInfo>, AppError> {
    let mut result = Vec::new();
    for cf in &doc.files {
        let changed = match fsutil::has_changed(&cf.path, &cf.fingerprint) {
            Ok(c) => c,
            Err(AppError::Io(e)) if e.kind() == std::io::ErrorKind::NotFound => true,
            Err(e) => return Err(e),
        };
        result.push(DriftInfo {
            path: cf.path.to_string_lossy().into_owned(),
            changed,
        });
    }
    Ok(result)
}

/// If `name` matches `<X>.<digits>.bak`, return `(X, millis)`. The `<X>` part is everything before
/// the final `.<digits>.bak` segment.
fn parse_backup_name(name: &str) -> Option<(String, u64)> {
    let stem = name.strip_suffix(".bak")?;
    // Split off the trailing `.<digits>` segment.
    let (target, millis_str) = stem.rsplit_once('.')?;
    if target.is_empty() || millis_str.is_empty() {
        return None;
    }
    if !millis_str.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let millis = millis_str.parse::<u64>().ok()?;
    Some((target.to_string(), millis))
}

/// List `<name>.<millis>.bak` files in each managed ConfigFile's mirror dir under
/// `fsutil::backups_root()`, newest first.
pub fn list_backups(
    doc: &crate::config::model::SshConfigDoc,
) -> Result<Vec<BackupInfo>, AppError> {
    let mut out: Vec<BackupInfo> = Vec::new();

    for cf in &doc.files {
        let filename = match cf.path.file_name().and_then(|n| n.to_str()) {
            Some(n) => n.to_string(),
            None => continue,
        };
        let mirror = match fsutil::backup_dir_for(&cf.path) {
            Ok(d) => d,
            Err(_) => continue,
        };
        let entries = match std::fs::read_dir(&mirror) {
            Ok(e) => e,
            Err(_) => continue, // mirror dir missing/unreadable → no backups for this file
        };

        let managed = cf.path.to_string_lossy().into_owned();
        for entry in entries.filter_map(|e| e.ok()) {
            let entry_name = entry.file_name().to_string_lossy().into_owned();
            if let Some((target, millis)) = parse_backup_name(&entry_name) {
                // Only backups OF this managed file (target == its filename).
                if target == filename {
                    out.push(BackupInfo {
                        path: entry.path().to_string_lossy().into_owned(),
                        file: managed.clone(),
                        timestamp_ms: millis,
                    });
                }
            }
        }
    }

    // Newest first.
    out.sort_by(|a, b| b.timestamp_ms.cmp(&a.timestamp_ms));
    Ok(out)
}

/// SECURITY-CRITICAL validation for backup restore. Given the loaded doc and a candidate
/// `backup_path`, return the managed target file path to overwrite, or `ForbiddenPath`.
///
/// The mirror layout (`fsutil::backup_dir_for`) is reversible, and every rule below is enforced on
/// canonicalized paths:
/// 1. the backup's parent dir must canonicalize to somewhere STRICTLY INSIDE the canonicalized
///    backups root (created first so canonicalization can succeed);
/// 2. the filename must strictly parse as `<name>.<digits u64>.bak`;
/// 3. the implied target — `/` + (parent relative to the root) + `/<name>` — must canonicalize to
///    EXACTLY one of the loaded managed `ConfigFile.path`s;
/// 4. the backup itself must be a regular file per `symlink_metadata` (never a symlink).
///
/// This prevents restoring from arbitrary paths and overwriting arbitrary targets. The legacy
/// next-to-file backup scheme is NOT accepted (those files are auto-migrated on load).
pub fn resolve_restore_target(
    doc: &crate::config::model::SshConfigDoc,
    backup_path: &str,
) -> Result<PathBuf, AppError> {
    let forbidden = || AppError::ForbiddenPath(backup_path.to_string());

    let root = fsutil::backups_root()?;
    std::fs::create_dir_all(&root)?;
    let root = root.canonicalize().map_err(|_| forbidden())?;

    let backup = PathBuf::from(backup_path);

    // Rule 4: regular file only — never restore through a symlink (or from anything missing/odd).
    match std::fs::symlink_metadata(&backup) {
        Ok(md) if md.file_type().is_file() => {}
        _ => return Err(forbidden()),
    }

    // Rule 1: canonical parent strictly inside the canonical backups root.
    let parent = backup.parent().ok_or_else(forbidden)?;
    let parent = parent.canonicalize().map_err(|_| forbidden())?;
    let rel = parent.strip_prefix(&root).map_err(|_| forbidden())?;
    if rel.as_os_str().is_empty() {
        // Directly in the root would imply a target of `/<name>`; strict prefix required.
        return Err(forbidden());
    }

    // Rule 2: strict `<name>.<digits>.bak` filename.
    let backup_name = backup
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or_else(forbidden)?;
    let (target_name, _millis) = parse_backup_name(backup_name).ok_or_else(forbidden)?;

    // Rule 3: the implied target must exist and canonically EXACTLY equal a managed file.
    let implied = PathBuf::from("/").join(rel).join(&target_name);
    let implied_canonical = implied.canonicalize().map_err(|_| forbidden())?;
    for cf in &doc.files {
        if let Ok(managed_canonical) = cf.path.canonicalize() {
            if managed_canonical == implied_canonical {
                return Ok(cf.path.clone());
            }
        }
    }

    Err(forbidden())
}

/// Legacy-layout cleanup: older SSHelter versions wrote `<file>.<millis>.bak` NEXT TO each config
/// file, which glob `Include` lines (e.g. `Include config.d/*`) then fed back to both our loader
/// and the real `ssh` binary as live config. Move every such stray into the file's mirror dir
/// under `fsutil::backups_root()`.
///
/// Returns `true` if any file that was loaded AS config (a glob-Included stray) got moved — the
/// caller must reload the doc once so it no longer contains those files.
///
/// Edge-case handling:
/// - only strict `<loaded filename>.<digits>.bak` names in the file's own parent dir are touched;
/// - backup-named loaded files are migration targets, never scan anchors;
/// - symlinks (and anything not a regular file) are never migrated;
/// - the loaded ROOT config itself is never moved, even if backup-named;
/// - `fs::rename` falls back to copy+remove (cross-device); any single failure is logged via
///   eprintln and skipped without failing the load.
pub fn migrate_legacy_backups(doc: &crate::config::model::SshConfigDoc) -> bool {
    // Canonical identities of everything loaded AS config, captured BEFORE any file moves
    // (canonicalize fails once the file has been moved away).
    let loaded_canonical: Vec<Option<PathBuf>> =
        doc.files.iter().map(|cf| cf.path.canonicalize().ok()).collect();
    let root_canonical: Option<&PathBuf> = loaded_canonical.first().and_then(|c| c.as_ref());

    let mut moved: HashSet<PathBuf> = HashSet::new();

    for cf in &doc.files {
        let Some(filename) = cf.path.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        // Backup-named loaded files (glob-Included strays) are what we migrate, not where we scan.
        if parse_backup_name(filename).is_some() {
            continue;
        }
        let Some(parent) = cf.path.parent() else {
            continue;
        };
        let Ok(entries) = std::fs::read_dir(parent) else {
            continue;
        };
        let mirror = match fsutil::backup_dir_for(&cf.path) {
            Ok(m) => m,
            Err(e) => {
                eprintln!("[migrate] no backups root for {}: {e}", cf.path.display());
                continue;
            }
        };

        // Collect first: we rename entries out of the directory we're iterating.
        let candidates: Vec<PathBuf> = entries
            .filter_map(|e| e.ok())
            .filter(|e| {
                e.file_name()
                    .to_str()
                    .and_then(|n| fsutil::backup_millis_for(n, filename))
                    .is_some()
            })
            .map(|e| e.path())
            .collect();

        for src in candidates {
            // Regular files only — never migrate through a symlink.
            match std::fs::symlink_metadata(&src) {
                Ok(md) if md.file_type().is_file() => {}
                _ => continue,
            }
            let src_canonical = src.canonicalize().ok();
            // Paranoia: never move the loaded ROOT config out from under ourselves.
            if src_canonical.is_some() && src_canonical.as_ref() == root_canonical {
                continue;
            }

            if let Err(e) = std::fs::create_dir_all(&mirror) {
                eprintln!("[migrate] cannot create {}: {e}", mirror.display());
                continue;
            }
            let dest = mirror.join(src.file_name().expect("candidate has a file name"));
            let result = std::fs::rename(&src, &dest).or_else(|_| {
                // Cross-device fallback: copy then remove the original.
                std::fs::copy(&src, &dest).and_then(|_| std::fs::remove_file(&src))
            });
            match result {
                Ok(()) => {
                    if let Some(c) = src_canonical {
                        moved.insert(c);
                    }
                    moved.insert(src);
                }
                Err(e) => eprintln!(
                    "[migrate] failed to move {} -> {}: {e}",
                    src.display(),
                    dest.display()
                ),
            }
        }
    }

    if moved.is_empty() {
        return false;
    }
    // Did we move any file that had been loaded AS config? Then the doc is stale.
    doc.files.iter().zip(&loaded_canonical).any(|(cf, canonical)| {
        moved.contains(&cf.path) || canonical.as_ref().is_some_and(|c| moved.contains(c))
    })
}

/// `load_doc` + legacy backup migration. If migration moved files that had been loaded AS config
/// (glob-Included strays), reload once so the returned doc no longer contains them. The reload is
/// unconditional-once (migration is not re-run on its result), so this can never loop.
pub fn load_doc_migrated(path: &Path) -> Result<crate::config::model::SshConfigDoc, AppError> {
    let doc = load_doc(path)?;
    if migrate_legacy_backups(&doc) {
        return load_doc(path);
    }
    Ok(doc)
}

// ─── Tauri command wrappers ───────────────────────────────────────────────────

/// 改了主機區塊的命令(改 `IdentityFile`、新增、刪除、改名、搬動、複製、重排、還原備份……)的外殼:`edit` 做完(它拿的 doc、backed_up 鎖都在它裡面放掉)而且存檔成功,
/// 才馬上更新 agent 的設定(`sync::engine::refresh_agent_config`;金鑰保管庫 spec §6「何時重寫:主機的 `IdentityFile` 變了」),不必等下一次同步嘗試。
/// 不能在拿著鎖的時候更新:它自己依序拿 doc → backed_up → core,`std::sync::Mutex` 不能重入。更新不成不讓存檔失敗(它只記到 stderr)。
fn edit_hosts<T>(edit: impl FnOnce() -> Result<T, AppError>) -> Result<T, AppError> {
    after_host_edit(edit, crate::sync::engine::refresh_agent_config)
}

/// `edit_hosts` 的本體:`refresh` 由呼叫端注入(測試用來確認它在 `edit` 放掉鎖之後、只在成功之後才跑)。
fn after_host_edit<T>(edit: impl FnOnce() -> Result<T, AppError>, refresh: impl FnOnce()) -> Result<T, AppError> {
    let result = edit();
    if result.is_ok() {
        refresh();
    }
    result
}

#[tauri::command]
pub fn config_load(
    app: tauri::AppHandle,
    state: State<AppState>,
    path: Option<String>,
) -> Result<LoadResult, AppError> {
    let config_path = match path {
        Some(p) => PathBuf::from(p),
        None => default_config_path()?,
    };

    let doc = load_doc_migrated(&config_path)?;
    let files = doc.files.iter().map(|f| f.path.to_string_lossy().into_owned()).collect();
    let hosts = host_summaries(&doc);

    // Refresh the menubar quick-connect menu from the freshly loaded doc.
    let aliases = crate::tray::tray_aliases(&doc);
    let _ = crate::tray::rebuild_tray(&app, &aliases);

    // 這台勾選的 space 檔(與同步引擎相同);拿不到家目錄時只在第一次載入喚醒。
    let managed: Option<Vec<PathBuf>> = crate::keys::ssh_dir().ok().map(|dir| {
        crate::sync::migrate::selected_space_files(&state.sync, &dir).into_iter().map(|(_, path)| path).collect()
    });
    let wake = {
        let mut doc_lock = state.doc.lock().unwrap();
        let wake = load_wakes_sync(doc_lock.as_ref(), &doc, managed.as_deref());
        *doc_lock = Some(doc);

        let mut backed_up_lock = state.backed_up.lock().unwrap();
        backed_up_lock.clear();
        wake
    };
    // 在放掉 doc 鎖之後才喚醒(見 `load_wakes_sync`)。刻意用一般的 `wake`、不是順便的 `wake_implicit`:這次載入帶進了 app 以外的修改(或第一次載入),要讓同步輪次
    // 馬上先看到它(下一次 app 存檔才不會對著過期的快取行動)—— 退避期間也一樣,不能等到退避結束。
    if wake {
        crate::sync::engine::wake();
    }

    Ok(LoadResult { files, hosts })
}

/// `config_load` 換上新的 doc 之後要不要喚醒同步引擎(純函式):
/// - 之前沒有 doc(第一次載入,或寫入失敗後被作廢):要 —— 引擎的輪次在 doc 是 None 時都安靜跳過。
/// - 任何一個勾選的 space 檔(`managed`,與引擎同一組路徑)在新舊 doc 裡的有無或指紋不同:要 —— 這次載入帶進了
///   app 以外的修改(例如被外部工具清空)。存檔當下的規劃(`note_file_written`)拿整個檔案去比快取,要讓同步輪次
///   先看到這次載入(例如先從 chain 重新長出被清空的檔案),下一次 app 存檔才不會對著過期的快取把每一台主機都
///   規劃成刪除。
/// - 其他情況不喚醒。前端在每次 `sync://applied` 之後都會重新載入,而引擎每次整份重載 doc(即使什麼都沒套用)
///   都會發 `sync://applied`:例如勾選的 space 檔存在卻載入不了(非 UTF-8、讀不到、不是一般檔案)時,
///   `load_doc` 會略過它,每一輪都重載、失敗、再發一次 —— 每次載入都喚醒的話,就成了沒有間隔的迴圈。
///   引擎自己寫檔之後的重新載入也一樣:指紋相同,不必多跑一輪。
///
/// 拿不到受管檔路徑(`managed` 為 None)時只有第一次載入會喚醒。
fn load_wakes_sync(
    previous: Option<&crate::config::model::SshConfigDoc>,
    next: &crate::config::model::SshConfigDoc,
    managed: Option<&[PathBuf]>,
) -> bool {
    let Some(previous) = previous else { return true };
    let Some(managed) = managed else { return false };
    let fingerprints = |doc: &crate::config::model::SshConfigDoc| {
        managed
            .iter()
            .map(|path| doc.files.iter().find(|f| &f.path == path).map(|f| f.fingerprint.clone()))
            .collect::<Vec<_>>()
    };
    fingerprints(previous) != fingerprints(next)
}

/// main config top-level 的 enabled Include 值(文件順序)。
fn main_include_values(doc: &crate::config::model::SshConfigDoc) -> Vec<String> {
    doc.files
        .first()
        .map(|main| {
            main.items
                .iter()
                .filter_map(|item| match item {
                    Item::Directive(d) if d.key == "include" && d.enabled => {
                        Some(d.value.clone())
                    }
                    _ => None,
                })
                .collect()
        })
        .unwrap_or_default()
}

/// 無副作用的建檔預覽:給對話框即時顯示「會建在哪、動不動 main config」。
#[tauri::command]
pub fn config_plan_new_file(
    state: State<AppState>,
    name: String,
) -> Result<NewFilePlan, AppError> {
    let doc_lock = state.doc.lock().unwrap();
    let doc = doc_lock
        .as_ref()
        .ok_or_else(|| AppError::Other("no config loaded".to_string()))?;
    let main_dir = doc
        .files
        .first()
        .and_then(|f| f.path.parent().map(|p| p.to_path_buf()))
        .ok_or_else(|| AppError::Other("no config loaded".to_string()))?;
    let patterns = main_include_values(doc);
    let mut plan =
        newfile::plan_new_file(&name, &main_dir, &patterns, dirs::home_dir().as_deref())?;
    plan.already_exists = Path::new(&plan.path).exists();
    Ok(plan)
}

/// 建立空的 config 檔;未被既有 Include glob 涵蓋時,同時把 `Include` 行
/// 插入 main config(既有 lossless/backup 機制),最後重載整份文件。
#[tauri::command]
pub fn config_create_file(state: State<AppState>, name: String) -> Result<String, AppError> {
    let mut doc_lock = state.doc.lock().unwrap();
    let mut backed_up_lock = state.backed_up.lock().unwrap();
    let retention = *state.backup_retention.lock().unwrap();

    let doc = doc_lock
        .as_mut()
        .ok_or_else(|| AppError::Other("no config loaded".to_string()))?;
    let main_path = doc
        .files
        .first()
        .map(|f| f.path.clone())
        .ok_or_else(|| AppError::Other("no config loaded".to_string()))?;
    let main_dir = main_path
        .parent()
        .map(|p| p.to_path_buf())
        .ok_or_else(|| AppError::Other("main config has no parent directory".to_string()))?;

    let patterns = main_include_values(doc);
    let plan = newfile::plan_new_file(&name, &main_dir, &patterns, dirs::home_dir().as_deref())?;

    let target = PathBuf::from(&plan.path);
    if target.exists() {
        return Err(AppError::Other(format!(
            "{} already exists",
            target.display()
        )));
    }
    if let Some(parent) = target.parent() {
        std::fs::create_dir_all(parent).map_err(AppError::Io)?;
    }

    // create_new:絕不覆蓋既有檔案;Unix 上以 0600 建立(ssh 慣例權限)。
    {
        let mut opts = std::fs::OpenOptions::new();
        opts.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        opts.open(&target).map_err(AppError::Io)?;
    }

    if let Some(value) = &plan.include_value {
        let idx = newfile::include_insert_index(&doc.files[0].items);
        doc.files[0]
            .items
            .insert(idx, Item::Directive(Directive::new("Include", value, "")));
        persist_file(doc, 0, &mut backed_up_lock, retention)?;
    }

    // 重載讓新(空)檔案進入 files 清單;失敗時檔案已建立,前端可手動 reload。
    *doc_lock = Some(load_doc_migrated(&main_path)?);
    Ok(plan.path)
}

#[tauri::command]
pub fn config_list_files(state: State<AppState>) -> Result<Vec<String>, AppError> {
    let doc_lock = state.doc.lock().unwrap();
    match doc_lock.as_ref() {
        None => Ok(Vec::new()),
        Some(doc) => Ok(doc.files.iter().map(|f| f.path.to_string_lossy().into_owned()).collect()),
    }
}

#[tauri::command]
pub fn config_get_host(state: State<AppState>, alias: String) -> Result<Option<HostDetail>, AppError> {
    let doc_lock = state.doc.lock().unwrap();
    match doc_lock.as_ref() {
        None => Err(AppError::Other("no config loaded".to_string())),
        Some(doc) => Ok(host_detail(doc, &alias)),
    }
}

#[tauri::command]
pub fn config_save_host(
    state: State<AppState>,
    alias: String,
    changes: Vec<HostFieldChange>,
) -> Result<Option<HostDetail>, AppError> {
    edit_hosts(|| {
        let mut doc_lock = state.doc.lock().unwrap();
        let mut backed_up_lock = state.backed_up.lock().unwrap();
        let retention = *state.backup_retention.lock().unwrap();

        match doc_lock.as_mut() {
            None => Err(AppError::Other("no config loaded".to_string())),
            Some(doc) => {
                let idx = apply_changes(doc, &alias, &changes)?;
                persist_file(doc, idx, &mut backed_up_lock, retention)?;
                Ok(host_detail(doc, &alias))
            }
        }
    })
}

/// Export to host 之後把主機連到這把金鑰(金鑰保管庫 spec §7.3.1):`edit::replace_identity_files` 改記憶體裡的 doc,`persist` 寫回。
/// 寫不進去(檔案在載入之後被改過、I/O 錯誤)就把記憶體裡的那個檔案還原(同 `agent::wiring::put_include_first`),錯誤照樣回給呼叫端。回傳原本生效的值。
pub fn set_identity_file(
    doc: &mut crate::config::model::SshConfigDoc,
    alias: &str,
    value: &str,
    persist: impl FnOnce(&mut crate::config::model::SshConfigDoc, usize) -> Result<(), AppError>,
) -> Result<Vec<String>, AppError> {
    let idx = find_host_file_index(doc, alias).ok_or_else(|| AppError::NotFound(format!("host '{alias}' not found")))?;
    let saved = doc.files[idx].items.clone();
    let host = edit::find_host_mut(&mut doc.files[idx].items, alias)
        .ok_or_else(|| AppError::NotFound(format!("host '{alias}' not found in file")))?;
    let old = edit::replace_identity_files(host, value);
    if let Err(e) = persist(doc, idx) {
        doc.files[idx].items = saved;
        return Err(e);
    }
    Ok(old)
}

/// Export to host 的「Use this key」:主機區塊裡生效的 IdentityFile 換成這把金鑰(`set_identity_file`)。回傳更新後的主機明細。
/// 放掉鎖之後馬上更新 agent 的設定(`edit_hosts`):主機指到保管庫的金鑰時,`ssh` 立刻接得到 agent。
#[tauri::command]
pub fn config_set_identity_file(state: State<AppState>, alias: String, value: String) -> Result<Option<HostDetail>, AppError> {
    edit_hosts(|| {
        let mut doc_lock = state.doc.lock().unwrap();
        let mut backed_up = state.backed_up.lock().unwrap();
        let retention = *state.backup_retention.lock().unwrap();
        let doc = doc_lock.as_mut().ok_or_else(|| AppError::Other("no config loaded".to_string()))?;
        set_identity_file(doc, &alias, &value, |doc, idx| persist_file(doc, idx, &mut backed_up, retention))?;
        Ok(host_detail(doc, &alias))
    })
}

#[tauri::command]
pub fn config_add_host(
    state: State<AppState>,
    target_file: String,
    alias: String,
    fields: Vec<HostFieldChange>,
) -> Result<(), AppError> {
    edit_hosts(|| {
        let mut doc_lock = state.doc.lock().unwrap();
        let mut backed_up_lock = state.backed_up.lock().unwrap();
        let retention = *state.backup_retention.lock().unwrap();

        match doc_lock.as_mut() {
            None => Err(AppError::Other("no config loaded".to_string())),
            Some(doc) => {
                let idx = doc
                    .files
                    .iter()
                    .position(|f| f.path.to_string_lossy() == target_file.as_str())
                    .ok_or_else(|| AppError::NotFound(format!("file '{}' not found", target_file)))?;

                let kv: Vec<(String, String)> = fields
                    .iter()
                    .map(|c| (c.keyword.clone(), c.value.clone()))
                    .collect();
                edit::add_host(&mut doc.files[idx].items, &alias, &kv);
                persist_file(doc, idx, &mut backed_up_lock, retention)
            }
        }
    })
}

#[tauri::command]
pub fn config_remove_host(
    state: State<AppState>,
    alias: String,
) -> Result<bool, AppError> {
    edit_hosts(|| {
        let mut doc_lock = state.doc.lock().unwrap();
        let mut backed_up_lock = state.backed_up.lock().unwrap();
        let retention = *state.backup_retention.lock().unwrap();

        match doc_lock.as_mut() {
            None => Err(AppError::Other("no config loaded".to_string())),
            Some(doc) => {
                let idx = find_host_file_index(doc, &alias)
                    .ok_or_else(|| AppError::NotFound(format!("host '{}' not found", alias)))?;
                let removed = edit::remove_host(&mut doc.files[idx].items, &alias);
                persist_file(doc, idx, &mut backed_up_lock, retention)?;
                Ok(removed)
            }
        }
    })
}

#[tauri::command]
pub fn config_rename_host(
    state: State<AppState>,
    alias: String,
    patterns: Vec<String>,
) -> Result<Option<HostDetail>, AppError> {
    edit_hosts(|| {
        let mut doc_lock = state.doc.lock().unwrap();
        let mut backed_up_lock = state.backed_up.lock().unwrap();
        let retention = *state.backup_retention.lock().unwrap();

        match doc_lock.as_mut() {
            None => Err(AppError::Other("no config loaded".to_string())),
            Some(doc) => {
                let idx = rename_host(doc, &alias, &patterns)?;
                persist_file(doc, idx, &mut backed_up_lock, retention)?;
                // The host's identity may have changed: look it up by the NEW first pattern.
                Ok(host_detail(doc, &patterns[0]))
            }
        }
    })
}

#[tauri::command]
pub fn config_move_host(
    state: State<AppState>,
    alias: String,
    target_file: String,
) -> Result<(), AppError> {
    edit_hosts(|| {
        let mut doc_lock = state.doc.lock().unwrap();
        let mut backed_up_lock = state.backed_up.lock().unwrap();
        let retention = *state.backup_retention.lock().unwrap();

        let doc = doc_lock
            .as_ref()
            .ok_or_else(|| AppError::Other("no config loaded".to_string()))?;
        // 拖進 sidebar 的某個 space 群組(目標是已載入的、這台勾選的 space 檔;spec §7.2 跨 space 搬移也走這裡):與搬移
        // 精靈同一套規則(`migrate::refuse_move_into_space`,兩邊共用同一組檢查),都在任何改動之前 —— 這個行程沒有同步引擎就拒絕;目標 space 第一輪同步還沒完成就拒絕;
        // 區塊含 wildcard、`Include` 或帶引號的 keyword 就拒絕;要搬的區塊有任何名字已經在目標檔裡也拒絕(重複會讓那個 space
        // 停下)。`move_host_and_persist` 先寫目標檔、再從來源移除。鎖順序 doc → backed_up → core。
        let target = crate::keys::ssh_dir().ok().and_then(|dir| {
            crate::sync::migrate::selected_space_files(&state.sync, &dir)
                .into_iter()
                .find(|(_, path)| path.to_string_lossy() == target_file.as_str() && doc.files.iter().any(|f| &f.path == path))
        });
        if let Some((space_id, path)) = target {
            crate::sync::migrate::refuse_move_into_space(doc, &state.sync, crate::sync::engine::engine_active(), &space_id, &path, &alias)?;
        }
        move_host_and_persist(&mut doc_lock, &alias, &target_file, |doc, idx| {
            persist_file(doc, idx, &mut backed_up_lock, retention)
        })
    })
}

/// `config_move_host` 的搬移與寫檔(`persist` 由呼叫端注入,測試可模擬寫入失敗)。
/// 任一寫入失敗:區塊已經在 in-memory doc 裡搬過去,磁碟上卻沒有(或只寫了一半)—— doc 比磁碟新,任何人
/// (含同步引擎)都不能再拿它行動。從磁碟重載主 config(改動前記下的路徑)讓兩邊一致;重載也失敗就整份作廢
/// (`None`):前端下次取主機清單時重新載入,引擎在 doc 是 None 時安靜跳過(搬移精靈的 `migrate::move_hosts_into_space` 一樣)。
pub(crate) fn move_host_and_persist(
    slot: &mut Option<crate::config::model::SshConfigDoc>,
    alias: &str,
    target_file: &str,
    mut persist: impl FnMut(&mut crate::config::model::SshConfigDoc, usize) -> Result<(), AppError>,
) -> Result<(), AppError> {
    let doc = slot
        .as_mut()
        .ok_or_else(|| AppError::Other("no config loaded".to_string()))?;
    let main_path = doc.files[0].path.clone();
    let (src, tgt) = move_host(doc, alias, target_file)?;
    // Persist the TARGET first: if the source write then fails, the block exists in
    // both files (a recoverable duplicate) rather than in neither.
    let persisted = persist(doc, tgt).and_then(|()| persist(doc, src));
    if let Err(e) = persisted {
        *slot = load_doc_migrated(&main_path).ok();
        return Err(e);
    }
    Ok(())
}

#[tauri::command]
pub fn config_duplicate_host(
    state: State<AppState>,
    alias: String,
    new_alias: String,
) -> Result<(), AppError> {
    edit_hosts(|| {
        let mut doc_lock = state.doc.lock().unwrap();
        let mut backed_up_lock = state.backed_up.lock().unwrap();
        let retention = *state.backup_retention.lock().unwrap();

        match doc_lock.as_mut() {
            None => Err(AppError::Other("no config loaded".to_string())),
            Some(doc) => {
                let idx = duplicate_host(doc, &alias, &new_alias)?;
                persist_file(doc, idx, &mut backed_up_lock, retention)
            }
        }
    })
}

/// Raw text of ONE loaded managed config file (read-only viewer). The path must resolve to
/// a loaded file (exact string or canonical match) — anything else is ForbiddenPath. The
/// content is config the app already holds in memory, so returning it is safe.
#[tauri::command]
pub fn config_read_file(state: State<AppState>, path: String) -> Result<String, AppError> {
    let doc_lock = state.doc.lock().unwrap();
    match doc_lock.as_ref() {
        None => Err(AppError::Other("no config loaded".to_string())),
        Some(doc) => {
            let idx = find_managed_file(doc, &path)?;
            Ok(std::fs::read_to_string(&doc.files[idx].path)?)
        }
    }
}

#[tauri::command]
pub fn config_set_option_enabled(
    state: State<AppState>,
    alias: String,
    keyword: String,
    index: usize,
    enabled: bool,
) -> Result<(), AppError> {
    // 打開或關掉的可能是一行 `IdentityFile`:同樣要更新 agent 的設定。
    edit_hosts(|| {
        let mut doc_lock = state.doc.lock().unwrap();
        let mut backed_up_lock = state.backed_up.lock().unwrap();
        let retention = *state.backup_retention.lock().unwrap();

        match doc_lock.as_mut() {
            None => Err(AppError::Other("no config loaded".to_string())),
            Some(doc) => {
                let idx = set_option_enabled(doc, &alias, &keyword, index, enabled)?;
                persist_file(doc, idx, &mut backed_up_lock, retention)
            }
        }
    })
}

#[tauri::command]
pub fn config_set_tags(
    state: State<AppState>,
    alias: String,
    tags: Vec<String>,
) -> Result<(), AppError> {
    let mut doc_lock = state.doc.lock().unwrap();
    let mut backed_up_lock = state.backed_up.lock().unwrap();
    let retention = *state.backup_retention.lock().unwrap();

    match doc_lock.as_mut() {
        None => Err(AppError::Other("no config loaded".to_string())),
        Some(doc) => {
            let idx = find_host_file_index(doc, &alias)
                .ok_or_else(|| AppError::NotFound(format!("host '{}' not found", alias)))?;

            let host = edit::find_host_mut(&mut doc.files[idx].items, &alias)
                .ok_or_else(|| AppError::NotFound(format!("host '{}' not found in file", alias)))?;

            edit::set_tags(host, &tags);
            persist_file(doc, idx, &mut backed_up_lock, retention)
        }
    }
}

#[tauri::command]
pub fn config_reorder_hosts(
    state: State<AppState>,
    file: String,
    order: Vec<String>,
) -> Result<(), AppError> {
    // `agent/config` 依主機在 config 裡的順序列出它們。
    edit_hosts(|| {
        let mut doc_lock = state.doc.lock().unwrap();
        let mut backed_up_lock = state.backed_up.lock().unwrap();
        let retention = *state.backup_retention.lock().unwrap();

        match doc_lock.as_mut() {
            None => Err(AppError::Other("no config loaded".to_string())),
            Some(doc) => {
                let idx = doc
                    .files
                    .iter()
                    .position(|f| f.path.to_string_lossy() == file.as_str())
                    .ok_or_else(|| AppError::NotFound(format!("file '{}' not found", file)))?;

                edit::reorder_hosts(&mut doc.files[idx].items, &order);
                persist_file(doc, idx, &mut backed_up_lock, retention)
            }
        }
    })
}

#[tauri::command]
pub fn config_set_backup_retention(
    state: State<AppState>,
    limit: Option<u32>,
) -> Result<(), AppError> {
    // keep >= 1: a limit of 0 would prune the backup we just created, silently
    // disabling the safety net. Unlimited is expressed as None, not 0.
    *state.backup_retention.lock().unwrap() = limit.map(|v| (v as usize).max(1));
    Ok(())
}

#[tauri::command]
pub fn config_check_drift(state: State<AppState>) -> Result<Vec<DriftInfo>, AppError> {
    let doc_lock = state.doc.lock().unwrap();
    match doc_lock.as_ref() {
        None => Err(AppError::Other("no config loaded".to_string())),
        Some(doc) => drift(doc),
    }
}

#[tauri::command]
pub fn discover_hosts(state: State<AppState>) -> Result<Vec<crate::discover::Suggestion>, AppError> {
    let doc_lock = state.doc.lock().unwrap();
    match doc_lock.as_ref() {
        None => Ok(Vec::new()),
        Some(doc) => Ok(crate::discover::discover_all(doc)),
    }
}

#[tauri::command]
pub fn config_list_backups(state: State<AppState>) -> Result<Vec<BackupInfo>, AppError> {
    let doc_lock = state.doc.lock().unwrap();
    match doc_lock.as_ref() {
        None => Ok(Vec::new()),
        Some(doc) => list_backups(doc),
    }
}

#[tauri::command]
pub fn config_restore_backup(
    state: State<AppState>,
    app: tauri::AppHandle,
    backup_path: String,
) -> Result<LoadResult, AppError> {
    // 1. Lock doc; none loaded → error. Validate BEFORE touching the filesystem.
    let target = {
        let doc_lock = state.doc.lock().unwrap();
        let doc = doc_lock
            .as_ref()
            .ok_or_else(|| AppError::Other("no config loaded".to_string()))?;

        // 2. SECURITY-CRITICAL path validation.
        let target = resolve_restore_target(doc, &backup_path)?;

        // Remember the doc's main file path to reload from after restore.
        let main_path = doc.files[0].path.clone();
        (target, main_path)
    };
    let (target, main_path) = target;

    // 3. Snapshot the CURRENT state first (so the restore is itself undoable), then overwrite the
    //    managed target with the backup bytes.
    fsutil::backup(&target)?;
    let retention = *state.backup_retention.lock().unwrap();
    if let Some(keep) = retention {
        if let Err(e) = fsutil::prune_backups(&target, keep) {
            eprintln!("[backup] prune failed for {}: {e}", target.display());
        }
    }
    let bytes = std::fs::read(&backup_path)?;
    fsutil::atomic_write(&target, &bytes, 0o600)?;

    // 4. Reload the doc from the main file, refresh state + tray, return a fresh LoadResult.
    let doc = load_doc_migrated(&main_path)?;
    let files = doc.files.iter().map(|f| f.path.to_string_lossy().into_owned()).collect();
    let hosts = host_summaries(&doc);

    let aliases = crate::tray::tray_aliases(&doc);
    let _ = crate::tray::rebuild_tray(&app, &aliases);

    {
        let mut doc_lock = state.doc.lock().unwrap();
        *doc_lock = Some(doc);

        let mut backed_up_lock = state.backed_up.lock().unwrap();
        backed_up_lock.clear();
    }
    // 還原的是整個檔案:主機與它們的 `IdentityFile` 都可能變了。鎖都放掉之後才更新 agent 的設定(同 `edit_hosts`)。
    crate::sync::engine::refresh_agent_config();

    Ok(LoadResult { files, hosts })
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::include::load_doc;

    fn write_config(dir: &tempfile::TempDir, name: &str, content: &str) -> PathBuf {
        let path = dir.path().join(name);
        std::fs::write(&path, content).unwrap();
        path
    }

    /// The mirror backup dir for `target`, created so tests can seed/inspect backups.
    fn mirror_dir(target: &Path) -> PathBuf {
        let dir = fsutil::backup_dir_for(target).unwrap();
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn bak_count_in(dir: &Path) -> usize {
        match std::fs::read_dir(dir) {
            Ok(entries) => entries
                .filter_map(|e| e.ok())
                .filter(|e| e.file_name().to_string_lossy().ends_with(".bak"))
                .count(),
            Err(_) => 0,
        }
    }

    // ── Test 1: apply_changes + persist round-trip minimal change ─────────────
    #[test]
    fn apply_changes_and_persist_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let content = "Host web\n    User deploy\n";
        let config_path = write_config(&dir, "config", content);

        let mut doc = load_doc(&config_path).expect("load_doc ok");
        let changes = vec![HostFieldChange {
            keyword: "User".to_string(),
            value: "newuser".to_string(),
            remove: false,
        }];

        let idx = apply_changes(&mut doc, "web", &changes).expect("apply_changes ok");
        assert_eq!(idx, 0);

        let mut backed_up: HashSet<PathBuf> = HashSet::new();
        persist_file(&mut doc, idx, &mut backed_up, None).expect("persist_file ok");

        // Re-read from disk.
        let on_disk = std::fs::read_to_string(&config_path).unwrap();
        assert!(on_disk.contains("    User newuser"), "new value on disk:\n{}", on_disk);
        assert!(!on_disk.contains("    User deploy"), "old value must be gone:\n{}", on_disk);

        // Backup file was created in the MIRROR dir — never next to the live file,
        // where a glob `Include` would feed it back to ssh as live config.
        assert_eq!(bak_count_in(dir.path()), 0, "no .bak next to the live file");
        assert_eq!(bak_count_in(&mirror_dir(&config_path)), 1, "exactly one .bak in the mirror dir");
    }

    // ── Test 1b: persist refuses to clobber an externally-modified file ───────
    #[test]
    fn persist_refuses_on_external_change_conflict() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = write_config(&dir, "config", "Host web\n    User deploy\n");
        let mut doc = load_doc(&config_path).expect("load_doc ok");
        let mut backed_up: HashSet<PathBuf> = HashSet::new();

        // Someone (another editor / ssh-keygen -R) rewrites the file AFTER we loaded it.
        std::fs::write(&config_path, "Host web\n    User externally_changed\n").unwrap();

        // A persist must now REFUSE (Conflict), not clobber the external edit.
        let res = persist_file(&mut doc, 0, &mut backed_up, None);
        assert!(
            matches!(res, Err(AppError::Conflict(_))),
            "expected Conflict, got {res:?}"
        );
        // The external edit survives untouched on disk.
        let on_disk = std::fs::read_to_string(&config_path).unwrap();
        assert!(on_disk.contains("externally_changed"), "external edit must be preserved");
    }

    // ── Test 1c: a normal second save (no external change) still succeeds ─────
    #[test]
    fn persist_succeeds_twice_without_external_change() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = write_config(&dir, "config", "Host web\n    User deploy\n");
        let mut doc = load_doc(&config_path).expect("load_doc ok");
        let mut backed_up: HashSet<PathBuf> = HashSet::new();

        apply_changes(
            &mut doc,
            "web",
            &[HostFieldChange { keyword: "User".into(), value: "u1".into(), remove: false }],
        )
        .unwrap();
        persist_file(&mut doc, 0, &mut backed_up, None).expect("first persist ok");

        // Second save against the fingerprint refreshed by the first write — no false conflict.
        apply_changes(
            &mut doc,
            "web",
            &[HostFieldChange { keyword: "User".into(), value: "u2".into(), remove: false }],
        )
        .unwrap();
        persist_file(&mut doc, 0, &mut backed_up, None).expect("second persist must succeed");
        assert!(std::fs::read_to_string(&config_path).unwrap().contains("User u2"));
    }

    // ── Test 1d: a write that landed is never reported as failed ──────────────
    #[test]
    fn a_landed_write_is_not_reported_as_failed_when_the_fingerprint_cannot_be_re_read() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = write_config(&dir, "config", "Host web\n    User deploy\n");
        let mut doc = load_doc(&config_path).expect("load_doc ok");
        let mut backed_up: HashSet<PathBuf> = HashSet::new();
        let change = |value: &str| vec![HostFieldChange { keyword: "User".into(), value: value.into(), remove: false }];
        apply_changes(&mut doc, "web", &change("u1")).unwrap();
        // 寫入落地了,之後重讀指紋卻失敗(檔案剛好被別的程式鎖住):這次存檔仍然成功 —— 回 Err 會讓呼叫端照「沒寫成」回復別的東西(例如離開帳戶時移除
        // 新路徑),磁碟上的主 config 卻已經列著它們。
        FAIL_FINGERPRINT_REREAD.with(|f| f.set(true));
        persist_file(&mut doc, 0, &mut backed_up, None).expect("the write landed, so the save succeeded");
        assert!(!FAIL_FINGERPRINT_REREAD.with(|f| f.get()), "the injected failure was used");
        let on_disk = std::fs::read_to_string(&config_path).unwrap();
        assert!(on_disk.contains("User u1"));
        // 指紋是剛寫的位元組算的:同一個 doc 的下一次存檔不會誤報衝突;之後外部改了檔案,照樣擋下。
        assert_eq!(doc.files[0].fingerprint, fsutil::fingerprint_of(on_disk.as_bytes()));
        apply_changes(&mut doc, "web", &change("u2")).unwrap();
        persist_file(&mut doc, 0, &mut backed_up, None).expect("no false conflict after the fallback fingerprint");
        std::fs::write(&config_path, "Host web\n    User external\n").unwrap();
        apply_changes(&mut doc, "web", &change("u3")).unwrap();
        assert!(matches!(persist_file(&mut doc, 0, &mut backed_up, None), Err(AppError::Conflict(_))));
    }

    // ── Test 2: apply_changes add new field and remove field ─────────────────
    #[test]
    fn apply_changes_add_and_remove_field() {
        let dir = tempfile::tempdir().unwrap();
        let content = "Host web\n    User deploy\n    Port 22\n";
        let config_path = write_config(&dir, "config", content);

        let mut doc = load_doc(&config_path).expect("load_doc ok");

        // Add a new field.
        let add_changes = vec![HostFieldChange {
            keyword: "ForwardAgent".to_string(),
            value: "yes".to_string(),
            remove: false,
        }];
        let idx = apply_changes(&mut doc, "web", &add_changes).expect("apply_changes ok");
        let text = serialize_items(&doc.files[idx].items, doc.files[idx].trailing_newline);
        assert!(text.contains("ForwardAgent yes"), "new field must be present:\n{}", text);

        // Remove Port.
        let remove_changes = vec![HostFieldChange {
            keyword: "Port".to_string(),
            value: String::new(),
            remove: true,
        }];
        apply_changes(&mut doc, "web", &remove_changes).expect("apply_changes remove ok");
        let text2 = serialize_items(&doc.files[idx].items, doc.files[idx].trailing_newline);
        assert!(!text2.contains("Port 22"), "removed field must be gone:\n{}", text2);
    }

    // ── Tests: set_option_enabled — addressed by options index, not keyword ──

    /// Serialized text of file 0.
    fn doc_text(doc: &crate::config::model::SshConfigDoc) -> String {
        serialize_items(&doc.files[0].items, doc.files[0].trailing_newline)
    }

    /// Indices of the lines that differ between two equal-length texts.
    fn diff_lines(a: &str, b: &str) -> Vec<usize> {
        let al: Vec<&str> = a.lines().collect();
        let bl: Vec<&str> = b.lines().collect();
        assert_eq!(al.len(), bl.len(), "line count must not change:\n{a}\n--- vs ---\n{b}");
        al.iter()
            .zip(bl.iter())
            .enumerate()
            .filter_map(|(i, (x, y))| if x != y { Some(i) } else { None })
            .collect()
    }

    /// A doc whose 'web' host holds `IdentityFile a` (enabled) plus `IdentityFile b` and
    /// `IdentityFile c` disabled in-memory (serialized as `# IdentityFile …`) — the
    /// same-keyword mix that keyword-only addressing gets wrong. Options indices:
    /// 0 = HostName, 1 = IdentityFile a, 2 = IdentityFile b, 3 = IdentityFile c, 4 = User.
    fn doc_with_same_keyword_mix(dir: &tempfile::TempDir) -> crate::config::model::SshConfigDoc {
        let content = "Host web\n    HostName web.example.com\n    IdentityFile a\n    IdentityFile b\n    IdentityFile c\n    User deploy\n";
        let config_path = write_config(dir, "config", content);
        let mut doc = load_doc(&config_path).expect("load_doc ok");
        // Disabled state only exists in-memory (a reload re-classifies `# …` as comments),
        // so build it through the op under test.
        set_option_enabled(&mut doc, "web", "IdentityFile", 2, false).expect("disable b");
        set_option_enabled(&mut doc, "web", "IdentityFile", 3, false).expect("disable c");
        let text = doc_text(&doc);
        assert!(text.contains("    # IdentityFile b"), "b disabled:\n{text}");
        assert!(text.contains("    # IdentityFile c"), "c disabled:\n{text}");
        assert!(text.contains("    IdentityFile a"), "a still enabled:\n{text}");
        doc
    }

    #[test]
    fn set_option_enabled_enables_the_second_disabled_same_keyword_line_only() {
        let dir = tempfile::tempdir().unwrap();
        let mut doc = doc_with_same_keyword_mix(&dir);
        let before = doc_text(&doc);

        // Enable the SECOND disabled IdentityFile (c, options index 3). Keyword-only
        // addressing would have hit the enabled `IdentityFile a` instead.
        set_option_enabled(&mut doc, "web", "IdentityFile", 3, true).expect("enable c");
        let after = doc_text(&doc);

        let diffs = diff_lines(&before, &after);
        assert_eq!(diffs.len(), 1, "exactly one line may change, got {diffs:?}:\n{after}");
        assert_eq!(before.lines().nth(diffs[0]).unwrap(), "    # IdentityFile c");
        assert_eq!(after.lines().nth(diffs[0]).unwrap(), "    IdentityFile c");
        // The other same-keyword lines are untouched.
        assert!(after.contains("    IdentityFile a"));
        assert!(after.contains("    # IdentityFile b"));
    }

    #[test]
    fn set_option_enabled_disables_the_enabled_same_keyword_line_only() {
        let dir = tempfile::tempdir().unwrap();
        let mut doc = doc_with_same_keyword_mix(&dir);
        let before = doc_text(&doc);

        // Disable the still-enabled `IdentityFile a` (options index 1).
        set_option_enabled(&mut doc, "web", "IdentityFile", 1, false).expect("disable a");
        let after = doc_text(&doc);

        let diffs = diff_lines(&before, &after);
        assert_eq!(diffs.len(), 1, "exactly one line may change, got {diffs:?}:\n{after}");
        assert_eq!(before.lines().nth(diffs[0]).unwrap(), "    IdentityFile a");
        assert_eq!(after.lines().nth(diffs[0]).unwrap(), "    # IdentityFile a");
        assert!(after.contains("    # IdentityFile b"));
        assert!(after.contains("    # IdentityFile c"));
    }

    #[test]
    fn set_option_enabled_rejects_keyword_index_mismatch_and_bad_index() {
        let dir = tempfile::tempdir().unwrap();
        let mut doc = doc_with_same_keyword_mix(&dir);
        let before = doc_text(&doc);

        // Index 0 is HostName, not IdentityFile → keyword mismatch is refused.
        let r = set_option_enabled(&mut doc, "web", "IdentityFile", 0, true);
        assert!(matches!(r, Err(AppError::Other(_))), "mismatch must error, got {r:?}");

        // Index past the directive list → NotFound.
        let r2 = set_option_enabled(&mut doc, "web", "IdentityFile", 99, true);
        assert!(matches!(r2, Err(AppError::NotFound(_))), "out of range must error, got {r2:?}");

        // Unknown alias → NotFound.
        let r3 = set_option_enabled(&mut doc, "nope", "IdentityFile", 1, true);
        assert!(matches!(r3, Err(AppError::NotFound(_))), "unknown alias must error, got {r3:?}");

        // Rejected attempts change nothing.
        assert_eq!(doc_text(&doc), before, "failed toggles must not modify the doc");
    }

    #[test]
    fn set_option_enabled_keyword_check_is_case_insensitive() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = write_config(&dir, "config", "Host web\n    IdentityFile a\n");
        let mut doc = load_doc(&config_path).expect("load_doc ok");
        set_option_enabled(&mut doc, "web", "identityfile", 0, false)
            .expect("case-insensitive keyword match");
        assert!(doc_text(&doc).contains("    # IdentityFile a"));
    }

    // ── Tests: rename_host ────────────────────────────────────────────────────

    #[test]
    fn rename_host_persists_and_findable_under_new_alias() {
        let dir = tempfile::tempdir().unwrap();
        let content = "Host web\n    HostName web.example.com\n    User deploy\n\nHost db\n    User admin\n";
        let config_path = write_config(&dir, "config", content);

        let mut doc = load_doc(&config_path).expect("load_doc ok");
        let idx = rename_host(
            &mut doc,
            "web",
            &["web-prod".to_string(), "web".to_string()],
        )
        .expect("rename_host ok");
        assert_eq!(idx, 0);

        let mut backed_up: HashSet<PathBuf> = HashSet::new();
        persist_file(&mut doc, idx, &mut backed_up, None).expect("persist_file ok");

        // Reload from disk: the host is findable under the NEW first pattern, the body is
        // untouched, and every non-header line is byte-identical.
        let reloaded = load_doc(&config_path).expect("reload ok");
        assert!(find_host_file_index(&reloaded, "web-prod").is_some(), "new alias findable");
        let on_disk = std::fs::read_to_string(&config_path).unwrap();
        assert_eq!(
            on_disk,
            "Host web-prod web\n    HostName web.example.com\n    User deploy\n\nHost db\n    User admin\n",
            "only the Host header line may change"
        );
    }

    #[test]
    fn rename_host_collision_rejected_same_block_ok() {
        let dir = tempfile::tempdir().unwrap();
        let content = "Host web\n    User deploy\n\nHost db\n    User admin\n";
        let config_path = write_config(&dir, "config", content);
        let mut doc = load_doc(&config_path).expect("load_doc ok");

        // Renaming 'web' to another block's alias is rejected.
        let r = rename_host(&mut doc, "web", &["db".to_string()]);
        match r {
            Err(AppError::Other(msg)) => assert!(
                msg.contains("already exists"),
                "collision message should say already exists, got: {msg}"
            ),
            other => panic!("expected Other(already exists), got {other:?}"),
        }

        // A same-block no-op rename is fine.
        rename_host(&mut doc, "web", &["web".to_string()]).expect("same-block rename ok");
        // …and so is keeping the alias while adding a pattern.
        rename_host(&mut doc, "web", &["web".to_string(), "web.example.com".to_string()])
            .expect("same-block pattern addition ok");
    }

    #[test]
    fn rename_host_rejects_invalid_tokens() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = write_config(&dir, "config", "Host web\n    User deploy\n");
        let mut doc = load_doc(&config_path).expect("load_doc ok");

        let bad: &[&[&str]] = &[
            &[],                  // empty list
            &[""],                // empty token
            &["a b"],             // whitespace
            &["a\tb"],            // tab
            &["a\nb"],            // newline
            &["web#prod"],        // hash
            &["-web"],            // leading dash
        ];
        for tokens in bad {
            let patterns: Vec<String> = tokens.iter().map(|s| s.to_string()).collect();
            let r = rename_host(&mut doc, "web", &patterns);
            assert!(
                matches!(r, Err(AppError::Other(_))),
                "tokens {tokens:?} must be rejected, got {r:?}"
            );
        }

        // Nothing was changed by the rejected attempts.
        let text = serialize_items(&doc.files[0].items, doc.files[0].trailing_newline);
        assert_eq!(text, "Host web\n    User deploy\n");
    }

    #[test]
    fn rename_host_not_found() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = write_config(&dir, "config", "Host web\n    User deploy\n");
        let mut doc = load_doc(&config_path).expect("load_doc ok");
        let r = rename_host(&mut doc, "nope", &["x".to_string()]);
        assert!(matches!(r, Err(AppError::NotFound(_))), "unknown alias → NotFound, got {r:?}");
    }

    // ── Tests: move_host — verbatim cross-file block move ─────────────────────

    /// Main config (`Include sub` + two hosts) and an included `sub` file. Returns
    /// (doc, main_path, sub_path).
    fn two_file_doc(
        dir: &tempfile::TempDir,
        sub_content: &str,
    ) -> (crate::config::model::SshConfigDoc, PathBuf, PathBuf) {
        let main_content =
            "Include sub\n\nHost web\n    User deploy\n\nHost db\n    User admin\n";
        let sub_path = write_config(dir, "sub", sub_content);
        let main_path = write_config(dir, "config", main_content);
        let doc = load_doc(&main_path).expect("load_doc ok");
        assert_eq!(doc.files.len(), 2, "main + included sub");
        (doc, main_path, sub_path)
    }

    #[test]
    fn move_host_moves_block_verbatim_golden() {
        let dir = tempfile::tempdir().unwrap();
        let (mut doc, main_path, sub_path) = two_file_doc(&dir, "Host s1\n    User a\n");

        let (src, tgt) =
            move_host(&mut doc, "db", &sub_path.to_string_lossy()).expect("move_host ok");
        assert_eq!((src, tgt), (0, 1));

        let mut backed_up: HashSet<PathBuf> = HashSet::new();
        persist_file(&mut doc, tgt, &mut backed_up, None).expect("persist target ok");
        persist_file(&mut doc, src, &mut backed_up, None).expect("persist source ok");

        // Source: byte-identical except the removed block lines.
        let main_on_disk = std::fs::read_to_string(&main_path).unwrap();
        assert_eq!(main_on_disk, "Include sub\n\nHost web\n    User deploy\n\n");

        // Target: original bytes + one separating blank + the block's bytes VERBATIM.
        let sub_on_disk = std::fs::read_to_string(&sub_path).unwrap();
        assert_eq!(sub_on_disk, "Host s1\n    User a\n\nHost db\n    User admin\n");

        // Reload from disk: the host now lives in sub.
        let reloaded = load_doc(&main_path).expect("reload ok");
        let idx = find_host_file_index(&reloaded, "db").expect("db still findable");
        assert_eq!(reloaded.files[idx].path, sub_path);
    }

    #[test]
    fn move_host_keeps_comments_and_no_double_blank_when_target_ends_blank() {
        let dir = tempfile::tempdir().unwrap();
        // The block carries an inline header comment, a body comment, and odd spacing —
        // all of it must move byte-for-byte. The target already ENDS with a blank line,
        // so no extra separator is inserted.
        let sub_path = write_config(&dir, "sub", "Host s1\n    User a\n\n");
        let main_path = write_config(
            &dir,
            "config",
            "Include sub\nHost web  extra # prod box\n    User deploy\n    # pinned note\n\tPort  2222\n",
        );
        let mut doc = load_doc(&main_path).expect("load_doc ok");

        move_host(&mut doc, "web", &sub_path.to_string_lossy()).expect("move_host ok");
        let mut backed_up: HashSet<PathBuf> = HashSet::new();
        persist_file(&mut doc, 1, &mut backed_up, None).unwrap();
        persist_file(&mut doc, 0, &mut backed_up, None).unwrap();

        assert_eq!(std::fs::read_to_string(&main_path).unwrap(), "Include sub\n");
        assert_eq!(
            std::fs::read_to_string(&sub_path).unwrap(),
            "Host s1\n    User a\n\nHost web  extra # prod box\n    User deploy\n    # pinned note\n\tPort  2222\n"
        );
    }

    #[test]
    fn move_host_rejects_unloaded_target_same_file_and_unknown_alias() {
        let dir = tempfile::tempdir().unwrap();
        let (mut doc, main_path, sub_path) = two_file_doc(&dir, "Host s1\n    User a\n");
        let before_main = doc_text(&doc);

        // Target not a loaded managed file → ForbiddenPath.
        let stray = dir.path().join("not-loaded");
        std::fs::write(&stray, "Host x\n").unwrap();
        let r = move_host(&mut doc, "db", &stray.to_string_lossy());
        assert!(matches!(r, Err(AppError::ForbiddenPath(_))), "unloaded target: {r:?}");

        // target == source → no-op error.
        let r2 = move_host(&mut doc, "db", &main_path.to_string_lossy());
        assert!(matches!(r2, Err(AppError::Other(_))), "same-file move: {r2:?}");

        // Unknown alias → NotFound.
        let r3 = move_host(&mut doc, "nope", &sub_path.to_string_lossy());
        assert!(matches!(r3, Err(AppError::NotFound(_))), "unknown alias: {r3:?}");

        // Rejected attempts change nothing in memory.
        assert_eq!(doc_text(&doc), before_main);
    }

    #[test]
    fn move_host_refuses_on_drifted_file() {
        let dir = tempfile::tempdir().unwrap();
        let (mut doc, _main_path, sub_path) = two_file_doc(&dir, "Host s1\n    User a\n");

        // The TARGET changes on disk after load — the move must refuse before mutating.
        std::fs::write(&sub_path, "Host s1\n    User changed\n").unwrap();
        let r = move_host(&mut doc, "db", &sub_path.to_string_lossy());
        assert!(matches!(r, Err(AppError::Conflict(_))), "drifted target: {r:?}");
        // The source doc was not mutated.
        assert!(doc_text(&doc).contains("Host db"));
    }

    /// Every loaded file's in-memory items serialize to exactly its on-disk bytes.
    fn assert_doc_matches_disk(doc: &crate::config::model::SshConfigDoc) {
        for f in &doc.files {
            assert_eq!(
                serialize_items(&f.items, f.trailing_newline),
                std::fs::read_to_string(&f.path).unwrap(),
                "{} in memory differs from disk",
                f.path.display()
            );
        }
    }

    #[test]
    fn a_failed_source_write_reloads_the_doc_so_it_is_never_ahead_of_disk() {
        let dir = tempfile::tempdir().unwrap();
        let (doc, _main_path, sub_path) = two_file_doc(&dir, "Host s1\n    User a\n");
        let mut slot = Some(doc);
        let mut backed_up: HashSet<PathBuf> = HashSet::new();
        let mut calls = 0;
        // Target written, then the SOURCE write fails: on disk the block is now in both files.
        let r = move_host_and_persist(&mut slot, "db", &sub_path.to_string_lossy(), |doc, idx| {
            calls += 1;
            if calls == 2 {
                Err(AppError::Other("disk is full".to_string()))
            } else {
                persist_file(doc, idx, &mut backed_up, None)
            }
        });
        assert_eq!(r.unwrap_err().to_string(), "disk is full");
        let doc = slot.expect("reloaded from disk");
        assert!(doc_text(&doc).contains("Host db"), "the source still has the block on disk, so in memory too");
        assert_doc_matches_disk(&doc);
    }

    #[test]
    fn a_failed_target_write_reloads_the_untouched_doc() {
        let dir = tempfile::tempdir().unwrap();
        let (doc, main_path, sub_path) = two_file_doc(&dir, "Host s1\n    User a\n");
        let before = std::fs::read_to_string(&main_path).unwrap();
        let mut slot = Some(doc);
        let r = move_host_and_persist(&mut slot, "db", &sub_path.to_string_lossy(), |_, _| {
            Err(AppError::Other("disk is full".to_string()))
        });
        assert!(r.is_err());
        let doc = slot.as_ref().expect("reloaded from disk");
        assert_eq!(doc_text(doc), before, "the moved-in-memory block is back where the disk has it");
        assert_doc_matches_disk(doc);
        // A successful move needs no reload and persists both files.
        let mut backed_up: HashSet<PathBuf> = HashSet::new();
        move_host_and_persist(&mut slot, "db", &sub_path.to_string_lossy(), |doc, idx| {
            persist_file(doc, idx, &mut backed_up, None)
        })
        .unwrap();
        assert!(std::fs::read_to_string(&sub_path).unwrap().contains("Host db"));
        assert_doc_matches_disk(slot.as_ref().unwrap());
    }

    #[test]
    fn a_failed_move_write_drops_the_doc_when_the_reload_fails_too() {
        let dir = tempfile::tempdir().unwrap();
        let (doc, main_path, sub_path) = two_file_doc(&dir, "Host s1\n    User a\n");
        let mut slot = Some(doc);
        let r = move_host_and_persist(&mut slot, "db", &sub_path.to_string_lossy(), |_, _| {
            // The main config vanishes as the write fails: the reload cannot succeed either.
            std::fs::remove_file(&main_path).unwrap();
            Err(AppError::Other("disk is full".to_string()))
        });
        assert!(r.is_err());
        assert!(slot.is_none(), "a doc that may differ from disk is dropped, never kept");
    }

    // ── Tests: duplicate_host — same-file copy, only the header line differs ──

    #[test]
    fn duplicate_host_appends_copy_with_only_header_changed_golden() {
        let dir = tempfile::tempdir().unwrap();
        let original =
            "Host web extra  # prod\n    HostName w.example.com\n    # pinned\n    User deploy\n";
        let config_path = write_config(&dir, "config", original);
        let mut doc = load_doc(&config_path).expect("load_doc ok");

        let idx = duplicate_host(&mut doc, "web", "web-copy").expect("duplicate ok");
        assert_eq!(idx, 0);
        let mut backed_up: HashSet<PathBuf> = HashSet::new();
        persist_file(&mut doc, idx, &mut backed_up, None).expect("persist ok");

        let on_disk = std::fs::read_to_string(&config_path).unwrap();
        // Prefix byte-identical; the copy keeps the header's spacing + inline comment and
        // every body line verbatim — only the pattern tokens became `web-copy`.
        assert!(on_disk.starts_with(original), "prefix must be untouched:\n{on_disk}");
        assert_eq!(
            on_disk,
            format!(
                "{original}\nHost web-copy  # prod\n    HostName w.example.com\n    # pinned\n    User deploy\n"
            )
        );

        // Reload: both hosts findable; the copy's patterns are exactly [new_alias].
        let reloaded = load_doc(&config_path).expect("reload ok");
        assert!(find_host_file_index(&reloaded, "web").is_some());
        let copy = reloaded.files[0]
            .items
            .iter()
            .find_map(|it| match it {
                crate::config::model::Item::Host(h)
                    if h.patterns.first().map(String::as_str) == Some("web-copy") =>
                {
                    Some(h)
                }
                _ => None,
            })
            .expect("copy present");
        assert_eq!(copy.patterns, vec!["web-copy".to_string()]);
    }

    #[test]
    fn duplicate_host_rejects_collisions_and_invalid_aliases() {
        let dir = tempfile::tempdir().unwrap();
        let original = "Host web\n    User deploy\n\nHost db\n    User admin\n";
        let config_path = write_config(&dir, "config", original);
        let mut doc = load_doc(&config_path).expect("load_doc ok");

        // Collision with ANY existing host's first pattern (incl. its own).
        for taken in ["db", "web"] {
            match duplicate_host(&mut doc, "web", taken) {
                Err(AppError::Other(msg)) => {
                    assert!(msg.contains("already exists"), "got: {msg}")
                }
                other => panic!("expected Other(already exists), got {other:?}"),
            }
        }

        // Invalid tokens — same rules as rename.
        for bad in ["", "a b", "a#b", "-web", "a\nb"] {
            let r = duplicate_host(&mut doc, "web", bad);
            assert!(matches!(r, Err(AppError::Other(_))), "alias {bad:?} must be rejected: {r:?}");
        }

        // Unknown source alias → NotFound.
        let r = duplicate_host(&mut doc, "nope", "fresh");
        assert!(matches!(r, Err(AppError::NotFound(_))), "unknown alias: {r:?}");

        // Nothing changed in memory after all the rejections.
        assert_eq!(doc_text(&doc), original);
    }

    // ── Tests: find_managed_file (config_read_file path validation) ───────────

    #[test]
    fn find_managed_file_accepts_loaded_paths_and_rejects_everything_else() {
        let dir = tempfile::tempdir().unwrap();
        let (doc, main_path, sub_path) = two_file_doc(&dir, "Host s1\n    User a\n");

        // Exact string matches.
        assert_eq!(find_managed_file(&doc, &main_path.to_string_lossy()).unwrap(), 0);
        assert_eq!(find_managed_file(&doc, &sub_path.to_string_lossy()).unwrap(), 1);

        // Canonical equivalence (a `./` hop) also resolves.
        let dotted = format!(
            "{}/./{}",
            dir.path().to_string_lossy(),
            main_path.file_name().unwrap().to_string_lossy()
        );
        assert_eq!(find_managed_file(&doc, &dotted).unwrap(), 0);

        // Unmanaged sibling, system file, and nonsense are all forbidden.
        let stray = dir.path().join("unmanaged");
        std::fs::write(&stray, "Host x\n").unwrap();
        for bad in [stray.to_string_lossy().to_string(), "/etc/passwd".into(), "nope".into()] {
            let r = find_managed_file(&doc, &bad);
            assert!(matches!(r, Err(AppError::ForbiddenPath(_))), "path {bad:?}: {r:?}");
        }
    }

    // ── Test 3: apply_changes NotFound for unknown alias ─────────────────────
    #[test]
    fn apply_changes_not_found_for_unknown_alias() {
        let dir = tempfile::tempdir().unwrap();
        let content = "Host web\n    User deploy\n";
        let config_path = write_config(&dir, "config", content);

        let mut doc = load_doc(&config_path).expect("load_doc ok");
        let changes = vec![HostFieldChange {
            keyword: "User".to_string(),
            value: "x".to_string(),
            remove: false,
        }];

        let result = apply_changes(&mut doc, "nonexistent", &changes);
        assert!(result.is_err(), "should return Err for unknown alias");
        match result.unwrap_err() {
            AppError::NotFound(_) => {}
            e => panic!("expected NotFound, got {:?}", e),
        }
    }

    // ── Test 4: persist_file backs up only once ────────────────────────────────
    #[test]
    fn persist_file_backs_up_once() {
        let dir = tempfile::tempdir().unwrap();
        let content = "Host web\n    User deploy\n";
        let config_path = write_config(&dir, "config", content);

        let mut doc = load_doc(&config_path).expect("load_doc ok");
        let mut backed_up: HashSet<PathBuf> = HashSet::new();

        // First persist.
        persist_file(&mut doc, 0, &mut backed_up, None).expect("first persist ok");
        assert!(backed_up.contains(&config_path), "path must be in backed_up after first persist");

        let mirror = mirror_dir(&config_path);
        assert_eq!(bak_count_in(&mirror), 1, "one .bak in the mirror dir after first persist");

        // Second persist — backed_up already contains the path, so no new backup.
        persist_file(&mut doc, 0, &mut backed_up, None).expect("second persist ok");
        assert_eq!(bak_count_in(&mirror), 1, "still one .bak after second persist");
        assert_eq!(bak_count_in(dir.path()), 0, "never a .bak next to the live file");
    }

    // ── Test 4b: persist_file prunes old backups when retention is set ────────
    #[test]
    fn persist_file_prunes_with_retention() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = write_config(&dir, "config", "Host web\n    User deploy\n");
        // Two stale backups from earlier sessions, in the mirror dir (name-millis far in the past).
        let mirror = mirror_dir(&config_path);
        std::fs::write(mirror.join("config.100.bak"), b"old1").unwrap();
        std::fs::write(mirror.join("config.200.bak"), b"old2").unwrap();

        let mut doc = load_doc(&config_path).expect("load_doc ok");
        let mut backed_up: HashSet<PathBuf> = HashSet::new();
        persist_file(&mut doc, 0, &mut backed_up, Some(1)).expect("persist ok");

        // Only the newest backup (the one just created) survives.
        assert_eq!(bak_count_in(&mirror), 1, "retention 1 keeps only the newest");
        assert!(!mirror.join("config.100.bak").exists());
        assert!(!mirror.join("config.200.bak").exists());
    }

    // ── Test 5: drift detection ───────────────────────────────────────────────
    #[test]
    fn drift_reports_changed_and_unchanged() {
        let dir = tempfile::tempdir().unwrap();
        let content = "Host web\n    User deploy\n";
        let config_path = write_config(&dir, "config", content);

        let doc = load_doc(&config_path).expect("load_doc ok");

        // Right after load: no drift.
        let infos = drift(&doc).expect("drift ok");
        assert_eq!(infos.len(), 1);
        assert!(!infos[0].changed, "file must not be changed right after load");

        // Modify file externally.
        std::fs::write(&config_path, "Host web\n    User changed\n").unwrap();

        // Now drift should detect the change.
        let infos2 = drift(&doc).expect("drift ok after modification");
        assert!(infos2[0].changed, "drift must report changed after external modification");
    }

    // ── Test 6: default_config_path ends with .ssh/config ────────────────────
    #[test]
    fn default_config_path_ends_with_ssh_config() {
        let path = default_config_path().expect("default_config_path ok");
        assert!(
            path.ends_with(".ssh/config"),
            "expected path ending with .ssh/config, got: {:?}",
            path
        );
    }

    // ── Test 7: ts-rs ─────────────────────────────────────────────────────────
    #[test]
    fn ts_export_types_compile() {
        let _change = HostFieldChange {
            keyword: "User".to_string(),
            value: "deploy".to_string(),
            remove: false,
        };
        let _result = LoadResult {
            files: vec!["/tmp/config".to_string()],
            hosts: vec![],
        };
        let _drift = DriftInfo {
            path: "/tmp/config".to_string(),
            changed: false,
        };
        let _backup = BackupInfo {
            path: "/tmp/config.123.bak".to_string(),
            file: "/tmp/config".to_string(),
            timestamp_ms: 123,
        };
    }

    // ── Test 8: list_backups scans the mirror dir, newest first ───────────────
    #[test]
    fn list_backups_scans_mirror_dir_newest_first() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = write_config(&dir, "config", "Host web\n    User deploy\n");
        let doc = load_doc(&config_path).expect("load_doc ok");

        // Create three backups + decoys in the mirror dir.
        let mirror = mirror_dir(&config_path);
        std::fs::write(mirror.join("config.100.bak"), b"v1").unwrap();
        std::fs::write(mirror.join("config.300.bak"), b"v3").unwrap();
        std::fs::write(mirror.join("config.200.bak"), b"v2").unwrap();
        std::fs::write(mirror.join("other.500.bak"), b"x").unwrap(); // different target
        std::fs::write(mirror.join("config.bak"), b"x").unwrap(); // no millis → ignored
        std::fs::write(mirror.join("config.notdigits.bak"), b"x").unwrap(); // non-digit
        // A LEGACY-location backup next to the live file must NOT be listed anymore.
        std::fs::write(dir.path().join("config.999.bak"), b"legacy").unwrap();

        let backups = list_backups(&doc).expect("list_backups ok");
        let ts: Vec<u64> = backups.iter().map(|b| b.timestamp_ms).collect();
        assert_eq!(ts, vec![300, 200, 100], "newest first, only this file's mirror backups");

        for b in &backups {
            assert_eq!(b.file, config_path.to_string_lossy());
            assert!(b.path.ends_with(".bak"));
            assert!(
                PathBuf::from(&b.path).starts_with(fsutil::backups_root().unwrap()),
                "every listed backup lives under the backups root: {}",
                b.path
            );
        }
    }

    // ── Test 9: resolve_restore_target accepts a valid mirror-dir backup ──────
    #[test]
    fn resolve_restore_target_accepts_mirror_dir_bak() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = write_config(&dir, "config", "Host web\n    User deploy\n");
        let doc = load_doc(&config_path).expect("load_doc ok");

        // A real backup created through fsutil::backup …
        let bak = fsutil::backup(&config_path).unwrap().expect("backup created");
        let target = resolve_restore_target(&doc, &bak.to_string_lossy())
            .expect("a valid mirror-dir .bak must resolve");
        assert_eq!(
            target.canonicalize().unwrap(),
            config_path.canonicalize().unwrap()
        );

        // … and a manually placed one with a fixed timestamp.
        let manual = mirror_dir(&config_path).join("config.123.bak");
        std::fs::write(&manual, b"Host web\n    User restored\n").unwrap();
        let target2 = resolve_restore_target(&doc, &manual.to_string_lossy())
            .expect("manual mirror-dir .bak must resolve");
        assert_eq!(
            target2.canonicalize().unwrap(),
            config_path.canonicalize().unwrap()
        );
    }

    // ── Test 10: resolve_restore_target rejects everything outside backups_root ─
    #[test]
    fn resolve_restore_target_rejects_paths_outside_backups_root() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = write_config(&dir, "config", "Host web\n    User deploy\n");
        let doc = load_doc(&config_path).expect("load_doc ok");

        // (a) A LEGACY next-to-file backup is no longer restorable (outside backups_root).
        let legacy = dir.path().join("config.123.bak");
        std::fs::write(&legacy, b"legacy").unwrap();
        let r = resolve_restore_target(&doc, &legacy.to_string_lossy());
        assert!(matches!(r, Err(AppError::ForbiddenPath(_))), "legacy sibling .bak rejected: {r:?}");

        // (b) A .bak in an unrelated directory.
        let other_dir = tempfile::tempdir().unwrap();
        let stray = other_dir.path().join("config.123.bak");
        std::fs::write(&stray, b"malicious").unwrap();
        let r2 = resolve_restore_target(&doc, &stray.to_string_lossy());
        assert!(matches!(r2, Err(AppError::ForbiddenPath(_))), "stray .bak rejected: {r2:?}");

        // (c) A non-.bak path (e.g. /etc/passwd) must be rejected.
        let r3 = resolve_restore_target(&doc, "/etc/passwd");
        assert!(matches!(r3, Err(AppError::ForbiddenPath(_))), "non-.bak path rejected: {r3:?}");

        // (d) A nonexistent path must be rejected.
        let missing = fsutil::backup_dir_for(&config_path).unwrap().join("config.999.bak");
        let r4 = resolve_restore_target(&doc, &missing.to_string_lossy());
        assert!(matches!(r4, Err(AppError::ForbiddenPath(_))), "missing .bak rejected: {r4:?}");

        // (e) A file DIRECTLY in backups_root (parent must be STRICTLY inside the root).
        let root = fsutil::backups_root().unwrap();
        std::fs::create_dir_all(&root).unwrap();
        let in_root = root.join("config.777.bak");
        std::fs::write(&in_root, b"x").unwrap();
        let r5 = resolve_restore_target(&doc, &in_root.to_string_lossy());
        assert!(matches!(r5, Err(AppError::ForbiddenPath(_))), "root-level .bak rejected: {r5:?}");
    }

    // ── Test 10b: bad filenames and unmanaged implied targets are rejected ────
    #[test]
    fn resolve_restore_target_rejects_bad_names_and_unmanaged_targets() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = write_config(&dir, "config", "Host web\n    User deploy\n");
        let doc = load_doc(&config_path).expect("load_doc ok");
        let mirror = mirror_dir(&config_path);

        // Bad filenames INSIDE the correct mirror dir.
        for bad in ["config.abc.bak", "other.123.bak.txt", "config.bak"] {
            let p = mirror.join(bad);
            std::fs::write(&p, b"x").unwrap();
            let r = resolve_restore_target(&doc, &p.to_string_lossy());
            assert!(
                matches!(r, Err(AppError::ForbiddenPath(_))),
                "bad filename '{bad}' must be rejected: {r:?}"
            );
        }

        // Implied target exists on disk but is NOT a managed file.
        std::fs::write(dir.path().join("other"), b"unmanaged").unwrap();
        let p = mirror.join("other.123.bak"); // same mirror dir: `other` sits next to `config`
        std::fs::write(&p, b"x").unwrap();
        let r = resolve_restore_target(&doc, &p.to_string_lossy());
        assert!(
            matches!(r, Err(AppError::ForbiddenPath(_))),
            "backup of an unmanaged file must be rejected: {r:?}"
        );
    }

    // ── Test 10c: symlinked backups are never restored ────────────────────────
    #[cfg(unix)]
    #[test]
    fn resolve_restore_target_rejects_symlinked_backup() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = write_config(&dir, "config", "Host web\n    User deploy\n");
        let doc = load_doc(&config_path).expect("load_doc ok");
        let mirror = mirror_dir(&config_path);

        let real = dir.path().join("realfile");
        std::fs::write(&real, b"sneaky").unwrap();
        let link = mirror.join("config.456.bak");
        std::os::unix::fs::symlink(&real, &link).unwrap();

        let r = resolve_restore_target(&doc, &link.to_string_lossy());
        assert!(
            matches!(r, Err(AppError::ForbiddenPath(_))),
            "a symlinked .bak must be rejected: {r:?}"
        );
    }

    // ── Test 11: legacy migration moves stray sibling .bak files into the mirror ─
    #[test]
    fn migration_moves_stray_sibling_baks_into_mirror() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = write_config(&dir, "config", "Host web\n    User deploy\n");
        // Legacy strays next to the live file.
        std::fs::write(dir.path().join("config.100.bak"), b"old1").unwrap();
        std::fs::write(dir.path().join("config.200.bak"), b"old2").unwrap();
        // Decoys that must stay put (strict name parse).
        std::fs::write(dir.path().join("config.abc.bak"), b"decoy").unwrap();
        std::fs::write(dir.path().join("other.999.bak"), b"decoy").unwrap(); // `other` not loaded

        let doc = load_doc(&config_path).expect("load_doc ok");
        let needs_reload = migrate_legacy_backups(&doc);
        assert!(!needs_reload, "strays were not loaded as config → no reload needed");

        // Strays moved into the mirror dir, contents intact.
        let mirror = fsutil::backup_dir_for(&config_path).unwrap();
        assert_eq!(std::fs::read(mirror.join("config.100.bak")).unwrap(), b"old1");
        assert_eq!(std::fs::read(mirror.join("config.200.bak")).unwrap(), b"old2");
        assert!(!dir.path().join("config.100.bak").exists());
        assert!(!dir.path().join("config.200.bak").exists());
        // Decoys untouched.
        assert!(dir.path().join("config.abc.bak").exists());
        assert!(dir.path().join("other.999.bak").exists());
    }

    // ── Test 11b: glob-Included strays trigger the one-shot reload ────────────
    #[test]
    fn migration_of_glob_included_strays_triggers_one_reload() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("config.d")).unwrap();
        let config_path = write_config(
            &dir,
            "config",
            "Include config.d/*\nHost main-h\n    HostName main.example.com\n",
        );
        std::fs::write(
            dir.path().join("config.d/leg.config"),
            "Host leg\n    HostName leg.example.com\n",
        )
        .unwrap();
        // THE BUG: a legacy backup matched by `Include config.d/*` and loaded as live config.
        std::fs::write(
            dir.path().join("config.d/leg.config.123.bak"),
            "Host stale\n    HostName stale.example.com\n",
        )
        .unwrap();

        // Plain load_doc DOES pick up the stray (that's the bug being fixed).
        let polluted = load_doc(&config_path).expect("load_doc ok");
        assert_eq!(polluted.files.len(), 3, "stray .bak is glob-Included");
        assert!(find_host_file_index(&polluted, "stale").is_some());

        // load_doc_migrated migrates and reloads once: clean doc, stray gone from disk + doc.
        let doc = load_doc_migrated(&config_path).expect("load_doc_migrated ok");
        assert_eq!(doc.files.len(), 2, "the .bak must be gone after migration: {:?}",
            doc.files.iter().map(|f| f.path.clone()).collect::<Vec<_>>());
        assert!(
            doc.files.iter().all(|f| !f.path.to_string_lossy().ends_with(".bak")),
            "no loaded file may be backup-named"
        );
        assert!(find_host_file_index(&doc, "stale").is_none(), "stale host gone");
        assert!(find_host_file_index(&doc, "leg").is_some(), "real host still loaded");
        assert!(find_host_file_index(&doc, "main-h").is_some());

        // The stray now lives in the mirror dir of leg.config, content intact.
        let leg = dir.path().join("config.d/leg.config");
        let mirror = fsutil::backup_dir_for(&leg).unwrap();
        assert_eq!(
            std::fs::read_to_string(mirror.join("leg.config.123.bak")).unwrap(),
            "Host stale\n    HostName stale.example.com\n"
        );
        assert_eq!(bak_count_in(&dir.path().join("config.d")), 0, "ssh-visible dir is clean");
    }

    // ── Test 11c: migration never moves symlinks ──────────────────────────────
    #[cfg(unix)]
    #[test]
    fn migration_skips_symlinked_strays() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = write_config(&dir, "config", "Host web\n    User deploy\n");
        let precious = dir.path().join("precious");
        std::fs::write(&precious, b"keep me").unwrap();
        let link = dir.path().join("config.100.bak");
        std::os::unix::fs::symlink(&precious, &link).unwrap();

        let doc = load_doc(&config_path).expect("load_doc ok");
        let needs_reload = migrate_legacy_backups(&doc);
        assert!(!needs_reload);
        assert!(link.exists(), "symlink must not be migrated");
        assert!(precious.exists());
    }

    // ── Test 11d: a clean config loads identically through load_doc_migrated ──
    #[test]
    fn load_doc_migrated_is_noop_on_clean_config() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = write_config(&dir, "config", "Host web\n    User deploy\n");
        let doc = load_doc_migrated(&config_path).expect("load ok");
        assert_eq!(doc.files.len(), 1);
        assert!(find_host_file_index(&doc, "web").is_some());
    }

    // ── config_load 只在受管同步檔變了時喚醒同步引擎 ─────────────────────────────
    // 只用暫存目錄:受管檔路徑由測試傳入(正式環境是這台勾選的 space 檔,~/.ssh/sshelter/<slug>-<id8>.config)。

    #[test]
    fn a_config_load_wakes_sync_on_the_first_load_and_when_the_synced_file_changed() {
        let dir = tempfile::tempdir().unwrap();
        let managed = write_config(&dir, "hosts.config", "Host web\n");
        let main = write_config(&dir, "config", &format!("Include {}\nHost local\n", managed.display()));
        let first = load_doc(&main).unwrap();
        assert!(load_wakes_sync(None, &first, Some(std::slice::from_ref(&managed))), "the first load wakes the engine");
        // 什麼都沒變(例如引擎寫檔之後、前端因 sync://applied 重新載入):不喚醒。
        let same = load_doc(&main).unwrap();
        assert!(!load_wakes_sync(Some(&first), &same, Some(std::slice::from_ref(&managed))), "an identical reload does not");
        // 只有別的檔案變了:不喚醒。
        std::fs::write(&main, format!("Include {}\nHost local\n  User me\n", managed.display())).unwrap();
        let main_edited = load_doc(&main).unwrap();
        assert!(!load_wakes_sync(Some(&same), &main_edited, Some(std::slice::from_ref(&managed))), "other files do not matter");
        // 受管檔在 app 以外被改了(例如被清空):喚醒。
        std::fs::write(&managed, "").unwrap();
        let emptied = load_doc(&main).unwrap();
        assert!(load_wakes_sync(Some(&main_edited), &emptied, Some(std::slice::from_ref(&managed))), "a changed fingerprint wakes it");
        // 拿不到受管檔路徑:只有第一次載入喚醒。
        assert!(load_wakes_sync(None, &emptied, None));
        assert!(!load_wakes_sync(Some(&first), &emptied, None));
    }

    #[test]
    fn a_fallback_fingerprint_after_a_landed_write_costs_at_most_one_extra_wake() {
        // `persist_file` 寫入落地後重讀指紋失敗:doc 裡放的是以寫入的位元組算的指紋(`fsutil::fingerprint_of`,`mtime_ms` = 0)。`load_wakes_sync` 把整個指紋一起比,
        // 所以下一次重載(算出真的指紋,`mtime_ms` 不是 0)會被當成「受管檔變了」多喚醒一次引擎;重載之後 doc 裡就是真的指紋,再重載不會再喚醒。
        let dir = tempfile::tempdir().unwrap();
        let managed = write_config(&dir, "hosts.config", "Host web\n  User deploy\n");
        let main = write_config(&dir, "config", &format!("Include {}\nHost local\n", managed.display()));
        let mut doc = load_doc(&main).unwrap();
        let mut backed_up: HashSet<PathBuf> = HashSet::new();
        let idx = apply_changes(&mut doc, "web", &[HostFieldChange { keyword: "User".into(), value: "u1".into(), remove: false }]).unwrap();
        assert_eq!(doc.files[idx].path, managed);
        FAIL_FINGERPRINT_REREAD.with(|f| f.set(true));
        persist_file(&mut doc, idx, &mut backed_up, None).unwrap();
        assert_eq!(doc.files[idx].fingerprint.mtime_ms, 0, "the stand-in fingerprint does not know the modification time");
        let managed_files = std::slice::from_ref(&managed);
        let reloaded = load_doc(&main).unwrap();
        assert_eq!(reloaded.files[idx].fingerprint.sha256, doc.files[idx].fingerprint.sha256, "the same bytes");
        assert_ne!(reloaded.files[idx].fingerprint.mtime_ms, 0);
        assert!(load_wakes_sync(Some(&doc), &reloaded, Some(managed_files)), "one extra wake: the whole fingerprint differs by mtime_ms");
        let again = load_doc(&main).unwrap();
        assert!(!load_wakes_sync(Some(&reloaded), &again, Some(managed_files)), "and then the real fingerprint is back: no more");
    }

    #[test]
    fn a_config_load_wakes_sync_when_the_synced_file_appears_or_disappears_but_not_while_it_stays_unloadable() {
        let dir = tempfile::tempdir().unwrap();
        let managed = dir.path().join("hosts.config");
        let main = write_config(&dir, "config", &format!("Include {}\nHost local\n", managed.display()));
        let without = load_doc(&main).unwrap();
        assert!(without.files.iter().all(|f| f.path != managed));
        std::fs::write(&managed, "Host web\n").unwrap();
        let with = load_doc(&main).unwrap();
        assert!(load_wakes_sync(Some(&without), &with, Some(std::slice::from_ref(&managed))), "appeared");
        assert!(load_wakes_sync(Some(&with), &without, Some(std::slice::from_ref(&managed))), "disappeared");
        // 存在卻載入不了(例如另存成 UTF-16):`load_doc` 略過它,引擎每一輪都重載 doc 並發 sync://applied。
        // 前端因此重新載入時不能再喚醒 —— 否則就是沒有間隔的迴圈。
        std::fs::write(&managed, [0xff, 0xfe, b'H', 0x00]).unwrap();
        let unloadable = load_doc(&main).unwrap();
        assert!(unloadable.files.iter().all(|f| f.path != managed), "load_doc skips a non-UTF-8 include");
        let reloaded = load_doc(&main).unwrap();
        assert!(!load_wakes_sync(Some(&unloadable), &reloaded, Some(std::slice::from_ref(&managed))));
    }

    fn doc_of(text: &str) -> (tempfile::TempDir, crate::config::model::SshConfigDoc) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config");
        std::fs::write(&path, text).unwrap();
        let doc = load_doc(&path).unwrap();
        (dir, doc)
    }

    /// Export to host 之後:主機區塊裡生效的 IdentityFile 換成一行新的,註解掉的不動,其他區塊不動;回傳原本的值。
    #[test]
    fn setting_the_identity_file_replaces_every_live_line_of_the_host() {
        let (_dir, mut doc) = doc_of(
            "Host web\n  HostName 10.0.0.1\n  IdentityFile ~/.ssh/id_rsa\n  # IdentityFile ~/.ssh/old\n  IdentityFile \"~/.ssh/id work\"\nHost db\n  IdentityFile ~/.ssh/id_rsa\n",
        );
        let old = set_identity_file(&mut doc, "web", "~/.ssh/sshelter/keys/id_mac-3fa2c1d9", |_, _| Ok(())).unwrap();
        assert_eq!(old, vec!["~/.ssh/id_rsa".to_string(), "\"~/.ssh/id work\"".to_string()]);
        assert_eq!(
            serialize_items(&doc.files[0].items, doc.files[0].trailing_newline),
            "Host web\n  HostName 10.0.0.1\n  IdentityFile ~/.ssh/sshelter/keys/id_mac-3fa2c1d9\n  # IdentityFile ~/.ssh/old\nHost db\n  IdentityFile ~/.ssh/id_rsa\n"
        );
    }

    /// 原本沒有 IdentityFile:加在最後一個指令之後。
    #[test]
    fn setting_the_identity_file_on_a_host_without_one_adds_it() {
        let (_dir, mut doc) = doc_of("Host web\n  HostName 10.0.0.1\n\n# trailing\n");
        assert!(set_identity_file(&mut doc, "web", "~/.ssh/id_mac", |_, _| Ok(())).unwrap().is_empty());
        assert_eq!(
            serialize_items(&doc.files[0].items, doc.files[0].trailing_newline),
            "Host web\n  HostName 10.0.0.1\n  IdentityFile ~/.ssh/id_mac\n\n# trailing\n"
        );
    }

    /// 存不進去(例如檔案在載入之後被改過):記憶體裡的 doc 還原,錯誤照樣回給呼叫端。
    #[test]
    fn a_failed_save_leaves_the_loaded_config_as_it_was() {
        let text = "Host web\n  IdentityFile ~/.ssh/id_rsa\n";
        let (_dir, mut doc) = doc_of(text);
        let err = set_identity_file(&mut doc, "web", "~/.ssh/id_mac", |_, _| Err(AppError::Conflict("config".to_string()))).unwrap_err();
        assert!(matches!(err, AppError::Conflict(_)));
        assert_eq!(serialize_items(&doc.files[0].items, doc.files[0].trailing_newline), text);
    }

    /// 主機在被 Include 的檔案裡,用真的 `persist_file` 存:改、存、失敗時還原的都是那個檔案(不是主 config);載入之後被別的程式改過就被擋下(Conflict),磁碟上別人的改動留著。
    #[test]
    fn setting_the_identity_file_edits_and_saves_the_file_that_holds_the_host() {
        let dir = tempfile::tempdir().unwrap();
        let hosts = write_config(&dir, "hosts.config", "Host web\n  IdentityFile ~/.ssh/id_rsa\n");
        let main_text = format!("Include {}\nHost local\n  User me\n", hosts.display());
        let main = write_config(&dir, "config", &main_text);
        let mut doc = load_doc(&main).unwrap();
        let file = find_host_file_index(&doc, "web").unwrap();
        assert_eq!(doc.files[file].path, hosts);
        let mut backed_up: HashSet<PathBuf> = HashSet::new();

        let old = set_identity_file(&mut doc, "web", "~/.ssh/id_mac", |doc, idx| persist_file(doc, idx, &mut backed_up, None)).unwrap();
        assert_eq!(old, vec!["~/.ssh/id_rsa".to_string()]);
        assert_eq!(std::fs::read_to_string(&hosts).unwrap(), "Host web\n  IdentityFile ~/.ssh/id_mac\n");
        assert_eq!(std::fs::read_to_string(&main).unwrap(), main_text, "the main config is not touched");

        std::fs::write(&hosts, "Host web\n  IdentityFile ~/.ssh/external\n").unwrap();
        let err = set_identity_file(&mut doc, "web", "~/.ssh/id_other", |doc, idx| persist_file(doc, idx, &mut backed_up, None)).unwrap_err();
        assert!(matches!(err, AppError::Conflict(_)));
        assert_eq!(serialize_items(&doc.files[file].items, doc.files[file].trailing_newline), "Host web\n  IdentityFile ~/.ssh/id_mac\n");
        assert_eq!(std::fs::read_to_string(&hosts).unwrap(), "Host web\n  IdentityFile ~/.ssh/external\n");
    }

    /// 找不到這個主機:回 NotFound,什麼都不存。
    #[test]
    fn setting_the_identity_file_of_an_unknown_host_is_not_found() {
        let (_dir, mut doc) = doc_of("Host web\n  IdentityFile ~/.ssh/id_rsa\n");
        let err = set_identity_file(&mut doc, "nope", "~/.ssh/id_mac", |_, _| panic!("nothing to save")).unwrap_err();
        assert!(matches!(err, AppError::NotFound(_)));
    }

    /// 改了主機區塊的命令(`after_host_edit`):agent 的設定在命令放掉它拿的鎖之後才更新(更新自己要拿 doc 與 backed_up 的鎖,`std::sync::Mutex` 不能重入),
    /// 而且只在存檔成功之後 —— 失敗的存檔什麼都沒改。
    #[test]
    fn the_agent_config_is_refreshed_once_a_host_edit_has_let_go_of_its_locks_and_only_after_it_saved() {
        let config = std::sync::Mutex::new(());
        let refreshed = std::cell::Cell::new(0);
        let refresh = || {
            assert!(config.try_lock().is_ok(), "the edit still held the config while the agent config was refreshed");
            refreshed.set(refreshed.get() + 1);
        };
        let saved = after_host_edit(
            || {
                let _held = config.lock().unwrap();
                Ok::<_, AppError>("detail")
            },
            refresh,
        );
        assert_eq!(saved.unwrap(), "detail", "the command's answer is passed through");
        assert_eq!(refreshed.get(), 1);

        let failed = after_host_edit(
            || {
                let _held = config.lock().unwrap();
                Err::<(), _>(AppError::Conflict("config".to_string()))
            },
            || refreshed.set(refreshed.get() + 1),
        );
        assert!(matches!(failed, Err(AppError::Conflict(_))), "the error is passed through");
        assert_eq!(refreshed.get(), 1, "nothing was saved, so nothing is refreshed");
    }
}
