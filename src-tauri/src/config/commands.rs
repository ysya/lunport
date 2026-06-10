use std::collections::HashSet;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use tauri::State;

use crate::config::dto::{host_detail, host_summaries, HostDetail, HostSummary};
use crate::config::edit;
use crate::config::include::{find_host_file_index, load_doc};
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
/// non-empty with no whitespace, no `#`, and no newline (newlines are whitespace).
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
    doc.files[idx].fingerprint = fsutil::file_fingerprint(&path)?;

    Ok(())
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

    let mut doc_lock = state.doc.lock().unwrap();
    *doc_lock = Some(doc);

    let mut backed_up_lock = state.backed_up.lock().unwrap();
    backed_up_lock.clear();

    Ok(LoadResult { files, hosts })
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
}

#[tauri::command]
pub fn config_add_host(
    state: State<AppState>,
    target_file: String,
    alias: String,
    fields: Vec<HostFieldChange>,
) -> Result<(), AppError> {
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
}

#[tauri::command]
pub fn config_remove_host(
    state: State<AppState>,
    alias: String,
) -> Result<bool, AppError> {
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
}

#[tauri::command]
pub fn config_rename_host(
    state: State<AppState>,
    alias: String,
    patterns: Vec<String>,
) -> Result<Option<HostDetail>, AppError> {
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
}

#[tauri::command]
pub fn config_set_option_enabled(
    state: State<AppState>,
    alias: String,
    keyword: String,
    enabled: bool,
) -> Result<(), AppError> {
    let mut doc_lock = state.doc.lock().unwrap();
    let mut backed_up_lock = state.backed_up.lock().unwrap();
    let retention = *state.backup_retention.lock().unwrap();

    match doc_lock.as_mut() {
        None => Err(AppError::Other("no config loaded".to_string())),
        Some(doc) => {
            let idx = find_host_file_index(doc, &alias)
                .ok_or_else(|| AppError::NotFound(format!("host '{}' not found", alias)))?;

            let key_lower = keyword.to_lowercase();
            let host = edit::find_host_mut(&mut doc.files[idx].items, &alias)
                .ok_or_else(|| AppError::NotFound(format!("host '{}' not found in file", alias)))?;

            let directive = host.body.iter_mut().find_map(|item| {
                if let crate::config::model::Item::Directive(d) = item {
                    if d.key == key_lower {
                        return Some(d);
                    }
                }
                None
            }).ok_or_else(|| AppError::NotFound(format!("keyword '{}' not found in host '{}'", keyword, alias)))?;

            edit::set_directive_enabled(directive, enabled);
            persist_file(doc, idx, &mut backed_up_lock, retention)
        }
    }
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

    let mut doc_lock = state.doc.lock().unwrap();
    *doc_lock = Some(doc);

    let mut backed_up_lock = state.backed_up.lock().unwrap();
    backed_up_lock.clear();

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
}
