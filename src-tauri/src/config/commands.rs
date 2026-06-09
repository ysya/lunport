use std::collections::HashSet;
use std::path::PathBuf;

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

/// Serialize file `idx`, back it up once (tracked in `backed_up`), atomic-write at 0o600, and
/// refresh its in-memory fingerprint.
pub fn persist_file(
    doc: &mut crate::config::model::SshConfigDoc,
    idx: usize,
    backed_up: &mut HashSet<PathBuf>,
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

// ─── Tauri command wrappers ───────────────────────────────────────────────────

#[tauri::command]
pub fn config_load(state: State<AppState>, path: Option<String>) -> Result<LoadResult, AppError> {
    let config_path = match path {
        Some(p) => PathBuf::from(p),
        None => default_config_path()?,
    };

    let doc = load_doc(&config_path)?;
    let files = doc.files.iter().map(|f| f.path.to_string_lossy().into_owned()).collect();
    let hosts = host_summaries(&doc);

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

    match doc_lock.as_mut() {
        None => Err(AppError::Other("no config loaded".to_string())),
        Some(doc) => {
            let idx = apply_changes(doc, &alias, &changes)?;
            persist_file(doc, idx, &mut backed_up_lock)?;
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
            persist_file(doc, idx, &mut backed_up_lock)
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

    match doc_lock.as_mut() {
        None => Err(AppError::Other("no config loaded".to_string())),
        Some(doc) => {
            let idx = find_host_file_index(doc, &alias)
                .ok_or_else(|| AppError::NotFound(format!("host '{}' not found", alias)))?;
            let removed = edit::remove_host(&mut doc.files[idx].items, &alias);
            persist_file(doc, idx, &mut backed_up_lock)?;
            Ok(removed)
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
            persist_file(doc, idx, &mut backed_up_lock)
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

    match doc_lock.as_mut() {
        None => Err(AppError::Other("no config loaded".to_string())),
        Some(doc) => {
            let idx = find_host_file_index(doc, &alias)
                .ok_or_else(|| AppError::NotFound(format!("host '{}' not found", alias)))?;

            let host = edit::find_host_mut(&mut doc.files[idx].items, &alias)
                .ok_or_else(|| AppError::NotFound(format!("host '{}' not found in file", alias)))?;

            edit::set_tags(host, &tags);
            persist_file(doc, idx, &mut backed_up_lock)
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

    match doc_lock.as_mut() {
        None => Err(AppError::Other("no config loaded".to_string())),
        Some(doc) => {
            let idx = doc
                .files
                .iter()
                .position(|f| f.path.to_string_lossy() == file.as_str())
                .ok_or_else(|| AppError::NotFound(format!("file '{}' not found", file)))?;

            edit::reorder_hosts(&mut doc.files[idx].items, &order);
            persist_file(doc, idx, &mut backed_up_lock)
        }
    }
}

#[tauri::command]
pub fn config_check_drift(state: State<AppState>) -> Result<Vec<DriftInfo>, AppError> {
    let doc_lock = state.doc.lock().unwrap();
    match doc_lock.as_ref() {
        None => Err(AppError::Other("no config loaded".to_string())),
        Some(doc) => drift(doc),
    }
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
        persist_file(&mut doc, idx, &mut backed_up).expect("persist_file ok");

        // Re-read from disk.
        let on_disk = std::fs::read_to_string(&config_path).unwrap();
        assert!(on_disk.contains("    User newuser"), "new value on disk:\n{}", on_disk);
        assert!(!on_disk.contains("    User deploy"), "old value must be gone:\n{}", on_disk);

        // Backup file was created.
        let bak_count = std::fs::read_dir(dir.path())
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_name().to_string_lossy().ends_with(".bak"))
            .count();
        assert_eq!(bak_count, 1, "exactly one .bak file should be created");
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
        let res = persist_file(&mut doc, 0, &mut backed_up);
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
        persist_file(&mut doc, 0, &mut backed_up).expect("first persist ok");

        // Second save against the fingerprint refreshed by the first write — no false conflict.
        apply_changes(
            &mut doc,
            "web",
            &[HostFieldChange { keyword: "User".into(), value: "u2".into(), remove: false }],
        )
        .unwrap();
        persist_file(&mut doc, 0, &mut backed_up).expect("second persist must succeed");
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
        persist_file(&mut doc, 0, &mut backed_up).expect("first persist ok");
        assert!(backed_up.contains(&config_path), "path must be in backed_up after first persist");

        let bak_count_after_first = std::fs::read_dir(dir.path())
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_name().to_string_lossy().ends_with(".bak"))
            .count();
        assert_eq!(bak_count_after_first, 1, "one .bak after first persist");

        // Second persist — backed_up already contains the path, so no new backup.
        persist_file(&mut doc, 0, &mut backed_up).expect("second persist ok");
        let bak_count_after_second = std::fs::read_dir(dir.path())
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_name().to_string_lossy().ends_with(".bak"))
            .count();
        assert_eq!(bak_count_after_second, 1, "still one .bak after second persist");
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
    }
}
