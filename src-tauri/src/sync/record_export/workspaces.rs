//! Retained public settings are discovered explicitly; authority is never activated or copied.
use crate::{
    error::AppError,
    sync::{central::wire::hex, record_groups, record_repository, record_runtime},
};
use std::path::{Path, PathBuf};

#[derive(serde::Serialize)]
pub struct SavedWorkspace {
    id: String,
    active: bool,
    service: Option<String>,
    hosts: usize,
    groups: usize,
    modified_ms: Option<u64>,
    error: Option<String>,
}
pub(super) fn source(root: &Path, id: &str) -> Result<PathBuf, AppError> {
    let folder = if id == "original" {
        root.to_owned()
    } else if hex(id, 32) {
        root.join(format!("server-workspace-{id}"))
    } else {
        return Err(AppError::Other("Choose a saved Lunport workspace.".into()));
    };
    let metadata = std::fs::symlink_metadata(&folder)?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(AppError::Other(
            "Saved workspace is not a regular directory.".into(),
        ));
    }
    #[cfg(windows)]
    let _directory = crate::sync::central_files_windows::Directory::private(&folder, false)?;
    let path = folder.join("sync-state.json");
    let metadata = std::fs::symlink_metadata(&path)?;
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        return Err(AppError::Other(
            "Saved workspace is not a regular file.".into(),
        ));
    }
    Ok(path)
}
fn list(root: &Path, active: &Path) -> Result<Vec<SavedWorkspace>, AppError> {
    let mut ids = vec![];
    if root.join("sync-state.json").try_exists()? {
        ids.push("original".to_owned());
    }
    for entry in std::fs::read_dir(root)? {
        let entry = entry?;
        if let Some(id) = entry
            .file_name()
            .to_str()
            .and_then(|name| name.strip_prefix("server-workspace-"))
            .filter(|id| hex(id, 32))
        {
            ids.push(id.to_owned());
            if ids.len() > 256 {
                return Err(AppError::Other("Too many retained workspaces. Export a selected sync-state.json through the import tool.".into()));
            }
        }
    }
    let mut rows = vec![];
    for id in ids {
        let path = source(root, &id);
        let modified_ms = path
            .as_ref()
            .ok()
            .and_then(|p| std::fs::metadata(p).ok())
            .and_then(|m| m.modified().ok())
            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
            .and_then(|t| t.as_millis().try_into().ok());
        let summary = path.as_ref().map_err(|e| e.to_string()).and_then(|p| {
            let state = record_runtime::read_saved_records(p).map_err(|e| e.to_string())?;
            let hosts = record_repository::list_hosts(&state)
                .map_err(|e| e.to_string())?
                .len();
            let groups = record_groups::list_groups(&state)
                .map_err(|e| e.to_string())?
                .len();
            Ok((
                hosts,
                groups,
                state
                    .local
                    .central
                    .as_ref()
                    .map(|w| w.control.profile.origin.clone()),
            ))
        });
        let (hosts, groups, service, error) = match summary {
            Ok((hosts, groups, service)) => (hosts, groups, service, None),
            Err(_) => (0, 0, None, Some("Cannot read this saved workspace. Its files are retained; try importing its sync-state.json directly.".into())),
        };
        rows.push(SavedWorkspace {
            id,
            active: path.as_deref().ok() == Some(active),
            service,
            hosts,
            groups,
            modified_ms,
            error,
        });
    }
    rows.sort_by(|a, b| {
        b.active
            .cmp(&a.active)
            .then_with(|| b.modified_ms.cmp(&a.modified_ms))
            .then_with(|| a.id.cmp(&b.id))
    });
    Ok(rows)
}
#[tauri::command]
pub async fn records_saved_workspaces(
    app: tauri::AppHandle,
) -> Result<Vec<SavedWorkspace>, AppError> {
    tauri::async_runtime::spawn_blocking(move || {
        let root = crate::fsutil::app_data_root()?;
        let active = crate::sync::engine::with_env(&app, |env| env.state_path.clone())?;
        list(&root, &active)
    })
    .await
    .map_err(crate::sync::engine::join_error)?
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn retained_sources_are_bounded_and_cannot_escape_application_data() {
        let root = tempfile::tempdir().unwrap();
        assert!(source(root.path(), "../other").is_err());
        assert!(source(root.path(), "/tmp").is_err());
        assert!(source(root.path(), &"a".repeat(31)).is_err());
        let state = root.path().join("sync-state.json");
        std::fs::write(&state, "unsupported source").unwrap();
        let rows = list(root.path(), &state).unwrap();
        assert_eq!(rows.len(), 1);
        assert!(rows[0].active && rows[0].error.is_some());
        assert_eq!(
            std::fs::read_to_string(&state).unwrap(),
            "unsupported source"
        );
        #[cfg(unix)]
        {
            let folder = root
                .path()
                .join(format!("server-workspace-{}", "a".repeat(32)));
            std::os::unix::fs::symlink(root.path(), &folder).unwrap();
            assert!(source(root.path(), &"a".repeat(32)).is_err());
        }
    }

    #[test]
    fn discovers_multiple_retained_libraries_without_switching_the_active_account() {
        let root = tempfile::tempdir().unwrap();
        crate::fsutil::ensure_dir_secure(root.path()).unwrap();
        let (state, _, _) = crate::sync::central::library_fixture_for_test();
        let original = root.path().join("sync-state.json");
        crate::sync::record_runtime::save_active(&original, &state).unwrap();
        let folder = root
            .path()
            .join(format!("server-workspace-{}", "b".repeat(32)));
        crate::fsutil::ensure_dir_secure(&folder).unwrap();
        let active = folder.join("sync-state.json");
        crate::sync::record_runtime::save_active(&active, &state).unwrap();
        let index = root.path().join("central-server.json");
        std::fs::write(&index, "retained selection").unwrap();
        let rows = list(root.path(), &active).unwrap();
        assert_eq!(rows.len(), 2);
        assert!(rows[0].active && !rows[1].active);
        assert!(rows.iter().all(|row| row.hosts == 2 && row.error.is_none()));
        assert_eq!(
            std::fs::read_to_string(&index).unwrap(),
            "retained selection"
        );
        assert_eq!(
            crate::sync::record_runtime::read_saved_records(&original).unwrap(),
            state
        );
    }
}
