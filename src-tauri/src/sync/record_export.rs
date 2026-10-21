//! Offline host-only export. Reads public cached records without contacting a relay or Vault.
use crate::error::AppError;
use tauri_plugin_dialog::DialogExt;

#[derive(serde::Serialize)]
pub struct ExportReceipt {
    path: String,
    hosts: usize,
}

fn write_export(
    path: &std::path::Path,
    root: &std::path::Path,
    json: &str,
) -> Result<(), AppError> {
    let parent = path
        .parent()
        .ok_or_else(|| AppError::Other("Choose a host export file.".into()))?
        .canonicalize()?;
    // A settings export must never replace a live or retained application workspace.
    if parent.starts_with(root.canonicalize()?) {
        return Err(AppError::Other(
            "Save the host export outside the Lunport application data folder.".into(),
        ));
    }
    crate::fsutil::atomic_write(path, json.as_bytes(), 0o600)
}

#[tauri::command]
pub async fn records_hosts_export(
    app: tauri::AppHandle,
    previous_workspace: bool,
) -> Result<Option<ExportReceipt>, AppError> {
    tauri::async_runtime::spawn_blocking(move || {
        let root = crate::fsutil::app_data_root()?;
        let (json, count) = if previous_workspace {
            let home = dirs::home_dir()
                .ok_or_else(|| AppError::Other("Cannot find your saved workspace.".into()))?;
            crate::sync::records_v3::importer::saved_hosts::export_workspace(
                &root.join("sync-state.json"),
                home,
            )
            .map_err(|e| AppError::Other(e.to_string()))?
        } else {
            crate::sync::engine::with_env(&app, |env| {
                let (state, _) = crate::sync::record_runtime::snapshot(env)?;
                crate::sync::records_v3::importer::saved_hosts::export_state(&state)
                    .map_err(|e| AppError::Other(e.to_string()))
            })??
        };
        let Some(file) = app
            .dialog()
            .file()
            .set_title(format!("Export {count} hosts — settings only"))
            .set_file_name("lunport-hosts.json")
            .add_filter("Lunport host settings", &["json"])
            .blocking_save_file()
        else {
            return Ok(None);
        };
        let path = file
            .into_path()
            .map_err(|e| AppError::Other(e.to_string()))?;
        write_export(&path, &root, &json)?;
        Ok(Some(ExportReceipt {
            path: path.to_string_lossy().into_owned(),
            hosts: count,
        }))
    })
    .await
    .map_err(crate::sync::engine::join_error)?
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn export_cannot_replace_a_retained_workspace() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("app");
        std::fs::create_dir(&root).unwrap();
        let state = root.join("sync-state.json");
        std::fs::write(&state, b"original").unwrap();
        assert!(write_export(&state, &root, "export").is_err());
        assert_eq!(std::fs::read(&state).unwrap(), b"original");
        let export = dir.path().join("hosts.json");
        write_export(&export, &root, "export").unwrap();
        assert_eq!(std::fs::read(export).unwrap(), b"export");
    }
}
