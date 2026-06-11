//! Settings export / import: native file dialogs + the actual file IO stay in
//! Rust so the WebView never needs a general filesystem permission. The
//! frontend hands us the serialized settings envelope (export) or receives the
//! raw file contents back for validation (import).

use crate::error::AppError;
use tauri_plugin_dialog::DialogExt;

/// Hard cap for imported settings files — anything bigger is certainly not an
/// SSHelter settings envelope (the real one is a few KB).
const MAX_IMPORT_BYTES: u64 = 1024 * 1024; // 1 MB

/// Read a file as UTF-8, refusing anything larger than `max` bytes.
/// Split out of the command so the cap is unit-testable without a dialog.
fn read_capped(path: &std::path::Path, max: u64) -> Result<String, AppError> {
    let len = std::fs::metadata(path)?.len();
    if len > max {
        return Err(AppError::Other(format!(
            "file is too large to be a settings export ({len} bytes; limit {max})"
        )));
    }
    Ok(std::fs::read_to_string(path)?)
}

/// Open a native save dialog and write `json` (the frontend's pretty-printed
/// settings envelope) to the chosen path. Returns the path, or `None` when the
/// user cancels. Async so the blocking dialog never runs on the main thread.
#[tauri::command]
pub async fn settings_export(
    app: tauri::AppHandle,
    json: String,
) -> Result<Option<String>, AppError> {
    let picked = app
        .dialog()
        .file()
        .set_file_name("sshelter-settings.json")
        .add_filter("JSON", &["json"])
        .blocking_save_file();
    let Some(file_path) = picked else {
        return Ok(None);
    };
    let path = file_path
        .into_path()
        .map_err(|e| AppError::Other(e.to_string()))?;
    std::fs::write(&path, json.as_bytes())?;
    Ok(Some(path.to_string_lossy().into_owned()))
}

/// Open a native open dialog filtered to `.json` and return the file's
/// contents (capped at 1 MB), or `None` when the user cancels. Validation of
/// the envelope happens in the frontend, which owns the settings schema.
#[tauri::command]
pub async fn settings_import(app: tauri::AppHandle) -> Result<Option<String>, AppError> {
    let picked = app
        .dialog()
        .file()
        .add_filter("JSON", &["json"])
        .blocking_pick_file();
    let Some(file_path) = picked else {
        return Ok(None);
    };
    let path = file_path
        .into_path()
        .map_err(|e| AppError::Other(e.to_string()))?;
    Ok(Some(read_capped(&path, MAX_IMPORT_BYTES)?))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn read_capped_returns_contents_within_limit() {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        f.write_all(b"{\"state\":{}}").unwrap();
        let got = read_capped(f.path(), MAX_IMPORT_BYTES).unwrap();
        assert_eq!(got, "{\"state\":{}}");
    }

    #[test]
    fn read_capped_rejects_oversized_files() {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        f.write_all(&vec![b'x'; 64]).unwrap();
        let err = read_capped(f.path(), 16).unwrap_err();
        assert!(err.to_string().contains("too large"), "got: {err}");
    }

    #[test]
    fn read_capped_missing_file_is_io_error() {
        let err = read_capped(std::path::Path::new("/nonexistent/sshelter-nope.json"), 16)
            .unwrap_err();
        assert!(matches!(err, AppError::Io(_)));
    }
}
