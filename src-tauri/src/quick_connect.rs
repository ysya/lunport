//! Keep the opted-in shortcut usable even before a lazy main WebView exists.
use std::sync::atomic::{AtomicBool, Ordering};
use tauri::{Emitter, Manager};

const EVENT: &str = "app://quick-connect";
#[derive(Default)]
pub(crate) struct QuickConnect(AtomicBool);

#[cfg(desktop)]
fn shortcut() -> &'static str {
    if cfg!(target_os = "macos") {
        "Alt+Super+K"
    } else {
        "Ctrl+Alt+K"
    }
}

pub(crate) fn initialize(app: &tauri::AppHandle) {
    let enabled = path()
        .ok()
        .and_then(|p| std::fs::read(p).ok())
        .is_some_and(|b| b == b"1");
    if let Err(error) = register(app, enabled) {
        eprintln!("[hotkey] {error}");
    }
}

fn path() -> Result<std::path::PathBuf, String> {
    crate::fsutil::app_data_root()
        .map(|p| p.join("quick-connect-enabled"))
        .map_err(|e| e.to_string())
}

fn register(app: &tauri::AppHandle, enabled: bool) -> Result<(), String> {
    #[cfg(desktop)]
    {
        use tauri_plugin_global_shortcut::{GlobalShortcutExt, ShortcutState};
        let shortcuts = app.global_shortcut();
        if enabled && !shortcuts.is_registered(shortcut()) {
            shortcuts
                .on_shortcut(shortcut(), |app, _, event| {
                    if event.state == ShortcutState::Pressed {
                        app.state::<QuickConnect>().0.store(true, Ordering::SeqCst);
                        crate::show_main_window_by_user(app);
                        let _ = app.emit_to("main", EVENT, ());
                    }
                })
                .map_err(|e| e.to_string())?;
        } else if !enabled && shortcuts.is_registered(shortcut()) {
            shortcuts
                .unregister(shortcut())
                .map_err(|e| e.to_string())?;
        }
    }
    Ok(())
}

#[tauri::command]
pub(crate) async fn app_set_global_hotkey(
    app: tauri::AppHandle,
    enabled: bool,
) -> Result<(), String> {
    register(&app, enabled)?;
    let path = path()?;
    let value = if enabled { b"1" } else { b"0" };
    if std::fs::read(&path).ok().as_deref() != Some(value) {
        crate::fsutil::ensure_dir_secure(path.parent().expect("app data parent"))
            .map_err(|e| e.to_string())?;
        crate::fsutil::atomic_write(&path, value, 0o600).map_err(|e| e.to_string())?;
    }
    Ok(())
}

#[tauri::command]
pub(crate) fn app_take_quick_connect(state: tauri::State<QuickConnect>) -> bool {
    state.0.swap(false, Ordering::SeqCst)
}
