mod config;
mod connect;
mod discover;
mod error;
mod fsutil;
mod state;
mod tray;

use config::commands::*;
use config::intel::{config_effective, config_jump_chain, config_key_hygiene, config_lint};
use connect::{connect_launch, connect_list_terminals};
use tauri::Manager;
use tray::tray_set_visible;

/// 端到端 smoke command：回傳目前作業系統（"macos" / "linux" / "windows"）。
#[tauri::command]
fn app_platform() -> String {
    std::env::consts::OS.to_string()
}

/// 設定「關閉視窗時收進系統匣（隱藏）而非結束程式」。
#[tauri::command]
fn app_set_close_to_tray(
    state: tauri::State<state::AppState>,
    enabled: bool,
) -> Result<(), error::AppError> {
    state
        .close_to_tray
        .store(enabled, std::sync::atomic::Ordering::Relaxed);
    Ok(())
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    let mut builder = tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_os::init())
        .plugin(tauri_plugin_process::init());
    // The updater plugin is desktop-only (the crate is a desktop-target dependency).
    #[cfg(desktop)]
    {
        builder = builder.plugin(tauri_plugin_updater::Builder::new().build());
    }
    builder
        .manage(state::AppState::default())
        .setup(|app| {
            tray::rebuild_tray(app.handle(), &[])?;
            Ok(())
        })
        .on_window_event(|window, event| {
            if let tauri::WindowEvent::CloseRequested { api, .. } = event {
                let state = window.app_handle().state::<state::AppState>();
                if state
                    .close_to_tray
                    .load(std::sync::atomic::Ordering::Relaxed)
                {
                    // Hide to tray instead of quitting; the tray "Open SSHelter" item
                    // (show + set_focus) brings it back.
                    api.prevent_close();
                    let _ = window.hide();
                }
            }
        })
        .invoke_handler(tauri::generate_handler![
            app_platform,
            app_set_close_to_tray,
            config_load,
            config_list_files,
            config_get_host,
            config_save_host,
            config_add_host,
            config_remove_host,
            config_rename_host,
            config_set_option_enabled,
            config_set_tags,
            config_reorder_hosts,
            config_check_drift,
            config_set_backup_retention,
            discover_hosts,
            config_list_backups,
            config_restore_backup,
            connect_list_terminals,
            connect_launch,
            config_effective,
            config_lint,
            config_jump_chain,
            config_key_hygiene,
            tray_set_visible,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
