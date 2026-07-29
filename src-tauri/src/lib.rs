pub mod askpass;
mod config;
mod connect;
mod deploy;
mod discover;
mod error;
mod fsutil;
mod keys;
mod known_hosts;
mod secrets;
mod settings_io;
mod state;
mod tray;

use config::commands::*;
use config::intel::{config_effective, config_jump_chain, config_key_hygiene, config_lint};
use connect::{connect_launch, connect_list_terminals};
use deploy::{
    deploy_key, deploy_precheck_host_key, deploy_trust_host_key, secrets_delete, secrets_get,
    secrets_has, secrets_set,
};
use keys::{
    keys_agent_status, keys_deploy, keys_generate, keys_generate_in_terminal, keys_list,
    keys_read_public,
};
use known_hosts::{known_hosts_list, known_hosts_remove};
use settings_io::{settings_export, settings_import};
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
        .plugin(tauri_plugin_process::init())
        .plugin(tauri_plugin_dialog::init());
    // Desktop-only plugins (the crates are desktop-target dependencies).
    #[cfg(desktop)]
    {
        builder = builder
            .plugin(tauri_plugin_updater::Builder::new().build())
            // Launch-at-login. macOS uses a LaunchAgent (no AppleScript); no
            // extra args are passed to the binary on autostart.
            .plugin(tauri_plugin_autostart::init(
                tauri_plugin_autostart::MacosLauncher::LaunchAgent,
                None,
            ))
            // Global quick-connect hotkey; registration is driven from the
            // frontend (`useGlobalHotkey`) via the JS plugin API.
            .plugin(tauri_plugin_global_shortcut::Builder::new().build());
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
            config_move_host,
            config_duplicate_host,
            config_read_file,
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
            keys_list,
            keys_agent_status,
            keys_read_public,
            keys_generate,
            keys_generate_in_terminal,
            keys_deploy,
            deploy_precheck_host_key,
            deploy_trust_host_key,
            deploy_key,
            secrets_has,
            secrets_get,
            secrets_set,
            secrets_delete,
            known_hosts_list,
            known_hosts_remove,
            config_effective,
            config_lint,
            config_jump_chain,
            config_key_hygiene,
            tray_set_visible,
            settings_export,
            settings_import,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
