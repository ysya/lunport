mod config;
mod error;
mod fsutil;
mod state;

use config::commands::*;

/// 端到端 smoke command：回傳目前作業系統（"macos" / "linux" / "windows"）。
#[tauri::command]
fn app_platform() -> String {
    std::env::consts::OS.to_string()
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_os::init())
        .manage(state::AppState::default())
        .invoke_handler(tauri::generate_handler![
            app_platform,
            config_load,
            config_list_files,
            config_get_host,
            config_save_host,
            config_add_host,
            config_remove_host,
            config_set_option_enabled,
            config_set_tags,
            config_reorder_hosts,
            config_check_drift,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
