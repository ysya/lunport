mod config;
mod error;
mod fsutil;

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
        .invoke_handler(tauri::generate_handler![app_platform])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
