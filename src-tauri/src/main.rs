// Prevents additional console window on Windows in release, DO NOT REMOVE!!
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    // SSH_ASKPASS helper 模式：ssh 會用這支執行檔再次啟動我們來要密碼。
    // 必須在任何 Tauri 初始化「之前」攔截，helper 模式完全不開 GUI。
    if std::env::var_os("SSHELTER_ASKPASS").is_some() {
        sshelter_lib::askpass::run();
    }

    match std::env::args().nth(1).as_deref() {
        Some("--mcp") => sshelter_lib::mcp::run_stdio(),
        Some("--mcp-host") => sshelter_lib::run_mcp_host(),
        _ => sshelter_lib::run(),
    }
}
