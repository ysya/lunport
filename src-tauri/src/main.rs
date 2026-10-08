// Prevents additional console window on Windows in release, DO NOT REMOVE!!
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    // SSH_ASKPASS helper 模式：ssh 會用這支執行檔再次啟動我們來要密碼。
    // 必須在任何 Tauri 初始化「之前」攔截，helper 模式完全不開 GUI。
    if std::env::var_os("SSHELTER_ASKPASS").is_some() {
        sshelter_lib::askpass::run();
    }

    // MCP adapter 啟動 SSHelter 時設 SSHELTER_START_HIDDEN=1，主視窗先不顯示。讀完就從環境移除，
    // 趁行程還只有這一個執行緒（Tauri 還沒啟動，edition 2021 的 remove_var 不需要 unsafe）：
    // 重新啟動（例如更新的「Install & restart」）沿用同樣的參數與這個環境，要帶著視窗回來。
    let start_hidden =
        sshelter_lib::starts_hidden(std::env::var_os(sshelter_lib::START_HIDDEN_ENV).as_deref());
    std::env::remove_var(sshelter_lib::START_HIDDEN_ENV);

    match std::env::args().nth(1).as_deref() {
        Some("--mcp") => sshelter_lib::mcp::run_stdio(),
        Some(sshelter_lib::mcp::HOST_FLAG) => sshelter_lib::run_desktop(true, start_hidden),
        _ => sshelter_lib::run_desktop(false, start_hidden),
    }
}
