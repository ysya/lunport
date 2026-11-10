// Prevents additional console window on Windows in release, DO NOT REMOVE!!
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use lunport_lib::identity_migration::{self, Entry};

fn main() {
    // Internal, disposable CoreAudio child: no Tauri, keychain, broker or GUI initialization.
    #[cfg(target_os = "macos")]
    if std::env::args_os().nth(1).as_deref() == Some(std::ffi::OsStr::new("--coreaudio-probe")) {
        std::process::exit(lunport_lib::macos_health::probe_child());
    }
    #[cfg(target_os = "macos")]
    if std::env::args_os().nth(1).as_deref() == Some(std::ffi::OsStr::new("--check-window-health")) {
        std::process::exit(lunport_lib::macos_health::check_from_terminal());
    }
    // 用戶端（MCP adapter、`lunport connect`）在背景啟動 Lunport 時設 LUNPORT_START_HIDDEN=1，主視窗先不顯示。
    // 讀完就從環境移除，趁行程還只有這一個執行緒（Tauri 還沒啟動，edition 2021 的 remove_var 不需要 unsafe）：
    // 重新啟動（例如更新的「Install & restart」）沿用同樣的參數與這個環境，要帶著視窗回來。
    let start_hidden =
        lunport_lib::starts_hidden(std::env::var_os(lunport_lib::START_HIDDEN_ENV).as_deref());
    std::env::remove_var(lunport_lib::START_HIDDEN_ENV);

    // As `OsString`s: `std::env::args()` panics on an argument that is not UTF-8, whatever the mode.
    let args: Vec<std::ffi::OsString> = std::env::args_os().collect();
    let entry = identity_migration::entry_for(args.get(1).map(|mode| mode.as_os_str()));
    let host = entry == Entry::Desktop
        && args.get(1).and_then(|mode| mode.to_str()).is_some_and(lunport_lib::host_start::is_host_flag);
    // Every way of starting first moves what a version with the identity before the rename left, before anything could create this
    // version's data root: the bundle rename's lock, diagnostics, a client's spawn lock. When that cannot finish, the desktop app shows
    // why and `connect` and the MCP adapter say so (`identity_migration::ensure_ready`). A desktop start hidden for a client moves no
    // saved credentials that would ask the user anything.
    let migration = identity_migration::run_before_startup(entry, host && start_hidden);
    #[cfg(target_os = "macos")]
    if entry == Entry::Desktop && !migration.blocks_startup() {
        lunport_lib::macos_install::prepare_desktop_launch();
    }
    #[cfg(not(target_os = "macos"))]
    let _ = migration;

    match entry {
        // `lunport connect <alias>`: the terminal's end of a session in the app, nothing of Tauri.
        Entry::Connect => std::process::exit(lunport_lib::cli::run_connect(&args[2..])),
        Entry::Mcp => lunport_lib::mcp::run_stdio(),
        Entry::Desktop => lunport_lib::run_desktop(host, start_hidden),
    }
}
