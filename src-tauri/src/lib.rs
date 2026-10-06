mod agent;
pub mod askpass;
mod sync;
mod config;
mod connect;
mod deploy;
mod discover;
mod error;
mod fsutil;
mod keys;
mod known_hosts;
pub mod mcp;
mod process;
mod secrets;
mod settings_io;
mod state;
mod tray;
mod updater_channel;
mod vault;

use agent::prompt::{agent_pending, agent_resolve};
use config::commands::*;
use config::intel::{config_effective, config_jump_chain, config_key_hygiene, config_lint};
use connect::{connect_launch, connect_list_terminals};
use deploy::{
    deploy_key, deploy_precheck_host_key, deploy_preflight, deploy_trust_host_key, secrets_delete,
    secrets_get, secrets_has, secrets_set,
};
use keys::{
    keys_agent_status, keys_deploy, keys_generate, keys_generate_in_terminal, keys_list,
    keys_read_public,
};
use known_hosts::{known_hosts_list, known_hosts_remove};
use mcp::{mcp_resolve_request, mcp_set_enabled, mcp_set_host_allowed, mcp_status};
use settings_io::{settings_export, settings_import};
use sync::engine::{
    sync_approve, sync_cancel_sync_code_change, sync_change_sync_code, sync_check_relay,
    sync_create_account, sync_create_space, sync_delete_space, sync_dismiss_notice,
    sync_forget_device, sync_join_account, sync_key_candidates, sync_key_delete_copy,
    sync_key_pick, sync_key_set_mode, sync_key_use_synced, sync_leave_account,
    sync_move_files_to_new_spaces, sync_move_hosts_to_space, sync_now, sync_overview,
    sync_pending_approvals, sync_rebuild_space, sync_reject, sync_rejoin_account,
    sync_rename_space, sync_select_space, sync_set_device_name, sync_set_relay_url,
    sync_setup_keys, sync_show_words, sync_unmovable_hosts, sync_unselect_space,
};
use sync::migrate::{sync_duplicate_aliases, sync_resolve_shadowed};
use tauri::Manager;
use tray::tray_set_visible;
use updater_channel::{updater_check_beta, updater_install_beta};

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
    run_app(false);
}

/// Start the desktop approval center on behalf of a stdio MCP adapter.
/// Closing the window hides it instead of terminating active MCP access.
pub fn run_mcp_host() {
    run_app(true);
}

fn run_app(mcp_keep_alive: bool) {
    let mut builder = tauri::Builder::default()
        .plugin(tauri_plugin_clipboard_manager::init())
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_os::init())
        .plugin(tauri_plugin_process::init())
        .plugin(tauri_plugin_dialog::init());
    // Desktop-only plugins (the crates are desktop-target dependencies).
    #[cfg(desktop)]
    {
        builder = builder
            .plugin(tauri_plugin_updater::Builder::new().build())
            // Beta 頻道暫存的更新(`PendingBetaUpdate` 只在桌面平台存在,所以在這裡才 manage)。
            .manage(updater_channel::PendingBetaUpdate::default())
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
        .setup(move |app| {
            mcp::initialize(app.handle(), mcp_keep_alive)?;
            sync::engine::initialize(app.handle())?;
            tray::rebuild_tray(app.handle(), &[])?;
            Ok(())
        })
        .on_window_event(|window, event| {
            // 視窗在前景時以一般間隔輪詢、回到前景立刻同步一輪(同步退避期間要等退避結束,spec §6.4);不在前景時省 relay 的配額(Sync v2)。
            if let tauri::WindowEvent::Focused(focused) = event {
                sync::engine::window_focused(window.app_handle(), *focused);
            }
            if let tauri::WindowEvent::CloseRequested { api, .. } = event {
                let state = window.app_handle().state::<state::AppState>();
                if state
                    .close_to_tray
                    .load(std::sync::atomic::Ordering::Relaxed)
                    || state
                        .mcp
                        .keep_alive
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
            updater_check_beta,
            updater_install_beta,
            config_load,
            config_list_files,
            config_plan_new_file,
            config_create_file,
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
            deploy_preflight,
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
            mcp_status,
            mcp_set_enabled,
            mcp_set_host_allowed,
            mcp_resolve_request,
            sync_overview,
            sync_now,
            sync_create_account,
            sync_join_account,
            sync_leave_account,
            sync_show_words,
            sync_set_relay_url,
            sync_check_relay,
            sync_set_device_name,
            sync_forget_device,
            sync_create_space,
            sync_rename_space,
            sync_delete_space,
            sync_select_space,
            sync_unselect_space,
            sync_rebuild_space,
            sync_pending_approvals,
            sync_approve,
            sync_reject,
            sync_dismiss_notice,
            sync_move_hosts_to_space,
            sync_move_files_to_new_spaces,
            sync_unmovable_hosts,
            sync_key_candidates,
            sync_setup_keys,
            sync_key_set_mode,
            sync_key_pick,
            sync_key_use_synced,
            sync_key_delete_copy,
            sync_change_sync_code,
            sync_cancel_sync_code_change,
            sync_rejoin_account,
            sync_duplicate_aliases,
            sync_resolve_shadowed,
            agent_pending,
            agent_resolve,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
