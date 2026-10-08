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
use agent::{agent_fix_include, agent_problem};
use config::commands::*;
use config::intel::{config_effective, config_jump_chain, config_key_hygiene, config_lint};
use connect::{connect_launch, connect_list_terminals};
use deploy::{
    deploy_key, deploy_precheck_host_key, deploy_preflight, deploy_trust_host_key, secrets_delete,
    secrets_get, secrets_has, secrets_set,
};
use keys::{
    keys_agent_status, keys_deploy, keys_generate, keys_generate_in_terminal, keys_git_ssh_hint,
    keys_list, keys_read_public,
};
use known_hosts::{known_hosts_list, known_hosts_remove};
use mcp::{mcp_resolve_request, mcp_set_enabled, mcp_set_host_allowed, mcp_status};
use settings_io::{settings_export, settings_import};
use sync::engine::{
    sync_approve, sync_cancel_sync_code_change, sync_change_sync_code, sync_check_relay,
    sync_create_account, sync_create_space, sync_delete_space, sync_dismiss_notice,
    sync_forget_device, sync_join_account, sync_key_candidates, sync_key_delete_copy,
    sync_key_export_private, sync_key_move_all_into_vault, sync_key_pick, sync_key_set_delivery,
    sync_key_set_mode, sync_key_use_synced, sync_leave_account, sync_move_files_to_new_spaces,
    sync_move_hosts_to_space, sync_now, sync_overview, sync_pending_approvals, sync_rebuild_space,
    sync_reject, sync_rejoin_account, sync_rename_space, sync_select_space, sync_set_device_name,
    sync_set_relay_url, sync_setup_keys, sync_show_words, sync_unmovable_hosts,
    sync_unselect_space,
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
    run_app(false, false);
}

/// The desktop app (main.rs).
/// - `mcp_host`: started with `--mcp-host` by a stdio MCP adapter. Closing the window hides it
///   instead of terminating active MCP access. (When SSHelter already runs, such a launch hands
///   over without showing a window: `second_launch_shows_window`.)
/// - `start_hidden`: see `starts_hidden`. The adapter's start runs in the background: no window
///   until the user opens it or an MCP `run` request needs approval.
pub fn run_desktop(mcp_host: bool, start_hidden: bool) {
    run_app(mcp_host, start_hidden);
}

/// Set to `1` by the stdio MCP adapter on the SSHelter it starts (mcp.rs `host_command`).
/// main.rs reads it, then removes it before anything else runs.
pub const START_HIDDEN_ENV: &str = "SSHELTER_START_HIDDEN";

/// Whether the main window starts hidden, from the value of `SSHELTER_START_HIDDEN`; nothing else
/// decides it. A restart (an update's "Install & restart") reuses the arguments, `--mcp-host`
/// included, but inherits an environment without the variable, so it comes back with its window.
pub fn starts_hidden(value: Option<&std::ffi::OsStr>) -> bool {
    value == Some(std::ffi::OsStr::new("1"))
}

/// Show, unminimize and focus the main window.
pub(crate) fn show_main_window(app: &tauri::AppHandle) {
    if let Some(window) = app.get_webview_window("main") {
        let _ = window.show();
        let _ = window.unminimize();
        let _ = window.set_focus();
    }
}

/// What a second launch does in the running SSHelter. `args` are the second process's
/// arguments, executable path first, so its mode is `args[1]` (as in main.rs). An MCP host
/// launch means an adapter could not reach the bridge: it needs the bridge, not a window.
/// Any other launch is the user opening SSHelter again.
#[cfg(desktop)]
fn second_launch_shows_window(args: &[String]) -> bool {
    args.get(1).map(String::as_str) != Some(mcp::HOST_FLAG)
}

/// The single-instance plugin stopped a second launch before it started anything and handed
/// its arguments to this instance.
#[cfg(desktop)]
fn on_second_launch(app: &tauri::AppHandle, args: Vec<String>, _cwd: String) {
    if second_launch_shows_window(&args) {
        show_main_window(app);
    } else {
        mcp::republish_bridge(app);
    }
}

fn run_app(mcp_host: bool, start_hidden: bool) {
    let builder = tauri::Builder::default();
    // Only one SSHelter runs at a time: a second launch hands over to the running instance and
    // exits during plugin setup, before any window, the MCP bridge (and its runtime file), the
    // sync engine or the SSH agent starts. It must be the first plugin registered.
    #[cfg(desktop)]
    let builder = builder.plugin(tauri_plugin_single_instance::init(on_second_launch));
    let mut builder = builder
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
            // The main window is created hidden (`"visible": false` in tauri.conf.json), so a
            // hidden start never flashes it. Any other start shows it before anything else
            // starts, as when it was created visible.
            if !start_hidden {
                if let Some(window) = app.get_webview_window("main") {
                    window.show()?;
                }
            }
            mcp::initialize(app.handle(), mcp_host)?;
            sync::engine::initialize(app.handle())?;
            // SSHelter 的 SSH agent(金鑰保管庫 spec §5.1):開不起來只記在 `AgentRuntime::status`,不擋啟動。
            agent::start(app.handle());
            tray::rebuild_tray(app.handle(), &[])?;
            Ok(())
        })
        .on_window_event(|window, event| {
            // SSH agent 的核准視窗(金鑰保管庫 spec §7.4):關掉它就是拒絕等待中的請求;它的焦點與同步的輪詢無關。
            if window.label() == agent::prompt::APPROVAL_WINDOW {
                if let tauri::WindowEvent::CloseRequested { .. } = event {
                    window.app_handle().state::<state::AppState>().agent.prompts.deny_all();
                }
                return;
            }
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
            config_set_identity_file,
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
            keys_git_ssh_hint,
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
            sync_key_set_delivery,
            sync_key_move_all_into_vault,
            sync_key_export_private,
            sync_change_sync_code,
            sync_cancel_sync_code_change,
            sync_rejoin_account,
            sync_duplicate_aliases,
            sync_resolve_shadowed,
            agent_pending,
            agent_resolve,
            agent_problem,
            agent_fix_include,
        ])
        .build(tauri::generate_context!())
        .expect("error while building tauri application")
        .run(|app, event| match event {
            // macOS: clicking SSHelter in the Dock or opening it from Finder while it runs starts
            // no second process; it sends Reopen. Bring back the window, even a hidden one.
            #[cfg(target_os = "macos")]
            tauri::RunEvent::Reopen { .. } => show_main_window(app),
            tauri::RunEvent::Exit => mcp::forget_bridge(app),
            _ => {}
        });
}

#[cfg(all(test, desktop))]
mod tests {
    use super::*;

    const EXE: &str = "/Applications/SSHelter.app/Contents/MacOS/sshelter";

    /// The decision for a second launch with these arguments.
    fn shows(list: &[&str]) -> bool {
        let args: Vec<String> = list.iter().map(|s| s.to_string()).collect();
        second_launch_shows_window(&args)
    }

    #[test]
    fn a_second_mcp_host_launch_shows_no_window() {
        assert!(!shows(&[EXE, "--mcp-host"]));
        assert!(!shows(&[r"C:\SSHelter\sshelter.exe", "--mcp-host"]));
    }

    #[test]
    fn any_other_second_launch_shows_the_window() {
        assert!(shows(&[EXE]));
        assert!(shows(&[]));
        // Same rule as main.rs: only the first argument picks the mode.
        assert!(shows(&[EXE, "--other", "--mcp-host"]));
        assert!(shows(&[EXE, "--mcp"]));
        assert!(shows(&[EXE, "--mcp-host=1"]));
    }

    #[test]
    fn only_the_adapter_flag_starts_the_window_hidden() {
        use std::ffi::OsStr;
        assert!(starts_hidden(Some(OsStr::new("1"))));
        assert!(!starts_hidden(None));
        assert!(!starts_hidden(Some(OsStr::new(""))));
        assert!(!starts_hidden(Some(OsStr::new("0"))));
        assert!(!starts_hidden(Some(OsStr::new("true"))));
    }

    /// A normal launch, the adapter's start and its restart after an update: visible, hidden,
    /// visible. The environments are what each start sees; main.rs removes the variable.
    #[test]
    fn a_restart_of_an_adapter_started_sshelter_shows_its_window() {
        use std::collections::HashMap;
        use std::ffi::OsStr;
        let hidden =
            |env: &HashMap<&str, &str>| starts_hidden(env.get(START_HIDDEN_ENV).map(OsStr::new));

        let normal_launch = HashMap::new();
        assert!(!hidden(&normal_launch));

        // mcp.rs `host_command` sets it; main.rs reads it and then removes it from the process.
        let mut adapter_start = HashMap::from([(START_HIDDEN_ENV, "1")]);
        assert!(hidden(&adapter_start));
        adapter_start.remove(START_HIDDEN_ENV);

        // tauri restarts with the same arguments (`--mcp-host`) and this process's environment.
        let restart = adapter_start;
        assert!(!hidden(&restart));
    }
}
