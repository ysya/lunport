pub mod write_policy;
pub mod app_profile;
#[cfg(target_os = "macos")]
mod about;
mod agent;
pub mod askpass;
pub mod cli;
mod sync;
mod config;
mod connect;
mod connection_probe;
mod deploy;
mod discover;
mod diagnostics;
mod error;
mod fsutil;
pub mod host_start;
mod ipc;
mod keys;
mod known_hosts;
#[cfg(target_os = "macos")]
pub mod macos_health;
pub mod mcp;
mod process;
mod quick_connect;
mod secrets;
mod session;
mod settings_io;
mod ssh;
mod state;
mod tray;
mod updater_channel;
pub mod vault;

use agent::prompt::{agent_pending, agent_resolve};
use agent::{agent_fix_include, agent_problem};
use config::commands::*;
use config::intel::{config_effective, config_jump_chain, config_key_hygiene, config_lint};
use connect::{connect_launch, connect_list_terminals};
use deploy::{
    deploy_key, deploy_precheck_host_key, deploy_preflight, deploy_trust_host_key, secrets_delete,
    secrets_get, secrets_has, secrets_set,
};
use keys::{keys_agent_status, keys_deploy, keys_git_ssh_hint, keys_list, keys_read_public};
use known_hosts::{known_hosts_list, known_hosts_remove};
use mcp::{mcp_set_approval_mode, mcp_resolve_request, mcp_set_enabled, mcp_set_host_allowed, mcp_status};
use session::hostkey_window::{hostkey_pending, hostkey_resolve};
use settings_io::{settings_export, settings_import};
use sync::engine::{
    sync_approve, sync_cancel_sync_code_change, sync_change_sync_code, sync_check_relay,
    sync_create_account, sync_create_space, sync_delete_space, sync_dismiss_notice,
    sync_forget_device, sync_join_account, sync_key_candidates, sync_key_delete_copy,
    sync_key_export_private, sync_key_generate, sync_key_import_file, sync_key_import_text,
    sync_key_move_all_into_vault, sync_key_pick, sync_key_preview_file, sync_key_set_delivery,
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

#[tauri::command]
fn app_is_development() -> bool {
    app_profile::CURRENT == app_profile::AppProfile::Development
}

#[tauri::command]
fn app_home_dir() -> Result<String, error::AppError> {
    Ok(fsutil::home_dir()?.to_string_lossy().into_owned())
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
/// - `host`: started with `--host` (or the older `--mcp-host`) by a client that needed it: the
///   stdio MCP adapter or `sshelter connect` (`host_start`). Closing the window hides it instead
///   of ending what the clients are using. (When Lunport already runs, such a launch hands over
///   without showing a window: `second_launch_shows_window`.)
/// - `start_hidden`: see `starts_hidden`. A client's start runs in the background: no window
///   until the user opens it or something needs the user (an MCP approval, a host key).
pub fn run_desktop(host: bool, start_hidden: bool) {
    run_app(host, start_hidden);
}

/// Set to `1` by a client on the Lunport it starts (host_start.rs `host_command`).
/// main.rs reads it, then removes it before anything else runs.
pub const START_HIDDEN_ENV: &str = "SSHELTER_START_HIDDEN";

/// Whether the main window starts hidden, from the value of `SSHELTER_START_HIDDEN`; nothing else
/// decides it. A restart (an update's "Install & restart") reuses the arguments, the host flag
/// included, but inherits an environment without the variable, so it comes back with its window.
pub fn starts_hidden(value: Option<&std::ffi::OsStr>) -> bool {
    value == Some(std::ffi::OsStr::new("1"))
}

/// Show, unminimize and focus the main window.
pub(crate) fn show_main_window(app: &tauri::AppHandle) {
    #[cfg(target_os = "macos")]
    {
        macos_health::request(app, macos_health::Surface::Main);
    }
    #[cfg(not(target_os = "macos"))]
    show_main_window_now(app);
}

pub(crate) fn show_main_window_now(app: &tauri::AppHandle) {
    if app.get_webview_window("main").is_none() {
        let Some(config) = app.config().app.windows.iter().find(|w| w.label == "main") else { return; };
        if let Err(error) = tauri::WebviewWindowBuilder::from_config(app, config).and_then(|w| w.build()) {
            diagnostics::tauri_error("main_window_create_failed", &error);
            #[cfg(windows)]
            diagnostics::show_startup_failure();
            eprintln!("[window] cannot create main window: {error}");
            return;
        }
    }
    if let Some(window) = app.get_webview_window("main") {
        let _ = window.show();
        let _ = window.unminimize();
        let _ = window.set_focus();
    }
}

/// Only native user activation clears the hidden-host credential gate.
pub(crate) fn show_main_window_by_user(app: &tauri::AppHandle) {
    app.state::<state::AppState>().background_credentials_only.store(false, std::sync::atomic::Ordering::SeqCst);
    show_main_window(app);
}

/// What a second launch does in the running Lunport. `args` are the second process's
/// arguments, executable path first, so its mode is `args[1]` (as in main.rs). A host launch
/// means a client could not reach this instance: it needs the bridge or the socket, not a
/// window. Any other launch is the user opening Lunport again.
#[cfg(desktop)]
fn second_launch_shows_window(args: &[String]) -> bool {
    !args.get(1).is_some_and(|mode| host_start::is_host_flag(mode))
}

/// The single-instance plugin stopped a second launch before it started anything and handed
/// its arguments to this instance.
#[cfg(desktop)]
fn on_second_launch(app: &tauri::AppHandle, args: Vec<String>, _cwd: String) {
    #[cfg(target_os = "macos")]
    if args.get(1).is_some_and(|mode| mode == "--window-diagnostics") {
        macos_health::request(app, macos_health::Surface::Diagnostics);
        return;
    }
    if second_launch_shows_window(&args) {
        show_main_window_by_user(app);
    } else {
        mcp::republish_bridge(app);
        session::app::start(app);
    }
}

fn run_app(host: bool, start_hidden: bool) {
    diagnostics::install();
    diagnostics::stage(diagnostics::Stage::Context);
    let context = tauri::generate_context!();
    // macOS must check CoreAudio before WKWebView. Windows must catch WebView2 creation
    // errors explicitly: Tauri's automatic Ready-time creation turns them into a panic.
    #[cfg(any(target_os = "macos", windows))]
    let context = {
        let mut context = context;
        for window in &mut context.config_mut().app.windows {
            window.create = false;
        }
        context
    };
    app_profile::CURRENT.verify_configuration(
        &context.config().identifier,
        context.config().product_name.as_deref(),
    ).expect("Lunport profile configuration mismatch");
    let builder = tauri::Builder::default();
    #[cfg(target_os = "macos")]
    let builder = builder
        .menu(about::menu)
        .manage(macos_health::HealthState::default())
        .on_web_content_process_terminate(macos_health::web_content_terminated)
        .on_menu_event(|app, event| {
            if event.id().as_ref() == "window-diagnostics" {
                macos_health::request(app, macos_health::Surface::Diagnostics);
            }
        });
    // Only one Lunport runs at a time: a second launch hands over to the running instance and
    // exits during plugin setup, before any window, the MCP bridge (and its runtime file), the
    // sync engine or the SSH agent starts. It must be the first plugin registered.
    // Each build profile has its own identifier and single-instance namespace.
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
        builder = builder.manage(updater_channel::PendingBetaUpdate::default());
        if app_profile::CURRENT.allows_os_integrations() {
            builder = builder
                .plugin(tauri_plugin_updater::Builder::new().build())
                .plugin(tauri_plugin_autostart::Builder::new()
                    .app_name(app_profile::CURRENT.autostart_name())
                    .build());
        }
        builder = builder
            // Global quick-connect hotkey; registration is driven from the
            // frontend (`useGlobalHotkey`) via the JS plugin API.
            .plugin(tauri_plugin_global_shortcut::Builder::new().build());
    }
    diagnostics::stage(diagnostics::Stage::Window);
    let application = builder
        .manage(state::AppState::default())
        .manage(tray::TrayState::default())
        .manage(quick_connect::QuickConnect::default())
        .setup(move |app| {
            diagnostics::stage(diagnostics::Stage::Setup);
            app.state::<state::AppState>().background_credentials_only.store(host && start_hidden,std::sync::atomic::Ordering::SeqCst);
            // Publish the initial native tray before any worker can request an update.
            // A missing/unavailable notification area must not prevent the main UI from opening.
            diagnostics::stage(diagnostics::Stage::Tray);
            if let Err(error) = tray::rebuild_tray(app.handle(), &[]) {
                diagnostics::tauri_error("tray_initialization_failed", &error);
                eprintln!("[tray] initial menu unavailable: {error}");
            }
            diagnostics::stage(diagnostics::Stage::Sync);
            sync::engine::initialize(app.handle())?;
            diagnostics::stage(diagnostics::Stage::Mcp);
            mcp::initialize(app.handle(), host)?;
            // Lunport 的 SSH agent(金鑰保管庫 spec §5.1):開不起來只記在 `AgentRuntime::status`,不擋啟動。
            if sync::engine::require_legacy(&app.state::<state::AppState>().sync).is_ok() { agent::start(app.handle()); }
            // The session broker that `sshelter connect` talks to (own-ssh spec §4, §7): a failure is recorded, it does not stop the app.
            diagnostics::stage(diagnostics::Stage::Broker);
            session::app::start(app.handle());
            quick_connect::initialize(app.handle());
            #[cfg(target_os = "macos")]
            macos_health::install_diagnostics_menu(app.handle())?;
            if !start_hidden {
                #[cfg(target_os = "macos")]
                if std::env::args_os().nth(1).as_deref() == Some(std::ffi::OsStr::new("--window-diagnostics")) {
                    macos_health::request(app.handle(), macos_health::Surface::Diagnostics);
                    return Ok(());
                }
                #[cfg(windows)]
                diagnostics::stage(diagnostics::Stage::Window);
                show_main_window(app.handle());
            }
            diagnostics::stage(diagnostics::Stage::Ready);
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
            // The host key window (own-ssh spec §10): closing it refuses every key it was asking about.
            if window.label() == session::auth_window::AUTH_WINDOW {
                if let tauri::WindowEvent::CloseRequested { .. } = event {window.app_handle().state::<state::AppState>().session.auth_questions.deny_all();}
                return;
            }
            if window.label() == session::hostkey_window::HOSTKEY_WINDOW {
                if let tauri::WindowEvent::CloseRequested { .. } = event {
                    window.app_handle().state::<state::AppState>().session.host_keys.deny_all();
                }
                return;
            }
            // 視窗在前景時以一般間隔輪詢、回到前景立刻同步一輪(同步退避期間要等退避結束,spec §6.4);不在前景時省 relay 的配額(Sync v2)。
            if let tauri::WindowEvent::Focused(focused) = event {
                sync::engine::window_focused(window.app_handle(), *focused);
            }
            if let tauri::WindowEvent::CloseRequested { api, .. } = event {
                let state = window.app_handle().state::<state::AppState>();
                // Open sessions keep the app running too: quitting would end them (own-ssh spec §4).
                if session::app::hides_on_close(
                    state.close_to_tray.load(std::sync::atomic::Ordering::Relaxed),
                    state.mcp.keep_alive.load(std::sync::atomic::Ordering::Relaxed),
                    session::app::has_sessions(window.app_handle()),
                ) {
                    // Hide to tray instead of quitting; the tray "Open Lunport" item
                    // (show + set_focus) brings it back.
                    api.prevent_close();
                    let _ = window.hide();
                }
            }
        })
        .invoke_handler(tauri::generate_handler![
            app_platform,
            diagnostics::app_open_diagnostics,
            app_is_development,
            quick_connect::app_set_global_hotkey,
            quick_connect::app_take_quick_connect,
            app_home_dir,
            app_set_close_to_tray,
            updater_check_beta,
            updater_install_beta,
            sync::central::commands::central_devices,
            sync::central::commands::central_pairing_code,
            sync::central::commands::central_approve_device,
            sync::central::commands::central_status,
            sync::central::commands::central_sign_in,
            sync::central::commands::central_cancel_sign_in,
            sync::central::commands::central_refresh,
            sync::central::commands::central_sign_out,
            sync::central::commands::central_prepare_vault,
            sync::central::commands::central_reveal_recovery,
            sync::central::commands::central_confirm_recovery,
            sync::record_commands::records_status,
            sync::record_commands::records_conflict_resolve,
            sync::record_commands::records_group_create,
            sync::record_commands::records_group_order,
            sync::record_commands::records_group_update,
            sync::record_commands::records_group_delete,
            sync::record_commands::records_host_create,
            sync::record_commands::records_host_update,
            sync::record_commands::records_host_delete,
            sync::record_commands::records_host_move,
            sync::record_commands::records_host_group,
            sync::record_commands::records_sync_now,
            sync::record_commands::records_use_legacy,
            sync::record_commands::records_pause_legacy,
            sync::record_commands::records_connect,
            connection_probe::records_host_probe,
            sync::record_commands::records_import_preview,
            sync::record_commands::records_import_confirm,
            sync::record_commands::records_import_cancel,
            sync::record_commands::records_import_resume,
            sync::record_commands::records_import_pending,
            sync::record_commands::records_set_relay_url,
            sync::record_commands::records_account_words,
            sync::record_commands::records_account_create,
            sync::record_commands::records_library_preview,
            sync::record_commands::records_host_verify_key,
            sync::record_commands::records_host_forget_key,
            sync::record_commands::records_library_enable,
            sync::record_commands::records_account_join,
            sync::record_commands::records_account_resume,
            sync::record_commands::records_account_leave,
            sync::record_commands::records_account_rotate,
            sync::record_commands::records_space_create,
            sync::record_commands::records_space_select,
            sync::record_commands::records_key_import,
            sync::record_commands::records_key_import_file,
            sync::record_commands::records_key_generate,
            sync::record_commands::records_key_rename,
            sync::record_commands::records_key_download,
            sync::record_commands::records_key_sync,
            session::deploy::records_deploy_preview,
            session::deploy::records_deploy_confirm,
            session::deploy::records_deploy_cancel,
            sync::record_commands::records_migration_preview,
            sync::record_commands::records_migration_confirm,
            sync::record_commands::records_migration_cancel,
            sync::record_commands::records_migration_resume,
            sync::record_commands::records_migration_pending,
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
            mcp_set_approval_mode,
            session::auth_window::auth_pending,
            session::auth_window::auth_resolve,
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
            sync_key_import_text,
            sync_key_import_file,
            sync_key_preview_file,
            sync_key_generate,
            sync_change_sync_code,
            sync_cancel_sync_code_change,
            sync_rejoin_account,
            sync_duplicate_aliases,
            sync_resolve_shadowed,
            agent_pending,
            agent_resolve,
            agent_problem,
            agent_fix_include,
            hostkey_pending,
            hostkey_resolve,
        ])
        .build(context);
    let application = match application {
        Ok(app) => app,
        Err(error) => {
            diagnostics::tauri_error("gui_build_failed", &error);
            #[cfg(windows)]
            if !start_hidden { diagnostics::show_startup_failure(); }
            eprintln!("[startup] could not build application: {error}");
            return;
        }
    };
    application.run(|app, event| match event {
            // macOS: clicking Lunport in the Dock or opening it from Finder while it runs starts
            // no second process; it sends Reopen. Bring back the window, even a hidden one.
            #[cfg(target_os = "macos")]
            tauri::RunEvent::Reopen { .. } => show_main_window_by_user(app),
            tauri::RunEvent::Exit => {
                diagnostics::stage(diagnostics::Stage::Exit);
                mcp::forget_bridge(app);
                // Quitting ends every session; each terminal is told why (own-ssh spec §4).
                session::app::quit(app);
            }
            _ => {}
        });
}

#[cfg(all(test, desktop))]
mod tests {
    use super::*;

    const EXE: &str = "/Applications/Lunport.app/Contents/MacOS/sshelter";

    /// The decision for a second launch with these arguments.
    fn shows(list: &[&str]) -> bool {
        let args: Vec<String> = list.iter().map(|s| s.to_string()).collect();
        second_launch_shows_window(&args)
    }

    #[test]
    fn a_second_host_launch_shows_no_window_with_the_new_flag_or_the_old_one() {
        assert!(!shows(&[EXE, "--host"]));
        assert!(!shows(&[EXE, "--mcp-host"]));
        assert!(!shows(&[r"C:\Lunport\sshelter.exe", "--host"]));
    }

    #[test]
    fn any_other_second_launch_shows_the_window() {
        assert!(shows(&[EXE]));
        assert!(shows(&[]));
        // Same rule as main.rs: only the first argument picks the mode.
        assert!(shows(&[EXE, "--other", "--host"]));
        assert!(shows(&[EXE, "--mcp"]));
        assert!(shows(&[EXE, "connect", "web"]));
        assert!(shows(&[EXE, "--host=1"]));
    }

    #[test]
    fn only_the_hidden_start_variable_starts_the_window_hidden() {
        use std::ffi::OsStr;
        assert!(starts_hidden(Some(OsStr::new("1"))));
        assert!(!starts_hidden(None));
        assert!(!starts_hidden(Some(OsStr::new(""))));
        assert!(!starts_hidden(Some(OsStr::new("0"))));
        assert!(!starts_hidden(Some(OsStr::new("true"))));
    }

    /// A normal launch, a client's start (the MCP adapter's, `sshelter connect`'s) and its restart
    /// after an update: visible, hidden, visible. The environments are what each start sees;
    /// main.rs removes the variable.
    #[test]
    fn a_restart_of_a_client_started_sshelter_shows_its_window() {
        use std::collections::HashMap;
        use std::ffi::OsStr;
        let hidden =
            |env: &HashMap<&str, &str>| starts_hidden(env.get(START_HIDDEN_ENV).map(OsStr::new));

        let normal_launch = HashMap::new();
        assert!(!hidden(&normal_launch));

        // host_start.rs `host_command` sets it; main.rs reads it and then removes it from the process.
        let mut client_start = HashMap::from([(START_HIDDEN_ENV, "1")]);
        assert!(hidden(&client_start));
        client_start.remove(START_HIDDEN_ENV);

        // tauri restarts with the same arguments (`--host`) and this process's environment.
        let restart = client_start;
        assert!(!hidden(&restart));
    }
}
