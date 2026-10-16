//! Real Win32 tray/event-loop regression. No WebView, real credentials or remote relay.
use super::*;
use crate::sync::{
    record_groups, record_library, record_repository as repo, record_runtime, records_v3::*,
};
use std::sync::Arc;

#[test]
#[ignore = "requires a Windows desktop and its own native event loop; run separately in CI"]
fn synced_library_startup_and_concurrent_tray_updates() {
    let device = crate::sync::record_round::tests::pin_fixture();
    record_runtime::mutate_records(&device.env(), |state| {
        let mut next = record_groups::create_group(
            state, "ffffffffffffffff", HostScope::Local,
            serde_json::from_value(serde_json::json!({"schema":1,"name":"Synced Group","defaults":{"user":"ops"}})).unwrap(),
            true, 10,
        ).map_err(|e| AppError::Other(e.to_string()))?;
        for i in 2..=17 {
            next = repo::create_host(
                &next, &format!("{i:016x}"), HostScope::Local,
                serde_json::from_value(serde_json::json!({"schema":3,"alias":format!("host-{i} 雲端"),"hostname":"fixture.invalid","auth":"password","group_id":"ffffffffffffffff","inherit":["user"]})).unwrap(),
                11,
            ).map_err(|e| AppError::Other(e.to_string()))?;
        }
        Ok(next)
    }).unwrap();
    record_library::enable(&device.env(), true).unwrap();
    crate::sync::record_round::sync_once(&device.env()).unwrap();
    let config_before = std::fs::read(device.main_path()).unwrap();
    let state_before = std::fs::read(&device.env().state_path).unwrap();

    // Restart from the saved, grouped, opted-in library rather than a synthetic menu alone.
    let app_state = AppState::default();
    {
        let probe = record_runtime::probe_startup(&device.env().state_path, "Windows restart");
        let mut core = app_state.sync.core.lock().unwrap();
        record_runtime::activate_probe(&mut core, probe).unwrap();
        let records = record_runtime::active_state(&core).unwrap();
        core.account_keys = record_runtime::read_account_keys(records, &device.keychain).unwrap();
    }
    assert_eq!(
        std::fs::read(&device.env().state_path).unwrap(),
        state_before
    );

    let mut context = tauri::generate_context!();
    // Menus use real Win32 HWNDs. WebView2 and all production startup plugins are deliberately absent.
    context.config_mut().app.windows.clear();
    let (done_tx, done_rx) = mpsc::channel();
    let fixture = Arc::clone(&device);
    let app = tauri::Builder::default()
        .any_thread()
        .manage(app_state)
        .manage(crate::tray::TrayState::default())
        .setup(move |app| {
            let handle = app.handle().clone();
            let watchdog = handle.clone();
            let (stop_tx, stop_rx) = mpsc::channel();
            std::thread::spawn(move || {
                if stop_rx.recv_timeout(Duration::from_secs(90)).is_err() {
                    watchdog.exit(2);
                }
            });
            std::thread::spawn(move || {
                let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    exercise(&handle, &fixture)
                }));
                let code = if outcome.is_ok() { 0 } else { 1 };
                let _ = stop_tx.send(());
                let _ = done_tx.send(outcome);
                handle.exit(code);
            });
            // Race the first background status with the same initial publication used by setup.
            crate::tray::rebuild_tray(app.handle(), &[])?;
            Ok(())
        })
        .build(context)
        .unwrap();
    assert_eq!(app.run_return(|_, _| {}), 0);
    if let Err(panic) = done_rx.recv_timeout(Duration::from_secs(5)).unwrap() {
        std::panic::resume_unwind(panic);
    }
    assert_eq!(std::fs::read(device.main_path()).unwrap(), config_before);
    let saved = record_runtime::probe_startup(&device.env().state_path, "after sync");
    assert!(matches!(
        saved,
        record_runtime::StartupProbe::Records { .. }
    ));
}

fn exercise(app: &AppHandle, device: &crate::sync::testkit::TestDevice) {
    let state = app.state::<AppState>();
    let events = TauriEvents { app: app.clone() };
    let mut env = device.env();
    env.runtime = &state.sync;
    env.events = &events;
    events.status();
    let before = crate::tray::test_publications(app);
    assert_eq!(before, 2, "one initial menu and one records menu");
    let user_before = user_objects(app);

    // Background status callbacks and visibility commands used to clone/drop the same
    // Rc-backed native TrayIcon on different threads. Keep the native loop active throughout.
    let workers: Vec<_> = (0..3)
        .map(|_| {
            let app = app.clone();
            std::thread::spawn(move || {
                for i in 0..100 {
                    TauriEvents { app: app.clone() }.status();
                    crate::tray::tray_set_visible(app.clone(), app.state::<AppState>(), i % 2 == 0)
                        .unwrap();
                }
            })
        })
        .collect();
    for _ in 0..10 {
        let report = crate::sync::record_round::sync_once(&env).unwrap();
        assert_eq!(
            report.gate,
            Some(crate::sync::record_merge::AccountGate::Compatible)
        );
    }
    for worker in workers {
        worker.join().unwrap();
    }
    assert_eq!(
        crate::tray::test_publications(app),
        before,
        "activity-only updates must allocate no new native menus"
    );

    record_runtime::mutate_records(&env, |s| {
        let host = repo::get_host(s, "0000000000000002").unwrap();
        let mut payload = host.host.payload;
        payload.alias = "renamed".into();
        repo::update_host(s, &host.host.id, &host.revision, payload, env.now())
            .map_err(|e| AppError::Other(e.to_string()))
    })
    .unwrap();
    events.status();
    assert_eq!(crate::tray::test_publications(app), before + 1);
    crate::tray::test_assert_menu(app, "renamed");
    let user_after = user_objects(app);
    assert!(
        user_after <= user_before + 8,
        "USER objects grew from {user_before} to {user_after}"
    );
    println!("Windows native startup: 17 synced hosts + inherited Group; 10 transport rounds; 300 concurrent status/visibility pairs; menu publications {before} -> {}; USER objects {user_before} -> {user_after}; SSH config unchanged", crate::tray::test_publications(app));
}

fn user_objects(app: &AppHandle) -> u32 {
    #[link(name = "user32")]
    unsafe extern "system" {
        fn GetGuiResources(process: *mut std::ffi::c_void, flags: u32) -> u32;
    }
    let (tx, rx) = mpsc::channel();
    app.run_on_main_thread(move || {
        let count = unsafe {
            GetGuiResources(
                windows_sys::Win32::System::Threading::GetCurrentProcess(),
                1,
            )
        };
        tx.send(count).unwrap();
    })
    .unwrap();
    let count = rx.recv_timeout(Duration::from_secs(10)).unwrap();
    assert!(count > 0);
    count
}
