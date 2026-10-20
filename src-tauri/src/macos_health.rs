//! A bounded, disposable CoreAudio query before using WKWebView. This detects an
//! unavailable audio service; it neither repairs that service nor proves GPU health.
use std::collections::{HashSet, VecDeque};
use std::process::{Child, Command, Stdio};
use std::sync::{Mutex, PoisonError};
use std::time::{Duration, Instant, SystemTime};
use tauri::Manager;

const PROBE_LIMIT: Duration = Duration::from_secs(2);
const POLL: Duration = Duration::from_millis(10);
const FAULT_FILE: &str = "SSHELTER_TEST_COREAUDIO_FILE";

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Surface {
    Main,
    Authentication,
    HostKey,
    Approval,
    Diagnostics,
    Reload(String),
    Terminated(String),
}

#[derive(Default)]
struct Queue {
    running: bool,
    current: Option<Surface>,
    pending: VecDeque<Surface>,
    // Never reset this on page load/heartbeat: neither proves successful drawing.
    reloads: HashSet<String>,
}

impl Queue {
    fn push(&mut self, surface: Surface) -> bool {
        if self.current.as_ref() != Some(&surface) && !self.pending.contains(&surface) {
            self.pending.push_back(surface);
        }
        if self.running {
            return false;
        }
        self.running = true;
        true
    }

    fn next(&mut self) -> Option<Surface> {
        self.current = self.pending.pop_front();
        if self.current.is_none() {
            self.running = false;
        }
        self.current.clone()
    }
}

#[derive(Default)]
pub(crate) struct HealthState(Mutex<Queue>);

/// Remains reachable when the user hides the tray, or a WebView cannot draw.
pub(crate) fn install_diagnostics_menu(app: &tauri::AppHandle) -> tauri::Result<()> {
    use tauri::menu::{MenuItem, HELP_SUBMENU_ID};
    if let Some(menu) = app.menu() {
        if let Some(help) = menu
            .get(HELP_SUBMENU_ID)
            .and_then(|item| item.as_submenu().cloned())
        {
            help.append(&MenuItem::with_id(
                app,
                "window-diagnostics",
                "Window Diagnostics…",
                true,
                None::<&str>,
            )?)?;
        }
    }
    Ok(())
}

/// Coalesce every native entry point. One worker owns at most one child and one
/// NSAlert; no UI-thread query, uncancellable query thread, or cached health pass.
pub(crate) fn request(app: &tauri::AppHandle, surface: Surface) {
    let state = app.state::<HealthState>();
    if !state
        .0
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .push(surface)
    {
        return;
    }
    let handle = app.clone();
    if let Err(error) = std::thread::Builder::new()
        .name("window-health".into())
        .spawn(move || worker(&handle))
    {
        let mut queue = state.0.lock().unwrap_or_else(PoisonError::into_inner);
        queue.running = false;
        queue.pending.clear();
        drop(queue);
        deny_interactions(app);
        // Queue a native alert without waiting on the event thread.
        let message = format!("Cannot start the window health check: {error}. Open Lunport again to retry. Existing SSH sessions keep running.");
        let _ = app.run_on_main_thread(move || {
            appkit_alert("Lunport — Window unavailable", &message, &["OK"]);
        });
    }
}

fn worker(app: &tauri::AppHandle) {
    loop {
        let surface = app
            .state::<HealthState>()
            .0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .next();
        let Some(surface) = surface else {
            return;
        };
        if let Surface::Terminated(label) = surface {
            termination_notice(app, label);
            continue;
        }
        // An authentication request can expire while another window's alert is open.
        if !still_needed(app, &surface) {
            continue;
        }
        'attempt: loop {
            let began = Instant::now();
            let result = probe();
            eprintln!(
                "[window-health] {surface:?}: {result:?}; elapsed_ms={}",
                began.elapsed().as_millis()
            );
            match result {
                Ok(()) if surface == Surface::Diagnostics => {
                    diagnostics(app, "CoreAudio responded within the deadline. This does not establish that WebKit or the GPU can draw.");
                    break;
                }
                Ok(()) => {
                    if still_needed(app, &surface) {
                        present(app, surface);
                    }
                    break;
                }
                Err(error) => {
                    let detail = error.to_string();
                    loop {
                        let answer = native_dialog(app, "Lunport — System audio unavailable", &format!(
                        "The macOS audio service did not pass the window safety check ({detail}). Lunport has paused this window to avoid an unexplained black screen.\n\nExisting SSH sessions and background services keep running. No key or host is approved by this check.\n\nRestore system audio, then choose Retry. Diagnostics explains how to collect evidence. Keep Running dismisses this attempt and refuses pending authentication/key approvals; open Lunport again to retry."
                    ), &["Retry", "Diagnostics", "Keep Running"]);
                        match answer {
                            0 => {
                                if !still_needed(app, &surface) {
                                    break 'attempt;
                                }
                                continue 'attempt;
                            }
                            1 => diagnostics(app, &detail),
                            _ => {
                                // Do not leave an invisible security prompt waiting or turn a
                                // failed health check into an implicit approval.
                                deny_interactions(app);
                                app.state::<HealthState>()
                                    .0
                                    .lock()
                                    .unwrap_or_else(PoisonError::into_inner)
                                    .pending
                                    .clear();
                                break 'attempt;
                            }
                        }
                    }
                }
            }
        }
    }
}

fn still_needed(app: &tauri::AppHandle, surface: &Surface) -> bool {
    let state = app.state::<crate::state::AppState>();
    match surface {
        Surface::Authentication => !state.session.auth_questions.pending().is_empty(),
        Surface::HostKey => !state.session.host_keys.pending().is_empty(),
        Surface::Approval => !state.agent.prompts.pending().is_empty(),
        Surface::Reload(label) => app.get_webview_window(label).is_some(),
        _ => true,
    }
}

fn present(app: &tauri::AppHandle, surface: Surface) {
    match surface {
        Surface::Main => crate::show_main_window_now(app),
        Surface::Authentication => crate::session::auth_window::present(app),
        Surface::HostKey => crate::session::hostkey_window::present(app),
        Surface::Approval => crate::agent::prompt::present(app),
        Surface::Reload(label) => {
            // A user can authorize one reload per window per app lifetime. No
            // automatic recovery loop, including when the reload immediately dies.
            let allowed = app
                .state::<HealthState>()
                .0
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .reloads
                .insert(label.clone());
            if allowed {
                if let Some(view) = app.get_webview_window(&label) {
                    if let Err(error) = view.reload() {
                        diagnostics(app, &format!("Window reload failed: {error}"));
                    }
                }
            }
        }
        Surface::Diagnostics | Surface::Terminated(_) => {}
    }
}

fn deny_interactions(app: &tauri::AppHandle) {
    let state = app.state::<crate::state::AppState>();
    deny_pending(&state);
}

fn deny_pending(state: &crate::state::AppState) {
    state.session.auth_questions.deny_all();
    state.session.host_keys.deny_all();
    state.agent.prompts.deny_all();
}

fn diagnostics(app: &tauri::AppHandle, result: &str) {
    let report = format!(
        "Lunport window health\nProfile: {:?}\nArchitecture: {}\nTime: {:?}\nProbe deadline: {} ms\nResult: {result}\n\nIn Activity Monitor, sample coreaudiod and the Lunport WebKit GPU process while the fault is present. Record the macOS version and recent sleep/wake or audio-device changes. Samples may contain private data; review before sharing.\n\nIf system audio is unavailable, save work in other apps and restart macOS, or ask your administrator to restore the audio service. Lunport does not restart system services. After audio recovers, use Retry or Open Lunport.\n\nFor a window that stays black while audio responds, keep SSH clients connected and collect a screenshot and GPU sample. A page-load event or heartbeat does not prove drawing. No automatic reload or app restart is attempted. Reloading or quitting can lose unsaved edits.\n\nThe original cause of an audio-service deadlock is unknown; this check cannot identify a driver or cure the deadlock.",
        crate::app_profile::CURRENT, std::env::consts::ARCH, SystemTime::now(), PROBE_LIMIT.as_millis()
    );
    let saved = (|| -> Result<_, crate::error::AppError> {
        let dir = crate::fsutil::app_data_root()?.join("diagnostics");
        crate::fsutil::ensure_dir_secure(&dir)?;
        let path = dir.join("window-health.txt");
        crate::fsutil::atomic_write(&path, report.as_bytes(), 0o600)?;
        Ok(path)
    })();
    let path = saved
        .map(|p| format!("\n\nReport: {}", p.display()))
        .unwrap_or_else(|e| format!("\n\nCould not save report: {e}"));
    native_dialog(
        app,
        "Lunport — Window Diagnostics",
        &format!("{report}{path}"),
        &["OK"],
    );
}

/// Replaces (rather than supplements) tauri-runtime-wry 2.11.2's default reload.
/// WebContent termination is not a GPU rendering failure notification.
pub(crate) fn web_content_terminated(view: &tauri::Webview) {
    let app = view.app_handle();
    let label = view.label().to_owned();
    // No security decision is replayed after a WebContent context is lost.
    deny_interactions(app);
    request(app, Surface::Terminated(label));
}

fn termination_notice(app: &tauri::AppHandle, label: String) {
    let already_reloaded = app
        .state::<HealthState>()
        .0
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .reloads
        .contains(&label);
    let reload = native_dialog(
        app,
        "Lunport — Web content stopped",
        if already_reloaded {
            "Web content stopped again. This window has already used its one recovery reload. Collect Window Diagnostics from the tray. Existing SSH sessions keep running; save available work before restarting Lunport."
        } else {
            "Web content stopped. Existing SSH sessions keep running. Reloading may discard unsaved edits in this window. Pending authentication/key questions are never approved automatically. Reload is available once per window during this app run; if the view stays black, collect Window Diagnostics from the tray."
        },
        if already_reloaded {
            &["Keep Running"]
        } else {
            &["Reload Window", "Keep Window"]
        },
    );
    if reload == 0 && !already_reloaded {
        request(app, Surface::Reload(label));
    }
}

// All calls except the spawn-error fallback originate on the one health worker.
// Keep AppKit work on the event thread and wait only on the worker.
fn native_dialog(app: &tauri::AppHandle, title: &str, message: &str, buttons: &[&str]) -> i64 {
    let (title, message) = (title.to_owned(), message.to_owned());
    let buttons: Vec<String> = buttons.iter().map(|s| (*s).to_owned()).collect();
    let (tx, rx) = std::sync::mpsc::sync_channel(1);
    if app
        .run_on_main_thread(move || {
            let buttons: Vec<&str> = buttons.iter().map(String::as_str).collect();
            let _ = tx.send(appkit_alert(&title, &message, &buttons));
        })
        .is_err()
    {
        return -1;
    }
    rx.recv().unwrap_or(-1)
}

fn appkit_alert(title: &str, message: &str, buttons: &[&str]) -> i64 {
    use std::ffi::{c_char, c_long, c_ulong, CString};
    unsafe extern "C" {
        fn sshelter_native_alert(
            title: *const c_char,
            message: *const c_char,
            buttons: *const *const c_char,
            count: c_ulong,
        ) -> c_long;
    }
    let string = |s: &str| CString::new(s.replace('\0', "?")).expect("NUL removed");
    let (title, message) = (string(title), string(message));
    let buttons: Vec<CString> = buttons.iter().map(|s| string(s)).collect();
    let pointers: Vec<_> = buttons.iter().map(|s| s.as_ptr()).collect();
    // The bridge copies the strings while these allocations are alive. Caller
    // schedules this function on the main thread; NSAlert runs its modal loop.
    unsafe {
        sshelter_native_alert(
            title.as_ptr(),
            message.as_ptr(),
            pointers.as_ptr(),
            pointers.len() as c_ulong,
        ) as i64
    }
}

#[derive(Debug, PartialEq, Eq)]
enum ProbeError {
    Start(String),
    Failed(Option<i32>),
    Timeout,
    Wait(String),
}
impl std::fmt::Display for ProbeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Start(e) => write!(f, "cannot start probe: {e}"),
            Self::Failed(code) => write!(f, "probe exited with {code:?}"),
            Self::Timeout => write!(
                f,
                "probe timed out after {} ms and was terminated and reaped",
                PROBE_LIMIT.as_millis()
            ),
            Self::Wait(e) => write!(f, "cannot collect probe: {e}"),
        }
    }
}

// Drop also cleans up on error/unwind; no inherited pipes or helper descendants.
struct ProbeChild(Child);
impl Drop for ProbeChild {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn probe() -> Result<(), ProbeError> {
    let exe = std::env::current_exe().map_err(|e| ProbeError::Start(e.to_string()))?;
    let mut command = Command::new(exe);
    command
        .arg("--coreaudio-probe")
        .env_remove("SSHELTER_ASKPASS")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    run_probe(&mut command, PROBE_LIMIT)
}

/// A bounded support command: unlike the internal helper it is safe to run
/// directly in Terminal, and never initializes the GUI or background services.
pub fn check_from_terminal() -> i32 {
    let began = Instant::now();
    let result = probe();
    println!(
        "Profile: {:?}; CoreAudio: {result:?}; elapsed_ms={}. This does not prove GPU rendering health.",
        crate::app_profile::CURRENT, began.elapsed().as_millis()
    );
    if result.is_ok() {
        0
    } else {
        1
    }
}

fn run_probe(command: &mut Command, limit: Duration) -> Result<(), ProbeError> {
    let began = Instant::now();
    let wall = SystemTime::now();
    let mut child =
        ProbeChild(crate::process::spawn(command).map_err(|e| ProbeError::Start(e.to_string()))?);
    loop {
        // Wall time covers sleep on clocks where Instant stops during suspend.
        if expired(began.elapsed(), wall.elapsed().unwrap_or_default(), limit) {
            return Err(ProbeError::Timeout);
        }
        match child
            .0
            .try_wait()
            .map_err(|e| ProbeError::Wait(e.to_string()))?
        {
            Some(status) => {
                return if status.success() {
                    Ok(())
                } else {
                    Err(ProbeError::Failed(status.code()))
                }
            }
            None => std::thread::sleep(POLL),
        }
    }
}

fn expired(monotonic: Duration, wall: Duration, limit: Duration) -> bool {
    monotonic >= limit || wall >= limit
}

/// This function only runs in the disposable child, before all application setup.
pub fn probe_child() -> i32 {
    // Also bound the helper if the parent crashes or is killed before reaping.
    // No app signal handlers have been installed in this early helper mode.
    unsafe {
        libc::alarm(3);
    }
    // Development-only, fixed fault modes. A file lets an operator restore the
    // simulated service and exercise Retry in the same app without touching HAL.
    if crate::app_profile::CURRENT == crate::app_profile::AppProfile::Development {
        if let Some(path) = std::env::var_os(FAULT_FILE) {
            match std::fs::read_to_string(path).as_deref().map(str::trim) {
                Ok("success") => return 0,
                Ok("error") => return 70,
                Ok("timeout") => loop {
                    std::thread::sleep(Duration::from_secs(60));
                },
                Ok("real") => {}
                _ => return 71,
            }
        }
    }
    #[repr(C)]
    struct PropertyAddress {
        selector: u32,
        scope: u32,
        element: u32,
    }
    #[link(name = "CoreAudio", kind = "framework")]
    unsafe extern "C" {
        fn AudioObjectGetPropertyData(
            object: u32,
            address: *const PropertyAddress,
            qualifier_size: u32,
            qualifier: *const std::ffi::c_void,
            size: *mut u32,
            data: *mut std::ffi::c_void,
        ) -> i32;
    }
    // Public CoreAudio constants from AudioHardwareBase.h: system object 1,
    // default output 'dOut', global scope 'glob', main element 0.
    let address = PropertyAddress {
        selector: u32::from_be_bytes(*b"dOut"),
        scope: u32::from_be_bytes(*b"glob"),
        element: 0,
    };
    let mut device = 0u32;
    let mut size = std::mem::size_of_val(&device) as u32;
    let status = unsafe {
        AudioObjectGetPropertyData(
            1,
            &address,
            0,
            std::ptr::null(),
            &mut size,
            (&mut device as *mut u32).cast(),
        )
    };
    // No output device is a valid response. Do not require speakers or start IO.
    if status == 0 {
        0
    } else {
        eprintln!("CoreAudio query status={status}");
        1
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unavailable_windows_cancel_auth_and_refuse_host_and_key_approvals() {
        use crate::agent::prompt::{AgentApprovalRequest, PromptSurface};
        use crate::session::auth::{Owner, Reply};
        use crate::session::auth_window::{AuthRequest, AuthSurface, NativeOwner};
        use crate::session::connect::CancelToken;
        use crate::session::hostkey_window::{HostKeyRequest, HostKeySurface};
        use crate::session::protocol::QuestionKind;
        use std::sync::Arc;
        struct Silent;
        impl AuthSurface for Silent {
            fn changed(&self, _: &[AuthRequest]) {}
        }
        impl HostKeySurface for Silent {
            fn changed(&self, _: &[HostKeyRequest]) {}
        }
        impl PromptSurface for Silent {
            fn changed(&self, _: &[AgentApprovalRequest]) {}
        }
        let state = Arc::new(crate::state::AppState::default());
        let owner = NativeOwner {
            hub: state.session.auth_questions.clone(),
            surface: Arc::new(Silent),
            request_id: "health-test".into(),
            cancel: CancelToken::default(),
        };
        let auth =
            std::thread::spawn(move || owner.ask(QuestionKind::Password, "Password", false, None));
        let host_state = state.clone();
        let host = std::thread::spawn(move || {
            host_state.session.host_keys.ask(
                &Silent,
                HostKeyRequest {
                    user: "ops".into(),
                    id: String::new(),
                    alias: "fixture".into(),
                    hostname: "example.invalid".into(),
                    port: 22,
                    algorithm: "ssh-ed25519".into(),
                    fingerprint: "SHA256:fixture".into(),
                    changed: None,
                },
                Duration::from_secs(5),
                &CancelToken::default(),
            )
        });
        let key_state = state.clone();
        let key = std::thread::spawn(move || {
            key_state.agent.prompts.ask(
                &Silent,
                AgentApprovalRequest {
                    id: String::new(),
                    key_name: "fixture".into(),
                    key_fingerprint: "SHA256:fixture".into(),
                    program_chain: vec![],
                    user: None,
                    host: None,
                    host_fingerprint: None,
                    rememberable: true,
                    remember_minutes: 60,
                    needs_passphrase: false,
                    passphrase_error: None,
                    preapproved: false,
                },
                Duration::from_secs(5),
            )
        });
        let end = Instant::now() + Duration::from_secs(3);
        while state.session.auth_questions.pending().is_empty()
            || state.session.host_keys.pending().is_empty()
            || state.agent.prompts.pending().is_empty()
        {
            assert!(Instant::now() < end);
            std::thread::sleep(POLL);
        }
        let auth_id = state.session.auth_questions.pending()[0].id.clone();
        deny_pending(&state);
        assert!(matches!(auth.join().unwrap(), Reply::Cancelled));
        assert!(!host.join().unwrap().unwrap().trust);
        let answer = key.join().unwrap().unwrap();
        assert!(!answer.allow && !answer.remember && !answer.remember_passphrase);
        assert!(state
            .session
            .auth_questions
            .resolve(&auth_id, None)
            .is_err());
        assert!(state.session.host_keys.pending().is_empty());
        assert!(state.agent.prompts.pending().is_empty());
        assert!(state.doc.lock().unwrap().is_none());
    }

    #[test]
    fn helper_success_error_and_spawn_failure_are_distinct() {
        assert_eq!(
            run_probe(&mut Command::new("/usr/bin/true"), Duration::from_secs(2)),
            Ok(())
        );
        assert_eq!(
            run_probe(&mut Command::new("/usr/bin/false"), Duration::from_secs(2)),
            Err(ProbeError::Failed(Some(1)))
        );
        assert!(matches!(
            run_probe(
                &mut Command::new("/no/such/sshelter"),
                Duration::from_secs(2)
            ),
            Err(ProbeError::Start(_))
        ));
    }

    #[test]
    fn timeout_kills_and_reaps_the_child_before_a_recovery_attempt() {
        let temp = tempfile::tempdir().unwrap();
        let pid_file = temp.path().join("pid");
        let mut command = Command::new("/bin/sh");
        // exec replaces the shell: no descendants, just like the real helper.
        command
            .args(["-c", "echo $$ > \"$1\"; exec /bin/sleep 60", "probe"])
            .arg(&pid_file);
        let began = Instant::now();
        assert_eq!(
            run_probe(&mut command, Duration::from_millis(200)),
            Err(ProbeError::Timeout)
        );
        assert!(began.elapsed() < Duration::from_secs(2));
        let pid: i32 = std::fs::read_to_string(pid_file)
            .unwrap()
            .trim()
            .parse()
            .unwrap();
        assert_eq!(unsafe { libc::kill(pid, 0) }, -1);
        let mut status = 0;
        assert_eq!(
            unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG) },
            -1
        );
        assert_eq!(
            std::io::Error::last_os_error().raw_os_error(),
            Some(libc::ECHILD)
        );
        assert_eq!(
            run_probe(&mut Command::new("/usr/bin/true"), Duration::from_secs(2)),
            Ok(())
        );
    }

    #[test]
    fn sleep_time_expires_a_probe_even_if_the_monotonic_clock_pauses() {
        assert!(expired(
            Duration::from_millis(1),
            Duration::from_secs(30),
            PROBE_LIMIT
        ));
        assert!(expired(PROBE_LIMIT, Duration::ZERO, PROBE_LIMIT));
        assert!(!expired(
            Duration::from_millis(1),
            Duration::from_millis(1),
            PROBE_LIMIT
        ));
    }

    #[test]
    fn concurrent_surfaces_coalesce_without_caching_a_pass_or_resetting_reload_budget() {
        let mut q = Queue::default();
        assert!(q.push(Surface::Main));
        assert!(!q.push(Surface::Main));
        assert_eq!(q.next(), Some(Surface::Main));
        assert!(!q.push(Surface::Main));
        assert!(!q.push(Surface::HostKey));
        assert!(!q.push(Surface::Authentication));
        assert_eq!(q.next(), Some(Surface::HostKey));
        assert_eq!(q.next(), Some(Surface::Authentication));
        assert_eq!(q.next(), None);
        assert!(q.push(Surface::Main));
        assert!(q.reloads.insert("main".into()));
        assert!(!q.reloads.insert("main".into()));
    }
}
