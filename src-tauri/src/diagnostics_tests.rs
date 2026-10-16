use super::*;

#[test]
fn logs_rotate_as_valid_json_and_refuse_redirected_files() {
    let temp = tempfile::tempdir().unwrap();
    let logger = Logger {
        directory: temp.path().join("logs"),
        writer: Mutex::new(()),
    };
    let trace = "frame_at_code_location\n".repeat(600);
    for _ in 0..80 {
        logger
            .write(
                "test_failure",
                Some("io:PermissionDenied:5"),
                Some(&trace),
                false,
            )
            .unwrap();
    }
    for name in ["app.log", "app.log.1", "app.log.2"] {
        let path = logger.directory.join(name);
        assert!(fs::metadata(&path).unwrap().len() <= MAX_LOG_BYTES);
        for line in fs::read_to_string(path).unwrap().lines() {
            let value: serde_json::Value = serde_json::from_str(line).unwrap();
            assert_eq!(value["event"], "test_failure");
            assert_eq!(value["code"], "io:PermissionDenied:5");
        }
    }
    #[cfg(unix)]
    {
        use std::os::unix::{fs::symlink, fs::PermissionsExt};
        assert_eq!(
            fs::metadata(logger.directory.join("app.log"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        let source = temp.path().join("config");
        fs::write(&source, "preserve config").unwrap();
        fs::remove_file(logger.directory.join("app.log")).unwrap();
        symlink(&source, logger.directory.join("app.log")).unwrap();
        assert!(logger.write("refused", None, None, false).is_err());
        assert_eq!(fs::read_to_string(source).unwrap(), "preserve config");
    }
}

#[test]
fn panic_log_survives_restart_without_serializing_the_payload() {
    const CHILD: &str = "SSHELTER_TEST_DIAGNOSTICS_CHILD";
    if let Some(directory) = std::env::var_os(CHILD) {
        install_at(PathBuf::from(directory)).unwrap();
        stage(Stage::Setup);
        panic!("sensitive-sync-code-and-private-key-fixture");
    }
    let temp = tempfile::tempdir().unwrap();
    let mut command = crate::process::background_command(std::env::current_exe().unwrap());
    command
        .args([
            "--exact",
            "diagnostics::tests::panic_log_survives_restart_without_serializing_the_payload",
            "--nocapture",
        ])
        .env(CHILD, temp.path())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null());
    let mut child = crate::process::spawn(&mut command).unwrap();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(20);
    loop {
        if let Some(status) = child.try_wait().unwrap() {
            assert!(!status.success());
            break;
        }
        if std::time::Instant::now() >= deadline {
            child.kill().unwrap();
            child.wait().unwrap();
            panic!("panic child timed out");
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    let path = temp.path().join("app.log");
    let before = fs::read_to_string(&path).unwrap();
    assert!(!before.contains("sensitive-sync-code-and-private-key-fixture"));
    let events: Vec<serde_json::Value> = before
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    let panic = events.iter().find(|e| e["event"] == "rust_panic").unwrap();
    assert_eq!(panic["stage"], "setup");
    assert!(panic["backtrace"].as_str().unwrap().contains("diagnostics"));
    let logger = Logger {
        directory: temp.path().into(),
        writer: Mutex::new(()),
    };
    logger.write("logging_started", None, None, false).unwrap();
    assert!(fs::read_to_string(path).unwrap().starts_with(&before));
}

#[cfg(windows)]
#[test]
#[ignore = "injects a native exception in a disposable child; run separately in Windows CI"]
fn native_exception_leaves_metadata_for_windows_error_reporting() {
    const CHILD: &str = "SSHELTER_TEST_NATIVE_CRASH_CHILD";
    if let Some(directory) = std::env::var_os(CHILD) {
        install_at(PathBuf::from(directory)).unwrap();
        stage(Stage::Window);
        unsafe {
            // Suppress the OS modal crash UI in this test process only.
            windows_sys::Win32::System::ErrorReporting::WerSetFlags(
                windows_sys::Win32::System::ErrorReporting::WER_FAULT_REPORTING_NO_UI,
            );
            windows_sys::Win32::System::Diagnostics::Debug::RaiseException(
                0xe0535348,
                0,
                0,
                std::ptr::null(),
            );
        }
        panic!("native exception unexpectedly returned");
    }
    let temp = tempfile::tempdir().unwrap();
    let mut command = crate::process::background_command(std::env::current_exe().unwrap());
    command
        .args([
            "--ignored",
            "--exact",
            "diagnostics::tests::native_exception_leaves_metadata_for_windows_error_reporting",
            "--nocapture",
        ])
        .env(CHILD, temp.path())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null());
    let mut child = crate::process::spawn(&mut command).unwrap();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(20);
    loop {
        if let Some(status) = child.try_wait().unwrap() {
            assert_eq!(status.code(), Some(0xe0535348u32 as i32));
            break;
        }
        if std::time::Instant::now() >= deadline {
            child.kill().unwrap();
            child.wait().unwrap();
            panic!("native crash child timed out");
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    let text = fs::read_to_string(temp.path().join("native-crash.log")).unwrap();
    assert!(text.contains("native_exception code=0xe0535348"), "{text}");
    assert!(text.contains("stage=07"), "{text}");
}
