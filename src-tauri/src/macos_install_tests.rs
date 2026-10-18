use super::*;

fn fixture() -> (tempfile::TempDir, Plan, PathBuf) {
    let root = tempfile::tempdir().unwrap();
    let old = root.path().join("SSHelter.app");
    let new = root.path().join("Lunport.app");
    fs::create_dir_all(old.join("Contents/MacOS")).unwrap();
    fs::write(bundle_exe(&old), b"disposable-executable").unwrap();
    let data = root.path().join("data");
    (root, Plan { old, new }, data)
}

#[test]
fn old_absolute_commands_survive_a_rename_and_a_later_update() {
    let (_root, plan, data) = fixture();
    let old = bundle_exe(&plan.old);
    let new = bundle_exe(&plan.new);
    assert_eq!(
        perform(&old, false, false, &data).unwrap(),
        Some(new.clone())
    );
    assert_eq!(fs::read(&old).unwrap(), b"disposable-executable");
    assert!(fs::symlink_metadata(&plan.old)
        .unwrap()
        .file_type()
        .is_symlink());
    assert_eq!(fs::read_link(&plan.old).unwrap(), Path::new("Lunport.app"));
    assert_eq!(perform(&new, false, false, &data).unwrap(), None);
    // The updater replaces Contents under the canonical app, leaving the compatibility alias.
    fs::write(&new, b"later-update").unwrap();
    assert_eq!(fs::read(&old).unwrap(), b"later-update");
    assert_eq!(perform(&new, false, false, &data).unwrap(), None);
}

#[test]
fn destination_conflicts_never_replace_another_app_even_an_empty_directory() {
    let (_root, plan, data) = fixture();
    fs::create_dir(&plan.new).unwrap();
    assert!(perform(&bundle_exe(&plan.old), false, false, &data).is_err());
    assert_eq!(
        fs::read(bundle_exe(&plan.old)).unwrap(),
        b"disposable-executable"
    );
    assert!(fs::read_dir(&plan.new).unwrap().next().is_none());
}

#[test]
fn a_compatibility_link_failure_rolls_back_the_bundle_move() {
    let (_root, plan, _data) = fixture();
    assert!(move_bundle_with(&plan, |_| Err(io::Error::new(
        io::ErrorKind::PermissionDenied,
        "fixture"
    )))
    .is_err());
    assert_eq!(
        fs::read(bundle_exe(&plan.old)).unwrap(),
        b"disposable-executable"
    );
    assert!(!plan.new.exists());
}

#[test]
fn rollback_never_overwrites_a_concurrently_occupied_old_path() {
    let (_root, plan, _data) = fixture();
    assert!(move_bundle_with(&plan, |plan| {
        fs::write(&plan.old, b"unrelated").unwrap();
        Err(io::Error::other("fixture link failure"))
    })
    .is_err());
    assert_eq!(fs::read(&plan.old).unwrap(), b"unrelated");
    assert_eq!(
        fs::read(bundle_exe(&plan.new)).unwrap(),
        b"disposable-executable"
    );
}

#[test]
fn an_interrupted_move_repairs_the_compatibility_link_from_its_journal() {
    let (_root, plan, data) = fixture();
    fs::create_dir(&data).unwrap();
    fs::write(journal_path(&data), serde_json::to_vec(&plan).unwrap()).unwrap();
    rename_exclusive(&plan.old, &plan.new).unwrap();
    assert_eq!(
        perform(&bundle_exe(&plan.new), false, false, &data).unwrap(),
        None
    );
    assert_eq!(
        fs::read(bundle_exe(&plan.old)).unwrap(),
        b"disposable-executable"
    );
}

#[test]
fn a_journal_cannot_redirect_a_different_installation() {
    let (root, plan, data) = fixture();
    fs::create_dir(&data).unwrap();
    let elsewhere = Plan {
        old: root.path().join("else/SSHelter.app"),
        new: root.path().join("else/Lunport.app"),
    };
    fs::write(journal_path(&data), serde_json::to_vec(&elsewhere).unwrap()).unwrap();
    rename_exclusive(&plan.old, &plan.new).unwrap();
    assert_eq!(
        perform(&bundle_exe(&plan.new), false, false, &data).unwrap(),
        None
    );
    assert!(!elsewhere.new.exists());
}

#[test]
fn a_fresh_canonical_install_does_not_create_legacy_aliases_or_a_journal() {
    let (_root, plan, data) = fixture();
    rename_exclusive(&plan.old, &plan.new).unwrap();
    assert_eq!(
        perform(&bundle_exe(&plan.new), false, false, &data).unwrap(),
        None
    );
    assert!(!plan.old.exists());
    assert!(!data.exists());
}

#[test]
fn development_cannot_migrate_production_or_escape_its_write_policy() {
    let (_root, plan, data) = fixture();
    assert_eq!(
        perform(&bundle_exe(&plan.old), true, false, &data).unwrap(),
        None
    );
    crate::fsutil::with_test_write_policy(
        crate::write_policy::WritePolicy::Confined { root: data.clone() },
        || {
            assert!(perform(&bundle_exe(&plan.old), false, false, &data).is_err());
        },
    );
    assert!(plan.old.is_dir());
    assert!(!plan.new.exists());
}

#[test]
fn shell_arguments_for_authorization_are_literal() {
    assert_eq!(
        shell_quote(std::ffi::OsStr::new(
            "/Apps/O'Brien $(ignored) app/sshelter"
        ))
        .unwrap(),
        "'/Apps/O'\\''Brien $(ignored) app/sshelter'"
    );
}

#[test]
fn system_authorization_program_moves_only_the_literal_fixture_and_refuses_conflicts() {
    let root = tempfile::tempdir().unwrap();
    let parent = root.path().join("Spaces 測試 O'Brien $(ignored)");
    let plan = Plan {
        old: parent.join("SSHelter.app"),
        new: parent.join("Lunport.app"),
    };
    fs::create_dir_all(plan.old.join("Contents/MacOS")).unwrap();
    fs::write(bundle_exe(&plan.old), b"fixture").unwrap();
    let command = authorization_command(&plan).unwrap();
    // Exercise the same two quoting layers without requesting administrator privileges.
    let script = format!(
        "do shell script {}",
        serde_json::to_string(&command).unwrap()
    );
    let output = std::process::Command::new("/usr/bin/osascript")
        .args(["-e", &script])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(fs::read(bundle_exe(&plan.old)).unwrap(), b"fixture");
    assert_eq!(fs::read_link(&plan.old).unwrap(), Path::new("Lunport.app"));
    fs::remove_file(&plan.old).unwrap();
    fs::create_dir(&plan.old).unwrap();
    fs::write(plan.old.join("keep"), b"old").unwrap();
    let output = std::process::Command::new("/usr/bin/osascript")
        .args(["-e", &script])
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert_eq!(fs::read(plan.old.join("keep")).unwrap(), b"old");
    assert_eq!(fs::read(bundle_exe(&plan.new)).unwrap(), b"fixture");
}

#[test]
fn cancelled_authorization_preserves_the_working_old_app_and_can_retry() {
    use std::os::unix::fs::PermissionsExt;
    if unsafe { libc::geteuid() } == 0 {
        return;
    }
    let root = tempfile::tempdir().unwrap();
    let apps = root.path().join("Applications");
    let old = apps.join("SSHelter.app");
    fs::create_dir_all(old.join("Contents/MacOS")).unwrap();
    fs::write(bundle_exe(&old), b"fixture").unwrap();
    fs::set_permissions(&apps, fs::Permissions::from_mode(0o500)).unwrap();
    let data = root.path().join("data");
    let called = std::cell::Cell::new(false);
    let result = perform_with_authorizer(&bundle_exe(&old), false, true, &data, |exe, name| {
        called.set(true);
        assert_eq!(exe, bundle_exe(&old));
        assert_eq!(name, "SSHelter.app");
        Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "fixture cancelled",
        ))
    });
    fs::set_permissions(&apps, fs::Permissions::from_mode(0o700)).unwrap();
    assert!(called.get());
    assert_eq!(result.unwrap_err().kind(), io::ErrorKind::PermissionDenied);
    assert_eq!(fs::read(bundle_exe(&old)).unwrap(), b"fixture");
    assert!(!apps.join("Lunport.app").exists());
    assert!(perform(&bundle_exe(&old), false, false, &data)
        .unwrap()
        .is_some());
    assert_eq!(fs::read(bundle_exe(&old)).unwrap(), b"fixture");
}

fn login_file(home: &Path, args: Vec<plist::Value>) -> PathBuf {
    let path = home.join("Library/LaunchAgents/SSHelter.plist");
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    let mut dictionary = plist::Dictionary::new();
    dictionary.insert("Label".into(), "SSHelter".into());
    dictionary.insert("ProgramArguments".into(), args.into());
    dictionary.insert("RunAtLoad".into(), true.into());
    dictionary.insert("UnknownSetting".into(), "keep-me".into());
    plist::Value::Dictionary(dictionary)
        .to_file_xml(&path)
        .unwrap();
    path
}

#[test]
fn enabled_login_retains_its_arguments_and_unknown_keys() {
    let (root, plan, _data) = fixture();
    let home = root.path().join("home");
    let path = login_file(
        &home,
        vec![
            bundle_exe(&plan.old).to_string_lossy().into_owned().into(),
            "--hidden".into(),
        ],
    );
    move_bundle(&plan).unwrap();
    assert!(repair_login_at(&home, &bundle_exe(&plan.new)).unwrap());
    let entry = plist::Value::from_file(path).unwrap();
    let d = entry.as_dictionary().unwrap();
    assert_eq!(d["UnknownSetting"].as_string(), Some("keep-me"));
    assert_eq!(d["RunAtLoad"].as_boolean(), Some(true));
    let args = d["ProgramArguments"].as_array().unwrap();
    assert_eq!(args[0].as_string(), bundle_exe(&plan.new).to_str());
    assert_eq!(args[1].as_string(), Some("--hidden"));
    assert!(!repair_login_at(&home, &bundle_exe(&plan.new)).unwrap());
}

#[test]
fn disabled_login_stays_disabled_and_unrelated_entries_are_not_rewritten() {
    let (root, plan, _data) = fixture();
    move_bundle(&plan).unwrap();
    let home = root.path().join("home");
    assert!(!repair_login_at(&home, &bundle_exe(&plan.new)).unwrap());
    assert!(!home.exists());
    let path = login_file(
        &home,
        vec!["/unrelated/App.app/Contents/MacOS/sshelter".into()],
    );
    let before = fs::read(&path).unwrap();
    assert!(!repair_login_at(&home, &bundle_exe(&plan.new)).unwrap());
    assert_eq!(fs::read(path).unwrap(), before);
}
