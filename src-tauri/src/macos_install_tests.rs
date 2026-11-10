use super::*;
use crate::legacy_identity;

/// The name of the app bundle before the rename.
fn old_bundle_name() -> &'static str {
    legacy_identity::BUNDLE_NAMES[0]
}

/// The executable of a bundle from before the rename, as an old launch agent names it.
fn old_exe(bundle: &Path) -> PathBuf {
    bundle
        .join("Contents/MacOS")
        .join(legacy_identity::current().main_binary)
}

fn fixture() -> (tempfile::TempDir, Plan, PathBuf) {
    let root = tempfile::tempdir().unwrap();
    let old = root.path().join(old_bundle_name());
    let new = root.path().join("Lunport.app");
    fs::create_dir_all(old.join("Contents/MacOS")).unwrap();
    fs::write(bundle_exe(&old), b"disposable-executable").unwrap();
    let data = root.path().join("data");
    (root, Plan { old, new }, data)
}

#[test]
fn a_bundle_is_found_by_the_executable_of_this_version_not_by_an_older_one() {
    let bundle = Path::new("/Applications/Lunport.app");
    let exe = bundle_exe(bundle);
    assert_eq!(
        exe,
        Path::new("/Applications/Lunport.app/Contents/MacOS/lunport")
    );
    assert_eq!(bundle_for(&exe), Some(bundle));
    assert_eq!(bundle_for(&old_exe(bundle)), None);
    // The older executable is recognized where an old launch agent names it, and only there.
    assert_eq!(
        bundle_of(&old_exe(bundle), legacy_identity::current().main_binary),
        Some(bundle)
    );
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
        old: root.path().join("else").join(old_bundle_name()),
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

/// A Development bundle under one of the old Development names becomes `Lunport Dev.app`, with the compatibility link left behind.
#[test]
fn a_development_bundle_with_an_old_name_moves_to_the_development_name() {
    for old_name in legacy_identity::DEVELOPMENT.bundle_names {
        let root = tempfile::tempdir().unwrap();
        let old = root.path().join(old_name);
        let new = root
            .path()
            .join(format!("{}.app", identity::DEVELOPMENT.product_name));
        fs::create_dir_all(old.join("Contents/MacOS")).unwrap();
        fs::write(bundle_exe(&old), b"disposable-executable").unwrap();
        let data = root.path().join("data");
        // Production's names are not Development's: a Production build leaves the bundle alone.
        assert_eq!(read_plan(&bundle_exe(&old), false, &data).unwrap(), None);
        assert_eq!(
            read_plan(&bundle_exe(&old), true, &data).unwrap(),
            Some(Plan { old: old.clone(), new: new.clone() })
        );
        assert_eq!(
            perform(&bundle_exe(&old), true, false, &data).unwrap(),
            Some(bundle_exe(&new))
        );
        assert_eq!(fs::read(bundle_exe(&new)).unwrap(), b"disposable-executable");
        assert_eq!(
            fs::read_link(&old).unwrap(),
            Path::new(new.file_name().unwrap())
        );
    }
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
            "/Apps/O'Brien $(ignored) app/lunport"
        ))
        .unwrap(),
        "'/Apps/O'\\''Brien $(ignored) app/lunport'"
    );
}

#[test]
fn system_authorization_program_moves_only_the_literal_fixture_and_refuses_conflicts() {
    let root = tempfile::tempdir().unwrap();
    let parent = root.path().join("Spaces 測試 O'Brien $(ignored)");
    let plan = Plan {
        old: parent.join(old_bundle_name()),
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

/// The elevated script takes its paths from this process, and it still accepts nothing but an old bundle name inside a folder: a path
/// that is only the name would be read against whatever folder it runs in.
#[test]
fn the_elevated_move_refuses_an_old_name_without_its_folder() {
    let root = tempfile::tempdir().unwrap();
    fs::create_dir_all(root.path().join(old_bundle_name()).join("Contents/MacOS")).unwrap();
    let mut command = std::process::Command::new("/usr/bin/osascript");
    command
        .current_dir(root.path())
        .args(["-l", "JavaScript", "-e", &authorized_move_script().unwrap()])
        .arg(old_bundle_name())
        .arg(new_name(false))
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped());
    let output = crate::process::spawn(&mut command).unwrap().wait_with_output().unwrap();
    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("Invalid installation paths"),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(root.path().join(old_bundle_name()).is_dir());
    assert!(!root.path().join(new_name(false)).exists());
}

#[test]
fn cancelled_authorization_preserves_the_working_old_app_and_can_retry() {
    use std::os::unix::fs::PermissionsExt;
    if unsafe { libc::geteuid() } == 0 {
        return;
    }
    let root = tempfile::tempdir().unwrap();
    let apps = root.path().join("Applications");
    let old = apps.join(old_bundle_name());
    fs::create_dir_all(old.join("Contents/MacOS")).unwrap();
    fs::write(bundle_exe(&old), b"fixture").unwrap();
    fs::set_permissions(&apps, fs::Permissions::from_mode(0o500)).unwrap();
    let data = root.path().join("data");
    let called = std::cell::Cell::new(false);
    let result = perform_with_authorizer(&bundle_exe(&old), false, true, &data, |exe, name| {
        called.set(true);
        assert_eq!(exe, bundle_exe(&old));
        assert_eq!(name, old_bundle_name());
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

/// The launch agent from before the rename, as the autostart plugin wrote it, with a key of someone else's.
fn login_file(home: &Path, args: Vec<plist::Value>) -> PathBuf {
    login_file_named(home, legacy_identity::PRODUCTION.login_item, args)
}

fn login_file_named(home: &Path, name: &str, args: Vec<plist::Value>) -> PathBuf {
    let path = home.join(format!("Library/LaunchAgents/{name}.plist"));
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    let mut dictionary = plist::Dictionary::new();
    dictionary.insert("Label".into(), name.into());
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
            old_exe(&plan.old).to_string_lossy().into_owned().into(),
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

/// 1.14.4 was already `Lunport.app`, only its executable still had the old name: the update replaced the bundle, and the launch agent
/// that 1.14.4 registered names a file that is gone.
#[test]
fn a_launch_agent_naming_the_old_executable_of_this_bundle_is_repaired() {
    let root = tempfile::tempdir().unwrap();
    let bundle = root.path().join(new_name(false));
    fs::create_dir_all(bundle.join("Contents/MacOS")).unwrap();
    fs::write(bundle_exe(&bundle), b"disposable-executable").unwrap();
    let home = root.path().join("home");
    let path = login_file(
        &home,
        vec![
            old_exe(&bundle).to_string_lossy().into_owned().into(),
            "--keep".into(),
        ],
    );
    assert!(repair_login_at(&home, &bundle_exe(&bundle)).unwrap());
    let entry = plist::Value::from_file(&path).unwrap();
    let d = entry.as_dictionary().unwrap();
    assert_eq!(
        d["Label"].as_string(),
        Some(legacy_identity::PRODUCTION.login_item)
    );
    assert_eq!(d["UnknownSetting"].as_string(), Some("keep-me"));
    let args = d["ProgramArguments"].as_array().unwrap();
    assert_eq!(args[0].as_string(), bundle_exe(&bundle).to_str());
    assert_eq!(args[1].as_string(), Some("--keep"));
    assert!(!repair_login_at(&home, &bundle_exe(&bundle)).unwrap());
}

/// An agent that cannot be read (the plugin writes an app path that holds `&` into the XML unescaped) is reported, and the other agent
/// is repaired all the same.
#[test]
fn an_agent_that_cannot_be_read_does_not_stop_the_repair_of_the_other() {
    let root = tempfile::tempdir().unwrap();
    let bundle = root.path().join(new_name(false));
    fs::create_dir_all(bundle.join("Contents/MacOS")).unwrap();
    fs::write(bundle_exe(&bundle), b"disposable-executable").unwrap();
    let home = root.path().join("home");
    let legacy = login_file(
        &home,
        vec![old_exe(&bundle).to_string_lossy().into_owned().into()],
    );
    let current = home.join(format!("Library/LaunchAgents/{}.plist", identity::PRODUCTION.login_item));
    let unreadable = format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<plist version=\"1.0\">\n  <dict>\n  <key>Label</key>\n  <string>{}</string>\n  \
         <key>ProgramArguments</key>\n  <array><string>/Applications/Tom & Jerry/Lunport.app/Contents/MacOS/lunport</string></array>\n  \
         </dict>\n</plist>",
        identity::PRODUCTION.login_item
    );
    fs::write(&current, &unreadable).unwrap();
    assert!(repair_login_at(&home, &bundle_exe(&bundle)).is_err());
    let entry = plist::Value::from_file(&legacy).unwrap();
    assert_eq!(
        entry.as_dictionary().unwrap()["ProgramArguments"].as_array().unwrap()[0].as_string(),
        bundle_exe(&bundle).to_str()
    );
    assert_eq!(fs::read_to_string(&current).unwrap(), unreadable);
}

/// An old executable that is still there runs whatever it is: an entry that names it is left as it is.
#[test]
fn a_launch_agent_naming_an_old_executable_that_still_exists_is_left_alone() {
    let root = tempfile::tempdir().unwrap();
    let bundle = root.path().join(new_name(false));
    fs::create_dir_all(bundle.join("Contents/MacOS")).unwrap();
    fs::write(bundle_exe(&bundle), b"disposable-executable").unwrap();
    fs::write(old_exe(&bundle), b"another-executable").unwrap();
    let home = root.path().join("home");
    let path = login_file(
        &home,
        vec![old_exe(&bundle).to_string_lossy().into_owned().into()],
    );
    let before = fs::read(&path).unwrap();
    assert!(!repair_login_at(&home, &bundle_exe(&bundle)).unwrap());
    assert_eq!(fs::read(&path).unwrap(), before);
}

/// The launch agent under the current name is this app's too: when it names the executable through an old bundle name, it is repaired
/// once the bundle has its new name.
#[test]
fn the_current_launch_agent_follows_the_bundle_rename() {
    let (root, plan, _data) = fixture();
    let home = root.path().join("home");
    let current = identity::PRODUCTION.login_item;
    let path = login_file_named(
        &home,
        current,
        vec![bundle_exe(&plan.old).to_string_lossy().into_owned().into()],
    );
    move_bundle(&plan).unwrap();
    assert!(repair_login_at(&home, &bundle_exe(&plan.new)).unwrap());
    let entry = plist::Value::from_file(&path).unwrap();
    let d = entry.as_dictionary().unwrap();
    assert_eq!(d["Label"].as_string(), Some(current));
    assert_eq!(
        d["ProgramArguments"].as_array().unwrap()[0].as_string(),
        bundle_exe(&plan.new).to_str()
    );
    assert!(!repair_login_at(&home, &bundle_exe(&plan.new)).unwrap());
}

#[test]
fn disabled_login_stays_disabled_and_unrelated_entries_are_not_rewritten() {
    let (root, plan, _data) = fixture();
    move_bundle(&plan).unwrap();
    let home = root.path().join("home");
    assert!(!repair_login_at(&home, &bundle_exe(&plan.new)).unwrap());
    assert!(!home.exists());
    let unrelated = old_exe(Path::new("/unrelated/App.app"));
    let path = login_file(
        &home,
        vec![unrelated.to_string_lossy().into_owned().into()],
    );
    let before = fs::read(&path).unwrap();
    assert!(!repair_login_at(&home, &bundle_exe(&plan.new)).unwrap());
    assert_eq!(fs::read(path).unwrap(), before);
}
