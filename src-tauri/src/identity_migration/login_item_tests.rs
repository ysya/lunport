//! The launch-at-login entry as 1.14.4 left it, in a temporary folder or a registry key in memory: the autostart plugin's entry
//! `SSHelter`, which the first start moves to `Lunport`. Nothing here reads or writes this computer's own entries.

use super::*;
use std::cell::RefCell;
use std::collections::BTreeMap;
use std::fs;
use std::io;
use std::path::Path;

const NAMES: Names<'static> = Names { old: "SSHelter", new: "Lunport" };

#[test]
fn the_entry_moves_from_the_old_login_item_to_the_current_one() {
    assert_eq!(Names::of(AppProfile::Production), NAMES);
    assert_eq!(
        Names::of(AppProfile::Development),
        Names { old: "SSHelter Dev", new: "Lunport Dev" }
    );
}

/// A registry key in memory.
#[derive(Default)]
struct Key(RefCell<BTreeMap<String, Data>>);

#[derive(Clone, Debug, PartialEq, Eq)]
enum Data {
    Text(String),
    Bytes(Vec<u8>),
}

impl Key {
    fn with(values: &[(&str, Data)]) -> Self {
        Self(RefCell::new(values.iter().map(|(name, data)| (name.to_string(), data.clone())).collect()))
    }
    fn get(&self, name: &str) -> Option<Data> {
        self.0.borrow().get(name).cloned()
    }
    fn names(&self) -> Vec<String> {
        self.0.borrow().keys().cloned().collect()
    }
}

impl run_key::Values for Key {
    fn contains(&self, name: &str) -> io::Result<bool> {
        Ok(self.0.borrow().contains_key(name))
    }
    fn string(&self, name: &str) -> io::Result<Option<String>> {
        Ok(match self.get(name) {
            Some(Data::Text(text)) => Some(text),
            _ => None,
        })
    }
    fn binary(&self, name: &str) -> io::Result<Option<Vec<u8>>> {
        Ok(match self.get(name) {
            Some(Data::Bytes(bytes)) => Some(bytes),
            _ => None,
        })
    }
    fn set_string(&self, name: &str, value: &str) -> io::Result<()> {
        self.0.borrow_mut().insert(name.into(), Data::Text(value.into()));
        Ok(())
    }
    fn set_binary(&self, name: &str, value: &[u8]) -> io::Result<()> {
        self.0.borrow_mut().insert(name.into(), Data::Bytes(value.into()));
        Ok(())
    }
    fn delete(&self, name: &str) -> io::Result<()> {
        self.0.borrow_mut().remove(name);
        Ok(())
    }
}

const OLD_EXE: &str = r"C:\Users\frank\AppData\Local\Lunport\sshelter.exe";
const NEW_EXE: &str = r"C:\Users\frank\AppData\Local\Lunport\lunport.exe";
/// Task Manager's state of an entry that is on, which the autostart plugin writes when it turns one on.
const ON: [u8; 12] = [2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
/// Task Manager's state of an entry turned off there: the time it was turned off fills the last eight bytes.
const OFF: [u8; 12] = [3, 0, 0, 0, 0x60, 0x2b, 0x9c, 0x1e, 0x51, 0x4f, 0xdc, 0x01];
const ONEDRIVE: &str = r#""C:\Program Files\Microsoft OneDrive\OneDrive.exe" /background"#;

/// The Run key and Task Manager's key as 1.14.4 leaves them beside another program's entry: the autostart plugin's value (the unquoted
/// path, then a space) and Task Manager's `state` for it.
fn registry_1_14_4(state: &[u8]) -> (Key, Key) {
    let run = Key::with(&[
        ("SSHelter", Data::Text(format!("{OLD_EXE} "))),
        ("OneDrive", Data::Text(ONEDRIVE.into())),
    ]);
    let approved = Key::with(&[("SSHelter", Data::Bytes(state.to_vec())), ("OneDrive", Data::Bytes(ON.to_vec()))]);
    (run, approved)
}

#[test]
fn old_run_value_becomes_lunport_with_its_startup_state() {
    let (run, approved) = registry_1_14_4(&ON);
    let enabled = run_key::enabled(&run, Some(&approved), NAMES.old).unwrap();
    assert!(enabled);
    run_key::migrate(&run, Some(&approved), NAMES, Path::new(NEW_EXE), enabled).unwrap();
    // As the autostart plugin writes it for this executable, so that the switch in Settings reads it as on.
    assert_eq!(run.get("Lunport"), Some(Data::Text(format!("{NEW_EXE} "))));
    assert_eq!(approved.get("Lunport"), Some(Data::Bytes(ON.to_vec())));
    assert!(run_key::enabled(&run, Some(&approved), NAMES.new).unwrap());
    // The old name is gone from both keys; another program's entry is as it was.
    assert_eq!(run.names(), ["Lunport", "OneDrive"]);
    assert_eq!(approved.names(), ["Lunport", "OneDrive"]);
    assert_eq!(run.get("OneDrive"), Some(Data::Text(ONEDRIVE.into())));
}

#[test]
fn old_run_value_removed_when_disabled() {
    let (run, approved) = registry_1_14_4(&OFF);
    let enabled = run_key::enabled(&run, Some(&approved), NAMES.old).unwrap();
    assert!(!enabled);
    run_key::migrate(&run, Some(&approved), NAMES, Path::new(NEW_EXE), enabled).unwrap();
    assert_eq!(run.names(), ["OneDrive"]);
    assert_eq!(approved.names(), ["OneDrive"]);
    assert!(!run_key::enabled(&run, Some(&approved), NAMES.new).unwrap());
}

#[test]
fn a_run_value_is_on_the_way_the_autostart_plugin_reads_it() {
    let run = Key::with(&[("SSHelter", Data::Text(format!("{OLD_EXE} ")))]);
    let state = |bytes: &[u8]| Key::with(&[("SSHelter", Data::Bytes(bytes.to_vec()))]);
    // No state in Task Manager, no Task Manager key at all, or a state too short to hold a time: on.
    assert!(run_key::enabled(&run, Some(&Key::default()), NAMES.old).unwrap());
    assert!(run_key::enabled(&run, None, NAMES.old).unwrap());
    assert!(run_key::enabled(&run, Some(&state(&[3])), NAMES.old).unwrap());
    assert!(run_key::enabled(&run, Some(&state(&ON)), NAMES.old).unwrap());
    assert!(!run_key::enabled(&run, Some(&state(&OFF)), NAMES.old).unwrap());
    // Without its Run value there is no entry, whatever Task Manager holds.
    assert!(!run_key::enabled(&Key::default(), Some(&state(&ON)), NAMES.old).unwrap());
}

/// Once the entry has moved, a later run finds no old entry and changes nothing, whatever it is told: a moved entry the user turned
/// off in Task Manager stays off.
#[test]
fn moving_the_run_value_again_changes_nothing() {
    let (run, approved) = registry_1_14_4(&ON);
    run_key::migrate(&run, Some(&approved), NAMES, Path::new(NEW_EXE), true).unwrap();
    run_key::Values::set_binary(&approved, "Lunport", &OFF).unwrap();
    for enabled_before in [true, false] {
        run_key::migrate(&run, Some(&approved), NAMES, Path::new(NEW_EXE), enabled_before).unwrap();
        assert_eq!(run.names(), ["Lunport", "OneDrive"]);
        assert_eq!(run.get("Lunport"), Some(Data::Text(format!("{NEW_EXE} "))));
        assert_eq!(approved.get("Lunport"), Some(Data::Bytes(OFF.to_vec())));
    }
    // Without any entry, nothing is made either.
    let (run, approved) = (Key::default(), Key::default());
    run_key::migrate(&run, Some(&approved), NAMES, Path::new(NEW_EXE), true).unwrap();
    assert!(run.names().is_empty() && approved.names().is_empty());
}

/// The Run value from before the rename is gone already (removed by the user, or by a cleanup) while Task Manager still keeps a state
/// under the old name: that state goes, and nothing else changes, whatever the step is told.
#[test]
fn a_leftover_task_manager_state_goes_without_its_run_value() {
    for enabled_before in [false, true] {
        let run = Key::with(&[("Lunport", Data::Text(format!("{NEW_EXE} "))), ("OneDrive", Data::Text(ONEDRIVE.into()))]);
        let approved = Key::with(&[
            ("SSHelter", Data::Bytes(ON.to_vec())),
            ("Lunport", Data::Bytes(OFF.to_vec())),
            ("OneDrive", Data::Bytes(ON.to_vec())),
        ]);
        let (run_before, mut approved_after) = (run.0.borrow().clone(), approved.0.borrow().clone());
        approved_after.remove("SSHelter");
        assert!(!run_key::enabled(&run, Some(&approved), NAMES.old).unwrap(), "without its Run value the old entry is off");
        run_key::migrate(&run, Some(&approved), NAMES, Path::new(NEW_EXE), enabled_before).unwrap();
        assert_eq!(*run.0.borrow(), run_before, "the Run key is as it was ({enabled_before})");
        assert_eq!(*approved.0.borrow(), approved_after, "only the old state went ({enabled_before})");
    }
}

#[test]
fn an_entry_that_was_on_moves_without_task_managers_key_and_without_a_state() {
    let run = Key::with(&[("SSHelter", Data::Text(format!("{OLD_EXE} ")))]);
    run_key::migrate(&run, None, NAMES, Path::new(NEW_EXE), true).unwrap();
    assert_eq!(run.names(), ["Lunport"]);
    assert_eq!(run.get("Lunport"), Some(Data::Text(format!("{NEW_EXE} "))));

    // Task Manager's key without a state for the old entry: the moved one gets the state the plugin gives an entry it turns on.
    let run = Key::with(&[("SSHelter", Data::Text(format!("{OLD_EXE} ")))]);
    let approved = Key::default();
    run_key::migrate(&run, Some(&approved), NAMES, Path::new(NEW_EXE), true).unwrap();
    assert_eq!(approved.get("Lunport"), Some(Data::Bytes(ON.to_vec())));
    assert!(run_key::enabled(&run, Some(&approved), NAMES.new).unwrap());
}

/// The autostart entry as the autostart plugin writes it (auto-launch 0.5: `Comment` runs the name into "startup script", `Exec` ends in
/// the space before the arguments, of which there are none), with a key a desktop environment added.
const AUTOSTART_1_14_4: &str = "[Desktop Entry]\nType=Application\nVersion=1.0\nName=SSHelter\nComment=SSHelterstartup script\nExec=/usr/bin/sshelter \nStartupNotify=false\nTerminal=false\nX-GNOME-Autostart-Delay=5";

#[test]
fn linux_autostart_renamed() {
    let temp = tempfile::tempdir().unwrap();
    let folder = temp.path().join("autostart");
    fs::create_dir(&folder).unwrap();
    fs::write(folder.join("SSHelter.desktop"), AUTOSTART_1_14_4).unwrap();
    let exe = Path::new("/usr/bin/lunport");
    assert!(autostart::enabled(&folder, NAMES.old));
    autostart::migrate(&folder, NAMES, exe, true).unwrap();
    assert!(!folder.join("SSHelter.desktop").exists());
    assert!(autostart::enabled(&folder, NAMES.new));
    assert_eq!(
        fs::read_to_string(folder.join("Lunport.desktop")).unwrap(),
        "[Desktop Entry]\nType=Application\nVersion=1.0\nName=Lunport\nComment=Lunportstartup script\nExec=/usr/bin/lunport \nStartupNotify=false\nTerminal=false\nX-GNOME-Autostart-Delay=5"
    );
}

/// Once the entry has moved, a later run finds no old entry and changes nothing, whatever it is told: a moved entry the desktop
/// environment turned off stays off.
#[test]
fn moving_the_linux_entry_again_changes_nothing() {
    let temp = tempfile::tempdir().unwrap();
    let folder = temp.path().join("autostart");
    fs::create_dir(&folder).unwrap();
    fs::write(folder.join("SSHelter.desktop"), AUTOSTART_1_14_4).unwrap();
    let exe = Path::new("/usr/bin/lunport");
    autostart::migrate(&folder, NAMES, exe, true).unwrap();
    let moved = format!("{}\nX-GNOME-Autostart-enabled=false", fs::read_to_string(folder.join("Lunport.desktop")).unwrap());
    fs::write(folder.join("Lunport.desktop"), &moved).unwrap();
    for enabled_before in [true, false] {
        autostart::migrate(&folder, NAMES, exe, enabled_before).unwrap();
        assert_eq!(fs::read_to_string(folder.join("Lunport.desktop")).unwrap(), moved);
    }
    // Without any entry, nothing is made either.
    let empty = temp.path().join("empty");
    autostart::migrate(&empty, NAMES, exe, true).unwrap();
    assert!(!empty.join("Lunport.desktop").exists());
}

#[test]
fn linux_autostart_removed_when_disabled() {
    let temp = tempfile::tempdir().unwrap();
    let folder = temp.path().join("autostart");
    fs::create_dir(&folder).unwrap();
    fs::write(folder.join("SSHelter.desktop"), AUTOSTART_1_14_4).unwrap();
    autostart::migrate(&folder, NAMES, Path::new("/usr/bin/lunport"), false).unwrap();
    assert!(fs::read_dir(&folder).unwrap().next().is_none());
}

#[cfg(unix)]
#[test]
fn only_an_entry_file_that_is_not_there_is_absent() {
    let temp = tempfile::tempdir().unwrap();
    let file = temp.path().join("entry");
    assert!(!present(&file).unwrap());
    fs::write(&file, b"").unwrap();
    assert!(present(&file).unwrap());
    let dangling = temp.path().join("dangling");
    std::os::unix::fs::symlink(temp.path().join("gone"), &dangling).unwrap();
    assert!(present(&dangling).unwrap(), "a link that leads nowhere goes like the rest");
    assert_ne!(present(&file.join("child")).unwrap_err().kind(), io::ErrorKind::NotFound);
}

/// Only an old entry that is not there counts as absent. One that cannot be looked at (a folder that cannot be searched, or a file in
/// the folder's place) fails the move, which the next start tries again, instead of passing for an entry that was never there: the
/// old entry stays, and nothing is made.
#[cfg(unix)]
#[test]
fn a_linux_entry_that_cannot_be_looked_at_is_not_taken_for_absent() {
    use std::os::unix::fs::PermissionsExt;
    let temp = tempfile::tempdir().unwrap();
    let exe = Path::new("/usr/bin/lunport");

    let blocked = temp.path().join("blocked");
    fs::write(&blocked, b"not a folder").unwrap();
    for enabled_before in [true, false] {
        let error = autostart::migrate(&blocked, NAMES, exe, enabled_before).unwrap_err();
        assert!(matches!(&error, AppError::Io(error) if error.kind() != io::ErrorKind::NotFound), "{error:?}");
    }
    assert_eq!(fs::read(&blocked).unwrap(), b"not a folder");

    let folder = temp.path().join("autostart");
    fs::create_dir(&folder).unwrap();
    fs::write(folder.join("SSHelter.desktop"), AUTOSTART_1_14_4).unwrap();
    fs::set_permissions(&folder, fs::Permissions::from_mode(0o000)).unwrap();
    let held_back = fs::symlink_metadata(folder.join("SSHelter.desktop")).is_err();
    let result = autostart::migrate(&folder, NAMES, exe, false);
    fs::set_permissions(&folder, fs::Permissions::from_mode(0o755)).unwrap();
    if held_back {
        assert!(result.is_err(), "{result:?}");
    }
    assert_eq!(fs::read_to_string(folder.join("SSHelter.desktop")).unwrap(), AUTOSTART_1_14_4, "the old entry stays for the next start");
    assert!(!folder.join("Lunport.desktop").exists());
}

/// An old entry that is not text gives way to the entry the plugin writes.
#[test]
fn a_linux_entry_that_cannot_be_read_gives_way_to_the_plugins_entry() {
    let temp = tempfile::tempdir().unwrap();
    let folder = temp.path().join("autostart");
    fs::create_dir(&folder).unwrap();
    fs::write(folder.join("SSHelter.desktop"), b"[Desktop Entry]\nName=\xff\xfe\n").unwrap();
    autostart::migrate(&folder, NAMES, Path::new("/home/frank/Applications/Lunport.AppImage"), true).unwrap();
    assert!(!folder.join("SSHelter.desktop").exists());
    assert_eq!(
        fs::read_to_string(folder.join("Lunport.desktop")).unwrap(),
        "[Desktop Entry]\nType=Application\nVersion=1.0\nName=Lunport\nComment=Lunportstartup script\nExec=/home/frank/Applications/Lunport.AppImage \nStartupNotify=false\nTerminal=false"
    );
}

#[cfg(target_os = "macos")]
mod launch_agents {
    use super::*;
    use std::path::PathBuf;

    /// A home folder's launch agents, with 1.14.4's executable (gone since the update) and this version's in the same bundle.
    struct Mac {
        temp: tempfile::TempDir,
    }

    impl Mac {
        fn new() -> Self {
            Self { temp: tempfile::tempdir().unwrap() }
        }
        fn folder(&self) -> PathBuf {
            self.temp.path().join("Library/LaunchAgents")
        }
        fn old_exe(&self) -> PathBuf {
            self.temp.path().join("Applications/Lunport.app/Contents/MacOS/sshelter")
        }
        fn new_exe(&self) -> PathBuf {
            self.temp.path().join("Applications/Lunport.app/Contents/MacOS/lunport")
        }
        /// 1.14.4's launch agent as the autostart plugin writes it, with `arguments` after the program and `keys` after `RunAtLoad`.
        fn agent_1_14_4(&self, arguments: &str, keys: &str) -> PathBuf {
            fs::create_dir_all(self.folder()).unwrap();
            let path = self.folder().join("SSHelter.plist");
            fs::write(
                &path,
                format!(
                    "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \
                     \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n<plist version=\"1.0\">\n  <dict>\n  <key>Label</key>\n  \
                     <string>SSHelter</string>\n  <key>ProgramArguments</key>\n  <array><string>{}</string>{arguments}</array>\n  \
                     <key>RunAtLoad</key>\n  <true/>{keys}\n  </dict>\n</plist>",
                    self.old_exe().display()
                ),
            )
            .unwrap();
            path
        }
        fn migrate(&self, enabled_before: bool) {
            launch_agent::migrate(&self.folder(), NAMES, &self.new_exe(), enabled_before).unwrap();
        }
        fn current(&self) -> plist::Value {
            plist::Value::from_file(self.folder().join("Lunport.plist")).unwrap()
        }
    }

    /// The launch agent the autostart plugin writes for `exe`.
    fn plugin_agent(exe: &Path) -> plist::Value {
        let mut dictionary = plist::Dictionary::new();
        dictionary.insert("Label".into(), "Lunport".into());
        dictionary.insert("ProgramArguments".into(), vec![plist::Value::from(exe.to_str().unwrap())].into());
        dictionary.insert("RunAtLoad".into(), true.into());
        plist::Value::Dictionary(dictionary)
    }

    #[test]
    fn old_launch_agent_enabled_becomes_lunport_enabled() {
        let mac = Mac::new();
        mac.agent_1_14_4("", "");
        assert!(launch_agent::enabled(&mac.folder(), NAMES.old));
        mac.migrate(true);
        assert!(!mac.folder().join("SSHelter.plist").exists());
        assert!(launch_agent::enabled(&mac.folder(), NAMES.new));
        assert_eq!(mac.current(), plugin_agent(&mac.new_exe()));
    }

    /// Once the agent has moved, a later run finds no old agent and changes nothing, whatever it is told: the moved agent keeps its
    /// other arguments and keys, and no agent is made where there was none.
    #[test]
    fn moving_the_launch_agent_again_changes_nothing() {
        let mac = Mac::new();
        mac.agent_1_14_4("<string>--keep</string>", "\n  <key>ProcessType</key>\n  <string>Interactive</string>");
        mac.migrate(true);
        let moved = fs::read(mac.folder().join("Lunport.plist")).unwrap();
        for enabled_before in [true, false] {
            mac.migrate(enabled_before);
            assert_eq!(fs::read(mac.folder().join("Lunport.plist")).unwrap(), moved);
        }
        let empty = Mac::new();
        empty.migrate(true);
        assert!(!empty.folder().join("Lunport.plist").exists());
    }

    #[test]
    fn a_moved_launch_agent_keeps_its_other_arguments_and_settings() {
        let mac = Mac::new();
        mac.agent_1_14_4("<string>--keep</string>", "\n  <key>ProcessType</key>\n  <string>Interactive</string>");
        mac.migrate(true);
        let entry = mac.current();
        let d = entry.as_dictionary().unwrap();
        assert_eq!(d["Label"].as_string(), Some("Lunport"));
        let arguments: Vec<_> = d["ProgramArguments"].as_array().unwrap().iter().map(|v| v.as_string().unwrap()).collect();
        assert_eq!(arguments, [mac.new_exe().to_str().unwrap(), "--keep"]);
        assert_eq!(d["RunAtLoad"].as_boolean(), Some(true));
        assert_eq!(d["ProcessType"].as_string(), Some("Interactive"));
    }

    #[test]
    fn old_launch_agent_removed_when_disabled() {
        let mac = Mac::new();
        mac.agent_1_14_4("", "");
        mac.migrate(false);
        assert!(fs::read_dir(mac.folder()).unwrap().next().is_none());
    }

    /// Only an old agent that is not there counts as absent: one that cannot be looked at fails the move, which the next start tries
    /// again, and nothing changes.
    #[test]
    fn an_old_launch_agent_that_cannot_be_looked_at_is_not_taken_for_absent() {
        let mac = Mac::new();
        fs::create_dir_all(mac.folder().parent().unwrap()).unwrap();
        fs::write(mac.folder(), b"not a folder").unwrap();
        for enabled_before in [true, false] {
            let error = launch_agent::migrate(&mac.folder(), NAMES, &mac.new_exe(), enabled_before).unwrap_err();
            assert!(matches!(&error, AppError::Io(error) if error.kind() != io::ErrorKind::NotFound), "{error:?}");
        }
        assert_eq!(fs::read(mac.folder()).unwrap(), b"not a folder");
    }

    #[test]
    fn an_old_launch_agent_that_cannot_be_read_gives_way_to_the_plugins_entry() {
        let mac = Mac::new();
        fs::create_dir_all(mac.folder()).unwrap();
        fs::write(mac.folder().join("SSHelter.plist"), b"not a property list").unwrap();
        mac.migrate(true);
        assert!(!mac.folder().join("SSHelter.plist").exists());
        assert_eq!(mac.current(), plugin_agent(&mac.new_exe()));
    }
}
