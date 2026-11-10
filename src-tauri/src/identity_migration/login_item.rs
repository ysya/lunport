//! The launch-at-login entry from before the rename, moved to the current login item and to this version's executable: an entry that
//! was on is made again under the current name, starting this executable, with what else it holds (the macOS launch agent's other keys
//! and arguments, the Linux autostart entry's other keys, Task Manager's state on Windows); the old entry goes either way. The switch in
//! Settings reads the current entry through the autostart plugin, so afterwards it shows what the old one was.
//!
//! The entries are the autostart plugin's (auto-launch): a launch agent in `~/Library/LaunchAgents` on macOS, a value of the Run key
//! with Task Manager's state under `StartupApproved\Run` on Windows (the installer leaves the old one for this), an autostart entry in
//! `~/.config/autostart` on Linux. Only Production registers one: a Development build has nothing to move.
//!
//! The migration moves it in a step of its own on desktop starts (`mover`), until an attempt succeeds.

use std::io;
use std::path::Path;

use super::journal::{Journal, StepState};
use super::{Entry, Mover, Roots};
use crate::app_profile::{self, AppProfile};
use crate::error::AppError;
use crate::legacy_identity;

/// The entry's name from before the rename, and its current one.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Names<'a> {
    pub old: &'a str,
    pub new: &'a str,
}

impl Names<'static> {
    /// The login items of `profile`.
    pub(crate) const fn of(profile: AppProfile) -> Self {
        Self { old: legacy_identity::of(profile).login_item, new: profile.identity().login_item }
    }
}

/// Whether the entry from before the rename is on, decided the way the autostart plugin decides it for its own: what `migrate` is
/// given.
pub fn enabled_before() -> Result<bool, AppError> {
    if !app_profile::CURRENT.allows_os_integrations() {
        return Ok(false);
    }
    platform::enabled(Names::of(app_profile::CURRENT).old)
}

/// Moves the launch-at-login entry to the current name: when the old one was on (`enabled_before`), the current entry starts this
/// executable; the old entry goes either way. Without an old entry there is nothing to move, whatever `enabled_before` says, so running
/// it again changes nothing: a moved entry stays as the user has it since.
pub fn migrate(enabled_before: bool) -> Result<(), AppError> {
    if !app_profile::CURRENT.allows_os_integrations() {
        return Ok(());
    }
    platform::migrate(Names::of(app_profile::CURRENT), enabled_before)
}

/// The step's mover for a start through `entry` (`identity_migration::mover`): the desktop's. `connect` and the MCP adapter leave it to
/// the desktop app, which a client's start brings up too; it asks the user nothing, so a start hidden for a client moves it as well. In
/// a test only stand-ins for this computer's entries move anything (`with_test_entries`): no test reaches the owner's own.
pub(super) fn mover(entry: Entry) -> Option<Mover> {
    #[cfg(test)]
    if TEST_ENTRIES.with(|entries| entries.borrow().is_none()) {
        return None;
    }
    (entry == Entry::Desktop).then_some(run_step as Mover)
}

/// Moves the entry, reading again on every attempt whether the old one is on: an attempt after the one that moved it finds no old
/// entry and changes nothing (`migrate`), so a repeat never changes what the user has since. One that fails leaves the step for the next
/// desktop start, and holds nothing else back.
fn run_step(_: &Roots, _: &mut Journal) -> StepState {
    #[cfg(not(test))]
    let moved = enabled_before().and_then(migrate);
    #[cfg(test)]
    let moved = test_enabled_before().and_then(test_migrate);
    match moved {
        Ok(()) => StepState::Done,
        Err(error) => StepState::Failed(error.to_string()),
    }
}

/// A test's stand-ins for this computer's entries: whether the old one is on, and the move.
#[cfg(test)]
type TestEntries = (Box<dyn Fn() -> Result<bool, AppError>>, Box<dyn Fn(bool) -> Result<(), AppError>>);

#[cfg(test)]
thread_local! {
    /// The stand-ins of a test on this thread (`with_test_entries`).
    static TEST_ENTRIES: std::cell::RefCell<Option<std::rc::Rc<TestEntries>>> = const { std::cell::RefCell::new(None) };
}

#[cfg(test)]
fn test_entries() -> std::rc::Rc<TestEntries> {
    TEST_ENTRIES.with(|entries| entries.borrow().clone()).expect("the test's stand-ins for the entries")
}

#[cfg(test)]
fn test_enabled_before() -> Result<bool, AppError> {
    (test_entries().0)()
}

#[cfg(test)]
fn test_migrate(enabled_before: bool) -> Result<(), AppError> {
    (test_entries().1)(enabled_before)
}

/// Runs `f` with `enabled_before` and `migrate` standing in for this computer's entries on this thread.
#[cfg(test)]
pub(crate) fn with_test_entries<T>(
    enabled_before: impl Fn() -> Result<bool, AppError> + 'static,
    migrate: impl Fn(bool) -> Result<(), AppError> + 'static,
    f: impl FnOnce() -> T,
) -> T {
    struct Restore(Option<std::rc::Rc<TestEntries>>);
    impl Drop for Restore {
        fn drop(&mut self) {
            TEST_ENTRIES.with(|entries| *entries.borrow_mut() = self.0.take());
        }
    }
    let entries: TestEntries = (Box::new(enabled_before), Box::new(migrate));
    let _restore = Restore(TEST_ENTRIES.with(|slot| slot.replace(Some(std::rc::Rc::new(entries)))));
    f()
}

/// The real system's side, which the tests do not reach: where this computer keeps the entries, and the executable the plugin names. The
/// parts below take both as arguments; the tests give them temporary folders and a registry key in memory.
#[cfg(target_os = "macos")]
mod platform {
    use super::*;
    use std::path::PathBuf;

    fn folder() -> Result<PathBuf, AppError> {
        Ok(crate::fsutil::home_dir()?.join("Library/LaunchAgents"))
    }
    pub(super) fn enabled(name: &str) -> Result<bool, AppError> {
        Ok(launch_agent::enabled(&folder()?, name))
    }
    pub(super) fn migrate(names: Names, enabled_before: bool) -> Result<(), AppError> {
        // The plugin names the executable by its real path.
        let exe = std::env::current_exe()?.canonicalize()?;
        launch_agent::migrate(&folder()?, names, &exe, enabled_before)
    }
}

#[cfg(windows)]
mod platform {
    use super::*;
    use winreg::enums::{HKEY_CURRENT_USER, KEY_READ, KEY_SET_VALUE};
    use winreg::RegKey;

    const RUN: &str = r"Software\Microsoft\Windows\CurrentVersion\Run";
    const APPROVED: &str = r"Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run";

    /// `HKEY_CURRENT_USER\<path>` opened with `access`, or `None` when it does not exist.
    fn open(path: &str, access: u32) -> io::Result<Option<RegKey>> {
        absent(RegKey::predef(HKEY_CURRENT_USER).open_subkey_with_flags(path, access))
    }
    pub(super) fn enabled(name: &str) -> Result<bool, AppError> {
        // Read access only, as the plugin reads: a policy that refuses writes there does not stop the check.
        let Some(run) = open(RUN, KEY_READ)? else {
            return Ok(false);
        };
        let approved = open(APPROVED, KEY_READ)?;
        Ok(run_key::enabled(&run, approved.as_ref().map(|key| key as &dyn run_key::Values), name)?)
    }
    pub(super) fn migrate(names: Names, enabled_before: bool) -> Result<(), AppError> {
        // Without a Run key there is no old entry to move.
        let Some(run) = open(RUN, KEY_READ | KEY_SET_VALUE)? else {
            return Ok(());
        };
        let approved = open(APPROVED, KEY_READ | KEY_SET_VALUE)?;
        // The plugin names the executable by the path this process was started from.
        let exe = std::env::current_exe()?;
        Ok(run_key::migrate(&run, approved.as_ref().map(|key| key as &dyn run_key::Values), names, &exe, enabled_before)?)
    }
}

#[cfg(target_os = "linux")]
mod platform {
    use super::*;
    use std::path::PathBuf;

    fn folder() -> Result<PathBuf, AppError> {
        Ok(crate::fsutil::home_dir()?.join(".config/autostart"))
    }
    pub(super) fn enabled(name: &str) -> Result<bool, AppError> {
        Ok(autostart::enabled(&folder()?, name))
    }
    pub(super) fn migrate(names: Names, enabled_before: bool) -> Result<(), AppError> {
        // The plugin names the AppImage that runs, which keeps its path across updates, or else the executable.
        let exe = match std::env::var_os("APPIMAGE").map(PathBuf::from).filter(|path| path.is_absolute()) {
            Some(appimage) => appimage,
            None => std::env::current_exe()?,
        };
        autostart::migrate(&folder()?, names, &exe, enabled_before)
    }
}

#[cfg(not(any(target_os = "macos", windows, target_os = "linux")))]
mod platform {
    use super::*;

    pub(super) fn enabled(_: &str) -> Result<bool, AppError> {
        Ok(false)
    }
    pub(super) fn migrate(_: Names, _: bool) -> Result<(), AppError> {
        Ok(())
    }
}

/// The macOS launch agent `<folder>/<name>.plist`.
#[cfg(target_os = "macos")]
pub(crate) mod launch_agent {
    use super::*;
    use crate::macos_install::{read_login_entry, write_login_entry};
    use std::path::PathBuf;

    fn file(folder: &Path, name: &str) -> PathBuf {
        folder.join(format!("{name}.plist"))
    }

    /// Whether the launch agent `name` is on: it is there, as the plugin tells.
    pub(crate) fn enabled(folder: &Path, name: &str) -> bool {
        file(folder, name).exists()
    }

    /// The launch agent the plugin writes for `exe`.
    fn plugin_agent(name: &str, exe: &Path) -> plist::Value {
        let mut dictionary = plist::Dictionary::new();
        dictionary.insert("Label".into(), name.into());
        dictionary.insert("ProgramArguments".into(), vec![plist::Value::from(exe.to_string_lossy().into_owned())].into());
        dictionary.insert("RunAtLoad".into(), true.into());
        plist::Value::Dictionary(dictionary)
    }

    pub(crate) fn migrate(folder: &Path, names: Names, exe: &Path, enabled_before: bool) -> Result<(), AppError> {
        let old = file(folder, names.old);
        if !present(&old)? {
            return Ok(());
        }
        if enabled_before {
            // What the old agent holds, under the current label and starting `exe`; when it cannot be read, what the plugin writes.
            let agent = match read_login_entry(&old) {
                Ok(Some((_, mut agent))) if agent.as_dictionary().is_some() => {
                    let dictionary = agent.as_dictionary_mut().expect("a dictionary");
                    dictionary.insert("Label".into(), names.new.into());
                    let program = plist::Value::from(exe.to_string_lossy().into_owned());
                    match dictionary.get_mut("ProgramArguments").and_then(|value| value.as_array_mut()) {
                        Some(arguments) if arguments.first().is_some_and(|first| first.as_string().is_some()) => {
                            arguments[0] = program;
                        }
                        _ => {
                            dictionary.insert("ProgramArguments".into(), vec![program].into());
                        }
                    }
                    agent
                }
                _ => plugin_agent(names.new, exe),
            };
            write_login_entry(&file(folder, names.new), &agent, None)?;
        }
        remove(&old)
    }
}

/// The values of a Windows registry key, as the launch-at-login entries need them: the Run key, and Task Manager's state of each entry
/// under `StartupApproved\Run`. A missing value reads as `None`, and removing one that is missing is no error.
#[cfg(any(windows, test))]
pub(crate) mod run_key {
    use super::*;

    /// The state Task Manager keeps for an entry that is on, which the plugin writes when it turns one on.
    const ON: [u8; 12] = [2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];

    pub(crate) trait Values {
        /// Whether the key holds a value `name`, of whatever type.
        fn contains(&self, name: &str) -> io::Result<bool>;
        /// The value `name` when it is a string.
        fn string(&self, name: &str) -> io::Result<Option<String>>;
        /// The data of the value `name`, whatever its type.
        fn binary(&self, name: &str) -> io::Result<Option<Vec<u8>>>;
        fn set_string(&self, name: &str, value: &str) -> io::Result<()>;
        fn set_binary(&self, name: &str, value: &[u8]) -> io::Result<()>;
        fn delete(&self, name: &str) -> io::Result<()>;
    }

    /// Whether a state from Task Manager leaves an entry on: an entry turned off there holds the time it was turned off in its last
    /// eight bytes. A state too short to hold one leaves it on, as it does for the plugin.
    fn on(state: &[u8]) -> bool {
        state.len() < 8 || state[state.len() - 8..].iter().all(|&byte| byte == 0)
    }

    /// Whether the entry `name` is on, as the plugin decides it: its Run value is there, and Task Manager (when it has a state for it)
    /// has not turned it off.
    pub(crate) fn enabled(run: &dyn Values, approved: Option<&dyn Values>, name: &str) -> io::Result<bool> {
        if run.string(name)?.is_none() {
            return Ok(false);
        }
        Ok(match approved {
            Some(approved) => approved.binary(name)?.is_none_or(|state| on(&state)),
            None => true,
        })
    }

    /// The Run value the plugin writes for `exe`: the path as it is, unquoted, and the space before the arguments, of which it has none.
    fn command(exe: &Path) -> String {
        format!("{} ", exe.display())
    }

    pub(crate) fn migrate(
        run: &dyn Values,
        approved: Option<&dyn Values>,
        names: Names,
        exe: &Path,
        enabled_before: bool,
    ) -> io::Result<()> {
        // Without the old Run value there is nothing to move: a moved entry and its state stay as the user has them.
        if run.contains(names.old)? {
            if enabled_before {
                run.set_string(names.new, &command(exe))?;
                if let Some(approved) = approved {
                    // The old entry's state goes with it; an entry on without a state of its own gets the plugin's.
                    let state = approved.binary(names.old)?.filter(|state| on(state)).unwrap_or_else(|| ON.to_vec());
                    approved.set_binary(names.new, &state)?;
                }
            }
            run.delete(names.old)?;
        }
        // A state Task Manager kept for the old name goes in any case.
        if let Some(approved) = approved {
            approved.delete(names.old)?;
        }
        Ok(())
    }
}

/// A registry key's values through winreg, the crate the plugin writes them with: a string is stored as it stores one (REG_SZ), and a
/// value that is not a string reads as no string, as it does for the plugin.
#[cfg(windows)]
impl run_key::Values for winreg::RegKey {
    fn contains(&self, name: &str) -> io::Result<bool> {
        Ok(absent(self.get_raw_value(name))?.is_some())
    }
    fn string(&self, name: &str) -> io::Result<Option<String>> {
        use winreg::types::FromRegValue;
        Ok(absent(self.get_raw_value(name))?.and_then(|value| String::from_reg_value(&value).ok()))
    }
    fn binary(&self, name: &str) -> io::Result<Option<Vec<u8>>> {
        Ok(absent(self.get_raw_value(name))?.map(|value| value.bytes))
    }
    fn set_string(&self, name: &str, value: &str) -> io::Result<()> {
        self.set_value(name, &value)
    }
    fn set_binary(&self, name: &str, value: &[u8]) -> io::Result<()> {
        self.set_raw_value(name, &winreg::RegValue { bytes: value.to_vec(), vtype: winreg::enums::REG_BINARY })
    }
    fn delete(&self, name: &str) -> io::Result<()> {
        absent(self.delete_value(name)).map(|_| ())
    }
}

/// `result`, with a key or value that does not exist as `None`.
#[cfg(windows)]
fn absent<T>(result: io::Result<T>) -> io::Result<Option<T>> {
    match result {
        Ok(value) => Ok(Some(value)),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error),
    }
}

/// The Linux autostart entry `<folder>/<name>.desktop`.
#[cfg(any(target_os = "linux", test))]
pub(crate) mod autostart {
    use super::*;
    use std::path::PathBuf;

    /// The most of an old entry that is read: the plugin writes a few hundred bytes.
    const MAX_BYTES: u64 = 64 * 1024;

    fn file(folder: &Path, name: &str) -> PathBuf {
        folder.join(format!("{name}.desktop"))
    }

    /// Whether the entry `name` is on: it is there, as the plugin tells.
    pub(crate) fn enabled(folder: &Path, name: &str) -> bool {
        file(folder, name).exists()
    }

    /// The `Exec` value the plugin writes for `exe`: the path as it is, and the space before the arguments, of which it has none.
    fn exec(exe: &Path) -> String {
        format!("{} ", exe.display())
    }

    /// The entry as the plugin writes it (auto-launch runs the name into "startup script" in `Comment`).
    fn plugin_entry(name: &str, exe: &Path) -> String {
        format!(
            "[Desktop Entry]\nType=Application\nVersion=1.0\nName={name}\nComment={name}startup script\nExec={}\nStartupNotify=false\nTerminal=false",
            exec(exe)
        )
    }

    /// The old entry under the current name, starting `exe`; the keys a desktop environment added (a delay, or that it is turned off
    /// there) stay.
    fn moved_entry(old_entry: &str, names: Names, exe: &Path) -> String {
        let (old_comment, new_comment) = (format!("Comment={}startup script", names.old), format!("Comment={}startup script", names.new));
        let lines: Vec<String> = old_entry
            .split('\n')
            .map(|line| {
                if line.starts_with("Exec=") {
                    format!("Exec={}", exec(exe))
                } else if line == format!("Name={}", names.old) {
                    format!("Name={}", names.new)
                } else if line == old_comment {
                    new_comment.clone()
                } else {
                    line.to_string()
                }
            })
            .collect();
        lines.join("\n")
    }

    /// The old entry's text, or `None` when it is missing or is not a small text file.
    fn read_entry(path: &Path) -> Option<String> {
        let metadata = std::fs::symlink_metadata(path).ok()?;
        if !metadata.is_file() || metadata.len() > MAX_BYTES {
            return None;
        }
        String::from_utf8(std::fs::read(path).ok()?).ok()
    }

    pub(crate) fn migrate(folder: &Path, names: Names, exe: &Path, enabled_before: bool) -> Result<(), AppError> {
        let old = file(folder, names.old);
        if !present(&old)? {
            return Ok(());
        }
        if enabled_before {
            let entry = match read_entry(&old) {
                Some(old_entry) => moved_entry(&old_entry, names, exe),
                None => plugin_entry(names.new, exe),
            };
            crate::fsutil::atomic_write(&file(folder, names.new), entry.as_bytes(), 0o644)?;
        }
        remove(&old)
    }
}

/// Whether the old entry's file is there (a link that leads nowhere included, which goes like the rest). Only a file that is not there
/// is absent: one that cannot be looked at (a folder that cannot be searched, say) is an error, and the step tries again on a later
/// start.
#[cfg(any(target_os = "macos", target_os = "linux", test))]
fn present(path: &Path) -> io::Result<bool> {
    match std::fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error),
    }
}

/// Removes the old entry's file; one that is gone already is no error.
#[cfg(any(target_os = "macos", target_os = "linux", test))]
fn remove(path: &Path) -> Result<(), AppError> {
    match std::fs::remove_file(path) {
        Err(error) if error.kind() != io::ErrorKind::NotFound => Err(error.into()),
        _ => Ok(()),
    }
}

#[cfg(test)]
#[path = "login_item_tests.rs"]
mod tests;
