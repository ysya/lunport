//! One-time bundle rename. The old absolute path remains a compatibility symlink.
//! Runs before Cocoa, the broker and updater learn this process's executable path.
use crate::app_profile::AppProfile;
// rename(2) can overwrite an empty destination; an exclusive rename never replaces one.
use crate::fsutil::rename_exclusive;
use crate::{identity, legacy_identity};
use serde::{Deserialize, Serialize};
use std::os::unix::{
    fs::{symlink, MetadataExt},
    process::CommandExt,
};
use std::{
    fs, io,
    path::{Path, PathBuf},
    sync::Mutex,
};

static STATUS: Mutex<Option<InstallStatus>> = Mutex::new(None);

#[derive(Clone, Debug, Default, Serialize)]
#[cfg_attr(test, derive(ts_rs::TS))]
#[cfg_attr(test, ts(export, export_to = "../../src/bindings/"))]
pub struct InstallStatus {
    pub needs_attention: bool,
    pub message: Option<String>,
    pub migrated: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
struct Plan {
    old: PathBuf,
    new: PathBuf,
}

/// The profile that the `development` flag of these functions stands for.
fn profile_of(development: bool) -> AppProfile {
    if development {
        AppProfile::Development
    } else {
        AppProfile::Production
    }
}

/// The names the app bundle of this profile had before the rename.
fn old_names(development: bool) -> impl Iterator<Item = &'static str> {
    legacy_identity::of(profile_of(development))
        .bundle_names
        .into_iter()
}

/// The name of the app bundle of this profile, which is the bundle an old one is renamed to.
fn new_name(development: bool) -> String {
    format!("{}.app", profile_of(development).identity().product_name)
}

/// The app bundle that holds `executable`, when its path is `<bundle>/Contents/MacOS/<binary>`.
fn bundle_of<'a>(executable: &'a Path, binary: &str) -> Option<&'a Path> {
    let macos = executable.parent()?;
    let contents = macos.parent()?;
    if executable.file_name()? != binary
        || macos.file_name()? != "MacOS"
        || contents.file_name()? != "Contents"
    {
        return None;
    }
    contents.parent()
}
/// The bundle that holds `executable`, an executable of this version.
fn bundle_for(executable: &Path) -> Option<&Path> {
    bundle_of(executable, identity::current().main_binary)
}
/// The executable of this version in `bundle`.
fn bundle_exe(bundle: &Path) -> PathBuf {
    bundle
        .join("Contents/MacOS")
        .join(identity::current().main_binary)
}
fn validate_plan(plan: &Plan, development: bool) -> io::Result<()> {
    let name = plan.old.file_name().and_then(|v| v.to_str()).unwrap_or("");
    if !plan.old.is_absolute()
        || !old_names(development).any(|old| old == name)
        || plan.old.parent() != plan.new.parent()
        || plan.new.file_name().and_then(|v| v.to_str()) != Some(new_name(development).as_str())
    {
        return Err(io::Error::other("Invalid application rename plan"));
    }
    Ok(())
}
fn same_executable(a: &Path, b: &Path) -> bool {
    match (fs::metadata(a), fs::metadata(b)) {
        (Ok(a), Ok(b)) => a.dev() == b.dev() && a.ino() == b.ino(),
        _ => false,
    }
}

fn complete_link(plan: &Plan) -> io::Result<()> {
    match fs::symlink_metadata(&plan.old) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink()
                && fs::canonicalize(&plan.old).ok() == fs::canonicalize(&plan.new).ok()
            {
                return Ok(());
            }
            Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "The old app path is occupied; it was not replaced",
            ))
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            symlink(plan.new.file_name().unwrap(), &plan.old)
        }
        Err(e) => Err(e),
    }
}

fn move_bundle(plan: &Plan) -> io::Result<()> {
    move_bundle_with(plan, complete_link)
}
fn move_bundle_with(plan: &Plan, link: impl FnOnce(&Plan) -> io::Result<()>) -> io::Result<()> {
    rename_exclusive(&plan.old, &plan.new)?;
    if let Err(error) = link(plan) {
        // Do not overwrite a concurrently-created old path, even while rolling back.
        let _ = rename_exclusive(&plan.new, &plan.old);
        return Err(error);
    }
    Ok(())
}

fn journal_path(data: &Path) -> PathBuf {
    data.join("installation-rename.json")
}
fn set_status(result: io::Result<bool>) {
    *STATUS.lock().unwrap() = Some(match result {
        Ok(migrated) => InstallStatus { migrated, ..Default::default() },
        Err(error) => InstallStatus {
            needs_attention: true,
            message: Some(match error.kind() {
                io::ErrorKind::AlreadyExists => "Lunport could not finish its rename because an application path is occupied. Your existing app and integrations were preserved.".into(),
                io::ErrorKind::PermissionDenied => "Lunport needs permission to finish renaming this installation. You can retry here without reinstalling.".into(),
                _ => "Lunport could not finish renaming this installation. Your app remains usable; retry to finish the migration.".into(),
            }),
            migrated: false,
        },
    });
}

fn lock_installation(root: &Path) -> io::Result<fs::File> {
    use std::{
        io::ErrorKind,
        os::{fd::AsRawFd, unix::fs::OpenOptionsExt},
    };
    crate::fsutil::ensure_dir_secure(root).map_err(io::Error::other)?;
    let file = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(root.join("installation-rename.lock"))?;
    if !file.metadata()?.is_file() {
        return Err(io::Error::other("Invalid installation lock"));
    }
    // Bounded wait: another starting instance should finish its rename promptly.
    for _ in 0..40 {
        if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0 {
            return Ok(file);
        }
        let error = io::Error::last_os_error();
        if error.kind() != ErrorKind::WouldBlock {
            return Err(error);
        }
        std::thread::sleep(std::time::Duration::from_millis(25));
    }
    Err(io::Error::new(
        ErrorKind::WouldBlock,
        "Another instance is finishing the installation",
    ))
}

fn read_plan(executable: &Path, development: bool, data: &Path) -> io::Result<Option<Plan>> {
    let Some(bundle) = bundle_for(executable) else {
        return Ok(None);
    };
    let name = bundle.file_name().and_then(|n| n.to_str()).unwrap_or("");
    let plan = if old_names(development).any(|old| old == name) {
        Some(Plan {
            old: bundle.to_path_buf(),
            new: bundle.with_file_name(new_name(development)),
        })
    } else if name == new_name(development) {
        let path = journal_path(data);
        match fs::symlink_metadata(&path) {
            Err(e) if e.kind() == io::ErrorKind::NotFound => None,
            Err(e) => return Err(e),
            Ok(metadata) if !metadata.is_file() || metadata.len() > 8192 => {
                return Err(io::Error::other("Invalid rename journal"))
            }
            Ok(_) => Some(
                serde_json::from_slice::<Plan>(&fs::read(path)?)
                    .map_err(|_| io::Error::other("Invalid rename journal"))?,
            ),
        }
    } else {
        None
    };
    if let Some(plan) = &plan {
        validate_plan(plan, development)?;
        if bundle != plan.old && bundle != plan.new {
            return Ok(None);
        }
    }
    Ok(plan)
}

fn perform(
    executable: &Path,
    development: bool,
    authorize: bool,
    data: &Path,
) -> io::Result<Option<PathBuf>> {
    perform_with_authorizer(executable, development, authorize, data, authorize_move)
}
fn perform_with_authorizer(
    executable: &Path,
    development: bool,
    authorize: bool,
    data: &Path,
    request_authorization: impl FnOnce(&Path, &std::ffi::OsStr) -> io::Result<()>,
) -> io::Result<Option<PathBuf>> {
    let Some(plan) = read_plan(executable, development, data)? else {
        return Ok(None);
    };
    // Development may exercise the same migration only inside its existing write sandbox.
    crate::fsutil::check_write_io(&plan.old)?;
    crate::fsutil::check_write_io(&plan.new)?;
    let _lock = lock_installation(data)?;
    let path = journal_path(data);
    crate::fsutil::atomic_write(&path, &serde_json::to_vec(&plan)?, 0o600)
        .map_err(io::Error::other)?;
    let canonical = bundle_exe(&plan.new);
    if same_executable(executable, &canonical) {
        complete_link(&plan)?;
    } else {
        if !same_executable(executable, &bundle_exe(&plan.old)) {
            return Err(io::Error::other("The source installation changed"));
        }
        let result = move_bundle(&plan);
        if matches!(&result, Err(e) if e.kind() == io::ErrorKind::PermissionDenied)
            && authorize
            && !development
        {
            request_authorization(executable, plan.old.file_name().unwrap())?;
        } else {
            result?;
        }
    }
    if !same_executable(executable, &canonical) {
        return Err(io::Error::other(
            "The migrated executable did not match this installation",
        ));
    }
    if executable != canonical {
        Ok(Some(canonical))
    } else {
        Ok(None)
    }
}

fn shell_quote(value: &std::ffi::OsStr) -> io::Result<String> {
    let value = value
        .to_str()
        .ok_or_else(|| io::Error::other("The installation path is not UTF-8"))?;
    Ok(format!("'{}'", value.replace('\'', "'\\''")))
}
// Only the system interpreter is elevated. The fixed program and literal paths
// come from this running process, never from a mutable on-disk app executable.
// `__OLD_NAMES__` and `__NEW_NAME__` become JSON, which JavaScript reads as it is.
const AUTHORIZED_MOVE_SCRIPT: &str = r#"
ObjC.import('Foundation');
function run(argv) {
    if (argv.length !== 2) throw Error('Invalid installation arguments');
    var old = argv[0], next = argv[1];
    var folder = old.slice(0, old.lastIndexOf('/') + 1);
    if (!__OLD_NAMES__.some(function (name) { return old.endsWith('/' + name); }) ||
        next !== folder + __NEW_NAME__) {
        throw Error('Invalid installation paths');
    }
    var manager = $.NSFileManager.defaultManager;
    // NSFileManager refuses an existing destination, including during rollback.
    if (!manager.moveItemAtPathToPathError($(old), $(next), Ref())) {
        throw Error('The application could not be moved');
    }
    if (!manager.createSymbolicLinkAtPathWithDestinationPathError($(old), $(__NEW_NAME__), Ref())) {
        manager.moveItemAtPathToPathError($(next), $(old), Ref());
        throw Error('The compatibility link could not be created');
    }
}
"#;

/// The script that moves the production bundle: the old names it accepts and the name it moves to are the identity modules'.
fn authorized_move_script() -> io::Result<String> {
    let old_names: Vec<&str> = old_names(false).collect();
    Ok(AUTHORIZED_MOVE_SCRIPT
        .replace("__OLD_NAMES__", &serde_json::to_string(&old_names)?)
        .replace("__NEW_NAME__", &serde_json::to_string(&new_name(false))?))
}

fn authorization_command(plan: &Plan) -> io::Result<String> {
    validate_plan(plan, false)?;
    Ok(format!(
        "/usr/bin/osascript -l JavaScript -e {} {} {}",
        shell_quote(std::ffi::OsStr::new(&authorized_move_script()?))?,
        shell_quote(plan.old.as_os_str())?,
        shell_quote(plan.new.as_os_str())?,
    ))
}

fn authorize_move(executable: &Path, old_name: &std::ffi::OsStr) -> io::Result<()> {
    let bundle =
        bundle_for(executable).ok_or_else(|| io::Error::other("Not an application bundle"))?;
    if bundle.file_name() != Some(old_name) {
        return Err(io::Error::other("Installation source changed"));
    }
    let plan = Plan {
        old: bundle.to_path_buf(),
        new: bundle.with_file_name(new_name(false)),
    };
    let command = authorization_command(&plan)?;
    let script = format!(
        "do shell script {} with administrator privileges",
        serde_json::to_string(&command)?
    );
    let status = std::process::Command::new("/usr/bin/osascript")
        .args(["-e", &script])
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()?;
    if status.success() {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "Installation authorization was not completed",
        ))
    }
}

pub fn prepare_desktop_launch() {
    let development = !crate::app_profile::CURRENT.allows_os_integrations();
    let result = std::env::current_exe().and_then(|exe| {
        let data = crate::fsutil::app_data_root().map_err(io::Error::other)?;
        perform(&exe, development, true, &data).map(|next| (exe, next, data))
    });
    match result {
        Ok((_, Some(next), _)) => {
            refresh_registration(bundle_for(&next).unwrap());
            let error = std::process::Command::new(next)
                .args(std::env::args_os().skip(1))
                .exec();
            set_status(Err(error));
        }
        Ok((exe, None, data)) => set_status(Ok(read_plan(&exe, development, &data)
            .ok()
            .flatten()
            .is_some())),
        Err(error) => set_status(Err(error)),
    }
}

fn refresh_registration(bundle: &Path) {
    use std::{ffi::c_void, os::unix::ffi::OsStrExt};
    #[link(name = "CoreFoundation", kind = "framework")]
    extern "C" {
        fn CFURLCreateFromFileSystemRepresentation(
            allocator: *const c_void,
            buffer: *const u8,
            length: isize,
            directory: u8,
        ) -> *const c_void;
        fn CFRelease(value: *const c_void);
    }
    #[link(name = "CoreServices", kind = "framework")]
    extern "C" {
        fn LSRegisterURL(url: *const c_void, update: u8) -> i32;
    }
    let bytes = bundle.as_os_str().as_bytes();
    unsafe {
        let url = CFURLCreateFromFileSystemRepresentation(
            std::ptr::null(),
            bytes.as_ptr(),
            bytes.len() as isize,
            1,
        );
        if !url.is_null() {
            let _ = LSRegisterURL(url, 1);
            CFRelease(url);
        }
    }
}

/// The launch agent at `path` as read, its bytes and its property list: `None` when there is none, an error when it is not a small
/// regular file or not a property list.
pub(crate) fn read_login_entry(path: &Path) -> io::Result<Option<(Vec<u8>, plist::Value)>> {
    let metadata = match fs::symlink_metadata(path) {
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        other => other?,
    };
    if !metadata.is_file() || metadata.len() > 65536 {
        return Err(io::Error::other("Invalid login entry"));
    }
    let bytes = fs::read(path)?;
    let value = plist::Value::from_reader(io::Cursor::new(&bytes))
        .map_err(|_| io::Error::other("Cannot parse login entry"))?;
    Ok(Some((bytes, value)))
}

/// Writes the launch agent `entry` to `path` as XML, atomically and for its owner only. `before`, when given, is what `path` must still
/// hold: a change made meanwhile is not overwritten.
pub(crate) fn write_login_entry(path: &Path, entry: &plist::Value, before: Option<&[u8]>) -> io::Result<()> {
    let mut bytes = Vec::new();
    entry.to_writer_xml(&mut bytes).map_err(io::Error::other)?;
    if before.is_some_and(|before| fs::read(path).ok().as_deref() != Some(before)) {
        return Err(io::Error::other("Login entry changed; retry later"));
    }
    crate::fsutil::atomic_write(path, &bytes, 0o600).map_err(io::Error::other)
}

/// Points this app's existing launch agents at `executable` where they still name it by a path from before a rename. The agent under
/// the current login item and the one from before the identity rename are both this app's (the identity migration moves the second to
/// the first, `identity_migration::login_item`); an absent one means launch at login is off, and stays absent. Each agent is repaired on
/// its own: one that cannot be read or written is reported after the other was repaired. Whether one changed.
pub(crate) fn repair_login_at(home: &Path, executable: &Path) -> io::Result<bool> {
    let Some(bundle) = bundle_for(executable) else {
        return Ok(false);
    };
    if bundle.file_name().and_then(|v| v.to_str()) != Some(new_name(false).as_str()) {
        return Ok(false);
    }
    let (mut repaired, mut failure) = (false, None);
    // Production's: only Production has a login item.
    for label in [identity::PRODUCTION.login_item, legacy_identity::PRODUCTION.login_item] {
        let path = home.join(format!("Library/LaunchAgents/{label}.plist"));
        match repair_agent(&path, label, bundle, executable) {
            Ok(changed) => repaired |= changed,
            Err(error) => {
                failure.get_or_insert(error);
            }
        }
    }
    failure.map_or(Ok(repaired), Err)
}

fn repair_agent(path: &Path, label: &str, bundle: &Path, executable: &Path) -> io::Result<bool> {
    let Some((before, mut value)) = read_login_entry(path)? else {
        return Ok(false);
    };
    let dictionary = value
        .as_dictionary_mut()
        .ok_or_else(|| io::Error::other("Invalid login entry"))?;
    if dictionary.get("Label").and_then(|v| v.as_string()) != Some(label) {
        return Ok(false);
    }
    let Some(args) = dictionary
        .get_mut("ProgramArguments")
        .and_then(|v| v.as_array_mut())
    else {
        return Ok(false);
    };
    let Some(first) = args.first().and_then(|v| v.as_string()) else {
        return Ok(false);
    };
    if !names_earlier_executable(Path::new(first), bundle, executable) {
        return Ok(false);
    }
    args[0] = plist::Value::String(executable.to_string_lossy().into_owned());
    write_login_entry(path, &value, Some(&before))?;
    Ok(true)
}

/// Whether `program` is the executable of `bundle`, which runs as `executable`, under a path from before a rename:
/// - in a bundle with an old name beside `bundle`, under the current or the old executable name: the bundle rename left a compatibility
///   link there, through which the old bundle's path leads to the executable that runs;
/// - in `bundle` itself under the old executable name, which no longer exists: 1.14.4 was `Lunport.app` already, and the update replaced
///   the bundle that still had the old executable.
fn names_earlier_executable(program: &Path, bundle: &Path, executable: &Path) -> bool {
    let old_binary = legacy_identity::PRODUCTION.main_binary;
    let Some(program_bundle) =
        bundle_of(program, identity::current().main_binary).or_else(|| bundle_of(program, old_binary))
    else {
        return false;
    };
    if program_bundle == bundle {
        return program.file_name() == Some(old_binary.as_ref())
            && matches!(fs::symlink_metadata(program), Err(e) if e.kind() == io::ErrorKind::NotFound);
    }
    let name = program_bundle.file_name().and_then(|v| v.to_str()).unwrap_or("");
    program_bundle.parent() == bundle.parent()
        && old_names(false).any(|old| old == name)
        && same_executable(&bundle_exe(program_bundle), executable)
}

pub(crate) fn repair_login() {
    if !crate::app_profile::CURRENT.allows_os_integrations() {
        return;
    }
    let result = crate::fsutil::home_dir()
        .map_err(io::Error::other)
        .and_then(|home| repair_login_at(&home, &std::env::current_exe()?));
    if let Err(error) = result {
        set_status(Err(error));
    }
}

#[tauri::command]
pub fn app_installation_status() -> InstallStatus {
    STATUS.lock().unwrap().clone().unwrap_or_default()
}

#[tauri::command]
pub fn app_finish_rename(app: tauri::AppHandle) -> Result<(), crate::error::AppError> {
    // The existing restart lifecycle handles active-session confirmation in the frontend.
    // A normal restart reaches prepare_desktop_launch before any broker/GUI initialization.
    app.restart();
}

#[cfg(test)]
#[path = "macos_install_tests.rs"]
mod tests;
