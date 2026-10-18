//! One-time bundle rename. The old absolute path remains a compatibility symlink.
//! Runs before Cocoa, the broker and updater learn this process's executable path.
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

const HELPER_MODE: &str = "--finish-app-rename";
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

fn old_names(development: bool) -> &'static [&'static str] {
    if development {
        &["SSHelter Dev.app", "sshelter Dev.app"]
    } else {
        &["SSHelter.app", "sshelter.app"]
    }
}
fn bundle_for(executable: &Path) -> Option<&Path> {
    let macos = executable.parent()?;
    let contents = macos.parent()?;
    if executable.file_name()? != "sshelter"
        || macos.file_name()? != "MacOS"
        || contents.file_name()? != "Contents"
    {
        return None;
    }
    contents.parent()
}
fn bundle_exe(bundle: &Path) -> PathBuf {
    bundle.join("Contents/MacOS/sshelter")
}
fn validate_plan(plan: &Plan, development: bool) -> io::Result<()> {
    let name = plan.old.file_name().and_then(|v| v.to_str()).unwrap_or("");
    let new_name = if development {
        "Lunport Dev.app"
    } else {
        "Lunport.app"
    };
    if !plan.old.is_absolute()
        || !old_names(development).contains(&name)
        || plan.old.parent() != plan.new.parent()
        || plan.new.file_name().and_then(|v| v.to_str()) != Some(new_name)
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

/// rename(2) can overwrite an empty destination; RENAME_EXCL never replaces one.
fn rename_exclusive(from: &Path, to: &Path) -> io::Result<()> {
    use std::{ffi::CString, os::unix::ffi::OsStrExt};
    let from = CString::new(from.as_os_str().as_bytes())?;
    let to = CString::new(to.as_os_str().as_bytes())?;
    let result = unsafe { libc::renamex_np(from.as_ptr(), to.as_ptr(), libc::RENAME_EXCL) };
    if result == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
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
    let plan = if old_names(development).contains(&name) {
        Some(Plan {
            old: bundle.to_path_buf(),
            new: bundle.with_file_name(if development {
                "Lunport Dev.app"
            } else {
                "Lunport.app"
            }),
        })
    } else if name
        == if development {
            "Lunport Dev.app"
        } else {
            "Lunport.app"
        }
    {
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
fn authorize_move(executable: &Path, old_name: &std::ffi::OsStr) -> io::Result<()> {
    // A fixed self-mode computes its own source/destination; no caller-supplied paths or shell code.
    let command = format!(
        "{} {} {}",
        shell_quote(executable.as_os_str())?,
        HELPER_MODE,
        shell_quote(old_name)?
    );
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

/// The only elevated mode moves this very app and creates its old-name compatibility link.
/// It never initializes Tauri, reads a user's credentials or accepts a destination path.
pub fn handle_installer_mode() {
    let args: Vec<_> = std::env::args_os().collect();
    if args.get(1).and_then(|s| s.to_str()) != Some(HELPER_MODE) {
        return;
    }
    let result = (|| -> io::Result<()> {
        if unsafe { libc::geteuid() } != 0
            || !crate::app_profile::CURRENT.allows_os_integrations()
            || args.len() != 3
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "Invalid installation mode",
            ));
        }
        let exe = std::env::current_exe()?;
        let bundle =
            bundle_for(&exe).ok_or_else(|| io::Error::other("Not an application bundle"))?;
        let old_name = args[2].to_str().unwrap_or("");
        if !old_names(false).contains(&old_name) {
            return Err(io::Error::other("Invalid legacy name"));
        }
        let plan = Plan {
            old: bundle.with_file_name(old_name),
            new: bundle.with_file_name("Lunport.app"),
        };
        validate_plan(&plan, false)?;
        if bundle == plan.old {
            move_bundle(&plan)
        } else if bundle == plan.new {
            complete_link(&plan)
        } else {
            Err(io::Error::other("Not a legacy or migrated installation"))
        }
    })();
    std::process::exit(if result.is_ok() { 0 } else { 1 });
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

/// Update only this app's existing launch entry; absent means disabled and stays absent.
pub(crate) fn repair_login_at(home: &Path, executable: &Path) -> io::Result<bool> {
    let Some(bundle) = bundle_for(executable) else {
        return Ok(false);
    };
    if bundle.file_name().and_then(|v| v.to_str()) != Some("Lunport.app") {
        return Ok(false);
    }
    let path = home.join("Library/LaunchAgents/SSHelter.plist");
    let metadata = match fs::symlink_metadata(&path) {
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(false),
        other => other?,
    };
    if !metadata.is_file() || metadata.len() > 65536 {
        return Err(io::Error::other("Invalid login entry"));
    }
    let before = fs::read(&path)?;
    let mut value = plist::Value::from_reader(std::io::Cursor::new(&before))
        .map_err(|_| io::Error::other("Cannot parse login entry"))?;
    let dictionary = value
        .as_dictionary_mut()
        .ok_or_else(|| io::Error::other("Invalid login entry"))?;
    if dictionary.get("Label").and_then(|v| v.as_string()) != Some("SSHelter") {
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
    let old = Path::new(first);
    let Some(old_bundle) = bundle_for(old) else {
        return Ok(false);
    };
    if old_bundle.parent() != bundle.parent()
        || !old_names(false).contains(
            &old_bundle
                .file_name()
                .and_then(|v| v.to_str())
                .unwrap_or(""),
        )
    {
        return Ok(false);
    }
    if !same_executable(old, executable) {
        return Ok(false);
    }
    args[0] = plist::Value::String(executable.to_string_lossy().into_owned());
    let mut bytes = Vec::new();
    value.to_writer_xml(&mut bytes).map_err(io::Error::other)?;
    if fs::read(&path)? != before {
        return Err(io::Error::other("Login entry changed; retry later"));
    }
    crate::fsutil::atomic_write(&path, &bytes, 0o600).map_err(io::Error::other)?;
    Ok(true)
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
