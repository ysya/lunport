//! Bounded, local diagnostics. Never record error Display strings, panic payloads, records,
//! credentials, command arguments or environment variables. Backtraces contain code locations only.
use serde::Serialize;
use std::{
    fs::{self, File, OpenOptions},
    io::{self, Write},
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicU8, Ordering},
        Mutex, OnceLock,
    },
    time::{SystemTime, UNIX_EPOCH},
};

const MAX_LOG_BYTES: u64 = 256 * 1024;
const MAX_EVENT_BYTES: usize = 32 * 1024;
static LOGGER: OnceLock<Logger> = OnceLock::new();
static STAGE: AtomicU8 = AtomicU8::new(Stage::Bootstrap as u8);

#[derive(Clone, Copy)]
#[repr(u8)]
pub(crate) enum Stage {
    Bootstrap,
    Context,
    Setup,
    Tray,
    Sync,
    Mcp,
    Broker,
    Window,
    Ready,
    Exit,
}
impl Stage {
    fn name(value: u8) -> &'static str {
        match value {
            0 => "bootstrap",
            1 => "context",
            2 => "setup",
            3 => "tray",
            4 => "sync",
            5 => "mcp",
            6 => "broker",
            7 => "window",
            8 => "ready",
            9 => "exit",
            _ => "unknown",
        }
    }
}

struct Logger {
    directory: PathBuf,
    writer: Mutex<()>,
}
#[derive(Serialize)]
struct Event<'a> {
    timestamp_ms: u128,
    pid: u32,
    app_version: &'static str,
    profile: &'static str,
    platform: &'static str,
    event: &'a str,
    stage: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    code: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    backtrace: Option<&'a str>,
}

pub(crate) fn directory() -> Result<PathBuf, crate::error::AppError> {
    Ok(crate::fsutil::app_data_root()?.join("diagnostics"))
}

pub(crate) fn install() {
    let Ok(directory) = directory() else { return };
    if let Err(error) = install_at(directory) {
        // IO kind only: even a failed log path must not expose user data to stderr.
        eprintln!(
            "[diagnostics] local logging unavailable: {:?}",
            error.kind()
        );
    }
}

fn install_at(directory: PathBuf) -> io::Result<()> {
    prepare_directory(&directory)?;
    let logger = Logger {
        directory,
        writer: Mutex::new(()),
    };
    logger.write("logging_started", None, None, false)?;
    if LOGGER.set(logger).is_err() {
        return Ok(());
    }
    #[cfg(windows)]
    if windows::install(&LOGGER.get().unwrap().directory).is_err() {
        event("native_logging_unavailable", None);
    }
    let previous = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        // Do not format `info`: its payload can include a secret from a failed assertion.
        let location = info
            .location()
            .map(|location| {
                format!(
                    "{}:{}:{}",
                    location.file(),
                    location.line(),
                    location.column()
                )
            })
            .unwrap_or_else(|| "unknown".into());
        let backtrace = format!(
            "panic at {location}\n{}",
            std::backtrace::Backtrace::force_capture()
        );
        if let Some(logger) = LOGGER.get() {
            let _ = logger.write(
                "rust_panic",
                Some("payload_omitted"),
                Some(&backtrace),
                true,
            );
        }
        previous(info);
    }));
    Ok(())
}

pub(crate) fn stage(stage: Stage) {
    STAGE.store(stage as u8, Ordering::Relaxed);
    event("startup_stage", None);
}

pub(crate) fn event(name: &'static str, code: Option<&str>) {
    if let Some(logger) = LOGGER.get() {
        let _ = logger.write(name, code, None, false);
    }
}

pub(crate) fn app_error(name: &'static str, error: &crate::error::AppError) {
    use crate::error::AppError;
    let code = match error {
        AppError::Io(error) => format!(
            "io:{:?}:{}",
            error.kind(),
            error.raw_os_error().unwrap_or(0)
        ),
        AppError::ForbiddenPath(_) => "forbidden_path".into(),
        AppError::NotFound(_) => "not_found".into(),
        AppError::Parse { .. } => "parse".into(),
        AppError::Conflict(_) => "conflict".into(),
        AppError::Other(_) => "operation_failed".into(),
    };
    event(name, Some(&code));
}

pub(crate) fn tauri_error(name: &'static str, error: &tauri::Error) {
    let code = match error {
        tauri::Error::Runtime(error) => match error.to_string().as_str() {
            "failed to create window" => "window_create",
            "Could not find the webview runtime, make sure it is installed" => "webview_runtime_missing",
            text if text.starts_with("failed to create webview:") => "webview_create",
            "the event loop has been closed" => "event_loop_closed",
            _ => "runtime",
        },
        tauri::Error::Setup(_) => "setup",
        tauri::Error::PluginInitialization(_, _) => "plugin_initialization",
        tauri::Error::Io(_) => "io",
        tauri::Error::InvalidIcon(_) => "invalid_icon",
        tauri::Error::Menu(_) => "menu",
        tauri::Error::Tray(_) => "tray",
        _ => "tauri",
    };
    let backtrace = std::backtrace::Backtrace::force_capture().to_string();
    if let Some(logger) = LOGGER.get() {
        let _ = logger.write(name, Some(code), Some(&backtrace), false);
    }
}

fn prepare_directory(directory: &Path) -> io::Result<()> {
    crate::fsutil::check_write_io(directory)?;
    // Refuse a redirected diagnostic directory; diagnostics must never overwrite another file.
    if let Ok(meta) = fs::symlink_metadata(directory) {
        if meta.file_type().is_symlink() || !meta.is_dir() {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        #[cfg(windows)]
        {
            use std::os::windows::fs::MetadataExt;
            if meta.file_attributes() & 0x400 != 0 {
                return Err(io::ErrorKind::InvalidInput.into());
            }
        }
    }
    crate::fsutil::ensure_dir_secure(directory)
        .map_err(|_| io::Error::other("diagnostic directory unavailable"))
}

fn regular_file(path: &Path) -> io::Result<()> {
    crate::fsutil::check_write_io(path)?;
    match fs::symlink_metadata(path) {
        Ok(meta) if !meta.is_file() || meta.file_type().is_symlink() => {
            Err(io::ErrorKind::InvalidInput.into())
        }
        Ok(meta) if meta.len() > MAX_LOG_BYTES * 4 => Err(io::ErrorKind::InvalidData.into()),
        Ok(_) => Ok(()),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e),
    }
}

fn open_log(path: &Path) -> io::Result<File> {
    regular_file(path)?;
    let mut options = OpenOptions::new();
    options.create(true).append(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        options.custom_flags(0x00200000);
    } // FILE_FLAG_OPEN_REPARSE_POINT
    let file = options.open(path)?;
    let meta = file.metadata()?;
    if !meta.is_file() {
        return Err(io::ErrorKind::InvalidInput.into());
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        if meta.file_attributes() & 0x400 != 0 {
            return Err(io::ErrorKind::InvalidInput.into());
        }
    }
    Ok(file)
}

fn rotate(directory: &Path, base: &str, incoming: u64) -> io::Result<()> {
    let path = directory.join(base);
    regular_file(&path)?;
    if fs::metadata(&path).map_or(0, |m| m.len()) + incoming <= MAX_LOG_BYTES {
        return Ok(());
    }
    let one = directory.join(format!("{base}.1"));
    let two = directory.join(format!("{base}.2"));
    regular_file(&one)?;
    regular_file(&two)?;
    if two.exists() {
        fs::remove_file(&two)?;
    }
    if one.exists() {
        fs::rename(&one, &two)?;
    }
    if path.exists() {
        fs::rename(path, one)?;
    }
    Ok(())
}

impl Logger {
    fn write(
        &self,
        name: &str,
        code: Option<&str>,
        backtrace: Option<&str>,
        panic: bool,
    ) -> io::Result<()> {
        // Never wait for a poisoned/busy writer in the panic hook.
        let _guard = if panic {
            self.writer
                .try_lock()
                .map_err(|_| io::Error::other("log busy"))?
        } else {
            self.writer
                .lock()
                .map_err(|_| io::Error::other("log poisoned"))?
        };
        let event = Event {
            timestamp_ms: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis(),
            pid: std::process::id(),
            app_version: env!("CARGO_PKG_VERSION"),
            profile: match crate::app_profile::CURRENT {
                crate::app_profile::AppProfile::Production => "production",
                crate::app_profile::AppProfile::Development => "development",
            },
            platform: std::env::consts::OS,
            event: name,
            stage: Stage::name(STAGE.load(Ordering::Relaxed)),
            code,
            backtrace: backtrace.map(|text| {
                let mut end = text.len().min(MAX_EVENT_BYTES / 2);
                while !text.is_char_boundary(end) {
                    end -= 1;
                }
                &text[..end]
            }),
        };
        let mut bytes = serde_json::to_vec(&event)?;
        if bytes.len() > MAX_EVENT_BYTES {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        bytes.push(b'\n');
        prepare_directory(&self.directory)?;
        rotate(&self.directory, "app.log", bytes.len() as u64)?;
        let mut file = open_log(&self.directory.join("app.log"))?;
        file.write_all(&bytes)?;
        file.flush()
    }
}

#[cfg(test)]
#[path = "diagnostics_tests.rs"]
mod tests;
#[cfg(windows)]
#[path = "diagnostics_windows.rs"]
mod windows;

#[tauri::command]
pub(crate) fn app_open_diagnostics(app: tauri::AppHandle) -> Result<(), crate::error::AppError> {
    use tauri_plugin_opener::OpenerExt;
    let directory = directory()?;
    prepare_directory(&directory)?;
    app.opener()
        .open_path(directory.to_string_lossy(), None::<String>)
        .map_err(|_| {
            crate::error::AppError::Other("Could not open the diagnostic logs folder.".into())
        })
}

#[cfg(windows)]
pub(crate) fn show_startup_failure() {
    use windows_sys::Win32::UI::WindowsAndMessaging::{MessageBoxW, MB_ICONERROR, MB_OK};
    let message = format!("Lunport could not start its interface.\n\nPlease open %LOCALAPPDATA%\\{}\\diagnostics and include app.log when reporting this problem.\n\nThe logs do not include your hosts, passwords, keys or sync code.", crate::app_profile::CURRENT.identifier());
    let text: Vec<u16> = message.encode_utf16().chain(Some(0)).collect();
    let title: Vec<u16> = "Lunport startup error"
        .encode_utf16()
        .chain(Some(0))
        .collect();
    unsafe {
        MessageBoxW(
            std::ptr::null_mut(),
            text.as_ptr(),
            title.as_ptr(),
            MB_OK | MB_ICONERROR,
        );
    }
}
