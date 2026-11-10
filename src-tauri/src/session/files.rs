//! Human file browsing and single-file SCP transfers on saved SSH routes.
use std::collections::HashMap;
use std::fs::File;
use std::io::{Read, Write};
use std::path::Path;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc, Mutex,
};
use std::time::{Duration, Instant};

use serde::Serialize;
use tauri::{AppHandle, Emitter, Manager, WebviewWindow};

use super::connect::CancelToken;
use super::protocol::HostQuery;
use crate::error::AppError;
use crate::ssh::RemoteListing;
use crate::state::AppState;

const LIST_TIMEOUT: Duration = Duration::from_secs(30);
const TRANSFER_TIMEOUT: Duration = Duration::from_secs(3600);

#[derive(Default)]
pub struct Transfers {
    active: Arc<Mutex<HashMap<String, CancelToken>>>,
}

struct ActiveTransfer {
    active: Arc<Mutex<HashMap<String, CancelToken>>>,
    id: String,
}

impl Drop for ActiveTransfer {
    fn drop(&mut self) {
        self.active.lock().unwrap().remove(&self.id);
    }
}

impl Transfers {
    fn begin(&self, id: String) -> Result<(CancelToken, ActiveTransfer), String> {
        if id.is_empty()
            || id.len() > 128
            || !id
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        {
            return Err("Invalid transfer ID.".into());
        }
        let mut active = self.active.lock().unwrap();
        if active.contains_key(&id) {
            return Err("This transfer is already running.".into());
        }
        let cancel = CancelToken::default();
        active.insert(id.clone(), cancel.clone());
        Ok((
            cancel,
            ActiveTransfer {
                active: self.active.clone(),
                id,
            },
        ))
    }

    fn cancel(&self, id: &str) {
        if let Some(cancel) = self.active.lock().unwrap().get(id) {
            cancel.cancel();
        }
    }
}

fn safe_path(path: &str) -> bool {
    !path.is_empty()
        && path.len() <= 4096
        && !path
            .chars()
            .any(|c| c.is_control() || super::auth::is_deceptive_format(c))
}

fn remote_child(parent: &str, name: &str) -> Result<String, String> {
    if !safe_path(parent)
        || name.is_empty()
        || name == "."
        || name == ".."
        || name.len() > 255
        || name.contains('/')
        || name.contains('\\')
        || !safe_path(name)
    {
        return Err("Invalid remote file path.".into());
    }
    let path = format!("{}/{}", parent.trim_end_matches('/'), name);
    if path.len() > 4096 {
        return Err("Remote file path is too long.".into());
    }
    Ok(path)
}

fn split_remote_file(path: &str) -> Result<(&str, &str), String> {
    let (parent, name) = path.rsplit_once('/').ok_or("Invalid remote file path.")?;
    let parent = if parent.is_empty() { "/" } else { parent };
    remote_child(parent, name)?;
    Ok((parent, name))
}

fn local_file(path: &str) -> Result<&Path, String> {
    if !safe_path(path) || !Path::new(path).is_absolute() {
        return Err("Choose an absolute local file path.".into());
    }
    Ok(Path::new(path))
}

fn persist_download(staged: tempfile::NamedTempFile, target: &Path) -> Result<(), String> {
    staged
        .as_file()
        .sync_all()
        .map_err(|_| "Downloaded file could not be saved locally".to_string())?;
    staged
        .persist_noclobber(target)
        .map_err(|_| "Local destination already exists or cannot be saved".to_string())?;
    Ok(())
}

fn owner(app: &AppHandle, cancel: &CancelToken, id: &str) -> super::auth_window::NativeOwner {
    let state = app.state::<AppState>();
    super::auth_window::NativeOwner {
        ai: None,
        hub: state.session.auth_questions.clone(),
        surface: Arc::new(super::auth_window::TauriAuthSurface { app: app.clone() }),
        request_id: format!("files-{id}"),
        cancel: cancel.clone(),
    }
}

fn main_only(window: &WebviewWindow) -> Result<(), AppError> {
    if window.label() == "main" {
        Ok(())
    } else {
        Err(AppError::Other(
            "Files are available in the main window only.".into(),
        ))
    }
}

#[tauri::command]
pub async fn records_files_list(
    window: WebviewWindow,
    app: AppHandle,
    host_id: String,
    path: String,
) -> Result<RemoteListing, AppError> {
    main_only(&window)?;
    if !safe_path(&path) {
        return Err(AppError::Other("Invalid remote folder path.".into()));
    }
    tauri::async_runtime::spawn_blocking(move || -> Result<RemoteListing, AppError> {
        super::deploy::records_current(&app).map_err(AppError::Other)?;
        let broker = super::deploy::broker(&app).map_err(AppError::Other)?;
        let cancel = CancelToken::default();
        let _registered = broker
            .register_deployment(cancel.clone())
            .map_err(AppError::Other)?;
        let connected = broker
            .connector()
            .connect(
                &HostQuery::Id(host_id),
                &owner(&app, &cancel, "list"),
                &cancel,
            )
            .map_err(|error| AppError::Other(error.text))?;
        let result = connected
            .session
            .sftp_list(&path, LIST_TIMEOUT)
            .map_err(|error| AppError::Other(error.to_string()));
        connected.session.close();
        result
    })
    .await
    .map_err(crate::sync::engine::join_error)?
}

#[derive(Clone, Serialize)]
struct ProgressEvent {
    id: String,
    bytes: u64,
    total: Option<u64>,
}

struct Progress {
    window: WebviewWindow,
    id: String,
    cancel: CancelToken,
    bytes: u64,
    total: Option<u64>,
    last_emit: Instant,
}

impl Progress {
    fn new(window: WebviewWindow, id: String, cancel: CancelToken, total: Option<u64>) -> Self {
        let progress = Self {
            window,
            id,
            cancel,
            bytes: 0,
            total,
            last_emit: Instant::now(),
        };
        progress.emit();
        progress
    }
    fn emit(&self) {
        let _ = self.window.emit(
            "files://progress",
            ProgressEvent {
                id: self.id.clone(),
                bytes: self.bytes,
                total: self.total,
            },
        );
    }
    fn advanced(&mut self, count: usize) {
        self.bytes += count as u64;
        if self.last_emit.elapsed() >= Duration::from_millis(100) || self.total == Some(self.bytes)
        {
            self.emit();
            self.last_emit = Instant::now();
        }
    }
    fn check(&self) -> std::io::Result<()> {
        if self.cancel.is_cancelled() {
            Err(std::io::ErrorKind::Interrupted.into())
        } else {
            Ok(())
        }
    }
}

struct ProgressReader<R> {
    inner: R,
    progress: Progress,
}
impl<R: Read> Read for ProgressReader<R> {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        self.progress.check()?;
        let count = self.inner.read(buffer)?;
        self.progress.advanced(count);
        Ok(count)
    }
}

struct ProgressWriter<W> {
    inner: W,
    progress: Progress,
}
impl<W: Write> Write for ProgressWriter<W> {
    fn write(&mut self, buffer: &[u8]) -> std::io::Result<usize> {
        self.progress.check()?;
        let count = self.inner.write(buffer)?;
        self.progress.advanced(count);
        Ok(count)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
}

#[tauri::command]
#[allow(clippy::too_many_arguments)]
pub async fn records_files_transfer(
    window: WebviewWindow,
    app: AppHandle,
    id: String,
    host_id: String,
    direction: String,
    local_path: String,
    remote_path: String,
    overwrite: bool,
) -> Result<u64, AppError> {
    main_only(&window)?;
    let local = local_file(&local_path)
        .map_err(AppError::Other)?
        .to_path_buf();
    let (remote_dir, remote_name) = split_remote_file(&remote_path).map_err(AppError::Other)?;
    let remote_dir = remote_dir.to_string();
    let remote_name = remote_name.to_string();
    if direction != "upload" && direction != "download" {
        return Err(AppError::Other("Invalid transfer direction.".into()));
    }
    let (cancel, _active) = app
        .state::<AppState>()
        .session
        .files
        .begin(id.clone())
        .map_err(AppError::Other)?;
    tauri::async_runtime::spawn_blocking(move || -> Result<u64, AppError> {
        super::deploy::records_current(&app).map_err(AppError::Other)?;
        let state = app.state::<AppState>();
        let broker = super::deploy::broker(&app).map_err(AppError::Other)?;
        let _registered = broker
            .register_deployment(cancel.clone())
            .map_err(AppError::Other)?;
        let limit_mib = state.mcp.file_transfer_limit_mib();
        let limit = u64::from(limit_mib) * 1024 * 1024;
        let mut source = if direction == "upload" {
            let file = File::open(&local)
                .map_err(|_| AppError::Other("Local upload file cannot be opened.".into()))?;
            let metadata = file
                .metadata()
                .map_err(|_| AppError::Other("Local upload file cannot be inspected.".into()))?;
            if !metadata.is_file() || metadata.len() > limit {
                return Err(AppError::Other(format!(
                    "Choose a regular file no larger than {limit_mib} MiB."
                )));
            }
            Some((file, metadata.len()))
        } else {
            if local.exists() || !local.parent().is_some_and(Path::is_dir) {
                return Err(AppError::Other(
                    "Choose an unused local file name in an existing folder.".into(),
                ));
            }
            None
        };
        let connected = broker
            .connector()
            .connect(&HostQuery::Id(host_id), &owner(&app, &cancel, &id), &cancel)
            .map_err(|error| AppError::Other(error.text))?;
        let result = (|| -> Result<u64, String> {
            if cancel.is_cancelled() {
                return Err("Transfer canceled.".into());
            }
            let listing = connected
                .session
                .sftp_list(&remote_dir, LIST_TIMEOUT)
                .map_err(|error| error.to_string())?;
            let existing = listing
                .entries
                .iter()
                .find(|entry| entry.name == remote_name);
            if direction == "upload" {
                match existing {
                    Some(entry) if entry.kind != "file" => {
                        return Err("The remote destination is not a regular file.".into())
                    }
                    Some(_) if !overwrite => return Err(
                        "A remote file with this name already exists. Confirm replacement first."
                            .into(),
                    ),
                    _ => {}
                }
            } else {
                match existing {
                    Some(entry) if entry.kind == "file" && entry.size <= limit => {}
                    Some(entry) if entry.kind == "file" => {
                        return Err(format!("Remote file exceeds {limit_mib} MiB."))
                    }
                    _ => return Err("The remote file is no longer available.".into()),
                }
            }
            let done = AtomicBool::new(false);
            let transferred = std::thread::scope(|scope| {
                scope.spawn(|| {
                    while !done.load(Ordering::SeqCst) {
                        if cancel.is_cancelled() {
                            connected.session.close();
                            break;
                        }
                        std::thread::sleep(Duration::from_millis(25));
                    }
                });
                let result = (|| -> Result<u64, String> {
                    if let Some((source, size)) = source.as_mut() {
                        let name = local
                            .file_name()
                            .and_then(|value| value.to_str())
                            .ok_or("Local file has no usable name")?;
                        let mut reader = ProgressReader {
                            inner: source,
                            progress: Progress::new(
                                window.clone(),
                                id.clone(),
                                cancel.clone(),
                                Some(*size),
                            ),
                        };
                        let bytes = connected
                            .session
                            .scp_upload(&remote_path, name, *size, &mut reader, TRANSFER_TIMEOUT)
                            .map_err(|error| error.to_string())?;
                        reader.progress.emit();
                        Ok(bytes)
                    } else {
                        let mut staged = tempfile::NamedTempFile::new_in(
                            local
                                .parent()
                                .ok_or("Local download needs a parent folder")?,
                        )
                        .map_err(|_| "Local download could not be staged".to_string())?;
                        let mut writer = ProgressWriter {
                            inner: staged.as_file_mut(),
                            progress: Progress::new(
                                window.clone(),
                                id.clone(),
                                cancel.clone(),
                                existing.map(|entry| entry.size),
                            ),
                        };
                        let bytes = connected
                            .session
                            .scp_download(&remote_path, &mut writer, limit, TRANSFER_TIMEOUT)
                            .map_err(|error| error.to_string())?;
                        writer.progress.emit();
                        drop(writer);
                        if cancel.is_cancelled() {
                            return Err("Transfer canceled.".into());
                        }
                        persist_download(staged, &local)?;
                        Ok(bytes)
                    }
                })();
                done.store(true, Ordering::SeqCst);
                result
            });
            if cancel.is_cancelled() {
                return Err("Transfer canceled.".into());
            }
            transferred
        })();
        connected.session.close();
        result.map_err(AppError::Other)
    })
    .await
    .map_err(crate::sync::engine::join_error)?
}

#[tauri::command]
pub fn records_files_cancel(
    window: WebviewWindow,
    app: AppHandle,
    id: String,
) -> Result<(), AppError> {
    main_only(&window)?;
    app.state::<AppState>().session.files.cancel(&id);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn remote_child_rejects_untrusted_names() {
        assert_eq!(
            remote_child("/srv/files", "report.txt").unwrap(),
            "/srv/files/report.txt"
        );
        assert!(remote_child("/srv/files", "../escape").is_err());
        assert!(remote_child("/srv/files", "bad\nname").is_err());
    }

    #[test]
    fn download_never_replaces_an_existing_file() {
        let directory = tempfile::tempdir().unwrap();
        let target = directory.path().join("report.txt");
        std::fs::write(&target, b"original").unwrap();
        let mut staged = tempfile::NamedTempFile::new_in(directory.path()).unwrap();
        std::io::Write::write_all(&mut staged, b"downloaded").unwrap();
        assert!(persist_download(staged, &target).is_err());
        assert_eq!(std::fs::read(target).unwrap(), b"original");
    }

    #[test]
    fn cancel_marks_the_running_transfer() {
        let transfers = Transfers::default();
        let (token, _active) = transfers.begin("transfer-1".into()).unwrap();
        transfers.cancel("transfer-1");
        assert!(token.is_cancelled());
    }
}
