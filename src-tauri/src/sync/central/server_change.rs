//! Selecting a server starts a separate, empty workspace after restart. No old account,
//! private material, cursor or migration source is relabelled for another service.
use super::{
    crypto,
    wire::{hex, origin},
};
use crate::{error::AppError, fsutil};
use serde::{Deserialize, Serialize};
use std::{
    fs,
    io::Read,
    path::{Path, PathBuf},
    sync::OnceLock,
};

const INDEX: &str = "central-server.json";
const PREFIX: &str = "server-workspace-";
const MAX_INDEX: u64 = 4096;
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Selection {
    version: u8,
    service: String,
    workspace: String,
}
#[derive(Clone)]
pub(crate) struct Active {
    pub path: PathBuf,
    service: Option<String>,
}
static ACTIVE: OnceLock<Active> = OnceLock::new();
fn invalid() -> AppError {
    AppError::Other("Cannot select the sync server. Check the server URL and local workspace; existing files are unchanged.".into())
}
fn read_selection(root: &Path) -> Result<Option<Selection>, AppError> {
    let path = root.join(INDEX);
    let metadata = match fs::symlink_metadata(&path) {
        Ok(value) => value,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e.into()),
    };
    if !metadata.is_file() || metadata.file_type().is_symlink() || metadata.len() > MAX_INDEX {
        return Err(invalid());
    }
    let mut options = fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    let file = options.open(&path)?;
    if !file.metadata()?.is_file() {
        return Err(invalid());
    }
    let mut bytes = Vec::new();
    file.take(MAX_INDEX + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_INDEX {
        return Err(invalid());
    }
    let selection: Selection = serde_json::from_slice(&bytes).map_err(|_| invalid())?;
    if selection.version != 1 || !origin(&selection.service) || !hex(&selection.workspace, 32) {
        return Err(invalid());
    }
    Ok(Some(selection))
}
fn directory(path: &Path, create: bool) -> Result<(), AppError> {
    fsutil::check_write(path)?;
    #[cfg(windows)]
    {
        let _ = crate::sync::central_files_windows::Directory::private(path, create)?;
    }
    #[cfg(not(windows))]
    {
        if create {
            let mut builder = fs::DirBuilder::new();
            #[cfg(unix)]
            {
                use std::os::unix::fs::DirBuilderExt;
                builder.mode(0o700);
            }
            match builder.create(path) {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(e) => return Err(e.into()),
            }
        }
        let metadata = fs::symlink_metadata(path)?;
        if !metadata.is_dir() || metadata.file_type().is_symlink() {
            return Err(invalid());
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            if metadata.uid() != unsafe { libc::geteuid() } || metadata.mode() & 0o077 != 0 {
                return Err(invalid());
            }
        }
    }
    Ok(())
}
fn load_at(root: &Path) -> Result<Active, AppError> {
    let Some(selection) = read_selection(root)? else {
        return Ok(Active {
            path: root.join("sync-state.json"),
            service: None,
        });
    };
    let folder = root.join(format!("{PREFIX}{}", selection.workspace));
    directory(&folder, false)?;
    Ok(Active {
        path: folder.join("sync-state.json"),
        service: Some(selection.service),
    })
}
pub(crate) fn load() -> Result<Active, AppError> {
    load_at(&fsutil::app_data_root()?)
}
pub(crate) fn bind(active: Active) {
    let _ = ACTIVE.set(active);
}
pub(crate) fn state_path() -> Result<PathBuf, AppError> {
    Ok(match ACTIVE.get() {
        Some(active) => active.clone(),
        None => load()?,
    }
    .path)
}
pub(crate) fn service() -> Option<String> {
    ACTIVE.get().and_then(|active| active.service.clone())
}
pub(crate) fn service_for(path: &Path) -> Option<String> {
    ACTIVE
        .get()
        .filter(|active| active.path == path)
        .and_then(|active| active.service.clone())
}
/// Only the new workspace's sources belong to its first upload. The real SSH config remains
/// available to the explicit SSH-config import; old managed key archives are not imported silently.
pub(crate) fn is_fresh_workspace(path: &Path) -> bool {
    path.parent()
        .and_then(Path::file_name)
        .and_then(|n| n.to_str())
        .and_then(|n| n.strip_prefix(PREFIX))
        .is_some_and(|id| hex(id, 32))
}
fn select_at(root: &Path, service: &str) -> Result<(), AppError> {
    if !origin(service) {
        return Err(invalid());
    }
    fsutil::ensure_dir_secure(root)?;
    let selection = Selection {
        version: 1,
        service: service.into(),
        workspace: crypto::random_id(16)?,
    };
    let folder = root.join(format!("{PREFIX}{}", selection.workspace));
    // Random exclusive workspace names prevent accidental reuse of a previous server's data.
    if folder.try_exists()? {
        return Err(invalid());
    }
    directory(&folder, true)?;
    let state_path = folder.join("sync-state.json");
    let crate::sync::record_runtime::StartupProbe::Records { state, fresh: true } =
        crate::sync::record_runtime::probe_startup(&state_path, "Lunport")
    else {
        return Err(invalid());
    };
    crate::sync::record_runtime::save_active(&state_path, &state)?;
    match crate::sync::record_runtime::probe_startup(&state_path, "Lunport") {
        crate::sync::record_runtime::StartupProbe::Records {
            state: readback,
            fresh: false,
        } if readback == state => {}
        _ => return Err(invalid()),
    }
    let bytes = serde_json::to_vec(&selection).map_err(|_| invalid())?;
    fsutil::atomic_write(&root.join(INDEX), &bytes, 0o600)?;
    #[cfg(unix)]
    fs::File::open(root)?.sync_all()?;
    let active = load_at(root)?;
    if active.path != state_path || active.service.as_deref() != Some(service) {
        return Err(invalid());
    }
    Ok(())
}
pub(crate) fn select(service: &str) -> Result<(), AppError> {
    select_at(&fsutil::app_data_root()?, service)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn an_unconfigured_workspace_has_no_distributor_server_or_sign_in_session() {
        use crate::sync::{
            fake_relay::FakeRelay,
            record_runtime,
            testkit::{TestClock, TestDevice},
        };
        let device = TestDevice::new("blank-service", &FakeRelay::new(), &TestClock::new());
        let env = device.env();
        let probe = record_runtime::probe_startup(&env.state_path, "test");
        record_runtime::activate_probe(&mut env.runtime.core.lock().unwrap(), probe).unwrap();
        let status = super::super::controller::status(&env).unwrap();
        assert!(status.service.is_none());
        assert!(!status.configured && !status.has_session && !status.can_sync);
        assert_eq!(status.phase, "signed_out");
    }
    #[test]
    fn a_server_change_starts_empty_and_does_not_relabel_or_import_old_files() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path();
        fs::write(root.join("sync-state.json"), b"old account").unwrap();
        fs::write(root.join("vault.json"), b"old protected material").unwrap();
        assert_eq!(load_at(root).unwrap().path, root.join("sync-state.json"));
        select_at(root, "https://new.example.com").unwrap();
        let first = load_at(root).unwrap();
        assert!(is_fresh_workspace(&first.path));
        assert_eq!(first.service.as_deref(), Some("https://new.example.com"));
        let crate::sync::record_runtime::StartupProbe::Records { state, .. } =
            crate::sync::record_runtime::probe_startup(&first.path, "test")
        else {
            panic!()
        };
        assert!(state.account.is_none() && state.spaces.is_empty());
        assert!(
            state.local.central.is_none()
                && state.local.keys.is_empty()
                && state.local.hosts.is_empty()
        );
        assert!(!crate::vault::store::vault_path(&first.path).exists());
        select_at(root, "https://other.example.com").unwrap();
        assert_ne!(load_at(root).unwrap().path, first.path);
        assert!(first.path.is_file());
        assert_eq!(
            fs::read(root.join("sync-state.json")).unwrap(),
            b"old account"
        );
        assert_eq!(
            fs::read(root.join("vault.json")).unwrap(),
            b"old protected material"
        );
    }
    #[test]
    fn bad_urls_corrupt_indices_and_path_escapes_fail_closed() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path();
        for service in [
            "https://example.com/path",
            "https://user@example.com",
            "http://example.com",
            "https://example.com/#x",
            "",
        ] {
            assert!(select_at(root, service).is_err());
            assert!(!root.join(INDEX).exists());
        }
        fs::write(
            root.join(INDEX),
            br#"{"version":1,"service":"https://example.com","workspace":"../outside"}"#,
        )
        .unwrap();
        assert!(load_at(root).is_err());
        fs::write(root.join(INDEX), b"broken").unwrap();
        assert!(load_at(root).is_err());
    }
    #[cfg(unix)]
    #[test]
    fn redirected_or_shared_workspace_is_rejected() {
        use std::os::unix::fs::{symlink, PermissionsExt};
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path();
        select_at(root, "https://example.com").unwrap();
        let active = load_at(root).unwrap();
        let folder = active.path.parent().unwrap();
        fs::set_permissions(folder, fs::Permissions::from_mode(0o755)).unwrap();
        assert!(load_at(root).is_err());
        fs::set_permissions(folder, fs::Permissions::from_mode(0o700)).unwrap();
        let moved = root.join("old-profile");
        fs::rename(folder, &moved).unwrap();
        symlink(&moved, folder).unwrap();
        assert!(load_at(root).is_err());
    }
}
