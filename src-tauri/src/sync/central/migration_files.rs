//! Read-only complete designated source trees. No private bytes or hashes are a frontend DTO.
use super::wire::invalid;
use crate::{error::AppError, sync::env::SyncEnv};
use std::{
    collections::{BTreeMap, BTreeSet},
    path::{Path, PathBuf},
};
use zeroize::Zeroizing;
const MAX_ENTRIES: usize = 8192;
const MAX_TOTAL_BYTES: u64 = 128 * 1024 * 1024;
const MAX_FILE_BYTES: u64 = 64 * 1024 * 1024 + 8192;
const MAX_DEPTH: usize = 8;
mod archive;
pub(super) use archive::MAX_ENCODED as MAX_ARCHIVE_BYTES;

pub(super) struct Files {
    // Relative category paths only; preserve raw bytes in native memory until explicit local encryption.
    pub bytes: BTreeMap<PathBuf, Zeroizing<Vec<u8>>>,
    pub directories: BTreeSet<PathBuf>,
    total: u64,
    entries: usize,
}
impl Files {
    pub fn capture(env: &SyncEnv, legacy_backup: Option<&str>) -> Result<Self, AppError> {
        Self::capture_checked(env, legacy_backup, BTreeMap::new())
    }
    pub fn capture_after_archive(
        env: &SyncEnv,
        backup: Option<&str>,
        outputs: &super::source_archive::Outputs,
    ) -> Result<Self, AppError> {
        let owned = outputs
            .files()
            .map(|(path, bytes)| (path.to_owned(), bytes))
            .collect();
        Self::capture_checked(env, backup, owned)
    }
    /// Only an empty native output root can differ after an interrupted first reservation.
    /// The caller must then match the entire encoded package to its protected source digest.
    pub fn without_empty_source_root(&mut self) -> Result<(), AppError> {
        let root = Path::new("data/central-source-archives");
        if self.bytes.keys().any(|p| p.starts_with(root))
            || self
                .directories
                .iter()
                .any(|p| p != root && p.starts_with(root))
            || !self.directories.remove(root)
        {
            return Err(invalid());
        }
        self.entries = self.entries.checked_sub(1).ok_or_else(invalid)?;
        Ok(())
    }
    fn capture_checked(
        env: &SyncEnv,
        legacy_backup: Option<&str>,
        owned: BTreeMap<PathBuf, &[u8]>,
    ) -> Result<Self, AppError> {
        Self::capture_at(&env.state_path, &env.ssh_dir, legacy_backup, owned)
    }
    fn capture_at(
        state_path: &Path,
        ssh_dir: &Path,
        legacy_backup: Option<&str>,
        mut owned: BTreeMap<PathBuf, &[u8]>,
    ) -> Result<Self, AppError> {
        let parent = state_path.parent().ok_or_else(invalid)?;
        let current = state_path
            .file_name()
            .and_then(|v| v.to_str())
            .ok_or_else(invalid)?;
        if legacy_backup.is_some_and(|name| !single_name(name)) {
            return Err(invalid());
        }
        let mut result = Self {
            bytes: BTreeMap::new(),
            directories: BTreeSet::new(),
            total: 0,
            entries: 0,
        };
        if let Some(root) = Directory::open(parent)? {
            result.count()?;
            result.directories.insert("data".into());
            for name in root.names()? {
                let source = Path::new("data").join(&name);
                if [
                    "imports",
                    "migrations",
                    "central-recovery-archives",
                    "central-source-archives",
                ]
                .contains(&name.as_str())
                {
                    result.walk(&root, &name, &source, 0, &mut owned)?;
                } else if name == current
                    || name.starts_with("sync-state")
                    || name.starts_with("vault")
                    || Some(name.as_str()) == legacy_backup
                {
                    result.file(&root, &name, &source, &mut owned)?;
                }
            }
            root.unchanged()?;
        }
        if let Some(backup) = legacy_backup {
            if !result.bytes.contains_key(&Path::new("data").join(backup)) {
                return Err(invalid());
            }
        }
        if let Some(ssh) = Directory::open(ssh_dir)? {
            // Only the caller's SSH base may resolve platform aliases. App-owned components
            // must be opened relative to that descriptor without following a redirected parent.
            if let Some(app) = ssh.optional_directory("sshelter")? {
                if let Some(root) = app.optional_directory("keys")? {
                    result.count()?;
                    result.directories.insert("keys".into());
                    for name in root.names()? {
                        result.walk(&root, &name, &Path::new("keys").join(&name), 0, &mut owned)?;
                    }
                    root.unchanged()?;
                }
                app.unchanged()?;
            }
            ssh.unchanged()?;
        }
        if !owned.is_empty() {
            return Err(crate::sync::runtime::superseded());
        }
        Ok(result)
    }
    fn count(&mut self) -> Result<(), AppError> {
        self.entries += 1;
        if self.entries > MAX_ENTRIES {
            return Err(invalid());
        }
        Ok(())
    }
    fn walk(
        &mut self,
        parent: &Directory,
        name: &str,
        path: &Path,
        depth: usize,
        owned: &mut BTreeMap<PathBuf, &[u8]>,
    ) -> Result<(), AppError> {
        if depth > MAX_DEPTH {
            return Err(invalid());
        }
        if let Some(dir) = parent.child(name)? {
            self.count()?;
            if !self.directories.insert(path.into()) {
                return Err(invalid());
            }
            for name in dir.names()? {
                self.walk(&dir, &name, &path.join(&name), depth + 1, owned)?;
            }
            dir.unchanged()?;
            Ok(())
        } else {
            self.file(parent, name, path, owned)
        }
    }
    fn file(
        &mut self,
        parent: &Directory,
        name: &str,
        path: &Path,
        owned: &mut BTreeMap<PathBuf, &[u8]>,
    ) -> Result<(), AppError> {
        if let Some(expected) = owned.remove(path) {
            let bytes = parent.read(name, expected.len() as u64)?;
            if bytes.as_slice() != expected {
                return Err(crate::sync::runtime::superseded());
            }
            return Ok(());
        }
        self.count()?;
        let limit = (MAX_TOTAL_BYTES - self.total).min(MAX_FILE_BYTES);
        let bytes = parent.read(name, limit)?;
        self.total += bytes.len() as u64;
        if self.bytes.insert(path.into(), bytes).is_some() {
            return Err(invalid());
        }
        Ok(())
    }
    pub fn require_unchanged(&self, env: &SyncEnv, backup: Option<&str>) -> Result<(), AppError> {
        let latest = Self::capture(env, backup)?;
        if self.bytes != latest.bytes
            || self.directories != latest.directories
            || self.entries != latest.entries
        {
            return Err(crate::sync::runtime::superseded());
        }
        Ok(())
    }
    /// The exception is constructed only by the exact reserved stage's full native readback.
    pub fn require_unchanged_after_initial(
        &self,
        env: &SyncEnv,
        backup: Option<&str>,
        outputs: &super::source_archive::Outputs,
        effects: &crate::sync::record_import::central_stage::InitialEffects,
    ) -> Result<(), AppError> {
        self.require_unchanged_after_initial_at(
            &env.state_path,
            &env.ssh_dir,
            backup,
            outputs,
            effects,
        )
    }
    /// Filesystem only; safe for the typed initial writer's final pre-rename check under Core.
    pub fn require_unchanged_after_initial_at(
        &self,
        state_path: &Path,
        ssh_dir: &Path,
        backup: Option<&str>,
        outputs: &super::source_archive::Outputs,
        effects: &crate::sync::record_import::central_stage::InitialEffects,
    ) -> Result<(), AppError> {
        let mut fresh = BTreeMap::new();
        for (path, bytes) in outputs.files() {
            match self.bytes.get(path) {
                Some(before) if before.as_slice() == bytes => {}
                Some(_) => return Err(invalid()),
                None => {
                    fresh.insert(path.to_owned(), bytes);
                }
            }
        }
        for (path, bytes) in effects.files() {
            if self.bytes.contains_key(path) || fresh.insert(path.to_owned(), bytes).is_some() {
                return Err(invalid());
            }
        }
        let replacement = effects.replacement();
        if let Some((path, before, after)) = replacement {
            if self.bytes.get(path).map(|b| b.as_slice()) != before
                || fresh.insert(path.to_owned(), after).is_some()
            {
                return Err(invalid());
            }
        }
        let latest = Self::capture_at(state_path, ssh_dir, backup, fresh)?;
        let replaced = replacement.map(|(path, _, _)| path);
        let expected =
            self.bytes.len() - usize::from(replaced.is_some_and(|p| self.bytes.contains_key(p)));
        if latest.bytes.len() != expected
            || self.bytes.iter().any(|(path, bytes)| {
                Some(path.as_path()) != replaced && latest.bytes.get(path) != Some(bytes)
            })
            || !self.directories.is_subset(&latest.directories)
            || latest
                .directories
                .difference(&self.directories)
                .any(|path| {
                    path != Path::new("data/central-source-archives")
                        && !effects.directories().contains(path)
                })
        {
            return Err(crate::sync::runtime::superseded());
        }
        Ok(())
    }
    pub fn require_unchanged_after_archive(
        &self,
        env: &SyncEnv,
        backup: Option<&str>,
        outputs: &super::source_archive::Outputs,
    ) -> Result<(), AppError> {
        let mut fresh = BTreeMap::new();
        for (path, bytes) in outputs.files() {
            match self.bytes.get(path) {
                Some(before) if before.as_slice() == bytes => {}
                Some(_) => return Err(crate::sync::runtime::superseded()),
                None => {
                    fresh.insert(path.to_owned(), bytes);
                }
            }
        }
        // Only authenticated newly owned output bytes use their exact readback size. All original
        // and unrelated files still pass the ordinary source limits and are compared below.
        let latest = Self::capture_checked(env, backup, fresh)?;
        let root = Path::new("data/central-source-archives");
        if latest.bytes.len() != self.bytes.len()
            || self
                .bytes
                .iter()
                .any(|(path, bytes)| latest.bytes.get(path) != Some(bytes))
            || !self.directories.is_subset(&latest.directories)
            || latest
                .directories
                .difference(&self.directories)
                .any(|path| path != root)
        {
            return Err(crate::sync::runtime::superseded());
        }
        Ok(())
    }
}
fn single_name(name: &str) -> bool {
    !name.is_empty()
        && name != "."
        && name != ".."
        && name.len() <= 255
        && !name.contains(['/', '\\', '\0'])
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
use platform::Directory;
#[cfg(any(target_os = "macos", target_os = "linux"))]
mod platform {
    use super::*;
    use std::{
        ffi::{CStr, CString},
        fs::{File, Metadata, OpenOptions},
        io::Read,
        os::{
            fd::{AsRawFd, FromRawFd},
            unix::{
                ffi::OsStrExt,
                fs::{MetadataExt, OpenOptionsExt},
            },
        },
    };
    pub(super) struct Directory {
        file: File,
        path: PathBuf,
        observed: Metadata,
    }
    fn name(value: &str) -> Result<CString, AppError> {
        if !single_name(value) {
            return Err(invalid());
        }
        CString::new(value).map_err(|_| invalid())
    }
    fn owned(metadata: &Metadata) -> bool {
        metadata.uid() == unsafe { libc::geteuid() } && metadata.mode() & 0o022 == 0
    }
    fn same(a: &Metadata, b: &Metadata) -> bool {
        a.dev() == b.dev()
            && a.ino() == b.ino()
            && a.len() == b.len()
            && a.mtime() == b.mtime()
            && a.mtime_nsec() == b.mtime_nsec()
            && a.ctime() == b.ctime()
            && a.ctime_nsec() == b.ctime_nsec()
    }
    #[cfg(target_os = "macos")]
    unsafe fn errno() -> *mut libc::c_int {
        unsafe { libc::__error() }
    }
    #[cfg(target_os = "linux")]
    unsafe fn errno() -> *mut libc::c_int {
        unsafe { libc::__errno_location() }
    }
    struct Stream(*mut libc::DIR);
    impl Drop for Stream {
        fn drop(&mut self) {
            unsafe {
                libc::closedir(self.0);
            }
        }
    }
    impl Directory {
        pub fn open(path: &Path) -> Result<Option<Self>, AppError> {
            let canonical = match std::fs::canonicalize(path) {
                Ok(v) => v,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                    let mut ancestor = Some(path);
                    while let Some(candidate) = ancestor {
                        match std::fs::symlink_metadata(candidate) {
                            Ok(metadata)
                                if metadata.is_dir() && !metadata.file_type().is_symlink() =>
                            {
                                return Ok(None)
                            }
                            Ok(_) => return Err(invalid()),
                            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                                ancestor = candidate.parent();
                            }
                            Err(_) => return Err(invalid()),
                        }
                    }
                    return Err(invalid());
                }
                Err(_) => return Err(invalid()),
            };
            let mut file = OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
                .open("/")?;
            for component in canonical.components() {
                if let std::path::Component::Normal(value) = component {
                    let value = CString::new(value.as_bytes()).map_err(|_| invalid())?;
                    let fd = unsafe {
                        libc::openat(
                            file.as_raw_fd(),
                            value.as_ptr(),
                            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                        )
                    };
                    if fd < 0 {
                        return Err(invalid());
                    }
                    file = unsafe { File::from_raw_fd(fd) };
                } else if component != std::path::Component::RootDir {
                    return Err(invalid());
                }
            }
            if !owned(&file.metadata()?) {
                return Err(invalid());
            }
            let observed = file.metadata()?;
            let result = Self {
                file,
                path: path.into(),
                observed,
            };
            result.unchanged()?;
            Ok(Some(result))
        }
        pub fn names(&self) -> Result<Vec<String>, AppError> {
            let fd = unsafe { libc::dup(self.file.as_raw_fd()) };
            if fd < 0 {
                return Err(invalid());
            }
            let stream = unsafe { libc::fdopendir(fd) };
            if stream.is_null() {
                unsafe {
                    libc::close(fd);
                }
                return Err(invalid());
            }
            let stream = Stream(stream);
            let mut names = std::collections::BTreeSet::new();
            loop {
                unsafe {
                    *errno() = 0;
                }
                let entry = unsafe { libc::readdir(stream.0) };
                if entry.is_null() {
                    if unsafe { *errno() } != 0 {
                        return Err(invalid());
                    }
                    break;
                }
                let value = unsafe { CStr::from_ptr((*entry).d_name.as_ptr()) }
                    .to_str()
                    .map_err(|_| invalid())?;
                if value == "." || value == ".." {
                    continue;
                }
                if !single_name(value)
                    || names.len() >= MAX_ENTRIES
                    || !names.insert(value.to_owned())
                {
                    return Err(invalid());
                }
            }
            Ok(names.into_iter().collect())
        }
        pub fn optional_directory(&self, value: &str) -> Result<Option<Self>, AppError> {
            let name = name(value)?;
            let fd = unsafe {
                libc::openat(
                    self.file.as_raw_fd(),
                    name.as_ptr(),
                    libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                )
            };
            if fd < 0 {
                return if std::io::Error::last_os_error().kind() == std::io::ErrorKind::NotFound {
                    Ok(None)
                } else {
                    Err(invalid())
                };
            }
            let file = unsafe { File::from_raw_fd(fd) };
            let metadata = file.metadata()?;
            if !metadata.is_dir() || !owned(&metadata) {
                return Err(invalid());
            }
            let child = Self {
                file,
                path: self.path.join(value),
                observed: metadata,
            };
            child.unchanged()?;
            Ok(Some(child))
        }
        pub fn child(&self, value: &str) -> Result<Option<Self>, AppError> {
            let name = name(value)?;
            let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
            if unsafe {
                libc::fstatat(
                    self.file.as_raw_fd(),
                    name.as_ptr(),
                    stat.as_mut_ptr(),
                    libc::AT_SYMLINK_NOFOLLOW,
                )
            } < 0
            {
                return Err(invalid());
            }
            let stat = unsafe { stat.assume_init() };
            if stat.st_mode & libc::S_IFMT == libc::S_IFREG {
                return Ok(None);
            }
            if stat.st_mode & libc::S_IFMT != libc::S_IFDIR {
                return Err(invalid());
            }
            let fd = unsafe {
                libc::openat(
                    self.file.as_raw_fd(),
                    name.as_ptr(),
                    libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                )
            };
            if fd < 0 {
                return Err(invalid());
            }
            let file = unsafe { File::from_raw_fd(fd) };
            let metadata = file.metadata()?;
            if !metadata.is_dir() || !owned(&metadata) {
                return Err(invalid());
            }
            let child = Self {
                file,
                path: self.path.join(value),
                observed: metadata,
            };
            child.unchanged()?;
            Ok(Some(child))
        }
        pub fn read(&self, value: &str, limit: u64) -> Result<Zeroizing<Vec<u8>>, AppError> {
            let name = name(value)?;
            let fd = unsafe {
                libc::openat(
                    self.file.as_raw_fd(),
                    name.as_ptr(),
                    libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC,
                )
            };
            if fd < 0 {
                return Err(invalid());
            }
            let file = unsafe { File::from_raw_fd(fd) };
            let before = file.metadata()?;
            if !before.is_file() || !owned(&before) || before.len() > limit {
                return Err(invalid());
            }
            let mut bytes = Zeroizing::new(vec![]);
            let mut capped = (&file).take(limit + 1);
            capped.read_to_end(&mut bytes).map_err(|_| invalid())?;
            if bytes.len() as u64 > limit || !same(&before, &file.metadata()?) {
                return Err(invalid());
            }
            let current =
                std::fs::symlink_metadata(self.path.join(value)).map_err(|_| invalid())?;
            if current.file_type().is_symlink() || !same(&before, &current) {
                return Err(invalid());
            }
            Ok(bytes)
        }
        pub fn unchanged(&self) -> Result<(), AppError> {
            let latest = std::fs::symlink_metadata(&self.path).map_err(|_| invalid())?;
            let anchored = self.file.metadata()?;
            if !latest.is_dir()
                || latest.file_type().is_symlink()
                || !owned(&latest)
                || latest.dev() != anchored.dev()
                || latest.ino() != anchored.ino()
                || !same(&self.observed, &anchored)
            {
                return Err(invalid());
            }
            Ok(())
        }
    }
}
#[cfg(windows)]
use windows::Directory;
#[cfg(windows)]
mod windows {
    use super::*;
    pub(super) struct Directory(crate::sync::central_files_windows::Directory);
    impl Directory {
    pub fn open(path: &Path) -> Result<Option<Self>, AppError> {
        Ok(crate::sync::central_files_windows::Directory::open(path)?.map(Self))
    }
    pub fn names(&self) -> Result<Vec<String>, AppError> {
        self.0.names()
    }
    pub fn optional_directory(&self, name: &str) -> Result<Option<Self>, AppError> {
        Ok(self.0.optional_directory(name)?.map(Self))
    }
    pub fn child(&self, name: &str) -> Result<Option<Self>, AppError> {
        Ok(self.0.child(name)?.map(Self))
    }
    pub fn read(&self, name: &str, limit: u64) -> Result<Zeroizing<Vec<u8>>, AppError> {
        Ok(Zeroizing::new(self.0.read(name, limit)?))
    }
    pub fn unchanged(&self) -> Result<(), AppError> {
        self.0.unchanged()
    }
    }
}
#[cfg(not(any(target_os = "macos", target_os = "linux", windows)))]
struct Directory;
#[cfg(not(any(target_os = "macos", target_os = "linux", windows)))]
impl Directory {
    fn open(_: &Path) -> Result<Option<Self>, AppError> {
        Err(invalid())
    }
    fn names(&self) -> Result<Vec<String>, AppError> {
        Err(invalid())
    }
    fn optional_directory(&self, _: &str) -> Result<Option<Self>, AppError> {
        Err(invalid())
    }
    fn child(&self, _: &str) -> Result<Option<Self>, AppError> {
        Err(invalid())
    }
    fn read(&self, _: &str, _: u64) -> Result<Zeroizing<Vec<u8>>, AppError> {
        Err(invalid())
    }
    fn unchanged(&self) -> Result<(), AppError> {
        Err(invalid())
    }
}

#[cfg(all(test, any(target_os = "macos", target_os = "linux", windows)))]
mod tests {
    use super::*;
    use crate::sync::{
        fake_relay::FakeRelay,
        testkit::{TestClock, TestDevice},
    };
    use std::fs;
    fn device() -> TestDevice {
        TestDevice::new("source-files", &FakeRelay::new(), &TestClock::new())
    }
    fn write(path: &Path, value: &[u8]) {
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, value).unwrap();
    }
    #[test]
    fn captures_every_designated_source_and_unknown_entry_without_reading_unmanaged_ssh_files() {
        let device = device();
        let env = device.env();
        let root = env.state_path.parent().unwrap();
        let files = [
            ("sync-state.json", b"state".as_slice()),
            ("sync-state.unreadable-1.json", b"retained"),
            ("vault.json", b"protected"),
            ("vault.keyless-1.json", b"unreadable retained"),
            (
                "imports/not-a-valid-operation/unknown-file",
                b"never filtered",
            ),
            ("migrations/old/journal.json", b"recovery"),
            (
                "central-recovery-archives/source.lparch",
                b"encrypted archive",
            ),
            (
                "central-source-archives/old.lpsource",
                b"retained source archive",
            ),
            ("legacy-backup", b"legacy"),
        ];
        for (path, value) in files {
            write(&root.join(path), value);
        }
        fs::create_dir_all(root.join("imports/empty-unknown")).unwrap();
        write(&root.join("unrelated-settings.json"), b"unrelated");
        write(
            &env.ssh_dir.join("id_unmanaged"),
            b"unrelated private key must never be read",
        );
        let keys = env.ssh_dir.join("sshelter/keys");
        write(&keys.join("orphan-key"), b"original private bytes");
        write(&keys.join("orphan-key.pub"), b"public bytes");
        write(
            &keys.join("orphan-key.previous-1"),
            b"retired private bytes",
        );
        let captured = Files::capture(&env, Some("legacy-backup")).unwrap();
        assert_eq!(captured.bytes.len(), 12);
        for (path, value) in files {
            assert_eq!(
                captured.bytes[&Path::new("data").join(path)].as_slice(),
                value
            );
        }
        assert!(captured
            .directories
            .contains(Path::new("data/imports/empty-unknown")));
        assert!(captured
            .bytes
            .keys()
            .all(|path| !path.to_string_lossy().contains("id_unmanaged")
                && !path.to_string_lossy().contains("unrelated-settings")));
        captured
            .require_unchanged(&env, Some("legacy-backup"))
            .unwrap();
        assert_eq!(
            fs::read(keys.join("orphan-key")).unwrap(),
            b"original private bytes"
        );
        assert!(!root.join("central-migration-archives").exists());
    }
    #[test]
    fn revalidation_rejects_modified_deleted_or_added_sources_and_changed_empty_directories() {
        let device = device();
        let env = device.env();
        let root = env.state_path.parent().unwrap();
        write(&env.state_path, b"A");
        let captured = Files::capture(&env, None).unwrap();
        write(&env.state_path, b"B");
        assert!(captured.require_unchanged(&env, None).is_err());
        write(&env.state_path, b"A");
        captured.require_unchanged(&env, None).unwrap();
        write(&root.join("imports/new-source/saved"), b"new");
        assert!(captured.require_unchanged(&env, None).is_err());
        let captured = Files::capture(&env, None).unwrap();
        fs::remove_file(root.join("imports/new-source/saved")).unwrap();
        assert!(captured.require_unchanged(&env, None).is_err());
        fs::create_dir_all(root.join("imports/empty-A")).unwrap();
        let captured = Files::capture(&env, None).unwrap();
        fs::rename(root.join("imports/empty-A"), root.join("imports/empty-B")).unwrap();
        assert!(captured.require_unchanged(&env, None).is_err());
    }
    #[cfg(unix)]
    #[test]
    fn source_symlinks_special_files_and_open_directory_replacement_fail_closed() {
        use std::os::unix::fs::symlink;
        for location in ["imports/redirect", "imports/redirect-file", "vault.json"] {
            let device = device();
            let env = device.env();
            let root = env.state_path.parent().unwrap();
            let outside = tempfile::tempdir().unwrap();
            write(&outside.path().join("key"), b"outside source");
            fs::create_dir_all(root.join("imports")).unwrap();
            symlink(
                if location == "imports/redirect" {
                    outside.path().to_path_buf()
                } else {
                    outside.path().join("key")
                },
                root.join(location),
            )
            .unwrap();
            assert!(Files::capture(&env, None).is_err());
            assert_eq!(
                fs::read(outside.path().join("key")).unwrap(),
                b"outside source"
            );
        }
        let device = device();
        let env = device.env();
        let keys = env.ssh_dir.join("sshelter/keys");
        fs::create_dir_all(&keys).unwrap();
        let fifo = std::ffi::CString::new(keys.join("fifo").to_str().unwrap()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(fifo.as_ptr(), 0o600) }, 0);
        assert!(Files::capture(&env, None).is_err());
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("source");
        write(&path.join("file"), b"original");
        let opened = Directory::open(&path).unwrap().unwrap();
        fs::rename(&path, root.path().join("moved")).unwrap();
        write(&path.join("file"), b"replacement");
        assert!(opened.unchanged().is_err());
        assert!(opened.read("file", 1024).is_err());
    }
    #[cfg(unix)]
    #[test]
    fn linked_managed_parent_and_dangling_source_roots_cannot_redirect_or_hide_sources() {
        use std::os::unix::fs::symlink;
        for dangling in [false, true] {
            let device = device();
            let env = device.env();
            let outside = tempfile::tempdir().unwrap();
            write(
                &outside.path().join("keys/unmanaged"),
                b"outside SSH private bytes",
            );
            symlink(
                if dangling {
                    outside.path().join("missing")
                } else {
                    outside.path().to_path_buf()
                },
                env.ssh_dir.join("sshelter"),
            )
            .unwrap();
            assert!(Files::capture(&env, None).is_err());
        }
        let device = device();
        let env = device.env();
        let root = env.state_path.parent().unwrap();
        if root.exists() {
            fs::remove_dir_all(root).unwrap();
        }
        symlink(root.with_file_name("missing-data"), root).unwrap();
        assert!(Files::capture(&env, None).is_err());
    }
    #[cfg(unix)]
    #[test]
    fn missing_referenced_backup_invalid_names_and_redirected_key_roots_cannot_be_skipped() {
        use std::os::unix::fs::symlink;
        let device = device();
        let env = device.env();
        for backup in [
            "../outside",
            "/outside",
            "a/b",
            "a\\b",
            ".",
            "..",
            "missing-backup",
        ] {
            assert!(Files::capture(&env, Some(backup)).is_err());
        }
        let outside = tempfile::tempdir().unwrap();
        fs::create_dir_all(env.ssh_dir.join("sshelter")).unwrap();
        symlink(outside.path(), env.ssh_dir.join("sshelter/keys")).unwrap();
        assert!(Files::capture(&env, None).is_err());
        assert_eq!(fs::read_dir(outside.path()).unwrap().count(), 0);
    }
    #[cfg(unix)]
    #[test]
    fn file_aggregate_depth_and_directory_name_changes_stop_before_a_partial_snapshot_is_accepted()
    {
        use std::os::unix::fs::PermissionsExt;
        let device = device();
        let env = device.env();
        let root = env.state_path.parent().unwrap();
        write(&root.join("vault.oversize.json"), b"");
        fs::OpenOptions::new()
            .write(true)
            .open(root.join("vault.oversize.json"))
            .unwrap()
            .set_len(MAX_FILE_BYTES + 1)
            .unwrap();
        assert!(Files::capture(&env, None).is_err());
        fs::remove_file(root.join("vault.oversize.json")).unwrap();
        let mut nested = root.join("imports");
        for _ in 0..=MAX_DEPTH {
            nested = nested.join("level");
        }
        write(&nested.join("source"), b"never silently omitted");
        assert!(Files::capture(&env, None).is_err());
        fs::remove_dir_all(root.join("imports")).unwrap();
        write(&root.join("vault.json"), b"abc");
        let opened = Directory::open(root).unwrap().unwrap();
        let mut constrained = Files {
            bytes: BTreeMap::new(),
            directories: BTreeSet::new(),
            total: MAX_TOTAL_BYTES - 2,
            entries: 0,
        };
        assert!(constrained
            .file(
                &opened,
                "vault.json",
                Path::new("data/vault.json"),
                &mut BTreeMap::new()
            )
            .is_err());
        assert!(constrained.bytes.is_empty());
        write(&root.join("sync-state-new.json"), b"new");
        assert!(opened.unchanged().is_err());
        fs::set_permissions(root.join("vault.json"), fs::Permissions::from_mode(0o666)).unwrap();
        assert!(Files::capture(&env, None).is_err());
    }
}
