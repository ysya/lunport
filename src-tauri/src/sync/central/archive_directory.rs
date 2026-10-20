//! Closed private immutable archive roots. Source inventory and crypto authority remain in callers.
use super::{crypto, wire::invalid};
use crate::{
    error::AppError,
    sync::{env::SyncEnv, record_runtime},
};
#[derive(Clone, Copy)]
pub(super) enum Kind {
    Replacement,
    Source,
}
impl Kind {
    fn name(self) -> &'static str {
        match self {
            Self::Replacement => "central-recovery-archives",
            Self::Source => "central-source-archives",
        }
    }
    fn maximum(self) -> u64 {
        match self {
            Self::Replacement => record_runtime::MAX_STATE_BYTES + 4096 + 28,
            Self::Source => 256 * 1024 * 1024,
        }
    }
}
fn filename(name: &str) -> Result<(), AppError> {
    if name.is_empty()
        || name == "."
        || name == ".."
        || name.len() > 255
        || name.contains(['/', '\\', '\0'])
    {
        return Err(invalid());
    }
    Ok(())
}
#[cfg(unix)]
pub(super) struct ArchiveDirectory {
    directory: std::fs::File,
    base: std::fs::File,
    kind: Kind,
}
#[cfg(unix)]
impl ArchiveDirectory {
    pub fn open(env: &SyncEnv, kind: Kind) -> Result<Self, AppError> {
        use std::os::{
            fd::{AsRawFd, FromRawFd},
            unix::fs::{MetadataExt, OpenOptionsExt},
        };
        let parent = env.state_path.parent().ok_or_else(invalid)?;
        crate::fsutil::check_write(&parent.join(kind.name()))?;
        let parent = std::fs::canonicalize(parent)?;
        crate::fsutil::check_write(&parent.join(kind.name()))?;
        let mut base = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open("/")?;
        use std::os::unix::ffi::OsStrExt;
        for component in parent.components() {
            match component {
                std::path::Component::RootDir => {}
                std::path::Component::Normal(name) => {
                    let name = std::ffi::CString::new(name.as_bytes()).map_err(|_| invalid())?;
                    let fd = unsafe {
                        libc::openat(
                            base.as_raw_fd(),
                            name.as_ptr(),
                            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                        )
                    };
                    if fd < 0 {
                        return Err(std::io::Error::last_os_error().into());
                    }
                    base = unsafe { std::fs::File::from_raw_fd(fd) };
                }
                _ => return Err(invalid()),
            }
        }
        let name = std::ffi::CString::new(kind.name()).map_err(|_| invalid())?;
        let made = unsafe { libc::mkdirat(base.as_raw_fd(), name.as_ptr(), 0o700) };
        if made < 0 && std::io::Error::last_os_error().kind() != std::io::ErrorKind::AlreadyExists {
            return Err(std::io::Error::last_os_error().into());
        }
        let fd = unsafe {
            libc::openat(
                base.as_raw_fd(),
                name.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        let dir = unsafe { std::fs::File::from_raw_fd(fd) };
        let metadata = dir.metadata()?;
        if !metadata.is_dir()
            || metadata.uid() != unsafe { libc::geteuid() }
            || metadata.mode() & 0o077 != 0
        {
            return Err(invalid());
        }
        base.sync_all()?;
        Ok(Self {
            directory: dir,
            base,
            kind,
        })
    }
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    pub fn names(&self) -> Result<Vec<String>, AppError> {
        use std::{ffi::CStr, os::fd::AsRawFd};
        struct Stream(*mut libc::DIR);
        impl Drop for Stream {
            fn drop(&mut self) {
                unsafe {
                    libc::closedir(self.0);
                }
            }
        }
        let fd = unsafe { libc::dup(self.directory.as_raw_fd()) };
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
        unsafe {
            libc::rewinddir(stream.0);
        }
        let mut names = std::collections::BTreeSet::new();
        loop {
            #[cfg(target_os = "macos")]
            let errno = unsafe { libc::__error() };
            #[cfg(target_os = "linux")]
            let errno = unsafe { libc::__errno_location() };
            unsafe {
                *errno = 0;
            }
            let entry = unsafe { libc::readdir(stream.0) };
            if entry.is_null() {
                if unsafe { *errno } != 0 {
                    return Err(invalid());
                }
                break;
            }
            let name = unsafe { CStr::from_ptr((*entry).d_name.as_ptr()) }
                .to_str()
                .map_err(|_| invalid())?;
            if matches!(name, "." | "..") {
                continue;
            }
            filename(name)?;
            if names.len() >= 8192 || !names.insert(name.to_owned()) {
                return Err(invalid());
            }
        }
        self.sync()?;
        Ok(names.into_iter().collect())
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    pub fn names(&self) -> Result<Vec<String>, AppError> {
        Err(invalid())
    }
    pub fn read(&self, name: &str) -> Result<Option<Vec<u8>>, AppError> {
        use std::os::fd::{AsRawFd, FromRawFd};
        filename(name)?;
        let name = std::ffi::CString::new(name).map_err(|_| invalid())?;
        let fd = unsafe {
            libc::openat(
                self.directory.as_raw_fd(),
                name.as_ptr(),
                libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            let error = std::io::Error::last_os_error();
            return if error.kind() == std::io::ErrorKind::NotFound {
                Ok(None)
            } else {
                Err(error.into())
            };
        }
        let file = unsafe { std::fs::File::from_raw_fd(fd) };
        self.read_opened(&name, file).map(Some)
    }
    fn read_opened(
        &self,
        name: &std::ffi::CStr,
        mut file: std::fs::File,
    ) -> Result<Vec<u8>, AppError> {
        use std::{io::Read, os::fd::AsRawFd};
        let metadata = file.metadata()?;
        use std::os::unix::fs::MetadataExt;
        if !metadata.is_file()
            || metadata.len() > self.kind.maximum()
            || metadata.uid() != unsafe { libc::geteuid() }
            || metadata.mode() & 0o077 != 0
        {
            return Err(invalid());
        }
        let mut bytes = Vec::new();
        (&mut file)
            .take(self.kind.maximum() + 1)
            .read_to_end(&mut bytes)?;
        let after = file.metadata()?;
        if bytes.len() as u64 > self.kind.maximum()
            || bytes.len() as u64 != metadata.len()
            || after.len() != metadata.len()
            || after.mtime() != metadata.mtime()
            || after.mtime_nsec() != metadata.mtime_nsec()
            || after.ctime() != metadata.ctime()
            || after.ctime_nsec() != metadata.ctime_nsec()
            || after.uid() != metadata.uid()
            || after.mode() & 0o077 != 0
        {
            return Err(invalid());
        }
        // A still-open old descriptor cannot prove that the immutable named snapshot survived
        // a concurrent restore/replacement of the archive file itself.
        let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
        if unsafe {
            libc::fstatat(
                self.directory.as_raw_fd(),
                name.as_ptr(),
                stat.as_mut_ptr(),
                libc::AT_SYMLINK_NOFOLLOW,
            )
        } < 0
        {
            return Err(invalid());
        }
        let stat = unsafe { stat.assume_init() };
        if stat.st_mode & libc::S_IFMT != libc::S_IFREG
            || stat.st_dev as u64 != after.dev()
            || stat.st_ino as u64 != after.ino()
            || stat.st_size as u64 != after.len()
        {
            return Err(invalid());
        }
        Ok(bytes)
    }
    pub fn publish(&self, name: &str, bytes: &[u8]) -> Result<(), AppError> {
        if bytes.len() as u64 > self.kind.maximum() {
            return Err(invalid());
        }
        use std::{
            io::Write,
            os::fd::{AsRawFd, FromRawFd},
        };
        filename(name)?;
        let name = std::ffi::CString::new(name).map_err(|_| invalid())?;
        let temporary = std::ffi::CString::new(format!(".pending-{}", crypto::random_id(16)?))
            .map_err(|_| invalid())?;
        let fd = unsafe {
            libc::openat(
                self.directory.as_raw_fd(),
                temporary.as_ptr(),
                libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                0o600,
            )
        };
        if fd < 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        let mut file = unsafe { std::fs::File::from_raw_fd(fd) };
        let result: Result<(), AppError> = (|| {
            file.write_all(bytes)?;
            file.sync_all()?;
            if unsafe {
                libc::linkat(
                    self.directory.as_raw_fd(),
                    temporary.as_ptr(),
                    self.directory.as_raw_fd(),
                    name.as_ptr(),
                    0,
                )
            } < 0
            {
                return Err(std::io::Error::last_os_error().into());
            }
            Ok(())
        })();
        let removed = unsafe { libc::unlinkat(self.directory.as_raw_fd(), temporary.as_ptr(), 0) };
        result?;
        if removed < 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        self.sync()
    }
    pub fn sync(&self) -> Result<(), AppError> {
        use std::os::{fd::AsRawFd, unix::fs::MetadataExt};
        self.directory.sync_all()?;
        let name = std::ffi::CString::new(self.kind.name()).map_err(|_| invalid())?;
        let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
        if unsafe {
            libc::fstatat(
                self.base.as_raw_fd(),
                name.as_ptr(),
                stat.as_mut_ptr(),
                libc::AT_SYMLINK_NOFOLLOW,
            )
        } < 0
        {
            return Err(std::io::Error::last_os_error().into());
        }
        let stat = unsafe { stat.assume_init() };
        let actual = self.directory.metadata()?;
        if stat.st_mode & libc::S_IFMT != libc::S_IFDIR
            || stat.st_dev as u64 != actual.dev()
            || stat.st_ino as u64 != actual.ino()
            || actual.mode() & 0o077 != 0
        {
            return Err(invalid());
        }
        self.base.sync_all()?;
        Ok(())
    }
}
#[cfg(windows)]
pub(super) struct ArchiveDirectory {
    directory: crate::sync::central_files_windows::Directory,
    kind: Kind,
}
#[cfg(windows)]
impl ArchiveDirectory {
    pub fn open(env: &SyncEnv, kind: Kind) -> Result<Self, AppError> {
        let parent = env.state_path.parent().ok_or_else(invalid)?;
        let _base = crate::sync::central_files_windows::Directory::private(parent, true)?;
        let directory = crate::sync::central_files_windows::Directory::private(
            &parent.join(kind.name()),
            true,
        )?;
        Ok(Self { directory, kind })
    }
    pub fn names(&self) -> Result<Vec<String>, AppError> {
        self.directory.check_private()?;
        self.directory.list()
    }
    pub fn read(&self, name: &str) -> Result<Option<Vec<u8>>, AppError> {
        filename(name)?;
        self.directory.check_private()?;
        match self.directory.read_private(name, self.kind.maximum()) {
            Ok(bytes) => Ok(Some(bytes)),
            Err(AppError::Io(e)) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e),
        }
    }
    pub fn publish(&self, name: &str, bytes: &[u8]) -> Result<(), AppError> {
        filename(name)?;
        if bytes.len() as u64 > self.kind.maximum() {
            return Err(invalid());
        }
        self.directory.check_private()?;
        crate::sync::central_files_windows::write(&self.directory.path().join(name), bytes, false)?;
        self.sync()
    }
    pub fn sync(&self) -> Result<(), AppError> {
        self.directory.check_private()
    }
}
#[cfg(not(any(unix, windows)))]
pub(super) struct ArchiveDirectory;
#[cfg(not(any(unix, windows)))]
impl ArchiveDirectory {
    pub fn open(_: &SyncEnv, _: Kind) -> Result<Self, AppError> {
        Err(AppError::Other("This platform build cannot yet guarantee durable device-recovery archives. Original data is retained.".into()))
    }
    pub fn names(&self) -> Result<Vec<String>, AppError> {
        Err(invalid())
    }
    pub fn read(&self, _: &str) -> Result<Option<Vec<u8>>, AppError> {
        Err(invalid())
    }
    pub fn publish(&self, _: &str, _: &[u8]) -> Result<(), AppError> {
        Err(invalid())
    }
    pub fn sync(&self) -> Result<(), AppError> {
        Err(invalid())
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use crate::sync::{
        fake_relay::FakeRelay,
        testkit::{TestClock, TestDevice},
    };
    use std::{
        fs,
        os::unix::fs::{symlink, PermissionsExt},
    };
    fn device() -> TestDevice {
        TestDevice::new(
            "source-archive-directory",
            &FakeRelay::new(),
            &TestClock::new(),
        )
    }
    #[test]
    fn closed_archive_roots_are_separate_immutable_and_private() {
        let device = device();
        let env = device.env();
        let parent = env.state_path.parent().unwrap();
        fs::create_dir_all(parent).unwrap();
        let source = ArchiveDirectory::open(&env, Kind::Source).unwrap();
        let recovery = ArchiveDirectory::open(&env, Kind::Replacement).unwrap();
        source.publish("same-name", b"encrypted source").unwrap();
        recovery
            .publish("same-name", b"encrypted replacement")
            .unwrap();
        assert_eq!(
            source.read("same-name").unwrap().unwrap(),
            b"encrypted source"
        );
        assert_eq!(
            recovery.read("same-name").unwrap().unwrap(),
            b"encrypted replacement"
        );
        assert!(source.publish("same-name", b"overwrite attempt").is_err());
        assert_eq!(
            source.read("same-name").unwrap().unwrap(),
            b"encrypted source"
        );
        for name in [Kind::Source.name(), Kind::Replacement.name()] {
            assert_eq!(
                fs::metadata(parent.join(name))
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o700
            );
            assert_eq!(
                fs::metadata(parent.join(name).join("same-name"))
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o600
            );
        }
    }
    #[test]
    fn source_root_rejects_escape_special_or_oversized_files_and_never_repairs_untrusted_permissions(
    ) {
        let device = device();
        let env = device.env();
        let parent = env.state_path.parent().unwrap();
        fs::create_dir_all(parent).unwrap();
        let source = ArchiveDirectory::open(&env, Kind::Source).unwrap();
        let root = parent.join(Kind::Source.name());
        for name in ["../vault.json", "/outside", "a/b", "a\\b", ".", "..", ""] {
            assert!(source.read(name).is_err());
            assert!(source.publish(name, b"never written").is_err());
        }
        assert_eq!(fs::read_dir(&root).unwrap().count(), 0);
        let outside = tempfile::tempdir().unwrap();
        fs::write(outside.path().join("ciphertext"), b"outside").unwrap();
        symlink(outside.path().join("ciphertext"), root.join("redirect")).unwrap();
        assert!(source.read("redirect").is_err());
        let file = fs::File::create(root.join("oversize")).unwrap();
        file.set_permissions(fs::Permissions::from_mode(0o600))
            .unwrap();
        file.set_len(Kind::Source.maximum() + 1).unwrap();
        assert!(source.read("oversize").is_err());
        fs::set_permissions(&root, fs::Permissions::from_mode(0o755)).unwrap();
        assert!(ArchiveDirectory::open(&env, Kind::Source).is_err());
        assert_eq!(
            fs::metadata(&root).unwrap().permissions().mode() & 0o777,
            0o755
        );
    }
    #[test]
    fn an_open_old_file_descriptor_cannot_claim_that_a_replaced_named_archive_is_retained() {
        let device = device();
        let env = device.env();
        let parent = env.state_path.parent().unwrap();
        fs::create_dir_all(parent).unwrap();
        let source = ArchiveDirectory::open(&env, Kind::Source).unwrap();
        source.publish("snapshot", b"old encrypted source").unwrap();
        let root = parent.join(Kind::Source.name());
        let old = fs::File::open(root.join("snapshot")).unwrap();
        fs::rename(root.join("snapshot"), root.join("kept-old")).unwrap();
        fs::write(root.join("snapshot"), b"other encrypted source").unwrap();
        fs::set_permissions(root.join("snapshot"), fs::Permissions::from_mode(0o600)).unwrap();
        assert!(source
            .read_opened(&std::ffi::CString::new("snapshot").unwrap(), old)
            .is_err());
        assert_eq!(
            source.read("snapshot").unwrap().unwrap(),
            b"other encrypted source"
        );
        assert_eq!(
            fs::read(root.join("kept-old")).unwrap(),
            b"old encrypted source"
        );
    }
    #[test]
    fn detached_or_redirected_source_archive_root_cannot_claim_durable_publication() {
        let device = device();
        let env = device.env();
        let parent = env.state_path.parent().unwrap();
        fs::create_dir_all(parent).unwrap();
        let source = ArchiveDirectory::open(&env, Kind::Source).unwrap();
        let root = parent.join(Kind::Source.name());
        let moved = parent.join("moved-source-archives");
        fs::rename(&root, &moved).unwrap();
        fs::create_dir(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        assert!(source.publish("source", b"encrypted source").is_err());
        assert_eq!(fs::read_dir(&root).unwrap().count(), 0);
        assert_eq!(fs::read(moved.join("source")).unwrap(), b"encrypted source");
        fs::remove_dir(&root).unwrap();
        symlink(&moved, &root).unwrap();
        assert!(ArchiveDirectory::open(&env, Kind::Source).is_err());
    }
}
