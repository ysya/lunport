//! Windows filesystem boundary for central sync. Paths stay pinned while native
//! handles verify ownership, ACLs, reparse points, file identity and bounded reads.
use crate::error::AppError;
use std::{
    cell::RefCell,
    ffi::c_void,
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    os::windows::{
        ffi::OsStrExt,
        fs::OpenOptionsExt,
        io::{AsRawHandle, FromRawHandle},
    },
    path::{Component, Path, PathBuf, Prefix},
    ptr,
    sync::Arc,
};
use windows_sys::Win32::{
    Foundation::{LocalFree, ERROR_HANDLE_EOF, ERROR_SUCCESS, INVALID_HANDLE_VALUE},
    Foundation::{GENERIC_READ, GENERIC_WRITE},
    Security::{
        Authorization::{
            ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW,
            GetSecurityInfo, SDDL_REVISION_1, SE_FILE_OBJECT,
        },
        EqualSid, GetAce, IsValidSid, ACCESS_ALLOWED_ACE, ACL, DACL_SECURITY_INFORMATION,
        INHERIT_ONLY_ACE, OWNER_SECURITY_INFORMATION, SECURITY_ATTRIBUTES, TOKEN_USER,
    },
    Storage::FileSystem::{
        CreateDirectoryW, CreateFileW, FileRenameInfo, FindClose, FindFirstStreamW,
        FindNextStreamW, FindStreamInfoStandard, GetFileInformationByHandle,
        SetFileInformationByHandle, BY_HANDLE_FILE_INFORMATION, CREATE_NEW, DELETE,
        FILE_ALL_ACCESS, FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_BACKUP_SEMANTICS,
        FILE_FLAG_OPEN_REPARSE_POINT, FILE_FLAG_WRITE_THROUGH, FILE_RENAME_INFO, FILE_SHARE_READ,
        WIN32_FIND_STREAM_DATA, WRITE_DAC,
    },
    System::SystemServices::{ACCESS_ALLOWED_ACE_TYPE, ACCESS_DENIED_ACE_TYPE},
};
use zeroize::Zeroizing;
fn invalid() -> AppError {
    io::Error::new(
        io::ErrorKind::PermissionDenied,
        "Central sync requires an owned regular Windows path with safe permissions.",
    )
    .into()
}
fn wide(path: &Path) -> Vec<u16> {
    path.as_os_str().encode_wide().chain(Some(0)).collect()
}
struct Local(*mut c_void);
impl Drop for Local {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe {
                LocalFree(self.0);
            }
        }
    }
}
fn sid_text(sid: *mut c_void) -> Result<String, AppError> {
    if sid.is_null() || unsafe { IsValidSid(sid) } == 0 {
        return Err(invalid());
    }
    let mut text = ptr::null_mut();
    if unsafe { ConvertSidToStringSidW(sid, &mut text) } == 0 {
        return Err(io::Error::last_os_error().into());
    }
    let _allocation = Local(text as *mut c_void);
    let mut length = 0;
    while unsafe { *text.add(length) } != 0 {
        length += 1;
    }
    String::from_utf16(unsafe { std::slice::from_raw_parts(text, length) }).map_err(|_| invalid())
}
fn security(file: &File, private: bool) -> Result<(), AppError> {
    let token = super::slot_files_windows::current_user_token()?;
    let user = unsafe { &*(token.as_ptr() as *const TOKEN_USER) }.User.Sid;
    let mut owner = ptr::null_mut();
    let mut acl: *mut ACL = ptr::null_mut();
    let mut descriptor = ptr::null_mut();
    let result = unsafe {
        GetSecurityInfo(
            file.as_raw_handle(),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            &mut owner,
            ptr::null_mut(),
            &mut acl,
            ptr::null_mut(),
            &mut descriptor,
        )
    };
    let _allocation = Local(descriptor);
    if result != ERROR_SUCCESS {
        return Err(io::Error::from_raw_os_error(result as i32).into());
    }
    // Elevated Windows users can create originals owned by Administrators. Administrators,
    // like Unix root, are already outside this per-user filesystem boundary.
    if owner.is_null()
        || (unsafe { EqualSid(owner, user) } == 0 && sid_text(owner)? != "S-1-5-32-544")
        || acl.is_null()
    {
        return Err(invalid());
    }
    const WRITE_ACCESS: u32 = 0x0000_0156 | 0x000d_0000 | 0x4000_0000 | 0x1000_0000;
    let mut own_access = 0;
    for index in 0..unsafe { (*acl).AceCount } {
        let mut ace = ptr::null_mut();
        if unsafe { GetAce(acl, index as u32, &mut ace) } == 0 || ace.is_null() {
            return Err(invalid());
        }
        let header = unsafe { &*(ace as *const windows_sys::Win32::Security::ACE_HEADER) };
        if u32::from(header.AceType) == ACCESS_DENIED_ACE_TYPE {
            continue;
        }
        if u32::from(header.AceType) != ACCESS_ALLOWED_ACE_TYPE
            || usize::from(header.AceSize) < std::mem::size_of::<ACCESS_ALLOWED_ACE>()
        {
            return Err(invalid());
        }
        let allow = unsafe { &*(ace as *const ACCESS_ALLOWED_ACE) };
        let sid = std::ptr::addr_of!(allow.SidStart) as *mut c_void;
        if unsafe { IsValidSid(sid) } == 0 {
            return Err(invalid());
        }
        let own = unsafe { EqualSid(sid, user) } != 0;
        if private {
            if !own {
                return Err(invalid());
            }
            if u32::from(header.AceFlags) & INHERIT_ONLY_ACE == 0 {
                own_access |= allow.Mask;
            }
        } else if !own
            && u32::from(header.AceFlags) & INHERIT_ONLY_ACE == 0
            && allow.Mask & WRITE_ACCESS != 0
        {
            let text = sid_text(sid)?;
            if text != "S-1-5-18" && text != "S-1-5-32-544" {
                return Err(invalid());
            }
        }
    }
    if private && own_access & FILE_ALL_ACCESS != FILE_ALL_ACCESS {
        return Err(invalid());
    }
    Ok(())
}
struct Descriptor(Local);
impl Descriptor {
    fn owner_only(directory: bool) -> Result<Self, AppError> {
        let token = super::slot_files_windows::current_user_token()?;
        let sid = unsafe { &*(token.as_ptr() as *const TOKEN_USER) }.User.Sid;
        let sid = sid_text(sid)?;
        let sddl = format!(
            "O:{sid}D:P(A;{};FA;;;{sid})",
            if directory { "OICI" } else { "" }
        );
        let text: Vec<u16> = sddl.encode_utf16().chain(Some(0)).collect();
        let mut descriptor = ptr::null_mut();
        if unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                text.as_ptr(),
                SDDL_REVISION_1,
                &mut descriptor,
                ptr::null_mut(),
            )
        } == 0
        {
            return Err(io::Error::last_os_error().into());
        }
        Ok(Self(Local(descriptor)))
    }
    fn attributes(&self) -> SECURITY_ATTRIBUTES {
        SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: self.0 .0,
            bInheritHandle: 0,
        }
    }
}
#[derive(Clone, Copy, PartialEq, Eq)]
struct Stamp {
    identity: (u32, u32, u32),
    size: u64,
    modified: (u32, u32),
    created: (u32, u32),
    attributes: u32,
    links: u32,
}
fn stamp(file: &File) -> Result<Stamp, AppError> {
    let mut info = std::mem::MaybeUninit::<BY_HANDLE_FILE_INFORMATION>::uninit();
    if unsafe { GetFileInformationByHandle(file.as_raw_handle(), info.as_mut_ptr()) } == 0 {
        return Err(io::Error::last_os_error().into());
    }
    let info = unsafe { info.assume_init() };
    if info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(invalid());
    }
    Ok(Stamp {
        identity: (
            info.dwVolumeSerialNumber,
            info.nFileIndexHigh,
            info.nFileIndexLow,
        ),
        size: (u64::from(info.nFileSizeHigh) << 32) | u64::from(info.nFileSizeLow),
        modified: (
            info.ftLastWriteTime.dwHighDateTime,
            info.ftLastWriteTime.dwLowDateTime,
        ),
        created: (
            info.ftCreationTime.dwHighDateTime,
            info.ftCreationTime.dwLowDateTime,
        ),
        attributes: info.dwFileAttributes,
        links: info.nNumberOfLinks,
    })
}
pub(crate) fn name(value: &str) -> Result<(), AppError> {
    let stem = value.split('.').next().unwrap_or("").to_ascii_uppercase();
    if value.is_empty()
        || value.len() > 255
        || value == "."
        || value == ".."
        || value.ends_with(['.', ' '])
        || value
            .chars()
            .any(|c| c.is_control() || "<>:\"/\\|?*".contains(c))
        || ["CON", "PRN", "AUX", "NUL", "CONIN$", "CONOUT$"].contains(&stem.as_str())
        || ["COM", "LPT"].iter().any(|prefix| {
            stem.strip_prefix(*prefix)
                .is_some_and(|n| ["1", "2", "3", "4", "5", "6", "7", "8", "9"].contains(&n))
        })
    {
        return Err(invalid());
    }
    Ok(())
}
fn opened(path: &Path, write: bool, acl_write: bool) -> Result<File, AppError> {
    let mut options = OpenOptions::new();
    options
        .access_mode(
            GENERIC_READ
                | if write { GENERIC_WRITE } else { 0 }
                | if acl_write { WRITE_DAC } else { 0 },
        )
        .share_mode(FILE_SHARE_READ)
        .custom_flags(
            FILE_FLAG_BACKUP_SEMANTICS
                | FILE_FLAG_OPEN_REPARSE_POINT
                | if write { FILE_FLAG_WRITE_THROUGH } else { 0 },
        );
    let file = options.open(path).map_err(|error| {
        io::Error::new(
            error.kind(),
            format!(
                "Cannot open pinned Windows path {}: {error}",
                path.display()
            ),
        )
    })?;
    stamp(&file)?;
    Ok(file)
}
fn no_streams(path: &Path) -> Result<(), AppError> {
    let mut data = std::mem::MaybeUninit::<WIN32_FIND_STREAM_DATA>::zeroed();
    let handle = unsafe {
        FindFirstStreamW(
            wide(path).as_ptr(),
            FindStreamInfoStandard,
            data.as_mut_ptr() as *mut c_void,
            0,
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        let e = io::Error::last_os_error();
        return if e.raw_os_error() == Some(ERROR_HANDLE_EOF as i32) {
            Ok(())
        } else {
            Err(e.into())
        };
    }
    struct Search(windows_sys::Win32::Foundation::HANDLE);
    impl Drop for Search {
        fn drop(&mut self) {
            unsafe {
                FindClose(self.0);
            }
        }
    }
    let _search = Search(handle);
    loop {
        let observed = unsafe { data.assume_init_ref() };
        let length = observed
            .cStreamName
            .iter()
            .position(|c| *c == 0)
            .ok_or_else(invalid)?;
        if String::from_utf16(&observed.cStreamName[..length]).map_err(|_| invalid())? != "::$DATA"
        {
            return Err(invalid());
        }
        if unsafe { FindNextStreamW(handle, data.as_mut_ptr().cast()) } == 0 {
            let e = io::Error::last_os_error();
            return if e.raw_os_error() == Some(ERROR_HANDLE_EOF as i32) {
                Ok(())
            } else {
                Err(e.into())
            };
        }
    }
}
/// Every component remains open without write/delete sharing. Junctions cannot
/// redirect later path-based operations while these handles are held.
pub(crate) struct Directory {
    path: PathBuf,
    pins: Vec<Arc<File>>,
    observed: Stamp,
    names: RefCell<Option<Vec<String>>>,
}
impl Directory {
    pub(crate) fn path(&self) -> &Path {
        &self.path
    }
    pub(crate) fn open(path: &Path) -> Result<Option<Self>, AppError> {
        Self::open_at(path, false, false)
    }
    pub(crate) fn private(path: &Path, create: bool) -> Result<Self, AppError> {
        Self::open_at(path, create, true)?.ok_or_else(invalid)
    }
    fn open_at(path: &Path, create: bool, private: bool) -> Result<Option<Self>, AppError> {
        if !path.is_absolute()
            || path
                .components()
                .any(|p| matches!(p, Component::ParentDir | Component::CurDir))
        {
            return Err(invalid());
        }
        if create || private {
            crate::fsutil::check_write(path)?;
        }
        let mut at = PathBuf::new();
        let mut pins = vec![];
        for component in path.components() {
            match component {
                Component::Prefix(p)
                    if matches!(p.kind(), Prefix::Disk(_) | Prefix::VerbatimDisk(_)) =>
                {
                    at.push(p.as_os_str())
                }
                Component::RootDir => at.push(component.as_os_str()),
                Component::Normal(p) => {
                    name(p.to_str().ok_or_else(invalid)?)?;
                    at.push(p);
                }
                _ => return Err(invalid()),
            }
            if !at.is_absolute() {
                continue;
            }
            let file = match opened(&at, false, private && at == path) {
                Ok(file) => file,
                Err(AppError::Io(e)) if e.kind() == io::ErrorKind::NotFound => {
                    if !create {
                        return Ok(None);
                    }
                    crate::fsutil::check_write(&at)?;
                    let descriptor = Descriptor::owner_only(true)?;
                    if unsafe { CreateDirectoryW(wide(&at).as_ptr(), &descriptor.attributes()) }
                        == 0
                    {
                        let e = io::Error::last_os_error();
                        if e.kind() != io::ErrorKind::AlreadyExists {
                            return Err(e.into());
                        }
                    }
                    opened(&at, false, private && at == path)?
                }
                Err(e) => return Err(e),
            };
            if !file.metadata()?.is_dir() {
                return Err(invalid());
            }
            pins.push(Arc::new(file));
        }
        let file = pins.last().ok_or_else(invalid)?;
        security(file, false)?;
        no_streams(path)?;
        if private {
            // Existing app directories may have safe inherited SYSTEM/admin ACEs. Tighten
            // only this owned directory, never propagate changes into user key hard links.
            super::slot_files_windows::restrict_to_owner(path, true).map_err(|error| {
                io::Error::new(
                    error.kind(),
                    format!("Cannot apply private Windows directory permissions: {error}"),
                )
            })?;
            security(file, true)?;
        }
        let observed = stamp(file)?;
        Ok(Some(Self {
            path: path.into(),
            pins,
            observed,
            names: RefCell::new(None),
        }))
    }
    pub(crate) fn list(&self) -> Result<Vec<String>, AppError> {
        let mut names = std::collections::BTreeSet::new();
        for entry in fs::read_dir(&self.path)? {
            let value = entry?.file_name().into_string().map_err(|_| invalid())?;
            name(&value)?;
            if names.len() >= 8192 || !names.insert(value) {
                return Err(invalid());
            }
        }
        Ok(names.into_iter().collect())
    }
    pub(crate) fn names(&self) -> Result<Vec<String>, AppError> {
        let result = self.list()?;
        if let Some(before) = self.names.borrow().as_ref() {
            if before != &result {
                return Err(invalid());
            }
        }
        *self.names.borrow_mut() = Some(result.clone());
        Ok(result)
    }
    pub(crate) fn optional_directory(&self, value: &str) -> Result<Option<Self>, AppError> {
        name(value)?;
        let Some(child) = Self::open(&self.path.join(value))? else {
            return Ok(None);
        };
        Ok(Some(child))
    }
    pub(crate) fn child(&self, value: &str) -> Result<Option<Self>, AppError> {
        name(value)?;
        let file = opened(&self.path.join(value), false, false)?;
        if !file.metadata()?.is_dir() {
            return Ok(None);
        }
        drop(file);
        self.optional_directory(value)
    }
    pub(crate) fn read(&self, value: &str, limit: u64) -> Result<Vec<u8>, AppError> {
        self.read_checked(value, limit, false)
    }
    pub(crate) fn read_private(&self, value: &str, limit: u64) -> Result<Vec<u8>, AppError> {
        self.read_checked(value, limit, true)
    }
    fn read_checked(&self, value: &str, limit: u64, private: bool) -> Result<Vec<u8>, AppError> {
        name(value)?;
        let path = self.path.join(value);
        let file = opened(&path, false, false)?;
        let before = stamp(&file)?;
        security(&file, private)?;
        if !file.metadata()?.is_file() || before.size > limit || private && before.links != 1 {
            return Err(invalid());
        }
        no_streams(&path)?;
        let mut bytes = Zeroizing::new(vec![]);
        (&file)
            .take(limit.checked_add(1).ok_or_else(invalid)?)
            .read_to_end(&mut bytes)?;
        if bytes.len() as u64 != before.size || stamp(&file)? != before {
            return Err(invalid());
        }
        let current = opened(&path, false, false)?;
        if stamp(&current)? != before {
            return Err(invalid());
        }
        security(&file, private)?;
        Ok(std::mem::take(&mut *bytes))
    }
    pub(crate) fn unchanged(&self) -> Result<(), AppError> {
        let file = self.pins.last().ok_or_else(invalid)?;
        if stamp(file)? != self.observed {
            return Err(invalid());
        }
        let current = opened(&self.path, false, false)?;
        if stamp(&current)?.identity != self.observed.identity {
            return Err(invalid());
        }
        security(file, false)?;
        let listed = self.names.borrow().is_some();
        if listed {
            self.names()?;
        }
        Ok(())
    }
    pub(crate) fn check_private(&self) -> Result<(), AppError> {
        let file = self.pins.last().ok_or_else(invalid)?;
        let current = opened(&self.path, false, false)?;
        if stamp(&current)?.identity != self.observed.identity {
            return Err(invalid());
        }
        security(file, true)?;
        no_streams(&self.path)
    }
}
/// A new owner-only file under pinned directories. No plaintext is written before
/// the security descriptor exists; callers retain their existing pre-rename checks.
fn check_destination(path: &Path) -> Result<(), AppError> {
    match opened(path, false, false) {
        Ok(file) => {
            let info = stamp(&file)?;
            if !file.metadata()?.is_file() || info.links != 1 {
                return Err(invalid());
            }
            security(&file, false)?;
            no_streams(path)
        }
        Err(AppError::Io(e)) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e),
    }
}
pub(crate) struct Temporary {
    pub(crate) file: Option<File>,
    path: PathBuf,
    destination: PathBuf,
    _directory: Directory,
    moved: bool,
}
impl Temporary {
    pub(crate) fn new(destination: &Path) -> Result<Self, AppError> {
        crate::fsutil::check_write(destination)?;
        name(
            destination
                .file_name()
                .and_then(|n| n.to_str())
                .ok_or_else(invalid)?,
        )?;
        let directory = Directory::private(destination.parent().ok_or_else(invalid)?, true)?;
        check_destination(destination)?;
        let path = destination.with_file_name(format!(
            ".pending-{}",
            super::central::crypto::random_id(16)?
        ));
        let descriptor = Descriptor::owner_only(false)?;
        let handle = unsafe {
            CreateFileW(
                wide(&path).as_ptr(),
                GENERIC_READ | GENERIC_WRITE | DELETE,
                FILE_SHARE_READ,
                &descriptor.attributes(),
                CREATE_NEW,
                FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_WRITE_THROUGH,
                ptr::null_mut(),
            )
        };
        if handle == INVALID_HANDLE_VALUE {
            let error = io::Error::last_os_error();
            return Err(io::Error::new(
                error.kind(),
                format!("Cannot create private Windows temporary: {error}"),
            )
            .into());
        }
        let file = unsafe { File::from_raw_handle(handle) };
        if let Err(error) = security(&file, true) {
            drop(file);
            let _ = fs::remove_file(&path);
            return Err(error);
        }
        Ok(Self {
            file: Some(file),
            path,
            destination: destination.into(),
            _directory: directory,
            moved: false,
        })
    }
    pub(crate) fn writer(&mut self) -> &mut File {
        self.file.as_mut().expect("unpublished temporary")
    }
    pub(crate) fn commit(&mut self, replace: bool) -> Result<(), AppError> {
        check_destination(&self.destination)?;
        let name: Vec<u16> = self
            .destination
            .file_name()
            .ok_or_else(invalid)?
            .encode_wide()
            .collect();
        let size = std::mem::size_of::<FILE_RENAME_INFO>() + name.len() * 2;
        let mut storage = vec![0u64; size.div_ceil(8)];
        let info = storage.as_mut_ptr() as *mut FILE_RENAME_INFO;
        unsafe {
            (*info).Anonymous.ReplaceIfExists = replace;
            // A simple name with a null root renames within this open file's actual parent.
            // Full-path MoveFileEx reopens that parent for write and conflicts with its guard.
            (*info).RootDirectory = ptr::null_mut();
            (*info).FileNameLength = (name.len() * 2) as u32;
            ptr::copy_nonoverlapping(name.as_ptr(), (*info).FileName.as_mut_ptr(), name.len());
        }
        if unsafe {
            SetFileInformationByHandle(
                self.as_file().as_raw_handle(),
                FileRenameInfo,
                info.cast(),
                size as u32,
            )
        } == 0
        {
            let error = io::Error::last_os_error();
            return Err(io::Error::new(
                error.kind(),
                format!("Cannot publish Windows temporary by handle: {error}"),
            )
            .into());
        }
        // No fallible action after rename: the caller first records publication, then flushes
        // the exact new image through a write-through handle, blocking Core if that is uncertain.
        self.moved = true;
        self.file.take();
        Ok(())
    }
}
impl Drop for Temporary {
    fn drop(&mut self) {
        self.file.take();
        if !self.moved {
            let _ = fs::remove_file(&self.path);
        }
    }
}
pub(crate) fn confirm(path: &Path) -> Result<(), AppError> {
    let _directory = Directory::private(path.parent().ok_or_else(invalid)?, false)?;
    let file = opened(path, true, false)?;
    let info = stamp(&file)?;
    if !file.metadata()?.is_file() || info.links != 1 {
        return Err(invalid());
    }
    security(&file, true)?;
    no_streams(path)?;
    file.sync_all()?;
    if stamp(&file)? != info {
        return Err(invalid());
    }
    Ok(())
}
pub(crate) fn write(path: &Path, bytes: &[u8], replace: bool) -> Result<(), AppError> {
    let mut temporary = Temporary::new(path)?;
    temporary.writer().write_all(bytes)?;
    temporary.writer().sync_all()?;
    temporary.commit(replace)?;
    confirm(path)?;
    let directory = Directory::private(path.parent().ok_or_else(invalid)?, false)?;
    if directory.read(
        path.file_name()
            .and_then(|n| n.to_str())
            .ok_or_else(invalid)?,
        bytes.len() as u64,
    )? != bytes
    {
        return Err(invalid());
    }
    Ok(())
}

impl std::io::Write for Temporary {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.writer().write(bytes)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.writer().flush()
    }
}
impl Temporary {
    pub(crate) fn as_file(&self) -> &File {
        self.file.as_ref().expect("unpublished temporary")
    }
}

pub(crate) fn read(path: &Path, limit: u64) -> Result<Vec<u8>, AppError> {
    let directory = Directory::open(path.parent().ok_or_else(invalid)?)?.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::NotFound,
            "central source directory is missing",
        )
    })?;
    directory.read(
        path.file_name()
            .and_then(|n| n.to_str())
            .ok_or_else(invalid)?,
        limit,
    )
}
pub(crate) fn optional(path: &Path, limit: u64) -> Result<Option<Vec<u8>>, AppError> {
    match read(path, limit) {
        Ok(bytes) => Ok(Some(bytes)),
        Err(AppError::Io(e)) if e.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn set_acl(path: &Path, sddl: &str) {
        let text: Vec<u16> = sddl.encode_utf16().chain(Some(0)).collect();
        let mut descriptor = ptr::null_mut();
        assert_ne!(
            unsafe {
                ConvertStringSecurityDescriptorToSecurityDescriptorW(
                    text.as_ptr(),
                    SDDL_REVISION_1,
                    &mut descriptor,
                    ptr::null_mut(),
                )
            },
            0
        );
        let descriptor = Local(descriptor);
        assert_ne!(
            unsafe {
                windows_sys::Win32::Security::SetFileSecurityW(
                    wide(path).as_ptr(),
                    DACL_SECURITY_INFORMATION,
                    descriptor.0,
                )
            },
            0
        );
    }
    #[test]
    fn private_create_replace_and_abandoned_write_preserve_originals_and_owner_only_access() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("private");
        let file = root.join("vault.json");
        write(&file, b"original encrypted material", false).unwrap();
        assert_eq!(
            super::super::slot_files_windows::ace_count(&root).unwrap(),
            1
        );
        assert_eq!(
            super::super::slot_files_windows::ace_count(&file).unwrap(),
            1
        );
        assert!(write(&file, b"overwrite", false).is_err());
        {
            let mut staged = Temporary::new(&file).unwrap();
            staged.write_all(b"uncommitted").unwrap();
            staged.as_file().sync_all().unwrap();
        }
        assert_eq!(read(&file, 1024).unwrap(), b"original encrypted material");
        assert_eq!(fs::read_dir(&root).unwrap().count(), 1);
        write(&file, b"replacement encrypted material", true).unwrap();
        confirm(&file).unwrap();
        assert_eq!(
            read(&file, 1024).unwrap(),
            b"replacement encrypted material"
        );
    }
    #[test]
    fn pinned_directories_and_files_refuse_rename_delete_and_concurrent_writers() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("private");
        let file = root.join("source");
        write(&file, b"original", false).unwrap();
        let directory = Directory::private(&root, false).unwrap();
        assert!(fs::rename(&root, temp.path().join("replaced")).is_err());
        {
            let _source = opened(&file, false, false).unwrap();
            assert!(fs::write(&file, b"changed").is_err());
            assert!(fs::remove_file(&file).is_err());
        }
        assert_eq!(directory.read_private("source", 1024).unwrap(), b"original");
        directory.check_private().unwrap();
    }
    #[test]
    fn junctions_cannot_redirect_reads_archives_or_private_temporary_files() {
        let temp = tempfile::tempdir().unwrap();
        let outside = temp.path().join("outside");
        fs::create_dir(&outside).unwrap();
        fs::write(outside.join("source"), b"original outside file").unwrap();
        let link = temp.path().join("redirect");
        let status = std::process::Command::new("cmd")
            .args(["/d", "/c", "mklink", "/J"])
            .arg(&link)
            .arg(&outside)
            .status()
            .unwrap();
        assert!(status.success());
        assert!(Directory::open(&link).is_err());
        assert!(Temporary::new(&link.join("source")).is_err());
        assert!(read(&link.join("source"), 1024).is_err());
        assert_eq!(
            fs::read(outside.join("source")).unwrap(),
            b"original outside file"
        );
        fs::remove_dir(&link).unwrap();
    }
    #[test]
    fn alternate_streams_unsafe_names_hard_links_and_broad_permissions_fail_closed() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("private");
        let file = root.join("source");
        write(&file, b"original", false).unwrap();
        for value in [
            "../outside",
            "a:b",
            "trailing.",
            "trailing ",
            "NUL",
            "con.txt",
            "COM1",
            "LPT9.log",
            "a\\b",
        ] {
            assert!(name(value).is_err(), "{value}");
        }
        fs::write(
            root.join("source:hidden"),
            b"retained unknown historical material",
        )
        .unwrap();
        assert!(read(&file, 1024).is_err());
        fs::remove_file(root.join("source:hidden")).unwrap();
        fs::hard_link(&file, root.join("linked")).unwrap();
        assert!(confirm(&file).is_err());
        fs::remove_file(root.join("linked")).unwrap();
        set_acl(&file, "D:P(A;;FA;;;WD)");
        assert!(read(&file, 1024).is_err());
        assert!(confirm(&file).is_err());
        assert_eq!(fs::read(&file).unwrap(), b"original");
        set_acl(&root, "D:P(A;OICI;FA;;;WD)");
        let before = super::super::slot_files_windows::ace_count(&root).unwrap();
        assert!(Directory::private(&root, false).is_err());
        assert_eq!(
            super::super::slot_files_windows::ace_count(&root).unwrap(),
            before
        );
    }
    #[test]
    fn complete_source_enumeration_detects_new_files_and_bounded_reads_refuse_partial_sources() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("private");
        write(&root.join("source"), b"original", false).unwrap();
        let directory = Directory::open(&root).unwrap().unwrap();
        assert_eq!(directory.names().unwrap(), vec!["source"]);
        assert!(directory.read("source", 3).is_err());
        write(&root.join("later"), b"new source", false).unwrap();
        assert!(directory.unchanged().is_err());
        assert!(optional(&root.join("missing"), 1024).unwrap().is_none());
        assert!(Directory::open(&root.join("source/child")).is_err());
    }
}
