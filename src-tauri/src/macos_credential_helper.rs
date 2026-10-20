//! Production macOS credentials belong to a frozen, signed executable. Its bytes
//! are embedded as data so the App bundler cannot re-sign it on each release.
//! Development keeps its separate native store. No secret reaches argv, disk,
//! logs or an unauthenticated child process.
use crate::error::AppError;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::fd::{AsRawFd, OwnedFd};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::Duration;
use zeroize::Zeroizing;

const MAGIC: &[u8; 8] = b"LPKC0001";
const MAX_ACCOUNT: usize = 4096;
const MAX_SECRET: usize = 1024 * 1024;
const NOT_FOUND: i32 = -25300;
const HELPER_NAME: &str = "Lunport Credential Helper";

extern "C" {
    fn lunport_validate_credential_peer(
        fd: i32,
        expected_pid: i32,
        required: *const std::ffi::c_char,
    ) -> i32;
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum Operation {
    Get = 1,
    Set = 2,
    Delete = 3,
}

fn error(message: impl std::fmt::Display) -> AppError {
    // Messages describe the operation, never its account, request or response.
    AppError::Other(format!("credential helper: {message}"))
}

#[cfg(not(debug_assertions))]
fn frozen() -> Result<(&'static [u8], String), AppError> {
    const BYTES: &[u8] = include_bytes!("../signing/credential-helper-v1.bin");
    Ok((
        BYTES,
        artifact_identity(BYTES, include_str!("../signing/credential-helper-v1.json"))?,
    ))
}

#[cfg(any(not(debug_assertions), test))]
fn artifact_identity(bytes: &[u8], manifest: &str) -> Result<String, AppError> {
    use sha2::{Digest, Sha256};
    let manifest: serde_json::Value =
        serde_json::from_str(manifest).map_err(|_| error("invalid embedded manifest"))?;
    let hash = Sha256::digest(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>();
    if manifest["protocol"] != 1
        || manifest["artifact_sha256"] != hash
        || manifest["identifier"] != "org.homelab.sshelter.credential-helper.v1"
    {
        return Err(error("embedded artifact does not match its manifest"));
    }
    let hashes =
        ["arm64", "x86_64"].map(|arch| manifest["cdhashes"][arch].as_str().unwrap_or_default());
    if hashes
        .iter()
        .any(|hash| hash.len() != 40 || !hash.bytes().all(|b| b.is_ascii_hexdigit()))
    {
        return Err(error("invalid embedded code hashes"));
    }
    Ok(format!("identifier \"org.homelab.sshelter.credential-helper.v1\" and certificate leaf = H\"a346b47b8dccb4faeac8aec1ea997535809aeec9\" and (cdhash H\"{}\" or cdhash H\"{}\")", hashes[0], hashes[1]))
}

#[cfg(debug_assertions)]
fn frozen() -> Result<(&'static [u8], String), AppError> {
    Err(error("only signed Production builds use the fixed helper"))
}

fn unsafe_path() -> io::Error {
    io::Error::new(
        io::ErrorKind::PermissionDenied,
        "unsafe credential-helper installation path",
    )
}

fn check_directory(path: &Path, private: bool) -> io::Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    let uid = unsafe { libc::geteuid() };
    if !metadata.is_dir()
        || metadata.file_type().is_symlink()
        || (metadata.uid() != uid && metadata.uid() != 0)
        || (metadata.mode() & 0o022 != 0
            && !(metadata.uid() == 0 && metadata.mode() & u32::from(libc::S_ISVTX) != 0))
        || (private && (metadata.uid() != uid || metadata.mode() & 0o077 != 0))
    {
        return Err(unsafe_path());
    }
    Ok(())
}

fn matching_file(path: &Path, bytes: &[u8]) -> io::Result<bool> {
    let mut file = match OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
    {
        Ok(file) => file,
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(false),
        Err(err) => return Err(err),
    };
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.uid() != unsafe { libc::geteuid() } || metadata.nlink() != 1
    {
        return Err(unsafe_path());
    }
    if metadata.mode() & 0o777 != 0o700 || metadata.len() != bytes.len() as u64 {
        return Ok(false);
    }
    let mut existing = Vec::with_capacity(bytes.len());
    Read::by_ref(&mut file)
        .take(bytes.len() as u64 + 1)
        .read_to_end(&mut existing)?;
    Ok(existing == bytes)
}

// Existing correct bytes are never rewritten. Missing/corrupt regular files can
// be restored from the signed App; symlinks and unsafe directories fail closed.
fn install(root: &Path, bytes: &[u8]) -> io::Result<PathBuf> {
    for ancestor in root.ancestors() {
        check_directory(ancestor, false)?;
    }
    let directory = root.join("credential-helper");
    match fs::DirBuilder::new().mode(0o700).create(&directory) {
        Ok(()) => (),
        Err(err) if err.kind() == io::ErrorKind::AlreadyExists => (),
        Err(err) => return Err(err),
    }
    check_directory(&directory, true)?;
    let directory = directory.join("v1");
    match fs::DirBuilder::new().mode(0o700).create(&directory) {
        Ok(()) => (),
        Err(err) if err.kind() == io::ErrorKind::AlreadyExists => (),
        Err(err) => return Err(err),
    }
    check_directory(&directory, true)?;
    let target = directory.join(HELPER_NAME);
    if matching_file(&target, bytes)? {
        return Ok(target);
    }
    let mut temporary = tempfile::NamedTempFile::new_in(&directory)?;
    temporary
        .as_file()
        .set_permissions(fs::Permissions::from_mode(0o700))?;
    temporary.write_all(bytes)?;
    temporary.as_file().sync_all()?;
    // A concurrent signed App/CLI installs the exact same artifact. Rechecking
    // handles that race; live child authentication also protects the exec race.
    if !matching_file(&target, bytes)? {
        temporary.persist(&target).map_err(|err| err.error)?;
        File::open(&directory)?.sync_all()?;
    }
    if !matching_file(&target, bytes)? {
        return Err(unsafe_path());
    }
    Ok(target)
}

struct Running(Child);
impl Drop for Running {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn request(
    operation: Operation,
    account: &str,
    secret: &[u8],
    no_ui: bool,
) -> Result<Option<Zeroizing<Vec<u8>>>, AppError> {
    validate_input(operation, account, secret).map_err(error)?;
    let (bytes, requirement) = frozen()?;
    let root = crate::fsutil::app_data_root()?;
    crate::fsutil::ensure_dir_secure(&root)?;
    let executable = install(&root, bytes).map_err(|_| {
        error("cannot safely install the helper; check this device's application-data permissions")
    })?;
    exchange(&executable, &requirement, operation, account, secret, no_ui)
}

fn validate_input(operation: Operation, account: &str, secret: &[u8]) -> io::Result<()> {
    if account.is_empty()
        || account.len() > MAX_ACCOUNT
        || account.as_bytes().contains(&0)
        || secret.len() > MAX_SECRET
        || (operation != Operation::Set && !secret.is_empty())
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid credential request",
        ));
    }
    Ok(())
}

fn exchange(
    executable: &Path,
    requirement: &str,
    operation: Operation,
    account: &str,
    secret: &[u8],
    no_ui: bool,
) -> Result<Option<Zeroizing<Vec<u8>>>, AppError> {
    let (mut socket, child_socket) = crate::process::without_spawns(UnixStream::pair)
        .map_err(|_| error("cannot create private channel"))?;
    socket
        .set_read_timeout(Some(Duration::from_secs(if no_ui { 10 } else { 305 })))
        .map_err(error)?;
    socket
        .set_write_timeout(Some(Duration::from_secs(5)))
        .map_err(error)?;
    let child_output: OwnedFd = child_socket.try_clone().map_err(error)?.into();
    let child_input: OwnedFd = child_socket.into();
    let mut command = Command::new(executable);
    command
        .env_clear()
        .stdin(Stdio::from(child_input))
        .stdout(Stdio::from(child_output))
        .stderr(Stdio::null());
    let mut child = Running(
        crate::process::spawn(&mut command).map_err(|_| error("cannot start the signed helper"))?,
    );
    // Command retains its Stdio handles after spawn; release them for EOF.
    drop(command);
    let mut hello = [0u8; 8];
    socket
        .read_exact(&mut hello)
        .map_err(|_| error("helper authentication failed; no credentials were sent"))?;
    let required =
        std::ffi::CString::new(requirement).map_err(|_| error("invalid helper requirement"))?;
    if &hello != MAGIC
        || unsafe {
            lunport_validate_credential_peer(
                socket.as_raw_fd(),
                child.0.id() as i32,
                required.as_ptr(),
            )
        } != 1
    {
        return Err(error(
            "helper identity did not match the frozen artifact; no credentials were sent",
        ));
    }
    let mut header = [0u8; 18];
    header[..8].copy_from_slice(MAGIC);
    header[8] = operation as u8;
    header[9] = u8::from(no_ui);
    header[10..14].copy_from_slice(&(account.len() as u32).to_be_bytes());
    header[14..18].copy_from_slice(&(secret.len() as u32).to_be_bytes());
    socket
        .write_all(&header)
        .and_then(|_| socket.write_all(account.as_bytes()))
        .and_then(|_| socket.write_all(secret))
        .map_err(|_| error("request channel closed"))?;
    socket.shutdown(std::net::Shutdown::Write).map_err(error)?;
    let mut response = [0u8; 8];
    socket
        .read_exact(&mut response)
        .map_err(|_| error("request was cancelled, timed out or the helper stopped"))?;
    let status = i32::from_be_bytes(response[..4].try_into().unwrap());
    let length = u32::from_be_bytes(response[4..].try_into().unwrap()) as usize;
    if length > MAX_SECRET
        || (status != 0 && length != 0)
        || (operation != Operation::Get && length != 0)
    {
        return Err(error("invalid helper response"));
    }
    let mut output = Zeroizing::new(vec![0u8; length]);
    socket
        .read_exact(&mut output)
        .map_err(|_| error("incomplete helper response"))?;
    let mut trailing = [0u8; 1];
    if socket.read(&mut trailing).map_err(error)? != 0 || !child.0.wait().map_err(error)?.success()
    {
        return Err(error("helper did not complete its request"));
    }
    match status {
        0 => Ok(Some(output)),
        NOT_FOUND => Ok(None),
        -128 | -25293 | -25308 => Err(error("macOS did not authorize this request. Existing credentials are preserved. Allow Lunport Credential Helper when macOS asks, then retry")),
        other => Err(error(format!("Keychain request failed (OSStatus {other})"))),
    }
}

pub(super) fn get(account: &str) -> Result<Option<String>, AppError> {
    request(Operation::Get, account, &[], false)?
        .map(|value| {
            std::str::from_utf8(&value)
                .map(str::to_owned)
                .map_err(|_| error("stored credential is not UTF-8"))
        })
        .transpose()
}

pub(super) fn set(account: &str, secret: &str) -> Result<(), AppError> {
    request(Operation::Set, account, secret.as_bytes(), false).map(|_| ())
}

pub(super) fn delete(account: &str) -> Result<(), AppError> {
    request(Operation::Delete, account, &[], false).map(|_| ())
}

pub(super) fn get_noninteractive(account: &str) -> Result<Option<String>, AppError> {
    request(Operation::Get, account, &[], true)?
        .map(|bytes| {
            std::str::from_utf8(&bytes)
                .map(str::to_owned)
                .map_err(|_| error("stored credential is not UTF-8"))
        })
        .transpose()
}
pub(super) fn set_noninteractive(account: &str, secret: &str) -> Result<(), AppError> {
    request(Operation::Set, account, secret.as_bytes(), true).map(|_| ())
}
#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;

    #[test]
    fn ordinary_update_keeps_same_helper_inode_and_restores_missing_or_corrupt_bytes() {
        let temp = tempfile::tempdir_in("/private/tmp").unwrap();
        let first = install(temp.path(), b"frozen signed fixture").unwrap();
        let before = fs::metadata(&first).unwrap();
        assert_eq!(
            install(temp.path(), b"frozen signed fixture").unwrap(),
            first
        );
        let after = fs::metadata(&first).unwrap();
        assert_eq!(
            (before.ino(), before.mtime(), before.mtime_nsec()),
            (after.ino(), after.mtime(), after.mtime_nsec())
        );
        fs::write(&first, b"corrupt").unwrap();
        assert_eq!(
            fs::read(install(temp.path(), b"frozen signed fixture").unwrap()).unwrap(),
            b"frozen signed fixture"
        );
        fs::remove_file(&first).unwrap();
        assert_eq!(
            fs::read(install(temp.path(), b"frozen signed fixture").unwrap()).unwrap(),
            b"frozen signed fixture"
        );
    }

    #[test]
    fn unsafe_installations_preserve_symlink_targets_and_reject_shared_directories() {
        let temp = tempfile::tempdir_in("/private/tmp").unwrap();
        let target = install(temp.path(), b"trusted").unwrap();
        let other = temp.path().join("other");
        fs::write(&other, b"sentinel").unwrap();
        fs::remove_file(&target).unwrap();
        symlink(&other, &target).unwrap();
        assert!(install(temp.path(), b"trusted").is_err());
        assert_eq!(fs::read(&other).unwrap(), b"sentinel");
        fs::remove_file(&target).unwrap();
        fs::set_permissions(target.parent().unwrap(), fs::Permissions::from_mode(0o777)).unwrap();
        assert!(install(temp.path(), b"trusted").is_err());
    }

    #[test]
    fn malformed_requests_fail_before_creating_a_channel_or_installation() {
        assert!(validate_input(Operation::Get, "", &[]).is_err());
        assert!(validate_input(Operation::Set, "a\0b", b"private").is_err());
        assert!(validate_input(Operation::Get, "account", b"private").is_err());
        assert!(validate_input(Operation::Set, "account", &vec![0; MAX_SECRET + 1]).is_err());
        assert!(validate_input(Operation::Set, "account", b"").is_ok());
    }

    #[test]
    fn frozen_artifact_manifest_rejects_changed_bytes() {
        let bytes = include_bytes!("../signing/credential-helper-v1.bin");
        let manifest = include_str!("../signing/credential-helper-v1.json");
        assert!(artifact_identity(bytes, manifest).is_ok());
        assert!(artifact_identity(b"replaced executable", manifest).is_err());
    }

    /// Only the disposable CI runner signs this test binary as the production
    /// client. It never runs on a user's login keychain or changes an item ACL.
    #[test]
    #[ignore = "requires a disposable macOS runner and pinned signed test executable"]
    fn native_frozen_transport_probe() {
        assert_eq!(std::env::var("GITHUB_ACTIONS").as_deref(), Ok("true"));
        assert_eq!(std::env::var("RUNNER_OS").as_deref(), Ok("macOS"));
        let run = std::env::var("GITHUB_RUN_ID").unwrap();
        assert!(!run.is_empty() && run.bytes().all(|b| b.is_ascii_digit()));
        let account = format!("lunport-ci-helper-rust-{run}");
        let bytes = include_bytes!("../signing/credential-helper-v1.bin");
        let requirement =
            artifact_identity(bytes, include_str!("../signing/credential-helper-v1.json")).unwrap();
        let temp = tempfile::tempdir_in("/private/tmp").unwrap();
        let executable = install(temp.path(), bytes).unwrap();
        struct Cleanup<'a>(&'a Path, &'a str, &'a str);
        impl Drop for Cleanup<'_> {
            fn drop(&mut self) {
                let _ = exchange(self.0, self.1, Operation::Delete, self.2, &[], true);
            }
        }
        let _cleanup = Cleanup(&executable, &requirement, &account);
        let send = |operation, value: &[u8]| {
            exchange(&executable, &requirement, operation, &account, value, true).unwrap()
        };
        assert!(send(Operation::Get, &[]).is_none());
        send(Operation::Set, b"public-frozen-rust-fixture");
        assert_eq!(
            send(Operation::Get, &[]).unwrap().as_slice(),
            b"public-frozen-rust-fixture"
        );
        let inode = fs::metadata(&executable).unwrap().ino();
        install(temp.path(), bytes).unwrap();
        assert_eq!(fs::metadata(&executable).unwrap().ino(), inode);
        // Recovery retains the exact same Keychain owner and item contents.
        fs::remove_file(&executable).unwrap();
        install(temp.path(), bytes).unwrap();
        assert_eq!(
            send(Operation::Get, &[]).unwrap().as_slice(),
            b"public-frozen-rust-fixture"
        );
        fs::write(&executable, b"corrupt frozen helper").unwrap();
        install(temp.path(), bytes).unwrap();
        assert_eq!(
            send(Operation::Get, &[]).unwrap().as_slice(),
            b"public-frozen-rust-fixture"
        );
        send(Operation::Set, b"public-replacement-fixture");
        assert_eq!(
            send(Operation::Get, &[]).unwrap().as_slice(),
            b"public-replacement-fixture"
        );
        send(Operation::Delete, &[]);
        send(Operation::Delete, &[]);
        assert!(send(Operation::Get, &[]).is_none());
    }
}
