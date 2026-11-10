//! How the app installs a frozen credential program and talks to it. Each program is installed from bytes that must be the ones its
//! spec pins, into a private folder of its own under the data root, and started with nothing but a private channel as stdin and
//! stdout. The live process greets first; only once its greeting and its code signature match the spec does the app send it one
//! request, and the process answers that one request and exits.
use super::{checked, error, HelperSpec, Operation};
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

pub(super) const MAX_ACCOUNT: usize = 4096;
pub(super) const MAX_SECRET: usize = 1024 * 1024;

extern "C" {
    fn lunport_validate_credential_peer(
        fd: i32,
        expected_pid: i32,
        required: *const std::ffi::c_char,
    ) -> i32;
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

/// Installs `bytes` as the program `spec` pins, at its path under `root`, and returns where it is. Bytes that are not that program
/// (another SHA-256) are refused before anything is created.
pub(crate) fn install(root: &Path, spec: &HelperSpec, bytes: &[u8]) -> io::Result<PathBuf> {
    checked(spec, bytes)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "these bytes are not the pinned credential program"))?;
    place(root, spec.path(), bytes)
}

// Existing correct bytes are never rewritten. Missing/corrupt regular files can
// be restored from the signed App; symlinks and unsafe directories fail closed.
// Every program has a private folder of its own (`HelperSpec::path`).
fn place(root: &Path, path: &str, bytes: &[u8]) -> io::Result<PathBuf> {
    for ancestor in root.ancestors() {
        check_directory(ancestor, false)?;
    }
    let (folders, name) = path.rsplit_once('/').ok_or_else(unsafe_path)?;
    let mut directory = root.to_path_buf();
    for folder in folders.split('/') {
        directory.push(folder);
        match fs::DirBuilder::new().mode(0o700).create(&directory) {
            Ok(()) => (),
            Err(err) if err.kind() == io::ErrorKind::AlreadyExists => (),
            Err(err) => return Err(err),
        }
        check_directory(&directory, true)?;
    }
    let target = directory.join(name);
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

/// A started program, stopped and reaped when dropped.
pub(super) struct Running(pub(super) Child);
impl Drop for Running {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// Sends one request to the program `spec` pins, installed from `bytes` in this profile's data root.
pub(super) fn request(
    spec: &HelperSpec,
    bytes: &[u8],
    operation: Operation,
    account: &str,
    secret: &[u8],
    no_ui: bool,
) -> Result<Response, AppError> {
    // A malformed request touches nothing, not even the data root.
    validate_input(operation, account, secret).map_err(error)?;
    let root = crate::fsutil::app_data_root()?;
    crate::fsutil::ensure_dir_secure(&root)?;
    let executable = install(&root, spec, bytes).map_err(|_| {
        error("cannot safely install the helper; check this device's application-data permissions")
    })?;
    exchange(&executable, spec, operation, account, secret, no_ui)
}

pub(super) fn validate_input(operation: Operation, account: &str, secret: &[u8]) -> io::Result<()> {
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

/// What a program answered: its Keychain status (an OSStatus) and, for a successful get, the data.
pub(crate) struct Response {
    pub status: i32,
    pub data: Zeroizing<Vec<u8>>,
}

// Never the data: it may be a secret.
impl std::fmt::Debug for Response {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Response")
            .field("status", &self.status)
            .field("length", &self.data.len())
            .finish()
    }
}

/// A program the app started: its process and the app's end of the private channel.
pub(super) struct Started {
    pub(super) child: Running,
    pub(super) socket: UnixStream,
}

/// Why a program could not be started.
#[derive(Debug)]
pub(super) enum StartFailure {
    /// The private channel could not be made.
    Channel,
    /// The program could not be started.
    Spawn,
}

/// Starts `executable` with an empty environment, one end of a private channel as stdin and stdout, and nothing else. Each read on the
/// channel waits at most `answer`, each write at most 5 seconds.
pub(super) fn start(executable: &Path, answer: Duration) -> Result<Started, StartFailure> {
    let (socket, child_socket) =
        crate::process::without_spawns(UnixStream::pair).map_err(|_| StartFailure::Channel)?;
    socket.set_read_timeout(Some(answer)).map_err(|_| StartFailure::Channel)?;
    socket.set_write_timeout(Some(Duration::from_secs(5))).map_err(|_| StartFailure::Channel)?;
    let child_output: OwnedFd = child_socket.try_clone().map_err(|_| StartFailure::Channel)?.into();
    let child_input: OwnedFd = child_socket.into();
    let mut command = Command::new(executable);
    command
        .env_clear()
        .stdin(Stdio::from(child_input))
        .stdout(Stdio::from(child_output))
        .stderr(Stdio::null());
    let child = Running(crate::process::spawn(&mut command).map_err(|_| StartFailure::Spawn)?);
    // Command retains its Stdio handles after spawn; release them for EOF.
    drop(command);
    Ok(Started { child, socket })
}

/// Why a started program is not sent anything.
#[derive(Debug, PartialEq, Eq)]
pub(super) enum Greeting {
    /// It sent no complete greeting: it refused this app as its parent, or stopped.
    Silent,
    /// It greeted as another program, or the live process is not the one `spec` pins.
    NotPinned,
}

/// Reads the greeting of `started`, then checks that the live process is the program `spec` pins: its greeting, and its code
/// signature against the spec's requirement.
pub(super) fn greet(started: &mut Started, spec: &HelperSpec) -> Result<(), Greeting> {
    let mut hello = [0u8; 8];
    started.socket.read_exact(&mut hello).map_err(|_| Greeting::Silent)?;
    let required = std::ffi::CString::new(spec.requirement()).map_err(|_| Greeting::NotPinned)?;
    // A greeting meant for another program fails before the code-signing check.
    if &hello != spec.magic()
        || unsafe {
            lunport_validate_credential_peer(started.socket.as_raw_fd(), started.child.0.id() as i32, required.as_ptr())
        } != 1
    {
        return Err(Greeting::NotPinned);
    }
    Ok(())
}

/// Starts the installed program `executable`, checks that the live process is the one `spec` pins, and only then sends it one
/// request and reads its response. A malformed request starts nothing.
pub(crate) fn exchange(
    executable: &Path,
    spec: &HelperSpec,
    operation: Operation,
    account: &str,
    secret: &[u8],
    no_ui: bool,
) -> Result<Response, AppError> {
    validate_input(operation, account, secret).map_err(error)?;
    if operation == Operation::Adopt && spec.version() < 2 {
        return Err(error("this program has no adopt operation; nothing was sent"));
    }
    let answer = Duration::from_secs(if no_ui { 10 } else { 305 });
    let mut started = start(executable, answer).map_err(|failure| match failure {
        StartFailure::Channel => error("cannot create private channel"),
        StartFailure::Spawn => error("cannot start the signed helper"),
    })?;
    greet(&mut started, spec).map_err(|greeting| match greeting {
        Greeting::Silent => error("helper authentication failed; no credentials were sent"),
        Greeting::NotPinned => error("helper identity did not match the frozen artifact; no credentials were sent"),
    })?;
    send(&mut started.socket, spec.magic(), operation, account, secret, no_ui)?;
    let response = receive(&mut started.socket, operation)?;
    if !started.child.0.wait().map_err(error)?.success() {
        return Err(error("helper did not complete its request"));
    }
    Ok(response)
}

/// A request frame's header: the program's magic, the operation, the flags (1 forbids authorization UI), then the lengths of the
/// account and of the data, big-endian (`validate_input` bounds both).
pub(super) fn header(magic: &[u8; 8], operation: Operation, no_ui: bool, account: usize, data: usize) -> [u8; 18] {
    let mut header = [0u8; 18];
    header[..8].copy_from_slice(magic);
    header[8] = operation as u8;
    header[9] = u8::from(no_ui);
    header[10..14].copy_from_slice(&(account as u32).to_be_bytes());
    header[14..18].copy_from_slice(&(data as u32).to_be_bytes());
    header
}

/// Writes one request frame, then closes the writing side, which tells the program the frame is complete.
fn send(
    socket: &mut UnixStream,
    magic: &[u8; 8],
    operation: Operation,
    account: &str,
    secret: &[u8],
    no_ui: bool,
) -> Result<(), AppError> {
    socket
        .write_all(&header(magic, operation, no_ui, account.len(), secret.len()))
        .and_then(|_| socket.write_all(account.as_bytes()))
        .and_then(|_| socket.write_all(secret))
        .map_err(|_| error("request channel closed"))?;
    socket.shutdown(std::net::Shutdown::Write).map_err(error)
}

/// Reads the one response: status, length and data, with nothing after it. Data comes only with a successful get and never
/// exceeds 1 MiB.
pub(super) fn receive(socket: &mut UnixStream, operation: Operation) -> Result<Response, AppError> {
    let mut header = [0u8; 8];
    socket
        .read_exact(&mut header)
        .map_err(|_| error("request was cancelled, timed out or the helper stopped"))?;
    let status = i32::from_be_bytes(header[..4].try_into().unwrap());
    let length = u32::from_be_bytes(header[4..].try_into().unwrap()) as usize;
    if length > MAX_SECRET
        || (status != 0 && length != 0)
        || (operation != Operation::Get && length != 0)
    {
        return Err(error("invalid helper response"));
    }
    let mut data = Zeroizing::new(vec![0u8; length]);
    socket
        .read_exact(&mut data)
        .map_err(|_| error("incomplete helper response"))?;
    let mut trailing = [0u8; 1];
    if socket.read(&mut trailing).map_err(error)? != 0 {
        return Err(error("helper did not complete its request"));
    }
    Ok(Response { status, data })
}

#[cfg(test)]
mod tests {
    use super::super::{bridge, helper_v1, helper_v2};
    use super::*;
    use std::os::unix::fs::symlink;

    // Bytes that stand in for a frozen program.
    const FIXTURE: &[u8] = b"frozen signed fixture";

    #[test]
    fn ordinary_update_keeps_same_helper_inode_and_restores_missing_or_corrupt_bytes() {
        let temp = tempfile::tempdir_in("/private/tmp").unwrap();
        let path = helper_v2().path();
        let first = place(temp.path(), path, FIXTURE).unwrap();
        let before = fs::metadata(&first).unwrap();
        assert_eq!(place(temp.path(), path, FIXTURE).unwrap(), first);
        let after = fs::metadata(&first).unwrap();
        assert_eq!(
            (before.ino(), before.mtime(), before.mtime_nsec()),
            (after.ino(), after.mtime(), after.mtime_nsec())
        );
        fs::write(&first, b"corrupt").unwrap();
        assert_eq!(fs::read(place(temp.path(), path, FIXTURE).unwrap()).unwrap(), FIXTURE);
        fs::remove_file(&first).unwrap();
        assert_eq!(fs::read(place(temp.path(), path, FIXTURE).unwrap()).unwrap(), FIXTURE);
    }

    #[test]
    fn unsafe_installations_preserve_symlink_targets_and_reject_shared_directories() {
        let temp = tempfile::tempdir_in("/private/tmp").unwrap();
        let path = helper_v2().path();
        let target = place(temp.path(), path, b"trusted").unwrap();
        let other = temp.path().join("other");
        fs::write(&other, b"sentinel").unwrap();
        fs::remove_file(&target).unwrap();
        symlink(&other, &target).unwrap();
        assert!(place(temp.path(), path, b"trusted").is_err());
        assert_eq!(fs::read(&other).unwrap(), b"sentinel");
        fs::remove_file(&target).unwrap();
        fs::set_permissions(target.parent().unwrap(), fs::Permissions::from_mode(0o777)).unwrap();
        assert!(place(temp.path(), path, b"trusted").is_err());
    }

    /// Only the program a spec pins is installed for it: other bytes are refused before a folder or a file is created.
    #[test]
    fn only_the_pinned_program_is_installed() {
        let temp = tempfile::tempdir_in("/private/tmp").unwrap();
        for spec in [helper_v1(), helper_v2(), bridge()] {
            let failure = install(temp.path(), &spec, FIXTURE).unwrap_err();
            assert_eq!(failure.kind(), io::ErrorKind::InvalidData, "{}", spec.path());
        }
        assert!(!temp.path().join("credential-helper").exists(), "nothing was created");
        let v1 = include_bytes!("../signing/legacy/credential-helper-v1.bin");
        let installed = install(temp.path(), &helper_v1(), v1).unwrap();
        assert_eq!((installed.clone(), fs::read(&installed).unwrap()), (temp.path().join(helper_v1().path()), v1.to_vec()));
        // The bytes of one program are not another's.
        assert!(install(temp.path(), &bridge(), v1).is_err());
    }

    /// Helper v1 stays where versions before 2.0.0 installed it, so the copy already on a computer is the one the migration uses,
    /// and helper v2 and the bridge get folders of their own: installing one never touches another.
    #[test]
    fn each_program_is_installed_in_a_folder_of_its_own() {
        let temp = tempfile::tempdir_in("/private/tmp").unwrap();
        let v1 = place(temp.path(), helper_v1().path(), b"helper v1 fixture").unwrap();
        assert_eq!(v1, temp.path().join("credential-helper").join("v1").join("Lunport Credential Helper"));
        let before = fs::metadata(&v1).unwrap();
        let v2 = place(temp.path(), helper_v2().path(), b"helper v2 fixture").unwrap();
        assert_eq!(v2, temp.path().join("credential-helper").join("v2").join("Lunport Credential Helper"));
        let relay = place(temp.path(), bridge().path(), b"bridge fixture").unwrap();
        assert_eq!(relay, temp.path().join("credential-helper").join("bridge").join("Lunport Credential Bridge"));
        let after = fs::metadata(&v1).unwrap();
        assert_eq!((before.ino(), before.mtime_nsec()), (after.ino(), after.mtime_nsec()));
        assert_eq!(fs::read(&v1).unwrap(), b"helper v1 fixture");
        assert_eq!(fs::read(&v2).unwrap(), b"helper v2 fixture");
        for folder in ["credential-helper", "credential-helper/v1", "credential-helper/v2", "credential-helper/bridge"] {
            assert_eq!(fs::metadata(temp.path().join(folder)).unwrap().mode() & 0o777, 0o700, "{folder}");
        }
        // Every program lives in its own folder under credential-helper, named by a plain file name.
        let specs = [helper_v1(), helper_v2(), bridge()];
        for spec in &specs {
            let parts: Vec<&str> = spec.path().split('/').collect();
            assert!(
                parts.len() == 3
                    && parts[0] == "credential-helper"
                    && parts[1..].iter().all(|part| !part.is_empty() && *part != "." && *part != ".."),
                "{}",
                spec.path()
            );
        }
        let folders: std::collections::HashSet<&str> = specs.iter().map(|spec| spec.path().rsplit_once('/').unwrap().0).collect();
        assert_eq!(folders.len(), specs.len(), "no two programs share a folder");
    }

    #[test]
    fn malformed_requests_fail_before_creating_a_channel_or_installation() {
        assert!(validate_input(Operation::Get, "", &[]).is_err());
        assert!(validate_input(Operation::Set, "a\0b", b"private").is_err());
        assert!(validate_input(Operation::Get, "account", b"private").is_err());
        assert!(validate_input(Operation::Set, "account", &vec![0; MAX_SECRET + 1]).is_err());
        assert!(validate_input(Operation::Set, "account", b"").is_ok());
        assert!(validate_input(Operation::Get, &"a".repeat(MAX_ACCOUNT + 1), &[]).is_err());
    }

    #[test]
    fn a_request_header_is_the_magic_operation_flags_and_big_endian_lengths() {
        let set = header(b"LPKC0002", Operation::Set, false, 7, 300);
        assert_eq!(&set[..8], b"LPKC0002");
        assert_eq!(set[8..10], [2, 0]);
        assert_eq!(set[10..14], 7u32.to_be_bytes());
        assert_eq!(set[14..18], 300u32.to_be_bytes());
        assert_eq!(header(b"LPKC0001", Operation::Get, true, 1, 0)[..10], *b"LPKC0001\x01\x01");
        assert_eq!(header(b"LPKC0001", Operation::Delete, true, 1, 0)[8], 3);
    }

    #[test]
    fn an_adopt_request_is_operation_5_without_data() {
        assert_eq!(
            header(helper_v2().magic(), Operation::Adopt, true, "host:web".len(), 0),
            *b"LPKC0002\x05\x01\x00\x00\x00\x08\x00\x00\x00\x00"
        );
        assert!(validate_input(Operation::Adopt, "host:web", b"").is_ok());
        assert!(validate_input(Operation::Adopt, "host:web", b"private").is_err());
        assert!(validate_input(Operation::Adopt, "", b"").is_err());
        assert!(validate_input(Operation::Adopt, "a\0b", b"").is_err());
    }

    /// What goes over the channel after the helper was authenticated: exactly one frame, then the writing side closes.
    #[test]
    fn a_request_is_one_frame_and_then_the_end_of_writing() {
        let (mut ours, mut theirs) = UnixStream::pair().unwrap();
        send(&mut ours, helper_v2().magic(), Operation::Adopt, "host:web", &[], true).unwrap();
        let mut received = Vec::new();
        theirs.read_to_end(&mut received).unwrap();
        assert_eq!(received, b"LPKC0002\x05\x01\x00\x00\x00\x08\x00\x00\x00\x00host:web");

        let (mut ours, mut theirs) = UnixStream::pair().unwrap();
        send(&mut ours, helper_v1().magic(), Operation::Set, "vault:key", b"public-fixture", false).unwrap();
        let mut received = Vec::new();
        theirs.read_to_end(&mut received).unwrap();
        assert_eq!(&received[..18], header(b"LPKC0001", Operation::Set, false, 9, 14));
        assert_eq!(&received[18..], b"vault:keypublic-fixture");
    }

    fn answered(response: &[u8]) -> UnixStream {
        let (mut theirs, ours) = UnixStream::pair().unwrap();
        theirs.write_all(response).unwrap();
        drop(theirs);
        ours
    }

    #[test]
    fn a_response_carries_data_only_for_a_successful_get() {
        let frame = |status: i32, length: u32, data: &[u8]| [&status.to_be_bytes()[..], &length.to_be_bytes(), data].concat();
        let get = receive(&mut answered(&frame(0, 4, b"data")), Operation::Get).unwrap();
        assert_eq!((get.status, get.data.as_slice()), (0, &b"data"[..]));
        let adopted = receive(&mut answered(&frame(0, 0, b"")), Operation::Adopt).unwrap();
        assert_eq!((adopted.status, adopted.data.len()), (0, 0));
        let conflict = receive(&mut answered(&frame(-25299, 0, b"")), Operation::Adopt).unwrap();
        assert_eq!(conflict.status, -25299);
        // Adopt never returns the secret, and no failure carries data.
        assert!(receive(&mut answered(&frame(0, 4, b"data")), Operation::Adopt).is_err());
        assert!(receive(&mut answered(&frame(-25300, 4, b"data")), Operation::Get).is_err());
        assert!(receive(&mut answered(&frame(0, MAX_SECRET as u32 + 1, b"")), Operation::Get).is_err());
        // Truncated, or followed by anything: not a response.
        assert!(receive(&mut answered(&frame(0, 4, b"da")), Operation::Get).is_err());
        assert!(receive(&mut answered(&frame(0, 0, b"!")), Operation::Delete).is_err());
        assert!(receive(&mut answered(&[0, 0]), Operation::Delete).is_err());
    }

    // A stand-in for a frozen program: a script that greets with `hello` and keeps what it is sent in `received`.
    fn stand_in(directory: &Path, hello: &[u8; 8], received: &Path) -> PathBuf {
        let script = directory.join(format!("stand-in-{}", std::str::from_utf8(hello).unwrap()));
        let text = format!(
            "#!/bin/sh\nprintf '%s' '{}'\nexec /bin/cat > '{}'\n",
            std::str::from_utf8(hello).unwrap(),
            received.display()
        );
        fs::write(&script, text).unwrap();
        fs::set_permissions(&script, fs::Permissions::from_mode(0o700)).unwrap();
        script
    }

    /// Each program greets with its own magic, so a program started for one spec that answers as another is sent nothing.
    #[test]
    fn a_greeting_meant_for_another_program_is_sent_nothing() {
        let temp = tempfile::tempdir_in("/private/tmp").unwrap();
        let specs = [helper_v1(), helper_v2(), bridge()];
        let magics: std::collections::HashSet<&[u8; 8]> = specs.iter().map(|spec| spec.magic()).collect();
        assert_eq!(magics.len(), specs.len(), "every program has its own magic");
        for spec in &specs {
            for other in specs.iter().filter(|other| other.magic() != spec.magic()) {
                let received = temp.path().join("received");
                let _ = fs::remove_file(&received);
                let program = stand_in(temp.path(), other.magic(), &received);
                let failure = exchange(&program, spec, Operation::Get, "acme-account", &[], true).unwrap_err();
                assert!(failure.to_string().contains("no credentials were sent"), "{failure}");
                assert_eq!(fs::read(&received).unwrap_or_default(), b"", "nothing reaches a program that greets as another");
            }
        }
    }

    /// The right magic is not enough: a program that is not the pinned one is sent nothing either.
    #[test]
    fn a_program_that_fails_its_pin_is_sent_nothing() {
        let temp = tempfile::tempdir_in("/private/tmp").unwrap();
        let received = temp.path().join("received");
        let spec = helper_v2();
        let program = stand_in(temp.path(), spec.magic(), &received);
        let failure = exchange(&program, &spec, Operation::Set, "acme-account", b"public-fixture", true).unwrap_err();
        assert!(failure.to_string().contains("no credentials were sent"), "{failure}");
        assert_eq!(fs::read(&received).unwrap_or_default(), b"");
    }

    /// A malformed request starts nothing, whoever asks for it.
    #[test]
    fn a_malformed_request_starts_nothing() {
        let temp = tempfile::tempdir_in("/private/tmp").unwrap();
        let received = temp.path().join("received");
        let spec = helper_v2();
        let program = stand_in(temp.path(), spec.magic(), &received);
        for (operation, account, secret) in [
            (Operation::Get, "", &b""[..]),
            (Operation::Get, "a\0b", b""),
            (Operation::Delete, "acme-account", b"private"),
            (Operation::Adopt, "acme-account", b"private"),
        ] {
            let failure = exchange(&program, &spec, operation, account, secret, true).unwrap_err();
            assert!(failure.to_string().contains("invalid credential request"), "{failure}");
            assert!(!received.exists(), "the program was not even started");
        }
    }

    /// Adopt exists from protocol 2: a request for it never reaches helper v1 or the bridge.
    #[test]
    fn adopt_goes_only_to_a_protocol_2_program() {
        let temp = tempfile::tempdir_in("/private/tmp").unwrap();
        let received = temp.path().join("received");
        for spec in [helper_v1(), bridge()] {
            let program = stand_in(temp.path(), spec.magic(), &received);
            let failure = exchange(&program, &spec, Operation::Adopt, "acme-account", &[], true).unwrap_err();
            assert!(failure.to_string().contains("no adopt operation"), "{failure}");
            assert!(!received.exists(), "the program was not even started");
        }
    }
}
