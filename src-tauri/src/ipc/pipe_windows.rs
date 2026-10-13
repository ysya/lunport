//! The local IPC endpoint on Windows: a named pipe per role, `\\.\pipe\sshelter-<role>-<the first 16 hex digits of the SHA-256 of the
//! user's SID string>` (the key vault's `sshelter-agent-…`, its spec §4.4 and §5.1; the session broker's `sshelter-session-…`, own-ssh
//! spec §4). Every instance's DACL grants the current user alone and remote clients are refused; the first instance carries
//! `FILE_FLAG_FIRST_PIPE_INSTANCE`, so a name another program holds is not served (spec §11; another SSHelter is stopped before that, by
//! `server::take_lock`). Only std and windows-sys.
//!
//! Both ends of a connection are a `PipeStream`, and its handle is in overlapped mode. A handle in synchronous mode serializes all I/O on
//! it across threads (`NtCreateFile`, `FILE_SYNCHRONOUS_IO_NONALERT`): a thread waiting in a read would hold up the thread that writes,
//! and the broker reads its client on one thread while the session writes to it from another. Every call of the stream still blocks
//! until its I/O is over.

use std::ffi::c_void;
use std::io::{self, Read, Write};
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use std::path::Path;
use std::ptr;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use sha2::{Digest, Sha256};
use windows_sys::core::BOOL;
use windows_sys::Win32::Foundation::{
    LocalFree, ERROR_ACCESS_DENIED, ERROR_BROKEN_PIPE, ERROR_FILE_NOT_FOUND, ERROR_IO_PENDING, ERROR_PIPE_BUSY, ERROR_PIPE_CONNECTED,
    ERROR_SEM_TIMEOUT, ERROR_SUCCESS, FALSE, GENERIC_READ, GENERIC_WRITE, HANDLE, INVALID_HANDLE_VALUE, TRUE, WAIT_OBJECT_0,
};
use windows_sys::Win32::Security::Authorization::{
    ConvertSidToStringSidW, GetSecurityInfo, SetEntriesInAclW, EXPLICIT_ACCESS_W, NO_MULTIPLE_TRUSTEE, SET_ACCESS, SE_KERNEL_OBJECT,
    TRUSTEE_IS_SID, TRUSTEE_IS_USER, TRUSTEE_W,
};
use windows_sys::Win32::Security::{
    GetLengthSid, InitializeSecurityDescriptor, IsValidSid, SetSecurityDescriptorDacl, SetSecurityDescriptorOwner, ACL, NO_INHERITANCE,
    OWNER_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID, SECURITY_ATTRIBUTES, SECURITY_DESCRIPTOR, TOKEN_USER,
};
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, ReadFile, WriteFile, FILE_ALL_ACCESS, FILE_FLAG_FIRST_PIPE_INSTANCE, FILE_FLAG_OVERLAPPED, OPEN_EXISTING, PIPE_ACCESS_DUPLEX,
    SECURITY_IDENTIFICATION, SECURITY_SQOS_PRESENT,
};
use windows_sys::Win32::System::Pipes::{
    ConnectNamedPipe, CreateNamedPipeW, GetNamedPipeClientProcessId, WaitNamedPipeW, PIPE_READMODE_BYTE, PIPE_REJECT_REMOTE_CLIENTS,
    PIPE_TYPE_BYTE, PIPE_UNLIMITED_INSTANCES, PIPE_WAIT,
};
use windows_sys::Win32::System::SystemServices::SECURITY_DESCRIPTOR_REVISION;
use windows_sys::Win32::System::Threading::{
    CancelWaitableTimer, CreateEventW, CreateWaitableTimerW, SetEvent, SetWaitableTimer, WaitForMultipleObjects, WaitForSingleObject, INFINITE,
};
use windows_sys::Win32::System::IO::{CancelIoEx, GetOverlappedResult, OVERLAPPED};

use crate::error::AppError;
use crate::ipc::server::{dispatch, take_lock, Handler, Started};
use crate::sync::slot_files_windows::current_user_token;

/// The SECURITY_ATTRIBUTES every pipe instance shares: owned by the current user, with a DACL of one ACE, "the current user: full
/// control". The owner is named explicitly: an elevated administrator's objects are otherwise owned by the Administrators group (the
/// token's default owner), and `connect` takes only a pipe the user owns. `SetEntriesInAclW` copies the SID into the ACE, but the
/// descriptor only points to its owner, so the `TOKEN_USER` that holds the SID stays with it.
struct OwnerOnly {
    acl: *mut ACL,
    _descriptor: Box<SECURITY_DESCRIPTOR>,
    /// The `TOKEN_USER` whose SID is the descriptor's owner.
    _user: Vec<u64>,
    attributes: SECURITY_ATTRIBUTES,
}

// 指標只指向這個結構自己擁有的記憶體(LocalAlloc 的 ACL、Box 的描述元、`_user` 裡的 SID);整個結構一起搬到 listener 的執行緒,只在那裡使用。
unsafe impl Send for OwnerOnly {}

impl Drop for OwnerOnly {
    fn drop(&mut self) {
        // SAFETY: `acl` came from SetEntriesInAclW (LocalAlloc) and is freed once.
        unsafe { LocalFree(self.acl as *mut c_void) };
    }
}

impl OwnerOnly {
    fn new() -> io::Result<Self> {
        let token = current_user_token()?;
        // SAFETY: `token` holds an 8-byte aligned TOKEN_USER whose SID points into `token`'s heap buffer, which the result keeps (moving
        // the Vec does not move the buffer); SetEntriesInAclW copies the SID into the ACE, the descriptor's owner points to it.
        unsafe {
            let user = &*(token.as_ptr() as *const TOKEN_USER);
            let access = EXPLICIT_ACCESS_W {
                grfAccessPermissions: FILE_ALL_ACCESS,
                grfAccessMode: SET_ACCESS,
                grfInheritance: NO_INHERITANCE,
                Trustee: TRUSTEE_W {
                    pMultipleTrustee: ptr::null_mut(),
                    MultipleTrusteeOperation: NO_MULTIPLE_TRUSTEE,
                    TrusteeForm: TRUSTEE_IS_SID,
                    TrusteeType: TRUSTEE_IS_USER,
                    ptstrName: user.User.Sid as *mut u16,
                },
            };
            let mut acl: *mut ACL = ptr::null_mut();
            let status = SetEntriesInAclW(1, &access, ptr::null(), &mut acl);
            if status != ERROR_SUCCESS {
                return Err(io::Error::from_raw_os_error(status as i32));
            }
            let mut descriptor: Box<SECURITY_DESCRIPTOR> = Box::new(std::mem::zeroed());
            let pointer = &mut *descriptor as *mut SECURITY_DESCRIPTOR as *mut c_void;
            if InitializeSecurityDescriptor(pointer, SECURITY_DESCRIPTOR_REVISION) == 0
                || SetSecurityDescriptorDacl(pointer, 1, acl, 0) == 0
                || SetSecurityDescriptorOwner(pointer, user.User.Sid, 0) == 0
            {
                let error = io::Error::last_os_error();
                LocalFree(acl as *mut c_void);
                return Err(error);
            }
            let attributes = SECURITY_ATTRIBUTES {
                nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
                lpSecurityDescriptor: pointer,
                bInheritHandle: 0,
            };
            Ok(Self { acl, _descriptor: descriptor, _user: token, attributes })
        }
    }
}

/// 目前使用者 SID 的字串(`S-1-5-21-…`)。
fn user_sid() -> io::Result<String> {
    let token = current_user_token()?;
    // SAFETY: as in `OwnerOnly::new`; ConvertSidToStringSidW returns a LocalAlloc'ed NUL-terminated string, freed here.
    unsafe {
        let user = &*(token.as_ptr() as *const TOKEN_USER);
        let mut text: *mut u16 = ptr::null_mut();
        if ConvertSidToStringSidW(user.User.Sid, &mut text) == 0 {
            return Err(io::Error::last_os_error());
        }
        let length = (0..).take_while(|&i| *text.add(i) != 0).count();
        let sid = String::from_utf16_lossy(std::slice::from_raw_parts(text, length));
        LocalFree(text as *mut c_void);
        Ok(sid)
    }
}

/// The pipe name of a role (`agent`, `session`): `sshelter-<role>-<the first 16 hex digits of the SHA-256 of the user's SID string>`
/// (key vault spec §4.4, own-ssh spec §4). The same every time for a user, and another user's is another name.
pub fn pipe_name_for(role: &str) -> io::Result<String> {
    let digest = Sha256::digest(user_sid()?.as_bytes());
    Ok(format!("sshelter-{role}-{}", digest.iter().take(8).map(|b| format!("{b:02x}")).collect::<String>()))
}

/// The bytes of a SID; `None` for a null or malformed one. Two SIDs are equal exactly when their bytes are (the fields `EqualSid`
/// compares, in a canonical layout).
///
/// # Safety
/// `sid` is null, or points to memory that holds a SID for the whole call.
unsafe fn sid_bytes(sid: PSID) -> Option<Vec<u8>> {
    if sid.is_null() {
        return None;
    }
    // SAFETY: the caller's promise; IsValidSid only reads the SID, and GetLengthSid gives the length of a valid one.
    unsafe {
        if IsValidSid(sid) == 0 {
            return None;
        }
        let length = GetLengthSid(sid) as usize;
        Some(std::slice::from_raw_parts(sid as *const u8, length).to_vec())
    }
}

/// The current user's SID, as bytes.
fn user_sid_bytes() -> io::Result<Vec<u8>> {
    let token = current_user_token()?;
    // SAFETY: as in `OwnerOnly::new`: `token` holds a TOKEN_USER whose SID points into `token`, which lives through the copy.
    let sid = unsafe { sid_bytes((*(token.as_ptr() as *const TOKEN_USER)).User.Sid) };
    sid.ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "the user's SID is not valid"))
}

/// The owner of the pipe that `pipe` is an end of, as bytes; `None` when it cannot be read. Reading it takes READ_CONTROL, which a
/// client that opened the pipe with GENERIC_READ holds: a pipe's FILE_GENERIC_READ includes reading its security descriptor.
fn pipe_owner(pipe: &OwnedHandle) -> Option<Vec<u8>> {
    let mut owner: PSID = ptr::null_mut();
    let mut descriptor: PSECURITY_DESCRIPTOR = ptr::null_mut();
    // SAFETY: a valid handle; on success the system allocates `descriptor` (freed below with LocalFree) and points `owner` into it.
    let status = unsafe {
        GetSecurityInfo(raw(pipe), SE_KERNEL_OBJECT, OWNER_SECURITY_INFORMATION, &mut owner, ptr::null_mut(), ptr::null_mut(), ptr::null_mut(), &mut descriptor)
    };
    if status != ERROR_SUCCESS {
        return None;
    }
    // SAFETY: `owner` points into `descriptor`, which is freed once, after the copy.
    unsafe {
        let owner = sid_bytes(owner);
        LocalFree(descriptor);
        owner
    }
}

/// Whether the user owns a pipe whose owner `connect` read (`None`: it could not be read). Only such a pipe is SSHelter's: `OwnerOnly`
/// makes the user the owner of SSHelter's pipes, and no other program can make the user the owner of its own (that takes the user's
/// token, or a privilege that already rules the computer).
fn served_by_user(owner: Option<&[u8]>, user: &[u8]) -> bool {
    owner == Some(user)
}

/// The role a pipe or listener name stands for, which names the pipe in messages: `agent` in `sshelter-agent` and
/// `sshelter-agent-<hex>`, `session` in `sshelter-session-<hex>`.
fn role_in(name: &str) -> &str {
    let rest = name.strip_prefix("sshelter-").unwrap_or(name);
    rest.split('-').next().unwrap_or(rest)
}

/// Why `connect` refused the pipe `name`: another program made it.
fn not_sshelters(name: &str) -> io::Error {
    io::Error::new(io::ErrorKind::PermissionDenied, format!(r"Another program is using SSHelter's {} pipe (\\.\pipe\{name})", role_in(name)))
}

fn wide_pipe_path(name: &str) -> Vec<u16> {
    format!(r"\\.\pipe\{name}").encode_utf16().chain(std::iter::once(0)).collect()
}

fn raw(handle: &OwnedHandle) -> HANDLE {
    handle.as_raw_handle() as HANDLE
}

/// Owns a handle a `Create…` function returned, which is null when it failed.
fn owned(handle: HANDLE) -> io::Result<OwnedHandle> {
    if handle.is_null() {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: a fresh, valid handle that nothing else owns.
    Ok(unsafe { OwnedHandle::from_raw_handle(handle as _) })
}

/// A manual-reset event, not signalled.
fn event() -> io::Result<OwnedHandle> {
    // SAFETY: no security attributes and no name; `owned` checks the result.
    owned(unsafe { CreateEventW(ptr::null(), TRUE, FALSE, ptr::null()) })
}

/// A manual-reset waitable timer, not set: once it is due it stays signalled until it is set again.
fn timer() -> io::Result<OwnedHandle> {
    // SAFETY: no security attributes and no name; `owned` checks the result.
    owned(unsafe { CreateWaitableTimerW(ptr::null(), TRUE, ptr::null()) })
}

/// What a write says once the stream has been hung up.
fn hung_up_error() -> io::Error {
    io::Error::new(io::ErrorKind::BrokenPipe, "the pipe was hung up")
}

/// One end of a connection on a pipe: the server's, which `listen` hands to the handler, or the client's, from `connect`. Reads and writes
/// block until they are over, and threads may read and write at the same time. Clones (`try_clone`) share the handle and its state: a
/// hang-up is the hang-up of every clone, and for good. The handle is closed when the last clone is dropped, and only then does the other
/// end read the end of the pipe.
pub struct PipeStream {
    shared: Arc<Shared>,
}

struct Shared {
    pipe: OwnedHandle,
    /// `hang_up` was called, or the deadline ran out.
    hung_up: AtomicBool,
    /// Signalled by `hang_up` and never reset. Every call waits on it next to its own I/O, so that a call which started its I/O just
    /// after the cancel of a hang-up (too late to be cancelled by it) returns as well.
    hang_up_event: OwnedHandle,
    /// The deadline of `hang_up_after`: a manual-reset waitable timer, signalled once it is due. Every call waits on it too.
    deadline: OwnedHandle,
}

impl PipeStream {
    /// Wraps a connected pipe handle that is in overlapped mode.
    fn new(pipe: OwnedHandle) -> io::Result<PipeStream> {
        let shared = Shared { pipe, hung_up: AtomicBool::new(false), hang_up_event: event()?, deadline: timer()? };
        Ok(PipeStream { shared: Arc::new(shared) })
    }

    /// Another handle on the same connection, sharing its state. (It cannot fail; it returns a `Result` as `UnixStream::try_clone` does.)
    pub fn try_clone(&self) -> io::Result<PipeStream> {
        Ok(PipeStream { shared: Arc::clone(&self.shared) })
    }

    /// Hangs the connection up for good (own-ssh spec §4): from now on every read returns the end of the stream (`Ok(0)`) and every write
    /// fails (`BrokenPipe`), and a read or a write that is waiting on the pipe, in any thread, returns now. The pipe is not disconnected
    /// (`DisconnectNamedPipe` throws away what the other end has not read yet, such as the last frames of a session): the other end reads
    /// what was written before the hang-up, and then the end of the pipe, once the last clone of this stream is dropped.
    pub fn hang_up(&self) {
        self.shared.hang_up();
    }

    /// `Some(after)`: the stream hangs up (`hang_up`) unless the deadline is cleared before `after` has passed. A read or a write that
    /// is waiting when the time is over returns then, and one made later finds the stream hung up; a deadline that ran out while nothing
    /// was waiting on the pipe has hung it up all the same. `None` clears the deadline; a new one replaces the one before. A pipe has no
    /// read timeout: the broker bounds with this how long a new connection may take for its first messages (spec §7.2).
    pub fn hang_up_after(&self, after: Option<Duration>) -> io::Result<()> {
        self.shared.hang_up_after(after)
    }

    /// Whether the stream has been hung up, by `hang_up` or by a deadline that ran out.
    #[cfg(test)]
    pub(crate) fn is_hung_up(&self) -> bool {
        self.shared.is_hung_up()
    }
}

impl Shared {
    fn hang_up(&self) {
        self.hung_up.store(true, Ordering::SeqCst);
        // SAFETY: a valid event handle.
        unsafe { SetEvent(raw(&self.hang_up_event)) };
        // SAFETY: a valid pipe handle; a null OVERLAPPED cancels all the I/O on it that this process started, from any thread (the
        // cancelled calls fail with ERROR_OPERATION_ABORTED). Each call waits for its I/O to be over before it returns (`transfer`).
        unsafe { CancelIoEx(raw(&self.pipe), ptr::null()) };
    }

    fn is_hung_up(&self) -> bool {
        if self.hung_up.load(Ordering::SeqCst) {
            return true;
        }
        // SAFETY: a valid timer handle; a wait of zero only looks at its state.
        let due = unsafe { WaitForSingleObject(raw(&self.deadline), 0) } == WAIT_OBJECT_0;
        if due {
            self.hang_up();
        }
        due
    }

    fn hang_up_after(&self, after: Option<Duration>) -> io::Result<()> {
        if after.is_some_and(|after| after.is_zero()) {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "a deadline of zero"));
        }
        // A deadline that ran out is a hang-up even if nothing noticed it: setting or cancelling the timer must not forget it.
        if self.is_hung_up() {
            return Ok(());
        }
        let deadline = raw(&self.deadline);
        match after {
            None => {
                // SAFETY: a valid timer handle.
                if unsafe { CancelWaitableTimer(deadline) } == 0 {
                    return Err(io::Error::last_os_error());
                }
                // It may have come due between the look above and the cancel, which leaves it signalled.
                self.is_hung_up();
            }
            Some(after) => {
                // A relative due time is negative, in units of 100 ns.
                let due = -i64::try_from(after.as_nanos().div_ceil(100)).unwrap_or(i64::MAX);
                // SAFETY: a valid timer handle; `due` lives through the call; no completion routine.
                if unsafe { SetWaitableTimer(deadline, &due, 0, None, ptr::null(), FALSE) } == 0 {
                    return Err(io::Error::last_os_error());
                }
            }
        }
        Ok(())
    }

    fn read(&self, buf: &mut [u8]) -> io::Result<usize> {
        if self.is_hung_up() || buf.is_empty() {
            return Ok(0);
        }
        let length = u32::try_from(buf.len()).unwrap_or(u32::MAX);
        // SAFETY: `buf` is valid for `length` bytes, and `transfer` returns only once the read is over.
        let read = self.transfer(|pipe, overlapped| unsafe { ReadFile(pipe, buf.as_mut_ptr(), length, ptr::null_mut(), overlapped) });
        match read {
            Ok(count) => Ok(count),
            // The other end closed the pipe: the end of the stream, as std reads a pipe.
            Err(error) if error.raw_os_error() == Some(ERROR_BROKEN_PIPE as i32) => Ok(0),
            // Cancelled by a hang-up (ERROR_OPERATION_ABORTED), or anything else once there was one: the end.
            Err(_) if self.hung_up.load(Ordering::SeqCst) => Ok(0),
            Err(error) => Err(error),
        }
    }

    fn write(&self, buf: &[u8]) -> io::Result<usize> {
        if self.is_hung_up() {
            return Err(hung_up_error());
        }
        if buf.is_empty() {
            return Ok(0);
        }
        let length = u32::try_from(buf.len()).unwrap_or(u32::MAX);
        // SAFETY: as in `read`.
        let written = self.transfer(|pipe, overlapped| unsafe { WriteFile(pipe, buf.as_ptr(), length, ptr::null_mut(), overlapped) });
        match written {
            Ok(count) => Ok(count),
            Err(_) if self.hung_up.load(Ordering::SeqCst) => Err(hung_up_error()),
            Err(error) => Err(error),
        }
    }

    /// Starts one overlapped read or write (`start`) and waits until it is over: done, or cancelled because the stream was hung up or
    /// its deadline ran out. Whichever it is, it returns only once the I/O is over, because until then the system may still write to the
    /// buffer and to the `OVERLAPPED`.
    fn transfer(&self, start: impl FnOnce(HANDLE, *mut OVERLAPPED) -> BOOL) -> io::Result<usize> {
        let pipe = raw(&self.pipe);
        let done = event()?;
        let mut overlapped = OVERLAPPED { hEvent: raw(&done), ..Default::default() };
        // Only through this pointer from here on: the system writes to the OVERLAPPED until the I/O is over.
        let overlapped: *mut OVERLAPPED = &mut overlapped;
        if start(pipe, overlapped) == 0 {
            let error = io::Error::last_os_error();
            if error.raw_os_error() != Some(ERROR_IO_PENDING as i32) {
                return Err(error);
            }
            let waits = [raw(&done), raw(&self.hang_up_event), raw(&self.deadline)];
            // SAFETY: three valid handles.
            let woke = unsafe { WaitForMultipleObjects(waits.len() as u32, waits.as_ptr(), FALSE, INFINITE) };
            if woke != WAIT_OBJECT_0 {
                if woke == WAIT_OBJECT_0 + 2 {
                    // The deadline ran out.
                    self.hang_up();
                }
                // Hung up, out of time, or the wait failed: the I/O is cancelled. It may have finished meanwhile; its result then stands.
                // SAFETY: cancels the one operation that uses `overlapped`, on the handle it was started on.
                unsafe { CancelIoEx(pipe, overlapped) };
            }
        }
        let mut count = 0u32;
        // SAFETY: the operation was started above with `overlapped`; waiting (TRUE) returns only once it is over.
        if unsafe { GetOverlappedResult(pipe, overlapped, &mut count, TRUE) } == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(count as usize)
    }
}

impl Read for &PipeStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.shared.read(buf)
    }
}

impl Read for PipeStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.shared.read(buf)
    }
}

impl Write for &PipeStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.shared.write(buf)
    }

    /// Nothing is buffered here: what was written is in the pipe. (Waiting until the other end has read it, `FlushFileBuffers`, is not
    /// what a flush of a stream is for.)
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl Write for PipeStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.shared.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl std::fmt::Debug for PipeStream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PipeStream").field("pipe", &self.shared.pipe).field("hung_up", &self.shared.hung_up.load(Ordering::SeqCst)).finish()
    }
}

/// Connects to `\\.\pipe\<name>` as a client. No pipe of that name: `NotFound`, at once (nobody serves it). Every instance busy (each one
/// serves a client, and the server has not made the next one yet): waits for one with `WaitNamedPipeW`, `busy_wait` in all, and then
/// `TimedOut`. A pipe the user does not own is not SSHelter's: `PermissionDenied` ("Another program is using SSHelter's … pipe"), and
/// nothing was written to it. The server is given the client's identity only, not a token it could act as.
// `sshelter connect` uses this from plan 1b-3 Task 3 on; until then only the tests do.
#[cfg_attr(not(test), allow(dead_code))]
pub fn connect(name: &str, busy_wait: Duration) -> io::Result<PipeStream> {
    let path = wide_pipe_path(name);
    let deadline = Instant::now().checked_add(busy_wait);
    let busy = || io::Error::new(io::ErrorKind::TimedOut, format!("every instance of the pipe {name} stayed busy"));
    loop {
        // SAFETY: `path` is NUL-terminated; no security attributes and no template file.
        let handle = unsafe {
            CreateFileW(
                path.as_ptr(),
                GENERIC_READ | GENERIC_WRITE,
                0,
                ptr::null(),
                OPEN_EXISTING,
                FILE_FLAG_OVERLAPPED | SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION,
                ptr::null_mut(),
            )
        };
        if handle != INVALID_HANDLE_VALUE {
            // SAFETY: a fresh handle that nothing else owns.
            let pipe = unsafe { OwnedHandle::from_raw_handle(handle as _) };
            // The name comes from the user's SID, which is no secret: any local program can make a pipe of that name while SSHelter does
            // not serve it (unlike the socket, which lives in a directory only the user can enter). Refused, it is closed unused.
            if !served_by_user(pipe_owner(&pipe).as_deref(), &user_sid_bytes()?) {
                return Err(not_sshelters(name));
            }
            return PipeStream::new(pipe);
        }
        let error = io::Error::last_os_error();
        if error.raw_os_error() != Some(ERROR_PIPE_BUSY as i32) {
            return Err(error);
        }
        let left = deadline.map_or(Duration::MAX, |deadline| deadline.saturating_duration_since(Instant::now()));
        if left.is_zero() {
            return Err(busy());
        }
        // In milliseconds, at least 1 (0 asks for the server's default) and short of NMPWAIT_WAIT_FOREVER.
        let millis = u32::try_from(left.as_millis()).unwrap_or(u32::MAX).clamp(1, u32::MAX - 1);
        // SAFETY: `path` is NUL-terminated.
        if unsafe { WaitNamedPipeW(path.as_ptr(), millis) } == 0 {
            let error = io::Error::last_os_error();
            if error.raw_os_error() == Some(ERROR_SEM_TIMEOUT as i32) {
                return Err(busy());
            }
            // The pipe is gone (the next open says so), or the wait failed: not again at once.
            if error.raw_os_error() != Some(ERROR_FILE_NOT_FOUND as i32) {
                std::thread::sleep(Duration::from_millis(10));
            }
        }
    }
}

/// Creates a pipe instance, in overlapped mode (`PipeStream`). `max_instances`: `PIPE_UNLIMITED_INSTANCES` for a listener.
fn create_instance(path: &[u16], security: &OwnerOnly, first: bool, max_instances: u32) -> io::Result<OwnedHandle> {
    let open_mode = PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED | if first { FILE_FLAG_FIRST_PIPE_INSTANCE } else { 0 };
    let pipe_mode = PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS;
    // SAFETY: `path` is NUL-terminated; the security attributes outlive the call (the system copies them).
    let handle =
        unsafe { CreateNamedPipeW(path.as_ptr(), open_mode, pipe_mode, max_instances, 65536, 65536, 0, &security.attributes) };
    if handle == INVALID_HANDLE_VALUE {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: a fresh handle that nothing else owns.
    Ok(unsafe { OwnedHandle::from_raw_handle(handle as _) })
}

/// 第一個 instance 開不起來的說明:名稱已經有人用時,`FILE_FLAG_FIRST_PIPE_INSTANCE` 回 `ERROR_ACCESS_DENIED`(spec §11);其他錯誤不是名稱被佔用。
/// `what` names the pipe (`agent`, `session`).
fn first_instance_error(e: io::Error, what: &str) -> AppError {
    if e.raw_os_error() == Some(ERROR_ACCESS_DENIED as i32) {
        AppError::Other(format!("Another program is using SSHelter's {what} pipe ({e})"))
    } else {
        AppError::Other(format!("Can't create SSHelter's {what} pipe ({e})"))
    }
}

/// Waits for a client on `pipe` (an instance in overlapped mode); once one is connected, its process id (`None` when it cannot be read).
pub(crate) fn accept(pipe: &OwnedHandle) -> io::Result<Option<u32>> {
    let handle = raw(pipe);
    let done = event()?;
    let mut overlapped = OVERLAPPED { hEvent: raw(&done), ..Default::default() };
    // Only through this pointer from here on, as in `Shared::transfer`.
    let overlapped: *mut OVERLAPPED = &mut overlapped;
    // SAFETY: a valid pipe handle in overlapped mode; `overlapped` and its event live until the connect is over (waited for below).
    if unsafe { ConnectNamedPipe(handle, overlapped) } == 0 {
        let error = io::Error::last_os_error();
        match error.raw_os_error() {
            // The client connected between CreateNamedPipeW and here: connected all the same.
            Some(code) if code == ERROR_PIPE_CONNECTED as i32 => {}
            Some(code) if code == ERROR_IO_PENDING as i32 => {
                let mut transferred = 0u32;
                // SAFETY: waits (TRUE) for the connect started above with `overlapped`.
                if unsafe { GetOverlappedResult(handle, overlapped, &mut transferred, TRUE) } == 0 {
                    return Err(io::Error::last_os_error());
                }
            }
            _ => return Err(error),
        }
    }
    let mut pid = 0u32;
    // SAFETY: writes one u32.
    let known = unsafe { GetNamedPipeClientProcessId(handle, &mut pid) } != 0;
    Ok(known.then_some(pid))
}

/// Takes the lock in `dir`, opens `\\.\pipe\<name>` and hands every connection, as a `PipeStream`, to `handle` on a thread of its own
/// (`dispatch`). The listener's own thread is named `thread` (`sshelter-agent`, `sshelter-session`). Another SSHelter holds the lock →
/// `OtherInstance`; the name is held by another program (or the pipe cannot be made) → an error.
pub fn listen(dir: &Path, name: &str, thread: &str, handle: Handler) -> Result<Started, AppError> {
    // What the messages call this pipe: `agent`, `session`.
    let what = role_in(thread).to_string();
    let Some(lock) = take_lock(dir)? else { return Ok(Started::OtherInstance) };
    let security = OwnerOnly::new()?;
    let path = wide_pipe_path(name);
    let first = create_instance(&path, &security, true, PIPE_UNLIMITED_INSTANCES).map_err(|e| first_instance_error(e, &what))?;
    std::thread::Builder::new().name(thread.to_string()).spawn(move || {
        let _lock = lock;
        let active = Arc::new(AtomicUsize::new(0));
        let mut current = first;
        loop {
            let connected = accept(&current);
            // 先建好下一個 instance:這條連線處理的時候,別的程式才連得上。
            let next = loop {
                match create_instance(&path, &security, false, PIPE_UNLIMITED_INSTANCES) {
                    Ok(next) => break next,
                    Err(e) => {
                        eprintln!("[{what}] cannot create a pipe instance: {e}");
                        std::thread::sleep(Duration::from_secs(1));
                    }
                }
            };
            let served = std::mem::replace(&mut current, next);
            match connected.and_then(|pid| Ok((PipeStream::new(served)?, pid))) {
                Ok((stream, pid)) => dispatch(stream, pid, &active, &handle),
                Err(e) => {
                    eprintln!("[{what}] a pipe connection failed: {e}");
                    // 持續出錯時不要空轉(同 Unix 的 accept 迴圈)。
                    std::thread::sleep(Duration::from_millis(50));
                }
            }
        }
    })?;
    Ok(Started::Running)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ipc::server::testing::{echoing, ping, PONG};
    use std::sync::{mpsc, Mutex};
    use std::thread;

    #[test]
    fn the_pipe_name_is_stable_hex_from_the_user() {
        let name = pipe_name_for("agent").unwrap();
        assert_eq!(name, pipe_name_for("agent").unwrap());
        let hex = name.strip_prefix("sshelter-agent-").unwrap();
        assert_eq!(hex.len(), 16);
        assert!(hex.chars().all(|c| c.is_ascii_hexdigit()));
    }

    /// Plan 1b-3 Task 1: the broker's pipe is named like the agent's, after the same user, with its own role.
    #[test]
    fn each_role_has_its_own_pipe_named_after_the_user() {
        let agent = pipe_name_for("agent").unwrap();
        let hex = agent.strip_prefix("sshelter-agent-").unwrap();
        assert_eq!(pipe_name_for("session").unwrap(), format!("sshelter-session-{hex}"));
    }

    #[test]
    fn serves_a_client_and_a_second_agent_does_not_start() {
        let dir = tempfile::tempdir().unwrap();
        let agent = dir.path().join("agent");
        let name = format!("sshelter-test-{}", std::process::id());
        let (tx, rx) = mpsc::channel();
        assert_eq!(listen(&agent, &name, "sshelter-agent", echoing(tx.clone())).unwrap(), Started::Running);
        let mut client = std::fs::OpenOptions::new().read(true).write(true).open(format!(r"\\.\pipe\{name}")).unwrap();
        assert_eq!(ping(&mut client), PONG);
        assert_eq!(rx.recv_timeout(Duration::from_secs(5)).unwrap(), Some(std::process::id()));
        assert_eq!(listen(&agent, &name, "sshelter-agent", echoing(tx)).unwrap(), Started::OtherInstance);
    }

    /// 只有 `ERROR_ACCESS_DENIED`(`FILE_FLAG_FIRST_PIPE_INSTANCE` 遇到已經存在的名稱時回的錯誤)才說名稱被別的程式佔用;其他錯誤不是。
    #[test]
    fn only_access_denied_is_reported_as_a_taken_name() {
        use windows_sys::Win32::Foundation::{ERROR_ACCESS_DENIED, ERROR_INVALID_PARAMETER};
        let taken = first_instance_error(io::Error::from_raw_os_error(ERROR_ACCESS_DENIED as i32), "agent").to_string();
        assert!(taken.contains("Another program is using SSHelter's agent pipe"), "{taken}");
        let other = first_instance_error(io::Error::from_raw_os_error(ERROR_INVALID_PARAMETER as i32), "agent").to_string();
        assert!(other.starts_with("Can't create SSHelter's agent pipe ("), "{other}");
        assert!(!other.contains("Another program"), "{other}");
    }


    #[test]
    fn a_pipe_name_someone_else_holds_is_an_error() {
        let dir = tempfile::tempdir().unwrap();
        let name = format!("sshelter-squat-{}", std::process::id());
        let security = OwnerOnly::new().unwrap();
        let _squatter = create_instance(&wide_pipe_path(&name), &security, true, PIPE_UNLIMITED_INSTANCES).unwrap();
        let (tx, _rx) = mpsc::channel();
        let err = listen(&dir.path().join("agent"), &name, "sshelter-agent", echoing(tx)).unwrap_err().to_string();
        assert!(err.contains("Another program"), "{err}");
    }

    /// A pipe name no other test uses (the tests of a run share one process).
    fn fresh_name(what: &str) -> String {
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        format!("sshelter-{what}-{}-{}", std::process::id(), NEXT.fetch_add(1, Ordering::SeqCst))
    }

    /// A client connected through a listener, and the server's end of that connection, which the handler hands over. The directory holds
    /// the listener's lock.
    fn connected() -> (PipeStream, PipeStream, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let name = fresh_name("pipetest");
        let (tx, rx) = mpsc::channel();
        let tx = Mutex::new(tx);
        let handler: Handler = Arc::new(move |stream, _pid| {
            let _ = tx.lock().unwrap().send(stream);
        });
        assert_eq!(listen(&dir.path().join("ipc"), &name, "sshelter-pipetest", handler).unwrap(), Started::Running);
        let client = connect(&name, Duration::from_secs(5)).expect("the listener serves the pipe");
        let server = rx.recv_timeout(Duration::from_secs(5)).expect("the handler was given the connection");
        (client, server, dir)
    }

    /// Runs `call` on a thread of its own; what it returns arrives on the receiver (nothing, while it is still blocked).
    fn on_a_thread<T: Send + 'static>(call: impl FnOnce() -> T + Send + 'static) -> mpsc::Receiver<T> {
        let (tx, rx) = mpsc::channel();
        thread::spawn(move || {
            let _ = tx.send(call());
        });
        rx
    }

    /// Plan 1b-3 Task 1: a hang-up wakes a read that waits in another thread, every read after it is the end at once, and every write
    /// fails. The pipe is not disconnected: what was written just before the hang-up stays in it, and the client reads that, and then the
    /// end once the server's last handle is closed.
    #[test]
    fn a_hang_up_wakes_a_blocked_reader_and_keeps_what_was_written() {
        let (mut client, server, _dir) = connected();
        let reading = {
            let server = server.try_clone().unwrap();
            on_a_thread(move || (&server).read(&mut [0u8; 16]))
        };
        assert!(reading.recv_timeout(Duration::from_millis(300)).is_err(), "the read waits: the client has sent nothing");
        // Written while that read waits (the pipe carries both ways at once), just before the hang-up. On a thread of its own: were the
        // handle synchronous again, the write would wait behind the read, and the test must fail then, not hang.
        let writing = {
            let server = server.try_clone().unwrap();
            on_a_thread(move || (&server).write_all(b"last words"))
        };
        writing.recv_timeout(Duration::from_secs(5)).expect("the write did not wait behind the read").unwrap();
        server.hang_up();
        let woken = reading.recv_timeout(Duration::from_secs(5)).expect("the hang-up woke the read");
        assert_eq!(woken.unwrap(), 0, "and it read the end of the stream");
        let started = Instant::now();
        assert_eq!((&server).read(&mut [0u8; 16]).unwrap(), 0, "a read after the hang-up is the end");
        assert!(started.elapsed() < Duration::from_secs(1), "at once: {:?}", started.elapsed());
        assert_eq!((&server).write(b"more").unwrap_err().kind(), io::ErrorKind::BrokenPipe);
        assert!(server.is_hung_up());
        drop(server);
        client.hang_up_after(Some(Duration::from_secs(10))).unwrap();
        let mut got = Vec::new();
        client.read_to_end(&mut got).unwrap();
        assert!(!client.is_hung_up(), "the end came from the server, not from the client's own deadline");
        assert_eq!(got, b"last words");
    }

    /// A write that the client does not read (more than the pipe holds) waits; a hang-up wakes it, and it fails.
    #[test]
    fn a_hang_up_wakes_a_blocked_writer() {
        let (_client, server, _dir) = connected();
        let writing = {
            let server = server.try_clone().unwrap();
            on_a_thread(move || (&server).write_all(&vec![7u8; 4 << 20]))
        };
        assert!(writing.recv_timeout(Duration::from_millis(500)).is_err(), "the write waits for a reader");
        server.hang_up();
        let woken = writing.recv_timeout(Duration::from_secs(5)).expect("the hang-up woke the write");
        assert_eq!(woken.unwrap_err().kind(), io::ErrorKind::BrokenPipe);
    }

    /// `hang_up_after`: a read that waits when the time is over returns the end, and the stream stays hung up; a deadline cleared in time
    /// leaves the stream as it was; one that ran out while nothing waited has hung the stream up all the same; zero is refused.
    #[test]
    fn a_deadline_hangs_the_stream_up_unless_it_is_cleared_in_time() {
        let (mut client, server, _dir) = connected();
        let mut byte = [0u8; 1];
        server.hang_up_after(Some(Duration::from_millis(300))).unwrap();
        server.hang_up_after(None).unwrap();
        thread::sleep(Duration::from_millis(600));
        client.write_all(b"a").unwrap();
        assert_eq!((&server).read(&mut byte).unwrap(), 1, "cleared in time: the stream goes on");
        server.hang_up_after(Some(Duration::from_millis(300))).unwrap();
        let started = Instant::now();
        assert_eq!((&server).read(&mut byte).unwrap(), 0, "the read that waited when the time ran out is the end");
        let waited = started.elapsed();
        assert!(waited >= Duration::from_millis(250) && waited < Duration::from_secs(3), "{waited:?}");
        assert!(server.is_hung_up());
        client.write_all(b"b").unwrap();
        assert_eq!((&server).read(&mut byte).unwrap(), 0, "hung up for good");

        let (_client, server, _dir) = connected();
        assert_eq!(server.hang_up_after(Some(Duration::ZERO)).unwrap_err().kind(), io::ErrorKind::InvalidInput);
        server.hang_up_after(Some(Duration::from_millis(100))).unwrap();
        thread::sleep(Duration::from_millis(400));
        server.hang_up_after(None).unwrap();
        assert!(server.is_hung_up(), "a deadline that ran out while nothing waited is a hang-up too");
    }

    /// Plan 1b-3 Task 1: no pipe of that name, nobody to wait for.
    #[test]
    fn connect_says_not_found_without_a_listener() {
        let started = Instant::now();
        let error = connect(&fresh_name("nobody"), Duration::from_secs(5)).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::NotFound, "{error}");
        assert!(started.elapsed() < Duration::from_secs(2), "it did not wait: {:?}", started.elapsed());
    }

    /// Every instance is busy: `connect` waits (`WaitNamedPipeW`) for one to listen, and gives up once its time is over.
    #[test]
    fn connect_waits_while_every_instance_is_busy() {
        let name = fresh_name("busytest");
        let path = wide_pipe_path(&name);
        let security = OwnerOnly::new().unwrap();
        let only = create_instance(&path, &security, true, 2).unwrap();
        let first = connect(&name, Duration::from_secs(1)).expect("the one instance takes the first client");
        let started = Instant::now();
        let error = connect(&name, Duration::from_millis(300)).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::TimedOut, "{error}");
        assert!(started.elapsed() >= Duration::from_millis(250), "it waited: {:?}", started.elapsed());
        // A second instance listens while a client waits: the client gets it.
        let waiting = {
            let name = name.clone();
            on_a_thread(move || connect(&name, Duration::from_secs(10)))
        };
        thread::sleep(Duration::from_millis(200));
        let accepting = on_a_thread(move || {
            let second = create_instance(&path, &security, false, 2).unwrap();
            accept(&second).map(|_| second)
        });
        let client = waiting.recv_timeout(Duration::from_secs(5)).expect("connect returned").expect("connected");
        let second = accepting.recv_timeout(Duration::from_secs(5)).expect("the instance was connected").unwrap();
        drop((first, client, only, second));
    }

    /// Makes the first instance of `name` as another owner would: owned by the Administrators group, with a null DACL (anyone may connect:
    /// a squatter that wants the user's client lets it in). `None` when this process cannot make that group an owner; it can when it runs
    /// elevated, where the group is in its token with `SE_GROUP_OWNER` (`TOKEN_OWNER`; the CI runner is elevated).
    fn squat_as_administrators(name: &str) -> Option<OwnedHandle> {
        use windows_sys::Win32::Foundation::ERROR_INVALID_OWNER;
        use windows_sys::Win32::Security::{CreateWellKnownSid, SetSecurityDescriptorOwner, WinBuiltinAdministratorsSid, SECURITY_MAX_SID_SIZE};
        let mut sid = [0u8; SECURITY_MAX_SID_SIZE as usize];
        let mut size = SECURITY_MAX_SID_SIZE;
        // SAFETY: `sid` has room for any SID, and `size` says so.
        assert_ne!(unsafe { CreateWellKnownSid(WinBuiltinAdministratorsSid, ptr::null_mut(), sid.as_mut_ptr() as PSID, &mut size) }, 0);
        // SAFETY: plain old data, initialized below.
        let mut descriptor: SECURITY_DESCRIPTOR = unsafe { std::mem::zeroed() };
        let pointer = &mut descriptor as *mut SECURITY_DESCRIPTOR as *mut c_void;
        // SAFETY: `pointer` is the descriptor above; its owner points into `sid`, and both outlive the CreateNamedPipeW below.
        unsafe {
            assert_ne!(InitializeSecurityDescriptor(pointer, SECURITY_DESCRIPTOR_REVISION), 0);
            assert_ne!(SetSecurityDescriptorDacl(pointer, 1, ptr::null(), 0), 0);
            assert_ne!(SetSecurityDescriptorOwner(pointer, sid.as_mut_ptr() as PSID, 0), 0);
        }
        let attributes = SECURITY_ATTRIBUTES { nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32, lpSecurityDescriptor: pointer, bInheritHandle: 0 };
        let path = wide_pipe_path(name);
        let open_mode = PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED | FILE_FLAG_FIRST_PIPE_INSTANCE;
        // SAFETY: `path` is NUL-terminated; the security attributes outlive the call.
        let handle = unsafe { CreateNamedPipeW(path.as_ptr(), open_mode, PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT, 1, 65536, 65536, 0, &attributes) };
        if handle == INVALID_HANDLE_VALUE {
            let error = io::Error::last_os_error();
            assert_eq!(error.raw_os_error(), Some(ERROR_INVALID_OWNER as i32), "the squatter's pipe could not be made: {error}");
            return None;
        }
        // SAFETY: a fresh handle that nothing else owns.
        Some(unsafe { OwnedHandle::from_raw_handle(handle as _) })
    }

    /// Fix round 1 (security): only a pipe the user owns is SSHelter's; one of another owner, or one whose owner cannot be read, is not,
    /// and the refusal says which pipe another program is using.
    #[test]
    fn only_a_pipe_the_user_owns_is_sshelters() {
        let user = user_sid_bytes().unwrap();
        assert!(served_by_user(Some(user.as_slice()), &user), "the user's own pipe");
        let mut other = user.clone();
        *other.last_mut().unwrap() ^= 1;
        assert!(!served_by_user(Some(other.as_slice()), &user), "another owner (another last sub-authority)");
        assert!(!served_by_user(Some(&user[..user.len() - 4]), &user), "another owner (a shorter SID)");
        assert!(!served_by_user(None, &user), "an owner that could not be read");
        let refused = not_sshelters("sshelter-session-0123456789abcdef");
        assert_eq!(refused.kind(), io::ErrorKind::PermissionDenied);
        assert_eq!(refused.to_string(), r"Another program is using SSHelter's session pipe (\\.\pipe\sshelter-session-0123456789abcdef)");
        assert_eq!((role_in("sshelter-agent"), role_in("sshelter-agent-0123456789abcdef")), ("agent", "agent"));
    }

    /// Fix round 1 (security): the pipe's name comes from the user's SID, which is no secret, and any local program can make a pipe of
    /// that name while SSHelter does not serve it. `connect` takes a pipe only if the user owns it, and says why it refuses one.
    #[test]
    fn connect_refuses_a_pipe_another_owner_made() {
        let name = fresh_name("session-squat");
        let Some(_squatter) = squat_as_administrators(&name) else {
            eprintln!("skipped: this process cannot make the Administrators group the owner of a pipe (it is not elevated)");
            return;
        };
        let error = connect(&name, Duration::from_secs(5)).expect_err("a pipe the user does not own is not SSHelter's");
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied, "{error}");
        assert!(error.to_string().contains("Another program is using SSHelter's session pipe"), "{error}");
    }

    /// Fix round 1: the pipes a listener makes are the user's, also when SSHelter runs elevated, where its objects would otherwise be
    /// owned by the Administrators group (an elevated administrator's default owner), and `connect` would refuse SSHelter's own pipe.
    #[test]
    fn a_listener_makes_its_pipes_the_users_own() {
        let (client, _server, _dir) = connected();
        assert_eq!(pipe_owner(&client.shared.pipe), Some(user_sid_bytes().unwrap()));
    }
}
