//! Windows 的 agent 端點(金鑰保管庫 spec §4.4、§5.1):自己的 named pipe `\\.\pipe\sshelter-agent-<使用者 SID 字串的 SHA-256 前 16 個十六進位>`。
//! 每個 instance 的 DACL 只給目前使用者、拒絕遠端連線;第一個 instance 帶 `FILE_FLAG_FIRST_PIPE_INSTANCE`:名稱已經被別的程式佔用就開不起來
//! (spec §11;另一個 SSHelter 先被 `server::take_lock` 擋下)。只依賴 std 與 windows-sys。

use std::ffi::c_void;
use std::fs::File;
use std::io;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use std::path::Path;
use std::ptr;
use std::sync::atomic::AtomicUsize;
use std::sync::Arc;
use std::time::Duration;

use sha2::{Digest, Sha256};
use windows_sys::Win32::Foundation::{LocalFree, ERROR_ACCESS_DENIED, ERROR_PIPE_CONNECTED, ERROR_SUCCESS, HANDLE, INVALID_HANDLE_VALUE};
use windows_sys::Win32::Security::Authorization::{
    ConvertSidToStringSidW, SetEntriesInAclW, EXPLICIT_ACCESS_W, NO_MULTIPLE_TRUSTEE, SET_ACCESS, TRUSTEE_IS_SID, TRUSTEE_IS_USER, TRUSTEE_W,
};
use windows_sys::Win32::Security::{
    InitializeSecurityDescriptor, SetSecurityDescriptorDacl, ACL, NO_INHERITANCE, SECURITY_ATTRIBUTES, SECURITY_DESCRIPTOR, TOKEN_USER,
};
use windows_sys::Win32::Storage::FileSystem::{FILE_ALL_ACCESS, FILE_FLAG_FIRST_PIPE_INSTANCE, PIPE_ACCESS_DUPLEX};
use windows_sys::Win32::System::Pipes::{
    ConnectNamedPipe, CreateNamedPipeW, GetNamedPipeClientProcessId, PIPE_READMODE_BYTE, PIPE_REJECT_REMOTE_CLIENTS, PIPE_TYPE_BYTE,
    PIPE_UNLIMITED_INSTANCES, PIPE_WAIT,
};
use windows_sys::Win32::System::SystemServices::SECURITY_DESCRIPTOR_REVISION;

use crate::agent::server::{dispatch, take_lock, Handler, Started};
use crate::error::AppError;
use crate::sync::slot_files_windows::current_user_token;

/// 每個 pipe instance 共用的 SECURITY_ATTRIBUTES:DACL 只有一條「目前使用者:完全控制」。`SetEntriesInAclW` 把 SID 複製進 ACE,所以讀 SID 用的
/// `TOKEN_USER` 緩衝區只在 `new` 裡用到,不必跟著留下。
struct OwnerOnly {
    acl: *mut ACL,
    _descriptor: Box<SECURITY_DESCRIPTOR>,
    attributes: SECURITY_ATTRIBUTES,
}

// 指標只指向這個結構自己擁有的記憶體(LocalAlloc 的 ACL、Box 的描述元);整個結構一起搬到 listener 的執行緒,只在那裡使用。
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
        // SAFETY: `token` holds an 8-byte aligned TOKEN_USER whose SID points into `token`, which lives to the end of this function; SetEntriesInAclW copies the SID into the ACE.
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
            if InitializeSecurityDescriptor(pointer, SECURITY_DESCRIPTOR_REVISION) == 0 || SetSecurityDescriptorDacl(pointer, 1, acl, 0) == 0 {
                let error = io::Error::last_os_error();
                LocalFree(acl as *mut c_void);
                return Err(error);
            }
            let attributes = SECURITY_ATTRIBUTES {
                nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
                lpSecurityDescriptor: pointer,
                bInheritHandle: 0,
            };
            Ok(Self { acl, _descriptor: descriptor, attributes })
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

/// `sshelter-agent-<SID 字串的 SHA-256 前 16 個十六進位>`(spec §4.4)。
pub fn pipe_name() -> io::Result<String> {
    let digest = Sha256::digest(user_sid()?.as_bytes());
    Ok(format!("sshelter-agent-{}", digest.iter().take(8).map(|b| format!("{b:02x}")).collect::<String>()))
}

fn wide_pipe_path(name: &str) -> Vec<u16> {
    format!(r"\\.\pipe\{name}").encode_utf16().chain(std::iter::once(0)).collect()
}

/// 建一個 pipe instance。`max_instances`:agent 是 `PIPE_UNLIMITED_INSTANCES`,Connect 的一次性 pipe 是 1。
fn create_instance(path: &[u16], security: &OwnerOnly, first: bool, max_instances: u32) -> io::Result<OwnedHandle> {
    let open_mode = PIPE_ACCESS_DUPLEX | if first { FILE_FLAG_FIRST_PIPE_INSTANCE } else { 0 };
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
fn first_instance_error(e: io::Error) -> AppError {
    if e.raw_os_error() == Some(ERROR_ACCESS_DENIED as i32) {
        AppError::Other(format!("Another program is using SSHelter's agent pipe ({e})"))
    } else {
        AppError::Other(format!("Can't create SSHelter's agent pipe ({e})"))
    }
}

/// 等一個連線;連上了回傳對方的 PID(拿不到 → None)。
pub(crate) fn accept(pipe: &OwnedHandle) -> io::Result<Option<u32>> {
    let handle = pipe.as_raw_handle() as HANDLE;
    // SAFETY: a valid pipe handle in synchronous mode (no OVERLAPPED).
    if unsafe { ConnectNamedPipe(handle, ptr::null_mut()) } == 0 {
        let error = io::Error::last_os_error();
        // 對方在 CreateNamedPipeW 與 ConnectNamedPipe 之間就連上了:也算連上。
        if error.raw_os_error() != Some(ERROR_PIPE_CONNECTED as i32) {
            return Err(error);
        }
    }
    let mut pid = 0u32;
    // SAFETY: writes one u32.
    let known = unsafe { GetNamedPipeClientProcessId(handle, &mut pid) } != 0;
    Ok(known.then_some(pid))
}

/// Connect 的一次性 pipe:只有一個 instance,名稱已經存在就失敗(`FILE_FLAG_FIRST_PIPE_INSTANCE`)。描述元在建立時複製,用完即丟。
pub(crate) fn one_shot(name: &str) -> io::Result<OwnedHandle> {
    let security = OwnerOnly::new()?;
    create_instance(&wide_pipe_path(name), &security, true, 1)
}

/// 在 `dir` 拿鎖,開 `\\.\pipe\<name>`,每條連線交給 `handle`。另一個 SSHelter 拿著鎖 → `OtherInstance`;名稱被別的程式佔用(或其他開不起來的原因)→ 錯誤。
pub fn listen(dir: &Path, name: &str, handle: Handler) -> Result<Started, AppError> {
    let Some(lock) = take_lock(dir)? else { return Ok(Started::OtherInstance) };
    let security = OwnerOnly::new()?;
    let path = wide_pipe_path(name);
    let first = create_instance(&path, &security, true, PIPE_UNLIMITED_INSTANCES).map_err(first_instance_error)?;
    std::thread::Builder::new().name("sshelter-agent".to_string()).spawn(move || {
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
                        eprintln!("[agent] cannot create a pipe instance: {e}");
                        std::thread::sleep(Duration::from_secs(1));
                    }
                }
            };
            let served = std::mem::replace(&mut current, next);
            match connected {
                Ok(pid) => dispatch(File::from(served), pid, &active, &handle),
                Err(e) => {
                    eprintln!("[agent] a pipe connection failed: {e}");
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
    use crate::agent::protocol::{read_frame, write_frame, SSH_AGENTC_REQUEST_IDENTITIES, SSH_AGENT_IDENTITIES_ANSWER};
    use crate::agent::server::testing::serving;
    use std::sync::mpsc;

    #[test]
    fn the_pipe_name_is_stable_hex_from_the_user() {
        let name = pipe_name().unwrap();
        assert_eq!(name, pipe_name().unwrap());
        let hex = name.strip_prefix("sshelter-agent-").unwrap();
        assert_eq!(hex.len(), 16);
        assert!(hex.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn serves_a_client_and_a_second_agent_does_not_start() {
        let dir = tempfile::tempdir().unwrap();
        let agent = dir.path().join("agent");
        let name = format!("sshelter-test-{}", std::process::id());
        let (tx, rx) = mpsc::channel();
        assert_eq!(listen(&agent, &name, serving(tx.clone())).unwrap(), Started::Running);
        let mut client = std::fs::OpenOptions::new().read(true).write(true).open(format!(r"\\.\pipe\{name}")).unwrap();
        write_frame(&mut client, &[SSH_AGENTC_REQUEST_IDENTITIES]).unwrap();
        assert_eq!(read_frame(&mut client).unwrap().unwrap()[0], SSH_AGENT_IDENTITIES_ANSWER);
        assert_eq!(rx.recv_timeout(Duration::from_secs(5)).unwrap(), Some(std::process::id()));
        assert_eq!(listen(&agent, &name, serving(tx)).unwrap(), Started::OtherInstance);
    }

    /// 只有 `ERROR_ACCESS_DENIED`(`FILE_FLAG_FIRST_PIPE_INSTANCE` 遇到已經存在的名稱時回的錯誤)才說名稱被別的程式佔用;其他錯誤不是。
    #[test]
    fn only_access_denied_is_reported_as_a_taken_name() {
        use windows_sys::Win32::Foundation::{ERROR_ACCESS_DENIED, ERROR_INVALID_PARAMETER};
        let taken = first_instance_error(io::Error::from_raw_os_error(ERROR_ACCESS_DENIED as i32)).to_string();
        assert!(taken.contains("Another program is using SSHelter's agent pipe"), "{taken}");
        let other = first_instance_error(io::Error::from_raw_os_error(ERROR_INVALID_PARAMETER as i32)).to_string();
        assert!(other.starts_with("Can't create SSHelter's agent pipe ("), "{other}");
        assert!(!other.contains("Another program"), "{other}");
    }

    /// Connect 的一次性 pipe 只有一個 instance,名稱被佔用時開不起來(`FILE_FLAG_FIRST_PIPE_INSTANCE`),instance 關掉之後名稱又空出來。
    #[test]
    fn a_one_shot_pipe_cannot_be_opened_twice_under_one_name() {
        let name = format!("sshelter-oneshot-test-{}", std::process::id());
        let first = one_shot(&name).unwrap();
        assert!(one_shot(&name).is_err(), "the name is taken");
        drop(first);
        assert!(one_shot(&name).is_ok(), "free again once the only instance is closed");
    }

    #[test]
    fn a_pipe_name_someone_else_holds_is_an_error() {
        let dir = tempfile::tempdir().unwrap();
        let name = format!("sshelter-squat-{}", std::process::id());
        let security = OwnerOnly::new().unwrap();
        let _squatter = create_instance(&wide_pipe_path(&name), &security, true, PIPE_UNLIMITED_INSTANCES).unwrap();
        let (tx, _rx) = mpsc::channel();
        let err = listen(&dir.path().join("agent"), &name, serving(tx)).unwrap_err().to_string();
        assert!(err.contains("Another program"), "{err}");
    }
}
