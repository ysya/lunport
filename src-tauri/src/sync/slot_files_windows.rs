//! Windows:把檔案或目錄的 DACL 設成「只有目前使用者、不繼承上層」(SP3 spec §8;Win32-OpenSSH 拒用其他人也能讀的
//! 私鑰)。只依賴 std 與 windows-sys,好讓它能在其他平台上單獨做型別檢查(計畫 Task 2 Step 6)。
use std::ffi::{c_void, OsStr};
use std::io;
use std::os::windows::ffi::OsStrExt;
use std::path::Path;
use std::ptr;

use windows_sys::Win32::Foundation::{CloseHandle, LocalFree, ERROR_SUCCESS, GENERIC_ALL, HANDLE};
use windows_sys::Win32::Security::Authorization::{
    SetEntriesInAclW, SetNamedSecurityInfoW, EXPLICIT_ACCESS_W, NO_MULTIPLE_TRUSTEE, SET_ACCESS, SE_FILE_OBJECT,
    TRUSTEE_IS_SID, TRUSTEE_IS_USER, TRUSTEE_W,
};
use windows_sys::Win32::Security::{
    GetTokenInformation, TokenUser, ACL, DACL_SECURITY_INFORMATION, NO_INHERITANCE, PROTECTED_DACL_SECURITY_INFORMATION,
    SUB_CONTAINERS_AND_OBJECTS_INHERIT, TOKEN_QUERY, TOKEN_USER,
};
use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

fn wide(path: &Path) -> Vec<u16> {
    OsStr::new(path).encode_wide().chain(std::iter::once(0)).collect()
}

/// 目前使用者的 `TOKEN_USER`(放在回傳的緩衝區裡;SID 指標指進緩衝區)。
fn current_user_token() -> io::Result<Vec<u8>> {
    unsafe {
        let mut token: HANDLE = ptr::null_mut();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == 0 {
            return Err(io::Error::last_os_error());
        }
        let mut needed = 0u32;
        GetTokenInformation(token, TokenUser, ptr::null_mut(), 0, &mut needed);
        let mut buffer = vec![0u8; needed as usize];
        let ok = GetTokenInformation(token, TokenUser, buffer.as_mut_ptr() as *mut c_void, needed, &mut needed);
        let error = io::Error::last_os_error();
        CloseHandle(token);
        if ok == 0 {
            return Err(error);
        }
        Ok(buffer)
    }
}

/// 把 `path` 的 DACL 換成只有一條「目前使用者:完全控制」,並切斷上層繼承。`inheritable` = true(目錄)時這一條會被
/// 之後在裡面建立的檔案與目錄繼承 —— 暫存檔一建立就是 owner-only,沒有可被讀取的空窗。
pub fn restrict_to_owner(path: &Path, inheritable: bool) -> io::Result<()> {
    let token = current_user_token()?;
    unsafe {
        let user = &*(token.as_ptr() as *const TOKEN_USER);
        let access = EXPLICIT_ACCESS_W {
            grfAccessPermissions: GENERIC_ALL,
            grfAccessMode: SET_ACCESS,
            grfInheritance: if inheritable { SUB_CONTAINERS_AND_OBJECTS_INHERIT } else { NO_INHERITANCE },
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
        let name = wide(path);
        let status = SetNamedSecurityInfoW(
            name.as_ptr(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            ptr::null_mut(),
            ptr::null_mut(),
            acl,
            ptr::null(),
        );
        LocalFree(acl as *mut c_void);
        if status != ERROR_SUCCESS {
            return Err(io::Error::from_raw_os_error(status as i32));
        }
    }
    Ok(())
}

/// 測試用:`path` 的 DACL 有幾條 ACE。
#[cfg(test)]
pub fn ace_count(path: &Path) -> io::Result<u32> {
    use windows_sys::Win32::Security::Authorization::GetNamedSecurityInfoW;
    use windows_sys::Win32::Security::{AclSizeInformation, GetAclInformation, ACL_SIZE_INFORMATION};
    unsafe {
        let name = wide(path);
        let mut dacl: *mut ACL = ptr::null_mut();
        let mut descriptor: *mut c_void = ptr::null_mut();
        let status = GetNamedSecurityInfoW(
            name.as_ptr(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            ptr::null_mut(),
            ptr::null_mut(),
            &mut dacl,
            ptr::null_mut(),
            &mut descriptor,
        );
        if status != ERROR_SUCCESS {
            return Err(io::Error::from_raw_os_error(status as i32));
        }
        let mut info: ACL_SIZE_INFORMATION = std::mem::zeroed();
        let ok = GetAclInformation(
            dacl,
            &mut info as *mut ACL_SIZE_INFORMATION as *mut c_void,
            std::mem::size_of::<ACL_SIZE_INFORMATION>() as u32,
            AclSizeInformation,
        );
        let error = io::Error::last_os_error();
        LocalFree(descriptor);
        if ok == 0 {
            return Err(error);
        }
        Ok(info.AceCount)
    }
}
