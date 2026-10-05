//! Windows:把檔案或目錄的 DACL 設成「只有目前使用者、不繼承上層」(SP3 spec §8;Win32-OpenSSH 拒用其他人也能讀的
//! 私鑰)。只依賴 std 與 windows-sys,好讓它能在其他平台上單獨做型別檢查(計畫 Task 2 Step 6)。
use std::ffi::{c_void, OsStr};
use std::io;
use std::os::windows::ffi::OsStrExt;
use std::path::Path;
use std::ptr;

use windows_sys::Win32::Foundation::{CloseHandle, LocalFree, ERROR_SUCCESS, HANDLE};
use windows_sys::Win32::Security::Authorization::{
    SetEntriesInAclW, EXPLICIT_ACCESS_W, NO_MULTIPLE_TRUSTEE, SET_ACCESS, TRUSTEE_IS_SID, TRUSTEE_IS_USER, TRUSTEE_W,
};
use windows_sys::Win32::Security::{
    GetTokenInformation, InitializeSecurityDescriptor, SetFileSecurityW, SetSecurityDescriptorControl,
    SetSecurityDescriptorDacl, TokenUser, ACL, DACL_SECURITY_INFORMATION, NO_INHERITANCE, SECURITY_DESCRIPTOR,
    SE_DACL_PROTECTED, SUB_CONTAINERS_AND_OBJECTS_INHERIT, TOKEN_QUERY, TOKEN_USER,
};
use windows_sys::Win32::Storage::FileSystem::FILE_ALL_ACCESS;
use windows_sys::Win32::System::SystemServices::SECURITY_DESCRIPTOR_REVISION;
use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

fn wide(path: &Path) -> Vec<u16> {
    OsStr::new(path).encode_wide().chain(std::iter::once(0)).collect()
}

/// 目前使用者的 `TOKEN_USER`(放在回傳的緩衝區裡;SID 指標指進緩衝區)。緩衝區是 `Vec<u64>` 而不是 `Vec<u8>`:
/// `TOKEN_USER` 含指標,起點必須 8 位元組對齊,`Vec<u8>` 只保證 1 位元組(得倚賴配置器的行為),`Vec<u64>` 由型別保證 8。
fn current_user_token() -> io::Result<Vec<u64>> {
    unsafe {
        let mut token: HANDLE = ptr::null_mut();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == 0 {
            return Err(io::Error::last_os_error());
        }
        let mut needed = 0u32;
        GetTokenInformation(token, TokenUser, ptr::null_mut(), 0, &mut needed);
        // 以 8 位元組為單位向上取整配置;傳給 Win32 的長度仍是位元組數(`needed`)。
        let mut buffer = vec![0u64; (needed as usize).div_ceil(8)];
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
///
/// - 用 `SetFileSecurityW`,不用 `SetNamedSecurityInfoW`:後者設在目錄上會把可繼承的 ACE 自動傳播給既有的子項,而插槽可能是
///   使用者原檔的 hard link(和原檔共用同一份安全描述元),傳播會改到使用者自己的金鑰檔;前者只改這一個物件,設在目錄上的
///   安全設定不會被既有的子項繼承。
/// - 「不繼承上層」放在描述元的 `SE_DACL_PROTECTED` 控制位元,不傳 `PROTECTED_DACL_SECURITY_INFORMATION`(文件沒有說
///   `SetFileSecurityW` 認得它)。輸入的描述元帶著這個位元時,系統忽略物件現有的 DACL,整份換成這裡給的,不會和上層繼承
///   來的 ACE 合併(見 `SeSetSecurityDescriptorInfoEx` 的規則)。
/// - 權限用具體的 `FILE_ALL_ACCESS`,不用 `GENERIC_ALL`:含 generic 權限的可繼承 ACE 會被存成兩條(一條 inherit-only、一條
///   對應後的有效 ACE),DACL 就不是只有一條。
pub fn restrict_to_owner(path: &Path, inheritable: bool) -> io::Result<()> {
    let token = current_user_token()?;
    // 路徑先轉好:`last_os_error` 要緊接在失敗的 Win32 呼叫之後讀,中間不能再有別的配置。
    let name = wide(path);
    unsafe {
        // `token` 是 `Vec<u64>`,起點 8 位元組對齊,夠 `TOKEN_USER` 用(內容已由 `GetTokenInformation` 填好)。
        let user = &*(token.as_ptr() as *const TOKEN_USER);
        let access = EXPLICIT_ACCESS_W {
            grfAccessPermissions: FILE_ALL_ACCESS,
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
        // 絕對格式的描述元,只帶這一份 DACL 並標成受保護;描述元只引用 `acl`、不複製,所以 `acl` 要活到 `SetFileSecurityW` 回來。
        // 任何一步失敗就不再往下做,錯誤碼留在 last error。
        let mut descriptor: SECURITY_DESCRIPTOR = std::mem::zeroed();
        let descriptor_ptr = &mut descriptor as *mut SECURITY_DESCRIPTOR as *mut c_void;
        let applied = InitializeSecurityDescriptor(descriptor_ptr, SECURITY_DESCRIPTOR_REVISION) != 0
            && SetSecurityDescriptorDacl(descriptor_ptr, 1, acl, 0) != 0
            && SetSecurityDescriptorControl(descriptor_ptr, SE_DACL_PROTECTED, SE_DACL_PROTECTED) != 0
            && SetFileSecurityW(name.as_ptr(), DACL_SECURITY_INFORMATION, descriptor_ptr) != 0;
        let error = io::Error::last_os_error();
        LocalFree(acl as *mut c_void);
        if !applied {
            return Err(error);
        }
    }
    Ok(())
}

/// 測試用:`path` 的 DACL 有幾條 ACE。
#[cfg(test)]
pub fn ace_count(path: &Path) -> io::Result<u32> {
    use windows_sys::Win32::Security::Authorization::{GetNamedSecurityInfoW, SE_FILE_OBJECT};
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
