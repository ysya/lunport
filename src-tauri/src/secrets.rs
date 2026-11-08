//! 作業系統 keychain 的薄封裝（macOS Keychain / Windows Credential Manager / Linux Secret Service）。
//!
//! 密碼只存在這裡：絕不寫進 `~/.ssh/config`（會被 `fsutil::backup()` 帶進備份歷史），
//! 也不進 settings export。account 命名見 `host_account`。

use crate::error::AppError;

#[cfg(any(windows, test))]
#[path = "credential_blob.rs"]
pub(crate) mod credential_blob;
#[cfg(windows)]
#[path = "windows_credentials.rs"]
mod windows_credentials;

// Small credentials retain the legacy encoding. Large Windows values use DPAPI
// files whose exact current contents are pinned by the OS credential entry.
#[cfg(windows)]
pub fn get(account: &str) -> Result<Option<String>, AppError> { windows_credentials::get(account) }
#[cfg(windows)]
pub fn set(account: &str, value: &str) -> Result<(), AppError> { windows_credentials::set(account, value) }
#[cfg(windows)]
pub fn delete(account: &str) -> Result<(), AppError> { windows_credentials::delete(account) }

#[cfg(target_os = "macos")]
#[path = "macos_credential_helper.rs"]
mod macos_helper;

/// keychain 的 service 名稱，全 app 固定。
pub const SERVICE: &str = crate::app_profile::CURRENT.keychain_service();

// A foreground authorization must finish before another protected request starts.
// No passwords are cached, and the user's Keychain access controls remain in force.
#[cfg(target_os = "macos")]
fn access_guard() -> std::sync::MutexGuard<'static, ()> {
    static ACCESS: std::sync::Mutex<()> = std::sync::Mutex::new(());
    ACCESS.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// 正式項目：使用者勾了「記住密碼」時使用，不會被自動刪除。
pub fn host_account(alias: &str) -> String {
    format!("host:{alias}")
}

/// 把 keyring 的錯誤轉成 AppError。`NoEntry` 由呼叫端各自處理，不會走到這裡。
fn map_err(e: keyring::Error) -> AppError {
    match e {
        keyring::Error::NoDefaultStore => AppError::Other(
            "no OS credential store available on this machine".to_string(),
        ),
        other => AppError::Other(format!("keychain error: {other}")),
    }
}

/// 讀取一筆密碼。沒有這筆項目時回 `Ok(None)`（不是錯誤）。
#[cfg(not(windows))]
pub fn get(account: &str) -> Result<Option<String>, AppError> {
    #[cfg(target_os = "macos")]
    let _access = access_guard();
    #[cfg(target_os = "macos")]
    if crate::app_profile::CURRENT == crate::app_profile::AppProfile::Production {
        return macos_helper::get(account);
    }
    let entry = keyring::Entry::new(SERVICE, account).map_err(map_err)?;
    match entry.get_password() {
        Ok(secret) => Ok(Some(secret)),
        Err(keyring::Error::NoEntry) => Ok(None),
        Err(e) => Err(map_err(e)),
    }
}

/// Background APIs never fall back to an interactive keyring operation.
pub fn get_noninteractive(account:&str)->Result<Option<String>,AppError> {
    #[cfg(target_os="macos")]
    {
        let _access=access_guard();
        if crate::app_profile::CURRENT==crate::app_profile::AppProfile::Production {return macos_helper::get_noninteractive(account);}
        return Err(AppError::Other("needs interaction: unlock credentials in the Development app".into()));
    }
    #[cfg(windows)] {return get(account);}
    #[cfg(target_os="linux")] {return linux_background::get(account);}
    #[cfg(not(any(target_os="macos",windows,target_os="linux")))]
    Err(AppError::Other("needs interaction: no verified background credential store".into()))
}
pub fn set_noninteractive(account:&str,secret:&str)->Result<(),AppError> {
    #[cfg(target_os="macos")]
    {
        let _access=access_guard();
        if crate::app_profile::CURRENT==crate::app_profile::AppProfile::Production {return macos_helper::set_noninteractive(account,secret);}
        return Err(AppError::Other("needs interaction: unlock credentials in the Development app".into()));
    }
    #[cfg(windows)] {return set(account,secret);}
    #[cfg(target_os="linux")] {return linux_background::set(account,secret);}
    #[cfg(not(any(target_os="macos",windows,target_os="linux")))]
    Err(AppError::Other("needs interaction: no verified background credential store".into()))
}
#[cfg(target_os="linux")]
#[path="linux_background_credentials.rs"]
mod linux_background;

/// 寫入（或覆蓋）一筆密碼。
#[cfg(not(windows))]
pub fn set(account: &str, secret: &str) -> Result<(), AppError> {
    #[cfg(target_os = "macos")]
    let _access = access_guard();
    #[cfg(target_os = "macos")]
    if crate::app_profile::CURRENT == crate::app_profile::AppProfile::Production {
        return macos_helper::set(account, secret);
    }
    let entry = keyring::Entry::new(SERVICE, account).map_err(map_err)?;
    entry.set_password(secret).map_err(map_err)
}

/// 刪除一筆密碼。項目本來就不存在時視為成功（清理路徑要能重複執行）。
#[cfg(not(windows))]
pub fn delete(account: &str) -> Result<(), AppError> {
    #[cfg(target_os = "macos")]
    let _access = access_guard();
    #[cfg(target_os = "macos")]
    if crate::app_profile::CURRENT == crate::app_profile::AppProfile::Production {
        return macos_helper::delete(account);
    }
    let entry = keyring::Entry::new(SERVICE, account).map_err(map_err)?;
    match entry.delete_credential() {
        Ok(()) => Ok(()),
        Err(keyring::Error::NoEntry) => Ok(()),
        Err(e) => Err(map_err(e)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_passwords_are_namespaced() {
        assert_eq!(host_account("web"), "host:web");
    }

    /// 保底清理：就算 `set` 之後、下面明確呼叫 `delete` 之前的斷言或 `unwrap` panic，
    /// unwind 過程也會呼叫 `drop`，確保不會在真實使用者的 keychain 裡留下明文密碼。
    struct CleanupGuard<'a>(&'a str);
    impl Drop for CleanupGuard<'_> {
        fn drop(&mut self) {
            let _ = delete(self.0);
        }
    }

    /// 真的碰作業系統 keychain。CI 上沒有可用的密鑰環時自動跳過。
    #[test]
    fn round_trip_set_get_delete() {
        if keyring::Entry::new(SERVICE, "availability-probe").is_err() {
            eprintln!("skipping: no credential store on this machine");
            return;
        }
        let account = "test:round-trip";
        let _cleanup = CleanupGuard(account);
        set(account, "hunter2").expect("set ok");
        assert_eq!(get(account).unwrap().as_deref(), Some("hunter2"));
        delete(account).expect("delete ok");
        assert_eq!(get(account).unwrap(), None, "deleted entry reads back as None");
        // 重複刪除不報錯（清理路徑必須可重入）。
        delete(account).expect("second delete is a no-op");
    }
}
