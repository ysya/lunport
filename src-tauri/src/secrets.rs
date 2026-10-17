//! 作業系統 keychain 的薄封裝（macOS Keychain / Windows Credential Manager / Linux Secret Service）。
//!
//! 密碼只存在這裡：絕不寫進 `~/.ssh/config`（會被 `fsutil::backup()` 帶進備份歷史），
//! 也不進 settings export。account 命名見 `host_account` / `tmp_account`。

use crate::error::AppError;

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

/// 暫存項目：沒勾「記住密碼」時使用，部署結束後一律刪除。
pub fn tmp_account(alias: &str) -> String {
    format!("deploy-tmp:{alias}")
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

/// Check whether a saved credential exists without requesting its protected data.
#[cfg(target_os = "macos")]
pub fn contains(account: &str) -> Result<bool, AppError> {
    use security_framework::item::{ItemClass, ItemSearchOptions};
    use security_framework::os::macos::keychain::{SecKeychain, SecPreferencesDomain};

    if account.is_empty() {
        return Err(AppError::Other("keychain account must not be empty".into()));
    }
    let _access = access_guard();
    // Match keyring's apple-native store: the current user's default file keychain.
    let keychain = SecKeychain::default_for_domain(SecPreferencesDomain::User)
        .map_err(|err| AppError::Other(format!("keychain metadata error: {err}")))?;
    let result = ItemSearchOptions::new()
        .keychains(&[keychain])
        .class(ItemClass::generic_password())
        .service(SERVICE)
        .account(account)
        .load_attributes(true)
        .load_data(false)
        .load_refs(false)
        .skip_authenticated_items(true)
        .search();
    match result {
        Ok(items) => Ok(!items.is_empty()),
        Err(err) if err.code() == -25300 => Ok(false), // errSecItemNotFound
        Err(err) => Err(AppError::Other(format!("keychain metadata error: {err}"))),
    }
}

#[cfg(not(target_os = "macos"))]
pub fn contains(account: &str) -> Result<bool, AppError> {
    get(account).map(|secret| secret.is_some())
}

/// 寫入（或覆蓋）一筆密碼。
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

/// 本機是否有可用的密鑰環。false 時呼叫端要改走環境變數 fallback 並告知使用者。
///
/// 刻意把「任何錯誤」都視為不可用，而不是只認 `NoDefaultStore`：在沒有 Secret Service
/// 的 Linux 上，第一次呼叫拿到的是 D-Bus 連線錯誤，第二次以後才是 `NoDefaultStore`
/// （`Entry::new` 會先把初始化旗標設成 true 才嘗試建 store）。只認單一變體會在這個
/// 機制唯一存在意義的平台上、第一次呼叫時錯答「可用」。
pub fn available() -> bool {
    keyring::Entry::new(SERVICE, "availability-probe").is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Only scripts/validate-macos-keychain.sh may run this, against its disposable CI keychain.
    #[cfg(target_os = "macos")]
    #[test]
    #[ignore = "requires an isolated CI keychain with a differently signed fixture writer"]
    fn native_metadata_probe() {
        use security_framework::os::macos::keychain::SecKeychain;
        assert_eq!(std::env::var("GITHUB_ACTIONS").as_deref(), Ok("true"));
        assert_eq!(SERVICE, "SSHelter Development");
        let account = std::env::var("SSHELTER_CI_KEYCHAIN_PROBE_ACCOUNT").unwrap();
        assert!(account.starts_with("lunport-ci-keychain-"));
        // This test owns the process; production never disables UI globally.
        let _no_ui = SecKeychain::disable_user_interaction().unwrap();
        assert!(contains(&account).unwrap(), "metadata must find an ACL-protected item");
        assert!(!contains(&format!("{account}-missing")).unwrap());
        assert!(contains("").is_err());
        assert!(get(&account).is_err(), "metadata lookup must not grant password access");
    }

    #[test]
    fn accounts_are_namespaced_and_distinct() {
        assert_eq!(host_account("web"), "host:web");
        assert_eq!(tmp_account("web"), "deploy-tmp:web");
        assert_ne!(host_account("web"), tmp_account("web"));
    }

    #[test]
    fn account_namespaces_cannot_collide_across_aliases() {
        // 一個 alias 的正式項目不可能等於另一個 alias 的暫存項目。
        assert_ne!(host_account("deploy-tmp:web"), tmp_account("web"));
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
        if !available() {
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
