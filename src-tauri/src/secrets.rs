//! 作業系統 keychain 的薄封裝（macOS Keychain / Windows Credential Manager / Linux Secret Service）。
//!
//! 密碼只存在這裡：絕不寫進 `~/.ssh/config`（會被 `fsutil::backup()` 帶進備份歷史），
//! 也不進 settings export。account 命名見 `host_account` / `tmp_account`。

use crate::error::AppError;

/// keychain 的 service 名稱，全 app 固定。
pub const SERVICE: &str = "SSHelter";

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
    let entry = keyring::Entry::new(SERVICE, account).map_err(map_err)?;
    match entry.get_password() {
        Ok(secret) => Ok(Some(secret)),
        Err(keyring::Error::NoEntry) => Ok(None),
        Err(e) => Err(map_err(e)),
    }
}

/// 寫入（或覆蓋）一筆密碼。
pub fn set(account: &str, secret: &str) -> Result<(), AppError> {
    let entry = keyring::Entry::new(SERVICE, account).map_err(map_err)?;
    entry.set_password(secret).map_err(map_err)
}

/// 刪除一筆密碼。項目本來就不存在時視為成功（清理路徑要能重複執行）。
pub fn delete(account: &str) -> Result<(), AppError> {
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
