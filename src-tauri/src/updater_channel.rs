//! Beta 更新頻道(spec:docs/superpowers/specs/2026-10-01-update-channels-design.md §3.2)。
//! Stable 頻道沿用前端 `@tauri-apps/plugin-updater` 的 `check()`(讀 tauri.conf.json 的網址);
//! 這裡只處理 Beta:以 `updater_builder().endpoints(...)` 改讀 `updater-beta` release 的清單。
//! 簽章驗證與「遠端版本較新才更新(不降版)」沿用 plugin 預設。

use std::sync::Mutex;

use serde::Serialize;
use tauri::{AppHandle, Url};

use crate::error::AppError;

/// Beta 頻道的更新清單(由 CI 的 scripts/beta-channel.mjs 維護)。
pub const BETA_ENDPOINT: &str = "https://github.com/ysya/sshelter/releases/download/updater-beta/latest.json";

const NOTHING_PENDING: &str = "no beta update is ready to install; check for updates again";

/// 給前端的更新摘要,對應 plugin JS `Update` 的 version / body。
#[derive(Clone, Debug, Serialize)]
#[cfg_attr(test, derive(ts_rs::TS))]
#[cfg_attr(test, ts(export, export_to = "../../src/bindings/"))]
pub struct UpdateInfo {
    pub version: String,
    pub body: Option<String>,
}

fn beta_endpoint() -> Result<Url, AppError> {
    Url::parse(BETA_ENDPOINT).map_err(|e| AppError::Other(format!("invalid beta update endpoint: {e}")))
}

/// 取出等待安裝的更新:每個檢查到的更新最多安裝一次;沒有(app 重開過、或已裝過)就請使用者重新檢查。
fn take_pending<T>(slot: &Mutex<Option<T>>) -> Result<T, AppError> {
    slot.lock().unwrap().take().ok_or_else(|| AppError::Other(NOTHING_PENDING.to_string()))
}

/// `updater_check_beta` 找到、等使用者按「Install & restart」的更新(只在桌面平台有 updater)。
#[cfg(desktop)]
#[derive(Default)]
pub struct PendingBetaUpdate(Mutex<Option<tauri_plugin_updater::Update>>);

#[cfg(desktop)]
fn plugin_error(e: tauri_plugin_updater::Error) -> AppError {
    AppError::Other(e.to_string())
}

/// 檢查 Beta 頻道:有較新版本就暫存起來(覆寫先前的暫存)並回傳摘要;沒有就清掉暫存、回傳 None。
#[tauri::command]
pub async fn updater_check_beta(app: AppHandle) -> Result<Option<UpdateInfo>, AppError> {
    #[cfg(desktop)]
    {
        use tauri::Manager;
        use tauri_plugin_updater::UpdaterExt;

        let updater = app
            .updater_builder()
            .endpoints(vec![beta_endpoint()?])
            .map_err(plugin_error)?
            .build()
            .map_err(plugin_error)?;
        let update = updater.check().await.map_err(plugin_error)?;
        let info = update.as_ref().map(|u| UpdateInfo { version: u.version.clone(), body: u.body.clone() });
        *app.state::<PendingBetaUpdate>().0.lock().unwrap() = update;
        Ok(info)
    }
    #[cfg(not(desktop))]
    {
        let _ = app;
        Err(AppError::Other("updates are not supported on this platform".to_string()))
    }
}

/// 下載並安裝 `updater_check_beta` 暫存的更新(簽章由 plugin 驗證);重開 app 由前端 `relaunch()` 負責。
#[tauri::command]
pub async fn updater_install_beta(app: AppHandle) -> Result<(), AppError> {
    #[cfg(desktop)]
    {
        use tauri::Manager;

        let update = take_pending(&app.state::<PendingBetaUpdate>().0)?;
        update.download_and_install(|_, _| {}, || {}).await.map_err(plugin_error)
    }
    #[cfg(not(desktop))]
    {
        let _ = app;
        Err(AppError::Other("updates are not supported on this platform".to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_beta_endpoint_is_the_updater_beta_release_manifest() {
        let url = beta_endpoint().unwrap();
        assert_eq!(url.scheme(), "https");
        assert_eq!(url.as_str(), "https://github.com/ysya/sshelter/releases/download/updater-beta/latest.json");
    }

    #[test]
    fn an_update_is_installed_at_most_once_and_otherwise_needs_a_new_check() {
        let empty: Mutex<Option<String>> = Mutex::new(None);
        assert_eq!(take_pending(&empty).unwrap_err().to_string(), NOTHING_PENDING);

        let slot = Mutex::new(Some("0.16.1-1".to_string()));
        assert_eq!(take_pending(&slot).unwrap(), "0.16.1-1");
        assert_eq!(take_pending(&slot).unwrap_err().to_string(), NOTHING_PENDING);
    }
}
