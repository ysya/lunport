//! Beta 更新頻道(spec:docs/superpowers/specs/2026-10-01-update-channels-design.md §3.2)。
//! Stable 頻道沿用前端 `@tauri-apps/plugin-updater` 的 `check()`(讀 tauri.conf.json 的網址);
//! 這裡只處理 Beta:以 `updater_builder().endpoints(...)` 改讀 `updater-beta` release 的清單。
//! 簽章驗證與「遠端版本較新才更新(不降版)」沿用 plugin 預設。

use std::sync::Mutex;

use serde::Serialize;
use tauri::{ipc::Channel, AppHandle, Url};

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

/// 下載進度事件。格式同 plugin 自己的 `DownloadEvent`(tag = "event"、content = "data"、欄位 camelCase),
/// 前端兩個頻道才能用同一套處理顯示下載進度。
#[derive(Clone, Debug, PartialEq, Serialize)]
#[serde(tag = "event", content = "data")]
#[cfg_attr(test, derive(ts_rs::TS))]
#[cfg_attr(test, ts(export, export_to = "../../src/bindings/"))]
pub enum UpdateDownloadEvent {
    /// 第一個資料塊到了;`content_length` 是伺服器給的總大小(沒給就是 null)。
    #[serde(rename_all = "camelCase")]
    Started {
        #[cfg_attr(test, ts(type = "number | null"))]
        content_length: Option<u64>,
    },
    /// 又收到一個資料塊。
    #[serde(rename_all = "camelCase")]
    Progress { chunk_length: usize },
    /// 下載完了,接著驗證簽章並安裝。
    Finished,
}

/// 把 plugin 的下載回呼轉成給前端的事件,順序同 plugin 自己的 `download_and_install` 指令:
/// 第一個資料塊先送 Started(帶總大小),每個資料塊送 Progress,下載完送 Finished。
fn download_callbacks<'a, F>(send: &'a F) -> (impl FnMut(usize, Option<u64>) + Send + 'a, impl FnOnce() + Send + 'a)
where
    F: Fn(UpdateDownloadEvent) + Sync,
{
    let mut started = false;
    let on_chunk = move |chunk_length: usize, content_length: Option<u64>| {
        if !started {
            started = true;
            send(UpdateDownloadEvent::Started { content_length });
        }
        send(UpdateDownloadEvent::Progress { chunk_length });
    };
    let on_finish = move || send(UpdateDownloadEvent::Finished);
    (on_chunk, on_finish)
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

/// 下載並安裝 `updater_check_beta` 暫存的更新(簽章由 plugin 驗證),下載進度經 `on_event` 送給前端;
/// 重開 app 由前端 `relaunch()` 負責。
#[tauri::command]
pub async fn updater_install_beta(app: AppHandle, on_event: Channel<UpdateDownloadEvent>) -> Result<(), AppError> {
    #[cfg(desktop)]
    {
        use tauri::Manager;

        let update = take_pending(&app.state::<PendingBetaUpdate>().0)?;
        // 進度送不出去(例如視窗已關)不影響安裝,同 plugin 自己的做法。
        let send = |event: UpdateDownloadEvent| {
            let _ = on_event.send(event);
        };
        let (on_chunk, on_finish) = download_callbacks(&send);
        update.download_and_install(on_chunk, on_finish).await.map_err(plugin_error)
    }
    #[cfg(not(desktop))]
    {
        let _ = (app, on_event);
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

    #[test]
    fn download_events_have_the_updater_plugins_own_shape() {
        // 同 tauri-plugin-updater 2.10.1 commands.rs 的 DownloadEvent,前端兩個頻道才能用同一套處理。
        let json = |event: UpdateDownloadEvent| serde_json::to_string(&event).unwrap();
        assert_eq!(
            json(UpdateDownloadEvent::Started { content_length: Some(48_000_000) }),
            r#"{"event":"Started","data":{"contentLength":48000000}}"#
        );
        assert_eq!(
            json(UpdateDownloadEvent::Started { content_length: None }),
            r#"{"event":"Started","data":{"contentLength":null}}"#
        );
        assert_eq!(
            json(UpdateDownloadEvent::Progress { chunk_length: 16_384 }),
            r#"{"event":"Progress","data":{"chunkLength":16384}}"#
        );
        assert_eq!(json(UpdateDownloadEvent::Finished), r#"{"event":"Finished"}"#);
    }

    #[test]
    fn a_download_reports_started_once_then_every_chunk_then_finished() {
        let sent = Mutex::new(Vec::new());
        {
            let send = |event: UpdateDownloadEvent| sent.lock().unwrap().push(event);
            let (mut on_chunk, on_finish) = download_callbacks(&send);
            on_chunk(100, Some(300));
            on_chunk(200, Some(300));
            on_finish();
        }
        assert_eq!(
            sent.into_inner().unwrap(),
            vec![
                UpdateDownloadEvent::Started { content_length: Some(300) },
                UpdateDownloadEvent::Progress { chunk_length: 100 },
                UpdateDownloadEvent::Progress { chunk_length: 200 },
                UpdateDownloadEvent::Finished,
            ]
        );
    }
}
