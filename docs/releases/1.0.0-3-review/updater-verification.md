# 自動檢查更新：版本與條件

2026-10-15 依實際發布原始碼核對；未讀取或操作使用者目前安裝版本、儲存的通道、更新選項或裝置安裝程序。

- Beta 1 (`22855e70c8b8fdf46b4539cadb16c4c2f1983d4f`) 的 Records 畫面缺少設定入口，也未掛載 `useSyncBackendSettings`。當時只有 `LegacyApp` 掛載，App 根節點沒有補掛。因此若使用者仍停在這版的 Records 畫面，不能靠它自動跳出這次更新；需要手動下載新版安裝一次。
- Beta 2 (`07e669a7682b4550d006e9e3ee6e1523502be424`) 已在 `RecordsWorkspace` 掛載該 hook，Beta 3 發布來源 `d1642a8b5c57dc9eb1f8e23d5c36645d5082e056` 保留。它由工作區掛載，不依賴是否開啟 `SettingsDialog`。Legacy 畫面也保留此機制。
- `src/lib/backend-settings.ts`：必須 `autoCheckUpdates` 開啟，且 `useIsDevelopment()` 已確定回報 false。首次約 5 秒後檢查；執行中每 4 小時再查，視窗取得焦點時最多每小時再查一次。相同版本的自動通知在同一次 App 執行只提示一次。
- `src/stores/settings.ts`：自動檢查預設 true，但更新通道預設 **Stable**。安裝 Beta 檔不代表此選項會自動改為 Beta；要持續收到 Beta，須保留或選擇 Beta 通道。既有已關閉自動檢查的設定不會擅自打開。
- `src/lib/updater.ts`：依儲存的通道讀取 Stable 或 Beta manifest，有更新就顯示持續通知與 **Install & restart** 按鈕。自動檢查不等於靜默安裝；須由使用者按下安裝。網路錯誤的自動檢查只記錄 console，手動檢查會呈現錯誤。
- `src-tauri/src/lib.rs` 依 profile 註冊 updater；Development 不啟用自動更新。Beta 安裝包仍是具 updater 的 Production profile。

這些結論適用於上述已掛載的正常 Records／Legacy 工作區。沒有把更新提示的 source／測試 coverage 宣稱為使用者裝置的實際下載、安裝、重啟或其他 gate 畫面的驗收。
