# Lunport 改名與相容性

產品名稱採用 **Lunport**，副標為 **Your SSH workspace.** GitHub 專案已由 ysya/sshelter 改名為 ysya/lunport，repository ID 1264083592 相同，origin 已更新到 git@github.com:ysya/lunport.git。

目前已發布的 Stable 仍為 SSHelter 1.0.0；Lunport 名稱準備納入下一版。未重建或覆寫 1.0.0 的標籤、說明、簽章與安裝檔，歷史驗證文件保留當時的名稱及網址。

## 改名範圍

- Records、Legacy、Keychain、Settings、同步與匯入／部署流程、MCP 審閱、CLI 提示、原生認證／信任／診斷視窗及托盤使用 Lunport。
- Production／Development 的 Tauri product name 及視窗標題分別為 Lunport／Lunport Dev；HTML title、套件說明及目前 README 同步更新。
- 新匯出的偏好檔預設名稱為 lunport-settings.json，匯入仍接受既有設定 envelope。
- 目前使用的 GitHub、relay 部署及更新通道連結改用 ysya/lunport。歷史發布收據保持原貌。
- 新標誌採 Folded L：Lunport 的 L 與連線入口形成兩塊幾何輪廓，切角比例一致。app icon 使用深藍底與兩階藍色；Records、Legacy 及開啟工作區畫面共享同一份單色符號，顏色隨介面主題調整。favicon、macOS ICNS、Windows ICO／Store 圖示及 Linux PNG 同步更新。
- macOS 選單列使用獨立的透明單色圖示，避免 app icon 的底色變成方塊；Windows／Linux 托盤使用彩色 app icon。原始幾何位於 src/brand/lunport-mark.json，執行 node scripts/generate-brand-icons.mjs 可由專案鎖定的 Tauri CLI 重建所有平台圖示。

## 既有使用者的相容性

- Application identifier、資料路徑、金鑰圈服務、localStorage key、SSH include／agent／slot 路徑、IPC／crypto context 保持原值。沒有遷移或改寫使用者資料，也沒有重新授權同步、MCP 或私鑰分享。
- 登入啟動項目使用原本的名稱。sshelter、sshelter.exe 及 Windows sshelter-cli.exe 保留，讓已儲存的 MCP 與終端機指令能繼續使用。
- Windows 的 NSIS／MSI 保留舊 registry identity、原安裝位置與 MSI UpgradeCode；Production 和 Development 維持隔離。安裝器範本來源、授權與差異見[說明](../src-tauri/installers/README.md)。
- Linux DEB 以 Provides／Conflicts／Replaces、RPM 以 Provides／Obsoletes 取代舊的 ss-helter 套件；Development 使用獨立的 ss-helter-dev 名稱。
- 舊的 Stable／Beta 更新網址已實際下載比對，與原收據相同；9 個舊套件下載網址均可取得正確的內容片段，對應簽章亦相同。1.0.0 的 20 個 asset ID／名稱／大小／digest 及標籤來源不變。見[repository 改名收據](rebrand/2026-10-17/repository-rename.json)。
- 保留舊 repository 名稱的轉址；不要另外建立新的 ysya/sshelter 專案，以免中斷舊版更新連結。

## 驗證

- 前端 84 檔／1,071 案例、TypeScript 與 production build 通過。更新 GitHub 連結後再驗證相關前端測試與建置。
- 本機完整安全 Rust 測試首次為 2,600 passed／1 failed／10 filtered，失敗為測試預期字串中換行後的舊品牌漏改；已修正，重跑相關回歸及更新／profile 測試。跳過真實金鑰圈寫入及 PAM 案例。
- 跨平台完整 CI、Windows 兩種安裝器的實際舊版升級，以及 Linux DEB／RPM 的套件取代檢查待完成。這些檢查不發布新版本。
- macOS Development 原生名稱及啟動驗收待完成；Windows／Linux 的逐畫面人工驗收不包含在套件升級測試內。
