# Windows Beta 12 啟動閃退後續

使用者已確認原本 Library sync 失敗的電腦更新後可成功同步；另一台 Windows 的 Beta 12 在開啟時直接退出，並非按 Sync 才退出。所提供的 10000／10010 為事件識別碼，尚無事件來源、SSHelter 例外代碼、故障模組或 crash dump，不能以此確認特定根因。

## 已確認的程式路徑與修補

- 原本 setup 在啟動背景同步與 broker 後才建立初始 tray；背景 Records status 同時會取得／建立原生 tray。Tauri 2.11.2 的 `tray_by_id`／`TrayIcon::clone` 會在呼叫執行緒複製 tray-icon 0.23.1 的 `Rc<RefCell<_>>`。原本 background status 與 visibility command 的 native handle 複製／釋放會跨執行緒，不能僅因 `set_menu` 內部派送到主執行緒就視為整段安全。
- 初始 tray 現在先於背景 worker 建立。整次 lookup、建構、安裝、visibility 與 native handle drop 放在事件迴圈的一次主執行緒工作中，跨執行緒只傳公開選單資料。相同 ID／標籤／enabled 清單不重建；主機或可連線狀態改變仍更新。原生 tray 初始化失敗不再阻擋主視窗啟動。
- 鎖定 muda 0.19.3 的相容 patch，包含 [Windows dangling pointer 修正](https://github.com/tauri-apps/muda/pull/363)。此上游修正的 window-menubar 情境與 SSHelter tray 啟動競態不同，**沒有把上游 issue 當作這台電腦已證實的 crash 根因**。
- 不改變 Records、SSH config、pin 核准、既有 session、草稿或金鑰授權規則。Records 編輯／同步仍只保存 SSHelter 資料，Legacy 工作區仍有其原本的 SSH config 編輯行為。

## 本機診斷

- GUI 入口在 Tauri context 建立前安裝 logger。app.log 為 JSON Lines，記錄時間、PID、版號、profile、平台、啟動階段與固定錯誤分類；同步起訖／失敗、tray 錯誤、GUI build 失敗與 Rust panic 都有事件。panic 記錄編譯程式位置與 backtrace，省略 payload。一般錯誤不序列化 Display 字串；IO 只記 error kind／OS code。不能從 `operation_failed` 的分類反推完整 relay 錯誤。
- 不記錄 hosts、Groups、SSH／MCP 命令、連線結果、環境變數、密碼、私鑰或同步碼，不上傳任何 log。backtrace 可能含編譯時的程式來源路徑。
- 每個 log 檔 256 KiB 上限，保留目前檔及 `.1`、`.2` 兩代，單筆事件最多 32 KiB。重啟接續保留紀錄，正常退出有 exit 階段。Unix 新檔 0600／目錄 0700，拒絕 log symlink 及 Windows 最終檔案／診斷目錄 reparse point；無法寫 log 不阻止啟動。
- Windows 另預先開啟 native-crash.log。未處理原生例外 filter 只以固定 buffer／Win32 WriteFile 記錄例外代碼、位址與階段編號，不配置 heap、不取得 mutex、不寫記憶體 dump。會轉交原有 filter，或回傳 EXCEPTION_CONTINUE_SEARCH，保留 Windows 原本的處理。原生 filter 可能被其他 runtime 覆寫；fast-fail、kill、嚴重 stack 損壞與 WebView2 子程序 crash 不保證可捕捉。[Windows 官方限制](https://learn.microsoft.com/en-us/windows/win32/api/errhandlingapi/nf-errhandlingapi-setunhandledexceptionfilter)。
- Windows 的一般 GUI build error 顯示不依賴 WebView2 的原生提示與 log 路徑；背景 client-started host 不彈出此提示。`ready` 僅表示 setup 已完成，**不是 WebView／GPU 正常繪圖的證明**。
- 設定 → General → Data → Diagnostic logs → Open logs 可開啟目前 profile 的診斷資料夾。

正式 Windows：`%LOCALAPPDATA%\org.homelab.sshelter\diagnostics`；Development 使用 `org.homelab.sshelter.dev`。Mac 使用 `~/Library/Application Support/<identifier>/diagnostics`。ASKPASS、CLI connect、MCP stdio 與 CoreAudio child 不經過 GUI logger 安裝，不會為 log 啟動 WebView 或解鎖憑證。

## 驗證

本次加入：

- 連續寫入跨越兩次以上輪替，逐行驗證 JSON、檔案上限與 Unix 權限；symlink 目標 config 保留原內容。
- 拋出含敏感字串的 disposable child panic，確認失敗狀態、setup 階段與程式位置／backtrace 保存，payload 不在 log，下一次寫入不抹除舊紀錄。
- Windows 獨立原生事件迴圈從儲存的 17 hosts＋繼承 Group／已啟用 Library 資料重建 runtime；實際 native tray、10 次 transport round、3 個並行 status／visibility workers 共 300 組呼叫；檢查相同選單不重建、改名可更新實際 Win32 選單、只有一個 tray resource、USER objects 有界、SSH config 不變。此測試不建立 WebView2，不能冒充正式 GUI／特定機器的人工驗收。
- Windows disposable child 透過 RaiseException 注入自訂例外，核對退出代碼與 native-crash.log；只在該 child 使用 WER_NO_UI，產品不關閉 Windows Error Reporting。
- CI-only PowerShell smoke 額外啟動真正的 Development exe 與 WebView2，讀取上述已同步 state（不匯出 MemKeychain），檢查 PID 對應 ready／exit log、原生視窗、背景更新後仍存活及正常關閉。拒絕覆蓋既有 Development state，且限定 disposable GitHub runner。此 CI 的 frontend 為 placeholder，驗證的是 bootstrap／WebView2 建立，並非 React 繪圖或正式 Windows 實機驗收。

測試結果與 Beta 發布收據待本次驗證完成後補齊。仍需回報機器實際更新後驗收；若繼續閃退，應保留 app.log／native-crash.log 與 Windows Application Error／WER 的模組及例外資料，不重建 chain、重置 vault 或刪除 sync-state.json。
