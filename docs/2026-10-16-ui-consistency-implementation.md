# SSHelter 介面一致性實作紀錄

第一批將共用工作區、側欄動態與 Hosts／Keys 的列表和詳情落實到正式前端元件；第二批統一表單、流程頁與獨立決策視窗；第三批重新整理設定架構，並延伸到 Legacy 和次要表面。完整改版方向及第三批覆蓋表見[設計規格](superpowers/specs/2026-10-16-ui-consistency-design.md)。

## 已實作

- 共用 PageHeader、頁面留白、字級及 motion tokens；Hosts、Keys、Sync、Import 採用相同頁首規則。
- 側邊欄展開／收合，220ms 寬度轉場與文字淡入淡出；記住側欄狀態，收合時提供有名稱的圖示入口與 tooltip。
- Group 的獨立 disclosure、子樹開合與箭頭動畫；收起內容立即 inert，Records Group 狀態與 Legacy 檔案群組分開保存。
- Hosts 預設列表並記住檢視偏好；首頁的群組導覽集中在側欄，Group 頁仍可瀏覽子群組。
- Keys 的搜尋、列表與共用詳情欄；保留既有下載、部署、複製及分享審閱的控制條件。
- 金鑰新增／匯入對話框、草稿丟棄確認及焦點還原；搜尋和新增快捷鍵依目前主機／金鑰頁執行。
- 設定視窗的內容寬度、視窗邊界和返回焦點；Records 模式使用 Local data 名稱。
- Appearance 的 System／Reduced 動態偏好，初始畫面就套用；System 同時遵循 OS reduced motion。
- Reduced 模式使用近乎即時的單次動畫，保留 Radix Presence 的關閉事件，避免切換偏好時殘留選單或遮罩。

## 第二批實作

- 共用 FormSection、ActionBar、EditorHeader 和 WorkflowSteps；統一區塊標題、說明、欄位高度、分隔線與按鈕排列。
- 主機與 Group 編輯器共用標頭、可捲動內容及固定底部操作列。保留繼承、格式升級、草稿、刪除與連線的既有條件；移除兩套重複樣式。
- Group 選用設定改用共用 Disclosure，展開與收合皆有轉場，收起內容立即 inert。
- Import 使用「Choose source → Review → Finish」。候選主機改為分隔清單，私鑰複製依舊逐項勾選且預設不選；保留 token、已提交預覽和 pending import 的續作邏輯。
- Sync 使用相同流程頁結構，區分 relay、裝置與 library sync；保留私密代碼在元件記憶體、格式升級同意、名稱審閱與 setup recovery。遷移頁也套用相同頁首、步驟、審閱區及操作列。
- 獨立 HostKey、Authentication、AgentApproval 視窗共用 DecisionLayout，內容可捲動，回應欄與決策按鈕保持可見。認證畫面優先呈現伺服器與提示，技術 ID 收入 Connection details；原有 arming、busy、expiry 及回答條件保留。
- 詳情欄關閉增加 120ms 淡出，退出內容立即 inert／aria-hidden，選取與焦點立即返回列表。動畫結束移除內容，280ms fallback 處理事件未送達；新開啟會取消舊的退出清理。拖曳調寬不套用寬度動畫。
- 補齊未儲存確認的 Keep editing 與離開焦點、同步建立／取消／代碼／續作／審閱完成焦點，以及匯入檢查／完成／取消焦點。

## 第三批：設定與 Legacy

- 設定保留獨立視窗，改為 Application／Workspace／Maintenance 三組導覽。標頭顯示 Records library 或 OpenSSH files；標題與導覽固定、內容獨立捲動，小視窗改為水平分類。
- 導覽與搜尋共用模式索引。Records 使用 General、Appearance、Connections、Local data、AI access、Updates、Diagnostics；Legacy 保留 Files & backups、Sync、Discovery & checks。搜尋結果包含分類、說明及區塊跳轉，支援 Enter、Escape、⌘/Ctrl+F；分類支援方向鍵、Home／End，主題使用可鍵盤操作的 radio group。
- 偏好匯入／匯出集中在資料分類，診斷 log 集中到維護分類。Records 的 Import／Sync 是現有流程的入口，不再重複列出 Sync 設定分類。語言呈現為唯讀資訊，移除無法操作的 select。
- SettingsRow 的說明、語意分組、字級、控制項尺寸及窄內容換行一致；補齊終端機、備份與檢查間隔的控制項名稱。共用 Section 使用真正的章節標題，替代各頁不同的全大寫小字。
- Config path 草稿跨分類與搜尋保留，關閉前確認，Keep editing 回到原欄位；只有載入成功才儲存路徑。載入期間關閉暫停並顯示狀態，避免把已提交的載入誤當成可丟棄草稿。Legacy Sync 在設定視窗開啟期間保留其表單狀態，關閉後卸載。
- AI access 補上依名稱、目的地、ID、Group 搜尋主機權限，以及顯示／允許數量；狀態讀取失敗提供重試。Ask／Auto-log、逐主機權限與風險確認沿用既有條件。
- 新增共用 TaskDialogContent／TaskDialogBody：固定標頭與操作列、單一主要內容捲動。檔案檢視、備份、known_hosts、探索、lint、Legacy 新增主機／檔案／複製、兩種部署、同步審閱／遷移／升級／金鑰／space 輔助、Keychain 浮層及 MCP 審閱接上同一骨架。
- AlertDialog 共用可捲動的長內容與固定確認列，保留 Radix 的標題關聯、取消焦點及事件。已確認 config 草稿的 Keep editing，以及 MCP／同步／私鑰相關既有測試仍通過。
- Legacy 與 Keychain 的頁首、章節、編輯操作及留白接上共用規則。Legacy 的儲存列跟隨實際側欄寬度；遷移入口移到側欄底部，確認改用 Radix focus trap，初始焦點為 Keep editing。
- Legacy 檔案／標籤群組、Keychain 其他金鑰檔案、effective config 使用共用 Disclosure；收合內容立即 inert。列表與儲存列改用共用 motion tokens。
- known_hosts、備份、探索、lint、檔案檢視讀取失敗不再顯示為空資料，均提供明確錯誤與 Retry。Records 部署補上 Target／Review／Result，完整路由仍在捲動內容中，授權和取消／確認留在固定操作區。

### 本批覆蓋結果

| 範圍 | 實作 | 驗證 |
| --- | --- | --- |
| 設定資訊架構及各分類 | 完成兩模式分類、搜尋、控制項及生效說明 | Records 7 分類、Legacy 8 分類瀏覽器操作；模式邊界測試；macOS 原生搜尋與設定 |
| Legacy 工作區及 Keychain | 完成頁首、章節、操作列及 disclosure | 主機編輯、側欄調寬與儲存列對齊、金鑰詳情與新增表單；沿用功能測試 |
| 檔案及診斷工具 | 完成共用任務視窗與錯誤／重試 | 800×560、17px、dark／Reduced 下六種工具／新增畫面；五種讀取失敗 |
| 部署與決策 | 完成共用容器、審閱與固定操作區 | 16 層示意部署路由；MCP、部署、account、同步、keychain 既有測試；保留所有提交條件 |
| 同步及資料維護輔助 | 完成章節、Task dialog 及確認浮層 | Legacy Sync 草稿切頁保留；現有 migration／review／key／code／space 測試 |

## 開發預覽

啟動既有 Vite 開發伺服器後，開啟 `/dev-preview.html`。入口使用真實的 RecordsWorkspace 與假資料 adapter，可操作側欄、搜尋、主機與金鑰詳情、設定、假資料金鑰產生、匯入及同步建立流程。檔案選擇只回傳 `/fixture/config`，同步代碼明確標示 DEMO ONLY。

額外情境：`?scenario=sync-review`、`sync-pending`、`hostkey`、`hostkey-changed`、`authentication`、`authentication-expired`、`approval`。獨立視窗情境只渲染正式元件及示範問題，回答不會呼叫 native backend。

第三批增加 `?scenario=legacy`，使用正式 App 的 Legacy 分支及純記憶體示意讀取；`&failure=known_hosts_list`、`config_list_backups`、`discover_hosts`、`config_lint`、`config_read_file` 可重現讀取失敗。Config path 輸入 `/fixture/slow-config` 會模擬 1.5 秒載入，用於驗證 busy 關閉保護；不讀取該路徑。預覽支援 Records 部署的公開預覽，不執行遠端安裝。

入口只允許 development browser；偵測到既有 Tauri bridge 時拒絕啟動。adapter 不呼叫原生檔案、SSH、vault、relay 或更新安裝，未支援的操作明確拒絕。它不屬於預設 production build 的入口。

修改開發入口本身時會完整重載假資料 backend，避免重複安裝 bridge；一般元件修改仍沿用 HMR。

## 已驗證

- TypeScript 檢查與 Vite production build 通過；production 產物不含開發預覽入口及假資料 adapter。
- 前端 82 個測試檔、1,063 個案例通過，包含新增的導覽可及性與狀態持久化案例。
- 瀏覽器檢查：800×560、1100×720 及預設桌面視窗；light／dark，15px／17px，System／Reduced 動態。
- 側欄快速反向開合、群組收起後 inert、主機與金鑰詳情在小視窗的返回與焦點、金鑰搜尋快捷鍵、草稿保留與丟棄、假資料產生成功、詳情欄鍵盤調寬與重設。
- Reduced 切換後選單可正常卸載；頁面沒有橫向溢出。
- 第二批瀏覽器操作：主機草稿 Keep editing／Discard 的焦點還原、Group 選用設定開合、匯入預覽與未選金鑰的完成結果、同步建立及保存代碼、名稱衝突審閱與續作完成。
- 詳情欄在 System／Reduced 下關閉與重開，主機與金鑰都只有一個開啟的詳情欄；800×560、17px、dark／Reduced 下，單欄返回焦點、編輯器操作列及橫向邊界正常。
- 獨立視窗瀏覽器尺寸：HostKey 480×320、Authentication 480×360、AgentApproval 460×340；按鈕保持可見，較長的指紋內容可捲動。
- Beta 14 發布前另完成 macOS Development 原生 bundle／WebView 檢查：1100×720、15／17px、System／Reduced、側欄、詳情返回焦點、編輯器、設定及正常退出。macOS／Linux／Windows 的固定來源 CI 通過；Windows 原生啟動檢查使用 placeholder 前端，並不代表完整 React 畫面驗收。詳見[Beta 14 驗證](releases/1.0.0-14-validation.md)。
- 第三批 TypeScript、production build 及 83 檔／1,066 案例通過；正式產物排除兩個 development fixture 模組。保留既有 Vite chunk size 提示。
- 第三批瀏覽器代表矩陣：800×560／17px／dark／Reduced（設定各分類、長清單、部署）；1100×720／15px／light／System（Legacy 各分類、主機、Keychain、草稿與焦點）；1440×900／13px／light／System（設定版型）。這是代表性覆蓋，不表示每個狀態都遍歷完整笛卡兒積。
- Config path 草稿經分類與搜尋返回仍保留；Keep editing 焦點還原；慢速載入時 Escape 不關閉、關閉按鈕暫停、完成後可操作；Legacy Sync relay 草稿切頁保留。Legacy 檔案群組收起後 `inert`／`aria-hidden`，儲存列左側與調整後側欄右側同為 345px。
- 第三批 macOS Development bundle 可啟動，實際 WebView 的搜尋跳轉、分類切換、15／17px、System／Reduced、選單卸載、關閉後返回 Settings 焦點均通過；偏好還原為 System theme／15px／System motion，正常退出。未在原生環境切入 Legacy 或執行遠端操作。
- [第三批驗收收據與截圖](ui-review/2026-10-16-settings-legacy/validation.json)，[macOS 原生設定畫面](ui-review/2026-10-16-settings-legacy/macos-native-local-data.jpg)。

## 後續工作

第三批已將設定、Legacy 周邊與次要流程接上共用介面系統。仍需 Windows／Linux 逐畫面原生驗收，以及各平台使用真實 SSH／relay 的完整任務驗證；瀏覽器與 macOS 設定檢查不代替這些工作。詳情欄已有雙向內容轉場；欄位寬度在選取／關閉時仍立即切換，以免與手動調寬或單欄焦點返回互相干擾。

主要畫面矩陣來自假資料瀏覽器入口，並補上 macOS Development WebView 檢查；Windows 與 Linux 的逐畫面原生視覺驗收仍待完成，也未透過這些介面執行真實伺服器連線或同步操作。
