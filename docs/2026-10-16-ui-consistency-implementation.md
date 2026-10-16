# SSHelter 介面一致性實作紀錄

第一批將共用工作區、側欄動態與 Hosts／Keys 的列表和詳情落實到正式前端元件；第二批統一表單、流程頁與獨立決策視窗。完整改版方向見[設計規格](superpowers/specs/2026-10-16-ui-consistency-design.md)。

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

## 開發預覽

啟動既有 Vite 開發伺服器後，開啟 `/dev-preview.html`。入口使用真實的 RecordsWorkspace 與假資料 adapter，可操作側欄、搜尋、主機與金鑰詳情、設定、假資料金鑰產生、匯入及同步建立流程。檔案選擇只回傳 `/fixture/config`，同步代碼明確標示 DEMO ONLY。

額外情境：`?scenario=sync-review`、`sync-pending`、`hostkey`、`hostkey-changed`、`authentication`、`authentication-expired`、`approval`。獨立視窗情境只渲染正式元件及示範問題，回答不會呼叫 native backend。

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

## 後續工作

這兩批沒有完成整份改版規格。Legacy 周邊頁面、設定各分類的細部整理、部署等次要流程的全面視覺驗收，以及完整跨平台原生驗收，仍依原規格的後續工作包進行。詳情欄已有雙向內容轉場；欄位寬度在選取／關閉時仍立即切換，以免與手動調寬或單欄焦點返回互相干擾。

目前的畫面驗證來自假資料瀏覽器入口，尚不能替代 macOS WebView、Windows 與 Linux 的原生驗收，也未進行真實伺服器連線或同步操作。
