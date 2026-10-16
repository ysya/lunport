### Spec Compliance

- ✅ 已核對的 Task 4 規格符合。審查固定 BASE `e8b8da06faeaa70d840a04b329015aaebd13ae8b` → HEAD `246bd5677094fca25da3631878673ec3eafa38b9` 的 14 檔案 diff；未發現 Missing／Extra／Misunderstood 的阻擋項目。
- ✅ 實際 AI pane 透過 Records effective payload 與 scope-aware Group path 顯示 endpoint／穩定 ID；授權仍逐 Host ID 呼叫，不新增 Group grants：`src/components/SettingsDialog.tsx:116`, `src/components/SettingsDialog.tsx:124`, `src/components/SettingsDialog.tsx:934`。
- ✅ Auto-log selection 僅開風險確認；具體警告及 checkbox 之後才帶 acknowledgement 呼叫 native mutation。Ask 直接切回；Legacy 清楚維持 Ask：`src/components/SettingsDialog.tsx:848`, `src/components/SettingsDialog.tsx:856`, `src/components/SettingsDialog.tsx:886`, `src/components/SettingsDialog.tsx:902`, `src/lib/mcp-flow.ts:18`, `src/lib/mcp.ts:56`。
- ✅ 平台 notice 使用 native DTO；文案不承諾 Auto-log 補 credentials／2FA／host trust，hidden-launch 說明限於一般 background sync。Advanced 說明未宣稱尚未實作的 Task 5 deployment：`src/components/SettingsDialog.tsx:150`, `src/components/SettingsDialog.tsx:861`, `src/components/SettingsDialog.tsx:864`, `src/components/SettingsDialog.tsx:868`。
- ✅ latest 10 audit 同時呈現 client／mode／authorization、actual ended、nullable exit／signal 及 persistence error，未把 allowed 視為執行成功：`src/components/SettingsDialog.tsx:961`, `src/components/SettingsDialog.tsx:964`, `src/components/SettingsDialog.tsx:970`, `src/components/SettingsDialog.tsx:976`。
- ✅ OS-observed requester 與 self-reported clientInfo 分開，clientInfo 顯示端再次限 100 Unicode codepoints／reveal hidden characters：`src/components/McpAttribution.tsx:5`, `src/components/McpAttribution.tsx:16`, `src/components/McpAttribution.tsx:20`。
- ✅ Records branch 掛載 approval；卡片捕捉 immutable candidate，DialogContent／Card 皆按 request ID remount，Deny 有預設焦點；Allow 有 guard／expiry，完整 command 與 target／route／attribution 保留同一候選：`src/App.tsx:398`, `src/components/McpApprovalDialog.tsx:31`, `src/components/McpApprovalDialog.tsx:48`, `src/components/McpApprovalDialog.tsx:70`, `src/components/McpApprovalDialog.tsx:83`, `src/components/McpApprovalDialog.tsx:115`, `src/components/McpApprovalDialog.tsx:123`。
- ✅ 認證 feed 先 listen 再 fetch，revision 拒絕舊 fetch 覆蓋新 event；late registration 與 unmount 皆清 listener／拒絕 publish：`src/lib/authentication.ts:16`, `src/lib/authentication.ts:24`, `src/lib/authentication.ts:28`, `src/lib/authentication.ts:35`, `src/lib/authentication.ts:39`。
- ✅ 認證 prompt 經 React text escaping，可信 hop 與不可信 server prompt 分區；echo 決定 text／password，Cancel 預設焦點；回答及 expiry/status 區在 scrollable main 之外、footer 之上：`src/components/AuthenticationWindow.tsx:39`, `src/components/AuthenticationWindow.tsx:51`, `src/components/AuthenticationWindow.tsx:61`, `src/components/AuthenticationWindow.tsx:68`, `src/components/AuthenticationWindow.tsx:80`, `src/components/AuthenticationWindow.tsx:97`。
- ✅ `remaining_ms` 在 receipt 建立 wall／monotonic deadline，same-ID refresh 只縮短；question ID remount 清前答；expire／consume／unmount 清 answer，IPC 前設 abandoned；error 不顯示原生訊息／舊答，無自動 replay：`src/lib/mcp-flow.ts:29`, `src/lib/mcp-flow.ts:55`, `src/components/AuthenticationWindow.tsx:104`, `src/components/AuthenticationWindow.tsx:134`, `src/components/AuthenticationWindow.tsx:138`, `src/components/AuthenticationWindow.tsx:145`, `src/components/AuthenticationWindow.tsx:189`。此處只確認 JS reference 清除與不重送，沒有 JS string zeroization 保證。
- ✅ entrypoint 使用既有 authentication native label，保留 approval／hostkey／main routing：`src/main.tsx:27`, `src/main.tsx:28`, `src/main.tsx:29`。

### Strengths

- 權限模式與人類回答均保持 native authority，UI 不以 optimistic policy 代替 backend mutation；native acknowledgement payload/cache response 有 IPC 邊界回歸：`src/lib/mcp.ts:56`, `src/lib/mcp.test.ts:30`。
- 對 request replacement、舊 snapshot race 與秘密重送分別用 keyed candidate、revision、single-consume state 解決，沒有增加依賴或全域秘密儲存：`src/components/McpApprovalDialog.tsx:70`, `src/lib/authentication.ts:24`, `src/lib/mcp-flow.ts:55`。
- 新測試驗證 effective endpoint／nested Group path／latest10 unknown exit，以及 echo／expired input／nullable cancel 等具體輸出與狀態轉移，沒有只斷言 mock 存在：`src/components/McpPane.test.tsx:48`, `src/components/McpPane.test.tsx:62`, `src/components/McpQuestions.test.tsx:76`, `src/lib/mcp-flow.test.ts:23`, `src/lib/mcp.test.ts:44`。

### Issues

#### Critical (Must Fix)

- 無。

#### Important (Should Fix)

- 無。

#### Minor (Nice to Have)

- `src/components/McpQuestions.test.tsx:24`, `src/components/McpQuestions.test.tsx:45`, `src/components/McpQuestions.test.tsx:66`, `src/lib/mcp-flow.test.ts:23`：目前問題卡的測試直接 SSR View、檢查 autofocus markup，生命週期相關測試則測純 helper。這些能確認 rendered output 與狀態算法，但不能直接保護「實際 Card IPC 前清空」、「舊 answer 在 request-ID transition 不被重新提交」、「焦點從 Allow 移至新 request 的 Deny」等 component wiring。程式碼已有對應防護，因此為覆蓋改善；後續宜加入 mounted Card／dialog interaction regression，或保存 controller 實際互動證據。
- `.superpowers/sdd/2026-10-14-groups-mcp-completion/task-4-report.md:49` 的 Vite build evidence 保留 >500 kB chunk advisory；此為 controller 已指定的 baseline advisory，未列為新 blocker，亦不把輸出稱作 warning-free。

### Cannot Verify / named checks

- ⚠️ 480×360 authentication（含 4096-character prompt／長 hop）、1100×720／800×560 主視窗的 actual-component 布局及 horizontal overflow，仍由 controller 的 fake-bridge fixture QA 給最終證據；此審查沒有啟動瀏覽器、改真實 grants 或讀 credentials。
- ⚠️ browser/native 焦點 transition、native close→deny_all、OS credential UI／SSH、Windows behavior、真實 suspend/resume 無法由本 diff／SSR 證實。不得把 SSR autofocus 或 fake IPC tests 稱作原生 OS 測試。
- 具名契約風險檢查「frontend invoke／DTO 與 Task 3 不一致」：讀 `task-3-report.md:35`–`83` exact frontend contract 及 `task-3-report.md:210`–`214` fix1 handoff；核對 camelCase invokes、snake_case DTO、question.id、relative remaining_ms、Windows-only noninteractive credentials 及已修正的 hidden Space-pin 語義。未讀取其他 Task 3 implementation diff、未重跑 backend suites。
- 具名整合風險檢查「authentication entrypoint 缺少 native window／permission／command registration」：檢查 `src-tauri/capabilities/authentication.json:4`–`6`（label／core:default）、`src-tauri/src/session/auth_window.rs:238`–`257`（empty pending destroy、index.html、480×360、event target）、`src-tauri/src/session/auth_window.rs:260`–`273`（auth commands／backend Zeroizing）及 `src-tauri/src/lib.rs:330`–`332`（invoke registration）。未新增 native permission，前端不呼叫 clipboard／filesystem／credential plugin。
- 已讀驗證 evidence，未重跑測試或 git：`/private/tmp/sshelter-task4-focused-final.log` 5 files／20 passed；`/private/tmp/sshelter-task4-full-suite-final.log` 71 files／997 passed；`/private/tmp/sshelter-task4-tsc-final.log` 無診斷；`/private/tmp/sshelter-task4-build-final.log` build 成功並保留上述 advisory。
- Diff 初次工具輸出中段被 transport 截斷，因此補讀固定 diff 的未顯示區間；未另讀任何 changed source file，未執行 git commands／branch-wide security scan。

### Assessment

**Task quality:** Approved（已核對 source／契約範圍；controller mounted/native QA 限制如上）。

**Reasoning:** 規格範圍的 mode、immutable approval、public audit 與 native auth UI 行為皆有清楚對應實作，未發現 Critical／Important 問題。測試證據充分支援 helper／SSR／IPC 行為；實際焦點及原生環境邊界仍需 controller 最終驗證，不能由本報告推定已完成。
