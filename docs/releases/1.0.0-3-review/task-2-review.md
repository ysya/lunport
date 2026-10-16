# Task 2 獨立規格與品質審查

- 審查範圍：`f6bcf98edc56f3b99591649330dc9175e7dc1464..f071333f8889f690e455c277e775e717937d588a`，16 個 frontend 路徑。
- 方法：完整差異讀取一次，依 task-2 brief/context、global constraints、completion spec §2–4 與 controller 裁定檢查；只對具體疑慮補讀相關函式及現存測試紀錄。
- 未變更產品原始碼、index、HEAD、分支或測試；本檔是唯一新增審查產物。未派遣子代理，未重跑完整套件。

## Spec verdict：Needs fixes

大部分規格已落實：Local/Space roots、巢狀 Group/Ungrouped、同 scope 選單、穩定 ID、診斷與重複 ID 可見、搜尋揭露祖先、原始值與有效值分離、七個欄位繼承、auth/key 原子處理、格式同意、草稿與 busy 切換保護、跨 workspace section 保留 editor。`operations.ts` guard 與 CommandPalette 路徑補充符合 controller 授權。

HostEditor 的 per-field controls/source 放在原欄位旁，進階繼承留在 Advanced，符合 controller 版面裁定。GroupEditor 的 defaults 位於 Connection defaults，controller 已確認其不受 HostEditor 的 Advanced 折疊裁定約束。

尚有兩個具體缺口：Group 刪除確認未固定候選 revision，以及修復 Group 的未儲存 host 草稿仍被舊診斷遮住有效預覽。詳見 Important。

### Cannot verify／明確不在本次判定範圍

- 最終 1100×720／800×560、light/dark 的實際互動截圖與 native 整合：屬 Task 6；現有 report 明確未宣稱全部完成，SSR markup 測試不能代替最終視覺驗證。
- Rust 的 persist-before-replace、Group 刪除物化、帳號格式 gate、同步收斂／opaque record 保護：屬 Task 1／整合驗證；此處只按已記錄的 DTO 契約核對 UI，不擴大審查 native 實作。
- MCP product UI、遠端主機、真實帳號／credential、release／publication：不屬 Task 2，未操作也未判定完成。
- tsc log 為空，與「沒有診斷」一致；單靠該檔無法獨立重建 shell exit code，因此 exit 0 是執行者 report 的紀錄，並非本 reviewer 再執行確認。

## 具體優點

- `inheritance.ts:17` 的 toggle 只改選取欄位；`editor.ts:84` save 直接 clone raw draft，schema-2 空 extension 省略。`groups.test.tsx:45` 實際 wrapper payload 與真實 HostEditor markup 同時驗證 `fallback` 被保留、`ops`/Operations 顯示，以及 disabled effective control。
- `group-tree.ts:16` 統一處理 cycle、32 層、missing/duplicate ID 與跨 scope；tree 留下 diagnostics，selection 不從重複 ID 任選。搜尋與 expansion 狀態分開，搜尋祖先有 literal regression。
- `group-editor.ts:55` 對 dirty／removed draft 保留 payload 和 CAS revision；native failure 不改 draft。Group scope 不可在既有 editor 修改，auth/key default 以單一物件 patch。
- `HostEditor.tsx:124`、`GroupEditor.tsx:150` 依 Local/shared 格式要求開啟同意視窗；既有 schema-2 呼叫不新增未提供的 consent 欄位。對話框以 Keep editing 為 default focus。
- `operations.ts:14` 共用連線 guard 對 stale ready + group_error fail closed，測試確認零 IPC；CommandPalette 加入 Group path 並走相同 guard。

## Critical

無。

## Important

### 1. [P2] 刪除確認期間 overview 刷新會更換已確認候選的 CAS token

- 位置：`src/components/records/GroupEditor.tsx:538`、`:580`；`src/components/records/group-editor.ts:62`。
- 可達情境：開啟一個已儲存、沒有 dirty draft 的 Group，按 Delete group 開啟確認；另一個裝置修改該 Group，overview 在確認視窗開啟期間刷新。`deleting` 只有 boolean；effect 仍呼叫 `refreshGroupEditor`，pristine state 因而重新 `beginGroupEditor(group)`，換成新 revision。Confirm delete 隨後直接使用當下 `state.revision`，因此可能成功刪除開啟確認時尚未審閱的新版 Group，而非以原 token 觸發 CAS conflict。
- 影響：削弱 global constraints 的 immutable candidate/CAS 保護及刪除確認的審閱邊界。Hosts 雖由 native 保留，仍可能刪除同步新增的 Group 設定；不能因資料保留就視為安全候選固定。
- 建議：開啟確認時保存 `{id, revision, counts}` 的 immutable candidate；確認只送該 token。候選若過期，讓 CAS 拒絕並保留草稿／要求重新確認。新增真實 component 的「確認開啟 → overview rerender → confirm」測試。現有 `groups.test.tsx:320` 只是直接呼叫 wrapper 並核對傳入 revision，沒有驗證這個 UI 刷新情境。

### 2. [P2] 已儲存 Group 診斷遮住修復後的草稿有效值與來源

- 位置：`src/components/records/HostEditor.tsx:175`、`:200`。
- 可達情境：已儲存 host 帶有 missing／cross-scope／opaque Group 的 `group_error`；使用者在 editor 將 Group 改成同 scope 的有效 Group，或 detach 成 Ungrouped 並保留 app-default inheritance。`previewInheritance` 已按新的 `state.payload` 算出有效值，但下一行無條件以原 `host.group_error` 覆蓋 `preview.error`。因此直到 save 成功前，繼承控制仍空白／Unavailable，provenance 仍顯示 Effective value unavailable，無法審閱這次修復會使用的 settings。
- 影響：違反 changed-unsaved-selection 的 draft preview／effective source 要求，尤其是使用者修復 Needs review host 時最需要預覽的情境。Connect 仍應根據 saved diagnostic 被禁止，這個安全 guard 沒有問題。
- 建議：將 saved connection diagnostic 與 draft preview diagnostic 分離。若草稿的 resolution inputs 已改變，展示按草稿計算的 preview；只有仍依賴不可讀 saved winning data 時阻止 preview。保留 saved connection guard，新增「broken saved Group → valid draft Group」及「detach → app defaults」互動 regression，核對有效控制值、來源與保存 raw payload。

## Minor

無需阻擋交付的額外項目。TDD report 第 3 點的兩個 RED 中，連線 promise 誤成功是行為 RED；`recordHostSearchText is not a function` 是 feature-boundary failure，不能單獨算作「搜尋文字行為失敗」。最終 path assertion 有實際 literal expected value，不影響最終功能判定。

## 測試／建置證據核對

- `/private/tmp/sshelter-task2-full-frontend.log` 的摘要確實是 **66 files / 972 tests passed**，start 00:01:43、duration 1.36s，與 report 一致。
- `/private/tmp/sshelter-task2-vite-final.log` 確實顯示 **built in 13.94s**、974.16 kB／gzip 284.71 kB 和 >500 kB advisory；沒有把 advisory 誤報為失敗。
- `/private/tmp/sshelter-task2-tsc-final.log` 無 diagnostics；exit-code 的證據限制如前述。
- 已核對 normalization、effective-user markup、stale-ready connection、inline control、duplicate selected option、aria-label、diagnostic ancestor search 的 RED logs；其 assertion 對應目前 diff。缺 module／function 的 failure 與行為 RED 分開評估。
- reviewer 執行的 `git diff --check <base>..<head>` 成功，當前 HEAD 為記錄的 `f071333f8889f690e455c277e775e717937d588a`。
- 沒有重新跑整套測試；上述兩個問題可由已讀取的實際 state/handler 控制流程直接判定，無剩餘需要額外 focused test 才能釐清的程式疑問。

## Task quality：Needs fixes

核心分工、DTO 與 raw/effective separation 清楚，覆蓋主要 helper/native payload 以及真實 component markup；規格的大部分要求都有可追溯證據。修正兩個 Important 的可達 UI 情境並補足互動 regression 後，才適合將 Task 2 quality 判為 Approved。Task 6 的最終視覺／native 整合仍應獨立完成。
