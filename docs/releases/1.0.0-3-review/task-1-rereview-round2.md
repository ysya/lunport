# Task 1 re-review — fix round 2

審查基準：`bcfd05d94d1a7e54e25e8a6466709894c1b08126..f6bcf98edc56f3b99591649330dc9175e7dc1464`。範圍限定 R1、R2 與本輪四個 Rust 檔案的新差異；原 I1 維持 **ADDRESSED**，不重開未修改程式的全量審查。

## Finding verdicts

### Important R1 — ADDRESSED

- `src-tauri/src/sync/record_round.rs:471` 改用 `scope_requires_relationship_review`；`:489` 的整個 Space upload gate 不再直接依賴彙總 connection `NeedsReview`。
- `src-tauri/src/sync/record_repository.rs:377` 的 helper 共用完整 `snapshot` 與既有 effective payload、`route_indices`，在 `:383` 限定目前 scope，並只判斷 Group resolution error、opaque Host authority、alias conflict 與 effective route error。既有 `ensure_host_authority`（`:561`）只檢查 opaque identity shadow，不把 import warning 當成 authority 衝突。
- `needs_import_review` 仍在 `src-tauri/src/sync/record_repository.rs:345` 影響連線 readiness；新 helper 不使用該條件，也沒有更動 directory 的連線防護。Group／missing／cycle relationship gate 保留原中央實作，跨 scope targets 仍由完整 snapshot 提供。
- 新測試 `src-tauri/src/sync/record_round_tests.rs:1099` 與 `:1104` 分別覆蓋 dirty／clean warning host。`:1065` 明確確認初始 dirty 狀態，`:1071`–`:1078` 確認 Space 無 review gate、實際 push、dirty rows 清除且 relay 保留兩筆；`:1080`–`:1094` 驗證 warning host 仍 NeedsReview、effective jump 為空，directory 回傳 Unsupported，而且 material／username／pin callbacks 不得執行。這是 R1 要求的同步與連線分離行為。

### Minor R2 — ADDRESSED

- `src-tauri/src/sync/record_merge.rs:20`–`:23` 已移除 unused `TypedRecord` import；本檔搜尋沒有殘留該 identifier。
- `task-1-report.md:177` 已明確更正 round 1 實際為四個 warnings；`:191` 正確記錄 round 2 僅剩三個既存 warnings。對照 round 1 merge／round logs 的 `:38`／`:37`（4 warnings），以及 round 2 merge／repository／round logs 的 `:29`（3 warnings），報告與實際輸出一致。

## New fix-diff breakage

- **Critical：無。**
- **Important：無。**
- **Minor：無。**

本輪未新增 schema、DTO、依賴或 connection readiness 語意；helper 使用既有 Group／authority／route 判定，未見本輪差異引入的可確認退化。

## Verification evidence

- 已讀 Task 1 brief、global constraints、appended round 2 report、round 1 R1／R2 原文與完整 fix diff。補讀僅針對新 helper 使用的 snapshot／authority／route 定義、測試行號與日誌；未重跑測試套件。
- RED：`/private/tmp/sshelter-task1-fix-round2-red.log:64` 為 **0 passed／2 failed**；`:50`–`:57` 顯示 dirty／clean 兩者皆因 `assertion failed: !report.review_required` 失敗，與 R1 行為一致。
- GREEN：`/private/tmp/sshelter-task1-fix-round2-green.log:35`–`:38` 為兩個新增測試通過，**2 passed／0 failed**。
- 最終 focused logs：round `:62` 為 **27 passed／0 failed**；repository `:82` 為 **47 passed／0 failed**；merge `:66` 為 **31 passed／0 failed**，合計 **105 passed／0 failed**。
- `/private/tmp/sshelter-task1-fix-round2-round.log:50`、`:52` 確認新增 dirty／clean warning 測試通過；`:54`、`:58`–`:60` 確認原 remote relationship conflict、effective missing／cycle、cross-scope targets、inherited empty route／peer 回歸仍通過。
- 三個最終 focused logs 均只列 `deselect_key_copy`、`observed_schema`、`set_host_enabled` 三個既存 warnings，未將它們表示成 warning-free。

## Spec compliance

**通過本輪 scoped completion gate。** R1／R2 均已處理；同步 gate 保留 effective relationship／Group authority 檢查，同時允許單純匯入連線註記的有效資料同步。原 I1 維持 ADDRESSED。此判定僅涵蓋上述 commit range，不表示完整 Task 1／產品整合已完成。

## Out-of-scope observations / cannot verify

- 原 M1 三個既存 warnings 保留 baseline，未重新審查或要求本輪處理。
- 完整 safe suite、frontend／MCP、跨平台 integration 與 Beta gate 仍由 controller 執行；105 focused passes 不代表這些 gate 已通過。
- 未操作真實 hosts／credentials／relay；未修改 source、index 或 HEAD。唯一新增檔案為本重審報告。

## Task quality

**Approved（本輪範圍）。** 修正直接解決 R1 根因，dirty／clean 兩個具體情境有 meaningful RED→GREEN，並驗證同步後仍拒絕連線。R2 的程式與報告更正都有輸出證據；沒有新增需要先修正的 Critical／Important／Minor finding。
