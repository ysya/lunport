# Task 1 re-review — fix round 1

## Spec compliance

- **原 I1：ADDRESSED。** `src-tauri/src/sync/record_merge.rs:1036` 移除對單一 Space raw hosts 的 relationship 判定；`src-tauri/src/sync/record_round.rs:472` 改用完整 candidate 的 repository snapshot，能解析 inherited jump 與其它 selected scope 的 target。新增／擴充測試實際驗證有效 inherited empty route 上傳及第二裝置解析、effective missing／cycle 阻擋、跨 Space target。
- **Completion gate：❌ Issues found。** 本輪修正把上傳阻擋條件擴大至所有 connection NeedsReview，新增 Important R1；因此 Task 1 尚不能完成。
- 審查範圍限 `2b8ef00f69938c1e902a768d0865bb21c514e2bf..bcfd05d94d1a7e54e25e8a6466709894c1b08126`、原 I1 與 fix 引入的問題；未重開其他既有議題。

## Strengths

- `src-tauri/src/sync/record_round.rs:472` 共用既有 repository resolver，沒有複製 inheritance／route 演算法；目前 Space 的過濾保留完整跨 scope context。
- `src-tauri/src/sync/record_round_tests.rs:840` 同時保留 account gate 零 child push 的斷言，並驗證 raw missing jump 仍保留、effective jump 為空、兩裝置均 Ready。
- `src-tauri/src/sync/record_round_tests.rs:907` 以真實 fake-relay encrypted rows 覆蓋 effective missing 與 cycle，確認 dirty rows 保留且零 push；`:983` 覆蓋跨 scope target。這些測試直接驗證 I1 的行為，不只是檢查實作形狀。

## New fix-diff breakage

### Critical

- 無。

### Important R1 — 通用 connection NeedsReview 被誤用為整個 Space 的 upload gate

- **位置**：`src-tauri/src/sync/record_round.rs:474` 的 `review = repository.hosts.iter().any(...)`，以及 `:491` 的 `if review { continue; }`。
- **根因**：這個 predicate 不只代表 Group／route relationship 衝突。`src-tauri/src/sync/record_repository.rs:213`、`:345` 也會因 `payload.imported.unsupported[*].requires_review` 將有效路由的主機標成 NeedsReview。匯入器把該旗標定義成 **blocks_connection**（`src-tauri/src/sync/records_v3/importer/resolve.rs:598`、`:604`），不是禁止保存或同步。
- **可達情境**：既有 `src-tauri/src/sync/records_v3/importer/tests.rs:342` 的 legacy Space fixture 保留 `Include` 的 review 標記，同時具有有效 hostname、空 jump；其 producer 在 `src-tauri/src/sync/records_v3/importer/resolve.rs:93` 設定 Space scope，`:98` 的 `validate_hosts` 成功。本輪前 merge 使用的正是該 validator，所以此類 host 可同步。修正後只要 Space 中留有一筆這種尚待連線審查的 host，每次 round 都判 review，該 Space 所有 dirty Group／host（包括其他完全有效主機的修改）都不再上傳。即使阻擋主機本身已是 clean row，其他變更仍受影響。
- **修正方向**：把「effective relationship／Group authority 是否有問題」與「能否立即連線」分開；由 repository 提供或重用明確的 relationship 判定，避免用總合 NeedsReview 當同步條件。維持原 I1 對 effective missing／cycle 的阻擋。
- **必要回歸**：同 Space 放入一筆 empty effective route、含 `requires_review: true` 匯入註記的 host，再修改另一筆有效 host；同步應成功上傳 dirty row，前者仍維持 NeedsReview、不能直接連線。
- **判斷**：這是 fix 新增的正常資料同步退化，屬 Important，應在 completion gate 前修正。

### Minor R2 — 新增 unused import，報告的 warning 數不正確

- `src-tauri/src/sync/record_merge.rs:22` 保留已無使用處的 `TypedRecord` import。`/private/tmp/sshelter-task1-fix-round1-merge.log:2` 與 `/private/tmp/sshelter-task1-fix-round1-round.log:1` 均記錄新增 warning，彙總分別在 `:38`、`:37` 明確為 **4 warnings**。
- 移除該 import，並更正 task report「仍只有三個既存 warning」的陳述；原 M1 的三個既存 warnings 另行保留 baseline。

## Verification evidence

- 已讀完整 fix diff 一次、Task 1 brief／global constraints 與 appended fix report。針對新 gate 誤用 connection readiness 的具體風險，只補查 repository 的 readiness 定義、既有 legacy importer producer／fixture；沒有瀏覽無關模組或重新執行 git。
- RED log `/private/tmp/sshelter-task1-fix-round1-red.log:78`：22 passed／3 failed；`:52`、`:63`、`:67` 對應三個修正情境。
- 最終 merge log `/private/tmp/sshelter-task1-fix-round1-merge.log:75`：31 passed／0 failed；`:68` 記錄調整後 merge preservation test 通過。
- 最終 round log `/private/tmp/sshelter-task1-fix-round1-round.log:68`：25 passed／0 failed；`:64`、`:65`、`:66` 對應跨 scope、effective missing／cycle、inherited empty route／peer tests 通過。合計 **56 focused passes**。
- 本 reviewer 未重跑測試；R1 由新增 predicate、既有 readiness 定義、既有成功 importer fixture 與 downstream skip-push 控制流程確認。唯一新增檔案是本報告。

## Out-of-scope observations / cannot verify

- 原 M1 三個既存 warning 未在本輪解決；它們不阻擋 task gate，但 R2 是這次新增。
- 完整 safe suite、frontend／MCP 及跨平台 integration 仍由 controller 後續驗證；56 focused passes 不代表完整 integration 已通過。
- 未對原 review 其他已通過項目重做全量審查，未操作真實 credentials／hosts／relay。

## Task quality

**Needs fixes。** 原 I1 已被明確行為回歸覆蓋並修正；但用 connection readiness 取代 relationship review 擴大了同步阻擋範圍，需先修正 R1。R2 可同輪清理。
