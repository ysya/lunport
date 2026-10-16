# Task 1 review

## Spec Compliance

- ❌ **Issues found**：Group／host repository 已改用 effective route，但同步 merge 仍驗證 raw route，合法繼承狀態會被判成衝突並停止上傳。這違反設計 §2 的「readiness and jump routing use effective values」與 Task 1 的同步整合要求；詳見 Important I1。
- ✅ 原生 host create/update 的 optional `upgrade_confirmed` 缺省為 false，且共用 Group promotion：`src-tauri/src/sync/record_commands.rs:398`、`:420`、`src-tauri/src/sync/record_groups.rs:214`。未見超出 Task 1 的 frontend／MCP 實作。
- ⚠️ 此為 `bd36d41d69ae55f343c7c70de9d42d5e240e3dd9..2b8ef00f69938c1e902a768d0865bb21c514e2bf` 的 task-scoped 審查；frontend、MCP 消費契約、跨平台實際執行、Beta 發布仍由後續任務及最終 branch review 驗證。
- ⚠️ 完整 safe suite 的 2468-pass 證據在 optional-host API follow-up 之前；最後 331-pass Records 回歸涵蓋該 follow-up。最終整合 suite 仍須由 controller 執行，不能將舊 full-suite 結果視為最後 HEAD 的完整驗證。

## Strengths

- **raw/effective 與 provenance 分離清楚**：`record_groups.rs:91` 只對選定的 inherited fields 套用最近 ancestor／app default，auth 與 key ID 同步解析；`record_groups_tests.rs:18` 明確斷言 `ops / 2222 / keepalive 10`、來源 ID，以及 raw 值保持不變。上述路徑均位於 `src-tauri/src/sync/`。
- **安全失敗與 identity shadow 有實作證據**：`src-tauri/src/sync/record_groups.rs:47`、`:70` 以同 scope、上限 32、cycle／missing／opaque winner 檢查 ancestor；`src-tauri/src/sync/record_merge.rs:445` 對 Group 擴充 authenticated public identity，`src-tauri/src/sync/record_merge_tests.rs:1036` 驗證 future winner 遮蔽舊 parent；`src-tauri/src/sync/record_repository_tests/mod.rs:877` 驗證 inherited key 不回退到同 ID 的衝突 Local material。
- **effective endpoint 綁定一致**：`src-tauri/src/session/record_directory.rs:44`、`:76`、`:151` 使用 effective payload；`src-tauri/src/sync/record_repository.rs:817` 的 pin CAS 同樣檢查 effective endpoint 與 Group error。`src-tauri/src/sync/record_groups_tests.rs:144` 涵蓋 22→2222、舊 endpoint CAS 失敗、無關 host pin 保留。
- **接收端 state3 ingress 並未漏掉 promotion**：`src-tauri/src/sync/record_runtime.rs:351` 在 `save_active` 前統一呼叫 `has_group_data` 並升至 4；`src-tauri/src/sync/record_groups.rs:356` 同時辨認 account schema 4、Group caches／sealed envelopes、host schema 3。`src-tauri/src/sync/record_runtime.rs:232`、`:247` 在既有 source version 3 時先寫 digest-named 0600 備份。`commit_candidate`（`:380`）與 `mutate_records`（`:460`）都通過該入口；account metadata 接收和 selected-space merge 均使用 mutate_records。這項結論是靜態追蹤，並有 `record_round_tests.rs:840` 的第二裝置 join/decrypt/effective-value 覆蓋；該測試未直接斷言接收端磁碟版本／backup bytes。
- **共享 schema gate 與 lifecycle 有針對性回歸**：`src-tauri/src/sync/record_round.rs:304`、`:314` 要求 clean schema-4 metadata 才釋出 child push，`record_round_tests.rs:840` 驗證失敗 gate 零 child upload；`record_leave_tests.rs:710`、`:762` 覆蓋 Group/member/jump remap 與 unreadable source 拒絕 detach；`record_rotation_tests.rs:812` 覆蓋 live/tombstone 與 schema-4 保留。
- **刪除與移動保留設定**：`src-tauri/src/sync/record_groups.rs:482` 先解析、materialize host 再 tombstone subtree；`src-tauri/src/sync/record_repository.rs:779` 跨 scope 搬移產生 schema-2 materialized payload；對應 `record_groups_tests.rs:200`、`:283` 驗證值、ID／key reference 與 membership 清除。

## Issues

### Critical (Must Fix)

- 無。

### Important (Should Fix)

#### I1 — 同步 merge 仍驗證 raw jump，合法繼承主機會卡住同步

- **位置**：`src-tauri/src/sync/record_merge.rs:1044`、`:1057`；下游 `src-tauri/src/sync/record_round.rs:481`。新的 producer 行為位於 `src-tauri/src/sync/record_groups.rs:112` 與 `src-tauri/src/sync/record_repository.rs:613`、`:696`。
- **具體情境**：shared schema-3 host 保留 `jump: ["0000000000000099"]` 的 raw 值，而該 ID 已不存在；使用者將 `inherit` 設為 `["jump"]`，其 Group default 為 `[]`（或無 default，採 app `[]`）。`validate_host` 只驗證 raw ID 格式、重複／self-cycle／長度，沒有查存在性；repository 的 transition 則讀 effective `[]`，所以這筆資料可合法儲存，directory 也可正確直連。
- **錯誤**：`merge_space` 將 cached rows 直接 `decode_host` 後交給 `validate_hosts(&hosts)`，沒有 resolve Group inheritance。`validate_hosts` 會對 raw `0000000000000099` 回傳 `MissingJump`（`src-tauri/src/sync/records_v3/validate.rs:250`），令 `review_required = true`。`sync_once` 因此跳過該 space 的所有 dirty uploads；再次同步仍得到相同判定，連其他有效編輯也無法上傳。反方向的 inherited route 衝突也不會由這個 merge review 判定捕捉。
- **修正**：在有完整候選 snapshot 的同步階段以 repository／Group resolver 檢查 effective routes，避免用 raw route 判斷 review。新增 focused regression：上述 raw missing jump + inherited empty route 必須能完成上傳並在第二裝置解析為空路由；另驗證 raw route 有效但 effective route 缺失／cycle 時會正確 Needs review。
- **嚴重度理由**：這是正常編輯可產生且不可自行恢復的同步停滯，不是僅缺測試；Task 1 完成前應修正。

### Minor (Nice to Have)

#### M1 — 驗證輸出仍有三個既存 warning

- **證據**：`/private/tmp/sshelter-task1-record-final.log:2`、`:13`、`:24` 分別為 unused `deselect_key_copy`、`observed_schema`、`set_host_enabled`；`:30` 彙總三個 warning。相同 warning 也存在 full-safe log。
- **影響／建議**：不構成本次 Group regression，但依 reviewer 契約需記錄非 pristine output；controller 可另案清理或明確保留既存 warning baseline，勿描述為零 warning。

## Checks and review boundaries

- 已讀指定 brief、report、global constraints、設計 §2／§3／§7 與整份 review diff。第一次 diff 輸出被工具截斷，因此只補讀缺失區段；沒有重跑 git 或重讀整份 changed file。
- 針對 **state3 接收端 promotion 是否早於驗證／存檔**，補讀 diff 未涵蓋的 `commit_candidate`、`mutate_records`、account gate／section commit callers；確認都走集中 promotion 與 backup。
- 針對 **新增 raw/effective 契約是否仍被舊同步 relationship validator 誤用**，補讀 diff 未涵蓋的 `merge_space`、`space_outgoing`、`sync_once` 與 `validate_hosts`，得出 I1。另補讀被 diff 截斷的 `validate_transition`／route 函式尾部以確認 producer 的接受條件。
- 已核對既有 log 結果，未重新執行測試：`/private/tmp/sshelter-task1-groups-ready.log:62` 為 26 passed；`/private/tmp/sshelter-task1-full-safe.log:2503` 為 2468 passed／3 filtered；`/private/tmp/sshelter-task1-record-final.log:367` 為 331 passed／2141 filtered。I1 由可完整追蹤的 producer→merge→skip-push 控制流程證實，未新增或執行會修改 checkout 的測試。
- 唯一新增檔案為本報告；未修改程式、index、HEAD、分支或使用任何真實 credentials／hosts／relay。

## Assessment

**Task quality: Needs fixes**

effective resolution、format promotion、pin CAS、opaque authority 與 lifecycle 基本設計一致，且已有具體行為測試。同步 merge 的 raw route consumer 尚未整合新契約，會使有效繼承狀態停止上傳；修正 I1 並補 focused regression 後再進 task gate。
