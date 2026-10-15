# Task 3 Review — Records MCP backend

## Spec Compliance

- ❌ **Issues found**：MCP Ask 的 Space host-key pin 路徑仍跨憑證／relay 等待持有 lifecycle lock（I1）；120 秒核准期限沒有在接收答案時強制檢查（I2）。其餘本任務可從差異與既有證據驗證的 backend 要求符合。
- 審查基準：`a3ce927276769d544e1e2ca749730e572a4d44bc` → `66acc1cde84fbbc888438ce7de4a2d3bbed0eb93`，依 completion design §5、own-SSH design §8、task brief 與 global constraints。
- 已套用 controller 裁決：Connect protocol 1／MCP protocol 2 相容設計可接受；Windows per-call CredReadW 路徑與 macOS/Linux fail-closed capability notice 可接受；不能以 generic focus 解除 hidden-host gate。

## Strengths

- `src-tauri/src/mcp/adapter.rs:36`、`:47`、`:148`；`src-tauri/src/session/broker.rs:324`：Records adapter 只呼叫既有 IPC；broker 一連線一請求、最多 16 個 MCP requests，OS peer PID 在 server 端建立 context。重複 JSON-RPC ID 在插入前拒絕，原取消 handle 保留；取消先於 stream 註冊也會被檢查。
- `src-tauri/src/mcp/records.rs:26`、`src-tauri/src/mcp.rs:52`：clientInfo 只取 name/title/version，app 端再過濾控制／deceptive characters 並限 100 字元；未信任 client 提供的 PID/requester_id，未知 OS attribution 明確顯示 Unknown。
- `src-tauri/src/mcp/records.rs:55`、`:72`、`:371`、`:467`：核准快照包含整條 resolved Target 與 authoritative public-key bytes；連線前、重連前、exec 前重查。Group port 改變不靠 host revision 判斷，同 key ID 換公鑰也會拒絕。對應真實行為回歸位於 `:1184`、`:1254`。
- `src-tauri/src/mcp/records.rs:421`、`:479`、`:503`：Auto-log 的 auth/confirmer/credential wrappers fail closed；exec 無 PTY、傳入 combined 128 KiB cap，保留 nullable exit/signal，取消 watcher 關閉 session。對應 `:1040`、`:1432` 測試驗證 secret/output sentinel 不進 log、取消／revoke 只產生一次 audit。
- `src-tauri/src/lib.rs:124`、`:194`；`src-tauri/src/sync/engine.rs:149`、`:244`：hidden gate 在 initialize 前建立；只有明確 native human activation 解除。MCP approval 使用未解除 gate 的 show_main_window；startup account reads、with_env 與背景 sync 有各自保護。
- `src-tauri/src/session/auth_window.rs:21`、`:91`、`:184`：native DTO 把可信 hop 與不可信 prompt 分開，答案以 Zeroizing 儲存、消耗一次，request 取消／期限後不交給 connector；pending snapshot 動態計算 remaining_ms。auth DTO/bindings/capability 已交給 Task 4。
- `src-tauri/src/mcp.rs:219`、`:229`；`src-tauri/src/session/broker.rs:434`：Connect 與 MCP 共用 public-only persistent writer，detail 在 memory 與 disk 都移除，保留 1000 筆／status 10 筆，I/O failure 可見，沒有自動重跑已完成指令。Connect 已收到 exit status 後的 close race 有具體 regression。

## Issues

### Critical（Must Fix）

- 無。

### Important（Should Fix）

**I1 — MCP Ask 確認 Space host-key 後仍跨 credential／relay 等待持有 lifecycle lock。**

- 位置：`src-tauri/src/mcp/records.rs:195`、`:202` → `src-tauri/src/session/format_directory.rs:19`、`:54`、`:57` → `src-tauri/src/session/app.rs:129`、`:133`。
- `PublicDirectory` 只替換 resolve；pin_for/replace_pin_for 仍委派原 FormatDirectory。Connector 在 host-key confirmation 完成後呼叫這兩個方法（`src-tauri/src/session/connect.rs:354`），FormatDirectory.with_active 在整個 callback 期間持有 lifecycle。Space pin callback 呼叫 fresh_account_gate，而該方法會讀 OS credential 並做 relay.pull（`src-tauri/src/sync/record_round.rs:91`、`:140`）。正常人工開啟、gate 已解除的 app 中，credential read 也可能等待 OS UI。
- 影響：MCP 自身的 pin 階段違反「no lifecycle lock across authentication/waits」；其他需要 lifecycle 的操作被等待中的憑證／relay 阻擋，取消 token 雖可設置，這段等待並不因此停止。這不是僅 Task 5 human resolve 才會觸及的既有問題，不能以 human-only 備註豁免。
- 修正：在 MCP 可達的 pin contract 中，把 credential／relay preparation 移到 lifecycle 外，最後寫入仍以目前 workspace/generation/endpoint/public-key/CAS 重驗後提交。不要直接刪除鎖而破壞 Task 1 atomicity。新增可停住 credential read、relay pull 的 Space pin regression：等待期間 lifecycle 可取得，revoke/disable 能設置取消並阻止後續 exec，取消後不得因 stale preparation 意外提交 pin。

**I2 — Ask 核准可在 120 秒期限後被當作 Allow 消耗。**

- 位置：`src-tauri/src/mcp/records.rs:754`、`:764`；`src-tauri/src/mcp.rs:134`、`:1126`。
- PendingApproval 沒有 deadline，mcp_resolve_request 只看 pending 是否仍在便送出 Allow。等待端雖先算剩餘時間，`recv_timeout` 收到答案後直接回傳 decision，沒有再次檢查 deadline。若 worker 在期限附近暫停排程、app 從睡眠恢復，pending 還在時的晚到答案能先進 channel，恢復後便走 Allow → check → connect。相較之下 native auth 在 `auth_window.rs:184` 有收到答案後的期限重驗。
- 影響：不符合 completion §5／own-SSH §8.3 的「120 秒逾時視為拒絕」，也不符合 report 宣稱 expired resolve 會回 error 的介面契約。
- 修正：pending 保存 monotonic deadline；resolve 在持 pending mutex 時拒絕 expired entry，等待端收到 decision 後再次檢查 authoritative deadline。新增可注入短期限／受控時鐘的行為測試，讓晚到 Allow 到達仍存在的 pending，驗證 resolve 回 error、engine 未被呼叫、audit outcome 為 timed_out。現有 `records.rs:1095` 只注入 ApprovalDecision::TimedOut，沒有測這條真實等待路徑。

### Minor（Nice to Have）

**M1 — 宣稱 32 MiB read limit，但先完整讀檔才判斷大小。**

- `src-tauri/src/mcp.rs:229`、`:231`：`std::fs::read` 在檢查 bytes.len 前已配置並讀取整個檔案；異常巨大的 session-log.jsonl 仍可能讓 startup 大量配置／等待。改用 bounded reader（limit + 1 byte）再拒絕超量檔案，保留原 bytes。這是復原／資源邊界品質問題，非同帳戶惡意行程的新安全邊界。

**M2 — Native auth resolve 的成功回應與 expired 契約不一致。**

- `src-tauri/src/session/auth_window.rs:91`：resolve 沒有檢查 Waiting.deadline，過期但尚未由 worker 清除的 question 仍可回 Ok。`:184` 會把答案丟棄，因此不會用過期秘密認證；問題在 UI 會收到成功卻實際 timeout。可與 I2 一起在 resolve 邊界檢查 deadline，補 queued/expired-answer regression。

**M3 — 新的併發入口以大量單行語句壓縮，增加維護與 race 審查負擔。**

- `src-tauri/src/mcp.rs:1151`、`src-tauri/src/session/broker.rs:324`：新 stdio loop／serve_mcp 的 register、spawn、cancel、remove、join 分支集中在很長的單行。建議只格式化這些新增區段並抽出清楚的 worker cleanup，避免下一次變更難以核對 handle ownership。此項不要求重排既有整檔。

**M4 — Warning 分類與 Task 5 收尾。**

- `src-tauri/src/ssh/mod.rs:29` 新增 production `ExecResult` re-export 目前未被 production 引用，是本 diff 可直接歸因的新 warning；report 說明為 Task 5 介面，應在 Task 5 接線後確認消失，或讓 import 依實際用途條件化，不要全域 suppression。
- 既有 3 個 test warnings：`src-tauri/src/sync/record_import.rs:49`（deselect_key_copy）、`src-tauri/src/sync/record_round.rs:14`（observed_schema）、`src-tauri/src/config/edit.rs:175`（set_host_enabled）。Task 1 report 已記載，Task 3 safe/focused logs 完全相同；不能列為 Task 3 新回歸。
- production check 為 16 warnings：上述新增 ExecResult 1 個，其餘 15 個皆在差異未變動的既有符號（engine 行號因插入而移動）。本輪未取得 BASE production check 的獨立 log，因此精確 baseline 數量屬 Cannot verify；可確認沒有其他本 diff 新增的 warning 定義點。最終 Task 6 應重新分辨尚存 baseline 與新增項目，不宣稱 warning-free。

## Cannot Verify／後續任務邊界

- ⚠️ `src-tauri/capabilities/authentication.json:1`、`src-tauri/src/session/auth_window.rs:210`：native authentication window 的 frontend mount、視覺、echo rendering、event race UI 補齊是 Task 4；本輪不列為 backend missing。Backend 已有事件與 auth_pending 補抓契約。
- ⚠️ `src-tauri/src/session/broker.rs:164`、`src-tauri/src/session/format_directory.rs:34`：human deployment connector 的完整接線、取消／quit registration 與原本 human resolve/material 的 lifecycle 修復是 Task 5；未將它泛化成 Task 3 重構要求。I1 僅針對新增 MCP 可達的 Space pin 路徑。
- ⚠️ `src-tauri/src/sync/env.rs:29`：Windows CredReadW 的來源／平台裁決已接受，但本 diff 與 macOS logs 不能證明 Windows OS/no-dialog integration；Task 6 native CI／實機仍需完成。macOS/Linux fail-closed 是本次已接受的支援邊界。
- ⚠️ 真實 IPC peer listener 的跨平台 ACL／peer PID 取得、真實 engine 合併 output cap 的底層實作不是本次差異；本輪確認新 caller 傳遞與既有 FakeEngine 回歸，沒有擴成全面安全或平台掃描。
- ⚠️ safe suite 是後續 Legacy/audit cleanup 前版本；最終差異有 MCP focused 35 tests、Connect audit focused 1 test、production check 的補驗。全套整合與 Task 4–6 的 native/visual gates 仍由 controller 完成；沒有把舊 suite 說成 final HEAD 全套。

## Named Checks／證據

- 已讀 immutable diff 一輪，依檔案順序檢查全部 31 個檔案；首次工具回應把中段省略，因此只補讀被省略段。之後用 diff hunk 計數定位 file:line，沒有重新產生 diff、執行 git 或重跑測試。
- **具名風險：PublicDirectory 的 pin 轉交是否仍持 lifecycle 等待。** diff 的 FormatDirectory.with_active／Connector.confirm 上下文不足，限定讀取 `format_directory.rs:14`、`session/app.rs:118`、`connect.rs:178`、`:280`，並沿該風險讀 `record_round.rs:83`、`:140` 與 `record_runtime.rs:460`。確認 credential/relay 在 lifecycle 內且最終 mutate_records 自身有 core/CAS 持久化；結論為 I1，未擴查其他 lifecycle 使用者。
- **具名風險：warnings 是否為新回歸。** 讀取 Task 3 check/test logs 與 Task 1 report 的 warning 記錄；分類如 M4。未修改 suppression 或重跑編譯。
- 既有 RED 原文已直接核對：`/private/tmp/sshelter-task3-red-policy.log:43` Null/ask、`...-red-exec.log:51` execution unavailable、`...-red-denied-audit.log:48` empty audit、`...-red-noninteractive.log:72` forbidden credential access 後錯誤成功；這些是有效行為 RED，fixture EPERM 不計。
- 既有 GREEN 原文已直接核對：`/private/tmp/sshelter-task3-safe-suite.log:2537` **2501 passed / 0 failed / 3 filtered**；`...-broker-final.log:79` **43 passed**；`...-postreview-mcp.log:72` **35 passed**；`...-connect-audit-final.log:37` **1 passed**；`...-check.log:523` **16 warnings / build finished**。未執行任何測試。

## Assessment

- **Spec verdict：Needs fixes。Quality verdict：Needs fixes。**
- 核心分層、OS attribution、target/public-key recheck、Auto-log fail-closed 與 public audit 已有具體實作和有效測試；I1 是實際 MCP Ask 路徑的 lifecycle 違約，I2 是 approval expiration 的執行邊界漏洞，修正並提供 focused regression 後再過此 task gate。其他 frontend／deployment／native 平台工作維持既定 Task 4–6 邊界。
