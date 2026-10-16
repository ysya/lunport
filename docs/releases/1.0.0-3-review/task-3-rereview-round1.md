# Task 3 scoped re-review — round 1

## Finding Verdicts

- **I1：MCP Ask Space pin 跨 credential／relay 等待持有 lifecycle — ADDRESSED。** `src-tauri/src/session/connect.rs:355` 已切到 `pin_confirmed`；production 在 `session/app.rs:139` 安裝新 helper。`session/format_directory.rs:65` 先在鎖外執行可重入 guard，在 lifecycle 內選取 Records adapter，放鎖後才委派。`session/record_pin.rs:47` 只在短鎖內 preflight／capture，`:75`、`:77`、`:87` 的 guard、credential read、relay pull 都在 lifecycle 外。
- **I1 提交安全 — ADDRESSED。** `session/record_pin.rs:90` 重新取得 lifecycle，核對 pending migration、完整 snapshot／generation／prepared generation 與 cancel；`:104` 以 expected generation 發布 authenticated account proof，`sync/record_runtime.rs:470` 在同一 core lock 完成 generation check、pure transform 與 durable publication。`record_pin.rs:108` 後以純 snapshot/repository 操作重驗 device、relay/account identity、scope/effective route、authoritative key metadata，pin CAS 後於 `:131` 依 current generation 提交；提交前再次檢查取消。這些鎖內步驟不執行 caller guard／credential／relay callback。
- **I1 行為回歸 — ADDRESSED。** `sync/record_round_tests.rs:1109` 分別停住 credential read 與 relay pull，確認 lifecycle 可取得且取消不寫 pin；`:1215` 覆蓋 generation/scope/account/endpoint/key metadata 變化；`:1326` 覆蓋 guard 期間 Local→Space 不能跳過 fresh proof。`mcp/records.rs:1661` 經實際 PublicDirectory→FormatDirectory→RecordDirectory→record_pin 路徑，驗證 allow 可 pin/exec、revoke/disable 可設置 token 並阻止 pin/exec，沒有只測獨立 helper。
- **I2：晚到 Ask Allow 可能越過 120 秒期限 — ADDRESSED。** `src-tauri/src/mcp.rs:245` 在 pending mutex 內取出問題並以 authoritative deadline 拒絕過期解答、送 TimedOut；`:265` 在註冊／publish 前建立期限；`:1187` 在等待前與收到答案後重驗期限及取消。`mcp/records.rs:1499` 透過 production wait_approval/resolve_approval 路徑驗證晚到核准回 error、無 engine event、audit=timed_out；`:1549` 驗證已排隊 Allow 在消耗前過期亦拒絕。
- **I2 雙時鐘期限 — ADDRESSED。** `session/deadline.rs:21` 取 monotonic 與 UTC 剩餘時間的最小值；任一到期就拒絕。`mcp/records.rs:1569`、`:1620` 覆蓋 Instant 仍活著但 UTC 已到期的 resolve／queued-answer。此判斷符合 controller 接受的保守 forward-wall／不可被 backward-wall 延長 monotonic 上限策略，未改 DTO 或 IPC。
- **M2：AuthHub.resolve 過期問題仍回成功 — ADDRESSED。** `session/auth_window.rs:89`、`:99` 在 pending mutex 內拒絕 expired question，送 TimedOut 而不送 Answer；`:184` 在答案消耗前後檢查雙時鐘，`:177` 保留清理後最後檢查。`:470`、`:481`、`:486` 分別驗證過期 secret resolve 回 error、remaining_ms=0、排隊 secret 不被消耗。原有 Zeroizing／單次消耗契約保留。

## New Breakage in the Fix Diff

- **Critical：無。Important：無。** 僅核對本輪 15 個檔案的 fix diff 及上述 findings，未重新開啟全量審查。
- `sync/record_round.rs:140` 保留舊 fresh_account_gate wrapper，使用 `expected_generation=None` 維持對最新 local cache 的 merge；新 pin path 使用 Some(generation)。原 account merge／fail-closed／core account_keys 尾段行為保留；既有 delayed authenticated gate、unreachable relay、compatible proof 清 gate 等測試在本輪 record_round log 中通過。
- `session/directory.rs:92` 的預設 pin_confirmed 保留 Legacy／CLI 原 pin_for/replace_pin_for 路徑，新增 guard/cancel 前置檢查；FormatDirectory 的 callback 不在 lifecycle 內重入。`session/app.rs:139` 只對 explicit native trust 注入單次 OsKeychain，未更改 background gate；本輪未改 Auto-log NoPin。
- **具名 consequential check：final pin commit 是否重入 publication/lifecycle。** 限定補讀 diff 截斷的 `sync/record_runtime.rs:380` commit_candidate 及 `sync/record_round.rs:232` publish 尾段。commit_candidate 只取得 core、檢查 generation、persist，沒有重取 publication/lifecycle；publish 的 guard 在函式返回時釋放後，新 helper 才取下一段 publication lock。

## Evidence Checked

- 本輪 immutable diff：`66acc1cde84fbbc888438ce7de4a2d3bbed0eb93` → `e8b8da06faeaa70d840a04b329015aaebd13ae8b`；已讀完整 fix diff 一輪，另以 hunk 行號定位引用，沒有 git 命令、套件／測試重跑、產品碼變更或 subagent。
- RED 原文：`/private/tmp/sshelter-task3-fix1-deadline-red.log:56` **0 passed / 2 failed**；`...-auth-red.log:50` **0/1**；`...-pin-red.log:42` 明確為 **credential/relay wait must not own lifecycle**，`:49` **0/1**；`...-wall-red.log:80` **0/5**。Sandbox EPERM 與不合法 fixture 嘗試沒有被當作有效 RED。
- 最終相關 GREEN 原文：`/private/tmp/sshelter-task3-fix1-mcp-green.log:75` **40/40**；`...-auth-green.log:44` **9/9**；`...-wall-green.log:41` **5/5**；`...-deadline-green.log:36` **1/1**。直接核對通過名單包含 actual pending、queued Allow、native Space pin、auth expiry 與 backward wall bound regressions。
- 其他受 pin/account helper 修正影響的既有 GREEN：`...-connect-green.log:78` **43/43**；`...-record-directory-green.log:46` **11/11**；`...-format-directory.log:38` **3/3**；`...-record-round.log:66` **30/30**。這些在 clock-only 最後修正前執行；沒有誇稱在最後版本全部重跑。
- `/private/tmp/sshelter-task3-fix1-check.log:118`、`:119` 顯示 **16 warnings、production check 成功**；test logs 為先前已分類的 **3 warnings**。本輪沒有 warning-free 宣稱。

## Cannot Verify／Out-of-Scope Observations

- ⚠️ 雙時鐘測試是可控時鐘／短期限行為證據，未實際暫停 OS 或驗證 native suspend/resume；Task 6 平台驗收仍待完成。
- ⚠️ credential／relay 已開始的同步外部呼叫不會被強行中斷；本輪驗證的是 lifecycle 可用、取消可記錄、返回後不能 pin/exec，符合本輪接受的取消邊界。
- ⚠️ 原 native UI mount/視覺與 Windows 真實 OS credential 行為仍屬 Task 4／6；不在此輪新增 missing。
- 原 **M1 bounded audit reader、M3 stdio/broker formatting、M4 Task 5 ExecResult warning** 維持 controller 明確 defer；未宣稱修復、未擴充本輪。Human resolve/material lifecycle 工作維持 Task 5 範圍。
- 本輪沒有另外新增範圍外 finding。

## Verdict

**Fix round：All findings addressed, no new Critical/Important breakage。** I1、I2 與相關 M2 全部 ADDRESSED；本輪 task gate 可通過，後續平台／整合驗收與既列 minor ledger 保留。
