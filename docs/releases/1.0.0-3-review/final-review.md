# SSHelter Beta3 — final whole-branch review

審查日期：2026-10-15。單一 reviewer，未派子代理。

固定範圍：`0e9c727f35f6f704e443d694c1c62f08432ca389` → `5eb8b7f0c9094c34c9c47ac0a8819d9e1bfd2350`，13 commits。指定 diff package 共 804,911 bytes／19,521 行，依序分段讀完；未重建 diff，未重新全面閱讀變更檔案，後續只用 diff 的行號映射定位引用。最終確認 HEAD 未變、產品與 index 無修改。僅寫入本報告。

依據：指定 design、plan、global constraints、progress 的全部 26 個 Ruling、integration verification、task 2／4／5 實際 React 視覺收據，以及未追蹤的 Beta3 release notes／繁中 review checklist。採 requesting-code-review 的 reviewer 輸出與 Declined to judge 規則。

## Strengths

- Group 的 state 3→4／account 3→4 升級、原始位元組備份、account gate 先於子資料發布、future schema 保留原檔，以及離開／輪替的 Group ID、parent、membership remap 有實作與相對應回歸；raw override 與 effective resolution 分離，CLI／MCP／部署共用解析語義。
- MCP 以穩定 host ID 授權，Ask 預設、Auto-log 明確確認，純中介資料有界且標示 clientInfo 不可信。逐呼叫取消、paired UTC／Instant 到期、原生問題單次消耗、無 PTY 執行、合併輸出界限、字面 exit／signal／ended 與不保存輸出／回答的 audit 契約相互一致。
- Shared pin 的外部 credential／relay preparation 已離開 lifecycle，再以目前 snapshot、generation、scope、endpoint、CAS 與 cancellation 驗證提交。MCP／部署的 immutable target 綁定覆蓋 actual resolved target、engine 及 connected target；只容許既有的明確人工 Interactive→Password 適配和新信任 pin。
- 公鑰部署使用已選 key 的 canonical public identity、單次預覽與再次驗證；CRLF／unterminated bytes、restricted existing key、permissions、symlink、quoted HOME、未知結果不重試都有針對性證據。使用實際 own SSH engine 的隔離 installer 測試補足了純腳本測試。
- 已把 UI 最小視窗長文字的問題修正到真實元件：auth input／footer 與部署 actions 固定、完整路由可捲動、取消預設焦點。手動 mounted React 收據與 SSR／helper 測試的證明範圍有清楚區分。

## Issues

### Critical

無已證實項目。

### Important

**I1 — 刪除確認未綁定使用者已審閱的完整子樹，仍可刪除確認後新增或移入的 Group。**

- 證據：`src/components/records/group-editor.ts:156` 的 candidate 只保存根 ID、根 revision 和顯示 counts；`:180` 只送根 revision。`src-tauri/src/sync/record_commands.rs:389`–`:393` 同樣沒有子樹 snapshot。`src-tauri/src/sync/record_groups.rs:488` 只驗根 revision，`:503` 從**當下** snapshot 展開 descendants，`:535` tombstone 該集合。`src/components/records/GroupEditor.tsx:540` 開啟確認、`:564` 顯示凍結數量、`:583` 提交該 candidate。
- 可確定的觸發：使用者看到根 G 的「0 descendant Groups」並開啟刪除確認；另一裝置新增子 Group C 或將既有 C 移入 G，同步回來時 G 自己的 revision 不變。確認仍通過根 CAS，當下的 C 被納入刪除。已有子 Group 的 defaults／parent 或相關 host membership 更新也不由根 revision 代表。
- 影響：未列入使用者確認的新 Group 與其繼承關係被刪除；受影響 hosts 雖會 materialize 保留有效連線設定，仍失去未被確認的 Group membership／inheritance。這是刪除授權範圍與 stale review 的正確性缺口，不是單純數字顯示問題。`docs/releases/1.0.0-3-review-checklist.md:9` 的「確認期間資料變更會拒絕舊版本操作」目前亦過度概括。
- 修正方向：凍結 reviewed set，並在刪除提交的同一 lifecycle／snapshot 原子比對。可採後端 preview token／snapshot fingerprint 或保守 expected generation，但不能只在 UI 比 counts。Reviewed set 至少包含根及全部 descendants 的 stable ID、scope、revision、parent／defaults，以及將 materialize 的所有 affected hosts 的 stable ID、scope、revision、membership／inheritance；若 materialization 使用子樹外祖先的 defaults，也須綁定這些依賴或其 effective snapshot。以 generation 保守拒絕任何變更亦可，但需呈現重新確認的流程。
- 必要回歸：開確認後新增／移入 descendant、既有 descendant 更新／移出、affected host 加入／移出／設定更新，都拒絕舊 candidate，且拒絕時不部分 materialize 或 tombstone；刷新預覽並重新確認後成功，保留有效設定。保留現有 root revision 改變的回歸。現有 `group-review-fixes.test.ts:15` 測試只更新根 revision，不能證明這個子樹邊界。

### Minor

**M1 — audit 的 32 MiB 限制在完整讀取之後才生效。**

- `src-tauri/src/mcp.rs:252` 使用 `std::fs::read`，`:253` 才判斷 bytes 長度。過大的本機 log 已先配置／讀入記憶體，之後才回報過大。
- 分級：Minor。正常 writer 截到 1,000 筆，這不是已證實的遠端或不同 OS user 可觸發的無界輸入；損壞／手動替換的本機檔仍有啟動健壯性風險，因此不以先前 deferred 記錄直接豁免。
- 建議：對開啟的檔案採有界 read（limit + 1）再解析，保留原本 corrupt／partial-tail 診斷；不要只先查 metadata，否則檔案增長仍可繞過配置界限。

**M2 — 持久 audit 重啟後會重複 ID，而 UI 將它用作唯一 React key。**

- `src-tauri/src/session/broker.rs:169` 從 0 初始化 counter，`:361` 產生 `mcp-session-{id}`；`src-tauri/src/mcp/records.rs:556` 直接保存 context ID。`src-tauri/src/session/deploy.rs:103`／`:129` 的預設 counter 也重啟歸零。`src-tauri/src/mcp.rs:250` 載入過往 audit，而 `src/components/SettingsDialog.tsx:971` 使用 `key={entry.id}`。
- 具體結果：重啟前後各有第一筆 MCP session，兩筆 `mcp-session-1` 可同時出現在 recent 的十筆中，形成 duplicate sibling keys。audit 檔的內容不因此遺失，但 UI 的列 identity 不再唯一，後續更新／重排無法依賴正確 reconciliation。
- 分級：Minor；沒有證據顯示執行授權或持久 audit 內容受影響。建議給持久事件獨立且跨啟動唯一的 identity，或在 view 層建立確保唯一的 row identity（須處理既存歷史）；不要假設 process-local request ID 永久唯一。

**M3 — 新增併發控制過度壓縮，難以核對 lock／取消／清理邊界。**

- `src-tauri/src/mcp.rs:1242`–`:1269` 的 worker 管理、取消和結束清理，以及 `src-tauri/src/session/broker.rs:343`–`:361` 的新增 MCP session 路徑，大量控制流程壓在單行。
- 分級：Minor maintainability；本次未因格式推定 deadlock 或取消漏洞。建議只格式化新增區段、拆開 lock scope／錯誤分支／RAII cleanup 以便維護，避免順便重構既有 CLI。這是品質改善，不是獨立 merge blocker。

## Recommendations

先用一次 findings fix wave 修正 I1，並一併決定 M1／M2／M3 要修正或明確延期；修復後針對新 diff 做一次 scoped re-review。I1 的重點是後端原子比對 reviewed set，不是增加另一個前端確認框。release checklist 第 9 行應等此修正與回歸完成再維持已完成宣告。

Task4 的 SSR／helper tests 沒有 mount Card effects：`src/components/McpQuestions.test.tsx:21`、`:26` 只 render view，`src/lib/mcp-flow.test.ts` 測 clock／answer helper。獨立分級為**非阻擋的自動化覆蓋限制**，不是已證實產品缺陷；既有 root mounted QA 確實補了本次焦點、換題、expiry 與長文字呈現證據。可後續增加掛載真實 Card 的回歸，無須為本次重跑全部 UI 或宣稱目前效果未測。

Rust 的 3 個 test warnings／15 個 production warnings 為**非阻擋的既有 dead-code 維護負債**，未發現因本次改動造成的行為失效；不得寫成 warning-free。已核對本次 log 的位置包括 `src-tauri/src/sync/record_import.rs:49`、`src-tauri/src/sync/record_round.rs:14`、`src-tauri/src/config/edit.rs:175`。production 另含舊 importer／state／validate／engine 等未使用入口，完整清單在 build log。Vite 大 chunk advisory 同樣保留。

## Verification 與未變更契約核對

本次 reviewer 未重跑測試，未操作真實主機／credential／grant／Production app／relay。已有結果解答 happy／edge cases；I1 的缺口由 DTO 與原子刪除路徑即可確立，沒有額外執行壓力／race suite 的必要。

- 核對 `/private/tmp/sshelter-beta3-final-rust.log`：2546 passed、0 failed、0 ignored、3 filtered out，130.85 秒，exit 0。三項真實 OS credential 測試依既定安全限制排除；REQUIRE_OPENSSH=1 的 disposable macOS SSH／IPC 在此結果內，Linux PAM 尚待 native CI。
- 核對 `/private/tmp/sshelter-beta3-final-frontend.log`：73 files／1001 tests passed，exit 0；`final-tsc.log`、`final-vite.log` exit 0。最後一個 commit 只新增 native 隔離 installer 測試，前端 bytes 不變。
- actual installer 收據：隔離 Temporary HOME（空格／apostrophe）、own SSH engine、no PTY、Added→AlreadyPresent、CRLF／unterminated 原始 bytes、key once、permissions、symlink 拒絕，1 passed／0.67 秒／exit 0。
- Development bundle：`/private/tmp/sshelter-beta3-dev-build.log` exit 0，2 分 36 秒；root 核對 Info.plist 為 `org.homelab.sshelter.dev`／`SSHelter Dev`／`0.16.0`，executable 120,015,304 bytes。未啟動 app；這不是 Beta 簽章／發布收據。
- 具名未變更契約 **IPC 同 OS user 邊界**：讀 `src-tauri/src/ipc/server.rs` 的 Unix listener／peer；macOS getpeereid、Linux SO_PEERCRED 比對有效 UID，unknown platform 拒絕。讀 `src-tauri/src/ipc/pipe_windows.rs:73`–`:115`、`:515` 的 owner-only SID DACL、remote-client rejection，與既有 peer 顯示名稱取用路徑。確認新 MCP 依既有 OS 邊界，不把 clientInfo／程序名稱當獨立安全身分。
- 具名未變更契約 **Windows credential provider 讀取鏈**：讀 `src-tauri/src/secrets.rs:32` 的 Entry/get_password，Cargo.lock 的 keyring 4.1.5／windows-native-keyring-store 1.1.0，與本機鎖定 dependency 的 `v1.rs:94`、`cred.rs:116`、`utils.rs:228`–`:255`；確認 Windows get_password 經 generic credential `CredReadW`，未走 UI API。這支持程式路徑判斷，不能替代 Windows 原生裝置驗證。沒有另取外部網頁或更新依賴。

## 26 個 Ruling 的審查處理

以下行號均指本次 `progress.md`，保留所有決定及其成本，不把 scope decision 當成自動豁免。

| 行 | 決定／本次裁定 |
|---|---|
| 9 | 原 checkout 的專屬 branch：接受，未改 retained worktree。 |
| 10 | 自主 design／plan 決策：接受，仍以產品行為審查。 |
| 11 | 舊相同 Rust baseline 不重跑：已有本次完整 Rust，接受。 |
| 12 | 順序實作＋task review＋final review：本次完成單 reviewer final pass。 |
| 45 | materialized cross-scope host 使用 schema 2 或先升級：程式／回歸符合。 |
| 46 | Auto-log 不新增互動：按 per-call 路徑核對，平台能力限制保留。 |
| 48 | host create／update optional upgrade_confirmed：相容舊缺省與 schema 2。 |
| 62 | effective controls／raw overrides 分離：程式與 mounted UI 相符。 |
| 65 | 共用 Connect helper 也擋 group_error：palette 與 editor 一致。 |
| 70 | 最小 color-scheme 修正：接受，實際 Windows popup 未宣稱。 |
| 78 | MCP protocol 2／既有 Connect protocol 1：明確分支與回歸。 |
| 80 | 非互動 credential／directory／startup call sites：新路徑 fail closed，不用全域 unlock bypass。 |
| 81 | native question trusted hop／request context：DTO 與 UI 有據。 |
| 83 | Windows CredReadW 支援、macOS／Linux fail closed：讀依賴契約支持，device gate 保留。 |
| 91 | pin preparation 離開 lifecycle 後 CAS／cancel：實作與測試符合。 |
| 92 | native auth 與 Ask late answer 一起修：paired expiry／consume 行為一致。 |
| 94 | 保留 fresh_account_gate wrapper、保守 generation：接受，無擴張既有 CLI 修復範圍。 |
| 96 | paired monotonic／UTC expiry：controlled clock 證據有效，實際 suspend 未測。 |
| 106 | auth answer／status／footer 固定：mounted QA 支持。 |
| 113 | deployment 共用 PublicDirectory／CheckedEngine：actual target checks 覆蓋；legacy CLI limitation 保留。 |
| 115 | audit helper 回傳本次 write error：避免讀全域 error 的競態，接受。 |
| 116 | deployment 固定 actions／fingerprint 排序：mounted QA 支持。 |
| 121 | MCP／deployment actual target binding：ABA 回歸與程式一致。 |
| 122 | 僅明確人工 Interactive→Password adaptation：範圍窄，初始／目前 resolve 維持嚴格。 |
| 136 | 保存證據後可逆搬移 scratch：尚未執行，不以 cleanup 刪除證據。 |
| 139 | 固定 source review 與 Development build 並行：build 成功；review 的 I1 仍阻擋合併。 |

## Declined to judge

以下是考慮後未做通過宣告或未列為新缺陷的項目，請 executor 在整合／發布裁決逐項保留理由。

- **真實 Windows credential no-prompt 裝置行為**：本次只有 per-call 程式／鎖定 provider 的 CredReadW 路徑及測試替身，未讀真實 credentials；不能宣稱原生實測通過。
- **macOS／Linux Auto-log 已存 credentials 可用性**：有意 fail closed，狀態／UI 有能力限制，不是偷偷接受的缺功能；Ask 的 native 使用體驗仍需實機。
- **實際 Windows native select popup 顏色**：CSS/computed scheme 與 IAB 展開已有證據，原生 popup overlay／Windows 實機沒有；不以截圖外推。
- **實際 OS suspend／resume、native auth-window close、系統 credential UI 與 clipboard 整合**：paired clock／mock、mounted React 不能涵蓋 OS 行為，維持驗證限制；未操作 real credentials。
- **same-user 惡意程式隔離**：明確威脅模型只提供 OS-user 邊界、逐 host allowlist／Ask 與 audit；clientInfo／程序鏈不構成同 user 程序沙箱。未以本地任意程序可改自己的 log 當遠端漏洞。
- **unchanged ordinary human CLI 的 private-material readiness lifecycle 等待**：既有已文件化限制，新 MCP／部署不走該等待路徑；未要求本次廣泛重構或推定新 deadlock。
- **SSR／helper 未 mount effects**：列於上方獨立非阻擋覆蓋限制，root 的真實元件 fixture 已驗本次呈現／焦點／expiry；自動化不等於 native QA，也不等於完全未驗。
- **baseline warnings／Vite chunks advisory**：保留具體 log 與分級，不推定此次功能失效，不宣稱 warning-free。
- **既有 Beta2 Settings／host-key dialog／scrollbars**：已發布基線；本次只審查相交變更，不誤列為尚未實作。
- **任何帳號／workspace 變更都保守使 pin 或 deployment review 失效**：這是明確 generation／immutable target 策略；使用者重新 review 的成本已揭露，不作無證據的可用性 defect。
- **installer 結果在 cancellation／timeout／transport loss 後不可確知**：程式回傳 unknown／帶不確定性的 outcome 且不自動重試，符合契約；未聲稱所有中斷都遠端未寫入。
- **remote Windows installer 支援**：明確只支援 compatible POSIX shell，UI 有 unsupported_shell 說明；未把 remote Windows 排除隱藏成成功。
- **最終 native CI、Linux PAM、Windows OpenSSH console**：目前 pending，local pass 和 Development bundle 不可替代；需在最終修正 commit 完成既定 CI gate。
- **Beta 四平台資產、簽章、tag／manifest、stable channel 不變、下載更新**：本次未發布，release notes／checklist 正確保留 publication pending；不能從本報告推定已發布或可下載。
- **實際 Production app／relay／使用者真實帳號資料的端到端效果**：未取得本次操作範圍，未執行；隔離 fixtures／own-engine installer 的證據不得外推成 production 驗證。

## Assessment

**Ready to merge: With fixes。現況不應合併／發布。**

I1 是會越過使用者已審閱刪除範圍的正確性缺口，應在合併前修復並完成 scoped re-review；M1／M2／M3 可由 executor 明確修正或延期。其餘核心路徑有充分本地程式、回歸與 UI 證據，Development bundle 已成功，但 Beta ship readiness 仍須最終修正版本的既定 native CI 與發布資產／簽章 gate，不能視為已完成。
