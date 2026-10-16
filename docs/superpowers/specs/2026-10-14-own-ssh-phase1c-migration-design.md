# Own SSH client：1c 資料隔離與遷移設計

日期：2026-10-14。基準：next/own-ssh 9476f10，與 main 81e4e7c 的檔案樹相同。

狀態：使用者已確認書面設計，並於 2026-10-14 授權持續實作、依業界做法自行決策。尚未執行任何真實資料遷移。
本文件補充 2026-10-10-own-ssh-client-design.md 的 §5、§9、§10、§12、§13；下列分期調整為實作依據；後續決策與驗證結果記錄於進度表。
調查證據：docs/superpowers/plans/2026-10-14-own-ssh-phase1c-scout.md。該報告記錄既有程式行為，不是實作指令。

## 1. 目標與成功條件

1c 將主機、金鑰中繼資料與同步從 ssh_config 檔案模型轉成 SSHelter 記錄。
已完成的引擎、broker、CLI、Windows helper 留用。匯入金鑰只複製，不刪除原檔。
開發在 next/own-ssh 進行；main 繼續維護 0.17。1.0 的正式資料切換與 beta 發布是後續獨立操作。

### 1.1 產品方向：Brave-style 同步鏈

使用者補充：最終目標是參考 Brave Sync，以 chain 同步的 Termius 類 SSH 工具。
依使用者授權，本設計採用的邊界如下；這是信任模型與產品體驗，並非複製 Chromium 的同步協定：

- 各台電腦保有自己的主機記錄與本機 vault，離線仍可使用本機可用的主機與金鑰。
- 用隨機產生的同步碼／QR code 加入自己的裝置群組；沒有必要為此建立登入帳號。
- 主機設定與使用者選擇同步的金鑰，在本機加密成記錄，再送進 chain；不整包上傳 vault.json。
- relay 保存密文與必要的同步中繼資料，不持有 chain 的解密金鑰、本機 vault 的解密金鑰或私鑰明文。
- 私鑰預設留在本機，只有明確選擇同步的金鑰才產生密封 key 記錄；連線密碼與 passphrase 第一版仍留在該裝置。
- 「不用伺服器存 vault」在此代表不由伺服器管理、解密 vault；選擇同步的私鑰密文仍會儲存在 relay。

[Brave 官方 Sync v2 設計](https://github.com/brave/brave-browser/wiki/Brave-Sync-v2) 說明同步鏈採客戶端加密與同步伺服器；
[官方 FAQ](https://support.brave.app/hc/en-us/articles/360047642371-Sync-FAQ) 也說明同步資料會送到 Brave 的伺服器。
SSHelter 已有對應的骨架：sync/crypto.rs 的同步碼與用途分離金鑰、sync/reconcile.rs 的記錄加密、relay/src/index.ts 的密文儲存。
以既有 chain 與密碼學實作為基礎；1c／1d 的工作是將 SSH 記錄、vault 與 UI 接上它。

### 1.2 本次設計的可驗收結果


- 開發版、其 CLI 與背景 host 共用同一個開發 profile，與已安裝版的檔案、Keychain、IPC、啟動鎖分離。
- 未確認的匯入只產生預覽；沒有啟動即搬遷、修改真實 ~/.ssh 或升級真實 relay 帳戶的路徑。
- 相同 space 的兩台裝置轉換同一份舊記錄得到相同 host id；中斷重試不新增重複主機。
- 本機狀態格式、帳戶格式分別升級；存檔失敗、Keychain 失敗、網路部分成功皆可從已持久化進度接續。
- 0.17 與 1.0 切換期間不以刪除舊 host 記錄作為遷移手段，1.0 不依賴舊版已推進的游標。
- 每段保持編譯與測試可用；新的同步與匯入測試實際進入 CI。

## 2. 已核對的限制

| 事實 | 目前程式 | 對設計的影響 |
|---|---|---|
| app data 與 Keychain 名稱固定 | fsutil.rs:12；secrets.rs:9 | 改 Tauri identifier 本身不會隔離 Rust 的存放路徑 |
| debug 不使用 single-instance plugin | lib.rs:137 | 開發版可與已安裝版同時執行，必須先完成資料隔離 |
| Windows session pipe 只依角色與使用者命名 | session/mod.rs:20；ipc/pipe_windows.rs | 資料目錄不同仍可能接到正式 broker，pipe 也要分 profile |
| 載入 config 可搬備份、喚醒同步 | config/commands.rs:688 | 遷移預覽不能呼叫既有 config_load／load_doc_migrated |
| 新版帳戶唯讀仍合併、套用 space，最後才擋上傳 | sync/round.rs:597、622、717 | 舊版會跳過新 payload 並套用 tombstone，不能靠「唯讀」保證安全 |
| 不認得 payload 仍推進 space 游標 | sync/merge.rs:156、235 | 1.0 初次升級必須從 seq 0 重拉 |
| 同步的記錄層與檔案層耦合 | sync/runtime.rs:128；round.rs；account.rs | 先建立新資料路徑，再一次切換，不先刪 config／slots |
| 目前 CI 未涵蓋大半 sync 與前端測試 | .github/workflows/test-engine.yml；test-windows.yml | 每個新模組與遷移回歸情境都要加入實際執行的工作 |

這些是現有程式的靜態證據。實作完成前，不宣稱隔離、遷移或兩台升級已通過驗證。

## 3. 方案比較與建議

| 方案 | 成本與代價 | 判斷 |
|---|---|---|
| 分 profile、保留舊記錄、重拉游標，補強 0.17 格式閘門 | 多一份相容修正；遷移暫時佔用新舊兩份 relay 列 | 建議。保留原資料，支援重試與協調切換 |
| 在現有資料目錄直接轉換，立刻刪掉舊記錄 | 程式路徑較少；開發與實機共用資料，舊版可套用刪除 | 不採用 |
| 遷移時建立全新帳戶與 chains | 能分離協定；同步碼、分享、裝置與 rotation 都須一起搬 | 超出 1c 範圍，不採用 |

## 4. 先做開發 profile（1c-0）

新增一個不依賴 Tauri 的 profile／路徑模組，app、CLI、背景 host 都使用它。
profile 在編譯時決定：debug 使用 Development；本機 release 測試必須使用 development-profile feature。
沒有 feature 的 release 是 Production。profile 不依賴啟動終端機是否繼承環境變數。

| 項目 | Production | Development |
|---|---|---|
| app data 子目錄 | org.homelab.sshelter | org.homelab.sshelter.dev |
| Keychain service | SSHelter | SSHelter Development |
| Tauri identifier | org.homelab.sshelter | org.homelab.sshelter.dev |
| 顯示名稱 | SSHelter | SSHelter Dev |
| Windows pipe 角色 | session、agent | dev-session、dev-agent |
| 舊檔案層使用的 home | OS home | 開發 app data 底下的 sandbox-home |
| updater、autostart | 現有行為 | 停用 |

sync-state、vault、host-pins、MCP policy/runtime、backups、spawn lock、IPC lock/socket 均從 profile 派生。
不得只改 app_data_root 而漏掉 backups_root 或 keys::ssh_dir。
仍存活的 agent Include、slots、config 寫入與 KnownHosts 功能只能接觸 sandbox-home。
設定中指定的外部 config 路徑、Include 或 symlink 不得讓開發版的舊寫入路徑越出 sandbox。
匯入器另有明確的唯讀 source 路徑，不能把該 source 交給舊檔案寫入器。

Windows 的 pipe 角色仍沿用現有 SID、owner、DACL 檢查，不更改權限模型。
helper 啟動旁邊的同一個 app 執行檔；app 與 CLI 內建同一 profile。
Tauri 的開發 config 與 Rust profile 必須一致；不一致時在資料初始化之前拒絕啟動。
開發 profile 不自動複製正式資料、不讀取正式 Keychain 的同步碼、不自動加入既有 relay 帳戶。
需要真實配置做測試時，使用者選取來源，匯入器唯讀解析；金鑰須經逐項同意才能複製。

## 5. 新記錄與本機狀態（1c-1）

- 新增獨立的 version 3 本機狀態型別；保留唯讀的 v1／v2 decoder。
- 沿用帳戶與 space 的記錄、sealed envelope、LWW、generation 與 unsaved 語義。
- host payload schema 2、keyslot payload schema 2、帳戶 schema_version 3 各自有驗證器；不共用一個模糊的「版本」。
- local 區段保存未加入 space 的主機與只在這台的金鑰中繼資料；私鑰仍只在 vault／密封記錄中。
- 從已有同步記錄遷移的 host id 為 SHA-256(domain、space id、舊 record id) 的前 8 bytes，編碼為 16 個小寫 hex；各欄位長度編碼，避免串接歧義。
- domain 固定為 sshelter-host-migration-v1；新建主機仍用隨機 16 hex id。
- 任一新 id 與舊 alias id 或其他來源的 id 衝突，預檢即拒絕；不得隨機重抽造成兩台裝置使用不同映射。
- 檔案匯入的本機主機使用新隨機 id；使用者確認後、第一次寫入前將來源摘要與 id 映射持久化，重試沿用。
- alias 沿用可供 CLI 使用的字元限制，同一 space 唯一；跨 space 重名以 --id 連線，直接輸入歧義 alias 回錯誤。
- 驗證 port、時間上限、jump 循環與深度、auth 所需欄位；缺金鑰是可保存的「需要金鑰」狀態，不能送進引擎當成有效認證。

Synced keyslot 以現有公開資訊升為 schema 2，vault id 與密封 key id 保留。
Own keyslot 沒有全帳戶一致的公開金鑰：各裝置將可用材料轉成本機 keyslot，保留該裝置的 vault id，不擅自上傳私鑰。
拒絕複製的 Linked／SyncedCopy 保留原檔與遷移來源，主機標示需要金鑰。
帳戶 keyslot 與本機材料若同 id 不同 fingerprint，禁止簽章；不能用本機材料覆蓋帳戶的公開身分。
把本機金鑰改成同步時須檢查這個衝突，不同材料使用新 id 並明確重新指派主機。

## 6. 唯讀匯入與預覽（1c-2）

匯入器重用 lexer／parser 的解析能力，不呼叫會修復 Include、搬備份或喚醒同步的載入命令。
輸入分成三類：relay 的舊 host 記錄、該裝置尚未上傳的本機修改、使用者選取的 SSH 設定檔。
每筆來源保留 provenance 與摘要；相同 synced host 不從 SSHelter 自己的 Include 再匯入一次。

- 明確的單一 alias 轉為主機；多個明確 alias 分別列入預覽。Host * 與 wildcard 是預設／模式來源，不當成可連線的主機。
- 只解析靜態文字與有界 Include，使用第一個有效值的規則合併可支援的預設；Include 循環或超過深度 16、128 個檔案、單檔 1 MiB／合計 4 MiB 時回可定位錯誤。
- 不執行 ssh -G、Match exec、ProxyCommand、KnownHostsCommand、LocalCommand。
- Match、token 展開及不能確定的設定保留在 imported.unsupported；受影響主機必須先完成確認／編輯才可連線。
- schema 2 沒有欄位的舊編輯器設定保留原文，不靜默丟棄；可忽略的註記與阻止連線的設定分開呈現。
- ProxyJump 只能指向主機記錄。只有端點資訊完整且解析無歧義時才能在預覽建立缺少的跳板；否則要求使用者補齊。
- 現有 account／space 主機留在原 space；一般檔案匯入預設進 local，之後明確搬進 space。
- 金鑰來源只讀；預覽顯示來源、名稱、fingerprint、是否會複製，不顯示私鑰或 passphrase。
- 取消預覽不寫入 vault、Keychain、新狀態或 relay。預覽來源改變後，舊的確認失效，必須重新預覽。

離開帳戶時，所選 space 的可用主機複製到 local，並重映射 id／jump／密碼引用；本機已有條目不被覆蓋。
無法取得的 space 明確回報錯誤，不能報告為已完整保留；共享私鑰只按已有本機可用材料保留，不自動匯出到檔案。

## 7. 遷移交易與版本相容（1c-3）

### 7.1 本機進度

預覽只存在記憶體；使用者確認後開始備份與持久化 journal：prepared → account-gated → publishing → active。
journal 記錄 source 摘要、host 映射、複製授權、備份位置、已完成步驟與待上傳記錄，不保存明文私鑰或密碼。
先取得 lifecycle／sync／vault 的既有互斥與檔案鎖；第二個行程不得修改任何遷移狀態。

prepared 階段先保存原 state 的受保護備份與 migration 工作目錄中的新狀態，驗證能重讀，再做確認過的 vault 與 Keychain 複製。
新 state 與 vault 工作副本在 active 前不取代原檔；新增的 Keychain 項目使用可識別的遷移命名，不改寫原 vault 的解密鍵。
active 的檔案切換逐項記進 journal，中斷時依已完成項目接續；不把多檔案 rename 說成一個原子交易。
Keychain 的 host:<alias> 複製為 host:<id>；舊項目本輪保留，只有複製成功才切換密碼引用。
多筆主機由同一 alias 衍生時，只按來源對應關係複製；有歧義或目標已有不同密碼就交由使用者處理，不覆蓋。
既有 host-pins.json 的值只套用到能證明 hostname／port 一致的映射；不確定就保留來源並重新確認。

任一步失敗保留來源與進度，以相同映射接續。網路已接受的批次不能靠還原本機備份撤銷。
account-gated 前取消可丟棄新工作副本；已新增但尚未啟用的 Keychain 項目記為待清理，不刪原項目。
之後退出只能暫停，不能把帳戶 schema 降回 2 或宣稱已回滾。
UI 與 broker 只在 active 使用新目錄；中途不能拿半份記錄連線。

### 7.2 0.17 相容修正

在 1.0 真正改變共享帳戶前，先準備並驗證 0.17 的前向格式保護修正：

- 每輪先檢查 account 格式，再進入 prepare_files、本機 diff 或其他檔案維護；不能等批次 space 拉取後才檢查。
- 拉到比自己新的 account meta 時，在 reconcile_space_files、slot maintenance、space merge/apply 之前結束本輪。
- 保留這次開始時的舊 account／space 快取與游標，只記錄「需要更新」及必要的格式狀態；不能把略過的新 payload 當成同步完成。
- 已知帳戶是較新格式時，後續輪次只做有界的帳戶格式檢查；不做 space 檔案維護、不推送、不刪 chain。
- 保留使用者的 ~/.ssh、slot 檔案、本機編輯與原密碼；離開帳戶等寫入操作不得繞過格式保護。
- 修正先在隔離 fixture 驗證，再形成 main 的獨立相容補丁；發布與兩台更新另有明確切換步驟。

這個用戶端修正不是 relay 的寫入鎖，也無法停止其他成員還在執行的舊版。
實際切換前要求兩台舊 app 都退出，並確認使用相容版／1.0；離線舊用戶端仍可能回來，不能宣稱自動證明所有用戶端已升級。

### 7.3 共享記錄轉換

- 1.0 必須從 seq 0 重拉帳戶與所選 space，恢復被舊版跳過的已知 kind 新 payload。
- 保留舊 alias-keyed host 記錄，不 tombstone／刪除舊主機，不自動刪除舊檔案。
- 完整來源 snapshot 與容量預檢通過後才寫 schema 3 gate；gate 確認後分批發布新記錄，journal 記錄每批結果。
- 新 host id 由共享舊記錄確定；舊格式記錄只作為遷移來源，active 模式不把它再次顯示或重新匯出。
- 兩台並行遷移沿用相同映射；第二台見到新記錄不得用初始轉換覆蓋 1.0 使用者已編輯的欄位、刪除或主機 pin。
- 已確認 snapshot 之後又出現的舊格式修改作為待審查差異保留，不靜默覆蓋新記錄。
- 未完成的首次重拉、解密失敗、來源衝突或 relay 容量不足，均阻止 active，不推進不完整來源的完成標記。
- 新舊列並存的預算計入每 chain 的 4096 rows／1 MiB 和每記錄限制；不能用刪除舊記錄來騰出遷移容量。
- 沿用現有批次上限、429／5xx 退避、generation 與 unsaved 重存。未持久化本機進度前不發下一筆網路寫入。
- 更換同步碼與遷移互斥；遷移完成後 rotation 複製 host schema 2 與 keyslot schema 2。

stable 0.16 的 v1 狀態由唯讀 decoder 直接形成新狀態／匯入預覽，不呼叫會寫 ~/.ssh 的 v1→v2 upgrader。
其 relay 舊記錄需要與本機來源一起完整重拉、去重；不能以「離開再加入」丟棄尚未上傳的編輯。
較新且不認識的本機 state 原樣保留並拒絕寫入；不以空白新狀態覆蓋它。
降級到未經修正的舊版仍可能將 version 3 狀態移到 unreadable 備份並離開帳戶，須列入 1.0 release notes。

## 8. 分段替換與功能邊界

| 段落 | 職責與主要檔案 | 結束條件 |
|---|---|---|
| 1c-0 | profile、路徑與寫入邊界；fsutil、secrets、keys、config、session、agent、host_start、Tauri dev config | app／CLI／pipe 全面隔離的測試通過；不啓動真實 app |
| 1c-compat | 0.17 的較新格式保護；round、account、slots 與其呼叫入口 | 新 meta＋tombstone／新 payload 不修改舊檔案、不推進 space cursor；補丁可獨立移植 |
| 1c-1 | 結構化 payload、v3 store、驗證與 id 映射 | 純資料測試通過；舊 UI／backend 仍可編譯 |
| 1c-2 | 唯讀 import、preview、provenance | fixture 的 Include／Match／多 alias／Linked key 路徑均可預覽，無寫入副作用 |
| 1c-3 | record sync、journal、v1／v2 轉換、密碼與 pin 複製 | FakeRelay／MemKeychain 雙裝置、中斷、容量與重試測試通過 |
| 1c-4 | record-backed HostDirectory、vault key lookup、--id launch、tray | 既有 pin contract 與真實引擎臨時 sshd 測試通過 |
| 1d-cutover | 預覽確認 UI、最小主機清單／編輯器、新 commands／bindings | 使用者可取消、確認、重試，完整新路徑執行後才刪除舊模組 |

這是架構分段，不是可直接執行的逐步實作計畫。每段的精確修改、介面、測試與提交順序在該段計畫中定義。
不能先刪除 config／slots／agent 再讓前端暫時失效。
遷移來源解析器與必要的 Windows owner-only 寫入 helper 從舊模組抽出後留用。
AppState 的 doc 鎖等舊依賴在所有消費者改完後移除。

MCP phase 2 與 deploy 不偷偷提前到 1c：legacy 模式保留現有功能；records 模式不能繼續用系統 ssh 執行 run／deploy。
records 模式可列主機與讀取結構化設置，執行功能顯示明確不可用；最小 UI 切換時同步修改對應入口。
發現主機／known_hosts／文件 lint、drift、backup UI 的移除與 1d 一起完成；密碼命令移出 deploy 後保留。
設備 slots 中繼資料可繼續報告本機 fingerprint，不再包含交付檔案狀態；之後不由 agent 更新。
hostTerminals／recentConnections 以來源映射轉為 id；對不上或歧義的項保留遷移通知，不套到其他主機。
使用者空白時由平台 OS 身分查詢取得本機 username，不取未經驗證的環境字符串；新增依賴若必要，須在該段計畫說明。
版本 bump 在首次 1.0 測試安裝包前完成；開發 profile 禁用 updater，因此不會消費現有 Beta 通道。

## 9. 驗證與驗收

使用臨時 home／app data、MemKeychain、FakeRelay 與臨時 sshd。默認全套排除會觸碰真實 Keychain 的兩項測試。
不為驗證而啓動會初始化生產資料的 app。cargo export_bindings 會改寫 tracked bindings，驗證後核對 diff。

| 情境 | 必須證明的行為 |
|---|---|
| 開發版與正式版共存；CLI 獨立由終端機啓動 | 存放路徑、服務、pipe、鎖均不同，開發用戶端不會連接正式 broker |
| 開發 config／Include／symlink 指向真實目錄 | 所有舊寫入入口在首次寫入前拒絕；只讀 importer 不喚醒同步 |
| 舊版讀到 schema 3＋舊 host tombstone＋新 host payload | 相容修正保留舊檔案與 space cursor，不套用刪除、不吞掉新記錄 |
| 舊游標已超過新記錄；兩台同時升級；第二台有舊修改 | 全量重拉、相同 id、無重復、已編輯的新記錄不被初始遷移覆蓋 |
| 每個 journal 階段中斷、save／Keychain 失敗、批次部分成功 | 來源保留、進度可重讀、重試映射不變，active 不暴露半份資料 |
| v1／v2／無帳戶；Own／Synced／Linked／SyncedCopy；拒絕複製 | 不刪原文件、不擅自上傳私鑰，缺材料的主機明確需要金鑰 |
| 賬號金鑰 metadata 與本機材料不一致；pin 衝突 | 不簽錯材料、不覆蓋密碼、不自動接受不同主機 pin |
| relay 容量不足、限流、rotation、第二個進程 | 不以刪除舊來源解決問題，不越過持久化／互斥／退避門檻 |
| frontend 與舊模組逐段替換 | 實際執行新增 tests，移除生成 binding 後不會由殘留類型掩蓋壞入口 |

每段必須跑對應 Rust 測試、現有必要回歸、tsc 與相關 Vitest；Windows 由 Windows CI 執行平台測試。
CI 增加新 store／import／migration／record sync 和前端 tests，不以能編譯或 filter 匹配不到測試視為驗證通過。
真實 Mac／Windows 的匯入、鍵盤與終端行為、升級及降級仍是後續實機驗收，不能由本機 unit tests 代替。

## 10. 審閱範圍與後續

這次需要確認的設計變更是：先做完整 dev profile、補強 0.17 格式保護、保留舊記錄並全量重拉，
以及把舊模組刪除延後到 1d 的最小 UI／遷移確認可用之後。
同意書面設計後，先寫 1c-0 的精確實作計畫；其他段落按介面穩定程度接續，不一次生成整套未經驗證的程式碼。
真實帳戶遷移由已完成的匯入 UI 逐項確認；main 發布、1.0 beta 與真實資料清理不屬於本次文件工作的執行動作。
