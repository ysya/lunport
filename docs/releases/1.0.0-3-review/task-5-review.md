### Spec Compliance

- ❌ Issues found：Task 5 的公開預覽、原生確認／取消、Keys 入口與部署結果已實作，但尚有兩項 Important：CRLF 受限金鑰會被新增的 unrestricted duplicate 繞過（`src-tauri/src/session/deploy-script.sh:37`）；核准資料未綁定實際交給 engine 的 Target，A→B→A 的解析時序可能把金鑰部署到未審閱的 B（`src-tauri/src/mcp/records.rs:151`）。因此「保留既有限制」及「確認後僅對審閱目標執行」尚未完全成立。
- 檢查範圍：BASE `246bd5677094fca25da3631878673ec3eafa38b9` → HEAD `f292b462db23d190d7f7a4bf52fd18d782d3965a`；指定 immutable diff 的 15 個檔案均有對應實作，未發現無關新增功能。未修改產品、index、branch，未 push／release。

### CannotVerify

- ⚠️ 最終 HEAD 的 mounted UI、1100×720／800×560、light／dark 與長 route 完整視覺驗收仍由 Root 完成；`src/components/records/deploy-markup.test.tsx:11` 的 static markup 測試不能證明瀏覽器實際可見／可操作。
- ⚠️ 真正 own-engine → disposable POSIX SSH server → installer 的整合、Windows native CI／裝置行為仍屬 Task 6；`src-tauri/src/session/deploy_tests.rs:13` 證明本機 TempDir shell 行為，不能代替這些驗收。
- ⚠️ 本次未重新執行 Rust／frontend suites。既有 log 的結果已核對，但空白的 `/private/tmp/sshelter-task5-tsc.log` 本身不含 exit status；TypeScript exit 0 仍為 implementer report 提供的證據。

### Strengths

- `src-tauri/src/session/deploy-script.sh:9`、`:22`、`:49`：拒絕 `.ssh`／`authorized_keys` symlink，採用有限次數的 mkdir lock；LF 格式下的 plain／options-prefixed duplicate 比對可保留現有 restriction，並排除註解及 quoted command 的假命中。
- `src-tauri/src/session/deploy.rs:1`、`src/lib/records.ts:517`：以 authoritative public metadata 建立 canonical algorithm/blob；確認 API 僅接受 backend preview ID 與 authorization，沒有 caller-provided endpoint／key bytes，也沒有 host auth／MCP grant mutation。
- `src-tauri/src/session/broker.rs:180`、`:206`：deployment registration 納入 quit barrier；RAII 清理、取消 token 與實際 session close 有行為測試，沒有把 worker 排除在 has_sessions／end_all 之外。
- `src-tauri/src/session/deploy.rs:536`、`src-tauri/src/mcp.rs:221`：執行與每次 audit write result 分離，audit failure 不重試遠端命令；audit 不保存 stdout／stderr／authentication reply。
- `src/components/records/DeployKeyDialog.tsx:80`：目的地與 fingerprint 先於 route，details 可獨立捲動，authorization／取消／結果留在 footer；狀態不因一次 remote failure 自動重試。

### Issues

#### Critical (Must Fix)

- 無。

#### Important (Should Fix)

- **I1 — CRLF 會新增 unrestricted duplicate，放寬既有 key restrictions。** `src-tauri/src/session/deploy-script.sh:37`（比對 `:49`、新增 `:59`）：tokenizer 只將空格與 tab 視為分隔，awk 去除 LF 後仍保留 CR。既有 `restrict ssh-ed25519 <blob>\r\n` 的第三個 token 因此是 `<blob>\r`，不等於 canonical blob；腳本輸出 `SSHELTER_ADDED` 並附加同一把不受限的 key。若原行同時含 `from=`／`expiry-time=` 等條件，該行不適用時 sshd 可繼續接受後加的 unrestricted entry，造成實際授權放寬；若只有 `restrict` 且原行仍適用，OpenSSH 仍會先接受原行，不宣稱該情形立即繞過所有限制。OpenSSH 的 [sshkey_read](https://github.com/openssh/openssh-portable/blob/master/sshkey.c) 經 [sshbuf_b64tod](https://github.com/openssh/openssh-portable/blob/master/sshbuf-misc.c) 使用會忽略 whitespace 的 [b64_pton](https://github.com/openssh/openssh-portable/blob/master/openbsd-compat/base64.c)，既有 CRLF key 可被正常解析；[authorized_keys 檢查](https://github.com/openssh/openssh-portable/blob/master/auth2-pubkeyfile.c) 則持續尋找適用的 matching entry。修正應只正規化解析用的行尾 CR／key token，不重寫原檔；加入 plain 與 restricted CRLF、含／不含 comment 的實際 installer regression，要求 `SSHELTER_PRESENT` 且 bytes 不變。
  - 集中實測：使用公開合成 Ed25519 fixture（32 bytes `0..31`），TempDir HOME，原檔為 `restrict <canonical-public>\r\n`；以 `/usr/bin/ssh-keygen -l -f <temp>/authorized_keys` 驗證 public fixture 可解析，再替換實際 checked-in shell template 的 public placeholders，透過 `/bin/sh -c` 執行，環境僅 HOME 與 `/usr/bin:/bin` PATH。結果：public parse exit **0**；installer exit **0**；marker **SSHELTER_ADDED**；original preserved **true**；unrestricted duplicate appended **true**；identity occurrences **2**。沒有 SSH 連線、private key 或真實使用者 HOME 存取。

- **I2 — 核准檢查沒有綁定 connector 實際使用的 Target。** `src-tauri/src/session/deploy.rs:304`、`src-tauri/src/mcp/records.rs:151`：新部署路徑重用的 `CheckedEngine` 呼叫零參數 `check()`，然後直接把收到的 `t` 傳給 inner engine；該 check 透過 `ApprovedTarget::check` 另行 resolve 當前 directory，沒有比較 `t`。`Connector::connect_within` 則先獨立 resolve 並保留自己的 target。具體時序為 preview=A → execute 首次 check=A → connector resolve=B → directory 回到 A → CheckedEngine check=A → engine 連 B → pre-exec check=A → 在 B 安裝。B 若已有可用 pin／authentication，就不會經過額外 pin guard 阻擋。最後檢查目前的 A 不能證明實際 session 連的是 A。
  - 集中靜態核對：為這一項 named risk 讀取未變動的 `ApprovedTarget::capture/check`（`src-tauri/src/mcp/records.rs:57`）及 `Connector::connect_within`（`src-tauri/src/session/connect.rs:201` 起的 resolve／engine 呼叫）；沒有重新讀取其他產品檔案或重跑 suite。這是具體 code-path 證據，**尚未跑 deterministic ABA regression**。
  - 修正：在 guarded resolve／engine boundary 綁定「實際回傳／傳入的 Target」與 Reviewed identity，而不只是重查另一份 current target；exec 前亦確保 Connected.target 對應已核准的 endpoint／route，保留合法新增 pin 的例外。加入受控 directory 依序回 A/B/A 的測試，斷言 B 不得進入 engine／exec。此 helper 原已由 Task 3 使用，最小共享合約修正需同步檢查 MCP 與 deployment 兩個 call sites，不應只補 UI 檢查。

#### Minor (Nice to Have)

- 無新增 Task 5 Minor。既有 M1 audit-reader preallocation、M3 formatting 與 baseline warnings 保留原 ledger；不在本次重複列為新增缺陷，也不宣稱 warning-free。

### Checks

- 已核對既有 logs：deployment **20/20**（`/private/tmp/sshelter-task5-final-deploy.log:56`）；MCP **41/41**（`/private/tmp/sshelter-task5-final-mcp.log:76`）；broker **43/43**（`/private/tmp/sshelter-task5-final-broker.log:79`）；connect **43/43**（`/private/tmp/sshelter-task5-final-connect.log:78`）；native auth **9/9**（`/private/tmp/sshelter-task5-final-auth.log:44`）；format directory **3/3**（`/private/tmp/sshelter-task5-final-format.log:38`）。這些測試並未涵蓋本次 CRLF 與 ABA finding。
- 已核對 production check finished 且有 **15 warnings**（`/private/tmp/sshelter-task5-check.log:110`）；Rust test builds 各有既有 **3 warnings**（例如 `/private/tmp/sshelter-task5-final-deploy.log:30`）；frontend **73 files／1001 tests passed**（`/private/tmp/sshelter-task5-frontend-all.log:9`）。
- 本次唯一新增執行是 I1 的 TempDir focused installer probe；未執行 package-wide tests、真實 host 操作或 secret round trips。

### Assessment

**Task quality:** Needs fixes

**Reasoning:** 公開資料邊界、取消／quit integration、每次 audit error 與 durable UI outcome 都有合理分工及既有測試證據，但 CRLF restriction bypass 已實測，目標綁定亦有可成立的 A→B→A 時序；兩項都應在 Task 5 通過前修正並加集中 regression。最終 mounted visual 與真實原生 POSIX SSH 驗收仍由 Root／Task 6 完成。
