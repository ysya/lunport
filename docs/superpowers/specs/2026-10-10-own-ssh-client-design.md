# SSHelter 自有 SSH 用戶端(Termius 模式)設計

- 日期:2026-10-10
- 狀態:已核准。使用者 2026-10-10 分段核准:方向(A、A1、B1、第一版範圍、做法 1)與第 4–13 節的內容。2026-10-11 依第 0 期試驗報告(`2026-10-10-own-ssh-spike-report.md`,判定 GO)修訂:§4、§6.1–6.3、§7.1–7.3、§8.2、§11–§13、§15–§16;修訂處標「(第 0 期)」。
- 取代:`2026-10-07-key-vault-agent-design.md` 第 0 節「用系統的 `ssh`,由 SSHelter 的 agent 提供金鑰」這個前提,以及該文件的 §5(agent)、§6(接線)、§8(搬遷)、§9(MCP)與 §10 的 agent 相關內容;分支 `feat/mcp-ssh-exec` 上的 `2026-10-10-mcp-ssh-exec-design.md`(其核准模式、log 與請求者辨識的決定併入本文件第 8 節)。
- 不動:0.17 系列照常維護;本設計在新的主版本 1.0 實作(第 13 節)。
- 相關:金鑰保管庫格式(`vault/`)與同步鏈的密碼學(`sync/crypto.rs`)沿用,不在本文件重述。

## 0. 定位與改變了什麼

SSHelter 原本是「`~/.ssh/config` 的編輯器,加上同步與金鑰保管庫」:連線用系統的 OpenSSH `ssh`,金鑰經 SSHelter 的 agent 提供,主機以 ssh_config 檔案為來源。這個前提帶來一整層「和 `~/.ssh` 共存」的狀態機:插槽檔、`.pub`、Move/Keep、改寫 IdentityFile、Include、drift、維護輪,以及 agent 的接線與程序辨識(後端約 36,000 行,含測試)。

2026-10-10 使用者決定改成 Termius 的模式:**SSHelter 自己實作 SSH 連線,自己保存主機與金鑰,不再依賴系統的 `ssh`,也不再讀寫 `~/.ssh`。** 一句話:SSHelter 從「ssh_config 管理器」變成「SSH 用戶端管理器」。

和 Termius 的差異:第一版沒有內建終端機分頁;使用者仍用本機的終端機程式(Terminal、iTerm2、Windows Terminal),由 SSHelter 的命令列模式把終端機接到 app 裡的連線。

## 1. 目標與非目標

**目標**
1. 連線、金鑰、主機記錄都只在 SSHelter 裡:私鑰不離開 app 行程,連線由 app 持有。
2. 使用者在自己的終端機裡用 `sshelter connect <alias>` 連線;AI 工具經 MCP 的 `ssh_exec` 執行指令;兩者共用同一個 session broker。
3. 主機與金鑰在電腦之間同步(沿用端對端加密的同步鏈),主機金鑰的釘住也同步。
4. 核准規則清楚:終端機是使用者自己敲的,不核准;AI 依全域模式(每次問,或自動允許並記錄);主機金鑰永遠要人確認。
5. 可以替換 SSH 引擎:russh 只出現在一個檔案裡。

**非目標(第一版)**
- 內建終端機分頁。
- 給其他程式用的 ssh-agent socket:`git`、`scp`、`rsync`、VS Code Remote-SSH 用不到 SSHelter 的金鑰;需要就 Export private key 成檔案自己管。
- 本機與遠端連接埠轉送、SFTP、OpenSSH 憑證認證、X11 轉送、agent forwarding。
- 讀取或寫入 `~/.ssh`,除了一次性匯入(只讀)與使用者主動按的清理(第 9 節)。
- 支援 FIDO 的 sk-* 金鑰(保管庫本來就不收)。
- 密碼同步(記錄種類 `password` 保留給之後)。
- 舊版(0.17)與 1.0 混用同步:1.0 升級帳戶的 schema 之後,舊版唯讀。

## 2. 決策表

| # | 決策 | 來源 |
|---|---|---|
| 1 | 完全自有(A):主機、金鑰、設定在 SSHelter 自己的記錄裡;`~/.ssh/config` 只匯入一次 | 使用者,2026-10-10 |
| 2 | 連線住在 app 裡(A1):CLI 與 MCP adapter 都是接到 app 的 session 的薄用戶端,沒有簽章協定 | 使用者,2026-10-10 |
| 3 | 不留相容用的 ssh-agent socket(B1):`agent/` 刪除 | 使用者,2026-10-10 |
| 4 | 第一版範圍:互動 shell(PTY、視窗大小)、exec、公鑰/密碼/keyboard-interactive、主機金鑰確認與釘住、ProxyJump 多層、keepalive 與逾時、一次性匯入 | 使用者,2026-10-10 |
| 5 | 引擎用 russh 0.64.x,釘死 `=0.64.x`,自訂 `Signer` 接保管庫;之後可能換成自製引擎,所以隔離在 `ssh/russh_engine.rs` | 使用者,2026-10-10 |
| 6 | 主機金鑰的確認只在 app 的視窗做;MCP `auto_log` 遇到未確認的主機金鑰回錯誤,絕不自動接受 | 設計,2026-10-10 核准 |
| 7 | 互動提示(passphrase、密碼、2FA)送給 session 的擁有者:終端機 CLI 在終端機裡問;MCP `ask` 送 app 視窗;MCP `auto_log` 不問、回錯誤 | 設計,2026-10-10 核准 |
| 8 | 跳板只能是已儲存的主機;主機金鑰釘在 host 記錄裡並同步,不另設 known_hosts 檔 | 設計,2026-10-10 核准 |
| 9 | 密碼仍存這台的系統 keychain,第一版不同步 | 設計,2026-10-10 核准 |
| 10 | 新主版本 1.0,長期分支開發;帳戶 `schema_version` 2 → 3,所有電腦一起更新 | 設計,2026-10-10 核准 |
| 11 | MCP:`run` 改名 `ssh_exec`;全域核准模式 `ask`(預設)/ `auto_log`;log 1000 筆;視窗與 log 標出請求者(程序鏈)與自報的 clientInfo | 使用者 2026-10-10(沿用 `feat/mcp-ssh-exec` 的決定) |
| 12 | 不設 `_meta["anthropic/requiresUserInteraction"]`:它會讓 Claude Code 每次都問、抵銷 `auto_log` | 設計,2026-10-10 核准 |

## 3. 威脅模型

| 誰 | 做什麼 | 擋得住 | 擋不住 |
|---|---|---|---|
| AI 工具經 MCP | 在允許清單上的主機執行指令 | `ask` 模式每條指令要核准;`auto_log` 只在你明確開啟並確認風險後生效,每條都記錄;允許清單外的主機一律拒絕;主機金鑰未確認、要密碼或 2FA 時 `auto_log` 回錯誤 | `auto_log` 開啟期間,AI 在允許的主機上能執行任何指令;AI 讀到的內容夾帶的指令也會執行 |
| 同一使用者身分的其他程式 | 連上 IPC 偽裝成 CLI 或 adapter | IPC 只接受同使用者;私鑰永遠不經 IPC 傳出;開 session 只能用已儲存的主機 | 能開到已儲存主機的 session(和它自己跑 `ssh` 的能力相當);程序鏈可偽造,只用來分組與顯示 |
| 中間人 | 冒充主機 | 第一次連線要人確認指紋,之後釘住並同步;不符就警告,不自動更新 | 使用者在第一次確認時按錯 |
| 讀到磁碟的人 | 拿金鑰、密碼 | 私鑰在保管庫(個別加密,金鑰在系統 keychain);密碼在系統 keychain;狀態檔裡的秘密都是密封記錄 | 已解鎖的這台電腦 |
| russh 的漏洞 | 對端讓 client 當掉或卡住 | 版本釘死、`cargo audit` 進 CI、每個 channel 都有讀取工作 | 零時差;我們接手了 OpenSSH 原本替使用者擋的這一層 |

## 4. 行程模型與邊界

**只有 app 行程持有金鑰和連線。** app(Tauri)裡:

- **同步引擎**:現有的阻塞式執行緒(`sync/engine.rs`),不動。
- **連線 runtime**:一個專用的 tokio runtime 跑 russh。同步引擎與它之間只用 channel 傳訊息,不共用鎖;保管庫的簽章(`AuthSource::sign`)與主機金鑰查表(`HostKeyPolicy::check`)在呼叫 `connect` 的那條執行緒上執行,russh 的 task 用 channel 把請求送過來(借用的 `&dyn` 進不了 'static 的 task);兩者都必須快。
- **`ssh/` 模組**:SSHelter 自己的介面(第 6 節的 `SshEngine`、`Session`)。只有 `ssh/russh_engine.rs` import russh。
- **Session broker**(`session/` 模組):session 表(id、主機、狀態、擁有者、開始時間),核准與 log 的入口。
- **本機 IPC 伺服器**(`ipc/` 模組):第 0 期已從 `agent/server.rs`(`listen_unix`、`take_lock`、`check_socket_path`、`peer`)、`agent/pipe_windows.rs`(`listen`、`pipe_name`)、`agent/peer.rs`(`process_chain`、`identify`)搬到 `src-tauri/src/ipc/`(行為不變,`agent/` 暫時仍用它;第 1 期刪 `agent/` 時去掉 agent 協定;`ipc/mod.rs` 的守門測試保證 `ipc/` 不再指回 `agent`)。socket 在 `<app data>/ipc/sock`(macOS 的 socket 路徑上限 104 bytes,這台實測 69;超過時 `check_socket_path` 回明確錯誤,不退回其他目錄);Windows 用 per-user SID 的 named pipe。只接受同使用者;對端 pid 往上找程序鏈,去掉 SSHelter 自己的執行檔,得到「Terminal → zsh」或「Claude → claude」這種名稱鏈與識別值。
- **保管庫**(`vault/`)、**MCP 的政策、核准視窗、log**(`mcp.rs` 的這部分)沿用。

**兩個薄用戶端,都是 SSHelter 同一個執行檔:**
- `sshelter connect <alias>`:第 7 節。
- `sshelter --mcp`:第 8 節。

**app 沒在跑時**:用戶端沿用現在 MCP 的做法,背景啟動 `--mcp-host`(改名為 `--host`)並等待,啟動用 `SPAWN_LOCK` 加鎖檔序列化;單一實例外掛照舊;交接後 socket 路徑不變,用戶端只要重試連線。

(Windows,第 1 期)broker 在 Windows 用 named pipe `\\.\pipe\sshelter-session-<使用者 SID 字串的 SHA-256 前 16 個十六進位>`,做法同 agent 的 pipe(兩者都由 `ipc::pipe_windows::listen` 建立):DACL 只給目前使用者、拒絕遠端連線、第一個 instance 帶 `FILE_FLAG_FIRST_PIPE_INSTANCE`,擁有者明確設成目前使用者(以系統管理員身分執行時,行程建的物件預設屬於 Administrators 群組,下面用戶端的檢查就會拒絕 SSHelter 自己的 pipe);鎖檔照舊是 `<app data>/ipc/lock`。pipe 兩端的 handle 都是 overlapped 模式(`FILE_FLAG_OVERLAPPED`),每次讀寫仍然等到 I/O 完成才回來:同步模式的 handle 上,所有 I/O 跨執行緒排隊(`NtCreateFile` 的 Remarks;「Synchronous and Overlapped Pipe I/O」),而 broker 用一條執行緒等著讀用戶端、session 的執行緒同時要寫給它,同步的 handle 會讓每次寫都等到用戶端送來東西;agent 的 pipe 也一起改成 overlapped。pipe 沒有 `shutdown`,所以 broker「掛斷」一條連線是先記下已掛斷(之後的讀一律讀到結尾、寫一律失敗),再用 `CancelIoEx` 讓卡在讀寫的執行緒回來(每次讀寫也同時等一個掛斷時設下、不再重設的 event,剛好在取消之後才開始的讀寫一樣會回來);不用 `DisconnectNamedPipe`,它會丟掉用戶端還沒讀的訊框(例如最後的 `exited`)。用戶端讀完掛斷前寫的訊框之後,要等 broker 對這條連線的最後一個 handle 關掉才讀到結尾,所以 CLI 讀到 `exited` 就結束,不等結尾。pipe 也沒有讀取逾時:§7.2 的上限在 Windows 是一個期限(waitable timer,`PipeStream::hang_up_after`),時間到還沒清掉就掛斷;`hello` 到了之後重新設定,所以 `hello` 與 `open_shell` 各有 10 秒,同 Unix。用戶端開 pipe 時帶 `SECURITY_IDENTIFICATION`(pipe 的伺服端只拿到用戶端的身分,拿不到能冒充它的 token);所有 instance 都忙就用 `WaitNamedPipeW` 等,最多 2 秒;找不到 pipe、或等不到空出來的 instance,就照第 4 節背景啟動 SSHelter(已經在跑的 SSHelter 接手這次啟動)。pipe 的名稱來自使用者的 SID,不是秘密:SSHelter 沒在服務時,本機任何程式都能先建一個同名的 pipe(socket 不會,它在只有使用者進得去的目錄裡)。所以 `sshelter connect` 開到 pipe 之後、寫任何東西之前,先讀 pipe 的擁有者(`GetSecurityInfo`),只用目前使用者擁有的 pipe;不是的就關掉不用,印 `Another program is using SSHelter's session pipe (\\.\pipe\sshelter-session-<…>)`、結束碼 1,也不啟動 SSHelter(它的 listener 同樣拿不到那個名稱)。這驗證的是建 pipe 的「使用者」,不是 SSHelter:以這個使用者身分執行的程式都通過,同 Unix 在使用者自己目錄裡的 socket(§3 已接受同使用者的其他程式)。系統拒絕用戶端開 pipe 時(例如 pipe 的 DACL 不讓這個使用者進來)印 `sshelter: cannot connect to SSHelter ({error})`、結束碼 1,同樣不啟動 SSHelter。

**生命週期**:用戶端斷線就關掉它的 session;app 結束全部中斷;螢幕鎖定不中斷(認證完成後不再用到金鑰);app 裡的「進行中的 session」清單可以手動關。

## 5. 資料模型與同步

不另外做資料庫引擎:沿用 `SyncStateV2` 的記錄儲存(帳戶鏈 + space 鏈,`sync/record.rs`、`sync/state_v2.rs`),主機從 ssh_config 文字變成結構化記錄。

### 5.1 `host` 記錄(space 鏈;schema 2)

```
id: 固定的隨機 id(16 hex;改名不再是刪除加新增)
schema: 2
alias: 顯示與 CLI 用的名稱;同一個 space 內唯一(重複時 UI 拒絕;同步合併撞名時後者加 " (2)" 並通知)
hostname, port(預設 22), user(可空 = 本機使用者名稱)
auth: "key" | "password" | "interactive"
key_id: 保管庫的 key id(auth = key 時必填;指到的 keyslot 不存在時主機標「需要金鑰」)
jump: [host id, ...](依序經過;可空;只能是已儲存的主機;循環時 UI 拒絕、引擎拒絕)
keepalive_secs(預設 30)、keepalive_max_missed(預設 3)、connect_timeout_secs(預設 15)
host_key: { algorithm, public_key(base64), fingerprint("SHA256:…"), pinned_at_ms, pinned_by_device_id } | null
tags: [string], notes: string
imported: { source: "~/.ssh/config", at_ms, unsupported: [{keyword, value}] } | null  ← 匯入時保留不支援的設定原文,標「需要處理」
```

合併規則不變(LWW,`updated_at_ms`、`version`)。`host_key` 是記錄的一部分,所以釘住的值會同步;「接受新金鑰」改寫它並同步。

### 5.2 金鑰記錄

- `keyslot`(明文中繼資料)升到 schema 2:`name, public_key, fingerprint, key_type, has_passphrase, created_at_ms, origin_device_id`;刪掉 `mode` 與任何檔名欄位。
- `key`(密封私鑰)不變。
- 保管庫(`vault/store.rs`)的項目與 id 不變;`EntryOrigin` 不變。
- 「只在這台」的金鑰:保留概念,放在本機 store(見 5.4),不進帳戶。

### 5.3 Space 與帳戶

- space 仍是一條鏈、分享的單位,預設 Personal;不再對應本機檔案。`spaces.rs` 留下記錄層,刪掉檔案層。
- 帳戶鏈的 `device`、`meta`、`space`、`spacekey`、`keyslot`、`key` 記錄留用;`device` 記錄不再列插槽檔名。
- 帳戶 `schema_version` 2 → 3:舊版讀到就唯讀並顯示「需要更新」(現有閘門,`record.rs`);key rotation 的 `copy()` 要把 `host` schema 2 與 `keyslot` schema 2 列入。

### 5.4 本機 store

沒有帳戶時,主機與只在這台的金鑰存在本機 store(`sync-state.json` 內的 `local` 區段,和今天本機金鑰記錄同一個地方);加入帳戶後可用現有的「搬進 space」流程把主機搬進 space。每台電腦的設定(終端機選擇、keepalive 預設等)不同步,照舊放 settings。

### 5.5 密碼

存這台的系統 keychain,鍵 `host:<host id>`;第一版不同步。

## 6. 連線引擎(`ssh/`)

### 6.1 介面

```rust
// 所有方法都是同步呼叫:引擎內部有自己的 tokio runtime(§4)。引擎只做連線;提示、保管庫、UI 都在 broker(§7)。
pub trait SshEngine: Send + Sync {
    /// 建立到 target 的連線(跳板鏈、每一跳的主機金鑰檢查、認證)。HostKeyUnknown/HostKeyMismatch 帶回觀察到的金鑰:
    /// 呼叫端問使用者、釘住,再呼叫一次(§6.2 第 3 步)。
    fn connect(&self, target: &Target, host_keys: &dyn HostKeyPolicy, auth: &dyn AuthSource) -> Result<Box<dyn Session>, ConnectError>;
}
pub trait Session: Send + Sync {
    fn shell(&self, pty: Pty) -> Result<Box<dyn ShellChannel>, SessionError>;
    fn exec(&self, command: &str, timeout: Duration, output_cap: usize) -> Result<ExecResult, SessionError>; // 無 PTY;到上限就 close(),連線仍可用
    fn is_alive(&self) -> bool;                              // 連線自己的狀態(§6.2 第 3 步),不是錯誤的種類
    fn disconnect_reason(&self) -> Option<DisconnectReason>; // 出事那一跳自己的紀錄(§6.2 第 2 步)
    fn close(&self);                                         // 明確關閉整條鏈:每一跳 disconnect()
}
pub trait ShellChannel: Send + Sync {
    fn write(&self, data: &[u8]) -> Result<(), SessionError>;               // stdin
    fn read(&self, buf: &mut [u8]) -> Result<usize, SessionError>;           // PTY 輸出(stdout/stderr 合併);0 = 已結束
    fn window_change(&self, cols: u16, rows: u16) -> Result<(), SessionError>; // shell 就緒前送的會被忽略,broker 記住最後一次再送(§7.2)
    fn exited(&self) -> Option<Exit>;                                        // 結束後才有值
    fn close(&self);
}
pub trait HostKeyPolicy: Send + Sync {
    /// 引擎在呼叫 connect 的執行緒上同步呼叫(russh 的 callback 把問題送過來):只查表,不等人、不碰 UI(§6.2 第 3 步)。
    fn check(&self, hop: &HopRef, key: &HostKey) -> HostKeyVerdict;         // Pinned | Unknown | Mismatch { pinned }
}
pub trait AuthSource: Send + Sync {
    /// 保管庫 Material::sign;RSA 的雜湊由引擎傳入(sha256 | sha512),見 §6.3;必須快(不問 passphrase、不等核准)。
    fn sign(&self, key_id: &str, data: &[u8], rsa_hash: Option<RsaHash>) -> Result<Signature, AuthError>;
    fn public_key(&self, key_id: &str) -> Option<String>;                    // 該金鑰的 OpenSSH 公鑰行(公鑰登入要先送公鑰);None = 金鑰不存在
    fn password(&self, hop: &HopRef) -> Option<Secret>;                      // 已有的密碼(keychain 或剛問到的);None = 不試密碼
    fn interactive(&self, hop: &HopRef, prompts: &[Prompt], deadline: Instant) -> Option<Vec<Secret>>; // 在 deadline 前回答;None = 放棄 → 引擎丟掉連線;提示文字是伺服器寫的,顯示前先清理(同 banner),每一行前面加真正的 (user@alias)(第 1b 期,§7.1)
    fn banner(&self, hop: &HopRef, text: &str) {}                            // 伺服器登入時送的 banner(sshd 的 Banner);每跳最多 64 KiB;預設丟掉;顯示前先清理:控制字元與雙向文字控制字元換成 ?(第 1b 期,§7.1)
}

pub struct Target { pub hops: Vec<Hop> }   // 依序經過,最後一個是目標;每一跳自帶設定
pub struct Hop {
    pub id: HostId, pub alias: String, pub hostname: String, pub port: u16, pub user: String,
    pub auth: AuthMethod,                   // Key { key_id } | Password | Interactive(依序嘗試的起點;伺服器拒絕才換下一個)
    pub pinned: Option<HostKey>,            // 已釘住時限縮 preferred.key 成它的演算法家族
    pub connect_timeout: Duration, pub keepalive_every: Duration, pub keepalive_max_missed: u32,
    pub nodelay: bool,                      // shell 用的連線 true
}
pub struct HostKey { pub algorithm: String, pub public_key: Vec<u8>, pub fingerprint: String } // "SHA256:…"
pub enum ConnectError {
    BadJumpChain { why: String },
    Unreachable { hop: HopRef, reason: String },                       // DNS、TCP
    Timeout { hop: HopRef, phase: Phase },                              // Tcp | Handshake | Auth
    HostKeyUnknown { hop: HopRef, key: HostKey },
    HostKeyMismatch { hop: HopRef, key: HostKey, pinned: HostKey },
    NoCommonHostKeyAlgorithm { hop: HopRef, ours: Vec<String>, theirs: Vec<String> },
    AuthFailed { hop: HopRef, tried: Vec<AuthMethod>, reason: String, password_wanted: bool }, // 含「RSA 只能 SHA-1」;password_wanted 見下方(第 1b 期)
    AuthAbandoned { hop: HopRef, reason: String },                      // sign 出錯、提示逾時或取消:連線已丟掉
    Protocol { hop: HopRef, text: String },                             // russh 的錯誤文字,不含秘密
}
pub struct ExecResult { pub ended: Ended, pub exit_code: Option<u32>, pub signal: Option<String>, pub stdout: Vec<u8>, pub stderr: Vec<u8>, pub truncated: bool }
pub enum Ended { Exited, Signaled, TimedOut, Truncated, Disconnected } // Truncated:引擎在 output_cap 關掉 channel,結束碼不明、連線仍可用
pub enum Exit { Code(u32), Signal(String), Refused(String), Disconnected } // Refused:伺服器拒絕 PTY 或 shell 的請求,連線仍在(第 1b 期)
```

`Target` 是 host 記錄解析後的結果(含跳板鏈)。`HostKeyPolicy` 與 `AuthSource` 由 broker 實作:它決定提示送給誰(決策 7)。引擎不碰保管庫、不碰 UI。

(第 1b 期)`AuthFailed` 的 `password_wanted`:伺服器最後的方法清單仍提供 `password`,而這條連線沒有試過密碼(`AuthSource::password` 沒有給,或登入的順序沒走到密碼)——現在輸入的密碼有機會登入。broker 據此問人,再以該跳**原本的方法順序**重連,並讓 `AuthSource::password` 立刻從記憶體回答剛輸入的密碼;連線開著時不能等人輸入密碼(那會讓 russh 空轉,§6.2 第 4 步)。不能一律改成密碼優先:`AuthenticationMethods publickey,password` 的伺服器要先收公鑰(部分成功)、再收密碼,密碼優先的重連不送公鑰,永遠登不進去。只有方法順序裡沒有密碼的跳(從 keyboard-interactive 開始的跳)才改成密碼優先重連。`banner`:伺服器在登入途中送的 banner,引擎在呼叫 connect 的執行緒上、下一個提示之前(最晚在登入結束時)交給 `AuthSource`;兩次交付之間收到的 banner 接成一段、一次交出。伺服器在登入期間可以一直送 banner(單一封包最大 256 KiB,啟用壓縮時只要幾百位元組就送得出去),所以每一跳的 banner 合計最多保留 64 KiB(已交出去的也算在內):在字元邊界截斷,後面補一行說明伺服器其餘的 banner 被丟掉了,之後再來的一律丟掉,不再占記憶體。

`sign` 的合約(第 0 期):russh 的 `Signer::auth_sign(&mut self, &AgentIdentity, Option<HashAlg>, Vec<u8>)` 把待簽緩衝區與**呼叫端選的** `hash_alg` 原樣交給簽章器,russh 自己不檢查;引擎把 `hash_alg` 轉成 `rsa_hash` 傳給 `sign`,RSA 金鑰而 `rsa_hash` 是 `None`(伺服器只接受 SHA-1)時引擎不呼叫 `sign`、直接回 `ConnectError::AuthFailed` 並說明原因。`sign`、`password`、`interactive`、`banner` 都要**快**:russh 在等簽章與等 keyboard-interactive 的回答時把整條 session 停住、不讀 socket,等待期間伺服器的 `LoginGraceTime` 照跑,`disconnect()` 也變成 no-op(§6.2 第 4 步);`banner` 在兩個登入請求之間被呼叫,慢了同樣耗掉 `LoginGraceTime`,超過 keepalive 間隔還會讓 russh 空轉。passphrase 的輸入、保管庫解鎖、核准等使用者互動都在呼叫引擎之前做完;keyboard-interactive 的提示本來就在認證途中回答,所以有逾時(§6.2 第 4 步)。

### 6.2 流程

1. 解析 host 記錄:跳板鏈展開成 `[jump1, jump2, …, target]`,每一跳都是已儲存的主機;循環或缺主機 → `ConnectError::BadJumpChain`。
2. 連第一跳(TCP + 握手);之後每一跳:在前一跳的 session 上開 direct-tcpip 通道到下一跳的 hostname:port,把通道當成串流再跑一次連線(russh:`channel_open_direct_tcpip` → `into_stream` → `connect_stream`)。(第 0 期)russh 沒有連線或握手的逾時,`connect` 會一直等:每一跳的 `connect`(含握手)都用 `tokio::time::timeout` 包住,時間取 host 記錄的 `connect_timeout_secs`;§11 的「連不上」要涵蓋握手沒有回應。(第 1 期)握手另有內層上限 `stall_limit` = min(connect_timeout, 0.75 × keepalive_secs),至少 1 秒:russh 收到伺服器的版本行就啟動 keepalive 計時器、登入完成前從不重設,計時器到期後它的迴圈會空轉燒掉一顆核心,所以登入前對伺服器的每一次等待都要在計時器到期前結束(TCP 連線與等人的提示不受此限)。跳板鏈由一個連線物件擁有整條生命週期,關閉一律用明確的 `disconnect()`(只丟掉外層的 `Handle` 不會結束任何一跳);外層先沒了時 russh 不會替內層呼叫 `Handler::disconnected`、內層的 `Handle` future 與 `is_closed()` 只回答「結束了」,所以斷線原因取自出事那一跳自己的紀錄(內層自己先結束、外層還活著的情況尚未量測,§16)。
3. 每一跳做主機金鑰檢查(`HostKeyPolicy`):`Pinned` 繼續;`Unknown` → broker 在 app 視窗要求確認(接受後寫進該主機記錄並同步);`Mismatch` → 警告視窗,只有按「接受新金鑰」才更新,否則 `ConnectError::HostKeyMismatch`。(第 0 期)**引擎的 `check_server_key` 不等人**:russh 在這個 callback 回來之前不讀 socket,等待期間伺服器的 `LoginGraceTime`(引擎無從得知)照跑,答得慢時 `connect` 仍回 Ok 但連線已死、失敗要到之後的呼叫才浮現、面貌依呼叫而異,甚至第一次呼叫還能得到正常的拒絕。所以:`Unknown`/`Mismatch` 時 handler 記下金鑰(演算法、公鑰、指紋)並回 `false`,這次 `connect` 以 `UnknownKey` 失敗;broker 拿記下的金鑰問使用者;接受(釘住並同步)後**重連**,第二次 `Pinned` 直接通過。引擎自己記下「拒絕的原因」(沒看過 vs 不符),因為 russh 兩種都回同一個 `UnknownKey`。已釘住的主機把 `Config::preferred.key` 限縮成釘住的演算法家族(伺服器之後新增別種金鑰或 russh 升版改預設順序時才不會誤報不符;沒有共同演算法時用 `NoCommonAlgo` 的 `ours`/`theirs` 組訊息)。連線是否還活著一律看連線自己的狀態(`Handle` future 是否已結束、`is_closed()`、handler 記下的 `disconnected`),不看錯誤的 variant,並在第一次呼叫失敗之後才判斷(`connect` 剛回來時 `is_closed()` 一律 false)。
4. 認證依序:公鑰(`key_id`;有 passphrase 則走現有的「輸入或記住」)→ 密碼(keychain;沒有就問,可勾記住)→ keyboard-interactive。全部失敗 → `ConnectError::AuthFailed{tried}`。(第 0 期)**只有伺服器拒絕時,才在同一條連線上換下一個方法**(拒絕時呼叫回 `AuthResult::Failure` 並列出剩下的方法,連線仍可用):`sign` 回錯誤、`interactive` 回 `None`、提示逾時或被取消,一律丟掉這條連線(`Handle`),需要時重連,不在同一條連線上換方法(第 1 期:`password` 回 `None` 只是跳過密碼方法——密碼是 `authenticate_password` 的引數,russh 沒有停在那裡等它;所以使用者取消密碼對話框後,伺服器若還提供 keyboard-interactive,引擎會接著問,broker 要記住這次取消)——russh 在等簽章與等 keyboard-interactive 回答時把 session 停住,出錯後 session 卡死、`authenticate_*` 永遠沒有回答、`disconnect()` 是 no-op(讀 russh 0.64.1 原始碼推得,§12 的測試要量)。每個 `authenticate_*` 都用 `tokio::time::timeout` 包住;(第 1 期)上限同樣是步驟 2 的 `stall_limit`,等人的部分除外;keyboard-interactive 回答送出後等伺服器裁決的這段仍用提示的上限(用 `stall_limit` 會切斷慢的推播核准)——伺服器裁決慢過 keepalive 間隔時 russh 會空轉,這是 russh 的限制,留待上游修正;keyboard-interactive 的提示給使用者的等待有上限(取 `connect_timeout_secs` 的 4 倍,最少 60 秒),逾時或取消 → 丟掉連線;等待期間若伺服器先斷(寬限時間),重連後再問一次(一次性密碼要重新產生)。
5. keepalive:每 `keepalive_secs` 一次,連續 `keepalive_max_missed` 次沒回應就斷線並通知擁有者。(第 0 期)russh 預設關閉 keepalive(`keepalive_interval: None`),引擎自己設;russh 的語意是「這麼久沒收到任何東西才送一次」、超過 `keepalive_max` 次沒回應才斷,察覺斷線要 **(`keepalive_max_missed` + 1) × `keepalive_secs`**(§11 的 `{n}` 用這個值);keepalive 只在認證完成後計時,認證前由第 2 步的逾時與第 3 步的存活檢查負責。

### 6.3 紀律與限制

- 每個 channel 都有專屬的讀取工作(russh 已知:沒人讀的 channel 會卡住整條連線,維護者拒絕修改)。
- 演算法用 russh 預設(mlkem768x25519、curve25519-sha256、chacha20-poly1305、aes-gcm、rsa-sha2、strict-kex),第一版不提供舊演算法;拿掉 `ssh-rsa`(SHA-1)分成兩件事(第 0 期):(a) 主機金鑰:`Config::preferred.key` = `Preferred::DEFAULT.key` 去掉 `Rsa { hash: None }`;只給 ssh-rsa 的主機連不上,錯誤訊息用 `NoCommonAlgo` 的 `ours` 與 `theirs` 說明原因(已驗證);(b) 登入簽章:**拒絕 SHA-1 是引擎自己的檢查**,不是 russh 的設定——`preferred.key` 只管主機金鑰與協商,使用者認證的雜湊由呼叫端傳給 `Signer`,預設會簽 SHA-1;RSA 金鑰且 `hash_alg` 為 `None` 就不簽、回明確錯誤;`best_supported_rsa_hash()` 只對 RSA 金鑰呼叫(伺服器還沒送 `server-sig-algs` 時它最多等 1 秒)。(b) 要有一個會擋下來的測試(§12)。
- (第 0 期)每個 channel 的讀取工作到 IPC 之間用有界佇列並定好滿了怎麼辦(終端機暫停時不能拖住整條連線);exec 的輸出設上限,到了就 `close()`,連線仍可用。
- (第 0 期)shell 用的連線設 `nodelay = true`(russh 預設 false、Nagle 開著;`connect_stream` 的跳板要自己對 socket 設,russh 只在 `connect` 裡套用)。
- (第 0 期)不要假設輸出的換行是 `\n`:Windows OpenSSH 的 exec 輸出以 CRLF 結尾(對 `echo` 觀察到);`ssh_exec` 照原樣回位元組,SSHelter 自己切行的地方兩種都要收。
- 不支援 sk-* 金鑰;不做 agent forwarding。
- 版本釘死 `=0.64.x`;升版是獨立的任務,要跑整合測試。
- 第 0 期已驗證:ssh-key 0.6.7(保管庫)與 russh 釘的 ssh-key 0.7.0-rc 並存;Windows 實機連線;`Signer` 接 `Material::sign`(Ed25519、ECDSA P-256、RSA 3072 都登入成功);見試驗報告。

## 7. Session broker、本機 IPC、CLI

### 7.1 IPC 協定

長度前綴的訊框:`u32 長度 | u8 型別 | 內容`。控制訊息是 JSON,資料訊息是原始位元組。

- 用戶端 → app:`hello{client: "connect" | "mcp", client_info?}`、`open_shell{host, pty{cols, rows, term}}`、`exec{host, command, timeout_secs}`、`data`(stdin)、`window_change{cols, rows}`、`answer{question_id, value | cancel}`、`close`。
- app → 用戶端:`opened{session_id}`、`data`(stdout/stderr 合併,因為是 PTY)、`exec_result{ended: exited | signaled | timed_out | truncated | disconnected, exit_code (可空), signal (可空), stdout, stderr, truncated: bool}`(第 0 期:被訊號殺掉的指令沒有結束碼,連線中斷也沒有;輸出到上限時 `truncated`,連線仍可用;不能回 0)、`question{question_id, kind: host_key_notice | passphrase | password | interactive, text, echo: bool, deadline_ms}`(逾時視同取消:連線丟掉,§6.2 第 4 步)、`event{connected | disconnected{reason} | error{kind, text}}`、`exited{code (可空), signal (可空)}`;跳板的 `disconnected{reason}` 取自出事那一跳自己的紀錄(§6.2 第 2 步)。
- `host` 可以是 alias 或 host id;alias 在多個 space 重複時回錯誤要求用 id。
- (第 1b 期)訊框的長度是 big-endian、包含型別那一個位元組;型別 `1` = 控制(一則 JSON,以 `type` 欄位分辨)、`2` = 資料;一個訊框最多 1 MiB,超過、型別不明或在訊框中間斷掉都結束連線。長度為 0(連型別位元組都沒有)也結束連線;1 MiB 指的是長度欄位的值(型別位元組加內容)。`event{error}` 的 `kind` 是給程式看的短字:`protocol`、`unsupported`、`host`、`host_key`、`auth`、`connect`、`shell`、`input`(`session::protocol::kinds`)。`hello` 另帶 `version`(協定版本,目前 `1`):app 更新後磁碟上的 CLI 可能和執行中的 app 不同版,版本不合時 broker 回錯誤,請使用者重開 SSHelter。`host` 寫成 `{"alias": …}` 或 `{"id": …}`,`--id` 明確指 id、不和 alias 混淆。`question` 的 `deadline_ms` 是從送出起還等多少毫秒,`host_key_notice` 為 `null`(只顯示,不回答);`answer` 帶 `value` 或 `cancel: true`。`event` 另有 `banner{text}`:伺服器在登入時送的 banner,已清理(見下一條)。
- (第 1b 期)伺服器寫的文字,顯示給人看之前一律先清理:banner,以及 keyboard-interactive 的提示(也就是 `question.text` 裡伺服器寫的部分,和 banner 同一套規則)。CRLF 換成 LF;其他控制字元(含 C1)換成 `?`;不是控制字元、卻能騙人的格式字元也換成 `?`:雙向文字控制字元(U+061C、U+200E、U+200F、U+202A 至 U+202E、U+2066 至 U+2069,它們能讓文字以不同於書寫的順序顯示)與行/段分隔字元(U+2028、U+2029,有些終端機可能在這裡斷行);只留 Tab 與 LF,LF 是唯一的換行。keyboard-interactive 的提示另外在**每一行**前面都加上 broker 自己的 `(user@alias) `,不只第一行:跳板可以用換行接上 `(deploy@db) Password: ` 假冒另一跳,讓輸入密碼的那一行看起來是另一台在問;每一行都有真正的前綴,那一行就仍然標著真正在問的那一跳。已知的限制:終端機自動換行時,一行夠長的提示可以把假冒的 `(deploy@db) ` 推到下一個畫面列的開頭;真正的修法需要知道終端機寬度,第 1b 期不做。`user` 來自 ssh_config(`ssh -G` 照抄、沒有驗證),所以前綴裡的 `user` 與 `alias` 也先清理,並壓成一行(Tab、LF 也換成 `?`)。提示以 LF 結尾時,結尾的 LF 保留,游標落在新的一行;那一行沒有伺服器的文字,不加前綴。`event{error}` 與 `event{disconnected}` 的文字也是這樣:引擎的錯誤文字可能照抄對端送來的位元組(例如 `invalid label: '…'`),所以 broker 送給用戶端的每一則訊息(shell 自己的輸出除外)都從同一個地方出去,文字在那裡照同一套規則清理,`event{error}` 與 `event{disconnected}` 的文字也在那裡限長:最多 512 個字元(清理之後才算,在字元邊界截,被截的後面加 `…`)。伺服器能讓這些文字長過一個訊框(1 MiB),放不下的事件不會被寫出去,用戶端就只收到 `exited`、不知道原因;banner 不截,它本來就可以很長(引擎已把它限在 64 KiB)。`exited{signal}` 的訊號名稱是伺服器取的名字(`Sig::Custom` 可以是任何文字),所以只讓大寫字母、數字、`_`、`+`、`-` 通過(最多 32 個字元),其他一律寫成 `UNKNOWN`:沒有哪個訊號叫這個名字,用戶端對不到訊號編號。

### 7.2 Broker 規則

- 一個 session 一個擁有者(IPC 連線);連線斷掉就關 session;app 結束全部關。
- (第 1b 期)一條 IPC 連線一個 session。新連線的 `hello` 與接著的 `open_shell` 各要在 10 秒內送到,否則 broker 直接關掉連線(一條連線占一個名額和一條執行緒,不能無限期留著);`open_shell` 之後連線不受 IPC 伺服器的閒置逾時限制:閒置的 shell 照樣開著。(第 1 期,Windows)Windows 也是各 10 秒:pipe 沒有讀取逾時,上限是一個期限,`hello` 到了之後重新設定(§4)。
- (第 1b 期)第一則訊息不能用時,broker 先告知再關連線(不是默默關掉)。版本先看:`hello` 的 `version` 不是 `1`,不論 `client` 寫什麼、其他欄位讀不讀得懂,都回 `error{kind: protocol}`,請使用者結束 SSHelter 再重開;讀不懂的第一則訊息(不是 JSON、型別不明的訊框、`hello` 缺 `version`)回 `error{kind: protocol}`(`SSHelter could not read the first message.`);一開始就送資料、或第一則不是 `hello`,回 `The first message must be hello.`;`hello` 之後來的不是 `open_shell` 也一樣先告知(`SSHelter expected open_shell.`)。`exec` 與 `hello{client: mcp}` 在第 1b 期回 `error{kind: unsupported}`。
- (第 1b 期)session 表從 `open_shell` 起就有那一筆,狀態是 connecting 或 open,不是連上之後才有:正在被問問題、在等主機金鑰視窗、shell 還在開的用戶端,也都是 session。`has_sessions()`(app 據此決定關掉視窗時要不要繼續執行)與 `end_all()` 都把連線中的算進去,結束時一筆都不漏。開不成 session 時 broker 送 `event{error}` 再送 `exited{code: null, signal: null}`,然後關掉連線(連執行緒都起不來時也是)。用戶端斷線時,broker 等 shell 第一次有輸出(或開啟滿 3 秒)才關 shell 與連線,免得 macOS 的 sshd 留下拿著 PTY 的程序;shell 還沒開時不開;引擎已經在開的,等它開好再關;這兩種都不告訴用戶端 shell 開了(沒有 `opened`)。
- (第 1b 期)app 結束時(`end_all`)每個 session 的用戶端都收到 `event{disconnected{reason}}`(`SSHelter quit, so the connection to {alias} was closed.`)與 `exited`,不論 session 當時在做什麼;`end_all` 回來(app 隨即結束)的時候這些用戶端都已經被告知,不是等 session 的執行緒結束:還在連線的(問問題、等主機金鑰視窗、引擎連線中)立刻取消,另開一個執行緒告知(那句話與 `exited` 在連線的寫入鎖下一次寫完,中間不會夾別的訊框;`exited` 是最後一個訊框,之後什麼都不再寫,banner 與主機金鑰通知對已經走了的用戶端也不寫)、關連線,然後才把那一筆從 session 表移除,`end_all` 等的是這件事,不是 session 的執行緒(引擎的 connect 無法中斷,app 不等它:那個執行緒自己跑完,關掉連上的 session、不開 shell;連線中的 `{alias}` 是用戶端要求的名稱,連上之後才是主機的別名);shell 已開的,在 shell 第一次有輸出(或開啟滿 3 秒)關掉之後告知,所以 app 結束時要在 `end_all` 等 `QUIT_WAIT`(`session::broker::QUIT_WAIT`,3 秒再加 2 秒;只等 3 秒的話,剛好卡在界線上的 shell 會在告知之前就讓 `end_all` 回來);正在開的 shell 同樣要等引擎開好才能關、才能告知(`Session::shell` 也無法中斷;它不會再被告知 `opened`),這可能比 `QUIT_WAIT` 更久:`end_all` 等到時間就回來、app 結束,那個用戶端的連線沒有任何說明就斷了,它的終端機印的是 CLI 自己的 `The connection to SSHelter ended.`,不是原因;自己先結束的 shell(結束碼、被訊號殺掉、伺服器拒絕 PTY)照實回報它自己的結束,不說成 app 結束。`end_all` 開始之後才送來的 `open_shell` 同樣被拒絕,收到同一句。
- 開 session 的核准:`client = connect`(終端機 CLI)不核准;`client = mcp` 依第 8 節。
- 提示的去向(決策 7):擁有者是 `connect` → `question` 訊框送到 CLI,在終端機裡問;擁有者是 `mcp` 且模式 `ask` → app 視窗;`mcp` 且 `auto_log` → 回 `error{needs_interaction}`。主機金鑰的確認永遠在 app 視窗(決策 6),CLI 只收到 `host_key_notice`。
- 每個 session 寫一筆 log(第 8.4 節的同一份 log,`client` 欄位區分 connect 與 mcp)。
- 請求者辨識:接受連線時做一次(peer uid 檢查 → pid → 程序鏈 → 去掉自己的執行檔 → `identify`),附在該連線的每個請求上;認不出來顯示 `an unknown program`。
- 視窗大小(第 0 期):broker 記住每個 session 最後一次的 `window_change`,PTY 建好、shell 就緒後再送一次(PTY 之前送的會被忽略)。

### 7.3 `sshelter connect <alias>`

- 參數:`<alias>` 或 `--id <host id>`;`--new-window`/`--new-tab` 不在 CLI(由 app 的啟動程式決定)。
- app 沒跑:背景啟動並等待(第 4 節),等不到就印 `SSHelter did not start within 12 seconds.` 結束碼 1。
- 連上 broker 後送 `hello`、`open_shell`(`term` 取 `$TERM`,預設 `xterm-256color`),進 raw mode;stdin → `data`;`data` → stdout;視窗大小變更 → `window_change`;`question` → 暫時離開 raw mode、在終端機問、送 `answer`、回到 raw mode;`exited{code}` → 還原終端機、以該 code 結束。
- Unix:raw mode 用 termios(第 1b 期用 app 已有的 `libc`,沒有加 `nix`),`SIGWINCH` 用 tokio 的 `SignalKind::window_change`。
- Windows(第 1 期;原本排在第 3 期,2026-10-13 使用者決定 1.0 的 beta 之前做好):release 版的 `sshelter.exe` 是 GUI 程式(`windows_subsystem = "windows"`),Windows 的 shell 不等 GUI 程式結束、Windows Terminal 的分頁也不給它 console,所以另附一個 console 程式 `sshelter-cli.exe`,放在 `sshelter.exe` 旁邊:它只用 std,用同樣的參數啟動自己資料夾裡的 `sshelter.exe`(不經 shell;標準輸入輸出照原樣交給它)、等它結束、以它的結束碼結束(32 位元照傳),自己不理會 Ctrl-C 與 Ctrl-Break,交給 `sshelter.exe` 處理:用一個對這兩個事件回 TRUE 的 handler,不用 `SetConsoleCtrlHandler(NULL, TRUE)`(那個「忽略 Ctrl-C」的屬性會被子行程繼承);關掉視窗、登出與關機照預設結束它。這個 handler 在啟動 `sshelter.exe` 之前裝好,裝不起來就不啟動:否則一個 Ctrl-C 會結束它、把終端機還給 shell,`sshelter.exe` 卻還在讀 console。`sshelter.exe connect` 先看參數(錯了就印用法、結束碼 2;印之前先接上 console,release 版才看得到),再 `AttachConsole(ATTACH_PARENT_PROCESS)` 接上 `sshelter-cli.exe` 的 console(debug 版本來就是 console 程式、已經有 console,這個呼叫回 `ERROR_ACCESS_DENIED`,什麼都不變);接上之後才找 console 的 buffer(GUI 程式接上之前,標準 handle 可能無效):輸入用標準輸入(是 pipe 或檔案就不是 console;完全沒有標準輸入時才開 `CONIN$`),輸出用標準輸出所在的 console screen buffer,標準輸出不是 console 時開 `CONOUT$`。標準輸入不是 console 就印 `sshelter connect needs a terminal.`、結束碼 1(同 Unix),不連也不啟動 SSHelter。
- (第 1 期,Windows)console 的設定:一開始(`Tty::new`)只讀下輸入與輸出的模式和兩個 code page,什麼都不改;連上 broker,裝好 panic hook、watchdog 與 control handler(`SetConsoleCtrlHandler`;要在 `AttachConsole` 之後裝,接上 console 會把行程的 handler 表重設回只剩預設的那個)之後,才接手 console(`Tty::take_over`):輸出開 `ENABLE_VIRTUAL_TERMINAL_PROCESSING`(與它需要的 `ENABLE_PROCESSED_OUTPUT`),輸出的 code page 設成 UTF-8。所以在 CLI 等 SSHelter 啟動時按 Ctrl-C,程式照預設結束,console 原封不動;接手之後任何結束路徑(正常結束、`Tty` 被丟掉、panic hook、watchdog)都把四個值放回去,輸入的模式先;還沒接手就什麼都不放回。handler 或 watchdog 裝不起來就印 `sshelter: cannot take over the console's control keys: {error}`、結束碼 1;開 VT 的 `SetConsoleMode` 被拒絕成 `ERROR_INVALID_PARAMETER` 的 console(傳統 console;Microsoft 的「Example of Enabling Virtual Terminal Processing」說這個錯誤就是舊版的記號)接手不了,印 `sshelter: the console does not support virtual terminal sequences ({error})`、結束碼 1;這兩種情形 console 都沒被動過。每個模式的輸入與輸出都從一開始存下的值算,不從上一個模式疊上去:raw mode 的輸出另開 `DISABLE_NEWLINE_AUTO_RETURN`(換行照 xterm),同 OpenSSH 的 raw mode 關掉 Unix 終端機的 `OPOST`;問問題與 cooked mode 的輸出保持一開始的換行方式,CLI 自己的句子才從行首開始(Unix 靠 `ONLCR`)。拒絕 `DISABLE_NEWLINE_AUTO_RETURN`(同樣是 invalid parameter)的 console 試一次就記住,之後的 raw mode 只開 VT(同一份範例:收到這個錯誤就少開新的旗標再試)。寫進 console 用 `WriteConsoleW`(UTF-16),所以顯示的字和 code page 無關;不把一個 UTF-8 字元切成兩次寫(切在一段結尾的字元等下一段,到最後照原樣寫)。結束時先讓寫終端機的執行緒寫完手上的輸出(最多 200 毫秒;之後不再開始新的一段,正在寫的那段最多再等 200 毫秒),才放回 console:放回之後輸出回到一開始的模式與 code page(通常沒有 VT、也不是 UTF-8),晚到的輸出可能變成原始的跳脫序列。收到 `opened` 才把輸入改成 raw:關掉 `ENABLE_LINE_INPUT`、`ENABLE_ECHO_INPUT`、`ENABLE_PROCESSED_INPUT`,開 `ENABLE_VIRTUAL_TERMINAL_INPUT`(按鍵成為 VT 序列,Ctrl-C 是送給遠端的字元),其他旗標(quick edit、insert mode、`ENABLE_EXTENDED_FLAGS`、滑鼠與視窗事件)照一開始的值;`question` 用 console 自己的行編輯問(`ENABLE_LINE_INPUT`、`ENABLE_PROCESSED_INPUT`,`echo` 決定有沒有 `ENABLE_ECHO_INPUT`,不開 `ENABLE_VIRTUAL_TERMINAL_INPUT`),問之前 `FlushConsoleInputBuffer`。
- (第 1 期,Windows)按鍵用 `ReadConsoleW` 讀(一次最多 4096 個 UTF-16 單位,轉成 UTF-8;一個代理對分在兩次讀取時接起來,落單的一半變 U+FFFD;讀進來的緩衝區讀完就清掉),而且沒有一次讀取跨過模式的切換。這是在 CI runner 的 conhost 上量出來的(子行程有自己的 console,用 `WriteConsoleInputW` 打字;`cli/real_console_tests.rs` 留作迴歸測試):讀取等著的時候,其他 console 呼叫(設模式、清輸入、讀大小、寫)都立刻回來,不被擋住;但等著的讀取維持它開始時的樣子:raw 的讀取在切到隱藏的問題之後照樣把下一個鍵當 raw 收走、不顯示;行讀取把已經打在編輯列裡的字留著,`FlushConsoleInputBuffer` 清不到(先打 `hunt`,切成隱藏、清掉輸入之後再打 `er2` 與 Enter,讀到 `hunter2`);取消讀取(`CancelIoEx`、`CancelSynchronousIo`)讓呼叫立刻回來,但被取消的讀取還活在 console 裡,收走下一個鍵或下一行。所以:cooked mode 什麼都不讀;一個問題只讀一行(讀到了、或被 Ctrl-C 結束,就等下一個模式);切到 raw 或問題之前,先用程式自己寫進輸入的一個 Enter(`WriteConsoleInputW`)結束等著的讀取,最多等它 500 毫秒,丟掉它讀到的東西,再清掉 console 裡還有的輸入(讀取沒收走的 Enter 不能留給新模式的第一次讀取),才設模式。在問題中結束 session(切回 cooked、丟掉先打的字:broker 結束 session、app 結束、連線斷了)時也一樣,而且是在 console 還隱藏輸入的時候結束問題的行讀取:否則這個讀取和打進它編輯列的半個密碼會留到一開始的(會顯示輸入的)模式裡,把接下來打的字顯示出來、收走。切回 cooked 而保留先打的字時不叫醒讀取(cooked 不讀,接下來不是程式結束,就是下一次切換,那時再結束它)。和 Unix 不同的兩點:`opened` 之前打的字留在 console 裡、不顯示(Unix 的終端機會顯示,也能就地編輯),shell 開了才以 raw 讀到,Backspace 與 Enter 都當成按鍵送給 shell;問題的那一行以 Ctrl-Z 開頭時(Windows 的輸入結束,讀到 `"\x1a\r\n"`)同 Unix 的 Ctrl-D,取消問題,而 Ctrl-D 在 Windows 只是答案裡的一個字(raw mode 的 Ctrl-Z 是送給遠端的字元)。讀到 0 個字(Ctrl-C 結束了行讀取;`ERROR_OPERATION_ABORTED`、超過緩衝區的字數也算)不是結束;其他讀取失敗表示 console 不見了,同 `SIGHUP`:結束碼 129,watchdog 起動。
- (第 1 期,Windows)視窗大小每 250 毫秒用 `GetConsoleScreenBufferInfo` 的 `srWindow` 看一次,變了才送 `window_change`(讀不到的不送;不用原本寫的 `ReadConsoleInput` 事件:那要自己把按鍵記錄轉回位元組)。信號用 `SetConsoleCtrlHandler`(Windows 為每個事件開一條新的執行緒呼叫它):Ctrl-C(只有輸入不是 raw 時才是信號)與 Ctrl-Break(永遠是信號,shell 開著時也是)同 `SIGINT`:取消問題,沒有問題時結束程式(130);關掉 console 視窗同 `SIGHUP`:這時 handler 一回傳 Windows 就結束行程,不回傳也最多只給約 5 秒(`SPI_GETHUNGAPPTIMEOUT`,預設 5000 毫秒),所以 handler 起動 watchdog,等到這次執行結束、console 放回去才回傳,最多等 watchdog 的寬限(2 秒)加 1.2 秒,那時 watchdog 已經還原並結束程式。`CTRL_LOGOFF_EVENT` 與 `CTRL_SHUTDOWN_EVENT` 只有服務收得到(HandlerRoutine 的文件:登出與關機時互動的程式已經被結束),所以 `sshelter connect` 實際收到的是 Ctrl-C、Ctrl-Break 與關掉視窗;程式仍把這兩個當 `SIGTERM`,和關視窗一樣處理。結束碼與 Unix 相同(130、129、143 等):訊號編號用 CLI 自己的表(`cli::signal`),Windows 上是 POSIX/Linux 的編號,遠端被訊號殺掉也照這張表;Windows 沒有 Ctrl-Z 停止與 `SIGQUIT`。Windows Terminal 與傳統 console 都要手動測(`docs/superpowers/plans/2026-10-13-own-ssh-windows-manual-checks.md`)。
- 任何結束路徑(含 panic)都還原終端機模式。
- (第 1b 期)實作的細節:收到 `opened` 才進 raw mode(之前終端機維持原狀,Ctrl-C 照常中止;連線中打的字等 shell 開了再送,同 OpenSSH);raw mode 照 OpenSSH 的 `enter_raw_mode` 設;`question` 用終端機的行編輯問,`echo: false` 時不顯示,問之前丟掉先打的字(不讓它變成密碼),Ctrl-C 或 Ctrl-D 取消;termios 用 app 已有的 `libc`(Cargo.lock 不多套件),信號用 tokio 的 `signal`(`SIGWINCH`、`SIGINT`、`SIGTERM`、`SIGHUP`、`SIGQUIT`、`SIGTSTP`、`SIGCONT`),接不到這些信號就不開始;問題或連線中按 Ctrl-Z(raw mode 時 Ctrl-Z 是送給遠端的字元)先還原終端機再真的停下,`fg` 之後重設模式、重問還沒答的問題(同 OpenSSH 的 `readpassphrase`);寫終端機與寫 broker 各用一條執行緒,等著寫到終端機的輸出有上限(終端機慢時 CLI 先停止讀 broker 的訊框,broker 的轉送跟著停下;引擎的佇列照 §6.3 不等人,滿了之後多出的輸出被丟掉,串流裡用一行字說少了多少位元組;SSH 的 window 不受影響),按鍵與信號不排在輸出後面;只有 session 自己結束時(shell 結束、broker 結束 session 或離開),CLI 會等終端機把最後的輸出收完才離開(同 OpenSSH;終端機一直在收就一直等,等著寫的最多是 CLI 的輸出上限 256 KiB),這段時間收到 `SIGINT`、`SIGTERM`、`SIGHUP` 或 `SIGQUIT` 就不再等,還原終端機並結束;收到 `SIGTERM`、`SIGHUP`、`SIGQUIT` 或終端機關掉之後,迴圈若沒在 2 秒內結束,由 watchdog 還原終端機並結束;結束碼:shell 的結束碼(遠端被訊號殺掉為 128 + 訊號編號,同 shell);CLI 自己收到的訊號也是 128 + 訊號編號(連線中按 Ctrl-C 為 130,`SIGHUP` 或終端機關掉為 129,`SIGQUIT` 為 131,`SIGTERM` 為 143);連線中斷、開不成或 SSHelter 離開為 255(同 ssh),執行緒 panic 也是 255;參數錯誤為 2;沒有終端機、SSHelter 沒啟動或接不到信號為 1;Windows 在第 1b 期印 `sshelter connect is not supported on Windows yet.` 並以 1 結束;(第 1 期)Windows 版做好之後這句已經拿掉(見上面 Windows 的幾條)。

### 7.4 從 app 啟動終端機

Connect 按鈕、指令面板、托盤的快速連線:沿用 `connect.rs` 的 `detect_terminals`、`build_launch_command`、`launch`,只是 argv 從 `ssh <alias>` 變成 `<SSHelter 執行檔> connect <alias>`。密碼自動填入與一次性通道刪除。(第 1 期,Windows 版做好之後)Windows 的 Connect(三個入口都經 `connect::launch_for`)開 `<sshelter.exe 所在的資料夾>\sshelter-cli.exe connect <alias>`:Windows Terminal 直接執行這個 argv(`wt.exe <argv>`,開在新分頁時 `wt.exe -w 0 nt <argv>`),cmd 用 `cmd /c start "" cmd /k <argv>` 開新視窗、結束後視窗留著(同現在)。只有 debug 版在旁邊沒有 `sshelter-cli.exe` 時用 `sshelter.exe` 本身(debug 版是 console 程式);release 版找不到就不開終端機,Connect 按鈕與指令面板顯示 `Could not connect` 與 `sshelter-cli.exe is missing from <dir>. Reinstall SSHelter.`,托盤的快速連線只記在 log(`[tray] quick-connect '<alias>' failed: …`):release 版的 `sshelter.exe` 是 GUI 程式,終端機不等它、也不給它 console(§7.3)。cmd 這條路有已知的限制(§16:路徑裡有 cmd 的特殊字元)。下面第 1b 期列的 Windows 損失由此補回:存著的密碼由 broker 從系統的認證儲存取用(或在終端機問),「只在 SSHelter」的金鑰由保管庫直接簽章。(第 1b 期;已由上面第 1 期的 Windows 版取代,留著說明當時少了什麼)Windows 在第 3 期之前照舊開 `ssh <alias>`。一次性通道與自動填入在各平台都已刪除,所以 Windows 的 Connect 少了這些:存著的密碼不再自動填入(ssh 自己問);「只在 SSHelter」的金鑰不再走預先核准的一次性通道,改經 `~/.ssh/config` 那行 `Include` 設的 `IdentityAgent` 與 agent 的核准視窗(沒有那行 `Include`,或 agent 沒在跑時,Connect 用不到這把金鑰);開終端機之前「這台電腦上沒有這把金鑰」的提示沒了(改成 ssh 在終端機裡失敗);一次性通道逾時後的「Connect to {alias} again」提示也沒了。

## 8. MCP

### 8.1 adapter

`sshelter --mcp` 的形狀不變:stdio 對 AI 工具,IPC 對 broker。沒有 TCP、token、runtime 檔。adapter 在本地回答 `initialize` 時,把 AI 工具的 `clientInfo`(`name`、`title`、`version`,各截到 100 字元、去掉控制字元)留下來,放進 `hello.client_info`。

### 8.2 工具

- `list_hosts`:允許清單上的主機(alias、hostname、user、port、tags、space)。
- `get_host(alias)`:該主機的結構化欄位,不含任何秘密與主機金鑰的公鑰。
- `ssh_exec(alias, command, timeout_seconds 1–300 預設 60)`:走 broker 的 `exec`(無 PTY),回 stdout、stderr、`ended`(exited | signaled | timed_out | truncated | disconnected)、結束碼(可空)、signal(可空);被訊號殺掉、輸出到上限或連線中斷時明說,不回 0(第 0 期)。
- 呼叫舊名 `run`:JSON-RPC 錯誤,訊息 `run was renamed to ssh_exec`。
- 不設 `_meta["anthropic/requiresUserInteraction"]`(決策 12)。

### 8.3 政策與核准

- `mcp-policy.json`:`enabled`、`allowed_hosts`(主機 id)、`approval_mode: "ask" | "auto_log"`(缺省 `ask`)。
- `ask`:每條指令跳 app 的核准視窗,顯示主機、完整指令、`Requested by` 程序鏈、自報的 clientInfo;允許或拒絕;120 秒逾時視為拒絕。
- `auto_log`:允許清單上的主機直接執行,每條寫 log;切換到它要先在確認視窗同意(字串見第 14 節);切回 `ask` 不用確認。
- 兩種模式都先做:MCP 已開啟、主機在允許清單、指令長度與控制字元檢查。
- 需要互動時(主機金鑰未確認、要 passphrase、密碼、2FA):`ask` 走 app 視窗;`auto_log` 回錯誤 `needs interaction: <原因>`,絕不代答。

### 8.4 log

`<app data>/session-log.jsonl`,保留最近 1000 筆,重開後仍在。每筆:`at_ms`、`client`(connect | mcp)、`host`(alias 與 id)、`command`(connect 時為空)、`outcome`(allowed | denied | timed_out | canceled | error)、`exit_code`、`mode`、`requested_by`(名稱鏈)、`requester_id`、`client_info`。不記輸出內容。AI Access 頁顯示最近 10 筆。

## 9. 搬遷與版本切換

- **版本**:1.0.0;長期分支 `next/own-ssh`,main 繼續 0.17 的 beta,定期把 main 併進來。beta 通道只有一條,1.0.0-N 的 beta 等使用者準備好把兩台測試機一起切換時才發;之前用本機建置測。
- **第一次啟動 1.0**(一次性,之後可在 Advanced 再做):
  1. 讀 `~/.ssh/config`(含 Include,只讀),把每個 Host 區塊轉成 host 記錄:對應現有編輯器的 18 個設定;`IdentityFile` 指到保管庫插槽的路徑 → `key_id`;指到使用者自己的金鑰檔 → 問要不要複製進保管庫(絕不刪原檔;拒絕就 `auth = key` 但 `key_id` 空,標「需要金鑰」);`ProxyJump` → 解析成主機 id(缺的主機順便建立);`Match` 區塊與 ProxyCommand、LocalCommand 等不支援的設定 → 原文存進 `imported.unsupported`,主機標「需要處理」。
  2. `keyslot` 升到 schema 2;還是連結或複製檔案的插槽(Linked、SyncedCopy)→ 問要不要把那個檔案複製進保管庫,不刪原檔。
  3. keychain 的主機密碼:`host:<alias>` → `host:<host id>`。
  4. 同步:第一台 1.0 同步時把帳戶 `schema_version` 升到 3,其他電腦唯讀並顯示「需要更新」。
- **`~/.ssh` 一律不碰**,只有一個例外:Advanced 的「Clean up what SSHelter wrote in ~/.ssh」列出清單(那行 Include、`~/.ssh/sshelter/` 底下的檔案),預設關閉,使用者按了才做。不清也沒事:OpenSSH 對不存在的 Include 會忽略。
- **降級**:0.17 讀不懂 1.0 的狀態檔,會照現有行為把它搬到旁邊(`sync-state.unreadable-<time>.json`)並離開帳戶;release notes 要寫清楚。

## 10. 前端

- **主機清單**:來自記錄,space 當分組;Include、drift、lint、shadow、重複複本、設定檔相關的對話框全部拿掉;`host-filter`、`selection-range`、`host-display`、指令面板留用。
- **主機編輯器**:結構化表單(alias、hostname、port、user、認證方式、金鑰選擇、密碼設定/忘記、跳板依序挑、keepalive 與逾時、tags、notes);「匯入備註」唯讀區塊與「需要處理」標記;Connect 按鈕啟動 `sshelter connect`;Delete。
- **Keychain**:清單和明細留用;拿掉「Other key files in ~/.ssh」、Move/Keep;New key 剩貼上、產生、選檔案複製進來;Export private key、Delete key、Sync key 對話框留用(沒有檔案候選)。
- **新視窗**:主機金鑰指紋確認(仿現有核准視窗);MCP `ask` 模式的提問視窗(passphrase、密碼、2FA)。主機明細顯示釘住的金鑰與「Forget pinned key」。
- **進行中的 session**:設定或側欄一小區,可關閉。
- **設定**:AI Access(允許清單用主機 id、核准模式單選加確認視窗、最近 10 筆含請求者);Advanced(再次匯入、清理);Sync 的檔案相關文字刪除。介面字串英文。
- (第 0 期後的介面後果;確認視窗在第 1b 期做,CLI 在終端機裡印 §11 的句子也是;MCP `ask` 模式的提問視窗與它的「這次作廢,請重連」提示在第 2 期;主機明細與「Forget pinned key」在 1d;進行中的 session 清單在第 3 期;AI Access 的最近 10 筆在第 2 期)主機金鑰確認:第一次連線會先失敗(引擎回 `HostKeyUnknown`,連線不留著等人),視窗問完、釘住後 broker 自動重連,使用者看到的是「確認 → 連上」,CLI 這段印 `Waiting for you to confirm {alias}'s host key in SSHelter.`;不符時同樣先失敗、警告視窗、接受才重連。認證提示(passphrase、密碼、2FA)有期限,逾時或取消後連線已丟掉,要再連一次(§11 的 `Authentication for {alias} was abandoned`),視窗要讓人看得出「這次作廢,請重連」。進行中的 session 清單與 AI Access 的最近 10 筆顯示結束方式(`ended`:正常結束碼、被訊號終止、逾時、連線中斷),不再把中斷顯示成 0。

## 11. 錯誤處理

| 狀況 | 使用者看到 |
|---|---|
| 連不上(DNS、TCP、逾時) | `Could not reach {hostname}:{port} ({reason}).` |
| 跳板失敗 | `Could not connect through {jump alias}: {reason}` |
| 主機金鑰未確認 | app 視窗問;CLI 印 `Waiting for you to confirm {alias}'s host key in SSHelter.`;MCP `auto_log` 回 `needs interaction: host key not confirmed` |
| 主機金鑰不符 | 警告視窗;拒絕 → `The host key of {alias} changed. Connection refused.` |
| 連線途中主機金鑰一直變 | `The host key of {alias} kept changing while SSHelter was connecting. Connection refused.`(一次連線只問一次) |
| 問之前釘住的記錄已被別的連線改掉 | `SSHelter's record of {alias}'s host key changed while it was connecting. Connect again.` |
| 認證失敗 | `Authentication failed for {user}@{alias} (tried: publickey, password).` |
| keepalive 連續沒回應 | `Connection to {alias} lost (no response for {n} seconds).`,`{n}` = (`keepalive_max_missed` + 1) × `keepalive_secs`(第 0 期) |
| 連線在指令執行中斷掉 | `Connection to {alias} lost while the command was running.`;MCP 回 `ended: disconnected`,沒有結束碼(第 0 期) |
| 簽章器出錯、提示逾時或被取消 | 連線丟掉:`Authentication for {alias} was abandoned ({reason}).`;使用者再連一次(第 0 期) |
| IPC 連不上 app | `SSHelter did not start within 12 seconds.` |
| russh 回報的協定錯誤 | `SSH error: {text}`,不含金鑰或密碼 |
| (第 1 期,Windows)session pipe 不是使用者自己的(別的程式先建了同名的 pipe) | `sshelter connect` 印 `Another program is using SSHelter's session pipe (\\.\pipe\sshelter-session-<…>)`,結束碼 1,不啟動 SSHelter(§4) |
| (第 1 期,Windows)系統拒絕 `sshelter connect` 開 session pipe | `sshelter: cannot connect to SSHelter ({error})`,結束碼 1,不啟動 SSHelter |
| (第 1 期,Windows)app 建不了 session pipe | 只在 app 的 stderr:`[session] the broker is not listening: Another program is using SSHelter's session pipe ({error})`(名稱被別的程式占了),其他錯誤是 `… Can't create SSHelter's session pipe ({error})` |
| (第 1 期,Windows)console 不支援 virtual terminal sequences(傳統 console) | `sshelter: the console does not support virtual terminal sequences ({error})`,結束碼 1,console 沒被動過 |
| (第 1 期,Windows)control handler 或 watchdog 裝不起來 | `sshelter: cannot take over the console's control keys: {error}`,結束碼 1,console 沒被動過 |
| (第 1 期,Windows)release 版的 `sshelter.exe` 旁邊沒有 `sshelter-cli.exe` | Connect 按鈕與指令面板:`Could not connect`,`sshelter-cli.exe is missing from <dir>. Reinstall SSHelter.`;托盤只記 log(§7.4) |
| (第 1 期,Windows)`sshelter-cli.exe` 自己出錯 | `sshelter-cli: cannot find sshelter.exe in <dir>.`、`sshelter-cli: cannot find its own directory: {error}.`、`sshelter-cli: cannot ignore Ctrl-C and Ctrl-Break: {error}.`、`sshelter-cli: cannot start <path>: {error}.`,結束碼都是 1;在 Windows 以外執行它:`sshelter-cli is for Windows; run sshelter connect instead.` |

## 12. 測試、CI、安全

- 單元測試照舊(inline);引擎在介面後面,所以 broker、MCP、CLI 的測試用假引擎(`FakeEngine`:可編排主機金鑰結果、認證結果、輸出、斷線)。
- 整合測試:真引擎對本機臨時 `sshd`。第 0 期已建好這套架構(`spike/russh/src/harness.rs`:臨時目錄、先綁 socket 取得空閒埠、測試用主機金鑰與 authorized_keys、以一般使用者執行 `sshd -D -e -f <設定>`、`PermitUserRC no`、工具不在 PATH 上就略過、不碰使用者的 `~/.ssh`),第 1 期搬進 app 的測試支援程式碼(改用 `crate::process`,順便讓逾時殺掉子行程後的等待有上限),每個測試自己起一個 sshd、不共用;非共用不可的長迴圈設 `PerSourcePenalties no`(OpenSSH ≥ 9.8 才認得,不能放進預設設定)。涵蓋公鑰(從保管庫簽章)、密碼、keyboard-interactive、PTY 與 window change、exec、兩層跳板、主機金鑰的三種結果、keepalive 斷線;第 0 期之後必加:拒絕 SHA-1 RSA 簽章的檢查(§6.3 b);`sign` 回錯誤之後 `authenticate_none` 與 `disconnect()` 的行為(session 卡死的量測);被放棄的 keyboard-interactive;經過跳板的大量輸出(流量控制);未認證且閒置超過 `keepalive_interval` 時 CPU 不空轉(讀原始碼懷疑的點)。密碼與 keyboard-interactive 的**成功**路徑臨時 sshd 沒有 PAM 走不到,要用有 PAM 的 sshd 容器(CI 的 Linux 工作)。CI:macOS、Linux(新增;`vault::` 在 `zeroize` 1.9.1 下)都跑;Windows 的 `test-windows.yml` 加上引擎的整合測試(對 runner 的 OpenSSH server;第 0 期的 `spike-windows.yml` 已證明做法),並在加了 russh 的 `src-tauri/Cargo.lock` 下建置整個 app(第 0 期只建了試驗 crate)。
- 兩台電腦的同步測試在記錄層用 `FakeRelay`(不再需要檔案);搬遷測試用固定的 ssh_config 樣本。
- CLI 測試:協定編解碼、raw mode 的進出與還原(假的 termios);Windows console 的部分列入手動清單。(第 1 期,Windows)`test-windows.yml` 也在 `next/own-ssh` 的每次 push 跑:broker 經真的 named pipe 的測試(假引擎;掛斷、`hello` 與 `open_shell` 各自的上限、用戶端讀到 `exited` 之後才讀到結尾、只用使用者自己擁有的 pipe:runner 以系統管理員身分執行,測試先建一個屬於 Administrators 群組的同名 pipe)、CLI 的 Windows 部分(假的 console:模式的計算與還原、讀取不跨模式的切換、UTF-16 轉 UTF-8、ctrl 事件、視窗大小;`run()` 經真的 pipe 對真的 broker;真的 console:測試把自己在一個有自己 console 的子行程裡再跑一次(`CREATE_NEW_CONSOLE`),用 `WriteConsoleInputW` 打字,量 `ReadConsoleW` 與模式切換,§7.3)、`connect::`(Windows Terminal 與 cmd 執行 helper、debug 版旁邊沒有 helper 時執行自己)、`sshelter-cli.exe` 自己的測試(參數與結束碼的轉交,含 NTSTATUS 大小的結束碼),以及 debug 版的 `sshelter.exe` 旁邊放上 helper 時,`sshelter-cli.exe connect` 帶回和 `sshelter.exe connect` 一樣的用法與結束碼 2;console 的實際行為(Windows Terminal、傳統 console、輸入法、改變視窗大小、關掉視窗)列入手動清單(`docs/superpowers/plans/2026-10-13-own-ssh-windows-manual-checks.md`)。release 與 beta 的 Windows 建置(`build-platform.yml` 也是,只對有 `src-tauri/cli-helper` 的 tag)先編 `sshelter-cli.exe`(獨立的小 crate,只用 std;以 `-C target-feature=+crt-static` 把 C runtime 靜態連進去:`tauri build` 對 `sshelter.exe` 也這樣做,安裝檔不帶 VC++ runtime),再用 `tauri build --config '{"bundle":{"externalBin":["binaries/sshelter-cli"]}}'` 打包進安裝檔(這段 JSON 不能有反斜線或 cmd 的特殊字元:tauri-action 經 `pnpm.cmd`,也就是 cmd,執行 tauri);平常的 `cargo build`、`cargo test` 用不到它。`windows-bundle-check.yml`(手動觸發;改了這個檔案的那次 push 也跑)照 beta 的 Windows 那條建出 NSIS 安裝檔,檢查 helper 與 `sshelter.exe` 在同一個資料夾、helper 不 import VC runtime(`dumpbin /dependents`),並讓安裝檔裡的這一對執行 `sshelter-cli.exe connect`(用法、結束碼 2)。
- 安全:`cargo audit` 進 CI;russh 的公告每月看一次;私鑰只在 app 行程;IPC 只接受同使用者;MCP `auto_log` 絕不接受主機金鑰、絕不代答提示。

## 13. 分期與發布

| 期 | 內容 | 產出 |
|---|---|---|
| 0 試驗(完成 2026-10-11) | russh 與 ssh-key 0.6.7 並存;對本機 sshd 連線、exec、shell;Windows 實機;`Signer` 接 `Material::sign`;IPC 搬成 `ipc/` | 判定 GO;報告 `2026-10-10-own-ssh-spike-report.md`;本文件依它修訂(標「(第 0 期)」處);`ipc/` 已搬、隨 beta 0.17.0-9 出貨 |
| 1 核心 | 資料模型與 schema 3、匯入、引擎、broker、IPC、`sshelter connect`、Connect 按鈕、最小主機編輯器、主機金鑰釘住;Windows 版的 `sshelter connect`(console 小程式 `sshelter-cli.exe`、named pipe;2026-10-13 從第 3 期移來) | 使用者日常可以用它連線 |
| 2 MCP | `ssh_exec`、核准模式、log、請求者辨識、AI Access 頁 | AI 可以用 |
| 3 收尾 | Keychain 清理、session 清單、搬遷清理、文件、手動檢查清單、`cargo audit` | 1.0.0-1 beta |
| 之後 | 連接埠轉送、SFTP、憑證;換成自製引擎 | |

每一期一份計畫(writing-plans),沿用 subagent-driven 執行。

## 14. 字串(第一版要固定的)

- 切到 `auto_log` 的確認:標題 `Let AI run commands without asking?`;內容 `AI can run commands on the hosts in your AI allowed list without asking first. Every command is logged. Keys in SSHelter still ask the first time they are used.`;按鈕 `Cancel`、`Let AI run without asking`。
- AI Access 的核准模式單選:標籤 `Approval`,選項 `Ask before every command`、`Run without asking, keep a log`。
- 核准視窗與 log:`Requested by` + 名稱鏈(` → ` 連接,每段經 `revealHidden`);認不出來 `an unknown program`;clientInfo 一行 `{name} {version} (self-reported)`。
- 主機金鑰確認視窗:標題 `Is this {alias}?`;內容 `{hostname}:{port} presented the key {algorithm} {fingerprint}. SSHelter has not seen it before. Connect only if the fingerprint matches what the server's administrator gave you.`;按鈕 `Cancel`、`Trust this key`。
- 主機金鑰不符:標題 `{alias}'s host key changed`;內容 `The key {hostname}:{port} presented does not match the one SSHelter pinned on {pinned_at}. Someone could be intercepting the connection. Refuse unless you know the server's key was reinstalled.`;按鈕 `Refuse`、`Accept new key`。
- 其餘字串在各期的計畫裡定,寫進介面前先對照本節。

## 15. 查證紀錄(2026-10-10)

- russh 0.64.1(2026-10-05);2026 年 182 個 commit、58 個 open issues、實質單一維護者;MSRV 1.89;tokio 硬相依;預設 aws-lc-rs;釘 `ssh-key =0.7.0-rc.11`、`rsa =0.10.0-rc.18`;`authenticate_publickey_with(user, PublicKey, hash_alg, &mut impl Signer)` 的 `Signer::auth_sign(&mut self, &AgentIdentity, Option<HashAlg>, Vec<u8>) -> impl Future<Output = Result<Vec<u8>, Self::Error>> + Send` 收待簽緩衝區與呼叫端選的雜湊,要回傳「原緩衝區 + u32 長度 + 簽章 blob」(第 0 期以編譯器確認,三種金鑰登入成功);`check_server_key` 預設全拒;預設協商 ed25519、ecdsa、rsa-sha2-512/256、ssh-rsa,不含 sk-*;channel 提供 PTY、`window_change`、shell、exec、subsystem、direct-tcpip、`tcpip_forward`、keepalive;ProxyJump 無內建,用 direct-tcpip + `connect_stream`;Windows 只有 CI 建置、測試只跑 Linux;2026 年 19 則 GHSA(多為對端觸發的 DoS/panic),RustSec 2026-0154 已修;沒人讀的 channel 會卡住連線(PR 730 被拒)。
- russh-sftp 3.0.1(2026-09-28),SFTP v3,之後用。
- `ssh2`(libssh2 綁定)0.9.6:C 相依、同步 API、文件無自訂簽章、libssh2 正式版停在 2024-10、2026 年有 client 端 CVE;不採用。
- 保管庫的 `vault/material.rs` `Material::sign(data, flags)` 可對任意位元組簽章(Ed25519、ECDSA、RSA),可當 `AuthSource::sign` 的實作。
- lib crate 名稱是 `sshelter_lib`(crate-type 含 rlib,可用路徑相依),但 `lib.rs` 的 `mod vault` 不是 `pub`:試驗要開放可見性或在試驗 crate 裡複製簽章那段。`tokio 1.52`、`aws-lc-rs 1.18`、`ring 0.17`、`rustls 0.23` 已在 app 的 Cargo.lock 裡,所以 TLS 那一層不會多一套;但 russh 會帶進第二組 RustCrypto 的 rc 版本(`ssh-key 0.7.0-rc.11`、`rsa 0.10.0-rc.18` 等),和 app 現用的 `ssh-key 0.6.7`、`rsa 0.9` 並存。第 0 期驗證:兩代並存、編譯、互認公鑰都沒問題;以試驗 crate 的 `Cargo.lock` 計多 92 個套件(34 個新 crate + 58 個既有 crate 的第二版本)、3 個預覽版(pkcs1、rsa、ssh-key),`zeroize` 被迫從 1.8.2 升到 1.9.1——加進 `src-tauri/` 時要重算、重跑整個 lib 測試(特別是 `vault::`),`cargo audit` 與升版要看兩代。`lib.rs` 的 `mod vault` 已在第 0 期改成 `pub mod vault;`。
- 同步引擎是阻塞式執行緒(`reqwest::blocking` 不能跑在 tokio 上),所以連線 runtime 要分開。
- 現有記錄模型:`Record{kind,id,version,updated_at_ms,device_id,deleted,payload}`;space 鏈的 `host` 記錄今天是整段 Host 文字(`HostPayload{schema,text}`);帳戶 `schema_version` 超過支援的值就唯讀。
- Windows 的 release 版是 `windows_subsystem = "windows"`,沒有 console;`GetNamedPipeClientProcessId` 已在 `agent/pipe_windows.rs` 使用。
- app data 目錄 `~/Library/Application Support/org.homelab.sshelter/` 下的 socket 路徑在這台是 69 bytes(上限 104)。
- 臨時 sshd(2026-10-10 本機實測,macOS 內建 OpenSSH 10.3p1,一般使用者、不碰 `~/.ssh`):在臨時目錄放 `hostkey`(ssh-keygen ed25519)、`authorized_keys`(0600),設定 `Port <空閒埠>`、`ListenAddress 127.0.0.1`、`HostKey <絕對路徑>`、`PidFile none`、`UsePAM no`、`PasswordAuthentication no`、`KbdInteractiveAuthentication no`、`PubkeyAuthentication yes`、`AuthorizedKeysFile <絕對路徑>`、`StrictModes no`、`LogLevel ERROR`;`sshd -t -f` 通過,`sshd -D -e -f <設定>` 啟動約 1 秒後可用公鑰登入,遠端結束碼與輸出正確傳回;sshd 的 stderr 只有一行無害的 `BSM audit: … setaudit_addr failed: Operation not permitted`。`Port 0` 不被接受,埠要先用 socket 綁 0 取得。密碼與 keyboard-interactive 在沒有 PAM 的臨時 sshd 上無法驗證,要在真實主機上測。
- Termius:更新紀錄顯示堆疊裡有 libssh2(2026-07 修補 CVE-2026-55200);桌面版是 Electron;SSH 核心是否自研不公開;用自己的內建 agent,未見提供給其他程式;AI agent 每條指令要確認;未見 MCP。

## 16. 待試驗與未決

- Windows(第 1 期):CI 只量過 runner 的 conhost(§7.3 的讀取與模式切換、`real_console_tests`);Windows Terminal(ConPTY)、傳統 console、輸入法、貼上大量文字、改變視窗大小、真的鍵盤按的 Ctrl-C 與 Ctrl-Break、關掉視窗或 Windows Terminal 的分頁,只有手動檢查看得到(`docs/superpowers/plans/2026-10-13-own-ssh-windows-manual-checks.md`)。
- (第 1 期,Windows,已知的限制)cmd 的 Connect 執行 `cmd /c start "" cmd /k <argv>`,argv 的第一個是 helper 的完整路徑,而 Rust 只替有空白、Tab 或空的參數加引號:路徑沒有空白時,cmd 會讀路徑裡的 `&`、`^`;路徑有空白(加了引號)時,`cmd /k` 看到後面恰好兩個引號、中間卻有 `&<>()@^|` 之一,就拿掉這對引號(`cmd /?`),路徑在空白處斷開;路徑裡的 `%名稱%` 是環境變數時,有沒有引號都會被展開。這些情形 Connect 都開不起來。預設是裝給目前使用者(`%LOCALAPPDATA%\SSHelter`),路徑裡就有使用者設定檔的資料夾名稱,而帳戶名稱可以有 `&`、`(`、`)`、`^`(`<`、`>`、`|` 不能出現在 Windows 的路徑裡)。`LaunchSpec` 只有程式與參數,寫不出 cmd 要的原樣命令列(Rust 的 `raw_arg`),所以第 1 期不修;Windows Terminal 不經 cmd,不受影響。
- (第 1 期,Windows,已知的限制)切換模式時用程式自己寫進輸入的 Enter(`WriteConsoleInputW`)結束等著的讀取(§7.3)。拒絕這個寫入的 console(UWP 的 console 程式,或用戶端的 integrity level 比 console 低時:「Console Buffer Security and Access Rights」的 wrong-way verbs,`WriteConsoleInput` 回 access denied)叫不醒讀取:等滿 500 毫秒之後模式照樣切換,舊的讀取跨過切換,照它自己的模式收走新模式裡先打的鍵(舊的是行讀取時,一直收到 Enter),讀到的東西當成過期的丟掉。
- (第 1 期,Windows,已知)隱藏的回答按 Enter 時 console 自己換到下一行(§7.3 的量測),用戶端又照 Unix 的需要印一個換行,所以 Windows 上密碼提示之後多一行空白;別的程式在問題進行中送來的 `CTRL_C_EVENT`(`GenerateConsoleCtrlEvent`)取消問題,卻不結束等著的行讀取(量過),接下來切回 cooked 也不叫醒它,連線中打的一行就進了這個過期的讀取、被丟掉。
- 第 0 期沒量到、第 1 期要補(§12):密碼與 keyboard-interactive 的成功路徑(PAM);`sign` 出錯與被放棄的 keyboard-interactive 之後的 session;內層跳板自己先結束、外層還活著時的 `disconnected`;Linux 與其他版本的 sshd(所有計時只在 macOS OpenSSH 10.3p1 量過);長時間連線與 rekey;沒有 `server-sig-algs` 的老伺服器;app 加上 russh 後的 Windows build;`cargo audit` 對兩代 RustCrypto 的結果。
- 試驗 crate `spike/` 的壽命:已結束。它的 lock 記了 app 的整個相依圖,`src-tauri/Cargo.toml` 一變,它的 `--locked` Windows 工作就壞,所以第 1a 期在 harness 搬進 app(`src-tauri/src/ssh/testing/`)之後刪掉了 `spike/` 與 `spike-windows.yml`。報告 `2026-10-10-own-ssh-spike-report.md` 留著;它引用的 `spike/russh/...` 檔案只剩 git 歷史(刪除那個 commit 之前)裡看得到。
- 同一個 alias 在不同 space 重複時 CLI 的選法(本文件:回錯誤要求用 id;UI 可以禁止同名)。
- keyboard-interactive 的提示在 MCP `ask` 模式下送 app 視窗,是否需要遮蔽輸入(`echo` 旗標已在協定裡,視窗照它做)。
- 1.0 的 beta 何時開始發到唯一的 beta 通道(使用者決定)。
