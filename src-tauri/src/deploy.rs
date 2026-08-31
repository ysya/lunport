//! 一鍵部署公鑰：全程在 Rust 內完成，不開終端機。
//!
//! 刻意不使用 `ssh-copy-id` —— Windows OpenSSH 沒有這支程式，且自己實作才控制得了
//! 錯誤分類（要在 app 內分辨「密碼錯」與「連不上」）。
//!
//! 安全模型：本機以純 argv 啟動 ssh（絕不 `sh -c`）；遠端 script 是一段固定字串，
//! 不含任何使用者輸入；公鑰內容走 stdin，因為 `.pub` 的 comment 欄位是使用者可控的，
//! 拼進遠端指令即為注入點。

use serde::{Deserialize, Serialize};

use crate::error::AppError;

/// 在遠端執行的固定 script。不含任何使用者輸入；公鑰從 stdin 讀入。
/// 退出碼 90/91/92/94 用來區分遠端失敗的階段（90=mkdir、91=空輸入、92=寫入、94=chmod）。
///
/// 三個防守點，每一個都對應一種「回報成功但實際沒成功」的失敗：
/// 1. **補結尾換行**：遠端 `authorized_keys` 若最後一個 byte 不是 `\n`（手動編輯、
///    `echo -n`、某些 provisioning 模板），直接 append 會把新金鑰接在舊金鑰的同一行後面，
///    造成兩把金鑰同時失效，而 script 仍會 `echo SSHELTER_ADDED`。這正是 `ssh-copy-id`
///    長年防守的情境。
/// 2. **`grep -e`**：`$k` 是 pattern operand，開頭若是 `-` 會被當成選項。PEM 格式的
///    `.pub`（`-----BEGIN PUBLIC KEY-----`）就會踩到。
/// 3. **`chmod` 失敗要回報**：權限沒設好時 sshd 的 StrictModes 會拒絕該金鑰。
///
/// 「公鑰必須是單行、且以已知 key type 開頭」由呼叫端的 `validate_public_material`
/// 在 Rust 側把關（可單元測試），不放在這裡。
pub const REMOTE_SCRIPT: &str = r#"umask 077
mkdir -p ~/.ssh || exit 90
k=$(cat)
[ -n "$k" ] || exit 91
if [ -f ~/.ssh/authorized_keys ] && grep -qxF -e "$k" ~/.ssh/authorized_keys; then
  echo SSHELTER_EXISTS
else
  [ ! -s ~/.ssh/authorized_keys ] || [ -z "$(tail -c 1 ~/.ssh/authorized_keys)" ] || echo >> ~/.ssh/authorized_keys || exit 92
  printf '%s\n' "$k" >> ~/.ssh/authorized_keys || exit 92
  chmod 600 ~/.ssh/authorized_keys || exit 94
  echo SSHELTER_ADDED
fi"#;

/// 已知的公鑰型別前綴。`validate_public_material` 用它擋掉 PEM/RFC4716 等非 authorized_keys
/// 格式的內容 —— 那些內容開頭是 `-`，會被遠端的 `grep` 當成選項。
const KEY_TYPE_PREFIXES: &[&str] = &[
    "ssh-", "ecdsa-sha2-", "sk-ssh-", "sk-ecdsa-sha2-",
];

/// 驗證要部署的公鑰內容：必須是**單一行**、非空、且以已知 key type 開頭。
///
/// 這道閘門擋掉兩種真實可達的輸入（`keys::validate_public_path` 只驗路徑、不驗內容，
/// 整個 codebase 目前沒有任何一處驗證 `.pub` 的格式）：
/// - **PEM / RFC4716 格式**（`-----BEGIN PUBLIC KEY-----`）：開頭的 `-` 會被遠端
///   `grep` 當成選項，導致重複偵測永久失效並把整坨 PEM 寫進 authorized_keys。
/// - **多行檔案**（有人把 authorized_keys 風格的多金鑰檔命名成 `.pub`）：`grep -F` 會
///   把換行分隔的內容當成「多個 pattern，任一命中即命中」，於是只要其中一行已存在就
///   回報 AlreadyPresent，實際上一把都沒送上去。
pub fn validate_public_material(text: &str) -> Result<String, AppError> {
    let line = text.trim();
    if line.is_empty() {
        return Err(AppError::Other("public key file is empty".to_string()));
    }
    if line.lines().count() != 1 {
        return Err(AppError::Other(
            "public key file must contain exactly one key line".to_string(),
        ));
    }
    if !KEY_TYPE_PREFIXES.iter().any(|p| line.starts_with(p)) {
        return Err(AppError::Other(
            "not an OpenSSH public key line (PEM/RFC4716 formats are not supported)".to_string(),
        ));
    }
    Ok(line.to_string())
}

/// 部署結果。前端據此顯示對應文案。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "camelCase")]
#[cfg_attr(test, derive(ts_rs::TS))]
#[cfg_attr(test, ts(export, export_to = "../../src/bindings/"))]
pub enum DeployOutcome {
    /// 公鑰已新增到遠端 authorized_keys。
    Added,
    /// 遠端本來就有這把公鑰，未重複加入。
    AlreadyPresent,
    /// 密碼錯誤（只嘗試一次）。
    WrongPassword,
    /// host key 驗證失敗（理論上 Step 0 已擋掉，屬防禦性分類）。
    HostKeyFailed,
    /// 連不上：DNS 解析失敗、逾時、連線被拒。
    Unreachable,
    /// 遠端 script 失敗，帶回退出碼。
    RemoteError { code: i32 },
    /// 其他未分類錯誤，帶回可讀訊息。
    Other { message: String },
}

/// 組出 `ssh` 的 argv（不含程式名）。`alias` 必須已通過 `connect::validate_alias`。
pub fn build_deploy_argv(alias: &str) -> Vec<String> {
    vec![
        // 不配置 pty：ssh 沒有終端機可提示，只能走 askpass；同時讓 stdin 乾淨傳遞公鑰。
        "-T".to_string(),
        // host key 已於 Step 0 驗好並寫入 known_hosts，這裡不接受任何提示。
        "-o".to_string(), "StrictHostKeyChecking=yes".to_string(),
        // 防使用者 config 全域設了 `BatchMode yes` 而封鎖密碼提示。
        "-o".to_string(), "BatchMode=no".to_string(),
        // 密碼錯就立刻失敗，不問三次。
        "-o".to_string(), "NumberOfPasswordPrompts=1".to_string(),
        // 關掉 keyboard-interactive。這是安全關鍵，不是效能調校：kbdint 的提示文字由
        // 「伺服器」控制，而 OpenSSH 只在前面加一個 client 產生的 `(user@host) ` 前綴就
        // 原文轉交 askpass。關掉之後，helper 收到的提示全部由 client 產生，惡意主機再也
        // 無法構造提示來誘騙 helper 印出密碼。與 Step 0 用 StrictHostKeyChecking=yes
        // 消除 host key 提示是同一個思路：讓危險的輸入根本不存在，而不是事後過濾。
        // 代價：只提供 kbdint 的主機（PAM 2FA 等）無法自動部署，但會「乾淨地」失敗。
        "-o".to_string(), "KbdInteractiveAuthentication=no".to_string(),
        "-o".to_string(), "ConnectTimeout=10".to_string(),
        alias.to_string(),
        REMOTE_SCRIPT.to_string(),
    ]
}

/// stderr 中代表「連不上」的片段。
const UNREACHABLE_MARKERS: &[&str] = &[
    "Could not resolve",
    "Connection timed out",
    "Connection refused",
    "No route to host",
    "Operation timed out",
];

/// 把 ssh 的退出碼與輸出翻譯成使用者看得懂的結果。
///
/// 順序很重要：部署成功時退出碼是 0，所以先看 stdout 的標記。
///
/// ssh(1) 明載退出碼是「**遠端指令的退出碼，或發生錯誤時的 255**」—— 兩者無法從退出碼
/// 本身區分。我們靠自訂的 90/91/92/94 避開碰撞，並接受一個已知取捨：遠端指令若剛好
/// 回 255，會被歸類成 ssh 層級錯誤。
pub fn classify_outcome(code: Option<i32>, stdout: &str, stderr: &str) -> DeployOutcome {
    if stdout.contains("SSHELTER_ADDED") {
        return DeployOutcome::Added;
    }
    if stdout.contains("SSHELTER_EXISTS") {
        return DeployOutcome::AlreadyPresent;
    }
    match code {
        Some(255) => {
            if stderr.contains("Host key verification failed") {
                DeployOutcome::HostKeyFailed
            } else if stderr.contains("Permission denied") {
                // `Permission denied (publickey,password).` —— 括號裡是伺服器實際提供的
                // 方法。若清單裡根本沒有 password，密碼從來就沒被送出過，回報「密碼錯誤」
                // 會害使用者一再重打正確的密碼。這正是 kbdint-only 主機（FreeBSD 預設、
                // `PasswordAuthentication no` + PAM 的 RHEL 系）會走到的分支。
                match permission_denied_methods(stderr) {
                    Some(methods) if !methods.iter().any(|m| m == "password") => {
                        DeployOutcome::Other {
                            message: format!(
                                "the host refused password authentication (it offers: {})",
                                methods.join(", ")
                            ),
                        }
                    }
                    _ => classify_denied_password(stderr),
                }
            } else if UNREACHABLE_MARKERS.iter().any(|m| stderr.contains(m)) {
                DeployOutcome::Unreachable
            } else {
                DeployOutcome::Other {
                    message: first_line_or(stderr, "ssh failed"),
                }
            }
        }
        Some(0) => DeployOutcome::Other {
            message: "deploy finished but reported no result".to_string(),
        },
        Some(code) => DeployOutcome::RemoteError { code },
        None => DeployOutcome::Other {
            message: "ssh was terminated by a signal".to_string(),
        },
    }
}

/// `Permission denied` 且伺服器有提供 password 方法時，靠 helper 留在 stderr 的標記
/// 分辨四種完全不同的失敗（見 `askpass::log_decision`）。
///
/// 沒有 `answered` 標記時**不能**回報「密碼錯誤」：那代表 ssh 根本沒把密碼要走
/// （本機 OpenSSH 不支援 askpass、helper 啟動失敗、或 helper 拒答），實際送出的是
/// 空密碼 —— Windows 8.1 沒有 DISPLAY 時正是這樣。此時回報「密碼錯誤」會讓使用者
/// 重打幾次正確密碼都得到同樣結果。
///
/// 標記理論上可被惡意伺服器的 pre-auth banner 偽造（banner 走同一條 stderr），但偽造
/// 的效果只是把診斷訊息換成「密碼錯誤」—— 與沒有這個分類器時的行為相同，不構成新風險。
fn classify_denied_password(stderr: &str) -> DeployOutcome {
    if stderr.contains("[sshelter-askpass] answered:") {
        return DeployOutcome::WrongPassword;
    }
    if stderr.contains("[sshelter-askpass] no-secret:") {
        return DeployOutcome::Other {
            message: "the askpass helper had no password to send (keychain read failed?)"
                .to_string(),
        };
    }
    if stderr.contains("[sshelter-askpass] refused:") {
        return DeployOutcome::Other {
            message: "ssh asked for something other than this host's password; \
                      SSHelter refused to auto-answer it"
                .to_string(),
        };
    }
    DeployOutcome::Other {
        message: "ssh never asked SSHelter for the password — the local OpenSSH \
                  likely cannot run askpass automation"
            .to_string(),
    }
}

/// 從 `Permission denied (publickey,password).` 取出括號內伺服器實際提供的方法清單。
/// 沒有括號（訊息形式不同）時回 `None`，呼叫端交由標記分類處理。
fn permission_denied_methods(stderr: &str) -> Option<Vec<String>> {
    let line = stderr.lines().find(|l| l.contains("Permission denied"))?;
    let start = line.find('(')?;
    let end = line[start..].find(')')? + start;
    Some(
        line[start + 1..end]
            .split(',')
            .map(|m| m.trim().to_string())
            .filter(|m| !m.is_empty())
            .collect(),
    )
}

/// 取 stderr 第一行非空內容，作為給使用者看的訊息。
/// askpass helper 的診斷行也走 stderr（見 `askpass::log_decision`），要濾掉 ——
/// 否則使用者看到的錯誤訊息會變成我們自己的除錯輸出。
fn first_line_or(stderr: &str, fallback: &str) -> String {
    stderr
        .lines()
        .map(str::trim)
        .find(|l| !l.is_empty() && !l.starts_with("[sshelter-askpass]"))
        .unwrap_or(fallback)
        .to_string()
}

/// `ssh -G` 解析出的實際連線目標。
#[derive(Debug, Clone, PartialEq)]
pub struct Endpoint {
    pub hostname: String,
    pub port: String,
}

/// 從 `ssh -G` 的 key/value 對取出 hostname 與 port。沒有 hostname 就回 None。
pub fn endpoint_from_effective(pairs: &[(String, String)]) -> Option<Endpoint> {
    let find = |key: &str| {
        pairs
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(key))
            .map(|(_, v)| v.clone())
    };
    let hostname = find("hostname").filter(|h| !h.is_empty())?;
    Some(Endpoint {
        hostname,
        port: find("port").filter(|p| !p.is_empty()).unwrap_or_else(|| "22".to_string()),
    })
}

/// `ssh-keyscan` 的 argv（不含程式名）。純函式，方便測試。
pub fn keyscan_target(ep: &Endpoint) -> Vec<String> {
    vec![
        "-T".to_string(),
        "5".to_string(),
        "-p".to_string(),
        ep.port.clone(),
        ep.hostname.clone(),
    ]
}

/// host key 的三種狀態（外加「掃不到」）。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "camelCase")]
#[cfg_attr(test, derive(ts_rs::TS))]
#[cfg_attr(test, ts(export, export_to = "../../src/bindings/"))]
pub enum HostKeyStatus {
    /// known_hosts 已有且相符，可直接部署。
    Trusted,
    /// known_hosts 沒有這台；前端顯示指紋讓使用者確認後寫入。
    New { fingerprint: String, key_line: String },
    /// known_hosts 有但金鑰不同 —— 可能是中間人，一律中止。
    Mismatch { fingerprint: String },
    /// `ssh-keyscan` 掃不到（非標準網路路徑、ProxyJump 後方等）。
    Unavailable { message: String },
}

/// known_hosts 的 host 欄位寫法：22 埠是裸主機名，其他埠是 `[host]:port`。
/// 這也是 `ssh-keygen -F` 期望的查詢字串形式。
pub fn known_hosts_host_field(ep: &Endpoint) -> String {
    if ep.port == "22" {
        ep.hostname.clone()
    } else {
        format!("[{}]:{}", ep.hostname, ep.port)
    }
}

/// 從一行 known_hosts 項目取出 `(marker, type, base64)`。註解行與空行回 `None`。
///
/// **marker（`@cert-authority` / `@revoked`）是獨立欄位，會把後面每一欄往後推一格。**
/// 不處理的話，host 會被當成 key type、key type 被當成 base64，解出一個「非 None 但
/// 完全錯亂」的結果 —— 那個結果不可能等於任何真實金鑰，於是一台合法透過 CA 信任的
/// 主機會被誤判成 `Mismatch`（可能是中間人，硬中止）。本 repo 的
/// `known_hosts::parse_fields` 早就正確處理了同一件事，這裡的規則與它一致。
fn split_key_line(line: &str) -> Option<(Option<&str>, &str, &str)> {
    let line = line.trim();
    if line.is_empty() || line.starts_with('#') {
        return None;
    }
    let mut parts = line.split_whitespace();
    let first = parts.next()?;
    let marker = if first.starts_with('@') { Some(first) } else { None };
    if marker.is_some() {
        parts.next()?; // marker 之後才是真正的 hosts 欄位
    }
    let key_type = parts.next()?;
    let material = parts.next()?;
    Some((marker, key_type, material))
}

/// 查詢這台 host 既有的 known_hosts 項目所需的 argv（不含程式名）。
///
/// **刻意用 `ssh-keygen -F` 而不是自己讀 known_hosts 檔案。** 原因：known_hosts 可以是
/// 雜湊過的（`|1|salt|hash` 開頭），而 Debian／Ubuntu 的 `HashKnownHosts` 預設就是 `yes`。
/// 自己用字面 host 欄位比對，在那些系統上永遠比不中 —— 後果不只是每次都要重新確認指紋，
/// 而是**已信任主機的金鑰被換掉時會被判成 `New` 而不是 `Mismatch`**，中間人攻擊會顯示成
/// 「新主機，要信任嗎？」而不是硬中止。`ssh-keygen -F` 原生處理雜湊項目，這正是它存在的理由。
pub fn keygen_find_args(ep: &Endpoint) -> Vec<String> {
    vec!["-F".to_string(), known_hosts_host_field(ep)]
}

/// 比對 `ssh-keyscan` 的輸出與 `ssh-keygen -F` 回報的既有項目。
///
/// `known_for_host` 是 `ssh-keygen -F` 的 stdout —— 它已經只包含這台 host 的項目，
/// 所以這裡**不再、也不可以**用字面 host 欄位過濾（雜湊項目的第一欄是 `|1|…`，
/// 過濾會把它們全部濾掉，等於回到上面說的那個安全性缺口）。
///
/// 掃到多把金鑰（ed25519 + rsa）時，只要有任何一把相符即視為已信任 —— 與 ssh 一致。
pub fn compare_host_keys(
    scanned: &str,
    known_for_host: &str,
    ep: &Endpoint,
) -> HostKeyStatus {
    let host_field = known_hosts_host_field(ep);

    // ssh-keyscan 的輸出不含 marker，取後兩欄即可。
    let scanned_keys: Vec<(&str, &str)> = scanned
        .lines()
        .filter_map(split_key_line)
        .map(|(_, t, k)| (t, k))
        .collect();
    if scanned_keys.is_empty() {
        return HostKeyStatus::Unavailable {
            message: format!("ssh-keyscan returned no host key for {host_field}"),
        };
    }

    let known: Vec<(Option<&str>, &str, &str)> =
        known_for_host.lines().filter_map(split_key_line).collect();

    let (first_type, first_material) = scanned_keys[0];
    let fingerprint = crate::known_hosts::fingerprint_sha256(first_material)
        .unwrap_or_else(|| "SHA256:<unreadable>".to_string());

    // `@revoked` 明確標記這把金鑰已作廢 —— 比「不符」更嚴重，一律中止。
    if known.iter().any(|(m, t, k)| {
        *m == Some("@revoked") && scanned_keys.iter().any(|(st, sk)| st == t && sk == k)
    }) {
        return HostKeyStatus::Mismatch { fingerprint };
    }

    // `@cert-authority`：這台主機透過 CA 信任。ssh 自己會驗證主機憑證，
    // `StrictHostKeyChecking=yes` 不會跳提示，所以部署可以直接進行、也不該去動
    // known_hosts。把它當成新主機要求使用者確認指紋，是對已信任狀態的誤報。
    if known.iter().any(|(m, _, _)| *m == Some("@cert-authority")) {
        return HostKeyStatus::Trusted;
    }

    let known_keys: Vec<(&str, &str)> = known
        .iter()
        .filter(|(m, _, _)| m.is_none())
        .map(|(_, t, k)| (*t, *k))
        .collect();

    if known_keys.is_empty() {
        return HostKeyStatus::New {
            fingerprint,
            key_line: format!("{host_field} {first_type} {first_material}"),
        };
    }
    if scanned_keys.iter().any(|s| known_keys.contains(s)) {
        return HostKeyStatus::Trusted;
    }
    HostKeyStatus::Mismatch { fingerprint }
}

// ─── 執行層（有副作用，不做單元測試；以 Task 12 的手動驗證涵蓋） ─────────────

use std::io::Write;
use std::process::Stdio;

/// 這個 alias 是否經過跳板。
///
/// 實測（OpenSSH 10.2p1）：設了 `ProxyJump bastion` 時 `ssh -G` 只印 `proxyjump bastion`，
/// **不會**另外印 `proxycommand`；而 `ProxyJump none` 則是**整行都不印**。所以 `none` 的
/// 字串比對其實碰不到 —— 保留它是縱深防禦（不同 OpenSSH 版本輸出可能不同），不是它讓
/// `none` 判對的。直接設 `ProxyCommand` 的情形則會印 `proxycommand`，因此兩個 key 都要檢查。
pub fn has_proxy(pairs: &[(String, String)]) -> bool {
    pairs.iter().any(|(k, v)| {
        (k.eq_ignore_ascii_case("proxyjump") || k.eq_ignore_ascii_case("proxycommand"))
            && !v.trim().is_empty()
            && !v.trim().eq_ignore_ascii_case("none")
    })
}

/// 取得 alias 的 `ssh -G` key/value 對（驗證 alias 後）。
///
/// **刻意傳 `None` 而不是已載入的 config 路徑。** 部署真正跑的是 `ssh <alias>`，沒有 `-F`；
/// 而 ssh(1) 明載「If a configuration file is given on the command line, the system-wide
/// configuration file (/etc/ssh/ssh_config) will be ignored」。若這裡帶 `-F`，探測看到的
/// 設定就和實際執行的不同 —— 一個寫在 `/etc/ssh/ssh_config`（或 RHEL/Fedora 預設 Include
/// 進來的 `ssh_config.d/*.conf`）裡的 `ProxyJump`，會對 `has_proxy` 完全隱形，跳板拒絕
/// 因此在它唯一存在意義的情境下失效。安全閘門必須建模「實際會跑的那條指令」。
fn effective_pairs(
    state: &tauri::State<crate::state::AppState>,
    alias: &str,
) -> Result<Vec<(String, String)>, AppError> {
    {
        let doc_lock = state.doc.lock().unwrap();
        let doc = doc_lock
            .as_ref()
            .ok_or_else(|| AppError::Other("no config loaded".to_string()))?;
        crate::connect::validate_alias(doc, alias)?;
    }
    crate::config::intel::effective_config(alias, None)
}

/// in-app 部署要求「載入的設定檔就是 ssh 預設會讀的那一份」。
///
/// 使用者可以把 SSHelter 指向任意 config 路徑，但部署跑的 `ssh <alias>` 永遠讀
/// `~/.ssh/config`。兩者不同時，我們對這個 alias 的一切推理（跳板、endpoint、認證方式）
/// 都可能來自一份 ssh 根本不會讀的檔案 —— 與拒絕跳板同一個理由：無法保證我們推理的設定
/// 就是 ssh 會用的設定，就不該把使用者的密碼送出去。
fn require_default_config_root(state: &tauri::State<crate::state::AppState>) -> Result<(), AppError> {
    let loaded = {
        let doc_lock = state.doc.lock().unwrap();
        doc_lock
            .as_ref()
            .and_then(|d| d.files.first().map(|f| f.path.clone()))
            .ok_or_else(|| AppError::Other("no config loaded".to_string()))?
    };
    let default = crate::config::commands::default_config_path()?;
    let same = loaded.canonicalize().ok() == default.canonicalize().ok()
        || loaded == default;
    if !same {
        return Err(AppError::Other(format!(
            "in-app deploy needs the default config ({}); SSHelter is currently viewing {}",
            default.display(),
            loaded.display()
        )));
    }
    Ok(())
}

/// `require_default_config_root` 的布林版，給「不該報錯、只該安靜退回」的呼叫端
/// （connect 的密碼自動填入）。理由同上：終端機跑的是 `ssh <alias>`（無 `-F`），
/// 對非預設 config 的推理可能與 ssh 實際讀到的設定無關。
pub(crate) fn is_default_config_root(state: &tauri::State<crate::state::AppState>) -> bool {
    let Some(loaded) = ({
        let doc_lock = state.doc.lock().unwrap();
        doc_lock
            .as_ref()
            .and_then(|d| d.files.first().map(|f| f.path.clone()))
    }) else {
        return false;
    };
    let Ok(default) = crate::config::commands::default_config_path() else {
        return false;
    };
    loaded.canonicalize().ok() == default.canonicalize().ok() || loaded == default
}

/// `ssh -V` 的輸出（版本寫在 stderr；順手併上 stdout 以防未來變動）。
pub(crate) fn local_ssh_version() -> String {
    crate::process::background_command("ssh")
        .arg("-V")
        .output()
        .map(|o| {
            let mut s = String::from_utf8_lossy(&o.stderr).into_owned();
            s.push_str(&String::from_utf8_lossy(&o.stdout));
            s
        })
        .unwrap_or_default()
}

/// 解析 alias 的實際連線目標（走既有的 `ssh -G` 整合）。
fn resolve_endpoint(
    state: &tauri::State<crate::state::AppState>,
    alias: &str,
) -> Result<Endpoint, AppError> {
    let main_path = {
        let doc_lock = state.doc.lock().unwrap();
        let doc = doc_lock
            .as_ref()
            .ok_or_else(|| AppError::Other("no config loaded".to_string()))?;
        crate::connect::validate_alias(doc, alias)?;
        doc.files.first().map(|f| f.path.clone())
    };
    let pairs = crate::config::intel::effective_config(alias, main_path.as_deref())?;
    endpoint_from_effective(&pairs)
        .ok_or_else(|| AppError::NotFound(format!("ssh -G returned no hostname for '{alias}'")))
}

/// 執行部署本體。回傳 (outcome)。密碼已事先放進 `account` 指向的 keychain 項目。
fn run_ssh_deploy(
    alias: &str,
    pub_material: &str,
    account: &str,
    env_secret: Option<&str>,
) -> Result<DeployOutcome, AppError> {
    let exe = std::env::current_exe().map_err(AppError::Io)?;

    let mut cmd = crate::process::background_command("ssh");
    cmd.args(build_deploy_argv(alias))
        .env("SSH_ASKPASS", &exe)
        .env("SSH_ASKPASS_REQUIRE", "force")
        .env("SSHELTER_ASKPASS", "1")
        .env("SSHELTER_ASKPASS_ACCOUNT", account)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if let Some(secret) = env_secret {
        // 本機無密鑰環時的 fallback；UI 已告知使用者密碼不會被儲存。
        cmd.env("SSHELTER_ASKPASS_SECRET", secret);
    }
    // Win10 內建的 OpenSSH 8.1 不認識 `SSH_ASKPASS_REQUIRE`：它走 askpass 的唯一
    // 條件是「DISPLAY 非空」且「開不到 console」（readpass.c v8.1.0.0）。這個子程序
    // 以 CREATE_NO_WINDOW 啟動、本來就沒有 console，補上 DISPLAY 就補齊了另一半；
    // 缺了它，8.1 會直接送出空密碼。8.6+ 靠 REQUIRE=force 已強制 askpass，多一個
    // DISPLAY 無作用。非 Windows 不動 —— 那裡 DISPLAY 是真實桌面環境的語意。
    if cfg!(target_os = "windows") && std::env::var_os("DISPLAY").is_none() {
        cmd.env("DISPLAY", "sshelter");
    }

    let mut child = cmd.spawn().map_err(|e| {
        if e.kind() == std::io::ErrorKind::NotFound {
            AppError::NotFound("ssh not found".to_string())
        } else {
            AppError::Io(e)
        }
    })?;

    {
        // 公鑰走 stdin。handle 必須在這個 scope 結束時 drop，遠端的 `cat` 才會看到 EOF。
        let mut stdin = child
            .stdin
            .take()
            .ok_or_else(|| AppError::Other("failed to open ssh stdin".to_string()))?;
        // 失敗時要主動收掉子程序：Rust 的 `Child::drop` 既不 kill 也不 reap，
        // 而那個程序身上帶著 SSHELTER_ASKPASS_ACCOUNT，隨後那筆 keychain 項目就會被刪。
        if let Err(e) = stdin.write_all(pub_material.as_bytes()) {
            drop(stdin);
            let _ = child.kill();
            let _ = child.wait();
            return Err(AppError::Io(e));
        }
    }

    // 整體逾時。`ConnectTimeout=10` 只涵蓋 TCP 連線，**不涵蓋認證之後的 hang** ——
    // 沒有這一段，遠端掛住時 `wait_with_output()` 會無限期阻塞、使用者沒有任何取消路徑，
    // 而 `classify_outcome(None, ..)` 那條分支也永遠不會被觸發。
    const DEPLOY_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(60);
    let deadline = std::time::Instant::now() + DEPLOY_TIMEOUT;
    loop {
        match child.try_wait().map_err(AppError::Io)? {
            Some(_) => break,
            None if std::time::Instant::now() >= deadline => {
                let _ = child.kill();
                let _ = child.wait();
                return Ok(classify_outcome(None, "", ""));
            }
            None => std::thread::sleep(std::time::Duration::from_millis(50)),
        }
    }

    let output = child.wait_with_output().map_err(AppError::Io)?;
    Ok(classify_outcome(
        output.status.code(),
        &String::from_utf8_lossy(&output.stdout),
        &String::from_utf8_lossy(&output.stderr),
    ))
}

// ─── 部署前的環境檢查（純函式） ──────────────────────────────────────────────

/// 非 Windows 的閘門是 OpenSSH **8.5**：`SSH_ASKPASS_REQUIRE` 雖然 8.4 就有，但 kbdint
/// 提示的 `(user@host) ` 前綴要到 8.5 才加入，而白名單已不接受裸的 `Password: `。
///
/// **Microsoft 的 Windows port 自報 `OpenSSH_for_Windows_X.Y`，必須另外解析。**
/// 舊版解析在 `for_Windows_` 上取不出數字，於是走「認不出版本 → 保守放行」——
/// Win10 內建的 8.1 因此從未被擋下，部署一路走到 ssh 拿不到密碼、送出空密碼，
/// 被分類成「密碼錯誤」，使用者重打幾次正確密碼都一樣。
///
/// Windows 的門檻是 **8.1** 而非 8.5：
/// - 8.1 不認識 `SSH_ASKPASS_REQUIRE`（忽略、無害），但只要 `DISPLAY` 非空且開不到
///   console，它就走 askpass（readpass.c v8.1.0.0）；`run_ssh_deploy` 因此在 Windows
///   注入 DISPLAY。把提示文字傳給 askpass 的修改 8.1 已包含，白名單收得到完整的
///   `user@host's password: `；7.x 沒有那個修改，helper 只收得到空提示 → 擋下。
/// - 8.6+（Win11 內建）直接支援 `SSH_ASKPASS_REQUIRE=force`
///   （PowerShell/Win32-OpenSSH#2115 的結論，兩位使用者實測證實）。
/// - 8.5 的 kbdint 前綴顧慮在部署路徑不適用：argv 帶 `KbdInteractiveAuthentication=no`，
///   kbdint 提示根本不會出現。
///
/// 認不出版本時回 true（保守放行，讓真正的部署去回報實際錯誤）。
pub fn openssh_supports_askpass_require(version_line: &str) -> bool {
    match parse_openssh_version(version_line) {
        Some((major, minor, true)) => (major, minor) >= (8, 1),
        Some((major, minor, false)) => (major, minor) >= (8, 5),
        None => true,
    }
}

/// Connect 自動填入用的閘門：在「有 tty 的終端機裡」強制 askpass。
///
/// 與 `openssh_supports_askpass_require`（部署用，子程序無 console）只差 Windows
/// 門檻：8.1 走 askpass 的前提是「開不到 console」，終端機裡必然有 console，所以
/// 8.1 在這個情境等於不支援；8.6（Win11 內建）起 `SSH_ASKPASS_REQUIRE=force` 直接
/// 蓋過 tty（v8.6.0.0 readpass.c，並經 Win32-OpenSSH#2115 實測證實）。
///
/// 認不出版本 → 放行：多注入的環境變數在不支援的 ssh 上是無害的 no-op（終端機照樣
/// 出現一般密碼提示），少注入則是功能無聲失效。
pub fn openssh_supports_forced_askpass_in_terminal(version_line: &str) -> bool {
    match parse_openssh_version(version_line) {
        Some((major, minor, true)) => (major, minor) >= (8, 6),
        Some((major, minor, false)) => (major, minor) >= (8, 5),
        None => true,
    }
}

/// 解析 `ssh -V` 的版本行，回 `(major, minor, 是否為 Microsoft Windows port)`。
/// Windows port 自報 `OpenSSH_for_Windows_X.Y`，上游則是 `OpenSSH_X.Y`。
fn parse_openssh_version(version_line: &str) -> Option<(u32, u32, bool)> {
    let rest = version_line.split("OpenSSH_").nth(1)?;
    let (rest, windows) = match rest.strip_prefix("for_Windows_") {
        Some(rest) => (rest, true),
        None => (rest, false),
    };
    let digits: String = rest
        .chars()
        .take_while(|c| c.is_ascii_digit() || *c == '.')
        .collect();
    let mut parts = digits.split('.');
    let major = parts.next()?.parse::<u32>().ok()?;
    let minor = parts.next()?.parse::<u32>().ok()?;
    Some((major, minor, windows))
}

/// 使用者的設定是否讓密碼認證根本用不上。
pub fn password_auth_is_blocked(pairs: &[(String, String)]) -> bool {
    let Some((_, value)) = pairs
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("preferredauthentications"))
    else {
        return false; // 未設定 → ssh 預設含 password
    };
    !value
        .split(',')
        .any(|m| matches!(m.trim(), "password" | "keyboard-interactive"))
}

/// 部署前的環境檢查結果。
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(test, derive(ts_rs::TS))]
#[cfg_attr(test, ts(export, export_to = "../../src/bindings/"))]
pub struct DeployPreflight {
    /// 本機 ssh 是否夠新（>= 8.5）可自動填密碼。
    pub askpass_supported: bool,
    /// 這台 host 的設定是否封鎖了密碼認證。
    pub password_auth_blocked: bool,
    /// 本機是否有可用的密鑰環。false 時密碼只能經環境變數傳給 helper，且無法「記住」。
    pub keychain_available: bool,
}

// ─── Tauri commands ──────────────────────────────────────────────────────────

/// 諮詢性質的環境檢查 —— 只產生警告，不擋部署（硬閘門住在 `deploy_key` 裡）。
/// probe 刻意與 `effective_pairs` 同一條路（無 `-F`，建模實際會跑的 `ssh <alias>`）；
/// 探測失敗時回退為「沒有警告」，讓真正的部署去回報實際錯誤。
#[tauri::command(async)]
pub fn deploy_preflight(
    state: tauri::State<crate::state::AppState>,
    alias: String,
) -> Result<DeployPreflight, AppError> {
    let version = local_ssh_version();

    let pairs = effective_pairs(&state, &alias).unwrap_or_default();

    Ok(DeployPreflight {
        askpass_supported: openssh_supports_askpass_require(&version),
        password_auth_blocked: password_auth_is_blocked(&pairs),
        keychain_available: crate::secrets::available(),
    })
}

#[tauri::command(async)]
pub fn deploy_precheck_host_key(
    state: tauri::State<crate::state::AppState>,
    alias: String,
) -> Result<HostKeyStatus, AppError> {
    // Same reasoning as `deploy_key`: the actual deploy always reads `~/.ssh/config` (no
    // `-F`), so a precheck against a non-default loaded config could scan/trust the wrong host.
    require_default_config_root(&state)?;
    let ep = resolve_endpoint(&state, &alias)?;

    let scanned = match crate::process::background_command("ssh-keyscan")
        .args(keyscan_target(&ep))
        .output()
    {
        Ok(o) => String::from_utf8_lossy(&o.stdout).into_owned(),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Ok(HostKeyStatus::Unavailable {
                message: "ssh-keyscan not found".to_string(),
            });
        }
        Err(e) => return Err(AppError::Io(e)),
    };

    // 用 `ssh-keygen -F` 查既有項目，而不是自己讀 known_hosts —— 它原生處理雜湊項目
    // （HashKnownHosts 在 Debian／Ubuntu 預設為 yes）。找不到時 exit 1、stdout 為空，
    // 那正是我們要的「這台是新主機」。
    let known = crate::process::background_command("ssh-keygen")
        .args(keygen_find_args(&ep))
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).into_owned())
        .unwrap_or_default();
    Ok(compare_host_keys(&scanned, &known, &ep))
}

#[tauri::command(async)]
pub fn deploy_trust_host_key(
    state: tauri::State<crate::state::AppState>,
    alias: String,
    fingerprint: String,
) -> Result<(), AppError> {
    // **前端不提供要寫入的那一行。** 這個 command 會寫進使用者真實的
    // `~/.ssh/known_hosts`，而那個檔案的效力遠超出本 app —— 一旦寫進去，使用者從終端機
    // 直接 `ssh` 也會接受那把金鑰。若接受前端傳來的 key_line，一個被入侵或有 bug 的前端
    // 就能替一台真實主機永久釘上攻擊者的 host key（形狀檢查完全擋不住這件事，因為那一行
    // 的形狀是合法的），甚至在 precheck 已回報 Mismatch 的情況下把「硬中止」洗白成「信任」。
    //
    // 因此：重跑一次 precheck，只有結果是 `New` 時才寫入，而且寫入的是**後端自己算出來的**
    // key_line。前端只傳使用者按下確認時看到的 fingerprint，用來確認「使用者確認的那把」
    // 就是「現在掃到的那把」—— 保留使用者的確認語意，卻把前端移出信任路徑。
    require_default_config_root(&state)?;
    match deploy_precheck_host_key(state, alias.clone())? {
        HostKeyStatus::New {
            fingerprint: actual,
            key_line,
        } if actual == fingerprint => crate::known_hosts::append_known_hosts_line(&key_line),
        HostKeyStatus::New { .. } => Err(AppError::Other(format!(
            "the host key for '{alias}' changed since you confirmed it; nothing was written"
        ))),
        other => Err(AppError::Other(format!(
            "refusing to trust '{alias}': precheck now reports {other:?}"
        ))),
    }
}

#[tauri::command(async)]
pub fn deploy_key(
    state: tauri::State<crate::state::AppState>,
    alias: String,
    public_path: String,
    password: String,
    remember: bool,
) -> Result<DeployOutcome, AppError> {
    {
        let doc_lock = state.doc.lock().unwrap();
        let doc = doc_lock
            .as_ref()
            .ok_or_else(|| AppError::Other("no config loaded".to_string()))?;
        crate::connect::validate_alias(doc, &alias)?;
    }
    require_default_config_root(&state)?;
    // ProxyJump／ProxyCommand 必須「主動拒絕」，不能只是「不支援」。
    // `SSH_ASKPASS` 與 `SSHELTER_ASKPASS_*` 會被 ProxyCommand 子進程繼承，於是跳板
    // 主機的 `user@jump's password: ` 提示會被 helper 用「目標主機的密碼」回答 ——
    // 那是把密碼洩漏給另一台機器。白名單擋不住這個，因為那是一個完全合法的提示。
    {
        let ep_pairs = effective_pairs(&state, &alias)?;
        if has_proxy(&ep_pairs) {
            return Err(AppError::Other(format!(
                "'{alias}' goes through a jump host; in-app deploy is refused because the \
                 password would be offered to the jump host as well"
            )));
        }
    }

    let dir = crate::keys::ssh_dir()?;
    let pub_path = crate::keys::validate_public_path(&public_path, &dir)?;
    // 內容驗證不可省略：`validate_public_path` 只驗路徑，不看檔案內容。多行的 `.pub`
    // （例如有人把 authorized_keys 複製成 backup.pub）會讓遠端的 `grep -F` 把換行當成
    // pattern 分隔，只要任一行已存在就回報「已存在」，實際一把金鑰都沒部署。
    // 送出去的必須是驗證後的「單行」，不是原始檔案內容。
    let pub_material = validate_public_material(&std::fs::read_to_string(&pub_path)?)?;

    let use_keychain = crate::secrets::available();
    // **嘗試期間一律用暫存項目，即使使用者勾了「記住密碼」。** 先寫永久項目的話，
    // 密碼打錯時那個錯的密碼會永久留著（清理條件是 !remember），之後的自動填入會反覆
    // 把錯密碼送給主機 —— 有 fail2ban／帳號鎖定政策的主機會把使用者鎖在門外。
    // 不變式：永久項目永遠只含「已經成功用過」的密碼。
    let account = crate::secrets::tmp_account(&alias);
    if use_keychain {
        // 上一次崩潰／強制結束可能留下殘留，先回收。
        let _ = crate::secrets::delete(&account);
        crate::secrets::set(&account, &password)?;
    }

    // unwind 也要清掉：panic 或使用者在部署中途強制結束時，`?` 之後的清理不會執行，
    // 明文密碼就會永久留在作業系統鑰匙圈裡而且沒有任何地方會再掃它。
    // 寫法沿用 `secrets.rs` 既有的 CleanupGuard。
    struct TmpSecretGuard<'a>(&'a str, bool);
    impl Drop for TmpSecretGuard<'_> {
        fn drop(&mut self) {
            if self.1 {
                let _ = crate::secrets::delete(self.0);
            }
        }
    }
    let _guard = TmpSecretGuard(&account, use_keychain);

    let env_secret = if use_keychain { None } else { Some(password.as_str()) };
    let result = run_ssh_deploy(&alias, &pub_material, &account, env_secret);

    // 只有真的成功過的密碼才升級成永久項目。
    if use_keychain
        && remember
        && matches!(result, Ok(DeployOutcome::Added) | Ok(DeployOutcome::AlreadyPresent))
    {
        crate::secrets::set(&crate::secrets::host_account(&alias), &password)?;
    }
    result
}

#[tauri::command(async)]
pub fn secrets_has(alias: String) -> Result<bool, AppError> {
    Ok(crate::secrets::get(&crate::secrets::host_account(&alias))?.is_some())
}

#[tauri::command(async)]
pub fn secrets_get(alias: String) -> Result<Option<String>, AppError> {
    crate::secrets::get(&crate::secrets::host_account(&alias))
}

#[tauri::command(async)]
pub fn secrets_set(alias: String, password: String) -> Result<(), AppError> {
    crate::secrets::set(&crate::secrets::host_account(&alias), &password)
}

#[tauri::command(async)]
pub fn secrets_delete(alias: String) -> Result<(), AppError> {
    crate::secrets::delete(&crate::secrets::host_account(&alias))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(unix)]
    use std::path::Path;

    #[test]
    fn argv_pins_host_key_and_limits_password_attempts() {
        let argv = build_deploy_argv("web");
        assert!(argv.contains(&"-T".to_string()), "must not allocate a pty");
        assert!(argv.contains(&"StrictHostKeyChecking=yes".to_string()));
        assert!(argv.contains(&"BatchMode=no".to_string()));
        assert!(argv.contains(&"NumberOfPasswordPrompts=1".to_string()));
        assert!(argv.contains(&"ConnectTimeout=10".to_string()));
    }

    #[test]
    fn argv_disables_keyboard_interactive() {
        // 安全關鍵：kbdint 的提示文字由伺服器控制，關掉它才能保證 askpass helper
        // 收到的提示全部是 client 產生的。移掉這個選項會讓白名單重新暴露在
        // 伺服器可控的輸入之下。
        let argv = build_deploy_argv("web");
        // 驗相鄰而非只驗值：只刪掉配對的 `-o` 會讓 ssh 把它當成 destination 或 command。
        assert!(argv.windows(2).any(|w| w == ["-o", "KbdInteractiveAuthentication=no"]));
        // `-n` 會把 stdin 導向 /dev/null，遠端的 `k=$(cat)` 就永遠讀不到金鑰。
        assert!(!argv.iter().any(|a| a == "-n"), "-n would starve the remote `cat`");
    }

    #[test]
    fn argv_puts_alias_before_the_remote_script() {
        let argv = build_deploy_argv("web");
        let alias_at = argv.iter().position(|a| a == "web").expect("alias present");
        let script_at = argv.iter().position(|a| a == REMOTE_SCRIPT).expect("script present");
        assert!(alias_at < script_at, "alias must precede the remote command");
        assert_eq!(script_at, argv.len() - 1, "remote script is the last argv element");
    }

    #[test]
    fn argv_never_sets_preferred_authentications() {
        // 刻意不設：使用者若已有可用金鑰，ssh 根本不會呼叫 askpass，部署直接成功。
        let argv = build_deploy_argv("web");
        assert!(
            !argv.iter().any(|a| a.starts_with("PreferredAuthentications")),
            "PreferredAuthentications must be left to the user's config"
        );
    }

    #[test]
    fn remote_script_reads_key_from_stdin_not_argv() {
        // 公鑰必須來自 stdin（`$(cat)`），絕不出現在 script 字串裡。
        assert!(REMOTE_SCRIPT.contains("k=$(cat)"));
        assert!(REMOTE_SCRIPT.contains("umask 077"));
        assert!(REMOTE_SCRIPT.contains("SSHELTER_ADDED"));
        assert!(REMOTE_SCRIPT.contains("SSHELTER_EXISTS"));
        // 真正保證「金鑰進不了 argv」的是 build_deploy_argv 的簽章本身（沒有金鑰參數），
        // 不是對常數做字串比對 —— 那種斷言除非有人手動把金鑰打進常數，否則不可能失敗。
    }

    #[test]
    fn classify_added_and_already_present_from_stdout_markers() {
        assert_eq!(classify_outcome(Some(0), "SSHELTER_ADDED\n", ""), DeployOutcome::Added);
        assert_eq!(
            classify_outcome(Some(0), "SSHELTER_EXISTS\n", ""),
            DeployOutcome::AlreadyPresent
        );
    }

    #[test]
    fn classify_wrong_password() {
        // 「密碼錯誤」需要兩個條件：伺服器提供 password 方法，且 helper 留下 answered
        // 標記（密碼真的送出過）。沒有標記的 Permission denied 走診斷分類，見
        // `denied_password_without_helper_consultation_is_not_wrong_password`。
        let stderr = "[sshelter-askpass] answered: \"spike@localhost's password: \"\n\
                      spike@localhost: Permission denied (publickey,password).";
        assert_eq!(classify_outcome(Some(255), "", stderr), DeployOutcome::WrongPassword);
    }

    #[test]
    fn classify_host_key_failure() {
        let stderr = "Host key verification failed.";
        assert_eq!(classify_outcome(Some(255), "", stderr), DeployOutcome::HostKeyFailed);
    }

    #[test]
    fn classify_unreachable_variants() {
        for stderr in [
            "ssh: Could not resolve hostname nope: nodename nor servname provided",
            "ssh: connect to host 10.0.0.9 port 22: Connection timed out",
            "ssh: connect to host 10.0.0.9 port 22: Connection refused",
            "ssh: connect to host 10.0.0.9 port 22: No route to host",
            "ssh: connect to host 10.0.0.9 port 22: Operation timed out",
        ] {
            assert_eq!(
                classify_outcome(Some(255), "", stderr),
                DeployOutcome::Unreachable,
                "stderr {stderr:?} should classify as Unreachable"
            );
        }
    }

    #[test]
    fn permission_denied_without_password_is_not_reported_as_wrong_password() {
        // kbdint-only 主機（FreeBSD 預設、PasswordAuthentication no + PAM 的 RHEL 系）。
        // 密碼從未被送出，回報「密碼錯誤」會害使用者一再重打正確的密碼。
        let stderr = "frank@h: Permission denied (publickey,keyboard-interactive).";
        match classify_outcome(Some(255), "", stderr) {
            DeployOutcome::Other { message } => {
                assert!(message.contains("refused password authentication"), "{message}");
                assert!(message.contains("keyboard-interactive"), "{message}");
            }
            other => panic!("expected Other, got {other:?}"),
        }
        // 純 publickey 主機同理。
        assert!(matches!(
            classify_outcome(Some(255), "", "Permission denied (publickey)."),
            DeployOutcome::Other { .. }
        ));
        // 括號裡有 password、且 helper 真的送出過密碼，才是密碼錯誤。
        assert_eq!(
            classify_outcome(
                Some(255),
                "",
                "[sshelter-askpass] answered: \"f@h's password: \"\n\
                 Permission denied (publickey,password)."
            ),
            DeployOutcome::WrongPassword
        );
        // 沒有括號時同樣交給標記分類：有 answered 標記照樣是密碼錯誤。
        assert_eq!(
            classify_outcome(
                Some(255),
                "",
                "[sshelter-askpass] answered: \"f@h's password: \"\nPermission denied"
            ),
            DeployOutcome::WrongPassword
        );
    }

    #[test]
    fn first_line_skips_our_own_askpass_diagnostics() {
        // askpass helper 的診斷行也走 stderr；沒有過濾的話，我們自己的除錯輸出
        // 會變成使用者看到的部署錯誤訊息。刪掉過濾條件這個測試必須變紅。
        let stderr = "[sshelter-askpass] refused: \"(x@y) Verification code: \"\n\
                      ssh: connect to host h port 22: some novel failure";
        assert_eq!(
            classify_outcome(Some(255), "", stderr),
            DeployOutcome::Other {
                message: "ssh: connect to host h port 22: some novel failure".to_string()
            }
        );
        // 只有診斷行時要落到 fallback，而不是把診斷行當成錯誤訊息。
        assert_eq!(
            classify_outcome(Some(255), "", "[sshelter-askpass] no-secret: \"a@b's password: \""),
            DeployOutcome::Other { message: "ssh failed".to_string() }
        );
    }

    // ── 公鑰內容驗證 ──────────────────────────────────────────────────────────

    #[test]
    fn public_material_accepts_a_single_openssh_key_line() {
        let key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFake frank@laptop\n";
        assert_eq!(validate_public_material(key).unwrap(), key.trim());
        assert!(validate_public_material("ecdsa-sha2-nistp256 AAAA... x").is_ok());
        assert!(validate_public_material("sk-ssh-ed25519@openssh.com AAAA... x").is_ok());
    }

    #[test]
    fn public_material_rejects_pem_because_leading_dash_is_a_grep_option() {
        // `-----BEGIN...` 送到遠端會被 grep 當成選項 → 重複偵測永久失效。
        let pem = "-----BEGIN PUBLIC KEY-----\nMIIBIjAN\n-----END PUBLIC KEY-----";
        assert!(validate_public_material(pem).is_err());
        assert!(validate_public_material("---- BEGIN SSH2 PUBLIC KEY ----").is_err());
    }

    #[test]
    fn public_material_rejects_multiline_because_grep_treats_it_as_a_pattern_list() {
        // grep -F 會把換行分隔的內容當成多個 pattern，任一命中就回報 AlreadyPresent，
        // 實際上一把金鑰都沒送上去。
        let two = "ssh-ed25519 AAAA... a@b\nssh-rsa AAAA... c@d";
        assert!(validate_public_material(two).is_err());
    }

    #[test]
    fn public_material_rejects_empty_and_non_key_content() {
        assert!(validate_public_material("").is_err());
        assert!(validate_public_material("   \n  ").is_err());
        assert!(validate_public_material("hello world").is_err());
    }

    /// 真的把 REMOTE_SCRIPT 交給 `/bin/sh` 執行，`HOME` 指向暫存目錄完全沙箱化
    /// （script 只碰 `~/.ssh`，而 sh 的 `~` 展開讀 `$HOME`）。
    ///
    /// 為什麼非要這個測試不可：上面那三條 `REMOTE_SCRIPT.contains(...)` 只證明「某段文字
    /// 還在常數裡」，不證明那段 shell 邏輯是對的。把 `-z` 改成 `-n`、把 `[ ! -s ]` 改成
    /// `[ -s ]`、或把補換行那行搬到 printf 之後 —— 三種突變都會讓 C1 完全復發，而字串
    /// 比對測試全部照樣是綠的。這一條會抓到。
    #[cfg(unix)]
    fn run_remote_script(home: &Path, stdin: &str) -> (i32, String) {
        use std::io::Write;
        use std::process::{Command, Stdio};

        let mut child = Command::new("/bin/sh")
            .arg("-c")
            .arg(REMOTE_SCRIPT)
            .env("HOME", home)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn /bin/sh");
        child
            .stdin
            .take()
            .unwrap()
            .write_all(stdin.as_bytes())
            .unwrap();
        let out = child.wait_with_output().unwrap();
        (
            out.status.code().unwrap_or(-1),
            String::from_utf8_lossy(&out.stdout).into_owned(),
        )
    }

    #[cfg(unix)]
    #[test]
    fn remote_script_appends_without_corrupting_a_file_that_lacks_a_trailing_newline() {
        // 這是 C1 的行為測試：舊金鑰結尾沒有換行時，新金鑰必須「另起一行」，
        // 而且舊那一行必須原封不動。
        let dir = tempfile::tempdir().unwrap();
        let ssh = dir.path().join(".ssh");
        std::fs::create_dir_all(&ssh).unwrap();
        let ak = ssh.join("authorized_keys");
        std::fs::write(&ak, "ssh-rsa AAAAOLD").unwrap(); // 刻意無結尾換行

        let (code, stdout) = run_remote_script(dir.path(), "ssh-ed25519 AAAANEW frank@laptop\n");
        assert_eq!(code, 0, "stdout={stdout}");
        assert!(stdout.contains("SSHELTER_ADDED"), "stdout={stdout}");

        let text = std::fs::read_to_string(&ak).unwrap();
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines.len(), 2, "expected two separate lines, got {text:?}");
        assert_eq!(lines[0], "ssh-rsa AAAAOLD", "the existing key must survive intact");
        assert_eq!(lines[1], "ssh-ed25519 AAAANEW frank@laptop");
    }

    #[cfg(unix)]
    #[test]
    fn remote_script_handles_absent_empty_and_newline_terminated_files() {
        let key = "ssh-ed25519 AAAANEW frank@laptop\n";

        // 檔案不存在 → 直接建立，只有一行。
        let d1 = tempfile::tempdir().unwrap();
        let (c1, _) = run_remote_script(d1.path(), key);
        assert_eq!(c1, 0);
        let t1 = std::fs::read_to_string(d1.path().join(".ssh/authorized_keys")).unwrap();
        assert_eq!(t1, key, "no leading blank line for a fresh file");

        // 空檔 → 不可補出開頭空行。
        let d2 = tempfile::tempdir().unwrap();
        let ssh2 = d2.path().join(".ssh");
        std::fs::create_dir_all(&ssh2).unwrap();
        std::fs::write(ssh2.join("authorized_keys"), "").unwrap();
        let (c2, _) = run_remote_script(d2.path(), key);
        assert_eq!(c2, 0);
        let t2 = std::fs::read_to_string(ssh2.join("authorized_keys")).unwrap();
        assert_eq!(t2, key, "empty file must not gain a leading blank line");

        // 結尾已有換行 → 不可重複補。
        let d3 = tempfile::tempdir().unwrap();
        let ssh3 = d3.path().join(".ssh");
        std::fs::create_dir_all(&ssh3).unwrap();
        std::fs::write(ssh3.join("authorized_keys"), "ssh-rsa AAAAOLD\n").unwrap();
        let (c3, _) = run_remote_script(d3.path(), key);
        assert_eq!(c3, 0);
        let t3 = std::fs::read_to_string(ssh3.join("authorized_keys")).unwrap();
        assert_eq!(t3, format!("ssh-rsa AAAAOLD\n{key}"), "no extra blank line");
    }

    #[cfg(unix)]
    #[test]
    fn remote_script_reports_existing_key_without_touching_the_file() {
        let dir = tempfile::tempdir().unwrap();
        let ssh = dir.path().join(".ssh");
        std::fs::create_dir_all(&ssh).unwrap();
        let ak = ssh.join("authorized_keys");
        let existing = "ssh-ed25519 AAAANEW frank@laptop\n";
        std::fs::write(&ak, existing).unwrap();

        let (code, stdout) = run_remote_script(dir.path(), existing);
        assert_eq!(code, 0);
        assert!(stdout.contains("SSHELTER_EXISTS"), "stdout={stdout}");
        assert_eq!(
            std::fs::read_to_string(&ak).unwrap(),
            existing,
            "an already-present key must leave the file byte-identical"
        );
    }

    #[cfg(unix)]
    #[test]
    fn remote_script_rejects_empty_stdin() {
        let dir = tempfile::tempdir().unwrap();
        let (code, _) = run_remote_script(dir.path(), "");
        assert_eq!(code, 91, "empty key material must exit 91");
    }

    #[test]
    fn remote_script_guards_against_a_missing_trailing_newline() {
        // 遠端 authorized_keys 結尾若無換行，直接 append 會把新舊金鑰接成一行，
        // 兩把同時失效 —— 而 script 仍會回報成功。這是 ssh-copy-id 長年防守的情境。
        assert!(REMOTE_SCRIPT.contains("tail -c 1"));
        // grep 的 pattern operand 必須用 -e 保護，否則開頭是 `-` 的內容會被當成選項。
        assert!(REMOTE_SCRIPT.contains("grep -qxF -e"));
        // chmod 失敗必須回報：權限沒設好時 sshd 的 StrictModes 會拒絕該金鑰。
        assert!(REMOTE_SCRIPT.contains("chmod 600 ~/.ssh/authorized_keys || exit 94"));
    }

    #[test]
    fn classify_remote_script_exit_codes() {
        assert_eq!(
            classify_outcome(Some(90), "", ""),
            DeployOutcome::RemoteError { code: 90 }
        );
        assert_eq!(
            classify_outcome(Some(92), "", ""),
            DeployOutcome::RemoteError { code: 92 }
        );
    }

    #[test]
    fn classify_unknown_falls_back_to_other_with_stderr() {
        let out = classify_outcome(Some(255), "", "something entirely new");
        assert_eq!(
            out,
            DeployOutcome::Other { message: "something entirely new".to_string() }
        );
    }

    #[test]
    fn classify_signal_killed_process_has_no_exit_code() {
        let out = classify_outcome(None, "", "");
        assert!(matches!(out, DeployOutcome::Other { .. }), "got {out:?}");
    }

    // ── endpoint 解析 ─────────────────────────────────────────────────────────

    fn pairs(kv: &[(&str, &str)]) -> Vec<(String, String)> {
        kv.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect()
    }

    #[test]
    fn endpoint_reads_hostname_and_port_from_ssh_dash_g() {
        let p = pairs(&[("user", "frank"), ("hostname", "10.0.0.9"), ("port", "2222")]);
        let ep = endpoint_from_effective(&p).expect("endpoint");
        assert_eq!(ep.hostname, "10.0.0.9");
        assert_eq!(ep.port, "2222");
    }

    #[test]
    fn endpoint_defaults_port_to_22_when_absent() {
        let p = pairs(&[("hostname", "example.com")]);
        let ep = endpoint_from_effective(&p).expect("endpoint");
        assert_eq!(ep.port, "22");
    }

    #[test]
    fn endpoint_is_none_without_hostname() {
        assert!(endpoint_from_effective(&pairs(&[("user", "frank")])).is_none());
    }

    #[test]
    fn keyscan_target_passes_port_and_host_as_separate_argv() {
        let ep = Endpoint { hostname: "10.0.0.9".into(), port: "2222".into() };
        assert_eq!(
            keyscan_target(&ep),
            vec!["-T", "5", "-p", "2222", "10.0.0.9"]
                .into_iter()
                .map(String::from)
                .collect::<Vec<_>>()
        );
    }

    // ── host key 比對 ─────────────────────────────────────────────────────────

    // 真實 ed25519 host key blob（`ssh-keyscan github.com` 取得，已用 `ssh-keygen -lf`
    // 交叉驗證得到 SHA256:+DiY3wvvV6TuJJhbpZisF/zLDA0zPMSvHdkr4UvCOqU）。用真實 blob
    // 而非隨手編的假 base64，這樣「New 狀態的指紋確實算得出來」才是這條測試真正驗到的事，
    // 不是靠 `compare_host_keys` 內部 `unwrap_or_else` 的 fallback 字串矇混過去。
    const SCANNED: &str =
        "# 10.0.0.9:22 SSH-2.0-OpenSSH_9.6\n10.0.0.9 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl\n";

    #[test]
    fn host_key_trusted_when_known_hosts_matches() {
        let ep = Endpoint { hostname: "10.0.0.9".into(), port: "22".into() };
        let known = "10.0.0.9 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl\n";
        assert_eq!(compare_host_keys(SCANNED, known, &ep), HostKeyStatus::Trusted);
    }

    #[test]
    fn host_key_new_when_absent_from_known_hosts() {
        let ep = Endpoint { hostname: "10.0.0.9".into(), port: "22".into() };
        match compare_host_keys(SCANNED, "", &ep) {
            HostKeyStatus::New { fingerprint, key_line } => {
                assert!(fingerprint.starts_with("SHA256:"), "got {fingerprint}");
                assert_eq!(
                    fingerprint, "SHA256:+DiY3wvvV6TuJJhbpZisF/zLDA0zPMSvHdkr4UvCOqU",
                    "must be the real computed fingerprint, not the <unreadable> fallback"
                );
                assert!(key_line.contains("ssh-ed25519"));
            }
            other => panic!("expected New, got {other:?}"),
        }
    }

    #[test]
    fn host_key_mismatch_is_reported_not_silently_trusted() {
        let ep = Endpoint { hostname: "10.0.0.9".into(), port: "22".into() };
        let known = "10.0.0.9 ssh-ed25519 AAAADIFFERENTKEYMATERIALZZZ\n";
        assert!(
            matches!(compare_host_keys(SCANNED, known, &ep), HostKeyStatus::Mismatch { .. }),
            "a changed host key must never be auto-trusted"
        );
    }

    #[test]
    fn host_key_unavailable_when_keyscan_returned_nothing() {
        let ep = Endpoint { hostname: "10.0.0.9".into(), port: "22".into() };
        assert!(matches!(
            compare_host_keys("", "", &ep),
            HostKeyStatus::Unavailable { .. }
        ));
    }

    #[test]
    fn keygen_find_args_use_bracket_form_for_nonstandard_ports() {
        let std_port = Endpoint { hostname: "h".into(), port: "22".into() };
        assert_eq!(keygen_find_args(&std_port), vec!["-F".to_string(), "h".to_string()]);
        let odd_port = Endpoint { hostname: "h".into(), port: "2222".into() };
        assert_eq!(keygen_find_args(&odd_port), vec!["-F".to_string(), "[h]:2222".to_string()]);
    }

    #[test]
    fn host_key_trusted_when_the_known_entry_is_hashed() {
        // Debian／Ubuntu 的 HashKnownHosts 預設為 yes，項目長這樣。`ssh-keygen -F`
        // 會替我們解析出來，所以第一欄是 `|1|…` 也必須照樣比對成功。
        // 若這裡退回用字面 host 欄位過濾，這個測試會紅 —— 而真實後果是中間人攻擊
        // 會被判成 New（可信任）而不是 Mismatch（硬中止）。
        let ep = Endpoint { hostname: "10.0.0.9".into(), port: "22".into() };
        let scanned = "10.0.0.9 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl\n";
        let hashed = "# Host 10.0.0.9 found: line 7\n                      |1|F1E2D3C4B5A6=|Zm9vYmFyYmF6cXV4= ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl\n";
        assert_eq!(compare_host_keys(scanned, hashed, &ep), HostKeyStatus::Trusted);
    }

    #[test]
    fn ca_trusted_host_is_not_reported_as_a_man_in_the_middle() {
        // `@cert-authority` 是獨立欄位，會把後面每一欄往後推一格。不處理的話
        // host 會被當成 key type，解出一個錯亂但非 None 的結果 —— 於是一台合法
        // 透過 CA 信任、用 ssh 連線完全正常的主機，會被指控成中間人攻擊。
        let ep = Endpoint { hostname: "10.0.0.9".into(), port: "22".into() };
        let scanned = "10.0.0.9 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl\n";
        let ca = "# Host 10.0.0.9 found: line 3 CA\n                  @cert-authority 10.0.0.9 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAICAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n";
        assert_eq!(compare_host_keys(scanned, ca, &ep), HostKeyStatus::Trusted);
    }

    #[test]
    fn revoked_key_aborts_rather_than_being_trusted() {
        // `@revoked` 明確標記金鑰已作廢，比「不符」更嚴重，絕不可放行。
        let ep = Endpoint { hostname: "10.0.0.9".into(), port: "22".into() };
        let blob = "AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl";
        let scanned = format!("10.0.0.9 ssh-ed25519 {blob}\n");
        let revoked = format!("@revoked 10.0.0.9 ssh-ed25519 {blob}\n");
        assert!(matches!(
            compare_host_keys(&scanned, &revoked, &ep),
            HostKeyStatus::Mismatch { .. }
        ));
    }

    #[test]
    fn revoked_outranks_cert_authority_when_both_are_present() {
        // 同一台 host 的 known_hosts 項目可以同時有 `@cert-authority`（信任這台的 CA）
        // 與 `@revoked`（這把「特定」金鑰已作廢）。順序不能顛倒：revoked 必須先擋下來，
        // 否則 CA 分支只看 marker 是否存在、完全不比對金鑰內容，會把一把明確被撤銷、
        // 且剛好被 ssh-keyscan 掃到的金鑰洗白成 Trusted。
        let ep = Endpoint { hostname: "10.0.0.9".into(), port: "22".into() };
        let blob = "AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl";
        let scanned = format!("10.0.0.9 ssh-ed25519 {blob}\n");
        let known = format!(
            "@cert-authority 10.0.0.9 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAICAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n\
             @revoked 10.0.0.9 ssh-ed25519 {blob}\n"
        );
        assert!(
            matches!(compare_host_keys(&scanned, &known, &ep), HostKeyStatus::Mismatch { .. }),
            "a revoked key must abort even when the same host also carries a cert-authority line"
        );
    }

    #[test]
    fn split_key_line_skips_markers_without_shifting_fields() {
        assert_eq!(split_key_line("h ssh-ed25519 AAAA"), Some((None, "ssh-ed25519", "AAAA")));
        assert_eq!(
            split_key_line("@cert-authority h ssh-ed25519 AAAA"),
            Some((Some("@cert-authority"), "ssh-ed25519", "AAAA"))
        );
        assert_eq!(
            split_key_line("@revoked h ssh-rsa BBBB"),
            Some((Some("@revoked"), "ssh-rsa", "BBBB"))
        );
        // 註解、空行、欄位不足一律 None。
        assert_eq!(split_key_line("# Host h found: line 3"), None);
        assert_eq!(split_key_line("   "), None);
        assert_eq!(split_key_line("h ssh-ed25519"), None);
        assert_eq!(split_key_line("@cert-authority h ssh-ed25519"), None);
    }

    #[test]
    fn host_key_mismatch_is_detected_even_for_hashed_entries() {
        // 這是上面那個缺口最要命的一半：已信任但金鑰被換掉，必須是 Mismatch。
        let ep = Endpoint { hostname: "10.0.0.9".into(), port: "22".into() };
        let scanned = "10.0.0.9 ssh-ed25519 AAAAATTACKERKEYZZZ\n";
        let hashed = "|1|F1E2D3C4B5A6=|Zm9vYmFyYmF6cXV4= ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl\n";
        assert!(matches!(
            compare_host_keys(scanned, hashed, &ep),
            HostKeyStatus::Mismatch { .. }
        ));
    }

    // ── 部署前的環境檢查 ──────────────────────────────────────────────────────

    #[test]
    fn openssh_version_gate_requires_8_5() {
        // SSH_ASKPASS_REQUIRE 是 OpenSSH 8.4 引入的，但 kbdint 的 `(user@host) ` 前綴要到
        // 8.5 才有。白名單已不接受裸的 `Password: `，所以閘門必須是 8.5 而非 8.4。
        assert!(openssh_supports_askpass_require("OpenSSH_10.2p1, LibreSSL 3.3.6"));
        assert!(openssh_supports_askpass_require("OpenSSH_9.6p1, LibreSSL 3.3.6"));
        assert!(openssh_supports_askpass_require("OpenSSH_8.5p1, OpenSSL 1.1.1"));
        assert!(!openssh_supports_askpass_require("OpenSSH_8.4p1, OpenSSL 1.1.1"));
        assert!(!openssh_supports_askpass_require("OpenSSH_8.3p1, OpenSSL 1.1.1"));
        assert!(!openssh_supports_askpass_require("OpenSSH_7.9p1, LibreSSL 2.7.3"));
        // 認不出來時保守放行，讓實際部署去回報真正的錯誤。
        assert!(openssh_supports_askpass_require("something unparseable"));
    }

    #[test]
    fn openssh_version_gate_parses_the_windows_port_string() {
        // Microsoft 的 port 自報 `OpenSSH_for_Windows_X.Y`。舊解析在 `for_Windows_`
        // 取不出數字 → 一律走「認不出 → 保守放行」，Win10 內建的 8.1 因此從未被擋，
        // 一路走到空密碼被送出、被回報成「密碼錯誤」。
        // Windows 的門檻是 8.1（配合 run_ssh_deploy 注入 DISPLAY）：
        // 把提示傳給 askpass 的 commit 8.1 才有，7.x 的 helper 只收得到空提示。
        assert!(openssh_supports_askpass_require(
            "OpenSSH_for_Windows_8.1p1, LibreSSL 3.0.2"
        ));
        assert!(openssh_supports_askpass_require(
            "OpenSSH_for_Windows_8.6p1, LibreSSL 3.4.3"
        ));
        assert!(openssh_supports_askpass_require(
            "OpenSSH_for_Windows_9.5p1, LibreSSL 3.8.2"
        ));
        assert!(!openssh_supports_askpass_require(
            "OpenSSH_for_Windows_7.7p1, LibreSSL 2.6.5"
        ));
    }

    #[test]
    fn terminal_askpass_gate_needs_8_5_or_windows_8_6() {
        // Connect 的自動填入是在「有 tty 的終端機裡」跑 ssh：
        // - 非 Windows 沿用 8.5 門檻（force 蓋過 tty）。
        // - Windows 8.1 只有在「開不到 console」時才走 askpass，終端機裡必然有
        //   console，所以 Windows 門檻是 8.6（第一個支援 REQUIRE=force 的內建版）。
        assert!(openssh_supports_forced_askpass_in_terminal("OpenSSH_9.6p1, LibreSSL 3.3.6"));
        assert!(openssh_supports_forced_askpass_in_terminal("OpenSSH_8.5p1, OpenSSL 1.1.1"));
        assert!(!openssh_supports_forced_askpass_in_terminal("OpenSSH_8.4p1, OpenSSL 1.1.1"));
        assert!(openssh_supports_forced_askpass_in_terminal(
            "OpenSSH_for_Windows_8.6p1, LibreSSL 3.4.3"
        ));
        assert!(openssh_supports_forced_askpass_in_terminal(
            "OpenSSH_for_Windows_9.5p1, LibreSSL 3.8.2"
        ));
        assert!(!openssh_supports_forced_askpass_in_terminal(
            "OpenSSH_for_Windows_8.1p1, LibreSSL 3.0.2"
        ));
        // 認不出版本 → 放行：多注入的環境變數在不支援的 ssh 上是無害的 no-op
        //（終端機照樣出現一般密碼提示），少注入則是功能無聲失效。
        assert!(openssh_supports_forced_askpass_in_terminal("something unparseable"));
    }

    #[test]
    fn denied_password_with_answered_marker_is_wrong_password() {
        // helper 真的送出過密碼、伺服器仍拒絕 → 才是「密碼錯誤」。
        let stderr = "[sshelter-askpass] answered: \"spike@localhost's password: \"\n\
                      spike@localhost: Permission denied (publickey,password).";
        assert_eq!(classify_outcome(Some(255), "", stderr), DeployOutcome::WrongPassword);
    }

    #[test]
    fn denied_password_without_helper_consultation_is_not_wrong_password() {
        // Windows 8.1 沒有 DISPLAY 時 ssh 根本不會啟動 helper，直接送出空密碼。
        // 這裡若回報「密碼錯誤」，使用者重打幾次正確密碼都會得到同樣結果。
        let stderr = "frank@h: Permission denied (publickey,password).";
        match classify_outcome(Some(255), "", stderr) {
            DeployOutcome::Other { message } => {
                assert!(message.contains("never asked"), "{message}");
            }
            other => panic!("expected Other, got {other:?}"),
        }
        // 沒有括號的 `Permission denied` 同理：沒有 answered 標記就不是密碼錯誤。
        assert!(matches!(
            classify_outcome(Some(255), "", "Permission denied"),
            DeployOutcome::Other { .. }
        ));
    }

    #[test]
    fn denied_password_with_no_secret_marker_reports_keychain_problem() {
        let stderr = "[sshelter-askpass] no-secret: \"frank@h's password: \"\n\
                      frank@h: Permission denied (publickey,password).";
        match classify_outcome(Some(255), "", stderr) {
            DeployOutcome::Other { message } => {
                assert!(message.contains("no password"), "{message}");
            }
            other => panic!("expected Other, got {other:?}"),
        }
    }

    #[test]
    fn denied_password_with_refused_marker_reports_unexpected_prompt() {
        let stderr = "[sshelter-askpass] refused: \"(x@y) Verification code: \"\n\
                      frank@h: Permission denied (publickey,password).";
        match classify_outcome(Some(255), "", stderr) {
            DeployOutcome::Other { message } => {
                assert!(message.contains("refused"), "{message}");
            }
            other => panic!("expected Other, got {other:?}"),
        }
    }

    #[test]
    fn detects_jump_hosts_so_deploy_can_refuse_them() {
        // 這不是「不支援」而是「必須拒絕」：askpass 的環境變數會被 ProxyCommand 子進程
        // 繼承，跳板的密碼提示是完全合法的形狀，白名單擋不住 —— 結果是把目標主機的密碼
        // 送給跳板主機。
        assert!(has_proxy(&pairs(&[("proxyjump", "bastion")])));
        assert!(has_proxy(&pairs(&[("proxycommand", "ssh -W %h:%p bastion")])));
        // `none` 是明確停用，不算跳板。
        assert!(!has_proxy(&pairs(&[("proxyjump", "none")])));
        assert!(!has_proxy(&pairs(&[("proxycommand", "none")])));
        assert!(!has_proxy(&pairs(&[("proxyjump", "")])));
        assert!(!has_proxy(&pairs(&[("hostname", "10.0.0.9")])));
    }

    #[test]
    fn detects_config_that_blocks_password_auth() {
        // 使用者若全域設了 PreferredAuthentications publickey，密碼永遠用不到，
        // 部署會以 "Permission denied" 失敗 —— 那個訊息會被誤讀成「密碼錯」。
        let blocked = pairs(&[("preferredauthentications", "publickey")]);
        assert!(password_auth_is_blocked(&blocked));

        let ok = pairs(&[("preferredauthentications", "publickey,password")]);
        assert!(!password_auth_is_blocked(&ok));

        let ki = pairs(&[("preferredauthentications", "keyboard-interactive")]);
        assert!(!password_auth_is_blocked(&ki));

        // 沒設就是 ssh 的預設值，包含 password。
        assert!(!password_auth_is_blocked(&pairs(&[("user", "frank")])));
    }
}
