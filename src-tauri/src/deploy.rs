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
                    _ => DeployOutcome::WrongPassword,
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

/// 從 `Permission denied (publickey,password).` 取出括號內伺服器實際提供的方法清單。
/// 沒有括號（訊息形式不同）時回 `None`，呼叫端保守地當成密碼錯誤處理。
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

/// 從一行 `<host> <type> <base64>` 取出 (type, base64)。註解行與空行回 None。
fn split_key_line(line: &str) -> Option<(&str, &str)> {
    let line = line.trim();
    if line.is_empty() || line.starts_with('#') {
        return None;
    }
    let mut parts = line.split_whitespace();
    let _host = parts.next()?;
    let key_type = parts.next()?;
    let material = parts.next()?;
    Some((key_type, material))
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

    let scanned_keys: Vec<(&str, &str)> = scanned.lines().filter_map(split_key_line).collect();
    if scanned_keys.is_empty() {
        return HostKeyStatus::Unavailable {
            message: format!("ssh-keyscan returned no host key for {host_field}"),
        };
    }

    let known_keys: Vec<(&str, &str)> =
        known_for_host.lines().filter_map(split_key_line).collect();

    // 指紋一律取掃到的第一把，作為要顯示給使用者的代表。
    let (first_type, first_material) = scanned_keys[0];
    let fingerprint = crate::known_hosts::fingerprint_sha256(first_material)
        .unwrap_or_else(|| "SHA256:<unreadable>".to_string());

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
        let stderr = "spike@localhost: Permission denied (publickey,password).";
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
        // 括號裡有 password 才是真的密碼錯誤。
        assert_eq!(
            classify_outcome(Some(255), "", "Permission denied (publickey,password)."),
            DeployOutcome::WrongPassword
        );
        // 沒有括號時保守處理成密碼錯誤。
        assert_eq!(
            classify_outcome(Some(255), "", "Permission denied"),
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
}
