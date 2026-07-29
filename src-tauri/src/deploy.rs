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
/// 退出碼 90/91/92 用來區分遠端失敗的階段。
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
/// 順序很重要：部署成功時退出碼是 0，所以先看 stdout 的標記；255 是 ssh 自己的
/// 錯誤（連線／認證），其餘退出碼來自遠端 script。
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

#[cfg(test)]
mod tests {
    use super::*;

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
}
