//! 一鍵部署公鑰：全程在 Rust 內完成，不開終端機。
//!
//! 刻意不使用 `ssh-copy-id` —— Windows OpenSSH 沒有這支程式，且自己實作才控制得了
//! 錯誤分類（要在 app 內分辨「密碼錯」與「連不上」）。
//!
//! 安全模型：本機以純 argv 啟動 ssh（絕不 `sh -c`）；遠端 script 是一段固定字串，
//! 不含任何使用者輸入；公鑰內容走 stdin，因為 `.pub` 的 comment 欄位是使用者可控的，
//! 拼進遠端指令即為注入點。

use serde::{Deserialize, Serialize};

/// 在遠端執行的固定 script。不含任何使用者輸入；公鑰從 stdin 讀入。
/// 退出碼 90/91/92 用來區分遠端失敗的階段。
pub const REMOTE_SCRIPT: &str = r#"umask 077
mkdir -p ~/.ssh || exit 90
k=$(cat)
[ -n "$k" ] || exit 91
if [ -f ~/.ssh/authorized_keys ] && grep -qxF "$k" ~/.ssh/authorized_keys; then
  echo SSHELTER_EXISTS
else
  printf '%s\n' "$k" >> ~/.ssh/authorized_keys || exit 92
  chmod 600 ~/.ssh/authorized_keys
  echo SSHELTER_ADDED
fi"#;

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
            if stderr.contains("Permission denied") {
                DeployOutcome::WrongPassword
            } else if stderr.contains("Host key verification failed") {
                DeployOutcome::HostKeyFailed
            } else if UNREACHABLE_MARKERS.iter().any(|m| stderr.contains(m)) {
                DeployOutcome::Unreachable
            } else {
                DeployOutcome::Other {
                    message: first_line_or(stderr, "ssh failed"),
                }
            }
        }
        Some(code @ (90 | 91 | 92)) => DeployOutcome::RemoteError { code },
        Some(0) => DeployOutcome::Other {
            message: "deploy finished but reported no result".to_string(),
        },
        Some(code) => DeployOutcome::RemoteError { code },
        None => DeployOutcome::Other {
            message: "ssh was terminated by a signal".to_string(),
        },
    }
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
        assert!(build_deploy_argv("web").contains(&"KbdInteractiveAuthentication=no".to_string()));
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
        assert!(!REMOTE_SCRIPT.contains("ssh-ed25519"), "no key material in the script");
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
