//! SSH_ASKPASS helper 模式。
//!
//! SSHelter 的執行檔會被 ssh 以 `SSH_ASKPASS` 再次啟動；`main()` 偵測到 `SSHELTER_ASKPASS=1`
//! 就呼叫 `run()`，完全不初始化 GUI。ssh 把提示文字當作 argv[1] 傳進來。
//!
//! 安全性：`SSH_ASKPASS_REQUIRE=force` 會讓「所有」提示都走這裡，包含 host key 驗證。
//! 若無條件印出密碼，就會拿密碼去回答 host key 提示、ssh 再問一次 → 無窮迴圈；而且
//! keyboard-interactive 的提示文字由伺服器控制，惡意主機可藉此騙走密碼。因此這裡採
//! 白名單：只回應真正的密碼／passphrase 提示，其餘一律 exit 1 交回 ssh 正常處理。

/// 只回應真正的密碼／passphrase 提示。
///
/// 刻意比「結尾是 password:」更嚴格 —— 伺服器自訂的
/// `Please enter your password:` 必須被拒絕。
pub fn prompt_is_answerable(prompt: &str) -> bool {
    let p = prompt.trim().to_ascii_lowercase();
    p == "password:" || p.ends_with("'s password:") || p.contains("passphrase for")
}

/// 取得要回覆的密碼：優先用環境變數 fallback（本機無密鑰環時），否則查 keychain。
pub fn resolve_secret(account: &str, env_secret: Option<String>) -> Option<String> {
    if let Some(s) = env_secret {
        return Some(s);
    }
    crate::secrets::get(account).ok().flatten()
}

/// helper 模式進入點。永不返回。
///
/// 退出碼：0 = 已把密碼寫到 stdout；1 = 拒絕回答（提示不在白名單、或查不到密碼）。
pub fn run() -> ! {
    use std::io::Write;

    let prompt = std::env::args().nth(1).unwrap_or_default();
    if !prompt_is_answerable(&prompt) {
        std::process::exit(1);
    }

    let account = std::env::var("SSHELTER_ASKPASS_ACCOUNT").unwrap_or_default();
    let env_secret = std::env::var("SSHELTER_ASKPASS_SECRET").ok();

    match resolve_secret(&account, env_secret) {
        Some(secret) => {
            let stdout = std::io::stdout();
            let mut lock = stdout.lock();
            // ssh 讀一行；結尾必須有換行。
            let _ = writeln!(lock, "{secret}");
            let _ = lock.flush();
            std::process::exit(0);
        }
        None => std::process::exit(1),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_real_openssh_password_prompts() {
        // Task 0 Step 3 實測到的字串（spike 環境，byte-exact，注意結尾單一空白）。
        assert!(prompt_is_answerable("spike@localhost's password: "));
        assert!(prompt_is_answerable("frank@10.0.0.9's password: "));
        // PAM keyboard-interactive 常見形式。
        assert!(prompt_is_answerable("Password: "));
        assert!(prompt_is_answerable("password:"));
    }

    #[test]
    fn accepts_key_passphrase_prompts() {
        assert!(prompt_is_answerable(
            "Enter passphrase for key '/Users/frank/.ssh/id_ed25519': "
        ));
    }

    #[test]
    fn rejects_host_key_confirmation_prompt() {
        // Task 0 Step 4 實測字串（spike 環境，byte-exact，單一多行字串，結尾單一空白）：
        // 這正是造成無窮迴圈的關鍵案例 —— SSH_ASKPASS_REQUIRE=force 下，若這句被誤答
        // 密碼，ssh 會再問一次，且沒有重試上限。
        assert!(!prompt_is_answerable(
            "The authenticity of host '[localhost]:2299 ([::1]:2299)' can't be established.\nED25519 key fingerprint is: SHA256:wcPzOF//CE0QpQ3DikA+x+obBSnSP2DMbevjEiSnouQ\nThis key is not known by any other names.\nAre you sure you want to continue connecting (yes/no/[fingerprint])? "
        ));
    }

    #[test]
    fn rejects_reprompt_that_actually_caused_the_infinite_loop() {
        // Task 0 Step 4 實測字串：host key 提示被誤答後，ssh 重問的版本。
        // 這句沒有重試上限 —— spike 因此寫出 44,657 行 log 才被手動中止。
        assert!(!prompt_is_answerable(
            "Please type 'yes', 'no' or the fingerprint: "
        ));
    }

    #[test]
    fn rejects_host_key_prompt_shape_regardless_of_host_details() {
        // spike 的 host/port/fingerprint 只是那次一次性容器的產物。換一組完全不同的
        // 值，確保白名單拒絕的是「host key 提示的形狀」，不是剛好卡在這幾個字面值上
        // ——否則只保護 spike 那台機器，實際的防護等於沒生效。
        assert!(!prompt_is_answerable(
            "The authenticity of host 'example.com (203.0.113.7)' can't be established.\nRSA key fingerprint is: SHA256:AbCdEfGhIjKlMnOpQrStUvWxYz0123456789ABCDEFGHIJ\nAre you sure you want to continue connecting (yes/no/[fingerprint])? "
        ));
    }

    #[test]
    fn rejects_server_controlled_lookalike_prompts() {
        // 伺服器可任意指定 keyboard-interactive 的提示文字。
        assert!(!prompt_is_answerable("Please enter your password:"));
        assert!(!prompt_is_answerable("Type the password: now"));
        assert!(!prompt_is_answerable("Verification code: "));
        assert!(!prompt_is_answerable(""));
        assert!(!prompt_is_answerable("   "));
    }

    #[test]
    fn env_secret_takes_priority_over_keychain() {
        // 環境變數 fallback 存在時，不去碰 keychain（本機無密鑰環也能運作）。
        let got = resolve_secret("host:nonexistent-alias", Some("from-env".to_string()));
        assert_eq!(got.as_deref(), Some("from-env"));
    }

    #[test]
    fn missing_account_and_no_env_yields_none() {
        let got = resolve_secret("host:definitely-not-a-real-account-xyz", None);
        assert_eq!(got, None);
    }
}
