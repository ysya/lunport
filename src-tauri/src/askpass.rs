//! SSH_ASKPASS helper 模式。
//!
//! SSHelter 的執行檔會被 ssh 以 `SSH_ASKPASS` 再次啟動；`main()` 偵測到 `SSHELTER_ASKPASS=1`
//! 就呼叫 `run()`，完全不初始化 GUI。ssh 把提示文字當作 argv[1] 傳進來。
//!
//! 安全性：`SSH_ASKPASS_REQUIRE=force` 會讓「所有」提示都走這裡，包含 host key 驗證。
//! 若無條件印出密碼，就會拿密碼去回答 host key 提示、ssh 再問一次 → 無窮迴圈（已實測，
//! 見 spike 記錄）；而且 keyboard-interactive 的提示文字由伺服器控制，惡意主機可藉此
//! 騙走密碼。因此這裡採白名單：只回應真正的密碼／passphrase 提示。
//!
//! **但「拒絕」不是免費的，也不是安全的預設。** `readpass.c` 的 `read_passphrase` 在
//! askpass 失敗時，若呼叫端沒帶 `RP_ALLOW_EOF` 就 `return xstrdup("")`，而 `sshconnect2.c`
//! 的兩個認證呼叫點都沒帶。所以 exit 1 會讓 ssh **送出一個空密碼**，在遠端留下一筆真實
//! 的失敗認證；只有 host key 的 `confirm()` 會把空字串當成 "no" 而安全失敗。
//!
//! 真正的結構性防線因此不在這個白名單，而在部署 argv 的 `-o KbdInteractiveAuthentication=no`
//! （見 `deploy::build_deploy_argv`）：關掉之後，helper 收到的提示全部由 client 產生，
//! 伺服器可控的文字根本進不來。**移除那個選項會讓這個白名單重新暴露在伺服器可控的輸入
//! 之下 —— 它不是效能調校。**

/// 只回應真正的密碼／passphrase 提示。
///
/// 兩端錨定，永遠不用 `contains` —— 對攻擊者可控的字串做無錨定子字串比對等於沒有防禦。
///
/// OpenSSH 8.5 起，client 會把 keyboard-interactive 提示加上自己產生的 `(user@host) `
/// 前綴（`sshconnect2.c` 的 `asmprintf(&display_prompt, …, "(%s@%s) %s", …)`），前綴
/// 「之後」的文字則完全由伺服器控制。因此：有前綴 → 剝掉後只接受完全等於 `password:`；
/// 無前綴 → 是 client 自己組的固定形狀，逐一錨定比對。
pub fn prompt_is_answerable(prompt: &str) -> bool {
    // 多行提示只有 host key 確認一種，一律拒絕。
    if prompt.contains('\n') {
        return false;
    }
    let trimmed = prompt.trim();

    if let Some(rest) = strip_kbdint_prefix(trimmed) {
        return rest.trim().eq_ignore_ascii_case("password:");
    }

    let lower = trimmed.to_ascii_lowercase();
    is_client_password_prompt(&lower) || lower.starts_with("enter passphrase for ")
}

/// 剝除 client 產生的 `(user@host) ` 前綴；沒有前綴時回 `None`。
/// 前綴內容由 `"%s@%s"` 組成，不含空白。
fn strip_kbdint_prefix(s: &str) -> Option<&str> {
    let rest = s.strip_prefix('(')?;
    let close = rest.find(')')?;
    let inside = &rest[..close];
    if inside.is_empty() || inside.contains(char::is_whitespace) || !inside.contains('@') {
        return None;
    }
    Some(rest[close + 1..].trim_start())
}

/// `<user>@<host>'s password:` —— user 與 host 皆非空且不得含空白。
/// 這道形狀檢查正是 `Please enter your account's password:` 被擋下的原因。
fn is_client_password_prompt(lower: &str) -> bool {
    let Some(head) = lower.strip_suffix("'s password:") else {
        return false;
    };
    if head.contains(char::is_whitespace) {
        return false;
    }
    match head.split_once('@') {
        Some((user, host)) => !user.is_empty() && !host.is_empty(),
        None => false,
    }
}

/// 診斷紀錄一律走 stderr —— stdout 是 ssh 讀取答案的通道，寫任何東西進去都會被當成密碼。
/// 絕不記錄密碼本身。前綴讓 `deploy::classify_outcome` 能濾掉這些行。
fn log_decision(prompt: &str, decision: &str) {
    eprintln!("[sshelter-askpass] {decision}: {prompt:?}");
}

/// 取得要回覆的密碼：優先用環境變數 fallback（本機無密鑰環時），否則查 keychain。
///
/// 空字串一律當成「沒有密碼」。否則 `run()` 會印出一行空白並 exit 0，而 ssh 會把那個
/// 空字串當成密碼送給伺服器（見 `run()` 的說明）。
pub fn resolve_secret(account: &str, env_secret: Option<String>) -> Option<String> {
    if let Some(s) = env_secret {
        return if s.is_empty() { None } else { Some(s) };
    }
    crate::secrets::get(account)
        .ok()
        .flatten()
        .filter(|s| !s.is_empty())
}

/// helper 模式進入點。永不返回。
///
/// 退出碼：0 = 已把密碼完整寫到 stdout；1 = 沒有回答。
///
/// **重要：exit 1 不等於「ssh 會安全地放棄」。** `readpass.c` 的 `read_passphrase` 在
/// askpass 失敗時，若呼叫端沒帶 `RP_ALLOW_EOF` 就 `return xstrdup("")`，而
/// `sshconnect2.c` 的兩個認證呼叫點都沒帶。也就是說 exit 1 會讓 ssh 送出一個「空密碼」，
/// 在遠端留下一筆真實的失敗認證。只有 host key 的 `confirm()` 會把空字串當成 "no" 而
/// 安全失敗。這正是部署 argv 必須帶 `-o KbdInteractiveAuthentication=no` 的原因：讓
/// 伺服器可控的提示根本不會出現，helper 就不必在「洩漏」與「送空密碼」之間二選一。
pub fn run() -> ! {
    use std::io::Write;

    // 用 args_os，不用 args()：伺服器可以在 keyboard-interactive 提示塞任意 bytes，
    // ssh 原樣轉交給 argv[1]。args() 遇到非法 UTF-8 會 panic；lossy 轉換則讓非法
    // UTF-8 的提示直接在白名單比對時被拒絕，而不是讓整個 process 帶著一段沒有
    // `[sshelter-askpass]` 前綴的 panic 訊息死在 stderr 上。
    let prompt = std::env::args_os()
        .nth(1)
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_default();
    if !prompt_is_answerable(&prompt) {
        log_decision(&prompt, "refused");
        std::process::exit(1);
    }

    let account = std::env::var("SSHELTER_ASKPASS_ACCOUNT").unwrap_or_default();
    let env_secret = std::env::var("SSHELTER_ASKPASS_SECRET").ok();

    match resolve_secret(&account, env_secret) {
        Some(secret) => {
            let stdout = std::io::stdout();
            let mut lock = stdout.lock();
            // ssh 讀一行；結尾必須有換行。寫入或 flush 失敗時絕不能 exit 0 ——
            // 那會讓 ssh 把「只寫出一半的密碼前綴」當成答案送給對方。
            if writeln!(lock, "{secret}").is_err() || lock.flush().is_err() {
                log_decision(&prompt, "write-failed");
                std::process::exit(1);
            }
            std::process::exit(0);
        }
        None => {
            log_decision(&prompt, "no-secret");
            std::process::exit(1)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_real_openssh_password_prompts() {
        // Task 0 Step 3 唯一的 byte-exact 實測字串（spike 環境，注意結尾單一空白）。
        assert!(prompt_is_answerable("spike@localhost's password: "));
        // 同形狀的另一個例子——不是實測字串，只是換一組 user/host 驗證「形狀」比對
        // 而非字面值（先前版本的註解誤把這句也標成 byte-exact 實測，已更正）。
        assert!(prompt_is_answerable("frank@10.0.0.9's password: "));
    }

    #[test]
    fn accepts_kbdint_password_prompt_with_client_prefix() {
        // OpenSSH >= 8.5 起，keyboard-interactive 提示一律被 client 包上
        // `(user@host) ` 前綴（release notes 8.5 + sshconnect2.c 的
        // `asmprintf(&display_prompt, …, "(%s@%s) %s", …)`）。這是舊規則完全漏接
        // 的情境：舊規則只認得無前綴的字面值，遇到前綴整句比對就失敗，等於拒絕了
        // 所有真正的 kbdint 密碼提示。
        assert!(prompt_is_answerable("(frank@10.0.0.9) Password: "));
        // 反過來的規格：裸的 `Password: `（沒有 client 前綴）沒有任何 ssh 路徑會
        // 產生，刻意不接受——接受它等於接受一段完全沒有 client 附加上下文的文字。
        assert!(!prompt_is_answerable("Password: "));
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
    fn rejects_any_prompt_containing_a_newline() {
        // 換行是獨立、無條件的拒絕理由：即使把換行前的部分單獨拿出來看完全符合
        // 密碼提示的形狀，只要整句含換行就一律拒絕——host key 確認正是唯一的多行
        // 提示，也是最初造成無窮迴圈的那種提示。
        assert!(!prompt_is_answerable(
            "frank@10.0.0.9's password: \nunexpected second line"
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
    fn rejects_unprefixed_apostrophe_s_password_bypass() {
        // 舊規則的 `ends_with("'s password:")` 被這句用兩個字元繞過：
        // "account" 比 "your" 多兩個字，但一樣以 "'s password:" 結尾。新規則額外要求
        // `'s password:` 前面那段（head）不得含空白；這裡的 head 是
        // "please enter your account"，含空白 → 拒絕。
        assert!(!prompt_is_answerable(
            "Please enter your account's password:"
        ));
    }

    #[test]
    fn rejects_prefixed_prompt_with_server_controlled_text_after_prefix() {
        // client 加的 `(user@host) ` 前綴只擔保「前綴本身」是 client 產生的；
        // 前綴之後的文字仍然 100% 由伺服器控制。有前綴時只接受逐字的 "password:"，
        // 其餘一律拒絕——包括看起來很像合法提示的文字，伺服器不能藉此觸發
        // passphrase 規則，也不能藉此重現無前綴時的兩字元繞過。
        assert!(!prompt_is_answerable(
            "(frank@10.0.0.9) Please enter your account's password:"
        ));
        assert!(!prompt_is_answerable(
            "(frank@10.0.0.9) Enter passphrase for key '/root/.ssh/id_rsa': "
        ));
    }

    #[test]
    fn env_secret_empty_string_is_treated_as_no_secret() {
        // 空字串一律當成「沒有密碼」，否則 run() 會印出空白行並 exit 0，
        // ssh 會把那個空字串當成密碼送出去（見 resolve_secret 的說明）。
        let got = resolve_secret("host:whatever-empty-env-case", Some(String::new()));
        assert_eq!(got, None);
    }

    /// 保底清理：確保這個測試不會在真實使用者的 keychain 留下測試資料。
    /// 寫法抄自 `secrets.rs`：`round_trip_set_get_delete` 用的 `CleanupGuard`。
    struct KeychainCleanupGuard<'a>(&'a str);
    impl Drop for KeychainCleanupGuard<'_> {
        fn drop(&mut self) {
            let _ = crate::secrets::delete(self.0);
        }
    }

    #[test]
    fn env_secret_takes_priority_over_keychain() {
        // 真的在 keychain 存一筆「不同」的值，才能證明環境變數贏過 keychain
        // 是因為「根本不查」，而不是剛好查到同一個值——用不存在的帳號無法
        // 分辨這兩種情況。
        if !crate::secrets::available() {
            eprintln!("skipping: no credential store on this machine");
            return;
        }
        let account = "test:askpass-env-priority";
        let _cleanup = KeychainCleanupGuard(account);
        crate::secrets::set(account, "from-keychain").expect("set ok");

        let got = resolve_secret(account, Some("from-env".to_string()));
        assert_eq!(got.as_deref(), Some("from-env"));
    }

    #[test]
    fn missing_account_and_no_env_yields_none() {
        // 沒有這個 guard，這個測試在「沒有可用密鑰環」的機器上也會綠燈，但原因
        // 是 `secrets::get` 整個回 Err 被 `.ok()` 吞掉，不是真的驗證到
        // 「帳號不存在 → None」這條路徑。
        if !crate::secrets::available() {
            eprintln!("skipping: no credential store on this machine");
            return;
        }
        let got = resolve_secret("host:definitely-not-a-real-account-xyz", None);
        assert_eq!(got, None);
    }

    #[cfg(unix)]
    #[test]
    fn invalid_utf8_prompt_is_rejected_not_panicking() {
        // 鏡射 run() 讀 argv[1] 的路徑：std::env::args_os().to_string_lossy()。伺服器
        // 能在 keyboard-interactive 提示塞任意 bytes，ssh 原樣轉交給 argv[1]；若這裡
        // 用的是 std::env::args()，非法 UTF-8 會直接 panic，而 panic 訊息沒有
        // `[sshelter-askpass]` 前綴，會被 Task 4 的 first_line_or 誤當成真正的錯誤
        // 訊息秀給使用者。無法從 unit test 設定真的 argv，所以直接構造非法 UTF-8
        // bytes、模擬 run() 裡的 lossy 轉換，確認轉換後的結果會被白名單安全拒絕。
        use std::ffi::OsString;
        use std::os::unix::ffi::OsStringExt;

        let invalid = OsString::from_vec(vec![b'(', b'x', 0xff, 0xfe, b')', b' ', b'P']);
        let prompt = invalid.to_string_lossy().into_owned();
        assert!(!prompt_is_answerable(&prompt));
    }
}
