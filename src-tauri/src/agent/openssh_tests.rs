//! 用真的 OpenSSH 工具測 agent(金鑰保管庫 spec §12):`ssh-add -L` 列出、`ssh-keygen -Y sign` 經 agent 簽章、`ssh-keygen -Y verify` 驗證。
//! 不需要 sshd,也不碰真的 `~/.ssh`:工具只讀 `SSH_AUTH_SOCK` 與測試目錄裡的檔案。工具不在 PATH 上就略過;環境變數
//! `SSHELTER_REQUIRE_OPENSSH` 剛好是 `1`(CI 設的)時改成失敗;別的值(包括空字串與 `0`)都不算。每次執行工具都有期限(`TOOL_TIMEOUT`)。

use std::collections::HashMap;
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use ssh_key::public::KeyData;
use zeroize::Zeroizing;

use crate::agent::broker::{AgentHost, Broker, Connection, Grant, VaultKey};
use crate::agent::prompt::{AgentApprovalAnswer, AgentApprovalRequest};
use crate::agent::server::{Handler, Stream};
use crate::agent::{oneshot, peer, session};
use crate::error::AppError;
use crate::sync::env::{Clock, Keychain, SystemClock};
use crate::sync::slot_rules::test_keys;
use crate::sync::testkit::MemKeychain;
use crate::vault::store::AgentSettings;

const IDS: [&str; 3] = ["11111111111111111111111111111111", "22222222222222222222222222222222", "33333333333333333333333333333333"];

/// 三把測試金鑰,每次都允許(並記下問了什麼)。
struct TestHost {
    keys: Vec<VaultKey>,
    private: HashMap<String, String>,
    keychain: MemKeychain,
    asked: Mutex<Vec<AgentApprovalRequest>>,
}

impl TestHost {
    fn new() -> Self {
        let key = |id: &str, name: &str, public: &str, fingerprint: &str| VaultKey {
            slot_id: id.into(),
            name: name.into(),
            fingerprint: fingerprint.into(),
            public_key: public.into(),
            has_passphrase: false,
        };
        TestHost {
            keys: vec![
                key(IDS[0], "ed25519", test_keys::PLAIN_PUBLIC, test_keys::PLAIN_FINGERPRINT),
                key(IDS[1], "ecdsa", test_keys::ECDSA_PUBLIC, test_keys::ECDSA_FINGERPRINT),
                key(IDS[2], "rsa", test_keys::RSA_PUBLIC, test_keys::RSA_FINGERPRINT),
            ],
            private: HashMap::from([
                (IDS[0].to_string(), test_keys::plain()),
                (IDS[1].to_string(), test_keys::ecdsa()),
                (IDS[2].to_string(), test_keys::rsa()),
            ]),
            keychain: MemKeychain::default(),
            asked: Mutex::new(Vec::new()),
        }
    }
}

impl AgentHost for TestHost {
    fn keys(&self) -> Vec<VaultKey> {
        self.keys.clone()
    }
    fn private_key(&self, slot_id: &str) -> Result<Option<Zeroizing<String>>, AppError> {
        Ok(self.private.get(slot_id).cloned().map(Zeroizing::new))
    }
    fn settings(&self) -> AgentSettings {
        AgentSettings::default()
    }
    fn keychain(&self) -> &dyn Keychain {
        &self.keychain
    }
    fn now_ms(&self) -> u64 {
        SystemClock.now_ms()
    }
    fn host_name(&self, _host_key: &KeyData) -> Option<String> {
        None
    }
    fn ask(&self, request: AgentApprovalRequest) -> Option<AgentApprovalAnswer> {
        self.asked.lock().unwrap().push(request);
        Some(AgentApprovalAnswer { allow: true, ..Default::default() })
    }
}

/// 工具的路徑。Windows 先用系統內建的 Win32-OpenSSH(`System32\OpenSSH`),沒有才用 PATH 上的:PATH 上 Git for Windows 的 `usr\bin` 也有
/// ssh-add 與 ssh-keygen,但那是 MSYS2 的版本,說的是 Unix socket,連不上 SSHelter 的 named pipe。其他平台就是 PATH 上的。
fn tool(name: &str) -> std::path::PathBuf {
    #[cfg(windows)]
    {
        let system = std::env::var_os("SystemRoot")
            .map(|root| std::path::Path::new(&root).join("System32").join("OpenSSH").join(format!("{name}.exe")));
        if let Some(path) = system.filter(|path| path.is_file()) {
            return path;
        }
    }
    std::path::PathBuf::from(name)
}

/// 不存在的 agent 端點:不需要 agent 的工具(探測與 `-Y verify`)把 `SSH_AUTH_SOCK` 指到這裡,免得連上開發者真正的 agent
/// (`ssh-add` 在回報選項錯誤之前就先連它)。
const NOWHERE: &str = if cfg!(windows) { r"\\.\pipe\sshelter-no-such-agent" } else { "/nonexistent/sshelter-no-such-agent" };

/// 一次工具執行最多等多久。
const TOOL_TIMEOUT: Duration = Duration::from_secs(30);

/// `run` 的本體,期限由呼叫端給(測試用短的)。起不來(找不到工具)回 `Err`;逾時就砍掉它,讀完它的輸出,然後 panic:訊息有完整的命令列與
/// 它到那一刻為止的 stderr。stdin 照呼叫端設的(沒設就繼承);stdout 與 stderr 是 pipe,結束之後才讀:這些工具的輸出很小,塞不滿 pipe。
fn run_within(command: &mut Command, timeout: Duration) -> std::io::Result<std::process::Output> {
    let mut child = command.stdout(Stdio::piped()).stderr(Stdio::piped()).spawn()?;
    let deadline = Instant::now() + timeout;
    while child.try_wait()?.is_none() {
        if Instant::now() >= deadline {
            let _ = child.kill();
            let out = child.wait_with_output()?;
            panic!("{command:?} did not finish within {timeout:?} and was killed; its stderr so far: {}", stderr(&out));
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    child.wait_with_output()
}

/// 執行工具,最多等 `TOOL_TIMEOUT`;逾時就砍掉它,並把它的 stderr 放進失敗訊息(CI 上卡住的工具不該讓整個 job 等到 30 分鐘)。
fn run(command: &mut Command) -> std::process::Output {
    run_within(command, TOOL_TIMEOUT).unwrap_or_else(|e| panic!("cannot run {command:?}: {e}"))
}

/// OpenSSH 的工具找不找得到;環境變數 `SSHELTER_REQUIRE_OPENSSH` 剛好是 `1` 時找不到就失敗。探測只為了看工具起不起得來(起不來是值,不是
/// panic,所以用 `run_within`),`SSH_AUTH_SOCK` 指到 `NOWHERE`。
fn have(name: &str) -> bool {
    let found = run_within(Command::new(tool(name)).arg("-?").env("SSH_AUTH_SOCK", NOWHERE), TOOL_TIMEOUT).is_ok();
    if !found {
        let required = std::env::var("SSHELTER_REQUIRE_OPENSSH").is_ok_and(|v| v == "1");
        assert!(!required, "{name} is not found");
        eprintln!("skipped: {name} is not found");
    }
    found
}

/// macOS 的暫存目錄路徑太長,放不下 socket:Unix 用 /tmp 底下的短目錄。
fn scratch() -> tempfile::TempDir {
    #[cfg(unix)]
    {
        tempfile::Builder::new().prefix("so").tempdir_in("/tmp").unwrap()
    }
    #[cfg(windows)]
    {
        tempfile::tempdir().unwrap()
    }
}

struct Running {
    dir: tempfile::TempDir,
    /// `SSH_AUTH_SOCK` 的值。
    endpoint: String,
    host: Arc<TestHost>,
    broker: Arc<Broker>,
}

/// 在暫存目錄開一個 agent(Windows 用這個測試自己的 pipe 名稱)。
fn start() -> Running {
    let dir = scratch();
    let host = Arc::new(TestHost::new());
    let broker = Arc::new(Broker::default());
    let handler: Handler = {
        let (host, broker) = (Arc::clone(&host), Arc::clone(&broker));
        Arc::new(move |mut stream: Stream, pid: Option<u32>| {
            let program = pid.and_then(|pid| peer::identify(&peer::process_chain(pid)));
            let connection = Connection { broker: &broker, host: host.as_ref(), program, grant: None };
            let _ = session::serve(&mut stream, &connection);
        })
    };
    let agent_dir = dir.path().join("agent");
    #[cfg(unix)]
    let endpoint = {
        crate::agent::server::listen_unix(&agent_dir, handler).unwrap();
        agent_dir.join("sock").display().to_string()
    };
    #[cfg(windows)]
    let endpoint = {
        use std::sync::atomic::{AtomicUsize, Ordering};
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let name = format!("sshelter-ossh-{}-{}", std::process::id(), NEXT.fetch_add(1, Ordering::SeqCst));
        crate::agent::pipe_windows::listen(&agent_dir, &name, handler).unwrap();
        format!(r"\\.\pipe\{name}")
    };
    Running { dir, endpoint, host, broker }
}

fn stderr(out: &std::process::Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

#[test]
fn ssh_add_lists_the_vault_keys_without_asking() {
    if !have("ssh-add") {
        return;
    }
    let agent = start();
    let out = run(Command::new(tool("ssh-add")).arg("-L").env("SSH_AUTH_SOCK", &agent.endpoint));
    assert!(out.status.success(), "{}", stderr(&out));
    let listed = String::from_utf8_lossy(&out.stdout);
    for public in [test_keys::PLAIN_PUBLIC, test_keys::ECDSA_PUBLIC, test_keys::RSA_PUBLIC] {
        assert!(listed.contains(public), "{public} missing from {listed}");
    }
    assert!(agent.host.asked.lock().unwrap().is_empty(), "listing never asks");
}

#[test]
fn ssh_keygen_signs_through_the_agent_and_the_signature_verifies() {
    if !have("ssh-keygen") {
        return;
    }
    let agent = start();
    let files = agent.dir.path();
    let data = files.join("data.txt");
    std::fs::write(&data, b"sign me").unwrap();
    let signature = files.join("data.txt.sig");
    for (name, public) in [("ed25519", test_keys::PLAIN_PUBLIC), ("ecdsa", test_keys::ECDSA_PUBLIC), ("rsa", test_keys::RSA_PUBLIC)] {
        let public_file = files.join(format!("{name}.pub"));
        std::fs::write(&public_file, format!("{public} {name}\n")).unwrap();
        let _ = std::fs::remove_file(&signature);
        let out = run(Command::new(tool("ssh-keygen"))
            .args(["-Y", "sign", "-n", "test", "-f"])
            .arg(&public_file)
            .arg(&data)
            .env("SSH_AUTH_SOCK", &agent.endpoint));
        assert!(out.status.success(), "{name}: {}", stderr(&out));
        let signers = files.join("allowed_signers");
        std::fs::write(&signers, format!("test@sshelter {public}\n")).unwrap();
        // 驗證只看簽章與 allowed_signers 裡的公鑰,不需要 agent:`SSH_AUTH_SOCK` 指到 `NOWHERE`,同探測。
        let verify = run(Command::new(tool("ssh-keygen"))
            .args(["-Y", "verify", "-n", "test", "-I", "test@sshelter", "-f"])
            .arg(&signers)
            .arg("-s")
            .arg(&signature)
            .stdin(std::fs::File::open(&data).unwrap())
            .env("SSH_AUTH_SOCK", NOWHERE));
        assert!(verify.status.success(), "{name}: {}", stderr(&verify));
    }
    let asked = agent.host.asked.lock().unwrap();
    assert_eq!(asked.len(), 3, "each signature was approved");
    assert!(asked.iter().all(|r| r.host.is_none() && !r.rememberable), "an SSHSIG request has no host and is never remembered");
}

#[test]
fn a_one_shot_channel_lists_only_its_key_and_only_once() {
    if !have("ssh-add") {
        return;
    }
    let agent = start();
    let serve: Box<dyn FnOnce(Stream, Option<u32>) + Send> = {
        let (host, broker) = (Arc::clone(&agent.host), Arc::clone(&agent.broker));
        Box::new(move |mut stream, _pid| {
            let grant = Some(Grant { slot_id: IDS[1].into() });
            let connection = Connection { broker: &broker, host: host.as_ref(), program: None, grant };
            let _ = session::serve(&mut stream, &connection);
        })
    };
    // `late` 不會被呼叫(10 秒內就連上了);`channel` 要留到兩次 ssh-add 都跑完:沒有 `keep` 就丟掉會取消通道。
    let channel =
        oneshot::open(&agent.dir.path().join("run"), serve, Box::new(|| {}), Duration::from_secs(10), Duration::from_secs(10)).unwrap();
    #[cfg(unix)]
    let endpoint = channel.path.display().to_string();
    #[cfg(windows)]
    let endpoint = format!(r"\\.\pipe\{}", channel.name);
    let out = run(Command::new(tool("ssh-add")).arg("-L").env("SSH_AUTH_SOCK", &endpoint));
    assert!(out.status.success(), "{}", stderr(&out));
    let listed = String::from_utf8_lossy(&out.stdout);
    assert!(listed.contains(test_keys::ECDSA_PUBLIC), "{listed}");
    assert!(!listed.contains(test_keys::PLAIN_PUBLIC), "only the granted key: {listed}");
    assert_eq!(listed.lines().count(), 1, "exactly one key is listed: {listed}");
    // 第二次要的是「連不上」:ssh-add 連不到 agent 時結束碼是 2,連上了但 agent 沒有金鑰時是 1(只是「沒列出東西」不夠)。
    let again = run(Command::new(tool("ssh-add")).arg("-L").env("SSH_AUTH_SOCK", &endpoint));
    assert_eq!(
        again.status.code(),
        Some(2),
        "the channel is gone after its first connection: ssh-add must fail to reach it (exit 2; exit 1 = it connected): stderr: {}, stdout: {}",
        stderr(&again),
        String::from_utf8_lossy(&again.stdout)
    );
}

/// 立刻結束的命令:`run` 回傳它的輸出。命令用測試程式自己(兩個平台都有),它只列出這個測試的名稱就結束。
#[test]
fn run_returns_the_output_of_a_command_that_exits_at_once() {
    let name = "run_returns_the_output_of_a_command_that_exits_at_once";
    let out = run(Command::new(std::env::current_exe().unwrap()).args(["--list", name]));
    assert!(out.status.success(), "{}", stderr(&out));
    let listed = String::from_utf8_lossy(&out.stdout);
    assert!(listed.contains(&format!("{name}: test")), "{listed}");
}

/// 逾時的命令被砍掉而不是等它跑完,失敗訊息有它的命令列與到那一刻為止的 stderr。`exec` 讓 sleep 取代 sh:砍 sh 不會留下還握著 pipe 的子行程。
/// stderr 的句子不整句出現在命令列裡(`printf` 把它拆開),所以訊息裡有整句就是真的讀到了 stderr。
#[cfg(unix)]
#[test]
fn a_command_that_outlives_its_deadline_is_killed_and_named() {
    let started = Instant::now();
    let payload = std::panic::catch_unwind(|| {
        run_within(Command::new("sh").args(["-c", "printf 'no %s yet\\n' answer >&2; exec sleep 5"]), Duration::from_millis(500))
    })
    .expect_err("a command that outlives its deadline must panic");
    let message = payload.downcast_ref::<String>().expect("a formatted panic message");
    assert!(message.contains(r#""sh""#) && message.contains("exec sleep 5"), "the message names the command: {message}");
    assert!(message.contains("no answer yet"), "the message carries the stderr so far: {message}");
    assert!(started.elapsed() < Duration::from_secs(4), "killed at the deadline, not waited for: {:?}", started.elapsed());
}
