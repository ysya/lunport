//! Connect 的一次性通道(金鑰保管庫 spec §5.6):從 SSHelter 按 Connect(或系統匣的快速連線)連到用「只在 SSHelter」金鑰的主機時,開一個只給這次
//! 連線的 agent 端點,在終端機執行 `ssh -o IdentityAgent=<通道> -o ForwardAgent=no <主機>`。通道只接受同一使用者的第一個連線,60 秒內沒人連
//! 就關掉,連線結束就關掉;裡面只提供這台主機的金鑰,而且已經核准(`broker::Grant`:不跳核准視窗、不算進記住的核准)。

use std::path::Path;
#[cfg(unix)]
use std::path::PathBuf;
use std::time::Duration;

use tauri::Manager;

use crate::agent::broker::{Connection, Grant};
use crate::agent::server::Stream;
use crate::agent::{agent_dir, home_dir, peer, session, AppAgentHost};
use crate::error::AppError;
use crate::state::AppState;
use crate::sync::slot_rules::{resolve_identity_value, IdentityTarget};
use crate::sync::state_v2::{SlotSource, SyncStateV2};

pub const ONE_SHOT_TIMEOUT: Duration = Duration::from_secs(60);

/// 一個開著、等第一個連線的通道。
#[derive(Debug)]
pub struct Channel {
    /// Unix:`run/` 裡的 socket 檔名;Windows:pipe 名稱。
    pub name: String,
    /// socket 的路徑(測試用它連;正式的程式只用 `name`)。
    #[cfg(unix)]
    #[cfg_attr(not(test), allow(dead_code))]
    pub path: PathBuf,
}

impl Channel {
    /// `ssh -o IdentityAgent=` 的值:Unix 用 `~/…`(ssh 自己展開,命令裡不放可能含空白的家目錄路徑),Windows 用正斜線的 pipe 路徑。
    pub fn identity_agent(&self) -> String {
        #[cfg(windows)]
        {
            format!("//./pipe/{}", self.name)
        }
        #[cfg(not(windows))]
        {
            format!("~/.ssh/sshelter/agent/run/{}", self.name)
        }
    }
}

/// `identity_files`(`ssh -G` 的 `identityfile` 值,依序;`~`、`%d` 不展開)裡第一個指到這台「只在 SSHelter」插槽的,回傳插槽 id。
pub fn vault_slot_of(identity_files: &[String], state: &SyncStateV2, home: &Path) -> Option<String> {
    identity_files.iter().find_map(|value| {
        let IdentityTarget::Slot(file) = resolve_identity_value(value, home) else { return None };
        state
            .key_slots
            .iter()
            .find(|(_, local)| local.file_name == file && matches!(local.source, Some(SlotSource::Vault { .. })))
            .map(|(id, _)| id.clone())
    })
}

/// ssh 要多帶的選項(放在主機名稱之前)。
pub fn ssh_options(channel: &Channel) -> Vec<String> {
    vec!["-o".into(), format!("IdentityAgent={}", channel.identity_agent()), "-o".into(), "ForwardAgent=no".into()]
}

fn random_hex(bytes: usize) -> Result<String, AppError> {
    let mut buf = vec![0u8; bytes];
    getrandom::fill(&mut buf).map_err(|e| AppError::Other(format!("cannot draw a channel name: {e}")))?;
    Ok(buf.iter().map(|b| format!("{b:02x}")).collect())
}

/// 在 `run_dir`(`~/.ssh/sshelter/agent/run`)開一個 socket,背景等第一個同一使用者的連線並交給 `serve`;`timeout` 內沒人連就關掉。
/// 第一個連線一到 socket 檔就移除,不會有第二個連線。
#[cfg(unix)]
pub fn open(run_dir: &Path, serve: Box<dyn FnOnce(Stream, Option<u32>) + Send>, timeout: Duration) -> Result<Channel, AppError> {
    use std::os::unix::fs::PermissionsExt;
    use std::os::unix::net::UnixListener;

    crate::sync::slot_files::ensure_keys_dir(run_dir)?;
    let name = random_hex(4)?;
    let path = run_dir.join(&name);
    crate::agent::server::check_socket_path(&path)?;
    let listener = UnixListener::bind(&path)?;
    // 綁好之後有一步失敗,就把 socket 檔移掉:沒有人在聽的檔案不該留在 `run/` 裡。
    let started = (|| -> std::io::Result<()> {
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
        listener.set_nonblocking(true)?;
        let socket = path.clone();
        std::thread::Builder::new().name("sshelter-agent-connect".to_string()).spawn(move || {
            let deadline = std::time::Instant::now() + timeout;
            let accepted = loop {
                match listener.accept() {
                    Ok((stream, _)) => break Some(stream),
                    Err(e)
                        if matches!(e.kind(), std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted)
                            && std::time::Instant::now() < deadline =>
                    {
                        std::thread::sleep(Duration::from_millis(50));
                    }
                    Err(_) => break None,
                }
            };
            drop(listener);
            let _ = std::fs::remove_file(&socket);
            if let Some(stream) = accepted {
                // macOS 的 accept 沿用 listener 的 non-blocking;不是同一個使用者就不服務。
                if stream.set_nonblocking(false).is_ok() {
                    if let Ok(pid) = crate::agent::server::peer(&stream) {
                        let _ = stream.set_read_timeout(Some(crate::agent::server::IDLE_TIMEOUT));
                        serve(stream, pid);
                    }
                }
            }
        })?;
        Ok(())
    })();
    if let Err(e) = started {
        let _ = std::fs::remove_file(&path);
        return Err(e.into());
    }
    Ok(Channel { name, path })
}

/// Windows:一次性的 pipe(只有一個 instance)。`ConnectNamedPipe` 沒有逾時,時間到還沒人連就自己連一次讓等待結束(認得出是自己,不服務)。
#[cfg(windows)]
pub fn open(_run_dir: &Path, serve: Box<dyn FnOnce(Stream, Option<u32>) + Send>, timeout: Duration) -> Result<Channel, AppError> {
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;

    let name = format!("sshelter-connect-{}", random_hex(16)?);
    let pipe = crate::agent::pipe_windows::one_shot(&name)?;
    let client_path = format!(r"\\.\pipe\{name}");
    std::thread::Builder::new().name("sshelter-agent-connect".to_string()).spawn(move || {
        let connected = Arc::new(AtomicBool::new(false));
        let woken = Arc::new(AtomicBool::new(false));
        {
            let (connected, woken) = (Arc::clone(&connected), Arc::clone(&woken));
            std::thread::spawn(move || {
                std::thread::sleep(timeout);
                if !connected.load(Ordering::SeqCst) {
                    woken.store(true, Ordering::SeqCst);
                    let _ = std::fs::OpenOptions::new().read(true).write(true).open(&client_path);
                }
            });
        }
        let accepted = crate::agent::pipe_windows::accept(&pipe);
        connected.store(true, Ordering::SeqCst);
        if let Ok(pid) = accepted {
            if !woken.load(Ordering::SeqCst) {
                serve(std::fs::File::from(pipe), pid);
            }
        }
    })?;
    Ok(Channel { name })
}

/// 連上通道的程式可以用這個授權嗎:認得出執行檔而且不是 `ssh` 就不行(只有 SSHelter 剛在終端機啟動的 `ssh` 該用這個已經核准的授權);
/// 讀不到執行檔(程序已經結束、沒有權限)照常服務。
fn is_ssh_or_unknown(executable: Option<&str>) -> bool {
    executable.is_none_or(|base| base == "ssh")
}

/// Connect 之前:這台主機用的是「只在 SSHelter」的金鑰 → 開一次性通道,回傳 ssh 要多帶的選項;不是(或這台沒有任何這種金鑰)→ None。
/// 會執行 `ssh -G`:不要在主執行緒呼叫。
pub fn prepare(app: &tauri::AppHandle, alias: &str) -> Result<Option<Vec<String>>, AppError> {
    let state = app.state::<AppState>();
    let any_vault = state
        .sync
        .core
        .lock()
        .unwrap()
        .state
        .as_ref()
        .is_some_and(|s| s.key_slots.values().any(|l| matches!(l.source, Some(SlotSource::Vault { .. }))));
    if !any_vault {
        return Ok(None);
    }
    let identity_files: Vec<String> = crate::config::intel::effective_config(alias, None)?
        .into_iter()
        .filter(|(key, _)| key == "identityfile")
        .map(|(_, value)| value)
        .collect();
    let home = home_dir()?;
    let slot_id = state.sync.core.lock().unwrap().state.as_ref().and_then(|s| vault_slot_of(&identity_files, s, &home));
    let Some(slot_id) = slot_id else { return Ok(None) };
    let app = app.clone();
    let serve: Box<dyn FnOnce(Stream, Option<u32>) + Send> = Box::new(move |mut stream, pid| {
        // 只服務剛在終端機啟動的 ssh(認得出程式的時候):同一使用者的其他程式搶先連上來,拿不到這個已經核准的授權。
        let executable = pid.and_then(peer::executable_base);
        if !is_ssh_or_unknown(executable.as_deref()) {
            eprintln!("[agent] connect channel refused a connection from {}", executable.unwrap_or_default());
            return;
        }
        let state = app.state::<AppState>();
        let host = AppAgentHost { app: app.clone() };
        let connection = Connection { broker: &state.agent.broker, host: &host, program: None, grant: Some(Grant { slot_id }) };
        if let Err(e) = session::serve(&mut stream, &connection) {
            eprintln!("[agent] connect channel closed: {e}");
        }
    });
    let channel = open(&agent_dir(&home).join("run"), serve, ONE_SHOT_TIMEOUT)?;
    Ok(Some(ssh_options(&channel)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agent::protocol::{read_frame, write_frame, SSH_AGENTC_REQUEST_IDENTITIES, SSH_AGENT_IDENTITIES_ANSWER};
    use crate::agent::server::testing::NoKeys;
    use crate::sync::state_v2::LocalSlot;
    use std::sync::mpsc;

    fn slot(file: &str, source: Option<SlotSource>) -> LocalSlot {
        LocalSlot {
            file_name: file.into(),
            source,
            last_error: None,
            asked: false,
            payload: None,
            uploaded_fingerprint: None,
            parked: false,
            learned_in: None,
            copy_from_another_account: false,
        }
    }

    #[test]
    fn the_first_identity_file_on_a_vault_slot_picks_the_key() {
        let home = Path::new("/h");
        let mut state = SyncStateV2::fresh("mac").unwrap();
        let vault = SlotSource::Vault { fingerprint: "SHA256:v".into(), public_key: "ssh-ed25519 AAAA".into(), has_passphrase: false };
        state.key_slots.insert("a".repeat(32), slot("id_mac-aaaaaaaa", Some(vault)));
        state.key_slots.insert("b".repeat(32), slot("work-bbbbbbbb", Some(SlotSource::SyncedCopy { fingerprint: "SHA256:w".into() })));
        let files = |values: &[&str]| values.iter().map(|v| v.to_string()).collect::<Vec<_>>();
        assert_eq!(
            vault_slot_of(&files(&["~/.ssh/id_rsa", "~/.ssh/sshelter/keys/id_mac-aaaaaaaa"]), &state, home),
            Some("a".repeat(32))
        );
        assert_eq!(vault_slot_of(&files(&["%d/.ssh/sshelter/keys/id_mac-aaaaaaaa"]), &state, home), Some("a".repeat(32)));
        assert_eq!(vault_slot_of(&files(&["~/.ssh/sshelter/keys/work-bbbbbbbb"]), &state, home), None, "a file slot is not a vault key");
        assert_eq!(vault_slot_of(&files(&["~/.ssh/id_rsa"]), &state, home), None);
    }

    /// 兩把都是「只在 SSHelter」的金鑰時,以 `IdentityFile` 的順序為準(ssh 試的順序),不是插槽在狀態裡的順序:`a` 排在 `c` 前面。
    #[test]
    fn the_first_identity_file_wins_when_several_are_vault_slots() {
        let home = Path::new("/h");
        let mut state = SyncStateV2::fresh("mac").unwrap();
        let vault = |fingerprint: &str| {
            Some(SlotSource::Vault { fingerprint: fingerprint.into(), public_key: "ssh-ed25519 AAAA".into(), has_passphrase: false })
        };
        state.key_slots.insert("a".repeat(32), slot("id_mac-aaaaaaaa", vault("SHA256:a")));
        state.key_slots.insert("c".repeat(32), slot("work-cccccccc", vault("SHA256:c")));
        let files = |values: &[&str]| values.iter().map(|v| v.to_string()).collect::<Vec<_>>();
        assert_eq!(
            vault_slot_of(&files(&["~/.ssh/sshelter/keys/work-cccccccc", "~/.ssh/sshelter/keys/id_mac-aaaaaaaa"]), &state, home),
            Some("c".repeat(32))
        );
        assert_eq!(
            vault_slot_of(&files(&["~/.ssh/sshelter/keys/id_mac-aaaaaaaa", "~/.ssh/sshelter/keys/work-cccccccc"]), &state, home),
            Some("a".repeat(32))
        );
    }

    #[test]
    fn only_ssh_or_a_program_we_cannot_read_may_use_the_channel() {
        assert!(is_ssh_or_unknown(Some("ssh")));
        assert!(is_ssh_or_unknown(None), "an executable we cannot read is served like before");
        for other in ["ssh-add", "ssh-keygen", "python3", "sshelter", "sh", ""] {
            assert!(!is_ssh_or_unknown(Some(other)), "{other:?} is not the ssh SSHelter launched");
        }
    }

    #[cfg(unix)]
    #[test]
    fn ssh_gets_the_channel_with_tilde_and_no_forwarding() {
        let channel = Channel { name: "0a1b2c3d".into(), path: PathBuf::from("/x/run/0a1b2c3d") };
        assert_eq!(
            ssh_options(&channel),
            vec!["-o", "IdentityAgent=~/.ssh/sshelter/agent/run/0a1b2c3d", "-o", "ForwardAgent=no"]
        );
    }

    #[cfg(windows)]
    #[test]
    fn ssh_gets_the_channel_as_a_forward_slash_pipe_and_no_forwarding() {
        let channel = Channel { name: "sshelter-connect-00".into() };
        assert_eq!(ssh_options(&channel), vec!["-o", "IdentityAgent=//./pipe/sshelter-connect-00", "-o", "ForwardAgent=no"]);
    }

    fn serving(pids: mpsc::Sender<Option<u32>>) -> Box<dyn FnOnce(Stream, Option<u32>) + Send> {
        Box::new(move |mut stream, pid| {
            let _ = pids.send(pid);
            let _ = crate::agent::session::serve(&mut stream, &NoKeys);
        })
    }

    #[cfg(unix)]
    fn short_dir() -> tempfile::TempDir {
        tempfile::Builder::new().prefix("so").tempdir_in("/tmp").unwrap()
    }

    #[cfg(unix)]
    #[test]
    fn the_first_connection_is_served_and_the_socket_disappears() {
        use std::os::unix::net::UnixStream;
        let dir = short_dir();
        let (tx, rx) = mpsc::channel();
        let channel = open(&dir.path().join("run"), serving(tx), Duration::from_secs(5)).unwrap();
        assert_eq!(channel.name.len(), 8);
        let mut stream = UnixStream::connect(&channel.path).unwrap();
        write_frame(&mut stream, &[SSH_AGENTC_REQUEST_IDENTITIES]).unwrap();
        assert_eq!(read_frame(&mut stream).unwrap().unwrap()[0], SSH_AGENT_IDENTITIES_ANSWER);
        assert_eq!(rx.recv_timeout(Duration::from_secs(5)).unwrap(), Some(std::process::id()));
        assert!(!channel.path.exists(), "removed as soon as the first connection arrived");
        assert!(UnixStream::connect(&channel.path).is_err(), "no second connection");
    }

    #[cfg(unix)]
    #[test]
    fn the_socket_is_owner_only_in_an_owner_only_directory_and_named_in_hex() {
        use std::os::unix::fs::PermissionsExt;
        use std::os::unix::net::UnixStream;
        let dir = short_dir();
        let run = dir.path().join("run");
        let (tx, rx) = mpsc::channel();
        let channel = open(&run, serving(tx), Duration::from_secs(5)).unwrap();
        let mode = |path: &Path| std::fs::metadata(path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(&run), 0o700);
        assert_eq!(mode(&channel.path), 0o600);
        assert_eq!(channel.path, run.join(&channel.name));
        assert!(channel.name.chars().all(|c| matches!(c, '0'..='9' | 'a'..='f')), "{}", channel.name);
        // 用掉它:背景執行緒到此結束,不留到逾時。
        drop(UnixStream::connect(&channel.path).unwrap());
        rx.recv_timeout(Duration::from_secs(5)).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn a_run_directory_too_deep_for_a_socket_path_is_refused_and_leaves_no_socket() {
        let dir = short_dir();
        let run = dir.path().join("a".repeat(120));
        let (tx, rx) = mpsc::channel();
        let err = open(&run, serving(tx), Duration::from_secs(5)).unwrap_err().to_string();
        assert!(err.contains("too long"), "{err}");
        assert_eq!(std::fs::read_dir(&run).unwrap().count(), 0, "nothing was bound");
        assert!(rx.recv_timeout(Duration::from_millis(100)).is_err(), "nothing was served");
    }

    #[cfg(unix)]
    #[test]
    fn a_channel_nobody_uses_closes_after_the_timeout() {
        let dir = short_dir();
        let (tx, rx) = mpsc::channel();
        let channel = open(&dir.path().join("run"), serving(tx), Duration::from_millis(100)).unwrap();
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        while channel.path.exists() && std::time::Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(20));
        }
        assert!(!channel.path.exists());
        assert!(rx.recv_timeout(Duration::from_millis(200)).is_err(), "nothing was served");
    }

    /// `ConnectNamedPipe` 沒有逾時:時間到沒人連,執行緒自己連一次讓等待結束,認得出是自己、不服務,pipe 的名稱隨 instance 一起消失。
    /// 測試在逾時之前不能去連它(連上去就是第一個連線)。
    #[cfg(windows)]
    #[test]
    fn a_pipe_nobody_uses_closes_after_the_timeout() {
        let dir = tempfile::tempdir().unwrap();
        let (tx, rx) = mpsc::channel();
        let channel = open(&dir.path().join("run"), serving(tx), Duration::from_millis(100)).unwrap();
        let path = format!(r"\\.\pipe\{}", channel.name);
        std::thread::sleep(Duration::from_millis(500));
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        loop {
            match std::fs::OpenOptions::new().read(true).write(true).open(&path) {
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => break,
                Ok(_) => panic!("the pipe still takes a client after the timeout"),
                Err(e) => assert!(std::time::Instant::now() < deadline, "the pipe is still there: {e}"),
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        assert!(rx.recv_timeout(Duration::from_millis(200)).is_err(), "nothing was served");
    }

    #[cfg(windows)]
    #[test]
    fn the_first_pipe_client_is_served_and_nobody_else() {
        let dir = tempfile::tempdir().unwrap();
        let (tx, rx) = mpsc::channel();
        let channel = open(&dir.path().join("run"), serving(tx), Duration::from_secs(5)).unwrap();
        let path = format!(r"\\.\pipe\{}", channel.name);
        let mut client = std::fs::OpenOptions::new().read(true).write(true).open(&path).unwrap();
        write_frame(&mut client, &[SSH_AGENTC_REQUEST_IDENTITIES]).unwrap();
        assert_eq!(read_frame(&mut client).unwrap().unwrap()[0], SSH_AGENT_IDENTITIES_ANSWER);
        assert_eq!(rx.recv_timeout(Duration::from_secs(5)).unwrap(), Some(std::process::id()));
        assert!(std::fs::OpenOptions::new().read(true).write(true).open(&path).is_err(), "one instance only");
    }
}
