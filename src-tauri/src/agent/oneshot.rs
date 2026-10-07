//! Connect 的一次性通道(金鑰保管庫 spec §5.6):從 SSHelter 按 Connect(或系統匣的快速連線)連到用「只在 SSHelter」金鑰的主機時,開一個只給這次
//! 連線的 agent 端點,在終端機執行 `ssh -o IdentityAgent=<通道> -o ForwardAgent=no <主機>`。通道只接受同一使用者的第一個連線,60 秒內沒人連
//! 就關掉,連線結束就關掉;裡面只提供這台主機的金鑰,而且已經核准(`broker::Grant`:不跳核准視窗、不算進記住的核准)。
//! 呼叫端在終端機啟動之前出了錯(丟掉 `Channel` 而沒有 `keep`),通道馬上取消;60 秒到了還沒人連,通知畫面(spec §11:Connect 沒有連上,說明原因)。

use std::path::Path;
#[cfg(unix)]
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use tauri::{Emitter, Manager};

use crate::agent::broker::{Connection, Grant};
use crate::agent::server::Stream;
use crate::agent::{agent_dir, home_dir, peer, session, AppAgentHost};
use crate::error::AppError;
use crate::state::AppState;
use crate::sync::slot_rules::{resolve_identity_value, IdentityTarget};
use crate::sync::state_v2::{SlotSource, SyncStateV2};
use crate::vault::store::{stored_ids, vault_path};

pub const ONE_SHOT_TIMEOUT: Duration = Duration::from_secs(60);

/// 通道 60 秒內沒人連就關掉時送給畫面的事件,payload 是主機的 alias(畫面請使用者再連一次)。
pub const CONNECT_EXPIRED_EVENT: &str = "agent://connect-expired";

/// 這台的保管庫沒有這個主機要用的金鑰(spec §11):Connect 不啟動,說明原因。
pub const VAULT_KEY_MISSING_MESSAGE: &str =
    "This host's key isn't in SSHelter on this computer. A synced key comes back with the next sync; then connect again.";

/// 通道與它的背景執行緒共用的停止狀態。
#[derive(Debug, Default)]
struct Stop {
    /// 呼叫端放棄了這個通道(`Channel` 沒被 `keep` 就被丟掉,例如終端機沒啟動):不再服務任何連線,也不說逾時。
    cancelled: AtomicBool,
    /// Windows:第一個連線已經到了(或等待已經結束),不必再連自己的 pipe 去叫醒 `ConnectNamedPipe`。
    #[cfg(windows)]
    connected: AtomicBool,
}

/// 一個開著、等第一個連線的通道。沒有 `keep` 就丟掉它,通道取消:呼叫端在終端機啟動之前出了錯,不該留一個已經核准的通道空等 60 秒。
#[derive(Debug)]
pub struct Channel {
    /// Unix:`run/` 裡的 socket 檔名;Windows:pipe 名稱。
    pub name: String,
    /// socket 的路徑(測試用它連;取消時用它移掉 socket 檔)。
    #[cfg(unix)]
    pub path: PathBuf,
    /// 與背景執行緒共用。
    stop: Arc<Stop>,
    /// 還沒被 `keep`:丟掉時要取消。
    armed: bool,
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

    /// 終端機啟動了:通道留給它的 ssh,丟掉這個值不再取消(第一個連線之後、或 60 秒逾時,通道自己關掉)。
    pub fn keep(mut self) {
        self.armed = false;
    }
}

impl Drop for Channel {
    /// 沒被 `keep` 就取消:旗標讓背景執行緒不再服務任何連線、也不說逾時;Unix 立刻移掉 socket 檔(連不上了),Windows 連自己的 pipe 一次,
    /// 讓還在等的 `ConnectNamedPipe` 結束(已經有人連上的就不必)。
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        self.stop.cancelled.store(true, Ordering::SeqCst);
        #[cfg(unix)]
        {
            let _ = std::fs::remove_file(&self.path);
        }
        #[cfg(windows)]
        {
            if !self.stop.connected.load(Ordering::SeqCst) {
                let _ = std::fs::OpenOptions::new().read(true).write(true).open(format!(r"\\.\pipe\{}", self.name));
            }
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

/// 上一次沒收好的通道(SSHelter 在通道開著時結束或當掉):`run/` 裡檔名是 8 個 hex 字元、是 socket、而且比 `max_age` 舊的移掉。
/// 不連上去確認(連上去就是那個通道的第一個連線);活著的通道最多 `ONE_SHOT_TIMEOUT` 就自己移掉,比它舊很多的一定沒人在聽。
#[cfg(unix)]
fn sweep_stale(run_dir: &Path, now: std::time::SystemTime, max_age: Duration) {
    use std::os::unix::fs::FileTypeExt;

    let Ok(entries) = std::fs::read_dir(run_dir) else { return };
    for entry in entries.flatten() {
        let named_like_a_channel = entry
            .file_name()
            .to_str()
            .is_some_and(|name| name.len() == 8 && name.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')));
        // `DirEntry::file_type` 與 `metadata` 不跟著 symlink 走:指到別處的 symlink 不是我們的 socket。
        let is_socket = entry.file_type().is_ok_and(|kind| kind.is_socket());
        // 讀不到修改時間、或修改時間比 `now` 還晚:留著。
        let old = entry
            .metadata()
            .and_then(|meta| meta.modified())
            .ok()
            .and_then(|modified| now.duration_since(modified).ok())
            .is_some_and(|age| age > max_age);
        if named_like_a_channel && is_socket && old {
            let _ = std::fs::remove_file(entry.path());
        }
    }
}

/// Unix:等第一個連線的結果。
#[cfg(unix)]
enum Waited {
    Connected(Stream),
    TimedOut,
    Cancelled,
    Failed(std::io::Error),
}

/// 等到結果之後:同一個使用者的連線交給 `serve`(不是同一個使用者就不服務),逾時呼叫 `expired`。已經取消的(`cancelled`)什麼都不做:
/// 取消之後才接到的連線直接丟掉,也不說逾時。
#[cfg(unix)]
fn settle(waited: Waited, cancelled: bool, serve: Box<dyn FnOnce(Stream, Option<u32>) + Send>, expired: Box<dyn FnOnce() + Send>) {
    match waited {
        Waited::Connected(stream) if !cancelled => {
            // macOS 的 accept 沿用 listener 的 non-blocking;不是同一個使用者就不服務。
            if stream.set_nonblocking(false).is_ok() {
                if let Ok(pid) = crate::agent::server::peer(&stream) {
                    let _ = stream.set_read_timeout(Some(crate::agent::server::IDLE_TIMEOUT));
                    serve(stream, pid);
                }
            }
        }
        Waited::TimedOut if !cancelled => expired(),
        Waited::Failed(e) => eprintln!("[agent] connect channel stopped: {e}"),
        Waited::Connected(_) | Waited::TimedOut | Waited::Cancelled => {}
    }
}

/// 在 `run_dir`(`~/.ssh/sshelter/agent/run`)開一個 socket,背景等第一個連線:同一個使用者的就交給 `serve`(別人先連上來也算用掉了通道:
/// 關掉、不服務),`timeout` 內沒人連就關掉並呼叫 `expired`(一次)。第一個連線一到 socket 檔就移除,不會有第二個連線。開之前先清掉上一次留下的
/// 舊 socket 檔(`sweep_stale`)。回傳的 `Channel` 沒有被 `keep` 就丟掉,通道取消:socket 檔移掉、不服務、也不呼叫 `expired`。
#[cfg(unix)]
pub fn open(
    run_dir: &Path,
    serve: Box<dyn FnOnce(Stream, Option<u32>) + Send>,
    expired: Box<dyn FnOnce() + Send>,
    timeout: Duration,
) -> Result<Channel, AppError> {
    use std::os::unix::fs::PermissionsExt;
    use std::os::unix::net::UnixListener;

    crate::sync::slot_files::ensure_keys_dir(run_dir)?;
    sweep_stale(run_dir, std::time::SystemTime::now(), ONE_SHOT_TIMEOUT * 2);
    let name = random_hex(4)?;
    let path = run_dir.join(&name);
    crate::agent::server::check_socket_path(&path)?;
    let listener = UnixListener::bind(&path)?;
    let stop = Arc::new(Stop::default());
    // 綁好之後有一步失敗,就把 socket 檔移掉:沒有人在聽的檔案不該留在 `run/` 裡。
    let started = (|| -> std::io::Result<()> {
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
        listener.set_nonblocking(true)?;
        let (socket, stop) = (path.clone(), Arc::clone(&stop));
        std::thread::Builder::new().name("sshelter-agent-connect".to_string()).spawn(move || {
            let deadline = std::time::Instant::now() + timeout;
            let waited = loop {
                if stop.cancelled.load(Ordering::SeqCst) {
                    break Waited::Cancelled;
                }
                match listener.accept() {
                    Ok((stream, _)) => break Waited::Connected(stream),
                    Err(e) if matches!(e.kind(), std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted) => {
                        if std::time::Instant::now() >= deadline {
                            break Waited::TimedOut;
                        }
                        std::thread::sleep(Duration::from_millis(50));
                    }
                    Err(e) => break Waited::Failed(e),
                }
            };
            drop(listener);
            let _ = std::fs::remove_file(&socket);
            settle(waited, stop.cancelled.load(Ordering::SeqCst), serve, expired);
        })?;
        Ok(())
    })();
    if let Err(e) = started {
        let _ = std::fs::remove_file(&path);
        return Err(e.into());
    }
    Ok(Channel { name, path, stop, armed: true })
}

/// Windows:一次性的 pipe(只有一個 instance)。`ConnectNamedPipe` 沒有逾時,時間到還沒人連就自己連一次讓等待結束(認得出是自己,不服務,呼叫
/// `expired`)。其餘同 Unix 的 `open`:同一個使用者由 pipe 的 DACL 保證,沒有 `keep` 就丟掉 `Channel` 也取消(`Channel::drop` 連自己一次,不呼叫 `expired`)。
#[cfg(windows)]
pub fn open(
    _run_dir: &Path,
    serve: Box<dyn FnOnce(Stream, Option<u32>) + Send>,
    expired: Box<dyn FnOnce() + Send>,
    timeout: Duration,
) -> Result<Channel, AppError> {
    let name = format!("sshelter-connect-{}", random_hex(16)?);
    let pipe = crate::agent::pipe_windows::one_shot(&name)?;
    let client_path = format!(r"\\.\pipe\{name}");
    let stop = Arc::new(Stop::default());
    let shared = Arc::clone(&stop);
    std::thread::Builder::new().name("sshelter-agent-connect".to_string()).spawn(move || {
        let stop = shared;
        let timed_out = Arc::new(AtomicBool::new(false));
        {
            let (stop, timed_out) = (Arc::clone(&stop), Arc::clone(&timed_out));
            std::thread::spawn(move || {
                std::thread::sleep(timeout);
                if !stop.connected.load(Ordering::SeqCst) {
                    timed_out.store(true, Ordering::SeqCst);
                    let _ = std::fs::OpenOptions::new().read(true).write(true).open(&client_path);
                }
            });
        }
        let accepted = crate::agent::pipe_windows::accept(&pipe);
        stop.connected.store(true, Ordering::SeqCst);
        let cancelled = stop.cancelled.load(Ordering::SeqCst);
        match accepted {
            // 取消之後才連上的(包括取消時連自己的那一次):不服務,也不說逾時。
            Ok(_) if cancelled => {}
            // 時間到:連上來的是上面那個執行緒自己,不服務。
            Ok(_) if timed_out.load(Ordering::SeqCst) => expired(),
            Ok(pid) => serve(std::fs::File::from(pipe), pid),
            Err(e) => eprintln!("[agent] connect channel stopped: {e}"),
        }
    })?;
    Ok(Channel { name, stop, armed: true })
}

/// 連上通道的程式可以用這個授權嗎:認得出執行檔而且不是 `ssh` 就不行(只有 SSHelter 剛在終端機啟動的 `ssh` 該用這個已經核准的授權);
/// 讀不到執行檔(程序已經結束、沒有權限)照常服務。
fn is_ssh_or_unknown(executable: Option<&str>) -> bool {
    executable.is_none_or(|base| base == "ssh")
}

/// 這台的保管庫有沒有這個插槽的私鑰(只讀檔裡的 id,不開 keychain、不搬檔案):沒有 → `VAULT_KEY_MISSING_MESSAGE`;
/// 讀不懂或更新版的格式 → 那個錯誤。
fn check_vault_holds(vault_file: &Path, slot_id: &str) -> Result<(), AppError> {
    if stored_ids(vault_file)?.contains(slot_id) {
        Ok(())
    } else {
        Err(AppError::Other(VAULT_KEY_MISSING_MESSAGE.to_string()))
    }
}

/// Connect 之前:這台主機用的是「只在 SSHelter」的金鑰 → 開一次性通道並回傳它(ssh 要多帶的選項用 `ssh_options`);不是(或這台沒有任何這種金鑰)→ None。
/// 回傳的 `Channel` 要在終端機啟動之後 `keep`,沒有就丟掉會取消。`ssh -G` 讀不了這台主機的設定時不擋 Connect:記一行、回 None,
/// 這台主機照沒有通道的方式連(經 Include 的主 agent,有核准視窗)。這台的保管庫沒有這個插槽的私鑰時回錯誤(`VAULT_KEY_MISSING_MESSAGE`),
/// Connect 不啟動。通道 60 秒內沒人連上來:記一行,並通知畫面(`CONNECT_EXPIRED_EVENT`)。會執行 `ssh -G`:不要在主執行緒呼叫。
pub fn prepare(app: &tauri::AppHandle, alias: &str) -> Result<Option<Channel>, AppError> {
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
    let identity_files: Vec<String> = match crate::config::intel::effective_config(alias, None) {
        Ok(pairs) => pairs.into_iter().filter(|(key, _)| key == "identityfile").map(|(_, value)| value).collect(),
        Err(e) => {
            eprintln!("[agent] ssh -G can't read {alias}'s settings, connecting without the key channel: {e}");
            return Ok(None);
        }
    };
    let home = home_dir()?;
    let slot_id = state.sync.core.lock().unwrap().state.as_ref().and_then(|s| vault_slot_of(&identity_files, s, &home));
    let Some(slot_id) = slot_id else { return Ok(None) };
    // `with_env` 不鎖任何東西(不要在這裡呼叫會鎖 `sync.core` 的函式)。
    let vault_file = crate::sync::engine::with_env(app, |env| vault_path(&env.state_path))?;
    check_vault_holds(&vault_file, &slot_id)?;
    let serve: Box<dyn FnOnce(Stream, Option<u32>) + Send> = {
        let app = app.clone();
        Box::new(move |mut stream, pid| {
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
        })
    };
    let expired: Box<dyn FnOnce() + Send> = {
        let (app, alias) = (app.clone(), alias.to_string());
        Box::new(move || {
            eprintln!("[agent] the key channel for {alias} closed unused after {} s", ONE_SHOT_TIMEOUT.as_secs());
            let _ = app.emit(CONNECT_EXPIRED_EVENT, alias);
        })
    };
    Ok(Some(open(&agent_dir(&home).join("run"), serve, expired, ONE_SHOT_TIMEOUT)?))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agent::protocol::{read_frame, write_frame, SSH_AGENTC_REQUEST_IDENTITIES, SSH_AGENT_IDENTITIES_ANSWER};
    use crate::agent::server::testing::NoKeys;
    use crate::sync::state_v2::LocalSlot;
    use std::path::PathBuf;
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

    /// 畫面(`src/lib/agent.ts`)聽的事件名稱,和給使用者看的說明:兩邊各有一份,這裡釘住 Rust 這一份(`agent.test.ts` 釘住另一份)。
    #[test]
    fn the_event_and_the_message_the_screen_depends_on_are_pinned() {
        assert_eq!(CONNECT_EXPIRED_EVENT, "agent://connect-expired");
        assert_eq!(
            VAULT_KEY_MISSING_MESSAGE,
            "This host's key isn't in SSHelter on this computer. A synced key comes back with the next sync; then connect again."
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

    /// 不連到任何端點的 `Channel`(只看它的選項):丟掉它什麼都不取消。
    #[cfg(unix)]
    fn detached(name: &str) -> Channel {
        Channel { name: name.into(), path: PathBuf::from(format!("/x/run/{name}")), stop: Arc::default(), armed: false }
    }

    #[cfg(windows)]
    fn detached(name: &str) -> Channel {
        Channel { name: name.into(), stop: Arc::default(), armed: false }
    }

    #[cfg(unix)]
    #[test]
    fn ssh_gets_the_channel_with_tilde_and_no_forwarding() {
        let channel = detached("0a1b2c3d");
        assert_eq!(
            ssh_options(&channel),
            vec!["-o", "IdentityAgent=~/.ssh/sshelter/agent/run/0a1b2c3d", "-o", "ForwardAgent=no"]
        );
    }

    #[cfg(windows)]
    #[test]
    fn ssh_gets_the_channel_as_a_forward_slash_pipe_and_no_forwarding() {
        let channel = detached("sshelter-connect-00");
        assert_eq!(ssh_options(&channel), vec!["-o", "IdentityAgent=//./pipe/sshelter-connect-00", "-o", "ForwardAgent=no"]);
    }

    fn serving(pids: mpsc::Sender<Option<u32>>) -> Box<dyn FnOnce(Stream, Option<u32>) + Send> {
        Box::new(move |mut stream, pid| {
            let _ = pids.send(pid);
            let _ = crate::agent::session::serve(&mut stream, &NoKeys);
        })
    }

    /// 逾時的 callback:被呼叫就在 `calls` 送一個訊號。
    fn expiring(calls: mpsc::Sender<()>) -> Box<dyn FnOnce() + Send> {
        Box::new(move || {
            let _ = calls.send(());
        })
    }

    /// 不在乎逾時的測試用。
    fn never_expires() -> Box<dyn FnOnce() + Send> {
        Box::new(|| {})
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
        let channel = open(&dir.path().join("run"), serving(tx), never_expires(), Duration::from_secs(5)).unwrap();
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
        let channel = open(&run, serving(tx), never_expires(), Duration::from_secs(5)).unwrap();
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
        let err = open(&run, serving(tx), never_expires(), Duration::from_secs(5)).unwrap_err().to_string();
        assert!(err.contains("too long"), "{err}");
        assert_eq!(std::fs::read_dir(&run).unwrap().count(), 0, "nothing was bound");
        assert!(rx.recv_timeout(Duration::from_millis(100)).is_err(), "nothing was served");
    }

    #[cfg(unix)]
    #[test]
    fn a_channel_nobody_uses_closes_after_the_timeout() {
        let dir = short_dir();
        let (tx, rx) = mpsc::channel();
        let (expired_tx, expired_rx) = mpsc::channel();
        let channel = open(&dir.path().join("run"), serving(tx), expiring(expired_tx), Duration::from_millis(100)).unwrap();
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        while channel.path.exists() && std::time::Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(20));
        }
        assert!(!channel.path.exists());
        assert_eq!(expired_rx.recv_timeout(Duration::from_secs(5)), Ok(()), "the time ran out: the caller is told");
        assert!(expired_rx.recv_timeout(Duration::from_millis(200)).is_err(), "and told once");
        assert!(rx.recv_timeout(Duration::from_millis(200)).is_err(), "nothing was served");
    }

    #[cfg(unix)]
    #[test]
    fn a_channel_that_was_used_never_says_it_expired() {
        use std::os::unix::net::UnixStream;
        let dir = short_dir();
        let (tx, rx) = mpsc::channel();
        let (expired_tx, expired_rx) = mpsc::channel();
        let channel = open(&dir.path().join("run"), serving(tx), expiring(expired_tx), Duration::from_secs(1)).unwrap();
        let mut stream = UnixStream::connect(&channel.path).unwrap();
        write_frame(&mut stream, &[SSH_AGENTC_REQUEST_IDENTITIES]).unwrap();
        assert_eq!(read_frame(&mut stream).unwrap().unwrap()[0], SSH_AGENT_IDENTITIES_ANSWER);
        assert_eq!(rx.recv_timeout(Duration::from_secs(5)).unwrap(), Some(std::process::id()));
        drop(stream);
        std::thread::sleep(Duration::from_millis(1500)); // past the timeout
        assert!(expired_rx.try_recv().is_err(), "a connection was made: the time did not run out");
    }

    #[cfg(unix)]
    #[test]
    fn dropping_a_channel_that_was_not_kept_cancels_it() {
        use std::os::unix::net::UnixStream;
        let dir = short_dir();
        let (tx, rx) = mpsc::channel();
        let (expired_tx, expired_rx) = mpsc::channel();
        let channel = open(&dir.path().join("run"), serving(tx), expiring(expired_tx), Duration::from_millis(300)).unwrap();
        let path = channel.path.clone();
        drop(channel);
        assert!(!path.exists(), "the socket is gone at once");
        assert!(UnixStream::connect(&path).is_err(), "nobody can connect to it");
        std::thread::sleep(Duration::from_millis(800)); // past the timeout
        assert!(rx.try_recv().is_err(), "nothing was served");
        assert!(expired_rx.try_recv().is_err(), "a cancelled channel does not say that the time ran out");
    }

    /// 取消不等逾時:背景執行緒結束時,它手上的兩個 callback 一起被丟掉(沒有被呼叫),送出端斷線就代表執行緒結束了。
    #[cfg(unix)]
    #[test]
    fn cancelling_ends_the_wait_without_waiting_for_the_timeout() {
        let dir = short_dir();
        let (tx, rx) = mpsc::channel();
        let (expired_tx, expired_rx) = mpsc::channel();
        let channel = open(&dir.path().join("run"), serving(tx), expiring(expired_tx), Duration::from_secs(60)).unwrap();
        drop(channel);
        assert_eq!(rx.recv_timeout(Duration::from_secs(5)), Err(mpsc::RecvTimeoutError::Disconnected));
        assert_eq!(expired_rx.recv_timeout(Duration::from_secs(5)), Err(mpsc::RecvTimeoutError::Disconnected));
    }

    #[cfg(unix)]
    #[test]
    fn a_kept_channel_stays_open_for_its_ssh() {
        use std::os::unix::net::UnixStream;
        let dir = short_dir();
        let (tx, rx) = mpsc::channel();
        let (expired_tx, expired_rx) = mpsc::channel();
        let channel = open(&dir.path().join("run"), serving(tx), expiring(expired_tx), Duration::from_secs(5)).unwrap();
        let path = channel.path.clone();
        channel.keep();
        assert!(path.exists(), "keeping it leaves the socket where it is");
        let mut stream = UnixStream::connect(&path).unwrap();
        write_frame(&mut stream, &[SSH_AGENTC_REQUEST_IDENTITIES]).unwrap();
        assert_eq!(read_frame(&mut stream).unwrap().unwrap()[0], SSH_AGENT_IDENTITIES_ANSWER);
        assert_eq!(rx.recv_timeout(Duration::from_secs(5)).unwrap(), Some(std::process::id()));
        assert!(expired_rx.try_recv().is_err());
    }

    /// 等到結果之後的決定(不經背景執行緒,所以取消與連線、逾時剛好同時發生的情形也能測):取消了就什麼都不做。
    #[cfg(unix)]
    #[test]
    fn once_cancelled_nothing_is_served_and_no_timeout_is_reported() {
        use std::os::unix::net::UnixStream;
        let (tx, rx) = mpsc::channel();
        let (expired_tx, expired_rx) = mpsc::channel();
        let (client, accepted) = UnixStream::pair().unwrap();
        drop(client);
        settle(Waited::Connected(accepted), true, serving(tx), expiring(expired_tx));
        assert!(rx.try_recv().is_err(), "a connection that arrives after the cancel is dropped unserved");
        assert!(expired_rx.try_recv().is_err());

        let (tx, rx) = mpsc::channel();
        let (expired_tx, expired_rx) = mpsc::channel();
        settle(Waited::TimedOut, true, serving(tx), expiring(expired_tx));
        assert!(rx.try_recv().is_err());
        assert!(expired_rx.try_recv().is_err(), "the deadline and the cancel at the same moment: no timeout is reported");

        let (tx, rx) = mpsc::channel();
        let (expired_tx, expired_rx) = mpsc::channel();
        settle(Waited::Cancelled, true, serving(tx), expiring(expired_tx));
        assert!(rx.try_recv().is_err() && expired_rx.try_recv().is_err());
    }

    #[cfg(unix)]
    #[test]
    fn without_a_cancel_a_connection_is_served_and_only_a_timeout_is_reported() {
        use std::os::unix::net::UnixStream;
        let (tx, rx) = mpsc::channel();
        let (expired_tx, expired_rx) = mpsc::channel();
        let (client, accepted) = UnixStream::pair().unwrap();
        drop(client); // `serve` ends at once: the client is gone
        settle(Waited::Connected(accepted), false, serving(tx), expiring(expired_tx));
        assert!(rx.try_recv().is_ok(), "the connection was served");
        assert!(expired_rx.try_recv().is_err(), "a connection was made: the time did not run out");

        let (tx, rx) = mpsc::channel();
        let (expired_tx, expired_rx) = mpsc::channel();
        settle(Waited::TimedOut, false, serving(tx), expiring(expired_tx));
        assert!(rx.try_recv().is_err());
        assert_eq!(expired_rx.try_recv(), Ok(()), "the time ran out");

        let (tx, rx) = mpsc::channel();
        let (expired_tx, expired_rx) = mpsc::channel();
        settle(Waited::Failed(std::io::Error::other("accept failed")), false, serving(tx), expiring(expired_tx));
        assert!(rx.try_recv().is_err());
        assert!(expired_rx.try_recv().is_err(), "a failure is not a timeout: nobody is told to connect again");
    }

    /// 把 `path` 的修改時間設成 `seconds_ago` 秒之前(socket 檔不能用 `File` 開,所以直接呼叫 `utimes`)。
    #[cfg(unix)]
    fn backdate(path: &Path, seconds_ago: u64) {
        use std::os::unix::ffi::OsStrExt;
        let c_path = std::ffi::CString::new(path.as_os_str().as_bytes()).unwrap();
        let then = std::time::SystemTime::now() - Duration::from_secs(seconds_ago);
        let secs = then.duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() as libc::time_t;
        let stamp = libc::timeval { tv_sec: secs, tv_usec: 0 };
        // SAFETY: `c_path` is NUL-terminated and `[stamp, stamp]` is the two `timeval`s `utimes` reads.
        assert_eq!(unsafe { libc::utimes(c_path.as_ptr(), [stamp, stamp].as_ptr()) }, 0);
    }

    #[cfg(unix)]
    #[test]
    fn only_old_sockets_with_a_channels_name_are_swept() {
        use std::os::unix::net::UnixListener;
        use std::time::SystemTime;
        let dir = short_dir();
        let run = dir.path().join("run");
        std::fs::create_dir_all(&run).unwrap();
        let names = |dir: &Path| -> Vec<String> {
            let mut names: Vec<String> =
                std::fs::read_dir(dir).unwrap().map(|e| e.unwrap().file_name().to_string_lossy().into_owned()).collect();
            names.sort();
            names
        };
        // 當掉留下的樣子:綁好就丟掉 listener,socket 檔留在原處,沒有人在聽。
        drop(UnixListener::bind(run.join("0a1b2c3d")).unwrap()); // a channel's leftover: the only one to go
        drop(UnixListener::bind(run.join("not-hex1")).unwrap()); // 8 characters, not hex
        drop(UnixListener::bind(run.join("ABCDEF01")).unwrap()); // upper case is not how channels are named
        drop(UnixListener::bind(run.join("0a1b2c3")).unwrap()); // 7 characters
        drop(UnixListener::bind(run.join("0a1b2c3d4")).unwrap()); // 9 characters
        std::fs::write(run.join("deadbeef"), b"x").unwrap(); // a regular file with a channel's name
        std::os::unix::fs::symlink(run.join("not-hex1"), run.join("cafebabe")).unwrap(); // a symlink to a live-looking socket: never followed
        let before = names(&run);
        assert_eq!(before.len(), 7);

        let now = SystemTime::now();
        sweep_stale(&run, now, Duration::from_secs(120));
        assert_eq!(names(&run), before, "nothing is old yet");
        sweep_stale(&run, now - Duration::from_secs(600), Duration::from_secs(120));
        assert_eq!(names(&run), before, "a file newer than the clock is kept");
        sweep_stale(&run, now + Duration::from_secs(600), Duration::from_secs(120));
        let mut left = before.clone();
        left.retain(|name| name != "0a1b2c3d");
        assert_eq!(names(&run), left, "only the old socket with a channel's name went");

        sweep_stale(&dir.path().join("no-such-directory"), now, Duration::from_secs(120)); // best effort: nothing to sweep, no panic
    }

    #[cfg(unix)]
    #[test]
    fn opening_a_channel_sweeps_what_an_earlier_run_left_behind() {
        use std::os::unix::net::UnixListener;
        let dir = short_dir();
        let run = dir.path().join("run");
        std::fs::create_dir_all(&run).unwrap();
        let (old, young) = (run.join("0a1b2c3d"), run.join("1a2b3c4d"));
        drop(UnixListener::bind(&old).unwrap());
        drop(UnixListener::bind(&young).unwrap());
        backdate(&old, 10 * 60);
        let (tx, _rx) = mpsc::channel();
        let channel = open(&run, serving(tx), never_expires(), Duration::from_secs(5)).unwrap();
        assert!(!old.exists(), "a socket from ten minutes ago has nobody behind it");
        assert!(young.exists(), "a younger one may be a live channel of another SSHelter");
        assert!(channel.path.exists());
    }

    /// 這台的保管庫(`vault.json`)裡放著 `slot_id` 的一筆。
    fn vault_holding(slot_id: &str) -> (tempfile::TempDir, PathBuf) {
        use crate::sync::slot_rules::test_keys;
        use crate::sync::testkit::MemKeychain;
        use crate::vault::store::{EntryOrigin, Vault, VaultEntry, VAULT_FILE};
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(VAULT_FILE);
        let keychain = MemKeychain::default();
        let mut vault = Vault::open(&path, &keychain, 1).unwrap();
        let entry = VaultEntry {
            private_key: test_keys::plain(),
            public_key: test_keys::PLAIN_PUBLIC.to_string(),
            fingerprint: test_keys::PLAIN_FINGERPRINT.to_string(),
            origin: EntryOrigin::Synced,
            added_at_ms: 5,
        };
        vault.put(&keychain, slot_id, &entry).unwrap();
        (dir, path)
    }

    #[test]
    fn a_host_whose_key_is_in_this_vault_may_connect() {
        let (_dir, path) = vault_holding(&"a".repeat(32));
        check_vault_holds(&path, &"a".repeat(32)).unwrap();
    }

    #[test]
    fn a_host_whose_key_is_not_in_this_vault_is_told_so() {
        let dir = tempfile::tempdir().unwrap();
        let none = dir.path().join(crate::vault::store::VAULT_FILE);
        let err = check_vault_holds(&none, &"a".repeat(32)).unwrap_err();
        assert_eq!(err.to_string(), VAULT_KEY_MISSING_MESSAGE, "no vault file at all");
        assert!(!none.exists(), "looking does not create it");

        let (_dir, other) = vault_holding(&"b".repeat(32));
        let err = check_vault_holds(&other, &"a".repeat(32)).unwrap_err();
        assert_eq!(err.to_string(), VAULT_KEY_MISSING_MESSAGE, "a vault with another slot's key");
    }

    #[test]
    fn a_vault_file_that_cannot_be_read_is_its_own_error_and_stays_where_it_is() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(crate::vault::store::VAULT_FILE);
        std::fs::write(&path, b"this is not json").unwrap();
        let err = check_vault_holds(&path, &"a".repeat(32)).unwrap_err().to_string();
        assert!(err.contains("unreadable"), "{err}");
        assert_ne!(err, VAULT_KEY_MISSING_MESSAGE);
        assert_eq!(std::fs::read(&path).unwrap(), b"this is not json", "neither moved nor changed");
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 1, "nothing was set aside next to it");

        std::fs::write(&path, br#"{"version": 99}"#).unwrap();
        let err = check_vault_holds(&path, &"a".repeat(32)).unwrap_err().to_string();
        assert!(err.contains("newer SSHelter"), "{err}");
        assert_eq!(std::fs::read(&path).unwrap(), br#"{"version": 99}"#, "a newer format stays as it is");
    }

    /// 開一個 pipe 之後,用 `ok` 判斷每次連它的結果,直到 pipe 的名稱不見(`NotFound`);還連得上就是取消沒有生效。
    #[cfg(windows)]
    fn wait_until_the_pipe_is_gone(path: &str) {
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        loop {
            match std::fs::OpenOptions::new().read(true).write(true).open(path) {
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => return,
                Ok(_) => panic!("the pipe still takes a client"),
                Err(e) => assert!(std::time::Instant::now() < deadline, "the pipe is still there: {e}"),
            }
            std::thread::sleep(Duration::from_millis(50));
        }
    }

    /// `ConnectNamedPipe` 沒有逾時:時間到沒人連,執行緒自己連一次讓等待結束,認得出是自己、不服務、說逾時一次,pipe 的名稱隨 instance 一起消失。
    /// 測試在逾時之前不能去連它(連上去就是第一個連線)。
    #[cfg(windows)]
    #[test]
    fn a_pipe_nobody_uses_closes_after_the_timeout() {
        let dir = tempfile::tempdir().unwrap();
        let (tx, rx) = mpsc::channel();
        let (expired_tx, expired_rx) = mpsc::channel();
        let channel = open(&dir.path().join("run"), serving(tx), expiring(expired_tx), Duration::from_millis(100)).unwrap();
        let path = format!(r"\\.\pipe\{}", channel.name);
        std::thread::sleep(Duration::from_secs(2));
        wait_until_the_pipe_is_gone(&path);
        assert_eq!(expired_rx.recv_timeout(Duration::from_secs(5)), Ok(()), "the time ran out: the caller is told");
        assert!(expired_rx.recv_timeout(Duration::from_millis(200)).is_err(), "and told once");
        assert!(rx.recv_timeout(Duration::from_millis(200)).is_err(), "nothing was served");
    }

    #[cfg(windows)]
    #[test]
    fn dropping_a_pipe_that_was_not_kept_cancels_it() {
        let dir = tempfile::tempdir().unwrap();
        let (tx, rx) = mpsc::channel();
        let (expired_tx, expired_rx) = mpsc::channel();
        let channel = open(&dir.path().join("run"), serving(tx), expiring(expired_tx), Duration::from_millis(300)).unwrap();
        let path = format!(r"\\.\pipe\{}", channel.name);
        drop(channel);
        wait_until_the_pipe_is_gone(&path);
        std::thread::sleep(Duration::from_millis(800)); // past the timeout
        assert!(rx.try_recv().is_err(), "nothing was served");
        assert!(expired_rx.try_recv().is_err(), "a cancelled channel does not say that the time ran out");
    }

    #[cfg(windows)]
    #[test]
    fn a_kept_pipe_stays_open_for_its_client() {
        let dir = tempfile::tempdir().unwrap();
        let (tx, rx) = mpsc::channel();
        let (expired_tx, expired_rx) = mpsc::channel();
        let channel = open(&dir.path().join("run"), serving(tx), expiring(expired_tx), Duration::from_secs(5)).unwrap();
        let path = format!(r"\\.\pipe\{}", channel.name);
        channel.keep();
        let mut client = std::fs::OpenOptions::new().read(true).write(true).open(&path).unwrap();
        write_frame(&mut client, &[SSH_AGENTC_REQUEST_IDENTITIES]).unwrap();
        assert_eq!(read_frame(&mut client).unwrap().unwrap()[0], SSH_AGENT_IDENTITIES_ANSWER);
        assert_eq!(rx.recv_timeout(Duration::from_secs(5)).unwrap(), Some(std::process::id()));
        assert!(expired_rx.try_recv().is_err());
    }

    #[cfg(windows)]
    #[test]
    fn the_first_pipe_client_is_served_and_nobody_else() {
        let dir = tempfile::tempdir().unwrap();
        let (tx, rx) = mpsc::channel();
        let channel = open(&dir.path().join("run"), serving(tx), never_expires(), Duration::from_secs(5)).unwrap();
        let path = format!(r"\\.\pipe\{}", channel.name);
        let mut client = std::fs::OpenOptions::new().read(true).write(true).open(&path).unwrap();
        write_frame(&mut client, &[SSH_AGENTC_REQUEST_IDENTITIES]).unwrap();
        assert_eq!(read_frame(&mut client).unwrap().unwrap()[0], SSH_AGENT_IDENTITIES_ANSWER);
        assert_eq!(rx.recv_timeout(Duration::from_secs(5)).unwrap(), Some(std::process::id()));
        assert!(std::fs::OpenOptions::new().read(true).write(true).open(&path).is_err(), "one instance only");
    }
}
