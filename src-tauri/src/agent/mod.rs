//! SSHelter 的 SSH agent(key roadmap 第 2 階段 spec §5)。
pub mod approval;
pub mod broker;
pub mod peer;
#[cfg(windows)]
pub mod pipe_windows;
pub mod prompt;
pub mod protocol;
pub mod server;
pub mod session;
pub mod wiring;

use std::path::{Path, PathBuf};
use std::sync::Mutex;

use ssh_key::public::KeyData;
use tauri::Manager;
use zeroize::Zeroizing;

use crate::error::AppError;
use crate::state::AppState;
use crate::sync::env::{Clock, Keychain, OsKeychain, SystemClock};
use crate::vault::store::{vault_path, with_vault, AgentSettings};

/// `IdentityAgent` 在 `agent/config` 裡的值(spec §4.4、§6;ssh 自己展開 `~`)。
#[cfg(unix)]
pub const SOCKET_VALUE: &str = "~/.ssh/sshelter/agent/sock";

/// agent 的目錄 `<home>/.ssh/sshelter/agent`(0700):`config`、`sock`、`lock`、Connect 的 `run/`。
pub fn agent_dir(home: &Path) -> PathBuf {
    home.join(".ssh").join("sshelter").join("agent")
}

/// 寫進 `agent/config` 的 `IdentityAgent` 值。Windows 的 pipe 寫成正斜線(Win32-OpenSSH 8.9 起反斜線的寫法會失敗,spec §4.4)。
pub fn identity_agent_value() -> Result<String, AppError> {
    #[cfg(windows)]
    {
        Ok(format!("//./pipe/{}", pipe_windows::pipe_name()?))
    }
    #[cfg(not(windows))]
    {
        Ok(SOCKET_VALUE.to_string())
    }
}

/// agent 有沒有在提供(spec §11)。
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub enum AgentStatus {
    #[default]
    NotStarted,
    Running,
    /// 另一個 SSHelter 在提供。
    OtherInstance,
    /// 開不起來(路徑太長、權限、pipe 名稱被佔)。
    Failed(String),
}

/// agent 的執行期狀態(`AppState::agent`)。
#[derive(Default)]
pub struct AgentRuntime {
    pub prompts: prompt::PromptHub,
    pub broker: broker::Broker,
    pub status: Mutex<AgentStatus>,
}

/// production 的 `AgentHost`:同步狀態的金鑰、保管庫、OS keychain、系統時鐘、known_hosts 與核准視窗。
pub struct AppAgentHost {
    pub app: tauri::AppHandle,
}

impl broker::AgentHost for AppAgentHost {
    fn keys(&self) -> Vec<broker::VaultKey> {
        let state = self.app.state::<AppState>();
        let core = state.sync.core.lock().unwrap();
        core.state.as_ref().map(broker::vault_keys).unwrap_or_default()
    }

    /// 使用者按了允許,金鑰卻拿不出來(keychain 鎖著、保管庫讀不懂)時回錯誤;原因由 broker 記(`refused`,帶插槽 id),這裡不再記一次。
    fn private_key(&self, slot_id: &str) -> Result<Option<Zeroizing<String>>, AppError> {
        crate::sync::engine::with_env(&self.app, |env| {
            with_vault(env.runtime, &vault_path(&env.state_path), env.keychain, env.now(), |vault| vault.get(slot_id))
                .map(|entry| entry.map(|entry| Zeroizing::new(entry.private_key.clone())))
                .map_err(AppError::from)
        })
        .and_then(|inner| inner)
    }

    fn settings(&self) -> AgentSettings {
        let result = crate::sync::engine::with_env(&self.app, |env| {
            with_vault(env.runtime, &vault_path(&env.state_path), env.keychain, env.now(), |vault| Ok(vault.settings().clone()))
                .map_err(AppError::from)
        })
        .and_then(|inner| inner);
        settings_or_ask_every_time(result)
    }

    fn keychain(&self) -> &dyn Keychain {
        &OsKeychain
    }

    fn now_ms(&self) -> u64 {
        SystemClock.now_ms()
    }

    fn host_name(&self, host_key: &KeyData) -> Option<String> {
        host_name_in_files(&known_hosts_files(), host_key)
    }

    fn ask(&self, request: prompt::AgentApprovalRequest) -> Option<prompt::AgentApprovalAnswer> {
        let surface = prompt::TauriPromptSurface { app: self.app.clone() };
        self.app.state::<AppState>().agent.prompts.ask(&surface, request, prompt::APPROVAL_TIMEOUT)
    }
}

/// 讀得到就用這台的設定;讀不到(保管庫讀不懂、keychain 鎖著)就往嚴格的一邊退:每次都問,原因記到 stderr。不能退回預設值:預設值允許記住核准,
/// 而這台更嚴的設定(`always_ask`)正好讀不到,記住的核准就會在沒有視窗的情況下簽章。
fn settings_or_ask_every_time(result: Result<AgentSettings, AppError>) -> AgentSettings {
    result.unwrap_or_else(|e| {
        eprintln!("[agent] cannot read the agent settings: {e}");
        AgentSettings { always_ask: true, ..AgentSettings::default() }
    })
}

/// 找主機名稱的 known_hosts 檔,依優先順序:使用者的、系統的(Unix 的 `/etc/ssh`,Windows 的 `%ProgramData%\ssh`)。
fn known_hosts_files() -> Vec<PathBuf> {
    let mut files = Vec::new();
    if let Ok(ssh_dir) = crate::keys::ssh_dir() {
        files.push(ssh_dir.join("known_hosts"));
    }
    #[cfg(unix)]
    files.push(PathBuf::from("/etc/ssh/ssh_known_hosts"));
    #[cfg(windows)]
    {
        if let Some(program_data) = std::env::var_os("ProgramData") {
            files.push(PathBuf::from(program_data).join("ssh").join("ssh_known_hosts"));
        }
    }
    files
}

/// 這些 known_hosts 檔裡,第一個認得這把主機金鑰的名稱(前面的檔案優先,讀不到的檔案跳過)。以位元組讀、不合法的 UTF-8 換成 U+FFFD:
/// 一個壞掉的位元組(例如註解裡的非 UTF-8 文字)不該讓整個檔案讀不出來。
fn host_name_in_files(files: &[PathBuf], host_key: &KeyData) -> Option<String> {
    files
        .iter()
        .filter_map(|path| std::fs::read(path).ok())
        .find_map(|bytes| broker::host_name_in(&String::from_utf8_lossy(&bytes), host_key))
}

/// 開 agent(SSHelter 的視窗程式啟動時,含 `--mcp-host`;`--mcp` 的 stdio 轉接不建 Tauri,不會到這裡)。開不起來只記下原因(spec §11),
/// SSHelter 其他功能照常。
pub fn start(app: &tauri::AppHandle) {
    // 記住的核准與解開的私鑰到期就丟掉(spec §5.5),不等下一個請求;agent 開不起來也照做(Connect 的一次性通道仍會用到 broker)。
    let janitor = app.clone();
    let _ = std::thread::Builder::new().name("sshelter-agent-expire".to_string()).spawn(move || loop {
        std::thread::sleep(std::time::Duration::from_secs(60));
        janitor.state::<AppState>().agent.broker.expire(SystemClock.now_ms());
    });
    let status = match listen(app) {
        Ok(server::Started::Running) => AgentStatus::Running,
        Ok(server::Started::OtherInstance) => AgentStatus::OtherInstance,
        Err(e) => {
            eprintln!("[agent] not started: {e}");
            AgentStatus::Failed(e.to_string())
        }
    };
    *app.state::<AppState>().agent.status.lock().unwrap() = status;
}

fn listen(app: &tauri::AppHandle) -> Result<server::Started, AppError> {
    let ssh_dir = crate::keys::ssh_dir()?;
    let home = ssh_dir.parent().ok_or_else(|| AppError::Other("cannot determine home directory".to_string()))?;
    let dir = agent_dir(home);
    let app = app.clone();
    let handle: server::Handler = std::sync::Arc::new(move |mut stream, pid| {
        let program = pid.and_then(|pid| peer::identify(&peer::process_chain(pid)));
        let host = AppAgentHost { app: app.clone() };
        let state = app.state::<AppState>();
        let connection = broker::Connection { broker: &state.agent.broker, host: &host, program, grant: None };
        if let Err(e) = session::serve(&mut stream, &connection) {
            eprintln!("[agent] connection closed: {e}");
        }
    });
    #[cfg(unix)]
    {
        server::listen_unix(&dir, handle)
    }
    #[cfg(windows)]
    {
        pipe_windows::listen(&dir, &pipe_windows::pipe_name()?, handle)
    }
}

/// 「Keys used by synced hosts」上方的提示(spec §6、§11)。
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize)]
#[cfg_attr(test, derive(ts_rs::TS))]
#[cfg_attr(test, ts(export, export_to = "../../src/bindings/"))]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum AgentProblem {
    /// agent 開不起來:用保管庫金鑰的主機暫時連不上。
    NotRunning { reason: String },
    /// 用到保管庫金鑰的主機接不到 agent:`~/.ssh/config` 沒有 `agent/config` 的 Include(使用者拿掉了,或第一次一直放不進去,`agent/config` 還沒寫),或載入的不是預設的 config。
    IncludeMissing,
}

/// 要顯示的提示:agent 開不起來優先,其次是 Include 不見了。另一個 SSHelter 在提供不算問題。
pub fn problem(status: &AgentStatus, wiring: wiring::WiringStatus) -> Option<AgentProblem> {
    if let AgentStatus::Failed(reason) = status {
        return Some(AgentProblem::NotRunning { reason: reason.clone() });
    }
    (wiring == wiring::WiringStatus::IncludeMissing).then_some(AgentProblem::IncludeMissing)
}

/// 使用者的家目錄(`~/.ssh` 的上一層)。
pub(crate) fn home_dir() -> Result<PathBuf, AppError> {
    let ssh_dir = crate::keys::ssh_dir()?;
    ssh_dir.parent().map(Path::to_path_buf).ok_or_else(|| AppError::Other("cannot determine home directory".to_string()))
}

fn current_problem(state: &AppState) -> Result<Option<AgentProblem>, AppError> {
    let home = home_dir()?;
    let wiring = {
        // doc → core,同 `config/commands.rs` 的順序。
        let doc_lock = state.doc.lock().unwrap();
        let vault_files =
            state.sync.core.lock().unwrap().state.as_ref().map(crate::sync::slots::vault_slot_files).unwrap_or_default();
        doc_lock.as_ref().map_or(wiring::WiringStatus::NotNeeded, |doc| wiring::status(doc, &home, &vault_files))
    };
    let status = state.agent.status.lock().unwrap().clone();
    Ok(problem(&status, wiring))
}

#[tauri::command]
pub fn agent_problem(state: tauri::State<AppState>) -> Result<Option<AgentProblem>, AppError> {
    current_problem(&state)
}

/// Fix:把 Include 放回 `~/.ssh/config` 的第一行,連同 `agent/config` 一起補齊(`wiring::fix_env`),回傳之後的提示。錯誤回給畫面(Fix 的 toast)。
#[tauri::command]
pub fn agent_fix_include(app: tauri::AppHandle, state: tauri::State<AppState>) -> Result<Option<AgentProblem>, AppError> {
    crate::sync::engine::with_env(&app, wiring::fix_env).and_then(|fixed| fixed)?;
    current_problem(&state)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agent::wiring::WiringStatus;
    use crate::sync::slot_rules::test_keys;
    use crate::vault::material::public_key_data;

    #[test]
    fn a_failed_agent_comes_first_and_another_instance_is_fine() {
        assert_eq!(
            problem(&AgentStatus::Failed("path too long".into()), WiringStatus::IncludeMissing),
            Some(AgentProblem::NotRunning { reason: "path too long".into() })
        );
        assert_eq!(
            problem(&AgentStatus::Failed("path too long".into()), WiringStatus::Ready),
            Some(AgentProblem::NotRunning { reason: "path too long".into() }),
            "a failed agent is a problem however well ssh is wired"
        );
        assert_eq!(problem(&AgentStatus::Running, WiringStatus::IncludeMissing), Some(AgentProblem::IncludeMissing));
        assert_eq!(problem(&AgentStatus::NotStarted, WiringStatus::IncludeMissing), Some(AgentProblem::IncludeMissing));
        assert_eq!(problem(&AgentStatus::OtherInstance, WiringStatus::Ready), None);
        assert_eq!(problem(&AgentStatus::Running, WiringStatus::NotNeeded), None);
    }

    /// 這台的設定讀不到時,往嚴格的一邊退:記住的核准不能在沒有視窗的情況下簽章,而更嚴的設定(`always_ask`)正好讀不到。
    #[test]
    fn settings_that_cannot_be_read_ask_every_time() {
        let readable = AgentSettings { remember_minutes: 60, always_ask: false };
        assert_eq!(settings_or_ask_every_time(Ok(readable.clone())), readable, "readable settings are used as they are");

        let unreadable = settings_or_ask_every_time(Err(AppError::Other("the vault file is unreadable".to_string())));
        assert!(unreadable.always_ask, "unreadable settings must not let a remembered approval sign without a prompt");
        assert_eq!(unreadable.remember_minutes, AgentSettings::default().remember_minutes);
    }

    /// 以位元組讀、不合法的 UTF-8 換成 U+FFFD:一個壞掉的位元組不該讓整個 known_hosts 讀不出來;前面的檔案優先,讀不到的檔案跳過。
    #[test]
    fn a_bad_byte_does_not_hide_a_known_hosts_file() {
        let dir = tempfile::tempdir().unwrap();
        let key = public_key_data(test_keys::ECDSA_PUBLIC).unwrap();
        let mut with_bad_bytes = b"# caf\xe9 \xff\n".to_vec();
        with_bad_bytes.extend_from_slice(format!("web {}\n", test_keys::ECDSA_PUBLIC).as_bytes());
        let first = dir.path().join("known_hosts");
        std::fs::write(&first, with_bad_bytes).unwrap();
        let system = dir.path().join("ssh_known_hosts");
        std::fs::write(&system, format!("lab {}\n", test_keys::ECDSA_PUBLIC)).unwrap();
        let other_key = dir.path().join("other");
        std::fs::write(&other_key, format!("elsewhere {}\n", test_keys::PLAIN_PUBLIC)).unwrap();
        let missing = dir.path().join("missing");

        let name = |files: &[&PathBuf]| host_name_in_files(&files.iter().map(|f| (*f).clone()).collect::<Vec<_>>(), &key);
        assert_eq!(name(&[&missing, &first, &system]).as_deref(), Some("web"), "the bad bytes hide nothing, and the earlier file wins");
        assert_eq!(name(&[&other_key, &system]).as_deref(), Some("lab"), "a file that does not know the key is passed over");
        assert_eq!(name(&[&missing, &other_key]), None);
    }
}
