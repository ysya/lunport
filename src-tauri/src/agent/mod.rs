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

    fn private_key(&self, slot_id: &str) -> Result<Option<Zeroizing<String>>, AppError> {
        let result = crate::sync::engine::with_env(&self.app, |env| {
            with_vault(env.runtime, &vault_path(&env.state_path), env.keychain, env.now(), |vault| vault.get(slot_id))
                .map(|entry| entry.map(|entry| Zeroizing::new(entry.private_key.clone())))
                .map_err(AppError::from)
        })
        .and_then(|inner| inner);
        // 使用者按了允許,金鑰卻拿不出來(keychain 鎖著、保管庫讀不懂):broker 只會拒絕,原因記在這裡。
        if let Err(e) = &result {
            eprintln!("[agent] cannot read the key from SSHelter's vault: {e}");
        }
        result
    }

    fn settings(&self) -> AgentSettings {
        crate::sync::engine::with_env(&self.app, |env| {
            with_vault(env.runtime, &vault_path(&env.state_path), env.keychain, env.now(), |vault| Ok(vault.settings().clone()))
        })
        .ok()
        .and_then(Result::ok)
        .unwrap_or_default()
    }

    fn keychain(&self) -> &dyn Keychain {
        &OsKeychain
    }

    fn now_ms(&self) -> u64 {
        SystemClock.now_ms()
    }

    fn host_name(&self, host_key: &KeyData) -> Option<String> {
        let mut files = Vec::new();
        if let Ok(ssh_dir) = crate::keys::ssh_dir() {
            files.push(ssh_dir.join("known_hosts"));
        }
        #[cfg(unix)]
        files.push(PathBuf::from("/etc/ssh/ssh_known_hosts"));
        files.iter().filter_map(|path| std::fs::read_to_string(path).ok()).find_map(|text| broker::host_name_in(&text, host_key))
    }

    fn ask(&self, request: prompt::AgentApprovalRequest) -> Option<prompt::AgentApprovalAnswer> {
        let surface = prompt::TauriPromptSurface { app: self.app.clone() };
        self.app.state::<AppState>().agent.prompts.ask(&surface, request, prompt::APPROVAL_TIMEOUT)
    }
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
