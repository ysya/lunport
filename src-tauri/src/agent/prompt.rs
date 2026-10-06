//! 核准視窗與等待中的請求(spec §5.3、§7.4)。agent 的連線執行緒呼叫 `PromptHub::ask` 等待答案(最多 60 秒;伺服器預設 120 秒內
//! 沒完成認證就斷線);核准視窗(標籤 `approval`)用 `agent_pending` 取得請求、用 `agent_resolve` 回答。

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{mpsc, Mutex};
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::error::AppError;

pub const APPROVAL_WINDOW: &str = "approval";
pub const APPROVAL_TIMEOUT: Duration = Duration::from_secs(60);
pub const APPROVALS_EVENT: &str = "agent://approvals";

/// 一個等待回答的請求。顯示用的字串(程式、使用者、主機)來自別的程式或伺服器,前端一律經 `revealHidden` 顯示。
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(test, derive(ts_rs::TS))]
#[cfg_attr(test, ts(export, export_to = "../../src/bindings/"))]
pub struct AgentApprovalRequest {
    pub id: String,
    pub key_name: String,
    pub key_fingerprint: String,
    /// 發出請求的程式,由外到內(例如 `["claude", "zsh", "ssh"]`);空 = 認不出來。
    pub program_chain: Vec<String>,
    pub user: Option<String>,
    /// 顯示用的主機:known_hosts 裡的名稱,找不到名稱就是主機金鑰的指紋;None = 未知的主機(這條連線沒有可信的 session-bind)。
    pub host: Option<String>,
    pub host_fingerprint: Option<String>,
    /// 視窗可以提供「記住」(spec §5.3)。
    pub rememberable: bool,
    pub remember_minutes: u32,
    pub needs_passphrase: bool,
    /// 上一次輸入的 passphrase 不對時的說明。
    pub passphrase_error: Option<String>,
    /// 已經核准,只需要 passphrase:從 SSHelter 按 Connect(spec §5.6),或剛允許了、記住的 passphrase 卻不對、或上一次輸入的不對。
    pub preapproved: bool,
}

/// 視窗的回答。
#[derive(Clone, Default, PartialEq, Serialize, Deserialize)]
#[cfg_attr(test, derive(ts_rs::TS))]
#[cfg_attr(test, ts(export, export_to = "../../src/bindings/"))]
pub struct AgentApprovalAnswer {
    pub allow: bool,
    pub remember: bool,
    pub passphrase: Option<String>,
    pub remember_passphrase: bool,
}

impl std::fmt::Debug for AgentApprovalAnswer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AgentApprovalAnswer")
            .field("allow", &self.allow)
            .field("remember", &self.remember)
            .field("passphrase", &self.passphrase.as_ref().map(|_| "<hidden>"))
            .field("remember_passphrase", &self.remember_passphrase)
            .finish()
    }
}

/// 等待中的請求變了(新增或回答)時通知畫面:production 打開或更新核准視窗,沒有請求時關掉它(`TauriPromptSurface`)。
pub trait PromptSurface: Send + Sync {
    fn changed(&self, pending: &[AgentApprovalRequest]);
}

struct Waiting {
    request: AgentApprovalRequest,
    answer: mpsc::SyncSender<AgentApprovalAnswer>,
}

/// 等待中的請求(依到達順序)。
#[derive(Default)]
pub struct PromptHub {
    pending: Mutex<Vec<Waiting>>,
    next_id: AtomicU64,
}

impl PromptHub {
    /// 送出請求並等待回答。逾時回 None(呼叫端當成拒絕)。`request.id` 由這裡指定。
    pub fn ask(&self, surface: &dyn PromptSurface, mut request: AgentApprovalRequest, timeout: Duration) -> Option<AgentApprovalAnswer> {
        let id = format!("approval-{}", self.next_id.fetch_add(1, Ordering::Relaxed) + 1);
        request.id = id.clone();
        let (tx, rx) = mpsc::sync_channel(1);
        let shown = {
            let mut pending = self.pending.lock().unwrap();
            pending.push(Waiting { request, answer: tx });
            pending.iter().map(|w| w.request.clone()).collect::<Vec<_>>()
        };
        surface.changed(&shown);
        let answer = rx.recv_timeout(timeout).ok();
        let left = {
            let mut pending = self.pending.lock().unwrap();
            pending.retain(|w| w.request.id != id);
            pending.iter().map(|w| w.request.clone()).collect::<Vec<_>>()
        };
        surface.changed(&left);
        answer
    }

    /// 回答一個等待中的請求。不存在、已經回答過或已逾時 → NotFound。
    pub fn resolve(&self, id: &str, answer: AgentApprovalAnswer) -> Result<(), AppError> {
        let gone = || AppError::NotFound("that request was already answered or has expired".to_string());
        let pending = self.pending.lock().unwrap();
        let waiting = pending.iter().find(|w| w.request.id == id).ok_or_else(gone)?;
        waiting.answer.try_send(answer).map_err(|_| gone())
    }

    pub fn pending(&self) -> Vec<AgentApprovalRequest> {
        self.pending.lock().unwrap().iter().map(|w| w.request.clone()).collect()
    }
}

/// production 的畫面:核准視窗是獨立的小視窗,永遠在最上層;SSHelter 縮在系統匣時也會出現(spec §7.4)。沒有請求時銷毀它
/// (`destroy` 不經過 `CloseRequested`,不會被「關閉視窗時縮到系統匣」攔下)。
pub struct TauriPromptSurface {
    pub app: tauri::AppHandle,
}

impl PromptSurface for TauriPromptSurface {
    fn changed(&self, pending: &[AgentApprovalRequest]) {
        use tauri::{Emitter, Manager, WebviewUrl, WebviewWindowBuilder};
        if pending.is_empty() {
            if let Some(window) = self.app.get_webview_window(APPROVAL_WINDOW) {
                let _ = window.destroy();
            }
            return;
        }
        let window = match self.app.get_webview_window(APPROVAL_WINDOW) {
            Some(window) => Some(window),
            None => WebviewWindowBuilder::new(&self.app, APPROVAL_WINDOW, WebviewUrl::App("index.html".into()))
                .title("SSHelter")
                .inner_size(460.0, 340.0)
                .resizable(false)
                .always_on_top(true)
                .center()
                .build()
                .ok(),
        };
        if let Some(window) = window {
            let _ = window.show();
            let _ = window.unminimize();
            let _ = window.set_focus();
        }
        let _ = self.app.emit(APPROVALS_EVENT, pending);
    }
}

#[tauri::command]
pub fn agent_pending(state: tauri::State<crate::state::AppState>) -> Vec<AgentApprovalRequest> {
    state.agent.prompts.pending()
}

#[tauri::command]
pub fn agent_resolve(
    state: tauri::State<crate::state::AppState>,
    request_id: String,
    answer: AgentApprovalAnswer,
) -> Result<(), AppError> {
    state.agent.prompts.resolve(&request_id, answer)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    #[derive(Default)]
    struct Recorder {
        seen: Mutex<Vec<Vec<String>>>,
    }

    impl PromptSurface for Recorder {
        fn changed(&self, pending: &[AgentApprovalRequest]) {
            self.seen.lock().unwrap().push(pending.iter().map(|r| r.id.clone()).collect());
        }
    }

    fn request(key: &str) -> AgentApprovalRequest {
        AgentApprovalRequest {
            id: String::new(),
            key_name: key.into(),
            key_fingerprint: "SHA256:k".into(),
            program_chain: vec!["claude".into(), "ssh".into()],
            user: Some("root".into()),
            host: Some("web".into()),
            host_fingerprint: Some("SHA256:h".into()),
            rememberable: true,
            remember_minutes: 240,
            needs_passphrase: false,
            passphrase_error: None,
            preapproved: false,
        }
    }

    #[test]
    fn an_answer_reaches_the_waiting_request_and_the_window_is_told_both_times() {
        let hub = Arc::new(PromptHub::default());
        let surface = Arc::new(Recorder::default());
        let (h, s) = (Arc::clone(&hub), Arc::clone(&surface));
        let waiter = std::thread::spawn(move || h.ask(s.as_ref(), request("id_mac"), Duration::from_secs(5)));
        let id = loop {
            if let Some(r) = hub.pending().first() {
                break r.id.clone();
            }
            std::thread::sleep(Duration::from_millis(5));
        };
        hub.resolve(&id, AgentApprovalAnswer { allow: true, remember: true, ..Default::default() }).unwrap();
        let answer = waiter.join().unwrap().unwrap();
        assert!(answer.allow && answer.remember);
        assert!(hub.pending().is_empty());
        let seen = surface.seen.lock().unwrap().clone();
        assert_eq!(seen, vec![vec![id.clone()], vec![]], "shown with the request, then told it is gone");
    }

    #[test]
    fn a_request_nobody_answers_times_out_as_none() {
        let hub = PromptHub::default();
        let surface = Recorder::default();
        assert_eq!(hub.ask(&surface, request("id_mac"), Duration::from_millis(20)), None);
        assert!(hub.pending().is_empty());
    }

    #[test]
    fn resolving_an_unknown_or_answered_request_is_not_found() {
        let hub = Arc::new(PromptHub::default());
        assert!(matches!(hub.resolve("approval-99", AgentApprovalAnswer::default()), Err(AppError::NotFound(_))));
        let h = Arc::clone(&hub);
        let waiter = std::thread::spawn(move || h.ask(&Recorder::default(), request("a"), Duration::from_secs(5)));
        let id = loop {
            if let Some(r) = hub.pending().first() {
                break r.id.clone();
            }
            std::thread::sleep(Duration::from_millis(5));
        };
        hub.resolve(&id, AgentApprovalAnswer { allow: true, ..Default::default() }).unwrap();
        let second = hub.resolve(&id, AgentApprovalAnswer::default());
        assert!(second.is_err() || hub.pending().is_empty(), "a second answer never replaces the first");
        assert!(waiter.join().unwrap().unwrap().allow);
    }

    #[test]
    fn requests_get_distinct_ids_in_arrival_order() {
        let hub = Arc::new(PromptHub::default());
        let mut waiters = Vec::new();
        for key in ["a", "b"] {
            let h = Arc::clone(&hub);
            waiters.push(std::thread::spawn(move || h.ask(&Recorder::default(), request(key), Duration::from_millis(300))));
            while hub.pending().iter().all(|r| r.key_name != key) {
                std::thread::sleep(Duration::from_millis(5));
            }
        }
        let pending = hub.pending();
        assert_eq!(pending.iter().map(|r| r.key_name.as_str()).collect::<Vec<_>>(), vec!["a", "b"]);
        assert_ne!(pending[0].id, pending[1].id);
        for w in waiters {
            assert_eq!(w.join().unwrap(), None);
        }
    }

    #[test]
    fn the_answer_debug_output_hides_the_passphrase() {
        let shown = format!("{:?}", AgentApprovalAnswer { passphrase: Some("hunter2".into()), ..Default::default() });
        assert!(!shown.contains("hunter2"));
    }
}
