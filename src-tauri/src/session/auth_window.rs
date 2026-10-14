//! Request-scoped native authentication. Answers never enter IPC, events, state or logs.
use super::{
    auth::{printable, Owner, Reply},
    connect::CancelToken,
    protocol::QuestionKind,
};
use crate::error::AppError;
use serde::{Deserialize, Serialize};
use std::sync::{
    atomic::{AtomicU64, Ordering},
    mpsc, Arc, Mutex,
};
use std::time::{Duration, Instant};
use zeroize::Zeroizing;

pub const AUTH_WINDOW: &str = "authentication";
pub const AUTH_EVENT: &str = "authentication://requests";
#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(test, derive(ts_rs::TS))]
#[cfg_attr(test, ts(export, export_to = "../../src/bindings/"))]
pub struct AuthRequest {
    pub id: String,
    pub request_id: String,
    pub hop: Option<AuthHop>,
    pub kind: String,
    pub text: String,
    pub echo: bool,
    #[cfg_attr(test, ts(type = "number"))]
    pub remaining_ms: u64,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(test, derive(ts_rs::TS))]
#[cfg_attr(test, ts(export, export_to = "../../src/bindings/"))]
pub struct AuthHop {
    pub host_id: String,
    pub alias: String,
    pub hostname: String,
    pub user: String,
    pub port: u16,
}
impl From<&crate::ssh::HopRef> for AuthHop {
    fn from(h: &crate::ssh::HopRef) -> Self {
        Self {
            host_id: h.id.as_str().into(),
            alias: printable(&h.alias),
            hostname: printable(&h.hostname),
            user: printable(&h.user),
            port: h.port,
        }
    }
}
pub trait AuthSurface: Send + Sync {
    fn changed(&self, requests: &[AuthRequest]);
}
struct Waiting {
    request: AuthRequest,
    deadline: Instant,
    answer: mpsc::SyncSender<Reply>,
}
#[derive(Default)]
pub struct AuthHub {
    pending: Mutex<Vec<Waiting>>,
    next: AtomicU64,
    notify: Mutex<()>,
}
impl AuthHub {
    pub fn pending(&self) -> Vec<AuthRequest> {
        self.pending
            .lock()
            .unwrap()
            .iter()
            .map(|w| {
                let mut request = w.request.clone();
                request.remaining_ms = w
                    .deadline
                    .saturating_duration_since(Instant::now())
                    .as_millis() as u64;
                request
            })
            .collect()
    }
    fn publish(&self, surface: &dyn AuthSurface) {
        let _order = self.notify.lock().unwrap();
        surface.changed(&self.pending());
    }
    pub fn deny_all(&self) {
        for w in self.pending.lock().unwrap().drain(..) {
            let _ = w.answer.try_send(Reply::Cancelled);
        }
    }
    pub fn resolve(&self, id: &str, value: Option<Zeroizing<String>>) -> Result<(), AppError> {
        if value.as_ref().is_some_and(|s| s.len() > 16384) {
            return Err(AppError::Other("Authentication answer is too long.".into()));
        }
        let mut p = self.pending.lock().unwrap();
        let i = p
            .iter()
            .position(|w| w.request.id == id)
            .ok_or_else(|| AppError::NotFound("Authentication question expired.".into()))?;
        p.remove(i)
            .answer
            .try_send(value.map(Reply::Answer).unwrap_or(Reply::Cancelled))
            .map_err(|_| AppError::Other("Authentication request ended.".into()))
    }
}
/// Reusable for human deployment: construct with its own request ID and cancellation token; no MCP policy is consulted.
pub struct NativeOwner {
    pub hub: Arc<AuthHub>,
    pub surface: Arc<dyn AuthSurface>,
    pub request_id: String,
    pub cancel: CancelToken,
}
impl NativeOwner {
    fn ask_context(
        &self,
        hop: Option<AuthHop>,
        kind: QuestionKind,
        text: &str,
        echo: bool,
        deadline: Option<Instant>,
    ) -> Reply {
        if self.cancel.is_cancelled() {
            return Reply::Gone;
        }
        let deadline = deadline
            .unwrap_or_else(|| Instant::now() + Duration::from_secs(120))
            .min(Instant::now() + Duration::from_secs(120));
        if deadline <= Instant::now() {
            return Reply::TimedOut;
        }
        let id = format!("auth-{}", self.hub.next.fetch_add(1, Ordering::Relaxed));
        let (tx, rx) = mpsc::sync_channel(1);
        let request = AuthRequest {
            id: id.clone(),
            request_id: self.request_id.clone(),
            hop,
            kind: match kind {
                QuestionKind::Passphrase => "passphrase",
                QuestionKind::Password => "password",
                QuestionKind::Interactive => "interactive",
                QuestionKind::HostKeyNotice => return Reply::Gone,
            }
            .into(),
            text: printable(text).chars().take(4096).collect(),
            echo,
            remaining_ms: deadline
                .saturating_duration_since(Instant::now())
                .as_millis() as u64,
        };
        {
            let mut p = self.hub.pending.lock().unwrap();
            if p.len() >= 32 {
                return Reply::Gone;
            }
            p.push(Waiting {
                request,
                deadline,
                answer: tx,
            });
        }
        self.hub.publish(self.surface.as_ref());
        let answer = loop {
            if self.cancel.is_cancelled() {
                break Reply::Gone;
            }
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                break Reply::TimedOut;
            }
            match rx.recv_timeout(left.min(Duration::from_millis(50))) {
                Ok(answer) => break answer,
                Err(mpsc::RecvTimeoutError::Disconnected) => break Reply::Gone,
                Err(_) => {}
            }
        };
        self.hub
            .pending
            .lock()
            .unwrap()
            .retain(|w| w.request.id != id);
        self.hub.publish(self.surface.as_ref());
        if self.cancel.is_cancelled() {
            Reply::Gone
        } else if Instant::now() >= deadline {
            Reply::TimedOut
        } else {
            answer
        }
    }
}
impl Owner for NativeOwner {
    fn ask(&self, kind: QuestionKind, text: &str, echo: bool, deadline: Option<Instant>) -> Reply {
        self.ask_context(None, kind, text, echo, deadline)
    }
    fn ask_at(
        &self,
        hop: &crate::ssh::HopRef,
        kind: QuestionKind,
        text: &str,
        echo: bool,
        deadline: Option<Instant>,
    ) -> Reply {
        self.ask_context(Some(hop.into()), kind, text, echo, deadline)
    }
    fn host_key_notice(&self, _: &str) {}
    fn banner(&self, _: &str) {}
}
pub struct TauriAuthSurface {
    pub app: tauri::AppHandle,
}
impl AuthSurface for TauriAuthSurface {
    fn changed(&self, requests: &[AuthRequest]) {
        use tauri::{Emitter, Manager, WebviewUrl, WebviewWindowBuilder};
        if requests.is_empty() {
            if let Some(w) = self.app.get_webview_window(AUTH_WINDOW) {
                let _ = w.destroy();
            }
            return;
        }
        if self.app.get_webview_window(AUTH_WINDOW).is_none() {
            let _ = WebviewWindowBuilder::new(
                &self.app,
                AUTH_WINDOW,
                WebviewUrl::App("index.html".into()),
            )
            .title("SSHelter — Authentication")
            .inner_size(480.0, 360.0)
            .resizable(true)
            .always_on_top(true)
            .center()
            .build();
        }
        let _ = self.app.emit_to(AUTH_WINDOW, AUTH_EVENT, requests);
    }
}
#[tauri::command]
pub fn auth_pending(state: tauri::State<crate::state::AppState>) -> Vec<AuthRequest> {
    state.session.auth_questions.pending()
}
#[tauri::command]
pub fn auth_resolve(
    state: tauri::State<crate::state::AppState>,
    request_id: String,
    value: Option<String>,
) -> Result<(), AppError> {
    state
        .session
        .auth_questions
        .resolve(&request_id, value.map(Zeroizing::new))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[derive(Default)]
    struct Surface(Mutex<Vec<Vec<AuthRequest>>>);
    impl AuthSurface for Surface {
        fn changed(&self, p: &[AuthRequest]) {
            self.0.lock().unwrap().push(p.to_vec());
        }
    }
    fn wait(h: &AuthHub) {
        let end = Instant::now() + Duration::from_secs(3);
        while h.pending().is_empty() {
            assert!(Instant::now() < end);
            std::thread::sleep(Duration::from_millis(2));
        }
    }
    #[test]
    fn native_questions_bound_escape_and_cancel_all_interactive_categories() {
        for kind in [
            QuestionKind::Password,
            QuestionKind::Passphrase,
            QuestionKind::Interactive,
        ] {
            let hub = Arc::new(AuthHub::default());
            let surface = Arc::new(Surface::default());
            let cancel = CancelToken::default();
            let owner = NativeOwner {
                hub: hub.clone(),
                surface: surface.clone(),
                request_id: "request-hop-context".into(),
                cancel: cancel.clone(),
            };
            let worker = std::thread::spawn(move || {
                owner.ask(kind, "(user@hop) prompt\u{1b}\u{202e}", true, None)
            });
            wait(&hub);
            let q = hub.pending().remove(0);
            assert_eq!(q.request_id, "request-hop-context");
            assert!(q.echo);
            assert!(!q.text.contains('\u{1b}'));
            assert!(q.remaining_ms <= 120000);
            cancel.cancel();
            assert!(matches!(worker.join().unwrap(), Reply::Gone));
            assert!(hub.pending().is_empty());
            assert!(hub
                .resolve(&q.id, Some(Zeroizing::new("AUTH_SENTINEL".into())))
                .is_err());
            assert!(!format!("{:?}", surface.0.lock().unwrap()).contains("AUTH_SENTINEL"));
        }
    }
    #[test]
    fn native_answer_is_consumed_once_and_timeout_never_reuses_it() {
        let hub = Arc::new(AuthHub::default());
        let owner = NativeOwner {
            hub: hub.clone(),
            surface: Arc::new(Surface::default()),
            request_id: "request".into(),
            cancel: CancelToken::default(),
        };
        let worker =
            std::thread::spawn(move || owner.ask(QuestionKind::Password, "Password:", false, None));
        wait(&hub);
        let id = hub.pending()[0].id.clone();
        hub.resolve(&id, Some(Zeroizing::new("AUTH_SENTINEL".into())))
            .unwrap();
        assert!(matches!(worker.join().unwrap(),Reply::Answer(s) if s.as_str()=="AUTH_SENTINEL"));
        assert!(hub.resolve(&id, None).is_err());
        let owner = NativeOwner {
            hub: hub.clone(),
            surface: Arc::new(Surface::default()),
            request_id: "next".into(),
            cancel: CancelToken::default(),
        };
        assert!(matches!(
            owner.ask(
                QuestionKind::Password,
                "Password:",
                false,
                Some(Instant::now())
            ),
            Reply::TimedOut
        ));
        assert!(hub.pending().is_empty());
    }
}

#[cfg(test)]
mod attribution_tests {
    use super::*;
    struct Surface;
    impl AuthSurface for Surface {
        fn changed(&self, _: &[AuthRequest]) {}
    }
    #[test]
    fn passphrase_question_carries_trusted_hop_separately_from_server_text() {
        let hub = Arc::new(AuthHub::default());
        let owner = NativeOwner {
            hub: hub.clone(),
            surface: Arc::new(Surface),
            request_id: "deployment-or-mcp-request".into(),
            cancel: CancelToken::default(),
        };
        let hop = crate::ssh::Hop::new(
            "id-jump",
            "jump",
            "jump.example",
            2222,
            "ops",
            crate::ssh::AuthMethod::Password,
        )
        .reference();
        let worker = std::thread::spawn(move || {
            owner.ask_at(
                &hop,
                QuestionKind::Passphrase,
                "key name claims root@other",
                false,
                None,
            )
        });
        let deadline = Instant::now() + Duration::from_secs(3);
        while hub.pending().is_empty() {
            assert!(Instant::now() < deadline);
            std::thread::sleep(Duration::from_millis(2));
        }
        let question = hub.pending().remove(0);
        let h = question.hop.unwrap();
        assert_eq!(
            (
                h.host_id.as_str(),
                h.alias.as_str(),
                h.hostname.as_str(),
                h.user.as_str(),
                h.port
            ),
            ("id-jump", "jump", "jump.example", "ops", 2222)
        );
        hub.resolve(&question.id, None).unwrap();
        assert!(matches!(worker.join().unwrap(), Reply::Cancelled));
    }
}
