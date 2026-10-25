//! Request-scoped native authentication. Answers never enter IPC, events, state or logs.
use super::{
    auth::{printable, Owner, Reply},
    connect::CancelToken,
    deadline::InteractionDeadline,
    protocol::{GrantPrompt, QuestionKind},
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
    /// The form of a `grant` question (design 2026-10-25, PAM grant requests); `None` for every other kind.
    #[serde(default)]
    pub grant: Option<GrantPrompt>,
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
    deadline: InteractionDeadline,
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
                request.remaining_ms = w.deadline.remaining().as_millis() as u64;
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
        let waiting = p.remove(i);
        if waiting.deadline.expired() {
            let _ = waiting.answer.try_send(Reply::TimedOut);
            return Err(AppError::NotFound(
                "Authentication question expired.".into(),
            ));
        }
        waiting
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
        // A server's question waits two minutes; a grant request is Lunport's own and the person may be away from the window.
        let cap = Duration::from_secs(if kind == QuestionKind::Grant { 300 } else { 120 });
        let deadline = deadline.unwrap_or_else(|| Instant::now() + cap).min(Instant::now() + cap);
        let deadline = InteractionDeadline::from_instant(deadline);
        if deadline.expired() {
            return Reply::TimedOut;
        }
        let id = format!("auth-{}", self.hub.next.fetch_add(1, Ordering::Relaxed));
        let (tx, rx) = mpsc::sync_channel(1);
        let (word, text, grant) = match kind {
            QuestionKind::Passphrase => ("passphrase", text.to_string(), None),
            QuestionKind::Password => ("password", text.to_string(), None),
            QuestionKind::Interactive => ("interactive", text.to_string(), None),
            QuestionKind::Grant => {
                // The window shows the sentence and the form; the prompt itself is Lunport's own data.
                let prompt = GrantPrompt::from_text(text);
                (
                    "grant",
                    prompt.as_ref().map(GrantPrompt::sentence).unwrap_or_else(|| text.to_string()),
                    prompt,
                )
            }
            QuestionKind::HostKeyNotice => return Reply::Gone,
        };
        let request = AuthRequest {
            id: id.clone(),
            request_id: self.request_id.clone(),
            hop,
            kind: word.into(),
            text: printable(&text).chars().take(4096).collect(),
            echo,
            remaining_ms: deadline.remaining().as_millis() as u64,
            grant,
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
        let answer = receive_answer(&rx, &self.cancel, deadline, &|| {
            (Instant::now(), std::time::SystemTime::now())
        });
        self.hub
            .pending
            .lock()
            .unwrap()
            .retain(|w| w.request.id != id);
        self.hub.publish(self.surface.as_ref());
        if self.cancel.is_cancelled() {
            Reply::Gone
        } else if deadline.expired() {
            Reply::TimedOut
        } else {
            answer
        }
    }
}
fn receive_answer(
    rx: &mpsc::Receiver<Reply>,
    cancel: &CancelToken,
    deadline: InteractionDeadline,
    now: &dyn Fn() -> (Instant, std::time::SystemTime),
) -> Reply {
    loop {
        if cancel.is_cancelled() {
            return Reply::Gone;
        }
        let (monotonic, utc) = now();
        let left = deadline.remaining_at(monotonic, utc);
        if left.is_zero() {
            return Reply::TimedOut;
        }
        match rx.recv_timeout(left.min(Duration::from_millis(50))) {
            Ok(answer) => {
                let (monotonic, utc) = now();
                return if deadline.remaining_at(monotonic, utc).is_zero() {
                    Reply::TimedOut
                } else if cancel.is_cancelled() {
                    Reply::Gone
                } else {
                    answer
                };
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => return Reply::Gone,
            Err(_) => {}
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
        #[cfg(target_os = "macos")]
        {
            use tauri::Manager;
            if requests.is_empty() {
                if let Some(window) = self.app.get_webview_window(AUTH_WINDOW) {
                    let _ = window.destroy();
                }
            } else {
                crate::macos_health::request(&self.app, crate::macos_health::Surface::Authentication);
            }
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = requests;
            present(&self.app);
        }
    }
}

/// Read the current hub after the health check; never replay an expired snapshot.
/// The window's logical size for what is pending: a server's one-line question fits the small window; the Request-a-grant form (two
/// fields and a hint; design 2026-10-25, PAM grant requests) gets a taller one when a grant question is anywhere in the queue.
pub(crate) fn window_size(requests: &[AuthRequest]) -> (f64, f64) {
    if requests.iter().any(|request| request.kind == "grant") {
        (520.0, 500.0)
    } else {
        (480.0, 360.0)
    }
}

pub(crate) fn present(app: &tauri::AppHandle) {
    use tauri::Manager;
    let requests = app.state::<crate::state::AppState>().session.auth_questions.pending();

    use tauri::{Emitter, WebviewUrl, WebviewWindowBuilder};
    if requests.is_empty() {
        if let Some(w) = app.get_webview_window(AUTH_WINDOW) {
            let _ = w.destroy();
        }
        return;
    }
    let (width, height) = window_size(&requests);
    if let Some(window) = app.get_webview_window(AUTH_WINDOW) {
        // A window already open for a smaller question grows for a grant form; it is never shrunk under the person.
        if let (Ok(size), Ok(scale)) = (window.inner_size(), window.scale_factor()) {
            let current = size.to_logical::<f64>(scale);
            if current.height < height {
                let _ = window.set_size(tauri::LogicalSize::new(current.width.max(width), height));
            }
        }
    } else {
        match WebviewWindowBuilder::new(
            app,
            AUTH_WINDOW,
            WebviewUrl::App("index.html".into()),
        )
        .title("Lunport — Authentication")
        .inner_size(width, height)
        .resizable(true)
        .always_on_top(true)
        .visible(false)
        .build()
        {
            Ok(window) => crate::prompt_window::show(&window),
            Err(error) => eprintln!("[session] cannot open the authentication window: {error}"),
        }
    }
    let _ = app.emit_to(AUTH_WINDOW, AUTH_EVENT, &requests);
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
    /// The window was sized for a server's one-line question; the Request-a-grant form (two fields and a hint) needs more room, so a
    /// grant anywhere in the queue gets the taller window (design 2026-10-25, PAM grant requests).
    #[test]
    fn the_window_is_taller_for_a_grant_form_than_for_a_servers_question() {
        let password = AuthRequest { id: "a".into(), request_id: "r".into(), hop: None, kind: "password".into(), text: "pw".into(), echo: false, remaining_ms: 1, grant: None };
        let grant = AuthRequest { kind: "grant".into(), ..password.clone() };
        assert_eq!(window_size(&[]), (480.0, 360.0));
        assert_eq!(window_size(&[password.clone()]), (480.0, 360.0));
        assert_eq!(window_size(&[grant.clone()]), (520.0, 500.0));
        assert_eq!(window_size(&[password, grant]), (520.0, 500.0), "a grant anywhere in the queue gets the room");
    }

    #[test]
    fn a_grant_question_carries_its_prompt_and_waits_five_minutes() {
        use crate::session::protocol::GrantAnswer;
        let hub = Arc::new(AuthHub::default());
        let owner = NativeOwner { hub: hub.clone(), surface: Arc::new(Surface::default()), request_id: "terminal-7".into(), cancel: CancelToken::default() };
        let prompt = GrantPrompt { project: "knowknow-prod".into(), entitlement: "prod-operate".into(), minutes: 30, justification: Some("restart app-api".into()) };
        let text = prompt.to_text();
        let worker = std::thread::spawn(move || owner.ask(QuestionKind::Grant, &text, true, Some(Instant::now() + Duration::from_secs(3600))));
        wait(&hub);
        let q = hub.pending().remove(0);
        assert_eq!(q.kind, "grant");
        assert_eq!(q.grant, Some(prompt));
        assert_eq!(q.text, "No active Privileged Access Manager grant for prod-operate on knowknow-prod.");
        assert!(q.remaining_ms > 120_000 && q.remaining_ms <= 300_000, "a grant question waits five minutes, not two: {}ms", q.remaining_ms);
        let answer = GrantAnswer { minutes: 45, justification: "restart app-api after the deploy".into() };
        hub.resolve(&q.id, Some(Zeroizing::new(answer.encode()))).unwrap();
        match worker.join().unwrap() {
            Reply::Answer(secret) => assert_eq!(GrantAnswer::decode(&secret), Some(answer)),
            other => panic!("expected the answer, got {other:?}"),
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

#[cfg(test)]
mod expiry_tests {
    use super::*;
    #[test]
    fn expired_auth_deadline_rejects_answer_before_reporting_success() {
        let hub = AuthHub::default();
        let (tx, rx) = mpsc::sync_channel(1);
        hub.pending.lock().unwrap().push(Waiting {
            request: AuthRequest {
                id: "expired".into(),
                request_id: "request".into(),
                hop: None,
                kind: "password".into(),
                text: "Password".into(),
                echo: false,
                remaining_ms: 0,
                grant: None,
            },
            deadline: InteractionDeadline::from_instant(Instant::now() - Duration::from_secs(1)),
            answer: tx,
        });
        assert!(hub
            .resolve(
                "expired",
                Some(Zeroizing::new("EXPIRED_SECRET_SENTINEL".into()))
            )
            .is_err());
        assert!(!matches!(rx.try_recv(), Ok(Reply::Answer(_))));
        assert!(hub.pending().is_empty());
    }
    fn wall_expired_question() -> (AuthHub, mpsc::Receiver<Reply>) {
        let hub = AuthHub::default();
        let (tx, rx) = mpsc::sync_channel(1);
        hub.pending.lock().unwrap().push(Waiting {
            request: AuthRequest {
                id: "wall-expired".into(),
                request_id: "request".into(),
                hop: None,
                kind: "password".into(),
                text: "Password".into(),
                echo: false,
                remaining_ms: 120000,
                grant: None,
            },
            deadline: InteractionDeadline {
                monotonic: Instant::now() + Duration::from_secs(120),
                utc: std::time::SystemTime::now() - Duration::from_secs(1),
            },
            answer: tx,
        });
        (hub, rx)
    }
    #[test]
    fn wall_expiry_rejects_secret_with_live_monotonic_deadline() {
        let (hub, rx) = wall_expired_question();
        assert!(hub
            .resolve(
                "wall-expired",
                Some(Zeroizing::new("EXPIRED_SECRET_SENTINEL".into()))
            )
            .is_err());
        assert!(!matches!(rx.try_recv(), Ok(Reply::Answer(_))));
    }
    #[test]
    fn wall_expiry_reports_zero_remaining_with_live_monotonic_deadline() {
        let (hub, _rx) = wall_expired_question();
        assert_eq!(hub.pending()[0].remaining_ms, 0);
    }
    #[test]
    fn wall_expiry_discards_queued_secret_after_clock_advances() {
        let (tx, rx) = mpsc::sync_channel(1);
        tx.send(Reply::Answer(Zeroizing::new(
            "EXPIRED_SECRET_SENTINEL".into(),
        )))
        .unwrap();
        let now = Instant::now();
        let utc = std::time::SystemTime::now();
        let calls = AtomicU64::new(0);
        let deadline = InteractionDeadline {
            monotonic: now + Duration::from_secs(120),
            utc: utc + Duration::from_secs(120),
        };
        let answer = receive_answer(&rx, &CancelToken::default(), deadline, &|| {
            (
                now,
                if calls.fetch_add(1, Ordering::SeqCst) == 0 {
                    utc
                } else {
                    utc + Duration::from_secs(121)
                },
            )
        });
        assert!(matches!(answer, Reply::TimedOut));
    }
}
