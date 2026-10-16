//! Lunport's host key window (own-ssh spec §10, §14, decision 6): the broker's `HostKeyConfirmer`. A host key is confirmed only here,
//! never in a terminal: the broker's session thread asks (`HostKeyHub::ask` blocks it), a small always-on-top window labelled `hostkey`
//! shows the oldest question, and the person's answer comes back through `hostkey_resolve`. Closing the window refuses every waiting
//! question (`deny_all`, from lib.rs). The window and its hub are modelled on the SSH agent's approval window (`agent/prompt.rs`), copied
//! rather than shared because plan 1c deletes `agent/`.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{mpsc, Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use super::connect::{CancelToken, HostKeyConfirmer, HostKeyQuestion};
use crate::error::AppError;

pub const HOSTKEY_WINDOW: &str = "hostkey";
pub const HOSTKEY_EVENT: &str = "hostkey://requests";
/// How long a question waits for the person (the connection itself is not waiting: the engine failed fast, spec §6.2 step 3).
pub const HOSTKEY_TIMEOUT: Duration = Duration::from_secs(120);

/// A host key question as the window shows it. The strings come from the user's host settings and the server: the window shows them
/// through `revealHidden`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(test, derive(ts_rs::TS))]
#[cfg_attr(test, ts(export, export_to = "../../src/bindings/"))]
pub struct HostKeyRequest {
    pub id: String,
    pub alias: String,
    pub hostname: String,
    pub port: u16,
    pub algorithm: String,
    pub fingerprint: String,
    /// Set for a key that changed: the pinned one.
    pub changed: Option<PinnedHostKey>,
}

/// The pinned key a changed key replaces.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(test, derive(ts_rs::TS))]
#[cfg_attr(test, ts(export, export_to = "../../src/bindings/"))]
pub struct PinnedHostKey {
    pub fingerprint: String,
    /// When it was pinned (milliseconds since the Unix epoch). A number in the binding: it fits a JavaScript number until the year 287396.
    #[cfg_attr(test, ts(type = "number"))]
    pub pinned_at_ms: u64,
}

/// The window's answer: trust (Trust this key, Accept new key) or not (Cancel, Refuse), for the fingerprint the window showed.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(test, derive(ts_rs::TS))]
#[cfg_attr(test, ts(export, export_to = "../../src/bindings/"))]
pub struct HostKeyAnswer {
    pub trust: bool,
    pub fingerprint: String,
}

/// Told when the waiting questions change: opens, updates or closes the window. Called one at a time, each time with the latest list.
pub trait HostKeySurface: Send + Sync {
    fn changed(&self, pending: &[HostKeyRequest]);
}

struct Waiting {
    request: HostKeyRequest,
    answer: mpsc::SyncSender<HostKeyAnswer>,
    answered: bool,
}

/// The questions waiting for the person, in the order they came.
#[derive(Default)]
pub struct HostKeyHub {
    pending: Mutex<Vec<Waiting>>,
    /// Orders the notifications to the surface: taking the list and telling the surface happen under it, so the surface is told last
    /// what is pending last. Never held together with `pending` the other way round.
    notify: Mutex<()>,
    next_id: AtomicU64,
}

/// Takes the question off the list when `ask` leaves, however it leaves.
struct Leaving<'a> {
    hub: &'a HostKeyHub,
    id: &'a str,
}

impl Drop for Leaving<'_> {
    fn drop(&mut self) {
        self.hub.forget(self.id);
    }
}

impl HostKeyHub {
    /// Asks and waits for the answer, at most `timeout`, and gives up early when `cancel` is set (the client went away). `None` when
    /// nobody answered. A question withdrawn before it is asked is not asked: the window does not open for it. Blocks, and the surface may
    /// create a window: call it from a worker thread (the broker's session thread).
    pub fn ask(&self, surface: &dyn HostKeySurface, mut request: HostKeyRequest, timeout: Duration, cancel: &CancelToken) -> Option<HostKeyAnswer> {
        if cancel.is_cancelled() {
            return None;
        }
        let id = format!("hostkey-{}", self.next_id.fetch_add(1, Ordering::Relaxed) + 1);
        request.id = id.clone();
        let (answer, answered) = mpsc::sync_channel(1);
        self.pending.lock().unwrap_or_else(PoisonError::into_inner).push(Waiting { request, answer, answered: false });
        let _leave = Leaving { hub: self, id: &id };
        self.publish(surface);
        let deadline = Instant::now() + timeout;
        let mut reply = None;
        while reply.is_none() && !cancel.is_cancelled() {
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                break;
            }
            match answered.recv_timeout(left.min(Duration::from_millis(100))) {
                Ok(answer) => reply = Some(answer),
                Err(mpsc::RecvTimeoutError::Timeout) => {}
                Err(mpsc::RecvTimeoutError::Disconnected) => break,
            }
        }
        // No longer waiting: off the list first (a later `resolve` finds nothing), then one more look, so an answer that `resolve` reported
        // as taken still counts.
        self.forget(&id);
        if reply.is_none() {
            reply = answered.try_recv().ok();
        }
        self.publish(surface);
        reply
    }

    fn forget(&self, id: &str) {
        self.pending.lock().unwrap_or_else(PoisonError::into_inner).retain(|waiting| waiting.request.id != id);
    }

    fn publish(&self, surface: &dyn HostKeySurface) {
        let _order = self.notify.lock().unwrap_or_else(PoisonError::into_inner);
        let snapshot = self.pending();
        surface.changed(&snapshot);
    }

    /// Answers a waiting question. One that does not exist, was answered or gave up → NotFound.
    pub fn resolve(&self, id: &str, answer: HostKeyAnswer) -> Result<(), AppError> {
        let gone = || AppError::NotFound("that question was already answered or has expired".to_string());
        let mut pending = self.pending.lock().unwrap_or_else(PoisonError::into_inner);
        let waiting = pending.iter_mut().find(|waiting| waiting.request.id == id && !waiting.answered).ok_or_else(gone)?;
        waiting.answered = true;
        waiting.answer.try_send(answer).map_err(|_| gone())
    }

    /// The window was closed: every waiting question is refused.
    pub fn deny_all(&self) {
        for waiting in self.pending.lock().unwrap_or_else(PoisonError::into_inner).drain(..) {
            let _ = waiting.answer.try_send(HostKeyAnswer::default());
        }
    }

    /// The questions still waiting for an answer, oldest first.
    pub fn pending(&self) -> Vec<HostKeyRequest> {
        self.pending.lock().unwrap_or_else(PoisonError::into_inner).iter().filter(|waiting| !waiting.answered).map(|waiting| waiting.request.clone()).collect()
    }
}

/// The broker's `HostKeyConfirmer` over the hub and a surface.
pub struct WindowConfirmer {
    pub hub: Arc<HostKeyHub>,
    pub surface: Arc<dyn HostKeySurface>,
    pub timeout: Duration,
}

impl HostKeyConfirmer for WindowConfirmer {
    fn confirm(&self, question: &HostKeyQuestion, cancel: &CancelToken) -> Option<String> {
        let request = HostKeyRequest {
            id: String::new(),
            alias: question.alias.clone(),
            hostname: question.hostname.clone(),
            port: question.port,
            algorithm: question.algorithm.clone(),
            fingerprint: question.fingerprint.clone(),
            changed: question.changed.as_ref().map(|pinned| PinnedHostKey { fingerprint: pinned.fingerprint.clone(), pinned_at_ms: pinned.pinned_at_ms }),
        };
        let answer = self.hub.ask(self.surface.as_ref(), request, self.timeout, cancel)?;
        answer.trust.then_some(answer.fingerprint)
    }
}

/// The window last brought to the front for this head question (only one host key window exists).
static SHOWN_HEAD: Mutex<Option<String>> = Mutex::new(None);

/// Whether a new question is at the head (only then is the window brought to the front: another question timing out must not take the
/// focus from what the person is doing).
fn note_head(shown: &mut Option<String>, pending: &[HostKeyRequest]) -> bool {
    let head = pending.first().map(|request| request.id.as_str());
    let new_head = head.is_some() && shown.as_deref() != head;
    *shown = head.map(str::to_string);
    new_head
}

/// The app's surface: a small window that stays on top, shown even while Lunport sits in the tray; destroyed when nothing is pending
/// (`destroy` does not go through `CloseRequested`, so it is not taken for the person closing it).
pub struct TauriHostKeySurface {
    pub app: tauri::AppHandle,
}

impl HostKeySurface for TauriHostKeySurface {
    fn changed(&self, pending: &[HostKeyRequest]) {
        #[cfg(target_os = "macos")]
        {
            use tauri::Manager;
            if pending.is_empty() {
                *SHOWN_HEAD.lock().unwrap_or_else(std::sync::PoisonError::into_inner) = None;
                if let Some(window) = self.app.get_webview_window(HOSTKEY_WINDOW) {
                    let _ = window.destroy();
                }
            } else {
                crate::macos_health::request(&self.app, crate::macos_health::Surface::HostKey);
            }
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = pending;
            present(&self.app);
        }
    }
}

/// Read the current hub after the health check; never replay an expired snapshot.
pub(crate) fn present(app: &tauri::AppHandle) {
    use tauri::Manager;
    let pending = app.state::<crate::state::AppState>().session.host_keys.pending();

    use tauri::{Emitter, WebviewUrl, WebviewWindowBuilder};
    let new_head = note_head(&mut SHOWN_HEAD.lock().unwrap_or_else(PoisonError::into_inner), &pending);
    if pending.is_empty() {
        if let Some(window) = app.get_webview_window(HOSTKEY_WINDOW) {
            let _ = window.destroy();
        }
        return;
    }
    let (window, built) = match app.get_webview_window(HOSTKEY_WINDOW) {
        Some(window) => (Some(window), false),
        None => match WebviewWindowBuilder::new(app, HOSTKEY_WINDOW, WebviewUrl::App("index.html".into()))
            .title("Lunport")
            .inner_size(480.0, 320.0)
            .resizable(false)
            .always_on_top(true)
            .center()
            .build()
        {
            Ok(window) => (Some(window), true),
            Err(error) => {
                eprintln!("[session] cannot open the host key window: {error}");
                (None, false)
            }
        },
    };
    if let Some(window) = window {
        if built || new_head {
            let _ = window.show();
            let _ = window.unminimize();
            let _ = window.set_focus();
        }
    }
    let _ = app.emit_to(HOSTKEY_WINDOW, HOSTKEY_EVENT, &pending);
}

#[tauri::command]
pub fn hostkey_pending(state: tauri::State<crate::state::AppState>) -> Vec<HostKeyRequest> {
    state.session.host_keys.pending()
}

#[tauri::command]
pub fn hostkey_resolve(state: tauri::State<crate::state::AppState>, request_id: String, answer: HostKeyAnswer) -> Result<(), AppError> {
    state.session.host_keys.resolve(&request_id, answer)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::session::connect::PinnedSummary;

    #[derive(Default)]
    struct Recorder {
        seen: Mutex<Vec<Vec<String>>>,
    }

    impl HostKeySurface for Recorder {
        fn changed(&self, pending: &[HostKeyRequest]) {
            self.seen.lock().unwrap().push(pending.iter().map(|request| request.id.clone()).collect());
        }
    }

    fn question(alias: &str) -> HostKeyQuestion {
        HostKeyQuestion { alias: alias.into(), hostname: format!("{alias}.example.com"), port: 22, algorithm: "ssh-ed25519".into(), fingerprint: "SHA256:new".into(), changed: None }
    }

    fn wait_until(what: &str, condition: impl Fn() -> bool) {
        let deadline = Instant::now() + Duration::from_secs(5);
        while !condition() {
            assert!(Instant::now() < deadline, "timed out waiting for: {what}");
            std::thread::sleep(Duration::from_millis(2));
        }
    }

    /// The broker asks; the window shows the question; the person trusts it: the fingerprint comes back.
    #[test]
    fn a_trusted_key_comes_back_as_its_fingerprint_and_the_window_is_told_both_times() {
        let hub = Arc::new(HostKeyHub::default());
        let surface = Arc::new(Recorder::default());
        let confirmer = WindowConfirmer { hub: Arc::clone(&hub), surface: Arc::clone(&surface) as Arc<dyn HostKeySurface>, timeout: Duration::from_secs(5) };
        let asking = std::thread::spawn(move || confirmer.confirm(&question("web"), &CancelToken::default()));
        wait_until("the question to be shown", || !surface.seen.lock().unwrap().is_empty());
        let shown = hub.pending();
        assert_eq!((shown[0].alias.as_str(), shown[0].fingerprint.as_str(), shown[0].changed.clone()), ("web", "SHA256:new", None));
        hub.resolve(&shown[0].id, HostKeyAnswer { trust: true, fingerprint: "SHA256:new".into() }).unwrap();
        assert_eq!(asking.join().unwrap(), Some("SHA256:new".to_string()));
        assert_eq!(*surface.seen.lock().unwrap(), vec![vec![shown[0].id.clone()], vec![]]);
    }

    #[test]
    fn a_refusal_a_timeout_or_a_closed_window_is_no_trust() {
        let hub = Arc::new(HostKeyHub::default());
        let surface: Arc<dyn HostKeySurface> = Arc::new(Recorder::default());
        let confirmer = |timeout| WindowConfirmer { hub: Arc::clone(&hub), surface: Arc::clone(&surface), timeout };
        assert_eq!(confirmer(Duration::from_millis(20)).confirm(&question("web"), &CancelToken::default()), None, "nobody answered");

        let refusing = confirmer(Duration::from_secs(5));
        let asking = std::thread::spawn(move || refusing.confirm(&question("web"), &CancelToken::default()));
        wait_until("the question", || !hub.pending().is_empty());
        hub.resolve(&hub.pending()[0].id, HostKeyAnswer { trust: false, fingerprint: "SHA256:new".into() }).unwrap();
        assert_eq!(asking.join().unwrap(), None);

        let closed = confirmer(Duration::from_secs(5));
        let asking = std::thread::spawn(move || closed.confirm(&question("web"), &CancelToken::default()));
        wait_until("the question", || !hub.pending().is_empty());
        hub.deny_all();
        assert_eq!(asking.join().unwrap(), None);
        assert!(hub.pending().is_empty());
    }

    /// A question withdrawn before it is asked (the client went away between the connect's own look at the token and `ask`) opens no
    /// window: it is not put on the list, and the surface is told nothing.
    #[test]
    fn a_question_withdrawn_before_it_is_asked_opens_no_window() {
        let hub = HostKeyHub::default();
        let surface = Recorder::default();
        let cancel = CancelToken::default();
        cancel.cancel();
        assert_eq!(hub.ask(&surface, request("web"), Duration::from_secs(5), &cancel), None);
        assert!(surface.seen.lock().unwrap().is_empty(), "the window was told of a question nobody waits for: {:?}", surface.seen.lock().unwrap());
        assert!(hub.pending().is_empty());
    }

    /// The client went away while the window asked: the question leaves the window soon, and nothing is trusted.
    #[test]
    fn a_withdrawn_question_leaves_the_window() {
        let hub = Arc::new(HostKeyHub::default());
        let surface = Arc::new(Recorder::default());
        let cancel = CancelToken::default();
        let confirmer = WindowConfirmer { hub: Arc::clone(&hub), surface: Arc::clone(&surface) as Arc<dyn HostKeySurface>, timeout: Duration::from_secs(30) };
        let withdrawn = cancel.clone();
        let asking = std::thread::spawn(move || confirmer.confirm(&question("web"), &withdrawn));
        wait_until("the question", || !hub.pending().is_empty());
        let started = Instant::now();
        cancel.cancel();
        assert_eq!(asking.join().unwrap(), None);
        assert!(started.elapsed() < Duration::from_secs(2), "{:?}", started.elapsed());
        assert!(hub.pending().is_empty());
        assert_eq!(surface.seen.lock().unwrap().last(), Some(&vec![]), "the window is told nothing is pending");
    }

    #[test]
    fn a_changed_key_carries_the_pinned_one_and_answers_go_to_the_right_question() {
        let hub = Arc::new(HostKeyHub::default());
        let surface: Arc<dyn HostKeySurface> = Arc::new(Recorder::default());
        let mut changed = question("db");
        changed.changed = Some(PinnedSummary { fingerprint: "SHA256:old".into(), pinned_at_ms: 1_700_000_000_000 });
        let first = WindowConfirmer { hub: Arc::clone(&hub), surface: Arc::clone(&surface), timeout: Duration::from_secs(5) };
        let second = WindowConfirmer { hub: Arc::clone(&hub), surface: Arc::clone(&surface), timeout: Duration::from_secs(5) };
        let web = std::thread::spawn(move || first.confirm(&question("web"), &CancelToken::default()));
        wait_until("web's question", || hub.pending().len() == 1);
        let db = std::thread::spawn(move || second.confirm(&changed, &CancelToken::default()));
        wait_until("db's question", || hub.pending().len() == 2);
        let pending = hub.pending();
        assert_eq!(pending.iter().map(|request| request.alias.as_str()).collect::<Vec<_>>(), ["web", "db"], "oldest first");
        assert_eq!(pending[1].changed, Some(PinnedHostKey { fingerprint: "SHA256:old".into(), pinned_at_ms: 1_700_000_000_000 }));
        assert_ne!(pending[0].id, pending[1].id);
        hub.resolve(&pending[1].id, HostKeyAnswer { trust: true, fingerprint: "SHA256:new".into() }).unwrap();
        assert_eq!(db.join().unwrap(), Some("SHA256:new".into()));
        assert!(hub.resolve(&pending[1].id, HostKeyAnswer::default()).is_err(), "a question that was answered and has left the list cannot be answered again");
        hub.resolve(&pending[0].id, HostKeyAnswer::default()).unwrap();
        assert_eq!(web.join().unwrap(), None);
    }

    fn request(alias: &str) -> HostKeyRequest {
        HostKeyRequest { id: String::new(), alias: alias.into(), hostname: format!("{alias}.example.com"), port: 22, algorithm: "ssh-ed25519".into(), fingerprint: "SHA256:new".into(), changed: None }
    }

    /// An answered question whose `ask` has not woken up yet is no longer listed: it would be announced again, as the head, meanwhile.
    #[test]
    fn an_answered_question_is_not_listed_before_its_ask_wakes_up() {
        let hub = HostKeyHub::default();
        // Two waiting questions: nobody reads the channel of the first (its `ask` has not woken up), the second still waits.
        let (first, _first_reader) = mpsc::sync_channel(1);
        let (second, _second_reader) = mpsc::sync_channel(1);
        {
            let mut pending = hub.pending.lock().unwrap();
            pending.push(Waiting { request: HostKeyRequest { id: "hostkey-1".into(), ..request("web") }, answer: first, answered: false });
            pending.push(Waiting { request: HostKeyRequest { id: "hostkey-2".into(), ..request("db") }, answer: second, answered: false });
        }
        hub.resolve("hostkey-1", HostKeyAnswer { trust: true, fingerprint: "SHA256:new".into() }).unwrap();
        assert_eq!(hub.pending().into_iter().map(|request| request.id).collect::<Vec<_>>(), ["hostkey-2"], "the answered question is not listed");
        let surface = Recorder::default();
        hub.publish(&surface);
        assert_eq!(*surface.seen.lock().unwrap(), vec![vec!["hostkey-2".to_string()]], "and not announced again");
    }

    /// An answer that `resolve` took as the wait ran out counts: `resolve` reported success.
    #[test]
    fn an_answer_that_arrives_as_the_wait_times_out_is_not_lost() {
        let hub = Arc::new(HostKeyHub::default());
        let surface = Arc::new(Recorder::default());
        let (asking_hub, asking_surface) = (Arc::clone(&hub), Arc::clone(&surface));
        let asking = std::thread::spawn(move || asking_hub.ask(asking_surface.as_ref(), request("web"), Duration::from_secs(1), &CancelToken::default()));
        // `ask` has told the surface (and let go of `notify`), and waits for the answer.
        wait_until("ask to wait", || !surface.seen.lock().unwrap().is_empty() && hub.notify.try_lock().is_ok());
        let id = hub.pending()[0].id.clone();
        // While this lock is held, `ask` runs out of time and stops at taking the question off the list. What `resolve` does under the
        // lock (mark it answered, send the answer) comes before that.
        let mut pending = hub.pending.lock().unwrap();
        std::thread::sleep(Duration::from_millis(1500));
        let waiting = pending.iter_mut().find(|waiting| waiting.request.id == id).expect("the question stays listed while the lock is held");
        waiting.answered = true;
        waiting.answer.try_send(HostKeyAnswer { trust: true, fingerprint: "SHA256:new".into() }).unwrap();
        drop(pending);
        assert_eq!(asking.join().unwrap().map(|answer| answer.trust), Some(true), "resolve had reported success, so the answer counts");
        assert!(hub.pending().is_empty());
    }

    /// Closing the window refuses every waiting question at once, and none of them is listed again.
    #[test]
    fn closing_the_window_refuses_every_waiting_question_at_once() {
        let hub = Arc::new(HostKeyHub::default());
        let mut asking = Vec::new();
        for alias in ["web", "db"] {
            let asking_hub = Arc::clone(&hub);
            asking.push(std::thread::spawn(move || asking_hub.ask(&Recorder::default(), request(alias), Duration::from_secs(5), &CancelToken::default())));
            wait_until("the question to wait", || hub.pending().iter().any(|request| request.alias == alias));
        }
        hub.deny_all();
        assert!(hub.pending().is_empty(), "a refused question is gone at once, so no later notification lists it again");
        for asking in asking {
            let answer = asking.join().unwrap().expect("a refusal, not a timeout");
            assert!(!answer.trust);
        }
        assert!(hub.pending().is_empty());
    }

    /// A surface that panics leaves no question behind, and the questions after it are shown as usual.
    #[test]
    fn a_surface_that_panics_does_not_stop_later_notifications() {
        struct Panics;
        impl HostKeySurface for Panics {
            fn changed(&self, _: &[HostKeyRequest]) {
                panic!("the window failed");
            }
        }
        let hub = HostKeyHub::default();
        let crashed = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| hub.ask(&Panics, request("web"), Duration::from_millis(20), &CancelToken::default())));
        assert!(crashed.is_err());
        assert!(hub.pending().is_empty(), "the failed call leaves no question behind");
        let surface = Recorder::default();
        assert_eq!(hub.ask(&surface, request("db"), Duration::from_millis(20), &CancelToken::default()), None);
        assert_eq!(*surface.seen.lock().unwrap(), vec![vec!["hostkey-2".to_string()], vec![]], "a question after the failure is shown on its own, then gone");
    }

    #[test]
    fn the_window_comes_to_the_front_only_for_a_new_question_at_the_head() {
        let list = |ids: &[&str]| {
            ids.iter()
                .map(|id| HostKeyRequest { id: (*id).into(), alias: "web".into(), hostname: "web".into(), port: 22, algorithm: "ssh-ed25519".into(), fingerprint: "SHA256:x".into(), changed: None })
                .collect::<Vec<_>>()
        };
        let mut shown = None;
        assert!(note_head(&mut shown, &list(&["hostkey-1"])));
        assert!(!note_head(&mut shown, &list(&["hostkey-1", "hostkey-2"])));
        assert!(note_head(&mut shown, &list(&["hostkey-2"])));
        assert!(!note_head(&mut shown, &[]));
        assert_eq!(shown, None);
    }
}
