//! 核准視窗與等待中的請求(spec §5.3、§7.4)。agent 的連線執行緒呼叫 `PromptHub::ask` 等待答案(最多 60 秒;伺服器預設 120 秒內
//! 沒完成認證就斷線);核准視窗(標籤 `approval`)用 `agent_pending` 取得請求、用 `agent_resolve` 回答。關掉核准視窗等於拒絕
//! (`PromptHub::deny_all`,由 `lib.rs` 的視窗事件呼叫)。

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
/// `PromptHub` 一次只呼叫一個 `changed`,每次帶的是呼叫當下最新的清單,所以最後一次呼叫帶的一定是最後的狀態。
pub trait PromptSurface: Send + Sync {
    fn changed(&self, pending: &[AgentApprovalRequest]);
}

struct Waiting {
    request: AgentApprovalRequest,
    answer: mpsc::SyncSender<AgentApprovalAnswer>,
    /// 已經有人回答(答案在 channel 裡,或已被 `ask` 取走):之後的 `resolve` 一律 NotFound,不再塞進沒人讀的 channel。
    answered: bool,
}

/// 等待中的請求(依到達順序)。
#[derive(Default)]
pub struct PromptHub {
    pending: Mutex<Vec<Waiting>>,
    /// 通知畫面的順序鎖:取清單和呼叫 `PromptSurface::changed` 在同一把鎖裡(`publish`)。鎖的順序一律是 `notify` → `pending`,
    /// 呼叫 `changed` 時不持有 `pending`;指令(`agent_pending`、`agent_resolve`)與視窗事件(`deny_all`)只拿 `pending`,主執行緒不會等 `notify`。
    notify: Mutex<()>,
    next_id: AtomicU64,
}

/// `ask` 離開時(正常回傳、逾時,或 `changed` panic 讓它展開)把請求從清單拿掉,清單裡不會留下幽靈請求。
struct Leaving<'a> {
    hub: &'a PromptHub,
    id: &'a str,
}

impl Drop for Leaving<'_> {
    fn drop(&mut self) {
        self.hub.forget(self.id);
    }
}

impl PromptHub {
    /// 送出請求並等待回答。逾時回 None(呼叫端當成拒絕);逾時的瞬間才到的答案照樣算數(`resolve` 已經回報成功)。`request.id` 由這裡指定。
    /// 會阻塞到逾時,而且畫面會建立視窗:Tauri 文件說在 Windows 上從同步指令或事件處理函式建立視窗會死結,所以只能從工作執行緒呼叫
    /// (agent 的連線執行緒)。
    pub fn ask(&self, surface: &dyn PromptSurface, mut request: AgentApprovalRequest, timeout: Duration) -> Option<AgentApprovalAnswer> {
        let id = format!("approval-{}", self.next_id.fetch_add(1, Ordering::Relaxed) + 1);
        request.id = id.clone();
        let (tx, rx) = mpsc::sync_channel(1);
        self.pending.lock().unwrap().push(Waiting { request, answer: tx, answered: false });
        let _leave = Leaving { hub: self, id: &id };
        self.publish(surface);
        let mut answer = rx.recv_timeout(timeout).ok();
        // 不再等了:先把請求從清單拿掉(之後的 `resolve` 找不到它,不會再送答案),再看一次 channel:逾時的瞬間才到的答案
        // (`resolve` 已經回報成功)照樣算數。
        self.forget(&id);
        if answer.is_none() {
            answer = rx.try_recv().ok();
        }
        self.publish(surface);
        answer
    }

    /// 把請求從清單拿掉(不在清單裡也沒關係)。panic 展開的途中也會用到,所以鎖中毒時照樣使用:在展開中再 panic 會讓整個程式中止。
    fn forget(&self, id: &str) {
        self.pending.lock().unwrap_or_else(std::sync::PoisonError::into_inner).retain(|w| w.request.id != id);
    }

    /// 把目前的清單告訴畫面。取清單和呼叫 `changed` 都在 `notify` 裡:同時有請求進出時,後一個通知帶的一定是較新的清單,畫面不會最後
    /// 收到舊的(例如請求還在等,視窗卻被一份較早取得的空清單關掉)。`changed` 可能很慢(開關視窗要等主執行緒),所以不能持有 `pending`。
    fn publish(&self, surface: &dyn PromptSurface) {
        // `notify` 裡沒有資料:`changed` panic 讓它中毒時照樣使用,不然之後每一次詢問都會跟著 panic。
        let _order = self.notify.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let snapshot = self.pending();
        surface.changed(&snapshot);
    }

    /// 回答一個等待中的請求。不存在、已經回答過或已逾時 → NotFound。
    pub fn resolve(&self, id: &str, answer: AgentApprovalAnswer) -> Result<(), AppError> {
        let gone = || AppError::NotFound("that request was already answered or has expired".to_string());
        let mut pending = self.pending.lock().unwrap();
        let waiting = pending.iter_mut().find(|w| w.request.id == id && !w.answered).ok_or_else(gone)?;
        waiting.answered = true;
        waiting.answer.try_send(answer).map_err(|_| gone())
    }

    /// 核准視窗被關掉:等待中的請求一律拒絕。
    /// 清單一併清空:被拒絕的請求不會再出現在之後的通知裡(不然第一個回來的 `ask` 會通知一份還列著其他請求的清單,畫面又為它們開一個新視窗)。
    pub fn deny_all(&self) {
        for waiting in self.pending.lock().unwrap().drain(..) {
            // 已經有答案在 channel 裡的(`Full`)維持原來的答案。
            let _ = waiting.answer.try_send(AgentApprovalAnswer::default());
        }
    }

    /// 還在等答案的請求(依到達順序)。已經回答、但它的 `ask` 還沒醒來移除的不列出:不然那一小段時間裡它會被當成排在最前面的請求再通知一次。
    pub fn pending(&self) -> Vec<AgentApprovalRequest> {
        self.pending.lock().unwrap().iter().filter(|w| !w.answered).map(|w| w.request.clone()).collect()
    }
}

/// 核准視窗上一次被叫到前面時,排在最前面的請求(整個程式只有一個核准視窗)。`TauriPromptSurface` 是呼叫端每次 `ask` 現做的,
/// 自己不能記狀態,所以放在這裡。
static SHOWN_HEAD: Mutex<Option<String>> = Mutex::new(None);

/// 記住排在最前面的請求,回傳是不是有新的請求排到最前面(才需要把視窗叫到前面;別的請求逾時、被拒絕都不算)。清單空了就忘掉。
fn note_head(shown: &mut Option<String>, pending: &[AgentApprovalRequest]) -> bool {
    let head = pending.first().map(|r| r.id.as_str());
    let new_head = head.is_some() && shown.as_deref() != head;
    *shown = head.map(str::to_string);
    new_head
}

/// production 的畫面:核准視窗是獨立的小視窗,永遠在最上層;SSHelter 縮在系統匣時也會出現(spec §7.4)。沒有請求時銷毀它
/// (`destroy` 不經過 `CloseRequested`,所以不會被當成使用者關掉視窗而拒絕等待中的請求,見 `lib.rs` 的 `on_window_event`)。
pub struct TauriPromptSurface {
    pub app: tauri::AppHandle,
}

impl PromptSurface for TauriPromptSurface {
    fn changed(&self, pending: &[AgentApprovalRequest]) {
        use tauri::{Emitter, Manager, WebviewUrl, WebviewWindowBuilder};
        let new_head = note_head(&mut SHOWN_HEAD.lock().unwrap_or_else(std::sync::PoisonError::into_inner), pending);
        if pending.is_empty() {
            if let Some(window) = self.app.get_webview_window(APPROVAL_WINDOW) {
                let _ = window.destroy();
            }
            return;
        }
        let (window, built) = match self.app.get_webview_window(APPROVAL_WINDOW) {
            Some(window) => (Some(window), false),
            None => match WebviewWindowBuilder::new(&self.app, APPROVAL_WINDOW, WebviewUrl::App("index.html".into()))
                .title("SSHelter")
                .inner_size(460.0, 340.0)
                .resizable(false)
                .always_on_top(true)
                .center()
                .build()
            {
                Ok(window) => (Some(window), true),
                Err(e) => {
                    eprintln!("[agent] cannot open the approval window: {e}");
                    (None, false)
                }
            },
        };
        // 只有剛建好,或有新的請求排到最前面才把視窗叫到前面:別的請求逾時,不該搶走使用者正在操作的焦點。
        if let Some(window) = window {
            if built || new_head {
                let _ = window.show();
                let _ = window.unminimize();
                let _ = window.set_focus();
            }
        }
        let _ = self.app.emit_to(APPROVAL_WINDOW, APPROVALS_EVENT, pending);
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
    use std::sync::atomic::AtomicBool;
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
        // 視窗被告知有這個請求才回答(視窗就是這樣回答的):已回答的請求不再列在通知裡,太早回答會讓第一次通知變成空的。
        let id = loop {
            if !surface.seen.lock().unwrap().is_empty() {
                break hub.pending()[0].id.clone();
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

    /// 等條件成立,最多 5 秒(不然出錯時測試會卡住)。
    fn wait_until(what: &str, condition: impl Fn() -> bool) {
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        while !condition() {
            assert!(std::time::Instant::now() < deadline, "timed out waiting for: {what}");
            std::thread::sleep(Duration::from_millis(2));
        }
    }

    /// 「沒有等待中的請求」那一次通知很慢的畫面(像銷毀視窗要等主執行緒),記下每次被告知的清單。
    #[derive(Default)]
    struct SlowWhenEmpty {
        seen: Mutex<Vec<Vec<String>>>,
        slow_call_started: AtomicBool,
        release: AtomicBool,
    }

    impl PromptSurface for SlowWhenEmpty {
        fn changed(&self, pending: &[AgentApprovalRequest]) {
            if pending.is_empty() {
                self.slow_call_started.store(true, Ordering::SeqCst);
                while !self.release.load(Ordering::SeqCst) {
                    std::thread::sleep(Duration::from_millis(2));
                }
            }
            self.seen.lock().unwrap().push(pending.iter().map(|r| r.id.clone()).collect());
        }
    }

    #[test]
    fn the_window_is_last_told_what_is_really_pending_even_when_a_notification_is_slow() {
        let hub = Arc::new(PromptHub::default());
        let surface = Arc::new(SlowWhenEmpty::default());
        // 請求 b 逾時,它的「沒有等待中的請求」通知卡在那裡(像視窗正在銷毀)。
        let (h, s) = (Arc::clone(&hub), Arc::clone(&surface));
        let b = std::thread::spawn(move || h.ask(s.as_ref(), request("b"), Duration::from_millis(50)));
        wait_until("b's slow notification starts", || surface.slow_call_started.load(Ordering::SeqCst));
        // 它還卡著的時候,新的請求 a 進來。
        let (h, s) = (Arc::clone(&hub), Arc::clone(&surface));
        let a = std::thread::spawn(move || h.ask(s.as_ref(), request("a"), Duration::from_secs(5)));
        wait_until("a is waiting", || !hub.pending().is_empty());
        // 讓 a 自己的通知有時間搶在慢的那一次前面(逐一通知的實作不會讓它搶),再放行。
        std::thread::sleep(Duration::from_millis(100));
        surface.release.store(true, Ordering::SeqCst);
        assert_eq!(b.join().unwrap(), None);
        wait_until("all three notifications arrived", || surface.seen.lock().unwrap().len() == 3);
        let seen = surface.seen.lock().unwrap().clone();
        let really_pending: Vec<String> = hub.pending().iter().map(|r| r.id.clone()).collect();
        assert_eq!(seen.last(), Some(&really_pending), "the last list the window saw must be what is really pending; it saw {seen:?}");
        hub.resolve(&really_pending[0], AgentApprovalAnswer { allow: true, ..Default::default() }).unwrap();
        assert!(a.join().unwrap().unwrap().allow);
    }

    #[test]
    fn closing_the_window_denies_every_waiting_request_at_once() {
        let hub = Arc::new(PromptHub::default());
        let mut waiters = Vec::new();
        for key in ["a", "b"] {
            let h = Arc::clone(&hub);
            waiters.push(std::thread::spawn(move || h.ask(&Recorder::default(), request(key), Duration::from_secs(5))));
            wait_until("the request is waiting", || hub.pending().iter().any(|r| r.key_name == key));
        }
        hub.deny_all();
        assert!(hub.pending().is_empty(), "a denied request is gone at once, so no later notification lists it again");
        for waiter in waiters {
            let answer = waiter.join().unwrap().expect("a denial, not a timeout");
            assert!(!answer.allow);
        }
        assert!(hub.pending().is_empty());
    }

    #[test]
    fn a_surface_that_panics_does_not_stop_later_notifications() {
        struct Panics;
        impl PromptSurface for Panics {
            fn changed(&self, _: &[AgentApprovalRequest]) {
                panic!("the window failed");
            }
        }
        let hub = PromptHub::default();
        let crashed = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| hub.ask(&Panics, request("a"), Duration::from_millis(20))));
        assert!(crashed.is_err());
        assert!(hub.pending().is_empty(), "the failed call leaves no ghost request behind");
        let surface = Recorder::default();
        assert_eq!(hub.ask(&surface, request("b"), Duration::from_millis(20)), None);
        assert_eq!(
            *surface.seen.lock().unwrap(),
            vec![vec!["approval-2".to_string()], vec![]],
            "a request after the failure is shown on its own, then gone"
        );
    }

    #[test]
    fn an_answer_that_arrives_as_the_wait_times_out_is_not_lost() {
        let hub = Arc::new(PromptHub::default());
        let surface = Arc::new(Recorder::default());
        let (h, s) = (Arc::clone(&hub), Arc::clone(&surface));
        let waiter = std::thread::spawn(move || h.ask(s.as_ref(), request("a"), Duration::from_secs(1)));
        // `ask` 已經通知過畫面(放開了 `notify`),開始等答案。
        wait_until("ask is waiting", || !surface.seen.lock().unwrap().is_empty() && hub.notify.try_lock().is_ok());
        let id = hub.pending()[0].id.clone();
        // 這把鎖在手上的時候,`ask` 等不到答案而逾時,卡在移除請求那一步。`resolve` 在鎖裡做的事(標記已回答、送出答案)排在它移除之前。
        let mut pending = hub.pending.lock().unwrap();
        std::thread::sleep(Duration::from_millis(1500));
        let waiting = pending.iter_mut().find(|w| w.request.id == id).expect("the request stays listed while the lock is held");
        waiting.answered = true;
        waiting.answer.try_send(AgentApprovalAnswer { allow: true, ..Default::default() }).unwrap();
        drop(pending);
        let answer = waiter.join().unwrap();
        assert_eq!(answer.map(|a| a.allow), Some(true), "resolve had reported success, so the answer must count");
        assert!(hub.pending().is_empty());
    }

    #[test]
    fn an_answered_request_is_not_listed_before_its_ask_wakes_up() {
        let hub = PromptHub::default();
        // 兩個等待中的請求:a 的 `ask` 還沒醒來(沒有人在讀它的 channel),b 還在等。
        let (tx_a, _rx_a) = mpsc::sync_channel(1);
        let (tx_b, _rx_b) = mpsc::sync_channel(1);
        {
            let mut pending = hub.pending.lock().unwrap();
            pending.push(Waiting { request: AgentApprovalRequest { id: "approval-1".into(), ..request("a") }, answer: tx_a, answered: false });
            pending.push(Waiting { request: AgentApprovalRequest { id: "approval-2".into(), ..request("b") }, answer: tx_b, answered: false });
        }
        hub.resolve("approval-1", AgentApprovalAnswer { allow: true, ..Default::default() }).unwrap();
        let ids = hub.pending().into_iter().map(|r| r.id).collect::<Vec<_>>();
        assert_eq!(ids, vec!["approval-2"], "the answered request is not listed");
        let surface = Recorder::default();
        hub.publish(&surface);
        assert_eq!(*surface.seen.lock().unwrap(), vec![vec!["approval-2".to_string()]], "and not announced again");
    }

    #[test]
    fn the_window_is_only_brought_forward_when_a_new_request_is_at_the_head() {
        let list = |ids: &[&str]| ids.iter().map(|id| AgentApprovalRequest { id: (*id).into(), ..request("k") }).collect::<Vec<_>>();
        let mut shown = None;
        assert!(note_head(&mut shown, &list(&["approval-1"])), "a first request is brought forward");
        assert!(!note_head(&mut shown, &list(&["approval-1", "approval-2"])), "a request queued behind it is not");
        assert!(!note_head(&mut shown, &list(&["approval-1"])), "nor is the request behind it timing out");
        assert!(note_head(&mut shown, &list(&["approval-2"])), "the next request becomes the head and is");
        assert!(!note_head(&mut shown, &[]), "an empty list brings nothing forward");
        assert_eq!(shown, None, "and it is forgotten, so the next request starts from scratch");
        assert!(note_head(&mut shown, &list(&["approval-2"])), "even one whose id was seen before");
    }
}
