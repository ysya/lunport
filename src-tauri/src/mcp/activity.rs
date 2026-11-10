//! What the AI activity page reads of the audit log: how the review of an AI client's request went, what stopped the request, and the
//! AI entries themselves, kept apart from the person's own terminal sessions and key deploys.

use std::collections::VecDeque;
use std::sync::atomic::Ordering;
use std::sync::Mutex;
use std::time::Instant;

use serde::{Deserialize, Serialize};

use super::{ApprovalDecision, ApprovalMode, McpAuditEntry, McpRuntime};
use crate::session::auth::{printable, Owner, Reply};
use crate::session::connect::CancelToken;
use crate::session::protocol::QuestionKind;

/// How many AI entries the log keeps; the person's own entries (terminal sessions, key deploys) keep as many again, apart from them.
pub(crate) const AUDIT_KEEP: usize = 1000;
/// The most characters a recorded reason keeps.
pub(crate) const REASON_LIMIT: usize = 300;

/// How the review of an AI client's command or proposal went.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(test, derive(ts_rs::TS))]
#[cfg_attr(test, ts(export, export_to = "../../src/bindings/"))]
pub enum McpReview {
    /// The person approved it in Lunport's window.
    Approved,
    /// The person refused it in Lunport's window.
    Refused,
    /// Lunport's window got no answer in time.
    NoAnswer,
    /// It went ahead under Auto-log, without per-request review.
    AutoLog,
    /// The tool has no review step (stopping a tunnel, deciding on a server key).
    NotAsked,
}

/// What stopped an AI client's request that did not succeed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(test, derive(ts_rs::TS))]
#[cfg_attr(test, ts(export, export_to = "../../src/bindings/"))]
pub enum McpStopKind {
    /// The person refused it in one of Lunport's windows.
    Refused,
    /// One of Lunport's windows got no answer in time.
    NoAnswer,
    /// The client cancelled or went away, or AI access was turned off or changed mode, before it ran.
    Canceled,
    /// AI access does not allow the host.
    NotAllowed,
    /// Lunport could not carry it out.
    Error,
}

/// The Lunport window a request stopped in.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(test, derive(ts_rs::TS))]
#[cfg_attr(test, ts(export, export_to = "../../src/bindings/"))]
pub enum McpWindow {
    /// The approval of the command, tunnel start or proposal.
    Approval,
    /// A new or changed server key.
    ServerKey,
    /// A password, key passphrase or two-factor answer.
    Credentials,
    /// Request a grant (Privileged Access Manager).
    Grant,
}

/// What stopped an AI client's request, where, and Lunport's sentence for it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(test, derive(ts_rs::TS))]
#[cfg_attr(test, ts(export, export_to = "../../src/bindings/"))]
pub struct McpStop {
    pub kind: McpStopKind,
    #[serde(default)]
    pub window: Option<McpWindow>,
    /// The error the request answered with, printable, on one line and capped (`reason_text`); never command output.
    #[serde(default)]
    pub reason: Option<String>,
}

/// The AI entries the AI activity page shows, newest first, with the revision of the log they were read at.
#[derive(Debug, Clone, Serialize)]
#[cfg_attr(test, derive(ts_rs::TS))]
#[cfg_attr(test, ts(export, export_to = "../../src/bindings/"))]
pub struct McpActivityLog {
    #[cfg_attr(test, ts(type = "number"))]
    pub revision: u64,
    /// `None` when the log is still at the revision the page asked with.
    pub entries: Option<Vec<McpAuditEntry>>,
    pub audit_error: Option<String>,
}

impl McpAuditEntry {
    /// Whether an AI client's tool call wrote it: `client` is "mcp", or empty in lines written before the field existed.
    pub(crate) fn is_ai(&self) -> bool {
        self.client.is_empty() || self.client == "mcp"
    }
}

/// Keeps, in order, the newest `AUDIT_KEEP` AI entries and, apart from them, the newest `AUDIT_KEEP` others (`entries` is newest first).
pub(crate) fn retain_per_kind(entries: &mut VecDeque<McpAuditEntry>) {
    let (mut ai, mut other) = (0, 0);
    entries.retain(|entry| {
        let count = if entry.is_ai() { &mut ai } else { &mut other };
        *count += 1;
        *count <= AUDIT_KEEP
    });
}

/// A request's error as its audit entry keeps it: printable (no control or deceptive format characters), on one line, at most
/// `REASON_LIMIT` characters.
pub(crate) fn reason_text(error: &str) -> String {
    let line = printable(error).replace(['\n', '\t'], " ");
    line.trim().chars().take(REASON_LIMIT).collect::<String>().trim_end().to_string()
}

/// How the approval window's decision reviewed a request; `None` when the request was withdrawn before anyone answered.
pub(super) fn review_of(decision: ApprovalDecision) -> Option<McpReview> {
    match decision {
        ApprovalDecision::Allow => Some(McpReview::Approved),
        ApprovalDecision::Deny => Some(McpReview::Refused),
        ApprovalDecision::TimedOut => Some(McpReview::NoAnswer),
        ApprovalDecision::Cancel => None,
    }
}

/// What stopped a request that ended with `error`: the approval window's decision when it did not allow the request; else a window the
/// request opened that the person declined or left unanswered (`declined`); else a withdrawal (`cancelled`: the client went away, or AI
/// access changed); else an error. The reason is the error, as `reason_text` keeps it.
pub(super) fn stop_for(
    error: &str,
    decision: Option<ApprovalDecision>,
    declined: Option<(McpStopKind, McpWindow)>,
    cancelled: bool,
) -> McpStop {
    let (kind, window) = match (decision, declined) {
        (Some(ApprovalDecision::Deny), _) => (McpStopKind::Refused, Some(McpWindow::Approval)),
        (Some(ApprovalDecision::TimedOut), _) => (McpStopKind::NoAnswer, Some(McpWindow::Approval)),
        (Some(ApprovalDecision::Cancel), _) => (McpStopKind::Canceled, Some(McpWindow::Approval)),
        (_, Some((kind, window))) => (kind, Some(window)),
        _ if cancelled => (McpStopKind::Canceled, None),
        _ => (McpStopKind::Error, None),
    };
    McpStop { kind, window, reason: Some(reason_text(error)) }
}

/// The first of Lunport's windows an AI client's request opened that the person declined or left unanswered.
#[derive(Debug, Default)]
pub(crate) struct Declines(Mutex<Option<(McpStopKind, McpWindow)>>);
impl Declines {
    /// Notes a window that ended without the person's agreement; the first one noted stays.
    pub(crate) fn note(&self, kind: McpStopKind, window: McpWindow) {
        self.0.lock().unwrap().get_or_insert((kind, window));
    }
    pub(crate) fn first(&self) -> Option<(McpStopKind, McpWindow)> {
        *self.0.lock().unwrap()
    }
}

/// The owner of an AI client's request: it asks as `inner` does and notes on `declines` a credential or grant question the person declined
/// (`Reply::Cancelled`) or left unanswered (`Reply::TimedOut`). A question withdrawn because the request was (`Reply::Gone`) notes nothing:
/// the withdrawal is what stopped the request.
pub(crate) struct NotingOwner<'a> {
    pub(crate) inner: &'a dyn Owner,
    pub(crate) declines: &'a Declines,
}
impl NotingOwner<'_> {
    fn noted(&self, kind: QuestionKind, reply: Reply) -> Reply {
        let window = match kind {
            QuestionKind::Passphrase | QuestionKind::Password | QuestionKind::Interactive => Some(McpWindow::Credentials),
            QuestionKind::Grant => Some(McpWindow::Grant),
            QuestionKind::HostKeyNotice => None,
        };
        match (&reply, window) {
            (Reply::Cancelled, Some(window)) => self.declines.note(McpStopKind::Refused, window),
            (Reply::TimedOut, Some(window)) => self.declines.note(McpStopKind::NoAnswer, window),
            _ => {}
        }
        reply
    }
}
impl Owner for NotingOwner<'_> {
    fn ask(&self, kind: QuestionKind, text: &str, echo: bool, deadline: Option<Instant>) -> Reply {
        self.noted(kind, self.inner.ask(kind, text, echo, deadline))
    }
    fn ask_at(&self, hop: &crate::ssh::HopRef, kind: QuestionKind, text: &str, echo: bool, deadline: Option<Instant>) -> Reply {
        self.noted(kind, self.inner.ask_at(hop, kind, text, echo, deadline))
    }
    fn host_key_notice(&self, text: &str) {
        self.inner.host_key_notice(text)
    }
    fn banner(&self, text: &str) {
        self.inner.banner(text)
    }
}

impl McpRuntime {
    /// Whether an AI client's request in `mode` was withdrawn: its token cancelled (the client went away, or the person changed AI access),
    /// or AI access is now off or in another mode. The app cancels the requests' tokens right after such a change; this also covers the
    /// moment in between.
    pub(super) fn withdrawn(&self, mode: ApprovalMode, cancel: &CancelToken) -> bool {
        if cancel.is_cancelled() {
            return true;
        }
        let policy = self.policy.lock().unwrap();
        !policy.enabled || policy.approval_mode != mode
    }

    /// The AI entries, newest first, unless the log is still at `since`.
    pub(super) fn activity(&self, since: Option<u64>) -> McpActivityLog {
        let audit_error = self.audit.lock().unwrap().error.clone();
        let recent = self.recent.lock().unwrap();
        let revision = self.revision.load(Ordering::SeqCst);
        let entries = (since != Some(revision)).then(|| recent.iter().filter(|entry| entry.is_ai()).cloned().collect());
        McpActivityLog { revision, entries, audit_error }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mcp::{McpAuditEntry, McpPolicy, McpRuntime};
    use crate::session::auth::{Owner, Reply};
    use crate::session::connect::CancelToken;
    use crate::session::protocol::QuestionKind;
    use crate::session::testing::FakeOwner;

    fn entry(id: &str, client: &str) -> McpAuditEntry {
        McpAuditEntry { id: id.into(), client: client.into(), ..Default::default() }
    }

    fn enabled(mode: ApprovalMode) -> McpRuntime {
        let runtime = McpRuntime::default();
        *runtime.policy.lock().unwrap() = McpPolicy { enabled: true, approval_mode: mode, ..Default::default() };
        runtime
    }

    #[test]
    fn new_fields_round_trip_and_a_line_from_before_loads() {
        let recorded = McpAuditEntry {
            review: Some(McpReview::AutoLog),
            stop: Some(McpStop { kind: McpStopKind::Refused, window: Some(McpWindow::ServerKey), reason: Some("x".into()) }),
            tunnel: Some("Database".into()),
            ..entry("r1", "mcp")
        };
        let read: McpAuditEntry = serde_json::from_str(&serde_json::to_string(&recorded).unwrap()).unwrap();
        assert_eq!(read.review, Some(McpReview::AutoLog));
        assert_eq!(
            read.stop,
            Some(McpStop { kind: McpStopKind::Refused, window: Some(McpWindow::ServerKey), reason: Some("x".into()) })
        );
        assert_eq!(read.tunnel.as_deref(), Some("Database"));

        let before: McpAuditEntry = serde_json::from_str(
            r#"{"client":"mcp","id":"r1","alias":"web-1","command":"uptime","outcome":"allowed","exit_code":0,"detail":null,"completed_at_ms":5}"#,
        )
        .unwrap();
        assert_eq!(before.review, None);
        assert_eq!(before.stop, None);
        assert_eq!(before.tunnel, None);
    }

    #[test]
    fn ai_entries_keep_their_own_thousand() {
        let runtime = McpRuntime::default();
        runtime.recent.lock().unwrap().extend((0..1000).map(|n| entry(&format!("ai-{n}"), "mcp")));
        for n in 0..1001 {
            runtime.record(entry(&format!("connect-{n}"), "connect"));
        }
        let recent = runtime.recent.lock().unwrap();
        assert_eq!(recent.iter().filter(|e| e.client == "mcp").count(), 1000);
        assert!((0..1000).all(|n| recent.iter().any(|e| e.id == format!("ai-{n}"))));
        assert_eq!(recent.iter().filter(|e| e.client == "connect").count(), 1000);
        assert!(!recent.iter().any(|e| e.id == "connect-0"), "the oldest terminal session goes first");
        drop(recent);

        let runtime = McpRuntime::default();
        runtime.recent.lock().unwrap().extend((0..1000).map(|n| entry(&format!("connect-{n}"), "connect")));
        for n in 0..1001 {
            runtime.record(entry(&format!("ai-{n}"), "mcp"));
        }
        let recent = runtime.recent.lock().unwrap();
        assert!((0..1000).all(|n| recent.iter().any(|e| e.id == format!("connect-{n}"))));
        assert_eq!(recent.iter().filter(|e| e.client == "mcp").count(), 1000);
        assert!(!recent.iter().any(|e| e.id == "ai-0"), "the oldest AI entry goes first");
        assert_eq!(recent[0].id, "ai-1000");
    }

    #[test]
    fn load_keeps_the_newest_thousand_of_each_kind() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("session-log.jsonl");
        let mut bytes = Vec::new();
        for n in 0..1100 {
            for item in [entry(&format!("ai-{n}"), "mcp"), entry(&format!("deploy-{n}"), "deploy")] {
                serde_json::to_writer(&mut bytes, &item).unwrap();
                bytes.push(b'\n');
            }
        }
        std::fs::write(&path, bytes).unwrap();
        let runtime = McpRuntime::default();
        runtime.load_audit(path);
        let recent = runtime.recent.lock().unwrap();
        assert_eq!(recent.len(), 2000);
        assert_eq!(recent[0].id, "deploy-1099");
        for kind in ["ai", "deploy"] {
            assert!(!recent.iter().any(|e| e.id == format!("{kind}-99")), "{kind}: the oldest 100 are gone");
            assert!(recent.iter().any(|e| e.id == format!("{kind}-100")), "{kind}: the newest 1,000 stay");
        }
    }

    #[test]
    fn activity_returns_ai_entries_with_a_revision_and_nothing_when_unchanged() {
        let runtime = McpRuntime::default();
        for (id, client) in [("e1", "connect"), ("e2", "mcp"), ("e3", "deploy"), ("e4", "")] {
            runtime.record(entry(id, client));
        }
        let first = runtime.activity(None);
        let entries = first.entries.expect("a first read has entries");
        assert_eq!(entries.iter().map(|e| e.id.as_str()).collect::<Vec<_>>(), ["e4", "e2"]);
        assert_eq!(entries[0].client, "mcp", "an entry without a client is stored as an AI entry");
        assert!(runtime.activity(Some(first.revision)).entries.is_none());

        runtime.record(entry("e5", "mcp"));
        let next = runtime.activity(Some(first.revision));
        assert_ne!(next.revision, first.revision);
        assert_eq!(next.entries.expect("a new entry is sent").len(), 3);
    }

    #[test]
    fn activity_carries_the_audit_error_even_when_unchanged() {
        let runtime = McpRuntime::default();
        runtime.audit.lock().unwrap().error = Some("Session log could not be read.".into());
        let read = runtime.activity(None);
        assert_eq!(runtime.activity(Some(read.revision)).audit_error.as_deref(), Some("Session log could not be read."));
    }

    #[test]
    fn status_recent_holds_ai_entries_only() {
        let runtime = McpRuntime::default();
        runtime.record(entry("ai", "mcp"));
        for n in 0..20 {
            runtime.record(entry(&format!("connect-{n}"), "connect"));
        }
        let recent = runtime.status().recent;
        assert_eq!(recent.iter().map(|e| e.id.as_str()).collect::<Vec<_>>(), ["ai"]);
    }

    #[test]
    fn withdrawn_covers_a_cancelled_token_and_a_policy_change() {
        let runtime = enabled(ApprovalMode::Ask);
        assert!(!runtime.withdrawn(ApprovalMode::Ask, &CancelToken::default()));
        let cancelled = CancelToken::default();
        cancelled.cancel();
        assert!(runtime.withdrawn(ApprovalMode::Ask, &cancelled));
        runtime.policy.lock().unwrap().approval_mode = ApprovalMode::AutoLog;
        assert!(runtime.withdrawn(ApprovalMode::Ask, &CancelToken::default()));
        let runtime = enabled(ApprovalMode::Ask);
        runtime.policy.lock().unwrap().enabled = false;
        assert!(runtime.withdrawn(ApprovalMode::Ask, &CancelToken::default()));
    }

    #[test]
    fn reason_is_printable_one_line_and_capped() {
        let reason = reason_text(&format!("a\u{1b}[2Jb\nc\u{202e}d{}", "x".repeat(400)));
        assert!(reason.starts_with("a?[2Jb c?d"), "{reason}");
        assert!(!reason.chars().any(|c| c.is_control()));
        assert!(!reason.contains('\u{202e}'));
        assert_eq!(reason.chars().count(), REASON_LIMIT);
        assert_eq!(reason_text("  Could not reach web-1:22.\r\n"), "Could not reach web-1:22.");
    }

    #[test]
    fn stop_for_takes_the_window_decision_then_a_decline_then_cancellation() {
        let stop = |kind, window: Option<McpWindow>, reason: &str| McpStop { kind, window, reason: Some(reason.into()) };
        let declined = Some((McpStopKind::Refused, McpWindow::Credentials));
        assert_eq!(
            stop_for("Host creation was denied.", Some(ApprovalDecision::Deny), declined, true),
            stop(McpStopKind::Refused, Some(McpWindow::Approval), "Host creation was denied.")
        );
        assert_eq!(
            stop_for("MCP approval timed out", Some(ApprovalDecision::TimedOut), None, false),
            stop(McpStopKind::NoAnswer, Some(McpWindow::Approval), "MCP approval timed out")
        );
        assert_eq!(
            stop_for("MCP request was canceled", Some(ApprovalDecision::Cancel), None, true),
            stop(McpStopKind::Canceled, Some(McpWindow::Approval), "MCP request was canceled")
        );
        assert_eq!(
            stop_for("No password was given.", Some(ApprovalDecision::Allow), declined, true),
            stop(McpStopKind::Refused, Some(McpWindow::Credentials), "No password was given.")
        );
        assert_eq!(
            stop_for("MCP request was canceled", Some(ApprovalDecision::Allow), None, true),
            stop(McpStopKind::Canceled, None, "MCP request was canceled")
        );
        assert_eq!(
            stop_for("Could not reach web-1:22 (connection refused).", None, None, false),
            stop(McpStopKind::Error, None, "Could not reach web-1:22 (connection refused).")
        );
    }

    #[test]
    fn review_of_follows_the_window_decision() {
        assert_eq!(review_of(ApprovalDecision::Allow), Some(McpReview::Approved));
        assert_eq!(review_of(ApprovalDecision::Deny), Some(McpReview::Refused));
        assert_eq!(review_of(ApprovalDecision::TimedOut), Some(McpReview::NoAnswer));
        assert_eq!(review_of(ApprovalDecision::Cancel), None);
    }

    #[test]
    fn noting_owner_notes_declines_by_window() {
        let cases: [(QuestionKind, fn() -> Reply, Option<(McpStopKind, McpWindow)>); 5] = [
            (QuestionKind::Password, || Reply::Cancelled, Some((McpStopKind::Refused, McpWindow::Credentials))),
            (QuestionKind::Passphrase, || Reply::TimedOut, Some((McpStopKind::NoAnswer, McpWindow::Credentials))),
            (QuestionKind::Grant, || Reply::TimedOut, Some((McpStopKind::NoAnswer, McpWindow::Grant))),
            (QuestionKind::Grant, || Reply::Cancelled, Some((McpStopKind::Refused, McpWindow::Grant))),
            (QuestionKind::Interactive, || Reply::Gone, None),
        ];
        for (kind, reply, noted) in cases {
            let person = FakeOwner::answering(vec![reply()]);
            let declines = Declines::default();
            let owner = NotingOwner { inner: &person, declines: &declines };
            let _ = owner.ask(kind, "Question:", false, None);
            assert_eq!(declines.first(), noted, "{kind:?}");
        }

        let person = FakeOwner::answering(vec![Reply::Cancelled, Reply::TimedOut]);
        let declines = Declines::default();
        let owner = NotingOwner { inner: &person, declines: &declines };
        assert!(matches!(owner.ask(QuestionKind::Password, "Password:", false, None), Reply::Cancelled), "the reply is passed on");
        let _ = owner.ask(QuestionKind::Grant, "Grant:", true, None);
        assert_eq!(declines.first(), Some((McpStopKind::Refused, McpWindow::Credentials)), "the first decline stays");
    }
}
