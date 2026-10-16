//! Human-confirmed, public-only installation through the native SSH engine.
fn canonical(public: &str) -> Result<(String, String), String> {
    let key = ssh_key::PublicKey::from_openssh(public.trim())
        .map_err(|_| "Invalid public key identity.".to_string())?;
    let fingerprint = key.fingerprint(ssh_key::HashAlg::Sha256).to_string();
    let encoded = key
        .to_openssh()
        .map_err(|_| "Invalid public key encoding.".to_string())?;
    let text = encoded
        .split_whitespace()
        .take(2)
        .collect::<Vec<_>>()
        .join(" ");
    Ok((text, fingerprint))
}
fn script(public: &str) -> Result<String, String> {
    let (public, _) = canonical(public)?;
    let (algorithm, blob) = public
        .split_once(' ')
        .ok_or("Invalid public key identity.")?;
    let body = include_str!("deploy-script.sh")
        .replace("__ALGORITHM__", algorithm)
        .replace("__BLOB__", blob)
        .replace("__PUBLIC__", &public);
    // A POSIX installer even when the account's login shell is not sh; no local shell is launched.
    Ok(format!("sh -c '{}'", body.replace('\'', "'\\''")))
}
#[cfg(test)]
#[path = "deploy_tests.rs"]
mod tests;
#[cfg(all(test, any(target_os = "macos", target_os = "linux")))]
#[path = "deploy_ssh_tests.rs"]
mod ssh_tests;

use super::{
    auth::Owner,
    connect::{CancelToken, Connector},
    deadline::InteractionDeadline,
    protocol::HostQuery,
};
use crate::mcp::records::ApprovedTarget;
use crate::ssh::{Ended, ExecResult};
use serde::Serialize;
use std::{
    collections::BTreeMap,
    sync::{
        atomic::{AtomicU64, Ordering},
        Mutex,
    },
    time::Duration,
};

#[derive(Clone, Debug, Serialize)]
pub struct DeployPreview {
    pub id: String,
    pub host_id: String,
    pub key_id: String,
    pub alias: String,
    pub hostname: String,
    pub port: u16,
    pub user: String,
    pub route: Vec<String>,
    pub key_name: String,
    pub fingerprint: String,
    pub public_key: String,
}
#[derive(Clone)]
struct Reviewed {
    public: DeployPreview,
    target: ApprovedTarget,
    deadline: InteractionDeadline,
    cancel: CancelToken,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    Added,
    AlreadyPresent,
    StalePreview,
    Denied,
    Canceled,
    TimedOut,
    AuthAbandoned,
    HostKeyRefused,
    UnsupportedShell,
    RemoteFailed,
    ConnectionFailed,
    Unknown,
}
#[derive(Clone, Debug, Serialize)]
pub struct DeployResult {
    pub outcome: Outcome,
    pub audit_error: Option<String>,
}
impl From<Outcome> for DeployResult {
    fn from(outcome: Outcome) -> Self {
        Self {
            outcome,
            audit_error: None,
        }
    }
}
#[derive(Default)]
pub struct Deployments {
    next: AtomicU64,
    pending: Mutex<BTreeMap<String, Reviewed>>,
    active: Mutex<BTreeMap<String, CancelToken>>,
}

impl Deployments {
    fn preview(
        &self,
        connector: &Connector<'_>,
        host_id: &str,
        key_id: &str,
    ) -> Result<DeployPreview, String> {
        let target = connector
            .directory
            .resolve_public(&HostQuery::Id(host_id.into()))
            .map_err(|e| e.to_string())?;
        let approved = ApprovedTarget::capture(&target, connector.keys)?;
        let destination = target.hops.last().ok_or("No destination.")?;
        let key = connector
            .keys
            .key(key_id)
            .ok_or("The authoritative public key is unavailable.")?;
        let (public_key, fingerprint) = canonical(&key.public_key)?;
        let public = DeployPreview {
            id: format!("deploy-{}", self.next.fetch_add(1, Ordering::Relaxed)),
            host_id: destination.id.as_str().into(),
            key_id: key_id.into(),
            alias: destination.alias.clone(),
            hostname: destination.hostname.clone(),
            port: destination.port,
            user: destination.user.clone(),
            route: target
                .hops
                .iter()
                .map(|h| format!("{}@{}:{} ({})", h.user, h.hostname, h.port, h.alias))
                .collect(),
            key_name: key.name,
            fingerprint,
            public_key,
        };
        let mut pending = self.pending.lock().unwrap();
        pending.retain(|_, p| !p.deadline.expired() && !p.cancel.is_cancelled());
        if pending.len() >= 32 {
            return Err("Close unused deployment previews before opening another.".into());
        }
        pending.insert(
            public.id.clone(),
            Reviewed {
                public: public.clone(),
                target: approved,
                deadline: InteractionDeadline::after(Duration::from_secs(120)),
                cancel: CancelToken::default(),
            },
        );
        Ok(public)
    }
    fn take(&self, id: &str, authorized: bool) -> Result<(Reviewed, CancelToken), Outcome> {
        // Keep cancellation atomic with the transition from preview to active request.
        let mut pending = self.pending.lock().unwrap();
        let review = pending.remove(id).ok_or(Outcome::StalePreview)?;
        if !authorized {
            return Err(Outcome::Denied);
        }
        if review.cancel.is_cancelled() {
            return Err(Outcome::Canceled);
        }
        if review.deadline.expired() {
            return Err(Outcome::StalePreview);
        }
        let cancel = review.cancel.clone();
        self.active
            .lock()
            .unwrap()
            .insert(id.into(), cancel.clone());
        Ok((review, cancel))
    }
    fn cancel(&self, id: &str) {
        let pending = self.pending.lock().unwrap();
        if let Some(review) = pending.get(id) {
            review.cancel.cancel();
        }
        if let Some(cancel) = self.active.lock().unwrap().get(id) {
            cancel.cancel();
        }
    }
}
impl Reviewed {
    fn check(
        &self,
        connector: &Connector<'_>,
        cancel: &CancelToken,
        current: &(dyn Fn() -> Result<(), String> + Sync),
    ) -> Result<(), String> {
        if cancel.is_cancelled() {
            return Err("Deployment canceled.".into());
        }
        current()?;
        self.target
            .check(connector, &HostQuery::Id(self.public.host_id.clone()))?;
        let key = connector
            .keys
            .key(&self.public.key_id)
            .ok_or("The selected public key is unavailable.")?;
        if canonical(&key.public_key)?.0 != self.public.public_key {
            return Err("The selected public key changed.".into());
        }
        Ok(())
    }
}
struct Stop<'a>(&'a std::sync::atomic::AtomicBool);
impl Drop for Stop<'_> {
    fn drop(&mut self) {
        self.0.store(true, Ordering::SeqCst);
    }
}
struct ObservedOwner<'a> {
    inner: &'a dyn Owner,
    outcome: Mutex<Option<Outcome>>,
}
impl ObservedOwner<'_> {
    fn observe(&self, reply: super::auth::Reply) -> super::auth::Reply {
        use super::auth::Reply;
        let outcome = match &reply {
            Reply::TimedOut => Some(Outcome::TimedOut),
            Reply::Cancelled | Reply::Gone => Some(Outcome::AuthAbandoned),
            Reply::Answer(_) => None,
        };
        if outcome.is_some() {
            *self.outcome.lock().unwrap() = outcome;
        }
        reply
    }
}
impl Owner for ObservedOwner<'_> {
    fn ask(
        &self,
        k: super::protocol::QuestionKind,
        t: &str,
        e: bool,
        d: Option<std::time::Instant>,
    ) -> super::auth::Reply {
        self.observe(self.inner.ask(k, t, e, d))
    }
    fn ask_at(
        &self,
        h: &crate::ssh::HopRef,
        k: super::protocol::QuestionKind,
        t: &str,
        e: bool,
        d: Option<std::time::Instant>,
    ) -> super::auth::Reply {
        self.observe(self.inner.ask_at(h, k, t, e, d))
    }
    fn host_key_notice(&self, t: &str) {
        self.inner.host_key_notice(t)
    }
    fn banner(&self, t: &str) {
        self.inner.banner(t)
    }
}
/// Preserve typed connection timeouts without parsing server-derived error text.
struct ObservedEngine<'a> {
    inner: &'a dyn crate::ssh::SshEngine,
    timed_out: std::sync::atomic::AtomicBool,
}
impl crate::ssh::SshEngine for ObservedEngine<'_> {
    fn connect(
        &self,
        target: &crate::ssh::Target,
        pins: &dyn crate::ssh::HostKeyPolicy,
        auth: &dyn crate::ssh::AuthSource,
    ) -> Result<Box<dyn crate::ssh::Session>, crate::ssh::ConnectError> {
        let result = self.inner.connect(target, pins, auth);
        if matches!(&result, Err(crate::ssh::ConnectError::Timeout { .. })) {
            self.timed_out.store(true, Ordering::SeqCst);
        }
        result
    }
}
fn execute(
    review: &Reviewed,
    connector: &Connector<'_>,
    owner: &dyn Owner,
    cancel: &CancelToken,
    current: &(dyn Fn() -> Result<(), String> + Sync),
) -> DeployResult {
    use crate::mcp::records::{CheckedEngine, PublicDirectory};
    let check = || review.check(connector, cancel, current);
    let invalid = || {
        if cancel.is_cancelled() {
            Outcome::Canceled
        } else {
            Outcome::StalePreview
        }
    };
    if check().is_err() {
        return invalid().into();
    }
    let observed_engine = ObservedEngine {
        inner: connector.engine,
        timed_out: std::sync::atomic::AtomicBool::new(false),
    };
    let target_changed = std::sync::atomic::AtomicBool::new(false);
    let check_resolved = |actual: &crate::ssh::Target| {
        let result = review.target.check_resolved(actual, connector.keys);
        if result.is_err() {
            target_changed.store(true, Ordering::SeqCst);
        }
        result
    };
    let check_connected = |actual: &crate::ssh::Target| {
        check()?;
        let result = review.target.check_connected(actual, connector.keys);
        if result.is_err() {
            target_changed.store(true, Ordering::SeqCst);
        }
        result
    };
    let engine = CheckedEngine {
        inner: &observed_engine,
        check: &check_connected,
    };
    let directory = PublicDirectory(connector.directory, &check, &check_resolved);
    let guarded = Connector {
        engine: &engine,
        directory: &directory,
        keys: connector.keys,
        keychain: connector.keychain,
        confirmer: connector.confirmer,
    };
    let owner = ObservedOwner {
        inner: owner,
        outcome: Mutex::new(None),
    };
    let connected = match guarded.connect(
        &HostQuery::Id(review.public.host_id.clone()),
        &owner,
        cancel,
    ) {
        Ok(connected) => connected,
        Err(error) => {
            let outcome = if cancel.is_cancelled() {
                Outcome::Canceled
            } else if target_changed.load(Ordering::SeqCst) || check().is_err() {
                Outcome::StalePreview
            } else if let Some(outcome) = *owner.outcome.lock().unwrap() {
                outcome
            } else if observed_engine.timed_out.load(Ordering::SeqCst) {
                Outcome::TimedOut
            } else if error.kind == super::protocol::kinds::HOST_KEY {
                Outcome::HostKeyRefused
            } else if error.kind == super::protocol::kinds::AUTH {
                Outcome::AuthAbandoned
            } else {
                Outcome::ConnectionFailed
            };
            return outcome.into();
        }
    };
    if let Some(outcome) = *owner.outcome.lock().unwrap() {
        connected.session.close();
        return outcome.into();
    }
    if check_connected(&connected.target).is_err() {
        connected.session.close();
        return invalid().into();
    }
    let command = match script(&review.public.public_key) {
        Ok(command) => command,
        Err(_) => {
            connected.session.close();
            return Outcome::StalePreview.into();
        }
    };
    let done = std::sync::atomic::AtomicBool::new(false);
    let output = std::thread::scope(|scope| {
        scope.spawn(|| {
            while !done.load(Ordering::SeqCst) {
                if cancel.is_cancelled() {
                    connected.session.close();
                    break;
                }
                std::thread::sleep(Duration::from_millis(25));
            }
        });
        let _stop = Stop(&done);
        if cancel.is_cancelled() {
            return None;
        }
        Some(
            connected
                .session
                .exec(&command, Duration::from_secs(60), 8192),
        )
    });
    connected.session.close();
    if cancel.is_cancelled() {
        return Outcome::Canceled.into();
    }
    match output {
        Some(Ok(output)) => classify(&output).into(),
        Some(Err(crate::ssh::SessionError::Timeout { .. })) => Outcome::TimedOut.into(),
        _ => Outcome::Unknown.into(),
    }
}
fn classify(result: &ExecResult) -> Outcome {
    if result.ended == Ended::TimedOut {
        return Outcome::TimedOut;
    }
    if result.ended != Ended::Exited
        || result.truncated
        || result.signal.is_some()
        || result.exit_code.is_none()
    {
        return Outcome::Unknown;
    }
    match result.exit_code {
        Some(0) if result.stderr.is_empty() && result.stdout == b"SSHELTER_ADDED\n" => {
            Outcome::Added
        }
        Some(0) if result.stderr.is_empty() && result.stdout == b"SSHELTER_PRESENT\n" => {
            Outcome::AlreadyPresent
        }
        Some(0) => Outcome::Unknown,
        Some(69) | Some(126) | Some(127) => Outcome::UnsupportedShell,
        _ => Outcome::RemoteFailed,
    }
}

use crate::{error::AppError, state::AppState};
use std::sync::Arc;
use tauri::{AppHandle, Manager};

fn records_current(app: &AppHandle) -> Result<(), String> {
    crate::sync::engine::with_env(app, |env| {
        let _lifecycle = env.runtime.lifecycle.lock().unwrap();
        crate::sync::record_round::require_no_pending_migration(env)?;
        crate::sync::record_runtime::snapshot(env).map(|_| ())
    })
    .map_err(|e| e.to_string())?
    .map_err(|e| e.to_string())
}
fn broker(app: &AppHandle) -> Result<Arc<super::broker::Broker>, String> {
    let state = app.state::<AppState>();
    let broker = state.session.broker.lock().unwrap().clone();
    broker.ok_or("The native SSH service is unavailable.".into())
}
#[tauri::command]
pub async fn records_deploy_preview(
    app: AppHandle,
    host_id: String,
    key_id: String,
) -> Result<DeployPreview, AppError> {
    tauri::async_runtime::spawn_blocking(move || {
        records_current(&app).map_err(AppError::Other)?;
        let broker = broker(&app).map_err(AppError::Other)?;
        app.state::<AppState>()
            .session
            .deployments
            .preview(&broker.connector(), &host_id, &key_id)
            .map_err(AppError::Other)
    })
    .await
    .map_err(crate::sync::engine::join_error)?
}
#[tauri::command]
pub async fn records_deploy_confirm(
    app: AppHandle,
    preview_id: String,
    authorized: bool,
) -> Result<DeployResult, AppError> {
    tauri::async_runtime::spawn_blocking(move || {
        let state = app.state::<AppState>();
        let (review, cancel) = match state.session.deployments.take(&preview_id, authorized) {
            Ok(value) => value,
            Err(outcome) => return Ok(outcome.into()),
        };
        struct Active<'a>(&'a Deployments, String);
        impl Drop for Active<'_> {
            fn drop(&mut self) {
                self.0.active.lock().unwrap().remove(&self.1);
            }
        }
        let _active = Active(&state.session.deployments, preview_id.clone());
        let broker = broker(&app).map_err(AppError::Other)?;
        let _registered = match broker.register_deployment(cancel.clone()) {
            Ok(registration) => registration,
            Err(_) => return Ok(Outcome::Canceled.into()),
        };
        let owner = super::auth_window::NativeOwner {
            hub: state.session.auth_questions.clone(),
            surface: Arc::new(super::auth_window::TauriAuthSurface { app: app.clone() }),
            request_id: preview_id.clone(),
            cancel: cancel.clone(),
        };
        Ok(execute_recorded(
            &review,
            &broker.connector(),
            &owner,
            &cancel,
            &|| records_current(&app),
            &state.mcp,
        ))
    })
    .await
    .map_err(crate::sync::engine::join_error)?
}
#[tauri::command]
pub fn records_deploy_cancel(app: AppHandle, preview_id: String) {
    app.state::<AppState>()
        .session
        .deployments
        .cancel(&preview_id);
}
fn unix_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}
fn audit(
    runtime: &crate::mcp::McpRuntime,
    preview: &DeployPreview,
    result: &DeployResult,
    started: u64,
) -> Option<String> {
    let outcome = serde_json::to_value(result.outcome)
        .ok()
        .and_then(|v| v.as_str().map(str::to_owned))
        .unwrap_or_else(|| "unknown".into());
    runtime.record_deployment(crate::mcp::McpAuditEntry {
        client: "deploy".into(),
        host_id: Some(preview.host_id.clone()),
        ended: Some(outcome.clone()),
        signal: None,
        mode: crate::mcp::ApprovalMode::Ask,
        requested_by: vec!["Lunport Keys".into()],
        requester_id: None,
        client_info: Default::default(),
        at_ms: started,
        id: preview.id.clone(),
        alias: preview.alias.clone(),
        command: format!("Deploy public key {}", preview.fingerprint),
        outcome,
        exit_code: matches!(result.outcome, Outcome::Added | Outcome::AlreadyPresent).then_some(0),
        detail: None,
        completed_at_ms: unix_ms(),
    })
}

fn execute_recorded(
    review: &Reviewed,
    connector: &Connector<'_>,
    owner: &dyn Owner,
    cancel: &CancelToken,
    current: &(dyn Fn() -> Result<(), String> + Sync),
    runtime: &crate::mcp::McpRuntime,
) -> DeployResult {
    let started = unix_ms();
    let mut result = execute(review, connector, owner, cancel, current);
    result.audit_error = audit(runtime, &review.public, &result, started);
    result
}
