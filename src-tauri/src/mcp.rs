//! MCP stdio adapter backed by the OS-authenticated session IPC broker.
//!
//! The adapter owns no credentials and executes no SSH. Records tools use protocol 2
//! on the session socket or named pipe. The token-authenticated loopback transport
//! is retained only after the broker explicitly confirms Legacy workspace mode.

use crate::session::deadline::InteractionDeadline;
use std::collections::{BTreeSet, HashMap, HashSet, VecDeque};
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{Ipv4Addr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use tauri::{AppHandle, Emitter, Manager};

use crate::config::dto::host_summaries;
use crate::config::intel::effective_config;
use crate::connect::validate_alias;
use crate::error::AppError;
use crate::fsutil;
use crate::state::AppState;

pub(crate) mod records;
mod adapter;
mod management;
mod permissions;
pub use records::RequestContext;

const MCP_PROTOCOL_VERSION: &str = "2025-06-18";
const MAX_BRIDGE_LINE: u64 = 1_048_576;
const MAX_COMMAND_BYTES: usize = 16_384;
const MAX_STREAM_BYTES: usize = 65_536;
const APPROVAL_TIMEOUT: Duration = Duration::from_secs(120);

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct McpPolicy {
    enabled: bool,
    #[serde(default)]
    allowed_hosts: BTreeSet<String>,
    #[serde(default)]
    allowed_groups: BTreeSet<String>,
    #[serde(default)]
    approval_mode: ApprovalMode,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(test, derive(ts_rs::TS))]
#[cfg_attr(test, ts(export, export_to = "../../src/bindings/"))]
pub enum ApprovalMode { #[default] Ask, AutoLog }

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(test, derive(ts_rs::TS))]
#[cfg_attr(test, ts(export, export_to = "../../src/bindings/"))]
pub struct McpClientInfo { pub name: Option<String>, pub title: Option<String>, pub version: Option<String> }
impl McpClientInfo {
    pub fn sanitize(value: Option<&Value>) -> Self {
        let field = |key| value.and_then(|v|v.get(key)).and_then(Value::as_str).map(|s| s.chars().filter(|c|!c.is_control() && !crate::session::auth::is_deceptive_format(*c)).take(100).collect());
        Self { name:field("name"), title:field("title"), version:field("version") }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct RuntimeInfo {
    port: u16,
    token: String,
    pid: u32,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[cfg_attr(test, derive(ts_rs::TS))]
#[cfg_attr(test, ts(export, export_to = "../../src/bindings/"))]
pub struct McpPendingRequest {
    #[serde(default)]
    #[cfg_attr(test, ts(optional = nullable))]
    pub host_proposal: Option<McpHostProposal>,
    #[serde(default)] pub host_id: Option<String>,
    #[serde(default)] pub route: Vec<String>,
    #[serde(default)] pub requested_by: Vec<String>,
    #[serde(default)] pub requester_id: Option<String>,
    #[serde(default)] pub client_info: McpClientInfo,
    pub id: String,
    pub alias: String,
    pub command: String,
    pub hostname: Option<String>,
    pub user: Option<String>,
    pub port: Option<String>,
    #[cfg_attr(test, ts(type = "number"))]
    pub requested_at_ms: u64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[cfg_attr(test, derive(ts_rs::TS))]
#[cfg_attr(test, ts(export, export_to = "../../src/bindings/"))]
pub struct McpAuditEntry {
    #[serde(default)] pub client: String,
    #[serde(default)] pub host_id: Option<String>,
    #[serde(default)] pub ended: Option<String>,
    #[serde(default)] pub signal: Option<String>,
    #[serde(default)] pub mode: ApprovalMode,
    #[serde(default)] pub requested_by: Vec<String>,
    #[serde(default)] pub requester_id: Option<String>,
    #[serde(default)] pub client_info: McpClientInfo,
    #[serde(default)]
    #[cfg_attr(test, ts(type = "number"))]
    pub at_ms: u64,
    pub id: String,
    pub alias: String,
    pub command: String,
    pub outcome: String,
    #[cfg_attr(test, ts(type = "number | null"))]
    pub exit_code: Option<i64>,
    pub detail: Option<String>,
    #[cfg_attr(test, ts(type = "number"))]
    pub completed_at_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(test, derive(ts_rs::TS))]
#[cfg_attr(test, ts(export, export_to = "../../src/bindings/"))]
pub struct McpStatus {
    pub noninteractive_credentials_supported: bool,
    pub noninteractive_credentials_notice: String,
    pub approval_mode: ApprovalMode,
    pub audit_error: Option<String>,
    pub enabled: bool,
    pub bridge_active: bool,
    pub allowed_hosts: Vec<String>,
    pub allowed_groups: Vec<String>,
    pub pending: Vec<McpPendingRequest>,
    pub recent: Vec<McpAuditEntry>,
    pub executable: String,
    #[cfg_attr(test, ts(type = "number | null"))]
    pub last_client_at_ms: Option<u64>,
}

struct PendingApproval {
    deadline: InteractionDeadline,
    request: McpPendingRequest,
    decision: mpsc::SyncSender<ApprovalDecision>,
}

/// What kind of change a proposal asks the person to approve (design 2026-10-26, AI edits): the window words each kind.
pub mod proposal_kinds {
    pub const CREATE_HOST: &str = "create_host";
    pub const UPDATE_HOST: &str = "update_host";
    pub const SET_TRANSPORT: &str = "set_transport";
    pub const REMOVE_TRANSPORT: &str = "remove_transport";
}

fn create_host_kind() -> String {
    proposal_kinds::CREATE_HOST.to_string()
}

/// A change the client proposes, as the window shows it: its kind and its rows (a label and a value; a changed field's value reads
/// `old → new`). No secret is ever a row.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(test, derive(ts_rs::TS))]
#[cfg_attr(test, ts(export, export_to = "../../src/bindings/"))]
pub struct McpHostProposal {
    #[serde(default = "create_host_kind")]
    pub kind: String,
    pub settings: Vec<(String, String)>,
}

#[derive(Debug, Clone, Copy)]
enum ApprovalDecision {
    Allow,
    Deny,
    Cancel,
    TimedOut,
}

#[derive(Default)]
struct CancellationState {
    active: HashMap<String, Arc<AtomicBool>>,
    early: HashSet<String>,
}

/// Runtime state shared by Tauri commands and loopback bridge workers.
pub struct McpRuntime {
    policy: Mutex<McpPolicy>,
    audit: Mutex<records::AuditLog>,
    records_active:Mutex<HashMap<String,(String,crate::session::connect::CancelToken)>>,
    pending: Mutex<HashMap<String, PendingApproval>>,
    recent: Mutex<VecDeque<McpAuditEntry>>,
    cancellations: Mutex<CancellationState>,
    /// This instance's bridge (port, token, pid): what it wrote to `mcp-runtime.json`.
    bridge: Mutex<Option<RuntimeInfo>>,
    bridge_start: Mutex<()>,
    bridge_active: AtomicBool,
    pub keep_alive: AtomicBool,
    next_request_id: AtomicU64,
    last_client_at_ms: AtomicU64,
}

impl Default for McpRuntime {
    fn default() -> Self {
        Self {
            policy: Mutex::new(McpPolicy::default()),
            audit: Mutex::new(records::AuditLog::default()),
            records_active:Mutex::new(HashMap::new()),
            pending: Mutex::new(HashMap::new()),
            recent: Mutex::new(VecDeque::new()),
            cancellations: Mutex::new(CancellationState::default()),
            bridge: Mutex::new(None),
            bridge_start: Mutex::new(()),
            bridge_active: AtomicBool::new(false),
            keep_alive: AtomicBool::new(false),
            next_request_id: AtomicU64::new(1),
            last_client_at_ms: AtomicU64::new(0),
        }
    }
}

const AUDIT_READ_LIMIT: u64 = 32 * 1024 * 1024;

fn read_audit_bytes(reader: impl std::io::Read) -> std::io::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    reader.take(AUDIT_READ_LIMIT + 1).read_to_end(&mut bytes)?;
    Ok(bytes)
}

impl McpRuntime {
    fn status(&self) -> McpStatus {
        let policy = self.policy.lock().unwrap().clone();
        let mut pending: Vec<_> = self
            .pending
            .lock()
            .unwrap()
            .values()
            .map(|p| p.request.clone())
            .collect();
        pending.sort_by_key(|p| p.requested_at_ms);
        let recent = self.recent.lock().unwrap().iter().take(10).cloned().collect();
        let last = self.last_client_at_ms.load(Ordering::Relaxed);
        McpStatus {
            noninteractive_credentials_supported: cfg!(windows),
            noninteractive_credentials_notice: if cfg!(windows) { "Windows stored credentials support noninteractive Auto-log reads. Missing or locked credentials still require Ask." } else { "This platform cannot guarantee noninteractive credential reads. Credential-dependent requests require Ask." }.into(),
            approval_mode: policy.approval_mode,
            audit_error: self.audit.lock().unwrap().error.clone(),
            enabled: policy.enabled,
            bridge_active: self.bridge_active.load(Ordering::Relaxed),
            allowed_hosts: policy.allowed_hosts.into_iter().collect(),
            allowed_groups: vec![],
            pending,
            recent,
            executable: std::env::current_exe()
                .map(|p| p.to_string_lossy().into_owned())
                .unwrap_or_else(|_| "sshelter".to_string()),
            last_client_at_ms: (last != 0).then_some(last),
        }
    }

    pub(crate) fn record(&self, entry: McpAuditEntry) {
        let _ = self.record_result(entry);
    }
    fn record_result(&self, mut entry: McpAuditEntry) -> Option<String> {
        entry.detail = None;
        if entry.at_ms == 0 { entry.at_ms = entry.completed_at_ms; }
        if entry.client.is_empty() { entry.client = "mcp".into(); }
        let mut audit = self.audit.lock().unwrap();
        let mut recent = self.recent.lock().unwrap();
        recent.push_front(entry);
        recent.truncate(1000);
        let result = audit.path.as_ref().map(|path| {
            let mut bytes = Vec::new();
            for item in recent.iter().rev() {
                let mut item = item.clone();
                item.detail = None;
                serde_json::to_writer(&mut bytes, &item).map_err(|_| "Cannot encode session log".to_string())?;
                bytes.push(b'\n');
            }
            fsutil::atomic_write(path, &bytes, 0o600).map_err(|_| "Session log could not be saved; completed execution was not retried.".to_string())
        }).transpose();
        let error = result.err();
        if let Some(error) = &error { audit.error = Some(error.clone()); }
        error
    }
    /// Returns this request's persistence result while holding the audit serialization lock.
    pub(crate) fn record_deployment(&self, entry: McpAuditEntry) -> Option<String> {
        self.record_result(entry)
    }
    fn load_audit(&self,path:PathBuf) {
        let mut audit=self.audit.lock().unwrap();audit.path=Some(path.clone());
        match std::fs::File::open(&path).and_then(read_audit_bytes) {
            Ok(bytes) if bytes.len() as u64 <= AUDIT_READ_LIMIT=>{
                let mut entries=VecDeque::new();let lines=bytes.split(|b|*b==b'\n').collect::<Vec<_>>();
                for (i,line) in lines.iter().enumerate(){if line.is_empty(){continue;}match serde_json::from_slice::<McpAuditEntry>(line){Ok(mut entry)=>{entry.detail=None;entries.push_front(entry);entries.truncate(1000);},Err(_)=>{audit.error=Some(if i==lines.len()-1 && !bytes.ends_with(b"\n"){"Partial trailing session-log entry was ignored."}else{"Session log contains a corrupt entry; valid entries were retained."}.into());}}}
                *self.recent.lock().unwrap()=entries;
            }
            Ok(_)=>audit.error=Some("Session log exceeds the 32 MiB read limit.".into()),
            Err(e) if e.kind()==std::io::ErrorKind::NotFound=>{},
            Err(_)=>audit.error=Some("Session log could not be read.".into()),
        }
    }

    fn resolve_approval(&self, request_id: &str, allow: bool) -> Result<(), AppError> {
        let mut waiting = self.pending.lock().unwrap();
        let pending = waiting
            .remove(request_id)
            .ok_or_else(|| AppError::NotFound("MCP request already resolved or expired".into()))?;
        if pending.deadline.expired() {
            let _ = pending.decision.try_send(ApprovalDecision::TimedOut);
            return Err(AppError::NotFound(
                "MCP request already resolved or expired".into(),
            ));
        }
        pending
            .decision
            .try_send(if allow {
                ApprovalDecision::Allow
            } else {
                ApprovalDecision::Deny
            })
            .map_err(|_| AppError::Other("MCP client disconnected".into()))
    }
    fn wait_approval(
        &self,
        request: &McpPendingRequest,
        cancel: &crate::session::connect::CancelToken,
        timeout: Duration,
        publish: impl FnOnce(),
    ) -> ApprovalDecision {
        if cancel.is_cancelled() {
            return ApprovalDecision::Cancel;
        }
        let deadline = InteractionDeadline::after(timeout);
        let (tx, rx) = mpsc::sync_channel(1);
        self.pending.lock().unwrap().insert(
            request.id.clone(),
            PendingApproval {
                deadline,
                request: request.clone(),
                decision: tx,
            },
        );
        publish();
        let decision = receive_approval(&rx, cancel, deadline, &|| {
            (Instant::now(), SystemTime::now())
        });
        self.pending.lock().unwrap().remove(&request.id);
        decision
    }
    fn cancel_records(&self,host:Option<&str>){
        for (id,cancel) in self.records_active.lock().unwrap().values(){if host.is_none_or(|h|h==id){cancel.cancel();}}
    }
    fn deny_all_pending(&self) {
        let pending: Vec<_> = self
            .pending
            .lock()
            .unwrap()
            .drain()
            .map(|(_, p)| p)
            .collect();
        for request in pending {
            let _ = request.decision.send(ApprovalDecision::Deny);
        }
    }

    fn register_request(&self, id: &str) -> Result<Arc<AtomicBool>, String> {
        let mut cancellations = self.cancellations.lock().unwrap();
        if cancellations.early.remove(id) {
            return Err("MCP request was canceled".to_string());
        }
        if cancellations.active.contains_key(id) {
            return Err("duplicate MCP request id".to_string());
        }
        let flag = Arc::new(AtomicBool::new(false));
        cancellations.active.insert(id.to_string(), flag.clone());
        Ok(flag)
    }

    fn finish_request(&self, id: &str) {
        self.cancellations.lock().unwrap().active.remove(id);
    }

    fn cancel_request(&self, id: &str) -> bool {
        let active = {
            let mut cancellations = self.cancellations.lock().unwrap();
            if let Some(flag) = cancellations.active.get(id) {
                flag.store(true, Ordering::Relaxed);
                true
            } else {
                // Covers cancellation racing just ahead of request registration.
                if cancellations.early.len() >= 256 {
                    cancellations.early.clear();
                }
                cancellations.early.insert(id.to_string());
                false
            }
        };
        let pending = self.pending.lock().unwrap().remove(id);
        if let Some(pending) = pending {
            let _ = pending.decision.send(ApprovalDecision::Cancel);
            true
        } else {
            active
        }
    }
}

struct ActiveRequestGuard<'a> {
    runtime: &'a McpRuntime,
    id: &'a str,
}

impl Drop for ActiveRequestGuard<'_> {
    fn drop(&mut self) {
        self.runtime.finish_request(self.id);
    }
}

fn unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

fn policy_path() -> Result<PathBuf, AppError> {
    Ok(crate::fsutil::app_data_root()?.join("mcp-policy.json"))
}

fn runtime_path() -> Result<PathBuf, AppError> {
    Ok(crate::fsutil::app_data_root()?.join("mcp-runtime.json"))
}

fn load_policy() -> Result<McpPolicy, AppError> {
    let path = policy_path()?;
    match std::fs::read(&path) {
        Ok(bytes) => serde_json::from_slice(&bytes)
            .map_err(|e| AppError::Other(format!("invalid MCP policy: {e}"))),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(McpPolicy::default()),
        Err(e) => Err(AppError::Io(e)),
    }
}

fn save_policy(policy: &McpPolicy) -> Result<(), AppError> {
    let bytes = serde_json::to_vec_pretty(policy)
        .map_err(|e| AppError::Other(format!("cannot serialize MCP policy: {e}")))?;
    fsutil::atomic_write(&policy_path()?, &bytes, 0o600)
}

/// Load policy and start the authenticated local bridge for a desktop app instance.
pub fn initialize(app: &AppHandle, keep_alive: bool) -> Result<(), AppError> {
    let state = app.state::<AppState>();
    // A corrupt policy must fail closed without preventing Lunport from opening.
    *state.mcp.policy.lock().unwrap() = load_policy().unwrap_or_default();
    state.mcp.load_audit(fsutil::app_data_root()?.join("session-log.jsonl"));
    state.mcp.keep_alive.store(keep_alive, Ordering::Relaxed);
    Ok(())
}

fn random_token() -> Result<String, AppError> {
    let mut bytes = [0_u8; 32];
    getrandom::fill(&mut bytes)
        .map_err(|e| AppError::Other(format!("cannot create MCP bridge token: {e}")))?;
    Ok(bytes.iter().map(|b| format!("{b:02x}")).collect())
}

pub(super) fn ensure_legacy_bridge(app:&AppHandle)->Result<(),String>{
    let state=app.state::<AppState>();let _start=state.mcp.bridge_start.lock().unwrap();
    crate::sync::engine::require_legacy(&state.sync).map_err(|e|e.to_string())?;
    if !state.mcp.bridge_active.load(Ordering::Relaxed){start_bridge(app.clone()).map_err(|e|e.to_string())?;}Ok(())
}

fn start_bridge(app: AppHandle) -> Result<(), AppError> {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
    let info = RuntimeInfo {
        port: listener.local_addr()?.port(),
        token: random_token()?,
        pid: std::process::id(),
    };
    write_runtime_info(&info)?;

    {
        let state = app.state::<AppState>();
        *state.mcp.bridge.lock().unwrap() = Some(info);
        state.mcp.bridge_active.store(true, Ordering::Relaxed);
    }

    thread::Builder::new()
        .name("sshelter-mcp-bridge".to_string())
        .spawn(move || {
            for incoming in listener.incoming() {
                match incoming {
                    Ok(stream) => {
                        let app = app.clone();
                        let _ = thread::Builder::new()
                            .name("sshelter-mcp-request".to_string())
                            .spawn(move || handle_bridge_connection(app, stream));
                    }
                    // A failed accept (a connection aborted before it was accepted, no free file
                    // descriptors) does not end the bridge: only one Lunport runs, so no other
                    // instance would take over.
                    Err(_) => thread::sleep(Duration::from_millis(100)),
                }
            }
        })
        .map_err(AppError::Io)?;
    Ok(())
}

/// `mcp-runtime.json` tells `--mcp` adapters which bridge to connect to and how to authenticate.
fn write_runtime_info(info: &RuntimeInfo) -> Result<(), AppError> {
    let bytes = serde_json::to_vec(info)
        .map_err(|e| AppError::Other(format!("cannot serialize MCP runtime info: {e}")))?;
    fsutil::atomic_write(&runtime_path()?, &bytes, 0o600)
}

/// A second `--mcp-host` launch was handed over to this instance (single instance, lib.rs): its
/// adapter could not reach the bridge named in `mcp-runtime.json`. Point the file at this
/// instance's bridge again, so the waiting adapter finds it.
pub fn republish_bridge(app: &AppHandle) {
    let info = app.state::<AppState>().mcp.bridge.lock().unwrap().clone();
    // No bridge yet: this instance is still starting, and `start_bridge` writes the file.
    if let Some(info) = info {
        if let Err(e) = write_runtime_info(&info) {
            eprintln!("[mcp] cannot rewrite the MCP runtime file: {e}");
        }
    }
}

/// This instance is exiting: remove `mcp-runtime.json` if it still names this process, so
/// adapters stop trying a bridge that is gone. A file another process wrote is left alone.
pub fn forget_bridge(app: &AppHandle) {
    let Some(info) = app.state::<AppState>().mcp.bridge.lock().unwrap().clone() else {
        return;
    };
    let removed = runtime_path()
        .map_err(|e| e.to_string())
        .and_then(|path| remove_runtime_file_if_owned(&path, info.pid).map_err(|e| e.to_string()));
    if let Err(e) = removed {
        eprintln!("[mcp] cannot remove the MCP runtime file: {e}");
    }
}

fn remove_runtime_file_if_owned(path: &Path, pid: u32) -> std::io::Result<bool> {
    crate::fsutil::check_write_io(path)?;
    let bytes = match std::fs::read(path) {
        Ok(bytes) => bytes,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(e) => return Err(e),
    };
    if !runtime_file_names(&bytes, pid) {
        return Ok(false);
    }
    match std::fs::remove_file(path) {
        Ok(()) => Ok(true),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(e),
    }
}

/// Whether the contents of `mcp-runtime.json` name the process `pid`. Unreadable contents name
/// nobody.
fn runtime_file_names(contents: &[u8], pid: u32) -> bool {
    serde_json::from_slice::<RuntimeInfo>(contents).is_ok_and(|info| info.pid == pid)
}

#[derive(Debug, Deserialize, Serialize)]
struct BridgeEnvelope {
    token: String,
    method: String,
    #[serde(default)]
    params: Value,
}

#[derive(Debug, Deserialize, Serialize)]
struct BridgeResponse {
    ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    result: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

fn handle_bridge_connection(app: AppHandle, mut stream: TcpStream) {
    let cloned = match stream.try_clone() {
        Ok(s) => s,
        Err(_) => return,
    };
    let mut reader = BufReader::new(cloned).take(MAX_BRIDGE_LINE + 1);
    let mut line = String::new();
    let response = match reader.read_line(&mut line) {
        Ok(n) if n as u64 <= MAX_BRIDGE_LINE => match serde_json::from_str::<BridgeEnvelope>(&line)
        {
            Ok(envelope) => {
                let completed = Arc::new(AtomicBool::new(false));
                if envelope.method == "run" {
                    if let Some(id) = envelope
                        .params
                        .get("_request_id")
                        .and_then(Value::as_str)
                        .map(str::to_string)
                    {
                        if let Ok(monitor_stream) = stream.try_clone() {
                            let monitor_app = app.clone();
                            let monitor_completed = completed.clone();
                            let _ = thread::Builder::new()
                                .name("sshelter-mcp-disconnect".to_string())
                                .spawn(move || {
                                    monitor_bridge_disconnect(
                                        monitor_app,
                                        monitor_stream,
                                        id,
                                        monitor_completed,
                                    )
                                });
                        }
                    }
                }
                let result = dispatch_bridge(&app, envelope);
                completed.store(true, Ordering::Relaxed);
                result
            }
            Err(e) => Err(format!("invalid bridge request: {e}")),
        },
        Ok(_) => Err("bridge request too large".to_string()),
        Err(e) => Err(format!("cannot read bridge request: {e}")),
    };
    let response = match response {
        Ok(result) => BridgeResponse {
            ok: true,
            result: Some(result),
            error: None,
        },
        Err(error) => BridgeResponse {
            ok: false,
            result: None,
            error: Some(error),
        },
    };
    if serde_json::to_writer(&mut stream, &response).is_ok() {
        let _ = stream.write_all(b"\n");
        let _ = stream.flush();
    }
}

fn monitor_bridge_disconnect(
    app: AppHandle,
    mut stream: TcpStream,
    request_id: String,
    completed: Arc<AtomicBool>,
) {
    let _ = stream.set_read_timeout(Some(Duration::from_millis(250)));
    let mut byte = [0_u8; 1];
    while !completed.load(Ordering::Relaxed) {
        match stream.read(&mut byte) {
            Ok(0) => {
                app.state::<AppState>().mcp.cancel_request(&request_id);
                return;
            }
            Ok(_) => {}
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) => {}
            Err(_) => {
                app.state::<AppState>().mcp.cancel_request(&request_id);
                return;
            }
        }
    }
}

fn dispatch_bridge(app: &AppHandle, envelope: BridgeEnvelope) -> Result<Value, String> {
    let state = app.state::<AppState>();
    let authorized = state
        .mcp
        .bridge
        .lock()
        .unwrap()
        .as_ref()
        .is_some_and(|bridge| bridge.token == envelope.token);
    if !authorized {
        return Err("unauthorized local MCP bridge request".to_string());
    }
    state
        .mcp
        .last_client_at_ms
        .store(unix_ms(), Ordering::Relaxed);

    crate::sync::engine::require_legacy(&state.sync).map_err(|e|e.to_string())?;

    if envelope.method == "ping" {
        return Ok(json!({ "status": "ok" }));
    }
    if envelope.method == "cancel" {
        let request_id = string_param(&envelope.params, "request_id")?;
        return Ok(json!({ "canceled": state.mcp.cancel_request(request_id) }));
    }

    let policy = state.mcp.policy.lock().unwrap().clone();
    if !policy.enabled {
        return Err("MCP access is disabled in Lunport Settings → AI Access".to_string());
    }

    match envelope.method.as_str() {
        "list_hosts" => {
            let _lifecycle=state.sync.lifecycle.lock().unwrap();
            crate::sync::engine::require_legacy(&state.sync).map_err(|e|e.to_string())?;
            let doc = wait_for_loaded_doc(&state)?;
            let hosts: Vec<_> = host_summaries(&doc)
                .into_iter()
                .filter(|h| policy.allowed_hosts.contains(&h.alias))
                .collect();
            Ok(json!({ "hosts": hosts }))
        }
        "get_effective_config" => {
            let _lifecycle=state.sync.lifecycle.lock().unwrap();
            crate::sync::engine::require_legacy(&state.sync).map_err(|e|e.to_string())?;
            let alias = string_param(&envelope.params, "alias")?;
            ensure_allowed(&policy, alias)?;
            let doc = wait_for_loaded_doc(&state)?;
            validate_alias(&doc, alias).map_err(|e| e.to_string())?;
            let main_path = doc.files.first().map(|f| f.path.clone());
            let config =
                effective_config(alias, main_path.as_deref()).map_err(|e| e.to_string())?;
            let safe: Vec<_> = config
                .into_iter()
                .filter(|(key, _)| {
                    matches!(
                        key.as_str(),
                        "hostname" | "user" | "port" | "proxyjump" | "identitiesonly"
                    )
                })
                .map(|(key, value)| json!({ "key": key, "value": value }))
                .collect();
            Ok(json!({ "alias": alias, "config": safe }))
        }
        "run" => run_approved(app, &state, &policy, &envelope.params),
        _ => Err(format!("unknown bridge method: {}", envelope.method)),
    }
}

/// MCP sees endpoint and routing metadata, never notes or arbitrary imported directive values.
#[cfg(test)]
fn record_host_metadata(host: &crate::sync::records_v3::HostRecord) -> Value {
    json!({
        "id": host.id,
        "scope": host.scope,
        "alias": host.payload.alias,
        "hostname": host.payload.hostname,
        "port": host.payload.port,
        "user": host.payload.user,
        "jump_ids": host.payload.jump,
        "auth": host.payload.auth,
        "key_id": host.payload.key_id,
    })
}
fn string_param<'a>(params: &'a Value, key: &str) -> Result<&'a str, String> {
    params
        .get(key)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| format!("missing or empty '{key}'"))
}

fn wait_for_loaded_doc(state: &AppState) -> Result<crate::config::model::SshConfigDoc, String> {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if let Some(doc) = state.doc.lock().unwrap().clone() {
            return Ok(doc);
        }
        if Instant::now() >= deadline {
            return Err("SSH config is not loaded yet".to_string());
        }
        thread::sleep(Duration::from_millis(50));
    }
}

fn ensure_allowed(policy: &McpPolicy, alias: &str) -> Result<(), String> {
    if !policy.allowed_hosts.contains(alias) {
        return Err(format!("host '{alias}' is not allowed for AI access"));
    }
    Ok(())
}

#[cfg(test)]
fn ensure_record_allowed(policy: &McpPolicy, host: &crate::sync::records_v3::HostRecord) -> Result<(), String> {
    ensure_allowed(policy, &host.id)
}

fn change_host_permission(
    policy: &Mutex<McpPolicy>,
    target: &str,
    allowed: bool,
    validate: impl FnOnce() -> Result<(), AppError>,
    persist: impl FnOnce(&McpPolicy) -> Result<(), AppError>,
) -> Result<(), AppError> {
    if allowed { validate()?; }
    let mut policy = policy.lock().unwrap();
    let mut next = policy.clone();
    if allowed { next.allowed_hosts.insert(target.into()); }
    else { next.allowed_hosts.remove(target); }
    persist(&next)?;
    *policy = next;
    Ok(())
}

fn display_safe_command(command: &str) -> bool {
    !command.is_empty()
        && command.len() <= MAX_COMMAND_BYTES
        && !command.chars().any(|c|(c.is_control() && c != '\n' && c != '\t') || crate::session::auth::is_deceptive_format(c))
        && !command.chars().any(|c| {
            matches!(
                c,
                '\u{202a}'
                    | '\u{202b}'
                    | '\u{202d}'
                    | '\u{202e}'
                    | '\u{202c}'
                    | '\u{2066}'
                    | '\u{2067}'
                    | '\u{2068}'
                    | '\u{2069}'
            )
        })
}

fn run_approved(
    app: &AppHandle,
    state: &AppState,
    policy: &McpPolicy,
    params: &Value,
) -> Result<Value, String> {
    let _lifecycle=state.sync.lifecycle.lock().unwrap();
    if state.sync.core.lock().unwrap().records.is_some() {
        return Err("MCP remote command execution is not available in the records workspace yet".into());
    }
    crate::sync::engine::require_legacy(&state.sync).map_err(|e|e.to_string())?;
    crate::app_profile::CURRENT.require_legacy_ssh().map_err(str::to_string)?;
    drop(_lifecycle);
    let alias = string_param(params, "alias")?.to_string();
    let command = string_param(params, "command")?.to_string();
    if !display_safe_command(&command) {
        return Err("command is empty, too large, contains NUL, or contains bidirectional control characters".to_string());
    }
    ensure_allowed(policy, &alias)?;
    let timeout_seconds = params
        .get("timeout_seconds")
        .and_then(Value::as_u64)
        .unwrap_or(60)
        .clamp(1, 300);

    let (config_path, identity) = {
        let doc = wait_for_loaded_doc(state)?;
        validate_alias(&doc, &alias).map_err(|e| e.to_string())?;
        let main_path = doc.files.first().map(|f| f.path.clone());
        let effective =
            effective_config(&alias, main_path.as_deref()).map_err(|e| e.to_string())?;
        for (key, value) in &effective {
            let active = !value.eq_ignore_ascii_case("none") && !value.is_empty();
            if (key == "proxycommand" || key == "knownhostscommand") && active {
                return Err(format!(
                    "host '{alias}' uses {key}; local command hooks are not allowed for MCP execution"
                ));
            }
            if key == "permitlocalcommand" && value.eq_ignore_ascii_case("yes") {
                return Err(format!(
                    "host '{alias}' enables LocalCommand; local command hooks are not allowed for MCP execution"
                ));
            }
        }
        let value = |key: &str| {
            effective
                .iter()
                .find(|(k, _)| k == key)
                .map(|(_, v)| v.clone())
        };
        (main_path, (value("hostname"), value("user"), value("port")))
    };

    let id = params
        .get("_request_id")
        .and_then(Value::as_str)
        .filter(|id| !id.is_empty() && id.len() <= 160)
        .map(str::to_string)
        .unwrap_or_else(|| {
            format!(
                "mcp-{}-{}",
                std::process::id(),
                state.mcp.next_request_id.fetch_add(1, Ordering::Relaxed)
            )
        });
    let cancel_flag = state.mcp.register_request(&id)?;
    let _active_guard = ActiveRequestGuard {
        runtime: &state.mcp,
        id: &id,
    };
    let request = McpPendingRequest {
        id: id.clone(),
        alias: alias.clone(),
        command: command.clone(),
        hostname: identity.0,
        user: identity.1,
        port: identity.2,
        requested_at_ms: unix_ms(),
        ..Default::default()
    };
    let deadline=InteractionDeadline::after(APPROVAL_TIMEOUT);
    let (tx, rx) = mpsc::sync_channel(1);
    state.mcp.pending.lock().unwrap().insert(
        id.clone(),
        PendingApproval {
            deadline,
            request: request.clone(),
            decision: tx,
        },
    );
    // Cancellation can race between active-request registration and pending
    // approval insertion. Re-check the shared flag so that race still wakes
    // the approval waiter instead of leaving a stale dialog for 120 seconds.
    if cancel_flag.load(Ordering::Relaxed) {
        state.mcp.cancel_request(&id);
    }
    state.mcp.keep_alive.store(true, Ordering::Relaxed);

    // Also brings up the window of an MCP host that started in the background.
    crate::show_main_window(app);
    let _ = app.emit("mcp://approval-requested", &request);

    let decision=rx.recv_timeout(deadline.remaining());
    let decision=if deadline.expired(){Ok(ApprovalDecision::TimedOut)}else{decision};
    let approved = match decision {
        Ok(ApprovalDecision::Allow) => true,
        Ok(ApprovalDecision::Deny) => false,
        Ok(ApprovalDecision::Cancel) => {
            state.mcp.pending.lock().unwrap().remove(&id);
            state.mcp.record(McpAuditEntry {
                id: id.clone(),
                alias,
                command,
                outcome: "canceled".to_string(),
                exit_code: None,
                detail: Some("MCP client canceled or disconnected".to_string()),
                completed_at_ms: unix_ms(),
                ..Default::default()
            });
            return Err("MCP request was canceled".to_string());
        }
        Ok(ApprovalDecision::TimedOut) | Err(_) => {
            state.mcp.pending.lock().unwrap().remove(&id);
            state.mcp.record(McpAuditEntry {
                id: id.clone(),
                alias,
                command,
                outcome: "timed_out".to_string(),
                exit_code: None,
                detail: Some("No decision within 120 seconds".to_string()),
                completed_at_ms: unix_ms(),
                ..Default::default()
            });
            return Err("Lunport approval timed out".to_string());
        }
    };
    state.mcp.pending.lock().unwrap().remove(&id);
    if !approved {
        state.mcp.record(McpAuditEntry {
            id: id.clone(),
            alias,
            command,
            outcome: "denied".to_string(),
            exit_code: None,
            detail: None,
            completed_at_ms: unix_ms(),
            ..Default::default()
        });
        return Err("Denied in Lunport".to_string());
    }

    crate::sync::engine::require_legacy(&state.sync).map_err(|e|e.to_string())?;
    let current=state.mcp.policy.lock().unwrap().clone();
    if !current.enabled{return Err("MCP access was disabled".into());}ensure_allowed(&current,&alias)?;
    match execute_ssh(
        &alias,
        &command,
        config_path.as_deref(),
        timeout_seconds,
        &cancel_flag,
    ) {
        Ok(output) => {
            if output.canceled {
                state.mcp.record(McpAuditEntry {
                    id: id.clone(),
                    alias,
                    command,
                    outcome: "canceled".to_string(),
                    exit_code: output.exit_code.map(i64::from),
                    detail: Some("MCP client canceled or disconnected".to_string()),
                    completed_at_ms: unix_ms(),
                ..Default::default()
                });
                return Err("MCP request was canceled".to_string());
            }
            state.mcp.record(McpAuditEntry {
                id: id.clone(),
                alias,
                command,
                outcome: "allowed".to_string(),
                exit_code: output.exit_code.map(i64::from),
                detail: output
                    .timed_out
                    .then(|| "SSH command timed out".to_string()),
                completed_at_ms: unix_ms(),
                ..Default::default()
            });
            serde_json::to_value(output).map_err(|e| e.to_string())
        }
        Err(error) => {
            state.mcp.record(McpAuditEntry {
                id: id.clone(),
                alias,
                command,
                outcome: "failed".to_string(),
                exit_code: None,
                detail: Some(error.clone()),
                completed_at_ms: unix_ms(),
                ..Default::default()
            });
            Err(error)
        }
    }
}

#[derive(Debug, Serialize)]
struct RunOutput {
    alias: String,
    stdout: String,
    stderr: String,
    exit_code: Option<i32>,
    timed_out: bool,
    canceled: bool,
    stdout_truncated: bool,
    stderr_truncated: bool,
    #[serde(rename = "duration_ms")]
    duration_ms: u64,
}

fn drain_stream<R: Read>(mut reader: R) -> (Vec<u8>, bool) {
    let mut kept = Vec::new();
    let mut truncated = false;
    let mut buffer = [0_u8; 8_192];
    loop {
        match reader.read(&mut buffer) {
            Ok(0) | Err(_) => break,
            Ok(n) => {
                let remaining = MAX_STREAM_BYTES.saturating_sub(kept.len());
                kept.extend_from_slice(&buffer[..n.min(remaining)]);
                truncated |= n > remaining;
            }
        }
    }
    (kept, truncated)
}

fn execute_ssh(
    alias: &str,
    remote_command: &str,
    config_path: Option<&Path>,
    timeout_seconds: u64,
    canceled: &AtomicBool,
) -> Result<RunOutput, String> {
    crate::app_profile::CURRENT.require_legacy_ssh().map_err(str::to_string)?;
    let mut command = crate::process::background_command("ssh");
    if let Some(path) = config_path {
        command.arg("-F").arg(path);
    }
    command
        .arg("-o")
        .arg("BatchMode=yes")
        .arg("-o")
        .arg("ConnectTimeout=15")
        .arg("-o")
        .arg("ClearAllForwardings=yes")
        .arg("-o")
        .arg("ForwardAgent=no")
        .arg("-o")
        .arg("PermitLocalCommand=no")
        .arg("-o")
        .arg("RequestTTY=no")
        .arg("-o")
        .arg("KnownHostsCommand=none")
        .arg(alias)
        .arg(remote_command)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .env_remove("SSH_ASKPASS")
        .env_remove("SSH_ASKPASS_REQUIRE");

    let started = Instant::now();
    let mut child =
        crate::process::spawn(&mut command).map_err(|e| format!("cannot start ssh: {e}"))?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| "cannot capture ssh stdout".to_string())?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| "cannot capture ssh stderr".to_string())?;
    let stdout_reader = thread::spawn(move || drain_stream(stdout));
    let stderr_reader = thread::spawn(move || drain_stream(stderr));

    let deadline = started + Duration::from_secs(timeout_seconds);
    let (status, timed_out, was_canceled) = loop {
        match child.try_wait() {
            Ok(Some(status)) => break (status, false, canceled.load(Ordering::Relaxed)),
            Ok(None) if canceled.load(Ordering::Relaxed) => {
                let _ = child.kill();
                let status = child.wait().map_err(|e| format!("cannot reap ssh: {e}"))?;
                break (status, false, true);
            }
            Ok(None) if Instant::now() < deadline => thread::sleep(Duration::from_millis(50)),
            Ok(None) => {
                let _ = child.kill();
                let status = child.wait().map_err(|e| format!("cannot reap ssh: {e}"))?;
                break (status, true, false);
            }
            Err(e) => return Err(format!("cannot wait for ssh: {e}")),
        }
    };
    let (stdout, stdout_truncated) = stdout_reader
        .join()
        .map_err(|_| "ssh stdout reader panicked".to_string())?;
    let (stderr, stderr_truncated) = stderr_reader
        .join()
        .map_err(|_| "ssh stderr reader panicked".to_string())?;

    Ok(RunOutput {
        alias: alias.to_string(),
        stdout: String::from_utf8_lossy(&stdout).into_owned(),
        stderr: String::from_utf8_lossy(&stderr).into_owned(),
        exit_code: status.code(),
        timed_out,
        canceled: was_canceled,
        stdout_truncated,
        stderr_truncated,
        duration_ms: started.elapsed().as_millis() as u64,
    })
}

#[tauri::command]
pub fn mcp_status(state: tauri::State<AppState>) -> McpStatus {
    status_for(&state)
}
fn status_for(state:&AppState)->McpStatus{
    let mut status=state.mcp.status();
    {
        let core = state.sync.core.lock().unwrap();
        if let Ok(records) = crate::sync::record_runtime::active_state(&core) {
            status.allowed_groups = permissions::active_groups(&state.mcp.policy.lock().unwrap(), records);
        }
    }
    if state.sync.core.lock().unwrap().format==crate::sync::record_runtime::RuntimeFormat::Records {status.bridge_active=matches!(*state.session.status.lock().unwrap(),crate::session::app::BrokerStatus::Running);}
    status
}

fn change_approval_mode(policy:&Mutex<McpPolicy>,mode:ApprovalMode,acknowledged:bool,persist:impl FnOnce(&McpPolicy)->Result<(),AppError>)->Result<(),AppError>{
    let mut current=policy.lock().unwrap();
    if mode==ApprovalMode::AutoLog && current.approval_mode!=mode && !acknowledged{return Err(AppError::Other("Confirm the risk of allowing AI commands without per-command approval.".into()));}
    let mut next=current.clone();next.approval_mode=mode;persist(&next)?;*current=next;Ok(())
}
#[tauri::command]
pub fn mcp_set_approval_mode(state:tauri::State<AppState>,approval_mode:ApprovalMode,risk_acknowledged:bool)->Result<McpStatus,AppError>{
    change_approval_mode(&state.mcp.policy,approval_mode,risk_acknowledged,save_policy)?;
    state.mcp.cancel_records(None);state.mcp.deny_all_pending();Ok(status_for(&state))
}

#[tauri::command]
pub fn mcp_set_enabled(
    state: tauri::State<AppState>,
    enabled: bool,
) -> Result<McpStatus, AppError> {
    let snapshot = {
        let mut policy = state.mcp.policy.lock().unwrap();
        let mut next = policy.clone();
        next.enabled = enabled;
        save_policy(&next)?;
        *policy = next.clone();
        next
    };
    if !snapshot.enabled {
        state.mcp.cancel_records(None);
        state.mcp.deny_all_pending();
    }
    Ok(status_for(&state))
}

#[tauri::command]
pub fn mcp_set_host_allowed(
    state: tauri::State<AppState>,
    alias: String,
    allowed: bool,
) -> Result<McpStatus, AppError> {
    change_host_permission(&state.mcp.policy, &alias, allowed, || {
        let _lifecycle = state.sync.lifecycle.lock().unwrap();
        let records = state.sync.core.lock().unwrap().records.clone();
        if let Some(records) = records {
            crate::sync::record_repository::get_host(&records, &alias)
                .map_err(|error| AppError::Other(error.to_string()))?;
        } else {
            crate::sync::engine::require_legacy(&state.sync)?;
            let doc = state.doc.lock().unwrap();
            let doc = doc
                .as_ref()
                .ok_or_else(|| AppError::Other("no config loaded".to_string()))?;
            validate_alias(doc, &alias)?;
        }
        Ok(())
    }, save_policy)?;
    if !allowed {
        state.mcp.cancel_records(Some(&alias));
        let denied: Vec<_> = {
            let mut pending = state.mcp.pending.lock().unwrap();
            let ids: Vec<_> = pending
                .iter()
                .filter(|(_, p)| p.request.alias == alias)
                .map(|(id, _)| id.clone())
                .collect();
            ids.into_iter()
                .filter_map(|id| pending.remove(&id))
                .collect()
        };
        for request in denied {
            let _ = request.decision.send(ApprovalDecision::Deny);
        }
    }
    Ok(status_for(&state))
}

#[tauri::command]
pub fn mcp_set_group_allowed(
    state: tauri::State<AppState>,
    group_id: String,
    scope: crate::sync::records_v3::HostScope,
    generation: String,
    allowed: bool,
) -> Result<McpStatus, AppError> {
    // Bind grants to the selected library and scope; never authorize by a display name.
    let _lifecycle = state.sync.lifecycle.lock().unwrap();
    let core = state.sync.core.lock().unwrap();
    let records = crate::sync::record_runtime::active_state(&core)?;
    if generation != core.generation.to_string() {
        return Err(AppError::Other("The library changed. Refresh AI Access and try again.".into()));
    }
    permissions::change_group(&state.mcp.policy, records, &scope, &group_id, allowed, save_policy)?;
    drop(core);
    drop(_lifecycle);
    state.mcp.cancel_records(None);
    state.mcp.deny_all_pending();
    Ok(status_for(&state))
}

#[tauri::command]
pub fn mcp_resolve_request(
    state: tauri::State<AppState>,
    request_id: String,
    allow: bool,
) -> Result<(), AppError> {
    state.mcp.resolve_approval(&request_id,allow)
}

fn receive_approval(
    rx: &mpsc::Receiver<ApprovalDecision>,
    cancel: &crate::session::connect::CancelToken,
    deadline: InteractionDeadline,
    now: &dyn Fn() -> (Instant, SystemTime),
) -> ApprovalDecision {
    loop {
        if cancel.is_cancelled() {
            return ApprovalDecision::Cancel;
        }
        let (monotonic, utc) = now();
        let left = deadline.remaining_at(monotonic, utc);
        if left.is_zero() {
            return ApprovalDecision::TimedOut;
        }
        match rx.recv_timeout(left.min(Duration::from_millis(50))) {
            Ok(decision) => {
                let (monotonic, utc) = now();
                return if deadline.remaining_at(monotonic, utc).is_zero() {
                    ApprovalDecision::TimedOut
                } else if cancel.is_cancelled() {
                    ApprovalDecision::Cancel
                } else {
                    decision
                };
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => return ApprovalDecision::Cancel,
            Err(_) => {}
        }
    }
}
// ─── stdio MCP adapter ───────────────────────────────────────────────────────

/// Run the headless MCP stdio adapter. Only JSON-RPC is written to stdout.
pub fn run_stdio() {
    let active=Arc::new(Mutex::new(HashMap::<String,(String,Arc<adapter::Call>)>::new()));
    let next=AtomicU64::new(1);let mut info=McpClientInfo::default();let mut workers:Vec<thread::JoinHandle<()>>=Vec::new();
    let stdin=std::io::stdin();let mut input=stdin.lock();
    loop {
        let mut i=0;while i<workers.len(){if workers[i].is_finished(){let _=workers.swap_remove(i).join();}else{i+=1;}}
        let mut line=String::new();match input.by_ref().take(MAX_BRIDGE_LINE+1).read_line(&mut line){Ok(0)|Err(_)=>break,Ok(n) if n as u64>MAX_BRIDGE_LINE=>break,_=>{}}
        if line.trim().is_empty(){continue;}
        let message=match serde_json::from_str::<Value>(&line){Ok(v)=>v,Err(_)=>{if !write_mcp_response(&jsonrpc_error(Value::Null,-32700,"Parse error".into())){break;}continue;}};
        let method=message.get("method").and_then(Value::as_str).unwrap_or_default();
        if method=="initialize"{info=McpClientInfo::sanitize(message.pointer("/params/clientInfo"));}
        if method=="notifications/cancelled" {
            let found=message.pointer("/params/requestId").and_then(|id|active.lock().unwrap().get(&rpc_id_key(id)).cloned());
            if let Some((id,call))=found{call.cancel(&id);}continue;
        }
        if method=="tools/call" && message.get("id").is_some() {
            let rpc=message["id"].clone();let key=rpc_id_key(&rpc);let id=format!("adapter-{}-{}",std::process::id(),next.fetch_add(1,Ordering::Relaxed));
            let call=match adapter::insert(&active,key.clone(),id.clone()){Ok(c)=>c,Err(e)=>{let _=write_mcp_response(&jsonrpc_error(rpc,-32600,e));continue;}};
            let params=message.get("params").cloned().unwrap_or_else(||json!({}));let active=active.clone();let info=info.clone();
            let worker=thread::spawn(move||{let result=adapter::tool(&params,&id,&info,&call);let renamed=result.pointer("/content/0/text").and_then(Value::as_str)==Some("run was renamed to ssh_exec");let response=if renamed{jsonrpc_error(rpc,-32601,"run was renamed to ssh_exec".into())}else{json!({"jsonrpc":"2.0","id":rpc,"result":result})};if !write_mcp_response(&response){call.cancel(&id);}active.lock().unwrap().remove(&key);});
            workers.retain(|w:&thread::JoinHandle<()>|!w.is_finished());workers.push(worker);continue;
        }
        if method=="tools/list" && message.get("id").is_some(){
            let mode=adapter::ipc_call("mode",json!({}),&info,&adapter::Call::default());
            let response=match mode {Ok(v)=>json!({"jsonrpc":"2.0","id":message["id"],"result":{"tools":tools_for_mode(v["mode"].as_str().unwrap_or("legacy"))}}),Err(e)=>jsonrpc_error(message["id"].clone(),-32000,e)};
            if !write_mcp_response(&response){break;}continue;
        }
        if let Some(response)=handle_mcp_message(message){if !write_mcp_response(&response){break;}}
    }
    let calls:Vec<_>=active.lock().unwrap().values().cloned().collect();for(id,call)in calls{call.cancel(&id);}for worker in workers{let _=worker.join();}
}

fn write_mcp_response(response: &Value) -> bool {
    let stdout = std::io::stdout();
    let mut stdout = stdout.lock();
    serde_json::to_writer(&mut stdout, response).is_ok()
        && stdout.write_all(b"\n").is_ok()
        && stdout.flush().is_ok()
}

fn rpc_id_key(id: &Value) -> String {
    serde_json::to_string(id).unwrap_or_else(|_| "null".to_string())
}

fn handle_mcp_message(message: Value) -> Option<Value> {
    let id = message.get("id").cloned();
    let method = message.get("method").and_then(Value::as_str)?;
    if id.is_none() {
        return None;
    }
    let id = id.unwrap_or(Value::Null);
    match method {
        "initialize" => Some(json!({
            "jsonrpc": "2.0",
            "id": id,
            "result": {
                "protocolVersion": MCP_PROTOCOL_VERSION,
                "capabilities": { "tools": { "listChanged": false } },
                "serverInfo": { "name": "lunport", "version": env!("CARGO_PKG_VERSION") },
                "instructions": "Existing hosts are exposed when allowed individually or through an explicitly allowed Group and its descendants in Lunport AI Access. Records create_host always needs native human approval; a saved host can inherit access from an already allowed Group. verify_host_key requests native human review of a new or changed server fingerprint without destination login. ssh_exec follows Ask or Auto-log; Auto-log never silently trusts keys or requests credentials. Never ask for or send passwords, passphrases, private keys or secrets in tool arguments."
            }
        })),
        "ping" => Some(json!({ "jsonrpc": "2.0", "id": id, "result": {} })),
        "tools/list" => Some(json!({
            "jsonrpc": "2.0",
            "id": id,
            "result": { "tools": tool_definitions() }
        })),
        "tools/call" => {
            let params = message.get("params").cloned().unwrap_or_else(|| json!({}));
            Some(json!({
                "jsonrpc": "2.0",
                "id": id,
                "result": call_tool(&params, None)
            }))
        }
        _ => Some(jsonrpc_error(
            id,
            -32601,
            format!("Method not found: {method}"),
        )),
    }
}

fn jsonrpc_error(id: Value, code: i32, message: String) -> Value {
    json!({ "jsonrpc": "2.0", "id": id, "error": { "code": code, "message": message } })
}

fn tool_definitions() -> Value {
    json!([
        {
            "name": "list_hosts",
            "title": "List AI-approved SSH hosts",
            "description": "List only SSH hosts that the user explicitly allowed in Lunport's AI Access interface.",
            "inputSchema": { "type": "object", "properties": {}, "additionalProperties": false },
            "annotations": { "readOnlyHint": true, "destructiveHint": false, "idempotentHint": true, "openWorldHint": false }
        },
        {
            "name": "get_effective_config",
            "title": "Get sanitized SSH configuration",
            "description": "Resolve non-secret connection settings for an AI-approved host.",
            "inputSchema": {
                "type": "object",
                "properties": { "alias": { "type": "string", "description": "Stable host ID returned by list_hosts in a records workspace, or an exact unambiguous host alias" } },
                "required": ["alias"],
                "additionalProperties": false
            },
            "annotations": { "readOnlyHint": true, "destructiveHint": false, "idempotentHint": true, "openWorldHint": false }
        },
        {
            "name": "run",
            "title": "Run an approved SSH command",
            "description": "Ask the user to approve one exact remote command in Lunport, then run it over SSH. The request is denied if the UI does not approve it.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "alias": { "type": "string", "description": "Exact AI-approved Lunport host alias" },
                    "command": { "type": "string", "description": "Exact remote shell command shown to the user for approval" },
                    "timeout_seconds": { "type": "integer", "minimum": 1, "maximum": 300, "default": 60 }
                },
                "required": ["alias", "command"],
                "additionalProperties": false
            },
            "annotations": { "readOnlyHint": false, "destructiveHint": true, "idempotentHint": false, "openWorldHint": true }
        }
    ])
}

fn tools_for_mode(mode: &str) -> Value {
    let mut tools = tool_definitions();
    if mode == "records" {
        tools[1]["name"] = json!("get_host");
        tools[2]["name"] = json!("ssh_exec");
        tools[2]["description"] = json!("Run a remote command under the current Lunport Ask or Auto-log policy. For an untrusted server key, use verify_host_key for native human review first.");
        tools.as_array_mut().unwrap().extend(management::tool_definitions());
    }
    tools
}

fn call_tool(params: &Value, request_id: Option<&str>) -> Value {
    let name = params
        .get("name")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let mut arguments = params
        .get("arguments")
        .cloned()
        .unwrap_or_else(|| json!({}));
    let method = match name {
        "list_hosts" => "list_hosts",
        "get_effective_config" => "get_effective_config",
        "run" => "run",
        _ => return tool_error(format!("Unknown tool: {name}")),
    };
    if method == "run" {
        if let (Some(request_id), Some(arguments)) = (request_id, arguments.as_object_mut()) {
            arguments.insert("_request_id".to_string(), json!(request_id));
        }
    }
    match bridge_call(method, arguments) {
        Ok(result) => {
            let text = serde_json::to_string_pretty(&result).unwrap_or_else(|_| result.to_string());
            json!({
                "content": [{ "type": "text", "text": text }],
                "structuredContent": result,
                "isError": false
            })
        }
        Err(error) => tool_error(error),
    }
}

fn tool_error(error: String) -> Value {
    json!({
        "content": [{ "type": "text", "text": error }],
        "isError": true
    })
}

fn read_runtime_info() -> Result<RuntimeInfo, String> {
    let path = runtime_path().map_err(|e| e.to_string())?;
    let bytes = std::fs::read(&path).map_err(|e| format!("cannot read {}: {e}", path.display()))?;
    serde_json::from_slice(&bytes).map_err(|e| format!("invalid MCP runtime info: {e}"))
}

fn send_to_runtime(
    info: &RuntimeInfo,
    method: &str,
    params: Value,
    read_timeout: Duration,
) -> Result<Value, String> {
    let mut stream = TcpStream::connect_timeout(
        &(Ipv4Addr::LOCALHOST, info.port).into(),
        Duration::from_secs(2),
    )
    .map_err(|e| format!("cannot connect to Lunport desktop: {e}"))?;
    stream
        .set_read_timeout(Some(read_timeout))
        .map_err(|e| e.to_string())?;
    stream
        .set_write_timeout(Some(Duration::from_secs(5)))
        .map_err(|e| e.to_string())?;
    let envelope = BridgeEnvelope {
        token: info.token.clone(),
        method: method.to_string(),
        params,
    };
    serde_json::to_writer(&mut stream, &envelope).map_err(|e| e.to_string())?;
    stream.write_all(b"\n").map_err(|e| e.to_string())?;
    stream.flush().map_err(|e| e.to_string())?;

    let mut line = String::new();
    BufReader::new(stream)
        .take(MAX_BRIDGE_LINE + 1)
        .read_line(&mut line)
        .map_err(|e| format!("cannot read Lunport response: {e}"))?;
    if line.len() as u64 > MAX_BRIDGE_LINE {
        return Err("Lunport response is too large".to_string());
    }
    let response: BridgeResponse =
        serde_json::from_str(&line).map_err(|e| format!("invalid Lunport response: {e}"))?;
    if response.ok {
        Ok(response.result.unwrap_or(Value::Null))
    } else {
        Err(response
            .error
            .unwrap_or_else(|| "Lunport rejected the request".to_string()))
    }
}

/// How long a tool call may wait for Lunport's answer: an approval (up to 120 s) and then the
/// SSH command (up to 300 s).
const CALL_TIMEOUT: Duration = Duration::from_secs(430);
/// How long a ping may wait for its answer. A bridge answers at once; the port in a stale runtime
/// file may belong to another program by now, and a ping must not hang on it while holding the
/// spawn locks.
const PING_TIMEOUT: Duration = Duration::from_secs(5);
/// Only one Lunport runs: an open Lunport whose bridge doesn't answer is not replaced.
const NO_ANSWER: &str =
    "Lunport didn't answer within 12 seconds. If it is open, quit it and open it again.";

/// The bridge of a running Lunport, started in the background first if none answers
/// (`host_start`, shared with `sshelter connect`).
fn ensure_desktop_bridge() -> Result<RuntimeInfo, String> {
    use crate::host_start::{ensure_started, start_host, take_spawn_locks, START_WAIT};
    ensure_started(answering_bridge, take_spawn_locks, start_host, START_WAIT, NO_ANSWER)
}

/// The bridge named in `mcp-runtime.json`, if it answers a ping.
fn answering_bridge() -> Option<RuntimeInfo> {
    read_runtime_info()
        .ok()
        .filter(|info| send_to_runtime(info, "ping", json!({}), PING_TIMEOUT).is_ok())
}

fn bridge_call(method: &str, params: Value) -> Result<Value, String> {
    let info = ensure_desktop_bridge()?;
    // Never automatically retry a tool call: an application-level denial or a
    // dropped response after execution must not create a duplicate SSH action.
    send_to_runtime(&info, method, params, CALL_TIMEOUT)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn auto_log_requires_explicit_risk_acknowledgement_and_persistence_before_replacement(){
        let policy=Mutex::new(McpPolicy::default());
        assert!(change_approval_mode(&policy,ApprovalMode::AutoLog,false,|_|panic!("unacknowledged mode never persists")).is_err());
        assert_eq!(policy.lock().unwrap().approval_mode,ApprovalMode::Ask);
        assert!(change_approval_mode(&policy,ApprovalMode::AutoLog,true,|_|Err(AppError::Other("disk full".into()))).is_err());
        assert_eq!(policy.lock().unwrap().approval_mode,ApprovalMode::Ask);
        change_approval_mode(&policy,ApprovalMode::AutoLog,true,|_|Ok(())).unwrap();
        change_approval_mode(&policy,ApprovalMode::Ask,false,|_|Ok(())).unwrap();
        assert_eq!(policy.lock().unwrap().approval_mode,ApprovalMode::Ask);
    }

    #[test]
    fn records_policy_defaults_to_ask_and_rejects_control_commands() {
        let policy: McpPolicy = serde_json::from_str(r#"{"enabled":true,"allowed_hosts":["id-web"]}"#).unwrap();
        assert_eq!(serde_json::to_value(policy).unwrap()["approval_mode"], "ask");
        assert!(!display_safe_command("echo hello\rhidden"));
        assert!(!display_safe_command("echo \u{200f}hidden"));
    }

    #[test]
    fn revoking_a_host_does_not_wait_for_an_active_run_lifecycle_lock() {
        let lifecycle = Mutex::new(());
        let _active_run = lifecycle.lock().unwrap();
        let policy = Mutex::new(McpPolicy { enabled: true, allowed_hosts: BTreeSet::from(["web".into()]), approval_mode: ApprovalMode::Ask, ..Default::default() });
        change_host_permission(&policy, "web", false, || {
            let _guard = lifecycle.try_lock().map_err(|_| AppError::Other("an active run owns lifecycle".into()))?;
            Ok(())
        }, |_| Ok(())).unwrap();
        assert!(!policy.lock().unwrap().allowed_hosts.contains("web"));
    }

    #[test]
    fn records_allowlist_does_not_inherit_a_legacy_alias_grant() {
        let host: crate::sync::records_v3::HostRecord = serde_json::from_value(json!({"id":"0123456789abcdef","scope":{"kind":"local"},"payload":{"schema":2,"alias":"web","hostname":"fixture.invalid","auth":"password"}})).unwrap();
        let mut policy = McpPolicy::default();
        policy.allowed_hosts.insert("web".into());
        assert!(ensure_record_allowed(&policy, &host).is_err());
        policy.allowed_hosts.insert(host.id.clone());
        assert!(ensure_record_allowed(&policy, &host).is_ok());
    }

    #[test]
    fn record_metadata_does_not_expose_notes_or_imported_directive_values(){
        let host:crate::sync::records_v3::HostRecord=serde_json::from_value(json!({"id":"0123456789abcdef","scope":{"kind":"local"},"payload":{"schema":2,"alias":"web","hostname":"example.test","auth":"password","notes":"private-note-sentinel","imported":{"source":"private-source-sentinel","at_ms":1,"unsupported":[{"keyword":"setenv","value":"private-env-sentinel","requires_review":true}]}}})).unwrap();
        let result=record_host_metadata(&host).to_string();
        for private in ["private-note-sentinel","private-source-sentinel","private-env-sentinel"] {assert!(!result.contains(private));}
        assert_eq!(record_host_metadata(&host)["hostname"],"example.test");
    }
    #[test]
    fn development_mcp_execution_is_refused_before_spawning() {
        if crate::app_profile::CURRENT != crate::app_profile::AppProfile::Development { return; }
        let dir = tempfile::tempdir().unwrap();
        let config = dir.path().join("nonexistent");
        let canceled = AtomicBool::new(false);
        let error = execute_ssh("fixture", "true", Some(&config), 1, &canceled).err().expect("Development must refuse before opening a config or spawning ssh");
        assert!(error.contains("Development"), "{error}");
        assert!(!config.exists());
    }

    #[test]
    fn rejects_bidi_control_characters_in_commands() {
        assert!(display_safe_command("sudo systemctl status runner"));
        assert!(!display_safe_command("echo safe\u{202e}txt"));
        assert!(!display_safe_command(""));
        assert!(!display_safe_command("echo\0secret"));
    }

    #[test]
    fn tool_list_marks_run_as_destructive_and_not_read_only() {
        let tools = tool_definitions();
        let run = tools
            .as_array()
            .unwrap()
            .iter()
            .find(|tool| tool["name"] == "run")
            .unwrap();
        assert_eq!(run["annotations"]["readOnlyHint"], false);
        assert_eq!(run["annotations"]["destructiveHint"], true);
    }

    #[test]
    fn initialize_advertises_tools_capability() {
        let response = handle_mcp_message(json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": { "protocolVersion": MCP_PROTOCOL_VERSION }
        }))
        .unwrap();
        assert_eq!(response["result"]["protocolVersion"], MCP_PROTOCOL_VERSION);
        assert_eq!(response["result"]["serverInfo"]["name"], "lunport");
        assert!(response["result"]["capabilities"]["tools"].is_object());
    }

    #[test]
    fn cancellation_marks_an_active_request() {
        let runtime = McpRuntime::default();
        let flag = runtime.register_request("request-1").unwrap();
        assert!(runtime.cancel_request("request-1"));
        assert!(flag.load(Ordering::Relaxed));
        runtime.finish_request("request-1");
    }

    fn runtime_json(pid: u32) -> Vec<u8> {
        serde_json::to_vec(&RuntimeInfo {
            port: 49152,
            token: "ab".repeat(32),
            pid,
        })
        .unwrap()
    }

    #[test]
    fn a_confined_profile_does_not_remove_an_owned_runtime_file_outside_its_root() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("runtime.json");
        let bytes = runtime_json(4242);
        std::fs::write(&path, &bytes).unwrap();
        crate::fsutil::with_test_write_policy(crate::write_policy::WritePolicy::Confined { root: temp.path().join("dev") }, || {
            assert!(remove_runtime_file_if_owned(&path, 4242).is_err());
        });
        assert_eq!(std::fs::read(path).unwrap(), bytes);
    }

    #[test]
    fn runtime_file_names_only_the_process_it_was_written_for() {
        assert!(runtime_file_names(&runtime_json(4242), 4242));
        assert!(!runtime_file_names(&runtime_json(4242), 4243));
        assert!(!runtime_file_names(b"", 4242));
        assert!(!runtime_file_names(b"not json", 4242));
        assert!(!runtime_file_names(br#"{"port":1,"token":"t"}"#, 4242));
    }

    #[test]
    fn exiting_removes_only_a_runtime_file_that_names_this_process() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("mcp-runtime.json");

        std::fs::write(&path, runtime_json(4243)).unwrap();
        assert!(!remove_runtime_file_if_owned(&path, 4242).unwrap());
        assert!(path.exists(), "another instance's file must stay");

        std::fs::write(&path, runtime_json(4242)).unwrap();
        assert!(remove_runtime_file_if_owned(&path, 4242).unwrap());
        assert!(!path.exists());

        assert!(
            !remove_runtime_file_if_owned(&path, 4242).unwrap(),
            "a missing file is fine"
        );
    }
}

#[cfg(test)]
#[path = "mcp/deployment_audit_tests.rs"]
pub(crate) mod deployment_audit_tests;
