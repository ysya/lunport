//! MCP stdio adapter and the authenticated loopback bridge to SSHelter's desktop UI.
//!
//! The `--mcp` process never owns credentials and never executes SSH. It speaks
//! newline-delimited MCP JSON-RPC over stdin/stdout and forwards tool calls to the
//! running desktop app. The app owns host policy, native approval, execution, and
//! the audit trail. A random token in a mode-0600 runtime file authenticates the
//! loopback bridge; this protects against unrelated local users, not a malicious
//! process running as the same OS account.

use std::collections::{BTreeSet, HashMap, HashSet, VecDeque};
use std::fs::{File, OpenOptions, TryLockError};
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{Ipv4Addr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{mpsc, Arc, Mutex, MutexGuard, PoisonError};
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

/// First argument that starts SSHelter as the MCP host (main.rs): the desktop app, in the background.
pub const HOST_FLAG: &str = "--mcp-host";

const MCP_PROTOCOL_VERSION: &str = "2025-06-18";
const MAX_BRIDGE_LINE: u64 = 1_048_576;
const MAX_COMMAND_BYTES: usize = 16_384;
const MAX_STREAM_BYTES: usize = 65_536;
const APPROVAL_TIMEOUT: Duration = Duration::from_secs(120);
const MAX_RECENT_AUDIT: usize = 100;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct McpPolicy {
    enabled: bool,
    #[serde(default)]
    allowed_hosts: BTreeSet<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct RuntimeInfo {
    port: u16,
    token: String,
    pid: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(test, derive(ts_rs::TS))]
#[cfg_attr(test, ts(export, export_to = "../../src/bindings/"))]
pub struct McpPendingRequest {
    pub id: String,
    pub alias: String,
    pub command: String,
    pub hostname: Option<String>,
    pub user: Option<String>,
    pub port: Option<String>,
    #[cfg_attr(test, ts(type = "number"))]
    pub requested_at_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(test, derive(ts_rs::TS))]
#[cfg_attr(test, ts(export, export_to = "../../src/bindings/"))]
pub struct McpAuditEntry {
    pub id: String,
    pub alias: String,
    pub command: String,
    pub outcome: String,
    pub exit_code: Option<i32>,
    pub detail: Option<String>,
    #[cfg_attr(test, ts(type = "number"))]
    pub completed_at_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(test, derive(ts_rs::TS))]
#[cfg_attr(test, ts(export, export_to = "../../src/bindings/"))]
pub struct McpStatus {
    pub enabled: bool,
    pub bridge_active: bool,
    pub allowed_hosts: Vec<String>,
    pub pending: Vec<McpPendingRequest>,
    pub recent: Vec<McpAuditEntry>,
    pub executable: String,
    #[cfg_attr(test, ts(type = "number | null"))]
    pub last_client_at_ms: Option<u64>,
}

struct PendingApproval {
    request: McpPendingRequest,
    decision: mpsc::SyncSender<ApprovalDecision>,
}

#[derive(Debug, Clone, Copy)]
enum ApprovalDecision {
    Allow,
    Deny,
    Cancel,
}

#[derive(Default)]
struct CancellationState {
    active: HashMap<String, Arc<AtomicBool>>,
    early: HashSet<String>,
}

/// Runtime state shared by Tauri commands and loopback bridge workers.
pub struct McpRuntime {
    policy: Mutex<McpPolicy>,
    pending: Mutex<HashMap<String, PendingApproval>>,
    recent: Mutex<VecDeque<McpAuditEntry>>,
    cancellations: Mutex<CancellationState>,
    /// This instance's bridge (port, token, pid): what it wrote to `mcp-runtime.json`.
    bridge: Mutex<Option<RuntimeInfo>>,
    bridge_active: AtomicBool,
    pub keep_alive: AtomicBool,
    next_request_id: AtomicU64,
    last_client_at_ms: AtomicU64,
}

impl Default for McpRuntime {
    fn default() -> Self {
        Self {
            policy: Mutex::new(McpPolicy::default()),
            pending: Mutex::new(HashMap::new()),
            recent: Mutex::new(VecDeque::new()),
            cancellations: Mutex::new(CancellationState::default()),
            bridge: Mutex::new(None),
            bridge_active: AtomicBool::new(false),
            keep_alive: AtomicBool::new(false),
            next_request_id: AtomicU64::new(1),
            last_client_at_ms: AtomicU64::new(0),
        }
    }
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
        let recent = self.recent.lock().unwrap().iter().cloned().collect();
        let last = self.last_client_at_ms.load(Ordering::Relaxed);
        McpStatus {
            enabled: policy.enabled,
            bridge_active: self.bridge_active.load(Ordering::Relaxed),
            allowed_hosts: policy.allowed_hosts.into_iter().collect(),
            pending,
            recent,
            executable: std::env::current_exe()
                .map(|p| p.to_string_lossy().into_owned())
                .unwrap_or_else(|_| "SSHelter".to_string()),
            last_client_at_ms: (last != 0).then_some(last),
        }
    }

    fn record(&self, entry: McpAuditEntry) {
        let mut recent = self.recent.lock().unwrap();
        recent.push_front(entry);
        recent.truncate(MAX_RECENT_AUDIT);
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
    // A corrupt policy must fail closed without preventing SSHelter from opening.
    *state.mcp.policy.lock().unwrap() = load_policy().unwrap_or_default();
    state.mcp.keep_alive.store(keep_alive, Ordering::Relaxed);
    start_bridge(app.clone())
}

fn random_token() -> Result<String, AppError> {
    let mut bytes = [0_u8; 32];
    getrandom::fill(&mut bytes)
        .map_err(|e| AppError::Other(format!("cannot create MCP bridge token: {e}")))?;
    Ok(bytes.iter().map(|b| format!("{b:02x}")).collect())
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
                    // descriptors) does not end the bridge: only one SSHelter runs, so no other
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

    if envelope.method == "ping" {
        return Ok(json!({ "status": "ok" }));
    }
    if envelope.method == "cancel" {
        let request_id = string_param(&envelope.params, "request_id")?;
        return Ok(json!({ "canceled": state.mcp.cancel_request(request_id) }));
    }

    let policy = state.mcp.policy.lock().unwrap().clone();
    if !policy.enabled {
        return Err("MCP access is disabled in SSHelter Settings → AI Access".to_string());
    }

    match envelope.method.as_str() {
        "list_hosts" => {
            let doc = wait_for_loaded_doc(&state)?;
            let hosts: Vec<_> = host_summaries(&doc)
                .into_iter()
                .filter(|h| policy.allowed_hosts.contains(&h.alias))
                .collect();
            Ok(json!({ "hosts": hosts }))
        }
        "get_effective_config" => {
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

fn display_safe_command(command: &str) -> bool {
    !command.is_empty()
        && command.len() <= MAX_COMMAND_BYTES
        && !command.contains('\0')
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
    };
    let (tx, rx) = mpsc::sync_channel(1);
    state.mcp.pending.lock().unwrap().insert(
        id.clone(),
        PendingApproval {
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

    let approved = match rx.recv_timeout(APPROVAL_TIMEOUT) {
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
            });
            return Err("MCP request was canceled".to_string());
        }
        Err(_) => {
            state.mcp.pending.lock().unwrap().remove(&id);
            state.mcp.record(McpAuditEntry {
                id: id.clone(),
                alias,
                command,
                outcome: "timed_out".to_string(),
                exit_code: None,
                detail: Some("No decision within 120 seconds".to_string()),
                completed_at_ms: unix_ms(),
            });
            return Err("SSHelter approval timed out".to_string());
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
        });
        return Err("Denied in SSHelter".to_string());
    }

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
                    exit_code: output.exit_code,
                    detail: Some("MCP client canceled or disconnected".to_string()),
                    completed_at_ms: unix_ms(),
                });
                return Err("MCP request was canceled".to_string());
            }
            state.mcp.record(McpAuditEntry {
                id: id.clone(),
                alias,
                command,
                outcome: "allowed".to_string(),
                exit_code: output.exit_code,
                detail: output
                    .timed_out
                    .then(|| "SSH command timed out".to_string()),
                completed_at_ms: unix_ms(),
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
    state.mcp.status()
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
        state.mcp.deny_all_pending();
    }
    Ok(state.mcp.status())
}

#[tauri::command]
pub fn mcp_set_host_allowed(
    state: tauri::State<AppState>,
    alias: String,
    allowed: bool,
) -> Result<McpStatus, AppError> {
    if allowed {
        let doc = state.doc.lock().unwrap();
        let doc = doc
            .as_ref()
            .ok_or_else(|| AppError::Other("no config loaded".to_string()))?;
        validate_alias(doc, &alias)?;
    }
    {
        let mut policy = state.mcp.policy.lock().unwrap();
        let mut next = policy.clone();
        if allowed {
            next.allowed_hosts.insert(alias.clone());
        } else {
            next.allowed_hosts.remove(&alias);
        }
        save_policy(&next)?;
        *policy = next;
    }
    if !allowed {
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
    Ok(state.mcp.status())
}

#[tauri::command]
pub fn mcp_resolve_request(
    state: tauri::State<AppState>,
    request_id: String,
    allow: bool,
) -> Result<(), AppError> {
    let pending = state
        .mcp
        .pending
        .lock()
        .unwrap()
        .remove(&request_id)
        .ok_or_else(|| AppError::NotFound("MCP request already resolved or expired".to_string()))?;
    pending
        .decision
        .send(if allow {
            ApprovalDecision::Allow
        } else {
            ApprovalDecision::Deny
        })
        .map_err(|_| AppError::Other("MCP client disconnected".to_string()))
}

// ─── stdio MCP adapter ───────────────────────────────────────────────────────

/// Run the headless MCP stdio adapter. Only JSON-RPC is written to stdout.
pub fn run_stdio() {
    let active_calls = Arc::new(Mutex::new(HashMap::<String, String>::new()));
    let next_call_id = AtomicU64::new(1);
    let stdin = std::io::stdin();
    for line in stdin.lock().lines() {
        let line = match line {
            Ok(line) if !line.trim().is_empty() => line,
            Ok(_) => continue,
            Err(_) => break,
        };
        let response = match serde_json::from_str::<Value>(&line) {
            Ok(message)
                if message.get("method").and_then(Value::as_str) == Some("tools/call")
                    && message.get("id").is_some() =>
            {
                let id = message.get("id").cloned().unwrap_or(Value::Null);
                let key = rpc_id_key(&id);
                let internal_id = format!(
                    "mcp-adapter-{}-{}",
                    std::process::id(),
                    next_call_id.fetch_add(1, Ordering::Relaxed)
                );
                active_calls
                    .lock()
                    .unwrap()
                    .insert(key.clone(), internal_id.clone());
                let params = message.get("params").cloned().unwrap_or_else(|| json!({}));
                let calls = active_calls.clone();
                let _ = thread::Builder::new()
                    .name("sshelter-mcp-tool-call".to_string())
                    .spawn(move || {
                        let result = call_tool(&params, Some(&internal_id));
                        let response = json!({ "jsonrpc": "2.0", "id": id, "result": result });
                        let _ = write_mcp_response(&response);
                        calls.lock().unwrap().remove(&key);
                    });
                None
            }
            Ok(message)
                if message.get("method").and_then(Value::as_str)
                    == Some("notifications/cancelled") =>
            {
                if let Some(request_id) = message
                    .pointer("/params/requestId")
                    .map(rpc_id_key)
                    .and_then(|key| active_calls.lock().unwrap().get(&key).cloned())
                {
                    let _ = thread::Builder::new()
                        .name("sshelter-mcp-cancel".to_string())
                        .spawn(move || {
                            let _ = bridge_call("cancel", json!({ "request_id": request_id }));
                        });
                }
                None
            }
            Ok(message) => handle_mcp_message(message),
            Err(e) => Some(jsonrpc_error(
                Value::Null,
                -32700,
                format!("Parse error: {e}"),
            )),
        };
        if let Some(response) = response {
            if !write_mcp_response(&response) {
                break;
            }
        }
    }

    // EOF normally means the MCP client is shutting down. Best-effort cancel
    // every request before this adapter process exits.
    let pending: Vec<_> = active_calls.lock().unwrap().values().cloned().collect();
    for request_id in pending {
        let _ = bridge_call("cancel", json!({ "request_id": request_id }));
    }
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
                "serverInfo": { "name": "sshelter", "version": env!("CARGO_PKG_VERSION") },
                "instructions": "SSHelter exposes only hosts explicitly allowed in its AI Access settings. Every run request requires an Allow once decision in the SSHelter desktop UI. Never ask for or send passwords, passphrases, private keys, or secrets in command arguments."
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
            "description": "List only SSH hosts that the user explicitly allowed in SSHelter's AI Access interface.",
            "inputSchema": { "type": "object", "properties": {}, "additionalProperties": false },
            "annotations": { "readOnlyHint": true, "destructiveHint": false, "idempotentHint": true, "openWorldHint": false }
        },
        {
            "name": "get_effective_config",
            "title": "Get sanitized SSH configuration",
            "description": "Resolve non-secret connection settings for an AI-approved host.",
            "inputSchema": {
                "type": "object",
                "properties": { "alias": { "type": "string", "description": "Exact SSHelter host alias" } },
                "required": ["alias"],
                "additionalProperties": false
            },
            "annotations": { "readOnlyHint": true, "destructiveHint": false, "idempotentHint": true, "openWorldHint": false }
        },
        {
            "name": "run",
            "title": "Run an approved SSH command",
            "description": "Ask the user to approve one exact remote command in SSHelter, then run it over SSH. The request is denied if the UI does not approve it.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "alias": { "type": "string", "description": "Exact AI-approved SSHelter host alias" },
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
    .map_err(|e| format!("cannot connect to SSHelter desktop: {e}"))?;
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
        .map_err(|e| format!("cannot read SSHelter response: {e}"))?;
    if line.len() as u64 > MAX_BRIDGE_LINE {
        return Err("SSHelter response is too large".to_string());
    }
    let response: BridgeResponse =
        serde_json::from_str(&line).map_err(|e| format!("invalid SSHelter response: {e}"))?;
    if response.ok {
        Ok(response.result.unwrap_or(Value::Null))
    } else {
        Err(response
            .error
            .unwrap_or_else(|| "SSHelter rejected the request".to_string()))
    }
}

/// How long a tool call may wait for SSHelter's answer: an approval (up to 120 s) and then the
/// SSH command (up to 300 s).
const CALL_TIMEOUT: Duration = Duration::from_secs(430);
/// How long a ping may wait for its answer. A bridge answers at once; the port in a stale runtime
/// file may belong to another program by now, and a ping must not hang on it while holding the
/// spawn locks.
const PING_TIMEOUT: Duration = Duration::from_secs(5);
/// How long an adapter waits for the bridge of the SSHelter it started, and how often it looks.
const START_WAIT: Duration = Duration::from_secs(12);
const START_POLL: Duration = Duration::from_millis(120);
/// Only one SSHelter runs: an open SSHelter whose bridge doesn't answer is not replaced.
const NO_ANSWER: &str =
    "SSHelter didn't answer within 12 seconds. If it is open, quit it and open it again.";

/// Serializes starting SSHelter between this adapter's tool calls, which run in parallel.
static SPAWN_LOCK: Mutex<()> = Mutex::new(());

fn ensure_desktop_bridge() -> Result<RuntimeInfo, String> {
    ensure_started(answering_bridge, take_spawn_locks, start_host, START_WAIT)
}

/// The bridge named in `mcp-runtime.json`, if it answers a ping.
fn answering_bridge() -> Option<RuntimeInfo> {
    read_runtime_info()
        .ok()
        .filter(|info| send_to_runtime(info, "ping", json!({}), PING_TIMEOUT).is_ok())
}

/// What a call got when it asked for the spawn locks.
enum SpawnLocks<G> {
    /// Start SSHelter while holding `G`.
    Held(G),
    /// Another adapter kept `mcp-spawn.lock` past the deadline: it may be stopped in the middle
    /// of a start (its AI CLI suspended, for example).
    Busy,
}

/// Return a bridge that answers. If none does, take the spawn locks and look again: a parallel
/// call or another adapter may have started SSHelter meanwhile. Only if still none answers, start
/// SSHelter once and wait for its bridge. Several near-simultaneous starts could each claim the
/// single instance before the others see it (macOS), and leave two SSHelters running; so when
/// another adapter keeps the locks too long, look once more instead of starting a second one.
fn ensure_started<T, G>(
    mut answering: impl FnMut() -> Option<T>,
    lock: impl FnOnce() -> SpawnLocks<G>,
    start: impl FnOnce() -> Result<(), String>,
    wait: Duration,
) -> Result<T, String> {
    if let Some(found) = answering() {
        return Ok(found);
    }
    let _locks = match lock() {
        SpawnLocks::Held(locks) => locks,
        SpawnLocks::Busy => return answering().ok_or_else(|| NO_ANSWER.to_string()),
    };
    if let Some(found) = answering() {
        return Ok(found);
    }
    start()?;
    let deadline = Instant::now() + wait;
    while Instant::now() < deadline {
        thread::sleep(START_POLL);
        if let Some(found) = answering() {
            return Ok(found);
        }
    }
    Err(NO_ANSWER.to_string())
}

/// `SPAWN_LOCK`, and `mcp-spawn.lock` unless it can't be taken here.
type SpawnGuards = (MutexGuard<'static, ()>, Option<File>);

fn take_spawn_locks() -> SpawnLocks<SpawnGuards> {
    // The deadline counts from before this call waits for the adapter's other calls, so a call
    // never waits much longer than `START_WAIT` for the locks.
    let deadline = Instant::now() + START_WAIT;
    take_spawn_locks_at(spawn_lock_path().map_err(|e| e.to_string()), deadline)
}

/// Takes `SPAWN_LOCK` (this adapter's tool calls), then the exclusive file lock on `path`, by
/// default `mcp-spawn.lock` in the app data directory (other adapters, that is other AI
/// sessions), which the system releases when its holder exits. Dropping the guards releases both.
/// A file lock that can't be taken here at all (no app data directory, a file system without
/// locks) is skipped, as before there was one: only this adapter's calls wait for each other.
fn take_spawn_locks_at(
    path: Result<PathBuf, String>,
    deadline: Instant,
) -> SpawnLocks<SpawnGuards> {
    let calls = SPAWN_LOCK.lock().unwrap_or_else(PoisonError::into_inner);
    let file = match path {
        Ok(path) => lock_file_until(&path, deadline),
        Err(e) => FileLock::Unavailable(e),
    };
    match file {
        FileLock::Held(file) => SpawnLocks::Held((calls, Some(file))),
        FileLock::Busy => SpawnLocks::Busy,
        FileLock::Unavailable(reason) => {
            eprintln!("[mcp] starting SSHelter without mcp-spawn.lock: {reason}");
            SpawnLocks::Held((calls, None))
        }
    }
}

fn spawn_lock_path() -> Result<PathBuf, AppError> {
    Ok(crate::fsutil::app_data_root()?.join("mcp-spawn.lock"))
}

enum FileLock {
    Held(File),
    /// Someone else still held it at the deadline.
    Busy,
    /// It can't be opened or locked here.
    Unavailable(String),
}

/// Open `path`, creating it and its directory, and take an exclusive lock on it, trying until
/// `deadline`.
fn lock_file_until(path: &Path, deadline: Instant) -> FileLock {
    let opened = path
        .parent()
        .map_or(Ok(()), fsutil::ensure_dir_secure)
        .map_err(|e| e.to_string())
        .and_then(|()| {
            OpenOptions::new()
                .create(true)
                .truncate(false)
                .write(true)
                .open(path)
                .map_err(|e| e.to_string())
        });
    let file = match opened {
        Ok(file) => file,
        Err(e) => return FileLock::Unavailable(format!("cannot open {}: {e}", path.display())),
    };
    loop {
        match file.try_lock() {
            Ok(()) => return FileLock::Held(file),
            Err(TryLockError::WouldBlock) if Instant::now() < deadline => thread::sleep(START_POLL),
            Err(TryLockError::WouldBlock) => return FileLock::Busy,
            Err(TryLockError::Error(e)) => {
                return FileLock::Unavailable(format!("cannot lock {}: {e}", path.display()))
            }
        }
    }
}

/// Start SSHelter in the background, or, when it already runs, hand over to it (single
/// instance): the running SSHelter rewrites the runtime file with its bridge.
fn start_host() -> Result<(), String> {
    let exe = std::env::current_exe().map_err(|e| format!("cannot locate SSHelter: {e}"))?;
    let mut host = crate::process::spawn(&mut host_command(&exe))
        .map_err(|e| format!("cannot start SSHelter desktop: {e}"))?;
    // A launch that hands over exits at once: reap it instead of leaving a zombie behind.
    let _ = thread::Builder::new()
        .name("sshelter-mcp-host-wait".to_string())
        .spawn(move || {
            let _ = host.wait();
        });
    Ok(())
}

/// `--mcp-host` decides the hand-over and keeps SSHelter running when its window closes;
/// `SSHELTER_START_HIDDEN=1` keeps the window hidden at this start only (lib.rs `starts_hidden`).
fn host_command(exe: &Path) -> Command {
    let mut command = Command::new(exe);
    command
        .arg(HOST_FLAG)
        .env(crate::START_HIDDEN_ENV, "1")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    detach_from_adapter(&mut command);
    command
}

/// Start the MCP host outside the adapter's process group: an AI tool that ends its session by
/// killing its MCP server's process group must not take SSHelter down with it.
fn detach_from_adapter(command: &mut Command) {
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        command.process_group(0);
    }
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        use windows_sys::Win32::System::Threading::{CREATE_NEW_PROCESS_GROUP, DETACHED_PROCESS};
        // Its own process group: the adapter's console Ctrl+C / Ctrl+Break does not reach it.
        // No console: closing the console the AI tool runs in does not end it either.
        command.creation_flags(CREATE_NEW_PROCESS_GROUP | DETACHED_PROCESS);
    }
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

    #[test]
    fn a_call_that_finds_a_bridge_once_it_holds_the_locks_starts_nothing() {
        // Another call or adapter started SSHelter while this one waited for the locks.
        let mut answers = [None, Some("bridge")].into_iter();
        let found = ensure_started(
            || answers.next().flatten(),
            || SpawnLocks::Held(()),
            || panic!("SSHelter already answers: starting it again could run two"),
            Duration::ZERO,
        );
        assert_eq!(found, Ok("bridge"));
    }

    #[test]
    fn parallel_calls_start_sshelter_once() {
        let running = Arc::new(AtomicBool::new(false));
        let starts = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let locks = Arc::new(Mutex::new(()));
        let calls: Vec<_> = (0..4)
            .map(|_| {
                let (running, starts, locks) = (running.clone(), starts.clone(), locks.clone());
                thread::spawn(move || {
                    ensure_started(
                        || running.load(Ordering::SeqCst).then_some(()),
                        || SpawnLocks::Held(locks.lock().unwrap()),
                        || {
                            starts.fetch_add(1, Ordering::SeqCst);
                            // Its bridge answers a little later, as a real start's does.
                            let running = running.clone();
                            thread::spawn(move || {
                                thread::sleep(Duration::from_millis(50));
                                running.store(true, Ordering::SeqCst);
                            });
                            Ok(())
                        },
                        Duration::from_secs(5),
                    )
                })
            })
            .collect();
        for call in calls {
            assert_eq!(call.join().unwrap(), Ok(()));
        }
        assert_eq!(starts.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn no_answer_after_the_start_says_what_to_do() {
        let mut starts = 0;
        let result: Result<(), String> = ensure_started(
            || None,
            || SpawnLocks::Held(()),
            || {
                starts += 1;
                Ok(())
            },
            Duration::ZERO,
        );
        assert_eq!(result, Err(NO_ANSWER.to_string()));
        assert_eq!(starts, 1);
    }

    #[test]
    fn when_another_adapter_keeps_the_locks_one_more_look_decides() {
        let no_start = || -> Result<(), String> { panic!("the other adapter may be starting it") };
        let mut answers = [None, Some("bridge")].into_iter();
        let found = ensure_started(
            || answers.next().flatten(),
            || SpawnLocks::<()>::Busy,
            no_start,
            Duration::ZERO,
        );
        assert_eq!(found, Ok("bridge"));

        let found: Result<(), String> =
            ensure_started(|| None, || SpawnLocks::<()>::Busy, no_start, Duration::ZERO);
        assert_eq!(found, Err(NO_ANSWER.to_string()));
    }

    fn held(lock: FileLock) -> File {
        match lock {
            FileLock::Held(file) => file,
            FileLock::Busy => panic!("busy"),
            FileLock::Unavailable(e) => panic!("{e}"),
        }
    }

    #[test]
    fn the_spawn_lock_file_lets_one_adapter_in_at_a_time() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("app-data").join("mcp-spawn.lock");
        let first = held(lock_file_until(&path, Instant::now()));
        let second = lock_file_until(&path, Instant::now());
        assert!(matches!(second, FileLock::Busy));
        drop(first);
        // Free again: taken, even if it takes a few tries.
        let soon = Instant::now() + Duration::from_secs(5);
        held(lock_file_until(&path, soon));
    }

    #[test]
    fn a_spawn_lock_held_past_the_deadline_ends_the_call_after_one_more_ping() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("mcp-spawn.lock");
        // Another adapter holds it, stopped in the middle of a start.
        let _other = held(lock_file_until(&path, Instant::now()));
        let mut pings = 0;
        let began = Instant::now();
        let result: Result<(), String> = ensure_started(
            || {
                pings += 1;
                None
            },
            || take_spawn_locks_at(Ok(path.clone()), began + Duration::from_millis(300)),
            || panic!("the other adapter may be starting it"),
            Duration::from_secs(5),
        );
        assert_eq!(result, Err(NO_ANSWER.to_string()));
        assert_eq!(pings, 2, "the first look, and one more at the deadline");
        assert!(began.elapsed() >= Duration::from_millis(300));
        assert!(began.elapsed() < Duration::from_secs(5));
    }

    #[test]
    fn without_a_lock_file_the_call_still_starts_sshelter() {
        let dir = tempfile::tempdir().unwrap();
        let not_a_dir = dir.path().join("file");
        std::fs::write(&not_a_dir, b"").unwrap();
        let path = not_a_dir.join("mcp-spawn.lock");
        assert!(matches!(
            lock_file_until(&path, Instant::now()),
            FileLock::Unavailable(_)
        ));

        let mut starts = 0;
        let mut answers = [None, None, Some("bridge")].into_iter();
        let found = ensure_started(
            || answers.next().flatten(),
            || take_spawn_locks_at(Ok(path.clone()), Instant::now()),
            || {
                starts += 1;
                Ok(())
            },
            Duration::from_secs(5),
        );
        assert_eq!(found, Ok("bridge"));
        assert_eq!(starts, 1);
    }

    #[test]
    fn the_adapter_starts_the_mcp_host_with_its_window_hidden() {
        use std::ffi::OsStr;
        let command = host_command(Path::new("/usr/bin/sshelter"));
        let args: Vec<_> = command.get_args().collect();
        assert_eq!(args, [OsStr::new(HOST_FLAG)]);
        let flag = command
            .get_envs()
            .find(|(key, _)| *key == OsStr::new(crate::START_HIDDEN_ENV))
            .and_then(|(_, value)| value);
        assert!(crate::starts_hidden(flag));
    }

    #[cfg(unix)]
    #[test]
    fn the_host_starts_in_its_own_process_group() {
        let mut command = Command::new("cat");
        command.stdin(Stdio::piped()).stdout(Stdio::null());
        detach_from_adapter(&mut command);
        let mut child = crate::process::spawn(&mut command).unwrap();
        let pid = child.id() as libc::pid_t;
        let group = unsafe { libc::getpgid(pid) };
        let ours = unsafe { libc::getpgid(0) };
        drop(child.stdin.take()); // `cat` exits at end of input.
        child.wait().unwrap();
        assert_eq!(group, pid);
        assert_ne!(group, ours);
    }
}
