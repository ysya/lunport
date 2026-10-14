//! Records execution service shared by the OS-authenticated broker and native UI.
use super::*;
use crate::session::{
    auth::{KeyStore, Owner, Reply},
    connect::{CancelToken, Connector, HostKeyConfirmer, HostKeyQuestion},
    protocol::{HostQuery, QuestionKind},
};
use crate::ssh::{
    AuthMethod, AuthSource, ConnectError, Ended, HostKeyPolicy, Session, SshEngine, Target,
};

#[derive(Default)]
pub(super) struct AuditLog {
    pub path: Option<PathBuf>,
    pub error: Option<String>,
}

#[derive(Clone, Debug, Default)]
pub struct RequestContext {
    pub id: String,
    pub requested_by: Vec<String>,
    pub requester_id: Option<String>,
    pub client_info: McpClientInfo,
}
impl RequestContext {
    pub fn from_peer(pid: Option<u32>, info: Option<&Value>) -> Self {
        let own = std::env::current_exe()
            .ok()
            .map(|p| std::fs::canonicalize(&p).unwrap_or(p));
        let program = pid.and_then(|pid| {
            crate::ipc::peer::identify(&crate::session::broker::without_own_executable(
                crate::ipc::peer::process_chain(pid),
                own.as_deref(),
            ))
        });
        Self {
            id: String::new(),
            requested_by: program
                .as_ref()
                .map(|p| p.chain.clone())
                .unwrap_or_else(|| vec!["Unknown".into()]),
            requester_id: program.map(|p| p.identity),
            client_info: McpClientInfo::sanitize(info),
        }
    }
}

/// Public identity captured independently of the mutable key ID. Pins may legitimately be added by this connection.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ApprovedTarget {
    target: Target,
    keys: Vec<(String, Vec<u8>)>,
}
impl ApprovedTarget {
    pub fn capture(target: &Target, keys: &dyn KeyStore) -> Result<Self, String> {
        let mut target = target.clone();
        let mut identities = Vec::new();
        for hop in &mut target.hops {
            hop.pinned = None;
            if let AuthMethod::Key { key_id } = &hop.auth {
                let key = keys.key(key_id).ok_or("The approved key is unavailable.")?;
                let public = crate::ssh::HostKey::from_openssh_line(&key.public_key)
                    .ok_or("The approved key identity is invalid.")?;
                identities.push((key_id.clone(), public.public_key));
            }
        }
        Ok(Self {
            target,
            keys: identities,
        })
    }
    pub fn check(&self, connector: &Connector<'_>, query: &HostQuery) -> Result<(), String> {
        let target = connector
            .directory
            .resolve_public(query)
            .map_err(|e| e.to_string())?;
        if *self != Self::capture(&target, connector.keys)? {
            return Err(
                "The approved destination, route or key changed; request approval again.".into(),
            );
        }
        Ok(())
    }
}
struct NoInteraction<'a> {
    owner: &'a dyn Owner,
    enabled: bool,
    needed: AtomicBool,
}
impl Owner for NoInteraction<'_> {
    fn ask(&self, k: QuestionKind, t: &str, e: bool, d: Option<Instant>) -> Reply {
        if self.enabled {
            self.needed.store(true, Ordering::SeqCst);
            Reply::Cancelled
        } else {
            self.owner.ask(k, t, e, d)
        }
    }
    fn ask_at(
        &self,
        h: &crate::ssh::HopRef,
        k: QuestionKind,
        t: &str,
        e: bool,
        d: Option<Instant>,
    ) -> Reply {
        if self.enabled {
            self.needed.store(true, Ordering::SeqCst);
            Reply::Cancelled
        } else {
            self.owner.ask_at(h, k, t, e, d)
        }
    }
    fn host_key_notice(&self, t: &str) {
        if !self.enabled {
            self.owner.host_key_notice(t)
        }
    }
    fn banner(&self, t: &str) {
        if !self.enabled {
            self.owner.banner(t)
        }
    }
}
struct NoPin<'a> {
    confirmer: &'a dyn HostKeyConfirmer,
    enabled: bool,
    needed: AtomicBool,
}
impl HostKeyConfirmer for NoPin<'_> {
    fn confirm(&self, q: &HostKeyQuestion, c: &CancelToken) -> Option<String> {
        if self.enabled {
            self.needed.store(true, Ordering::SeqCst);
            None
        } else {
            self.confirmer.confirm(q, c)
        }
    }
}
struct CheckedEngine<'a> {
    inner: &'a dyn SshEngine,
    check: &'a (dyn Fn() -> Result<(), String> + Sync),
}
impl SshEngine for CheckedEngine<'_> {
    fn connect(
        &self,
        t: &Target,
        p: &dyn HostKeyPolicy,
        a: &dyn AuthSource,
    ) -> Result<Box<dyn Session>, ConnectError> {
        (self.check)().map_err(|reason| ConnectError::BadJumpChain { why: reason })?;
        self.inner.connect(t, p, a)
    }
}

/// Uses public resolution; private material is verified by KeyStore immediately before authentication.
struct PublicDirectory<'a>(
    &'a dyn crate::session::directory::HostDirectory,
    &'a (dyn Fn() -> Result<(), String> + Sync),
);
impl crate::session::directory::HostDirectory for PublicDirectory<'_> {
    fn resolve(&self, q: &HostQuery) -> Result<Target, crate::session::directory::DirectoryError> {
        self.0.resolve_public(q)
    }
    fn pinned(
        &self,
        h: &crate::ssh::HostId,
    ) -> Result<
        Option<crate::session::directory::PinnedKey>,
        crate::session::directory::DirectoryError,
    > {
        self.0.pinned(h)
    }
    fn pin(
        &self,
        h: &crate::ssh::HostId,
        k: &crate::ssh::HostKey,
    ) -> Result<(), crate::session::directory::DirectoryError> {
        self.0.pin(h, k)
    }
    fn replace_pin(
        &self,
        h: &crate::ssh::HostId,
        p: &crate::ssh::HostKey,
        k: &crate::ssh::HostKey,
    ) -> Result<(), crate::session::directory::DirectoryError> {
        self.0.replace_pin(h, p, k)
    }
    fn pinned_for(
        &self,
        h: &crate::ssh::HopRef,
    ) -> Result<
        Option<crate::session::directory::PinnedKey>,
        crate::session::directory::DirectoryError,
    > {
        self.0.pinned_for(h)
    }
    fn pin_for(
        &self,
        h: &crate::ssh::HopRef,
        k: &crate::ssh::HostKey,
    ) -> Result<(), crate::session::directory::DirectoryError> {
        self.0.pin_for(h, k)
    }
    fn replace_pin_for(
        &self,
        h: &crate::ssh::HopRef,
        p: &crate::ssh::HostKey,
        k: &crate::ssh::HostKey,
    ) -> Result<(), crate::session::directory::DirectoryError> {
        self.0.replace_pin_for(h, p, k)
    }
    fn pin_confirmed(
        &self,
        hop: &crate::ssh::HopRef,
        previous: Option<&crate::ssh::HostKey>,
        key: &crate::ssh::HostKey,
        cancel: &CancelToken,
        guard: &(dyn Fn() -> Result<(), crate::session::directory::DirectoryError> + Sync),
    ) -> Result<(), crate::session::directory::DirectoryError> {
        self.0.pin_confirmed(hop, previous, key, cancel, &|| {
            guard()?;
            (self.1)().map_err(crate::session::directory::DirectoryError::Failed)
        })
    }
    fn password_account(&self, h: &crate::ssh::HostId) -> String {
        self.0.password_account(h)
    }
}
fn credential_reason(error: &str) -> &'static str {
    if error.contains("no verified noninteractive")
        || error.contains("noninteractive vault access is unavailable")
    {
        "needs interaction: credential provider does not support noninteractive reads"
    } else {
        "needs interaction: stored credential or vault is missing, locked, or unavailable"
    }
}
struct CredentialView<'a> {
    source: &'a dyn crate::sync::env::Keychain,
    reason: Mutex<Option<&'static str>>,
}
impl crate::sync::env::Keychain for CredentialView<'_> {
    fn get(&self, account: &str) -> Result<Option<String>, AppError> {
        let result = self.source.get_noninteractive(account);
        if let Err(error) = &result {
            *self.reason.lock().unwrap() = Some(credential_reason(&error.to_string()));
        }
        result
    }
    fn set(&self, _: &str, _: &str) -> Result<(), AppError> {
        Err(AppError::Other(
            "needs interaction: credential writes are disabled".into(),
        ))
    }
    fn delete(&self, _: &str) -> Result<(), AppError> {
        Err(AppError::Other(
            "needs interaction: credential deletion is disabled".into(),
        ))
    }
}
struct KeyView<'a> {
    keys: &'a dyn KeyStore,
    noninteractive: bool,
    reason: Mutex<Option<&'static str>>,
}
impl KeyStore for KeyView<'_> {
    fn key(&self, id: &str) -> Option<crate::session::auth::VaultKey> {
        self.keys.key(id)
    }
    fn private_text(&self, id: &str) -> Result<Option<zeroize::Zeroizing<String>>, String> {
        if self.noninteractive {
            let result = self.keys.private_text_noninteractive(id);
            if let Err(error) = &result {
                *self.reason.lock().unwrap() = Some(credential_reason(error));
            }
            result
        } else {
            self.keys.private_text(id)
        }
    }
}

#[cfg(test)]
pub(super) fn execute(
    runtime: &McpRuntime,
    connector: &Connector<'_>,
    alias: &str,
    command: &str,
    timeout: u64,
    cancel: &CancelToken,
    owner: &dyn Owner,
    approve: &(dyn Fn(&McpPendingRequest) -> ApprovalDecision + Sync),
) -> Result<Value, String> {
    execute_context(
        runtime,
        connector,
        alias,
        command,
        timeout,
        cancel,
        owner,
        approve,
        RequestContext::default(),
    )
}
pub(super) fn execute_context(
    runtime: &McpRuntime,
    connector: &Connector<'_>,
    alias: &str,
    command: &str,
    timeout: u64,
    cancel: &CancelToken,
    owner: &dyn Owner,
    approve: &(dyn Fn(&McpPendingRequest) -> ApprovalDecision + Sync),
    mut context: RequestContext,
) -> Result<Value, String> {
    if !display_safe_command(command) {
        return Err("Command is empty, unsafe to display, or exceeds 16384 bytes.".into());
    }
    if !(1..=300).contains(&timeout) {
        return Err("timeout_seconds must be an integer from 1 to 300.".into());
    }
    if cancel.is_cancelled() {
        return Err("MCP request was canceled".into());
    }
    let target = connector
        .directory
        .resolve_public(&HostQuery::Id(alias.into()))
        .or_else(|_| {
            connector
                .directory
                .resolve_public(&HostQuery::Alias(alias.into()))
        })
        .map_err(|e| e.to_string())?;
    let destination = target.hops.last().ok_or("No destination.")?;
    let host_id = destination.id.as_str().to_string();
    let query = HostQuery::Id(host_id.clone());
    let approved = ApprovedTarget::capture(&target, connector.keys)?;
    let policy = runtime.policy.lock().unwrap().clone();

    if context.id.is_empty() {
        context.id = format!(
            "records-{}",
            runtime.next_request_id.fetch_add(1, Ordering::Relaxed)
        );
    }
    struct Active<'a> {
        runtime: &'a McpRuntime,
        id: String,
    }
    impl Drop for Active<'_> {
        fn drop(&mut self) {
            self.runtime.records_active.lock().unwrap().remove(&self.id);
        }
    }
    {
        let mut active = runtime.records_active.lock().unwrap();
        if active.contains_key(&context.id) {
            return Err("duplicate MCP request id".into());
        }
        active.insert(context.id.clone(), (host_id.clone(), cancel.clone()));
    }
    let _active = Active {
        runtime,
        id: context.id.clone(),
    };
    let request = McpPendingRequest {
        id: context.id.clone(),
        alias: destination.alias.clone(),
        host_id: Some(host_id.clone()),
        command: command.into(),
        hostname: Some(destination.hostname.clone()),
        user: Some(destination.user.clone()),
        port: Some(destination.port.to_string()),
        route: target
            .hops
            .iter()
            .map(|h| format!("{}@{}:{} ({})", h.user, h.hostname, h.port, h.alias))
            .collect(),
        requested_by: context.requested_by.clone(),
        requester_id: context.requester_id.clone(),
        client_info: context.client_info.clone(),
        requested_at_ms: unix_ms(),
    };
    let mode = policy.approval_mode;
    let check = || {
        if cancel.is_cancelled() {
            return Err("MCP request was canceled".into());
        }
        let current = runtime.policy.lock().unwrap().clone();
        if !current.enabled || current.approval_mode != mode {
            return Err("MCP policy changed; request approval again.".into());
        }
        ensure_allowed(&current, &host_id)?;
        approved.check(connector, &query)
    };
    struct Stop<'a>(&'a AtomicBool);
    impl Drop for Stop<'_> {
        fn drop(&mut self) {
            self.0.store(true, Ordering::SeqCst);
        }
    }
    let done = AtomicBool::new(false);
    let result = std::thread::scope(|scope| {
        // Revoke/disable and disconnect wake native authentication and approval while the worker waits.
        scope.spawn(|| {
            while !done.load(Ordering::SeqCst) {
                let p = runtime.policy.lock().unwrap().clone();
                if policy.enabled
                    && policy.allowed_hosts.contains(&host_id)
                    && (!p.enabled
                        || p.approval_mode != mode
                        || !p.allowed_hosts.contains(&host_id))
                {
                    cancel.cancel();
                    break;
                }
                std::thread::sleep(Duration::from_millis(25));
            }
        });
        let _stop = Stop(&done);
        let result = (|| {
            if !policy.enabled || !policy.allowed_hosts.contains(&host_id) {
                return Err("MCP request was denied by host policy".into());
            }
            if mode == ApprovalMode::Ask {
                match approve(&request) {
                    ApprovalDecision::Allow => {}
                    ApprovalDecision::Deny => return Err("MCP request was denied".into()),
                    ApprovalDecision::TimedOut => return Err("MCP approval timed out".into()),
                    ApprovalDecision::Cancel => {
                        cancel.cancel();
                        return Err("MCP request was canceled".into());
                    }
                }
            }
            check()?;
            let owner = NoInteraction {
                owner,
                enabled: mode == ApprovalMode::AutoLog,
                needed: AtomicBool::new(false),
            };
            let confirmer = NoPin {
                confirmer: connector.confirmer,
                enabled: mode == ApprovalMode::AutoLog,
                needed: AtomicBool::new(false),
            };
            if mode == ApprovalMode::AutoLog && target.hops.iter().any(|h| h.pinned.is_none()) {
                return Err("needs interaction: host key is not pinned".into());
            }
            let engine = CheckedEngine {
                inner: connector.engine,
                check: &check,
            };
            let keys = KeyView {
                keys: connector.keys,
                noninteractive: mode == ApprovalMode::AutoLog,
                reason: Mutex::new(None),
            };
            let noninteractive = CredentialView {
                source: connector.keychain,
                reason: Mutex::new(None),
            };
            let keychain = if mode == ApprovalMode::AutoLog {
                &noninteractive as &dyn crate::sync::env::Keychain
            } else {
                connector.keychain
            };
            let directory = PublicDirectory(connector.directory,&check);
            let guarded = Connector {
                engine: &engine,
                confirmer: &confirmer,
                keys: &keys,
                keychain,
                directory: &directory,
            };
            let interaction_reason = || {
                (*keys.reason.lock().unwrap()).or(*noninteractive.reason.lock().unwrap())
                    .or_else(||confirmer.needed.load(Ordering::SeqCst).then_some("needs interaction: host key confirmation is required"))
                    .or_else(||owner.needed.load(Ordering::SeqCst).then_some("needs interaction: stored credentials are missing or authentication requires input"))
            };
            let connected = guarded
                .connect(&query, &owner, cancel)
                .map_err(|e| interaction_reason().map(str::to_owned).unwrap_or(e.text))?;
            if let Some(reason) = interaction_reason() {
                connected.session.close();
                return Err(reason.into());
            }
            if let Err(error) = check() {
                connected.session.close();
                return Err(error);
            }
            let over = AtomicBool::new(false);
            let output = std::thread::scope(|scope| {
                scope.spawn(|| {
                    while !over.load(Ordering::SeqCst) {
                        if cancel.is_cancelled() {
                            connected.session.close();
                            break;
                        }
                        std::thread::sleep(Duration::from_millis(25));
                    }
                });
                let _stop = Stop(&over);
                let output =
                    connected
                        .session
                        .exec(command, Duration::from_secs(timeout), 128 * 1024);
                over.store(true, Ordering::SeqCst);
                output
            });
            connected.session.close();
            if cancel.is_cancelled() && output.is_err() {
                return Ok(
                    json!({"stdout":"","stderr":"","ended":"canceled","exit_code":null,"signal":null,"truncated":false}),
                );
            }
            let output =
                output.map_err(|_| "Remote execution failed; it was not retried.".to_string())?;
            Ok(
                json!({"stdout":String::from_utf8_lossy(&output.stdout),"stderr":String::from_utf8_lossy(&output.stderr),"ended":if cancel.is_cancelled(){"canceled"}else{match output.ended {Ended::Exited=>"exited",Ended::Signaled=>"signaled",Ended::TimedOut=>"timed_out",Ended::Truncated=>"truncated",Ended::Disconnected=>"disconnected"}},"exit_code":output.exit_code,"signal":output.signal,"truncated":output.truncated}),
            )
        })();
        done.store(true, Ordering::SeqCst);
        result
    });
    let value = result.as_ref().ok();
    runtime.record(McpAuditEntry {
        id: context.id,
        alias: destination.alias.clone(),
        command: command.into(),
        client: "mcp".into(),
        host_id: Some(host_id),
        mode,
        requested_by: context.requested_by,
        requester_id: context.requester_id,
        client_info: context.client_info,
        at_ms: unix_ms(),
        completed_at_ms: unix_ms(),
        outcome: if cancel.is_cancelled() {
            "canceled"
        } else if result.is_ok() {
            "allowed"
        } else if result
            .as_ref()
            .err()
            .is_some_and(|e: &String| e.contains("timed out"))
        {
            "timed_out"
        } else if result
            .as_ref()
            .err()
            .is_some_and(|e: &String| e.contains("denied"))
        {
            "denied"
        } else {
            "error"
        }
        .into(),
        ended: value.and_then(|v| v["ended"].as_str().map(str::to_owned)),
        exit_code: value
            .and_then(|v| v["exit_code"].as_u64())
            .and_then(|n| i64::try_from(n).ok()),
        signal: value.and_then(|v| v["signal"].as_str().map(str::to_owned)),
        detail: None,
    });
    match result {
        Ok(mut value) => {
            if let Some(error) = runtime.audit.lock().unwrap().error.clone() {
                value["audit_error"] = json!(error);
            }
            Ok(value)
        }
        Err(e) => Err(e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::session::testing::{FakeConfirmer, FakeDirectory, FakeKeys, FakeOwner};
    use crate::ssh::{
        fake::{default_server_key, FakeEngine, FakeEvent},
        AuthMethod, Ended, ExecResult,
    };
    use crate::sync::testkit::MemKeychain;

    #[test]
    fn allowed_id_executes_without_pty_and_preserves_disconnected_null_status() {
        let runtime = McpRuntime::default();
        runtime.policy.lock().unwrap().enabled = true;
        runtime
            .policy
            .lock()
            .unwrap()
            .allowed_hosts
            .insert("id-web".into());
        let engine = FakeEngine::new().with_exec(
            "uptime",
            ExecResult {
                ended: Ended::Disconnected,
                exit_code: None,
                signal: None,
                stdout: b"partial".to_vec(),
                stderr: vec![],
                truncated: false,
            },
        );
        let directory = FakeDirectory::new()
            .with_host(
                "web",
                AuthMethod::Key {
                    key_id: "k-plain".into(),
                },
            )
            .with_pin("web", default_server_key());
        let keys = FakeKeys::new();
        let keychain = MemKeychain::default();
        let confirmer = FakeConfirmer::default();
        let connector = Connector {
            engine: &engine,
            directory: &directory,
            keys: &keys,
            keychain: &keychain,
            confirmer: &confirmer,
        };
        let value = execute(
            &runtime,
            &connector,
            "id-web",
            "uptime",
            60,
            &CancelToken::default(),
            &FakeOwner::default(),
            &|_| ApprovalDecision::Allow,
        )
        .unwrap();
        assert_eq!(value["ended"], "disconnected");
        assert!(value["exit_code"].is_null());
        assert!(engine.events().contains(&FakeEvent::Exec {
            command: "uptime".into(),
            timeout: Duration::from_secs(60),
            output_cap: 128 * 1024
        }));
        assert!(!engine
            .events()
            .iter()
            .any(|e| matches!(e, FakeEvent::ShellOpened { .. })));
    }
}

pub(super) fn validate_method(method: &str) -> Result<(), String> {
    if method == "run" {
        Err("run was renamed to ssh_exec".into())
    } else if matches!(
        method,
        "list_hosts" | "get_host" | "get_effective_config" | "ssh_exec"
    ) {
        Ok(())
    } else {
        Err("Unknown MCP method".into())
    }
}

pub(crate) fn dispatch(
    app: &AppHandle,
    connector: &Connector<'_>,
    method: &str,
    params: &Value,
    context: RequestContext,
    cancel: &CancelToken,
) -> Result<Value, String> {
    use crate::sync::{record_repository as repo, record_runtime::RuntimeFormat};
    let state = app.state::<AppState>();
    let records = {
        let _lifecycle = state.sync.lifecycle.lock().unwrap();
        let core = state.sync.core.lock().unwrap();
        match core.format {
            RuntimeFormat::Legacy if !core.legacy_paused => None,
            RuntimeFormat::Records => Some(
                core.records
                    .clone()
                    .ok_or("Records workspace is unavailable")?,
            ),
            _ => return Err("Choose a workspace or resolve the blocked state first.".into()),
        }
    };
    let Some(records) = records else {
        super::ensure_legacy_bridge(app)?;
        return if method == "mode" {
            Ok(json!({"mode":"legacy"}))
        } else {
            Err("legacy_transport_required".into())
        };
    };
    if method == "mode" {
        return Ok(json!({"mode":"records"}));
    }
    validate_method(method)?;
    let policy = state.mcp.policy.lock().unwrap().clone();
    if !policy.enabled {
        return Err("MCP access is disabled in SSHelter Settings → AI Access".into());
    }
    state
        .mcp
        .last_client_at_ms
        .store(unix_ms(), Ordering::Relaxed);
    match method {
        "list_hosts" => {
            let hosts = repo::list_hosts(&records)
                .map_err(|e| e.to_string())?
                .into_iter()
                .filter(|v| policy.allowed_hosts.contains(&v.host.id))
                .map(|v| metadata(&records, &v))
                .collect::<Result<Vec<_>, _>>()?;
            Ok(json!({"hosts":hosts}))
        }
        "get_host" | "get_effective_config" => {
            let alias = string_param(params, "alias")?;
            let host = repo::get_host(&records, alias)
                .or_else(|_| repo::find_by_alias(&records, alias))
                .map_err(|e| e.to_string())?;
            ensure_allowed(&policy, &host.host.id)?;
            metadata(&records, &host)
        }
        "ssh_exec" => {
            let alias = string_param(params, "alias")?;
            let command = params
                .get("command")
                .and_then(Value::as_str)
                .ok_or("missing command")?;
            let timeout = match params.get("timeout_seconds") {
                None => 60,
                Some(v) => v
                    .as_u64()
                    .filter(|n| (1..=300).contains(n))
                    .ok_or("timeout_seconds must be an integer from 1 to 300")?,
            };
            let owner = crate::session::auth_window::NativeOwner {
                hub: state.session.auth_questions.clone(),
                surface: Arc::new(crate::session::auth_window::TauriAuthSurface {
                    app: app.clone(),
                }),
                request_id: context.id.clone(),
                cancel: cancel.clone(),
            };
            execute_context(
                &state.mcp,
                connector,
                alias,
                command,
                timeout,
                cancel,
                &owner,
                &|request| {
                    state.mcp.wait_approval(request,cancel,APPROVAL_TIMEOUT,||{
                        crate::show_main_window(app);
                        let _=app.emit("mcp://approval-requested",request);
                    })
                },
                context,
            )
        }
        _ => Err(format!("Unknown MCP method: {method}")),
    }
}
fn metadata(
    state: &crate::sync::records_v3::SyncStateV3,
    view: &crate::sync::record_repository::HostView,
) -> Result<Value, String> {
    if view.group_error.is_some() {
        return Err("Host Group inheritance needs review.".into());
    }
    let p = &view.effective_payload;
    let path =
        crate::sync::record_groups::ancestor_path(state, &view.host.scope, p.group_id.as_deref())
            .map_err(|e| e.to_string())?;
    let user = if p.user.is_empty() {
        crate::session::os_identity::current_username()
            .map_err(|_| "Cannot read OS username".to_string())?
    } else {
        p.user.clone()
    };
    let safe = |s: &str| crate::session::auth::printable(s).replace(['\n', '\t'], "?");
    Ok(
        json!({"id":view.host.id,"alias":safe(&p.alias),"hostname":safe(&p.hostname),"user":safe(&user),"port":p.port,"auth":p.auth,"key_id":p.key_id,"jump_ids":p.jump,"tags":p.tags.iter().map(|t|safe(t)).collect::<Vec<_>>(),"scope":view.host.scope,"group_path":path.iter().rev().map(|g|json!({"id":g.id,"name":safe(&g.payload.name)})).collect::<Vec<_>>(),"inherited_from":view.inherited_from}),
    )
}

#[cfg(test)]
mod behavior_tests {
    use super::*;
    use crate::session::testing::{FakeConfirmer, FakeDirectory, FakeKeys, FakeOwner};
    use crate::ssh::{
        fake::{default_server_key, FakeEngine, FakeEvent, FakeLogin, FakeMethods},
        ExecResult,
    };
    use crate::sync::testkit::MemKeychain;
    fn runtime(mode: ApprovalMode) -> McpRuntime {
        let r = McpRuntime::default();
        *r.policy.lock().unwrap() = McpPolicy {
            enabled: true,
            allowed_hosts: BTreeSet::from(["id-web".into()]),
            approval_mode: mode,
        };
        r
    }
    fn directory(auth: AuthMethod, pinned: bool) -> FakeDirectory {
        let d = FakeDirectory::new().with_host("web", auth);
        if pinned {
            d.with_pin("web", default_server_key())
        } else {
            d
        }
    }
    fn run(
        r: &McpRuntime,
        e: &FakeEngine,
        d: &FakeDirectory,
        owner: &FakeOwner,
        approve: &(dyn Fn(&McpPendingRequest) -> ApprovalDecision + Sync),
    ) -> Result<Value, String> {
        execute(
            r,
            &Connector {
                engine: e,
                directory: d,
                keys: &FakeKeys::new(),
                keychain: &MemKeychain::default(),
                confirmer: &FakeConfirmer::default(),
            },
            "id-web",
            "uptime",
            60,
            &CancelToken::default(),
            owner,
            approve,
        )
    }
    #[test]
    fn denied_host_never_reaches_engine_and_is_audited() {
        let r = runtime(ApprovalMode::Ask);
        r.policy.lock().unwrap().allowed_hosts.clear();
        let e = FakeEngine::new();
        assert!(run(
            &r,
            &e,
            &directory(AuthMethod::Password, true),
            &FakeOwner::default(),
            &|_| panic!("denied hosts never ask")
        )
        .is_err());
        assert!(e.events().is_empty());
        assert_eq!(r.status().recent[0].outcome, "denied");
    }
    #[test]
    fn all_auto_log_interactions_fail_without_asking_or_pinning() {
        for (auth, pinned, login) in [
            (
                AuthMethod::Password,
                true,
                FakeLogin::Server(FakeMethods::password("secret")),
            ),
            (
                AuthMethod::Key {
                    key_id: "k-enc".into(),
                },
                true,
                FakeLogin::Accept,
            ),
            (
                AuthMethod::Interactive,
                true,
                FakeLogin::Server(FakeMethods::interactive("2FA:", "code")),
            ),
            (
                AuthMethod::Key {
                    key_id: "k-plain".into(),
                },
                false,
                FakeLogin::Accept,
            ),
        ] {
            let r = runtime(ApprovalMode::AutoLog);
            let e = FakeEngine::new().with_login(login);
            let owner = FakeOwner::default();
            let d = directory(auth, pinned);
            let error = run(&r, &e, &d, &owner, &|_| {
                panic!("auto-log never asks approval")
            })
            .unwrap_err();
            assert!(error.starts_with("needs interaction:"), "{error}");
            assert!(owner.asked().is_empty());
            assert!(!e
                .events()
                .iter()
                .any(|e| matches!(e, FakeEvent::Exec { .. })));
        }
    }
    #[test]
    fn changed_target_after_approval_never_connects() {
        use crate::session::directory::{DirectoryError, HostDirectory, PinnedKey};
        use crate::ssh::{HostId, HostKey};
        struct Mutable(Mutex<FakeDirectory>);
        impl HostDirectory for Mutable {
            fn resolve(&self, q: &HostQuery) -> Result<Target, DirectoryError> {
                self.0.lock().unwrap().resolve(q)
            }
            fn pinned(&self, h: &HostId) -> Result<Option<PinnedKey>, DirectoryError> {
                self.0.lock().unwrap().pinned(h)
            }
            fn pin(&self, h: &HostId, k: &HostKey) -> Result<(), DirectoryError> {
                self.0.lock().unwrap().pin(h, k)
            }
            fn replace_pin(
                &self,
                h: &HostId,
                p: &HostKey,
                k: &HostKey,
            ) -> Result<(), DirectoryError> {
                self.0.lock().unwrap().replace_pin(h, p, k)
            }
            fn password_account(&self, h: &HostId) -> String {
                self.0.lock().unwrap().password_account(h)
            }
        }
        let d = Mutable(Mutex::new(directory(AuthMethod::Password, true)));
        let e = FakeEngine::new();
        let r = runtime(ApprovalMode::Ask);
        let c = Connector {
            engine: &e,
            directory: &d,
            keys: &FakeKeys::new(),
            keychain: &MemKeychain::default(),
            confirmer: &FakeConfirmer::default(),
        };
        let error = execute(
            &r,
            &c,
            "id-web",
            "uptime",
            60,
            &CancelToken::default(),
            &FakeOwner::default(),
            &|_| {
                *d.0.lock().unwrap() = directory(AuthMethod::Password, true).with_address(
                    "web",
                    "changed.example",
                    2200,
                );
                ApprovalDecision::Allow
            },
        )
        .unwrap_err();
        assert!(error.contains("changed"));
        assert!(e.events().is_empty());
    }
    #[test]
    fn all_engine_endings_and_combined_cap_are_retained() {
        for ended in [
            Ended::Exited,
            Ended::Signaled,
            Ended::TimedOut,
            Ended::Truncated,
            Ended::Disconnected,
        ] {
            let e = FakeEngine::new().with_exec(
                "uptime",
                ExecResult {
                    ended,
                    exit_code: (ended == Ended::Exited).then_some(7),
                    signal: (ended == Ended::Signaled).then(|| "TERM".into()),
                    stdout: b"out".to_vec(),
                    stderr: b"err".to_vec(),
                    truncated: ended == Ended::Truncated,
                },
            );
            let value = run(
                &runtime(ApprovalMode::AutoLog),
                &e,
                &directory(
                    AuthMethod::Key {
                        key_id: "k-plain".into(),
                    },
                    true,
                ),
                &FakeOwner::default(),
                &|_| panic!(),
            )
            .unwrap();
            assert_eq!(value["stdout"], "out");
            assert_eq!(value["stderr"], "err");
            assert_eq!(value["truncated"], ended == Ended::Truncated);
            assert_eq!(value["exit_code"].is_null(), ended != Ended::Exited);
        }
        let e = FakeEngine::new().with_exec(
            "uptime",
            ExecResult {
                ended: Ended::Exited,
                exit_code: Some(0),
                signal: None,
                stdout: vec![b'a'; 100000],
                stderr: vec![b'b'; 100000],
                truncated: false,
            },
        );
        let value = run(
            &runtime(ApprovalMode::AutoLog),
            &e,
            &directory(
                AuthMethod::Key {
                    key_id: "k-plain".into(),
                },
                true,
            ),
            &FakeOwner::default(),
            &|_| panic!(),
        )
        .unwrap();
        assert_eq!(
            value["stdout"].as_str().unwrap().len() + value["stderr"].as_str().unwrap().len(),
            128 * 1024
        );
        assert_eq!(value["ended"], "truncated");
    }
    #[test]
    fn saved_password_auto_log_never_prompts_and_persists_no_secret_output() {
        use crate::sync::env::Keychain;
        let r = runtime(ApprovalMode::AutoLog);
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("session-log.jsonl");
        r.load_audit(path.clone());
        let keychain = MemKeychain::default();
        keychain.set("host:id-web", "AUTH_SECRET_SENTINEL").unwrap();
        let engine = FakeEngine::new()
            .with_login(FakeLogin::Server(FakeMethods::password(
                "AUTH_SECRET_SENTINEL",
            )))
            .with_exec(
                "uptime",
                ExecResult {
                    stdout: b"STDOUT_SECRET_SENTINEL".to_vec(),
                    stderr: b"STDERR_SECRET_SENTINEL".to_vec(),
                    ended: Ended::Exited,
                    exit_code: Some(0),
                    signal: None,
                    truncated: false,
                },
            );
        let d = directory(AuthMethod::Password, true);
        let owner = FakeOwner::default();
        let connector = Connector {
            engine: &engine,
            directory: &d,
            keys: &FakeKeys::new(),
            keychain: &keychain,
            confirmer: &FakeConfirmer::default(),
        };
        let result = execute(
            &r,
            &connector,
            "id-web",
            "uptime",
            60,
            &CancelToken::default(),
            &owner,
            &|_| panic!(),
        )
        .unwrap();
        assert_eq!(result["stdout"], "STDOUT_SECRET_SENTINEL");
        assert!(owner.asked().is_empty());
        let bytes = std::fs::read_to_string(path).unwrap();
        for secret in [
            "AUTH_SECRET_SENTINEL",
            "STDOUT_SECRET_SENTINEL",
            "STDERR_SECRET_SENTINEL",
        ] {
            assert!(!bytes.contains(secret));
        }
    }
    #[test]
    fn approval_timeout_and_denial_never_connect_and_are_audited() {
        for (decision, outcome) in [
            (ApprovalDecision::TimedOut, "timed_out"),
            (ApprovalDecision::Deny, "denied"),
            (ApprovalDecision::Cancel, "canceled"),
        ] {
            let r = runtime(ApprovalMode::Ask);
            let e = FakeEngine::new();
            assert!(run(
                &r,
                &e,
                &directory(AuthMethod::Password, true),
                &FakeOwner::default(),
                &|_| decision
            )
            .is_err());
            assert!(e.events().is_empty());
            assert_eq!(r.status().recent[0].outcome, outcome);
        }
    }
    #[test]
    fn audit_restart_cap_partial_tail_and_failure_are_visible_without_output_or_auth() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("session-log.jsonl");
        let r = runtime(ApprovalMode::Ask);
        r.load_audit(path.clone());
        // Set up the cap without 1000 redundant atomic writes.
        {
            let mut recent = r.recent.lock().unwrap();
            for n in 0..1000 {
                recent.push_back(McpAuditEntry {
                    id: n.to_string(),
                    ..Default::default()
                });
            }
        }
        r.record(McpAuditEntry {
            id: "new".into(),
            command: "uptime".into(),
            detail: Some("OUTPUT_SECRET_SENTINEL".into()),
            ..Default::default()
        });
        assert_eq!(r.recent.lock().unwrap().len(), 1000);
        assert!(r.status().recent[0].detail.is_none());
        let bytes = std::fs::read(&path).unwrap();
        assert!(!String::from_utf8_lossy(&bytes).contains("OUTPUT_SECRET_SENTINEL"));
        use std::io::Write;
        std::fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap()
            .write_all(b"{partial")
            .unwrap();
        let restarted = McpRuntime::default();
        restarted.load_audit(path);
        assert_eq!(restarted.status().recent[0].id, "new");
        assert_eq!(restarted.status().recent.len(), 10);
        assert!(restarted.status().audit_error.unwrap().contains("Partial"));
        r.audit.lock().unwrap().path = Some(
            dir.path()
                .join("missing")
                .join("blocked")
                .join("session-log.jsonl"),
        );
        // Atomic writes can create missing parents, so a file used as parent is the deterministic I/O failure.
        let bad = dir.path().join("file");
        std::fs::write(&bad, b"not a directory").unwrap();
        r.audit.lock().unwrap().path = Some(bad.join("log"));
        r.record(McpAuditEntry::default());
        assert!(r.status().audit_error.is_some());
    }
}

#[cfg(test)]
mod identity_tests {
    use super::*;
    use crate::session::{
        directory::DirectoryError,
        record_directory::{RecordDirectory, RecordSources},
        testing::{FakeConfirmer, FakeDirectory, FakeKeys, FakeOwner},
    };
    use crate::ssh::{
        fake::{default_server_key, FakeEngine, FakeEvent},
        AuthMethod,
    };
    use crate::sync::{
        record_groups as groups, record_repository as repo, records_v3::*, testkit::MemKeychain,
    };
    #[test]
    fn group_derived_port_change_during_approval_cancels_without_changing_host_revision() {
        let state:SyncStateV3=serde_json::from_value(json!({"version":3,"device_id":"a".repeat(32),"device_name":"fixture","relay_url":"http://127.0.0.1:8787","account":null,"spaces":{},"local":{"hosts":{},"keys":{}},"rotation":null,"relay_features":null,"legacy_v1_backup":null,"phrase_cleanup_pending":false,"migration_gate":null,"shared_writes_blocked":false,"pending_account":null,"notices":[],"last_sync_ms":null,"last_error":null})).unwrap();
        let state = groups::create_group(
            &state,
            "0000000000000031",
            HostScope::Local,
            serde_json::from_value(
                json!({"schema":1,"name":"Ops","defaults":{"port":2222,"user":"ops"}}),
            )
            .unwrap(),
            true,
            1,
        )
        .unwrap();
        let payload=serde_json::from_value(json!({"schema":3,"alias":"web","hostname":"web.example.test","auth":"password","group_id":"0000000000000031","inherit":["port","user"]})).unwrap();
        let state = Arc::new(Mutex::new(
            repo::create_host(&state, "0000000000000001", HostScope::Local, payload, 2).unwrap(),
        ));
        let read = state.clone();
        let directory = RecordDirectory::new(RecordSources {
            snapshot: Box::new(move || Ok(read.lock().unwrap().clone())),
            material: Box::new(|_| {
                panic!("public target resolution must never read vault material")
            }),
            username: Box::new(|| Ok("local".into())),
            pin: Box::new(|_, _, _, _| panic!("stale target never pins")),
        });
        let runtime = McpRuntime::default();
        {
            let mut p = runtime.policy.lock().unwrap();
            p.enabled = true;
            p.allowed_hosts.insert("0000000000000001".into());
        }
        let engine = FakeEngine::new();
        let connector = Connector {
            engine: &engine,
            directory: &directory,
            keys: &FakeKeys::new(),
            keychain: &MemKeychain::default(),
            confirmer: &FakeConfirmer::default(),
        };
        let error = execute(
            &runtime,
            &connector,
            "0000000000000001",
            "uptime",
            60,
            &CancelToken::default(),
            &FakeOwner::default(),
            &|request| {
                assert_eq!(request.port.as_deref(), Some("2222"));
                let mut s = state.lock().unwrap();
                let before = repo::get_host(&s, "0000000000000001").unwrap().revision;
                let group = groups::list_groups(&s).unwrap().remove(0);
                let mut payload = group.group.payload;
                payload.defaults.port = Some(2223);
                *s =
                    groups::update_group(&s, &group.group.id, &group.revision, payload, 3).unwrap();
                assert_eq!(
                    repo::get_host(&s, "0000000000000001").unwrap().revision,
                    before
                );
                ApprovalDecision::Allow
            },
        )
        .unwrap_err();
        assert!(error.contains("changed"), "{error}");
        assert!(engine.events().is_empty());
    }
    #[test]
    fn replacing_public_identity_under_same_key_id_invalidates_approval() {
        struct Keys {
            key: Mutex<crate::session::auth::VaultKey>,
            fake: FakeKeys,
        }
        impl KeyStore for Keys {
            fn key(&self, _: &str) -> Option<crate::session::auth::VaultKey> {
                Some(self.key.lock().unwrap().clone())
            }
            fn private_text(&self, id: &str) -> Result<Option<zeroize::Zeroizing<String>>, String> {
                self.fake.private_text(id)
            }
        }
        let fake = FakeKeys::new();
        let keys = Keys {
            key: Mutex::new(fake.key("k-plain").unwrap()),
            fake,
        };
        let engine = FakeEngine::new();
        let directory = FakeDirectory::new()
            .with_host(
                "web",
                AuthMethod::Key {
                    key_id: "k-plain".into(),
                },
            )
            .with_pin("web", default_server_key());
        let r = McpRuntime::default();
        {
            let mut p = r.policy.lock().unwrap();
            p.enabled = true;
            p.allowed_hosts.insert("id-web".into());
        }
        let c = Connector {
            engine: &engine,
            directory: &directory,
            keys: &keys,
            keychain: &MemKeychain::default(),
            confirmer: &FakeConfirmer::default(),
        };
        let result = execute(
            &r,
            &c,
            "id-web",
            "uptime",
            60,
            &CancelToken::default(),
            &FakeOwner::default(),
            &|_| {
                keys.key.lock().unwrap().public_key =
                    crate::sync::slot_rules::test_keys::ECDSA_PUBLIC.into();
                ApprovalDecision::Allow
            },
        );
        assert!(result.unwrap_err().contains("changed"));
        assert!(!engine
            .events()
            .iter()
            .any(|e| matches!(e, FakeEvent::Exec { .. })));
    }
    #[test]
    fn noninteractive_vault_and_credentials_never_fall_back_to_interactive_reads() {
        struct LockedKeys(FakeKeys);
        impl KeyStore for LockedKeys {
            fn key(&self, id: &str) -> Option<crate::session::auth::VaultKey> {
                self.0.key(id)
            }
            fn private_text(&self, _: &str) -> Result<Option<zeroize::Zeroizing<String>>, String> {
                panic!("interactive vault read forbidden")
            }
        }
        struct LockedCredentials;
        impl crate::sync::env::Keychain for LockedCredentials {
            fn get(&self, _: &str) -> Result<Option<String>, AppError> {
                panic!("interactive OS read forbidden")
            }
            fn set(&self, _: &str, _: &str) -> Result<(), AppError> {
                panic!()
            }
            fn delete(&self, _: &str) -> Result<(), AppError> {
                panic!()
            }
        }
        let engine = FakeEngine::new();
        let keys = LockedKeys(FakeKeys::new());
        let keychain = LockedCredentials;
        let r = McpRuntime::default();
        {
            let mut p = r.policy.lock().unwrap();
            p.enabled = true;
            p.allowed_hosts.insert("id-web".into());
            p.approval_mode = ApprovalMode::AutoLog;
        }
        for auth in [
            AuthMethod::Key {
                key_id: "k-plain".into(),
            },
            AuthMethod::Password,
        ] {
            let d = FakeDirectory::new()
                .with_host("web", auth)
                .with_pin("web", default_server_key());
            let c = Connector {
                engine: &engine,
                directory: &d,
                keys: &keys,
                keychain: &keychain,
                confirmer: &FakeConfirmer::default(),
            };
            let error = execute(
                &r,
                &c,
                "id-web",
                "uptime",
                60,
                &CancelToken::default(),
                &FakeOwner::default(),
                &|_| panic!(),
            )
            .unwrap_err();
            assert!(
                error.contains("provider does not support noninteractive"),
                "{error}"
            );
        }
        let _ = DirectoryError::Failed(String::new());
    }
}

#[cfg(test)]
mod cancellation_tests {
    use super::*;
    use crate::session::testing::{FakeConfirmer, FakeDirectory, FakeKeys, FakeOwner};
    use crate::ssh::{
        fake::default_server_key, DisconnectReason, ExecResult, Pty, SessionError, ShellChannel,
    };
    use crate::sync::testkit::MemKeychain;
    struct Waiting {
        entered: Arc<AtomicBool>,
        closed: Arc<AtomicBool>,
    }
    impl SshEngine for Waiting {
        fn connect(
            &self,
            _: &Target,
            _: &dyn HostKeyPolicy,
            _: &dyn AuthSource,
        ) -> Result<Box<dyn Session>, ConnectError> {
            Ok(Box::new(Self {
                entered: self.entered.clone(),
                closed: self.closed.clone(),
            }))
        }
    }
    impl Session for Waiting {
        fn shell(&self, _: Pty) -> Result<Box<dyn ShellChannel>, SessionError> {
            panic!("MCP never allocates a PTY")
        }
        fn exec(&self, _: &str, _: Duration, _: usize) -> Result<ExecResult, SessionError> {
            self.entered.store(true, Ordering::SeqCst);
            let deadline = Instant::now() + Duration::from_secs(3);
            while !self.closed.load(Ordering::SeqCst) {
                assert!(Instant::now() < deadline);
                thread::sleep(Duration::from_millis(2));
            }
            Err(SessionError::Closed)
        }
        fn is_alive(&self) -> bool {
            !self.closed.load(Ordering::SeqCst)
        }
        fn disconnect_reason(&self) -> Option<DisconnectReason> {
            None
        }
        fn close(&self) {
            self.closed.store(true, Ordering::SeqCst);
        }
    }
    #[test]
    fn cancellation_and_revoke_during_exec_close_session_and_audit_once() {
        for revoke in [false, true] {
            let r = McpRuntime::default();
            {
                let mut p = r.policy.lock().unwrap();
                p.enabled = true;
                p.allowed_hosts.insert("id-web".into());
            }
            let cancel = CancelToken::default();
            let engine = Waiting {
                entered: Arc::new(AtomicBool::new(false)),
                closed: Arc::new(AtomicBool::new(false)),
            };
            let directory = FakeDirectory::new()
                .with_host(
                    "web",
                    AuthMethod::Key {
                        key_id: "k-plain".into(),
                    },
                )
                .with_pin("web", default_server_key());
            let connector = Connector {
                engine: &engine,
                directory: &directory,
                keys: &FakeKeys::new(),
                keychain: &MemKeychain::default(),
                confirmer: &FakeConfirmer::default(),
            };
            thread::scope(|scope| {
                let worker = scope.spawn(|| {
                    execute(
                        &r,
                        &connector,
                        "id-web",
                        "sleep 99",
                        60,
                        &cancel,
                        &FakeOwner::default(),
                        &|_| ApprovalDecision::Allow,
                    )
                });
                let end = Instant::now() + Duration::from_secs(3);
                while !engine.entered.load(Ordering::SeqCst) {
                    assert!(Instant::now() < end);
                    thread::sleep(Duration::from_millis(2));
                }
                if revoke {
                    r.policy.lock().unwrap().allowed_hosts.clear();
                } else {
                    cancel.cancel();
                }
                let output = worker.join().unwrap().unwrap();
                assert_eq!(output["ended"], "canceled");
                assert!(output["exit_code"].is_null());
            });
            assert!(engine.closed.load(Ordering::SeqCst));
            assert_eq!(r.status().recent.len(), 1);
            assert_eq!(r.status().recent[0].outcome, "canceled");
            assert!(r.records_active.lock().unwrap().is_empty());
        }
    }
    #[test]
    fn old_run_is_rejected_with_the_exact_rename_error() {
        assert_eq!(
            validate_method("run"),
            Err("run was renamed to ssh_exec".into())
        );
        assert!(validate_method("ssh_exec").is_ok());
        assert!(validate_method("get_effective_config").is_ok());
    }
}

#[cfg(test)]
mod approval_deadline_tests {
    use super::*;
    use crate::session::testing::{FakeConfirmer, FakeDirectory, FakeKeys, FakeOwner};
    use crate::ssh::fake::{default_server_key, FakeEngine};
    use crate::sync::testkit::MemKeychain;
    #[test]
    fn expired_pending_allow_is_rejected_without_connect_and_audited_timed_out() {
        let r = McpRuntime::default();
        {
            let mut p = r.policy.lock().unwrap();
            p.enabled = true;
            p.allowed_hosts.insert("id-web".into());
        }
        let e = FakeEngine::new();
        let d = FakeDirectory::new()
            .with_host("web", AuthMethod::Password)
            .with_pin("web", default_server_key());
        let c = Connector {
            engine: &e,
            directory: &d,
            keys: &FakeKeys::new(),
            keychain: &MemKeychain::default(),
            confirmer: &FakeConfirmer::default(),
        };
        let result = execute(
            &r,
            &c,
            "id-web",
            "uptime",
            60,
            &CancelToken::default(),
            &FakeOwner::default(),
            &|request| {
                r.wait_approval(
                    request,
                    &CancelToken::default(),
                    Duration::from_millis(1),
                    || {
                        thread::sleep(Duration::from_millis(5));
                        assert!(
                            r.pending.lock().unwrap().contains_key(&request.id),
                            "simulate a suspended waiter with pending still registered"
                        );
                        assert!(
                            r.resolve_approval(&request.id, true).is_err(),
                            "late resolve must fail at the command boundary"
                        );
                    },
                )
            },
        );
        assert!(result.unwrap_err().contains("timed out"));
        assert!(e.events().is_empty());
        assert_eq!(r.status().recent[0].outcome, "timed_out");
    }
    #[test]
    fn queued_allow_after_deadline_is_not_consumed() {
        let (tx, rx) = mpsc::sync_channel(1);
        tx.send(ApprovalDecision::Allow).unwrap();
        let start = Instant::now();
        let calls = AtomicU64::new(0);
        let decision = receive_approval(
            &rx,
            &CancelToken::default(),
            InteractionDeadline::from_instant(start + Duration::from_secs(1)),
            &|| {
                if calls.fetch_add(1, Ordering::SeqCst) == 0 {
                    (start, SystemTime::now())
                } else {
                    (start + Duration::from_secs(2), SystemTime::now())
                }
            },
        );
        assert!(matches!(decision, ApprovalDecision::TimedOut));
    }
    #[test]
    fn wall_expiry_rejects_late_allow_with_live_monotonic_deadline() {
        let runtime = McpRuntime::default();
        {
            let mut p = runtime.policy.lock().unwrap();
            p.enabled = true;
            p.allowed_hosts.insert("id-web".into());
        }
        let engine = FakeEngine::new();
        let directory = FakeDirectory::new()
            .with_host("web", AuthMethod::Password)
            .with_pin("web", default_server_key());
        let connector = Connector {
            engine: &engine,
            directory: &directory,
            keys: &FakeKeys::new(),
            keychain: &MemKeychain::default(),
            confirmer: &FakeConfirmer::default(),
        };
        let result = execute(
            &runtime,
            &connector,
            "id-web",
            "uptime",
            60,
            &CancelToken::default(),
            &FakeOwner::default(),
            &|request| {
                runtime.wait_approval(
                    request,
                    &CancelToken::default(),
                    Duration::from_secs(120),
                    || {
                        {
                            let mut pending = runtime.pending.lock().unwrap();
                            let deadline = &mut pending.get_mut(&request.id).unwrap().deadline;
                            assert!(deadline.monotonic > Instant::now());
                            deadline.utc = SystemTime::now() - Duration::from_secs(1);
                        }
                        assert!(
                            runtime.resolve_approval(&request.id, true).is_err(),
                            "UTC-expired Allow must fail even while monotonic clock is live"
                        );
                    },
                )
            },
        );
        assert!(result.unwrap_err().contains("timed out"));
        assert!(engine.events().is_empty());
        assert_eq!(runtime.status().recent[0].outcome, "timed_out");
    }
    #[test]
    fn wall_expiry_discards_queued_allow_after_clock_advances() {
        let (tx, rx) = mpsc::sync_channel(1);
        tx.send(ApprovalDecision::Allow).unwrap();
        let now = Instant::now();
        let utc = SystemTime::now();
        let calls = AtomicU64::new(0);
        let deadline = InteractionDeadline {
            monotonic: now + Duration::from_secs(120),
            utc: utc + Duration::from_secs(120),
        };
        let decision = receive_approval(&rx, &CancelToken::default(), deadline, &|| {
            (
                now,
                if calls.fetch_add(1, Ordering::SeqCst) == 0 {
                    utc
                } else {
                    utc + Duration::from_secs(121)
                },
            )
        });
        assert!(matches!(decision, ApprovalDecision::TimedOut));
    }
}

#[cfg(test)]
mod confirmed_pin_tests {
    use super::*;
    use crate::session::{
        directory::DirectoryError,
        format_directory::FormatDirectory,
        record_directory::{RecordDirectory, RecordSources},
        testing::{Decision, FakeConfirmer, FakeDirectory, FakeKeys, FakeOwner},
    };
    use crate::ssh::fake::{FakeEngine, FakeEvent};
    use crate::sync::{
        record_repository as repo,
        record_round::tests::pin_fixture,
        record_runtime,
        testkit::{HookedConnector, Hooks},
    };
    #[test]
    fn native_space_pin_wait_releases_lifecycle_and_revoke_disable_prevent_pin_and_exec() {
        for action in ["allow", "revoke", "disable"] {
            let device = pin_fixture();
            let runtime = McpRuntime::default();
            {
                let mut p = runtime.policy.lock().unwrap();
                p.enabled = true;
                p.allowed_hosts.insert("0000000000000001".into());
            }
            let (entered, observed) = mpsc::sync_channel(1);
            let (release, resume) = mpsc::sync_channel(1);
            let relay = Arc::new(HookedConnector::new(
                &device.relay,
                Hooks {
                    before_pull: Some(Box::new(move || {
                        entered.send(()).unwrap();
                        resume.recv().unwrap();
                    })),
                    ..Default::default()
                },
            ));
            let read = device.clone();
            let pin = device.clone();
            let directory = RecordDirectory::new(RecordSources {
                snapshot: Box::new(move || {
                    record_runtime::snapshot(&read.env())
                        .map(|(s, _)| s)
                        .map_err(|e| DirectoryError::Failed(e.to_string()))
                }),
                material: Box::new(|_| panic!("public route must not read material")),
                username: Box::new(|| Ok("ops".into())),
                pin: Box::new(|_, _, _, _| {
                    panic!("MCP must use the cancellable confirmed-pin contract")
                }),
            })
            .with_confirmed_pin(Box::new(move |hop, previous, key, cancel, guard| {
                let mut env = pin.env();
                env.relays = relay.as_ref();
                crate::session::record_pin::confirm(
                    &env,
                    hop,
                    previous,
                    key,
                    env.keychain,
                    cancel,
                    guard,
                )
                .map_err(|e| DirectoryError::Failed(e.to_string()))
            }));
            let mode = device.clone();
            let directory = FormatDirectory {
                lifecycle: device.runtime.lifecycle.clone(),
                mode: Box::new(move || {
                    let core = mode.runtime.core.lock().unwrap();
                    (core.format, core.legacy_paused)
                }),
                legacy: Arc::new(FakeDirectory::new()),
                records: Arc::new(directory),
            };
            let engine = FakeEngine::new();
            let keys = FakeKeys::new();
            let confirmer = FakeConfirmer::deciding(vec![Decision::Trust]);
            let connector = Connector {
                engine: &engine,
                directory: &directory,
                keys: &keys,
                keychain: &device.keychain,
                confirmer: &confirmer,
            };
            let cancel = CancelToken::default();
            thread::scope(|scope| {
                let worker = scope.spawn(|| {
                    execute(
                        &runtime,
                        &connector,
                        "0000000000000001",
                        "uptime",
                        60,
                        &cancel,
                        &FakeOwner::default(),
                        &|_| ApprovalDecision::Allow,
                    )
                });
                observed.recv_timeout(Duration::from_secs(3)).unwrap();
                let free = device.runtime.lifecycle.try_lock().is_ok();
                if action != "allow" {
                    let mut p = runtime.policy.lock().unwrap();
                    if action == "revoke" {
                        p.allowed_hosts.clear();
                    } else {
                        p.enabled = false;
                    }
                    drop(p);
                    runtime.cancel_records(None);
                    assert!(cancel.is_cancelled());
                }
                release.send(()).unwrap();
                let result = worker.join().unwrap();
                assert!(free, "external preparation must leave lifecycle available");
                assert_eq!(result.is_ok(), action == "allow", "{result:?}");
            });
            let pinned = repo::get_host(
                &record_runtime::snapshot(&device.env()).unwrap().0,
                "0000000000000001",
            )
            .unwrap()
            .host
            .payload
            .host_key
            .is_some();
            assert_eq!(pinned, action == "allow");
            assert_eq!(
                engine
                    .events()
                    .iter()
                    .any(|e| matches!(e, FakeEvent::Exec { .. })),
                action == "allow"
            );
        }
    }
}
