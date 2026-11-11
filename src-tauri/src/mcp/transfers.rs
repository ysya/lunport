//! Single-file SCP transfers through Lunport's authenticated SSH connection.
use super::*;
use std::fs::File;
use std::path::Path;

use crate::session::{
    auth::Owner,
    connect::{CancelToken, Connector},
    protocol::{HostQuery, Unreviewed},
};
use crate::ssh::Target;

#[derive(Clone, Copy)]
pub(super) enum TransferKind {
    Upload,
    Download,
}
impl TransferKind {
    fn method(self) -> &'static str {
        match self {
            Self::Upload => "scp_upload",
            Self::Download => "scp_download",
        }
    }
    fn action(self) -> &'static str {
        match self {
            Self::Upload => "Upload",
            Self::Download => "Download",
        }
    }
    fn success(self) -> &'static str {
        match self {
            Self::Upload => "scp_uploaded",
            Self::Download => "scp_downloaded",
        }
    }
    fn failure(self) -> &'static str {
        match self {
            Self::Upload => "scp_not_uploaded",
            Self::Download => "scp_not_downloaded",
        }
    }
}

pub(super) fn validate_paths(local: &str, remote: &str) -> Result<(), String> {
    if !Path::new(local).is_absolute()
        || local.len() > 4096
        || local
            .chars()
            .any(|c| c.is_control() || crate::session::auth::is_deceptive_format(c))
    {
        return Err(
            "local_path must be an absolute, display-safe path of at most 4096 bytes".into(),
        );
    }
    if remote.is_empty()
        || remote.len() > 4096
        || remote
            .chars()
            .any(|c| c.is_control() || crate::session::auth::is_deceptive_format(c))
    {
        return Err(
            "remote_path must be a nonempty, display-safe path of at most 4096 bytes".into(),
        );
    }
    Ok(())
}

fn persist_download(staged: tempfile::NamedTempFile, target: &Path) -> Result<(), String> {
    staged
        .as_file()
        .sync_all()
        .map_err(|_| "Downloaded file could not be saved locally".to_string())?;
    staged
        .persist_noclobber(target)
        .map_err(|_| "Local destination already exists or cannot be saved".to_string())?;
    Ok(())
}

pub(super) fn tool_definitions() -> Vec<Value> {
    [TransferKind::Upload, TransferKind::Download].into_iter().map(|kind| json!({
        "name": kind.method(),
        "title": if matches!(kind, TransferKind::Upload) { "Upload one file with SCP" } else { "Download one file with SCP" },
        "description": "Transfer one regular file through a Lunport AI-approved host using its saved SSH route and native authentication. Ask reviews both paths; Auto-log transfers without per-transfer review. The local path must be absolute. Settings → AI access controls the single-file size limit. Downloads never replace an existing local target.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "alias": { "type": "string", "description": "AI-approved host ID or exact alias" },
                "local_path": { "type": "string", "description": "Absolute path on this computer" },
                "remote_path": { "type": "string", "description": "Path on the SSH server" },
                "timeout_seconds": { "type": "integer", "minimum": 1, "maximum": 3600, "default": 300 }
            },
            "required": ["alias", "local_path", "remote_path"],
            "additionalProperties": false
        },
        "annotations": { "readOnlyHint": false, "destructiveHint": true, "idempotentHint": false, "openWorldHint": false }
    })).collect()
}

#[allow(clippy::too_many_arguments)]
pub(super) fn execute_context(
    runtime: &McpRuntime,
    connector: &Connector<'_>,
    kind: TransferKind,
    alias: &str,
    local_path: &str,
    remote_path: &str,
    timeout: u64,
    cancel: &CancelToken,
    owner: &dyn Owner,
    approve: &(dyn Fn(&McpPendingRequest) -> ApprovalDecision + Sync),
    mut context: records::RequestContext,
    authorize: &(dyn Fn(&McpPolicy, &str) -> Result<(), String> + Sync),
) -> Result<Value, String> {
    validate_paths(local_path, remote_path)?;
    if !(1..=3600).contains(&timeout) {
        return Err("timeout_seconds must be an integer from 1 to 3600".into());
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
    let approved = records::ApprovedTarget::capture(&target, connector.keys)?;
    let policy = runtime.policy.lock().unwrap().clone();
    let limit_mib = transfer_limit_mib(&policy);
    let limit_bytes = u64::from(limit_mib) * 1024 * 1024;
    if !policy.enabled || authorize(&policy, &host_id).is_err() {
        return Err("MCP request was denied by host policy".into());
    }

    let local = Path::new(local_path);
    let mut source = if matches!(kind, TransferKind::Upload) {
        let file =
            File::open(local).map_err(|_| "Local upload file cannot be opened".to_string())?;
        let metadata = file
            .metadata()
            .map_err(|_| "Local upload file cannot be inspected".to_string())?;
        if !metadata.is_file() || metadata.len() > limit_bytes {
            return Err(format!(
                "Local upload must be a regular file no larger than {limit_mib} MiB"
            ));
        }
        Some((file, metadata.len()))
    } else {
        let parent = local
            .parent()
            .ok_or("Local download needs a parent directory")?;
        if !parent.is_dir() || local.exists() {
            return Err(
                "Local download directory is unavailable or the destination already exists".into(),
            );
        }
        None
    };
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
    let mode = policy.approval_mode;
    let check = || {
        if cancel.is_cancelled() {
            return Err("MCP request was canceled".into());
        }
        let current = runtime.policy.lock().unwrap().clone();
        if !current.enabled
            || current.approval_mode != mode
            || transfer_limit_mib(&current) != limit_mib
        {
            return Err("MCP policy changed; request approval again.".into());
        }
        authorize(&current, &host_id)?;
        approved.check(connector, &query)
    };
    let request = McpPendingRequest {
        host_proposal: Some(McpHostProposal {
            kind: kind.method().into(),
            settings: vec![
                ("Local file".into(), local_path.into()),
                ("Remote path".into(), remote_path.into()),
                ("File limit".into(), format!("{limit_mib} MiB")),
            ],
        }),
        id: context.id.clone(),
        alias: destination.alias.clone(),
        host_id: Some(host_id.clone()),
        command: String::new(),
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
    let done = AtomicBool::new(false);
    let mut decision = None;
    let declines = activity::Declines::default();
    let owner = activity::NotingOwner { inner: owner, declines: &declines };
    let confirmer = records::ClientConfirmer::new(
        connector.confirmer,
        records::asker(&context, mode, Unreviewed::Transfer),
    );
    let result = std::thread::scope(|scope| {
        scope.spawn(|| {
            while !done.load(Ordering::SeqCst) {
                let p = runtime.policy.lock().unwrap().clone();
                if !p.enabled
                    || p.approval_mode != mode
                    || transfer_limit_mib(&p) != limit_mib
                    || authorize(&p, &host_id).is_err()
                {
                    cancel.cancel();
                    break;
                }
                std::thread::sleep(Duration::from_millis(25));
            }
        });
        let result = (|| {
            if mode == ApprovalMode::Ask {
                let decided = approve(&request);
                decision = Some(decided);
                match decided {
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
            records::verify_unverified(
                runtime,
                connector,
                &query,
                &target,
                &owner,
                &declines,
                cancel,
                &check,
                &confirmer,
                (&context, mode),
                "the transfer did not start",
            )?;
            let check_resolved = |actual: &Target| approved.check_resolved(actual, connector.keys);
            let check_connected = |actual: &Target| {
                check()?;
                approved.check_connected(actual, connector.keys)
            };
            let engine = records::CheckedEngine {
                inner: connector.engine,
                check: &check_connected,
            };
            let directory = records::PublicDirectory(connector.directory, &check, &check_resolved);
            let guarded = Connector {
                engine: &engine,
                confirmer: &confirmer,
                keys: connector.keys,
                keychain: connector.keychain,
                directory: &directory,
                grants: connector.grants,
            };
            let connected = guarded.connect(&query, &owner, cancel).map_err(|e| {
                confirmer
                    .answer(Some("the transfer did not start"))
                    .unwrap_or(e.text)
            })?;
            if let Some(answer) = confirmer.answer(Some("the transfer did not start")) {
                connected.session.close();
                return Err(answer);
            }
            check_connected(&connected.target).inspect_err(|_| connected.session.close())?;
            let transferring = AtomicBool::new(false);
            let transferred = std::thread::scope(|scope| {
                scope.spawn(|| {
                    while !transferring.load(Ordering::SeqCst) {
                        if cancel.is_cancelled() {
                            connected.session.close();
                            break;
                        }
                        std::thread::sleep(Duration::from_millis(25));
                    }
                });
                let result = (|| -> Result<u64, String> {
                    match kind {
                        TransferKind::Upload => {
                            let (file, size) = source.as_mut().expect("upload source was opened");
                            let name = local
                                .file_name()
                                .and_then(|n| n.to_str())
                                .ok_or("Local file has no usable name")?;
                            connected
                                .session
                                .scp_upload(
                                    remote_path,
                                    name,
                                    *size,
                                    file,
                                    Duration::from_secs(timeout),
                                )
                                .map_err(|e| e.to_string())
                        }
                        TransferKind::Download => {
                            let parent = local
                                .parent()
                                .ok_or("Local download needs a parent directory")?;
                            let mut staged = tempfile::NamedTempFile::new_in(parent)
                                .map_err(|_| "Local download could not be staged".to_string())?;
                            let size = connected
                                .session
                                .scp_download(
                                    remote_path,
                                    staged.as_file_mut(),
                                    limit_bytes,
                                    Duration::from_secs(timeout),
                                )
                                .map_err(|e| e.to_string())?;
                            check()?;
                            persist_download(staged, local)?;
                            Ok(size)
                        }
                    }
                })();
                transferring.store(true, Ordering::SeqCst);
                result
            });
            connected.session.close();
            let bytes = transferred?;
            check()?;
            Ok(
                json!({ "host_id": host_id, "local_path": local_path, "remote_path": remote_path, "bytes": bytes }),
            )
        })();
        done.store(true, Ordering::SeqCst);
        result
    });
    let review = if mode == ApprovalMode::AutoLog {
        Some(McpReview::AutoLog)
    } else {
        decision.and_then(activity::review_of)
    };
    let stop = result.as_ref().err().map(|error| {
        activity::stop_for(
            error,
            decision,
            declines.first().or_else(|| confirmer.declined()),
            runtime.withdrawn(mode, cancel),
        )
    });
    runtime.record(McpAuditEntry {
        id: context.id,
        alias: destination.alias.clone(),
        host_id: Some(host_id),
        client: "mcp".into(),
        command: format!(
            "{} {local_path} {} {remote_path}",
            kind.action(),
            if matches!(kind, TransferKind::Upload) {
                "→"
            } else {
                "←"
            }
        ),
        mode,
        requested_by: context.requested_by,
        requester_id: context.requester_id,
        client_info: context.client_info,
        at_ms: request.requested_at_ms,
        completed_at_ms: unix_ms(),
        outcome: if cancel.is_cancelled() {
            "canceled"
        } else if result.is_ok() {
            kind.success()
        } else if result
            .as_ref()
            .err()
            .is_some_and(|e: &String| e.contains("denied"))
        {
            "denied"
        } else if result
            .as_ref()
            .err()
            .is_some_and(|e: &String| e.contains("timed out"))
        {
            "timed_out"
        } else {
            kind.failure()
        }
        .into(),
        ended: None,
        exit_code: None,
        signal: None,
        detail: None,
        review,
        stop,
        tunnel: None,
    });
    match result {
        Ok(mut value) => {
            if let Some(error) = runtime.audit.lock().unwrap().error.clone() {
                value["audit_error"] = json!(error);
            }
            Ok(value)
        }
        Err(error) => Err(error),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::session::{
        directory::HostDirectory,
        testing::{FakeConfirmer, FakeDirectory, FakeKeys, FakeOwner},
    };
    use crate::ssh::{fake::FakeEngine, AuthMethod, Hop, HostId};

    #[test]
    fn transfer_paths_require_safe_absolute_local_and_remote_names() {
        let directory = tempfile::tempdir().unwrap();
        let local = directory.path().join("report.txt");
        assert!(validate_paths(local.to_str().unwrap(), "/srv/report.txt").is_ok());
        assert!(validate_paths("report.txt", "/srv/report.txt").is_err());
        assert!(validate_paths(local.to_str().unwrap(), "").is_err());
        assert!(validate_paths(local.to_str().unwrap(), "/srv/report\nother.txt").is_err());
        assert!(validate_paths(local.to_str().unwrap(), "/srv/\u{202e}txt").is_err());
    }

    #[test]
    fn completed_download_never_replaces_an_existing_local_file() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("report.txt");
        std::fs::write(&target, b"original").unwrap();
        let mut staged = tempfile::NamedTempFile::new_in(dir.path()).unwrap();
        staged.write_all(b"new").unwrap();
        assert!(persist_download(staged, &target).is_err());
        assert_eq!(std::fs::read(&target).unwrap(), b"original");
    }

    #[test]
    fn ask_denial_prevents_the_agent_from_opening_an_ssh_connection() {
        let runtime = McpRuntime::default();
        *runtime.policy.lock().unwrap() = McpPolicy {
            enabled: true,
            allowed_hosts: BTreeSet::from(["host-1".into()]),
            approval_mode: ApprovalMode::Ask,
            ..Default::default()
        };
        let directory = FakeDirectory::new().with_hop(Hop::new(
            "host-1",
            "web-1",
            "fixture.invalid",
            22,
            "frank",
            AuthMethod::Interactive,
        ));
        directory
            .pin(
                &HostId::from("host-1"),
                &crate::ssh::fake::default_server_key(),
            )
            .unwrap();
        let engine = FakeEngine::new();
        let keys = FakeKeys::new();
        let keychain = crate::sync::testkit::MemKeychain::default();
        let confirmer = FakeConfirmer::default();
        let connector = Connector {
            directory: &directory,
            engine: &engine,
            keys: &keys,
            keychain: &keychain,
            confirmer: &confirmer,
            grants: crate::session::grants::GrantGates::for_tests(),
        };
        let local = tempfile::NamedTempFile::new().unwrap();
        let result = execute_context(
            &runtime,
            &connector,
            TransferKind::Upload,
            "host-1",
            local.path().to_str().unwrap(),
            "/tmp/report.txt",
            60,
            &CancelToken::default(),
            &FakeOwner::default(),
            &|_| ApprovalDecision::Deny,
            RequestContext::default(),
            &|policy, id| ensure_allowed(policy, id),
        );
        assert!(result.unwrap_err().contains("denied"));
        assert!(engine.events().is_empty());
    }

    #[test]
    fn configured_upload_limit_rejects_the_file_before_connecting() {
        let runtime = McpRuntime::default();
        *runtime.policy.lock().unwrap() = McpPolicy {
            enabled: true,
            allowed_hosts: BTreeSet::from(["host-1".into()]),
            approval_mode: ApprovalMode::AutoLog,
            max_transfer_mib: Some(1),
            ..Default::default()
        };
        let directory = FakeDirectory::new().with_hop(Hop::new(
            "host-1",
            "web-1",
            "fixture.invalid",
            22,
            "frank",
            AuthMethod::Interactive,
        ));
        directory
            .pin(
                &HostId::from("host-1"),
                &crate::ssh::fake::default_server_key(),
            )
            .unwrap();
        let engine = FakeEngine::new();
        let keys = FakeKeys::new();
        let keychain = crate::sync::testkit::MemKeychain::default();
        let confirmer = FakeConfirmer::default();
        let connector = Connector {
            directory: &directory,
            engine: &engine,
            keys: &keys,
            keychain: &keychain,
            confirmer: &confirmer,
            grants: crate::session::grants::GrantGates::for_tests(),
        };
        let file = tempfile::NamedTempFile::new().unwrap();
        file.as_file().set_len(1024 * 1024 + 1).unwrap();
        let result = execute_context(
            &runtime,
            &connector,
            TransferKind::Upload,
            "host-1",
            file.path().to_str().unwrap(),
            "/tmp/report.txt",
            60,
            &CancelToken::default(),
            &FakeOwner::default(),
            &|_| panic!("Auto-log must not ask"),
            RequestContext::default(),
            &|policy, id| ensure_allowed(policy, id),
        );
        assert!(result.unwrap_err().contains("1 MiB"));
        assert!(engine.events().is_empty());
    }
}
