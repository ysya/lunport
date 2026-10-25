//! Public connection creation always needs native consent; key verification never grants AI access.
use super::*;
use crate::session::{
    connect::{CancelToken, Connector},
    protocol::HostQuery,
};
use crate::sync::{
    env::SyncEnv,
    record_groups, record_library, record_repository as repo, record_runtime,
    records_v3::{AuthKind, HostPayload, HostScope, SyncStateV3},
};

fn port() -> u16 {
    22
}
fn auth() -> AuthKind {
    AuthKind::Password
}
fn keepalive() -> u32 {
    30
}
fn missed() -> u32 {
    3
}
fn timeout() -> u32 {
    15
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CreateInput {
    alias: String,
    hostname: String,
    #[serde(default = "port")]
    port: u16,
    #[serde(default)]
    user: String,
    #[serde(default = "auth")]
    auth: AuthKind,
    #[serde(default)]
    key_id: Option<String>,
    #[serde(default)]
    group_id: Option<String>,
    #[serde(default)]
    jump: Vec<String>,
    #[serde(default = "keepalive")]
    keepalive_secs: u32,
    #[serde(default = "missed")]
    keepalive_max_missed: u32,
    #[serde(default = "timeout")]
    connect_timeout_secs: u32,
    #[serde(default)]
    tags: Vec<String>,
}
fn payload(input: &Value) -> Result<HostPayload, String> {
    let p:CreateInput=serde_json::from_value(input.clone()).map_err(|_|"Provide public connection settings only. Passwords, private keys, host-key pins and unknown fields are not accepted.".to_string())?;
    if p.alias.len() > 128
        || p.hostname.len() > 255
        || p.user.len() > 128
        || p.tags.len() > 32
        || p.tags.iter().any(|t| t.chars().count() > 64)
        || p.auth != AuthKind::Key && p.key_id.is_some()
    {
        return Err("Connection fields exceed their limits or the key reference does not match the authentication method.".into());
    }
    Ok(HostPayload {
        schema: if p.group_id.is_some() { 3 } else { 2 },
        alias: p.alias,
        hostname: p.hostname,
        port: p.port,
        user: p.user,
        auth: p.auth,
        key_id: p.key_id,
        group_id: p.group_id,
        inherit: vec![],
        jump: p.jump,
        keepalive_secs: p.keepalive_secs,
        keepalive_max_missed: p.keepalive_max_missed,
        connect_timeout_secs: p.connect_timeout_secs,
        host_key: None,
        tags: p.tags,
        notes: String::new(),
        imported: None,
    })
}
fn candidate(
    state: &SyncStateV3,
    id: &str,
    payload: &HostPayload,
    now: u64,
) -> Result<(SyncStateV3, McpHostProposal), String> {
    let scope = match payload.group_id.as_deref() {
        Some(id) => record_library::group_scope(state, id),
        None => record_library::creation_scope(state),
    }
    .map_err(|e| e.to_string())?;
    let promoted=record_groups::promote_for_host(state,&scope,payload,false,now).map_err(|_|"This connection requires a format upgrade. Confirm that upgrade in Lunport first, then retry create_host.".to_string())?;
    let next = repo::create_host(&promoted, id, scope.clone(), payload.clone(), now)
        .map_err(|e| e.to_string())?;
    let host = repo::get_host(&next, id).map_err(|e| e.to_string())?;
    let key = payload
        .key_id
        .as_deref()
        .map(|id| {
            repo::resolve_key(state, id)
                .ok()
                .and_then(|k| k.public)
                .map(|p| format!("{} · {}", p.name, p.fingerprint))
                .unwrap_or_else(|| format!("Unavailable key ({id})"))
        })
        .unwrap_or_else(|| "None".into());
    let groups = record_groups::list_groups(state).map_err(|e| e.to_string())?;
    let group = payload
        .group_id
        .as_deref()
        .and_then(|id| groups.iter().find(|g| g.group.id == id))
        .map(|g| format!("{} ({})", g.group.payload.name, g.group.id))
        .unwrap_or_else(|| "Ungrouped".into());
    let route = repo::resolve_host_chain(&next, id)
        .map_err(|e| e.to_string())?
        .iter()
        .map(|v| {
            format!(
                "{}@{}:{} ({})",
                if v.effective_payload.user.is_empty() {
                    "OS username"
                } else {
                    &v.effective_payload.user
                },
                v.effective_payload.hostname,
                v.effective_payload.port,
                v.host.payload.alias
            )
        })
        .collect::<Vec<_>>()
        .join(" → ");
    let p = &host.effective_payload;
    Ok((
        next,
        McpHostProposal {
            kind: proposal_kinds::CREATE_HOST.into(),
            settings: vec![
                (
                    "Storage".into(),
                    match &scope {
                        HostScope::Space { space_id } => format!("Synced library ({space_id})"),
                        HostScope::Local => "This device's library".into(),
                    },
                ),
                ("Alias".into(), p.alias.clone()),
                ("Hostname".into(), p.hostname.clone()),
                ("Port".into(), p.port.to_string()),
                (
                    "Username".into(),
                    if p.user.is_empty() {
                        "OS username".into()
                    } else {
                        p.user.clone()
                    },
                ),
                ("Authentication".into(), format!("{:?}", p.auth)),
                ("SSH key".into(), key),
                ("Group".into(), group),
                ("Route".into(), route),
                (
                    "Keepalive interval / missed".into(),
                    format!("{} s / {}", p.keepalive_secs, p.keepalive_max_missed),
                ),
                (
                    "Connect timeout".into(),
                    format!("{} s", p.connect_timeout_secs),
                ),
                ("Tags".into(), p.tags.join(", ")),
            ],
        },
    ))
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
fn active<'a>(
    runtime: &'a McpRuntime,
    context: &mut RequestContext,
    host: &str,
    cancel: &CancelToken,
) -> Result<Active<'a>, String> {
    if context.id.is_empty() {
        context.id = format!(
            "management-{}",
            runtime.next_request_id.fetch_add(1, Ordering::Relaxed)
        );
    }
    let mut active = runtime.records_active.lock().unwrap();
    if active.contains_key(&context.id) {
        return Err("Duplicate MCP request id.".into());
    }
    active.insert(context.id.clone(), (host.into(), cancel.clone()));
    Ok(Active {
        runtime,
        id: context.id.clone(),
    })
}
fn live(runtime: &McpRuntime, mode: ApprovalMode, cancel: &CancelToken) -> Result<(), String> {
    if cancel.is_cancelled() {
        return Err("MCP request was canceled.".into());
    }
    let policy = runtime.policy.lock().unwrap();
    if !policy.enabled || policy.approval_mode != mode {
        return Err("MCP policy changed; request approval again.".into());
    }
    Ok(())
}

pub(super) fn create(
    env: &SyncEnv,
    runtime: &McpRuntime,
    input: &Value,
    mut context: RequestContext,
    cancel: &CancelToken,
    approve: &(dyn Fn(&McpPendingRequest) -> ApprovalDecision + Sync),
) -> Result<Value, String> {
    let policy = runtime.policy.lock().unwrap().clone();
    if !policy.enabled {
        return Err("MCP access is disabled.".into());
    }
    let payload = payload(input)?;
    let id = crate::sync::record_commands::new_host_id().map_err(|e| e.to_string())?;
    let state = record_runtime::snapshot(env).map_err(|e| e.to_string())?.0;
    let (candidate_state, mut proposal) = candidate(&state, &id, &payload, env.now())?;
    let access = |s: &SyncStateV3, policy: &McpPolicy| repo::get_host(s, &id).is_ok_and(|host| permissions::record_allowed(policy, s, &host));
    proposal.settings.push(("AI access".into(), if access(&candidate_state, &policy) { "Allowed by existing Group permission" } else { "Not allowed" }.into()));
    let _active = active(runtime, &mut context, &id, cancel)?;
    live(runtime, policy.approval_mode, cancel)?;
    let request = McpPendingRequest {
        host_proposal: Some(proposal.clone()),
        id: context.id.clone(),
        alias: payload.alias.clone(),
        host_id: Some(id.clone()),
        hostname: Some(payload.hostname.clone()),
        user: Some(payload.user.clone()),
        port: Some(payload.port.to_string()),
        requested_by: context.requested_by.clone(),
        requester_id: context.requester_id.clone(),
        client_info: context.client_info.clone(),
        requested_at_ms: unix_ms(),
        ..Default::default()
    };
    let result = (|| {
        // Saving connection data is never covered by Auto-log's execution permission.
        match approve(&request) {
            ApprovalDecision::Allow => {}
            ApprovalDecision::TimedOut => return Err("Host creation approval timed out.".into()),
            ApprovalDecision::Cancel => return Err("Host creation was canceled.".into()),
            ApprovalDecision::Deny => return Err("Host creation was denied.".into()),
        }
        live(runtime, policy.approval_mode, cancel)?;
        crate::sync::record_commands::edit_records(env,|state,now|{
            live(runtime,policy.approval_mode,cancel).map_err(AppError::Other)?;
            let (next,mut current)=candidate(state,&id,&payload,now).map_err(AppError::Other)?;
            let current_policy = runtime.policy.lock().unwrap().clone();
            current.settings.push(("AI access".into(), if access(&next, &current_policy) { "Allowed by existing Group permission" } else { "Not allowed" }.into()));
            if current!=proposal{return Err(AppError::Other("Connection settings or storage changed while awaiting approval. Request creation again.".into()));}
            Ok(next)
        }).map_err(|e|e.to_string())?;
        let state = record_runtime::snapshot(env).map_err(|e| e.to_string())?.0;
        let host = repo::get_host(&state, &id).map_err(|e| e.to_string())?;
        Ok(
            json!({"host":records::metadata(&state,&host)?,"ai_access_allowed":permissions::record_allowed(&runtime.policy.lock().unwrap(), &state, &host),"message":"Host saved. AI access follows existing individual and Group permissions; server trust is still verified separately."}),
        )
    })();
    runtime.record(McpAuditEntry {
        at_ms: request.requested_at_ms,
        completed_at_ms: unix_ms(),
        id: context.id,
        client: "mcp".into(),
        host_id: Some(id),
        alias: payload.alias,
        mode: policy.approval_mode,
        requested_by: context.requested_by,
        requester_id: context.requester_id,
        client_info: context.client_info,
        outcome: if result.is_ok() {
            "host_created"
        } else {
            "host_creation_not_completed"
        }
        .into(),
        ..Default::default()
    });
    result
}

pub(super) fn verify(
    runtime: &McpRuntime,
    connector: &Connector<'_>,
    alias: &str,
    mut context: RequestContext,
    cancel: &CancelToken,
    owner: &dyn crate::session::auth::Owner,
    authorize: &(dyn Fn(&McpPolicy, &str) -> Result<(), String> + Sync),
) -> Result<Value, String> {
    let target = connector
        .directory
        .resolve_host_key(&HostQuery::Id(alias.into()))
        .or_else(|_| {
            connector
                .directory
                .resolve_host_key(&HostQuery::Alias(alias.into()))
        })
        .map_err(|e| e.to_string())?;
    let host = target
        .hops
        .last()
        .ok_or("No destination.")?
        .id
        .as_str()
        .to_owned();
    let query = HostQuery::Id(host.clone());
    let policy = runtime.policy.lock().unwrap().clone();
    authorize(&policy, &host)?;
    let approved = records::ApprovedTarget::capture(&target, connector.keys)?;
    let _active = active(runtime, &mut context, &host, cancel)?;
    let check = || {
        live(runtime, policy.approval_mode, cancel)?;
        let current_policy = runtime.policy.lock().unwrap().clone();
        authorize(&current_policy, &host)?;
        let current = connector
            .directory
            .resolve_host_key(&query)
            .map_err(|e| e.to_string())?;
        approved.check_resolved(&current, connector.keys)
    };
    let check_resolved =
        |target: &crate::ssh::Target| approved.check_resolved(target, connector.keys);
    let directory = records::PublicDirectory(connector.directory, &check, &check_resolved, records::Asker::Automation);
    let guarded = Connector {
        directory: &directory,
        engine: connector.engine,
        keys: connector.keys,
        keychain: connector.keychain,
        confirmer: connector.confirmer,
        grants: connector.grants,
    };
    check()?;
    let result =
        crate::session::verify::verify(&guarded, &query, owner, cancel).and_then(|value| {
            check()?;
            serde_json::to_value(value).map_err(|_| "Could not encode verified identity.".into())
        });
    runtime.record(McpAuditEntry {
        at_ms: unix_ms(),
        completed_at_ms: unix_ms(),
        id: context.id,
        client: "mcp".into(),
        host_id: Some(host.clone()),
        alias: alias.into(),
        mode: policy.approval_mode,
        requested_by: context.requested_by,
        requester_id: context.requester_id,
        client_info: context.client_info,
        outcome: if result.is_ok() {
            "host_key_verified"
        } else {
            "host_key_not_verified"
        }
        .into(),
        ..Default::default()
    });
    result
}

pub(super) fn tool_definitions() -> Vec<Value> {
    vec![
        json!({"name":"create_host","title":"Propose a new SSH host","description":"Propose public connection settings. Lunport always asks the user before saving, including in Auto-log mode. Does not connect, trust a host key or import private keys. A host in an explicitly allowed Group inherits its AI access.","inputSchema":{"type":"object","properties":{
        "alias":{"type":"string","maxLength":128},"hostname":{"type":"string","maxLength":255},"port":{"type":"integer","minimum":1,"maximum":65535,"default":22},"user":{"type":"string","maxLength":128},"auth":{"type":"string","enum":["password","key","interactive"],"default":"password"},"key_id":{"type":"string","description":"Existing Lunport key ID; no private key or password."},"group_id":{"type":"string","description":"Optional existing Group ID; settings remain explicit overrides."},"jump":{"type":"array","items":{"type":"string"},"maxItems":5},"keepalive_secs":{"type":"integer","minimum":0},"keepalive_max_missed":{"type":"integer","minimum":0},"connect_timeout_secs":{"type":"integer","minimum":1},"tags":{"type":"array","maxItems":32,"items":{"type":"string","maxLength":64}}},"required":["alias","hostname"],"additionalProperties":false},"annotations":{"readOnlyHint":false,"destructiveHint":false,"idempotentHint":false,"openWorldHint":false}}),
        json!({"name":"verify_host_key","title":"Verify and review a server fingerprint","description":"For an AI-approved host, perform the SSH handshake and show Lunport's native trust window for a new or changed server key. New or changed keys always need a human trust decision; never authenticates to the destination or runs a command. Jump hosts may require login. Does not bypass Auto-log's no-interaction policy for ssh_exec.","inputSchema":{"type":"object","properties":{"alias":{"type":"string","description":"AI-approved stable host ID or exact unambiguous alias."}},"required":["alias"],"additionalProperties":false},"annotations":{"readOnlyHint":false,"destructiveHint":true,"idempotentHint":true,"openWorldHint":true}}),
    ]
}

#[cfg(test)]
#[path = "management_tests.rs"]
mod tests;
