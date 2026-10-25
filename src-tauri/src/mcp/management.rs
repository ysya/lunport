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
/// The key as the window names it: its name and fingerprint, never its material.
fn key_label(state: &SyncStateV3, key_id: Option<&str>) -> String {
    key_id
        .map(|id| {
            repo::resolve_key(state, id)
                .ok()
                .and_then(|k| k.public)
                .map(|p| format!("{} · {}", p.name, p.fingerprint))
                .unwrap_or_else(|| format!("Unavailable key ({id})"))
        })
        .unwrap_or_else(|| "None".into())
}

/// The chain a connection to `id` takes, hop by hop.
fn route_label(state: &SyncStateV3, id: &str) -> Result<String, String> {
    Ok(repo::resolve_host_chain(state, id)
        .map_err(|e| e.to_string())?
        .iter()
        .map(|v| {
            format!(
                "{}@{}:{} ({})",
                if v.effective_payload.user.is_empty() { "OS username" } else { &v.effective_payload.user },
                v.effective_payload.hostname,
                v.effective_payload.port,
                v.host.payload.alias
            )
        })
        .collect::<Vec<_>>()
        .join(" → "))
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
    let key = key_label(state, payload.key_id.as_deref());
    let groups = record_groups::list_groups(state).map_err(|e| e.to_string())?;
    let group = payload
        .group_id
        .as_deref()
        .and_then(|id| groups.iter().find(|g| g.group.id == id))
        .map(|g| format!("{} ({})", g.group.payload.name, g.group.id))
        .unwrap_or_else(|| "Ungrouped".into());
    let route = route_label(&next, id)?;
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

const PUBLIC_ONLY: &str = "Provide public connection settings only. Passwords, private keys, host-key pins and unknown fields are not accepted.";
const HOST_CHANGED: &str = "The host changed while the request was open; read it again and retry.";
const PIN_CLEARED: &str = "pinned → verified again at the next connection";

/// What `update_host` may change: every field optional, replacing that field only (design 2026-10-26, AI edits).
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct UpdateInput {
    alias: String,
    #[serde(default)]
    new_alias: Option<String>,
    #[serde(default)]
    hostname: Option<String>,
    #[serde(default)]
    port: Option<u16>,
    #[serde(default)]
    user: Option<String>,
    #[serde(default)]
    auth: Option<AuthKind>,
    #[serde(default)]
    key_id: Option<String>,
    #[serde(default)]
    jump: Option<Vec<String>>,
    #[serde(default)]
    keepalive_secs: Option<u32>,
    #[serde(default)]
    keepalive_max_missed: Option<u32>,
    #[serde(default)]
    connect_timeout_secs: Option<u32>,
    #[serde(default)]
    tags: Option<Vec<String>>,
}

impl UpdateInput {
    fn checked(input: &Value) -> Result<UpdateInput, String> {
        let p: UpdateInput = serde_json::from_value(input.clone()).map_err(|_| PUBLIC_ONLY.to_string())?;
        if p.new_alias.is_none()
            && p.hostname.is_none()
            && p.port.is_none()
            && p.user.is_none()
            && p.auth.is_none()
            && p.key_id.is_none()
            && p.jump.is_none()
            && p.keepalive_secs.is_none()
            && p.keepalive_max_missed.is_none()
            && p.connect_timeout_secs.is_none()
            && p.tags.is_none()
        {
            return Err("Provide at least one setting to change.".into());
        }
        if p.new_alias.as_ref().is_some_and(|a| a.len() > 128)
            || p.hostname.as_ref().is_some_and(|h| h.len() > 255)
            || p.user.as_ref().is_some_and(|u| u.len() > 128)
            || p.tags.as_ref().is_some_and(|t| t.len() > 32 || t.iter().any(|t| t.chars().count() > 64))
        {
            return Err("Connection fields exceed their limits or the key reference does not match the authentication method.".into());
        }
        Ok(p)
    }

    /// The host's own payload with these changes applied; a field the host inherited from its Group becomes its own.
    fn apply(&self, mut payload: HostPayload) -> Result<HostPayload, String> {
        use crate::sync::records_v3::InheritedField;
        fn own(payload: &mut HostPayload, field: InheritedField) {
            payload.inherit.retain(|f| *f != field);
        }
        if let Some(alias) = &self.new_alias {
            payload.alias = alias.clone();
        }
        if let Some(hostname) = &self.hostname {
            payload.hostname = hostname.clone();
        }
        if let Some(port) = self.port {
            payload.port = port;
            own(&mut payload, InheritedField::Port);
        }
        if let Some(user) = &self.user {
            payload.user = user.clone();
            own(&mut payload, InheritedField::User);
        }
        if self.auth.is_some() || self.key_id.is_some() {
            own(&mut payload, InheritedField::Authentication);
        }
        if let Some(auth) = self.auth {
            payload.auth = auth;
            if auth != AuthKind::Key {
                payload.key_id = None;
            }
        }
        if let Some(key_id) = &self.key_id {
            payload.key_id = Some(key_id.clone());
        }
        if payload.auth != AuthKind::Key && payload.key_id.is_some() {
            return Err("Connection fields exceed their limits or the key reference does not match the authentication method.".into());
        }
        if let Some(jump) = &self.jump {
            payload.jump = jump.clone();
            own(&mut payload, InheritedField::Jump);
        }
        if let Some(secs) = self.keepalive_secs {
            payload.keepalive_secs = secs;
            own(&mut payload, InheritedField::KeepaliveSecs);
        }
        if let Some(missed) = self.keepalive_max_missed {
            payload.keepalive_max_missed = missed;
            own(&mut payload, InheritedField::KeepaliveMaxMissed);
        }
        if let Some(secs) = self.connect_timeout_secs {
            payload.connect_timeout_secs = secs;
            own(&mut payload, InheritedField::ConnectTimeoutSecs);
        }
        if let Some(tags) = &self.tags {
            payload.tags = tags.clone();
        }
        Ok(payload)
    }
}

/// The host `alias` names, by id or by exact alias, as `get_host` finds it.
fn find_host(state: &SyncStateV3, alias: &str) -> Result<repo::HostView, String> {
    repo::get_host(state, alias)
        .or_else(|_| repo::find_by_alias(state, alias))
        .map_err(|e| e.to_string())
}

/// Where an inherited value came from, for the window: `(from Group <name>)`, or `(Group default)` when no Group sets it.
fn inherited_note(state: &SyncStateV3, before: &repo::HostView, field: &str) -> String {
    match before.inherited_from.get(field) {
        None => String::new(),
        Some(from) if from == "default" => " (Group default)".into(),
        Some(from) => {
            let name = record_groups::list_groups(state)
                .ok()
                .and_then(|groups| groups.into_iter().find(|g| &g.group.id == from).map(|g| g.group.payload.name))
                .unwrap_or_else(|| from.clone());
            format!(" (from Group {name})")
        }
    }
}

/// The rows of a change: every field whose effective value differs, as `old → new`.
fn changed_rows(state: &SyncStateV3, next: &SyncStateV3, before: &repo::HostView, after: &repo::HostView) -> Result<Vec<(String, String)>, String> {
    let (b, a) = (&before.effective_payload, &after.effective_payload);
    let user = |u: &str| if u.is_empty() { "OS username".to_string() } else { u.to_string() };
    let mut rows = Vec::new();
    let mut row = |label: &str, field: &str, old: String, new: String| {
        if old != new {
            rows.push((label.to_string(), format!("{old}{} → {new}", inherited_note(state, before, field))));
        }
    };
    row("Alias", "", b.alias.clone(), a.alias.clone());
    row("Hostname", "", b.hostname.clone(), a.hostname.clone());
    row("Port", "port", b.port.to_string(), a.port.to_string());
    row("Username", "user", user(&b.user), user(&a.user));
    row("Authentication", "authentication", format!("{:?}", b.auth), format!("{:?}", a.auth));
    row("SSH key", "authentication", key_label(state, b.key_id.as_deref()), key_label(next, a.key_id.as_deref()));
    // The route is a row only when the jump hosts change: the chain's label repeats the destination's own address, which has its rows.
    if b.jump != a.jump {
        row("Route", "jump", route_label(state, &before.host.id)?, route_label(next, &after.host.id)?);
    }
    row("Keepalive interval / missed", "keepalive_secs", format!("{} s / {}", b.keepalive_secs, b.keepalive_max_missed), format!("{} s / {}", a.keepalive_secs, a.keepalive_max_missed));
    row("Connect timeout", "connect_timeout_secs", format!("{} s", b.connect_timeout_secs), format!("{} s", a.connect_timeout_secs));
    row("Tags", "", b.tags.join(", "), a.tags.join(", "));
    Ok(rows)
}

/// The state with the change applied, the rows the window shows, and whether the pinned server key goes with the old address.
fn update_candidate(state: &SyncStateV3, before: &repo::HostView, changes: &UpdateInput, now: u64) -> Result<(SyncStateV3, McpHostProposal, bool), String> {
    if before.group_error.is_some() {
        return Err("Host Group inheritance needs review.".into());
    }
    let payload = changes.apply(before.host.payload.clone())?;
    let next = repo::update_host(state, &before.host.id, &before.revision, payload, now).map_err(|e| e.to_string())?;
    let after = repo::get_host(&next, &before.host.id).map_err(|e| e.to_string())?;
    let mut rows = changed_rows(state, &next, before, &after)?;
    if rows.is_empty() {
        return Err("Nothing would change.".into());
    }
    let pin_cleared = before.host.payload.host_key.is_some() && after.host.payload.host_key.is_none();
    if pin_cleared {
        rows.push(("Server key".into(), PIN_CLEARED.into()));
    }
    Ok((next, McpHostProposal { kind: proposal_kinds::UPDATE_HOST.into(), settings: rows }, pin_cleared))
}

/// `update_host`: a permitted host's connection settings, changed with the person's consent (design 2026-10-26, AI edits).
pub(super) fn update(
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
    let changes = UpdateInput::checked(input)?;
    let state = record_runtime::snapshot(env).map_err(|e| e.to_string())?.0;
    let before = find_host(&state, &changes.alias)?;
    let id = before.host.id.clone();
    permissions::ensure_record(&policy, &state, &id)?;
    let (candidate_state, proposal, pin_cleared) = update_candidate(&state, &before, &changes, env.now())?;
    let after = repo::get_host(&candidate_state, &id).map_err(|e| e.to_string())?;
    let _active = active(runtime, &mut context, &id, cancel)?;
    live(runtime, policy.approval_mode, cancel)?;
    let request = McpPendingRequest {
        host_proposal: Some(proposal.clone()),
        id: context.id.clone(),
        alias: before.host.payload.alias.clone(),
        host_id: Some(id.clone()),
        hostname: Some(after.effective_payload.hostname.clone()),
        user: Some(after.effective_payload.user.clone()),
        port: Some(after.effective_payload.port.to_string()),
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
            ApprovalDecision::TimedOut => return Err("Host update approval timed out.".into()),
            ApprovalDecision::Cancel => return Err("Host update was canceled.".into()),
            ApprovalDecision::Deny => return Err("Host update was denied.".into()),
        }
        live(runtime, policy.approval_mode, cancel)?;
        crate::sync::record_commands::edit_records(env, |state, now| {
            live(runtime, policy.approval_mode, cancel).map_err(AppError::Other)?;
            let current = repo::get_host(state, &id).map_err(|e| AppError::Other(e.to_string()))?;
            if current.revision != before.revision {
                return Err(AppError::Other(HOST_CHANGED.into()));
            }
            let current_policy = runtime.policy.lock().unwrap().clone();
            permissions::ensure_record(&current_policy, state, &id).map_err(AppError::Other)?;
            let (next, again, _) = update_candidate(state, &current, &changes, now).map_err(AppError::Other)?;
            if again != proposal {
                return Err(AppError::Other(HOST_CHANGED.into()));
            }
            Ok(next)
        })
        .map_err(|e| e.to_string())?;
        let state = record_runtime::snapshot(env).map_err(|e| e.to_string())?.0;
        let saved = repo::get_host(&state, &id).map_err(|e| e.to_string())?;
        let message = if pin_cleared { "Host saved. Its server key is no longer pinned; run verify_host_key before relying on it." } else { "Host saved." };
        Ok(json!({"host": records::metadata(&state, &saved)?, "message": message}))
    })();
    runtime.record(McpAuditEntry {
        at_ms: request.requested_at_ms,
        completed_at_ms: unix_ms(),
        id: context.id,
        client: "mcp".into(),
        host_id: Some(id),
        alias: changes.alias,
        mode: policy.approval_mode,
        requested_by: context.requested_by,
        requester_id: context.requester_id,
        client_info: context.client_info,
        outcome: if result.is_ok() { "host_updated" } else { "host_update_not_completed" }.into(),
        ..Default::default()
    });
    result
}

const TRANSPORT_CHANGED: &str = "The transport changed while the request was open; read it again and retry.";
const TRANSPORT_ONLY: &str = "Provide the transport's settings only: project, zone, instance, interface, account, os_login and pam.";

/// `null` and an absent field apart: `None` absent, `Some(None)` given as null.
fn given<'de, D: serde::Deserializer<'de>, T: Deserialize<'de>>(d: D) -> Result<Option<T>, D::Error> {
    T::deserialize(d).map(Some)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PamInput {
    entitlements: Vec<String>,
    #[serde(default)]
    location: Option<String>,
    #[serde(default)]
    duration_minutes: Option<u32>,
}

/// What `set_transport` may change: a field given replaces that field only (design 2026-10-26, AI edits).
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TransportInput {
    alias: String,
    #[serde(default)]
    project: Option<String>,
    #[serde(default)]
    zone: Option<String>,
    #[serde(default)]
    instance: Option<String>,
    #[serde(default)]
    interface: Option<String>,
    #[serde(default, deserialize_with = "given")]
    account: Option<Option<String>>,
    #[serde(default)]
    os_login: Option<bool>,
    #[serde(default, deserialize_with = "given")]
    pam: Option<Option<PamInput>>,
}

impl TransportInput {
    /// The transport as it would be saved: the current one (or a new one from project, zone and instance) with the fields given
    /// replaced, validated as the panel validates it.
    fn merged(&self, host_id: &str, current: Option<&crate::sync::transports::HostTransport>) -> Result<crate::sync::transports::HostTransport, String> {
        use crate::sync::transports::{HostTransport, PamCheck, TransportKind};
        let mut kind = match current {
            Some(current) => current.kind.clone(),
            None => match (&self.project, &self.zone, &self.instance) {
                (Some(project), Some(zone), Some(instance)) => TransportKind::GcpIap {
                    project: project.clone(),
                    zone: zone.clone(),
                    instance: instance.clone(),
                    interface: "nic0".into(),
                    account: None,
                    os_login: true,
                    pam: None,
                },
                _ => return Err("Provide the project, zone and instance of a new transport.".into()),
            },
        };
        let TransportKind::GcpIap { project, zone, instance, interface, account, os_login, pam } = &mut kind;
        if let Some(v) = &self.project {
            *project = v.clone();
        }
        if let Some(v) = &self.zone {
            *zone = v.clone();
        }
        if let Some(v) = &self.instance {
            *instance = v.clone();
        }
        if let Some(v) = &self.interface {
            *interface = v.clone();
        }
        if let Some(v) = &self.account {
            *account = v.clone();
        }
        if let Some(v) = self.os_login {
            *os_login = v;
        }
        match &self.pam {
            None => {}
            Some(None) => *pam = None,
            Some(Some(input)) => {
                let stored = pam.take();
                *pam = Some(PamCheck {
                    entitlements: input.entitlements.clone(),
                    location: input.location.clone().unwrap_or_else(|| "global".into()),
                    duration_secs: input.duration_minutes.map(|minutes| minutes.saturating_mul(60)).or(stored.as_ref().map(|s| s.duration_secs)).unwrap_or(30 * 60),
                    // The justification is the person's: what they last sent stays theirs.
                    justification: stored.and_then(|s| s.justification),
                });
            }
        }
        let transport = HostTransport { host_id: host_id.into(), kind };
        transport.validate()?;
        Ok(transport)
    }
}

/// A transport's fields as the window names them.
fn transport_fields(transport: &crate::sync::transports::HostTransport) -> Vec<(&'static str, String)> {
    let crate::sync::transports::TransportKind::GcpIap { project, zone, instance, interface, account, os_login, pam } = &transport.kind;
    let mut fields = vec![
        ("Project", project.clone()),
        ("Zone", zone.clone()),
        ("Instance", instance.clone()),
        ("Interface", interface.clone()),
        ("Account", account.clone().unwrap_or_else(|| "gcloud's active account".into())),
        ("OS Login", if *os_login { "on" } else { "off" }.into()),
        ("PAM entitlements", pam.as_ref().map(|pam| pam.entitlements.join(", ")).unwrap_or_else(|| "none".into())),
    ];
    if let Some(pam) = pam {
        fields.push(("PAM location", pam.location.clone()));
        fields.push(("Grant duration", format!("{} min", pam.duration_secs / 60)));
    }
    fields
}

/// The rows of a transport change: every field for a new or a removed transport, `old → new` for the fields that change otherwise.
fn transport_rows(before: Option<&crate::sync::transports::HostTransport>, after: Option<&crate::sync::transports::HostTransport>) -> Vec<(String, String)> {
    match (before, after) {
        (None, Some(new)) => transport_fields(new).into_iter().map(|(label, value)| (label.to_string(), value)).collect(),
        (Some(old), None) => transport_fields(old).into_iter().map(|(label, value)| (label.to_string(), value)).collect(),
        (Some(old), Some(new)) => {
            let olds: std::collections::BTreeMap<&str, String> = transport_fields(old).into_iter().collect();
            let news: std::collections::BTreeMap<&str, String> = transport_fields(new).into_iter().collect();
            let mut rows = Vec::new();
            for (label, _) in transport_fields(new) {
                match (olds.get(label), news.get(label)) {
                    (Some(o), Some(n)) if o != n => rows.push((label.to_string(), format!("{o} → {n}"))),
                    (None, Some(n)) => rows.push((label.to_string(), format!("none → {n}"))),
                    _ => {}
                }
            }
            for (label, o) in transport_fields(old) {
                if !news.contains_key(label) {
                    rows.push((label.to_string(), format!("{o} → none")));
                }
            }
            rows
        }
        (None, None) => Vec::new(),
    }
}

/// The words of a transport proposal: what the sentences say when the person does not allow it, and what the audit calls the outcome.
struct TransportWords {
    timed_out: &'static str,
    canceled: &'static str,
    denied: &'static str,
    done: &'static str,
    saved: &'static str,
    not_saved: &'static str,
}

const SET_WORDS: TransportWords = TransportWords {
    timed_out: "Transport change approval timed out.",
    canceled: "Transport change was canceled.",
    denied: "Transport change was denied.",
    done: "Transport saved.",
    saved: "transport_set",
    not_saved: "transport_not_set",
};
const REMOVE_WORDS: TransportWords = TransportWords {
    timed_out: "Transport removal approval timed out.",
    canceled: "Transport removal was canceled.",
    denied: "Transport removal was denied.",
    done: "Transport removed; the host is reached at its saved address.",
    saved: "transport_removed",
    not_saved: "transport_not_removed",
};

/// Shows a transport change (`after`, or its removal when `None`) in the window and saves it on consent against the transport as it
/// was (`before`): the shape `set_transport` and `remove_transport` share.
#[allow(clippy::too_many_arguments)]
fn transport_change(
    env: &SyncEnv,
    runtime: &McpRuntime,
    policy: McpPolicy,
    mut context: RequestContext,
    cancel: &CancelToken,
    approve: &(dyn Fn(&McpPendingRequest) -> ApprovalDecision + Sync),
    alias: String,
    host: &repo::HostView,
    before: Option<crate::sync::transports::HostTransport>,
    after: Option<crate::sync::transports::HostTransport>,
    kind: &str,
    words: &TransportWords,
) -> Result<Value, String> {
    let id = host.host.id.clone();
    let rows = transport_rows(before.as_ref(), after.as_ref());
    if rows.is_empty() {
        return Err("Nothing would change.".into());
    }
    let proposal = McpHostProposal { kind: kind.into(), settings: rows };
    let _active = active(runtime, &mut context, &id, cancel)?;
    live(runtime, policy.approval_mode, cancel)?;
    let request = McpPendingRequest {
        host_proposal: Some(proposal.clone()),
        id: context.id.clone(),
        alias: host.host.payload.alias.clone(),
        host_id: Some(id.clone()),
        hostname: Some(host.effective_payload.hostname.clone()),
        user: Some(host.effective_payload.user.clone()),
        port: Some(host.effective_payload.port.to_string()),
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
            ApprovalDecision::TimedOut => return Err(words.timed_out.into()),
            ApprovalDecision::Cancel => return Err(words.canceled.into()),
            ApprovalDecision::Deny => return Err(words.denied.into()),
        }
        live(runtime, policy.approval_mode, cancel)?;
        crate::sync::record_commands::edit_records(env, |state, now| {
            live(runtime, policy.approval_mode, cancel).map_err(AppError::Other)?;
            let current_policy = runtime.policy.lock().unwrap().clone();
            permissions::ensure_record(&current_policy, state, &id).map_err(AppError::Other)?;
            if crate::sync::transports::get(state, &id) != before {
                return Err(AppError::Other(TRANSPORT_CHANGED.into()));
            }
            crate::sync::transports::set(state, &id, before.as_ref(), after.clone(), now).map_err(|e| AppError::Other(e.to_string()))
        })
        .map_err(|e| e.to_string())?;
        let state = record_runtime::snapshot(env).map_err(|e| e.to_string())?.0;
        let saved = repo::get_host(&state, &id).map_err(|e| e.to_string())?;
        Ok(json!({"host": records::metadata(&state, &saved)?, "message": words.done}))
    })();
    runtime.record(McpAuditEntry {
        at_ms: request.requested_at_ms,
        completed_at_ms: unix_ms(),
        id: context.id,
        client: "mcp".into(),
        host_id: Some(id),
        alias,
        mode: policy.approval_mode,
        requested_by: context.requested_by,
        requester_id: context.requester_id,
        client_info: context.client_info,
        outcome: if result.is_ok() { words.saved } else { words.not_saved }.into(),
        ..Default::default()
    });
    result
}

/// `set_transport`: a permitted host's Google Cloud IAP transport, set or changed with the person's consent.
pub(super) fn set_transport(
    env: &SyncEnv,
    runtime: &McpRuntime,
    input: &Value,
    context: RequestContext,
    cancel: &CancelToken,
    approve: &(dyn Fn(&McpPendingRequest) -> ApprovalDecision + Sync),
) -> Result<Value, String> {
    let policy = runtime.policy.lock().unwrap().clone();
    if !policy.enabled {
        return Err("MCP access is disabled.".into());
    }
    let changes: TransportInput = serde_json::from_value(input.clone()).map_err(|_| TRANSPORT_ONLY.to_string())?;
    let state = record_runtime::snapshot(env).map_err(|e| e.to_string())?.0;
    let host = find_host(&state, &changes.alias)?;
    permissions::ensure_record(&policy, &state, &host.host.id)?;
    if host.group_error.is_some() {
        return Err("Host Group inheritance needs review.".into());
    }
    let before = crate::sync::transports::get(&state, &host.host.id);
    let after = changes.merged(&host.host.id, before.as_ref())?;
    transport_change(env, runtime, policy, context, cancel, approve, changes.alias, &host, before, Some(after), proposal_kinds::SET_TRANSPORT, &SET_WORDS)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RemoveInput {
    alias: String,
}

/// `remove_transport`: a permitted host reached at its saved address again, with the person's consent.
pub(super) fn remove_transport(
    env: &SyncEnv,
    runtime: &McpRuntime,
    input: &Value,
    context: RequestContext,
    cancel: &CancelToken,
    approve: &(dyn Fn(&McpPendingRequest) -> ApprovalDecision + Sync),
) -> Result<Value, String> {
    let policy = runtime.policy.lock().unwrap().clone();
    if !policy.enabled {
        return Err("MCP access is disabled.".into());
    }
    let RemoveInput { alias } = serde_json::from_value(input.clone()).map_err(|_| "remove_transport accepts only an AI-approved host ID or alias.".to_string())?;
    let state = record_runtime::snapshot(env).map_err(|e| e.to_string())?.0;
    let host = find_host(&state, &alias)?;
    permissions::ensure_record(&policy, &state, &host.host.id)?;
    if host.group_error.is_some() {
        return Err("Host Group inheritance needs review.".into());
    }
    let before = crate::sync::transports::get(&state, &host.host.id);
    if before.is_none() {
        return Err("This host has no transport.".into());
    }
    transport_change(env, runtime, policy, context, cancel, approve, alias, &host, before, None, proposal_kinds::REMOVE_TRANSPORT, &REMOVE_WORDS)
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
        json!({"name":"update_host","title":"Change an SSH host's connection settings","description":"Propose changes to the public connection settings of a host this client may use. Only the fields given change; a field the host takes from its Group becomes the host's own. Lunport always asks the user before saving, including in Auto-log mode, and shows each change as old → new. Never changes the server key, passwords or private keys; changing the hostname or port clears the pinned server key, which the next connection verifies again (run verify_host_key). Does not move the host between Groups.","inputSchema":{"type":"object","properties":{
        "alias":{"type":"string","description":"AI-approved stable host ID or exact unambiguous alias of the host to change."},"new_alias":{"type":"string","maxLength":128},"hostname":{"type":"string","maxLength":255},"port":{"type":"integer","minimum":1,"maximum":65535},"user":{"type":"string","maxLength":128},"auth":{"type":"string","enum":["password","key","interactive"]},"key_id":{"type":"string","description":"Existing Lunport key ID; no private key or password."},"jump":{"type":"array","items":{"type":"string"},"maxItems":5},"keepalive_secs":{"type":"integer","minimum":0},"keepalive_max_missed":{"type":"integer","minimum":0},"connect_timeout_secs":{"type":"integer","minimum":1},"tags":{"type":"array","maxItems":32,"items":{"type":"string","maxLength":64}}},"required":["alias"],"additionalProperties":false},"annotations":{"readOnlyHint":false,"destructiveHint":false,"idempotentHint":false,"openWorldHint":false}}),
        json!({"name":"set_transport","title":"Set a host's Google Cloud IAP transport","description":"Propose a host's Google Cloud IAP tunnel settings (project, zone, instance, network interface, Google account, OS Login, and the Privileged Access Manager check) for a host this client may use. A field given replaces that field only; a host without a transport needs project, zone and instance. pam as an object sets the grant check (entitlements, location, duration_minutes); pam as null removes the check. Lunport always asks the user before saving, including in Auto-log mode, and shows each change as old → new. Does not connect or request a grant.","inputSchema":{"type":"object","properties":{
        "alias":{"type":"string","description":"AI-approved stable host ID or exact unambiguous alias."},"project":{"type":"string"},"zone":{"type":"string"},"instance":{"type":"string"},"interface":{"type":"string","description":"nic0 for the first interface."},"account":{"type":["string","null"],"description":"The Google account whose gcloud sign-in is used; null for gcloud's active account."},"os_login":{"type":"boolean"},"pam":{"anyOf":[{"type":"null"},{"type":"object","properties":{"entitlements":{"type":"array","items":{"type":"string"},"minItems":1,"maxItems":8},"location":{"type":"string"},"duration_minutes":{"type":"integer","minimum":1,"maximum":480}},"required":["entitlements"],"additionalProperties":false}]}},"required":["alias"],"additionalProperties":false},"annotations":{"readOnlyHint":false,"destructiveHint":false,"idempotentHint":true,"openWorldHint":false}}),
        json!({"name":"remove_transport","title":"Remove a host's Google Cloud IAP transport","description":"Propose removing a host's Google Cloud IAP transport, so the host is reached at its saved address again. Lunport always asks the user before saving, including in Auto-log mode.","inputSchema":{"type":"object","properties":{"alias":{"type":"string","description":"AI-approved stable host ID or exact unambiguous alias."}},"required":["alias"],"additionalProperties":false},"annotations":{"readOnlyHint":false,"destructiveHint":true,"idempotentHint":true,"openWorldHint":false}}),
    ]
}

#[cfg(test)]
#[path = "management_tests.rs"]
mod tests;
