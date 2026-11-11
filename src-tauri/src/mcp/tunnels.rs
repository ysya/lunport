//! Tunnels through MCP: a client reads, saves, starts and stops the tunnels of the hosts it may use. Saving always
//! asks the person; starting follows Ask or Auto-log as `ssh_exec` does; stopping never asks.
use super::management::{active, find_host, live, route_label};
use super::*;
use crate::session::{
    connect::{CancelToken, Connector},
    protocol::{AiAsker, HostQuery, Unreviewed},
    tunnels::{Entry, TunnelLive, TunnelPhase, TunnelView, Tunnels},
};
use crate::ssh::forward::{ForwardKind, ForwardSpec};
use crate::sync::{
    env::SyncEnv,
    record_repository as repo,
    record_runtime,
    records_v3::SyncStateV3,
    tunnel_rules::{self, TunnelRule},
};

/// How long `start_tunnel` waits for the tunnel to run or fail before it answers that it is still connecting, unless the tunnel's
/// connection has one of Lunport's windows open for the person (`wait_for_start`).
const START_WAIT: Duration = Duration::from_secs(90);
/// How long `stop_tunnel` waits for the tunnel to finish stopping.
const STOP_WAIT: Duration = Duration::from_secs(5);

const SETTINGS_ONLY: &str =
    "Provide the tunnel's settings only: name, host, kind, bind_address, port, target_host and target_port.";
const TUNNEL_ONLY: &str = "Name the tunnel only: its id from list_tunnels, or its exact name.";
const TUNNEL_CHANGED: &str = "The tunnel changed while the request was open; read it again and retry.";
const NEEDS_REVIEW: &str = "This tunnel needs a sync review in Lunport before it can start.";
/// What `start_tunnel` says when a server key question stopped it.
const TUNNEL_STOPPED: &str = "the tunnel did not start";
const GROUP_REVIEW: &str = "Host Group inheritance needs review.";

fn local() -> ForwardKind {
    ForwardKind::Local
}
fn loopback() -> String {
    "127.0.0.1".into()
}

/// What `create_tunnel` takes: the rule's name, its host and its forward, as the Tunnels panel edits them.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CreateInput {
    name: String,
    host: String,
    #[serde(default = "local")]
    kind: ForwardKind,
    #[serde(default = "loopback")]
    bind_address: String,
    #[serde(default)]
    port: u16,
    #[serde(default)]
    target_host: Option<String>,
    #[serde(default)]
    target_port: Option<u16>,
}

/// What `update_tunnel` may change: a field given replaces that field only.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct UpdateInput {
    tunnel: String,
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    host: Option<String>,
    #[serde(default)]
    kind: Option<ForwardKind>,
    #[serde(default)]
    bind_address: Option<String>,
    #[serde(default)]
    port: Option<u16>,
    #[serde(default)]
    target_host: Option<String>,
    #[serde(default)]
    target_port: Option<u16>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TunnelRef {
    tunnel: String,
}

fn tunnel_ref(input: &Value) -> Result<String, String> {
    serde_json::from_value::<TunnelRef>(input.clone()).map(|r| r.tunnel).map_err(|_| TUNNEL_ONLY.to_string())
}

/// Text from the library as the client reads it.
pub(super) fn safe(s: &str) -> String {
    crate::session::auth::printable(s).replace(['\n', '\t'], "?")
}

/// The hosts this client may use, as `get_host` permits them, by id with their aliases: read once per request, so that listing many
/// tunnels does not read the library once per tunnel.
pub(super) struct Usable(std::collections::BTreeMap<String, String>);
impl Usable {
    pub(super) fn of(policy: &McpPolicy, state: &SyncStateV3) -> Result<Usable, String> {
        let hosts = repo::list_hosts(state).map_err(|e| e.to_string())?;
        Ok(Usable(
            hosts
                .into_iter()
                .filter(|host| permissions::record_allowed(policy, state, host))
                .map(|host| (host.host.id.clone(), host.effective_payload.alias.clone()))
                .collect(),
        ))
    }
    /// Whether a tunnel through `host_id` is the client's.
    pub(super) fn has(&self, host_id: &str) -> bool {
        self.0.contains_key(host_id)
    }
    pub(super) fn alias(&self, host_id: &str) -> Option<&str> {
        self.0.get(host_id).map(String::as_str)
    }
}

/// The row `key` names among `rows`: by id, or else by exact name, which must name one row. Only the client's tunnels are searched,
/// so a tunnel it may not use answers as one that does not exist.
fn pick<T>(rows: Vec<T>, key: &str, rule: impl Fn(&T) -> &TunnelRule) -> Result<T, String> {
    let mut rows = rows;
    if let Some(at) = rows.iter().position(|row| rule(row).id == key) {
        return Ok(rows.swap_remove(at));
    }
    let mut named: Vec<T> = rows.into_iter().filter(|row| rule(row).name == key).collect();
    match named.len() {
        1 => Ok(named.pop().expect("one tunnel")),
        0 => Err(format!("No tunnel this client may use is named or identified as '{}'.", safe(key))),
        _ => Err(format!("Several tunnels this client may use are named '{}'; name it by its id.", safe(key))),
    }
}

/// The saved tunnel `key` names among the client's.
fn find_saved(usable: &Usable, state: &SyncStateV3, key: &str) -> Result<tunnel_rules::Stored, String> {
    let rows = tunnel_rules::view(state).into_iter().filter(|row| usable.has(&row.rule.host_id)).collect();
    pick(rows, key, |row: &tunnel_rules::Stored| &row.rule)
}

/// The client's tunnels as they stand on this computer: the saved ones, and those deleted elsewhere that still run here.
fn client_views(usable: &Usable, state: &SyncStateV3, tunnels: &Tunnels) -> Vec<TunnelView> {
    tunnels.list(state).into_iter().filter(|view| usable.has(&view.rule.host_id)).collect()
}

/// `host:port`, an IPv6 host in brackets.
fn endpoint(host: &str, port: u16) -> String {
    if host.contains(':') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

/// A tunnel of the client's as it reads it: its rule and its state on this computer.
fn view_json(usable: &Usable, view: &TunnelView) -> Value {
    let forward = &view.rule.forward;
    let destination = forward.kind != ForwardKind::Dynamic;
    let host_alias = usable.alias(&view.rule.host_id).map(safe);
    let active = view.live.phase.busy();
    let listening = (active && view.live.forwarding.port != 0).then_some(view.live.forwarding.port);
    json!({
        "id": view.rule.id,
        "name": safe(&view.rule.name),
        "host_id": view.rule.host_id,
        "host_alias": host_alias,
        "kind": forward.kind,
        "bind_address": safe(&forward.bind_address),
        "port": forward.port,
        "target_host": destination.then(|| safe(&forward.target_host)),
        "target_port": destination.then_some(forward.target_port),
        "state": view.live.phase,
        "listening": listening.map(|port| endpoint(&safe(&forward.bind_address), port)),
        "listening_port": listening,
        "connections": view.live.forwarding.connections,
        "error": view.live.forwarding.error.as_deref().map(safe),
        "started_by_ai_client": active && view.live.started_by.is_some(),
        "synced": view.synced,
        "needs_sync_review": view.blocked && !view.removed,
        "restart_to_apply_changes": view.changed,
        "deleted_elsewhere": view.removed,
    })
}

/// The kind of forward as the window names it.
fn kind_label(kind: ForwardKind) -> String {
    match kind {
        ForwardKind::Local => "Local forward",
        ForwardKind::Remote => "Remote forward",
        ForwardKind::Dynamic => "SOCKS5 proxy",
    }
    .into()
}

/// Who can connect to the tunnel's listener: loopback keeps it to the listening side; another address opens it to other computers (a
/// remote listener only when the host's SSH server allows that, as OpenSSH's GatewayPorts decides).
fn exposure(forward: &ForwardSpec, alias: &str) -> String {
    // An IPv4-mapped IPv6 address (`::ffff:0.0.0.0`) listens on its IPv4 address on a dual-stack socket: it is judged as that address.
    let ip = forward.bind_address.parse::<std::net::IpAddr>().ok().map(|ip| ip.to_canonical());
    let remote = forward.kind == ForwardKind::Remote;
    match ip {
        Some(ip) if ip.is_loopback() => {
            if remote {
                format!("{alias} only")
            } else {
                "This computer only".into()
            }
        }
        Some(ip) if ip.is_unspecified() => {
            if remote {
                format!("Any computer that can reach {alias}, if its SSH server allows it")
            } else {
                "Any computer that can reach this one".into()
            }
        }
        _ => {
            if remote {
                format!("Computers that can reach {} on {alias}, if its SSH server allows it", forward.bind_address)
            } else {
                format!("Computers that can reach {} on this computer", forward.bind_address)
            }
        }
    }
}

/// A tunnel's fields as the approval window names them.
fn fields(state: &SyncStateV3, rule: &TunnelRule) -> Vec<(&'static str, String)> {
    let alias = repo::get_host(state, &rule.host_id).map(|host| host.effective_payload.alias).unwrap_or_else(|_| "the host".into());
    let forward = &rule.forward;
    let side = if forward.kind == ForwardKind::Remote { format!("on {alias}") } else { "on this computer".into() };
    let listen = if forward.port == 0 {
        let address = if forward.bind_address.contains(':') { format!("[{}]", forward.bind_address) } else { forward.bind_address.clone() };
        format!("{address} {side}, a free port chosen at each start")
    } else {
        format!("{} {side}", endpoint(&forward.bind_address, forward.port))
    };
    let destination = match forward.kind {
        ForwardKind::Local => format!("{} as {alias} reaches it", endpoint(&forward.target_host, forward.target_port)),
        ForwardKind::Remote => format!("{} as this computer reaches it", endpoint(&forward.target_host, forward.target_port)),
        ForwardKind::Dynamic => format!("The destination each connection asks for, as {alias} reaches it"),
    };
    vec![
        ("Name", rule.name.clone()),
        ("Host", format!("{alias} ({})", rule.host_id)),
        ("Type", kind_label(forward.kind)),
        ("Listens on", listen),
        ("Forwards to", destination),
        ("Reachable from", exposure(forward, &alias)),
    ]
}

pub(super) fn rows(fields: Vec<(&'static str, String)>) -> Vec<(String, String)> {
    fields.into_iter().map(|(label, value)| (label.to_string(), value)).collect()
}

/// The rows of a change: every field whose value differs, as `old → new`, and the route when the host changes.
fn changed_rows(state: &SyncStateV3, before: &TunnelRule, after: &TunnelRule) -> Result<Vec<(String, String)>, String> {
    let olds: std::collections::BTreeMap<&str, String> = fields(state, before).into_iter().collect();
    let mut changes = Vec::new();
    for (label, new) in fields(state, after) {
        match olds.get(label) {
            Some(old) if *old != new => changes.push((label.to_string(), format!("{old} → {new}"))),
            _ => {}
        }
    }
    if before.host_id != after.host_id {
        changes.push(("Route".into(), format!("{} → {}", route_label(state, &before.host_id)?, route_label(state, &after.host_id)?)));
    }
    Ok(changes)
}

/// Where a new rule is saved, as the window names it: with the library's account it syncs.
pub(super) fn storage(state: &SyncStateV3) -> String {
    if state.account.is_some() { "Synced library" } else { "This device's library" }.into()
}

/// The host a tunnel may go through: one the client may use, whose Group inheritance is sound.
pub(super) fn usable_host(policy: &McpPolicy, state: &SyncStateV3, name: &str) -> Result<repo::HostView, String> {
    let host = find_host(state, name)?;
    permissions::ensure_record(policy, state, &host.host.id)?;
    if host.group_error.is_some() {
        return Err(GROUP_REVIEW.into());
    }
    Ok(host)
}

/// A forward from what the client sent: the destination of a SOCKS5 proxy is chosen per connection, so it stays empty unless given.
fn forward_of(kind: ForwardKind, bind_address: &str, port: u16, target_host: Option<&str>, target_port: Option<u16>) -> ForwardSpec {
    ForwardSpec {
        kind,
        bind_address: bind_address.trim().to_string(),
        port,
        target_host: target_host.unwrap_or_default().trim().to_string(),
        target_port: target_port.unwrap_or(0),
    }
}

impl UpdateInput {
    fn checked(input: &Value) -> Result<UpdateInput, String> {
        let p: UpdateInput = serde_json::from_value(input.clone()).map_err(|_| SETTINGS_ONLY.to_string())?;
        if p.name.is_none()
            && p.host.is_none()
            && p.kind.is_none()
            && p.bind_address.is_none()
            && p.port.is_none()
            && p.target_host.is_none()
            && p.target_port.is_none()
        {
            return Err("Provide at least one setting to change.".into());
        }
        Ok(p)
    }

    /// The rule with these changes applied: a new host must be one the client may use; a SOCKS5 proxy has no destination.
    fn apply(&self, policy: &McpPolicy, state: &SyncStateV3, before: &TunnelRule) -> Result<TunnelRule, String> {
        let mut rule = before.clone();
        if let Some(name) = &self.name {
            rule.name = name.trim().to_string();
        }
        if let Some(host) = &self.host {
            rule.host_id = usable_host(policy, state, host)?.host.id;
        }
        let forward = &mut rule.forward;
        if let Some(kind) = self.kind {
            forward.kind = kind;
            if kind == ForwardKind::Dynamic {
                forward.target_host.clear();
                forward.target_port = 0;
            }
        }
        if let Some(bind_address) = &self.bind_address {
            forward.bind_address = bind_address.trim().to_string();
        }
        if let Some(port) = self.port {
            forward.port = port;
        }
        if let Some(target_host) = &self.target_host {
            forward.target_host = target_host.trim().to_string();
        }
        if let Some(target_port) = self.target_port {
            forward.target_port = target_port;
        }
        rule.validate()?;
        Ok(rule)
    }
}

/// The words of a save: what the client is told when the person does not allow it or when it is done, and what the audit calls it.
pub(super) struct Words {
    pub(super) timed_out: &'static str,
    pub(super) canceled: &'static str,
    pub(super) denied: &'static str,
    pub(super) done: &'static str,
    pub(super) saved: &'static str,
    pub(super) not_saved: &'static str,
}

const CREATE_WORDS: Words = Words {
    timed_out: "Tunnel creation approval timed out.",
    canceled: "Tunnel creation was canceled.",
    denied: "Tunnel creation was denied.",
    done: "Tunnel saved. Start it with start_tunnel.",
    saved: "tunnel_created",
    not_saved: "tunnel_not_created",
};
const UPDATE_WORDS: Words = Words {
    timed_out: "Tunnel change approval timed out.",
    canceled: "Tunnel change was canceled.",
    denied: "Tunnel change was denied.",
    done: "Tunnel saved.",
    saved: "tunnel_updated",
    not_saved: "tunnel_not_updated",
};
const DELETE_WORDS: Words = Words {
    timed_out: "Tunnel deletion approval timed out.",
    canceled: "Tunnel deletion was canceled.",
    denied: "Tunnel deletion was denied.",
    done: "Tunnel deleted.",
    saved: "tunnel_deleted",
    not_saved: "tunnel_not_deleted",
};

/// The host a tunnel request's audit entry names (`alias`; its `tunnel` names the tunnel): the alias of the host the tunnel goes through,
/// or its id once the host is gone.
fn host_alias(state: &SyncStateV3, rule: &TunnelRule) -> String {
    repo::get_host(state, &rule.host_id).map(|host| host.host.payload.alias).unwrap_or_else(|_| rule.host_id.clone())
}

/// The approval request for a proposal about a tunnel through `host`.
fn request_for(context: &RequestContext, host: &repo::HostView, proposal: McpHostProposal, route: Vec<String>) -> McpPendingRequest {
    McpPendingRequest {
        host_proposal: Some(proposal),
        id: context.id.clone(),
        alias: host.host.payload.alias.clone(),
        host_id: Some(host.host.id.clone()),
        hostname: Some(host.effective_payload.hostname.clone()),
        user: Some(host.effective_payload.user.clone()),
        port: Some(host.effective_payload.port.to_string()),
        route,
        requested_by: context.requested_by.clone(),
        requester_id: context.requester_id.clone(),
        client_info: context.client_info.clone(),
        requested_at_ms: unix_ms(),
        ..Default::default()
    }
}

/// Shows a rule change (`after`, or the deletion of `before` when `None`) in the window and saves it on consent against the rule as it
/// was: the shape `create_tunnel`, `update_tunnel` and `delete_tunnel` share. `host` is the host the rule goes through after the change.
#[allow(clippy::too_many_arguments)]
fn save(
    env: &SyncEnv,
    runtime: &McpRuntime,
    tunnels: &Tunnels,
    policy: McpPolicy,
    mut context: RequestContext,
    cancel: &CancelToken,
    approve: &(dyn Fn(&McpPendingRequest) -> ApprovalDecision + Sync),
    state: &SyncStateV3,
    host: &repo::HostView,
    before: Option<TunnelRule>,
    after: Option<TunnelRule>,
    proposal: McpHostProposal,
    words: &Words,
) -> Result<Value, String> {
    let rule = after.clone().or_else(|| before.clone()).ok_or("Nothing would change.")?;
    let id = rule.id.clone();
    let keys = env.runtime.core.lock().unwrap().account_keys.clone();
    // What the save would refuse is refused before the window: a paused library, no room in the Catalog, too many tunnels.
    tunnel_rules::set(state, keys.as_ref(), &id, before.as_ref(), after.clone(), env.now()).map_err(crate::sync::transports::refusal)?;
    let _active = active(runtime, &mut context, &host.host.id, cancel)?;
    live(runtime, policy.approval_mode, cancel)?;
    let request = request_for(&context, host, proposal, Vec::new());
    let hosts: Vec<String> = before.iter().chain(after.iter()).map(|rule| rule.host_id.clone()).collect();
    let mut decision = None;
    let result = (|| {
        // Saving a tunnel is never covered by Auto-log's execution permission.
        let decided = approve(&request);
        decision = Some(decided);
        match decided {
            ApprovalDecision::Allow => {}
            ApprovalDecision::TimedOut => return Err(words.timed_out.into()),
            ApprovalDecision::Cancel => return Err(words.canceled.into()),
            ApprovalDecision::Deny => return Err(words.denied.into()),
        }
        live(runtime, policy.approval_mode, cancel)?;
        let keys = env.runtime.core.lock().unwrap().account_keys.clone();
        tunnels.edit(&id, || {
            crate::sync::record_commands::edit_records(env, |state, now| {
                live(runtime, policy.approval_mode, cancel).map_err(AppError::Other)?;
                let current_policy = runtime.policy.lock().unwrap().clone();
                for host_id in &hosts {
                    permissions::ensure_record(&current_policy, state, host_id).map_err(AppError::Other)?;
                }
                let current = tunnel_rules::view(state).into_iter().find(|row| row.rule.id == id).map(|row| row.rule);
                if current != before {
                    return Err(AppError::Other(TUNNEL_CHANGED.into()));
                }
                tunnel_rules::set(state, keys.as_ref(), &id, before.as_ref(), after.clone(), now).map_err(|e| AppError::Other(crate::sync::transports::refusal(e)))
            })
            .map(|_| ())
            .map_err(|e| e.to_string())
        })?;
        let state = record_runtime::snapshot(env).map_err(|e| e.to_string())?.0;
        let usable = Usable::of(&runtime.policy.lock().unwrap().clone(), &state)?;
        let tunnel = tunnels.list(&state).into_iter().find(|view| after.is_some() && view.rule.id == id).map(|view| view_json(&usable, &view));
        Ok(json!({"tunnel": tunnel, "message": words.done}))
    })();
    runtime.record(McpAuditEntry {
        at_ms: request.requested_at_ms,
        completed_at_ms: unix_ms(),
        id: context.id,
        client: "mcp".into(),
        host_id: Some(host.host.id.clone()),
        alias: host_alias(state, &rule),
        tunnel: Some(rule.name.clone()),
        mode: policy.approval_mode,
        requested_by: context.requested_by,
        requester_id: context.requester_id,
        client_info: context.client_info,
        outcome: if result.is_ok() { words.saved } else { words.not_saved }.into(),
        review: decision.and_then(activity::review_of),
        stop: result.as_ref().err().map(|error: &String| activity::stop_for(error, decision, None, runtime.withdrawn(policy.approval_mode, cancel))),
        ..Default::default()
    });
    result
}

pub(super) fn enabled_policy(runtime: &McpRuntime) -> Result<McpPolicy, String> {
    let policy = runtime.policy.lock().unwrap().clone();
    if !policy.enabled {
        return Err("MCP access is disabled.".into());
    }
    Ok(policy)
}

/// `list_tunnels`: the client's tunnels, with their state on this computer.
pub(super) fn list(env: &SyncEnv, runtime: &McpRuntime, tunnels: &Tunnels) -> Result<Value, String> {
    let policy = enabled_policy(runtime)?;
    let state = record_runtime::snapshot(env).map_err(|e| e.to_string())?.0;
    let usable = Usable::of(&policy, &state)?;
    let views: Vec<Value> = client_views(&usable, &state, tunnels).iter().map(|view| view_json(&usable, view)).collect();
    Ok(json!({"tunnels": views}))
}

/// `create_tunnel`: a new saved tunnel through a host the client may use, with the person's consent.
pub(super) fn create(
    env: &SyncEnv,
    runtime: &McpRuntime,
    tunnels: &Tunnels,
    input: &Value,
    context: RequestContext,
    cancel: &CancelToken,
    approve: &(dyn Fn(&McpPendingRequest) -> ApprovalDecision + Sync),
) -> Result<Value, String> {
    let policy = enabled_policy(runtime)?;
    let p: CreateInput = serde_json::from_value(input.clone()).map_err(|_| SETTINGS_ONLY.to_string())?;
    let state = record_runtime::snapshot(env).map_err(|e| e.to_string())?.0;
    let host = usable_host(&policy, &state, &p.host)?;
    let rule = TunnelRule {
        id: crate::sync::record_commands::new_host_id().map_err(|e| e.to_string())?,
        name: p.name.trim().to_string(),
        host_id: host.host.id.clone(),
        forward: forward_of(p.kind, &p.bind_address, p.port, p.target_host.as_deref(), p.target_port),
    };
    rule.validate()?;
    let mut settings = rows(fields(&state, &rule));
    settings.push(("Route".into(), route_label(&state, &host.host.id)?));
    settings.push(("Storage".into(), storage(&state)));
    let proposal = McpHostProposal { kind: proposal_kinds::CREATE_TUNNEL.into(), settings };
    save(env, runtime, tunnels, policy, context, cancel, approve, &state, &host, None, Some(rule), proposal, &CREATE_WORDS)
}

/// `update_tunnel`: changes to a saved tunnel of the client's, with the person's consent; a running tunnel is not changed.
pub(super) fn update(
    env: &SyncEnv,
    runtime: &McpRuntime,
    tunnels: &Tunnels,
    input: &Value,
    context: RequestContext,
    cancel: &CancelToken,
    approve: &(dyn Fn(&McpPendingRequest) -> ApprovalDecision + Sync),
) -> Result<Value, String> {
    let policy = enabled_policy(runtime)?;
    let changes = UpdateInput::checked(input)?;
    let state = record_runtime::snapshot(env).map_err(|e| e.to_string())?.0;
    // A rule the library cannot write now (paused, or shadowed by a newer one) is refused by the save's dry run, in its sentence.
    let saved = find_saved(&Usable::of(&policy, &state)?, &state, &changes.tunnel)?;
    if tunnels.busy(&saved.rule.id) {
        return Err(crate::session::tunnels::STOP_FIRST.into());
    }
    let before = saved.rule;
    usable_host(&policy, &state, &before.host_id)?;
    let after = changes.apply(&policy, &state, &before)?;
    let settings = changed_rows(&state, &before, &after)?;
    if settings.is_empty() {
        return Err("Nothing would change.".into());
    }
    let host = repo::get_host(&state, &after.host_id).map_err(|e| e.to_string())?;
    let proposal = McpHostProposal { kind: proposal_kinds::UPDATE_TUNNEL.into(), settings };
    save(env, runtime, tunnels, policy, context, cancel, approve, &state, &host, Some(before), Some(after), proposal, &UPDATE_WORDS)
}

/// `delete_tunnel`: a saved tunnel of the client's deleted, with the person's consent; a running tunnel is not deleted.
pub(super) fn delete(
    env: &SyncEnv,
    runtime: &McpRuntime,
    tunnels: &Tunnels,
    input: &Value,
    context: RequestContext,
    cancel: &CancelToken,
    approve: &(dyn Fn(&McpPendingRequest) -> ApprovalDecision + Sync),
) -> Result<Value, String> {
    let policy = enabled_policy(runtime)?;
    let key = tunnel_ref(input)?;
    let state = record_runtime::snapshot(env).map_err(|e| e.to_string())?.0;
    let saved = find_saved(&Usable::of(&policy, &state)?, &state, &key)?;
    if tunnels.busy(&saved.rule.id) {
        return Err(crate::session::tunnels::STOP_FIRST.into());
    }
    let host = repo::get_host(&state, &saved.rule.host_id).map_err(|e| e.to_string())?;
    let proposal = McpHostProposal { kind: proposal_kinds::DELETE_TUNNEL.into(), settings: rows(fields(&state, &saved.rule)) };
    save(env, runtime, tunnels, policy, context, cancel, approve, &state, &host, Some(saved.rule), None, proposal, &DELETE_WORDS)
}

/// Starts a tunnel an AI client was allowed to start: the rule as approved, the route and keys it was approved for, the mode it was
/// approved in and who started it. It answers the tunnel's entry, which `start` watches until the tunnel runs or fails.
pub(super) type Launch<'a> =
    dyn Fn(&TunnelRule, records::ApprovedTarget, ApprovalMode, String) -> Result<Arc<Entry>, String> + 'a;

/// The most tunnels that run on one device at once (`Tunnels::prepare` refuses the next).
const MAX_ACTIVE: usize = 16;

/// `start_tunnel`: a saved tunnel of the client's started on this computer under Ask or Auto-log, as `ssh_exec` connects.
/// The call waits until the tunnel runs or fails, up to `START_WAIT`.
#[allow(clippy::too_many_arguments)]
pub(super) fn start(
    env: &SyncEnv,
    runtime: &McpRuntime,
    tunnels: &Tunnels,
    connector: &Connector<'_>,
    owner: &dyn crate::session::auth::Owner,
    input: &Value,
    context: RequestContext,
    cancel: &CancelToken,
    approve: &(dyn Fn(&McpPendingRequest) -> ApprovalDecision + Sync),
    launch: &Launch<'_>,
) -> Result<Value, String> {
    start_within(env, runtime, tunnels, connector, owner, input, context, cancel, approve, launch, START_WAIT)
}

/// `start`, waiting up to `wait` for the launched tunnel to run or fail.
#[allow(clippy::too_many_arguments)]
fn start_within(
    env: &SyncEnv,
    runtime: &McpRuntime,
    tunnels: &Tunnels,
    connector: &Connector<'_>,
    owner: &dyn crate::session::auth::Owner,
    input: &Value,
    mut context: RequestContext,
    cancel: &CancelToken,
    approve: &(dyn Fn(&McpPendingRequest) -> ApprovalDecision + Sync),
    launch: &Launch<'_>,
    wait: Duration,
) -> Result<Value, String> {
    let policy = enabled_policy(runtime)?;
    let key = tunnel_ref(input)?;
    let state = record_runtime::snapshot(env).map_err(|e| e.to_string())?.0;
    let usable = Usable::of(&policy, &state)?;
    let saved = find_saved(&usable, &state, &key)?;
    if let Some(view) = tunnels.list(&state).into_iter().find(|view| view.rule.id == saved.rule.id && view.live.phase.busy()) {
        let message = match view.live.phase {
            TunnelPhase::Stopping => return Err("The tunnel is stopping; start it again once it has stopped.".into()),
            TunnelPhase::Connecting => "The tunnel is already starting; read list_tunnels for its state.",
            _ => "The tunnel is already running.",
        };
        return Ok(json!({"tunnel": view_json(&usable, &view), "message": message}));
    }
    // What the start would refuse once allowed is refused before the window.
    let keys = env.runtime.core.lock().unwrap().account_keys.clone();
    if saved.blocked || tunnel_rules::blocked_by_opaque(&state, keys.as_ref(), &tunnel_rules::wire_id(&saved.rule.id)) {
        return Err(NEEDS_REVIEW.into());
    }
    if tunnels.active_count() >= MAX_ACTIVE {
        return Err(format!("{MAX_ACTIVE} tunnels are already active on this computer; stop one first."));
    }
    let rule = saved.rule;
    let host = usable_host(&policy, &state, &rule.host_id)?;
    let query = HostQuery::Id(rule.host_id.clone());
    let target = connector.directory.resolve_public(&query).map_err(|e| e.to_string())?;
    let approved = records::ApprovedTarget::capture(&target, connector.keys)?;
    let mode = policy.approval_mode;
    let _active = active(runtime, &mut context, &rule.host_id, cancel)?;
    live(runtime, mode, cancel)?;
    let route: Vec<String> = target.hops.iter().map(|h| format!("{}@{}:{} ({})", h.user, h.hostname, h.port, h.alias)).collect();
    let mut settings = rows(fields(&state, &rule));
    settings.push(("Route".into(), route.join(" → ")));
    let proposal = McpHostProposal { kind: proposal_kinds::START_TUNNEL.into(), settings };
    let request = request_for(&context, &host, proposal, route);
    // What the start's windows decided, for its audit entry: the approval window's decision, the questions the person declined or left
    // unanswered here, and those of the launched tunnel's connection, which its entry notes.
    let mut decision = None;
    let declines = activity::Declines::default();
    let noting = activity::NotingOwner { inner: owner, declines: &declines };
    let confirmer = records::ClientConfirmer::new(connector.confirmer, records::asker(&context, mode, Unreviewed::Tunnel));
    let mut launched: Option<Arc<Entry>> = None;
    // Whether the tunnel ran by the time the call answered: one still connecting then is recorded as starting, not as started.
    let mut running = false;
    let result = (|| {
        if mode == ApprovalMode::Ask {
            let decided = approve(&request);
            decision = Some(decided);
            match decided {
                ApprovalDecision::Allow => {}
                ApprovalDecision::TimedOut => return Err("Tunnel start approval timed out.".to_string()),
                ApprovalDecision::Cancel => return Err("Tunnel start was canceled.".into()),
                ApprovalDecision::Deny => return Err("Tunnel start was denied.".into()),
            }
        }
        live(runtime, mode, cancel)?;
        // The rule, its host's permission and its route as they are now must be the ones approved.
        let current = record_runtime::snapshot(env).map_err(|e| e.to_string())?.0;
        permissions::ensure_record(&runtime.policy.lock().unwrap().clone(), &current, &rule.host_id)?;
        if !tunnel_rules::view(&current).into_iter().any(|row| row.rule == rule && !row.blocked) {
            return Err(TUNNEL_CHANGED.into());
        }
        approved.check(connector, &query)?;
        // A server key this device has not verified is decided here, before the tunnel launches: its worker would
        // ask while this call waits only `START_WAIT`. A rule changed meanwhile is refused by the launch.
        let host_still_allowed = || -> Result<(), String> {
            live(runtime, mode, cancel)?;
            let current = record_runtime::snapshot(env).map_err(|e| e.to_string())?.0;
            permissions::ensure_record(&runtime.policy.lock().unwrap().clone(), &current, &rule.host_id)?;
            approved.check(connector, &query)
        };
        records::verify_unverified(runtime, connector, &query, &target, &noting, &declines, cancel, &host_still_allowed, &confirmer, (&context, mode), TUNNEL_STOPPED)?;
        let entry = launch(&rule, approved.clone(), mode, records::client_label(&context))?;
        launched = Some(Arc::clone(&entry));
        // The answer is the tunnel as last seen, so that its state, the message and the audit agree.
        let seen = wait_for_start(&entry, cancel, wait)?;
        running = matches!(seen.phase, TunnelPhase::Running);
        let current = record_runtime::snapshot(env).map_err(|e| e.to_string())?.0;
        let mut view = tunnels.list(&current).into_iter().find(|view| view.rule.id == rule.id).ok_or("The saved tunnel no longer exists.")?;
        view.live = seen;
        let answer = view_json(&usable, &view);
        let message = match (&view.live.phase, answer["listening"].as_str()) {
            (TunnelPhase::Running, Some(at)) if rule.forward.kind == ForwardKind::Remote => format!("Tunnel running; {} listens on {at}.", host.effective_payload.alias),
            (TunnelPhase::Running, Some(at)) => format!("Tunnel running; connect to {at} on this computer."),
            (TunnelPhase::Running, None) => "Tunnel running.".into(),
            _ => "The tunnel is still connecting; read list_tunnels for its state.".into(),
        };
        Ok(json!({"tunnel": answer, "message": message}))
    })();
    runtime.record(McpAuditEntry {
        at_ms: request.requested_at_ms,
        completed_at_ms: unix_ms(),
        id: context.id,
        client: "mcp".into(),
        host_id: Some(rule.host_id.clone()),
        alias: host_alias(&state, &rule),
        tunnel: Some(rule.name.clone()),
        mode,
        requested_by: context.requested_by,
        requester_id: context.requester_id,
        client_info: context.client_info,
        outcome: match &result {
            Ok(_) if running => "tunnel_started",
            Ok(_) => "tunnel_starting",
            Err(_) => "tunnel_not_started",
        }
        .into(),
        review: if mode == ApprovalMode::AutoLog { Some(McpReview::AutoLog) } else { decision.and_then(activity::review_of) },
        stop: result.as_ref().err().map(|error: &String| {
            let declined = declines
                .first()
                .or_else(|| confirmer.declined())
                .or_else(|| launched.as_ref().and_then(|entry| entry.declines().first()));
            activity::stop_for(error, decision, declined, runtime.withdrawn(mode, cancel))
        }),
        ..Default::default()
    });
    result
}

/// Waits until the started tunnel `entry` runs or fails, up to `wait`, and answers it as last seen. While its connection has one of
/// Lunport's windows open for the person (a server key, a password, a grant), it waits
/// on past `wait`: the windows' own limits end the wait, and a client that cancels stops the tunnel, which withdraws them.
fn wait_for_start(entry: &Entry, cancel: &CancelToken, wait: Duration) -> Result<TunnelLive, String> {
    let deadline = Instant::now() + wait;
    loop {
        let now = entry.live();
        match now.phase {
            TunnelPhase::Running => return Ok(now),
            TunnelPhase::Error => {
                let error = now.forwarding.error.as_deref().map(safe).unwrap_or_else(|| "it ended.".into());
                // As `ssh_exec` says it, so that a client can tell what it needs from the person.
                return Err(if error.starts_with("needs interaction:") { error } else { format!("The tunnel could not start: {error}") });
            }
            TunnelPhase::Stopped => return Err("The tunnel was stopped before it ran.".into()),
            TunnelPhase::Connecting | TunnelPhase::Stopping => {}
        }
        if cancel.is_cancelled() {
            // The client went away or its access changed while the tunnel connected: nothing is left running for it.
            entry.stop();
            return Err("Tunnel start was canceled.".into());
        }
        if Instant::now() >= deadline && !entry.asking() {
            return Ok(now);
        }
        thread::sleep(Duration::from_millis(50));
    }
}

/// `stop_tunnel`: a running tunnel of the client's stopped, without a window; one that is not running is left as it is.
pub(super) fn stop(
    env: &SyncEnv,
    runtime: &McpRuntime,
    tunnels: &Tunnels,
    input: &Value,
    mut context: RequestContext,
    cancel: &CancelToken,
) -> Result<Value, String> {
    let policy = enabled_policy(runtime)?;
    let key = tunnel_ref(input)?;
    let state = record_runtime::snapshot(env).map_err(|e| e.to_string())?.0;
    let usable = Usable::of(&policy, &state)?;
    let mut view = pick(client_views(&usable, &state, tunnels), &key, |view: &TunnelView| &view.rule)?;
    let entry = tunnels.entry(&view.rule.id).filter(|entry| entry.live().phase.busy());
    let Some(entry) = entry else {
        return Ok(json!({"tunnel": view_json(&usable, &view), "message": "The tunnel is not running."}));
    };
    let _active = active(runtime, &mut context, &view.rule.host_id, cancel)?;
    let requested_at_ms = unix_ms();
    entry.stop();
    let deadline = Instant::now() + STOP_WAIT;
    view.live = loop {
        let now = entry.live();
        if !now.phase.busy() || Instant::now() >= deadline {
            break now;
        }
        thread::sleep(Duration::from_millis(50));
    };
    let message = if view.live.phase.busy() { "The tunnel is stopping." } else { "Tunnel stopped." };
    runtime.record(McpAuditEntry {
        at_ms: requested_at_ms,
        completed_at_ms: unix_ms(),
        id: context.id,
        client: "mcp".into(),
        host_id: Some(view.rule.host_id.clone()),
        alias: host_alias(&state, &view.rule),
        tunnel: Some(view.rule.name.clone()),
        mode: policy.approval_mode,
        requested_by: context.requested_by,
        requester_id: context.requester_id,
        client_info: context.client_info,
        outcome: "tunnel_stopped".into(),
        // Stopping never asks.
        review: Some(McpReview::NotAsked),
        ..Default::default()
    });
    Ok(json!({"tunnel": view_json(&usable, &view), "message": message}))
}

/// Whether an AI client's started tunnel may go on connecting: AI access on, in the mode the start was approved in, its host permitted
/// (`authorize`, as `ssh_exec` asks it).
fn may_connect(policy: &McpPolicy, mode: ApprovalMode, authorize: impl FnOnce(&McpPolicy) -> Result<(), String>) -> Result<(), String> {
    if !policy.enabled || policy.approval_mode != mode {
        return Err("MCP policy changed; request approval again.".into());
    }
    authorize(policy)
}

/// Why an AI client's tunnel must stop, if it must: AI access turned off, or its host no longer permitted. Another mode does not stop
/// a tunnel that was allowed to start.
fn access_ended(policy: &McpPolicy, authorize: impl FnOnce(&McpPolicy) -> Result<(), String>) -> Option<String> {
    (!policy.enabled || authorize(policy).is_err()).then(|| crate::session::tunnels::AI_ACCESS_ENDED.to_string())
}

/// What starts a tunnel in the app for `start_tunnel`: the panel's launch, guarded by what the client was approved for, and stopped
/// when the client's access to the tunnel's host ends.
pub(super) fn launcher(app: &AppHandle) -> impl Fn(&TunnelRule, records::ApprovedTarget, ApprovalMode, String) -> Result<Arc<Entry>, String> + '_ {
    move |rule, approved, mode, started_by| {
        let host_id = rule.host_id.clone();
        let worker_app = app.clone();
        // Who asks in the windows the tunnel's connection opens: the client, and in
        // Auto-log that the tunnel then starts without review.
        let asker = AiAsker { client: started_by, unreviewed: (mode == ApprovalMode::AutoLog).then_some(Unreviewed::Tunnel) };
        let for_worker = asker.clone();
        let work: crate::session::tunnels::Work = Box::new(move |rule, entry, connector, owner, account, needs_grant| {
            let state = worker_app.state::<AppState>();
            let policy = || state.mcp.policy.lock().unwrap().clone();
            let authorize = |policy: &McpPolicy| permissions::authorize(&state, policy, &host_id);
            let allowed = || may_connect(&policy(), mode, authorize);
            let revoked = || access_ended(&policy(), authorize);
            let ai = crate::session::tunnels::AiApproval { approved: &approved, asker: for_worker, allowed: &allowed, revoked: &revoked };
            crate::session::tunnels::run_for_ai(rule, entry, connector, owner, &ai, account, needs_grant)
        });
        crate::session::tunnels::launch(app, rule, Some(asker), work)
    }
}

/// `schema` with a `default`: what `create_tunnel` assumes when the field is left out.
fn with_default(schema: &Value, default: Value) -> Value {
    let mut schema = schema.clone();
    schema["default"] = default;
    schema
}

pub(super) fn tool_definitions() -> Vec<Value> {
    let tunnel = json!({"type":"string","description":"Tunnel ID from list_tunnels, or the tunnel's exact unambiguous name."});
    let kind = json!({"type":"string","enum":["local","remote","dynamic"],"description":"local: listens on this computer and forwards to target_host:target_port as the host reaches it. remote: listens on the host and forwards to target_host:target_port as this computer reaches it. dynamic: a SOCKS5 proxy on this computer; no target."});
    let bind_address = json!({"type":"string","description":"IPv4 or IPv6 listening address; 127.0.0.1 keeps it to the listening side."});
    let port = json!({"type":"integer","minimum":0,"maximum":65535,"description":"Listening port; 0 chooses a free port at each start."});
    let target_host = json!({"type":"string","maxLength":253,"description":"Destination host for local and remote tunnels."});
    let target_port = json!({"type":"integer","minimum":1,"maximum":65535,"description":"Destination port for local and remote tunnels."});
    let only_tunnel = json!({"type":"object","properties":{"tunnel":tunnel},"required":["tunnel"],"additionalProperties":false});
    vec![
        json!({"name":"list_tunnels","title":"List tunnels","description":"List the saved tunnels (SSH port forwards) through hosts this client may use, with their state on this computer: stopped, connecting, running, stopping or error; the address and port a running tunnel listens on, its open connections and its last error.","inputSchema":{"type":"object","properties":{},"additionalProperties":false},"annotations":{"readOnlyHint":true,"destructiveHint":false,"idempotentHint":true,"openWorldHint":false}}),
        json!({"name":"create_tunnel","title":"Propose a new tunnel","description":"Propose a saved tunnel through a host this client may use. Lunport always asks the user before saving, including in Auto-log mode, and shows who could reach the listener. Does not start it; use start_tunnel.","inputSchema":{"type":"object","properties":{"name":{"type":"string","maxLength":128},"host":{"type":"string","description":"AI-approved stable host ID or exact unambiguous alias of the host the tunnel goes through."},"kind":with_default(&kind, json!("local")),"bind_address":with_default(&bind_address, json!("127.0.0.1")),"port":with_default(&port, json!(0)),"target_host":target_host.clone(),"target_port":target_port.clone()},"required":["name","host"],"additionalProperties":false},"annotations":{"readOnlyHint":false,"destructiveHint":false,"idempotentHint":false,"openWorldHint":false}}),
        json!({"name":"update_tunnel","title":"Change a tunnel","description":"Propose changes to a saved tunnel through a host this client may use. Only the fields given change; changing kind to dynamic clears the destination. Lunport always asks the user before saving, including in Auto-log mode, and shows each change as old → new. A running tunnel must be stopped first.","inputSchema":{"type":"object","properties":{"tunnel":tunnel,"name":{"type":"string","maxLength":128},"host":{"type":"string","description":"AI-approved stable host ID or exact unambiguous alias of the host to go through instead."},"kind":kind,"bind_address":bind_address,"port":port,"target_host":target_host,"target_port":target_port},"required":["tunnel"],"additionalProperties":false},"annotations":{"readOnlyHint":false,"destructiveHint":false,"idempotentHint":false,"openWorldHint":false}}),
        json!({"name":"delete_tunnel","title":"Delete a tunnel","description":"Propose deleting a saved tunnel through a host this client may use. Lunport always asks the user first, including in Auto-log mode. A running tunnel must be stopped first.","inputSchema":only_tunnel.clone(),"annotations":{"readOnlyHint":false,"destructiveHint":true,"idempotentHint":true,"openWorldHint":false}}),
        json!({"name":"start_tunnel","title":"Start a tunnel","description":"Start a saved tunnel on this computer under the current Lunport Ask or Auto-log policy and wait until it runs (up to 90 seconds, longer while one of Lunport's windows waits for the user); answers where it listens. Ask mode shows the tunnel in Lunport's approval window. In both modes a new or changed server key opens Lunport's native trust window, and a Privileged Access Manager grant the route needs Lunport's Request a grant window. Credentials may be requested through Lunport's native windows. The tunnel keeps running after this call until stop_tunnel or the user stops it; Lunport stops it when AI access to its host ends.","inputSchema":only_tunnel.clone(),"annotations":{"readOnlyHint":false,"destructiveHint":false,"idempotentHint":true,"openWorldHint":true}}),
        json!({"name":"stop_tunnel","title":"Stop a tunnel","description":"Stop a running tunnel through a host this client may use, including one the user started. Does not ask; a tunnel that is not running is left as it is.","inputSchema":only_tunnel,"annotations":{"readOnlyHint":false,"destructiveHint":true,"idempotentHint":true,"openWorldHint":false}}),
    ]
}

#[cfg(test)]
#[path = "tunnels_tests.rs"]
mod tests;
