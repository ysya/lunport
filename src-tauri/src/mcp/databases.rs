//! Saved Cloud SQL databases through MCP: a client reads, saves, starts and stops the databases it may use. One on its public IP is the
//! client's while AI access is on; one reached through a host is the client's only while that host is allowed for AI access, as a tunnel
//! is, and any other answers as one that does not exist. Saving and deleting always ask the person; starting follows Ask or Auto-log as
//! `start_tunnel` does; stopping never asks. No tool takes or returns a port password: apps sign in with it, and only the person reads it
//! in Lunport. A database the client started keeps running when AI access to its host ends, since it serves the person's apps.
use super::management::{active, given, live, PamInput};
use super::tunnels::{enabled_policy, rows, safe, usable_host, Usable, Words};
use super::*;
use crate::session::{
    connect::{CancelToken, Connector},
    database_ports::{DatabasePorts, NO_LOCAL_PORT},
    databases::{delete_database, views, DatabaseLive, DatabasePhase, DatabaseView, CHANGED as DATABASE_CHANGED},
    protocol::{AiAsker, HostQuery, Unreviewed},
};
use crate::sync::{
    databases::{self, DatabaseEngine, DatabaseEnvironment, DatabaseNetwork, SavedDatabase},
    env::{Keychain, SyncEnv},
    record_repository as repo, record_runtime,
    records_v3::SyncStateV3,
    transports::{self, refusal, PamCheck},
};
use std::cell::Cell;

/// How long `start_database` waits for the port to run or fail before it answers that the database is still starting.
pub(super) const START_WAIT: Duration = Duration::from_secs(90);
/// How often `start_database` looks at the port while it waits.
const START_POLL: Duration = Duration::from_millis(100);
/// How long `stop_database` waits for the port to finish stopping.
const STOP_WAIT: Duration = Duration::from_secs(5);
/// The first local port a new database is offered on when the client names none, as the Databases page offers it.
const FIRST_PORT: u16 = 6543;

const SETTINGS_ONLY: &str =
    "Provide the database's settings only: name, connection_name, environment, default_database, account, pam, local_port and via_host.";
const DATABASE_ONLY: &str = "Name the database only: its id from list_databases, or its exact name.";
const NEEDS_REVIEW: &str = "This database needs a sync review in Lunport before it can start.";
const CONNECTION_NAME: &str = "Enter the connection name as project:region:instance.";
/// What `start_database` says when a server key question about its route host stopped it.
const DATABASE_STOPPED: &str = "the database did not start";

/// What `create_database` takes: a database as the Databases page saves one, its instance named by its connection name.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CreateInput {
    name: String,
    connection_name: String,
    environment: DatabaseEnvironment,
    #[serde(default)]
    default_database: Option<String>,
    #[serde(default)]
    account: Option<String>,
    #[serde(default)]
    pam: Option<PamInput>,
    #[serde(default)]
    local_port: Option<u16>,
    #[serde(default)]
    via_host: Option<String>,
}

/// What `update_database` may change: a field given replaces that field only; `account`, `pam` and `via_host` given as null remove
/// theirs.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct UpdateInput {
    database: String,
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    connection_name: Option<String>,
    #[serde(default)]
    environment: Option<DatabaseEnvironment>,
    #[serde(default)]
    default_database: Option<String>,
    #[serde(default, deserialize_with = "given")]
    account: Option<Option<String>>,
    #[serde(default, deserialize_with = "given")]
    pam: Option<Option<PamInput>>,
    #[serde(default)]
    local_port: Option<u16>,
    #[serde(default, deserialize_with = "given")]
    via_host: Option<Option<String>>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DatabaseRef {
    database: String,
}

fn database_ref(input: &Value) -> Result<String, String> {
    serde_json::from_value::<DatabaseRef>(input.clone()).map(|r| r.database).map_err(|_| DATABASE_ONLY.to_string())
}

fn snapshot(env: &SyncEnv) -> Result<SyncStateV3, String> {
    Ok(record_runtime::snapshot(env).map_err(|e| e.to_string())?.0)
}

/// Whether `database` is the client's: one on its public IP is, and one reached through a host is when the client may use that host.
fn visible(usable: &Usable, database: &SavedDatabase) -> bool {
    database.route_host().is_none_or(|host| usable.has(host))
}

/// The row `key` names among `rows`: by id, or else by exact name, which must name one row. Only the client's databases are searched,
/// so a database it may not use answers as one that does not exist.
fn pick<T>(rows: Vec<T>, key: &str, database: impl Fn(&T) -> &SavedDatabase) -> Result<T, String> {
    let mut rows = rows;
    if let Some(at) = rows.iter().position(|row| database(row).id == key) {
        return Ok(rows.swap_remove(at));
    }
    let mut named: Vec<T> = rows.into_iter().filter(|row| database(row).name == key).collect();
    match named.len() {
        1 => Ok(named.pop().expect("one database")),
        0 => Err(format!("No database this client may use is named or identified as '{}'.", safe(key))),
        _ => Err(format!("Several databases this client may use are named '{}'; name it by its id.", safe(key))),
    }
}

/// The saved database `key` names among the client's.
fn find_saved(usable: &Usable, state: &SyncStateV3, key: &str) -> Result<databases::Stored, String> {
    let rows = databases::view(state).into_iter().filter(|row| visible(usable, &row.database)).collect();
    pick(rows, key, |row: &databases::Stored| &row.database)
}

/// The client's databases as they stand on this computer: the saved ones, and those deleted elsewhere that still run here.
fn client_views(usable: &Usable, state: &SyncStateV3, ports: &DatabasePorts) -> Vec<DatabaseView> {
    views(state, ports).into_iter().filter(|view| visible(usable, &view.database)).collect()
}

/// Where a database is reached, as the client reads it: on its public IP, or through a host by its alias.
fn route_text(usable: &Usable, database: &SavedDatabase) -> String {
    match database.route_host() {
        None => "public IP".into(),
        Some(host) => format!("through {}", usable.alias(host).map(safe).unwrap_or_else(|| host.to_owned())),
    }
}

/// A database of the client's as it reads it, with its state on this computer. Never its port password, nor anything else the keychain
/// keeps.
fn view_json(usable: &Usable, view: &DatabaseView) -> Value {
    let database = &view.database;
    let live = &view.live;
    // While the port starts or runs, apps connect where it listens; otherwise where it will.
    let port = if live.phase.busy() { live.port.or(database.local_port) } else { database.local_port };
    json!({
        "id": database.id,
        "name": safe(&database.name),
        "environment": view.environment,
        "connection_name": safe(&database.connection_name()),
        "route": route_text(usable, database),
        "status": {"phase": live.phase, "step": live.step, "error": live.error.as_deref().map(safe)},
        "local_address": port.map(|port| format!("127.0.0.1:{port}")),
        "default_database": safe(&database.default_database),
        "account": database.account.as_deref().map(safe),
        "grant": database.pam.as_ref().map(|pam| json!({
            "entitlements": pam.entitlements.iter().map(|entitlement| safe(entitlement)).collect::<Vec<_>>(),
            "location": safe(&pam.location),
            "duration_minutes": pam.duration_secs / 60,
        })),
        "synced": view.synced,
    })
}

fn environment_label(environment: DatabaseEnvironment) -> String {
    match environment {
        DatabaseEnvironment::Dev => "Dev",
        DatabaseEnvironment::Staging => "Staging",
        DatabaseEnvironment::Prod => "Prod",
    }
    .into()
}

/// A grant check as the window names it: its entitlements, where they live and how long a grant asks for.
fn grant_label(pam: Option<&PamCheck>) -> String {
    pam.map(|pam| format!("{} ({}, {} min)", pam.entitlements.join(", "), pam.location, pam.duration_secs / 60)).unwrap_or_else(|| "None".into())
}

/// How a database is reached, as the window names it: the host by its alias and its id.
fn route_row(state: &SyncStateV3, database: &SavedDatabase) -> String {
    match database.route_host() {
        None => "Public IP".into(),
        Some(id) => {
            let alias = repo::get_host(state, id).map(|host| host.effective_payload.alias).unwrap_or_else(|_| "a host no longer in the library".into());
            format!("Through {alias} ({id})")
        }
    }
}

/// A database's fields as the approval window names them.
fn fields(state: &SyncStateV3, database: &SavedDatabase) -> Vec<(&'static str, String)> {
    vec![
        ("Name", database.name.clone()),
        ("Connection name", database.connection_name()),
        ("Environment", environment_label(database.environment)),
        ("Route", route_row(state, database)),
        ("Default database", database.default_database.clone()),
        ("Google account", database.account.clone().unwrap_or_else(|| "gcloud's active account".into())),
        ("Grant check", grant_label(database.pam.as_ref())),
        ("Local port", database.local_port.map(|port| format!("127.0.0.1:{port}")).unwrap_or_else(|| "Not shared".into())),
    ]
}

/// The rows of a change: every field whose value differs, as `old → new`.
fn changed_rows(state: &SyncStateV3, before: &SavedDatabase, after: &SavedDatabase) -> Vec<(String, String)> {
    fields(state, before)
        .into_iter()
        .zip(fields(state, after))
        .filter(|((_, old), (_, new))| old != new)
        .map(|((label, old), (_, new))| (label.to_string(), format!("{old} → {new}")))
        .collect()
}

/// Where a new database is saved, as the window names it: in the library, which syncs, once it uses central sync, as `databases::set`
/// stores it and `databases::view` marks it synced; on this device alone otherwise, with an account on the older chain-mode sync as well.
fn storage(state: &SyncStateV3) -> String {
    if transports::central_library(state) { "Synced library" } else { "This device's library" }.into()
}

/// The project, region and instance a connection name (`project:region:instance`) names; `SavedDatabase::validate` checks each.
fn instance_of(connection_name: &str) -> Result<(String, String, String), String> {
    match connection_name.trim().split(':').collect::<Vec<_>>().as_slice() {
        [project, region, instance] => Ok((project.to_string(), region.to_string(), instance.to_string())),
        _ => Err(CONNECTION_NAME.into()),
    }
}

/// How a database is reached when the client names `via_host`: through a host it may use, over the instance's private IP; with none, over
/// its public IP.
fn route_to(policy: &McpPolicy, state: &SyncStateV3, via_host: Option<&str>) -> Result<(DatabaseNetwork, Option<String>), String> {
    match via_host {
        Some(name) => Ok((DatabaseNetwork::Private, Some(usable_host(policy, state, name)?.host.id))),
        None => Ok((DatabaseNetwork::Public, None)),
    }
}

/// The first local port from 6543 up that none of `views` holds: what the Databases page offers a new database on.
fn first_free_port(views: &[DatabaseView]) -> Option<u16> {
    let taken: BTreeSet<u16> = views.iter().filter_map(|view| view.database.local_port).collect();
    (FIRST_PORT..=u16::MAX).find(|port| !taken.contains(port))
}

impl UpdateInput {
    fn checked(input: &Value) -> Result<UpdateInput, String> {
        let p: UpdateInput = serde_json::from_value(input.clone()).map_err(|_| SETTINGS_ONLY.to_string())?;
        if p.name.is_none()
            && p.connection_name.is_none()
            && p.environment.is_none()
            && p.default_database.is_none()
            && p.account.is_none()
            && p.pam.is_none()
            && p.local_port.is_none()
            && p.via_host.is_none()
        {
            return Err("Provide at least one setting to change.".into());
        }
        Ok(p)
    }

    /// The database with these changes applied: a host to go through must be one the client may use.
    fn apply(&self, policy: &McpPolicy, state: &SyncStateV3, before: &SavedDatabase) -> Result<SavedDatabase, String> {
        let mut database = before.clone();
        if let Some(name) = &self.name {
            database.name = name.trim().to_string();
        }
        if let Some(connection_name) = &self.connection_name {
            (database.project, database.region, database.instance) = instance_of(connection_name)?;
        }
        if let Some(environment) = self.environment {
            database.environment = environment;
        }
        if let Some(default_database) = &self.default_database {
            database.default_database = default_database.trim().to_string();
        }
        if let Some(account) = &self.account {
            database.account = account.as_deref().map(|account| account.trim().to_string());
        }
        if let Some(pam) = &self.pam {
            let stored = database.pam.take();
            database.pam = pam.as_ref().map(|input| input.merged(stored));
        }
        if let Some(port) = self.local_port {
            database.local_port = Some(port);
        }
        if let Some(via_host) = &self.via_host {
            (database.network, database.via_host) = route_to(policy, state, via_host.as_deref())?;
        }
        database.validate()?;
        Ok(database)
    }
}

const CREATE_WORDS: Words = Words {
    timed_out: "Database creation approval timed out.",
    canceled: "Database creation was canceled.",
    denied: "Database creation was denied.",
    done: "Database saved. Start it with start_database.",
    saved: "database_created",
    not_saved: "database_not_created",
};
const UPDATE_WORDS: Words = Words {
    timed_out: "Database change approval timed out.",
    canceled: "Database change was canceled.",
    denied: "Database change was denied.",
    done: "Database saved.",
    saved: "database_updated",
    not_saved: "database_not_updated",
};
const DELETE_WORDS: Words = Words {
    timed_out: "Database deletion approval timed out.",
    canceled: "Database deletion was canceled.",
    denied: "Database deletion was denied.",
    done: "Database deleted.",
    saved: "database_deleted",
    not_saved: "database_not_deleted",
};

/// What a request about the database `id` is registered under while it is open (`active`): the host it goes through, so that taking that
/// host's AI access away withdraws the request, or else its record.
fn registered_as(id: &str, host: Option<&str>) -> String {
    host.map_or_else(|| databases::wire_id(id), str::to_owned)
}

/// The approval request for a proposal about `database`, reached through `host` when it goes through one. The window names the database;
/// the host's own address is not part of it.
fn request_for(context: &RequestContext, database: &SavedDatabase, host: Option<&str>, proposal: McpHostProposal) -> McpPendingRequest {
    McpPendingRequest {
        host_proposal: Some(proposal),
        id: context.id.clone(),
        alias: database.name.clone(),
        host_id: host.map(str::to_owned),
        requested_by: context.requested_by.clone(),
        requester_id: context.requester_id.clone(),
        client_info: context.client_info.clone(),
        requested_at_ms: unix_ms(),
        ..Default::default()
    }
}

/// The audit entry of a request about the database `name` (`database`): `host_id` and `alias` are the host it goes through, by its own
/// alias or by its id once it is gone, and none and empty for a database on its public IP.
fn audit_entry(state: &SyncStateV3, context: RequestContext, host: Option<&str>, name: &str, mode: ApprovalMode, at_ms: u64, outcome: &str) -> McpAuditEntry {
    McpAuditEntry {
        at_ms,
        completed_at_ms: unix_ms(),
        id: context.id,
        client: "mcp".into(),
        host_id: host.map(str::to_owned),
        alias: host.map(|id| repo::get_host(state, id).map(|host| host.host.payload.alias).unwrap_or_else(|_| id.to_owned())).unwrap_or_default(),
        database: Some(name.to_owned()),
        mode,
        requested_by: context.requested_by,
        requester_id: context.requester_id,
        client_info: context.client_info,
        outcome: outcome.into(),
        ..Default::default()
    }
}

/// Shows a change to a database (`after`, or the deletion of `before` when `None`) in the window and saves it on consent against the
/// database as it was: the shape `create_database`, `update_database` and `delete_database` share. `commit` runs the edit of the library as
/// the change needs it: under the lock that refuses a running database, and for a deletion letting go of what this device had for it.
#[allow(clippy::too_many_arguments)]
fn save(
    env: &SyncEnv,
    runtime: &McpRuntime,
    ports: &DatabasePorts,
    policy: McpPolicy,
    mut context: RequestContext,
    cancel: &CancelToken,
    approve: &(dyn Fn(&McpPendingRequest) -> ApprovalDecision + Sync),
    state: &SyncStateV3,
    before: Option<SavedDatabase>,
    after: Option<SavedDatabase>,
    proposal: McpHostProposal,
    words: &Words,
    commit: &dyn Fn(&dyn Fn() -> Result<(), String>) -> Result<(), String>,
) -> Result<Value, String> {
    let database = after.clone().or_else(|| before.clone()).ok_or("Nothing would change.")?;
    let id = database.id.clone();
    // What the save would refuse is refused before the window: a paused library, no room in the Catalog, too many databases.
    databases::set(state, &id, before.as_ref(), after.clone(), env.now()).map_err(refusal)?;
    // Every host the database goes through, before the change and after it: the client must still be allowed each when it is saved.
    let hosts: Vec<String> = before.iter().chain(after.iter()).filter_map(|database| database.route_host().map(str::to_owned)).collect();
    // The host the request is about: the one the database goes through after the change, else the one it leaves.
    let host = after.as_ref().and_then(SavedDatabase::route_host).or_else(|| before.as_ref().and_then(SavedDatabase::route_host)).map(str::to_owned);
    let _active = active(runtime, &mut context, &registered_as(&id, host.as_deref()), cancel)?;
    live(runtime, policy.approval_mode, cancel)?;
    let request = request_for(&context, &database, host.as_deref(), proposal);
    let mut decision = None;
    // Whether the library took the change: a deletion whose port password could not be removed afterwards was made all the same.
    let saved = Cell::new(false);
    let result = (|| {
        // Saving or deleting a database is never covered by Auto-log's execution permission.
        let decided = approve(&request);
        decision = Some(decided);
        match decided {
            ApprovalDecision::Allow => {}
            ApprovalDecision::TimedOut => return Err(words.timed_out.into()),
            ApprovalDecision::Cancel => return Err(words.canceled.into()),
            ApprovalDecision::Deny => return Err(words.denied.into()),
        }
        live(runtime, policy.approval_mode, cancel)?;
        let record = || -> Result<(), String> {
            crate::sync::record_commands::edit_records(env, |state, now| {
                live(runtime, policy.approval_mode, cancel).map_err(AppError::Other)?;
                let current_policy = runtime.policy.lock().unwrap().clone();
                for host_id in &hosts {
                    permissions::ensure_record(&current_policy, state, host_id).map_err(AppError::Other)?;
                }
                let current = databases::view(state).into_iter().find(|row| row.database.id == id).map(|row| row.database);
                if current != before {
                    return Err(AppError::Other(DATABASE_CHANGED.into()));
                }
                databases::set(state, &id, before.as_ref(), after.clone(), now).map_err(|e| AppError::Other(refusal(e)))
            })
            .map_err(|e| e.to_string())?;
            saved.set(true);
            Ok(())
        };
        commit(&record)?;
        let state = snapshot(env)?;
        let usable = Usable::of(&runtime.policy.lock().unwrap().clone(), &state)?;
        let view = after.as_ref().and_then(|after| views(&state, ports).into_iter().find(|view| view.database.id == after.id));
        Ok(json!({"database": view.map(|view| view_json(&usable, &view)), "message": words.done}))
    })();
    runtime.record(McpAuditEntry {
        review: decision.and_then(activity::review_of),
        stop: result.as_ref().err().map(|error: &String| activity::stop_for(error, decision, None, runtime.withdrawn(policy.approval_mode, cancel))),
        ..audit_entry(state, context, host.as_deref(), &database.name, policy.approval_mode, request.requested_at_ms, if saved.get() { words.saved } else { words.not_saved })
    });
    result
}

/// `list_databases`: the client's databases, with their state on this computer.
pub(super) fn list(env: &SyncEnv, runtime: &McpRuntime, ports: &DatabasePorts) -> Result<Value, String> {
    let policy = enabled_policy(runtime)?;
    let state = snapshot(env)?;
    let usable = Usable::of(&policy, &state)?;
    let listed: Vec<Value> = client_views(&usable, &state, ports).iter().map(|view| view_json(&usable, view)).collect();
    Ok(json!({"databases": listed}))
}

/// `create_database`: a new saved database, on its public IP or through a host the client may use, with the person's consent.
pub(super) fn create(
    env: &SyncEnv,
    runtime: &McpRuntime,
    ports: &DatabasePorts,
    input: &Value,
    context: RequestContext,
    cancel: &CancelToken,
    approve: &(dyn Fn(&McpPendingRequest) -> ApprovalDecision + Sync),
) -> Result<Value, String> {
    let policy = enabled_policy(runtime)?;
    let p: CreateInput = serde_json::from_value(input.clone()).map_err(|_| SETTINGS_ONLY.to_string())?;
    let state = snapshot(env)?;
    let (network, via_host) = route_to(&policy, &state, p.via_host.as_deref())?;
    let (project, region, instance) = instance_of(&p.connection_name)?;
    let database = SavedDatabase {
        id: crate::sync::record_commands::new_host_id().map_err(|e| e.to_string())?,
        name: p.name.trim().to_string(),
        engine: DatabaseEngine::Postgres,
        project,
        region,
        instance,
        environment: p.environment,
        network,
        via_host,
        account: p.account.map(|account| account.trim().to_string()),
        default_database: p.default_database.map_or_else(|| "postgres".into(), |name| name.trim().to_string()),
        pam: p.pam.map(|pam| pam.merged(None)),
        local_port: p.local_port.or_else(|| first_free_port(&views(&state, ports))),
    };
    database.validate()?;
    let mut settings = rows(fields(&state, &database));
    settings.push(("Storage".into(), storage(&state)));
    let proposal = McpHostProposal { kind: proposal_kinds::CREATE_DATABASE.into(), settings };
    let id = database.id.clone();
    save(env, runtime, ports, policy, context, cancel, approve, &state, None, Some(database), proposal, &CREATE_WORDS, &|record| ports.edit(&id, record))
}

/// `update_database`: changes to a saved database of the client's, with the person's consent; a running database is not changed.
pub(super) fn update(
    env: &SyncEnv,
    runtime: &McpRuntime,
    ports: &DatabasePorts,
    input: &Value,
    context: RequestContext,
    cancel: &CancelToken,
    approve: &(dyn Fn(&McpPendingRequest) -> ApprovalDecision + Sync),
) -> Result<Value, String> {
    let policy = enabled_policy(runtime)?;
    let changes = UpdateInput::checked(input)?;
    let state = snapshot(env)?;
    // A database the library cannot write now (paused) is refused by the save's dry run, in its sentence.
    let before = find_saved(&Usable::of(&policy, &state)?, &state, &changes.database)?.database;
    // A running database is not changed: refused before the window, in the sentence the Databases page gets.
    ports.edit(&before.id, || Ok(()))?;
    if let Some(host) = before.route_host() {
        usable_host(&policy, &state, host)?;
    }
    let after = changes.apply(&policy, &state, &before)?;
    let settings = changed_rows(&state, &before, &after);
    if settings.is_empty() {
        return Err("Nothing would change.".into());
    }
    let proposal = McpHostProposal { kind: proposal_kinds::UPDATE_DATABASE.into(), settings };
    let id = before.id.clone();
    save(env, runtime, ports, policy, context, cancel, approve, &state, Some(before), Some(after), proposal, &UPDATE_WORDS, &|record| ports.edit(&id, record))
}

/// `delete_database`: a saved database of the client's deleted, with the person's consent, as the Databases page deletes it: with the
/// password of its port, which `keychain` keeps. A running database is not deleted.
#[allow(clippy::too_many_arguments)]
pub(super) fn delete(
    env: &SyncEnv,
    runtime: &McpRuntime,
    ports: &DatabasePorts,
    keychain: &dyn Keychain,
    input: &Value,
    context: RequestContext,
    cancel: &CancelToken,
    approve: &(dyn Fn(&McpPendingRequest) -> ApprovalDecision + Sync),
) -> Result<Value, String> {
    let policy = enabled_policy(runtime)?;
    let key = database_ref(input)?;
    let state = snapshot(env)?;
    let before = find_saved(&Usable::of(&policy, &state)?, &state, &key)?.database;
    ports.edit(&before.id, || Ok(()))?;
    let proposal = McpHostProposal { kind: proposal_kinds::DELETE_DATABASE.into(), settings: rows(fields(&state, &before)) };
    let id = before.id.clone();
    save(env, runtime, ports, policy, context, cancel, approve, &state, Some(before), None, proposal, &DELETE_WORDS, &|record| delete_database(ports, keychain, &id, record))
}

/// The route host of a database `start_database` starts: the route it resolved to when the request was read, which the start is approved
/// for.
struct RouteHost {
    id: String,
    query: HostQuery,
    target: crate::ssh::Target,
    approved: records::ApprovedTarget,
}

/// `start_database`: a saved database of the client's started on its local port under Ask or Auto-log, as `start_tunnel` starts a tunnel.
/// `start_port` starts it in the app (`starter`), with the windows on its way naming the client; the call waits until the port runs or
/// fails, up to `wait`.
#[allow(clippy::too_many_arguments)]
pub(super) fn start(
    env: &SyncEnv,
    runtime: &McpRuntime,
    ports: &DatabasePorts,
    connector: &Connector<'_>,
    owner: &dyn crate::session::auth::Owner,
    input: &Value,
    mut context: RequestContext,
    cancel: &CancelToken,
    approve: &(dyn Fn(&McpPendingRequest) -> ApprovalDecision + Sync),
    start_port: &dyn Fn(&SavedDatabase, AiAsker) -> Result<(), String>,
    wait: Duration,
) -> Result<Value, String> {
    let policy = enabled_policy(runtime)?;
    let key = database_ref(input)?;
    let state = snapshot(env)?;
    let usable = Usable::of(&policy, &state)?;
    let saved = find_saved(&usable, &state, &key)?;
    let database = saved.database;
    let name = safe(&database.name);
    if let Some(view) = client_views(&usable, &state, ports).into_iter().find(|view| view.database.id == database.id && view.live.phase.busy()) {
        let message = match view.live.phase {
            DatabasePhase::Stopping => return Err(format!("{name} is still stopping. Try again in a moment.")),
            DatabasePhase::Starting => format!("{name} is already starting; read list_databases for its state."),
            _ => format!("{name} is already running."),
        };
        return Ok(json!({"database": view_json(&usable, &view), "message": message}));
    }
    // What the start would refuse once allowed is refused before the window.
    if saved.blocked {
        return Err(NEEDS_REVIEW.into());
    }
    if database.local_port.is_none() {
        return Err(NO_LOCAL_PORT.into());
    }
    let route = database
        .route_host()
        .map(|id| -> Result<RouteHost, String> {
            usable_host(&policy, &state, id)?;
            let query = HostQuery::Id(id.to_owned());
            let target = connector.directory.resolve_public(&query).map_err(|e| e.to_string())?;
            let approved = records::ApprovedTarget::capture(&target, connector.keys)?;
            Ok(RouteHost { id: id.to_owned(), query, target, approved })
        })
        .transpose()?;
    let host = route.as_ref().map(|route| route.id.as_str());
    let mode = policy.approval_mode;
    let _active = active(runtime, &mut context, &registered_as(&database.id, host), cancel)?;
    live(runtime, mode, cancel)?;
    let proposal = McpHostProposal { kind: proposal_kinds::START_DATABASE.into(), settings: rows(fields(&state, &database)) };
    let request = request_for(&context, &database, host, proposal);
    // What the start's windows decided, for its audit entry: the approval window's decision, and the questions the person declined or
    // left unanswered while the route host's server key was verified.
    let mut decision = None;
    let declines = activity::Declines::default();
    let noting = activity::NotingOwner { inner: owner, declines: &declines };
    let confirmer = records::ClientConfirmer::new(connector.confirmer, records::asker(&context, mode, Unreviewed::Database));
    // Whether the port ran by the time the call answered: one still starting then is recorded as starting, not as started.
    let mut running = false;
    let result = (|| {
        if mode == ApprovalMode::Ask {
            let decided = approve(&request);
            decision = Some(decided);
            match decided {
                ApprovalDecision::Allow => {}
                ApprovalDecision::TimedOut => return Err("Database start approval timed out.".to_string()),
                ApprovalDecision::Cancel => return Err("Database start was canceled.".into()),
                ApprovalDecision::Deny => return Err("Database start was denied.".into()),
            }
        }
        live(runtime, mode, cancel)?;
        // The database, its route host's permission and its route as they are now must be the ones approved.
        let current = snapshot(env)?;
        if let Some(route) = &route {
            permissions::ensure_record(&runtime.policy.lock().unwrap().clone(), &current, &route.id)?;
        }
        if !databases::view(&current).into_iter().any(|row| row.database == database && !row.blocked) {
            return Err(DATABASE_CHANGED.into());
        }
        if let Some(route) = &route {
            route.approved.check(connector, &route.query)?;
            // A server key of the route host that this device has not verified is decided here, in the trust window that names the client:
            // the connection the start opens would ask in a window that does not.
            let host_still_allowed = || -> Result<(), String> {
                live(runtime, mode, cancel)?;
                let current = snapshot(env)?;
                permissions::ensure_record(&runtime.policy.lock().unwrap().clone(), &current, &route.id)?;
                route.approved.check(connector, &route.query)
            };
            records::verify_unverified(runtime, connector, &route.query, &route.target, &noting, &declines, cancel, &host_still_allowed, &confirmer, (&context, mode), DATABASE_STOPPED)?;
        }
        let ai = AiAsker { client: records::client_label(&context), unreviewed: (mode == ApprovalMode::AutoLog).then_some(Unreviewed::Database) };
        start_port(&database, ai)?;
        // The answer is the port as last seen, so that its state, the message and the audit agree.
        let seen = wait_for_start(ports, &database.id, cancel, wait)?;
        running = seen.phase == DatabasePhase::Running;
        let message = match seen.port.or(database.local_port).filter(|_| running) {
            Some(port) => format!("Database running on 127.0.0.1:{port}. Apps sign in with its port password, which the person copies from Lunport; no tool returns it."),
            None => "The database is still starting; read list_databases for its state.".into(),
        };
        let current = snapshot(env)?;
        let mut view = views(&current, ports).into_iter().find(|view| view.database.id == database.id).ok_or("The saved database no longer exists.")?;
        view.live = seen;
        Ok(json!({"database": view_json(&usable, &view), "message": message}))
    })();
    let outcome = match &result {
        Ok(_) if running => "database_started",
        Ok(_) => "database_starting",
        Err(_) => "database_not_started",
    };
    runtime.record(McpAuditEntry {
        review: if mode == ApprovalMode::AutoLog { Some(McpReview::AutoLog) } else { decision.and_then(activity::review_of) },
        stop: result.as_ref().err().map(|error: &String| {
            let declined = declines.first().or_else(|| confirmer.declined());
            activity::stop_for(error, decision, declined, runtime.withdrawn(mode, cancel))
        }),
        ..audit_entry(&state, context, host, &database.name, mode, request.requested_at_ms, outcome)
    });
    result
}

/// Waits until the started database `id` runs or fails, up to `wait`, and answers its port as last seen. A client that goes away meanwhile,
/// or whose access changed, stops the port: nothing is left starting for it.
fn wait_for_start(ports: &DatabasePorts, id: &str, cancel: &CancelToken, wait: Duration) -> Result<DatabaseLive, String> {
    let deadline = Instant::now() + wait;
    loop {
        let now = ports.live(id);
        match now.phase {
            DatabasePhase::Running => return Ok(now),
            DatabasePhase::Error => {
                let error = now.error.as_deref().map(safe).unwrap_or_else(|| "it ended.".into());
                return Err(format!("The database could not start: {error}"));
            }
            DatabasePhase::Stopped => return Err("The database was stopped before it ran.".into()),
            DatabasePhase::Starting | DatabasePhase::Stopping => {}
        }
        if cancel.is_cancelled() {
            ports.stop(id);
            return Err("Database start was canceled.".into());
        }
        if Instant::now() >= deadline {
            return Ok(now);
        }
        thread::sleep(START_POLL);
    }
}

/// `stop_database`: a running database of the client's stopped, without a window; one that is not running is left as it is.
pub(super) fn stop(env: &SyncEnv, runtime: &McpRuntime, ports: &DatabasePorts, input: &Value, mut context: RequestContext, cancel: &CancelToken) -> Result<Value, String> {
    let policy = enabled_policy(runtime)?;
    let key = database_ref(input)?;
    let state = snapshot(env)?;
    let usable = Usable::of(&policy, &state)?;
    let mut view = pick(client_views(&usable, &state, ports), &key, |view: &DatabaseView| &view.database)?;
    if !view.live.phase.busy() {
        return Ok(json!({"database": view_json(&usable, &view), "message": "The database is not running."}));
    }
    let id = view.database.id.clone();
    let host = view.database.route_host().map(str::to_owned);
    let _active = active(runtime, &mut context, &registered_as(&id, host.as_deref()), cancel)?;
    let requested_at_ms = unix_ms();
    ports.stop(&id);
    let deadline = Instant::now() + STOP_WAIT;
    view.live = loop {
        let now = ports.live(&id);
        if !now.phase.busy() || Instant::now() >= deadline {
            break now;
        }
        thread::sleep(Duration::from_millis(50));
    };
    let message = if view.live.phase.busy() { "The database is stopping." } else { "Database stopped." };
    runtime.record(McpAuditEntry {
        // Stopping never asks.
        review: Some(McpReview::NotAsked),
        ..audit_entry(&state, context, host.as_deref(), &view.database.name, policy.approval_mode, requested_at_ms, "database_stopped")
    });
    Ok(json!({"database": view_json(&usable, &view), "message": message}))
}

/// What starts a database in the app for `start_database`: the Databases page's Start, for the database as the client read it, refused
/// when it is no longer saved so; the windows on the way name `ai`.
pub(crate) fn starter(app: &AppHandle) -> impl Fn(&SavedDatabase, AiAsker) -> Result<(), String> + '_ {
    move |database, ai| crate::session::databases::start(app, &database.id, Some(database), Some(ai))
}

pub(super) fn tool_definitions() -> Vec<Value> {
    let database = json!({"type":"string","description":"Database ID from list_databases, or the database's exact unambiguous name."});
    let name = json!({"type":"string","maxLength":128});
    let connection_name = json!({"type":"string","description":"The instance's connection name: project:region:instance."});
    let environment = json!({"type":"string","enum":["dev","staging","prod"]});
    let default_database = json!({"type":"string","maxLength":63,"description":"The database to open on the instance."});
    let account = json!({"type":["string","null"],"description":"The Google account whose gcloud sign-in connects; null for gcloud's active account."});
    let pam = json!({"anyOf":[{"type":"null"},{"type":"object","properties":{"entitlements":{"type":"array","items":{"type":"string"},"minItems":1,"maxItems":8},"location":{"type":"string","description":"Where the entitlements live; global unless given."},"duration_minutes":{"type":"integer","minimum":1,"maximum":480}},"required":["entitlements"],"additionalProperties":false}],"description":"The Privileged Access Manager grant needed before connecting; null for none."});
    let local_port = json!({"type":"integer","minimum":1024,"maximum":65535,"description":"The port on 127.0.0.1 where apps on this computer connect."});
    let only_database = json!({"type":"object","properties":{"database":database},"required":["database"],"additionalProperties":false});
    let mut new_default_database = default_database.clone();
    new_default_database["default"] = json!("postgres");
    let mut new_local_port = local_port.clone();
    new_local_port["description"] = json!("The port on 127.0.0.1 where apps on this computer connect; omitted, the first free one from 6543.");
    vec![
        json!({"name":"list_databases","title":"List databases","description":"List the saved Cloud SQL databases this client may use: name, environment, connection name, route, status and local address. A database reached through a host is listed only when that host is allowed for AI access. Never returns port passwords.","inputSchema":{"type":"object","properties":{},"additionalProperties":false},"annotations":{"readOnlyHint":true,"destructiveHint":false,"idempotentHint":true,"openWorldHint":false}}),
        json!({"name":"create_database","title":"Propose a new database","description":"Propose a new saved Cloud SQL for PostgreSQL database. connection_name is project:region:instance; environment is dev, staging or prod; via_host names an allowed host to reach the instance's private IP through (omit it for the public IP). Lunport always asks the user before saving, including in Auto-log mode. Does not start the database or connect.","inputSchema":{"type":"object","properties":{"name":name,"connection_name":connection_name,"environment":environment,"default_database":new_default_database,"account":account,"pam":pam,"local_port":new_local_port,"via_host":{"type":"string","description":"AI-approved stable host ID or exact unambiguous alias of the host to reach the instance's private IP through; omit it for the public IP."}},"required":["name","connection_name","environment"],"additionalProperties":false},"annotations":{"readOnlyHint":false,"destructiveHint":false,"idempotentHint":false,"openWorldHint":false}}),
        json!({"name":"update_database","title":"Change a database","description":"Propose changes to a saved database this client may use. A field given replaces that field only: via_host null switches to the public IP, pam null removes the grant check. Lunport always asks the user before saving and shows each change as old → new. A running database must be stopped first.","inputSchema":{"type":"object","properties":{"database":database,"name":name,"connection_name":connection_name,"environment":environment,"default_database":default_database,"account":account,"pam":pam,"local_port":local_port,"via_host":{"type":["string","null"],"description":"AI-approved stable host ID or exact unambiguous alias of the host to reach the instance's private IP through; null for the public IP."}},"required":["database"],"additionalProperties":false},"annotations":{"readOnlyHint":false,"destructiveHint":false,"idempotentHint":false,"openWorldHint":false}}),
        json!({"name":"delete_database","title":"Delete a database","description":"Propose deleting a saved database this client may use, with its port password on this computer. Lunport always asks the user. A running database must be stopped first.","inputSchema":only_database.clone(),"annotations":{"readOnlyHint":false,"destructiveHint":true,"idempotentHint":true,"openWorldHint":false}}),
        json!({"name":"start_database","title":"Start a database","description":"Start a saved database's local port. Lunport requests the grants it needs, connects through its host and gets the Cloud SQL certificate, asking the user in its own windows. Follows Ask or Auto-log like start_tunnel. Answers when the port runs or fails, or after 90 seconds while it is still starting. Apps connect with the port password, which no tool returns.","inputSchema":only_database.clone(),"annotations":{"readOnlyHint":false,"destructiveHint":false,"idempotentHint":true,"openWorldHint":true}}),
        json!({"name":"stop_database","title":"Stop a database","description":"Stop a saved database's local port and close its connections. Never asks.","inputSchema":only_database,"annotations":{"readOnlyHint":false,"destructiveHint":true,"idempotentHint":true,"openWorldHint":false}}),
    ]
}

#[cfg(test)]
#[path = "databases_tests.rs"]
mod tests;
