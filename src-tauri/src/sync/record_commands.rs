//! Native public-record API. Credentials and private key text never enter overview DTOs.
use crate::error::AppError;
use crate::sync::central::payload::KeyStorage;
use crate::sync::env::SyncEnv;
use crate::sync::record_repository::{
    self as repo, HostReadiness, KeyAuthority, KeyStatus, RecordRevision,
};
use crate::sync::record_runtime::{self, RuntimeFormat};
use crate::sync::records_v3::{GroupPayload, HostPayload, HostScope, KeySlotPayload, SyncStateV3};
use crate::sync::transports::RouteChange;
use serde::{Deserialize, Serialize};
use tauri::{AppHandle, Emitter, Manager};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RevisionToken {
    pub version: String,
    pub updated_at_ms: String,
    pub device_id: String,
}
fn token_number(value: &str) -> Result<u64, AppError> {
    if value.is_empty()
        || (value.len() > 1 && value.starts_with('0'))
        || !value.bytes().all(|b| b.is_ascii_digit())
    {
        return Err(AppError::Other("invalid revision token".into()));
    }
    value
        .parse()
        .map_err(|_| AppError::Other("invalid revision token".into()))
}
impl RevisionToken {
    pub(in crate::sync) fn revision(&self) -> Result<RecordRevision, AppError> {
        Ok(RecordRevision {
            version: token_number(&self.version)?,
            updated_at_ms: token_number(&self.updated_at_ms)?,
            device_id: self.device_id.clone(),
        })
    }
}
impl From<RecordRevision> for RevisionToken {
    fn from(r: RecordRevision) -> Self {
        Self {
            version: r.version.to_string(),
            updated_at_ms: r.updated_at_ms.to_string(),
            device_id: r.device_id,
        }
    }
}
#[derive(Clone, Debug, Serialize)]
pub struct Readiness {
    kind: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    key_id: Option<String>,
}
#[derive(Clone, Debug, Serialize)]
pub struct HostView {
    id: String,
    scope: HostScope,
    payload: HostPayload,
    effective_payload: HostPayload,
    inherited_from: std::collections::BTreeMap<String, String>,
    group_error: Option<String>,
    revision: RevisionToken,
    readiness: Readiness,
}
#[derive(Clone, Debug, Serialize)]
pub struct GroupView {
    id: String,
    scope: HostScope,
    payload: GroupPayload,
    revision: RevisionToken,
    group_error: Option<String>,
}
#[derive(Clone, Debug, Serialize)]
pub struct KeyView {
    #[serde(skip_serializing_if = "Option::is_none")]
    storage: Option<&'static str>,
    synced: Option<bool>,
    id: String,
    authority: &'static str,
    public: Option<KeySlotPayload>,
    status: &'static str,
}
#[derive(Clone, Debug, Serialize)]
pub struct SpaceView {
    id: String,
    name: String,
    selected: bool,
    missing: bool,
}
#[derive(Clone, Debug, Serialize)]
pub struct AccountView {
    chain_id: String,
    device_name: String,
}
#[derive(Clone, Debug, Serialize)]
pub struct PendingAccountView {
    id: String,
    kind: crate::sync::record_account::PendingAccountKind,
    phase: crate::sync::record_account::PendingAccountPhase,
}
/// Why a route of a library that uses central sync stays on this computer, when the Google Cloud page can say it (R65): the library has
/// no room for it, as the publish step's walk finds (`transports::local_routes`). A route held back for any other reason has none.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(test, derive(ts_rs::TS))]
#[cfg_attr(test, ts(export, export_to = "../../src/bindings/"))]
pub enum TransportLocalReason {
    NoRoom,
}
/// Whether the route a host has syncs wherever the host does (the library's) or stays on this computer; one per route in `transports`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[cfg_attr(test, derive(ts_rs::TS))]
#[cfg_attr(test, ts(export, export_to = "../../src/bindings/"))]
pub struct TransportSyncView {
    pub host_id: String,
    pub synced: bool,
    /// Why a route stays on this computer, when that can be said: only that the library has no room for it. None for a synced route,
    /// and for one waiting on anything else (the library's latest changes not read yet, a conflict, paused writes).
    pub reason: Option<TransportLocalReason>,
}
/// What this device remembers of its last grant request for a host: the justification given and the length asked for, offered again
/// next time. It never leaves this device.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[cfg_attr(test, derive(ts_rs::TS))]
#[cfg_attr(test, ts(export, export_to = "../../src/bindings/"))]
pub struct GrantMemoryView {
    pub host_id: String,
    pub justification: String,
    pub duration_secs: u32,
}
#[derive(Clone, Debug, Serialize)]
pub struct RecordOverview {
    central_mode: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    key_scope: Option<crate::sync::record_import::central_local::Invocation>,
    syncing: bool,
    generation: String,
    group_deletion_token: String,
    relay_url: String,
    hosts: Vec<HostView>,
    groups: Vec<GroupView>,
    group_order: GroupOrderView,
    format_upgrade_required: bool,
    shared_format_upgrade_required: bool,
    keys: Vec<KeyView>,
    spaces: Vec<SpaceView>,
    account: Option<AccountView>,
    shared_writes_blocked: bool,
    pending_account: Option<PendingAccountView>,
    last_sync_ms: Option<u64>,
    last_error: Option<String>,
    library_enabled: bool,
    library_scope: Option<HostScope>,
    pending_changes: usize,
    conflicts: Vec<crate::sync::record_conflicts::ConflictView>,
    /// Host routes (Google Cloud IAP), one per host at most: the library's when it holds one, else the one saved on this device.
    transports: Vec<crate::sync::transports::HostTransport>,
    /// For each route in `transports`, whether it syncs with its host.
    transport_sync: Vec<TransportSyncView>,
    /// What grant requests taught this device, per host.
    grant_memory: Vec<GrantMemoryView>,
}
#[derive(Clone, Debug, Serialize)]
pub struct GroupOrderView {
    ids: Vec<String>,
    revision: Option<RevisionToken>,
    blocked: bool,
    sync_enabled: bool,
}
#[derive(Clone, Debug, Serialize)]
pub struct RecordStatus {
    format: RuntimeFormat,
    legacy_paused: bool,
    blocked_reason: Option<String>,
    overview: Option<RecordOverview>,
}
fn new_host_payload(mut payload: HostPayload) -> HostPayload {
    payload.host_key = None;
    payload
}
pub(crate) fn new_host_id() -> Result<String, AppError> {
    let mut bytes = [0u8; 8];
    getrandom::fill(&mut bytes).map_err(|_| AppError::Other("cannot create host id".into()))?;
    Ok(bytes.iter().map(|b| format!("{b:02x}")).collect())
}
fn error(e: impl std::fmt::Display) -> AppError {
    AppError::Other(e.to_string())
}
pub fn overview_from(
    state: &SyncStateV3,
    generation: u64,
    account_keys: Option<&crate::sync::crypto::ChainKeys>,
) -> Result<RecordOverview, AppError> {
    let snapshot = repo::snapshot(state).map_err(error)?;
    let group_deletion_token =
        crate::sync::record_groups::deletion_snapshot_token(&snapshot).map_err(error)?;
    let hosts = snapshot
        .hosts
        .into_iter()
        .map(|view| {
            let readiness = match view.readiness {
                HostReadiness::Ready => Readiness {
                    kind: "ready",
                    key_id: None,
                },
                HostReadiness::NeedsReview => Readiness {
                    kind: "needs_review",
                    key_id: None,
                },
                HostReadiness::NeedsKey(id) => Readiness {
                    kind: "needs_key",
                    key_id: Some(id),
                },
                HostReadiness::KeyConflict(id) => Readiness {
                    kind: "key_conflict",
                    key_id: Some(id),
                },
            };
            HostView {
                id: view.host.id,
                scope: view.host.scope,
                payload: view.host.payload,
                effective_payload: view.effective_payload,
                inherited_from: view.inherited_from,
                group_error: view.group_error,
                revision: view.revision.into(),
                readiness,
            }
        })
        .collect();
    let keys = snapshot
        .keys
        .into_iter()
        .map(|key| KeyView {
            storage: state.local.central_projection.as_ref()
                .and_then(|ledger| ledger.key_storage(&key.id))
                .map(|storage| match storage {
                    KeyStorage::Managed { .. } => "managed",
                    KeyStorage::Hardware => "hardware",
                    KeyStorage::ExternalAgent => "external_agent",
                }),
            synced: if key.authority == KeyAuthority::Local {
                Some(false)
            } else {
                account_keys
                    .filter(|keys| {
                        state
                            .account
                            .as_ref()
                            .is_some_and(|a| a.chain_id == keys.chain_id)
                    })
                    .map(|keys| {
                        state.account.as_ref().is_some_and(|a| {
                            a.sealed
                                .get(&crate::sync::state_v2::sealed_key(
                                    "key",
                                    &crate::sync::crypto::id_hash(keys, "key", &key.id),
                                ))
                                .is_some_and(|row| !row.envelope.deleted)
                        })
                    })
            },
            id: key.id,
            authority: match key.authority {
                KeyAuthority::Local => "local",
                KeyAuthority::Account => "account",
            },
            public: key.public,
            status: match key.status {
                KeyStatus::Available => "available",
                KeyStatus::NeedsMaterial => "needs_material",
                KeyStatus::Conflict => "conflict",
                KeyStatus::Deleted => "deleted",
            },
        })
        .collect();
    let spaces = state
        .spaces
        .iter()
        .map(|(id, s)| {
            let name = state
                .account
                .as_ref()
                .and_then(|a| {
                    a.records.get(&crate::sync::record::record_key(
                        crate::sync::record::RecordKind::Space,
                        id,
                    ))
                })
                .and_then(|r| (!r.record.deleted).then_some(&r.record.payload))
                .and_then(|p| p.get("name"))
                .and_then(|n| n.as_str())
                .unwrap_or(id)
                .to_owned();
            SpaceView {
                id: id.clone(),
                name,
                selected: s.selected,
                missing: s.missing,
            }
        })
        .collect();
    let routes = crate::sync::transports::view(state);
    // The walk the publish step takes; a Catalog that cannot be built gives no reason, as it moves nothing.
    let no_room = crate::sync::transports::local_routes(state).map(|walk| walk.no_room).unwrap_or_default();
    Ok(RecordOverview {
        key_scope: crate::sync::record_import::central_local::invocation(state).map(|scope| scope.with_generation(generation)),
        central_mode: state.local.central.as_ref().is_some_and(|owner| owner.control.cutover),
        syncing: false,
        conflicts: crate::sync::record_conflicts::views(state)?,
        generation: generation.to_string(),
        group_deletion_token,
        relay_url: state.relay_url.clone(),
        hosts,
        transport_sync: routes
            .iter()
            .map(|route| TransportSyncView {
                host_id: route.host_id.clone(),
                synced: crate::sync::transports::synced(state, &route.host_id),
                reason: no_room.contains(&route.host_id).then_some(TransportLocalReason::NoRoom),
            })
            .collect(),
        transports: routes,
        grant_memory: state
            .local
            .transport_grants
            .iter()
            .map(|(host_id, memory)| GrantMemoryView { host_id: host_id.clone(), justification: memory.justification.clone(), duration_secs: memory.duration_secs })
            .collect(),
        groups: snapshot
            .groups
            .into_iter()
            .map(|g| GroupView {
                id: g.group.id,
                scope: g.group.scope,
                payload: g.group.payload,
                revision: g.revision.into(),
                group_error: g.group_error,
            })
            .collect(),
        group_order: {
            let order = crate::sync::group_order::view(state);
            GroupOrderView {
                ids: order.ids,
                revision: order.revision.map(Into::into),
                blocked: order.blocked
                    || crate::sync::group_order::blocked_by_opaque(state, account_keys),
                sync_enabled: state.account.is_some(),
            }
        },
        format_upgrade_required: state.version < 4,
        shared_format_upgrade_required: state.account.as_ref().is_some_and(|a| {
            a.records
                .get(&crate::sync::record::record_key(
                    crate::sync::record::RecordKind::Meta,
                    crate::sync::record::ACCOUNT_META_ID,
                ))
                .is_none_or(|r| {
                    r.record
                        .payload
                        .get("schema_version")
                        .and_then(serde_json::Value::as_u64)
                        != Some(4)
                })
        }),
        keys,
        spaces,
        account: state.account.as_ref().map(|a| AccountView {
            chain_id: a.chain_id.clone(),
            device_name: state.device_name.clone(),
        }),
        shared_writes_blocked: crate::sync::records_v3::account_writes_blocked(state),
        pending_account: state.pending_account.as_ref().map(|op| PendingAccountView {
            id: op.id.clone(),
            kind: op.kind,
            phase: op.phase,
        }),
        library_enabled: crate::sync::record_library::enabled(state),
        library_scope: crate::sync::record_library::creation_scope(state).ok(),
        pending_changes: state
            .spaces
            .values()
            .flat_map(|s| s.records.values())
            .filter(|r| r.dirty)
            .count()
            + state
                .account
                .as_ref()
                .map_or(0, |a| a.records.values().filter(|r| r.dirty).count())
            + if crate::sync::record_library::enabled(state) {
                state
                    .local
                    .hosts
                    .values()
                    .chain(state.local.groups.values())
                    .filter(|r| !r.record.deleted)
                    .count()
            } else {
                0
            },
        last_sync_ms: state.last_sync_ms,
        last_error: state.last_error.clone(),
    })
}
pub fn overview(env: &SyncEnv) -> Result<RecordOverview, AppError> {
    let core = env.runtime.core.lock().unwrap();
    let mut overview = overview_from(
        record_runtime::active_state(&core)?,
        core.generation,
        core.account_keys.as_ref(),
    )?;
    overview.syncing = env
        .runtime
        .syncing
        .load(std::sync::atomic::Ordering::SeqCst);
    Ok(overview)
}
pub fn status(app: &AppHandle) -> Result<RecordStatus, AppError> {
    let state = app.state::<crate::state::AppState>();
    let core = state.sync.core.lock().unwrap();
    let overview = core
        .records
        .as_ref()
        .map(|s| {
            let mut overview = overview_from(s, core.generation, core.account_keys.as_ref())?;
            overview.syncing = state.sync.syncing.load(std::sync::atomic::Ordering::SeqCst);
            Ok::<_, AppError>(overview)
        })
        .transpose()?;
    Ok(RecordStatus {
        format: core.format,
        legacy_paused: core.legacy_paused,
        blocked_reason: core.save_blocked.clone(),
        overview,
    })
}
#[tauri::command]
pub async fn records_status(app: AppHandle) -> Result<RecordStatus, AppError> {
    tauri::async_runtime::spawn_blocking(move || status(&app))
        .await
        .map_err(crate::sync::engine::join_error)?
}
pub(crate) fn edit_records(
    env: &SyncEnv,
    transform: impl Fn(&SyncStateV3, u64) -> Result<SyncStateV3, AppError>,
) -> Result<RecordOverview, AppError> {
    let lifecycle = env.runtime.lifecycle.lock().unwrap();
    let now = env.now();
    env.runtime.note_activity(now);
    let (before, _) = record_runtime::snapshot(env)?;
    let proposed = transform(&before, now)?;
    if proposed.relay_url != before.relay_url {
        crate::sync::record_round::require_no_pending_migration(env)?;
    }
    if proposed.spaces != before.spaces {
        crate::sync::record_round::require_no_pending_migration(env)?;
    }
    // Routine library edits save to the cache offline. Transport still performs a
    // fresh authenticated format check before any upload. Format upgrades require
    // an online check here because they also modify account metadata.
    if proposed.spaces != before.spaces
        && (!crate::sync::record_library::enabled(&before) || proposed.account != before.account)
    {
        crate::sync::record_round::fresh_account_gate(env)?.ensure_compatible()?;
        if crate::sync::records_v3::account_writes_blocked(&record_runtime::snapshot(env)?.0) {
            return Err(AppError::Other(
                "Shared writes are blocked until the pending account operation completes.".into(),
            ));
        }
    }
    record_runtime::mutate_records(env, |s| transform(s, now))?;
    drop(lifecycle);
    let view = overview(env)?;
    env.events.status();
    env.events.wake();
    Ok(view)
}
async fn edit(
    app: AppHandle,
    transform: impl Fn(&SyncStateV3, u64) -> Result<SyncStateV3, AppError> + Send + 'static,
) -> Result<RecordOverview, AppError> {
    tauri::async_runtime::spawn_blocking(move || {
        crate::sync::engine::with_env(&app, |env| edit_records(env, transform))?
    })
    .await
    .map_err(crate::sync::engine::join_error)?
}
#[tauri::command]
pub async fn records_group_order(
    app: AppHandle,
    expected_ids: Vec<String>,
    revision: Option<RevisionToken>,
    ids: Vec<String>,
) -> Result<RecordOverview, AppError> {
    let revision = revision.map(|r| r.revision()).transpose()?;
    let account_keys = crate::sync::engine::with_env(&app, |env| {
        env.runtime.core.lock().unwrap().account_keys.clone()
    })?;
    edit(app, move |state, now| {
        if crate::sync::group_order::blocked_by_opaque(state, account_keys.as_ref()) {
            return Err(AppError::Other(
                "The synced group order cannot be read yet. Review Sync before reordering.".into(),
            ));
        }
        crate::sync::group_order::set(state, &expected_ids, revision.as_ref(), ids.clone(), now)
            .map_err(|e| match e {
                repo::RepositoryError::ReadOnlyAccount => AppError::Other(
                    "Group ordering is paused. Review Sync and app updates before trying again."
                        .into(),
                ),
                _ => AppError::Other(
                    "The group list or its order changed. Refresh the library and try again."
                        .into(),
                ),
            })
    })
    .await
}
#[tauri::command]
pub async fn records_host_forget_key(
    app: AppHandle,
    id: String,
    revision: RevisionToken,
    hostname: String,
    port: u16,
    expected_pin: crate::sync::records_v3::StoredHostKey,
) -> Result<RecordOverview, AppError> {
    let revision = revision.revision()?;
    edit(app, move |state, now| {
        repo::forget_host_key(state, &id, &revision, &repo::HostEndpoint { hostname:hostname.clone(), port }, &expected_pin, now).map_err(|e| match e {
            repo::RepositoryError::RevisionConflict {..} | repo::RepositoryError::EndpointChanged(_) | repo::RepositoryError::PinConflict(_) => AppError::Other("This host or its fingerprint changed. Reload the library and review the current identity before removing it.".into()),
            repo::RepositoryError::ReadOnlyAccount => AppError::Other("Shared changes are paused. Review Sync before removing this identity.".into()),
            other => error(other),
        })
    }).await
}

#[tauri::command]
pub async fn records_group_create(
    app: AppHandle,
    scope: HostScope,
    payload: GroupPayload,
    upgrade_confirmed: bool,
) -> Result<RecordOverview, AppError> {
    let id = new_host_id()?;
    edit(app, move |s, now| {
        let scope = if scope == HostScope::Local {
            crate::sync::record_library::creation_scope(s).map_err(error)?
        } else {
            scope.clone()
        };
        crate::sync::record_groups::create_group(
            s,
            &id,
            scope.clone(),
            payload.clone(),
            upgrade_confirmed,
            now,
        )
        .map_err(error)
    })
    .await
}
#[tauri::command]
pub async fn records_group_update(
    app: AppHandle,
    id: String,
    revision: RevisionToken,
    payload: GroupPayload,
) -> Result<RecordOverview, AppError> {
    let revision = revision.revision()?;
    edit(app, move |s, now| {
        crate::sync::record_groups::update_group(s, &id, &revision, payload.clone(), now)
            .map_err(error)
    })
    .await
}
#[tauri::command]
pub async fn records_group_delete(
    app: AppHandle,
    id: String,
    revision: RevisionToken,
    snapshot_token: Option<String>,
) -> Result<RecordOverview, AppError> {
    let revision = revision.revision()?;
    edit(app, move |s, now| {
        crate::sync::record_groups::delete_group(s, &id, &revision, snapshot_token.as_deref(), now)
            .map_err(error)
    })
    .await
}
/// A new host and its route, saved as one edit (design 2026-10-26, Commands): the route takes the new host's id, and a route that is
/// refused refuses the host with it.
pub(crate) fn create_host_with_route(
    state: &SyncStateV3,
    id: &str,
    scope: &HostScope,
    payload: &HostPayload,
    upgrade_confirmed: bool,
    route: Option<&RouteChange>,
    now: u64,
) -> Result<SyncStateV3, AppError> {
    let scope = if *scope == HostScope::Local {
        crate::sync::record_library::creation_scope(state).map_err(error)?
    } else {
        scope.clone()
    };
    let candidate = crate::sync::record_groups::promote_for_host(state, &scope, payload, upgrade_confirmed, now).map_err(error)?;
    let created = repo::create_host(&candidate, id, scope, payload.clone(), now).map_err(error)?;
    with_route(created, id, route, now)
}
/// A host's save and its route change, as one edit: the route is applied to the state the host write produced, so either both are
/// saved or neither.
pub(crate) fn update_host_with_route(
    state: &SyncStateV3,
    id: &str,
    revision: &RecordRevision,
    payload: &HostPayload,
    upgrade_confirmed: bool,
    route: Option<&RouteChange>,
    now: u64,
) -> Result<SyncStateV3, AppError> {
    let updated = crate::sync::record_library::update_host(state, id, revision, payload.clone(), upgrade_confirmed, now).map_err(error)?;
    with_route(updated, id, route, now)
}
/// A host's deletion takes its route with it, in the same edit; a library that cannot take the route's removal keeps the host too.
pub(crate) fn delete_host_with_route(state: &SyncStateV3, id: &str, revision: &RecordRevision, now: u64) -> Result<SyncStateV3, AppError> {
    let deleted = repo::delete_host(state, id, revision, now).map_err(error)?;
    crate::sync::transports::remove_route(&deleted, id, now).map_err(route_error)
}
/// `state` with the route change applied to `host_id`, if there is one; without, the route is untouched.
fn with_route(state: SyncStateV3, host_id: &str, route: Option<&RouteChange>, now: u64) -> Result<SyncStateV3, AppError> {
    match route {
        Some(change) => crate::sync::transports::apply_route_change(&state, host_id, change, now).map_err(route_error),
        None => Ok(state),
    }
}
/// A refused route write, as the person reads it (R16, R18).
fn route_error(e: repo::RepositoryError) -> AppError {
    AppError::Other(crate::sync::transports::refusal(e))
}
#[tauri::command]
pub async fn records_host_create(
    app: AppHandle,
    scope: HostScope,
    payload: HostPayload,
    upgrade_confirmed: Option<bool>,
    route: Option<RouteChange>,
) -> Result<RecordOverview, AppError> {
    let payload = new_host_payload(payload);
    let id = new_host_id()?;
    edit(app, move |s, now| {
        create_host_with_route(s, &id, &scope, &payload, upgrade_confirmed.unwrap_or(false), route.as_ref(), now)
    })
    .await
}
#[tauri::command]
pub async fn records_host_update(
    app: AppHandle,
    id: String,
    revision: RevisionToken,
    payload: HostPayload,
    upgrade_confirmed: Option<bool>,
    route: Option<RouteChange>,
) -> Result<RecordOverview, AppError> {
    let revision = revision.revision()?;
    edit(app, move |s, now| {
        update_host_with_route(s, &id, &revision, &payload, upgrade_confirmed.unwrap_or(false), route.as_ref(), now)
    })
    .await
}
#[tauri::command]
pub async fn records_host_delete(
    app: AppHandle,
    id: String,
    revision: RevisionToken,
) -> Result<RecordOverview, AppError> {
    let revision = revision.revision()?;
    edit(app, move |s, now| delete_host_with_route(s, &id, &revision, now)).await
}
#[tauri::command]
pub async fn records_host_move(
    app: AppHandle,
    id: String,
    revision: RevisionToken,
    destination: HostScope,
) -> Result<RecordOverview, AppError> {
    let revision = revision.revision()?;
    edit(app, move |s, now| {
        repo::move_host(s, &id, &revision, destination.clone(), now).map_err(error)
    })
    .await
}
#[tauri::command]
pub async fn records_host_group(
    app: AppHandle,
    id: String,
    revision: RevisionToken,
    group_id: Option<String>,
) -> Result<RecordOverview, AppError> {
    let revision = revision.revision()?;
    edit(app, move |s, now| {
        crate::sync::record_library::set_host_group(s, &id, &revision, group_id.as_deref(), now)
            .map_err(error)
    })
    .await
}
#[tauri::command]
pub async fn records_use_legacy(app: AppHandle) -> Result<(), AppError> {
    tauri::async_runtime::spawn_blocking(move || crate::sync::engine::resume_legacy(&app))
        .await
        .map_err(crate::sync::engine::join_error)?
}
#[tauri::command]
pub async fn records_pause_legacy(app: AppHandle) -> Result<RecordStatus, AppError> {
    tauri::async_runtime::spawn_blocking(move || {
        crate::sync::engine::with_env(&app, record_runtime::pause_legacy_workspace)??;
        let state = app.state::<crate::state::AppState>();
        state.agent.prompts.deny_all();
        state.agent.broker.clear();
        let result = status(&app)?;
        app.emit("records://status", &result)
            .map_err(|_| AppError::Other("cannot publish the paused workspace status".into()))?;
        Ok(result)
    })
    .await
    .map_err(crate::sync::engine::join_error)?
}
#[tauri::command]
pub fn records_sync_now() {
    crate::sync::engine::wake();
}
#[tauri::command]
pub async fn records_connect(
    app: AppHandle,
    host_id: String,
    terminal_id: Option<String>,
    new_tab: Option<bool>,
) -> Result<(), AppError> {
    tauri::async_runtime::spawn_blocking(move || {
        crate::sync::engine::with_env(&app, |env| {
            let (s, _) = record_runtime::snapshot(env)?;
            repo::get_host(&s, &host_id).map_err(error)?;
            let terminal = terminal_id
                .or_else(|| {
                    crate::connect::detect_terminals()
                        .into_iter()
                        .next()
                        .map(|t| t.id)
                })
                .ok_or_else(|| AppError::Other("no terminal found".into()))?;
            crate::connect::launch(&crate::connect::launch_for_id(
                &terminal,
                &host_id,
                new_tab.unwrap_or(false),
            )?)
        })?
    })
    .await
    .map_err(crate::sync::engine::join_error)?
}
#[tauri::command]
pub async fn records_set_relay_url(
    app: AppHandle,
    url: String,
) -> Result<RecordOverview, AppError> {
    let normalized = crate::sync::relay::validate_url(&url)?;
    edit(app, move |s, _| {
        if s.relay_url != normalized && (s.account.is_some() || s.pending_account.is_some()) {
            return Err(AppError::Other(
                "Finish the pending operation or leave the account before changing relays.".into(),
            ));
        }
        let mut next = s.clone();
        next.relay_url = normalized.clone();
        next.relay_features = None;
        next.last_error = None;
        Ok(next)
    })
    .await
}
/// User-requested code display: never a query-cache field or status event.
pub fn account_words(env: &SyncEnv) -> Result<zeroize::Zeroizing<String>, AppError> {
    let _lifecycle = env.runtime.lifecycle.lock().unwrap();
    let (state, _) = record_runtime::snapshot(env)?;
    let account = state
        .account
        .as_ref()
        .ok_or_else(|| AppError::Other("Join or create a sync chain first.".into()))?;
    let code = zeroize::Zeroizing::new(
        env.keychain
            .get(crate::sync::state::MNEMONIC_ACCOUNT)
            .map_err(|_| AppError::Other("The sync code cannot be read from this device.".into()))?
            .ok_or_else(|| {
                AppError::Other("The sync code is unavailable on this device.".into())
            })?,
    );
    let keys = crate::sync::crypto::derive_account(&code)
        .map_err(|_| AppError::Other("The stored sync code is invalid.".into()))?;
    if keys.chain_id != account.chain_id {
        return Err(AppError::Other(
            "The stored sync code belongs to a different chain; finish account recovery.".into(),
        ));
    }
    Ok(code)
}
#[tauri::command]
pub async fn records_account_words(app: AppHandle) -> Result<String, AppError> {
    tauri::async_runtime::spawn_blocking(move || {
        crate::sync::engine::with_env(&app, |env| {
            account_words(env).map(|words| words.to_string())
        })?
    })
    .await
    .map_err(crate::sync::engine::join_error)?
}
#[derive(Serialize)]
pub struct AccountSetupReply {
    words: String,
    overview: RecordOverview,
    complete: bool,
    pending_error: Option<String>,
    operation_id: String,
}
#[tauri::command]
pub async fn records_account_create(
    app: AppHandle,
    device_name: String,
    upgrade_confirmed: Option<bool>,
) -> Result<AccountSetupReply, AppError> {
    tauri::async_runtime::spawn_blocking(move || {
        crate::sync::engine::with_env(&app, |env| {
            let mut result = crate::sync::record_account::create_account(env, &device_name)?;
            if result.complete {
                if let Err(error) =
                    crate::sync::record_library::enable(env, upgrade_confirmed.unwrap_or(false))
                {
                    result.complete = false;
                    result.pending_error = Some(format!(
                        "The sync chain was created. Finish library sync setup: {error}"
                    ));
                }
            }
            Ok(AccountSetupReply {
                words: result.code.to_string(),
                overview: overview(env)?,
                complete: result.complete,
                pending_error: result.pending_error,
                operation_id: result.operation_id,
            })
        })?
    })
    .await
    .map_err(crate::sync::engine::join_error)?
}
#[tauri::command]
pub async fn records_account_join(
    app: AppHandle,
    words: String,
    device_name: String,
    upgrade_confirmed: Option<bool>,
) -> Result<RecordOverview, AppError> {
    let words = zeroize::Zeroizing::new(words);
    tauri::async_runtime::spawn_blocking(move || {
        crate::sync::engine::with_env(&app, |env| {
            crate::sync::record_account::join_account(env, &words, &device_name)?;
            crate::sync::record_library::enable(env, upgrade_confirmed.unwrap_or(false))?;
            overview(env)
        })?
    })
    .await
    .map_err(crate::sync::engine::join_error)?
}
#[tauri::command]
pub async fn records_account_resume(
    app: AppHandle,
    words: Option<String>,
) -> Result<RecordOverview, AppError> {
    let words = words.map(zeroize::Zeroizing::new);
    tauri::async_runtime::spawn_blocking(move || {
        crate::sync::engine::with_env(&app, |env| {
            crate::sync::record_account::resume_pending(env, words.as_ref().map(|w| w.as_str()))?;
            overview(env)
        })?
    })
    .await
    .map_err(crate::sync::engine::join_error)?
}
#[tauri::command]
pub async fn records_library_preview(
    app: AppHandle,
) -> Result<
    crate::sync::record_library::review::LibraryPreview,
    crate::sync::record_library::review::LibraryFailure,
> {
    tauri::async_runtime::spawn_blocking(move || {
        crate::sync::engine::with_env(&app, crate::sync::record_library::prepare)?
    })
    .await
    .map_err(|_| {
        crate::sync::record_library::review::LibraryFailure::new(
            "unavailable",
            "Library sync could not finish checking this workspace. Retry when it is available.",
        )
    })?
}

#[derive(Serialize)]
pub struct HostKeyVerificationReply {
    identity: crate::session::verify::VerifiedHostKey,
    overview: RecordOverview,
}
#[tauri::command]
pub async fn records_host_verify_key(
    app: AppHandle,
    id: String,
) -> Result<HostKeyVerificationReply, AppError> {
    tauri::async_runtime::spawn_blocking(move || {
        let state = app.state::<crate::state::AppState>();
        let broker = state
            .session
            .broker
            .lock()
            .unwrap()
            .clone()
            .ok_or_else(|| {
                AppError::Other("The SSH broker is unavailable. Restart Lunport and retry.".into())
            })?;
        let cancel = crate::session::connect::CancelToken::default();
        let _active = broker.register_deployment(cancel.clone()).map_err(error)?;
        let owner = crate::session::auth_window::NativeOwner {
            hub: state.session.auth_questions.clone(),
            surface: std::sync::Arc::new(crate::session::auth_window::TauriAuthSurface {
                app: app.clone(),
            }),
            request_id: format!("verify-{}", new_host_id()?),
            cancel: cancel.clone(),
        };
        let identity = crate::session::verify::verify(
            &broker.connector(),
            &crate::session::protocol::HostQuery::Id(id),
            &owner,
            &cancel,
        )
        .map_err(error)?;
        let overview = crate::sync::engine::with_env(&app, overview)??;
        Ok(HostKeyVerificationReply { identity, overview })
    })
    .await
    .map_err(crate::sync::engine::join_error)?
}
#[tauri::command]
pub async fn records_library_enable(
    app: AppHandle,
    upgrade_confirmed: bool,
    review: Option<crate::sync::record_library::review::LibraryReview>,
) -> Result<RecordOverview, crate::sync::record_library::review::LibraryFailure> {
    tauri::async_runtime::spawn_blocking(move || {
        crate::sync::engine::with_env(&app, |env| {
            crate::sync::record_library::enable_reviewed(env, upgrade_confirmed, review.as_ref())?;
            overview(env).map_err(Into::into)
        })?
    })
    .await
    .map_err(|_| {
        crate::sync::record_library::review::LibraryFailure::new(
            "unavailable",
            "Library sync could not finish updating this workspace. Retry when it is available.",
        )
    })?
}
#[tauri::command]
pub async fn records_space_create(
    app: AppHandle,
    name: String,
) -> Result<RecordOverview, AppError> {
    tauri::async_runtime::spawn_blocking(move || {
        crate::sync::engine::with_env(&app, |env| {
            crate::sync::record_account::create_space(env, &name)?;
            overview(env)
        })?
    })
    .await
    .map_err(crate::sync::engine::join_error)?
}
#[derive(Serialize)]
pub struct LeaveReply {
    receipt: crate::sync::record_leave::LeaveReceipt,
    overview: RecordOverview,
}
#[tauri::command]
pub async fn records_account_leave(app: AppHandle) -> Result<LeaveReply, AppError> {
    tauri::async_runtime::spawn_blocking(move || {
        crate::sync::engine::with_env(&app, |env| {
            let receipt = crate::sync::record_leave::leave_account(env)?;
            Ok(LeaveReply {
                receipt,
                overview: overview(env)?,
            })
        })?
    })
    .await
    .map_err(crate::sync::engine::join_error)?
}
#[tauri::command]
pub async fn records_account_rotate(
    app: AppHandle,
    device_name: String,
) -> Result<AccountSetupReply, AppError> {
    tauri::async_runtime::spawn_blocking(move || {
        crate::sync::engine::with_env(&app, |env| {
            let result = crate::sync::record_rotation::start_rotation(env, &device_name)?;
            Ok(AccountSetupReply {
                words: result.code.to_string(),
                overview: overview(env)?,
                complete: result.complete,
                pending_error: result.pending_error,
                operation_id: result.operation_id,
            })
        })?
    })
    .await
    .map_err(crate::sync::engine::join_error)?
}
#[tauri::command]
pub async fn records_space_select(
    app: AppHandle,
    space_id: String,
    selected: bool,
) -> Result<RecordOverview, AppError> {
    tauri::async_runtime::spawn_blocking(move || {
        crate::sync::engine::with_env(&app, |env| {
            crate::sync::record_account::select_space(env, &space_id, selected)?;
            overview(env)
        })?
    })
    .await
    .map_err(crate::sync::engine::join_error)?
}
#[tauri::command]
pub async fn records_key_import(
    app: AppHandle,
    name: String,
    private_text: String,
    invocation: Option<crate::sync::record_import::central_local::Invocation>,
) -> Result<RecordOverview, AppError> {
    let private = zeroize::Zeroizing::new(private_text);
    tauri::async_runtime::spawn_blocking(move || {
        crate::sync::engine::with_env(&app, |env| {
            crate::sync::record_keys::import_local_scoped(
                env,
                &name,
                private,
                crate::vault::store::EntryOrigin::Imported,
                invocation.as_ref(),
            )?;
            let result = overview(env)?;
            env.events.status();
            Ok(result)
        })?
    })
    .await
    .map_err(crate::sync::engine::join_error)?
}
#[tauri::command]
pub async fn records_key_import_file(
    app: AppHandle,
    name: String,
    path: String,
    invocation: Option<crate::sync::record_import::central_local::Invocation>,
) -> Result<RecordOverview, AppError> {
    tauri::async_runtime::spawn_blocking(move || {
        crate::sync::engine::with_env(&app, |env| {
            crate::sync::record_keys::import_local_file_scoped(env, &name, std::path::Path::new(&path), invocation.as_ref())?;
            let result = overview(env)?;
            env.events.status();
            Ok(result)
        })?
    })
    .await
    .map_err(crate::sync::engine::join_error)?
}
#[tauri::command]
pub async fn records_key_generate(
    app: AppHandle,
    name: String,
    invocation: Option<crate::sync::record_import::central_local::Invocation>,
) -> Result<RecordOverview, AppError> {
    tauri::async_runtime::spawn_blocking(move || {
        crate::sync::engine::with_env(&app, |env| {
            crate::sync::record_keys::generate_local_scoped(
                env,
                &name,
                crate::vault::generate::KeyAlgorithm::Ed25519,
                &name,
                None,
                invocation.as_ref(),
            )?;
            let result = overview(env)?;
            env.events.status();
            Ok(result)
        })?
    })
    .await
    .map_err(crate::sync::engine::join_error)?
}
#[tauri::command]
pub async fn records_key_rename(
    app: AppHandle,
    key_id: String,
    expected: KeySlotPayload,
    name: String,
    invocation: Option<crate::sync::record_import::central_local::Invocation>,
) -> Result<RecordOverview, AppError> {
    tauri::async_runtime::spawn_blocking(move || {
        crate::sync::engine::with_env(&app, |env| {
            if let Some(invocation) = invocation.as_ref() {
                crate::sync::record_import::central_local::rename(env, invocation, &key_id, &expected, &name)
            } else {
                edit_records(env, |state, now| {
                    crate::sync::record_import::central_local::check_invocation(state, None)?;
                    repo::rename_key(state, &key_id, &expected, &name, now).map_err(error)
                })
            }
        })?
    }).await.map_err(crate::sync::engine::join_error)?
}
#[tauri::command]
pub async fn records_key_delete(
    app: AppHandle,
    key_id: String,
    expected: KeySlotPayload,
    snapshot_token: String,
    force: bool,
    generation: String,
    invocation: Option<crate::sync::record_import::central_local::Invocation>,
) -> Result<RecordOverview, AppError> {
    let generation = token_number(&generation)?;
    tauri::async_runtime::spawn_blocking(move || {
        crate::sync::engine::with_env(&app, |env| {
            crate::sync::record_keys::delete_scoped(
                env,
                &key_id,
                &expected,
                &snapshot_token,
                force,
                generation,
                invocation.as_ref(),
            )
        })?
    })
    .await
    .map_err(crate::sync::engine::join_error)?
}

#[tauri::command]
pub async fn records_key_download(
    app: AppHandle,
    key_id: String,
) -> Result<RecordOverview, AppError> {
    tauri::async_runtime::spawn_blocking(move || {
        crate::sync::engine::with_env(&app, |env| {
            crate::sync::record_account::download_key(env, &key_id)?;
            overview(env)
        })?
    })
    .await
    .map_err(crate::sync::engine::join_error)?
}
/// Read only under lifecycle/vault. No repair, import or private-file fallback is permitted.
fn material_for_sync(
    env: &SyncEnv,
    id: &str,
) -> Result<(KeySlotPayload, zeroize::Zeroizing<String>), AppError> {
    let _lifecycle = env.runtime.lifecycle.lock().unwrap();
    {
        let core = env.runtime.core.lock().unwrap();
        if record_runtime::active_state(&core)?.local.central.as_ref().is_some_and(|owner| owner.control.cutover) {
            return Err(AppError::Other("Keys synchronize automatically in central account mode.".into()));
        }
    }
    crate::sync::record_round::require_no_pending_migration(env)?;
    let _vault = env.runtime.vault.lock().unwrap();
    let (state, _) = record_runtime::snapshot(env)?;
    let key = repo::resolve_key(&state, id).map_err(error)?;
    let vault_id = key
        .vault_id
        .as_ref()
        .ok_or_else(|| AppError::Other("This key has no material on this device.".into()))?;
    let vault = crate::vault::store::read_vault(
        &crate::vault::store::vault_path(&env.state_path),
        env.keychain,
    )
    .map_err(|_| {
        AppError::Other("The vault is unavailable; its original file was retained.".into())
    })?;
    let entry = vault
        .get(vault_id)
        .map_err(|_| AppError::Other("The vault key cannot be read.".into()))?
        .ok_or_else(|| AppError::Other("The key material is unavailable on this device.".into()))?;
    crate::session::record_material::verify(&key, &entry)
        .map_err(|message| AppError::Other(message.into()))?;
    Ok((
        key.public
            .ok_or_else(|| AppError::Other("The key has no public identity.".into()))?,
        zeroize::Zeroizing::new(entry.private_key.clone()),
    ))
}
#[tauri::command]
pub async fn records_key_sync(
    app: AppHandle,
    key_id: String,
    enabled: bool,
) -> Result<RecordOverview, AppError> {
    tauri::async_runtime::spawn_blocking(move || {
        crate::sync::engine::with_env(&app, |env| {
            if enabled {
                let (public, private) = material_for_sync(env, &key_id)?;
                crate::sync::record_account::publish_key(env, &key_id, public, private)?;
            } else {
                crate::sync::record_account::unpublish_key(env, &key_id)?;
            }
            overview(env)
        })?
    })
    .await
    .map_err(crate::sync::engine::join_error)?
}
struct CachedPreview {
    created: std::time::Instant,
    prepared: crate::sync::record_import::PreparedImport,
}
static PREVIEWS: std::sync::OnceLock<
    std::sync::Mutex<std::collections::BTreeMap<String, CachedPreview>>,
> = std::sync::OnceLock::new();
const PREVIEW_TTL: std::time::Duration = std::time::Duration::from_secs(15 * 60);
#[derive(Serialize)]
pub struct PreviewReply {
    token: String,
    preview: crate::sync::records_v3::importer::ImportPreview,
}
#[derive(Serialize)]
pub struct ImportReply {
    receipt: crate::sync::record_import::ImportReceipt,
    overview: RecordOverview,
}
#[tauri::command]
pub async fn records_import_preview(
    app: AppHandle,
    source: String,
) -> Result<PreviewReply, AppError> {
    tauri::async_runtime::spawn_blocking(move || {
        crate::sync::engine::with_env(&app, |env| {
            let (s, _) = record_runtime::snapshot(env)?;
            // Explicit import uses the source user's home for tilde expansion; never ambient environment values.
            let home = dirs::home_dir()
                .ok_or_else(|| AppError::Other("cannot determine the import home".into()))?;
            let mut options = crate::sync::records_v3::importer::ImportOptions::new(home);
            options.at_ms = env.now();
            options.reserved_host_ids = repo::list_hosts(&s)
                .map_err(error)?
                .into_iter()
                .map(|h| h.host.id)
                .collect();
            let managed = env.ssh_dir.join("sshelter");
            if let Ok(entries) = std::fs::read_dir(managed) {
                for entry in entries.take(128).flatten() {
                    if entry.path().extension().is_some_and(|e| e == "conf") {
                        options.excluded_sources.insert(entry.path());
                    }
                }
            }
            let prepared =
                crate::sync::record_import::prepare(std::path::Path::new(&source), &options)?;
            let preview = prepared.preview().clone();
            let token = crate::sync::slot_rules::new_slot_id()?;
            let mut cache = PREVIEWS.get_or_init(Default::default).lock().unwrap();
            cache.retain(|_, entry| entry.created.elapsed() < PREVIEW_TTL);
            if cache.len() >= 8 {
                return Err(AppError::Other(
                    "too many import previews; cancel an earlier preview or retry later".into(),
                ));
            }
            cache.insert(
                token.clone(),
                CachedPreview {
                    created: std::time::Instant::now(),
                    prepared,
                },
            );
            Ok(PreviewReply { token, preview })
        })?
    })
    .await
    .map_err(crate::sync::engine::join_error)?
}
#[tauri::command]
pub fn records_import_cancel(token: String) {
    if let Some(cache) = PREVIEWS.get() {
        cache.lock().unwrap().remove(&token);
    }
}
#[tauri::command]
pub async fn records_import_confirm(
    app: AppHandle,
    token: String,
    copy_key_ids: Vec<String>,
) -> Result<ImportReply, AppError> {
    tauri::async_runtime::spawn_blocking(move || {
        let mut prepared = PREVIEWS
            .get_or_init(Default::default)
            .lock()
            .unwrap()
            .remove(&token)
            .filter(|p| p.created.elapsed() < PREVIEW_TTL)
            .ok_or_else(|| {
                AppError::Other("import preview expired; preview the source again".into())
            })?
            .prepared;
        for id in copy_key_ids {
            crate::sync::record_import::select_key_copy(&mut prepared, &id)?;
        }
        crate::sync::engine::with_env(&app, |env| {
            let receipt = crate::sync::record_import::confirm(env, prepared)?;
            let overview = overview(env)?;
            env.events.status();
            Ok(ImportReply { receipt, overview })
        })?
    })
    .await
    .map_err(crate::sync::engine::join_error)?
}
#[tauri::command]
pub async fn records_import_resume(
    app: AppHandle,
    import_id: String,
) -> Result<ImportReply, AppError> {
    tauri::async_runtime::spawn_blocking(move || {
        crate::sync::engine::with_env(&app, |env| {
            let receipt = crate::sync::record_import::resume(env, &import_id)?;
            let overview = overview(env)?;
            env.events.status();
            Ok(ImportReply { receipt, overview })
        })?
    })
    .await
    .map_err(crate::sync::engine::join_error)?
}
#[tauri::command]
pub async fn records_import_pending(
    app: AppHandle,
) -> Result<Vec<crate::sync::record_import::PendingImport>, AppError> {
    tauri::async_runtime::spawn_blocking(move || {
        crate::sync::engine::with_env(&app, crate::sync::record_import::pending_imports)?
    })
    .await
    .map_err(crate::sync::engine::join_error)?
}
struct CachedMigrationPreview {
    created: std::time::Instant,
    prepared: crate::sync::record_migration::PreparedMigration,
}
static MIGRATION_PREVIEWS: std::sync::OnceLock<
    std::sync::Mutex<std::collections::BTreeMap<String, CachedMigrationPreview>>,
> = std::sync::OnceLock::new();
#[derive(Serialize)]
pub struct MigrationPreviewReply {
    token: String,
    preview: crate::sync::record_migration::MigrationPreview,
}
#[derive(Serialize)]
pub struct MigrationReply {
    receipt: crate::sync::record_migration::MigrationReceipt,
    status: RecordStatus,
}
#[tauri::command]
pub async fn records_migration_preview(
    app: AppHandle,
    words: Option<String>,
) -> Result<MigrationPreviewReply, AppError> {
    let words = words.map(zeroize::Zeroizing::new);
    tauri::async_runtime::spawn_blocking(move || {
        crate::sync::engine::with_env(&app, |env| {
            let prepared = crate::sync::record_migration::prepare(env, words)?;
            let preview = prepared.preview().clone();
            let token = crate::sync::slot_rules::new_slot_id()?;
            let mut cache = MIGRATION_PREVIEWS
                .get_or_init(Default::default)
                .lock()
                .unwrap();
            cache.retain(|_, entry| entry.created.elapsed() < PREVIEW_TTL);
            if cache.len() >= 8 {
                return Err(AppError::Other(
                    "too many migration previews; cancel an earlier preview or retry later".into(),
                ));
            }
            cache.insert(
                token.clone(),
                CachedMigrationPreview {
                    created: std::time::Instant::now(),
                    prepared,
                },
            );
            Ok(MigrationPreviewReply { token, preview })
        })?
    })
    .await
    .map_err(crate::sync::engine::join_error)?
}
#[tauri::command]
pub fn records_migration_cancel(token: String) {
    if let Some(cache) = MIGRATION_PREVIEWS.get() {
        cache.lock().unwrap().remove(&token);
    }
}
fn migration_reply(
    app: &AppHandle,
    receipt: crate::sync::record_migration::MigrationReceipt,
) -> Result<MigrationReply, AppError> {
    if receipt.complete {
        let state = app.state::<crate::state::AppState>();
        state.agent.prompts.deny_all();
        state.agent.broker.clear();
    }
    let status = status(app)?;
    crate::sync::engine::with_env(app, |env| {
        env.events.status();
        env.events.wake();
    })?;
    Ok(MigrationReply { receipt, status })
}
#[tauri::command]
pub async fn records_migration_confirm(
    app: AppHandle,
    token: String,
    old_clients_stopped_or_compatible: bool,
) -> Result<MigrationReply, AppError> {
    tauri::async_runtime::spawn_blocking(move || {
        let prepared = MIGRATION_PREVIEWS
            .get_or_init(Default::default)
            .lock()
            .unwrap()
            .remove(&token)
            .filter(|entry| entry.created.elapsed() < PREVIEW_TTL)
            .ok_or_else(|| {
                AppError::Other("migration preview expired; preview the source again".into())
            })?
            .prepared;
        let receipt = crate::sync::engine::with_env(&app, |env| {
            crate::sync::record_migration::confirm(
                env,
                prepared,
                crate::sync::record_migration::MigrationConsent {
                    old_clients_stopped_or_compatible,
                },
            )
        })??;
        migration_reply(&app, receipt)
    })
    .await
    .map_err(crate::sync::engine::join_error)?
}
#[tauri::command]
pub async fn records_migration_resume(
    app: AppHandle,
    migration_id: String,
    words: Option<String>,
) -> Result<MigrationReply, AppError> {
    let words = words.map(zeroize::Zeroizing::new);
    tauri::async_runtime::spawn_blocking(move || {
        let receipt = crate::sync::engine::with_env(&app, |env| match words {
            Some(words) => {
                crate::sync::record_migration::resume_with_code(env, &migration_id, words)
            }
            None => crate::sync::record_migration::resume(env, &migration_id),
        })??;
        migration_reply(&app, receipt)
    })
    .await
    .map_err(crate::sync::engine::join_error)?
}
#[tauri::command]
pub async fn records_migration_pending(
    app: AppHandle,
) -> Result<Vec<crate::sync::record_migration::PendingMigration>, AppError> {
    tauri::async_runtime::spawn_blocking(move || {
        crate::sync::engine::with_env(&app, crate::sync::record_migration::pending_migrations)?
    })
    .await
    .map_err(crate::sync::engine::join_error)?
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::sync::env::Keychain;
    use crate::sync::fake_relay::FakeRelay;
    use crate::sync::record::{record_key, RecordKind};
    use crate::sync::records_v3::validate_state;
    use crate::sync::testkit::{TestClock, TestDevice};
    use crate::sync::transports::{self, tests as fixtures};
    struct ForbiddenKeyIo;
    impl Keychain for ForbiddenKeyIo {
        fn get(&self, _: &str) -> Result<Option<String>, AppError> {
            panic!("manual central key actions cannot read credentials")
        }
        fn get_noninteractive(&self, _: &str) -> Result<Option<String>, AppError> {
            panic!("manual central key actions cannot read credentials")
        }
        fn set(&self, _: &str, _: &str) -> Result<(), AppError> {
            panic!("manual central key actions cannot write credentials")
        }
        fn delete(&self, _: &str) -> Result<(), AppError> {
            panic!("manual central key actions cannot delete credentials")
        }
    }
    #[test]
    fn central_key_policy_is_public_and_legacy_actions_stop_before_material_or_network_access() {
        let d = device("central-key-actions", &FakeRelay::new(), &TestClock::new());
        let (state, _, _, id, entry) = crate::sync::central::material_fixture_for_test();
        let view = overview_from(&state, 1, None).unwrap();
        assert!(view.central_mode);
        assert_eq!(view.keys[0].storage, Some("managed"));
        if let KeyStorage::Managed { sha256 } =
            &state.local.central_projection.as_ref().unwrap().storage[&id]
        {
            assert!(!serde_json::to_string(&view).unwrap().contains(sha256));
        }
        assert!(!serde_json::to_string(&view)
            .unwrap()
            .contains(&entry.private_key));
        d.runtime.core.lock().unwrap().records = Some(state.clone());
        let mut env = d.env();
        env.keychain = &ForbiddenKeyIo;
        assert!(material_for_sync(&env, &id)
            .err()
            .unwrap()
            .to_string()
            .contains("automatically"));
        assert!(crate::sync::record_account::download_key(&env, &id).is_err());
        assert!(crate::sync::record_account::unpublish_key(&env, &id).is_err());
        assert!(d.relay.calls().is_empty());
        let mut configured = state;
        configured.local.central_projection = None;
        let control = &mut configured.local.central.as_mut().unwrap().control;
        control.phase = crate::sync::central::client_state::Phase::Enrolled;
        control.cutover = false;
        assert!(!overview_from(&configured, 1, None).unwrap().central_mode);
    }
    #[test]
    fn pending_migration_blocks_account_effects_but_keeps_local_edits_available() {
        let d = device("pending", &FakeRelay::new(), &TestClock::new());
        let id = "e".repeat(32);
        let directory = d
            .env()
            .state_path
            .parent()
            .unwrap()
            .join("migrations")
            .join(id);
        std::fs::create_dir_all(&directory).unwrap();
        std::fs::write(
            directory.join("journal.json"),
            r#"{"phase":"prepared","host_count":1,"key_count":0}"#,
        )
        .unwrap();
        assert!(crate::sync::record_account::create_account(&d.env(), "pending").is_err());
        assert!(d.relay.calls().is_empty());
        assert!(d
            .keychain
            .entry(crate::sync::state::MNEMONIC_ACCOUNT)
            .is_none());
        let payload: HostPayload = serde_json::from_value(serde_json::json!({"schema":2,"alias":"local","hostname":"example.test","auth":"password"})).unwrap();
        record_runtime::mutate_records(&d.env(), |s| {
            repo::create_host(s, "0123456789abcdef", HostScope::Local, payload, 1).map_err(error)
        })
        .unwrap();
        assert_eq!(overview(&d.env()).unwrap().hosts.len(), 1);
    }
    fn device(
        name: &str,
        relay: &std::sync::Arc<FakeRelay>,
        clock: &std::sync::Arc<TestClock>,
    ) -> TestDevice {
        let device = TestDevice::new(name, relay, clock);
        let record_runtime::StartupProbe::Records { mut state, .. } =
            record_runtime::probe_startup(&device.env().state_path, name)
        else {
            panic!("fresh records")
        };
        state.relay_url = crate::sync::testkit::RELAY_URL.into();
        record_runtime::activate_probe(
            &mut device.runtime.core.lock().unwrap(),
            record_runtime::StartupProbe::Records {
                state,
                fresh: false,
            },
        )
        .unwrap();
        device
    }
    #[test]
    fn two_devices_share_hosts_and_only_explicitly_selected_private_material() {
        let relay = FakeRelay::new();
        let clock = TestClock::new();
        let a = device("first", &relay, &clock);
        let b = device("second", &relay, &clock);
        let created = crate::sync::record_account::create_account(&a.env(), "first").unwrap();
        assert!(created.complete);
        let local = crate::sync::record_keys::generate_local(
            &a.env(),
            "work",
            crate::vault::generate::KeyAlgorithm::Ed25519,
            "fixture",
            None,
        )
        .unwrap();
        let local_view = overview(&a.env()).unwrap();
        assert_eq!(local_view.keys[0].synced, Some(false));
        assert_eq!(local_view.keys[0].authority, "local");
        let space = crate::sync::record_account::create_space(&a.env(), "work").unwrap();
        let payload: HostPayload = serde_json::from_value(serde_json::json!({"schema":2,"alias":"web","hostname":"example.test","auth":"key","key_id":local.key_id})).unwrap();
        let created_at = a.env().now();
        record_runtime::mutate_records(&a.env(), |s| {
            repo::create_host(
                s,
                "0123456789abcdef",
                HostScope::Space {
                    space_id: space.clone(),
                },
                payload,
                created_at,
            )
            .map_err(error)
        })
        .unwrap();
        // Publication requires an explicit key choice; the first round cannot copy its private text.
        crate::sync::record_round::sync_once(&a.env()).unwrap();
        crate::sync::record_account::join_account(&b.env(), &created.code, "second").unwrap();
        crate::sync::record_account::select_space(&b.env(), &space, true).unwrap();
        crate::sync::record_round::sync_once(&b.env()).unwrap();
        let before = overview(&b.env()).unwrap();
        assert_eq!(before.hosts.len(), 1);
        assert_eq!(before.hosts[0].readiness.kind, "needs_key");
        assert!(material_for_sync(&b.env(), &local.key_id).is_err());
        let (public, private) = material_for_sync(&a.env(), &local.key_id).unwrap();
        crate::sync::record_account::publish_key(&a.env(), &local.key_id, public, private).unwrap();
        crate::sync::record_round::sync_once(&b.env()).unwrap();
        assert_eq!(overview(&b.env()).unwrap().keys[0].status, "needs_material");
        crate::sync::record_account::download_key(&b.env(), &local.key_id).unwrap();
        let after = overview(&b.env()).unwrap();
        assert_eq!(after.hosts[0].readiness.kind, "ready");
        assert_eq!(after.keys[0].synced, Some(true));
        let (public, private) = material_for_sync(&b.env(), &local.key_id).unwrap();
        assert_eq!(public, local.public);
        let rendered = serde_json::to_string(&after).unwrap();
        assert!(!rendered.contains("BEGIN OPENSSH PRIVATE KEY"));
        assert!(!rendered.contains(private.lines().nth(1).unwrap()));
        assert!(!rendered.contains(&*created.code));
        assert_eq!(&*account_words(&b.env()).unwrap(), &*created.code);
        for device in [&a, &b] {
            assert_eq!(
                std::fs::read_to_string(device.ssh_dir().join("config")).unwrap(),
                "# main\n"
            );
            assert!(!device.ssh_dir().join("sshelter").exists());
        }
    }
    #[test]
    fn code_display_rejects_mismatched_credentials_without_exposing_them() {
        let d = device("a", &FakeRelay::new(), &TestClock::new());
        assert!(account_words(&d.env()).is_err());
        let created = crate::sync::record_account::create_account(&d.env(), "a").unwrap();
        let other = crate::sync::crypto::generate_mnemonic().unwrap();
        d.keychain
            .set(crate::sync::state::MNEMONIC_ACCOUNT, &other)
            .unwrap();
        let error = account_words(&d.env()).unwrap_err().to_string();
        assert!(error.contains("different chain"));
        assert!(!error.contains(&other) && !error.contains(&*created.code));
    }
    #[test]
    fn webview_new_hosts_cannot_pretrust_a_server_key() {
        let payload:HostPayload=serde_json::from_value(serde_json::json!({"schema":2,"alias":"web","hostname":"example.test","auth":"password","host_key":{"algorithm":"ssh-ed25519","public_key":"caller-supplied","fingerprint":"caller-supplied","pinned_at_ms":1,"pinned_by_device_id":"caller"}})).unwrap();
        assert!(new_host_payload(payload).host_key.is_none());
    }
    #[test]
    fn full_width_tokens_roundtrip_without_javascript_number_loss() {
        let token: RevisionToken = RecordRevision {
            version: u64::MAX,
            updated_at_ms: 9_007_199_254_740_993,
            device_id: "d".repeat(32),
        }
        .into();
        let json = serde_json::to_value(&token).unwrap();
        assert!(json["version"].is_string());
        assert_eq!(token.revision().unwrap().version, u64::MAX);
        assert_eq!(
            token.revision().unwrap().updated_at_ms,
            9_007_199_254_740_993
        );
    }
    #[test]
    fn noncanonical_and_overflow_revision_tokens_are_rejected() {
        for value in ["00", "01", "+1", " 1", "1 ", "18446744073709551616", ""] {
            assert!(token_number(value).is_err(), "{value}");
        }
    }

    // ---- A host and its route are saved as one edit (design 2026-10-26, Commands) ----

    const HOST: &str = "0000000000000001";
    const OTHER: &str = "0000000000000002";
    const PAUSED: &str = "Sync changes are paused while account data is reviewed.";

    fn bare_state() -> SyncStateV3 {
        serde_json::from_value(serde_json::json!({"version":4,"device_id":"dddddddddddddddddddddddddddddddd","device_name":"fixture","relay_url":"http://127.0.0.1","last_sync_ms":null,"last_error":null})).unwrap()
    }
    fn web(alias: &str) -> HostPayload {
        serde_json::from_value(serde_json::json!({"schema":2,"alias":alias,"hostname":"fixture.invalid","auth":"password"})).unwrap()
    }
    /// Saving `host`'s route for the first time, as the editor sends it.
    fn first_route(host: &str) -> RouteChange {
        RouteChange { expected: None, kind: Some(fixtures::iap(host).kind) }
    }
    fn revision_of(state: &SyncStateV3, id: &str) -> RecordRevision {
        repo::get_host(state, id).unwrap().revision
    }
    /// `HOST` created in `state` with the route change the editor sent.
    fn host_with(state: &SyncStateV3, change: Option<&RouteChange>) -> SyncStateV3 {
        create_host_with_route(state, HOST, &HostScope::Local, &web("web"), false, change, 1).unwrap()
    }

    #[test]
    fn creating_a_host_with_an_invalid_route_saves_neither() {
        let d = device("invalid-route", &FakeRelay::new(), &TestClock::new());
        let id = new_host_id().unwrap();
        let mut invalid = fixtures::iap(&id);
        let transports::TransportKind::GcpIap { project, .. } = &mut invalid.kind;
        *project = "Eng".into();
        let change = RouteChange { expected: None, kind: Some(invalid.kind) };
        let refused = edit_records(&d.env(), |s, now| create_host_with_route(s, &id, &HostScope::Local, &web("web"), false, Some(&change), now));
        assert!(refused.unwrap_err().to_string().contains("Enter the Google Cloud project id."));
        let nothing = overview(&d.env()).unwrap();
        assert!(nothing.hosts.is_empty() && nothing.transports.is_empty(), "the host was not saved without its route");
        // The same save with a good route is one edit that holds both.
        let change = first_route(&id);
        let saved = edit_records(&d.env(), |s, now| create_host_with_route(s, &id, &HostScope::Local, &web("web"), false, Some(&change), now)).unwrap();
        assert_eq!((saved.hosts.len(), saved.transports), (1, vec![fixtures::iap(&id)]));
    }

    /// A new host's route takes the new host's id inside the same edit; with no route change, the host is saved as it always was.
    #[test]
    fn creating_a_host_saves_its_route_under_the_new_id() {
        let saved = host_with(&bare_state(), Some(&first_route(HOST)));
        assert!(repo::get_host(&saved, HOST).is_ok());
        assert_eq!(transports::get(&saved, HOST), Some(fixtures::iap(HOST)));
        validate_state(&saved).unwrap();
        let plain = host_with(&bare_state(), None);
        assert_eq!(plain, repo::create_host(&bare_state(), HOST, HostScope::Local, web("web"), 1).unwrap(), "no route change, no route write");
        // A host that is new has no route to have displayed.
        let shown = RouteChange { expected: Some(fixtures::iap(HOST)), kind: Some(fixtures::iap(HOST).kind) };
        let error = create_host_with_route(&bare_state(), HOST, &HostScope::Local, &web("web"), false, Some(&shown), 1).unwrap_err();
        assert_eq!(error.to_string(), transports::ROUTE_CHANGED);
    }

    #[test]
    fn updating_a_host_saves_changes_or_removes_its_route_in_the_same_edit() {
        let base = host_with(&bare_state(), Some(&first_route(HOST)));
        let changed = fixtures::with_zone(fixtures::iap(HOST), "asia-east1-c");
        let edit = RouteChange { expected: Some(fixtures::iap(HOST)), kind: Some(changed.kind.clone()) };
        let updated = update_host_with_route(&base, HOST, &revision_of(&base, HOST), &web("renamed"), false, Some(&edit), 2).unwrap();
        assert_eq!(repo::get_host(&updated, HOST).unwrap().host.payload.alias, "renamed");
        assert_eq!(transports::get(&updated, HOST), Some(changed.clone()));
        // Omitted, the route is untouched, down to its record.
        let untouched = update_host_with_route(&updated, HOST, &revision_of(&updated, HOST), &web("again"), false, None, 3).unwrap();
        assert_eq!(untouched.local.transports, updated.local.transports);
        assert_eq!(repo::get_host(&untouched, HOST).unwrap().host.payload.alias, "again");
        // Removed with the host's save.
        let removal = RouteChange { expected: Some(changed), kind: None };
        let removed = update_host_with_route(&untouched, HOST, &revision_of(&untouched, HOST), &web("direct"), false, Some(&removal), 4).unwrap();
        assert_eq!((repo::get_host(&removed, HOST).unwrap().host.payload.alias.as_str(), transports::get(&removed, HOST)), ("direct", None));
        validate_state(&removed).unwrap();
    }

    /// R16: a route that is not the one the editor displayed refuses the whole save, and the person reads the route's own sentence.
    #[test]
    fn a_route_that_changed_meanwhile_refuses_the_whole_save_in_its_own_sentence() {
        let d = device("stale-route", &FakeRelay::new(), &TestClock::new());
        let id = new_host_id().unwrap();
        let first = first_route(&id);
        edit_records(&d.env(), |s, now| create_host_with_route(s, &id, &HostScope::Local, &web("web"), false, Some(&first), now)).unwrap();
        let revision = revision_of(&record_runtime::snapshot(&d.env()).unwrap().0, &id);
        // The editor displayed a host without a route, but it has one now.
        let stale = first_route(&id);
        let error = edit_records(&d.env(), |s, now| update_host_with_route(s, &id, &revision, &web("renamed"), false, Some(&stale), now)).unwrap_err();
        assert_eq!(error.to_string(), "The host's route changed while you were editing; reload and try again.");
        let after = overview(&d.env()).unwrap();
        assert_eq!((after.hosts[0].payload.alias.as_str(), after.transports), ("web", vec![fixtures::iap(&id)]), "the host was not renamed either");
    }

    /// R18 and the room check: a library that refuses the route refuses the whole save, in a sentence.
    #[test]
    fn a_library_that_refuses_the_route_refuses_the_whole_save_in_a_sentence() {
        let mut paused = fixtures::in_central_mode(bare_state());
        paused.shared_writes_blocked = true;
        let error = create_host_with_route(&paused, HOST, &HostScope::Local, &web("web"), false, Some(&first_route(HOST)), 1).unwrap_err();
        assert_eq!(error.to_string(), PAUSED);
        let host = host_with(&paused, None);
        let error = update_host_with_route(&host, HOST, &revision_of(&host, HOST), &web("renamed"), false, Some(&first_route(HOST)), 2).unwrap_err();
        assert_eq!(error.to_string(), PAUSED);
        let full = fixtures::filled_past_the_limit_with_tunnels(fixtures::in_central_mode(bare_state()));
        let error = create_host_with_route(&full, HOST, &HostScope::Local, &web("web"), false, Some(&first_route(HOST)), 1).unwrap_err();
        assert_eq!(error.to_string(), transports::NO_ROOM);
    }

    #[test]
    fn deleting_a_host_removes_its_route() {
        // A route saved on this device goes with the host, and so does what grant requests taught this device about it.
        let route = RouteChange { expected: None, kind: Some(fixtures::with_pam(HOST).kind) };
        let base = host_with(&bare_state(), Some(&route));
        let remembered = transports::remember_grant_request(&base, HOST, "restart app-api", 1800, 2).unwrap();
        let deleted = delete_host_with_route(&remembered, HOST, &revision_of(&remembered, HOST), 3).unwrap();
        assert!(repo::get_host(&deleted, HOST).is_err());
        assert_eq!((transports::get(&deleted, HOST), transports::grant_memory(&deleted, HOST)), (None, None));
        assert!(transports::view(&deleted).is_empty());
        validate_state(&deleted).unwrap();
        // The library's route goes with it, as a row for the next capture to publish.
        let library = transports::set(&fixtures::central_with_host(HOST), HOST, None, Some(fixtures::with_pam(HOST)), 1).unwrap();
        assert!(transports::synced(&library, HOST));
        let deleted = delete_host_with_route(&library, HOST, &revision_of(&library, HOST), 2).unwrap();
        let row = &deleted.account.as_ref().unwrap().records[&record_key(RecordKind::Meta, &transports::wire_id(HOST))];
        assert!(row.dirty && row.record.deleted, "a tombstone for the next capture to publish");
        assert_eq!(transports::get(&deleted, HOST), None);
        validate_state(&deleted).unwrap();
        // Another host's route stays.
        let both = transports::set(&base, OTHER, None, Some(fixtures::iap(OTHER)), 2).unwrap();
        let deleted = delete_host_with_route(&both, HOST, &revision_of(&both, HOST), 3).unwrap();
        assert_eq!(transports::view(&deleted), vec![fixtures::iap(OTHER)]);
    }

    /// A host that has no route is deleted as it always was: no tombstone for a route that never was, and no state version for it.
    #[test]
    fn deleting_a_host_without_a_route_writes_nothing_for_a_route() {
        for base in [host_with(&bare_state(), None), fixtures::central_with_host(HOST)] {
            let revision = revision_of(&base, HOST);
            assert_eq!(delete_host_with_route(&base, HOST, &revision, 2).unwrap(), repo::delete_host(&base, HOST, &revision, 2).unwrap());
        }
    }

    /// The library's writes are paused, so the library's route cannot be removed, and the host then stays with it.
    #[test]
    fn deleting_a_host_whose_route_the_paused_library_keeps_refuses_the_whole_delete() {
        let mut library = transports::set(&fixtures::central_with_host(HOST), HOST, None, Some(fixtures::iap(HOST)), 1).unwrap();
        library.shared_writes_blocked = true;
        let error = delete_host_with_route(&library, HOST, &revision_of(&library, HOST), 2).unwrap_err();
        assert_eq!(error.to_string(), PAUSED);
    }

    /// R65: the overview says why a route of a central library stays on this computer only when the library has no room for it, as the
    /// publish step's walk finds. A route that waits for anything else, the step itself or paused writes, gives no reason.
    #[test]
    fn the_overview_gives_a_reason_only_for_a_route_the_library_has_no_room_for() {
        let entry = |reason| vec![TransportSyncView { host_id: HOST.into(), synced: false, reason }];
        let kept = fixtures::saved_on_this_device(&fixtures::central_with_host(HOST), &fixtures::iap(HOST));
        assert_eq!(overview_from(&kept, 1, None).unwrap().transport_sync, entry(None), "it fits: the publish step takes it");
        let mut paused = kept.clone();
        paused.shared_writes_blocked = true;
        assert_eq!(overview_from(&paused, 1, None).unwrap().transport_sync, entry(None));
        let full = fixtures::filled_short_of(kept, |catalog| catalog.transports.push(fixtures::iap(HOST)));
        let view = overview_from(&full, 1, None).unwrap();
        assert_eq!(view.transport_sync, entry(Some(TransportLocalReason::NoRoom)));
        assert_eq!(serde_json::to_value(&view).unwrap()["transport_sync"][0]["reason"], "no_room", "the shape the webview reads");
    }

    #[test]
    fn the_overview_reports_route_sync_and_grant_memory() {
        // HOST's route is the library's. OTHER's stays on this device, as one saved before the library used central sync is.
        let library = transports::set(&fixtures::central_with_host(HOST), HOST, None, Some(fixtures::with_pam(HOST)), 1).unwrap();
        let state = fixtures::saved_on_this_device(&library, &fixtures::iap(OTHER));
        let state = transports::remember_grant_request(&state, HOST, "restart app-api", 1800, 2).unwrap();
        let view = overview_from(&state, 1, None).unwrap();
        assert_eq!(view.transports, vec![fixtures::with_pam(HOST), fixtures::iap(OTHER)]);
        let entry = |host_id: &str, synced: bool| TransportSyncView { host_id: host_id.into(), synced, reason: None };
        assert_eq!(view.transport_sync, vec![entry(HOST, true), entry(OTHER, false)]);
        assert_eq!(view.grant_memory, vec![GrantMemoryView { host_id: HOST.into(), justification: "restart app-api".into(), duration_secs: 1800 }]);
        // The shape the webview reads.
        let json = serde_json::to_value(&view).unwrap();
        assert_eq!(
            json["transport_sync"],
            serde_json::json!([{"host_id": HOST, "synced": true, "reason": null}, {"host_id": OTHER, "synced": false, "reason": null}])
        );
        assert_eq!(json["grant_memory"], serde_json::json!([{"host_id": HOST, "justification": "restart app-api", "duration_secs": 1800}]));
        // Nothing saved, nothing reported.
        let none = overview_from(&bare_state(), 1, None).unwrap();
        assert!(none.transport_sync.is_empty() && none.grant_memory.is_empty());
    }
}

#[tauri::command]
pub async fn records_conflict_resolve(app: AppHandle, space_id: Option<String>, key: String, token: String, choice: crate::sync::record_conflicts::Resolution, copy_alias: Option<String>) -> Result<RecordOverview, AppError> {
    tauri::async_runtime::spawn_blocking(move || crate::sync::engine::with_env(&app, |env| crate::sync::record_conflicts::resolve_saved(env, space_id.as_deref(), &key, &token, choice, copy_alias.as_deref()))?)
        .await.map_err(crate::sync::engine::join_error)?
}
