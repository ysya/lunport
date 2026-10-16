//! Native public-record API. Credentials and private key text never enter overview DTOs.
use crate::error::AppError;
use crate::sync::env::SyncEnv;
use crate::sync::record_repository::{
    self as repo, HostReadiness, KeyAuthority, KeyStatus, RecordRevision,
};
use crate::sync::record_runtime::{self, RuntimeFormat};
use crate::sync::records_v3::{GroupPayload, HostPayload, HostScope, KeySlotPayload, SyncStateV3};
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
    fn revision(&self) -> Result<RecordRevision, AppError> {
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
#[derive(Clone, Debug, Serialize)]
pub struct RecordOverview {
    syncing: bool,
    generation: String,
    group_deletion_token: String,
    relay_url: String,
    hosts: Vec<HostView>,
    groups: Vec<GroupView>,
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
    Ok(RecordOverview {
        syncing: false,
        generation: generation.to_string(),
        group_deletion_token,
        relay_url: state.relay_url.clone(),
        hosts,
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
#[tauri::command]
pub async fn records_host_create(
    app: AppHandle,
    scope: HostScope,
    payload: HostPayload,
    upgrade_confirmed: Option<bool>,
) -> Result<RecordOverview, AppError> {
    let payload = new_host_payload(payload);
    let id = new_host_id()?;
    edit(app, move |s, now| {
        let scope = if scope == HostScope::Local {
            crate::sync::record_library::creation_scope(s).map_err(error)?
        } else {
            scope.clone()
        };
        let candidate = crate::sync::record_groups::promote_for_host(
            s,
            &scope,
            &payload,
            upgrade_confirmed.unwrap_or(false),
            now,
        )
        .map_err(error)?;
        repo::create_host(&candidate, &id, scope.clone(), payload.clone(), now).map_err(error)
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
) -> Result<RecordOverview, AppError> {
    let revision = revision.revision()?;
    edit(app, move |s, now| {
        crate::sync::record_library::update_host(
            s,
            &id,
            &revision,
            payload.clone(),
            upgrade_confirmed.unwrap_or(false),
            now,
        )
        .map_err(error)
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
    edit(app, move |s, now| {
        repo::delete_host(s, &id, &revision, now).map_err(error)
    })
    .await
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
    let normalized = crate::sync::relay::RelayClient::validate_url(&url)?;
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
) -> Result<RecordOverview, AppError> {
    let private = zeroize::Zeroizing::new(private_text);
    tauri::async_runtime::spawn_blocking(move || {
        crate::sync::engine::with_env(&app, |env| {
            crate::sync::record_keys::import_local(
                env,
                &name,
                private,
                crate::vault::store::EntryOrigin::Imported,
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
) -> Result<RecordOverview, AppError> {
    tauri::async_runtime::spawn_blocking(move || {
        crate::sync::engine::with_env(&app, |env| {
            crate::sync::record_keys::import_local_file(env, &name, std::path::Path::new(&path))?;
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
) -> Result<RecordOverview, AppError> {
    tauri::async_runtime::spawn_blocking(move || {
        crate::sync::engine::with_env(&app, |env| {
            crate::sync::record_keys::generate_local(
                env,
                &name,
                crate::vault::generate::KeyAlgorithm::Ed25519,
                &name,
                None,
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
    if !crate::session::record_material::matches(&key, &entry) {
        return Err(AppError::Other(
            "The vault key does not match its authoritative public identity.".into(),
        ));
    }
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
    use crate::sync::testkit::{TestClock, TestDevice};
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
}
