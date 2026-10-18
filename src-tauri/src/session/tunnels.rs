//! Human-started port forwards. Definitions sync; running state is device-local.
use super::{
    auth::Owner,
    connect::{CancelToken, Connector},
    protocol::HostQuery,
};
use crate::{ssh::forward::ForwardStatus, state::AppState};
use serde::Serialize;
use std::{
    collections::BTreeMap,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc, Mutex,
    },
    time::Duration,
};
use tauri::Manager;

pub use crate::sync::tunnel_rules::TunnelRule;
#[derive(Clone, Debug, Default, Serialize)]
#[cfg_attr(test, derive(ts_rs::TS))]
#[cfg_attr(test, ts(export, export_to = "../../src/bindings/"))]
#[serde(rename_all = "snake_case")]
pub enum TunnelPhase {
    #[default]
    Stopped,
    Connecting,
    Running,
    Stopping,
    Error,
}
impl TunnelPhase {
    fn busy(&self) -> bool {
        matches!(self, Self::Connecting | Self::Running | Self::Stopping)
    }
}
#[derive(Clone, Debug, Default, Serialize)]
#[cfg_attr(test, derive(ts_rs::TS))]
#[cfg_attr(test, ts(export, export_to = "../../src/bindings/"))]
pub struct TunnelLive {
    pub phase: TunnelPhase,
    pub forwarding: ForwardStatus,
}
#[derive(Clone, Debug, Serialize)]
#[cfg_attr(test, derive(ts_rs::TS))]
#[cfg_attr(test, ts(export, export_to = "../../src/bindings/"))]
pub struct TunnelView {
    pub rule: TunnelRule,
    pub live: TunnelLive,
    pub synced: bool,
    pub blocked: bool,
    pub changed: bool,
    pub removed: bool,
}
struct Entry {
    rule: TunnelRule,
    account_id: Option<String>,
    cancel: CancelToken,
    live: Mutex<TunnelLive>,
}
#[derive(Default)]
pub struct Tunnels {
    edits: Mutex<()>,
    entries: Mutex<BTreeMap<String, Arc<Entry>>>,
    next: AtomicU64,
}
impl Tunnels {
    fn list(&self, state: &crate::sync::records_v3::SyncStateV3) -> Vec<TunnelView> {
        let saved = crate::sync::tunnel_rules::view(state);
        let mut entries = self.entries.lock().unwrap();
        entries.retain(|id, entry| {
            saved.iter().any(|row| &row.rule.id == id) || entry.live.lock().unwrap().phase.busy()
        });
        let mut views: Vec<_> = saved
            .into_iter()
            .map(|row| {
                let live = entries
                    .get(&row.rule.id)
                    .map(|e| e.live.lock().unwrap().clone())
                    .unwrap_or_default();
                let changed = live.phase.busy()
                    && entries
                        .get(&row.rule.id)
                        .is_some_and(|entry| entry.rule != row.rule);
                TunnelView {
                    rule: row.rule,
                    live,
                    synced: row.synced,
                    blocked: row.blocked,
                    changed,
                    removed: false,
                }
            })
            .collect();
        // A deletion elsewhere never hides a listener that still needs to be stopped here.
        for (id, entry) in entries.iter() {
            let live = entry.live.lock().unwrap().clone();
            if live.phase.busy() && !views.iter().any(|v| &v.rule.id == id) {
                views.push(TunnelView {
                    rule: entry.rule.clone(),
                    live,
                    synced: false,
                    blocked: true,
                    changed: false,
                    removed: true,
                });
            }
        }
        views.sort_by(|a, b| {
            a.rule
                .name
                .to_lowercase()
                .cmp(&b.rule.name.to_lowercase())
                .then_with(|| a.rule.id.cmp(&b.rule.id))
        });
        views
    }
    fn busy(&self, id: &str) -> bool {
        self.entries
            .lock()
            .unwrap()
            .get(id)
            .is_some_and(|entry| entry.live.lock().unwrap().phase.busy())
    }
    fn prepare(
        &self,
        state: &crate::sync::records_v3::SyncStateV3,
        expected: &TunnelRule,
        keys: Option<&crate::sync::crypto::ChainKeys>,
    ) -> Result<(TunnelRule, Arc<Entry>, u64), String> {
        let rule = crate::sync::tunnel_rules::view(state)
            .into_iter()
            .find(|r| r.rule.id == expected.id)
            .ok_or("The saved tunnel no longer exists.")?;
        if rule.blocked
            || &rule.rule != expected
            || crate::sync::tunnel_rules::blocked_by_opaque(
                state,
                keys,
                &crate::sync::tunnel_rules::wire_id(&expected.id),
            )
        {
            return Err("The tunnel changed or needs a sync review. Refresh and try again.".into());
        }
        let rule = rule.rule;
        let mut entries = self.entries.lock().unwrap();
        if entries
            .get(&rule.id)
            .is_some_and(|entry| entry.live.lock().unwrap().phase.busy())
        {
            return Err("This tunnel is already active.".into());
        }
        if entries
            .values()
            .filter(|entry| entry.live.lock().unwrap().phase.busy())
            .count()
            >= 16
        {
            return Err("Stop a tunnel before starting another (maximum 16).".into());
        }
        let entry = Arc::new(Entry {
            rule: rule.clone(),
            account_id: state.account.as_ref().map(|a| a.chain_id.clone()),
            cancel: CancelToken::default(),
            live: Mutex::new(TunnelLive {
                phase: TunnelPhase::Connecting,
                ..Default::default()
            }),
        });
        entries.insert(rule.id.clone(), Arc::clone(&entry));
        Ok((rule, entry, self.next.fetch_add(1, Ordering::Relaxed)))
    }
    fn stop(&self, id: &str) {
        if let Some(entry) = self.entries.lock().unwrap().get(id) {
            let mut live = entry.live.lock().unwrap();
            if live.phase.busy() {
                live.phase = TunnelPhase::Stopping;
                entry.cancel.cancel();
            }
        }
    }
}

fn run(
    rule: &TunnelRule,
    entry: &Entry,
    connector: &Connector<'_>,
    owner: &dyn Owner,
    account: &dyn Fn() -> Option<String>,
) -> Result<(), String> {
    let connected = connector
        .connect(&HostQuery::Id(rule.host_id.clone()), owner, &entry.cancel)
        .map_err(|e| e.text)?;
    if entry.cancel.is_cancelled() {
        connected.session.close();
        return Ok(());
    }
    let forwarding = match connected.session.forward(&rule.forward) {
        Ok(forwarding) => forwarding,
        Err(error) => {
            connected.session.close();
            return Err(error.to_string());
        }
    };
    let mut account_check = std::time::Instant::now();
    loop {
        if account_check.elapsed() >= Duration::from_secs(1) {
            if entry.account_id.is_some() && account() != entry.account_id {
                entry.cancel.cancel();
            }
            account_check = std::time::Instant::now();
        }
        let status = forwarding.status();
        {
            let mut live = entry.live.lock().unwrap();
            live.forwarding = status.clone();
            if !entry.cancel.is_cancelled() {
                live.phase = TunnelPhase::Running;
            }
        }
        if entry.cancel.is_cancelled() || !status.running || !connected.session.is_alive() {
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    forwarding.stop();
    let final_status = forwarding.status();
    connected.session.close();
    if entry.cancel.is_cancelled() {
        Ok(())
    } else {
        Err(final_status.error.unwrap_or_else(|| {
            "The SSH connection ended. Start the tunnel again to reconnect.".into()
        }))
    }
}
fn finish(entry: &Entry, result: Result<(), String>) {
    let mut live = entry.live.lock().unwrap();
    live.forwarding.running = false;
    live.forwarding.connections = 0;
    if entry.cancel.is_cancelled() || result.is_ok() {
        live.phase = TunnelPhase::Stopped;
    } else {
        live.phase = TunnelPhase::Error;
        live.forwarding.error = result
            .err()
            .map(|e| super::auth::printable(&e).chars().take(512).collect());
    }
}
fn main_only(window: &tauri::WebviewWindow) -> Result<(), String> {
    if window.label() == "main" {
        Ok(())
    } else {
        Err("Tunnel management is available in the main window only.".into())
    }
}
fn snapshot(app: &tauri::AppHandle) -> Result<crate::sync::records_v3::SyncStateV3, String> {
    crate::sync::engine::with_env(app, crate::sync::record_runtime::snapshot)
        .map_err(|e| e.to_string())?
        .map(|(state, _)| state)
        .map_err(|e| e.to_string())
}
#[tauri::command]
pub async fn tunnels_list(
    app: tauri::AppHandle,
    window: tauri::WebviewWindow,
) -> Result<Vec<TunnelView>, String> {
    main_only(&window)?;
    tauri::async_runtime::spawn_blocking(move || {
        Ok(app
            .state::<AppState>()
            .session
            .tunnels
            .list(&snapshot(&app)?))
    })
    .await
    .map_err(|e| e.to_string())?
}
fn edit(
    app: &tauri::AppHandle,
    id: &str,
    expected: Option<TunnelRule>,
    rule: Option<TunnelRule>,
) -> Result<(), String> {
    let state = app.state::<AppState>();
    let _edit = state.session.tunnels.edits.lock().unwrap();
    if state.session.tunnels.busy(id) {
        return Err("Stop the tunnel before editing or deleting it.".into());
    }
    crate::sync::engine::with_env(app, |env| {
        let keys = env.runtime.core.lock().unwrap().account_keys.clone();
        crate::sync::record_commands::edit_records(env, |state, now| {
            crate::sync::tunnel_rules::set(
                state,
                keys.as_ref(),
                id,
                expected.as_ref(),
                rule.clone(),
                now,
            )
            .map_err(|e| crate::error::AppError::Other(e.to_string()))
        })
    })
    .map_err(|e| e.to_string())?
    .map(|_| ())
    .map_err(|e| e.to_string())
}
#[tauri::command]
pub async fn tunnels_save(
    app: tauri::AppHandle,
    window: tauri::WebviewWindow,
    mut rule: TunnelRule,
    expected: Option<TunnelRule>,
) -> Result<(), String> {
    main_only(&window)?;
    if rule.id.is_empty() {
        let mut bytes = [0u8; 8];
        getrandom::fill(&mut bytes)
            .map_err(|_| "Could not create a tunnel identity.".to_string())?;
        rule.id = bytes.iter().map(|byte| format!("{byte:02x}")).collect();
    }
    tauri::async_runtime::spawn_blocking(move || edit(&app, &rule.id.clone(), expected, Some(rule)))
        .await
        .map_err(|e| e.to_string())?
}
#[tauri::command]
pub async fn tunnels_delete(
    app: tauri::AppHandle,
    window: tauri::WebviewWindow,
    expected: TunnelRule,
) -> Result<(), String> {
    main_only(&window)?;
    tauri::async_runtime::spawn_blocking(move || {
        edit(&app, &expected.id.clone(), Some(expected), None)
    })
    .await
    .map_err(|e| e.to_string())?
}
#[tauri::command]
pub async fn tunnels_start(
    app: tauri::AppHandle,
    window: tauri::WebviewWindow,
    expected: TunnelRule,
) -> Result<(), String> {
    main_only(&window)?;
    tauri::async_runtime::spawn_blocking(move || {
        super::app::start(&app);
        let (broker, rule, entry, generation) = {
            let state = app.state::<AppState>();
            if !matches!(
                *state.session.status.lock().unwrap(),
                super::app::BrokerStatus::Running
            ) {
                return Err(
                    "Could not start the SSH service. Quit other Lunport instances and try again."
                        .into(),
                );
            }
            let broker = state
                .session
                .broker
                .lock()
                .unwrap()
                .clone()
                .ok_or("The SSH service is unavailable.")?;
            let _edit = state.session.tunnels.edits.lock().unwrap();
            let (rule, entry, generation) = state.session.tunnels.prepare(
                &snapshot(&app)?,
                &expected,
                state.sync.core.lock().unwrap().account_keys.as_ref(),
            )?;
            (broker, rule, entry, generation)
        };
        let activity = match broker.register_tunnel(entry.cancel.clone()) {
            Ok(activity) => activity,
            Err(error) => {
                finish(&entry, Err(error.clone()));
                return Err(error);
            }
        };
        let worker_entry = Arc::clone(&entry);
        let spawned = std::thread::Builder::new()
            .name("lunport-tunnel".into())
            .spawn(move || {
                let result = (|| {
                    let owner = super::auth_window::NativeOwner {
                        hub: app.state::<AppState>().session.auth_questions.clone(),
                        surface: Arc::new(super::auth_window::TauriAuthSurface {
                            app: app.clone(),
                        }),
                        request_id: format!("tunnel-{}-{generation}", rule.id),
                        cancel: worker_entry.cancel.clone(),
                    };
                    run(&rule, &worker_entry, &broker.connector(), &owner, &|| {
                        app.state::<AppState>()
                            .sync
                            .core
                            .lock()
                            .unwrap()
                            .records
                            .as_ref()
                            .and_then(|s| s.account.as_ref().map(|a| a.chain_id.clone()))
                    })
                })();
                finish(&worker_entry, result);
                drop(activity);
            });
        if let Err(error) = spawned {
            finish(&entry, Err(error.to_string()));
            return Err("Could not start the tunnel worker.".into());
        }
        Ok(())
    })
    .await
    .map_err(|e| e.to_string())?
}
#[tauri::command]
pub fn tunnels_stop(
    app: tauri::AppHandle,
    window: tauri::WebviewWindow,
    id: String,
) -> Result<(), String> {
    main_only(&window)?;
    app.state::<AppState>().session.tunnels.stop(&id);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        ssh::forward::{ForwardKind, ForwardSpec},
        sync::{records_v3::SyncStateV3, tunnel_rules},
    };
    fn saved() -> (SyncStateV3, TunnelRule) {
        let state = serde_json::from_value(serde_json::json!({"version":4,"device_id":"dddddddddddddddddddddddddddddddd","device_name":"fixture","relay_url":"http://127.0.0.1","last_sync_ms":null,"last_error":null})).unwrap();
        let rule = TunnelRule {
            id: "0000000000000001".into(),
            host_id: "0000000000000002".into(),
            name: "Database".into(),
            forward: ForwardSpec {
                kind: ForwardKind::Local,
                bind_address: "127.0.0.1".into(),
                port: 0,
                target_host: "db.internal".into(),
                target_port: 5432,
            },
        };
        (
            tunnel_rules::set(&state, None, &rule.id, None, Some(rule.clone()), 10).unwrap(),
            rule,
        )
    }
    #[test]
    fn loaded_rules_never_start_on_another_device_and_stale_starts_are_rejected() {
        let (state, rule) = saved();
        let manager = Tunnels::default();
        assert!(matches!(
            manager.list(&state)[0].live.phase,
            TunnelPhase::Stopped
        ));
        assert!(!manager.busy(&rule.id));
        let mut changed = rule.clone();
        changed.name = "Changed elsewhere".into();
        let updated = tunnel_rules::set(
            &state,
            None,
            &rule.id,
            Some(&rule),
            Some(changed.clone()),
            11,
        )
        .unwrap();
        assert!(manager.prepare(&updated, &rule, None).is_err());
        manager.prepare(&updated, &changed, None).unwrap();
        assert!(manager.prepare(&updated, &changed, None).is_err());
        assert!(matches!(
            Tunnels::default().list(&updated)[0].live.phase,
            TunnelPhase::Stopped
        ));
    }
    #[test]
    fn remote_edits_do_not_mutate_a_running_listener_and_deletions_keep_stop_available() {
        let (state, rule) = saved();
        let manager = Tunnels::default();
        let (_, entry, _) = manager.prepare(&state, &rule, None).unwrap();
        entry.live.lock().unwrap().phase = TunnelPhase::Running;
        let mut changed = rule.clone();
        changed.forward.target_port = 5433;
        let updated = tunnel_rules::set(
            &state,
            None,
            &rule.id,
            Some(&rule),
            Some(changed.clone()),
            11,
        )
        .unwrap();
        assert!(manager.list(&updated)[0].changed);
        assert_eq!(entry.rule.forward.target_port, 5432);
        let deleted =
            tunnel_rules::set(&updated, None, &rule.id, Some(&changed), None, 12).unwrap();
        let rows = manager.list(&deleted);
        assert_eq!(rows.len(), 1);
        assert!(rows[0].removed);
        manager.stop(&rule.id);
        assert!(entry.cancel.is_cancelled());
        assert!(matches!(
            manager.list(&deleted)[0].live.phase,
            TunnelPhase::Stopping
        ));
        finish(&entry, Ok(()));
        assert!(manager.list(&deleted).is_empty());
    }
}
