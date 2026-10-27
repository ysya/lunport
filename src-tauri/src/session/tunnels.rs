//! Human-started port forwards. Definitions sync; running state is device-local.
use super::{
    auth::Owner,
    connect::{CancelToken, Connector},
    protocol::HostQuery,
};
use crate::{
    gcp::iap::IapError,
    ssh::forward::ForwardStatus,
    state::AppState,
    sync::{
        records_v3::SyncStateV3,
        transports::{self, TransportKind},
    },
};
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

/// What a tunnel whose SSH connection ended says when nothing more specific is known.
const CONNECTION_ENDED: &str = "The SSH connection ended. Start the tunnel again to reconnect.";

/// What a tunnel says when IAP stopped it because the grant its first hop needs ended (design
/// 2026-10-26, Tunnels through a host that needs a grant).
pub(crate) const GRANT_ENDED: &str =
    "The Privileged Access Manager grant this tunnel needs has ended. Start the tunnel again to request a new one.";

/// Why a tunnel that was not stopped in Lunport ended. IAP refusing the first hop's account on a
/// route with a PAM check means its grant ended; every other ending keeps `fallback`. An IAP
/// refusal for another reason on such a route (access removed in Google Cloud) reads the same
/// (design 2026-10-26, call 14). The spec names two refusals, the relay's 4033 "not authorized"
/// close and a 403 handshake refusal; only the 4033 close reaches a running tunnel today, because
/// `iap::reconnect` retries a 403 until its budget runs out (R61). The 403 arm stays for the spec.
pub(crate) fn stop_reason(end: Option<&IapError>, needs_grant: bool, fallback: String) -> String {
    let refused = matches!(
        end,
        Some(IapError::Closed { code: 4033, .. } | IapError::Refused { status: 403 })
    );
    if refused && needs_grant {
        GRANT_ENDED.to_string()
    } else {
        fallback
    }
}

/// Whether `host_id`'s route has a Privileged Access Manager check.
fn route_needs_grant(state: &SyncStateV3, host_id: &str) -> bool {
    transports::get(state, host_id)
        .is_some_and(|route| matches!(route.kind, TransportKind::GcpIap { pam: Some(_), .. }))
}

/// Runs the tunnel until it is stopped or its connection ends. `account` reads the sync account's
/// id (a change stops the tunnel); `needs_grant` reads whether a host's route has a PAM check, and
/// is asked of the first hop only when the connection ended with its IAP tunnel, so any other
/// ending reads no route.
fn run(
    rule: &TunnelRule,
    entry: &Entry,
    connector: &Connector<'_>,
    owner: &dyn Owner,
    account: &dyn Fn() -> Option<String>,
    needs_grant: &dyn Fn(&str) -> bool,
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
    // Read before our own teardown, so that nothing the teardown does can change it.
    let tunnel_end = connected.session.tunnel_end();
    forwarding.stop();
    let final_status = forwarding.status();
    connected.session.close();
    if entry.cancel.is_cancelled() {
        Ok(())
    } else {
        let fallback = final_status
            .error
            .unwrap_or_else(|| CONNECTION_ENDED.into());
        // The first hop is the hop dialed first, the only one an IAP route applies to. Its route is
        // read only for an ended IAP tunnel: an ordinary ending takes no lock.
        let first_hop = connected.target.hops.first().map(|hop| hop.id.as_str());
        let first_hop_needs_grant = tunnel_end.is_some() && first_hop.is_some_and(needs_grant);
        Err(stop_reason(
            tunnel_end.as_ref(),
            first_hop_needs_grant,
            fallback,
        ))
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
                    run(
                        &rule,
                        &worker_entry,
                        &broker.connector(),
                        &owner,
                        &|| {
                            app.state::<AppState>()
                                .sync
                                .core
                                .lock()
                                .unwrap()
                                .records
                                .as_ref()
                                .and_then(|s| s.account.as_ref().map(|a| a.chain_id.clone()))
                        },
                        &|host_id| {
                            app.state::<AppState>()
                                .sync
                                .core
                                .lock()
                                .unwrap()
                                .records
                                .as_ref()
                                .is_some_and(|s| route_needs_grant(s, host_id))
                        },
                    )
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
        gcp::{auth::AuthError, iap::IapError},
        session::{
            grants::GrantGates,
            testing::{FakeConfirmer, FakeDirectory, FakeKeys, FakeOwner},
        },
        ssh::{
            fake::{default_server_key, FakeEngine},
            forward::{ForwardKind, ForwardSpec},
            AuthMethod, DisconnectKind, DisconnectReason, HopRef,
        },
        sync::{records_v3::SyncStateV3, testkit::MemKeychain, tunnel_rules},
    };
    use std::time::Instant;
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

    #[test]
    fn a_tunnel_stopped_by_an_ended_grant_says_so() {
        let refused = IapError::Closed {
            code: 4033,
            reason: "not authorized".into(),
        };
        assert_eq!(
            stop_reason(Some(&refused), true, "fallback".into()),
            GRANT_ENDED
        );
        assert_eq!(
            stop_reason(
                Some(&IapError::Refused { status: 403 }),
                true,
                "fallback".into()
            ),
            GRANT_ENDED
        );
        assert_eq!(
            stop_reason(Some(&refused), false, "fallback".into()),
            "fallback"
        );
        let backend = IapError::Closed {
            code: 4003,
            reason: "failed to connect to backend".into(),
        };
        assert_eq!(
            stop_reason(Some(&backend), true, "fallback".into()),
            "fallback"
        );
        assert_eq!(stop_reason(None, true, "fallback".into()), "fallback");
        // The spec's sentence, word for word.
        assert_eq!(GRANT_ENDED, "The Privileged Access Manager grant this tunnel needs has ended. Start the tunnel again to request a new one.");
    }

    /// Design 2026-10-26 (R27): only IAP refusing the first hop's account names the grant; every
    /// other way its tunnel ends keeps today's text, on a route with a PAM check too.
    #[test]
    fn every_other_end_of_the_iap_tunnel_keeps_todays_text() {
        let others = [
            IapError::Refused { status: 401 },
            IapError::Closed {
                code: 1000,
                reason: "bye".into(),
            },
            IapError::Credentials(AuthError::SignInExpired {
                account: "ops@example.com".into(),
            }),
            IapError::Protocol("the relay sent a text message".into()),
            IapError::Io("connection reset by peer".into()),
            IapError::ReconnectExhausted,
        ];
        for end in &others {
            assert_eq!(
                stop_reason(Some(end), true, "fallback".into()),
                "fallback",
                "{end:?}"
            );
        }
    }

    /// IAP's close when it stops authorizing the account: what a running tunnel sees when its
    /// grant ends.
    fn not_authorized() -> IapError {
        IapError::Closed {
            code: 4033,
            reason: "not authorized".into(),
        }
    }

    fn key() -> AuthMethod {
        AuthMethod::Key {
            key_id: "k-plain".into(),
        }
    }

    /// `run` for a tunnel to `host` (a host of `directory`, every key of the chain pinned, so
    /// nobody is asked anything) over the fake engine: once the tunnel runs, `once_running` ends it
    /// the way the test needs, and this hands back what `run` returned. `needs_grant` answers for
    /// the route of the hop it is asked about.
    fn run_until(
        directory: &FakeDirectory,
        host: &str,
        needs_grant: &dyn Fn(&str) -> bool,
        once_running: &(dyn Fn(&FakeEngine, &Entry) + Sync),
    ) -> Result<(), String> {
        let engine = FakeEngine::new();
        let (keys, keychain, confirmer, grants) = (
            FakeKeys::new(),
            MemKeychain::default(),
            FakeConfirmer::default(),
            GrantGates::default(),
        );
        let connector = Connector {
            engine: &engine,
            directory,
            keys: &keys,
            keychain: &keychain,
            confirmer: &confirmer,
            grants: &grants,
        };
        let rule = TunnelRule {
            host_id: format!("id-{host}"),
            ..saved().1
        };
        let entry = Entry {
            rule: rule.clone(),
            account_id: None,
            cancel: CancelToken::default(),
            live: Mutex::new(TunnelLive {
                phase: TunnelPhase::Connecting,
                ..Default::default()
            }),
        };
        std::thread::scope(|scope| {
            scope.spawn(|| {
                // Bounded, and `once_running` is called whatever happened, so that `run` returns
                // and the scope with it.
                let deadline = Instant::now() + Duration::from_secs(10);
                while !matches!(entry.live.lock().unwrap().phase, TunnelPhase::Running)
                    && Instant::now() < deadline
                {
                    std::thread::sleep(Duration::from_millis(5));
                }
                once_running(&engine, &entry);
            });
            run(
                &rule,
                &entry,
                &connector,
                &FakeOwner::default(),
                &|| None,
                needs_grant,
            )
        })
    }

    /// Design 2026-10-26, Tunnels through a host that needs a grant: a running tunnel that IAP
    /// stops with its 4033 "not authorized" close says that its grant ended when the first hop's
    /// route has a PAM check, which is asked of that hop (the tunnel's host here). Without a PAM
    /// check, for another close, and for a connection lost another way, it keeps today's text; a
    /// connection that ended without its IAP tunnel ending does not even read the route.
    #[test]
    fn a_running_tunnel_that_iap_stops_says_why() {
        let directory = FakeDirectory::new()
            .with_host("db", key())
            .with_pin("db", default_server_key());
        let asked = Mutex::new(Vec::new());
        let needs_grant = |host: &str| {
            asked.lock().unwrap().push(host.to_string());
            true
        };
        let refused = |engine: &FakeEngine, _: &Entry| engine.end_tunnel_now(not_authorized());
        assert_eq!(
            run_until(&directory, "db", &needs_grant, &refused),
            Err(GRANT_ENDED.to_string())
        );
        assert_eq!(*asked.lock().unwrap(), ["id-db"]);

        assert_eq!(
            run_until(&directory, "db", &|_| false, &refused),
            Err(CONNECTION_ENDED.to_string())
        );
        let unreachable = |engine: &FakeEngine, _: &Entry| {
            engine.end_tunnel_now(IapError::Closed {
                code: 4003,
                reason: "failed to connect to backend".into(),
            })
        };
        assert_eq!(
            run_until(&directory, "db", &|_| true, &unreachable),
            Err(CONNECTION_ENDED.to_string())
        );
        let lost = |engine: &FakeEngine, _: &Entry| {
            let hop = HopRef {
                id: "id-db".into(),
                alias: "db".into(),
                hostname: "db.example.com".into(),
                port: 22,
                user: "deploy".into(),
            };
            engine.disconnect_now(DisconnectReason {
                hop,
                kind: DisconnectKind::ConnectionLost,
                detail: "connection reset by peer".into(),
            })
        };
        assert_eq!(
            run_until(&directory, "db", &needs_grant, &lost),
            Err(CONNECTION_ENDED.to_string())
        );
        assert_eq!(
            *asked.lock().unwrap(),
            ["id-db"],
            "an ending without a tunnel end reads no route"
        );
    }

    /// `needs_grant`'s answer in the app: a route with a PAM check needs a grant; a route without
    /// one and a host without a route need none.
    #[test]
    fn only_a_route_with_a_pam_check_needs_a_grant() {
        let (pam_host, plain_host, bare_host) =
            ("0000000000000003", "0000000000000004", "0000000000000005");
        let routes = [
            (pam_host, transports::tests::with_pam(pam_host)),
            (plain_host, transports::tests::iap(plain_host)),
        ];
        let state = routes.into_iter().fold(saved().0, |state, (host, route)| {
            transports::set(&state, host, None, Some(route), 11).unwrap()
        });
        assert!(route_needs_grant(&state, pam_host));
        assert!(!route_needs_grant(&state, plain_host));
        assert!(!route_needs_grant(&state, bare_host));
    }

    /// Behind a jump host the first hop is the jump host, the only hop an IAP route applies to: its
    /// route decides, not the tunnel's host's.
    #[test]
    fn the_grant_of_a_tunnel_behind_a_jump_host_is_the_jump_hosts() {
        let directory = FakeDirectory::new()
            .with_host("bastion", key())
            .with_host_via("db", key(), &["bastion"])
            .with_pin("bastion", default_server_key())
            .with_pin("db", default_server_key());
        let refused = |engine: &FakeEngine, _: &Entry| engine.end_tunnel_now(not_authorized());
        assert_eq!(
            run_until(&directory, "db", &|host| host == "id-bastion", &refused),
            Err(GRANT_ENDED.to_string())
        );
        assert_eq!(
            run_until(&directory, "db", &|host| host == "id-db", &refused),
            Err(CONNECTION_ENDED.to_string())
        );
    }

    /// A tunnel stopped in Lunport stops without an error, whatever IAP does meanwhile.
    #[test]
    fn a_tunnel_stopped_in_lunport_has_no_stop_reason() {
        let directory = FakeDirectory::new()
            .with_host("db", key())
            .with_pin("db", default_server_key());
        let stopped = |engine: &FakeEngine, entry: &Entry| {
            entry.cancel.cancel();
            engine.end_tunnel_now(not_authorized());
        };
        assert_eq!(run_until(&directory, "db", &|_| true, &stopped), Ok(()));
    }
}
