//! Port forwards started in Lunport, or by an AI client through MCP (design 2026-11-08). Definitions sync; running state is device-local.
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
    /// Connecting, running or stopping: the tunnel holds a connection or a listener here.
    pub(crate) fn busy(&self) -> bool {
        matches!(self, Self::Connecting | Self::Running | Self::Stopping)
    }
}
#[derive(Clone, Debug, Default, Serialize)]
#[cfg_attr(test, derive(ts_rs::TS))]
#[cfg_attr(test, ts(export, export_to = "../../src/bindings/"))]
pub struct TunnelLive {
    pub phase: TunnelPhase,
    pub forwarding: ForwardStatus,
    /// Who started the tunnel when an AI client started it through MCP (design 2026-11-08): the requester Lunport observed. `None`
    /// for a tunnel started in Lunport.
    #[cfg_attr(test, ts(optional = nullable))]
    pub started_by: Option<String>,
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
/// One tunnel that was started here: the rule it runs, and its live state.
pub(crate) struct Entry {
    rule: TunnelRule,
    account_id: Option<String>,
    cancel: CancelToken,
    live: Mutex<TunnelLive>,
    /// Why Lunport itself stopped the tunnel, when it did for a reason of its own (an AI client's access ended): its error then.
    ended_for: Mutex<Option<String>>,
    /// How many of Lunport's windows its connection has open for the person (design 2026-11-09, native windows for AI requests):
    /// `start_tunnel` keeps waiting while one is.
    asking: std::sync::atomic::AtomicUsize,
}
impl Entry {
    /// Whether its connection has one of Lunport's windows open for the person now.
    pub(crate) fn asking(&self) -> bool {
        self.asking.load(Ordering::SeqCst) > 0
    }
    /// `ask`, counted as a window its connection has open for as long as it runs.
    pub(crate) fn while_asking<T>(&self, ask: impl FnOnce() -> T) -> T {
        struct Answered<'a>(&'a std::sync::atomic::AtomicUsize);
        impl Drop for Answered<'_> {
            fn drop(&mut self) {
                self.0.fetch_sub(1, Ordering::SeqCst);
            }
        }
        self.asking.fetch_add(1, Ordering::SeqCst);
        let _answered = Answered(&self.asking);
        ask()
    }
    /// Its live state now.
    pub(crate) fn live(&self) -> TunnelLive {
        self.live.lock().unwrap().clone()
    }
    /// Stops it, as its Stop button does.
    pub(crate) fn stop(&self) {
        let mut live = self.live.lock().unwrap();
        if live.phase.busy() {
            live.phase = TunnelPhase::Stopping;
            self.cancel.cancel();
        }
    }
    /// Stops it for a reason of Lunport's own, which it then shows as its error, whether it was running or still connecting.
    pub(crate) fn stop_because(&self, reason: String) {
        *self.ended_for.lock().unwrap() = Some(reason);
        self.stop();
    }
}

#[cfg(test)]
impl Entry {
    /// Stands the tunnel in a state of its own without running it, for tests outside this module.
    pub(crate) fn set_live(&self, live: TunnelLive) {
        *self.live.lock().unwrap() = live;
    }
}

/// What an edit or a delete of a running tunnel is refused with, in the panel and through MCP.
pub(crate) const STOP_FIRST: &str = "Stop the tunnel before editing or deleting it.";
#[derive(Default)]
pub struct Tunnels {
    edits: Mutex<()>,
    entries: Mutex<BTreeMap<String, Arc<Entry>>>,
    next: AtomicU64,
}
impl Tunnels {
    pub(crate) fn list(&self, state: &crate::sync::records_v3::SyncStateV3) -> Vec<TunnelView> {
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
    pub(crate) fn busy(&self, id: &str) -> bool {
        self.entries
            .lock()
            .unwrap()
            .get(id)
            .is_some_and(|entry| entry.live.lock().unwrap().phase.busy())
    }
    /// Runs `save` under the edit lock, unless the tunnel `id` is active here: a running tunnel is not edited or deleted.
    pub(crate) fn edit<T>(&self, id: &str, save: impl FnOnce() -> Result<T, String>) -> Result<T, String> {
        let _edit = self.edits.lock().unwrap();
        if self.busy(id) {
            return Err(STOP_FIRST.into());
        }
        save()
    }
    /// The entry of `expected`, which must be the saved rule as it is now, ready to start: refused when the rule changed, needs a sync
    /// review or runs already, or when 16 tunnels run. `started_by` names the AI client that starts it, if one does.
    pub(crate) fn prepare(
        &self,
        state: &crate::sync::records_v3::SyncStateV3,
        expected: &TunnelRule,
        keys: Option<&crate::sync::crypto::ChainKeys>,
        started_by: Option<String>,
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
                started_by,
                ..Default::default()
            }),
            ended_for: Mutex::new(None),
            asking: Default::default(),
        });
        entries.insert(rule.id.clone(), Arc::clone(&entry));
        Ok((rule, entry, self.next.fetch_add(1, Ordering::Relaxed)))
    }
    pub(crate) fn stop(&self, id: &str) {
        if let Some(entry) = self.entries.lock().unwrap().get(id) {
            entry.stop();
        }
    }
    /// The entry of the tunnel `id` started here, if it was.
    pub(crate) fn entry(&self, id: &str) -> Option<Arc<Entry>> {
        self.entries.lock().unwrap().get(id).cloned()
    }
    /// How many tunnels are active here (connecting, running or stopping); `prepare` allows 16.
    pub(crate) fn active_count(&self) -> usize {
        self.entries.lock().unwrap().values().filter(|entry| entry.live.lock().unwrap().phase.busy()).count()
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

/// What may end a running tunnel besides its Stop and its connection. An AI client's start (design 2026-11-08) adds the last two.
pub(crate) struct Watch<'a> {
    /// The sync account's id now: a change stops the tunnel.
    pub account: &'a dyn Fn() -> Option<String>,
    /// Whether a host's route has a PAM check. It is asked of the first hop only when the connection ended with its IAP tunnel, so any
    /// other ending reads no route.
    pub needs_grant: &'a dyn Fn(&str) -> bool,
    /// Checked once connected, before anything is forwarded: an AI client's start holds the connection to the route and keys it was
    /// approved for.
    pub connected: &'a dyn Fn(&crate::ssh::Target) -> Result<(), String>,
}

impl Watch<'_> {
    /// What a tunnel started in Lunport watches: the account and the grant, nothing an AI client's start adds.
    pub(crate) fn of_a_person<'a>(account: &'a dyn Fn() -> Option<String>, needs_grant: &'a dyn Fn(&str) -> bool) -> Watch<'a> {
        Watch { account, needs_grant, connected: &|_| Ok(()) }
    }
}

/// What a tunnel an AI client started says when Lunport stopped it because the client's access to its host ended (design 2026-11-08).
pub(crate) const AI_ACCESS_ENDED: &str =
    "AI access to this tunnel's host ended, so Lunport stopped the tunnel the AI client started.";

/// Runs the tunnel until it is stopped or its connection ends, or until `watch` ends it.
fn run(
    rule: &TunnelRule,
    entry: &Entry,
    connector: &Connector<'_>,
    owner: &dyn Owner,
    watch: &Watch<'_>,
) -> Result<(), String> {
    let connected = connector
        .connect(&HostQuery::Id(rule.host_id.clone()), owner, &entry.cancel)
        .map_err(|e| e.text)?;
    if entry.cancel.is_cancelled() {
        connected.session.close();
        return Ok(());
    }
    if let Err(error) = (watch.connected)(&connected.target) {
        connected.session.close();
        return Err(error);
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
            if entry.account_id.is_some() && (watch.account)() != entry.account_id {
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
        let first_hop_needs_grant = tunnel_end.is_some() && first_hop.is_some_and(watch.needs_grant);
        Err(stop_reason(
            tunnel_end.as_ref(),
            first_hop_needs_grant,
            fallback,
        ))
    }
}

/// What an AI client's start was approved for (design 2026-11-08), for `run_for_ai`.
pub(crate) struct AiApproval<'a> {
    /// The destination, route and keys the start was approved for, captured as `ssh_exec` captures them.
    pub approved: &'a crate::mcp::records::ApprovedTarget,
    /// Who asks in the windows the tunnel's connection opens (design 2026-11-09, native windows for AI requests).
    pub asker: crate::session::protocol::AiAsker,
    /// The policy as it is now still allows the start: AI access on, the mode it was approved in, the host permitted.
    pub allowed: &'a (dyn Fn() -> Result<(), String> + Sync),
    /// Why the tunnel must stop now, if it must: the client's AI access ended. Asked every `REVOCATION_POLL` while it connects or runs.
    pub revoked: &'a (dyn Fn() -> Option<String> + Sync),
}

/// How often an AI client's tunnel asks whether the client's access ended.
const REVOCATION_POLL: Duration = Duration::from_millis(250);

/// Runs `rule` for an AI client (design 2026-11-08) over `base` guarded as `ssh_exec` guards its connection: it connects only to the
/// approved route with the approved keys while the policy still allows it, and asks what `ssh_exec` asks in Lunport's windows, naming
/// the client (design 2026-11-09, native windows for AI requests): a new or changed server key, credentials, a Privileged Access Manager
/// grant. The windows count on the entry while they wait for the person. When `ai.revoked` says the client's access ended, the tunnel
/// stops with that reason, while it still connects too, which withdraws the windows its connection opened.
pub(crate) fn run_for_ai(
    rule: &TunnelRule,
    entry: &Entry,
    base: &Connector<'_>,
    owner: &dyn Owner,
    ai: &AiApproval<'_>,
    account: &dyn Fn() -> Option<String>,
    needs_grant: &dyn Fn(&str) -> bool,
) -> Result<(), String> {
    use crate::mcp::records::{CheckedEngine, ClientConfirmer, PublicDirectory};
    let query = HostQuery::Id(rule.host_id.clone());
    let check = || -> Result<(), String> {
        if entry.cancel.is_cancelled() {
            return Err("The tunnel was stopped.".into());
        }
        (ai.allowed)()?;
        ai.approved.check(base, &query)
    };
    let check_resolved = |target: &crate::ssh::Target| ai.approved.check_resolved(target, base.keys);
    let check_connected = |target: &crate::ssh::Target| {
        check()?;
        ai.approved.check_connected(target, base.keys)
    };
    let engine = CheckedEngine { inner: base.engine, check: &check_connected };
    let directory = PublicDirectory(base.directory, &check, &check_resolved);
    // The windows the connection opens count on the entry while they wait for the person (design 2026-11-09): `start_tunnel` waits for
    // the person instead of answering that the tunnel is still connecting.
    let window = CountedWindow { inner: base.confirmer, entry };
    let owner = CountedOwner { inner: owner, entry };
    let confirmer = ClientConfirmer::new(&window, ai.asker.clone());
    let guarded = Connector {
        engine: &engine,
        directory: &directory,
        keys: base.keys,
        keychain: base.keychain,
        confirmer: &confirmer,
        grants: base.grants,
    };
    let watch = Watch { account, needs_grant, connected: &check_connected };
    struct Done<'a>(&'a std::sync::atomic::AtomicBool);
    impl Drop for Done<'_> {
        fn drop(&mut self) {
            self.0.store(true, Ordering::SeqCst);
        }
    }
    let done = std::sync::atomic::AtomicBool::new(false);
    let result = std::thread::scope(|scope| {
        scope.spawn(|| {
            let mut next = std::time::Instant::now();
            while !done.load(Ordering::SeqCst) && !entry.cancel.is_cancelled() {
                if std::time::Instant::now() >= next {
                    if let Some(reason) = (ai.revoked)() {
                        entry.stop_because(reason);
                        break;
                    }
                    next = std::time::Instant::now() + REVOCATION_POLL;
                }
                std::thread::sleep(Duration::from_millis(25));
            }
        });
        let _done = Done(&done);
        run(rule, entry, &guarded, &owner, &watch)
    });
    // `start_tunnel` passes a "needs interaction:" answer on as it is and prefixes the others with "The tunnel could not start".
    result.map_err(|error| confirmer.answer(None).unwrap_or(error))
}
/// The owner of an AI client's tunnel, counted on its entry while it asks the person (design 2026-11-09, native windows for AI requests).
struct CountedOwner<'a> {
    inner: &'a dyn Owner,
    entry: &'a Entry,
}
impl Owner for CountedOwner<'_> {
    fn ask(&self, kind: super::protocol::QuestionKind, text: &str, echo: bool, deadline: Option<std::time::Instant>) -> super::auth::Reply {
        self.entry.while_asking(|| self.inner.ask(kind, text, echo, deadline))
    }
    fn ask_at(
        &self,
        hop: &crate::ssh::HopRef,
        kind: super::protocol::QuestionKind,
        text: &str,
        echo: bool,
        deadline: Option<std::time::Instant>,
    ) -> super::auth::Reply {
        self.entry.while_asking(|| self.inner.ask_at(hop, kind, text, echo, deadline))
    }
    fn host_key_notice(&self, text: &str) {
        self.inner.host_key_notice(text)
    }
    fn banner(&self, text: &str) {
        self.inner.banner(text)
    }
}

/// The host key window of an AI client's tunnel, counted on its entry while it asks the person.
struct CountedWindow<'a> {
    inner: &'a dyn super::connect::HostKeyConfirmer,
    entry: &'a Entry,
}
impl super::connect::HostKeyConfirmer for CountedWindow<'_> {
    fn confirm(&self, question: &super::connect::HostKeyQuestion, cancel: &CancelToken) -> Option<String> {
        self.entry.while_asking(|| self.inner.confirm(question, cancel))
    }
    fn decide(&self, question: &super::connect::HostKeyQuestion, cancel: &CancelToken) -> super::connect::HostKeyDecision {
        self.entry.while_asking(|| self.inner.decide(question, cancel))
    }
}

fn finish(entry: &Entry, result: Result<(), String>) {
    // A reason of Lunport's own (an AI client's access ended) is the tunnel's error, however its run ended.
    let ended_for = entry.ended_for.lock().unwrap().take();
    let mut live = entry.live.lock().unwrap();
    live.forwarding.running = false;
    live.forwarding.connections = 0;
    let error = match (ended_for, result) {
        (Some(reason), _) => Some(reason),
        (None, _) if entry.cancel.is_cancelled() => None,
        (None, result) => result.err(),
    };
    match error {
        None => live.phase = TunnelPhase::Stopped,
        Some(error) => {
            live.phase = TunnelPhase::Error;
            live.forwarding.error = Some(super::auth::printable(&error).chars().take(512).collect());
        }
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
    state.session.tunnels.edit(id, || {
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
    })
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
/// What runs a started tunnel on its worker thread: the rule and its entry, the broker's connector, the person's native windows as the
/// owner, and what `Watch` reads of the app (the sync account, a host's PAM check).
pub(crate) type Work = Box<
    dyn FnOnce(&TunnelRule, &Entry, &Connector<'_>, &dyn Owner, &dyn Fn() -> Option<String>, &dyn Fn(&str) -> bool) -> Result<(), String>
        + Send,
>;

/// Starts the saved tunnel `expected` on a worker thread of its own, registered with the broker so that quitting stops it, and answers
/// its entry: the panel's Start, and an AI client's (design 2026-11-08), which names the client in `ai` (who started it, and who asks in
/// the windows its connection opens, design 2026-11-09) and guards the connection in `work`.
pub(crate) fn launch(app: &tauri::AppHandle, expected: &TunnelRule, ai: Option<crate::session::protocol::AiAsker>, work: Work) -> Result<Arc<Entry>, String> {
    // The credential window names the request: an AI client's tunnel says so.
    let request = if ai.is_some() { "mcp-tunnel" } else { "tunnel" };
    let started_by = ai.as_ref().map(|asker| asker.client.clone());
    super::app::start(app);
    let (broker, rule, entry, generation) = {
        let state = app.state::<AppState>();
        if !matches!(*state.session.status.lock().unwrap(), super::app::BrokerStatus::Running) {
            return Err("Could not start the SSH service. Quit other Lunport instances and try again.".into());
        }
        let broker = state.session.broker.lock().unwrap().clone().ok_or("The SSH service is unavailable.")?;
        let _edit = state.session.tunnels.edits.lock().unwrap();
        let (rule, entry, generation) =
            state.session.tunnels.prepare(&snapshot(app)?, expected, state.sync.core.lock().unwrap().account_keys.as_ref(), started_by)?;
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
    let app = app.clone();
    let spawned = std::thread::Builder::new().name(crate::identity::thread_name("tunnel")).spawn(move || {
        let owner = super::auth_window::NativeOwner {
            ai,
            hub: app.state::<AppState>().session.auth_questions.clone(),
            surface: Arc::new(super::auth_window::TauriAuthSurface { app: app.clone() }),
            request_id: format!("{request}-{}-{generation}", rule.id),
            cancel: worker_entry.cancel.clone(),
        };
        let account = || {
            app.state::<AppState>().sync.core.lock().unwrap().records.as_ref().and_then(|s| s.account.as_ref().map(|a| a.chain_id.clone()))
        };
        let needs_grant = |host_id: &str| {
            app.state::<AppState>().sync.core.lock().unwrap().records.as_ref().is_some_and(|s| route_needs_grant(s, host_id))
        };
        let result = work(&rule, &worker_entry, &broker.connector(), &owner, &account, &needs_grant);
        finish(&worker_entry, result);
        drop(activity);
    });
    if let Err(error) = spawned {
        finish(&entry, Err(error.to_string()));
        return Err("Could not start the tunnel worker.".into());
    }
    Ok(entry)
}
#[tauri::command]
pub async fn tunnels_start(
    app: tauri::AppHandle,
    window: tauri::WebviewWindow,
    expected: TunnelRule,
) -> Result<(), String> {
    main_only(&window)?;
    tauri::async_runtime::spawn_blocking(move || {
        let work: Work = Box::new(|rule, entry, connector, owner, account, needs_grant| {
            run(rule, entry, connector, owner, &Watch::of_a_person(account, needs_grant))
        });
        launch(&app, &expected, None, work).map(|_| ())
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
        assert!(manager.prepare(&updated, &rule, None, None).is_err());
        manager.prepare(&updated, &changed, None, None).unwrap();
        assert!(manager.prepare(&updated, &changed, None, None).is_err());
        assert!(matches!(
            Tunnels::default().list(&updated)[0].live.phase,
            TunnelPhase::Stopped
        ));
    }
    #[test]
    fn remote_edits_do_not_mutate_a_running_listener_and_deletions_keep_stop_available() {
        let (state, rule) = saved();
        let manager = Tunnels::default();
        let (_, entry, _) = manager.prepare(&state, &rule, None, None).unwrap();
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
            ended_for: Mutex::new(None),
            asking: Default::default(),
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
                &Watch::of_a_person(&|| None, needs_grant),
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

    // ---- An AI client's tunnel (design 2026-11-08) ----

    /// What a run of an AI client's tunnel came to: what `run_for_ai` returned, the tunnel as the worker left it (`finish`), whether it
    /// ran, and the engine, for its events.
    struct AiRun {
        result: Result<(), String>,
        live: TunnelLive,
        ran: bool,
        engine: FakeEngine,
    }

    /// `run_for_ai` for a tunnel to `host`, approved for the route `approved_from` resolves for it, over the fake engine and `directory`
    /// (which may differ from what was approved), then `finish` as the worker does. Once the tunnel runs, `once_running` acts; it must
    /// end the tunnel or make `revoked` end it, and must not panic (a panic there would leave `run_for_ai` running and the scope waiting).
    #[allow(clippy::too_many_arguments)]
    fn run_ai_until(
        directory: &FakeDirectory,
        approved_from: &FakeDirectory,
        host: &str,
        auto_log: bool,
        confirmer: &FakeConfirmer,
        allowed: &(dyn Fn() -> Result<(), String> + Sync),
        revoked: &(dyn Fn() -> Option<String> + Sync),
        once_running: &(dyn Fn(&Entry) + Sync),
    ) -> AiRun {
        let engine = FakeEngine::new();
        let (keys, keychain, grants) = (FakeKeys::new(), MemKeychain::default(), GrantGates::default());
        let connector = Connector { engine: &engine, directory, keys: &keys, keychain: &keychain, confirmer, grants: &grants };
        let query = HostQuery::Id(format!("id-{host}"));
        let approved = crate::mcp::records::ApprovedTarget::capture(
            &crate::session::directory::HostDirectory::resolve_public(approved_from, &query).unwrap(),
            &keys,
        )
        .unwrap();
        let rule = TunnelRule { host_id: format!("id-{host}"), ..saved().1 };
        let entry = Entry {
            rule: rule.clone(),
            account_id: None,
            cancel: CancelToken::default(),
            live: Mutex::new(TunnelLive { phase: TunnelPhase::Connecting, started_by: Some("Claude".into()), ..Default::default() }),
            ended_for: Mutex::new(None),
            asking: Default::default(),
        };
        let ai = AiApproval { approved: &approved, asker: claude(auto_log), allowed, revoked };
        let ran = std::sync::atomic::AtomicBool::new(false);
        let result = std::thread::scope(|scope| {
            let watcher = scope.spawn(|| {
                let deadline = Instant::now() + Duration::from_secs(10);
                while matches!(entry.live.lock().unwrap().phase, TunnelPhase::Connecting) && Instant::now() < deadline {
                    std::thread::sleep(Duration::from_millis(5));
                }
                if matches!(entry.live.lock().unwrap().phase, TunnelPhase::Running) {
                    ran.store(true, Ordering::SeqCst);
                    once_running(&entry);
                }
            });
            let result = run_for_ai(&rule, &entry, &connector, &FakeOwner::default(), &ai, &|| None, &|_| false);
            // The worker's ending, as `launch` does it; it also lets the watcher go when the tunnel never ran.
            finish(&entry, result.clone());
            watcher.join().unwrap();
            result
        });
        AiRun { result, live: entry.live(), ran: ran.load(Ordering::SeqCst), engine }
    }

    fn pinned_db() -> FakeDirectory {
        FakeDirectory::new().with_host("db", key()).with_pin("db", default_server_key())
    }

    /// The AI client the tests' tunnels were started by, in Auto-log or Ask mode.
    fn claude(auto_log: bool) -> crate::session::protocol::AiAsker {
        crate::session::protocol::AiAsker {
            client: "Claude".into(),
            unreviewed: auto_log.then_some(crate::session::protocol::Unreviewed::Tunnel),
        }
    }

    /// A run that must not get as far as forwarding: if it does, it is stopped at once and the test sees `ran`.
    fn stop_it(entry: &Entry) {
        entry.stop();
    }

    /// The tunnel runs as approved; when the client's AI access ends it stops, and the panel says why.
    #[test]
    fn an_ai_clients_tunnel_stops_when_its_access_ends_and_says_why() {
        let ended = std::sync::atomic::AtomicBool::new(false);
        let revoked = || ended.load(Ordering::SeqCst).then(|| AI_ACCESS_ENDED.to_string());
        let run = run_ai_until(&pinned_db(), &pinned_db(), "db", true, &FakeConfirmer::default(), &|| Ok(()), &revoked, &|_| ended.store(true, Ordering::SeqCst));
        assert!(run.ran, "it ran");
        assert_eq!(run.result, Ok(()), "Lunport stopped it");
        assert!(matches!(run.live.phase, TunnelPhase::Error), "{:?}", run.live.phase);
        assert_eq!(run.live.forwarding.error.as_deref(), Some(AI_ACCESS_ENDED));
        assert!(!run.live.forwarding.running);
    }

    /// Stopped by the client or the person, it ends without an error.
    #[test]
    fn an_ai_clients_tunnel_stopped_in_lunport_has_no_error() {
        let run = run_ai_until(&pinned_db(), &pinned_db(), "db", true, &FakeConfirmer::default(), &|| Ok(()), &|| None, &stop_it);
        assert!(run.ran);
        assert_eq!(run.result, Ok(()));
        assert!(matches!(run.live.phase, TunnelPhase::Stopped), "{:?}", run.live.phase);
        assert_eq!(run.live.forwarding.error, None);
    }

    /// The route changed after the approval (the host now goes through a jump host): nothing connects.
    #[test]
    fn an_ai_clients_tunnel_connects_only_to_the_route_it_was_approved_for() {
        let now = FakeDirectory::new()
            .with_host("bastion", key())
            .with_host_via("db", key(), &["bastion"])
            .with_pin("bastion", default_server_key())
            .with_pin("db", default_server_key());
        let run = run_ai_until(&now, &pinned_db(), "db", true, &FakeConfirmer::default(), &|| Ok(()), &|| None, &stop_it);
        assert!(!run.ran);
        assert!(run.result.as_ref().is_err_and(|error| error.contains("request approval again")), "{:?}", run.result);
        assert!(!run.engine.events().iter().any(|event| matches!(event, crate::ssh::fake::FakeEvent::Connect { .. })), "nothing connected");
        assert!(matches!(run.live.phase, TunnelPhase::Error));
    }

    /// The policy changed while the tunnel connected (AI access off, or another mode): it does not run.
    #[test]
    fn a_policy_change_while_an_ai_clients_tunnel_connects_stops_it() {
        let run = run_ai_until(&pinned_db(), &pinned_db(), "db", false, &FakeConfirmer::default(), &|| Err("MCP policy changed; request approval again.".into()), &|| None, &stop_it);
        assert!(!run.ran);
        assert!(run.result.as_ref().is_err_and(|error| error.contains("MCP policy changed")), "{:?}", run.result);
    }

    /// Design 2026-11-09: a server key that is not verified when the tunnel connects (the start verified it, so it went in between) is
    /// asked about in the host key window, in either mode; a refusal says so, and nothing runs.
    #[test]
    fn an_ai_clients_tunnel_asks_the_window_about_a_new_server_key_in_either_mode() {
        use crate::session::testing::Decision;
        let unpinned = || FakeDirectory::new().with_host("db", key());
        for auto_log in [true, false] {
            let refusing = FakeConfirmer::default();
            let run = run_ai_until(&unpinned(), &unpinned(), "db", auto_log, &refusing, &|| Ok(()), &|| None, &stop_it);
            assert!(!run.ran, "auto_log: {auto_log}");
            assert_eq!(run.result, Err("The server key of db was denied in Lunport's trust window; nothing was saved.".to_string()));
            assert_eq!(refusing.asked().len(), 1);
            let person = FakeConfirmer::deciding(vec![Decision::Trust]);
            let run = run_ai_until(&unpinned(), &unpinned(), "db", auto_log, &person, &|| Ok(()), &|| None, &stop_it);
            assert!(run.ran, "auto_log: {auto_log}");
            assert_eq!(run.result, Ok(()));
            assert_eq!(person.asked().len(), 1);
        }
    }

    /// A changed server key in an AI client's tunnel opens the warning window in both modes (design 2026-11-09, native windows for AI
    /// requests); the window names the client and, in Auto-log, says the tunnel starts without review. After Accept new key the tunnel
    /// runs; a refusal says the key had changed and nothing runs.
    #[test]
    fn an_ai_clients_tunnel_warns_about_a_changed_server_key_in_both_modes() {
        use crate::session::testing::Decision;
        let other = crate::ssh::HostKey::from_openssh_line(crate::sync::slot_rules::test_keys::ECDSA_PUBLIC).unwrap();
        let changed = || FakeDirectory::new().with_host("db", key()).with_pin("db", other.clone());
        for auto_log in [true, false] {
            let person = FakeConfirmer::deciding(vec![Decision::Trust]);
            let run = run_ai_until(&changed(), &changed(), "db", auto_log, &person, &|| Ok(()), &|| None, &stop_it);
            assert!(run.ran, "auto_log: {auto_log}");
            let asked = person.asked();
            assert_eq!(
                asked.iter().map(|q| (q.changed.as_ref().map(|pinned| pinned.fingerprint.clone()), q.ai.clone())).collect::<Vec<_>>(),
                [(Some(other.fingerprint.clone()), Some(claude(auto_log)))],
                "auto_log: {auto_log}"
            );

            let refusing = FakeConfirmer::deciding(vec![Decision::Refuse]);
            let run = run_ai_until(&changed(), &changed(), "db", auto_log, &refusing, &|| Ok(()), &|| None, &stop_it);
            assert!(!run.ran, "auto_log: {auto_log}");
            assert_eq!(run.result, Err("The changed server key of db was denied in Lunport's trust window; nothing was saved.".to_string()));
        }
    }

    /// While a window the tunnel's connection opened waits for the person (its server key, its password), its entry says so, so that
    /// `start_tunnel` keeps waiting for the person (design 2026-11-09, native windows for AI requests); once answered, it does not.
    #[test]
    fn an_ai_clients_tunnel_counts_the_windows_its_connection_has_open() {
        use crate::session::{
            auth::Reply,
            connect::{HostKeyConfirmer, HostKeyQuestion},
            protocol::QuestionKind,
        };
        use crate::ssh::fake::{FakeLogin, FakeMethods};
        /// The host key window: trusts the key, noting whether the entry counted it as open.
        struct Window<'a> {
            entry: &'a Entry,
            seen: Mutex<Vec<bool>>,
        }
        impl HostKeyConfirmer for Window<'_> {
            fn confirm(&self, question: &HostKeyQuestion, _: &CancelToken) -> Option<String> {
                self.seen.lock().unwrap().push(self.entry.asking());
                Some(question.fingerprint.clone())
            }
        }
        /// The password window: answers, noting the same.
        struct Person<'a> {
            entry: &'a Entry,
            seen: Mutex<Vec<bool>>,
        }
        impl Owner for Person<'_> {
            fn ask(&self, _: QuestionKind, _: &str, _: bool, _: Option<Instant>) -> Reply {
                self.seen.lock().unwrap().push(self.entry.asking());
                Reply::Answer(zeroize::Zeroizing::new("secret".into()))
            }
            fn host_key_notice(&self, _: &str) {}
            fn banner(&self, _: &str) {}
        }
        let directory = FakeDirectory::new().with_host("db", crate::ssh::AuthMethod::Password);
        let engine = FakeEngine::new().with_login(FakeLogin::Server(FakeMethods::password("secret")));
        let (keys, keychain, grants) = (FakeKeys::new(), MemKeychain::default(), GrantGates::default());
        let approved = crate::mcp::records::ApprovedTarget::capture(
            &crate::session::directory::HostDirectory::resolve_public(&directory, &HostQuery::Id("id-db".into())).unwrap(),
            &keys,
        )
        .unwrap();
        let rule = TunnelRule { host_id: "id-db".into(), ..saved().1 };
        let entry = Entry {
            rule: rule.clone(),
            account_id: None,
            cancel: CancelToken::default(),
            live: Mutex::new(TunnelLive { phase: TunnelPhase::Connecting, ..Default::default() }),
            ended_for: Mutex::new(None),
            asking: Default::default(),
        };
        let window = Window { entry: &entry, seen: Mutex::new(Vec::new()) };
        let person = Person { entry: &entry, seen: Mutex::new(Vec::new()) };
        let connector = Connector { engine: &engine, directory: &directory, keys: &keys, keychain: &keychain, confirmer: &window, grants: &grants };
        let ai = AiApproval { approved: &approved, asker: claude(true), allowed: &|| Ok(()), revoked: &|| None };
        let result = std::thread::scope(|scope| {
            // Once it runs, stop it: the test is about how it got there.
            scope.spawn(|| {
                let deadline = Instant::now() + Duration::from_secs(10);
                while matches!(entry.live().phase, TunnelPhase::Connecting) && Instant::now() < deadline {
                    std::thread::sleep(Duration::from_millis(5));
                }
                entry.stop();
            });
            run_for_ai(&rule, &entry, &connector, &person, &ai, &|| None, &|_| false)
        });
        assert_eq!(result, Ok(()));
        assert_eq!(*window.seen.lock().unwrap(), [true], "the host key window counted as open");
        assert_eq!(*person.seen.lock().unwrap(), [true], "the password window counted as open");
        assert!(!entry.asking(), "nothing open once answered");
    }

    /// An AI client's tunnel through a host that needs a Privileged Access Manager grant asks for one in Lunport's Request-a-grant window
    /// (design 2026-11-09, native windows for AI requests), and runs once the grant is active.
    #[test]
    fn an_ai_clients_tunnel_asks_for_the_grant_its_host_needs() {
        use crate::session::{
            protocol::QuestionKind,
            testing::{grant_answer, grant_need, NeedsGrant},
        };
        let inner = pinned_db();
        let directory = NeedsGrant::new(&inner, grant_need("db", "acme-tunnel-302020"));
        let engine = FakeEngine::new();
        let (keys, keychain, grants, confirmer) = (FakeKeys::new(), MemKeychain::default(), GrantGates::default(), FakeConfirmer::default());
        let connector = Connector { engine: &engine, directory: &directory, keys: &keys, keychain: &keychain, confirmer: &confirmer, grants: &grants };
        let approved = crate::mcp::records::ApprovedTarget::capture(
            &crate::session::directory::HostDirectory::resolve_public(&directory, &HostQuery::Id("id-db".into())).unwrap(),
            &keys,
        )
        .unwrap();
        let rule = TunnelRule { host_id: "id-db".into(), ..saved().1 };
        let entry = Entry {
            rule: rule.clone(),
            account_id: None,
            cancel: CancelToken::default(),
            live: Mutex::new(TunnelLive { phase: TunnelPhase::Connecting, ..Default::default() }),
            ended_for: Mutex::new(None),
            asking: Default::default(),
        };
        let owner = FakeOwner::typing(&[&grant_answer(60, "open the database tunnel")]);
        let ai = AiApproval { approved: &approved, asker: claude(true), allowed: &|| Ok(()), revoked: &|| None };
        let ran = std::sync::atomic::AtomicBool::new(false);
        let result = std::thread::scope(|scope| {
            scope.spawn(|| {
                let deadline = Instant::now() + Duration::from_secs(10);
                while matches!(entry.live().phase, TunnelPhase::Connecting) && Instant::now() < deadline {
                    std::thread::sleep(Duration::from_millis(5));
                }
                ran.store(matches!(entry.live().phase, TunnelPhase::Running), Ordering::SeqCst);
                entry.stop();
            });
            run_for_ai(&rule, &entry, &connector, &owner, &ai, &|| None, &|_| false)
        });
        assert_eq!(result, Ok(()));
        assert!(ran.load(Ordering::SeqCst), "it ran");
        assert_eq!(owner.asked().iter().map(|asked| asked.kind).collect::<Vec<_>>(), [QuestionKind::Grant]);
        assert_eq!(directory.requested(), [("open the database tunnel".to_string(), 3600)]);
    }

    /// The client's access ends while the tunnel still waits for the person's password: the window is withdrawn (the question is
    /// cancelled) and the tunnel says why it stopped.
    #[test]
    fn an_ai_clients_tunnel_ended_while_it_connects_withdraws_its_windows() {
        use crate::session::{auth::Reply, protocol::QuestionKind};
        use crate::ssh::fake::{FakeLogin, FakeMethods};
        /// A person who has the password window open and does not answer: it waits until the question is cancelled.
        struct Waiting<'a> {
            entry: &'a Entry,
            asked: &'a std::sync::atomic::AtomicBool,
            withdrawn: &'a std::sync::atomic::AtomicBool,
        }
        impl Owner for Waiting<'_> {
            fn ask(&self, _: QuestionKind, _: &str, _: bool, _: Option<Instant>) -> Reply {
                self.asked.store(true, Ordering::SeqCst);
                let deadline = Instant::now() + Duration::from_secs(10);
                while !self.entry.cancel.is_cancelled() && Instant::now() < deadline {
                    std::thread::sleep(Duration::from_millis(5));
                }
                self.withdrawn.store(self.entry.cancel.is_cancelled(), Ordering::SeqCst);
                Reply::Cancelled
            }
            fn host_key_notice(&self, _: &str) {}
            fn banner(&self, _: &str) {}
        }
        let directory = FakeDirectory::new().with_host("db", crate::ssh::AuthMethod::Password).with_pin("db", default_server_key());
        let engine = FakeEngine::new().with_login(FakeLogin::Server(FakeMethods::password("secret")));
        let (keys, keychain, grants, confirmer) = (FakeKeys::new(), MemKeychain::default(), GrantGates::default(), FakeConfirmer::default());
        let connector = Connector { engine: &engine, directory: &directory, keys: &keys, keychain: &keychain, confirmer: &confirmer, grants: &grants };
        let approved = crate::mcp::records::ApprovedTarget::capture(
            &crate::session::directory::HostDirectory::resolve_public(&directory, &HostQuery::Id("id-db".into())).unwrap(),
            &keys,
        )
        .unwrap();
        let rule = TunnelRule { host_id: "id-db".into(), ..saved().1 };
        let entry = Entry {
            rule: rule.clone(),
            account_id: None,
            cancel: CancelToken::default(),
            live: Mutex::new(TunnelLive { phase: TunnelPhase::Connecting, ..Default::default() }),
            ended_for: Mutex::new(None),
            asking: Default::default(),
        };
        let (asked, withdrawn) = (std::sync::atomic::AtomicBool::new(false), std::sync::atomic::AtomicBool::new(false));
        // The access ends once the password window is open.
        let revoked = || asked.load(Ordering::SeqCst).then(|| AI_ACCESS_ENDED.to_string());
        let ai = AiApproval { approved: &approved, asker: claude(false), allowed: &|| Ok(()), revoked: &revoked };
        let owner = Waiting { entry: &entry, asked: &asked, withdrawn: &withdrawn };
        let result = run_for_ai(&rule, &entry, &connector, &owner, &ai, &|| None, &|_| false);
        finish(&entry, result);
        assert!(withdrawn.load(Ordering::SeqCst), "the password window was withdrawn");
        assert!(matches!(entry.live().phase, TunnelPhase::Error), "{:?}", entry.live().phase);
        assert_eq!(entry.live().forwarding.error.as_deref(), Some(AI_ACCESS_ENDED));
    }

    /// The panel's Stop, its tunnels and an account change stay as they were: only a reason of Lunport's own becomes an error after a
    /// stop.
    #[test]
    fn a_stop_is_an_error_only_when_lunport_gives_a_reason() {
        let entry = |reason: Option<&str>| {
            let entry = Entry {
                rule: saved().1,
                account_id: None,
                cancel: CancelToken::default(),
                live: Mutex::new(TunnelLive { phase: TunnelPhase::Running, ..Default::default() }),
                ended_for: Mutex::new(None),
                asking: Default::default(),
            };
            match reason {
                Some(reason) => entry.stop_because(reason.into()),
                None => entry.stop(),
            }
            entry
        };
        let stopped = entry(None);
        finish(&stopped, Err("connection reset".into()));
        assert!(matches!(stopped.live().phase, TunnelPhase::Stopped));
        assert_eq!(stopped.live().forwarding.error, None);
        let ended = entry(Some(AI_ACCESS_ENDED));
        finish(&ended, Ok(()));
        assert!(matches!(ended.live().phase, TunnelPhase::Error));
        assert_eq!(ended.live().forwarding.error.as_deref(), Some(AI_ACCESS_ENDED));
    }
}
