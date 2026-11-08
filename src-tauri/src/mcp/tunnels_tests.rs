use super::*;
use crate::session::directory::HostDirectory;
use crate::session::testing::{FakeConfirmer, FakeDirectory, FakeKeys};
use crate::session::tunnels::TunnelLive;
use crate::ssh::{
    fake::{default_server_key, FakeEngine},
    forward::ForwardStatus,
    AuthMethod, Hop, HostId,
};
use crate::sync::testkit::MemKeychain;
use crate::sync::{
    fake_relay::FakeRelay,
    testkit::{TestClock, TestDevice},
};
use std::sync::atomic::AtomicUsize;

fn device() -> TestDevice {
    device_with(|state| state)
}
/// A device whose fresh records `edit` changes before they are activated.
fn device_with(edit: impl FnOnce(SyncStateV3) -> SyncStateV3) -> TestDevice {
    let d = TestDevice::new("tunnels", &FakeRelay::new(), &TestClock::new());
    let record_runtime::StartupProbe::Records { mut state, .. } = record_runtime::probe_startup(&d.env().state_path, "tunnels") else {
        panic!("fresh records")
    };
    state.relay_url = crate::sync::testkit::RELAY_URL.into();
    record_runtime::activate_probe(
        &mut d.runtime.core.lock().unwrap(),
        record_runtime::StartupProbe::Records { state: Box::new(edit(*state)), fresh: false },
    )
    .unwrap();
    d
}
fn runtime(mode: ApprovalMode) -> McpRuntime {
    let r = McpRuntime::default();
    *r.policy.lock().unwrap() = McpPolicy { enabled: true, approval_mode: mode, ..Default::default() };
    r
}
fn snapshot(d: &TestDevice) -> SyncStateV3 {
    record_runtime::snapshot(&d.env()).unwrap().0
}
/// A host saved through `create_host` and allowed for the client when `allowed`: its id.
fn host(d: &TestDevice, r: &McpRuntime, alias: &str, allowed: bool) -> String {
    let input = json!({"alias": alias, "hostname": format!("{alias}.example.com"), "user": "deploy"});
    let value = management::create(&d.env(), r, &input, RequestContext::default(), &CancelToken::default(), &|_| ApprovalDecision::Allow).unwrap();
    let id = value["host"]["id"].as_str().unwrap().to_string();
    if allowed {
        r.policy.lock().unwrap().allowed_hosts.insert(id.clone());
    }
    id
}
fn saved(d: &TestDevice) -> Vec<TunnelRule> {
    tunnel_rules::view(&snapshot(d)).into_iter().map(|row| row.rule).collect()
}
fn never(_: &McpPendingRequest) -> ApprovalDecision {
    panic!("no window")
}
fn allow(_: &McpPendingRequest) -> ApprovalDecision {
    ApprovalDecision::Allow
}
fn rows_of(q: &McpPendingRequest) -> Vec<(String, String)> {
    q.host_proposal.as_ref().unwrap().settings.clone()
}
fn row(label: &str, value: &str) -> (String, String) {
    (label.to_string(), value.to_string())
}
fn last_outcome(r: &McpRuntime) -> String {
    r.recent.lock().unwrap().front().unwrap().outcome.clone()
}
fn database() -> Value {
    json!({"name": "Database", "host": "web-1", "port": 15432, "target_host": "db.internal", "target_port": 5432})
}
/// The Database tunnel through web-1, saved with consent: its id.
fn created(d: &TestDevice, r: &McpRuntime, tunnels: &Tunnels) -> String {
    let value = create(&d.env(), r, tunnels, &database(), RequestContext::default(), &CancelToken::default(), &allow).unwrap();
    value["tunnel"]["id"].as_str().unwrap().to_string()
}
/// A rule saved outside MCP (as the panel saves it).
fn save_directly(d: &TestDevice, rule: TunnelRule) {
    crate::sync::record_commands::edit_records(&d.env(), |state, now| {
        tunnel_rules::set(state, None, &rule.id.clone(), None, Some(rule.clone()), now).map_err(|e| AppError::Other(e.to_string()))
    })
    .unwrap();
}
fn rule_on(host_id: &str, id: &str, name: &str) -> TunnelRule {
    TunnelRule {
        id: id.into(),
        name: name.into(),
        host_id: host_id.into(),
        forward: ForwardSpec { kind: ForwardKind::Local, bind_address: "127.0.0.1".into(), port: 15433, target_host: "db.internal".into(), target_port: 5432 },
    }
}
fn running(port: u16, started_by: Option<String>) -> TunnelLive {
    TunnelLive {
        phase: TunnelPhase::Running,
        forwarding: ForwardStatus { running: true, port, connections: 1, error: None },
        started_by,
    }
}
/// Stands the saved tunnel `id` as running here, as the panel's Start would.
fn start_here(d: &TestDevice, tunnels: &Tunnels, id: &str) -> Arc<Entry> {
    let rule = saved(d).into_iter().find(|rule| rule.id == id).unwrap();
    let (_, entry, _) = tunnels.prepare(&snapshot(d), &rule, None, None).unwrap();
    entry.set_live(running(rule.forward.port, None));
    entry
}

// ---- list_tunnels ----

#[test]
fn the_list_shows_only_the_clients_tunnels_with_their_state() {
    let d = device();
    let r = runtime(ApprovalMode::Ask);
    let tunnels = Tunnels::default();
    host(&d, &r, "web-1", true);
    let other = host(&d, &r, "web-2", false);
    let id = created(&d, &r, &tunnels);
    save_directly(&d, rule_on(&other, "00000000000000f2", "Hidden"));
    let listed = list(&d.env(), &r, &tunnels).unwrap();
    let rows = listed["tunnels"].as_array().unwrap();
    assert_eq!(rows.len(), 1, "{listed}");
    let tunnel = &rows[0];
    assert_eq!(tunnel["id"], id.as_str());
    assert_eq!(tunnel["name"], "Database");
    assert_eq!(tunnel["host_alias"], "web-1");
    assert_eq!(tunnel["kind"], "local");
    assert_eq!((tunnel["bind_address"].as_str(), tunnel["port"].as_u64()), (Some("127.0.0.1"), Some(15432)));
    assert_eq!((tunnel["target_host"].as_str(), tunnel["target_port"].as_u64()), (Some("db.internal"), Some(5432)));
    assert_eq!(tunnel["state"], "stopped");
    assert_eq!(tunnel["listening"], Value::Null);
    assert_eq!(tunnel["started_by_ai_client"], false);
    let entry = start_here(&d, &tunnels, &id);
    entry.set_live(running(15432, Some("Claude".into())));
    let tunnel = list(&d.env(), &r, &tunnels).unwrap()["tunnels"][0].clone();
    assert_eq!(tunnel["state"], "running");
    assert_eq!(tunnel["listening"], "127.0.0.1:15432");
    assert_eq!(tunnel["listening_port"], 15432);
    assert_eq!(tunnel["connections"], 1);
    assert_eq!(tunnel["started_by_ai_client"], true);
    entry.set_live(TunnelLive { started_by: Some("Claude".into()), ..TunnelLive::default() });
    let tunnel = list(&d.env(), &r, &tunnels).unwrap()["tunnels"][0].clone();
    assert_eq!((tunnel["state"].as_str(), tunnel["started_by_ai_client"].as_bool()), (Some("stopped"), Some(false)), "only while it runs");
}

#[test]
fn the_tunnels_of_hosts_the_client_may_not_use_answer_as_unknown() {
    let d = device();
    let r = runtime(ApprovalMode::AutoLog);
    let tunnels = Tunnels::default();
    host(&d, &r, "web-1", true);
    let other = host(&d, &r, "web-2", false);
    save_directly(&d, rule_on(&other, "00000000000000f2", "Hidden"));
    let unknown = "No tunnel this client may use is named or identified as '00000000000000f2'.";
    let by_id = json!({"tunnel": "00000000000000f2"});
    let connector_parts = (FakeEngine::new(), FakeDirectory::new(), FakeKeys::new(), MemKeychain::default(), FakeConfirmer::default());
    let connector = Connector {
        engine: &connector_parts.0,
        directory: &connector_parts.1,
        keys: &connector_parts.2,
        keychain: &connector_parts.3,
        confirmer: &connector_parts.4,
        grants: crate::session::grants::GrantGates::for_tests(),
    };
    let no_launch = |_: &TunnelRule, _: records::ApprovedTarget, _: ApprovalMode, _: String| -> Result<Arc<Entry>, String> { panic!("nothing starts") };
    for result in [
        update(&d.env(), &r, &tunnels, &json!({"tunnel": "00000000000000f2", "port": 1}), RequestContext::default(), &CancelToken::default(), &never),
        delete(&d.env(), &r, &tunnels, &by_id, RequestContext::default(), &CancelToken::default(), &never),
        start(&d.env(), &r, &tunnels, &connector, &by_id, RequestContext::default(), &CancelToken::default(), &never, &no_launch),
        stop(&d.env(), &r, &tunnels, &by_id, RequestContext::default(), &CancelToken::default()),
    ] {
        assert_eq!(result.unwrap_err(), unknown);
    }
    let error = create(&d.env(), &r, &tunnels, &json!({"name": "New", "host": "web-2", "target_host": "db.internal", "target_port": 5432}), RequestContext::default(), &CancelToken::default(), &never).unwrap_err();
    assert_eq!(error, format!("host '{other}' is not allowed for AI access"));
    assert_eq!(saved(&d).len(), 1, "only the rule saved outside MCP");
    r.policy.lock().unwrap().enabled = false;
    assert_eq!(list(&d.env(), &r, &tunnels).unwrap_err(), "MCP access is disabled.");
}

// ---- create_tunnel ----

#[test]
fn creating_a_tunnel_asks_in_every_mode_and_saves_only_on_consent() {
    for mode in [ApprovalMode::Ask, ApprovalMode::AutoLog] {
        let d = device();
        let r = runtime(mode);
        let tunnels = Tunnels::default();
        let web = host(&d, &r, "web-1", true);
        let asked = AtomicUsize::new(0);
        let value = create(&d.env(), &r, &tunnels, &database(), RequestContext::default(), &CancelToken::default(), &|q| {
            asked.fetch_add(1, Ordering::SeqCst);
            assert!(saved(&d).is_empty(), "nothing saved before consent");
            assert_eq!(q.host_proposal.as_ref().unwrap().kind, proposal_kinds::CREATE_TUNNEL);
            assert_eq!(q.host_id.as_deref(), Some(web.as_str()));
            let rows = rows_of(q);
            for expected in [
                row("Name", "Database"),
                row("Host", &format!("web-1 ({web})")),
                row("Type", "Local forward"),
                row("Listens on", "127.0.0.1:15432 on this computer"),
                row("Forwards to", "db.internal:5432 as web-1 reaches it"),
                row("Reachable from", "This computer only"),
                row("Route", "deploy@web-1.example.com:22 (web-1)"),
                row("Storage", "This device's library"),
            ] {
                assert!(rows.contains(&expected), "{expected:?} in {rows:?}");
            }
            ApprovalDecision::Allow
        })
        .unwrap();
        assert_eq!(asked.load(Ordering::SeqCst), 1);
        let rules = saved(&d);
        assert_eq!(rules.len(), 1);
        assert_eq!((rules[0].name.as_str(), rules[0].host_id.as_str()), ("Database", web.as_str()));
        assert_eq!(rules[0].forward, ForwardSpec { kind: ForwardKind::Local, bind_address: "127.0.0.1".into(), port: 15432, target_host: "db.internal".into(), target_port: 5432 });
        assert_eq!(value["tunnel"]["id"], rules[0].id.as_str());
        assert_eq!(value["message"], "Tunnel saved. Start it with start_tunnel.");
        assert_eq!(last_outcome(&r), "tunnel_created");
        assert!(r.records_active.lock().unwrap().is_empty());
        assert!(!tunnels.busy(&rules[0].id), "saving does not start it");
    }
}

#[test]
fn a_new_tunnel_listens_on_loopback_with_a_free_port_unless_told_otherwise() {
    let d = device();
    let r = runtime(ApprovalMode::Ask);
    let tunnels = Tunnels::default();
    host(&d, &r, "web-1", true);
    create(&d.env(), &r, &tunnels, &json!({"name": "Proxy", "host": "web-1", "kind": "dynamic"}), RequestContext::default(), &CancelToken::default(), &|q| {
        let rows = rows_of(q);
        for expected in [
            row("Type", "SOCKS5 proxy"),
            row("Listens on", "127.0.0.1 on this computer, a free port chosen at each start"),
            row("Forwards to", "The destination each connection asks for, as web-1 reaches it"),
            row("Reachable from", "This computer only"),
        ] {
            assert!(rows.contains(&expected), "{expected:?} in {rows:?}");
        }
        ApprovalDecision::Allow
    })
    .unwrap();
    assert_eq!(saved(&d)[0].forward, ForwardSpec { kind: ForwardKind::Dynamic, bind_address: "127.0.0.1".into(), port: 0, target_host: String::new(), target_port: 0 });
}

#[test]
fn the_window_says_who_can_reach_the_listener() {
    let forward = |kind, bind: &str| ForwardSpec { kind, bind_address: bind.into(), port: 8080, target_host: "127.0.0.1".into(), target_port: 3000 };
    assert_eq!(exposure(&forward(ForwardKind::Local, "::1"), "web-1"), "This computer only");
    assert_eq!(exposure(&forward(ForwardKind::Local, "0.0.0.0"), "web-1"), "Any computer that can reach this one");
    assert_eq!(exposure(&forward(ForwardKind::Dynamic, "192.168.1.10"), "web-1"), "Computers that can reach 192.168.1.10 on this computer");
    assert_eq!(exposure(&forward(ForwardKind::Remote, "127.0.0.1"), "web-1"), "web-1 only");
    assert_eq!(exposure(&forward(ForwardKind::Remote, "::"), "web-1"), "Any computer that can reach web-1, if its SSH server allows it");
    assert_eq!(exposure(&forward(ForwardKind::Remote, "10.0.0.5"), "web-1"), "Computers that can reach 10.0.0.5 on web-1, if its SSH server allows it");
    // An IPv4-mapped IPv6 address listens on its IPv4 address on a dual-stack socket, and is judged as that address.
    assert_eq!(exposure(&forward(ForwardKind::Local, "::ffff:0.0.0.0"), "web-1"), "Any computer that can reach this one");
    assert_eq!(exposure(&forward(ForwardKind::Dynamic, "::ffff:127.0.0.1"), "web-1"), "This computer only");
    assert_eq!(exposure(&forward(ForwardKind::Remote, "::ffff:0.0.0.0"), "web-1"), "Any computer that can reach web-1, if its SSH server allows it");
}

#[test]
fn invalid_or_private_settings_are_refused_before_the_window() {
    let d = device();
    let r = runtime(ApprovalMode::Ask);
    let tunnels = Tunnels::default();
    host(&d, &r, "web-1", true);
    for (input, sentence) in [
        (json!({"name": "Proxy", "host": "web-1", "kind": "dynamic", "target_host": "db.internal"}), "A SOCKS5 tunnel chooses its destination for each connection."),
        (json!({"name": "Database", "host": "web-1"}), "Enter a destination host and a port between 1 and 65535."),
        (json!({"name": "Database", "host": "web-1", "bind_address": "localhost", "target_host": "db", "target_port": 5432}), "Enter an IPv4 or IPv6 listening address."),
        (json!({"name": "  ", "host": "web-1", "target_host": "db", "target_port": 5432}), "Enter a tunnel name (up to 128 characters)."),
        (json!({"name": "Database", "host": "web-1", "target_host": "db", "target_port": 5432, "password": "hunter2"}), SETTINGS_ONLY),
        (json!({"name": "Database", "host": "web-1", "target_host": "db", "target_port": 70000}), SETTINGS_ONLY),
    ] {
        let error = create(&d.env(), &r, &tunnels, &input, RequestContext::default(), &CancelToken::default(), &never).unwrap_err();
        assert_eq!(error, sentence, "{input}");
        assert!(!error.contains("hunter2"));
    }
    assert!(saved(&d).is_empty());
    assert!(r.recent.lock().unwrap().iter().all(|entry| !entry.outcome.starts_with("tunnel_")), "nothing to audit: no window opened");
}

#[test]
fn a_creation_the_person_does_not_allow_saves_nothing_and_is_audited() {
    for (decision, sentence) in [
        (ApprovalDecision::Deny, "Tunnel creation was denied."),
        (ApprovalDecision::TimedOut, "Tunnel creation approval timed out."),
        (ApprovalDecision::Cancel, "Tunnel creation was canceled."),
    ] {
        let d = device();
        let r = runtime(ApprovalMode::AutoLog);
        let tunnels = Tunnels::default();
        host(&d, &r, "web-1", true);
        assert_eq!(create(&d.env(), &r, &tunnels, &database(), RequestContext::default(), &CancelToken::default(), &|_| decision).unwrap_err(), sentence);
        assert!(saved(&d).is_empty());
        assert_eq!(last_outcome(&r), "tunnel_not_created");
        assert!(r.records_active.lock().unwrap().is_empty());
    }
}

#[test]
fn a_policy_change_during_the_window_saves_nothing() {
    let d = device();
    let r = runtime(ApprovalMode::Ask);
    let tunnels = Tunnels::default();
    let web = host(&d, &r, "web-1", true);
    let error = create(&d.env(), &r, &tunnels, &database(), RequestContext::default(), &CancelToken::default(), &|_| {
        r.policy.lock().unwrap().allowed_hosts.clear();
        ApprovalDecision::Allow
    })
    .unwrap_err();
    assert_eq!(error, format!("host '{web}' is not allowed for AI access"));
    r.policy.lock().unwrap().allowed_hosts.insert(web);
    let error = create(&d.env(), &r, &tunnels, &database(), RequestContext::default(), &CancelToken::default(), &|_| {
        r.policy.lock().unwrap().enabled = false;
        ApprovalDecision::Allow
    })
    .unwrap_err();
    assert_eq!(error, "MCP policy changed; request approval again.");
    assert!(saved(&d).is_empty());
}

/// A library whose writes are paused, or whose Catalog has no room, refuses the save with its own sentence before any window.
#[test]
fn a_library_that_cannot_take_the_tunnel_refuses_it_before_the_window() {
    use crate::sync::transports::tests::{filled_past_the_limit_with_tunnels, in_central_mode};
    let d = device_with(|state| filled_past_the_limit_with_tunnels(in_central_mode(state)));
    let r = runtime(ApprovalMode::Ask);
    let tunnels = Tunnels::default();
    host(&d, &r, "web-1", true);
    assert_eq!(create(&d.env(), &r, &tunnels, &database(), RequestContext::default(), &CancelToken::default(), &never).unwrap_err(), crate::sync::transports::NO_ROOM);

    let d = device_with(in_central_mode);
    let r = runtime(ApprovalMode::Ask);
    host(&d, &r, "web-1", true);
    created(&d, &r, &tunnels);
    record_runtime::mutate_records(&d.env(), |state| {
        let mut next = state.clone();
        next.shared_writes_blocked = true;
        Ok(next)
    })
    .unwrap();
    assert_eq!(create(&d.env(), &r, &tunnels, &database(), RequestContext::default(), &CancelToken::default(), &never).unwrap_err(), crate::sync::transports::SYNC_PAUSED);
    assert_eq!(delete(&d.env(), &r, &tunnels, &json!({"tunnel": "Database"}), RequestContext::default(), &CancelToken::default(), &never).unwrap_err(), crate::sync::transports::SYNC_PAUSED);
}

// ---- update_tunnel ----

#[test]
fn an_update_shows_old_to_new_and_changes_only_what_was_sent() {
    let d = device();
    let r = runtime(ApprovalMode::Ask);
    let tunnels = Tunnels::default();
    host(&d, &r, "web-1", true);
    let id = created(&d, &r, &tunnels);
    let value = update(&d.env(), &r, &tunnels, &json!({"tunnel": "Database", "port": 25432}), RequestContext::default(), &CancelToken::default(), &|q| {
        assert_eq!(q.host_proposal.as_ref().unwrap().kind, proposal_kinds::UPDATE_TUNNEL);
        assert_eq!(rows_of(q), vec![row("Listens on", "127.0.0.1:15432 on this computer → 127.0.0.1:25432 on this computer")]);
        assert_eq!(saved(&d)[0].forward.port, 15432, "nothing saved before consent");
        ApprovalDecision::Allow
    })
    .unwrap();
    let rule = saved(&d).pop().unwrap();
    assert_eq!((rule.id.as_str(), rule.forward.port, rule.forward.target_host.as_str()), (id.as_str(), 25432, "db.internal"));
    assert_eq!(value["tunnel"]["port"], 25432);
    assert_eq!(value["message"], "Tunnel saved.");
    assert_eq!(last_outcome(&r), "tunnel_updated");
}

#[test]
fn switching_to_socks5_clears_the_destination() {
    let d = device();
    let r = runtime(ApprovalMode::Ask);
    let tunnels = Tunnels::default();
    host(&d, &r, "web-1", true);
    let id = created(&d, &r, &tunnels);
    update(&d.env(), &r, &tunnels, &json!({"tunnel": id, "kind": "dynamic"}), RequestContext::default(), &CancelToken::default(), &|q| {
        let rows = rows_of(q);
        assert!(rows.contains(&row("Type", "Local forward → SOCKS5 proxy")), "{rows:?}");
        assert!(rows.contains(&row("Forwards to", "db.internal:5432 as web-1 reaches it → The destination each connection asks for, as web-1 reaches it")), "{rows:?}");
        ApprovalDecision::Allow
    })
    .unwrap();
    let forward = saved(&d).pop().unwrap().forward;
    assert_eq!((forward.kind, forward.target_host.as_str(), forward.target_port), (ForwardKind::Dynamic, "", 0));
    assert_eq!(
        update(&d.env(), &r, &tunnels, &json!({"tunnel": "Database", "kind": "local"}), RequestContext::default(), &CancelToken::default(), &never).unwrap_err(),
        "Enter a destination host and a port between 1 and 65535."
    );
}

#[test]
fn an_update_with_nothing_to_change_is_refused_without_a_window() {
    let d = device();
    let r = runtime(ApprovalMode::Ask);
    let tunnels = Tunnels::default();
    host(&d, &r, "web-1", true);
    created(&d, &r, &tunnels);
    assert_eq!(update(&d.env(), &r, &tunnels, &json!({"tunnel": "Database"}), RequestContext::default(), &CancelToken::default(), &never).unwrap_err(), "Provide at least one setting to change.");
    assert_eq!(update(&d.env(), &r, &tunnels, &json!({"tunnel": "Database", "port": 15432}), RequestContext::default(), &CancelToken::default(), &never).unwrap_err(), "Nothing would change.");
    assert_eq!(update(&d.env(), &r, &tunnels, &json!({"tunnel": "Database", "host_id": "x"}), RequestContext::default(), &CancelToken::default(), &never).unwrap_err(), SETTINGS_ONLY);
}

#[test]
fn moving_a_tunnel_needs_both_hosts_and_shows_the_new_route() {
    let d = device();
    let r = runtime(ApprovalMode::Ask);
    let tunnels = Tunnels::default();
    host(&d, &r, "web-1", true);
    let other = host(&d, &r, "web-2", false);
    created(&d, &r, &tunnels);
    let to_web2 = json!({"tunnel": "Database", "host": "web-2"});
    assert_eq!(update(&d.env(), &r, &tunnels, &to_web2, RequestContext::default(), &CancelToken::default(), &never).unwrap_err(), format!("host '{other}' is not allowed for AI access"));
    r.policy.lock().unwrap().allowed_hosts.insert(other.clone());
    update(&d.env(), &r, &tunnels, &to_web2, RequestContext::default(), &CancelToken::default(), &|q| {
        let rows = rows_of(q);
        assert!(rows.iter().any(|(label, value)| label == "Host" && value.ends_with(&format!("web-2 ({other})"))), "{rows:?}");
        assert!(rows.contains(&row("Route", "deploy@web-1.example.com:22 (web-1) → deploy@web-2.example.com:22 (web-2)")), "{rows:?}");
        assert_eq!(q.host_id.as_deref(), Some(other.as_str()), "the window names the host the tunnel will go through");
        ApprovalDecision::Allow
    })
    .unwrap();
    assert_eq!(saved(&d)[0].host_id, other);
}

#[test]
fn a_running_tunnel_is_neither_changed_nor_deleted() {
    let d = device();
    let r = runtime(ApprovalMode::Ask);
    let tunnels = Tunnels::default();
    host(&d, &r, "web-1", true);
    let id = created(&d, &r, &tunnels);
    let _entry = start_here(&d, &tunnels, &id);
    let stop_first = crate::session::tunnels::STOP_FIRST;
    assert_eq!(update(&d.env(), &r, &tunnels, &json!({"tunnel": "Database", "port": 1}), RequestContext::default(), &CancelToken::default(), &never).unwrap_err(), stop_first);
    assert_eq!(delete(&d.env(), &r, &tunnels, &json!({"tunnel": "Database"}), RequestContext::default(), &CancelToken::default(), &never).unwrap_err(), stop_first);
    assert_eq!(saved(&d).len(), 1);
}

/// A tunnel started while the window was open is not changed under it either.
#[test]
fn a_tunnel_started_while_the_window_was_open_is_not_changed() {
    let d = device();
    let r = runtime(ApprovalMode::Ask);
    let tunnels = Tunnels::default();
    host(&d, &r, "web-1", true);
    let id = created(&d, &r, &tunnels);
    let entry = std::sync::Mutex::new(None);
    let error = update(&d.env(), &r, &tunnels, &json!({"tunnel": "Database", "port": 1}), RequestContext::default(), &CancelToken::default(), &|_| {
        *entry.lock().unwrap() = Some(start_here(&d, &tunnels, &id));
        ApprovalDecision::Allow
    })
    .unwrap_err();
    assert_eq!(error, crate::session::tunnels::STOP_FIRST);
    assert_eq!(saved(&d)[0].forward.port, 15432);
    assert_eq!(last_outcome(&r), "tunnel_not_updated");
}

#[test]
fn a_tunnel_changed_meanwhile_is_refused() {
    let d = device();
    let r = runtime(ApprovalMode::Ask);
    let tunnels = Tunnels::default();
    host(&d, &r, "web-1", true);
    created(&d, &r, &tunnels);
    let error = update(&d.env(), &r, &tunnels, &json!({"tunnel": "Database", "port": 25432}), RequestContext::default(), &CancelToken::default(), &|_| {
        let current = saved(&d).pop().unwrap();
        let mut other = current.clone();
        other.forward.target_port = 5433;
        crate::sync::record_commands::edit_records(&d.env(), |state, now| {
            tunnel_rules::set(state, None, &current.id, Some(&current), Some(other.clone()), now).map_err(|e| AppError::Other(e.to_string()))
        })
        .unwrap();
        ApprovalDecision::Allow
    })
    .unwrap_err();
    assert_eq!(error, TUNNEL_CHANGED);
    let rule = saved(&d).pop().unwrap();
    assert_eq!((rule.forward.port, rule.forward.target_port), (15432, 5433), "the other change stands");
}

#[test]
fn a_tunnel_is_named_by_its_id_or_its_one_exact_name() {
    let d = device();
    let r = runtime(ApprovalMode::Ask);
    let tunnels = Tunnels::default();
    host(&d, &r, "web-1", true);
    let first = created(&d, &r, &tunnels);
    created(&d, &r, &tunnels);
    assert_eq!(
        update(&d.env(), &r, &tunnels, &json!({"tunnel": "Database", "port": 1}), RequestContext::default(), &CancelToken::default(), &never).unwrap_err(),
        "Several tunnels this client may use are named 'Database'; name it by its id."
    );
    update(&d.env(), &r, &tunnels, &json!({"tunnel": first, "name": "Primary database"}), RequestContext::default(), &CancelToken::default(), &allow).unwrap();
    assert!(saved(&d).iter().any(|rule| rule.id == first && rule.name == "Primary database"));
    assert_eq!(delete(&d.env(), &r, &tunnels, &json!({"tunnel": "Nothing"}), RequestContext::default(), &CancelToken::default(), &never).unwrap_err(), "No tunnel this client may use is named or identified as 'Nothing'.");
    assert_eq!(delete(&d.env(), &r, &tunnels, &json!({"name": "Database"}), RequestContext::default(), &CancelToken::default(), &never).unwrap_err(), TUNNEL_ONLY);
}

// ---- delete_tunnel ----

#[test]
fn deleting_a_tunnel_asks_and_removes_it_only_on_consent() {
    let d = device();
    let r = runtime(ApprovalMode::AutoLog);
    let tunnels = Tunnels::default();
    host(&d, &r, "web-1", true);
    created(&d, &r, &tunnels);
    assert_eq!(delete(&d.env(), &r, &tunnels, &json!({"tunnel": "Database"}), RequestContext::default(), &CancelToken::default(), &|_| ApprovalDecision::Deny).unwrap_err(), "Tunnel deletion was denied.");
    assert_eq!(saved(&d).len(), 1);
    assert_eq!(last_outcome(&r), "tunnel_not_deleted");
    let value = delete(&d.env(), &r, &tunnels, &json!({"tunnel": "Database"}), RequestContext::default(), &CancelToken::default(), &|q| {
        assert_eq!(q.host_proposal.as_ref().unwrap().kind, proposal_kinds::DELETE_TUNNEL);
        assert!(rows_of(q).contains(&row("Forwards to", "db.internal:5432 as web-1 reaches it")), "{:?}", rows_of(q));
        assert_eq!(saved(&d).len(), 1, "still there before consent");
        ApprovalDecision::Allow
    })
    .unwrap();
    assert!(saved(&d).is_empty());
    assert_eq!(value, json!({"tunnel": null, "message": "Tunnel deleted."}));
    assert_eq!(last_outcome(&r), "tunnel_deleted");
    let audited = r.recent.lock().unwrap().front().unwrap().clone();
    assert_eq!(audited.alias, "web-1 · Database");
    assert!(audited.command.is_empty());
}

// ---- start_tunnel ----

/// The fakes `start` resolves the route through: web-1 reached directly with the vault's plain key, its server key pinned when
/// `pinned`.
struct Route {
    engine: FakeEngine,
    directory: FakeDirectory,
    keys: FakeKeys,
    keychain: MemKeychain,
    confirmer: FakeConfirmer,
}
impl Route {
    fn to(web: &str, pinned: bool) -> Route {
        let directory = FakeDirectory::new().with_hop(Hop::new(web, "web-1", "web-1.example.com", 22, "deploy", AuthMethod::Key { key_id: "k-plain".into() }));
        if pinned {
            directory.pin(&HostId::from(web), &default_server_key()).unwrap();
        }
        Route { engine: FakeEngine::new(), directory, keys: FakeKeys::new(), keychain: MemKeychain::default(), confirmer: FakeConfirmer::default() }
    }
    fn connector(&self) -> Connector<'_> {
        Connector {
            engine: &self.engine,
            directory: &self.directory,
            keys: &self.keys,
            keychain: &self.keychain,
            confirmer: &self.confirmer,
            grants: crate::session::grants::GrantGates::for_tests(),
        }
    }
}

/// A launch that starts nothing: it prepares the tunnel's entry as the app does, notes what it was given, and stands the entry in
/// `then` a moment later, as the worker would.
struct Launches<'a> {
    d: &'a TestDevice,
    tunnels: &'a Tunnels,
    then: Option<TunnelLive>,
    given: Mutex<Vec<(ApprovalMode, String)>>,
}
impl<'a> Launches<'a> {
    fn new(d: &'a TestDevice, tunnels: &'a Tunnels, then: Option<TunnelLive>) -> Self {
        Launches { d, tunnels, then, given: Mutex::new(Vec::new()) }
    }
    fn launch(&self, rule: &TunnelRule, _: records::ApprovedTarget, mode: ApprovalMode, started_by: String) -> Result<Arc<Entry>, String> {
        self.given.lock().unwrap().push((mode, started_by.clone()));
        let (_, entry, _) = self.tunnels.prepare(&snapshot(self.d), rule, None, Some(started_by.clone()))?;
        if let Some(mut then) = self.then.clone() {
            then.started_by = Some(started_by);
            let worker = Arc::clone(&entry);
            thread::spawn(move || {
                thread::sleep(Duration::from_millis(30));
                worker.set_live(then);
            });
        }
        Ok(entry)
    }
    fn given(&self) -> Vec<(ApprovalMode, String)> {
        self.given.lock().unwrap().clone()
    }
}

#[test]
fn starting_in_ask_mode_asks_with_the_route_and_answers_where_it_listens() {
    let d = device();
    let r = runtime(ApprovalMode::Ask);
    let tunnels = Tunnels::default();
    let web = host(&d, &r, "web-1", true);
    created(&d, &r, &tunnels);
    let route = Route::to(&web, false);
    let launches = Launches::new(&d, &tunnels, Some(running(15432, None)));
    let context = RequestContext { requested_by: vec!["Terminal".into(), "claude".into()], ..Default::default() };
    let asked = AtomicUsize::new(0);
    let value = start(&d.env(), &r, &tunnels, &route.connector(), &json!({"tunnel": "Database"}), context, &CancelToken::default(), &|q| {
        asked.fetch_add(1, Ordering::SeqCst);
        assert_eq!(q.host_proposal.as_ref().unwrap().kind, proposal_kinds::START_TUNNEL);
        let rows = rows_of(q);
        assert!(rows.contains(&row("Route", "deploy@web-1.example.com:22 (web-1)")), "{rows:?}");
        assert!(rows.contains(&row("Listens on", "127.0.0.1:15432 on this computer")), "{rows:?}");
        assert_eq!(q.route, vec!["deploy@web-1.example.com:22 (web-1)".to_string()]);
        assert!(launches.given().is_empty(), "nothing starts before consent");
        ApprovalDecision::Allow
    }, &|rule, approved, mode, who| launches.launch(rule, approved, mode, who))
    .unwrap();
    assert_eq!(asked.load(Ordering::SeqCst), 1);
    assert_eq!(launches.given(), vec![(ApprovalMode::Ask, "Terminal → claude".to_string())]);
    assert_eq!(value["tunnel"]["state"], "running");
    assert_eq!(value["tunnel"]["listening"], "127.0.0.1:15432");
    assert_eq!(value["tunnel"]["started_by_ai_client"], true);
    assert_eq!(value["message"], "Tunnel running; connect to 127.0.0.1:15432 on this computer.");
    assert_eq!(last_outcome(&r), "tunnel_started");
    assert!(r.records_active.lock().unwrap().is_empty());
}

#[test]
fn auto_log_starts_without_a_window_once_the_server_key_is_verified() {
    let d = device();
    let r = runtime(ApprovalMode::AutoLog);
    let tunnels = Tunnels::default();
    let web = host(&d, &r, "web-1", true);
    created(&d, &r, &tunnels);
    let unverified = Route::to(&web, false);
    let launches = Launches::new(&d, &tunnels, Some(running(15432, None)));
    let launch = |rule: &TunnelRule, approved, mode, who| launches.launch(rule, approved, mode, who);
    let error = start(&d.env(), &r, &tunnels, &unverified.connector(), &json!({"tunnel": "Database"}), RequestContext::default(), &CancelToken::default(), &never, &launch).unwrap_err();
    assert_eq!(error, "needs interaction: host key is not pinned");
    assert!(launches.given().is_empty());
    assert_eq!(last_outcome(&r), "tunnel_not_started");
    let verified = Route::to(&web, true);
    let value = start(&d.env(), &r, &tunnels, &verified.connector(), &json!({"tunnel": "Database"}), RequestContext::default(), &CancelToken::default(), &never, &launch).unwrap();
    assert_eq!(value["tunnel"]["state"], "running");
    assert_eq!(launches.given(), vec![(ApprovalMode::AutoLog, "An unidentified AI client".to_string())]);
}

#[test]
fn a_start_the_person_does_not_allow_starts_nothing() {
    for (decision, sentence) in [
        (ApprovalDecision::Deny, "Tunnel start was denied."),
        (ApprovalDecision::TimedOut, "Tunnel start approval timed out."),
        (ApprovalDecision::Cancel, "Tunnel start was canceled."),
    ] {
        let d = device();
        let r = runtime(ApprovalMode::Ask);
        let tunnels = Tunnels::default();
        let web = host(&d, &r, "web-1", true);
        created(&d, &r, &tunnels);
        let route = Route::to(&web, true);
        let launches = Launches::new(&d, &tunnels, Some(running(15432, None)));
        let error = start(&d.env(), &r, &tunnels, &route.connector(), &json!({"tunnel": "Database"}), RequestContext::default(), &CancelToken::default(), &|_| decision, &|rule, approved, mode, who| launches.launch(rule, approved, mode, who)).unwrap_err();
        assert_eq!(error, sentence);
        assert!(launches.given().is_empty());
        assert_eq!(last_outcome(&r), "tunnel_not_started");
    }
}

/// The route changed while the window was open: the approval does not cover it.
#[test]
fn a_start_whose_route_changed_during_the_window_starts_nothing() {
    let d = device();
    let r = runtime(ApprovalMode::Ask);
    let tunnels = Tunnels::default();
    let web = host(&d, &r, "web-1", true);
    created(&d, &r, &tunnels);
    let route = Route::to(&web, true);
    let changed = Route {
        directory: FakeDirectory::new().with_hop(Hop::new(&web, "web-1", "web-1-new.example.com", 22, "deploy", AuthMethod::Key { key_id: "k-plain".into() })),
        ..Route::to(&web, true)
    };
    let launches = Launches::new(&d, &tunnels, Some(running(15432, None)));
    // The window shows the route as resolved first; the start then resolves it again, now elsewhere.
    let resolving = std::sync::atomic::AtomicBool::new(false);
    struct Switching<'a> {
        first: &'a FakeDirectory,
        then: &'a FakeDirectory,
        switched: &'a std::sync::atomic::AtomicBool,
    }
    impl HostDirectory for Switching<'_> {
        fn resolve(&self, query: &HostQuery) -> Result<crate::ssh::Target, crate::session::directory::DirectoryError> {
            if self.switched.load(Ordering::SeqCst) { self.then.resolve(query) } else { self.first.resolve(query) }
        }
        fn pinned(&self, host: &HostId) -> Result<Option<crate::session::directory::PinnedKey>, crate::session::directory::DirectoryError> {
            self.first.pinned(host)
        }
        fn pin(&self, host: &HostId, key: &crate::ssh::HostKey) -> Result<(), crate::session::directory::DirectoryError> {
            self.first.pin(host, key)
        }
        fn replace_pin(&self, host: &HostId, previous: &crate::ssh::HostKey, key: &crate::ssh::HostKey) -> Result<(), crate::session::directory::DirectoryError> {
            self.first.replace_pin(host, previous, key)
        }
        fn password_account(&self, host: &HostId) -> String {
            self.first.password_account(host)
        }
    }
    let directory = Switching { first: &route.directory, then: &changed.directory, switched: &resolving };
    let connector = Connector { directory: &directory, ..route.connector() };
    let error = start(&d.env(), &r, &tunnels, &connector, &json!({"tunnel": "Database"}), RequestContext::default(), &CancelToken::default(), &|_| {
        resolving.store(true, Ordering::SeqCst);
        ApprovalDecision::Allow
    }, &|rule, approved, mode, who| launches.launch(rule, approved, mode, who))
    .unwrap_err();
    assert_eq!(error, "The approved destination, route or key changed; request approval again.");
    assert!(launches.given().is_empty());
}

#[test]
fn a_start_that_fails_says_why() {
    let d = device();
    let r = runtime(ApprovalMode::AutoLog);
    let tunnels = Tunnels::default();
    let web = host(&d, &r, "web-1", true);
    created(&d, &r, &tunnels);
    let route = Route::to(&web, true);
    let failed = TunnelLive { phase: TunnelPhase::Error, forwarding: ForwardStatus { error: Some("Connection refused by web-1.example.com".into()), ..Default::default() }, started_by: None };
    let launches = Launches::new(&d, &tunnels, Some(failed));
    let error = start(&d.env(), &r, &tunnels, &route.connector(), &json!({"tunnel": "Database"}), RequestContext::default(), &CancelToken::default(), &never, &|rule, approved, mode, who| launches.launch(rule, approved, mode, who)).unwrap_err();
    assert_eq!(error, "The tunnel could not start: Connection refused by web-1.example.com");
    assert_eq!(last_outcome(&r), "tunnel_not_started");
}

#[test]
fn a_running_tunnel_answers_its_state_instead_of_starting_again() {
    let d = device();
    let r = runtime(ApprovalMode::Ask);
    let tunnels = Tunnels::default();
    let web = host(&d, &r, "web-1", true);
    let id = created(&d, &r, &tunnels);
    start_here(&d, &tunnels, &id);
    let route = Route::to(&web, true);
    let launches = Launches::new(&d, &tunnels, None);
    let value = start(&d.env(), &r, &tunnels, &route.connector(), &json!({"tunnel": id}), RequestContext::default(), &CancelToken::default(), &never, &|rule, approved, mode, who| launches.launch(rule, approved, mode, who)).unwrap();
    assert_eq!(value["message"], "The tunnel is already running.");
    assert_eq!(value["tunnel"]["state"], "running");
    assert!(launches.given().is_empty());
}

/// The client went away (or its access changed) while the tunnel connected: it is stopped, and nothing is left running for it.
#[test]
fn a_start_canceled_while_connecting_leaves_nothing_running() {
    let d = device();
    let r = runtime(ApprovalMode::AutoLog);
    let tunnels = Tunnels::default();
    let web = host(&d, &r, "web-1", true);
    let id = created(&d, &r, &tunnels);
    let route = Route::to(&web, true);
    let launches = Launches::new(&d, &tunnels, None);
    let cancel = CancelToken::default();
    let entry = Mutex::new(None);
    let error = start(&d.env(), &r, &tunnels, &route.connector(), &json!({"tunnel": "Database"}), RequestContext::default(), &cancel, &never, &|rule, approved, mode, who| {
        let started = launches.launch(rule, approved, mode, who)?;
        *entry.lock().unwrap() = Some(Arc::clone(&started));
        cancel.cancel();
        Ok(started)
    })
    .unwrap_err();
    assert_eq!(error, "Tunnel start was canceled.");
    let entry = entry.lock().unwrap().take().unwrap();
    assert!(matches!(entry.live().phase, TunnelPhase::Stopping), "{:?}", entry.live().phase);
    assert!(tunnels.busy(&id), "the worker finishes the stop");
}

#[test]
fn a_tunnel_still_connecting_says_so_instead_of_starting_again() {
    let d = device();
    let r = runtime(ApprovalMode::Ask);
    let tunnels = Tunnels::default();
    let web = host(&d, &r, "web-1", true);
    let id = created(&d, &r, &tunnels);
    let entry = start_here(&d, &tunnels, &id);
    entry.set_live(TunnelLive { phase: TunnelPhase::Connecting, ..TunnelLive::default() });
    let route = Route::to(&web, true);
    let launches = Launches::new(&d, &tunnels, None);
    let value = start(&d.env(), &r, &tunnels, &route.connector(), &json!({"tunnel": id}), RequestContext::default(), &CancelToken::default(), &never, &|rule, approved, mode, who| launches.launch(rule, approved, mode, who)).unwrap();
    assert_eq!(value["message"], "The tunnel is already starting; read list_tunnels for its state.");
    assert_eq!(value["tunnel"]["state"], "connecting");
    assert!(launches.given().is_empty());
}

/// Sixteen tunnels already active: refused before the window, which could only lead to a start that fails.
#[test]
fn a_start_beyond_the_limit_is_refused_before_the_window() {
    let d = device();
    let r = runtime(ApprovalMode::Ask);
    let tunnels = Tunnels::default();
    let web = host(&d, &r, "web-1", true);
    created(&d, &r, &tunnels);
    for n in 0..16 {
        let rule = rule_on(&web, &format!("00000000000001{n:02x}"), &format!("Busy {n}"));
        save_directly(&d, rule.clone());
        start_here(&d, &tunnels, &rule.id);
    }
    let route = Route::to(&web, true);
    let launches = Launches::new(&d, &tunnels, None);
    let error = start(&d.env(), &r, &tunnels, &route.connector(), &json!({"tunnel": "Database"}), RequestContext::default(), &CancelToken::default(), &never, &|rule, approved, mode, who| launches.launch(rule, approved, mode, who)).unwrap_err();
    assert_eq!(error, "16 tunnels are already active on this computer; stop one first.");
    assert!(launches.given().is_empty());
}

/// The rule was edited in the panel while the window was open: the approval does not cover the new one.
#[test]
fn a_start_whose_rule_changed_during_the_window_starts_nothing() {
    let d = device();
    let r = runtime(ApprovalMode::Ask);
    let tunnels = Tunnels::default();
    let web = host(&d, &r, "web-1", true);
    created(&d, &r, &tunnels);
    let route = Route::to(&web, true);
    let launches = Launches::new(&d, &tunnels, Some(running(15432, None)));
    let error = start(&d.env(), &r, &tunnels, &route.connector(), &json!({"tunnel": "Database"}), RequestContext::default(), &CancelToken::default(), &|_| {
        let current = saved(&d).pop().unwrap();
        let mut other = current.clone();
        other.forward.bind_address = "0.0.0.0".into();
        crate::sync::record_commands::edit_records(&d.env(), |state, now| {
            tunnel_rules::set(state, None, &current.id, Some(&current), Some(other.clone()), now).map_err(|e| AppError::Other(e.to_string()))
        })
        .unwrap();
        ApprovalDecision::Allow
    }, &|rule, approved, mode, who| launches.launch(rule, approved, mode, who))
    .unwrap_err();
    assert_eq!(error, TUNNEL_CHANGED);
    assert!(launches.given().is_empty());
}

/// A server key that needs the person's decision reaches the client in `ssh_exec`'s words.
#[test]
fn a_start_that_needs_the_person_says_so_as_ssh_exec_does() {
    let d = device();
    let r = runtime(ApprovalMode::AutoLog);
    let tunnels = Tunnels::default();
    let web = host(&d, &r, "web-1", true);
    created(&d, &r, &tunnels);
    let route = Route::to(&web, true);
    let refused = TunnelLive { phase: TunnelPhase::Error, forwarding: ForwardStatus { error: Some("needs interaction: host key confirmation is required".into()), ..Default::default() }, started_by: None };
    let launches = Launches::new(&d, &tunnels, Some(refused));
    let error = start(&d.env(), &r, &tunnels, &route.connector(), &json!({"tunnel": "Database"}), RequestContext::default(), &CancelToken::default(), &never, &|rule, approved, mode, who| launches.launch(rule, approved, mode, who)).unwrap_err();
    assert_eq!(error, "needs interaction: host key confirmation is required");
}

/// What the app's worker asks while an AI client's tunnel connects and runs, over the real permission rules: turning AI access off
/// or taking the host's permission away ends it; another mode refuses a start still connecting but does not stop a running tunnel.
#[test]
fn an_ai_clients_tunnel_ends_with_its_access() {
    let d = device();
    let r = runtime(ApprovalMode::Ask);
    let web = host(&d, &r, "web-1", true);
    let state = snapshot(&d);
    let authorize = |policy: &McpPolicy| permissions::ensure_record(policy, &state, &web);
    let policy = || r.policy.lock().unwrap().clone();
    assert_eq!(may_connect(&policy(), ApprovalMode::Ask, authorize), Ok(()));
    assert_eq!(access_ended(&policy(), authorize), None);
    assert_eq!(may_connect(&policy(), ApprovalMode::AutoLog, authorize), Err("MCP policy changed; request approval again.".into()));
    r.policy.lock().unwrap().approval_mode = ApprovalMode::AutoLog;
    assert_eq!(access_ended(&policy(), authorize), None, "another mode does not stop a running tunnel");
    r.policy.lock().unwrap().allowed_hosts.clear();
    assert_eq!(access_ended(&policy(), authorize).as_deref(), Some(crate::session::tunnels::AI_ACCESS_ENDED));
    assert!(may_connect(&policy(), ApprovalMode::AutoLog, authorize).is_err());
    r.policy.lock().unwrap().allowed_hosts.insert(web.clone());
    r.policy.lock().unwrap().enabled = false;
    assert_eq!(access_ended(&policy(), authorize).as_deref(), Some(crate::session::tunnels::AI_ACCESS_ENDED));
    assert!(may_connect(&policy(), ApprovalMode::AutoLog, authorize).is_err());
}

// ---- stop_tunnel ----

#[test]
fn stopping_needs_no_window_and_leaves_a_stopped_tunnel_alone() {
    let d = device();
    let r = runtime(ApprovalMode::Ask);
    let tunnels = Tunnels::default();
    host(&d, &r, "web-1", true);
    let id = created(&d, &r, &tunnels);
    let entry = start_here(&d, &tunnels, &id);
    // The worker: once stopped, it finishes.
    let worker = Arc::clone(&entry);
    let finishing = thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_secs(5);
        while !matches!(worker.live().phase, TunnelPhase::Stopping) && Instant::now() < deadline {
            thread::sleep(Duration::from_millis(5));
        }
        worker.set_live(TunnelLive::default());
    });
    let value = stop(&d.env(), &r, &tunnels, &json!({"tunnel": "Database"}), RequestContext::default(), &CancelToken::default()).unwrap();
    finishing.join().unwrap();
    assert_eq!(value["message"], "Tunnel stopped.");
    assert_eq!(value["tunnel"]["state"], "stopped");
    assert_eq!(last_outcome(&r), "tunnel_stopped");
    let audited = r.recent.lock().unwrap().len();
    let value = stop(&d.env(), &r, &tunnels, &json!({"tunnel": "Database"}), RequestContext::default(), &CancelToken::default()).unwrap();
    assert_eq!(value["message"], "The tunnel is not running.");
    assert_eq!(r.recent.lock().unwrap().len(), audited, "nothing stopped, nothing audited");
}
