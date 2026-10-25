use super::*;
use crate::session::testing::{Decision, FakeConfirmer, FakeDirectory, FakeKeys, FakeOwner};
use crate::ssh::{
    fake::{default_server_key, FakeEngine},
    AuthMethod,
};
use crate::sync::testkit::MemKeychain;
use crate::sync::{
    fake_relay::FakeRelay,
    testkit::{TestClock, TestDevice},
};
use std::sync::atomic::AtomicUsize;

fn device() -> TestDevice {
    let d = TestDevice::new("management", &FakeRelay::new(), &TestClock::new());
    let record_runtime::StartupProbe::Records { mut state, .. } =
        record_runtime::probe_startup(&d.env().state_path, "management")
    else {
        panic!("fresh records")
    };
    state.relay_url = crate::sync::testkit::RELAY_URL.into();
    record_runtime::activate_probe(
        &mut d.runtime.core.lock().unwrap(),
        record_runtime::StartupProbe::Records {
            state,
            fresh: false,
        },
    )
    .unwrap();
    d
}
fn runtime(mode: ApprovalMode) -> McpRuntime {
    let r = McpRuntime::default();
    *r.policy.lock().unwrap() = McpPolicy {
        enabled: true,
        approval_mode: mode,
        allowed_hosts: BTreeSet::new(),
        ..Default::default()
    };
    r
}
fn input() -> Value {
    json!({"alias":"fixture-web","hostname":"fixture.invalid","user":"ops","port":2222,"tags":["fixture"]})
}
fn snapshot(d: &TestDevice) -> SyncStateV3 {
    record_runtime::snapshot(&d.env()).unwrap().0
}
#[test]
fn creation_always_needs_approval_including_auto_log_and_never_grants_ai_or_pins() {
    for mode in [ApprovalMode::Ask, ApprovalMode::AutoLog] {
        let d = device();
        let r = runtime(mode);
        let asked = AtomicUsize::new(0);
        let value = create(
            &d.env(),
            &r,
            &input(),
            RequestContext::default(),
            &CancelToken::default(),
            &|q| {
                asked.fetch_add(1, Ordering::SeqCst);
                assert!(
                    repo::list_hosts(&snapshot(&d)).unwrap().is_empty(),
                    "nothing saved before consent"
                );
                let proposal = q.host_proposal.as_ref().unwrap();
                assert!(proposal
                    .settings
                    .contains(&("Hostname".into(), "fixture.invalid".into())));
                assert!(proposal.settings.contains(&("Port".into(), "2222".into())));
                assert!(q.command.is_empty());
                ApprovalDecision::Allow
            },
        )
        .unwrap();
        assert_eq!(asked.load(Ordering::SeqCst), 1);
        assert_eq!(value["ai_access_allowed"], false);
        let hosts = repo::list_hosts(&snapshot(&d)).unwrap();
        assert_eq!(hosts.len(), 1);
        assert_eq!(hosts[0].host.payload.alias, "fixture-web");
        assert!(hosts[0].host.payload.host_key.is_none());
        assert!(r.policy.lock().unwrap().allowed_hosts.is_empty());
        assert!(r.records_active.lock().unwrap().is_empty());
    }
}
/// The window words each proposal by its kind (design 2026-10-26, AI edits): a creation says so.
#[test]
fn the_creation_proposal_says_which_kind_it_is() {
    let d = device();
    let r = runtime(ApprovalMode::Ask);
    let asked = AtomicUsize::new(0);
    let result = create(&d.env(), &r, &input(), RequestContext::default(), &CancelToken::default(), &|q| {
        asked.fetch_add(1, Ordering::SeqCst);
        assert_eq!(q.host_proposal.as_ref().unwrap().kind, proposal_kinds::CREATE_HOST);
        ApprovalDecision::Deny
    });
    assert!(result.is_err());
    assert_eq!(asked.load(Ordering::SeqCst), 1);
}
#[test]
fn denied_canceled_expired_and_policy_revoked_creation_leave_no_host() {
    for decision in [
        ApprovalDecision::Deny,
        ApprovalDecision::Cancel,
        ApprovalDecision::TimedOut,
    ] {
        let d = device();
        let r = runtime(ApprovalMode::Ask);
        assert!(create(
            &d.env(),
            &r,
            &input(),
            RequestContext::default(),
            &CancelToken::default(),
            &|_| decision
        )
        .is_err());
        assert!(repo::list_hosts(&snapshot(&d)).unwrap().is_empty());
    }
    for cancel_it in [true, false] {
        let d = device();
        let r = runtime(ApprovalMode::Ask);
        let cancel = CancelToken::default();
        assert!(create(
            &d.env(),
            &r,
            &input(),
            RequestContext::default(),
            &cancel,
            &|_| {
                if cancel_it {
                    cancel.cancel()
                } else {
                    r.policy.lock().unwrap().enabled = false;
                }
                ApprovalDecision::Allow
            }
        )
        .is_err());
        assert!(repo::list_hosts(&snapshot(&d)).unwrap().is_empty());
        assert!(r.records_active.lock().unwrap().is_empty());
    }
}
#[test]
fn private_data_and_duplicate_names_are_rejected_without_requesting_approval() {
    let d = device();
    let r = runtime(ApprovalMode::Ask);
    for field in [
        "password",
        "private_key",
        "host_key",
        "imported",
        "notes",
        "ai_access_allowed",
    ] {
        let mut p = input();
        p[field] = json!("secret-must-not-be-accepted");
        let error = create(
            &d.env(),
            &r,
            &p,
            RequestContext::default(),
            &CancelToken::default(),
            &|_| panic!("invalid input must not reach approval"),
        )
        .unwrap_err();
        assert!(!error.contains("secret-must-not-be-accepted"));
    }
    create(
        &d.env(),
        &r,
        &input(),
        RequestContext::default(),
        &CancelToken::default(),
        &|_| ApprovalDecision::Allow,
    )
    .unwrap();
    assert!(create(
        &d.env(),
        &r,
        &input(),
        RequestContext::default(),
        &CancelToken::default(),
        &|_| panic!("duplicate alias must be rejected before approval")
    )
    .is_err());
    assert_eq!(repo::list_hosts(&snapshot(&d)).unwrap().len(), 1);
}
#[test]
fn a_concurrent_conflicting_save_cannot_overwrite_the_existing_host() {
    let d = device();
    let r = runtime(ApprovalMode::Ask);
    let result = create(
        &d.env(),
        &r,
        &input(),
        RequestContext::default(),
        &CancelToken::default(),
        &|_| {
            crate::sync::record_commands::edit_records(&d.env(), |s, now| {
                repo::create_host(
                    s,
                    "0000000000000001",
                    HostScope::Local,
                    payload(&input()).unwrap(),
                    now,
                )
                .map_err(|e| AppError::Other(e.to_string()))
            })
            .unwrap();
            ApprovalDecision::Allow
        },
    );
    assert!(result.is_err());
    let hosts = repo::list_hosts(&snapshot(&d)).unwrap();
    assert_eq!(hosts.len(), 1);
    assert_eq!(hosts[0].host.id, "0000000000000001");
}
#[test]
fn explicit_verification_requires_host_permission_and_human_trust_even_in_auto_log() {
    for mode in [ApprovalMode::Ask, ApprovalMode::AutoLog] {
        let r = runtime(mode);
        let directory = FakeDirectory::new().with_host(
            "web",
            AuthMethod::Key {
                key_id: "missing".into(),
            },
        );
        let engine = FakeEngine::new();
        let confirmer = FakeConfirmer::deciding(vec![Decision::Trust]);
        let keys = FakeKeys::new();
        let keychain = MemKeychain::default();
        let connector = Connector {
            grants: crate::session::grants::GrantGates::for_tests(),
            directory: &directory,
            engine: &engine,
            confirmer: &confirmer,
            keys: &keys,
            keychain: &keychain,
        };
        assert!(verify(
            &r,
            &connector,
            "web",
            RequestContext::default(),
            &CancelToken::default(),
            &FakeOwner::default(),
            &ensure_allowed,
        )
        .is_err());
        assert!(confirmer.asked().is_empty());
        r.policy
            .lock()
            .unwrap()
            .allowed_hosts
            .insert("id-web".into());
        let value = verify(
            &r,
            &connector,
            "web",
            RequestContext::default(),
            &CancelToken::default(),
            &FakeOwner::default(),
            &ensure_allowed,
        )
        .unwrap();
        assert_eq!(value["fingerprint"], default_server_key().fingerprint);
        assert_eq!(confirmer.asked().len(), 1);
        assert!(
            engine.events().is_empty(),
            "verification cannot authenticate, execute or open a shell"
        );
        assert!(r.records_active.lock().unwrap().is_empty());
    }
}
#[test]
fn records_tool_inventory_is_explicit_and_legacy_tools_remain_compatible() {
    let records_value = tools_for_mode("records");
    let records = records_value.as_array().unwrap();
    let names: Vec<_> = records
        .iter()
        .map(|t| t["name"].as_str().unwrap())
        .collect();
    assert_eq!(
        names,
        vec![
            "list_hosts",
            "get_host",
            "ssh_exec",
            "create_host",
            "verify_host_key",
            "update_host",
            "set_transport",
            "remove_transport"
        ]
    );
    let legacy_value = tools_for_mode("legacy");
    let legacy = legacy_value.as_array().unwrap();
    assert_eq!(legacy.len(), 3);
    assert!(!legacy.iter().any(|t| t["name"] == "create_host"));
}

#[test]
fn changing_storage_during_approval_requires_a_new_proposal() {
    let d = device();
    let r = runtime(ApprovalMode::Ask);
    let result = create(
        &d.env(),
        &r,
        &input(),
        RequestContext::default(),
        &CancelToken::default(),
        &|_| {
            crate::sync::record_account::create_account(&d.env(), "management").unwrap();
            record_library::enable(&d.env(), false).unwrap();
            ApprovalDecision::Allow
        },
    );
    assert!(result.unwrap_err().contains("storage changed"));
    assert!(repo::list_hosts(&snapshot(&d)).unwrap().is_empty());
}
#[test]
fn revoked_permission_or_cancel_during_trust_never_saves_a_pin() {
    use crate::session::connect::{HostKeyConfirmer, HostKeyQuestion};
    use crate::session::directory::HostDirectory;
    struct Revoke<'a>(&'a McpRuntime, bool);
    impl HostKeyConfirmer for Revoke<'_> {
        fn confirm(&self, q: &HostKeyQuestion, c: &CancelToken) -> Option<String> {
            if self.1 {
                c.cancel();
            } else {
                self.0.policy.lock().unwrap().allowed_hosts.clear();
            }
            Some(q.fingerprint.clone())
        }
    }
    for cancel_it in [true, false] {
        let r = runtime(ApprovalMode::Ask);
        r.policy
            .lock()
            .unwrap()
            .allowed_hosts
            .insert("id-web".into());
        let directory = FakeDirectory::new().with_host("web", AuthMethod::Password);
        let confirmer = Revoke(&r, cancel_it);
        let result = verify(
            &r,
            &Connector {
                grants: crate::session::grants::GrantGates::for_tests(),
                directory: &directory,
                engine: &FakeEngine::new(),
                confirmer: &confirmer,
                keys: &FakeKeys::new(),
                keychain: &MemKeychain::default(),
            },
            "web",
            RequestContext::default(),
            &CancelToken::default(),
            &FakeOwner::default(),
            &ensure_allowed,
        );
        assert!(result.is_err());
        assert!(directory
            .pinned(&crate::ssh::HostId::from("id-web"))
            .unwrap()
            .is_none());
        assert!(r.records_active.lock().unwrap().is_empty());
    }
}

#[test]
fn native_creation_review_discloses_existing_group_access_and_rejects_stale_grant() {
    let group_id = "0000000000000001";
    for revoke in [false, true] {
        let d = device();
        crate::sync::record_commands::edit_records(&d.env(), |state, now| {
            crate::sync::record_groups::create_group(state, group_id, HostScope::Local,
                serde_json::from_value(json!({"schema":1,"name":"Operations","defaults":{}})).unwrap(), true, now)
                .map_err(|e| AppError::Other(e.to_string()))
        }).unwrap();
        let r = runtime(ApprovalMode::AutoLog);
        permissions::change_group(&r.policy, &snapshot(&d), &HostScope::Local, group_id, true, |_| Ok(())).unwrap();
        let mut proposal = input();
        proposal["group_id"] = json!(group_id);
        let value = create(&d.env(), &r, &proposal, RequestContext::default(), &CancelToken::default(), &|request| {
            assert!(request.host_proposal.as_ref().unwrap().settings.contains(&("AI access".into(), "Allowed by existing Group permission".into())));
            if revoke { r.policy.lock().unwrap().allowed_groups.clear(); }
            ApprovalDecision::Allow
        });
        if revoke {
            assert!(value.is_err());
            assert!(repo::list_hosts(&snapshot(&d)).unwrap().is_empty());
        } else {
            assert_eq!(value.unwrap()["ai_access_allowed"], true);
            assert!(r.policy.lock().unwrap().allowed_hosts.is_empty());
        }
    }
}


// ---- update_host (design 2026-10-26, AI edits) ----

/// A host the client may use: `fixture-web`, created through `create` with consent and then allowed individually.
fn created(d: &TestDevice, r: &McpRuntime) -> String {
    let value = create(&d.env(), r, &input(), RequestContext::default(), &CancelToken::default(), &|_| ApprovalDecision::Allow).unwrap();
    let id = value["host"]["id"].as_str().unwrap().to_string();
    r.policy.lock().unwrap().allowed_hosts.insert(id.clone());
    id
}

fn host_of(d: &TestDevice, id: &str) -> repo::HostView {
    repo::get_host(&snapshot(d), id).unwrap()
}

fn rows(q: &McpPendingRequest) -> Vec<(String, String)> {
    q.host_proposal.as_ref().unwrap().settings.clone()
}

fn last_outcome(r: &McpRuntime) -> String {
    r.recent.lock().unwrap().front().unwrap().outcome.clone()
}

#[test]
fn an_update_asks_shows_old_and_new_and_saves_only_on_consent() {
    for mode in [ApprovalMode::Ask, ApprovalMode::AutoLog] {
        let d = device();
        let r = runtime(mode);
        let id = created(&d, &r);
        let asked = AtomicUsize::new(0);
        let value = update(&d.env(), &r, &json!({"alias":"fixture-web","hostname":"10.20.0.8","port":22}), RequestContext::default(), &CancelToken::default(), &|q| {
            asked.fetch_add(1, Ordering::SeqCst);
            assert_eq!(q.host_proposal.as_ref().unwrap().kind, proposal_kinds::UPDATE_HOST);
            assert_eq!(q.host_id.as_deref(), Some(id.as_str()));
            let rows = rows(q);
            assert!(rows.contains(&("Hostname".into(), "fixture.invalid → 10.20.0.8".into())), "{rows:?}");
            assert!(rows.contains(&("Port".into(), "2222 → 22".into())), "{rows:?}");
            assert!(!rows.iter().any(|(label, _)| label == "Username"), "an unchanged field is not a row: {rows:?}");
            assert_eq!(host_of(&d, &id).effective_payload.hostname, "fixture.invalid", "nothing saved before consent");
            ApprovalDecision::Allow
        })
        .unwrap();
        assert_eq!(asked.load(Ordering::SeqCst), 1);
        assert_eq!(value["host"]["hostname"], "10.20.0.8");
        assert_eq!(value["message"], "Host saved.");
        let host = host_of(&d, &id);
        assert_eq!((host.effective_payload.hostname.as_str(), host.effective_payload.port), ("10.20.0.8", 22));
        assert_eq!(last_outcome(&r), "host_updated");
        assert!(r.records_active.lock().unwrap().is_empty());
    }
}

#[test]
fn an_update_of_a_pinned_address_says_the_key_will_be_verified_again() {
    let d = device();
    let r = runtime(ApprovalMode::Ask);
    let id = created(&d, &r);
    crate::sync::record_commands::edit_records(&d.env(), |state, now| {
        let host = repo::get_host(state, &id).map_err(|e| AppError::Other(e.to_string()))?;
        let endpoint = repo::HostEndpoint { hostname: host.effective_payload.hostname.clone(), port: host.effective_payload.port };
        // A key whose fingerprint matches its blob, as the repository checks (the test key of the slot rules).
        let public = ssh_key::PublicKey::from_openssh(crate::sync::slot_rules::test_keys::PLAIN_PUBLIC).unwrap();
        let key = crate::sync::records_v3::StoredHostKey {
            algorithm: public.algorithm().as_str().into(),
            public_key: crate::sync::slot_rules::test_keys::PLAIN_PUBLIC.split_whitespace().nth(1).unwrap().into(),
            fingerprint: public.fingerprint(ssh_key::HashAlg::Sha256).to_string(),
            pinned_at_ms: now,
            pinned_by_device_id: state.device_id.clone(),
        };
        repo::pin_host_key(state, &id, &endpoint, None, key, now).map_err(|e| AppError::Other(e.to_string()))
    })
    .unwrap();
    assert!(host_of(&d, &id).host.payload.host_key.is_some(), "pinned");
    let value = update(&d.env(), &r, &json!({"alias":"fixture-web","hostname":"10.20.0.8"}), RequestContext::default(), &CancelToken::default(), &|q| {
        assert!(rows(q).contains(&("Server key".into(), "pinned → verified again at the next connection".into())), "{:?}", rows(q));
        ApprovalDecision::Allow
    })
    .unwrap();
    assert!(host_of(&d, &id).host.payload.host_key.is_none(), "the pin is gone with the address");
    assert!(value["message"].as_str().unwrap().contains("verify_host_key"), "{}", value["message"]);
}

#[test]
fn an_update_with_nothing_to_change_or_only_the_identifier_is_refused_without_a_window() {
    let d = device();
    let r = runtime(ApprovalMode::Ask);
    let _id = created(&d, &r);
    let never = |_: &McpPendingRequest| -> ApprovalDecision { panic!("no window") };
    assert_eq!(update(&d.env(), &r, &json!({"alias":"fixture-web"}), RequestContext::default(), &CancelToken::default(), &never).unwrap_err(), "Provide at least one setting to change.");
    assert_eq!(update(&d.env(), &r, &json!({"alias":"fixture-web","hostname":"fixture.invalid","tags":["fixture"]}), RequestContext::default(), &CancelToken::default(), &never).unwrap_err(), "Nothing would change.");
}

#[test]
fn an_update_needs_the_hosts_ai_permission_and_answers_as_get_host_does() {
    let d = device();
    let r = runtime(ApprovalMode::Ask);
    let id = created(&d, &r);
    r.policy.lock().unwrap().allowed_hosts.clear();
    let never = |_: &McpPendingRequest| -> ApprovalDecision { panic!("no window") };
    assert_eq!(update(&d.env(), &r, &json!({"alias":"fixture-web","port":22}), RequestContext::default(), &CancelToken::default(), &never).unwrap_err(), format!("host '{id}' is not allowed for AI access"));
    let unknown = repo::find_by_alias(&snapshot(&d), "nope").unwrap_err().to_string();
    assert_eq!(update(&d.env(), &r, &json!({"alias":"nope","port":22}), RequestContext::default(), &CancelToken::default(), &never).unwrap_err(), unknown);
    assert_eq!(host_of(&d, &id).effective_payload.port, 2222);
}

#[test]
fn an_inherited_field_becomes_the_hosts_own_when_the_client_changes_it() {
    let d = device();
    let r = runtime(ApprovalMode::Ask);
    let group_id = "0000000000000031";
    let id = "0000000000000041";
    crate::sync::record_commands::edit_records(&d.env(), |state, now| {
        let state = crate::sync::record_groups::create_group(state, group_id, HostScope::Local, serde_json::from_value(json!({"schema":1,"name":"Operations","defaults":{"port":2222}})).unwrap(), true, now).map_err(|e| AppError::Other(e.to_string()))?;
        let payload = serde_json::from_value(json!({"schema":3,"alias":"grouped","hostname":"g.invalid","user":"ops","auth":"password","group_id":group_id,"inherit":["port"]})).unwrap();
        repo::create_host(&state, id, HostScope::Local, payload, now).map_err(|e| AppError::Other(e.to_string()))
    })
    .unwrap();
    r.policy.lock().unwrap().allowed_hosts.insert(id.into());
    assert_eq!(host_of(&d, id).effective_payload.port, 2222, "inherited from the Group");
    update(&d.env(), &r, &json!({"alias":"grouped","port":2200}), RequestContext::default(), &CancelToken::default(), &|q| {
        assert!(rows(q).contains(&("Port".into(), "2222 (from Group Operations) → 2200".into())), "{:?}", rows(q));
        ApprovalDecision::Allow
    })
    .unwrap();
    let host = host_of(&d, id);
    assert_eq!(host.effective_payload.port, 2200);
    assert!(host.host.payload.inherit.is_empty(), "the port is the host's own now: {:?}", host.host.payload.inherit);
}

#[test]
fn a_denied_timed_out_or_cancelled_update_changes_nothing_and_is_audited() {
    for (decision, sentence) in [(ApprovalDecision::Deny, "Host update was denied."), (ApprovalDecision::TimedOut, "Host update approval timed out."), (ApprovalDecision::Cancel, "Host update was canceled.")] {
        let d = device();
        let r = runtime(ApprovalMode::Ask);
        let id = created(&d, &r);
        assert_eq!(update(&d.env(), &r, &json!({"alias":"fixture-web","hostname":"10.20.0.8"}), RequestContext::default(), &CancelToken::default(), &|_| decision).unwrap_err(), sentence);
        assert_eq!(host_of(&d, &id).effective_payload.hostname, "fixture.invalid");
        assert_eq!(last_outcome(&r), "host_update_not_completed");
        assert!(r.records_active.lock().unwrap().is_empty());
    }
}

#[test]
fn an_update_over_a_host_changed_meanwhile_is_refused() {
    let d = device();
    let r = runtime(ApprovalMode::Ask);
    let id = created(&d, &r);
    let error = update(&d.env(), &r, &json!({"alias":"fixture-web","hostname":"10.20.0.8"}), RequestContext::default(), &CancelToken::default(), &|_| {
        crate::sync::record_commands::edit_records(&d.env(), |state, now| {
            let host = repo::get_host(state, &id).map_err(|e| AppError::Other(e.to_string()))?;
            let mut payload = host.host.payload.clone();
            payload.hostname = "other.invalid".into();
            repo::update_host(state, &id, &host.revision, payload, now).map_err(|e| AppError::Other(e.to_string()))
        })
        .unwrap();
        ApprovalDecision::Allow
    })
    .unwrap_err();
    assert_eq!(error, "The host changed while the request was open; read it again and retry.");
    assert_eq!(host_of(&d, &id).effective_payload.hostname, "other.invalid", "the other change stands");
}

#[test]
fn an_update_rejects_private_data_group_moves_and_a_loop_through_itself() {
    let d = device();
    let r = runtime(ApprovalMode::Ask);
    let id = created(&d, &r);
    let never = |_: &McpPendingRequest| -> ApprovalDecision { panic!("no window") };
    for input in [json!({"alias":"fixture-web","password":"x"}), json!({"alias":"fixture-web","group_id":"0000000000000031"}), json!({"alias":"fixture-web","host_key":{}})] {
        let error = update(&d.env(), &r, &input, RequestContext::default(), &CancelToken::default(), &never).unwrap_err();
        assert!(error.starts_with("Provide public connection settings only."), "{input}: {error}");
    }
    assert!(update(&d.env(), &r, &json!({"alias":"fixture-web","jump":[id]}), RequestContext::default(), &CancelToken::default(), &never).is_err());
    assert_eq!(host_of(&d, &id).effective_payload.hostname, "fixture.invalid");
}


// ---- set_transport / remove_transport (design 2026-10-26, AI edits) ----

fn transport_of(d: &TestDevice, id: &str) -> Option<crate::sync::transports::HostTransport> {
    crate::sync::transports::get(&snapshot(d), id)
}

fn pam_transport() -> Value {
    json!({"alias":"fixture-web","project":"knowknow-prod","zone":"asia-east1-b","instance":"jumpbox","account":"frank@retower.io","os_login":false,"pam":{"entitlements":["prod-operate","prod-admin"]}})
}

fn never(_: &McpPendingRequest) -> ApprovalDecision {
    panic!("no window")
}

/// The transport as saved, for the assertions.
fn kind_of(transport: &crate::sync::transports::HostTransport) -> (String, String, String, Option<String>, bool, Option<crate::sync::transports::PamCheck>) {
    let crate::sync::transports::TransportKind::GcpIap { project, zone, instance, account, os_login, pam, .. } = &transport.kind;
    (project.clone(), zone.clone(), instance.clone(), account.clone(), *os_login, pam.clone())
}

#[test]
fn a_new_transport_needs_its_place_and_shows_every_field() {
    for mode in [ApprovalMode::Ask, ApprovalMode::AutoLog] {
        let d = device();
        let r = runtime(mode);
        let id = created(&d, &r);
        assert_eq!(
            set_transport(&d.env(), &r, &json!({"alias":"fixture-web","pam":{"entitlements":["prod-operate"]}}), RequestContext::default(), &CancelToken::default(), &never).unwrap_err(),
            "Provide the project, zone and instance of a new transport."
        );
        let asked = AtomicUsize::new(0);
        let value = set_transport(&d.env(), &r, &pam_transport(), RequestContext::default(), &CancelToken::default(), &|q| {
            asked.fetch_add(1, Ordering::SeqCst);
            assert_eq!(q.host_proposal.as_ref().unwrap().kind, proposal_kinds::SET_TRANSPORT);
            let rows = rows(q);
            for row in [("Project", "knowknow-prod"), ("OS Login", "off"), ("PAM entitlements", "prod-operate, prod-admin"), ("Grant duration", "30 min"), ("Account", "frank@retower.io")] {
                assert!(rows.contains(&(row.0.into(), row.1.into())), "{row:?} in {rows:?}");
            }
            assert!(transport_of(&d, &id).is_none(), "nothing saved before consent");
            ApprovalDecision::Allow
        })
        .unwrap();
        assert_eq!(asked.load(Ordering::SeqCst), 1);
        let (project, zone, instance, account, os_login, pam) = kind_of(&transport_of(&d, &id).expect("saved"));
        assert_eq!((project.as_str(), zone.as_str(), instance.as_str(), account.as_deref(), os_login), ("knowknow-prod", "asia-east1-b", "jumpbox", Some("frank@retower.io"), false));
        let pam = pam.unwrap();
        assert_eq!((pam.entitlements.clone(), pam.location.as_str(), pam.duration_secs, pam.justification), (vec!["prod-operate".to_string(), "prod-admin".to_string()], "global", 1800, None));
        assert_eq!(value["host"]["transport"]["project"], "knowknow-prod");
        assert_eq!(value["message"], "Transport saved.");
        assert_eq!(last_outcome(&r), "transport_set");
        assert!(r.records_active.lock().unwrap().is_empty());
    }
}

#[test]
fn a_transport_change_keeps_what_was_not_sent_and_shows_old_to_new() {
    let d = device();
    let r = runtime(ApprovalMode::Ask);
    let id = created(&d, &r);
    set_transport(&d.env(), &r, &pam_transport(), RequestContext::default(), &CancelToken::default(), &|_| ApprovalDecision::Allow).unwrap();
    crate::sync::record_commands::edit_records(&d.env(), |state, now| {
        crate::sync::transports::remember_grant_request(state, &id, "restart app-api", 1800, now).map_err(|e| AppError::Other(e.to_string()))
    })
    .unwrap();
    set_transport(&d.env(), &r, &json!({"alias":"fixture-web","pam":{"entitlements":["prod-admin"],"duration_minutes":45}}), RequestContext::default(), &CancelToken::default(), &|q| {
        let rows = rows(q);
        assert!(rows.contains(&("PAM entitlements".into(), "prod-operate, prod-admin → prod-admin".into())), "{rows:?}");
        assert!(rows.contains(&("Grant duration".into(), "30 min → 45 min".into())), "{rows:?}");
        assert!(!rows.iter().any(|(label, _)| label == "Instance"), "unchanged fields are not rows: {rows:?}");
        ApprovalDecision::Allow
    })
    .unwrap();
    let (_, _, instance, _, _, pam) = kind_of(&transport_of(&d, &id).unwrap());
    let pam = pam.unwrap();
    assert_eq!((instance.as_str(), pam.entitlements.clone(), pam.duration_secs, pam.justification.as_deref()), ("jumpbox", vec!["prod-admin".to_string()], 2700, Some("restart app-api")));
    set_transport(&d.env(), &r, &json!({"alias":"fixture-web","pam":null}), RequestContext::default(), &CancelToken::default(), &|q| {
        assert!(rows(q).contains(&("PAM entitlements".into(), "prod-admin → none".into())), "{:?}", rows(q));
        ApprovalDecision::Allow
    })
    .unwrap();
    assert!(kind_of(&transport_of(&d, &id).unwrap()).5.is_none(), "the check is gone");
}

#[test]
fn a_transport_that_would_not_change_or_fails_the_editors_rules_gets_no_window() {
    let d = device();
    let r = runtime(ApprovalMode::Ask);
    let _id = created(&d, &r);
    set_transport(&d.env(), &r, &pam_transport(), RequestContext::default(), &CancelToken::default(), &|_| ApprovalDecision::Allow).unwrap();
    assert_eq!(set_transport(&d.env(), &r, &pam_transport(), RequestContext::default(), &CancelToken::default(), &never).unwrap_err(), "Nothing would change.");
    assert_eq!(set_transport(&d.env(), &r, &json!({"alias":"fixture-web","zone":"Asia East"}), RequestContext::default(), &CancelToken::default(), &never).unwrap_err(), "Enter the zone of the instance.");
    assert_eq!(set_transport(&d.env(), &r, &json!({"alias":"fixture-web","pam":{"entitlements":[]}}), RequestContext::default(), &CancelToken::default(), &never).unwrap_err(), "Enter at least one PAM entitlement.");
}

#[test]
fn removing_a_transport_asks_and_restores_the_saved_address() {
    let d = device();
    let r = runtime(ApprovalMode::Ask);
    let id = created(&d, &r);
    assert_eq!(remove_transport(&d.env(), &r, &json!({"alias":"fixture-web"}), RequestContext::default(), &CancelToken::default(), &never).unwrap_err(), "This host has no transport.");
    set_transport(&d.env(), &r, &pam_transport(), RequestContext::default(), &CancelToken::default(), &|_| ApprovalDecision::Allow).unwrap();
    let value = remove_transport(&d.env(), &r, &json!({"alias":"fixture-web"}), RequestContext::default(), &CancelToken::default(), &|q| {
        assert_eq!(q.host_proposal.as_ref().unwrap().kind, proposal_kinds::REMOVE_TRANSPORT);
        assert!(rows(q).contains(&("Instance".into(), "jumpbox".into())), "{:?}", rows(q));
        assert!(transport_of(&d, &id).is_some(), "still there before consent");
        ApprovalDecision::Allow
    })
    .unwrap();
    assert!(transport_of(&d, &id).is_none());
    assert_eq!(value["message"], "Transport removed; the host is reached at its saved address.");
    assert_eq!(value["host"]["transport"], Value::Null);
    assert_eq!(last_outcome(&r), "transport_removed");
    set_transport(&d.env(), &r, &pam_transport(), RequestContext::default(), &CancelToken::default(), &|_| ApprovalDecision::Allow).unwrap();
    assert_eq!(remove_transport(&d.env(), &r, &json!({"alias":"fixture-web"}), RequestContext::default(), &CancelToken::default(), &|_| ApprovalDecision::Deny).unwrap_err(), "Transport removal was denied.");
    assert!(transport_of(&d, &id).is_some());
    assert_eq!(last_outcome(&r), "transport_not_removed");
}

#[test]
fn a_transport_changed_meanwhile_is_refused() {
    let d = device();
    let r = runtime(ApprovalMode::Ask);
    let id = created(&d, &r);
    set_transport(&d.env(), &r, &pam_transport(), RequestContext::default(), &CancelToken::default(), &|_| ApprovalDecision::Allow).unwrap();
    let error = set_transport(&d.env(), &r, &json!({"alias":"fixture-web","instance":"jumpbox-2"}), RequestContext::default(), &CancelToken::default(), &|_| {
        crate::sync::record_commands::edit_records(&d.env(), |state, now| {
            let current = crate::sync::transports::get(state, &id).unwrap();
            let mut other = current.clone();
            let crate::sync::transports::TransportKind::GcpIap { zone, .. } = &mut other.kind;
            *zone = "asia-east1-c".into();
            crate::sync::transports::set(state, &id, Some(&current), Some(other), now).map_err(|e| AppError::Other(e.to_string()))
        })
        .unwrap();
        ApprovalDecision::Allow
    })
    .unwrap_err();
    assert_eq!(error, "The transport changed while the request was open; read it again and retry.");
    assert_eq!(kind_of(&transport_of(&d, &id).unwrap()).1, "asia-east1-c", "the other change stands");
}

#[test]
fn transport_tools_need_the_hosts_ai_permission() {
    let d = device();
    let r = runtime(ApprovalMode::Ask);
    let id = created(&d, &r);
    r.policy.lock().unwrap().allowed_hosts.clear();
    let sentence = format!("host '{id}' is not allowed for AI access");
    assert_eq!(set_transport(&d.env(), &r, &pam_transport(), RequestContext::default(), &CancelToken::default(), &never).unwrap_err(), sentence);
    assert_eq!(remove_transport(&d.env(), &r, &json!({"alias":"fixture-web"}), RequestContext::default(), &CancelToken::default(), &never).unwrap_err(), sentence);
    assert!(transport_of(&d, &id).is_none());
}
