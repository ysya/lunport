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
            "verify_host_key"
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
