//! Explicit local Group grants. Membership is resolved from current validated Records, never aliases.
use super::*;
use crate::sync::{
    record_groups, record_repository as repo,
    records_v3::{HostScope, SyncStateV3},
};

pub(super) fn group_key(scope: &HostScope, id: &str) -> String {
    match scope {
        HostScope::Local => format!("local/{id}"),
        HostScope::Space { space_id } => format!("space/{space_id}/{id}"),
    }
}
fn grant_key(state: &SyncStateV3, scope: &HostScope, id: &str) -> String {
    // A new server workspace has its own persistent random device_id. Imported record IDs alone
    // must not transfer local AI authorization between libraries, accounts or servers.
    format!("{}/{}", state.device_id, group_key(scope, id))
}
pub(super) fn active_groups(policy: &McpPolicy, state: &SyncStateV3) -> Vec<String> {
    let prefix = format!("{}/", state.device_id);
    policy
        .allowed_groups
        .iter()
        .filter_map(|key| key.strip_prefix(&prefix).map(str::to_owned))
        .collect()
}
pub(super) fn record_allowed(
    policy: &McpPolicy,
    state: &SyncStateV3,
    host: &repo::HostView,
) -> bool {
    if policy.allowed_hosts.contains(&host.host.id) {
        return true;
    }
    host.group_error.is_none()
        && record_groups::ancestor_path(
            state,
            &host.host.scope,
            host.host.payload.group_id.as_deref(),
        )
        .is_ok_and(|groups| {
            groups.iter().any(|group| {
                policy
                    .allowed_groups
                    .contains(&grant_key(state, &group.scope, &group.id))
            })
        })
}
pub(super) fn ensure_record(
    policy: &McpPolicy,
    state: &SyncStateV3,
    id: &str,
) -> Result<(), String> {
    let host = repo::get_host(state, id).map_err(|error| error.to_string())?;
    if record_allowed(policy, state, &host) {
        Ok(())
    } else {
        Err(format!("host '{id}' is not allowed for AI access"))
    }
}
pub(super) fn authorize(state: &AppState, policy: &McpPolicy, id: &str) -> Result<(), String> {
    // Preserve the existing individual-ID contract without loading Groups on that path.
    if policy.allowed_hosts.contains(id) {
        return Ok(());
    }
    let core = state.sync.core.lock().unwrap();
    let records =
        crate::sync::record_runtime::active_state(&core).map_err(|error| error.to_string())?;
    ensure_record(policy, records, id)
}
pub(super) fn change_group(
    policy: &Mutex<McpPolicy>,
    state: &SyncStateV3,
    scope: &HostScope,
    id: &str,
    allowed: bool,
    persist: impl FnOnce(&McpPolicy) -> Result<(), AppError>,
) -> Result<(), AppError> {
    if allowed {
        let groups =
            record_groups::list_groups(state).map_err(|e| AppError::Other(e.to_string()))?;
        let matching: Vec<_> = groups
            .iter()
            .filter(|g| g.group.id == id && &g.group.scope == scope)
            .collect();
        if matching.len() != 1 || matching[0].group_error.is_some() {
            return Err(AppError::Other(
                "Choose an existing Group with valid ancestry in this library.".into(),
            ));
        }
    }
    let mut current = policy.lock().unwrap();
    let mut next = current.clone();
    let key = grant_key(state, scope, id);
    if allowed {
        next.allowed_groups.insert(key);
    } else {
        next.allowed_groups.remove(&key);
    }
    persist(&next)?;
    *current = next;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    const PARENT: &str = "0000000000000001";
    const CHILD: &str = "0000000000000002";
    const HOST: &str = "0000000000000010";
    fn state() -> SyncStateV3 {
        let state: SyncStateV3 = serde_json::from_value(json!({"version":4,"device_id":"dddddddddddddddddddddddddddddddd","device_name":"fixture","relay_url":"http://127.0.0.1","local":{}})).unwrap();
        let payload = |name: &str, parent: Option<&str>| {
            serde_json::from_value(json!({"schema":1,"name":name,"parent_id":parent,"defaults":{}}))
                .unwrap()
        };
        let state = record_groups::create_group(
            &state,
            PARENT,
            HostScope::Local,
            payload("Operations", None),
            false,
            1,
        )
        .unwrap();
        let state = record_groups::create_group(
            &state,
            CHILD,
            HostScope::Local,
            payload("Servers", Some(PARENT)),
            false,
            2,
        )
        .unwrap();
        let host = serde_json::from_value(json!({"schema":3,"alias":"web","hostname":"fixture.invalid","group_id":CHILD,"auth":"password"})).unwrap();
        repo::create_host(&state, HOST, HostScope::Local, host, 3).unwrap()
    }
    fn policy(state: &SyncStateV3) -> McpPolicy {
        let policy = Mutex::new(McpPolicy {
            enabled: true,
            ..Default::default()
        });
        change_group(&policy, state, &HostScope::Local, PARENT, true, |_| Ok(())).unwrap();
        policy.into_inner().unwrap()
    }
    fn directory() -> crate::session::testing::FakeDirectory {
        use crate::session::directory::HostDirectory;
        let d = crate::session::testing::FakeDirectory::new().with_hop(crate::ssh::Hop::new(
            HOST,
            "web",
            "fixture.invalid",
            22,
            "ops",
            crate::ssh::AuthMethod::Key {
                key_id: "k-plain".into(),
            },
        ));
        d.pin(
            &crate::ssh::HostId::from(HOST),
            &crate::ssh::fake::default_server_key(),
        )
        .unwrap();
        d
    }
    fn run(
        runtime: &McpRuntime,
        state: &Mutex<SyncStateV3>,
        engine: &dyn crate::ssh::SshEngine,
        cancel: &crate::session::connect::CancelToken,
        approve: &(dyn Fn(&McpPendingRequest) -> ApprovalDecision + Sync),
    ) -> Result<Value, String> {
        use crate::session::{
            connect::Connector,
            testing::{FakeConfirmer, FakeKeys, FakeOwner},
        };
        records::execute_context(
            runtime,
            &Connector {
                directory: &directory(),
                engine,
                keys: &FakeKeys::new(),
                keychain: &crate::sync::testkit::MemKeychain::default(),
                confirmer: &FakeConfirmer::default(),
            },
            HOST,
            "uptime",
            60,
            cancel,
            &FakeOwner::default(),
            approve,
            RequestContext::default(),
            &|policy, id| ensure_record(policy, &state.lock().unwrap(), id),
        )
    }
    fn move_out(state: &Mutex<SyncStateV3>) {
        let mut state = state.lock().unwrap();
        let host = repo::get_host(&state, HOST).unwrap();
        let mut payload = host.host.payload;
        payload.group_id = None;
        *state = repo::update_host(&state, HOST, &host.revision, payload, 9).unwrap();
    }
    #[test]
    fn group_only_execution_obeys_ask_auto_log_and_rechecks_after_approval() {
        use crate::ssh::fake::FakeEngine;
        for mode in [ApprovalMode::Ask, ApprovalMode::AutoLog] {
            let state = Mutex::new(state());
            let runtime = McpRuntime::default();
            *runtime.policy.lock().unwrap() = McpPolicy {
                approval_mode: mode,
                ..policy(&state.lock().unwrap())
            };
            let engine = FakeEngine::new();
            let approvals = AtomicU64::new(0);
            assert!(run(&runtime, &state, &engine, &Default::default(), &|_| {
                approvals.fetch_add(1, Ordering::SeqCst);
                ApprovalDecision::Allow
            })
            .is_ok());
            assert_eq!(
                approvals.load(Ordering::SeqCst),
                if mode == ApprovalMode::Ask { 1 } else { 0 }
            );
            assert!(!engine.events().is_empty());
        }
        for revoke_group in [true, false] {
            let state = Mutex::new(state());
            let runtime = McpRuntime::default();
            *runtime.policy.lock().unwrap() = policy(&state.lock().unwrap());
            let engine = FakeEngine::new();
            assert!(run(&runtime, &state, &engine, &Default::default(), &|_| {
                if revoke_group {
                    runtime.policy.lock().unwrap().allowed_groups.clear();
                } else {
                    move_out(&state);
                }
                ApprovalDecision::Allow
            })
            .is_err());
            assert!(engine.events().is_empty());
        }
    }
    #[test]
    fn moving_out_or_revoking_group_during_execution_closes_the_session() {
        use crate::ssh::{DisconnectReason, ExecResult, Pty, Session, SessionError, ShellChannel};
        struct Waiting {
            entered: Arc<AtomicBool>,
            closed: Arc<AtomicBool>,
        }
        impl crate::ssh::SshEngine for Waiting {
            fn connect(
                &self,
                _: &crate::ssh::Target,
                _: &dyn crate::ssh::HostKeyPolicy,
                _: &dyn crate::ssh::AuthSource,
            ) -> Result<Box<dyn Session>, crate::ssh::ConnectError> {
                Ok(Box::new(Waiting {
                    entered: self.entered.clone(),
                    closed: self.closed.clone(),
                }))
            }
        }
        impl Session for Waiting {
            fn shell(&self, _: Pty) -> Result<Box<dyn ShellChannel>, SessionError> {
                panic!("MCP must not allocate a PTY")
            }
            fn exec(&self, _: &str, _: Duration, _: usize) -> Result<ExecResult, SessionError> {
                self.entered.store(true, Ordering::SeqCst);
                let end = Instant::now() + Duration::from_secs(3);
                while !self.closed.load(Ordering::SeqCst) {
                    assert!(Instant::now() < end);
                    thread::sleep(Duration::from_millis(2));
                }
                Err(SessionError::Closed)
            }
            fn is_alive(&self) -> bool {
                !self.closed.load(Ordering::SeqCst)
            }
            fn disconnect_reason(&self) -> Option<DisconnectReason> {
                None
            }
            fn close(&self) {
                self.closed.store(true, Ordering::SeqCst);
            }
        }
        for revoke_group in [true, false] {
            let state = Mutex::new(state());
            let runtime = McpRuntime::default();
            *runtime.policy.lock().unwrap() = policy(&state.lock().unwrap());
            let engine = Waiting {
                entered: Arc::new(AtomicBool::new(false)),
                closed: Arc::new(AtomicBool::new(false)),
            };
            let cancel = Default::default();
            thread::scope(|scope| {
                let worker = scope.spawn(|| {
                    run(&runtime, &state, &engine, &cancel, &|_| {
                        ApprovalDecision::Allow
                    })
                });
                let end = Instant::now() + Duration::from_secs(3);
                while !engine.entered.load(Ordering::SeqCst) {
                    assert!(Instant::now() < end);
                    thread::sleep(Duration::from_millis(2));
                }
                if revoke_group {
                    runtime.policy.lock().unwrap().allowed_groups.clear();
                } else {
                    move_out(&state);
                }
                let output = worker.join().unwrap().unwrap();
                assert_eq!(output["ended"], "canceled");
                assert!(output["exit_code"].is_null());
            });
            assert!(engine.closed.load(Ordering::SeqCst));
            assert_eq!(runtime.status().recent.len(), 1);
        }
    }

    #[test]
    fn parent_grant_follows_nested_membership_new_hosts_and_rename_but_not_moves_out() {
        let state = state();
        let policy = policy(&state);
        assert!(ensure_record(&policy, &state, HOST).is_ok());
        let group = record_groups::list_groups(&state)
            .unwrap()
            .into_iter()
            .find(|g| g.group.id == PARENT)
            .unwrap();
        let mut payload = group.group.payload;
        payload.name = "Renamed".into();
        let state =
            record_groups::update_group(&state, PARENT, &group.revision, payload, 4).unwrap();
        assert!(ensure_record(&policy, &state, HOST).is_ok());
        let host = repo::get_host(&state, HOST).unwrap();
        let mut payload = host.host.payload.clone();
        payload.alias = "new-host".into();
        let next =
            repo::create_host(&state, "0000000000000020", HostScope::Local, payload, 5).unwrap();
        assert!(ensure_record(&policy, &next, "0000000000000020").is_ok());
        let mut payload = host.host.payload;
        payload.group_id = None;
        let next = repo::update_host(&state, HOST, &host.revision, payload, 6).unwrap();
        assert!(ensure_record(&policy, &next, HOST).is_err());
        let mut individual = policy.clone();
        individual.allowed_hosts.insert(HOST.into());
        assert!(ensure_record(&individual, &next, HOST).is_ok());
    }
    #[test]
    fn grants_do_not_match_names_other_workspaces_or_scopes_and_bad_ancestry_fails_closed() {
        let mut state = state();
        let policy = policy(&state);
        let mut other = state.clone();
        other.device_id = "e".repeat(32);
        assert!(ensure_record(&policy, &other, HOST).is_err());
        assert!(active_groups(&policy, &other).is_empty());
        let mut wrong_scope = policy.clone();
        wrong_scope.allowed_groups = BTreeSet::from([grant_key(
            &state,
            &HostScope::Space {
                space_id: "a".repeat(64),
            },
            PARENT,
        )]);
        assert!(ensure_record(&wrong_scope, &state, HOST).is_err());
        let mut name_only = policy.clone();
        name_only.allowed_groups =
            BTreeSet::from([grant_key(&state, &HostScope::Local, "Operations")]);
        assert!(ensure_record(&name_only, &state, HOST).is_err());
        state.local.groups.remove(&format!("group:{PARENT}"));
        assert!(ensure_record(&policy, &state, HOST).is_err());
        let policy = Mutex::new(policy);
        assert!(change_group(&policy, &state, &HostScope::Local, CHILD, true, |_| Ok(())).is_err());
        change_group(
            &policy,
            &state,
            &HostScope::Local,
            PARENT,
            false,
            |_| Ok(()),
        )
        .unwrap();
        assert!(active_groups(&policy.lock().unwrap(), &state).is_empty());
    }
    #[test]
    fn policy_persistence_failure_retains_old_grant_and_old_policy_defaults_to_none() {
        let state = state();
        let old: McpPolicy =
            serde_json::from_value(json!({"enabled":true,"allowed_hosts":[HOST]})).unwrap();
        assert!(old.allowed_groups.is_empty());
        let policy = Mutex::new(policy(&state));
        assert!(
            change_group(&policy, &state, &HostScope::Local, PARENT, false, |_| Err(
                AppError::Other("save failed".into())
            ))
            .is_err()
        );
        assert!(ensure_record(&policy.lock().unwrap(), &state, HOST).is_ok());
        let saved = serde_json::to_string(&*policy.lock().unwrap()).unwrap();
        let reloaded: McpPolicy = serde_json::from_str(&saved).unwrap();
        assert!(ensure_record(&reloaded, &state, HOST).is_ok());
    }
}
