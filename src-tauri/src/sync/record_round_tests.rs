use super::*;
use crate::sync::crypto;
use crate::sync::env::{Keychain, RelayConnector};
use crate::sync::fake_relay::FakeRelay;
use crate::sync::record::{record_key, LocalRecord, Record, RecordKind, ACCOUNT_META_ID};
use crate::sync::record_merge::{encode_record, seal_secret_record};
use crate::sync::record_runtime::{self, StartupProbe};
use crate::sync::records_v3::SpaceStateV3;
use crate::sync::relay::*;
use crate::sync::state::MNEMONIC_ACCOUNT;
use crate::sync::state_v2::AccountState;
use crate::sync::testkit::{HookedConnector, Hooks, TestClock, TestDevice};
use serde_json::json;
use std::sync::{Arc, Mutex};

const HOST: &str = "0000000000000001";
#[test]
fn required_round_waits_for_transport_and_activity_is_public_without_persisting_it() {
    use std::sync::mpsc;
    use std::time::Duration;
    let (device, keys) = fixture();
    add_space(&device, &keys, true);
    let (started_tx, started_rx) = mpsc::channel();
    let (resume_tx, resume_rx) = mpsc::channel();
    let connector = HookedConnector::new(&device.relay, Hooks {
        before_pull: Some(Box::new(move || {
            started_tx.send(()).unwrap();
            resume_rx.recv_timeout(Duration::from_secs(10)).unwrap();
        })),
        ..Default::default()
    });
    let background_device = Arc::clone(&device);
    let background = std::thread::spawn(move || {
        let mut env = background_device.env();
        env.relays = &connector;
        sync_once(&env)
    });
    started_rx.recv_timeout(Duration::from_secs(10)).unwrap();
    let active = serde_json::to_value(crate::sync::record_commands::overview(&device.env()).unwrap()).unwrap();
    assert_eq!(active["syncing"], true);
    assert_eq!(sync_once(&device.env()).unwrap().gate, None); // ordinary wake still coalesces
    let setup_device = Arc::clone(&device);
    let setup = std::thread::spawn(move || sync_once_required(&setup_device.env()));
    resume_tx.send(()).unwrap();
    background.join().unwrap().unwrap();
    let report = setup.join().unwrap().unwrap();
    assert_eq!(report.gate, Some(AccountGate::Compatible));
    assert_eq!(report.spaces_pulled, 1);
    let idle = serde_json::to_value(crate::sync::record_commands::overview(&device.env()).unwrap()).unwrap();
    assert_eq!(idle["syncing"], false);
    let disk: serde_json::Value = serde_json::from_slice(&std::fs::read(&device.env().state_path).unwrap()).unwrap();
    assert!(disk.get("syncing").is_none());
}
fn value(kind: RecordKind, id: &str, payload: serde_json::Value, at: u64) -> Record {
    Record {
        kind,
        id: id.into(),
        version: 1,
        updated_at_ms: at,
        device_id: "d".repeat(32),
        deleted: false,
        payload,
    }
}
fn host(id: &str, alias: &str, at: u64) -> Record {
    value(
        RecordKind::Host,
        id,
        json!({"schema":2,"alias":alias,"hostname":"host.test","auth":"password"}),
        at,
    )
}
fn fixture() -> (Arc<TestDevice>, ChainKeys) {
    let relay = FakeRelay::new();
    let device = Arc::new(TestDevice::new("a", &relay, &TestClock::new()));
    let phrase = crypto::generate_mnemonic().unwrap();
    let keys = crypto::derive_account(&phrase).unwrap();
    let env = device.env();
    let StartupProbe::Records { mut state, .. } =
        record_runtime::probe_startup(&env.state_path, "fixture")
    else {
        panic!("fresh")
    };
    state.relay_url = crate::sync::testkit::RELAY_URL.into();
    let mut account = AccountState::new(&keys.chain_id);
    let meta = value(
        RecordKind::Meta,
        ACCOUNT_META_ID,
        json!({"schema_version":3,"created_by_app_version":"test"}),
        1,
    );
    account.records.insert(
        record_key(meta.kind, &meta.id),
        LocalRecord {
            record: meta.clone(),
            seq: 1,
            dirty: false,
        },
    );
    account.cursor_seq = 1;
    account.baseline_established = true;
    account.remote_schema_version = Some(3);
    state.account = Some(account);
    relay
        .create_chain(&keys.chain_id, &keys.auth_token)
        .unwrap();
    relay
        .push(
            &keys.chain_id,
            &keys.auth_token,
            &[encode_record(&keys, &meta, 0).unwrap()],
        )
        .unwrap();
    device.keychain.set(MNEMONIC_ACCOUNT, &phrase).unwrap();
    record_runtime::activate_probe(
        &mut device.runtime.core.lock().unwrap(),
        StartupProbe::Records {
            state,
            fresh: false,
        },
    )
    .unwrap();
    let (s, g) = record_runtime::snapshot(&env).unwrap();
    record_runtime::commit_candidate(&env, g, s).unwrap();
    relay.clear_calls();
    (device, keys)
}
fn add_space(device: &TestDevice, keys: &ChainKeys, selected: bool) -> ChainKeys {
    let child = ChainKeys::generate().unwrap();
    device
        .relay
        .create_chain(&child.chain_id, &child.auth_token)
        .unwrap();
    let metadata = value(
        RecordKind::Space,
        &child.chain_id,
        json!({"schema":1,"name":"test","slug":"test","created_at_ms":1}),
        2,
    );
    let key = value(
        RecordKind::SpaceKey,
        &child.chain_id,
        json!({"schema":1,"auth_token":child.auth_token,"enc_key":child.enc_key_b64()}),
        2,
    );
    let envelope = seal_secret_record(keys, key, 0).unwrap();
    device
        .relay
        .push(
            &keys.chain_id,
            &keys.auth_token,
            &[
                encode_record(keys, &metadata, 0).unwrap(),
                PushItem {
                    id_hash: envelope.envelope.id_hash.clone(),
                    kind: envelope.envelope.kind.clone(),
                    nonce: envelope.envelope.nonce.clone(),
                    ciphertext: envelope.envelope.ciphertext.clone(),
                    deleted: false,
                    base_seq: 0,
                },
            ],
        )
        .unwrap();
    record_runtime::mutate_records(&device.env(), |s| {
        let mut next = s.clone();
        next.spaces.insert(
            child.chain_id.clone(),
            SpaceStateV3 {
                selected,
                ..Default::default()
            },
        );
        Ok(next)
    })
    .unwrap();
    child
}
fn update_meta(device: &TestDevice, keys: &ChainKeys, schema: u32, migration: Option<&str>) {
    let mut meta = value(
        RecordKind::Meta,
        ACCOUNT_META_ID,
        json!({"schema_version":schema,"created_by_app_version":"future"}),
        50,
    );
    if let Some(phase) = migration {
        meta.payload["migration"] =
            json!({"id":"e".repeat(32),"source_digest":"f".repeat(64),"phase":phase});
    }
    let seq = device
        .relay
        .rows(&keys.chain_id)
        .iter()
        .find(|r| r.kind == "meta")
        .unwrap()
        .seq;
    device
        .relay
        .push(
            &keys.chain_id,
            &keys.auth_token,
            &[encode_record(keys, &meta, seq).unwrap()],
        )
        .unwrap();
}
fn state(device: &TestDevice) -> crate::sync::records_v3::SyncStateV3 {
    record_runtime::snapshot(&device.env()).unwrap().0
}

#[test]
fn cached_cursor_never_hides_future_account_format_and_only_account_is_polled() {
    let (d, keys) = fixture();
    let child = add_space(&d, &keys, true);
    record_runtime::mutate_records(&d.env(), |s| {
        let mut n = s.clone();
        n.spaces.get_mut(&child.chain_id).unwrap().records.insert(
            record_key(RecordKind::Host, HOST),
            LocalRecord {
                record: host(HOST, "dirty", 2),
                seq: 0,
                dirty: true,
            },
        );
        Ok(n)
    })
    .unwrap();
    let before = state(&d);
    update_meta(&d, &keys, 5, None);
    d.relay.clear_calls();
    let report = sync_once(&d.env()).unwrap();
    assert_eq!(report.gate, Some(AccountGate::NeedsUpdate { schema: 5 }));
    let after = state(&d);
    assert_eq!(after.spaces, before.spaces);
    assert_eq!(after.local, before.local);
    assert_eq!(
        after.account.as_ref().unwrap().records,
        before.account.as_ref().unwrap().records
    );
    assert_eq!(
        after.account.as_ref().unwrap().sealed,
        before.account.as_ref().unwrap().sealed
    );
    assert_eq!(
        after.account.as_ref().unwrap().cursor_seq,
        before.account.as_ref().unwrap().cursor_seq
    );
    assert!(after.shared_writes_blocked);
    assert_eq!(
        d.relay.calls(),
        vec![format!("pull:{}", &keys.chain_id[..8])]
    );
    sync_once(&d.env()).unwrap();
    assert_eq!(d.relay.calls().len(), 2);
}
#[test]
fn pending_migration_is_durable_and_does_not_touch_selected_space() {
    let (d, keys) = fixture();
    let child = add_space(&d, &keys, true);
    let before = state(&d);
    update_meta(&d, &keys, 3, Some("publishing"));
    d.relay.clear_calls();
    let proof = fresh_account_gate(&d.env()).unwrap();
    assert!(proof.ensure_compatible().is_err());
    let after = state(&d);
    assert!(after.shared_writes_blocked);
    assert!(after.migration_gate.is_some());
    assert_eq!(
        after.spaces[&child.chain_id],
        before.spaces[&child.chain_id]
    );
    assert_eq!(
        after.account.as_ref().unwrap().records,
        before.account.as_ref().unwrap().records
    );
    let bytes = std::fs::read(d.env().state_path).unwrap();
    let disk: crate::sync::records_v3::SyncStateV3 = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(disk.migration_gate, after.migration_gate);
}
#[test]
fn compatible_full_account_proof_clears_only_the_explicit_shared_gate() {
    let (d, _) = fixture();
    record_runtime::mutate_records(&d.env(), |s| {
        let mut n = s.clone();
        n.shared_writes_blocked = true;
        n.last_error = Some("temporary gate".into());
        Ok(n)
    })
    .unwrap();
    fresh_account_gate(&d.env())
        .unwrap()
        .ensure_compatible()
        .unwrap();
    assert!(!state(&d).shared_writes_blocked);
}
#[test]
fn typed_selected_space_has_zero_baseline_then_current_cursor_and_never_writes_ssh_files() {
    let (d, keys) = fixture();
    let child = add_space(&d, &keys, true);
    d.relay
        .push(
            &child.chain_id,
            &child.auth_token,
            &[encode_record(&child, &host(HOST, "web", 3), 0).unwrap()],
        )
        .unwrap();
    let config = d.ssh_dir().join("config");
    let bytes = std::fs::read(&config).unwrap();
    d.relay.clear_calls();
    let report = sync_once(&d.env()).unwrap();
    assert_eq!(report.spaces_pulled, 1);
    let current = state(&d);
    assert!(current.spaces[&child.chain_id].baseline_established);
    assert_eq!(current.spaces[&child.chain_id].cursor_seq, 1);
    assert!(current.spaces[&child.chain_id]
        .records
        .contains_key(&record_key(RecordKind::Host, HOST)));
    assert_eq!(std::fs::read(config).unwrap(), bytes);
    assert!(!d.ssh_dir().join("sshelter").exists());
    assert!(d.events.applied.lock().unwrap().is_empty());
    sync_once(&d.env()).unwrap();
    assert_eq!(state(&d).spaces[&child.chain_id].cursor_seq, 1);
}
#[test]
fn unselected_spaces_have_no_requests_and_missing_spaces_are_never_recreated() {
    let (d, keys) = fixture();
    let first = add_space(&d, &keys, false);
    let second = add_space(&d, &keys, true);
    d.relay.expire(&second.chain_id);
    d.relay.clear_calls();
    sync_once(&d.env()).unwrap();
    let after = state(&d);
    assert!(after.spaces[&second.chain_id].missing);
    assert!(!d.relay.exists(&second.chain_id));
    assert!(!d
        .relay
        .calls()
        .iter()
        .any(|c| c.ends_with(&first.chain_id[..8])));
    assert!(!d
        .relay
        .calls()
        .iter()
        .any(|c| c.starts_with("create:") || c.starts_with("delete:")));
}
#[test]
fn partial_push_receipts_survive_later_quota_failure_and_cursor_stays_at_pull() {
    let (d, keys) = fixture();
    let child = add_space(&d, &keys, true);
    sync_once(&d.env()).unwrap();
    record_runtime::mutate_records(&d.env(), |s| {
        let mut n = s.clone();
        let space = n.spaces.get_mut(&child.chain_id).unwrap();
        for i in 1..=201 {
            let id = format!("{i:016x}");
            space.records.insert(
                record_key(RecordKind::Host, &id),
                LocalRecord {
                    record: host(&id, &format!("host{i}"), 100),
                    seq: 0,
                    dirty: true,
                },
            );
        }
        Ok(n)
    })
    .unwrap();
    d.relay.set_push_quota(Some(1));
    assert!(sync_once(&d.env()).is_err());
    let after = state(&d);
    let space = &after.spaces[&child.chain_id];
    assert_eq!(space.records.values().filter(|r| !r.dirty).count(), 200);
    assert_eq!(space.records.values().filter(|r| r.dirty).count(), 1);
    assert_eq!(space.cursor_seq, 0);
    assert_eq!(d.relay.rows(&child.chain_id).len(), 200);
}
#[test]
fn changed_local_revision_while_push_waits_stays_dirty_and_newest_state_is_not_replaced() {
    let (d, keys) = fixture();
    let child = add_space(&d, &keys, true);
    sync_once(&d.env()).unwrap();
    record_runtime::mutate_records(&d.env(), |s| {
        let mut n = s.clone();
        n.spaces.get_mut(&child.chain_id).unwrap().records.insert(
            record_key(RecordKind::Host, HOST),
            LocalRecord {
                record: host(HOST, "first", 20),
                seq: 0,
                dirty: true,
            },
        );
        Ok(n)
    })
    .unwrap();
    let edit = Arc::clone(&d);
    let id = child.chain_id.clone();
    let connector = HookedConnector::new(
        &d.relay,
        Hooks {
            after_push: Some(Box::new(move || {
                record_runtime::mutate_records(&edit.env(), |s| {
                    let mut n = s.clone();
                    let row = n
                        .spaces
                        .get_mut(&id)
                        .unwrap()
                        .records
                        .get_mut(&record_key(RecordKind::Host, HOST))
                        .unwrap();
                    row.record.version += 1;
                    row.record.updated_at_ms += 1;
                    row.record.payload["alias"] = json!("newest");
                    Ok(n)
                })
                .unwrap();
            })),
            ..Default::default()
        },
    );
    let mut env = d.env();
    env.relays = &connector;
    sync_once(&env).unwrap();
    let after = state(&d);
    let row = &after.spaces[&child.chain_id].records[&record_key(RecordKind::Host, HOST)];
    assert!(row.dirty);
    assert_eq!(row.record.payload["alias"], json!("newest"));
}
#[test]
fn known_save_blocked_refuses_network_before_credential_read() {
    let (d, _) = fixture();
    d.runtime.core.lock().unwrap().save_blocked = Some("locked".into());
    d.keychain
        .fail_reads
        .store(true, std::sync::atomic::Ordering::SeqCst);
    d.relay.clear_calls();
    let error = sync_once(&d.env()).unwrap_err();
    assert!(error.to_string().contains("locked"));
    assert!(d.relay.calls().is_empty());
}
#[test]
fn fresh_gate_does_not_clear_or_publish_while_relay_is_unreachable() {
    let (d, _) = fixture();
    record_runtime::mutate_records(&d.env(), |s| {
        let mut n = s.clone();
        n.shared_writes_blocked = true;
        Ok(n)
    })
    .unwrap();
    let before = state(&d);
    d.relay.set_offline(true);
    assert!(fresh_account_gate(&d.env()).is_err());
    assert_eq!(state(&d), before);
}
#[test]
fn a_new_local_workspace_has_no_account_requests_and_no_legacy_tail() {
    let (d, _) = fixture();
    record_runtime::mutate_records(&d.env(), |s| {
        let mut n = s.clone();
        n.account = None;
        Ok(n)
    })
    .unwrap();
    d.relay.clear_calls();
    let report = sync_once(&d.env()).unwrap();
    assert!(report.gate.is_none());
    assert!(d.relay.calls().is_empty());
    assert!(!d.ssh_dir().join("sshelter").exists());
    assert!(d.events.applied.lock().unwrap().is_empty());
}

struct PullHookConnector {
    relay: Arc<FakeRelay>,
    hook: Arc<Mutex<Option<Box<dyn FnOnce() + Send>>>>,
}
struct PullHookRelay {
    relay: Arc<FakeRelay>,
    hook: Arc<Mutex<Option<Box<dyn FnOnce() + Send>>>>,
}
impl RelayConnector for PullHookConnector {
    fn connect(&self, _: &str) -> Result<Box<dyn RelayApi>, AppError> {
        Ok(Box::new(PullHookRelay {
            relay: Arc::clone(&self.relay),
            hook: Arc::clone(&self.hook),
        }))
    }
}
impl RelayApi for PullHookRelay {
    fn info(&self) -> Result<RelayInfo, RelayError> {
        self.relay.info()
    }
    fn create_chain(&self, c: &str, t: &str) -> Result<(), RelayError> {
        self.relay.create_chain(c, t)
    }
    fn delete_chain(&self, c: &str, t: &str) -> Result<(), RelayError> {
        self.relay.delete_chain(c, t)
    }
    fn freeze_chain(&self, c: &str, t: &str) -> Result<(), RelayError> {
        self.relay.freeze_chain(c, t)
    }
    fn pull(&self, c: &str, t: &str, s: u64) -> Result<PullResponse, RelayError> {
        let result = self.relay.pull(c, t, s);
        let hook = self.hook.lock().unwrap().take();
        if let Some(hook) = hook {
            hook();
        }
        result
    }
    fn pull_batch(&self, i: &[BatchPullItem]) -> Result<Vec<BatchPullEntry>, RelayError> {
        self.relay.pull_batch(i)
    }
    fn push(&self, c: &str, t: &str, i: &[PushItem]) -> Result<PushOutcome, RelayError> {
        self.relay.push(c, t, i)
    }
}
#[cfg(unix)]
#[test]
fn gate_persistence_failure_keeps_original_disk_and_blocks_current_memory() {
    let (d, keys) = fixture();
    update_meta(&d, &keys, 5, None);
    let old = std::fs::read(d.env().state_path).unwrap();
    let sentinel = d.home.path().join("outside-state");
    std::fs::write(&sentinel, &old).unwrap();
    let path = d.env().state_path;
    let target = sentinel.clone();
    let connector = PullHookConnector {
        relay: Arc::clone(&d.relay),
        hook: Arc::new(Mutex::new(Some(Box::new(move || {
            std::fs::remove_file(&path).unwrap();
            std::os::unix::fs::symlink(&target, &path).unwrap();
        })))),
    };
    let mut env = d.env();
    env.relays = &connector;
    assert!(fresh_account_gate(&env).is_err());
    assert_eq!(std::fs::read(sentinel).unwrap(), old);
    let core = d.runtime.core.lock().unwrap();
    assert!(core.save_blocked.is_some());
    assert!(core.records.as_ref().unwrap().shared_writes_blocked);
    assert_eq!(
        core.records
            .as_ref()
            .unwrap()
            .account
            .as_ref()
            .unwrap()
            .remote_schema_version,
        Some(5)
    );
}
#[cfg(unix)]
#[test]
fn accepted_receipts_remain_unsaved_in_memory_when_disk_breaks_and_next_round_has_no_network() {
    let (d, keys) = fixture();
    let child = add_space(&d, &keys, true);
    sync_once(&d.env()).unwrap();
    record_runtime::mutate_records(&d.env(), |s| {
        let mut n = s.clone();
        n.spaces.get_mut(&child.chain_id).unwrap().records.insert(
            record_key(RecordKind::Host, HOST),
            LocalRecord {
                record: host(HOST, "pending", 20),
                seq: 0,
                dirty: true,
            },
        );
        Ok(n)
    })
    .unwrap();
    let path = d.env().state_path;
    let target = d.home.path().join("sentinel");
    std::fs::write(&target, b"unchanged").unwrap();
    let saved = target.clone();
    let connector = HookedConnector::new(
        &d.relay,
        Hooks {
            after_push: Some(Box::new(move || {
                std::fs::remove_file(&path).unwrap();
                std::os::unix::fs::symlink(&target, &path).unwrap();
            })),
            ..Default::default()
        },
    );
    let mut env = d.env();
    env.relays = &connector;
    assert!(sync_once(&env).is_err());
    let core = d.runtime.core.lock().unwrap();
    assert!(core.unsaved);
    assert!(
        !core.records.as_ref().unwrap().spaces[&child.chain_id].records
            [&record_key(RecordKind::Host, HOST)]
            .dirty
    );
    drop(core);
    d.relay.clear_calls();
    assert!(sync_once(&d.env()).is_err());
    assert!(d.relay.calls().is_empty());
    assert_eq!(std::fs::read(saved).unwrap(), b"unchanged");
}
#[test]
fn delayed_authenticated_gate_survives_a_local_generation_change_and_keeps_latest_local_cache() {
    let (d, keys) = fixture();
    update_meta(&d, &keys, 5, None);
    let publication = d.runtime.format_publication.lock().unwrap();
    let (sender, receiver) = std::sync::mpsc::channel();
    let connector = PullHookConnector {
        relay: Arc::clone(&d.relay),
        hook: Arc::new(Mutex::new(Some(Box::new(move || {
            sender.send(()).unwrap();
        })))),
    };
    std::thread::scope(|scope| {
        let join = scope.spawn(|| {
            let mut env = d.env();
            env.relays = &connector;
            fresh_account_gate(&env)
        });
        receiver
            .recv_timeout(std::time::Duration::from_secs(3))
            .unwrap();
        record_runtime::mutate_records(&d.env(), |s| {
            let mut n = s.clone();
            n.local.hosts.insert(
                record_key(RecordKind::Host, HOST),
                LocalRecord {
                    record: host(HOST, "latest-local", 60),
                    seq: 0,
                    dirty: false,
                },
            );
            Ok(n)
        })
        .unwrap();
        drop(publication);
        assert_eq!(
            join.join().unwrap().unwrap().gate,
            AccountGate::NeedsUpdate { schema: 5 }
        );
    });
    let latest = state(&d);
    assert!(latest.shared_writes_blocked);
    assert_eq!(
        latest.local.hosts[&record_key(RecordKind::Host, HOST)]
            .record
            .payload["alias"],
        json!("latest-local")
    );
}
#[test]
fn remote_relationship_conflict_is_cached_for_review_and_dirty_hosts_are_not_pushed() {
    let (d, keys) = fixture();
    let child = add_space(&d, &keys, true);
    sync_once(&d.env()).unwrap();
    record_runtime::mutate_records(&d.env(), |s| {
        let mut n = s.clone();
        n.spaces.get_mut(&child.chain_id).unwrap().records.insert(
            record_key(RecordKind::Host, HOST),
            LocalRecord {
                record: host(HOST, "local", 10),
                seq: 0,
                dirty: true,
            },
        );
        Ok(n)
    })
    .unwrap();
    let mut invalid = host("0000000000000002", "remote", 20);
    invalid.payload["jump"] = json!(["0000000000000003"]);
    d.relay
        .push(
            &child.chain_id,
            &child.auth_token,
            &[encode_record(&child, &invalid, 0).unwrap()],
        )
        .unwrap();
    d.relay.clear_calls();
    let report = sync_once(&d.env()).unwrap();
    assert!(report.review_required);
    let cache = &state(&d).spaces[&child.chain_id];
    assert!(cache.records[&record_key(RecordKind::Host, HOST)].dirty);
    assert!(cache
        .records
        .contains_key(&record_key(RecordKind::Host, "0000000000000002")));
    assert!(!d.relay.calls().iter().any(|c| c.starts_with("push:")));
}

#[test]
fn authenticated_schema_three_cannot_clear_a_retained_schema_five_observation() {
    let (d, keys) = fixture();
    let child = add_space(&d, &keys, true);
    update_meta(&d, &keys, 5, None);
    fresh_account_gate(&d.env()).unwrap();
    let previous = d
        .relay
        .rows(&keys.chain_id)
        .iter()
        .find(|r| r.kind == "meta")
        .unwrap()
        .seq;
    let old = value(
        RecordKind::Meta,
        ACCOUNT_META_ID,
        json!({"schema_version":3,"created_by_app_version":"downgraded"}),
        100,
    );
    d.relay
        .push(
            &keys.chain_id,
            &keys.auth_token,
            &[encode_record(&keys, &old, previous).unwrap()],
        )
        .unwrap();
    let before = state(&d);
    d.relay.clear_calls();
    let report = sync_once(&d.env()).unwrap();
    assert_eq!(report.gate, Some(AccountGate::NeedsUpdate { schema: 5 }));
    assert!(state(&d).shared_writes_blocked);
    assert_eq!(
        state(&d).spaces[&child.chain_id],
        before.spaces[&child.chain_id]
    );
    assert_eq!(
        d.relay.calls(),
        vec![format!("pull:{}", &keys.chain_id[..8])]
    );
}
#[test]
fn exhausted_generation_rejects_before_credential_and_relay_callbacks() {
    let (d, _) = fixture();
    d.runtime.core.lock().unwrap().generation = u64::MAX;
    d.keychain
        .fail_reads
        .store(true, std::sync::atomic::Ordering::SeqCst);
    d.relay.clear_calls();
    let error = sync_once(&d.env()).unwrap_err();
    assert!(error.to_string().contains("generation"));
    assert!(d.relay.calls().is_empty());
}
#[test]
fn receipt_generation_overflow_does_not_replace_current_state() {
    let (d, keys) = fixture();
    record_runtime::mutate_records(&d.env(), |s| {
        let mut n = s.clone();
        n.account
            .as_mut()
            .unwrap()
            .records
            .get_mut(&record_key(RecordKind::Meta, ACCOUNT_META_ID))
            .unwrap()
            .dirty = true;
        Ok(n)
    })
    .unwrap();
    let before = state(&d);
    let sent = crate::sync::record_merge::account_outgoing(before.account.as_ref().unwrap(), &keys)
        .unwrap();
    let pushed = crate::sync::merge::Pushed {
        accepted: vec![(sent[0].outgoing.key.clone(), 2)],
        ..Default::default()
    };
    let proof = FreshAccountProof {
        keys,
        relay_url: before.relay_url.clone(),
        gate: AccountGate::Compatible,
        format_gate: AccountGate::Compatible,
        observed_schema: Some(3),
    };
    d.runtime.core.lock().unwrap().generation = u64::MAX;
    assert!(receipt_commit(&d.env(), &proof, None, &sent, &pushed).is_err());
    assert_eq!(state(&d), before);
    assert!(!d.runtime.core.lock().unwrap().unsaved);
}

#[test]
fn frozen_space_stops_all_shared_work_until_account_lifecycle_can_recover() {
    let (d, keys) = fixture();
    let child = add_space(&d, &keys, true);
    sync_once(&d.env()).unwrap();
    record_runtime::mutate_records(&d.env(), |s| {
        let mut n = s.clone();
        n.spaces.get_mut(&child.chain_id).unwrap().records.insert(
            record_key(RecordKind::Host, HOST),
            LocalRecord {
                record: host(HOST, "pending", 20),
                seq: 0,
                dirty: true,
            },
        );
        Ok(n)
    })
    .unwrap();
    d.relay
        .freeze_chain(&child.chain_id, &child.auth_token)
        .unwrap();
    sync_once(&d.env()).unwrap();
    assert!(state(&d).account.as_ref().unwrap().frozen.is_some());
    d.relay.clear_calls();
    sync_once(&d.env()).unwrap();
    assert_eq!(
        d.relay.calls(),
        vec![format!("pull:{}", &keys.chain_id[..8])]
    );
    assert!(state(&d).spaces[&child.chain_id].records[&record_key(RecordKind::Host, HOST)].dirty);
}

#[test]
fn failed_background_sync_exposes_a_generic_durable_error_without_losing_last_success() {
    let (d, _) = fixture();
    sync_once(&d.env()).unwrap();
    let last = state(&d).last_sync_ms;
    d.relay.set_offline(true);
    assert!(sync_once(&d.env()).is_err());
    let after = state(&d);
    assert!(after
        .last_error
        .as_deref()
        .is_some_and(|e| e.starts_with("Sync could not complete")));
    assert_eq!(after.last_sync_ms, last);
    let disk: crate::sync::records_v3::SyncStateV3 =
        serde_json::from_slice(&std::fs::read(d.env().state_path).unwrap()).unwrap();
    assert_eq!(disk.last_error, after.last_error);
}
#[test]
fn network_failure_keeps_a_more_important_retained_format_gate_message() {
    let (d, _) = fixture();
    record_runtime::mutate_records(&d.env(), |s| {
        let mut n = s.clone();
        n.shared_writes_blocked = true;
        n.account.as_mut().unwrap().remote_schema_version = Some(5);
        n.last_error = Some("newer format requires update".into());
        Ok(n)
    })
    .unwrap();
    d.relay.set_offline(true);
    assert!(sync_once(&d.env()).is_err());
    assert_eq!(
        state(&d).last_error.as_deref(),
        Some("newer format requires update")
    );
}

#[test]
fn frozen_policy_cannot_hide_an_authenticated_future_format_gate() {
    let (d, keys) = fixture();
    record_runtime::mutate_records(&d.env(), |s| {
        let mut n = s.clone();
        n.account.as_mut().unwrap().frozen = Some(crate::sync::state_v2::FreezeInfo {
            detected_at_ms: 1,
            markers: Vec::new(),
        });
        Ok(n)
    })
    .unwrap();
    update_meta(&d, &keys, 5, None);
    let proof = fresh_account_gate(&d.env()).unwrap();
    assert_eq!(proof.format_gate, AccountGate::NeedsUpdate { schema: 5 });
    assert_eq!(proof.gate, AccountGate::NeedsUpdate { schema: 5 });
    assert!(proof.ensure_compatible().is_err());
}
#[test]
fn frozen_supported_format_proof_stays_blocked_for_shared_commands() {
    let (d, _) = fixture();
    record_runtime::mutate_records(&d.env(), |s| {
        let mut n = s.clone();
        n.account.as_mut().unwrap().frozen = Some(crate::sync::state_v2::FreezeInfo {
            detected_at_ms: 1,
            markers: Vec::new(),
        });
        Ok(n)
    })
    .unwrap();
    let proof = fresh_account_gate(&d.env()).unwrap();
    assert_eq!(proof.format_gate, AccountGate::Compatible);
    assert!(proof.ensure_compatible().is_err());
    assert!(state(&d).shared_writes_blocked);
}

#[test]
fn group_schema_gate_and_inherited_empty_route_upload_and_resolve_on_peer() {
    use crate::sync::{
        record_groups, record_repository,
        records_v3::{GroupPayload, HostPayload, HostScope},
    };
    let (d, keys) = fixture();
    let child = add_space(&d, &keys, true);
    sync_once(&d.env()).unwrap();
    let scope = HostScope::Space {
        space_id: child.chain_id.clone(),
    };
    record_runtime::mutate_records(&d.env(),|s| {
        let parent:GroupPayload=serde_json::from_value(json!({"schema":1,"name":"Ops","defaults":{"user":"ops","port":22}})).unwrap();
        let s=record_groups::create_group(s,"0000000000000031",scope.clone(),parent,true,100).unwrap();
        let nested:GroupPayload=serde_json::from_value(json!({"schema":1,"name":"Nested","parent_id":"0000000000000031","defaults":{"port":2222,"jump":[]}})).unwrap();
        let s=record_groups::create_group(&s,"0000000000000032",scope.clone(),nested,false,101).unwrap();
        let p:HostPayload=serde_json::from_value(json!({"schema":3,"alias":"grouped","hostname":"group.test","auth":"password","keepalive_secs":10,"group_id":"0000000000000032","jump":["0000000000000099"],"inherit":["user","port","jump"]})).unwrap();
        Ok(record_repository::create_host(&s,HOST,scope.clone(),p,102).unwrap())
    }).unwrap();
    d.relay.clear_calls();
    d.relay.set_push_quota(Some(0));
    assert!(sync_once(&d.env()).is_err());
    assert!(d.relay.rows(&child.chain_id).is_empty());
    assert!(!d
        .relay
        .calls()
        .iter()
        .any(|c| c.starts_with("push:") && c.ends_with(&child.chain_id[..8])));
    d.relay.set_push_quota(None);
    let report = sync_once(&d.env()).unwrap();
    assert!(!report.review_required);
    assert_eq!(d.relay.rows(&child.chain_id).len(), 3);
    // A second device independently joins, decrypts and resolves the same literal values.
    let peer = TestDevice::new("group-peer", &d.relay, &TestClock::new());
    let StartupProbe::Records {
        state: mut peer_state,
        ..
    } = record_runtime::probe_startup(&peer.env().state_path, "peer")
    else {
        panic!()
    };
    peer_state.relay_url = crate::sync::testkit::RELAY_URL.into();
    record_runtime::activate_probe(
        &mut peer.runtime.core.lock().unwrap(),
        StartupProbe::Records {
            state: peer_state,
            fresh: false,
        },
    )
    .unwrap();
    let phrase = d.keychain.get(MNEMONIC_ACCOUNT).unwrap().unwrap();
    crate::sync::record_account::join_account(&peer.env(), &phrase, "peer").unwrap();
    crate::sync::record_account::select_space(&peer.env(), &child.chain_id, true).unwrap();
    sync_once(&peer.env()).unwrap();
    for device in [&*d, &peer] {
        let h = record_repository::get_host(&state(device), HOST).unwrap();
        assert_eq!(h.host.payload.jump, vec!["0000000000000099"]);
        assert!(h.effective_payload.jump.is_empty());
        assert_eq!(h.readiness, record_repository::HostReadiness::Ready);
        assert_eq!(h.effective_payload.user, "ops");
        assert_eq!(h.effective_payload.port, 2222);
        assert_eq!(h.effective_payload.keepalive_secs, 10);
        assert_eq!(h.inherited_from["port"], "0000000000000032");
    }
}

#[test]
fn effective_missing_and_cyclic_routes_require_review_and_preserve_dirty_rows() {
    use crate::sync::{record_repository, records_v3::HostScope};
    for cycle in [false, true] {
        let (d, keys) = fixture();
        let child = add_space(&d, &keys, true);
        update_meta(&d, &keys, 4, None);
        sync_once(&d.env()).unwrap();
        record_runtime::mutate_records(&d.env(), |s| {
            let mut next = s.clone();
            next.spaces
                .get_mut(&child.chain_id)
                .unwrap()
                .records
                .insert(
                    record_key(RecordKind::Host, "0000000000000008"),
                    LocalRecord {
                        record: host("0000000000000008", "dirty", 10),
                        seq: 0,
                        dirty: true,
                    },
                );
            Ok(next)
        })
        .unwrap();
        let group = value(
            RecordKind::Group,
            "0000000000000031",
            json!({
                "schema":1,"name":"Route","defaults":{"jump":["0000000000000002"]}
            }),
            20,
        );
        let mut inherited = host(HOST, "inherited", 20);
        inherited.payload["schema"] = json!(3);
        inherited.payload["group_id"] = json!(group.id);
        inherited.payload["inherit"] = json!(["jump"]);
        let mut rows = vec![group, inherited];
        if cycle {
            let mut target = host("0000000000000002", "target", 20);
            target.payload["jump"] = json!([HOST]);
            rows.push(target);
        }
        let outgoing: Vec<_> = rows
            .iter()
            .map(|row| encode_record(&child, row, 0).unwrap())
            .collect();
        d.relay
            .push(&child.chain_id, &child.auth_token, &outgoing)
            .unwrap();
        d.relay.clear_calls();
        let report = sync_once(&d.env()).unwrap();
        assert!(report.review_required, "cycle={cycle}");
        let current = state(&d);
        let view = record_repository::get_host(&current, HOST).unwrap();
        assert_eq!(
            view.host.scope,
            HostScope::Space {
                space_id: child.chain_id.clone()
            }
        );
        assert_eq!(
            view.readiness,
            record_repository::HostReadiness::NeedsReview
        );
        assert!(view.host.payload.jump.is_empty());
        assert_eq!(view.effective_payload.jump, vec!["0000000000000002"]);
        assert!(
            current.spaces[&child.chain_id].records
                [&record_key(RecordKind::Host, "0000000000000008")]
                .dirty
        );
        assert!(!d.relay.calls().iter().any(|call| call.starts_with("push:")));
    }
}

#[test]
fn route_review_uses_targets_from_other_scopes_in_the_candidate_snapshot() {
    let (d, keys) = fixture();
    let source = add_space(&d, &keys, true);
    let target = add_space(&d, &keys, true);
    sync_once(&d.env()).unwrap();
    record_runtime::mutate_records(&d.env(), |s| {
        let mut next = s.clone();
        let mut root = host(HOST, "root", 10);
        root.payload["jump"] = json!(["0000000000000002"]);
        for (id, record) in [
            (&source.chain_id, root),
            (&target.chain_id, host("0000000000000002", "target", 10)),
        ] {
            next.spaces.get_mut(id).unwrap().records.insert(
                record_key(record.kind, &record.id),
                LocalRecord {
                    record,
                    seq: 0,
                    dirty: true,
                },
            );
        }
        Ok(next)
    })
    .unwrap();
    let report = sync_once(&d.env()).unwrap();
    assert!(!report.review_required);
    assert_eq!(d.relay.rows(&source.chain_id).len(), 1);
    assert_eq!(d.relay.rows(&target.chain_id).len(), 1);
}

fn assert_import_warning_does_not_block_space_uploads(warning_already_clean: bool) {
    use crate::session::directory::{DirectoryError, HostDirectory};
    use crate::session::protocol::HostQuery;
    use crate::session::record_directory::{RecordDirectory, RecordSources};
    use crate::sync::record_repository::{self as repo, HostReadiness};

    let (d, keys) = fixture();
    let child = add_space(&d, &keys, true);
    let mut warning = host("0000000000000002", "import-warning", 10);
    warning.payload["imported"] = json!({
        "source":"fixture/config","at_ms":1,"unsupported":[{
            "keyword":"Include","value":"fixture/*.conf","requires_review":true
        }]
    });
    let mut initial = vec![host(HOST, "valid-peer", 10)];
    if warning_already_clean {
        initial.push(warning.clone());
    }
    d.relay
        .push(
            &child.chain_id,
            &child.auth_token,
            &initial
                .iter()
                .map(|row| encode_record(&child, row, 0).unwrap())
                .collect::<Vec<_>>(),
        )
        .unwrap();
    sync_once(&d.env()).unwrap();
    record_runtime::mutate_records(&d.env(), |s| {
        let current = repo::get_host(s, HOST).unwrap();
        let mut payload = current.host.payload;
        payload.notes = "Edited while an imported host awaits connection review".into();
        let mut next = repo::update_host(s, HOST, &current.revision, payload, 20).unwrap();
        if !warning_already_clean {
            next.spaces
                .get_mut(&child.chain_id)
                .unwrap()
                .records
                .insert(
                    record_key(warning.kind, &warning.id),
                    LocalRecord {
                        record: warning.clone(),
                        seq: 0,
                        dirty: true,
                    },
                );
        }
        Ok(next)
    })
    .unwrap();
    let before = state(&d);
    assert_eq!(
        before.spaces[&child.chain_id].records[&record_key(warning.kind, &warning.id)].dirty,
        !warning_already_clean
    );
    let report = sync_once(&d.env()).unwrap();
    assert!(!report.review_required);
    assert!(report.pushed >= 1);
    let current = state(&d);
    assert!(current.spaces[&child.chain_id]
        .records
        .values()
        .all(|row| !row.dirty));
    assert_eq!(d.relay.rows(&child.chain_id).len(), 2);
    let imported = repo::get_host(&current, &warning.id).unwrap();
    assert_eq!(imported.readiness, HostReadiness::NeedsReview);
    assert!(imported.effective_payload.jump.is_empty());
    assert_eq!(
        repo::get_host(&current, HOST).unwrap().readiness,
        HostReadiness::Ready
    );
    let directory = RecordDirectory::new(RecordSources {
        snapshot: Box::new(move || Ok(current.clone())),
        material: Box::new(|_| panic!("review must precede key material access")),
        username: Box::new(|| panic!("review must precede username resolution")),
        pin: Box::new(|_, _, _, _| panic!("review must precede pinning")),
    });
    assert!(matches!(
        directory.resolve(&HostQuery::Id(warning.id)),
        Err(DirectoryError::Unsupported(_))
    ));
}

#[test]
fn dirty_import_warning_allows_valid_peer_upload_but_still_blocks_connection() {
    assert_import_warning_does_not_block_space_uploads(false);
}

#[test]
fn clean_import_warning_allows_valid_peer_upload_but_still_blocks_connection() {
    assert_import_warning_does_not_block_space_uploads(true);
}

#[test]
fn space_pin_credential_and_relay_waits_release_lifecycle_and_cancel_cannot_pin() {
    use crate::session::{connect::CancelToken, record_pin};
    use crate::ssh::{fake::default_server_key, AuthMethod, Hop};
    struct BlockingKeys<'a> {
        inner: &'a dyn Keychain,
        entered: std::sync::mpsc::SyncSender<()>,
        release: Arc<Mutex<std::sync::mpsc::Receiver<()>>>,
    }
    impl Keychain for BlockingKeys<'_> {
        fn get(&self, a: &str) -> Result<Option<String>, AppError> {
            self.entered.send(()).unwrap();
            self.release.lock().unwrap().recv().unwrap();
            self.inner.get(a)
        }
        fn set(&self, _: &str, _: &str) -> Result<(), AppError> {
            panic!()
        }
        fn delete(&self, _: &str) -> Result<(), AppError> {
            panic!()
        }
    }
    for credential in [true, false] {
        let (device, keys) = fixture();
        let child = add_space(&device, &keys, true);
        fresh_account_gate(&device.env())
            .unwrap()
            .ensure_compatible()
            .unwrap();
        record_runtime::mutate_records(&device.env(),|s|crate::sync::record_repository::create_host(s,HOST,crate::sync::records_v3::HostScope::Space{space_id:child.chain_id.clone()},serde_json::from_value(json!({"schema":2,"alias":"web","hostname":"host.test","user":"ops","auth":"password"})).unwrap(),3).map_err(|e|AppError::Other(e.to_string()))).unwrap();
        let (entered, observed) = std::sync::mpsc::sync_channel(1);
        let (release, resume) = std::sync::mpsc::sync_channel(1);
        let blocking = BlockingKeys {
            inner: &device.keychain,
            entered: entered.clone(),
            release: Arc::new(Mutex::new(resume)),
        };
        let cancel = CancelToken::default();
        let hop = Hop::new(HOST, "web", "host.test", 22, "ops", AuthMethod::Password).reference();
        let hook = Hooks {
            before_pull: (!credential).then(|| {
                let entered = entered.clone();
                let resume = blocking.release.clone();
                Box::new(move || {
                    entered.send(()).unwrap();
                    resume.lock().unwrap().recv().unwrap();
                }) as Box<dyn FnOnce() + Send>
            }),
            ..Default::default()
        };
        let connector = HookedConnector::new(&device.relay, hook);
        let mut env = device.env();
        if credential {
            env.keychain = &blocking;
        } else {
            env.relays = &connector;
        }
        std::thread::scope(|scope| {
            let worker = scope.spawn(|| {
                record_pin::confirm(
                    &env,
                    &hop,
                    None,
                    &default_server_key(),
                    env.keychain,
                    &cancel,
                    &|| Ok(()),
                )
            });
            observed
                .recv_timeout(std::time::Duration::from_secs(3))
                .unwrap();
            let lifecycle_free = device.runtime.lifecycle.try_lock().is_ok();
            cancel.cancel();
            release.send(()).unwrap();
            let result = worker.join().unwrap();
            assert!(
                lifecycle_free,
                "credential/relay wait must not own lifecycle"
            );
            assert!(result.is_err(), "canceled preparation must not pin");
        });
        assert!(crate::sync::record_repository::get_host(
            &record_runtime::snapshot(&device.env()).unwrap().0,
            HOST
        )
        .unwrap()
        .host
        .payload
        .host_key
        .is_none());
    }
}

/// Public test fixture reused by the end-to-end MCP pin contract tests; no OS resources.
pub(crate) fn pin_fixture() -> Arc<TestDevice> {
    let (device, keys) = fixture();
    let child = add_space(&device, &keys, true);
    fresh_account_gate(&device.env())
        .unwrap()
        .ensure_compatible()
        .unwrap();
    record_runtime::mutate_records(&device.env(),|s|crate::sync::record_repository::create_host(s,HOST,crate::sync::records_v3::HostScope::Space{space_id:child.chain_id.clone()},serde_json::from_value(json!({"schema":2,"alias":"web","hostname":"host.test","user":"ops","auth":"interactive"})).unwrap(),3).map_err(|e|AppError::Other(e.to_string()))).unwrap();
    device
}

#[test]
fn pin_preparation_rejects_changed_generation_scope_account_endpoint_and_public_key() {
    use crate::session::{connect::CancelToken, record_pin};
    use crate::ssh::{fake::default_server_key, AuthMethod, Hop};
    use crate::sync::{record_repository as repo, records_v3::*, slot_rules::test_keys};
    const KEY: &str = "11111111111111111111111111111111";
    for change in ["generation", "scope", "account", "endpoint", "public_key"] {
        let device = pin_fixture();
        record_runtime::mutate_records(&device.env(), |state| {
            let mut next = state.clone();
            let public = ssh_key::PublicKey::from_openssh(test_keys::PLAIN_PUBLIC).unwrap();
            next.local.keys.insert(
                KEY.into(),
                LocalKeyMetadata {
                    vault_id: KEY.into(),
                    public: KeySlotPayload {
                        schema: 2,
                        name: "fixture".into(),
                        public_key: test_keys::PLAIN_PUBLIC.into(),
                        fingerprint: public.fingerprint(ssh_key::HashAlg::Sha256).to_string(),
                        key_type: public.algorithm().to_string(),
                        has_passphrase: false,
                        created_at_ms: 1,
                        origin_device_id: next.device_id.clone(),
                    },
                },
            );
            Ok(next)
        })
        .unwrap();
        let changed = device.clone();
        let connector = HookedConnector::new(
            &device.relay,
            Hooks {
                before_pull: Some(Box::new(move || {
                    assert!(changed.runtime.lifecycle.try_lock().is_ok());
                    record_runtime::mutate_records(&changed.env(), |state| {
                        let mut next = state.clone();
                        let host = repo::get_host(state, HOST).unwrap();
                        match change {
                            "generation" => {}
                            "scope" => {
                                next = repo::move_host(
                                    state,
                                    HOST,
                                    &host.revision,
                                    HostScope::Local,
                                    40,
                                )
                                .unwrap()
                            }
                            "account" => next.account.as_mut().unwrap().chain_id = "b".repeat(64),
                            "endpoint" => {
                                let mut payload = host.host.payload;
                                payload.hostname = "changed.test".into();
                                next = repo::update_host(state, HOST, &host.revision, payload, 40)
                                    .unwrap();
                            }
                            "public_key" => {
                                let public =
                                    ssh_key::PublicKey::from_openssh(test_keys::ECDSA_PUBLIC)
                                        .unwrap();
                                let key = &mut next.local.keys.get_mut(KEY).unwrap().public;
                                key.public_key = test_keys::ECDSA_PUBLIC.into();
                                key.fingerprint =
                                    public.fingerprint(ssh_key::HashAlg::Sha256).to_string();
                                key.key_type = public.algorithm().to_string();
                            }
                            _ => unreachable!(),
                        }
                        Ok(next)
                    })
                    .unwrap();
                })),
                ..Default::default()
            },
        );
        let mut env = device.env();
        env.relays = &connector;
        let hop =
            Hop::new(HOST, "web", "host.test", 22, "ops", AuthMethod::Interactive).reference();
        let result = record_pin::confirm(
            &env,
            &hop,
            None,
            &default_server_key(),
            env.keychain,
            &CancelToken::default(),
            &|| Ok(()),
        );
        assert!(result.is_err(), "stale {change} preparation must fail");
        let current = record_runtime::snapshot(&env).unwrap().0;
        assert!(
            repo::get_host(&current, HOST)
                .unwrap()
                .host
                .payload
                .host_key
                .is_none(),
            "{change}"
        );
        if change == "account" {
            assert_eq!(
                current.account.as_ref().unwrap().chain_id,
                "b".repeat(64),
                "preparation must not republish old account"
            );
        }
    }
}

#[test]
fn local_to_space_during_external_guard_cannot_bypass_fresh_account_preparation() {
    use crate::session::{connect::CancelToken, record_pin};
    use crate::ssh::{fake::default_server_key, AuthMethod, Hop};
    use crate::sync::{record_repository as repo, records_v3::HostScope};
    let device = pin_fixture();
    let original = repo::get_host(&record_runtime::snapshot(&device.env()).unwrap().0, HOST)
        .unwrap()
        .host
        .scope;
    record_runtime::mutate_records(&device.env(), |state| {
        let host = repo::get_host(state, HOST).unwrap();
        Ok(repo::move_host(state, HOST, &host.revision, HostScope::Local, 40).unwrap())
    })
    .unwrap();
    let once = std::sync::atomic::AtomicBool::new(false);
    let guard = || {
        assert!(
            device.runtime.lifecycle.try_lock().is_ok(),
            "caller guard must run outside lifecycle"
        );
        if !once.swap(true, std::sync::atomic::Ordering::SeqCst) {
            record_runtime::mutate_records(&device.env(), |state| {
                let host = repo::get_host(state, HOST).unwrap();
                Ok(repo::move_host(state, HOST, &host.revision, original.clone(), 41).unwrap())
            })
            .unwrap();
        }
        Ok(())
    };
    let hop = Hop::new(HOST, "web", "host.test", 22, "ops", AuthMethod::Interactive).reference();
    assert!(record_pin::confirm(
        &device.env(),
        &hop,
        None,
        &default_server_key(),
        &device.keychain,
        &CancelToken::default(),
        &guard
    )
    .is_err());
    assert!(
        repo::get_host(&record_runtime::snapshot(&device.env()).unwrap().0, HOST)
            .unwrap()
            .host
            .payload
            .host_key
            .is_none()
    );
}
