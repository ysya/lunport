//! Actual loopback account transport; the cutover fixture is test-only, not migration authority.
use super::*;
use crate::sync::{
    central::{
        active_cycle,
        payload::{self, Catalog, Data, GroupOrder, Identity},
        projection::Plan,
        projection_cache::Cache,
        projection_state::Ledger,
        rekey::{self, Checkpoint},
        request_budget::Budget,
        round,
        wire::{self, number},
    },
    record_import::central_local,
    record_keys, record_repository,
    records_v3::{HostScope, CENTRAL_STATE_VERSION},
    slot_rules::test_keys,
};
use crate::vault::store::{self, EntryOrigin};
use std::{
    fs,
    sync::atomic::{AtomicBool, Ordering},
    time::Duration,
};
fn state(d: &TestDevice) -> crate::sync::records_v3::SyncStateV3 {
    record_runtime::snapshot(&d.env()).unwrap().0
}
struct Fixture {
    service: Service,
    d: Arc<TestDevice>,
    key: String,
    keys: crypto::VaultKeys,
    batches: Arc<Mutex<Vec<Vec<crypto::RecordEnvelope>>>>,
    lose_response: Arc<AtomicBool>,
}
fn install_push(
    service: &mut Service,
) -> (
    Arc<Mutex<Vec<Vec<crypto::RecordEnvelope>>>>,
    Arc<AtomicBool>,
) {
    let batches = Arc::new(Mutex::new(vec![]));
    let seen = Arc::clone(&batches);
    let lose = Arc::new(AtomicBool::new(false));
    let status = Arc::clone(&lose);
    let state = Arc::clone(&service.state);
    service.server.mock("POST", mockito::Matcher::Regex("^/v1/vaults/[0-9a-f]{64}/records$".into()))
        .with_status_code_from_request(move |_| if status.swap(false, Ordering::SeqCst) {503} else {200})
        .with_body_from_request(move |request| {
            let body:Value = serde_json::from_slice(request.body().unwrap()).unwrap();
            let rows:Vec<crypto::RecordEnvelope> = serde_json::from_value(body["records"].clone()).unwrap();
            assert!(!rows.is_empty() && rows.len() <= 32);
            seen.lock().unwrap().push(rows.clone());
            let mut account = state.lock().unwrap(); let mut next = account.history.clone();
            let chain = account.chain().unwrap(); let mut receipts = vec![];
            for envelope in rows {
                let h = &envelope.header;
                assert_eq!(h.author, account.device(request)); assert_eq!(h.membership_head, chain.current().head());
                envelope.verify(&chain.author_at(&h.membership_head, &h.author).unwrap().signing).unwrap();
                let digest = rekey::envelope_digest(&envelope).unwrap();
                let row = if let Some(old) = next.iter().find(|row| row.envelope.header.operation_id == h.operation_id) {
                    assert_eq!(old.envelope, envelope); old.clone()
                } else {
                    let revision = next.iter().rev().find(|row| row.envelope.header.record_id == h.record_id).map_or(0, |row| number(&row.revision, false).unwrap());
                    assert_eq!(number(&h.expected_revision,true).unwrap(), revision);
                    let sequence = (next.len()+1).to_string();
                    let history_hash = crypto::hash(&wire::canonical(&["lunport-history-v2", next.last().map_or(crate::sync::central::rotation::ZERO, |row| row.history_hash.as_str()), &sequence, &digest]).unwrap());
                    let row = rekey::Version {envelope:envelope.clone(), revision:(revision+1).to_string(), sequence, digest:digest.clone(), history_hash};
                    next.push(row.clone()); row
                };
                receipts.push(json!({"operation_id":row.envelope.header.operation_id,"record_id":row.envelope.header.record_id,"revision":row.revision,"sequence":row.sequence,"digest":row.digest,"history_hash":row.history_hash}));
            }
            account.history = next;
            json!({"receipts":receipts,"sequence":account.history.len().to_string(),"history_hash":account.history.last().unwrap().history_hash}).to_string().into_bytes()
        }).create();
    (batches, lose)
}
fn fixture() -> Fixture {
    fixture_with_service(Service::new())
}
fn fixture_with_service(mut service: Service) -> Fixture {
    let d = Arc::new(TestDevice::new(
        "active-cycle",
        &FakeRelay::new(),
        &TestClock::new(),
    ));
    service.login(&d);
    bootstrap::prepare(&d.env()).unwrap();
    let kit = bootstrap::reveal(&d.env()).unwrap();
    bootstrap::confirm(&d.env(), &kit.root).unwrap();
    controller::refresh(&d.env()).unwrap();
    joining::initialize(&d.env()).unwrap();
    let session = controller::context(&d.env()).unwrap();
    let mut records = state(&d);
    let owner = records.local.central.as_mut().unwrap();
    let chain = owner.control.verified_chain().unwrap();
    let wrap = &owner.own_wraps[0];
    let keys = wrap
        .open(
            &session.identity.as_ref().unwrap().keys,
            &wrap.header,
            &chain
                .author_at(&wrap.header.membership_head, &wrap.header.author)
                .unwrap()
                .signing,
        )
        .unwrap();
    owner.control.cutover = true;
    owner.control = owner
        .control
        .approve_library("a".repeat(64), chain.current().head())
        .unwrap();
    let id = Identity {
        kind: "meta".into(),
        id: "catalog".into(),
        scope: None,
    };
    let catalog = Data::Catalog(Catalog {
        tunnels: vec![],
        transports: vec![],
        collections: vec![],
        group_orders: vec![GroupOrder {
            scope: HostScope::Local,
            ids: vec![],
        }],
    });
    let anchor = owner.control.anchor.as_ref().unwrap();
    let envelope = crypto::seal_record(
        &keys,
        &session.identity.as_ref().unwrap().keys,
        RecordHeader {
            origin: anchor.origin.clone(),
            account_id: anchor.account_id.clone(),
            genesis_hash: anchor.genesis_hash.clone(),
            vault_id: owner.replica.as_ref().unwrap().vault.clone(),
            record_id: id.opaque(&keys).unwrap(),
            key_epoch: "1".into(),
            membership_head: chain.current().head().into(),
            author: owner.control.device.id.clone(),
            operation_id: crypto::random_id(16).unwrap(),
            expected_revision: "0".into(),
            kind: "meta".into(),
            deleted: false,
        },
        &payload::encode(&id, &catalog).unwrap(),
    )
    .unwrap();
    let digest = rekey::envelope_digest(&envelope).unwrap();
    let history_hash = crypto::hash(
        &wire::canonical(&[
            "lunport-history-v2",
            crate::sync::central::rotation::ZERO,
            "1",
            &digest,
        ])
        .unwrap(),
    );
    let row = rekey::Version {
        envelope,
        revision: "1".into(),
        sequence: "1".into(),
        digest,
        history_hash: history_hash.clone(),
    };
    owner.replica = Some(
        owner
            .replica
            .as_ref()
            .unwrap()
            .prepare_page(
                &chain,
                &keys,
                &[row.clone()],
                &Checkpoint {
                    epoch: 1,
                    sequence: 1,
                    history_hash,
                },
            )
            .unwrap()
            .next,
    );
    service.state.lock().unwrap().history = vec![row];
    let plan = Plan::current(owner.clone(), &keys).unwrap();
    let cache = Cache::initial(&plan, 100, &BTreeMap::new()).unwrap();
    records.version = CENTRAL_STATE_VERSION;
    records.account = Some(cache.account);
    records.spaces = cache.spaces;
    records.local.hosts = cache.hosts;
    records.local.groups = cache.groups;
    records.local.group_order = cache.group_order;
    records.local.central_projection = Some(Ledger::initial(&plan, &records, &keys).unwrap());
    // An inert test-only post-migration disk image. The production migration guard stays intact.
    crate::sync::records_v3::validate_state(&records).unwrap();
    fs::write(&d.env().state_path, serde_json::to_vec(&records).unwrap()).unwrap();
    let probe = record_runtime::probe_startup(&d.env().state_path, "active-cycle");
    record_runtime::activate_probe(&mut d.runtime.core.lock().unwrap(), probe).unwrap();
    d.runtime.core.lock().unwrap().central_session = Some(session);
    let (records, generation) = record_runtime::snapshot(&d.env()).unwrap();
    let invocation = central_local::invocation(&records)
        .unwrap()
        .with_generation(generation);
    let imported = record_keys::import_local_scoped(
        &d.env(),
        "work",
        Zeroizing::new(test_keys::plain()),
        EntryOrigin::Imported,
        Some(&invocation),
    )
    .unwrap();
    let (batches, lose_response) = install_push(&mut service);
    Fixture {
        service,
        d,
        key: imported.key_id,
        keys,
        batches,
        lose_response,
    }
}
fn assert_finished(f: &Fixture) {
    let state = state(&f.d);
    let owner = state.local.central.as_ref().unwrap();
    assert!(owner.replica.as_ref().unwrap().pending.is_empty());
    assert_eq!(owner.replica.as_ref().unwrap().checkpoint.sequence, 3);
    assert_eq!(
        record_repository::resolve_key(&state, &f.key)
            .unwrap()
            .status,
        record_repository::KeyStatus::Available
    );
    assert_eq!(f.service.state.lock().unwrap().history.len(), 3);
    let kinds: Vec<_> = f
        .batches
        .lock()
        .unwrap()
        .iter()
        .flatten()
        .map(|row| row.header.kind.clone())
        .collect();
    assert_eq!(kinds, vec!["keyslot", "key"]);
}
#[test]
fn normal_round_confirms_public_then_private_and_automatically_reuses_the_protected_source() {
    let f = fixture();
    let vault = fs::read(store::vault_path(&f.d.env().state_path)).unwrap();
    let no_prompt = NoPrompt(&f.d.keychain);
    let mut env = f.d.env();
    env.keychain = &no_prompt;
    let report = round::sync_once(&env).unwrap();
    assert_eq!(report.requests, 5);
    assert_eq!(report.staged, 2);
    assert!(!report.more);
    assert_finished(&f);
    assert_eq!(
        fs::read(store::vault_path(&f.d.env().state_path)).unwrap(),
        vault
    );
    assert_eq!(round::sync_once(&f.d.env()).unwrap().requests, 1);
}
#[test]
fn a_lost_push_response_is_reconciled_from_history_before_private_material_is_released() {
    let f = fixture();
    f.lose_response.store(true, Ordering::SeqCst);
    assert!(round::sync_once(&f.d.env()).is_err());
    assert_eq!(f.batches.lock().unwrap().len(), 1);
    assert_eq!(f.service.state.lock().unwrap().history.len(), 2);
    {
        let mut core = f.d.runtime.core.lock().unwrap();
        core.central_poll.retry_at = None;
    }
    round::sync_once(&f.d.env()).unwrap();
    assert_finished(&f);
}
#[test]
fn one_refused_grant_can_be_renewed_under_the_same_budget_without_legacy_fallback() {
    let f = fixture();
    f.service.state.lock().unwrap().reject_pull_once = true;
    let sessions = f.service.state.lock().unwrap().sessions.len();
    let report = round::sync_once(&f.d.env()).unwrap();
    assert_eq!(report.requests, 8);
    assert_eq!(f.service.state.lock().unwrap().sessions.len(), sessions + 1);
    assert_finished(&f);
}
#[test]
fn a_request_limit_defers_claimed_public_and_unsent_private_then_resumes_from_verified_history() {
    let f = fixture();
    let budget = Budget::limited(2, Duration::from_secs(30));
    let error =
        active_cycle::with_budget(&f.d.env(), &mut round::Report::default(), &budget).unwrap_err();
    assert!(Budget::exhausted(&error));
    assert_eq!(budget.used(), 2);
    let state = state(&f.d);
    let pending = &state
        .local
        .central
        .as_ref()
        .unwrap()
        .replica
        .as_ref()
        .unwrap()
        .pending;
    assert!(pending.values().any(|p| p.claimed.is_some()));
    assert!(pending
        .values()
        .any(|p| p.latest.envelope.header.kind == "key" && p.sent.is_none()));
    round::sync_once(&f.d.env()).unwrap();
    assert_finished(&f);
}
#[test]
fn a_rekey_notice_blocks_all_uploads_and_does_not_activate_an_unverified_epoch() {
    let f = fixture();
    let before = state(&f.d);
    f.service.state.lock().unwrap().rekey_pending = true;
    assert!(round::sync_once(&f.d.env()).is_err());
    let after = state(&f.d);
    assert_eq!(
        after.local.central.as_ref().unwrap().control.phase,
        crate::sync::central::client_state::Phase::Rekey
    );
    assert_eq!(
        after.local.central.as_ref().unwrap().replica,
        before.local.central.as_ref().unwrap().replica
    );
    assert_eq!(
        after.local.central_projection,
        before.local.central_projection
    );
    assert!(f.batches.lock().unwrap().is_empty());
}
#[test]
fn service_cooldown_stops_the_whole_active_round_and_never_echoes_response_secrets() {
    let mut f = fixture();
    // Consume the fixture's fallback route once before installing a higher-priority denial.
    let session = controller::context(&f.d.env()).unwrap();
    let records = state(&f.d);
    let vault = &records
        .local
        .central
        .as_ref()
        .unwrap()
        .replica
        .as_ref()
        .unwrap()
        .vault;
    crate::sync::central::api::Api::new(&session.profile.origin)
        .unwrap()
        .vault(
            session.device.as_ref().unwrap(),
            vault,
            crate::sync::central::api::VaultResource::Records { since: 1 },
        )
        .unwrap()
        .success()
        .unwrap();
    let limited = f
        .service
        .server
        .mock(
            "GET",
            mockito::Matcher::Regex("^/v1/vaults/[0-9a-f]{64}/records$".into()),
        )
        .match_query(mockito::Matcher::Any)
        .with_status(429)
        .with_header("retry-after", "200")
        .with_body("SYNTHETIC_SECRET_SENTINEL")
        .expect(1)
        .create();
    let before = state(&f.d);
    assert!(round::sync_once(&f.d.env()).is_err());
    assert!(
        state(&f.d) == before,
        "cooldown must retain the complete source state"
    );
    assert!(round::cooldown(&f.d.env()) > Duration::from_secs(199));
    assert_eq!(round::sync_once(&f.d.env()).unwrap().requests, 0);
    assert!(!controller::status(&f.d.env())
        .unwrap()
        .error
        .unwrap()
        .contains("SENTINEL"));
    assert!(f.batches.lock().unwrap().is_empty());
    limited.assert();
}

struct NoPrompt<'a>(&'a crate::sync::testkit::MemKeychain);
impl crate::sync::env::Keychain for NoPrompt<'_> {
    fn get(&self, _: &str) -> Result<Option<String>, crate::error::AppError> {
        panic!("background sync requested interactive read")
    }
    fn set(&self, _: &str, _: &str) -> Result<(), crate::error::AppError> {
        panic!("background sync requested interactive write")
    }
    fn delete(&self, _: &str) -> Result<(), crate::error::AppError> {
        panic!("background sync requested credential deletion")
    }
    fn get_noninteractive(&self, role: &str) -> Result<Option<String>, crate::error::AppError> {
        crate::sync::env::Keychain::get(self.0, role)
    }
    fn set_noninteractive(&self, role: &str, secret: &str) -> Result<(), crate::error::AppError> {
        crate::sync::env::Keychain::set(self.0, role, secret)
    }
}
#[test]
fn a_local_b_during_http_remains_visible_and_conflicts_with_remote_c_without_blocking_other_records(
) {
    let f = fixture();
    let logical = "000000000000f001";
    let before = state(&f.d);
    let owner = before.local.central.as_ref().unwrap();
    let anchor = owner.control.anchor.as_ref().unwrap();
    let session = controller::context(&f.d.env()).unwrap();
    let id = Identity {
        kind: "host".into(),
        id: logical.into(),
        scope: Some(HostScope::Local),
    };
    let host = serde_json::from_value(
        json!({"schema":2,"alias":"remote_c","hostname":"fixture.invalid","auth":"password"}),
    )
    .unwrap();
    let envelope = crypto::seal_record(
        &f.keys,
        &session.identity.as_ref().unwrap().keys,
        RecordHeader {
            origin: anchor.origin.clone(),
            account_id: anchor.account_id.clone(),
            genesis_hash: anchor.genesis_hash.clone(),
            vault_id: owner.replica.as_ref().unwrap().vault.clone(),
            record_id: id.opaque(&f.keys).unwrap(),
            key_epoch: "1".into(),
            membership_head: owner.control.highwater.as_ref().unwrap().head.clone(),
            author: owner.control.device.id.clone(),
            operation_id: crypto::random_id(16).unwrap(),
            expected_revision: "0".into(),
            kind: "host".into(),
            deleted: false,
        },
        &payload::encode(&id, &Data::Host(host)).unwrap(),
    )
    .unwrap();
    let digest = rekey::envelope_digest(&envelope).unwrap();
    let mut account = f.service.state.lock().unwrap();
    let history_hash = crypto::hash(
        &wire::canonical(&[
            "lunport-history-v2",
            &account.history.last().unwrap().history_hash,
            "2",
            &digest,
        ])
        .unwrap(),
    );
    account.history.push(rekey::Version {
        envelope,
        revision: "1".into(),
        sequence: "2".into(),
        digest,
        history_hash,
    });
    let active = Arc::clone(&f.d);
    account.on_pull = Some(Box::new(move || {
        // Server callback runs while the client is in HTTP; none of the runtime locks may be held.
        drop(
            active
                .runtime
                .lifecycle
                .try_lock()
                .expect("HTTP held lifecycle"),
        );
        drop(active.runtime.vault.try_lock().expect("HTTP held vault"));
        drop(
            active
                .runtime
                .format_publication
                .try_lock()
                .expect("HTTP held publication"),
        );
        drop(active.runtime.core.try_lock().expect("HTTP held Core"));
        record_runtime::mutate_records(&active.env(),|state| {
            record_repository::create_host(state,logical,HostScope::Local,serde_json::from_value(json!({"schema":2,"alias":"local_b","hostname":"local.invalid","auth":"password"})).unwrap(),900).map_err(|_|crate::error::AppError::Other("synthetic local edit failed".into()))
        }).unwrap();
    }));
    drop(account);
    round::sync_once(&f.d.env()).unwrap();
    let after = state(&f.d);
    assert_eq!(
        after.local.hosts
            [&crate::sync::record::record_key(crate::sync::record::RecordKind::Host, logical)]
            .record
            .payload["alias"],
        "local_b"
    );
    let replica = after
        .local
        .central
        .as_ref()
        .unwrap()
        .replica
        .as_ref()
        .unwrap();
    assert!(replica.conflicts.contains_key(&id.opaque(&f.keys).unwrap()));
    assert_eq!(
        record_repository::resolve_key(&after, &f.key)
            .unwrap()
            .status,
        record_repository::KeyStatus::Available
    );
    assert!(f
        .batches
        .lock()
        .unwrap()
        .iter()
        .flatten()
        .all(|row| row.header.kind != "host"));
}

#[test]
fn actual_active_takeover_rotates_then_reconciles_its_unsent_key_through_background_rounds() {
    use crate::sync::central::{client_state::Phase, migration_flow, replacement_flow};
    use crate::sync::env::Keychain;
    let origin = "https://takeover.synthetic.invalid";
    let service = Service::at_origin(Some(origin));
    let address = service.server.url();
    crate::sync::central::api::with_test_transport(origin, &address, || {
        let f = fixture_with_service(service);
        let trusted = TestDevice::new("trusted-peer", &FakeRelay::new(), &f.d.clock);
        f.service.login(&trusted);
        let invite = devices::pairing_code(&trusted.env()).unwrap();
        devices::approve(&f.d.env(), &invite.code).unwrap();
        controller::refresh(&trusted.env()).unwrap();
        round::sync_once(&trusted.env()).unwrap();
        let before = state(&f.d);
        assert!(!before
            .local
            .central
            .as_ref()
            .unwrap()
            .replica
            .as_ref()
            .unwrap()
            .pending
            .is_empty());
        let pending = replacement_flow::begin_trusted(&f.d.env()).unwrap();
        let operation = pending.operation.unwrap();
        let invite = replacement_flow::pairing_code(&f.d.env(), &operation).unwrap();
        devices::approve(&trusted.env(), &invite.code).unwrap();
        assert_eq!(
            replacement_flow::begin_trusted(&f.d.env()).unwrap().phase,
            "reading"
        );
        assert_eq!(
            replacement_flow::advance(&f.d.env(), &operation)
                .unwrap()
                .phase,
            "complete"
        );
        let switched = state(&f.d);
        assert!(switched.local.central_cache_source.is_some());
        assert!(switched.local.central_projection.is_none());
        assert_eq!(
            switched.local.central.as_ref().unwrap().control.phase,
            Phase::Rekey
        );
        let profile = before
            .local
            .central
            .as_ref()
            .unwrap()
            .control
            .profile
            .profile()
            .unwrap();
        f.d.keychain.delete(&profile.slot("device")).unwrap();
        for _ in 0..12 {
            round::sync_once(&f.d.env()).unwrap();
            if state(&f.d).local.central.as_ref().unwrap().control.phase == Phase::Active {
                break;
            }
        }
        let rotated = state(&f.d);
        assert_eq!(
            rotated.local.central.as_ref().unwrap().control.phase,
            Phase::Active
        );
        assert_eq!(
            rotated
                .local
                .central
                .as_ref()
                .unwrap()
                .replica
                .as_ref()
                .unwrap()
                .checkpoint
                .epoch,
            2
        );
        assert!(rotated
            .local
            .central
            .as_ref()
            .unwrap()
            .replacement_archives
            .iter()
            .all(|a| a.needs_reconciliation));
        assert!(rotated.local.central_cache_source.is_some());
        let scope = migration_flow::Scope::from_state(&rotated).unwrap();
        let mut review = None;
        for _ in 0..12 {
            if let Some(value) = migration_flow::prepare(&f.d.env(), &scope).unwrap().review {
                review = Some(value);
                break;
            }
        }
        let review = serde_json::to_value(review.unwrap()).unwrap();
        migration_flow::confirm(&f.d.env(), &scope, review["ticket"].as_str().unwrap())
            .unwrap();
        for _ in 0..40 {
            round::sync_once(&f.d.env()).unwrap();
            if state(&f.d).local.central.as_ref().unwrap().can_upload() {
                break;
            }
        }
        let completed = state(&f.d);
        let owner = completed.local.central.as_ref().unwrap();
        assert!(owner.can_upload());
        assert!(completed.local.central_cache_source.is_none());
        completed
            .local
            .central_projection
            .as_ref()
            .unwrap()
            .validate(owner)
            .unwrap();
        let key = completed
            .local
            .keys
            .values()
            .find(|k| k.public.name == "work")
            .unwrap();
        let vault = store::read_vault(&store::vault_path(&f.d.env().state_path), &f.d.keychain)
            .unwrap();
        assert_eq!(
            vault.get(&key.vault_id).unwrap().unwrap().private_key,
            test_keys::plain()
        );
        assert!(f.d.keychain.get(&profile.slot("device")).unwrap().is_none());
    });
}

#[test]
fn tunnel_catalog_edits_upload_read_back_materialize_and_delete_without_plaintext_or_resurrection(
) {
    use crate::sync::tunnel_rules::{self, TunnelRule};
    let f = fixture();
    round::sync_once(&f.d.env()).unwrap();
    let rule: TunnelRule = serde_json::from_value(json!({"id":"e".repeat(16),"name":"Private database","host_id":"f".repeat(16),"forward":{"kind":"local","bind_address":"127.0.0.1","port":15432,"target_host":"private-db.internal","target_port":5432}})).unwrap();
    crate::sync::record_commands::edit_records(&f.d.env(), |s, now| {
        tunnel_rules::set(s, None, &rule.id, None, Some(rule.clone()), now)
            .map_err(|e| crate::error::AppError::Other(e.to_string()))
    })
    .unwrap();
    round::sync_once(&f.d.env()).unwrap();
    let current = state(&f.d);
    let ledger = current.local.central_projection.as_ref().unwrap();
    assert_eq!(ledger.catalog.tunnels, vec![rule.clone()]);
    let plan = Plan::current(current.local.central.clone().unwrap(), &f.keys).unwrap();
    let cache = Cache::initial(&plan, 200, &BTreeMap::new()).unwrap();
    let mut peer = current.clone();
    peer.account = Some(cache.account);
    peer.local.tunnel_rules.clear();
    assert_eq!(tunnel_rules::view(&peer)[0].rule, rule);
    assert!(peer
        .account
        .as_ref()
        .unwrap()
        .records
        .values()
        .filter(|r| tunnel_rules::is_id(&r.record.id))
        .all(|r| !r.dirty));
    crate::sync::record_commands::edit_records(&f.d.env(), |s, now| {
        tunnel_rules::set(s, None, &rule.id, Some(&rule), None, now)
            .map_err(|e| crate::error::AppError::Other(e.to_string()))
    })
    .unwrap();
    round::sync_once(&f.d.env()).unwrap();
    let after = state(&f.d);
    assert!(after
        .local
        .central_projection
        .as_ref()
        .unwrap()
        .catalog
        .tunnels
        .is_empty());
    assert!(tunnel_rules::view(&after).is_empty());
    let plan = Plan::current(after.local.central.clone().unwrap(), &f.keys).unwrap();
    let cache = Cache::initial(&plan, 300, &BTreeMap::new()).unwrap();
    peer.account = Some(cache.account);
    assert!(tunnel_rules::view(&peer).is_empty());
    let wire = serde_json::to_string(&f.service.state.lock().unwrap().history).unwrap();
    assert!(!wire.contains("private-db.internal") && !wire.contains("Private database"));
}
