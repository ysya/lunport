//! Native two-device lifecycle against a synthetic service; real OS credentials are never used.
use super::{
    bootstrap, controller,
    credentials::Profile,
    crypto::{self, WrappedKeys},
    devices, joining,
    membership::{Device, Enrollment, Genesis, SignedMembership, TrustAnchor},
    oidc::{LoginTokens, OidcConfig},
    trust::ControlProof,
    wire::RecordHeader,
};
use crate::sync::{
    fake_relay::FakeRelay,
    record_runtime,
    testkit::{TestClock, TestDevice},
};
use serde_json::{json, Value};
use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex},
};
use zeroize::Zeroizing;
#[derive(Default)]
struct Account {
    proof: Option<ControlProof>,
    wraps: Vec<WrappedKeys>,
    vault: Option<String>,
    epoch: u64,
    history: Vec<super::rekey::Version>,
    pulls: usize,
    reject_pull_once: bool,
    denied: Vec<String>,
    rekey_pending: bool,
    barrier_pending: bool,
    hold_barrier: bool,
    lose_control_response_once: bool,
    on_pull: Option<Box<dyn Fn() + Send + Sync>>,
    devices: BTreeMap<String, Device>,
    sessions: BTreeMap<String, String>,
    requests: BTreeMap<String, Enrollment>,
    confirmations: BTreeMap<String, super::pairing::PairingConfirmation>,
}
impl Account {
    fn chain(&self) -> Option<super::trust::VerifiedChain> {
        self.proof.as_ref().map(|p| {
            p.verify(
                &TrustAnchor {
                    origin: p.genesis.origin.clone(),
                    account_id: p.genesis.account_id.clone(),
                    genesis_hash: crypto::hash(&p.genesis.canonical().unwrap()),
                },
                None,
            )
            .unwrap()
        })
    }
    fn device(&self, r: &mockito::Request) -> String {
        let header = r.header("authorization")[0].to_str().unwrap();
        let id = header.split('.').nth(2).unwrap();
        self.sessions[id].clone()
    }
}
struct Service {
    server: mockito::ServerGuard,
    state: Arc<Mutex<Account>>,
    config: OidcConfig,
}
impl Service {
    fn new() -> Self {
        let mut server = mockito::Server::new();
        let state = Arc::new(Mutex::new(Account {
            epoch: 1,
            ..Default::default()
        }));
        let config = OidcConfig {
            issuer: "https://identity.test".into(),
            client_id: "native".into(),
            scopes: vec![],
            audience: Some("api".into()),
        };
        let profile = Profile::new(&server.url(), &config.issuer, "opaque").unwrap();
        let account = Arc::clone(&state);
        server.mock("POST","/v2/session").with_header("content-type","application/json").with_body_from_request(move|r|{
            let body:Value=serde_json::from_slice(r.body().unwrap()).unwrap();let device:Device=serde_json::from_value(body["device"].clone()).unwrap();
            let mut s=account.lock().unwrap();s.devices.insert(device.id.clone(),device.clone());s.sessions.insert(body["session_id"].as_str().unwrap().into(),device.id.clone());
            let active=s.chain().is_some_and(|c|c.current().devices().contains_key(&device.id));
            json!({"account_id":"a".repeat(64),"account_locator":profile.locator,"device_state":if active {"active"}else{"pending"},"auth_epoch":s.epoch,"expires_at_ms":1700000300000u64}).to_string().into_bytes()
        }).create();
        let account = Arc::clone(&state);
        server.mock("GET","/v2/account").with_header("content-type","application/json").with_body_from_request(move|r|{
            let s=account.lock().unwrap();let own=s.device(r);let chain=s.chain();let active=chain.as_ref().is_some_and(|c|c.current().devices().contains_key(&own));
            let devices:Vec<Value>=s.devices.values().map(|d|json!({"device":d,"name":"Synthetic device","state":if chain.as_ref().is_some_and(|c|c.current().devices().contains_key(&d.id)){"active"}else{"pending"},"request":s.requests.get(&d.id)})).collect();
            json!({"account_id":"a".repeat(64),"device_state":if active{"active"}else{"pending"},"auth_epoch":s.epoch,"phase":if s.barrier_pending{"revocation_pending"}else{"ready"},"proof":s.proof,
                "genesis_hash":chain.as_ref().map(|c|c.current().anchor().genesis_hash.clone()),"pairing_confirmation":s.confirmations.get(&own),
                "vaults":s.vault.as_ref().map(|v|json!({v:{"epoch":1,"rekey":s.rekey_pending}})).unwrap_or_else(||json!({})),"denied":s.denied,"devices":devices,"barrier":if s.barrier_pending{json!({"id":"synthetic barrier","acknowledged":0,"total":1})}else{Value::Null}}).to_string().into_bytes()
        }).create();
        let account = Arc::clone(&state);
        server
            .mock("POST", "/v2/bootstrap")
            .with_body_from_request(move |r| {
                let body: Value = serde_json::from_slice(r.body().unwrap()).unwrap();
                let mut s = account.lock().unwrap();
                let genesis: Genesis = serde_json::from_value(body["genesis"].clone()).unwrap();
                s.proof = Some(ControlProof {
                    genesis,
                    nodes: vec![],
                });
                s.chain().unwrap();
                s.wraps = serde_json::from_value(body["wraps"].clone()).unwrap();
                s.vault = Some(body["vault"].as_str().unwrap().into());
                s.epoch += 1;
                b"{}".to_vec()
            })
            .create();
        let account = Arc::clone(&state);
        server
            .mock("POST", "/v2/enrollment")
            .with_status(204)
            .with_body_from_request(move |r| {
                let body: Value = serde_json::from_slice(r.body().unwrap()).unwrap();
                let request: Enrollment = serde_json::from_value(body["request"].clone()).unwrap();
                request.verify_signature().unwrap();
                account
                    .lock()
                    .unwrap()
                    .requests
                    .insert(request.device.id.clone(), request);
                vec![]
            })
            .create();
        let account = Arc::clone(&state);
        let response = Arc::clone(&state);
        server
            .mock("POST", "/v2/membership")
            .with_status_code_from_request(move |_| {
                if std::mem::take(&mut response.lock().unwrap().lose_control_response_once) {
                    503
                } else {
                    200
                }
            })
            .with_body_from_request(move |r| {
                let body: Value = serde_json::from_slice(r.body().unwrap()).unwrap();
                let node: SignedMembership = serde_json::from_value(body["node"].clone()).unwrap();
                let mut s = account.lock().unwrap();
                let previous = s.chain().unwrap();
                let next = previous.current().apply(&node).unwrap();
                if let Some(request) = &node.body.enrollment {
                    s.confirmations.insert(
                        request.device.id.clone(),
                        serde_json::from_value(body["confirmation"].clone()).unwrap(),
                    );
                    let vault = s.vault.as_ref().unwrap().clone();
                    s.wraps = serde_json::from_value(body["wraps"][&vault].clone()).unwrap();
                } else {
                    assert_eq!(body["wraps"], json!({}));
                    s.denied.extend(
                        previous
                            .current()
                            .devices()
                            .keys()
                            .filter(|id| !next.devices().contains_key(*id))
                            .cloned(),
                    );
                    s.rekey_pending = true;
                    s.barrier_pending = s.hold_barrier;
                }
                s.proof.as_mut().unwrap().nodes.push(node);
                s.epoch += 1;
                b"{}".to_vec()
            })
            .create();
        let account = Arc::clone(&state);
        server.mock("POST", "/v2/barrier/resume").with_body_from_request(move |_| {
            let mut s = account.lock().unwrap(); s.barrier_pending = s.hold_barrier;
            json!({"access_revoked":!s.barrier_pending,"barrier_pending":s.barrier_pending,"rekey_pending":s.rekey_pending}).to_string().into_bytes()
        }).create();
        let account = Arc::clone(&state);
        server
            .mock(
                "GET",
                mockito::Matcher::Regex("^/v2/vaults/[0-9a-f]{64}/wrap$".into()),
            )
            .with_header("content-type", "application/json")
            .with_body_from_request(move |r| {
                let s = account.lock().unwrap();
                let own = s.device(r);
                serde_json::to_vec(s.wraps.iter().find(|w| w.header.recipient == own).unwrap())
                    .unwrap()
            })
            .create();
        let account = Arc::clone(&state);
        server.mock("GET",mockito::Matcher::Regex("^/v2/vaults/[0-9a-f]{64}/metadata$".into())).with_header("content-type","application/json").with_body_from_request(move |_|{
            let s=account.lock().unwrap();json!({"vault":s.vault,"epoch":1,"membership_head":s.chain().unwrap().current().head(),"authorization_epoch":s.epoch.to_string(),"phase":"ready","sequence":"0","history_hash":"0".repeat(64)}).to_string().into_bytes()
        }).create();
        let account = Arc::clone(&state);
        let authorization = Arc::clone(&state);
        server.mock("GET", mockito::Matcher::Regex("^/v2/vaults/[0-9a-f]{64}/records$".into()))
            .match_query(mockito::Matcher::Any).with_status_code_from_request(move |_| {
                if std::mem::take(&mut authorization.lock().unwrap().reject_pull_once) {403} else {200}
            }).with_header("content-type", "application/json")
            .with_body_from_request(move |r| {
                let since: u64 = r.path_and_query().split_once("?since=").unwrap().1.parse().unwrap();
                let mut s = account.lock().unwrap(); s.pulls += 1;
                let rows: Vec<_> = s.history.iter().filter(|row| row.sequence.parse::<u64>().unwrap() > since).take(32).collect();
                let body = json!({"records": rows, "sequence": s.history.len().to_string(),
                    "history_hash": s.history.last().map(|r| r.history_hash.clone()).unwrap_or_else(|| "0".repeat(64)),
                    "membership_head": s.chain().unwrap().current().head(), "epoch": 1, "phase": "ready"}).to_string().into_bytes();
                let hook = s.on_pull.take(); drop(s); if let Some(hook) = hook { hook(); } body
            }).create();
        Self {
            server,
            state,
            config,
        }
    }
    fn login(&self, d: &TestDevice) {
        let probe = record_runtime::probe_startup(&d.env().state_path, "synthetic");
        record_runtime::activate_probe(&mut d.runtime.core.lock().unwrap(), probe).unwrap();
        let tokens = LoginTokens {
            issuer: self.config.issuer.clone(),
            subject: "opaque".into(),
            nonce: Zeroizing::new("synthetic nonce".into()),
            access: Zeroizing::new("synthetic access".into()),
            refresh: Some(Zeroizing::new("synthetic refresh".into())),
            expires_in: std::time::Duration::from_secs(300),
        };
        controller::establish(
            &d.env(),
            &self.server.url(),
            self.config.clone(),
            tokens,
            None,
        )
        .unwrap();
    }
}
#[test]
fn two_device_approval_binds_request_and_mac_then_acquires_the_same_keys_without_publishing_a_library(
) {
    let mut service = Service::new();
    let relay = FakeRelay::new();
    let clock = TestClock::new();
    let first = Arc::new(TestDevice::new("first", &relay, &clock));
    let peer = Arc::new(TestDevice::new("peer", &relay, &clock));
    service.login(&first);
    bootstrap::prepare(&first.env()).unwrap();
    let kit = bootstrap::reveal(&first.env()).unwrap();
    bootstrap::confirm(&first.env(), &kit.root).unwrap();
    service.login(&peer);
    assert_eq!(
        controller::status(&peer.env()).unwrap().phase,
        "awaiting_approval"
    );
    let code = devices::pairing_code(&peer.env()).unwrap();
    let peer_context = controller::context(&peer.env()).unwrap();
    let peer_id = peer_context.identity.as_ref().unwrap();
    let original = service.state.lock().unwrap().requests[&peer_id.id].clone();
    let anchor = service
        .state
        .lock()
        .unwrap()
        .chain()
        .unwrap()
        .current()
        .anchor()
        .clone();
    let replacement =
        Enrollment::create(&anchor, &peer_id.id, &peer_id.keys, 1_700_000_000_050).unwrap();
    service
        .state
        .lock()
        .unwrap()
        .requests
        .insert(peer_id.id.clone(), replacement);
    assert!(devices::approve(&first.env(), &code.code).is_err());
    assert_eq!(
        service
            .state
            .lock()
            .unwrap()
            .proof
            .as_ref()
            .unwrap()
            .nodes
            .len(),
        0
    );
    service
        .state
        .lock()
        .unwrap()
        .requests
        .insert(peer_id.id.clone(), original);
    devices::approve(&first.env(), &code.code).unwrap();
    let confirmation = service.state.lock().unwrap().confirmations[&peer_id.id].clone();
    service
        .state
        .lock()
        .unwrap()
        .confirmations
        .get_mut(&peer_id.id)
        .unwrap()
        .mac = "A".repeat(43) + "=";
    let before = record_runtime::snapshot(&peer.env()).unwrap();
    assert!(controller::refresh(&peer.env()).is_err());
    assert_eq!(record_runtime::snapshot(&peer.env()).unwrap(), before);
    service
        .state
        .lock()
        .unwrap()
        .confirmations
        .insert(peer_id.id.clone(), confirmation);
    controller::refresh(&peer.env()).unwrap();
    let wrap_signature = service
        .state
        .lock()
        .unwrap()
        .wraps
        .iter()
        .find(|w| w.header.recipient == peer_id.id)
        .unwrap()
        .signature
        .clone();
    service
        .state
        .lock()
        .unwrap()
        .wraps
        .iter_mut()
        .find(|w| w.header.recipient == peer_id.id)
        .unwrap()
        .signature = "A".repeat(86) + "==";
    let before_keys = record_runtime::snapshot(&peer.env()).unwrap();
    assert!(joining::initialize(&peer.env()).is_err());
    assert_eq!(record_runtime::snapshot(&peer.env()).unwrap(), before_keys);
    service
        .state
        .lock()
        .unwrap()
        .wraps
        .iter_mut()
        .find(|w| w.header.recipient == peer_id.id)
        .unwrap()
        .signature = wrap_signature;
    joining::initialize(&peer.env()).unwrap();
    // A background opaque-session refresh can use cached access with only no-UI credential calls.
    struct NoUi<'a>(&'a crate::sync::testkit::MemKeychain);
    impl crate::sync::env::Keychain for NoUi<'_> {
        fn get(&self, _: &str) -> Result<Option<String>, crate::error::AppError> {
            panic!("background opened credential UI");
        }
        fn set(&self, _: &str, _: &str) -> Result<(), crate::error::AppError> {
            panic!("background opened credential UI");
        }
        fn delete(&self, _: &str) -> Result<(), crate::error::AppError> {
            panic!("background deleted credentials");
        }
        fn get_noninteractive(&self, key: &str) -> Result<Option<String>, crate::error::AppError> {
            crate::sync::env::Keychain::get(self.0, key)
        }
        fn set_noninteractive(&self, key: &str, value: &str) -> Result<(), crate::error::AppError> {
            crate::sync::env::Keychain::set(self.0, key, value)
        }
    }
    let no_ui = NoUi(&first.keychain);
    let background_env = crate::sync::env::SyncEnv {
        keychain: &no_ui,
        ..first.env()
    };
    assert!(controller::resume(&background_env, true).unwrap());
    let profile = controller::context(&first.env())
        .unwrap()
        .profile
        .profile()
        .unwrap();
    let refresh_slot = profile.slot("refresh");
    let saved_refresh = crate::sync::env::Keychain::get(&first.keychain, &refresh_slot)
        .unwrap()
        .unwrap();
    let mut interrupted: Value = serde_json::from_str(&saved_refresh).unwrap();
    interrupted["state"] = json!("in_flight");
    crate::sync::env::Keychain::set(&first.keychain, &refresh_slot, &interrupted.to_string())
        .unwrap();
    let cached = first.runtime.core.lock().unwrap().central_session.take();
    let public_before = record_runtime::snapshot(&first.env()).unwrap();
    let error = controller::resume(&background_env, true)
        .unwrap_err()
        .to_string();
    assert!(error.contains("previous credential renewal was interrupted"));
    assert_eq!(
        record_runtime::snapshot(&first.env()).unwrap(),
        public_before
    );
    assert!(first.runtime.core.lock().unwrap().central_session.is_none());
    crate::sync::env::Keychain::set(&first.keychain, &refresh_slot, &saved_refresh).unwrap();
    first.runtime.core.lock().unwrap().central_session = cached;
    let first_ws = record_runtime::snapshot(&first.env())
        .unwrap()
        .0
        .local
        .central
        .unwrap();
    let peer_records = record_runtime::snapshot(&peer.env()).unwrap().0;
    let peer_ws = peer_records.local.central.as_ref().unwrap();
    assert_eq!(first_ws.control.anchor, peer_ws.control.anchor);
    assert_eq!(
        peer_ws
            .replica
            .as_ref()
            .unwrap()
            .minimum
            .as_ref()
            .unwrap()
            .sequence,
        0
    );
    assert!(peer_ws.replica.as_ref().unwrap().baseline_ready());
    assert!(!peer_ws.can_upload());
    assert!(!peer_ws.control.cutover);
    assert!(peer_ws.control.library.is_none());
    assert!(peer_records.local.hosts.is_empty());
    assert!(peer_records.account.is_none());
    let old = controller::context(&first.env()).unwrap();
    let old_id = old.identity.as_ref().unwrap();
    let first_wrap = &first_ws.own_wraps[0];
    let first_keys = first_wrap
        .open(
            &old_id.keys,
            &first_wrap.header,
            &old_id.keys.public().signing,
        )
        .unwrap();
    let peer_wrap = &peer_ws.own_wraps[0];
    let peer_keys = peer_wrap
        .open(
            &peer_id.keys,
            &peer_wrap.header,
            &old_id.keys.public().signing,
        )
        .unwrap();
    let chain = peer_ws.control.verified_chain().unwrap();
    let record = crypto::seal_record(
        &first_keys,
        &old_id.keys,
        RecordHeader {
            origin: anchor.origin,
            account_id: anchor.account_id,
            genesis_hash: anchor.genesis_hash,
            vault_id: first_ws.replica.as_ref().unwrap().vault.clone(),
            record_id: first_keys.record_id("host", "fixture").unwrap(),
            key_epoch: "1".into(),
            membership_head: chain.current().head().into(),
            author: old_id.id.clone(),
            operation_id: crypto::random_id(16).unwrap(),
            expected_revision: "0".into(),
            kind: "host".into(),
            deleted: false,
        },
        b"SYNTHETIC ENCRYPTED LIBRARY",
    )
    .unwrap();
    assert_eq!(
        &*record
            .verify(&old_id.keys.public().signing)
            .unwrap()
            .open(&peer_keys)
            .unwrap(),
        b"SYNTHETIC ENCRYPTED LIBRARY"
    );
    // A service omission may not hide a device retained in the anchored membership proof.
    service.state.lock().unwrap().devices.remove(&old_id.id);
    let view = devices::registry(&first.env()).unwrap();
    assert_eq!(
        view.devices
            .iter()
            .filter(|d| d.state == "approved")
            .count(),
        2
    );
    let public =
        serde_json::to_string(&peer_records).unwrap() + &serde_json::to_string(&view).unwrap();
    assert!(!public.contains("LPPAIR2:"));
    assert!(!public.contains("LPREC2:"));
    assert!(!public.contains("SYNTHETIC ENCRYPTED LIBRARY"));
    assert!(!public.contains(peer_id.credential()));
    assert!(!public.contains(&*peer_id.keys.encode_secret()));
    stage_ciphertext_checks(
        &mut service,
        &first,
        &peer,
        &first_keys,
        &old_id.keys,
        record.header.clone(),
    );
}

fn stage_ciphertext_checks(
    service: &mut Service,
    first: &Arc<TestDevice>,
    peer: &Arc<TestDevice>,
    keys: &super::crypto::VaultKeys,
    signer: &super::crypto::DeviceKeys,
    mut header: RecordHeader,
) {
    use super::{payload, rekey, round, wire};
    use crate::sync::{record_repository as repo, records_v3::HostScope};
    let id = payload::Identity {
        kind: "host".into(),
        id: "0000000000000001".into(),
        scope: Some(HostScope::Local),
    };
    let host = serde_json::from_value(
        json!({"schema":2,"alias":"remote-staged","hostname":"fixture.invalid","auth":"password"}),
    )
    .unwrap();
    let plain = payload::encode(&id, &payload::Data::Host(host)).unwrap();
    header.record_id = id.opaque(keys).unwrap();
    header.operation_id = crypto::random_id(16).unwrap();
    let envelope = crypto::seal_record(keys, signer, header, &plain).unwrap();
    let digest = rekey::envelope_digest(&envelope).unwrap();
    let history_hash = crypto::hash(
        &wire::canonical(&["lunport-history-v2", &"0".repeat(64), "1", &digest]).unwrap(),
    );
    service.state.lock().unwrap().history.push(rekey::Version {
        revision: "1".into(),
        sequence: "1".into(),
        envelope,
        digest,
        history_hash,
    });
    let local_edit = Arc::clone(first);
    service.state.lock().unwrap().on_pull = Some(Box::new(move || {
        record_runtime::mutate_records(&local_edit.env(), |state| {
            repo::create_host(state, "0000000000000001", HostScope::Local,
                serde_json::from_value(json!({"schema":2,"alias":"newer-local","hostname":"local.invalid","auth":"password"})).unwrap(), 1)
                .map_err(|e| crate::error::AppError::Other(e.to_string()))
        }).unwrap();
    }));
    let error = round::sync_once(&first.env()).err().unwrap().to_string();
    assert_eq!(error, crate::sync::runtime::SUPERSEDED);
    assert!(round::cooldown(&first.env()).is_zero());
    let snapshot = record_runtime::snapshot(&first.env()).unwrap().0;
    assert_eq!(
        snapshot
            .local
            .central
            .as_ref()
            .unwrap()
            .replica
            .as_ref()
            .unwrap()
            .checkpoint
            .sequence,
        0
    );
    assert_eq!(
        snapshot.local.hosts[&crate::sync::record::record_key(
            crate::sync::record::RecordKind::Host,
            "0000000000000001"
        )]
            .record
            .payload["alias"],
        "newer-local"
    );
    let report = round::sync_once(&first.env()).unwrap();
    assert_eq!(report.staged, 1);
    let snapshot = record_runtime::snapshot(&first.env()).unwrap().0;
    assert_eq!(
        snapshot.local.hosts[&crate::sync::record::record_key(
            crate::sync::record::RecordKind::Host,
            "0000000000000001"
        )]
            .record
            .payload["alias"],
        "newer-local"
    );
    assert_eq!(snapshot.local.hosts.len(), 1);
    assert!(!snapshot.local.central.as_ref().unwrap().control.cutover);
    assert_eq!(round::sync_once(&peer.env()).unwrap().staged, 1);
    assert!(record_runtime::snapshot(&peer.env())
        .unwrap()
        .0
        .local
        .hosts
        .is_empty());
    // A child authorization barrier may reject an in-flight old grant. Re-register once,
    // verify the current control state, and retry without changing the library projection.
    service.state.lock().unwrap().reject_pull_once = true;
    let retried = round::sync_once(&peer.env()).unwrap();
    assert_eq!(retried.requests, 2);
    assert_eq!(retried.staged, 0);
    assert!(record_runtime::snapshot(&peer.env())
        .unwrap()
        .0
        .local
        .hosts
        .is_empty());
    assert!(!service.state.lock().unwrap().reject_pull_once);
    let limited = service
        .server
        .mock(
            "GET",
            mockito::Matcher::Regex("^/v2/vaults/[0-9a-f]{64}/records$".into()),
        )
        .match_query(mockito::Matcher::Any)
        .with_status(429)
        .with_header("retry-after", "200")
        .with_body("UNTRUSTED-TOKEN-SENTINEL")
        .expect(1)
        .create();
    let before = record_runtime::snapshot(&first.env()).unwrap();
    assert!(round::sync_once(&first.env()).is_err());
    assert!(round::cooldown(&first.env()) > std::time::Duration::from_secs(199));
    assert_eq!(round::sync_once(&first.env()).unwrap().requests, 0);
    let sessions = service.state.lock().unwrap().sessions.len();
    assert!(controller::refresh(&first.env()).is_err());
    assert_eq!(service.state.lock().unwrap().sessions.len(), sessions);
    assert_eq!(record_runtime::snapshot(&first.env()).unwrap(), before);
    assert!(!controller::status(&first.env())
        .unwrap()
        .error
        .unwrap()
        .contains("SENTINEL"));
    limited.assert();
}

#[test]
fn revoke_intent_survives_lost_response_restart_and_omission_until_verified_barriers_finish() {
    let service = Service::new();
    let relay = FakeRelay::new();
    let clock = TestClock::new();
    let first = TestDevice::new("first", &relay, &clock);
    let peer = TestDevice::new("peer", &relay, &clock);
    service.login(&first);
    bootstrap::prepare(&first.env()).unwrap();
    let kit = bootstrap::reveal(&first.env()).unwrap();
    bootstrap::confirm(&first.env(), &kit.root).unwrap();
    service.login(&peer);
    let code = devices::pairing_code(&peer.env()).unwrap();
    devices::approve(&first.env(), &code.code).unwrap();
    let registry = devices::registry(&first.env()).unwrap();
    let target = registry.devices.iter().find(|d| !d.current).unwrap();
    assert!(devices::revoke(
        &first.env(),
        &target.id,
        &registry.membership_head,
        &registry.authorization_epoch,
        &"0".repeat(64)
    )
    .is_err());
    assert!(record_runtime::snapshot(&first.env())
        .unwrap()
        .0
        .local
        .central
        .unwrap()
        .control
        .denied_devices
        .is_empty());
    service.state.lock().unwrap().hold_barrier = true;
    service.state.lock().unwrap().lose_control_response_once = true;
    assert!(devices::revoke(
        &first.env(),
        &target.id,
        &registry.membership_head,
        &registry.authorization_epoch,
        &target.fingerprint
    )
    .is_err());
    let saved = record_runtime::snapshot(&first.env())
        .unwrap()
        .0
        .local
        .central
        .unwrap();
    assert!(saved.control.denied_devices.contains(&target.id));
    assert_eq!(saved.control.phase, super::client_state::Phase::Rekey);
    // The uncertain response cannot speculate a signed removal locally. Publishing ANY new
    // content-key wrap remains blocked while the old verified membership includes the target.
    assert!(saved
        .control
        .verified_chain()
        .unwrap()
        .current()
        .devices()
        .contains_key(&target.id));
    assert!(saved.control.require_key_recipients().is_err());
    let probe = record_runtime::probe_startup(&first.env().state_path, "synthetic");
    record_runtime::activate_probe(&mut first.runtime.core.lock().unwrap(), probe).unwrap();
    assert!(record_runtime::snapshot(&first.env())
        .unwrap()
        .0
        .local
        .central
        .unwrap()
        .control
        .denied_devices
        .contains(&target.id));
    service.state.lock().unwrap().denied.clear(); // hostile/old service omits the known denial
    service.login(&first);
    let registry = devices::registry(&first.env()).unwrap();
    assert_eq!(
        registry
            .devices
            .iter()
            .find(|d| d.id == target.id)
            .unwrap()
            .state,
        "access_blocked"
    );
    let pending = devices::revoke(
        &first.env(),
        &target.id,
        &registry.membership_head,
        &registry.authorization_epoch,
        &target.fingerprint,
    )
    .unwrap();
    assert!(!pending.access_revoked);
    assert!(pending.barrier_pending);
    assert!(pending.rekey_pending);
    service.state.lock().unwrap().hold_barrier = false;
    let registry = devices::registry(&first.env()).unwrap();
    let finished = devices::revoke(
        &first.env(),
        &target.id,
        &registry.membership_head,
        &registry.authorization_epoch,
        &target.fingerprint,
    )
    .unwrap();
    assert!(finished.access_revoked);
    assert!(!finished.barrier_pending);
    assert!(finished.rekey_pending);
    let after = record_runtime::snapshot(&first.env())
        .unwrap()
        .0
        .local
        .central
        .unwrap();
    after.control.require_key_recipients().unwrap();
    assert!(after.control.denied_devices.contains(&target.id));
    let mut forgotten = after.clone();
    forgotten.control.denied_devices.clear();
    assert!(after.verify_transition(&forgotten).is_err());
    controller::sign_out(&first.env()).unwrap();
    assert!(record_runtime::snapshot(&first.env())
        .unwrap()
        .0
        .local
        .central
        .unwrap()
        .control
        .denied_devices
        .contains(&target.id));
}
