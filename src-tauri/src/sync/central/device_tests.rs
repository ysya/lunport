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
    corrupt_pull_once: bool,
    denied: Vec<String>,
    rekey_pending: bool,
    barrier_pending: bool,
    hold_barrier: bool,
    lose_control_response_once: bool,
    key_epoch: u64,
    commits: Vec<super::rekey::SignedRekey>,
    committed_wraps: BTreeMap<u64, Vec<WrappedKeys>>,
    source_digests: BTreeMap<u64, Vec<super::rekey::SourceDigest>>,
    rotation: Option<(
        super::rekey::SignedRekey,
        Vec<WrappedKeys>,
        Vec<super::rekey::Version>,
    )>,
    lose_stage_response_once: bool,
    lose_commit_response_once: bool,
    begun_rotations: Vec<String>,
    lose_access_response_once: bool,
    duplicate_access_row: bool,
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
            key_epoch: 1,
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
        let authorization = Arc::clone(&state);
        server.mock("POST","/v2/session").with_status_code_from_request(move |r| {let body:Value=serde_json::from_slice(r.body().unwrap()).unwrap();if authorization.lock().unwrap().denied.iter().any(|id|Some(id.as_str())==body["device"]["id"].as_str()){403}else{200}}).with_header("content-type","application/json").with_body_from_request(move|r|{
            let body:Value=serde_json::from_slice(r.body().unwrap()).unwrap();let device:Device=serde_json::from_value(body["device"].clone()).unwrap();
            let mut s=account.lock().unwrap();if s.denied.contains(&device.id){return b"{}".to_vec();}s.devices.insert(device.id.clone(),device.clone());s.sessions.insert(body["session_id"].as_str().unwrap().into(),device.id.clone());
            let active=s.chain().is_some_and(|c|c.current().devices().contains_key(&device.id));
            json!({"account_id":"a".repeat(64),"account_locator":profile.locator,"device_state":if active {"active"}else{"pending"},"auth_epoch":s.epoch,"expires_at_ms":1700000300000u64}).to_string().into_bytes()
        }).create();
        let account = Arc::clone(&state);
        server.mock("GET","/v2/account").with_header("content-type","application/json").with_body_from_request(move|r|{
            let s=account.lock().unwrap();let own=s.device(r);let chain=s.chain();let active=chain.as_ref().is_some_and(|c|c.current().devices().contains_key(&own));
            let devices:Vec<Value>=s.devices.values().map(|d|json!({"device":d,"name":"Synthetic device","state":if chain.as_ref().is_some_and(|c|c.current().devices().contains_key(&d.id)){"active"}else{"pending"},"request":s.requests.get(&d.id)})).collect();
            json!({"account_id":"a".repeat(64),"device_state":if active{"active"}else{"pending"},"auth_epoch":s.epoch,"phase":if s.barrier_pending{"revocation_pending"}else{"ready"},"proof":s.proof,
                "genesis_hash":chain.as_ref().map(|c|c.current().anchor().genesis_hash.clone()),"pairing_confirmation":s.confirmations.get(&own),
                "vaults":s.vault.as_ref().map(|v|json!({v:{"epoch":s.key_epoch,"rekey":s.rekey_pending}})).unwrap_or_else(||json!({})),"denied":s.denied,"devices":devices,"barrier":if s.barrier_pending{json!({"id":"synthetic barrier","acknowledged":0,"total":1})}else{Value::Null}}).to_string().into_bytes()
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
                    s.rotation = None;
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
                let mut body = json!({"records": rows, "sequence": s.history.len().to_string(),
                    "history_hash": s.history.last().map(|r| r.history_hash.clone()).unwrap_or_else(|| "0".repeat(64)),
                    "membership_head": s.chain().unwrap().current().head(), "epoch": s.key_epoch, "phase": if s.rekey_pending {"rekey_pending"} else {"ready"}});
                if std::mem::take(&mut s.corrupt_pull_once) {
                    body["records"].as_array_mut().unwrap().last_mut().unwrap()["envelope"]["signature"] = json!("AA==");
                }
                let body=body.to_string().into_bytes();
                let hook = s.on_pull.take(); drop(s); if let Some(hook) = hook { hook(); } body
            }).create();
        let locator = Profile::new(&server.url(), &config.issuer, "opaque")
            .unwrap()
            .locator;
        install_account_access_routes(&mut server, &state, locator);
        install_rotation_routes(&mut server, &state);
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
fn install_account_access_routes(
    server: &mut mockito::ServerGuard,
    state: &Arc<Mutex<Account>>,
    locator: String,
) {
    let account = Arc::clone(state);
    server.mock("GET","/v2/device-access").with_body_from_request(move |_| {
        let s=account.lock().unwrap();let chain=s.chain();
        let mut devices:Vec<_>=s.devices.values().map(|d|json!({"id":d.id,"name":"Synthetic device","created_at_ms":1700000000000u64,"state":if s.denied.contains(&d.id){"revoked"}else if chain.as_ref().is_some_and(|c|c.current().devices().contains_key(&d.id)){"active"}else{"pending"}})).collect();
        if s.duplicate_access_row {if let Some(first)=devices.first().cloned(){devices.push(first);}}
        json!({"account_locator":locator,"auth_epoch":s.epoch,"barrier_pending":s.barrier_pending,"devices":devices}).to_string().into_bytes()
    }).create();
    let account = Arc::clone(state);
    let response = Arc::clone(state);
    server.mock("POST","/v2/device-access/revoke").with_status_code_from_request(move |_|{
        let mut s=response.lock().unwrap();if std::mem::take(&mut s.lose_access_response_once){503}else if s.hold_barrier{202}else{200}
    }).with_body_from_request(move |r| {
        let body:Value=serde_json::from_slice(r.body().unwrap()).unwrap();let id=body["device"].as_str().unwrap();let mut s=account.lock().unwrap();
        assert!(s.devices.contains_key(id));if !s.denied.iter().any(|d|d==id){s.denied.push(id.into());s.epoch+=1;}s.rekey_pending=true;s.barrier_pending=s.hold_barrier;
        json!({"access_revoked":!s.barrier_pending,"rekey_pending":true,"barrier_pending":s.barrier_pending}).to_string().into_bytes()
    }).create();
}
fn install_rotation_routes(server: &mut mockito::ServerGuard, state: &Arc<Mutex<Account>>) {
    use super::{rekey, rotation};
    let account = Arc::clone(state);
    server.mock("GET", mockito::Matcher::Regex("^/v2/vaults/[0-9a-f]{64}/rekey$".into())).with_body_from_request(move |_| {
        let s=account.lock().unwrap();json!({"phase":if s.rekey_pending{"rekey_pending"}else{"ready"},"epoch":s.key_epoch,"sequence":s.history.len().to_string(),"history_hash":s.history.last().map_or(rotation::ZERO,|r|r.history_hash.as_str()),
            "commits":s.commits,"journal":s.rotation.as_ref().map(|(m,_,rows)|json!({"manifest":m,"staged":rows.len().to_string(),"history_hash":rows.last().map_or(rotation::ZERO,|r|r.history_hash.as_str())}))}).to_string().into_bytes()
    }).create();
    let account = Arc::clone(state);
    server.mock("POST",mockito::Matcher::Regex("^/v2/vaults/[0-9a-f]{64}/rekey/begin$".into())).with_body_from_request(move |r| {
        let body:Value=serde_json::from_slice(r.body().unwrap()).unwrap(); let manifest:rekey::SignedRekey=serde_json::from_value(body["manifest"].clone()).unwrap();let wraps:Vec<WrappedKeys>=serde_json::from_value(body["wraps"].clone()).unwrap();
        let mut s=account.lock().unwrap();let chain=s.chain().unwrap();
        assert!(!chain.current().devices().keys().any(|id|s.denied.contains(id)));
        rekey::verify_committed_wraps(&chain,&manifest,&wraps).unwrap();
        s.begun_rotations.push(manifest.body.rotation_id.clone());
        if let Some((old,_,_))=&s.rotation {assert_eq!(old,&manifest);}else{s.rotation=Some((manifest,wraps,vec![]));}
        let rows=&s.rotation.as_ref().unwrap().2;
        json!({"staged":rows.len().to_string(),"history_hash":rows.last().map_or(rotation::ZERO,|r|r.history_hash.as_str())}).to_string().into_bytes()
    }).create();
    let account = Arc::clone(state);
    let response = Arc::clone(state);
    server.mock("POST",mockito::Matcher::Regex("^/v2/vaults/[0-9a-f]{64}/rekey/stage$".into())).with_status_code_from_request(move |_|if std::mem::take(&mut response.lock().unwrap().lose_stage_response_once){503}else{200}).with_body_from_request(move |r| {
        let body:Value=serde_json::from_slice(r.body().unwrap()).unwrap(); let after:usize=body["after"].as_str().unwrap().parse().unwrap();let rows:Vec<rekey::Version>=serde_json::from_value(body["rows"].clone()).unwrap();
        let mut s=account.lock().unwrap();let (manifest,_,saved)=s.rotation.as_mut().unwrap(); assert_eq!(body["rotation"],manifest.body.rotation_id);assert_eq!(after,saved.len());assert!(rows.len()<=32);saved.extend(rows);
        json!({"staged":saved.len().to_string(),"history_hash":saved.last().unwrap().history_hash}).to_string().into_bytes()
    }).create();
    let account = Arc::clone(state);
    let response = Arc::clone(state);
    server
        .mock(
            "POST",
            mockito::Matcher::Regex("^/v2/vaults/[0-9a-f]{64}/rekey/commit$".into()),
        )
        .with_status_code_from_request(move |_| {
            if std::mem::take(&mut response.lock().unwrap().lose_commit_response_once) {
                503
            } else {
                200
            }
        })
        .with_body_from_request(move |_| {
            let mut s = account.lock().unwrap();
            let (manifest, wraps, rows) = s.rotation.take().unwrap();
            assert_eq!(rows.len(), s.history.len());
            assert_eq!(
                rows.last()
                    .map_or(rotation::ZERO, |r| r.history_hash.as_str()),
                manifest.body.target_history_hash
            );
            let epoch = s.key_epoch + 1;
            let digests = s
                .history
                .iter()
                .map(|r| rekey::SourceDigest {
                    sequence: r.sequence.clone(),
                    digest: r.digest.clone(),
                })
                .collect();
            s.source_digests.insert(epoch, digests);
            s.committed_wraps.insert(epoch, wraps.clone());
            s.wraps = wraps;
            s.history = rows;
            s.key_epoch = epoch;
            s.rekey_pending = false;
            s.commits.push(manifest.clone());
            json!({"manifest":manifest}).to_string().into_bytes()
        })
        .create();
    server
        .mock(
            "POST",
            mockito::Matcher::Regex("^/v2/vaults/[0-9a-f]{64}/rekey/reconcile$".into()),
        )
        .with_body("{}")
        .create();
    let account = Arc::clone(state);
    server
        .mock(
            "GET",
            mockito::Matcher::Regex("^/v2/vaults/[0-9a-f]{64}/rekey/wraps$".into()),
        )
        .match_query(mockito::Matcher::Any)
        .with_body_from_request(move |r| {
            let epoch: u64 = r
                .path_and_query()
                .split_once("?epoch=")
                .unwrap()
                .1
                .parse()
                .unwrap();
            let s = account.lock().unwrap();
            json!({"manifest":s.commits[epoch as usize-2],"wraps":s.committed_wraps[&epoch]})
                .to_string()
                .into_bytes()
        })
        .create();
    let account = Arc::clone(state);
    server.mock("GET",mockito::Matcher::Regex("^/v2/vaults/[0-9a-f]{64}/rekey/source$".into())).match_query(mockito::Matcher::Any).with_body_from_request(move |r| {
        let query=r.path_and_query().split_once('?').unwrap().1; let params:BTreeMap<_,_>=query.split('&').map(|v|v.split_once('=').unwrap()).collect();let epoch:u64=params["epoch"].parse().unwrap();let after:usize=params["after"].parse().unwrap();
        let s=account.lock().unwrap();json!({"manifest":s.commits[epoch as usize-2],"digests":s.source_digests[&epoch].iter().skip(after).take(256).collect::<Vec<_>>()}).to_string().into_bytes()
    }).create();
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

#[test]
fn native_rotation_resumes_the_same_plan_after_lost_stage_and_commit_responses_and_keeps_newer_local_b(
) {
    use super::{
        payload, rekey,
        replica::{Draft, Pending, Receipt},
        rotation, rotation_runtime, round, wire,
    };
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
    let second = TestDevice::new("second", &relay, &clock);
    let offline = TestDevice::new("offline", &relay, &clock);
    let late = TestDevice::new("late", &relay, &clock);
    for d in [&second, &offline, &late] {
        service.login(d);
        let code = devices::pairing_code(&d.env()).unwrap();
        devices::approve(&first.env(), &code.code).unwrap();
        controller::refresh(&d.env()).unwrap();
    }
    controller::refresh(&offline.env()).unwrap();
    joining::initialize(&offline.env()).unwrap();
    let late_approval = record_runtime::snapshot(&late.env())
        .unwrap()
        .0
        .local
        .central
        .unwrap()
        .control
        .pairing_confirmation
        .unwrap();
    let context = controller::context(&first.env()).unwrap();
    let identity = context.identity.as_ref().unwrap();
    let workspace = record_runtime::snapshot(&first.env())
        .unwrap()
        .0
        .local
        .central
        .unwrap();
    let chain = workspace.control.verified_chain().unwrap();
    let wrap = &workspace.own_wraps[0];
    let keys = wrap
        .open(
            &identity.keys,
            &wrap.header,
            &identity.keys.public().signing,
        )
        .unwrap();
    let mut rows = vec![];
    let mut plaintexts = vec![];
    let mut previous = rotation::ZERO.to_string();
    for seq in 1..=33u64 {
        let id = payload::Identity {
            kind: "host".into(),
            id: format!("{seq:016x}"),
            scope: Some(crate::sync::records_v3::HostScope::Local),
        };
        let data=payload::Data::Host(serde_json::from_value(json!({"schema":2,"alias":format!("host-{seq}"),"hostname":"fixture.invalid","auth":"password"})).unwrap());
        let plain = payload::encode(&id, &data).unwrap();
        let envelope = crypto::seal_record(
            &keys,
            &identity.keys,
            RecordHeader {
                origin: workspace.control.profile.origin.clone(),
                account_id: workspace.control.account_id.clone(),
                genesis_hash: workspace
                    .control
                    .anchor
                    .as_ref()
                    .unwrap()
                    .genesis_hash
                    .clone(),
                vault_id: workspace.control.personal_vault.clone().unwrap(),
                record_id: id.opaque(&keys).unwrap(),
                key_epoch: "1".into(),
                membership_head: chain.current().head().into(),
                author: identity.id.clone(),
                operation_id: crypto::random_id(16).unwrap(),
                expected_revision: "0".into(),
                kind: "host".into(),
                deleted: false,
            },
            &plain,
        )
        .unwrap();
        let digest = rekey::envelope_digest(&envelope).unwrap();
        let history_hash = crypto::hash(
            &wire::canonical(&["lunport-history-v2", &previous, &seq.to_string(), &digest])
                .unwrap(),
        );
        previous = history_hash.clone();
        rows.push(rekey::Version {
            revision: "1".into(),
            sequence: seq.to_string(),
            envelope,
            digest,
            history_hash,
        });
        plaintexts.push(plain);
    }
    service.state.lock().unwrap().history = rows.clone();
    let registry = devices::registry(&first.env()).unwrap();
    let peer_id = controller::context(&peer.env())
        .unwrap()
        .identity
        .as_ref()
        .unwrap()
        .id
        .clone();
    let target = registry.devices.iter().find(|d| d.id == peer_id).unwrap();
    let revoked = devices::revoke(
        &first.env(),
        &target.id,
        &registry.membership_head,
        &registry.authorization_epoch,
        &target.fingerprint,
    )
    .unwrap();
    assert!(revoked.access_revoked);
    // A is in cloud history, while the local user already saved B. Its receipt must be checked
    // against the old source digest, then confirmed by exact operation/plaintext in the new epoch.
    let sent = Draft {
        local_revision: 1,
        content_hash: crypto::hash(&plaintexts[0]),
        envelope: rows[0].envelope.clone(),
    };
    let mut header = sent.envelope.header.clone();
    header.expected_revision = "1".into();
    header.operation_id = crypto::random_id(16).unwrap();
    let b=payload::encode(&payload::Identity{kind:"host".into(),id:"0000000000000001".into(),scope:Some(crate::sync::records_v3::HostScope::Local)},&payload::Data::Host(serde_json::from_value(json!({"schema":2,"alias":"newer-local-b","hostname":"local.invalid","auth":"password"})).unwrap())).unwrap();
    let latest = Draft {
        local_revision: 2,
        content_hash: crypto::hash(&b),
        envelope: crypto::seal_record(&keys, &identity.keys, header, &b).unwrap(),
    };
    let receipt = Receipt {
        operation_id: sent.envelope.header.operation_id.clone(),
        record_id: sent.envelope.header.record_id.clone(),
        revision: rows[0].revision.clone(),
        sequence: rows[0].sequence.clone(),
        digest: rows[0].digest.clone(),
        history_hash: rows[0].history_hash.clone(),
    };
    record_runtime::mutate_records(&first.env(), |records| {
        let mut records = records.clone();
        records
            .local
            .central
            .as_mut()
            .unwrap()
            .replica
            .as_mut()
            .unwrap()
            .pending
            .insert(
                receipt.record_id.clone(),
                Pending {
                    latest: latest.clone(),
                    sent: Some(sent.clone()),
                    claimed: Some(receipt.clone()),
                },
            );
        Ok(records)
    })
    .unwrap();
    service.state.lock().unwrap().lose_stage_response_once = true;
    let mut report = round::Report::default();
    assert!(rotation_runtime::advance(&first.env(), &mut report).is_err());
    assert!(report.requests <= 32);
    let saved = record_runtime::snapshot(&first.env())
        .unwrap()
        .0
        .local
        .central
        .unwrap();
    let plan = saved.rotation.clone().unwrap();
    assert!(matches!(
        &plan,
        rotation::Journal::Sending { verified: 0, .. }
    ));
    assert_eq!(
        service
            .state
            .lock()
            .unwrap()
            .rotation
            .as_ref()
            .unwrap()
            .2
            .len(),
        32
    );
    let mut forgotten = saved.clone();
    forgotten.rotation = None;
    assert!(saved.verify_transition(&forgotten).is_err());
    let mut tampered = saved.clone();
    if let Some(rotation::Journal::Sending { rows, .. }) = &mut tampered.rotation {
        rows.pop();
    }
    assert!(tampered.validate().is_err());
    let serialized = serde_json::to_string(&saved).unwrap();
    assert!(!serialized.contains("newer-local-b"));
    assert!(!serialized.contains(&*identity.keys.encode_secret()));
    let probe = record_runtime::probe_startup(&first.env().state_path, "synthetic");
    record_runtime::activate_probe(&mut first.runtime.core.lock().unwrap(), probe).unwrap();
    service.login(&first);
    assert_eq!(
        record_runtime::snapshot(&first.env())
            .unwrap()
            .0
            .local
            .central
            .unwrap()
            .rotation
            .as_ref(),
        Some(&plan)
    );
    service.state.lock().unwrap().lose_commit_response_once = true;
    assert!(rotation_runtime::advance(&first.env(), &mut round::Report::default()).is_err());
    assert_eq!(service.state.lock().unwrap().key_epoch, 2);
    assert_eq!(
        record_runtime::snapshot(&first.env())
            .unwrap()
            .0
            .local
            .central
            .unwrap()
            .replica
            .unwrap()
            .checkpoint
            .epoch,
        1
    );
    service.state.lock().unwrap().corrupt_pull_once = true;
    assert!(rotation_runtime::advance(&first.env(), &mut round::Report::default()).is_err());
    let rejected = record_runtime::snapshot(&first.env())
        .unwrap()
        .0
        .local
        .central
        .unwrap();
    assert_eq!(rejected.replica.as_ref().unwrap().checkpoint.epoch, 1);
    assert!(matches!(
        rejected.rotation,
        Some(rotation::Journal::Sending { verified: 0, .. })
    ));
    let mut report = round::Report::default();
    assert!(!rotation_runtime::advance(&first.env(), &mut report).unwrap());
    assert!(report.requests <= 32);
    let after = record_runtime::snapshot(&first.env())
        .unwrap()
        .0
        .local
        .central
        .unwrap();
    let replica = after.replica.as_ref().unwrap();
    assert!(after.rotation.is_none());
    assert_eq!(replica.checkpoint.epoch, 2);
    assert_eq!(replica.checkpoint.sequence, 33);
    assert_eq!(after.control.phase, super::client_state::Phase::Enrolled);
    let pending = &replica.pending[&receipt.record_id];
    assert_eq!(pending.latest, latest);
    assert!(pending.sent.is_none());
    assert!(pending.claimed.is_none());
    assert!(replica.conflicts.is_empty());
    let chain = after.control.verified_chain().unwrap();
    let state = service.state.lock().unwrap();
    assert!(!state.wraps.iter().any(|w| w.header.recipient == target.id));
    assert!(state.wraps.iter().any(|w| w.header.recipient == "recovery"));
    let next_keys = rekey::open_committed_keys(
        &chain,
        &state.commits[0],
        &state.wraps,
        &identity.id,
        &identity.keys,
    )
    .unwrap();
    for (row, plain) in state.history.iter().zip(plaintexts.iter()) {
        assert_eq!(
            &*row
                .envelope
                .verify(&identity.keys.public().signing)
                .unwrap()
                .open(&next_keys)
                .unwrap(),
            &**plain
        );
        assert!(row
            .envelope
            .verify(&identity.keys.public().signing)
            .unwrap()
            .open(&keys)
            .is_err());
    }
    assert!(record_runtime::snapshot(&first.env())
        .unwrap()
        .0
        .local
        .hosts
        .is_empty());
    drop(state);
    let second_id = controller::context(&second.env())
        .unwrap()
        .identity
        .as_ref()
        .unwrap()
        .id
        .clone();
    let registry = devices::registry(&first.env()).unwrap();
    let target = registry.devices.iter().find(|d| d.id == second_id).unwrap();
    devices::revoke(
        &first.env(),
        &target.id,
        &registry.membership_head,
        &registry.authorization_epoch,
        &target.fingerprint,
    )
    .unwrap();
    let mut complete = false;
    for _ in 0..8 {
        let mut report = round::Report::default();
        if !rotation_runtime::advance(&first.env(), &mut report).unwrap() {
            complete = true;
            break;
        }
        assert!(report.requests <= 32);
    }
    assert!(complete);
    assert_eq!(service.state.lock().unwrap().key_epoch, 3);
    service.login(&offline);
    round::sync_once(&offline.env()).unwrap();
    // Constrain round budgets so an intermediate bridge is durably observable before the
    // latest cache rebuild. Known future manifests may never be forgotten at this point.
    for _ in 0..8 {
        let mut report = round::Report {
            requests: 22,
            ..Default::default()
        };
        rotation_runtime::advance(&offline.env(), &mut report).unwrap();
        assert!(report.requests <= 32);
        let mid = record_runtime::snapshot(&offline.env())
            .unwrap()
            .0
            .local
            .central
            .unwrap();
        if mid.replica.as_ref().unwrap().checkpoint.epoch == 2 {
            assert!(mid.replica.as_ref().unwrap().needs_epoch_rebuild);
            assert!(!mid.replica.as_ref().unwrap().baseline_ready());
            assert!(!mid.can_upload());
            assert_eq!(mid.observed_epochs.len(), 2);
            let mut false_rebuild = mid.clone();
            false_rebuild.replica.as_mut().unwrap().needs_epoch_rebuild = false;
            assert!(mid.verify_transition(&false_rebuild).is_err());
            let mut forgotten = mid.clone();
            forgotten.observed_epochs.pop();
            assert!(mid.verify_transition(&forgotten).is_err());
            break;
        }
    }
    assert_eq!(
        record_runtime::snapshot(&offline.env())
            .unwrap()
            .0
            .local
            .central
            .unwrap()
            .replica
            .unwrap()
            .checkpoint
            .epoch,
        2
    );
    complete = false;
    for _ in 0..8 {
        if !rotation_runtime::advance(&offline.env(), &mut round::Report::default()).unwrap() {
            complete = true;
            break;
        }
    }
    assert!(complete);
    let caught_up = record_runtime::snapshot(&offline.env())
        .unwrap()
        .0
        .local
        .central
        .unwrap();
    assert_eq!(caught_up.replica.as_ref().unwrap().checkpoint.epoch, 3);
    assert!(!caught_up.replica.as_ref().unwrap().needs_epoch_rebuild);
    assert_eq!(caught_up.replica.as_ref().unwrap().current.len(), 33);
    // This device was approved at epoch 1 but had never initialized a replica before epoch 3.
    service.login(&late);
    joining::initialize(&late.env()).unwrap();
    let uninitialized = record_runtime::snapshot(&late.env())
        .unwrap()
        .0
        .local
        .central
        .unwrap();
    assert!(uninitialized.own_wraps.is_empty());
    assert_eq!(
        uninitialized.control.pairing_confirmation.as_ref(),
        Some(&late_approval)
    );
    complete = false;
    for _ in 0..8 {
        if !rotation_runtime::advance(&late.env(), &mut round::Report::default()).unwrap() {
            complete = true;
            break;
        }
    }
    assert!(complete);
    let joined = record_runtime::snapshot(&late.env())
        .unwrap()
        .0
        .local
        .central
        .unwrap();
    assert_eq!(joined.replica.as_ref().unwrap().checkpoint.epoch, 3);
    assert_eq!(joined.replica.as_ref().unwrap().current.len(), 33);
    assert_eq!(
        joined.control.pairing_confirmation.as_ref(),
        Some(&late_approval)
    );
    // A new account-only denial while an old sending plan exists must remove the recipient,
    // invalidate that plan, and avoid re-uploading its wraps under the newer authorization.
    {
        let mut state = service.state.lock().unwrap();
        state.epoch += 1;
        state.rekey_pending = true;
    }
    controller::refresh(&first.env()).unwrap();
    service.state.lock().unwrap().lose_stage_response_once = true;
    assert!(rotation_runtime::advance(&first.env(), &mut round::Report::default()).is_err());
    let stale = record_runtime::snapshot(&first.env())
        .unwrap()
        .0
        .local
        .central
        .unwrap();
    let stale_id = if let Some(rotation::Journal::Sending { manifest, .. }) = &stale.rotation {
        manifest.body.rotation_id.clone()
    } else {
        panic!("expected saved sending journal")
    };
    let offline_id = controller::context(&offline.env())
        .unwrap()
        .identity
        .as_ref()
        .unwrap()
        .id
        .clone();
    {
        let mut state = service.state.lock().unwrap();
        state.epoch += 1;
        state.denied.push(offline_id.clone());
        state.rekey_pending = true;
        state.rotation = None;
    }
    controller::refresh(&first.env()).unwrap();
    let started = service.state.lock().unwrap().begun_rotations.len();
    complete = false;
    for _ in 0..12 {
        let mut report = round::Report::default();
        if !rotation_runtime::advance(&first.env(), &mut report).unwrap() {
            complete = true;
            break;
        }
        assert!(report.requests <= 32);
    }
    assert!(complete);
    let state = service.state.lock().unwrap();
    assert_eq!(state.key_epoch, 4);
    assert!(!state.begun_rotations[started..].contains(&stale_id));
    assert!(!state.wraps.iter().any(|w| w.header.recipient == offline_id));
}

#[test]
fn refused_device_grant_retains_only_account_access_and_can_be_retried_without_resetting_trust() {
    let mut service = Service::new();
    let first = TestDevice::new("first", &FakeRelay::new(), &TestClock::new());
    service.login(&first);
    bootstrap::prepare(&first.env()).unwrap();
    let kit = bootstrap::reveal(&first.env()).unwrap();
    bootstrap::confirm(&first.env(), &kit.root).unwrap();
    let before = record_runtime::snapshot(&first.env()).unwrap();
    let context = controller::context(&first.env()).unwrap();
    let refusal = service
        .server
        .mock("POST", "/v2/session")
        .with_status(403)
        .with_body("UNTRUSTED-REFUSAL-SENTINEL")
        .expect(1)
        .create();
    let status = controller::refresh(&first.env()).unwrap();
    assert!(!status.has_session);
    assert!(!status.can_sync);
    assert!(status.needs_recovery);
    assert!(!status.error.unwrap().contains("UNTRUSTED-REFUSAL-SENTINEL"));
    let current = before.0.local.central.as_ref().unwrap();
    service
        .state
        .lock()
        .unwrap()
        .denied
        .push(current.control.device.id.clone());
    let metadata = super::account_access::registry(&first.env()).unwrap();
    assert!(metadata.devices[0].current);
    assert_eq!(metadata.devices[0].state, "revoked");
    let public = serde_json::to_string(&metadata).unwrap();
    assert!(!public.contains("synthetic access"));
    service.state.lock().unwrap().duplicate_access_row = true;
    assert!(super::account_access::registry(&first.env()).is_err());
    {
        let mut state = service.state.lock().unwrap();
        state.duplicate_access_row = false;
        state.denied.clear();
    }
    let account = controller::context(&first.env()).unwrap();
    assert!(account.device_access_denied);
    assert!(account.device.is_none());
    assert!(Arc::ptr_eq(&account.tokens, &context.tokens));
    assert_eq!(record_runtime::snapshot(&first.env()).unwrap().0, before.0);
    assert!(!controller::resume(&first.env(), false).unwrap());
    refusal.assert();
    refusal.remove();
    let recovered = controller::refresh(&first.env()).unwrap();
    assert!(recovered.has_session);
    assert!(!recovered.needs_recovery);
    assert_eq!(record_runtime::snapshot(&first.env()).unwrap().0, before.0);
}

#[test]
fn account_only_revoke_binds_fresh_subject_target_and_epoch_preserves_intent_and_works_without_device_keys(
) {
    use super::{account_access, oidc::FreshLoginTokens};
    fn fresh(service: &Service, subject: &str) -> FreshLoginTokens {
        FreshLoginTokens::synthetic_for_test(LoginTokens {
            issuer: service.config.issuer.clone(),
            subject: subject.into(),
            nonce: Zeroizing::new("synthetic-fresh-nonce".into()),
            access: Zeroizing::new("synthetic-fresh-access".into()),
            refresh: Some(Zeroizing::new("synthetic-fresh-refresh".into())),
            expires_in: std::time::Duration::from_secs(300),
        })
    }
    fn selection(device: &TestDevice, id: &str) -> account_access::Selection {
        let registry = account_access::registry(&device.env()).unwrap();
        let target = registry.devices.iter().find(|d| d.id == id).unwrap();
        account_access::Selection {
            device: id.into(),
            authorization_epoch: registry.authorization_epoch,
            created_at_ms: target.created_at_ms.clone(),
        }
    }
    fn reserve(device: &TestDevice) {
        *device.runtime.central_login.lock().unwrap() = Some(("synthetic-step-up".into(), None));
    }
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
    let first_id = controller::context(&first.env())
        .unwrap()
        .identity
        .as_ref()
        .unwrap()
        .id
        .clone();
    let peer_id = controller::context(&peer.env())
        .unwrap()
        .identity
        .as_ref()
        .unwrap()
        .id
        .clone();
    let before = record_runtime::snapshot(&first.env()).unwrap().0;
    let anchor = before
        .local
        .central
        .as_ref()
        .unwrap()
        .control
        .anchor
        .clone();
    let selected = selection(&first, &peer_id);
    let prepared = account_access::prepare_revoke(&first.env(), selected.clone()).unwrap();
    assert!(account_access::complete_revoke(
        &first.env(),
        prepared,
        fresh(&service, "opaque"),
        "synthetic-step-up"
    )
    .is_err());
    assert_eq!(record_runtime::snapshot(&first.env()).unwrap().0, before);
    reserve(&first);
    let prepared = account_access::prepare_revoke(&first.env(), selected.clone()).unwrap();
    assert!(account_access::complete_revoke(
        &first.env(),
        prepared,
        fresh(&service, "wrong-subject"),
        "synthetic-step-up"
    )
    .is_err());
    assert_eq!(record_runtime::snapshot(&first.env()).unwrap().0, before);
    let prepared = account_access::prepare_revoke(&first.env(), selected).unwrap();
    service.state.lock().unwrap().epoch += 1;
    assert!(account_access::complete_revoke(
        &first.env(),
        prepared,
        fresh(&service, "opaque"),
        "synthetic-step-up"
    )
    .is_err());
    assert!(service.state.lock().unwrap().denied.is_empty());
    controller::refresh(&first.env()).unwrap();
    let prepared =
        account_access::prepare_revoke(&first.env(), selection(&first, &peer_id)).unwrap();
    reserve(&first);
    service.state.lock().unwrap().lose_access_response_once = true;
    assert!(account_access::complete_revoke(
        &first.env(),
        prepared,
        fresh(&service, "opaque"),
        "synthetic-step-up"
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
        .contains(&peer_id));
    assert!(service.state.lock().unwrap().denied.contains(&peer_id));
    service.state.lock().unwrap().hold_barrier = true;
    let prepared =
        account_access::prepare_revoke(&first.env(), selection(&first, &peer_id)).unwrap();
    reserve(&first);
    let pending = account_access::complete_revoke(
        &first.env(),
        prepared,
        fresh(&service, "opaque"),
        "synthetic-step-up",
    )
    .unwrap();
    assert!(!pending.access_revoked);
    assert!(pending.barrier_pending);
    assert!(pending.rekey_pending);
    service.state.lock().unwrap().hold_barrier = false;
    let prepared =
        account_access::prepare_revoke(&first.env(), selection(&first, &peer_id)).unwrap();
    reserve(&first);
    let completed = account_access::complete_revoke(
        &first.env(),
        prepared,
        fresh(&service, "opaque"),
        "synthetic-step-up",
    )
    .unwrap();
    assert!(completed.access_revoked);
    assert!(!completed.barrier_pending);
    assert!(completed.rekey_pending);
    let profile = controller::context(&first.env())
        .unwrap()
        .profile
        .profile()
        .unwrap();
    crate::sync::env::Keychain::delete(&first.keychain, &profile.slot("device")).unwrap();
    controller::refresh(&first.env()).unwrap();
    assert!(controller::context(&first.env())
        .unwrap()
        .identity
        .is_none());
    let prepared =
        account_access::prepare_revoke(&first.env(), selection(&first, &first_id)).unwrap();
    reserve(&first);
    let self_revoked = account_access::complete_revoke(
        &first.env(),
        prepared,
        fresh(&service, "opaque"),
        "synthetic-step-up",
    )
    .unwrap();
    assert!(self_revoked.access_revoked);
    assert!(!self_revoked.status.has_session);
    assert!(self_revoked.status.needs_recovery);
    let after = record_runtime::snapshot(&first.env())
        .unwrap()
        .0
        .local
        .central
        .unwrap();
    assert_eq!(after.control.anchor, anchor);
    assert_eq!(after.control.phase, super::client_state::Phase::Revoked);
    assert!(after.control.denied_devices.contains(&first_id));
    assert!(after.control.denied_devices.contains(&peer_id));
    assert!(
        crate::sync::env::Keychain::get(&first.keychain, &profile.slot("device"))
            .unwrap()
            .is_none()
    );
    assert!(account_access::registry(&first.env()).is_ok());
    let public = serde_json::to_string(&self_revoked).unwrap();
    assert!(!public.contains("synthetic-fresh-access"));
    assert!(!public.contains("synthetic-fresh-refresh"));
}
