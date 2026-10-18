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
            json!({"account_id":"a".repeat(64),"device_state":if active{"active"}else{"pending"},"auth_epoch":s.epoch,"phase":"ready","proof":s.proof,
                "genesis_hash":chain.as_ref().map(|c|c.current().anchor().genesis_hash.clone()),"pairing_confirmation":s.confirmations.get(&own),
                "vaults":s.vault.as_ref().map(|v|json!({v:{"epoch":1,"rekey":false}})).unwrap_or_else(||json!({})),"denied":[],"devices":devices,"barrier":null}).to_string().into_bytes()
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
        server
            .mock("POST", "/v2/membership")
            .with_body_from_request(move |r| {
                let body: Value = serde_json::from_slice(r.body().unwrap()).unwrap();
                let node: SignedMembership = serde_json::from_value(body["node"].clone()).unwrap();
                let mut s = account.lock().unwrap();
                s.chain().unwrap().current().apply(&node).unwrap();
                let id = node.body.enrollment.as_ref().unwrap().device.id.clone();
                s.confirmations.insert(
                    id,
                    serde_json::from_value(body["confirmation"].clone()).unwrap(),
                );
                let vault = s.vault.as_ref().unwrap().clone();
                s.wraps = serde_json::from_value(body["wraps"][&vault].clone()).unwrap();
                s.proof.as_mut().unwrap().nodes.push(node);
                s.epoch += 1;
                b"{}".to_vec()
            })
            .create();
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
}
