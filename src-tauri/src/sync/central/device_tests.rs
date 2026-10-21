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
    unlock: Option<super::unlock_registry::SignedRegistry>,
    reject_unlock: bool,
    lose_unlock_join_reply: bool,
    unlock_joins: usize,
    migration: Option<(
        super::migration::SignedMigration,
        String,
        Vec<super::rekey::Version>,
    )>,
    proof: Option<ControlProof>,
    wraps: Vec<WrappedKeys>,
    vault: Option<String>,
    epoch: u64,
    session_expires_at_ms: Option<u64>,
    history: Vec<super::rekey::Version>,
    pulls: usize,
    recovery_posts: usize,
    recovery_corrupt_after_first: bool,
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
    origin: String,
}
impl Service {
    fn new() -> Self {
        Self::at_origin(None)
    }
    fn at_origin(logical: Option<&str>) -> Self {
        let mut server = mockito::Server::new();
        let origin = logical.map(str::to_owned).unwrap_or_else(|| server.url());
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
        let profile = Profile::new(&origin, &config.issuer, "opaque").unwrap();
        let account = Arc::clone(&state);
        let authorization = Arc::clone(&state);
        server.mock("POST","/v2/session").with_status_code_from_request(move |r| {let body:Value=serde_json::from_slice(r.body().unwrap()).unwrap();if authorization.lock().unwrap().denied.iter().any(|id|Some(id.as_str())==body["device"]["id"].as_str()){403}else{200}}).with_header("content-type","application/json").with_body_from_request(move|r|{
            let body:Value=serde_json::from_slice(r.body().unwrap()).unwrap();let device:Device=serde_json::from_value(body["device"].clone()).unwrap();
            let mut s=account.lock().unwrap();if s.denied.contains(&device.id){return b"{}".to_vec();}s.devices.insert(device.id.clone(),device.clone());s.sessions.insert(body["session_id"].as_str().unwrap().into(),device.id.clone());
            let active=s.chain().is_some_and(|c|c.current().devices().contains_key(&device.id));
            json!({"account_id":"a".repeat(64),"account_locator":profile.locator,"device_state":if active {"active"}else{"pending"},"auth_epoch":s.epoch,"expires_at_ms":s.session_expires_at_ms.unwrap_or(1700000300000u64)}).to_string().into_bytes()
        }).create();
        let account = Arc::clone(&state);
        server.mock("GET","/v2/account").with_header("content-type","application/json").with_body_from_request(move|r|{
            let s=account.lock().unwrap();let own=s.device(r);let chain=s.chain();let active=chain.as_ref().is_some_and(|c|c.current().devices().contains_key(&own));
            let devices:Vec<Value>=s.devices.values().map(|d|json!({"device":d,"name":"Synthetic device","state":if chain.as_ref().is_some_and(|c|c.current().devices().contains_key(&d.id)){"active"}else{"pending"},"request":s.requests.get(&d.id)})).collect();
            // Production omits private account metadata until the device is approved.
            let mut body=json!({"account_id":"a".repeat(64),"device_state":if active{"active"}else{"pending"},"auth_epoch":s.epoch,"phase":if s.barrier_pending{"revocation_pending"}else{"ready"},"proof":s.proof,
                "genesis_hash":chain.as_ref().map(|c|c.current().anchor().genesis_hash.clone()),"pairing_confirmation":s.confirmations.get(&own)});
            if active {
                body["vaults"]=s.vault.as_ref().map(|v|json!({v:{"epoch":s.key_epoch,"rekey":s.rekey_pending}})).unwrap_or_else(||json!({}));
                body["denied"]=json!(s.denied);
                body["devices"]=json!(devices);
                body["barrier"]=if s.barrier_pending{json!({"id":"synthetic barrier","acknowledged":0,"total":1})}else{Value::Null};
            }
            body.to_string().into_bytes()
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
            let s=account.lock().unwrap();json!({"vault":s.vault,"epoch":s.key_epoch,"membership_head":s.chain().unwrap().current().head(),"authorization_epoch":s.epoch.to_string(),"phase":if s.rekey_pending{"rekey_pending"}else{"ready"},"sequence":s.history.len().to_string(),"history_hash":s.history.last().map_or("0".repeat(64),|row|row.history_hash.clone())}).to_string().into_bytes()
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
        let locator = Profile::new(&origin, &config.issuer, "opaque")
            .unwrap()
            .locator;
        install_account_access_routes(&mut server, &state, locator);
        install_rotation_routes(&mut server, &state);
        install_recovery_routes(&mut server, &state, &config);
        Self {
            server,
            state,
            config,
            origin,
        }
    }
    fn automatic() -> Self {
        let mut service = Self::at_origin(Some("https://sync.example"));
        install_unlock_routes(&mut service.server, &service.state);
        install_fresh_library_routes(&mut service.server, &service.state);
        service
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
        controller::establish(&d.env(), &self.origin, self.config.clone(), tokens, None).unwrap();
    }
}
#[test]
fn fresh_sign_in_repairs_local_backoff_but_cannot_bypass_server_retry_after() {
    use super::{api::Reply, round};
    use std::time::{Duration, Instant};
    let mut service = Service::new();
    let d = TestDevice::new("sign-in-cooldown", &FakeRelay::new(), &TestClock::new());
    service.login(&d);
    let before = record_runtime::snapshot(&d.env()).unwrap().0;
    let sign_in = || controller::establish(
        &d.env(), &service.origin, service.config.clone(),
        LoginTokens {
            issuer: service.config.issuer.clone(), subject: "opaque".into(),
            nonce: Zeroizing::new("synthetic nonce".into()),
            access: Zeroizing::new("synthetic access".into()),
            refresh: Some(Zeroizing::new("synthetic refresh".into())),
            expires_in: Duration::from_secs(300),
        }, None,
    );
    {
        let mut core = d.runtime.core.lock().unwrap();
        core.central_poll.retry_at = Some(Instant::now() + Duration::from_secs(600));
        core.central_poll.failures = 4;
        core.central_user_action = Some("Synthetic local sync failure".into());
    }
    assert!(round::cooldown(&d.env()) > Duration::from_secs(599));
    round::check_cooldown(&d.env()).unwrap();
    assert!(sign_in().unwrap().has_session);
    // This is also the post-browser-login step that used to surface the false cooldown.
    joining::initialize(&d.env()).unwrap();
    assert!(round::cooldown(&d.env()).is_zero());
    assert_eq!(d.runtime.core.lock().unwrap().central_poll.failures, 0);
    assert!(controller::status(&d.env()).unwrap().error.is_none());
    assert_eq!(record_runtime::snapshot(&d.env()).unwrap().0, before);

    let mut limited = Reply::for_test(429, &json!({}));
    limited.retry_after = Some(Duration::from_secs(200));
    assert!(round::require_success(&d.env(), &limited).is_err());
    assert!(round::cooldown(&d.env()) > Duration::from_secs(199));
    assert!(round::next_delay(&d.env()) > Duration::from_secs(199));
    let no_registration = service.server.mock("POST", "/v2/session").expect(0).create();
    let expected = round::check_cooldown(&d.env()).unwrap_err().to_string();
    assert_eq!(sign_in().unwrap_err().to_string(), expected);
    assert_eq!(record_runtime::snapshot(&d.env()).unwrap().0, before);
    assert!(round::cooldown(&d.env()) > Duration::from_secs(199));
    no_registration.assert();
}

fn install_recovery_routes(
    server: &mut mockito::ServerGuard,
    state: &Arc<Mutex<Account>>,
    config: &OidcConfig,
) {
    server.mock("GET", "/v2/info").with_header("content-type", "application/json")
        .with_body(json!({"protocol":2,"features":["account-unlock-v1","central-accounts","anchored-membership","exact-revision","operation-receipts","paged-history","signed-rekey","paired-checkpoints","recovery-history","recovery-source-proofs"],"oidc":config}).to_string()).create();
    let account = Arc::clone(state);
    let barrier = Arc::clone(state);
    server.mock("POST", "/v2/recovery/wraps").with_status_code_from_request(move |_| {let s = barrier.lock().unwrap(); if s.barrier_pending && s.hold_barrier {202} else {200}}).with_header("content-type", "application/json").with_body_from_request(move |request| {
        let body: Value = serde_json::from_slice(request.body().unwrap()).unwrap();
        let mut s = account.lock().unwrap();
        verify_recovery_read(&s, request, &body);
        s.barrier_pending = s.barrier_pending && s.hold_barrier;
        if s.barrier_pending {return b"{}".to_vec();}
        let committed = if s.key_epoch == 1 {Value::Null} else {json!({"manifest":s.commits.last(),"wraps":s.committed_wraps[&s.key_epoch]})};
        json!({"membership_head":s.chain().unwrap().current().head(),"auth_epoch":s.epoch,"results":[{
            "vault":s.vault,"epoch":s.key_epoch,"phase":if s.rekey_pending {"rekey_pending"}else{"ready"},"wrap":s.wraps.iter().find(|w|w.header.recipient=="recovery").unwrap(),"committed":committed,
            "commits":s.commits,"sequence":s.history.len().to_string(),"history_hash":s.history.last().map_or("0".repeat(64),|row|row.history_hash.clone())}]}).to_string().into_bytes()
    }).create();
    let account = Arc::clone(state);
    server.mock("POST", "/v2/recovery/history").with_header("content-type", "application/json").with_body_from_request(move |request| {
        let body: Value = serde_json::from_slice(request.body().unwrap()).unwrap();
        let mut s = account.lock().unwrap();
        verify_recovery_read(&s, request, &body);
        assert_eq!(body["vault"].as_str(),s.vault.as_deref());
        let since: u64 = body["since"].as_str().unwrap().parse().unwrap();
        let rows: Vec<_> = s.history.iter().filter(|row|row.sequence.parse::<u64>().unwrap()>since).take(32).cloned().collect();
        let mut body=json!({"records":rows,"sequence":s.history.len().to_string(),"history_hash":s.history.last().map_or("0".repeat(64),|row|row.history_hash.clone()),
            "membership_head":s.chain().unwrap().current().head(),"epoch":s.key_epoch,"phase":if s.rekey_pending {"rekey_pending"}else{"ready"}});
        s.pulls += 1;
        if std::mem::take(&mut s.corrupt_pull_once) || since > 0 && std::mem::take(&mut s.recovery_corrupt_after_first) {body["records"].as_array_mut().unwrap().last_mut().unwrap()["envelope"]["signature"]=json!("AA==");}
        let encoded=body.to_string().into_bytes();
        let hook=s.on_pull.take(); drop(s); if let Some(hook)=hook {hook();} encoded
    }).create();
    let account = Arc::clone(state);
    server
        .mock("POST", "/v2/recovery/source")
        .with_header("content-type", "application/json")
        .with_body_from_request(move |request| {
            let body: Value = serde_json::from_slice(request.body().unwrap()).unwrap();
            let s = account.lock().unwrap();
            verify_recovery_read(&s, request, &body);
            let epoch = body["epoch"].as_str().unwrap().parse::<u64>().unwrap();
            let after = body["after"].as_str().unwrap().parse::<u64>().unwrap();
            let manifest = s
                .commits
                .iter()
                .find(|m| m.body.to_epoch == epoch.to_string())
                .unwrap();
            let digests = s.source_digests[&epoch]
                .iter()
                .filter(|d| d.sequence.parse::<u64>().unwrap() > after)
                .take(256)
                .collect::<Vec<_>>();
            json!({"manifest":manifest,"digests":digests})
                .to_string()
                .into_bytes()
        })
        .create();
    let response = Arc::clone(state);
    let account = Arc::clone(state);
    server
        .mock("POST", "/v2/recovery/commit")
        .with_status_code_from_request(move |_| {
            if std::mem::take(&mut response.lock().unwrap().lose_control_response_once) {
                503
            } else {
                200
            }
        })
        .with_body_from_request(move |request| {
            let body: Value = serde_json::from_slice(request.body().unwrap()).unwrap();
            let node: SignedMembership = serde_json::from_value(body["node"].clone()).unwrap();
            let mut s = account.lock().unwrap();
            s.recovery_posts += 1;
            if s.proof.as_ref().unwrap().nodes.last() == Some(&node) {
                return b"{}".to_vec();
            }
            let previous = s.chain().unwrap();
            let next = previous.current().apply(&node).unwrap();
            let own = s.device(request);
            assert_eq!(node.body.enrollment.as_ref().unwrap(), &s.requests[&own]);
            assert_eq!(node.body.action, super::membership::Action::Recover);
            let vault = s.vault.clone().unwrap();
            s.wraps = serde_json::from_value(body["wraps"][&vault].clone()).unwrap();
            s.denied.extend(
                previous
                    .current()
                    .devices()
                    .keys()
                    .filter(|id| !next.devices().contains_key(*id))
                    .cloned(),
            );
            s.proof.as_mut().unwrap().nodes.push(node);
            s.epoch += 1;
            s.rekey_pending = true;
            s.barrier_pending = s.hold_barrier;
            b"{}".to_vec()
        })
        .create();
}
fn verify_recovery_read(s: &Account, request: &mockito::Request, body: &Value) {
    use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
    let chain = s.chain().unwrap();
    let own = s.device(request);
    let enrollment = &s.requests[&own];
    let proof = &body["proof"];
    assert_eq!(proof["request_id"], enrollment.request_id);
    assert_eq!(proof["membership_head"], chain.current().head());
    assert_eq!(proof["auth_epoch"], s.epoch.to_string());
    let a = chain.current().anchor();
    let bytes = super::wire::canonical(&[
        "lunport-recovery-read-v2",
        &a.origin,
        &a.account_id,
        &a.genesis_hash,
        chain.current().head(),
        &s.epoch.to_string(),
        &B64.encode(enrollment.canonical().unwrap()),
        &enrollment.signature,
    ])
    .unwrap();
    crypto::verify(
        &chain.current().recovery().signing,
        &bytes,
        proof["signature"].as_str().unwrap(),
    )
    .unwrap();
}
fn append_automatic_row(
    rows: &mut Vec<super::rekey::Version>,
    envelope: crypto::RecordEnvelope,
) -> super::rekey::Version {
    if let Some(row) = rows
        .iter()
        .find(|row| row.envelope.header.operation_id == envelope.header.operation_id)
    {
        assert_eq!(row.envelope, envelope);
        return row.clone();
    }
    let revision = rows
        .iter()
        .rev()
        .find(|row| row.envelope.header.record_id == envelope.header.record_id)
        .map_or(0, |r| r.revision.parse::<u64>().unwrap());
    assert_eq!(envelope.header.expected_revision, revision.to_string());
    let sequence = (rows.len() + 1).to_string();
    let digest = super::rekey::envelope_digest(&envelope).unwrap();
    let history_hash = crypto::hash(
        &super::wire::canonical(&[
            "lunport-history-v2",
            rows.last()
                .map_or(super::rotation::ZERO, |r| r.history_hash.as_str()),
            &sequence,
            &digest,
        ])
        .unwrap(),
    );
    let row = super::rekey::Version {
        revision: (revision + 1).to_string(),
        sequence,
        envelope,
        digest,
        history_hash,
    };
    rows.push(row.clone());
    row
}
fn migration_progress(s: &Account) -> Value {
    let (manifest, phase, rows) = s.migration.as_ref().unwrap();
    json!({"manifest":manifest,"manifest_digest":manifest.digest().unwrap(),"phase":phase,"staged":rows.len().to_string(),"history_hash":rows.last().map_or(super::rotation::ZERO,|r|r.history_hash.as_str()),"retired":if phase=="retired"{manifest.body.sources.len().to_string()}else{"0".into()}})
}
fn install_fresh_library_routes(server: &mut mockito::ServerGuard, state: &Arc<Mutex<Account>>) {
    let account = Arc::clone(state);
    server.mock("POST",mockito::Matcher::Regex("^/v2/vaults/[0-9a-f]{64}/migration/freeze$".into())).with_body_from_request(move |r|{
        let body:Value=serde_json::from_slice(r.body().unwrap()).unwrap();
        let intent:super::migration_freeze::SignedFreeze=serde_json::from_value(body["intent"].clone()).unwrap();
        let s=account.lock().unwrap();assert!(intent.body.chains.is_empty());
        assert_eq!(intent.body.author,s.device(r));
        json!({"proof":[{"digest":intent.digest().unwrap(),"intent":intent}],"sources":[],"phase":"frozen","next":[]}).to_string().into_bytes()
    }).create();
    let account = Arc::clone(state);
    let exists = Arc::clone(state);
    server
        .mock(
            "GET",
            mockito::Matcher::Regex("^/v2/vaults/[0-9a-f]{64}/migration$".into()),
        )
        .with_status_code_from_request(move |_| {
            if exists.lock().unwrap().migration.is_some() {
                200
            } else {
                404
            }
        })
        .with_body_from_request(move |_| {
            let s = account.lock().unwrap();
            if s.migration.is_some() {
                migration_progress(&s).to_string().into_bytes()
            } else {
                b"{}".to_vec()
            }
        })
        .create();
    for action in ["begin", "stage", "commit", "retire"] {
        let account = Arc::clone(state);
        server
            .mock(
                "POST",
                mockito::Matcher::Regex(format!("^/v2/vaults/[0-9a-f]{{64}}/migration/{action}$")),
            )
            .with_body_from_request(move |r| {
                let body: Value = serde_json::from_slice(r.body().unwrap()).unwrap();
                let mut s = account.lock().unwrap();
                if action == "begin" {
                    let manifest: super::migration::SignedMigration =
                        serde_json::from_value(body["manifest"].clone()).unwrap();
                    manifest.body.canonical().unwrap();
                    s.wraps = serde_json::from_value(body["wraps"].clone()).unwrap();
                    s.migration = Some((manifest, "staging".into(), vec![]));
                } else if action == "stage" {
                    let chain = s.chain().unwrap();
                    let (_, _, rows) = s.migration.as_mut().unwrap();
                    assert_eq!(body["after"], rows.len().to_string());
                    let incoming: Vec<crypto::RecordEnvelope> =
                        serde_json::from_value(body["rows"].clone()).unwrap();
                    for envelope in incoming {
                        envelope
                            .verify(&chain.current().devices()[&envelope.header.author].signing)
                            .unwrap();
                        append_automatic_row(rows, envelope);
                    }
                } else {
                    let (_, phase, rows) = s.migration.as_mut().unwrap();
                    *phase = "retired".into();
                    let rows = rows.clone();
                    s.history = rows;
                }
                migration_progress(&s).to_string().into_bytes()
            })
            .create();
    }
    let account = Arc::clone(state);
    server.mock("POST",mockito::Matcher::Regex("^/v2/vaults/[0-9a-f]{64}/records$".into())).with_body_from_request(move |r| {
        let body:Value=serde_json::from_slice(r.body().unwrap()).unwrap();let mut s=account.lock().unwrap();let chain=s.chain().unwrap();let mut receipts=vec![];
        let incoming:Vec<crypto::RecordEnvelope>=serde_json::from_value(body["records"].clone()).unwrap();
        for envelope in incoming { envelope.verify(&chain.current().devices()[&envelope.header.author].signing).unwrap();let row=append_automatic_row(&mut s.history,envelope);
            receipts.push(json!({"operation_id":row.envelope.header.operation_id,"record_id":row.envelope.header.record_id,"revision":row.revision,"sequence":row.sequence,"digest":row.digest,"history_hash":row.history_hash})); }
        json!({"receipts":receipts,"sequence":s.history.len().to_string(),"history_hash":s.history.last().map_or(super::rotation::ZERO,|r|r.history_hash.as_str())}).to_string().into_bytes()
    }).create();
}
fn install_unlock_routes(server: &mut mockito::ServerGuard, state: &Arc<Mutex<Account>>) {
    let account = Arc::clone(state);
    server
        .mock("GET", "/v2/unlock")
        .with_header("content-type", "application/json")
        .with_body_from_request(move |_| {
            json!({"registry":account.lock().unwrap().unlock})
                .to_string()
                .into_bytes()
        })
        .create();
    let account = Arc::clone(state);
    let reject = Arc::clone(state);
    server
        .mock("POST", "/v2/unlock")
        .with_status_code_from_request(move |_| {
            if reject.lock().unwrap().reject_unlock {
                503
            } else {
                200
            }
        })
        .with_body_from_request(move |r| {
            let body: Value = serde_json::from_slice(r.body().unwrap()).unwrap();
            let registry: super::unlock_registry::SignedRegistry =
                serde_json::from_value(body["registry"].clone()).unwrap();
            let mut s = account.lock().unwrap();
            let chain = s.chain().unwrap();
            registry.verify(&chain, None).unwrap();
            assert_eq!(registry.body.author, s.device(r));
            assert_eq!(registry.body.authorization_epoch, s.epoch.to_string());
            if !s.reject_unlock {
                s.unlock = Some(registry);
            }
            b"{}".to_vec()
        })
        .create();
    let account = Arc::clone(state);
    let response = Arc::clone(state);
    server
        .mock("POST", "/v2/unlock/join")
        .with_status_code_from_request(move |_| {
            if std::mem::take(&mut response.lock().unwrap().lose_unlock_join_reply) {
                503
            } else {
                200
            }
        })
        .with_body_from_request(move |r| {
            let body: Value = serde_json::from_slice(r.body().unwrap()).unwrap();
            let mut s = account.lock().unwrap();
            let node: SignedMembership = serde_json::from_value(body["node"].clone()).unwrap();
            let previous = s.chain().unwrap();
            if previous.current().head() == crypto::hash(&node.body.canonical().unwrap()) {
                return b"{}".to_vec();
            }
            verify_recovery_read(&s, r, &json!({"proof":body["read_proof"]}));
            assert_eq!(node.body.action, super::membership::Action::Unlock);
            let next = previous.current().apply(&node).unwrap();
            assert_eq!(next.devices().len(), previous.current().devices().len() + 1);
            let own = s.device(r);
            assert_eq!(node.body.enrollment.as_ref().unwrap().device.id, own);
            let confirmation: super::pairing::PairingConfirmation =
                serde_json::from_value(body["confirmation"].clone()).unwrap();
            assert_eq!(
                confirmation.minimums[0].sequence,
                s.history.len().to_string()
            );
            let vault = s.vault.as_ref().unwrap().clone();
            s.wraps = serde_json::from_value(body["wraps"][&vault].clone()).unwrap();
            s.confirmations.insert(own, confirmation);
            s.proof.as_mut().unwrap().nodes.push(node);
            s.epoch += 1;
            s.unlock_joins += 1;
            b"{}".to_vec()
        })
        .create();
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
                    confirmed: None,
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

fn recovery_fixture(
    count: u64,
) -> (
    Service,
    Arc<TestDevice>,
    bootstrap::RecoveryReveal,
    super::crypto::VaultKeys,
) {
    let (service, peer, kit, keys, _) = recovery_fixture_with_source(count);
    (service, peer, kit, keys)
}

fn recovery_fixture_with_source(
    count: u64,
) -> (
    Service,
    Arc<TestDevice>,
    bootstrap::RecoveryReveal,
    super::crypto::VaultKeys,
    Arc<TestDevice>,
) {
    use super::{payload, rekey, wire};
    use crate::sync::records_v3::HostScope;
    let service = Service::new();
    let relay = FakeRelay::new();
    let clock = TestClock::new();
    let first = Arc::new(TestDevice::new("original", &relay, &clock));
    let peer = Arc::new(TestDevice::new("recovered", &relay, &clock));
    service.login(&first);
    bootstrap::prepare(&first.env()).unwrap();
    let kit = bootstrap::reveal(&first.env()).unwrap();
    bootstrap::confirm(&first.env(), &kit.root).unwrap();
    let original = controller::context(&first.env()).unwrap();
    let signer = &original.identity.as_ref().unwrap().keys;
    let ws = record_runtime::snapshot(&first.env())
        .unwrap()
        .0
        .local
        .central
        .unwrap();
    let wrap = &ws.own_wraps[0];
    let keys = wrap
        .open(signer, &wrap.header, &signer.public().signing)
        .unwrap();
    let a = ws.control.anchor.as_ref().unwrap();
    let mut previous = "0".repeat(64);
    for seq in 1..=count {
        let id = payload::Identity {
            kind: "host".into(),
            id: format!("{seq:016x}"),
            scope: Some(HostScope::Local),
        };
        let body=payload::encode(&id,&payload::Data::Host(serde_json::from_value(json!({"schema":2,"alias":format!("cloud-{seq}"),"hostname":"fixture.invalid","auth":"password"})).unwrap())).unwrap();
        let envelope = crypto::seal_record(
            &keys,
            signer,
            RecordHeader {
                origin: a.origin.clone(),
                account_id: a.account_id.clone(),
                genesis_hash: a.genesis_hash.clone(),
                vault_id: ws.control.personal_vault.clone().unwrap(),
                record_id: id.opaque(&keys).unwrap(),
                key_epoch: "1".into(),
                membership_head: a.genesis_hash.clone(),
                author: original.identity.as_ref().unwrap().id.clone(),
                operation_id: format!("{seq:032x}"),
                expected_revision: "0".into(),
                kind: "host".into(),
                deleted: false,
            },
            &body,
        )
        .unwrap();
        let digest = rekey::envelope_digest(&envelope).unwrap();
        let history_hash = crypto::hash(
            &wire::canonical(&["lunport-history-v2", &previous, &seq.to_string(), &digest])
                .unwrap(),
        );
        previous = history_hash.clone();
        service.state.lock().unwrap().history.push(rekey::Version {
            revision: "1".into(),
            sequence: seq.to_string(),
            envelope,
            digest,
            history_hash,
        });
    }
    service.login(&peer);
    (service, peer, kit, keys, first)
}

#[test]
fn offline_kit_recovery_drives_verified_history_backup_lost_reply_restart_barriers_and_cleanup() {
    use super::{recovery::RecoveryKit, recovery_credentials, recovery_flow};
    let (service, peer, kit, keys) = recovery_fixture(33);
    let local = Arc::clone(&peer);
    service.state.lock().unwrap().on_pull = Some(Box::new(move || {
        record_runtime::mutate_records(&local.env(), |records| {
            let mut next = records.clone();
            next.device_name = "local-B".into();
            Ok(next)
        })
        .unwrap();
    }));
    let ready = recovery_flow::begin(&peer.env(), Some(&kit.kit)).unwrap();
    assert_eq!(ready.phase, "backup_required");
    assert_eq!(ready.verified, 33);
    let operation = ready.operation.unwrap();
    let shown = recovery_credentials::reveal(&peer.env()).unwrap();
    assert_ne!(shown.kit, kit.kit);
    let before = record_runtime::snapshot(&peer.env()).unwrap().0;
    assert!(before
        .local
        .central
        .as_ref()
        .unwrap()
        .control
        .anchor
        .is_none());
    assert_eq!(service.state.lock().unwrap().recovery_posts, 0);
    assert_eq!(before.device_name, "local-B");
    service.login(&peer);
    assert_eq!(
        recovery_flow::status(&peer.env()).unwrap().phase,
        "backup_required"
    );
    service.state.lock().unwrap().hold_barrier = true;
    service.state.lock().unwrap().lose_control_response_once = true;
    assert!(recovery_flow::confirm(&peer.env(), &operation).is_err());
    assert_eq!(
        recovery_flow::status(&peer.env()).unwrap().phase,
        "submitted"
    );
    assert_eq!(service.state.lock().unwrap().recovery_posts, 1);
    service.login(&peer);
    let sessions = service.state.lock().unwrap().sessions.len();
    controller::resume(&peer.env(), false).unwrap();
    assert_eq!(service.state.lock().unwrap().sessions.len(), sessions);
    let active = controller::context(&peer.env()).unwrap();
    record_runtime::mutate_records(&peer.env(), |records| Ok(records.clone())).unwrap();
    assert!(Arc::ptr_eq(
        &active,
        &controller::context(&peer.env()).unwrap()
    ));
    assert_eq!(
        recovery_flow::revalidate(&peer.env(), None)
            .unwrap()
            .phase,
        "submitted"
    );
    assert_eq!(service.state.lock().unwrap().recovery_posts, 1);
    service.state.lock().unwrap().hold_barrier = false;
    assert_eq!(
        recovery_flow::confirm(&peer.env(), &operation)
            .unwrap()
            .phase,
        "complete"
    );
    let records = record_runtime::snapshot(&peer.env()).unwrap().0;
    let ws = records.local.central.as_ref().unwrap();
    assert_eq!(ws.replica.as_ref().unwrap().checkpoint.sequence, 33);
    assert_eq!(ws.control.phase, super::client_state::Phase::Rekey);
    assert!(!ws.can_upload());
    assert_eq!(records.device_name, "local-B");
    assert!(!serde_json::to_string(&records)
        .unwrap()
        .contains("fixture.invalid"));
    assert!(!serde_json::to_string(&records).unwrap().contains("LPREC2:"));
    let identity = controller::context(&peer.env()).unwrap();
    let identity = identity.identity.as_ref().unwrap();
    let own = &ws.own_wraps[0];
    keys.verify_same(
        &own.open(&identity.keys, &own.header, &identity.keys.public().signing)
            .unwrap(),
    )
    .unwrap();
    let chain = ws.control.verified_chain().unwrap();
    RecoveryKit::parse(&shown.kit)
        .unwrap()
        .current_keys(&chain)
        .unwrap();
    assert!(RecoveryKit::parse(&kit.kit)
        .unwrap()
        .current_keys(&chain)
        .is_err());
    let slot = ws
        .control
        .profile
        .profile()
        .unwrap()
        .slot("recovery-intent");
    assert!(peer.keychain.entry(&slot).is_none());
    assert!(recovery_credentials::reveal(&peer.env()).is_err());
    assert_eq!(service.state.lock().unwrap().recovery_posts, 1);
}

#[test]
fn offline_kit_recovery_rejects_a_late_corrupt_page_and_cancel_keeps_only_unadopted_local_state() {
    use super::{recovery_credentials, recovery_flow};
    let (service, peer, kit, _) = recovery_fixture(33);
    let before = record_runtime::snapshot(&peer.env()).unwrap().0;
    service.state.lock().unwrap().recovery_corrupt_after_first = true;
    assert!(recovery_flow::begin(&peer.env(), Some(&kit.kit)).is_err());
    assert_eq!(record_runtime::snapshot(&peer.env()).unwrap().0, before);
    assert_eq!(recovery_flow::status(&peer.env()).unwrap().verified, 32);
    assert_eq!(service.state.lock().unwrap().recovery_posts, 0);
    let workspace = before.local.central.as_ref().unwrap();
    assert!(!recovery_credentials::has_intent(&peer.env(), workspace).unwrap());
    recovery_flow::cancel(&peer.env());
    assert_eq!(recovery_flow::status(&peer.env()).unwrap().phase, "idle");
    let own = Arc::clone(&peer);
    service.state.lock().unwrap().on_pull =
        Some(Box::new(move || recovery_flow::cancel(&own.env())));
    assert!(recovery_flow::begin(&peer.env(), Some(&kit.kit)).is_err());
    assert_eq!(recovery_flow::status(&peer.env()).unwrap().phase, "idle");
    assert!(!recovery_credentials::has_intent(&peer.env(), workspace).unwrap());
    assert_eq!(record_runtime::snapshot(&peer.env()).unwrap().0, before);
}
#[test]
fn offline_kit_recovery_never_submits_a_plan_after_a_new_access_barrier() {
    use super::recovery_flow;
    let (service, peer, kit, _) = recovery_fixture(1);
    let ready = recovery_flow::begin(&peer.env(), Some(&kit.kit)).unwrap();
    let before = record_runtime::snapshot(&peer.env()).unwrap().0;
    service.state.lock().unwrap().epoch += 1;
    service.state.lock().unwrap().rekey_pending = true;
    assert!(recovery_flow::confirm(&peer.env(), ready.operation.as_deref().unwrap()).is_err());
    assert_eq!(service.state.lock().unwrap().recovery_posts, 0);
    assert_eq!(record_runtime::snapshot(&peer.env()).unwrap().0, before);
    assert_eq!(
        recovery_flow::status(&peer.env()).unwrap().phase,
        "backup_required"
    );
}
#[test]
fn offline_kit_recovery_pages_are_bounded_and_continue_without_returning_secret_material() {
    use super::recovery_flow;
    let (_service, peer, kit, _) = recovery_fixture(1025);
    let mut progress = recovery_flow::begin(&peer.env(), Some(&kit.kit)).unwrap();
    assert_eq!(progress.phase, "reading");
    assert!(progress.verified <= 1024);
    assert_eq!(progress.total, 1025);
    assert!(!serde_json::to_string(&progress)
        .unwrap()
        .contains("LPREC2:"));
    for _ in 0..4 {
        progress = recovery_flow::advance(&peer.env()).unwrap();
        if progress.phase != "reading" {
            break;
        }
    }
    assert_eq!(progress.phase, "backup_required");
    assert_eq!(progress.verified, 1025);
}

#[test]
fn offline_kit_recovery_handles_a_second_loss_before_the_prior_barrier_or_content_rotation_finishes(
) {
    use super::{recovery_credentials, recovery_flow};
    let (service, peer, original_kit, _) = recovery_fixture(1);
    let first = recovery_flow::begin(&peer.env(), Some(&original_kit.kit)).unwrap();
    let replacement = recovery_credentials::reveal(&peer.env()).unwrap();
    service.state.lock().unwrap().hold_barrier = true;
    assert_eq!(
        recovery_flow::confirm(&peer.env(), first.operation.as_deref().unwrap())
            .unwrap()
            .phase,
        "submitted"
    );
    assert!(service.state.lock().unwrap().barrier_pending);
    let relay = FakeRelay::new();
    let clock = TestClock::new();
    let another = TestDevice::new("second-loss", &relay, &clock);
    service.login(&another);
    service.state.lock().unwrap().hold_barrier = false;
    let second = recovery_flow::begin(&another.env(), Some(&replacement.kit)).unwrap();
    assert_eq!(second.phase, "backup_required");
    assert!(!service.state.lock().unwrap().barrier_pending);
    assert_eq!(service.state.lock().unwrap().key_epoch, 1);
    let latest = recovery_credentials::reveal(&another.env()).unwrap();
    assert_ne!(latest.kit, replacement.kit);
    assert_eq!(
        recovery_flow::confirm(&another.env(), second.operation.as_deref().unwrap())
            .unwrap()
            .phase,
        "complete"
    );
    let state = record_runtime::snapshot(&another.env())
        .unwrap()
        .0
        .local
        .central
        .unwrap();
    assert_eq!(state.replica.as_ref().unwrap().checkpoint.sequence, 1);
    assert_eq!(state.replica.as_ref().unwrap().checkpoint.epoch, 1);
    assert_eq!(state.control.phase, super::client_state::Phase::Rekey);
    assert_eq!(service.state.lock().unwrap().recovery_posts, 2);
}

#[test]
fn offline_kit_recovery_keeps_a_protected_admitted_checkpoint_after_core_save_loss() {
    use super::{recovery_credentials, recovery_flow};
    let (service, peer, kit, _) = recovery_fixture(1);
    let state_path = peer.env().state_path;
    let retained_path = state_path.with_extension("retained-before-recovery");
    let original = state_path.clone();
    let retained = retained_path.clone();
    service.state.lock().unwrap().on_pull = Some(Box::new(move || {
        std::fs::rename(&original, &retained).unwrap();
        std::fs::create_dir(&original).unwrap();
    }));
    assert!(recovery_flow::begin(&peer.env(), Some(&kit.kit)).is_err());
    let records = record_runtime::snapshot(&peer.env()).unwrap().0;
    let before = records.local.central.as_ref().unwrap();
    assert!(before.recovery.is_none());
    let slot = before
        .control
        .profile
        .profile()
        .unwrap()
        .slot("recovery-intent");
    let protected = peer.keychain.entry(&slot).unwrap();
    let future_kit = serde_json::from_str::<Value>(&protected).unwrap()["new_kit"]
        .as_str()
        .unwrap()
        .to_string();
    recovery_flow::cancel(&peer.env());
    std::fs::remove_dir(&state_path).unwrap();
    std::fs::rename(&retained_path, &state_path).unwrap();
    service.login(&peer);
    let history = std::mem::take(&mut service.state.lock().unwrap().history);
    assert!(recovery_flow::begin(&peer.env(), Some(&kit.kit)).is_err());
    assert_eq!(
        peer.keychain.entry(&slot).as_deref(),
        Some(protected.as_str())
    );
    assert!(record_runtime::snapshot(&peer.env())
        .unwrap()
        .0
        .local
        .central
        .unwrap()
        .recovery
        .is_none());
    assert_eq!(service.state.lock().unwrap().recovery_posts, 0);
    service.state.lock().unwrap().history = history;
    let ready = recovery_flow::begin(&peer.env(), Some(&kit.kit)).unwrap();
    assert_eq!(ready.phase, "backup_required");
    assert_eq!(
        recovery_credentials::reveal(&peer.env()).unwrap().kit,
        future_kit
    );
}


#[test]
fn offline_kit_recovery_revalidates_expired_barrier_and_appended_history_without_changing_the_saved_kit() {
    use super::{recovery_credentials, recovery_flow, recovery_state::RecoveryState};
    let (service, peer, kit, _) = recovery_fixture(2);
    let second = service.state.lock().unwrap().history.pop().unwrap();
    let first = recovery_flow::begin(&peer.env(), Some(&kit.kit)).unwrap();
    let operation = first.operation.unwrap();
    let future = recovery_credentials::reveal(&peer.env()).unwrap();
    recovery_credentials::confirm_backup(&peer.env(), &operation).unwrap();
    let before = record_runtime::snapshot(&peer.env()).unwrap().0.local.central.unwrap();
    service.state.lock().unwrap().history.push(second);
    service.state.lock().unwrap().epoch += 1;
    peer.clock.advance(16 * 60 * 1000);
    service.state.lock().unwrap().session_expires_at_ms = Some(peer.env().now() + 300000);
    let local = Arc::clone(&peer);
    service.state.lock().unwrap().on_pull = Some(Box::new(move || {
        record_runtime::mutate_records(&local.env(), |records| {
            let mut next = records.clone(); next.device_name = "local-B-during-revalidation".into(); Ok(next)
        }).unwrap();
    }));
    let ready = recovery_flow::revalidate(&peer.env(), None).unwrap();
    assert_eq!(ready.operation.as_deref(), Some(operation.as_str()));
    assert_eq!(ready.phase, "backup_required");
    assert!(ready.backup_confirmed);
    assert_eq!(ready.verified, 2);
    assert_eq!(recovery_credentials::reveal(&peer.env()).unwrap().kit, future.kit);
    let records = record_runtime::snapshot(&peer.env()).unwrap().0;
    assert_eq!(records.device_name, "local-B-during-revalidation");
    let after = records.local.central.unwrap();
    before.verify_transition(&after).unwrap();
    match after.recovery.as_ref().unwrap() {
        RecoveryState::Pending {package} => { assert_eq!(package.attempt, 1); assert!(!package.submitted); }
        _ => panic!(),
    }
    assert_eq!(service.state.lock().unwrap().recovery_posts, 0);
    assert_eq!(recovery_flow::confirm(&peer.env(), &operation).unwrap().phase, "complete");
}

#[test]
fn offline_kit_recovery_revalidates_across_a_committed_epoch_without_old_ciphertext() {
    use super::{recovery_credentials, recovery_flow, rekey, rotation};
    let (service, peer, kit, keys, original) = recovery_fixture_with_source(2);
    let row = service.state.lock().unwrap().history.pop().unwrap();
    let ready = recovery_flow::begin(&peer.env(), Some(&kit.kit)).unwrap();
    let future = recovery_credentials::reveal(&peer.env()).unwrap();
    service.state.lock().unwrap().history.push(row);
    let context = controller::context(&original.env()).unwrap();
    let identity = context.identity.as_ref().unwrap();
    {
        let mut server = service.state.lock().unwrap();
        server.epoch += 1;
        let checkpoint = rotation::checkpoint(1, &server.history).unwrap();
        let plan = rekey::prepare(&server.chain().unwrap(), &identity.id, &identity.keys,
            server.vault.as_ref().unwrap(), server.epoch, &keys, &checkpoint, &checkpoint, &server.history).unwrap();
        let source = server.history.iter().map(|r| rekey::SourceDigest { sequence:r.sequence.clone(), digest:r.digest.clone() }).collect();
        server.source_digests.insert(2, source);
        server.committed_wraps.insert(2, plan.wraps.clone());
        server.commits.push(plan.manifest);
        server.wraps = plan.wraps;
        server.history = plan.rows;
        server.key_epoch = 2;
    }
    let rebased = recovery_flow::revalidate(&peer.env(), None).unwrap();
    assert_eq!(rebased.operation, ready.operation);
    assert_eq!(rebased.verified, 2);
    assert_eq!(recovery_credentials::reveal(&peer.env()).unwrap().kit, future.kit);
    let state = record_runtime::snapshot(&peer.env()).unwrap().0;
    let package = match state.local.central.unwrap().recovery.unwrap() {
        super::recovery_state::RecoveryState::Pending {package} => package,
        _ => panic!(),
    };
    assert_eq!(package.admission.checkpoint.epoch, 2);
    assert_eq!(package.revalidation.unwrap().bridges[0].digests.len(), 1);
    assert_eq!(service.state.lock().unwrap().recovery_posts, 0);
}

#[test]
fn offline_kit_recovery_revalidation_preserves_a_stronger_protected_checkpoint_after_core_save_loss() {
    use super::{recovery_credentials, recovery_flow};
    let (service, peer, kit, _) = recovery_fixture(3);
    let rest = service.state.lock().unwrap().history.split_off(1);
    let ready = recovery_flow::begin(&peer.env(), Some(&kit.kit)).unwrap();
    let future = recovery_credentials::reveal(&peer.env()).unwrap();
    service.state.lock().unwrap().history.push(rest[0].clone());
    let state_path = peer.env().state_path;
    let retained_path = state_path.with_extension("retained-before-rebase");
    let original = state_path.clone(); let retained = retained_path.clone();
    service.state.lock().unwrap().on_pull = Some(Box::new(move || {
        std::fs::rename(&original, &retained).unwrap(); std::fs::create_dir(&original).unwrap();
    }));
    assert!(recovery_flow::revalidate(&peer.env(), None).is_err());
    recovery_flow::cancel(&peer.env());
    std::fs::remove_dir(&state_path).unwrap(); std::fs::rename(&retained_path, &state_path).unwrap();
    let owner = record_runtime::snapshot(&peer.env()).unwrap().0.local.central.unwrap();
    let slot = owner.control.profile.profile().unwrap().slot("recovery-intent");
    let protected = peer.keychain.entry(&slot).unwrap();
    service.state.lock().unwrap().history.pop();
    assert!(recovery_flow::revalidate(&peer.env(), None).is_err());
    assert_eq!(peer.keychain.entry(&slot).as_deref(), Some(protected.as_str()));
    assert_eq!(record_runtime::snapshot(&peer.env()).unwrap().0.local.central.as_ref(), Some(&owner));
    service.state.lock().unwrap().history.extend(rest);
    let next = recovery_flow::revalidate(&peer.env(), None).unwrap();
    assert_eq!(next.operation, ready.operation);
    assert_eq!(next.verified, 3);
    assert_eq!(recovery_credentials::reveal(&peer.env()).unwrap().kit, future.kit);
    assert_eq!(service.state.lock().unwrap().recovery_posts, 0);
}

#[test]
fn offline_kit_recovery_revalidation_requires_the_current_source_kit_but_keeps_its_future_kit() {
    use super::{recovery_credentials, recovery_flow};
    let (service, peer, kit, _) = recovery_fixture(1);
    let ready = recovery_flow::begin(&peer.env(), Some(&kit.kit)).unwrap();
    let future = recovery_credentials::reveal(&peer.env()).unwrap();
    let other = TestDevice::new("other-recovery", &peer.relay, &peer.clock);
    service.login(&other);
    let another = recovery_flow::begin(&other.env(), Some(&kit.kit)).unwrap();
    let current = recovery_credentials::reveal(&other.env()).unwrap();
    assert_eq!(recovery_flow::confirm(&other.env(), another.operation.as_deref().unwrap()).unwrap().phase, "complete");
    let before = record_runtime::snapshot(&peer.env()).unwrap().0;
    assert!(recovery_flow::revalidate(&peer.env(), None).is_err());
    assert_eq!(record_runtime::snapshot(&peer.env()).unwrap().0, before);
    assert!(recovery_flow::revalidate(&peer.env(), Some(&kit.kit)).is_err());
    let next = recovery_flow::revalidate(&peer.env(), Some(&current.kit)).unwrap();
    assert_eq!(next.operation, ready.operation);
    assert_eq!(recovery_credentials::reveal(&peer.env()).unwrap().kit, future.kit);
    assert_eq!(recovery_flow::confirm(&peer.env(), next.operation.as_deref().unwrap()).unwrap().phase, "complete");
}


#[test]
fn offline_kit_recovery_revalidation_keeps_the_previous_durable_attempt_on_cancel_or_corrupt_history() {
    use super::{recovery_credentials, recovery_flow};
    let (service, peer, kit, _) = recovery_fixture(33);
    let remaining = service.state.lock().unwrap().history.split_off(1);
    recovery_flow::begin(&peer.env(), Some(&kit.kit)).unwrap();
    let future = recovery_credentials::reveal(&peer.env()).unwrap();
    let before = record_runtime::snapshot(&peer.env()).unwrap().0;
    let slot = before.local.central.as_ref().unwrap().control.profile.profile().unwrap().slot("recovery-intent");
    let credentials = peer.keychain.entry(&slot);
    service.state.lock().unwrap().history.extend(remaining);
    let local = Arc::clone(&peer);
    service.state.lock().unwrap().on_pull = Some(Box::new(move || recovery_flow::cancel(&local.env())));
    assert!(recovery_flow::revalidate(&peer.env(), None).is_err());
    assert_eq!(recovery_flow::status(&peer.env()).unwrap().phase, "backup_required");
    assert_eq!(record_runtime::snapshot(&peer.env()).unwrap().0, before);
    assert_eq!(peer.keychain.entry(&slot), credentials);
    service.state.lock().unwrap().recovery_corrupt_after_first = true;
    assert!(recovery_flow::revalidate(&peer.env(), None).is_err());
    assert_eq!(recovery_flow::status(&peer.env()).unwrap().phase, "reading");
    assert_eq!(record_runtime::snapshot(&peer.env()).unwrap().0, before);
    assert_eq!(peer.keychain.entry(&slot), credentials);
    assert_eq!(recovery_flow::advance(&peer.env()).unwrap().verified, 33);
    assert_eq!(recovery_credentials::reveal(&peer.env()).unwrap().kit, future.kit);
    assert_eq!(service.state.lock().unwrap().recovery_posts, 0);
}

#[test]
fn selected_replacement_identity_is_used_for_sign_in_and_background_resume_without_default_fallback() {
    use super::{client_state::State, credentials::DeviceIdentity, workspace::Workspace};
    use crate::sync::env::Keychain;
    let service=Service::new(); let peer=TestDevice::new("selected",&FakeRelay::new(),&TestClock::new());
    service.login(&peer);
    let mut records=record_runtime::snapshot(&peer.env()).unwrap().0;
    let old=records.local.central.as_ref().unwrap();
    let profile=old.control.profile.profile().unwrap();
    let original=peer.keychain.entry(&profile.slot("device")).unwrap();
    let original_attempt=peer.keychain.entry(&profile.slot("session-attempt"));
    peer.keychain.set(&profile.slot("pairing"),"retained-original-pairing-proof").unwrap();
    let operation="b".repeat(32);
    let replacement=DeviceIdentity::create_replacement(&peer.keychain,&profile,&operation).unwrap();
    let mut selected=Workspace::new(State::new(old.control.profile.clone(),old.control.account_id.clone(),replacement.device(),old.control.auth_epoch).unwrap()).unwrap();
    selected.identity_slot=Some(operation.clone());
    selected.validate().unwrap();
    assert!(super::workspace::verify_publication(None,Some(&selected)).is_err());
    // Fixture for a previously authorized on-disk selection. Ordinary publication cannot seed it.
    records.local.central=Some(selected);
    std::fs::write(&peer.env().state_path,serde_json::to_vec(&records).unwrap()).unwrap();
    let trusted=TestDevice::new("trusted-selector",&peer.relay,&peer.clock);
    service.login(&trusted);
    bootstrap::prepare(&trusted.env()).unwrap(); let kit=bootstrap::reveal(&trusted.env()).unwrap();
    bootstrap::confirm(&trusted.env(),&kit.root).unwrap();
    service.login(&peer);
    assert_eq!(controller::context(&peer.env()).unwrap().identity.as_ref().unwrap().device(),replacement.device());
    let pairing=devices::pairing_code(&peer.env()).unwrap();
    devices::approve(&trusted.env(),&pairing.code).unwrap();
    controller::refresh(&peer.env()).unwrap();
    joining::initialize(&peer.env()).unwrap();
    struct NoDefault<'a> { source:&'a dyn Keychain, default:String }
    impl Keychain for NoDefault<'_> {
        fn get(&self,_:&str)->Result<Option<String>,crate::error::AppError>{panic!("background attempted an interactive read")}
        fn set(&self,_:&str,_:&str)->Result<(),crate::error::AppError>{panic!("background attempted an interactive write")}
        fn delete(&self,_:&str)->Result<(),crate::error::AppError>{panic!("background attempted deletion")}
        fn get_noninteractive(&self,key:&str)->Result<Option<String>,crate::error::AppError>{
            assert_ne!(key,self.default);self.source.get(key)
        }
        fn set_noninteractive(&self,key:&str,value:&str)->Result<(),crate::error::AppError>{
            assert_ne!(key,self.default);self.source.set(key,value)
        }
    }
    let protected=NoDefault{source:&peer.keychain,default:profile.slot("device")};
    assert!(controller::resume(&crate::sync::env::SyncEnv{keychain:&protected,..peer.env()},true).unwrap());
    assert_eq!(controller::context(&peer.env()).unwrap().identity.as_ref().unwrap().device(),replacement.device());
    assert_eq!(peer.keychain.entry(&profile.slot("session-attempt")),original_attempt);
    assert_eq!(peer.keychain.entry(&profile.slot("pairing")).as_deref(),Some("retained-original-pairing-proof"));
    let selected_attempt=profile.device_slot("session-attempt",Some(&operation)).unwrap();
    assert!(peer.keychain.entry(&selected_attempt).is_some());
    let slot=profile.slot(&format!("device-replacement-{operation}"));
    for wrong in [None,Some("corrupt selected identity".to_string()),Some(original.clone())] {
        match wrong { Some(value)=>peer.keychain.set(&slot,&value).unwrap(),None=>peer.keychain.delete(&slot).unwrap() }
        let before=record_runtime::snapshot(&peer.env()).unwrap().0;
        let sessions=service.state.lock().unwrap().sessions.len();
        service.login(&peer);
        let context=controller::context(&peer.env()).unwrap();
        assert!(context.identity.is_none());assert!(context.device.is_none());
        assert_eq!(service.state.lock().unwrap().sessions.len(),sessions);
        assert_eq!(record_runtime::snapshot(&peer.env()).unwrap().0,before);
        assert!(controller::resume(&crate::sync::env::SyncEnv{keychain:&protected,..peer.env()},true).is_err());
        assert_eq!(peer.keychain.entry(&profile.slot("device")).as_deref(),Some(original.as_str()));
        assert!(record_runtime::snapshot(&peer.env()).unwrap().0.local.central.as_ref().unwrap().identity_slot.as_ref()==Some(&operation));
    }
    controller::sign_out(&peer.env()).unwrap();
    assert!(peer.keychain.entry(&selected_attempt).is_none());
    assert_eq!(peer.keychain.entry(&profile.slot("session-attempt")),original_attempt);
    assert_eq!(peer.keychain.entry(&profile.slot("pairing")).as_deref(),Some("retained-original-pairing-proof"));
    assert_eq!(record_runtime::snapshot(&peer.env()).unwrap().0.local.central.unwrap().identity_slot,Some(operation));
}

#[test]
fn active_full_baseline_reads_after_trusted_approval_or_committed_recovery_use_only_the_new_device_keys(
) {
    use super::{
        active_read, recovery_flow,
        recovery_read::{EpochBundle, RecoveryVault},
    };
    for recovered in [false, true] {
        let (service, peer, kit, keys, original) = recovery_fixture_with_source(33);
        if recovered {
            let ready = recovery_flow::begin(&peer.env(), Some(&kit.kit)).unwrap();
            recovery_flow::confirm(&peer.env(), ready.operation.as_deref().unwrap()).unwrap();
        } else {
            super::round::sync_once(&original.env()).unwrap();
            let code = devices::pairing_code(&peer.env()).unwrap();
            devices::approve(&original.env(), &code.code).unwrap();
            controller::refresh(&peer.env()).unwrap();
            joining::initialize(&peer.env()).unwrap();
        }
        let session = controller::context(&peer.env()).unwrap();
        let identity = session.identity.as_ref().unwrap();
        let before = record_runtime::snapshot(&peer.env()).unwrap().0;
        let owner = before.local.central.as_ref().unwrap();
        let (proof, snapshot, rows) = {
            let state = service.state.lock().unwrap();
            let head = state.chain().unwrap().current().head().to_string();
            let committed = if state.key_epoch == 1 {
                None
            } else {
                Some(EpochBundle {
                    manifest: state.commits.last().unwrap().clone(),
                    wraps: state.committed_wraps[&state.key_epoch].clone(),
                })
            };
            (
                state.proof.clone().unwrap(),
                active_read::Snapshot {
                    membership_head: head,
                    auth_epoch: state.epoch,
                    vault: RecoveryVault {
                        vault: state.vault.clone().unwrap(),
                        epoch: state.key_epoch,
                        phase: if state.rekey_pending {
                            "rekey_pending"
                        } else {
                            "ready"
                        }
                        .into(),
                        wrap: state
                            .wraps
                            .iter()
                            .find(|w| w.header.recipient == identity.id)
                            .unwrap()
                            .clone(),
                        committed,
                        commits: state.commits.clone(),
                        sequence: state.history.len().to_string(),
                        history_hash: state
                            .history
                            .last()
                            .map_or("0".repeat(64), |r| r.history_hash.clone()),
                    },
                },
                state.history.clone(),
            )
        };
        let mut reader =
            active_read::ReadSession::begin(owner, identity, proof, snapshot.clone(), &[]).unwrap();
        for page in rows.chunks(32) {
            reader
                .append(super::recovery_read::HistoryPage {
                    records: page.to_vec(),
                    sequence: snapshot.vault.sequence.clone(),
                    history_hash: snapshot.vault.history_hash.clone(),
                    membership_head: snapshot.membership_head.clone(),
                    epoch: snapshot.vault.epoch,
                    phase: snapshot.vault.phase.clone(),
                })
                .unwrap();
        }
        let verified = reader.finish().unwrap();
        assert_eq!(verified.replica().current.len(), 33);
        verified.keys().verify_same(&keys).unwrap();
        assert_eq!(verified.previous_owner(), owner);
        let operation = "c".repeat(32);
        let profile = owner.control.profile.profile().unwrap();
        use crate::sync::env::Keychain;
        let saved = peer.keychain.entry(&profile.slot("device")).unwrap();
        peer.keychain
            .set(
                &profile.device_slot("device", Some(&operation)).unwrap(),
                &saved,
            )
            .unwrap();
        let selected = super::credentials::DeviceIdentity::load_selected(
            &peer.keychain,
            &profile,
            Some(&operation),
            true,
        )
        .unwrap();
        let mut candidate = owner.clone();
        candidate.identity_slot = Some(operation.clone());
        let mut source = record_runtime::snapshot(&original.env())
            .unwrap()
            .0
            .local
            .central
            .unwrap();
        let old_chain = source.control.verified_chain().unwrap();
        let existing = source.replica.as_ref().unwrap();
        let partial = super::replica::Replica::new(
            existing.vault.clone(),
            existing.creation_head.clone(),
            existing.creation_authorization_epoch,
        )
        .unwrap();
        let old = partial
            .prepare_page(
                &old_chain,
                &keys,
                &rows[..1],
                &super::rekey::Checkpoint {
                    epoch: 1,
                    sequence: 1,
                    history_hash: rows[0].history_hash.clone(),
                },
            )
            .unwrap()
            .next;
        source.replica = Some(old);
        source.replacement = Some(super::replacement::Intent {
            operation: operation.clone(),
            route: if recovered {
                super::replacement::Route::RecoveryKit
            } else {
                super::replacement::Route::TrustedDevice
            },
            device: Some(selected.device()),
            candidate: None,
            recovery_confirmation: None,
        });
        source.validate().unwrap();
        let mut reader = active_read::ReadSession::begin(
            &candidate,
            &selected,
            verified.proof().clone(),
            snapshot.clone(),
            &[],
        )
        .unwrap();
        super::replacement_proof::pin_active_read(&source, &mut reader, &[]).unwrap();
        for page in rows.chunks(32) {
            reader
                .append(super::recovery_read::HistoryPage {
                    records: page.to_vec(),
                    sequence: snapshot.vault.sequence.clone(),
                    history_hash: snapshot.vault.history_hash.clone(),
                    membership_head: snapshot.membership_head.clone(),
                    epoch: snapshot.vault.epoch,
                    phase: snapshot.vault.phase.clone(),
                })
                .unwrap();
        }
        let completed = reader.finish().unwrap();
        super::replacement_proof::active_read(&source, &completed, &[]).unwrap();
        let newer = source
            .replica
            .as_ref()
            .unwrap()
            .prepare_page(
                &old_chain,
                &keys,
                &rows[1..2],
                &super::rekey::Checkpoint {
                    epoch: 1,
                    sequence: 2,
                    history_hash: rows[1].history_hash.clone(),
                },
            )
            .unwrap()
            .next;
        source.replica = Some(newer);
        source.validate().unwrap();
        super::replacement_proof::active_read(&source, &completed, &[]).unwrap();
        source.replica.as_mut().unwrap().checkpoint.history_hash = "f".repeat(64);
        assert!(super::replacement_proof::active_read(&source, &completed, &[]).is_err());
        assert_eq!(record_runtime::snapshot(&peer.env()).unwrap().0, before);
    }
}

#[test]
fn staged_replacement_uses_one_core_and_independent_recovery_authorities_through_confirmation_and_cleanup() {
    use super::{api::{Api,Control},client_state::Phase,credentials::DeviceIdentity,
        owner::OwnerPath,recovery::{RecoveryKit,RecoverySeed},recovery_credentials,recovery_read::{ReadSession,RecoveryReply},
        recovery_state::PreparedRecovery,replacement::{self,Route}};
    use crate::sync::env::Keychain;
    for fail_after_rename in [false,true] {
    let service=Service::new();let d=TestDevice::new("replace-same-machine",&FakeRelay::new(),&TestClock::new());
    service.login(&d);bootstrap::prepare(&d.env()).unwrap();let reveal=bootstrap::reveal(&d.env()).unwrap();
    bootstrap::confirm(&d.env(),&reveal.root).unwrap();
    let original=record_runtime::snapshot(&d.env()).unwrap().0;
    let global=controller::context(&d.env()).unwrap();let profile=global.profile.profile().unwrap();
    let saved_identity=d.keychain.entry(&profile.slot("device"));
    let intent=replacement::prepare(&d.env(),Route::RecoveryKit).unwrap();
    let operation=intent.operation.clone();let path=OwnerPath::Replacement(operation.clone());
    let selected=DeviceIdentity::load_selected(&d.keychain,&profile,Some(&operation),true).unwrap();
    let template=controller::Session{profile:global.profile.clone(),identity:Some(Arc::new(selected)),tokens:Arc::clone(&global.tokens),
        device:None,device_access_denied:false,tokens_started:global.tokens_started};
    let api=Api::new(&service.server.url()).unwrap();let session=bootstrap::register(&d.env(),&template,&api).unwrap();
    let _lifecycle=d.runtime.lifecycle.lock().unwrap();
    let initial=replacement::initialize_candidate(&d.env(),&operation,&session).unwrap();
    assert_eq!(replacement::initialize_candidate(&d.env(),&operation,&session).unwrap(),initial);
    assert!(replacement::initialize_candidate(&d.env(),&operation,&global).is_err());
    assert_eq!(OwnerPath::Current.snapshot(&d.env()).unwrap().control,original.local.central.as_ref().unwrap().control);
    let identity=session.identity.as_ref().unwrap();let kit=RecoveryKit::parse(&reveal.kit).unwrap();
    let request=Enrollment::create(kit.anchor(),&identity.id,&identity.keys,d.env().now()).unwrap();
    let mut awaiting=initial.clone();awaiting.control.phase=Phase::AwaitingApproval;awaiting.control.pending_request=Some(request.clone());
    path.publish(&d.env(),&initial,&awaiting).unwrap();
    let response=api.control(session.device.as_ref().unwrap(),Control::Enrollment,&json!({"request":request})).unwrap();assert_eq!(response.status,204);
    let remote=controller::overview(&d.env(),&api,&session).unwrap();let proof=remote.proof.unwrap();
    let chain=proof.verify(kit.anchor(),None).unwrap();let read_proof=kit.read_proof(&chain,&request,remote.auth_epoch,d.env().now()).unwrap();
    let reply:RecoveryReply=api.control(session.device.as_ref().unwrap(),Control::RecoveryRead,&json!({"proof":read_proof})).unwrap().decode().unwrap();
    let read=ReadSession::begin_fresh(&awaiting,&kit,proof,reply,d.env().now()).unwrap().finish().unwrap();
    let prepared=PreparedRecovery::create(read,&kit,&identity.keys,RecoverySeed::generate().unwrap(),operation.clone(),d.env().now()).unwrap();
    d.keychain.set(&profile.slot("recovery-intent"),"retained-original-recovery-authority").unwrap();
    let permit=recovery_credentials::stage_at(&d.env(),&path,&awaiting,&prepared,&kit).unwrap();
    assert!(recovery_credentials::install(&d.env(),&awaiting,&prepared.package,permit).is_err());
    let permit=recovery_credentials::stage_at(&d.env(),&path,&awaiting,&prepared,&kit).unwrap();
    recovery_credentials::install_at(&d.env(),&path,&awaiting,&prepared.package,permit).unwrap();
    let shown=recovery_credentials::reveal_at(&d.env(),&path).unwrap();assert_ne!(shown.kit,reveal.kit);
    let unconfirmed=path.snapshot(&d.env()).unwrap();
    let premature=prepared.package.accepted(&unconfirmed,prepared.package.proof(),prepared.package.admission.authorization_epoch+1).unwrap();
    let saved=record_runtime::snapshot(&d.env()).unwrap();
    assert!(path.publish(&d.env(),&unconfirmed,&premature).is_err());
    assert_eq!(record_runtime::snapshot(&d.env()).unwrap(),saved);
    recovery_credentials::confirm_backup_at(&d.env(),&path,&operation).unwrap();
    let before=path.snapshot(&d.env()).unwrap();
    let premature=prepared.package.accepted(&before,prepared.package.proof(),prepared.package.admission.authorization_epoch+1).unwrap();
    assert!(path.publish(&d.env(),&before,&premature).is_err());
    let mut submitted=before.clone();
    match submitted.recovery.as_mut().unwrap(){super::recovery_state::RecoveryState::Pending{package}=>package.submitted=true,_=>panic!()}
    path.publish(&d.env(),&before,&submitted).unwrap();
    let wraps=BTreeMap::from([(prepared.package.admission.vault.clone(),prepared.package.wraps.clone())]);
    let reply=api.control(session.device.as_ref().unwrap(),Control::Recover,&json!({"node":prepared.package.node,"wraps":wraps})).unwrap();assert_eq!(reply.status,200);
    let renewed=bootstrap::register(&d.env(),&session,&api).unwrap();let remote=controller::overview(&d.env(),&api,&renewed).unwrap();
    let accepted=prepared.package.accepted(&submitted,remote.proof.unwrap(),remote.auth_epoch).unwrap();
    path.publish(&d.env(),&submitted,&accepted).unwrap();
    recovery_credentials::cleanup_at(&d.env(),&path).unwrap();
    let staged=path.snapshot(&d.env()).unwrap();staged.require_key_recipients().unwrap();
    assert!(d.keychain.entry(&profile.device_slot("recovery-intent",Some(&operation)).unwrap()).is_none());
    assert_eq!(d.keychain.entry(&profile.slot("recovery-intent")).as_deref(),Some("retained-original-recovery-authority"));
    assert_eq!(d.keychain.entry(&profile.slot("device")),saved_identity);
    let source=OwnerPath::Current.snapshot(&d.env()).unwrap();
    assert_eq!(source.control,original.local.central.as_ref().unwrap().control);
    assert_eq!(source.replica,original.local.central.as_ref().unwrap().replica);
    assert_eq!(source.replacement.as_ref().unwrap().recovery_confirmation.as_ref(),Some(&prepared.package.admission));
    assert!(source.require_key_recipients().is_err());
    // No independent runtime was constructed and no old local record or owner was replaced.
    assert_eq!(record_runtime::snapshot(&d.env()).unwrap().0.local.hosts,original.local.hosts);
    let (proof,snapshot)={let state=service.state.lock().unwrap();(state.proof.clone().unwrap(),super::active_read::Snapshot{
        membership_head:state.chain().unwrap().current().head().into(),auth_epoch:state.epoch,vault:super::recovery_read::RecoveryVault{
            vault:state.vault.clone().unwrap(),epoch:1,phase:"rekey_pending".into(),wrap:state.wraps.iter().find(|w|w.header.recipient==identity.id).unwrap().clone(),
            committed:None,commits:vec![],sequence:"0".into(),history_hash:"0".repeat(64)}})};
    let read=super::active_read::ReadSession::begin(&staged,renewed.identity.as_ref().unwrap(),proof,snapshot,&[]).unwrap().finish().unwrap();
    let authority=super::replacement_publication::Authorization::prepare(&d.env(),Arc::new(renewed),read,vec![],vec![]).unwrap();
    let (latest,generation)=record_runtime::snapshot(&d.env()).unwrap();
    let archive=super::replacement_archive::prepare(&d.env(),&_lifecycle,&latest,generation,&operation).unwrap();
    let manual=authority.records(&latest,archive.receipt().clone()).unwrap();
    assert!(record_runtime::commit_candidate(&d.env(),generation,manual.clone()).is_err());
    assert!(record_runtime::save_active(&d.env().state_path,&manual).is_err());
    let old_owner=original.local.central.as_ref().unwrap();let old_chain=old_owner.control.verified_chain().unwrap();
    let old_identity=global.identity.as_ref().unwrap();let old_wrap=&old_owner.own_wraps[0];
    let old_keys=old_wrap.open(&old_identity.keys,&old_wrap.header,&old_identity.keys.public().signing).unwrap();
    let local_id=super::payload::Identity{kind:"host".into(),id:"0000000000000001".into(),scope:Some(crate::sync::records_v3::HostScope::Local)};
    let local_data=super::payload::Data::Host(serde_json::from_value(json!({"schema":2,"alias":"unsent-local-B","hostname":"local.invalid","auth":"password"})).unwrap());
    let local_plain=super::payload::encode(&local_id,&local_data).unwrap();
    let mut old_replica=old_owner.replica.clone().unwrap();
    old_replica.enqueue(&old_chain,&old_keys,&old_identity.keys,1,RecordHeader{
        origin:old_owner.control.profile.origin.clone(),account_id:old_owner.control.account_id.clone(),genesis_hash:old_owner.control.anchor.as_ref().unwrap().genesis_hash.clone(),
        vault_id:old_replica.vault.clone(),record_id:local_id.opaque(&old_keys).unwrap(),key_epoch:"1".into(),membership_head:old_chain.current().head().into(),author:old_identity.id.clone(),
        operation_id:crypto::random_id(16).unwrap(),expected_revision:"0".into(),kind:"host".into(),deleted:false},&local_plain).unwrap();
    record_runtime::mutate_records(&d.env(),|records|{let mut next=records.clone();next.device_name="local-B-after-first-archive".into();next.local.central.as_mut().unwrap().replica=Some(old_replica.clone());Ok(next)}).unwrap();
    assert!(record_runtime::publish_replacement(&d.env(),&authority,archive).is_err());
    let (latest,generation)=record_runtime::snapshot(&d.env()).unwrap();
    assert_eq!(latest.local.central.as_ref().unwrap().control.device,original.local.central.as_ref().unwrap().control.device);
    // Neither a failed durable write nor an unexpected source file may switch the live owner.
    let bytes=std::fs::read(&d.env().state_path).unwrap();
    for failure in [record_runtime::ReplacementWriteStage::FileSync,record_runtime::ReplacementWriteStage::Rename] {
        let archive=super::replacement_archive::prepare(&d.env(),&_lifecycle,&latest,generation,&operation).unwrap();
        let result=record_runtime::with_replacement_write_hook(Box::new(move |stage,_| {
            if stage==failure {Err(crate::error::AppError::Other("injected replacement write failure".into()))}else{Ok(())}
        }),||record_runtime::publish_replacement(&d.env(),&authority,archive));
        assert!(result.is_err());assert_eq!(record_runtime::snapshot(&d.env()).unwrap(),(latest.clone(),generation));
        assert_eq!(std::fs::read(&d.env().state_path).unwrap(),bytes);
        assert!(d.runtime.core.lock().unwrap().save_blocked.is_none());
    }
    let mut external=latest.clone();external.device_name="unexpected disk modification".into();
    let external_bytes=serde_json::to_vec_pretty(&external).unwrap();let changed_bytes=external_bytes.clone();
    let archive=super::replacement_archive::prepare(&d.env(),&_lifecycle,&latest,generation,&operation).unwrap();
    let result=record_runtime::with_replacement_write_hook(Box::new(move |stage,path| {
        if stage==record_runtime::ReplacementWriteStage::SourceRecheck {
            #[cfg(windows)]
            crate::sync::central_files_windows::write(path,&changed_bytes,true)?;
            #[cfg(not(windows))]
            crate::fsutil::atomic_write(path,&changed_bytes,0o600)?;
        }
        Ok(())
    }),||record_runtime::publish_replacement(&d.env(),&authority,archive));
    assert!(result.is_err());assert_eq!(std::fs::read(&d.env().state_path).unwrap(),external_bytes);
    assert_eq!(record_runtime::snapshot(&d.env()).unwrap(),(latest.clone(),generation));
    crate::fsutil::atomic_write(&d.env().state_path,&bytes,0o600).unwrap();
    let archive=super::replacement_archive::prepare(&d.env(),&_lifecycle,&latest,generation,&operation).unwrap();
    let expected=authority.records(&latest,archive.receipt().clone()).unwrap();
    if fail_after_rename {
        let result=record_runtime::with_replacement_write_hook(Box::new(|stage,_| {
            if stage==record_runtime::ReplacementWriteStage::DirectorySync {Err(crate::error::AppError::Other("injected directory sync failure".into()))}else{Ok(())}
        }),||record_runtime::publish_replacement(&d.env(),&authority,archive));
        assert!(result.is_err());assert_eq!(record_runtime::snapshot(&d.env()).unwrap(),(latest.clone(),generation));
        {let core=d.runtime.core.lock().unwrap();assert!(core.save_blocked.is_some());assert!(core.central_session.is_none());}
        assert!(record_runtime::mutate_records(&d.env(),|records|Ok(records.clone())).is_err());
        let probe=record_runtime::probe_startup(&d.env().state_path,"durability-restart");
        record_runtime::activate_probe(&mut d.runtime.core.lock().unwrap(),probe).unwrap();
        assert!(d.runtime.core.lock().unwrap().save_blocked.is_none());
    } else {
        drop(archive);authority.publish(&d.env(),&_lifecycle).unwrap();
        assert_eq!(controller::context(&d.env()).unwrap().identity.as_ref().unwrap().device(),identity.device());
    }
    let published=record_runtime::snapshot(&d.env()).unwrap().0;assert_eq!(published,expected);
    assert_eq!(published.device_name,"local-B-after-first-archive");
    let current=published.local.central.as_ref().unwrap();assert_eq!(current.control.device,identity.device());
    assert_eq!(current.identity_slot.as_ref(),Some(&operation));assert!(current.replacement.is_none());
    assert_eq!(current.replacement_archives.len(),1);assert!(current.control.denied_devices.contains(&original.local.central.as_ref().unwrap().control.device.id));
    let restored=super::replacement_archive::restore(&d.env(),&profile,&current.replacement_archives[0].receipt).unwrap();
    assert_eq!(restored,latest);
    let restored_replica=restored.local.central.as_ref().unwrap().replica.as_ref().unwrap();
    assert_eq!(restored_replica.pending.len(),1);
    let draft=&restored_replica.pending.values().next().unwrap().latest;
    let decrypted=draft.envelope.verify(&old_identity.keys.public().signing).unwrap().open(&old_keys).unwrap();
    assert_eq!(decrypted.as_slice(),local_plain.as_slice());
    assert!(current.replacement_archives[0].needs_reconciliation);assert!(!current.can_upload());
    assert!(current.replica.as_ref().unwrap().pending.is_empty());
    let retry=super::replacement_archive::prepare(&d.env(),&_lifecycle,&latest,generation,&operation).unwrap();
    assert!(record_runtime::publish_replacement(&d.env(),&authority,retry).is_err());
    assert_eq!(record_runtime::snapshot(&d.env()).unwrap().0,published);
    assert_eq!(d.keychain.entry(&profile.slot("device")),saved_identity);
    let mut discarded=current.clone();discarded.replacement_archives.clear();assert!(current.verify_transition(&discarded).is_err());
    let mut swapped=current.clone();swapped.identity_slot=None;assert!(current.verify_transition(&swapped).is_err());
    let probe=record_runtime::probe_startup(&d.env().state_path,"after-replacement");
    record_runtime::activate_probe(&mut d.runtime.core.lock().unwrap(),probe).unwrap();
    assert_eq!(record_runtime::snapshot(&d.env()).unwrap().0,published);
    }
}

#[test]
fn trusted_replacement_requires_the_protected_oob_secret_and_exact_selected_session() {
    use super::{api::{Api,Control},credentials::DeviceIdentity,owner::OwnerPath,replacement::{self,Route}};
    use crate::sync::env::Keychain;
    let service=Service::new();let relay=FakeRelay::new();let clock=TestClock::new();
    let d=TestDevice::new("old-owner",&relay,&clock);let trusted=TestDevice::new("trusted",&relay,&clock);
    service.login(&d);bootstrap::prepare(&d.env()).unwrap();let kit=bootstrap::reveal(&d.env()).unwrap();bootstrap::confirm(&d.env(),&kit.root).unwrap();
    service.login(&trusted);let code=devices::pairing_code(&trusted.env()).unwrap();devices::approve(&d.env(),&code.code).unwrap();controller::refresh(&trusted.env()).unwrap();
    let old=controller::context(&d.env()).unwrap();let profile=old.profile.profile().unwrap();let saved=d.keychain.entry(&profile.slot("device"));
    let intent=replacement::prepare(&d.env(),Route::TrustedDevice).unwrap();let operation=intent.operation.clone();let path=OwnerPath::Replacement(operation.clone());
    let identity=DeviceIdentity::load_selected(&d.keychain,&profile,Some(&operation),true).unwrap();
    let template=controller::Session{profile:old.profile.clone(),identity:Some(Arc::new(identity)),tokens:Arc::clone(&old.tokens),device:None,device_access_denied:false,tokens_started:old.tokens_started};
    let api=Api::new(&service.server.url()).unwrap();let session=bootstrap::register(&d.env(),&template,&api).unwrap();
    let lifecycle=d.runtime.lifecycle.lock().unwrap();let initial=replacement::initialize_candidate(&d.env(),&operation,&session).unwrap();
    let source=OwnerPath::Current.snapshot(&d.env()).unwrap();let anchor=source.control.anchor.as_ref().unwrap();let identity=session.identity.as_ref().unwrap();
    let pairing=super::pairing::PendingPairing::begin(anchor,&identity.id,&identity.keys,d.env().now()).unwrap();
    let slot=profile.device_slot("pairing",Some(&operation)).unwrap();let secret=pairing.encode_secret().unwrap();d.keychain.set(&slot,&secret).unwrap();
    let mut awaiting=initial.clone();awaiting.control=initial.control.begin_pairing(&pairing).unwrap();path.publish(&d.env(),&initial,&awaiting).unwrap();
    let reply=api.control(session.device.as_ref().unwrap(),Control::Enrollment,&json!({"request":pairing.request()})).unwrap();assert_eq!(reply.status,204);
    devices::approve(&trusted.env(),&pairing.code().unwrap()).unwrap();
    let renewed=bootstrap::register(&d.env(),&session,&api).unwrap();let remote=controller::overview(&d.env(),&api,&renewed).unwrap();
    let mut accepted=awaiting.clone();accepted.control=awaiting.control.accept_pairing(&pairing,remote.pairing_confirmation.as_ref().unwrap(),remote.proof.unwrap()).unwrap();
    accepted.control.auth_epoch=remote.auth_epoch;path.publish(&d.env(),&awaiting,&accepted).unwrap();
    let read=||{let state=service.state.lock().unwrap();let proof=state.proof.clone().unwrap();let snapshot=super::active_read::Snapshot{
        membership_head:state.chain().unwrap().current().head().into(),auth_epoch:state.epoch,vault:super::recovery_read::RecoveryVault{
            vault:state.vault.clone().unwrap(),epoch:1,phase:"ready".into(),wrap:state.wraps.iter().find(|w|w.header.recipient==identity.id).unwrap().clone(),
            committed:None,commits:vec![],sequence:"0".into(),history_hash:"0".repeat(64)}};
        super::active_read::ReadSession::begin(&accepted,identity,proof,snapshot,&[]).unwrap().finish().unwrap()};
    let renewed=Arc::new(renewed);
    assert!(super::replacement_publication::Authorization::prepare(&d.env(),Arc::clone(&old),read(),vec![],vec![]).is_err());
    d.keychain.set(&slot,"{}").unwrap();
    assert!(super::replacement_publication::Authorization::prepare(&d.env(),Arc::clone(&renewed),read(),vec![],vec![]).is_err());
    assert_eq!(OwnerPath::Current.snapshot(&d.env()).unwrap().control.device,source.control.device);
    d.keychain.set(&slot,&secret).unwrap();
    let authority=super::replacement_publication::Authorization::prepare(&d.env(),Arc::clone(&renewed),read(),vec![],vec![]).unwrap();
    authority.publish(&d.env(),&lifecycle).unwrap();
    let switched=OwnerPath::Current.snapshot(&d.env()).unwrap();assert_eq!(switched.control.device,identity.device());
    assert_eq!(switched.control.phase,super::client_state::Phase::Rekey);
    assert!(switched.control.denied_devices.contains(&source.control.device.id));assert!(switched.require_key_recipients().is_err());
    assert_eq!(switched.replacement_archives[0].route,Route::TrustedDevice);assert!(switched.replacement_archives[0].needs_reconciliation);
    assert_eq!(d.keychain.entry(&profile.slot("device")),saved);
}

#[test]
fn trusted_replacement_driver_uses_account_only_login_and_fences_cancelled_or_corrupt_reads() {
    use super::{replacement_flow,round};
    use crate::sync::env::Keychain;
    for (interrupted,rotated,stronger) in [(false,false,false),(true,false,false),(false,true,false),(false,false,true)] {
        let (service,peer,_kit,_keys,first)=recovery_fixture_with_source(33);
        round::sync_once(&first.env()).unwrap();
        let invite=devices::pairing_code(&peer.env()).unwrap();devices::approve(&first.env(),&invite.code).unwrap();
        controller::refresh(&peer.env()).unwrap();round::sync_once(&peer.env()).unwrap();
        assert_eq!(record_runtime::snapshot(&peer.env()).unwrap().0.local.central.as_ref().unwrap().replica.as_ref().unwrap().checkpoint.sequence,33);
        let original=record_runtime::snapshot(&first.env()).unwrap().0;
        if rotated {
            let registry=devices::registry(&peer.env()).unwrap();let old=registry.devices.iter().find(|v|v.id==original.local.central.as_ref().unwrap().control.device.id).unwrap();
            devices::revoke(&peer.env(),&old.id,&registry.membership_head,&registry.authorization_epoch,&old.fingerprint).unwrap();
            for _ in 0..8 {round::sync_once(&peer.env()).unwrap();if !service.state.lock().unwrap().rekey_pending && record_runtime::snapshot(&peer.env()).unwrap().0.local.central.as_ref().unwrap().control.phase==super::client_state::Phase::Enrolled{break;}}
            assert_eq!(service.state.lock().unwrap().key_epoch,2);assert!(!service.state.lock().unwrap().rekey_pending);
            assert_eq!(record_runtime::snapshot(&peer.env()).unwrap().0.local.central.as_ref().unwrap().control.phase,super::client_state::Phase::Enrolled);
        }
        let profile=controller::context(&first.env()).unwrap().profile.profile().unwrap();
        first.keychain.delete(&profile.slot("device")).unwrap();controller::refresh(&first.env()).unwrap();
        assert!(controller::context(&first.env()).unwrap().identity.is_none());
        let pending=replacement_flow::begin_trusted(&first.env()).unwrap();assert_eq!(pending.phase,"awaiting_approval");let operation=pending.operation.unwrap();
        let invite=replacement_flow::pairing_code(&first.env(),&operation).unwrap();devices::approve(&peer.env(),&invite.code).unwrap();
        let reading=replacement_flow::begin_trusted(&first.env()).unwrap();assert_eq!(reading.phase,"reading");assert_eq!(reading.total,33);
        assert_eq!(record_runtime::snapshot(&first.env()).unwrap().0.local.central.as_ref().unwrap().control.device,original.local.central.as_ref().unwrap().control.device);
        if stronger {
            // Model a separate verified round advancing the old owner's floor after HTTP began.
            let local=Arc::clone(&first);service.state.lock().unwrap().on_pull=Some(Box::new(move||{
                record_runtime::mutate_records(&local.env(),|records|{let mut next=records.clone();let replica=next.local.central.as_mut().unwrap().replica.as_mut().unwrap();replica.checkpoint.sequence=34;replica.checkpoint.history_hash="f".repeat(64);Ok(next)}).unwrap();
            }));
            assert!(replacement_flow::advance(&first.env(),&operation).is_err());
            let retained=record_runtime::snapshot(&first.env()).unwrap().0;let owner=retained.local.central.as_ref().unwrap();
            assert_eq!(owner.control.device,original.local.central.as_ref().unwrap().control.device);assert_eq!(owner.replica.as_ref().unwrap().checkpoint.sequence,34);
            assert!(owner.replacement_archives.is_empty());assert!(owner.replacement.is_some());continue;
        }
        if interrupted {
            let local=Arc::clone(&first);service.state.lock().unwrap().on_pull=Some(Box::new(move||replacement_flow::cancel(&local.env())));
            assert!(replacement_flow::advance(&first.env(),&operation).is_err());
            assert_eq!(replacement_flow::status(&first.env()).unwrap().phase,"paused");
            assert!(record_runtime::snapshot(&first.env()).unwrap().0.local.central.as_ref().unwrap().replacement_archives.is_empty());
            assert_eq!(replacement_flow::begin_trusted(&first.env()).unwrap().operation.as_deref(),Some(operation.as_str()));
            service.state.lock().unwrap().corrupt_pull_once=true;
            assert!(replacement_flow::advance(&first.env(),&operation).is_err());
            assert!(record_runtime::snapshot(&first.env()).unwrap().0.local.central.as_ref().unwrap().replacement_archives.is_empty());
            replacement_flow::cancel(&first.env());replacement_flow::begin_trusted(&first.env()).unwrap();
        }
        let local=Arc::clone(&first);service.state.lock().unwrap().on_pull=Some(Box::new(move||{
            record_runtime::mutate_records(&local.env(),|records|{let mut next=records.clone();next.device_name="local-B-during-active-read".into();Ok(next)}).unwrap();
        }));
        let result=replacement_flow::advance(&first.env(),&operation).unwrap();assert_eq!(result.phase,"complete");
        let published=record_runtime::snapshot(&first.env()).unwrap().0;let owner=published.local.central.as_ref().unwrap();
        assert_eq!(published.device_name,"local-B-during-active-read");assert_eq!(owner.identity_slot.as_deref(),Some(operation.as_str()));
        assert_ne!(owner.control.device,original.local.central.as_ref().unwrap().control.device);
        assert_eq!(owner.replica.as_ref().unwrap().current.len(),33);assert_eq!(owner.replica.as_ref().unwrap().checkpoint.sequence,33);
        assert_eq!(owner.replica.as_ref().unwrap().checkpoint.epoch,if rotated{2}else{1});
        assert_eq!(owner.replacement_archives[0].minimums[0].epoch,1);
        assert_eq!(owner.control.phase,if rotated{super::client_state::Phase::Enrolled}else{super::client_state::Phase::Rekey});assert_eq!(owner.require_key_recipients().is_ok(),rotated);
        let restored=super::replacement_archive::restore(&first.env(),&profile,&owner.replacement_archives[0].receipt).unwrap();
        assert_eq!(restored.device_name,"local-B-during-active-read");assert_eq!(restored.local.central.as_ref().unwrap().control.device,original.local.central.as_ref().unwrap().control.device);
        assert!(first.keychain.get(&profile.slot("device")).unwrap().is_none());
        let selected=owner.control.device.clone();controller::refresh(&first.env()).unwrap();
        assert_eq!(controller::context(&first.env()).unwrap().identity.as_ref().unwrap().device(),selected);
        assert_eq!(replacement_flow::status(&first.env()).unwrap().phase,"complete");
    }
}

#[test]
fn scoped_kit_replacement_keeps_the_original_owner_until_backup_recovery_and_a_newer_full_baseline()
{
    use super::{
        active_flow,
        owner::OwnerPath,
        recovery_credentials,
        recovery_flow::{self, Scope},
        replacement::{self, Route},
        replacement_publication::Authorization,
    };
    use crate::sync::env::Keychain;
    for interrupted in [false, true] {
        let (service, _peer, kit, keys, first) = recovery_fixture_with_source(33);
        super::round::sync_once(&first.env()).unwrap();
        let original = record_runtime::snapshot(&first.env()).unwrap().0;
        let old_session = controller::context(&first.env()).unwrap();
        let profile = old_session.profile.profile().unwrap();
        first.keychain.delete(&profile.slot("device")).unwrap();
        controller::refresh(&first.env()).unwrap();
        assert!(controller::context(&first.env())
            .unwrap()
            .identity
            .is_none());
        first
            .keychain
            .set(
                &profile.slot("recovery-intent"),
                "unrelated-old-protected-authority",
            )
            .unwrap();
        let intent = replacement::prepare(&first.env(), Route::RecoveryKit).unwrap();
        let operation = intent.operation.clone();
        let path = OwnerPath::Replacement(operation.clone());
        let selected = super::credentials::DeviceIdentity::load_selected(
            &first.keychain,
            &profile,
            Some(&operation),
            true,
        )
        .unwrap();
        let account = controller::context(&first.env()).unwrap();
        let template = controller::Session {
            profile: account.profile.clone(),
            identity: Some(Arc::new(selected)),
            tokens: Arc::clone(&account.tokens),
            device: None,
            device_access_denied: false,
            tokens_started: account.tokens_started,
        };
        let api = super::api::Api::new(&service.server.url()).unwrap();
        let session = Arc::new(bootstrap::register(&first.env(), &template, &api).unwrap());
        {
            let _lifecycle = first.runtime.lifecycle.lock().unwrap();
            replacement::initialize_candidate(&first.env(), &operation, &session).unwrap();
        }
        let generation = "b".repeat(32);
        *first.runtime.central_replacement_generation.lock().unwrap() = Some(generation.clone());
        let scope = Scope::replacement(
            &operation,
            Arc::clone(&session),
            &generation,
            std::time::Instant::now(),
        )
        .unwrap();
        if interrupted {
            let local = Arc::clone(&first);
            service.state.lock().unwrap().on_pull = Some(Box::new(move || {
                super::replacement_flow::cancel(&local.env());
                assert_eq!(
                    super::replacement_flow::status(&local.env()).unwrap().phase,
                    "paused"
                );
            }));
            assert!(
                recovery_flow::start_at(&first.env(), scope.clone(), Some(&kit.kit), false)
                    .is_err()
            );
            assert!(OwnerPath::Current
                .snapshot(&first.env())
                .unwrap()
                .replacement_archives
                .is_empty());
            assert!(path.snapshot(&first.env()).unwrap().recovery.is_none());
            *first.runtime.central_replacement_generation.lock().unwrap() =
                Some(generation.clone());
        }
        if !interrupted {
            let local = Arc::clone(&first);
            service.state.lock().unwrap().on_pull =
                Some(Box::new(move || recovery_flow::cancel(&local.env())));
        }
        let ready =
            recovery_flow::start_at(&first.env(), scope.clone(), Some(&kit.kit), false).unwrap();
        assert_eq!(ready.phase, "backup_required");
        assert_eq!(ready.operation.as_deref(), Some(operation.as_str()));
        let shown = {
            let _lifecycle = first.runtime.lifecycle.lock().unwrap();
            recovery_credentials::reveal_at(&first.env(), &path).unwrap()
        };
        assert_ne!(shown.kit, kit.kit);
        assert!(recovery_flow::confirm(&first.env(), &operation).is_err());
        assert!(recovery_flow::advance(&first.env()).is_err());
        assert_eq!(
            controller::context(&first.env())
                .unwrap()
                .identity
                .is_none(),
            true
        );
        assert_eq!(
            OwnerPath::Current
                .snapshot(&first.env())
                .unwrap()
                .control
                .device,
            original.local.central.as_ref().unwrap().control.device
        );
        // Another old authorized device may append after the initial 33-row verification.
        let id = super::payload::Identity {
            kind: "host".into(),
            id: "0000000000000022".into(),
            scope: Some(crate::sync::records_v3::HostScope::Local),
        };
        let data=super::payload::Data::Host(serde_json::from_value(json!({"schema":2,"alias":"late-before-recover","hostname":"late.invalid","auth":"password"})).unwrap());
        let plain = super::payload::encode(&id, &data).unwrap();
        {
            let mut state = service.state.lock().unwrap();
            let chain = state.chain().unwrap();
            let anchor = chain.current().anchor();
            let envelope = crypto::seal_record(
                &keys,
                &old_session.identity.as_ref().unwrap().keys,
                RecordHeader {
                    origin: anchor.origin.clone(),
                    account_id: anchor.account_id.clone(),
                    genesis_hash: anchor.genesis_hash.clone(),
                    vault_id: state.vault.clone().unwrap(),
                    record_id: id.opaque(&keys).unwrap(),
                    key_epoch: "1".into(),
                    membership_head: chain.current().head().into(),
                    author: old_session.identity.as_ref().unwrap().id.clone(),
                    operation_id: "d".repeat(32),
                    expected_revision: "0".into(),
                    kind: "host".into(),
                    deleted: false,
                },
                &plain,
            )
            .unwrap();
            let digest = super::rekey::envelope_digest(&envelope).unwrap();
            let previous = state.history.last().unwrap().history_hash.clone();
            let history_hash = crypto::hash(
                &super::wire::canonical(&["lunport-history-v2", &previous, "34", &digest]).unwrap(),
            );
            state.history.push(super::rekey::Version {
                envelope,
                digest,
                history_hash,
                sequence: "34".into(),
                revision: "1".into(),
            });
        }
        service.state.lock().unwrap().lose_control_response_once = true;
        assert!(recovery_flow::confirm_at(&first.env(), &scope, &operation).is_err());
        let complete = recovery_flow::confirm_at(&first.env(), &scope, &operation).unwrap();
        assert_eq!(complete.phase, "complete");
        assert!(controller::context(&first.env())
            .unwrap()
            .identity
            .is_none());
        assert_eq!(
            first
                .keychain
                .get(&profile.slot("recovery-intent"))
                .unwrap()
                .as_deref(),
            Some("unrelated-old-protected-authority")
        );
        assert!(first
            .keychain
            .get(
                &profile
                    .device_slot("recovery-intent", Some(&operation))
                    .unwrap()
            )
            .unwrap()
            .is_none());
        assert!(OwnerPath::Current
            .snapshot(&first.env())
            .unwrap()
            .replacement_archives
            .is_empty());
        let lifecycle = first.runtime.lifecycle.lock().unwrap();
        let renewed = Arc::new(bootstrap::register(&first.env(), &template, &api).unwrap());
        let mut active = active_flow::Reading::begin(
            &first.env(),
            path.clone(),
            Arc::clone(&renewed),
            Some(OwnerPath::Current.snapshot(&first.env()).unwrap()),
            &|| super::replacement_flow::check(&first.env(), &generation),
        )
        .unwrap();
        assert_eq!(active.total(), 34);
        assert!(active
            .advance(&first.env(), &|| super::replacement_flow::check(
                &first.env(),
                &generation
            ))
            .unwrap());
        let (read, own, source) = active.finish().unwrap();
        let authority = Authorization::prepare(&first.env(), renewed, read, own, source).unwrap();
        authority.publish(&first.env(), &lifecycle).unwrap();
        let published = record_runtime::snapshot(&first.env()).unwrap().0;
        let owner = published.local.central.as_ref().unwrap();
        assert_eq!(owner.replica.as_ref().unwrap().checkpoint.sequence, 34);
        assert_eq!(owner.replica.as_ref().unwrap().current.len(), 34);
        assert_eq!(
            owner
                .recovery
                .as_ref()
                .unwrap()
                .admission()
                .checkpoint
                .sequence,
            33
        );
        assert_eq!(owner.identity_slot.as_deref(), Some(operation.as_str()));
        assert_eq!(
            owner.control.device,
            session.identity.as_ref().unwrap().device()
        );
        assert_eq!(owner.replacement_archives.len(), 1);
        assert!(first
            .keychain
            .get(&profile.slot("device"))
            .unwrap()
            .is_none());
    }
}

#[test]
fn recovery_initialization_and_history_share_one_bounded_continuation_budget() {
    let (service,peer,kit,_)=recovery_fixture(1025);
    let mut progress=super::recovery_flow::begin(&peer.env(),Some(&kit.kit)).unwrap();
    assert_eq!(progress.phase,"reading");assert!(progress.verified>0 && progress.verified<=832);
    assert!(service.state.lock().unwrap().pulls<=26);
    assert!(record_runtime::snapshot(&peer.env()).unwrap().0.local.central.as_ref().unwrap().recovery.is_none());
    while progress.phase=="reading" {
        let before=service.state.lock().unwrap().pulls;
        progress=super::recovery_flow::advance(&peer.env()).unwrap();
        assert!(service.state.lock().unwrap().pulls-before<=30);
    }
    assert_eq!(progress.phase,"backup_required");assert_eq!(progress.verified,1025);
    assert_eq!(record_runtime::snapshot(&peer.env()).unwrap().0.local.central.as_ref().unwrap().recovery.as_ref().unwrap().admission().checkpoint.sequence,1025);
}

#[test]
fn replacement_recovery_commands_resume_after_lost_reply_barrier_cancel_and_restart_without_the_old_identity() {
    use super::replacement_flow as flow;
    use crate::sync::env::Keychain;
    let (service,_peer,kit,_keys,first)=recovery_fixture_with_source(33);super::round::sync_once(&first.env()).unwrap();
    let original=record_runtime::snapshot(&first.env()).unwrap().0;let profile=controller::context(&first.env()).unwrap().profile.profile().unwrap();
    first.keychain.delete(&profile.slot("device")).unwrap();controller::refresh(&first.env()).unwrap();
    let ready=flow::begin_recovery(&first.env(),Some(&kit.kit)).unwrap();assert_eq!(ready.phase,"backup_required");
    let operation=ready.operation.unwrap();let shown=flow::recovery_kit(&first.env(),&operation).unwrap();
    assert_ne!(shown.kit,kit.kit);assert!(!flow::status(&first.env()).unwrap().backup_confirmed);
    assert!(flow::confirm_recovery(&first.env(),&"f".repeat(32)).is_err());
    assert!(flow::recovery_kit(&first.env(),&"f".repeat(32)).is_err());
    {let mut state=service.state.lock().unwrap();state.hold_barrier=true;state.lose_control_response_once=true;}
    assert!(flow::confirm_recovery(&first.env(),&operation).is_err());
    assert_eq!(flow::status(&first.env()).unwrap().phase,"submitted");assert!(flow::status(&first.env()).unwrap().backup_confirmed);
    flow::cancel(&first.env());let before=record_runtime::snapshot(&first.env()).unwrap().0;
    let probe=record_runtime::probe_startup(&first.env().state_path,"replacement-restart");record_runtime::activate_probe(&mut first.runtime.core.lock().unwrap(),probe).unwrap();
    service.login(&first);assert!(controller::context(&first.env()).unwrap().identity.is_none());
    let resumed=flow::begin_recovery(&first.env(),None).unwrap();assert_eq!(resumed.operation.as_deref(),Some(operation.as_str()));assert_eq!(resumed.phase,"submitted");
    assert_eq!(flow::recovery_kit(&first.env(),&operation).unwrap().kit,shown.kit);
    let waiting=flow::confirm_recovery(&first.env(),&operation).unwrap();assert_eq!(waiting.phase,"submitted");
    assert_eq!(record_runtime::snapshot(&first.env()).unwrap().0.local.central.as_ref().unwrap().control.device,original.local.central.as_ref().unwrap().control.device);
    service.state.lock().unwrap().hold_barrier=false;
    let verified=flow::confirm_recovery(&first.env(),&operation).unwrap();assert_eq!(verified.phase,"reading");assert_eq!(verified.total,33);
    assert!(controller::context(&first.env()).unwrap().identity.is_none());
    let status_json=serde_json::to_string(&flow::status(&first.env()).unwrap()).unwrap();assert!(!status_json.contains(&shown.kit));assert!(!status_json.contains(&kit.kit));
    let complete=flow::advance(&first.env(),&operation).unwrap();assert_eq!(complete.phase,"complete");
    let published=record_runtime::snapshot(&first.env()).unwrap().0;let owner=published.local.central.as_ref().unwrap();
    assert_eq!(owner.identity_slot.as_deref(),Some(operation.as_str()));assert_eq!(owner.replica.as_ref().unwrap().current.len(),33);
    assert_ne!(owner.control.device,original.local.central.as_ref().unwrap().control.device);assert!(owner.replacement.is_none());
    assert_eq!(owner.replacement_archives.len(),1);assert!(owner.control.denied_devices.contains(&original.local.central.as_ref().unwrap().control.device.id));
    let restored=super::replacement_archive::restore(&first.env(),&profile,&owner.replacement_archives[0].receipt).unwrap();
    assert_eq!(restored.local.central.as_ref().unwrap().control.device,before.local.central.as_ref().unwrap().control.device);
    assert!(first.keychain.get(&profile.slot("device")).unwrap().is_none());
    assert!(first.keychain.get(&profile.device_slot("recovery-intent",Some(&operation)).unwrap()).unwrap().is_none());
    controller::refresh(&first.env()).unwrap();assert_eq!(controller::context(&first.env()).unwrap().identity.as_ref().unwrap().device(),owner.control.device);
}

#[test]
fn replacement_ui_invocations_cannot_revive_cancelled_starts_or_control_a_newer_reader() {
    use super::{replacement::Route, replacement_flow as flow};
    use crate::sync::env::Keychain;
    use std::sync::atomic::Ordering;
    let (service, _peer, kit, _keys, first) = recovery_fixture_with_source(33);
    super::round::sync_once(&first.env()).unwrap();
    let profile = controller::context(&first.env())
        .unwrap()
        .profile
        .profile()
        .unwrap();
    first.keychain.delete(&profile.slot("device")).unwrap();
    controller::refresh(&first.env()).unwrap();
    let before = record_runtime::snapshot(&first.env()).unwrap();
    first.keychain.fail_reads.store(true, Ordering::SeqCst);
    let cancelled = flow::reserve_invocation(&first.env(), Route::RecoveryKit).unwrap();
    assert!(cancelled.operation.is_none());
    flow::cancel_invocation(&first.env(), &cancelled).unwrap();
    assert!(flow::start_invocation(&first.env(), &cancelled, Some(&kit.kit)).is_err());
    assert_eq!(record_runtime::snapshot(&first.env()).unwrap(), before);
    first.keychain.fail_reads.store(false, Ordering::SeqCst);
    let current = flow::reserve_invocation(&first.env(), Route::RecoveryKit).unwrap();
    flow::cancel_invocation(&first.env(), &cancelled).unwrap();
    assert_eq!(
        first
            .runtime
            .central_replacement_generation
            .lock()
            .unwrap()
            .as_deref(),
        Some(current.generation.as_str())
    );
    let mut forged = current.clone();
    forged.route = Route::TrustedDevice;
    assert!(flow::start_invocation(&first.env(), &forged, None).is_err());
    let mut forged = current.clone();
    forged.scope = "f".repeat(64);
    assert!(flow::start_invocation(&first.env(), &forged, None).is_err());
    let ready = flow::start_invocation(&first.env(), &current, Some(&kit.kit)).unwrap();
    assert_eq!(ready.phase, "backup_required");
    let operation = ready.operation.unwrap();
    let shown = flow::reveal_kit_invocation(&first.env(), &current, &operation).unwrap();
    flow::cancel_invocation(&first.env(), &current).unwrap();
    let next = flow::reserve_invocation(&first.env(), Route::RecoveryKit).unwrap();
    assert_eq!(next.operation.as_deref(), Some(operation.as_str()));
    let retained = record_runtime::snapshot(&first.env()).unwrap();
    assert!(flow::confirm_invocation(&first.env(), &current, &operation).is_err());
    assert!(flow::revalidate_invocation(&first.env(), &current, &operation, None).is_err());
    assert!(flow::reveal_kit_invocation(&first.env(), &current, &operation).is_err());
    assert_eq!(record_runtime::snapshot(&first.env()).unwrap(), retained);
    assert_eq!(
        flow::reveal_kit_invocation(&first.env(), &next, &operation)
            .unwrap()
            .kit,
        shown.kit
    );
    let reading = flow::confirm_invocation(&first.env(), &next, &operation).unwrap();
    assert_eq!(reading.phase, "reading");
    let latest = flow::reserve_invocation(&first.env(), Route::RecoveryKit).unwrap();
    assert_eq!(
        flow::start_invocation(&first.env(), &latest, None)
            .unwrap()
            .phase,
        "reading"
    );
    let pulls = service.state.lock().unwrap().pulls;
    assert!(flow::continue_invocation(&first.env(), &next, &operation).is_err());
    flow::cancel_invocation(&first.env(), &next).unwrap();
    assert_eq!(service.state.lock().unwrap().pulls, pulls);
    assert_eq!(flow::status(&first.env()).unwrap().verified, 0);
    assert_eq!(
        flow::continue_invocation(&first.env(), &latest, &operation)
            .unwrap()
            .phase,
        "complete"
    );
    assert_eq!(
        flow::cancel_invocation(&first.env(), &latest)
            .unwrap()
            .phase,
        "complete"
    );
}

#[cfg(any(unix, windows))]
#[path = "active_cycle_tests.rs"]
mod active_cycle_tests;

#[test]
fn automatic_password_setup_commits_only_ciphertext_before_cleanup_and_new_device_unlock_is_additive(
) {
    use super::{automatic, unlock_flow};
    let service = Service::automatic();
    super::api::with_test_transport(&service.origin, &service.server.url(), || {
        let relay = FakeRelay::new();
        let clock = TestClock::new();
        let first = TestDevice::new("automatic-first", &relay, &clock);
        let peer = TestDevice::new("automatic-peer", &relay, &clock);
        first.keychain.windows_credentials.store(true, std::sync::atomic::Ordering::SeqCst);
        peer.keychain.windows_credentials.store(true, std::sync::atomic::Ordering::SeqCst);
        service.login(&first);
        assert_eq!(
            automatic::start(&first.env()).unwrap().phase,
            "password_setup"
        );
        let password = "synthetic long unlock password";
        service.state.lock().unwrap().reject_unlock = true;
        assert!(automatic::password(&first.env(), password).is_err());
        let session = controller::context(&first.env()).unwrap();
        let profile = session.profile.profile().unwrap();
        assert!(
            crate::sync::env::Keychain::get(&first.keychain, &profile.slot("bootstrap"))
                .unwrap()
                .is_some()
        );
        assert_eq!(
            controller::status(&first.env()).unwrap().phase,
            "backup_required"
        );
        assert!(!controller::status(&first.env()).unwrap().can_sync);
        service.state.lock().unwrap().reject_unlock = false;
        automatic::password(&first.env(), password).unwrap();
        assert!(
            crate::sync::env::Keychain::get(&first.keychain, &profile.slot("bootstrap"))
                .unwrap()
                .is_none()
        );
        assert!(
            !serde_json::to_string(&service.state.lock().unwrap().unlock)
                .unwrap()
                .contains(password)
        );
        let first_id = controller::context(&first.env())
            .unwrap()
            .identity
            .as_ref()
            .unwrap()
            .id
            .clone();
        service.login(&peer);
        automatic::start(&peer.env()).unwrap();
        let peer_session = controller::context(&peer.env()).unwrap();
        let api = super::api::Api::new(&service.origin).unwrap();
        let view = controller::overview(&peer.env(), &api, &peer_session).unwrap();
        assert_eq!(view.device_state, super::api::DeviceState::Pending);
        assert!(view.vaults.is_empty());
        assert!(view.devices.is_empty());
        let before = record_runtime::snapshot(&peer.env()).unwrap();
        let wrong = automatic::password(&peer.env(), "wrong password").err().unwrap();
        assert!(wrong.to_string().contains("Check your sync unlock password"), "{wrong}");
        assert_eq!(record_runtime::snapshot(&peer.env()).unwrap(), before);
        assert_eq!(service.state.lock().unwrap().unlock_joins, 0);
        service.state.lock().unwrap().barrier_pending = true;
        let blocked = automatic::password(&peer.env(), password).err().unwrap();
        assert!(blocked.to_string().contains("The account changed"), "{blocked}");
        assert_eq!(record_runtime::snapshot(&peer.env()).unwrap(), before);
        assert!(!unlock_flow::active(&peer.env()));
        service.state.lock().unwrap().barrier_pending = false;
        automatic::password(&peer.env(), password).unwrap();
        assert!(unlock_flow::active(&peer.env()));
        assert!(!unlock_flow::advance(&peer.env()).unwrap());
        joining::initialize(&peer.env()).unwrap();
        assert_eq!(controller::status(&peer.env()).unwrap().phase, "enrolled");
        let s = service.state.lock().unwrap();
        assert!(s
            .chain()
            .unwrap()
            .current()
            .devices()
            .contains_key(&first_id));
        assert_eq!(s.chain().unwrap().current().devices().len(), 2);
        assert_eq!(s.unlock_joins, 1);
    });
}
#[test]
fn automatic_unlock_resumes_a_committed_join_after_lost_reply_and_process_restart() {
    use super::{automatic, unlock_flow};
    let service = Service::automatic();
    super::api::with_test_transport(&service.origin, &service.server.url(), || {
        let relay = FakeRelay::new();
        let clock = TestClock::new();
        let first = TestDevice::new("automatic-a", &relay, &clock);
        let peer = TestDevice::new("automatic-b", &relay, &clock);
        service.login(&first);
        automatic::start(&first.env()).unwrap();
        let password = "synthetic recovery password";
        automatic::password(&first.env(), password).unwrap();
        service.login(&peer);
        automatic::start(&peer.env()).unwrap();
        automatic::password(&peer.env(), password).unwrap();
        service.state.lock().unwrap().lose_unlock_join_reply = true;
        assert!(unlock_flow::advance(&peer.env()).is_err());
        assert_eq!(service.state.lock().unwrap().unlock_joins, 1);
        assert_eq!(
            controller::status(&peer.env()).unwrap().phase,
            "awaiting_approval"
        );
        unlock_flow::cancel(&peer.env());
        service.login(&peer);
        joining::initialize(&peer.env()).unwrap();
        assert_eq!(controller::status(&peer.env()).unwrap().phase, "enrolled");
        assert_eq!(service.state.lock().unwrap().unlock_joins, 1);
    });
}

#[test]
fn automatic_fresh_library_publishes_and_second_device_materializes_hosts_without_manual_review() {
    use super::automatic;
    let service = Service::automatic();
    super::api::with_test_transport(&service.origin, &service.server.url(), || {
        let relay = FakeRelay::new();
        let clock = TestClock::new();
        let first = TestDevice::new("automatic-library-a", &relay, &clock);
        let peer = TestDevice::new("automatic-library-b", &relay, &clock);
        first.keychain.windows_credentials.store(true, std::sync::atomic::Ordering::SeqCst);
        peer.keychain.windows_credentials.store(true, std::sync::atomic::Ordering::SeqCst);
        service.login(&first);
        crate::sync::testkit::private_directory(first.env().state_path.parent().unwrap());
        let payload:crate::sync::records_v3::HostPayload=serde_json::from_value(json!({"schema":2,"alias":"automatic-host","hostname":"synthetic.invalid","user":"fixture","port":22,"auth":"password"})).unwrap();
        crate::sync::record_commands::edit_records(&first.env(), |state, now| {
            crate::sync::record_repository::create_host(
                state,
                "f".repeat(16).as_str(),
                crate::sync::records_v3::HostScope::Local,
                payload.clone(),
                now,
            )
            .map_err(|_| super::wire::invalid())
        })
        .unwrap();
        let key_text = crate::sync::slot_rules::test_keys::plain();
        let key = crate::sync::record_keys::import_local(
            &first.env(),
            "automatic-key",
            Zeroizing::new(key_text.clone()),
            crate::vault::store::EntryOrigin::Imported,
        )
        .unwrap();
        automatic::start(&first.env()).unwrap();
        automatic::password(&first.env(), "automatic test password").unwrap();
        // Renew a missing device grant without repeating the sync password setup.
        let previous = controller::context(&first.env()).unwrap();
        first.runtime.core.lock().unwrap().central_session = Some(Arc::new(controller::Session {
            profile: previous.profile.clone(), identity: previous.identity.clone(),
            tokens: previous.tokens.clone(), device: None, device_access_denied: false,
            tokens_started: previous.tokens_started,
        }));
        for _ in 0..40 {
            if controller::status(&first.env()).unwrap().can_sync {
                break;
            }
            automatic::step(&first.env()).unwrap();
        }
        assert!(controller::status(&first.env()).unwrap().can_sync);
        assert!(!service.state.lock().unwrap().history.is_empty());
        service.login(&peer);
        crate::sync::testkit::private_directory(peer.env().state_path.parent().unwrap());
        automatic::start(&peer.env()).unwrap();
        automatic::password(&peer.env(), "automatic test password").unwrap();
        service.state.lock().unwrap().corrupt_pull_once = true;
        assert!(super::unlock_flow::advance(&peer.env()).is_err());
        assert_eq!(service.state.lock().unwrap().unlock_joins, 0);
        assert_eq!(
            controller::status(&peer.env()).unwrap().phase,
            "awaiting_approval"
        );
        super::unlock_flow::cancel(&peer.env());
        automatic::password(&peer.env(), "automatic test password").unwrap();
        for _ in 0..40 {
            if controller::status(&peer.env()).unwrap().can_sync {
                break;
            }
            automatic::step(&peer.env()).unwrap();
        }
        assert!(controller::status(&peer.env()).unwrap().can_sync);
        let records = record_runtime::snapshot(&peer.env()).unwrap().0;
        let overview = crate::sync::record_commands::overview(&peer.env()).unwrap();
        assert!(serde_json::to_string(&overview)
            .unwrap()
            .contains("automatic-host"));
        assert!(records.local.central.as_ref().unwrap().control.cutover);
        let vault = crate::vault::store::read_vault(
            &crate::vault::store::vault_path(&peer.env().state_path),
            &peer.keychain,
        )
        .unwrap();
        assert_eq!(
            vault.get(&records.local.keys.values().find(|k| k.public.fingerprint == key.public.fingerprint).unwrap().vault_id).unwrap().unwrap().private_key,
            key_text
        );
    });
}

#[test]
fn automatic_empty_library_resumes_after_signout_before_cutover() {
    use super::automatic;
    for prepared_steps in [0, 2] {
        let service = Service::automatic();
        super::api::with_test_transport(&service.origin, &service.server.url(), || {
            let first = TestDevice::new("resume-empty", &FakeRelay::new(), &TestClock::new());
            service.login(&first);
            crate::sync::testkit::private_directory(first.env().state_path.parent().unwrap());
            automatic::start(&first.env()).unwrap();
            automatic::password(&first.env(), "synthetic resume password").unwrap();
            for _ in 0..prepared_steps { automatic::step(&first.env()).unwrap(); }
            controller::sign_out(&first.env()).unwrap();
            let signed_out = record_runtime::snapshot(&first.env()).unwrap().0;
            let other = LoginTokens {
                issuer: service.config.issuer.clone(), subject: "another-account".into(),
                nonce: Zeroizing::new("synthetic nonce".into()),
                access: Zeroizing::new("synthetic access".into()),
                refresh: Some(Zeroizing::new("synthetic refresh".into())),
                expires_in: std::time::Duration::from_secs(300),
            };
            let error = controller::establish(&first.env(), &service.origin, service.config.clone(), other, None).unwrap_err().to_string();
            assert!(error.contains("different account"));
            assert_eq!(record_runtime::snapshot(&first.env()).unwrap().0, signed_out);
            service.login(&first);
            joining::initialize(&first.env()).unwrap();
            automatic::start(&first.env()).unwrap();
            for step in 0..40 {
                if controller::status(&first.env()).unwrap().can_sync { break; }
                automatic::step(&first.env()).unwrap_or_else(|error| panic!("resume step {step}, prepared {prepared_steps}: {error}"));
            }
            assert!(controller::status(&first.env()).unwrap().can_sync);
        });
    }
}
