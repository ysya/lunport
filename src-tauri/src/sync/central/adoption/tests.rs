use super::*;
use crate::sync::{
    central::{
        api::{self, DeviceSession, DeviceState},
        credentials::DeviceIdentity,
        crypto::{wrap_keys, DeviceKeys},
        membership::{self, Enrollment, SignedMembership},
        oidc::LoginTokens,
        replica::Replica,
        trust::ControlProof,
    },
    env::Keychain,
    fake_relay::FakeRelay,
    testkit::{TestClock, TestDevice},
};
use serde_json::{json, Value};
use std::{fs, os::unix::fs::PermissionsExt, sync::Mutex};
struct Fixture {
    first: TestDevice,
    peer: TestDevice,
    keys: VaultKeys,
    proof: ControlProof,
    rows: Vec<super::super::rekey::Version>,
    wrap: super::super::crypto::WrappedKeys,
    origin: String,
    manifest: super::super::migration::SignedMigration,
}
fn fixture(local: bool) -> Fixture {
    fixture_at(local, false)
}
fn fixture_at(local: bool, empty_minimum: bool) -> Fixture {
    fixture_legacy(local, empty_minimum, false)
}
fn fixture_legacy(local: bool, empty_minimum: bool, legacy: bool) -> Fixture {
    let (first, keys) = if legacy {
        super::super::capture_dispatch::material_ready_legacy_for_adoption_test()
    } else {
        super::super::capture_dispatch::material_ready_for_adoption_test()
    };
    let legacy_phrase = first
        .keychain
        .get(crate::sync::state::MNEMONIC_ACCOUNT)
        .unwrap()
        .map(Zeroizing::new);
    super::super::source_complete::ensure(&first.env(), &keys)
        .unwrap()
        .unwrap();
    let shown = serde_json::to_value(
        super::super::migration_journal::review::preview(&first.env(), &keys, &BTreeMap::new())
            .unwrap(),
    )
    .unwrap();
    super::super::migration_journal::review::confirm(
        &first.env(),
        &keys,
        &BTreeMap::new(),
        shown["ticket"].as_str().unwrap(),
    )
    .unwrap();
    let verified = super::super::migration_dispatch::verified_for_test(&first.env(), &keys);
    let rows = verified.loaded.plan.rows.clone();
    let manifest = verified.loaded.plan.manifest.clone();
    let first_owner = verified.loaded.plan.before().clone();
    fs::set_permissions(
        first.env().state_path.parent().unwrap(),
        fs::Permissions::from_mode(0o700),
    )
    .unwrap();
    let prepared =
        super::super::initial_publication::prepare(&first.env(), verified, &keys).unwrap();
    crate::sync::record_import::central_stage::prepare_initial_reserved(
        &first.env(),
        &prepared,
        &keys,
    )
    .unwrap();
    crate::sync::record_import::central_stage::publish_initial(&first.env(), &prepared, &keys)
        .unwrap();
    let peer = TestDevice::new("peer", &FakeRelay::new(), &TestClock::new());
    let env = peer.env();
    fs::create_dir_all(env.state_path.parent().unwrap()).unwrap();
    fs::set_permissions(
        env.state_path.parent().unwrap(),
        fs::Permissions::from_mode(0o700),
    )
    .unwrap();
    let probe = record_runtime::probe_startup(&env.state_path, "peer");
    record_runtime::activate_probe(&mut peer.runtime.core.lock().unwrap(), probe).unwrap();
    if local {
        let private = crate::sync::slot_rules::test_keys::encrypted();
        let imported = crate::sync::record_keys::import_local(
            &env,
            "peer-key",
            Zeroizing::new(private),
            crate::vault::store::EntryOrigin::Imported,
        )
        .unwrap();
        let payload:crate::sync::records_v3::HostPayload=serde_json::from_value(json!({"schema":2,"alias":"peer-local-host","hostname":"synthetic.invalid","user":"fixture","port":22,"auth":"key","key_id":imported.key_id})).unwrap();
        crate::sync::record_commands::edit_records(&env, |state, now| {
            crate::sync::record_repository::create_host(
                state,
                &"a".repeat(16),
                crate::sync::records_v3::HostScope::Local,
                payload.clone(),
                now,
            )
            .map_err(|e| AppError::Other(e.to_string()))
        })
        .unwrap();
    }
    let device_keys = DeviceKeys::generate().unwrap();
    let id = "b".repeat(32);
    let anchor = first_owner.control.anchor.clone().unwrap();
    let enrollment = Enrollment::create(&anchor, &id, &device_keys, env.now()).unwrap();
    let chain = first_owner.control.verified_chain().unwrap();
    let mut members = chain.current().devices().clone();
    members.insert(id.clone(), device_keys.public());
    let first_session = controller::context(&first.env()).unwrap();
    let first_identity = first_session.identity.as_ref().unwrap();
    let node = SignedMembership::sign(
        chain.current().proposal(
            &first_owner.control.device.id,
            membership::Action::Add,
            Some(enrollment),
            members,
            chain.current().recovery().clone(),
            env.now(),
        ),
        &first_identity.keys,
    )
    .unwrap();
    let mut proof = first_owner.control.proof.clone().unwrap();
    proof.nodes.push(node);
    let trusted = proof.verify(&anchor, None).unwrap();
    let profile = first_owner.control.profile.profile().unwrap();
    let encoded=Zeroizing::new(json!({"version":1,"locator":profile.locator,"id":id,"keys":device_keys.encode_secret().as_str(),"credential":"e".repeat(64)}).to_string());
    peer.keychain
        .set(&profile.slot("device"), &encoded)
        .unwrap();
    let identity = Arc::new(DeviceIdentity::load(&peer.keychain, &profile, false).unwrap());
    let wrap = wrap_keys(
        &keys,
        &first_identity.keys,
        super::super::wire::WrapHeader {
            origin: anchor.origin.clone(),
            account_id: anchor.account_id.clone(),
            genesis_hash: anchor.genesis_hash.clone(),
            vault_id: first_owner.control.personal_vault.clone().unwrap(),
            key_epoch: "1".into(),
            membership_head: trusted.current().head().into(),
            author: first_owner.control.device.id.clone(),
            recipient: id.clone(),
            recipient_key: identity.keys.public().encryption,
        },
    )
    .unwrap();
    let mut control = super::super::client_state::State::new(
        first_owner.control.profile.clone(),
        anchor.account_id.clone(),
        identity.device(),
        3,
    )
    .unwrap();
    control.anchor = Some(anchor.clone());
    control.proof = Some(proof.clone());
    control.highwater = Some(trusted.highwater());
    control.personal_vault = first_owner.control.personal_vault.clone();
    control.phase = super::super::client_state::Phase::Enrolled;
    let mut owner = Workspace::new(control).unwrap();
    owner.replica = Some(
        Replica::join(
            first_owner.control.personal_vault.clone().unwrap(),
            first_owner.replica.as_ref().unwrap().creation_head.clone(),
            2,
            Checkpoint {
                epoch: 1,
                sequence: if empty_minimum { 0 } else { rows.len() as u64 },
                history_hash: if empty_minimum {
                    "0".repeat(64)
                } else {
                    rows.last()
                        .map(|r| r.history_hash.clone())
                        .unwrap_or_else(|| "0".repeat(64))
                        .clone()
                },
            },
        )
        .unwrap(),
    );
    owner.own_wraps.push(wrap.clone());
    owner.validate().unwrap();
    record_runtime::mutate_records(&env, |old| {
        let mut next = old.clone();
        next.local.central = Some(owner.clone());
        Ok(next)
    })
    .unwrap();
    let session = Arc::new(Session {
        profile: owner.control.profile.clone(),
        identity: Some(identity),
        tokens: Arc::new(LoginTokens {
            issuer: profile.issuer,
            subject: profile.subject,
            nonce: Zeroizing::new("synthetic nonce".into()),
            access: Zeroizing::new("synthetic access".into()),
            refresh: None,
            expires_in: std::time::Duration::from_secs(300),
        }),
        device: Some(DeviceSession::synthetic_for_test(
            anchor.account_id.clone(),
            DeviceState::Active,
            3,
            std::time::Duration::from_secs(300),
        )),
        device_access_denied: false,
        tokens_started: std::time::Instant::now(),
    });
    peer.runtime.core.lock().unwrap().central_session = Some(session);
    record_runtime::mutate_records(&first.env(), |state| {
        let mut next = state.clone();
        let owner = next.local.central.as_mut().unwrap();
        owner.control.proof = Some(proof.clone());
        owner.control.highwater = Some(trusted.highwater());
        owner.control.auth_epoch = 3;
        Ok(next)
    })
    .unwrap();
    first.runtime.core.lock().unwrap().central_session = Some(Arc::new(Session {
        profile: first_session.profile.clone(),
        identity: first_session.identity.clone(),
        tokens: Arc::clone(&first_session.tokens),
        device: Some(DeviceSession::synthetic_for_test(
            anchor.account_id.clone(),
            DeviceState::Active,
            3,
            std::time::Duration::from_secs(300),
        )),
        device_access_denied: false,
        tokens_started: std::time::Instant::now(),
    }));
    if legacy {
        let phrase = legacy_phrase.as_ref().unwrap();
        let parent = crate::sync::crypto::derive_account(phrase).unwrap();
        assert!(manifest
            .body
            .sources
            .iter()
            .any(|source| source.chain_id == parent.chain_id));
        peer.keychain
            .set(crate::sync::state::MNEMONIC_ACCOUNT, phrase)
            .unwrap();
        record_runtime::mutate_records(&env, |state| {
            let mut state = state.clone();
            state.account = Some(crate::sync::state_v2::AccountState::new(&parent.chain_id));
            state.relay_url = anchor.origin.clone();
            Ok(state)
        })
        .unwrap();
    }
    Fixture {
        first,
        peer,
        keys,
        proof,
        rows,
        wrap,
        origin: anchor.origin,
        manifest,
    }
}
struct Service {
    server: mockito::ServerGuard,
    rows: Arc<Mutex<Vec<super::super::rekey::Version>>>,
    calls: Arc<std::sync::atomic::AtomicUsize>,
}
fn service(f: &Fixture) -> Service {
    let mut server = mockito::Server::new();
    let rows = Arc::new(Mutex::new(f.rows.clone()));
    let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let owner = record_runtime::snapshot(&f.peer.env())
        .unwrap()
        .0
        .local
        .central
        .unwrap();
    let vault = owner.control.personal_vault.clone().unwrap();
    let proof = f.proof.clone();
    let head = proof
        .verify(owner.control.anchor.as_ref().unwrap(), None)
        .unwrap()
        .current()
        .head()
        .to_string();
    let account = owner.control.account_id.clone();
    server.mock("GET","/v2/account").with_header("content-type","application/json").with_body(json!({"account_id":account,"device_state":"active","auth_epoch":3,"phase":"ready","proof":proof,"genesis_hash":owner.control.anchor.as_ref().unwrap().genesis_hash,"pairing_confirmation":Value::Null,"vaults":{&vault:{"epoch":1,"rekey":false}},"denied":[],"devices":[],"barrier":Value::Null}).to_string()).create();
    let data = rows.clone();
    server.mock("GET",format!("/v2/vaults/{vault}/rekey").as_str()).with_body_from_request(move|_|{let rows=data.lock().unwrap();json!({"phase":"ready","epoch":1,"sequence":rows.len().to_string(),"history_hash":rows.last().map(|r|r.history_hash.clone()).unwrap_or_else(||"0".repeat(64)),"journal":Value::Null,"commits":[]}).to_string().into_bytes()}).create();
    server
        .mock("GET", format!("/v2/vaults/{vault}/wrap").as_str())
        .with_body(serde_json::to_string(&f.wrap).unwrap())
        .create();
    let data = rows.clone();
    let h = head.clone();
    let v = vault.clone();
    server.mock("GET",format!("/v2/vaults/{vault}/metadata").as_str()).with_body_from_request(move|_|{let rows=data.lock().unwrap();json!({"vault":v,"epoch":1,"membership_head":h,"authorization_epoch":"3","phase":"ready","sequence":rows.len().to_string(),"history_hash":rows.last().map(|r|r.history_hash.clone()).unwrap_or_else(||"0".repeat(64))}).to_string().into_bytes()}).create();
    let data = rows.clone();
    let h = head.clone();
    let cost = calls.clone();
    server.mock("GET",format!("/v2/vaults/{vault}/records").as_str()).match_query(mockito::Matcher::Any).with_body_from_request(move|request|{
        cost.fetch_add(1,std::sync::atomic::Ordering::SeqCst);let url=reqwest::Url::parse(&format!("http://127.0.0.1{}",request.path_and_query())).unwrap();let since=url.query_pairs().find(|(k,_)|k=="since").unwrap().1.parse::<usize>().unwrap();
        let rows=data.lock().unwrap();json!({"records":rows.iter().skip(since).take(32).collect::<Vec<_>>(),"sequence":rows.len().to_string(),"history_hash":rows.last().map(|r|r.history_hash.clone()).unwrap_or_else(||"0".repeat(64)),"membership_head":h,"epoch":1,"phase":"ready"}).to_string().into_bytes()
    }).create();
    let data = rows.clone();
    let chain = f
        .proof
        .verify(owner.control.anchor.as_ref().unwrap(), None)
        .unwrap();
    let v = vault.clone();
    server.mock("POST",format!("/v2/vaults/{vault}/records").as_str()).with_body_from_request(move|request|{
        let body:Value=serde_json::from_slice(request.body().unwrap()).unwrap();let incoming:Vec<super::super::crypto::RecordEnvelope>=serde_json::from_value(body["records"].clone()).unwrap();let mut rows=data.lock().unwrap();let mut receipts=vec![];let mut ids=std::collections::BTreeSet::new();
        for envelope in incoming {
            assert!(ids.insert(envelope.header.record_id.clone()));chain.current().verify_write(&envelope,&v,1,&envelope.header.author).unwrap();
            let row=if let Some(prior)=rows.iter().find(|r|r.envelope.header.operation_id==envelope.header.operation_id){assert_eq!(prior.envelope,envelope);prior.clone()}else{
                let revision=rows.iter().rev().find(|r|r.envelope.header.record_id==envelope.header.record_id).map_or(0,|r|number(&r.revision,false).unwrap());assert_eq!(envelope.header.expected_revision,revision.to_string());
                let sequence=rows.len()+1;let digest=super::super::rekey::envelope_digest(&envelope).unwrap();let hash=super::super::crypto::hash(&super::super::wire::canonical(&["lunport-history-v2",&rows.last().map(|r|r.history_hash.clone()).unwrap_or_else(||"0".repeat(64)),&sequence.to_string(),&digest]).unwrap());
                let row=super::super::rekey::Version{revision:(revision+1).to_string(),sequence:sequence.to_string(),envelope,digest,history_hash:hash};rows.push(row.clone());row
            };
            receipts.push(json!({"operation_id":row.envelope.header.operation_id,"record_id":row.envelope.header.record_id,"revision":row.revision,"sequence":row.sequence,"digest":row.digest,"history_hash":row.history_hash}));
        }
        json!({"receipts":receipts,"sequence":rows.len().to_string(),"history_hash":rows.last().map(|r|r.history_hash.clone()).unwrap_or_else(||"0".repeat(64))}).to_string().into_bytes()
    }).create();
    Service {
        server,
        rows,
        calls,
    }
}
#[test]
fn approved_empty_device_reviews_and_materializes_the_existing_managed_library_then_retries_safely()
{
    let f = fixture(false);
    let s = service(&f);
    api::with_test_transport(&f.origin, &s.server.url(), || {
        let env = f.peer.env();
        let scope = Scope::from_state(&record_runtime::snapshot(&env).unwrap().0).unwrap();
        let prepared = migration_flow::prepare(&env, &scope).unwrap();
        assert!(prepared.review.is_some());
        assert!(
            !record_runtime::snapshot(&env)
                .unwrap()
                .0
                .local
                .central
                .unwrap()
                .control
                .cutover
        );
        let ticket = load(&env).unwrap().unwrap().state.ticket;
        migration_flow::confirm(&env, &scope, &ticket).unwrap();
        assert_eq!(
            migration_flow::advance(&env, &scope).unwrap().phase,
            "complete"
        );
        let active = record_runtime::snapshot(&env).unwrap();
        assert!(active.0.local.central.as_ref().unwrap().control.cutover);
        assert!(!active.0.local.keys.is_empty());
        assert_eq!(
            migration_flow::advance(&env, &scope).unwrap().phase,
            "complete"
        );
        assert_eq!(record_runtime::snapshot(&env).unwrap(), active);
        assert_eq!(s.rows.lock().unwrap().len(), f.rows.len());
    });
}
#[test]
fn approved_device_merges_its_managed_key_history_without_overwriting_the_shared_library() {
    let f = fixture(true);
    let s = service(&f);
    api::with_test_transport(&f.origin, &s.server.url(), || {
        let env = f.peer.env();
        let before = record_runtime::snapshot(&env).unwrap().0;
        let local = before
            .local
            .keys
            .values()
            .find(|k| k.public.name == "peer-key")
            .unwrap()
            .public
            .clone();
        let scope = Scope::from_state(&before).unwrap();
        migration_flow::prepare(&env, &scope).unwrap();
        let saved = load(&env).unwrap().unwrap();
        let ticket = saved.state.ticket.clone();
        let remote = saved
            .remote(&env)
            .unwrap()
            .verify(
                saved.owner().unwrap(),
                saved.session.identity.as_ref().unwrap(),
                None,
            )
            .unwrap();
        let plan = saved.plan(&env, &remote).unwrap();
        assert!(!plan.rows.is_empty());
        drop(saved);
        migration_flow::confirm(&env, &scope, &ticket).unwrap();
        let mut complete = false;
        for _ in 0..20 {
            if migration_flow::advance(&env, &scope).unwrap().phase == "complete" {
                complete = true;
                break;
            }
        }
        assert!(complete);
        let active = record_runtime::snapshot(&env).unwrap().0;
        assert!(active
            .local
            .keys
            .values()
            .any(|k| k.public.fingerprint == local.fingerprint));
        assert!(s.rows.lock().unwrap().starts_with(&f.rows));
        assert!(s.rows.lock().unwrap().len() > f.rows.len());
        let vault = crate::vault::store::read_vault(
            &crate::vault::store::vault_path(&env.state_path),
            &f.peer.keychain,
        )
        .unwrap();
        let key = active
            .local
            .keys
            .values()
            .find(|k| k.public.fingerprint == local.fingerprint)
            .unwrap();
        assert_eq!(
            vault.get(&key.vault_id).unwrap().unwrap().private_key,
            crate::sync::slot_rules::test_keys::encrypted()
        );
    });
}
fn prepared(f: &Fixture) -> (Scope, String) {
    let env = f.peer.env();
    let scope = Scope::from_state(&record_runtime::snapshot(&env).unwrap().0).unwrap();
    assert!(migration_flow::prepare(&env, &scope)
        .unwrap()
        .review
        .is_some());
    let ticket = load(&env).unwrap().unwrap().state.ticket;
    (scope, ticket)
}
fn finish(f: &Fixture, scope: &Scope) {
    for _ in 0..30 {
        if migration_flow::advance(&f.peer.env(), scope).unwrap().phase == "complete" {
            return;
        }
    }
    panic!("adoption failed to complete");
}
fn reopen(d: &TestDevice) {
    let session = controller::context(&d.env()).unwrap();
    let probe = record_runtime::probe_startup(&d.env().state_path, "reopened");
    record_runtime::activate_probe(&mut d.runtime.core.lock().unwrap(), probe).unwrap();
    d.runtime.core.lock().unwrap().central_session = Some(session);
}
fn append(
    rows: &mut Vec<super::super::rekey::Version>,
    envelope: super::super::crypto::RecordEnvelope,
) {
    let revision = rows
        .iter()
        .rev()
        .find(|r| r.envelope.header.record_id == envelope.header.record_id)
        .map_or(0, |r| number(&r.revision, false).unwrap())
        + 1;
    let sequence = rows.len() + 1;
    let digest = super::super::rekey::envelope_digest(&envelope).unwrap();
    let history_hash = super::super::crypto::hash(
        &super::super::wire::canonical(&[
            "lunport-history-v2",
            &rows
                .last()
                .map(|r| r.history_hash.clone())
                .unwrap_or_else(|| "0".repeat(64)),
            &sequence.to_string(),
            &digest,
        ])
        .unwrap(),
    );
    rows.push(super::super::rekey::Version {
        revision: revision.to_string(),
        sequence: sequence.to_string(),
        envelope,
        digest,
        history_hash,
    });
}
fn catalog_write(f: &Fixture, rows: &mut Vec<super::super::rekey::Version>, name: &str) {
    use super::super::payload::{Collection, Data, Identity};
    let owner = record_runtime::snapshot(&f.first.env())
        .unwrap()
        .0
        .local
        .central
        .unwrap();
    let session = controller::context(&f.first.env()).unwrap();
    let identity = session.identity.as_ref().unwrap();
    let id = Identity {
        kind: "meta".into(),
        id: "catalog".into(),
        scope: None,
    };
    let record_id = id.opaque(&f.keys).unwrap();
    let revision = rows
        .iter()
        .rev()
        .find(|r| r.envelope.header.record_id == record_id)
        .map_or(0, |r| number(&r.revision, false).unwrap());
    let anchor = owner.control.anchor.as_ref().unwrap();
    let prior = &rows
        .iter()
        .rev()
        .find(|r| r.envelope.header.record_id == record_id)
        .unwrap()
        .envelope;
    let chain = f.proof.verify(anchor, None).unwrap();
    let author = chain
        .author_at(&prior.header.membership_head, &prior.header.author)
        .unwrap();
    let plain = prior
        .verify(&author.signing)
        .unwrap()
        .open(&f.keys)
        .unwrap();
    let mut catalog = match super::super::payload::admit(&f.keys, &prior.header, &plain)
        .unwrap()
        .data
    {
        Data::Catalog(c) => c,
        _ => panic!("missing catalogue"),
    };
    if !name.is_empty() {
        catalog.collections.retain(|c| c.id != "f".repeat(64));
        catalog.collections.push(Collection {
            id: "f".repeat(64),
            name: name.into(),
        });
    }
    let data = Data::Catalog(catalog);
    let row = super::super::crypto::seal_record(
        &f.keys,
        &identity.keys,
        super::super::wire::RecordHeader {
            origin: anchor.origin.clone(),
            account_id: anchor.account_id.clone(),
            genesis_hash: anchor.genesis_hash.clone(),
            vault_id: owner.control.personal_vault.unwrap(),
            record_id,
            key_epoch: "1".into(),
            membership_head: owner.control.highwater.unwrap().head,
            author: identity.id.clone(),
            operation_id: super::super::crypto::random_id(16).unwrap(),
            expected_revision: revision.to_string(),
            kind: "meta".into(),
            deleted: false,
        },
        &super::super::payload::encode(&id, &data).unwrap(),
    )
    .unwrap();
    append(rows, row);
}
#[test]
fn review_and_wrong_scope_or_ticket_cannot_upload_and_source_changes_block_consent() {
    let f = fixture(true);
    let s = service(&f);
    api::with_test_transport(&f.origin, &s.server.url(), || {
        let (scope, ticket) = prepared(&f);
        let env = f.peer.env();
        assert_eq!(
            migration_flow::advance(&env, &scope).unwrap().phase,
            "review"
        );
        assert_eq!(s.rows.lock().unwrap().len(), f.rows.len());
        assert!(migration_flow::confirm(&env, &scope, &"0".repeat(64)).is_err());
        let mut other = serde_json::to_value(&scope).unwrap();
        other["account_id"] = json!("0".repeat(64));
        assert!(
            migration_flow::confirm(&env, &serde_json::from_value(other).unwrap(), &ticket)
                .is_err()
        );
        let unknown = env
            .state_path
            .parent()
            .unwrap()
            .join("sync-state.new-input");
        fs::write(&unknown, b"SYNTHETIC-PRIVATE-SENTINEL").unwrap();
        let error = migration_flow::confirm(&env, &scope, &ticket)
            .err()
            .unwrap()
            .to_string();
        assert!(!error.contains("SYNTHETIC-PRIVATE-SENTINEL"));
        assert!(!load(&env).unwrap().unwrap().state.accepted);
        assert_eq!(s.rows.lock().unwrap().len(), f.rows.len());
        fs::remove_file(unknown).unwrap();
        migration_flow::confirm(&env, &scope, &ticket).unwrap();
        reopen(&f.peer);
        finish(&f, &scope);
    });
}
#[test]
fn staged_and_vault_published_adoptions_resume_after_a_cold_reopen() {
    use crate::sync::record_import::{with_test_step, PublishStep};
    for stop in [PublishStep::VaultStaged, PublishStep::VaultSaved] {
        let f = fixture(false);
        let s = service(&f);
        api::with_test_transport(&f.origin, &s.server.url(), || {
            let (scope, ticket) = prepared(&f);
            migration_flow::confirm(&f.peer.env(), &scope, &ticket).unwrap();
            let stopped = with_test_step(
                move |step| if step == stop { Err(invalid()) } else { Ok(()) },
                || migration_flow::advance(&f.peer.env(), &scope),
            );
            assert!(stopped.is_err());
            assert!(
                !record_runtime::snapshot(&f.peer.env())
                    .unwrap()
                    .0
                    .local
                    .central
                    .unwrap()
                    .control
                    .cutover
            );
            reopen(&f.peer);
            finish(&f, &scope);
            assert_eq!(s.rows.lock().unwrap().len(), f.rows.len());
        });
    }
}
#[test]
fn empty_reserved_stage_is_recovered_but_unknown_contents_are_retained() {
    let f = fixture(false);
    let s = service(&f);
    api::with_test_transport(&f.origin, &s.server.url(), || {
        let (scope, ticket) = prepared(&f);
        migration_flow::confirm(&f.peer.env(), &scope, &ticket).unwrap();
        use crate::sync::record_import::{with_test_step, PublishStep};
        assert!(with_test_step(
            |step| if step == PublishStep::JournalPrepared {
                Err(invalid())
            } else {
                Ok(())
            },
            || migration_flow::advance(&f.peer.env(), &scope)
        )
        .is_err());
        let loaded = load(&f.peer.env()).unwrap().unwrap();
        let op = loaded.state.operation;
        let root = f.peer.env().state_path.parent().unwrap().join("imports");
        let dir = root.join(op);
        fs::remove_file(dir.join("journal.json")).unwrap();
        for p in [&root, &dir] {
            fs::set_permissions(p, fs::Permissions::from_mode(0o700)).unwrap();
        }
        let unknown = dir.join("unrecognized-source");
        fs::write(&unknown, b"SYNTHETIC-RETAINED").unwrap();
        assert!(migration_flow::advance(&f.peer.env(), &scope).is_err());
        assert_eq!(fs::read(&unknown).unwrap(), b"SYNTHETIC-RETAINED");
        fs::remove_file(unknown).unwrap();
        finish(&f, &scope);
    });
}
#[test]
fn a_lost_state_saved_response_preserves_later_active_edits() {
    use crate::sync::record_import::{with_test_step, PublishStep};
    let f = fixture(false);
    let s = service(&f);
    api::with_test_transport(&f.origin, &s.server.url(), || {
        let (scope, ticket) = prepared(&f);
        migration_flow::confirm(&f.peer.env(), &scope, &ticket).unwrap();
        assert!(with_test_step(
            |step| if step == PublishStep::StateSaved {
                Err(invalid())
            } else {
                Ok(())
            },
            || migration_flow::advance(&f.peer.env(), &scope)
        )
        .is_err());
        let env = f.peer.env();
        assert!(
            record_runtime::snapshot(&env)
                .unwrap()
                .0
                .local
                .central
                .unwrap()
                .control
                .cutover
        );
        record_runtime::mutate_records(&env, |state| {
            let mut next = state.clone();
            next.device_name = "later active device edit".into();
            Ok(next)
        })
        .unwrap();
        let later = record_runtime::snapshot(&env).unwrap().0;
        let vault = fs::read(crate::vault::store::vault_path(&env.state_path)).unwrap();
        reopen(&f.peer);
        finish(&f, &scope);
        assert_eq!(record_runtime::snapshot(&env).unwrap().0, later);
        assert_eq!(
            fs::read(crate::vault::store::vault_path(&env.state_path)).unwrap(),
            vault
        );
    });
}
#[test]
fn a_concurrent_foreign_catalog_edit_is_kept_by_the_reviewed_additive_merge() {
    let f = fixture(true);
    let s = service(&f);
    api::with_test_transport(&f.origin, &s.server.url(), || {
        let (scope, ticket) = prepared(&f);
        catalog_write(&f, &mut s.rows.lock().unwrap(), "A concurrent collection");
        migration_flow::confirm(&f.peer.env(), &scope, &ticket).unwrap();
        finish(&f, &scope);
        let state = record_runtime::snapshot(&f.peer.env()).unwrap().0;
        assert!(state.spaces.contains_key(&"f".repeat(64)));
        let projected = super::super::projection::Plan::current(
            state.local.central.as_ref().unwrap().clone(),
            &f.keys,
        )
        .unwrap();
        assert!(projected.rows().values().any(|r|matches!(&r.data,super::super::projection::PublicData::Catalog(c) if c.collections.iter().any(|v|v.id=="f".repeat(64)&&v.name=="A concurrent collection"))));
        assert!(state
            .local
            .keys
            .values()
            .any(|k| k.public.name == "peer-key"));
        assert!(s.rows.lock().unwrap().starts_with(&f.rows));
    });
}
#[test]
fn large_history_is_bounded_and_continues_without_an_archive_for_every_page() {
    let f = fixture(false);
    let s = service(&f);
    {
        let mut rows = s.rows.lock().unwrap();
        for _ in 0..920 {
            catalog_write(&f, &mut rows, "");
        }
    }
    api::with_test_transport(&f.origin, &s.server.url(), || {
        let env = f.peer.env();
        let scope = Scope::from_state(&record_runtime::snapshot(&env).unwrap().0).unwrap();
        let first = migration_flow::prepare(&env, &scope).unwrap();
        assert!(first.review.is_none());
        assert!(f.peer.runtime.core.lock().unwrap().central_poll.requests <= 32);
        let directory = env
            .state_path
            .parent()
            .unwrap()
            .join("central-source-archives");
        let entries = fs::read_dir(&directory).unwrap().count();
        f.peer.runtime.core.lock().unwrap().adoption_read = None;
        let mut review = None;
        for _ in 0..4 {
            let next = migration_flow::prepare(&env, &scope).unwrap();
            if next.review.is_some() {
                review = next.review;
                break;
            }
        }
        assert!(review.is_some());
        assert_eq!(fs::read_dir(directory).unwrap().count(), entries + 2); // Two immutable frames share the original operation marker.
        assert!(s.calls.load(std::sync::atomic::Ordering::SeqCst) > 32);
    });
}
fn add_host(d: &TestDevice, id: &str, alias: &str) {
    let payload:crate::sync::records_v3::HostPayload=serde_json::from_value(json!({"schema":2,"alias":alias,"hostname":"synthetic.invalid","user":"fixture","port":22,"auth":"password"})).unwrap();
    crate::sync::record_commands::edit_records(&d.env(), |state, now| {
        crate::sync::record_repository::create_host(
            state,
            id,
            crate::sync::records_v3::HostScope::Local,
            payload.clone(),
            now,
        )
        .map_err(|_| invalid())
    })
    .unwrap();
}
#[test]
fn both_devices_use_ordinary_rounds_for_later_edits_and_received_managed_material() {
    let f = fixture(false);
    let s = service(&f);
    api::with_test_transport(&f.origin, &s.server.url(), || {
        let (scope, ticket) = prepared(&f);
        migration_flow::confirm(&f.peer.env(), &scope, &ticket).unwrap();
        finish(&f, &scope);
        add_host(&f.first, &"1".repeat(16), "from-first");
        super::super::round::sync_once(&f.first.env()).unwrap();
        super::super::round::sync_once(&f.peer.env()).unwrap();
        assert!(record_runtime::snapshot(&f.peer.env())
            .unwrap()
            .0
            .local
            .hosts
            .values()
            .any(|h| h.record.payload["alias"] == "from-first"));
        add_host(&f.peer, &"2".repeat(16), "from-peer");
        super::super::round::sync_once(&f.peer.env()).unwrap();
        super::super::round::sync_once(&f.first.env()).unwrap();
        assert!(record_runtime::snapshot(&f.first.env())
            .unwrap()
            .0
            .local
            .hosts
            .values()
            .any(|h| h.record.payload["alias"] == "from-peer"));
        let (state, generation) = record_runtime::snapshot(&f.peer.env()).unwrap();
        let invocation = crate::sync::record_import::central_local::invocation(&state)
            .unwrap()
            .with_generation(generation);
        let receipt = crate::sync::record_keys::import_local_scoped(
            &f.peer.env(),
            "later-key",
            Zeroizing::new(crate::sync::slot_rules::test_keys::plain()),
            crate::vault::store::EntryOrigin::Imported,
            Some(&invocation),
        )
        .unwrap();
        super::super::round::sync_once(&f.peer.env()).unwrap();
        super::super::round::sync_once(&f.first.env()).unwrap();
        let received = record_runtime::snapshot(&f.first.env())
            .unwrap()
            .0
            .local
            .keys[&receipt.key_id]
            .clone();
        let vault = crate::vault::store::read_vault(
            &crate::vault::store::vault_path(&f.first.env().state_path),
            &f.first.keychain,
        )
        .unwrap();
        assert_eq!(
            vault.get(&received.vault_id).unwrap().unwrap().private_key,
            crate::sync::slot_rules::test_keys::plain()
        );
    });
}
#[test]
fn corrupt_ciphertext_cannot_activate_or_become_a_saved_verified_read() {
    let f = fixture(false);
    let s = service(&f);
    s.rows.lock().unwrap()[0].digest = "0".repeat(64);
    api::with_test_transport(&f.origin, &s.server.url(), || {
        let env = f.peer.env();
        let scope = Scope::from_state(&record_runtime::snapshot(&env).unwrap().0).unwrap();
        assert!(migration_flow::prepare(&env, &scope).is_err());
        let loaded = load(&env).unwrap().unwrap();
        assert!(loaded.state.remote.is_none());
        assert!(!loaded.state.accepted);
        assert!(
            !record_runtime::snapshot(&env)
                .unwrap()
                .0
                .local
                .central
                .unwrap()
                .control
                .cutover
        );
        assert!(!crate::vault::store::vault_path(&env.state_path).exists());
        *s.rows.lock().unwrap() = f.rows[..f.rows.len() - 1].to_vec();
        assert!(migration_flow::prepare(&env, &scope).is_err()); // Below the approved out-of-band minimum.
        *s.rows.lock().unwrap() = f.rows.clone();
        let repaired = migration_flow::prepare(&env, &scope).unwrap();
        assert!(repaired.review.is_some());
    });
}
#[test]
fn an_enrolled_peer_can_adopt_a_later_epoch_only_with_the_verified_original_source_extension() {
    use super::super::{
        active_read::Snapshot,
        recovery_read::{EpochBundle, HistoryPage, RecoveryVault},
        recovery_revalidation::Bridge,
    };
    for legacy in [false, true] {
        let f = fixture_legacy(false, false, legacy);
        let env = f.peer.env();
        let source = record_runtime::snapshot(&env).unwrap().0;
        let owner = source.local.central.as_ref().unwrap();
        let first = controller::context(&f.first.env()).unwrap();
        let identity = first.identity.as_ref().unwrap();
        let chain = f
            .proof
            .verify(owner.control.anchor.as_ref().unwrap(), None)
            .unwrap();
        let zero = Checkpoint {
            epoch: 1,
            sequence: 0,
            history_hash: "0".repeat(64),
        };
        let checkpoint = Checkpoint {
            epoch: 1,
            sequence: f.rows.len() as u64,
            history_hash: f
                .rows
                .last()
                .map(|r| r.history_hash.clone())
                .unwrap_or_else(|| "0".repeat(64))
                .clone(),
        };
        let plan = super::super::rekey::prepare(
            &chain,
            &identity.id,
            &identity.keys,
            owner.control.personal_vault.as_ref().unwrap(),
            3,
            &f.keys,
            &checkpoint,
            &zero,
            &f.rows,
        )
        .unwrap();
        let peer = controller::context(&env).unwrap();
        let peer_identity = peer.identity.as_ref().unwrap();
        let wrap = plan
            .wraps
            .iter()
            .find(|w| w.header.recipient == peer_identity.id)
            .unwrap()
            .clone();
        let snapshot = Snapshot {
            membership_head: chain.current().head().into(),
            auth_epoch: 3,
            vault: RecoveryVault {
                vault: owner.control.personal_vault.clone().unwrap(),
                epoch: 2,
                phase: "ready".into(),
                wrap,
                committed: Some(EpochBundle {
                    manifest: plan.manifest.clone(),
                    wraps: plan.wraps.clone(),
                }),
                commits: vec![plan.manifest.clone()],
                sequence: plan.rows.len().to_string(),
                history_hash: plan
                    .rows
                    .last()
                    .map(|r| r.history_hash.clone())
                    .unwrap_or_else(|| "0".repeat(64))
                    .clone(),
            },
        };
        let page = HistoryPage {
            records: plan.rows,
            sequence: snapshot.vault.sequence.clone(),
            history_hash: snapshot.vault.history_hash.clone(),
            membership_head: snapshot.membership_head.clone(),
            epoch: 2,
            phase: "ready".into(),
        };
        let transcript = Transcript {
            snapshot,
            proof: f.proof.clone(),
            bridges: vec![Bridge {
                epoch: 2,
                digests: f
                    .rows
                    .iter()
                    .map(|r| super::super::rekey::SourceDigest {
                        sequence: r.sequence.clone(),
                        digest: r.digest.clone(),
                    })
                    .collect(),
            }],
            pages: vec![page],
        };
        let read = transcript.verify(owner, peer_identity, None).unwrap();
        assert!(read.epoch_acceptance().is_some());
        // Check every independently retained hash, including lower forks under a valid stronger floor.
        Package::require_historical_prefixes(
            &read,
            &transcript,
            std::slice::from_ref(&checkpoint),
            &[],
        )
        .unwrap();
        let earlier = &f.rows[0];
        let fork = Checkpoint {
            epoch: 1,
            sequence: earlier.sequence.parse().unwrap(),
            history_hash: "f".repeat(64),
        };
        assert!(Package::require_historical_prefixes(
            &read,
            &transcript,
            &[checkpoint.clone(), fork],
            &[]
        )
        .is_err());
        let control = captured::ControlMinimum {
            highwater: read.chain().highwater(),
            auth_epoch: read.auth_epoch(),
        };
        Package::require_historical_prefixes(
            &read,
            &transcript,
            &[],
            std::slice::from_ref(&control),
        )
        .unwrap();
        let mut wrong = control.clone();
        wrong.highwater.head = "f".repeat(64);
        assert!(Package::require_historical_prefixes(
            &read,
            &transcript,
            &[],
            &[control.clone(), wrong]
        )
        .is_err());
        let mut later = control;
        later.auth_epoch += 1;
        assert!(
            Package::require_historical_prefixes(&read, &transcript, &[], &[later]).is_err()
        );

        if legacy {
            let evidence: legacy::Evidence = serde_json::from_value(
                json!({"version":1,"proof":f.proof,"status":retired_status(&f)}),
            )
            .unwrap();
            evidence.require_read(&read, &transcript).unwrap();
            let mut manifest = f.manifest.clone();
            manifest.body.target_history_hash = "f".repeat(64);
            manifest =
                super::super::migration::SignedMigration::sign(manifest.body, &identity.keys)
                    .unwrap();
            let mut status = retired_status(&f);
            status["manifest"] = serde_json::to_value(&manifest).unwrap();
            status["manifest_digest"] = manifest.digest().unwrap().into();
            status["history_hash"] = "f".repeat(64).into();
            let forged: legacy::Evidence =
                serde_json::from_value(json!({"version":1,"proof":f.proof,"status":status}))
                    .unwrap();
            assert!(forged.require_read(&read, &transcript).is_err());
        }
        let candidate =
            Candidate::adopt(&source, &read, &"c".repeat(64), env.now(), &BTreeMap::new())
                .unwrap();
        assert!(!candidate.delta().required_material().is_empty());
        candidate
            .shadow()
            .local
            .central
            .as_ref()
            .unwrap()
            .validate()
            .unwrap();
        let mut forged = transcript;
        forged.bridges.clear();
        assert!(forged.verify(owner, peer_identity, None).is_err());
    }
}
struct StateWriteFault<'a> {
    inner: &'a crate::sync::testkit::MemKeychain,
    role: String,
    field: &'static str,
    after: bool,
    armed: std::sync::atomic::AtomicBool,
}
impl Keychain for StateWriteFault<'_> {
    fn get_noninteractive(&self, role: &str) -> Result<Option<String>, AppError> {
        self.inner.get_noninteractive(role)
    }
    fn set_noninteractive(&self, role: &str, value: &str) -> Result<(), AppError> {
        self.set(role, value)
    }
    fn get(&self, role: &str) -> Result<Option<String>, AppError> {
        self.inner.get(role)
    }
    fn set(&self, role: &str, value: &str) -> Result<(), AppError> {
        let fail = role == self.role
            && serde_json::from_str::<Value>(value).is_ok_and(|v| v[self.field].is_object())
            && self.armed.swap(false, std::sync::atomic::Ordering::SeqCst);
        if fail && !self.after {
            return Err(invalid());
        }
        self.inner.set(role, value)?;
        if fail {
            return Err(invalid());
        }
        Ok(())
    }
    fn delete(&self, role: &str) -> Result<(), AppError> {
        self.inner.delete(role)
    }
}
fn archive_bytes(env: &SyncEnv) -> BTreeMap<std::ffi::OsString, Vec<u8>> {
    fs::read_dir(
        env.state_path
            .parent()
            .unwrap()
            .join("central-source-archives"),
    )
    .unwrap()
    .map(|e| {
        let e = e.unwrap();
        (e.file_name(), fs::read(e.path()).unwrap())
    })
    .collect()
}
#[test]
fn archive_attachment_uncertainty_recovers_the_same_remote_plan_and_final_ciphertext() {
    for field in ["legacy", "remote", "plan", "final_read"] {
        for after in [false, true] {
            let f = fixture_legacy(false, false, field == "legacy");
            let mut s = service(&f);
            let _retirement =
                (field == "legacy").then(|| migration_status_mock(&mut s, &f, retired_status(&f)));
            api::with_test_transport(&f.origin, &s.server.url(), || {
                let owner = record_runtime::snapshot(&f.peer.env())
                    .unwrap()
                    .0
                    .local
                    .central
                    .unwrap();
                let fault = StateWriteFault {
                    inner: &f.peer.keychain,
                    role: role(&owner).unwrap(),
                    field,
                    after,
                    armed: std::sync::atomic::AtomicBool::new(true),
                };
                let mut env = f.peer.env();
                env.keychain = &fault;
                let scope = Scope::from_state(&record_runtime::snapshot(&env).unwrap().0).unwrap();
                if field == "final_read" {
                    let prepared = migration_flow::prepare(&env, &scope).unwrap();
                    assert!(prepared.review.is_some());
                    let ticket = load(&env).unwrap().unwrap().state.ticket;
                    migration_flow::confirm(&env, &scope, &ticket).unwrap();
                    assert!(migration_flow::advance(&env, &scope).is_err());
                } else {
                    assert!(migration_flow::prepare(&env, &scope).is_err());
                }
                assert!(!fault.armed.load(std::sync::atomic::Ordering::SeqCst));
                let captured = archive_bytes(&env);
                reopen(&f.peer);
                if field != "final_read" {
                    let (scope, ticket) = prepared(&f);
                    migration_flow::confirm(&f.peer.env(), &scope, &ticket).unwrap();
                    finish(&f, &scope);
                } else {
                    finish(&f, &scope);
                }
                let latest = archive_bytes(&f.peer.env());
                for (path, bytes) in captured {
                    assert_eq!(latest.get(&path), Some(&bytes));
                }
                assert_eq!(s.rows.lock().unwrap().len(), f.rows.len());
            });
        }
    }
}

#[test]
fn catalog_rebase_after_partial_acceptance_keeps_all_previously_sent_ciphertext() {
    let f = fixture(true);
    let s = service(&f);
    api::with_test_transport(&f.origin, &s.server.url(), || {
        let (scope, ticket) = prepared(&f);
        migration_flow::confirm(&f.peer.env(), &scope, &ticket).unwrap();
        assert_eq!(
            migration_flow::advance(&f.peer.env(), &scope)
                .unwrap()
                .phase,
            "staging"
        );
        let sent = s.rows.lock().unwrap().clone();
        assert!(sent.len() > f.rows.len());
        catalog_write(
            &f,
            &mut s.rows.lock().unwrap(),
            "Concurrent later collection",
        );
        finish(&f, &scope);
        assert!(s.rows.lock().unwrap().starts_with(&sent));
        let state = record_runtime::snapshot(&f.peer.env()).unwrap().0;
        assert!(state.spaces.contains_key(&"f".repeat(64)));
        let host = state
            .spaces
            .values()
            .flat_map(|s| s.records.values())
            .find(|h| h.record.payload["alias"] == "peer-local-host")
            .unwrap();
        let key = host.record.payload["key_id"].as_str().unwrap();
        assert_eq!(state.local.keys[key].public.name, "peer-key");
    });
}
#[test]
fn approved_peer_waits_without_capturing_local_data_until_the_first_library_is_published() {
    let f = fixture_at(false, true);
    let s = service(&f);
    s.rows.lock().unwrap().clear();
    api::with_test_transport(&f.origin, &s.server.url(), || {
        let env = f.peer.env();
        let scope = Scope::from_state(&record_runtime::snapshot(&env).unwrap().0).unwrap();
        let waiting = migration_flow::prepare(&env, &scope).unwrap();
        assert_eq!(waiting.progress.phase, "waiting");
        assert!(waiting.review.is_none());
        assert!(load(&env).unwrap().is_none());
        assert!(!env
            .state_path
            .parent()
            .unwrap()
            .join("central-source-archives")
            .exists());
        add_host(&f.peer, &"3".repeat(16), "added-while-waiting");
        *s.rows.lock().unwrap() = f.rows.clone();
        let (scope, ticket) = prepared(&f);
        migration_flow::confirm(&env, &scope, &ticket).unwrap();
        finish(&f, &scope);
        let state = record_runtime::snapshot(&env).unwrap().0;
        assert!(state
            .spaces
            .values()
            .flat_map(|s| s.records.values())
            .any(|r| r.record.payload["alias"] == "added-while-waiting"));
    });
}

fn retired_status(f: &Fixture) -> Value {
    json!({"manifest": f.manifest, "manifest_digest": f.manifest.digest().unwrap(), "phase":"retired", "staged": f.manifest.body.target_sequence, "history_hash": f.manifest.body.target_history_hash, "retired": f.manifest.body.sources.len().to_string()})
}
fn migration_status_mock(s: &mut Service, f: &Fixture, status: Value) -> mockito::Mock {
    let vault = &f.manifest.body.vault_id;
    s.server
        .mock("GET", format!("/v2/vaults/{vault}/migration").as_str())
        .with_body(status.to_string())
        .create()
}
#[test]
fn retired_legacy_source_peer_preserves_local_edits_and_originals_across_review_and_cold_reentry() {
    use crate::sync::record::{record_key, LocalRecord, Record, RecordKind};
    let f = fixture_legacy(true, false, true);
    let parent = f.manifest.body.sources[0].chain_id.clone();
    // This retained/local draft has never reached the frozen parent snapshot.
    // Additive joining must preserve it without treating it as a remote update.
    record_runtime::mutate_records(&f.peer.env(), |state| {
        let mut state = state.clone();
        // Local hosts and managed material were already created by the fixture.
        state.account.as_mut().unwrap().records.insert(
            record_key(RecordKind::Meta, crate::sync::record::ACCOUNT_META_ID),
            LocalRecord {
                record: Record {
                    kind: RecordKind::Meta,
                    id: crate::sync::record::ACCOUNT_META_ID.into(),
                    version: 1,
                    updated_at_ms: 1,
                    device_id: state.device_id.clone(),
                    deleted: false,
                    payload: json!({"schema_version":3,"created_by_app_version":"synthetic"}),
                },
                seq: 0,
                dirty: true,
            },
        );
        Ok(state)
    })
    .unwrap();
    let mut s = service(&f);
    let status = migration_status_mock(&mut s, &f, retired_status(&f));
    let before = record_runtime::snapshot(&f.peer.env()).unwrap().0;
    api::with_test_transport(&f.origin, &s.server.url(), || {
        let (scope, ticket) = prepared(&f);
        assert_eq!(s.rows.lock().unwrap().as_slice(), f.rows.as_slice());
        let archives = archive_bytes(&f.peer.env());
        let loaded = load(&f.peer.env()).unwrap().unwrap();
        assert!(loaded.state.legacy.is_some());
        assert!(loaded.legacy_evidence(&f.peer.env()).unwrap().is_some());
        drop(loaded);
        reopen(&f.peer);
        migration_flow::confirm(&f.peer.env(), &scope, &ticket).unwrap();
        finish(&f, &scope);
        let active = record_runtime::snapshot(&f.peer.env()).unwrap().0;
        assert!(active.local.central.as_ref().unwrap().control.cutover);
        assert_ne!(active.account.as_ref().unwrap().chain_id, parent);
        let local_key = before
            .local
            .keys
            .values()
            .find(|key| key.public.name == "peer-key")
            .unwrap();
        assert!(active
            .local
            .keys
            .values()
            .any(|key| key.public.fingerprint == local_key.public.fingerprint));
        assert!(active
            .spaces
            .values()
            .flat_map(|space| space.records.values())
            .any(|host| host.record.payload["alias"] == "peer-local-host"));
        let latest = archive_bytes(&f.peer.env());
        for (path, bytes) in archives {
            assert_eq!(latest.get(&path), Some(&bytes));
        }
        assert!(s.rows.lock().unwrap().starts_with(&f.rows));
        assert_eq!(before.account.as_ref().unwrap().chain_id, parent);
    });
    status.assert();
}
#[test]
fn incomplete_retirement_wrong_source_or_missing_original_target_blocks_before_local_capture() {
    for case in [
        "phase",
        "retired",
        "signature",
        "source",
        "floor",
        "origin",
        "target",
    ] {
        let f = fixture_legacy(false, false, true);
        let mut s = service(&f);
        let mut status = retired_status(&f);
        match case {
            "phase" => status["phase"] = "committed".into(),
            "retired" => status["retired"] = "0".into(),
            "signature" => status["manifest"]["signature"] = "AAAA".into(),
            "source" => {
                let session = controller::context(&f.first.env()).unwrap();
                let mut manifest = f.manifest.clone();
                manifest.body.sources[0].chain_id = "f".repeat(64);
                let manifest = super::super::migration::SignedMigration::sign(
                    manifest.body,
                    &session.identity.as_ref().unwrap().keys,
                )
                .unwrap();
                status["manifest_digest"] = manifest.digest().unwrap().into();
                status["manifest"] = serde_json::to_value(manifest).unwrap();
            }
            "origin" => {
                record_runtime::mutate_records(&f.peer.env(), |state| {
                    let mut state = state.clone();
                    state.relay_url = "https://other.invalid".into();
                    Ok(state)
                })
                .unwrap();
            }
            "floor" => {
                record_runtime::mutate_records(&f.peer.env(), |state| {
                    let mut state = state.clone();
                    state.account.as_mut().unwrap().cursor_seq = 2;
                    Ok(state)
                })
                .unwrap();
            }
            _ => {
                s.rows.lock().unwrap().clear();
            }
        }
        let _m = migration_status_mock(&mut s, &f, status);
        let before = record_runtime::snapshot(&f.peer.env()).unwrap().0;
        let env = f.peer.env();
        let scope = Scope::from_state(&before).unwrap();
        api::with_test_transport(&f.origin, &s.server.url(), || {
            if case == "target" {
                assert_eq!(
                    migration_flow::prepare(&env, &scope)
                        .unwrap()
                        .progress
                        .phase,
                    "waiting"
                );
            } else {
                assert!(migration_flow::prepare(&env, &scope).is_err(), "{case}");
            }
            assert!(load(&env).unwrap().is_none());
            assert_eq!(record_runtime::snapshot(&env).unwrap().0, before);
        });
    }
}

fn captured_frames(device: &TestDevice) -> Vec<(Receipt, Zeroizing<Vec<u8>>)> {
    let files = super::super::migration_files::Files::capture(&device.env(), None).unwrap();
    super::super::source_archive::captured::read_all(&files.bytes, &device.keychain)
        .unwrap()
        .frames
}
#[test]
fn captured_adoption_plan_is_verified_without_network_calls_consent_or_publication() {
    let f = fixture(true);
    let service = service(&f);
    api::with_test_transport(&f.origin, &service.server.url(), || {
        let _ = prepared(&f);
        let saved = load(&f.peer.env()).unwrap().unwrap();
        let source = saved.state.source.receipt();
        let identity = saved.session.identity.as_ref().unwrap();
        let frames = captured_frames(&f.peer);
        let before = record_runtime::snapshot(&f.peer.env()).unwrap();
        let files = archive_bytes(&f.peer.env());
        let calls = service.calls.load(std::sync::atomic::Ordering::SeqCst);
        let captured = captured::read_group(source, &frames, identity).unwrap();
        assert_eq!(captured.package.state, saved.package.state);
        assert!(captured
            .history
            .into_rows()
            .iter()
            .any(|(_, data)| matches!(data, super::super::payload::Data::Key(_))));
        assert!(captured
            .floors
            .iter()
            .any(|floor| floor.sequence == f.rows.len() as u64));
        assert_eq!(captured.admitted.len(), 3);
        let mut duplicate: Vec<_> = frames
            .iter()
            .map(|(r, b)| (r.clone(), Zeroizing::new(b.to_vec())))
            .collect();
        let repeated = duplicate
            .iter()
            .find(|(_, b)| b.starts_with(b"LPADOPT1"))
            .unwrap();
        duplicate.push((repeated.0.clone(), Zeroizing::new(repeated.1.to_vec())));
        assert!(captured::read_group(source, &duplicate, identity).is_err());
        let mut gap: Vec<_> = frames
            .iter()
            .map(|(r, b)| (r.clone(), Zeroizing::new(b.to_vec())))
            .collect();
        let first = gap
            .iter()
            .enumerate()
            .filter(|(_, (_, b))| b.starts_with(b"LPADOPT1"))
            .min_by_key(|(_, (r, _))| r.next_ordinal().unwrap())
            .unwrap()
            .0;
        gap.remove(first);
        assert!(captured::read_group(source, &gap, identity).is_err());

        let wrong = controller::context(&f.first.env()).unwrap();
        assert!(
            captured::read_group(source, &frames, wrong.identity.as_ref().unwrap()).is_err()
        );
        assert_eq!(record_runtime::snapshot(&f.peer.env()).unwrap(), before);
        assert_eq!(archive_bytes(&f.peer.env()), files);
        assert_eq!(
            service.calls.load(std::sync::atomic::Ordering::SeqCst),
            calls
        );
        assert!(!saved.state.accepted);
    });
}
#[test]
fn captured_adoption_rebase_and_final_read_retain_all_versions_and_stronger_checkpoints() {
    let f = fixture(true);
    let service = service(&f);
    api::with_test_transport(&f.origin, &service.server.url(), || {
        let (scope, ticket) = prepared(&f);
        let saved = load(&f.peer.env()).unwrap().unwrap();
        let source = saved.state.source.receipt().clone();
        let identity = Arc::clone(saved.session.identity.as_ref().unwrap());
        migration_flow::confirm(&f.peer.env(), &scope, &ticket).unwrap();
        assert_eq!(
            migration_flow::advance(&f.peer.env(), &scope)
                .unwrap()
                .phase,
            "staging"
        );
        catalog_write(
            &f,
            &mut service.rows.lock().unwrap(),
            "Captured concurrent collection",
        );
        finish(&f, &scope);
        let frames = captured_frames(&f.peer);
        let before = record_runtime::snapshot(&f.peer.env()).unwrap();
        let files = archive_bytes(&f.peer.env());
        let calls = service.calls.load(std::sync::atomic::Ordering::SeqCst);
        let captured = captured::read_group(&source, &frames, &identity).unwrap();
        assert!(captured
            .floors
            .iter()
            .any(|floor| floor.sequence == service.rows.lock().unwrap().len() as u64));
        let history = captured.history.into_rows();
        assert!(history
            .iter()
            .any(|(_, data)| matches!(data, super::super::payload::Data::Key(_))));
        assert!(history.iter().any(|(_,data)|matches!(data,super::super::payload::Data::Catalog(c) if c.collections.iter().any(|c|c.name=="Captured concurrent collection"))));
        assert_eq!(record_runtime::snapshot(&f.peer.env()).unwrap(), before);
        assert_eq!(archive_bytes(&f.peer.env()), files);
        assert_eq!(
            service.calls.load(std::sync::atomic::Ordering::SeqCst),
            calls
        );
    });
}

fn historical_inputs(f: &Fixture, base: &Package) -> Package {
    use super::super::{
        inventory_keys::Capture, migration_files::Files, migration_materials::Materials,
        migration_sources::Sources,
    };
    let env = f.peer.env();
    let files = Files::capture(&env, None).unwrap();
    let observer = Capture::new(&f.peer.keychain);
    drop(
        Materials::from_files(&base.state, &f.keys, &files, &observer, &BTreeMap::new())
            .unwrap(),
    );
    drop(source_archive::captured::read_all(&files.bytes, &observer).unwrap());
    Package::assemble(
        &base.state,
        env.state_path.file_name().unwrap().to_str().unwrap(),
        files,
        Sources::decode_local(&base.sources.encode_local().unwrap(), &base.state).unwrap(),
        observer.finish().unwrap(),
    )
    .unwrap()
}
#[test]
fn signed_historical_snapshot_restores_without_old_device_identity_and_binds_every_original_input(
) {
    use super::super::{
        inventory_keys::Capture, migration_files::Files, migration_materials::Materials,
        migration_sources::Sources,
    };
    let f = fixture(true);
    let s = service(&f);
    api::with_test_transport(&f.origin, &s.server.url(), || {
        let (_scope, _ticket) = prepared(&f);
        let loaded = load(&f.peer.env()).unwrap().unwrap();
        let owner = loaded.owner().unwrap().clone();
        let files = Files::capture(&f.peer.env(), None).unwrap();
        let observer = Capture::new(&f.peer.keychain);
        drop(
            Materials::from_files(
                &loaded.package.state,
                &f.keys,
                &files,
                &observer,
                &BTreeMap::new(),
            )
            .unwrap(),
        );
        drop(source_archive::captured::read_all(&files.bytes, &observer).unwrap());
        let mut package = Package::assemble(
            &loaded.package.state,
            f.peer
                .env()
                .state_path
                .file_name()
                .unwrap()
                .to_str()
                .unwrap(),
            files,
            Sources::decode_local(
                &loaded.package.sources.encode_local().unwrap(),
                &loaded.package.state,
            )
            .unwrap(),
            observer.finish().unwrap(),
        )
        .unwrap();
        assert!(package
            .structured_history(&f.keys, &BTreeMap::new())
            .is_err());
        let identity = loaded.session.identity.as_ref().unwrap();
        let calls = s.calls.load(std::sync::atomic::Ordering::SeqCst);
        let originals = archive_bytes(&f.peer.env());
        package
            .capture_historical_snapshots(
                identity,
                &|before| {
                    DeviceIdentity::load_selected(
                        &f.peer.keychain,
                        &before.control.profile.profile()?,
                        before.identity_slot.as_deref(),
                        false,
                    )
                },
                &f.keys,
                &BTreeMap::new(),
            )
            .unwrap();
        let floors = package.historical_floors().unwrap();
        assert!(floors.iter().any(|p| p.sequence == f.rows.len() as u64));
        let bytes = package.encode_local().unwrap();
        assert_eq!(&bytes[..8], b"LPSRCPK3");
        let archived = {
            let env = f.peer.env();
            let life = env.runtime.lifecycle.lock().unwrap();
            package.archive(&env, &life, &owner, 20).unwrap()
        };
        let older_operation = archived.receipt().operation().to_owned();
        let mut outer = historical_inputs(&f, &package);
        // The already signed nested capsule supplies this proof; no old identity lookup is needed.
        outer
            .capture_historical_snapshots(
                identity,
                &|_| Err(invalid()),
                &f.keys,
                &BTreeMap::new(),
            )
            .unwrap();
        let bytes = outer.encode_local().unwrap();
        let archived = {
            let env = f.peer.env();
            let life = env.runtime.lifecycle.lock().unwrap();
            outer.archive(&env, &life, &owner, 21).unwrap()
        };
        drop(outer);
        f.peer
            .keychain
            .delete(
                &owner
                    .control
                    .profile
                    .profile()
                    .unwrap()
                    .slot(&format!("source-archive-{older_operation}")),
            )
            .unwrap();
        let receipt_json = serde_json::to_string(archived.receipt()).unwrap();
        assert!(!receipt_json.contains("PRIVATE KEY"));
        // The older operation key also disappears; the new capsule contains its captured decryptor.
        f.peer
            .keychain
            .delete(&owner.control.profile.profile().unwrap().slot(&format!(
                "source-archive-{}",
                loaded.state.source.receipt().operation()
            )))
            .unwrap();

        let profile = owner.control.profile.profile().unwrap();
        let role = identity.slot(&profile, "device").unwrap();
        f.peer.keychain.delete(&role).unwrap();
        assert!(DeviceIdentity::load_selected(
            &f.peer.keychain,
            &profile,
            owner.identity_slot.as_deref(),
            false
        )
        .is_err());
        drop(package);
        let mut restored =
            Package::restore(&f.peer.env(), &profile, archived.receipt()).unwrap();
        let later_keys = f.keys.next_epoch().unwrap();
        let rows = restored
            .structured_history(&later_keys, &BTreeMap::new())
            .unwrap()
            .into_rows();
        assert!(rows
            .iter()
            .any(|(_, data)| matches!(data, super::super::payload::Data::Key(_))));
        assert_eq!(restored.historical_floors().unwrap(), floors);
        restored
            .capture_historical_snapshots(
                identity,
                &|_| Err(invalid()),
                &later_keys,
                &BTreeMap::new(),
            )
            .unwrap();

        assert_eq!(
            restored.encode_local().unwrap().as_slice(),
            bytes.as_slice()
        );
        assert_eq!(s.calls.load(std::sync::atomic::Ordering::SeqCst), calls);
        let latest = archive_bytes(&f.peer.env());
        for (path, bytes) in originals {
            assert_eq!(latest.get(&path), Some(&bytes));
        }
        // Any change to the snapshot, selected public state or original retained bytes fails closed.
        let mut changed = bytes.to_vec();
        let last = changed.len() - 1;
        changed[last] ^= 1;
        assert!(Package::decode_local(&changed).is_err());
        let mut changed = Package::decode_local(&bytes).unwrap();
        let path = changed
            .files
            .bytes
            .keys()
            .find(|p| p.extension().is_some_and(|e| e == "lpsource"))
            .unwrap()
            .clone();
        changed.files.bytes.get_mut(&path).unwrap()[0] ^= 1;
        assert!(changed.encode_local().is_err());
        assert!(!loaded.state.accepted);
    });
}

#[test]
fn signed_historical_floor_blocks_a_valid_older_read_before_merge_or_publication() {
    use super::super::{
        inventory_keys::Capture, migration_files::Files, migration_materials::Materials,
        migration_sources::Sources,
    };
    let f = fixture(true);
    let service = service(&f);
    api::with_test_transport(&f.origin, &service.server.url(), || {
        let (scope, ticket) = prepared(&f);
        let old = load(&f.peer.env()).unwrap().unwrap();
        let original = old.remote(&f.peer.env()).unwrap();
        migration_flow::confirm(&f.peer.env(), &scope, &ticket).unwrap();
        assert_eq!(
            migration_flow::advance(&f.peer.env(), &scope)
                .unwrap()
                .phase,
            "staging"
        );
        catalog_write(
            &f,
            &mut service.rows.lock().unwrap(),
            "Newer independently captured history",
        );
        // Persist the legitimate final read, stopping before local publication creates an import.
        // The selected application state is still older than the encrypted retained history.
        let mut loaded = load(&f.peer.env()).unwrap().unwrap();
        let (read, current) = read_remote(&f.peer.env(), &scope, Some(&loaded), &Budget::new())
            .unwrap()
            .unwrap();
        let remote = original
            .verify(
                old.owner().unwrap(),
                old.session.identity.as_ref().unwrap(),
                None,
            )
            .unwrap();
        let plan = loaded.plan(&f.peer.env(), &remote).unwrap();
        assert_eq!(observed(&plan, &current).unwrap(), plan.rows.len());
        let mut next = loaded.state.clone();
        next.completed = plan.rows.len();
        next.floor = read.checkpoint().clone();
        loaded.update(&f.peer.env(), next).unwrap();
        loaded.append(&f.peer.env(), Body::Final(current)).unwrap();
        let current = loaded.final_read(&f.peer.env()).unwrap();
        let env = f.peer.env();
        let files = Files::capture(&env, None).unwrap();
        let name = env
            .state_path
            .file_name()
            .unwrap()
            .to_str()
            .unwrap()
            .to_owned();
        let observer = Capture::new(&f.peer.keychain);
        drop(
            Materials::from_files(
                &old.package.state,
                &f.keys,
                &files,
                &observer,
                &BTreeMap::new(),
            )
            .unwrap(),
        );
        drop(source_archive::captured::read_all(&files.bytes, &observer).unwrap());
        let mut package = Package::assemble(
            &old.package.state,
            &name,
            files,
            Sources::decode_local(
                &old.package.sources.encode_local().unwrap(),
                &old.package.state,
            )
            .unwrap(),
            observer.finish().unwrap(),
        )
        .unwrap();
        let identity = old.session.identity.as_ref().unwrap();
        let calls = service.calls.load(std::sync::atomic::Ordering::SeqCst);
        let before = record_runtime::snapshot(&f.peer.env()).unwrap();
        let originals = archive_bytes(&f.peer.env());
        package
            .capture_historical_snapshots(
                identity,
                &|owner| {
                    DeviceIdentity::load_selected(
                        &f.peer.keychain,
                        &owner.control.profile.profile()?,
                        owner.identity_slot.as_deref(),
                        false,
                    )
                },
                &f.keys,
                &BTreeMap::new(),
            )
            .unwrap();
        let older = original
            .verify(old.owner().unwrap(), identity, None)
            .unwrap();
        assert!(package.require_historical_read(&older, &original).is_err());
        let latest = current
            .verify(old.owner().unwrap(), identity, None)
            .unwrap();
        package.require_historical_read(&latest, &current).unwrap();
        assert_eq!(
            service.calls.load(std::sync::atomic::Ordering::SeqCst),
            calls
        );
        assert_eq!(record_runtime::snapshot(&f.peer.env()).unwrap(), before);
        assert_eq!(archive_bytes(&f.peer.env()), originals);
    });
}
