use super::*;
use crate::sync::record::{record_key, RecordKind};
use crate::sync::record_repository as repo;
use crate::sync::records_v3::*;
use crate::sync::slot_rules::test_keys;
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc, Mutex,
};
const WEB: &str = "0000000000000001";
const GATE: &str = "0000000000000002";
const KEY: &str = "11111111111111111111111111111111";
fn payload(alias: &str) -> HostPayload {
    HostPayload {
        schema: 2,
        group_id: None,
        inherit: vec![],
        alias: alias.into(),
        hostname: format!("{alias}.example.com"),
        port: 22,
        user: "deploy".into(),
        auth: AuthKind::Password,
        key_id: None,
        jump: vec![],
        keepalive_secs: 30,
        keepalive_max_missed: 3,
        connect_timeout_secs: 15,
        host_key: None,
        tags: vec![],
        notes: String::new(),
        imported: None,
    }
}
fn state() -> SyncStateV3 {
    SyncStateV3 {
        version: 3,
        device_id: "a".repeat(32),
        device_name: "fixture".into(),
        relay_url: "http://127.0.0.1:8787".into(),
        account: None,
        spaces: Default::default(),
        local: Default::default(),
        rotation: None,
        relay_features: None,
        legacy_v1_backup: None,
        phrase_cleanup_pending: false,
        migration_gate: None,
        shared_writes_blocked: false,
        pending_account: None,
        notices: vec![],
        last_sync_ms: None,
        last_error: None,
    }
}
fn add(s: &SyncStateV3, id: &str, payload: HostPayload) -> SyncStateV3 {
    repo::create_host(s, id, HostScope::Local, payload, 1).unwrap()
}
fn key() -> HostKey {
    HostKey::from_openssh_line(test_keys::PLAIN_PUBLIC).unwrap()
}
fn fixture(
    s: SyncStateV3,
    material: bool,
    save: bool,
) -> (RecordDirectory, Arc<Mutex<SyncStateV3>>, Arc<AtomicUsize>) {
    let state = Arc::new(Mutex::new(s));
    let count = Arc::new(AtomicUsize::new(0));
    let (read, write, times) = (state.clone(), state.clone(), count.clone());
    let sources = RecordSources {
        snapshot: Box::new(move || {
            times.fetch_add(1, Ordering::SeqCst);
            Ok(read.lock().unwrap().clone())
        }),
        material: Box::new(move |_| Ok(material)),
        username: Box::new(|| Ok("os-user".into())),
        pin: Box::new(move |id, endpoint, previous, candidate| {
            let mut s = write.lock().unwrap();
            let next =
                repo::pin_host_key(&s, id.as_str(), endpoint, previous, candidate.clone(), 99)
                    .map_err(|e| DirectoryError::Failed(e.to_string()))?;
            if !save {
                return Err(DirectoryError::Failed("save failed".into()));
            }
            let host = repo::get_host(&next, id.as_str()).unwrap();
            let p = &host.effective_payload;
            let hop = HopRef { id: id.clone(), alias: p.alias.clone(), hostname: p.hostname.clone(), port: p.port,
                user: if p.user.is_empty() { "os-user".into() } else { p.user.clone() } };
            *s = crate::session::credential_approval::approve(next, &hop, &pinned_key(candidate)?.key)?;
            Ok(())
        }),
    };
    (RecordDirectory::new(sources), state, count)
}
#[test]
fn resolves_a_jump_chain_from_one_snapshot_and_maps_explicit_settings() {
    let mut gate = payload("gate");
    gate.port = 2222;
    gate.user.clear();
    gate.keepalive_secs = 0;
    let s = add(&state(), GATE, gate);
    let mut web = payload("web");
    web.jump = vec![GATE.into()];
    web.connect_timeout_secs = 7;
    let (d, _, count) = fixture(add(&s, WEB, web), false, true);
    let t = d.resolve(&HostQuery::Id(WEB.into())).unwrap();
    assert_eq!(
        t.hops.iter().map(|h| h.id.as_str()).collect::<Vec<_>>(),
        vec![GATE, WEB]
    );
    assert_eq!(t.hops[0].user, "os-user");
    assert_eq!(t.hops[0].port, 2222);
    assert!(t.hops[0].keepalive_every.is_zero());
    assert_eq!(t.hops[1].connect_timeout.as_secs(), 7);
    assert_eq!(count.load(Ordering::SeqCst), 1);
    assert_eq!(d.password_account(&t.hops[1].id), format!("host:{WEB}"));
}
#[test]
fn a_missing_material_on_a_jump_refuses_the_whole_target() {
    let mut gate = payload("gate");
    gate.auth = AuthKind::Key;
    gate.key_id = Some(KEY.into());
    let mut s = add(&state(), GATE, gate);
    let pubkey = ssh_key::PublicKey::from_openssh(test_keys::PLAIN_PUBLIC).unwrap();
    s.local.keys.insert(
        KEY.into(),
        LocalKeyMetadata {
            vault_id: KEY.into(),
            public: KeySlotPayload {
                schema: 2,
                name: "key".into(),
                public_key: test_keys::PLAIN_PUBLIC.into(),
                fingerprint: pubkey.fingerprint(ssh_key::HashAlg::Sha256).to_string(),
                key_type: pubkey.algorithm().to_string(),
                has_passphrase: false,
                created_at_ms: 1,
                origin_device_id: "a".repeat(32),
            },
        },
    );
    let mut web = payload("web");
    web.jump = vec![GATE.into()];
    let s = add(&s, WEB, web);
    let (d, _, _) = fixture(s.clone(), false, true);
    assert!(
        d.resolve_public(&HostQuery::Id(WEB.into())).is_ok(),
        "public route resolution must not require vault material"
    );
    assert!(matches!(
        d.resolve(&HostQuery::Id(WEB.into())),
        Err(DirectoryError::Unsupported(_))
    ));
    let (d, _, _) = fixture(s, true, true);
    assert!(d.resolve(&HostQuery::Id(WEB.into())).is_ok());
}
#[test]
fn imported_review_and_a_missing_jump_refuse_without_reading_material() {
    let mut web = payload("web");
    web.imported = Some(ImportedSettings {
        source: "fixture".into(),
        at_ms: 1,
        unsupported: vec![UnsupportedSetting {
            keyword: "proxycommand".into(),
            value: "nc".into(),
            requires_review: true,
        }],
    });
    web.jump = vec![GATE.into()];
    let (d, _, _) = fixture(add(&state(), WEB, web), true, true);
    assert!(matches!(
        d.resolve(&HostQuery::Id(WEB.into())),
        Err(DirectoryError::Unsupported(_))
    ));
}
#[test]
fn pinning_and_replacing_obey_the_existing_contract_and_stamp_server_time() {
    let (d, s, _) = fixture(add(&state(), WEB, payload("web")), true, true);
    let t = d.resolve(&HostQuery::Alias("web".into())).unwrap();
    let h = t.hops[0].reference();
    let k = key();
    d.pin_for(&h, &k).unwrap();
    d.pin_for(&h, &k).unwrap();
    let pin = d.pinned_for(&h).unwrap().unwrap();
    assert_eq!(pin.key, k);
    assert_eq!(pin.pinned_at_ms, 99);
    let other = HostKey::from_openssh_line(test_keys::ECDSA_PUBLIC).unwrap();
    assert!(d.pin_for(&h, &other).is_err());
    d.replace_pin_for(&h, &k, &other).unwrap();
    assert_eq!(d.pinned(&h.id).unwrap().unwrap().key, other);
    assert_eq!(
        repo::get_host(&s.lock().unwrap(), WEB)
            .unwrap()
            .host
            .payload
            .host_key
            .unwrap()
            .pinned_by_device_id,
        "a".repeat(32)
    );
}
#[test]
fn a_changed_endpoint_after_resolve_cannot_receive_the_old_servers_pin() {
    let (d, s, _) = fixture(add(&state(), WEB, payload("web")), true, true);
    let hop = d.resolve(&HostQuery::Id(WEB.into())).unwrap().hops[0].reference();
    {
        let mut s = s.lock().unwrap();
        let view = repo::get_host(&s, WEB).unwrap();
        let mut p = view.host.payload;
        p.hostname = "changed.example.com".into();
        *s = repo::update_host(&s, WEB, &view.revision, p, 2).unwrap();
    }
    assert!(d.pin_for(&hop, &key()).is_err());
    assert!(d.pinned_for(&hop).is_err());
    assert!(repo::get_host(&s.lock().unwrap(), WEB)
        .unwrap()
        .host
        .payload
        .host_key
        .is_none());
}
#[test]
fn failed_pin_save_keeps_memory_and_record_revision_unchanged() {
    let original = add(&state(), WEB, payload("web"));
    let (d, s, _) = fixture(original.clone(), true, false);
    let h = d.resolve(&HostQuery::Id(WEB.into())).unwrap().hops[0].reference();
    assert!(d.pin_for(&h, &key()).is_err());
    assert_eq!(*s.lock().unwrap(), original);
}
#[test]
fn duplicate_aliases_are_ambiguous_while_ids_remain_explicit() {
    let mut s = add(&state(), WEB, payload("web"));
    let mut host = s.local.hosts[&record_key(RecordKind::Host, WEB)].clone();
    host.record.id = GATE.into();
    s.local
        .hosts
        .insert(record_key(RecordKind::Host, GATE), host);
    let (d, _, _) = fixture(s, false, true);
    assert!(matches!(
        d.resolve(&HostQuery::Alias("web".into())),
        Err(DirectoryError::Ambiguous(_))
    ));
    assert!(matches!(
        d.resolve(&HostQuery::Id(WEB.into())),
        Err(DirectoryError::Unsupported(_))
    ));
}

#[test]
fn an_identical_pin_still_requires_a_durable_runtime_receipt() {
    let initial = add(&state(), WEB, payload("web"));
    let initial = repo::pin_host_key(
        &initial,
        WEB,
        &HostEndpoint {
            hostname: "web.example.com".into(),
            port: 22,
        },
        None,
        stored(&key()),
        99,
    )
    .unwrap();
    let (d, _, _) = fixture(initial, true, false);
    let hop = d.resolve(&HostQuery::Id(WEB.into())).unwrap().hops[0].reference();
    assert!(
        d.pin_for(&hop, &key()).is_err(),
        "an unsaved matching pin is not a durable confirmation"
    );
}

#[test]
fn records_connect_through_the_real_engine_and_persist_first_contact() {
    use crate::session::connect::{CancelToken, Connector};
    use crate::session::testing::{Decision, FakeConfirmer, FakeKeys, FakeOwner};
    use crate::ssh::russh_engine::{
        toy_server::{ToyLogin, ToyServer},
        RusshEngine,
    };
    use crate::sync::testkit::MemKeychain;
    let server = ToyServer::start(ToyLogin {
        user: "deploy".into(),
        password: "fixture-password".into(),
        prompt: "Password: ".into(),
        rounds: None,
    });
    let mut web = payload("web");
    web.hostname = "127.0.0.1".into();
    web.port = server.port;
    let (directory, state, _) = fixture(add(&state(), WEB, web), false, true);
    let (engine, keys, keychain, owner, confirmer) = (
        RusshEngine::new(),
        FakeKeys::new(),
        MemKeychain::default(),
        FakeOwner::typing(&["fixture-password"]),
        FakeConfirmer::deciding(vec![Decision::Trust]),
    );
    let connector = Connector {
        grants: crate::session::grants::GrantGates::for_tests(),
        engine: &engine,
        directory: &directory,
        keys: &keys,
        keychain: &keychain,
        confirmer: &confirmer,
    };
    let connected = connector
        .connect(&HostQuery::Id(WEB.into()), &owner, &CancelToken::default())
        .unwrap();
    assert!(connected.session.is_alive());
    assert_eq!(confirmer.asked().len(), 1);
    assert_eq!(owner.asked().len(), 1);
    assert!(repo::get_host(&state.lock().unwrap(), WEB)
        .unwrap()
        .host
        .payload
        .host_key
        .is_some());
    connected.session.close();
}
#[test]
fn editing_the_endpoint_in_the_confirmation_window_refuses_the_connect() {
    use crate::session::connect::{CancelToken, Connector, HostKeyConfirmer, HostKeyQuestion};
    use crate::session::testing::{FakeKeys, FakeOwner};
    use crate::ssh::russh_engine::{
        toy_server::{ToyLogin, ToyServer},
        RusshEngine,
    };
    use crate::sync::testkit::MemKeychain;
    struct Change(Arc<Mutex<SyncStateV3>>);
    impl HostKeyConfirmer for Change {
        fn confirm(&self, q: &HostKeyQuestion, _: &CancelToken) -> Option<String> {
            let mut s = self.0.lock().unwrap();
            let old = repo::get_host(&s, WEB).unwrap();
            let mut p = old.host.payload;
            p.hostname = "changed.example.com".into();
            *s = repo::update_host(&s, WEB, &old.revision, p, 2).unwrap();
            Some(q.fingerprint.clone())
        }
    }
    let server = ToyServer::start(ToyLogin {
        user: "deploy".into(),
        password: "fixture-password".into(),
        prompt: "Password: ".into(),
        rounds: None,
    });
    let mut web = payload("web");
    web.hostname = "127.0.0.1".into();
    web.port = server.port;
    let (directory, state, _) = fixture(add(&state(), WEB, web), false, true);
    let (engine, keys, keychain, owner, confirmer) = (
        RusshEngine::new(),
        FakeKeys::new(),
        MemKeychain::default(),
        FakeOwner::typing(&["fixture-password"]),
        Change(state.clone()),
    );
    let connector = Connector {
        grants: crate::session::grants::GrantGates::for_tests(),
        engine: &engine,
        directory: &directory,
        keys: &keys,
        keychain: &keychain,
        confirmer: &confirmer,
    };
    let error = connector
        .connect(&HostQuery::Id(WEB.into()), &owner, &CancelToken::default())
        .err()
        .expect("endpoint changed while trust window was open");
    assert!(error.text.contains("endpoint"));
    assert!(repo::get_host(&state.lock().unwrap(), WEB)
        .unwrap()
        .host
        .payload
        .host_key
        .is_none());
}

#[test]
fn group_directory_uses_effective_destination_and_refuses_old_hop_after_parent_edit() {
    let p = serde_json::from_value(
        serde_json::json!({"schema":1,"name":"Ops","defaults":{"port":2222,"user":"ops"}}),
    )
    .unwrap();
    let s = crate::sync::record_groups::create_group(
        &state(),
        "0000000000000031",
        HostScope::Local,
        p,
        true,
        2,
    )
    .unwrap();
    let mut p = payload("web");
    p.schema = 3;
    p.group_id = Some("0000000000000031".into());
    p.inherit = vec![InheritedField::Port, InheritedField::User];
    let (directory, state, _) = fixture(add(&s, WEB, p), true, true);
    let target = directory.resolve(&HostQuery::Id(WEB.into())).unwrap();
    assert_eq!(target.hops[0].port, 2222);
    assert_eq!(target.hops[0].user, "ops");
    let old = target.hops[0].reference();
    let mut state = state.lock().unwrap();
    let group = crate::sync::record_groups::list_groups(&state)
        .unwrap()
        .remove(0);
    let mut p = group.group.payload;
    p.defaults.port = Some(2223);
    *state =
        crate::sync::record_groups::update_group(&state, &group.group.id, &group.revision, p, 3)
            .unwrap();
    drop(state);
    assert!(directory.checked_host(&old).is_err());
}

#[test]
fn server_key_probe_uses_no_destination_key_or_private_material() {
    let mut web = payload("web");
    web.auth = AuthKind::Key;
    web.key_id = Some(KEY.into());
    let (d, _, _) = fixture(add(&state(), WEB, web), false, true);
    assert!(d.resolve_public(&HostQuery::Id(WEB.into())).is_err());
    let probe = d.resolve_host_key(&HostQuery::Id(WEB.into())).unwrap();
    assert_eq!(probe.hops[0].auth, AuthMethod::Interactive);
    let mut gate = payload("gate");
    gate.auth = AuthKind::Key;
    gate.key_id = Some(KEY.into());
    let mut web = payload("web");
    web.jump = vec![GATE.into()];
    let (d, _, _) = fixture(add(&add(&state(), GATE, gate), WEB, web), false, true);
    assert!(
        d.resolve_host_key(&HostQuery::Id(WEB.into())).is_err(),
        "jump identities are still required"
    );
}

#[test]
fn editing_the_destination_during_probe_review_cannot_trust_the_old_endpoint() {
    use crate::session::{
        connect::{Connector, HostKeyConfirmer, HostKeyQuestion},
        testing::{FakeKeys, FakeOwner},
    };
    use crate::sync::testkit::MemKeychain;
    struct Edit(Arc<Mutex<SyncStateV3>>);
    impl HostKeyConfirmer for Edit {
        fn confirm(&self, q: &HostKeyQuestion, _: &crate::session::connect::CancelToken) -> Option<String> {
            let mut state = self.0.lock().unwrap();
            let view = repo::get_host(&state, WEB).unwrap();
            let mut payload = view.host.payload;
            payload.hostname = "changed.invalid".into();
            *state = repo::update_host(&state, WEB, &view.revision, payload, 50).unwrap();
            Some(q.fingerprint.clone())
        }
    }
    let (directory, state, _) = fixture(add(&state(), WEB, payload("web")), false, true);
    let confirmer = Edit(state.clone());
    let connector = Connector {
        grants: crate::session::grants::GrantGates::for_tests(),
        directory: &directory,
        engine: &crate::ssh::fake::FakeEngine::new(),
        confirmer: &confirmer,
        keys: &FakeKeys::new(),
        keychain: &MemKeychain::default(),
    };
    assert!(crate::session::verify::verify(
        &connector,
        &HostQuery::Id(WEB.into()),
        &FakeOwner::default(),
        &crate::session::connect::CancelToken::default()
    )
    .is_err());
    assert!(repo::get_host(&state.lock().unwrap(), WEB)
        .unwrap()
        .host
        .payload
        .host_key
        .is_none());
}


#[test]
fn synchronized_identity_changes_never_release_a_locally_saved_password() {
    use crate::session::{auth::BrokerAuth, testing::{FakeKeys, FakeOwner}};
    use crate::sync::{env::Keychain, testkit::MemKeychain};
    use crate::ssh::AuthSource;
    for field in ["hostname", "port", "user", "host_key"] {
        let original = add(&state(), WEB, payload("web"));
        // A synchronized pin is not a local approval, even on an otherwise valid host.
        let original = repo::pin_host_key(&original, WEB, &HostEndpoint { hostname: "web.example.com".into(), port: 22 }, None, stored(&key()), 1).unwrap();
        let (directory, shared, _) = fixture(original, true, true);
        let old = directory.resolve(&HostQuery::Id(WEB.into())).unwrap().hops.remove(0);
        assert!(old.pinned.is_none());
        let keys = FakeKeys::new();
        let secrets = MemKeychain::default();
        secrets.set(&format!("host:{WEB}"), "device-local-password").unwrap();
        let owner = FakeOwner::default();
        let auth = BrokerAuth::new(&keys, &secrets, &owner, &directory);
        auth.prepare(&Target { hops: vec![old.clone()] });
        assert!(auth.password(&old.reference()).is_none());
        assert!(owner.asked().is_empty(), "no fresh password prompt before reviewing the identity");
        // A human locally confirms this endpoint/user/key; normal reuse then works.
        directory.pin_for(&old.reference(), &key()).unwrap();
        auth.prepare(&directory.resolve(&HostQuery::Id(WEB.into())).unwrap());
        assert_eq!(auth.password(&old.reference()).as_deref().map(String::as_str), Some("device-local-password"));
        {
            let mut state = shared.lock().unwrap();
            let row = state.local.hosts.get_mut(&record_key(RecordKind::Host, WEB)).unwrap();
            match field {
                "hostname" => row.record.payload["hostname"] = "attacker.example.com".into(),
                "port" => row.record.payload["port"] = 2222.into(),
                "user" => row.record.payload["user"] = "root".into(),
                "host_key" => {
                    let mut pin = stored(&HostKey::from_openssh_line(test_keys::ECDSA_PUBLIC).unwrap());
                    pin.pinned_by_device_id = "b".repeat(32);
                    row.record.payload["host_key"] = serde_json::to_value(pin).unwrap();
                },
                _ => unreachable!(),
            }
        }
        let changed = directory.resolve(&HostQuery::Id(WEB.into())).unwrap().hops.remove(0);
        assert!(changed.pinned.is_none(), "{field} needs local server identity review");
        assert!(auth.password(&changed.reference()).is_none(), "{field} must not release the old password");
        assert_eq!(secrets.get(&format!("host:{WEB}")).unwrap().as_deref(), Some("device-local-password"));
        assert!(owner.asked().is_empty());
    }
}

#[test]
fn harmless_edits_preserve_local_approval_but_forgotten_pins_do_not() {
    let (directory, shared, _) = fixture(add(&state(), WEB, payload("web")), true, true);
    let hop = directory.resolve(&HostQuery::Id(WEB.into())).unwrap().hops.remove(0).reference();
    directory.pin_for(&hop, &key()).unwrap();
    {
        let mut state = shared.lock().unwrap();
        let host = repo::get_host(&state, WEB).unwrap();
        let mut payload = host.host.payload;
        payload.notes = "a harmless edit".into();
        *state = repo::update_host(&state, WEB, &host.revision, payload, 100).unwrap();
    }
    assert!(directory.password_authorized(&hop, Some(&key())).unwrap());
    let mut state = shared.lock().unwrap();
    let host = repo::get_host(&state, WEB).unwrap();
    *state = repo::forget_host_key(&state, WEB, &host.revision, &HostEndpoint { hostname: hop.hostname, port: hop.port }, host.host.payload.host_key.as_ref().unwrap(), 101).unwrap();
    assert!(!state.local.credential_approvals.contains_key(WEB));
}


#[test]
fn a_later_pin_approval_cannot_authorize_a_password_for_an_in_flight_old_server_key() {
    let (directory, _, _) = fixture(add(&state(), WEB, payload("web")), true, true);
    let hop = directory.resolve(&HostQuery::Id(WEB.into())).unwrap().hops.remove(0).reference();
    let original = key();
    directory.pin_for(&hop, &original).unwrap();
    let replacement = HostKey::from_openssh_line(test_keys::ECDSA_PUBLIC).unwrap();
    directory.replace_pin_for(&hop, &original, &replacement).unwrap();
    assert!(!directory.password_authorized(&hop, Some(&original)).unwrap());
    assert!(directory.password_authorized(&hop, Some(&replacement)).unwrap());
}

/// Google Cloud IAP transports (design 2026-10-25): the first hop's transport, and what `prepare` does with OS Login and PAM.
mod gcp_transport {
    use super::*;
    use crate::gcp::oslogin::{LoginProfile, PosixAccount};
    use crate::gcp::pam::Grant;
    use crate::gcp::rest::{GcpClient, GcpError};
    use crate::session::connect::CancelToken;
    use crate::session::directory::{GrantNeed, GrantReceipt};
    use crate::ssh::{IapTarget, Transport};
    use crate::sync::transports::{self, HostTransport, PamCheck, TransportKind};
    use std::collections::VecDeque;

    const ACCOUNT: &str = "frank@example.com";
    const LINE: &str = test_keys::PLAIN_PUBLIC;
    const GRANT_NAME: &str = "projects/acme-prod-123456/locations/global/entitlements/prod-operate/grants/42";

    /// A scripted Google: one login profile, optionally another one after an import, the grants of every entitlement, the states a
    /// requested grant goes through (`get_grant` answers them in turn, the last one again and again), and the calls made.
    #[derive(Default)]
    struct FakeGcp {
        profile: Mutex<LoginProfile>,
        after_import: Mutex<Option<LoginProfile>>,
        grants: Mutex<Vec<Grant>>,
        states: Mutex<VecDeque<&'static str>>,
        calls: Mutex<Vec<String>>,
    }

    struct Handle(Arc<FakeGcp>);

    /// A project entitlement's name in parts: the project, the location and the entitlement id.
    fn parts(name: &str) -> (String, String, String) {
        let name = crate::gcp::pam::EntitlementName::parse(name).expect("a well-formed entitlement name");
        (name.parent.strip_prefix("projects/").expect("a project's entitlement").to_string(), name.location, name.id)
    }

    impl GcpClient for Handle {
        fn login_profile(&self, account: Option<&str>, project: &str) -> Result<LoginProfile, GcpError> {
            self.0.calls.lock().unwrap().push(format!("profile {} {project}", account.unwrap_or("-")));
            Ok(self.0.profile.lock().unwrap().clone())
        }
        fn import_ssh_public_key(&self, account: Option<&str>, project: &str, key_line: &str) -> Result<LoginProfile, GcpError> {
            self.0.calls.lock().unwrap().push(format!("import {} {project} {key_line}", account.unwrap_or("-")));
            let after = self.0.after_import.lock().unwrap().clone();
            Ok(after.unwrap_or_else(|| self.0.profile.lock().unwrap().clone()))
        }
        fn grants(&self, account: Option<&str>, name: &str) -> Result<Vec<Grant>, GcpError> {
            let (project, location, entitlement) = parts(name);
            self.0.calls.lock().unwrap().push(format!("grants {} {project} {location} {entitlement}", account.unwrap_or("-")));
            Ok(self.0.grants.lock().unwrap().clone())
        }
        fn create_grant(&self, account: Option<&str>, name: &str, duration_secs: u32, justification: &str) -> Result<Grant, GcpError> {
            let (project, location, entitlement) = parts(name);
            self.0.calls.lock().unwrap().push(format!("create {} {project} {location} {entitlement} {duration_secs} {justification}", account.unwrap_or("-")));
            Ok(Grant {
                name: GRANT_NAME.into(),
                state: "ACTIVATING".into(),
                requested_duration: Some(crate::gcp::pam::duration_text(duration_secs)),
                access_grant_time: None,
                justification: Some(justification.to_string()),
            })
        }
        fn get_grant(&self, account: Option<&str>, name: &str) -> Result<Grant, GcpError> {
            self.0.calls.lock().unwrap().push(format!("get {} {name}", account.unwrap_or("-")));
            let mut states = self.0.states.lock().unwrap();
            let state = if states.len() > 1 { states.pop_front().unwrap() } else { states.front().copied().unwrap_or("ACTIVE") };
            Ok(Grant {
                name: name.into(),
                state: state.into(),
                requested_duration: Some("1800s".into()),
                access_grant_time: (state == "ACTIVE").then(|| crate::gcp::pam::rfc3339(std::time::SystemTime::now())),
                justification: None,
            })
        }
    }

    fn linux(username: &str, keys: &[&str]) -> LoginProfile {
        LoginProfile {
            posix_accounts: vec![PosixAccount { username: username.into(), primary: true, operating_system_type: Some("LINUX".into()) }],
            ssh_public_keys: keys.iter().map(|key| key.to_string()).collect(),
        }
    }

    fn grant(state: &str) -> Grant {
        Grant { name: format!("grants/{state}"), state: state.into(), requested_duration: Some("1800s".into()), access_grant_time: None, justification: None }
    }

    fn transport(project: &str, host: &str, os_login: bool, pam: Option<PamCheck>) -> HostTransport {
        HostTransport {
            host_id: host.into(),
            kind: TransportKind::GcpIap {
                project: project.into(),
                zone: "asia-east1-b".into(),
                instance: "jumpbox".into(),
                interface: "nic0".into(),
                account: Some(ACCOUNT.into()),
                os_login,
                pam,
            },
        }
    }

    fn prod_pam() -> Option<PamCheck> {
        Some(PamCheck { entitlements: vec!["prod-operate".into(), "prod-admin".into()], location: "global".into(), duration_secs: 1800, justification: None })
    }

    /// GATE as a key host (its key available on this device) logging in as `user`, with `transport` when given.
    fn gate_state(user: &str, transport: Option<HostTransport>) -> SyncStateV3 {
        let mut gate = payload("gate");
        gate.auth = AuthKind::Key;
        gate.key_id = Some(KEY.into());
        gate.user = user.into();
        let mut s = add(&state(), GATE, gate);
        let pubkey = ssh_key::PublicKey::from_openssh(LINE).unwrap();
        s.local.keys.insert(
            KEY.into(),
            LocalKeyMetadata {
                vault_id: KEY.into(),
                public: KeySlotPayload {
                    schema: 2,
                    name: "key".into(),
                    public_key: LINE.into(),
                    fingerprint: pubkey.fingerprint(ssh_key::HashAlg::Sha256).to_string(),
                    key_type: pubkey.algorithm().to_string(),
                    has_passphrase: false,
                    created_at_ms: 1,
                    origin_device_id: "a".repeat(32),
                },
            },
        );
        match transport {
            Some(transport) => transports::set(&s, GATE, None, Some(transport), 1).unwrap(),
            None => s,
        }
    }

    fn directory(s: SyncStateV3, gcp: &Arc<FakeGcp>) -> RecordDirectory {
        let (d, _, _) = fixture(s, true, true);
        d.with_gcp(Arc::new(Handle(Arc::clone(gcp))))
    }

    /// What grant requests asked this computer to remember: `(host, justification, duration)`.
    type Remembered = Arc<Mutex<Vec<(String, String, u32)>>>;

    /// `directory` that also records what a grant request asked this computer to remember.
    fn directory_with_memory(s: SyncStateV3, gcp: &Arc<FakeGcp>) -> (RecordDirectory, Remembered) {
        let remembered = Arc::new(Mutex::new(Vec::new()));
        let sink = Arc::clone(&remembered);
        let d = directory(s, gcp).with_grant_memory(Box::new(move |host, justification, duration| {
            sink.lock().unwrap().push((host.to_string(), justification.to_string(), duration));
            Ok(())
        }));
        (d, remembered)
    }

    fn public_key(key_id: &str) -> Option<String> {
        (key_id == KEY).then(|| LINE.to_string())
    }

    fn gate() -> HostQuery {
        HostQuery::Id(GATE.into())
    }

    fn calls(gcp: &FakeGcp) -> Vec<String> {
        gcp.calls.lock().unwrap().clone()
    }

    fn denied(error: DirectoryError) -> String {
        match error {
            DirectoryError::Denied(text) => text,
            other => panic!("expected Denied, got {other:?}"),
        }
    }

    #[test]
    fn a_transport_on_the_first_hop_becomes_an_iap_target() {
        let gcp = Arc::new(FakeGcp::default());
        let d = directory(gate_state("frank_example_com", Some(transport("acme-dev-654321", GATE, true, None))), &gcp);
        let t = d.resolve(&gate()).unwrap();
        assert_eq!(
            t.hops[0].transport,
            Transport::GcpIap(IapTarget {
                project: "acme-dev-654321".into(),
                zone: "asia-east1-b".into(),
                instance: "jumpbox".into(),
                interface: "nic0".into(),
                account: Some(ACCOUNT.into()),
                url_root: None,
            })
        );
        assert_eq!(t.hops[0].user, "frank_example_com", "resolving leaves the saved user alone");
        assert!(calls(&gcp).is_empty(), "resolving talks to nobody");
        let d = directory(gate_state("deploy", None), &gcp);
        assert_eq!(d.resolve(&gate()).unwrap().hops[0].transport, Transport::Tcp);
    }

    #[test]
    fn a_transport_on_a_jump_target_is_refused() {
        let mut s = gate_state("deploy", None);
        let mut web = payload("web");
        web.jump = vec![GATE.into()];
        s = add(&s, WEB, web);
        s = transports::set(&s, WEB, None, Some(transport("acme-dev-654321", WEB, false, None)), 2).unwrap();
        let d = directory(s, &Arc::new(FakeGcp::default()));
        assert_eq!(
            d.resolve(&HostQuery::Id(WEB.into())).unwrap_err(),
            DirectoryError::Unsupported("web connects through Google Cloud IAP and cannot be reached through a jump host.".into())
        );
    }

    #[test]
    fn prepare_imports_a_missing_key_and_accepts_a_matching_username() {
        let gcp = Arc::new(FakeGcp::default());
        *gcp.profile.lock().unwrap() = linux("frank_example_com", &[]);
        let d = directory(gate_state("frank_example_com", Some(transport("acme-dev-654321", GATE, true, None))), &gcp);
        let target = d.resolve(&gate()).unwrap();
        d.prepare(&target, &public_key, &CancelToken::default()).unwrap();
        assert_eq!(calls(&gcp), vec![format!("profile {ACCOUNT} acme-dev-654321"), format!("import {ACCOUNT} acme-dev-654321 {LINE}")]);
    }

    #[test]
    fn prepare_skips_the_import_when_the_key_is_registered() {
        let gcp = Arc::new(FakeGcp::default());
        *gcp.profile.lock().unwrap() = linux("frank_example_com", &[&format!("{LINE} frank@laptop")]);
        let d = directory(gate_state("frank_example_com", Some(transport("acme-dev-654321", GATE, true, None))), &gcp);
        let target = d.resolve(&gate()).unwrap();
        d.prepare(&target, &public_key, &CancelToken::default()).unwrap();
        assert_eq!(calls(&gcp), vec![format!("profile {ACCOUNT} acme-dev-654321")]);
    }

    #[test]
    fn prepare_imports_the_key_when_the_profile_has_no_posix_account_and_uses_the_returned_profile() {
        let gcp = Arc::new(FakeGcp::default());
        *gcp.after_import.lock().unwrap() = Some(linux("frank_example_com", &[LINE]));
        let d = directory(gate_state("frank_example_com", Some(transport("acme-dev-654321", GATE, true, None))), &gcp);
        let target = d.resolve(&gate()).unwrap();
        d.prepare(&target, &public_key, &CancelToken::default()).unwrap();
        assert_eq!(calls(&gcp), vec![format!("profile {ACCOUNT} acme-dev-654321"), format!("import {ACCOUNT} acme-dev-654321 {LINE}")]);
        let gcp = Arc::new(FakeGcp::default());
        let d = directory(gate_state("frank_example_com", Some(transport("acme-dev-654321", GATE, true, None))), &gcp);
        let target = d.resolve(&gate()).unwrap();
        assert_eq!(
            denied(d.prepare(&target, &public_key, &CancelToken::default()).unwrap_err()),
            "OS Login has no POSIX account for frank@example.com in acme-dev-654321; the project may not have OS Login enabled."
        );
    }

    #[test]
    fn prepare_refuses_a_username_that_differs_from_os_login() {
        let gcp = Arc::new(FakeGcp::default());
        *gcp.profile.lock().unwrap() = linux("frank_example_com", &[LINE]);
        let d = directory(gate_state("frank", Some(transport("acme-dev-654321", GATE, true, None))), &gcp);
        let target = d.resolve(&gate()).unwrap();
        assert_eq!(
            denied(d.prepare(&target, &public_key, &CancelToken::default()).unwrap_err()),
            "OS Login names frank@example.com frank_example_com on acme-dev-654321, but the host is saved with user frank; save that username into the host (Use OS Login username in the host editor)."
        );
    }

    #[test]
    fn prepare_refuses_without_an_in_flight_pam_grant_and_passes_with_one() {
        let gcp = Arc::new(FakeGcp::default());
        *gcp.grants.lock().unwrap() = vec![grant("ENDED"), grant("DENIED")];
        let d = directory(gate_state("deploy", Some(transport("acme-prod-123456", GATE, false, prod_pam()))), &gcp);
        let target = d.resolve(&gate()).unwrap();
        // A missing grant is a `GrantNeeded` now (design 2026-10-25, PAM grant requests); its sentence is the refusal of old.
        let error = d.prepare(&target, &public_key, &CancelToken::default()).unwrap_err();
        assert!(matches!(error, DirectoryError::GrantNeeded(_)), "{error:?}");
        let text = error.to_string();
        assert!(text.starts_with("No active Privileged Access Manager grant for prod-operate or prod-admin on acme-prod-123456."), "{text}");
        assert!(
            text.contains("gcloud pam grants create --entitlement=prod-operate --requested-duration=30m --justification=\"…\" --location=global --project=acme-prod-123456"),
            "{text}"
        );
        assert_eq!(calls(&gcp), vec![format!("grants {ACCOUNT} acme-prod-123456 global prod-operate"), format!("grants {ACCOUNT} acme-prod-123456 global prod-admin")]);
        *gcp.grants.lock().unwrap() = vec![grant("ENDED"), grant("ACTIVE")];
        assert!(!d.prepare(&target, &public_key, &CancelToken::default()).unwrap().recent_grant);
    }

    /// Design 2026-10-25: IAP can take about 1½ minutes to see a grant, so the broker is told when the grant it found is that fresh and
    /// adds the note to a 4033 refusal. A grant given earlier than two minutes ago, or one without a time, is not fresh.
    #[test]
    fn prepare_reports_a_grant_that_became_active_moments_ago() {
        use crate::gcp::pam::rfc3339;
        use std::time::{Duration, SystemTime};
        let gcp = Arc::new(FakeGcp::default());
        let d = directory(gate_state("deploy", Some(transport("acme-prod-123456", GATE, false, prod_pam()))), &gcp);
        let target = d.resolve(&gate()).unwrap();
        let given = |ago: u64| Grant { access_grant_time: Some(rfc3339(SystemTime::now() - Duration::from_secs(ago))), ..grant("ACTIVE") };
        *gcp.grants.lock().unwrap() = vec![grant("ENDED"), given(60)];
        assert!(d.prepare(&target, &public_key, &CancelToken::default()).unwrap().recent_grant);
        *gcp.grants.lock().unwrap() = vec![given(600)];
        assert!(!d.prepare(&target, &public_key, &CancelToken::default()).unwrap().recent_grant);
        // A grant still activating is as fresh as one just given, and a grant time ahead of this clock (Google's clock is ahead) is fresh too.
        *gcp.grants.lock().unwrap() = vec![grant("ACTIVATING")];
        assert!(d.prepare(&target, &public_key, &CancelToken::default()).unwrap().recent_grant);
        *gcp.grants.lock().unwrap() = vec![Grant { access_grant_time: Some(rfc3339(SystemTime::now() + Duration::from_secs(30))), ..grant("ACTIVE") }];
        assert!(d.prepare(&target, &public_key, &CancelToken::default()).unwrap().recent_grant);
    }

    /// Design 2026-10-25 (PAM grant requests): a missing grant is reported with everything the broker needs to ask and request, and
    /// the refusal sentence stays the one that quotes the gcloud command.
    #[test]
    fn prepare_asks_for_a_grant_with_the_transports_defaults_when_none_is_in_flight() {
        let gcp = Arc::new(FakeGcp::default());
        *gcp.grants.lock().unwrap() = vec![grant("ENDED")];
        let d = directory(gate_state("deploy", Some(transport("acme-prod-123456", GATE, false, prod_pam()))), &gcp);
        let target = d.resolve(&gate()).unwrap();
        let error = d.prepare(&target, &public_key, &CancelToken::default()).unwrap_err();
        let DirectoryError::GrantNeeded(need) = error.clone() else { panic!("expected GrantNeeded, got {error:?}") };
        let need = *need;
        assert_eq!(
            need,
            GrantNeed {
                host: GATE.into(),
                account: Some(ACCOUNT.into()),
                project: "acme-prod-123456".into(),
                location: "global".into(),
                entitlement: "prod-operate".into(),
                entitlements: vec!["prod-operate".into(), "prod-admin".into()],
                duration_secs: 1800,
                justification: None,
            }
        );
        assert_eq!(
            need.refusal_sentence(),
            "No active Privileged Access Manager grant for prod-operate or prod-admin on acme-prod-123456. Request one (for example gcloud pam grants create --entitlement=prod-operate --requested-duration=30m --justification=\"…\" --location=global --project=acme-prod-123456) and connect again."
        );
        assert_eq!(error.to_string(), need.refusal_sentence());
        // Automation (an MCP request, the verification probe) gets the refusal, never a question.
        assert_eq!(error.for_automation(), DirectoryError::Denied(need.refusal_sentence()));
        assert_eq!(DirectoryError::Failed("x".into()).for_automation(), DirectoryError::Failed("x".into()));
    }

    /// The grant `prepare` says GATE's connection needs, with no grant in flight.
    fn grant_needed(s: SyncStateV3) -> GrantNeed {
        let gcp = Arc::new(FakeGcp::default());
        *gcp.grants.lock().unwrap() = vec![grant("ENDED")];
        let d = directory(s, &gcp);
        let target = d.resolve(&gate()).unwrap();
        let DirectoryError::GrantNeeded(need) = d.prepare(&target, &public_key, &CancelToken::default()).unwrap_err() else { panic!("a needed grant") };
        *need
    }

    /// Design 2026-10-26 (Grant requests): the question a connection asks offers what this computer last asked for on the host, as the
    /// request dialog does, not what the route holds: that justification and that length, whatever the route's default length is.
    #[test]
    fn the_grant_question_offers_what_this_computer_last_asked_for_on_the_host() {
        let routed = gate_state("deploy", Some(transport("acme-prod-123456", GATE, false, prod_pam())));
        let remembered = transports::remember_grant_request(&routed, GATE, "restart app-api", 2700, 2).unwrap();
        let need = grant_needed(remembered);
        assert_eq!((need.duration_secs, need.justification.as_deref()), (2700, Some("restart app-api")));
        // The rest of the question is the route's, as before.
        assert_eq!((need.entitlement.as_str(), need.entitlements.len(), need.project.as_str()), ("prod-operate", 2, "acme-prod-123456"));
        // The route itself keeps the default (1800 s): the memory is not part of it.
        let TransportKind::GcpIap { pam, .. } = transports::get(&routed, GATE).unwrap().kind;
        assert_eq!(pam.map(|pam| pam.duration_secs), Some(1800));
    }

    /// A host this computer never asked a grant for is offered the route's own default length and nothing to prefill: a justification
    /// an earlier release left in the route is not offered (no request writes it any more), nor is another host's memory.
    #[test]
    fn without_a_memory_the_grant_question_offers_the_routes_default_length_and_no_justification() {
        let mut pam = prod_pam();
        let check = pam.as_mut().unwrap();
        (check.duration_secs, check.justification) = (3600, Some("left by an earlier release".into()));
        let mut s = gate_state("deploy", Some(transport("acme-prod-123456", GATE, false, pam)));
        let need = grant_needed(s.clone());
        assert_eq!((need.duration_secs, need.justification), (3600, None));
        // Another host's memory is that host's.
        s = add(&s, WEB, payload("web"));
        s = transports::set(&s, WEB, None, Some(transport("acme-prod-123456", WEB, false, prod_pam())), 2).unwrap();
        s = transports::remember_grant_request(&s, WEB, "rotate certs", 600, 3).unwrap();
        assert!(transports::grant_memory(&s, WEB).is_some() && transports::grant_memory(&s, GATE).is_none());
        let need = grant_needed(s);
        assert_eq!((need.duration_secs, need.justification), (3600, None));
    }

    #[test]
    fn prepare_dates_a_fresh_grant_and_never_in_the_future() {
        use crate::gcp::pam::rfc3339;
        let gcp = Arc::new(FakeGcp::default());
        let d = directory(gate_state("deploy", Some(transport("acme-prod-123456", GATE, false, prod_pam()))), &gcp);
        let target = d.resolve(&gate()).unwrap();
        let at = |offset: i64| {
            let time = if offset >= 0 { std::time::SystemTime::now() + std::time::Duration::from_secs(offset as u64) } else { std::time::SystemTime::now() - std::time::Duration::from_secs((-offset) as u64) };
            Grant { access_grant_time: Some(rfc3339(time)), ..grant("ACTIVE") }
        };
        let age = |prepared: Prepared| std::time::SystemTime::now().duration_since(prepared.granted_at.expect("a date")).unwrap_or_default().as_secs();
        *gcp.grants.lock().unwrap() = vec![at(-60)];
        assert!((58..=62).contains(&age(d.prepare(&target, &public_key, &CancelToken::default()).unwrap())));
        *gcp.grants.lock().unwrap() = vec![at(30)];
        assert!(age(d.prepare(&target, &public_key, &CancelToken::default()).unwrap()) <= 2, "a time ahead of this clock counts as now");
        *gcp.grants.lock().unwrap() = vec![grant("ACTIVATING")];
        assert!(age(d.prepare(&target, &public_key, &CancelToken::default()).unwrap()) <= 2, "still activating: as fresh as now");
        *gcp.grants.lock().unwrap() = vec![at(-600)];
        let old = d.prepare(&target, &public_key, &CancelToken::default()).unwrap();
        assert!(!old.recent_grant && old.granted_at.is_some());
    }

    #[test]
    fn request_grant_creates_remembers_polls_and_answers_a_receipt() {
        let gcp = Arc::new(FakeGcp::default());
        *gcp.states.lock().unwrap() = VecDeque::from(vec!["ACTIVATING", "ACTIVE"]);
        let (d, remembered) = directory_with_memory(gate_state("deploy", Some(transport("acme-prod-123456", GATE, false, prod_pam()))), &gcp);
        let target = d.resolve(&gate()).unwrap();
        let DirectoryError::GrantNeeded(need) = d.prepare(&target, &public_key, &CancelToken::default()).unwrap_err() else { panic!("a needed grant") };
        let receipt = d.request_grant_with(&need, "restart app-api", 1800, &CancelToken::default(), std::time::Duration::ZERO, std::time::Duration::from_secs(5)).unwrap();
        assert_eq!(receipt.entitlement, "prod-operate");
        assert_eq!(receipt.active_until, receipt.granted_at + std::time::Duration::from_secs(1800));
        assert!(std::time::SystemTime::now().duration_since(receipt.granted_at).unwrap_or_default().as_secs() <= 2);
        assert_eq!(*remembered.lock().unwrap(), vec![(GATE.to_string(), "restart app-api".to_string(), 1800)]);
        let calls = calls(&gcp);
        assert!(calls.contains(&format!("create {ACCOUNT} acme-prod-123456 global prod-operate 1800 restart app-api")), "{calls:?}");
        assert_eq!(calls.iter().filter(|call| call.starts_with("get ")).count(), 2, "polled until ACTIVE: {calls:?}");
    }

    #[test]
    fn request_grant_reuses_a_grant_that_appeared_meanwhile() {
        let gcp = Arc::new(FakeGcp::default());
        let (d, remembered) = directory_with_memory(gate_state("deploy", Some(transport("acme-prod-123456", GATE, false, prod_pam()))), &gcp);
        let target = d.resolve(&gate()).unwrap();
        let DirectoryError::GrantNeeded(need) = d.prepare(&target, &public_key, &CancelToken::default()).unwrap_err() else { panic!("a needed grant") };
        // Another connection (or the panel) requested one in between: PAM would refuse a second request with the same scope.
        *gcp.grants.lock().unwrap() = vec![Grant { access_grant_time: Some(crate::gcp::pam::rfc3339(std::time::SystemTime::now())), ..grant("ACTIVE") }];
        let receipt = d.request_grant_with(&need, "restart app-api", 1800, &CancelToken::default(), std::time::Duration::ZERO, std::time::Duration::from_secs(5)).unwrap();
        assert_eq!(receipt.entitlement, "prod-operate");
        assert!(!calls(&gcp).iter().any(|call| call.starts_with("create ")), "nothing requested: {:?}", calls(&gcp));
        assert!(remembered.lock().unwrap().is_empty());
    }

    #[test]
    fn request_grant_names_a_state_that_will_not_activate_and_gives_up_after_a_while() {
        let gcp = Arc::new(FakeGcp::default());
        *gcp.states.lock().unwrap() = VecDeque::from(vec!["APPROVAL_AWAITED"]);
        let (d, _) = directory_with_memory(gate_state("deploy", Some(transport("acme-prod-123456", GATE, false, prod_pam()))), &gcp);
        let target = d.resolve(&gate()).unwrap();
        let DirectoryError::GrantNeeded(need) = d.prepare(&target, &public_key, &CancelToken::default()).unwrap_err() else { panic!("a needed grant") };
        let waiting = d.request_grant_with(&need, "x", 1800, &CancelToken::default(), std::time::Duration::ZERO, std::time::Duration::from_secs(5)).unwrap_err();
        assert_eq!(denied(waiting), "The prod-operate grant did not become active (state: APPROVAL_AWAITED); Lunport does not wait for an approver.");
        *gcp.states.lock().unwrap() = VecDeque::from(vec!["ACTIVATING"]);
        let stuck = d.request_grant_with(&need, "x", 1800, &CancelToken::default(), std::time::Duration::ZERO, std::time::Duration::from_millis(50)).unwrap_err();
        assert_eq!(denied(stuck), "The prod-operate grant did not become active within a minute (state: ACTIVATING); try connecting again.");
        *gcp.states.lock().unwrap() = VecDeque::from(vec!["DENIED"]);
        assert_eq!(
            denied(d.request_grant_with(&need, "x", 1800, &CancelToken::default(), std::time::Duration::ZERO, std::time::Duration::from_secs(5)).unwrap_err()),
            "The prod-operate grant did not become active (state: DENIED)."
        );
        let cancel = CancelToken::default();
        cancel.cancel();
        assert_eq!(d.request_grant_with(&need, "x", 1800, &cancel, std::time::Duration::ZERO, std::time::Duration::from_secs(5)).unwrap_err(), DirectoryError::Failed("The connection was cancelled.".into()));
        // The trait method is the inner one with the design's pacing: a cancelled token returns at once there too.
        assert_eq!(d.request_grant(&need, "x", 1800, &cancel).unwrap_err(), DirectoryError::Failed("The connection was cancelled.".into()));
        let _: Option<GrantReceipt> = None;
    }

    #[test]
    fn prepare_does_nothing_for_a_direct_host_and_without_a_client() {
        let gcp = Arc::new(FakeGcp::default());
        let d = directory(gate_state("deploy", None), &gcp);
        let target = d.resolve(&gate()).unwrap();
        d.prepare(&target, &public_key, &CancelToken::default()).unwrap();
        assert!(calls(&gcp).is_empty());

        let (d, _, _) = fixture(gate_state("frank_example_com", Some(transport("acme-dev-654321", GATE, true, None))), true, true);
        let target = d.resolve(&gate()).unwrap();
        assert_eq!(
            d.prepare(&target, &public_key, &CancelToken::default()).unwrap_err(),
            DirectoryError::Failed("Google Cloud access is not configured in this build.".into())
        );

        let cancel = CancelToken::default();
        cancel.cancel();
        let d = directory(gate_state("frank_example_com", Some(transport("acme-dev-654321", GATE, true, None))), &gcp);
        assert_eq!(d.prepare(&target, &public_key, &cancel).unwrap_err(), DirectoryError::Failed("The connection was cancelled.".into()));
        assert!(calls(&gcp).is_empty(), "a cancelled connect talks to nobody");
    }
}
