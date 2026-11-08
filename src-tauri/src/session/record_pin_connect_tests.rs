//! Trusting a host key through the confirmed pin persists it and the real connection continues to the destination.
use super::*;
use crate::session::{
    connect::{Connector, PinnedSummary},
    format_directory::FormatDirectory,
    protocol::HostQuery,
    record_directory::{RecordDirectory, RecordSources},
    testing::{Decision, FakeConfirmer, FakeKeys, FakeOwner},
};
use crate::ssh::{
    fake::{default_server_key, FakeEngine},
    russh_engine::{EngineOptions, RusshEngine},
    testing::{
        fixture::Server,
        harness::{tools, KeyKind},
    },
};
use crate::sync::{
    records_v3::{AuthKind, HostScope, KeySlotPayload, LocalKeyMetadata},
    slot_rules::test_keys,
    testkit::{TestClock, TestDevice},
};
use std::{sync::Arc, time::Duration};

const HOST: &str = "0000000000000001";
const KEY: &str = "11111111111111111111111111111111";

/// A records library with one host, `web`.
fn library() -> Arc<TestDevice> {
    let device = Arc::new(TestDevice::new("pin-connect", &TestClock::new()));
    let env = device.env();
    let probe = record_runtime::probe_startup(&env.state_path, "pin-connect");
    record_runtime::activate_probe(&mut device.runtime.core.lock().unwrap(), probe).unwrap();
    record_runtime::mutate_records(&env, |state| {
        repo::create_host(
            state,
            HOST,
            HostScope::Local,
            serde_json::from_value(serde_json::json!({"schema":2,"alias":"web","hostname":"host.test","user":"ops","auth":"interactive"})).unwrap(),
            3,
        )
        .map_err(failed)
    })
    .unwrap();
    device
}

/// The broker's directory over the library: the Records directory under the format check, pins written through the confirmed pin.
fn directory(device: &Arc<TestDevice>) -> FormatDirectory {
    let read = device.clone();
    let pin = device.clone();
    let records = RecordDirectory::new(RecordSources {
        snapshot: Box::new(move || {
            record_runtime::snapshot(&read.env())
                .map(|(s, _)| s)
                .map_err(|e| DirectoryError::Failed(e.to_string()))
        }),
        material: Box::new(|_| Ok(true)),
        username: Box::new(|| panic!("use the explicitly saved login")),
        pin: Box::new(|_, _, _, _| panic!("use confirmed pin persistence")),
    })
    .with_confirmed_pin(Box::new(move |hop, previous, key, cancel, guard| {
        super::confirm(&pin.env(), hop, previous, key, cancel, guard)
            .map_err(|e| DirectoryError::Failed(e.to_string()))
    }));
    let mode = device.clone();
    FormatDirectory {
        lifecycle: device.runtime.lifecycle.clone(),
        mode: Box::new(move || mode.runtime.core.lock().unwrap().format),
        records: Arc::new(records),
    }
}

/// Design 2026-11-09 (saved pins), through the library: a server key that differs from the pin saved for the host, which this device has
/// not approved (another device saved it), is asked about as a changed key with that pin's date, and only accepting it replaces the pin.
/// The very key that was saved is asked about as new, says when it was saved, and keeps its pin. Either way the key is approved here once
/// and the next connect asks nothing; refused, nothing is written.
#[test]
fn a_saved_pin_this_device_has_not_approved_is_asked_about_as_changed_or_as_saved() {
    let other = HostKey::from_openssh_line(test_keys::ECDSA_PUBLIC).unwrap();
    for saved in [other, default_server_key()] {
        let differs = saved != default_server_key();
        let device = library();
        record_runtime::mutate_records(&device.env(), |state| {
            repo::pin_host_key(
                state,
                HOST,
                &repo::HostEndpoint { hostname: "host.test".into(), port: 22 },
                None,
                crate::session::record_directory::stored(&saved),
                5,
            )
            .map_err(failed)
        })
        .unwrap();
        let stored = || {
            let state = record_runtime::snapshot(&device.env()).unwrap().0;
            let pin = repo::get_host(&state, HOST).unwrap().host.payload.host_key.unwrap();
            (pin.fingerprint, pin.pinned_at_ms, state.local.credential_approvals.contains_key(HOST))
        };
        let directory = directory(&device);
        let engine = FakeEngine::new();
        let keys = FakeKeys::new();
        let connect = |confirmer: &FakeConfirmer| {
            Connector {
                grants: crate::session::grants::GrantGates::for_tests(),
                engine: &engine,
                directory: &directory,
                keys: &keys,
                keychain: &device.keychain,
                confirmer,
            }
            .connect(&HostQuery::Id(HOST.into()), &FakeOwner::default(), &CancelToken::default())
        };
        let summary = Some(PinnedSummary { fingerprint: saved.fingerprint.clone(), pinned_at_ms: 5 });

        let refusing = FakeConfirmer::deciding(vec![Decision::Refuse]);
        let refused = connect(&refusing).err().map(|failure| failure.text);
        let sentence = if differs { "The host key of web changed. Connection refused." } else { "The host key of web has not been confirmed yet." };
        assert_eq!(refused.as_deref(), Some(sentence));
        let asked = refusing.asked();
        assert_eq!(asked.len(), 1);
        let shown = if differs { (summary.clone(), None) } else { (None, summary.clone()) };
        assert_eq!((asked[0].changed.clone(), asked[0].saved.clone()), shown, "differs: {differs}");
        assert_eq!(stored(), (saved.fingerprint.clone(), 5, false), "refused: nothing written (differs: {differs})");

        let trusting = FakeConfirmer::deciding(vec![Decision::Trust]);
        for _ in 0..2 {
            connect(&trusting).expect("connects once the key is trusted").session.close();
        }
        assert_eq!(trusting.asked().len(), 1, "trusted once (differs: {differs})");
        let (fingerprint, pinned_at_ms, approved) = stored();
        assert_eq!(fingerprint, default_server_key().fingerprint);
        assert!(approved, "approved here (differs: {differs})");
        assert_eq!(pinned_at_ms == 5, !differs, "only a replaced pin gets a new date (differs: {differs})");
    }
}

/// Points `web` at `server`: its address, port and user, logging in with the server's user key, saved as the library key `KEY`.
fn serve(device: &TestDevice, server: &Server) {
    record_runtime::mutate_records(&device.env(), |state| {
        let mut next = state.clone();
        let public = ssh_key::PublicKey::from_openssh(&server.key.public_line).unwrap();
        next.local.keys.insert(
            KEY.into(),
            LocalKeyMetadata {
                vault_id: KEY.into(),
                public: KeySlotPayload {
                    schema: 2,
                    name: "loopback".into(),
                    public_key: server.key.public_line.clone(),
                    fingerprint: public.fingerprint(ssh_key::HashAlg::Sha256).to_string(),
                    key_type: public.algorithm().to_string(),
                    has_passphrase: false,
                    created_at_ms: 1,
                    origin_device_id: next.device_id.clone(),
                },
            },
        );
        let host = repo::get_host(&next, HOST).unwrap();
        let mut payload = host.host.payload;
        payload.hostname = "127.0.0.1".into();
        payload.port = server.sshd.port;
        payload.user = server.sshd.user.clone();
        payload.auth = AuthKind::Key;
        payload.key_id = Some(KEY.into());
        repo::update_host(&next, HOST, &host.revision, payload, 4).map_err(failed)
    })
    .unwrap();
}

#[test]
fn trusting_an_unknown_or_changed_host_key_connects_to_openssh() {
    let Some(tools) = tools() else { return };
    for changed_key in [false, true] {
        let server = Server::start(&tools, &["LogLevel INFO"]);
        let device = library();
        serve(&device, &server);
        if changed_key {
            record_runtime::mutate_records(&device.env(), |state| {
                repo::pin_host_key(
                    state,
                    HOST,
                    &repo::HostEndpoint {
                        hostname: "127.0.0.1".into(),
                        port: server.sshd.port,
                    },
                    None,
                    crate::session::record_directory::stored(
                        &HostKey::from_openssh_line(test_keys::ECDSA_PUBLIC).unwrap(),
                    ),
                    5,
                )
                .map_err(failed)
                .and_then(|next| crate::session::credential_approval::approve(next, &crate::ssh::HopRef {
                    id: HOST.into(), alias: "web".into(), hostname: "127.0.0.1".into(),
                    port: server.sshd.port, user: server.sshd.user.clone(),
                }, &HostKey::from_openssh_line(test_keys::ECDSA_PUBLIC).unwrap()).map_err(failed))
            })
            .unwrap();
        }
        let directory = directory(&device);
        let engine = RusshEngine::with_options(EngineOptions {
            worker_threads: 2,
            ..Default::default()
        });
        let keys = FakeKeys::new().with_key(KEY, "loopback", &server.key.private_text);
        let confirmer = FakeConfirmer::deciding(vec![Decision::Trust]);
        let connector = Connector {
            grants: crate::session::grants::GrantGates::for_tests(),
            engine: &engine,
            directory: &directory,
            keys: &keys,
            keychain: &device.keychain,
            confirmer: &confirmer,
        };
        let owner = FakeOwner::default();
        for _ in 0..2 {
            let connected = connector
                .connect(&HostQuery::Id(HOST.into()), &owner, &CancelToken::default())
                .unwrap();
            let result = connected
                .session
                .exec("printf sync-pin-ok", Duration::from_secs(10), 1024)
                .unwrap();
            assert_eq!(result.stdout, b"sync-pin-ok");
            connected.session.close();
        }
        assert_eq!(
            confirmer.asked().len(),
            1,
            "trust once; matching pin reconnects without prompting"
        );
        assert_eq!(confirmer.asked()[0].changed.is_some(), changed_key);
        assert_eq!(
            owner.notices.lock().unwrap().as_slice(),
            ["Waiting for you to confirm web's host key in Lunport."]
        );
        let current = record_runtime::snapshot(&device.env()).unwrap().0;
        assert_eq!(
            repo::get_host(&current, HOST)
                .unwrap()
                .host
                .payload
                .host_key
                .unwrap()
                .fingerprint,
            server.host_key().fingerprint
        );
        assert!(
            server.sshd.log().contains("Accepted publickey"),
            "the actual destination accepted login"
        );
    }
}

/// Design 2026-11-09 (saved pins), against OpenSSH with an Ed25519 and an RSA host key: another device saved the RSA key, which this device
/// has not approved. The handshake asks for the saved key's type, so the server presents that very key and the question says it was saved,
/// instead of warning about the Ed25519 key the client would prefer. Trusting it approves the saved pin as it is, and the next connect
/// asks nothing.
#[test]
fn a_server_with_a_preferred_key_type_next_to_the_saved_key_presents_the_saved_key() {
    let Some(tools) = tools() else { return };
    let server = Server::start_with(&tools, &[KeyKind::Ed25519, KeyKind::Rsa3072], KeyKind::Ed25519, &["LogLevel INFO"]);
    let rsa = server.host_keys().remove(1);
    assert_eq!(rsa.algorithm, "ssh-rsa");
    let device = library();
    serve(&device, &server);
    record_runtime::mutate_records(&device.env(), |state| {
        repo::pin_host_key(
            state,
            HOST,
            &repo::HostEndpoint { hostname: "127.0.0.1".into(), port: server.sshd.port },
            None,
            crate::session::record_directory::stored(&rsa),
            5,
        )
        .map_err(failed)
    })
    .unwrap();
    let directory = directory(&device);
    let engine = RusshEngine::with_options(EngineOptions { worker_threads: 2, ..Default::default() });
    let keys = FakeKeys::new().with_key(KEY, "loopback", &server.key.private_text);
    let confirmer = FakeConfirmer::deciding(vec![Decision::Trust]);
    let connector = Connector {
        grants: crate::session::grants::GrantGates::for_tests(),
        engine: &engine,
        directory: &directory,
        keys: &keys,
        keychain: &device.keychain,
        confirmer: &confirmer,
    };
    for _ in 0..2 {
        let connected = connector
            .connect(&HostQuery::Id(HOST.into()), &FakeOwner::default(), &CancelToken::default())
            .expect("connects with the saved key");
        connected.session.close();
    }
    let asked = confirmer.asked();
    assert_eq!(asked.len(), 1, "asked once: {asked:?}");
    assert_eq!((asked[0].fingerprint.clone(), asked[0].changed.clone()), (rsa.fingerprint.clone(), None), "the saved key, not a changed one");
    assert_eq!(asked[0].saved, Some(PinnedSummary { fingerprint: rsa.fingerprint.clone(), pinned_at_ms: 5 }));
    let current = record_runtime::snapshot(&device.env()).unwrap().0;
    let pin = repo::get_host(&current, HOST).unwrap().host.payload.host_key.unwrap();
    assert_eq!((pin.fingerprint, pin.pinned_at_ms), (rsa.fingerprint.clone(), 5), "the saved pin stays as it was");
    assert!(crate::session::credential_approval::matches(
        &current,
        &crate::ssh::HopRef { id: HOST.into(), alias: "web".into(), hostname: "127.0.0.1".into(), port: server.sshd.port, user: server.sshd.user.clone() },
        &rsa
    ));
}
